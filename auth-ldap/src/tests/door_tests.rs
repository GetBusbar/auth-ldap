// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's own pieces: the settings blob `validate`/`open`/`refresh` parse, the submitted-field
//! lookup, and the Statement's facts. The table itself is driven through the real loader in the
//! plugin crate's `tests/conformance.rs` (linked and dropped in).

use super::{field, Ldap, ALIAS, FORM, NAME, NEED, NEEDS, SECRET_REFS, STATEMENT, TAIL};
use crate::LdapModule;
use busbar_contract::abi::auth::{CAP_INBOUND, CAP_LOGIN, CAP_OUTBOUND, LOGIN_KIND_CREDENTIAL};
use busbar_contract::abi::host::conn::connector::{
    DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE,
};
use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::door::MARK_BLOCKS;
use busbar_contract::abi::sdk::life::Life;

const MINIMAL: &str = r#"{
    "url": "ldaps://ad.corp.example:636",
    "bind_dn_template": "uid={username},ou=people,dc=corp,dc=example",
    "base_dn": "dc=corp,dc=example"
}"#;

#[test]
fn settings_refuse_an_empty_blob() {
    for blob in ["", "   "] {
        let e = LdapModule::from_settings(blob.as_bytes())
            .err()
            .expect("an empty blob is refused");
        assert!(e.contains("requires config"), "{e}");
    }
}

#[test]
fn settings_refuse_malformed_json() {
    let e = LdapModule::from_settings(b"{ not json")
        .err()
        .expect("malformed JSON is refused");
    assert!(e.starts_with("invalid ldap plugin config:"), "{e}");
}

#[test]
fn settings_refuse_missing_required_fields() {
    assert!(LdapModule::from_settings(br#"{"url":"ldaps://x"}"#).is_err());
}

#[test]
fn settings_accept_a_minimal_config() {
    assert!(LdapModule::from_settings(MINIMAL.as_bytes()).is_ok());
    assert!(Ldap::validate(MINIMAL.as_bytes()).is_ok());
}

/// A direct-bind UPN template (`{username}@corp.example`) is not a DN, so the group read off the
/// bound entry could never succeed; `validate` refuses it.
#[test]
fn settings_refuse_a_direct_bind_upn_template() {
    let blob = br#"{
        "url": "ldaps://ad.corp.example:636",
        "bind_dn_template": "{username}@corp.example",
        "base_dn": "dc=corp,dc=example"
    }"#;
    let r = Ldap::validate(blob).expect_err("refused");
    assert!(r.text().is_some_and(|t| t.contains("is not a DN")), "{r:?}");
}

#[test]
fn a_refused_refresh_keeps_the_running_module() {
    let ldap = Ldap::open(MINIMAL.as_bytes(), &[], 1).expect("opens");
    let before = ldap.module();
    assert!(ldap.refresh(b"", &[], 2).is_err());
    assert!(std::sync::Arc::ptr_eq(&before, &ldap.module()));
    assert!(ldap.refresh(MINIMAL.as_bytes(), &[], 3).is_ok());
    assert!(!std::sync::Arc::ptr_eq(&before, &ldap.module()));
}

#[test]
fn a_field_is_found_by_its_declared_name_and_must_be_text() {
    let fields: [(&[u8], &[u8]); 3] = [
        (b"username", b"alice"),
        (b"password", b"\xff\xfe"),
        (b"other", b"x"),
    ];
    assert_eq!(field(&fields, "username"), Some("alice"));
    assert_eq!(field(&fields, "password"), None, "non-UTF-8 is no value");
    assert_eq!(field(&fields, "missing"), None);
}

fn text(s: AbiStr) -> &'static str {
    if s.ptr.is_null() {
        return "";
    }
    // SAFETY: every string in the Statement is `'static` UTF-8 (`abi_str`).
    #[allow(unsafe_code)]
    let bytes = unsafe { std::slice::from_raw_parts(s.ptr, s.len) };
    std::str::from_utf8(bytes).expect("UTF-8")
}

/// The Statement states a credential login that never blocks (no `MARK_BLOCKS`: every call is
/// Ready or Pending), its ONE need (outbound, a raw `tcp` stream, operator-infrastructure, the
/// target named per login), and the service password as its one secret reference.
#[test]
fn the_statement_states_a_non_blocking_credential_login_over_one_need() {
    assert_eq!(TAIL.caps, CAP_INBOUND | CAP_LOGIN);
    assert_eq!(TAIL.caps & CAP_OUTBOUND, 0);
    assert_eq!(TAIL.login_kind, LOGIN_KIND_CREDENTIAL);
    assert_eq!(STATEMENT.marks & MARK_BLOCKS, 0, "no call blocks");
    assert_eq!(STATEMENT.rewrites_len, 1);
    assert_eq!((NAME, ALIAS), ("busbar-auth-ldap", "ldap"));
    assert_eq!(FORM.len(), 2);

    assert_eq!((STATEMENT.needs, STATEMENT.needs_len), (NEEDS.as_ptr(), 1));
    let need = &NEEDS[NEED as usize];
    assert_eq!(need.direction, DIRECTION_OUTBOUND);
    assert_eq!(need.egress_class, EGRESS_OPERATOR_INFRASTRUCTURE);
    assert_eq!(text(need.transport), "tcp");
    assert_eq!(text(need.target_from), "", "the target is named per login");
    assert_eq!(text(need.trust_from), "settings.ca_cert_pem");

    assert_eq!(STATEMENT.secret_refs_len, 1);
    assert_eq!(text(SECRET_REFS[0]), "bind_service_password");
}

/// The secret the kernel resolved for `bind_service_password` wins over the settings' literal; an
/// absent or empty one leaves the literal (1.5.5's config still opens).
#[test]
fn the_resolved_service_secret_wins_over_the_literal() {
    let blob = br#"{
        "url": "ldaps://ad.corp.example:636",
        "bind_dn_template": "uid={username},dc=corp,dc=example",
        "base_dn": "dc=corp,dc=example",
        "user_search_filter": "(uid={username})",
        "bind_service_dn": "cn=svc,dc=corp,dc=example",
        "bind_service_password": "literal"
    }"#;
    let pw = |m: &LdapModule| {
        m.cfg
            .bind_service_password
            .as_ref()
            .map(|p| p.expose().to_owned())
    };
    let m = LdapModule::from_settings_with(blob, &[b"resolved".as_slice()]).expect("opens");
    assert_eq!(pw(&m).as_deref(), Some("resolved"));
    let m = LdapModule::from_settings_with(blob, &[b"".as_slice()]).expect("opens");
    assert_eq!(pw(&m).as_deref(), Some("literal"));
    let m = LdapModule::from_settings_with(blob, &[]).expect("opens");
    assert_eq!(pw(&m).as_deref(), Some("literal"));
    let e = LdapModule::from_settings_with(blob, &[b"\xff".as_slice()])
        .err()
        .expect("refused");
    assert!(e.contains("not UTF-8"), "{e}");
}
