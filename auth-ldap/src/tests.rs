// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Unit tests for the PURE surface of the LDAP module: config parsing, bind-DN templating +
//! injection defense, LDAP filter escaping, and the group-DN → role mapping (the README gap #6
//! normalization). The BIND itself needs a live directory and is not covered here.

use crate::groups::{escape_filter, first_cn, roles_from_group_dns, validate_username};
use crate::{
    AuthModule, AuthOutcome, BeginLogin, CompleteLogin, LdapConfig, LdapModule, LoginModule,
    LoginOutcome, RoleFrom,
};

fn base_cfg() -> LdapConfig {
    serde_json::from_value(serde_json::json!({
        "url": "ldaps://ad.corp.example:636",
        "bind_dn_template": "uid={username},ou=people,dc=corp,dc=example",
        "base_dn": "dc=corp,dc=example"
    }))
    .expect("valid config parses")
}

#[test]
fn config_defaults_apply() {
    let cfg = base_cfg();
    assert_eq!(cfg.group_attr, "memberOf");
    assert_eq!(cfg.role_from, RoleFrom::Cn);
    assert_eq!(cfg.timeout_secs, 10);
    assert!(!cfg.start_tls);
}

#[test]
fn config_rejects_unknown_field() {
    // deny_unknown_fields: a typo'd knob fails config parse, not silently ignored.
    let r: Result<LdapConfig, _> = serde_json::from_value(serde_json::json!({
        "url": "ldaps://x", "bind_dn_template": "uid={username},dc=x", "base_dn": "dc=x",
        "grp_attr": "memberOf"
    }));
    assert!(r.is_err(), "unknown field must be rejected");
}

#[test]
fn new_requires_username_placeholder() {
    let mut cfg = base_cfg();
    cfg.bind_dn_template = "uid=fixed,dc=corp,dc=example".to_string();
    assert!(LdapModule::new(cfg).is_err());
}

#[test]
fn search_then_bind_requires_service_dn() {
    let mut cfg = base_cfg();
    cfg.user_search_filter = Some("(sAMAccountName={username})".to_string());
    // bind_service_dn missing → error
    assert!(LdapModule::new(cfg).is_err());
}

#[test]
fn bind_dn_templating_substitutes_username() {
    let m = LdapModule::new(base_cfg()).unwrap();
    assert_eq!(
        m.bind_dn_for("alice").unwrap(),
        "uid=alice,ou=people,dc=corp,dc=example"
    );
}

#[test]
fn bind_dn_rejects_injection_username() {
    let m = LdapModule::new(base_cfg()).unwrap();
    // A username trying to break out of its RDN must be rejected, not templated in.
    for bad in [
        "alice,dc=corp,dc=example",
        "a=b",
        "x\\,y",
        "semi;colon",
        "with\0nul",
    ] {
        assert!(
            m.bind_dn_for(bad).is_err(),
            "username {bad:?} should be rejected"
        );
    }
}

#[test]
fn username_validation_allows_normal_names() {
    for ok in ["alice", "alice.smith", "a_b-c", "user@corp.example"] {
        assert!(validate_username(ok).is_ok(), "{ok} should be allowed");
    }
    // '@' allowed (AD UPN), but DN specials are not.
    assert!(validate_username("bad,name").is_err());
}

#[test]
fn filter_escaping_neutralizes_metachars() {
    assert_eq!(escape_filter("a*b"), "a\\2ab");
    assert_eq!(escape_filter("a(b)c"), "a\\28b\\29c");
    assert_eq!(escape_filter("a\\b"), "a\\5cb");
    assert_eq!(escape_filter("plain"), "plain");
}

#[test]
fn first_cn_extracts_leading_cn() {
    assert_eq!(
        first_cn("CN=engineers,OU=Groups,DC=corp,DC=example").as_deref(),
        Some("engineers")
    );
    // case-insensitive attribute name
    assert_eq!(first_cn("cn=sre,dc=x").as_deref(), Some("sre"));
    // escaped comma inside the CN value is preserved as a literal comma
    assert_eq!(
        first_cn("CN=Smith\\, Alice,OU=People,DC=x").as_deref(),
        Some("Smith, Alice")
    );
    assert_eq!(first_cn("OU=nope,DC=x"), None);
}

#[test]
fn roles_cn_mode_maps_and_dedups() {
    let dns = vec![
        "CN=engineers,OU=Groups,DC=corp,DC=example".to_string(),
        "CN=sre,OU=Groups,DC=corp,DC=example".to_string(),
        // duplicate CN via different case / path — dedups after CN extraction
        "CN=engineers,OU=Other,DC=corp,DC=example".to_string(),
    ];
    let roles = roles_from_group_dns(&dns, RoleFrom::Cn);
    assert_eq!(roles, vec!["engineers".to_string(), "sre".to_string()]);
}

#[test]
fn roles_dn_mode_lowercases_full_dn() {
    let dns = vec!["CN=Engineers,OU=Groups,DC=Corp,DC=Example".to_string()];
    let roles = roles_from_group_dns(&dns, RoleFrom::Dn);
    assert_eq!(roles, vec!["cn=engineers,ou=groups,dc=corp,dc=example"]);
}

#[test]
fn roles_empty_when_no_groups() {
    assert!(roles_from_group_dns(&[], RoleFrom::Cn).is_empty());
}

// ── ABI-shaped behavior (the gaps, asserted) ────────────────────────────────────────────────────

#[test]
fn authenticate_defers_ldap_is_login_only() {
    let m = LdapModule::new(base_cfg()).unwrap();
    // LDAP verifies no opaque bearer — it must Pass so the data-plane chain continues.
    assert_eq!(m.authenticate(Some("some-token")), AuthOutcome::Pass);
    assert_eq!(m.authenticate(None), AuthOutcome::Pass);
    assert_eq!(m.name(), "ldap");
    assert!(m.cacheable());
}

/// ABI GAP #1, asserted: begin_login cannot express "render a credential form", so it fails closed.
/// This test PINS the gap — when the ABI grows a `LoginOutcome::Prompt`, this expectation changes.
#[test]
fn begin_login_fails_closed_no_form_variant() {
    let m = LdapModule::new(base_cfg()).unwrap();
    let req = BeginLogin {
        redirect_uri: "https://busbar.example/auth/token".into(),
        state: "s".into(),
        code_challenge: "c".into(),
        nonce: None,
        scopes: vec![],
    };
    assert_eq!(m.begin_login(&req), LoginOutcome::Reject);
}

/// complete_login rejects when credentials are absent, and rejects an empty (anonymous-bind)
/// password — without ever reaching the socket. The happy path (real bind → Identify) needs a live
/// directory and is covered by integration testing, not here.
#[test]
fn complete_login_rejects_missing_or_empty_credentials() {
    let m = LdapModule::new(base_cfg()).unwrap();
    // no creds
    assert_eq!(
        m.complete_login(&CompleteLogin::default()),
        LoginOutcome::Reject
    );
    // empty password → anonymous-bind guard
    let empty_pw = CompleteLogin {
        username: Some("alice".into()),
        password: Some(String::new()),
        ..Default::default()
    };
    assert_eq!(m.complete_login(&empty_pw), LoginOutcome::Reject);
}

/// The direct-credential slots exist on CompleteLogin — the part of the ABI that fits LDAP. This
/// asserts they carry through (and documents that `password` rides an un-redacted `Debug` type —
/// gap #3).
#[test]
fn complete_login_carries_username_password() {
    let c = CompleteLogin {
        username: Some("alice".into()),
        password: Some("hunter2".into()),
        ..Default::default()
    };
    assert_eq!(c.username.as_deref(), Some("alice"));
    assert_eq!(c.password.as_deref(), Some("hunter2"));
    // gap #3 evidence: the password is visible in the Debug rendering (nothing redacts it).
    assert!(format!("{c:?}").contains("hunter2"));
}
