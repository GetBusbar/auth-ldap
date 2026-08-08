// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Unit tests for the PURE surface of the LDAP module: config parsing, bind-DN templating +
//! injection defense, LDAP filter escaping, and the group-DN → role mapping (README Gap 6
//! normalization). The BIND itself needs a live directory and is not covered here.

use crate::groups::{escape_filter, first_cn, roles_from_group_dns, validate_username};
use crate::{
    principal_id, submitted_field, AuthModule, AuthOutcome, BeginLogin, BindError, CompleteLogin,
    DirEntry, FieldKind, LdapBackend, LdapConfig, LdapModule, LoginForm, LoginKind, LoginModule,
    LoginOutcome, RoleFrom, SearchScope,
};
use busbar_api::Redacted;
use std::collections::HashMap;

/// Build a `CompleteLogin` carrying the given credential fields in its `submitted` map (each value
/// `Redacted`, exactly as the engine hands them across the credential boundary).
fn with_submitted(pairs: &[(&str, &str)]) -> CompleteLogin {
    CompleteLogin {
        submitted: pairs
            .iter()
            .map(|(k, v)| (k.to_string(), Redacted::new(v.to_string())))
            .collect(),
        ..Default::default()
    }
}

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

/// With a search filter set, a service DN but NO password would make `simple_bind(dn,
/// "")` an UNAUTHENTICATED bind. `new()` must require the password too.
#[test]
fn search_then_bind_requires_service_password() {
    let mut cfg = base_cfg();
    cfg.user_search_filter = Some("(sAMAccountName={username})".to_string());
    cfg.bind_service_dn = Some("cn=svc,dc=corp,dc=example".to_string());
    // bind_service_password absent → unauthenticated-bind guard fires
    assert!(
        LdapModule::new(cfg).is_err(),
        "search-then-bind without a service password must be rejected"
    );
}

/// A service DN with an EMPTY-STRING password still yields `simple_bind(dn, "")`
/// — an unauthenticated bind. The round-1 guard only checked `is_none()`; `new()` must also reject a
/// present-but-empty service password.
#[test]
fn search_then_bind_rejects_empty_service_password() {
    let mut cfg = base_cfg();
    cfg.user_search_filter = Some("(sAMAccountName={username})".to_string());
    cfg.bind_service_dn = Some("cn=svc,dc=corp,dc=example".to_string());
    cfg.bind_service_password = Some(serde_json::from_value(serde_json::json!("")).unwrap());
    assert!(
        LdapModule::new(cfg).is_err(),
        "an empty-string service password is an unauthenticated bind and must be rejected"
    );
}

/// A plaintext `ldap://` URL to a NON-loopback host with no STARTTLS sends the
/// service and end-user credentials in cleartext. `new()` must reject it by default...
#[test]
fn insecure_ldap_nonloopback_rejected() {
    let mut cfg = base_cfg();
    cfg.url = "ldap://ad.corp.example:389".to_string();
    assert!(
        LdapModule::new(cfg).is_err(),
        "plaintext ldap:// to a non-loopback host must be rejected by default"
    );
}

/// ...unless the operator explicitly opts out with `allow_insecure_transport`.
#[test]
fn insecure_ldap_allowed_with_optout() {
    let mut cfg = base_cfg();
    cfg.url = "ldap://ad.corp.example:389".to_string();
    cfg.allow_insecure_transport = true;
    assert!(
        LdapModule::new(cfg).is_ok(),
        "the explicit allow_insecure_transport opt-out must be honored"
    );
}

/// STARTTLS over `ldap://` is encrypted, so the plaintext guard must not fire.
#[test]
fn ldap_with_starttls_allowed() {
    let mut cfg = base_cfg();
    cfg.url = "ldap://ad.corp.example:389".to_string();
    cfg.start_tls = true;
    assert!(LdapModule::new(cfg).is_ok(), "STARTTLS must not be blocked");
}

/// Implicit LDAPS is encrypted — never blocked.
#[test]
fn ldaps_is_allowed() {
    let mut cfg = base_cfg();
    cfg.url = "ldaps://ad.corp.example:636".to_string();
    assert!(LdapModule::new(cfg).is_ok(), "ldaps:// must not be blocked");
}

/// A loopback host stays on the box — plaintext to it is not exposed on the network.
#[test]
fn loopback_ldap_allowed() {
    for host in ["127.0.0.1", "localhost", "[::1]"] {
        let mut cfg = base_cfg();
        cfg.url = format!("ldap://{host}:389");
        assert!(
            LdapModule::new(cfg).is_ok(),
            "plaintext ldap:// to loopback host {host} must be allowed"
        );
    }
}

/// Round-3: a userinfo component must not let a loopback-looking prefix bypass the plaintext guard.
/// `ldap://127.0.0.1:389@evil.com` dials `evil.com` in cleartext (the userinfo is `127.0.0.1:389`),
/// so the host is `evil.com` and the config must be REJECTED — not read as loopback.
#[test]
fn userinfo_loopback_prefix_is_treated_as_remote() {
    let mut cfg = base_cfg();
    cfg.url = "ldap://127.0.0.1:389@evil.com".to_string();
    assert!(
        LdapModule::new(cfg).is_err(),
        "a loopback-looking userinfo prefix must not bypass the plaintext-transport guard"
    );
}

/// Round-3: the `ldaps://` scheme check must not panic on a URL whose multi-byte UTF-8 char straddles
/// byte index 8 (a byte-boundary slice would panic; a plugin must never crash the host on any config).
#[test]
fn insecure_transport_check_does_not_panic_on_multibyte_url() {
    let mut cfg = base_cfg();
    cfg.url = "ldap://é.example:389".to_string(); // 'é' (2 bytes) straddles index 7-8
                                                  // Must return a Result (reject as insecure), never panic.
    assert!(
        LdapModule::new(cfg).is_err(),
        "a plaintext ldap:// to a non-loopback multibyte host must reject without panicking"
    );
}

/// `ca_cert_pem` is documented but never wired into TLS. `new()` must FAIL CLOSED rather
/// than accept-and-ignore it (which would silently fall back to system roots).
#[test]
fn new_rejects_ca_cert_pem() {
    let mut cfg = base_cfg();
    cfg.ca_cert_pem = Some("-----BEGIN CERTIFICATE-----\n...".to_string());
    assert!(
        LdapModule::new(cfg).is_err(),
        "an unsupported ca_cert_pem must be rejected, not silently ignored"
    );
}

/// The service-account password must never appear in a `Debug` dump of the config (it
/// used to be a bare `String` on a `#[derive(Debug)]` struct).
#[test]
fn service_password_redacted_in_debug() {
    let cfg: LdapConfig = serde_json::from_value(serde_json::json!({
        "url": "ldaps://ad.corp.example:636",
        "bind_dn_template": "uid={username},dc=corp,dc=example",
        "base_dn": "dc=corp,dc=example",
        "user_search_filter": "(sAMAccountName={username})",
        "bind_service_dn": "cn=svc,dc=corp,dc=example",
        "bind_service_password": "super-secret-pw"
    }))
    .expect("config with a service password deserializes");
    let dbg = format!("{cfg:?}");
    assert!(
        !dbg.contains("super-secret-pw"),
        "service password must not leak in Debug: {dbg}"
    );
    assert!(dbg.contains("[REDACTED]"), "expected a redaction marker");
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

/// `\XX` hex-pair DN escapes (RFC 4514) must be resolved, not left literal. Consecutive
/// hex bytes decode together as UTF-8.
#[test]
fn first_cn_unescapes_hex_pairs() {
    // `\41` → 'A'
    assert_eq!(first_cn("CN=\\41,DC=x").as_deref(), Some("A"));
    // a multi-byte char encoded as two hex escapes: `\C3\A9` → 'é'
    assert_eq!(first_cn("CN=caf\\C3\\A9,DC=x").as_deref(), Some("café"));
    // single-char escapes still work alongside hex ones
    assert_eq!(
        first_cn("CN=A\\,\\42,DC=x").as_deref(),
        Some("A,B") // `\,` → ',', `\42` → 'B'
    );
}

/// The operation timeout is derived from `timeout_secs`. (The full per-op wiring needs a
/// live/hung directory to exercise end-to-end; this guards the value the module hands to `ldap3`.)
#[test]
fn timeout_duration_derives_from_secs() {
    let mut cfg = base_cfg();
    cfg.timeout_secs = 7;
    assert_eq!(cfg.timeout(), std::time::Duration::from_secs(7));
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

// ── Auth ABI v2 credential-flow behavior ────────────────────────────────────────────────────────

#[test]
fn authenticate_defers_ldap_is_login_only() {
    let m = LdapModule::new(base_cfg()).unwrap();
    // LDAP verifies no opaque bearer — it must Pass so the data-plane chain continues.
    assert_eq!(m.authenticate(Some("some-token")), AuthOutcome::Pass);
    assert_eq!(m.authenticate(None), AuthOutcome::Pass);
    assert_eq!(m.name(), "ldap");
    assert!(m.cacheable());
}

/// LDAP self-classifies as a `Credential` method so the chooser renders a form (no side-effecting
/// `begin_login` call, no PKCE state minted).
#[test]
fn login_kind_is_credential() {
    let m = LdapModule::new(base_cfg()).unwrap();
    assert_eq!(m.login_kind(), LoginKind::Credential);
}

/// begin_login returns a `Prompt(LoginForm)` declaring exactly [username(Text,required),
/// password(Password,required)] — no redirect URL, no PKCE use.
#[test]
fn begin_login_prompts_username_password_form() {
    let m = LdapModule::new(base_cfg()).unwrap();
    let req = BeginLogin {
        redirect_uri: "https://busbar.example/auth/token".into(),
        state: "s".into(),
        code_challenge: "c".into(),
        nonce: None,
        scopes: vec![],
    };
    let LoginOutcome::Prompt(LoginForm { fields }) = m.begin_login(&req) else {
        panic!("begin_login must Prompt a credential form");
    };
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0].name, "username");
    assert_eq!(fields[0].kind, FieldKind::Text);
    assert!(fields[0].required);
    assert_eq!(fields[1].name, "password");
    assert_eq!(fields[1].kind, FieldKind::Password);
    assert!(fields[1].required);
}

/// `submitted_field` reads a value back by the field `name` the plugin declared, and returns `None`
/// for an absent field.
#[test]
fn submitted_field_reads_declared_names() {
    let req = with_submitted(&[("username", "alice"), ("password", "hunter2")]);
    assert_eq!(submitted_field(&req, "username"), Some("alice"));
    assert_eq!(submitted_field(&req, "password"), Some("hunter2"));
    assert_eq!(submitted_field(&req, "totp"), None);
    // The values ride Redacted on the engine side — Debug must never reveal the password.
    assert!(
        !format!("{req:?}").contains("hunter2"),
        "submitted values must be redacted in Debug"
    );
}

/// complete_login rejects when credentials are absent, and rejects an empty (anonymous-bind)
/// password — without ever reaching the socket. The happy path (real bind → Identify) needs a live
/// directory and is covered by integration testing, not here.
#[test]
fn complete_login_rejects_missing_or_empty_credentials() {
    let m = LdapModule::new(base_cfg()).unwrap();
    // no submitted map at all
    assert_eq!(
        m.complete_login(&CompleteLogin::default()),
        LoginOutcome::Reject
    );
    // username present but password missing from the map
    assert_eq!(
        m.complete_login(&with_submitted(&[("username", "alice")])),
        LoginOutcome::Reject
    );
    // empty password → anonymous-bind guard (never reaches the socket)
    assert_eq!(
        m.complete_login(&with_submitted(&[("username", "alice"), ("password", "")])),
        LoginOutcome::Reject
    );
}

/// LDAP is a `Credential` method: it has no confidential-client `client_secret`. The config type has
/// no such field, and `deny_unknown_fields` rejects one if an operator configures it — the
/// structural "client_secret must be absent" guarantee for a Credential method.
#[test]
fn config_rejects_client_secret() {
    let r: Result<LdapConfig, _> = serde_json::from_value(serde_json::json!({
        "url": "ldaps://x",
        "bind_dn_template": "uid={username},dc=x",
        "base_dn": "dc=x",
        "client_secret": "should-not-exist-for-ldap"
    }));
    assert!(
        r.is_err(),
        "a Credential method must have no client_secret slot"
    );
}

// ── Fake-backend coverage of the bind path ───────────────────────────────────────────────────────

/// A scriptable in-memory [`LdapBackend`] standing in for a live directory, so the post-connect bind
/// logic — result-code handling, ambiguity, group cap, roles, principal id — is unit-testable.
#[derive(Default)]
struct FakeLdap {
    /// A bind whose password equals this string returns rc 49 (invalidCredentials); all others 0.
    reject_password: Option<String>,
    /// Entries returned by the Subtree (search-then-bind user lookup) search.
    search_entries: Vec<DirEntry>,
    /// Group values returned on the Base (group read) search.
    group_values: Vec<String>,
    /// The attribute name under which `group_values` are returned.
    group_attr: String,
    /// Every bind DN attempted, in order.
    binds: Vec<String>,
    /// Set once `unbind` is called.
    unbound: bool,
    /// Inject a TRANSPORT failure (`Err`) from `simple_bind` when the bind DN equals this — models a
    /// connect/TLS/timeout error, distinct from a non-zero result code. Lets each service-bind and
    /// user-bind Directory→Reject branch be exercised independently.
    bind_err_on: Option<String>,
    /// Inject a TRANSPORT failure (`Err`) from the Subtree (search-then-bind user lookup) search.
    subtree_err: bool,
    /// Inject a TRANSPORT failure (`Err`) from the Base (group read) search.
    base_err: bool,
}

impl LdapBackend for FakeLdap {
    fn simple_bind(&mut self, dn: &str, password: &str) -> Result<u32, String> {
        self.binds.push(dn.to_string());
        if self.bind_err_on.as_deref() == Some(dn) {
            return Err(format!("transport failure binding {dn}"));
        }
        let rc = if self.reject_password.as_deref() == Some(password) {
            49
        } else {
            0
        };
        Ok(rc)
    }

    fn search(
        &mut self,
        _base: &str,
        scope: SearchScope,
        _filter: &str,
        _attrs: &[&str],
    ) -> Result<Vec<DirEntry>, String> {
        match scope {
            // search-then-bind user lookup
            SearchScope::Subtree => {
                if self.subtree_err {
                    return Err("transport failure on user search".to_string());
                }
                Ok(self.search_entries.clone())
            }
            // group read off the bound user entry
            SearchScope::Base => {
                if self.base_err {
                    return Err("transport failure on group read".to_string());
                }
                let mut attrs = HashMap::new();
                if !self.group_values.is_empty() {
                    attrs.insert(self.group_attr.clone(), self.group_values.clone());
                }
                Ok(vec![DirEntry {
                    dn: self.binds.last().cloned().unwrap_or_default(),
                    attrs,
                }])
            }
        }
    }

    fn unbind(&mut self) {
        self.unbound = true;
    }
}

fn search_cfg() -> LdapConfig {
    serde_json::from_value(serde_json::json!({
        "url": "ldaps://ad.corp.example:636",
        "bind_dn_template": "uid={username},dc=corp,dc=example",
        "base_dn": "dc=corp,dc=example",
        "user_search_filter": "(sAMAccountName={username})",
        "bind_service_dn": "cn=svc,dc=corp,dc=example",
        "bind_service_password": "svc-secret"
    }))
    .expect("valid search-then-bind config parses")
}

/// Reject path: a wrong password → non-zero bind rc → `InvalidCredentials`.
#[test]
fn bind_wrong_password_is_invalid_credentials() {
    let m = LdapModule::new(base_cfg()).unwrap();
    let mut fake = FakeLdap {
        reject_password: Some("wrongpw".to_string()),
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    let r = m.bind_and_identify_on(&mut fake, "alice", "wrongpw");
    assert!(matches!(r, Err(BindError::InvalidCredentials)));
}

/// Reject path: a search that matches nothing → `InvalidCredentials`, without ever
/// attempting the user bind.
#[test]
fn search_no_match_is_invalid_credentials() {
    let m = LdapModule::new(search_cfg()).unwrap();
    let mut fake = FakeLdap {
        search_entries: vec![], // no user found
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    let r = m.bind_and_identify_on(&mut fake, "ghost", "pw");
    assert!(matches!(r, Err(BindError::InvalidCredentials)));
}

/// Success path, with a normalized id: a successful search-then-bind returns `Identify`
/// with the CN-mapped roles and a principal id keyed on the resolved DN, lowercased.
#[test]
fn successful_bind_identifies_with_roles_and_normalized_id() {
    let m = LdapModule::new(search_cfg()).unwrap();
    let mut fake = FakeLdap {
        search_entries: vec![DirEntry {
            dn: "CN=Alice,OU=People,DC=corp,DC=example".to_string(),
            attrs: HashMap::new(),
        }],
        group_values: vec![
            "CN=engineers,OU=Groups,DC=corp,DC=example".to_string(),
            "CN=sre,OU=Groups,DC=corp,DC=example".to_string(),
        ],
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    let p = m
        .bind_and_identify_on(&mut fake, "Alice", "right-pw")
        .expect("bind should succeed");
    assert_eq!(p.id, "ldap:cn=alice,ou=people,dc=corp,dc=example");
    assert_eq!(p.roles, vec!["engineers".to_string(), "sre".to_string()]);
    assert!(fake.unbound, "connection should be unbound on success");
}

/// A search matching >1 entry is AMBIGUOUS and must be rejected, not silently bound to
/// the first match.
#[test]
fn ambiguous_search_is_rejected() {
    let m = LdapModule::new(search_cfg()).unwrap();
    let mut fake = FakeLdap {
        search_entries: vec![
            DirEntry {
                dn: "CN=Alice1,DC=corp,DC=example".to_string(),
                attrs: HashMap::new(),
            },
            DirEntry {
                dn: "CN=Alice2,DC=corp,DC=example".to_string(),
                attrs: HashMap::new(),
            },
        ],
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    let r = m.bind_and_identify_on(&mut fake, "alice", "pw");
    assert!(
        matches!(r, Err(BindError::InvalidCredentials)),
        "two matches must be rejected as ambiguous"
    );
}

/// Two username casings resolve to the SAME principal id (direct-template mode).
#[test]
fn username_casing_yields_same_principal_id() {
    let m = LdapModule::new(base_cfg()).unwrap();
    let id_for = |u: &str| {
        let mut fake = FakeLdap {
            group_attr: "memberOf".to_string(),
            ..Default::default()
        };
        m.bind_and_identify_on(&mut fake, u, "pw").unwrap().id
    };
    assert_eq!(id_for("Alice"), id_for("alice"));
    assert_eq!(
        id_for("alice"),
        "ldap:uid=alice,ou=people,dc=corp,dc=example"
    );
    // and the pure helper is stable under casing directly
    assert_eq!(
        principal_id("uid=Alice,DC=X"),
        principal_id("uid=alice,dc=x")
    );
}

/// An oversized `memberOf` is capped so a hostile directory cannot exhaust memory.
#[test]
fn group_values_are_capped() {
    let m = LdapModule::new(base_cfg()).unwrap();
    // 5000 DISTINCT group CNs — more than the 4096 cap.
    let vals: Vec<String> = (0..5000)
        .map(|i| format!("CN=g{i},DC=corp,DC=example"))
        .collect();
    let mut fake = FakeLdap {
        group_values: vals,
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    let p = m.bind_and_identify_on(&mut fake, "alice", "pw").unwrap();
    assert_eq!(p.roles.len(), 4096, "group values must be capped at 4096");
}

// ── Every Directory→Reject branch actually rejects ───────────────────────────────────────────────
// The fake now injects transport errors, so each operational-failure branch is exercised and proven
// to yield `Directory` (which `complete_login` maps to `Reject`) — never `Identify`.

/// A transport failure on the SERVICE bind is Directory→Reject.
#[test]
fn service_bind_error_rejects() {
    let m = LdapModule::new(search_cfg()).unwrap();
    let mut fake = FakeLdap {
        bind_err_on: Some("cn=svc,dc=corp,dc=example".to_string()),
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    let r = m.bind_and_identify_on(&mut fake, "alice", "pw");
    assert!(matches!(r, Err(BindError::Directory(_))), "got {r:?}");
}

/// A NON-ZERO service-bind result code (rejected service creds) is Directory→Reject.
#[test]
fn service_bind_nonzero_rc_rejects() {
    let m = LdapModule::new(search_cfg()).unwrap();
    let mut fake = FakeLdap {
        // the service password is "svc-secret"; make that bind return rc 49
        reject_password: Some("svc-secret".to_string()),
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    let r = m.bind_and_identify_on(&mut fake, "alice", "pw");
    assert!(matches!(r, Err(BindError::Directory(_))), "got {r:?}");
}

/// A transport failure on the USER SEARCH is Directory→Reject.
#[test]
fn user_search_error_rejects() {
    let m = LdapModule::new(search_cfg()).unwrap();
    let mut fake = FakeLdap {
        subtree_err: true,
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    let r = m.bind_and_identify_on(&mut fake, "alice", "pw");
    assert!(matches!(r, Err(BindError::Directory(_))), "got {r:?}");
}

/// A transport failure on the USER bind (service bind + search succeed first) is Directory→Reject.
#[test]
fn user_bind_error_rejects() {
    let m = LdapModule::new(search_cfg()).unwrap();
    let mut fake = FakeLdap {
        search_entries: vec![DirEntry {
            dn: "CN=Alice,DC=corp,DC=example".to_string(),
            attrs: HashMap::new(),
        }],
        bind_err_on: Some("CN=Alice,DC=corp,DC=example".to_string()),
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    let r = m.bind_and_identify_on(&mut fake, "alice", "pw");
    assert!(matches!(r, Err(BindError::Directory(_))), "got {r:?}");
}

/// A transport failure on the GROUP READ (after a successful user bind) is Directory→Reject.
#[test]
fn group_read_error_rejects() {
    let m = LdapModule::new(search_cfg()).unwrap();
    let mut fake = FakeLdap {
        search_entries: vec![DirEntry {
            dn: "CN=Alice,DC=corp,DC=example".to_string(),
            attrs: HashMap::new(),
        }],
        base_err: true,
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    let r = m.bind_and_identify_on(&mut fake, "alice", "pw");
    assert!(matches!(r, Err(BindError::Directory(_))), "got {r:?}");
}

// ── The search-then-bind path validates username / resolved DN ───────────────────────────────────

/// An EMPTY username in the search path must be rejected — even when an entry would otherwise match
/// — instead of proceeding to a bind. (Without the guard the matching entry below yields `Identify`.)
#[test]
fn search_path_rejects_empty_username() {
    let m = LdapModule::new(search_cfg()).unwrap();
    let mut fake = FakeLdap {
        search_entries: vec![DirEntry {
            dn: "CN=Someone,DC=corp,DC=example".to_string(),
            attrs: HashMap::new(),
        }],
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    let r = m.bind_and_identify_on(&mut fake, "", "pw");
    assert!(
        matches!(r, Err(BindError::InvalidCredentials)),
        "empty username in the search path must be rejected, got {r:?}"
    );
}

/// A search that resolves to an EMPTY DN must not be bound (an empty DN + password is an anonymous
/// bind on many directories). (Without the guard this binds `("", "pw")` and yields `Identify`.)
#[test]
fn search_path_rejects_empty_resolved_dn() {
    let m = LdapModule::new(search_cfg()).unwrap();
    let mut fake = FakeLdap {
        search_entries: vec![DirEntry {
            dn: String::new(),
            attrs: HashMap::new(),
        }],
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    let r = m.bind_and_identify_on(&mut fake, "alice", "pw");
    assert!(
        matches!(r, Err(BindError::InvalidCredentials)),
        "an empty resolved DN must be rejected before binding, got {r:?}"
    );
}

/// `principal_id` must be Unicode-aware. `to_ascii_lowercase` leaves non-ASCII
/// letters untouched, so two Unicode casings of the same name mint two distinct `ldap:` principals.
/// A Unicode-aware `to_lowercase` collapses them to one canonical id.
#[test]
fn unicode_username_casing_yields_same_principal_id() {
    // 'Ä' vs 'ä': identical under to_lowercase, but to_ascii_lowercase leaves 'Ä' unchanged.
    assert_eq!(principal_id("uid=Ä,dc=x"), principal_id("uid=ä,dc=x"));
    // 'İ'/'i' style non-ASCII casing likewise collapses.
    assert_eq!(
        principal_id("cn=ÉLODIE,dc=x"),
        principal_id("cn=élodie,dc=x")
    );
}
