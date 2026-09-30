// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Adapter-level tests: the `open()` ctor's config handling. The module behavior is tested in the
//! `busbar-auth-ldap` lib crate.

use super::open;

#[test]
fn open_rejects_empty_config() {
    assert!(open("").is_err());
    assert!(open("   ").is_err());
}

#[test]
fn open_rejects_malformed_json() {
    assert!(open("{ not json").is_err());
}

#[test]
fn open_rejects_missing_required_fields() {
    // no bind_dn_template / base_dn
    assert!(open(r#"{"url":"ldaps://x"}"#).is_err());
}

#[test]
fn open_accepts_minimal_valid_config() {
    let cfg = r#"{
        "url": "ldaps://ad.corp.example:636",
        "bind_dn_template": "uid={username},ou=people,dc=corp,dc=example",
        "base_dn": "dc=corp,dc=example"
    }"#;
    assert!(open(cfg).is_ok(), "minimal valid config should construct");
}

/// A direct-bind UPN template (`{username}@corp.example`) is not a DN, so the group read off the
/// bound entry could never succeed; `open` refuses it at boot.
#[test]
fn open_rejects_a_direct_bind_upn_template() {
    let cfg = r#"{
        "url": "ldaps://ad.corp.example:636",
        "bind_dn_template": "{username}@corp.example",
        "base_dn": "dc=corp,dc=example"
    }"#;
    assert!(open(cfg).is_err());
}
