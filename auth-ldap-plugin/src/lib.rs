// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **AD/LDAP auth module as a droppable busbar plugin** — a `cdylib` that exports the auth C ABI
//! ([`busbar_plugin_abi::auth`]). Build it, drop the resulting `.so`/`.dll`/`.dylib` into the
//! engine's plugins folder, add `ldap` to `auth.methods` (and/or `auth.chain`), and configure
//! `auth.methods.ldap` settings; the engine loads it in-process at boot over the auth ABI.
//!
//! Mirrors `auth-oidc-plugin`'s `open()` exactly — the only difference is it exports an
//! [`busbar_auth_ldap::LdapModule`] (which opens its own LDAP socket) instead of the OIDC module.
//! Because `LdapModule` implements BOTH `AuthModule` and `LoginModule`, it is exported through
//! [`busbar_plugin_sdk::export_login_plugin!`] (NOT the verify-only `export_auth_plugin!`, which
//! would mask the login capability behind the fail-closed adapter).

use busbar_api::AuthPlugin;
use busbar_auth_ldap::{LdapConfig, LdapModule};

/// Construct an LDAP auth module from the JSON config the engine passes through `open` — the
/// `auth.methods.ldap` opaque settings. Shape:
///
/// ```json
/// {
///   "url": "ldaps://ad.corp.example:636",
///   "bind_dn_template": "{username}@corp.example",
///   "base_dn": "dc=corp,dc=example",
///   "group_attr": "memberOf",
///   "role_from": "cn",
///   "ca_cert_pem": null,
///   "timeout_secs": 10
/// }
/// ```
///
/// An empty config is rejected: an LDAP module with no URL/DN template can never bind anyone, so a
/// boot-time error naming the reference is strictly better than deferring to every login.
fn open(cfg: &str) -> Result<Box<dyn AuthPlugin>, String> {
    let cfg: LdapConfig = if cfg.trim().is_empty() {
        return Err(
            "ldap plugin requires config (url, bind_dn_template, base_dn); none provided"
                .to_string(),
        );
    } else {
        serde_json::from_str(cfg).map_err(|e| format!("invalid ldap plugin config: {e}"))?
    };
    Ok(Box::new(LdapModule::new(cfg)?))
}

busbar_plugin_sdk::export_login_plugin!(open);

#[cfg(test)]
mod tests;
