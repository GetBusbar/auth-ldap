// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **AD/LDAP auth module** for busbar.
//!
//! Unlike `auth-oidc` (which is a redirect + core-executes-HTTP-hop flow), LDAP is a DIRECT
//! CREDENTIAL flow that opens ITS OWN socket, exactly like `hashicorp-vault` opens its own HTTPS:
//!
//! 1. A dev types username + password on the hosted login page.
//! 2. The core calls this module's [`LoginModule::complete_login`] with those credentials.
//! 3. The module opens an LDAP/LDAPS socket to the directory and performs a **BIND** with the
//!    user's DN + password (this is the credential check — no token, no redirect).
//! 4. On a successful bind it reads the user's group memberships (`memberOf`, or an AD group query)
//!    and returns [`busbar_api::LoginOutcome::Identify`] with a [`Principal`] whose `roles` are the
//!    group names, mapped to policy downstream by the operator's `auth.role_bindings.ldap`.
//!
//! ## ABI stress-test status (this is a design-validation prototype)
//!
//! This crate is a probe of the 1.5.2 `LoginModule` ABI. Every place the ABI cannot express the
//! LDAP credential flow is marked with an `// ABI GAP:` comment and catalogued in the repo README.
//! The credential-carrying half ([`CompleteLogin::username`]/`password` → `Identify`) fits the ABI
//! cleanly; the FORM-PROMPT half ([`begin_login`](LdapModule::begin_login)) does NOT — there is no
//! `LoginOutcome` variant that says "render a username/password form and POST it back", so that path
//! is stubbed at the gap.

use busbar_api::{
    AuthModule, AuthOutcome, BeginLogin, CompleteLogin, LoginModule, LoginOutcome, Principal,
};
use serde::Deserialize;
use std::time::Duration;

pub mod groups;

#[cfg(test)]
mod tests;

/// How a group DN read from the directory becomes a [`Principal`] role string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RoleFrom {
    /// Use the first `CN=` RDN value of the group DN (e.g. `CN=engineers,OU=...` → `engineers`).
    /// The natural, human-facing form to key `role_bindings` on.
    #[default]
    Cn,
    /// Use the full, lowercased group DN verbatim as the role string (exact but noisy to bind on).
    Dn,
}

/// Open-time configuration for the LDAP module — the module's OPAQUE `auth.methods.ldap` settings,
/// deserialized from the JSON the engine passes to `open`. Every LDAP-specific knob (URL, DN
/// templates, TLS/CA, group attribute) fits here as opaque module settings — this is one of the
/// parts of the ABI that fits LDAP cleanly (see README "What worked"): the engine never needs to
/// understand any of these fields.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LdapConfig {
    /// The directory URL: `ldaps://ad.corp.example:636` (LDAPS) or `ldap://ad.corp.example:389`
    /// (plaintext, or STARTTLS when `start_tls` is set).
    pub url: String,

    /// Template that turns a username into the BIND DN. `{username}` is substituted with the
    /// (validated) username. Examples:
    ///   - RFC4519 directory: `uid={username},ou=people,dc=corp,dc=example`
    ///   - Active Directory UPN bind: `{username}@corp.example`
    ///
    /// Mutually informative with `user_search_filter`: if a search filter is set, the module does
    /// search-then-bind (bind as `bind_service_dn`, find the user, bind as the found DN) instead.
    pub bind_dn_template: String,

    /// The search base for the group read (and for search-then-bind user lookup). e.g.
    /// `dc=corp,dc=example`.
    pub base_dn: String,

    /// The attribute on the user entry that lists group memberships. Default `memberOf` (AD and most
    /// directories). Each value is a group DN.
    #[serde(default = "default_group_attr")]
    pub group_attr: String,

    /// How a group DN becomes a role string. Default [`RoleFrom::Cn`].
    #[serde(default)]
    pub role_from: RoleFrom,

    /// Optional search-then-bind: an LDAP filter to locate the user entry BEFORE binding, e.g.
    /// `(sAMAccountName={username})`. When set, `bind_service_dn`/`bind_service_password` are used to
    /// bind for the search. When absent, the module binds directly with `bind_dn_template`.
    #[serde(default)]
    pub user_search_filter: Option<String>,

    /// Service-account DN for search-then-bind (only used when `user_search_filter` is set).
    #[serde(default)]
    pub bind_service_dn: Option<String>,

    /// Service-account password — a SECRET REFERENCE the operator resolves.
    ///
    /// ABI GAP (secret-ref): the OIDC `client_secret` is a `SecretRef` the CORE resolves and injects
    /// so the plugin never sees it. There is no equivalent seam for a plugin that must present a
    /// *service-account* secret on a socket it opens itself — this is a raw string here, so the
    /// bind-service password would arrive as plaintext in the opaque settings blob (no core-side
    /// secret resolution for plugin-opened connections). See README gap #5.
    #[serde(default)]
    pub bind_service_password: Option<String>,

    /// PEM CA bundle to trust for LDAPS/STARTTLS (private AD CA). Fits in opaque settings — NOT an
    /// ABI gap. (Mirrors auth-oidc's `ca_cert_pem`.)
    #[serde(default)]
    pub ca_cert_pem: Option<String>,

    /// Use STARTTLS over an `ldap://` connection instead of implicit LDAPS.
    #[serde(default)]
    pub start_tls: bool,

    /// Connect/operation timeout (seconds). Default 10.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_group_attr() -> String {
    "memberOf".to_string()
}
fn default_timeout_secs() -> u64 {
    10
}

impl LdapConfig {
    /// The connect/op timeout as a [`Duration`].
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
}

/// The LDAP auth module: a busbar auth plugin that is BOTH a verifier ([`AuthModule`]) and a login
/// provider ([`LoginModule`]). LDAP is a login-only method (it authenticates a form POST, it does not
/// verify opaque bearer tokens on the data plane), so [`AuthModule::authenticate`] returns `Pass` —
/// "not my credential shape" — and the real work is in [`LoginModule::complete_login`].
pub struct LdapModule {
    cfg: LdapConfig,
}

impl LdapModule {
    /// Build the module from parsed config. Validates the DN template references `{username}` so a
    /// misconfiguration fails at boot, not on the first login.
    pub fn new(cfg: LdapConfig) -> Result<Self, String> {
        if !cfg.bind_dn_template.contains("{username}") {
            return Err(
                "ldap bind_dn_template must contain the `{username}` placeholder".to_string(),
            );
        }
        if let Some(f) = &cfg.user_search_filter {
            if !f.contains("{username}") {
                return Err(
                    "ldap user_search_filter must contain the `{username}` placeholder".to_string(),
                );
            }
            if cfg.bind_service_dn.is_none() {
                return Err(
                    "ldap user_search_filter requires bind_service_dn for search-then-bind"
                        .to_string(),
                );
            }
        }
        Ok(Self { cfg })
    }

    /// Expand `bind_dn_template` with a validated username. Returns `Err` if the username contains
    /// characters that would break out of a DN component (LDAP injection defense).
    pub fn bind_dn_for(&self, username: &str) -> Result<String, String> {
        let safe = groups::validate_username(username)?;
        Ok(self.cfg.bind_dn_template.replace("{username}", safe))
    }
}

impl AuthModule for LdapModule {
    fn name(&self) -> &'static str {
        "ldap"
    }

    /// LDAP is a login (form) method, not a data-plane bearer verifier: it has no opaque credential
    /// shape to judge, so it always DEFERS. `Pass` keeps the auth chain moving to the next module.
    fn authenticate(&self, _candidate: Option<&str>) -> AuthOutcome {
        AuthOutcome::Pass
    }

    /// A directory lookup over a socket per login — the engine may cache the resulting identity for
    /// the module-suggested TTL. (Matches the `AuthModule::cacheable` doc's "real I/O per call" case.)
    fn cacheable(&self) -> bool {
        true
    }
}

impl LoginModule for LdapModule {
    /// Start browser login.
    ///
    /// ABI GAP #1 (THE blocking gap): OIDC returns `LoginOutcome::Authorize(url)` and the login page
    /// renders a redirect button. LDAP has NO URL to redirect to — it needs the page to render a
    /// USERNAME/PASSWORD FORM and POST it back to `/auth/token`. `LoginOutcome` has exactly four
    /// variants — `Authorize(String)`, `Exchange(LoginHop)`, `Identify(Principal)`, `Reject` — and
    /// NONE of them can say "collect these credentials from the browser and return them to me". The
    /// core's fail-closed mapping (`map_begin_login`) turns anything that isn't `AuthorizeUrl` into
    /// `Reject`, so even if we returned `Identify` here it would be dropped. There is therefore no way
    /// for begin_login to drive a credential form, and we fail closed.
    ///
    /// PROPOSED FIX (must land in 1.5.2, before the ABI freezes — see README): add
    ///
    /// ```ignore
    /// pub struct LoginField { pub key: String, pub label: String, pub secret: bool }
    /// // in enum LoginOutcome:
    /// Prompt(Vec<LoginField>),   // "render this form; POST the values back to /auth/token"
    /// ```
    ///
    /// The login page renders `Prompt(fields)` as a form (a `secret: true` field → `<input
    /// type=password>`), and the POST feeds the collected values back into `complete_login` (which for
    /// LDAP already has the `username`/`password` slots to receive them). Below we stub at the gap.
    fn begin_login(&self, _req: &BeginLogin) -> LoginOutcome {
        // ABI GAP #1: no `LoginOutcome::Prompt(Vec<LoginField>)` to request a credential form.
        // Fail closed — begin_login cannot express LDAP's form-collect step on the committed ABI.
        LoginOutcome::Reject
    }

    /// Handle the credential POST: BIND with the supplied username/password, read groups, `Identify`.
    ///
    /// This is the half of the ABI that fits LDAP: [`CompleteLogin`] already carries `username` +
    /// `password` (the direct-credential shape), so once the (missing) form path delivers them, this
    /// method does the real work. It opens its OWN LDAP socket here — the loader runs this in-process
    /// with no sandbox (verified: same six-symbol dlopen path as store/secret/vault plugins), so a
    /// plugin-opened socket is allowed. See the two remaining gaps flagged inline.
    fn complete_login(&self, req: &CompleteLogin) -> LoginOutcome {
        // ABI GAP #3 (credential transport / redaction): `req` (and the wire `CompleteLoginRequest`,
        // and `AuthRequest::CompleteLogin`) all derive `Debug`, so `{:?}` on any of them prints the
        // PASSWORD in the clear. OIDC's `client_secret` is structurally kept off the plugin; the LDAP
        // password has to cross to the plugin (only the plugin can bind), and nothing in the ABI
        // redacts it. We must NOT log `req`. There is no `Secret`/redacting wrapper on the
        // password field. See README gap #3.
        let (Some(username), Some(password)) = (req.username.as_deref(), req.password.as_deref())
        else {
            // No credentials on this call. On the committed ABI this is indistinguishable from the
            // OIDC "no token response yet" first hop — but LDAP has no hop, so absent creds = reject.
            return LoginOutcome::Reject;
        };
        if password.is_empty() {
            // Reject an unauthenticated (anonymous) bind attempt outright — an empty password against
            // many directories is an anonymous bind that "succeeds" without authenticating anyone.
            return LoginOutcome::Reject;
        }

        // ABI GAP (async / reactor-blocking): `complete_login` is SYNC and the LDAP bind is blocking
        // network I/O. OIDC never blocks — the CORE executes its HTTP hop on the core's async side.
        // LDAP must do the I/O itself, inside this sync FFI call, which the engine invokes from an
        // async login handler. There is no async seam and no "run me on a blocking thread" contract in
        // the LoginModule ABI, so a correct deployment must ensure the host offloads the plugin call
        // to a blocking thread. Catalogued in README as a secondary gap.
        match self.bind_and_identify(username, password) {
            Ok(principal) => LoginOutcome::Identify(principal),
            Err(BindError::InvalidCredentials) => LoginOutcome::Reject,
            Err(BindError::Directory(e)) => {
                // A directory-side failure (server unreachable, TLS error) is NOT "bad password". The
                // ABI's `LoginOutcome` has no `Error`/`Retry` variant distinct from `Reject`, so an
                // outage is squashed into the same fail-closed verdict as a wrong password — the user
                // sees "login failed" with no way for the page to say "try again later". (Minor gap;
                // additive-later — noted in README.) We at least log the operational detail (never the
                // credential) so an operator can tell the two apart.
                tracing::warn!(module = "ldap", error = %e, "ldap bind/search failed (not a credential rejection)");
                LoginOutcome::Reject
            }
        }
    }
}

/// Why a bind attempt did not yield an identity.
#[derive(Debug)]
enum BindError {
    /// The directory rejected the username/password (LDAP result 49 or a failed search).
    InvalidCredentials,
    /// An operational failure talking to the directory (connect/TLS/timeout/protocol) — NOT a
    /// statement about the credential's validity.
    Directory(String),
}

impl LdapModule {
    /// Open a socket to the directory, BIND with the credentials, read the user's groups, and build a
    /// [`Principal`]. This is the plugin-opens-its-own-socket path (like `hashicorp-vault`).
    ///
    /// Split out from the trait method so the trait method stays a thin ABI-shaped wrapper and this
    /// carries the real LDAP logic. Not exercised by unit tests (needs a live directory); the pure
    /// helpers it calls (`bind_dn_for`, group DN → role mapping, username validation) ARE unit-tested.
    fn bind_and_identify(&self, username: &str, password: &str) -> Result<Principal, BindError> {
        use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};

        // TLS settings. Custom-CA injection (ca_cert_pem) for ldap3's rustls backend would be wired
        // through LdapConnSettings here; the plaintext/default-roots path is implemented, and the
        // custom-CA path is a plugin-impl detail (fits opaque settings — NOT an ABI gap).
        let mut settings = LdapConnSettings::new().set_conn_timeout(self.cfg.timeout());
        if self.cfg.start_tls {
            settings = settings.set_starttls(true);
        }

        let mut ldap = LdapConn::with_settings(settings, &self.cfg.url)
            .map_err(|e| BindError::Directory(format!("connect {}: {e}", self.cfg.url)))?;

        // Resolve the DN to bind as: either search-then-bind, or the direct template.
        let user_dn = if let Some(filter_tpl) = &self.cfg.user_search_filter {
            // Search-then-bind: bind as the service account, find the user entry, take its DN.
            let svc_dn = self.cfg.bind_service_dn.as_deref().unwrap_or("");
            let svc_pw = self.cfg.bind_service_password.as_deref().unwrap_or("");
            ldap.simple_bind(svc_dn, svc_pw)
                .and_then(|r| r.success())
                .map_err(|e| BindError::Directory(format!("service bind: {e}")))?;
            let filter = filter_tpl.replace("{username}", groups::escape_filter(username).as_str());
            let (rs, _res) = ldap
                .search(&self.cfg.base_dn, Scope::Subtree, &filter, vec!["dn"])
                .and_then(|r| r.success())
                .map_err(|e| BindError::Directory(format!("user search: {e}")))?;
            let entry = rs.into_iter().next().ok_or(BindError::InvalidCredentials)?;
            SearchEntry::construct(entry).dn
        } else {
            self.bind_dn_for(username)
                .map_err(|_| BindError::InvalidCredentials)?
        };

        // The credential check: BIND as the user with the presented password. LDAP result code 49
        // (invalidCredentials) surfaces as a non-success rc → InvalidCredentials.
        let bind = ldap
            .simple_bind(&user_dn, password)
            .map_err(|e| BindError::Directory(format!("bind: {e}")))?;
        if bind.rc != 0 {
            return Err(BindError::InvalidCredentials);
        }

        // Read the group-membership attribute off the (now bound) user entry.
        let (rs, _res) = ldap
            .search(
                &user_dn,
                Scope::Base,
                "(objectClass=*)",
                vec![self.cfg.group_attr.as_str()],
            )
            .and_then(|r| r.success())
            .map_err(|e| BindError::Directory(format!("group read: {e}")))?;

        let mut group_dns: Vec<String> = Vec::new();
        if let Some(entry) = rs.into_iter().next() {
            let entry = SearchEntry::construct(entry);
            if let Some(vals) = entry.attrs.get(&self.cfg.group_attr) {
                group_dns.extend(vals.iter().cloned());
            }
        }

        let _ = ldap.unbind();

        let roles = groups::roles_from_group_dns(&group_dns, self.cfg.role_from);
        let mut principal = Principal::from_id(format!("ldap:{username}"));
        principal.roles = roles;
        Ok(principal)
    }
}
