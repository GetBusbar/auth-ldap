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
//! ## Auth ABI v2 — the LDAP credential method
//!
//! This module requires auth ABI v2, the version that carries the credential login flow:
//!
//! - [`login_kind`](LdapModule::login_kind) declares [`LoginKind::Credential`] so the chooser renders
//!   a form (not a redirect button) WITHOUT any side-effecting `begin_login` call.
//! - [`begin_login`](LdapModule::begin_login) returns [`LoginOutcome::Prompt`] with a declarative
//!   [`LoginForm`] (`username` Text + `password` Password) for the core to render.
//! - [`complete_login`](LdapModule::complete_login) reads the submitted values back by the field
//!   `name` it declared (via [`CompleteLogin::submitted`], the one documented plaintext boundary),
//!   opens its OWN LDAP socket, BINDs, reads groups, and returns `Identify`.
//! - LDAP is a `Credential` method, so it has NO confidential-client `client_secret` — `LdapConfig`
//!   structurally has no such field and `deny_unknown_fields` rejects one if configured.

use busbar_api::{
    AuthModule, AuthOutcome, BeginLogin, CompleteLogin, FieldKind, LoginField, LoginForm,
    LoginKind, LoginModule, LoginOutcome, Principal,
};
use core::fmt;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;

pub mod groups;

#[cfg(test)]
mod tests;

/// The maximum number of `memberOf` group values read off a user entry. A hostile or misconfigured
/// directory could list an unbounded number of groups; collection is capped here to bound memory.
/// 4096 is far above any real-world group membership; the module logs when it truncates.
const MAX_GROUP_VALUES: usize = 4096;

/// A secret string that NEVER reveals itself through `Debug`/`Display`.
///
/// The end-user password rides `Redacted` across the wire, but the service-account bind password
/// lives on the `#[derive(Debug)]` [`LdapConfig`], where a bare `String` could leak into a log line,
/// a `tracing` field, or a panic/`{:?}` dump. This wrapper makes the redaction STRUCTURAL.
/// `#[serde(transparent)]` keeps deserialization identical (a plain JSON
/// string), and the plaintext is reachable only through the explicit [`SecretString::expose`] audit
/// point.
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    /// Borrow the underlying secret. AUDIT POINT — the one place the plaintext escapes redaction.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

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
/// templates, TLS/CA, group attribute) fits here as opaque module settings: the engine never needs
/// to understand any of these fields.
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
    /// secret resolution for plugin-opened connections). See Limitations in the README.
    #[serde(default)]
    pub bind_service_password: Option<SecretString>,

    /// PEM CA bundle to trust for LDAPS/STARTTLS (private AD CA). Deserialized for forward
    /// compatibility, but the custom-CA TLS wiring is NOT implemented — [`LdapModule::new`] rejects a
    /// config that sets it (fail-closed) rather than silently ignoring it and lulling an operator into
    /// believing a private CA is trusted when it is not.
    #[serde(default)]
    pub ca_cert_pem: Option<String>,

    /// Use STARTTLS over an `ldap://` connection instead of implicit LDAPS.
    #[serde(default)]
    pub start_tls: bool,

    /// Escape hatch for the plaintext-transport guard. By default a plaintext `ldap://` URL to a
    /// NON-loopback host with no STARTTLS is REJECTED at config time, because it would send the
    /// service-account AND every end-user password across the network in cleartext. Set this to
    /// `true` to knowingly override that guard (e.g. a trusted, isolated network segment). It does
    /// nothing for `ldaps://`, for STARTTLS, or for a loopback host — those are already secure/local.
    #[serde(default)]
    pub allow_insecure_transport: bool,

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
        // Fail CLOSED on an unsupported CA bundle: `ca_cert_pem` is documented as "a CA bundle to
        // trust" but the custom-CA TLS path is not wired. Accepting-and-ignoring it would silently
        // fall back to the system trust roots while the operator believes their private CA is in use.
        if cfg.ca_cert_pem.is_some() {
            return Err(
                "ldap ca_cert_pem is not yet supported; omit it or use a system-trusted cert"
                    .to_string(),
            );
        }
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
            // A service DN with NO password — or a present-but-EMPTY one — would perform
            // `simple_bind(dn, "")`, an UNAUTHENTICATED bind on most directories. Require a
            // NON-EMPTY password so search-then-bind is always authenticated.
            match cfg.bind_service_password.as_ref() {
                None => {
                    return Err(
                        "ldap user_search_filter requires bind_service_password for \
                         search-then-bind (a missing password becomes an unauthenticated bind)"
                            .to_string(),
                    );
                }
                Some(pw) if pw.expose().is_empty() => {
                    return Err(
                        "ldap bind_service_password must not be empty (an empty password becomes \
                         an unauthenticated bind for search-then-bind)"
                            .to_string(),
                    );
                }
                Some(_) => {}
            }
        }
        // Fail CLOSED on a plaintext transport that would expose credentials on the network: a
        // `ldap://` URL (not `ldaps://`) with no STARTTLS, to a non-loopback host, sends the
        // service-account AND every end-user password in cleartext. Reject unless the operator
        // explicitly opts out. `ldaps://`, STARTTLS, or a loopback host are already secure/local.
        if is_insecure_transport(&cfg.url, cfg.start_tls) && !cfg.allow_insecure_transport {
            return Err(format!(
                "ldap url {:?} uses plaintext ldap:// to a non-loopback host with no STARTTLS, \
                 which sends the service and end-user credentials in cleartext; use an ldaps:// \
                 URL, set start_tls = true, or (to knowingly override) set \
                 allow_insecure_transport = true",
                cfg.url
            ));
        }
        Ok(Self { cfg })
    }

    /// Expand `bind_dn_template` with a validated username. Returns `Err` if the username contains
    /// characters that would break out of a DN component (LDAP injection defense).
    pub(crate) fn bind_dn_for(&self, username: &str) -> Result<String, String> {
        let safe = groups::validate_username(username)?;
        Ok(self.cfg.bind_dn_template.replace("{username}", safe))
    }
}

/// Would binding over this URL send credentials in CLEARTEXT on the network? True only for a
/// plaintext `ldap://` scheme (not `ldaps://`), with STARTTLS off, to a NON-loopback host. `ldaps://`
/// is implicit TLS; STARTTLS upgrades the `ldap://` socket; a loopback host never leaves the box.
fn is_insecure_transport(url: &str, start_tls: bool) -> bool {
    let url = url.trim();
    // Implicit LDAPS is already encrypted. Compare on BYTES (not `url[..8]`, which panics if a
    // multi-byte UTF-8 char straddles byte index 8) — the scheme is ASCII, so a byte compare is exact.
    if url.len() >= 8 && url.as_bytes()[..8].eq_ignore_ascii_case(b"ldaps://") {
        return false;
    }
    // STARTTLS upgrades the plaintext socket to TLS before any bind.
    if start_tls {
        return false;
    }
    // Anything else here is a plaintext `ldap://` (or scheme-less) connection: only safe to a
    // loopback host, which never puts the credential on the wire.
    !is_loopback_host(host_of(url))
}

/// Extract the host from an `ldap://host:port` / `ldaps://host:port` URL, tolerating an `[::1]`
/// bracketed IPv6 literal and an absent scheme. Returns the raw host with no port or path.
fn host_of(url: &str) -> &str {
    let after = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    // The authority ends at the first '/' (path).
    let authority = after.split('/').next().unwrap_or("");
    // Strip any userinfo: everything up to and including the LAST '@'. WITHOUT this, a URL like
    // `ldap://127.0.0.1:389@evil.com` reads as loopback here while ldap3 actually dials `evil.com`
    // in cleartext — a fail-OPEN bypass of the plaintext guard.
    let hostport = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    if let Some(rest) = hostport.strip_prefix('[') {
        // Bracketed IPv6 literal: the host is everything up to the closing bracket.
        if let Some(end) = rest.find(']') {
            return &rest[..end];
        }
    }
    // Otherwise the host ends at the first ':' (port).
    hostport.split(':').next().unwrap_or("")
}

/// Is this host a loopback address that never leaves the machine? Matches the canonical trio only —
/// `127.0.0.1`, `::1`, `localhost` — case-insensitively.
fn is_loopback_host(host: &str) -> bool {
    let host = host.trim();
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
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

/// Look up a submitted credential field by the `name` the plugin declared in its [`LoginForm`].
/// This is the ONE place the [`Redacted`](busbar_api::Redacted) value is exposed as plaintext — the
/// documented `complete_login` credential boundary (only the plugin can perform the bind). Callers
/// must NOT log the result.
fn submitted_field<'a>(req: &'a CompleteLogin, name: &str) -> Option<&'a str> {
    req.submitted
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.expose_secret().as_str())
}

impl LoginModule for LdapModule {
    /// LDAP is a direct-credential (form) method, not a redirect: the chooser reads this ONCE at load
    /// to render a username/password form instead of a redirect button — no side-effecting
    /// `begin_login` call, no PKCE state minted.
    fn login_kind(&self) -> LoginKind {
        LoginKind::Credential
    }

    /// Start browser login. LDAP has no external authorize URL — it returns a declarative
    /// [`LoginForm`] the core renders as a form and POSTs back. The fields are generic (the core
    /// renders whatever the plugin declares): `username` (Text) + `password` (Password, masked +
    /// carried [`Redacted`](busbar_api::Redacted) on the wire). No PKCE/redirect is used.
    fn begin_login(&self, _req: &BeginLogin) -> LoginOutcome {
        LoginOutcome::Prompt(LoginForm {
            fields: vec![
                LoginField {
                    name: "username".to_string(),
                    label: "Username".to_string(),
                    kind: FieldKind::Text,
                    required: true,
                },
                LoginField {
                    name: "password".to_string(),
                    label: "Password".to_string(),
                    kind: FieldKind::Password,
                    required: true,
                },
            ],
        })
    }

    /// Handle the credential POST: read the submitted `username`/`password` (keyed by the field names
    /// declared in [`begin_login`](Self::begin_login)), BIND against the directory, read groups,
    /// `Identify`.
    ///
    /// It opens its OWN LDAP socket here — the loader runs this in-process with no sandbox (same
    /// six-symbol dlopen path as store/secret/vault plugins), so a plugin-opened socket is allowed.
    /// The password crosses as a [`Redacted`](busbar_api::Redacted) value on the engine side and is
    /// exposed only via [`submitted_field`] for the bind; we never log `req` or the exposed values.
    fn complete_login(&self, req: &CompleteLogin) -> LoginOutcome {
        let (Some(username), Some(password)) = (
            submitted_field(req, "username"),
            submitted_field(req, "password"),
        ) else {
            // No credentials submitted on this call — nothing to bind. Fail closed.
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
        // to a blocking thread. See Limitations in the README.
        match self.bind_and_identify(username, password) {
            Ok(principal) => LoginOutcome::Identify(principal),
            Err(BindError::InvalidCredentials) => LoginOutcome::Reject,
            Err(BindError::Directory(e)) => {
                // A directory-side failure (server unreachable, TLS error) is NOT "bad password". The
                // ABI's `LoginOutcome` has no `Error`/`Retry` variant distinct from `Reject`, so an
                // outage is squashed into the same fail-closed verdict as a wrong password — the user
                // sees "login failed" with no way for the page to say "try again later". (Minor gap;
                // see Limitations in the README.) The operational detail is logged (never the
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

/// Scope of an [`LdapBackend::search`] — the two the module uses.
#[derive(Clone, Copy)]
pub(crate) enum SearchScope {
    /// The entry named by `base` itself (used for the group read).
    Base,
    /// The whole subtree under `base` (used for the search-then-bind user lookup).
    Subtree,
}

/// A directory entry reduced to what the module reads: its DN and requested attributes.
#[derive(Clone, Default)]
pub(crate) struct DirEntry {
    pub dn: String,
    pub attrs: HashMap<String, Vec<String>>,
}

/// The minimal LDAP operations [`LdapModule::bind_and_identify_on`] needs, abstracted behind a trait
/// so the post-connect bind logic (result-code handling, ambiguity, group cap, roles, principal id)
/// is UNIT-TESTABLE against a fake in-memory directory. The production impl ([`RealLdap`]) drives an
/// `ldap3::LdapConn`; tests drive a fake.
pub(crate) trait LdapBackend {
    /// Bind with the given DN + password. `Ok(rc)` is the LDAP result code (0 = success, e.g. 49 =
    /// invalidCredentials); `Err` is an operational/transport failure (connect/TLS/timeout), NOT a
    /// statement about the credential's validity.
    fn simple_bind(&mut self, dn: &str, password: &str) -> Result<u32, String>;

    /// Run a search and return the matched entries. `Err` is an operational failure (which includes a
    /// non-success result code).
    fn search(
        &mut self,
        base: &str,
        scope: SearchScope,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<DirEntry>, String>;

    /// Best-effort unbind/close of the connection.
    fn unbind(&mut self);
}

/// The production [`LdapBackend`]: a real `ldap3::LdapConn` plus the configured per-operation timeout,
/// re-applied before EVERY operation (`with_timeout` is consumed per-op) so a hung directory cannot
/// block a login indefinitely — the connect timeout alone does not bound the bind/search operations.
struct RealLdap {
    conn: ldap3::LdapConn,
    timeout: Duration,
}

impl LdapBackend for RealLdap {
    fn simple_bind(&mut self, dn: &str, password: &str) -> Result<u32, String> {
        self.conn.with_timeout(self.timeout);
        let r = self
            .conn
            .simple_bind(dn, password)
            .map_err(|e| e.to_string())?;
        Ok(r.rc)
    }

    fn search(
        &mut self,
        base: &str,
        scope: SearchScope,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<DirEntry>, String> {
        use ldap3::{Scope, SearchEntry};
        let scope = match scope {
            SearchScope::Base => Scope::Base,
            SearchScope::Subtree => Scope::Subtree,
        };
        self.conn.with_timeout(self.timeout);
        let (rs, _res) = self
            .conn
            .search(base, scope, filter, attrs.to_vec())
            .and_then(|r| r.success())
            .map_err(|e| e.to_string())?;
        Ok(rs
            .into_iter()
            .map(|e| {
                let e = SearchEntry::construct(e);
                DirEntry {
                    dn: e.dn,
                    attrs: e.attrs,
                }
            })
            .collect())
    }

    fn unbind(&mut self) {
        let _ = self.conn.unbind();
    }
}

/// Build the STABLE principal id from the resolved bind DN. The submitted username is user-controlled
/// in its CASING (`Alice`/`alice`) and form (`DOMAIN\alice`); using it raw would mint DIFFERENT
/// identities — and duplicate self-serve keys — for the SAME person. LDAP DNs are case-insensitive,
/// so we key identity on the resolved DN lowercased: exactly one canonical `ldap:<dn>` per directory
/// identity, in both direct-template and search-then-bind modes. Lowercasing is Unicode-aware
/// (`to_lowercase`, not `to_ascii_lowercase`) — `validate_username` allows non-ASCII names, so an
/// ASCII-only fold would mint two distinct principals for two casings of a non-ASCII username.
fn principal_id(user_dn: &str) -> String {
    format!("ldap:{}", user_dn.to_lowercase())
}

impl LdapModule {
    /// Open a socket to the directory, BIND with the credentials, read the user's groups, and build a
    /// [`Principal`]. This is the plugin-opens-its-own-socket path (like `hashicorp-vault`).
    ///
    /// A thin wrapper: it constructs the real [`RealLdap`] backend (TLS settings, connect + operation
    /// timeout) and delegates the actual bind/search/group logic to [`Self::bind_and_identify_on`],
    /// which is generic over [`LdapBackend`] and fully unit-tested against a fake directory.
    fn bind_and_identify(&self, username: &str, password: &str) -> Result<Principal, BindError> {
        use ldap3::{LdapConn, LdapConnSettings};

        // TLS/connect settings. `set_conn_timeout` bounds the CONNECT; the per-operation timeout is
        // re-applied inside `RealLdap` before each bind/search. (Custom-CA `ca_cert_pem` is rejected
        // at config time — see `LdapModule::new` — so only system-trusted roots are in play here.)
        let mut settings = LdapConnSettings::new().set_conn_timeout(self.cfg.timeout());
        if self.cfg.start_tls {
            settings = settings.set_starttls(true);
        }

        let conn = LdapConn::with_settings(settings, &self.cfg.url)
            .map_err(|e| BindError::Directory(format!("connect {}: {e}", self.cfg.url)))?;
        let mut backend = RealLdap {
            conn,
            timeout: self.cfg.timeout(),
        };
        self.bind_and_identify_on(&mut backend, username, password)
    }

    /// The post-connect bind/search/group logic, generic over [`LdapBackend`] so the reject paths are
    /// unit-testable. Resolves the bind DN (search-then-bind or direct template), rejects a non-zero
    /// user-bind result code, rejects an empty or AMBIGUOUS (>1 match) search, CAPS the number of
    /// group values read, and builds a stable, normalized principal id.
    fn bind_and_identify_on<B: LdapBackend>(
        &self,
        ldap: &mut B,
        username: &str,
        password: &str,
    ) -> Result<Principal, BindError> {
        // Resolve the DN to bind as: either search-then-bind, or the direct template.
        let user_dn = if let Some(filter_tpl) = &self.cfg.user_search_filter {
            // The direct-template path runs the username through `validate_username` (which rejects
            // an empty username); the search path must guard it too — an empty username has no
            // identity to resolve. Fail as invalid credentials, never reach the socket.
            if username.is_empty() {
                return Err(BindError::InvalidCredentials);
            }
            // Search-then-bind: bind as the service account, find the user entry, take its DN.
            // `new()` guarantees both bind_service_dn and bind_service_password are present here.
            let svc_dn = self.cfg.bind_service_dn.as_deref().unwrap_or("");
            let svc_pw = self
                .cfg
                .bind_service_password
                .as_ref()
                .map(SecretString::expose)
                .unwrap_or("");
            let rc = ldap
                .simple_bind(svc_dn, svc_pw)
                .map_err(|e| BindError::Directory(format!("service bind: {e}")))?;
            if rc != 0 {
                return Err(BindError::Directory(format!(
                    "service bind rejected (rc={rc})"
                )));
            }
            let filter = filter_tpl.replace("{username}", groups::escape_filter(username).as_str());
            let entries = ldap
                .search(&self.cfg.base_dn, SearchScope::Subtree, &filter, &["dn"])
                .map_err(|e| BindError::Directory(format!("user search: {e}")))?;
            // Ambiguous: more than one entry matched. Fail CLOSED rather than silently binding the
            // first — we cannot establish a single, unambiguous identity for the credential.
            if entries.len() > 1 {
                tracing::warn!(
                    module = "ldap",
                    matches = entries.len(),
                    "ldap user_search_filter matched multiple entries; rejecting as ambiguous"
                );
                return Err(BindError::InvalidCredentials);
            }
            let entry = entries
                .into_iter()
                .next()
                .ok_or(BindError::InvalidCredentials)?;
            // Guard an empty resolved DN before binding: `simple_bind("", password)` is an anonymous
            // bind on many directories and would "succeed" without authenticating anyone.
            if entry.dn.is_empty() {
                return Err(BindError::InvalidCredentials);
            }
            entry.dn
        } else {
            self.bind_dn_for(username)
                .map_err(|_| BindError::InvalidCredentials)?
        };

        // The credential check: BIND as the user with the presented password. A non-zero result code
        // (e.g. 49 invalidCredentials) is a credential rejection.
        let rc = ldap
            .simple_bind(&user_dn, password)
            .map_err(|e| BindError::Directory(format!("bind: {e}")))?;
        if rc != 0 {
            return Err(BindError::InvalidCredentials);
        }

        // Read the group-membership attribute off the (now bound) user entry.
        let entries = ldap
            .search(
                &user_dn,
                SearchScope::Base,
                "(objectClass=*)",
                &[self.cfg.group_attr.as_str()],
            )
            .map_err(|e| BindError::Directory(format!("group read: {e}")))?;

        let mut group_dns: Vec<String> = Vec::new();
        if let Some(entry) = entries.into_iter().next() {
            if let Some(vals) = entry.attrs.get(&self.cfg.group_attr) {
                // Cap the number of group values collected so a hostile/huge memberOf cannot exhaust
                // memory (see MAX_GROUP_VALUES). Log when truncating so an operator can spot it.
                if vals.len() > MAX_GROUP_VALUES {
                    tracing::warn!(
                        module = "ldap",
                        count = vals.len(),
                        cap = MAX_GROUP_VALUES,
                        "memberOf exceeded cap; truncating group values"
                    );
                }
                group_dns.extend(vals.iter().take(MAX_GROUP_VALUES).cloned());
            }
        }

        ldap.unbind();

        let roles = groups::roles_from_group_dns(&group_dns, self.cfg.role_from);
        let mut principal = Principal::from_id(principal_id(&user_dn));
        principal.roles = roles;
        Ok(principal)
    }
}
