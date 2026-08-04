<!-- SPDX-License-Identifier: Apache-2.0 -->
# busbar-auth-ldap — AD/LDAP auth module (1.5.2 LoginModule ABI stress-test)

This repo is an AD/LDAP auth plugin for busbar. It **began as a design-validation exercise** that stress-tested
the 1.5.2 `LoginModule` ABI (`crates/api/src/auth.rs`) against the one auth flavor that exercises the
**credential path** (username/password) **and opens its own socket** — unlike OIDC/GitHub, which are all
redirect + core-executes-HTTP-hop. The three blocking gaps it surfaced (**#1** credential form, **#2**
redirect-vs-credential classification, **#3** password redaction) then **LANDED in the frozen auth ABI v2**, and
this plugin now implements the **full LDAP credential flow** against it (`login_kind() = Credential`,
`begin_login → Prompt(LoginForm{username,password})`, `complete_login` reads the `submitted` map, BINDs,
`Identify`). The gap list below is kept as the record of that analysis, each blocking gap now annotated
**✅ RESOLVED (v2)**; only the additive-later items (#4-async, #5, #6, #7) remain open, marked `// ABI GAP:`
in-source.

## The intended LDAP flow

dev types username+password on the busbar login page → `POST /auth/token` → core calls the plugin's
`complete_login(username, password)` → plugin opens its **own LDAP/LDAPS socket** and does a **BIND** (the
credential check) → on success reads the user's groups (`memberOf`) → returns
`Identify(Principal{ id: "ldap:<uid>", roles: <groups> })`. **No browser redirect. No HTTP hop.**

---

## GAP LIST (ranked)

### 🔴 GAP #1 — No `LoginOutcome` variant to render a credential FORM  ·  **✅ RESOLVED (v2)**
> Landed as `LoginOutcome::Prompt(LoginForm{ fields: Vec<LoginField{ name, label, kind: FieldKind::{Text,Password}, required }> })` (+ wire mirror in `plugin-abi`). `begin_login` now returns `Prompt([username(Text), password(Password)])`; the core renders it and POSTs the values back. Original analysis below.

- **What LDAP needs:** `begin_login` must tell the hosted login page to render a **username/password form** and
  POST it back to `/auth/token`. OIDC returns `LoginOutcome::Authorize(url)` and the page renders a *redirect
  button*; LDAP has no URL.
- **Why the ABI can't express it:** `LoginOutcome` has exactly four variants —
  `Authorize(String)` · `Exchange(LoginHop)` · `Identify(Principal)` · `Reject`. None means "collect these
  fields from the browser and return them to me." Worse, the core's fail-closed `map_begin_login`
  (`crates/plugin-loader/src/auth.rs`) coerces *anything that isn't `AuthorizeUrl`* to `Reject` on the begin
  path — so the form step is unreachable no matter what the plugin returns.
- **Exact proposed change** (`crates/api/src/auth.rs`, mirrored in `crates/plugin-abi/src/auth.rs`):
  ```rust
  pub struct LoginField { pub key: String, pub label: String, pub secret: bool }
  pub enum LoginOutcome {
      Authorize(String),
      Prompt(Vec<LoginField>),   // NEW: render this form; POST the values back to /auth/token
      Exchange(LoginHop),
      Identify(Principal),
      Reject,
  }
  ```
  Wire side: add `AuthResponse::Prompt(Vec<FieldSpec>)` and admit it in `map_begin_login`. The login page
  renders `Prompt` (a `secret:true` field ⇒ `<input type=password>`); the POST feeds the collected values into
  `complete_login`, whose `username`/`password` slots **already exist** to receive them.
- **Why 1.5.2, not additive:** `LoginOutcome` is a `#[non_exhaustive]`-less public enum in the frozen ABI.
  Adding a variant later is a **breaking change** for every plugin/loader match arm. If credential login is a
  supported shape at all, the variant must exist before the ABI freezes. This is the single 1.5.2-blocking gap.

### 🔴 GAP #2 — The chooser can't classify credential-vs-redirect, and the login-button config is OAuth-only  ·  **✅ RESOLVED (v2)**
> Landed as `enum LoginKind { Redirect, Credential }` + a pure `fn login_kind(&self) -> LoginKind` (default `Redirect`) the chooser reads at load without side effects, plus `client_secret: Option<SecretRef>` (was required) validated per kind — `Credential` methods must have it ABSENT. LDAP returns `login_kind() = Credential` and carries no `client_secret`. Original analysis below.

- **What LDAP needs:** with `oidc` (redirect) + `ldap` (credential) both configured, the chooser must know
  *before the user clicks* that ldap shows a **form** and oidc **redirects** — and it must be able to render an
  ldap button at all.
- **Why the ABI can't express it:** (a) `LoginModule` exposes only `begin_login`/`complete_login`; there is **no
  capability/classification method** and no way to know a method is credential-shaped without calling
  `begin_login` — which for LDAP just fails closed (GAP #1). (b) The gate that decides a plugin can serve the
  browser flow is purely `abi_version >= 2` (`crates/plugin-loader/src/registry.rs`); it says *login-capable*,
  not *redirect vs form*. (c) Structurally worse: what makes a method render a button is the **presence of the
  `browser_login:` config block** (`BrowserLoginCfg` in `crates/busbar/src/config/mod.rs`), and that block
  **requires `client_secret: SecretRef` (non-optional)** — a *confidential-client secret LDAP does not have*.
  So an operator literally cannot render an LDAP button without inventing a bogus `client_secret`.
- **Exact proposed change:** add a classification the chooser can read without side effects. Minimal form — a
  method-kind on the login config plus an optional (not required) secret:
  ```rust
  pub enum LoginKind { Redirect, Credential }   // NEW
  // BrowserLoginCfg:
  pub kind: LoginKind,                 // default Redirect (back-compat with oidc)
  pub client_secret: Option<SecretRef>,// was required; make optional — LDAP has none
  ```
  A `Credential` method renders a form; a `Redirect` method calls `begin_login` for its URL. (Alternatively a
  `fn login_kind(&self) -> LoginKind` on `LoginModule`, but a config-side flag avoids a plugin round-trip at
  page render.)
- **Why 1.5.2:** making `client_secret` optional and adding the kind after the ABI freezes changes a required
  field and the login-config contract — both breaking for a released config schema.

### 🟠 GAP #3 — The password crosses to the plugin with no redaction  ·  **✅ RESOLVED (v2)**
> Landed as `CompleteLogin.submitted: Vec<(String, Redacted<String>)>` (subsuming the old ad-hoc `username`/`password`). Values ride `Redacted` (Debug/Display print `***`, `Zeroize` on drop) on the engine side; the plugin exposes them via `expose_secret()` only at the single documented `complete_login` boundary for the bind. Original analysis below.

- **What LDAP needs:** the password *must* cross to the plugin (only the plugin can BIND). It must not be
  loggable or leak into the error/out channel.
- **Why the ABI can't express it:** the ABI is deliberately asymmetric — OIDC's `client_secret` is
  **structurally kept off the plugin** (the core injects it into the hop's `secret_form_field`; `BeginLogin`
  has *no secret field* by design). But the LDAP password rides `CompleteLogin.password: Option<String>` /
  wire `CompleteLoginRequest.password`, and **every carrier derives `Debug`** (`CompleteLogin`,
  `CompleteLoginRequest`, `AuthRequest::CompleteLogin`) — so `{:?}` prints the password in the clear (asserted
  in `complete_login_carries_username_password`). There is no `Secret`-wrapper / redacting type and no
  documented "never log this" contract on the field, whereas the secret path got a structural guarantee.
- **Exact proposed change:** wrap the field in a redacting newtype whose `Debug`/`Display` print `***`:
  ```rust
  pub struct Redacted(String);              // Debug/Display => "***"; explicit .expose() to read
  pub struct CompleteLogin { /* … */ pub password: Option<Redacted>, /* … */ }
  ```
  Same on the wire type (it can still `serde` as a bare string). This gives the credential path the same
  can't-accidentally-leak property the secret path already has.
- **Why ideally 1.5.2:** changing the field type is breaking; doing it post-freeze is a second breaking change.
  Cheap to land now. (If deferred, it's *mitigable* by convention — "never `Debug` the request" — so it is a
  notch below #1/#2, but the structural fix belongs with the ABI.)

### 🟢 GAP #4 — Plugin-opens-socket: **NOT a gap.** (Verified allowed.)
- Auth plugins load over the **exact same six-symbol dlopen path** as store/secret/hook plugins
  (`export_login_plugin!` → `export_plugin!`, `crates/plugin-sdk/src/lib.rs`); the loader has **no sandbox, no
  seccomp, no network broker** — it runs the cdylib in-process. `hashicorp-vault` opens its own blocking HTTPS
  socket inside a sync `resolve()`; LDAP does the same inside `complete_login`. So a plugin-opened LDAP/LDAPS
  socket is fully allowed. **This part of the ABI fits LDAP cleanly.**
- **BUT — secondary async gap (🟠 additive-later):** `LoginModule::complete_login` is **synchronous**, and the
  LDAP BIND is **blocking network I/O**, invoked by the engine from an **async** login handler. OIDC never
  blocks (the core runs its hop on its own async side); LDAP has nowhere to put the I/O but inside the sync FFI
  call. There is no async seam and no "offload me to a blocking thread" contract in the `LoginModule` ABI, so a
  correct deployment depends on the host wrapping the plugin call in `spawn_blocking`. Marked
  `// ABI GAP (async):` in `complete_login`. Additive-later (a host-side convention / a documented threading
  contract fixes it without changing the ABI types).

### 🟢 GAP #5 — LDAPS/TLS, CA, bind-DN template, base-DN, group attr: **mostly fit; one small secret-ref gap**
- URL, `bind_dn_template`, `base_dn`, `group_attr`, `ca_cert_pem`, `start_tls`, `role_from`, timeouts all fit in
  the method's **opaque `settings` map** (`AuthMethodCfg { #[serde(flatten)] settings }`) — the engine never
  needs to understand them. This is the same clean opaque-config seam OIDC and Vault use. **No ABI gap.**
- **Small gap (🟠 additive-later):** search-then-bind needs a **service-account password**. OIDC's
  `client_secret` is a `SecretRef` the *core* resolves and injects so the plugin never sees it. There is **no
  equivalent core-side secret-resolution seam for a secret a plugin needs to present on a socket it opens
  itself** — so `bind_service_password` arrives as **plaintext inside the opaque settings blob**
  (`// ABI GAP (secret-ref)` in `LdapConfig`). Additive-later: extend the settings-resolution path to expand
  `SecretRef`s inside opaque plugin settings before `open()`.

### 🟢 GAP #6 — Group DN → role normalization is pushed entirely onto the plugin  ·  **additive-later**
- LDAP/AD groups are **DNs** (`CN=engineers,OU=Groups,DC=corp,DC=example`). `Principal.roles` (wire
  `Identity.groups`) is `Vec<String>` and `auth.role_bindings.ldap` keys policy on those strings, so a DN
  *works* verbatim — **the type fits**. But a DN is a hostile `role_bindings` key: commas + `=` (awkward YAML
  keys), **LDAP-case-insensitive but map-case-sensitive**, and OU-path-specific. The engine offers no DN
  normalization, so the plugin must choose the shape — this crate's `RoleFrom::{Cn,Dn}` (default `Cn`, tested).
  Not an ABI blocker; an engine-side DN-normalizing role mapper would be a nice additive-later ergonomic.

### 🟠 GAP #7 — No verdict distinct from `Reject` for "wrong password (retry)" vs "directory down"  ·  additive-later
- On a login form, a wrong password should re-render the form ("try again"); a directory outage is a 5xx
  ("try later"). `LoginOutcome` collapses both into `Reject` (fail-closed, stop the chain) — there is no
  `Retry`/`Error` verdict, so `complete_login` squashes an outage into the same result as a bad credential
  (marked inline; we log the operational detail, never the credential). Additive-later — a new terminal variant
  is only additive if `LoginOutcome` is already being reopened for GAP #1 (in which case land it together).

---

## What the ABI got RIGHT for LDAP (fits cleanly)
- **The generic `submitted: Vec<(String, Redacted<String>)>` map** (v2, subsuming the old ad-hoc
  `username`/`password`) delivers the form values keyed by the field `name` the plugin declared in `Prompt` —
  `complete_login` reads `submitted["username"]`/`submitted["password"]` with zero ABI friction, and a future
  method declaring `[username, password, totp]` just works.
- **`Identify(Principal{ id, roles, ttl_secs })`** maps to LDAP 1:1: `id = "ldap:<uid>"`, `roles = groups`,
  `ttl_secs` for the identity cache. `Identity ↔ Principal` (`groups ↔ roles`) is lossless.
- **`cacheable() = true`** is exactly the documented "real I/O per call" case — the engine caches the identity.
- **Plugin-opens-socket is allowed** (GAP #4) — no sandbox; same in-process dlopen as vault.
- **Opaque `settings`** carry every LDAP knob without the engine understanding any of them (GAP #5).
- **`authenticate` → `Pass`** cleanly models "LDAP is a login method, not a data-plane bearer verifier" — it
  defers and the chain continues.

## The plugin (implemented against frozen auth ABI v2)
- **Compiles + gate-green** against the frozen v2 ABI (`cargo build` / `test` / `clippy -D warnings` /
  `fmt --check`; path-deps into the `busbarAI` core checkout). Two-crate layout mirroring `auth-oidc`:
  `busbar-auth-ldap` (logic) + `busbar-auth-ldap-plugin` (cdylib, `export_login_plugin!`). Manifest
  `abi_version = 2`.
- **Full credential flow:** `login_kind() = Credential`; `begin_login → Prompt(LoginForm{ username(Text),
  password(Password) })`; `complete_login` reads the `submitted` map (`Redacted` values, exposed only for the
  bind), opens its OWN LDAP socket, BINDs, reads groups, `Identify`. No `client_secret` (structurally absent).
- **Real LDAP BIND + group read** via `ldap3` (sync, rustls TLS), incl. direct-bind and search-then-bind,
  LDAPS/STARTTLS, and DN→role mapping.
- **Remaining `// ABI GAP:` markers** are the additive-later items only (#5 secret-ref for the service-account
  password; #4-async sync/blocking I/O).
- **Tests: 22 passing** (18 lib + 4 plugin). Cover config parse + `deny_unknown_fields` incl. **client_secret
  rejected**, bind-DN templating + **LDAP-injection rejection**, RFC4515 filter escaping, group-DN → role
  mapping (CN/DN, dedup, escaped commas), the `authenticate` defer, `login_kind() = Credential`, the
  `begin_login` `Prompt` form shape, the `submitted`-map field parsing (+ `Redacted` never leaks in `Debug`),
  and `complete_login` credential guards (missing/empty). The live-bind happy path is integration-only.

## Recommendation
**The three 1.5.2-blocking gaps LDAP surfaced (#1 credential form, #2 redirect-vs-credential classification, #3
password redaction) all landed in the frozen auth ABI v2** — `LoginOutcome::Prompt(LoginForm)`, a pure
`login_kind()` classifier with `client_secret` made `Optional` + per-kind validated, and the generic
`submitted: Vec<(String, Redacted<String>)>` transport. This plugin now implements the full flow against them
with zero remaining blockers. GAP #4-async, #5-secret-ref, #6, #7 stay **additive-later** and do not block the
freeze.
