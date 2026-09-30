<!-- fleet:header:begin (rendered by `cargo xtask fleet render` from GetBusbar/busbar's plugins.yaml; edit it there) -->
# busbar-auth-ldap

The AD/LDAP auth module as a droppable busbar plugin: a cdylib exporting the auth C ABI. Drop it in the plugins folder, define it once under identity-providers.<name> (module: ldap, settings: url, bind_dn_template, base_dn, group_attr) and reference that name from auth.chain.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `auth` | `ldap` | `busbar-auth-ldap-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-auth-ldap/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-auth-ldap/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

<!-- SPDX-License-Identifier: Apache-2.0 -->

[![Coverage](https://codecov.io/gh/GetBusbar/busbar-auth-ldap/branch/dev/graph/badge.svg)](https://codecov.io/gh/GetBusbar/busbar-auth-ldap)

The first-party, signed `kind: auth` plugin for
[busbar](https://getbusbar.com) that authenticates a username and
password against an AD/LDAP directory: a real LDAP/LDAPS **BIND** as the
credential check, a group read off the bound user, and a group-DN → role
mapping that hands busbar a `Principal` it can bind to virtual keys and
roles.

It is a `cdylib` that implements busbar's `AuthModule` and `LoginModule`
traits (via
[`busbar-contract`](https://github.com/GetBusbar/busbar/tree/main/crates/busbar-contract))
and is loaded in-process by busbar over the signed hybrid plugin ABI —
`dlopen`'d, not spawned as a separate process. The credential login flow
it uses is carried by the auth ABI from v2 on; this plugin is built at
auth ABI 3 and declares `contract_abi` 3 (`auth-ldap/declares.json`).

It is a **separate plugin from `busbar-auth-oidc`**, and takes a
different shape: OIDC is a redirect flow where the core executes the
token-exchange HTTP hop, while LDAP is a direct credential flow where the
plugin opens its own socket — the same in-process model
`hashicorp-vault` uses for its HTTPS calls.

### The login flow

1. A user types a username and password on busbar's hosted login page.
   `login_kind()` returns `Credential`, so the method chooser renders a
   form rather than a redirect button, without having to call
   `begin_login` first.
2. `begin_login` returns `LoginOutcome::Prompt(LoginForm)` declaring two
   fields — `username` (text) and `password` (password) — which the core
   renders and POSTs back to `/auth/token`.
3. `complete_login` reads those values back out of `CompleteLogin::
   submitted`, keyed by the field names the plugin declared. The values
   ride `Redacted` (`Debug` prints `[REDACTED]`, zeroized on drop) and
   are exposed only at that one boundary, for the bind.
4. The plugin opens its own LDAP/LDAPS socket and BINDs with the user's
   DN and password. That bind *is* the credential check — no token, no
   redirect.
5. On a successful bind it reads the user's group memberships
   (`memberOf` by default) and returns
   `LoginOutcome::Identify(Principal)` with `id = "ldap:<the full lowercased bind DN>"` and
   `roles` set from the mapped group names.

Because LDAP is a login method rather than a data-plane bearer verifier,
`AuthModule::authenticate` returns `Pass` — "not my credential shape" —
and the auth chain continues.

There is no `client_secret`: a credential method is not a confidential
OAuth client, so `LdapConfig` has no such field and
`deny_unknown_fields` rejects one if it is configured.

### Design

This repo is a same-repo, 2-crate Cargo workspace, mirroring `auth-oidc`:
`auth-ldap/` (the `busbar-auth-ldap` library — the real LDAP BIND,
group-read and role-mapping logic, no plugin ABI) and
`auth-ldap-plugin/` (the `busbar-auth-ldap-plugin` cdylib adapter, which
is a thin `export_login_plugin!` shim). A custom build can link the
library crate statically instead of going through the plugin ABI.

LDAP work is done with [`ldap3`](https://crates.io/crates/ldap3) in its
`sync` + `tls-rustls` configuration: the blocking `LdapConn` is what the
synchronous `LoginModule::complete_login` signature needs, and rustls
keeps the plugin on the same TLS backend as the rest of the ecosystem
rather than pulling in a second, OpenSSL-based stack.

Two directory shapes are supported:

- **Direct bind** — `bind_dn_template` turns the username into a DN
  (`uid={username},ou=people,dc=corp,dc=example`) and the plugin binds as
  that DN, then reads the groups off that same entry. The template must
  expand to a DN: one with no `=` (an AD UPN such as
  `{username}@corp.example`) is refused at boot.
- **Search-then-bind** — set `user_search_filter` (e.g.
  `(sAMAccountName={username})`, or `(userPrincipalName={username})` for
  AD UPN logins) and the plugin first binds as `bind_service_dn`, locates
  the user entry, then re-binds as the DN it found. This is the mode for
  Active Directory.

A crafted username cannot inject DN components or filter syntax: on the
DN template path a username carrying a DN special character (`,` `=` `+`
`<` `>` `;` `\` `"`, or a control character) is rejected, and on the
search filter path the username is RFC 4515-escaped.

## Config

Configured like any other busbar auth method — an entry under
`identity-providers:` referenced by name from `auth.chain`:

```yaml
identity-providers:
  corp-ldap:                 # the NAME is the instance; `module:` is the plugin behind it
    module: ldap
    settings:
      url: "ldaps://ad.corp.example:636"
      bind_dn_template: "cn={username},cn=users,dc=corp,dc=example"
      base_dn: "dc=corp,dc=example"
      user_search_filter: "(userPrincipalName={username})"
      bind_service_dn: "cn=busbar-svc,cn=users,dc=corp,dc=example"
      bind_service_password: "<service account password>"
      role_from: cn

auth:
  chain: [keys, corp-ldap]   # built-ins (`keys`, `admin-tokens`) are referenced bare
```

Group-to-role mapping is keyed by that same provider name:

```yaml
auth:
  role_bindings:
    corp-ldap:
      engineers: { group: engineering }
```

| Setting | Required | Default | Notes |
|---|---|---|---|
| `url` | yes | — | `ldaps://host:636` (implicit TLS), or `ldap://host:389` for plaintext/STARTTLS. |
| `bind_dn_template` | yes | — | Turns a username into the bind DN. Must contain `{username}`; validated at boot. In direct-bind mode it must expand to a DN (contain `=`). |
| `base_dn` | yes | — | Search base for the search-then-bind user lookup; must not be empty when `user_search_filter` is set. (The group read is a base read of the bound user's own entry.) |
| `group_attr` | no | `memberOf` | The attribute on the user entry listing group memberships. Each value is a group DN. Must not be empty. |
| `role_from` | no | `cn` | How a group DN becomes a role string: `cn` takes the value of the first `CN=` RDN in the directory's own case (a value with no `CN=` RDN is used whole, trimmed); `dn` uses the full DN, trimmed and lowercased. `role_bindings` keys must match that spelling exactly. |
| `user_search_filter` | no | — | Enables search-then-bind. Must contain `{username}`; requires `bind_service_dn`. |
| `bind_service_dn` | no | — | Service-account DN used for the search-then-bind lookup. |
| `bind_service_password` | no | — | Service-account password. Held in a redacting wrapper; see [Limitations](#limitations). |
| `ca_cert_pem` | no | — | Reserved. A config that sets it is **rejected at boot** — see [Limitations](#limitations). |
| `start_tls` | no | `false` | Use STARTTLS over an `ldap://` connection instead of implicit LDAPS. |
| `allow_insecure_transport` | no | `false` | Override the plaintext-transport guard. See below. |
| `timeout_secs` | no | `10` | Connect and operation timeout, in seconds. Must be at least 1. |

Unknown config fields are rejected (`deny_unknown_fields`) — a typo'd or
stray key fails loudly at boot instead of being silently ignored.

A plaintext `ldap://` URL pointing at a **non-loopback** host with no
STARTTLS is rejected at config time: it would put the service-account
password and every end-user password on the wire in the clear.
`allow_insecure_transport: true` knowingly overrides that guard for a
trusted, isolated segment. It is a no-op for `ldaps://`, for STARTTLS,
and for a loopback host.

### Limitations

- **`ca_cert_pem` is not wired.** The field deserializes for forward
  compatibility, but the custom-CA TLS path is not implemented, so
  `LdapModule::new` **rejects** a config that sets it. Accepting and
  ignoring it would silently fall back to the system trust roots while
  the operator believed a private CA was in use. Use a system-trusted
  certificate until this lands.
- **The service-account password arrives as plaintext in the settings
  blob.** OIDC's `client_secret` is a `SecretRef` the core resolves and
  injects, so the plugin never sees it. There is no equivalent seam for
  a secret a plugin must present on a socket it opens itself, so
  `bind_service_password` is a raw string in the opaque settings map.
  The plugin wraps it in a redacting newtype (`Debug` prints
  `[REDACTED]`; there is no `Display`; plaintext reachable only through an
  explicit `expose()`), which
  bounds the blast radius but does not remove the plaintext from config.
- **Blocking I/O inside a synchronous FFI call.** `complete_login` is
  synchronous and the LDAP bind is blocking network I/O, invoked by the
  engine from an async login handler. The `LoginModule` ABI has no async
  seam and no "run me on a blocking thread" contract, so a correct
  deployment depends on the host offloading the plugin call to a
  blocking thread.
- **A directory outage is indistinguishable from a bad password to the
  caller.** `LoginOutcome` has no verdict between `Identify` and
  `Reject`, so an unreachable or TLS-broken directory collapses into the
  same fail-closed `Reject` a wrong password produces, and the login
  page cannot say "try again later". The plugin logs the operational
  detail (never the credential) at `warn` so an operator can tell the
  two apart.
- **Group DNs are normalized by the plugin, not the engine.** LDAP and
  AD groups are DNs (`CN=engineers,OU=Groups,DC=corp,DC=example`), which
  make hostile `role_bindings` keys: commas and `=` are awkward in YAML,
  LDAP compares case-insensitively while the map does not, and the OU
  path is deployment-specific. `role_from` picks the shape;
  `cn` is the default for that reason.
- **Group collection is capped** at 4096 values per user entry: the
  plugin keeps at most that many group values and logs when it truncates.
  The cap bounds what is retained, not what is received: the LDAP client
  reads each search response whole before the cap (and the search-then-
  bind ambiguity check) apply, so a hostile directory can still make one
  login buffer a large response.

## Build

Needs a Rust toolchain ([rustup](https://rustup.rs)); `rust-toolchain.toml` pins
the version CI uses. busbar is a pinned git dependency (see
[Dependencies](#dependencies) below).

```sh
cargo build --release      # cdylib: target/release/libbusbar_auth_ldap_plugin.{so,dylib}
cargo test                 # unit tests + the end-to-end loader test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

### Dependencies

`busbar-auth-ldap` (`auth-ldap/`) is a same-repo crate; `auth-ldap-plugin`
depends on it as a normal workspace path dependency (`../auth-ldap`).

The one [busbar](https://github.com/GetBusbar/busbar) crate either crate
names is `busbar-contract` — the plugin contract, whose `abi::sdk` module
carries the export macros. `busbar-plugin-loader` is a dev-dependency only,
for the linked + dropped-in conformance test and the end-to-end test. Both
are **git dependencies pinned to one busbar commit**: the `rev` in every
`Cargo.toml` is field 1 of `.busbar-ref`, and CI's `pin` job refuses a
manifest that disagrees. No sibling checkout of busbar is needed to build
or test; the live end-to-end test (`tests/e2e.rs`) builds the real `busbar`
binary from a checkout named by `BUSBAR_CHECKOUT` (CI's `e2e` job provides
one at `.busbar-ref`).

### Pack and sign

Once built, the cdylib is packed and signed like any other busbar plugin
— see
[`docs/plugins.md`](https://github.com/GetBusbar/busbar/blob/main/docs/plugins.md#signing-and-packaging)
in busbar for the full reference. In short:

```sh
BUSBAR_SIGN_KEY=<signing key> busbar-plugin-pack pack \
    --lib target/release/libbusbar_auth_ldap_plugin.so \
    --name busbar-auth-ldap-plugin --alias ldap --kind auth \
    --version 0.1.0 --publisher busbar \
    --license Apache-2.0 \
    --out busbar-auth-ldap-plugin-0.1.0-x86_64-linux.tar.gz
```

For local development without a signing key, `busbar-plugin-pack pack
--allow-unsigned` produces a tarball busbar loads only under
`plugins.trust.allow_unsigned: true`. Drop the resulting tarball into
busbar's configured `plugins.dir`.

## Tests

`cargo test` runs the library crate's unit tests (`auth-ldap/src/tests.rs`)
and the plugin crate's. Coverage includes config parsing and
`deny_unknown_fields` (including `client_secret` being rejected),
bind-DN templating and LDAP-injection rejection, RFC 4515 filter
escaping, group-DN → role mapping (CN and DN forms, dedup, escaped
commas), the `authenticate` defer, `login_kind()`, the `begin_login`
form shape, `submitted`-map parsing including `Redacted` never leaking
through `Debug`, and the `complete_login` credential guards for a
missing or empty field.

The live-bind happy path is integration-only: `auth-ldap-plugin/tests/e2e.rs`
packs the real cdylib with the `busbar-plugin-pack` binary, drives a
spawned busbar binary over real HTTP, and seeds a real OpenLDAP instance
over LDAP with the same `ldap3` client the plugin uses. A second live
test drives the library module straight against that directory in both
direct-bind and search-then-bind mode and checks the mapped role. Point
`BUSBAR_TEST_LDAP_URL` at that directory to run them; with the variable
unset they skip loudly, and under CI (`CI` set) they fail instead.

## License

Licensed **Apache-2.0** ([LICENSE](LICENSE)). Contributions welcome.
Security issues go through private disclosure, not public issues.
