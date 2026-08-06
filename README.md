<!-- SPDX-License-Identifier: Apache-2.0 -->
# auth-ldap

The first-party, signed `kind: auth` plugin for
[busbar](https://getbusbar.com) that authenticates a username and
password against an AD/LDAP directory: a real LDAP/LDAPS **BIND** as the
credential check, a group read off the bound user, and a group-DN → role
mapping that hands busbar a `Principal` it can bind to virtual keys and
roles.

It is a `cdylib` that implements busbar's `AuthModule` and `LoginModule`
traits (via
[`busbar-plugin-sdk`](https://github.com/GetBusbar/busbar/tree/main/crates/plugin-sdk))
and is loaded in-process by busbar over the signed hybrid plugin ABI —
`dlopen`'d, not spawned as a separate process. It requires **auth ABI
v2** (`abi_version = 2`), the version that carries the credential login
flow.

It is a **separate plugin from `busbar-auth-oidc`**, and takes a
different shape: OIDC is a redirect flow where the core executes the
token-exchange HTTP hop, while LDAP is a direct credential flow where the
plugin opens its own socket — the same in-process model
`hashicorp-vault` uses for its HTTPS calls.

## The login flow

1. A user types a username and password on busbar's hosted login page.
   `login_kind()` returns `Credential`, so the method chooser renders a
   form rather than a redirect button, without having to call
   `begin_login` first.
2. `begin_login` returns `LoginOutcome::Prompt(LoginForm)` declaring two
   fields — `username` (text) and `password` (password) — which the core
   renders and POSTs back to `/auth/token`.
3. `complete_login` reads those values back out of `CompleteLogin::
   submitted`, keyed by the field names the plugin declared. The values
   ride `Redacted` (`Debug`/`Display` print `***`, zeroized on drop) and
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

## Design

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
  (`uid={username},ou=people,dc=corp,dc=example`, or an AD UPN bind
  `{username}@corp.example`) and the plugin binds as that DN.
- **Search-then-bind** — set `user_search_filter` (e.g.
  `(sAMAccountName={username})`) and the plugin first binds as
  `bind_service_dn`, locates the user entry, then re-binds as the DN it
  found.

The username is validated and RFC 4515-escaped before it reaches either
a DN template or a search filter, so a crafted username cannot inject
DN components or filter syntax.

## Config

Configured like any other busbar auth method — an entry under
`identity-providers:` referenced by name from `auth.chain`:

```yaml
identity-providers:
  corp-ldap:                 # the NAME is the instance; `module:` is the plugin behind it
    module: ldap
    settings:
      url: "ldaps://ad.corp.example:636"
      bind_dn_template: "{username}@corp.example"
      base_dn: "dc=corp,dc=example"
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
| `bind_dn_template` | yes | — | Turns a username into the bind DN. Must contain `{username}`; validated at boot. |
| `base_dn` | yes | — | Search base for the group read, and for the search-then-bind user lookup. |
| `group_attr` | no | `memberOf` | The attribute on the user entry listing group memberships. Each value is a group DN. |
| `role_from` | no | `cn` | How a group DN becomes a role string: `cn` takes the leftmost RDN value, `dn` uses the full DN verbatim. |
| `user_search_filter` | no | — | Enables search-then-bind. Must contain `{username}`; requires `bind_service_dn`. |
| `bind_service_dn` | no | — | Service-account DN used for the search-then-bind lookup. |
| `bind_service_password` | no | — | Service-account password. Held in a redacting wrapper; see [Limitations](#limitations). |
| `ca_cert_pem` | no | — | Reserved. A config that sets it is **rejected at boot** — see [Limitations](#limitations). |
| `start_tls` | no | `false` | Use STARTTLS over an `ldap://` connection instead of implicit LDAPS. |
| `allow_insecure_transport` | no | `false` | Override the plaintext-transport guard. See below. |
| `timeout_secs` | no | `10` | Connect and operation timeout, in seconds. |

Unknown config fields are rejected (`deny_unknown_fields`) — a typo'd or
stray key fails loudly at boot instead of being silently ignored.

A plaintext `ldap://` URL pointing at a **non-loopback** host with no
STARTTLS is rejected at config time: it would put the service-account
password and every end-user password on the wire in the clear.
`allow_insecure_transport: true` knowingly overrides that guard for a
trusted, isolated segment. It is a no-op for `ldaps://`, for STARTTLS,
and for a loopback host.

## Limitations

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
  The plugin wraps it in a redacting newtype (`Debug`/`Display` print
  `***`, plaintext reachable only through an explicit `expose()`), which
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
- **Group collection is capped** at 4096 values per user entry, so a
  hostile or misconfigured directory cannot drive unbounded memory use.
  The plugin logs when it truncates.

## Build

Needs a Rust toolchain ([rustup](https://rustup.rs)), and — interim,
until [busbarAI](https://github.com/GetBusbar/busbar) ships publicly —
a sibling checkout of `busbarAI` at `../busbarAI` (see
[Dependencies](#dependencies) below).

```sh
cargo build --release      # cdylib: target/release/libbusbar_auth_ldap_plugin.{so,dylib}
cargo test                 # unit tests + the end-to-end loader test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Dependencies

`busbar-auth-ldap` (`auth-ldap/`) is a same-repo crate — no external
checkout is needed for the LDAP logic itself; `auth-ldap-plugin` depends
on it as a normal workspace path dependency (`../auth-ldap`).

The remaining dependencies reach into the
[busbarAI](https://github.com/GetBusbar/busbar) monorepo: `busbar-api`
(needed by both crates), `busbar-plugin-sdk` (`auth-ldap-plugin` only),
and, as a dev-dependency for the end-to-end test,
`busbar-plugin-loader`. Because busbarAI is not yet public, both crates'
`Cargo.toml` point at these as **local path dependencies**
(`../../busbarAI/crates/...`), which means this repo expects to be
checked out as a sibling of `busbarAI`:

```
some-parent-dir/
├── busbarAI/
└── auth-ldap/          # this repo — the auth-ldap/ + auth-ldap-plugin/ workspace
```

This is an interim measure — once busbarAI ships publicly, these should
become git (pinned rev/tag) or crates.io dependencies instead. Grep both
crates' `Cargo.toml` for the `INTERIM` comments when doing that
migration.

## Pack and sign

Once built, the cdylib is packed and signed like any other busbar plugin
— see
[`docs/plugins.md`](https://github.com/GetBusbar/busbar/blob/main/docs/plugins.md#signing-and-packaging)
in busbarAI for the full reference. In short:

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
over LDAP with the same `ldap3` client the plugin uses. Point
`BUSBAR_TEST_LDAP_URL` at that directory to run it; with the variable
unset the test skips loudly rather than passing silently.

## License

Licensed **Apache-2.0** ([LICENSE](LICENSE)). Contributions welcome.
Security issues go through private disclosure, not public issues.
