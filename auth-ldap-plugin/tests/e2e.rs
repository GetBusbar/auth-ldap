// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin-SIDE live end-to-end for the AD/LDAP login plugin — the mirror of `auth-oidc-plugin`'s
//! `tests/e2e.rs`, testing THIS plugin's OWN token-exchange direction (the GET credential-FORM flow:
//! chooser → form → POST creds → the plugin BINDs its own LDAP socket → key).
//!
//! LDAP is a `Credential` method: there is no held-token/redirect path, so the faithful test is a REAL
//! busbar boot driving the real form POST, with the plugin binding against a READY-MADE OpenLDAP
//! container (never a hand-rolled directory), provided by CI as a service container and addressed via
//! `BUSBAR_TEST_LDAP_URL` (mirrors the store plugins' `BUSBAR_TEST_POSTGRES_URL`). The container
//! auto-creates the base suffix + admin from its own env; this test seeds the test user/group over
//! LDAP itself (`ldap3`, the same client the plugin uses) — the CI-service equivalent of feeding
//! busbarAI/scripts/fixtures/auth-ldap/seed.ldif, kept in-test so the plugin's CI is self-contained.
//!
//! GATING: `BUSBAR_TEST_LDAP_URL` unset ⇒ SKIP loudly (local, no docker) — never a silent pass.
//! Under CI the plugin-ci `service: openldap` arm sets it and the test RUNS.

use std::io::Write as _;

const BASE_DN: &str = "dc=example,dc=org";
const ADMIN_DN: &str = "cn=admin,dc=example,dc=org";
const ADMIN_PW: &str = "adminpassword";
const ALICE_DN: &str = "uid=alice,ou=people,dc=example,dc=org";
const ALICE_PW: &str = "alicepassword";

fn ldap_url() -> Option<String> {
    match std::env::var("BUSBAR_TEST_LDAP_URL") {
        Ok(u) if !u.trim().is_empty() => Some(u.trim().to_string()),
        _ => None,
    }
}

fn busbarai_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../busbarAI")
        .canonicalize()
        .expect("sibling busbarAI checkout must exist (see Cargo.toml path deps)")
}

fn build_real_binaries() -> (std::path::PathBuf, std::path::PathBuf) {
    let root = busbarai_root();
    let status = std::process::Command::new("cargo")
        .args([
            "build",
            "--release",
            "-p",
            "busbar",
            "-p",
            "busbar-plugin-pack",
        ])
        .current_dir(&root)
        .status()
        .expect("run cargo build for busbar + busbar-plugin-pack");
    assert!(status.success(), "building the real binaries must succeed");
    (
        root.join("target/release/busbar"),
        root.join("target/release/busbar-plugin-pack"),
    )
}

fn plugin_path() -> Option<std::path::PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = busbar_plugin_loader::plugin_library_filename("busbar_auth_ldap_plugin");
        let uplifted = profile_dir.join(&name);
        let raw = profile_dir.join("deps").join(&name);
        [uplifted, raw]
            .into_iter()
            .filter_map(|p| {
                std::fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .ok()
                    .map(|mtime| (p, mtime))
            })
            .max_by_key(|(_, mtime)| *mtime)
            .map(|(p, _)| p)
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!("busbar_auth_ldap_plugin cdylib not built under CI (run `cargo test --workspace`)");
    }
    candidate
}

fn pack_ldap(pack_bin: &std::path::Path, so: &std::path::Path, out: &std::path::Path) {
    let status = std::process::Command::new(pack_bin)
        .args([
            "pack",
            "--lib",
            so.to_str().unwrap(),
            "--name",
            "busbar-auth-ldap-plugin",
            "--alias",
            "ldap",
            "--kind",
            "auth",
            "--version",
            "0.0.0-e2e",
            "--publisher",
            "busbar",
            "--description",
            "ldap plugin-side e2e",
            "--license",
            "Apache-2.0",
            "--out",
            out.to_str().unwrap(),
            "--allow-unsigned",
        ])
        .status()
        .expect("run busbar-plugin-pack");
    assert!(status.success(), "packing the ldap plugin must succeed");
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Seed the test directory over LDAP (idempotent): ou=people, ou=groups, uid=alice (bindable
/// userPassword + a `seeAlso` group-DN the plugin reads as membership), and cn=admins with alice as a
/// member — the in-test equivalent of scripts/fixtures/auth-ldap/seed.ldif. Uses `seeAlso` (a
/// standard DN-syntax attribute seeded directly on the user) so the group→role mapping is deterministic
/// on any OpenLDAP WITHOUT the operational `memberOf` overlay; the plugin's `group_attr` points at it.
fn seed_directory(url: &str) {
    use ldap3::{LdapConn, Scope, SearchEntry};
    // The OpenLDAP service container takes a few seconds to create its base suffix; retry the admin
    // bind until it is ready (or give up loudly after ~60s).
    let mut ldap = None;
    for _ in 0..60 {
        if let Ok(mut c) = LdapConn::new(url) {
            if c.simple_bind(ADMIN_DN, ADMIN_PW)
                .is_ok_and(|r| r.success().is_ok())
            {
                ldap = Some(c);
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
    let mut ldap =
        ldap.expect("OpenLDAP admin bind never succeeded (check LDAP_ADMIN_PASSWORD / base)");

    // Confirm the container auto-created the base suffix from its env before we add children.
    ldap.search(BASE_DN, Scope::Base, "(objectClass=*)", vec!["dn"])
        .and_then(|r| r.success())
        .unwrap_or_else(|e| {
            panic!("base suffix {BASE_DN} must exist (set LDAP_DOMAIN=example.org): {e}")
        });

    let add =
        |ldap: &mut LdapConn, dn: &str, attrs: Vec<(&str, std::collections::HashSet<&str>)>| {
            match ldap.add(dn, attrs).and_then(|r| r.success()) {
                Ok(_) => {}
                // 68 = entryAlreadyExists — a rerun against a warm container is fine.
                Err(ldap3::LdapError::LdapResult { result }) if result.rc == 68 => {}
                Err(e) => panic!("seed add {dn} failed: {e}"),
            }
        };
    add(
        &mut ldap,
        "ou=people,dc=example,dc=org",
        vec![
            ("objectClass", ["organizationalUnit"].into()),
            ("ou", ["people"].into()),
        ],
    );
    add(
        &mut ldap,
        "ou=groups,dc=example,dc=org",
        vec![
            ("objectClass", ["organizationalUnit"].into()),
            ("ou", ["groups"].into()),
        ],
    );
    add(
        &mut ldap,
        ALICE_DN,
        vec![
            ("objectClass", ["inetOrgPerson"].into()),
            ("uid", ["alice"].into()),
            ("cn", ["Alice Example"].into()),
            ("sn", ["Example"].into()),
            ("userPassword", [ALICE_PW].into()),
            ("seeAlso", ["cn=admins,ou=groups,dc=example,dc=org"].into()),
        ],
    );
    add(
        &mut ldap,
        "cn=admins,ou=groups,dc=example,dc=org",
        vec![
            ("objectClass", ["groupOfNames"].into()),
            ("cn", ["admins"].into()),
            ("member", [ALICE_DN].into()),
        ],
    );

    // Prove the seed landed the way the plugin will read it: alice carries seeAlso=cn=admins,...
    let (entries, _) = ldap
        .search(ALICE_DN, Scope::Base, "(objectClass=*)", vec!["seeAlso"])
        .and_then(|r| r.success())
        .expect("read alice back");
    let e = SearchEntry::construct(entries.into_iter().next().expect("alice present"));
    assert!(
        e.attrs
            .get("seeAlso")
            .is_some_and(|v| v.iter().any(|s| s.starts_with("cn=admins"))),
        "alice must carry the seeAlso group DN the plugin maps to role 'admins'"
    );
    let _ = ldap.unbind();
}

fn cookie_state(cookie_value: &str) -> String {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cookie_value)
        .expect("cookie is base64url");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("cookie is JSON");
    v["state"]
        .as_str()
        .expect("cookie carries state")
        .to_string()
}

fn issued_key_from_html(html: &str) -> Option<String> {
    let marker = "id=\"key\">";
    let start = html.find(marker)? + marker.len();
    let rest = &html[start..];
    let end = rest.find('<')?;
    Some(rest[..end].to_string())
}

fn login_cookie(resp: &reqwest::blocking::Response) -> String {
    resp.headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|c| {
            c.strip_prefix("busbar_login=")
                .map(|r| r.split(';').next().unwrap_or("").to_string())
        })
        .expect("begin sets the busbar_login cookie")
}

fn wait_for_health(client: &reqwest::blocking::Client, url: &str, child: &mut std::process::Child) {
    for _ in 0..150 {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("busbar exited early during health poll: {status}");
        }
        if client
            .get(url)
            .send()
            .is_ok_and(|r| r.status().is_success())
        {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("busbar did not become healthy at {url}");
}

/// THE plugin-side proof: a REAL busbar boot drives the ldap credential-form flow; the plugin BINDs
/// alice against OpenLDAP, reads her group DN (→ role `admins` → group eng-team), a key is minted, and
/// it authenticates on the data plane. A WRONG password is REJECTED 401 — the real bind gates.
#[test]
fn ldap_form_flow_binds_mints_key_and_gates_wrong_password() {
    let Some(url) = ldap_url() else {
        eprintln!(
            "skip: BUSBAR_TEST_LDAP_URL unset — ldap live e2e needs the OpenLDAP service container \
             (set by the plugin-ci `service: openldap` arm). Skipping (local, no docker)."
        );
        return;
    };
    let Some(so_path) = plugin_path() else {
        eprintln!("skip: busbar_auth_ldap_plugin cdylib not built");
        return;
    };
    seed_directory(&url);
    let (busbar_bin, pack_bin) = build_real_binaries();

    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let work = std::env::temp_dir().join(format!(
        "busbar-ldap-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let plugins_dir = work.join("plugins");
    std::fs::create_dir_all(&plugins_dir).unwrap();
    pack_ldap(
        &pack_bin,
        &so_path,
        &plugins_dir.join("busbar-auth-ldap.tar.gz"),
    );

    let data_port = free_port();
    let signing_key = work.join("signing.key");
    {
        let out = std::process::Command::new(&busbar_bin)
            .arg("--generate-signing-key")
            .output()
            .expect("generate signing key");
        assert!(out.status.success());
        std::fs::File::create(&signing_key)
            .unwrap()
            .write_all(&out.stdout)
            .unwrap();
    }

    let providers = work.join("providers.yaml");
    std::fs::write(
        &providers,
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n",
    )
    .unwrap();

    // busbar 1.5.3 retired both `auth.methods:` and INLINE entries under `auth.admin_auth:`: an
    // identity provider is now defined ONCE under `identity-providers:` (its `browser_login` and
    // `settings` hanging off that one definition) and referenced elsewhere by bare name. A config
    // still carrying the old shape is not merely deprecated — core recognises it as a 1.x config
    // and refuses to start at all, so this fixture described a gateway that could never boot and
    // the test failed a long way from the cause, as `busbar exited early during health poll: exit
    // status: 1`. The shape below is what core's own `--migrate-config` produces for the previous
    // fixture, then confirmed by feeding the rendered YAML back through `busbar --validate`.
    let config = work.join("config.yaml");
    std::fs::write(
        &config,
        format!(
            "listen: \"127.0.0.1:{data_port}\"\n\
             public_url: \"https://gate.busbar.e2e\"\n\
             auth:\n  key_ttl: \"7d\"\n  signing_key: {{ file: \"{signing}\" }}\n  chain:\n    - keys\n\
             \x20 admin_auth: [admin-tokens]\n\
             \x20 role_bindings:\n    ldap:\n      admins:\n        group: eng-team\n\
             identity-providers:\n\
             \x20 admin-tokens: {{ module: admin-tokens, token: {{ env: BUSBAR_ADMIN_TOKEN }} }}\n\
             \x20 ldap:\n    module: ldap\n\
             \x20   settings:\n      url: \"{url}\"\n\
             \x20     bind_dn_template: \"uid={{username}},ou=people,dc=example,dc=org\"\n\
             \x20     base_dn: \"dc=example,dc=org\"\n      group_attr: \"seeAlso\"\n      role_from: cn\n\
             \x20   browser_login: {{}}\n\
             plugins:\n  enabled: true\n  dir: {plugins}\n  trust:\n    allow_unsigned: true\n\
             groups:\n  eng-team:\n    limits:\n      - {{ requests: 1000000, per: day }}\n\
             \x20   child_default:\n      limits:\n        - {{ budget: 5000, per: month }}\n        - {{ requests: 1000, per: day }}\n\
             providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
             models:\n  test-model:\n    provider: mock\n",
            signing = signing_key.display(),
            plugins = plugins_dir.display(),
        ),
    )
    .unwrap();

    let mut child = std::process::Command::new(&busbar_bin)
        .env("BUSBAR_CONFIG", &config)
        .env("BUSBAR_PROVIDERS", &providers)
        .env("MOCK_KEY", "unused")
        .env("BUSBAR_ADMIN_TOKEN", "e2e-admin-token")
        .env("BUSBAR_STATE_FILE", "")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn busbar with auth.methods.ldap");
    let base = format!("http://127.0.0.1:{data_port}");
    wait_for_health(&client, &format!("{base}/healthz"), &mut child);

    // begin: GET ?method=ldap → 200 credential form + cookie.
    let begin = client
        .get(format!("{base}/auth/token?method=ldap"))
        .send()
        .expect("GET begin");
    assert!(
        begin.status().is_success(),
        "ldap begin renders a form (200), got {}",
        begin.status()
    );
    let cookie_value = login_cookie(&begin);
    let state = cookie_state(&cookie_value);

    // POST creds (correct password) → the plugin binds + reads groups → key page.
    let ok_page = client
        .post(format!("{base}/auth/token"))
        .header(
            reqwest::header::COOKIE,
            format!("busbar_login={cookie_value}"),
        )
        .form(&[
            ("__state", state.as_str()),
            ("username", "alice"),
            ("password", ALICE_PW),
        ])
        .send()
        .expect("POST creds");
    assert!(
        ok_page.status().is_success(),
        "correct creds should mint a key, got {}",
        ok_page.status()
    );
    let page = ok_page.text().unwrap();
    assert!(
        page.contains("ldap:uid=alice"),
        "identity ldap:uid=alice must appear: {page}"
    );
    assert!(
        page.contains("user:ldap:uid=alice"),
        "group user:ldap:uid=alice must appear (role 'admins' must have bound)"
    );
    let api_key = issued_key_from_html(&page).expect("the key page carries the issued api_key");

    let chat = client
        .post(format!("{base}/v1/chat/completions"))
        .bearer_auth(&api_key)
        .json(
            &serde_json::json!({"model":"test-model","messages":[{"role":"user","content":"hi"}]}),
        )
        .send()
        .expect("chat with the issued key");
    assert_ne!(
        chat.status().as_u16(),
        401,
        "the self-scoped ldap key must authenticate"
    );

    // WRONG password must be rejected 401 — proving the REAL bind gates. Fresh begin → fresh cookie.
    let begin2 = client
        .get(format!("{base}/auth/token?method=ldap"))
        .send()
        .expect("GET begin 2");
    let cookie2 = login_cookie(&begin2);
    let state2 = cookie_state(&cookie2);
    let bad = client
        .post(format!("{base}/auth/token"))
        .header(reqwest::header::COOKIE, format!("busbar_login={cookie2}"))
        .form(&[
            ("__state", state2.as_str()),
            ("username", "alice"),
            ("password", "wrong-password"),
        ])
        .send()
        .expect("POST wrong creds");
    assert_eq!(
        bad.status().as_u16(),
        401,
        "a wrong password must be rejected 401 (bind gates)"
    );

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&work);
}
