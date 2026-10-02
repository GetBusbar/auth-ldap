// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SOCKET/TLS BAN, held by this plugin's own tests (BUSBAR-1.6.0.md THE DESIGN §5, Connections:
//! "No plugin opens a socket, dials, binds or does TLS"; the OWNER LAW of 2026-09-27, "every plugin
//! that needs an external connection asks the kernel to instantiate a transport"; Part 2 #40(a); the
//! fleet policy's `[net-ban]` in GetBusbar/busbar `.github/fleet/deps.toml`). A connection is a
//! declared need, and TLS lives only in the host's connector.
//!
//! [`findings`] reads `cargo tree` over the plugin crate's NORMAL + BUILD closure (dev-dependencies
//! are tests, never the shipped image, and with them left out cargo resolves features as the shipped
//! build does) and names every banned crate and every banned feature it finds. The RED arm feeds it a
//! closure that carries a plugin-side TLS stack and a socket crate, and proves it says so.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The crates no plugin's shipped closure may hold (`deps.toml` `[net-ban].crates`).
const BANNED_CRATES: &[&str] = &[
    "rustls",
    "native-tls",
    "openssl",
    "openssl-sys",
    "socket2",
    "tokio-rustls",
    "hyper-rustls",
    "tokio-native-tls",
];

/// The `(crate, feature)` pairs no plugin's shipped closure may turn on (`[net-ban].features`).
const BANNED_FEATURES: &[(&str, &str)] = &[("tokio", "net"), ("mio", "net")];

/// Every banned crate and banned feature in `tree`, `cargo tree --format "{p}|{f}" --prefix none`
/// output: one `name vX.Y.Z [(source)] [(*)]|feature,feature` line per crate.
fn findings(tree: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in tree.lines() {
        let (package, features) = line.split_once('|').unwrap_or((line, ""));
        let Some(name) = package.split_whitespace().next() else {
            continue;
        };
        if BANNED_CRATES.contains(&name) {
            found.push(format!("crate {name}"));
        }
        for feature in features.split(',').map(str::trim) {
            if BANNED_FEATURES.contains(&(name, feature)) {
                found.push(format!("feature {name}/{feature}"));
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

/// `package`'s shipped closure under `dir`, as `cargo tree` resolves it: normal and build edges (no
/// dev-dependencies, so features resolve as the shipped build does), every target platform. `extra`
/// is `--locked` for the real crate and `--offline` for a fixture.
fn tree_of(dir: &Path, package: &str, extra: &str) -> String {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let out = Command::new(cargo)
        .args([
            "tree",
            extra,
            "--package",
            package,
            "--edges",
            "normal,build",
            "--target",
            "all",
            "--prefix",
            "none",
            "--format",
            "{p}|{f}",
        ])
        .current_dir(dir)
        .output()
        .expect("cargo tree runs");
    assert!(
        out.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("cargo tree prints UTF-8")
}

/// This crate's shipped closure, as `cargo tree` resolves it, the lockfile as committed.
fn shipped_closure() -> String {
    tree_of(
        Path::new(env!("CARGO_MANIFEST_DIR")),
        env!("CARGO_PKG_NAME"),
        "--locked",
    )
}

#[test]
fn the_shipped_closure_holds_no_socket_or_tls_stack() {
    let tree = shipped_closure();
    assert!(
        tree.lines()
            .any(|l| l.starts_with(&format!("{} ", env!("CARGO_PKG_NAME")))),
        "cargo tree did not list this crate: {tree}"
    );
    assert_eq!(findings(&tree), Vec::<String>::new());
}

/// RED: a closure that carries a plugin-side TLS stack, a socket crate and tokio's `net` feature is
/// named, crate by crate and feature by feature; an allowed closure is not.
#[test]
fn red_the_net_ban_names_a_plugin_side_tls_or_socket_stack() {
    let banned = "\
busbar-example-plugin v1.0.0 (/w/plugin)|default
reqwest v0.12.9|__rustls,default-tls,rustls-tls
hyper-rustls v0.27.3|http1,ring,tls12
rustls v0.23.20|logging,ring,std,tls12
socket2 v0.5.7|all
tokio v1.41.0 (*)|bytes,default,io-util,libc,mio,net,rt,socket2,time
";
    assert_eq!(
        findings(banned),
        vec![
            "crate hyper-rustls".to_string(),
            "crate rustls".to_string(),
            "crate socket2".to_string(),
            "feature tokio/net".to_string(),
        ]
    );
    let allowed = "\
busbar-example-plugin v1.0.0 (/w/plugin)|default
ring v0.17.8|alloc,default,dev_urandom_fallback
serde_json v1.0.133|default,std
tokio v1.41.0|default,rt,time
";
    assert_eq!(findings(allowed), Vec::<String>::new());
}

/// A fixture: path crates named like the banned ones (no registry needed), and two one-member
/// workspaces under a temp dir.
struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Fixture {
        let root = std::env::temp_dir().join(format!("net-ban-fixture-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let fx = Fixture(root);
        fx.krate("libs/socket2", "socket2", "0.5.7", "");
        fx.krate(
            "libs/tokio",
            "tokio",
            "1.41.0",
            "[features]\nnet = []\nrt = []\ndefault = [\"rt\"]\n",
        );
        // shipped with `socket2` as a dev-dependency only
        fx.member(
            "dev",
            "[dependencies]\ntokio = { path = \"../../libs/tokio\" }\n\
             [dev-dependencies]\nsocket2 = { path = \"../../libs/socket2\" }\n\
             tokio = { path = \"../../libs/tokio\", features = [\"net\"] }\n",
        );
        // shipped with `socket2` as a normal dependency
        fx.member(
            "normal",
            "[dependencies]\nsocket2 = { path = \"../../libs/socket2\" }\n",
        );
        fx
    }

    fn krate(&self, rel: &str, name: &str, version: &str, extra: &str) {
        let dir = self.0.join(rel);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "\n").unwrap();
        let toml = format!(
            "[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n{extra}"
        );
        std::fs::write(dir.join("Cargo.toml"), toml).unwrap();
    }

    fn member(&self, name: &str, deps: &str) {
        let ws = self.0.join(format!("ws-{name}"));
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(
            ws.join("Cargo.toml"),
            format!("[workspace]\nresolver = \"2\"\nmembers = [\"{name}\"]\n"),
        )
        .unwrap();
        let rel = format!("ws-{name}/{name}");
        self.krate(&rel, name, "0.1.0", deps);
    }

    fn findings(&self, name: &str) -> Vec<String> {
        findings(&tree_of(
            &self.0.join(format!("ws-{name}")),
            name,
            "--offline",
        ))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// RED/GREEN over the real `cargo tree` invocation: `socket2` as a dev-dependency only is not
/// reported (nor is a `tokio/net` that only a dev-dependency turns on); the same `socket2` as a
/// normal dependency is.
#[test]
fn a_dev_dependency_is_not_the_shipped_closure_and_a_normal_one_is() {
    let fx = Fixture::new();
    assert_eq!(fx.findings("dev"), Vec::<String>::new());
    assert_eq!(fx.findings("normal"), vec!["crate socket2".to_string()]);
}
