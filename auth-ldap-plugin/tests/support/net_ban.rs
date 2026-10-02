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

/// This crate's shipped closure, as `cargo tree` resolves it: normal and build edges, every target
/// platform, the lockfile as committed.
fn shipped_closure() -> String {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let out = Command::new(cargo)
        .args([
            "tree",
            "--locked",
            "--package",
            env!("CARGO_PKG_NAME"),
            "--edges",
            "normal,build",
            "--target",
            "all",
            "--prefix",
            "none",
            "--format",
            "{p}|{f}",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo tree runs");
    assert!(
        out.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("cargo tree prints UTF-8")
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
