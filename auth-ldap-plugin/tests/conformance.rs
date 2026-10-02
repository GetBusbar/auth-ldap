// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE LDAP DOOR, BOTH WAYS IN, ONE TRANSCRIPT**: the LDAP module's linked + dropped-in
//! conformance on the auth kind's memory ABI (THE DESIGN §11.4), run against the busbar rev this
//! repo pins (`.busbar-ref`).
//!
//! The module is held two ways at once: LINKED (the logic crate's `door::door`, its row's Statement
//! rendered by `LinkedRow::of` and admitted by the loader's `load_linked`) and DROPPED IN (this
//! crate's built cdylib, `dlopen`ed by `load_dropped`, which resolves `busbar_plugin_door` and admits
//! it only when its Statement renders byte for byte as the linked row's). Each is bound to a real
//! dispatcher and driven over the same script through the auth table: `validate` over the module's
//! refusals, `open`, `verify` (PASS), `begin_login` (the credential form), `complete_login` without
//! a password, with a username the DN template refuses, and against a directory that is not there
//! (OUTAGE), an outbound op (REFUSED), `refresh` refused and accepted, `close`. The two transcripts
//! must be equal. The live BIND against a real directory is `tests/e2e.rs` (OpenLDAP container).
//!
//! THE RED ARMS, same file: the door asked for as another kind is refused; a stated rendering that
//! differs from the door's by one byte is refused (the Statement check is not vacuous). A missing
//! cdylib PANICS: this test IS the dropped-in door's proof, and never skips.

use std::mem::zeroed;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::auth::{
    slot, BeginLoginIn, BeginLoginOut, CompleteLoginIn, IdentifyOut, IdentityBuf, LoginField,
    NamedValue, OpenOutboundIn, OpenOutboundOut, VerifyIn, BEGIN_FORM, LOGIN_BAD_CREDENTIAL,
    LOGIN_OUTAGE, VERDICT_PASS,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Span, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as lc, OpenIn, OpenOut, RefreshIn, ValidateIn,
};
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::kinds::secret::Secret;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, Bind, Called, DispatchConfig, Dispatcher, Frame,
    LinkedRow, NoSink, Plugin,
};

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip.
fn cdylib() -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_auth_ldap_plugin");
    [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the busbar-auth-ldap-plugin cdylib ({file}) is not built"))
}

/// The operator config: a directory on a loopback port nothing listens on, so a BIND fails fast
/// and identically through either door.
fn config() -> String {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("a loopback port")
        .port();
    serde_json::json!({
        "url": format!("ldaps://127.0.0.1:{port}"),
        "bind_dn_template": "uid={username},ou=people,dc=example,dc=org",
        "base_dn": "dc=example,dc=org",
        "timeout_secs": 2,
    })
    .to_string()
}

fn row() -> LinkedRow {
    LinkedRow::of(busbar_auth_ldap::door::door).expect("the door states itself")
}

fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("corp-ad"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: None,
    }
}

fn json(bytes: &[u8]) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_JSON,
        flags: 0,
    }
}

fn abi(s: &str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

/// A call's answer as the transcript spells it: outcome, lease, and error text.
fn spelled(c: &Called) -> String {
    let text = c
        .error
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    format!("{:?} lease={} {text}", c.outcome, c.lease != 0)
}

fn validate(p: &Plugin<Auth>, settings: &str) -> String {
    let mut reason = vec![0_u8; 1024];
    let mut i: ValidateIn = z();
    i.head = in_head();
    i.settings = json(settings.as_bytes());
    i.err_buf = reason.as_mut_ptr();
    i.err_cap = reason.len();
    let mut f = Frame::new(i, out_head());
    spelled(&p.call(lc::VALIDATE, &mut f))
}

fn open(p: &Plugin<Auth>, settings: &str) -> String {
    let mut reason = vec![0_u8; 1024];
    let mut i: OpenIn = z();
    i.head = in_head();
    i.settings = json(settings.as_bytes());
    i.generation = 1;
    i.err_buf = reason.as_mut_ptr();
    i.err_cap = reason.len();
    let mut o: OpenOut = z();
    o.head = out_head();
    let mut f = Frame::new(i, o);
    spelled(&p.call(lc::OPEN, &mut f))
}

fn refresh(p: &Plugin<Auth>, settings: &str, generation: u64) -> String {
    let mut i: RefreshIn = z();
    i.head = in_head();
    i.generation = generation;
    i.settings = json(settings.as_bytes());
    let mut f = Frame::new(i, out_head());
    spelled(&p.call(lc::REFRESH, &mut f))
}

fn close(p: &Plugin<Auth>) -> String {
    let mut f = Frame::new(in_head(), out_head());
    spelled(&p.call(lc::CLOSE, &mut f))
}

fn identify_out() -> IdentifyOut {
    let mut o: IdentifyOut = z();
    o.head = out_head();
    o
}

fn verify(p: &Plugin<Auth>) -> String {
    let mut i: VerifyIn = z();
    i.head = in_head();
    let mut f = Frame::new(i, identify_out());
    let c = p.call(slot::VERIFY, &mut f);
    format!("{} verdict={}", spelled(&c), f.out.verdict)
}

/// The form `begin_login` answers, read out of the plugin's memory while it is loaded.
fn begin_login(p: &Plugin<Auth>) -> String {
    let mut i: BeginLoginIn = z();
    i.head = in_head();
    let mut o: BeginLoginOut = z();
    o.head = out_head();
    let mut f = Frame::new(i, o);
    let c = p.call(slot::BEGIN_LOGIN, &mut f);
    let text = |s: AbiStr| {
        // SAFETY: the plugin's `'static` form text, alive while the plugin is loaded.
        String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(s.ptr, s.len) }).into_owned()
    };
    let form: Vec<String> = if f.out.form.is_null() {
        Vec::new()
    } else {
        // SAFETY: `form_len` fields at `form`, the plugin's `'static` memory.
        unsafe { std::slice::from_raw_parts::<LoginField>(f.out.form, f.out.form_len) }
            .iter()
            .map(|l| {
                format!(
                    "{}:{}:{}:{}",
                    text(l.name),
                    text(l.label),
                    l.kind,
                    l.required
                )
            })
            .collect()
    };
    format!("{} shape={} form={form:?}", spelled(&c), f.out.shape)
}

fn complete_login(p: &Plugin<Auth>, fields: &[(&str, &str)]) -> String {
    let submitted: Vec<NamedValue> = fields
        .iter()
        .map(|(k, v)| NamedValue {
            name: abi(k),
            value: Blob {
                ptr: v.as_ptr(),
                len: v.len(),
                fmt: BLOB_OCTETS,
                flags: BLOB_SECRET,
            },
        })
        .collect();
    let mut bytes = vec![0_u8; 4096];
    let mut groups: Vec<Span> = vec![z(); 16];
    let mut i: CompleteLoginIn = z();
    i.head = in_head();
    i.submitted = submitted.as_ptr();
    i.submitted_len = submitted.len();
    i.out_buf = IdentityBuf {
        buf: bytes.as_mut_ptr(),
        buf_cap: bytes.len(),
        groups: groups.as_mut_ptr(),
        groups_cap: groups.len() as u32,
        _reserved: 0,
    };
    let mut f = Frame::new(i, identify_out());
    let c = p.call(slot::COMPLETE_LOGIN, &mut f);
    format!("{} verdict={}", spelled(&c), f.out.verdict)
}

fn open_outbound(p: &Plugin<Auth>) -> String {
    let mut i: OpenOutboundIn = z();
    i.head = in_head();
    let mut o: OpenOutboundOut = z();
    o.head = out_head();
    let mut f = Frame::new(i, o);
    spelled(&p.call(slot::OPEN_OUTBOUND, &mut f))
}

/// What one door does with the module, as one comparable transcript.
fn transcript(p: &Plugin<Auth>, cfg: &str) -> Vec<String> {
    let upn = r#"{"url":"ldaps://ad.example","bind_dn_template":"{username}@corp.example","base_dn":"dc=x"}"#;
    vec![
        format!("name={}", p.name()),
        validate(p, ""),
        validate(p, "{ not json"),
        validate(p, upn),
        validate(p, cfg),
        open(p, cfg),
        verify(p),
        begin_login(p),
        complete_login(p, &[("username", "alice")]),
        complete_login(p, &[("username", "alice"), ("password", "")]),
        complete_login(p, &[("username", "bad)(user"), ("password", "pw")]),
        complete_login(p, &[("username", "alice"), ("password", "pw")]),
        open_outbound(p),
        refresh(p, "", 2),
        refresh(p, cfg, 3),
        close(p),
    ]
}

/// The LDAP door admits and answers as ONE plugin through either way in, and the RED arms show the
/// admission is not vacuous.
#[test]
fn the_linked_and_the_dropped_in_ldap_door_are_one_module() {
    let d = Dispatcher::new(DispatchConfig {
        workers: 2,
        watchdog_period: Duration::from_millis(20),
        ..DispatchConfig::default()
    });
    let cfg = config();
    let stated = row().statement;
    let linked: Plugin<Auth> = load_linked(&row(), bind(&d)).expect("the linked door loads");
    let dropped: Plugin<Auth> =
        load_dropped(&cdylib(), &stated, bind(&d)).expect("the dropped-in door loads");

    let a = transcript(&linked, &cfg);
    let b = transcript(&dropped, &cfg);
    assert_eq!(a, b, "the two doors are not one module");

    // Not a vacuous pass: the module answered what it must.
    let text = a.join("\n");
    assert_eq!(a[0], "name=busbar-auth-ldap", "{text}");
    assert!(
        a[1].starts_with("Failed") && a[1].contains("requires config"),
        "{text}"
    );
    assert!(a[2].contains("invalid ldap plugin config"), "{text}");
    assert!(a[3].contains("is not a DN"), "{text}");
    assert!(a[4].starts_with("Ready"), "{text}");
    assert!(a[5].starts_with("Ready"), "{text}");
    assert!(a[6].ends_with(&format!("verdict={VERDICT_PASS}")), "{text}");
    assert!(
        a[7].contains(&format!("shape={BEGIN_FORM}"))
            && a[7].contains("username:Username:1:1")
            && a[7].contains("password:Password:2:1"),
        "{text}"
    );
    for line in &a[8..=10] {
        assert!(
            line.starts_with("Ready") && line.ends_with(&format!("verdict={LOGIN_BAD_CREDENTIAL}")),
            "{text}"
        );
    }
    assert!(
        a[11].starts_with("Ready") && a[11].ends_with(&format!("verdict={LOGIN_OUTAGE}")),
        "a directory that is not there is an outage, not a bad credential: {text}"
    );
    assert!(a[12].starts_with("Refused"), "{text}");
    assert!(a[13].starts_with("Failed"), "{text}");
    assert!(a[14].starts_with("Ready"), "{text}");
    assert!(a[15].starts_with("Ready"), "{text}");

    // RED ARM 1: the door asked for as another kind is refused, through either way in.
    assert!(load_linked::<Secret>(&row(), bind(&d)).is_err());
    assert!(load_dropped::<Secret>(&cdylib(), &stated, bind(&d)).is_err());

    // RED ARM 2: a stated rendering one byte off the door's is refused before any slot is called.
    let mut other = stated.clone();
    *other.last_mut().expect("a rendering has bytes") ^= 1;
    let e = load_dropped::<Auth>(&cdylib(), &other, bind(&d))
        .err()
        .expect("a Statement that is not the door's is refused");
    assert!(!e.to_string().is_empty());
}
