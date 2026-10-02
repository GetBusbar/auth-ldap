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
//! dispatcher and to a connection table that PLAYS THE DIRECTORY ([`Directory`]): the plugin's
//! declared need opens a raw stream on it, the table reads the LDAP requests the plugin writes and
//! answers the directory's bytes, and it answers the FIRST read of every stream PENDING and wakes
//! the op's ticket from another thread. So every credential login crosses PENDING, is re-entered
//! on the wake and completes from the conversation it parked (THE DESIGN §5: no plugin opens a
//! socket, dials, binds or does TLS; the plugin ABI: Ready|Pending(wake)).
//!
//! The script, per door: `validate` over the module's refusals, `open`, `verify` (PASS),
//! `begin_login` (the credential form), `complete_login` without a password, with an empty
//! password, and on no ticket (an outage: a login that cannot pend cannot reach the directory),
//! then alice's login through the dispatcher (an identity with her groups) and a wrong password (a
//! bad credential), an outbound op (REFUSED), `refresh` refused and accepted, `close`. The two
//! transcripts — the directory's view of the wire included — must be equal.
//!
//! THE RED ARMS, same file: the door asked for as another kind is refused; a stated rendering that
//! differs from the door's by one byte is refused; the Statement declares its one need and secret
//! reference; a directory that never answers is an outage at the login's deadline (the op's timer,
//! no wake); and THE BAN ([`net_ban`]): the shipped closure holds no socket crate and no TLS stack.
//! A missing cdylib PANICS: this test IS the dropped-in door's proof, and never skips.

use std::collections::{HashMap, VecDeque};
use std::mem::zeroed;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use busbar_contract::abi::auth::{
    slot, BeginLoginIn, BeginLoginOut, CompleteLoginIn, IdentifyOut, IdentityBuf, LoginField,
    NamedValue, OpenOutboundIn, OpenOutboundOut, VerifyIn, BEGIN_FORM, LOGIN_BAD_CREDENTIAL,
    LOGIN_IDENTITY, LOGIN_OUTAGE, VERDICT_PASS,
};
use busbar_contract::abi::host::conn::connector::{
    DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, Span, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::door::MARK_BLOCKS;
use busbar_contract::abi::mechanism::lifecycle::{
    slot as lc, OpenIn, OpenOut, RefreshIn, ValidateIn,
};
use busbar_contract::abi::mechanism::rendering::{self, ReadNeed};
use busbar_contract::conn::{
    ConnError, ConnId, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece, PieceKind,
};
use busbar_contract::ids::StreamId;
use busbar_contract::services::{
    Caller, HostServices, Later, Ran, Reading, RecordsList, Stored, UNSERVED,
};
use busbar_contract::transport::ConnFacts;
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::kinds::secret::Secret;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, now_ns, out_head, Bind, Called, DispatchConfig, Dispatcher,
    Frame, LinkedRow, NoSink, Plugin,
};

#[path = "support/net_ban.rs"]
mod net_ban;

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

fn row() -> LinkedRow {
    LinkedRow::of(busbar_auth_ldap::door::door).expect("the door states itself")
}

// ── the directory ────────────────────────────────────────────────────────────────────────────────

const ALICE_DN: &str = "uid=alice,ou=people,dc=example,dc=org";
const ALICE_PW: &str = "alicepassword";
const GROUPS: [&str; 2] = [
    "cn=admins,ou=groups,dc=example,dc=org",
    "cn=Devs,ou=groups,dc=example,dc=org",
];

/// One BER element (definite length, short or long form), built here and not by the codec under
/// test.
fn el(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if content.len() < 0x80 {
        out.push(content.len() as u8);
    } else {
        let len = content.len().to_be_bytes();
        let skip = len.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (len.len() - skip) as u8);
        out.extend_from_slice(&len[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// The element at the head of `b`: tag, content, rest.
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = b.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let (octets, rest) = rest.split_at_checked(usize::from(first & 0x7f))?;
        (
            octets
                .iter()
                .fold(0_usize, |a, b| (a << 8) | usize::from(*b)),
            rest,
        )
    };
    let (content, rest) = rest.split_at_checked(len)?;
    Some((tag, content, rest))
}

fn reply(id: u8, op: Vec<u8>) -> Vec<u8> {
    el(0x30, &[el(0x02, &[id]), op].concat())
}

fn result(rc: u8) -> Vec<u8> {
    [el(0x0a, &[rc]), el(0x04, b""), el(0x04, b"")].concat()
}

/// The dispatcher's connection-table wake.
type Wake = Arc<dyn Fn(u64) + Send + Sync>;

/// One stream on the directory: the request bytes not yet read, the answer bytes not yet
/// delivered, how many reads it has had.
#[derive(Default)]
struct Stream {
    inbound: Vec<u8>,
    outbound: VecDeque<u8>,
    reads: u32,
}

/// THE DIRECTORY, as a connection table: an open is a raw stream (never framed); what the plugin
/// writes is read as LDAP requests and answered — a bind of alice's DN with her password binds
/// (anything else is invalidCredentials), a search answers alice's entry with her groups, an
/// unbind is noted — and the first read of every stream is PENDING, its ticket woken from another
/// thread. A SILENT directory opens and takes bytes but never answers or wakes.
struct Directory {
    wake: Mutex<Option<Wake>>,
    streams: Mutex<HashMap<u64, Stream>>,
    next: AtomicU64,
    pended: AtomicU32,
    silent: bool,
    /// The wire as the directory saw it, in order.
    log: Mutex<Vec<String>>,
}

impl Directory {
    fn new(silent: bool) -> Arc<Self> {
        Arc::new(Self {
            wake: Mutex::new(None),
            streams: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            pended: AtomicU32::new(0),
            silent,
            log: Mutex::new(Vec::new()),
        })
    }

    fn note(&self, line: String) {
        self.log.lock().unwrap().push(line);
    }

    /// The answer to one whole request message.
    fn answer(&self, id: u8, op: u8, content: &[u8]) -> Vec<u8> {
        match op {
            0x60 => {
                let (_, _, rest) = tlv(content).expect("a version");
                let (_, dn, rest) = tlv(rest).expect("a DN");
                let (_, pw, _) = tlv(rest).expect("a password");
                let dn = String::from_utf8_lossy(dn).into_owned();
                let ok = dn == ALICE_DN && pw == ALICE_PW.as_bytes();
                self.note(format!("bind #{id} {dn}"));
                reply(id, el(0x61, &result(if ok { 0 } else { 49 })))
            }
            0x63 => {
                let (_, base, rest) = tlv(content).expect("a base");
                let base = String::from_utf8_lossy(base).into_owned();
                // scope, deref, size, time, typesOnly, filter, attributes.
                let mut rest = rest;
                let mut parts = Vec::new();
                while let Some((tag, c, r)) = tlv(rest) {
                    parts.push((tag, c.to_vec()));
                    rest = r;
                }
                let attrs: Vec<String> = parts
                    .last()
                    .map(|(_, list)| {
                        let mut l = list.as_slice();
                        let mut names = Vec::new();
                        while let Some((_, n, r)) = tlv(l) {
                            names.push(String::from_utf8_lossy(n).into_owned());
                            l = r;
                        }
                        names
                    })
                    .unwrap_or_default();
                self.note(format!(
                    "search #{id} {base} scope={:?} {attrs:?}",
                    parts[0].1
                ));
                let vals: Vec<u8> = GROUPS.iter().flat_map(|g| el(0x04, g.as_bytes())).collect();
                let attr = el(0x30, &[el(0x04, b"memberOf"), el(0x31, &vals)].concat());
                let entry = el(
                    0x64,
                    &[el(0x04, ALICE_DN.as_bytes()), el(0x30, &attr)].concat(),
                );
                [reply(id, entry), reply(id, el(0x65, &result(0)))].concat()
            }
            0x42 => {
                self.note(format!("unbind #{id}"));
                Vec::new()
            }
            other => {
                self.note(format!("op {other:#x} #{id}"));
                reply(id, el(0x78, &result(2)))
            }
        }
    }
}

fn piece(len: usize) -> Piece {
    Piece {
        kind: PieceKind::Body,
        stream: StreamId(0),
        len,
        end: true,
        status: None,
        status_code: None,
        status_namespace: None,
        retry_after_secs: None,
        reason: None,
    }
}

impl Conns for Directory {
    fn open(&self, _: InstanceId, need: NeedId, desc: &OpenDesc<'_>) -> Result<ConnId, ConnError> {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        self.note(format!("open need={} {}", need.0, desc.target));
        self.streams.lock().unwrap().insert(id, Stream::default());
        Ok(ConnId(id))
    }
    fn write(
        &self,
        _: InstanceId,
        conn: ConnId,
        bytes: &[u8],
        _: bool,
    ) -> Result<usize, ConnError> {
        let mut streams = self.streams.lock().unwrap();
        let s = streams.get_mut(&conn.0).ok_or(ConnError::Closed)?;
        s.inbound.extend_from_slice(bytes);
        while let Some((0x30, msg, rest)) = tlv(&s.inbound) {
            let (_, id, op) = tlv(msg).expect("a message id");
            let (op, content, _) = tlv(op).expect("an op");
            let used = s.inbound.len() - rest.len();
            let answer = if self.silent {
                Vec::new()
            } else {
                self.answer(id[0], op, content)
            };
            s.outbound.extend(answer);
            s.inbound.drain(..used);
        }
        Ok(bytes.len())
    }
    fn read(
        &self,
        _: InstanceId,
        conn: ConnId,
        ticket: u64,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        let mut streams = self.streams.lock().unwrap();
        let s = streams.get_mut(&conn.0).ok_or(ConnError::Closed)?;
        s.reads += 1;
        if self.silent {
            return Err(ConnError::Pending);
        }
        if s.reads == 1 {
            // The directory has not answered yet: the wake comes later, from elsewhere.
            self.pended.fetch_add(1, Ordering::SeqCst);
            let wake = self
                .wake
                .lock()
                .unwrap()
                .clone()
                .expect("the table is armed");
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(5));
                wake(ticket);
            });
            return Err(ConnError::Pending);
        }
        if s.outbound.is_empty() {
            return Err(ConnError::Closed);
        }
        let n = buf.len().min(s.outbound.len());
        for (b, v) in buf.iter_mut().zip(s.outbound.drain(..n)) {
            *b = v;
        }
        Ok(piece(n))
    }
    fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
        Err(ConnError::Closed)
    }
    fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
        Err(ConnError::Closed)
    }
    fn close(&self, _: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        if self.streams.lock().unwrap().remove(&conn.0).is_some() {
            self.note("close".into());
        }
        Ok(())
    }
}

impl DeclaredConns for Directory {
    fn declare(
        &self,
        _: InstanceId,
        _: NeedId,
        _: &ReadNeed,
        _: Option<&str>,
    ) -> Result<(), ConnError> {
        Ok(())
    }
    fn declared(&self, _: InstanceId, _: NeedId) -> Option<Result<(), ConnError>> {
        Some(Ok(()))
    }
}

// ── the host's side ──────────────────────────────────────────────────────────────────────────────

/// THE HOST'S CLOCK, the one host service this plugin calls (`clock.now`, the login's deadline):
/// the dispatcher's own monotonic clock, the one an op's timer (`wake_at_ns`) is on. Every other
/// service says it is not served.
struct Clock;

impl HostServices for Clock {
    fn now(&self) -> Reading {
        Reading {
            wall_ns: 0,
            mono_ns: now_ns(),
        }
    }
    fn dest_judge(&self, _: &str, _: u32, _: bool, _: Option<Later>) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn records_get(&self, _: &Caller, _: &str, _: &[u8], _: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn records_list(&self, _: &Caller, _: RecordsList, _: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn records_claim(&self, _: &Caller, _: &str, _: &[u8], _: u64, _: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn sign(&self, _: &Caller, _: &[u8]) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_sight(&self, _: &Caller, _: &str, _: &str, _: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn trust_due(&self, _: &Caller) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn entitlement_check(&self, _: &Caller, _: Option<u64>, _: &str) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn random_fill(&self, _: u64) -> Stored {
        Stored::refused(UNSERVED)
    }
}

/// One door, bound: its dispatcher, its directory and the plugin.
struct Bound {
    dispatcher: Arc<Dispatcher>,
    directory: Arc<Directory>,
    plugin: Plugin<Auth>,
}

/// The two ways in.
#[derive(Clone)]
enum Arm {
    Linked,
    Dropped(PathBuf),
}

impl Arm {
    fn bind(&self, silent: bool) -> Bound {
        let dispatcher = Arc::new(Dispatcher::with_services(
            DispatchConfig {
                workers: 2,
                watchdog_period: Duration::from_millis(20),
                ..DispatchConfig::default()
            },
            Arc::new(Clock),
        ));
        let directory = Directory::new(silent);
        *directory.wake.lock().unwrap() = Some(dispatcher.conn_waker());
        let conns: Arc<dyn DeclaredConns> = directory.clone();
        let bind = Bind {
            instance: Arc::from("corp-ad"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: Some(conns),
        };
        let plugin = match self {
            Arm::Linked => load_linked::<Auth>(&row(), bind),
            Arm::Dropped(path) => load_dropped::<Auth>(path, &row().statement, bind),
        }
        .expect("the door loads");
        Bound {
            dispatcher,
            directory,
            plugin,
        }
    }
}

/// The operator config: a directory on loopback (plaintext allowed there).
fn config(timeout_secs: u64) -> String {
    serde_json::json!({
        "url": "ldap://127.0.0.1:3389",
        "bind_dn_template": "uid={username},ou=people,dc=example,dc=org",
        "base_dn": "dc=example,dc=org",
        "timeout_secs": timeout_secs,
    })
    .to_string()
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

/// The host's memory a `complete_login` is handed: the submitted fields and the identity buffer.
struct Submission {
    _values: Vec<(String, String)>,
    fields: Vec<NamedValue>,
    bytes: Vec<u8>,
    groups: Vec<Span>,
}

impl Submission {
    fn new(fields: &[(&str, &str)]) -> Self {
        let values: Vec<(String, String)> = fields
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        let named = values
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
        Self {
            _values: values,
            fields: named,
            bytes: vec![0; 4096],
            groups: vec![z(); 16],
        }
    }

    fn input(&mut self) -> CompleteLoginIn {
        let mut i: CompleteLoginIn = z();
        i.head = in_head();
        i.submitted = self.fields.as_ptr();
        i.submitted_len = self.fields.len();
        i.out_buf = IdentityBuf {
            buf: self.bytes.as_mut_ptr(),
            buf_cap: self.bytes.len(),
            groups: self.groups.as_mut_ptr(),
            groups_cap: self.groups.len() as u32,
            _reserved: 0,
        };
        i
    }

    /// The identity the plugin wrote: subject and groups.
    fn identity(&self, out: &IdentifyOut) -> String {
        let span = |s: Span| {
            let at = s.offset as usize;
            String::from_utf8_lossy(&self.bytes[at..at + s.len as usize]).into_owned()
        };
        let groups: Vec<String> = self.groups[..out.identity.groups_len as usize]
            .iter()
            .map(|g| span(*g))
            .collect();
        format!("subject={} groups={groups:?}", span(out.identity.subject))
    }
}

/// `complete_login` on NO ticket (`Plugin::call`): it cannot pend.
fn complete_login(p: &Plugin<Auth>, fields: &[(&str, &str)]) -> String {
    let mut s = Submission::new(fields);
    let mut f = Frame::new(s.input(), identify_out());
    let c = p.call(slot::COMPLETE_LOGIN, &mut f);
    format!("{} verdict={}", spelled(&c), f.out.verdict)
}

impl Bound {
    /// `complete_login` on a fresh ticket through the dispatcher: it may pend, and is resumed on
    /// its wake (or its timer).
    fn login(&self, fields: &[(&str, &str)]) -> String {
        let mut s = Submission::new(fields);
        let ticket = self.dispatcher.mint(0).expect("a ticket");
        let reply = self.dispatcher.submit(
            &self.plugin,
            ticket,
            slot::COMPLETE_LOGIN,
            Frame::new(s.input(), identify_out()),
            DeadlineClass::Call,
            now_ns() + 20_000_000_000,
        );
        let done = reply
            .wait(Duration::from_secs(30))
            .expect("the login completes");
        self.dispatcher.recycle(ticket);
        let out = done.frame.expect("the frame comes back").out;
        let who = if out.verdict == LOGIN_IDENTITY {
            format!(" {}", s.identity(&out))
        } else {
            String::new()
        };
        let error = done
            .error
            .as_deref()
            .map(String::from_utf8_lossy)
            .unwrap_or_default();
        format!("{:?} {error} verdict={}{who}", done.outcome, out.verdict)
    }
}

fn open_outbound(p: &Plugin<Auth>) -> String {
    let mut i: OpenOutboundIn = z();
    i.head = in_head();
    let mut o: OpenOutboundOut = z();
    o.head = out_head();
    let mut f = Frame::new(i, o);
    spelled(&p.call(slot::OPEN_OUTBOUND, &mut f))
}

/// What one door does with the module, as one comparable transcript: its answers, then the wire
/// as the directory saw it.
fn transcript(arm: &Arm) -> Vec<String> {
    let b = arm.bind(false);
    let p = &b.plugin;
    let cfg = config(10);
    let upn = r#"{"url":"ldaps://ad.example","bind_dn_template":"{username}@corp.example","base_dn":"dc=x"}"#;
    let mut t = vec![
        format!("name={}", p.name()),
        validate(p, ""),
        validate(p, "{ not json"),
        validate(p, upn),
        validate(p, &cfg),
        open(p, &cfg),
        verify(p),
        begin_login(p),
        complete_login(p, &[("username", "alice")]),
        complete_login(p, &[("username", "alice"), ("password", "")]),
        complete_login(p, &[("username", "alice"), ("password", ALICE_PW)]),
    ];
    let pended = b.directory.pended.load(Ordering::SeqCst);
    t.push(b.login(&[("username", "alice"), ("password", ALICE_PW)]));
    t.push(b.login(&[("username", "alice"), ("password", "wrong")]));
    assert_eq!(
        b.directory.pended.load(Ordering::SeqCst),
        pended + 2,
        "each login's first read pended and resumed on its wake"
    );
    t.extend([
        open_outbound(p),
        refresh(p, "", 2),
        refresh(p, &cfg, 3),
        close(p),
    ]);
    t.extend(b.directory.log.lock().unwrap().iter().cloned());
    t
}

/// The LDAP door admits and answers as ONE plugin through either way in, over the host's stream,
/// and the RED arms show the admission is not vacuous.
#[test]
fn the_linked_and_the_dropped_in_ldap_door_are_one_module() {
    let a = transcript(&Arm::Linked);
    let b = transcript(&Arm::Dropped(cdylib()));
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
    for line in &a[8..=9] {
        assert!(
            line.starts_with("Ready") && line.ends_with(&format!("verdict={LOGIN_BAD_CREDENTIAL}")),
            "{text}"
        );
    }
    assert!(
        a[10].starts_with("Ready") && a[10].ends_with(&format!("verdict={LOGIN_OUTAGE}")),
        "a login on no ticket cannot pend, so it cannot reach the directory: {text}"
    );
    assert_eq!(
        a[11],
        format!(
            "Ready  verdict={LOGIN_IDENTITY} subject=ldap:{ALICE_DN} groups=[\"admins\", \"Devs\"]"
        ),
        "{text}"
    );
    assert_eq!(
        a[12],
        format!("Ready  verdict={LOGIN_BAD_CREDENTIAL}"),
        "{text}"
    );
    assert!(a[13].starts_with("Refused"), "{text}");
    assert!(a[14].starts_with("Failed"), "{text}");
    assert!(a[15].starts_with("Ready"), "{text}");
    assert!(a[16].starts_with("Ready"), "{text}");
    // The wire: one stream per login on the declared need, at the URL's host:port; alice's bind,
    // the group read off her entry, the unbind; the wrong password's bind; each stream closed.
    assert_eq!(
        a[17..].to_vec(),
        vec![
            "open need=0 127.0.0.1:3389".to_string(),
            format!("bind #1 {ALICE_DN}"),
            format!("search #2 {ALICE_DN} scope=[0] [\"memberOf\"]"),
            "unbind #3".to_string(),
            "close".to_string(),
            "open need=0 127.0.0.1:3389".to_string(),
            format!("bind #1 {ALICE_DN}"),
            "close".to_string(),
        ],
        "{text}"
    );

    // RED ARM 1: the door asked for as another kind is refused, through either way in.
    let d = Dispatcher::new(DispatchConfig::default());
    let plain = || Bind {
        instance: Arc::from("corp-ad"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: None,
    };
    let stated = row().statement;
    assert!(load_linked::<Secret>(&row(), plain()).is_err());
    assert!(load_dropped::<Secret>(&cdylib(), &stated, plain()).is_err());

    // RED ARM 2: a stated rendering one byte off the door's is refused before any slot is called.
    let mut other = stated.clone();
    *other.last_mut().expect("a rendering has bytes") ^= 1;
    match load_dropped::<Auth>(&cdylib(), &other, plain()) {
        Ok(_) => panic!("a Statement that is not the door's must be refused"),
        Err(e) => assert!(!e.to_string().is_empty()),
    }
}

/// RED: the signed Statement declares exactly one need — outbound, a raw `tcp` stream (the plugin
/// frames LDAP itself), the operator-infrastructure egress class, the target named per login —
/// the service password as its one secret reference, and no blocking mark; the dropped-in image
/// states the same.
#[test]
fn red_the_statement_declares_one_operator_infrastructure_stream_and_never_blocks() {
    let stated = row().statement;
    let read = rendering::read(&stated).expect("the rendering reads");
    assert_eq!(read.needs.len(), 1);
    let need = &read.needs[0];
    assert_eq!(need.direction, DIRECTION_OUTBOUND);
    assert_eq!(need.egress_class, EGRESS_OPERATOR_INFRASTRUCTURE);
    assert_eq!(need.transport, "tcp");
    assert!(need.target_from.is_empty());
    assert_eq!(need.trust_from, "settings.ca_cert_pem");
    assert_eq!(read.secret_refs, vec!["bind_service_password".to_string()]);
    assert_eq!(read.marks & MARK_BLOCKS, 0, "no call blocks");
    let dropped = busbar_plugin_loader::dispatch::rendering_of_library(&cdylib())
        .expect("the cdylib opens")
        .expect("the cdylib exports the door");
    assert_eq!(dropped, stated);
}

/// RED: a directory that takes the bind and never answers (and never wakes the ticket) is an
/// outage once the login's `timeout_secs` pass — the op's own timer resumes it; nothing blocks
/// and nothing waits forever.
#[test]
fn red_a_directory_that_never_answers_is_an_outage_at_the_deadline() {
    for arm in [Arm::Linked, Arm::Dropped(cdylib())] {
        let b = arm.bind(true);
        let cfg = config(1);
        assert!(open(&b.plugin, &cfg).starts_with("Ready"));
        let started = Instant::now();
        let got = b.login(&[("username", "alice"), ("password", ALICE_PW)]);
        assert_eq!(got, format!("Ready  verdict={LOGIN_OUTAGE}"));
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(900) && took < Duration::from_secs(15),
            "the outage comes at the deadline: {took:?}"
        );
        assert_eq!(
            b.directory.log.lock().unwrap().clone(),
            vec![
                "open need=0 127.0.0.1:3389".to_string(),
                "close".to_string()
            ]
        );
        assert!(close(&b.plugin).starts_with("Ready"));
    }
}
