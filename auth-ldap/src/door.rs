// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR: the LDAP module on the auth kind's table (`busbar_contract::abi::auth`, v3). LDAP is a
//! login method, so this is its own `plugin_door!` over `abi::auth::Ops` (the SDK's
//! `auth_verify_door!` refuses the login ops):
//!
//! * the lifecycle is the SDK's (`lifecycle: life(Ldap)`): `validate`/`open` parse the settings
//!   blob with [`LdapModule::from_settings`] (its refusal texts), `refresh` swaps the module whole
//!   (a refusal keeps the running one);
//! * `verify` answers PASS: LDAP judges no bearer credential on the data plane (1.5.5's
//!   `authenticate` = `Pass`);
//! * `begin_login` answers the credential form (`username` text, `password` password), `'static`;
//! * `complete_login` BINDs the submitted credential over the host connector's stream on the ONE
//!   declared need ([`NEEDS`]) and writes the principal into the host's identity buffer:
//!   `LOGIN_IDENTITY`, `LOGIN_BAD_CREDENTIAL`, or `LOGIN_OUTAGE` when the directory could not
//!   answer. While a stream service pends it answers PENDING, its [`Conversation`] parked on the
//!   ticket, and resumes on the wake (THE REPLAY RULE, `abi::sdk::conn`): the connector is made
//!   from the handle of the service that pended, so no completed service runs twice. A short
//!   buffer keeps the reached identity for the ticket's one re-call, so the retry never binds again;
//! * the outbound ops are not served (the tail states no `CAP_OUTBOUND`) and answer REFUSED.
//!
//! No call blocks: the Statement states no `MARK_BLOCKS` (BUSBAR-1.6.0.md THE DESIGN §5: no plugin
//! opens a socket, dials, binds or does TLS; the plugin ABI: Ready or Pending(wake)).

use std::collections::HashMap;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::mem::size_of;
use std::ptr;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::task::Poll;

use busbar_contract::abi::auth::{
    AuthTail, BeginLoginIn, BeginLoginOut, CompleteLoginIn, FieldsIn, FieldsOut, IdentifyOut,
    IdentityBuf, LoginField, OpenOutboundIn, OpenOutboundOut, OutboundReadyIn, OutboundReadyOut,
    VerifyIn, BEGIN_FORM, CANCEL_ABANDONED, CAP_INBOUND, CAP_LOGIN, FACT_CACHEABLE, FORM_PASSWORD,
    FORM_TEXT, IDENTITY_HAS_TTL, LOGIN_BAD_CREDENTIAL, LOGIN_IDENTITY, LOGIN_KIND_CREDENTIAL,
    LOGIN_OUTAGE, SPAN_ABSENT, VERDICT_PASS,
};
use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, Span, BLOB_ABSENT};
use busbar_contract::abi::mechanism::door::{KindTailHead, Rewrite, Statement, REWRITE_ALIAS};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::auth_door::with_tail;
use busbar_contract::abi::sdk::conn::{Answer, Connector, Host};
use busbar_contract::abi::sdk::door::{abi_str, statement, AbiIn, AbiOut, Slot};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::auth::Principal;

use crate::conversation::{Conversation, Wire};
use crate::{LdapModule, Login, PASSWORD, USERNAME};

/// The plugin's registry name.
pub const NAME: &str = "busbar-auth-ldap";
/// The name an operator's `module:` gives it.
pub const ALIAS: &str = "ldap";

/// The most logins one instance holds in flight.
const MAX_INFLIGHT: u32 = 64;

const NONE: AbiStr = AbiStr {
    ptr: ptr::null(),
    len: 0,
};

/// The other name config may call it by.
const REWRITES: &[Rewrite] = &[Rewrite {
    class: REWRITE_ALIAS,
    _reserved: 0,
    from: abi_str(ALIAS),
    to: NONE,
}];

/// The auth tail: inbound (always PASS) and the credential login.
const TAIL: AuthTail = AuthTail {
    head: KindTailHead {
        size: size_of::<AuthTail>() as u32,
        _reserved: 0,
    },
    caps: CAP_INBOUND | CAP_LOGIN,
    facts: FACT_CACHEABLE,
    login_kind: LOGIN_KIND_CREDENTIAL,
    _reserved: 0,
    styles: ptr::null(),
    styles_len: 0,
};

/// The need every login's stream is established on.
pub const NEED: u32 = 0;

/// THE ONE NEED: outbound, a raw byte stream over the host's `tcp` carrier (the plugin frames LDAP
/// itself), under the `operator-infrastructure` egress class (directories: private, loopback and
/// plaintext allowed; pinned; cloud metadata hosts refused; BUSBAR-1.6.0.md §5). The plugin names
/// the target per login (`host:port`, read off the `url` setting), so no `target_from`: the
/// carrier's target is `host:port`, never an `ldap://` URL. The trust anchors come from the
/// `ca_cert_pem` setting (`trust_from`), which, as in 1.5.5, the module still refuses, so the
/// connector's defaults are trusted. The timeout is the module's own, per login (`timeout_secs`).
pub const NEEDS: &[Need] = &[Need {
    direction: DIRECTION_OUTBOUND,
    egress_class: EGRESS_OPERATOR_INFRASTRUCTURE,
    transport: abi_str("tcp"),
    auth: NONE,
    target_from: NONE,
    trust_from: abi_str("settings.ca_cert_pem"),
    details: Blob {
        ptr: ptr::null(),
        len: 0,
        fmt: BLOB_ABSENT,
        flags: 0,
    },
    keep_response_headers: ptr::null(),
    keep_response_headers_len: 0,
    timeout_ms: 0,
}];

/// The settings keys whose values are secret references, resolved in this order into
/// `OpenIn.secrets` (the spec's ruling: "LDAP: secret via OpenIn.secrets (1.5.5 literal accepted
/// by host)").
pub const SECRET_REFS: &[AbiStr] = &[abi_str("bind_service_password")];

/// This plugin's Statement.
pub const STATEMENT: Statement = with_tail(
    Statement {
        rewrites: REWRITES.as_ptr(),
        rewrites_len: REWRITES.len(),
        needs: NEEDS.as_ptr(),
        needs_len: NEEDS.len(),
        secret_refs: SECRET_REFS.as_ptr(),
        secret_refs_len: SECRET_REFS.len(),
        ..statement(NAME, env!("CARGO_PKG_VERSION"), MAX_INFLIGHT)
    },
    &TAIL,
);

/// The credential form `begin_login` answers: `'static`, so it holds no lease.
const FORM: &[LoginField] = &[
    LoginField {
        name: abi_str(USERNAME.0),
        label: abi_str(USERNAME.1),
        kind: FORM_TEXT,
        required: 1,
    },
    LoginField {
        name: abi_str(PASSWORD.0),
        label: abi_str(PASSWORD.1),
        kind: FORM_PASSWORD,
        required: 1,
    },
];

/// One instance: the module (swapped whole on `refresh`), and the identity a short answer reached,
/// by ticket, for its one re-call.
pub struct Ldap {
    module: RwLock<Arc<LdapModule>>,
    reached: Mutex<HashMap<(u32, u32), Principal>>,
}

impl Ldap {
    fn module(&self) -> Arc<LdapModule> {
        self.module
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Life for Ldap {
    const CANCEL: u32 = CANCEL_ABANDONED;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        LdapModule::from_settings(settings)
            .map(drop)
            .map_err(Refusal::failed)
    }

    fn open(settings: &[u8], secrets: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        let module = LdapModule::from_settings_with(settings, secrets).map_err(Refusal::failed)?;
        Ok(Self {
            module: RwLock::new(Arc::new(module)),
            reached: Mutex::default(),
        })
    }

    fn refresh(&self, settings: &[u8], secrets: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        let module = LdapModule::from_settings_with(settings, secrets).map_err(Refusal::failed)?;
        *self.module.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(module);
        Ok(Refreshed::default())
    }
}

/// `verify`: PASS, not this module's credential.
pub struct Verify;

impl Slot for Verify {
    type In = VerifyIn;
    type Out = IdentifyOut;
    fn call(_: *mut c_void, _: &VerifyIn, out: &mut IdentifyOut) -> Outcome {
        out.verdict = VERDICT_PASS;
        Outcome::Ready
    }
}

/// `begin_login`: the credential form.
pub struct BeginLogin;

impl Slot for BeginLogin {
    type In = BeginLoginIn;
    type Out = BeginLoginOut;
    fn call(_: *mut c_void, _: &BeginLoginIn, out: &mut BeginLoginOut) -> Outcome {
        out.shape = BEGIN_FORM;
        out.form = FORM.as_ptr();
        out.form_len = FORM.len();
        Outcome::Ready
    }
}

/// The submitted form fields `(name, value)`, lent for the call.
///
/// The safe SDK lends no accessor for `CompleteLoginIn::submitted`, so this reads the list the
/// auth ABI states directly: the one `unsafe` in this crate.
#[allow(unsafe_code)]
fn submitted(input: &CompleteLoginIn) -> Vec<(&[u8], &[u8])> {
    /// # Safety
    /// NULL, or `len` readable bytes at `p` for the call.
    unsafe fn bytes<'a>(p: *const u8, len: usize) -> &'a [u8] {
        if p.is_null() || len == 0 {
            return &[];
        }
        // SAFETY: the caller's contract.
        unsafe { std::slice::from_raw_parts(p, len) }
    }
    if input.submitted.is_null() || input.submitted_len == 0 {
        return Vec::new();
    }
    // SAFETY: `abi::auth::CompleteLoginIn`: `submitted` is `submitted_len` `NamedValue`s the host
    // lends for the call, each name and value bytes it lends for the call; `input` is the
    // trampoline's copy of that `in`, alive for the call, and nothing here outlives it.
    unsafe {
        std::slice::from_raw_parts(input.submitted, input.submitted_len)
            .iter()
            .map(|f| {
                (
                    bytes(f.name.ptr, f.name.len),
                    bytes(f.value.ptr, f.value.len),
                )
            })
            .collect()
    }
}

/// The submitted value of the field `name`, when it is text.
fn field<'a>(fields: &[(&[u8], &'a [u8])], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(n, _)| *n == name.as_bytes())
        .and_then(|(_, v)| std::str::from_utf8(v).ok())
}

const ABSENT: Span = Span {
    offset: SPAN_ABSENT,
    len: 0,
};

/// Write `p` into the host's identity buffer and answer READY, or the short FAILED (every
/// `needed_*` at its full size, nothing written) when it does not fit.
fn write_identity(
    p: &Principal,
    buf: Lent<'_, IdentityBuf>,
    out: &mut Out<'_, IdentifyOut>,
) -> Outcome {
    let (mut bytes, mut groups) = (buf.buf(), buf.groups());
    let need_bytes = p.id.len()
        + p.name.as_ref().map_or(0, String::len)
        + p.roles.iter().map(String::len).sum::<usize>();
    if need_bytes > bytes.cap() || p.roles.len() > groups.cap() {
        out.set(|o| &o.needed_bytes, need_bytes as u64);
        out.set(
            |o| &o.needed_groups,
            u32::try_from(p.roles.len()).unwrap_or(u32::MAX),
        );
        return Outcome::Failed;
    }
    let subject = bytes.span(p.id.as_bytes());
    let name = p.name.as_ref().map_or(ABSENT, |n| bytes.span(n.as_bytes()));
    for role in &p.roles {
        let s = bytes.span(role.as_bytes());
        groups.push(s);
    }
    let (flags, ttl) = p.ttl_secs.map_or((0, 0), |t| (IDENTITY_HAS_TTL, t));
    out.set(|o| &o.identity.subject, subject);
    out.set(|o| &o.identity.key_id, ABSENT);
    out.set(|o| &o.identity.key_name, ABSENT);
    out.set(|o| &o.identity.user, ABSENT);
    out.set(|o| &o.identity.provider, ABSENT);
    out.set(|o| &o.identity.name, name);
    out.set(|o| &o.identity.claims, ABSENT);
    out.set(|o| &o.identity.claims_fmt, BLOB_ABSENT);
    out.set(|o| &o.identity.flags, flags);
    out.set(|o| &o.identity.ttl_secs, ttl);
    out.set(
        |o| &o.identity.groups_len,
        u32::try_from(groups.written()).unwrap_or(u32::MAX),
    );
    out.set(|o| &o.verdict, LOGIN_IDENTITY);
    Outcome::Ready
}

/// One login in flight, parked on its ticket across its PENDING answers: the module it began with
/// (a `refresh` meanwhile does not change it), the submitted credential, the conversation, the
/// stream once established, and the handle of the first connector service not yet completed.
struct Run {
    module: Arc<LdapModule>,
    username: Option<String>,
    password: Option<String>,
    conv: Conversation,
    stream: Option<u64>,
    at: u32,
}

/// The host connector's stream as the conversation's [`Wire`], for one entry of the op: its
/// services count from the handle of the one that pended last (`Host::connector_from`), so the
/// replay re-issues exactly that one and the host answers its result.
struct HostWire<'h> {
    conn: Option<Connector<'h>>,
    stream: Option<u64>,
    at: u32,
}

impl HostWire<'_> {
    /// Make one service through `f`: a pending one leaves `at` on its own handle.
    fn serve<T>(
        &mut self,
        f: impl FnOnce(&mut Connector<'_>, u64) -> Answer<T>,
    ) -> Poll<Result<T, String>> {
        let Some(c) = self.conn.as_mut() else {
            return Poll::Ready(Err("the instance was handed no host tables".to_string()));
        };
        let before = c.issued();
        match f(c, self.stream.unwrap_or(0)) {
            Poll::Pending => {
                self.at = before;
                Poll::Pending
            }
            Poll::Ready(r) => {
                self.at = c.issued();
                Poll::Ready(r.map_err(|e| e.to_string()))
            }
        }
    }
}

impl Wire for HostWire<'_> {
    fn establish(&mut self, target: &str) -> Poll<Result<(), String>> {
        let opened = self.serve(|c, _| c.establish(NEED, Some(target), ""));
        opened.map(|r| {
            r.map(|stream| {
                self.stream = Some(stream);
            })
        })
    }

    fn secure(&mut self) -> Poll<Result<(), String>> {
        self.serve(|c, s| c.upgrade_secure(s, None, None))
    }

    fn write(&mut self, bytes: &[u8]) -> Poll<Result<usize, String>> {
        self.serve(|c, s| c.write(s, bytes))
    }

    fn read(&mut self, buf: &mut [u8]) -> Poll<Result<usize, String>> {
        self.serve(|c, s| c.read(s, buf))
    }
}

/// The host's monotonic clock, when it offers one.
fn now(host: Option<&Host>, ticket: Ticket) -> Option<u64> {
    match host?.connector(ticket).clock_now() {
        Poll::Ready(Ok(r)) => Some(r.mono_ns),
        _ => None,
    }
}

/// Run (or resume) the login on this call's ticket: PENDING while a stream service pends (the
/// run parked, the op's timer set to the login's deadline), else what it came to, the stream
/// closed.
fn drive(
    h: &Held<Ldap>,
    instance: &Instance<'_, Held<Ldap>>,
    input: &CompleteLoginIn,
    out: &mut Out<'_, IdentifyOut>,
) -> Poll<Login> {
    let ticket = instance.ticket();
    let mut run = match instance.resume::<Run>() {
        Some(run) => *run,
        None => {
            let fields = submitted(input);
            Run {
                module: h.life().module(),
                username: field(&fields, USERNAME.0).map(str::to_owned),
                password: field(&fields, PASSWORD.0).map(str::to_owned),
                conv: Conversation::new(),
                stream: None,
                at: 0,
            }
        }
    };
    let host = h.host();
    let now = now(host, ticket);
    let mut wire = HostWire {
        conn: host.map(|host| host.connector_from(ticket, run.at)),
        stream: run.stream,
        at: run.at,
    };
    let answer = run.module.login_over(
        &mut run.conv,
        &mut wire,
        run.username.as_deref(),
        run.password.as_deref(),
        now,
    );
    match answer {
        Poll::Pending => {
            run.stream = wire.stream;
            run.at = wire.at;
            if let Some(deadline) = run.conv.deadline_ns() {
                out.wake_at(deadline);
            }
            instance.park(run);
            Poll::Pending
        }
        Poll::Ready(login) => {
            if run.conv.opened() {
                // Best effort, as 1.5.5 dropped its connection: what the close answers changes
                // nothing.
                let _ = wire.serve(|c, s| c.close(s));
            }
            Poll::Ready(login)
        }
    }
}

/// `complete_login`: BIND the submitted credential over the host's stream (see
/// [`LdapModule::login_over`]); PENDING while the stream pends.
pub struct CompleteLogin;

impl SafeSlot for CompleteLogin {
    type In = CompleteLoginIn;
    type Out = IdentifyOut;
    type State = Held<Ldap>;
    fn call(
        instance: Instance<'_, Held<Ldap>>,
        input: Lent<'_, CompleteLoginIn>,
        mut out: Out<'_, IdentifyOut>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return Outcome::Fault;
        };
        let ldap = h.life();
        let ticket = instance.ticket();
        let key = (ticket.slot, ticket.generation);
        let kept = ldap
            .reached
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&key);
        let login = match kept {
            Some(p) => Login::Identity(p),
            None => match drive(h, &instance, input.get(), &mut out) {
                Poll::Ready(login) => login,
                Poll::Pending => return Outcome::Pending,
            },
        };
        match login {
            Login::BadCredential => {
                out.set(|o| &o.verdict, LOGIN_BAD_CREDENTIAL);
                Outcome::Ready
            }
            Login::Outage => {
                out.set(|o| &o.verdict, LOGIN_OUTAGE);
                Outcome::Ready
            }
            Login::Identity(p) => {
                let answer = write_identity(&p, input.field(|i| &i.out_buf), &mut out);
                // `0` is never a minted generation: a ticket-less call gets no re-call.
                if answer == Outcome::Failed && ticket.generation != 0 {
                    ldap.reached
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .insert(key, p);
                }
                answer
            }
        }
    }
}

/// An auth op this plugin does not serve (the tail states no `CAP_OUTBOUND`): REFUSED, never
/// called.
pub struct NotServed<I, O>(PhantomData<(I, O)>);

impl<I: AbiIn, O: AbiOut> Slot for NotServed<I, O> {
    type In = I;
    type Out = O;
    fn call(_: *mut c_void, _: &I, _: &mut O) -> Outcome {
        Outcome::Refused
    }
}

mod table {
    use super::{
        BeginLogin, CompleteLogin, FieldsIn, FieldsOut, Ldap, NotServed, OpenOutboundIn,
        OpenOutboundOut, OutboundReadyIn, OutboundReadyOut, Safe, Verify,
    };

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::auth::Ops,
        statement: super::STATEMENT,
        lifecycle: life(Ldap),
        kind_ops: {
            verify: Verify,
            begin_login: BeginLogin,
            complete_login: Safe<CompleteLogin>,
            open_outbound: NotServed<OpenOutboundIn, OpenOutboundOut>,
            outbound_ready: NotServed<OutboundReadyIn, OutboundReadyOut>,
            fields: NotServed<FieldsIn, FieldsOut>,
        },
    }
}

/// This plugin's door: the one a compiled-in build links and the dropped-in image exports.
pub use table::door;

#[cfg(test)]
#[path = "tests/door_tests.rs"]
mod tests;
