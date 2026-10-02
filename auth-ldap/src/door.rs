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
//! * `complete_login` BINDs the submitted credential and writes the principal into the host's
//!   identity buffer: `LOGIN_IDENTITY`, `LOGIN_BAD_CREDENTIAL`, or `LOGIN_OUTAGE` when the
//!   directory could not answer. A short buffer keeps the reached identity for the ticket's one
//!   re-call, so the retry never binds again;
//! * the outbound ops are not served (the tail states no `CAP_OUTBOUND`) and answer REFUSED.
//!
//! The bind opens the module's own LDAP socket and blocks, so the Statement states `MARK_BLOCKS`:
//! the host never runs a call inline on a worker.

use std::collections::HashMap;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::mem::size_of;
use std::ptr;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use busbar_contract::abi::auth::{
    AuthTail, BeginLoginIn, BeginLoginOut, CompleteLoginIn, FieldsIn, FieldsOut, IdentifyOut,
    IdentityBuf, LoginField, OpenOutboundIn, OpenOutboundOut, OutboundReadyIn, OutboundReadyOut,
    VerifyIn, BEGIN_FORM, CANCEL_ABANDONED, CAP_INBOUND, CAP_LOGIN, FACT_CACHEABLE, FORM_PASSWORD,
    FORM_TEXT, IDENTITY_HAS_TTL, LOGIN_BAD_CREDENTIAL, LOGIN_IDENTITY, LOGIN_KIND_CREDENTIAL,
    LOGIN_OUTAGE, SPAN_ABSENT, VERDICT_PASS,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Outcome, Span, BLOB_ABSENT};
use busbar_contract::abi::mechanism::door::{
    KindTailHead, Rewrite, Statement, MARK_BLOCKS, REWRITE_ALIAS,
};
use busbar_contract::abi::sdk::auth_door::with_tail;
use busbar_contract::abi::sdk::door::{abi_str, statement, AbiIn, AbiOut, Slot};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::auth::Principal;

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

/// This plugin's Statement.
pub const STATEMENT: Statement = with_tail(
    Statement {
        marks: MARK_BLOCKS,
        rewrites: REWRITES.as_ptr(),
        rewrites_len: REWRITES.len(),
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

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        let module = LdapModule::from_settings(settings).map_err(Refusal::failed)?;
        Ok(Self {
            module: RwLock::new(Arc::new(module)),
            reached: Mutex::default(),
        })
    }

    fn refresh(&self, settings: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        let module = LdapModule::from_settings(settings).map_err(Refusal::failed)?;
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

/// `complete_login`: BIND the submitted credential (see [`LdapModule::login`]).
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
            None => {
                let fields = submitted(input.get());
                ldap.module()
                    .login(field(&fields, USERNAME.0), field(&fields, PASSWORD.0))
            }
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
