// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LDAP CODEC (RFC 4511), sans-IO: the requests the module sends as bytes, and the replies it
//! reads back from bytes, as pure functions (BUSBAR-1.6.0.md R5 / Q82: "a sans-IO codec over the
//! host stream ... never a blocking driver"). What crosses the host's stream is exactly these
//! bytes; nothing here opens a socket or does TLS.
//!
//! Requests carry the encoding 1.5.5's client (ldap3 0.11) wrote: a simple BIND (version 3), a
//! SEARCH (never dereferencing aliases, no size or time limit, types and values), an UNBIND, and
//! the StartTLS extended request. Replies decode fail-closed ([`crate::ber`]): a malformed message,
//! an overrunning nested length or a message past the 16 MiB cap is an error, never a panic.

use std::collections::HashMap;

use crate::ber::{self, BerError, Tlv};
use crate::filter;

/// The StartTLS extended operation's name (RFC 4511 §4.14.1).
pub const START_TLS_OID: &str = "1.3.6.1.4.1.1466.20037";

const BIND_REQUEST: u8 = 0x60;
const BIND_RESPONSE: u8 = 0x61;
const UNBIND_REQUEST: u8 = 0x42;
const SEARCH_REQUEST: u8 = 0x63;
const SEARCH_RESULT_ENTRY: u8 = 0x64;
const SEARCH_RESULT_DONE: u8 = 0x65;
const SEARCH_RESULT_REFERENCE: u8 = 0x73;
const EXTENDED_REQUEST: u8 = 0x77;
const EXTENDED_RESPONSE: u8 = 0x78;

/// SEARCH scope `baseObject`.
pub const SCOPE_BASE: i64 = 0;
/// SEARCH scope `wholeSubtree`.
pub const SCOPE_SUBTREE: i64 = 2;

/// One LDAPMessage around `op`.
fn message(id: i32, op: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(op.len() + 6);
    ber::int(&mut content, ber::INTEGER, i64::from(id));
    content.extend_from_slice(op);
    ber::element(ber::SEQUENCE, &content)
}

/// A simple BIND of `dn` with `password`, version 3.
#[must_use]
pub fn bind(id: i32, dn: &str, password: &str) -> Vec<u8> {
    let mut op = Vec::new();
    ber::int(&mut op, ber::INTEGER, 3);
    ber::tlv(&mut op, ber::OCTET_STRING, dn.as_bytes());
    ber::tlv(&mut op, 0x80, password.as_bytes());
    message(id, &ber::element(BIND_REQUEST, &op))
}

/// A SEARCH under `base` at `scope` (`SCOPE_*`) for `filter`, asking for `attrs`.
///
/// # Errors
/// The filter does not parse: [`filter::PARSE_ERROR`], 1.5.5's words.
pub fn search(
    id: i32,
    base: &str,
    scope: i64,
    filter: &str,
    attrs: &[&str],
) -> Result<Vec<u8>, &'static str> {
    let filter = filter::encode(filter)?;
    let mut op = Vec::new();
    ber::tlv(&mut op, ber::OCTET_STRING, base.as_bytes());
    ber::int(&mut op, ber::ENUMERATED, scope);
    // derefAliases neverDerefAliases, sizeLimit 0, timeLimit 0, typesOnly FALSE.
    ber::int(&mut op, ber::ENUMERATED, 0);
    ber::int(&mut op, ber::INTEGER, 0);
    ber::int(&mut op, ber::INTEGER, 0);
    ber::boolean(&mut op, ber::BOOLEAN, false);
    op.extend_from_slice(&filter);
    let mut list = Vec::new();
    for a in attrs {
        ber::tlv(&mut list, ber::OCTET_STRING, a.as_bytes());
    }
    ber::tlv(&mut op, ber::SEQUENCE, &list);
    Ok(message(id, &ber::element(SEARCH_REQUEST, &op)))
}

/// An UNBIND.
#[must_use]
pub fn unbind(id: i32) -> Vec<u8> {
    message(id, &ber::element(UNBIND_REQUEST, &[]))
}

/// The StartTLS extended request.
#[must_use]
pub fn start_tls(id: i32) -> Vec<u8> {
    message(
        id,
        &ber::element(
            EXTENDED_REQUEST,
            &ber::element(0x80, START_TLS_OID.as_bytes()),
        ),
    )
}

/// An LDAPResult: the code, the matched DN and the diagnostic text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LdapResult {
    /// The result code (0 = success, 49 = invalidCredentials).
    pub rc: u32,
    /// The matched DN.
    pub matched: String,
    /// The diagnostic message.
    pub text: String,
}

/// RFC 4511's name for a result code, as 1.5.5's client spelled it in its error text.
#[must_use]
pub const fn rc_name(rc: u32) -> &'static str {
    match rc {
        0 => "success",
        1 => "operationsError",
        2 => "protocolError",
        3 => "timeLimitExceeded",
        4 => "sizeLimitExceeded",
        5 => "compareFalse",
        6 => "compareTrue",
        7 => "authMethodNotSupported",
        8 => "strongerAuthRequired",
        10 => "referral",
        11 => "adminLimitExceeded",
        12 => "unavailableCriticalExtension",
        13 => "confidentialityRequired",
        14 => "saslBindInProgress",
        16 => "noSuchAttribute",
        17 => "undefinedAttributeType",
        18 => "inappropriateMatching",
        19 => "constraintViolation",
        20 => "attributeOrValueExists",
        21 => "invalidAttributeSyntax",
        32 => "noSuchObject",
        33 => "aliasProblem",
        34 => "invalidDNSyntax",
        36 => "aliasDereferencingProblem",
        48 => "inappropriateAuthentication",
        49 => "invalidCredentials",
        50 => "insufficientAccessRights",
        51 => "busy",
        52 => "unavailable",
        53 => "unwillingToPerform",
        54 => "loopDetect",
        64 => "namingViolation",
        65 => "objectClassViolation",
        66 => "notAllowedOnNonLeaf",
        67 => "notAllowedOnRDN",
        68 => "entryAlreadyExists",
        69 => "objectClassModsProhibited",
        71 => "affectsMultipleDSAs",
        80 => "other",
        88 => "abandoned",
        122 => "assertionFailed",
        _ => "unknown",
    }
}

impl std::fmt::Display for LdapResult {
    /// 1.5.5's words for an operation that did not succeed (`LdapError::LdapResult`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "LDAP operation result: rc={} ({}), dn: \"{}\", text: \"{}\"",
            self.rc,
            rc_name(self.rc),
            self.matched,
            self.text
        )
    }
}

/// A directory entry as a search answers it: its DN and its text-valued attributes. An attribute
/// with any value that is not UTF-8 is left out, as 1.5.5's client left it out of `attrs`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entry {
    /// The entry's DN.
    pub dn: String,
    /// Its attributes, by the server's spelling of their names.
    pub attrs: HashMap<String, Vec<String>>,
}

/// What one reply message carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// A BindResponse.
    Bind(LdapResult),
    /// A SearchResultEntry.
    Entry(Entry),
    /// A SearchResultReference (a referral the module does not follow).
    Reference,
    /// A SearchResultDone.
    Done(LdapResult),
    /// An ExtendedResponse, with its responseName when present.
    Extended(LdapResult, Option<String>),
    /// Any other protocol op, by its tag.
    Other(u8),
}

/// One reply message: its message id and what it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The messageID (0 = an unsolicited notification).
    pub id: i32,
    /// The protocol op.
    pub reply: Reply,
}

/// How many bytes the first message at the head of `input` takes once whole (`None` while more
/// are owed): [`ber::frame`].
///
/// # Errors
/// As [`ber::frame`].
pub fn frame(input: &[u8]) -> Result<Option<usize>, BerError> {
    ber::frame(input)
}

fn text(bytes: &[u8], what: &'static str) -> Result<String, BerError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| BerError::Malformed(what))
}

/// An LDAPResult's three leading components, and what follows them.
fn ldap_result(content: &[u8]) -> Result<(LdapResult, &[u8]), BerError> {
    let (code, rest) = ber::expect(content, ber::ENUMERATED, "a result without its code")?;
    let rc = u32::try_from(ber::int_value(code)?)
        .map_err(|_| BerError::Malformed("a negative result code"))?;
    let (matched, rest) = ber::expect(rest, ber::OCTET_STRING, "a result without its matched DN")?;
    let (diag, rest) = ber::expect(rest, ber::OCTET_STRING, "a result without its diagnostic")?;
    Ok((
        LdapResult {
            rc,
            // Diagnostic and matched DN are LDAPStrings; a server that breaks UTF-8 in them still
            // answered its code, so they read lossily.
            matched: String::from_utf8_lossy(matched).into_owned(),
            text: String::from_utf8_lossy(diag).into_owned(),
        },
        rest,
    ))
}

fn entry(content: &[u8]) -> Result<Entry, BerError> {
    let (dn, rest) = ber::expect(content, ber::OCTET_STRING, "an entry without its DN")?;
    let dn = text(dn, "an entry DN that is not UTF-8")?;
    let (list, _) = ber::expect(rest, ber::SEQUENCE, "an entry without its attributes")?;
    let mut attrs = HashMap::new();
    for Tlv { tag, content } in ber::items(list)? {
        if tag != ber::SEQUENCE {
            return Err(BerError::Malformed("an attribute that is not a SEQUENCE"));
        }
        let (name, rest) =
            ber::expect(content, ber::OCTET_STRING, "an attribute without its type")?;
        let name = text(name, "an attribute type that is not UTF-8")?;
        let (vals, _) = ber::expect(rest, ber::SET, "an attribute without its values")?;
        let mut values = Vec::new();
        let mut binary = false;
        for v in ber::items(vals)? {
            if v.tag != ber::OCTET_STRING {
                return Err(BerError::Malformed("a value that is not an OCTET STRING"));
            }
            match std::str::from_utf8(v.content) {
                Ok(s) => values.push(s.to_owned()),
                Err(_) => binary = true,
            }
        }
        if !binary {
            attrs.insert(name, values);
        }
    }
    Ok(Entry { dn, attrs })
}

/// Decode one whole message (exactly the bytes [`frame`] measured).
///
/// # Errors
/// Anything that is not an LDAPMessage, an overrunning nested length: [`BerError`].
pub fn decode(bytes: &[u8]) -> Result<Message, BerError> {
    let (content, rest) = ber::expect(bytes, ber::SEQUENCE, "a message that is not a SEQUENCE")?;
    if !rest.is_empty() {
        return Err(BerError::Malformed("bytes after the message"));
    }
    let (id, rest) = ber::expect(content, ber::INTEGER, "a message without its id")?;
    let id = i32::try_from(ber::int_value(id)?)
        .map_err(|_| BerError::Malformed("a message id out of range"))?;
    // What follows the op (response controls) is not read.
    let (op, _) = ber::read(rest)?;
    let reply = match op.tag {
        BIND_RESPONSE => Reply::Bind(ldap_result(op.content)?.0),
        SEARCH_RESULT_ENTRY => Reply::Entry(entry(op.content)?),
        SEARCH_RESULT_REFERENCE => Reply::Reference,
        SEARCH_RESULT_DONE => Reply::Done(ldap_result(op.content)?.0),
        EXTENDED_RESPONSE => {
            let (result, mut rest) = ldap_result(op.content)?;
            let mut name = None;
            while !rest.is_empty() {
                let (t, next) = ber::read(rest)?;
                if t.tag == 0x8a {
                    name = Some(text(t.content, "a response name that is not UTF-8")?);
                }
                rest = next;
            }
            Reply::Extended(result, name)
        }
        other => Reply::Other(other),
    };
    Ok(Message { id, reply })
}

#[cfg(test)]
#[path = "tests/codec_tests.rs"]
mod tests;
