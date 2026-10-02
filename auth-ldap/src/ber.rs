// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BER, the subset LDAP speaks (RFC 4511 §5.1: definite lengths, one-byte tags), as pure functions
//! over bytes. No I/O: the LDAP codec ([`crate::codec`]) builds and reads its messages with these.
//!
//! Reading is fail-closed (the three OWNER-SIGNED differences from 1.5.5, 2026-09-28):
//!
//! * a malformed element is an [`BerError`], never a panic;
//! * a nested element whose length overruns its parent fails at once ([`BerError::Overrun`]): the
//!   whole message is already read, so the bytes it promises can never come;
//! * a message longer than [`INBOUND_CAP`] (16 MiB) is refused from its header
//!   ([`BerError::TooLarge`]), before its bytes are buffered.

use std::fmt;

/// The most one inbound LDAP message may hold, header included: 16 MiB.
pub const INBOUND_CAP: usize = 16 * 1024 * 1024;

/// Universal BOOLEAN.
pub const BOOLEAN: u8 = 0x01;
/// Universal INTEGER.
pub const INTEGER: u8 = 0x02;
/// Universal OCTET STRING.
pub const OCTET_STRING: u8 = 0x04;
/// Universal ENUMERATED.
pub const ENUMERATED: u8 = 0x0a;
/// Universal SEQUENCE (constructed).
pub const SEQUENCE: u8 = 0x30;
/// Universal SET (constructed).
pub const SET: u8 = 0x31;

/// Why bytes are not the BER element they claim to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BerError {
    /// The bytes break the encoding: what is wrong.
    Malformed(&'static str),
    /// A nested element's length runs past the end of the element that holds it.
    Overrun,
    /// A message's length passes [`INBOUND_CAP`]: how long it said it was.
    TooLarge(u64),
}

impl fmt::Display for BerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(what) => write!(f, "malformed reply: {what}"),
            Self::Overrun => {
                f.write_str("malformed reply: a nested BER length overruns its parent")
            }
            Self::TooLarge(n) => write!(
                f,
                "the directory's message of {n} bytes passes the {} MiB inbound cap",
                INBOUND_CAP / (1024 * 1024)
            ),
        }
    }
}

impl std::error::Error for BerError {}

// ── writing ─────────────────────────────────────────────────────────────────────────────────────

/// Append a definite length in its minimal form.
fn push_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let bytes = len.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count();
    out.push(0x80 | (bytes.len() - skip) as u8);
    out.extend_from_slice(&bytes[skip..]);
}

/// Append one element: `tag`, the length of `content`, `content`.
pub fn tlv(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    out.push(tag);
    push_len(out, content.len());
    out.extend_from_slice(content);
}

/// One element as its own bytes.
#[must_use]
pub fn element(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    tlv(&mut out, tag, content);
    out
}

/// An integer's content octets: minimal two's complement.
#[must_use]
pub fn int_content(v: i64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let mut start = 0;
    while start < bytes.len() - 1 {
        let (b, next) = (bytes[start], bytes[start + 1]);
        let redundant = (b == 0x00 && next & 0x80 == 0) || (b == 0xff && next & 0x80 != 0);
        if !redundant {
            break;
        }
        start += 1;
    }
    bytes[start..].to_vec()
}

/// Append an INTEGER-shaped element (`tag` = INTEGER or ENUMERATED).
pub fn int(out: &mut Vec<u8>, tag: u8, v: i64) {
    tlv(out, tag, &int_content(v));
}

/// Append a BOOLEAN-shaped element: TRUE is `0xff`, as 1.5.5's encoder wrote it.
pub fn boolean(out: &mut Vec<u8>, tag: u8, v: bool) {
    tlv(out, tag, &[if v { 0xff } else { 0x00 }]);
}

// ── reading ─────────────────────────────────────────────────────────────────────────────────────

/// One element read off bytes: its tag and its content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// The tag byte.
    pub tag: u8,
    /// The content octets.
    pub content: &'a [u8],
}

/// A header: the tag, the content length, and how many bytes the header took.
fn header(input: &[u8]) -> Result<Option<(u8, u64, usize)>, BerError> {
    let Some(&tag) = input.first() else {
        return Ok(None);
    };
    if tag & 0x1f == 0x1f {
        return Err(BerError::Malformed("a multi-byte tag"));
    }
    let Some(&first) = input.get(1) else {
        return Ok(None);
    };
    if first < 0x80 {
        return Ok(Some((tag, u64::from(first), 2)));
    }
    let n = usize::from(first & 0x7f);
    if n == 0 {
        return Err(BerError::Malformed("an indefinite length"));
    }
    if n > 8 {
        return Err(BerError::Malformed("a length of more than eight octets"));
    }
    let Some(octets) = input.get(2..2 + n) else {
        return Ok(None);
    };
    let len = octets
        .iter()
        .fold(0_u64, |acc, b| (acc << 8) | u64::from(*b));
    Ok(Some((tag, len, 2 + n)))
}

/// How many bytes the first message at the head of `input` takes, once all of them are there:
/// `Ok(None)` while more are owed. A message whose stated length passes [`INBOUND_CAP`] is refused
/// from its header; one that is not a SEQUENCE is malformed.
///
/// # Errors
/// [`BerError::Malformed`], [`BerError::TooLarge`].
pub fn frame(input: &[u8]) -> Result<Option<usize>, BerError> {
    let Some((tag, len, head)) = header(input)? else {
        return Ok(None);
    };
    if tag != SEQUENCE {
        return Err(BerError::Malformed("a message that is not a SEQUENCE"));
    }
    let total = len.saturating_add(head as u64);
    if total > INBOUND_CAP as u64 {
        return Err(BerError::TooLarge(total));
    }
    let total = total as usize;
    Ok((input.len() >= total).then_some(total))
}

/// Read the element at the head of `input` (a whole parent's content): the element and what
/// follows it. Its length must fit in `input`; one that runs past it is an [`BerError::Overrun`].
///
/// # Errors
/// [`BerError::Malformed`] (no element, a multi-byte tag, an indefinite length),
/// [`BerError::Overrun`].
pub fn read(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), BerError> {
    let (tag, len, head) = match header(input)? {
        Some(h) => h,
        None if input.is_empty() => return Err(BerError::Malformed("a missing element")),
        None => return Err(BerError::Overrun),
    };
    let end = usize::try_from(len)
        .ok()
        .and_then(|l| l.checked_add(head))
        .filter(|end| *end <= input.len())
        .ok_or(BerError::Overrun)?;
    Ok((
        Tlv {
            tag,
            content: &input[head..end],
        },
        &input[end..],
    ))
}

/// Read the element at the head of `input`, which must carry `tag`.
///
/// # Errors
/// As [`read`]; a different tag is malformed (`what` names the element).
pub fn expect<'a>(
    input: &'a [u8],
    tag: u8,
    what: &'static str,
) -> Result<(&'a [u8], &'a [u8]), BerError> {
    let (t, rest) = read(input)?;
    if t.tag != tag {
        return Err(BerError::Malformed(what));
    }
    Ok((t.content, rest))
}

/// An INTEGER-shaped content as an `i64`.
///
/// # Errors
/// Empty, or more than eight octets: malformed.
pub fn int_value(content: &[u8]) -> Result<i64, BerError> {
    if content.is_empty() {
        return Err(BerError::Malformed("an empty integer"));
    }
    if content.len() > 8 {
        return Err(BerError::Malformed("an integer of more than eight octets"));
    }
    let negative = content[0] & 0x80 != 0;
    let mut v: i64 = if negative { -1 } else { 0 };
    for b in content {
        v = (v << 8) | i64::from(*b);
    }
    Ok(v)
}

/// Every element of a constructed element's `content`, in order.
///
/// # Errors
/// As [`read`], for any of them.
pub fn items(mut content: &[u8]) -> Result<Vec<Tlv<'_>>, BerError> {
    let mut out = Vec::new();
    while !content.is_empty() {
        let (t, rest) = read(content)?;
        out.push(t);
        content = rest;
    }
    Ok(out)
}

#[cfg(test)]
#[path = "tests/ber_tests.rs"]
mod tests;
