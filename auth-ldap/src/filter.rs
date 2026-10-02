// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SEARCH FILTER: an RFC 4515 string filter to its RFC 4511 BER `Filter`, as a pure function.
//! The grammar is 1.5.5's (ldap3 0.11's `filter::parse`), alternative for alternative, so every
//! filter 1.5.5 accepted encodes to the same bytes and every filter it refused is refused:
//!
//! * a filter is `(` and, or, not or an item `)`, or a bare item;
//! * an item is equality / presence / substrings (`attr=...`), `>=` `<=` `~=`, or an extensible
//!   match (`attr[:dn][:rule]:=v` or `[:dn]:rule:=v`);
//! * an attribute is a numeric OID (no superfluous leading zeroes) or a name starting with a
//!   letter, then `;option`s; a value takes `\XX` escapes and never a raw NUL, `(`, `)` or `*`
//!   (outside a substrings pattern).

use crate::ber;

/// Filter CHOICE tags (RFC 4511 §4.5.1).
const AND: u8 = 0xa0;
const OR: u8 = 0xa1;
const NOT: u8 = 0xa2;
const EQUALITY: u8 = 0xa3;
const SUBSTRINGS: u8 = 0xa4;
const GREATER_OR_EQUAL: u8 = 0xa5;
const LESS_OR_EQUAL: u8 = 0xa6;
const PRESENT: u8 = 0x87;
const APPROX: u8 = 0xa8;
const EXTENSIBLE: u8 = 0xa9;

/// The words 1.5.5 answered for a filter it could not parse.
pub const PARSE_ERROR: &str = "filter parse error";

/// `filter` as BER, or [`PARSE_ERROR`].
///
/// # Errors
/// The filter is not one 1.5.5 would parse.
pub fn encode(filter: &str) -> Result<Vec<u8>, &'static str> {
    match filtexpr(filter.as_bytes()) {
        Some((ber, [])) => Ok(ber),
        _ => Err(PARSE_ERROR),
    }
}

type Parsed<'a> = Option<(Vec<u8>, &'a [u8])>;

fn filtexpr(i: &[u8]) -> Parsed<'_> {
    filter(i).or_else(|| item(i))
}

fn filter(i: &[u8]) -> Parsed<'_> {
    let i = i.strip_prefix(b"(")?;
    let (ber, i) = filtercomp(i)?;
    let i = i.strip_prefix(b")")?;
    Some((ber, i))
}

fn filtercomp(i: &[u8]) -> Parsed<'_> {
    and_or(i, b'&', AND)
        .or_else(|| and_or(i, b'|', OR))
        .or_else(|| not(i))
        .or_else(|| item(i))
}

fn and_or(i: &[u8], op: u8, tag: u8) -> Parsed<'_> {
    let mut i = i.strip_prefix(&[op])?;
    let mut content = Vec::new();
    while let Some((ber, rest)) = filter(i) {
        content.extend_from_slice(&ber);
        i = rest;
    }
    Some((ber::element(tag, &content), i))
}

fn not(i: &[u8]) -> Parsed<'_> {
    let i = i.strip_prefix(b"!")?;
    let (ber, i) = filter(i)?;
    Some((ber::element(NOT, &ber), i))
}

fn item(i: &[u8]) -> Parsed<'_> {
    eq(i).or_else(|| non_eq(i)).or_else(|| extensible(i))
}

/// Two OCTET STRINGs (an AttributeValueAssertion) inside `tag`.
fn assertion(tag: u8, attr: &[u8], value: &[u8]) -> Vec<u8> {
    let mut content = Vec::new();
    ber::tlv(&mut content, ber::OCTET_STRING, attr);
    ber::tlv(&mut content, ber::OCTET_STRING, value);
    ber::element(tag, &content)
}

fn non_eq(i: &[u8]) -> Parsed<'_> {
    let (attr, i) = attributedescription(i)?;
    let (tag, i) = if let Some(r) = i.strip_prefix(b">=") {
        (GREATER_OR_EQUAL, r)
    } else if let Some(r) = i.strip_prefix(b"<=") {
        (LESS_OR_EQUAL, r)
    } else if let Some(r) = i.strip_prefix(b"~=") {
        (APPROX, r)
    } else {
        return None;
    };
    let (value, i) = unescaped(i)?;
    Some((assertion(tag, attr, &value), i))
}

fn eq(i: &[u8]) -> Parsed<'_> {
    let (attr, i) = attributedescription(i)?;
    let i = i.strip_prefix(b"=")?;
    let (initial, mut i) = unescaped(i)?;
    let mut mid_final: Vec<Vec<u8>> = Vec::new();
    while let Some(rest) = i.strip_prefix(b"*") {
        let (part, rest) = unescaped(rest)?;
        mid_final.push(part);
        i = rest;
    }
    // Only the last part after a `*` may be empty (`a=v*`); `a=v**x` is refused.
    let n = mid_final.len();
    if mid_final
        .iter()
        .enumerate()
        .any(|(k, p)| p.is_empty() && k + 1 != n)
    {
        return None;
    }
    let ber = if mid_final.is_empty() {
        assertion(EQUALITY, attr, &initial)
    } else if initial.is_empty() && n == 1 && mid_final[0].is_empty() {
        ber::element(PRESENT, attr)
    } else {
        let mut subs = Vec::new();
        if !initial.is_empty() {
            ber::tlv(&mut subs, 0x80, &initial);
        }
        for (k, part) in mid_final.iter().enumerate() {
            if part.is_empty() {
                break;
            }
            ber::tlv(&mut subs, if k + 1 != n { 0x81 } else { 0x82 }, part);
        }
        let mut content = Vec::new();
        ber::tlv(&mut content, ber::OCTET_STRING, attr);
        ber::tlv(&mut content, ber::SEQUENCE, &subs);
        ber::element(SUBSTRINGS, &content)
    };
    Some((ber, i))
}

fn extensible(i: &[u8]) -> Parsed<'_> {
    attr_dn_mrule(i).or_else(|| dn_mrule(i))
}

fn attr_dn_mrule(i: &[u8]) -> Parsed<'_> {
    let (attr, i) = attributedescription(i)?;
    let (dn, i) = match i.strip_prefix(b":dn") {
        Some(r) => (true, r),
        None => (false, i),
    };
    let (mrule, i) = match i.strip_prefix(b":").and_then(attributetype) {
        Some((m, r)) => (Some(m), r),
        None => (None, i),
    };
    let i = i.strip_prefix(b":=")?;
    let (value, i) = unescaped(i)?;
    Some((extensible_tag(mrule, Some(attr), &value, dn), i))
}

fn dn_mrule(i: &[u8]) -> Parsed<'_> {
    let (dn, i) = match i.strip_prefix(b":dn") {
        Some(r) => (true, r),
        None => (false, i),
    };
    let (mrule, i) = attributetype(i.strip_prefix(b":")?)?;
    let i = i.strip_prefix(b":=")?;
    let (value, i) = unescaped(i)?;
    Some((extensible_tag(Some(mrule), None, &value, dn), i))
}

fn extensible_tag(mrule: Option<&[u8]>, attr: Option<&[u8]>, value: &[u8], dn: bool) -> Vec<u8> {
    let mut content = Vec::new();
    if let Some(m) = mrule {
        ber::tlv(&mut content, 0x81, m);
    }
    if let Some(a) = attr {
        ber::tlv(&mut content, 0x82, a);
    }
    ber::tlv(&mut content, 0x83, value);
    if dn {
        ber::boolean(&mut content, 0x84, true);
    }
    ber::element(EXTENSIBLE, &content)
}

fn is_value_char(c: u8) -> bool {
    c != 0 && c != b'(' && c != b')' && c != b'*'
}

fn hex(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

/// An assertion value: value characters, `\XX` escapes decoded; `None` on a broken escape.
fn unescaped(i: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    let end = i.iter().position(|c| !is_value_char(*c)).unwrap_or(i.len());
    let (raw, rest) = i.split_at(end);
    let mut out = Vec::with_capacity(raw.len());
    let mut k = 0;
    while k < raw.len() {
        if raw[k] == b'\\' {
            let hi = raw.get(k + 1).copied().and_then(hex)?;
            let lo = raw.get(k + 2).copied().and_then(hex)?;
            out.push((hi << 4) | lo);
            k += 3;
        } else {
            out.push(raw[k]);
            k += 1;
        }
    }
    Some((out, rest))
}

fn is_alnum_hyphen(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-'
}

/// An attribute type then its `;option`s: the bytes it spans.
fn attributedescription(i: &[u8]) -> Option<(&[u8], &[u8])> {
    let (_, mut rest) = attributetype(i)?;
    while let Some(r) = rest.strip_prefix(b";") {
        let n = r.iter().take_while(|c| is_alnum_hyphen(**c)).count();
        if n == 0 {
            break;
        }
        rest = &r[n..];
    }
    let used = i.len() - rest.len();
    Some((&i[..used], rest))
}

fn attributetype(i: &[u8]) -> Option<(&[u8], &[u8])> {
    numericoid(i).or_else(|| descr(i))
}

/// A number: digits, `0` alone or no leading zero.
fn number(i: &[u8]) -> Option<usize> {
    let n = i.iter().take_while(|c| c.is_ascii_digit()).count();
    (n == 1 || (n > 1 && i[0] != b'0')).then_some(n)
}

fn numericoid(i: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut used = number(i)?;
    while i.get(used) == Some(&b'.') {
        match number(&i[used + 1..]) {
            Some(n) => used += 1 + n,
            None => break,
        }
    }
    Some(i.split_at(used))
}

fn descr(i: &[u8]) -> Option<(&[u8], &[u8])> {
    if !i.first()?.is_ascii_alphabetic() {
        return None;
    }
    let used = 1 + i[1..].iter().take_while(|c| is_alnum_hyphen(**c)).count();
    Some(i.split_at(used))
}

#[cfg(test)]
#[path = "tests/filter_tests.rs"]
mod tests;
