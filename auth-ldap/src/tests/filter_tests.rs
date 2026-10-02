// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The filter encoder against 1.5.5's: every vector here is ldap3 0.11's own filter test, byte for
//! byte, plus the filters this module sends (the group read, an escaped search-then-bind username,
//! an AD in-chain rule).

use super::{encode, PARSE_ERROR};
use crate::groups::escape_filter;

fn ber(filter: &str) -> Vec<u8> {
    encode(filter).unwrap_or_else(|e| panic!("{filter}: {e}"))
}

#[test]
fn the_1_5_5_vectors_encode_byte_for_byte() {
    let vectors: [(&str, &[u8]); 16] = [
        ("a=v", b"\xa3\x06\x04\x01a\x04\x01v"),
        ("(a=v)", b"\xa3\x06\x04\x01a\x04\x01v"),
        ("(a<=2)", b"\xa6\x06\x04\x01a\x04\x012"),
        ("(a=*)", b"\x87\x01a"),
        ("(a=*v)", b"\xa4\x08\x04\x01a0\x03\x82\x01v"),
        ("(a=v*)", b"\xa4\x08\x04\x01a0\x03\x80\x01v"),
        ("(a=v*x*y)", b"\xa4\x0e\x04\x01a0\t\x80\x01v\x81\x01x\x82\x01y"),
        ("(a=v\\2ax)", b"\xa3\x08\x04\x01a\x04\x03v*x"),
        ("(2.5.4.3=v)", b"\xa3\x0c\x04\x072.5.4.3\x04\x01v"),
        ("(2.5.4.0=top)", b"\xa3\x0e\x04\x072.5.4.0\x04\x03top"),
        (
            "(&(a=v)(b=x)(!(c=y)))",
            b"\xa0\x1a\xa3\x06\x04\x01a\x04\x01v\xa3\x06\x04\x01b\x04\x01x\xa2\x08\xa3\x06\x04\x01c\x04\x01y",
        ),
        ("(&)", b"\xa0\0"),
        ("(|)", b"\xa1\0"),
        ("(ou:dn:=People)", b"\xa9\x0f\x82\x02ou\x83\x06People\x84\x01\xff"),
        ("(cn:2.5.13.5:=J D)", b"\xa9\x13\x81\x082.5.13.5\x82\x02cn\x83\x03J D"),
        ("(a=\u{107})", b"\xa3\x07\x04\x01a\x04\x02\xc4\x87"),
    ];
    for (filter, bytes) in vectors {
        assert_eq!(ber(filter), bytes, "{filter}");
    }
}

#[test]
fn the_filters_1_5_5_refused_are_refused() {
    for filter in [
        "(a=v)garbage",
        "(a=f**)",
        "(a=v\\2)",
        "(a=v\\0x)",
        "(2.5.04.0=top)",
        "",
        "()",
        "(a=v",
        "(&(a=v)x)",
        "(!(a=v)(b=w))",
        "(=v)",
        "(-a=v)",
        "(a=v(x)",
    ] {
        assert_eq!(encode(filter), Err(PARSE_ERROR), "{filter:?}");
    }
}

#[test]
fn the_filters_this_module_sends_encode() {
    assert_eq!(
        ber("(objectClass=*)"),
        [&b"\x87\x0b"[..], &b"objectClass"[..]].concat()
    );
    // An extensible match with only a rule (AD's in-chain membership).
    let mut rule = Vec::new();
    crate::ber::tlv(&mut rule, 0x81, b"1.2.840.113556.1.4.1941");
    crate::ber::tlv(&mut rule, 0x82, b"memberOf");
    crate::ber::tlv(&mut rule, 0x83, b"cn=g,dc=x");
    assert_eq!(
        ber("(memberOf:1.2.840.113556.1.4.1941:=cn=g,dc=x)"),
        crate::ber::element(0xa9, &rule)
    );
    // An attribute option.
    assert_eq!(ber("(cn;lang-en=x)")[..4], [0xa3, 0x0f, 0x04, 0x0a]);
}

/// The search-then-bind username as applied: `escape_filter` neutralises every metacharacter, and
/// the encoded filter carries the hostile bytes back as plain value bytes (an equality, never a
/// substrings or a second filter).
#[test]
fn an_escaped_username_is_one_equality_value() {
    let hostile = "a*)(uid=*))(|(uid=*\\\0";
    let filter = format!("(sAMAccountName={})", escape_filter(hostile));
    let got = ber(&filter);
    let mut want = Vec::new();
    crate::ber::tlv(&mut want, 0x04, b"sAMAccountName");
    crate::ber::tlv(&mut want, 0x04, hostile.as_bytes());
    assert_eq!(got, crate::ber::element(0xa3, &want));
}
