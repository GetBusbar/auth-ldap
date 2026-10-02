// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The LDAP codec: requests byte for byte as 1.5.5's client wrote them (hand-assembled here, not
//! through the encoder under test), replies decoded, and every malformed reply an error — never a
//! panic (OWNER-SIGNED difference 1).

use std::collections::HashMap;

use super::{
    bind, decode, frame, search, start_tls, unbind, Entry, LdapResult, Message, Reply, SCOPE_BASE,
    SCOPE_SUBTREE,
};
use crate::ber::{self, BerError};

/// `tag len content`, short form only (every hand-built message here is under 128 bytes).
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    assert!(content.len() < 128);
    [&[tag, content.len() as u8][..], content].concat()
}

#[test]
fn an_anonymous_bind_is_the_textbook_bytes() {
    assert_eq!(
        bind(1, "", ""),
        [0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00]
    );
}

#[test]
fn a_simple_bind_carries_version_3_the_dn_and_the_password() {
    let op = [
        tlv(0x02, &[3]),
        tlv(0x04, b"cn=a,dc=x"),
        tlv(0x80, b"s3cret"),
    ]
    .concat();
    let want = tlv(0x30, &[tlv(0x02, &[2]), tlv(0x60, &op)].concat());
    assert_eq!(bind(2, "cn=a,dc=x", "s3cret"), want);
}

#[test]
fn unbind_and_start_tls_are_their_textbook_bytes() {
    assert_eq!(unbind(3), [0x30, 0x05, 0x02, 0x01, 0x03, 0x42, 0x00]);
    let ext = tlv(0x77, &tlv(0x80, b"1.3.6.1.4.1.1466.20037"));
    assert_eq!(start_tls(1), tlv(0x30, &[tlv(0x02, &[1]), ext].concat()));
}

/// The group read exactly as 1.5.5 sent it: base scope, never deref, no limits, types and values,
/// `(objectClass=*)`, the one attribute.
#[test]
fn the_group_read_is_1_5_5s_search() {
    let op = [
        tlv(0x04, b"uid=alice,dc=x"),
        tlv(0x0a, &[0]),
        tlv(0x0a, &[0]),
        tlv(0x02, &[0]),
        tlv(0x02, &[0]),
        tlv(0x01, &[0]),
        tlv(0x87, b"objectClass"),
        tlv(0x30, &tlv(0x04, b"memberOf")),
    ]
    .concat();
    let want = tlv(0x30, &[tlv(0x02, &[4]), tlv(0x63, &op)].concat());
    assert_eq!(
        search(
            4,
            "uid=alice,dc=x",
            SCOPE_BASE,
            "(objectClass=*)",
            &["memberOf"]
        ),
        Ok(want)
    );
    let sub = search(5, "dc=x", SCOPE_SUBTREE, "(uid=a)", &["dn"]).expect("encodes");
    assert!(
        sub.windows(3).any(|w| w == [0x0a, 0x01, 0x02]),
        "subtree scope"
    );
}

#[test]
fn a_filter_1_5_5_could_not_parse_is_its_words() {
    assert_eq!(
        search(1, "dc=x", SCOPE_SUBTREE, "(uid=a", &["dn"]),
        Err("filter parse error")
    );
}

fn result(rc: u8, matched: &[u8], text: &[u8]) -> Vec<u8> {
    [tlv(0x0a, &[rc]), tlv(0x04, matched), tlv(0x04, text)].concat()
}

fn msg(id: u8, op: &[u8]) -> Vec<u8> {
    tlv(0x30, &[tlv(0x02, &[id]), op.to_vec()].concat())
}

#[test]
fn a_bind_response_decodes() {
    let m = msg(1, &tlv(0x61, &result(49, b"", b"bad")));
    assert_eq!(frame(&m), Ok(Some(m.len())));
    assert_eq!(
        decode(&m),
        Ok(Message {
            id: 1,
            reply: Reply::Bind(LdapResult {
                rc: 49,
                matched: String::new(),
                text: "bad".into()
            })
        })
    );
    // Response controls after the op are not read.
    let with_controls = msg(
        1,
        &[
            tlv(0x61, &result(0, b"", b"")),
            tlv(0xa0, &tlv(0x30, &tlv(0x04, b"1.2"))),
        ]
        .concat(),
    );
    assert!(
        matches!(decode(&with_controls), Ok(Message { id: 1, reply: Reply::Bind(r) }) if r.rc == 0)
    );
}

#[test]
fn a_search_entry_decodes_its_text_attributes_only() {
    fn attr(name: &[u8], vals: &[&[u8]]) -> Vec<u8> {
        let vals: Vec<u8> = vals.iter().flat_map(|v| tlv(0x04, v)).collect();
        tlv(0x30, &[tlv(0x04, name), tlv(0x31, &vals)].concat())
    }
    let attrs = [
        attr(b"memberOf", &[b"cn=a,dc=x", b"cn=b,dc=x"]),
        attr(b"jpegPhoto", &[b"\xff\xd8"]),
        attr(b"mixed", &[b"text", b"\xff"]),
        attr(b"empty", &[]),
    ]
    .concat();
    let m = msg(
        2,
        &tlv(
            0x64,
            &[tlv(0x04, b"uid=alice,dc=x"), tlv(0x30, &attrs)].concat(),
        ),
    );
    let want: HashMap<String, Vec<String>> = [
        (
            "memberOf".to_string(),
            vec!["cn=a,dc=x".to_string(), "cn=b,dc=x".to_string()],
        ),
        ("empty".to_string(), Vec::new()),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        decode(&m),
        Ok(Message {
            id: 2,
            reply: Reply::Entry(Entry {
                dn: "uid=alice,dc=x".into(),
                attrs: want
            })
        })
    );
}

/// A failed search reads in 1.5.5's words (`LdapError::LdapResult`'s Display).
#[test]
fn a_search_done_decodes_and_reads_in_1_5_5s_words() {
    let m = msg(3, &tlv(0x65, &result(32, b"dc=x", b"no such entry")));
    let Ok(Message {
        id: 3,
        reply: Reply::Done(r),
    }) = decode(&m)
    else {
        panic!("a done");
    };
    assert_eq!(
        r.to_string(),
        "LDAP operation result: rc=32 (noSuchObject), dn: \"dc=x\", text: \"no such entry\""
    );
    let reference = msg(3, &tlv(0x73, &tlv(0x04, b"ldap://elsewhere/")));
    assert_eq!(decode(&reference).map(|m| m.reply), Ok(Reply::Reference));
}

#[test]
fn an_extended_response_decodes_with_its_name() {
    let m = msg(
        1,
        &tlv(
            0x78,
            &[result(0, b"", b""), tlv(0x8a, b"1.3.6.1.4.1.1466.20037")].concat(),
        ),
    );
    assert_eq!(
        decode(&m).map(|m| m.reply),
        Ok(Reply::Extended(
            LdapResult::default(),
            Some("1.3.6.1.4.1.1466.20037".into())
        ))
    );
    // A notice of disconnection: id 0, its own name.
    let notice = msg(
        0,
        &tlv(
            0x78,
            &[
                result(52, b"", b"bye"),
                tlv(0x8a, b"1.3.6.1.4.1.1466.20036"),
            ]
            .concat(),
        ),
    );
    assert!(
        matches!(decode(&notice), Ok(Message { id: 0, reply: Reply::Extended(r, _) }) if r.rc == 52)
    );
}

/// SIGNED DIFFERENCE 1: a malformed reply is an error, never a panic.
#[test]
fn a_malformed_reply_is_an_error_never_a_panic() {
    for bad in [
        // Not a SEQUENCE.
        tlv(0x04, b"x"),
        // No message id.
        tlv(0x30, &tlv(0x61, &result(0, b"", b""))),
        // An op with no result code.
        msg(1, &tlv(0x61, &tlv(0x04, b""))),
        // A negative result code.
        msg(
            1,
            &tlv(
                0x61,
                &[tlv(0x0a, &[0xff]), tlv(0x04, b""), tlv(0x04, b"")].concat(),
            ),
        ),
        // An entry DN that is not UTF-8.
        msg(
            2,
            &tlv(0x64, &[tlv(0x04, b"\xff"), tlv(0x30, &[])].concat()),
        ),
        // An entry without its attribute list.
        msg(2, &tlv(0x64, &tlv(0x04, b"dn"))),
        // A value that is not an OCTET STRING.
        msg(
            2,
            &tlv(
                0x64,
                &[
                    tlv(0x04, b"dn"),
                    tlv(
                        0x30,
                        &tlv(
                            0x30,
                            &[tlv(0x04, b"a"), tlv(0x31, &tlv(0x02, &[1]))].concat(),
                        ),
                    ),
                ]
                .concat(),
            ),
        ),
        // Trailing bytes after the message.
        [msg(1, &tlv(0x61, &result(0, b"", b""))), vec![0x00]].concat(),
    ] {
        assert!(decode(&bad).is_err(), "{bad:02x?}");
    }
    // Every truncation and every one-byte corruption of a real entry decodes or fails, never
    // panics.
    let m = msg(
        2,
        &tlv(
            0x64,
            &[
                tlv(0x04, b"uid=alice,dc=x"),
                tlv(
                    0x30,
                    &tlv(
                        0x30,
                        &[tlv(0x04, b"memberOf"), tlv(0x31, &tlv(0x04, b"cn=a"))].concat(),
                    ),
                ),
            ]
            .concat(),
        ),
    );
    for n in 0..m.len() {
        assert!(
            decode(&m[..n]).is_err(),
            "a truncated message is no message"
        );
    }
    for at in 0..m.len() {
        for b in [0x00, 0x01, 0x7f, 0x80, 0x82, 0xff] {
            let mut c = m.clone();
            c[at] = b;
            let _ = frame(&c);
            let _ = decode(&c);
        }
    }
}

/// SIGNED DIFFERENCE 2: an overrunning nested length inside a whole message fails at once.
#[test]
fn an_overrunning_nested_length_fails_fast() {
    // The entry's attribute list claims 0x7f bytes inside a message that holds far fewer.
    let inner = [tlv(0x04, b"dn"), vec![0x30, 0x7f, 0x30, 0x00]].concat();
    let m = msg(2, &tlv(0x64, &inner));
    assert_eq!(frame(&m), Ok(Some(m.len())), "the message itself is whole");
    assert_eq!(decode(&m), Err(BerError::Overrun));
}

/// SIGNED DIFFERENCE 3: a reply past 16 MiB is refused from its header.
#[test]
fn a_reply_past_the_cap_is_refused_from_its_header() {
    let len = (ber::INBOUND_CAP as u32).to_be_bytes();
    let head = [&[0x30, 0x84][..], &len[..]].concat();
    assert!(matches!(frame(&head), Err(BerError::TooLarge(_))));
}
