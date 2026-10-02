// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BER, both ways: minimal lengths and integers as 1.5.5's encoder wrote them, and the reader's
//! three fail-closed rules (a malformed element, an overrunning nested length, the 16 MiB cap).

use super::{
    element, expect, frame, int_content, int_value, items, read, BerError, INBOUND_CAP,
    OCTET_STRING, SEQUENCE,
};

#[test]
fn lengths_take_their_minimal_form() {
    assert_eq!(&element(OCTET_STRING, &[0; 127])[..2], &[0x04, 0x7f]);
    assert_eq!(&element(OCTET_STRING, &[0; 128])[..3], &[0x04, 0x81, 0x80]);
    assert_eq!(&element(OCTET_STRING, &[0; 255])[..3], &[0x04, 0x81, 0xff]);
    assert_eq!(
        &element(OCTET_STRING, &[0; 256])[..4],
        &[0x04, 0x82, 0x01, 0x00]
    );
    assert_eq!(element(OCTET_STRING, &[]), vec![0x04, 0x00]);
}

#[test]
fn integers_take_their_minimal_twos_complement() {
    for (v, bytes) in [
        (0_i64, vec![0x00]),
        (3, vec![0x03]),
        (127, vec![0x7f]),
        (128, vec![0x00, 0x80]),
        (256, vec![0x01, 0x00]),
        (-1, vec![0xff]),
        (-128, vec![0x80]),
        (-129, vec![0xff, 0x7f]),
        (i64::from(i32::MAX), vec![0x7f, 0xff, 0xff, 0xff]),
    ] {
        assert_eq!(int_content(v), bytes, "{v}");
        assert_eq!(int_value(&bytes), Ok(v), "{v}");
    }
}

#[test]
fn a_whole_element_reads_back_with_what_follows_it() {
    let mut bytes = element(OCTET_STRING, b"abc");
    bytes.extend_from_slice(&[0x05, 0x00]);
    let (t, rest) = read(&bytes).expect("reads");
    assert_eq!((t.tag, t.content), (OCTET_STRING, &b"abc"[..]));
    assert_eq!(rest, &[0x05, 0x00]);
    let long = element(OCTET_STRING, &[7; 300]);
    let (t, rest) = read(&long).expect("reads a long form");
    assert_eq!((t.content.len(), rest.len()), (300, 0));
}

/// SIGNED DIFFERENCE 2: a nested length that runs past its parent fails at once — the parent is
/// whole, so the bytes it promises can never come.
#[test]
fn an_overrunning_nested_length_fails_fast() {
    // A SEQUENCE of 3 content bytes holding an OCTET STRING that claims 5.
    let msg = [0x30, 0x03, 0x04, 0x05, 0x41];
    let (outer, rest) = expect(&msg, SEQUENCE, "seq").expect("the outer element is whole");
    assert!(rest.is_empty());
    assert_eq!(read(outer), Err(BerError::Overrun));
    assert_eq!(items(outer), Err(BerError::Overrun));
    // A length octet count that runs past the parent, too.
    assert_eq!(read(&[0x04, 0x82, 0x01]), Err(BerError::Overrun));
    assert!(BerError::Overrun.to_string().contains("overruns"));
}

#[test]
fn malformed_elements_are_errors_never_panics() {
    assert!(matches!(read(&[]), Err(BerError::Malformed(_))));
    assert!(matches!(
        read(&[0x1f, 0x01, 0x00]),
        Err(BerError::Malformed(_))
    ));
    assert!(matches!(
        read(&[0x30, 0x80, 0x00, 0x00]),
        Err(BerError::Malformed(_))
    ));
    assert!(matches!(
        read(&[0x04, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        Err(BerError::Malformed(_))
    ));
    assert!(matches!(int_value(&[]), Err(BerError::Malformed(_))));
    assert!(matches!(int_value(&[1; 9]), Err(BerError::Malformed(_))));
    assert!(matches!(
        expect(&element(OCTET_STRING, b"x"), SEQUENCE, "a sequence"),
        Err(BerError::Malformed("a sequence"))
    ));
    // Every truncation and every single-byte corruption of a real message reads or fails, and
    // never panics.
    let mut msg = Vec::new();
    msg.extend_from_slice(&element(OCTET_STRING, b"dn"));
    msg.extend_from_slice(&element(SEQUENCE, &element(OCTET_STRING, &[9; 140])));
    let msg = element(SEQUENCE, &msg);
    for n in 0..msg.len() {
        let _ = frame(&msg[..n]);
        let _ = read(&msg[..n]).map(|(t, _)| items(t.content));
    }
    for at in 0..msg.len() {
        for b in [0x00, 0x7f, 0x80, 0x84, 0xff] {
            let mut m = msg.clone();
            m[at] = b;
            let _ = frame(&m);
            let _ = read(&m).map(|(t, _)| items(t.content));
        }
    }
}

#[test]
fn a_message_frames_once_whole() {
    let msg = element(SEQUENCE, &element(OCTET_STRING, b"abc"));
    for n in 0..msg.len() {
        assert_eq!(
            frame(&msg[..n]),
            Ok(None),
            "{n} bytes are not a whole message"
        );
    }
    let mut two = msg.clone();
    two.extend_from_slice(&msg);
    assert_eq!(frame(&two), Ok(Some(msg.len())));
    assert!(matches!(
        frame(&element(OCTET_STRING, b"x")),
        Err(BerError::Malformed(_))
    ));
}

/// SIGNED DIFFERENCE 3: a message longer than 16 MiB is refused from its header, before its
/// bytes are buffered; one of exactly 16 MiB is not.
#[test]
fn the_inbound_cap_is_sixteen_mib_from_the_header() {
    let cap = INBOUND_CAP as u32;
    // Header 6 bytes (0x30, 0x84 and four length octets): content = cap - 6 is exactly the cap.
    let at_cap = [&[0x30, 0x84][..], &(cap - 6).to_be_bytes()[..]].concat();
    assert_eq!(
        frame(&at_cap),
        Ok(None),
        "16 MiB exactly is owed, not refused"
    );
    let over = [&[0x30, 0x84][..], &(cap - 5).to_be_bytes()[..]].concat();
    assert_eq!(frame(&over), Err(BerError::TooLarge(u64::from(cap) + 1)));
    let huge = [0x30, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert!(matches!(frame(&huge), Err(BerError::TooLarge(_))));
    assert!(BerError::TooLarge(u64::from(cap) + 1)
        .to_string()
        .contains("16 MiB inbound cap"));
}
