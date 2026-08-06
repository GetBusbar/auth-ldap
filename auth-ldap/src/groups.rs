// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Pure helpers for the LDAP module: turning group DNs into role strings, and defending the two
//! places a username crosses into an LDAP wire syntax (a DN template, a search filter). These carry
//! no I/O, so they are fully unit-tested — the LDAP bind itself needs a live directory.
//!
//! ## Group DN → role normalization
//!
//! LDAP/AD groups are DNs: `CN=engineers,OU=Groups,DC=corp,DC=example`. A [`Principal`]'s `roles`
//! (wire `Identity.groups`) is a `Vec<String>` and `auth.role_bindings.ldap` keys policy on those
//! strings — so a DN "works" as a role verbatim. But it is a HOSTILE binding key: it has commas and
//! `=` (awkward YAML keys), it is case-insensitive in LDAP but case-SENSITIVE as a `role_bindings`
//! map key, and its OU path is deployment-specific. The engine offers no DN normalization, so the
//! module must decide the shape. [`RoleFrom`] lets the operator pick CN-only (the sane default) vs
//! full DN. The normalization decision sits with the plugin because the ABI has nowhere else to put
//! it; an engine-side DN-normalizing role mapper would be an additive improvement.

use std::collections::HashSet;

use crate::RoleFrom;

/// Map the raw group-membership DN values off the directory to [`crate::Principal`] role strings,
/// honoring [`RoleFrom`], de-duplicated and order-preserving.
pub fn roles_from_group_dns(group_dns: &[String], mode: RoleFrom) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(group_dns.len());
    // HashSet-backed dedup so a hostile/huge memberOf is O(n) rather than O(n^2) `Vec::contains`;
    // `out` still preserves first-seen order (we only push on a fresh insert).
    let mut seen: HashSet<String> = HashSet::with_capacity(group_dns.len());
    for dn in group_dns {
        let role = match mode {
            RoleFrom::Cn => match first_cn(dn) {
                Some(cn) => cn,
                // A memberOf value with no CN RDN (unusual) falls back to the whole trimmed value so
                // membership is never silently dropped.
                None => dn.trim().to_string(),
            },
            RoleFrom::Dn => dn.trim().to_lowercase(),
        };
        if !role.is_empty() && seen.insert(role.clone()) {
            out.push(role);
        }
    }
    out
}

/// Extract the value of the first `CN=` RDN of a DN, unescaping the handful of DN escapes we care
/// about (`\,` `\=` `\+`). Case-insensitive on the `CN` attribute name (LDAP is). Returns `None` if
/// there is no CN component.
pub(crate) fn first_cn(dn: &str) -> Option<String> {
    for rdn in split_dn_rdns(dn) {
        let (attr, val) = rdn.split_once('=')?;
        if attr.trim().eq_ignore_ascii_case("cn") {
            return Some(unescape_rdn_value(val.trim()));
        }
    }
    None
}

/// Split a DN into its top-level RDN components, honoring `\,` as an escaped comma that does NOT
/// separate RDNs. (A minimal RFC4514 split — enough for real AD/OpenLDAP memberOf values.)
fn split_dn_rdns(dn: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut chars = dn.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                // Keep the escape + escaped char together; the value unescaper deals with it later.
                cur.push('\\');
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            ',' => {
                parts.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        parts.push(cur);
    }
    parts
}

/// Unescape the DN-value escapes that survive [`split_dn_rdns`], per RFC 4514:
///   - the single-char escape `\c` (e.g. `\,` `\=` `\+` `\\` `\"`) yields the literal char `c`, and
///   - the hex-pair escape `\XX` yields the raw byte `0xXX`.
///
/// Consecutive `\XX` bytes are buffered and decoded together as UTF-8, so a multi-byte character
/// encoded as several hex escapes (e.g. `\C3\A9` → `é`) round-trips correctly.
fn unescape_rdn_value(v: &str) -> String {
    let bytes = v.as_bytes();
    let mut out = String::with_capacity(v.len());
    // Buffer of hex-escaped raw bytes awaiting a UTF-8 decode; flushed before any literal text.
    let mut pending: Vec<u8> = Vec::new();
    macro_rules! flush {
        () => {
            if !pending.is_empty() {
                out.push_str(&String::from_utf8_lossy(&pending));
                pending.clear();
            }
        };
    }
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = bytes.get(i + 2).and_then(|b| (*b as char).to_digit(16));
            if let (Some(hi), Some(lo)) = (hi, lo) {
                // `\XX` hex-pair form — a raw byte, buffered for a joint UTF-8 decode.
                pending.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
            // `\c` single-char escape — copy the escaped character verbatim (may be multi-byte).
            flush!();
            if let Some(ch) = v[i + 1..].chars().next() {
                out.push(ch);
                i += 1 + ch.len_utf8();
            } else {
                i += 1;
            }
            continue;
        }
        // Ordinary character.
        flush!();
        if let Some(ch) = v[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            i += 1;
        }
    }
    flush!();
    out
}

/// Validate a username destined for a BIND-DN TEMPLATE. A DN component cannot safely contain the DN
/// special characters, and a username with them is either a typo or an injection attempt (e.g.
/// `admin,dc=corp,dc=example` trying to rewrite the DN). Reject rather than escape here: a login
/// username legitimately has none of these. Returns the username unchanged on success.
pub fn validate_username(username: &str) -> Result<&str, String> {
    if username.is_empty() {
        return Err("empty username".to_string());
    }
    // DN special set (RFC4514) plus NUL and control chars: never valid in a login uid/sAMAccountName.
    const FORBIDDEN: &[char] = &[',', '+', '"', '\\', '<', '>', ';', '=', '\0', '\n', '\r'];
    if username
        .chars()
        .any(|c| FORBIDDEN.contains(&c) || c.is_control())
    {
        return Err("username contains characters not allowed in a bind DN".to_string());
    }
    Ok(username)
}

/// Escape a username for inclusion in an LDAP SEARCH FILTER (RFC4515). Used on the search-then-bind
/// path where the username goes into a filter like `(sAMAccountName={username})`. Unlike the DN path
/// we escape (not reject), because a search value can legitimately be broader — but `*()\NUL` must be
/// neutralized so a username can't inject filter syntax.
pub fn escape_filter(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\\' => out.push_str("\\5c"),
            '\0' => out.push_str("\\00"),
            _ => out.push(c),
        }
    }
    out
}
