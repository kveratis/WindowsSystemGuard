//! Groups events that are the same occurrence of the same problem, whatever language the log is in.

use std::collections::{BTreeMap, HashMap};

use crate::xml::EventRecord;

/// Most timestamps kept per group.
pub const MAX_TIMES: usize = 1000;
/// Most distinct payloads kept per group.
pub const MAX_VARIANTS: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupKey {
    pub provider: String,
    pub event_id: u16,
    pub version: u8,
    /// Payload field names and their values with volatile parts (GUIDs, long numbers, hex
    /// addresses, timestamps) replaced by placeholders. The localized message is never part of it.
    pub payload_sig: String,
}

#[derive(Debug, Clone)]
pub struct EventGroup {
    pub key: GroupKey,
    pub count: u64,
    pub first_utc_ns: i64,
    pub last_utc_ns: i64,
    /// The first `MAX_TIMES` occurrences in input order.
    pub times_utc_ns: Vec<i64>,
    /// Distinct payloads, the first `MAX_VARIANTS` seen.
    pub payload_variants: Vec<BTreeMap<String, String>>,
    /// The first event of the group.
    pub sample: EventRecord,
}

pub fn group_key(e: &EventRecord) -> GroupKey {
    let sig: Vec<String> = e.payload.iter().map(|(k, v)| format!("{k}={}", normalize(v))).collect();
    GroupKey { provider: e.provider.clone(), event_id: e.event_id, version: e.version, payload_sig: sig.join(";") }
}

/// Groups `events`; groups come back ordered by their first occurrence.
pub fn group(events: &[EventRecord]) -> Vec<EventGroup> {
    let mut index: HashMap<GroupKey, usize> = HashMap::new();
    let mut out: Vec<EventGroup> = Vec::new();
    for e in events {
        let key = group_key(e);
        let i = *index.entry(key.clone()).or_insert_with(|| {
            out.push(EventGroup {
                key,
                count: 0,
                first_utc_ns: e.utc_ns,
                last_utc_ns: e.utc_ns,
                times_utc_ns: Vec::new(),
                payload_variants: Vec::new(),
                sample: e.clone(),
            });
            out.len() - 1
        });
        let g = &mut out[i];
        g.count += 1;
        g.first_utc_ns = g.first_utc_ns.min(e.utc_ns);
        g.last_utc_ns = g.last_utc_ns.max(e.utc_ns);
        if g.times_utc_ns.len() < MAX_TIMES {
            g.times_utc_ns.push(e.utc_ns);
        }
        if g.payload_variants.len() < MAX_VARIANTS && !g.payload_variants.contains(&e.payload) {
            g.payload_variants.push(e.payload.clone());
        }
    }
    out.sort_by_key(|g| g.first_utc_ns);
    out
}

/// Replaces the parts of a value that change on every occurrence but do not change what happened:
/// GUIDs, ISO timestamps, `0x` hex of 9 or more digits and decimal runs of 9 or more digits.
// shortcut: short numbers (disk 1 versus disk 2, error codes) are kept because they usually name
// what failed; a provider that puts a small changing counter in its payload splits into many
// groups, so add a per-provider ignore list when one shows up.
fn normalize(v: &str) -> String {
    let b = v.as_bytes();
    let mut out = String::with_capacity(v.len());
    let mut i = 0;
    while i < b.len() {
        if let Some(n) = guid_len(&b[i..]) {
            out.push_str("<guid>");
            i += n;
        } else if let Some(n) = timestamp_len(&b[i..]) {
            out.push_str("<time>");
            i += n;
        } else if b[i] == b'0' && b.get(i + 1).is_some_and(|c| *c == b'x' || *c == b'X') {
            let n = b[i + 2..].iter().take_while(|c| c.is_ascii_hexdigit()).count();
            if n >= 9 {
                out.push_str("<hex>");
            } else {
                out.push_str(&v[i..i + 2 + n]);
            }
            i += 2 + n;
        } else if b[i].is_ascii_digit() {
            let n = b[i..].iter().take_while(|c| c.is_ascii_digit()).count();
            if n >= 9 {
                out.push_str("<num>");
            } else {
                out.push_str(&v[i..i + n]);
            }
            i += n;
        } else {
            let ch = v[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// Length of a GUID (`8-4-4-4-12` hex digits, optionally in braces) at the start of `b`.
fn guid_len(b: &[u8]) -> Option<usize> {
    let braced = b.first() == Some(&b'{');
    let s = if braced { &b[1..] } else { b };
    let mut p = 0;
    for (k, n) in [8usize, 4, 4, 4, 12].iter().enumerate() {
        if s.len() < p + n || !s[p..p + n].iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        p += n;
        if k < 4 {
            if s.get(p) != Some(&b'-') {
                return None;
            }
            p += 1;
        }
    }
    if braced {
        if s.get(p) != Some(&b'}') {
            return None;
        }
        p += 1;
    }
    Some(p + usize::from(braced))
}

/// `2026-11-13T10:00:00` with an optional fraction and `Z`, at the start of `b`.
fn timestamp_len(b: &[u8]) -> Option<usize> {
    const SHAPE: &[u8] = b"dddd-dd-ddTdd:dd:dd";
    if b.len() < SHAPE.len() {
        return None;
    }
    for (c, s) in b.iter().zip(SHAPE) {
        let ok = if *s == b'd' { c.is_ascii_digit() } else { c == s };
        if !ok {
            return None;
        }
    }
    let mut n = SHAPE.len();
    if b.get(n) == Some(&b'.') {
        n += 1 + b[n + 1..].iter().take_while(|c| c.is_ascii_digit()).count();
    }
    if b.get(n) == Some(&b'Z') {
        n += 1;
    }
    Some(n)
}

#[cfg(test)]
mod tests {
    use super::normalize;

    #[test]
    fn volatile_parts_are_replaced_and_short_numbers_kept() {
        assert_eq!(normalize(r"\Device\Harddisk1\DR1"), r"\Device\Harddisk1\DR1");
        assert_eq!(normalize("id {8BC3F05E-D86B-11D0-A075-00C04FB68820} at 2026-11-13T10:00:00.5Z"), "id <guid> at <time>");
        assert_eq!(normalize("addr 0xFFFFF80012345678 code 0x1A pid 1234567890"), "addr <hex> code 0x1A pid <num>");
        assert_eq!(normalize("диск ✓ 7"), "диск ✓ 7");
    }
}
