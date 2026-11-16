//! Merging the primary and fallback rings into one record stream.
//!
//! The two rings assign unrelated `seq` numbers, so they are merged by `(boot, mono_ns, kind)`.
//! A record present in both is kept once, from the primary.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use crate::record::{BootId, Record};
use crate::ring::RingReader;

/// Records of both rings, boots oldest first and each boot in monotonic order. A ring that is
/// missing or unreadable contributes nothing; use `merge_rings_with_notes` to learn why.
pub fn merge_rings(primary: &Path, fallback: &Path) -> Vec<Record> {
    merge_rings_with_notes(primary, fallback).0
}

/// Like `merge_rings`, plus one note per ring that could not be read.
pub fn merge_rings_with_notes(primary: &Path, fallback: &Path) -> (Vec<Record>, Vec<String>) {
    let mut notes = Vec::new();
    let mut read = |p: &Path, what: &str| match RingReader::open(p) {
        Ok(r) => {
            if r.skipped_corrupt() > 0 {
                notes.push(format!("{what} ring {}: {} corrupt frames skipped", p.display(), r.skipped_corrupt()));
            }
            r.records()
        }
        Err(e) => {
            notes.push(format!("{what} ring {} not read: {e}", p.display()));
            Vec::new()
        }
    };
    let (a, b) = (read(primary, "primary"), read(fallback, "fallback"));
    (merge_records(a, b), notes)
}

/// The merge itself, on records already read.
pub fn merge_records(primary: Vec<Record>, fallback: Vec<Record>) -> Vec<Record> {
    let mut seen: HashSet<(BootId, u64, u8)> = HashSet::new();
    let mut by_boot: BTreeMap<[u8; 16], Vec<Record>> = BTreeMap::new();
    for r in primary.into_iter().chain(fallback) {
        if seen.insert((r.boot, r.mono_ns, r.kind as u8)) {
            by_boot.entry(r.boot.0).or_default().push(r);
        }
    }
    let mut boots: Vec<Vec<Record>> = by_boot.into_values().collect();
    for b in &mut boots {
        b.sort_by_key(|r| (r.mono_ns, r.kind as u8, r.seq));
    }
    // Wall clocks can move, so boots are ordered by their earliest record.
    boots.sort_by_key(|b| b.iter().map(|r| r.utc_ns).min().unwrap_or(0));
    boots.into_iter().flatten().collect()
}
