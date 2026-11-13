//! Archives the previous boot's ring when it did not end with a clean-shutdown marker.

use crate::{BootId, RingError, RingReader};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentId(pub String);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentState {
    Archived,
    Analyzed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentMeta {
    pub id: IncidentId,
    /// Hex of the boot id recorded in the archived ring.
    pub previous_boot: String,
    pub detected_utc_ns: i64,
    pub state: IncidentState,
}

#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error("archive I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ring error: {0}")]
    Ring(#[from] RingError),
    #[error("incident metadata error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("archived copy does not match the original ring")]
    Mismatch,
}

fn hex(b: &[u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const META: &str = "incident.json";

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ArchiveError> {
    let tmp = path.with_extension("json.tmp");
    let mut f = fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Copies an unclean ring into `<archive_dir>/<id>/`. The original ring is never modified.
/// `incident.json` is written last (tmp file, sync, rename), so an interrupted archive is
/// retried on the next call; an unparseable `incident.json` counts as absent.
///
/// Caller contract: call this before any `Ring::create` or append on the ring path. Never
/// truncate or recreate the ring when this returns `Err`. Start a fresh empty ring only after
/// `Ok(_)`, so a new session's records never mix with the old unclean records (the incident id
/// is derived from the last record's boot id).
pub fn archive_if_unclean(
    ring: &Path,
    archive_dir: &Path,
    _new_boot: BootId,
    now_utc_ns: i64,
) -> Result<Option<IncidentId>, ArchiveError> {
    let reader = RingReader::open(ring)?;
    if reader.ended_cleanly() {
        return Ok(None);
    }
    let original = reader.records();
    let Some(last) = original.last() else {
        return Ok(None);
    };
    let prev = hex(&last.boot.0);
    let id = IncidentId(format!("inc-{prev}"));
    let dir = archive_dir.join(&id.0);
    let done = fs::read(dir.join(META)).is_ok_and(|b| serde_json::from_slice::<IncidentMeta>(&b).is_ok());
    if done {
        return Ok(Some(id));
    }
    fs::create_dir_all(&dir)?;
    let partial = dir.join("ring.bin.partial");
    fs::copy(ring, &partial)?;
    fs::OpenOptions::new().write(true).open(&partial)?.sync_all()?; // Windows needs write access to flush
    if RingReader::open(&partial)?.records() != original {
        return Err(ArchiveError::Mismatch);
    }
    fs::rename(&partial, dir.join("ring.bin"))?;
    let meta = IncidentMeta { id: id.clone(), previous_boot: prev, detected_utc_ns: now_utc_ns, state: IncidentState::Archived };
    write_atomic(&dir.join(META), &serde_json::to_vec_pretty(&meta)?)?;
    Ok(Some(id))
}

/// Lists readable incidents, oldest first. Unreadable entries are skipped.
pub fn list_incidents(archive_dir: &Path) -> Vec<IncidentMeta> {
    let Ok(rd) = fs::read_dir(archive_dir) else {
        return Vec::new();
    };
    let mut v: Vec<IncidentMeta> = rd
        .flatten()
        .filter_map(|e| serde_json::from_slice(&fs::read(e.path().join(META)).ok()?).ok())
        .collect();
    v.sort_by_key(|m| m.detected_utc_ns);
    v
}

pub fn set_state(archive_dir: &Path, id: &IncidentId, state: IncidentState) -> Result<(), ArchiveError> {
    let path = archive_dir.join(&id.0).join(META);
    let mut meta: IncidentMeta = serde_json::from_slice(&fs::read(&path)?)?;
    meta.state = state;
    write_atomic(&path, &serde_json::to_vec_pretty(&meta)?)?;
    Ok(())
}
