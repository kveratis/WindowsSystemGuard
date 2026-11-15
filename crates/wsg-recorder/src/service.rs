//! Recorder session lifecycle: archive an unclean previous ring, record, and mark a clean stop.

use std::io;
use std::path::Path;
use std::time::Duration;

use wsg_core::archive::{archive_if_unclean, ArchiveError};
use wsg_core::{
    mono_ns, now_utc_ns, BootId, NewRecord, RecordKind, Ring, RingFileSink, RingReader, RingSink, TieredWriter,
    MARKER_CLEAN,
};

const RING_BYTES: u64 = 64 << 20;

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("archiving the previous ring failed: {0}")]
    Archive(#[from] ArchiveError),
    #[error("preserving the previous fallback ring failed: {0}")]
    Preserve(#[from] io::Error),
}

/// A ring that could not be opened; every call fails, so the writer uses the other sink.
// shortcut: never retried, so a primary absent at start stays absent until restart; upgrade to
// reopening by volume GUID (Task 6 ruling) when the primary is on a removable drive.
struct Unavailable(String);

impl RingSink for Unavailable {
    fn append(&mut self, _: &NewRecord) -> io::Result<()> {
        Err(io::Error::other(self.0.clone()))
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other(self.0.clone()))
    }
}

pub struct Session {
    boot: BootId,
    writer: Option<TieredWriter>,
    primary_error: Option<String>,
}

impl Session {
    /// Archives `ring` if the previous session did not end cleanly, keeps any records left in the
    /// previous `fallback`, then starts fresh rings. `fallback` must be on a different volume from
    /// `ring`. If archiving or preserving fails, nothing is truncated and the error is returned.
    /// A primary that cannot be created (drive absent) does not stop the session: records go to
    /// the fallback and `primary_error` says why.
    pub fn start(ring: &Path, fallback: &Path, archive_dir: &Path, boot: BootId) -> Result<Session, ServiceError> {
        if ring.exists() {
            archive_if_unclean(ring, archive_dir, boot, now_utc_ns())?;
        }
        preserve_fallback(fallback, archive_dir)?;
        let (primary, primary_error) = open_sink(ring, RING_BYTES);
        let (fallback, _) = open_sink(fallback, RING_BYTES / 8);
        let writer = TieredWriter::new(primary, fallback, Duration::from_secs(1), 256);
        Ok(Session { boot, writer: Some(writer), primary_error })
    }

    pub fn writer(&self) -> &TieredWriter {
        self.writer.as_ref().expect("writer lives until stop")
    }

    /// Why the primary ring could not be created at start, if it could not.
    pub fn primary_error(&self) -> Option<&str> {
        self.primary_error.as_deref()
    }

    /// Queues the clean-shutdown marker behind every record and waits (bounded) for the writer's
    /// final flush. The marker goes through the same sink workers as the records, so it cannot
    /// race an outstanding append or block on a stalled drive.
    pub fn stop(mut self) {
        let w = self.writer.take().expect("writer lives until stop");
        w.submit(NewRecord {
            kind: RecordKind::Marker,
            boot: self.boot,
            utc_ns: now_utc_ns(),
            mono_ns: mono_ns(),
            payload: MARKER_CLEAN.to_vec(),
        });
        drop(w);
    }
}

fn open_sink(path: &Path, bytes: u64) -> (Box<dyn RingSink>, Option<String>) {
    match Ring::create(path, bytes) {
        Ok(r) => (Box::new(RingFileSink(r)), None),
        Err(e) => {
            let why = format!("{}: {e}", path.display());
            (Box::new(Unavailable(why.clone())), Some(why))
        }
    }
}

/// Copies a previous fallback ring that holds records (or cannot be read) into the archive
/// before `Ring::create` truncates it. Records there may exist nowhere else.
fn preserve_fallback(fallback: &Path, archive_dir: &Path) -> io::Result<()> {
    if !fallback.exists() {
        return Ok(());
    }
    if RingReader::open(fallback).is_ok_and(|r| r.records().is_empty()) {
        return Ok(());
    }
    std::fs::create_dir_all(archive_dir)?;
    let dest = archive_dir.join(format!("fallback-{}.bin", now_utc_ns()));
    std::fs::copy(fallback, &dest)?;
    std::fs::File::options().write(true).open(&dest)?.sync_all()
}
