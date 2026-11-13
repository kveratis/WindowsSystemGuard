//! Crash-consistent ring file.
//!
//! Layout: a fixed header (magic, schema version, capacity) followed by a data area of
//! `capacity` bytes used as a circular log of framed records. Frame layout, little endian:
//! frame magic (4), seq (8), boot (16), utc_ns (8), mono_ns (8), kind (1), payload length (4),
//! payload, CRC32 (4) over every preceding byte of the frame. Frames never straddle the end of
//! the data area: when a frame does not fit, the writer zeroes the rest of the area and starts
//! again at offset 0, so the surviving records always form one contiguous `seq` window.
//! There is no stored write position; it is recovered by scanning for the highest valid `seq`.

use crate::record::{BootId, Record, RecordKind};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

const FILE_MAGIC: &[u8; 8] = b"WSGRING\0";
const SCHEMA_VERSION: u32 = 1;
const HEADER_LEN: u64 = 24;
const FRAME_MAGIC: [u8; 4] = *b"WSGF";
const FRAME_HEAD_LEN: usize = 4 + 8 + 16 + 8 + 8 + 1 + 4;
const FRAME_OVERHEAD: usize = FRAME_HEAD_LEN + 4;
const MARKER_CLEAN: &[u8] = b"clean";

/// Largest payload one record may carry.
pub const MAX_PAYLOAD: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum RingError {
    #[error("ring I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("payload of {0} bytes exceeds the record limit or the ring capacity")]
    PayloadTooLarge(usize),
    #[error("not a ring file or unsupported schema version")]
    BadHeader,
}

pub struct Ring {
    file: File,
    capacity: u64,
    head: u64,
    next_seq: u64,
    durable_seq: u64,
    last_mono: u64,
}

impl Ring {
    pub fn create(path: &Path, capacity_bytes: u64) -> Result<Ring, RingError> {
        let mut file = open_rw(path, true)?;
        file.set_len(0)?;
        file.set_len(HEADER_LEN + capacity_bytes)?;
        let mut header = Vec::with_capacity(HEADER_LEN as usize);
        header.extend_from_slice(FILE_MAGIC);
        header.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(&capacity_bytes.to_le_bytes());
        file.write_all(&header)?;
        file.sync_all()?;
        Ok(Ring { file, capacity: capacity_bytes, head: 0, next_seq: 1, durable_seq: 0, last_mono: 0 })
    }

    pub fn open(path: &Path) -> Result<Ring, RingError> {
        let mut file = open_rw(path, false)?;
        // Keep only the highest-seq frame: (end offset, seq, mono_ns).
        let mut newest = (0u64, 0u64, 0u64);
        let capacity = scan(&mut file, SCAN_CHUNK, |off, len, r| {
            if r.seq > newest.1 {
                newest = (off + len, r.seq, r.mono_ns);
            }
        })?
        .capacity;
        let (head, last, last_mono) = newest;
        Ok(Ring { file, capacity, head, next_seq: last + 1, durable_seq: last, last_mono })
    }

    pub fn append(
        &mut self,
        kind: RecordKind,
        boot: BootId,
        utc_ns: i64,
        mono_ns: u64,
        payload: &[u8],
    ) -> Result<u64, RingError> {
        let frame_len = (FRAME_OVERHEAD + payload.len()) as u64;
        if payload.len() > MAX_PAYLOAD || frame_len > self.capacity {
            return Err(RingError::PayloadTooLarge(payload.len()));
        }
        if self.head + frame_len > self.capacity {
            // Wipe the previous lap's tail so no older, non-contiguous records survive.
            let tail = vec![0u8; (self.capacity - self.head) as usize];
            self.write_at(self.head, &tail)?;
            self.head = 0;
        }
        let seq = self.next_seq;
        let mut frame = Vec::with_capacity(frame_len as usize);
        frame.extend_from_slice(&FRAME_MAGIC);
        frame.extend_from_slice(&seq.to_le_bytes());
        frame.extend_from_slice(&boot.0);
        frame.extend_from_slice(&utc_ns.to_le_bytes());
        frame.extend_from_slice(&mono_ns.to_le_bytes());
        frame.push(kind as u8);
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(payload);
        let crc = crc32fast::hash(&frame);
        frame.extend_from_slice(&crc.to_le_bytes());
        self.write_at(self.head, &frame)?;
        self.head += frame_len;
        self.next_seq += 1;
        self.last_mono = mono_ns;
        Ok(seq)
    }

    pub fn flush(&mut self) -> Result<(), RingError> {
        self.file.sync_all()?;
        self.durable_seq = self.next_seq - 1;
        Ok(())
    }

    /// Highest `seq` known to be on disk: recovered on open, advanced by `flush`.
    pub fn last_durable_seq(&self) -> u64 {
        self.durable_seq
    }

    /// Appends a `Marker` record with payload `b"clean"` and flushes it. The marker carries the
    /// current wall-clock time and the `mono_ns` of the last appended record, since the ring has
    /// no monotonic clock of its own.
    pub fn mark_clean_shutdown(&mut self, boot: BootId) -> Result<(), RingError> {
        let utc_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as i64);
        self.append(RecordKind::Marker, boot, utc_ns, self.last_mono, MARKER_CLEAN)?;
        self.flush()
    }

    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), RingError> {
        self.file.seek(SeekFrom::Start(HEADER_LEN + offset))?;
        self.file.write_all(bytes)?;
        Ok(())
    }
}

fn open_rw(path: &Path, create: bool) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(create);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_WRITE_THROUGH: u32 = 0x8000_0000;
        opts.custom_flags(FILE_FLAG_WRITE_THROUGH);
    }
    opts.open(path)
}

pub struct RingReader {
    records: Vec<Record>,
    skipped: usize,
}

impl RingReader {
    /// Reads a snapshot of the ring. Safe while a writer appends: a frame in flight fails its
    /// CRC and is counted as corrupt.
    /// Memory is bounded by the scan buffer plus the decoded valid records, not the file size.
    /// A snapshot taken while the writer wraps can mix two laps, so only the order by `seq` is
    /// guaranteed, not contiguity.
    pub fn open(path: &Path) -> Result<RingReader, RingError> {
        Self::open_chunked(path, SCAN_CHUNK)
    }

    fn open_chunked(path: &Path, chunk: usize) -> Result<RingReader, RingError> {
        let mut records = Vec::new();
        let scan = scan(File::open(path)?, chunk, |_, _, r| records.push(r))?;
        records.sort_by_key(|r| r.seq);
        Ok(RingReader { records, skipped: scan.skipped })
    }

    pub fn records(&self) -> Vec<Record> {
        self.records.clone()
    }

    /// Frames whose magic was found but which failed length or CRC validation.
    pub fn skipped_corrupt(&self) -> usize {
        self.skipped
    }

    pub fn ended_cleanly(&self) -> bool {
        self.records
            .last()
            .is_some_and(|r| r.kind == RecordKind::Marker && r.payload == MARKER_CLEAN)
    }
}

const MAX_FRAME: usize = FRAME_OVERHEAD + MAX_PAYLOAD;
/// Bytes read per step of a scan; peak scan memory is this plus one maximum-size frame.
const SCAN_CHUNK: usize = 1024 * 1024;

struct Scan {
    capacity: u64,
    skipped: usize,
    /// Size of the scan buffer, which is fixed for the whole scan.
    #[cfg(test)]
    buf_len: usize,
}

/// Validates the header, then streams the data area in `chunk`-sized reads, calling `on_frame`
/// with (data offset, frame length, record) for each valid frame.
fn scan(
    mut file: impl Read,
    chunk: usize,
    mut on_frame: impl FnMut(u64, u64, Record),
) -> Result<Scan, RingError> {
    let mut header = [0u8; HEADER_LEN as usize];
    match file.read_exact(&mut header) {
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(RingError::BadHeader),
        r => r?,
    }
    if &header[0..8] != FILE_MAGIC
        || u32::from_le_bytes(header[8..12].try_into().unwrap()) != SCHEMA_VERSION
    {
        return Err(RingError::BadHeader);
    }
    let capacity = u64::from_le_bytes(header[16..24].try_into().unwrap());

    let mut data = file.take(capacity);
    let mut buf = vec![0u8; chunk + MAX_FRAME];
    let (mut len, mut off, mut base) = (0usize, 0usize, 0u64);
    let mut eof = false;
    let mut skipped = 0;
    loop {
        // Keep a full maximum-size frame in view unless the data area is exhausted.
        if !eof && len - off < MAX_FRAME {
            buf.copy_within(off..len, 0);
            len -= off;
            base += off as u64;
            off = 0;
            while len < buf.len() {
                let n = data.read(&mut buf[len..])?;
                if n == 0 {
                    eof = true;
                    break;
                }
                len += n;
            }
            continue;
        }
        if off + 4 > len {
            break;
        }
        if buf[off..off + 4] != FRAME_MAGIC {
            off += 1;
            continue;
        }
        match decode_frame(&buf[off..len]) {
            Some((frame_len, rec)) => {
                on_frame(base + off as u64, frame_len as u64, rec);
                off += frame_len;
            }
            None => {
                skipped += 1;
                off += 1; // resynchronise on the next frame magic
            }
        }
    }
    Ok(Scan {
        capacity,
        skipped,
        #[cfg(test)]
        buf_len: buf.len(),
    })
}

fn decode_frame(buf: &[u8]) -> Option<(usize, Record)> {
    if buf.len() < FRAME_OVERHEAD {
        return None;
    }
    let u64_at = |at: usize| u64::from_le_bytes(buf[at..at + 8].try_into().unwrap());
    let payload_len = u32::from_le_bytes(buf[45..49].try_into().unwrap()) as usize;
    if payload_len > MAX_PAYLOAD || buf.len() < FRAME_OVERHEAD + payload_len {
        return None;
    }
    let crc_at = FRAME_HEAD_LEN + payload_len;
    let crc = u32::from_le_bytes(buf[crc_at..crc_at + 4].try_into().unwrap());
    if crc32fast::hash(&buf[..crc_at]) != crc {
        return None;
    }
    let rec = Record {
        seq: u64_at(4),
        boot: BootId(buf[12..28].try_into().unwrap()),
        utc_ns: u64_at(28) as i64,
        mono_ns: u64_at(36),
        kind: RecordKind::from_u8(buf[44])?,
        payload: buf[FRAME_HEAD_LEN..crc_at].to_vec(),
    };
    Some((crc_at + 4, rec))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_does_not_read_whole_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ring.bin");
        let capacity = 4 * 1024 * 1024;
        let mut ring = Ring::create(&path, capacity).unwrap();
        // Frames of varying size so many of them straddle the tiny chunk boundaries.
        for i in 1..=400u64 {
            let payload = vec![b'a' + (i % 26) as u8; 1 + (i as usize * 37) % 3000];
            ring.append(RecordKind::Sample, BootId([1; 16]), 0, i, &payload).unwrap();
        }
        drop(ring);

        let chunk = 4096;
        let mut seen = Vec::new();
        let scan = scan(File::open(&path).unwrap(), chunk, |_, _, r| seen.push(r.seq)).unwrap();
        assert_eq!(seen, (1..=400).collect::<Vec<_>>());
        assert_eq!(scan.skipped, 0);
        // The buffer is fixed at chunk + one maximum frame, far below the file size.
        assert_eq!(scan.buf_len, chunk + MAX_FRAME);
        assert!((scan.buf_len as u64) * 32 < HEADER_LEN + capacity);

        let reader = RingReader::open_chunked(&path, chunk).unwrap();
        assert_eq!(reader.records().len(), 400);
        assert_eq!(Ring::open(&path).unwrap().next_seq, 401);
    }
}
