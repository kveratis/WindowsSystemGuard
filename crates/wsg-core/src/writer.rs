//! Tiered writer: a bounded queue feeding a primary sink with a fallback sink and an in-memory
//! last resort.
//!
//! A blocked I/O call cannot be cancelled, so each sink lives on its own worker thread and the
//! dispatcher waits at most `deadline` for each acknowledgement. On a timeout the primary is
//! marked stalled and records go to the fallback while the original operation stays
//! outstanding. Every record not confirmed in the primary is kept, in seq order, and replayed
//! to the primary once it acknowledges again. `submit` only touches a bounded channel and
//! atomics, so a stuck sink can never block it.

use crate::record::{BootId, RecordKind};
use crate::ring::Ring;
use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub use crate::stats::WriterStats;
pub use crate::volume::{resolve_volume_path, volume_guid_for};

/// Records not yet confirmed in the primary that are kept for replay.
// shortcut: fixed cap (about an hour of 1 Hz samples), make it configurable if a caller needs more.
const MEMORY_CAP: usize = 4096;

/// Destination for records, such as a ring file on one volume.
pub trait RingSink: Send {
    fn append(&mut self, rec: &NewRecord) -> io::Result<()>;
    fn flush(&mut self) -> io::Result<()>;
}

/// A record before the ring assigns its `seq`.
#[derive(Clone, Debug, PartialEq)]
pub struct NewRecord {
    pub kind: RecordKind,
    pub boot: BootId,
    pub utc_ns: i64,
    pub mono_ns: u64,
    pub payload: Vec<u8>,
}

/// A ring file as a sink.
pub struct RingFileSink(pub Ring);

impl RingSink for RingFileSink {
    fn append(&mut self, rec: &NewRecord) -> io::Result<()> {
        self.0
            .append(rec.kind, rec.boot, rec.utc_ns, rec.mono_ns, &rec.payload)
            .map(drop)
            .map_err(io::Error::other)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush().map_err(io::Error::other)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitResult {
    Queued,
    Dropped,
}

#[derive(Default)]
struct Shared {
    dropped: AtomicU64,
    fallback_active: AtomicBool,
    primary_stalls: AtomicU64,
    memory_only: AtomicBool,
}

pub struct TieredWriter {
    queue: Option<SyncSender<NewRecord>>,
    shared: Arc<Shared>,
    dispatcher: Option<JoinHandle<()>>,
}

impl TieredWriter {
    pub fn new(
        primary: Box<dyn RingSink>,
        fallback: Box<dyn RingSink>,
        deadline: Duration,
        queue_cap: usize,
    ) -> TieredWriter {
        let (queue, rx) = mpsc::sync_channel(queue_cap);
        let shared = Arc::new(Shared::default());
        let dispatcher = Dispatcher {
            primary: Worker::spawn(primary),
            fallback: Worker::spawn(fallback),
            deadline,
            shared: shared.clone(),
            last_seq: 0,
            pending: VecDeque::new(),
            primary_dirty: false,
            fallback_dirty: false,
        };
        let handle = thread::spawn(move || dispatcher.run(rx));
        TieredWriter { queue: Some(queue), shared, dispatcher: Some(handle) }
    }

    /// Never blocks: a full queue drops the record and counts it.
    pub fn submit(&self, r: NewRecord) -> SubmitResult {
        let sent = self.queue.as_ref().map(|q| q.try_send(r));
        match sent {
            Some(Ok(())) => SubmitResult::Queued,
            Some(Err(TrySendError::Full(_) | TrySendError::Disconnected(_))) | None => {
                self.shared.dropped.fetch_add(1, Ordering::Relaxed);
                SubmitResult::Dropped
            }
        }
    }

    pub fn stats(&self) -> WriterStats {
        let s = &self.shared;
        WriterStats {
            dropped: s.dropped.load(Ordering::Relaxed),
            fallback_active: s.fallback_active.load(Ordering::Relaxed),
            primary_stalls: s.primary_stalls.load(Ordering::Relaxed),
            memory_only: s.memory_only.load(Ordering::Relaxed),
        }
    }
}

impl Drop for TieredWriter {
    /// Closes the queue and waits for the dispatcher's final replay and flush. Each sink call is
    /// bounded by the deadline, so this cannot hang on a stuck sink.
    fn drop(&mut self) {
        drop(self.queue.take());
        if let Some(h) = self.dispatcher.take() {
            let _ = h.join();
        }
    }
}

enum Op {
    Append(NewRecord),
    Flush,
}

/// What a worker's outstanding operation is.
#[derive(Clone, Copy)]
enum Busy {
    Append(u64),
    Flush,
}

/// Owns one sink on a dedicated thread; at most one operation is outstanding at a time.
struct Worker {
    ops: Sender<Op>,
    done: Receiver<io::Result<()>>,
    busy: Option<Busy>,
}

impl Worker {
    fn spawn(mut sink: Box<dyn RingSink>) -> Worker {
        let (ops, op_rx) = mpsc::channel();
        let (done_tx, done) = mpsc::channel();
        thread::spawn(move || {
            for op in op_rx {
                let r = match op {
                    Op::Append(rec) => sink.append(&rec),
                    Op::Flush => sink.flush(),
                };
                if done_tx.send(r).is_err() {
                    break;
                }
            }
        });
        Worker { ops, done, busy: None }
    }

    /// Starts `op` on an idle worker and waits up to `deadline`; `None` means it stalled.
    fn run(&mut self, op: Op, tag: Busy, deadline: Duration) -> Option<io::Result<()>> {
        if self.ops.send(op).is_err() {
            return Some(Err(io::Error::other("sink worker exited")));
        }
        self.busy = Some(tag);
        self.wait(deadline).map(|(_, r)| r)
    }

    /// Result of the outstanding operation if it completes within `wait`.
    fn wait(&mut self, wait: Duration) -> Option<(Busy, io::Result<()>)> {
        let tag = self.busy?;
        let r = match self.done.recv_timeout(wait) {
            Ok(r) => r,
            Err(RecvTimeoutError::Timeout) => return None,
            Err(RecvTimeoutError::Disconnected) => Err(io::Error::other("sink worker exited")),
        };
        self.busy = None;
        Some((tag, r))
    }
}

/// A record not yet confirmed in the primary.
struct Pending {
    seq: u64,
    rec: NewRecord,
    in_fallback: bool,
}

struct Dispatcher {
    primary: Worker,
    fallback: Worker,
    deadline: Duration,
    shared: Arc<Shared>,
    last_seq: u64,
    /// In seq order. Non-empty means new records must not bypass it to the primary.
    pending: VecDeque<Pending>,
    primary_dirty: bool,
    fallback_dirty: bool,
}

impl Dispatcher {
    fn run(mut self, rx: Receiver<NewRecord>) {
        loop {
            // Waking every deadline lets a recovered primary reconcile without new records.
            let first = match rx.recv_timeout(self.deadline) {
                Ok(r) => Some(r),
                Err(RecvTimeoutError::Timeout) => None,
                Err(RecvTimeoutError::Disconnected) => {
                    self.reconcile();
                    self.flush();
                    return;
                }
            };
            self.reconcile();
            if let Some(r) = first {
                self.write(r);
                while let Ok(r) = rx.try_recv() {
                    self.write(r);
                }
            }
            self.flush();
        }
    }

    fn stall(&self) {
        self.shared.primary_stalls.fetch_add(1, Ordering::Relaxed);
    }

    fn publish(&self) {
        let active = self.primary.busy.is_some() || !self.pending.is_empty();
        self.shared.fallback_active.store(active, Ordering::Relaxed);
    }

    /// Applies a completed primary operation.
    fn settle(&mut self, tag: Busy, r: io::Result<()>) {
        if r.is_err() {
            return;
        }
        match tag {
            Busy::Append(seq) => {
                self.primary_dirty = true;
                if self.pending.front().is_some_and(|p| p.seq == seq) {
                    self.pending.pop_front();
                }
            }
            Busy::Flush => self.primary_dirty = false,
        }
    }

    /// Picks up a late primary acknowledgement, then replays pending records in seq order.
    fn reconcile(&mut self) {
        if let Some((tag, r)) = self.primary.wait(Duration::ZERO) {
            self.settle(tag, r);
        }
        while self.primary.busy.is_none() {
            let Some(front) = self.pending.front() else { break };
            let (seq, rec) = (front.seq, front.rec.clone());
            match self.primary.run(Op::Append(rec), Busy::Append(seq), self.deadline) {
                Some(Ok(())) => self.settle(Busy::Append(seq), Ok(())),
                Some(Err(_)) => break,
                None => {
                    self.stall();
                    break;
                }
            }
        }
        self.publish();
    }

    fn write(&mut self, rec: NewRecord) {
        self.last_seq += 1;
        let seq = self.last_seq;
        if self.pending.is_empty() && self.primary.busy.is_none() {
            match self.primary.run(Op::Append(rec.clone()), Busy::Append(seq), self.deadline) {
                Some(Ok(())) => {
                    self.primary_dirty = true;
                    self.shared.memory_only.store(false, Ordering::Relaxed);
                    self.publish();
                    return;
                }
                Some(Err(_)) => {}
                None => self.stall(),
            }
        }
        let in_fallback = self.fallback_append(&rec);
        self.shared.memory_only.store(!in_fallback, Ordering::Relaxed);
        if self.pending.len() >= MEMORY_CAP {
            if let Some(old) = self.pending.pop_front() {
                // Evicted from replay only; it is lost only if the fallback never got it either.
                if !old.in_fallback {
                    self.shared.dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        self.pending.push_back(Pending { seq, rec, in_fallback });
        self.publish();
    }

    fn fallback_append(&mut self, rec: &NewRecord) -> bool {
        // A late result of a stalled fallback call only frees the worker.
        let _ = self.fallback.wait(Duration::ZERO);
        if self.fallback.busy.is_some() {
            return false;
        }
        let ok = matches!(
            self.fallback.run(Op::Append(rec.clone()), Busy::Append(0), self.deadline),
            Some(Ok(()))
        );
        self.fallback_dirty |= ok;
        ok
    }

    fn flush(&mut self) {
        if self.primary_dirty && self.primary.busy.is_none() {
            match self.primary.run(Op::Flush, Busy::Flush, self.deadline) {
                Some(r) => self.settle(Busy::Flush, r),
                None => self.stall(),
            }
        }
        if self.fallback_dirty && self.fallback.busy.is_none() {
            if let Some(Ok(())) = self.fallback.run(Op::Flush, Busy::Flush, self.deadline) {
                self.fallback_dirty = false;
            }
        }
        self.publish();
    }
}
