//! Analysis of recorded telemetry and event logs: the honest incident timeline, gap
//! classification, and (later) divergence from baseline.

pub mod gap;
pub mod timeline;

pub use gap::{classify_gap, GapKind};
pub use timeline::{build_timeline, IncidentTimeline, Stamp};
