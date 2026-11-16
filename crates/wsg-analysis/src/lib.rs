//! Analysis of recorded telemetry and event logs: the honest incident timeline, gap
//! classification, divergence from baseline and hardware context.

pub mod baseline;
pub mod diverge;
pub mod gap;
pub mod hardware;
pub mod render;
pub mod timeline;

pub use baseline::{compare, Presence, WindowSummary};
pub use diverge::{diverged_metrics, Divergence, Stamped};
pub use gap::{classify_gap, GapKind};
pub use hardware::{DimmInfo, HardwareContext};
pub use render::{render_postmortem, PostMortemInput};
pub use timeline::{build_timeline, IncidentTimeline, Stamp};
