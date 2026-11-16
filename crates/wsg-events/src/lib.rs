//! Windows Event Log access and triage: parse event XML, query channels or exported `.evtx`
//! files, group events, apply noise rules and score what is left.

pub mod group;
pub mod noise;
pub mod reader;
pub mod score;
pub mod updates;
pub mod xml;

pub use group::{group, group_key, EventGroup, GroupKey, MAX_TIMES, MAX_VARIANTS};
pub use noise::{Disposition, NoiseError, NoiseRule, NoiseRules};
pub use reader::{
    check_rollover, inventory_channels, query, query_file, ChannelState, ChannelStatus, EventError,
    DEFAULT_CHANNELS,
};
pub use score::{score, triage, History, IncidentWindow, Triaged};
pub use xml::{format_system_time, parse_event_xml, EventRecord, XmlError};
