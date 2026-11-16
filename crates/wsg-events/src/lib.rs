//! Windows Event Log access: parse event XML and query channels or exported `.evtx` files.

pub mod reader;
pub mod xml;

pub use reader::{
    check_rollover, inventory_channels, query, query_file, ChannelState, ChannelStatus, EventError,
    DEFAULT_CHANNELS,
};
pub use xml::{parse_event_xml, EventRecord, XmlError};
