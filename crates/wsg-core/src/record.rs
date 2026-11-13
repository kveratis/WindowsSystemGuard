//! Record types stored in the ring.

/// Identifies one boot session of the machine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct BootId(pub [u8; 16]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RecordKind {
    Sample = 1,
    Heartbeat = 2,
    Marker = 3,
}

impl RecordKind {
    pub fn from_u8(v: u8) -> Option<RecordKind> {
        match v {
            1 => Some(RecordKind::Sample),
            2 => Some(RecordKind::Heartbeat),
            3 => Some(RecordKind::Marker),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub seq: u64,
    pub boot: BootId,
    pub utc_ns: i64,
    pub mono_ns: u64,
    pub kind: RecordKind,
    pub payload: Vec<u8>,
}
