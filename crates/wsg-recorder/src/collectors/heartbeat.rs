use super::{CollectOutcome, Collector, SampleFragment};
use std::time::Duration;

#[derive(Default)]
pub struct HeartbeatCollector {
    counter: u64,
}

impl HeartbeatCollector {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Collector for HeartbeatCollector {
    fn name(&self) -> &'static str {
        "heartbeat"
    }
    fn collect(&mut self, _budget: Duration) -> CollectOutcome {
        self.counter += 1;
        CollectOutcome::Ok(SampleFragment::Heartbeat {
            counter: self.counter,
            mono_ns: wsg_core::mono_ns(),
        })
    }
}
