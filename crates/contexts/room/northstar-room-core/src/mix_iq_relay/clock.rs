use std::time::Instant;

pub trait MixRelayMonotonic: Send + Sync {
    fn now(&self) -> Instant;
}

pub struct SystemMixRelayMonotonic;

impl MixRelayMonotonic for SystemMixRelayMonotonic {
    fn now(&self) -> Instant {
        Instant::now()
    }
}
