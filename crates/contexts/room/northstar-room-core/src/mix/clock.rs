use northstar_time::{DateTime, Utc};

pub trait MixClock: Send + Sync {
    fn now_utc(&self) -> DateTime<Utc>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemMixClock;

impl MixClock for SystemMixClock {
    fn now_utc(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FixedMixClock(pub DateTime<Utc>);

impl MixClock for FixedMixClock {
    fn now_utc(&self) -> DateTime<Utc> {
        self.0
    }
}
