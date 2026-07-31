use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

pub mod utils;

pub const UDP_TTL: Duration = Duration::from_secs(180);

/// Coalesces idle-timeout watchdog wakeups to at most one notification per second.
pub struct Heartbeat {
    notify: Notify,
    base: Instant,
    last_secs: AtomicU64,
}

impl Heartbeat {
    pub fn new() -> Self {
        Self {
            notify: Notify::new(),
            base: Instant::now(),
            last_secs: AtomicU64::new(0),
        }
    }

    pub fn tick(&self) {
        let secs = self.base.elapsed().as_secs();
        let prev = self.last_secs.fetch_max(secs, Ordering::Relaxed);
        if prev < secs {
            self.notify.notify_one();
        }
    }

    pub async fn notified(&self) {
        self.notify.notified().await;
    }
}

impl Default for Heartbeat {
    fn default() -> Self {
        Self::new()
    }
}
