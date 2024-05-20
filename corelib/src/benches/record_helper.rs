use std::time::{SystemTime, UNIX_EPOCH};

pub fn time_since_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
