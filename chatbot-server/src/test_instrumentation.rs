use std::sync::atomic::{AtomicUsize, Ordering};

static ERROR_COUNT: AtomicUsize = AtomicUsize::new(0);

pub fn record_error() {
    ERROR_COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Return the current error count and reset it to zero.
pub fn take_error_count() -> usize {
    ERROR_COUNT.swap(0, Ordering::SeqCst)
}
