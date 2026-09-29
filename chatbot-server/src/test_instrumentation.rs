use std::sync::atomic::{AtomicUsize, Ordering};

static ERROR_COUNT: AtomicUsize = AtomicUsize::new(0);

pub fn record_error() {
    ERROR_COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Return the current error count and reset it to zero.
pub fn take_error_count() -> usize {
    ERROR_COUNT.swap(0, Ordering::SeqCst)
}

/// Serializes log-capture unit tests in this crate. Tracing combines callsite
/// interest across live dispatchers, so two concurrent capture subscribers
/// with different levels can otherwise silence each other's events behind
/// each test's back. Hold across install, rebuild, emit, and asserts.
#[cfg(test)]
pub static LOG_CAPTURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
