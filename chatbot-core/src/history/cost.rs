//! Per-thread counts of sealed history blobs opened, for cost-bound tests.
//!
//! Counters are thread-local so concurrently running tests do not observe
//! each other; a `current_thread` runtime keeps a request on one thread.

use std::cell::Cell;

thread_local! {
    static PAIRS: Cell<u64> = const { Cell::new(0) };
    static IMAGES: Cell<u64> = const { Cell::new(0) };
    static THUMBS: Cell<u64> = const { Cell::new(0) };
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlobOpens {
    pub pairs: u64,
    pub images: u64,
    pub thumbs: u64,
}

/// Return this thread's counts since the last call and reset them.
pub fn take_blob_opens() -> BlobOpens {
    BlobOpens {
        pairs: PAIRS.with(|c| c.replace(0)),
        images: IMAGES.with(|c| c.replace(0)),
        thumbs: THUMBS.with(|c| c.replace(0)),
    }
}

pub(crate) fn pair_opened() {
    PAIRS.with(|c| c.set(c.get() + 1));
}

pub(crate) fn image_opened() {
    IMAGES.with(|c| c.set(c.get() + 1));
}

pub(crate) fn thumb_opened() {
    THUMBS.with(|c| c.set(c.get() + 1));
}
