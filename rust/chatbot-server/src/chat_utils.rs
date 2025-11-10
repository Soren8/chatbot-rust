use chatbot_core::bridge::chat_release_lock;
use tracing::error;

pub struct ChatLockGuard {
    session_id: String,
    released: bool,
}

impl ChatLockGuard {
    pub fn new(session_id: String) -> Self {
        Self {
            session_id,
            released: false,
        }
    }

    pub fn mark_released(&mut self) {
        self.released = true;
    }

    pub fn release_if_needed(&mut self) {
        if !self.released {
            if let Err(err) = chat_release_lock(&self.session_id) {
                error!(?err, "failed to release chat lock");
            }
            self.released = true;
        }
    }
}

impl Drop for ChatLockGuard {
    fn drop(&mut self) {
        self.release_if_needed();
    }
}
