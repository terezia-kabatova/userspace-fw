use std::sync::{Arc, RwLock, RwLockReadGuard};

// struct for thread-safe value - used propagating SIGTERM to threads and graceful shutdown
pub struct ThreadSafeRead<T> {
    inner: Arc<RwLock<T>>,
}

impl<T> ThreadSafeRead<T> {
    pub fn new(value: Arc<RwLock<T>>) -> ThreadSafeRead<T> {
        ThreadSafeRead { inner: value }
    }

    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        self.inner.read().unwrap()
    }
}