use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

// struct for thread-safe value - used propagating SIGTERM to threads and graceful shutdown
pub struct ThreadSafeRead<T> {
    inner: Arc<RwLock<T>>,
}

impl<T> ThreadSafeRead<T> {
    pub fn new(value: T) -> ThreadSafeRead<T> {
        ThreadSafeRead { inner: Arc::new(RwLock::new(value)) }
    }

    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        self.inner.read().unwrap()
    }

    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        self.inner.write().unwrap()
    }
}