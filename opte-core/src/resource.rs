use core::any::{Any, TypeId};

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::collections::BTreeMap;
#[cfg(any(feature = "std", test))]
use std::collections::BTreeMap;
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::string::{String, ToString};
#[cfg(any(feature = "std", test))]
use std::string::{String, ToString};
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::vec::Vec;
#[cfg(any(feature = "std", test))]
use std::vec::Vec;

use crate::sync::{KMutex, KMutexType};

pub trait Resource {
    /// Return the name of the resource. The name is used to register,
    /// lookup, and modify the resource. It must be unique in the
    /// [`Resources`] directory.
    fn name(&self) -> &str;
}

struct ResourcesInner {
    directory: BTreeMap<String, TypeId>,
    map: anymap::Map<dyn anymap::any::Any + Send + Sync>,
}

pub struct Resources {
    inner: KMutex<ResourcesInner>,
}

pub enum ResourceError {
    Exists { name: String },
}

impl Resources {
    pub fn list(&self) -> Vec<String> {
        let lock = self.inner.lock();

        let mut names = Vec::with_capacity(lock.directory.len());
        for (name, _) in lock.directory.iter() {
            names.push(name.clone());
        }

        names
    }

    pub fn new() -> Self {
        Self {
            inner: KMutex::new(
                ResourcesInner {
                    directory: BTreeMap::new(),
                    map: anymap::Map::new(),
                },
                KMutexType::Driver
            )
        }
    }

    pub fn register<R>(
        &self,
        name: &str,
        resource: R
    ) -> Result<(), ResourceError>
    where
        R: 'static + Resource + Send + Sync
    {
        let mut lock = self.inner.lock();

        if lock.directory.contains_key(name) {
            return Err(ResourceError::Exists { name: name.to_string() });
        }

        let _ = lock.directory.insert(name.to_string(), resource.type_id());
        let _ = lock.map.insert(resource);

        Ok(())
    }
}
