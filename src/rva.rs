
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};

use super::Loader;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct RVA<StorageType: Copy + Into<u64>, ResolvedType: From<u64>> {
    pub(crate) value: StorageType,
    _p: PhantomData<ResolvedType>,
}

impl<StorageType: Copy + Into<u64>, ResolvedType: From<u64>> RVA<StorageType, ResolvedType> {
    pub(crate) fn resolve(&self, base: u64) -> ResolvedType {
        (base + (self.value.into())).into()
    }
}

// Sadly *{const|mut} T: From<u64> is not implemented.
// This kind of fixes it

// The underlying pointer *must* be valid, because it will be dereferenced.
#[derive(Clone, Copy)]
pub(crate) struct Pointer<T> {
    pub(crate) p: T,
}

impl<T> Into<Pointer<*const T>> for Pointer<*mut T> {
    fn into(self) -> Pointer<*const T> {
        Pointer { p: self.p as _ }
    }
}

impl<T> From<u64> for Pointer<*const T> {
    fn from(address: u64) -> Self {
        Self { p: address as _ }
    }
}

impl<T> From<u64> for Pointer<*mut T> {
    fn from(address: u64) -> Self {
        Self { p: address as _ }
    }
}

impl<T> Deref for Pointer<*const T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.p }
    }
}

impl<T> Deref for Pointer<*mut T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.p }
    }
}

impl<T> DerefMut for Pointer<*mut T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.p }
    }
}
