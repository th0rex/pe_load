#![feature(conservative_impl_trait)]

extern crate kernel32;
extern crate winapi;

pub(crate) mod rva;
mod structs;

use std::borrow::Borrow;
use std::mem;
use std::os::raw::{c_char, c_void};
use std::ptr;

use kernel32::{GetNativeSystemInfo, GetProcAddress, LoadLibraryA, VirtualAlloc, VirtualFree,
               VirtualProtect};
use winapi::{HINSTANCE, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ,
             PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS, PAGE_READONLY,
             PAGE_READWRITE, PAGE_WRITECOPY};

use structs::*;

const DLL_PROCESS_ATTACH: u32 = 1;

unsafe fn get_native_page_size() -> u32 {
    let mut sys_info = mem::zeroed();
    GetNativeSystemInfo(&mut sys_info);
    sys_info.dwPageSize
}

struct WindowsBox<T> {
    raw: *mut T,
}

impl<T> WindowsBox<T> {
    fn new(raw: *mut T) -> Self {
        Self { raw }
    }

    fn alloc(size: u64, flags: u32, protection: u32) -> Result<Self, LoadError> {
        let result = unsafe { VirtualAlloc(ptr::null_mut(), size, flags, protection) };

        if result == ptr::null_mut() {
            Err(LoadError::NoMemory)
        } else {
            Ok(Self::new(result as *mut _))
        }
    }

    fn get(&self) -> &T {
        unsafe { &*self.raw }
    }

    fn get_mut(&mut self) -> &mut T {
        unsafe { &mut *self.raw }
    }
}

impl<T> Drop for WindowsBox<T> {
    fn drop(&mut self) {
        unsafe { VirtualFree(self.raw as *mut _, 0, MEM_RELEASE) };
    }
}

#[derive(Debug)]
pub enum LoadError {
    LoadLibraryFailed,
    NoMemory,
    UnsupporrtedRelocationType(RelocationType),
    VirtualProtectFailed,
}

pub struct LoadedPEFile {
    pub entry_point: Option<extern "C" fn()>,
    memory: WindowsBox<u8>,
}

pub fn wrapped_dll_main(ep: extern "C" fn()) -> impl FnOnce() -> () {
    let x: extern "stdcall" fn(HINSTANCE, u32, *mut c_void) = unsafe { mem::transmute(ep) };
    let y = move || {
        // TODO: Use the mapped address as the HMODULE parameter (i.e. loader.image_base)
        x(ptr::null_mut(), DLL_PROCESS_ATTACH, ptr::null_mut());
    };
    y
}

/*
TODO:

enum PreferredBase {
    Exact(u64), // error if cant get
    Default, // try default image base, if dont succeed use any
    DefaultExact, // fail if can't get default
    Any, // no preference
    TryExact(u64), // try to get specified address, but don't error if cant get it and just use any
}

struct LoaderConfig<DllLoadFunc: Fn(...)..., TLSLoadFunc: Fn(...)...> {
    dll: DllLoadFunc,
    tls: TLSLoadFunc,
    preferred_base: PrefferedBase
}

impl<..., ...> LoaderConfig<..., ...> {
    fn default() -> LoaderConfig<..., ...>;

    fn set_dll_func<NewFunc: Fn(...)...>(self) -> LoaderConfig<NewFunc, old_type_params...>
}

*/

// TODO: Use RVA's

pub struct Loader<T: AsRef<[u8]>> {
    pe_buffer: T,
    image_base: u64,
}

fn resolve<T>(base: &WindowsBox<T>, offset: isize) -> *mut T {
    unsafe { base.raw.offset(offset) }
}

fn resolve_raw(base: u64, offset: isize) -> u64 {
    base + offset as u64
}

impl<T: AsRef<[u8]>> Loader<T> {
    pub fn new(pe_buffer: T) -> Self {
        Self {
            pe_buffer,
            image_base: 0,
        }
    }

    pub fn load(mut self) -> Result<LoadedPEFile, LoadError> {
        let mapped_module = self.map_module()?;
        self.image_base = mapped_module.raw as _;

        self.relocate()?;
        self.resolve_imports()?;
        self.mem_protect()?;
        self.tls_callbacks()?;

        // TODO: We're leaking all mapped sections, lul
        // we actually aren't VirtualFree is best
        let dos_header = self.get_dos_header();
        let file_header = &dos_header.get_pe_header().file_header;
        let optional_header = &dos_header.get_pe_header().optional_header;
        let address = resolve_raw(self.image_base, optional_header.address_of_entry_point as _);

        Ok(LoadedPEFile {
            memory: mapped_module,
            entry_point: match address {
                0 => None,
                x => unsafe { Some(mem::transmute(x)) },
            },
        })
    }

    fn get_dos_header<'a>(&'a self) -> &'a DosHeader {
        unsafe { &*(self.pe_buffer.as_ref().as_ptr() as *const _) }
    }

    fn map_module(&mut self) -> Result<WindowsBox<u8>, LoadError> {
        let dos_header = self.get_dos_header();
        let file_header = &dos_header.get_pe_header().file_header;

        let size = file_header
            .get_sections()
            .iter()
            .filter(|&s| s.virtual_address.value != 0)
            .map(|x| x.virtual_address.value + x.size_of_raw_data)
            .max()
            .unwrap();
        let page_size = unsafe { get_native_page_size() } - 1;
        let size = (size + page_size) & !page_size;

        let base = WindowsBox::alloc(size as _, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)?;

        // TODO: We probably (99.9999%) don't need this, even when loading dlls with LoadLibraryA
        unsafe {
            ptr::copy(
                self.pe_buffer.as_ref().as_ptr(),
                base.raw,
                dos_header.get_pe_header().optional_header.size_of_headers as _,
            )
        };

        for section in file_header
            .get_sections()
            .iter()
            .filter(|&s| s.virtual_address.value != 0)
        {
            let p = section.virtual_address.resolve(base.raw as _).p;
            if section.size_of_raw_data == 0 {
                // ???
                unsafe {
                    ptr::write_bytes(
                        p,
                        0,
                        dos_header.get_pe_header().optional_header.section_alignment as _,
                    )
                };
            } else {
                let source = unsafe {
                    self.pe_buffer
                        .as_ref()
                        .as_ptr()
                        .offset(section.p_raw_data as _)
                };
                unsafe { ptr::copy(source, p, section.size_of_raw_data as _) };
            }
        }

        Ok(base)
    }

    fn relocate(&mut self) -> Result<(), LoadError> {
        let dos_header = self.get_dos_header();
        let optional_header = &dos_header.get_pe_header().optional_header;

        // We don't need to relocate if we managed to load the image at the preferred base address.
        if self.image_base == optional_header.image_base {
            return Ok(());
        }

        match optional_header.get_relocation_entries(self.image_base) {
            None => Ok(()),
            Some(base_relocation) => {
                let delta = self.image_base - optional_header.image_base;

                for base_reloc in base_relocation.base_relocations() {
                    for (relocation_type, offset) in base_reloc.relocations() {
                        let mut address = base_reloc
                            .virtual_address
                            .resolve(self.image_base + offset as u64);

                        if relocation_type == RelocateAbsolute {
                            // TODO what to even do lul ?
                            //return Err(LoadError::UnsupporrtedRelocationType(relocation_type));
                        } else if relocation_type == RelocateDir64 {
                            *address += delta;
                        } else if relocation_type == RelocateHighLow {
                            *address += delta & u32::max_value() as u64;
                        } else {
                            return Err(LoadError::UnsupporrtedRelocationType(relocation_type));
                        }
                    }
                }

                Ok(())
            }
        }
    }

    fn resolve_imports(&mut self) -> Result<(), LoadError> {
        let dos_header = self.get_dos_header();
        let optional_header = &dos_header.get_pe_header().optional_header;

        match optional_header.get_import_descriptor(self.image_base) {
            None => Ok(()),
            Some(import_descriptor) => {
                for import_descriptor in import_descriptor.import_iterator() {
                    let dll_name = import_descriptor.name.resolve(self.image_base);
                    let hmod = unsafe { LoadLibraryA(dll_name.p) };

                    if hmod.is_null() {
                        return Err(LoadError::LoadLibraryFailed);
                    }

                    for thunk in import_descriptor.thunk_iterator(self.image_base) {
                        let function = if image_snap_by_ordinal(unsafe { thunk.ordinal }) {
                            unsafe {
                                GetProcAddress(hmod, image_ordinal(thunk.ordinal) as *const c_char)
                            }
                        } else {
                            let name = unsafe { thunk.address_of_data }.resolve(self.image_base);
                            unsafe { GetProcAddress(hmod, &name.name as *const c_char) }
                        };

                        thunk.function = function as u64;
                    }
                }

                Ok(())
            }
        }
    }

    fn mem_protect(&mut self) -> Result<(), LoadError> {
        let dos_header = self.get_dos_header();
        let file_header = &dos_header.get_pe_header().file_header;
        let mut old_protect = 0u32;

        for section in file_header
            .get_sections()
            .iter()
            .filter(|&s| s.virtual_address.value != 0 && s.size_of_raw_data != 0)
        {
            let section_base = resolve_raw(self.image_base, section.virtual_address.value as _);
            let characteristics = section.characteristics as u32;

            let flags = match (
                characteristics & Characteristics::MemExecute as u32,
                characteristics & Characteristics::MemRead as u32,
                characteristics & Characteristics::MemWrite as u32,
            ) {
                (0, 0, 0) => PAGE_NOACCESS,
                (0, 0, _) => PAGE_WRITECOPY,
                (0, _, 0) => PAGE_READONLY,
                (0, _, _) => PAGE_READWRITE,
                (_, 0, 0) => PAGE_EXECUTE,
                (_, 0, _) => PAGE_EXECUTE_WRITECOPY,
                (_, _, 0) => PAGE_EXECUTE_READ,
                (_, _, _) => PAGE_EXECUTE_READWRITE,
            };

            if unsafe {
                VirtualProtect(
                    section_base as _,
                    section.size_of_raw_data as _,
                    flags,
                    &mut old_protect,
                )
            } == 0
            {
                return Err(LoadError::VirtualProtectFailed);
            }
        }

        Ok(())
    }

    fn tls_callbacks(&mut self) -> Result<(), LoadError> {
        let dos_header = self.get_dos_header();
        let optional_header = &dos_header.get_pe_header().optional_header;

        match optional_header.get_tls_entries(self.image_base) {
            None => Ok(()),
            Some(entry) => {
                let mut callback = entry.address_of_callbacks as *const TlsCallback;

                if !callback.is_null() {
                    while let &Some(f) = unsafe { &*callback } {
                        f(
                            self.image_base as *mut _,
                            DLL_PROCESS_ATTACH,
                            ptr::null_mut(),
                        );
                        callback = unsafe { callback.offset(1) };
                    }
                }

                Ok(())
            }
        }
    }
}
