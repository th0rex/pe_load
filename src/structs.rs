
use std::marker::PhantomData;
use std::mem::size_of;
use std::os::raw::{c_char, c_void};
use std::slice;

use super::rva::{Pointer, RVA};

#[repr(u16)]
pub enum Machine {
    X64 = 0x8864,
    I386 = 0x14c,
}

#[repr(u16)]
pub enum OptionalHeaderSignature {
    X64 = 523,
    X86 = 267,
    ROM = 263,
}

#[repr(u32)]
#[derive(Clone, Copy)]
pub enum Characteristics {
    NoPad = 0x8,
    CntCode = 0x20,
    CntInitializedData = 0x40,
    CntUninitializedData = 0x80,
    Gprel = 0x8000,
    NumRelocationsOverflow = 0x1000000,
    MemExecute = 0x20000000,
    MemRead = 0x40000000,
    MemWrite = 0x80000000,
}

#[repr(u16)]
pub enum FileCharacteristics {
    RelocsStripped = 0x1,
    ExecutableImage = 0x2,
    LineNumsStripped = 0x4,
    LocalSymsStripped = 0x8,
    LargeAddressAware = 0x20,
    X86Machine = 0x100, // 32 bit words are supported
    DebugStripped = 0x200,
    RemovableRunFromSwap = 0x400,
    NetRunFromSwap = 0x800,
    System = 0x1000,              // system file
    Dll = 0x2000,                 // dll file
    SingleProcessorOnly = 0x4000, // no multiprocessor systems
}

#[repr(u16)]
pub enum Subsystem {
    Unknown = 0,
    Native = 1,
    WindowsGUI = 2,
    WindowsCUI = 3,
    OS2Cui = 5,
    PosixCui = 7,
    WindowsCEGui = 9,
    EFIApplication = 10,
    EFIBootServiceDriver = 11,
    EFIRuntimeDriver = 12,
    EFIRom = 13,
    XBox = 14,
    WindowsBootApplication = 16,
}

#[repr(u16)]
pub enum DirectoryEntry {
    Export = 0,
    Import = 1,
    Resource = 2,
    Exception = 3,
    Security = 4,
    Basereloc = 5,
    Debug = 6,
    Architecture = 7,
    Globalptr = 8,
    Tls = 9,
    LoadConfig = 10,
    BoundImport = 11,
    Iat = 12,
    DelayImport = 13,
    ComDescriptor = 14,
}

#[derive(Debug, PartialEq)]
pub struct RelocationType(u16);
pub const RelocateAbsolute: RelocationType = RelocationType(0);
pub const RelocateHighLow: RelocationType = RelocationType(3);
pub const RelocateDir64: RelocationType = RelocationType(10);

#[repr(u16)]
pub enum DllCharacteristics {
    DynamicBase = 0x40,
    ForceIntegrity = 0x80,
    NXCompat = 0x100, // DEP
    NoIsolation = 0x200,
    NoSEH = 0x400,
    NoBind = 0x800,
    WDMDriver = 0x2000,
    TerminalServerAware = 0x8000,
}

pub union MiscUnion {
    physical_address: u32,
    virtual_size: u32,
}

#[repr(C)]
pub struct ImageSectionHeader {
    pub name: [c_char; 8],
    pub misc: MiscUnion,
    pub(crate) virtual_address: RVA<u32, Pointer<*mut u8>>,
    pub size_of_raw_data: u32,
    pub p_raw_data: u32,
    pub p_reloc: u32,
    pub p_line_nums: u32,
    pub num_relocations: u16,
    pub num_line_nums: u16,
    pub characteristics: Characteristics,
}

// TODO: Template to pointer size of the pe file being loaded
#[repr(C)]
pub struct ImageBaseRelocation {
    pub(crate) virtual_address: RVA<u32, Pointer<*mut u64>>,
    pub size_of_block: u32,
}

impl ImageBaseRelocation {
    pub fn base_relocations<'a>(&'a self) -> BaseRelocationIterator<'a> {
        BaseRelocationIterator::new(self)
    }

    pub fn relocations(&self) -> RelocationIterator {
        RelocationIterator::new(self)
    }

    pub fn next_relocation(&self) -> Option<&ImageBaseRelocation> {
        let relocations_start = unsafe { (self as *const _).offset(1) as *const u16 };
        let count = (self.size_of_block as usize - size_of::<ImageBaseRelocation>()) / 2;
        let next_base_relocation =
            unsafe { &*(relocations_start.offset(count as _) as *const ImageBaseRelocation) };

        // TODO: Is there a better condition to check?
        if next_base_relocation.virtual_address.value == 0
            && next_base_relocation.size_of_block == 0
        {
            None
        } else {
            Some(next_base_relocation)
        }
    }
}

pub type RelocationOffset = u16;

pub struct BaseRelocationIterator<'a> {
    current: Option<&'a ImageBaseRelocation>,
}

impl<'a> BaseRelocationIterator<'a> {
    fn new(current: &'a ImageBaseRelocation) -> Self {
        Self {
            current: Some(current),
        }
    }
}

impl<'a> Iterator for BaseRelocationIterator<'a> {
    type Item = &'a ImageBaseRelocation;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(c) = self.current {
            self.current = c.next_relocation();
            Some(c)
        } else {
            None
        }
    }
}

pub struct RelocationIterator {
    relocation: *const u16,
    current: usize,
    count: usize,
}

impl RelocationIterator {
    fn new(base_relocation: &ImageBaseRelocation) -> Self {
        Self {
            relocation: unsafe { (base_relocation as *const _).offset(1) as *const _ },
            current: 0,
            count: (base_relocation.size_of_block as usize - size_of::<ImageBaseRelocation>()) / 2,
        }
    }
}

impl Iterator for RelocationIterator {
    type Item = (RelocationType, RelocationOffset);

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.count {
            None
        } else {
            let value = unsafe { &*self.relocation.offset(self.current as _) };
            self.current += 1;
            Some((
                RelocationType((value >> 12) & 0b00001111u16),
                value & 0x0FFFu16,
            ))
        }
    }
}

pub(crate) struct ThunkIterator<'a> {
    current: Pointer<*mut ThunkData>,
    _p: PhantomData<&'a u32>,
}

impl<'a> ThunkIterator<'a> {
    fn new(c: &'a ImportDescriptor, base: u64) -> Self {
        Self {
            current: c.first_thunk.resolve(base),
            _p: PhantomData,
        }
    }
}

impl<'a> Iterator for ThunkIterator<'a> {
    type Item = &'a mut ThunkData;

    fn next(&mut self) -> Option<Self::Item> {
        if unsafe { self.current.address_of_data.value } != 0 {
            let current = self.current.p;
            self.current = Pointer {
                p: unsafe { current.offset(1) },
            };
            Some(unsafe { &mut *current })
        } else {
            None
        }
    }
}

#[repr(C)]
pub struct ImportDescriptor {
    pub imports_by_name: u32,
    pub time_stamp: u32,
    pub forwarder_chain: u32,
    pub(crate) name: RVA<u32, Pointer<*const c_char>>,
    pub(crate) first_thunk: RVA<u32, Pointer<*mut ThunkData>>,
}

impl ImportDescriptor {
    pub(crate) fn thunk_iterator<'a>(&'a self, base: u64) -> ThunkIterator<'a> {
        ThunkIterator::new(self, base)
    }

    pub(crate) fn import_iterator<'a>(&'a self) -> ImportIterator<'a> {
        ImportIterator::new(self)
    }
}

pub(crate) struct ImportIterator<'a> {
    p: *const ImportDescriptor,
    _p: PhantomData<&'a ImportDescriptor>,
}

impl<'a> ImportIterator<'a> {
    fn new(i: &'a ImportDescriptor) -> Self {
        Self {
            p: i as *const _,
            _p: PhantomData,
        }
    }
}

impl<'a> Iterator for ImportIterator<'a> {
    type Item = &'a ImportDescriptor;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            if (*self.p).name.value == 0 {
                None
            } else {
                let item = &(*self.p);
                self.p = self.p.offset(1);
                Some(item)
            }
        }
    }
}

pub fn image_snap_by_ordinal(ordinal: u64) -> bool {
    (ordinal & 0x8000000000000000) != 0
}

pub fn image_ordinal(ordinal: u64) -> u64 {
    ordinal & 0xffff
}

// 64 bit
#[repr(C)]
pub union ThunkData {
    pub forwarder_string: u64,
    pub function: u64,
    pub ordinal: u64,
    pub(crate) address_of_data: RVA<u64, Pointer<*const ImageImportByName>>,
}

#[repr(C)]
pub struct TlsDirectory {
    pub address_of_raw_data: u64,
    pub end_address_of_raw_data: u64,
    pub address_of_index: u64,
    pub address_of_callbacks: u64,
    // We don't really care about the characteristics so I won't bother putting them here
}

pub type TlsCallback = Option<extern "stdcall" fn(*mut c_void, u32, *mut c_void)>;

#[repr(C)]
pub struct ImageImportByName {
    pub hint: u16,
    pub name: c_char,
}

// TODO: Template this so we can resolve it to the correct types
// and then provide getter functions in the optional header
#[repr(C)]
pub struct DataEntry<T> {
    pub(crate) virtual_address: RVA<u32, Pointer<*mut T>>,
    pub size: u32,
}

#[repr(C)]
pub struct OptionalHeader {
    pub signature: OptionalHeaderSignature,
    pub _major_linker_version: c_char,
    pub _minor_linker_version: c_char,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    // Extensions:
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: Subsystem,
    pub dll_characteristics: DllCharacteristics,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub __loader_flags: u32, // obsolete
    pub num_of_rva_and_sizes: u32,
}

impl OptionalHeader {
    fn data_entries_start(&self) -> *const u8 {
        unsafe { (self as *const _ as *const u8).offset(size_of::<OptionalHeader>() as _) }
    }

    fn data_entry<T>(&self, e: DirectoryEntry) -> &DataEntry<T> {
        unsafe {
            let ptr = (self.data_entries_start() as *const DataEntry<T>).offset(e as _);
            &*ptr
        }
    }

    pub(crate) fn get_import_descriptor(
        &self,
        base: u64,
    ) -> Option<Pointer<*const ImportDescriptor>> {
        let entry = self.data_entry::<ImportDescriptor>(DirectoryEntry::Import);
        if entry.virtual_address.value == 0 || entry.size == 0 {
            None
        } else {
            Some(entry.virtual_address.resolve(base).into())
        }
    }

    pub(crate) fn get_relocation_entries(
        &self,
        base: u64,
    ) -> Option<Pointer<*mut ImageBaseRelocation>> {
        let entry = self.data_entry::<ImageBaseRelocation>(DirectoryEntry::Basereloc);
        if entry.virtual_address.value == 0 {
            None
        } else {
            let reloc = entry.virtual_address.resolve(base);
            if reloc.size_of_block as usize <= size_of::<ImageBaseRelocation>() {
                None
            } else {
                Some(reloc)
            }
        }
    }

    pub(crate) fn get_tls_entries(&self, base: u64) -> Option<Pointer<*const TlsDirectory>> {
        let entry = self.data_entry::<TlsDirectory>(DirectoryEntry::Tls);
        if entry.virtual_address.value == 0 {
            None
        } else {
            Some(entry.virtual_address.resolve(base).into())
        }
    }

    /*pub fn get_data_entries(&self) -> &[DataEntry] {
        unsafe {
            let self_ptr = self as *const _ as *const c_char;
            slice::from_raw_parts(
                self_ptr.offset(size_of::<OptionalHeader>() as _) as *const _,
                self.num_of_rva_and_sizes as _,
            )
        }
    }*/
}

#[repr(C)]
pub struct FileHeader {
    pub machine: Machine,
    pub num_sections: u16,
    pub time_date: u32,
    pub p_symbol_table: u32,
    pub num_symbols: u32,
    pub size_optional_header: u16,
    pub characteristics: u16,
}

impl FileHeader {
    pub fn get_sections(&self) -> &[ImageSectionHeader] {
        unsafe {
            let self_ptr = self as *const _ as *const c_char;
            slice::from_raw_parts(
                self_ptr.offset((size_of::<FileHeader>() + self.size_optional_header as usize) as _)
                    as *const _,
                self.num_sections as _,
            )
        }
    }
}

#[repr(C)]
pub struct PeHeader {
    pub signature: [c_char; 4], // PE\0\0
    pub file_header: FileHeader,
    pub optional_header: OptionalHeader,
}

#[repr(C)]
pub struct DosHeader {
    pub signature: [c_char; 2], // MZ
    pub not_needed: [c_char; 58],
    pub offset_to_pe_header: u32,
}

impl DosHeader {
    pub fn get_pe_header(&self) -> &PeHeader {
        unsafe {
            let self_ptr = self as *const _ as *const c_char;
            &*(self_ptr.offset(self.offset_to_pe_header as _) as *const _)
        }
    }
}
