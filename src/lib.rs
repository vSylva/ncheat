/*!

# Inspired by: <https://github.com/pseuxide/toy-arms>

# Example

```rust
use ncheat::*;

fn main() {

    unsafe {

        let process_name = "explorer.exe";

        // "explorer.exe" -> module_name: "Explorer.EXE"
        let module_name = "Explorer.EXE";

        let process_id = get_process_id_64(process_name).unwrap();

        let module_info = get_module_info_64(process_id, module_name).unwrap();

        // ** or ??
        let explorer_pat = "48 89 5C 24 08 57 ** 83 EC 30 ?? 01";

        let process_handle = get_process_handle(process_id);

        let explorer_module_data = memory_read(
            process_handle,
            module_info.modBaseAddr as isize,
            module_info.modBaseSize as usize,
        )
        .unwrap();

        let explorer_offset = pattern_find(explorer_pat, &explorer_module_data).unwrap();

        let explorer_offsets = pattern_scan(explorer_pat, &explorer_module_data).unwrap();

        println!("process_name: \"{process_name}\"");

        println!("process_id: {process_id}");

        println!("module_name: \"{module_name}\"");

        println!("module address: {:#X}", module_info.modBaseAddr as usize);

        println!("module size: {:#X}", module_info.modBaseSize,);

        println!("Explorer.EXE pat offset: {explorer_offset:#X}");

        println!("Explorer.EXE pat offsets: {explorer_offsets:#X?}");
    }

    {

        let test_data: [u8; 30] = [
            0x12, 0xAF, 0xBF, 0xC4, 0x51, 0x21, 0x98, 0x13, 0xFF, 0x20, 0x20, 0xAF, 0xBF, 0xC4,
            0x51, 0x21, 0x98, 0x13, 0xFF, 0xBA, 0x12, 0xAF, 0xBF, 0xC4, 0x51, 0x21, 0x98, 0x13,
            0xFF, 0xBA,
        ];

        // ** or ??
        let test_offset = pattern_find("51 ?? ** 13 FF ??", &test_data).unwrap();

        // ** or ??
        let test_offsets = pattern_scan("51 ** ?? 13 FF **", &test_data).unwrap();

        println!("test_offset: {:#X}", test_offset);

        println!("test_offsets: {:#X?}", test_offsets);
    }
}
```

 ```c
process_name: "explorer.exe"
process_id: 19212
module_name: "Explorer.EXE"
module address: 0x7FF779270000
module size: 0x49D000
Explorer.EXE pat offset: 0xA0420
Explorer.EXE pat offsets: [
    0xA0420,
]
test_offset: 0x4
test_offsets: [
    0x4,
    0xE,
    0x18,
]
 ```

 */

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

#[link(name = "kernel32")]

extern "system" {

    pub fn CloseHandle(hObject: isize) -> i32;

    pub fn IsWow64Process(hProcess: isize, Wow64Process: *mut i32);

    pub fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> isize;

    pub fn GetSystemInfo(lpSystemInfo: *mut SYSTEM_INFO);

    pub fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> isize;

    pub fn Module32First(hSnapshot: isize, lpme: *mut MODULEENTRY32) -> i32;

    pub fn Module32FirstW(hSnapshot: isize, lpme: *mut MODULEENTRY32W) -> i32;

    pub fn Module32Next(hSnapshot: isize, lpme: *mut MODULEENTRY32) -> i32;

    pub fn Module32NextW(hSnapshot: isize, lpme: *mut MODULEENTRY32W) -> i32;

    pub fn Process32First(hSnapshot: isize, lppe: *mut PROCESSENTRY32) -> i32;

    pub fn Process32FirstW(hSnapshot: isize, lppe: *mut PROCESSENTRY32W) -> i32;

    pub fn Process32Next(hSnapshot: isize, lppe: *mut PROCESSENTRY32) -> i32;

    pub fn Process32NextW(hSnapshot: isize, lppe: *mut PROCESSENTRY32W) -> i32;

    pub fn VirtualProtectEx(
        hProcess: isize,
        lpAddress: *const core::ffi::c_void,
        dwSize: usize,
        flNewProtect: u32,
        lpflOldProtect: *mut u32,
    ) -> i32;

    pub fn VirtualAlloc(
        lpAddress: *mut core::ffi::c_void,
        dwSize: usize,
        flAllocationType: u32,
        flProtect: u32,
    ) -> *mut core::ffi::c_void;

    pub fn VirtualAllocEx(
        hProcess: isize,
        lpAddress: *mut core::ffi::c_void,
        dwSize: usize,
        flAllocationType: u32,
        flProtect: u32,
    ) -> *mut core::ffi::c_void;

    pub fn VirtualQuery(
        lpAddress: *const core::ffi::c_void,
        lpBuffer: *mut MEMORY_BASIC_INFORMATION,
        dwLength: usize,
    ) -> usize;

    pub fn VirtualQueryEx(
        hProcess: isize,
        lpAddress: *const core::ffi::c_void,
        lpBuffer: *mut MEMORY_BASIC_INFORMATION,
        dwLength: usize,
    ) -> usize;

    pub fn ReadProcessMemory(
        hProcess: isize,
        lpBaseAddress: *const core::ffi::c_void,
        lpBuffer: *mut core::ffi::c_void,
        nSize: usize,
        lpNumberOfBytesRead: *mut usize,
    ) -> i32;

    pub fn WriteProcessMemory(
        hProcess: isize,
        lpBaseAddress: *const core::ffi::c_void,
        lpBuffer: *const core::ffi::c_void,
        nSize: usize,
        lpNumberOfBytesWritten: *mut usize,
    ) -> i32;

}

#[repr(C)]
#[derive(Clone, Copy)]

pub struct SYSTEM_INFO {
    pub Anonymous: SYSTEM_INFO_0,
    pub dwPageSize: u32,
    pub lpMinimumApplicationAddress: *mut core::ffi::c_void,
    pub lpMaximumApplicationAddress: *mut core::ffi::c_void,
    pub dwActiveProcessorMask: usize,
    pub dwNumberOfProcessors: u32,
    pub dwProcessorType: u32,
    pub dwAllocationGranularity: u32,
    pub wProcessorLevel: u16,
    pub wProcessorRevision: u16,
}

impl Default for SYSTEM_INFO {
    fn default() -> Self {

        unsafe {

            core::mem::zeroed()
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]

pub union SYSTEM_INFO_0 {
    pub dwOemId: u32,
    pub Anonymous: SYSTEM_INFO_0_0,
}

#[repr(C)]
#[derive(Clone, Copy)]

pub struct SYSTEM_INFO_0_0 {
    pub wProcessorArchitecture: u16,
    pub wReserved: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]

pub struct MEMORY_BASIC_INFORMATION {
    pub BaseAddress: *mut core::ffi::c_void,
    pub AllocationBase: *mut core::ffi::c_void,
    pub AllocationProtect: u32,
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    pub PartitionId: u16,
    pub RegionSize: usize,
    pub State: u32,
    pub Protect: u32,
    pub Type: u32,
}

impl Default for MEMORY_BASIC_INFORMATION {
    fn default() -> Self {

        unsafe {

            core::mem::zeroed()
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]

pub struct MODULEENTRY32 {
    pub dwSize: u32,
    pub th32ModuleID: u32,
    pub th32ProcessID: u32,
    pub GlblcntUsage: u32,
    pub ProccntUsage: u32,
    pub modBaseAddr: *mut u8,
    pub modBaseSize: u32,
    pub hModule: isize,
    pub szModule: [u8; 256],
    pub szExePath: [u8; 260],
}

impl Default for MODULEENTRY32 {
    fn default() -> Self {

        unsafe {

            core::mem::zeroed()
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]

pub struct MODULEENTRY32W {
    pub dwSize: u32,
    pub th32ModuleID: u32,
    pub th32ProcessID: u32,
    pub GlblcntUsage: u32,
    pub ProccntUsage: u32,
    pub modBaseAddr: *mut u8,
    pub modBaseSize: u32,
    pub hModule: isize,
    pub szModule: [u16; 256],
    pub szExePath: [u16; 260],
}

impl Default for MODULEENTRY32W {
    fn default() -> Self {

        unsafe {

            core::mem::zeroed()
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]

pub struct PROCESSENTRY32 {
    pub dwSize: u32,
    pub cntUsage: u32,
    pub th32ProcessID: u32,
    pub th32DefaultHeapID: usize,
    pub th32ModuleID: u32,
    pub cntThreads: u32,
    pub th32ParentProcessID: u32,
    pub pcPriClassBase: i32,
    pub dwFlags: u32,
    pub szExeFile: [u8; 260],
}

impl Default for PROCESSENTRY32 {
    fn default() -> Self {

        unsafe {

            core::mem::zeroed()
        }
    }
}

#[derive(Clone, Copy)]
#[repr(C)]

pub struct PROCESSENTRY32W {
    pub dwSize: u32,
    pub cntUsage: u32,
    pub th32ProcessID: u32,
    pub th32DefaultHeapID: usize,
    pub th32ModuleID: u32,
    pub cntThreads: u32,
    pub th32ParentProcessID: u32,
    pub pcPriClassBase: i32,
    pub dwFlags: u32,
    pub szExeFile: [u16; 260],
}

impl Default for PROCESSENTRY32W {
    #[inline(always)]

    fn default() -> Self {

        unsafe {

            core::mem::zeroed()
        }
    }
}

trait ToString {
    fn to_string(&self) -> String;
}

impl ToString for [u8] {
    #[inline(always)]

    fn to_string(&self) -> String {

        let mut temp_vec = Vec::<u8>::new();

        for c in self {

            if c.to_owned() == 0 {

                break;
            }

            temp_vec.push(*c);
        }

        String::from_utf8_lossy(&temp_vec).to_string()
    }
}

impl ToString for [u16] {
    #[inline(always)]

    fn to_string(&self) -> String {

        let mut temp_vec = Vec::<u16>::new();

        for c in self {

            if c.to_owned() == 0 {

                break;
            }

            temp_vec.push(*c);
        }

        String::from_utf16_lossy(&temp_vec).to_string()
    }
}

#[inline(always)]

pub unsafe fn get_process_id_32(process_name: &str) -> Option<u32> {

    let handle = CreateToolhelp32Snapshot(0x2, 0);

    {

        let mut process_entry = PROCESSENTRY32::default();

        process_entry.dwSize = core::mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(handle, &mut process_entry as *mut PROCESSENTRY32) == 0 {

            CloseHandle(handle);

            return None;
        }

        while 0 != Process32Next(handle, &mut process_entry as *mut PROCESSENTRY32) {

            if process_name == process_entry.szExeFile.to_string() {

                CloseHandle(handle);

                return Some(process_entry.th32ProcessID);
            }
        }

        CloseHandle(handle);

        None
    }
}

#[inline(always)]

pub unsafe fn get_process_id_64(process_name: &str) -> Option<u32> {

    let handle = CreateToolhelp32Snapshot(0x2, 0);

    {

        let mut process_entry = PROCESSENTRY32W::default();

        process_entry.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(handle, &mut process_entry as *mut PROCESSENTRY32W) == 0 {

            CloseHandle(handle);

            return None;
        }

        while 0 != Process32NextW(handle, &mut process_entry as *mut PROCESSENTRY32W) {

            if process_name == process_entry.szExeFile.to_string() {

                CloseHandle(handle);

                return Some(process_entry.th32ProcessID);
            }
        }

        CloseHandle(handle);

        None
    }
}

#[inline(always)]

pub unsafe fn get_process_handle(process_id: u32) -> isize {

    OpenProcess(2097151, 0, process_id)
}

#[inline(always)]

pub unsafe fn get_modules_32(snapshot_handle: isize) -> Option<Vec<MODULEENTRY32>> {

    let mut modules: Vec<MODULEENTRY32> = Vec::new();

    let mut module_entry: MODULEENTRY32 = MODULEENTRY32::default();

    module_entry.dwSize = core::mem::size_of::<MODULEENTRY32>() as u32;

    if Module32First(snapshot_handle, &mut module_entry as *mut MODULEENTRY32) != 0 {

        modules.push(module_entry.clone());
    }

    while let true = Module32Next(snapshot_handle, &mut module_entry as *mut MODULEENTRY32) != 0 {

        modules.push(module_entry);
    }

    if modules.len() == 0 {

        return None;
    }

    Some(modules)
}

#[inline(always)]

pub unsafe fn get_modules_64(snapshot_handle: isize) -> Option<Vec<MODULEENTRY32W>> {

    let mut modules: Vec<MODULEENTRY32W> = Vec::new();

    let mut module_entry: MODULEENTRY32W = MODULEENTRY32W::default();

    module_entry.dwSize = core::mem::size_of::<MODULEENTRY32W>() as u32;

    if Module32FirstW(snapshot_handle, &mut module_entry as *mut MODULEENTRY32W) != 0 {

        modules.push(module_entry.clone());
    }

    while let true = Module32NextW(snapshot_handle, &mut module_entry as *mut MODULEENTRY32W) != 0 {

        modules.push(module_entry);
    }

    if modules.len() == 0 {

        return None;
    }

    Some(modules)
}

#[inline(always)]

pub unsafe fn get_module_info_32(process_id: u32, module_name: &str) -> Option<MODULEENTRY32> {

    let snapshot_handle = CreateToolhelp32Snapshot(0x8, process_id);

    match get_modules_32(snapshot_handle) {
        Some(data) => {

            for ref module_entry in data {

                if module_name == module_entry.szModule.to_string() {

                    CloseHandle(snapshot_handle);

                    return Some(*module_entry);
                }
            }

            CloseHandle(snapshot_handle);

            None
        }
        None => {

            CloseHandle(snapshot_handle);

            None
        }
    }
}

#[inline(always)]

pub unsafe fn get_module_info_64(process_id: u32, module_name: &str) -> Option<MODULEENTRY32W> {

    let snapshot_handle = CreateToolhelp32Snapshot(8 | 16, process_id);

    match get_modules_64(snapshot_handle) {
        Some(data) => {

            for ref module_entry in data {

                if module_name == module_entry.szModule.to_string() {

                    CloseHandle(snapshot_handle);

                    return Some(*module_entry);
                }
            }

            CloseHandle(snapshot_handle);

            None
        }
        None => {

            CloseHandle(snapshot_handle);

            None
        }
    }
}

#[inline(always)]

pub unsafe fn memory_read(process_handle: isize, address: isize, size: usize) -> Option<Vec<u8>> {

    if VirtualQueryEx(
        process_handle,
        address as *const core::ffi::c_void,
        &mut MEMORY_BASIC_INFORMATION::default() as *mut MEMORY_BASIC_INFORMATION,
        core::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
    ) == 0
    {

        return None;
    }

    let mut old_protect = 0u32;

    let mut new_protect = 4u32;

    if VirtualProtectEx(
        process_handle,
        address as *mut core::ffi::c_void,
        core::mem::size_of::<*mut core::ffi::c_void>(),
        new_protect,
        &mut old_protect as *mut u32,
    ) == 0
    {

        return None;
    }

    let mut data: Vec<u8> = Vec::new();

    data.resize(size, 0u8);

    if ReadProcessMemory(
        process_handle,
        address as *const core::ffi::c_void,
        data.as_mut_ptr() as *mut core::ffi::c_void,
        size,
        core::ptr::null_mut(),
    ) == 0
    {

        return None;
    }

    if VirtualProtectEx(
        process_handle,
        address as *mut core::ffi::c_void,
        core::mem::size_of::<*mut core::ffi::c_void>(),
        old_protect,
        &mut new_protect as *mut u32,
    ) == 0
    {

        return None;
    }

    Some(data)
}

#[inline(always)]

pub unsafe fn memory_write(process_handle: isize, address: isize, data: &mut Vec<u8>) -> bool {

    WriteProcessMemory(
        process_handle,
        address as *mut core::ffi::c_void,
        data.as_ptr() as *const core::ffi::c_void,
        data.len(),
        core::ptr::null_mut(),
    ) != 0
}

#[inline(always)]

pub fn pattern_find(pattern: &str, data: &[u8]) -> Option<usize> {

    let pattern_bytes: Vec<Option<u8>> = pattern
        .split_whitespace()
        .map(|hex| {
            if hex == "**" || hex == "??" {

                None
            } else {

                Some(u8::from_str_radix(hex, 16).unwrap())
            }
        })
        .collect();

    let mut i = 0;

    let pattern_bytes_len = pattern_bytes.len();

    while i < data.len() {

        if data[i..].len() >= pattern_bytes_len {

            let mut match_found = true;

            for j in 0..pattern_bytes_len {

                if pattern_bytes[j] != None && Some(data[i + j]) != pattern_bytes[j] {

                    match_found = false;

                    break;
                }
            }

            if match_found {

                return Some(i);
            }
        }

        i += 1;
    }

    None
}

#[inline(always)]

pub fn pattern_scan(pattern: &str, data: &[u8]) -> Option<Vec<usize>> {

    let mut offsets: Vec<usize> = Vec::new();

    let pattern_bytes: Vec<Option<u8>> = pattern
        .split_whitespace()
        .map(|hex| {
            if hex == "**" || hex == "??" {

                None
            } else {

                Some(u8::from_str_radix(hex, 16).unwrap())
            }
        })
        .collect();

    let mut i = 0;

    let pattern_bytes_len = pattern_bytes.len();

    while i < data.len() {

        if data[i..].len() >= pattern_bytes_len {

            let mut match_found = true;

            for j in 0..pattern_bytes_len {

                if pattern_bytes[j] != None && Some(data[i + j]) != pattern_bytes[j] {

                    match_found = false;

                    break;
                }
            }

            if match_found {

                offsets.push(i);
            }
        }

        i += 1;
    }

    if offsets.len() == 0 {

        None
    } else {

        Some(offsets)
    }
}
