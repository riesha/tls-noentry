#![feature(core_intrinsics)]
#![feature(pointer_byte_offsets)]
use ntapi::{
    ntldr::LDR_DATA_TABLE_ENTRY,
    ntpebteb::{PPEB, PTEB},
    ntpsapi::NtCreateThread,
};
use std::{
    arch::asm,
    mem::{self, size_of},
    ptr::{self, addr_of_mut},
    thread,
};
use widestring::U16String;
use winapi::{
    shared::minwindef::{DWORD, LPVOID},
    um::{
        errhandlingapi::GetLastError,
        memoryapi::VirtualProtect,
        processthreadsapi::{CreateThread, ExitProcess},
        winnt::{
            IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
            PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE, PIMAGE_DOS_HEADER,
            PIMAGE_NT_HEADERS64,
        },
    },
};
#[link_section = ".CRT$XLB"]
#[allow(dead_code, unused_variables)]
#[used]
pub static p_thread_callback: unsafe extern "system" fn(LPVOID, DWORD, LPVOID) = on_tls_callback;
pub static mut TLS_FLAG: bool = false;
#[allow(dead_code, unused_variables)]
unsafe extern "system" fn on_tls_callback(h: LPVOID, dwReason: DWORD, pv: LPVOID)
{
    if TLS_FLAG == true
    {
        return;
    }
    let base = base();

    let dos_header = base as PIMAGE_DOS_HEADER;
    if unsafe { (*dos_header).e_magic != IMAGE_DOS_SIGNATURE }
    {
        return;
    }

    let mut nt_headers =
        base.byte_add(unsafe { (*dos_header).e_lfanew as _ }) as PIMAGE_NT_HEADERS64;
    if unsafe { (*nt_headers).Signature != IMAGE_NT_SIGNATURE }
    {
        return;
    }
    let mut entry_point = unsafe { (*nt_headers).OptionalHeader.AddressOfEntryPoint } as *mut u32;
    let mut import_table = unsafe {
        (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize]
            .VirtualAddress as *mut u32
    };
    let entry_ptr = addr_of_mut!((*nt_headers).OptionalHeader.AddressOfEntryPoint);
    let import_ptr = addr_of_mut!(
        (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize]
            .VirtualAddress
    );
    let mut old_protect = 0;
    VirtualProtect(
        base as _,
        (*nt_headers).OptionalHeader.SizeOfHeaders as _,
        PAGE_READWRITE,
        addr_of_mut!(old_protect),
    );
    dbg!(old_protect);

    dbg!(entry_point, import_table);
    TLS_FLAG = true;

    reference_tls_used();

    unsafe fn reference_tls_used()
    {
        extern "C" {
            static _tls_used: u8;
        }
        core::intrinsics::volatile_load(&_tls_used);
    }
    main()
}

fn main()
{
    println!("Hello, world!");
    unsafe { ExitProcess(0) };
}

pub fn teb() -> PTEB
{
    let teb: PTEB;
    unsafe { asm!("mov {teb}, gs:[0x30]", teb = out(reg) teb) };
    teb
}
pub fn peb() -> PPEB
{
    let teb = teb();
    unsafe { (*teb).ProcessEnvironmentBlock }
}
pub fn base() -> *mut u8
{
    let peb = peb();
    unsafe { (*peb).ImageBaseAddress as _ }
}
pub fn module_entry() -> *mut LDR_DATA_TABLE_ENTRY
{
    let peb = peb();
    unsafe { (*(*peb).Ldr).InLoadOrderModuleList.Flink as _ }
}
