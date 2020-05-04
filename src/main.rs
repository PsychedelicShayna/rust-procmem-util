extern crate rust_procmem_lib;
extern crate winapi;

use rust_procmem_lib::pmem;

use winapi::shared::windef::*;
use winapi::ctypes::*;

fn main() { unsafe {
    let window_handle:*mut HWND__ = pmem::window_handle_from_title(&mut "AdCap!").unwrap();
    println!("Window handle created: {:?}", window_handle);

    let process_id:u16 = pmem::pid_from_window_handle(window_handle).unwrap();
    println!("Process ID retrieved: {:?}", process_id);

    let proc_handle:*mut c_void = pmem::proc_handle_from_pid(process_id).unwrap();
    println!("Process handle created: {:?}", proc_handle);

    let mod_addr:pmem::memaddr = pmem::modaddress_from_modname(process_id, "mono-2.0-bdwgc.dll").unwrap();
    println!("Retrieved module address: {:0x}", mod_addr);

    let resolved_addr:pmem::memaddr = pmem::resolve_ptr_offsets(mod_addr, 0x0039B56C, vec![0x6DC, 0x110, 0x64, 0x28, 0x1C], proc_handle);
    println!("Resolved address: {:0x}", resolved_addr);

    let value_u32:u32 = pmem::read_primitive::<u32>(proc_handle, resolved_addr);
    println!("Read value: {}", value_u32);
}}