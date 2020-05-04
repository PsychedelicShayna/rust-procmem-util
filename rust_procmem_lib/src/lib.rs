extern crate winapi;

pub mod pmem {
    use winapi::um::tlhelp32::*;
    use winapi::um::handleapi::*;
    use winapi::um::winuser::*;
    use winapi::shared::windef::*;
    use winapi::um::processthreadsapi::*;
    use winapi::um::memoryapi::*;
    use winapi::ctypes::*;
    use winapi::um::winnt::*;

    pub type memaddr = usize;

    pub unsafe fn cstr_length(cstr:*const i8) -> usize {
        let mut index:isize = 0;
        
        loop {
            let character = *cstr.offset(index);
            if character == 0x00 {
                return index as usize;
            } else {
                index += 1;
            }
        }
    }

    pub unsafe fn cstr_to_str(cstr:*const i8) -> &'static str {
        let length:usize = cstr_length(cstr);
        let unsigned_cstr:*const u8 = std::mem::transmute_copy::<*const i8, *const u8>(&cstr);
        let cstr_slice:&[u8] = std::slice::from_raw_parts(unsigned_cstr, length);
        return std::str::from_utf8_unchecked(cstr_slice);
    }

    pub unsafe fn str_to_cstr(primitive_string:&str, length:usize, cstr_buffer:&mut Vec<i8>) -> *const i8 {
        *cstr_buffer = vec![0; length+1];
        cstr_buffer[length] = 0x00;
        std::ptr::copy(primitive_string.as_ptr() as *const i8, cstr_buffer.as_mut_ptr(), length);
        return cstr_buffer.as_ptr();
    }

    pub unsafe fn window_handle_from_title(window_title:&str) -> Result<*mut HWND__, &str> {
        let mut title_cstring_buffer:Vec<i8> = Vec::new();
        let title_cstring:*const i8 = str_to_cstr(window_title, window_title.len(), &mut title_cstring_buffer);
        let window_handle:*mut HWND__ = FindWindowA(std::ptr::null(), title_cstring as *const i8); 

        return 
            if IsWindow(window_handle) == 1 { Ok(window_handle) } 
            else { Err("Could not create a valid handle.") }
    }

    pub unsafe fn pid_from_image(image:&str) -> Result<u16, &str> {
        let snapshot:*mut c_void = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if snapshot != INVALID_HANDLE_VALUE {
            let mut process_entry = std::mem::uninitialized::<PROCESSENTRY32>();
            process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

            if Process32First(snapshot, &mut process_entry) != 0 {
                loop {
                    let i8_strbuf:*mut i8 = &mut(process_entry.szExeFile[0]);
                    let u8_strbuf:*mut u8 = std::mem::transmute_copy::<*mut i8, *mut u8>(&i8_strbuf);
                    let slice = std::slice::from_raw_parts(u8_strbuf, cstr_length(i8_strbuf));
                    
                    let slice_as_str = std::str::from_utf8_unchecked(slice);
                    
                    if slice_as_str == image {
                        CloseHandle(snapshot);
                        return Ok(process_entry.th32ProcessID as u16);
                    }

                    if Process32Next(snapshot, &mut process_entry) == 0 {
                        break;
                    }
                }

                CloseHandle(snapshot);
            }
        }

        return Err("Could not retrieve the process ID of the process with the supplied image.");
    }

    pub unsafe fn pid_from_window_handle(window_handle:*mut HWND__) -> Result<u16, &'static str> {
        let mut process_id:u32 = 0;         
        
        if IsWindow(window_handle) == 1 {
            GetWindowThreadProcessId(window_handle, &mut process_id as *mut u32);
            return Ok(process_id as u16);
        } else {
            return Err("The handle was not a valid window handle.");
        }
    }

    pub unsafe fn proc_handle_from_pid(process_id:u16) -> Result<winapi::um::winnt::HANDLE, &'static str> {
        let process_handle:winapi::um::winnt::HANDLE = OpenProcess(PROCESS_ALL_ACCESS, 0, process_id as u32);

        return
            if process_handle != INVALID_HANDLE_VALUE { Ok(process_handle) }
            else { Err("The created handle had an invalid value.") }
    }

    pub unsafe fn modaddress_from_modname(process_id:u16, module_name:&str) -> Result<memaddr, &'static str> {
        let snapshot:*mut c_void = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id as u32);

        if snapshot != INVALID_HANDLE_VALUE {
            let mut module_entry = std::mem::uninitialized::<MODULEENTRY32>();
            module_entry.dwSize = std::mem::size_of::<MODULEENTRY32>() as u32;

            if Module32First(snapshot, &mut module_entry) != 0 {
                loop {
                    let current_module_name:&str = cstr_to_str(&module_entry.szModule[0]);
                    
                    if module_name == current_module_name {
                        let module_address:memaddr = module_entry.modBaseAddr as memaddr;
                        CloseHandle(snapshot);
                        return Ok(module_address);
                    }

                    if Module32Next(snapshot, &mut module_entry) == 0 {
                        break;
                    }
                }
            }

        }

        return Err("Could not find the address of the given module.");
    }

    pub unsafe fn resolve_ptr_offsets(static_addr:memaddr, static_offset:memaddr, ptr_offsets:Vec<memaddr>, proc_handle:*mut c_void) -> memaddr {
        let mut dynamic_address:memaddr = 0;
        let trailing_offset = &ptr_offsets.last().unwrap();
        
        ReadProcessMemory(
            proc_handle, 
            (static_addr + static_offset) as *mut c_void,
            std::mem::transmute_copy::<*mut memaddr, *mut c_void>(&(&mut dynamic_address as *mut memaddr)),
            std::mem::size_of::<memaddr>(), 
            std::ptr::null_mut()
        );

        for offset in 0..ptr_offsets.len()-1 {
            let offset:memaddr = ptr_offsets[offset];

            ReadProcessMemory(
                proc_handle,
                (dynamic_address + offset) as *mut c_void,
                std::mem::transmute_copy::<*mut memaddr, *mut c_void>(&(&mut dynamic_address as *mut memaddr)),
                std::mem::size_of::<memaddr>(),
                std::ptr::null_mut()
            );
        }

        if dynamic_address != 0 {
            dynamic_address += *trailing_offset;
        }

        return dynamic_address;
    }

    pub unsafe fn read_primitive<T>(proc_handle:*mut c_void, memory_address:memaddr) -> T {
        let mut value:T = std::mem::uninitialized::<T>();

        ReadProcessMemory(
            proc_handle, 
            memory_address as *mut c_void, 
            std::mem::transmute_copy::<*mut T, *mut c_void>(&(&mut value as *mut T)), 
            std::mem::size_of::<T>(), 
            std::ptr::null_mut()
        );

        return value;
    }

    pub unsafe fn write_primitive<T>(proc_handle:*mut c_void, memory_address:memaddr, value:T) {
        let mut mutable_value:T = value;

        WriteProcessMemory(
            proc_handle, 
            memory_address as *mut c_void, 
            std::mem::transmute_copy::<*mut T, *mut c_void>(&(&mut  mutable_value as *mut T)), 
            std::mem::size_of::<T>(), 
            std::ptr::null_mut()
        );
    }

    pub unsafe fn read_primitive_array<T>(proc_handle:*mut c_void, memory_address:memaddr, amount:usize) -> Vec<T> {
        let mut buffer:Vec<T> = Vec::new();

        for offset in 0..amount {
            let primitive:T = read_primitive::<T>(proc_handle, memory_address + (std::mem::size_of::<T>() * offset) as memaddr);
            buffer.push(primitive);
        }

        return buffer;
    }

    pub unsafe fn write_primitive_array<T>(proc_handle:*mut c_void, memory_address:memaddr, values:Vec<T>) {
        let buffer_size:usize = std::mem::size_of::<T>() * values.len();
        let mut values_buffer:Vec<u8> = vec![0; buffer_size];
        let buffer_ptr:*mut u8 = values_buffer.as_mut_ptr();

        std::ptr::copy(values.as_ptr() as *const u8, values_buffer.as_mut_ptr(), buffer_size);

        WriteProcessMemory(
            proc_handle, 
            memory_address as *mut c_void, 
            buffer_ptr as *mut c_void,
            buffer_size, 
            std::ptr::null_mut()
        );
    }

    pub unsafe fn read_strlen(proc_handle:*mut c_void, memory_address:memaddr) -> usize {
        let mut length:usize = 0;

        loop {
            let byte:u8 = read_primitive::<u8>(proc_handle, memory_address + length as memaddr);

            if byte == 0x00 {
                return length;
            } else {
                length += 1;
            }
        }
    }

    pub unsafe fn read_cstring(proc_handle:*mut c_void, memory_address:memaddr, buffer:&mut Vec<i8>) -> *const i8 {
        let string_length:usize = read_strlen(proc_handle, memory_address);
        *buffer = vec![0; string_length];

        ReadProcessMemory(
            proc_handle, 
            memory_address as *mut c_void, 
            buffer.as_mut_ptr() as *mut c_void,
            string_length, 
            std::ptr::null_mut()
        );

        return buffer.as_ptr();
    }
}