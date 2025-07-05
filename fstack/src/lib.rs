#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!("bindings.rs");

use std::cell::RefCell;
use std::ffi::CString;
use std::os::raw::{c_char, c_uint, c_void};

unsafe impl Send for epoll_event {}

unsafe impl Sync for epoll_event {}

#[link(name = "hook")]          // 链到 libdemo.so
unsafe extern "C" {
    // 与 C 侧类型保持一致
    unsafe static mut isInit: std::os::raw::c_int;
}

// type FstackCallback<'a> = Box<dyn FnMut(*mut c_void) -> i32 + Send + 'a>;
//
// struct Args<'a> {
//     pub callback: FstackCallback<'a>,
//     pub arg: *mut c_void,
// }

// extern "C" fn run_adapter(arg: *mut c_void) -> std::os::raw::c_int {
//     let args = unsafe {
//         &mut *(arg as *mut Args)
//     };
//     (args.callback)(args.arg);
//     0
// }

pub fn run(callback: unsafe extern "C" fn(arg: *mut c_void) -> i32, arg: *mut c_void)
// where
//     F: FnMut(*mut c_void) -> i32 + 'a + Send,
{
    // let arg = std::ptr::addr_of_mut!(arg) as *mut c_void;
    // let mut arg = Args {
    //     callback: Box::new(callback),
    //     arg,
    // };
    unsafe {
        ff_run(Some(callback), arg);
    }
}

pub fn fstack_init(argc: usize, argv: Vec<String>) -> i32 {
    let strings: Vec<CString> = argv
        .iter()
        .map(|arg| CString::new(arg.as_str()).unwrap())
        .collect();

    let mut ptrs: Vec<*mut c_char> = strings
        .iter()
        .map(|c_str| c_str.as_ptr() as *mut c_char)
        .collect();
    ptrs.push(std::ptr::null_mut());

    let mut ret = 0;
    unsafe { ret = ff_init(argc as i32, ptrs.as_ptr()); }

    unsafe {
        println!("ff_init finished");
        isInit = 1;
    }

    return ret;
}

pub fn fstack_stop_run() {
    unsafe { ff_stop_run() }
}
