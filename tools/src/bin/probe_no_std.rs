//! The size probe, half two: the same work as `probe_std.rs`, with no `std`.
//!
//! `#![no_std]` plus `alloc` is the shape a device-side Rust module has to take
//! if it is to fit a size budget that `std` alone blows through. What is left
//! to prove is that the shape is workable: allocation is reachable through
//! bionic's `malloc`, and the formatting machinery still works.
//!
//! The `GlobalAlloc` below is the whole of the bridge. bionic already has an
//! allocator, and the injected and daemon-side processes are ordinary Android
//! processes, so there is no reason to carry a second one.
//!
//! `main` returns the length of what it built instead of printing it: std's
//! `io` is not here, and a value crossing back into C is something the
//! optimizer cannot elide.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use core::alloc::{GlobalAlloc, Layout};
use core::fmt::Write;
use core::panic::PanicInfo;

// `link(name = "c")` is not decoration, and it is the one thing about this
// shape that a first attempt gets wrong: nothing in a `no_std` graph declares a
// dependency on the C library, so rustc passes no `-lc` and the link ends on
// `undefined symbol: memcpy` with `__libc_init` right behind it. `std` used to
// supply that directive; without `std` the block has to say it itself.
#[link(name = "c")]
extern "C" {
    fn malloc(size: usize) -> *mut u8;
    fn free(pointer: *mut u8);
}

struct BionicAllocator;

// SAFETY: `malloc` and `free` are the platform's own allocator and are what
// every other process on the device uses; the returned pointer is aligned for
// any type, as `GlobalAlloc` requires of `alloc`.
unsafe impl GlobalAlloc for BionicAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        malloc(layout.size())
    }

    unsafe fn dealloc(&self, pointer: *mut u8, _layout: Layout) {
        free(pointer)
    }
}

#[global_allocator]
static ALLOCATOR: BionicAllocator = BionicAllocator;

#[panic_handler]
fn on_panic(_info: &PanicInfo) -> ! {
    // The release profile is `panic = "abort"`, so this is the whole unwind
    // story: a panic in a device-side process must not walk a stack that
    // belongs to something else.
    loop {}
}

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8) -> i32 {
    let mut text = String::new();

    for index in 0..8 {
        if index != 0 {
            text.push('-');
        }

        let _ = write!(text, "part-{index}");
    }

    text.len() as i32
}
