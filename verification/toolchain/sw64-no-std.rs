#![no_std]

#[no_mangle]
pub extern "C" fn jasper_sw64_add(a: u64, b: u64) -> u64 {
    a.wrapping_add(b)
}
