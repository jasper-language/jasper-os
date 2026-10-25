#![no_main]
use kernel_core::memory_abi::{MapArgs,MAP_ARGS_BYTES};
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(bytes) = <&[u8;MAP_ARGS_BYTES]>::try_from(data) {
        if let Some(decoded) = MapArgs::decode(bytes) {
            assert_eq!(&decoded.encode(), bytes);
            assert_eq!(decoded.version,1); assert_eq!(decoded.bytes,40);
            assert_eq!(decoded.reserved,0); assert_eq!(decoded.flags & !1,0);
        }
    }
});
