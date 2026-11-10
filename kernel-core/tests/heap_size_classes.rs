use std::alloc::{alloc, dealloc, Layout};
use std::time::Instant;

use kernel_core::bench;
use kernel_core::heap::LinkedListHeap;

const ARENA_BYTES: usize = 16 * 1024 * 1024;
const STEP_BYTES: usize = 64 * 1024;
const SIZES: [usize; 15] = [
    16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 1024, 2048, 4096, 8192,
];

struct Arena {
    ptr: *mut u8,
    layout: Layout,
}

impl Arena {
    fn new() -> Self {
        let layout = Layout::from_size_align(ARENA_BYTES, 4096).unwrap();
        let ptr = unsafe { alloc(layout) };
        assert!(!ptr.is_null());
        Self { ptr, layout }
    }

    fn heap(&self) -> LinkedListHeap {
        let mut heap = LinkedListHeap::empty();
        unsafe { heap.extend(self.ptr as usize, ARENA_BYTES) };
        heap
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        unsafe { dealloc(self.ptr, self.layout) };
    }
}

fn percentile(values: &[u64]) -> bench::Summary {
    let mut copy = values.to_vec();
    bench::summarize(&mut copy).unwrap()
}

#[test]
fn heap_size_class_growth_and_fragmentation_baseline() {
    let arena = Arena::new();
    for size in SIZES {
        let count = if size <= 256 {
            2048
        } else if size <= 4096 {
            512
        } else {
            128
        };
        let mut heap = arena.heap();
        let total = heap.total_bytes();
        let mut ptrs = Vec::with_capacity(count);
        let mut alloc_ns = Vec::with_capacity(count);
        let mut free_ns = Vec::with_capacity(count);
        for _ in 0..count {
            let started = Instant::now();
            let ptr = unsafe { heap.allocate(size, 16) };
            alloc_ns.push(started.elapsed().as_nanos().min(u64::MAX as u128) as u64);
            assert!(!ptr.is_null());
            ptrs.push(ptr);
        }
        for index in (0..ptrs.len()).step_by(2) {
            let started = Instant::now();
            unsafe { heap.deallocate(ptrs[index], size) };
            free_ns.push(started.elapsed().as_nanos().min(u64::MAX as u128) as u64);
        }
        let peak_blocks = heap.free_blocks();
        for index in (1..ptrs.len()).step_by(2) {
            let started = Instant::now();
            unsafe { heap.deallocate(ptrs[index], size) };
            free_ns.push(started.elapsed().as_nanos().min(u64::MAX as u128) as u64);
        }
        let final_blocks = heap.free_blocks();
        let alloc = percentile(&alloc_ns);
        let free = percentile(&free_ns);
        println!(
            "{{\"case\":\"size-class\",\"bytes\":{size},\"count\":{count},\"alloc_p50_ns\":{},\"alloc_p99_ns\":{},\"alloc_p999_ns\":{},\"alloc_max_ns\":{},\"free_p50_ns\":{},\"free_p99_ns\":{},\"free_p999_ns\":{},\"free_max_ns\":{},\"peak_free_blocks\":{peak_blocks},\"final_free_blocks\":{final_blocks},\"free_bytes\":{},\"total_bytes\":{total}}}",
            alloc.p50,
            alloc.p99,
            alloc.p999,
            alloc.max,
            free.p50,
            free.p99,
            free.p999,
            free.max,
            heap.free_bytes(),
        );
        assert_eq!(heap.free_bytes(), total);
        assert_eq!(final_blocks, 1);
    }

    for request in [64 * 1024, 128 * 1024, 256 * 1024, 512 * 1024, 1024 * 1024] {
        let mut heap = LinkedListHeap::empty();
        let base = arena.ptr as usize;
        let mut extends = 0usize;
        let mut ptr;
        loop {
            ptr = unsafe { heap.allocate(request, 16) };
            if !ptr.is_null() {
                break;
            }
            extends += 1;
            let offset = (extends - 1) * STEP_BYTES;
            assert!(offset + STEP_BYTES <= ARENA_BYTES);
            unsafe { heap.extend(base + offset, STEP_BYTES) };
            assert!(extends < ARENA_BYTES / STEP_BYTES);
        }
        println!(
            "{{\"case\":\"growth-tail\",\"request_bytes\":{request},\"step_bytes\":{STEP_BYTES},\"extends\":{extends},\"mapped_bytes\":{},\"tail_free_blocks\":{},\"allocated\":true}}",
            heap.total_bytes(),
            heap.free_blocks(),
        );
        unsafe { heap.deallocate(ptr, request) };
        assert_eq!(heap.free_bytes(), heap.total_bytes());
        assert_eq!(heap.free_blocks(), 1);
    }
}
