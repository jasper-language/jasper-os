use std::time::Instant;

use kernel_core::bench;
use kernel_core::frame::{
    BitmapFrameAllocator, FrameAllocator, PhysFrame, PhysRegion, RegionKind, FRAME_SIZE,
};

const WORDS: usize = 4096;
const CAPACITY: usize = 64;
const BATCH: usize = 16;
const OPS: usize = 4096;
const REGIONS: [PhysRegion; 1] = [PhysRegion {
    start: FRAME_SIZE,
    end: (WORDS as u64) * 64 * FRAME_SIZE,
    kind: RegionKind::Usable,
}];

fn allocator(bits: &mut [u64]) -> BitmapFrameAllocator<'_> {
    BitmapFrameAllocator::new(bits, &REGIONS)
}

fn percentile(values: &[u64]) -> bench::Summary {
    let mut copy = values.to_vec();
    bench::summarize(&mut copy).unwrap()
}

#[test]
fn frame_cache_alloc_free_migration_and_reclaim_baseline() {
    let mut bits = vec![0u64; WORDS];
    let mut frames = allocator(&mut bits);
    let baseline_free = frames.free_frames();
    let mut held = Vec::with_capacity(OPS);
    let mut alloc_ns = Vec::with_capacity(OPS);
    let mut free_ns = Vec::with_capacity(OPS);
    for _ in 0..OPS {
        let started = Instant::now();
        let frame = frames.allocate().unwrap();
        alloc_ns.push(started.elapsed().as_nanos().min(u64::MAX as u128) as u64);
        held.push(frame);
    }
    for frame in held.drain(..) {
        let started = Instant::now();
        frames.deallocate(frame).unwrap();
        free_ns.push(started.elapsed().as_nanos().min(u64::MAX as u128) as u64);
    }
    let alloc = percentile(&alloc_ns);
    let free = percentile(&free_ns);
    assert_eq!(frames.free_frames(), baseline_free);
    println!(
        "{{\"case\":\"baseline\",\"frames\":{OPS},\"alloc_p50_ns\":{},\"alloc_p99_ns\":{},\"alloc_p999_ns\":{},\"alloc_max_ns\":{},\"free_p50_ns\":{},\"free_p99_ns\":{},\"free_p999_ns\":{},\"free_max_ns\":{},\"metadata_bits_per_frame\":1,\"reclaimed\":true}}",
        alloc.p50,
        alloc.p99,
        alloc.p999,
        alloc.max,
        free.p50,
        free.p99,
        free.p999,
        free.max,
    );

    for cpus in [1usize, 2, 4, 8] {
        let mut bits = vec![0u64; WORDS];
        let mut frames = allocator(&mut bits);
        let baseline_free = frames.free_frames();
        let mut caches: Vec<Vec<PhysFrame>> =
            (0..cpus).map(|_| Vec::with_capacity(CAPACITY)).collect();
        let mut owners = Vec::with_capacity(OPS);
        let mut model_held = Vec::with_capacity(OPS);
        let mut model_alloc_ns = Vec::with_capacity(OPS);
        let mut model_free_ns = Vec::with_capacity(OPS);
        let mut refills = 0usize;
        let mut drains = 0usize;
        let mut remote_frees = 0usize;

        for index in 0..OPS {
            let owner = index % cpus;
            owners.push(owner);
            let started = Instant::now();
            if caches[owner].is_empty() {
                for _ in 0..BATCH {
                    caches[owner].push(frames.allocate().unwrap());
                }
                refills += 1;
            }
            let frame = caches[owner].pop().unwrap();
            model_alloc_ns.push(started.elapsed().as_nanos().min(u64::MAX as u128) as u64);
            model_held.push((frame, index));
        }

        for (frame, index) in model_held.drain(..) {
            let destination = (index * 7 + 3) % cpus;
            if destination != owners[index] {
                remote_frees += 1;
            }
            let started = Instant::now();
            if caches[destination].len() == CAPACITY {
                for _ in 0..CAPACITY / 2 {
                    frames
                        .deallocate(caches[destination].pop().unwrap())
                        .unwrap();
                }
                drains += 1;
            }
            caches[destination].push(frame);
            model_free_ns.push(started.elapsed().as_nanos().min(u64::MAX as u128) as u64);
        }
        for cache in &mut caches {
            while let Some(frame) = cache.pop() {
                frames.deallocate(frame).unwrap();
            }
        }
        let model_alloc = percentile(&model_alloc_ns);
        let model_free = percentile(&model_free_ns);
        let reclaimed = frames.free_frames() == baseline_free;
        assert!(reclaimed);
        println!(
            "{{\"case\":\"cache-model\",\"cpus\":{cpus},\"ops\":{OPS},\"capacity_per_cpu\":{CAPACITY},\"batch\":{BATCH},\"refills\":{refills},\"drains\":{drains},\"remote_frees\":{remote_frees},\"alloc_p50_ns\":{},\"alloc_p99_ns\":{},\"alloc_p999_ns\":{},\"alloc_max_ns\":{},\"free_p50_ns\":{},\"free_p99_ns\":{},\"free_p999_ns\":{},\"free_max_ns\":{},\"metadata_bytes\":{},\"reclaimed\":{reclaimed}}}",
            model_alloc.p50,
            model_alloc.p99,
            model_alloc.p999,
            model_alloc.max,
            model_free.p50,
            model_free.p99,
            model_free.p999,
            model_free.max,
            cpus * CAPACITY * std::mem::size_of::<PhysFrame>(),
        );
    }
}
