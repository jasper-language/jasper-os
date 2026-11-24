//! Read-only hardware facts for boot diagnostics and performance reports.

use alloc::string::String;

use crate::{early, kmain, mm, profile, smp};

pub struct CpuTopology {
    pub logical_per_package: Option<u32>,
    pub cores_per_package: Option<u32>,
    pub threads_per_core: Option<u32>,
}

pub fn cpu_vendor() -> String {
    let leaf = core::arch::x86_64::__cpuid(0);
    let mut bytes = [0u8; 12];
    bytes[0..4].copy_from_slice(&leaf.ebx.to_le_bytes());
    bytes[4..8].copy_from_slice(&leaf.edx.to_le_bytes());
    bytes[8..12].copy_from_slice(&leaf.ecx.to_le_bytes());
    String::from_utf8_lossy(&bytes).trim().into()
}

pub fn cpu_brand() -> String {
    let extended = core::arch::x86_64::__cpuid(0x8000_0000).eax;
    if extended < 0x8000_0004 {
        return String::from("unknown");
    }
    let mut bytes = [0u8; 48];
    for (index, leaf) in [0x8000_0002, 0x8000_0003, 0x8000_0004]
        .into_iter()
        .enumerate()
    {
        let value = core::arch::x86_64::__cpuid(leaf);
        let start = index * 16;
        bytes[start..start + 4].copy_from_slice(&value.eax.to_le_bytes());
        bytes[start + 4..start + 8].copy_from_slice(&value.ebx.to_le_bytes());
        bytes[start + 8..start + 12].copy_from_slice(&value.ecx.to_le_bytes());
        bytes[start + 12..start + 16].copy_from_slice(&value.edx.to_le_bytes());
    }
    String::from_utf8_lossy(&bytes).trim_matches(char::from(0)).trim().into()
}

pub fn cpu_identity() -> (u32, u32, u32) {
    let value = core::arch::x86_64::__cpuid(1);
    let base_family = (value.eax >> 8) & 0xf;
    let base_model = (value.eax >> 4) & 0xf;
    let stepping = value.eax & 0xf;
    let family = if base_family == 0xf {
        base_family + ((value.eax >> 20) & 0xff)
    } else {
        base_family
    };
    let model = if base_family == 0x6 || base_family == 0xf {
        base_model | (((value.eax >> 16) & 0xf) << 4)
    } else {
        base_model
    };
    (family, model, stepping)
}

pub fn invariant_tsc() -> bool {
    core::arch::x86_64::__cpuid(0x8000_0000).eax >= 0x8000_0007
        && core::arch::x86_64::__cpuid(0x8000_0007).edx & (1 << 8) != 0
}

pub fn nominal_frequency_hz() -> Option<u64> {
    (core::arch::x86_64::__cpuid(0).eax >= 0x16)
        .then(|| core::arch::x86_64::__cpuid(0x16).eax)
        .filter(|mhz| *mhz != 0)
        .map(|mhz| u64::from(mhz) * 1_000_000)
}

pub fn bus_frequency_hz() -> Option<u64> {
    (core::arch::x86_64::__cpuid(0).eax >= 0x16)
        .then(|| core::arch::x86_64::__cpuid(0x16).ecx)
        .filter(|mhz| *mhz != 0)
        .map(|mhz| u64::from(mhz) * 1_000_000)
}

pub fn rdtscp() -> bool {
    core::arch::x86_64::__cpuid(0x8000_0000).eax >= 0x8000_0001
        && core::arch::x86_64::__cpuid(0x8000_0001).edx & (1 << 27) != 0
}

fn hypervisor_vendor() -> String {
    let maximum = core::arch::x86_64::__cpuid(0).eax;
    let leaf = core::arch::x86_64::__cpuid(1);
    if maximum < 0x4000_0000 || leaf.ecx & (1 << 31) == 0 {
        return String::from("none");
    }
    let value = core::arch::x86_64::__cpuid(0x4000_0000);
    let mut bytes = [0u8; 12];
    bytes[..4].copy_from_slice(&value.ebx.to_le_bytes());
    bytes[4..8].copy_from_slice(&value.ecx.to_le_bytes());
    bytes[8..].copy_from_slice(&value.edx.to_le_bytes());
    String::from_utf8_lossy(&bytes).trim_matches(char::from(0)).into()
}

pub fn isa_extensions() -> String {
    let basic = core::arch::x86_64::__cpuid(1);
    let extended = if core::arch::x86_64::__cpuid(0x8000_0000).eax >= 0x8000_0001 {
        core::arch::x86_64::__cpuid(0x8000_0001)
    } else {
        core::arch::x86_64::__cpuid(0)
    };
    let maximum = core::arch::x86_64::__cpuid(0).eax;
    let seven = if maximum >= 7 {
        core::arch::x86_64::__cpuid_count(7, 0)
    } else {
        core::arch::x86_64::__cpuid(0)
    };
    let mut output = String::from("x86_64,sse2");
    let mut add = |present: bool, name: &str| {
        if present {
            output.push(',');
            output.push_str(name);
        }
    };
    add(basic.ecx & (1 << 9) != 0, "ssse3");
    add(basic.ecx & (1 << 19) != 0, "sse4_1");
    add(basic.ecx & (1 << 20) != 0, "sse4_2");
    add(basic.ecx & (1 << 25) != 0, "aes");
    add(basic.ecx & (1 << 26) != 0, "xsave");
    add(basic.ecx & (1 << 27) != 0, "osxsave");
    add(basic.ecx & (1 << 28) != 0, "avx");
    add(basic.ecx & (1 << 29) != 0, "f16c");
    add(basic.ecx & (1 << 30) != 0, "rdrand");
    add(basic.ecx & (1 << 31) != 0, "hypervisor");
    add(seven.ebx & (1 << 3) != 0, "bmi1");
    add(seven.ebx & (1 << 5) != 0, "avx2");
    add(seven.ebx & (1 << 8) != 0, "bmi2");
    add(seven.ebx & (1 << 16) != 0, "avx512f");
    add(seven.ebx & (1 << 18) != 0, "rdseed");
    add(seven.ebx & (1 << 20) != 0, "smap");
    add(seven.ebx & (1 << 23) != 0, "clflushopt");
    add(seven.ebx & (1 << 29) != 0, "sha");
    add(seven.ecx & (1 << 5) != 0, "waitpkg");
    add(extended.ecx & (1 << 2) != 0, "svm");
    add(extended.ecx & (1 << 5) != 0, "vmx");
    add(extended.edx & (1 << 20) != 0, "nx");
    add(extended.edx & (1 << 27) != 0, "rdtscp");
    add(invariant_tsc(), "invariant_tsc");
    output
}

pub fn topology() -> CpuTopology {
    let upper = core::arch::x86_64::__cpuid(0x8000_0000).eax;
    let leaf1 = core::arch::x86_64::__cpuid(1);
    let logical_per_package = Some((leaf1.ebx >> 16) & 0xff).filter(|count| *count != 0);
    if core::arch::x86_64::__cpuid(0).eax >= 0xb {
        let mut smt = None;
        let mut package = None;
        for subleaf in 0..8 {
            let value = core::arch::x86_64::__cpuid_count(0xb, subleaf);
            if value.ebx == 0 {
                break;
            }
            match value.ecx >> 8 {
                1 => smt = Some(value.ebx),
                2 => package = Some(value.ebx),
                _ => {}
            }
        }
        if let Some(cores) = package {
            return CpuTopology {
                logical_per_package,
                cores_per_package: Some(cores),
                threads_per_core: smt,
            };
        }
    }
    if upper >= 0x8000_0008 {
        let value = core::arch::x86_64::__cpuid(0x8000_0008);
        let cores = (value.ecx & 0xff) + 1;
        let threads = logical_per_package.and_then(|logical| {
            (logical != 0 && logical % cores == 0).then_some(logical / cores)
        });
        return CpuTopology {
            logical_per_package,
            cores_per_package: Some(cores),
            threads_per_core: threads,
        };
    }
    CpuTopology {
        logical_per_package,
        cores_per_package: None,
        threads_per_core: None,
    }
}

pub fn report() {
    let (family, model, stepping) = cpu_identity();
    let topology = topology();
    let tsc_hz = early::tsc_frequency_hz();
    let usable = mm::frame::usable_frames();
    let free = mm::frame::free_frames();
    let (heap_total, heap_free, _, heap_mapped) = mm::heap::stats();
    let discovered = smp::discovered_cpu_count();
    let admitted = smp::admitted_cpu_count();
    let online = smp::online_set().len();
    let disabled = smp::disabled_cpu_count();
    let participating = online;
    let packages = topology.logical_per_package.and_then(|logical| {
        (logical != 0).then_some(discovered.div_ceil(logical as usize))
    });
    let resolution_ns = tsc_hz.map(|hz| 1_000_000_000u64.div_ceil(hz));
    let nominal_hz = nominal_frequency_hz();
    let bus_hz = bus_frequency_hz();
    let features = isa_extensions();
    let line = alloc::format!(
        "HW CPU VENDOR={} FAMILY={} MODEL={} STEPPING={} BRAND={}",
        cpu_vendor(),
        family,
        model,
        stepping,
        cpu_brand()
    );
    emit(&line);
    let line = alloc::format!(
        "HW CPU DISCOVERED={} ADMITTED={} ONLINE={} DISABLED={} PARTICIPATING={} LOGICAL_PER_PACKAGE={} CORES_PER_PACKAGE={} THREADS_PER_CORE={} SMT={}",
        discovered,
        admitted,
        online,
        disabled,
        participating,
        optional(topology.logical_per_package),
        optional(topology.cores_per_package),
        optional(topology.threads_per_core),
        topology
            .threads_per_core
            .map(|threads| threads > 1)
            .map(|smt| if smt { "true" } else { "false" })
            .unwrap_or("unknown")
    );
    emit(&line);
    let line = alloc::format!(
        "HW TOPOLOGY PACKAGES={} SOURCE=cpuid-madt-smt",
        optional(packages)
    );
    emit(&line);
    let line = alloc::format!(
        "HW ISA EXTENSIONS={}",
        features
    );
    emit(&line);
    let line = alloc::format!(
        "HW VIRTUALIZATION HYPERVISOR={} VMX={} SVM={}",
        hypervisor_vendor(),
        features.split(',').any(|name| name == "vmx"),
        features.split(',').any(|name| name == "svm")
    );
    emit(&line);
    let line = alloc::format!(
        "HW TIME BACKEND=tsc frequency_hz={} source={} nominal_frequency_hz={} bus_frequency_hz={} invariant={} rdtscp={} resolution_ns={}",
        optional(tsc_hz),
        early::tsc_frequency_source(),
        optional(nominal_hz),
        optional(bus_hz),
        invariant_tsc(),
        rdtscp(),
        optional(resolution_ns)
    );
    emit(&line);
    let line = alloc::format!(
        "HW MEMORY USABLE_KIB={} FREE_KIB={} HEAP_TOTAL_KIB={} HEAP_FREE_KIB={} HEAP_MAPPED_KIB={}",
        usable.saturating_mul(4),
        free.saturating_mul(4),
        heap_total / 1024,
        heap_free / 1024,
        heap_mapped / 1024
    );
    emit(&line);
    let line = alloc::format!(
        "HW NUMA NODES=unavailable source=acpi.srat_not_parsed"
    );
    emit(&line);
    let line = alloc::format!(
        "HW FIRMWARE VENDOR=unavailable VERSION=unavailable DATE=unavailable source=smbios_unavailable_in_boot_handoff"
    );
    emit(&line);
    let line = alloc::format!(
        "HW BOARD VENDOR=unavailable PRODUCT=unavailable source=smbios_unavailable_in_boot_handoff"
    );
    emit(&line);
    let line = alloc::format!(
        "HW PLATFORM PROFILE={} KERNEL={} COMMIT={}",
        profile::ACTIVE.name,
        kmain::VERSION,
        option_env!("JASPER_BUILD_COMMIT").unwrap_or("unknown")
    );
    emit(&line);
    report_caches();
    crate::kprintln!(
        "{{\"schema\":\"jasper.hardware.v1\",\"kind\":\"system\",\"cpu_vendor\":\"{}\",\"cpu_brand\":\"{}\",\"family\":{},\"model\":{},\"stepping\":{},\"packages\":{},\"packages_source\":\"cpuid-madt-smt\",\"discovered_cpus\":{},\"admitted_cpus\":{},\"online_cpus\":{},\"disabled_cpus\":{},\"participating_cpus\":{},\"logical_per_package\":{},\"cores_per_package\":{},\"threads_per_core\":{},\"isa_extensions\":\"{}\",\"hypervisor\":\"{}\",\"invariant_tsc\":{},\"rdtscp\":{},\"timer_backend\":\"tsc\",\"tsc_hz\":{},\"tsc_source\":\"{}\",\"nominal_frequency_hz\":{},\"bus_frequency_hz\":{},\"timer_resolution_ns\":{},\"usable_kib\":{},\"free_kib\":{},\"heap_total_kib\":{},\"heap_free_kib\":{},\"heap_mapped_kib\":{},\"numa_nodes\":null,\"firmware_vendor\":null,\"firmware_version\":null,\"board_vendor\":null,\"board_product\":null,\"profile\":\"{}\",\"kernel\":\"{}\",\"commit\":\"{}\"}}",
        cpu_vendor(),
        cpu_brand(),
        family,
        model,
        stepping,
        optional_json(packages),
        discovered,
        admitted,
        online,
        disabled,
        participating,
        optional_json(topology.logical_per_package),
        optional_json(topology.cores_per_package),
        optional_json(topology.threads_per_core),
        features,
        hypervisor_vendor(),
        invariant_tsc(),
        rdtscp(),
        optional_json(tsc_hz),
        early::tsc_frequency_source(),
        optional_json(nominal_hz),
        optional_json(bus_hz),
        optional_json(resolution_ns),
        usable.saturating_mul(4),
        free.saturating_mul(4),
        heap_total / 1024,
        heap_free / 1024,
        heap_mapped / 1024,
        profile::ACTIVE.name,
        kmain::VERSION,
        option_env!("JASPER_BUILD_COMMIT").unwrap_or("unknown")
    );
}

fn report_caches() {
    let max_basic = core::arch::x86_64::__cpuid(0).eax;
    let max_extended = core::arch::x86_64::__cpuid(0x8000_0000).eax;
    let leaf = if max_basic >= 4 && core::arch::x86_64::__cpuid_count(4, 0).eax & 0x1f != 0 {
        4
    } else if max_extended >= 0x8000_001d
        && core::arch::x86_64::__cpuid_count(0x8000_001d, 0).eax & 0x1f != 0
    {
        0x8000_001d
    } else {
        emit("HW CACHE unavailable");
        return;
    };
    for index in 0..16 {
        let value = core::arch::x86_64::__cpuid_count(leaf, index);
        let cache_type = value.eax & 0x1f;
        if cache_type == 0 {
            break;
        }
        let level = (value.eax >> 5) & 0x7;
        let ways = ((value.ebx >> 22) & 0x3ff) + 1;
        let partitions = ((value.ebx >> 12) & 0x3ff) + 1;
        let line_size = (value.ebx & 0xfff) + 1;
        let sets = value.ecx + 1;
        let size = u64::from(ways)
            .saturating_mul(u64::from(partitions))
            .saturating_mul(u64::from(line_size))
            .saturating_mul(u64::from(sets));
        let threads = ((value.eax >> 14) & 0xfff) + 1;
        let kind = match cache_type {
            1 => "data",
            2 => "instruction",
            3 => "unified",
            _ => "unknown",
        };
        let line = alloc::format!(
            "HW CACHE level={} type={} size_kib={} shared_threads={}",
            level,
            kind,
            size / 1024,
            threads
        );
        emit(&line);
        crate::kprintln!(
            "{{\"schema\":\"jasper.hardware.v1\",\"kind\":\"cache\",\"level\":{},\"cache_type\":\"{}\",\"size_bytes\":{},\"shared_threads\":{}}}",
            level,
            kind,
            size,
            threads
        );
    }
}

fn optional<T: core::fmt::Display>(value: Option<T>) -> impl core::fmt::Display {
    Optional(value)
}

fn optional_json<T: core::fmt::Display>(value: Option<T>) -> impl core::fmt::Display {
    JsonOptional(value)
}

struct Optional<T>(Option<T>);
impl<T: core::fmt::Display> core::fmt::Display for Optional<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.0 {
            Some(value) => write!(f, "{value}"),
            None => f.write_str("unknown"),
        }
    }
}

struct JsonOptional<T>(Option<T>);
impl<T: core::fmt::Display> core::fmt::Display for JsonOptional<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.0 {
            Some(value) => write!(f, "{value}"),
            None => f.write_str("null"),
        }
    }
}

fn emit(text: &str) {
    crate::console::write_str(text);
    crate::console::write_str("\n");
    #[cfg(target_arch = "x86_64")]
    early::append_line(text);
}
