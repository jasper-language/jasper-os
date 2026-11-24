//! Read-only hardware facts for boot diagnostics and performance reports.

use alloc::string::String;

use kernel_core::acpi::{self, PhysRead};
use kernel_core::smbios;

use crate::{early, kmain, mm, profile, smp};

struct PhysicalWindow(u64);

impl PhysRead for PhysicalWindow {
    fn read(&self, phys: u64, buf: &mut [u8]) -> bool {
        match phys.checked_add(buf.len() as u64) {
            Some(_) => {
                // SAFETY: the bootloader direct map covers the physical address
                // range admitted by firmware; this reader only copies bytes
                // referenced by firmware tables.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (self.0 + phys) as *const u8,
                        buf.as_mut_ptr(),
                        buf.len(),
                    )
                };
                true
            }
            _ => false,
        }
    }
}

pub struct CpuTopology {
    pub logical_per_package: Option<u32>,
    pub cores_per_package: Option<u32>,
    pub threads_per_core: Option<u32>,
    pub nodes_per_processor: Option<u32>,
    pub dies_per_package: Option<u32>,
    pub source: &'static str,
}

pub fn cpu_vendor() -> String {
    let leaf = core::arch::x86_64::__cpuid(0);
    let mut bytes = [0u8; 12];
    bytes[0..4].copy_from_slice(&leaf.ebx.to_le_bytes());
    bytes[4..8].copy_from_slice(&leaf.edx.to_le_bytes());
    bytes[8..12].copy_from_slice(&leaf.ecx.to_le_bytes());
    String::from_utf8_lossy(&bytes).trim().into()
}

fn is_amd() -> bool {
    let leaf = core::arch::x86_64::__cpuid(0);
    let mut bytes = [0u8; 12];
    bytes[..4].copy_from_slice(&leaf.ebx.to_le_bytes());
    bytes[4..8].copy_from_slice(&leaf.edx.to_le_bytes());
    bytes[8..].copy_from_slice(&leaf.ecx.to_le_bytes());
    &bytes == b"AuthenticAMD"
}

fn is_intel() -> bool {
    cpu_vendor() == "GenuineIntel"
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
    let amd = is_amd();
    let intel = is_intel();
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
    add(amd && extended.ecx & (1 << 5) != 0, "lzcnt");
    add(intel && basic.ecx & (1 << 5) != 0, "vmx");
    add(extended.edx & (1 << 20) != 0, "nx");
    add(extended.edx & (1 << 27) != 0, "rdtscp");
    add(invariant_tsc(), "invariant_tsc");
    output
}

pub fn topology() -> CpuTopology {
    let maximum_basic = core::arch::x86_64::__cpuid(0).eax;
    let maximum_extended = core::arch::x86_64::__cpuid(0x8000_0000).eax;
    let leaf1 = core::arch::x86_64::__cpuid(1);
    let logical_per_package = Some((leaf1.ebx >> 16) & 0xff).filter(|count| *count != 0);
    if is_amd() && maximum_extended >= 0x8000_001e {
        let topology = core::arch::x86_64::__cpuid(0x8000_001e);
        let threads_per_core = ((topology.ebx >> 8) & 0xff) + 1;
        let nodes_per_processor = ((topology.ecx >> 8) & 0x7) + 1;
        let threads_per_processor = if maximum_extended >= 0x8000_0008 {
            Some((core::arch::x86_64::__cpuid(0x8000_0008).ecx & 0xff) + 1)
        } else {
            logical_per_package
        };
        let cores_per_package = threads_per_processor.map(|threads| {
            if threads_per_core != 0 {
                threads.div_ceil(threads_per_core)
            } else {
                threads
            }
        });
        return CpuTopology {
            logical_per_package: threads_per_processor,
            cores_per_package,
            threads_per_core: Some(threads_per_core),
            nodes_per_processor: Some(nodes_per_processor),
            dies_per_package: Some(nodes_per_processor),
            source: "cpuid.amd.8000001e+80000008",
        };
    }
    if maximum_basic >= 0x1f || maximum_basic >= 0xb {
        let leaf = if maximum_basic >= 0x1f
            && core::arch::x86_64::__cpuid_count(0x1f, 0).ebx != 0
        {
            0x1f
        } else {
            0xb
        };
        let mut smt = None;
        let mut core = None;
        let mut die = None;
        let mut package = None;
        for subleaf in 0..8 {
            let value = core::arch::x86_64::__cpuid_count(leaf, subleaf);
            if value.ebx == 0 {
                break;
            }
            match value.ecx >> 8 {
                1 => smt = Some(value.ebx),
                2 => core = Some(value.ebx),
                5 => die = Some(value.ebx),
                6.. => package = Some(value.ebx),
                _ => {}
            }
        }
        if smt.is_some() || core.is_some() || package.is_some() {
            return CpuTopology {
                logical_per_package: package.or(logical_per_package),
                cores_per_package: core,
                threads_per_core: smt,
                nodes_per_processor: None,
                dies_per_package: die,
                source: if leaf == 0x1f {
                    "cpuid.intel.1f"
                } else {
                    "cpuid.intel.0b"
                },
            };
        }
    }
    if maximum_extended >= 0x8000_0008 {
        let value = core::arch::x86_64::__cpuid(0x8000_0008);
        let cores = (value.ecx & 0xff) + 1;
        let threads = logical_per_package.and_then(|logical| {
            (logical != 0 && logical % cores == 0).then_some(logical / cores)
        });
        return CpuTopology {
            logical_per_package,
            cores_per_package: Some(cores),
            threads_per_core: threads,
            nodes_per_processor: None,
            dies_per_package: None,
            source: "cpuid.amd.80000008",
        };
    }
    CpuTopology {
        logical_per_package,
        cores_per_package: None,
        threads_per_core: None,
        nodes_per_processor: None,
        dies_per_package: None,
        source: "cpuid.legacy",
    }
}

/// Logical CPU identity gathered on the CPU itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApCpuTopology {
    pub logical: usize,
    pub x2apic_id: u32,
    pub core_key: u64,
    pub threads_per_core: u16,
}

fn local_ap_topology_probe(_: u64) -> u64 {
    if is_amd() && core::arch::x86_64::__cpuid(0x8000_0000).eax >= 0x8000_001e {
        let value = core::arch::x86_64::__cpuid(0x8000_001e);
        let core_id = u64::from(value.ebx & 0xff);
        let threads = u64::from((value.ebx >> 8) & 0xff) + 1;
        let node = u64::from(value.ecx & 0xff);
        let core_key = ((node & 0xff) << 8) | (core_id & 0xff);
        return (u64::from(value.eax) << 32)
            | ((threads & 0x3f) << 24)
            | (core_key & 0x00ff_ffff);
    }
    if is_intel() && core::arch::x86_64::__cpuid(0).eax >= 0x1f {
        let level0 = core::arch::x86_64::__cpuid_count(0x1f, 0);
        if level0.ebx != 0 {
            let x2apic = level0.edx;
            let shift = level0.eax & 0x1f;
            let threads = 1u64 << shift;
            let core_key = u64::from(x2apic) >> shift;
            return (u64::from(x2apic) << 32)
                | ((threads & 0x3f) << 24)
                | (core_key & 0x00ff_ffff);
        }
    }
    let x2apic = core::arch::x86_64::__cpuid(1).ebx >> 24;
    (u64::from(x2apic) << 32) | (1 << 24) | (u64::from(x2apic) & 0x00ff_ffff)
}

/// Query topology on every online CPU through the real cross-CPU call path.
pub fn online_cpu_topology() -> alloc::vec::Vec<ApCpuTopology> {
    let online = smp::online_set();
    let mut out = alloc::vec::Vec::new();
    if out.try_reserve_exact(online.len()).is_err() {
        return out;
    }
    for logical in online.iter() {
        let encoded = if logical == crate::arch::cpu_index() {
            local_ap_topology_probe(0)
        } else {
            match smp::call_on(logical, local_ap_topology_probe, 0) {
                Ok(value) => value,
                Err(_) => continue,
            }
        };
        out.push(ApCpuTopology {
            logical,
            x2apic_id: (encoded >> 32) as u32,
            core_key: encoded & 0x00ff_ffff,
            threads_per_core: ((encoded >> 24) & 0x3f) as u16,
        });
    }
    out
}

pub fn report() {
    let (family, model, stepping) = cpu_identity();
    let topology = topology();
    let tsc_hz = early::tsc_frequency_hz();
    let usable = mm::frame::usable_frames();
    let free = mm::frame::free_frames();
    let (heap_total, heap_free, _, heap_mapped) = mm::heap::stats();
    let heap_peak = mm::heap::peak_used();
    let raw_records = smp::discovered_cpu_count();
    let enabled_records = smp::firmware_enabled_cpu_record_count();
    let disabled_records = smp::firmware_disabled_cpu_record_count();
    let duplicate_records = smp::duplicate_cpu_record_count();
    let conflicting_duplicates = smp::conflicting_cpu_record_count();
    let unique_enabled = smp::unique_enabled_cpu_count().max(1);
    let admitted = smp::admitted_cpu_count();
    let online = smp::online_set().len();
    let unique_disabled = smp::disabled_cpu_count();
    let participating = online;
    let packages = topology.logical_per_package.and_then(|logical| {
        (logical != 0).then_some(unique_enabled.div_ceil(logical as usize))
    });
    let resolution_ns = tsc_hz.map(|hz| 1_000_000_000u64.div_ceil(hz));
    let nominal_hz = nominal_frequency_hz();
    let bus_hz = bus_frequency_hz();
    let features = isa_extensions();
    let vmx = is_intel() && core::arch::x86_64::__cpuid(1).ecx & (1 << 5) != 0;
    let svm = is_amd()
        && core::arch::x86_64::__cpuid(0x8000_0001).ecx & (1 << 2) != 0;
    let acpi_table = crate::boot::get().and_then(|boot| {
        boot.phys_offset
            .zip(boot.acpi_rsdp)
            .map(|(offset, rsdp)| (PhysicalWindow(offset), rsdp))
    });
    let firmware_info = acpi_table
        .as_ref()
        .and_then(|(memory, rsdp)| acpi::parse_firmware_info(memory, *rsdp).ok());
    let numa_result = acpi_table
        .as_ref()
        .map(|(memory, rsdp)| acpi::parse_numa(memory, *rsdp));
    let numa = numa_result.as_ref().and_then(|result| result.as_ref().ok());
    let numa_nodes = numa.map(|topology| topology.domain_count()).filter(|count| *count != 0);
    let smbios = crate::boot::get()
        .and_then(|boot| boot.phys_offset)
        .and_then(|offset| smbios::scan_legacy(&PhysicalWindow(offset)));
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
        "HW CPU RAW_RECORDS={} ENABLED_RECORDS={} DISABLED_RECORDS={} DUPLICATES={} CONFLICTING_DUPLICATES={} UNIQUE_ENABLED={} UNIQUE_DISABLED={} ADMITTED={} ONLINE={} PARTICIPATING={}",
        raw_records,
        enabled_records,
        disabled_records,
        duplicate_records,
        conflicting_duplicates,
        unique_enabled,
        unique_disabled,
        admitted,
        online,
        participating
    );
    emit(&line);
    let line = alloc::format!(
        "HW CPU TOPOLOGY LOGICAL_PER_PACKAGE={} CORES_PER_PACKAGE={} THREADS_PER_CORE={} NODES_PER_PROCESSOR={} DIES_PER_PACKAGE={} SMT={} SOURCE={}",
        optional(topology.logical_per_package),
        optional(topology.cores_per_package),
        optional(topology.threads_per_core),
        optional(topology.nodes_per_processor),
        optional(topology.dies_per_package),
        topology
            .threads_per_core
            .map(|threads| threads > 1)
            .map(|smt| if smt { "true" } else { "false" })
            .unwrap_or("unknown"),
        topology.source
    );
    emit(&line);
    let line = alloc::format!(
        "HW TOPOLOGY PACKAGES={} SOURCE=cpuid+firmware-inventory",
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
        vmx,
        svm
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
        "HW MEMORY USABLE_KIB={} FREE_KIB={} HEAP_TOTAL_KIB={} HEAP_USED_KIB={} HEAP_PEAK_KIB={} HEAP_FREE_KIB={} HEAP_MAPPED_KIB={}",
        usable.saturating_mul(4),
        free.saturating_mul(4),
        heap_total / 1024,
        heap_total.saturating_sub(heap_free) / 1024,
        heap_peak / 1024,
        heap_free / 1024,
        heap_mapped / 1024
    );
    emit(&line);
    let line = match numa {
        Some(topology) => alloc::format!(
            "HW NUMA DOMAINS={} LOCALITIES={} CPU_RECORDS={} MEMORY_RECORDS={} SOURCE=acpi.srat+slit",
            topology.domain_count(),
            optional(topology.localities()),
            topology.cpus().len(),
            topology.memory().len()
        ),
        None => alloc::format!(
            "HW NUMA NODES=unavailable source={}",
            numa_result
                .as_ref()
                .map_or("acpi.unavailable", |result| result
                    .as_ref()
                    .err()
                    .map_or("acpi.srat", |error| error.name()))
        ),
    };
    emit(&line);
    if let Some(topology) = numa {
        report_numa(topology);
    }
    let line = alloc::format!(
        "HW FIRMWARE VENDOR={} VERSION={} DATE={} ACPI_OEM_ID={} ACPI_OEM_TABLE_ID={} ACPI_OEM_REVISION={} ACPI_CREATOR_ID={} ACPI_CREATOR_REVISION={} SMBIOS={}",
        optional_text(smbios.as_ref().and_then(|info| info.bios_vendor.as_deref())),
        optional_text(smbios.as_ref().and_then(|info| info.bios_version.as_deref())),
        optional_text(smbios.as_ref().and_then(|info| info.bios_release_date.as_deref())),
        optional_text(firmware_info.as_ref().map(|info| ascii(&info.acpi_oem_id_text()))),
        optional_text(firmware_info.as_ref().map(|info| ascii(&info.acpi_oem_table_id_text()))),
        optional(firmware_info.as_ref().map(|info| info.acpi_oem_revision)),
        optional_text(firmware_info.as_ref().map(|info| ascii(&info.creator_id_text()))),
        optional(firmware_info.as_ref().map(|info| info.creator_revision)),
        smbios.as_ref().map_or("unavailable", |_| "available")
    );
    emit(&line);
    let line = alloc::format!(
        "HW BOARD VENDOR={} PRODUCT={} VERSION={} SYSTEM_VENDOR={} SYSTEM_PRODUCT={}",
        optional_text(smbios.as_ref().and_then(|info| info.board_vendor.as_deref())),
        optional_text(smbios.as_ref().and_then(|info| info.board_product.as_deref())),
        optional_text(smbios.as_ref().and_then(|info| info.board_version.as_deref())),
        optional_text(smbios.as_ref().and_then(|info| info.system_vendor.as_deref())),
        optional_text(smbios.as_ref().and_then(|info| info.system_product.as_deref()))
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
        "{{\"schema\":\"jasper.hardware.v1\",\"kind\":\"system\",\"cpu_vendor\":\"{}\",\"cpu_brand\":\"{}\",\"family\":{},\"model\":{},\"stepping\":{},\"topology_source\":\"{}\",\"packages\":{},\"packages_source\":\"cpuid+firmware-inventory\",\"raw_cpu_records\":{},\"enabled_cpu_records\":{},\"disabled_cpu_records\":{},\"duplicate_cpu_records\":{},\"conflicting_duplicate_records\":{},\"unique_enabled_cpus\":{},\"unique_disabled_cpus\":{},\"admitted_cpus\":{},\"online_cpus\":{},\"participating_cpus\":{},\"logical_per_package\":{},\"cores_per_package\":{},\"threads_per_core\":{},\"nodes_per_processor\":{},\"dies_per_package\":{},\"isa_extensions\":\"{}\",\"hypervisor\":\"{}\",\"vmx\":{},\"svm\":{},\"invariant_tsc\":{},\"rdtscp\":{},\"timer_backend\":\"tsc\",\"tsc_hz\":{},\"tsc_source\":\"{}\",\"nominal_frequency_hz\":{},\"bus_frequency_hz\":{},\"timer_resolution_ns\":{},\"usable_kib\":{},\"free_kib\":{},\"heap_total_kib\":{},\"heap_used_kib\":{},\"heap_peak_kib\":{},\"heap_free_kib\":{},\"heap_mapped_kib\":{},\"numa_nodes\":{},\"numa_localities\":{},\"acpi_oem_id\":{},\"acpi_oem_table_id\":{},\"acpi_oem_revision\":{},\"acpi_creator_id\":{},\"acpi_creator_revision\":{},\"firmware_vendor\":{},\"firmware_version\":{},\"firmware_date\":{},\"board_vendor\":{},\"board_product\":{},\"board_version\":{},\"system_vendor\":{},\"system_product\":{},\"smbios_major\":{},\"smbios_minor\":{},\"profile\":\"{}\",\"kernel\":\"{}\",\"commit\":\"{}\"}}",
        cpu_vendor(),
        cpu_brand(),
        family,
        model,
        stepping,
        topology.source,
        optional_json(packages),
        raw_records,
        enabled_records,
        disabled_records,
        duplicate_records,
        conflicting_duplicates,
        unique_enabled,
        unique_disabled,
        admitted,
        online,
        participating,
        optional_json(topology.logical_per_package),
        optional_json(topology.cores_per_package),
        optional_json(topology.threads_per_core),
        optional_json(topology.nodes_per_processor),
        optional_json(topology.dies_per_package),
        features,
        hypervisor_vendor(),
        vmx,
        svm,
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
        heap_total.saturating_sub(heap_free) / 1024,
        heap_peak / 1024,
        heap_free / 1024,
        heap_mapped / 1024,
        optional_json(numa_nodes),
        optional_json(numa.and_then(|topology| topology.localities())),
        json_text(firmware_info.as_ref().map(|info| ascii(&info.acpi_oem_id_text()))),
        json_text(firmware_info.as_ref().map(|info| ascii(&info.acpi_oem_table_id_text()))),
        optional_json(firmware_info.as_ref().map(|info| info.acpi_oem_revision)),
        json_text(firmware_info.as_ref().map(|info| ascii(&info.creator_id_text()))),
        optional_json(firmware_info.as_ref().map(|info| info.creator_revision)),
        json_text(smbios.as_ref().and_then(|info| info.bios_vendor.clone())),
        json_text(smbios.as_ref().and_then(|info| info.bios_version.clone())),
        json_text(smbios.as_ref().and_then(|info| info.bios_release_date.clone())),
        json_text(smbios.as_ref().and_then(|info| info.board_vendor.clone())),
        json_text(smbios.as_ref().and_then(|info| info.board_product.clone())),
        json_text(smbios.as_ref().and_then(|info| info.board_version.clone())),
        json_text(smbios.as_ref().and_then(|info| info.system_vendor.clone())),
        json_text(smbios.as_ref().and_then(|info| info.system_product.clone())),
        optional_json(smbios.as_ref().map(|info| info.major)),
        optional_json(smbios.as_ref().map(|info| info.minor)),
        profile::ACTIVE.name,
        kmain::VERSION,
        option_env!("JASPER_BUILD_COMMIT").unwrap_or("unknown")
    );
    crate::clock_fact::report();
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

fn report_numa(topology: &acpi::NumaTopology) {
    for cpu in topology.cpus() {
        let line = alloc::format!(
            "HW NUMA CPU APIC_ID={} DOMAIN={} ENABLED={}",
            cpu.hardware_id,
            cpu.proximity_domain,
            cpu.enabled
        );
        emit(&line);
        crate::kprintln!(
            "{{\"schema\":\"jasper.hardware.v1\",\"kind\":\"numa-cpu\",\"hardware_id\":{},\"proximity_domain\":{},\"enabled\":{}}}",
            cpu.hardware_id,
            cpu.proximity_domain,
            cpu.enabled
        );
    }
    for memory in topology.memory() {
        let line = alloc::format!(
            "HW NUMA MEMORY DOMAIN={} BASE={} LENGTH={} ENABLED={} HOT_PLUGGABLE={} NON_VOLATILE={}",
            memory.proximity_domain,
            memory.base,
            memory.length,
            memory.enabled,
            memory.hot_pluggable,
            memory.non_volatile
        );
        emit(&line);
        crate::kprintln!(
            "{{\"schema\":\"jasper.hardware.v1\",\"kind\":\"numa-memory\",\"proximity_domain\":{},\"base\":{},\"length\":{},\"enabled\":{},\"hot_pluggable\":{},\"non_volatile\":{}}}",
            memory.proximity_domain,
            memory.base,
            memory.length,
            memory.enabled,
            memory.hot_pluggable,
            memory.non_volatile
        );
    }
    if let Some(localities) = topology.localities() {
        for from in 0..localities {
            for to in 0..localities {
                if let Some(distance) = topology.distance(from, to) {
                    crate::kprintln!(
                        "{{\"schema\":\"jasper.hardware.v1\",\"kind\":\"numa-distance\",\"from\":{},\"to\":{},\"distance\":{}}}",
                        from,
                        to,
                        distance
                    );
                }
            }
        }
    }
}

fn ascii(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn optional_text<T: AsRef<str>>(value: Option<T>) -> impl core::fmt::Display {
    Text(value)
}

struct Text<T>(Option<T>);

impl<T: AsRef<str>> core::fmt::Display for Text<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0.as_ref().map_or("unavailable", AsRef::as_ref))
    }
}

fn json_text(value: Option<String>) -> impl core::fmt::Display {
    JsonText(value)
}

struct JsonText(Option<String>);

impl core::fmt::Display for JsonText {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.0 {
            Some(value) => {
                f.write_str("\"")?;
                for ch in value.chars() {
                    match ch {
                        '"' => f.write_str("\\\"")?,
                        '\\' => f.write_str("\\\\")?,
                        '\n' => f.write_str("\\n")?,
                        '\r' => f.write_str("\\r")?,
                        '\t' => f.write_str("\\t")?,
                        c if c.is_control() => write!(f, "\\u{:04x}", c as u32)?,
                        c => write!(f, "{c}")?,
                    }
                }
                f.write_str("\"")
            }
            None => f.write_str("null"),
        }
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
