//! Minimal native x86_64 Linux guest for HWV-4.
//!
//! This loader follows the kernel's 64-bit boot protocol. It does not emulate
//! BIOS or claim that a probe represents Linux: the bytes executed here are
//! the real `arch/x86/boot/vmlinux.bin` built from Linux 6.12, entering at
//! `startup_64` (`load address + 0x200`).

use kernel_core::frame::PhysFrame;
use kernel_core::hwvirt::Backend;
use kernel_core::hwvirt_vcpu::{GuestPermissions, VcpuState};
use kernel_core::vmm_device::{
    VirtioDeviceType, VirtioMmio, FEATURE_VERSION_1,
};
use kernel_core::virtio_net::{
    VirtioNetBackend, VirtioNetHeader, MAX_FRAME_BYTES, VIRTIO_NET_HEADER_BYTES,
};
use kernel_core::virtio_fs::{
    VirtioFsBackend, FUSE_OUT_HEADER_BYTES, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
};

use crate::arch::x86_64::vmx::{GuestExecutionState, LinuxPlatform, LinuxReport, VmxVm};
use crate::{kobj, kprintln, mm, proc, vcpu};
use core::sync::atomic::{fence, Ordering};

static LINUX_SETUP: &[u8] = include_bytes!(env!("JSR_LINUX_GUEST_HEADER"));
static LINUX_KERNEL: &[u8] = include_bytes!(env!("JSR_LINUX_GUEST_KERNEL"));

// The minimal kernel + initramfs boots in 64 MiB. Keep this below Jasper's
// default 128 MiB machine budget so the guest cap is exercised rather than
// relying on overcommitting the host RAM image.
const GUEST_FRAMES: u64 = 16 * 1024;
const GUEST_RAM: u64 = GUEST_FRAMES * 4096;
const LINUX_USABLE_RAM: u64 = 60 * 1024 * 1024;
const PAGE_TABLE_ROOT: u64 = 0x1000;
const BOOT_PARAMS: u64 = 0x8000;
const COMMAND_LINE: u64 = 0x7000;
const GUEST_STACK: u64 = 0x9f000;
const KERNEL_BASE: u64 = 0x0100_0000;
const PAGE_2M: u64 = 2 * 1024 * 1024;
const PAGE_ENTRIES: u64 = GUEST_RAM / PAGE_2M;
const VIRTIO_RNG_BASE: u64 = 0xd000_0000;
const VIRTIO_RNG_IRQ: u8 = 5;
const VIRTIO_CONSOLE_BASE: u64 = 0xd000_1000;
const VIRTIO_CONSOLE_IRQ: u8 = 6;
const VIRTIO_BLOCK_BASE: u64 = 0xd000_2000;
const VIRTIO_BLOCK_IRQ: u8 = 3;
const VIRTIO_NET_BASE: u64 = 0xd000_3000;
const VIRTIO_NET_IRQ: u8 = 10;
const VIRTIO_FS_BASE: u64 = 0xd000_4000;
const VIRTIO_FS_IRQ: u8 = 11;

struct VirtioGuestBus {
    pid: kernel_core::objtable::ObjId,
    vcpu: kernel_core::object::HandleId,
    rng: VirtioMmio,
    console: VirtioMmio,
    block: VirtioMmio,
    net: VirtioMmio,
    net_backend: VirtioNetBackend,
    fs: VirtioMmio,
    fs_backend: VirtioFsBackend,
    last_avail: [u16; 2],
    console_last_avail: [u16; 2],
    console_bytes: u32,
    block_last_avail: u16,
    block_requests: u32,
    net_rx_last_avail: u16,
    net_tx_last_avail: u16,
    net_tx_frames: u32,
    net_rx_frames: u32,
    net_rejected: u32,
    fs_last_avail: u16,
    fs_requests: u32,
    fs_rejected: u32,
    disk: [u8; 4096],
    pending_irqs: u16,
    rng_requests: u32,
    random_state: u64,
}

impl VirtioGuestBus {
    fn new(pid: kernel_core::objtable::ObjId, vcpu: kernel_core::object::HandleId) -> Self {
        Self {
            pid,
            vcpu,
            rng: VirtioMmio::new(
                VirtioDeviceType::Rng,
                16,
                [0, FEATURE_VERSION_1],
            ),
            console: VirtioMmio::new(
                VirtioDeviceType::Console,
                16,
                [0, FEATURE_VERSION_1],
            ),
            block: VirtioMmio::new(
                VirtioDeviceType::Block,
                16,
                [0, FEATURE_VERSION_1],
            ),
            net: VirtioMmio::new(
                VirtioDeviceType::Net,
                16,
                [kernel_core::virtio_net::FEATURE_MAC, FEATURE_VERSION_1],
            ),
            net_backend: VirtioNetBackend::new(
                [0x52, 0x54, 0x00, 0x12, 0x34, 0x57],
                [10, 0, 2, 2],
            ),
            fs: VirtioMmio::new(
                VirtioDeviceType::Fs,
                16,
                [0, FEATURE_VERSION_1],
            ),
            fs_backend: VirtioFsBackend::new(),
            last_avail: [0; 2],
            console_last_avail: [0; 2],
            console_bytes: 0,
            block_last_avail: 0,
            block_requests: 0,
            net_rx_last_avail: 0,
            net_tx_last_avail: 0,
            net_tx_frames: 0,
            net_rx_frames: 0,
            net_rejected: 0,
            fs_last_avail: 0,
            fs_requests: 0,
            fs_rejected: 0,
            disk: {
                let mut disk = [0u8; 4096];
                let marker = b"JASPER-BLOCK-001";
                let mut index = 0;
                while index < marker.len() {
                    disk[index] = marker[index];
                    index += 1;
                }
                disk
            },
            pending_irqs: 0,
            rng_requests: 0,
            random_state: 0x4a61_7370_6572_4f53,
        }
    }

    fn next_random(&mut self) -> u8 {
        self.random_state = self
            .random_state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.random_state >> 56) as u8
    }

    fn process_rng(&mut self, queue_index: u16) {
        // virtio-rng has one receive queue. A guest notification for any other
        // queue is rejected before it can index per-queue completion state.
        if queue_index != 0 {
            return;
        }
        let Some(queue) = self.rng.queue(queue_index) else {
            return;
        };
        if !queue.ready || queue.address.driver == 0 || queue.address.descriptor == 0 {
            return;
        }
        let Some(avail) = self.read_u16(queue.address.driver + 2) else {
            return;
        };
        let last_index = usize::from(queue_index);
        let mut last = self.last_avail[last_index];
        let mut completed = false;
        while last != avail {
            let slot = usize::from(last % queue.size);
            let Some(head) = self.read_u16(queue.address.driver + 4 + (slot as u64) * 2) else {
                return;
            };
            let descriptor = queue.address.descriptor + u64::from(head) * 16;
            let Some(address) = self.read_u64(descriptor) else {
                return;
            };
            let Some(length) = self.read_u32(descriptor + 8) else {
                return;
            };
            let length = length.min(4096);
            for offset in 0..length {
                let byte = self.next_random();
                if !self.write_guest(address + u64::from(offset), &[byte]) {
                    return;
                }
            }
            let used_slot = usize::from(last % queue.size);
            if !self.write_u32(queue.address.device + 4 + (used_slot as u64) * 8, u32::from(head))
                || !self.write_u32(queue.address.device + 8 + (used_slot as u64) * 8, length)
                || !self.write_u16(queue.address.device + 2, last.wrapping_add(1))
            {
                return;
            }
            last = last.wrapping_add(1);
            self.last_avail[last_index] = last;
            self.rng_requests = self.rng_requests.saturating_add(1);
            completed = true;
        }
        if completed {
            self.rng.raise_interrupt(1);
            self.pending_irqs |= 1u16 << VIRTIO_RNG_IRQ;
        }
    }

    fn process_console(&mut self, queue_index: u16) {
        if queue_index != 1 {
            return;
        }
        let Some(queue) = self.console.queue(queue_index) else {
            return;
        };
        if !queue.ready || queue.address.driver == 0 || queue.address.descriptor == 0 {
            return;
        }
        let Some(avail) = self.read_u16(queue.address.driver + 2) else {
            return;
        };
        let mut last = self.console_last_avail[1];
        let mut completed = false;
        while last != avail {
            let slot = usize::from(last % queue.size);
            let Some(head) = self.read_u16(queue.address.driver + 4 + (slot as u64) * 2) else {
                return;
            };
            let descriptor = queue.address.descriptor + u64::from(head) * 16;
            let Some(address) = self.read_u64(descriptor) else {
                return;
            };
            let Some(mut length) = self.read_u32(descriptor + 8) else {
                return;
            };
            length = length.min(4096);
            for offset in 0..length {
                let mut byte = [0u8];
                if !self.read_guest(address + u64::from(offset), &mut byte) {
                    return;
                }
                crate::arch::console_write_byte(byte[0]);
            }
            let used_slot = usize::from(last % queue.size);
            if !self.write_u32(queue.address.device + 4 + (used_slot as u64) * 8, u32::from(head))
                || !self.write_u32(queue.address.device + 8 + (used_slot as u64) * 8, length)
                || !self.write_u16(queue.address.device + 2, last.wrapping_add(1))
            {
                return;
            }
            last = last.wrapping_add(1);
            self.console_last_avail[1] = last;
            self.console_bytes = self.console_bytes.saturating_add(length);
            completed = true;
        }
        if completed {
            self.console.raise_interrupt(1);
            self.pending_irqs |= 1u16 << VIRTIO_CONSOLE_IRQ;
        }
    }

    fn process_block(&mut self, queue_index: u16) {
        if queue_index != 0 {
            return;
        }
        let Some(queue) = self.block.queue(queue_index) else {
            return;
        };
        if !queue.ready || queue.address.driver == 0 || queue.address.descriptor == 0 {
            return;
        }
        let Some(avail) = self.read_u16(queue.address.driver + 2) else {
            return;
        };
        while self.block_last_avail != avail {
            let slot = usize::from(self.block_last_avail % queue.size);
            let Some(head) = self.read_u16(queue.address.driver + 4 + (slot as u64) * 2) else {
                return;
            };
            let mut descriptors = [(0u64, 0u32, 0u16); 8];
            let mut count = 0usize;
            let mut index = head;
            loop {
                if count == descriptors.len() {
                    return;
                }
                let descriptor = queue.address.descriptor + u64::from(index) * 16;
                let Some(address) = self.read_u64(descriptor) else {
                    return;
                };
                let Some(length) = self.read_u32(descriptor + 8) else {
                    return;
                };
                let Some(flags) = self.read_u16(descriptor + 12) else {
                    return;
                };
                let Some(next) = self.read_u16(descriptor + 14) else {
                    return;
                };
                descriptors[count] = (address, length.min(4096), flags);
                count += 1;
                if flags & 1 == 0 {
                    break;
                }
                index = next;
            }
            if count < 3 {
                return;
            }
            let mut header = [0u8; 16];
            if !self.read_guest(descriptors[0].0, &mut header) {
                return;
            }
            let request_type = u32::from_le_bytes(header[0..4].try_into().unwrap());
            let sector = u64::from_le_bytes(header[8..16].try_into().unwrap());
            let disk_offset = match usize::try_from(sector).ok().and_then(|s| s.checked_mul(512)) {
                Some(offset) if offset < self.disk.len() => offset,
                _ => {
                    if !self.write_guest(descriptors[count - 1].0, &[1]) {
                        return;
                    }
                    self.complete_block(queue, head, 1);
                    continue;
                }
            };
            let mut cursor = disk_offset;
            let mut written = 0u32;
            for &(address, length, flags) in &descriptors[1..count - 1] {
                if request_type == 0 {
                    if flags & 2 == 0 {
                        continue;
                    }
                    for offset in 0..length as u64 {
                        let Some(byte) = self.disk.get(cursor).copied() else {
                            break;
                        };
                        if !self.write_guest(address + offset, &[byte]) {
                            return;
                        }
                        cursor += 1;
                        written += 1;
                    }
                } else if request_type == 1 {
                    for offset in 0..length as u64 {
                        let mut byte = [0u8];
                        if !self.read_guest(address + offset, &mut byte) {
                            return;
                        }
                        let Some(target) = self.disk.get_mut(cursor) else {
                            break;
                        };
                        *target = byte[0];
                        cursor += 1;
                        written += 1;
                    }
                }
            }
            let status = if matches!(request_type, 0 | 1) { 0 } else { 2 };
            if !self.write_guest(descriptors[count - 1].0, &[status]) {
                return;
            }
            self.complete_block(queue, head, 1);
            self.block_requests = self.block_requests.saturating_add(1);
            let _ = written;
        }
    }

    fn process_net_rx(&mut self, queue_index: u16) {
        if queue_index != 0 {
            return;
        }
        let Some(queue) = self.net.queue(queue_index) else {
            return;
        };
        if !queue.ready {
            return;
        }
        let Some(available) = self.read_u16(queue.address.driver + 2) else {
            return;
        };
        while self.net_rx_last_avail != available {
            let Some(frame) = self.net_backend.pop_rx() else {
                break;
            };
            let slot = usize::from(self.net_rx_last_avail % queue.size);
            let Some(head) = self.read_u16(queue.address.driver + 4 + (slot as u64) * 2) else {
                return;
            };
            let mut chain = [(0u64, 0u32, 0u16, 0u16); 8];
            let count = match self.read_virtio_chain(queue, head, &mut chain) {
                Ok(count) => count,
                Err(()) => {
                    self.net_rejected = self.net_rejected.saturating_add(1);
                    return;
                }
            };
            if chain[..count].iter().any(|descriptor| descriptor.2 & 2 == 0) {
                self.net_rejected = self.net_rejected.saturating_add(1);
                return;
            }
            let header = [0u8; VIRTIO_NET_HEADER_BYTES];
            let Some(written) = self.write_virtio_scatter(
                &chain[..count],
                &header,
                frame.bytes(),
            ) else {
                self.net_rejected = self.net_rejected.saturating_add(1);
                return;
            };
            let expected = VIRTIO_NET_HEADER_BYTES as u32 + frame.bytes().len() as u32;
            if written != expected
                || !self.complete_net_used(queue_index, queue, head, written)
            {
                self.net_rejected = self.net_rejected.saturating_add(1);
                return;
            }
            self.net_rx_last_avail = self.net_rx_last_avail.wrapping_add(1);
            self.net_rx_frames = self.net_rx_frames.saturating_add(1);
            self.net.raise_interrupt(1);
            self.pending_irqs |= 1u16 << VIRTIO_NET_IRQ;
            break;
        }
    }

    fn process_net_tx(&mut self, queue_index: u16) {
        if queue_index != 1 {
            return;
        }
        let Some(queue) = self.net.queue(queue_index) else {
            return;
        };
        if !queue.ready {
            return;
        }
        let Some(available) = self.read_u16(queue.address.driver + 2) else {
            return;
        };
        while self.net_tx_last_avail != available {
            let slot = usize::from(self.net_tx_last_avail % queue.size);
            let Some(head) = self.read_u16(queue.address.driver + 4 + (slot as u64) * 2) else {
                return;
            };
            let mut chain = [(0u64, 0u32, 0u16, 0u16); 8];
            let count = match self.read_virtio_chain(queue, head, &mut chain) {
                Ok(count) => count,
                Err(()) => {
                    self.net_rejected = self.net_rejected.saturating_add(1);
                    return;
                }
            };
            if chain[..count].iter().any(|descriptor| descriptor.2 & 2 != 0) {
                self.net_rejected = self.net_rejected.saturating_add(1);
                return;
            }
            let total = chain[..count]
                .iter()
                .try_fold(0u32, |sum, descriptor| sum.checked_add(descriptor.1));
            let Some(total) = total else {
                self.net_rejected = self.net_rejected.saturating_add(1);
                return;
            };
            if total < VIRTIO_NET_HEADER_BYTES as u32 {
                self.net_rejected = self.net_rejected.saturating_add(1);
                return;
            }
            let mut raw = [0u8; VIRTIO_NET_HEADER_BYTES + MAX_FRAME_BYTES];
            let payload_len = (total - VIRTIO_NET_HEADER_BYTES as u32) as usize;
            if payload_len > MAX_FRAME_BYTES
                || self.gather_virtio_chain(&chain[..count], &mut raw[..total as usize]).is_none()
                || VirtioNetHeader::decode(&raw[..VIRTIO_NET_HEADER_BYTES]).is_err()
                || self
                    .net_backend
                    .transmit(&raw[VIRTIO_NET_HEADER_BYTES..total as usize])
                    .is_err()
            {
                self.net_rejected = self.net_rejected.saturating_add(1);
                if !self.complete_net_used(queue_index, queue, head, total) {
                    return;
                }
            } else {
                if !self.complete_net_used(queue_index, queue, head, total) {
                    return;
                }
                self.net_tx_frames = self.net_tx_frames.saturating_add(1);
            }
            self.net_tx_last_avail = self.net_tx_last_avail.wrapping_add(1);
        }
        self.process_net_rx(0);
    }

    fn process_fs(&mut self, queue_index: u16) {
        // Queue 0 is reserved for high-priority FUSE messages. This frontend
        // accepts ordinary requests from queue 1 and leaves queue 0 idle.
        if queue_index != 1 {
            return;
        }
        let Some(queue) = self.fs.queue(queue_index) else {
            return;
        };
        if !queue.ready {
            return;
        }
        let Some(available) = self.read_u16(queue.address.driver + 2) else {
            return;
        };
        while self.fs_last_avail != available {
            let slot = usize::from(self.fs_last_avail % queue.size);
            let Some(head) = self.read_u16(queue.address.driver + 4 + (slot as u64) * 2) else {
                return;
            };
            let mut chain = [(0u64, 0u32, 0u16, 0u16); 8];
            let count = match self.read_virtio_chain(queue, head, &mut chain) {
                Ok(count) if count >= 2 => count,
                _ => {
                    self.fs_rejected = self.fs_rejected.saturating_add(1);
                    return;
                }
            };
            let mut request = [0u8; MAX_REQUEST_BYTES];
            let mut request_len = 0usize;
            let mut writable = false;
            for &(address, length, flags, _) in &chain[..count] {
                if flags & 2 != 0 {
                    writable = true;
                    continue;
                }
                let length = length as usize;
                let Some(end) = request_len.checked_add(length) else {
                    self.fs_rejected = self.fs_rejected.saturating_add(1);
                    return;
                };
                if end > request.len() || !self.read_guest(address, &mut request[request_len..end]) {
                    self.fs_rejected = self.fs_rejected.saturating_add(1);
                    return;
                }
                request_len = end;
            }
            if !writable || request_len < 4 {
                self.fs_rejected = self.fs_rejected.saturating_add(1);
                return;
            }
            let declared = u32::from_le_bytes(request[..4].try_into().unwrap()) as usize;
            if declared < FUSE_OUT_HEADER_BYTES || declared > request_len {
                self.fs_rejected = self.fs_rejected.saturating_add(1);
                return;
            }
            let request = &request[..declared];
            let mut response = [0u8; MAX_RESPONSE_BYTES];
            let response_len = match self.fs_backend.handle_request(request, &mut response) {
                Ok(length) => length,
                Err(_) if request.len() >= 16 => {
                    let unique = u64::from_le_bytes(request[8..16].try_into().unwrap());
                    response[..FUSE_OUT_HEADER_BYTES].fill(0);
                    response[..4].copy_from_slice(
                        &(FUSE_OUT_HEADER_BYTES as u32).to_le_bytes(),
                    );
                    response[4..8].copy_from_slice(&(-5i32 as u32).to_le_bytes());
                    response[8..16].copy_from_slice(&unique.to_le_bytes());
                    self.fs_rejected = self.fs_rejected.saturating_add(1);
                    FUSE_OUT_HEADER_BYTES
                }
                Err(_) => {
                    self.fs_rejected = self.fs_rejected.saturating_add(1);
                    return;
                }
            };
            let Some(written) =
                self.write_virtio_output(&chain[..count], &response[..response_len])
            else {
                self.fs_rejected = self.fs_rejected.saturating_add(1);
                return;
            };
            if !self.complete_fs_used(queue, head, written) {
                return;
            }
            self.fs_last_avail = self.fs_last_avail.wrapping_add(1);
            self.fs_requests = self.fs_requests.saturating_add(1);
            self.fs.raise_interrupt(1);
            self.pending_irqs |= 1u16 << VIRTIO_FS_IRQ;
        }
    }

    fn read_virtio_chain(
        &mut self,
        queue: kernel_core::vmm_device::QueueState,
        head: u16,
        output: &mut [(u64, u32, u16, u16); 8],
    ) -> Result<usize, ()> {
        if !queue.ready || queue.size == 0 || head >= queue.size {
            return Err(());
        }
        let mut index = head;
        let mut seen = 0u64;
        for count in 0..output.len() {
            if index >= queue.size || index >= 64 || seen & (1u64 << index) != 0 {
                return Err(());
            }
            seen |= 1u64 << index;
            let base = queue.address.descriptor + u64::from(index) * 16;
            let address = self.read_u64(base).ok_or(())?;
            let length = self.read_u32(base + 8).ok_or(())?;
            let flags = self.read_u16(base + 12).ok_or(())?;
            let next = self.read_u16(base + 14).ok_or(())?;
            output[count] = (address, length, flags, next);
            if flags & 1 == 0 {
                return Ok(count + 1);
            }
            if next >= queue.size {
                return Err(());
            }
            index = next;
        }
        Err(())
    }

    fn gather_virtio_chain(
        &mut self,
        chain: &[(u64, u32, u16, u16)],
        out: &mut [u8],
    ) -> Option<()> {
        let mut cursor = 0usize;
        for (address, length, _, _) in chain {
            let count = (*length as usize).min(out.len().saturating_sub(cursor));
            if count != 0 && !self.read_guest(*address, &mut out[cursor..cursor + count]) {
                return None;
            }
            cursor += count;
            if cursor == out.len() {
                return Some(());
            }
        }
        None
    }

    fn write_virtio_scatter(
        &mut self,
        chain: &[(u64, u32, u16, u16)],
        header: &[u8],
        frame: &[u8],
    ) -> Option<u32> {
        let total = header.len().checked_add(frame.len())?;
        let mut written = 0usize;
        for (address, length, _, _) in chain {
            let count = (*length as usize).min(total - written);
            for index in 0..count {
                let absolute = written + index;
                let byte = if absolute < header.len() {
                    header[absolute]
                } else {
                    frame[absolute - header.len()]
                };
                if !self.write_guest(*address + index as u64, &[byte]) {
                    return None;
                }
            }
            written += count;
            if written == total {
                return u32::try_from(written).ok();
            }
        }
        None
    }

    fn write_virtio_output(
        &mut self,
        chain: &[(u64, u32, u16, u16)],
        bytes: &[u8],
    ) -> Option<u32> {
        let capacity = chain
            .iter()
            .filter(|descriptor| descriptor.2 & 2 != 0)
            .try_fold(0usize, |sum, descriptor| {
                sum.checked_add(descriptor.1 as usize)
            })?;
        if capacity < bytes.len() {
            return None;
        }
        let mut written = 0usize;
        for &(address, length, flags, _) in chain {
            if flags & 2 == 0 {
                continue;
            }
            let count = (length as usize).min(bytes.len().saturating_sub(written));
            if count != 0 && !self.write_guest(address, &bytes[written..written + count]) {
                return None;
            }
            written += count;
            if written == bytes.len() {
                return u32::try_from(written).ok();
            }
        }
        None
    }

    fn complete_net_used(
        &mut self,
        queue_index: u16,
        queue: kernel_core::vmm_device::QueueState,
        head: u16,
        length: u32,
    ) -> bool {
        let last = if queue_index == 0 {
            self.net_rx_last_avail
        } else {
            self.net_tx_last_avail
        };
        let used = last.wrapping_add(1);
        let slot = usize::from(last % queue.size);
        fence(Ordering::Release);
        self.write_u32(queue.address.device + 4 + (slot as u64) * 8, u32::from(head))
            && self.write_u32(
                queue.address.device + 8 + (slot as u64) * 8,
                length,
            )
            && self.write_u16(queue.address.device + 2, used)
    }

    fn complete_fs_used(
        &mut self,
        queue: kernel_core::vmm_device::QueueState,
        head: u16,
        length: u32,
    ) -> bool {
        let used = self.fs_last_avail.wrapping_add(1);
        let slot = usize::from(self.fs_last_avail % queue.size);
        fence(Ordering::Release);
        self.write_u32(
            queue.address.device + 4 + (slot as u64) * 8,
            u32::from(head),
        ) && self.write_u32(
            queue.address.device + 8 + (slot as u64) * 8,
            length,
        ) && self.write_u16(queue.address.device + 2, used)
    }

    fn complete_block(
        &mut self,
        queue: kernel_core::vmm_device::QueueState,
        head: u16,
        length: u32,
    ) {
        let used_slot = usize::from(self.block_last_avail % queue.size);
        fence(Ordering::Release);
        if !self.write_u32(queue.address.device + 4 + (used_slot as u64) * 8, u32::from(head))
            || !self.write_u32(queue.address.device + 8 + (used_slot as u64) * 8, length)
            || !self.write_u16(
                queue.address.device + 2,
                self.block_last_avail.wrapping_add(1),
            )
        {
            return;
        }
        self.block_last_avail = self.block_last_avail.wrapping_add(1);
        self.block.raise_interrupt(1);
        self.pending_irqs |= 1u16 << VIRTIO_BLOCK_IRQ;
    }

    fn read_u16(&mut self, gpa: u64) -> Option<u16> {
        let mut bytes = [0; 2];
        self.read_guest(gpa, &mut bytes).then_some(u16::from_le_bytes(bytes))
    }

    fn read_u32(&mut self, gpa: u64) -> Option<u32> {
        let mut bytes = [0; 4];
        self.read_guest(gpa, &mut bytes).then_some(u32::from_le_bytes(bytes))
    }

    fn read_u64(&mut self, gpa: u64) -> Option<u64> {
        let mut bytes = [0; 8];
        self.read_guest(gpa, &mut bytes).then_some(u64::from_le_bytes(bytes))
    }

    fn write_u16(&mut self, gpa: u64, value: u16) -> bool {
        self.write_guest(gpa, &value.to_le_bytes())
    }

    fn write_u32(&mut self, gpa: u64, value: u32) -> bool {
        self.write_guest(gpa, &value.to_le_bytes())
    }
}

impl LinuxPlatform for VirtioGuestBus {
    fn read_guest(&mut self, mut gpa: u64, mut out: &mut [u8]) -> bool {
        while !out.is_empty() {
            let Some(frame) = vcpu::translate(self.pid, self.vcpu, gpa).ok().flatten() else {
                return false;
            };
            let offset = (gpa % 4096) as usize;
            let count = out.len().min(4096 - offset);
            let Some(mapped) = mm::phys_to_virt(frame.start() + offset as u64) else {
                return false;
            };
            // SAFETY: the vCPU mapping pins the frame and the copy is bounded to
            // the remaining bytes of that page.
            unsafe {
                core::ptr::copy_nonoverlapping(mapped as *const u8, out.as_mut_ptr(), count);
            }
            gpa += count as u64;
            out = &mut out[count..];
        }
        true
    }

    fn write_guest(&mut self, mut gpa: u64, mut bytes: &[u8]) -> bool {
        while !bytes.is_empty() {
            let Some(frame) = vcpu::translate(self.pid, self.vcpu, gpa).ok().flatten() else {
                return false;
            };
            let offset = (gpa % 4096) as usize;
            let count = bytes.len().min(4096 - offset);
            let Some(mapped) = mm::phys_to_virt(frame.start() + offset as u64) else {
                return false;
            };
            // SAFETY: same pinned-frame and page-bounded argument as `read_guest`.
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), mapped, count);
            }
            gpa += count as u64;
            bytes = &bytes[count..];
        }
        true
    }

    fn read_mmio(&mut self, gpa: u64, width: u8) -> Option<u64> {
        if (VIRTIO_RNG_BASE..VIRTIO_RNG_BASE + 0x1000).contains(&gpa) {
            return self.rng.read(gpa - VIRTIO_RNG_BASE, width).ok();
        }
        if (VIRTIO_CONSOLE_BASE..VIRTIO_CONSOLE_BASE + 0x1000).contains(&gpa) {
            let offset = gpa - VIRTIO_CONSOLE_BASE;
            return match (offset, width) {
                (0x100, 2) => Some(80),
                (0x102, 2) => Some(25),
                (0x104, 4) => Some(1),
                _ => self.console.read(offset, width).ok(),
            };
        }
        if (VIRTIO_BLOCK_BASE..VIRTIO_BLOCK_BASE + 0x1000).contains(&gpa) {
            let offset = gpa - VIRTIO_BLOCK_BASE;
            return match (offset, width) {
                (0x100, 8) => Some(8),
                (0x100, 4) => Some(8),
                (0x104, 4) => Some(0),
                _ => self.block.read(offset, width).ok(),
            };
        }
        if (VIRTIO_NET_BASE..VIRTIO_NET_BASE + 0x1000).contains(&gpa) {
            let offset = gpa - VIRTIO_NET_BASE;
            if let Some(config_offset) = offset.checked_sub(0x100) {
                if !matches!(width, 1 | 2 | 4 | 8)
                    || config_offset % u64::from(width) != 0
                    || config_offset + u64::from(width) > 8
                {
                    return None;
                }
                let mut config = [0u8; 8];
                config[..6].copy_from_slice(&self.net_backend.mac());
                config[6..8].copy_from_slice(&1u16.to_le_bytes());
                let start = config_offset as usize;
                let mut value = 0u64;
                for (index, byte) in config[start..start + width as usize]
                    .iter()
                    .enumerate()
                {
                    value |= u64::from(*byte) << (index * 8);
                }
                return Some(value);
            }
            return self.net.read(offset, width).ok();
        }
        if (VIRTIO_FS_BASE..VIRTIO_FS_BASE + 0x1000).contains(&gpa) {
            let offset = gpa - VIRTIO_FS_BASE;
            if let Some(config_offset) = offset.checked_sub(0x100) {
                if !matches!(width, 1 | 2 | 4 | 8)
                    || config_offset % u64::from(width) != 0
                    || config_offset + u64::from(width) > 40
                {
                    return None;
                }
                let mut config = [0u8; 40];
                config[..8].copy_from_slice(b"jasperfs");
                config[36..40].copy_from_slice(&1u32.to_le_bytes());
                let start = config_offset as usize;
                let mut value = 0u64;
                for (index, byte) in config[start..start + width as usize]
                    .iter()
                    .enumerate()
                {
                    value |= u64::from(*byte) << (index * 8);
                }
                return Some(value);
            }
            return self.fs.read(offset, width).ok();
        }
        None
    }

    fn write_mmio(&mut self, gpa: u64, width: u8, value: u64) -> bool {
        if (VIRTIO_RNG_BASE..VIRTIO_RNG_BASE + 0x1000).contains(&gpa) {
            let offset = gpa - VIRTIO_RNG_BASE;
            let Ok(event) = self.rng.write(offset, width, value) else {
                return false;
            };
            if offset == 0x070 && value == 0 {
                self.last_avail = [0; 2];
                self.pending_irqs &= !(1u16 << VIRTIO_RNG_IRQ);
            }
            if let Some(queue) = event.queue_notified {
                self.process_rng(queue);
            }
            return true;
        }
        if (VIRTIO_CONSOLE_BASE..VIRTIO_CONSOLE_BASE + 0x1000).contains(&gpa) {
            let offset = gpa - VIRTIO_CONSOLE_BASE;
            let Ok(event) = self.console.write(offset, width, value) else {
                return false;
            };
            if offset == 0x070 && value == 0 {
                self.console_last_avail = [0; 2];
                self.console_bytes = 0;
                self.pending_irqs &= !(1u16 << VIRTIO_CONSOLE_IRQ);
            }
            if let Some(queue) = event.queue_notified {
                self.process_console(queue);
            }
            return true;
        }
        if (VIRTIO_BLOCK_BASE..VIRTIO_BLOCK_BASE + 0x1000).contains(&gpa) {
            let offset = gpa - VIRTIO_BLOCK_BASE;
            let Ok(event) = self.block.write(offset, width, value) else {
                return false;
            };
            if offset == 0x070 && value == 0 {
                self.block_last_avail = 0;
                self.pending_irqs &= !(1u16 << VIRTIO_BLOCK_IRQ);
            }
            if let Some(queue) = event.queue_notified {
                self.process_block(queue);
            }
            return true;
        }
        if (VIRTIO_NET_BASE..VIRTIO_NET_BASE + 0x1000).contains(&gpa) {
            let offset = gpa - VIRTIO_NET_BASE;
            let Ok(event) = self.net.write(offset, width, value) else {
                return false;
            };
            if offset == 0x070 && value == 0 {
                self.net_backend.reset();
                self.net_rx_last_avail = 0;
                self.net_tx_last_avail = 0;
                self.pending_irqs &= !(1u16 << VIRTIO_NET_IRQ);
            }
            if let Some(queue) = event.queue_notified {
                match queue {
                    0 => self.process_net_rx(queue),
                    1 => self.process_net_tx(queue),
                    _ => return false,
                }
            }
            return true;
        }
        if (VIRTIO_FS_BASE..VIRTIO_FS_BASE + 0x1000).contains(&gpa) {
            let offset = gpa - VIRTIO_FS_BASE;
            let Ok(event) = self.fs.write(offset, width, value) else {
                return false;
            };
            if offset == 0x070 && value == 0 {
                self.fs_backend.reset();
                self.fs_last_avail = 0;
                self.pending_irqs &= !(1u16 << VIRTIO_FS_IRQ);
            }
            if let Some(queue) = event.queue_notified {
                self.process_fs(queue);
            }
            return true;
        }
        false
    }

    fn take_irq(&mut self) -> Option<u8> {
        if self.pending_irqs == 0 {
            return None;
        }
        let irq = self.pending_irqs.trailing_zeros() as u8;
        self.pending_irqs &= !(1u16 << irq);
        Some(irq)
    }

    fn return_irq(&mut self, irq: u8) {
        if irq < 8 {
            self.pending_irqs |= 1u16 << irq;
        }
    }
}

pub fn run() -> bool {
    run_impl(false)
}

#[cfg(feature = "hwv5-verify")]
pub fn run_virtio() -> bool {
    run_impl(true)
}

fn run_impl(virtio_rng: bool) -> bool {
    let before = crate::baseline::baseline();
    let heap_before = crate::mm::heap::stats().3 as usize / 4096;
    let pid = match proc::create("hwv4-linux", crate::syscall::SyscallSet::EMPTY) {
        Ok(pid) => pid,
        Err(_) => {
            kprintln!("[JSR-HWV4-LINUX-FAIL] process_create");
            return false;
        }
    };
    let memory = match proc::create_guest_memory(pid, GUEST_FRAMES) {
        Ok(handle) => handle,
        Err(_) => return cleanup(pid, None, None, before, "guest_memory"),
    };
    let vcpu_handle = match vcpu::create_for(pid, Backend::Vmx) {
        Ok(handle) => handle,
        Err(_) => return cleanup(pid, None, Some(memory), before, "vcpu_create"),
    };
    if vcpu::map_for(
        pid,
        vcpu_handle,
        memory,
        vcpu::MapRequest {
            guest_start: 0,
            pages: GUEST_FRAMES,
            memory_offset: 0,
            permissions: GuestPermissions::ALL,
        },
    )
    .is_err()
    {
        return cleanup(pid, Some(vcpu_handle), Some(memory), before, "ept_map");
    }
    if prepare(pid, vcpu_handle, virtio_rng).is_err() {
        return cleanup(
            pid,
            Some(vcpu_handle),
            Some(memory),
            before,
            "boot_protocol",
        );
    }

    let mut state = VcpuState::initial();
    state.cr0 = 0x8001_0011;
    state.cr3 = PAGE_TABLE_ROOT;
    state.cr4 = 0x20;
    state.xcr0 = 1;
    state.rip = KERNEL_BASE + 0x200;
    state.rflags = 2;
    state.registers[6] = BOOT_PARAMS;
    if vcpu::save_state_for(pid, vcpu_handle, state).is_err()
        || vcpu::make_ready_for(pid, vcpu_handle).is_err()
    {
        return cleanup(pid, Some(vcpu_handle), Some(memory), before, "vcpu_state");
    }
    let ept_root = match vcpu::view(pid, vcpu_handle) {
        Ok(view) => view.table_root,
        Err(_) => return cleanup(pid, Some(vcpu_handle), Some(memory), before, "vcpu_view"),
    };
    let execution = GuestExecutionState {
        state,
        rsp: GUEST_STACK,
        cr3_gpa: PAGE_TABLE_ROOT,
        efer: 0x500,
        tsc_offset: -1000,
    };
    let mut vm = match VmxVm::new_linux(ept_root, execution) {
        Ok(vm) => vm,
        Err(error) => {
            kprintln!(
                "[JSR-HWV4-LINUX-FAIL] vmx_setup={:?} name={}",
                error,
                error.name()
            );
            return cleanup(pid, Some(vcpu_handle), Some(memory), before, "vmx_setup");
        }
    };
    if vcpu::begin_run_for(pid, vcpu_handle).is_err() {
        let _ = vm.shutdown();
        drop(vm);
        return cleanup(pid, Some(vcpu_handle), Some(memory), before, "begin_run");
    }
    let mut devices = VirtioGuestBus::new(pid, vcpu_handle);
    let report: LinuxReport = match if virtio_rng {
        vm.run_linux_with(&mut devices)
    } else {
        vm.run_linux()
    } {
        Ok(report) => report,
        Err(error) => {
            vcpu::fail_run_for(pid, vcpu_handle);
            kprintln!(
                "[JSR-HWV4-LINUX-FAIL] vmx_run={:?} name={}",
                error,
                error.name()
            );
            let _ = vm.shutdown();
            drop(vm);
            return cleanup(pid, Some(vcpu_handle), Some(memory), before, "vmx_run");
        }
    };
    let final_state = vm.guest_state();
    let lifecycle = vcpu::finish_run_for(pid, vcpu_handle, final_state).is_ok();
    let shutdown = vm.shutdown().is_ok();
    drop(vm);
    let _ = proc::close_handle_for(pid, vcpu_handle);
    let _ = proc::close_handle_for(pid, memory);
    let _ = proc::exit_idle(pid, 0);
    let _ = proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
    let after = crate::baseline::baseline();
    let heap_after = crate::mm::heap::stats().3 as usize / 4096;
    let reclaimed = before.objects == after.objects
        && before.pending == after.pending
        && before.pins == after.pins
        && before.free_frames + heap_before == after.free_frames + heap_after;
    if !reclaimed {
        kprintln!(
            "[JSR-HWV4-LINUX-DBG] baseline before={:?} after={:?}",
            before,
            after
        );
    }
    let net_ok = !virtio_rng
        || (devices.net_backend.tx_frames() != 0
            && devices.net_backend.rx_frames() != 0
            && devices.net_tx_frames != 0
            && devices.net_rx_frames != 0
            && devices.net_rejected == 0);
    let virtio_ok = !virtio_rng
        || (devices.rng_requests != 0
            && devices.console_bytes != 0
            && devices.block_requests != 0
            && net_ok
            && report.pio_marker
            && report.pio_reads != 0
            && report.pio_writes != 0
            && report.pio_probe_generation == 2
            && report.pio_requests == 1
            && report.pio_cancels == 1);
    let ok = report.marker && report.halted && lifecycle && shutdown && reclaimed && virtio_ok;
    kprintln!(
        "[JSR-HWV4-LINUX] linux=true exits={} serial_bytes={} timer_interrupts={} timer_eois={} virtio_rng_requests={} virtio_console_bytes={} virtio_block_requests={} virtio_net_tx_frames={} virtio_net_rx_frames={} virtio_net_backend_tx={} virtio_net_backend_rx={} virtio_net_reset_generation={} virtio_net_rejected={} virtio_fs_requests={} virtio_fs_rejected={} virtio_fs_handles={} virtio_fs_reset_generation={} pio_reads={} pio_writes={} pio_generation={} pio_requests={} pio_cancels={} pio_marker={} marker={} halted={} lifecycle={} shutdown={} reclaim={}",
        report.exits,
        report.serial_bytes,
        report.timer_interrupts,
        report.timer_eois,
        devices.rng_requests,
        devices.console_bytes,
        devices.block_requests,
        devices.net_tx_frames,
        devices.net_rx_frames,
        devices.net_backend.tx_frames(),
        devices.net_backend.rx_frames(),
        devices.net_backend.reset_generation(),
        devices.net_rejected,
        devices.fs_requests,
        devices.fs_rejected,
        devices.fs_backend.handle_count(),
        devices.fs_backend.generation(),
        report.pio_reads,
        report.pio_writes,
        report.pio_probe_generation,
        report.pio_requests,
        report.pio_cancels,
        report.pio_marker,
        report.marker,
        report.halted,
        lifecycle,
        shutdown,
        reclaimed
    );
    ok
}

fn cleanup(
    pid: kernel_core::objtable::ObjId,
    vcpu_handle: Option<kernel_core::object::HandleId>,
    memory: Option<kernel_core::object::HandleId>,
    before: crate::baseline::Baseline,
    reason: &'static str,
) -> bool {
    if let Some(handle) = vcpu_handle {
        let _ = proc::close_handle_for(pid, handle);
    }
    if let Some(handle) = memory {
        let _ = proc::close_handle_for(pid, handle);
    }
    let _ = proc::exit_idle(pid, 0);
    let _ = proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
    let reclaimed = before == crate::baseline::baseline();
    kprintln!(
        "[JSR-HWV4-LINUX-FAIL] reason={} reclaim={}",
        reason,
        reclaimed
    );
    false
}

fn prepare(
    pid: kernel_core::objtable::ObjId,
    handle: kernel_core::object::HandleId,
    virtio_rng: bool,
) -> Result<(), ()> {
    if LINUX_SETUP.len() < 0x1000
        || LINUX_KERNEL.is_empty()
        || LINUX_KERNEL.len() as u64 > GUEST_RAM - KERNEL_BASE
    {
        return Err(());
    }
    if &LINUX_SETUP[0x202..0x206] != b"HdrS" {
        return Err(());
    }
    let init_size = read_u32(LINUX_SETUP, 0x260)? as u64;
    if init_size == 0 || init_size > GUEST_RAM - KERNEL_BASE {
        return Err(());
    }
    let alignment = read_u32(LINUX_SETUP, 0x230)? as u64;
    if alignment == 0 || KERNEL_BASE % alignment != 0 {
        return Err(());
    }

    write_u64(pid, handle, 0x1000, 0x2003);
    write_u64(pid, handle, 0x2000, 0x3003);
    for index in 0..PAGE_ENTRIES {
        write_u64(pid, handle, 0x3000 + index * 8, index * PAGE_2M | 0x83);
    }

    write_bytes(pid, handle, BOOT_PARAMS + 0x1f1, &LINUX_SETUP[0x1f1..0x290])?;
    write_u32(pid, handle, BOOT_PARAMS + 0x0c8, 0);
    if virtio_rng {
        write_bytes(
            pid,
            handle,
            COMMAND_LINE,
            b"earlyprintk=serial earlycon=uart,io,0x3f8,115200 keep_bootcon ignore_loglevel loglevel=7 nokaslr no_timer_check lpj=1000000 panic=-1 init=/init io_delay=none initcall_blacklist=serial8250_init virtio_mmio.device=0x200@0xd0000000:5 virtio_mmio.device=0x200@0xd0001000:6 virtio_mmio.device=0x200@0xd0002000:3 virtio_mmio.device=0x200@0xd0003000:10 virtio_mmio.device=0x200@0xd0004000:11\0",
        )?;
    } else {
        write_bytes(
            pid,
            handle,
            COMMAND_LINE,
            b"earlyprintk=serial earlycon=uart,io,0x3f8,115200 keep_bootcon ignore_loglevel loglevel=7 nokaslr no_timer_check lpj=1000000 panic=-1 init=/init io_delay=none initcall_blacklist=serial8250_init\0",
        )?;
    }
    write_u32(pid, handle, BOOT_PARAMS + 0x228, COMMAND_LINE as u32);
    write_u32(
        pid,
        handle,
        BOOT_PARAMS + 0x1e0,
        (LINUX_USABLE_RAM / 1024) as u32,
    );
    write_u8(pid, handle, BOOT_PARAMS + 0x1e8, 1);
    write_u8(pid, handle, BOOT_PARAMS + 0x210, 0xff);
    let loadflags = read_u8(LINUX_SETUP, 0x211)? | 1;
    write_u8(pid, handle, BOOT_PARAMS + 0x211, loadflags & !2);
    write_u32(pid, handle, BOOT_PARAMS + 0x214, KERNEL_BASE as u32);
    write_u32(pid, handle, BOOT_PARAMS + 0x218, 0);
    write_u32(pid, handle, BOOT_PARAMS + 0x21c, 0);

    write_u64(pid, handle, BOOT_PARAMS + 0x2d0, 0);
    write_u64(pid, handle, BOOT_PARAMS + 0x2d8, LINUX_USABLE_RAM);
    write_u32(pid, handle, BOOT_PARAMS + 0x2e0, 1);

    write_bytes(pid, handle, KERNEL_BASE, LINUX_KERNEL)
}

fn read_u8(bytes: &[u8], offset: usize) -> Result<u8, ()> {
    bytes.get(offset).copied().ok_or(())
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ()> {
    let raw = bytes.get(offset..offset + 4).ok_or(())?;
    Ok(u32::from_le_bytes(raw.try_into().map_err(|_| ())?))
}

fn write_u8(
    pid: kernel_core::objtable::ObjId,
    handle: kernel_core::object::HandleId,
    gpa: u64,
    value: u8,
) {
    let _ = write_bytes(pid, handle, gpa, &[value]);
}

fn write_u32(
    pid: kernel_core::objtable::ObjId,
    handle: kernel_core::object::HandleId,
    gpa: u64,
    value: u32,
) {
    let _ = write_bytes(pid, handle, gpa, &value.to_le_bytes());
}

fn write_u64(
    pid: kernel_core::objtable::ObjId,
    handle: kernel_core::object::HandleId,
    gpa: u64,
    value: u64,
) {
    let _ = write_bytes(pid, handle, gpa, &value.to_le_bytes());
}

fn write_bytes(
    pid: kernel_core::objtable::ObjId,
    handle: kernel_core::object::HandleId,
    mut gpa: u64,
    mut bytes: &[u8],
) -> Result<(), ()> {
    while !bytes.is_empty() {
        let frame: PhysFrame = vcpu::translate(pid, handle, gpa)
            .map_err(|_| ())?
            .ok_or(())?;
        let offset = (gpa % 4096) as usize;
        let count = bytes.len().min(4096 - offset);
        let mapped = mm::phys_to_virt(frame.start() + offset as u64).ok_or(())?;
        // SAFETY: the guest mapping pins the frame, and the copy is bounded to
        // the remainder of that page.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), mapped, count);
        }
        gpa += count as u64;
        bytes = &bytes[count..];
    }
    Ok(())
}
