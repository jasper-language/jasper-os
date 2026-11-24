//! Independent native Info Service process.
//! 独立原生 Info Service 进程。

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use jasper_rt::channel::Channel;
use jasper_rt::handle::Handle;
use jasper_rt::{entry, ids, sys, time};
use kernel_core::service_info::{self, Operation, Request, Response, Status};
use kernel_core::usi;

entry!(main);

#[derive(Clone, Copy)]
struct CacheEntry {
    request: Request,
    response: Response,
    order: u64,
}

struct ReplyCache<const N: usize> {
    entries: [Option<CacheEntry>; N],
    next_order: u64,
}

impl<const N: usize> ReplyCache<N> {
    const fn new() -> Self {
        Self {
            entries: [None; N],
            next_order: 0,
        }
    }

    fn find(&self, request: Request) -> Option<CacheEntry> {
        self.entries
            .iter()
            .flatten()
            .find(|entry| entry.request.request_id == request.request_id)
            .copied()
    }

    fn complete(&mut self, request: Request, response: Response) {
        self.next_order = self.next_order.wrapping_add(1).max(1);
        let slot = self
            .entries
            .iter()
            .position(Option::is_none)
            .or_else(|| {
                self.entries
                    .iter()
                    .enumerate()
                    .filter_map(|(index, entry)| {
                        entry.as_ref().map(|entry| (index, entry.order))
                    })
                    .min_by_key(|(_, order)| *order)
                    .map(|(index, _)| index)
            });
        if let Some(slot) = slot {
            self.entries[slot] = Some(CacheEntry {
                request,
                response,
                order: self.next_order,
            });
        }
    }
}

fn query(id: u64, service: usi::Service, request_id: u64) -> Result<Vec<u8>, i64> {
    let mut capacity = 256usize;
    loop {
        let mut buffer = vec![0u8; capacity];
        // SAFETY: the kernel validates the complete caller buffer before writing.
        let result = unsafe {
            sys::call3(
                id,
                request_id,
                buffer.as_mut_ptr() as u64,
                buffer.len() as u64,
            )
        };
        if result < 0 {
            return Err(result);
        }
        let required = result as usize;
        if required > buffer.len() {
            capacity = required;
            continue;
        }
        buffer.truncate(required);
        if buffer.len() < usi::HEADER_BYTES {
            return Err(-(ids::SYSTEM_USI_ERROR_SCHEMA as i64));
        }
        let mut raw = [0u8; usi::HEADER_BYTES];
        raw.copy_from_slice(&buffer[..usi::HEADER_BYTES]);
        let Some(header) = usi::Header::decode(&raw) else {
            return Err(-(ids::SYSTEM_USI_ERROR_SCHEMA as i64));
        };
        if header.service != service || header.request_id != request_id {
            return Err(-(ids::SYSTEM_USI_ERROR_REQUEST_ID as i64));
        }
        return Ok(buffer[usi::HEADER_BYTES..].to_vec());
    }
}

fn abi() -> Result<u64, Status> {
    // SAFETY: `system.abi.get` has no user-memory arguments.
    let value = unsafe { sys::call3(ids::SYSTEM_ABI_GET, 0, 0, 0) };
    (value > 0)
        .then_some(value as u64)
        .ok_or(Status::Unauthorized)
}

fn snapshot(request: Request, generation: u64) -> Response {
    let Ok(abi) = abi() else {
        return Response::error(request, Status::Unauthorized, generation).unwrap();
    };
    let processes = query(
        ids::SYSTEM_PROCESS_LIST,
        usi::Service::ProcessList,
        request.request_id,
    )
    .and_then(|payload| {
        (payload.len() % usi::PROCESS_BYTES == 0)
            .then_some((payload.len() / usi::PROCESS_BYTES) as u16)
            .ok_or(-(ids::SYSTEM_USI_ERROR_SCHEMA as i64))
    });
    let modules = query(
        ids::SYSTEM_MODULE_LIST,
        usi::Service::ModuleList,
        request.request_id.wrapping_add(1).max(1),
    )
    .and_then(|payload| {
        (payload.len() % usi::MODULE_BYTES == 0)
            .then_some((payload.len() / usi::MODULE_BYTES) as u16)
            .ok_or(-(ids::SYSTEM_USI_ERROR_SCHEMA as i64))
    });
    match (processes, modules) {
        (Ok(processes), Ok(modules)) => {
            Response::snapshot(request, abi, generation, processes, modules)
        }
        _ => Response::error(request, Status::Unauthorized, generation).unwrap(),
    }
}

fn dispatch(request: Request, generation: u64) -> Response {
    if request.deadline_tick != 0 && time::now() > request.deadline_tick {
        return Response::error(request, Status::TimedOut, generation).unwrap();
    }
    match request.operation {
        Operation::Describe => abi()
            .map(|value| Response::describe(request, value, generation))
            .unwrap_or_else(|status| Response::error(request, status, generation).unwrap()),
        Operation::Snapshot => snapshot(request, generation),
    }
}

fn protocol_error(bytes: &[u8]) -> Option<Response> {
    let request_id = u64::from_le_bytes(bytes.get(16..24)?.try_into().ok()?);
    if request_id == 0 {
        return None;
    }
    let operation = match *bytes.get(8)? {
        1 => Operation::Describe,
        2 => Operation::Snapshot,
        _ => return None,
    };
    Response::error(
        Request {
            request_id,
            deadline_tick: 0,
            operation,
        },
        Status::Protocol,
        1,
    )
}

fn main(channel_raw: u64, generation: u64) -> i32 {
    // SAFETY: process.spawn transfers one fresh bootstrap Channel endpoint.
    let channel = Channel::from_handle(unsafe { Handle::from_raw(channel_raw) });
    let generation = generation.max(1);
    let mut cache = ReplyCache::<16>::new();
    loop {
        let mut bytes = [0u8; service_info::REQUEST_BYTES];
        let received = match channel.recv(&mut bytes) {
            Ok(received) => received,
            Err(_) => return 0,
        };
        if !received.handles.is_empty() || received.sender_app == 0 || received.len != bytes.len() {
            if let Some(response) = protocol_error(&bytes) {
                let _ = channel.send(&response.encode());
            }
            continue;
        }
        let Some(request) = Request::decode(&bytes) else {
            if let Some(response) = protocol_error(&bytes) {
                let _ = channel.send(&response.encode());
            }
            continue;
        };
        if let Some(cached) = cache.find(request) {
            let response = if cached.request.operation == request.operation {
                cached.response
            } else {
                Response::error(request, Status::Protocol, generation).unwrap()
            };
            let _ = channel.send(&response.encode());
            continue;
        }
        let response = dispatch(request, generation);
        cache.complete(request, response);
        if channel.send(&response.encode()).is_err() {
            return 0;
        }
    }
}
