//! Independent native Time Service process.
//! 独立原生 Time Service 进程。

#![no_std]
#![no_main]

use jasper_rt::channel::Channel;
use jasper_rt::handle::Handle;
use jasper_rt::{entry, ids, sys, time};
use kernel_core::service_time::{self, Operation, Request, Response, Status};
use kernel_core::time128::Time128;

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

fn abi() -> Option<u64> {
    // SAFETY: `system.abi.get` has no user-memory arguments.
    let value = unsafe { sys::call3(ids::SYSTEM_ABI_GET, 0, 0, 0) };
    (value > 0).then_some(value as u64)
}

fn dispatch(
    request: Request,
    generation: u64,
    next_sample: &mut u64,
) -> Response {
    if request.deadline_ns != 0 {
        match time::monotonic_ns() {
            Ok(now) if now <= request.deadline_ns => {}
            Ok(_) => return Response::error(request, Status::TimedOut, generation).unwrap(),
            Err(_) => {
                return Response::error(request, Status::Unauthorized, generation).unwrap()
            }
        }
    }
    let Some(abi) = abi() else {
        return Response::error(request, Status::Unauthorized, generation).unwrap();
    };
    match request.operation {
        Operation::Describe => Response::describe(request, abi, generation),
        Operation::Sample => {
            let monotonic_ns = match time::monotonic_ns() {
                Ok(value) => value,
                Err(_) => {
                    return Response::error(request, Status::Unauthorized, generation).unwrap()
                }
            };
            let Ok(time128) = Time128::from_nanos(i128::from(monotonic_ns)) else {
                return Response::error(request, Status::FactUnavailable, generation).unwrap();
            };
            *next_sample = next_sample.wrapping_add(1).max(1);
            Response::sample(
                request,
                abi,
                generation,
                *next_sample,
                monotonic_ns,
                time128,
            )
        }
    }
}

fn protocol_error(bytes: &[u8], generation: u64) -> Option<Response> {
    let request_id = u64::from_le_bytes(bytes.get(16..24)?.try_into().ok()?);
    if request_id == 0 {
        return None;
    }
    let operation = match *bytes.get(8)? {
        1 => Operation::Describe,
        2 => Operation::Sample,
        _ => return None,
    };
    Response::error(
        Request {
            request_id,
            deadline_ns: 0,
            operation,
        },
        Status::Protocol,
        generation,
    )
}

fn main(channel_raw: u64, generation: u64) -> i32 {
    // SAFETY: process.spawn transfers one fresh bootstrap Channel endpoint.
    let channel = Channel::from_handle(unsafe { Handle::from_raw(channel_raw) });
    let generation = generation.max(1);
    let mut cache = ReplyCache::<16>::new();
    let mut next_sample = 0u64;
    loop {
        let mut bytes = [0u8; service_time::REQUEST_BYTES];
        let received = match channel.recv(&mut bytes) {
            Ok(received) => received,
            Err(_) => return 0,
        };
        if !received.handles.is_empty() || received.sender_app == 0 || received.len != bytes.len() {
            if let Some(response) = protocol_error(&bytes, generation) {
                let _ = channel.send(&response.encode());
            }
            continue;
        }
        let Some(request) = Request::decode(&bytes) else {
            if let Some(response) = protocol_error(&bytes, generation) {
                let _ = channel.send(&response.encode());
            }
            continue;
        };
        if let Some(cached) = cache.find(request) {
            let response = if cached.request == request {
                cached.response
            } else {
                Response::error(request, Status::Protocol, generation).unwrap()
            };
            let _ = channel.send(&response.encode());
            continue;
        }
        let response = dispatch(request, generation, &mut next_sample);
        cache.complete(request, response);
        if channel.send(&response.encode()).is_err() {
            return 0;
        }
    }
}
