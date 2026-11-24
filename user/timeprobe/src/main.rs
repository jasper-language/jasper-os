//! End-to-end probe for the independently deployed `service.time` process.
//! 独立部署 `service.time` 进程的端到端验收。

#![no_std]
#![no_main]

use jasper_rt::channel::Channel;
use jasper_rt::process::{self, CallSet};
use jasper_rt::{entry, ids, println, time};
use kernel_core::service_time::{self, Operation, Request, Response, Status};
use kernel_core::time128::Time128;

entry!(main);

static TIMED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/timed.elf"));

fn service_calls(allow_facts: bool) -> Option<CallSet> {
    let mut calls = CallSet::try_from_ids(&[
        ids::SYSTEM_CONSOLE_WRITE,
        ids::SYSTEM_MEMORY_MAP,
        ids::SYSTEM_PROCESS_EXIT,
        ids::SYSTEM_CHANNEL_SEND,
        ids::SYSTEM_CHANNEL_RECV,
    ])
    .ok()?;
    if allow_facts {
        for id in [ids::SYSTEM_ABI_GET, ids::SYSTEM_TIME_DEADLINE_GET] {
            calls.try_insert(id).ok()?;
        }
    }
    Some(calls)
}

fn exchange(channel: &Channel, request: Request) -> Option<Response> {
    channel.send(&request.encode()).ok()?;
    let mut bytes = [0u8; service_time::RESPONSE_BYTES];
    let received = channel.recv(&mut bytes).ok()?;
    if received.len != bytes.len() || !received.handles.is_empty() {
        return None;
    }
    let response = Response::decode(&bytes)?;
    (response.request_id == request.request_id).then_some(response)
}

fn spawn(calls: CallSet, generation: u64) -> Option<process::Child> {
    process::spawn(process::Spec {
        image: TIMED,
        calls,
        arg: generation,
        cpu_limit_permille: None,
    })
    .ok()
}

fn sample_request(request_id: u64) -> Request {
    Request {
        request_id,
        deadline_ns: time::monotonic_ns()
            .unwrap_or(0)
            .saturating_add(1_000_000_000),
        operation: Operation::Sample,
    }
}

fn main(_: u64, _: u64) -> i32 {
    let Some(calls) = service_calls(true) else {
        println!("[JSR-SERVICE-TIME] failed=calls");
        return 1;
    };
    let Some(child) = spawn(calls, 1) else {
        println!("[JSR-SERVICE-TIME] failed=spawn");
        return 2;
    };
    let first_process = child.process;
    let channel = child.channel;
    let describe = exchange(
        &channel,
        Request {
            request_id: 1,
            deadline_ns: 0,
            operation: Operation::Describe,
        },
    );
    let request = sample_request(2);
    let sample = exchange(&channel, request);
    let replay = exchange(&channel, request);
    let expired = exchange(
        &channel,
        Request {
            request_id: 3,
            deadline_ns: 1,
            operation: Operation::Sample,
        },
    );
    let mut malformed = request.encode();
    malformed[4] = 99;
    let protocol = channel.send(&malformed).ok().and_then(|_| {
        let mut bytes = [0u8; service_time::RESPONSE_BYTES];
        let received = channel.recv(&mut bytes).ok()?;
        (received.len == bytes.len()).then_some(Response::decode(&bytes)?)
    });
    let conflict = exchange(
        &channel,
        Request {
            request_id: 2,
            deadline_ns: 0,
            operation: Operation::Describe,
        },
    );

    let describe_ok = describe.is_some_and(|response| {
        response.status == Status::Ok
            && response.operation == Operation::Describe
            && response.abi != 0
            && response.flags == service_time::DESCRIBE_FLAGS
    });
    let sample_ok = sample.is_some_and(|response| {
        response.status == Status::Ok
            && response.operation == Operation::Sample
            && response.monotonic_ns != 0
            && response.sample_sequence == 1
            && response.flags
                == (service_time::FLAG_MONOTONIC | service_time::FLAG_TIME128)
            && response.time128.to_nanos() == i128::from(response.monotonic_ns)
    });
    let replay_ok = replay == sample;
    let deadline_ok = expired.is_some_and(|response| response.status == Status::TimedOut);
    let protocol_ok = protocol.is_some_and(|response| response.status == Status::Protocol);
    let conflict_ok = conflict.is_some_and(|response| response.status == Status::Protocol);
    let first_ns = sample.map_or(0, |response| response.monotonic_ns);

    drop(channel);
    let _ = jasper_rt::task::wait_process(&first_process).ok();
    drop(first_process);

    let restarted = spawn(service_calls(true).unwrap(), 2).is_some_and(|child| {
        let request = sample_request(10);
        let ok = exchange(&child.channel, request).is_some_and(|response| {
            response.status == Status::Ok
                && response.service_generation == 2
                && response.sample_sequence == 1
                && response.monotonic_ns >= first_ns
                && response.time128 == Time128::from_nanos(i128::from(response.monotonic_ns)).unwrap()
        });
        drop(child.channel);
        let _ = jasper_rt::task::wait_process(&child.process).ok();
        drop(child.process);
        ok
    });

    let denied = spawn(service_calls(false).unwrap(), 1).is_some_and(|child| {
        let ok = exchange(&child.channel, sample_request(20))
            .is_some_and(|response| response.status == Status::Unauthorized);
        drop(child.channel);
        let _ = jasper_rt::task::wait_process(&child.process).ok();
        drop(child.process);
        ok
    });

    let ok = describe_ok
        && sample_ok
        && replay_ok
        && deadline_ok
        && protocol_ok
        && conflict_ok
        && restarted
        && denied;
    println!(
        "[JSR-SERVICE-TIME] describe={} sample={} replay={} deadline={} protocol={} conflict={} restart={} denied_capability={} time64_time128_coherent={} ok={}",
        describe_ok,
        sample_ok,
        replay_ok,
        deadline_ok,
        protocol_ok,
        conflict_ok,
        restarted,
        denied,
        sample_ok,
        ok
    );
    if ok {
        0
    } else {
        5
    }
}
