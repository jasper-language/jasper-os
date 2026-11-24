//! End-to-end probe for the independently deployed `service.info` process.
//! 独立部署的 `service.info` 进程端到端验收。

#![no_std]
#![no_main]

extern crate alloc;

use jasper_rt::channel::Channel;
use jasper_rt::process::{self, CallSet};
use jasper_rt::{entry, ids, println, time};
use kernel_core::service_info::{Operation, Request, Response, Status};

entry!(main);

static INFOD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/infod.elf"));

fn service_calls(allow_facts: bool) -> Option<CallSet> {
    let mut calls = CallSet::try_from_ids(&[
        ids::SYSTEM_CONSOLE_WRITE,
        ids::SYSTEM_MEMORY_MAP,
        ids::SYSTEM_PROCESS_EXIT,
        ids::SYSTEM_CHANNEL_SEND,
        ids::SYSTEM_CHANNEL_RECV,
        ids::SYSTEM_TIME_NOW,
    ])
    .ok()?;
    if allow_facts {
        for id in [
            ids::SYSTEM_ABI_GET,
            ids::SYSTEM_PROCESS_LIST,
            ids::SYSTEM_MODULE_LIST,
        ] {
            calls.try_insert(id).ok()?;
        }
    }
    Some(calls)
}

fn exchange(channel: &Channel, request: Request) -> Option<Response> {
    channel.send(&request.encode()).ok()?;
    let mut bytes = [0u8; kernel_core::service_info::RESPONSE_BYTES];
    let received = channel.recv(&mut bytes).ok()?;
    if received.len != bytes.len() || !received.handles.is_empty() {
        return None;
    }
    let response = Response::decode(&bytes)?;
    (response.request_id == request.request_id).then_some(response)
}

fn spawn(calls: CallSet, generation: u64) -> Option<process::Child> {
    process::spawn(process::Spec {
        image: INFOD,
        calls,
        arg: generation,
        cpu_limit_permille: None,
    })
    .ok()
}

fn main(_: u64, _: u64) -> i32 {
    let Some(calls) = service_calls(true) else {
        println!("[JSR-SERVICE-INFO] failed=calls");
        return 1;
    };
    let Some(child) = spawn(calls, 1) else {
        println!("[JSR-SERVICE-INFO] failed=spawn");
        return 2;
    };
    let first_process = child.process;
    let channel = child.channel;
    let describe = exchange(
        &channel,
        Request {
            request_id: 1,
            deadline_tick: 0,
            operation: Operation::Describe,
        },
    );
    let snapshot_request = Request {
        request_id: 2,
        deadline_tick: time::now().saturating_add(1000),
        operation: Operation::Snapshot,
    };
    let snapshot = exchange(&channel, snapshot_request);
    let replay = exchange(&channel, snapshot_request);
    let expired = exchange(
        &channel,
        Request {
            request_id: 3,
            deadline_tick: 1,
            operation: Operation::Snapshot,
        },
    );
    let mut malformed = snapshot_request.encode();
    malformed[4] = 99;
    let protocol = channel.send(&malformed).ok().and_then(|_| {
        let mut bytes = [0u8; kernel_core::service_info::RESPONSE_BYTES];
        let received = channel.recv(&mut bytes).ok()?;
        (received.len == bytes.len()).then_some(Response::decode(&bytes)?)
    });
    let conflict = exchange(
        &channel,
        Request {
            request_id: 2,
            deadline_tick: 0,
            operation: Operation::Describe,
        },
    );
    let conflict_status = conflict.map_or(255, |response| response.status as u8);

    let describe_ok = describe.is_some_and(|response| {
        response.status == Status::Ok
            && response.operation == Operation::Describe
            && response.capabilities == 0b11
    });
    let snapshot_ok = snapshot.is_some_and(|response| {
        response.status == Status::Ok
            && response.operation == Operation::Snapshot
            && response.processes >= 1
            && response.modules >= 1
    });
    let replay_ok = replay == snapshot;
    let deadline_ok = expired.is_some_and(|response| response.status == Status::TimedOut);
    let protocol_ok = protocol.is_some_and(|response| response.status == Status::Protocol);
    let conflict_ok = conflict.is_some_and(|response| response.status == Status::Protocol);

    drop(channel);
    let _ = jasper_rt::task::wait_process(&first_process).ok();
    drop(first_process);

    let restarted = spawn(service_calls(true).unwrap(), 2).is_some_and(|child| {
        let ok = exchange(
            &child.channel,
            Request {
                request_id: 10,
                deadline_tick: 0,
                operation: Operation::Snapshot,
            },
        )
        .is_some_and(|response| {
            response.status == Status::Ok
                && response.service_generation == 2
                && response.processes >= 1
        });
        drop(child.channel);
        let _ = jasper_rt::task::wait_process(&child.process).ok();
        drop(child.process);
        ok
    });

    let denied = spawn(service_calls(false).unwrap(), 1).is_some_and(|child| {
        let ok = exchange(
            &child.channel,
            Request {
                request_id: 20,
                deadline_tick: 0,
                operation: Operation::Snapshot,
            },
        )
        .is_some_and(|response| response.status == Status::Unauthorized);
        drop(child.channel);
        let _ = jasper_rt::task::wait_process(&child.process).ok();
        drop(child.process);
        ok
    });

    let ok = describe_ok
        && snapshot_ok
        && replay_ok
        && deadline_ok
        && protocol_ok
        && conflict_ok
        && restarted
        && denied;
    println!(
        "[JSR-SERVICE-INFO] describe={} snapshot={} replay={} deadline={} protocol={} conflict={} conflict_status={} restart={} denied_capability={} ok={}",
        describe_ok,
        snapshot_ok,
        replay_ok,
        deadline_ok,
        protocol_ok,
        conflict_ok,
        conflict_status,
        restarted,
        denied,
        ok
    );
    if ok {
        0
    } else {
        5
    }
}
