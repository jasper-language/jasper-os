//! End-to-end external structured update Agent acceptance.

#![no_std]
#![no_main]

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use jasper_rt::process::{self, CallSet};
use jasper_rt::update::AgentChannelTransport;
use jasper_rt::{entry, ids, println, task, time};
use kernel_core::native_install_abi::UpdateListRequest;
use kernel_core::update_agent::{UpdateAgent, ACTION_JSON_BYTES, STATUS_JSON_BYTES};
use kernel_core::update_agent_ipc::{AgentOperation, AgentRequest};
use kernel_core::update_list_agent::{UpdateListAgent, LIST_JSON_BYTES};
use kernel_core::update_service::{StatusRequest, REQUEST_BYTES, SCOPE_PLATFORM};

entry!(main);

static AGENT_DAEMON: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/updateagentd.elf"));
const STRESS_WORKERS: usize = 4;
const STRESS_ROUNDS: u64 = 6;
static STRESS_READY: AtomicUsize = AtomicUsize::new(0);
static STRESS_GO: AtomicBool = AtomicBool::new(false);

fn broker_calls() -> Option<CallSet> {
    CallSet::try_from_ids(&[
        ids::SYSTEM_CONSOLE_WRITE,
        ids::SYSTEM_TASK_EXIT,
        ids::SYSTEM_PROCESS_EXIT,
        ids::SYSTEM_TASK_YIELD,
        ids::SYSTEM_CHANNEL_SEND,
        ids::SYSTEM_CHANNEL_RECV,
        ids::SYSTEM_MEMORY_MAP,
        ids::SYSTEM_MEMORY_UNMAP,
        ids::SYSTEM_MEMORY_PROTECT,
        ids::SYSTEM_HANDLE_CLOSE,
        ids::SYSTEM_TIME_NOW,
        ids::SYSTEM_UPDATE_STATUS_QUERY,
        ids::SYSTEM_UPDATE_ACTION_RECOVER,
        ids::SYSTEM_UPDATE_ACTION_ARCHIVE,
        ids::SYSTEM_INSTALL_UPDATE_LIST,
    ])
    .ok()
}

fn concurrent_worker(worker: usize, channel: jasper_rt::channel::Channel) -> u64 {
    let mut transport = AgentChannelTransport::new(channel, 500);
    let mut failed = 0u64;
    STRESS_READY.fetch_add(1, Ordering::Release);
    while !STRESS_GO.load(Ordering::Acquire) {
        task::yield_now();
    }

    for round in 0..STRESS_ROUNDS {
        // Every broker runs in its own process, so identical service request IDs
        // must remain independent rather than colliding in a global client cache.
        let request_id = 100 + round;
        let payload = status_request(request_id, 0);
        let request = AgentRequest::new(
            request_id,
            time::now().saturating_add(500),
            AgentOperation::Status,
            &payload,
        );
        match request {
            Some(request) => {
                if transport.exchange(request).is_err() {
                    failed += 1;
                }
            }
            None => failed += 1,
        }
    }

    let list_id = 500 + worker as u64;
    let list_payload = UpdateListRequest {
        request_id: list_id,
    }
    .encode();
    let request = list_payload.and_then(|payload| {
        AgentRequest::new(
            list_id,
            time::now().saturating_add(500),
            AgentOperation::List,
            &payload,
        )
    });
    match request {
        Some(request) => {
            if transport.exchange(request).is_err() {
                failed += 1;
            }
        }
        None => failed += 1,
    }

    drop(transport);
    failed
}

fn run_concurrency() -> bool {
    STRESS_READY.store(0, Ordering::Relaxed);
    STRESS_GO.store(false, Ordering::Relaxed);
    let Some(calls) = broker_calls() else {
        return false;
    };
    let mut threads = alloc::vec::Vec::new();
    let mut processes = alloc::vec::Vec::new();
    for worker in 0..STRESS_WORKERS {
        let child = match process::spawn(process::Spec {
            image: AGENT_DAEMON,
            calls,
            arg: 0,
            cpu_limit_permille: None,
        }) {
            Ok(child) => child,
            Err(_) => return false,
        };
        let process_handle = child.process;
        let channel = child.channel;
        let thread = match task::spawn(move || concurrent_worker(worker, channel)) {
            Ok(thread) => thread,
            Err(_) => {
                drop(process_handle);
                return false;
            }
        };
        processes.push(process_handle);
        threads.push(thread);
    }
    // Wait until every broker/client pair has reached the start gate before
    // releasing them together. This makes the acceptance run a real overlap
    // test instead of a sequence that only happens to finish concurrently.
    while STRESS_READY.load(Ordering::Acquire) != STRESS_WORKERS {
        task::yield_now();
    }
    STRESS_GO.store(true, Ordering::Release);

    let mut failed = 0u64;
    for thread in threads {
        match thread.join() {
            Ok(code) => failed = failed.saturating_add(code),
            Err(_) => failed = failed.saturating_add(1),
        }
    }
    for process in processes {
        if task::wait_process(&process).ok() != Some(0) {
            failed = failed.saturating_add(1);
        }
    }
    println!(
        "[JSR-UPDATE-AGENT-CONCURRENT] workers={} rounds={} process_isolation=true failed={} ok={}",
        STRESS_WORKERS,
        STRESS_ROUNDS,
        failed,
        failed == 0
    );
    failed == 0
}

fn status_request(id: u64, expected_generation: u64) -> [u8; REQUEST_BYTES] {
    StatusRequest {
        request_id: id,
        expected_generation,
        scope: SCOPE_PLATFORM,
    }
    .encode()
}

fn main(_: u64, _: u64) -> i32 {
    let Some(calls) = broker_calls() else {
        println!("[JSR-UPDATE-AGENT] failed=callset");
        return 1;
    };
    let child = match process::spawn(process::Spec {
        image: AGENT_DAEMON,
        calls,
        arg: 0,
        cpu_limit_permille: None,
    }) {
        Ok(child) => child,
        Err(_) => {
            println!("[JSR-UPDATE-AGENT] failed=spawn");
            return 2;
        }
    };
    let process_handle = child.process;
    let mut transport = AgentChannelTransport::new(child.channel, 500);

    let replay_payload = status_request(11, 0);
    let Some(replay_request) = AgentRequest::new(
        11,
        time::now().saturating_add(500),
        AgentOperation::Status,
        &replay_payload,
    ) else {
        println!("[JSR-UPDATE-AGENT] failed=request");
        return 3;
    };
    let first = match transport.exchange(replay_request) {
        Ok(response) => response,
        Err(code) => {
            println!("[JSR-UPDATE-AGENT] failed=status code={}", code);
            return 4;
        }
    };
    let retry_request = AgentRequest::new(
        11,
        time::now().saturating_add(500),
        AgentOperation::Status,
        &replay_payload,
    )
    .unwrap();
    let replay_ok = transport.exchange(retry_request).ok() == Some(first);
    let conflicting_payload = status_request(11, 1);
    let conflicting_request = AgentRequest::new(
        11,
        time::now().saturating_add(500),
        AgentOperation::Status,
        &conflicting_payload,
    )
    .unwrap();
    let payload_mismatch =
        transport.exchange(conflicting_request) == Err(ids::SYSTEM_USI_ERROR_REQUEST_ID as i64);

    let mut agent = UpdateAgent::new(transport);
    let mut status_json = [0u8; STATUS_JSON_BYTES];
    let status = agent.status_json(21, 0, &mut status_json).is_ok();
    let mut recover_json = [0u8; ACTION_JSON_BYTES];
    let recover = agent.recover_json(22, 23, &mut recover_json).is_ok();
    let mut archive_json = [0u8; ACTION_JSON_BYTES];
    let archive = agent.archive_json(24, 25, &mut archive_json).is_ok();
    let transport = agent.into_inner();
    let mut list_agent = UpdateListAgent::new(transport);
    let mut list_json = [0u8; LIST_JSON_BYTES];
    let list = list_agent.list_json(26, &mut list_json).is_ok();
    let mut transport = list_agent.into_inner();

    let expired = AgentRequest::new(31, 1, AgentOperation::Status, &status_request(31, 0)).unwrap();
    let timeout = transport.exchange(expired) == Err(ids::SYSTEM_ASYNC_ERROR_TIMED_OUT as i64);
    let after_timeout = transport
        .exchange(
            AgentRequest::new(
                32,
                time::now().saturating_add(500),
                AgentOperation::Status,
                &status_request(32, 0),
            )
            .unwrap(),
        )
        .is_ok();
    let server_app = transport.server_app().unwrap_or(0);
    drop(transport);
    let exit = task::wait_process(&process_handle).unwrap_or(u64::MAX);
    drop(process_handle);

    let concurrent = run_concurrency();
    let ok = replay_ok
        && status
        && recover
        && archive
        && list
        && timeout
        && after_timeout
        && payload_mismatch
        && server_app != 0
        && exit == 0
        && concurrent;
    println!(
        "[JSR-UPDATE-AGENT] transport=channel status={} recover={} archive={} list={} replay={} timeout={} after_timeout={} concurrent={} server_app={} child_exit={} ok={} payload_mismatch={}",
        status,
        recover,
        archive,
        list,
        replay_ok,
        timeout,
        after_timeout,
        concurrent,
        server_app,
        exit,
        ok,
        payload_mismatch
    );
    if ok {
        0
    } else {
        5
    }
}
