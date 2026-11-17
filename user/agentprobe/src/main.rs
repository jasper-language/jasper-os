//! End-to-end external structured update Agent acceptance.

#![no_std]
#![no_main]

use jasper_rt::process::{self, CallSet};
use jasper_rt::update::AgentChannelTransport;
use jasper_rt::{entry, ids, println, task, time};
use kernel_core::update_agent::{UpdateAgent, ACTION_JSON_BYTES, STATUS_JSON_BYTES};
use kernel_core::update_agent_ipc::{AgentOperation, AgentRequest};
use kernel_core::update_service::{StatusRequest, REQUEST_BYTES, SCOPE_PLATFORM};

entry!(main);

static AGENT_DAEMON: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/updateagentd.elf"));

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
    ])
    .ok()
}

fn status_request(id: u64) -> [u8; REQUEST_BYTES] {
    StatusRequest {
        request_id: id,
        expected_generation: 0,
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

    let replay_payload = status_request(11);
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
        Err(_) => {
            println!("[JSR-UPDATE-AGENT] failed=status");
            return 4;
        }
    };
    let replay_ok = transport.exchange(replay_request).ok() == Some(first);

    let mut agent = UpdateAgent::new(transport);
    let mut status_json = [0u8; STATUS_JSON_BYTES];
    let status = agent.status_json(21, 0, &mut status_json).is_ok();
    let mut recover_json = [0u8; ACTION_JSON_BYTES];
    let recover = agent.recover_json(22, 23, &mut recover_json).is_ok();
    let mut archive_json = [0u8; ACTION_JSON_BYTES];
    let archive = agent.archive_json(24, 25, &mut archive_json).is_ok();
    let mut transport = agent.into_inner();

    let expired = AgentRequest::new(31, 1, AgentOperation::Status, &status_request(31)).unwrap();
    let timeout = transport.exchange(expired) == Err(ids::SYSTEM_ASYNC_ERROR_TIMED_OUT as i64);
    let after_timeout = transport
        .exchange(
            AgentRequest::new(
                32,
                time::now().saturating_add(500),
                AgentOperation::Status,
                &status_request(32),
            )
            .unwrap(),
        )
        .is_ok();
    let server_app = transport.server_app().unwrap_or(0);
    drop(transport);
    let exit = task::wait_process(&process_handle).unwrap_or(u64::MAX);
    drop(process_handle);

    let ok = replay_ok
        && status
        && recover
        && archive
        && timeout
        && after_timeout
        && server_app != 0
        && exit == 0;
    println!(
        "[JSR-UPDATE-AGENT] transport=channel status={} recover={} archive={} replay={} timeout={} after_timeout={} server_app={} child_exit={} ok={}",
        status, recover, archive, replay_ok, timeout, after_timeout, server_app, exit, ok
    );
    if ok {
        0
    } else {
        5
    }
}
