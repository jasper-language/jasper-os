//! Native and Channel-backed transports for the structured update Agent.
//!
//! The native transport is the only place that issues update-service syscalls.
//! The external transport carries its already-encoded request/response records
//! through a bounded Channel and remains only a mechanical bridge.

use kernel_core::native_install_abi::{MAX_UPDATE_LIST_BYTES, UPDATE_LIST_REQUEST_BYTES};
use kernel_core::update_agent_ipc::{
    AgentOperation, AgentRequest, AgentResponse, REQUEST_MESSAGE_BYTES, RESPONSE_MESSAGE_BYTES,
};
use kernel_core::update_client::UpdateTransport;
use kernel_core::update_list_agent::UpdateListTransport;
use kernel_core::update_service::{
    StatusRequest, TransactionAction, TransactionActionRequest, ACTION_RESPONSE_BYTES,
    RESPONSE_BYTES, SCOPE_PLATFORM,
};

use crate::channel::Channel;
use crate::error::Error;
use crate::ring::Ring;
use crate::{ids, sys, time};

/// Native syscall transport shared by CLI and the Agent broker process.
pub struct NativeUpdateTransport;

impl UpdateTransport for NativeUpdateTransport {
    fn status(&mut self, request: &[u8], output: &mut [u8; RESPONSE_BYTES]) -> Result<(), i64> {
        let result = unsafe {
            sys::call3(
                ids::SYSTEM_UPDATE_STATUS_QUERY,
                request.as_ptr() as u64,
                output.as_mut_ptr() as u64,
                output.len() as u64,
            )
        };
        if result == RESPONSE_BYTES as i64 {
            Ok(())
        } else {
            Err(result.unsigned_abs() as i64)
        }
    }

    fn recover(
        &mut self,
        request: &[u8],
        output: &mut [u8; ACTION_RESPONSE_BYTES],
    ) -> Result<(), i64> {
        action_call(ids::SYSTEM_UPDATE_ACTION_RECOVER, request, output)
    }

    fn archive(
        &mut self,
        request: &[u8],
        output: &mut [u8; ACTION_RESPONSE_BYTES],
    ) -> Result<(), i64> {
        action_call(ids::SYSTEM_UPDATE_ACTION_ARCHIVE, request, output)
    }
}

/// Native list transport shared by CLI and structured frontends.
pub struct NativeUpdateListTransport;

impl UpdateListTransport for NativeUpdateListTransport {
    fn list(
        &mut self,
        request: &[u8; UPDATE_LIST_REQUEST_BYTES],
        output: &mut [u8; MAX_UPDATE_LIST_BYTES],
    ) -> Result<usize, i64> {
        let result = unsafe {
            sys::call3(
                ids::SYSTEM_INSTALL_UPDATE_LIST,
                request.as_ptr() as u64,
                output.as_mut_ptr() as u64,
                output.len() as u64,
            )
        };
        if result >= 0 {
            Ok(result as usize)
        } else {
            Err(result.unsigned_abs() as i64)
        }
    }
}

fn action_call(
    id: u64,
    request: &[u8],
    output: &mut [u8; ACTION_RESPONSE_BYTES],
) -> Result<(), i64> {
    let result = unsafe {
        sys::call3(
            id,
            request.as_ptr() as u64,
            output.as_mut_ptr() as u64,
            output.len() as u64,
        )
    };
    if result == ACTION_RESPONSE_BYTES as i64 {
        Ok(())
    } else {
        Err(result.unsigned_abs() as i64)
    }
}

/// Structured Agent client over a native Channel endpoint.
pub struct AgentChannelTransport {
    channel: Channel,
    timeout_ticks: u64,
    server_app: Option<u32>,
    ring: Option<Ring>,
}

impl AgentChannelTransport {
    /// Wrap the caller endpoint of a private Agent Channel.
    pub fn new(channel: Channel, timeout_ticks: u64) -> Self {
        Self {
            channel,
            timeout_ticks: timeout_ticks.max(1),
            server_app: None,
            ring: None,
        }
    }

    /// Kernel-stamped server application identity, pinned after the first reply.
    pub const fn server_app(&self) -> Option<u32> {
        self.server_app
    }

    /// Send one fixed protocol request and validate its fixed response.
    pub fn exchange(&mut self, request: AgentRequest) -> Result<AgentResponse, i64> {
        self.channel
            .send(&request.encode())
            .map_err(|error| error.id() as i64)?;
        let deadline = if request.deadline_tick == 0 {
            time::now().saturating_add(self.timeout_ticks)
        } else {
            request.deadline_tick
        };
        loop {
            if self.ring.is_none() {
                self.ring = Some(Ring::create(4).map_err(|error| error.id() as i64)?);
            }
            let mut bytes = [0u8; RESPONSE_MESSAGE_BYTES];
            let received = self
                .channel
                .recv_until(
                    self.ring
                        .as_ref()
                        .ok_or(Error::INVALID_ARGUMENT.id() as i64)?,
                    &mut bytes,
                    deadline,
                )
                .map_err(|error| error.id() as i64)?;
            if !received.handles.is_empty() || received.sender_app == 0 {
                crate::println!(
                    "[JSR-UPDATE-AGENT-CLIENT] reject=sender handles={} sender_app={}",
                    received.handles.len(),
                    received.sender_app
                );
                return Err(ids::SYSTEM_UPDATE_ERROR_TENANT_SCOPE as i64);
            }
            if let Some(expected) = self.server_app {
                if received.sender_app != expected {
                    crate::println!(
                        "[JSR-UPDATE-AGENT-CLIENT] reject=sender_change expected={} actual={}",
                        expected,
                        received.sender_app
                    );
                    return Err(ids::SYSTEM_UPDATE_ERROR_TENANT_SCOPE as i64);
                }
            } else {
                self.server_app = Some(received.sender_app);
            }
            let response =
                AgentResponse::decode(&bytes).ok_or(ids::SYSTEM_UPDATE_ERROR_PROTOCOL as i64)?;
            if response.message_id != request.message_id || response.operation != request.operation
            {
                // A timed-out receive can complete in the broker after the
                // caller has already cancelled its wait. Discard that response
                // rather than returning it to the next request. Its handles are
                // closed by `Received` when this iteration ends.
                continue;
            }
            if response.code != 0 {
                return Err(response.code.unsigned_abs() as i64);
            }
            return Ok(response);
        }
    }

    fn call(
        &mut self,
        operation: AgentOperation,
        request: &[u8],
        output: &mut [u8],
    ) -> Result<(), i64> {
        let message_id = service_request_id(operation, request)
            .ok_or(ids::SYSTEM_UPDATE_ERROR_PROTOCOL as i64)?;
        let deadline_tick = time::now().saturating_add(self.timeout_ticks);
        let request = AgentRequest::new(message_id, deadline_tick, operation, request)
            .ok_or(ids::SYSTEM_UPDATE_ERROR_PROTOCOL as i64)?;
        let response = self.exchange(request)?;
        if response.payload().len() != output.len() {
            return Err(ids::SYSTEM_UPDATE_ERROR_PROTOCOL as i64);
        }
        output.copy_from_slice(response.payload());
        Ok(())
    }

    fn call_variable(
        &mut self,
        operation: AgentOperation,
        request: &[u8],
        output: &mut [u8],
    ) -> Result<usize, i64> {
        let message_id = service_request_id(operation, request)
            .ok_or(ids::SYSTEM_UPDATE_ERROR_PROTOCOL as i64)?;
        let deadline_tick = time::now().saturating_add(self.timeout_ticks);
        let request = AgentRequest::new(message_id, deadline_tick, operation, request)
            .ok_or(ids::SYSTEM_UPDATE_ERROR_PROTOCOL as i64)?;
        let response = self.exchange(request)?;
        let payload = response.payload();
        if payload.len() > output.len() {
            return Err(ids::SYSTEM_UPDATE_ERROR_PROTOCOL as i64);
        }
        output[..payload.len()].copy_from_slice(payload);
        Ok(payload.len())
    }
}

impl UpdateTransport for AgentChannelTransport {
    fn status(&mut self, request: &[u8], output: &mut [u8; RESPONSE_BYTES]) -> Result<(), i64> {
        self.call(AgentOperation::Status, request, output)
    }

    fn recover(
        &mut self,
        request: &[u8],
        output: &mut [u8; ACTION_RESPONSE_BYTES],
    ) -> Result<(), i64> {
        self.call(AgentOperation::Recover, request, output)
    }

    fn archive(
        &mut self,
        request: &[u8],
        output: &mut [u8; ACTION_RESPONSE_BYTES],
    ) -> Result<(), i64> {
        self.call(AgentOperation::Archive, request, output)
    }
}

impl UpdateListTransport for AgentChannelTransport {
    fn list(
        &mut self,
        request: &[u8; UPDATE_LIST_REQUEST_BYTES],
        output: &mut [u8; MAX_UPDATE_LIST_BYTES],
    ) -> Result<usize, i64> {
        self.call_variable(AgentOperation::List, request, output)
    }
}

fn service_request_id(operation: AgentOperation, payload: &[u8]) -> Option<u64> {
    match operation {
        AgentOperation::Status => {
            let request = StatusRequest::decode(payload.try_into().ok()?)?;
            (request.scope == SCOPE_PLATFORM).then_some(request.request_id)
        }
        AgentOperation::Recover | AgentOperation::Archive => {
            let request = TransactionActionRequest::decode(payload.try_into().ok()?)?;
            let expected = match operation {
                AgentOperation::Recover => TransactionAction::Recover,
                AgentOperation::Archive => TransactionAction::Archive,
                AgentOperation::Status | AgentOperation::List => unreachable!(),
            };
            (request.scope == SCOPE_PLATFORM && request.action == expected)
                .then_some(request.request_id)
        }
        AgentOperation::List => {
            let request = kernel_core::native_install_abi::UpdateListRequest::decode(payload)?;
            Some(request.request_id)
        }
    }
}

/// Run the Agent broker loop against the kernel-stamped parent identity.
pub fn serve(channel: Channel) -> i32 {
    let mut native = NativeUpdateTransport;
    let mut client_app = None;
    let mut cache = ReplyCache::<16>::new();
    loop {
        let mut bytes = [0u8; REQUEST_MESSAGE_BYTES];
        let received = match channel.recv(&mut bytes) {
            Ok(received) => received,
            Err(Error(ids::SYSTEM_CHANNEL_ERROR_PEER_CLOSED)) => return 0,
            Err(_) => return 1,
        };
        if !received.handles.is_empty() || received.sender_app == 0 {
            crate::println!(
                "[JSR-UPDATE-AGENT-BROKER] reject=sender handles={} sender_app={}",
                received.handles.len(),
                received.sender_app
            );
            let _ = channel.send(&protocol_error());
            continue;
        }
        if client_app.is_none() {
            crate::println!(
                "[JSR-UPDATE-AGENT-BROKER] client_app={}",
                received.sender_app
            );
        }
        match client_app {
            None => client_app = Some(received.sender_app),
            Some(expected) if expected != received.sender_app => {
                let _ = channel.send(&protocol_error());
                continue;
            }
            Some(_) => {}
        }
        let Some(request) = AgentRequest::decode(&bytes) else {
            let version = u16::from_le_bytes([bytes[4], bytes[5]]);
            let operation = bytes[6];
            crate::println!(
                "[JSR-UPDATE-AGENT-BROKER] reject=request version={} operation={}",
                version,
                operation
            );
            let _ = channel.send(&protocol_error());
            continue;
        };
        if request.deadline_tick != 0 && time::now() > request.deadline_tick {
            let _ = send_error(&channel, &request, ids::SYSTEM_ASYNC_ERROR_TIMED_OUT as i64);
            continue;
        }
        if let Some(response) = cache.replay(&request) {
            let _ = channel.send(&response.encode());
            continue;
        }
        if cache.conflict(&request) {
            let _ = send_error(&channel, &request, ids::SYSTEM_USI_ERROR_REQUEST_ID as i64);
            continue;
        }
        let response = match dispatch(&mut native, &request) {
            Ok(response) => response,
            Err(code) => match AgentResponse::error(&request, code) {
                Some(response) => response,
                None => return 2,
            },
        };
        cache.complete(&request, response);
        if channel.send(&response.encode()).is_err() {
            return 0;
        }
    }
}

fn dispatch(
    native: &mut NativeUpdateTransport,
    request: &AgentRequest,
) -> Result<AgentResponse, i64> {
    match request.operation {
        AgentOperation::Status => {
            let mut output = [0u8; RESPONSE_BYTES];
            native.status(request.payload(), &mut output)?;
            AgentResponse::ok(request, &output).ok_or(ids::SYSTEM_UPDATE_ERROR_PROTOCOL as i64)
        }
        AgentOperation::Recover => {
            let mut output = [0u8; ACTION_RESPONSE_BYTES];
            native.recover(request.payload(), &mut output)?;
            AgentResponse::ok(request, &output).ok_or(ids::SYSTEM_UPDATE_ERROR_PROTOCOL as i64)
        }
        AgentOperation::Archive => {
            let mut output = [0u8; ACTION_RESPONSE_BYTES];
            native.archive(request.payload(), &mut output)?;
            AgentResponse::ok(request, &output).ok_or(ids::SYSTEM_UPDATE_ERROR_PROTOCOL as i64)
        }
        AgentOperation::List => {
            let payload: &[u8; UPDATE_LIST_REQUEST_BYTES] = request
                .payload()
                .try_into()
                .map_err(|_| ids::SYSTEM_UPDATE_ERROR_PROTOCOL as i64)?;
            let mut output = [0u8; MAX_UPDATE_LIST_BYTES];
            let mut list = NativeUpdateListTransport;
            let length = list.list(payload, &mut output)?;
            AgentResponse::ok(request, &output[..length])
                .ok_or(ids::SYSTEM_UPDATE_ERROR_PROTOCOL as i64)
        }
    }
}

fn send_error(channel: &Channel, request: &AgentRequest, code: i64) -> Result<(), Error> {
    let response = AgentResponse::error(request, code).ok_or(Error::INVALID_ARGUMENT)?;
    channel.send(&response.encode())
}

fn protocol_error() -> [u8; RESPONSE_MESSAGE_BYTES] {
    let mut bytes = [0u8; RESPONSE_MESSAGE_BYTES];
    bytes[26] = 1;
    bytes
}

#[derive(Clone, Copy)]
struct CacheEntry {
    request: AgentRequest,
    response: AgentResponse,
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

    fn replay(&self, request: &AgentRequest) -> Option<AgentResponse> {
        self.entries.iter().flatten().find_map(|entry| {
            entry
                .request
                .same_service_request(request)
                .then_some(entry.response)
        })
    }

    fn conflict(&self, request: &AgentRequest) -> bool {
        self.entries.iter().flatten().any(|entry| {
            entry.response.message_id == request.message_id
                && !entry.request.same_service_request(request)
        })
    }

    fn complete(&mut self, request: &AgentRequest, response: AgentResponse) {
        self.next_order = self.next_order.wrapping_add(1).max(1);
        let slot = self
            .entries
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| {
                self.entries
                    .iter()
                    .enumerate()
                    .filter_map(|(index, entry)| entry.as_ref().map(|entry| (index, entry.order)))
                    .min_by_key(|(_, order)| *order)
                    .map(|(index, _)| index)
                    .unwrap_or(0)
            });
        debug_assert_eq!(response.message_id, request.message_id);
        self.entries[slot] = Some(CacheEntry {
            request: *request,
            response,
            order: self.next_order,
        });
    }
}
