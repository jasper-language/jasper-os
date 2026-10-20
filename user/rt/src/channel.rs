//! Channel 端点：收发消息（字节 + 句柄）。
//! Channel endpoints: messages carry bytes and handles.
//!
//! 语义来自内核：send 要么整条消息（连同其中的句柄）进入对端队列，要么什么都不动；
//! recv 要么整条消息交付（字节写入缓冲区、句柄进入本进程句柄表），要么消息留在队列。

use alloc::vec::Vec;

use kernel_core::ring_abi::{MsgDesc, MSG_DESC_SIZE};

use crate::error::{check, Error, Result};
use crate::handle::Handle;
use crate::{ids, sys};

/// 单条消息的句柄数上限（与内核一致）。
pub const MAX_HANDLES: usize = 8;
/// 单条消息的字节数上限（与内核一致）。
pub const MAX_BYTES: usize = 64 * 1024;

/// 一个 Channel 端点（拥有其句柄）。
#[derive(Debug)]
pub struct Channel(Handle);

/// 收到的一条消息的规模与其中的句柄。
#[derive(Debug)]
pub struct Received {
    /// 写入缓冲区的字节数。
    pub len: usize,
    /// 随消息到达的句柄（已进入本进程句柄表）。
    pub handles: Vec<Handle>,
}

/// 新建一对相连的端点。
pub fn pair() -> Result<(Channel, Channel)> {
    let mut out = [0u64; 2];
    // SAFETY：out 是本函数栈上 16 字节的可写缓冲。
    check(unsafe { sys::call3(ids::SYSTEM_CHANNEL_CREATE, out.as_mut_ptr() as u64, 0, 0) })?;
    // SAFETY：内核刚放入本进程句柄表的两个新句柄。
    Ok(unsafe { (Channel(Handle::from_raw(out[0])), Channel(Handle::from_raw(out[1]))) })
}

impl Channel {
    /// 由句柄构造（句柄须指向 Channel 端点，否则各操作返回 `HANDLE_INVALID`）。
    pub fn from_handle(h: Handle) -> Channel {
        Channel(h)
    }

    /// 取回句柄。
    pub fn into_handle(self) -> Handle {
        self.0
    }

    /// 端点句柄。
    pub fn handle(&self) -> &Handle {
        &self.0
    }

    /// 发送一条只含字节的消息。
    pub fn send(&self, data: &[u8]) -> Result<()> {
        self.send_raw(data, &[])
    }

    /// 发送字节与句柄。成功时句柄随消息转移给接收方；失败时原样交还（连同错误）。
    pub fn send_with(&self, data: &[u8], handles: Vec<Handle>) -> core::result::Result<(), (Error, Vec<Handle>)> {
        let raw: Vec<u64> = handles.iter().map(Handle::raw).collect();
        match self.send_raw(data, &raw) {
            Ok(()) => {
                for h in handles {
                    let _ = h.into_raw(); // 已不在本进程句柄表中
                }
                Ok(())
            }
            Err(e) => Err((e, handles)),
        }
    }

    fn send_raw(&self, data: &[u8], handles: &[u64]) -> Result<()> {
        if data.len() > MAX_BYTES || handles.len() > MAX_HANDLES {
            return Err(Error::INVALID_ARGUMENT);
        }
        let desc = MsgDesc {
            data_ptr: data.as_ptr() as u64,
            handles_ptr: handles.as_ptr() as u64,
            data_len: data.len() as u32,
            handles_cap: handles.len() as u32,
            out_data_len: 0,
            out_handles: 0,
            out_sender: 0,
            reserved: 0,
        };
        let b = desc.encode();
        // SAFETY：描述、消息体、句柄数组都在调用期间有效；内核在返回前复制完毕。
        check(unsafe { sys::call3(ids::SYSTEM_CHANNEL_SEND, self.0.raw() as u64, b.as_ptr() as u64, 0) }).map(|_| ())
    }

    /// 阻塞接收一条消息到 `buf`。缓冲区不足 ⇒ `CHANNEL_BUFFER_TOO_SMALL`，消息留在队列
    /// （需要自动扩大缓冲区时用 [`Channel::recv_vec`]）。对端已关闭且队列为空 ⇒ `CHANNEL_PEER_CLOSED`。
    pub fn recv(&self, buf: &mut [u8]) -> Result<Received> {
        self.recv_into(buf).map(|(r, _)| r).map_err(|(e, _)| e)
    }

    /// 阻塞接收一条消息，按需扩大缓冲区（不超过 [`MAX_BYTES`]）。
    pub fn recv_vec(&self) -> Result<(Vec<u8>, Vec<Handle>)> {
        let mut buf = alloc::vec![0u8; 256];
        loop {
            match self.recv_into(&mut buf) {
                Ok((r, _)) => {
                    buf.truncate(r.len);
                    return Ok((buf, r.handles));
                }
                Err((e, need)) if e == Error::CHANNEL_BUFFER_TOO_SMALL && need > buf.len() && need <= MAX_BYTES => {
                    buf.resize(need, 0);
                }
                Err((e, _)) => return Err(e),
            }
        }
    }

    /// 接收一次；失败时附带内核报告的消息字节数（仅缓冲区不足时有意义）。
    fn recv_into(&self, buf: &mut [u8]) -> core::result::Result<(Received, usize), (Error, usize)> {
        let mut hs = [0u64; MAX_HANDLES];
        let desc = MsgDesc {
            data_ptr: buf.as_mut_ptr() as u64,
            handles_ptr: hs.as_mut_ptr() as u64,
            data_len: buf.len().min(MAX_BYTES) as u32,
            handles_cap: MAX_HANDLES as u32,
            out_data_len: 0,
            out_handles: 0,
            out_sender: 0,
            reserved: 0,
        };
        let mut b: [u8; MSG_DESC_SIZE] = desc.encode();
        // SAFETY：描述、缓冲区、句柄数组都在调用期间有效（同步 recv 在返回前完成交付）。
        let ret = unsafe { sys::call3(ids::SYSTEM_CHANNEL_RECV, self.0.raw() as u64, b.as_mut_ptr() as u64, 0) };
        let out = MsgDesc::decode(&b);
        match check(ret) {
            Ok(_) => {
                let n = (out.out_handles as usize).min(MAX_HANDLES);
                // SAFETY：这些句柄由内核随消息放入本进程句柄表，尚无人拥有。
                let handles = hs[..n].iter().map(|&h| unsafe { Handle::from_raw(h) }).collect();
                Ok((Received { len: out.out_data_len as usize, handles }, out.out_data_len as usize))
            }
            Err(e) => Err((e, out.out_data_len as usize)),
        }
    }
}
