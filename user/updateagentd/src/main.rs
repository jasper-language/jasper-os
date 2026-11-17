//! Structured update Agent broker process.
//!
//! The kernel-provided bootstrap Channel is the only external authority this
//! process receives. Identity, tenant and authorization remain kernel facts and
//! cannot be supplied by an Agent request.

#![no_std]
#![no_main]

use jasper_rt::channel::Channel;
use jasper_rt::handle::Handle;
use jasper_rt::{entry, update};

entry!(main);

fn main(channel: u64, _: u64) -> i32 {
    // SAFETY: process.spawn enters this image with one fresh bootstrap Channel.
    let channel = Channel::from_handle(unsafe { Handle::from_raw(channel) });
    update::serve(channel)
}
