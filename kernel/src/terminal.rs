//! Native console-backed terminal session.
//!
//! Serial and framebuffer/PS-2 frontends feed the same bounded session ring.
//! Input is echoed to the diagnostic console and native graphical terminal.
//! The kernel does not claim PTY, termios, line editing, or job control.
//!
//! 串口与 framebuffer/PS-2 前端共用有界会话环，输入同时回显到串口与原生
//! 图形终端；不宣称已实现 PTY、termios、行编辑或作业控制。

use kernel_core::frame::FRAME_SIZE;
use kernel_core::terminal_session::{
    plan_terminal_capacity, DynamicTerminalSession, TerminalError, TerminalState,
};
use spin::Once;

use crate::sync::IrqSpinLock;
use crate::{arch, console, display, mm, proc, sched};

struct TerminalRuntime {
    session: DynamicTerminalSession,
    uart_pump_bytes: usize,
}

static TERMINAL: Once<IrqSpinLock<TerminalRuntime>> = Once::new();

/// Allocate terminal rings from the runtime-admitted memory budget.
pub fn init() -> bool {
    if TERMINAL.get().is_some() {
        return true;
    }
    let available = mm::frame::free_frames()
        .checked_mul(FRAME_SIZE as usize)
        .and_then(|free| u64::try_from(free).ok())
        .map(|free| free.min(mm::heap::limit()));
    let Some(available) = available else {
        crate::kprintln!("[JSR-TERM] reject=capacity_budget_overflow");
        return false;
    };
    let Some(capacity) = plan_terminal_capacity(available, 1) else {
        crate::kprintln!("[JSR-TERM] reject=capacity_unavailable available={available}");
        return false;
    };
    let Ok(session) = DynamicTerminalSession::new(capacity.input_bytes, capacity.output_bytes)
    else {
        crate::kprintln!("[JSR-TERM] reject=capacity_invalid");
        return false;
    };
    crate::kprintln!(
        "[JSR-TERM] capacity input={} output={} uart_pump={} available={}",
        capacity.input_bytes,
        capacity.output_bytes,
        capacity.uart_pump_bytes,
        available
    );
    TERMINAL.call_once(|| {
        IrqSpinLock::ranked(
            crate::lockorder::TERMINAL,
            TerminalRuntime {
                session,
                uart_pump_bytes: capacity.uart_pump_bytes,
            },
        )
    });
    true
}

/// Read standard input, translating serial CR to LF and blocking outside IRQ context.
///
/// 读取标准输入；串口 CR 转为 LF，阻塞等待时通过调度器让出处理器。
pub fn read_input(destination: &mut [u8], nonblocking: bool) -> Result<usize, TerminalError> {
    if destination.is_empty() {
        return Ok(0);
    }
    loop {
        pump_serial_input();
        pump_display_input();
        let result = match TERMINAL.get() {
            Some(terminal) => terminal.lock().session.read_input(destination),
            None => Err(TerminalError::Failed),
        };
        match result {
            Err(TerminalError::WouldBlock) if !nonblocking => {
                if proc::current_exiting() {
                    return Err(TerminalError::Closed);
                }
                sched::sleep_ticks(1);
            }
            result => return result,
        }
    }
}

/// Writes process output to the terminal frontend and diagnostic console.
///
/// 将进程输出写入终端前端，同时保留串口诊断副本。
pub fn write_output(bytes: &[u8]) {
    emit(bytes);
}

/// Poll whether input bytes are pending and whether a stable hangup is visible.
///
/// 查询是否有待读输入，以及是否已出现稳定挂断。
pub fn input_status() -> (bool, bool, bool) {
    pump_serial_input();
    let Some(terminal) = TERMINAL.get() else {
        return (false, true, true);
    };
    let snapshot = terminal.lock().session.snapshot();
    let ended = matches!(
        snapshot.state,
        TerminalState::InputClosed | TerminalState::Closed | TerminalState::Failed
    ) && snapshot.input_bytes == 0;
    (
        snapshot.input_bytes != 0,
        ended,
        snapshot.state == TerminalState::Failed,
    )
}

fn pump_serial_input() {
    let Some(pump_bytes) = TERMINAL
        .get()
        .map(|terminal| terminal.lock().uart_pump_bytes)
    else {
        return;
    };
    for _ in 0..pump_bytes {
        let Some(received) = arch::console_try_read_byte() else {
            return;
        };
        if received == 0x04 {
            let closed = TERMINAL
                .get()
                .is_some_and(|terminal| terminal.lock().session.close_input().is_ok());
            if closed {
                emit(b"\n");
            }
            return;
        }
        let byte = if received == b'\r' { b'\n' } else { received };
        let accepted = TERMINAL
            .get()
            .is_some_and(|terminal| terminal.lock().session.enqueue_input(&[byte]).is_ok());
        if !accepted {
            emit(b"\n[JSR-TERM] input_full=true drop=true\n");
            return;
        }
        emit(&[byte]);
    }
}

fn pump_display_input() {
    let Some(pump_bytes) = TERMINAL
        .get()
        .map(|terminal| terminal.lock().uart_pump_bytes)
    else {
        return;
    };
    display::poll_input();
    for _ in 0..pump_bytes {
        let Some(key) = display::next_key() else {
            return;
        };
        let Some(byte) = key_to_byte(key) else {
            continue;
        };
        let accepted = TERMINAL
            .get()
            .is_some_and(|terminal| terminal.lock().session.enqueue_input(&[byte]).is_ok());
        if !accepted {
            emit(b"\n[JSR-TERM] input_full=true drop=true\n");
            return;
        }
        emit(&[byte]);
    }
}

fn key_to_byte(key: kernel_core::display_input::KeyInput) -> Option<u8> {
    if !key.pressed {
        return None;
    }
    match key.code {
        0x0101 => Some(0x08),
        0x0102 => Some(b'\t'),
        0x0103 => Some(b'\n'),
        0x0110 => Some(0x0e),
        0x0111 => Some(0x10),
        0x20..=0x7e => {
            let byte = key.code as u8;
            if key.modifiers & 2 != 0 && byte.is_ascii_alphabetic() {
                Some(byte.to_ascii_uppercase() & 0x1f)
            } else if byte.is_ascii_uppercase() && key.modifiers & 1 == 0 {
                Some(byte.to_ascii_lowercase())
            } else {
                Some(byte)
            }
        }
        _ => None,
    }
}

fn emit(bytes: &[u8]) {
    console::write_bytes(bytes);
    display::terminal_write(bytes);
}
