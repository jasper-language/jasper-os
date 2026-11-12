//! Native console-backed terminal session.
//!
//! This is the first real transport slice for issue #27: serial input is polled
//! into a bounded session ring and Linux standard input consumes it. The kernel
//! does not claim PTY, termios, line editing, job control, or a graphical
//! terminal frontend.
//!
//! 原生控制台终端会话的首个真实传输切片：串口输入进入有界会话环，Linux
//! 标准输入从中读取；不宣称已实现 PTY、termios、行编辑、作业控制或图形前端。

use kernel_core::terminal_session::{TerminalError, TerminalSession, TerminalState};

use crate::proc;
use crate::sync::IrqSpinLock;
use crate::{arch, console, sched};

const INPUT_CAPACITY: usize = 4096;
const OUTPUT_CAPACITY: usize = 4096;
const UART_PUMP_LIMIT: usize = 64;

static TERMINAL: IrqSpinLock<TerminalSession<INPUT_CAPACITY, OUTPUT_CAPACITY>> =
    IrqSpinLock::ranked(crate::lockorder::TERMINAL, TerminalSession::new());

/// Read standard input, translating serial CR to LF and blocking outside IRQ context.
///
/// 读取标准输入；串口 CR 转为 LF，阻塞等待时通过调度器让出处理器。
pub fn read_input(destination: &mut [u8], nonblocking: bool) -> Result<usize, TerminalError> {
    if destination.is_empty() {
        return Ok(0);
    }
    loop {
        pump_serial_input();
        let result = {
            let mut terminal = TERMINAL.lock();
            terminal.read_input(destination)
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

/// Poll whether input bytes are pending and whether a stable hangup is visible.
///
/// 查询是否有待读输入，以及是否已出现稳定挂断。
pub fn input_status() -> (bool, bool, bool) {
    pump_serial_input();
    let snapshot = TERMINAL.lock().snapshot();
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
    for _ in 0..UART_PUMP_LIMIT {
        let Some(received) = arch::console_try_read_byte() else {
            return;
        };
        if received == 0x04 {
            let closed = TERMINAL.lock().close_input().is_ok();
            if closed {
                console::write_bytes(b"\r\n");
            }
            return;
        }
        let byte = if received == b'\r' { b'\n' } else { received };
        let accepted = TERMINAL.lock().enqueue_input(&[byte]).is_ok();
        if !accepted {
            console::write_str("\n[JSR-TERM] input_full=true drop=true\n");
            return;
        }
        if byte == b'\n' {
            console::write_bytes(b"\n");
        } else {
            console::write_bytes(&[byte]);
        }
    }
}
