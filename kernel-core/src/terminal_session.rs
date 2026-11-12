//! Bounded native terminal session mechanism.
//!
//! This module owns only the transport state shared by a terminal frontend and
//! a process: two bounded byte rings, independent input/output half-close, and
//! one terminal outcome. It deliberately contains no PTY, termios, device,
//! scheduler, or filesystem semantics.
//!
//! 原生终端会话的有界机制。本模块只负责前后端共享的输入/输出字节环、
//! 独立半关闭和唯一终态；不复制 PTY、termios、设备驱动或 VFS 语义。

/// Stable terminal-session error.
///
/// 终端会话错误；错误名是稳定系统接口标识。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalError {
    /// The fixed-capacity destination ring has insufficient room.
    Full,
    /// The stream or complete session was closed.
    Closed,
    /// The session terminated because of a fault.
    Failed,
    /// No input is available and the session remains open.
    WouldBlock,
    /// The input half is closed and every queued byte was consumed.
    Eof,
    /// An operand or configured direction is invalid.
    Invalid,
}

impl TerminalError {
    /// Stable system interface name.
    ///
    /// 稳定系统接口名称。
    pub const fn name(self) -> &'static str {
        match self {
            Self::Full => "system.terminal.error.full",
            Self::Closed => "system.terminal.error.closed",
            Self::Failed => "system.terminal.error.failed",
            Self::WouldBlock => "system.terminal.error.would_block",
            Self::Eof => "system.terminal.error.eof",
            Self::Invalid => "system.terminal.error.invalid",
        }
    }
}

/// Observable session state derived from the two half-closes and terminal result.
///
/// 由输入/输出半关闭与终态共同导出的可观察会话状态。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalState {
    Open,
    InputClosed,
    OutputClosed,
    Closed,
    Failed,
}

/// Why a terminal session reached its unique terminal state.
///
/// 终端会话进入唯一终态的原因。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalOutcome {
    Closed,
    Failed,
}

/// Immutable diagnostic view; byte contents are intentionally omitted.
///
/// 不可变诊断快照；有意不暴露会话内容。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalSnapshot {
    pub state: TerminalState,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub input_capacity: usize,
    pub output_capacity: usize,
}

/// One fixed-capacity, non-allocating terminal session.
///
/// 单个固定容量、无堆分配的终端会话。
pub struct TerminalSession<const INPUT_CAP: usize, const OUTPUT_CAP: usize> {
    input: [u8; INPUT_CAP],
    input_head: usize,
    input_len: usize,
    output: [u8; OUTPUT_CAP],
    output_head: usize,
    output_len: usize,
    input_closed: bool,
    output_closed: bool,
    terminal: Option<TerminalOutcome>,
}

impl<const INPUT_CAP: usize, const OUTPUT_CAP: usize> TerminalSession<INPUT_CAP, OUTPUT_CAP> {
    /// Creates an open, empty session.
    ///
    /// 创建一个打开且为空的会话。
    pub const fn new() -> Self {
        Self {
            input: [0; INPUT_CAP],
            input_head: 0,
            input_len: 0,
            output: [0; OUTPUT_CAP],
            output_head: 0,
            output_len: 0,
            input_closed: false,
            output_closed: false,
            terminal: None,
        }
    }

    /// Current derived state.
    ///
    /// 返回当前派生状态。
    pub const fn state(&self) -> TerminalState {
        match self.terminal {
            Some(TerminalOutcome::Failed) => TerminalState::Failed,
            Some(TerminalOutcome::Closed) => TerminalState::Closed,
            None if self.input_closed && self.output_closed => TerminalState::Closed,
            None if self.input_closed => TerminalState::InputClosed,
            None if self.output_closed => TerminalState::OutputClosed,
            None => TerminalState::Open,
        }
    }

    /// Diagnostic snapshot.
    ///
    /// 返回诊断快照。
    pub const fn snapshot(&self) -> TerminalSnapshot {
        TerminalSnapshot {
            state: self.state(),
            input_bytes: self.input_len,
            output_bytes: self.output_len,
            input_capacity: INPUT_CAP,
            output_capacity: OUTPUT_CAP,
        }
    }

    /// Append frontend input atomically or reject the whole append.
    ///
    /// 原子追加终端前端输入；空间不足时整次拒绝且不留下部分字节。
    pub fn enqueue_input(&mut self, bytes: &[u8]) -> Result<(), TerminalError> {
        self.ensure_writable(INPUT_CAP, self.input_closed)?;
        if bytes.len() > INPUT_CAP.saturating_sub(self.input_len) {
            return Err(TerminalError::Full);
        }
        let tail = (self.input_head + self.input_len) % INPUT_CAP;
        for (index, byte) in bytes.iter().copied().enumerate() {
            self.input[(tail + index) % INPUT_CAP] = byte;
        }
        self.input_len += bytes.len();
        Ok(())
    }

    /// Read available input without crossing into a later terminal state.
    ///
    /// 读取可用输入；输入半关闭且已排空时返回 EOF，尚未关闭时返回非阻塞。
    pub fn read_input(&mut self, destination: &mut [u8]) -> Result<usize, TerminalError> {
        if destination.is_empty() {
            return Ok(0);
        }
        self.ensure_live(INPUT_CAP)?;
        if self.input_len == 0 {
            return if self.input_closed {
                Err(TerminalError::Eof)
            } else {
                Err(TerminalError::WouldBlock)
            };
        }
        let count = destination.len().min(self.input_len);
        for (index, slot) in destination[..count].iter_mut().enumerate() {
            *slot = self.input[(self.input_head + index) % INPUT_CAP];
        }
        self.input_head = (self.input_head + count) % INPUT_CAP;
        self.input_len -= count;
        Ok(count)
    }

    /// Append process output atomically or reject the whole append.
    ///
    /// 原子追加进程输出；缓冲区不足时整次拒绝。
    pub fn enqueue_output(&mut self, bytes: &[u8]) -> Result<(), TerminalError> {
        self.ensure_writable(OUTPUT_CAP, self.output_closed)?;
        if bytes.len() > OUTPUT_CAP.saturating_sub(self.output_len) {
            return Err(TerminalError::Full);
        }
        let tail = (self.output_head + self.output_len) % OUTPUT_CAP;
        for (index, byte) in bytes.iter().copied().enumerate() {
            self.output[(tail + index) % OUTPUT_CAP] = byte;
        }
        self.output_len += bytes.len();
        Ok(())
    }

    /// Drain queued output into a frontend buffer.
    ///
    /// 将已排队输出排入前端缓冲区。
    pub fn drain_output(&mut self, destination: &mut [u8]) -> Result<usize, TerminalError> {
        if destination.is_empty() {
            return Ok(0);
        }
        self.ensure_live(OUTPUT_CAP)?;
        let count = destination.len().min(self.output_len);
        for (index, slot) in destination[..count].iter_mut().enumerate() {
            *slot = self.output[(self.output_head + index) % OUTPUT_CAP];
        }
        self.output_head = (self.output_head + count) % OUTPUT_CAP;
        self.output_len -= count;
        Ok(count)
    }

    /// Close the frontend input half after already queued bytes.
    ///
    /// 关闭前端输入半流；已排队字节仍可由进程读取。
    pub fn close_input(&mut self) -> Result<(), TerminalError> {
        self.ensure_live(INPUT_CAP)?;
        self.input_closed = true;
        if self.output_closed {
            self.terminal = Some(TerminalOutcome::Closed);
        }
        Ok(())
    }

    /// Close the process output half after already queued bytes.
    ///
    /// 关闭进程输出半流；已排队字节仍可由前端排空。
    pub fn close_output(&mut self) -> Result<(), TerminalError> {
        self.ensure_live(OUTPUT_CAP)?;
        self.output_closed = true;
        if self.input_closed {
            self.terminal = Some(TerminalOutcome::Closed);
        }
        Ok(())
    }

    /// Commit the unique normal terminal result.
    ///
    /// 提交唯一的正常终态；重复关闭幂等，故障终态不可被覆盖。
    pub fn close(&mut self) -> Result<(), TerminalError> {
        match self.terminal {
            None => {
                self.terminal = Some(TerminalOutcome::Closed);
                Ok(())
            }
            Some(TerminalOutcome::Closed) => Ok(()),
            Some(TerminalOutcome::Failed) => Err(TerminalError::Failed),
        }
    }

    /// Commit the unique failed terminal result.
    ///
    /// 提交唯一的失败终态；失败后不允许重新打开。
    pub fn fail(&mut self) -> Result<(), TerminalError> {
        match self.terminal {
            Some(TerminalOutcome::Failed) => Ok(()),
            Some(TerminalOutcome::Closed) => Err(TerminalError::Closed),
            None => {
                self.terminal = Some(TerminalOutcome::Failed);
                Ok(())
            }
        }
    }

    fn ensure_writable(&self, capacity: usize, half_closed: bool) -> Result<(), TerminalError> {
        if capacity == 0 {
            return Err(TerminalError::Invalid);
        }
        match self.terminal {
            Some(TerminalOutcome::Failed) => Err(TerminalError::Failed),
            Some(TerminalOutcome::Closed) => Err(TerminalError::Closed),
            None if half_closed => Err(TerminalError::Closed),
            None => Ok(()),
        }
    }

    fn ensure_live(&self, capacity: usize) -> Result<(), TerminalError> {
        if capacity == 0 {
            return Err(TerminalError::Invalid);
        }
        match self.terminal {
            Some(TerminalOutcome::Failed) => Err(TerminalError::Failed),
            Some(TerminalOutcome::Closed) => Err(TerminalError::Closed),
            None => Ok(()),
        }
    }
}

impl<const INPUT_CAP: usize, const OUTPUT_CAP: usize> Default
    for TerminalSession<INPUT_CAP, OUTPUT_CAP>
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_wraps_and_preserves_byte_order() {
        let mut session = TerminalSession::<4, 4>::new();
        session.enqueue_input(b"abc").unwrap();
        let mut first = [0u8; 2];
        assert_eq!(session.read_input(&mut first), Ok(2));
        assert_eq!(&first, b"ab");
        session.enqueue_input(b"def").unwrap();
        let mut second = [0u8; 4];
        assert_eq!(session.read_input(&mut second), Ok(4));
        assert_eq!(&second, b"cdef");
    }

    #[test]
    fn input_and_output_overflow_are_failure_atomic() {
        let mut session = TerminalSession::<4, 3>::new();
        session.enqueue_input(b"abc").unwrap();
        assert_eq!(session.enqueue_input(b"de"), Err(TerminalError::Full));
        assert_eq!(session.snapshot().input_bytes, 3);
        assert_eq!(session.read_input(&mut [0u8; 4]).is_ok(), true);

        session.enqueue_output(b"xy").unwrap();
        assert_eq!(session.enqueue_output(b"z0"), Err(TerminalError::Full));
        let mut output = [0u8; 3];
        assert_eq!(session.drain_output(&mut output), Ok(2));
        assert_eq!(&output[..2], b"xy");
    }

    #[test]
    fn input_half_close_returns_eof_only_after_queued_bytes() {
        let mut session = TerminalSession::<8, 8>::new();
        session.enqueue_input(b"ok").unwrap();
        session.close_input().unwrap();
        assert_eq!(session.state(), TerminalState::InputClosed);
        assert_eq!(session.enqueue_input(b"x"), Err(TerminalError::Closed));
        let mut bytes = [0u8; 4];
        assert_eq!(session.read_input(&mut bytes), Ok(2));
        assert_eq!(session.read_input(&mut bytes), Err(TerminalError::Eof));
    }

    #[test]
    fn output_half_close_is_independent_of_input() {
        let mut session = TerminalSession::<8, 8>::new();
        session.close_output().unwrap();
        assert_eq!(session.state(), TerminalState::OutputClosed);
        assert_eq!(session.enqueue_output(b"x"), Err(TerminalError::Closed));
        session.enqueue_input(b"in").unwrap();
        let mut bytes = [0u8; 2];
        assert_eq!(session.read_input(&mut bytes), Ok(2));
        assert_eq!(&bytes, b"in");
    }

    #[test]
    fn terminal_outcomes_are_unique_and_failure_cannot_be_reopened() {
        let mut session = TerminalSession::<8, 8>::new();
        session.close().unwrap();
        session.close().unwrap();
        assert_eq!(session.state(), TerminalState::Closed);
        assert_eq!(session.fail(), Err(TerminalError::Closed));
        assert_eq!(session.enqueue_input(b"x"), Err(TerminalError::Closed));

        let mut failed = TerminalSession::<8, 8>::new();
        failed.fail().unwrap();
        failed.fail().unwrap();
        assert_eq!(failed.state(), TerminalState::Failed);
        assert_eq!(failed.close(), Err(TerminalError::Failed));
        assert_eq!(failed.read_input(&mut [0u8; 1]), Err(TerminalError::Failed));
    }

    #[test]
    fn empty_read_is_zero_but_zero_capacity_is_invalid() {
        let mut session = TerminalSession::<4, 4>::new();
        assert_eq!(session.read_input(&mut []), Ok(0));
        assert_eq!(session.drain_output(&mut []), Ok(0));

        let mut empty = TerminalSession::<0, 0>::new();
        assert_eq!(empty.enqueue_input(b"x"), Err(TerminalError::Invalid));
        assert_eq!(empty.read_input(&mut [0u8; 1]), Err(TerminalError::Invalid));
        assert_eq!(empty.snapshot().state, TerminalState::Open);
    }
}
