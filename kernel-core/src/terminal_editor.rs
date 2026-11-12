//! Bounded terminal line editing and command history.
//!
//! The editor is independent of the input device: serial control bytes and
//! PS/2-derived bytes feed the same state machine. It never allocates and
//! rejects overflow without changing the accepted line.
//!
//! 有界终端行编辑与命令历史。串口控制字节和 PS/2 派生字节进入同一个状态机；
//! 不分配内存，行缓冲溢出时整次拒绝且不改变已有内容。

/// Result of consuming one input byte.
///
/// 消费一个输入字节后的编辑结果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EditEvent {
    Pending,
    Submit,
    Eof,
    Cancel,
    Redraw,
    Rejected,
}

/// Fixed-capacity command line editor.
///
/// 固定容量命令行编辑器。
pub struct LineEditor<const INPUT: usize, const HISTORY: usize, const ENTRY: usize> {
    line: [u8; INPUT],
    len: usize,
    draft: [u8; ENTRY],
    draft_len: usize,
    history: [[u8; ENTRY]; HISTORY],
    history_len: [usize; HISTORY],
    history_count: usize,
    history_index: usize,
    browsing: bool,
    escape: u8,
}

impl<const INPUT: usize, const HISTORY: usize, const ENTRY: usize>
    LineEditor<INPUT, HISTORY, ENTRY>
{
    pub const fn new() -> Self {
        Self {
            line: [0; INPUT],
            len: 0,
            draft: [0; ENTRY],
            draft_len: 0,
            history: [[0; ENTRY]; HISTORY],
            history_len: [0; HISTORY],
            history_count: 0,
            history_index: 0,
            browsing: false,
            escape: 0,
        }
    }

    pub fn begin_line(&mut self) {
        self.len = 0;
        self.browsing = false;
        self.escape = 0;
    }

    pub fn line(&self) -> &[u8] {
        &self.line[..self.len]
    }

    pub const fn history_count(&self) -> usize {
        self.history_count
    }

    /// Consume one byte and report the required frontend action.
    ///
    /// 消费一个字节并报告前端动作。
    pub fn input(&mut self, byte: u8) -> EditEvent {
        if self.escape != 0 {
            return self.input_escape(byte);
        }
        match byte {
            0x1b => {
                self.escape = 1;
                EditEvent::Pending
            }
            0x03 => {
                self.begin_line();
                EditEvent::Cancel
            }
            0x04 if self.len == 0 => EditEvent::Eof,
            0x04 => EditEvent::Pending,
            0x0e => self.history_up(),
            0x10 => self.history_down(),
            b'\r' | b'\n' => EditEvent::Submit,
            0x08 | 0x7f => {
                self.backspace();
                EditEvent::Pending
            }
            0x00..=0x1f => EditEvent::Pending,
            _ if self.len == INPUT => EditEvent::Rejected,
            _ => {
                self.line[self.len] = byte;
                self.len += 1;
                EditEvent::Pending
            }
        }
    }

    /// Commit the submitted line into bounded history and clear it.
    ///
    /// 将已提交行写入有界历史并清空当前行。
    pub fn finish_submit(&mut self) {
        if self.len != 0 {
            let duplicate =
                self.history_count != 0 && self.last_history() == &self.line[..self.len];
            if !duplicate && HISTORY != 0 && ENTRY != 0 {
                if self.history_count == HISTORY {
                    self.history.copy_within(1.., 0);
                    self.history_len.copy_within(1.., 0);
                    self.history_count -= 1;
                }
                let copy = self.len.min(ENTRY);
                self.history[self.history_count][..copy].copy_from_slice(&self.line[..copy]);
                self.history_len[self.history_count] = copy;
                self.history_count += 1;
            }
        }
        self.begin_line();
    }

    fn backspace(&mut self) {
        if self.len == 0 {
            return;
        }
        let end = self.len;
        let mut start = end - 1;
        while start != 0 && self.line[start] & 0xc0 == 0x80 {
            start -= 1;
        }
        if core::str::from_utf8(&self.line[start..end]).is_ok() {
            self.len = start;
        } else {
            self.len = end - 1;
        }
        self.browsing = false;
    }

    fn input_escape(&mut self, byte: u8) -> EditEvent {
        match (self.escape, byte) {
            (1, b'[') => {
                self.escape = 2;
                EditEvent::Pending
            }
            (2, b'A') => {
                self.escape = 0;
                self.history_up()
            }
            (2, b'B') => {
                self.escape = 0;
                self.history_down()
            }
            _ => {
                self.escape = 0;
                EditEvent::Pending
            }
        }
    }

    fn history_up(&mut self) -> EditEvent {
        if self.history_count == 0 || HISTORY == 0 {
            return EditEvent::Pending;
        }
        if !self.browsing {
            self.draft_len = self.len.min(ENTRY);
            self.draft[..self.draft_len].copy_from_slice(&self.line[..self.draft_len]);
            self.history_index = self.history_count - 1;
            self.browsing = true;
        } else if self.history_index != 0 {
            self.history_index -= 1;
        } else {
            return EditEvent::Pending;
        }
        self.load_history(self.history_index);
        EditEvent::Redraw
    }

    fn history_down(&mut self) -> EditEvent {
        if !self.browsing {
            return EditEvent::Pending;
        }
        if self.history_index + 1 < self.history_count {
            self.history_index += 1;
            self.load_history(self.history_index);
        } else {
            self.load_draft();
            self.browsing = false;
        }
        EditEvent::Redraw
    }

    fn load_history(&mut self, index: usize) {
        let count = self.history_len[index].min(INPUT);
        self.line[..count].copy_from_slice(&self.history[index][..count]);
        self.len = count;
    }

    fn load_draft(&mut self) {
        let count = self.draft_len.min(INPUT);
        self.line[..count].copy_from_slice(&self.draft[..count]);
        self.len = count;
    }

    fn last_history(&self) -> &[u8] {
        let index = self.history_count - 1;
        &self.history[index][..self.history_len[index].min(ENTRY)]
    }
}

impl<const INPUT: usize, const HISTORY: usize, const ENTRY: usize> Default
    for LineEditor<INPUT, HISTORY, ENTRY>
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backspace_removes_complete_utf8_codepoints() {
        let mut editor = LineEditor::<16, 4, 16>::new();
        editor.input(b'a');
        for byte in "你".as_bytes() {
            editor.input(*byte);
        }
        editor.input(0x7f);
        assert_eq!(editor.line(), b"a");
    }

    #[test]
    fn control_actions_are_distinct_and_bounded() {
        let mut editor = LineEditor::<4, 4, 4>::new();
        for byte in b"line" {
            editor.input(*byte);
        }
        assert_eq!(editor.input(b'x'), EditEvent::Rejected);
        assert_eq!(editor.line(), b"line");
        assert_eq!(editor.input(0x04), EditEvent::Pending);
        assert_eq!(editor.input(0x03), EditEvent::Cancel);
        assert_eq!(editor.line(), b"");
        assert_eq!(editor.input(0x04), EditEvent::Eof);
    }

    #[test]
    fn history_is_bounded_deduplicated_and_navigable() {
        let mut editor = LineEditor::<16, 2, 16>::new();
        for command in [b"one".as_slice(), b"one", b"two", b"three"] {
            for byte in command {
                editor.input(*byte);
            }
            assert_eq!(editor.input(b'\n'), EditEvent::Submit);
            editor.finish_submit();
        }
        assert_eq!(editor.history_count(), 2);

        assert_eq!(editor.input(0x0e), EditEvent::Redraw);
        assert_eq!(editor.line(), b"three");
        assert_eq!(editor.input(0x0e), EditEvent::Redraw);
        assert_eq!(editor.line(), b"two");
        assert_eq!(editor.input(0x10), EditEvent::Redraw);
        assert_eq!(editor.line(), b"three");
        assert_eq!(editor.input(0x10), EditEvent::Redraw);
        assert_eq!(editor.line(), b"");
    }

    #[test]
    fn ansi_arrow_sequences_and_invalid_bytes_never_panic() {
        let mut editor = LineEditor::<8, 2, 8>::new();
        for byte in b"ok\n" {
            editor.input(*byte);
        }
        editor.finish_submit();
        for byte in [0x1b, b'[', b'A'] {
            editor.input(byte);
        }
        assert_eq!(editor.line(), b"ok");
        for byte in [0xff, 0xf0, 0x80, 0x7f] {
            editor.input(byte);
        }
    }
}
