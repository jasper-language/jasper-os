//! Streaming UTF-8 decoder for bounded terminal output.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decode {
    Pending,
    Character(char),
    /// An invalid sequence ended. The optional byte is a valid ASCII byte that
    /// followed a partial sequence and must be fed back into the decoder.
    Invalid(Option<u8>),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Utf8StreamDecoder {
    pending: [u8; 4],
    len: u8,
}

impl Utf8StreamDecoder {
    pub const fn new() -> Self {
        Self {
            pending: [0; 4],
            len: 0,
        }
    }

    pub const fn pending_len(self) -> u8 {
        self.len
    }

    pub fn push(&mut self, byte: u8) -> Decode {
        if self.len == 0 {
            if byte < 0x80 {
                return Decode::Character(byte as char);
            }
            let expected = match byte {
                0xc2..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf4 => 4,
                _ => return Decode::Invalid(None),
            };
            self.pending[0] = byte;
            self.len = 1;
            debug_assert!(expected > 1);
            return Decode::Pending;
        }

        if byte & 0xc0 != 0x80 {
            self.len = 0;
            if byte < 0x80 {
                return Decode::Invalid(Some(byte));
            }
            let expected = match byte {
                0xc2..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf4 => 4,
                _ => return Decode::Invalid(None),
            };
            self.pending[0] = byte;
            self.len = 1;
            debug_assert!(expected > 1);
            return Decode::Invalid(None);
        }

        let expected = match self.pending[0] {
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => {
                self.len = 0;
                return Decode::Invalid(None);
            }
        };
        self.pending[self.len as usize] = byte;
        self.len += 1;
        if self.len != expected {
            return Decode::Pending;
        }
        let decoded = core::str::from_utf8(&self.pending[..expected as usize])
            .ok()
            .and_then(|text| text.chars().next());
        self.len = 0;
        decoded.map_or(Decode::Invalid(None), Decode::Character)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multibyte_character_can_span_calls() {
        let mut decoder = Utf8StreamDecoder::new();
        assert_eq!(decoder.push(0xe2), Decode::Pending);
        assert_eq!(decoder.push(0x82), Decode::Pending);
        assert_eq!(decoder.push(0xac), Decode::Character('€'));
        assert_eq!(decoder.pending_len(), 0);
    }

    #[test]
    fn separate_calls_continue_after_complete_characters() {
        let mut decoder = Utf8StreamDecoder::new();
        assert_eq!(decoder.push(0xf0), Decode::Pending);
        assert_eq!(decoder.push(0x9f), Decode::Pending);
        assert_eq!(decoder.push(0x98), Decode::Pending);
        assert_eq!(decoder.push(0x80), Decode::Character('😀'));
        assert_eq!(decoder.push(b'A'), Decode::Character('A'));
    }

    #[test]
    fn invalid_sequences_fail_without_swallowing_ascii() {
        let mut decoder = Utf8StreamDecoder::new();
        assert_eq!(decoder.push(0xff), Decode::Invalid(None));
        assert_eq!(decoder.push(0xe2), Decode::Pending);
        assert_eq!(decoder.push(b'A'), Decode::Invalid(Some(b'A')));
        assert_eq!(decoder.push(b'A'), Decode::Character('A'));
    }
}
