//! Jasper Unified Command Standard command identity and parsing.
//!
//! JUCS is the internal command contract shared by native frontends. It does
//! not add a `jucs` command prefix; users type the canonical resource command
//! directly, such as `system update status`.
//!
//! Jasper 统一命令标准（JUCS）的命令身份与解析。JUCS 是原生前端共享的
//! 内部契约，不会给用户命令增加 `jucs` 前缀。

pub const UPDATE_STATUS_ID: &str = "system.update.status";
pub const UPDATE_STATUS_VERSION: u16 = 1;

pub const UPDATE_STATUS_HELP: &str =
    "system update status [--help|--schema]\nShow the authenticated system update and boot-slot status.\n";

pub const UPDATE_STATUS_SCHEMA: &str = concat!(
    "{\"schema\":\"jucs.command/1\",\"id\":\"system.update.status\",",
    "\"version\":1,\"effects\":\"read\",\"arguments\":[],",
    "\"options\":[\"--help\",\"--schema\"],",
    "\"service\":\"service.update.status\",\"service_version\":1}\n"
);

/// A JUCS command whose identity has been frozen for this runtime generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// Query the current A/B boot control and update-service state.
    UpdateStatus,
}

impl Command {
    /// Stable command ID. This is a JUCS identity, not a syscall name.
    pub const fn id(self) -> &'static str {
        match self {
            Self::UpdateStatus => UPDATE_STATUS_ID,
        }
    }

    /// Command contract generation.
    pub const fn version(self) -> u16 {
        match self {
            Self::UpdateStatus => UPDATE_STATUS_VERSION,
        }
    }
}

/// The action requested for a recognized command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    /// Execute the command.
    Invoke,
    /// Return canonical help.
    Help,
    /// Return the machine-readable command schema.
    Schema,
}

/// One parsed command ready for the single JUCS service dispatcher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invocation {
    pub command: Command,
    pub form: Form,
}

/// Stable parse failure classes. Frontends map these to structured errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The input contains no command tokens.
    Empty,
    /// A mandatory JUCS tool prefix was used.
    ToolPrefix,
    /// The command identity is unknown.
    Unknown,
    /// A known command has an unsupported or malformed suffix.
    InvalidOption,
}

impl ParseError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Empty | Self::ToolPrefix | Self::Unknown | Self::InvalidOption => {
                "system.error.invalid_argument"
            }
        }
    }
}

/// Parse one native command line without allocating.
///
/// The only accepted invocations are the canonical three-token command and
/// its two discovery options. Leading/trailing ASCII whitespace is ignored.
pub fn parse(line: &[u8]) -> Result<Invocation, ParseError> {
    let mut tokens = Tokens::new(line);
    let Some(first) = tokens.next() else {
        return Err(ParseError::Empty);
    };
    if first == b"jucs" || first == b"jasper" {
        return Err(ParseError::ToolPrefix);
    }
    if first != b"system" || tokens.next() != Some(b"update".as_slice()) {
        return Err(ParseError::Unknown);
    }
    if tokens.next() != Some(b"status".as_slice()) {
        return Err(ParseError::Unknown);
    }
    let form = match tokens.next() {
        None => Form::Invoke,
        Some(b"--help") if tokens.next().is_none() => Form::Help,
        Some(b"--schema") if tokens.next().is_none() => Form::Schema,
        Some(_) => return Err(ParseError::InvalidOption),
    };
    Ok(Invocation {
        command: Command::UpdateStatus,
        form,
    })
}

struct Tokens<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Tokens<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn next(&mut self) -> Option<&'a [u8]> {
        while self
            .input
            .get(self.offset)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.offset += 1;
        }
        let start = self.offset;
        while self
            .input
            .get(self.offset)
            .is_some_and(|byte| !byte.is_ascii_whitespace())
        {
            self.offset += 1;
        }
        (self.offset != start).then_some(&self.input[start..self.offset])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_command_and_discovery_forms_parse_without_prefix() {
        assert_eq!(
            parse(b"system update status"),
            Ok(Invocation {
                command: Command::UpdateStatus,
                form: Form::Invoke,
            })
        );
        assert_eq!(
            parse(b"  system\tupdate status --help \n").unwrap().form,
            Form::Help
        );
        assert_eq!(
            parse(b"system update status --schema").unwrap().form,
            Form::Schema
        );
    }

    #[test]
    fn tool_prefix_unknown_commands_and_extra_arguments_fail_closed() {
        assert_eq!(
            parse(b"jucs system update status"),
            Err(ParseError::ToolPrefix)
        );
        assert_eq!(
            parse(b"jasper system update status"),
            Err(ParseError::ToolPrefix)
        );
        assert_eq!(parse(b"system update"), Err(ParseError::Unknown));
        assert_eq!(
            parse(b"system update status /control"),
            Err(ParseError::InvalidOption)
        );
        assert_eq!(
            parse(b"system update status --help extra"),
            Err(ParseError::InvalidOption)
        );
        assert_eq!(parse(b" \r\n"), Err(ParseError::Empty));
    }
}
