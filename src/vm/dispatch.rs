use std::fmt;
use std::str::FromStr;

/// Inline handler rel32 size in threaded bytecode (after each opcode wire byte).
pub const THREAD_TARGET_SIZE: usize = 4;

/// VM interpreter dispatch strategy (L4c).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchMode {
    /// Central dispatch loop + opcode-indexed handler offset table (default).
    Table,
    /// Direct threading: per-instruction handler rel32 embedded in the bytecode stream.
    Threaded,
}

impl DispatchMode {
    pub const DEFAULT: Self = DispatchMode::Table;

    pub fn as_wire(self) -> u8 {
        match self {
            DispatchMode::Table => 0,
            DispatchMode::Threaded => 1,
        }
    }

    pub fn from_wire(wire: u8) -> Option<Self> {
        match wire {
            0 => Some(DispatchMode::Table),
            1 => Some(DispatchMode::Threaded),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            DispatchMode::Table => "table",
            DispatchMode::Threaded => "threaded",
        }
    }
}

impl Default for DispatchMode {
    fn default() -> Self {
        DispatchMode::DEFAULT
    }
}

impl fmt::Display for DispatchMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for DispatchMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "table" => Ok(DispatchMode::Table),
            "threaded" => Ok(DispatchMode::Threaded),
            other => Err(format!(
                "unknown dispatch mode '{other}' (expected table or threaded)"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_roundtrip() {
        for mode in [DispatchMode::Table, DispatchMode::Threaded] {
            assert_eq!(DispatchMode::from_wire(mode.as_wire()), Some(mode));
        }
        assert_eq!(DispatchMode::from_wire(2), None);
    }

    #[test]
    fn parse_cli_names() {
        assert_eq!("table".parse(), Ok(DispatchMode::Table));
        assert_eq!("THREADED".parse(), Ok(DispatchMode::Threaded));
        assert!("bogus".parse::<DispatchMode>().is_err());
    }
}
