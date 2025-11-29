use owo_colors::OwoColorize;
use snafu::{Backtrace, Snafu};
use std::fmt::{Display, Formatter};

/// Enum representing a severity level
#[derive(Debug, Clone, Copy)]
pub enum SeverityLevel {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
    Trace = 8,
}

#[derive(Snafu, Debug)]
pub enum SeverityLevelParseError {
    #[snafu(display("Unknown value ({value}) for severity level"))]
    UnknownValue { value: usize, backtrace: Backtrace },
}

impl TryFrom<usize> for SeverityLevel {
    type Error = SeverityLevelParseError;

    /// Convert a textual severity level id to a severity level
    fn try_from(value: usize) -> Result<Self, <Self as TryFrom<usize>>::Error> {
        let value = match value {
            0 => Self::Emergency,
            1 => Self::Alert,
            2 => Self::Critical,
            3 => Self::Error,
            4 => Self::Warning,
            5 => Self::Notice,
            6 => Self::Info,
            7 => Self::Debug,
            8 => Self::Trace,
            _ => return UnknownValueSnafu { value }.fail(),
        };
        Ok(value)
    }
}

impl Display for SeverityLevel {
    /// Print the severity level to text form. Use alternate display to have colors
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            match &self {
                SeverityLevel::Emergency => {
                    f.write_str(&"EMERGENCY".bold().black().on_bright_red().to_string())
                }
                SeverityLevel::Alert => f.write_str(&"ALERT".black().on_bright_red().to_string()),
                SeverityLevel::Critical => {
                    f.write_str(&"CRITICAL".bold().bright_red().on_black().to_string())
                }
                SeverityLevel::Error => f.write_str(&"ERROR".bright_red().to_string()),
                SeverityLevel::Warning => f.write_str(&"WARNING".yellow().to_string()),
                SeverityLevel::Notice => f.write_str(&"NOTICE".cyan().to_string()),
                SeverityLevel::Info => f.write_str("INFO"),
                SeverityLevel::Debug => f.write_str(&"DEBUG".italic().to_string()),
                SeverityLevel::Trace => f.write_str(&"TRACE".italic().dimmed().to_string()),
            }
        } else {
            match &self {
                SeverityLevel::Emergency => f.write_str("Emergency"),
                SeverityLevel::Alert => f.write_str("Alert"),
                SeverityLevel::Critical => f.write_str("Critical"),
                SeverityLevel::Error => f.write_str("Error"),
                SeverityLevel::Warning => f.write_str("Warning"),
                SeverityLevel::Notice => f.write_str("Notice"),
                SeverityLevel::Info => f.write_str("Info"),
                SeverityLevel::Debug => f.write_str("Debug"),
                SeverityLevel::Trace => f.write_str("Trace"),
            }
        }
    }
}
