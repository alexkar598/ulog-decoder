use crate::location::Location;
use crate::severity::SeverityLevel;
use crate::ulog_argument::{ULogArgument, ULogArgumentReadError};
use crate::ulog_string::ULogStringMap;
use dyf::{FormatString, Formatter};
use snafu::{Backtrace, ResultExt, Snafu};
use std::borrow::Cow;
use std::collections::HashMap;
use std::io::BufRead;

#[derive(Snafu, Debug)]
pub enum ULogMessageFormatError {
    #[snafu(display("An error occurred while formatting"))]
    Format {
        backtrace: Backtrace,
        source: dyf::Error,
    },
    #[snafu(display("Argument number {number} could not be parsed"))]
    ULogArgumentRead {
        #[snafu(backtrace)]
        source: ULogArgumentReadError,
        number: usize,
    },
}

/// Struct representing a log message, both the definition and the realized type
#[derive(Debug, Clone)]
pub struct ULogMessage {
    /// Id of the message definition, equals the relative address to the ulog subsection start
    id: u16,
    /// Format string for this message
    format: FormatString,
    /// Location where this message was defined
    location: Location,
    /// Severity of this log entry
    severity_level: SeverityLevel,
    /// Arguments attached to this message
    arguments: Vec<ULogArgument>,
}

/// Helper type for a map of message ids to messages
pub type ULogMessageMap = HashMap<u16, ULogMessage>;

impl ULogMessage {
    pub fn new(
        id: u16,
        string: FormatString,
        location: Location,
        severity_level: SeverityLevel,
    ) -> Self {
        Self {
            id,
            format: string,
            location,
            severity_level,
            arguments: vec![],
        }
    }

    pub fn id(&self) -> u16 {
        self.id
    }

    pub fn format(&self) -> Cow<'_, str> {
        self.format.to_string_lossy()
    }

    pub fn location(&self) -> &Location {
        &self.location
    }

    pub fn severity_level(&self) -> SeverityLevel {
        self.severity_level
    }

    pub fn arguments(&self) -> &Vec<ULogArgument> {
        &self.arguments
    }

    pub fn arguments_mut(&mut self) -> &mut Vec<ULogArgument> {
        &mut self.arguments
    }

    /// Ingests the argument values from a reader into this message's arguments
    pub fn read_arguments(
        &mut self,
        reader: &mut impl BufRead,
        string_map: &ULogStringMap,
    ) -> Result<(), ULogArgumentReadError> {
        for argument in &mut self.arguments {
            argument.read(reader, string_map)?;
        }
        Ok(())
    }

    /// Formats this message using the values found in a reader
    pub fn formatted_string(
        &self,
        reader: &mut impl BufRead,
        string_map: &ULogStringMap,
    ) -> Result<String, ULogMessageFormatError> {
        // Clone the argument list
        let mut args = self.arguments.clone();

        // Read values for each argument
        for (idx, argument) in args.iter_mut().enumerate() {
            argument
                .read(reader, string_map)
                .context(ULogArgumentReadSnafu { number: idx })?;
        }

        // Format the string
        let mut template = Formatter::from(&self.format);
        for arg in &args {
            template.push_arg(arg);
        }
        template.format().context(FormatSnafu)?;
        Ok(template.into_string())
    }
}
