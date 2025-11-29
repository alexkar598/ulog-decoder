#![allow(unused_variables)]

use crate::location::Location;
use crate::severity::{SeverityLevel, SeverityLevelParseError};
use crate::splitter::{SplitSegmentError, split_segments};
use crate::ulog_argument::{ULogArgument, ULogArgumentParseError};
use crate::ulog_message::{ULogMessage, ULogMessageMap};
use crate::ulog_string::{ULogString, ULogStringMap};
use crate::ulog_system_info::ULogSystemInfo;
use dyf::FormatString;
use elf::ElfStream;
use elf::endian::{AnyEndian, EndianParse};
use elf::symbol::Symbol;
use itertools::Itertools;
use snafu::{Backtrace, OptionExt, ResultExt, Snafu};
use std::fs;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone, Debug)]
struct ElfSymbol<'a> {
    // Underlying symbol data
    symbol: &'a Symbol,
    // Position of the symbol compared to the start of the ulog section (string, level, etc)
    // Unique for a given system for a given section
    rel_pos: u64,
    // Name of the symbol
    name: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
struct MessageIdentifier(Location, String);

#[derive(Snafu, Debug)]
pub enum ElfParseError {
    #[snafu(display("Failed to open file"))]
    File {
        source: std::io::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("String table is missing"))]
    NoStringTable { backtrace: Backtrace },
    #[snafu(display(".ulog section not found"))]
    NoULogSection { backtrace: Backtrace },
    #[snafu(display("ulog section is compressed. Compressions sections are not supported."))]
    ULogSectionCompressed { backtrace: Backtrace },
    #[snafu(display("The ELF file could not be parsed"))]
    ElfParse {
        source: elf::ParseError,
        backtrace: Backtrace,
    },
    #[snafu(display("Symbol table is missing"))]
    NoSymbolTable { backtrace: Backtrace },
    #[snafu(display("Cannot find symbol {symbol}"))]
    MissingSymbol {
        symbol: String,
        backtrace: Backtrace,
    },
    #[snafu(display("Unable to process symbol '{name}'"))]
    ElfSymbolParse {
        #[snafu(backtrace)]
        source: ElfSymbolParseError,
        name: String,
    },
    #[snafu(display("Cannot find system id"))]
    NoSystemId { backtrace: Backtrace },
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum ElfSymbolParseError {
    #[snafu(display("Incorrect amount of segments (expected {expected}, got {actual})"))]
    SegmentCountMismatch {
        backtrace: Backtrace,
        expected: usize,
        actual: usize,
    },
    #[snafu(display("Invalid integer"))]
    InvalidInteger {
        backtrace: Backtrace,
        source: std::num::ParseIntError,
    },
    #[snafu(display("Unable to split symbol name"))]
    SplitSegment {
        #[snafu(backtrace)]
        source: SplitSegmentError,
    },
    #[snafu(display("Failed to parse severity level"))]
    SeverityLevelParse {
        #[snafu(backtrace)]
        source: SeverityLevelParseError,
    },
    #[snafu(display("Id not in range for any severity level"))]
    NoMatchingLogLevel { backtrace: Backtrace },
    #[snafu(display("Failed to parse argument"))]
    ULogArgumentParse {
        #[snafu(backtrace)]
        source: ULogArgumentParseError,
    },
    #[snafu(display("The ELF file could not be parsed"))]
    ElfParse {
        backtrace: Backtrace,
        source: elf::ParseError,
    },
    #[snafu(display("Ran out of messages to attribute arguments to"))]
    OrphanedArguments { backtrace: Backtrace },
    #[snafu(display("Invalid template string: {template}"))]
    TemplateParse {
        backtrace: Backtrace,
        source: dyf::Error,
        template: String,
    },
    #[snafu(display("A non argument was found in the argument section"))]
    NonArgumentInArguments { backtrace: Backtrace },
}

/// Loads an elf file with ulog information from a path
pub fn attempt_load_elf(path: &Path) -> Result<ULogSystemInfo, ElfParseError> {
    // Open the file and attempt to parse it
    let file = fs::File::open(path).context(FileSnafu)?;
    let mut elf_file = ElfStream::<AnyEndian, _>::open_stream(file).context(ElfParseSnafu)?;
    let endianness = elf_file.ehdr.endianness;

    let (section_headers, string_table) = elf_file
        .section_headers_with_strtab()
        .context(ElfParseSnafu)?;
    let string_table = string_table.context(NoStringTableSnafu)?;
    // Find the .ulog section, ignore everything else
    let (section_index, section) = section_headers
        .iter()
        .enumerate()
        .find(|(_, header)| matches!(string_table.get(header.sh_name as usize), Ok(".ulog")))
        .map(|(idx, header)| (idx, header.to_owned()))
        .context(NoULogSectionSnafu)?;

    // Unwrap the section into its byte representation, this is no longer streamed but ulog info should be fairly minimal and we don't really
    // have any other choice
    let section_data = {
        let (section_data, section_compression_header) =
            elf_file.section_data(&section).context(ElfParseSnafu)?;
        // Might implement this some day if really needed, can't imagine why it would though
        if section_compression_header.is_some() {
            return ULogSectionCompressedSnafu.fail();
        }
        section_data.to_owned()
    };

    // Now we move to the symbol table
    let (symbols, strings) = elf_file
        .symbol_table()
        .context(ElfParseSnafu)?
        .context(NoSymbolTableSnafu)?;

    // Get all symbols in the .ulog section, the rest is not our concern
    let symbols = symbols
        .into_iter()
        .filter(|x| x.st_shndx == section_index as u16)
        .map(|sym| {
            strings
                .get(sym.st_name as usize)
                .context(ElfParseSnafu)
                .map(|name| (sym, name))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // All ulog markers start with _(s|e)ulog, so filter that for efficient lookups
    let ulog_section_markers = symbols
        .iter()
        .filter(|x| x.1.starts_with("_sulog") || x.1.starts_with("_eulog"))
        .collect::<Vec<_>>();

    // Helper function to easily get a ulog section marker address from the filtered list
    let get_ulog_section_marker = |name: &str| {
        Ok::<_, ElfParseError>(
            ulog_section_markers
                .iter()
                .find(|x| x.1 == name)
                .with_context(|| MissingSymbolSnafu {
                    symbol: name.to_string(),
                })?
                .0
                .st_value,
        )
    };

    // Helper function to get a list of all symbols located within a section delimited by
    // section markers
    let get_ulog_section = |name: &str| {
        let start_symbol = "_sulog_".to_owned() + name;
        let end_symbol = "_eulog_".to_owned() + name;
        let start = get_ulog_section_marker(&start_symbol)?;
        let end = get_ulog_section_marker(&end_symbol)?;
        let range = start..end;

        let section_symbols = symbols
            .iter()
            .filter(|x| range.contains(&x.0.st_value))
            .filter_map(|(sym, name)| {
                name.strip_prefix("__ulog_sym_").map(|name| ElfSymbol {
                    symbol: sym,
                    name,
                    rel_pos: sym.st_value - start,
                })
            })
            .collect::<Vec<_>>();
        Ok::<_, ElfParseError>(section_symbols)
    };

    // This is a bit ugly but it works so it shall remain as is
    let severity_level_max_ids = [
        get_ulog_section_marker("_eulog_level_emergency")?,
        get_ulog_section_marker("_eulog_level_alert")?,
        get_ulog_section_marker("_eulog_level_critical")?,
        get_ulog_section_marker("_eulog_level_error")?,
        get_ulog_section_marker("_eulog_level_warning")?,
        get_ulog_section_marker("_eulog_level_notice")?,
        get_ulog_section_marker("_eulog_level_info")?,
        get_ulog_section_marker("_eulog_level_debug")?,
        get_ulog_section_marker("_eulog_level_trace")?,
    ];

    // Helper function to get the severity level based on what address a message definition is located at
    let get_severity_level = |x: &ElfSymbol| -> Result<_, ElfSymbolParseError> {
        let id = x.symbol.st_value;

        let log_level = severity_level_max_ids
            .iter()
            .enumerate()
            .find(|(idx, level_max_id)| id < **level_max_id)
            .context(elf_symbol_parse_error::NoMatchingLogLevelSnafu)?
            .0;
        SeverityLevel::try_from(log_level).context(elf_symbol_parse_error::SeverityLevelParseSnafu)
    };

    // User string handling
    let ulog_strings = get_ulog_section("string")?
        .into_iter()
        .map(|x| {
            (|| -> Result<ULogString, _> {
                // Split symbol name into file, line and string
                let segments = split_segments(x.name, '_')
                    .context(elf_symbol_parse_error::SplitSegmentSnafu)?;
                let [file, line, string] = segments.try_into().map_err(|x: Vec<_>| {
                    elf_symbol_parse_error::SegmentCountMismatchSnafu {
                        expected: 3usize,
                        actual: x.len(),
                    }
                    .build()
                })?;

                // Save that string into a ULogString
                Ok(ULogString::new(
                    x.rel_pos as u16,
                    string,
                    Location {
                        file: Arc::from(file),
                        line: line
                            .parse()
                            .context(elf_symbol_parse_error::InvalidIntegerSnafu)?,
                    },
                ))
            })()
            .context(ElfSymbolParseSnafu {
                name: x.name.to_string(),
            })
        })
        // Map to tuples to collect into the string map
        .map_ok(|x| (x.id(), x))
        .collect::<Result<ULogStringMap, _>>()?;

    // Handling for the actual messages themselves
    let mut ulog_messages = get_ulog_section("level")?
        .into_iter()
        .map(|x| {
            (|| -> Result<ULogMessage, _> {
                // Split into file, line and format
                let segments = split_segments(x.name, '_')
                    .context(elf_symbol_parse_error::SplitSegmentSnafu)?;
                let [file, line, format] = segments.try_into().map_err(|x: Vec<_>| {
                    elf_symbol_parse_error::SegmentCountMismatchSnafu {
                        expected: 3usize,
                        actual: x.len(),
                    }
                    .build()
                })?;

                // Save that message into the struct for it
                Ok(ULogMessage::new(
                    x.rel_pos as u16,
                    // Parse the format string
                    FormatString::from_string(format.clone()).with_context(|_| {
                        elf_symbol_parse_error::TemplateParseSnafu { template: format }
                    })?,
                    Location {
                        file: Arc::from(file),
                        line: line
                            .parse()
                            .context(elf_symbol_parse_error::InvalidIntegerSnafu)?,
                    },
                    get_severity_level(&x)?,
                ))
            })()
            .context(ElfSymbolParseSnafu {
                name: x.name.to_string(),
            })
        })
        // Then convert into the message map
        .map_ok(|x| (x.id(), x))
        .collect::<Result<ULogMessageMap, _>>()?;

    // Handling of arguments and saving those arguments into the approriate messages
    {
        let mut ulog_arguments = get_ulog_section("argument")?
            .into_iter()
            .map(|sym| {
                (|| -> Result<((MessageIdentifier, usize), ULogArgument), _> {
                    // Split into file, line, format string, "arg", and a sequential id
                    let segments = split_segments(sym.name, '_')
                        .context(elf_symbol_parse_error::SplitSegmentSnafu)?;
                    let [file, line, format, constant_arg, id] =
                        segments.try_into().map_err(|x: Vec<_>| {
                            elf_symbol_parse_error::SegmentCountMismatchSnafu {
                                expected: 4usize,
                                actual: x.len(),
                            }
                            .build()
                        })?;
                    // If this happens, the file is corrupt
                    if constant_arg != "arg" {
                        return elf_symbol_parse_error::NonArgumentInArgumentsSnafu.fail();
                    }

                    // Get the type id for the argument
                    let type_id = endianness
                        .parse_u8_at(&mut (sym.symbol.st_value as usize), &section_data)
                        .context(elf_symbol_parse_error::ElfParseSnafu)?;
                    // Turn that type id into the actual argument
                    let argument = ULogArgument::try_from(type_id)
                        .context(elf_symbol_parse_error::ULogArgumentParseSnafu)?;

                    // Store the argument in a tuple for sorting
                    Ok((
                        (
                            MessageIdentifier(
                                Location {
                                    file: Arc::from(file),
                                    line: line
                                        .parse()
                                        .context(elf_symbol_parse_error::InvalidIntegerSnafu)?,
                                },
                                format,
                            ),
                            // We keep the sequential id around to make sure the compiler emitted the symbols in the order of declaration
                            id.parse()
                                .context(elf_symbol_parse_error::InvalidIntegerSnafu)?,
                        ),
                        argument,
                    ))
                })()
                .context(ElfSymbolParseSnafu {
                    name: sym.name.to_string(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        ulog_arguments.sort_unstable_by(|a, b| a.0.cmp(&b.0));

        // Sorts all messages by declaration location, this lets us efficiently map arguments to their message
        let mut ulog_messages = ulog_messages
            .values_mut()
            .map(|x| {
                (
                    MessageIdentifier(x.location().clone(), x.format().to_string()),
                    x,
                )
            })
            .sorted_unstable_by(|a, b| a.0.cmp(&b.0))
            .peekable();

        // We no longer need the sequential id so drop it
        let mut ulog_arguments = ulog_arguments.into_iter().map(|((id, _), arg)| (id, arg));

        // Loop through every argument to attribute it to a message
        loop {
            let (message_id, argument) = match ulog_arguments.next() {
                // We processed all arguments
                None => break,
                // Next one to process
                Some(x) => x,
            };

            // Find the message this argument belongs to
            let message = loop {
                match ulog_messages.peek_mut() {
                    // This should never happen on a well formatted file, we still have arguments but no messages to put those arguments in
                    // This implies we managed to define arguments on a message that doesnt exist
                    None => {
                        return elf_symbol_parse_error::OrphanedArgumentsSnafu {}
                            .fail()
                            .context(ElfSymbolParseSnafu {
                                name: format!("{:?}", message_id),
                            });
                    }
                    // Found it
                    Some(x) if x.0 == message_id => break &mut x.1,
                    // Skip this message, its not the right one
                    _ => {
                        ulog_messages.next();
                        continue;
                    }
                };
            };

            // Add the argument on the message definition
            message.arguments_mut().push(argument);
        }
    };

    // Get the meta section for the system id
    let ulog_meta = get_ulog_section("meta")?;
    // Get the system id symbol
    let system_id = ulog_meta
        .iter()
        .find(|x| x.name == "system_id")
        .context(NoSystemIdSnafu)?;
    // And read that symbol from the section
    let system_id = endianness
        .parse_u16_at(&mut (system_id.symbol.st_value as usize), &section_data)
        .context(ElfParseSnafu)?;

    Ok(ULogSystemInfo::new(ulog_strings, ulog_messages, system_id))
}
