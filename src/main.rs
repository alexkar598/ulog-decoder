pub mod elf;
pub mod location;
pub mod severity;
mod splitter;
pub mod ulog_argument;
pub mod ulog_message;
pub mod ulog_string;
pub mod ulog_system_info;
mod util;

use crate::elf::{ElfParseError, attempt_load_elf};
use crate::ulog_argument::ULogArgumentReadError;
use crate::ulog_message::ULogMessageFormatError;
use crate::ulog_system_info::ULogSystemInfo;
use crate::util::hexdump;
use byteorder::{BE, ReadBytesExt};
use clap::ValueHint;
use clap::{Args, Parser};
use color_backtrace::BacktracePrinter;
use serialport::{SerialPortInfo, SerialPortType};
use snafu::{Backtrace, ErrorCompat, OptionExt, Report, ResultExt, Snafu};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, stdin};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Snafu, Debug)]
pub enum ULogDecoderError {
    #[snafu(display("Failed to open source file ({file})"))]
    FileSourceOpen {
        backtrace: Backtrace,
        source: std::io::Error,
        file: String,
    },
    #[snafu(display("Failed to open serial port ({port})"))]
    SerialSourceOpen {
        backtrace: Backtrace,
        source: serialport::Error,
        port: String,
    },
    #[snafu(display("Failed to find a serial source port"))]
    NoSerialSource { backtrace: Backtrace },
    #[snafu(display("Failed to load ELF file ({file})"))]
    ELFLoad {
        file: String,
        #[snafu(backtrace)]
        #[snafu(source(from(ElfParseError, Box::new)))]
        source: Box<ElfParseError>,
    },
    #[snafu(display("Failed to read entry"))]
    EntryRead {
        backtrace: Backtrace,
        source: std::io::Error,
    },
    #[snafu(display("Failed to decode rzcobs frame"))]
    Rzcobs { backtrace: Backtrace },
    #[snafu(display("Failed to read system id"))]
    SystemIdRead {
        backtrace: Backtrace,
        source: std::io::Error,
    },
    #[snafu(display("Failed to read message id"))]
    MessageIdRead {
        backtrace: Backtrace,
        source: std::io::Error,
    },
    #[snafu(display("Message not found!"))]
    UnknownMessage { backtrace: Backtrace },
    #[snafu(display("System not found!"))]
    UnknownSystem { backtrace: Backtrace },
    #[snafu(display("Failed to decode arguments"))]
    ArgumentDecode {
        #[snafu(backtrace)]
        source: ULogArgumentReadError,
    },
    #[snafu(display("Failed to format message"))]
    Format {
        #[snafu(backtrace)]
        source: ULogMessageFormatError,
    },
    #[snafu(display(
        "Failed to load {file} because the system id {system_id:x} is already in use"
    ))]
    DuplicateSystemId {
        backtrace: Backtrace,
        system_id: u16,
        file: String,
    },
}

/// Prints the backtrace assosicated with an error, if there is one
fn print_backtrace(err: &impl ErrorCompat) {
    if let Some(bt) = err.backtrace() {
        let bt_printer = BacktracePrinter::new().strip_function_hash(true);

        bt_printer
            .print_trace(bt, &mut color_backtrace::default_output_stream())
            .expect("Failed to print backtrace");
    }
}

#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct CliArgs {
    /// Path to ELF file containing a uLog map
    #[arg(required = true)]
    map_files: Vec<String>,
    #[command(flatten)]
    source: SourceArgs,
    /// Baud rate to use when opening a serial port
    #[arg(
        short = 'b',
        long,
        default_value_t = 38400,
        help_heading = "Serial Source"
    )]
    baudrate: u32,
    /// List detected serial ports and exit
    #[arg(short = 'l', long, exclusive = true, help_heading = "Serial Source")]
    list_ports: bool,
}

#[derive(Args, Debug)]
#[group(required = false, multiple = false)]
struct SourceArgs {
    /// Use standard input as the uLog stream source [default]
    #[arg(short = 'i', long, help_heading = "Stdin Source")]
    from_stdin: bool,
    /// Use <FILE> as the uLog stream source
    #[arg(short = 'f', long, value_hint = ValueHint::FilePath, help_heading = "File Source", value_name = "FILE")]
    from_file: Option<String>,
    /// Use serial port <PORT> as the uLog stream source. If <PORT> is unspecified, an attempt at automatically selected one will be made [default: auto]
    #[arg(
        short = 's',
        long,
        help_heading = "Serial Source",
        value_name = "PORT",
        num_args = 0..=1,
        default_missing_value = "auto"
    )]
    from_serial: Option<String>,
}

/// Wrapper around main_inner() with error handling for fatal errors
fn main() {
    if let Err(err) = &main_inner() {
        eprintln!("An error occurred: {}", Report::from_error(err));
        print_backtrace(&err);
    }
}

/// Gets a sorted list of all detected serial ports
fn get_serial_ports() -> Vec<SerialPortInfo> {
    let mut ports = serialport::available_ports().unwrap_or_default();
    ports.sort_by(|a, b| {
        // Send unknowns down at the bottom
        matches!(a.port_type, SerialPortType::Unknown)
            .cmp(&matches!(b.port_type, SerialPortType::Unknown))
    });
    ports
}

fn main_inner() -> Result<(), ULogDecoderError> {
    let args = CliArgs::parse();

    // Special mode: list serial ports and exit
    if args.list_ports {
        for p in get_serial_ports() {
            println!("- {}", p.port_name);
        }
        return Ok(());
    }

    // Squash down all possible readers into a Box<dyn BufRead>
    let mut reader: Box<dyn BufRead> = match (
        args.source.from_file,
        args.source.from_stdin,
        args.source.from_serial,
    ) {
        // Source: File
        (Some(file), _, _) => {
            println!("Source: file {file}\n\n");
            Box::new(BufReader::new(
                File::open(&file).with_context(|_| FileSourceOpenSnafu { file })?,
            ))
        }
        // Source: serial
        (_, _, Some(port)) => {
            let mut port = port;
            // Replace auto by the first detected serial port
            if port == "auto" {
                port = get_serial_ports()
                    .first()
                    .ok_or(NoSerialSourceSnafu.build())?
                    .port_name
                    .clone()
            }
            println!("Source: serial port {port} {}\n\n", args.baudrate);
            Box::new(BufReader::new(
                serialport::new(&port, args.baudrate)
                    // Timeout is important as by default we timeout immediately if reading when theres no data ready
                    .timeout(Duration::MAX)
                    .open()
                    .with_context(|_| SerialSourceOpenSnafu { port })?,
            ))
        }
        // Source: stdin, default
        (_, true, _) | (None, false, None) => {
            println!("Source: stdin\n\n");
            Box::new(stdin().lock())
        }
    };

    // Load all files into a hashmap with the system id
    let mut systems = HashMap::<u16, ULogSystemInfo>::new();
    for map_file in &args.map_files {
        let system = attempt_load_elf(&PathBuf::from(map_file))
            .with_context(|_| ELFLoadSnafu { file: map_file })?;

        // duplicate is Some when there already is an entry in the map, we want to error out if this is the case
        let duplicate = systems.insert(system.system_id(), system);
        if let Some(duplicate) = duplicate {
            return DuplicateSystemIdSnafu {
                system_id: duplicate.system_id(),
                file: map_file,
            }
            .fail();
        }
    }

    // main message handling loop
    let mut buf = vec![];
    loop {
        // Hoist data and message to print it out if theres an error
        let mut data = None;
        let mut message = None;

        // Handler is in a closure to not die if a single message fails to parse
        // Returns true when EOF is reached
        let result = (|| -> Result<bool, ULogDecoderError> {
            // Clear out the previous message
            buf.clear();

            // All rzcobs frames are delimited with a null byte
            {
                let result = reader.read_until(0x00, &mut buf);
                if result
                    .as_ref()
                    .is_err_and(|err| err.kind() == std::io::ErrorKind::TimedOut)
                {
                    // We ignore timeout errors and silently try again
                    return Ok(false);
                }
                result.context(EntryReadSnafu)?;
            }

            // Handle EOFFf by early returning with true to request exit
            if buf.is_empty() {
                return Ok(true);
            }

            // Rzcobs decode the message
            data = Some(rzcobs::decode(&buf[0..(buf.len() - 1)]).map_err(|_| RzcobsSnafu.build())?);
            // Funky ref taking because the read_* functions want a mut ref to a ref which is awkward
            let data = &mut (&data.as_ref().unwrap()[..]);

            // Get the system and message id
            let system_id = data.read_u16::<BE>().context(SystemIdReadSnafu)?;
            let message_id = data.read_u16::<BE>().context(MessageIdReadSnafu)?;

            // Find the system from the system map
            let system = systems.get(&system_id).context(UnknownSystemSnafu)?;

            // Get the message template from the system's message map
            message = Some(
                system
                    .messages()
                    .get(&message_id)
                    .context(UnknownMessageSnafu)?,
            );
            // Unwrap is safe here because we just now set it to Some
            let message = message.as_mut().unwrap();

            // Let the message read in its arguments
            let formatted_message = message
                .formatted_string(data, system.ulog_strings())
                .context(FormatSnafu)?;

            // Format and print the message
            println!(
                "[{:#}] {}\n    From: 0x{:X?}(file://{}:{})",
                message.severity_level(),
                formatted_message,
                system_id,
                message.location().file,
                message.location().line
            );
            Ok(false)
        })();

        // EOF was reached, break
        if result.as_ref().is_ok_and(|x| *x) {
            break;
        }

        // Error during message read
        if let Err(err) = &result {
            eprintln!(
                "An error occurred processing a log entry: {}",
                Report::from_error(err)
            );
            // If we have the parsed message, print whatever we managed to parse so far
            eprintln!("{:━^80}\n{:#?}", " PARSED ENTRY ", &message);
            // And the rzcobs decoded message
            eprintln!(
                "{:━^80}\n{}",
                " DECODED ENTRY ",
                data.as_deref().map(hexdump).unwrap_or("None".to_string())
            );
            // Then the raw entry in the event all else fails
            eprintln!("{:━^80}\n{}", " RAW ENTRY ", hexdump(&buf));
            print_backtrace(&err);
        }
    }

    Ok(())
}
