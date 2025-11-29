use crate::ulog_string::ULogStringMap;
use byteorder::{BE, ReadBytesExt};
use dyf::{DynDisplay, Error, FormatSpec};
use snafu::{Backtrace, OptionExt, ResultExt, Snafu};
use std::fmt::Debug;
use std::io::BufRead;
use std::sync::Arc;

/// Sum enum of all possible argument types.
/// Integer types have a size field denoting the size in bytes of the type
/// All types will have a value field with an option for the value. This should be None when
/// loading from the elf file
#[derive(Debug, Clone)]
pub enum ULogArgument {
    //                                          //Type Id
    Slice { value: Option<Vec<u8>> },           //1
    Float { value: Option<f32> },               //2
    Double { value: Option<f64> },              //3
    String { value: Option<String> },           //4
    Bool { value: Option<bool> },               //5
    ULogString { value: Option<Arc<String>> },  //6
    Int8 { value: Option<i8> },                 //240
    Int16 { value: Option<i16> },               //241
    Int32 { size: usize, value: Option<i32> },  //242-243
    Int64 { size: usize, value: Option<i64> },  //244-247
    UInt8 { value: Option<u8> },                //248
    UInt16 { value: Option<u16> },              //249
    UInt32 { size: usize, value: Option<u32> }, //250-251
    UInt64 { size: usize, value: Option<u64> }, //252-255
}

#[derive(Snafu, Debug)]
pub enum ULogArgumentReadError {
    #[snafu(display("The string Id is not present in the string table"))]
    MissingStringId { backtrace: Backtrace },
    #[snafu(display("An Io error occurred"))]
    Io {
        backtrace: Backtrace,
        source: std::io::Error,
    },
}

impl ULogArgument {
    /// Populates the value field with the value from a byte stream
    pub fn read(
        &mut self,
        reader: &mut impl BufRead,
        string_map: &ULogStringMap,
    ) -> Result<(), ULogArgumentReadError> {
        match self {
            // Format: (size: u32, data[size]: u8)
            ULogArgument::Slice { value } => {
                let size = reader.read_u32::<BE>().context(IoSnafu)?;
                let mut data = vec![0; size as usize];
                reader.read_exact(data.as_mut_slice()).context(IoSnafu)?;
                *value = Some(data);
            }
            // Format: f32
            ULogArgument::Float { value } => {
                *value = Some(reader.read_f32::<BE>().context(IoSnafu)?);
            }
            // Format: f64
            ULogArgument::Double { value } => {
                *value = Some(reader.read_f64::<BE>().context(IoSnafu)?);
            }
            // Format: null delimited c string
            ULogArgument::String { value } => {
                let mut string = vec![];
                reader.read_until(0x00, &mut string).context(IoSnafu)?;
                *value = Some(String::from_utf8_lossy(&string[0..(string.len() - 1)]).to_string());
            }
            // Format: u8
            ULogArgument::Bool { value } => {
                *value = Some(reader.read_u8().context(IoSnafu)? != 0x00);
            }
            // Format: (ulog_string_id: u16)
            ULogArgument::ULogString { value } => {
                let string_id = reader.read_u16::<BE>().context(IoSnafu)?;
                *value = Some(
                    string_map
                        .get(&string_id)
                        .context(MissingStringIdSnafu)?
                        .string()
                        .clone(),
                );
            }
            // Format: i8
            ULogArgument::Int8 { value } => {
                *value = Some(reader.read_i8().context(IoSnafu)?);
            }
            // Format: i16
            ULogArgument::Int16 { value } => {
                *value = Some(reader.read_i16::<BE>().context(IoSnafu)?);
            }
            // Format: i24 or i32
            ULogArgument::Int32 { size, value } => {
                // We cant have an actual i24, so we pad out an i32 with 0 bytes then sign extend
                let size = *size;
                let mut buf = vec![0u8; size];
                let empty_bytes = 4 - size;
                reader
                    .read_exact(&mut buf[empty_bytes..])
                    .context(IoSnafu)?;
                if buf[empty_bytes] & 0b1000_0000 > 0 {
                    buf[0..empty_bytes].fill(0xFF);
                }
                *value = Some(buf.as_slice().read_i32::<BE>().context(IoSnafu)?);
            }
            // Format: i40, i48, i56 or i64
            ULogArgument::Int64 { size, value } => {
                // We cant have an actual i40, so we pad out an i64 with 0 bytes then sign extend
                let size = *size;
                let mut buf = vec![0u8; size];
                let empty_bytes = 8 - size;
                reader
                    .read_exact(&mut buf[empty_bytes..])
                    .context(IoSnafu)?;
                if buf[empty_bytes] & 0b1000_0000 > 0 {
                    buf[0..empty_bytes].fill(0xFF);
                }
                *value = Some(buf.as_slice().read_i64::<BE>().context(IoSnafu)?);
            }
            // Format: u8
            ULogArgument::UInt8 { value } => {
                *value = Some(reader.read_u8().context(IoSnafu)?);
            }
            // Format: u16
            ULogArgument::UInt16 { value } => {
                *value = Some(reader.read_u16::<BE>().context(IoSnafu)?);
            }
            // Format: u24 or u32
            ULogArgument::UInt32 { size, value } => {
                // We cant have an actual u24, so we pad out a u32 with 0 bytes
                let size = *size;
                let mut buf = vec![0u8; size];
                let empty_bytes = 4 - size;
                reader
                    .read_exact(&mut buf[empty_bytes..])
                    .context(IoSnafu)?;
                *value = Some(buf.as_slice().read_u32::<BE>().context(IoSnafu)?);
            }
            // Format: u40, u48, u56 or u64
            ULogArgument::UInt64 { size, value } => {
                // We cant have an actual u40, so we pad out a u64 with 0 bytes
                let size = *size;
                let mut buf = vec![0u8; size];
                let empty_bytes = 8 - size;
                reader
                    .read_exact(&mut buf[empty_bytes..])
                    .context(IoSnafu)?;
                *value = Some(buf.as_slice().read_u64::<BE>().context(IoSnafu)?);
            }
        };

        Ok(())
    }
}

#[derive(Snafu, Debug)]
pub enum ULogArgumentParseError {
    #[snafu(display("Invalid type id {id}"))]
    InvalidTypeId { backtrace: Backtrace, id: u8 },
}
impl TryFrom<u8> for ULogArgument {
    type Error = ULogArgumentParseError;

    /// Converts an integer type id to a skeleton argument
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use crate::ulog_argument::ULogArgument::*;

        let arg = match value {
            1 => Slice { value: None },
            2 => Float { value: None },
            3 => Double { value: None },
            4 => String { value: None },
            5 => Bool { value: None },
            6 => ULogString { value: None },
            240 => Int8 { value: None },
            241 => Int16 { value: None },
            // The weirder integer types are merged into the more common ones
            x @ 242..=243 => Int32 {
                size: (x - 239) as usize,
                value: None,
            },
            x @ 244..=247 => Int64 {
                size: (x - 239) as usize,
                value: None,
            },
            248 => UInt8 { value: None },
            249 => UInt16 { value: None },
            x @ 250..=251 => UInt32 {
                size: (x - 247) as usize,
                value: None,
            },
            x @ 252..=255 => UInt64 {
                size: (x - 247) as usize,
                value: None,
            },
            x => return InvalidTypeIdSnafu { id: x }.fail(),
        };
        Ok(arg)
    }
}

impl DynDisplay for ULogArgument {
    /// Formats the argument value to be printed as part of a message
    fn dyn_fmt(&self, f: &FormatSpec) -> Result<String, Error> {
        match self {
            ULogArgument::Slice { value } => value
                .as_ref()
                .map(|x| format!("{x:x?}").dyn_fmt(f))
                .unwrap_or_else(|| "(nil)".dyn_fmt(f)),
            ULogArgument::Float { value } => value
                .as_ref()
                .map(|x| x.dyn_fmt(f))
                .unwrap_or_else(|| "(nil)".dyn_fmt(f)),
            ULogArgument::Double { value } => value
                .as_ref()
                .map(|x| x.dyn_fmt(f))
                .unwrap_or_else(|| "(nil)".dyn_fmt(f)),
            ULogArgument::String { value } => value
                .as_ref()
                .map(|x| x.dyn_fmt(f))
                .unwrap_or_else(|| "(nil)".dyn_fmt(f)),
            ULogArgument::Bool { value } => value
                .as_ref()
                .map(|x| x.dyn_fmt(f))
                .unwrap_or_else(|| "(nil)".dyn_fmt(f)),
            ULogArgument::ULogString { value } => value
                .as_ref()
                .map(|x| x.dyn_fmt(f))
                .unwrap_or_else(|| "(nil)".dyn_fmt(f)),
            ULogArgument::Int8 { value } => value
                .as_ref()
                .map(|x| x.dyn_fmt(f))
                .unwrap_or_else(|| "(nil)".dyn_fmt(f)),
            ULogArgument::Int16 { value } => value
                .as_ref()
                .map(|x| x.dyn_fmt(f))
                .unwrap_or_else(|| "(nil)".dyn_fmt(f)),
            ULogArgument::Int32 { size: _, value } => value
                .as_ref()
                .map(|x| x.dyn_fmt(f))
                .unwrap_or_else(|| "(nil)".dyn_fmt(f)),
            ULogArgument::Int64 { size: _, value } => value
                .as_ref()
                .map(|x| x.dyn_fmt(f))
                .unwrap_or_else(|| "(nil)".dyn_fmt(f)),
            ULogArgument::UInt8 { value } => value
                .as_ref()
                .map(|x| x.dyn_fmt(f))
                .unwrap_or_else(|| "(nil)".dyn_fmt(f)),
            ULogArgument::UInt16 { value } => value
                .as_ref()
                .map(|x| x.dyn_fmt(f))
                .unwrap_or_else(|| "(nil)".dyn_fmt(f)),
            ULogArgument::UInt32 { size: _, value } => value
                .as_ref()
                .map(|x| x.dyn_fmt(f))
                .unwrap_or_else(|| "(nil)".dyn_fmt(f)),
            ULogArgument::UInt64 { size: _, value } => value
                .as_ref()
                .map(|x| x.dyn_fmt(f))
                .unwrap_or_else(|| "(nil)".dyn_fmt(f)),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ulog_argument::ULogArgument;
    use assert_matches::assert_matches;
    use std::error::Error;

    #[test]
    pub fn test_32() -> Result<(), Box<dyn Error>> {
        assert_matches!(
            ULogArgument::try_from(242)?,
            ULogArgument::Int32 { size: 3, .. }
        );
        assert_matches!(
            ULogArgument::try_from(243)?,
            ULogArgument::Int32 { size: 4, .. }
        );
        assert_matches!(
            ULogArgument::try_from(250)?,
            ULogArgument::UInt32 { size: 3, .. }
        );
        assert_matches!(
            ULogArgument::try_from(251)?,
            ULogArgument::UInt32 { size: 4, .. }
        );
        Ok(())
    }

    #[test]
    #[should_panic = "Invalid type id 239"]
    pub fn invalid_id() {
        ULogArgument::try_from(239).unwrap();
    }
}
