#![allow(unused_variables)]

use snafu::{Backtrace, OptionExt, ResultExt, Snafu};
use unescaper::unescape;

#[derive(Snafu, Debug)]
pub enum SplitSegmentError {
    #[snafu(display("delim must be an ascii character"))]
    NonAsciiDelim { backtrace: Backtrace },
    #[snafu(display("Unbalanced quotes"))]
    UnbalancedQuotes { backtrace: Backtrace },
    #[snafu(display("Quotes do not encompass the entire field"))]
    PartiallyQuotedField { backtrace: Backtrace },
    #[snafu(display("Invalid escape sequence"))]
    UnescapeError {
        backtrace: Backtrace,
        source: unescaper::Error,
    },
}

/// Split off a segment off a delimited string, if quoted, unescapes the value.
/// The first value of the tuple is that segment, and the second value is the rest of the string
/// or None if this was the last field
fn split_segment_once(
    string: &str,
    delim: char,
) -> Result<(String, Option<&str>), SplitSegmentError> {
    // We make the assumption that we can turn the delimiter to a byte, so it needs to be ascii
    if !delim.is_ascii() {
        return NonAsciiDelimSnafu.fail();
    }

    // If the input string is empty, we assume that its a single segment string
    if string.is_empty() {
        return Ok(("".to_string(), None));
    }

    // Helper function to find the next quote with an even number of backslashes in front of it
    // (to allow escaping quotes in the string)
    let find_next_quote = |start: usize| {
        // Start looking at start
        let mut quote_location = start;
        loop {
            // We reached the end and didn't find it
            if quote_location >= string.len() {
                return None;
            }

            // Candidate location
            quote_location += string[quote_location..].find("\"")?;

            // Count parity of any backslash coming before
            let mut i = quote_location;
            let mut quote_escaped = false;
            while i > 1 {
                if string.as_bytes()[i - 1] == b'\\' {
                    // Flip parity
                    quote_escaped = !quote_escaped;
                } else {
                    // Terminate loop when we encounter a non backslash
                    break;
                }
                // Continue checking
                i -= 1;
            }

            // If the quote is escaped, we move onto the next one
            if quote_escaped {
                quote_location += 1;
                continue;
            }

            // Found an unescaped quote
            return Some(quote_location);
        }
    };

    // In this case, the segment is not quoted
    if string.as_bytes()[0] != b'"' {
        // Unquoted segment, we just find the next delim and use that
        let segment_end = string.find(delim).unwrap_or(string.len());
        let (segment, rest) = string.split_at(segment_end);

        // If we captured nothing, there's no delim and its over, otherwise, remove the delim
        let rest = if rest.is_empty() {
            None
        } else {
            Some(&rest[1..])
        };

        Ok((segment.to_string(), rest))
    } else {
        // Find the closing quote for the quoted segment
        let end_quote = find_next_quote(1).context(UnbalancedQuotesSnafu)?;
        let (mut segment, mut rest) = string.split_at(end_quote);
        // Remove the quote
        if rest.as_bytes().get(1).is_some_and(|x| *x != delim as u8) {
            return PartiallyQuotedFieldSnafu.fail();
        }
        // Strip quotes
        segment = &segment[1..];
        rest = &rest[1..];

        // If we captured nothing, there's no delim and its over, otherwise, remove the delim
        let rest = if rest.is_empty() {
            None
        } else {
            Some(&rest[1..])
        };

        // Unescape the value
        Ok((unescape(segment).context(UnescapeSnafu)?, rest))
    }
}

/// Split a delimited string of possibly escaped segments into a vector of segments
pub fn split_segments(string: &str, delim: char) -> Result<Vec<String>, SplitSegmentError> {
    let mut string = Some(string);
    let mut result = vec![];
    loop {
        match string {
            // We reached the end of the string
            None => break,
            Some(x) => {
                // Split off a segment
                let (segment, rest) = split_segment_once(x, delim)?;
                // And push it
                result.push(segment);
                string = rest;
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    type DynResult = Result<(), Box<dyn Error>>;

    use crate::splitter::{split_segment_once, split_segments};
    use std::error::Error;

    #[test]
    fn simple() -> DynResult {
        let x = split_segment_once(r#"14_meow_womp"#, '_')?;
        assert_eq!(x, ("14".to_string(), Some("meow_womp")));
        Ok(())
    }

    #[test]
    fn entire() -> DynResult {
        let x = split_segment_once(r#"1234"#, '_')?;
        assert_eq!(x, ("1234".to_string(), None));
        Ok(())
    }

    #[test]
    fn trailing() -> DynResult {
        let x = split_segment_once(r#"1234_"#, '_')?;
        assert_eq!(x, ("1234".to_string(), Some("")));
        Ok(())
    }

    #[test]
    fn quoted() -> DynResult {
        let x = split_segment_once(r#""14_meow"_whoa"#, '_')?;
        assert_eq!(x, ("14_meow".to_string(), Some("whoa")));
        Ok(())
    }

    #[test]
    fn quoted_entire() -> DynResult {
        let x = split_segment_once(r#""14_meow""#, '_')?;
        assert_eq!(x, ("14_meow".to_string(), None));
        Ok(())
    }

    #[test]
    fn quoted_trailing() -> DynResult {
        let x = split_segment_once(r#""14_meow"_"#, '_')?;
        assert_eq!(x, ("14_meow".to_string(), Some("")));
        Ok(())
    }

    #[test]
    fn empty() -> DynResult {
        let x = split_segment_once(r#""#, '_')?;
        assert_eq!(x, ("".to_string(), None));
        Ok(())
    }

    #[test]
    #[should_panic = "NonAsciiDelim"]
    fn error_non_ascii() {
        let x = split_segment_once(r#"meow"#, '😂').unwrap();
    }

    #[test]
    fn segments() -> DynResult {
        let x = split_segments(r#"123_45_6___"me_ow\"_"_"#, '_')?;
        assert_eq!(x, vec!["123", "45", "6", "", "", "me_ow\"_", ""]);
        Ok(())
    }
}
