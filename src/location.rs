use std::sync::Arc;

/// Simple struct that represents a location in a file
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Location {
    pub file: Arc<String>,
    pub line: usize,
}
