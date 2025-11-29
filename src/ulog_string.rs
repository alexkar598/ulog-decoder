use crate::location::Location;
use std::collections::HashMap;
use std::sync::Arc;

/// User defined ulog string
#[derive(Debug, Clone)]
pub struct ULogString {
    /// Id of the string
    id: u16,
    /// Actual value of the string
    string: Arc<String>,
    /// Location where the string was defined
    location: Location,
}

pub type ULogStringMap = HashMap<u16, ULogString>;

impl ULogString {
    pub fn new(id: u16, string: String, location: Location) -> Self {
        Self {
            id,
            string: Arc::from(string),
            location,
        }
    }

    pub fn id(&self) -> u16 {
        self.id
    }

    pub fn string(&self) -> &Arc<String> {
        &self.string
    }

    pub fn location(&self) -> &Location {
        &self.location
    }
}
