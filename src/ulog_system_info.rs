use crate::ulog_message::ULogMessageMap;
use crate::ulog_string::ULogStringMap;

/// Struct representing a system, each elf file maps to 1 system
#[derive(Debug, Clone)]
pub struct ULogSystemInfo {
    /// All user strings in the elf file
    ulog_strings: ULogStringMap,
    /// All messages defined in the elf file
    messages: ULogMessageMap,
    /// System id for this system
    system_id: u16,
}

impl ULogSystemInfo {
    pub fn new(ulog_strings: ULogStringMap, messages: ULogMessageMap, system_id: u16) -> Self {
        Self {
            ulog_strings,
            messages,
            system_id,
        }
    }

    pub fn ulog_strings(&self) -> &ULogStringMap {
        &self.ulog_strings
    }

    pub fn messages(&self) -> &ULogMessageMap {
        &self.messages
    }

    pub fn system_id(&self) -> u16 {
        self.system_id
    }
}
