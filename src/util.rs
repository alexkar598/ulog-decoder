/// Takes a byte slice and returns a hexdump in a string
pub fn hexdump(data: &[u8]) -> String {
    let mut buffer = Vec::new();
    hxdmp::hexdump(data, &mut buffer).expect("Failed to hexdump");
    String::from_utf8_lossy(&buffer).to_string()
}
