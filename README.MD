# uLog Decoder

Decoder for uLog, see https://github.com/alexkar598/ulog for more information.

## Usage

```
Utility to parse and decode uLog entries

Usage: ulog-decoder [OPTIONS] <MAP_FILES>...

Arguments:
  <MAP_FILES>...  Path to ELF file containing a uLog map

Options:
  -h, --help  Print help

Stdin Source:
  -i, --from-stdin  Use standard input as the uLog stream source [default]

File Source:
  -f, --from-file <FILE>  Use <FILE> as the uLog stream source

Serial Source:
  -s, --from-serial [<PORT>]  Use serial port <PORT> as the uLog stream source. If <PORT> is unspecified, an attempt at automatically selected one will be made [default: auto]
  -b, --baudrate <BAUDRATE>   Baud rate to use when opening a serial port [default: 38400]
  -l, --list-ports            List detected serial ports and exit
```