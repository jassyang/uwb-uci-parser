# UWB UCI Parser

A Python parser for Ultra-Wideband (UWB) Universal Control Interface (UCI) protocol commands. This tool helps decode and analyze UCI commands used in UWB communication systems.

## Features

- Parse UCI commands from hex strings
- Support multiple message types (Core/Session/Ranging/Data Control)
- Parse antenna configurations (RX/TX)
- Decode device information and application parameters
- Built-in error handling and logging
- Command-line interface for interactive usage

## Requirements

- Python 3.7+
- No external dependencies

## Usage

### Command Line
```bash
python uwb_uci_parser.py
```

### As Python Module
```python
from uwb_uci_parser import UCICommandParser

# Parse UCI command
hex_command = "21000005783508440000"
result = UCICommandParser.parse_hex_command(hex_command)
print(result)
```

### Example Output
```python
{
    "Message_Type": "COMMAND",
    "Group": "CORE (GID: 0)",
    "Command": "DEVICE_RESET (OID: 0)",
    "Packet_Boundary_Flag": True,
    "Extended": False,
    "Payload_Size": 5
}
```

## License

MIT License - see the [LICENSE](LICENSE) file for details.
