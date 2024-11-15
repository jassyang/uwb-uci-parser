from dataclasses import dataclass
from enum import IntEnum
from typing import Dict, List, Optional, Union
import logging
from functools import lru_cache

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MessageType(IntEnum):
    """UCI Message Types"""
    DATA = 0
    COMMAND = 1
    RESPONSE = 2
    NOTIFICATION = 3

class GroupID(IntEnum):
    """UCI Group IDs"""
    CORE = 0
    SESSION = 1
    RANGING = 2
    DATA_CTRL = 3
    DATA_CTRL_2 = 9
    TEST = 13
    PROPRIETARY = 14

class Status(IntEnum):
    """UCI Status Codes"""
    OK = 0x00
    REJECTED = 0x01
    FAILED = 0x02
    SYNTAX_ERROR = 0x03
    INVALID_PARAM = 0x04
    INVALID_RANGE = 0x05
    INVALID_MESSAGE_SIZE = 0x06
    UNKNOWN_GID = 0x07
    UNKNOWN_OID = 0x08
    READ_ONLY = 0x09
    CMD_RETRY = 0x0A

class RangingStatus(IntEnum):
    """Ranging Status Codes"""
    SUCCESS = 0x00
    FAILURE = 0x01
    TIMEOUT = 0x02
    INVALID_SESSION = 0x03
    SESSION_NOT_EXIST = 0x11
    SESSION_NOT_CONFIGURED = 0x12
    ACTIVE_SESSIONS_ONGOING = 0x16

@dataclass
class UCIMessage:
    """Data class for UCI message components"""
    message_type: MessageType
    group_id: GroupID
    operation_id: int
    pbf: bool
    extended: bool
    payload_size: int
    payload: Optional[bytes] = None
    parsed_data: Optional[Dict] = None

class UCICommandParser:
    """Enhanced UCI Command Parser with improved structure and performance"""
    
    # Class constants moved to separate Enum classes where appropriate
    DEVICE_STATUS = {
        0: "STATUS_INIT",
        1: "STATUS_READY",
        2: "STATUS_ACTIVE",
        3: "STATUS_SE_BINDING_UNKNOWN",
        4: "STATUS_SE_UNBOUND",
        5: "STATUS_SE_BOUND_UNLOCKED",
        6: "STATUS_SE_BOUND_LOCKED",
        255: "STATUS_ERROR"
    }

    COMMANDS = {
        GroupID.CORE: {
            0: "DEVICE_RESET",
            1: "DEVICE_STATUS_NTF",
            2: "GET_DEV_INFO",
            3: "GET_CAPS_INFO",
            4: "SET_CONFIG",
            5: "GET_CONFIG",
            6: "DEV_SUSPEND",
            7: "GENERIC_ERROR_NTF"
        },
        GroupID.SESSION: {
            0: "SESSION_INIT",
            1: "SESSION_DEINIT",
            2: "SESSION_STATUS_NTF",
            3: "SET_APP_CONFIG",
            4: "GET_APP_CONFIG",
            5: "SESSION_GET_COUNT",
            6: "SESSION_GET_STATE",
            7: "SESSION_UPDATE_CONTROLLER_MULTICAST_LIST"
        },
        GroupID.RANGING: {
            0: "RANGE_START",
            1: "RANGE_STOP",
            2: "RANGE_INTERVAL_UPDATE_REQ",
            3: "RANGE_GET_RANGING_COUNT",
            4: "BLINK_DATA_TX",
            5: "RANGE_DATA",
            6: "RANGE_STATUS_NTF"
        }
    }

    DEVICE_TLV_TYPES = {
        0x00: "Device Vendor",
        0x01: "UCI Version",
        0x02: "MAC Address",
        0x03: "Manufacturer ID",
        0xA0: "Device Type",
        0xA1: "FW Version"
    }
    
    APP_CONFIG_PARAMS = {
        0x00: "Generic Parameter",
        0x02: "Channel Number",
        0x03: "Device Role",
        0x04: "Session Priority", 
        0x05: "MAC Address Mode",
        0x06: "Vendor ID",
        0x07: "Static STS IV",
        0x08: "Number of STS Segments",
        0x09: "Ranging Interval",
        0x0A: "SFD ID",
        0x0B: "STS Length",
        0x0C: "Number of Controlees",
        0x0D: "PSDU Data Rate",
        0x0E: "PREAMBLE_DURATION",
        0x0F: "RANGING_ROUND_USAGE",
        0x10: "STS_CONFIG",
        0x11: "MAC_FCS_TYPE",
        0x12: "RANGING_ROUND_CONTROL",
        0x13: "AOA_RESULT_REQ",
        0x14: "RANGE_DATA_NTF_CONFIG",
        0x15: "DEVICE_TYPE",
        0x16: "NUMBER_OF_RANGES",
        0x17: "MULTI_NODE_MODE",
        0x18: "BLOCK_STRIDE_LENGTH",
        0x19: "RESULT_REPORT_CONFIG",
        0x1A: "RANGE_DATA_NTF_PROXIMITY_NEAR",
        0xA0: "HOPPING_MODE",
        0xA1: "BLOCK_INDEX",
        0xA2: "UWB_CONFIG_ID",
        0xA3: "RANGING_MODE",
        0xA4: "SLOT_DURATION",
        0xA5: "SCHEDULE_MODE",
        0xA6: "KEY_ROTATION"
    }
    
    CORE_CONFIG_PARAMS = {
        0xE460: {
            "name": "ANTENNA_RX_IDX_DEFINE",
            "description": "Define/Create all antenna Identifier for RX"
        },
        0xE461: {
            "name": "ANTENNA_TX_IDX_DEFINE",
            "description": "Define/Create all antenna Identifier for TX"
        },        
        0xE462: {
            "name": "ANTENNAS_RX_PAIR_DEFINE",
            "description": "Define all RX Antennas Configuration"
        }
    }
    
    @staticmethod
    def _parse_antenna_tx_config(payload: bytes) -> Dict:
        """Parse ANTENNA_TX_IDX_DEFINE configuration"""
        num_entries = payload[0]  # 第一個字節是條目數
        entries = []
        
        offset = 1
        for _ in range(num_entries):
            entry = {
                "tx_antenna_id": payload[offset],
                "gpio_filter_mask": payload[offset + 1:offset + 3].hex(),
                "gpio_state": payload[offset + 3:offset + 5].hex()
            }
            entries.append(entry)
            offset += 5

        return {
            "number_of_entries": num_entries,
            "tx_antenna_configs": entries
        }
            
    @staticmethod
    def _parse_antenna_rx_config(payload: bytes) -> Dict:
        """Parse ANTENNA_RX_IDX_DEFINE configuration"""
        num_entries = payload[0]  # 第一個字節是條目數
        entries = []
        
        offset = 1
        for _ in range(num_entries):
            entry = {
                "rx_antenna_id": payload[offset],
                "receiver_used": "RX1" if payload[offset + 1] == 0x01 else "RX2",
                "gpio_filter_mask": payload[offset + 2:offset + 4].hex(),
                "gpio_state": payload[offset + 4:offset + 6].hex()
            }
            entries.append(entry)
            offset += 6

        return {
            "number_of_entries": num_entries,
            "antenna_configs": entries
        }
        
    @staticmethod
    def _parse_antennas_rx_pair_define(payload: bytes) -> Dict:
        """Parse ANTENNAS_RX_PAIR_DEFINE configuration"""
        num_entries = payload[0]  # 第一個字節是條目數
        entries = []
        
        offset = 1
        for _ in range(num_entries):
            entry = {
                "antenna_pair_id": payload[offset],
                "antenna_id_1": payload[offset + 1],  # RX1 Port
                "antenna_id_2": payload[offset + 2],  # RX2 Port
                "rfu": payload[offset + 3],           # Reserved for future use
                "reserved": payload[offset + 4:offset + 6].hex()  # Reserved bytes
            }
            entries.append(entry)
            offset += 6

        return {
            "number_of_entries": num_entries,
            "antenna_pairs": entries
        }        

    @staticmethod
    def _parse_core_config_payload(payload: bytes) -> Dict:
        """Parse CORE_SET_CONFIG payload"""
        num_params = payload[0]
        result = {
            "number_of_parameters": num_params,
            "parameters": []
        }
        
        offset = 1
        for _ in range(num_params):
            param_tag = (payload[offset] << 8) | payload[offset + 1]
            param_len = payload[offset + 2]
            param_value = payload[offset + 3:offset + 3 + param_len]
            
            param_info = {
                "tag": f"0x{param_tag:04X}",
                "length": param_len,
                "value": param_value.hex()
            }
            
            # 特殊處理ANTENNA_RX_IDX_DEFINE
            if param_tag == 0xE460:
                param_info["decoded"] = UCICommandParser._parse_antenna_rx_config(param_value)
                param_info["name"] = "ANTENNA_RX_IDX_DEFINE"
                
            if param_tag == 0xE461:
                param_info["decoded"] = UCICommandParser._parse_antenna_tx_config(param_value)
                param_info["name"] = "ANTENNA_TX_IDX_DEFINE"
                                
            if param_tag == 0xE462:
                param_info["decoded"] = UCICommandParser._parse_antennas_rx_pair_define(param_value)
                param_info["name"] = "ANTENNAS_RX_PAIR_DEFINE"
                        
            result["parameters"].append(param_info)
            offset += 3 + param_len

        return result
        
    @staticmethod
    def _parse_app_config(payload: bytes) -> Dict:
        """Parse SET_APP_CONFIG payload"""
        result = {"parameters": []}
        index = 0
        
        while index < len(payload):
            try:
                param_id = payload[index]
                param_len = payload[index + 1]
                param_value = payload[index + 2:index + 2 + param_len]
                
                param_name = UCICommandParser.APP_CONFIG_PARAMS.get(param_id, f"Unknown_Param_0x{param_id:02X}")
                
                param_info = {
                    "parameter": param_name,
                    "id": f"0x{param_id:02X}",
                    "length": param_len,
                    "value": param_value.hex()
                }
                
                result["parameters"].append(param_info)
                index += 2 + param_len
                
            except Exception as e:
                logger.error(f"Error parsing app config at index {index}: {str(e)}")
                break
                
        return result


    @staticmethod
    @lru_cache(maxsize=128)
    def get_group_name(gid: int) -> str:
        """Get group name from group ID with caching"""
        try:
            return GroupID(gid).name
        except ValueError:
            return f"UNKNOWN_GROUP_{gid}"

    @staticmethod
    @lru_cache(maxsize=128)
    def get_command_name(gid: int, oid: int) -> str:
        """Get command name from group ID and operation ID with caching"""
        try:
            return UCICommandParser.COMMANDS.get(GroupID(gid), {}).get(oid, f"UNKNOWN_COMMAND_{oid}")
        except ValueError:
            return f"UNKNOWN_COMMAND_{oid}"

    @staticmethod
    def _parse_ranging_payload(message: UCIMessage) -> Dict:
        """Parse ranging-specific payload"""
        if not message.payload:
            return {}

        result = {"raw_payload": message.payload.hex()}

        if message.operation_id == 0:  # RANGE_START
            result.update({
                "session_id": int.from_bytes(message.payload[0:4], byteorder='little'),
                "ranging_status": RangingStatus(message.payload[4]).name if len(message.payload) > 4 else None
            })
        elif message.operation_id == 1:  # RANGE_STOP
            result.update({
                "session_id": int.from_bytes(message.payload[0:4], byteorder='little'),
                "status": Status(message.payload[4]).name if len(message.payload) > 4 else None
            })
        elif message.operation_id == 6:  # RANGE_STATUS_NTF
            result.update({
                "session_id": int.from_bytes(message.payload[0:4], byteorder='little'),
                "status": RangingStatus(message.payload[4]).name if len(message.payload) > 4 else None
            })

        return result

    @staticmethod
    def parse_hex_command(hex_string: str) -> Union[Dict, str]:
        """Parse UCI command from hex string with improved error handling"""
        try:
            # Clean and validate input
            hex_string = hex_string.replace(" ", "").replace("0x", "")
            message = bytes.fromhex(hex_string)
            
            if len(message) < 4:
                raise ValueError("Message too short")

            # Parse header
            uci_message = UCICommandParser._parse_header(message)
            
            # Parse payload if present
            if uci_message.payload_size > 0 and len(message) > 4:
                uci_message.payload = message[4:4 + uci_message.payload_size]
                            # 在payload解析部分添加新的條件
                            
                # Select appropriate payload parser based on group ID
                if uci_message.group_id == GroupID.RANGING:
                    uci_message.parsed_data = UCICommandParser._parse_ranging_payload(uci_message)
                elif uci_message.group_id == GroupID.CORE:
                    if uci_message.operation_id == 2:  # GET_DEV_INFO
                        uci_message.parsed_data = UCICommandParser._parse_dev_info_payload(uci_message.payload)
                    if uci_message.operation_id == 3:  # SET_APP_CONFIG
                        uci_message.parsed_data = UCICommandParser._parse_app_config(uci_message.payload) 
                    if uci_message.operation_id == 4:  # SET_CONFIG
                        uci_message.parsed_data = UCICommandParser._parse_core_config_payload(uci_message.payload)                                                 
                    elif uci_message.operation_id == 1:  # DEVICE_STATUS_NTF
                        uci_message.parsed_data = {"status": UCICommandParser.DEVICE_STATUS.get(
                            uci_message.payload[0], 
                            f"UNKNOWN_STATUS_{uci_message.payload[0]}"
                        )}

            return UCICommandParser._format_result(uci_message)

        except ValueError as e:
            logger.error(f"Invalid hex string: {str(e)}")
            return f"Error: Invalid hex string - {str(e)}"
        except Exception as e:
            logger.error(f"Parsing error: {str(e)}")
            return f"Error: {str(e)}"

    @staticmethod
    def _parse_header(message: bytes) -> UCIMessage:
        """Parse UCI message header"""
        mt = (message[0] >> 5) & 0x07
        pbf = bool((message[0] >> 4) & 0x01)
        gid = message[0] & 0x0F
        ext = bool((message[1] >> 7) & 0x01)
        oid = message[1] & 0x3F
        
        payload_size = (message[2] << 8 | message[3]) if ext else message[3]

        return UCIMessage(
            message_type=MessageType(mt),
            group_id=gid,
            operation_id=oid,
            pbf=pbf,
            extended=ext,
            payload_size=payload_size
        )

    @staticmethod
    def _parse_dev_info_payload(payload: bytes) -> Dict:
        """Parse device info TLV payload"""
        info = {}
        index = 0
        
        while index < len(payload):
            try:
                tlv_type = payload[index]
                length = payload[index + 1]
                value = payload[index + 2:index + 2 + length]
                
                type_name = UCICommandParser.DEVICE_TLV_TYPES.get(tlv_type, f"Unknown_Type_0x{tlv_type:02X}")
                
                # Handle specific TLV types
                if tlv_type in [0x0F, 0xA1]:  # Device Name or FW Version
                    info[type_name] = value.decode('ascii').rstrip('\0')
                else:
                    info[type_name] = value.hex()
                
                index += 2 + length
            except Exception as e:
                logger.error(f"Error parsing TLV at index {index}: {str(e)}")
                info[f"Parse_Error_{index}"] = str(e)
                break
        
        return info

    @staticmethod
    def _format_result(message: UCIMessage) -> Dict:
        """Format parsed message into result dictionary"""
        result = {
            "Message_Type": message.message_type.name,
            "Group": f"{UCICommandParser.get_group_name(message.group_id)} (GID: {message.group_id})",
            "Command": f"{UCICommandParser.get_command_name(message.group_id, message.operation_id)} (OID: {message.operation_id})",
            "Packet_Boundary_Flag": message.pbf,
            "Extended": message.extended,
            "Payload_Size": message.payload_size
        }

        if message.parsed_data:
            result.update(message.parsed_data)

        return result

def main():
    """Main function with improved user interface"""
    print("UCI Command Parser v2.0")
    print("Enter 'q' to quit, 'h' for help")
    
    while True:
        try:
            command = input("\nEnter UCI command in hex: ").strip().lower()
            
            if command == 'q':
                break
            elif command == 'h':
                print("\nHelp:")
                print("- Enter UCI command in hex format (e.g., 21000005783508440000)")
                print("- Spaces and '0x' prefix are allowed")
                print("- Enter 'q' to quit")
                continue
            elif not command:
                continue
                
            result = UCICommandParser.parse_hex_command(command)
            
            if isinstance(result, dict):
                print("\nParsed Command:")
                for key, value in result.items():
                    print(f"{key}: {value}")
            else:
                print(result)
                
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()