import struct
from binascii import hexlify, unhexlify

class TDDPHeader:
    """
    TDDP (TP-Link Device Debug Protocol) Header

    A TDDP header contains metadata of a TDDP packet.
    A TDDP header structure follows a specific binary format of 28 bytes for network transmission (big-endian).
    """

    STRUCT_FORMAT = '>B B B B I H B B 16s'
    STRUCT_SIZE = struct.calcsize(STRUCT_FORMAT)

    def __init__(
        self,
        *,
        version: int = 0x00,
        type: int = 0x00,
        code: int = 0x00,
        reply_info: int = 0x00,
        pkt_length: int = 0x00000000,
        pkt_id: int = 0x0000,
        sub_type: int = 0x00,
        reserve: int = 0x00,
        digest: bytes = None
    ):
        """
        Initialize a TDDP header with specified field values.

        Args:
            version (1 byte): Protocol version field (default: 0x00)
            type (1 byte): Command type field (default: 0x00)
            code (1 byte): Command code field (default: 0x00)
            reply_info (1 byte): Reply status field (default: 0x00)
            pkt_length (4 bytes): Packet length field in bytes (default: 0x0000)
            pkt_id (2 bytes): Packet identifier number field (default: 0x00000000)
            sub_type (1 byte): Command sub-type field (default: 0x00)
            reserve (1 byte): Reserved field (default: 0x00)
            digest (16 bytes): MD5 digest field. If None, it will be set to 16 bytes of '\x00' (default: None)
        """
        self.version = version
        self.type = type
        self.code = code
        self.reply_info = reply_info
        self.pkt_length = pkt_length
        self.pkt_id = pkt_id
        self.sub_type = sub_type
        self.reserve = reserve
        if digest is None:
            self.digest = b'\x00' * 16
        else:
            self.digest = digest

    def pack(self) -> bytes:
        """
        Serialize a TDDPHeader object into a binary representation following the STRUCT_FORMAT.

        Returns:
            bytes: Binary representation of the TDDPHeader object
        """
        return struct.pack(
            self.STRUCT_FORMAT,
            self.version,
            self.type,
            self.code,
            self.reply_info,
            self.pkt_length,
            self.pkt_id,
            self.sub_type,
            self.reserve,
            self.digest
        )

    @classmethod
    def unpack(cls, data: bytes) -> 'TDDPHeader':
        """
        Deserialize a binary representation into a TDDPHeader object following the STRUCT_FORMAT.

        Args:
            data: Binary representation of the TDDPHeader object

        Returns:
            TDDPHeader: TDDPHeader object populated from the binary representation

        Raises:
            ValueError: If the data is smaller than the STRUCT_SIZE
        """
        if len(data) < cls.STRUCT_SIZE:
            raise ValueError(f"TDDPHeader unpack error: expected {cls.STRUCT_SIZE} bytes, got {len(data)} bytes")

        unpacked = struct.unpack(cls.STRUCT_FORMAT, data[:cls.STRUCT_SIZE])
        return cls(
            version=unpacked[0],
            type=unpacked[1],
            code=unpacked[2],
            reply_info=unpacked[3],
            pkt_length=unpacked[4],
            pkt_id=unpacked[5],
            sub_type=unpacked[6],
            reserve=unpacked[7],
            digest=unpacked[8]
        )

    def to_hex(self) -> str:
        """
        Convert a TDDPHeader object to a hexadecimal string representation.

        Returns:
            str: Hexadecimal string representation of the TDDPHeader object
        """
        return hexlify(self.pack()).decode()

    @classmethod
    def from_hex(cls, hex_string: str) -> 'TDDPHeader':
        """
        Retrieve a TDDPHeader object from a hexadecimal string representation.

        Args:
            hex_string: Hexadecimal string representation of the TDDPHeader object

        Returns:
            TDDPHeader: TDDPHeader object retrieved from the hexadecimal string representation
        """
        return cls.unpack(unhexlify(hex_string))

    def __repr__(self) -> str:
        """
        Return a string representation of the TDDPHeader object.

        Returns:
            str: Formatted string showing all TDDPHeader object fields
        """
        return (
            f"TDDPHeader("
            f"version=0x{self.version:02x}, "
            f"type=0x{self.type:02x}, "
            f"code=0x{self.code:02x}, "
            f"reply_info=0x{self.reply_info:02x}, "
            f"pkt_length=0x{self.pkt_length:08x}, "
            f"pkt_id=0x{self.pkt_id:04x}, "
            f"sub_type=0x{self.sub_type:02x}, "
            f"reserve=0x{self.reserve:02x}, "
            f"digest={hexlify(self.digest).decode()}"
            f")"
        )