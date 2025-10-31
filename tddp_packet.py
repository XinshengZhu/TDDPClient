import hashlib
from Crypto.Cipher import DES
from binascii import hexlify, unhexlify

from tddp_header import TDDPHeader

class TDDPPacket:
    """
    TDDP (TP-Link Device Debug Protocol) packet

    A TDDP packet consists of a TDDP header and a TDDP data field.
    The data field can be in plain text (version 0x01) or encrypted using DES-ECB mode (version 0x02) with a key derived from administrator credentials.

    The packet supports two protocol versions:
    - Version 0x01: Plain data, no encryption or digest verification
    - Version 0x02: Encrypted data with MD5 digest for integrity verification
    """
    def __init__(
        self,
        *,
        header: TDDPHeader = None,
        plain_data: bytes = None,
        encrypted_data: bytes = None,
        **header_kwargs
    ):
        """
        Initialize a TDDP packet.

        A TDDP packet can be initialized in two ways:
        1. With plain_data: Create a new packet to send, pad the plain data, set the packet length and calculate the digest in the header (version 0x02 only)
        2. With encrypted_data: Unpack a received packet and store the encrypted data for later decryption

        Args:
            header: TDDPHeader object. If None, a new header is created using header_kwargs (default: None)
            plain_data: Unencrypted plain payload data (for sending). If provided, it will be padded to 8-byte boundaries for version 0x02, and the digest will be calculated automatically (default: None)
            encrypted_data: Encrypted payload data (for receiving). If provided, it will be unpacked from the received packet (version 0x02 only) (default: None)
            **header_kwargs: Additional keyword arguments passed to TDDPHeader constructor if header is None. Must include version=0x01 or version=0x02 (default: None)

        Raises:
            ValueError: If header version is not 0x01 or 0x02, or if encrypted_data is provided with version 0x01

        Note:
            If neither plain_data nor encrypted_data is provided, an empty byte string will be used as plain_data.
        """
        self.header = header if header is not None else TDDPHeader(**header_kwargs)
        self.plain_data = None
        self.encrypted_data = None
        if plain_data is None and encrypted_data is None:
            plain_data = b''
        if plain_data is not None:
            if self.header.version == 0x01:
                self.plain_data = plain_data + b'\x00' * ((8 - (len(plain_data) % 8)) % 8)
                self.header.pkt_length = len(self.plain_data)
                self.header.digest = b'\x00' * 16
            elif self.header.version == 0x02:
                self.plain_data = plain_data + b'\x00' * ((8 - (len(plain_data) % 8)) % 8)
                self.header.pkt_length = len(self.plain_data)
                self.header.digest = hashlib.md5(self.header.pack()[:TDDPHeader.STRUCT_SIZE-0x10] + b'\x00' * 0x10 + self.plain_data).digest()[:16]
        elif encrypted_data is not None:
            if self.header.version == 0x01:
                raise ValueError(f"TDDPPacket init error: version 0x01 is not supported for initialization with encrypted_data")
            elif self.header.version == 0x02:
                self.encrypted_data = encrypted_data

    def encrypt(self, tddp_key: bytes):
        """
        Encrypt the plain data using DES-ECB mode.

        The encrypted data is stored in the encrypted_data attribute and can be serialized for transmission.

        Args:
            tddp_key: 8-byte DES encryption key. Typically derived from the first 8 bytes of the MD5 hash of the concatenation of username and password

        Raises:
            ValueError: If version is 0x01 (encryption not supported), or if plain_data is not set for version 0x02

        Note:
            This method should be called before sending a packet to the server.
            Only supported for version 0x02.
            Requires plain_data to be set.
        """
        if self.header.version == 0x01:
            raise ValueError("TDDPPacket encrypt error: version 0x01 is not supported for encryption with plain data")
        elif self.header.version == 0x02:
            if self.plain_data is None:
                raise ValueError("TDDPPacket encrypt error: plain_data is not set for version 0x02")
            if self.header.pkt_length > 0:
                cipher = DES.new(tddp_key, DES.MODE_ECB)
                self.encrypted_data = cipher.encrypt(self.plain_data)
            else:
                self.encrypted_data = b''

    def decrypt(self, tddp_key: bytes):
        """
        Decrypt the encrypted data using DES-ECB mode.

        The decrypted plain data is stored in the plain_data attribute and can be verified to ensure data integrity.

        Args:
            tddp_key: 8-byte DES encryption key. Typically derived from the first 8 bytes of the MD5 hash of the concatenation of username and password

        Raises:
            ValueError: If version is 0x01 (decryption not supported), or if encrypted_data is not set for version 0x02

        Note:
            This method should be called after receiving a packet from the server.
            Only supported for version 0x02.
            Requires encrypted_data to be set.
        """
        if self.header.version == 0x01:
            raise ValueError("TDDPPacket decrypt error: version 0x01 is not supported for decryption with encrypted data")
        elif self.header.version == 0x02:
            if self.encrypted_data is None:
                raise ValueError("TDDPPacket decrypt error: encrypted_data is not set for version 0x02")
            if self.header.pkt_length > 0:
                cipher = DES.new(tddp_key, DES.MODE_ECB)
                self.plain_data = cipher.decrypt(self.encrypted_data)
            else:
                self.plain_data = b''

    def verify(self) -> bool:
        """
        Verify the integrity of the packet by checking the MD5 digest in the header.

        Recalculate the MD5 digest of the packet and compare it with the digest in the header to ensure packet integrity.
        The digest is calculated over the header (with digest field as null bytes) plus the plain data.

        Returns:
            bool: True if the digest matches (packet is valid), False otherwise

        Raises:
            ValueError: If version is 0x01 (digest verification not supported), or if plain_data is not set for version 0x02

        Note:
            Should be called after decrypting a received packet to ensure data integrity.
            Requires plain_data to be set. Only supported for version 0x02.
        """
        if self.header.version == 0x01:
            raise ValueError("TDDPPacket verify error: version 0x01 does not support digest verification")
        elif self.header.version == 0x02:
            if self.plain_data is None:
                raise ValueError("TDDPPacket verify error: plain_data is not set for version 0x02")
            return self.header.digest == hashlib.md5(self.header.pack()[:TDDPHeader.STRUCT_SIZE-0x10] + b'\x00' * 0x10 + self.plain_data).digest()

    def pack(self) -> bytes:
        """
        Serialize a TDDPPacket object into a binary representation.

        The serialized format is:
        - For version 0x01: header + plain_data
        - For version 0x02: header + encrypted_data

        Returns:
            bytes: Binary representation of the TDDPPacket object, ready for network transmission

        Raises:
            ValueError: If plain_data is not set for version 0x01, or if encrypted_data is not set for version 0x02

        Note:
            For version 0x02, the plain data must be encrypted using encrypt() before calling pack().
        """
        if self.header.version == 0x01:
            if self.plain_data is None:
                raise ValueError("TDDPPacket pack error: plain_data is not set for version 0x01")
            return self.header.pack() + self.plain_data
        elif self.header.version == 0x02:
            if self.encrypted_data is None:
                raise ValueError("TDDPPacket pack error: encrypted_data is not set for version 0x02")
            return self.header.pack() + self.encrypted_data

    @classmethod
    def unpack(cls, data: bytes) -> 'TDDPPacket':
        """
        Deserialize a binary representation into a TDDPPacket object.

        The binary format is:
        - For version 0x01: header + plain_data
        - For version 0x02: header + encrypted_data

        Args:
            data: Binary representation of the TDDPPacket object, typically received from the network

        Returns:
            TDDPPacket: TDDPPacket object populated from the binary representation

        Note:
            For version 0x02, the encrypted data must be decrypted using decrypt() after calling unpack() and before calling verify().
        """
        header = TDDPHeader.unpack(data[:TDDPHeader.STRUCT_SIZE])
        if header.version == 0x01:
            plain_data = data[TDDPHeader.STRUCT_SIZE:]
            return cls(header=header, plain_data=plain_data)
        elif header.version == 0x02:
            encrypted_data = data[TDDPHeader.STRUCT_SIZE:]
            return cls(header=header, encrypted_data=encrypted_data)

    def to_hex(self) -> str:
        """
        Convert a TDDPPacket object to a hexadecimal string representation.

        Returns:
            str: Hexadecimal string representation of the TDDPPacket object
        """
        return hexlify(self.pack()).decode()

    @classmethod
    def from_hex(cls, hex_string: str) -> 'TDDPPacket':
        """
        Retrieve a TDDPPacket object from a hexadecimal string representation.

        Args:
            hex_string: Hexadecimal string representation of the TDDPPacket object

        Returns:
            TDDPPacket: TDDPPacket object retrieved from the hexadecimal string representation
        """
        return cls.unpack(unhexlify(hex_string))

    def __repr__(self) -> str:
        """
        Return a string representation of the TDDPPacket object.

        Returns:
            str: Formatted string showing all TDDPPacket object fields
                  - For version 0x01: header + plain_data
                  - For version 0x02: header + plain_data + encrypted_data
        """
        if self.header.version == 0x01:
            return (
                f"TDDPPacket("
                f"header={self.header}, "
                f"plain_data={self.plain_data}"
                f")"
            )
        elif self.header.version == 0x02:
            return (
            f"TDDPPacket("
            f"header={self.header}, "
            f"plain_data={self.plain_data}, "
            f"encrypted_data={self.encrypted_data}"
            f")"
        )