import hashlib
from Crypto.Cipher import DES
from binascii import hexlify, unhexlify

from tddp_header import TDDPHeader

class TDDPPacket:
    """
    TDDP (TP-Link Device Debug Protocol) packet

    A TDDP packet consists of a TDDP header and a TDDP data field.
    The TDDP data field is encrypted using DES-ECB mode with a key derived from administrator credentials.
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
        1. With plain_data: Form a new packet to send, pad the plain data, set the packet length and calculate the digest in the header
        2. With encrypted_data: Unpack a received packet

        Args:
            header: TDDPHeader object. If None, a new header is created using header_kwargs (default: None)
            plain_data: Unencrypted plain payload data (for sending). If provided, it will be padded to 8-byte boundaries, and the digest will be calculated (default: None)
            encrypted_data: Encrypted payload data (for receiving). If provided, it will be unpacked from the received packet (default: None)
            **header_kwargs: Additional keyword arguments passed to TDDPHeader constructor if header is None
        """
        self.header = header if header is not None else TDDPHeader(**header_kwargs)
        self.plain_data = None
        self.encrypted_data = None
        if plain_data is not None:
            if len(plain_data) == 0:
                pad_len = 8
            else:
                pad_len = (8 - (len(plain_data) % 8)) % 8
            self.plain_data = plain_data + b'\x00' * pad_len
            self.header.pkt_length = len(self.plain_data)
            self.header.digest = hashlib.md5(self.header.pack()[:TDDPHeader.STRUCT_SIZE-0x10] + b'\x00' * 0x10 + self.plain_data).digest()[:16]
        elif encrypted_data is not None:
            self.encrypted_data = encrypted_data

    def encrypt(self, tddp_key: bytes):
        """
        Encrypt the plain data using DES-ECB mode.

        Args:
            tddp_key: 8-byte DES encryption key (typically derived from the first 8 bytes of the MD5 hash of the concatenation of username and password)

        Note:
            Used before sending a packet to the server.
            Requires plain_data to be set.
        """
        cipher = DES.new(tddp_key, DES.MODE_ECB)
        self.encrypted_data = cipher.encrypt(self.plain_data)

    def decrypt(self, tddp_key: bytes):
        """
        Decrypt the encrypted data using DES-ECB mode.

        Args:
            tddp_key: 8-byte DES encryption key (typically derived from the first 8 bytes of the MD5 hash of the concatenation of username and password)

        Note:
            Used after receiving a packet from the server.
            Requires encrypted_data to be set.
        """
        cipher = DES.new(tddp_key, DES.MODE_ECB)
        self.plain_data = cipher.decrypt(self.encrypted_data)

    def verify(self) -> bool:
        """
        Verify the integrity of the packet by checking the MD5 digest in the header.

        Recalculate the MD5 digest of the packet and compare it with the digest in the header to ensure packet integrity.
        The digest is calculated over the header (with digest field as null bytes) plus the plain data.

        Returns:
            bool: True if the digest matches (packet is valid), False otherwise

        Raises:
            ValueError: If plain data is not set.

        Note:
            Should be called after decrypting a received packet to ensure data integrity.
            Requires plain_data to be set.
        """
        if self.plain_data is not None:
            return self.header.digest == hashlib.md5(self.header.pack()[:TDDPHeader.STRUCT_SIZE-0x10] + b'\x00' * 0x10 + self.plain_data).digest()
        else:
            raise ValueError("TDDPPacket verify error: plain data is not set")

    def pack(self) -> bytes:
        """
        Serialize a TDDPPacket object into a binary representation.

        Returns:
            bytes: Binary representation (header + encrypted data) of the TDDPPacket object

        Raises:
            ValueError: If encrypted_data is not set.

        Note:
            The plain data must be encrypted before packing for transmission.
        """
        if self.encrypted_data is not None:
            return self.header.pack() + self.encrypted_data
        else:
            raise ValueError("TDDPPacket pack error: encrypted data is not set")

    @classmethod
    def unpack(cls, data: bytes) -> 'TDDPPacket':
        """
        Deserialize a binary representation into a TDDPPacket object.

        Args:
            data: Binary representation (header + encrypted data) of the TDDPPacket object

        Returns:
            TDDPPacket: TDDPPacket object populated from the binary representation

        Note:
            The encrypted data should be decrypted after unpacking for access to the plain data.
        """
        header = TDDPHeader.unpack(data[:TDDPHeader.STRUCT_SIZE])
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
        """
        return (
            f"TDDPPacket("
            f"header={self.header}, "
            f"plain_data={self.plain_data}, "
            f"encrypted_data={self.encrypted_data}"
            f")"
        )