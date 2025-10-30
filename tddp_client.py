import hashlib
import socket

from tddp_packet import TDDPPacket
from tddp_header import TDDPHeader

class TDDPClient:
    """
    Client for communicating with TDDP (TP-Link Device Debug Protocol) servers.

    The TDDP protocol achieves the interaction between clients and servers (network devices), which follows a Q&A mode of the server-side passive and client-side active.
    After a device reboot, the TDDP service is exposed on UDP/1040 for about fifteen minutes.
    This client handles UDP communication with TDDP-enabled TP-Link devices, including sending requests and receiving replies.
    It manages packet encryption/decryption using DES with a key derived from the MD5 hash of administrator credentials.
    """

    def __init__(
        self,
        host: str,
        username: str = "admin",
        password: str = "admin",
        server_port: int = 1040,
        client_port: int = 61000,
        timeout: float = 5.0
    ):
        """
        Initialize a TDDP client with connection parameters.

        Args:
            host: IP address or hostname of the TDDP server
            username: Username for authentication (default: "admin")
            password: Password for authentication (default: "admin")
            server_port: UDP port on which the server listens (default: 1040)
            client_port: UDP port on local machine to bind for sending/receiving (default: 61000)
            timeout: Socket timeout in seconds for send/receive operations (default: 5.0)

        Note:
            The encryption key is calculated as the first 8 bytes of the MD5 hash of the concatenation of username and password.
        """
        self.host = host
        self.username = username
        self.password = password
        self.server_port = server_port
        self.client_port = client_port
        self.timeout = timeout
        self.tddp_key = hashlib.md5((username + password).encode()).digest()[:8]

    def send_request(self, tddp_packet: TDDPPacket):
        """
        Send a TDDP request packet to the server over UDP.

        The packet is encrypted using the DES encryption key and packed up before sending.

        Args:
            tddp_packet: TDDPPacket object to send

        Note:
            The socket is closed after sending.
            This method does not wait for a reply.
        """
        tddp_packet.encrypt(self.tddp_key)
        sock_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_send.bind(("", self.client_port))
        sock_send.settimeout(self.timeout)
        sock_send.sendto(tddp_packet.pack(), (self.host, self.server_port))
        sock_send.close()

    def receive_reply(self) -> TDDPPacket:
        """
        Receive a TDDP reply packet from the server over UDP.

        The packet is unpacked and decrypted using the DES encryption key after receiving.

        Returns:
            TDDPPacket: TDDPPacket object received

        Note:
            A new UDP socket is created for each receive operation.
            This method closes the socket after receiving the packet.
        """
        sock_receive = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_receive.bind(("", self.client_port))
        sock_receive.settimeout(self.timeout)
        response, addr = sock_receive.recvfrom(1024)
        packet = TDDPPacket.unpack(response)
        packet.decrypt(self.tddp_key)
        sock_receive.close()
        return packet

    def update_credentials(self, username: str, password: str):
        """
        Update the administrator credentials and regenerate the DES encryption key.

        This method should be called if the device's administrator credentials have been changed.

        Args:
            username: New username for authentication
            password: New password for authentication
        """
        self.username = username
        self.password = password
        self.tddp_key = hashlib.md5((username + password).encode()).digest()[:8]