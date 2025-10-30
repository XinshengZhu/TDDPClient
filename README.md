# TDDPClient

***It is important to note TDDP‘s behavior on different firmware versions or router models may differ in several features.***

## Definition of TDDP

* **TP-Link Device Debug Protocol** *(TDDP)* is a proprietary, UDP-based binary request/response protocol used by TP‑Link devices for maintenance and debugging operations.
* **TP-Link Device Debug Protocol** *(TDDP)* achieves the interaction between clients and servers (network devices), which follows a Q&A mode of the server-side passive and client-side active.
* **TP-Link Device Debug Protocol** *(TDDP)* was first documented in the patent [CN102096654A](https://patents.google.com/patent/CN102096654A/en).

## Analysis of TDDP

### Preparation

1. Download the [TP-Link Archer C20 v5.6](https://www.tp-link.com/us/support/download/archer-c20/v5.60/#Firmware) firmware, and extract it with `binwalk` to access to the router's Linux file system.
2. Gain unauthorized shell access to the router’s operating system with 115200 as Minicom's Baud rate by exploiting the unprotected UART ports.
3. Confirm that the TDDP service is exposed on the UDP/1040 for approximately 15 minutes after each device reboot.

### Reverse Engineering

#### TDDP Packet Structure

<img src="images/tddp_packet.png" alt="TDDP Packet Structure" width="500">

#### TDDP Header Structure

<img src="images/tddp_header.png" alt="TDDP Header Structure" width="500">

#### TDDP Packet Construction Flow 

<img src="images/tddp_flow.png" alt="TDDP Packet Construction Flow" width="600">

### 

## Implementation of TDDP Client

### Files

Here's a brief description of all code files:

```
TDDPClient/
├─── tddp_client.py   # TDDP client implementation for UDP communication with TP-Link devices, including sending and receiving encrypted TDDP packets via UDP
├─── tddp_header.py   # TDDP header structure (28-byte binary format of packet metadata) and its serialization
└─── tddp_packet.py   # TDDP Packet structure with DES encryption/decryption on the data field and MD5 verification on the digest field
```

### Requirements

* Install the dependency with Python 3.8+:
    ```bash
    $ pip install pycryptodome
    ```
