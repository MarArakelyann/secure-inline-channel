# Secure Inline Channel

**A secure communication channel using X25519, HKDF-SHA256, and AES-256-GCM.**

## Overview

Secure Inline Channel is an educational cybersecurity project that demonstrates secure communication between two devices through an intermediary relay.

The prototype establishes a shared secret between communicating devices, derives a symmetric encryption key, and uses authenticated encryption to protect exchanged messages.

## Architecture

The communication follows this structure:

**Device 1 (Sender) → Device 1 (Relay) → Device 2 (Receiver)**

- **Sender:** Establishes the cryptographic session and sends an encrypted message.
- **Relay:** Forwards communication between the sender and receiver.
- **Receiver:** Receives the encrypted message, authenticates it, and decrypts it.
- **Packet Sniffer:** Captures and analyzes IPv4 TCP packets for network observation.

## Cryptographic Technologies

| Technology | Purpose |
|---|---|
| X25519 | Shared-secret establishment |
| HKDF-SHA256 | Derivation of the AES encryption key |
| AES-256-GCM | Authenticated encryption and decryption |
| OpenSSL | Cryptographic operations |
| libpcap | Network packet capture |

The derived AES key is 256 bits (32 bytes). AES-GCM also provides message authentication through an authentication tag.

## Project Structure

```text
secure-inline-channel/
│
├── src/
│   ├── main.c
│   ├── crypto.c
│   ├── handshake.c
│   ├── kdf.c
│   ├── sender.c
│   ├── receiver.c
│   ├── relay.c
│   └── sniffer.c
│
├── include/
│   ├── crypto.h
│   ├── handshake.h
│   └── kdf.h
│
├── Makefile
├── .gitignore
└── README.md
```

## Requirements

- GCC
- GNU Make
- OpenSSL development libraries
- libpcap development libraries
- Linux environment (tested with Kali Linux)

## Compilation

Clone the repository:

```bash
git clone https://github.com/MarArakelyann/secure-inline-channel.git
cd secure-inline-channel
```

Compile the project:

```bash
make
```

To remove compiled executables:

```bash
make clean
```

## Running the Prototype

The communication was tested using two Kali Linux virtual machines connected through a VirtualBox Internal Network.

Start the components in this order:

1. On Device 2, start the receiver:

```bash
./receiver
```

2. On Device 1, start the relay:

```bash
./relay
```

3. On Device 1, start the sender:

```bash
./sender
```

4. To observe TCP traffic on Device 1, run the packet sniffer:

```bash
sudo ./sniffer
```

The sniffer uses the network interface configured in its source code. Adjust the interface if your environment uses a different one.

## Testing

The prototype was successfully tested in an isolated virtual network.

Verified results include:

- Successful public-key exchange.
- Successful shared-secret establishment.
- Successful AES key derivation.
- Successful encrypted message transmission through the relay.
- Successful message authentication and decryption at the receiver.
- Successful IPv4 TCP packet capture.

## Project Scope

This project is an educational prototype demonstrating cryptographic communication and network packet observation. Its successful functional tests do not constitute a formal security audit or production-readiness assessment.



