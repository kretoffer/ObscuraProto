# ObscuraProto Architecture Overview

This document describes the architecture and components of the `ObscuraProto` library.

## Big Picture
`ObscuraProto` is a library for establishing a secure communication channel between a client and a server. The protocol performs a "handshake" to generate shared session keys and then uses them to encrypt all traffic. The architecture is similar to a simplified version of TLS, aimed at being lightweight and easy to integrate.

---

### 1. `keys.hpp`
This is a basic file that defines simple data structures for storing cryptographic keys and signatures.

- **`PublicKey` / `PrivateKey`**: Structures for public and private keys. Internally, they are just a byte array (`std::vector<uint8_t>`).
- **`KeyPair`**: Combines a public and a private key into a single pair.
- **`Signature`**: A structure for storing a digital signature.

**Purpose:** Creates "containers" for keys and signatures to make them convenient to pass around within the program.

---

### 2. `version.hpp`
This file is responsible for protocol versioning.

- **`Version`**: A type for the version number (`uint16_t`).
- **`Versions::V1_0`**: A constant for version 1.0.
- **`SUPPORTED_VERSIONS`**: A list of versions that the library supports.

**Purpose:** Allows the client and server to ensure they are "speaking the same language" (the same protocol version) when connecting.

---

### 3. `packet.hpp`
This describes the structure of data packets exchanged between parties *before* encryption.

- **`byte_vector`**: An alias for `std::vector<uint8_t>`, used for working with raw binary data.
- **`EncryptedPacket`**: An alias for `byte_vector`. This is an encrypted data packet; its content is opaque.
- **`Payload`**: The key class representing the "payload" — commands and data in unencrypted form.
    - **`op_code`**: "Operation code". A `uint16_t` that denotes the command type (e.g., 1 - "authorize", 2 - "send message").
    - **`parameters`**: Data related to this command.
    - **`add_param(...)`**: Methods for adding parameters. It uses length-prefixed serialization (the length of each parameter is written before it), which makes it easy to separate them when reading.
    - **`serialize()` / `deserialize()`**: Functions that turn a `Payload` object into a single byte array and back. `deserialize()` throws an `ObscuraProto::RuntimeError` if the data is malformed.
    - **`ParamParser`**: A helper class that makes it convenient to extract parameters one by one from a received `Payload`.

**Purpose:** `Payload` is the "envelope" where you put a command (`op_code`) and its data (`parameters`) before sealing it (encrypting).

---

### 4. `errors.hpp`
This file defines the custom exception types used throughout the library.

- **`Exception`**: The base exception class, inheriting from `std::exception`.
- **`RuntimeError`**: A general-purpose runtime error, used for issues like failed decryption, invalid signatures, or handshake failures.
- **`LogicError`**: An error indicating incorrect usage of the library (e.g., calling `encrypt` before the handshake is complete).

**Purpose:** Provides a structured way to handle errors, allowing the user to catch specific exception types.

---

### 5. `crypto.hpp`
This is the "brain" of the entire encryption system. All cryptographic operations are implemented as static methods in the `Crypto` class (likely using `libhydrogen`).

- **`init()`**: Initializes the crypto library. It must be called once when the program starts.
- **`generate_kx_keypair()` / `generate_sign_keypair()`**: Generate key pairs. `kx` (Key Exchange) is for key exchange, and `sign` is for digital signatures.
- **`sign()` / `verify()`**: Create and verify digital signatures for authentication and message integrity.
- **`SessionKeys`**: A structure for storing two session keys (`rx` for receiving, `tx` for sending), which are generated during the handshake.
- **`client_compute_session_keys()` / `server_compute_session_keys()`**: Implement the key exchange using the Diffie-Hellman (ECDH) algorithm to derive shared secret keys.
- **`encrypt()`**: Encrypts a `Payload` using the ChaCha20-Poly1305 algorithm. It takes a message counter as an argument, which is included in the encrypted packet to protect against replay attacks.
- **`decrypt()`**: Decrypts a packet. It returns a `DecryptedResult` containing both the `Payload` and the message `counter` from the packet. It throws an `ObscuraProto::RuntimeError` if decryption fails.

**Purpose:** Provides all the necessary tools for generating keys, establishing a secure connection, and encrypting data.

---

### 6. `session.hpp`
This file combines everything into a unified session management logic.

- **`Role`**: An enumeration that indicates who is using the session — `CLIENT` or `SERVER`.
- **`Session`**: The main class that manages the connection state.
    - **`Session(Role role, ...)`**: The constructor initializes a session. For a server, it requires the server's long-term signing key. For a client, it requires the server's public signing key.
    - **`client_initiate_handshake()`**: **For the client.** Starts the handshake by creating a `ClientHello` message.
    - **`server_respond_to_handshake(...)`**: **For the server.** Receives `ClientHello`, validates it, and generates a `ServerHello` response. Throws an error if the handshake fails.
    - **`client_finalize_handshake(...)`**: **For the client.** Receives `ServerHello`, validates it, and computes the shared session keys. Throws an error if the handshake fails.
    - **`encrypt_payload(...)` / `decrypt_packet(...)`**: The main functions for data exchange after the handshake. They manage encryption and message counters to protect against replay attacks.
    - **`is_handshake_complete()`**: Allows checking if the secure channel has been established.

### Session Lifecycle

1.  **Setup**: The client and server create a `Session` object, specifying their role and providing the necessary signing keys.
2.  **Handshake (3-way)**:
    *   The client calls `client_initiate_handshake()` and sends the resulting `ClientHello` to the server.
    *   The server receives `ClientHello` and calls `server_respond_to_handshake()`. It sends the resulting `ServerHello` back to the client.
    *   The client receives `ServerHello` and calls `client_finalize_handshake()`.
    *   **Result**: Both parties now have shared session keys, and the communication channel is considered secure.
3.  **Data Exchange**:
    *   The sender creates a `Payload` with a command and data.
    *   Calls `session.encrypt_payload()` to encrypt it.
    *   Sends the encrypted packet over the network.
    *   The receiver accepts the packet and calls `session.decrypt_packet()` to get the original `Payload`.
    *   Analyzes the `Payload` and executes the requested command.
