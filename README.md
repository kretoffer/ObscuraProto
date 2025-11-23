# ObscuraProto

This document describes the principles of the ObscuraProto **1.0** hybrid encryption protocol. This version uses elliptic curve cryptography, **ChaCha20-Poly1305**, and a session resumption mechanism.

## 1. Protocol Architecture

The protocol defines two ways to establish a secure channel: a full handshake for new connections and a shortened one for resuming previous sessions.

### Phase 1: Full Handshake using ECC

This phase is used for the client's first connection to the server and includes protocol version negotiation.

1.  **Client Initiation (Client Hello):**
    *   The client initiates the connection by sending a **list of supported protocol versions** (e.g., `[1.1, 1.0]`).
    *   The client generates its ephemeral ECDH key pair and sends the public part to the server.

2.  **Server Response and Authentication (Server Hello):**
    *   The server receives the list of versions and selects the highest one it also supports. If no common versions are found, the server terminates the connection. All further communication proceeds according to the rules of the selected version.
    *   The server possesses a long-term **Ed25519** key pair. Its public key must be known to the client.
    *   The server generates its ephemeral **ECDH** key pair.
    *   The server signs its public ECDH key with its private **Ed25519** key.
    *   The server sends the client: the **selected protocol version**, its public ECDH key, and the digital signature.

3.  **Client Authentication and Exchange Completion:**
    *   The client verifies that the version selected by the server is in its list of supported versions.
    *   The client verifies the signature of the public ECDH key using the server's public **Ed25519** key.

4.  **Shared Secret Generation:**
    *   The client and server compute a shared secret `S` using the ECDH protocol.
    *   The secret `S` is passed through a **Key Derivation Function (KDF)**, such as HKDF, to generate **two symmetric keys** (one for sending, one for receiving) for the ChaCha20-Poly1305 cipher.

5.  **Session Ticket Creation:** After a successful handshake, the server can create a **Session Ticket** for session resumption. This ticket contains session information, encrypted with a key known only to the server, and sends it to the client. The ticket **must include information about the protocol version** on which the session was established.

### Phase 2: Session Resumption

If the client has a session ticket, it can use a shortened handshake.

1.  **Client Initiation:**
    *   The client connects. **If the client has a newer protocol version available than the one with which the session ticket was issued, or if the session ticket is missing/invalid, the client initiates a full handshake.**
    *   Otherwise (if the ticket is valid and the client does not have a newer protocol version), the client sends the previously received **session ticket** for resumption.
2.  **Server Ticket Verification:**
    *   The server decrypts the ticket and extracts the **protocol version** and the session master key.
    *   The server verifies that it still supports the protocol version specified in the ticket. If the version is outdated and no longer supported, the server refuses resumption and may suggest the client perform a full handshake.
    *   If the version is supported, the server verifies the ticket's validity (e.g., its expiration date) and extracts the master key.
3.  **Data Transfer Start:** The parties skip asymmetric cryptography and immediately proceed to secure data transfer, using keys generated from the session master key.

### Phase 3: Data Transfer

1.  Data is encrypted using a modern **AEAD cipher (Authenticated Encryption with Associated Data) ChaCha20-Poly1305**. This cipher combines encryption and authentication in a single operation.
2.  For each message, a unique **Nonce** (number used once) of 12 bytes is generated and transmitted in plaintext.
3.  **Integrity and Authenticity Protection:** The ChaCha20-Poly1305 cipher automatically calculates an **Authentication Tag**. This tag protects against modification and forgery of both the encrypted data and "additional authenticated data" (Associated Data), which in our case is the message counter.
4.  The final message to be sent looks like this: `Nonce + Counter + Ciphertext + Auth Tag`.

## 2. Data Transfer Format

The format is divided into two levels: the **encryption envelope**, which provides security, and the **payload**, which contains the application data itself.

### 2.1. Encryption Envelope Structure

Each message transmitted over a secure channel is wrapped in the following "envelope":

`[Nonce (12 bytes)] + [Counter (8 bytes)] + [Encrypted Data (variable length)] + [Auth Tag (16 bytes)]`

1.  **Nonce (Number used once)**
    *   **Length:** 12 bytes. Generated for each message.
    *   **Purpose:** A unique number for each message, necessary for the correct and secure operation of the ChaCha20 cipher.

2.  **Message Counter**
    *   **Length:** 8 bytes.
    *   **Purpose:** Protection against replay attacks. This field is not encrypted, but its integrity is protected by the authentication tag.

3.  **Encrypted Data (Ciphertext)**
    *   **Content:** The original payload, encrypted using ChaCha20.

4.  **Auth Tag (Authentication Tag)**
    *   **Length:** 16 bytes (for Poly1305).
    *   **Purpose:** Ensures the integrity and authenticity of the `Nonce`, `Counter`, and `Ciphertext`. It is automatically calculated during the encryption process.

### 2.2. Payload Structure

The data placed in the `Encrypted Data` field (before encryption) must have the following binary structure:

`[Operation Code (2 bytes)] + [Operation Parameters (N bytes)]`

*   **Operation Code**: A 2-byte integer (in network byte order, Big-Endian) that uniquely identifies the type of request or message. For example, `0x1001` for an authentication request.
*   **Operation Parameters**: Data required to perform the operation, serialized using the **length-prefix method**.

#### "Length-Prefix" Serialization Method

Each parameter in `Operation Parameters` is encoded using the "length-value" scheme:

`[Field Length (2 bytes)] + [Field Value (N bytes)]`

**Example: Payload for "Login" operation (`0x1001`)**

Suppose the operation requires `username` (string) and `password` (string).
*   `username`: "test" (4 bytes)
*   `password`: "p@ss" (4 bytes)

The final payload before encryption will look like this:

1.  `0x10, 0x01` — Login Operation Code
2.  `0x00, 0x04` — Length of `username`
3.  `0x74, 0x65, 0x73, 0x74` — bytes of "test"
4.  `0x00, 0x04` — Length of `password`
5.  `0x70, 0x40, 0x73, 0x73` — bytes of "p@ss"

This exact sequence of bytes will be encrypted and placed in the `Encrypted Data` field.

### Message Sending Algorithm

1.  **Form the payload:** Assemble the `Operation Code` and `Parameters` into a single byte array according to the binary structure.
2.  **Increment counter:** Increment the value of your sent message counter by 1.
3.  **Generate Nonce:** Create a cryptographically random 12-byte Nonce.
4.  **Encrypt and Authenticate:** Perform the ChaCha20-Poly1305 encryption operation.
    *   **Input:** session key, Nonce, payload (as plaintext), and `Counter` (as "associated data").
    *   **Output:** `ciphertext` and a 16-byte `Auth Tag`.
5.  **Send:** Assemble and send the final message: `Nonce + Counter + ciphertext + Auth Tag`.

### Message Reception and Verification Algorithm

1.  **Split the message:** The received message is divided into `Nonce`, `Counter`, `ciphertext`, and `Auth Tag`.
2.  **Verify and Decrypt:** Perform the ChaCha20-Poly1305 decryption operation.
    *   **Input:** session key, `Nonce`, `ciphertext`, `Auth Tag`, and `Counter` (as "associated data").
    *   This operation automatically verifies the `Auth Tag`. If the tag is invalid, the operation will fail, and the message **must be immediately discarded**.
3.  **Check counter:** If decryption is successful, compare the counter value with the expected one. If it is less than or equal to the last received, discard the message as a replay.
4.  **Parse the payload:**
    *   Read the first 2 bytes of the decrypted data to determine the **Operation Code**.
    *   Depending on the operation code, sequentially parse the remaining data using the length-prefix method to extract all parameters.
5.  **Update counter** and pass the data for processing to the application logic.

This algorithm ensures reliable protection of transmitted data within the ObscuraProto protocol.

## 3. Reliability Analysis

*   **Perfect Forward Secrecy (PFS):** Maintained thanks to ephemeral ECDH keys.
*   **Performance:** ECC provides high speed for asymmetric operations. ChaCha20-Poly1305 is a very fast symmetric cipher. Session resumption speeds up repeated connections.
*   **Trust Model:** The protocol assumes that the client trusts the server's public Ed25519 key in advance.

## 4. Key Decisions

*   **ChaCha20-Poly1305:** A modern, high-performance AEAD cipher that provides both confidentiality and data integrity.
*   **Elliptic Curve Cryptography (ECC):** The basis of asymmetric operations, providing a balance of speed and security, specifically using Ed25519 for signatures and X25519 for key exchange.
*   **Key Derivation Function (KDF):** A critically important component for generating two distinct keys (for sending and receiving) from a shared secret.
*   **Replay Attack Protection:** Implemented using a message counter, which is included in each message and **authenticated using Poly1305**. This prevents the replaying of old messages.
