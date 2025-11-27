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

## 5. Basic API Usage

> **Warning:** The following guide describes the low-level "bare metal" API of ObscuraProto. This API is intended for building higher-level abstractions and is not recommended for direct use in most applications, as it requires careful state management.

The library provides a `Session` class that encapsulates the logic for a single client or server connection. The full lifecycle is demonstrated in `examples/basic_encryption_example.cpp`.

### Step 1: Initialization

First, the underlying cryptographic library (libsodium) must be initialized. This must be done once at the start of your application.

```cpp
#include "obscuraproto/crypto.hpp"

if (ObscuraProto::Crypto::init() != 0) {
    // Handle initialization failure
}
```

### Step 2: Key Setup

The server needs a long-term Ed25519 key pair for signing its handshake messages. The client must know the server's public signing key beforehand to verify its identity.

```cpp
// On the server: generate a long-term key
auto server_long_term_key = ObscuraProto::Crypto::generate_sign_keypair();

// On the client: configure the server's public key
ObscuraProto::KeyPair client_view_of_server_key;
client_view_of_server_key.publicKey = server_long_term_key.publicKey; // This key must be distributed to the client securely
```

### Step 3: Session Creation

Create `Session` objects for both the client and the server.

```cpp
#include "obscuraproto/session.hpp"

// Server-side
ObscuraProto::Session server_session(ObscuraProto::Role::SERVER, server_long_term_key);

// Client-side
ObscuraProto::Session client_session(ObscuraProto::Role::CLIENT, client_view_of_server_key);
```

### Step 4: Handshake

The handshake is a three-step process involving the exchange of ephemeral keys and signatures.

1.  **Client Initiates:** The client generates an ephemeral key and sends a `ClientHello` message.
    ```cpp
    // Client sends this to the server
    auto client_hello = client_session.client_initiate_handshake();
    ```

2.  **Server Responds:** The server receives the `ClientHello`, verifies it, generates its own ephemeral key, signs it, and computes the shared session keys. It then sends a `ServerHello` back.
    ```cpp
    // Server receives client_hello and sends this back
    auto server_hello = server_session.server_respond_to_handshake(client_hello);
    // The server's handshake is now complete
    assert(server_session.is_handshake_complete());
    ```

3.  **Client Finalizes:** The client receives the `ServerHello`, verifies the server's signature, and computes the same shared session keys.
    ```cpp
    // Client receives server_hello
    client_session.client_finalize_handshake(server_hello);
    // The client's handshake is now complete
    assert(client_session.is_handshake_complete());
    ```
At this point, both parties have a secure channel.

### Step 5: Data Transfer

To send data, you must first construct a `Payload`.

1.  **Create and Encrypt Payload:**
    ```cpp
    #include "obscuraproto/packet.hpp"

    // On the client
    ObscuraProto::Payload client_payload = ObscuraProto::PayloadBuilder(0x1001)
        .add_param("my_username")
        .add_param("my_secret_password")
        .add_param((uint32_t)1) // Example of adding an integer parameter
        .build();

    // Encrypt the payload to get a packet ready for transport
    ObscuraProto::EncryptedPacket packet_to_send = client_session.encrypt_payload(client_payload);
    ```
    The resulting `packet_to_send` is a `std::vector<uint8_t>` that can be sent over any network transport (TCP, UDP, etc.).

2.  **Receive and Decrypt Packet:**
    ```cpp
    // On the server, after receiving the packet_to_send
    try {
        ObscuraProto::Payload decrypted_payload = server_session.decrypt_packet(packet_to_send);

        // Parse the parameters
        ObscuraProto::PayloadReader reader(decrypted_payload);
        std::string username = reader.read_param_string();
        std::string password = reader.read_param_string();
        uint32_t login_attempts = reader.read_param_u32(); // Read the integer parameter
        
        // Use the data...
        std::cout << "Received username: " << username << ", password: " << password << ", attempts: " << login_attempts << std::endl;

    } catch (const ObscuraProto::RuntimeError& e) {
        // Decryption failed (e.g., invalid tag, replay attack)
        // The message must be discarded.
    }
    ```

## 6. High-Level API (WebSocket)

For most use cases, it is recommended to use the high-level WebSocket wrappers, which handle all the complexities of network communication, connection management, and the handshake process automatically.

The full example can be found in `examples/websocket_example.cpp`.

### 6.1. Bidirectional Request-Response Pattern

To simplify common request-response interactions, the high-level API provides dedicated methods for a **fully bidirectional** flow. Both the client and the server can initiate requests and respond to them. This pattern uses a special internal operation code (`0xFFFF`) for responses and prepends a unique request ID to the payload parameters.

#### Initiating a Request

Both `WsClientWrapper` and `WsServerWrapper` have an `async_request` method. It sends a request and returns a `std::future` that will be fulfilled with the response.

```cpp
// Client-side example
std::future<ObscuraProto::Payload> response_future = client.async_request(request_payload);

// Server-side example (requires a connection handle `hdl`)
std::future<ObscuraProto::Payload> response_future = server.async_request(hdl, request_payload);

// Common logic to get the response
if (response_future.wait_for(std::chrono::seconds(5)) == std::future_status::ready) {
    ObscuraProto::Payload response = response_future.get();
    // Process the application-level response payload.
    // The 0xFFFF wrapper is automatically handled by the library.
}
```

#### Handling a Request and Sending a Response

Requests from the other party are received in the standard `on_payload_callback`. Your application logic should identify the message as a request, parse its parameters (including the request ID), and use the corresponding `send_response` method.

-   **Request Payload Structure**: The first parameter is always the `uint32_t` request ID, followed by your application-specific parameters.
-   **Handling Logic**:
    1.  In `on_payload_callback`, check the `op_code` to identify a request.
    2.  Use `PayloadReader` to read the `request_id` first, then other parameters.
    3.  Create your application-level response `Payload`.
    4.  Call `send_response(request_id, response_payload)` on the client or `send_response(hdl, request_id, response_payload)` on the server.

```cpp
// Server-side example of handling a client's request
server.set_on_payload_callback([&server](auto hdl, ObscuraProto::Payload payload) {
    if (payload.op_code == 0x3001) { // A request from a client
        ObscuraProto::PayloadReader reader(payload);
        uint32_t request_id = reader.read_param_u32(); // 1. Read ID
        // ... read other params ...
        
        ObscuraProto::Payload response_payload = ObscuraProto::PayloadBuilder(0x3002).build();
        server.send_response(hdl, request_id, response_payload); // 2. Send response
    }
});

// Client-side example of handling a server's request
client.set_on_payload_callback([&client](ObscuraProto::Payload payload) {
    if (payload.op_code == 0x4001) { // A request from the server
        ObscuraProto::PayloadReader reader(payload);
        uint32_t request_id = reader.read_param_u32(); // 1. Read ID
        // ... read other params ...

        ObscuraProto::Payload response_payload = ObscuraProto::PayloadBuilder(0x4002).build();
        client.send_response(request_id, response_payload); // 2. Send response
    }
});
```

A complete example demonstrating this bidirectional pattern can be found in `examples/request_response_example.cpp`.

### Step 1: Initialization and Key Setup

This step is the same as in the low-level API. You need to initialize the crypto library and set up the server's keys.

```cpp
#include "obscuraproto/crypto.hpp"

// Initialize libsodium
ObscuraProto::Crypto::init();

// On the server: generate a long-term key
auto server_long_term_key = ObscuraProto::Crypto::generate_sign_keypair();

// On the client: configure the server's public key
ObscuraProto::KeyPair client_view_of_server_key;
client_view_of_server_key.publicKey = server_long_term_key.publicKey;
```

### Step 2: Running the Server

Create a `WsServerWrapper`, set a callback to handle incoming data, and run it on a port.

```cpp
#include "obscuraproto/ws_server.hpp"

// Create the server
ObscuraProto::net::WsServerWrapper server(server_long_term_key);

// Register a handler for a specific operation code (e.g., 0x1001)
server.register_op_handler(0x1001, [&server](auto hdl, ObscuraProto::Payload payload) {
    std::cout << "[SERVER] Received a payload with op_code 0x1001." << std::endl;
    
    // Example of reading mixed parameters
    ObscuraProto::PayloadReader reader(payload);
    std::string username = reader.read_param_string();
    std::string password = reader.read_param_string();
    uint32_t login_attempts = reader.read_param_u32();
    std::cout << "[SERVER] Decrypted: User=" << username << ", Pass=" << password << ", Attempts=" << login_attempts << std::endl;

    // Create and send a response
    ObscuraProto::Payload response_payload = ObscuraProto::PayloadBuilder(0x2002)
        .add_param("Hello from server!")
        .build();
    server.send(hdl, response_payload);
});

// Run the server on port 9002
server.run(9002);
```

### Step 3: Running the Client

Create a `WsClientWrapper`, set callbacks for events, and connect to the server.

```cpp
#include "obscuraproto/ws_client.hpp"

// Create the client
ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);

// Set a callback for when the secure channel is ready
client.set_on_ready_callback([&client]() {
    std::cout << "[CLIENT] Handshake complete. Sending a message..." << std::endl;
    ObscuraProto::Payload client_payload = ObscuraProto::PayloadBuilder(0x1001)
        .add_param("my_username")
        .add_param("my_password")
        .add_param((uint32_t)1)
        .build();
    client.send(client_payload);
});

// Register a handler for the response from the server (e.g., op_code 0x2002)
client.register_op_handler(0x2002, [](ObscuraProto::Payload payload) {
    std::cout << "[CLIENT] Received a response from the server." << std::endl;
    ObscuraProto::PayloadReader reader(payload);
    std::string message = reader.read_param_string();
    std::cout << "[CLIENT] Decrypted response: " << message << std::endl;
});

// Connect to the server
client.connect("ws://localhost:9002");

// ... wait for work to be done ...

// Disconnect when finished
client.disconnect();
server.stop();
```

### Dependencies

This library requires **libsodium**, **websocketpp**, and **asio**. If you are using CMake, they will be fetched and configured automatically via `FetchContent`. You only need to link against the `obscuraproto` target.

```cmake
target_link_libraries(your_executable_name
    PRIVATE
        obscuraproto
)
```
