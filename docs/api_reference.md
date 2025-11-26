# ObscuraProto API Reference

This document provides a detailed description of every public component in the ObscuraProto library.

---

## `errors.hpp`

Defines the hierarchy of exceptions used in the library.

### `class ObscuraProto::Exception`
The base class for all library exceptions. Inherits from `std::exception`.

#### `virtual const char* what() const noexcept override`
Returns the error message.

---

### `class ObscuraProto::RuntimeError`
An exception thrown for runtime errors.
- **Examples:** decryption failure, invalid signature, key exchange error.

---

### `class ObscuraProto::LogicError`
An exception indicating incorrect API usage.
- **Examples:** attempting to encrypt data before the handshake is complete, calling a server-only method on the client side.

---

### `class ObscuraProto::InvalidArgument`
An exception thrown when incorrect arguments are passed to a function. Inherits from `LogicError`.
- **Examples:** passing a key of the wrong size.

---

## `keys.hpp`

Defines basic structures for storing cryptographic keys and signatures.

### `struct ObscuraProto::PublicKey`
Represents a public key.
- `std::vector<uint8_t> data`: Raw bytes of the key.

### `struct ObscuraProto::PrivateKey`
Represents a private key.
- `std::vector<uint8_t> data`: Raw bytes of the key.

### `struct ObscuraProto::KeyPair`
Represents a pair consisting of a public and a private key.
- `PublicKey publicKey`: The public key.
- `PrivateKey privateKey`: The private key.

### `struct ObscuraProto::Signature`
Represents a digital signature.
- `std::vector<uint8_t> data`: Raw bytes of the signature.

---

## `version.hpp`

Defines constants and types for managing the protocol version.

### `using Version = uint16_t`
An alias for the protocol version type. Version `1.0` is represented as `0x0100`.

### `const std::vector<Version> SUPPORTED_VERSIONS`
A list of protocol versions supported by the current library version.

---

## `packet.hpp`

Defines the structure of the payload before encryption and after decryption, and provides helper classes for building and parsing payloads.

### `using byte_vector = std::vector<uint8_t>`
An alias for representing a byte array.

### `using EncryptedPacket = byte_vector`
An alias for an encrypted packet. Its content is opaque and ready for network transmission.

### `class ObscuraProto::Payload`
A class that holds the operation code and serialized parameters.

- `OpCode op_code`: A 16-bit operation code that defines the message type.
- `byte_vector parameters`: Serialized parameters for the given operation.

#### `byte_vector serialize() const`
Serializes the entire `Payload` object (op code + parameters) into a single byte array, ready for encryption.

#### `static Payload deserialize(const byte_vector& data)`
Deserializes a byte array back into a `Payload` object.
- **Throws:** `RuntimeError` if the data is corrupted or its size is insufficient.

---

### `class ObscuraProto::PayloadBuilder`
A helper class for fluently constructing `Payload` objects with various parameters.

#### `explicit PayloadBuilder(Payload::OpCode op_code)`
Constructor. Initializes the builder with the specified operation code.

#### `PayloadBuilder& add_param(const byte_vector& param)`
Adds a parameter as a byte array. Uses length-prefix serialization (2 bytes for length + N bytes for data).
- **Returns:** A reference to the builder for method chaining.
- **Throws:** `RuntimeError` if the parameter size exceeds `UINT16_MAX`.

#### `PayloadBuilder& add_param(const std::string& param)`
Adds a string parameter.
- **Returns:** A reference to the builder for method chaining.
- **Throws:** `RuntimeError` if the parameter size exceeds `UINT16_MAX`.

#### `PayloadBuilder& add_param(uint32_t param)`
Adds a `uint32_t` integer parameter. The integer is converted to network byte order (Big-Endian) and then length-prefixed.
- **Returns:** A reference to the builder for method chaining.

#### `Payload build()`
Finalizes the construction and returns the `Payload` object.

---

### `class ObscuraProto::PayloadReader`
A helper class for sequentially extracting parameters from a received `Payload`.

#### `explicit PayloadReader(const Payload& payload)`
Constructor. Initializes the reader with the `parameters` field from a `Payload` object.

#### `byte_vector read_param_bytes()`
Extracts the next parameter as a raw byte array.
- **Returns:** The parameter as a `byte_vector`.
- **Throws:** `RuntimeError` if the data is malformed or insufficient for the next parameter.

#### `std::string read_param_string()`
Extracts the next parameter as a string.
- **Returns:** The parameter as a `std::string`.
- **Throws:** `RuntimeError` if the data is malformed or insufficient for the next parameter.

#### `uint32_t read_param_u32()`
Extracts the next parameter as a `uint32_t` integer. The integer is converted from network byte order (Big-Endian) to host byte order.
- **Returns:** The parameter as a `uint32_t`.
- **Throws:** `RuntimeError` if the data is malformed, insufficient, or not exactly 4 bytes long.

#### `bool has_more() const`
Checks if there are more parameters to read in the payload.
- **Returns:** `true` if there are unread parameters, `false` otherwise.

---

## `crypto.hpp`

A static class that provides all low-level cryptographic functions.

### `static int init()`
Initializes the cryptographic library (libsodium). **Must be called once** at application startup.
- **Returns:** `0` on success, `-1` on error.

### `static KeyPair generate_kx_keypair()`
Generates a key pair (X25519) for key exchange using the Diffie-Hellman (ECDH) algorithm.

### `static KeyPair generate_sign_keypair()`
Generates a key pair (Ed25519) for creating and verifying digital signatures.

### `static Signature sign(const byte_vector& message, const PrivateKey& private_key)`
Creates a digital signature for a message.
- **Throws:** `InvalidArgument` if the private key size is incorrect.

### `static bool verify(const Signature& signature, const byte_vector& message, const PublicKey& public_key)`
Verifies a digital signature.
- **Returns:** `true` if the signature is valid, otherwise `false`.

### `struct SessionKeys`
A structure for storing session keys obtained after the handshake.
- `byte_vector rx`: The key for decrypting incoming messages.
- `byte_vector tx`: The key for encrypting outgoing messages.

### `static SessionKeys client_compute_session_keys(...)`
**For the client.** Computes session keys based on its own ephemeral key pair and the server's ephemeral public key.
- **Throws:** `InvalidArgument` for incorrect key sizes, `RuntimeError` on computation failure.

### `static SessionKeys server_compute_session_keys(...)`
**For the server.** Computes session keys based on its own ephemeral key pair and the client's ephemeral public key.
- **Throws:** `InvalidArgument` for incorrect key sizes, `RuntimeError` on computation failure.

### `static EncryptedPacket encrypt(const Payload& payload, uint64_t counter, const byte_vector& key)`
Encrypts a `Payload` using ChaCha20-Poly1305.
- `counter`: A message counter for replay attack protection. It is included in the packet as associated data (not encrypted, but protected by the authentication tag).
- **Returns:** An `EncryptedPacket` in the format `[Nonce][Counter][Ciphertext+Tag]`.
- **Throws:** `InvalidArgument` for an incorrect key size.

### `struct DecryptedResult`
The result of a successful decryption.
- `Payload payload`: The decrypted payload.
- `uint64_t counter`: The counter extracted from the packet.

### `static DecryptedResult decrypt(const EncryptedPacket& packet, const byte_vector& key)`
Decrypts a packet. Verifies the authentication tag.
- **Returns:** `DecryptedResult` on success.
- **Throws:** `InvalidArgument` for an incorrect key size, `RuntimeError` on decryption failure (invalid tag, corrupted data).

---

## `handshake_messages.hpp`

Defines the structures used during the handshake phase.

### `struct ObscuraProto::ClientHello`
Represents the initial message sent by the client.
- `std::vector<Version> supported_versions`: A list of protocol versions the client supports.
- `PublicKey ephemeral_pk`: The client's ephemeral public key for this session.

#### `byte_vector serialize() const`
Serializes the `ClientHello` object into a byte vector for network transmission.

#### `static ClientHello deserialize(const byte_vector& data)`
Deserializes a byte vector back into a `ClientHello` object.
- **Throws:** `RuntimeError` if the data is corrupted or its size is insufficient.

---

### `struct ObscuraProto::ServerHello`
Represents the server's response to a `ClientHello`.
- `Version selected_version`: The protocol version selected by the server.
- `PublicKey ephemeral_pk`: The server's ephemeral public key for this session.
- `Signature signature`: The server's signature over its ephemeral public key, for authentication.

#### `byte_vector serialize() const`
Serializes the `ServerHello` object into a byte vector for network transmission.

#### `static ServerHello deserialize(const byte_vector& data)`
Deserializes a byte vector back into a `ServerHello` object.
- **Throws:** `RuntimeError` if the data is corrupted or its size is insufficient.

---

## Network Wrappers (`ws_client.hpp`, `ws_server.hpp`)

These files provide high-level wrappers for running the ObscuraProto protocol over WebSockets. This is the recommended API for most use cases.

### `namespace ObscuraProto::net`
Contains all network-related classes.

---

### `class ObscuraProto::net::WsServerWrapper`
A wrapper that runs a WebSocket server to handle multiple secure client connections.

#### `WsServerWrapper(KeyPair server_sign_key)`
Constructor.
- `server_sign_key`: The server's long-term signing key pair (public and private).

#### `void run(uint16_t port)`
Starts the server in a new thread, listening for connections on the specified port.

#### `void stop()`
Stops the server and disconnects all clients.

#### `void send(WsConnectionHdl hdl, const Payload& payload)`
Encrypts and sends a `Payload` to a specific client identified by their connection handle `hdl`.

#### `void send_response(WsConnectionHdl hdl, uint32_t request_id, const Payload& payload)`
Sends a response to a client for a previously received request. The `payload` provided here is the application-level response. The library handles wrapping it with the internal `RESPONSE_OP_CODE` (`0xFFFF`) and the `request_id`.
- `hdl`: The connection handle of the client to send the response to.
- `request_id`: The unique ID of the request this response is for, extracted from the incoming request payload.
- `payload`: The application-level `Payload` containing the actual response data.

#### `std::future<Payload> async_request(WsConnectionHdl hdl, const Payload& payload)`
Sends a `Payload` as a request to a specific client and returns a `std::future` that will be fulfilled with the client's response.
- `hdl`: The connection handle of the client to send the request to.
- `payload`: The application-level `Payload` to send as a request.
- **Returns:** A `std::future<Payload>` that will eventually hold the client's application-level response.
- **Throws:** `LogicError` if the session is not ready.

#### `void set_on_payload_callback(OnPayloadCallback callback)`
Sets a callback function to be invoked when a valid, decrypted `Payload` is received from any client. This callback handles both push messages and requests that require a response.
- **Callback signature:** `std::function<void(WsConnectionHdl, Payload)>`

---

### `class ObscuraProto::net::WsClientWrapper`
A wrapper that runs a WebSocket client to connect to a secure server.

#### `WsClientWrapper(KeyPair server_sign_key)`
Constructor.
- `server_sign_key`: A `KeyPair` containing only the server's public signing key.

#### `void connect(const std::string& uri)`
Connects to the server at the given WebSocket URI (e.g., `ws://localhost:9002`) and starts the client thread. The handshake is initiated automatically upon connection.

#### `void disconnect()`
Disconnects from the server.

#### `void send(const Payload& payload)`
Encrypts and sends a `Payload` to the server.

#### `std::future<Payload> async_request(const Payload& payload)`
Sends a `Payload` as a request to the server and returns a `std::future` that will be fulfilled with the server's response.
- `payload`: The application-level `Payload` to send as a request.
- **Returns:** A `std::future<Payload>` that will eventually hold the server's application-level response.
- **Throws:** `LogicError` if the session is not ready.

#### `void send_response(uint32_t request_id, const Payload& payload)`
Sends a response to the server for a previously received request.
- `request_id`: The unique ID of the request this response is for, extracted from the incoming request payload.
- `payload`: The application-level `Payload` containing the actual response data.

#### `void set_on_ready_callback(OnReadyCallback callback)`
Sets a callback to be invoked when the handshake with the server is successfully completed.
- **Callback signature:** `std::function<void()>`

#### `void set_on_payload_callback(OnPayloadCallback callback)`
Sets a callback to be invoked when a valid, decrypted `Payload` is received from the server. This callback handles both push messages and requests from the server that require a response.
- **Callback signature:** `std::function<void(Payload)>`

#### `void set_on_disconnect_callback(OnDisconnectCallback callback)`
Sets a callback to be invoked when the client is disconnected from the server.
- **Callback signature:** `std::function<void()>`

---

## `session.hpp`

The main class for managing session state.

### `enum class Role`
Defines the role of the current party.
- `CLIENT`: The session is a client.
- `SERVER`: The session is a server.

### `class ObscuraProto::Session`
Manages the session state, including the handshake and data exchange.

#### `Session(Role role, KeyPair server_sign_key)`
Session constructor.
- `role`: The role of this session (`CLIENT` or `SERVER`).
- `server_sign_key`:
    - For a **server**: the full long-term signing key pair (public and private).
    - For a **client**: a pair containing only the server's public signing key.

- `struct ClientHello`: A message from the client to the server. Contains a list of supported versions and the client's ephemeral public key.
- `struct ServerHello`: A message from the server to the client. Contains the selected version, the server's ephemeral public key, and its signature.

These structures have been moved to `handshake_messages.hpp`.

### Handshake Methods

#### `ClientHello client_initiate_handshake()`
**For the client.** Initiates the handshake. Generates an ephemeral key pair and creates a `ClientHello`.
- **Throws:** `LogicError` if called on the server side.

#### `ServerHello server_respond_to_handshake(const ClientHello& client_hello)`
**For the server.** Processes a `ClientHello`, generates its own ephemeral pair, computes the session keys, and returns a `ServerHello`.
- **Throws:** `LogicError` if called on the client side; `RuntimeError` for version incompatibility or crypto operation failure.

#### `void client_finalize_handshake(const ServerHello& server_hello)`
**For the client.** Finalizes the handshake. Verifies the server's signature and computes the session keys.
- **Throws:** `LogicError` if called before `client_initiate_handshake`; `RuntimeError` for an invalid signature or crypto operation failure.

### Data Exchange Methods

#### `EncryptedPacket encrypt_payload(const Payload& payload)`
Encrypts a `Payload`. Automatically increments the sent message counter.
- **Throws:** `LogicError` if the handshake is not complete.

#### `Payload decrypt_packet(const EncryptedPacket& packet)`
Decrypts an `EncryptedPacket`. Checks the message counter for replay attack protection.
- **Returns:** `Payload` on success.
- **Throws:** `LogicError` if the handshake is not complete; `RuntimeError` on decryption failure or if a replay attack is detected.

### Other Methods

#### `bool is_handshake_complete() const`
Checks if the handshake has been successfully completed.
- **Returns:** `true` if the session is ready for data exchange.

---

## Protocol Constants

### `constexpr uint16_t RESPONSE_OP_CODE = 0xFFFF`
An internal operation code used by the request-response mechanism to identify a response message. This code is handled internally by the `WsClientWrapper` and `WsServerWrapper` and is not typically exposed to the application logic.
