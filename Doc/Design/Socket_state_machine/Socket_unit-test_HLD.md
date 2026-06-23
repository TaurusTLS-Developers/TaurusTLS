# High-Level Test Plan: Socket Unit-Testing (SO-UT)

## 1. Objectives
The objective of this test suite is to validate the actual execution of cryptographic processes, key exchanges, ECH handshakes, mTLS validations, and physical data transport inside `TTaurusTLSClientSocket` and `TTaurusTLSPeerSocket` under mock-free, real OpenSSL execution.

## 2. Test Scope & Exclusions
*   **In Scope**: Cryptographic handshakes, ECH fallback/retry scenarios, client certificate validation events, and the TCP RST/SIGPIPE shield.
*   **Out of Scope**: Physical network interfaces, operating system firewalls, and Indy high-level blocking wrappers. Handshakes must execute purely in-memory.

## 3. Test Components and Mocking Strategy

### 3.1. TaurusTLS Components
*   **`TTaurusTLSClientSocket` and `TTaurusTLSPeerSocket`**: The actual cryptographic engines under evaluation.
*   **`TTaurusTLSMemBio` (Read-Write)**: Used to intercept, buffer, and pump raw transport bytes between the sockets in-memory.
*   **`TaurusTLSClientSocketConfig` and `TTaurusTLSCustomSocketConfig`**: Configured with real, test-specific X.509 credentials (test root CA, test server leaf certificate, and test ECH keys).

### 3.2. Threaded Handshake Harness
Because Indy’s socket operations are synchronously blocking, a single-threaded loopback cannot negotiate a handshake (as the first call to `SSL_connect` would block waiting for data that hasn't been pumped yet). 
*   **The Strategy**: The unit test instantiates two lightweight Delphi background threads: one running `TTaurusTLSClientSocket.Connect` and the other running `TTaurusTLSPeerSocket.Connect`.
*   **The Bytes Pump**: The main unit-test thread runs a non-blocking loop that pumps raw encrypted bytes back and forth between the client's and server's `TTaurusTLSMemBio` instances until both threads complete.

---

## 4. Test Methods & Scenarios

### 4.1. Memory BIO Loopback Handshake (The Core Test Method)
*   **Method**: Instantiate a Client Socket and a Peer Socket. Intercept their I/O channels using `SSL_set_bio` with separate read and write `TTaurusTLSMemBio` instances. Spin up the threaded handshake harness.
*   **Verification**: 
    1.  Both sockets must transition successfully from `seHandshaking` to `seEstablished`.
    2.  Subsequent read/write operations must succeed natively through `SSL_read_ex` and `SSL_write_ex` using the bytes pump.

### 4.2. ECH Key Mismatch & Retry Config Validation
*   **Method**:
    1.  Load the server context (`TTaurusTLSPeerSocket`) with a valid ECH Key Pair.
    2.  Configure the client context (`TTaurusTLSClientSocket`) with an **invalid** (outdated) ECH Config.
    3.  Execute the loopback handshake.
*   **Verification**:
    1.  The client handshake must fail, preventing the transition to `seEstablished`.
    2.  The client must raise an `ETaurusTLSECHRetryRequired` exception.
    3.  The exception's `RetryConfigList` property must contain a valid, Base64-encoded `ECHConfigList` that matches the server's current public key.

### 4.3. Client Certificate / mTLS Interception
*   **Method**: Configure the server context to require client certificates (`cvfFailIfNoPeer`). 
*   **Scenario A (No Cert)**: Execute the handshake without providing a client cert. Verify that the client is rejected, the peer transitions to `seError`, and the connection is aborted.
*   **Scenario B (Valid Cert)**: Provide a valid client cert. Verify that both transition to `seEstablished`, and `OnVerifyCertificate` fires successfully on the server side.

### 4.4. TCP RST Shield Validation
*   **Method**: Move the client and peer to `seEstablished`. Simulate a sudden TCP Reset on the peer side.
*   **Simulation**: Force the peer's underlying socket handle to close, and mock a write error (`SSL_ERROR_SYSCALL`) on the client side.
*   **Verification**:
    1.  Verify that the client socket immediately transitions to `seClosed`.
    2.  Verify that `SSL_free` is called instantly (bypassing any `SSL_shutdown` protocol attempts).
    3.  Verify that the socket descriptor is closed safely without throwing unhandled exceptions.

### 4.5. Session Resumption (TLS 1.3 Ticket)
*   **Method**: 
    1.  Perform a successful Loopback Handshake.
    2.  Extract the generated `SSL_SESSION` from the client socket.
    3.  Instantiate a new client socket, passing the extracted session to `TaurusTLSClientSocketConfig`.
    4.  Execute a new loopback handshake.
*   **Verification**: 
    1.  Verify that the connection is established.
    2.  Query `SSL_session_reused(SSL)` on the client to assert that the session was resumed instead of performing a full key exchange.