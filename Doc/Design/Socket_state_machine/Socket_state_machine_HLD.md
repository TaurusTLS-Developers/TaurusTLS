# High-Level Design: TaurusTLS "Socket State Machine"

## 1. Architecture Overview
The **TaurusTLS "Socket State Machine" (SSM)** is a core architectural layer designed to manage the lifecycle of a secure connection. It acts as an intermediary between the Indy `TIdIOHandler` and the OpenSSL 4.0 engine. Its primary goal is to ensure I/O safety, handle protocol-specific transitions (SSLv3 to TLS 1.3), and prevent process-level crashes (SIGPIPE) caused by unaligned socket states.

```
+-------------------------------------------------------+
|              TIdHTTP / Indy Protocols                 |
+-------------------------------------------------------+
                           |
+-------------------------------------------------------+
|             TTaurusTLSIOHandlerSocket                 |  
+-------------------------------------------------------+
       |
       | Instantiates & Freezes Properties
       v
+-------------------------------------------------------+
|            TTaurusTLSHandshakeSnapshot                |  <-- Standard Class, Zero Ref-Counting
|  - FContext: PSSL_CTX                                 |  <-- Keeps SSL_CTX Alive via Reference Count
+-------------------------------------------------------+
       |
       | Ownership Transferred To
       v
+-------------------------------------------------------+
|                 TTaurusTLSBaseSocket                  |  <-- Manages Snapshot Lifetime
+-------------------------------------------------------+
       |                           |
       | (Outbound Client)         | (Inbound Peer)
       v                           v
+-------------------------------------------------------+ +-------------------------------------------------------+
|              TTaurusTLSClientSocket                   | |               TTaurusTLSPeerSocket                    |
+-------------------------------------------------------+ +-------------------------------------------------------+
       |                                                                         |
       +-----------------------------------+-------------------------------------+
                                           | Dispatches to
                                           v
                                    +--------------------------------------------+
                                    |          TTaurusSSLState (Active)          |
                                    +--------------------------------------------+
```

## 2. Core Architectural Patterns

### 2.1. The GoF State Pattern
Instead of a monolithic class with complex conditional branching, states are represented as lightweight, polymorphic classes inheriting from a common abstract base (`TTaurusSSLState`). The active state object executes state-specific protocol actions (e.g., ECH, mTLS, TLS 1.3 post-handshake) and delegates standard operations (`Read`, `Write`, `Connect`, `Shutdown`) to the OpenSSL C-API.

### 2.2. Role-Based Socket Polymorphism
The socket layer is divided into specialized descendants of `TTaurusTLSBaseSocket`:
*   `TTaurusTLSClientSocket`: Implements outbound connections using `SSL_connect`. It contains client-specific properties, including ECH configurations and properties for explicit TLS session resumption (`SSL_set_session` or `SSL_copy_session_id`).
*   `TTaurusTLSPeerSocket`: Implements inbound server-side accepted connections using `SSL_accept`. It relies on the server-side `SSL_CTX` cache for session resumption and does not contain outbound ECH configurations.

### 2.3. The Handshake Snapshot Pattern
To prevent data races and avoid Delphi `IInterface` vs. `TComponent` lifecycle conflicts, the connection's parameters and event pointers are frozen into a standard class (`TTaurusTLSHandshakeSnapshot`) right before the handshake starts. The active state classes and static callback bridges refer exclusively to this snapshot. The `TTaurusTLSBaseSocket` owns the snapshot and destroys it during teardown.

### 2.4. Context Memory Protection
The `TTaurusTLSHandshakeSnapshot` class keeps the shared `SSL_CTX` alive during asynchronous handshakes by incrementing its OpenSSL reference count via `SSL_CTX_up_ref` upon creation. Upon destruction, it decrements the count using `SSL_CTX_free`. This prevents use-after-free bugs if the parent component is destroyed mid-handshake or if the configuration is reassigned.

## 3. State Definitions
*   **seIdle**: The initial state. No OpenSSL objects exist.
*   **seInitialized**: `SSL` object is created and "armed" with a frozen snapshot of configuration parameters.
*   **seHandshaking**: Active negotiation. Executes SNI, ECH, and mTLS certificate exchanges.
*   **seEstablished**: Handshake successful. Data exchange is permitted.
*   **seClosing**: Graceful, bidirectional shutdown initiated (`CloseNotify` sent).
*   **seClosed**: Connection terminated. Socket is safe to close.
*   **seError**: Fatal protocol or transport error (e.g., Decryption failure).

## 4. Stability & Security Pillars

### 4.1. The SIGPIPE / TCP RST Shield
To prevent OS-level process termination during TCP RST events, the SSM implements:
1.  **Global Signal Masking**: Ignoring `SIGPIPE` at the POSIX level (`signal(SIGPIPE, SIG_IGN)`).
2.  **State-Gated I/O**: No `SSL_write` is attempted if the state is `seError` or `seClosed`.
3.  **Immediate RST Teardown**: Mapping `SSL_ERROR_SYSCALL` + `EPIPE/ECONNRESET` to an immediate `seClosed` transition. This instantly calls `SSL_free` (bypassing `SSL_shutdown`) and closes the physical socket.

### 4.2. Strict ECH Enforcement
The SSM follows a **"Success or Abort"** policy. If ECH is configured but the server falls back to a decoy "Outer" SNI (returning `SSL_ECH_STATUS_GREASE_ECH` or `SSL_ECH_STATUS_FAILED`), the SSM transitions to `seError` (or `seClosed` if a retry config is retrieved) and aborts the connection before any application data is sent.

### 4.3. TLS 1.3 Post-Handshake Asynchronicity
The SSM handles post-handshake events (NewSessionTickets, Post-Handshake Authentication) by treating `SSL_read` as a potential state-changing operation. If `SSL_read` returns `WANT_READ` in `seEstablished`, the SSM transparently processes the protocol message and resumes waiting for application data.

## 5. Event Lifecycle & Callback Routing
The SSM acts as a callback bridge by mapping the `PSSL` handle back to the `TTaurusTLSBaseSocket` instance using `SSL_get_app_data`.

### 5.1. Lifecycle Transition Monitoring (`OnStateChange`)
Fired synchronously inside the Context's transition method after the validation matrix approves the transition but before the new state class is instantiated.

### 5.2. Handshake Event Sequence
1.  **stHandshaking begins**: `OnStatusInfo` fires ("Handshake started").
2.  **Verify Peer**: `OnVerifyCallback` fires for each certificate in the chain.
3.  **Validation (Optional)**: `OnVerifyError` fires if validation fails.
4.  **Negotiation Complete**: `SSL_do_handshake` returns `1`.
5.  **Gatekeeper Check**: `OnSecurityLevel` fires. If the application rejects the negotiated protocol or cipher strength, the handshake is aborted.
6.  **Handshake Established**: `seEstablished` is reached; `OnSSLNegotiated` fires.
