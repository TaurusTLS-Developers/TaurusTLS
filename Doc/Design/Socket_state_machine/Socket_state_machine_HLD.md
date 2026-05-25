# High-Level Design: TaurusTLS "Socket State Machine"

## 1. Architecture Overview
The **TaurusTLS "Socket State Machine" (SSM)** is a core architectural layer designed to manage the lifecycle of a secure connection. It acts as an intermediary between the Indy `TIdIOHandler` pipeline and the OpenSSL 3.x and 4.0 engine. 

To maintain strict alignment with Indy's component and factory architectures, TaurusTLS utilizes a single outer component wrapper (`TTaurusTLSIOHandlerSocket`) that inherits from Indy's native `TIdSSLIOHandlerSocketBase`. Internally, this component encapsulates a polymorphic State Machine (`TTaurusTLSBaseSocket`) that isolates client-specific and server-specific connection logic depending on whether the connection is executing in a client or server-peer role.

```
+-------------------------------------------------------------+
|                 TTaurusTLSIOHandlerSocket                   |  <-- Registered in DFM / dropped on form
|            (Inherits TIdSSLIOHandlerSocketBase)             |  <-- Implements RecvEnc/SendEnc, Clone, etc.
+-------------------------------------------------------------+
                               |
                               | ConnectClient / AfterAccept
                               v
+-------------------------------------------------------------+
|             TTaurusTLSCustomSocketConfig                    |  <-- Keeps SSL_CTX alive (SSL_CTX_up_ref)
+-------------------------------------------------------------+  <-- Freezes data properties & event pointers
                               |
                               | Instantiates based on "IsPeer"
                               v
                +--------------+--------------+
                |                             |
                v                             v
+-----------------------------+ +-----------------------------+
|   TTaurusTLSClientSocket    | |    TTaurusTLSPeerSocket     |  <-- State Machine Engines
|  - Calls SSL_connect        | |  - Calls SSL_accept         |  <-- Managed by TTaurusTLSBaseSocket
+-----------------------------+ +-----------------------------+
                               |
                               +------------+
                                            v
                                 TTaurusTLSSslStateHandler (Active Handler)
```

## 2. Component Integration & Indy Pipeline Mapping

### 2.1. The Single Outer Wrapper (`TTaurusTLSIOHandlerSocket`)
The outer component represents the actual connection instance. It remains a single class type to satisfy Indy's design-time serialization, streaming, and data-channel factory mechanics (`Clone`, `MakeClientIOHandler`, `MakeFTPSvrPasv`, `MakeFTPSvrPort`).
*   It overrides `RecvEnc` and `SendEnc` to route the data flow directly through the internal state machine.
*   It overrides `ConnectClient` (for outbound client handshakes) and `AfterAccept` (for inbound accepted peer handshakes).

### 2.2. The Internal Polymorphic Engine (`TTaurusTLSBaseSocket` descendants)
At the start of a connection, `TTaurusTLSIOHandlerSocket` evaluates Indy's native `IsPeer` boolean flag to instantiate the correct polymorphic execution engine:
*   `IsPeer = False` $\rightarrow$ Instantiates `TTaurusTLSClientSocket`. Uses the `SSL_connect` handshake loop, handles client-side ECH configs, and implements client session resumption.
*   `IsPeer = True` $\rightarrow$ Instantiates `TTaurusTLSPeerSocket`. Uses the `SSL_accept` handshake loop and relies on the shared server-side context for automatic session cache lookup.

### 2.3. The I/O Pipeline Integration
When `PassThrough` is set to `False` (encryption is active), Indy’s read/write pipeline routes raw data through the following abstract hooks in our wrapper:
*   `function RecvEnc(var VBuffer: TIdBytes): Integer; override;` $\rightarrow$ Delegates to the active state's `Recv` operation, wrapping the OpenSSL `SSL_read` loop.
*   `function SendEnc(const ABuffer: TIdBytes; const AOffset, ALength: Integer): Integer; override;` $\rightarrow$ Delegates to the active state's `Send` operation, wrapping the OpenSSL `SSL_write` loop.

## 3. Core Architectural Patterns

### 3.1. The GoF State Pattern
Instead of a monolithic class with complex conditional branching, states are represented as lightweight, polymorphic classes inheriting from a common abstract base (`TTaurusTLSSslStateHandler`). The active handler object executes state-specific protocol actions (e.g., ECH, mTLS, TLS 1.3 post-handshake) and delegates standard operations (`Recv`, `Send`, `Connect`, `Shutdown`) to the OpenSSL C-API.

### 3.2. The Handshake Config Class Pattern
To prevent data races and avoid Delphi `IInterface` vs. `TComponent` lifecycle conflicts, the connection's parameters and event pointers are frozen into a polymorphic configuration class (`TTaurusTLSCustomSocketConfig` and its descendants `TTaurusTLSClientSocketConfig` and `TTaurusTLSPeerSocketConfig`) right before the handshake starts. The active handler classes and static callback bridges refer exclusively to this configuration instance. The `TTaurusTLSBaseSocket` owns the config object and destroys it during teardown.

### 3.3. Context Memory Protection
The `TTaurusTLSCustomSocketConfig` class keeps the shared `SSL_CTX` alive during asynchronous handshakes by incrementing its OpenSSL reference count via `SSL_CTX_up_ref` upon creation. Upon destruction, it decrements the count using `SSL_CTX_free`. This prevents use-after-free bugs if the parent component is destroyed mid-handshake or if the configuration is reassigned.

## 4. State Definitions
*   **seIdle**: The initial state. No OpenSSL objects exist.
*   **seInitialized**: `SSL` object is created and "armed" with a frozen snapshot of configuration parameters.
*   **seHandshaking**: Active negotiation. Executes SNI, ECH, and mTLS certificate exchanges.
*   **seEstablished**: Handshake successful. Data exchange is permitted.
*   **seClosing**: Graceful, bidirectional shutdown initiated (`CloseNotify` sent).
*   **seClosed**: Connection terminated. Socket is safe to close.
*   **seError**: Fatal protocol or transport error (e.g., Decryption failure).

## 5. Stability & Security Pillars

### 5.1. The SIGPIPE / TCP RST Shield
To prevent OS-level process termination during TCP RST events, the SSM implements:
1.  **Global Signal Masking**: Ignoring `SIGPIPE` at the POSIX level (`signal(SIGPIPE, SIG_IGN)`).
2.  **State-Gated I/O**: No `SSL_write` is attempted if the state is `seError` or `seClosed`.
3.  **Immediate RST Teardown**: Mapping `SSL_ERROR_SYSCALL` + `EPIPE/ECONNRESET` to an immediate `seClosed` transition. This instantly calls `SSL_free` (bypassing `SSL_shutdown`) and closes the physical socket.

### 5.2. Strict ECH Enforcement
The SSM follows a **"Success or Abort"** policy. If ECH is configured but the server falls back to a decoy "Outer" SNI (returning `SSL_ECH_STATUS_GREASE_ECH` or `SSL_ECH_STATUS_FAILED`), the SSM transitions to `seError` (or `seClosed` if a retry config is retrieved) and aborts the connection before any application data is sent.

### 5.3. TLS 1.3 Post-Handshake Asynchronicity
The SSM handles post-handshake events (NewSessionTickets, Post-Handshake Authentication) by treating `SSL_read` as a potential state-changing operation. If `SSL_read` returns `WANT_READ` in `seEstablished`, the SSM transparently processes the protocol message and resumes waiting for application data via `Recv`.

## 6. Event Lifecycle & Callback Routing
The SSM acts as a callback bridge by mapping the `PSSL` handle back to the `TTaurusTLSBaseSocket` instance using `SSL_get_app_data`.

### 6.1. Lifecycle Transition Monitoring (`OnStateChange`)
Fired synchronously inside the Context's transition method after the validation matrix approves the transition but before the new state class is instantiated.

### 6.2. Handshake Event Sequence
1.  **seHandshaking begins**: `OnStatusInfo` fires ("Handshake started").
2.  **Verify Peer**: `OnVerifyCallback` fires for each certificate in the chain.
3.  **Validation (Optional)**: `OnVerifyError` fires if validation fails.
4.  **Negotiation Complete**: `SSL_do_handshake` returns `1`.
5.  **Gatekeeper Check**: `OnSecurityLevel` fires. If the application rejects the negotiated protocol or cipher strength, the handshake is aborted.
6.  **Handshake Established**: `seEstablished` is reached; `OnSSLNegotiated` fires.
