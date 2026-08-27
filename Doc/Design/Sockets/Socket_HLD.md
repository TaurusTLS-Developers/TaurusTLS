# High-Level Design: TaurusTLS Socket and Socket State Machine (SSM)

## 1. Architecture Overview
The **TaurusTLS Socket and Socket State Machine (SSM)** are the core architectural layers governing the lifecycle of secure TLS connections. It serves as an intermediary between the Indy `TIdIOHandler` transport pipeline and the OpenSSL 3.x/4.0 engine.

TaurusTLS 2 implements an immutable-context, non-recursive, non-blocking state machine designed for high throughput, fine-grained timeout management, and multithreaded safety.

```
+-------------------------------------------------------------+
|                 TTaurusTLSIOHandlerSocket                   |  <-- High-Level Indy IOHandler (Control Plane)
+-------------------------------------------------------------+
                               |
                               | ConnectClient / AfterAccept
                               v
+-------------------------------------------------------------+
|               TTaurusTLSSslSocketCtxBuilder                 |  <-- Thread-Safe Builder (Compiles SSL_CTX)
+-------------------------------------------------------------+  <-- Manages X509VerifyParam & Trust Stores
                               |
                               | Build(ASender) / FreezeCtx
                               v
+-------------------------------------------------------------+
|                   ITaurusTLSSslSocketCtx                    |  <-- Reference-Counted Lifetime Interface
+-------------------------------------------------------------+
                               |
                               | Passed to Constructor
                               v
+-------------------------------------------------------------+
|                    TTaurusTLSSslSocket                      |  <-- State Machine Context Engine (Data Plane)
|    - FContextIntf: ITaurusTLSSslSocketCtx (Lifetime)        |  <-- RAII Reference Tracking
|    - FCtx: TTaurusTLSSslSocketCtx (Direct Pointer)          |  <-- O(1) Direct Memory Offset Lookups
+-------------------------------------------------------------+
                               |
                +--------------+--------------+
                |                             |
                v                             v
+-----------------------------+ +-----------------------------+
|   TTaurusTLSClientSocket    | |    TTaurusTLSPeerSocket     |  <-- Specialized Handshake Executors
|  - Overrides SetupConnection | |  - Overrides SetupConnection |
|  - Overrides HandshakeStep  | |  - Overrides HandshakeStep  |
+-----------------------------+ +-----------------------------+
                               |
                               +------------> TTaurusTLSSslSocketState (Active State Enum)
```

---

## 2. Component Integration & Indy Pipeline Mapping

### 2.1. The Single Outer Wrapper (`TTaurusTLSIOHandlerSocket`)
The outer component represents the actual connection instance. It remains a single class type to satisfy Indy's design-time serialization, streaming, and data-channel factory mechanics (`Clone`, `MakeClientIOHandler`).
*   **Data Flow Delegation:** Overrides `RecvEnc` and `SendEnc` to route raw network buffers directly through `TTaurusTLSSslSocket.Recv` and `Send`.
*   **Handshake Entry Points:** Overrides `ConnectClient` (for outbound client handshakes) and `AfterAccept` (for inbound accepted peer handshakes).
*   **Channel Cloning:** Overrides `Clone` to hand off the active `ITaurusTLSSslSocketCtx` interface reference directly to cloned data channels, guaranteeing $100\%$ configuration synchronization between FTP Control and Data channels with zero lock contention.

### 2.2. Disabled `SSL_MODE_AUTO_RETRY` & Precise Timeout Management
OpenSSL's `SSL_MODE_AUTO_RETRY` is explicitly disabled at the context level. 
*   When non-application data records (such as key updates or new session tickets) are processed, OpenSSL returns `SSL_ERROR_WANT_READ` or `SSL_ERROR_WANT_WRITE`.
*   The SSM uses dedicated `WaitForRead` and `WaitForWrite` methods driven by `TIdSocketList.Select` and `TStopWatch` budget counters. This gives TaurusTLS complete, millisecond-accurate timeout enforcement during both handshakes and data I/O, seamlessly supporting Indy's `TIdAntiFreeze`.

### 2.3. Decoupled Control and Data Planes
*   **Control Plane (UI / Main Thread):** Configures properties on the builder (`TTaurusTLSSslSocketCtxBuilder` / `TTaurusTLSSslClientSocketCtxBuilder`). Property setters acquire a fast critical section lock and set a `Dirty` flag.
*   **Data Plane (Connection Worker Thread):** When a connection begins, the builder compiles/freezes the context into an immutable `ITaurusTLSSslSocketCtx` snapshot. The socket engine reads properties directly from this frozen snapshot, executing completely lock-free during active handshakes and I/O.

---

## 3. Core Architectural Patterns

### 3.1. Non-Recursive, Loop-Driven State Transitions
To eliminate call-stack overflow risks and maintain strict state integrity:
*   `TransitionTo` is a **non-virtual public driver loop**. It calculates single forward steps using `GetNextStepTarget`, validates feasibility via `IsValidTransition`, executes the step via `DoTransitionTo`, and commits the state via `DoSetState`.
*   Sockets internal methods never call `TransitionTo` directly; they return the resulting target state enum (`seEstablished`, `seClosed`, `seError`), allowing the state machine loop to unwind naturally.

### 3.2. Dual-Track Direct Pointer Optimization
To eliminate interface virtual method table (VMT) lookup overhead:
*   `TTaurusTLSSslSocket` stores the interface reference `FContextIntf: ITaurusTLSSslSocketCtx` to manage memory lifetime via reference counting.
*   During construction, it resolves `FCtx := FContextIntf.Ctx` to a direct class pointer. Hot paths (`Send`, `Recv`, `SetupConnection`) read directly from `FCtx`, executing with zero interface dispatch overhead.

### 3.3. In-Place Hostname & IP Verification
During session initialization (`InitSSL`), the client socket retrieves the connection-specific parameter block via `SSL_get0_param(FSSL)` and applies `X509_VERIFY_PARAM_set1_host` or `_set1_ip_asc` in-place. This preserves all context-inherited settings (depth, trust stores, CRL flags) while binding the primary connection identity cleanly.

---

## 4. State Definitions & Lifecycle Rules

The state machine is governed by the `TTaurusTLSSslSocketState` enumeration:

| State | Description | Entry Action | Permitted Next States |
| :--- | :--- | :--- | :--- |
| **`seIdle`** | Initial state; no OpenSSL session exists. | Construction | `seInitializing`, `seClosed`, `seReleased`, `seError` |
| **`seInitializing`** | Session allocation and arming. | `InitSSL` (`SSL_new`, `SetupConnection`, callbacks) | `seInitialized`, `seClosed`, `seReleased`, `seError` |
| **`seInitialized`** | Session armed; ready for socket binding. | None (Ready for `BindSocket`) | `seHandshaking`, `seClosed`, `seReleased`, `seError` |
| **`seHandshaking`** | Active negotiation and key exchange. | `BindSocket` (`SSL_set_fd`) | `seEstablished`, `seClosed`, `seReleased`, `seError` |
| **`seEstablished`** | Handshake complete; active data exchange permitted. | `DoHandshake` (`SSL_connect` / `SSL_accept`) | `seClosed`, `seReleased`, `seError` |
| **`seClosed`** | Orderly TLS `close_notify` shutdown completed. | `DoShutdown` (`SSL_shutdown`) | `seReleased`, `seError` |
| **`seReleased`** | OpenSSL handles freed; socket unbound. | `ReleaseSSL` (`SSL_free`, unbind `app_data`) | Terminal state (No transitions out) |
| **`seError`** | Terminal fault state (decryption error, syscall reset). | `ReleaseSSL` | Terminal state (No transitions out) |

---

## 5. Stability & Security Pillars

### 5.1. The POSIX SIGPIPE Shield
On Linux and POSIX targets, writing to a broken TCP socket generates an unmasked `SIGPIPE` signal that terminates the host process immediately. TaurusTLS initializes `FSigSet` once at application startup in a class constructor and blocks `SIGPIPE` for every connection thread via `pthread_sigmask(SIG_BLOCK, @FSigSet, nil)` inside `InitSSL`.

### 5.2. Client ECH Strategy & SNI Mode Matrix
The client engine supports 6 distinct, mutually exclusive SNI and ECH wire policies via `TTaurusTLSSslClientSNIMode`:
*   `csmDisabled`: No SNI extension emitted on the wire (RFC 3546 / IP literals).
*   `csmStandardSNI`: Standard cleartext SNI (`HostName` or `DefaultSNI` override).
*   `csmECHGrease`: Anti-Ossification mode. Emits cleartext SNI + dummy ECH payload; ignores server `retry_configs` to avoid connection latency.
*   `csmECHGreaseDiscovery`: Bootstrapping mode. Probes with dummy ECH without emitting private cleartext SNI; catches `SSL_ECH_STATUS_GREASE_ECH`, extracts `retry_configs`, and signals `seClosed` for clean reconnection.
*   `csmECH`: Real ECH with outer decoy / `public_name`. Strict mode aborts on downgrade.
*   `csmECHNoOuter`: Real ECH with outer SNI extension omitted on wire (`no_outer = 1`).

### 5.3. Memory Hygiene & Leak Prevention
*   `SSL_ech_get1_status` allocates C-heap string pointers. `ProcessECHStatus` uses a strict `try..finally` guard to deallocate `lInner` and `lOuter` via `OPENSSL_free`.
*   When destroying the socket, `ReleaseSSL` sets `SSL_set_app_data(FSSL, nil)` prior to calling `SSL_free`, preventing callbacks from accessing freed Delphi memory during unmanaged teardown.

---

## 6. Event Lifecycle & Callback Bridges

All OpenSSL callbacks are routed through static `cdecl` functions on `TTaurusTLSSslSocket`. They retrieve the active Delphi socket instance using `SSL_get_app_data(ASSL)`.

1.  **State Tracing (`OnStatusInfo`):** `CbSslInfo` converts OpenSSL bitwise state integers into the `TTaurusTLSSslState` record.
2.  **Certificate Validation (`OnVerifyCertificate`):** `CbSslVerify` wraps `PX509_STORE_CTX` in `TTaurusTLSX509CertValidator` and dispatches validation events. Overriding errors clears the OpenSSL error state via `X509_STORE_CTX_set_error(ACtx, X509_V_OK)`.
3.  **Cryptographic Auditing (`OnSecurityCheck`):** `CbSslSecurityCheck` wraps parameters in `TTaurusTLSSecurityCheckState` and allows applications to permit or deny ciphers and key strengths.
4.  **Post-Handshake Error Audit (`OnPeerCertError`):** Fired after handshake completion if `SSL_get_verify_result` reports a verification failure, allowing dynamic application overrides before raising `ETaurusTLSSslSocketCertValidationError`.
5.  **Record Tracing (`OnMessage`):** `CbSslMessage` intercepts raw TLS protocol frames into `TTaurusTLSSslMessage`.
6.  **Secret Logging (`OnKeyLog`):** `CbCtxKeyLog` exports TLS 1.3 secrets for Wireshark decryption.