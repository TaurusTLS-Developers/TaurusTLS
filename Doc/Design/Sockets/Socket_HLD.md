# High-Level Design: TaurusTLS Socket and Socket State Machine (SSM)

## 1. Architecture Overview
The **TaurusTLS Socket State Machine (SSM)** is the core architectural layer governing the lifecycle of secure TLS connections. It serves as an intermediary between the Indy `TIdIOHandler` transport pipeline and the OpenSSL 3.x/4.0 engine.

~~~
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
|  - Overrides SetupConnection| |  - Overrides SetupConnection|
|  - Overrides                | |  - Overrides                |
|      DoHandshakeIteration   | |      DoHandshakeIteration   |
+-----------------------------+ +-----------------------------+
                               |
                               +------------> TTaurusTLSSslSocketState (Active State Enum)
~~~

---

## 2. Component Integration & Indy Pipeline Mapping

### 2.1. The Single Outer Wrapper (`TTaurusTLSIOHandlerSocket`)
The outer component represents the actual connection instance. It remains a single class type to satisfy Indy's design-time serialization, streaming, and data-channel factory mechanics (`Clone`, `MakeClientIOHandler`).
*   **Data Flow Delegation:** Overrides `RecvEnc` and `SendEnc` to route raw network buffers directly through `TTaurusTLSSslSocket.Recv` and `Send`.
*   **Handshake Entry Points:** Overrides `ConnectClient` (for outbound client handshakes) and `Accept` (for inbound accepted peer handshakes).
*   **Channel Cloning:** Overrides `Clone` to hand off the active `ITaurusTLSSslSocketCtx` interface reference directly to cloned data channels, guaranteeing 100% configuration synchronization between FTP Control and Data channels with zero lock contention.

### 2.2. Disabled `SSL_MODE_AUTO_RETRY` & Select Loop Ownership
OpenSSL's `SSL_MODE_AUTO_RETRY` is explicitly disabled at the context level (`SSL_CTX_clear_mode(SSLCtx, SSL_MODE_AUTO_RETRY)`).
*   **Single Select Loop Ownership:** There is no competing select loop with Indy. Indy's `TIdIOHandler` delegates encrypted buffer reads and writes entirely to `TTaurusTLSSslSocket.Recv` and `Send`. Indy does not poll the socket during encrypted payload retrieval.
*   **Timeout Budgeting & AntiFreeze:** When OpenSSL returns `SSL_ERROR_WANT_READ` or `SSL_ERROR_WANT_WRITE`, the SSM executes `WaitForRead` / `WaitForWrite` using `TIdSocketList.Select`. If `TIdAntiFreezeBase.ShouldUse` is `True`, `WaitForSocket` slices the timeout budget using `GAntiFreeze.IdleTimeOut` intervals, preventing main-thread UI freezing.

### 2.3. Control Plane / Data Plane & `SSL_CTX` Rebuild Policy
*   **Compilation-on-Demand (IsDirty):** The builder does not recompile `SSL_CTX` on every connection. The `Build` method checks `if (not IsDirty) and Assigned(FSocketCtx) then Exit(FSocketCtx)`. The `SSL_CTX` is compiled once and shared across multiple connections.
*   **Atomic Invalidation:** When a property setter is modified on the control plane, it acquires `FLock: TIdCriticalSection`, updates the field, and sets `FDirty := True`. The next connection triggers `Build`, compiling a fresh context snapshot.
*   **Zero-Downtime Memory Deallocation:** Active sockets hold an `ITaurusTLSSslSocketCtx` interface reference. Older connections continue using their referenced `SSL_CTX` without data races; when the last socket referencing an older context is destroyed, `SSL_CTX_free` is called automatically.

---

## 3. Core Architectural Patterns

### 3.1. The 1:1 Socket Instance Lifecycle Model (Option C 7-State Architecture)
`TTaurusTLSSslSocket` instances are strictly **1:1 with the physical connection lifecycle**:
*   Sockets are never recycled in-place across separate TCP connections.
*   **Terminal States:** `cTerminalStates = [seClosed, seError]`. No forward transitions are permitted out of terminal states.
*   **Reconnection & ECH Discovery:** When an orderly disconnect, error, or ECH retry occurs, the old socket transitions to `seClosed` or `seError` and is freed (`FreeAndNil(FSSLSocket)`). To reconnect, `TTaurusTLSIOHandlerSocket` establishes a new physical TCP connection and instantiates a brand-new `TTaurusTLSSslSocket` starting in `seIdle`.

### 3.2. Dual-Track Direct Pointer Optimization
To eliminate interface virtual method table (VMT) lookup overhead:
*   `TTaurusTLSSslSocket` stores the interface reference `FContextIntf: ITaurusTLSSslSocketCtx` to manage memory lifetime via reference counting.
*   During construction, it resolves `FCtx := FContextIntf.Ctx` to a direct class pointer. Hot paths (`Send`, `Recv`, `SetupConnection`) read directly from `FCtx`, executing with zero interface dispatch overhead.

### 3.3. In-Place Hostname & IP Verification
During session initialization (`InitSSL`), the client socket retrieves the connection-specific parameter block via `SSL_get0_param(FSSL)` and applies `X509_VERIFY_PARAM_set1_host` or `_set1_ip_asc` in-place. This preserves all context-inherited settings (depth, trust stores, CRL flags) while binding the primary connection identity cleanly.

---

## 4. State Definitions & Shutdown Mechanics

The state machine consists of 7 discrete states:

| State | Description | Entry Action | Permitted Next States |
| :--- | :--- | :--- | :--- |
| **`seIdle`** | Initial state; no OpenSSL objects allocated. | Construction | `seInitializing`, `seClosed`, `seError` |
| **`seInitializing`** | Session allocation and arming. | `InitSSL` (`SSL_new`, `SetupConnection`, callbacks) | `seInitialized`, `seClosed`, `seError` |
| **`seInitialized`** | Session armed; ready for socket binding. | None (Ready for `BindSocket`) | `seHandshaking`, `seClosed`, `seError` |
| **`seHandshaking`** | Active negotiation and key exchange. | `BindSocket` (`SSL_set_fd`) | `seEstablished`, `seClosed`, `seError` |
| **`seEstablished`** | Handshake complete; active encrypted I/O permitted. | `DoHandshake` (`SSL_connect` / `SSL_accept`) | `seClosed`, `seError` |
| **`seClosed`** | Orderly TLS `close_notify` and deallocation completed. | `DoShutdown` (`SSL_shutdown`) then `ReleaseSSL` | Terminal state |
| **`seError`** | Terminal fault state (decryption error, syscall reset). | `ReleaseSSL` | Terminal state |

*Note on `DoShutdown` (Best-Effort Teardown):* Inside `DoTransitionTo(seClosed)`, `DoShutdown` executes `SSL_shutdown` in a `try` block, and `ReleaseSSL` is guaranteed in the `finally` block. Any network reset (RST) or timeout during shutdown is swallowed, ensuring clean deallocation and committing `seClosed` without false-alarm error states.

---

## 5. Stability & Security Pillars

### 5.1. The POSIX SIGPIPE Shield
On Linux and POSIX targets, writing to a broken TCP socket generates an unmasked `SIGPIPE` signal. TaurusTLS initializes `FSigSet` once at application startup in `TTaurusTLSSslSocket.Create` (class constructor) and blocks `SIGPIPE` for every connection thread via `pthread_sigmask(SIG_BLOCK, @FSigSet, nil)` at the very beginning of `InitSSL`.

### 5.2. Client ECH Strategy & SNI Mode Mapping
The client engine supports 6 distinct SNI and ECH wire policies via `TTaurusTLSSslClientSNIMode`:
*   `csmDisabled`: No SNI extension emitted on the wire (RFC 3546 / IP literals).
*   `csmStandardSNI`: Standard cleartext SNI (`HostName` or `DefaultSNI` override).
*   `csmECHGrease`: Anti-Ossification mode. Emits cleartext SNI + dummy ECH payload; ignores server `retry_configs`.
*   `csmECHGreaseDiscovery`: Bootstrapping mode. Probes with dummy ECH without emitting private cleartext SNI; catches `SSL_ECH_STATUS_GREASE_ECH`, extracts `retry_configs`, and signals `seClosed` for clean reconnection.
*   `csmECH`: Real ECH with outer decoy / `public_name` (`SSL_ech_set1_server_names(s, inner, outer, 0)`). Strict mode aborts on downgrade.
*   `csmECHNoOuter`: Real ECH with outer SNI extension omitted on wire (`SSL_ech_set1_server_names(s, inner, nil, 1)`).

### 5.3. Memory Hygiene & Leak Prevention
*   `SSL_ech_get1_status` allocates C-heap string pointers. `ProcessECHStatus` uses a strict `try..finally` guard to deallocate `lInner` and `lOuter` via `OPENSSL_free`.
*   When destroying the socket, `ReleaseSSL` sets `SSL_set_app_data(FSSL, nil)` prior to calling `SSL_free`, preventing callbacks from accessing freed Delphi memory during unmanaged teardown.

---

## 6. Event Lifecycle & Callback Routing

### 6.1. Event Threading Model
All callback bridges and events (`OnStatusInfo`, `OnVerifyCertificate`, `OnPeerCertError`, `OnSecurityCheck`, `OnStateChange`, `OnMessage`, `OnKeyLog`) fire synchronously on the **background worker thread** executing the socket state machine (the Indy connection thread). Events are not automatically marshaled to the main UI thread.

### 6.2. Security Callback Bridge (`OnSecurityCheck`)
`TTaurusTLSSslSocket.CbSslSecurityCheck` directly wraps OpenSSL's `SSL_CTX_set_security_callback` / `SSL_set_security_callback` API (`SSL_SECOP_*` operations). The socket instance is resolved safely via `GetInstanceFromSSL(ASSL)`.

