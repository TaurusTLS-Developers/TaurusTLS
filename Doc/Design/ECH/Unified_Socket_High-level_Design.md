# TaurusTLS HLD: Socket State Machine, Multi-Tenancy, and ECH

## 1. Architecture Overview
The **TaurusTLS Socket State Machine (SSM)** is a core architectural layer designed to manage the lifecycle of a secure connection. It acts as an intermediary between the Indy `TIdIOHandler` pipeline and the OpenSSL 3.x/4.0 engine. 

To achieve maximum simplicity, execution performance, and native support for complex protocols (such as active FTPS), TaurusTLS consolidates its engine classes into two unified, highly optimized abstractions:
*   **The Universal Socket (`TTaurusTLSSocket`):** A single, bidirectional socket class that can execute both client-side (`SSL_connect`) and server-side (`SSL_accept`) handshakes natively depending on Indy's `IsPeer` boolean flag. This completely eliminates the need for specialized client and server socket descendants.
*   **The Universal Context (`TTaurusTLSSocketCtx`):** A single, reference-counted configuration context snapshot that stores both client-specific (SNI, ECH) and server-specific (mTLS, ALPN) parameters. It manages the underlying, shared OpenSSL context (`PSSL_CTX`) cleanly.
*   **The Dual-Track Reference Pattern:** Sockets hold a reference to `IITaurusTLSSocketConfig` (the base interface) to track lifetime and prevent leaks. Internally, the socket resolves this interface to a direct class pointer (`FConfig: TTaurusTLSSocketCtx`) exactly once during creation, allowing hot I/O paths to execute with zero virtual-method dispatch or reference-counting overhead.

```
+-------------------------------------------------------------+
|                 TTaurusTLSIOHandlerSocket                   |  <-- Design-Time Component (UI Thread)
+-------------------------------------------------------------+
                               |
                               | ConnectClient / AfterAccept
                               v
+-------------------------------------------------------------+
|                   TTaurusTLSConfig                          |  <-- Optional Shared Config Component
+-------------------------------------------------------------+  <-- Caches pre-compiled context snapshots
                               |
                               | Frozen during Connection Initiation
                               v
+-------------------------------------------------------------+
|                  IITaurusTLSSocketConfig                    |  <-- Unified Lifetime Interface (RAII)
+-------------------------------------------------------------+
                               |
                               | Passed to Constructor
                               v
+-------------------------------------------------------------+
|                      TTaurusTLSSocket                       |  <-- Unified State Machine Context Engine
|    - FConfigIntf: IITaurusTLSSocketConfig (Lifetime)        |  <-- Interface tracking prevents leaks
|    - FConfig: TTaurusTLSSocketCtx (Direct)                  |  <-- Concrete config class instance
+-------------------------------------------------------------+
```

---

## 2. Component Integration & Mapping

### 2.1. Configuration Snapshot Storage & Sharing
To decouple user-facing configuration properties from active connection threads, TaurusTLS separates the **Control Plane** (the design-time `TIdSSLIOHandlerSocketBase` component operating on the main thread) from the **Data Plane** (the socket engine running on a background connection thread).

*   **Config Instance Storage:** All configuration properties (such as domain names, ECH modes, and verification flags) and event handlers (such as `OnStateChange` and `OnVerifyCertificate`) are stored exclusively in the **Config Instance** (the compiled `TTaurusTLSSocketCtx` snapshot class), and **never in the Socket instance**. This keeps the Socket class entirely lightweight, focused solely on the operational state-machine, and free from configuration state management.
*   **Single-IOHandler Ownership:** Each `TTaurusTLSIOHandlerSocket` (and its server-peer descendant) owns its own dedicated, private configuration builder. No shared, global configuration components are used at this stage, completely avoiding cross-component locking or thread-contention hazards.
*   **Immutable Sharing via Cloning (FTP Channel Sync):** During multi-channel operations (such as FTPS active `PORT` or passive `PASV` data channel cloning), the control channel's `IOHandler` simply copies/hands off its active, reference-counted `FConfigIntf` interface reference directly to the cloned data channel . Because the data channel receives the *exact same* frozen, reference-counted `ITaurusTLSSocketCtx` configuration interface as the control channel, it is $100\%$ insulated from any subsequent property changes made to the parent components during the transfer, ensuring perfect channel synchronization with **zero thread-locking or cross-component synchronization issues**.

### 2.2. `TTaurusTLSOptions` & `TTaurusTLSVerifyModes` Additions
We unify peer verification behaviors under a single, highly optimized set:
*   **`TTaurusTLSVerifyMode`:** Enumerates verification modes, including `sslvrfPeer` (validate peer), `sslvrfFailIfNoPeerCert` (require client cert), and `sslvrfHostname` (validate certificate hostnames/IPs).
*   **`VerifyHostname` Property:** Exposed as a standard boolean property on the configuration class. Internally, it is packed as a bitwise set membership check (`sslvrfHostname in VerifyMode`), ensuring $100\%$ memory efficiency.
*   **`ECHOuterSNIRaw` & `ECHNoOuterVal`:** Pre-normalized ASCII Punycode parameters. Setting the `emMethECHNoOuter` flag tells OpenSSL to completely omit the decoy SNI extension (`no_outer = 1`) from the unencrypted ClientHello. If the flag is not set, OpenSSL automatically extracts the `public_name` from the ECHConfigList when `ECHOuterSNIRaw` is empty.

---

## 3. Client-Side SNI and ECH Configuration Matrix

The following matrix maps every valid client-side host, SNI, and ECH configuration, illustrating the precise unmanaged OpenSSL calls executed under each scenario:

| Case | `HostName` (Target) | `DefaultSNI` (Override) | `ECHEnabled` | `ECHConfigList` | `ECHDecoy` (Outer) | `ECHNoOuter` | `VerifyHostname` | API Calls Executed | Result / Cryptographic Outcome |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | `secret.com` | `""` | `False` | `""` | `""` | `False` | `True` | 1. `SSL_set_tlsext_host_name(ssl, "secret.com")`<br>2. `X509_VERIFY_PARAM_set1_host(param, "secret.com")` | **Standard TLS Handshake:** SNI is `secret.com` (plaintext). Certificate is validated against `secret.com`. |
| **2** | `secret.com` | `custom.com` | `False` | `""` | `""` | `False` | `True` | 1. `SSL_set_tlsext_host_name(ssl, "custom.com")`<br>2. `X509_VERIFY_PARAM_set1_host(param, "custom.com")` | **SNI Override:** Sent SNI is `custom.com` (plaintext) for gateway routing. Certificate is verified against the logical, enforced identity `custom.com` (not the transport endpoint). |
| **3** | `192.168.1.1` | `""` | `False` | `""` | `""` | `False` | `True` | 1. *No SNI call* (IP literal)<br>2. `X509_VERIFY_PARAM_set1_ip_asc(param, "192.168.1.1")` | **IP Direct Connect:** No SNI is sent (forbidden by RFC 3546). OpenSSL 3.0+ auto-detects the IP literal and validates SAN IP list. |
| **4** | `192.168.1.1` | `fallback.com` | `False` | `""` | `""` | `False` | `True` | 1. `SSL_set_tlsext_host_name(ssl, "fallback.com")`<br>2. `X509_VERIFY_PARAM_set1_host(param, "fallback.com")` | **IP Connect with SNI:** Sends `fallback.com` as SNI. Certificate is verified against the logical, enforced identity `fallback.com` (not the transport IP). |
| **5** | `secret.com` | `""` | `True` | `""` | `""` | `False` | `True` | 1. `SSL_set_options(ssl, SSL_OP_ECH_GREASE)`<br>2. `SSL_set_tlsext_host_name(ssl, "secret.com")`<br>3. `X509_VERIFY_PARAM_set1_host(param, "secret.com")` | **ECH GREASE:** Dummy ECH extension (GREASE) is sent to protect privacy. Handshake completes on standard plaintext SNI `secret.com`. |
| **6** | `secret.com` | `""` | `True` | `[Valid]` | `""` | `False` | `True` | 1. `SSL_set1_ech_config_list(ssl, ECL, Len)`<br>2. `SSL_ech_set1_server_names(ssl, "secret.com", nil, 0)`<br>3. `X509_VERIFY_PARAM_set1_host(param, "secret.com")` | **Real ECH (Default Decoy):** Encrypted Inner SNI is `secret.com`. Plaintext Outer SNI is automatically extracted by OpenSSL from the `public_name` inside `ECHConfigList`. |
| **7** | `secret.com` | `""` | `True` | `[Valid]` | `decoy.com` | `False` | `True` | 1. `SSL_set1_ech_config_list(ssl, ECL, Len)`<br>2. `SSL_ech_set1_server_names(ssl, "secret.com", "decoy.com", 0)`<br>3. `X509_VERIFY_PARAM_set1_host(param, "secret.com")` | **Real ECH (Custom Decoy):** Encrypted Inner SNI is `secret.com`. Plaintext Outer SNI is explicitly overridden on the wire to `decoy.com`. |
| **8** | `secret.com` | `""` | `True` | `[Valid]` | `""` | `True` | `True` | 1. `SSL_set1_ech_config_list(ssl, ECL, Len)`<br>2. `SSL_ech_set1_server_names(ssl, "secret.com", nil, 1)`<br>3. `X509_VERIFY_PARAM_set1_host(param, "secret.com")` | **Real ECH (Omitted Outer):** Encrypted Inner SNI is `secret.com`. The outer unencrypted ClientHello contains **no SNI extension at all** (`no_outer = 1` triggered via `ECHNoOuter := True`). |
| **9** | `192.168.1.1` | `secret.com` | `True` | `[Valid]` | `""` | `False` | `True` | 1. `SSL_set1_ech_config_list(ssl, ECL, Len)`<br>2. `SSL_ech_set1_server_names(ssl, "secret.com", nil, 0)`<br>3. `X509_VERIFY_PARAM_set1_host(param, "secret.com")` | **IP ECH Gateway Routing:** Encrypted Inner SNI is `secret.com`. Plaintext Outer SNI is the ECH list `public_name`. Certificate is verified against the logical, enforced identity `secret.com`. |

---

## 4. The Configuration Builder & Multi-Tenant Routing

To manage the compilation of immutable OpenSSL contexts and handle runtime configuration updates without introducing deadlocks or data races, TaurusTLS employs two runtime mapping structures:

### 4.1. Configuration, Context Preparation, and Freeze
All heavyweight cryptographic configuration, context compilation, and string normalizations are completed inside the `TTaurusTLSClientConfigBuilder.Build` call prior to socket creation. The `SSL_CTX` must be fully prepared and ready before the socket is instantiated:
1.  **Dynamic Ingestion & Context Compilation:** The local builder compiles its own `SSL_CTX` and wraps it inside a reference-counted `TTaurusTLSSslContext` container. This `SSL_CTX` can be shared safely across any cloned sockets (such as FTP data connections).
2.  **Domain Normalization:** The builder normalizes the input IDN hostnames (`HostName`, `DefaultSNI`, and `ECHDecoy`) to lower-case ASCII Punycode (RFC 3492) and caches them in the snapshot properties.
3.  **RAII ECH Key Loading:** If ECH is enabled and raw configurations are provided, the builder decodes the Base64 `ECHConfigs` string, loads it into a `TTaurusTLSECHStore` instance, and attaches it to the `SSL_CTX` using `Attach(ASSLCtx: PSSL_CTX)`. To prevent unmanaged OpenSSL memory leaks, this setup is wrapped strictly inside a `try..finally` block.
4.  **Snapshot Packing:** The builder creates the unified `TTaurusTLSSocketCtx` snapshot, populates its parameters, and returns it directly as a reference-counted `IITaurusTLSSocketConfig` interface.

### 4.2. Hybrid ServerName/SAN Routing Engine
For server-side multi-tenancy, the design-time virtual server collection is compiled once at startup into a thread-safe **`TDictionary<RawByteString, ITaurusTLSSocketCtx>`**. When a client SNI (or decrypted inner SNI) is parsed during the handshake, OpenSSL executes the static callback bridge:
*   **Phase 1 ($O(1)$ Exact Match):** The callback performs an $O(1)$ hash lookup on the dictionary. If an exact match is found, it swaps the context immediately via `SSL_set_SSL_CTX`. This handles almost all standard traffic with zero Delphi-level string-encoding conversions.
*   **Phase 2 ($O(N)$ Wildcard Fallback):** If the exact match fails, the callback loops over the compiled virtual server contexts and evaluates them using OpenSSL's native, RFC-compliant **`X509_check_host`** on each cached leaf certificate pointer. This natively validates wildcard CNs and both wildcard/exact SANs (Subject Alternative Names) without custom string parsing in Delphi.

---

## 5. Handshake Flow and Sequence

### 5.1. Context Preparation, and Freeze
All heavyweight cryptographic configuration, context compilation, and string normalizations (IDN domains converted to lower-case Punycode) are completed inside the builder prior to socket creation.

### 5.2. Socket Initialization (`Connect`)
1.  The background connection thread instantiates `TTaurusTLSSocket` by passing the `IITaurusTLSSocketConfig` interface (`FConfigIntf`) to its constructor, natively incrementing its reference count to pin the configuration in memory.
2.  Inside the socket's constructor, the engine resolves and caches its high-performance, typed class pointer **exactly once** by reading the interface property directly:
    ~~~pascal
    FConfig := AConfigIntf.GetConfig;
    ~~~
    This completely eliminates the need for any generic `GetConfig<T>` helper method, runtime downcasting, or virtual interface dispatch on hot I/O paths.
3.  The socket transitions to `seInitialized`. The transition engine executes `InitSSL`, which instantiates `FSSL` and automatically calls `ConfigureHostnameVerification` to bind the expected target hostnames and IP addresses to the session.
4.  The physical socket descriptor is bound to `FSSL` via `LinkSocket` (`SSL_set_fd`).

### 5.3. Handshake Loop
Because the ECH key stores, domain name normalizations, and PKI assets are pre-compiled and loaded into the `SSL_CTX`, the connection-specific setup on the `SSL` session is extremely lightweight. The socket only needs to configure the ECH/SNI server names on `FSSL` via `SSL_ech_set1_server_names` before initiating the handshake.

### 5.4. Post-Handshake Validation & Session Saving
Immediately upon a successful connection return (`lRet = 1`):
1. **ECH Status Check:** If ECH is active, the client calls `SSL_ech_get1_status` to determine the handshake outcome. If ECH succeeds, `FECHStatus` is set to `echCliSuccess`.
2. **Session Ticket Caching:** On success, the client calls `lConfig.SetSessionToResume(SSL)` to cache the negotiated session ticket back to the configuration snapshot.
3. **Verification Error Auditing:** If verification was requested and `SSL_get_verify_result` returns an error, the engine fires the high-level `OnPeerCertError` event. If the event is unassigned or returns `AHandled = False`, it raises `ETaurusTLSCertValidationError`. This allows developers to easily bypass or audit certificate errors without writing complex, unmanaged verify callbacks.

### 5.5. Strict ECH Enforcement
*   **ECH Key Rejection (Retry Path):** If the server rejects the ECH key but returns its valid keys in the unencrypted fallback handshake (`SSL_ECH_STATUS_GREASE_ECH`), the socket retrieves the server's new ECHConfigList, raises `ETaurusTLSECHRetryRequired`, and transitions to `seClosed` to safely teardown.
*   **ECH Downgrade Protection:** If ECH was forced (`ekForceECH`) but bypassed by the server (`SSL_ECH_STATUS_NOT_CONFIGURED`), the client detects the security downgrade, transitions to `seError`, and raises `ETaurusTLSECHDowngradeError`.

## 6. Risk Assessment & Mitigations

*   **Memory Management:** ECH configuration is loaded via the `TTaurusTLSECHStore` wrapper. Its usage (Create $\rightarrow$ Load $\rightarrow$ Attach(SSL_CTX) $\rightarrow$ Free) **must** be strictly wrapped in a `try..finally` block to prevent unmanaged OpenSSL memory leaks during context initialization. All other transient memory BIOs used for certificate loading and extraction must similarly employ strict `try..finally` guards.
*   **Header Bindings Compatibility:** Ensure that the signatures in `TaurusTLSHeaders_ech.pas` strictly match the OpenSSL 4.0 binary ABI, specifically verifying `SSL_ech_get1_status`.
*   **Indy Synchronous Blocking:** Transparent retry handling under the hood requires restarting the connection sequence. This must cleanly restart the socket connection (since the TCP connection itself must be re-established) without confusing Indy's internal state machine.

## 7. Testing & Verification Strategy (In-Memory Loopbacks)

To test the blocking sockets of TaurusTLS without relying on physical network resources, we implement an in-memory loopback test harness:
*   **Threaded Handshake Harness:** Since Indy’s socket operations are synchronously blocking, a single-threaded loopback cannot negotiate a handshake (as `SSL_connect` would block waiting for data that hasn't been pumped). We instantiate background threads running `TTaurusTLSSocket.Connect` in both client and server roles.
*   **The Bytes Pump:** The main test thread runs a non-blocking loop that pumps raw encrypted bytes back and forth between the client's and server's `TTaurusTLSMemBio` instances until both threads complete.
*   **Non-Blocking Retries in Test:** Because Memory BIOs cannot block, `SSL_connect` and `SSL_accept` will return `SSL_ERROR_WANT_READ` or `SSL_ERROR_WANT_WRITE` in the tests. We handle these cases in our `DoHandshakeIteration` loops by calling `Sleep(1)` to yield the CPU, allowing the main test thread's bytes pump to run.
*   **Thread-Termination Safety:** The blocking `DoHandshake` loop checks `TThread.CurrentThread.Terminated` on every iteration to prevent background threads from hanging indefinitely when a test crashes and the runner tries to deallocate them.