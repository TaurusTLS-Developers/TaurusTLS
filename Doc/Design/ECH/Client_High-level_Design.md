# TaurusTLS Client-Side ECH High-Level Design (HLD)

## 1. Architecture Overview
Encrypted Client Hello (ECH) is a TLS 1.3 extension that encrypts the entire ClientHello message (including the Server Name Indication, or SNI) to prevent intermediate observers from determining the target server's identity. 

TaurusTLS integrates ECH support on the client side (`TTaurusTLSIOHandlerSocket`) by leveraging OpenSSL 4.0's `OSSL_ECH_STORE` and `SSL_set1_ech_config_list` APIs. The application layer is responsible for discovering the `ECHConfigList` (e.g., via DNS HTTPS records) and providing it to TaurusTLS. TaurusTLS manages the OpenSSL ECH configurations, injects them into the handshake, and reports the ECH status back to the application.

```
+-------------------------------------------------------------+
|                 TTaurusTLSIOHandlerSocket                   |  <-- Design-Time Component (UI Thread)
+-------------------------------------------------------------+
                               |
                               | ConnectClient / Setup
                               v
+-------------------------------------------------------------+
|                 TTaurusTLSSslContext (Ctx)                  |  <-- Immutable context wrapper
+-------------------------------------------------------------+  <-- RAII reference counted (SSL_CTX_up_ref)
                               |
                               | Frozen during Connection Initiation
                               v
+-------------------------------------------------------------+
|                IITaurusTLSClientSocketConfig                |  <-- Client Configuration Interface
+-------------------------------------------------------------+  <-- Snapshot of ECH and SNI settings
                               |
                               | Passed to Constructor
                               v
+-------------------------------------------------------------+
|                  TTaurusTLSClientSocket                     |  <-- State Machine Context Engine
|    - FConfigIntf: IITaurusTLSSocketConfig (Lifetime)        |  <-- Interface tracking prevents leaks
|    - FClientConfig: TaurusTLSClientSocketConfig (Direct)    |  <-- Direct pointer ensures O(1) performance
+-------------------------------------------------------------+
```

#### 2. Component Integration & Mapping

##### 2.1. The Unified Configuration Snapshot Builder (`TTaurusTLSClientConfigFactory`)
To achieve complete decoupling between the UI-bound components (the control plane) and the active background network threads (the data plane), we introduce a unified factory class: **`TTaurusTLSClientConfigFactory`**.
*   **Single Responsibility:** This factory is the sole component responsible for gathering design-time or test-time properties, constructing a new immutable `SSL_CTX` [1.2], parsing and loading the ECH configuration via a `try..finally` guarded `TTaurusTLSECHStore` [2.1], and wrapping the finalized snapshot in a reference-counted `IITaurusTLSClientSocketConfig` interface.
*   **Absolute Code Reuse:** Both the design-time `TTaurusTLSIOHandlerSocket` (during its connection setup) and the unit-test fixtures invoke **this exact same factory method**. This guarantees that the core OpenSSL context compilation, ECH parsing, and string-to-Punycode normalizations are identical in both production and testing [2.1, 2.2].

##### 2.2. `TTaurusTLSOptions` Additions
`TTaurusTLSOptions` is extended with the following properties to configure ECH:
*   **`ECHConfigs` (String):** Accepts the Base64-encoded `ECHConfigList`. If populated, TaurusTLS will attempt to negotiate ECH.
*   **`ECHOuterHostname` (String):** Specifies the unencrypted Outer SNI (decoy) used in the ClientHello. The `FDefaultSNI` field (if not empty) or the standard `HostName` is used as the encrypted Inner SNI.
*   **`ECHKind` (Enumeration):** Configuration modes (`ekNoECH`, `ekTryECH`, `ekForceECH`).

##### 2.3. `TTaurusTLSIOHandlerSocket` Additions
The high-level `TTaurusTLSIOHandlerSocket` wrapper component exposes these Client Socket capabilities directly to the developer:
*   **`ECHStatus` Property:** Exposes the handshake outcome, utilizing the enumeration `TTaurusECHClientStatus` (e.g., `echCliSuccess`, `echCliFailed`, `echCliNone`).
*   **Secure Callbacks:** Maps peer verification (`OnVerifyCertificate`) and security gatekeeping (`OnSecurityLevel`) events safely to the user's event handlers.

## 3. Flow and Sequence

### 3.1. Configuration, Context Preparation, and Freeze
All heavyweight cryptographic configuration, file parsing, and string normalizations are completed during this initial stage on the main execution thread before the socket context is instantiated. This compiled configuration can be shared safely across multiple socket sessions:
1. **Dynamic Ingestion & Context Compilation:** The unified snapshot factory (`TTaurusTLSClientConfigFactory`) compiles a new `SSL_CTX` and wraps it inside a reference-counted `TTaurusTLSSslContext` container. 
2. **Domain Normalization:** The builder normalizes the input IDN hostnames (`HostName`, `DefaultSNI`, and `ECHDecoy`) to lower-case ASCII Punycode (RFC 3492) and caches them in the snapshot properties. The `DefaultSNI` (if not empty) or the standard `HostName` is designated as the encrypted Inner SNI, while `ECHDecoy` is designated as the unencrypted Outer SNI.
3. **RAII ECH Key Loading:** If ECH is enabled and raw configurations are provided, the factory decodes the Base64 `ECHConfigs` string, loads it into a `TTaurusTLSECHStore` instance, and attaches it globally to the `SSL_CTX` using `Attach(ASSLCtx: PSSL_CTX)`. To prevent unmanaged OpenSSL memory leaks, this setup is wrapped strictly inside a `try..finally` block:
   ~~~pascal
   LEchStore := TTaurusTLSECHStore.Create;
   try
     LEchStore.SetConfigList(RawByteString(AECHConfigs));
     LEchStore.Attach(LCtx);
   finally
     LEchStore.Free;
   end;
   ~~~
4. **Snapshot Packing:** The factory creates the `TaurusTLSClientSocketConfig` snapshot, populates its parameters, and wraps it inside a `TTaurusTLSClientSslConfigIntf` container, returning it as a reference-counted `IITaurusTLSSocketConfig` interface.

### 3.2. Socket Initialization (`Connect`)
1. The background connection thread instantiates `TTaurusTLSClientSocket` by passing the `IITaurusTLSSocketConfig` interface (FConfigIntf) to its constructor, natively incrementing its reference count to pin the configuration in memory.
2. The socket context retrieves its common configuration reference using the **`FConfigIntf.Config`** property.
3. The socket then queries for the specialized client-specific configuration interface and resolves its `FClientConfig` class pointer using **`Supports(FConfigIntf, IITaurusTLSClientSocketConfig, LClientConfigIntf)`** to enable zero-overhead direct property lookups on hot paths:
   ~~~pascal
   if Supports(AConfigIntf, IITaurusTLSClientSocketConfig, LClientConfigIntf) then
     FClientConfig := LClientConfigIntf.ClientConfig;
   ~~~
4. The socket transitions to `seInitialized`. The transition engine executes `InitSSL`, which instantiates `FSSL` and automatically calls `ConfigureHostnameVerification` to bind the expected target hostnames and IP addresses to the session.
5. The physical socket descriptor is bound to `FSSL` via `LinkSocket` (`SSL_set_fd`).

### 3.3. Handshake Loop
Because ECH key stores, domain name normalizations, and PKI assets are pre-compiled and loaded into the `SSL_CTX`, the connection-specific setup on the `SSL` session is extremely lightweight:
1. The socket's `SetupConnection` routine binds the expected server names to the `SSL` handle (configuring the decrypted Inner SNI and unencrypted Outer SNI decoy on `FSSL` via `SSL_ech_set1_server_names` or `SSL_set_tlsext_host_name`).
2. The client socket transitions to `seHandshaking` and invokes `SSL_connect` to initiate the handshake.

### 3.4. Post-Handshake Validation & Session Saving
Immediately upon a successful connection return (`lRet = 1`):
1. **ECH Status Check:** If ECH is active, the client calls `SSL_ech_get1_status` to determine the handshake outcome. If ECH succeeds (`SSL_ECH_STATUS_SUCCESS` or `SSL_ECH_STATUS_BACKEND`), `FECHStatus` is set to `echCliSuccess`.
2. **Post-Handshake Path Verification:** If hostname verification is active, the client calls `SSL_get_verify_result`. If the verification returns anything other than `X509_V_OK`, the client retrieves the peer certificate and raises a clean, standard `ETaurusTLSCertValidationError` (or fires `OnVerifyCertificate` if an application override is registered), gracefully halting the handshake.
3. **Session Ticket Caching:** On success, the client calls `lConfig.SetSessionToResume(SSL)` to cache the negotiated session ticket back to the configuration snapshot, enabling fast session resumption on subsequent connections.

### 3.5. Strict ECH Enforcement
*   **ECH Key Rejection (Retry Path):** If the server rejects the ECH key but returns its valid keys in the unencrypted fallback handshake (`SSL_ECH_STATUS_GREASE_ECH`), the socket retrieves the server's new ECHConfigList, raises `ETaurusTLSECHRetryRequired`, and transitions to `seClosed` to safely teardown.
*   **ECH Downgrade Protection:** If ECH was forced (`ekForceECH`) but bypassed by the server (`SSL_ECH_STATUS_NOT_CONFIGURED`), the client detects the security downgrade, transitions to `seError`, and raises `ETaurusTLSECHDowngradeError`.

## 4. Risk Assessment & Mitigations

*   **Memory Management:** ECH configurations are loaded via memory BIOs. Strict `try..finally` blocks must be employed to free the BIOs and any related `OSSL_ECH_STORE` objects to prevent leaks.
*   **Header Bindings Compatibility:** Ensure that the signatures in `TaurusTLSHeaders_ech.pas` strictly match the OpenSSL 4.0 binary ABI, specifically verifying `SSL_ech_get1_status`.
*   **Indy Synchronous Blocking:** Transparent retry handling under the hood requires restarting the connection sequence. This must cleanly restart the socket connection (since the TCP connection itself must be re-established) without confusing Indy's internal state machine.

## 5. Testing & Verification Strategy (In-Memory Loopbacks)

To test the blocking sockets of TaurusTLS without relying on physical network resources, we implement an in-memory loopback test harness:
*   **Threaded Handshake Harness:** Since Indy’s socket operations are synchronously blocking, a single-threaded loopback cannot negotiate a handshake (as `SSL_connect` would block waiting for data that hasn't been pumped). We instantiate background threads running `TTaurusTLSClientSocket.Connect` and `TTaurusTLSPeerSocket.Connect`.
*   **The Bytes Pump:** The main test thread runs a non-blocking loop that pumps raw encrypted bytes back and forth between the client's and server's `TTaurusTLSMemBio` instances until both threads complete.
*   **Non-Blocking Retries in Test:** Because Memory BIOs cannot block, `SSL_connect` and `SSL_accept` will return `SSL_ERROR_WANT_READ` or `SSL_ERROR_WANT_WRITE` in the tests. We handle these cases in our `DoHandshakeIteration` loops by calling `IndySleep(1)` to yield the CPU, allowing the main test thread's bytes pump to run. This logic is safely bypassed on physical, blocking OS sockets.
