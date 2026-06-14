# TaurusTLS Client-Side ECH & SNI High-Level Design (HLD)

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
|               TTaurusTLSClientConfigBuilder                 |  <-- Manages Immutable Config & Contexts
+-------------------------------------------------------------+  <-- Handles Dirty flag & Dynamic compiling
                               |
                               | Frozen during Connection Initiation
                               v
+-------------------------------------------------------------+
|                  IITaurusTLSSocketConfig                    |  <-- Unified Lifetime Interface
+-------------------------------------------------------------+
                               |
                               | Passed to Constructor
                               v
+-------------------------------------------------------------+
|                  TTaurusTLSClientSocket                     |  <-- State Machine Context Engine
|    - FConfigIntf: IITaurusTLSSocketConfig (Lifetime)        |  <-- Interface tracking prevents leaks
|    - FClientConfig: TaurusTLSClientSocketConfig (Direct)    |  <-- Resolved via GetConfig<T> once
+-------------------------------------------------------------+
```

---

## 2. Component Integration & Mapping

### 2.1. Configuration Snapshot Storage & Sharing
To decouple the user-facing properties from background execution, TaurusTLS separates the **Control Plane** (the design-time `TIdSSLIOHandlerSocketBase` component operating on the main thread) from the **Data Plane** (the socket engine running on a background connection thread).

*   **Config Instance Storage:** All configuration properties (such as domain names, ECH modes, and verification flags) and event handlers (the `OnXXXX` callbacks, such as `OnStateChange` and `OnVerifyCertificate`) are stored exclusively in the **Config Instance** (the compiled configuration snapshot class), and **never in the Socket instance**. This keeps the Socket class entirely lightweight, focused solely on the operational state-machine, and free from configuration state management.
*   **Immutable Sharing:** Because the configuration snapshot is reference-counted and immutable, a single compiled configuration instance can be safely shared concurrently across multiple active Socket instances (for example, during multi-threaded client requests or cloned FTP data channel connections). The snapshot naturally deallocates itself from memory only when all referencing sockets have been destroyed and its global reference count reaches zero.

### 2.2. `TTaurusTLSOptions` Additions
`TTaurusTLSOptions` is extended with the following properties to configure ECH:
*   **`ConfigList` (String):** Accepts the Base64-encoded `ECHConfigList`. If populated, TaurusTLS will attempt to negotiate ECH.
*   **`ECHDecoy` (String):** Specifies the unencrypted Outer SNI (decoy) used in the ClientHello. The `FDefaultSNI` field (if not empty) or the standard `HostName` is used as the encrypted Inner SNI.
*   **`ECHFlags` (Set):** Configures ECH flags, including `emMethECHNoOuter` to omit the decoy SNI entirely from the unencrypted ClientHello.

### 2.3. `TTaurusTLSIOHandlerSocket` Additions
The high-level `TTaurusTLSIOHandlerSocket` wrapper component exposes these Client Socket capabilities directly to the developer:
*   **`ECHStatus` Property:** Exposes the handshake outcome, utilizing the enumeration `TTaurusECHClientStatus` (e.g., `echCliSuccess`, `echCliFailed`, `echCliNone`).
*   **Secure Callbacks:** Maps peer verification (`OnVerifyCertificate`) events safely to the user's event handlers.

---

## 3. Client-Side SNI and ECH Configuration Matrix

The following matrix maps every valid client-side host, SNI, and ECH configuration, illustrating the precise unmanaged OpenSSL calls executed under each scenario:

| Case | `HostName` (Target) | `DefaultSNI` (Override) | `ECHEnabled` | `ECHConfigList` | `ECHDecoy` (Outer) | `ECHNoOuter` | `VerifyHostname` | API Calls Executed | Result / Cryptographic Outcome |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | `secret.com` | `""` | `False` | `""` | `""` | `False` | `True` | 1. `SSL_set_tlsext_host_name(ssl, "secret.com")`<br>2. `SSL_set1_host(ssl, "secret.com")` | **Standard TLS Handshake:** SNI is `secret.com` (plaintext). Certificate is validated against `secret.com`. |
| **2** | `secret.com` | `custom.com` | `False` | `""` | `""` | `False` | `True` | 1. `SSL_set_tlsext_host_name(ssl, "custom.com")`<br>2. `SSL_set1_host(ssl, "custom.com")` | **SNI Override:** Sent SNI is `custom.com` (plaintext) for gateway routing. Certificate is verified against the logical, enforced identity `custom.com` (not the transport endpoint). |
| **3** | `192.168.1.1` | `""` | `False` | `""` | `""` | `False` | `True` | 1. *No SNI call* (IP literal)<br>2. `SSL_set1_host(ssl, "192.168.1.1")` | **IP Direct Connect:** No SNI is sent (forbidden by RFC 3546). OpenSSL 3.0+ auto-detects the IP literal and validates SAN IP list. |
| **4** | `192.168.1.1` | `fallback.com` | `False` | `""` | `""` | `False` | `True` | 1. `SSL_set_tlsext_host_name(ssl, "fallback.com")`<br>2. `SSL_set1_host(ssl, "fallback.com")` | **IP Connect with SNI:** Sends `fallback.com` as SNI. Certificate is verified against the logical, enforced identity `fallback.com` (not the transport IP). |
| **5** | `secret.com` | `""` | `True` | `""` | `""` | `False` | `True` | 1. `SSL_set_options(ssl, SSL_OP_ECH_GREASE)`<br>2. `SSL_set_tlsext_host_name(ssl, "secret.com")`<br>3. `SSL_set1_host(ssl, "secret.com")` | **ECH GREASE:** Dummy ECH extension (GREASE) is sent to protect privacy. Handshake completes on standard plaintext SNI `secret.com`. |
| **6** | `secret.com` | `""` | `True` | `[Valid]` | `""` | `False` | `True` | 1. `SSL_set1_ech_config_list(ssl, ECL, Len)`<br>2. `SSL_ech_set1_server_names(ssl, "secret.com", nil, 0)`<br>3. `SSL_set1_host(ssl, "secret.com")` | **Real ECH (Default Decoy):** Encrypted Inner SNI is `secret.com`. Plaintext Outer SNI is automatically extracted by OpenSSL from the `public_name` inside `ECHConfigList`. |
| **7** | `secret.com` | `""` | `True` | `[Valid]` | `decoy.com` | `False` | `True` | 1. `SSL_set1_ech_config_list(ssl, ECL, Len)`<br>2. `SSL_ech_set1_server_names(ssl, "secret.com", "decoy.com", 0)`<br>3. `SSL_set1_host(ssl, "secret.com")` | **Real ECH (Custom Decoy):** Encrypted Inner SNI is `secret.com`. Plaintext Outer SNI is explicitly overridden on the wire to `decoy.com`. |
| **8** | `secret.com` | `""` | `True` | `[Valid]` | `""` | `True` | `True` | 1. `SSL_set1_ech_config_list(ssl, ECL, Len)`<br>2. `SSL_ech_set1_server_names(ssl, "secret.com", nil, 1)`<br>3. `SSL_set1_host(ssl, "secret.com")` | **Real ECH (Omitted Outer):** Encrypted Inner SNI is `secret.com`. The outer unencrypted ClientHello contains **no SNI extension at all** (`no_outer = 1` triggered via `ECHNoOuter := True`). |
| **9** | `192.168.1.1` | `secret.com` | `True` | `[Valid]` | `""` | `False` | `True` | 1. `SSL_set1_ech_config_list(ssl, ECL, Len)`<br>2. `SSL_ech_set1_server_names(ssl, "secret.com", nil, 0)`<br>3. `SSL_set1_host(ssl, "secret.com")` | **IP ECH Gateway Routing:** Encrypted Inner SNI is `secret.com`. Plaintext Outer SNI is the ECH list `public_name`. Certificate is verified against the logical, enforced identity `secret.com`. |

---

## 4. The Configuration Builder Workflow

To manage the compilation of immutable OpenSSL contexts and handle runtime configuration updates without disrupting active socket threads, the `TTaurusTLSIOHandlerSocket` delegates all configuration assembly to the **`TTaurusTLSClientConfigBuilder`** using the following state-controlled workflow:

1.  **Instantiation:** The `IOHandler` instantiates and owns the `TTaurusTLSClientConfigBuilder` instance. The `IOHandler` determines the appropriate builder class type to instantiate (for example, `TTaurusTLSIOHandlerSocket` creates a `TTaurusTLSClientConfigBuilder` designed to output `TTaurusTLSSocketConfig` instances).
2.  **Master Source:** The builder instance internally manages the master configuration interface instance (`IITaurusTLSSocketConfig`), which acts as the single master source of all configuration properties, active OpenSSL handles, and event handlers.
3.  **Property Modification and the Dirty Flag:** When the user or application code modifies properties on the high-level `IOHandler` component, the component's property setters pass these updates directly to the builder's properties using inline setter procedures. The builder compares the incoming value with the existing setting; if an actual change in the value is detected, the builder raises its internal `Dirty` flag.
4.  **Build Invocation:** When the `IOHandler` is ready to initiate a connection and create a socket, it requests the builder to build the configuration by calling the function `Build`. This function returns the active `IITaurusTLSSocketConfig` interface.
5.  **Builder State Checks:** The `Build` method executes a three-part validation check:
    *   **Case A (No Active Config):** If the internal configuration instance does not exist yet, the builder compiles a new `SSL_CTX` [via `SSL_CTX_new`], normalizes the hostnames to lower-case Punycode, decodes and attaches the ECH keys under a strict `try..finally` ECHStore block, populates the event pointers from the builder properties, instantiates the configuration class, and clears the `Dirty` flag.
    *   **Case B (Active Config & Not Dirty):** If the configuration instance already exists and the `Dirty` flag is *not* set, the `Build` method bypasses compilation entirely and immediately returns the existing configuration object as the interface instance.
    *   **Case C (Active Config & Dirty):** If the configuration instance exists but the `Dirty` flag *is* set, the builder compiles a brand-new configuration instance with the updated settings, replaces its internal reference property with the new instance, clears the `Dirty` flag, and returns the new interface. 
    
    *(Note: Thanks to reference counting, any background socket threads still performing handshakes on the old interface keep their respective older configuration instances alive in memory safely until they disconnect).*

---

## 5. Handshake Flow and Sequence

### 5.1. Configuration, Context Preparation, and Freeze
All heavyweight cryptographic configuration, context compilation, and string normalizations are completed inside the `TTaurusTLSClientConfigBuilder.Build` call prior to socket creation. The `SSL_CTX` must be fully prepared and ready before the socket is instantiated.

### 5.2. Socket Initialization (`Connect`)
1. The background connection thread instantiates `TTaurusTLSClientSocket` by passing the `IITaurusTLSSocketConfig` interface (FConfigIntf) to its constructor, natively incrementing its reference count to pin the configuration in memory.
2. The socket context retrieves its common configuration reference using the **`FConfigIntf.Config`** property.
3. Inside the client socket's constructor, the engine resolves and caches its high-performance, typed class pointer **exactly once** using the generic method:
   ~~~pascal
   FClientConfig := GetConfig<TaurusTLSClientSocketConfig>;
   ~~~
   This eliminates all interface casting and reference-counting overhead during active data-path operations.
4. The socket transitions to `seInitialized`. The transition engine executes `InitSSL`, which instantiates `FSSL` and automatically calls `ConfigureHostnameVerification` to bind the expected target hostnames and IP addresses to the session.
5. The physical socket descriptor is bound to `FSSL` via `LinkSocket` (`SSL_set_fd`).

### 5.3. Handshake Loop
Because the ECH key stores, domain name normalizations, and PKI assets are pre-compiled and loaded into the `SSL_CTX`, the connection-specific setup on the `SSL` session is extremely lightweight:
1. The socket's `SetupConnection` routine binds the expected server names to the `SSL` handle (configuring the decrypted Inner SNI and unencrypted Outer SNI decoy on `FSSL` via `SSL_ech_set1_server_names` or `SSL_set_tlsext_host_name`).
2. The client socket transitions to `seHandshaking` and invokes `SSL_connect` to initiate the handshake.

### 5.4. Post-Handshake Validation & Session Saving
Immediately upon a successful connection return (`lRet = 1`):
1. **ECH Status Check:** If ECH is active, the client calls `SSL_ech_get1_status` to determine the handshake outcome. If ECH succeeds (`SSL_ECH_STATUS_SUCCESS` or `SSL_ECH_STATUS_BACKEND`), `FECHStatus` is set to `echCliSuccess`.
2. **Session Ticket Caching:** On success, the client calls `lConfig.SetSessionToResume(SSL)` to cache the negotiated session ticket back to the configuration snapshot, enabling fast session resumption on subsequent connections.
3. *Note on Path Verification:* Manual post-handshake `SSL_get_verify_result` checks are omitted here. Because the verification hostnames are configured natively on the `SSL` session via `SSL_set1_host`, OpenSSL’s internal validation engine automatically handles all trust path and wildcard checks, feeding any failures directly into `SSLVerifyCallback`.

### 5.5. Strict ECH Enforcement
*   **ECH Key Rejection (Retry Path):** If the server rejects the ECH key but returns its valid keys in the unencrypted fallback handshake (`SSL_ECH_STATUS_GREASE_ECH`), the socket retrieves the server's new ECHConfigList, raises `ETaurusTLSECHRetryRequired`, and transitions to `seClosed` to safely teardown.
*   **ECH Downgrade Protection:** If ECH was forced (`ekForceECH`) but bypassed by the server (`SSL_ECH_STATUS_NOT_CONFIGURED`), the client detects the security downgrade, transitions to `seError`, and raises `ETaurusTLSECHDowngradeError`.

## 6. Risk Assessment & Mitigations

*   **Memory Management:** ECH configuration is loaded via the `TTaurusTLSECHStore` wrapper. Its usage (Create $\rightarrow$ Load $\rightarrow$ Attach(SSL_CTX) $\rightarrow$ Free) **must** be strictly wrapped in a `try..finally` block to prevent unmanaged OpenSSL memory leaks during context initialization. All other transient memory BIOs used for certificate loading and extraction must similarly employ strict `try..finally` guards.
*   **Header Bindings Compatibility:** Ensure that the signatures in `TaurusTLSHeaders_ech.pas` strictly match the OpenSSL 4.0 binary ABI, specifically verifying `SSL_ech_get1_status`.
*   **Indy Synchronous Blocking:** Transparent retry handling under the hood requires restarting the connection sequence. This must cleanly restart the socket connection (since the TCP connection itself must be re-established) without confusing Indy's internal state machine.

## 7. Testing & Verification Strategy (In-Memory Loopbacks)

To test the blocking sockets of TaurusTLS without relying on physical network resources, we implement an in-memory loopback test harness:
*   **Threaded Handshake Harness:** Since Indy’s socket operations are synchronously blocking, a single-threaded loopback cannot negotiate a handshake (as `SSL_connect` would block waiting for data that hasn't been pumped). We instantiate background threads running `TTaurusTLSClientSocket.Connect` and `TTaurusTLSPeerSocket.Connect`.
*   **The Bytes Pump:** The main test thread runs a non-blocking loop that pumps raw encrypted bytes back and forth between the client's and server's `TTaurusTLSMemBio` instances until both threads complete.
*   **Non-Blocking Retries in Test:** Because Memory BIOs cannot block, `SSL_connect` and `SSL_accept` will return `SSL_ERROR_WANT_READ` or `SSL_ERROR_WANT_WRITE` in the tests. We handle these cases in our `DoHandshakeIteration` loops by calling `IndySleep(1)` to yield the CPU, allowing the main test thread's bytes pump to run. This logic is safely bypassed on physical, blocking OS sockets.
