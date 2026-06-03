# High-Level Design: TaurusTLS Server-Side Multi-Tenancy, SNI Routing, and ECH Decryption

## 1. Architecture Overview
The **TaurusTLS Server-Side Multi-Tenancy Architecture** enables a single listening socket component (`TTaurusTLSServerIOHandler`) to dynamically host multiple independent "Virtual Servers" (tenants) in memory. 

Rather than merging all certificates, trust anchors, and ECH keys into a single global context, this architecture isolates each tenant into its own private, pre-compiled OpenSSL `SSL_CTX` container. Using OpenSSL's servername callback, TaurusTLS interceptively routes incoming handshakes to the correct tenant context based on the requested Server Name Indication (SNI)—even when that SNI is hidden inside an Encrypted Client Hello (ECH) payload.

```
       [Incoming Handshake ClientHello]
                      |
                      v
       +-------------------------------+
       |       FMasterCtx (Default)    | <-- Receives Handshake First
       +-------------------------------+
                      |
                      | Servername Callback (Outer SNI)
                      v
       +------------------------------------+
       |     TaurusTLS Callback Bridge      | <-- Reader Lock (FMapLock)
       | (arg = TTaurusTLSServerIOHandler)  |     Accesses FRuntimeServerMap
       +------------------------------------+
                      |
                      | ECH Decryption (if ECH keys match)
                      v
       [Inner SNI Decrypted Successfully]
                      |
                      | Servername Callback (Inner SNI)
                      v
       +------------------------------------+
       |     TaurusTLS Callback Bridge      | <-- Reader Lock (FMapLock)
       | (arg = TTaurusTLSServerIOHandler)  |     Accesses FRuntimeServerMap again
       +------------------------------------+
                      |
                      | Context Swapped via SSL_set_SSL_CTX
                      v
       +-------------------------------+
       |   Virtual Server SSL_CTX      | <-- Presents Target Certificate
       | (api.com / mTLS / ECH Private) |     & enforces specific mTLS rules
       +-------------------------------+
```

## 2. Component Integration & IDE Support

### 2.1. Design-Time Collections (`TCollection` & `TCollectionItem`)
To ensure complete compatibility with the Delphi/Lazarus IDE and Object Inspector, virtual servers are configured declaratively as a collection:
*   **`TTaurusTLSVirtualServerItem`**: Represents a single tenant, exposing properties like HostName, AssetStore (a unified TTaurusTLSOSSLStore to load standard certificate chains and private keys), ClientTrustStore (mTLS CA trust), and a dedicated ECHStore (TTaurusTLSECHStore). Because OpenSSL's OSSL_STORE does not natively support ECH configuration lists, the ECH public configs and private keys are loaded and managed independently using the dedicated ECHStore component wrapper.
*   **`TTaurusTLSVirtualServerCollection`**: A custom collection container owned by the server-side IOHandler.

### 2.2. High-Performance, Thread-Safe Runtime Lookup (`TDictionary` + Read-Write Lock)
At runtime, the design-time collection is compiled into a high-performance, read-only **`TDictionary<RawByteString, TTaurusTLSVirtualServerItem>`** [1.2, 1.9].
*   **Constant-Time Lookup ($O(1)$):** This replaces slow $O(N)$ linear collection scans with constant-time hash-table lookups, ensuring high performance under large multi-tenant configurations.
*   **Zero-Copy Byte Performance:** Because OpenSSL passes the negotiated SNI as a raw C-style `PAnsiChar` [1.9], we perform the hash lookup using `RawByteString`, completely bypassing the CPU overhead of converting C-strings to Delphi Unicode strings (`string`) during the critical servername callback execution path [1.9].
*   **Thread Safety (Read-Write Lock):** Since Indy runs each connection in its own thread, and the user can dynamically add or modify virtual servers on the main/UI thread, we protect the lookup map using a native, cross-platform **`TMultiReadExclusiveWriteSynchronizer`**. Background handshake threads acquire a shared read lock (enabling parallel lookups), while the UI/listener thread acquires an exclusive write lock when updating the server list [1.2].

### 2.3. The Servername Callback Bridge
The master context (`FMasterCtx`) registers a static servername callback (`SSL_CTX_set_tlsext_servername_callback`) [1.2.8], passing the parent `TTaurusTLSServerIOHandler` instance as the user-defined argument. During the handshake, OpenSSL invokes this callback to find the matching tenant context and swap the active session using `SSL_set_SSL_CTX` [1.9].

## 3. Core Architectural Patterns

### 3.1. Absolute Multi-Tenant Isolation
By swapping the entire `SSL_CTX` container on the fly, different virtual servers operating on the same physical port can enforce completely independent:
*   **Ciphersuites:** High-security APIs (`api.com`) can require TLS 1.3 only, while the public landing page (`www.com`) remains compatible with TLS 1.2.
*   **mTLS Rules:** Tenant A can require client certificate verification, while Tenant B remains public.
*   **Session Resumption Caches:** Session tickets are stored in isolated caches per context, preventing session-tracking attacks across different domains.

### 3.2. ECH SNI Rotation (Inner SNI Decryption)
When a client connects using ECH:
1.  OpenSSL triggers the servername callback with the unencrypted Outer SNI (the decoy).
2.  The callback can choose to let the handshake proceed on the default master context.
3.  OpenSSL decrypts the ECH payload using the ECH private keys loaded in the active context [1.1.2].
4.  If decryption succeeds, the active SNI becomes the decrypted **Inner SNI** [1.1.2].
5.  OpenSSL immediately triggers the servername callback **a second time** with this inner name [1.2.9].
6.  The callback performs a lookup, finds the matching virtual server, and swaps the connection context to the target tenant cleanly [1.2.9].

### 3.3. Independent Lifecycles & Reference Counting
*   **Leaf Certificates:** To decouple lifetimes, `TTaurusTLSVirtualServerItem` increments the reference count of the leaf certificate using `X509_up_ref` when caching `FLeafCert` [1.2.2]. It is cleanly freed via `X509_free` in the item's destructor.
*   **mTLS Trust Stores:** The server-peer configuration calls `X509_STORE_up_ref` right before attaching a custom validation store to `SSL_CTX_set_cert_store`, preventing double-free corruption [2.1].

## 4. State-Specific Exception Mapping
If compilation or asset loading fails for any virtual server during startup (`BuildConfig`), an exception is raised immediately to let the application handle it.

## 5. Stability & Security Pillars

### 5.1. The SIGPIPE / TCP RST Shield
To prevent OS-level process termination during TCP RST events, the SSM implements:
1.  **Global Signal Masking**: Ignoring `SIGPIPE` at the POSIX level (`signal(SIGPIPE, SIG_IGN)`).
2.  **State-Gated I/O**: No `SSL_write_ex` is attempted if the state is `seError` or `seClosed`.
3.  **Immediate RST Teardown**: Mapping `SSL_ERROR_SYSCALL` + `EPIPE/ECONNRESET` to an immediate `seClosed` transition. This instantly calls `SSL_free` (bypassing `SSL_shutdown`) and closes the physical socket.

### 5.2. Strict ECH Enforcement
The SSM follows a **"Success or Abort"** policy. If ECH is configured but the server falls back to a decoy "Outer" SNI (returning `SSL_ECH_STATUS_GREASE_ECH` or `SSL_ECH_STATUS_FAILED`), the SSM transitions to `seError` (or `seClosed` if a retry config is retrieved) and aborts the connection before any application data is sent.

### 5.3. TLS 1.3 Post-Handshake Asynchronicity
The SSM handles post-handshake events (NewSessionTickets, Post-Handshake Authentication) by treating `SSL_read_ex` as a potential state-changing operation. If `SSL_read_ex` returns `WANT_READ` or `WANT_WRITE` during active data exchange (e.g., for key updates or post-handshake message exchanges), the SSM transparently processes the protocol message and resumes waiting for application data via `Recv`.

## 6. Event Lifecycle & Callback Routing
The SSM acts as a callback bridge by mapping the `PSSL` handle back to the `TTaurusTLSBaseSocket` instance using `SSL_get_app_data`.

### 6.1. Lifecycle Transition Monitoring (`OnStateChange`)
Fired synchronously inside the Context's transition method after the validation matrix approves the transition.

### 6.2. Handshake Event Sequence
1.  **seHandshaking begins**: `OnStatusInfo` fires ("Handshake started").
2.  **Verify Peer**: `OnVerifyCallback` fires for each certificate in the chain.
3.  **Validation (Optional)**: `OnVerifyError` fires if validation fails.
4.  **Negotiation Complete**: `SSL_do_handshake` returns `1`.
5.  **Gatekeeper Check**: `OnSecurityLevel` fires. If the application rejects the negotiated protocol or cipher strength, the handshake is aborted.
6.  **Handshake Established**: `seEstablished` is reached; `OnSSLNegotiated` fires.