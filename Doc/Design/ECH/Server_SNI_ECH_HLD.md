# High-Level Design: TaurusTLS Server-Side Multi-Tenancy, SNI Routing, and ECH Decryption

## 1. Architecture Overview
The **TaurusTLS "Socket State Machine" (SSM)** is a core architectural layer designed to manage the lifecycle of a secure connection. It acts as an intermediary between the Indy `TIdIOHandler` pipeline and the OpenSSL 3.x/4.0 engine. 

To maintain strict alignment with Indy's component and factory architectures, TaurusTLS utilizes a single outer component wrapper (`TTaurusTLSIOHandlerSocket`) that inherits from Indy's native `TIdSSLIOHandlerSocketBase`. Internally, this component encapsulates a polymorphic execution engine (`TTaurusTLSBaseSocket`) that isolates client-specific and server-specific connection logic depending on whether the connection is executing in a client or server-peer role.

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
|   TTaurusTLSClientSocket    | |    TTaurusTLSPeerSocket     |  <-- Polymorphic Sockets
|  - Overrides DoHandshake     | |  - Overrides DoHandshake     |  <-- Managed by TTaurusTLSBaseSocket
+-----------------------------+ +-----------------------------+
                               |
                               +------------+
                                            v
                                     TTaurusTLSSslState (Active State Enum)
```

## 2. Component Integration & Indy Pipeline Mapping

### 2.1. The Single Outer Wrapper (`TTaurusTLSIOHandlerSocket`)
The outer component represents the actual connection instance. It remains a single class type to satisfy Indy's design-time serialization, streaming, and data-channel factory mechanics (`Clone`, `MakeClientIOHandler`, `MakeFTPSvrPasv`, `MakeFTPSvrPort`).
*   It overrides `RecvEnc` and `SendEnc` to route the data flow directly through the internal state machine.
*   It overrides `ConnectClient` (for outbound client handshakes) and `AfterAccept` (for inbound accepted peer handshakes).

### 2.2. The Internal Polymorphic Engine (`TTaurusTLSBaseSocket` descendants)
At the start of a connection, `TTaurusTLSIOHandlerSocket` evaluates Indy's native `IsPeer` boolean flag to instantiate the correct polymorphic execution engine:
*   `IsPeer = False` $\rightarrow$ Instantiates `TTaurusTLSClientSocket`. Implements client-side ECH configs, SNI mappings, client session resumption, and overrides the protected `DoHandshake` method to invoke `SSL_connect`.
*   `IsPeer = True` $\rightarrow$ Instantiates `TTaurusTLSPeerSocket`. Overrides the protected `DoHandshake` method to invoke `SSL_accept`, and relies on the shared server-side context for automatic session cache lookup.

### 2.3. The I/O Pipeline Integration
When `PassThrough` is set to `False` (encryption is active), Indy’s read/write pipeline routes raw data through the following abstract hooks in our wrapper:
*   `function RecvEnc(var VBuffer: TIdBytes): Integer; override;` $\rightarrow$ Delegates to the active context's `Recv` operation, wrapping the OpenSSL `SSL_read_ex` API.
*   `function SendEnc(const ABuffer: TIdBytes; const AOffset, ALength: Integer): Integer; override;` $\rightarrow$ Delegates to the active context's `Send` operation, wrapping the OpenSSL `SSL_write_ex` API.

## 3. Server-Side Multi-Tenancy Architecture

The server-side multi-tenancy implementation allows a single listening socket component (`TTaurusTLSServerIOHandler`) to dynamically host multiple independent "Virtual Servers" (tenants) in memory. 

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
       |     TaurusTLS Callback Bridge      | <-- Accesses FRuntimeServerMap
       | (arg = TTaurusTLSServerIOHandler)  |     & design-time Collection
       +------------------------------------+
                      |
                      | ECH Decryption (if ECH keys match)
                      v
       [Inner SNI Decrypted Successfully]
                      |
                      | Servername Callback (Inner SNI)
                      v
       +------------------------------------+
       |     TaurusTLS Callback Bridge      | <-- Accesses FRuntimeServerMap
       | (arg = TTaurusTLSServerIOHandler)  |     & design-time Collection again
       +------------------------------------+
                      |
                      | Context Swapped via SSL_set_SSL_CTX
                      v
       +-------------------------------+
       |   Virtual Server SSL_CTX      | <-- Presents Target Certificate
       | (api.com / mTLS / ECH Private) |     & enforces specific mTLS rules
       +-------------------------------+
```

### 3.1. Design-Time Collections (`TCollection` & `TCollectionItem`)
To ensure complete compatibility with the Delphi/Lazarus IDE and Object Inspector, virtual servers are configured declaratively as a collection:
*   **`TTaurusTLSVirtualServerItem`**: Represents a single tenant, exposing properties like `HostName`, `AssetStore` (a unified `TTaurusTLSOSSLStore` to load certs/keys from files, streams, or HSMs) [2.1], `ClientTrustStore` (mTLS CA trust), and `ECHStore` (ECH private keys).
*   **`TTaurusTLSVirtualServerCollection`**: A custom collection container owned by the server-side IOHandler.

### 3.2. Hybrid ServerName and SAN Lookup Engine
The Servername Callback is executed on a dedicated "Hybrid" lookup engine designed to optimize handshake routing under both exact-match and wildcard/SAN-match scenarios [1.2.2, 1.9]:

```
                  [Incoming SNI parsed by OpenSSL]
                                 |
                                 v
                     +-----------------------+
                     |    Phase 1: O(1)      | <-- Fast-path exact hash match
                     |     Exact Lookup      |     on FRuntimeServerMap
                     +-----------------------+
                                 |
                        [Exact Match Fails]
                                 v
                     +-----------------------+
                     |    Phase 2: O(N)      | <-- Iterates design-time collection
                     |  Wildcard/SAN Fallback|     using native X509_check_host
                     +-----------------------+
                                 |
                     [No Matches Found at All]
                                 v
                     +-----------------------+
                     |  Phase 3: Policy      | <-- Checks StrictSNICheck boolean
                     |      Enforcement      |     (Alert Abort vs. No-Ack Fallback)
                     +-----------------------+
```

#### Phase 1: High-Performance Exact Match ($O(1)$ Fast-Path)
1.  **Normalization on Ingestion:** When the virtual server collection is compiled at server startup, each `TTaurusTLSVirtualServerItem` converts its `HostName` to lower-case ASCII Punycode (RFC 3492) and registers itself in a global **`FRuntimeServerMap`** (`TDictionary<RawByteString, TTaurusTLSVirtualServerItem>`) [1.2, 1.9].
2.  **Handshake Lookup:** During the handshake, OpenSSL retrieves the client's SNI and triggers the callback [1.9]. The callback lowercases the raw ASCII `PAnsiChar` and executes an $O(1)$ hash lookup [1.9].
3.  **Context Swap:** If an exact match is found, the connection's context is swapped to the target tenant immediately using `SSL_set_SSL_CTX` [1.9]. This covers almost all standard connection traffic with zero Delphi-level string-encoding conversions or heap allocations [1.9].

#### Phase 2: Wildcard and SAN Fallback ($O(N)$ Sequential Check)
If the exact dictionary lookup fails, the engine falls back to a sequential loop over the design-time collection (`VirtualServers`) to evaluate wildcard and Subject Alternative Name (SAN) structures [1.2, 1.9].
1.  **Native OpenSSL Validation:** Instead of executing slow or error-prone custom string-parsing algorithms in Pascal, TaurusTLS delegates the evaluation entirely to OpenSSL's native **`X509_check_host`** API [1.2.2].
2.  **Subject Alternative Name (SAN) Priority:** As mandated by modern TLS standards, `X509_check_host` automatically checks the certificate's **SAN list** first, fully resolving both exact and wildcard SAN DNS names [1.2.2].
3.  **Common Name (CN) Fallback:** If no SAN matches, the API automatically falls back to validating the **Common Name (CN)** of the certificate (including wildcard CNs) [1.2.2].
4.  **Cached Leaf Pointers:** To prevent expensive context queries during this $O(N)$ loop, each virtual server item caches its native leaf certificate pointer (`LeafCert: PX509`) during startup, keeping the check extremely lightweight and fast [1.2.2].

#### Phase 3: SNI Policy Enforcement (`StrictSNICheck`)
If both the exact and wildcard lookups fail, the engine evaluates the server-wide **`StrictSNICheck`** boolean to enforce the desired security policy [1.2.8]:
*   **`StrictSNICheck = False` (Standard Web Fallback):** The callback returns `SSL_TLSEXT_ERR_NOACK` [1.2.8]. OpenSSL ignores the unrecognized SNI and gracefully falls back to negotiating the handshake using the default master context's certificates [1.2.8].
*   **`StrictSNICheck = True` (Strict Enterprise Isolation):** The callback populates the error alert pointer (`ad^ := SSL_AD_UNRECOGNIZED_NAME`) and returns `SSL_TLSEXT_ERR_ALERT_FATAL` [1.2.8]. OpenSSL immediately aborts the handshake with an unrecognized name alert, preventing unauthorized hosts from completing connections [1.2.8].

### 3.3. The Servername Callback Bridge
The master context (`FMasterCtx`) registers a static servername callback (`SSL_CTX_set_tlsext_servername_callback`) [1.2.8], passing the parent `TTaurusTLSServerIOHandler` instance as the user-defined argument. During the handshake, OpenSSL invokes this callback to find the matching tenant context and swap the active session using `SSL_set_SSL_CTX` [1.9].

### 3.4. ECH SNI Rotation (Inner SNI Decryption)
When a client connects using ECH:
1.  OpenSSL triggers the servername callback with the unencrypted Outer SNI (the decoy).
2.  The callback can choose to let the handshake proceed on the default master context.
3.  OpenSSL decrypts the ECH payload using the ECH private keys loaded in the active context [1.1.2].
4.  If decryption succeeds, the active SNI becomes the decrypted **Inner SNI** [1.1.2].
5.  OpenSSL immediately triggers the servername callback **a second time** with this inner name [1.2.9].
6.  The callback performs a lookup, finds the matching virtual server, and swaps the connection context to the target tenant cleanly [1.2.9].

## 4. Stability & Security Pillars

### 4.1. The SIGPIPE / TCP RST Shield
To prevent OS-level process termination during TCP RST events, the SSM implements:
1.  **Global Signal Masking**: Ignoring `SIGPIPE` at the POSIX level (`signal(SIGPIPE, SIG_IGN)`).
2.  **State-Gated I/O**: No `SSL_write_ex` is attempted if the state is `seError` or `seClosed`.
3.  **Immediate RST Teardown**: Mapping `SSL_ERROR_SYSCALL` + `EPIPE/ECONNRESET` to an immediate `seClosed` transition. This instantly calls `SSL_free` (bypassing `SSL_shutdown`) and closes the physical socket.

### 4.2. Strict ECH Enforcement
The SSM follows a **"Success or Abort"** policy. If ECH is configured but the server falls back to a decoy "Outer" SNI (returning `SSL_ECH_STATUS_GREASE_ECH` or `SSL_ECH_STATUS_FAILED`), the SSM transitions to `seError` (or `seClosed` if a retry config is retrieved) and aborts the connection before any application data is sent.

### 4.3. TLS 1.3 Post-Handshake Asynchronicity
The SSM handles post-handshake events (NewSessionTickets, Post-Handshake Authentication) by treating `SSL_read_ex` as a potential state-changing operation. If `SSL_read_ex` returns `WANT_READ` or `WANT_WRITE` during active data exchange (e.g., for key updates or post-handshake message exchanges), the SSM transparently processes the protocol message and resumes waiting for application data via `Recv`.

## 5. Event Lifecycle & Callback Routing
The SSM acts as a callback bridge by mapping the `PSSL` handle back to the `TTaurusTLSBaseSocket` instance using `SSL_get_app_data`.

### 5.1. Lifecycle Transition Monitoring (`OnStateChange`)
Fired synchronously inside the Context's transition method after the validation matrix approves the transition.

### 5.2. Handshake Event Sequence
1.  **seHandshaking begins**: `OnStatusInfo` fires ("Handshake started").
2.  **Verify Peer**: `OnVerifyCallback` fires for each certificate in the chain.
3.  **Validation (Optional)**: `OnVerifyError` fires if validation fails.
4.  **Negotiation Complete**: `SSL_do_handshake` returns `1`.
5.  **Gatekeeper Check**: `OnSecurityLevel` fires. If the application rejects the negotiated protocol or cipher strength, the handshake is aborted.
6.  **Handshake Established**: `seEstablished` is reached; `OnSSLNegotiated` fires.