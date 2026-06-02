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
       +-------------------------------+
       |       TaurusTLS Callback      | <-- Searches FVirtualServerMap Dictionary
       |             Bridge            |
       +-------------------------------+
                      |
                      | ECH Decryption (if ECH keys match)
                      v
       [Inner SNI Decrypted Successfully]
                      |
                      | Servername Callback (Inner SNI)
                      v
       +-------------------------------+
       |       TaurusTLS Callback      | <-- Searches FVirtualServerMap AGAIN
       |             Bridge            |
       +-------------------------------+
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
*   **`TTaurusTLSVirtualServerItem`**: Represents a single tenant, exposing properties like `HostName`, `OSSLStoreURI` (certificate/key store), `ClientTrustStoreURI` (mTLS CA trust), and `ECHConfigList` / `ECHPrivateKeyURI` (ECH private keys).
*   **`TTaurusTLSVirtualServerCollection`**: A custom collection container owned by the server-side IOHandler.

### 2.2. High-Performance Runtime Lookup (`TDictionary`)
At runtime (when the server starts listening), the design-time collection is "compiled" into a thread-safe **`TDictionary<RawByteString, PSSL_CTX>`**. 
*   **Constant-Time Lookup ($O(1)$):** This replaces slow $O(N)$ linear collection scans with constant-time hash-table lookups, ensuring high performance under large multi-tenant configurations.
*   **Zero-Copy Byte Performance:** Because OpenSSL passes the negotiated SNI as a raw C-style `PAnsiChar`, we perform the hash lookup using `RawByteString`, completely bypassing the CPU overhead of converting C-strings to Delphi Unicode strings (`string`) during the critical servername callback execution path.

### 2.3. The Servername Callback Bridge
The master context (`FMasterCtx`) registers a static servername callback (`SSL_CTX_set_tlsext_servername_callback`), passing the compiled `TDictionary` as the user-defined argument. During the handshake, OpenSSL invokes this callback to find the matching tenant context and swap the active session using `SSL_set_SSL_CTX`.

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
3.  OpenSSL decrypts the ECH payload using the ECH private keys loaded in the active context.
4.  If decryption succeeds, the active SNI becomes the decrypted **Inner SNI**.
5.  OpenSSL immediately triggers the servername callback **a second time** with this inner name.
6.  The callback performs a lookup, finds the matching virtual server, and swaps the connection context to the target tenant cleanly.

### 3.3. Polymorphic `SSLCtx` Management
To prevent memory corruption, the base configuration class (`TTaurusTLSCustomSocketConfig`) manages the `SSLCtx` property polymorphically as a read-only getter. The client configuration class retains private, reference-counted ownership of its `SSL_CTX`, while the server-peer configuration references the compiled virtual server contexts passively, preventing double-free or use-after-free bugs when peer connections terminate.

### 3.4. Native Memory Safety (Leak Prevention)
The OpenSSL API `SSL_ech_get1_status` allocates memory on the C-heap for both the `inner_sni` and `outer_sni` strings. The server-peer handshake loop implements a strict `try..finally` pattern to deallocate these pointers using `OPENSSL_free` immediately after copy, ensuring zero memory leaks per connection.