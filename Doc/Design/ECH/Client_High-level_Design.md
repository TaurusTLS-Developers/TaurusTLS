# TaurusTLS Client-Side ECH High-Level Design (HLD)

## 1. Architecture Overview
Encrypted Client Hello (ECH) is a TLS 1.3 extension that encrypts the entire ClientHello message (including the Server Name Indication, or SNI) to prevent intermediate observers from determining the target server's identity. 

TaurusTLS integrates ECH support on the client side (`TTaurusTLSIOHandlerSocket`) by leveraging OpenSSL 4.0's `OSSL_ECH_STORE` and `SSL_set1_ech_config_list` APIs. The application layer is responsible for discovering the `ECHConfigList` (e.g., via DNS HTTPS records) and providing it to TaurusTLS. TaurusTLS manages the OpenSSL ECH configurations, injects them into the handshake, and reports the ECH status back to the application.

## 2. Component Modifications

### 2.1. `TTaurusTLSOptions` Additions
`TTaurusTLSOptions` will be extended with the following properties to configure ECH:

- **`ECHConfigs` (String)**: Accepts the Base64-encoded `ECHConfigList`. If this is populated, TaurusTLS will attempt to negotiate ECH.
- **`ECHOuterHostname` (String)**: Specifies the outer SNI used in the unencrypted ClientHello. The existing `HostName` property (on `TTaurusTLSSocket`) will be utilized for the true, encrypted inner SNI.
- **`ECHRetryCount` (Integer)**: A configuration option to determine how many times to retry `ech_required` errors.

### 2.2. `TTaurusTLSIOHandlerSocket` Additions
The IOHandler will surface the ECH status and expose events/properties:

- **`ECHStatus` Property**: Exposes the handshake outcome, utilizing a new enumeration `TTaurusTLSECHStatus` (e.g., `ech_success`, `ech_failed`, `ech_not_attempted`).
- **`OnECHRetry` Event (Optional)**: If the retry mechanism is configured to be handled by the application, an event or custom exception (e.g., `ETaurusTLSECHRetry`) will be used to pass back the updated `ECHConfigList` provided by the server.

## 3. Flow and Sequence

1. **Configuration**: The application retrieves the Base64 `ECHConfigList` and sets it in `TTaurusTLSIOHandlerSocket.SSLOptions.ECHConfigs`. It also sets the `HostName` (Inner SNI) and `ECHOuterHostname` (Outer SNI).
2. **Initialization (`StartSSL`)**: 
   - TaurusTLS decodes the Base64 string and loads it into OpenSSL using a memory BIO (`BIO_s_mem`) to avoid disk I/O.
   - The configuration is applied using `SSL_set1_ech_config_list`.
   - The Inner and Outer SNI are configured via `SSL_ech_set1_server_names`.
3. **Handshake**:
   - `ConnectClient` invokes OpenSSL's `SSL_connect`.
   - OpenSSL handles the construction of the encrypted ClientHello.
4. **Post-Handshake Verification**:
   - After a successful connection, TaurusTLS uses `SSL_ech_get1_status` to determine if ECH was accepted.
   - The `ECHStatus` property is updated accordingly.
5. **Retry Scenario (`ech_required`)**:
   - If the server rejects the ECHConfig but provides a new one, `SSL_connect` will fail with an ECH-specific error.
   - If `ECHRetryCount > 0`, TaurusTLS should use internal variable that initialized with the `ECHRetryCount` value and is decremented each time when an ECH retry is performed. If the internal variable is still greater than 0 after the retry, set `ECHConfig` using the new config from `SSL_ech_get1_retry_config`, and restart the handshake. If the internal variable is 0, it will raise `ETaurusTLSECHRetry` with the new config.

## 4. Risk Assessment & Mitigations

- **Memory Management:** ECH configurations are loaded via memory BIOs. Strict `try..finally` blocks must be employed to free the BIOs and any related `OSSL_ECH_STORE` objects to prevent leaks.
- **Header Bindings Compatibility:** Ensure that the signatures in `TaurusTLSHeaders_ech.pas` strictly match the OpenSSL 4.0 binary ABI, specifically verifying `SSL_ech_get1_status`.
- **Indy Synchronous Blocking:** Transparent retry handling under the hood requires restarting the connection sequence. This must cleanly restart the socket connection (since the TCP connection itself must be re-established) without confusing Indy's internal state machine.
