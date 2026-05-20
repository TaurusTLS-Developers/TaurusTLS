# Detailed Design Document: TaurusTLS Socket State Machine

## 1. Technical Infrastructure

### 1.1. State Enumeration
```pascal
type
  TTaurusSSLState = (stIdle, stInitialized, stHandshaking, stEstablished, stClosing, stClosed, stError);
```

### 1.2. Exception Hierarchy
*   `ETaurusTLSECHRetryRequired`: Server rejected ECH key; provides new config.
*   `ETaurusTLSECHError`: General ECH failure (Decoy detected).
*   `ETaurusTLSHandshakeError`: Protocol negotiation failure.
*   `ETaurusTLSSecurityError`: Connection rejected by `OnSecurityLevel`.

## 2. State Transition Logic

### 2.1. Handshake Engine (`stHandshaking`)
The SSM uses a tight loop around `SSL_do_handshake`. This handles the multi-step process of ECH decryption, SNI selection, and mTLS verification.

**Pseudocode:**
```pascal
repeat
  Ret := SSL_do_handshake(FSSL);
  if Ret = 1 then 
  begin
    // Handshake done; perform final gate check
    if FireSecurityLevelEvent then
      SetState(stEstablished)
    else
      SetState(stError);
  end else begin
    Err := SSL_get_error(FSSL, Ret);
    case Err of
      SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE: 
        PerformIndySelect(Err); // Wait for socket activity
      SSL_ERROR_SYSCALL: 
        SetState(HandleRSTEvent); // Transition to stClosed on EPIPE
      SSL_ERROR_SSL: 
        SetState(stError); // Protocol failure
    end;
  end;
until (State <> stHandshaking);
```

### 2.2. I/O Guarding (Read/Write)
The SSM wraps `SSL_read` and `SSL_write` with state-awareness.

*   **Write**: Only permitted in `stEstablished`. If a write triggers a TCP RST, the SSM catches the syscall error, moves to `stClosed`, and raises a clean disconnect exception.
*   **Read**: Handles TLS 1.3 Post-Handshake messages. If `SSL_read` returns `WANT_READ` while in `stEstablished`, the SSM loops internally to process the protocol message (e.g., a NewSessionTicket) and resumes waiting for application data.

## 3. Event Integration & Callbacks

### 3.1. Callback Bridge
The SSM uses `SSL_set_app_data` to link the `PSSL` handle to the Delphi `TTaurusTLSSocket` instance.
*   **`OnStatusInfo`**: Triggered via `SSL_set_info_callback` for every protocol state change.
*   **`OnDebugMessage`**: Triggered via `SSL_set_msg_callback` for raw packet inspection.
*   **`OnVerifyCallback`**: Triggered during `stHandshaking` for certificate chain validation.

### 3.2. Security Gate (`OnSecurityLevel`)
Fired exactly once when `SSL_do_handshake` returns 1. The SSM provides the negotiated protocol, cipher, and key strength to the application. If rejected, the SSM terminates the connection.

### 3.3. Asset Decryption (Excluded)
Note: `OnGetPassword` is **excluded** from the SSM. Password handling for PKI assets is performed at the `TTaurusTLSContext` level using `OSSL_STORE` and `UI_METHOD` before the SSM is initialized.

## 4. ECH & mTLS Logic

### 4.1. ECH Workflow
1.  **Initialization**: `ECHConfigList` is attached to the `SSL` object.
2.  **Handshake**: SSM monitors `SSL_ech_get1_status`.
3.  **Validation**: If status is `GREASE_ECH` (fallback) and a real config was intended, the SSM extracts the `retry_config` and raises `ETaurusTLSECHRetryRequired`.

### 4.2. mTLS Workflow
1.  **Request**: Server SSM triggers `SSL_VERIFY_PEER` during handshake.
2.  **Provision**: Client SSM triggers `SSL_CTX_set_client_cert_cb`. The SSM pauses, allows the application to provide a certificate, and resumes the handshake.
3.  **Post-Handshake**: In TLS 1.3, if a server requests a certificate after the handshake, the SSM's `Read` loop handles the `WANT_READ` state to perform the late exchange.

## 5. Shutdown & Cleanup
*   **Graceful**: SSM calls `SSL_shutdown`. It supports bi-directional shutdown by waiting for the peer's `CloseNotify`.
*   **Abrupt**: If a TCP RST is detected during shutdown, the SSM immediately moves to `stClosed` and suppresses transport errors to ensure a clean application exit.