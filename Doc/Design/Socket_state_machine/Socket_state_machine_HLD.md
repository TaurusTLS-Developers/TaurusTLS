# High-Level Design: TaurusTLS Socket State Machine

## 1. Purpose and Scope
The **TaurusTLS Socket State Machine (SSM)** is the core engine responsible for managing the lifecycle of a secure connection. It abstracts the complexities of OpenSSL 4.0, providing a stable, synchronous interface to Indy IOHandlers while internally handling the asynchronous nature of modern protocols (TLS 1.3).

### Key Objectives:
*   **Stability**: Prevent process crashes (SIGPIPE) during TCP RST events.
*   **Privacy**: Enforce strict ECH (Encrypted Client Hello) logic to prevent SNI leakage.
*   **Modernity**: Support TLS 1.3 post-handshake events and Mutual TLS (mTLS).
*   **Clean Separation**: Isolate cryptographic asset loading (Context) from protocol execution (Socket).

## 2. Architecture Overview
The SSM sits between the **Indy IOHandler** and the **OpenSSL 4.0 Engine**. 
*   **Indy Layer**: Calls blocking methods like `Read` and `Write`.
*   **SSM Layer**: Manages the `PSSL` handle, state transitions, and I/O guarding.
*   **OpenSSL Layer**: Performs encryption, decryption, and protocol negotiation.

## 3. State Definitions
1.  **stIdle**: Initial state; no SSL objects exist.
2.  **stInitialized**: `SSL` object is created and "armed" with assets from the Context.
3.  **stHandshaking**: Active negotiation (ECH, SNI, mTLS).
4.  **stEstablished**: Handshake successful; `OnSSLNegotiated` fired; data exchange permitted.
5.  **stClosing**: `SSL_shutdown` initiated.
6.  **stClosed**: Connection terminated; safe to free resources.
7.  **stError**: Fatal failure (Protocol error or Transport Reset).

## 4. Stability & Security Pillars

### 4.1. The SIGPIPE/RST Shield
To handle the "TLS 1.3 RST Trap" (where OpenSSL attempts to write Session Tickets to a closed socket), the SSM implements:
*   **Global Masking**: Ignore `SIGPIPE` at the OS level.
*   **RST Mapping**: Map `SSL_ERROR_SYSCALL` + `ECONNRESET/EPIPE` directly to `stClosed`, bypassing standard shutdown to avoid further write attempts.

### 4.2. Strict ECH Enforcement
The SSM follows a **"Success or Abort"** policy. If ECH is configured but the server falls back to a decoy "Outer" SNI, the SSM transitions to `stError` and aborts the connection before any application data is sent.
