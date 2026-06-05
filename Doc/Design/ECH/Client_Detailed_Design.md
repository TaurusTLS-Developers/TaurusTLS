# Detailed Design Document: TaurusTLS Client-Side ECH & Socket Context

## 1. Architectural Foundations

The TaurusTLS client-side socket context is built on three pillars designed to resolve the architectural friction between Indy’s design-time components and unmanaged, multi-threaded OpenSSL execution:

### 1.1. Thread-Safe Control/Data Plane Separation
In Indy, an `IOHandlerSocket` is typically created and configured on the main VCL/Lazarus thread at design-time, but executed inside a background worker thread at runtime. 
To prevent race conditions and Access Violations (AVs) if the application modifies configuration properties while a background handshake is active, TaurusTLS treats configurations as **immutable snapshots**. 

Before a connection begins, the high-level `IOHandler` freezes its current properties into an immutable configuration instance. The active background thread connects, handshakes, and executes I/O using only this frozen snapshot, completely isolated from any concurrent changes on the UI thread.

### 1.2. The Dual-Track Reference Pattern
To manage the lifecycle of these snapshots automatically without introducing runtime CPU overhead, TaurusTLS combines reference-counted Delphi interfaces with direct class pointers:
*   **The Lifetime Track (The Interface):** Sockets hold a reference to `IITaurusTLSSocketConfig` (`FConfigIntf`). This interface keeps the snapshot and its compiled `SSL_CTX` alive in memory for the exact duration of the socket's lifecycle. Once the socket is destroyed, releasing this reference automatically decrements the context reference count, deallocating memory cleanly.
*   **The Performance Track (The Class Pointer):** During construction, the socket resolves the interface to a direct, raw class pointer (`FConfig` / `FClientConfig`) using a fast, non-virtual assignment. During active network reading and writing, the state engine reads configuration parameters directly from this class pointer, **bypassing the virtual-method table (VMT) dispatch and reference-counting overhead of interface calls entirely.**

### 1.3. Decoupled Interface Extensibility (`Supports`)
Rather than polluting the base configuration class with client-specific (e.g., ECH and SNI) and server-specific (e.g., virtual hosting) properties, TaurusTLS leverages Delphi's native interface querying:
*   Specialized contexts (like `TTaurusTLSClientSocket`) query the base configuration interface for specialized client-specific interfaces (such as `IITaurusTLSClientSocketConfig`).
*   Using `Supports(FConfigIntf, IITaurusTLSClientSocketConfig, LClientConfig)`, the client socket binds its private, highly optimized `FClientConfig` pointer at startup, achieving compile-time safety and total architectural decoupling.

---

## 2. Component Specifications

The relationships and skeletal definitions of the core configuration types are defined below.

```
       +-------------------------------+
       |    IITaurusTLSSocketConfig    | <--- Base Interface (RAII Lifetime)
       +-------------------------------+
                       ^
                       | Inherits
       +-------------------------------+
       | IITaurusTLSClientSocketConfig | <--- Client-Specific Interface
       +-------------------------------+
```

### 2.1. Snapshot Configuration Classes
These are **pure, runtime-only classes inheriting from `TObject`** (omitting the `TPersistent` dependency entirely). They represent the frozen state of the connection's parameters.

~~~pascal
type
  /// <summary>
  ///   Abstract base capturing shared parameters, such as ciphers and verification mode.
  /// </summary>
  TTaurusTLSCustomSocketConfig = class(TObject)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSender: TObject;
    FSSLCtx: PSSL_CTX; // Pinned in memory via SSL_CTX_up_ref
    FVerifyDepth: TIdC_INT;
    FVerifyFlags: TTaurusTLSCertificateVerifyFlagSet;
    FVerifyHostname: Boolean;
    FVerifyHostnames: TStrings;
    // Event handlers...
  public
    constructor Create(ASender: TObject); virtual;
    destructor Destroy; override;
    
    property SSLCtx: PSSL_CTX read FSSLCtx write FSSLCtx;
    property VerifyHostname: Boolean read FVerifyHostname write FVerifyHostname;
    property VerifyHostnames: TStrings read FVerifyHostnames;
    // ... [Other properties] ...
  end;

  /// <summary>
  ///   Client-specific snapshot extending the base with SNI, ECH, and session credentials.
  /// </summary>
  TaurusTLSClientSocketConfig = class(TTaurusTLSCustomSocketConfig)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSessionToResume: PSSL_SESSION;
    FHostName: string;
    FDefaultSNI: string;
    FECHEnabled: Boolean;
    FECHConfigList: string;
    FECHDecoy: string;
  public
    destructor Destroy; override;
    
    property SessionToResume: PSSL_SESSION read FSessionToResume;
    property HostName: string read FHostName write FHostName;
    property DefaultSNI: string read FDefaultSNI write FDefaultSNI;
    property ECHEnabled: Boolean read FECHEnabled write FECHEnabled;
    property ECHConfigList: string read FECHConfigList write FECHConfigList;
    property ECHDecoy: string read FECHDecoy write FECHDecoy;
  end;
~~~

### 2.2. The Configuration Snapshot Builder (`TTaurusTLSClientConfigBuilder`)
This class implements the **Builder Pattern**, allowing both the design-time `IOHandler` and mock-free unit tests to compile the OpenSSL context and freeze configurations using a unified, clean, and highly extensible interface.

~~~pascal
type
  /// <summary>
  ///   Compiles the SSL_CTX, normalizes hostnames, loads ECH keys, 
  ///   and outputs the read-only IITaurusTLSClientSocketConfig snapshot.
  /// </summary>
  TTaurusTLSClientConfigBuilder = class(TObject)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSender: TObject;
    FHostName: string;
    FECHConfigs: string;
    FECHDecoy: string;
    FECHKind: TTaurusTLSECHKind;
    // ... [Other private builder fields] ...
  public
    constructor Create(ASender: TObject);
    destructor Destroy; override;

    // Fluent or standard property-based setters
    function SetHostName(const AValue: string): TTaurusTLSClientConfigBuilder;
    function SetECH(const AConfigs: string; AKind: TTaurusTLSECHKind): TTaurusTLSClientConfigBuilder;
    // ...

    /// <summary>
    ///   Assembles the properties, decodes and loads ECH keys under a strict try..finally block, 
    ///   and returns the completed reference-counted configuration snapshot.
    /// </summary>
    function Build: IITaurusTLSClientSocketConfig;
  end;
~~~

---

## 3. Handshake & Connection Lifecycles

### 3.1. Handshake Loop Execution (`Handshake`)
The base class (`TTaurusTLSBaseSocket`) manages the synchronous, blocking loop driver [4.1]. It is completely decoupled from the concrete cryptographic operations and executes on the background thread:

~~~pascal
procedure TTaurusTLSBaseSocket.Handshake;
begin
  TransitionTo(seHandshaking); // Arm state [3.2]
  
  repeat
    DoHandshakeIteration; // Polymorphic, single-step execution [4.1]
    
    if FState = seHandshaking then
    begin
      // Thread Yield: Relinquish CPU timeslice to prevent high CPU utilization
      // in non-blocking test modes or thread renegotiations [2.2, 5].
      Sleep(1); 
    end;
  until FState <> seHandshaking; // Automatically terminates when state changes [4.1]
end;
~~~

### 3.2. Context Initialization & Hostname Verification (`InitSSL` & `ConfigureHostnameVerification`)
Immediately upon entering the `seInitialized` state, the socket allocates `FSSL` and automatically configures its multi-name hostname and IP validation targets centrally:

~~~pascal
procedure TTaurusTLSBaseSocket.ConfigureHostnameVerification;
var
  LIdx: Integer;
  LName: RawByteString;
  LRet: TIdC_INT;
begin
  if (not FConfig.VerifyHostname) or (FConfig.VerifyHostnames.Count = 0) then
    Exit;

  SSL_set1_host(FSSL, nil); // Clear previous hostnames
  SSL_set_hostflags(FSSL, 0); // Apply standard wildcard flags

  for LIdx := 0 to FConfig.VerifyHostnames.Count - 1 do
  begin
    LName := RawByteString(FConfig.VerifyHostnames[LIdx]);
    if LName = '' then Continue;

    if LIdx = 0 then
      // Sets primary verification target
      LRet := SSL_set1_host(FSSL, PIdAnsiChar(LName))
    else
      // Adds subsequent alternative acceptable DNS names or IP literals
      LRet := SSL_add1_host(FSSL, PIdAnsiChar(LName));

    if LRet <= 0 then
      ETaurusTLSSettingTLSHostNameError.RaiseException(FSSL, LRet, 
        'Failed to set verification host: ' + FConfig.VerifyHostnames[LIdx]);
  end;
end;
~~~

### 3.3. Handshake Iteration & ECH Status Checks (`DoHandshakeIteration`)
The concrete client class `TTaurusTLSClientSocket` overrides `DoHandshakeIteration` to execute a single step of `SSL_connect` [4.1]. On successful handshake completion (`lRet = 1`), it performs ECH verification, caches the session resumption ticket, and transitions to `seEstablished` [4.1]:

~~~pascal
procedure TTaurusTLSClientSocket.DoHandshakeIteration;
var
  lRet, lErr: Integer;
  lStatus: TIdC_INT;
  lInner, lOuter: PIdAnsiChar;
  lECHConfigBuf: PByte;
  lECHConfigLen: NativeUInt;
  lNewConfigBase64: String;
begin
  try
    ERR_clear_error; // Clear stale errors before I/O [4.2]
    lRet := SSL_connect(SSL);

    if lRet = 1 then
    begin
      // 1. Verify ECH status prior to accepting handshake success
      if FClientConfig.ECHEnabled and (FClientConfig.ECHConfigList <> '') then
      begin
        lInner := nil;
        lOuter := nil;
        lStatus := SSL_ech_get1_status(SSL, @lInner, @lOuter);
        try
          case lStatus of
            SSL_ECH_STATUS_SUCCESS,
            SSL_ECH_STATUS_BACKEND:
              ; // ECH accepted. Handshake proceeds normally.

            SSL_ECH_STATUS_GREASE:
              ; // Intended GREASE completed normally. Handshake proceeds.

            SSL_ECH_STATUS_GREASE_ECH,
            SSL_ECH_STATUS_FAILED_ECH,
            SSL_ECH_STATUS_FAILED_ECH_BAD_NAME:
              begin
                SetECHStatus(echCliFailed);
                lECHConfigBuf := nil;
                lECHConfigLen := 0;

                // Safely extract server's new ECH config keys
                if SSL_ech_get1_retry_config(SSL, @lECHConfigBuf, @lECHConfigLen) = 1 then
                begin
                  try
                    if (lECHConfigBuf <> nil) and (lECHConfigLen > 0) then
                    begin
                      lNewConfigBase64 := EncodeConfigList(lECHConfigBuf, lECHConfigLen);
                      TransitionTo(seClosed); // Close current session
                      raise ETaurusTLSECHRetryRequired.Create(
                        lStatus,
                        'ECH Key Rejected. Retry required with updated config.',
                        lNewConfigBase64
                      );
                    end;
                  finally
                    OPENSSL_free(lECHConfigBuf); // Free unmanaged buffers [4.1]
                  end;
                end;

                TransitionTo(seClosed);
                raise ETaurusTLSECHRejectedError.Create(lStatus, 'ECH Handshake failed. Server provided no new keys.');
              end;

            SSL_ECH_STATUS_NOT_TRIED,
            SSL_ECH_STATUS_NOT_CONFIGURED:
              begin
                TransitionTo(seError); // Bypassed/downgraded ECH is treated as a failure [4.1, 5.2]
                raise ETaurusTLSECHDowngradeError.Create(lStatus, 'ECH was bypassed. Possible downgrade attack.');
              end;

            SSL_ECH_STATUS_BAD_NAME:
              begin
                TransitionTo(seError);
                raise ETaurusTLSECHBadNameError.Create(lStatus, 'ECH succeeded but server certificate did not match.');
              end;
          else
            begin
              TransitionTo(seError);
              raise ETaurusTLSECHProtocolError.Create(lStatus, 'ECH Handshake failed due to an internal error.');
            end;
          end;
        finally
          // Memory Safety: Free C-strings allocated by SSL_ech_get1_status immediately [4.1]
          if Assigned(lInner) then OPENSSL_free(lInner);
          if Assigned(lOuter) then OPENSSL_free(lOuter);
        end;
      end;

      // 2. Handshake Succeeded Cryptographically & Logically
      TransitionTo(seEstablished);

      // 3. Cache the negotiated session ticket back to the config for future resumption [6]
      FClientConfig.SetSessionToResume(SSL);
      
      // Update ECH status for reporting
      if FClientConfig.ECHEnabled then
      begin
        lStatus := SSL_ech_get1_status(SSL, nil, nil);
        if (lStatus = SSL_ECH_STATUS_SUCCESS) or (lStatus = SSL_ECH_STATUS_BACKEND) then
          SetECHStatus(echCliSuccess)
        else
          SetECHStatus(echCliNone);
      end;

      FClientConfig.DoOnSSLNegotiated;
      Exit;
    end;

    // Handle Handshake Retry / Error States
    lErr := SSL_get_error(SSL, lRet);
    case lErr of
      SSL_ERROR_SYSCALL:
        begin
          TransitionTo(seClosed); // Immediate local teardown on TCP RST [5.1]
          raise ETaurusTLSConnectionReset.Create('Handshake reset by peer.');
        end;

      SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE:
        begin
          // Yield the background thread to allow the I/O pipeline to process
          Exit; 
        end;
    else
      begin
        TransitionTo(seError);
        raise ETaurusTLSHandshakeError.Create('Fatal handshake error.');
      end;
    end;
  except
    on E: Exception do
    begin
      if (State = seHandshaking) then
        TransitionTo(seError); // Abort cleanly to prevent "shutdown while in init" crashes [4.1]
      raise;
    end;
  end;
end;
~~~

---

## 4. Memory Safety & RAII Management

### 4.1. Unmanaged C-Heap Allocation Safety
The OpenSSL API `SSL_ech_get1_status` writes C-style allocated string pointers to the provided `PPIdAnsiChar` addresses. 
*   **The Risk:** These strings are allocated on the unmanaged C-heap via `OPENSSL_malloc` [1.1.1, 1.1.3]. If they are not freed, **every handshake attempt will leak native memory, degrading server or client stability over time.**
*   **The Mitigation:** TaurusTLS wraps this check in a strict `try..finally` block, extracting the data to safe Delphi `String` variables and immediately releasing the C-pointers using `OPENSSL_free` [1.1.1, 1.1.3]:
    ~~~pascal
    lInner := nil;
    lOuter := nil;
    lStatus := SSL_ech_get1_status(SSL, @lInner, @lOuter);
    try
      if Assigned(lInner) then FInnerSNI := String(lInner);
      if Assigned(lOuter) then FOuterSNI := String(lOuter);
    finally
      if Assigned(lInner) then OPENSSL_free(lInner);
      if Assigned(lOuter) then OPENSSL_free(lOuter);
    end;
    ~~~

### 4.2. Safe Callback De-registration
When `ReleaseSSL` is invoked during socket destruction, the destructor must unbind `app_data` from the `PSSL` handle **prior** to calling `SSL_free`. If callbacks fire during OpenSSL's internal deallocation sequence, they will find `SSL_get_app_data` returns `nil` and exit safely without attempting to access a freed Delphi object instance.
