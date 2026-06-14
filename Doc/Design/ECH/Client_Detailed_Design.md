# Section 2: Detailed Design Document

## 1. Architectural Foundations

The TaurusTLS client-side socket context is built on three pillars designed to resolve the architectural friction between Indy’s design-time components and unmanaged, multi-threaded OpenSSL execution:

### 1.1. Thread-Safe Control/Data Plane Separation
In Indy, an `IOHandlerSocket` is typically created and configured on the main VCL/Lazarus thread at design-time, but executed inside a background worker thread at runtime. 
To prevent race conditions and Access Violations (AVs) if the application modifies configuration properties while a background handshake is active, TaurusTLS treats configurations as **immutable snapshots**. 

Before a connection begins, the high-level `IOHandler` freezes its current properties into an immutable configuration instance. The active background thread connects, handshakes, and executes I/O using only this frozen snapshot, completely isolated from any concurrent changes on the UI thread.

### 1.2. The Dual-Track Reference Pattern
To manage the lifecycle of these snapshots automatically without introducing runtime CPU overhead, TaurusTLS combines reference-counted Delphi interfaces with direct class pointers:
*   **The Lifetime Track (The Interface):** Sockets hold a reference to `IITaurusTLSSocketConfig` (`FConfigIntf`). This interface keeps the snapshot and its compiled `SSL_CTX` alive in memory for the exact duration of the socket's lifecycle. Once the socket is destroyed, releasing this reference automatically decrements the context reference count, deallocating memory cleanly.
*   **The Performance Track (The Class Pointer):** During construction, the socket resolves the interface to a direct, raw class pointer (`FConfig` / `FClientConfig`) using the generic `GetConfig<T>` helper method. During active network reading, writing, and setup connection, the state engine reads configuration parameters directly from this cached class pointer, **bypassing the virtual-method table (VMT) dispatch and reference-counting overhead of interface calls entirely.**

---

## 2. Component Specifications

The relationships and skeletal definitions of the core configuration types are defined below.

```
+-------------------------------------------------------------+
|                  IITaurusTLSSocketConfig                    |  <-- Unified Lifetime Interface (RAII)
+-------------------------------------------------------------+
                               ^
                               | Implemented by
+-------------------------------------------------------------+
|                  TTaurusTLSSocketConfig                     |  <-- Base Pure Runtime Config Class
+-------------------------------------------------------------+
                               ^
                               | Inherited by
+-------------------------------------------------------------+
|                TaurusTLSClientSocketConfig                  |  <-- Client-Specific Runtime Config Class
+-------------------------------------------------------------+
```

### 2.1. Snapshot Configuration Classes
These are **pure, runtime-only classes inheriting from `TInterfacedObject`** (omitting the `TPersistent` dependency entirely). They implement `IITaurusTLSSocketConfig` and manage context ref-counting safely.

~~~pascal
type
  TTaurusTLSSocketConfig = class; // Forward declaration

  /// <summary>The single, unified lifetime interface used across the entire library.</summary>
  IITaurusTLSSocketConfig = interface(IInterface)
    ['{DCD600F0-1D28-482D-A883-A563CFE0D6FC}']
    function GetConfig: TTaurusTLSSocketConfig;
    property Config: TTaurusTLSSocketConfig read GetConfig;
  end;

  /// <summary>
  ///   Base runtime-only configuration snapshot. Managed via reference-counting.
  /// </summary>
  TTaurusTLSSocketConfig = class(TInterfacedObject, IITaurusTLSSocketConfig)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSender: TObject;
    FSSLCtx: PSSL_CTX; // Managed via SSL_CTX_up_ref / SSL_CTX_free
    FVerifyDepth: TIdC_INT;
    FVerifyFlags: TTaurusTLSCertificateVerifyFlagSet;
    FVerifyHostname: Boolean;
    FVerifyHostnames: TStrings;
    
    // Event handlers
    FOnStateChange: TTaurusTLSOnStateChange;
    FOnDebug: TTaurusTLSOnDebugMessage;
    FOnSecurityLevel: TTaurusTLSOnSecurityLevel;
    FOnStatusInfo: TTaurusTLSOnSSLStatusInfo;
    FOnVerifyCertificate: TTaurusTLSOnVerifyCallback;
    FOnNegotiated: TNotifyEvent;
  protected
    procedure SetSSLCtx(ASSLCtx: PSSL_CTX);
    function GetConfig: TTaurusTLSSocketConfig; {$IFDEF USE_INLINE}inline;{$ENDIF}
  public
    constructor Create(ASender: TObject); virtual;
    destructor Destroy; override;

    property Config: TTaurusTLSSocketConfig read GetConfig;
    property SSLCtx: PSSL_CTX read FSSLCtx write SetSSLCtx;
    property VerifyHostname: Boolean read FVerifyHostname write FVerifyHostname;
    property VerifyHostnames: TStrings read FVerifyHostnames;
    
    property OnStateChange: TTaurusTLSOnStateChange read FOnStateChange write FOnStateChange;
    property OnDebug: TTaurusTLSOnDebugMessage read FOnDebug write FOnDebug;
    property OnSecurityLevel: TTaurusTLSOnSecurityLevel read FOnSecurityLevel write FOnSecurityLevel;
    property OnStatusInfo: TTaurusTLSOnSSLStatusInfo read FOnStatusInfo write FOnStatusInfo;
    property OnVerifyCertificate: TTaurusTLSOnVerifyCallback read FOnVerifyCertificate write FOnVerifyCertificate;
    property OnNegotiated: TNotifyEvent read FOnNegotiated write FOnNegotiated;
  end;

  /// <summary>
  ///   Client-specific runtime-only configuration snapshot.
  /// </summary>
  TaurusTLSClientSocketConfig = class(TTaurusTLSSocketConfig)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSessionToResume: PSSL_SESSION;
    FHostName: string;
    FDefaultSNI: string;
    FNormalizedHostName: RawByteString;   // Pre-compiled lower-case Punycode
    FNormalizedDefaultSNI: RawByteString; // Pre-compiled lower-case Punycode
    FNormalizedECHDecoy: RawByteString;   // Pre-compiled lower-case Punycode
    FECHFlags: TTaurusTLSECHCliFlags;
    FECHConfigList: string;
    FECHDecoy: string;
  protected
    procedure SetSessionToResume(const ASSL: PSSL); {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    destructor Destroy; override;

    property SessionToResume: PSSL_SESSION read FSessionToResume;
    property HostName: string read FHostName write FHostName;
    property DefaultSNI: string read FDefaultSNI write FDefaultSNI;
    property NormalizedHostName: RawByteString read FNormalizedHostName write FNormalizedHostName;
    property NormalizedDefaultSNI: RawByteString read FNormalizedDefaultSNI write FNormalizedDefaultSNI;
    property NormalizedECHDecoy: RawByteString read FNormalizedECHDecoy write FNormalizedECHDecoy;
    property ECHFlags: TTaurusTLSECHCliFlags read FECHFlags write FECHFlags;
    property ECHConfigList: string read FECHConfigList write FECHConfigList;
    property ECHDecoy: string read FECHDecoy write FECHDecoy;
  end;
~~~

### 2.2. The Configuration Snapshot Builder (`TTaurusTLSClientConfigBuilder`)
This class implements the **Builder Pattern**, managing the `IITaurusTLSSocketConfig` master instance. If any property setters modify configuration parameters, they raise a `Dirty` flag.

~~~pascal
type
  /// <summary>
  ///   Fluent builder class responsible for gathering properties, compiling the immutable 
  ///   SSL_CTX, and producing the reference-counted IITaurusTLSSocketConfig snapshot.
  /// </summary>
  TTaurusTLSClientConfigBuilder = class(TObject)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSender: TObject;
    FConfigIntf: IITaurusTLSSocketConfig; // The master config interface reference
    FDirty: Boolean;
    
    // Properties matching the client options
    FCipherList: string;
    FVerifyFlags: TTaurusTLSCertificateVerifyFlagSet;
    FVerifyDepth: TIdC_INT;
    FVerifyHostname: Boolean;
    FVerifyHostnames: TStrings;
    FECHConfigs: string;
    FECHDecoy: string;
    FECHFlags: TTaurusTLSECHCliFlags;
    FHostName: string;
    FDefaultSNI: string;
    FSessionToResume: PSSL_SESSION;
    
    function GetVerifyHostnames: TStrings;
    function GetNormalizedHost(const AValue: string): RawByteString;
  public
    constructor Create(ASender: TObject);
    destructor Destroy; override;

    // Fluent Configuration Setters
    function SetHostName(const AValue: string): TTaurusTLSClientConfigBuilder;
    function SetSNIDefaults(const ADefaultSNI, AECHDecoy: string): TTaurusTLSClientConfigBuilder;
    function SetECH(const AConfigs: string; AFlags: TTaurusTLSECHCliFlags): TTaurusTLSClientConfigBuilder;
    function SetVerify(AFlags: TTaurusTLSCertificateVerifyFlagSet; ADepth: TIdC_INT): TTaurusTLSClientConfigBuilder;
    function SetSessionToResume(ASession: PSSL_SESSION): TTaurusTLSClientConfigBuilder;

    /// <summary>
    ///   Assembles properties, decodes and loads ECH keys under a strict try..finally block, 
    ///   and returns the completed reference-counted configuration snapshot.
    ///   Handles context compilation lazy-swapping based on the Dirty flag.
    /// </summary>
    function Build: IITaurusTLSSocketConfig;

    property CipherList: string read FCipherList write FCipherList;
    property VerifyFlags: TTaurusTLSCertificateVerifyFlagSet read FVerifyFlags write FVerifyFlags;
    property VerifyDepth: TIdC_INT read FVerifyDepth write FVerifyDepth;
    property VerifyHostname: Boolean read FVerifyHostname write FVerifyHostname;
    property VerifyHostnames: TStrings read GetVerifyHostnames;
    property ECHConfigs: string read FECHConfigs write FECHConfigs;
    property ECHDecoy: string read FECHDecoy write FECHDecoy;
    property ECHFlags: TTaurusTLSECHCliFlags read FECHFlags write FECHFlags;
    property HostName: string read FHostName write FHostName;
    property DefaultSNI: string read FDefaultSNI write FDefaultSNI;
    property SessionToResume: PSSL_SESSION read FSessionToResume write FSessionToResume;
    property IsDirty: Boolean read FDirty;
  end;
~~~

---

## 3. Handshake & Connection Lifecycles

### 3.1. Handshake Loop Execution (`Handshake`)
The base class (`TTaurusTLSBaseSocket`) manages the synchronous, blocking loop driver. It is completely decoupled from the concrete cryptographic operations and executes on the background thread:

~~~pascal
procedure TTaurusTLSBaseSocket.Handshake;
begin
  TransitionTo(seHandshaking); // Arm state
  
  repeat
    DoHandshakeIteration; // Polymorphic, single-step execution
    
    if FState = seHandshaking then
    begin
      // Thread Yield: Relinquish CPU timeslice to prevent high CPU utilization
      // in non-blocking test modes or thread renegotiations.
      Sleep(1); 
    end;
  until FState <> seHandshaking; // Automatically terminates when state changes
end;
~~~

### 3.2. Context Initialization & Hostname Verification (`InitSSL` & `ConfigureHostnameVerification`)
Immediately upon entering the `seInitialized` state, the socket allocates `FSSL` and automatically configures its multi-name hostname and IP validation targets centrally. 

If a custom, logical SNI (`DefaultSNI`) is configured, we prioritize verifying the certificate against this expected logical identity rather than the physical transport endpoint:

~~~pascal
procedure TTaurusTLSBaseSocket.ConfigureHostnameVerification;
var
  LIdx: Integer;
  LName, LTargetName: RawByteString;
  LRet: TIdC_INT;
begin
  if not FConfig.VerifyHostname then
    Exit;

  SSL_set1_host(FSSL, nil); // Clear previous hostnames
  SSL_set_hostflags(FSSL, 0); // Apply standard wildcard flags

  // 1. Determine the expected logical identity.
  // We prioritize the enforced SNI (DefaultSNI) over the transport address (HostName).
  if FConfig.DefaultSNI <> '' then
    LTargetName := RawByteString(FConfig.DefaultSNI)
  else
    LTargetName := RawByteString(FConfig.HostName);

  if LTargetName = '' then
    Exit;

  // 2. Set the primary verification target (IP literals are natively detected and checked by OpenSSL 3.0+)
  LRet := SSL_set1_host(FSSL, PIdAnsiChar(LTargetName));
  if LRet <= 0 then
    ETaurusTLSSettingTLSHostNameError.RaiseException(FSSL, LRet, 
      'Failed to set verification host: ' + String(LTargetName));

  // 3. Add any alternative acceptable verification names (VerifyHostnames) safely
  if FConfig.VerifyHostnames.Count > 0 then
  begin
    for LIdx := 0 to FConfig.VerifyHostnames.Count - 1 do
    begin
      LName := RawByteString(FConfig.VerifyHostnames[LIdx]);
      if (LName = '') or (LName = LTargetName) then Continue;

      LRet := SSL_add1_host(FSSL, PIdAnsiChar(LName));
      if LRet <= 0 then
        ETaurusTLSSettingTLSHostNameError.RaiseException(FSSL, LRet, 
          'Failed to add alternative verification host: ' + FConfig.VerifyHostnames[LIdx]);
    end;
  end;
end;
~~~

### 3.3. Handshake Iteration & ECH Status Checks (`DoHandshakeIteration`)
The concrete client class `TTaurusTLSClientSocket` overrides `DoHandshakeIteration` to execute a single step of `SSL_connect`. On successful handshake completion (`lRet = 1`), it performs ECH verification, caches the session resumption ticket, and transitions to `seEstablished`.

Manual post-handshake `SSL_get_verify_result` checks are omitted here. Because the verification hostnames are configured natively on the `SSL` session via `SSL_set1_host`, OpenSSL’s internal validation engine automatically handles all trust path and wildcard checks, feeding any failures directly into `SSLVerifyCallback`.

~~~pascal
procedure TTaurusTLSClientSocket.DoHandshakeIteration;
var
  lRet, lErr: Integer;
  lStatus: TIdC_INT;
  lInner, lOuter: PIdAnsiChar;
  lECHConfigBuf: PByte;
  lECHConfigLen: NativeUInt;
  lNewConfigBase64: String;
  lConfig: TaurusTLSClientSocketConfig;
  lAccept: boolean;
begin
  lConfig := FClientConfig;
  try
    ERR_clear_error; // Clear stale errors before I/O
    lRet := SSL_connect(SSL);

    if lRet = 1 then
    begin
      // 1. Verify ECH status prior to accepting handshake success
      if lConfig.ECHEnabled and (lConfig.ECHConfigList <> '') then
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
                    OPENSSL_free(lECHConfigBuf); // Free unmanaged buffers
                  end;
                end;

                TransitionTo(seClosed);
                raise ETaurusTLSECHRejectedError.Create(lStatus, 'ECH Handshake failed. Server provided no new keys.');
              end;

            SSL_ECH_STATUS_NOT_TRIED,
            SSL_ECH_STATUS_NOT_CONFIGURED:
              begin
                TransitionTo(seError); // Bypassed/downgraded ECH is treated as a failure
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
          // Memory Safety: Free C-strings allocated by SSL_ech_get1_status immediately
          if Assigned(lInner) then OPENSSL_free(lInner);
          if Assigned(lOuter) then OPENSSL_free(lOuter);
        end;
      end;

      // 2. Perform security level check via snapshot event
      lAccept := True;
      lConfig.DoOnSecurityLevel(lAccept);
      if not lAccept then
      begin
        TransitionTo(seError);
        Exit;
      end;

      // Handshake Succeeded Cryptographically & Logically
      TransitionTo(seEstablished);

      // 3. Cache the negotiated session ticket back to the config for future resumption
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
          TransitionTo(seClosed); // Immediate local teardown on TCP RST
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
        TransitionTo(seError); // Abort cleanly to prevent "shutdown while in init" crashes
      raise;
    end;
  end;
end;
~~~

### 3.4. Server-Name / Verify Callback Bridges

Static or non-member `cdecl` functions handle the low-level OpenSSL callbacks thread-safely. Connection-specific callbacks extract the active `SSL *` handle and retrieve the thread-specific Delphi socket instance using the connection's `app_data`.

The `SSLVerifyCallback` implementation preserves the platform-specific socket last error (`GStack.WSGetLastError` / `WSSetLastError`) safely across the OpenSSL C-boundary. It clears the validation error in OpenSSL (`X509_STORE_CTX_set_error(ACtx, X509_V_OK)`) if the user chooses to override and accept a failure.

~~~pascal
class function TTaurusTLSBaseSocket.SSLVerifyCallback(APreVerify: LongBool;
  ACtx: PX509_STORE_CTX): TIdC_INT;
var
  lInstance: TTaurusTLSBaseSocket;
  lConfig: TTaurusTLSSocketConfig;
  lSSL: PSSL;
  lErr: Integer;
  lResult, lContinue: Boolean;
begin
  Result := TIdC_INT(APreVerify);

  if not Assigned(ACtx) then
    Exit(0);

  try
    lErr := GStack.WSGetLastError;
    try
      lSSL := X509_STORE_CTX_get_ex_data(ACtx, SSL_get_ex_data_X509_STORE_CTX_idx());
      if not Assigned(lSSL) then
        Exit(0);

      lResult := APreVerify;
      lContinue := True;
      
      lInstance := GetInstanceFromSSL<TTaurusTLSBaseSocket>(lSSL);
      if Assigned(lInstance) then
      begin
        lConfig := lInstance.Config;
        if Assigned(lConfig) then
        begin
          lConfig.DoOnVerifyCertificate(ACtx, lResult, lContinue);
          if lContinue then 
            Result := 1 
          else 
            Result := 0;
            
          if lResult then
            X509_STORE_CTX_set_error(ACtx, X509_V_OK); // Clear the error in OpenSSL
        end;
      end;
    finally
      GStack.WSSetLastError(lErr);
    end;
  except
    Result := 0; 
  end;
end;
~~~

---

## 4. Memory Safety & RAII Management

### 4.1. Unmanaged C-Heap Allocation Safety
The OpenSSL API `SSL_ech_get1_status` writes C-style allocated string pointers to the provided `PPIdAnsiChar` addresses. 
*   **The Risk:** These strings are allocated on the unmanaged C-heap via `OPENSSL_malloc`. If they are not freed, **every handshake attempt will leak native memory, degrading server or client stability over time.**
*   **The Mitigation:** TaurusTLS wraps this check in a strict `try..finally` block, extracting the data to safe Delphi `String` variables and immediately releasing the C-pointers using `OPENSSL_free`:
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
