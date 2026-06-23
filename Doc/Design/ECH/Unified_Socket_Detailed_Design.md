# Detailed Design Document: TaurusTLS Client-Side ECH & Socket Context

## 1. Architectural Foundations

The TaurusTLS unified socket context architecture is built on three pillars designed to resolve the operational friction between Indy’s design-time components and unmanaged, multi-threaded OpenSSL execution:

### 1.1. Thread-Safe Control/Data Plane Separation
In Indy, an `IOHandlerSocket` is typically created and configured on the main VCL/Lazarus thread at design-time, but executed inside a background worker thread at runtime. 
To prevent race conditions and Access Violations (AVs) if the application modifies configuration properties while a background handshake is active, TaurusTLS treats configurations as **immutable snapshots**. 

Before a connection begins, the high-level `IOHandler` freezes its current properties into an immutable configuration instance. The active background thread connects, handshakes, and executes I/O using only this frozen snapshot, completely isolated from any concurrent changes on the UI thread.

### 1.2. The Dual-Track Reference Pattern
To manage the lifecycle of these snapshots automatically without introducing runtime CPU overhead, TaurusTLS combines reference-counted Delphi interfaces with direct class pointers:
*   **The Lifetime Track (The Interface):** Sockets hold a reference to `IITaurusTLSSocketConfig` (renamed to `ITaurusTLSSocketCtx`). This interface keeps the snapshot and its compiled `SSL_CTX` alive in memory for the exact duration of the socket's lifecycle. Once the socket is destroyed, releasing this reference automatically decrements the context reference count, deallocating memory cleanly on the C-heap.
*   **The Performance Track (The Class Pointer):** During construction, the socket resolves the interface to a direct, raw class pointer (`FConfig: TTaurusTLSSocketCtx`) using a fast, non-virtual assignment. During active network reading, writing, and setup connection, the state engine reads configuration parameters directly from this cached class pointer, **bypassing the virtual-method table (VMT) dispatch and reference-counting overhead of interface calls entirely.**

### 1.3. Symmetrical, Single-Class Design
TaurusTLS 2 bypasses subclass-level socket splitting entirely, implementing a single, unified bidirectional socket engine (**`TTaurusTLSSocket`**) and a single, reference-counted configuration context snapshot (**`TTaurusTLSSocketCtx`**). 
*   **Context Unification:** A single compiled context contains both client and server properties, allowing the same snapshot instance to be passed seamlessly to any socket.
*   **Handshake Unification:** Since OpenSSL's `TLS_method()` is bidirectional, the unified `TTaurusTLSSocket` class executes both `SSL_connect` and `SSL_accept` handshakes natively based on Indy's `IsPeer` boolean flag, cleanly supporting active FTPS modes with zero boilerplate.

---

## 2. Component Specifications

The relationships and definitions of the core configuration types are illustrated below.

```
+-------------------------------------------------------------+
|                     ITaurusTLSSocketCtx                     |  <-- Unified Lifetime Interface (RAII)
+-------------------------------------------------------------+
                               ^
                               | Implemented by
+-------------------------------------------------------------+
|                     TTaurusTLSSocketCtx                     |  <-- Unified Runtime Config Class
+-------------------------------------------------------------+
                               ^
                               | Managed by
+-------------------------------------------------------------+
|                TTaurusTLSClientConfigBuilder                |  <-- Fluent Context Builder Class
+-------------------------------------------------------------+
```

### 2.1. Snapshot Configuration Classes (`TaurusTLS_Sockets.pas`)
These are **pure, runtime-only classes inheriting from `TInterfacedObject`** (omitting the `TPersistent` dependency entirely). They implement `ITaurusTLSSocketCtx` and manage context reference-counting safely.

~~~pascal
type
  TTaurusTLSSocketCtx = class; // Forward declaration

  /// <summary>The single, unified lifetime interface used across the entire library.</summary>
  ITaurusTLSSocketCtx = interface(IInterface)
    ['{DCD600F0-1D28-482D-A883-A563CFE0D6FC}']
    function GetConfig: TTaurusTLSSocketCtx;
    property Config: TTaurusTLSSocketCtx read GetConfig;
  end;

  /// <summary>
  ///   Unified, runtime-only configuration snapshot. Managed via reference-counting.
  /// </summary>
  TTaurusTLSSocketCtx = class(TInterfacedObject, ITaurusTLSSocketCtx)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSender: TObject;
    FSSLCtx: PSSL_CTX; // Managed via SSL_CTX_up_ref / SSL_CTX_free

    // Common Verification Parameters
    FTrustStore: TaurusTLS_X509Store;
    FVerifyParam: TTaurusTLSCustomX509VerifyParam;
    FMinTLSVersion: TTaurusTLSSSLVersion;
    FMaxTLSVersion: TTaurusTLSSSLVersion;
    FCipherList: TStrings;
    FCipherSuites: TStrings;
    FCertVerifyFlags: TTaurusTLSVerifyModeFlags; // Stores sslvrfHostname internally
    FIgnoredVerifyErrors: TList<TIdC_INT>;
    FSessionToResume: PSSL_SESSION;

    // Client-Specific Properties
    FHostName: RawByteString;
    FDefaultSNI: RawByteString;
    FNormalizedHostName: RawByteString;   // Pre-compiled lower-case Punycode
    FNormalizedDefaultSNI: RawByteString; // Pre-compiled lower-case Punycode
    FNormalizedECHDecoy: RawByteString;   // Pre-compiled lower-case Punycode
    FECHFlags: TTaurusTLSECHCliFlags;
    FECHConfigList: RawByteString;
    FECHDecoy: RawByteString;

    // Identity Cache Fields
    FIdentity: RawByteString;
    FIdentityIP: Boolean;
    FIdentityBuilt: Boolean;
    FSNIKind: TTaurusTLSSNICliKind;

    // Server-Specific Properties (ALPN and mTLS Client-Verify)
    FVerifyClientModes: TTaurusTLSVerifyModes;
    FALPNPreferences: string;

    // Event handlers
    FOnStateChange: TTaurusTLSOnStateChange;
    FOnDebug: TTaurusTLSOnDebugMessage;
    FOnStatusInfo: TTaurusTLSOnSSLStatusInfo;
    FOnVerifyCertificate: TTaurusTLSOnVerifyCallback;
    FOnPeerCertError: TTaurusTLSOnPeerCertError;
    FOnSSLNegotiated: TNotifyEvent;
    FOnKeyLog: TTaurusTLSOnKeyLog;

    procedure ResetIdentity; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure BuildIdentity; {$IFDEF USE_INLINE}inline; {$ENDIF}
    
    function GetUseECH: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetUseGREASE: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetDecoySNI: RawByteString; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetECHNoOuterVal: TIdC_INT; {$IFDEF USE_INLINE}inline; {$ENDIF}
    
    function GetVerifyHostname: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetVerifyHostname(AValue: Boolean); {$IFDEF USE_INLINE}inline; {$ENDIF}

    function GetHostName: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetHostName(const AValue: string);
    function GetDefaultSNI: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetDefaultSNI(const AValue: string);
    function GetECHOuterSNI: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetECHOuterSNI(const AValue: string);
    function GetECHConfigList: string;
    procedure SetECHConfigList(const AValue: string);

    function GetIdentity: RawByteString;
    function GetIsIdentityIP: boolean;
  protected
    procedure SetSSLCtx(ASSLCtx: PSSL_CTX);
    function GetConfig: TTaurusTLSSocketCtx; {$IFDEF USE_INLINE}inline;{$ENDIF}
    procedure SetSessionToResume(const ASSL: PSSL); {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    constructor Create(ASender: TObject; ATLSMeth: PSSL_METHOD); virtual;
    destructor Destroy; override;

    property Config: TTaurusTLSSocketCtx read GetConfig;
    property SSLCtx: PSSL_CTX read FSSLCtx write SetSSLCtx;
    property VerifyHostname: Boolean read GetVerifyHostname write SetVerifyHostname;
    property CertVerifyFlags: TTaurusTLSVerifyModeFlags read FCertVerifyFlags write FCertVerifyFlags;
    property IgnoredVerifyErrors: TList<TIdC_INT> read FIgnoredVerifyErrors;
    property SessionToResume: PSSL_SESSION read FSessionToResume;

    // Client Identity & ECH Properties
    property HostName: string read GetHostName write SetHostName;
    property DefaultSNI: string read GetDefaultSNI write SetDefaultSNI;
    property SNIKind: TTaurusTLSSNICliKind read FSNIKind write FSNIKind;
    property ECHFlags: TTaurusTLSECHCliFlags read FECHFlags write FECHFlags;
    property ECHOuterSNI: string read GetECHOuterSNI write SetECHOuterSNI;
    property ECHConfigList: string read GetECHConfigList write SetECHConfigList;

    // Pre-Computed Getters
    property Identity: RawByteString read GetIdentity;
    property IsIdentityIP: boolean read GetIsIdentityIP;
    property UseECH: Boolean read GetUseECH;
    property UseGREASE: Boolean read GetUseGREASE;
    property DecoySNI: RawByteString read GetDecoySNI;
    property ECHNoOuterVal: TIdC_INT read GetECHNoOuterVal;

    property HostNameRaw: RawByteString read FHostname;
    property DefaultSNIRaw: RawByteString read FDefaultSNI;
    property ECHOuterSNIRaw: RawByteString read FECHOuterSNI;
    property ECHConfigListRaw: RawByteString read FECHConfigList;

    // Server Properties
    property VerifyClientModes: TTaurusTLSVerifyModes read FVerifyClientModes write FVerifyClientModes;
    property ALPNPreferences: string read FALPNPreferences write FALPNPreferences;

    // Event Handlers
    property OnStateChange: TTaurusTLSOnStateChange read FOnStateChange write FOnStateChange;
    property OnDebug: TTaurusTLSOnDebugMessage read FOnDebug write FOnDebug;
    property OnStatusInfo: TTaurusTLSOnSSLStatusInfo read FOnStatusInfo write FOnStatusInfo;
    property OnVerifyCertificate: TTaurusTLSOnVerifyCallback read FOnVerifyCertificate write FOnVerifyCertificate;
    property OnPeerCertError: TTaurusTLSOnPeerCertError read FOnPeerCertError write FOnPeerCertError;
    property OnNegotiated: TNotifyEvent read FOnNegotiated write FOnNegotiated;
    property OnKeyLog: TTaurusTLSOnKeyLog read FOnKeyLog write FOnKeyLog;
  end;
~~~

### 2.2. The Configuration Snapshot Builder (`TTaurusTLSClientConfigBuilder`)
This class implements the **Builder Pattern**, managing the `ITaurusTLSSocketCtx` master instance. If any property setters modify configuration parameters, they raise a `Dirty` flag.

~~~pascal
type
  /// <summary>
  ///   Fluent builder class responsible for gathering properties, compiling the immutable 
  ///   SSL_CTX, and producing the reference-counted ITaurusTLSSocketCtx snapshot.
  /// </summary>
  TTaurusTLSClientConfigBuilder = class(TObject)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSender: TObject;
    FConfigIntf: ITaurusTLSSocketCtx; // The master config interface reference
    FDirty: Boolean;
    
    // Properties matching the client options
    FCipherList: string;
    FVerifyFlags: TTaurusTLSVerifyModeFlags;
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
    function SetVerify(AFlags: TTaurusTLSVerifyModeFlags; ADepth: TIdC_INT): TTaurusTLSClientConfigBuilder;
    function SetSessionToResume(ASession: PSSL_SESSION): TTaurusTLSClientConfigBuilder;

    /// <summary>
    ///   Assembles properties, decodes and loads ECH keys under a strict try..finally block, 
    ///   and returns the completed reference-counted configuration snapshot.
    ///   Handles context compilation lazy-swapping based on the Dirty flag.
    /// </summary>
    function Build: ITaurusTLSSocketCtx;

    property CipherList: string read FCipherList write FCipherList;
    property VerifyFlags: TTaurusTLSVerifyModeFlags read FVerifyFlags write FVerifyFlags;
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
The base class (`TTaurusTLSSocket`) manages the synchronous, blocking loop driver. It is completely decoupled from the concrete cryptographic operations and executes on the background thread:

~~~pascal
procedure TTaurusTLSSocket.DoHandshake;
begin
  CheckActiveState([seHandshaking]);
  repeat
    DoHandshakeIteration; // Polymorphic, single-step execution
    
    if FState = seHandshaking then
    begin
      // Thread Yield: Relinquish CPU timeslice to prevent high CPU utilization
      // in non-blocking test modes or thread renegotiations.
      Sleep(1); 
    end;
    
  // Critical Security: We check both the state enum and thread termination status 
  // to guarantee the socket never hangs indefinitely when a unit test crashes.
  until (FState <> seHandshaking) or (Assigned(TThread.CurrentThread) and TThread.CurrentThread.Terminated);
end;
~~~

### 3.2. Context Initialization & Hostname Verification (`ConfigureHostnameVerification`)
Immediately upon entering the `seInitialized` state, the socket allocates `FSSL` and automatically configures its multi-name hostname and IP validation targets centrally. 

By operating directly on the connection's private, cloned parameters pointer via `SSL_get0_param(FSSL)`, we dynamically bind the expected validation target without disrupting or resetting any of the other properties inherited from the `SSL_CTX` (such as verification depths or CRL flags).

~~~pascal
procedure TTaurusTLSSocket.ConfigureHostnameVerification;
var
  LParams: PX509_VERIFY_PARAM;
  LTargetName: RawByteString;
  LIsIP: Boolean;
begin
  if not Config.VerifyHostname then
    Exit;

  // 1. Get the connection-specific verification parameters (cloned from SSL_CTX)
  LParams := SSL_get0_param(FSSL);
  if not Assigned(LParams) then
    Exit;

  // 2. Retrieve the pre-normalized, thread-safe logical identity
  LTargetName := Config.Identity;
  LIsIP := Config.IsIdentityIP;

  if LTargetName = '' then
    Exit;

  // 3. Bind the primary identity directly to the connection's parameter block.
  // This preserves all other inherited parameters (CRL flags, depth, etc.) intact.
  if LIsIP then
  begin
    // IPv4/IPv6 Literal Validation
    if X509_VERIFY_PARAM_set1_ip_asc(LParams, PIdAnsiChar(LTargetName)) <= 0 then
      ETaurusTLSSettingSANIPError.RaiseWithMessage('Failed to set IP validation parameter.');
  end
  else
  begin
    // Standard DNS / Wildcard Validation
    // X509_VERIFY_PARAM_set1_host clears any old hosts and sets this as the primary target
    if X509_VERIFY_PARAM_set1_host(LParams, PIdAnsiChar(LTargetName), Length(LTargetName)) <= 0 then
      ETaurusTLSSettingTLSHostNameError.RaiseException(FSSL, 0, 'Failed to set host verification parameter.');
  end;
end;
~~~

### 3.3. Handshake Iteration & ECH Status Checks (`DoHandshakeIteration`)
The concrete socket class overrides `DoHandshakeIteration` to execute a single step of the handshake, dynamically branching based on the role flag (`FIsPeer`). On successful handshake completion (`lRet = 1`), it performs ECH verification, caches the session resumption ticket, and transitions to `seEstablished`.

Manual post-handshake `SSL_get_verify_result` checks are omitted here. Because the verification hostnames are configured natively on the `SSL` session via `SSL_set1_host`, OpenSSL’s internal validation engine automatically handles all trust path and wildcard checks, feeding any failures directly into `SSLVerifyCallback`.

~~~pascal
procedure TTaurusTLSSocket.DoHandshakeIteration;
var
  lRet, lErr: Integer;
  lStatus: TIdC_INT;
  lInner, lOuter: PIdAnsiChar;
  lECHConfigBuf: PByte;
  lECHConfigLen: NativeUInt;
  lNewConfigBase64: String;
  lConfig: TTaurusTLSSocketCtx;
  lAccept: boolean;
begin
  lConfig := Config;
  try
    ERR_clear_error; // Clear error queue before doing read to avoid getting unhandled previously error
    
    if FIsPeer then
      lRet := SSL_accept(FSSL)
    else
      lRet := SSL_connect(FSSL);

    if lRet = 1 then
    begin
      // 1. Post-Handshake X.509 Verification & OnPeerCertError checks
      CheckPeerCertificateValidationResult;

      // 2. Verify ECH status prior to accepting handshake success (Clients Only)
      if (not FIsPeer) and lConfig.UseECH then
      begin
        lInner := nil;
        lOuter := nil;
        lStatus := SSL_ech_get1_status(FSSL, @lInner, @lOuter);
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
                FECHStatus := echCliFailed;
                lECHConfigBuf := nil;
                lECHConfigLen := 0;

                // Safely extract server's new ECH config keys
                if SSL_ech_get1_retry_config(FSSL, @lECHConfigBuf, @lECHConfigLen) = 1 then
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
                raise ETaurusTLSECHBadNameError.Create(lStatus, 'ECH succeeded but server certificate bad.');
              end;
          else
            begin
              TransitionTo(seError);
              raise ETaurusTLSECHProtocolError.Create(lStatus, 'ECH Handshake failed due to an internal error.');
            end;
          end;
        finally
          // Memory Safety: Free C-strings allocated by SSL_ech_get1_status immediately to prevent leaks
          if Assigned(lInner) then OPENSSL_free(lInner);
          if Assigned(lOuter) then OPENSSL_free(lOuter);
        end;
      end;

      // 3. Handshake Succeeded Cryptographically & Logically
      TransitionTo(seEstablished);

      // 4. Cache the negotiated session ticket back to the config for future resumption
      if not FIsPeer then
        FConfig.SetSessionToResume(FSSL);
      
      // Update ECH status for reporting (Clients Only)
      if (not FIsPeer) and FConfig.UseECH then
      begin
        lStatus := SSL_ech_get1_status(FSSL, nil, nil);
        if (lStatus = SSL_ECH_STATUS_SUCCESS) or (lStatus = SSL_ECH_STATUS_BACKEND) then
          FECHStatus := echCliSuccess
        else
          FECHStatus := echCliNone;
      end;

      FConfig.DoOnSSLNegotiated;
      Exit;
    end;

    // Handle Handshake Retry / Error States
    lErr := SSL_get_error(FSSL, lRet);
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
class function TTaurusTLSSocket.SSLVerifyCallback(const APreVerify: TIdC_INT;
  ACtx: PX509_STORE_CTX): TIdC_INT;
var
  lInstance: TTaurusTLSSocket;
  lConfig: TTaurusTLSSocketCtx;
  lSSL: PSSL;
  lErr: integer;
  lResult, lContinue: boolean;
begin
  Result := APreVerify;

  if not Assigned(ACtx) then
    Exit(0);

  try
    lErr := GStack.WSGetLastError;
    try
      lSSL := X509_STORE_CTX_get_ex_data(ACtx, SSL_get_ex_data_X509_STORE_CTX_idx());
      if not Assigned(lSSL) then
        Exit(0);

      lResult := APreVerify = 1;
      lContinue := True;
      
      lInstance := GetInstanceFromSSL<TTaurusTLSSocket>(lSSL);
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