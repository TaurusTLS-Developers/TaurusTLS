# Detailed Design Document: TaurusTLS "Socket State Machine"

## 1. Data Structures & Types

### 1.1. State Enumeration & Callbacks
~~~pascal
type
  /// <summary>Represents operational lifecycle states of the SSL socket.</summary>
  TTaurusTLSSslSocketState = (
    seIdle,          // Initial state; no OpenSSL objects allocated
    seInitializing,  // SSL session allocation and configuration in progress
    seInitialized,   // SSL session allocated and armed; ready for binding
    seHandshaking,   // Active TLS handshake negotiation
    seEstablished,   // Handshake complete; active encrypted I/O permitted
    seClosed,        // Orderly close_notify exchange and deallocation completed
    seError          // Terminal fault state
  );
  TTaurusTLSSslSocketStates = set of TTaurusTLSSslSocketState;

  TTaurusTLSSslSocketStateHelper = record helper for TTaurusTLSSslSocketState
  public const
    cNames: array[TTaurusTLSSslSocketState] of string = (
      'Idle', 'Initializing', 'Initialized', 'Handshaking',
      'Established', 'Closed', 'Error'
    );
    cTerminalStates = [seClosed, seError];
  private
    function GetAsString: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    property AsString: string read GetAsString;
  end;

  TTaurusTLSOnStateChange = procedure(ASender: TObject;
    ASocket: TTaurusTLSSslSocket; AOldState, ANewState: TTaurusTLSSslSocketState) of object;

  TTaurusTLSOnSSLStatusInfo = procedure(ASender: TObject;
    ASocket: TTaurusTLSSslSocket; const AState: TTaurusTLSSslState) of object;

  TTaurusTLSOnDebugMessage = procedure(ASender: TObject;
    const AMessage: String) of object;

  TTaurusTLSOnPeerCertError = procedure(ASender: TObject;
    ASocket: TTaurusTLSSslSocket; ACertificate: TTaurusTLSX509;
    const AError: TTaurusTLSX509Error; var ASuccess: boolean) of object;

  TTaurusTLSOnVerifyCallback = procedure(
    ASender: TObject; ASocket: TTaurusTLSSslSocket;
    ACertValidator: TTaurusTLSX509CertValidator;
    var ASuccess, AContinue: Boolean
  ) of object;

  TTaurusTLSOnSecurityCheck = procedure(
    ASender: TObject; ASocket: TTaurusTLSSslSocket;
    const AState: TTaurusTLSSecurityCheckState;
    var AAccept: Boolean
  ) of object;
~~~

### 1.2. Polymorphic Handshake Configuration Class Hierarchy
These classes capture and freeze the properties and event handlers of the parent `TIdSSLIOHandlerSocketBase` immediately prior to the handshake, preventing multi-threaded data races. 

The abstract base class manages the lifecycle of the shared `SSL_CTX` by incrementing its reference count via `SSL_CTX_up_ref` upon creation and decrementing it via `SSL_CTX_free` upon destruction.

~~~pascal
type
  TTaurusTLSSslSocketCtx = class;

  /// <summary>Reference-counted lifetime interface for context snapshots.</summary>
  ITaurusTLSSslSocketCtx = interface
  ['{DCD600F0-1D28-482D-A883-A563CFE0D6FC}']
    function GetCtx: TTaurusTLSSslSocketCtx;
    property Ctx: TTaurusTLSSslSocketCtx read GetCtx;
  end;

  /// <summary>Immutable runtime context snapshot holding compiled SSL_CTX and parameters.</summary>
  TTaurusTLSSslSocketCtx = class abstract(TInterfacedObject, ITaurusTLSSslSocketCtx)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSender: TObject;
    FSSLCtx: PSSL_CTX;
    FSession: PSSL_SESSION;
    FFlags: TaurusTLSSslSocketCtxFlags;
    FCertVerifyFlags: TTaurusTLSVerifyModeFlags;
    // Event handlers...
  protected
    function GetCtx: TTaurusTLSSslSocketCtx; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure InitCtx; virtual;
    procedure ReleaseCtx; virtual;
    procedure DoFreeze;
  public
    constructor Create(ASender: TObject; ATLSMeth: PSSL_METHOD);
    destructor Destroy; override;
    function FreezeCtx: TTaurusTLSSslSocketCtx; {$IFDEF USE_INLINE}inline; {$ENDIF}

    property Sender: TObject read FSender;
    property SSLCtx: PSSL_CTX read FSSLCtx;
    property Flags: TaurusTLSSslSocketCtxFlags read FFlags;
    property CertVerifyFlags: TTaurusTLSVerifyModeFlags read FCertVerifyFlags;
    property VerifyHostname: boolean index slfVerifyHostname read GetFlag;
  end;

  /// <summary>Client-specific snapshot managing SNI, ECH, and identity resolution.</summary>
  TTaurusTLSSslClientSocketCtx = class(TTaurusTLSSslSocketCtx)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FHostname: RawByteString;
    FDefaultSNI: RawByteString;
    FSNIMode: TTaurusTLSSslClientSNIMode;
    FECHOuterSNI: RawByteString;
    FECHConfigList: RawByteString;
    FIdentity: RawByteString;
    FIdentityIP: boolean;
    FIdentityBuilt: boolean;
  public
    property HostName: string read GetHostName;
    property DefaultSNI: string read GetDefaultSNI;
    property SNIMode: TTaurusTLSSslClientSNIMode read FSNIMode;
    property Identity: RawByteString read GetIdentity;
    property IsIdentityIP: boolean read GetIsIdentityIP;
    property UseECH: Boolean read GetUseECH;
    property UseGREASE: Boolean read GetUseGrease;
    property ECHNoOuterVal: TIdC_INT read GetECHNoOuterVal;
  end;

  /// <summary>Server-peer snapshot managing virtual hosting and ALPN selection.</summary>
  TTaurusTLSSslPeerCtx = class(TTaurusTLSSslSocketCtx)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FOnSniSelect: TTaurusTLSOnSniSelect;
    FOnAlpnSelect: TTaurusTLSOnAlpnSelect;
  public
    property OnSniSelect: TTaurusTLSOnSniSelect read FOnSniSelect;
    property OnAlpnSelect: TTaurusTLSOnAlpnSelect read FOnAlpnSelect;
  end;
~~~

### 1.3. The Abstract Context Class
`TTaurusTLSBaseSocket` serves as the state context. It holds a reference to the abstract `TTaurusTLSCustomSocketConfig` and processes connection states internally using direct, high-performance, enum-driven dispatches.

~~~pascal
type
  TTaurusTLSSslSocket = class
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    [Volatile]
    FState: TTaurusTLSSslSocketState;
    FSocketHandle: TIdStackSocketHandle;
    FHandshakeTimeout: Integer;           // Ephemeral handshake budget

    // The Dual-Track State Fields
    FContextIntf: ITaurusTLSSslSocketCtx; // Manages reference count safely
    FCtx: TTaurusTLSSslSocketCtx;         // Fast direct class pointer
    FSSL: PSSL;
    FIsSessionResumed: Boolean;
  protected
    class function GetInstanceFromSSL(ASSL: PSSL): TTaurusTLSSslSocket; static; inline;
    function CheckForError(ALastResult: Integer): Integer; virtual;
    function GetSSLError(ALastResult: Integer): Integer; inline;
    procedure ClearError; inline;

    function InitSSL: TTaurusTLSSslSocketState; virtual;
    procedure InitSSLCallbacks; virtual;
    procedure SetupConnection; virtual; abstract;
    procedure SetupHostnameVerification; virtual;
    procedure ReleaseSSL; virtual;
    procedure ReleaseSSLCallbacks; virtual;
    function BindSocket: TTaurusTLSSslSocketState; inline;

    function WaitForRead(AMsec: integer): boolean; inline;
    function WaitForWrite(AMsec: integer): boolean; inline;

    function DoHandshake: TTaurusTLSSslSocketState;
    function DoHandshakeIteration: TTaurusTLSSslSocketState; virtual; abstract;
    function DoShutdown: TTaurusTLSSslSocketState; virtual;

    function IsValidTransition(ACurrent, ATarget: TTaurusTLSSslSocketState): Boolean; virtual;
    function GetNextStepTarget(ACurrent, ATarget: TTaurusTLSSslSocketState): TTaurusTLSSslSocketState; virtual;
    function DoTransitionTo(ATarget: TTaurusTLSSslSocketState): TTaurusTLSSslSocketState; virtual;
    function DoSetState(ATarget: TTaurusTLSSslSocketState): boolean; overload; virtual;
    procedure DoSetState(ATarget: TTaurusTLSSslSocketState; ANotify: boolean); overload; inline;

    property HandshakeTimeout: Integer read FHandshakeTimeout;
  public
    constructor Create(const AConfigIntf: ITaurusTLSSslSocketCtx); virtual;
    destructor Destroy; override;

    procedure TransitionTo(ATarget: TTaurusTLSSslSocketState; ASteps: integer = cDefaultTransitions); virtual;
    function Connect(const pHandle: TIdStackSocketHandle; const AMSec: Integer = IdTimeoutDefault): Boolean; virtual;
    function Send(const ABuffer: TIdBytes; const AOffset, ALength: TIdC_SIZET; const AMSec: Integer): Integer; inline;
    function Recv(var ABuffer: TIdBytes; const AMSec: Integer): Integer; inline;
    function Readable(const AMsec: integer): boolean; inline;
    procedure Shutdown;

    property SSL: PSSL read FSSL;
    property State: TTaurusTLSSslSocketState read FState;
    property Ctx: TTaurusTLSSslSocketCtx read FCtx;
  end;
~~~

### 1.4. Specialized Descendant Classes
Specialized context classes implement client-specific and peer-specific setups. Descendants retrieve their appropriate concrete configuration safely via type-safe internal getters.

~~~pascal
type
  TTaurusTLSClientSocket = class(TTaurusTLSSslSocket)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSessionToResume: TTaurusTLSSslSession;
    FECHStatus: TTaurusECHClientStatus;
    function GetClientCtx: TTaurusTLSSslClientSocketCtx;
  protected
    procedure SetECHStatus(AECHStatus: TTaurusECHClientStatus); inline;
    procedure SetupConnection; override;
    procedure SetupHostnameVerification; inline;
    function DoHandshakeIteration: TTaurusTLSSslSocketState; override;
    function DoShutdown: TTaurusTLSSslSocketState; override;
    property ClientCtx: TTaurusTLSSslClientSocketCtx read GetClientCtx;
  public
    function Connect(const pHandle: TIdStackSocketHandle;
      ASessionToResume: TTaurusTLSSslSession): boolean; overload;
    property ECHStatus: TTaurusECHClientStatus read FECHStatus;
  end;

  TTaurusTLSPeerSocket = class(TTaurusTLSSslSocket)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    // Server-peer handshake implementation placeholder
  end;
~~~

---

## 2. Indy Wrapper Integration (`TTaurusTLSIOHandlerSocket`)

This skeleton shows how the high-level Indy component implements the secure I/O pipeline, delegates execution directly to the internal state machine, and implements the required factory methods.

~~~pascal
type
  TTaurusTLSIOHandlerSocket = class(TIdSSLIOHandlerSocketBase)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSSLSocket: TTaurusTLSBaseSocket;
    FSSLContext: PSSL_CTX; // Owned by the wrapper
  protected
    procedure SetPassThrough(const AValue: Boolean); override;
    function RecvEnc(var VBuffer: TIdBytes): Integer; override;
    function SendEnc(const ABuffer: TIdBytes; const AOffset, ALength: Integer): Integer; override;
  public
    procedure InitComponent; override;
    procedure ConnectClient; override;
    procedure AfterAccept; override;
    procedure Close; override;
    function Clone: TIdSSLIOHandlerSocketBase; override;
    function MakeClientIOHandler: TIdSSLIOHandlerSocketBase; override;
    function Readable(AMSec: Integer): Boolean; override;
    function CheckForError(ALastResult: Integer): Integer; override;
  end;

procedure TTaurusTLSIOHandlerSocket.InitComponent;
begin
  inherited InitComponent;
  fPassThrough := True; // Indy default: unencrypted until requested
  FSSLContext := nil;
  FSSLSocket := nil;
end;

procedure TTaurusTLSIOHandlerSocket.SetPassThrough(const AValue: Boolean);
begin
  if fPassThrough <> AValue then
  begin
    inherited SetPassThrough(AValue);
    if (not fPassThrough) and IsOpen then
      StartSSL;
  end;
end;

procedure TTaurusTLSIOHandlerSocket.ConnectClient;
var
  LPassThrough: Boolean;
begin
  try
    Init; // Ensure OpenSSL dynamic libraries are loaded
  except
    on ETaurusTLSCouldNotLoadSSLLibrary do
    begin
      if not PassThrough then
        raise;
    end;
  end;

  LPassThrough := fPassThrough;
  fPassThrough := True; // Pass through unencrypted during TCP connect (e.g., Proxies)
  try
    inherited ConnectClient; // Connects underlying TCP socket
  finally
    fPassThrough := LPassThrough;
  end;

  if Assigned(fOnBeforeConnect) then
    fOnBeforeConnect(Self);

  if not PassThrough then
    StartSSL;
end;

procedure TTaurusTLSIOHandlerSocket.Accept;
begin
  inherited Accept;
  if not PassThrough then
    StartSSL;
end;

procedure TTaurusTLSIOHandlerSocket.StartSSL;
var
  LClientCtx: ITaurusTLSSslSocketCtx;
begin
  if not Assigned(FSSLSocket) then
  begin
    if IsPeer then
    begin
      // Peer context compilation
    end
    else
    begin
      // Retrieve frozen client context snapshot from the builder
      LClientCtx := FClientBuilder.Build(Self);
      FSSLSocket := TTaurusTLSClientSocket.Create(LClientCtx);
    end;

    // Drives state machine through non-recursive loop: seIdle -> seInitializing -> seInitialized -> seHandshaking -> seEstablished
    FSSLSocket.Connect(Binding.Handle);
  end;
end;

function TTaurusTLSIOHandlerSocket.RecvEnc(var VBuffer: TIdBytes): Integer;
begin
  if Assigned(FSSLSocket) and (FSSLSocket.State = seEstablished) then
  begin
    Result := FSSLSocket.Recv(VBuffer);
  end;
end;

function TTaurusTLSIOHandlerSocket.SendEnc(const ABuffer: TIdBytes; const AOffset, ALength: Integer): Integer;
begin
  if Assigned(FSSLSocket) and (FSSLSocket.State = seEstablished) then
  begin
    Result := FSSLSocket.Send(ABuffer, AOffset, ALength);
  end;
end;

procedure TTaurusTLSIOHandlerSocket.Close;
begin
  if Assigned(FSSLSocket) then
  begin
    try
      FSSLSocket.Shutdown; // Moves to seClosing -> seClosed
    finally
      FreeAndNil(FSSLSocket);
    end;
  end;
  inherited Close;
end;

function TTaurusTLSIOHandlerSocket.Clone: TIdSSLIOHandlerSocketBase;
var
  LClone: TTaurusTLSIOHandlerSocket;
begin
  LClone := TTaurusTLSIOHandlerSocket(inherited Clone);
  // Share immutable context interface directly with cloned data channel (FTP parity)
  LClone.FContextIntf := Self.FContextIntf;
  Result := LClone;
end;

function TTaurusTLSIOHandlerSocket.MakeClientIOHandler: TIdSSLIOHandlerSocketBase;
var
  LClient: TTaurusTLSIOHandlerSocket;
begin
  LClient := TTaurusTLSIOHandlerSocket(Create(nil));
  LClient.FSSLContext := Self.FSSLContext;
  LClient.IsPeer := False;
  Result := LClient;
end;

function TTaurusTLSIOHandlerSocket.Readable(AMSec: Integer): Boolean;
begin
  if Assigned(FSSLSocket) and (FSSLSocket.State = seEstablished) then
  begin
    // Fast decrypted buffer check. If OpenSSL has decrypted data pending, we are readable immediately
    if FSSLSocket.Readable then
    begin
      Result := True;
      Exit;
    end;
  end;
  // Fall back to Indy's native OS-level socket select polling
  Result := inherited Readable(AMSec);
end;

function TTaurusTLSIOHandlerSocket.CheckForError(ALastResult: Integer): Integer;
var
  LSslErr: Integer;
begin
  if PassThrough then
  begin
    Result := inherited CheckForError(ALastResult);
  end
  else
  begin
    if not Assigned(FSSLSocket) then
    begin
      Result := inherited CheckForError(ALastResult);
      Exit;
    end;

    LSslErr := FSSLSocket.GetSSLError(ALastResult);
    if LSslErr = SSL_ERROR_NONE then
    begin
      Result := 0;
      Exit;
    end;

    if LSslErr = SSL_ERROR_SYSCALL then
    begin
      Result := inherited CheckForError(Integer(Id_SOCKET_ERROR));
      Exit;
    end;

    ETaurusTLSAPISSLError.RaiseExceptionCode(LSslErr, ALastResult);
  end;
end;
~~~

---

## 3. Centralized State Guard & Transition Factory

The Context (`TTaurusTLSBaseSocket`) enforces state-transition validity and manages the lifetime of `TTaurusTLSCustomSocketConfig`. State transitions are entirely allocation-free and OOM-immune.

To prevent memory leaks and access violations during teardown, the destructor unbinds `app_data` from the `SSL` handle prior to invocation of `SSL_free`.

~~~pascal
const
  cTerminalStates = [seClosed, seError];
  cDefaultTransitions = 8;

constructor TTaurusTLSSslSocket.Create(const AConfigIntf: ITaurusTLSSslSocketCtx);
begin
  inherited Create;
  FSocketHandle := Id_INVALID_SOCKET;
  FContextIntf := AConfigIntf;  // Pin reference count safely
  FCtx := AConfigIntf.Ctx;       // Fast direct class pointer
  FSSL := nil;
  FState := seIdle;
end;

destructor TTaurusTLSSslSocket.Destroy;
begin
  try
    Shutdown;
  except
    // Suppress exceptions during destruction teardown
  end;
  inherited Destroy;
end;

function TTaurusTLSSslSocket.IsValidTransition(ACurrent, ATarget: TTaurusTLSSslSocketState): Boolean;
begin
  if ACurrent in cTerminalStates then
    Exit(False);

  if ATarget = seError then
    Exit(True);

  case ACurrent of
    seIdle:         Result := ATarget in ([seInitializing] + cTerminalStates);
    seInitializing: Result := ATarget in ([seInitialized] + cTerminalStates);
    seInitialized:  Result := ATarget in ([seHandshaking] + cTerminalStates);
    seHandshaking:  Result := ATarget in ([seEstablished] + cTerminalStates);
    seEstablished:  Result := ATarget in cTerminalStates;
  else
    Result := False;
  end;
end;

function TTaurusTLSSslSocket.GetNextStepTarget(ACurrent, ATarget: TTaurusTLSSslSocketState): TTaurusTLSSslSocketState;
begin
  if ACurrent in cTerminalStates then
    Exit(ACurrent);

  if ATarget in cTerminalStates then
    Exit(ATarget);

  if ATarget <= ACurrent then
    Exit(ATarget);

  case ACurrent of
    seIdle:         Result := seInitializing;
    seInitializing: Result := seInitialized;
    seInitialized:  Result := seHandshaking;
    seHandshaking:  Result := seEstablished;
    seEstablished:  Result := seClosed;
  else
    Result := seError;
  end;
end;

function TTaurusTLSSslSocket.DoTransitionTo(ATarget: TTaurusTLSSslSocketState): TTaurusTLSSslSocketState;
begin
  Result := ATarget;
  if FState = Result then
    Exit;

  case ATarget of
    seInitializing: Result := InitSSL;
    seInitialized:
      begin
        CheckActiveState([seInitializing]);
        Result := seInitialized;
      end;
    seHandshaking:  Result := BindSocket;
    seEstablished:  Result := DoHandshake;
    seClosed:
      try
        DoShutdown; // Best-effort protocol close_notify
      finally
        ReleaseSSL; // Guaranteed unmanaged resource release
        Result := seClosed;
      end;
    seError:
      begin
        ReleaseSSL;
        Result := seError;
      end;
  else
    Result := seError;
  end;
end;

function TTaurusTLSSslSocket.DoShutdown: TTaurusTLSSslSocketState;
var
  lRet: Integer;
begin
  Result := seClosed;
  if not Assigned(FSSL) then
    Exit;

  ClearError;
  lRet := SSL_shutdown(FSSL);

  if (lRet = 0) and (not Ctx.Flags.UniDirectShutdown) then
  begin
    ERR_clear_error;
    SSL_shutdown(FSSL);
  end;
  // All errors (syscall drops, timeouts, RST) are swallowed here as DoTransitionTo
  // guarantees ReleaseSSL in its finally block.
end;

procedure TTaurusTLSSslSocket.Shutdown;
begin
  if not (FState in cTerminalStates) then
    TransitionTo(seClosed);
end;
~~~

---

## 4. Concrete Handshake Workflows & Direct I/O

### 4.1. Handshake Loop (`TTaurusTLSClientSocket` and `TTaurusTLSPeerSocket`)
The handshake process executes within a dedicated `try..except` block. If `SSL_connect` or `SSL_accept` raises an exception (or triggers a fatal protocol error), the handler transitions the socket to `seError` (or `seClosed` if ECH retry is expected) *prior* to bubbling the exception, preventing uncompleted handshake shutdown errors.

```pascal
function TTaurusTLSSslSocket.DoHandshake: TTaurusTLSSslSocketState;
var
  lTimeout: Integer;
  lSW: TStopWatch;
  lWaitOk: Boolean;
begin
  ClearError;
  CheckActiveState([seHandshaking]);

  lTimeout := FHandshakeTimeout;
  lSW := TStopWatch.StartNew;

  repeat
    Result := DoHandshakeIteration;

    if Result = seHandshaking then
    begin
      if lTimeout <> IdTimeoutInfinite then
      begin
        lTimeout := FHandshakeTimeout - Integer(lSW.ElapsedMilliseconds);
        if lTimeout <= 0 then
          ETaurusTLSHandshakeError.RaiseExceptionCode(
            SSL_ERROR_SYSCALL, -1, 'Handshake timeout expired.'
          );
      end;

      lWaitOk := True;
      if Assigned(FSSL) and (SSL_want_read(FSSL) > 0) then
        lWaitOk := WaitForRead(lTimeout)
      else if Assigned(FSSL) and (SSL_want_write(FSSL) > 0) then
        lWaitOk := WaitForWrite(lTimeout)
      else
        IndySleep(1); // In-memory loopback fallback

      if not lWaitOk then
        ETaurusTLSHandshakeError.RaiseExceptionCode(
          SSL_ERROR_SYSCALL, -1, 'Handshake I/O wait timed out.'
        );
    end;
  until (Result <> seHandshaking) or
        (Assigned(TThread.CurrentThread) and TThread.CurrentThread.Terminated);

  FIsSessionResumed := Assigned(FSSL) and (Result in [seEstablished, seClosed]) and
    (SSL_session_reused(FSSL) > 0);
end;

function TTaurusTLSClientSocket.DoHandshakeIteration: TTaurusTLSSslSocketState;
var
  lRet, lErr: Integer;
  lContext: TTaurusTLSSslClientSocketCtx;

  procedure ProcessECHStatus(const ARet: Integer);
  var
    lStatus: TIdC_INT;
    lInner, lOuter: PIdAnsiChar;
    lECHConfigBuf: PByte;
    lECHConfigLen: NativeUInt;
    lNewConfigBase64: string;
  begin
    lInner := nil;
    lOuter := nil;
    try
      lStatus := SSL_ech_get1_status(SSL, @lInner, @lOuter);
      case lStatus of
        SSL_ECH_STATUS_SUCCESS, SSL_ECH_STATUS_BACKEND:
          SetECHStatus(echCliSuccess);

        SSL_ECH_STATUS_GREASE:
          SetECHStatus(echCliNone);

        SSL_ECH_STATUS_GREASE_ECH, SSL_ECH_STATUS_FAILED_ECH, SSL_ECH_STATUS_FAILED_ECH_BAD_NAME:
          begin
            if lContext.SNIMode = csmECHGrease then
              SetECHStatus(echCliNone)
            else
            begin
              SetECHStatus(echCliFailed);
              lECHConfigBuf := nil;
              lECHConfigLen := 0;

              if SSL_ech_get1_retry_config(SSL, @lECHConfigBuf, @lECHConfigLen) > 0 then
              begin
                try
                  if (lECHConfigBuf <> nil) and (lECHConfigLen > 0) then
                  begin
                    lNewConfigBase64 := EncodeConfigList(lECHConfigBuf, lECHConfigLen);
                    lContext.DoOnECHConfigRetry(Self, lNewConfigBase64);
                  end;
                finally
                  OPENSSL_free(lECHConfigBuf);
                end;
                SetECHStatus(echCliRetryConfig);
                Result := seClosed; // Signal clean close so IOHandler can reconnect with fresh ECH keys
              end
              else
                ETaurusTLSECHRejectedError.RaiseException(FSSL, ARet,
                  'ECH Handshake failed. The server rejected the key and provided no retry configuration.');
            end;
          end;

        SSL_ECH_STATUS_NOT_TRIED, SSL_ECH_STATUS_NOT_CONFIGURED:
          begin
            if lContext.UseECH then
              ETaurusTLSECHDowngradeError.RaiseException(FSSL, ARet,
                'ECH Handshake bypassed. Possible downgrade attack or configuration mismatch.')
            else
            begin
              SetECHStatus(echCliNone);
              if ARet <= 0 then
                Result := seClosed; // Signal clean close for cleartext SNI fallback
            end;
          end;

        SSL_ECH_STATUS_BAD_NAME:
          ETaurusTLSECHBadNameError.RaiseException(FSSL, ARet,
            'ECH Handshake completed but the server certificate verification failed.');
      else
        if ARet <= 0 then
          ETaurusTLSECHProtocolError.RaiseException(FSSL, ARet,
            'ECH Handshake failed due to an internal OpenSSL or protocol error.');
      end;
    finally
      if Assigned(lInner) then OPENSSL_free(lInner);
      if Assigned(lOuter) then OPENSSL_free(lOuter);
    end;
  end;

begin
  lContext := ClientCtx;
  ClearError;
  Result := seError;
  lRet := SSL_connect(SSL);

  if lRet > 0 then
  begin
    Result := seEstablished;
    SetECHStatus(echCliNone);

    if (lContext.UseECH or lContext.UseGREASE) and (not lContext.IsIdentityIP) then
      ProcessECHStatus(lRet);

    if Result = seEstablished then
      CheckPeerCertificateValidationResult;
  end
  else
  begin
    lErr := GetSSLError(lRet);
    case lErr of
      SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE:
        Result := seHandshaking;

      SSL_ERROR_SYSCALL:
        ETaurusTLSSslSocketConnectionReset.RaiseException(FSSL, lErr, 'Handshake reset by peer.');

      SSL_ERROR_SSL:
        begin
          if (lContext.UseECH or lContext.UseGREASE) and (not lContext.IsIdentityIP) then
            ProcessECHStatus(lRet)
          else
            ETaurusTLSHandshakeError.RaiseExceptionCode(lErr, lRet, 'Fatal handshake error.');
        end;
    else
      ETaurusTLSHandshakeError.RaiseExceptionCode(lErr, lRet, 'Fatal handshake error.');
    end;
  end;
end;
```

### 4.2. Direct, High-Performance I/O (`Recv` and `Send`)
These methods bypass all state action classes, checking the `FState` directly in-memory to prevent virtual redirect overhead on critical paths.

```pascal
function TTaurusTLSSslSocket.Recv(var ABuffer: TIdBytes;
  const AMSec: Integer): Integer;
var
  lResult: TIdC_SIZET;
  lLen, lRet, lErr, lTimeout: Integer;
  lIsTimeout: Boolean;
  lSW: TStopWatch;
begin
  lResult := 0;
  lLen := Length(ABuffer);
  if lLen = 0 then Exit(0);

  CheckActiveState([seEstablished]);
  lIsTimeout := False;
  lSW := TStopWatch.StartNew;

  repeat
    ClearError;
    lRet := SSL_read_ex(FSSL, ABuffer[0], lLen, lResult);
    Result := lResult;

    if lRet > 0 then Break;

    if AMSec <> IdTimeoutInfinite then
    begin
      lTimeout := AMSec - Integer(lSW.ElapsedMilliseconds);
      lIsTimeout := (lTimeout <= 0);
    end
    else
      lTimeout := IdTimeoutInfinite;

    if lIsTimeout then Break;

    lErr := GetSSLError(lRet);
    case lErr of
      SSL_ERROR_WANT_READ:
        if SSL_has_pending(FSSL) > 0 then
          Continue
        else
          lIsTimeout := not WaitForRead(lTimeout);

      SSL_ERROR_WANT_WRITE:
        lIsTimeout := not WaitForWrite(lTimeout);

      SSL_ERROR_ZERO_RETURN:
        begin
          Result := 0; // Graceful TLS close_notify
          Break;
        end;
    else
      CheckForError(lRet);
      Break;
    end;
  until lIsTimeout;
end;

function TTaurusTLSSslSocket.Send(const ABuffer: TIdBytes; const AOffset,
  ALength: TIdC_SIZET; const AMSec: Integer): Integer;
var
  lResult: TIdC_SIZET;
  lRet, lErr, lTimeout: Integer;
  lLen: TIdC_SIZET;
  lIsTimeout: Boolean;
  lSW: TStopWatch;
begin
  Result := 0;
  lLen := Length(ABuffer);
  if (ALength = 0) or (lLen = 0) or (AOffset >= lLen) or (ALength > lLen - AOffset) then
    Exit(0);

  CheckActiveState([seEstablished]);
  lIsTimeout := False;
  lSW := TStopWatch.StartNew;

  repeat
    ClearError;
    lRet := SSL_write_ex(FSSL, ABuffer[AOffset], ALength, lResult);
    Result := lResult;

    if lRet > 0 then Break;

    if AMSec <> IdTimeoutInfinite then
    begin
      lTimeout := AMSec - Integer(lSW.ElapsedMilliseconds);
      lIsTimeout := (lTimeout <= 0);
    end
    else
      lTimeout := IdTimeoutInfinite;

    if lIsTimeout then Break;

    lErr := GetSSLError(lRet);
    case lErr of
      SSL_ERROR_WANT_WRITE: lIsTimeout := not WaitForWrite(lTimeout);
      SSL_ERROR_WANT_READ:  lIsTimeout := not WaitForRead(lTimeout);
      SSL_ERROR_ZERO_RETURN:
        begin
          Result := 0;
          Break;
        end;
    else
      CheckForError(lRet);
      Break;
    end;
  until lIsTimeout;
end;

function TTaurusTLSSslSocket.CheckForError(ALastResult: Integer): Integer;
var
  lSslErr: TIdC_INT;
  lQueueErr: TIdC_ULONG;
  lErrStr: string;
begin
  if ALastResult > 0 then
    Exit(0);

  if (FState in cTerminalStates) or (FSocketHandle = Id_INVALID_SOCKET) then
  begin
    GStack.CheckForSocketError(Integer(Id_SOCKET_ERROR),
      [Id_WSAESHUTDOWN, Id_WSAECONNABORTED, Id_WSAECONNRESET, Id_WSAETIMEDOUT]);
    ETaurusTLSSslSocketConnectionReset.RaiseWithMessage('Socket is closed.');
  end;

  if Assigned(FSSL) then
    lSslErr := SSL_get_error(FSSL, ALastResult)
  else
    lSslErr := SSL_ERROR_SYSCALL;

  Result := lSslErr;
  if lSslErr = SSL_ERROR_NONE then
    Exit(0);

  if lSslErr = SSL_ERROR_SYSCALL then
  begin
    // Delegates to Indy stack to raise EIdSocketError with OS error code
    GStack.CheckForSocketError(Integer(Id_SOCKET_ERROR));
    // If GStack error was 0 (unexpected EOF without TLS alert)
    ETaurusTLSSslSocketConnectionReset.RaiseWithMessage('Connection reset by peer.');
  end;

  lQueueErr := ERR_peek_error;
  if lQueueErr <> 0 then
    lErrStr := string(ERR_error_string(lQueueErr, nil))
  else
    lErrStr := 'Unspecified OpenSSL error.';

  ETaurusTLSAPISSLError.RaiseExceptionCode(lSslErr, ALastResult, lErrStr);
end;
```

### 4.3. Orderly Disconnection (DoShutdown)
Processes bidirectional closing of the TLS session with explicit try..except masking.

```pascal
function TTaurusTLSSslSocket.DoShutdown: TTaurusTLSSslSocketState;
var
  lRet, lErr: Integer;
begin
  if FState = seError then
    Exit(seError)
  else
    Result := seClosed;

  if not Assigned(FSSL) then Exit;

  ClearError;
  lRet := SSL_shutdown(FSSL);

  if lRet < 0 then
  begin
    lErr := GetSSLError(lRet);
    if lErr = SSL_ERROR_SYSCALL then
      Result := seClosed
    else
      Result := seError;
    Exit;
  end
  else if (lRet = 0) and (not Ctx.Flags.UniDirectShutdown) then
  begin
    ERR_clear_error;
    SSL_shutdown(FSSL);
    Result := seClosed;
  end;
end;
```

---

## 5. Callbacks & Bridge Execution
Static cdecl functions resolve the active Delphi socket instance using SSL_get_app_data(ASSL) and bridge to context event handlers:

```pascal
class function TTaurusTLSSslSocket.CbSslVerify(const APreVerify: TIdC_INT;
  ACtx: PX509_STORE_CTX): TIdC_INT;
var
  lInstance: TTaurusTLSSslSocket;
  lContext: TTaurusTLSSslSocketCtx;
  lSSL: PSSL;
  lErr: integer;
  lResult, lContinue: boolean;
begin
  Result := APreVerify;
  if not Assigned(ACtx) then Exit(0);

  try
    lErr := GStack.WSGetLastError;
    try
      lSSL := X509_STORE_CTX_get_ex_data(ACtx, SSL_get_ex_data_X509_STORE_CTX_idx());
      if not Assigned(lSSL) then Exit(0);

      lResult := (APreVerify = 1);
      lContinue := True;

      lInstance := GetInstanceFromSSL(lSSL);
      lContext := lInstance.FCtx;
      if Assigned(lContext) then
      begin
        lContext.DoOnVerifyCertificate(lInstance, ACtx, lResult, lContinue);
        if lContinue then Result := 1 else Result := 0;
        if lResult then
          X509_STORE_CTX_set_error(ACtx, X509_V_OK); // Clear error state in OpenSSL
      end;
    finally
      GStack.WSSetLastError(lErr);
    end;
  except
    Result := 0;
  end;
end;

class function TTaurusTLSSslSocket.CbSslSecurityCheck(const ASSL: PSSL;
  const ACtx: PSSL_CTX; AOp, ABits, ANid: TIdC_INT; AOther, AEx: pointer): TIdC_INT;
var
  lErr: TIdC_INT;
  lResult: boolean;
  lInstance: TTaurusTLSSslSocket;
  lContext: TTaurusTLSSslSocketCtx;
begin
  Result := 1;
  if not Assigned(ASSL) then Exit;

  try
    lErr := GStack.WSGetLastError;
    try
      lInstance := TTaurusTLSSslSocket(AEx);
      if not Assigned(lInstance) then Exit;

      lContext := lInstance.FCtx;
      if not Assigned(lContext) then Exit;

      lResult := False;
      lContext.DoOnSecurityCheck(lInstance, AOp, ABits, ANid, AOther, lResult);

      if lResult then Result := 1 else Result := 0;
    finally
      GStack.WSSetLastError(lErr);
    end;
  except
    Result := 0;
  end;
end;
```

---

## 6. Client Session Resumption Implementation
Explicit session resumption is isolated within `TTaurusTLSClientSocket`.

```pascal
function TTaurusTLSClientSocket.Connect(const pHandle: TIdStackSocketHandle;
  ASessionToResume: TTaurusTLSSslSession): boolean;
begin
  FSessionToResume := ASessionToResume;
  Result := Connect(pHandle);
end;

procedure TTaurusTLSClientSocket.SetupConnection;
begin
  // Applies session ticket to FSSL prior to handshake
  if Assigned(FSessionToResume) then
    SSL_set_session(FSSL, FSessionToResume.SSLSession);

  SetECHStatus(echCliNotConfigured);
  SetupHostnameVerification;
  // SNI / ECH setup...
end;
```

---

## 7. Platform Safety (Initialization)
To support the state machine and prevent OS-level process termination:
*   **SIGPIPE Shield**: FSigSet is initialized once in TTaurusTLSSslSocket.Create (class constructor) and blocked per-thread via pthread_sigmask(SIG_BLOCK, @FSigSet, nil) inside InitSSL.
*   **Disabled AUTO_RETRY**: Explicitly cleared at context initialization via SSL_CTX_clear_mode(SSLCtx, SSL_MODE_AUTO_RETRY) to give the state machine control over timeout budgets.

---

## 8. Shutdown Sequence
1.  **seEstablished -> seClosing**: Invokes DoShutdown (SSL_shutdown).
2.  **Bi-directional Check**: If lRet = 0 and not UniDirectShutdown, calls SSL_shutdown a second time to await the peer's CloseNotify.
3.  **Terminal Teardown**: Transitions to seReleased, where ReleaseSSL frees FSSL and clears app_data.


---

### Section 9: State-Specific Exception Mapping

The following table explicitly maps the exact exceptions permitted to be raised during each logical state of the connection lifecycle:

| Logical State | Allowed Exceptions | Triggering Cause |
| :--- | :--- | :--- |
| **`seIdle` / `seInitializing`** | `ETaurusTLSSslSocketCreateError` | `SSL_new` failed to allocate native OpenSSL session. |
| | `ETaurusTLSSslSocketDataBindingError` | `SSL_set_app_data` failed to bind Delphi socket instance. |
| | `ETaurusTLSSslClientSocketSetupError` | Target is an IP literal in real ECH mode, or context is missing. |
| | `ETaurusTLSSslClientSocketHostNameError` | `SSL_set_tlsext_host_name` or `SSL_ech_set1_server_names` failed. |
| **`seInitialized`** | `ETaurusTLSSslSocketBindError` | `SSL_set_fd` failed to bind OS socket descriptor. |
| **`seHandshaking`** | `ETaurusTLSECHRejectedError` | Server rejected ECH key and returned NO `retry_configs`. |
| | `ETaurusTLSECHDowngradeError` | Strict ECH requested (`csmECH`, `csmECHNoOuter`), but server bypassed ECH. |
| | `ETaurusTLSECHBadNameError` | ECH decrypted, but presented server certificate failed inner identity matching. |
| | `ETaurusTLSECHProtocolError` | OpenSSL internal protocol failure during ECH processing (`SSL_ECH_STATUS_FAILED`). |
| | `ETaurusTLSHandshakeError` | General OpenSSL handshake protocol negotiation failure. |
| | `ETaurusTLSSslSocketConnectionReset` | Physical TCP reset (RST) or syscall drop during handshake (`SSL_ERROR_SYSCALL`). |
| | `ETaurusTLSSslSocketCertValidationError` | Post-handshake peer certificate verification failed (when not handled by event). |
| | `EIdConnClosedGracefully` | Remote peer closed connection gracefully during handshake. |
| **`seEstablished`** | `ETaurusTLSSslSocketConnectionReset` | Physical TCP reset (RST) occurred during active `Recv` or `Send`. |
| | `ETaurusTLSAPISSLError` | OpenSSL protocol error during active encrypted `Recv` or `Send`. |
| | `EIdConnClosedGracefully` | Remote peer sent `close_notify` (handled via `SSL_ERROR_ZERO_RETURN`). |
| | `ETaurusTLSSslSocketCertValidationError` | Fired if a TLS 1.3 Post-Handshake Authentication (PHA) certificate update fails validation. |
| **`seClosed` / `seReleased`** | `ETaurusTLSSslSocketConnectionReset` | Connection was already closed when I/O or handshake was attempted. |
| **Any State (Transition)** | `ETaurusTLSSocketStateError` | Illegal state transition attempted or infinite transition loop threshold exceeded. |
