# Detailed Design Document: TaurusTLS "Socket State Machine"

## 1. Data Structures & Types

### 1.1. State Enumeration & Callbacks
~~~pascal
type
  TTaurusTLSSslState = (
    seIdle,
    seInitialized,
    seHandshaking,
    seEstablished,
    seClosing,
    seClosed,
    seError
  );

  TTaurusTLSSslStateHelper = record helper for TTaurusTLSSslState
  public const
    cNames: array[TTaurusTLSSslState] of string = ('Idle', 'Initialized',
      'Handshaking', 'Established', 'Closing', 'Closed', 'Error');
  private
    function GetAsString: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    property AsString: string read GetAsString;
  end;

  TTaurusTLSOnStateChange = procedure(ASender: TObject;
    AOldState, ANewState: TTaurusTLSSslState) of object;
  TTaurusTLSOnIOHandlerNotify = procedure(ASender: TObject) of object;
  TTaurusTLSOnSSLStatusInfo = procedure(ASender: TObject;
    AWhere, ARet: TIdC_INT) of object;
  TTaurusTLSOnDebugMessage = procedure(ASender: TObject;
    const AMessage: String) of object;
  TTaurusTLSOnSecurityLevel = procedure(ASender: TObject;
    var AAccept: Boolean) of object;

  TTaurusTLSOnVerifyCallback = procedure(
    ASender: TObject;
    ACert: TTaurusTLSX509;
    ADepth: TIdC_INT;
    AErrCode: TIdC_INT;
    var AVerifyOK: Boolean
  ) of object;
~~~

### 1.2. Polymorphic Handshake Configuration Class Hierarchy
These classes capture and freeze the properties and event handlers of the parent `TIdSSLIOHandlerSocketBase` immediately prior to the handshake, preventing multi-threaded data races. 

The abstract base class manages the lifecycle of the shared `SSL_CTX` by incrementing its reference count via `SSL_CTX_up_ref` upon creation and decrementing it via `SSL_CTX_free` upon destruction.

~~~pascal
type
  /// <summary>
  ///   Abstract base capturing shared connection parameters, common callback events,
  ///   and managing the lifetime of the underlying SSL_CTX.
  /// </summary>
  TTaurusTLSCustomSocketConfig = class abstract
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSender: TObject;
    FSSLCtx: PSSL_CTX;
    FTrustStore: PX509_STORE;
    FVerifyDepth: TIdC_INT;
    FVerifyFlags: TTaurusTLSCertificateVerifyFlagSet;

    FOnStateChange: TTaurusTLSOnStateChange;
    FOnDebug: TTaurusTLSOnDebugMessage;
    FOnSecurityLevel: TTaurusTLSOnSecurityLevel;
    FOnStatusInfo: TTaurusTLSOnSSLStatusInfo;
    FOnVerifyCertificate: TTaurusTLSOnVerifyCallback;
    FOnNegotiated: TNotifyEvent;
  protected
    procedure DoCloneSession(ASSL: PSSL); virtual; abstract;
    procedure SetTrustStore(ATrustStore: PX509_STORE);
    procedure SetSSLCtx(ASSLCtx: PSSL_CTX);
    
    procedure DoOnStateChange(AOldState, ANewState: TTaurusTLSSslState); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoOnDebug(const AMsg: string); {$IFDEF USE_INLINE}inline; {$ENDIF}
    function DoOnSecurityLevel: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoOnStatusInfo(AWhere, ARet: TIdC_INT); {$IFDEF USE_INLINE}inline; {$ENDIF}
    function DoOnVerifyCertificate(APreVerify: boolean; ACtx: PX509_STORE_CTX): boolean;
    procedure DoOnSSLNegotiated; {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    constructor Create(ASender: TObject); virtual;
    destructor Destroy; override;
    procedure CloneSession(ASSL: PSSL); {$IFDEF USE_INLINE}inline; {$ENDIF}
    
    property Sender: TObject read FSender;
    property SSLCtx: PSSL_CTX read FSSLCtx write SetSSLCtx;
    property TrustStore: PX509_STORE read FTrustStore write SetTrustStore;
    property VerifyDepth: TIdC_INT read FVerifyDepth write FVerifyDepth;
    property VerifyFlags: TTaurusTLSCertificateVerifyFlagSet read FVerifyFlags write FVerifyFlags;
    
    property OnStateChange: TTaurusTLSOnStateChange read FOnStateChange write FOnStateChange;
    property OnDebug: TTaurusTLSOnDebugMessage read FOnDebug write FOnDebug;
    property OnSecurityLevel: TTaurusTLSOnSecurityLevel read FOnSecurityLevel write FOnSecurityLevel;
    property OnStatusInfo: TTaurusTLSOnSSLStatusInfo read FOnStatusInfo write FOnStatusInfo;
    property OnVerifyCertificate: TTaurusTLSOnVerifyCallback read FOnVerifyCertificate write FOnVerifyCertificate;
    property OnNegotiated: TNotifyEvent read FOnNegotiated write FOnNegotiated;
  end;

  /// <summary>
  ///   Captures client-specific connection settings such as SNI, ECH, and hostname verification.
  /// </summary>
  TaurusTLSClientSocketConfig = class(TTaurusTLSCustomSocketConfig)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSessionToResume: PSSL_SESSION;
    FHostName: string;
    FDefaultSNI: string;
    FECHEnabled: boolean;
    FECHConfigList: string;
    FECHDecoy: string;
  protected
    procedure SetSessionToResume(const ASSL: PSSL); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoCloneSession(ASSL: PSSL); override;
  public
    destructor Destroy; override;
    
    property SessionToResume: PSSL_SESSION read FSessionToResume;
    property HostName: string read FHostName write FHostName;
    property DefaultSNI: string read FDefaultSNI write FDefaultSNI;
    property ECHEnabled: boolean read FECHEnabled write FECHEnabled;
    property ECHConfigList: string read FECHConfigList write FECHConfigList;
    property ECHDecoy: string read FECHDecoy write FECHDecoy;
  end;

  /// <summary>
  ///   Captures server-side client connection context such as client certificate verification mode.
  /// </summary>
  TTaurusTLSPeerHandshakeSnapshot = class(TTaurusTLSCustomSocketConfig)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FVerifyClientMode: TIdSSLVerifyMode;
    FALPNPreferences: String;
  public
    constructor Create(AIOHandler: TIdSSLIOHandlerSocketBase; ACTX: PSSL_CTX); override;
    
    property VerifyClientMode: TIdSSLVerifyMode read FVerifyClientMode;
    property ALPNPreferences: String read FALPNPreferences;
  end;
~~~

### 1.3. The Abstract Context Class
`TTaurusTLSBaseSocket` serves as the state context. It holds a reference to the abstract `TTaurusTLSCustomSocketConfig` and processes connection states internally using direct, high-performance, enum-driven dispatches.

~~~pascal
type
  TTaurusTLSBaseSocket = class abstract
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    [Volatile]
    FState: TTaurusTLSSslState;
    FConfig: TTaurusTLSCustomSocketConfig;
    FSocketHandle: TIdStackSocketHandle;
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    FSSL: PSSL;
    class procedure SslInfoCallback(const ASSL: PSSL; AWhere, ARet: TIdC_INT); static;
    class function SSLVerifyCallback(APreVerify: LongBool; ACtx: PX509_STORE_CTX): TIdC_INT; static;
    class function GetInstanceFromSSL<T: TTaurusTLSBaseSocket>(ASSL: PSSL): T; static; {$IFDEF USE_INLINE}inline; {$ENDIF}
    
    function CheckForError(ALastResult: Integer): Integer; virtual;
    function GetSSLError(ALastResult: Integer): Integer; {$IFDEF USE_INLINE}inline; {$ENDIF}
    
    procedure InitSSL; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure InitSSLCallbacks; virtual;
    procedure ReleaseSSL; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure ReleaseSSLCallbacks; virtual;
    procedure LinkSocket; {$IFDEF USE_INLINE}inline; {$ENDIF}
    
    procedure DoHandshake; virtual; abstract;
    procedure DoShutdown;
    
    function IsValidTransition(ACurrent, ATarget: TTaurusTLSSslState): Boolean; virtual;
    procedure DoSetState(ATarget: TTaurusTLSSslState); virtual;
    procedure CheckActiveState(AExpectedState: TTaurusTLSSslState); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoStateChangeNotify(ACurrent, ATarget: TTaurusTLSSslState); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoDebugLog(const AMessage: string); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure ClosePhysicalSocket; virtual; abstract;
    
    property SocketHandle: TIdStackSocketHandle read FSocketHandle;
  public
    constructor Create(AConfig: TTaurusTLSCustomSocketConfig);
    destructor Destroy; override;
    
    procedure TransitionTo(ATarget: TTaurusTLSSslState); virtual;
    
    // Core Socket Operations
    procedure Connect(const pHandle: TIdStackSocketHandle); virtual;
    procedure ProcessSSL; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function Send(const ABuffer: TIdBytes; const AOffset, ALength: TIdC_SIZET): TIdC_SIZET; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function Recv(var ABuffer: TIdBytes): TIdC_SIZET; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function Readable: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure Shutdown;
    
    property SSL: PSSL read FSSL;
    property State: TTaurusTLSSslState read FState;
    property Config: TTaurusTLSCustomSocketConfig read FConfig;
  end;
~~~

### 1.4. Specialized Descendant Classes
Specialized context classes implement client-specific and peer-specific setups. Descendants retrieve their appropriate concrete configuration safely via type-safe internal getters.

~~~pascal
type
  TTaurusTLSClientSocket = class(TTaurusTLSBaseSocket)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FECHStatus: TTaurusECHClientStatus;
    function GetClientConfig: TaurusTLSClientSocketConfig; {$IFDEF USE_INLINE}inline; {$ENDIF}
  protected
    procedure SetECHStatus(AECHStatus: TTaurusECHClientStatus); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoHandshake; override;
    property ClientConfig: TaurusTLSClientSocketConfig read GetClientConfig;
  public
  end;

  TTaurusTLSPeerSocket = class(TTaurusTLSBaseSocket)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    function GetPeerConfig: TTaurusTLSPeerHandshakeSnapshot; {$IFDEF USE_INLINE}inline; {$ENDIF}
  protected
    procedure DoHandshake; override;
    property PeerConfig: TTaurusTLSPeerHandshakeSnapshot read GetPeerConfig;
  public
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

procedure TTaurusTLSIOHandlerSocket.AfterAccept;
begin
  inherited AfterAccept;
  if not PassThrough then
    StartSSL;
end;

procedure TTaurusTLSIOHandlerSocket.StartSSL;
var
  LClientConfig: TaurusTLSClientSocketConfig;
  LPeerConfig: TTaurusTLSPeerHandshakeSnapshot;
begin
  if not Assigned(FSSLSocket) then
  begin
    if IsPeer then
    begin
      LPeerConfig := TTaurusTLSPeerHandshakeSnapshot.Create(Self, FSSLContext);
      FSSLSocket := TTaurusTLSPeerSocket.Create(LPeerConfig);
    end
    else
    begin
      LClientConfig := TaurusTLSClientSocketConfig.Create(Self, FSSLContext);
      FSSLSocket := TTaurusTLSClientSocket.Create(LClientConfig);
    end;
      
    FSSLSocket.Connect(Binding.Handle); // Initiates the handshake loop (seIdle -> seInitialized -> seHandshaking)
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
  LClone.FSSLContext := Self.FSSLContext; // Share context reference
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
constructor TTaurusTLSBaseSocket.Create(AConfig: TTaurusTLSCustomSocketConfig);
begin
  inherited Create;
  FSocketHandle:=Id_INVALID_SOCKET;
  FConfig := AConfig; // Take ownership of the Config
  FSSL := nil;
  FState := seIdle;
end;

destructor TTaurusTLSBaseSocket.Destroy;
begin
  ReleaseSSL;
  FreeAndNil(FConfig); // Safely destroy the reference-counted configuration class
  inherited Destroy;
end;

function TTaurusTLSBaseSocket.IsValidTransition(ACurrent, ATarget: TTaurusTLSSslState): Boolean;
begin
  // Global Panic State Rule: seError is valid from any state except Closed and itself
  if ATarget = seError then
  begin
    Result := (ACurrent <> seClosed) and (ACurrent <> seError);
    Exit;
  end;

  case ACurrent of
    seIdle:          Result := (ATarget = seInitialized);
    seInitialized:   Result := (ATarget = seHandshaking) or (ATarget = seClosed);
    seHandshaking:   Result := (ATarget = seEstablished) or (ATarget = seClosed);
    seEstablished:   Result := (ATarget = seClosing) or (ATarget = seClosed);
    seClosing:       Result := (ATarget = seClosed);
    seClosed, seError: Result := False; // Terminal states cannot transition out
  else
    Result := False;
  end;
end;

procedure TTaurusTLSBaseSocket.TransitionTo(ATarget: TTaurusTLSSslState);
var
  lCurrentState: TTaurusTLSSslState;
begin
  lCurrentState:=State; // Using internal State property

  // 1. Redundant Transition Guard (Fails fast in Debug, exits silently in Release)
  Assert(lCurrentState <> ATarget, 'Redundant state transition: ' + lCurrentState.AsString);
  if lCurrentState = ATarget then
  begin
    DoDebugLog('Warning: Redundant state transition attempted: ' + lCurrentState.AsString);
    Exit;
  end;

  // 2. Validate Transition Feasibility
  if not IsValidTransition(lCurrentState, ATarget) then
    ETaurusTLSSocketStateError.RaiseWithMessageFmt(
      'Unable to transit Socket ''%s''''s state from ''%s'' to ''%s''.',
      [ClassName, lCurrentState.AsString, ATarget.AsString]);

  // 3. Execute Transition-Specific Initialization or Cleanup
  case ATarget of
    seInitialized:
      // Transitioning from seIdle to seInitialized: Allocate session and arm callbacks
      InitSSL;

    seClosed, seError:
      // Safety Cleanup: If the socket is currently armed or active, release OpenSSL
      // session resources and tear down the physical OS network socket.
      if lCurrentState in [seInitialized, seHandshaking, seEstablished, seClosing] then
      begin
        ReleaseSSL;
        ClosePhysicalSocket; // Force-closes the underlying OS descriptor immediately
      end;
  end;

  // 4. Commit the new state enum
  DoSetState(ATarget);
end;

procedure TTaurusTLSBaseSocket.CheckActiveState(AExpectedState: TTaurusTLSSslState);
begin
  if FState <> AExpectedState then
    ETaurusTLSSocketStateError.RaiseWithMessageFmt(
      'Invalid socket operation in the ''%s'' state.', [AExpectedState.AsString]);
end;

procedure TTaurusTLSBaseSocket.Connect(const pHandle: TIdStackSocketHandle);
begin
  FSocketHandle := pHandle;
  TransitionTo(seInitialized);
  LinkSocket; // Binds the physical socket descriptor to OpenSSL
  TransitionTo(seHandshaking);
  ProcessSSL; // Starts DoHandshake loop
end;

procedure TTaurusTLSBaseSocket.ProcessSSL;
begin
  case FState of
    seHandshaking: DoHandshake; // Polymorphic dispatch to Client/Peer
    seClosing:     DoShutdown;  // Standard unified SSL_shutdown loop
  else
    ETaurusTLSSocketStateError.RaiseWithMessageFmt(
      'Invalid TLS Socket state ''%s'' for negotiation.', [FState.AsString]);
  end;
end;

function TTaurusTLSBaseSocket.GetSSLError(ALastResult: Integer): Integer;
begin
  if Assigned(FSSL) then
  begin
    ERR_clear_error; // Clear error queue to prevent stale reads
    Result := SSL_get_error(FSSL, ALastResult);
  end
  else
    Result := SSL_ERROR_SYSCALL;
end;

procedure TTaurusTLSBaseSocket.Shutdown;
begin
  try
    if FState = seEstablished then
    begin
      TransitionTo(seClosing);
      ProcessSSL;
    end;
  except
    on E: Exception do
    begin
      TransitionTo(seClosed); // Intercept and force immediate closed state teardown
    end;
  end;
end;
~~~

---

## 4. Concrete Handshake Workflows & Direct I/O

### 4.1. Handshake Loop (`TTaurusTLSClientSocket` and `TTaurusTLSPeerSocket`)
The handshake process executes within a dedicated `try..except` block. If `SSL_connect` or `SSL_accept` raises an exception (or triggers a fatal protocol error), the handler transitions the socket to `seError` (or `seClosed` if ECH retry is expected) *prior* to bubbling the exception, preventing uncompleted handshake shutdown errors.

```pascal
procedure TTaurusTLSClientSocket.DoHandshake;
var
  lRet, lErr: Integer;
  lStatus: TIdC_INT;
  lInner, lOuter: PIdAnsiChar;
  lECHConfigBuf: PByte;
  lECHConfigLen: NativeUInt;
  lNewConfigBase64: String;
  lConfig: TaurusTLSClientSocketConfig;
begin
  lConfig:=ClientConfig;
  try
    repeat
      ERR_clear_error;
      lRet := SSL_connect(SSL);

      if lRet = 1 then
      begin
        // Verify ECH status prior to accepting handshake success
        if lConfig.ECHEnabled and (lConfig.ECHConfigList <> '') then
        begin
          lStatus := SSL_ech_get1_status(SSL, @lInner, @lOuter);
          
          if lStatus = SSL_ECH_STATUS_GREASE_ECH then
          begin
            SetECHStatus(echCliFailed);
            lECHConfigBuf := nil;
            lECHConfigLen := 0;

            if SSL_ech_get1_retry_config(SSL, @lECHConfigBuf, @lECHConfigLen) = 1 then
            begin
              try
                if (lECHConfigBuf <> nil) and (lECHConfigLen > 0) then
                begin
                  lNewConfigBase64 := EncodeConfigList(lECHConfigBuf, lECHConfigLen);
                  TransitionTo(seClosed); // Safely close and tear down SSL session
                  ETaurusTLSECHRetryRequired.RaiseWithMessage(
                    'ECH Handshake error. Try to reconnect with updated ECH Config List.',
                    lNewConfigBase64
                  );
                end;
              finally
                OPENSSL_free(lECHConfigBuf);
              end;
            end;
            
            TransitionTo(seClosed);
            ETaurusTLSECHRejectedError.RaiseWithMessage(
              'ECH Handshake failed. The server rejected the key and provided no retry configuration.'
            );
          end
          else if lStatus = SSL_ECH_STATUS_FAILED then
          begin
            TransitionTo(seError);
            ETaurusTLSECHDowngradeError.RaiseWithMessage(
              'ECH Handshake failed due to a protocol or decryption error.'
            );
          end;
        end;

        // Perform security level check via snapshot event
        if not lConfig.DoOnSecurityLevel then
        begin
          TransitionTo(seError);
          Exit;
        end;
        
        TransitionTo(seEstablished);
        
        if lConfig.ECHEnabled then
        begin
          // Update the status for successful connections
          lStatus := SSL_ech_get1_status(SSL, @lInner, @lOuter);
          if lStatus = SSL_ECH_STATUS_SUCCESS then
            SetECHStatus(echCliSuccess)
          else
            SetECHStatus(echCliNone);
        end;

        lConfig.DoOnSSLNegotiated;
        Exit;
      end;

      lErr := SSL_get_error(SSL, lRet);
      case lErr of
        SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE:
          IndySelect(Self, lErr); // Synchronous block using Indy Select
        SSL_ERROR_SYSCALL:
          begin
            TransitionTo(seClosed); // Triggers immediate teardown
            raise ETaurusTLSConnectionReset.Create('Handshake reset by peer.');
          end;
        else
          begin
            TransitionTo(seError);
            raise ETaurusTLSHandshakeError.Create('Fatal handshake error.');
          end;
      end;
    until False;
  except
    on E: Exception do
    begin
      if (State = seHandshaking) then
        TransitionTo(seError); // Safely aborts, preventing illegal "shutdown while in init"
      raise;
    end;
  end;
end;

procedure TTaurusTLSPeerSocket.DoHandshake;
var
  LRet, LErr: Integer;
begin
  try
    repeat
      ERR_clear_error;
      LRet := SSL_accept(SSL);

      if LRet = 1 then
      begin
        // Perform security level check via snapshot event
        if not Config.DoOnSecurityLevel then
        begin
          TransitionTo(seError);
          Exit;
        end;
        
        TransitionTo(seEstablished);
        Exit;
      end;

      LErr := SSL_get_error(SSL, LRet);
      case LErr of
        SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE:
          IndySelect(Self, LErr); // Synchronous block using Indy Select
        SSL_ERROR_SYSCALL:
          begin
            TransitionTo(seClosed); // Triggers immediate teardown
            raise ETaurusTLSConnectionReset.Create('Handshake reset by peer.');
          end;
        else
          begin
            TransitionTo(seError);
            raise ETaurusTLSHandshakeError.Create('Fatal handshake error.');
          end;
      end;
    until False;
  except
    on E: Exception do
    begin
      if (State = seHandshaking) then
        TransitionTo(seError); // Safely aborts, preventing illegal "shutdown while in init"
      raise;
    end;
  end;
end;
```

### 4.2. Direct, High-Performance I/O (`Recv` and `Send`)
These methods bypass all state action classes, checking the `FState` directly in-memory to prevent virtual redirect overhead on critical paths.

```pascal
function TTaurusTLSBaseSocket.Recv(var ABuffer: TIdBytes): TIdC_SIZET;
var
  lLen, lRet, lErr, lQErr: Integer;
  lSSL: PSSL;
begin
  Result := 0;
  lLen := Length(ABuffer);

  if lLen = 0 then
    Exit;
  
  CheckActiveState(seEstablished); // Inlined security guard

  lSSL := FSSL;
  repeat
    // MUST clear the error queue before the I/O operation
    ERR_clear_error; 
    
    lRet := SSL_read_ex(lSSL, ABuffer[0], lLen, Result);
    if lRet = 1 then
      Exit
    else
    begin
      lErr := SSL_get_error(lSSL, lRet);
      case lErr of
        SSL_ERROR_ZERO_RETURN:
          begin
            // Peer sent close_notify. Safe, graceful shutdown.
            TransitionTo(seClosed);
            Exit(0); // Return 0 to let Indy handle graceful close natively
          end;
          
        SSL_ERROR_SSL:
          begin
            // Read the specific error from the queue
            lQErr := ERR_get_error;
            if (ERR_GET_LIB(lQErr) = ERR_LIB_SSL) and 
               (ERR_GET_REASON(lQErr) = SSL_R_UNEXPECTED_EOF_WHILE_READING) then
            begin
              // Treat unexpected EOF as graceful close for web/Indy compatibility
              TransitionTo(seClosed);
              Exit(0); // Return 0 to let Indy handle unexpected EOF gracefully
            end
            else
            begin
              TransitionTo(seError);
              ETaurusTLSIOError.RaiseWithMessage('Fatal SSL protocol error during read.');
            end;
          end;
          
        SSL_ERROR_SYSCALL:
          begin
            TransitionTo(seClosed); // Force-close immediate teardown on TCP RST
            CheckForError(lRet);
            ETaurusTLSConnectionReset.RaiseWithMessage('Connection reset by peer during read.');
          end;
        else
          begin
            TransitionTo(seError);
            raise ETaurusTLSIOError.Create('Fatal read error.');
          end;
      end;
    end;
  until False;
end;

function TTaurusTLSBaseSocket.Send(const ABuffer: TIdBytes; const AOffset,
  ALength: TIdC_SIZET): TIdC_SIZET;
var
  lRet, lErr: TIdC_INT;
begin
  if (ALength = 0) or (Length(ABuffer) = 0) then
    Exit(0);
  
  CheckActiveState(seEstablished); // Inlined security guard

  // MUST clear the error queue before the I/O operation
  ERR_clear_error; 
  
  lRet := SSL_write_ex(FSSL, ABuffer[AOffset], ALength, Result);
  if lRet = 1 then
    Exit
  else
  begin
    lErr := SSL_get_error(FSSL, lRet);
    case lErr of
      SSL_ERROR_SYSCALL:
        begin
          TransitionTo(seClosed); // Force-close immediate teardown on TCP RST
          CheckForError(lRet);
          ETaurusTLSConnectionReset.RaiseWithMessage('Connection reset by peer during write.');
        end;
      else
        begin
          TransitionTo(seError);
          ETaurusTLSIOError.RaiseWithMessage('Fatal write error.');
        end;
    end;
  end;
end;
```

### 4.3. Closing Connection (`DoShutdown`)
Processes bidirectional closing of the TLS session with explicit try..except masking.

```pascal
procedure TTaurusTLSBaseSocket.DoShutdown;
var
  LRet: Integer;
begin
  try
    try
      ERR_clear_error;
      LRet := SSL_shutdown(FSSL);

      // 1. Handle C-Style OpenSSL Failures
      if LRet < 0 then
      begin
        TransitionTo(seClosed);
        Exit;
      end;

      if LRet = 0 then
      begin
        // Sent close_notify successfully.
        // In blocking mode, calling SSL_shutdown a second time will block
        // synchronously until the peer's close_notify is read or a socket timeout/error occurs.
        ERR_clear_error;
        SSL_shutdown(FSSL);
      end;

      TransitionTo(seClosed);
    except
      on E: Exception do
      begin
        // 2. Handle Physical Transport Exceptions
        TransitionTo(seClosed);
      end;
    end;
  finally
    ERR_clear_error; // Guarantees the thread's error queue is clean upon exit
  end;
end;
```

---

## 5. Callbacks & Bridge Execution
Static or non-member `cdecl` functions handle the low-level OpenSSL callbacks. They safely bridge to the active socket context and read from the frozen snapshot properties and event handlers:

```pascal
class procedure TTaurusTLSBaseSocket.SslInfoCallback(const ASSL: PSSL; AWhere,
  ARet: TIdC_INT);
var
  lInstance: TTaurusTLSBaseSocket;
  lConfig: TTaurusTLSCustomSocketConfig;
begin
  if not Assigned(ASSL) then
    Exit;
  try
    lInstance := GetInstanceFromSSL<TTaurusTLSBaseSocket>(ASSL);
    if not Assigned(lInstance) then
      Exit;

    lConfig := lInstance.Config;
    if Assigned(lConfig) then
      lConfig.DoOnStatusInfo(AWhere, ARet);
  except
    // We must not raise exception to the OpenSSL stack
  end;
end;

class function TTaurusTLSBaseSocket.SSLVerifyCallback(APreVerify: LongBool;
  ACtx: PX509_STORE_CTX): TIdC_INT;
var
  lInstance: TTaurusTLSBaseSocket;
  lConfig: TTaurusTLSCustomSocketConfig;
  lSSL: PSSL;
begin
  if not Assigned(ACtx) then
    Exit(0);

  Result := TIdC_INT(APreVerify);
  try
    lSSL := X509_STORE_CTX_get_ex_data(ACtx, SSL_get_ex_data_X509_STORE_CTX_idx());
    if not Assigned(lSSL) then
      Exit;

    lInstance := GetInstanceFromSSL<TTaurusTLSBaseSocket>(lSSL);
    lConfig := lInstance.Config;
    if Assigned(lConfig) then
      lConfig.DoOnVerifyCertificate(APreVerify, ACtx);
  except
    // We must not raise exception to the OpenSSL stack
  end;
end;
```

---

## 6. Client Session Resumption Implementation
Explicit session resumption is isolated within `TTaurusTLSClientSocket`.

```pascal
procedure TTaurusTLSClientSocket.Connect(const pHandle: TIdStackSocketHandle);
begin
  inherited Connect(pHandle); // Base moves state to seInitialized and calls LinkSocket
  SetupConnection; // Handles ECH configs, SNI mappings, and hostname verify settings
  
  if Assigned(ClientConfig.SessionToResume) then
    SSL_set_session(SSL, ClientConfig.SessionToResume)
  else
    ClientConfig.CloneSession(SSL);
    
  TransitionTo(seHandshaking);
  ProcessSSL;
end;
```

---

## 7. Platform Safety (Initialization)
To support the state machine and prevent OS-level process termination:
*   **Unix/Linux Platforms**: `signal(SIGPIPE, SIG_IGN);` must be invoked during TaurusTLS library startup.
*   **OpenSSL Handshake Optimization**: `SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);` is enabled to automatically process non-application data records without dropping out of `SSL_read` where appropriate.

---

## 8. Shutdown Sequence
1.  **seEstablished -> seClosing**: The SSM invokes `SSL_shutdown` inside `Shutdown` via `ProcessSSL`.
2.  **Bi-directional Check**: If `SSL_shutdown` returns 0, the SSM waits for the peer's `CloseNotify` (using a short timeout) before transitioning to `seClosed`.
3.  **RST Protection**: If the peer sends a TCP RST during shutdown, the SSM catches the syscall error, immediately transitions to `seClosed` (which frees `PSSL`), and suppresses the transport exception to ensure a clean application shutdown.

---

## 9. State-Specific Exception Mapping

The following table explicitly maps the exact exceptions that are allowed to be raised during each logical state of the connection lifecycle:

| **Logical State** | **Allowed Exceptions** | **Triggering Cause** |
| :--- | :--- | :--- |
| **`seIdle`** / **`seInitialized`** | `ETaurusTLSBioCreateError` | OpenSSL failed to allocate Memory/BIO buffers. |
| | `ETaurusTLSCreatingSessionError` | `SSL_new` failed to instantiate the connection handle. |
| | `ETaurusTLSDataBindingError` | Failed to bind application data to the session. |
| | `ETaurusTLSFDSetError` | Socket descriptor registration failed. |
| **`seHandshaking`** | `ETaurusTLSECHRetryRequired` | ECH key rejected; server returned a valid `retry_config`. |
| | `ETaurusTLSECHRejectedError` | ECH key rejected; server provided NO retry configuration. |
| | `ETaurusTLSECHProtocolError` | ECH failed due to protocol violation or downgrade detection. |
| | `ETaurusTLSECHDowngradeError` | ECH requested but not negotiated (extension stripped). |
| | `ETaurusTLSHandshakeError` | General OpenSSL handshake failure (e.g., protocol version mismatch). |
| | `ETaurusTLSSecurityError` | Handshake completed, but connection rejected by `OnSecurityLevel`. |
| | `ETaurusTLSConnectionReset` | Physical TCP RST occurred during handshake. |
| | `EIdConnClosedGracefully` | Connection dropped during handshake. |
| **`seEstablished`** | `ETaurusTLSIOError` | General read/write socket failure. |
| | `ETaurusTLSConnectionReset` | Physical TCP RST occurred during active read/write. |
| | `EIdConnClosedGracefully` | Peer closed connection gracefully (received EOF during read). |
| | `ETaurusTLSCertValidationError` | Fired if a TLS 1.3 Post-Handshake certificate update fails validation. |
| **`seClosing`** / **`seClosed`** | `ETaurusTLSDisconnectError` | Bidirectional close failed to receive peer's `CloseNotify` before timeout. |
| **`seError`** | `ETaurusTLSStateError` | Fired if any standard read/write/shutdown operation is called while the machine is in the error state. |
