# Detailed Design Document: TaurusTLS "Socket State Machine" (v5.1)

## 1. Data Structures & Types

### 1.1. State Enumeration & Callbacks
```pascal
type
  TTaurusTLSSslState = (seIdle, seInitialized, seHandshaking, seEstablished, seClosing, seClosed, seError);

  TOnTaurusTLSStateChange = procedure(Sender: TObject; AOldState, ANewState: TTaurusTLSSslState) of object;
```

### 1.2. Polymorphic Handshake Configuration Class Hierarchy
These classes capture and freeze the properties and event handlers of the parent `TIdSSLIOHandlerSocketBase` immediately prior to the handshake, preventing multi-threaded data races. 

The abstract base class manages the lifecycle of the shared `SSL_CTX` by incrementing its reference count via `SSL_CTX_up_ref` upon creation and decrementing it via `SSL_CTX_free` upon destruction.

```pascal
type
  /// <summary>
  ///   Abstract base capturing shared connection parameters, common callback events,
  ///   and managing the lifetime of the underlying SSL_CTX.
  /// </summary>
  TTaurusTLSCustomSocketConfig = class abstract
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSender: TObject;
    FContext: PSSL_CTX;
    FOnStatusInfo: TOnStatusEvent;
    FOnStateChange: TOnTaurusTLSStateChange;
    FOnDebugMessage: TOnDebugMessageEvent;
    FOnVerifyCallback: TOnVerifyCallbackEvent;
    FOnVerifyError: TOnVerifyErrorEvent;
    FOnSecurityLevel: TOnSecurityLevelEvent;
  public
    constructor Create(AIOHandler: TIdSSLIOHandlerSocketBase; ACTX: PSSL_CTX); virtual;
    destructor Destroy; override;
    
    property Sender: TObject read FSender;
    property Context: PSSL_CTX read FContext;
    
    property OnStatusInfo: TOnStatusEvent read FOnStatusInfo;
    property OnStateChange: TOnTaurusTLSStateChange read FOnStateChange;
    property OnDebugMessage: TOnDebugMessageEvent read FOnDebugMessage;
    property OnVerifyCallback: TOnVerifyCallbackEvent read FOnVerifyCallback;
    property OnVerifyError: TOnVerifyErrorEvent read FOnVerifyError;
    property OnSecurityLevel: TOnSecurityLevelEvent read FOnSecurityLevel;
  end;

  /// <summary>
  ///   Captures client-specific connection settings such as SNI, ECH, and hostname verification.
  /// </summary>
  TTaurusTLSClientSocketConfig = class(TTaurusTLSCustomSocketConfig)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FECHEnabled: Boolean;
    FECHConfigList: String;
    FECHOuterHostname: String;
    FDefaultSNI: String;
    FHostName: String;
    FVerifyHostname: Boolean;
    FOnSSLNegotiated: TOnIOHandlerNotify;
  public
    constructor Create(AIOHandler: TIdSSLIOHandlerSocketBase; ACTX: PSSL_CTX); override;
    
    property ECHEnabled: Boolean read FECHEnabled;
    property ECHConfigList: String read FECHConfigList;
    property ECHOuterHostname: String read FECHOuterHostname;
    property DefaultSNI: String read FDefaultSNI;
    property HostName: String read FHostName;
    property VerifyHostname: Boolean read FVerifyHostname;
    property OnSSLNegotiated: TOnIOHandlerNotify read FOnSSLNegotiated;
  end;

  /// <summary>
  ///   Captures server-side client connection context such as client certificate verification mode.
  /// </summary>
  TTaurusTLSPeerSocketConfig = class(TTaurusTLSCustomSocketConfig)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FVerifyClientMode: TIdSSLVerifyMode;
    FALPNPreferences: String;
  public
    constructor Create(AIOHandler: TIdSSLIOHandlerSocketBase; ACTX: PSSL_CTX); override;
    
    property VerifyClientMode: TIdSSLVerifyMode read FVerifyClientMode;
    property ALPNPreferences: String read FALPNPreferences;
  end;
```

### 1.3. The Abstract Context Class
`TTaurusTLSBaseSocket` serves as the state context. It holds a reference to the abstract `TTaurusTLSCustomSocketConfig` and delegates all operational calls to the active state-specific behavioral handler object.

```pascal
type
  TTaurusTLSSslStateHandler = class; // Forward declaration

  TTaurusTLSBaseSocket = class abstract
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSSL: PSSL;
    FStateEnum: TTaurusTLSSslState;
    FCurrentState: TTaurusTLSSslStateHandler;
    FConfig: TTaurusTLSCustomSocketConfig;
    FClosedHandler: TTaurusTLSSslStateHandler;
    FErrorHandler: TTaurusTLSSslStateHandler;
    function IsValidTransition(ACurrent, ATarget: TTaurusTLSSslState): Boolean;
    procedure ClosePhysicalSocket;
  public
    constructor Create(AConfig: TTaurusTLSCustomSocketConfig); virtual;
    destructor Destroy; override;
    procedure TransitionTo(ATargetState: TTaurusTLSSslState);
    
    // Delegated Operations
    procedure Connect; virtual; abstract;
    procedure ProcessSSL; inline;
    function Recv(var Buf; Size: Integer): Integer; inline;
    function Send(const Buf; Size: Integer): Integer; inline;
    function Readable(AMSec: Integer): Boolean; virtual; abstract;
    procedure Shutdown; inline;
    
    property SSL: PSSL read FSSL;
    property StateEnum: TTaurusTLSSslState read FStateEnum;
    property Config: TTaurusTLSCustomSocketConfig read FConfig;
  end;
```

### 1.4. Specialized Descendant Classes
Specialized context classes implement client-specific and peer-specific setups. Descendants retrieve their appropriate concrete configuration safely via type-safe internal getters.

```pascal
type
  TTaurusTLSClientSocket = class(TTaurusTLSBaseSocket)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSessionToResume: PSSL_SESSION;
    FSourceSSLForCopy: PSSL;
    function GetClientConfig: TTaurusTLSClientSocketConfig; {$IFDEF USE_INLINE}inline;{$ENDIF}
  protected
    property ClientConfig: TTaurusTLSClientSocketConfig read GetClientConfig;
    procedure SetupConnection;
  public
    constructor Create(AConfig: TTaurusTLSClientSocketConfig; 
      ASessionToResume: PSSL_SESSION = nil; ASourceSSLForCopy: PSSL = nil); reintroduce;
    procedure Connect; override;
    function Readable(AMSec: Integer): Boolean; override;
  end;

  TTaurusTLSPeerSocket = class(TTaurusTLSBaseSocket)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    function GetPeerConfig: TTaurusTLSPeerSocketConfig; {$IFDEF USE_INLINE}inline;{$ENDIF}
  protected
    property PeerConfig: TTaurusTLSPeerSocketConfig read GetPeerConfig;
  public
    constructor Create(AConfig: TTaurusTLSPeerSocketConfig); reintroduce;
    procedure Connect; override;
    function Readable(AMSec: Integer): Boolean; override;
  end;

  /// <summary>
  ///   Abstract base state action class. Concrete descendants override these virtual methods
  ///   to execute state-specific protocols.
  /// </summary>
  TTaurusTLSSslStateHandler = class abstract
  public
    procedure ProcessSSL(ASocket: TTaurusTLSBaseSocket); virtual; abstract;
    function Recv(ASocket: TTaurusTLSBaseSocket; var Buf; Size: Integer): Integer; virtual; abstract;
    function Send(ASocket: TTaurusTLSBaseSocket; const Buf; Size: Integer): Integer; virtual; abstract;
    function Readable(ASocket: TTaurusTLSBaseSocket; AMSec: Integer): Boolean; virtual; abstract;
    procedure Shutdown(ASocket: TTaurusTLSBaseSocket); virtual; abstract;
  end;
```

---

## 2. Indy Wrapper Integration (`TTaurusTLSIOHandlerSocket`)

This skeleton shows how the high-level Indy component implements the secure I/O pipeline, delegates execution directly to the internal state machine, and implements the required factory methods.

```pascal
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
  LClientConfig: TTaurusTLSClientSocketConfig;
  LPeerConfig: TTaurusTLSPeerSocketConfig;
begin
  if not Assigned(FSSLSocket) then
  begin
    if IsPeer then
    begin
      LPeerConfig := TTaurusTLSPeerSocketConfig.Create(Self, FSSLContext);
      FSSLSocket := TTaurusTLSPeerSocket.Create(LPeerConfig);
    end
    else
    begin
      LClientConfig := TTaurusTLSClientSocketConfig.Create(Self, FSSLContext);
      FSSLSocket := TTaurusTLSClientSocket.Create(LClientConfig);
    end;
      
    FSSLSocket.Connect; // Initiates the handshake loop (seIdle -> seInitialized -> seHandshaking)
  end;
end;

function TTaurusTLSIOHandlerSocket.RecvEnc(var VBuffer: TIdBytes): Integer;
begin
  if Assigned(FSSLSocket) and (FSSLSocket.StateEnum = seEstablished) then
  begin
    Result := FSSLSocket.Recv(VBuffer[0], Length(VBuffer));
  end;
end;

function TTaurusTLSIOHandlerSocket.SendEnc(const ABuffer: TIdBytes; const AOffset, ALength: Integer): Integer;
begin
  if Assigned(FSSLSocket) and (FSSLSocket.StateEnum = seEstablished) then
  begin
    Result := FSSLSocket.Send(ABuffer[AOffset], ALength);
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
  if Assigned(FSSLSocket) then
  begin
    Exit(FSSLSocket.Readable(AMSec));
  end;
  Result := inherited Readable(AMSec);
end;
```

---

## 3. Centralized State Guard & Transition Factory

The Context (`TTaurusTLSBaseSocket`) enforces state-transition validity, manages the lifetime of `TTaurusTLSCustomSocketConfig`, and acts as the factory for state object instantiation.

To provide a strong exception guarantee (transactional commit-or-rollback) under memory pressure, the base class pre-allocates the terminal handlers (`FClosedHandler`, `FErrorHandler`) upon creation.

```pascal
constructor TTaurusTLSBaseSocket.Create(AConfig: TTaurusTLSCustomSocketConfig);
begin
  inherited Create;
  FConfig := AConfig; // Take ownership of the Config
  FSSL := nil;
  FStateEnum := seIdle;
  
  // Pre-allocate terminal state handlers to ensure transition safety under OOM conditions
  FClosedHandler := TTaurusTLSSslStateHandlerClosed.Create;
  FErrorHandler := TTaurusTLSSslStateHandlerError.Create;
  
  FCurrentState := TTaurusTLSSslStateHandlerIdle.Create;
end;

destructor TTaurusTLSBaseSocket.Destroy;
begin
  // Prevent double-freeing if FCurrentState references a pre-allocated terminal handler
  if (FCurrentState = FClosedHandler) or (FCurrentState = FErrorHandler) then
    FCurrentState := nil;
    
  FreeAndNil(FCurrentState);
  if Assigned(FSSL) then
  begin
    // Break the association so callbacks do not map back to this instance during SSL_free
    SSL_set_app_data(FSSL, nil); 
    SSL_free(FSSL);
    FSSL := nil;
  end;
  
  FreeAndNil(FClosedHandler);
  FreeAndNil(FErrorHandler);
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

procedure TTaurusTLSBaseSocket.TransitionTo(ATargetState: TTaurusTLSSslState);
var
  LOldState: TTaurusTLSSslState;
  LNewStateObj: TTaurusTLSSslStateHandler;
begin
  // 1. Redundant Transition Guard (Fails fast in Debug, exits silently in Release)
  if FStateEnum = ATargetState then
  begin
    if Assigned(FConfig) and Assigned(FConfig.OnDebugMessage) then
      FConfig.OnDebugMessage(FConfig.Sender, 'Warning: Redundant state transition attempted: ' + Ord(FStateEnum).ToString);
    Assert(False, 'Redundant state transition detected: ' + Ord(FStateEnum).ToString);
    Exit;
  end;

  if not IsValidTransition(FStateEnum, ATargetState) then
    raise ETaurusTLSInvalidTransition.CreateFmt('Invalid transition: %d -> %d', [Ord(FStateEnum), Ord(ATargetState)]);

  // 2. Transactional State Allocation (Commit-or-Rollback)
  // We allocate the new state handler first. If this raises an EOutOfMemory,
  // we exit the method cleanly, preserving the old handler and current state intact.
  LNewStateObj := nil;
  case ATargetState of
    seIdle:          LNewStateObj := TTaurusTLSSslStateHandlerIdle.Create;
    seInitialized:   LNewStateObj := TTaurusTLSSslStateHandlerInitialized.Create;
    seHandshaking:   LNewStateObj := TTaurusTLSSslStateHandlerHandshaking.Create;
    seEstablished:   LNewStateObj := TTaurusTLSSslStateHandlerEstablished.Create;
    seClosing:       LNewStateObj := TTaurusTLSSslStateHandlerClosing.Create;
    seClosed:        LNewStateObj := FClosedHandler; // Pre-allocated (No allocation)
    seError:         LNewStateObj := FErrorHandler;  // Pre-allocated (No allocation)
  end;

  // 3. State Mutation (Point of No Return)
  LOldState := FStateEnum;

  // Immediate TCP RST Teardown (avoids post-handshake write crashes)
  if (ATargetState = seClosed) and (LOldState in [seHandshaking, seEstablished]) then
  begin
    if Assigned(FSSL) then
    begin
      SSL_set_app_data(FSSL, nil); // Safely unbind app data
      SSL_free(FSSL); // Free context immediately, bypassing SSL_shutdown
      FSSL := nil;
    end;
    ClosePhysicalSocket; // Force-close the physical OS descriptor immediately
  end;

  // Free current state only if it is not one of our shared pre-allocated handlers
  if (FCurrentState <> nil) and (FCurrentState <> FClosedHandler) and (FCurrentState <> FErrorHandler) then
  begin
    FreeAndNil(FCurrentState);
  end
  else
  begin
    FCurrentState := nil;
  end;

  FCurrentState := LNewStateObj;
  FStateEnum := ATargetState;

  // Fire state change event safely from the configuration snapshot
  if Assigned(FConfig) and Assigned(FConfig.OnStateChange) then
    FConfig.OnStateChange(FConfig.Sender, LOldState, ATargetState);
end;

procedure TTaurusTLSBaseSocket.ProcessSSL;
begin
  FCurrentState.ProcessSSL(Self);
end;

function TTaurusTLSBaseSocket.Recv(var Buf; Size: Integer): Integer;
begin
  Result := FCurrentState.Recv(Self, Buf, Size);
end;

function TTaurusTLSBaseSocket.Send(const Buf; Size: Integer): Integer;
begin
  Result := FCurrentState.Send(Self, Buf, Size);
end;

procedure TTaurusTLSBaseSocket.Shutdown;
begin
  try
    FCurrentState.Shutdown(Self);
  except
    on E: Exception do
    begin
      TransitionTo(seClosed); // Intercept and force immediate closed state teardown
    end;
  end;
end;
```

---

## 4. Concrete State Implementation Workflows

### 4.1. Handshake Loop (`TTaurusTLSSslStateHandlerHandshaking`)
The handshake process executes within a dedicated `try..except` block. If `SSL_connect` or `SSL_accept` raises an exception (or triggers a fatal protocol error), the handler transitions the socket to `seError` (or `seClosed` if ECH retry is expected) *prior* to bubbling the exception, preventing uncompleted handshake shutdown errors.

```pascal
procedure TTaurusTLSSslStateHandlerHandshaking.ProcessSSL(ASocket: TTaurusTLSBaseSocket);
var
  LRet, LErr: Integer;
  LSecurityAccept: Boolean;
  LStatus: TIdC_INT;
  LInner, LOuter: PIdAnsiChar;
  LECHConfigBuf: PByte;
  LECHConfigLen: NativeUInt;
  LNewConfigBase64: String;
  LClientIO: TTaurusTLSIOHandlerSocket;
begin
  LClientIO := nil;
  if ASocket.Config.Sender is TTaurusTLSIOHandlerSocket then
    LClientIO := TTaurusTLSIOHandlerSocket(ASocket.Config.Sender);

  try
    repeat
      if ASocket is TTaurusTLSClientSocket then
        LRet := SSL_connect(ASocket.SSL)
      else
        LRet := SSL_accept(ASocket.SSL);

      if LRet = 1 then
      begin
        // Verify ECH status prior to accepting handshake success
        if Assigned(LClientIO) and LClientIO.ECHEnabled and (LClientIO.ECHConfigList <> '') then
        begin
          LStatus := SSL_ech_get1_status(ASocket.SSL, @LInner, @LOuter);
          
          if LStatus = SSL_ECH_STATUS_GREASE_ECH then
          begin
            LClientIO.SetECHStatus(ech_cli_failed);
            LECHConfigBuf := nil;
            LECHConfigLen := 0;

            if SSL_ech_get1_retry_config(ASocket.SSL, @LECHConfigBuf, @LECHConfigLen) = 1 then
            begin
              try
                if (LECHConfigBuf <> nil) and (LECHConfigLen > 0) then
                begin
                  LNewConfigBase64 := EncodeConfigList(LECHConfigBuf, LECHConfigLen);
                  ASocket.TransitionTo(seClosed); // Safely close and tear down SSL session
                  raise ETaurusTLSECHRetryRequired.Create(
                    'ECH Handshake error. Try to reconnect with updated ECH Config List.',
                    LNewConfigBase64
                  );
                end;
              finally
                OPENSSL_free(LECHConfigBuf);
              end;
            end;
            
            ASocket.TransitionTo(seClosed);
            raise ETaurusTLSECHRejectedError.Create(
              'ECH Handshake failed. The server rejected the key and provided no retry configuration.'
            );
          end
          else if LStatus = SSL_ECH_STATUS_FAILED then
          begin
            ASocket.TransitionTo(seError);
            raise ETaurusTLSECHProtocolError.Create('ECH Handshake failed due to a protocol or decryption error.');
          end;
        end;

        // Perform security level check via snapshot event
        LSecurityAccept := True;
        if Assigned(ASocket.Config) and Assigned(ASocket.Config.OnSecurityLevel) then
          ASocket.Config.OnSecurityLevel(ASocket.Config.Sender, LSecurityAccept);

        if not LSecurityAccept then
        begin
          ASocket.TransitionTo(seError);
          Exit;
        end;
        
        ASocket.TransitionTo(seEstablished);
        
        if Assigned(LClientIO) and LClientIO.ECHEnabled then
        begin
          // Update the status for successful connections
          LStatus := SSL_ech_get1_status(ASocket.SSL, @LInner, @LOuter);
          if LStatus = SSL_ECH_STATUS_SUCCESS then
            LClientIO.SetECHStatus(ech_cli_success)
          else
            LClientIO.SetECHStatus(ech_cli_not_attempted);
        end;

        if Assigned(ASocket.Config) and Assigned(ASocket.Config.OnSSLNegotiated) then
          ASocket.Config.OnSSLNegotiated(ASocket.Config.Sender);
        Exit;
      end;

      LErr := SSL_get_error(ASocket.SSL, LRet);
      case LErr of
        SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE:
          IndySelect(ASocket, LErr); // Synchronous block using Indy Select
        SSL_ERROR_SYSCALL:
          begin
            ASocket.TransitionTo(seClosed); // Triggers immediate teardown
            raise ETaurusTLSConnectionReset.Create('Handshake reset by peer.');
          end;
        else
          begin
            ASocket.TransitionTo(seError);
            raise ETaurusTLSHandshakeError.Create('Fatal handshake error.');
          end;
      end;
    until False;
  except
    on E: Exception do
    begin
      if (ASocket.StateEnum = seHandshaking) then
        ASocket.TransitionTo(seError); // Safely aborts, preventing illegal "shutdown while in init"
      raise;
    end;
  end;
end;
```

### 4.2. Established Connection (`TTaurusTLSSslStateHandlerEstablished`)
```pascal
function TTaurusTLSSslStateHandlerEstablished.Recv(ASocket: TTaurusTLSBaseSocket; var Buf; Size: Integer): Integer;
var
  LRet, LErr: Integer;
  LQueueErr: Cardinal;
begin
  repeat
    // 1. MUST clear the error queue before the I/O operation
    ERR_clear_error; 
    
    LRet := SSL_read(ASocket.SSL, @Buf, Size);
    if LRet <= 0 then
    begin
      LErr := SSL_get_error(ASocket.SSL, LRet);
      case LErr of
        SSL_ERROR_WANT_READ: 
          Continue; // Post-handshake control message, loop again.
          
        SSL_ERROR_ZERO_RETURN:
          begin
            // Peer sent close_notify. Safe, graceful shutdown.
            ASocket.TransitionTo(seClosed);
            raise EIdConnClosedGracefully.Create(RSConClosedGracefully);
          end;
          
        SSL_ERROR_SSL:
          begin
            // Read the specific error from the queue
            LQueueErr := ERR_get_error;
            if (ERR_GET_LIB(LQueueErr) = ERR_LIB_SSL) and 
               (ERR_GET_REASON(LQueueErr) = SSL_R_UNEXPECTED_EOF_WHILE_READING) then
            begin
              // Treat unexpected EOF as graceful close for web/Indy compatibility
              ASocket.TransitionTo(seClosed);
              raise EIdConnClosedGracefully.Create(RSConClosedGracefully);
            end
            else
            begin
              ASocket.TransitionTo(seError);
              raise ETaurusTLSIOError.Create('Fatal SSL protocol error during read.');
            end;
          end;
          
        SSL_ERROR_SYSCALL:
          begin
            ASocket.TransitionTo(seClosed); // Force-close immediate teardown
            raise ETaurusTLSConnectionReset.Create('Connection reset by peer.');
          end;
        else
          begin
            ASocket.TransitionTo(seError);
            raise ETaurusTLSIOError.Create('Fatal read error.');
          end;
      end;
    end
    else
      Exit(LRet);
  until False;
end;

function TTaurusTLSSslStateHandlerEstablished.Send(ASocket: TTaurusTLSBaseSocket; const Buf; Size: Integer): Integer;
var
  LRet, LErr: Integer;
begin
  // 1. MUST clear the error queue before the I/O operation
  ERR_clear_error; 
  
  LRet := SSL_write(ASocket.SSL, @Buf, Size);
  if LRet <= 0 then
  begin
    LErr := SSL_get_error(ASocket.SSL, LRet);
    case LErr of
      SSL_ERROR_SYSCALL:
        begin
          ASocket.TransitionTo(seClosed); // Force-close immediately on RST
          raise ETaurusTLSConnectionReset.Create('Connection reset by peer during write.');
        end;
      else
        begin
          ASocket.TransitionTo(seError);
          raise ETaurusTLSIOError.Create('Fatal write error.');
        end;
    end;
  end
  else
    Result := LRet;
end;
```

### 4.3. Closing Connection (`TTaurusTLSSslStateHandlerClosing`)
Processes bidirectional closing of the TLS session with explicit try..except masking.

```pascal
procedure TTaurusTLSSslStateHandlerClosing.ProcessSSL(ASocket: TTaurusTLSBaseSocket);
var
  LRet, LErr: Integer;
begin
  try
    repeat
      LRet := SSL_shutdown(ASocket.SSL);
      if LRet = 1 then
      begin
        ASocket.TransitionTo(seClosed);
        Exit;
      end
      else if LRet = 0 then
      begin
        // Unidirectional shutdown complete (Sent close_notify, waiting for peer response)
        if ASocket.Readable(500) then // Short timeout to poll for peer response
          Continue
        else
        begin
          ASocket.TransitionTo(seClosed);
          Exit;
        end;
      end;

      LErr := SSL_get_error(ASocket.SSL, LRet);
      case LErr of
        SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE:
          IndySelect(ASocket, LErr);
        else
          begin
            ASocket.TransitionTo(seClosed); // Force-closes immediately on syscall errors
            Exit;
          end;
      end;
    until False;
  except
    on E: Exception do
    begin
      ASocket.TransitionTo(seClosed); // Ensures robust cleanup of underlying SSL handle
    end;
  end;
end;
```

---

## 5. Callbacks & Bridge Execution
Static or non-member `cdecl` functions handle the low-level OpenSSL callbacks. They safely bridge to the active socket context and read from the frozen snapshot properties and event handlers:

```pascal
procedure TaurusTLS_InfoCallback(ssl: PSSL; where: Integer; ret: Integer); cdecl;
var
  LSocket: TTaurusTLSBaseSocket;
begin
  LSocket := TTaurusTLSBaseSocket(SSL_get_app_data(ssl));
  if Assigned(LSocket) and Assigned(LSocket.Config) and Assigned(LSocket.Config.OnStatusInfo) then
  begin
    LSocket.Config.OnStatusInfo(LSocket.Config.Sender, where, ret);
  end;
end;

// Verify callback remains aligned to use the FConfig bridge
```

---

## 6. Client Session Resumption Implementation
Explicit session resumption is isolated within `TTaurusTLSClientSocket`.

```pascal
constructor TTaurusTLSClientSocket.Create(AConfig: TTaurusTLSClientSocketConfig; 
  ASessionToResume: PSSL_SESSION = nil; ASourceSSLForCopy: PSSL = nil);
begin
  inherited Create(AConfig);
  FSessionToResume := ASessionToResume;
  FSourceSSLForCopy := ASourceSSLForCopy;
end;

procedure TTaurusTLSClientSocket.Connect;
begin
  TransitionTo(seInitialized);
  SetupConnection; // Handles ECH configs, SNI mappings, and hostname verify settings
  
  if Assigned(FSessionToResume) then
    SSL_set_session(SSL, FSessionToResume)
  else if Assigned(FSourceSSLForCopy) then
    SSL_copy_session_id(SSL, FSourceSSLForCopy);
    
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
1.  **seEstablished -> seClosing**: The SSM invokes `SSL_shutdown`.
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
