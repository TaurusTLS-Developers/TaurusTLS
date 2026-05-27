# Detailed Design Document: TaurusTLS "Socket State Machine"

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
`TTaurusTLSBaseSocket` serves as the state context. It holds a reference to the abstract `TTaurusTLSCustomSocketConfig` and processes connection states internally using direct, high-performance, enum-driven dispatches.

```pascal
type
  TTaurusTLSBaseSocket = class abstract
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSSL: PSSL;
    FStateEnum: TTaurusTLSSslState;
    FConfig: TTaurusTLSCustomSocketConfig;
    function IsValidTransition(ACurrent, ATarget: TTaurusTLSSslState): Boolean;
    procedure ClosePhysicalSocket;
    procedure DoShutdown;
  protected
    procedure DoHandshake; virtual; abstract;
    procedure CheckActiveState(AExpectedState: TTaurusTLSSslState); {$IFDEF USE_INLINE}inline;{$ENDIF}
  public
    constructor Create(AConfig: TTaurusTLSCustomSocketConfig); virtual;
    destructor Destroy; override;
    procedure TransitionTo(ATargetState: TTaurusTLSSslState);
    
    // Core Socket Operations
    procedure Connect; virtual;
    procedure ProcessSSL;
    function Recv(var Buf; Size: Integer): Integer;
    function Send(const Buf; Size: Integer): Integer;
    function Readable(AMSec: Integer): Boolean; virtual;
    procedure Shutdown;
    function GetSSLError(ALastResult: Integer): Integer;
    
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
    procedure DoHandshake; override;
  public
    constructor Create(AConfig: TTaurusTLSClientSocketConfig; 
      ASessionToResume: PSSL_SESSION = nil; ASourceSSLForCopy: PSSL = nil); reintroduce;
    function Readable(AMSec: Integer): Boolean; override;
  end;

  TTaurusTLSPeerSocket = class(TTaurusTLSBaseSocket)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    function GetPeerConfig: TTaurusTLSPeerSocketConfig; {$IFDEF USE_INLINE}inline;{$ENDIF}
  protected
    property PeerConfig: TTaurusTLSPeerSocketConfig read GetPeerConfig;
    procedure DoHandshake; override;
  public
    constructor Create(AConfig: TTaurusTLSPeerSocketConfig); reintroduce;
    function Readable(AMSec: Integer): Boolean; override;
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
```

---

## 3. Centralized State Guard & Transition Factory

The Context (`TTaurusTLSBaseSocket`) enforces state-transition validity and manages the lifetime of `TTaurusTLSCustomSocketConfig`. State transitions are entirely allocation-free and OOM-immune.

To prevent memory leaks and access violations during teardown, the destructor unbinds `app_data` from the `SSL` handle prior to invocation of `SSL_free`.

```pascal
constructor TTaurusTLSBaseSocket.Create(AConfig: TTaurusTLSCustomSocketConfig);
begin
  inherited Create;
  FConfig := AConfig; // Take ownership of the Config
  FSSL := nil;
  FStateEnum := seIdle;
end;

destructor TTaurusTLSBaseSocket.Destroy;
begin
  if Assigned(FSSL) then
  begin
    // Break the association so callbacks do not map back to this instance during SSL_free
    SSL_set_app_data(FSSL, nil); 
    SSL_free(FSSL);
    FSSL := nil;
  end;
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

  // 2. State Mutation (Point of No Return)
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

  FStateEnum := ATargetState;

  // Fire state change event safely from the configuration snapshot
  if Assigned(FConfig) and Assigned(FConfig.OnStateChange) then
    FConfig.OnStateChange(FConfig.Sender, LOldState, ATargetState);
end;

procedure TTaurusTLSBaseSocket.CheckActiveState(AExpectedState: TTaurusTLSSslState);
begin
  if FStateEnum <> AExpectedState then
    raise ETaurusTLSStateError.Create('Invalid socket operation in current state: ' + Ord(FStateEnum).ToString);
end;

procedure TTaurusTLSBaseSocket.Connect;
begin
  TransitionTo(seInitialized);
end;

procedure TTaurusTLSBaseSocket.ProcessSSL;
begin
  case FStateEnum of
    seHandshaking: DoHandshake; // Polymorphic dispatch to Client/Peer
    seClosing:     DoShutdown;  // Standard unified SSL_shutdown loop
  else
    raise ETaurusTLSStateError.Create('ProcessSSL is not valid in the current state: ' + Ord(FStateEnum).ToString);
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
    if FStateEnum = seEstablished then
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
```

---

## 4. Concrete Handshake Workflows & Direct I/O

### 4.1. Handshake Loop (`TTaurusTLSClientSocket` and `TTaurusTLSPeerSocket`)
The handshake process executes within a dedicated `try..except` block. If `SSL_connect` or `SSL_accept` raises an exception (or triggers a fatal protocol error), the handler transitions the socket to `seError` (or `seClosed` if ECH retry is expected) *prior* to bubbling the exception, preventing uncompleted handshake shutdown errors.

```pascal
procedure TTaurusTLSClientSocket.DoHandshake;
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
  if Config.Sender is TTaurusTLSIOHandlerSocket then
    LClientIO := TTaurusTLSIOHandlerSocket(Config.Sender);

  try
    repeat
      ERR_clear_error;
      LRet := SSL_connect(SSL);

      if LRet = 1 then
      begin
        // Verify ECH status prior to accepting handshake success
        if Assigned(LClientIO) and LClientIO.ECHEnabled and (LClientIO.ECHConfigList <> '') then
        begin
          LStatus := SSL_ech_get1_status(SSL, @LInner, @LOuter);
          
          if LStatus = SSL_ECH_STATUS_GREASE_ECH then
          begin
            LClientIO.SetECHStatus(ech_cli_failed);
            LECHConfigBuf := nil;
            LECHConfigLen := 0;

            if SSL_ech_get1_retry_config(SSL, @LECHConfigBuf, @LECHConfigLen) = 1 then
            begin
              try
                if (LECHConfigBuf <> nil) and (LECHConfigLen > 0) then
                begin
                  LNewConfigBase64 := EncodeConfigList(LECHConfigBuf, LECHConfigLen);
                  TransitionTo(seClosed); // Safely close and tear down SSL session
                  raise ETaurusTLSECHRetryRequired.Create(
                    'ECH Handshake error. Try to reconnect with updated ECH Config List.',
                    LNewConfigBase64
                  );
                end;
              finally
                OPENSSL_free(LECHConfigBuf);
              end;
            end;
            
            TransitionTo(seClosed);
            raise ETaurusTLSECHRejectedError.Create(
              'ECH Handshake failed. The server rejected the key and provided no retry configuration.'
            );
          end
          else if LStatus = SSL_ECH_STATUS_FAILED then
          begin
            TransitionTo(seError);
            raise ETaurusTLSECHProtocolError.Create('ECH Handshake failed due to a protocol or decryption error.');
          end;
        end;

        // Perform security level check via snapshot event
        LSecurityAccept := True;
        if Assigned(Config) and Assigned(Config.OnSecurityLevel) then
          Config.OnSecurityLevel(Config.Sender, LSecurityAccept);

        if not LSecurityAccept then
        begin
          TransitionTo(seError);
          Exit;
        end;
        
        TransitionTo(seEstablished);
        
        if Assigned(LClientIO) and LClientIO.ECHEnabled then
        begin
          // Update the status for successful connections
          LStatus := SSL_ech_get1_status(SSL, @LInner, @LOuter);
          if LStatus = SSL_ECH_STATUS_SUCCESS then
            LClientIO.SetECHStatus(ech_cli_success)
          else
            LClientIO.SetECHStatus(ech_cli_not_attempted);
        end;

        if Assigned(Config) and Assigned(Config.OnSSLNegotiated) then
          Config.OnSSLNegotiated(Config.Sender);
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
      if (StateEnum = seHandshaking) then
        TransitionTo(seError); // Safely aborts, preventing illegal "shutdown while in init"
      raise;
    end;
  end;
end;

procedure TTaurusTLSPeerSocket.DoHandshake;
var
  LRet, LErr: Integer;
  LSecurityAccept: Boolean;
begin
  try
    repeat
      ERR_clear_error;
      LRet := SSL_accept(SSL);

      if LRet = 1 then
      begin
        // Perform security level check via snapshot event
        LSecurityAccept := True;
        if Assigned(Config) and Assigned(Config.OnSecurityLevel) then
          Config.OnSecurityLevel(Config.Sender, LSecurityAccept);

        if not LSecurityAccept then
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
      if (StateEnum = seHandshaking) then
        TransitionTo(seError); // Safely aborts, preventing illegal "shutdown while in init"
      raise;
    end;
  end;
end;
```

### 4.2. Direct, High-Performance I/O (`Recv` and `Send`)
These methods bypass all state action classes, checking the `FStateEnum` directly in-memory to prevent virtual redirect overhead on critical paths.

```pascal
function TTaurusTLSBaseSocket.Recv(var Buf; Size: Integer): Integer;
var
  LRet, LErr: Integer;
  LQueueErr: Cardinal;
begin
  if (Size <= 0) or (@Buf = nil) then Exit(0);
  
  CheckActiveState(seEstablished); // Inlined security guard

  repeat
    // MUST clear the error queue before the I/O operation
    ERR_clear_error; 
    
    LRet := SSL_read(FSSL, @Buf, Size);
    if LRet <= 0 then
    begin
      LErr := SSL_get_error(FSSL, LRet);
      case LErr of
        SSL_ERROR_WANT_READ: 
          Continue; // Post-handshake control message, loop again.
          
        SSL_ERROR_ZERO_RETURN:
          begin
            // Peer sent close_notify. Safe, graceful shutdown.
            TransitionTo(seClosed);
            Exit(0); // Return 0 to let Indy handle graceful close natively
          end;
          
        SSL_ERROR_SSL:
          begin
            // Read the specific error from the queue
            LQueueErr := ERR_get_error;
            if (ERR_GET_LIB(LQueueErr) = ERR_LIB_SSL) and 
               (ERR_GET_REASON(LQueueErr) = SSL_R_UNEXPECTED_EOF_WHILE_READING) then
            begin
              // Treat unexpected EOF as graceful close for web/Indy compatibility
              TransitionTo(seClosed);
              Exit(0); // Return 0 to let Indy handle unexpected EOF natively
            end
            else
            begin
              TransitionTo(seError);
              raise ETaurusTLSIOError.Create('Fatal SSL protocol error during read.');
            end;
          end;
          
        SSL_ERROR_SYSCALL:
          begin
            TransitionTo(seClosed); // Force-close immediate teardown
            
            // Let Indy's GStack query LastError/errno and raise EIdSocketError
            GStack.CheckForSocketError(
              Id_SOCKET_ERROR, 
              [Id_WSAESHUTDOWN, Id_WSAECONNABORTED, Id_WSAECONNRESET, Id_WSAETIMEDOUT]
            );
            
            raise ETaurusTLSConnectionReset.Create('Connection reset by peer.');
          end;
        else
          begin
            TransitionTo(seError);
            raise ETaurusTLSIOError.Create('Fatal read error.');
          end;
      end;
    end
    else
      Exit(LRet);
  until False;
end;

function TTaurusTLSBaseSocket.Send(const Buf; Size: Integer): Integer;
var
  LRet, LErr: Integer;
begin
  if (Size <= 0) or (@Buf = nil) then Exit(0);
  
  CheckActiveState(seEstablished); // Inlined security guard

  // MUST clear the error queue before the I/O operation
  ERR_clear_error; 
  
  LRet := SSL_write(FSSL, @Buf, Size);
  if LRet <= 0 then
  begin
    LErr := SSL_get_error(FSSL, LRet);
    case LErr of
      SSL_ERROR_SYSCALL:
        begin
          TransitionTo(seClosed); // Force-close immediate teardown
          
          // Let Indy's GStack query LastError/errno and raise EIdSocketError
          GStack.CheckForSocketError(
            Id_SOCKET_ERROR, 
            [Id_WSAESHUTDOWN, Id_WSAECONNABORTED, Id_WSAECONNRESET, Id_WSAETIMEDOUT]
          );
          
          raise ETaurusTLSConnectionReset.Create('Connection reset by peer during write.');
        end;
      else
        begin
          TransitionTo(seError);
          raise ETaurusTLSIOError.Create('Fatal write error.');
        end;
    end;
  end
  else
    Result := LRet;
end;
```

### 4.3. Closing Connection (`DoShutdown`)
Processes bidirectional closing of the TLS session with explicit try..except masking.

```pascal
procedure TTaurusTLSBaseSocket.DoShutdown;
var
  LRet, LErr: Integer;
begin
  try
    repeat
      ERR_clear_error;
      LRet := SSL_shutdown(FSSL);
      if LRet = 1 then
      begin
        TransitionTo(seClosed);
        Exit;
      end
      else if LRet = 0 then
      begin
        // Unidirectional shutdown complete (Sent close_notify, waiting for peer response)
        if Readable(500) then // Short timeout to poll for peer response
          Continue
        else
        begin
          TransitionTo(seClosed);
          Exit;
        end;
      end;

      LErr := SSL_get_error(FSSL, LRet);
      case LErr of
        SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE:
          IndySelect(Self, LErr);
        else
          begin
            TransitionTo(seClosed); // Force-closes immediately on syscall errors
            Exit;
          end;
      end;
    until False;
  except
    on E: Exception do
    begin
      TransitionTo(seClosed); // Ensures robust cleanup of underlying SSL handle
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
  inherited Connect; // Base moves state to seInitialized
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
