# Detailed Design Document: TaurusTLS "Socket State Machine"

## 1. Data Structures & Types

### 1.1. State Enumeration
```pascal
type
  TTaurusTLSSslStateEnum = (seIdle, seInitialized, seHandshaking, seEstablished, seClosing, seClosed, seError);

  TOnTaurusTLSStateChange = procedure(Sender: TObject; AOldState, ANewState: TTaurusTLSSslStateEnum) of object;
```

### 1.2. The Handshake Snapshot Class
This class captures and freezes the properties and event handlers, preventing multi-threaded data races. It uses no interfaces, avoiding component lifetime conflicts. It safely increments and decrements the shared `SSL_CTX` reference count.

```pascal
type
  TTaurusTLSHandshakeSnapshot = class
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSender: TObject;
    FContext: PSSL_CTX;
    FECHEnabled: Boolean;
    FECHConfigList: String;
    FECHOuterHostname: String;
    FDefaultSNI: String;
    FHostName: String;
    FVerifyHostname: Boolean;
    
    FOnSSLNegotiated: TOnIOHandlerNotify;
    FOnStatusInfo: TOnStatusEvent;
    FOnStateChange: TOnTaurusTLSStateChange;
    FOnDebugMessage: TOnDebugMessageEvent;
    FOnVerifyCallback: TOnVerifyCallbackEvent;
    FOnVerifyError: TOnVerifyErrorEvent;
    FOnSecurityLevel: TOnSecurityLevelEvent;
  public
    constructor Create(AIOHandler: TIdSSLIOHandlerSocketBase; ACTX: PSSL_CTX);
    destructor Destroy; override;
    
    property Sender: TObject read FSender;
    property Context: PSSL_CTX read FContext;
    property ECHEnabled: Boolean read FECHEnabled;
    property ECHConfigList: String read FECHConfigList;
    property ECHOuterHostname: String read FECHOuterHostname;
    property DefaultSNI: String read FDefaultSNI;
    property HostName: String read FHostName;
    property VerifyHostname: Boolean read FVerifyHostname;
    
    property OnSSLNegotiated: TOnIOHandlerNotify read FOnSSLNegotiated;
    property OnStatusInfo: TOnStatusEvent read FOnStatusInfo;
    property OnStateChange: TOnTaurusTLSStateChange read FOnStateChange;
    property OnDebugMessage: TOnDebugMessageEvent read FOnDebugMessage;
    property OnVerifyCallback: TOnVerifyCallbackEvent read FOnVerifyCallback;
    property OnVerifyError: TOnVerifyErrorEvent read FOnVerifyError;
    property OnSecurityLevel: TOnSecurityLevelEvent read FOnSecurityLevel;
  end;
```

### 1.3. The Abstract Context Class
```pascal
type
  TTaurusTLSSslState = class; // Forward declaration

  TTaurusTLSBaseSocket = class abstract
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSSL: PSSL;
    FStateEnum: TTaurusTLSSslStateEnum;
    FCurrentState: TTaurusTLSSslState;
    FSnapshot: TTaurusTLSHandshakeSnapshot;
    function IsValidTransition(ACurrent, ATarget: TTaurusTLSSslStateEnum): Boolean;
    procedure ClosePhysicalSocket;
  public
    constructor Create(ASnapshot: TTaurusTLSHandshakeSnapshot); virtual;
    destructor Destroy; override;
    procedure TransitionTo(ATargetState: TTaurusTLSSslStateEnum);
    
    // Delegated Operations
    procedure Connect; virtual; abstract;
    procedure Process; inline;
    function Read(var Buf; Size: Integer): Integer; inline;
    function Write(const Buf; Size: Integer): Integer; inline;
    procedure Shutdown; inline;
    
    property SSL: PSSL read FSSL;
    property StateEnum: TTaurusTLSSslStateEnum read FStateEnum;
    property Snapshot: TTaurusTLSHandshakeSnapshot read FSnapshot;
  end;
```

### 1.4. Specialized Descendant Classes
```pascal
type
  TTaurusTLSClientSocket = class(TTaurusTLSBaseSocket)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSessionToResume: PSSL_SESSION;
    FSourceSSLForCopy: PSSL;
  public
    constructor Create(ASnapshot: TTaurusTLSHandshakeSnapshot; 
      ASessionToResume: PSSL_SESSION = nil; ASourceSSLForCopy: PSSL = nil); reintroduce;
    procedure Connect; override;
  end;

  TTaurusTLSPeerSocket = class(TTaurusTLSBaseSocket)
  public
    procedure Connect; override;
  end;

  TTaurusTLSSslState = class abstract
  public
    procedure Connect(ASocket: TTaurusTLSBaseSocket); virtual; abstract;
    procedure Process(ASocket: TTaurusTLSBaseSocket); virtual; abstract;
    function Read(ASocket: TTaurusTLSBaseSocket; var Buf; Size: Integer): Integer; virtual; abstract;
    function Write(ASocket: TTaurusTLSBaseSocket; const Buf; Size: Integer): Integer; virtual; abstract;
    procedure Shutdown(ASocket: TTaurusTLSBaseSocket); virtual; abstract;
  end;
```

## 2. Indy Wrapper Integration (`TTaurusTLSIOHandlerSocket`)

This skeleton shows how the high-level Indy component implements the pipeline, delegates read/write/setup calls directly to the internal state machine, and implements the factory methods.

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
    // If transitioning to secure mid-session (e.g., STARTTLS) and we are already connected
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

  // If PassThrough is false, negotiate SSL immediately
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
  LSnapshot: TTaurusTLSHandshakeSnapshot;
begin
  if not Assigned(FSSLSocket) then
  begin
    // 1. Create the frozen, thread-safe snapshot
    LSnapshot := TTaurusTLSHandshakeSnapshot.Create(Self, FSSLContext);
    
    // 2. Instantiate the polymorphic engine based on Indy's native IsPeer flag
    if IsPeer then
      FSSLSocket := TTaurusTLSPeerSocket.Create(LSnapshot)
    else
      FSSLSocket := TTaurusTLSClientSocket.Create(LSnapshot);
      
    // 3. Initiate the handshake state loop (seIdle -> seInitialized -> seHandshaking)
    FSSLSocket.Connect; 
  end;
end;

function TTaurusTLSIOHandlerSocket.RecvEnc(var VBuffer: TIdBytes): Integer;
begin
  if Assigned(FSSLSocket) and (FSSLSocket.StateEnum = seEstablished) then
  begin
    Result := FSSLSocket.Read(VBuffer[0], Length(VBuffer));
  end;
end;

function TTaurusTLSIOHandlerSocket.SendEnc(const ABuffer: TIdBytes; const AOffset, ALength: Integer): Integer;
begin
  if Assigned(FSSLSocket) and (FSSLSocket.StateEnum = seEstablished) then
  begin
    Result := FSSLSocket.Write(ABuffer[AOffset], ALength);
  end;
end;

procedure TTaurusTLSIOHandlerSocket.Close;
begin
  if Assigned(FSSLSocket) then
  begin
    FSSLSocket.Shutdown; // Moves to seClosing -> seClosed
    FreeAndNil(FSSLSocket);
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
  if Assigned(FSSLSocket) and (FSSLSocket.StateEnum = seEstablished) then
  begin
    // Memory Optimization: If OpenSSL has decrypted bytes pending in its buffer, we are readable.
    // This avoids blocking hangs on the raw OS socket poll.
    if SSL_pending(FSSLSocket.SSL) > 0 then
      Exit(True);
  end;
  Result := inherited Readable(AMSec);
end;
```

## 3. Centralized State Guard & Transition Factory

The Context (`TTaurusTLSBaseSocket`) enforces state-transition validity, manages the lifetime of `TTaurusTLSHandshakeSnapshot`, and acts as the factory for state object instantiation.

```pascal
constructor TTaurusTLSBaseSocket.Create(ASnapshot: TTaurusTLSHandshakeSnapshot);
begin
  inherited Create;
  FSnapshot := ASnapshot; // Take ownership of the snapshot
  FSSL := nil;
  FStateEnum := seIdle;
  FCurrentState := TTaurusTLSSslStateIdle.Create;
end;

destructor TTaurusTLSBaseSocket.Destroy;
begin
  FreeAndNil(FCurrentState);
  if Assigned(FSSL) then
  begin
    SSL_free(FSSL);
    FSSL := nil;
  end;
  FreeAndNil(FSnapshot); // Safely destroy the snapshot class
  inherited Destroy;
end;

function TTaurusTLSBaseSocket.IsValidTransition(ACurrent, ATarget: TTaurusTLSSslStateEnum): Boolean;
begin
  case ACurrent of
    seIdle:          Result := (ATarget = seInitialized);
    seInitialized:   Result := (ATarget = seHandshaking) or (ATarget = seClosed) or (ATarget = seError);
    seHandshaking:   Result := (ATarget = seEstablished) or (ATarget = seClosed) or (ATarget = seError);
    seEstablished:   Result := (ATarget = seClosing) or (ATarget = seClosed) or (ATarget = seError);
    seClosing:       Result := (ATarget = seClosed) or (ATarget = seError);
    seClosed, seError: Result := (ATarget = seIdle);
  else
    Result := False;
  end;
end;

procedure TTaurusTLSBaseSocket.TransitionTo(ATargetState: TTaurusTLSSslStateEnum);
var
  LOldState: TTaurusTLSSslStateEnum;
begin
  if not IsValidTransition(FStateEnum, ATargetState) then
    raise ETaurusTLSInvalidTransition.CreateFmt('Invalid transition: %d -> %d', [Ord(FStateEnum), Ord(ATargetState)]);

  LOldState := FStateEnum;
  FreeAndNil(FCurrentState);

  // Immediate TCP RST Teardown (avoids post-handshake write crashes)
  if (ATargetState = seClosed) and (LOldState in [seHandshaking, seEstablished]) then
  begin
    if Assigned(FSSL) then
    begin
      SSL_free(FSSL); // Free context immediately, bypassing SSL_shutdown
      FSSL := nil;
    end;
    ClosePhysicalSocket; // Force-close the physical OS descriptor immediately
  end;

  case ATargetState of
    seIdle:          FCurrentState := TTaurusTLSSslStateIdle.Create;
    seInitialized:   FCurrentState := TTaurusTLSSslStateInitialized.Create;
    seHandshaking:   FCurrentState := TTaurusTLSSslStateHandshaking.Create;
    seEstablished:   FCurrentState := TTaurusTLSSslStateEstablished.Create;
    seClosing:       FCurrentState := TTaurusTLSSslStateClosing.Create;
    seClosed:        FCurrentState := TTaurusTLSSslStateClosed.Create;
    seError:         FCurrentState := TTaurusTLSSslStateError.Create;
  end;

  FStateEnum := ATargetState;

  // Fire state change event safely from the snapshot
  if Assigned(FSnapshot) and Assigned(FSnapshot.OnStateChange) then
    FSnapshot.OnStateChange(FSnapshot.Sender, LOldState, ATargetState);
end;
```

### 3.1. Snapshot Memory Protection Implementation
```pascal
constructor TTaurusTLSHandshakeSnapshot.Create(AIOHandler: TIdSSLIOHandlerSocketBase; ACTX: PSSL_CTX);
begin
  inherited Create;
  FSender := AIOHandler;
  FContext := ACTX;
  
  if Assigned(FContext) then
    SSL_CTX_up_ref(FContext); // Pinned in memory

  if AIOHandler is TTaurusTLSIOHandlerSocket then
  begin
    with TTaurusTLSIOHandlerSocket(AIOHandler) do
    begin
      FECHEnabled := ECHEnabled;
      FECHConfigList := ECHConfigList;
      FECHOuterHostname := ECHOuterHostname;
      FDefaultSNI := DefaultSNI;
      FHostName := HostName;
      FVerifyHostname := VerifyHostname;
      
      FOnSSLNegotiated := OnSSLNegotiated;
      FOnStatusInfo := OnStatusInfo;
      FOnStateChange := OnStateChange;
      FOnDebugMessage := OnDebugMessage;
      FOnVerifyCallback := OnVerifyCallback;
      FOnVerifyError := OnVerifyError;
      FOnSecurityLevel := OnSecurityLevel;
    end;
  end;
end;

destructor TTaurusTLSHandshakeSnapshot.Destroy;
begin
  if Assigned(FContext) then
    SSL_CTX_free(FContext); // Decrement reference count
  inherited Destroy;
end;
```

## 4. Concrete State Implementation Workflows

### 4.1. Handshake Loop (`TTaurusTLSSslStateHandshaking`)
```pascal
procedure TTaurusTLSSslStateHandshaking.Process(ASocket: TTaurusTLSBaseSocket);
var
  LRet, LErr: Integer;
  LSecurityAccept: Boolean;
begin
  repeat
    if ASocket is TTaurusTLSClientSocket then
      LRet := SSL_connect(ASocket.SSL)
    else
      LRet := SSL_accept(ASocket.SSL);

    if LRet = 1 then
    begin
      // Perform security level check via snapshot event
      LSecurityAccept := True;
      if Assigned(ASocket.Snapshot) and Assigned(ASocket.Snapshot.OnSecurityLevel) then
        ASocket.Snapshot.OnSecurityLevel(ASocket.Snapshot.Sender, LSecurityAccept);

      if not LSecurityAccept then
      begin
        ASocket.TransitionTo(seError);
        Exit;
      end;
      
      ASocket.TransitionTo(seEstablished);
      if Assigned(ASocket.Snapshot) and Assigned(ASocket.Snapshot.OnSSLNegotiated) then
        ASocket.Snapshot.OnSSLNegotiated(ASocket.Snapshot.Sender);
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
          Exit;
        end;
    end;
  until False;
end;
```

### 4.2. Established Connection (`TTaurusTLSSslStateEstablished`)
```pascal
function TTaurusTLSSslStateEstablished.Read(ASocket: TTaurusTLSBaseSocket; var Buf; Size: Integer): Integer;
var
  LRet, LErr: Integer;
begin
  repeat
    LRet := SSL_read(ASocket.SSL, @Buf, Size);
    if LRet <= 0 then
    begin
      LErr := SSL_get_error(ASocket.SSL, LRet);
      case LErr of
        SSL_ERROR_WANT_READ: 
          Continue; // TLS 1.3 Post-Handshake message processed. Loop again.
        SSL_ERROR_SYSCALL:
          begin
            ASocket.TransitionTo(seClosed); // Triggers immediate teardown
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
```

## 5. Callbacks & Bridge Execution
Static or non-member `cdecl` functions handle the low-level OpenSSL callbacks. They safely bridge to the active socket context and read from the frozen `FSnapshot` properties and event handlers:

```pascal
procedure TaurusTLS_InfoCallback(ssl: PSSL; where: Integer; ret: Integer); cdecl;
var
  LSocket: TTaurusTLSBaseSocket;
begin
  LSocket := TTaurusTLSBaseSocket(SSL_get_app_data(ssl));
  if Assigned(LSocket) and Assigned(LSocket.Snapshot) and Assigned(LSocket.Snapshot.OnStatusInfo) then
  begin
    LSocket.Snapshot.OnStatusInfo(LSocket.Snapshot.Sender, where, ret);
  end;
end;

function TaurusTLS_VerifyCallback(preverify_ok: Integer; x509_ctx: PX509_STORE_CTX): Integer; cdecl;
var
  LSSL: PSSL;
  LSocket: TTaurusTLSBaseSocket;
  LCert: TTaurusTLSX509;
  Lpeercert: PX509;
  LVerifyOK: Boolean;
begin
  Result := preverify_ok;
  
  // Extract SSL object from X509 store context
  LSSL := X509_STORE_CTX_get_ex_data(x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
  if not Assigned(LSSL) then Exit;
  
  LSocket := TTaurusTLSBaseSocket(SSL_get_app_data(LSSL));
  if Assigned(LSocket) and Assigned(LSocket.Snapshot) and Assigned(LSocket.Snapshot.OnVerifyCallback) then
  begin
    Lpeercert := X509_STORE_CTX_get_current_cert(x509_ctx);
    LCert := TTaurusTLSX509.Create(Lpeercert, False); // Wrap without transferring ownership
    try
      LVerifyOK := (preverify_ok = 1);
      LSocket.Snapshot.OnVerifyCallback(LSocket.Snapshot.Sender, LCert, LVerifyOK);
      if LVerifyOK then
        Result := 1
      else
        Result := 0;
    finally
      LCert.Free;
    end;
  end;
end;
```

## 6. Client Session Resumption Implementation
Explicit session resumption is isolated within `TTaurusTLSClientSocket`.

```pascal
constructor TTaurusTLSClientSocket.Create(ASnapshot: TTaurusTLSHandshakeSnapshot; 
  ASessionToResume: PSSL_SESSION = nil; ASourceSSLForCopy: PSSL = nil);
begin
  inherited Create(ASnapshot);
  FSessionToResume := ASessionToResume;
  FSourceSSLForCopy := ASourceSSLForCopy;
end;

procedure TTaurusTLSClientSocket.Connect;
begin
  TransitionTo(seInitialized);
  
  if Assigned(FSessionToResume) then
    SSL_set_session(SSL, FSessionToResume)
  else if Assigned(FSourceSSLForCopy) then
    SSL_copy_session_id(SSL, FSourceSSLForCopy);
    
  TransitionTo(seHandshaking);
  Process;
end;
```

## 7. Platform Safety (Initialization)
To support the state machine and prevent OS-level process termination:
*   **Unix/Linux Platforms**: `signal(SIGPIPE, SIG_IGN);` must be invoked during TaurusTLS library startup.
*   **OpenSSL Handshake Optimization**: `SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);` is enabled to automatically process non-application data records without dropping out of `SSL_read` where appropriate.

## 8. Shutdown Sequence
1.  **stEstablished -> stClosing**: The SSM invokes `SSL_shutdown`.
2.  **Bi-directional Check**: If `SSL_shutdown` returns 0, the SSM waits for the peer's `CloseNotify` (using a short timeout) before transitioning to `stClosed`.
3.  **RST Protection**: If the peer sends a TCP RST during shutdown, the SSM catches the syscall error, immediately transitions to `seClosed` (which frees `PSSL`), and suppresses the transport exception to ensure a clean application shutdown.

## 9. State-Specific Exception Mapping

The following table explicitly maps the exact exceptions that are allowed to be raised during each logical state of the connection lifecycle:

| **Logical State** | **Allowed Exceptions** | **Triggering Cause** |
| :--- | :--- | :--- |
| **`seIdle`** / **`seInitialized`** | `ETaurusTLSBioCreateError` | OpenSSL failed to allocate Memory/BIO buffers. |
| | `ETaurusTLSCreatingSessionError` | `SSL_new` failed to instantiate the connection handle. |
| | `ETaurusTLSDataBindingError` | Failed to bind application data to the session. |
| | `ETaurusTLSFDSetError` | Socket descriptor registration failed. |
| **`seHandshaking`** | `ETaurusTLSECHRetryRequired` | ECH key rejected; server returned a valid `retry_config`. |
| | `ETaurusTLSECHError` | ECH key rejected; server provided NO retry configuration. |
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