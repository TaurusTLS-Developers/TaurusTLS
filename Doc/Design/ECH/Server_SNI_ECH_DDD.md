# Detailed Design Document: Server-Side Multi-Tenancy, SNI Routing, and ECH Decryption

## 1. Class Definitions & Collections

### 1.1.  Polymorphic Config and Dictionary declarations (`TaurusTLS_Sockets.pas` interface)
These classes allow developers to configure multiple virtual servers directly in the Delphi/Lazarus Object Inspector.

~~~pascal
type
  TTaurusTLSIOHandlerSocket = class; // Forward declaration

  /// <summary>
  ///   Abstract base capturing shared connection parameters, common callback events.
  /// </summary>
  TTaurusTLSCustomSocketConfig = class abstract(TPersistent)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    FSender: TTaurusTLSIOHandlerSocket;
    FVerifyDepth: TIdC_INT;
    FVerifyFlags: TTaurusTLSCertificateVerifyFlagSet;

    FOnStateChange: TTaurusTLSOnStateChange;
    FOnDebug: TTaurusTLSOnDebugMessage;
    FOnSecurityLevel: TTaurusTLSOnSecurityLevel;
    FOnStatusInfo: TTaurusTLSOnSSLStatusInfo;
    FOnVerifyCertificate: TTaurusTLSOnVerifyCallback;
    FOnNegotiated: TNotifyEvent;

    function GetSSLCtx: PSSL_CTX; virtual; abstract;
  protected
    procedure DoOnStateChange(AOldState, ANewState: TTaurusTLSSslState); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoOnDebug(const AMsg: string); {$IFDEF USE_INLINE}inline; {$ENDIF}
    function DoOnSecurityLevel: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoOnStatusInfo(AWhere, ARet: TIdC_INT); {$IFDEF USE_INLINE}inline; {$ENDIF}
    function DoOnVerifyCertificate(APreVerify: boolean; ACtx: PX509_STORE_CTX): boolean;
    procedure DoOnSSLNegotiated; {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    constructor Create(ASender: TTaurusTLSIOHandlerSocket); virtual;
    destructor Destroy; override;
    procedure CloneSession(ASSL: PSSL); virtual; abstract;

    property Sender: TTaurusTLSIOHandlerSocket read FSender;
    property SSLCtx: PSSL_CTX read GetSSLCtx; // Read-only, polymorphic
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
  ///   Captures client-specific connection settings, managing own context.
  /// </summary>
  TaurusTLSClientSocketConfig = class(TTaurusTLSCustomSocketConfig)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSSLCtx: PSSL_CTX;
    FSessionToResume: PSSL_SESSION;
    FHostName: string;
    FDefaultSNI: string;
    FECHEnabled: boolean;
    FECHConfigList: string;
    FECHDecoy: string;
  protected
    function GetSSLCtx: PSSL_CTX; override;
    procedure SetSSLCtx(ASSLCtx: PSSL_CTX);
    procedure SetSessionToResume(const ASSL: PSSL); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoCloneSession(ASSL: PSSL);
  public
    destructor Destroy; override;
    procedure CloneSession(ASSL: PSSL); override;

    property SessionToResume: PSSL_SESSION read FSessionToResume;
    property HostName: string read FHostName write FHostName;
    property DefaultSNI: string read FDefaultSNI write FDefaultSNI;
    property ECHEnabled: boolean read FECHEnabled write FECHEnabled;
    property ECHConfigList: string read FECHConfigList write FECHConfigList;
    property ECHDecoy: string read FECHDecoy write FECHDecoy;
  end;

  // Thread-safe, case-insensitive runtime virtual server context lookup map
  TTaurusTLSVirtualServerMap = TDictionary<RawByteString, PSSL_CTX>;

  /// <summary>
  ///   Captures server-side client connection context, referencing the virtual server map.
  /// </summary>
  TTaurusTLSPeerSocketConfig = class(TTaurusTLSCustomSocketConfig)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FVerifyClientModes: TTaurusTLSVerifyModes;
    FALPNPreferences: string;
    FDefaultConfig: TTaurusTLSCustomSocketConfig;
    FVirtualServerMap: TTaurusTLSVirtualServerMap;
  protected
    function GetSSLCtx: PSSL_CTX; override;
  public
    constructor Create(ASender: TTaurusTLSIOHandlerSocket; ADefaultConfig: TTaurusTLSCustomSocketConfig; AMap: TTaurusTLSVirtualServerMap); reintroduce;
    destructor Destroy; override;
    procedure CloneSession(ASSL: PSSL); override;

    property VerifyClientModes: TTaurusTLSVerifyModes read FVerifyClientModes write FVerifyClientModes;
    property ALPNPreferences: string read FALPNPreferences write FALPNPreferences;
    property DefaultConfig: TTaurusTLSCustomSocketConfig read FDefaultConfig;
    property VirtualServerMap: TTaurusTLSVirtualServerMap read FVirtualServerMap;
  end;
~~~

### 1.2. Upgraded Server Configuration snapshot
The server config snapshot is extended to hold a reference to the compiled virtual server collection.

~~~pascal
type
  TTaurusTLSPeerSocketConfig = class(TTaurusTLSCustomSocketConfig)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FVerifyClientModes: TTaurusTLSVerifyModes;
    FALPNPreferences: string;
    FVirtualServers: TTaurusTLSVirtualServerCollection;
  public
    constructor Create(ASender: TObject); override;
    destructor Destroy; override;
    
    property VerifyClientModes: TTaurusTLSVerifyModes read FVerifyClientModes write FVerifyClientModes;
    property ALPNPreferences: string read FALPNPreferences write FALPNPreferences;
    property VirtualServers: TTaurusTLSVirtualServerCollection read FVirtualServers write FVirtualServers;
  end;
~~~

---

## 2. Upgraded Servername Callback and Context Compilation (`TaurusTLS_Sockets.pas` implementation)

The static servername callback is registered on the master `SSL_CTX`. It intercepts the client's SNI and dynamically swaps the active context to the matching virtual server.

~~~pascal
{ TTaurusTLSCustomSocketConfig }
constructor TTaurusTLSCustomSocketConfig.Create(ASender: TTaurusTLSIOHandlerSocket);
begin
  FSender := ASender;
end;

{ TaurusTLSClientSocketConfig }
destructor TaurusTLSClientSocketConfig.Destroy;
begin
  SSL_SESSION_free(FSessionToResume);
  SetSSLCtx(nil);
  inherited;
end;

function TaurusTLSClientSocketConfig.GetSSLCtx: PSSL_CTX;
begin
  Result := FSSLCtx;
end;

procedure TaurusTLSClientSocketConfig.SetSSLCtx(ASSLCtx: PSSL_CTX);
var
  LSSLCtx: PSSL_CTX;
begin
  if FSSLCtx = ASSLCtx then Exit;
  LSSLCtx := FSSLCtx;
  if Assigned(ASSLCtx) and (SSL_CTX_up_ref(ASSLCtx) <> 1) then
    raise Exception.Create('Error incrementing SSL Context reference.');
  FSSLCtx := ASSLCtx;
  SSL_CTX_free(LSSLCtx);
end;

{ TTaurusTLSPeerSocketConfig }
constructor TTaurusTLSPeerSocketConfig.Create(ASender: TTaurusTLSIOHandlerSocket; 
  ADefaultConfig: TTaurusTLSCustomSocketConfig; AMap: TTaurusTLSVirtualServerMap);
begin
  inherited Create(ASender);
  FDefaultConfig := ADefaultConfig;
  FVirtualServerMap := AMap;
  FVerifyClientModes := [];
end;

destructor TTaurusTLSPeerSocketConfig.Destroy;
begin
  // References are passive, no deallocation
  FDefaultConfig := nil;
  FVirtualServerMap := nil;
  inherited;
end;

function TTaurusTLSPeerSocketConfig.GetSSLCtx: PSSL_CTX;
begin
  if Assigned(FDefaultConfig) then
    Result := FDefaultConfig.SSLCtx
  else
    Result := nil;
end;

procedure TTaurusTLSPeerSocketConfig.CloneSession(ASSL: PSSL);
begin
  // No-op on server peer
end;

{ Static Servername Callback Bridge }
function TaurusTLS_ServerNameCallback(ssl: PSSL; ad: PInteger; arg: Pointer): Integer; cdecl;
var
  LServerName: PIdAnsiChar;
  LAnsiName: RawByteString;
  LServerMap: TTaurusTLSVirtualServerMap;
  LTargetCtx: PSSL_CTX;
begin
  Result := SSL_TLSEXT_ERR_OK;

  if not Assigned(ssl) then Exit;
  
  LServerName := SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  if not Assigned(LServerName) then Exit;

  LServerMap := TTaurusTLSVirtualServerMap(arg);
  if not Assigned(LServerMap) then Exit;

  // O(1) hash lookup with zero-copy RawByteString
  LAnsiName := LowerCase(RawByteString(LServerName));
  if LServerMap.TryGetValue(LAnsiName, LTargetCtx) then
  begin
    SSL_set_SSL_CTX(ssl, LTargetCtx);
  end;
end;
~~~

---

## 3. Server Peer Socket Verification and Callback Binding (`TTaurusTLSPeerSocket`)

The peer socket manages client certificate verification and evaluates the server-side ECH decryption status upon successful handshake completion, ensuring all allocated C-strings are cleanly deallocated.

~~~pascal
type
  TTaurusECHServerStatus = (
    echSrvNone,          // ECH wasn't attempted
    echSrvSuccess,       // ECH successfully decrypted (Inner SNI active)
    echSrvFailed,        // ECH decryption failed (Outer SNI active)
    echSrvBackend,       // Handled in backend split-mode
    echSrvNotConfigured  // Server has no ECH keys loaded
  );

  TTaurusTLSPeerSocket = class(TTaurusTLSBaseSocket)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FECHStatus: TTaurusECHServerStatus;
    FInnerSNI: string;
    FOuterSNI: string;
    function GetPeerConfig: TTaurusTLSPeerSocketConfig; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetServerName: string;
  protected
    procedure DoHandshakeIteration; override;
    procedure InitSSLCallbacks; override;
    property PeerConfig: TTaurusTLSPeerSocketConfig read GetPeerConfig;
  public
    constructor Create(AConfig: TTaurusTLSPeerSocketConfig); reintroduce;
    
    property ECHStatus: TTaurusECHServerStatus read FECHStatus;
    property InnerSNI: string read FInnerSNI;
    property OuterSNI: string read FOuterSNI;
    property ServerName: string read GetServerName;
  end;

constructor TTaurusTLSPeerSocket.Create(AConfig: TTaurusTLSPeerSocketConfig);
begin
  inherited Create(AConfig);
  FECHStatus := echSrvNone;
  FInnerSNI := '';
  FOuterSNI := '';
end;

function TTaurusTLSPeerSocket.GetPeerConfig: TTaurusTLSPeerSocketConfig;
begin
  Result := Config as TTaurusTLSPeerSocketConfig;
end;

function TTaurusTLSPeerSocket.GetServerName: string;
var
  lName: PIdAnsiChar;
begin
  Result := '';
  if Assigned(FSSL) then
  begin
    lName := SSL_get_servername(FSSL, TLSEXT_NAMETYPE_host_name);
    if Assigned(lName) then
      Result := String(lName);
  end;
end;

procedure TTaurusTLSPeerSocket.InitSSLCallbacks;
var
  lMode: Integer;
  lPeerConfig: TTaurusTLSPeerSocketConfig;
begin
  inherited; // Registers standard base SslInfoCallback

  lPeerConfig := PeerConfig;
  if not Assigned(lPeerConfig) then Exit;

  // Set up mTLS Client Verification Modes
  lMode := 0;
  if sslvrfPeer in lPeerConfig.VerifyClientModes then
    lMode := lMode or SSL_VERIFY_PEER;
  if sslvrfFailIfNoPeerCert in lPeerConfig.VerifyClientModes then
    lMode := lMode or SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
  if sslvrfClientOnce in lPeerConfig.VerifyClientModes then
    lMode := lMode or SSL_VERIFY_CLIENT_ONCE;
  if sslvrfPostHandshake in lPeerConfig.VerifyClientModes then
    lMode := lMode or SSL_VERIFY_POST_HANDSHAKE;

  if lMode <> 0 then
  begin
    SSL_set_verify(FSSL, lMode, @TTaurusTLSBaseSocket.SSLVerifyCallback);
  end;
end;

procedure TTaurusTLSPeerSocket.DoHandshakeIteration;
var
  lRet, lErr: Integer;
  lAccepted: boolean;
  lStatus: TIdC_INT;
  lInner, lOuter: PIdAnsiChar;
begin
  try
    ERR_clear_error;
    lRet := SSL_accept(SSL);

    if lRet = 1 then
    begin
      // 1. Evaluate ECH Status and Prevent C-Heap Memory Leaks
      lInner := nil;
      lOuter := nil;
      lStatus := SSL_ech_get1_status(SSL, @lInner, @lOuter);
      try
        case lStatus of
          SSL_ECH_STATUS_SUCCESS:        FECHStatus := echSrvSuccess;
          SSL_ECH_STATUS_FAILED:         FECHStatus := echSrvFailed;
          SSL_ECH_STATUS_BACKEND:        FECHStatus := echSrvBackend;
          SSL_ECH_STATUS_NOT_CONFIGURED: FECHStatus := echSrvNotConfigured;
          else                           FECHStatus := echSrvNone;
        end;

        if Assigned(lInner) then
          FInnerSNI := String(lInner);
        if Assigned(lOuter) then
          FOuterSNI := String(lOuter);
      finally
        // Security Fix: Free C-strings allocated by OpenSSL
        if Assigned(lInner) then OPENSSL_free(lInner);
        if Assigned(lOuter) then OPENSSL_free(lOuter);
      end;

      // 2. Perform security level check via snapshot event
      lAccepted := True;
      Config.DoOnSecurityLevel(lAccepted);
      if not lAccepted then
      begin
        TransitionTo(seError);
        Exit;
      end;

      TransitionTo(seEstablished);
      Exit;
    end;

    lErr := SSL_get_error(SSL, lRet);
    case lErr of
      SSL_ERROR_SYSCALL:
        begin
          TransitionTo(seClosed); // Triggers immediate teardown
          raise ETaurusTLSConnectionReset.Create('Handshake reset by peer.');
        end;

      SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE:
        Exit; // Wait for data from the socket.

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
        TransitionTo(seError); // Safely aborts, preventing illegal "shutdown while in init"
      raise;
    end;
  end;
end;