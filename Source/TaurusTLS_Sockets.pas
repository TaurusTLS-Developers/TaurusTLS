{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2026 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 ? 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew ? http://www.IndyProject.org/  * }
{ ****************************************************************************** }
{$I TaurusTLSCompilerDefines.inc}

unit TaurusTLS_Sockets;

interface

uses
  Classes,
  SysUtils,
  IdCTypes,
  IdGlobal,
  IdComponent,
  IdStack,
  IdStackConsts,
  IdSocketHandle,
  IdGlobalProtocols,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_ech,
  TaurusTLSHeaders_ssl,
  TaurusTLSHeaders_ssl3,
  TaurusTLSHeaders_tls1,
  TaurusTLSHeaders_x509,
  TaurusTLSHeaders_x509_vfy,
  TaurusTLS_types,
  TaurusTLS_Utils,
  TaurusTLS_ECH,
  TaurusTLS_ECHStore,
  TaurusTLS_X509,
  TaurusTLSExceptionHandlers;

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
    // Do not localize
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

  TTaurusTLSSSLOp = (sslOpRead, sslOpWrite);

  TTaurusTLSOnSSLMessageCallback = procedure(
    ASender: TObject;
    AOp: TTaurusTLSSSLOp;
    AVersion: Integer;
    AContentType: Integer;
    ABuf: Pointer;
    ALen: NativeUInt
  ) of object;


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

    // Event triggers

    procedure DoOnStateChange(AOldState, ANewState: TTaurusTLSSslState);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoOnDebug(const AMsg: string); {$IFDEF USE_INLINE}inline; {$ENDIF}
    function DoOnSecurityLevel: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoOnStatusInfo(AWhere, ARet: TIdC_INT);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoOnVerifyCertificate(ACtx: PX509_STORE_CTX;
      var AVerify: boolean);
    procedure DoOnSSLNegotiated; {$IFDEF USE_INLINE}inline; {$ENDIF}

  public
    constructor Create(ASender: TObject); virtual;
    destructor Destroy; override;
    procedure CloneSession(ASSL: PSSL); {$IFDEF USE_INLINE}inline; {$ENDIF}

    property Sender: TObject read FSender;
    property SSLCtx: PSSL_CTX read FSSLCtx write SetSSLCtx;
    property TrustStore: PX509_STORE read FTrustStore write SetTrustStore;
    property VerifyDepth: TIdC_INT read FVerifyDepth write FVerifyDepth;
    property VerifyFlags: TTaurusTLSCertificateVerifyFlagSet read FVerifyFlags
      write FVerifyFlags;

    property OnStateChange: TTaurusTLSOnStateChange read FOnStateChange
      write FOnStateChange;
    property OnDebug: TTaurusTLSOnDebugMessage read FOnDebug
      write FOnDebug;
    property OnSecurityLevel: TTaurusTLSOnSecurityLevel read FOnSecurityLevel
      write FOnSecurityLevel;
    property OnStatusInfo: TTaurusTLSOnSSLStatusInfo read FOnStatusInfo
      write FOnStatusInfo;
    property OnVerifyCertificate: TTaurusTLSOnVerifyCallback read FOnVerifyCertificate
      write FOnVerifyCertificate;
    property OnNegotiated: TNotifyEvent read FOnNegotiated write FOnNegotiated;
  end;

  TTaurusTLSCustomSocketConfigFactory = class abstract
  public
    class function GetSocketConfig(
      AIOHandler: TIdComponent): TTaurusTLSCustomSocketConfig; virtual; abstract;
  end;

  TaurusTLSClientSocketConfig = class(TTaurusTLSCustomSocketConfig)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSessionToResume: PSSL_SESSION;
    FHostname: string;
    FDefaultSNI: string;
    FECHEnabled: boolean;
    FECHConfigList: string;
    FECHDecoy: string;
  protected
    procedure SetSessionToResume(const ASSL: PSSL);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
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


  TTaurusTLSBaseSocket = class abstract
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    [Volatile]
    FState: TTaurusTLSSslState;
    FConfig: TTaurusTLSCustomSocketConfig;
    FSocketHandle: TIdStackSocketHandle;

  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} protected
    FSSL: PSSL;
    class procedure SslInfoCallback(const ASSL: PSSL; AWhere, ARet: TIdC_INT);
      static; cdecl;
    class function SSLVerifyCallback(const APreVerify: TIdC_INT;
      ACtx: PX509_STORE_CTX): TIdC_INT; static; cdecl;
  protected
    class function GetInstanceFromSSL<T: TTaurusTLSBaseSocket>(ASSL: PSSL): T;
      static; {$IFDEF USE_INLINE}inline; {$ENDIF}

    function CheckForError(ALastResult: Integer): Integer; virtual;
    function GetSSLError(ALastResult: Integer): Integer;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    procedure InitSSL; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure InitSSLCallbacks; virtual;
    procedure ReleaseSSL; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure ReleaseSSLCallbacks; virtual;
    procedure LinkSocket; {$IFDEF USE_INLINE}inline; {$ENDIF}

    procedure DoHandshake; virtual; abstract;
    procedure DoShutdown;

    function IsValidTransition(ACurrent, ATarget: TTaurusTLSSslState): Boolean;
      virtual;

    procedure DoSetState(ATarget: TTaurusTLSSslState); virtual;
    procedure CheckActiveState(AExpectedState: TTaurusTLSSslState);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoStateChangeNotify(ACurrent, ATarget: TTaurusTLSSslState);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoDebugLog(const AMessage: string); {$IFDEF USE_INLINE}inline; {$ENDIF}

    property SocketHandle: TIdStackSocketHandle read FSocketHandle;

  public
    constructor Create(AConfig: TTaurusTLSCustomSocketConfig);
    destructor Destroy; override;

    procedure TransitionTo(ATarget: TTaurusTLSSslState); virtual;

    // Delegated Operations
    procedure Connect(const pHandle: TIdStackSocketHandle); virtual;
    procedure ProcessSSL; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function Send(const ABuffer: TIdBytes;
      const AOffset, ALength: TIdC_SIZET): TIdC_SIZET;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function Recv(var ABuffer: TIdBytes): TIdC_SIZET;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function Readable: boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure Shutdown;

    property SSL: PSSL read FSSL;
    property State: TTaurusTLSSslState read FState;
    property Config: TTaurusTLSCustomSocketConfig read FConfig;
  end;

  TTaurusECHClientStatus = (echCliNone, echCliSuccess, echCliFailed,
    echCliRetryConfig, echCliNotConfigured);



  TTaurusTLSClientSocket = class(TTaurusTLSBaseSocket)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FECHStatus: TTaurusECHClientStatus;
    function GetClientConfig: TaurusTLSClientSocketConfig;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
  protected
    procedure SetECHSTatus(AECHStatus: TTaurusECHClientStatus);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoHandshake; override;
    property ClientConfig: TaurusTLSClientSocketConfig read GetClientConfig;
  public
  end;

  /// <summary>
  /// Raised if <c>SSL_set_fd</c> failed.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/SSL_set_fd/">
  /// SSL_set_fd
  /// </seealso>
  ETaurusTLSFDSetError = class(ETaurusTLSAPISSLError);

  ETaurusTLSSocketConfigSSLCtxError = class(ETaurusTLSAPISSLError);
  ETaurusTLSSocketConfigSSLTrustStoreError = class(ETaurusTLSAPISSLError);

  ETaurusTLSBaseSocketInitError = class(ETaurusTLSAPISSLError);

  ETaurusTLSSocketStateError = class(ETaurusTLSAPISSLError);
  ETaurusTLSIOError = class(ETaurusTLSAPISSLError);
  ETaurusTLSConnectionReset = class(ETaurusTLSAPISSLError);

  /// <summary>
  /// Raised if <c>SSL_copy_session_id</c> failed.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man7/ssl/">
  /// SSL_copy_session_id
  /// </seealso>
  ETaurusTLSSSLCopySessionId = class(ETaurusTLSError);


type
  ETaurusTLSCouldNotCreateSSLObject = class(ETaurusTLSError);
  ETaurusTLSDataBindingError = class(ETaurusTLSAPISSLError);
  ETaurusTLSSettingTLSHostNameError = class(ETaurusTLSAPISSLError);
  ETaurusTLSSettingSANIPError = class(ETaurusTLSError);
  ETaurusTLSHandshakeError = class(ETaurusTLSAPISSLError);
  ETaurusTLSClientSocketSSLSetupError = class(ETaurusTLSError);
  ETaurusTLSSessionCanNotBeNil = class(ETaurusTLSError);
  ETaurusTLSInvalidSessionValue = class(ETaurusTLSError);
  ETaurusTLSECHConfigOutOfRange = class(ETaurusTLSError);

  TTaurusTLSSNIKind = (skNoSNI, skSNIHost, skForceSNI);
  TTaurusTLSECHKind = (ekNoECH, ekTryECH, ekForceECH);

//  TTaurusECHStatus = (eshNone, echCliSuccess, echClFfailed, echCliRetryConfig,
//    echCliNotConfigured);

  TTaurusTLSOpts = class(TPersistent)
  public const
    { TODO : Need to finalize defaults }
    cDefaultVerifyMode = [];
    cDefaultVerifyDepth = 5;
    cDefaultVerifyHostName = True;
    cDefaultCipherList = '';
    cDefaultSecurityBits = sb256;
  private
    FVerifyMode: TTaurusTLSVerifyModes;
    FVerifyDepth: Integer;
    FVerifyHostname: Boolean;
    FCipherList: string;
    FSecurityLevel: TTaurusTLSSecurityBits;
  public
    constructor Create;
    procedure Assign(Source: TPersistent); override;
  published
    property VerifyMode: TTaurusTLSVerifyModes read FVerifyMode
      write FVerifyMode default cDefaultVerifyMode;
    property VerifyDepth: Integer read FVerifyDepth write FVerifyDepth
      default cDefaultVerifyDepth;
    property VerifyHostname: Boolean read FVerifyHostname
      write FVerifyHostname default cDefaultVerifyHostName;
    property CipherList: string read FCipherList write FCipherList;
    property SecurityLevel: TTaurusTLSSecurityBits read FSecurityLevel
      write FSecurityLevel default cDefaultSecurityBits;
  end;

  TTaurusTLSCustomECHConfigList = class(TPersistent)
  private
    FConfigList: string;
    FStore: TTaurusTLSECHStore;
    FActiveConfig: TIdC_INT;
    FOuterSNI: string;
    function GetAge: TIdC_TIMET;
    function GetCount: TIdC_INT;
    function GetOuterSNI: string;
    procedure SetActiveConfig(const AValue: TIdC_INT);
      {$IFDEF USE_INLINE} inline;{$ENDIF}
    procedure SetConfigList(const AValue: string);
      {$IFDEF USE_INLINE} inline;{$ENDIF}
  protected
    procedure ResetActiveConfig; {$IFDEF USE_INLINE} inline;{$ENDIF}
  public
    constructor Create; overload;
    constructor Create(const AConfigList: string); overload;
    destructor Destroy; override;
    procedure Assign(Source: TPersistent); override;

    property OuterSNI: string read GetOuterSNI write FOuterSNI;
    property Age: TIdC_TIMET read GetAge;
  published
    property ConfigList: string read FConfigList write SetConfigList;
    property Count: TIdC_INT read GetCount stored False;
    property ActiveConfig: TIdC_INT read FActiveConfig write SetActiveConfig;
  end;

  /// <summary>
  /// SNI and Encrypted Client Hello (ECH) Configuration for Client-side.
  /// </summary>
  TTaurusSNIClientConfig = class(TTaurusTLSCustomECHConfigList)
  public const
    { TODO : Need to finalize defaults }
    cDefSNIKind = skSNIHost;
    cDefECHKind = ekNoECH;
  private
    FSNIKind: TTaurusTLSSNIKind;
    FECHKind: TTaurusTLSECHKind;
    procedure SetECHKind(Value: TTaurusTLSECHKind);
    procedure SetSNIKind(Value: TTaurusTLSSNIKind);
    procedure SetConfigList(const Value: string);
  public
    constructor Create;
    procedure Assign(Source: TPersistent); override;

  published
    property SNIKind: TTaurusTLSSNIKind read FSNIKind
      write SetSNIKind default cDefSNIKind;
    property ECHKind: TTaurusTLSECHKind read FECHKind
      write SetECHKind default cDefECHKind;
  end;

(*  *Commented iout for the future refactoring* *)
(*
  TTaurusTLSBaseSocket = class(TObject)
  protected
    FParent: TObject;
    FSSL: PSSL;
    FSSLContext: TObject; // Reference to legacy TTaurusTLSContext
    FSSLContextHandle: PSSL_CTX; // Raw handle for next-gen handlers
    FSession: PSSL_SESSION;
    FHostName: string;
    FVerifyHostname: Boolean;
    FPeerCert: TTaurusTLSX509;
    {$IFDEF UNITTEST}
    FVirtualHandshakeRet: Integer;
    FVirtualSSLErr: Integer;
    {$ENDIF}

    function GetSSLError(retCode: Integer): Integer;
    function GetPeerCert: TTaurusTLSX509; virtual;
    function GetSSLProtocolVersion: TTaurusTLSSSLVersion;
    function GetSSLProtocolVersionStr: string;
    procedure SetVerifyHostName(const Value: Boolean);
    procedure InitSSL(const pHandle: TIdStackSocketHandle); virtual;
    procedure SetupConnection; virtual; abstract;
  public
    constructor Create(AParent: TObject); virtual;
    destructor Destroy; override;

    function Send(const ABuffer: TIdBytes; const AOffset, ALength: Integer): Integer;
    function Recv(var VBuffer: TIdBytes): Integer;
    function Readable: TTaurusTLSReadStatus;
    procedure Shutdown; virtual;

    property SSL: PSSL read FSSL;
    property Parent: TObject read FParent;
    property HostName: string read FHostName write FHostName;
    property VerifyHostname: Boolean read FVerifyHostname write SetVerifyHostName;
    property PeerCert: TTaurusTLSX509 read GetPeerCert;
    property SSLContext: TObject read FSSLContext write FSSLContext;
    property SSLContextHandle: PSSL_CTX read FSSLContextHandle write FSSLContextHandle;
    property Session: PSSL_SESSION read FSession;
    property SSLProtocolVersion: TTaurusTLSSSLVersion read GetSSLProtocolVersion;
    property SSLProtocolVersionStr: string read GetSSLProtocolVersionStr;
    {$IFDEF UNITTEST}
    property VirtualHandshakeRet: Integer read FVirtualHandshakeRet write FVirtualHandshakeRet;
    property VirtualSSLErr: Integer read FVirtualSSLErr write FVirtualSSLErr;
    {$ENDIF}
  end;

  TTaurusTLSClientSocket = class(TTaurusTLSBaseSocket)
  protected
    FConfig: TTaurusSNIClientConfig;
    FECHSent: Boolean;
    FECHStatus: TTaurusECHStatus;

    {$IFDEF UNITTEST}
    FVirtualECHStatus: TIdC_INT;
    FVirtualECHRetryConfig: string;
    {$ENDIF}
    procedure SetupConnection; override;
  public
    destructor Destroy; override;
    procedure Connect(const pHandle: TIdStackSocketHandle);
    property Config: TTaurusSNIClientConfig read FConfig write FConfig;
    property ECHStatus: TTaurusECHStatus read FECHStatus;
    {$IFDEF UNITTEST}
    constructor Create(AParent: TObject); override;
    property VirtualECHStatus: TIdC_INT read FVirtualECHStatus write FVirtualECHStatus;
    property VirtualECHRetryConfig: string read FVirtualECHRetryConfig write FVirtualECHRetryConfig;
    {$ENDIF}
  end;

  TTaurusTLSServerSocket = class(TTaurusTLSBaseSocket)
  protected
    FECHConfig: string;
    FECHPrivateKey: string;
    procedure SetupConnection; override;
  public
    procedure Accept(const pHandle: TIdStackSocketHandle);
    property ECHConfig: string read FECHConfig write FECHConfig;
    property ECHPrivateKey: string read FECHPrivateKey write FECHPrivateKey;
  end;
*)

implementation

uses
  TaurusTLSHeaders_err,
  TaurusTLSHeaders_sslerr,
  IdException,
  TaurusTLS_ResourceStrings,
  IdResourceStrings,
  IdResourceStringsProtocols,
  IdIDN; // For IDNToPunnyCode

{ TTaurusTLSSslStateHelper }

function TTaurusTLSSslStateHelper.GetAsString: string;
begin
  Result:=cNames[Self];
end;

{ TTaurusTLSCustomSocketConfig }

procedure TTaurusTLSCustomSocketConfig.CloneSession(ASSL: PSSL);
begin
  DoCloneSession(ASSL);
end;

constructor TTaurusTLSCustomSocketConfig.Create(ASender: TObject);
begin
  FSender:=ASender;
end;

destructor TTaurusTLSCustomSocketConfig.Destroy;
begin
  SetTrustStore(nil);
  SetSSLCtx(nil);
  inherited;
end;

procedure TTaurusTLSCustomSocketConfig.SetSSLCtx(ASSLCtx: PSSL_CTX);
var
  LSSLCtx: PSSL_CTX;

begin
  if FSSLCtx = ASSLCtx then
    Exit;

  LSSLCtx:=FSSLCtx;
  if Assigned(ASSLCtx) and (SSL_CTX_up_ref(ASSLCtx)  <> 1) then
    ETaurusTLSSocketConfigSSLCtxError.
      RaiseWithMessage('Error assigning SSL Context');
  FSSLCtx:=ASSLCtx;

  SSL_CTX_free(LSSLCtx);
end;

procedure TTaurusTLSCustomSocketConfig.SetTrustStore(ATrustStore: PX509_STORE);
var
  LStore: PX509_STORE;

begin
  if FTrustStore = ATrustStore then
    Exit;

  LStore:=FTrustStore;
  if Assigned(ATrustStore) and (X509_STORE_up_ref(ATrustStore)  <> 1) then
    ETaurusTLSSocketConfigSSLTrustStoreError.
      RaiseWithMessage('Error assigning X509 Trust Store');
  FTrustStore:=ATrustStore;

  X509_STORE_free(LStore);
end;


procedure TTaurusTLSCustomSocketConfig.DoOnDebug(const AMsg: string);
begin
  if Assigned(FOnDebug) then
    FOnDebug(FSender, AMsg);
end;

procedure TTaurusTLSCustomSocketConfig.DoOnSSLNegotiated;
begin
  if Assigned(FOnNegotiated) then
    FOnNegotiated(FSender);
end;

procedure TTaurusTLSCustomSocketConfig.DoOnStateChange(AOldState,
  ANewState: TTaurusTLSSslState);
begin
  if Assigned(FOnStateChange) then
    FOnStateChange(FSender, AOldState, ANewState);
end;

procedure TTaurusTLSCustomSocketConfig.DoOnStatusInfo(AWhere, ARet: TIdC_INT);
begin
  if Assigned(FOnStatusInfo) then
  try
    FOnStatusInfo(FSender, AWhere, ARet);
  except
    // Must stop raising exception up as it OpenSSL callback.
  end;
end;

procedure TTaurusTLSCustomSocketConfig.DoOnVerifyCertificate(ACtx: PX509_STORE_CTX;
  var AVerify: boolean);
var
  lCert: TTaurusTLSX509;
  lX509: PX509;
  lDepth: TIdC_INT;
  lErr: TIdC_INT;

begin
  lCert:=nil;
  try
    lX509:=X509_STORE_CTX_get0_cert(ACtx);
    if Assigned(FOnVerifyCertificate) and Assigned(lX509) then
    try
      lCert:=TTaurusTLSX509.Create(lX509, False);
      lDepth:=X509_STORE_CTX_get_error_depth(ACtx);
      lErr:=X509_STORE_CTX_get_error(ACtx);
      FOnVerifyCertificate(FSender, lCert, lDepth, lErr, AVerify);
    except
      // Must stop raising exception up as it OpenSSL callback.
    end;
  finally
    lCert.Free;
  end;
end;

function TTaurusTLSCustomSocketConfig.DoOnSecurityLevel: boolean;
begin
  if Assigned(FOnSecurityLevel) then
    FOnSecurityLevel(FSender, Result);
end;

{ TaurusTLSClientSocketConfig }

destructor TaurusTLSClientSocketConfig.Destroy;
begin
  SSL_SESSION_free(FSessionToResume);
  inherited;
end;

procedure TaurusTLSClientSocketConfig.DoCloneSession(ASSL: PSSL);
var
  lSess: PSSL_SESSION;

begin
  if not Assigned(FSessionToResume) then
    Exit;

  lSess:=FSessionToResume;
  if (SSL_SESSION_is_resumable(lSess) and SSL_set_session(ASSL, lSess)) <> 1 then
    ETaurusTLSSSLCopySessionId.RaiseWithMessage(RSOSSLCopySessionIdError);
end;

procedure TaurusTLSClientSocketConfig.SetSessionToResume(
  const ASSL: PSSL);
begin
  if Assigned(ASSL) then
    FSessionToResume:= SSL_get1_session(ASSL);
end;

{ TTaurusTLSBaseSocket }

constructor TTaurusTLSBaseSocket.Create(AConfig: TTaurusTLSCustomSocketConfig);
begin
  inherited Create;
  FSocketHandle:=Id_INVALID_SOCKET;
  FConfig:=AConfig;
end;

destructor TTaurusTLSBaseSocket.Destroy;
begin
  ReleaseSSL;
  FreeAndNil(FConfig);
  inherited;
end;

procedure TTaurusTLSBaseSocket.InitSSL;
begin
  // 1. Allocate the SSL session structure using the pinned context
  FSSL:=SSL_new(FConfig.SSLCtx);
  if FSSL = nil then
    ETaurusTLSBaseSocketInitError.RaiseWithMessage('SSL_new failed to allocate session.');

  // 2. Bind the Delphi object instance to the SSL handle for callback routing
  if SSL_set_app_data(FSSL, Self) <> 1 then
  begin
    ReleaseSSL;
    raise ETaurusTLSDataBindingError.Create('SSL_set_app_data failed.');
  end;

  try
    // 3. Do initial socket setup
    SSL_set_verify_depth(FSSL, FConfig.VerifyDepth);

    // 4. Register the callback bridges
    InitSSLCallbacks;
  except
    on E: Exception do
    begin
      // If callback binding fails, fully deallocate SSL resources and propagate the error
      ReleaseSSL;
      raise;
    end;
  end;
end;

procedure TTaurusTLSBaseSocket.ReleaseSSL;
begin
  if Assigned(FSSL) then
  try
    try
      ReleaseSSLCallbacks;
    except
      // Suppress callback unbinding errors locally to ensure we proceed to freeing memory
    end;
  finally
    SSL_set_app_data(FSSL, nil);
    SSL_free(FSSL);
    FSSL:=nil;
  end;
end;

procedure TTaurusTLSBaseSocket.LinkSocket;
var
  lRet: TIdC_INT;

begin
  if FSocketHandle <> Id_INVALID_SOCKET then
  begin
    ERR_clear_error;
    LRet:=SSL_set_fd(FSSL, FSocketHandle);
    if LRet <= 0 then
      ETaurusTLSFDSetError.RaiseException(FSSL, lRet, RSSSLFDSetError);
  end;
end;

procedure TTaurusTLSBaseSocket.DoDebugLog(const AMessage: string);
var
  lConfig: TTaurusTLSCustomSocketConfig;

begin
  lConfig:=FConfig;
  if Assigned(lConfig)then
    lConfig.OnDebug(lConfig.Sender, AMessage);
end;

procedure TTaurusTLSBaseSocket.DoSetState(ATarget: TTaurusTLSSslState);
var
  lCurrentState: TTaurusTLSSslState;

begin
  lCurrentState:=FState;
  if ATarget = lCurrentState then // guard for notification.
    Exit;

  FState:=ATarget;
  DoStateChangeNotify(lCurrentState, ATarget);
end;

procedure TTaurusTLSBaseSocket.DoShutdown;
var
  lRet: Integer;

begin
  try
    try
      ERR_clear_error;
      LRet:=SSL_shutdown(FSSL);

      // 1. Handle C-Style OpenSSL Failures
      if LRet < 0 then
      begin
        // If the first call fails (e.g. session was already broken or uninitialized),
        // transition to closed immediately to safely deallocate the SSL handle and exit.
        TransitionTo(seClosed);
        Exit;
      end;

      if LRet = 0 then
        // Sent close_notify successfully.
        // In blocking mode, calling it a second time will block synchronously
        // until the peer's close_notify is read or a socket timeout/error occurs.
        SSL_shutdown(FSSL);
        // Even if the second call fails (returns < 0) due to a late TCP RST,
        // the next line will still transition to seClosed cleanly.
      TransitionTo(seClosed);
    except
      on E: Exception do
      begin
        // 2. Handle Physical Transport Exceptions
        // If Indy's transport layer raises a physical Delphi exception (e.g. timeout)
        // during the second blocking call, catch it and force safe teardown.
        TransitionTo(seClosed);
      end;
    end;
  finally
    ERR_clear_error;
  end;
end;

procedure TTaurusTLSBaseSocket.DoStateChangeNotify(ACurrent,
  ATarget: TTaurusTLSSslState);
var
  lConfig: TTaurusTLSCustomSocketConfig;

begin
  lConfig:=FConfig;
  if Assigned(lConfig) then
    lConfig.DoOnStateChange(ACurrent, ATarget);
end;

function TTaurusTLSBaseSocket.GetSSLError(ALastResult: Integer): Integer;
begin
  if Assigned(FSSL) then
  begin
    // Clear the error stack first to ensure we do not read stale results
    ERR_clear_error;
    Result:=SSL_get_error(FSSL, ALastResult);
  end
  else
  begin
    // Fallback if the SSL handle was already freed during state transition
    Result:=SSL_ERROR_SYSCALL;
  end;
end;

function TTaurusTLSBaseSocket.IsValidTransition(ACurrent,
  ATarget: TTaurusTLSSslState): Boolean;
begin
  // Global Panic State Rule: seError is valid from any state except Closed and itself
  if ATarget = seError then
    Exit((ACurrent <> seClosed) and (ACurrent <> seError));

  case ACurrent of
    seIdle:
      Result:=(ATarget = seInitialized);
    seInitialized:
      Result:=(ATarget = seHandshaking) or (ATarget = seClosed);
    seHandshaking:
      Result:=(ATarget = seEstablished) or (ATarget = seClosed);
    seEstablished:
      Result:=(ATarget = seClosing) or (ATarget = seClosed);
    seClosing:
      Result:=(ATarget = seClosed);
    seClosed, seError:
      Result:=False; // Terminal states cannot transition out
  else
    Result:=False;
  end;
end;

procedure TTaurusTLSBaseSocket.TransitionTo(ATarget: TTaurusTLSSslState);
var
  lCurrentState: TTaurusTLSSslState;
begin
  lCurrentState:=State; // Using your internal State property

  // 1. Redundant Transition Guard (Fails fast in Debug, exits silently in Release)
  Assert(lCurrentState <> ATarget, 'Redundant state transition: ' + lCurrentState.AsString);
  if lCurrentState = ATarget then
  begin
    // TODO: Trigger OnDebugMessage warning here (No-op in production)
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
      ReleaseSSL;
   // seIdle:         ; // Handled during object construction
   // seHandshaking:  ; // Handled by active call loops (Connect/Accept)
   // seEstablished:  ; // Handled upon successful Connect/Accept loop completion
   // seClosing:      ; // Handled during bi-directional CloseNotify negotiation
  end;

  // 4. Commit the new state enum
  DoSetState(ATarget);
end;

procedure TTaurusTLSBaseSocket.Connect(const pHandle: TIdStackSocketHandle);
begin
  FSocketHandle:=pHandle;
  TransitionTo(seInitialized);
  LinkSocket;
  TransitionTo(seHandshaking);
  ProcessSSL;
end;

procedure TTaurusTLSBaseSocket.CheckActiveState(
  AExpectedState: TTaurusTLSSslState);
begin
  if FState <> AExpectedState then
    ETaurusTLSSocketStateError.RaiseWithMessageFmt(
      'Invalid socket operation in the ''%s'' state.', [AExpectedState.AsString]);
end;

function TTaurusTLSBaseSocket.CheckForError(ALastResult: Integer): Integer;
begin
  // Get SSLError code
  Result:=SSL_get_error(FSSL, ALastResult);
  if Result = SSL_ERROR_NONE then
    Exit(0);

  if Result = SSL_ERROR_SYSCALL then
    Exit(GStack.CheckForSocketError(Integer(Id_SOCKET_ERROR),
      [Id_WSAESHUTDOWN, Id_WSAECONNABORTED, Id_WSAECONNRESET, Id_WSAETIMEDOUT]));

  { TODO : Use correct exception class here. }
  ETaurusTLSAPISSLError.RaiseExceptionCode(Result, ALastResult);
end;

procedure TTaurusTLSBaseSocket.ProcessSSL;
begin
  case FState of
    seHandshaking:
      DoHandshake; // Polymorphic dispatch to Client/Peer

    seClosing:
      DoShutdown;  // Standard unified SSL_shutdown loop
  else
    ETaurusTLSSocketStateError.RaiseWithMessageFmt(
      'Invalid TLS Socket state ''%s'' for negotiation.', [FState.AsString]);
  end;
end;

function TTaurusTLSBaseSocket.Readable: boolean;
begin
  Result:=Assigned(FSSL) and (FState = seEstablished) and
    (SSL_has_pending(FSSL) = 1);
end;

function TTaurusTLSBaseSocket.Recv(var ABuffer: TIdBytes): TIdC_SIZET;
var
  lLen, lRet, lErr, lQErr: Integer;
  lSSL: PSSL;

begin
  Result:=0;
  lLen:=Length(ABuffer);

  if lLen = 0 then
    Exit;

  CheckActiveState(seEstablished); // Security guard

  lSSL:=FSSL;
  repeat
    // Clear error queue before doing read to avoid getting unhandled previously error
    ERR_clear_error;

    lRet:=SSL_read_ex(lSSL, ABuffer[0], lLen, Result);
    if lRet = 1 then // Success
      Exit
    else
    begin // Read error. Checking the reason
      lErr:=SSL_get_error(lSSL, lRet);
      case lErr of
      SSL_ERROR_ZERO_RETURN:
        begin
          // 1. Cleanly update our internal state and free SSL
          TransitionTo(seClosed);
          // 2. Return 0 to let Indy's core pipeline handle the graceful close
          // Original code did Exit(lRet);
          Exit(0);
        end;

      SSL_ERROR_SSL:
        begin
          lQErr:=ERR_get_error; // Read the specific error from the queue
          if (ERR_GET_LIB(lQErr) = ERR_LIB_SSL) and
            (ERR_GET_REASON(lQErr) = SSL_R_UNEXPECTED_EOF_WHILE_READING) then
          begin
            // Treat unexpected EOF as graceful close for web/Indy compatibility
            TransitionTo(seClosed);
            Exit(0); // Return 0 to let Indy handle EOF gracefully
          end
          else
          begin
            TransitionTo(seError);
            ETaurusTLSIOError.RaiseWithMessage('Fatal SSL protocol error during read.');
          end;
        end;

      SSL_ERROR_SYSCALL:
        begin
          // This is a hard OS socket reset (RST), not a graceful close.
          // We transition to seClosed and raise the reset exception immediately.
          TransitionTo(seClosed);
          // Let Indy's GStack query LastError/errno and raise EIdSocketError
          CheckForError(lRet); //PALOFF
          ETaurusTLSConnectionReset.RaiseWithMessage('Connection reset by peer diring read.');
        end;
      else
        begin
          TransitionTo(seError);
          raise ETaurusTLSIOError.Create('Fatal read error.');
        end;
      end;
    end
  until False;
end;

function TTaurusTLSBaseSocket.Send(const ABuffer: TIdBytes; const AOffset,
  ALength: TIdC_SIZET): TIdC_SIZET;
var
  lRet, lErr: TIdC_INT;

begin
  if (ALength = 0) or (Length(ABuffer) = 0) then
    Exit(0);

  CheckActiveState(seEstablished); // Security guard

  // Clear error queue before doing read to avoid getting unhandled previously error
  ERR_clear_error;

  LRet:=SSL_write_ex(FSSL, ABuffer[0], ALength, Result);
  if LRet = 1 then
    Exit
  else
  begin
    LErr:=SSL_get_error(FSSL, LRet);
    if LErr = SSL_ERROR_SYSCALL then
    begin
      TransitionTo(seClosed); // Force-close immediate teardown

      // Let Indy's GStack query LastError/errno and raise EIdSocketError
      CheckForError(lRet);
      ETaurusTLSConnectionReset.RaiseWithMessage('Connection reset by peer during write.');
    end
    else
    begin
      TransitionTo(seError);
      ETaurusTLSIOError.RaiseWithMessage('Fatal write error.');
    end;
  end
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

// callbacks

procedure TTaurusTLSBaseSocket.InitSSLCallbacks;
begin
  if Assigned(FConfig.OnStatusInfo) then
    SSL_set_info_callback(FSSL, TTaurusTLSBaseSocket.SslInfoCallback);

  if Assigned(FConfig.OnVerifyCertificate) then
  begin
    SSL_set_verify(FSSL, FConfig.VerifyFlags.AsInt,
      TTaurusTLSBaseSocket.SSLVerifyCallback);
  end;
end;

procedure TTaurusTLSBaseSocket.ReleaseSSLCallbacks;
begin
  SSL_set_verify(FSSL, 0, nil);
  SSL_set_info_callback(FSSL, nil);
end;

class function TTaurusTLSBaseSocket.GetInstanceFromSSL<T>(ASSL: PSSL): T;
begin
  Result:=T(SSL_get_app_data(ASSL));
end;

class procedure TTaurusTLSBaseSocket.SslInfoCallback(const ASSL: PSSL; AWhere,
  ARet: TIdC_INT);
var
  lInstance: TTaurusTLSBaseSocket;
  lConfig: TTaurusTLSCustomSocketConfig;

begin
  if not Assigned(ASSL) then
    Exit;
  try
    lInstance:=GetInstanceFromSSL<TTaurusTLSBaseSocket>(ASSL);
    if not Assigned(lInstance) then
      Exit;

    lConfig:=lInstance.Config;
    if Assigned(lConfig) then
      lConfig.DoOnStatusInfo(AWhere, ARet);
  except
    // We must not raise exception to the OpenSSL stack
  end;
end;

class function TTaurusTLSBaseSocket.SSLVerifyCallback(const APreVerify: TIdC_INT;
  ACtx: PX509_STORE_CTX): TIdC_INT;
var
  lInstance: TTaurusTLSBaseSocket;
  lConfig: TTaurusTLSCustomSocketConfig;
  lSSL: PSSL;
  lResult: boolean;

begin
  if not Assigned(ACtx) then // this shouldn't happen ever
    Exit(0);

  try
    lSSL:=X509_STORE_CTX_get_ex_data(ACtx, SSL_get_ex_data_X509_STORE_CTX_idx());
    if not Assigned(lSSL) then
      Exit(0);

    lResult:=APreVerify = 1;
    lInstance:=GetInstanceFromSSL<TTaurusTLSBaseSocket>(lSSL);
    lConfig:=lInstance.Config;
    if Assigned(lConfig) then
    begin
      lConfig.DoOnVerifyCertificate(ACtx, lResult);
      if lResult then Result:=1 else Result:=0;
    end;
  except
    // We must not raise exception to the OpenSSL stack
  end;

end;

{ TTaurusTLSClientSocket }

function TTaurusTLSClientSocket.GetClientConfig: TaurusTLSClientSocketConfig;
begin
  Result:=Config as TaurusTLSClientSocketConfig;
end;

procedure TTaurusTLSClientSocket.SetECHSTatus(AECHStatus: TTaurusECHClientStatus);
begin
  FECHStatus:=AECHStatus;
end;

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

            if SSL_ech_get1_retry_config(SSL, @LECHConfigBuf, @LECHConfigLen) = 1 then
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
              'ECH Handshake failed. The server rejected the key and provided no retry configuration.');
          end
          else if lStatus = SSL_ECH_STATUS_FAILED then
          begin
            TransitionTo(seError);
            ETaurusTLSECHDowngradeError.RaiseWithMessage(
              'ECH Handshake failed due to a protocol or decryption error.');
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
          LStatus := SSL_ech_get1_status(SSL, @LInner, @LOuter);
          if LStatus = SSL_ECH_STATUS_SUCCESS then
            SetECHStatus(echCliSuccess)
          else
            SetECHStatus(echCliNone);
        end;

        lConfig.DoOnSSLNegotiated;
        Exit;
      end;

      lErr := SSL_get_error(SSL, lRet);
      if LErr = SSL_ERROR_SYSCALL then
      begin
        TransitionTo(seClosed); // Triggers immediate teardown
        raise ETaurusTLSConnectionReset.Create('Handshake reset by peer.');
      end
      else
      begin
        TransitionTo(seError);
        raise ETaurusTLSHandshakeError.Create('Fatal handshake error.');
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

{ TTaurusTLSOpts }

constructor TTaurusTLSOpts.Create;
begin
  inherited Create;
  FVerifyMode:=cDefaultVerifyMode;
  FVerifyDepth:=cDefaultVerifyDepth;
  FVerifyHostname:=cDefaultVerifyHostName;
  FCipherList:=cDefaultCipherList;
  FSecurityLevel:=cDefaultSecurityBits;
end;

procedure TTaurusTLSOpts.Assign(Source: TPersistent);
begin
  if Source is TTaurusTLSOpts then
  begin
    FVerifyMode:=TTaurusTLSOpts(Source).VerifyMode;
    FVerifyDepth:=TTaurusTLSOpts(Source).VerifyDepth;
    FVerifyHostname:=TTaurusTLSOpts(Source).VerifyHostname;
    FCipherList:=TTaurusTLSOpts(Source).CipherList;
    FSecurityLevel:=TTaurusTLSOpts(Source).SecurityLevel;
  end
  else inherited Assign(Source);
end;

{ TTaurusSNIClientConfig }

constructor TTaurusSNIClientConfig.Create;
begin
  inherited Create;
  FSNIKind:=skSNIHost;
  FECHKind:=ekNoECH;
end;

procedure TTaurusSNIClientConfig.SetConfigList(const Value: string);
begin
  FConfigList:=Value;
end;

procedure TTaurusSNIClientConfig.SetECHKind(Value: TTaurusTLSECHKind);
begin
  FECHKind:=Value;
end;

procedure TTaurusSNIClientConfig.SetSNIKind(Value: TTaurusTLSSNIKind);
begin
  FSNIKind:=Value;
end;

procedure TTaurusSNIClientConfig.Assign(Source: TPersistent);
begin
  inherited;
  if Source is TTaurusSNIClientConfig then
  begin
    FSNIKind:=TTaurusSNIClientConfig(Source).SNIKind;
    FECHKind:=TTaurusSNIClientConfig(Source).ECHKind;
  end;
end;

{ TTaurusTLSCustomECHConfigList }

constructor TTaurusTLSCustomECHConfigList.Create;
begin
  FStore:=TTaurusTLSECHStore.Create;
end;

constructor TTaurusTLSCustomECHConfigList.Create(const AConfigList: string);
begin
  Create;
  ConfigList:=AConfigList;
end;

destructor TTaurusTLSCustomECHConfigList.Destroy;
begin
  FreeAndNil(FStore);
  inherited;
end;

procedure TTaurusTLSCustomECHConfigList.Assign(Source: TPersistent);
begin
  if Source is TTaurusTLSCustomECHConfigList then
  begin
    ConfigList:=TTaurusTLSCustomECHConfigList(Source).ConfigList;
    FOuterSNI:=TTaurusTLSCustomECHConfigList(Source).FOuterSNI;
    ActiveConfig:=TTaurusTLSCustomECHConfigList(Source).ActiveConfig;
  end
  else
    inherited Assign(Source);
end;

function TTaurusTLSCustomECHConfigList.GetCount: TIdC_INT;
begin
  Result:=FStore.Count;
end;

function TTaurusTLSCustomECHConfigList.GetAge: TIdC_TIMET;
begin
  Result:=FStore.Age[FActiveConfig];
end;

function TTaurusTLSCustomECHConfigList.GetOuterSNI: string;
begin
  if FOuterSNI <> '' then
    Result:=FOuterSNI
  else
    Result:=FStore.PublicName[FActiveConfig];
end;

procedure TTaurusTLSCustomECHConfigList.ResetActiveConfig;
begin
  FActiveConfig:=0;
end;

procedure TTaurusTLSCustomECHConfigList.SetActiveConfig(const AValue: TIdC_INT);
begin
  if AValue = FActiveConfig then
    Exit;
  if AValue >= Count then
    ETaurusTLSECHConfigOutOfRange.RaiseWithMessage('Selected ECH Config is out of range.');

  FStore.SelectConfig(AValue);
  FActiveConfig:=AValue;
end;

procedure TTaurusTLSCustomECHConfigList.SetConfigList(const AValue: string);
begin
  if AValue = FConfigList then
    Exit;
  FConfigList:=AValue;
  ResetActiveConfig;
end;

(*  *Commented iout for the future refactoring* *)

(*
{ TTaurusTLSBaseSocket }

constructor TTaurusTLSBaseSocket.Create(AParent: TObject);
begin
  inherited Create;
  FParent := AParent;
  FVerifyHostname := True;
  {$IFDEF UNITTEST}
  FVirtualHandshakeRet := 0;
  FVirtualSSLErr := 0;
  {$ENDIF}
end;

destructor TTaurusTLSBaseSocket.Destroy;
begin
  if Assigned(FSession) then
  begin
    SSL_SESSION_free(FSession);
    FSession := nil;
  end;
  if Assigned(FSSL) then
  begin
    SSL_free(FSSL);
    FSSL := nil;
  end;
  FreeAndNil(FPeerCert);
  inherited Destroy;
end;

procedure TTaurusTLSBaseSocket.Shutdown;
begin
  if Assigned(FSSL) then
  begin
    SSL_shutdown(FSSL);
  end;
end;

function TTaurusTLSBaseSocket.GetSSLError(retCode: Integer): Integer;
begin
  Result := SSL_get_error(FSSL, retCode);
end;

function TTaurusTLSBaseSocket.GetPeerCert: TTaurusTLSX509;
var
  LX509: PX509;
begin
  Result := FPeerCert;
  if not Assigned(Result) and Assigned(FSSL) then
  begin
    LX509 := SSL_get_peer_certificate(FSSL);
    if Assigned(LX509) then
    begin
      Result := TTaurusTLSX509.Create(LX509, False);
      FPeerCert := Result;
    end;
  end;
end;

function TTaurusTLSBaseSocket.GetSSLProtocolVersion: TTaurusTLSSSLVersion;
begin
  if not Assigned(FSession) then
    raise ETaurusTLSSessionCanNotBeNil.Create(RSOSSSessionCanNotBeNul)
  else
    case SSL_SESSION_get_protocol_version(FSession) of
      SSL3_VERSION: Result := SSLv3;
      TLS1_VERSION: Result := TLSv1;
      TLS1_1_VERSION: Result := TLSv1_1;
      TLS1_2_VERSION: Result := TLSv1_2;
      TLS1_3_VERSION: Result := TLSv1_3;
    else
      raise ETaurusTLSInvalidSessionValue.Create(RSOSSInvalidSessionValue);
    end;
end;

function TTaurusTLSBaseSocket.GetSSLProtocolVersionStr: string;
begin
  case SSLProtocolVersion of
    SSLv23: Result := 'SSLv2 or SSLv3';
    SSLv2: Result := 'SSLv2';
    SSLv3: Result := 'SSLv3';
    TLSv1: Result := 'TLSv1';
    TLSv1_1: Result := 'TLSv1.1';
    TLSv1_2: Result := 'TLSv1.2';
    TLSv1_3: Result := 'TLSv1.3';
  else
    Result := 'Unknown';
  end;
end;

procedure TTaurusTLSBaseSocket.SetVerifyHostName(const Value: Boolean);
begin
  FVerifyHostname := Value;
end;

procedure TTaurusTLSBaseSocket.InitSSL(const pHandle: TIdStackSocketHandle);
var
  LHandle: PSSL_CTX;
begin
  if not Assigned(FSSL) then
  begin
    LHandle := FSSLContextHandle;
    if not Assigned(LHandle) and Assigned(FSSLContext) then
      LHandle := TTaurusTLSContext(FSSLContext).Context;

    if not Assigned(LHandle) then
       raise ETaurusTLSError.Create('SSL Context Handle not assigned');

    FSSL := SSL_new(LHandle);
    if not Assigned(FSSL) then
    begin
      ETaurusTLSCouldNotCreateSSLObject.RaiseWithMessage(RSOSSCouldNotCreateSSLObject);
    end;

    if SSL_set_fd(FSSL, pHandle) <= 0 then
    begin
      ETaurusTLSDataBindingError.RaiseException(FSSL, 0, RSSSLDataBindingError);
    end;

    SSL_set_app_data(FSSL, Self);
  end;
end;

function TTaurusTLSBaseSocket.Send(const ABuffer: TIdBytes; const AOffset,
  ALength: Integer): Integer;
var
  Lret, LErr: Integer;
  LOffset, LLength, LWritten: TIdC_SIZET;
begin
  Result := 0;
  LOffset := TIdC_SIZET(AOffset);
  LLength := TIdC_SIZET(ALength);
  
  repeat
    LWritten := 0;
    Lret := SSL_write_ex(FSSL, ABuffer[LOffset], LLength, LWritten);
    if Lret > 0 then
    begin
      Result := Result + Integer(LWritten);
      LOffset := LOffset + LWritten;
      LLength := LLength - LWritten;
      if LLength < 1 then break;
      Continue;
    end;
    
    LErr := GetSSLError(Lret);
    if (LErr = SSL_ERROR_WANT_READ) or (LErr = SSL_ERROR_WANT_WRITE) then
      Continue;
      
    if LErr <> SSL_ERROR_ZERO_RETURN then
      Result := Lret;
    break;
  until False;
end;

function TTaurusTLSBaseSocket.Recv(var VBuffer: TIdBytes): Integer;
var
  Lret, LErr: Integer;
  LRead: TIdC_SIZET;
begin
  Result := 0;
  repeat
    LRead := 0;
    Lret := SSL_read_ex(FSSL, VBuffer[0], Length(VBuffer), LRead);
    if Lret > 0 then
    begin
      Result := Integer(LRead);
      break;
    end;
    
    LErr := GetSSLError(Lret);
    if (LErr = SSL_ERROR_WANT_READ) or (LErr = SSL_ERROR_WANT_WRITE) then
      Continue;
      
    if LErr <> SSL_ERROR_ZERO_RETURN then
      Result := Lret;
    break;
  until False;
end;

function TTaurusTLSBaseSocket.Readable: TTaurusTLSReadStatus;
var
  Lbuf: Byte;
  Lr: Integer;
begin
  Result := sslNoData;
  Lr := SSL_peek(FSSL, Lbuf, 1);
  if Lr > 0 then
    Result := sslDataAvailable
  else
  begin
    case GetSSLError(Lr) of
      SSL_ERROR_SSL, SSL_ERROR_SYSCALL:
        if SSL_get_shutdown(FSSL) = SSL_RECEIVED_SHUTDOWN then
          Result := sslEOF
        else
          Result := sslUnrecoverableError;
      SSL_ERROR_ZERO_RETURN:
        if SSL_get_shutdown(FSSL) = SSL_RECEIVED_SHUTDOWN then
          Result := sslEOF;
    end;
  end;
end;

{ TTaurusTLSClientSocket }

{$IFDEF UNITTEST}
constructor TTaurusTLSClientSocket.Create(AParent: TObject);
begin
  inherited Create(AParent);
  FVirtualECHStatus := -1;
  FConfig := TTaurusSNIClientConfig.Create;
end;
{$ENDIF}

destructor TTaurusTLSClientSocket.Destroy;
begin
  FreeAndNil(FConfig);
  inherited Destroy;
end;

procedure TTaurusTLSClientSocket.SetupConnection;
var
  LRetCode: TIdC_INT;
  LIdentity: string;
  LIdentityAnsi: RawByteString;
  LIsIdentityIP: Boolean;
  LECHStore: TClientECHStore;
  LParams: PX509_VERIFY_PARAM;
begin
  if not Assigned(FConfig) then
    ETaurusTLSClientSocketSSLSetupError.RaiseWithMessage(RSOSSLModeNotSet);

  // 1. Determine Identity (Logical Hostname)
  if IsValidIP(FHostName) then
    LIdentity := FConfig.ForceSNI
  else
    LIdentity := FHostName;

  LIsIdentityIP := IsValidIP(LIdentity);

  // 2. Prepare Punycode
  if LIdentity <> '' then
  begin
    {$IFDEF WINDOWS}
    if Assigned(IdnToAscii) and (not LIsIdentityIP) then
      LIdentityAnsi := RawByteString(IDNToPunnyCode(LIdentity))
    else
    {$ENDIF}
      LIdentityAnsi := RawByteString(LIdentity);
  end;

  FECHSent := False;
  FECHStatus := echCliNotConfigured;

  if (LIdentityAnsi <> '') and (not LIsIdentityIP) then
  begin
    if (FConfig.ECHKind <> ekNoECH) and (FConfig.ConfigList <> '') then
    begin
      LECHStore := TClientECHStore.Create;
      try
        LECHStore.SetConfigList(RawByteString(FConfig.ConfigList));
        LECHStore.Attach(FSSL);
        FECHSent := True;
      finally
        LECHStore.Free;
      end;

      if FConfig.ECHOuterHostname <> '' then
      begin
        SSL_ech_set1_server_names(FSSL, PIdAnsiChar(LIdentityAnsi),
          PIdAnsiChar(AnsiString(FConfig.ECHOuterHostname)), 0);
      end
      else
      begin
        LRetCode := SSL_set_tlsext_host_name(FSSL, PIdAnsiChar(LIdentityAnsi));
        if LRetCode <= 0 then
          ETaurusTLSSettingTLSHostNameError.RaiseException(FSSL, LRetCode, RSSSLSettingTLSHostNameError_2);
      end;
    end
    else
    begin
      if FConfig.ECHKind <> ekNoECH then
        SSL_set_options(FSSL, SSL_OP_ECH_GREASE);

      LRetCode := SSL_set_tlsext_host_name(FSSL, PIdAnsiChar(LIdentityAnsi));
      if LRetCode <= 0 then
        ETaurusTLSSettingTLSHostNameError.RaiseException(FSSL, LRetCode, RSSSLSettingTLSHostNameError_2);
    end;
  end;

  if FVerifyHostname and (LIdentityAnsi <> '') then
  begin
    if LIsIdentityIP then
    begin
      LParams := SSL_get0_param(FSSL);
      if Assigned(LParams) then
        if X509_VERIFY_PARAM_set1_ip_asc(LParams, PIdAnsiChar(LIdentityAnsi)) <= 0 then
          ETaurusTLSSettingSANIPError.RaiseWithMessage(RSSLX509_VERIFY_PARAM_set1_ip_asc);
    end
    else
    begin
      SSL_set_hostflags(FSSL, 0);
      LRetCode := SSL_set1_host(FSSL, PIdAnsiChar(LIdentityAnsi));
      if LRetCode <= 0 then
        ETaurusTLSSettingTLSHostNameError.RaiseException(FSSL, LRetCode, RSSSLSettingTLSHostNameError_2);
    end;
  end;
end;

procedure TTaurusTLSClientSocket.Connect(const pHandle: TIdStackSocketHandle);
var
  LRetCode: TIdC_INT;
  LStatus: TIdC_INT;
  LHelper: ITaurusTLSCallbackHelper;
  LParentIO: TTaurusTLSIOHandlerSocket;
  LVerifyResult: TIdC_LONG;
  LPeerCertHandle: PX509;
  LWrappedCert: TTaurusTLSX509;
  LECHConfigBuf: Pointer;
  LECHConfigLen: TIdC_SIZET;
begin
  if Supports(FParent, ITaurusTLSCallbackHelper, LHelper) then
  begin
    LParentIO := LHelper.GetIOHandlerSelf;
    if Assigned(LParentIO) and Assigned(LParentIO.SSLSocket) and (TObject(LParentIO.SSLSocket) <> TObject(Self)) then
    begin
      if SSL_copy_session_id(FSSL, LParentIO.SSLSocket.SSL) <> 1 then
        ETaurusTLSAPISSLError.RaiseWithMessage(RSOSSLCopySessionIdError);
    end;
  end;

  InitSSL(pHandle);
  SetupConnection;

  {$IFDEF UNITTEST}
  if FVirtualHandshakeRet <> 0 then LRetCode := FVirtualHandshakeRet else
  {$ENDIF}
    LRetCode := SSL_connect(FSSL);

  if FECHSent then
  begin
    {$IFDEF UNITTEST}
    if FVirtualECHStatus <> -1 then LStatus := FVirtualECHStatus else
    {$ENDIF}
      LStatus := SSL_ech_get1_status(FSSL, nil, nil);

    case LStatus of
      SSL_ECH_STATUS_SUCCESS: FECHStatus := ech_cli_success;

      SSL_ECH_STATUS_GREASE_ECH: 
      begin
        FECHStatus := ech_cli_failed;
        {$IFDEF UNITTEST}
        if FVirtualECHRetryConfig <> '' then
        begin
          FECHStatus := ech_cli_retry_config;
          raise ETaurusTLSECHRetryRequired.Create(RSMsg_ECHRetryRequired_err, FVirtualECHRetryConfig);
        end;
        {$ELSE}
        if SSL_ech_get1_retry_config(FSSL, @LECHConfigBuf, @LECHConfigLen) = 1 then
        begin
          try
            if Assigned(LECHConfigBuf) and (LECHConfigLen > 0) then
            begin
              FECHStatus := ech_cli_retry_config;
              raise ETaurusTLSECHRetryRequired.Create(
                RSMsg_ECHRetryRequired_err,
                EncodeConfigList(LECHConfigBuf, LECHConfigLen));
            end;
          finally
            OPENSSL_free(LECHConfigBuf);
          end;
        end;
        {$ENDIF}
        raise ETaurusTLSECHRejectedError.Create(RSMsg_ECHRejected_err);
      end;

      SSL_ECH_STATUS_NOT_CONFIGURED: 
      begin
        FECHStatus := ech_cli_not_configured;
        if FConfig.ECHKind = ekForceECH then
          raise ETaurusTLSECHDowngradeError.Create(RSMsg_ECHNotConfigured_err);
      end;

    else
      FECHStatus := ech_cli_failed;
      raise ETaurusTLSECHError.CreateFmt(LStatus, RSMsg_ECHFailed_err, [LStatus]);
    end;
  end;

  if LRetCode <= 0 then
  begin
    {$IFDEF UNITTEST}
    if FVirtualSSLErr <> 0 then
      ETaurusTLSHandshakeError.RaiseExceptionCode(FVirtualSSLErr, LRetCode, RSOSSLConnectError)
    else
    {$ENDIF}
      ETaurusTLSHandshakeError.RaiseException(FSSL, LRetCode, RSOSSLConnectError);
  end;

  if Assigned(FSession) then SSL_SESSION_free(FSession);
  FSession := SSL_get1_session(FSSL);

  if FVerifyHostname then
  begin
    LVerifyResult := SSL_get_verify_result(FSSL);
    if LVerifyResult <> X509_V_OK then
    begin
      LPeerCertHandle := SSL_get_peer_certificate(FSSL);
      try
        if Assigned(LPeerCertHandle) and Supports(FParent, ITaurusTLSCallbackHelper, LHelper) then
        begin
          LWrappedCert := TTaurusTLSX509.Create(LPeerCertHandle, False);
          try
            if not LHelper.VerifyError(LWrappedCert, LVerifyResult) then
              ETaurusTLSAPICryptoError.RaiseWithMessage(AnsiStringToString(X509_verify_cert_error_string(LVerifyResult)));
          finally
            LWrappedCert.Free;
          end;
        end;
      finally
        if Assigned(LPeerCertHandle) then X509_free(LPeerCertHandle);
      end;
    end;
  end;
end;

{ TTaurusTLSServerSocket }

procedure TTaurusTLSServerSocket.SetupConnection;
var
  LECHStore: TServerECHStore;
begin
  if FECHConfig <> '' then
  begin
    LECHStore := TServerECHStore.Create;
    try
      LECHStore.ReadPem(FECHConfig, 0);
      LECHStore.Attach(FSSL);
    finally
      LECHStore.Free;
    end;
  end;
end;

procedure TTaurusTLSServerSocket.Accept(const pHandle: TIdStackSocketHandle);
var
  LRetCode: Integer;
begin
  InitSSL(pHandle);
  SetupConnection;

  {$IFDEF UNITTEST}
  if FVirtualHandshakeRet <> 0 then
    LRetCode := FVirtualHandshakeRet
  else
  {$ENDIF}
    LRetCode := SSL_accept(FSSL);

  if LRetCode <= 0 then
  begin
    ETaurusTLSHandshakeError.RaiseException(FSSL, LRetCode, RSOSSLAcceptError);
  end;

  if Assigned(FSession) then SSL_SESSION_free(FSession);
  FSession := SSL_get1_session(FSSL);
end;

*)

end.
