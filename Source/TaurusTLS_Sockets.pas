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
{$I TaurusTLSLinkDefines.inc}

interface

uses
  Classes,
  SysUtils,
{$IFDEF SIGPIPE_MASK}
  {$IFDEF FPC}
  BaseUnix,
  pthreads,
  {$ELSE}
  Posix.Signal,
  {$ENDIF}
{$ENDIF}
  Generics.Collections,
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
  TaurusTLS_BIO,
  TaurusTLS_ECH,
  TaurusTLS_ECHStore,
  TaurusTLS_SSLStores,
  TaurusTLS_SSLUI,
  TaurusTLS_X509,
  TaurusTLSExceptionHandlers;

type
  ETaurusTLSSslSocketCtxError = class(ETaurusTLSError);
  ETaurusTLSSslSocketCtxBuildError = class(ETaurusTLSError);


  ETaurusTLSSocketCtxSSLCtxError = class(ETaurusTLSAPISSLError);
  ETaurusTLSSocketCtxSSLTrustStoreError = class(ETaurusTLSAPISSLError);

  ETaurusTLSSocketStateError = class(ETaurusTLSError);

  /// <summary>
  /// Raised if <c>SSL_set_fd</c> failed.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/SSL_set_fd/">
  /// SSL_set_fd
  /// </seealso>
  ETaurusTLSSSLSocketCreateError = class(ETaurusTLSAPICryptoError);
  ETaurusTLSSslSocketBindError = class(ETaurusTLSAPICryptoError);

  ETaurusTLSSSLSocketError = class(ETaurusTLSAPISSLError)
  public
    class function TargetSocketState: TTaurusTLSSslSocketState; virtual;
  end;

  ETaurusTLSSSLSocketClose = class(ETaurusTLSSSLSocketError)
  public
    class function TargetSocketState: TTaurusTLSSslSocketState; override;
  end;

  ETaurusTLSSSLSocketConnectionReset = class(ETaurusTLSSSLSocketClose);

  /// <summary>
  /// Raised if certificate validation failed and the message breifly
  /// describes the failure.
  /// </summary>
  ETaurusTLSSSLSocketCertValidationError = class(ETaurusTLSError)
  private
    FVerifyCode: TIdC_LONG;
  public
    constructor Create(AVerifyCode: TIdC_LONG; const AMessage: string);
    class procedure RaiseErrorCode(AVerifyCode: TIdC_LONG;
      const AMessage: string);

    property VerifyCode: TIdC_LONG read FVerifyCode;
  end;

  ETaurusTLSSSLSocketDataBindingError = class(ETaurusTLSAPICryptoError);

  ETaurusTLSClientSSLSocketSetupError = class(ETaurusTLSSSLSocketError);
  ETaurusTLSClientSSLSocketHostNameError = class(ETaurusTLSAPISSLError);
  ETaurusTLSHandshakeError = class(ETaurusTLSAPISSLError);

  ETaurusTLSECHCliFlagsError = class(ETaurusTLSError);
  EECHNotSupported = class(ETaurusTLSError);


  ETaurusTLSECHBadNameError = class(ETaurusTLSECHError);
  ETaurusTLSECHProtocolError = class(ETaurusTLSECHError);


  ETaurusTLSAlpnResultError = class(ETaurusTLSError);


type
  TTaurusTLSSNICliKind = (
    skNoSNI,
    skHostSNI,
    skForceSNI
  );

  TTaurusTLSECHCliEnum = (
    ekNoECH,
    ekTryECH,
    ekForceECH,
    emMethECHList,
    emMethECHGrease,
    emMethECHNoOuter
  );

  TTaurusTLSECHCliKind  = ekNoECH..ekForceECH;
  TTaurusTLSECHCliKinds = set of TTaurusTLSECHCliKind;
  TTaurusTLSECHCliMeth  = emMethECHList..emMethECHNoOuter;
  TTaurusTLSECHCliMeths = set of TTaurusTLSECHCliMeth;

  TTaurusTLSECHCliEnums = set of TTaurusTLSECHCLiEnum;
  TTaurusTLSECHCliFlags = record
  private const
    cMaskKind     = [ekNoECH..ekForceECH];
    cMaskMethods  = [emMethECHList..emMethECHNoOuter];
    cMaskEchEnabled   = [ekTryECH..ekForceECH];

  private
    FValue: TTaurusTLSECHCliEnums;
    procedure SetValue(const AValue: TTaurusTLSECHCLiEnums);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function CheckECHSupported: boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetKind: TTaurusTLSECHCliKind; overload;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetMethods: TTaurusTLSECHCliMeths; overload;
    function GetEnabled: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetEnforced: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsMethSet: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetUseConfigList: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetUseFallback: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetUseGrease: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetUseNoOuter: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    class function IsEnabled(const AValue: TTaurusTLSECHCliEnums): boolean;
      static; {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    constructor Create(const AFlags: TTaurusTLSECHCliEnums);
    class function GetKinds(const AValue: TTaurusTLSECHCliEnums):
      TTaurusTLSECHCliKinds; overload; static; {$IFDEF USE_INLINE}inline; {$ENDIF}
    class function GetMethods(const AValue: TTaurusTLSECHCliEnums):
      TTaurusTLSECHCliMeths; overload; static; {$IFDEF USE_INLINE}inline; {$ENDIF}

    property Kind: TTaurusTLSECHCLiKind read GetKind;
    property Methods: TTaurusTLSECHCliMeths read GetMethods;
    property Enabled: boolean read GetEnabled;
    property Enforced: boolean read GetEnforced;
    property IsMethodSet: boolean read GetIsMethSet;
    property UseConfigList: boolean read GetUseConfigList;
    property UseGrease: boolean read GetUseGrease;
    property UseGreaseFallback: boolean read GetUseFallback;
    property UseNoOuter: boolean read GetUseNoOuter;
    property Value: TTaurusTLSECHCLiEnums read FValue write SetValue;
  end;

  TTaurusTLSSslStateFlag  = (
    stfLoop               = 0,    // 1 shl 0  = SSL_CB_LOOP
    stfExit               = 1,    // 1 shl 1  = SSL_CB_EXIT
    stfRead               = 2,    // 1 shl 2  = SSL_CB_READ
    stfWrite              = 3,    // 1 shl 3  = SSL_CB_WRITE
    stfHandShakeStart     = 4,    // 1 shl 4  = SSL_CB_HANDSHAKE_START
    stfHandShakeDone      = 5,    // 1 shl 5  = SSL_CB_HANDSHAKE_DONE
    stfConnect            = 12,   // 1 shl 12 = SSL_ST_CONNECT
    stfAccept             = 13,   // 1 shl 13 = SSL_ST_ACCEPT
    stfAlert              = 14    // 1 shl 14 = SSL_ST_ALERT
  );

  TTaurusTLSSslStateFlags = set of TTaurusTLSSslStateFlag;

  TTaurusTLSSslState = record
  public const
    cLowMin   = Ord(Low(TTaurusTLSSslStateFlag));
    cLowMax   = Ord(stfHandShakeDone);
    cHighMin  = Ord(stfConnect);
    cHighMax  = Ord(High(TTaurusTLSSslStateFlag));
    // Compute contiguously active bits for the low range (0..5): Mask = $3F
    cLowMask  = ((1 shl (cLowMax + 1)) - 1) - ((1 shl cLowMin) - 1);
    // Compute contiguously active bits for the high range (12..14): Mask = $7000
    cHighMask = ((1 shl (cHighMax + 1)) - 1) - ((1 shl cHighMin) - 1);
    // Combining masks: Mask = $703F
    cStateFlagsMask = cLowMask or cHighMask;

  private
    FStates: TIdC_INT;
    FCode: TIdC_INT;
    FSSL: PSSL;
    FStatusMessage: string;
    FAlertMessage: string;

    // property getters
    function GetIsAccept: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsAcceptExit: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsAcceptLoop: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsAlert: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsConnect: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsConnectExit: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsConnectLoop: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsExit: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsHandshakeDone: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsHandshakeStarts: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsInLoop: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsRead: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsReadAlert: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsWrite: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsWriteAlert: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetStateStatusMessage: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetAlertMessage: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetStateFlags: TTaurusTLSSslStateFlags; {$IFDEF USE_INLINE}inline; {$ENDIF}

    procedure Init(const ASSLStates, ACode: TIdC_INT; ASSL: PSSL);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure InitMessages; {$IFDEF USE_INLINE}inline; {$ENDIF}

  public
    constructor Create(const AStates: TTaurusTLSSslStateFlags; const ACode: TIdC_INT;
      ASSL: PSSL); overload;
    constructor Create(const ASSLStates, ACode: TIdC_INT; ASSL: PSSL); overload;

    class function ToInt(const AValue: TTaurusTLSSslStateFlags): TIdC_INT; static;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    property IsConnect: boolean read GetIsConnect;
    property IsAccept: boolean read GetIsAccept;
    property IsInLoop: boolean read GetIsInLoop;
    property IsExit: boolean read GetIsExit;
    property IsAlert: boolean read GetIsAlert;
    property IsRead: boolean read GetIsRead;
    property IsWrite: boolean read GetIsWrite;
    property IsHandshakeStarts: boolean read GetIsHandshakeStarts;
    property IsHandshakeDone: boolean read GetIsHandshakeDone;
    property IsReadAlert: boolean read GetIsReadAlert;
    property IsWriteAlert: boolean read GetIsWriteAlert;
    property IsAcceptLoop: boolean read GetIsAcceptLoop;
    property IsAcceptExit: boolean read GetIsAcceptExit;
    property IsConnectLoop: boolean read GetIsConnectLoop;
    property IsConnectExit: boolean read GetIsConnectExit;

    property StateFlags: TTaurusTLSSslStateFlags read GetStateFlags;
    property StatesAsInt: TIdC_INT read FStates;
    property ErrorCode: TIdC_INT read FCode;
    property StateStatusMessage: string read GetStateStatusMessage;
    property AlertMessage: string read GetAlertMessage;
  end;

  TTaurusTLSSecurityCheckState = record
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FOp: TIdC_INT;
    FBits: TTaurusTLSSecurityBits;
    FNid: TIdC_INT;
    FOther: Pointer;
    FCert: TTaurusTLSX509;

    function GetIsPeer: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsCipher: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsCurve: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsDH: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsPKey: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsSigAlg: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsCert: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetCertificate: TTaurusTLSX509; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetCipherName: string; {$IFDEF USE_INLINE}inline; {$ENDIF}

    function GetNidShortName: string;
    function GetNidLongName: string;
  private
    procedure Destroy; {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    constructor Create(AOp, ABits, ANid: TIdC_INT; AOther: Pointer);

    // Raw OpenSSL property accessors
    property Op: TIdC_INT read FOp;
    property Bits: TTaurusTLSSecurityBits read FBits;
    property Nid: TIdC_INT read FNid;
    property Other: Pointer read FOther; // Raw PX509 or PSSL_CIPHER pointer
    property Certificate: TTaurusTLSX509 read GetCertificate;

    // Bitwise state properties
    property IsPeer: Boolean read GetIsPeer;
    property IsCipher: Boolean read GetIsCipher;
    property IsCurve: Boolean read GetIsCurve;
    property IsDH: Boolean read GetIsDH;
    property IsPKey: Boolean read GetIsPKey;
    property IsSigAlg: Boolean read GetIsSigAlg;
    property IsCert: Boolean read GetIsCert;

    // Cryptographic name properties
    property NidShortName: string read GetNidShortName;
    property NidLongName: string read GetNidLongName;
    property CipherName: string read GetCipherName;
  end;


  // SSL Socket support types and classes
  TTaurusTLSTrustStore = class(TTaurusTLSOSSLStore)
  public const
    cFilter = [sitCert, sitCRL];
  public type
    TStoreItemTypes = TTaurusTLSOSSLStore.TStoreItemTypes;
  private
    FName: string;
  protected
    procedure SetName(const AName: string); {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    constructor Create(const AName: string; const AUri: RawByteString;
      AUiCtx: TTaurusTLS_UICtx); reintroduce; overload; {$IFDEF USE_INLINE}inline; {$ENDIF}
    constructor Create(const AName: string; const AUri: UnicodeString;
      AUiCtx: TTaurusTLS_UICtx); reintroduce; overload; {$IFDEF USE_INLINE}inline; {$ENDIF}
    constructor Create(const AName: string; ABio: TTaurusTLSCustomBIO;
      AUiCtx: TTaurusTLS_UICtx); reintroduce; overload; {$IFDEF USE_INLINE}inline; {$ENDIF}
    constructor CreateMem(const AName: string; AUiCtx: TTaurusTLS_UICtx;
      const AData: TBytes); reintroduce; overload; {$IFDEF USE_INLINE}inline; {$ENDIF}
    constructor CreateMem(const AName: string; AUiCtx: TTaurusTLS_UICtx;
      const AData: string); reintroduce; overload; {$IFDEF USE_INLINE}inline; {$ENDIF}

    property Name: string read FName;
  end;

  TTaurusTLSTrustStores = class(TDictionary<string, TTaurusTLSTrustStore>)
  protected
    procedure CheckStore(const AStore: TTaurusTLSTrustStore);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    procedure Add(const AValue: TTaurusTLSTrustStore);
      reintroduce; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure AddOrSetValue(const AValue: TTaurusTLSTrustStore);
      reintroduce; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function TryAdd(const AValue: TTaurusTLSTrustStore): boolean;
      reintroduce; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function BuildStore: TTaurusTLS_X509Store;
  end;

  // Forward declaration
  TTaurusTLSSslSocket = class;

  // Event type declarations

  TTaurusTLSOnSecurityCheck = procedure(
    ASender: TObject;
    ASocket: TTaurusTLSSslSocket;
    const AState: TTaurusTLSSecurityCheckState;
    var AAccept: Boolean
  ) of object;

  TTaurusTLSOnIOHandlerNotify = procedure(ASender: TObject;
    ASocket: TTaurusTLSSslSocket) of object;

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

  TTaurusTLSOnClientCertCallback = procedure(ASender: TObject;
    ASocket: TTaurusTLSSslSocket; var ACert: PX509; APKey: PEVP_PKEY
  ) of object;

  TTaurusTLSOnECHLog = procedure(ASender: TObject;
    ASocket: TTaurusTLSSslSocket; const AECHLogStr: PAnsiChar) of object;

  TTaurusTLSSSLOp = (sslOpRecvd, sslOpSent);

  TTaurusTLSSslMessage = record
  private
    FOp: TTaurusTLSSSLOp;
    FVersion: TIdC_INT;
    FContentType: TIdC_INT;
    FBuf: PByte;
    FLen: TIdC_SIZET;
    function GetContentTypeStr: string;
    function GetIsPseudoType: Boolean;
    function GetVersion: TTaurusTLS2SslVersion; // PALOFF 'Function result not set'
    function GetMsgDescription: string;

  public
    constructor Create(AWriteP, AVersion, AContentType: TIdC_INT;
      ABuf: pointer; ALen: TIdC_SIZET);
    function ToBytes: TIdBytes;

    property Op: TTaurusTLSSSLOp read FOp;
    property Version: TTaurusTLS2SslVersion read GetVersion;
    property VersionRaw: TIdC_INT read FVersion;
    property ContentType: TIdC_INT read FContentType;
    property ContentTypeStr: string read GetContentTypeStr;
    property Description: string read GetMsgDescription;
    property IsPseudoType: Boolean read GetIsPseudoType;
    property Buffer: PByte read FBuf;
    property Length: TIdC_SIZET read FLen;
  end;

  TTaurusTLSOnSSLMessageCallback = procedure(ASender: TObject;
    ASocket: TTaurusTLSSslSocket; const lMsg: TTaurusTLSSslMessage) of object;

  { TODO : This declararion is a subject to change due to security reason. }
  TTaurusTLSOnKeyLog = procedure(ASender: TObject; ASocket: TTaurusTLSSslSocket;
    ALine: PIdAnsiChar) of object;

  { TODO : This declararion is a subject to change due to future list of parameters change. }
  TTaurusTLSOnSniSelect = procedure(ASender: TObject;
    ASocket: TTaurusTLSSslSocket; var AAlert: TIdC_INT);

  TTaurusTLSAlpnResult = (
    alpnSuccess       = SSL_TLSEXT_ERR_OK,
    alpnFatalAlert    = SSL_TLSEXT_ERR_ALERT_FATAL,
    alpnWarningAlert  = SSL_TLSEXT_ERR_ALERT_WARNING,
    alpnNoAck         = SSL_TLSEXT_ERR_NOACK
  );

  TTaurusTLSAlpnResultHelper = record helper for TTaurusTLSAlpnResult
  private
    function GetAsInt: TIdC_INT;
    procedure SetAsInt(AValue: TIdC_INT);
  public
    constructor Create(AValue: TIdC_INT);
    property AsInt: TIdC_INT read GetAsInt write SetAsInt;
  end;

  TTaurusTLSAlpnSelector = record
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private type
    TAlpnPair = record
      FOffset: PIdC_UINT8;
      FValue: string;
    end;
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FOutProto: PIdC_UINT8;
    FOutLen: TIdC_UINT8;
    FInProtos: PIdC_UINT8;
    FInLen: TIdC_UINT;
    FResultValue: TTaurusTLSAlpnResult;

    // Pre-computed starting offset/Len pairs of each protocol in the raw buffer
    FPairs: TArray<TAlpnPair>;

    function GetCount: TIdC_INT; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetValues(AItem: TIdC_INT): string;
  public
    constructor Create(AInProtos: PIdC_UINT8; AInLen: TIdC_UINT);

    procedure Select(AItem: TIdC_INT);
    procedure Abort; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure Error(AValue: TTaurusTLSAlpnResult); {$IFDEF USE_INLINE}inline; {$ENDIF}

    property Count: TIdC_INT read GetCount;
    property Values[AItem: TIdC_INT]: string read GetValues; default;
    property ResultValue: TTaurusTLSAlpnResult read FResultValue;
    property SelectedProto: PIdC_UINT8 read FOutProto;
    property SelectedProtoLen: TIdC_UINT8 read FOutLen;
  end;

  TTaurusTLSOnAlpnSelect = procedure(ASender: TObject;
    ASocket: TTaurusTLSSslSocket; const AAlpnState: TTaurusTLSAlpnSelector);

  TTaurusTLSOnSslSessionNew = procedure(ASender: TObject;
    const ASession: PSSL_SESSION; var AAccept: boolean);

  TTaurusTLSOnSslSessionRemove = procedure(ASender: TObject;
    ACtx: PSSL_CTX; const ASession: PSSL_SESSION);

  TTaurusTLSSslSocketCtx = class;

  ITaurusTLSSslSocketCtx = interface
  ['{DCD600F0-1D28-482D-A883-A563CFE0D6FC}']
    function GetCtx: TTaurusTLSSslSocketCtx;
    property Ctx: TTaurusTLSSslSocketCtx read GetCtx;
  end;

  TaurusTLSSslSocketCtxFlag = (
    slfFrozen,
    slfClient,
    slfServer,
    slfVerifyHostname,
    slfUniDirectShutdown,
    slfQuietShutdown,
    slfReadAheadBuffering
  );

  TaurusTLSSslSocketCtxFlags = set of TaurusTLSSslSocketCtxFlag;

  TaurusTLSSslSocketCtxFlagsHelper = record helper for TaurusTLSSslSocketCtxFlags
  private
    function GetFlag(const AFlag: TaurusTLSSslSocketCtxFlag): boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    property IsFrozen: boolean index slfFrozen read GetFlag;
    property IsClientSocket: boolean index slfClient read GetFlag;
    property IsServerSocket: boolean index slfServer read GetFlag;
    property VerifyHostName: boolean index slfVerifyHostname read GetFlag;
    property UniDirectShutdown: boolean index slfUniDirectShutdown read GetFlag;
    property QuietShutdown: boolean index slfQuietShutdown read GetFlag;
    property ReadAheadBuffering: boolean index slfReadAheadBuffering read GetFlag;
  end;

  TTaurusTLSMetaX509VerifyParam = class;

  TTaurusTLSSslMaxSendFragment = 512.. SSL3_RT_MAX_PLAIN_LENGTH;

  TTaurusTLSSslSocketCtx = class abstract(TInterfacedObject, ITaurusTLSSslSocketCtx)
  public const
    cVerifyModesDef = [sslvrfPeer];
    cDefaultCtxOptions = [sslOpNoCompression, sslOpEnableMiddleboxCompat];

  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    // For Event parameters
    FSender: TObject;
    FSSLCtx: PSSL_CTX;

    // Common fields
    FSession: PSSL_SESSION;
    FFlags: TaurusTLSSslSocketCtxFlags;
    FCertVerifyFlags: TTaurusTLSVerifyModeFlags;

    // Common Events Events (via SSL_CTX)
    FOnStateChange: TTaurusTLSOnStateChange;
    FOnPeerCertError: TTaurusTLSOnPeerCertError;

    // OpenSSL SSL callback events
    FOnVerifyCertificate: TTaurusTLSOnVerifyCallback;
    FOnSecurityCheck: TTaurusTLSOnSecurityCheck;
    FOnStatusInfo: TTaurusTLSOnSSLStatusInfo;
    FOnMessage: TTaurusTLSOnSSLMessageCallback;
    FOnKeyLog: TTaurusTLSOnKeyLog;

    // SSL_CTX callback method(s)
    class procedure CbCtxKeyLog(const ASSL: PSSL;
      const ALine: PIdAnsiChar); cdecl; static;

    // callback event assignment status flags
    function GetHasOnStatusInfo: boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHasOnSecurityCheck: boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHasOnVerifyCertificate: boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHasOnMessage: boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHasOnKeyLog: boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
  protected
    // IITaurusTLSSocketCtx method(s)
    function GetCtx: TTaurusTLSSslSocketCtx; {$IFDEF USE_INLINE}inline; {$ENDIF}

    class function GetInstanceFromCtx(ACtx: PSSL_CTX): TTaurusTLSSslSocketCtx;
      static; {$IFDEF USE_INLINE}inline; {$ENDIF}

    class function NormalizeHostName(const AValue: RawByteString): RawByteString;
      static; {$IFDEF USE_INLINE}inline; {$ENDIF}

    procedure CheckFrozen; {$IFDEF USE_INLINE}inline; {$ENDIF}

    function GetFlag(const AFlag: TaurusTLSSslSocketCtxFlag): boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    // Event handlers
    procedure DoOnStateChange(ASocket: TTaurusTLSSslSocket;
      AOldState, ANewState: TTaurusTLSSslSocketState); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoOnPeerCertError(ASocket: TTaurusTLSSslSocket;
      ACertificate: TTaurusTLSX509; const AError: TTaurusTLSX509Error;
      var ASuccess: boolean); {$IFDEF USE_INLINE}inline; {$ENDIF}

    // OpenSSL Callback to Event bridges
    procedure DoOnVerifyCertificate(ASocket: TTaurusTLSSslSocket;
      ACtx: PX509_STORE_CTX; var ASuccess, AContinue: boolean);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoOnSecurityCheck(ASocket: TTaurusTLSSslSocket;
      op, bits, nid: TIdC_INT; other: pointer; var AAccept: boolean);
    procedure DoOnStatusInfo(ASocket: TTaurusTLSSslSocket;
      AWhere, ARet: TIdC_INT); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoOnMessage(ASocket: TTaurusTLSSslSocket;
      AWriteP, AVersion, AContentType: TIdC_INT;
      const ABuf: Pointer; ALen: TIdC_SIZET);
    { TODO : This declararion is a subject to change due to security reason. }
    procedure DoOnKeyLog(ASocket: TTaurusTLSSslSocket; ALine: PIdAnsiChar);

    // OpenSSL Callback status checkers
    property HasOnVerifyCertificate: boolean read GetHasOnVerifyCertificate;
    property HasOnSecurityCheck: boolean read GetHasOnSecurityCheck;
    property HasOnStatusInfo: boolean read GetHasOnStatusInfo;
    property HasOnMessage: boolean read GetHasOnMessage;
    property HasOnKeylog: boolean read GetHasOnKeyLog;

    // protected setters
    function SetFlags(const AValue: TaurusTLSSslSocketCtxFlags): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function SetMinTLSVersion(const AValue: TTaurusTLS2TlsVersion): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function SetMaxTLSVersion(const AValue: TTaurusTLS2TlsVersion): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function SetSSLCtxOptions(const AValue: TTaurusTLSSSLOptionFlags): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function SetCipherList(const AValue: string): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function SetCipherSuites(const AValue: string): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function SetKeXGroups(const AValue: string): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function SetSigAlgorithms(const AValue: string): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function SetVerifyModes(const AValue: TTaurusTLSVerifyModes): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function SetVerifyParam(const AValue: TTaurusTLSCustomX509VerifyParam): TTaurusTLSSslSocketCtx;
      overload; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function SetTrustStore(const AValue: TTaurusTLS_X509Store): TTaurusTLSSslSocketCtx;
      overload; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function SetMaxSendFragment(const AValue: TTaurusTLSSslMaxSendFragment): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    function SetOnPeerCertError(const AValue: TTaurusTLSOnPeerCertError): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function SetOnStateChange(const AValue: TTaurusTLSOnStateChange): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function SetOnStatusInfo(const AValue: TTaurusTLSOnSSLStatusInfo): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function SetOnVerifyCertificate(const AValue: TTaurusTLSOnVerifyCallback): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function SetOnSecurityCheck(const AValue: TTaurusTLSOnSecurityCheck): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function SetOnMessage(const AValue: TTaurusTLSOnSSLMessageCallback): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function SetOnKeyLog(const AValue: TTaurusTLSOnKeyLog): TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    { TODO : Add more SSL_CTX setters here. }

    // CtxBuild methods
    procedure InitCtx; virtual;
    procedure ReleaseCtx; virtual;
    procedure DoFreeze;

    property Session: PSSL_SESSION read FSession write FSession;
    property Flags: TaurusTLSSslSocketCtxFlags read FFlags;
    property CertVerifyFlags: TTaurusTLSVerifyModeFlags read FCertVerifyFlags;
    property VerifyHostname: boolean index slfVerifyHostname read GetFlag;
    property UniDirectShutdown: boolean index slfUniDirectShutdown read GetFlag;
    property QuietShutdown: boolean index slfQuietShutdown read GetFlag;
    property ReadAheadBuffering: boolean index slfReadAheadBuffering read GetFlag;

    property OnStateChange: TTaurusTLSOnStateChange read FOnStateChange;
    property OnPeerCertError: TTaurusTLSOnPeerCertError read FOnPeerCertError;
    property OnStatusInfo: TTaurusTLSOnSSLStatusInfo read FOnStatusInfo;
    property OnVerifyCertificate: TTaurusTLSOnVerifyCallback
      read FOnVerifyCertificate;

  public
    constructor Create(ASender: TObject; ATLSMeth: PSSL_METHOD);
    destructor Destroy; override;
    function FreezeCtx: TTaurusTLSSslSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    property Sender: TObject read FSender;
    property SSLCtx: PSSL_CTX read FSSLCtx;
  end;

  TTaurusTLSSslClientCtx = class(TTaurusTLSSslSocketCtx)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FHostname: RawByteString;
    FDefaultSNI: RawByteString;
    FSNIKind: TTaurusTLSSNICliKind;
    FECHFlags: TTaurusTLSECHCliFlags;
    FECHOuterSNI: RawByteString;
    FECHConfigList: RawByteString;
    FIdentity: RawByteString;
    FIdentityIP: boolean;
    FIdentityBuilt: boolean;

    // OpenSSL Callback to Event bridge(s)
    FOnClientCert: TTaurusTLSOnClientCertCallback;
    FOnECHLog: TTaurusTLSOnECHLog;

    class function CbCliCert(ASSL: PSSL; var AX509: PX509;
      var APKey: PEVP_PKEY): TIdC_INT; static; cdecl;

    class function cbEchLog(ASSL: PSSL; const ALogStr: PAnsiChar): TIdC_UINT;
      static; cdecl;

    procedure ResetIdentity; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure BuildIdentity; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetECHKind: TTaurusTLSECHCliKind;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetECHMethods: TTaurusTLSECHCliMeths;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetDefaultSNI: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetECHOuterSNI: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHostName: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetECHConfigList: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIdentity: RawByteString; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsIdentityIP: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetECHNoOuterVal: TIdC_INT; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetUseECH: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetUseGrease: Boolean;
    function GetECHOuterSNIRaw: RawByteString; {$IFDEF USE_INLINE}inline; {$ENDIF}

    function GetHasOnClientCert: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetOnECHLog: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
  protected
    procedure InitCtx; override;
    procedure ReleaseCtx; override;

    // protected setters
    function SetHostName(const AValue: string): TTaurusTLSSslClientCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function SetDefaultSNI(const AValue: string): TTaurusTLSSslClientCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function SetSNIKind(const AValue: TTaurusTLSSNICliKind): TTaurusTLSSslClientCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function SetECHFlags(const AValue: TTaurusTLSECHCliFlags): TTaurusTLSSslClientCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function SetECHOuterSNI(const AValue: string): TTaurusTLSSslClientCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function SetECHConfigList(const AValue: string): TTaurusTLSSslClientCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    function SetOnClientCert(
      const AValue: TTaurusTLSOnClientCertCallback): TTaurusTLSSslClientCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function SetOnECHLog(const AValue: TTaurusTLSOnECHLog): TTaurusTLSSslClientCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    //
    procedure DoOnClientCertCallback(ASocket: TTaurusTLSSslSocket;
      var ACert: PX509; APKey: PEVP_PKEY);

    procedure DoOnECHLogCallback(ASocket: TTaurusTLSSslSocket;
      const ALogStr: PAnsiChar);

  public
    property HasOnClientCert: boolean read GetHasOnClientCert;
    property HasOnECHLog: boolean read GetOnECHLog;
    property HostName: string read GetHostName;
    property DefaultSNI: string read GetDefaultSNI;
    property SNIKind: TTaurusTLSSNICliKind read FSNIKind;
    property ECHFlags: TTaurusTLSECHCliFlags read FECHFlags;
    property ECHKind: TTaurusTLSECHCliKind read GetECHKind;
    property ECHMethod: TTaurusTLSECHCliMeths read GetECHMethods;
    property ECHOuterSNI: string read GetECHOuterSNI;
    property ECHConfigList: string read GetECHConfigList;

    property Identity: RawByteString read GetIdentity;
    property IsIdentityIP: boolean read GetIsIdentityIP;

    property UseECH: Boolean read GetUseECH;
    property UseGREASE: Boolean read GetUseGrease;
    property ECHNoOuterVal: TIdC_INT read GetECHNoOuterVal;

    property HostNameRaw: RawByteString read FHostname;
    property DefaultSNIRaw: RawByteString read FDefaultSNI;
    property ECHOuterSNIRaw: RawByteString read GetECHOuterSNIRaw;
    property ECHConfigListRaw: RawByteString read FECHConfigList;
  end;

  TTaurusTLSSslPeerCtx = class(TTaurusTLSSslSocketCtx)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FOnSniSelect: TTaurusTLSOnSniSelect;
    FOnAlpnSelect: TTaurusTLSOnAlpnSelect;
    FOnSslSessionNew: TTaurusTLSOnSslSessionNew;
    FOnSslSessionRemove: TTaurusTLSOnSslSessionRemove;
  private
    class function CbPeerSniSelect(ASSL: PSSL; var AAlert: Integer;
      AArg: Pointer): TIdC_INT; cdecl; static;
    class function CbPeerAlpnSelect(ASSL: PSSL; var AOut: PIdC_UINT8;
      var AOutLen: TIdC_UINT8; const AIn: PIdC_UINT8;
      AInLen: TIdC_UINT; AArgs: pointer): TIdC_INT; cdecl; static;
    class function CbPeerSslSessionNew(ASSL: PSSL; ASession: PSSL_SESSION): TIdC_INT;
      cdecl; static;
    class procedure CbPeerSslSessionRemove(ACtx: PSSL_CTX;
      ASession: PSSL_SESSION); cdecl; static;

    function GetHasOnPeerSniSelect: boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHasOnPeerAlpnSelect: boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHasOnPeerSslSessionNew: boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHasOnPeerSslSessionRemove: boolean;

  protected
    procedure InitCtx; override;
    procedure ReleaseCtx; override;

    { TODO : This method is subject to change by implementing SNI Contexts Dictionary. }
    procedure DoOnPeerSniSelect(ASocket: TTaurusTLSSslSocket;
      var AAlert: TIdC_INT); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoOnAlpnSelect(ASocket: TTaurusTLSSslSocket;
      var AOut: PIdC_UINT8; var AOutLen: TIdC_UINT8; const AIn: PIdC_UINT8;
      const AInLen: TIdC_UINT; var AResultValue: TIdC_INT);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoOnSSLSessionNew(ASocket: TTaurusTLSSslSocket;
      ASession: PSSL_SESSION; var AAccept: boolean);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoOnSSLSessionRemove(ACtx: PSSL_CTX; ASession: PSSL_SESSION);
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    property OnSniSelect: TTaurusTLSOnSniSelect read FOnSniSelect;
    property OnAlpnSelect: TTaurusTLSOnAlpnSelect read FOnAlpnSelect;
    property OnSSLSessionNew: TTaurusTLSOnSslSessionNew
      read FOnSslSessionNew;
    property OnSSLSessionRemove: TTaurusTLSOnSslSessionRemove
      read FOnSslSessionRemove;
  public
    property HasOnPeerSniSelect: boolean read GetHasOnPeerSniSelect;
    property HasOnPeerAlpnSelect: boolean read GetHasOnPeerAlpnSelect;
    property HasOnPeerSslSessionNew: boolean read GetHasOnPeerSslSessionNew;
    property HasOnPeerSslSessionRemove: boolean read GetHasOnPeerSslSessionRemove;

  end;

  TTaurusTLSSslSocketCtxBuilder = class;

  TTaurusTLSBuilderCustomMetaField = class
  private
    FParent: TTaurusTLSSslSocketCtxBuilder;
  protected
    procedure Lock; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure Unlock; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetDirty; {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    constructor Create(AParent: TTaurusTLSSslSocketCtxBuilder);
    property Parent: TTaurusTLSSslSocketCtxBuilder read FParent;
  end;

  TTaurusTLSMetaX509VerifyParam = class(TTaurusTLSBuilderCustomMetaField)
  protected type
    TProperty = (vfDefSecurityBits, vfDefDepth, vfDefPurpose, vfDefTime,
      vfDefFlVerify, vfDefFlInheritance, vfDefFlHostCheck,
      vfDefHosts, vfDefIPAddresses, vfDefEmails);
    TNonDefaultProps = set of TProperty;

    { TODO :
      To implement concrete TStringList descendants
      with string format validations for host, IPAddress and EMail }
    THosts = TStringList;
    TIPAddresses = TStringList;
    TEmails = TStringList;

  private
    FProps: TNonDefaultProps; //set that indicates non-default property values
    FSecurityBits: TTaurusTLSSecurityBits;
    FDepth: TIdC_INT;
    FPurpose: TTaurusTLSX509Purpose;
    FTime: TDateTime;
    FVerifyFlags: TTaurusTLSX509VerifyFlags;
    FInheritanceFlags: TTaurusTLSX509InheritanceFlags;
    FHostCheckFlags: TTaurusTLSX509HostCheckFlags;
    FHosts: THosts;
    FIPAddresses: TIPAddresses;
    FEMails: TEmails;

  protected
    function IsPropSet(const AProp: TProperty): boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetDirty(const AProp: TProperty); reintroduce;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure ResetProp(const AProp: TProperty); {$IFDEF USE_INLINE}inline; {$ENDIF}

    // Property Setters
    procedure SetSecurityBits(const AValue: TTaurusTLSSecurityBits);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetDepth(const AValue: TIdC_INT); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetPurpose(const AValue: TTaurusTLSX509Purpose);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetTime(const AValue: TDateTime); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetVerifyFlags(const AValue: TTaurusTLSX509VerifyFlags);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetInheritanceFlags(const AValue: TTaurusTLSX509InheritanceFlags);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetHostCheckFlags(const AValue: TTaurusTLSX509HostCheckFlags);
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    procedure AddHost(const AValue: string); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetHost(const Item: TIdC_INT; const AValue: string);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHost(const Item: TIdC_INT): string;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DeleteHost(const Item: TIdC_INT);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHostCount: TIdC_INT;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure AddEMail(const AValue: string); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetEmail(const Item: TIdC_INT; const AValue: string);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetEmail(const Item: TIdC_INT): string;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DeleteEmail(const Item: TIdC_INT);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetEmailCount: TIdC_INT;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure AddIpAddress(const AValue: string); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetIpAddress(const Item: TIdC_INT; const AValue: string);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIpAddress(const Item: TIdC_INT): string;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DeleteIpAddress(const Item: TIdC_INT);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIpAddressCount: TIdC_INT;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    procedure ResetSecurityBits; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure ResetDepth; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure ResetPurspose; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure ResetTime; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure ResetVerifyFlags; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure ResetInheritanceFlags; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure ResetHostCheckFlags; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure ResetHosts; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure ResetIPAddresses; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure ResetEMails; {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    constructor Create(AParent: TTaurusTLSSslSocketCtxBuilder); reintroduce;
    destructor Destroy; override;
    function BuildParam: TTaurusTLSX509VerifyParam;

    property IsSecurityBitsSet: boolean index vfDefSecurityBits read IsPropSet;
    property IsDepthSet: boolean index vfDefDepth read IsPropSet;
    property IsPurposeSet: boolean index vfDefPurpose read IsPropSet;
    property IsTimeSet: boolean index vfDefTime read IsPropSet;
    property IsVerifyFlagsSet: boolean index vfDefFlVerify read IsPropSet;
    property IsInheritanceFlagsSet: boolean index vfDefFlInheritance read IsPropSet;
    property IsHostCheckFlagsSet: boolean index vfDefFlHostCheck read IsPropSet;
    property IsHostsSet: boolean index vfDefHosts read IsPropSet;
    property IsIPAddressesSet: boolean index vfDefIPAddresses read IsPropSet;
    property IsEmailsSet: boolean index vfDefEmails read IsPropSet;

    property VerifyFlags: TTaurusTLSX509VerifyFlags read FVerifyFlags;
    property InheritanceFlags: TTaurusTLSX509InheritanceFlags read FInheritanceFlags;
    property Depth: TIdC_INT read FDepth;
    property SecurityBits: TTaurusTLSSecurityBits read FSecurityBits;
    property Time: TDateTime read FTime;
    property HostCheckFlags: TTaurusTLSX509HostCheckFlags read FHostCheckFlags
      write SetHostCheckFlags;
    property Purpose: TTaurusTLSX509Purpose read FPurpose;
    property Hosts[const Item: TIdC_INT]: string read GetHost; // PALOFF 'Array properties that are referenced/set within methods'
    property HostCount: TIdC_INT read GetHostCount;
    property Emails[const Item: TIdC_INT]: string read GetEmail; // PALOFF 'Array properties that are referenced/set within methods'
    property EmailCount: TIdC_INT read GetEmailCount;
    property IpAddresses[const Item: TIdC_INT]: string read GetIpAddress; // PALOFF 'Array properties that are referenced/set within methods'
    property IpAddressCount: TIdC_INT read GetIpAddressCount;
  end;

  TTaurusTLSSslSocketCtxBuilder = class abstract
  private
    FLock: TIdCriticalSection;
    FTLSMeth: PSSL_METHOD;

    FSocketCtx: ITaurusTLSSslSocketCtx;
    FDirty: boolean;

    // TTaurusTLSSslSocketCtx fields
    FFlags: TaurusTLSSslSocketCtxFlags;
    FVerifyModes: TTaurusTLSVerifyModes;
    FSSLContextOptions: TTaurusTLSSSLOptionFlags;

    // standalone SSL_CTX fields
    FMinTLSVersion: TTaurusTLS2TlsVersion;
    FMaxTLSVersion: TTaurusTLS2TlsVersion;
    FCipherList: string;
    FCipherSuites: string;
    FKeyExchangeGroups: string;
    FSigAlgorithms: string;

    // X509 Verify Params field
    FX509VerifyParam: TTaurusTLSMetaX509VerifyParam; // PALOFF 'Created and freed objects'
    // Trust Stores collection
    FTrustStores: TTaurusTLSTrustStores;

    // FineTuning
    FMaxSendFragment: TTaurusTLSSslMaxSendFragment;

    // Common Events Events (via SSL_CTX)
    FOnStateChange: TTaurusTLSOnStateChange;
    FOnPeerCertError: TTaurusTLSOnPeerCertError;

    // OpenSSL SSL callback events
    FOnVerifyCertificate: TTaurusTLSOnVerifyCallback;
    FOnSecurityCheck: TTaurusTLSOnSecurityCheck;
    FOnStatusInfo: TTaurusTLSOnSSLStatusInfo;
    FOnMessage: TTaurusTLSOnSSLMessageCallback;
    FOnKeyLog: TTaurusTLSOnKeyLog;

    // Property Setters
    function GetFlag(const AFlag: TaurusTLSSslSocketCtxFlag): boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetVerifyHostName: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetUniDirectShutdown: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetQuietShutdown: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetReadAheadBuffering: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetVerifyHostName(const AValue: boolean);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetUniDirectShutdown(const AValue: boolean);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetQuietShutdown(const AValue: boolean);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetReadAheadBuffering(const AValue: boolean);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetSSLContextOptions(const AValue: TTaurusTLSSSLOptionFlags);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetMinTLSVersion(const AValue: TTaurusTLS2TlsVersion);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetMaxTLSVersion(const AValue: TTaurusTLS2TlsVersion);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetCipherList(const AValue: string);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetCipherSuites(const AValue: string);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetKeXGroups(const AValue: string);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetSigAlgorithms(const AValue: string);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetVerifyModes(const AValue: TTaurusTLSVerifyModes);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetTrustStores(AValue: TTaurusTLSTrustStores);
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    // Event setters
    procedure SetOnKeyLog(const AValue: TTaurusTLSOnKeyLog);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetOnMessage(const AValue: TTaurusTLSOnSSLMessageCallback);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetOnPeerCertError(const AValue: TTaurusTLSOnPeerCertError);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetOnSecurityCheck(const AValue: TTaurusTLSOnSecurityCheck);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetOnStateChange(const AValue: TTaurusTLSOnStateChange);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetOnStatusInfo(const AValue: TTaurusTLSOnSSLStatusInfo);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetOnVerifyCertificate(const AValue: TTaurusTLSOnVerifyCallback);
      {$IFDEF USE_INLINE}inline; {$ENDIF}

  protected
    procedure Lock; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure Unlock; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetDirty; {$IFDEF USE_INLINE}inline; {$ENDIF}

    procedure SetFlags(const AValue: TaurusTLSSslSocketCtxFlags);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function IncludeFlags(const AValue: TaurusTLSSslSocketCtxFlags): TaurusTLSSslSocketCtxFlags;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function ExcludeFlags(const AValue: TaurusTLSSslSocketCtxFlags): TaurusTLSSslSocketCtxFlags;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    procedure CheckRequirements; virtual;
    function DoNewSocketCtx(ASender: TObject): TTaurusTLSSslSocketCtx; virtual; abstract;
    procedure DoBuild(ASender: TObject; ASocketCtx: TTaurusTLSSslSocketCtx); virtual;

    property TLSMeth: PSSL_METHOD read FTLSMeth;
  public
    constructor Create(ATLSMeth: PSSL_METHOD);
    destructor Destroy; override;
    function Build(ASender : TObject): ITaurusTLSSslSocketCtx; {$IFDEF USE_INLINE}inline; {$ENDIF}

    property IsDirty: boolean read FDirty;

    // builder own the property instance
    // it can be configuree via X509VerifyParam.xxx properties
    property X509VerifyParam: TTaurusTLSMetaX509VerifyParam read FX509VerifyParam;

    // builder takes ownership on the property instance.
    property TrustedStores: TTaurusTLSTrustStores write SetTrustStores;

    // common properties
    property SSLContextOptions: TTaurusTLSSSLOptionFlags read FSSLContextOptions
      write SetSSLContextOptions;
    property MinTLSVersion: TTaurusTLS2TlsVersion read FMinTLSVersion
      write SetMinTLSVersion;
    property MaxTLSVersion: TTaurusTLS2TlsVersion read FMaxTLSVersion
      write SetMaxTLSVersion;
    property CipherList: string read FCipherList write SetCipherList;
    property CipherSuites: string read FCipherSuites write SetCipherSuites;
    property KeyExchangeGroups: string read FKeyExchangeGroups write SetKeXGroups;
    property SigAlgorithms: string read FSigAlgorithms write SetSigAlgorithms;
    property VerifyModes: TTaurusTLSVerifyModes read FVerifyModes
      write SetVerifyModes;
    property VerifyHostName: boolean read GetVerifyHostName write SetVerifyHostName;
    property UniDirectShutdown: boolean read GetUniDirectShutdown
      write SetUniDirectShutdown;
    property QuietShutdown: boolean read GetQuietShutdown
      write SetQuietShutdown;
    property ReadAheadBuffering: boolean read GetReadAheadBuffering
      write SetReadAheadBuffering;
    property Flags: TaurusTLSSslSocketCtxFlags read FFlags;
    property MaxSendFragment: TTaurusTLSSslMaxSendFragment read FMaxSendFragment
      write FMaxSendFragment default SSL3_RT_MAX_PLAIN_LENGTH;

    // Events
    property OnStateChange: TTaurusTLSOnStateChange read FOnStateChange
      write SetOnStateChange;
    property OnPeerCertError: TTaurusTLSOnPeerCertError read FOnPeerCertError
      write SetOnPeerCertError;
    property OnStatusInfo: TTaurusTLSOnSSLStatusInfo read FOnStatusInfo
      write SetOnStatusInfo;
    property OnVerifyCertificate: TTaurusTLSOnVerifyCallback read FOnVerifyCertificate
      write SetOnVerifyCertificate;
    property OnSecurityCheck: TTaurusTLSOnSecurityCheck read FOnSecurityCheck
      write SetOnSecurityCheck;
    property OnMessage: TTaurusTLSOnSSLMessageCallback read FOnMessage
      write SetOnMessage;
    property OnKeyLog: TTaurusTLSOnKeyLog read FOnKeyLog write SetOnKeyLog;

  end;

  TTaurusECHClientStatus = (echCliNone, echCliSuccess, echCliFailed,
    echCliRetryConfig, echCliNotConfigured);

  TTaurusTLSSslSocket = class
{$IFDEF SIGPIPE_MASK}
{ BUGFIX: Fixes issue #217 and #240 }
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict {$ENDIF}private class var
    /// <summary>
    /// This variable needs to mitigate SIGPIPE crash in Linux environment
    /// This variable is initialized in the <c>class constructor Create</c>
    /// once and used in the methods <c>Accpet</c> and <c>Connect</c> to setup
    /// POSIX thread.
    /// </summary>
    FSigSet: sigset_t;
{$ENDIF}

  public const
    cTerminalStates = [seReleased, seError];
    cDefaultTransitions = 8;

  protected type
    TSocketSelectKind = (sokRead, sokWrite, sokError);
    TSocketSelectKinds = set of TSocketSelectKind;

  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
  {$IFDEF DCC}
    [Volatile]
  {$ENDIF}
    FState: TTaurusTLSSslSocketState;
    FSocketHandle: TIdStackSocketHandle;

    // The Dual-Track State Fields
    FContextIntf: ITaurusTLSSslSocketCtx;  // Holds reference count safely
    FCtx: TTaurusTLSSslSocketCtx;

    // Error Snapshot
    FLastSSLError: TIdC_INT;      // Result of SSL_get_error (e.g. SSL_ERROR_SSL, SSL_ERROR_SYSCALL)
    FLastRetCode: TIdC_INT;       // Return code of SSL_read_ex / SSL_write_ex (e.g. 0 or -1)
    FLastQueueError: TIdC_ULONG;  // Peeked OpenSSL queue error code (via ERR_peek_error)
    FLastSocketError: Integer;    // Captured OS socket error (via GStack.WSGetLastError)

    // SSL Session Resumption flag
    FIsSessionResumed: boolean;

    function GetPeerCertificate: TTaurusTLSX509;       // Fast class pointer

    // OpenSSL callback methods
    class procedure CbSslInfo(const ASSL: PSSL;
      AWhere, ARet: TIdC_INT); static; cdecl;
    class procedure CbSslMessage(AWriteP, AVersion,
      AContentType: TIdC_INT; const ABuf: pointer; ALen: TIdC_SIZET; ASSL: PSSL;
      AArg: Pointer); static; cdecl;
    class function CbSslVerify(const APreVerify: TIdC_INT;
      ACtx: PX509_STORE_CTX): TIdC_INT; static; cdecl;
    class function CbSslSecurityCheck(const ASSL: PSSL; const ACtx: PSSL_CTX;
      AOp, ABits, ANid: TIdC_INT; AOther, AEx: pointer): TIdC_INT; static; cdecl;
    class function CbSrvAlpnSelectCallback(ASSL: PSSL; var AOutProto: PIdAnsiChar;
      var AOutLen: TIdC_UINT8; const AInProtos: PIdAnsiChar;
      AInLen: TIdC_UINT; AArg: Pointer): TIdC_INT; static; cdecl;

    class function CheckForSocketEvent(ASocketHandle: TIdStackSocketHandle;
      AKind: TSocketSelectKinds; AMsec: integer): boolean; static;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

{$IFDEF SIGPIPE_MASK}
{ BUGFIX: Fixes issue #217 and #240 }
    /// <summary>
    /// The <c>MaskSigPipe</c> excludes the POSIX SIGPIPE signal
    /// for the running thread.
    /// </summary>
    class procedure MaskSigPipe;  static; {$IFDEF USE_INLINE}inline; {$ENDIF}
{$ENDIF}

  protected
    FSSL: PSSL;
    class function GetInstanceFromSSL(ASSL: PSSL): TTaurusTLSSslSocket; static;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    function CheckForError: Integer; overload; virtual;
    function GetLastError(ARetCode: Integer): Integer; overload;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetSSLError(ALastResult: Integer): Integer; overload;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure ClearError; {$IFDEF USE_INLINE}inline; {$ENDIF}

    function InitSSL: TTaurusTLSSslSocketState; virtual;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure InitSSLCallbacks; virtual;
    procedure SetupConnection; virtual; abstract;
    function ReleaseSSL: TTaurusTLSSslSocketState; virtual;
    procedure ReleaseSSLCallbacks; virtual;
    function BindSocket: TTaurusTLSSslSocketState; {$IFDEF USE_INLINE}inline; {$ENDIF}

    class function WaitForSocket(ASocketHandle: TIdStackSocketHandle;
      AKind: TSocketSelectKinds; AMsec: integer): boolean; static;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function WaitForRead(AMsec: integer): boolean;  {$IFDEF USE_INLINE}inline; {$ENDIF}
    function WaitForWrite(AMsec: integer): boolean;  {$IFDEF USE_INLINE}inline; {$ENDIF}

    function DoHandshake: TTaurusTLSSslSocketState;
    function DoHandshakeIteration: TTaurusTLSSslSocketState; virtual; abstract;
    function DoShutdown: TTaurusTLSSslSocketState; virtual;

    // State machine
    function IsValidTransition(ACurrent, ATarget: TTaurusTLSSslSocketState): Boolean; virtual;
    procedure CheckActiveState(const AExpectedStates: TTaurusTLSSslSocketStates);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetNextStepTarget(ACurrent,
      ATarget: TTaurusTLSSslSocketState): TTaurusTLSSslSocketState; virtual;
    function DoTransitionTo(ATarget: TTaurusTLSSslSocketState): TTaurusTLSSslSocketState;
      virtual;
    function DoSetState(ATarget: TTaurusTLSSslSocketState): boolean;
      overload; virtual;
    procedure DoSetState(ATarget: TTaurusTLSSslSocketState; ANotify: boolean);
      overload; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoStateChangeNotify(ACurrent, ATarget: TTaurusTLSSslSocketState);
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    property SocketHandle: TIdStackSocketHandle read FSocketHandle write FSocketHandle;
    property IsSessionResumed: boolean read FIsSessionResumed;
    property PeerCertificate: TTaurusTLSX509 read GetPeerCertificate;
  public
{$IFDEF SIGPIPE_MASK}
{ BUGFIX: Fixes issue #217 and #240 }
    /// <summary>
    /// Initialized the <c>FSigSet</c> variable once on application starts.
    /// </summary?
    class constructor Create;
{$ENDIF}
    // Accepts the interface rather than raw class
    constructor Create(const AConfigIntf: ITaurusTLSSslSocketCtx); virtual;
    destructor Destroy; override;

    procedure TransitionTo(ATarget: TTaurusTLSSslSocketState;
      ASteps: integer = cDefaultTransitions); virtual;

    procedure Connect(const pHandle: TIdStackSocketHandle); overload; virtual;
    function Send(const ABuffer: TIdBytes; const AOffset, ALength: TIdC_SIZET;
      const AMSec: Integer): Integer; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function Recv(var ABuffer: TIdBytes; const AMSec: Integer): Integer;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function Readable(AMsec: integer): boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure Shutdown;
    procedure CheckPeerCertificateValidationResult; {$IFDEF USE_INLINE}inline; {$ENDIF}


    property SSL: PSSL read FSSL;
    property State: TTaurusTLSSslSocketState read FState;
    property Ctx: TTaurusTLSSslSocketCtx read FCtx;
  end;

  TTaurusTLSSSLSession = class
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSession: PSSL_SESSION;
  public
    constructor Create(ASocket: TTaurusTLSSslSocket);
    destructor Destroy; override;

    property SSLSession: PSSL_SESSION read FSession;
  end;

  TTaurusTLSClientSocket = class(TTaurusTLSSslSocket)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSessionToResume: TTaurusTLSSSLSession;
    FECHStatus: TTaurusECHClientStatus;
    function GetClientCtx: TTaurusTLSSslClientCtx;
  protected
    procedure SetECHStatus(AECHStatus: TTaurusECHClientStatus);
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    procedure SetupConnection; override;
    procedure SetupHostnameVerification;  {$IFDEF USE_INLINE} inline;{$ENDIF}

    function DoHandshakeIteration: TTaurusTLSSslSocketState; override;
    function DoShutdown: TTaurusTLSSslSocketState; override;
    property ClientCtx: TTaurusTLSSslClientCtx read GetClientCtx;
  public
    procedure Connect(const pHandle: TIdStackSocketHandle;
      ASessionToResume: TTaurusTLSSSLSession); overload;

    property ECHStatus: TTaurusECHClientStatus read FECHStatus;
  end;

  TTaurusTLSPeerSocket = class(TTaurusTLSSslSocket)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
  end;

  // Global support routines

function IsOpenSSLVersion(const AVersion: TTaurusTLSOSSLVersion): boolean;
  {$IFDEF USE_INLINE} inline;{$ENDIF}

function IsECHSupported: boolean; {$IFDEF USE_INLINE} inline;{$ENDIF}

function IsX509StoreMultiIPSupported: boolean; {$IFDEF USE_INLINE} inline;{$ENDIF}

function IsX509StoreMultiEmailSupported: boolean;  {$IFDEF USE_INLINE} inline;{$ENDIF}

implementation

uses
  SyncObjs,
{$IFDEF DCC}
  System.AnsiStrings,
{$ENDIF}
  DateUtils,
  TaurusTLSHeaders_err,
  TaurusTLSHeaders_sslerr,
  TaurusTLSHeaders_objects,
  TaurusTLS_ResourceStrings,
  IdAntifreezeBase,
  IdException,
  IdResourceStrings,
  IdResourceStringsProtocols
{$IFDEF MSWINDOWS}
  ,IdIDN // For IDNToPunnyCode
{$ENDIF}
  ;

const
  cVer40      = $40000000;
  cVerECH     = cVer40;
  cVerMIp     = cVer40;
  cVerMEmail  = cVer40;

function IsOpenSSLVersion(const AVersion: TTaurusTLSOSSLVersion): boolean;
begin
  Result:=OpenSSL_version_num >= AVersion;
end;

function IsECHSupported: boolean;
begin
  Result:=IsOpenSSLVersion(cVerECH);
end;

function IsX509StoreMultiIPSupported: boolean;
begin
  Result:=IsOpenSSLVersion(cVerMIp);
end;

function IsX509StoreMultiEmailSupported: boolean;
begin
  Result:=IsOpenSSLVersion(cVerMEmail);
end;


{ ETaurusTLSSSLSocketError }

class function ETaurusTLSSSLSocketError.TargetSocketState: TTaurusTLSSslSocketState;
begin
  Result:=seError;
end;

{ ETaurusTLSSSLSocketClose }

class function ETaurusTLSSSLSocketClose.TargetSocketState: TTaurusTLSSslSocketState;
begin
  Result:=seReleased;
end;

{ ETaurusTLSCertValidationError }

constructor ETaurusTLSSSLSocketCertValidationError.Create(AVerifyCode: TIdC_LONG;
  const AMessage: string);
begin
  FVerifyCode:=AVerifyCode;
  inherited Create(AMessage);
end;

class procedure ETaurusTLSSSLSocketCertValidationError.RaiseErrorCode(
  AVerifyCode: TIdC_LONG; const AMessage: string);
begin
  Raise ETaurusTLSSSLSocketCertValidationError.Create(AVerifyCode, AMessage);
end;

{ TTaurusTLSECHCliFlags }

function TTaurusTLSECHCliFlags.CheckECHSupported: boolean;
begin
  Result:=IsECHSupported;
  if (not Result) and (ekForceECH in FValue) then
    EECHNotSupported.RaiseWithMessage(RMSG_ECHNotSupported_err);
end;

constructor TTaurusTLSECHCliFlags.Create(const AFlags: TTaurusTLSECHCliEnums);
begin
  SetValue(AFlags);
end;

class function TTaurusTLSECHCliFlags.GetKinds(
  const AValue: TTaurusTLSECHCLiEnums): TTaurusTLSECHCliKinds;
begin
  Result:=AValue*cMaskKind;
end;

class function TTaurusTLSECHCliFlags.GetMethods(
  const AValue: TTaurusTLSECHCLiEnums): TTaurusTLSECHCliMeths;
begin
  if IsECHSupported then
    Result:=AValue*cMaskMethods
  else
    Result:=[];
end;

function TTaurusTLSECHCliFlags.GetKind: TTaurusTLSECHCliKind;
var
  lKinds: TTaurusTLSECHCliKinds;
  i: TTaurusTLSECHCliKind;

begin
  if not CheckECHSupported then
    Exit(ekNoECH);

  lKinds:=GetKinds(FValue);
  for i:=High(TTaurusTLSECHCliKind) downto Low(TTaurusTLSECHCliKind) do
    if i in lKinds then
      Exit(i);
  Result:=ekNoECH;
end;

function TTaurusTLSECHCliFlags.GetMethods: TTaurusTLSECHCliMeths;
begin
  Result:=GetMethods(FValue);
end;

function TTaurusTLSECHCliFlags.GetEnabled: boolean;
begin
  Result:=CheckECHSupported and (GetKinds(FValue)*cMaskEchEnabled <> []);
end;

function TTaurusTLSECHCliFlags.GetEnforced: boolean;
begin
  Result:=CheckECHSupported and (ekForceECH in FValue);
end;

function TTaurusTLSECHCliFlags.GetIsMethSet: boolean;
begin
  Result:=Enabled and (Methods <> []);
end;

function TTaurusTLSECHCliFlags.GetUseConfigList: boolean;
begin
  Result:=Enabled and (emMethECHList in FValue);
end;

function TTaurusTLSECHCliFlags.GetUseGrease: boolean;
begin
  Result:=Enabled and (emMethECHGrease in FValue);
end;

function TTaurusTLSECHCliFlags.GetUseFallback: boolean;
begin
  Result:=Enabled and (cMaskMethods*Methods <> []);
end;

function TTaurusTLSECHCliFlags.GetUseNoOuter: boolean;
begin
  Result:=Enabled and (emMethECHNoOuter in FValue);
end;

class function TTaurusTLSECHCliFlags.IsEnabled(
  const AValue: TTaurusTLSECHCliEnums): boolean;
begin
  Result:=GetKinds(AValue)*cMaskEchEnabled <> [];
end;

procedure TTaurusTLSECHCliFlags.SetValue(const AValue: TTaurusTLSECHCLiEnums);
var
  lValue: TTaurusTLSECHCLiKinds;

begin
  if ekForceECH in AValue then
    lValue:=AValue - [ekNoECH, ekTryECH]
  else if ekTryECH in AValue then
    lValue:=AValue - [ekNoECH]
  else
    lValue:=[ekNoECH];

  if IsEnabled(lValue) and (GetMethods(lValue) <> []) then
    ETaurusTLSECHCliFlagsError.RaiseWithMessage(RMSG_ClientECHFlagsInvalidMethods_err);
  FValue:=lValue;
end;

{ TTaurusTLSSslState }

constructor TTaurusTLSSslState.Create(const ASSLStates, ACode: TIdC_INT;
  ASSL: PSSL);
begin
  Init(ASSLStates, ACode, ASSL);
end;

constructor TTaurusTLSSslState.Create(const AStates: TTaurusTLSSslStateFlags;
  const ACode: TIdC_INT; ASSL: PSSL);
begin
  Init(ToInt(AStates), ACode, ASSL);
end;

procedure TTaurusTLSSslState.Init(const ASSLStates, ACode: TIdC_INT; ASSL: PSSL);
begin
  FStates:=ASSLStates and cStateFlagsMask; // cleanup possible unknown flags
  FCode:=ACode;
  FSSL:=ASSL;
  InitMessages;
end;

procedure TTaurusTLSSslState.InitMessages;
var
  lStatusMessage, lAlertMessage: string;

begin
  FStatusMessage:='';
  FAlertMessage:='';
  lStatusMessage:=AnsiStringToString(SSL_state_string_long(FSSL));
  lAlertMessage:=AnsiStringToString(SSL_alert_type_string_long(FCode));

  case FStates of
    SSL_CB_ALERT:
      begin
        FStatusMessage:=IndyFormat(RSOSSLAlert, [SSL_alert_type_string_long(FCode)]);
        FAlertMessage:=lAlertMessage;
      end;
    SSL_CB_READ_ALERT:
      begin
        FStatusMessage:=IndyFormat(RSOSSLReadAlert,
          [SSL_alert_type_string_long(FCode)]);
        FAlertMessage:=lAlertMessage;
      end;
    SSL_CB_WRITE_ALERT:
      begin
        FStatusMessage:=IndyFormat(RSOSSLWriteAlert, [lAlertMessage]);
        FAlertMessage:=AnsiStringToString(SSL_alert_desc_string_long(FCode));
      end;
    SSL_CB_ACCEPT_LOOP:
      begin
        FStatusMessage:=RSOSSLAcceptLoop;
        FAlertMessage:=lStatusMessage;
      end;
    SSL_CB_ACCEPT_EXIT:
      begin
        if FCode < 0 then
        begin
          FStatusMessage:=RSOSSLAcceptError;
        end
        else
        begin
          if FCode = 0 then
          begin
            FStatusMessage:=RSOSSLAcceptFailed;
          end
          else
          begin
            FStatusMessage:=RSOSSLAcceptExit;
          end;
        end;
        FAlertMessage:=lStatusMessage;
      end;
    SSL_CB_CONNECT_LOOP:
      begin
        FStatusMessage:=RSOSSLConnectLoop;
        FAlertMessage:=lStatusMessage;
      end;
    SSL_CB_CONNECT_EXIT:
      begin
        if FCode < 0 then
        begin
          FStatusMessage:=RSOSSLConnectError;
        end
        else
        begin
          if FCode = 0 then
          begin
            FStatusMessage:=RSOSSLConnectFailed
          end
          else
          begin
            FStatusMessage:=RSOSSLConnectExit;
          end;
        end;
        FAlertMessage:=lStatusMessage;
      end;
    SSL_CB_HANDSHAKE_START:
      begin
        FStatusMessage:=RSOSSLHandshakeStart;
        FAlertMessage:=lStatusMessage;
      end;
    SSL_CB_HANDSHAKE_DONE:
      begin
        FStatusMessage:=RSOSSLHandshakeDone;
        FAlertMessage:=lStatusMessage;
      end;
  end;
end;

class function TTaurusTLSSslState.ToInt(
  const AValue: TTaurusTLSSslStateFlags): TIdC_INT;
begin
{$IF SizeOf(TTaurusTLSSslStateFlags) = 1}
  Result:=PIdC_INT8(@AValue)^ and cStateFlagsMask;
{$ELSEIF SizeOf(TTaurusTLSSslStateFlags) = 2}
  Result:=PIdC_INT16(@AValue)^ and cStateFlagsMask;
{$ELSEIF SizeOf(TTaurusTLSSslStateFlags) = 4}
  Result:=PIdC_INT(@AValue)^ and cStateFlagsMask;
{$IFEND}
end;

function TTaurusTLSSslState.GetIsConnect: boolean;
begin
  Result:=stfConnect in StateFlags;
end;

function TTaurusTLSSslState.GetIsAccept: boolean;
begin
  Result:=stfAccept in StateFlags;
end;

function TTaurusTLSSslState.GetIsInLoop: boolean;
begin
  Result:=stfLoop in StateFlags;
end;

function TTaurusTLSSslState.GetIsAlert: boolean;
begin
  Result:=stfAlert in StateFlags;
end;

function TTaurusTLSSslState.GetIsRead: boolean;
begin
  Result:=stfRead in StateFlags;
end;

function TTaurusTLSSslState.GetIsWrite: boolean;
begin
  Result:=stfWrite in StateFlags;
end;

function TTaurusTLSSslState.GetIsHandshakeStarts: boolean;
begin
  Result:=stfHandShakeStart in StateFlags;
end;

function TTaurusTLSSslState.GetIsHandshakeDone: boolean;
begin
  Result:=stfHandShakeDone in StateFlags;
end;

function TTaurusTLSSslState.GetIsReadAlert: boolean;
begin
  Result:=IsAlert and IsRead;
end;

function TTaurusTLSSslState.GetIsWriteAlert: boolean;
begin
  Result:=IsAlert and IsWrite;
end;

function TTaurusTLSSslState.GetIsAcceptLoop: boolean;
begin
  Result:=IsAccept and IsInLoop;
end;

function TTaurusTLSSslState.GetIsAcceptExit: boolean;
begin
  Result:=IsAccept and IsExit;
end;

function TTaurusTLSSslState.GetIsConnectLoop: boolean;
begin
  Result:=IsConnect and IsInLoop;
end;

function TTaurusTLSSslState.GetIsExit: boolean;
begin
  Result:=stfExit in StateFlags;
end;

function TTaurusTLSSslState.GetIsConnectExit: boolean;
begin
  Result:=IsConnect and IsExit;
end;

function TTaurusTLSSslState.GetStateFlags: TTaurusTLSSslStateFlags;
begin
{$IF SizeOf(TTaurusTLSSslStateFlags) = 1}
  PIdC_INT8(@Result)^:=FStates;
{$ELSEIF SizeOf(TTaurusTLSSslStateFlags) = 2}
  PIdC_INT16(@Result)^:=FStates;
{$ELSEIF SizeOf(TTaurusTLSSslStateFlags) = 4}
  PIdC_INT(@Result)^:=FStates;
{$IFEND}
end;

function TTaurusTLSSslState.GetAlertMessage: string;
begin
  if FAlertMessage = '' then
    InitMessages;
  Result:=FAlertMessage;
end;

function TTaurusTLSSslState.GetStateStatusMessage: string;
begin
  if FStatusMessage = '' then
    InitMessages;
  Result:=FStatusMessage;
end;

{ TTaurusTLSSecurityCheckState }

constructor TTaurusTLSSecurityCheckState.Create(AOp, ABits, ANid: TIdC_INT;
  AOther: Pointer);
begin
  FOp:=AOp;
  FBits.AsInt:=ABits;
  FNid:=ANid;
  FOther:=AOther;
  FCert:=nil;
end;

procedure TTaurusTLSSecurityCheckState.Destroy;
begin
  if Assigned(FCert) then
    FreeAndNil(FCert);
end;

function TTaurusTLSSecurityCheckState.GetIsPeer: Boolean;
begin
  Result:=(FOp and SSL_SECOP_PEER) <> 0;
end;

function TTaurusTLSSecurityCheckState.GetIsCipher: Boolean;
begin
  Result:=(FOp and SSL_SECOP_OTHER_TYPE) = SSL_SECOP_OTHER_CIPHER;
end;

function TTaurusTLSSecurityCheckState.GetIsCurve: Boolean;
begin
  Result:=(FOp and SSL_SECOP_OTHER_TYPE) = SSL_SECOP_OTHER_CURVE;
end;

function TTaurusTLSSecurityCheckState.GetIsDH: Boolean;
begin
  Result:=(FOp and SSL_SECOP_OTHER_TYPE) = SSL_SECOP_OTHER_DH;
end;

function TTaurusTLSSecurityCheckState.GetIsPKey: Boolean;
begin
  Result:=(FOp and SSL_SECOP_OTHER_TYPE) = SSL_SECOP_OTHER_PKEY;
end;

function TTaurusTLSSecurityCheckState.GetIsSigAlg: Boolean;
begin
  Result:=(FOp and SSL_SECOP_OTHER_TYPE) = SSL_SECOP_OTHER_SIGALG;
end;

function TTaurusTLSSecurityCheckState.GetIsCert: Boolean;
begin
  Result:=(FOp and SSL_SECOP_OTHER_TYPE) = SSL_SECOP_OTHER_CERT;
end;

function TTaurusTLSSecurityCheckState.GetNidShortName: string;
var
  lName: PIdAnsiChar;
begin
  Result:='';
  if FNid <> 0 then
  begin
    lName:=OBJ_nid2sn(FNid);
    if Assigned(lName) then
      Result:=AnsiStringToString(lName);
  end;
end;

function TTaurusTLSSecurityCheckState.GetNidLongName: string;
var
  lName: PIdAnsiChar;
begin
  Result:='';
  if FNid <> 0 then
  begin
    lName:=OBJ_nid2ln(FNid);
    if Assigned(lName) then
      Result:=AnsiStringToString(lName);
  end;
end;

function TTaurusTLSSecurityCheckState.GetCipherName: string;
var
  lName: PIdAnsiChar;
begin
  Result:='';
  // Verify that the payload is actually a cipher, and that the pointer is valid
  if IsCipher and Assigned(FOther) then
  begin
    lName:=SSL_CIPHER_get_name(FOther);
    if Assigned(lName) then
      Result:=AnsiStringToString(lName);
  end;
end;

function TTaurusTLSSecurityCheckState.GetCertificate: TTaurusTLSX509;
begin
  if Assigned(FCert) then
    Exit(FCert);

  Result:=nil;
  // Verify that the payload is actually a certificate, and that the pointer is valid
  if IsCert and Assigned(FOther) then
    // Instantiates a non-owning wrapper around the unmanaged X509 pointer.
    // The record instance takes takes ownership of this wrapper.
    // The OnSecurityLevel Event handler MUST NOT FREE the certificate instance.
    Result:=TTaurusTLSX509.Create(FOther, False);
  FCert:=Result;
end;

{ TTaurusTLSTrustStore }

constructor TTaurusTLSTrustStore.Create(const AName: string;
  const AUri: RawByteString; AUiCtx: TTaurusTLS_UICtx);
begin
  inherited Create(AUri, AUiCtx, cFilter);
  SetName(AName);
end;

constructor TTaurusTLSTrustStore.Create(const AName: string;
  const AUri: UnicodeString; AUiCtx: TTaurusTLS_UICtx);
begin
  inherited Create(AUri, AUiCtx, cFilter);
  SetName(AName);
end;

constructor TTaurusTLSTrustStore.Create(const AName: string;
  ABio: TTaurusTLSCustomBIO; AUiCtx: TTaurusTLS_UICtx);
begin
  inherited Create(ABio, AUiCtx, cFilter);
  SetName(AName);
end;

constructor TTaurusTLSTrustStore.CreateMem(const AName: string;
  AUiCtx: TTaurusTLS_UICtx; const AData: string);
var
  lBio: TTaurusTLSRawByteStringBIO; // PALOFF 'Created and freed objects'

begin
  lBio:=TTaurusTLSRawByteStringBIO.Create(RawByteString(AData)); // PALOFF 'TBytes cast to RawByteString' // Why PAL detects AData as  TBytes ???
  try
    Create(AName, lBio, AUiCtx);
  finally
    lBio.Free;
  end;
end;

constructor TTaurusTLSTrustStore.CreateMem(const AName: string;
  AUiCtx: TTaurusTLS_UICtx; const AData: TBytes);
var
  lBio: TTaurusTLSBytesBio;  // PALOFF 'Created and freed objects'

begin
  lBio:=TTaurusTLSBytesBio.Create(AData);
  try
    Create(AName, lBio, AUiCtx);
  finally
    lBio.Free;
  end;
end;

procedure TTaurusTLSTrustStore.SetName(const AName: string);
begin
  FName:=AName;
end;

{ TTaurusTLSTrustStores }

procedure TTaurusTLSTrustStores.CheckStore(const AStore: TTaurusTLSTrustStore);
begin
  Assert(Assigned(AStore), 'AStore must not be ''nil'' value.'); // Do not localize
end;

procedure TTaurusTLSTrustStores.Add(const AValue: TTaurusTLSTrustStore);
begin
  CheckStore(AValue);
  inherited Add(AValue.Name, AValue);
end;

procedure TTaurusTLSTrustStores.AddOrSetValue(
  const AValue: TTaurusTLSTrustStore);
begin
  CheckStore(AValue);
  inherited AddOrSetValue(AValue.Name, AValue);
end;

function TTaurusTLSTrustStores.TryAdd(
  const AValue: TTaurusTLSTrustStore): boolean;
begin
  CheckStore(AValue);
  {$IF Defined(DCC) and (CompilerVersion < 33.0)} // Delph 10.2 and below
  Result:=True;
  try
    inherited Add(AValue.Name, AValue)
  except
    Result:=False; // Do not re-raise the exception
  end;
  {$ELSE}
  Result:=inherited TryAdd(AValue.Name, AValue);
  {$IFEND}
end;

function TTaurusTLSTrustStores.BuildStore: TTaurusTLS_X509Store;
var
  lStorePair: TPair<string, TTaurusTLSTrustStore>;

begin
  Result:=TTaurusTLS_X509Store.Create;
  try
    for lStorePair in Self do
      Result.AppendFromOsslStore(lStorePair.Value, [sitCert, sitCRL]);
  except
    FreeAndNil(Result);
    raise;
  end;
end;

{ TTaurusTLSSslMessage }

constructor TTaurusTLSSslMessage.Create(AWriteP, AVersion,
  AContentType: TIdC_INT; ABuf: pointer; ALen: TIdC_SIZET);
begin
  FVersion:=AVersion;
  FContentType:=AContentType;
  FBuf:=ABuf;
  FLen:=ALen;
  if AWriteP = 0 then
    FOp:=sslOpRecvd
  else
    FOp:=sslOpSent;
end;

function TTaurusTLSSslMessage.GetContentTypeStr: string;
begin
  // Do not localize below
  case FContentType of
    // Standard TLS Record Types
    SSL3_RT_CHANGE_CIPHER_SPEC:    Result:='Change Cipher Spec';
    SSL3_RT_ALERT:                 Result:='Alert';
    SSL3_RT_HANDSHAKE:             Result:='Handshake';
    SSL3_RT_APPLICATION_DATA:      Result:='Application Data';

    // Record Header & Inner Decoys
    SSL3_RT_HEADER:                Result:='Record Header';
    SSL3_RT_INNER_CONTENT_TYPE:    Result:='Decrypted Inner Content Type';

    // QUIC Frame Tracing
    SSL3_RT_QUIC_DATAGRAM:         Result:='QUIC Datagram';
    SSL3_RT_QUIC_PACKET:           Result:='QUIC Packet';
    SSL3_RT_QUIC_FRAME_FULL:       Result:='QUIC Frame (Full)';
    SSL3_RT_QUIC_FRAME_HEADER:     Result:='QUIC Frame (Header)';
    SSL3_RT_QUIC_FRAME_PADDING:    Result:='QUIC Frame (Padding)';

    // Cryptographic Keys & Secrets Tracing
    TLS1_RT_CRYPTO_PREMASTER:      Result:='Crypto: Premaster Secret';
    TLS1_RT_CRYPTO_CLIENT_RANDOM:  Result:='Crypto: Client Random';
    TLS1_RT_CRYPTO_SERVER_RANDOM:  Result:='Crypto: Server Random';
    TLS1_RT_CRYPTO_MASTER:         Result:='Crypto: Master Secret';
    TLS1_RT_CRYPTO_MAC:            Result:='Crypto: MAC Key';
    TLS1_RT_CRYPTO_KEY:            Result:='Crypto: Encryption Key';
    TLS1_RT_CRYPTO_IV:             Result:='Crypto: Initialization Vector (IV)';
    TLS1_RT_CRYPTO_FIXED_IV:       Result:='Crypto: Fixed IV';
  else
    Result:='Unknown (0x' + IntToHex(FContentType, 2) + ')';
  end;end;

function TTaurusTLSSslMessage.GetIsPseudoType: Boolean;
begin
  Result:=FContentType >= SSL3_RT_HEADER;
end;

function TTaurusTLSSslMessage.GetMsgDescription: string;
var
  LAlertLevel: Byte;
  LAlertDesc: Byte;
  LLevelStr: string;
  LDescStr: string;
begin
  Result:='';

  if (FContentType = SSL3_RT_ALERT) and Assigned(FBuf) and (FLen >= 2) then
  begin
    LAlertLevel:=PByte(FBuf)^;
    LAlertDesc:=PByte(NativeUInt(FBuf) + 1)^;

    // 1. Resolve Alert Level using standard constants
    case LAlertLevel of
      SSL3_AL_WARNING: LLevelStr:='Warning';
      SSL3_AL_FATAL:   LLevelStr:='Fatal';
    else
      LLevelStr:=Format('Unknown Level (%d)', [LAlertLevel]);
    end;

    // 2. Resolve Alert Description natively from OpenSSL
    LDescStr:=AnsiStringToString(SSL_alert_desc_string_long(LAlertDesc));

    Result:=Format('Alert [Level: %s, Desc: %d (%s)]',
      [LLevelStr, LAlertDesc, LDescStr]);
  end
  else if (FContentType = SSL3_RT_INNER_CONTENT_TYPE) and (FLen > 0) and Assigned(FBuf) then
  begin
    // TLS 1.3 Decrypted Inner Content Type indicator
    Result:=Format('Decrypted Inner Type: %d', [PByte(FBuf)^]);
  end
  else if (FContentType = DTLS1_RT_HEARTBEAT) and (FLen > 0) and Assigned(FBuf) then
  begin
    // Heartbeat Protocol frame type (RFC 6520)
    case PByte(FBuf)^ of
      TLS1_HB_REQUEST:  Result:='Heartbeat Request';
      TLS1_HB_RESPONSE: Result:='Heartbeat Response';
    else
      Result:='Heartbeat Unknown';
    end;
  end;
end;

function TTaurusTLSSslMessage.GetVersion: TTaurusTLS2SslVersion;
begin
  Result.AsInt:=FVersion;  // PALOFF 'Function result not set'
end;

function TTaurusTLSSslMessage.ToBytes: TIdBytes;
begin
  if Assigned(FBuf) and (FLen > 0) then
  begin
    SetLength(Result, FLen);
    Move(FBuf^, Result[0], FLen);
  end
  else
    Result:=[];
end;

{ TTaurusTLSAlpnResultHelper }

constructor TTaurusTLSAlpnResultHelper.Create(AValue: TIdC_INT);
begin
  AsInt:=AValue;
end;

function TTaurusTLSAlpnResultHelper.GetAsInt: TIdC_INT;
begin
  Result:=Ord(Self);
end;

procedure TTaurusTLSAlpnResultHelper.SetAsInt(AValue: TIdC_INT);
begin
  { TODO : Make a ResourceString for Exception call }
  if not (AValue in [Ord(Low(TTaurusTLSAlpnResult))..Ord(High(TTaurusTLSAlpnResult))]) then
    ETaurusTLSAlpnResultError.RaiseWithMessageFmt(
      { TODO : To make ResourceString }
      'Invalid ALPN result value: %d.', [AValue]);
  Self:=TTaurusTLSAlpnResult(AValue);
end;

{ TTaurusTLSAlpnSelector }
// The conditional compilation option below is not supported on all Delphi versions
//{$IFOPT POINTERMATH OFF}
//  {$DEFINE ENABLE_POINTERMATH}
//  {$POINTERMATH ON}
//{$ENDIF}

// So we have to replace them with the simple defines
{$DEFINE ENABLE_POINTERMATH}
{$POINTERMATH ON}
constructor TTaurusTLSAlpnSelector.Create(AInProtos: PIdC_UINT8; AInLen: TIdC_UINT);
var
  lPair: TAlpnPair;
  lPos: PIdC_UINT8;
  lLen: TIdC_UINT8;
  lCount: TIdC_INT;

begin
  FOutProto:=nil;
  FOutLen:=0;
  FInProtos:=AInProtos;
  FInLen:=AInLen;
  FResultValue:=alpnFatalAlert;

  SetLength(FPairs, 0);
  if not (Assigned(AInProtos) and (AInLen > 0)) then
    Exit;

  SetLength(FPairs, AInLen); // making largest possible array, then shrink it.
  lPos:=AInProtos;
  lCount:=0;
  repeat
    lLen:=PIdC_UINT8(lPos)^;
    if lLen = 0 then
      ETaurusTLSAlpnResultError.RaiseWithMessage(
        { TODO : To make ResourceString }
        'ALPN Input list corrupted. Unexpected Zero Length element found.');

    Inc(lPos);
    lPair.FOffset:=lPos;
    if ((lPos-AInProtos)+lLen) > NativeInt(AInLen) then // Boundary check
      ETaurusTLSAlpnResultError.RaiseWithMessage(
        { TODO : To make ResourceString }
        'ALPN Input list corrupted. Element length is out input bounds.');

    SetString(lPair.FValue, PIdAnsiChar(lPos), lLen); // PALOFF PIdC_UINT8 cast to PIdAnsiChar
    FPairs[lCount]:=lPair;

    Inc(lCount);
    Inc(lPos, lLen);
  until (lPos-AInProtos) >= NativeInt(AInLen);

  SetLength(FPairs, lCount);
  FResultValue:=alpnNoAck;
end;
{$IFDEF ENABLE_POINTERMATH}
  {$UNDEF ENABLE_POINTERMATH}
  {$POINTERMATH OFF}
{$ENDIF}

procedure TTaurusTLSAlpnSelector.Abort;
begin
  FResultValue:=alpnNoAck;
end;

procedure TTaurusTLSAlpnSelector.Error(AValue: TTaurusTLSAlpnResult);
begin
  FResultValue:=AValue;
end;

function TTaurusTLSAlpnSelector.GetCount: TIdC_INT;
begin
  Result:=Length(FPairs);
end;

function TTaurusTLSAlpnSelector.GetValues(AItem: TIdC_INT): string;
begin
  Result:=FPairs[AItem].FValue;
end;

procedure TTaurusTLSAlpnSelector.Select(AItem: TIdC_INT);
var
  lPair: TAlpnPair;

begin
  if (AItem < 0) or (AItem > (Count-1)) then
    { TODO : To make ResourceString }
    raise ERangeError.CreateFmt('ALPN selection index out of range: %d.', [AItem]);

  lPair:=FPairs[AItem];
  FOutProto:=lPair.FOffset;
  FOutLen:=Length(lPair.FValue);
  FResultValue:=alpnSuccess;
end;

{ TaurusTLSSslSocketCtxFlagsHelper }

function TaurusTLSSslSocketCtxFlagsHelper.GetFlag(
  const AFlag: TaurusTLSSslSocketCtxFlag): boolean;
begin
  Result:=AFlag in Self;
end;

{ TTaurusTLSSslSocketCtxBuilder }

constructor TTaurusTLSSslSocketCtxBuilder.Create(ATLSMeth: PSSL_METHOD);
begin
  inherited Create;
  SetDirty;
  FTLSMeth:=ATLSMeth;
  FX509VerifyParam:=TTaurusTLSMetaX509VerifyParam.Create(Self);
end;

destructor TTaurusTLSSslSocketCtxBuilder.Destroy;
begin
  try
    Lock;
    FSocketCtx:=nil;
  finally
    Unlock;
    FreeAndNil(FLock);
  end;
  inherited;
end;

procedure TTaurusTLSSslSocketCtxBuilder.Lock;
begin
  FLock.Enter;
end;

procedure TTaurusTLSSslSocketCtxBuilder.Unlock;
begin
  FLock.Leave;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetDirty;
begin
  FDirty:=True;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetFlags(
  const AValue: TaurusTLSSslSocketCtxFlags);
begin
  if FFlags = AValue then
    Exit;

  Lock;
  try
    // Check it again it can be changed by other thread
    // between previous check and actual lock accurision
    if FFlags = AValue then
      Exit;
    FFlags:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

function TTaurusTLSSslSocketCtxBuilder.IncludeFlags(
  const AValue: TaurusTLSSslSocketCtxFlags): TaurusTLSSslSocketCtxFlags;
begin
  if (FFlags * AValue) = AValue then
    Exit;

  Lock;
  try
    // Check it again it can be changed by other thread
    // between previous check and actual lock accurision
    if (FFlags * AValue) = AValue then
      Exit(FFlags);
    Result:=FFlags+AValue;
    FFlags:=Result;
    SetDirty;
  finally
    Unlock;
  end;
end;

function TTaurusTLSSslSocketCtxBuilder.ExcludeFlags(
  const AValue: TaurusTLSSslSocketCtxFlags): TaurusTLSSslSocketCtxFlags;
begin
  if (FFlags * AValue) = [] then
    Exit;

  Lock;
  try
    // Check it again it can be changed by other thread
    // between previous check and actual lock accurision
    if (FFlags * AValue) = [] then
      Exit(FFlags);
    Result:=FFlags-AValue;
    FFlags:=Result;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetVerifyModes(
  const AValue: TTaurusTLSVerifyModes);
begin
  if FVerifyModes = AValue then
    Exit;

  Lock;
  try
    // Check it again it can be changed by other thread
    // between previous check and actual lock accurision
    if FVerifyModes = AValue then
      Exit;
    FVerifyModes:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetSSLContextOptions(
  const AValue: TTaurusTLSSSLOptionFlags);
begin
  if FSSLContextOptions = AValue then
    Exit;

  Lock;
  try
    // Check it again it can be changed by other thread
    // between previous check and actual lock accurision
    if FSSLContextOptions = AValue then
      Exit;
    FSSLContextOptions:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetTrustStores(
  AValue: TTaurusTLSTrustStores);
begin
  if FTrustStores = AValue then
    Exit;

  Lock;
  try
    // Check it again it can be changed by other thread
    // between previous check and actual lock accurision
    if FTrustStores = AValue then
      Exit;
    FTrustStores:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetMinTLSVersion(
  const AValue: TTaurusTLS2TlsVersion);
begin
  if FMinTLSVersion = AValue then
    Exit;

  Lock;
  try
    // Check it again it can be changed by other thread
    // between previous check and actual lock accurision
    if FMinTLSVersion = AValue then
      Exit;
    FMinTLSVersion:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetMaxTLSVersion(
  const AValue: TTaurusTLS2TlsVersion);
begin
  if FMaxTLSVersion = AValue then
    Exit;

  Lock;
  try
    // Check it again it can be changed by other thread
    // between previous check and actual lock accurision
    if FMaxTLSVersion = AValue then
      Exit;
    FMaxTLSVersion:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetCipherList(const AValue: string);
begin
  if FCipherList = AValue then
    Exit;

  Lock;
  try
    // Check it again it can be changed by other thread
    // between previous check and actual lock accurision
    if FCipherList = AValue then
      Exit;
    FCipherList:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetCipherSuites(const AValue: string);
begin
  if FCipherSuites = AValue then
    Exit;

  Lock;
  try
    // Check it again it can be changed by other thread
    // between previous check and actual lock accurision
    if FCipherSuites = AValue then
      Exit;
    FCipherSuites:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetKeXGroups(const AValue: string);
begin
  if FKeyExchangeGroups = AValue then
    Exit;

  Lock;
  try
    // Check it again it can be changed by other thread
    // between previous check and actual lock accurision
    if FKeyExchangeGroups = AValue then
      Exit;
    FKeyExchangeGroups:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetSigAlgorithms(const AValue: string);
begin
  if FSigAlgorithms = AValue then
    Exit;

  Lock;
  try
    // Check it again it can be changed by other thread
    // between previous check and actual lock accurision
    if FSigAlgorithms = AValue then
      Exit;
    FSigAlgorithms:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetVerifyHostName(const AValue: boolean);
begin
  if AValue then
    IncludeFlags([slfVerifyHostname])
  else
    ExcludeFlags([slfVerifyHostname]);
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetUniDirectShutdown(
  const AValue: boolean);
begin
  Lock;
  try
    if AValue then
    begin
      Include(FFlags, slfUniDirectShutdown);
      Exclude(FFlags, slfQuietShutdown);
    end
    else
      Exclude(FFlags, slfUniDirectShutdown);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetQuietShutdown(const AValue: boolean);
begin
  Lock;
  try
    if AValue then
    begin
      Include(FFlags, slfQuietShutdown);
      Exclude(FFlags, slfUniDirectShutdown);
    end
    else
      Exclude(FFlags, slfQuietShutdown);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetReadAheadBuffering(
  const AValue: boolean);
begin
  if AValue then
    IncludeFlags([slfReadAheadBuffering])
  else
    ExcludeFlags([slfReadAheadBuffering]);
end;

function TTaurusTLSSslSocketCtxBuilder.GetFlag(
  const AFlag: TaurusTLSSslSocketCtxFlag): boolean;
begin
  Lock;
  try
    Result:=FFlags.GetFlag(AFlag);
  finally
    Unlock;
  end;
end;

function TTaurusTLSSslSocketCtxBuilder.GetQuietShutdown: boolean;
begin
  Result:=GetFlag(slfQuietShutdown);
end;

function TTaurusTLSSslSocketCtxBuilder.GetUniDirectShutdown: boolean;
begin
  Result:=GetFlag(slfUniDirectShutdown);
end;

function TTaurusTLSSslSocketCtxBuilder.GetVerifyHostName: boolean;
begin
  Result:=GetFlag(slfVerifyHostname);
end;

function TTaurusTLSSslSocketCtxBuilder.GetReadAheadBuffering: boolean;
begin
  Result:=GetFlag(slfReadAheadBuffering);
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetOnKeyLog(
  const AValue: TTaurusTLSOnKeyLog);
begin
  Lock;
  try
    if (TMethod(FOnKeyLog).Code = TMethod(AValue).Code) and
      (TMethod(FOnKeyLog).Data = TMethod(AValue).Data) then
      Exit;
    FOnKeyLog:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetOnMessage(
  const AValue: TTaurusTLSOnSSLMessageCallback);
begin
  Lock;
  try
    if (TMethod(FOnMessage).Code = TMethod(AValue).Code) and
      (TMethod(FOnMessage).Data = TMethod(AValue).Data) then
      Exit;
    FOnMessage:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetOnPeerCertError(
  const AValue: TTaurusTLSOnPeerCertError);
begin
  Lock;
  try
    if (TMethod(FOnPeerCertError).Code = TMethod(AValue).Code) and
      (TMethod(FOnPeerCertError).Data = TMethod(AValue).Data) then
      Exit;
    FOnPeerCertError:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetOnSecurityCheck(
  const AValue: TTaurusTLSOnSecurityCheck);
begin
  Lock;
  try
    if (TMethod(FOnSecurityCheck).Code = TMethod(AValue).Code) and
      (TMethod(FOnSecurityCheck).Data = TMethod(AValue).Data) then
      Exit;
    FOnSecurityCheck:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetOnStateChange(
  const AValue: TTaurusTLSOnStateChange);
begin
  Lock;
  try
    if (TMethod(FOnStateChange).Code = TMethod(AValue).Code) and
      (TMethod(FOnStateChange).Data = TMethod(AValue).Data) then
      Exit;
    FOnStateChange:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetOnStatusInfo(
  const AValue: TTaurusTLSOnSSLStatusInfo);
begin
  Lock;
  try
    if (TMethod(FOnStatusInfo).Code = TMethod(AValue).Code) and
      (TMethod(FOnStatusInfo).Data = TMethod(AValue).Data) then
      Exit;
    FOnStatusInfo:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.SetOnVerifyCertificate(
  const AValue: TTaurusTLSOnVerifyCallback);
begin
  Lock;
  try
    if (TMethod(FOnVerifyCertificate).Code = TMethod(AValue).Code) and
      (TMethod(FOnVerifyCertificate).Data = TMethod(AValue).Data) then
      Exit;
    FOnVerifyCertificate:=AValue;
    SetDirty;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.CheckRequirements;
begin
// Do nothing. Descendant may implement own requirement check.
end; // PALOFF 'Empty begin/end-blocks'

procedure TTaurusTLSSslSocketCtxBuilder.DoBuild(ASender: TObject;
  ASocketCtx: TTaurusTLSSslSocketCtx);
var
  lVerifyParam: TTaurusTLSX509VerifyParam; // PALOFF 'Created and freed objects'
  lTrustStore: TTaurusTLS_X509Store; // PALOFF 'Created and freed objects'

begin
  Assert(Assigned(ASender), '''ASender'' parameter must not be ''nil'' value.'); // Do not localize
  Assert(Assigned(ASocketCtx),
    '''ASocketCtx'' parameter must not be ''nil'' value.'); // Do not localize

  lVerifyParam:=nil;
  lTrustStore:=nil;
  try
    lVerifyParam:=FX509VerifyParam.BuildParam;
    lTrustStore:=FTrustStores.BuildStore;
    ASocketCtx
    // Set Context Parameters
      .SetFlags(FFlags)
      .SetMinTLSVersion(FMinTLSVersion)
      .SetMaxTLSVersion(FMaxTLSVersion)
      .SetCipherList(FCipherList)
      .SetCipherSuites(FCipherSuites)
      .SetKeXGroups(FKeyExchangeGroups)
      .SetSigAlgorithms(FSigAlgorithms)
      .SetVerifyModes(FVerifyModes)
      .SetMaxSendFragment(FMaxSendFragment)
      .SetSSLCtxOptions(FSSLContextOptions)
      .SetVerifyParam(lVerifyParam)
      .SetTrustStore(lTrustStore)
    // Set Context Events
      .SetOnStateChange(FOnStateChange)
      .SetOnPeerCertError(FOnPeerCertError)
      .SetOnVerifyCertificate(FOnVerifyCertificate)
      .SetOnSecurityCheck(FOnSecurityCheck)
      .SetOnStatusInfo(FOnStatusInfo)
      .SetOnMessage(FOnMessage)
      .SetOnKeyLog(FOnKeyLog); // PALOFF 'Functions called as procedures'
  finally
    lTrustStore.Free;
    lVerifyParam.Free;
  end;
end;

function TTaurusTLSSslSocketCtxBuilder.Build(ASender: TObject): ITaurusTLSSslSocketCtx;
var
  lSocketCtx: TTaurusTLSSslSocketCtx; // PALOFF 'Created and freed objects'

begin
  Lock;
  try
    if (not IsDirty) and Assigned(FSocketCtx) then
      Exit(FSocketCtx);

    CheckRequirements;
    lSocketCtx:=DoNewSocketCtx(ASender);
    Result:=lSocketCtx as ITaurusTLSSslSocketCtx; // PALOFF 'Mixing interface variables and objects'
    DoBuild(ASender, lSocketCtx);

      // The final SocketCTX configuration lock.
    lSocketCtx.FreezeCtx;
    FSocketCtx:=Result;
  finally
    Unlock;
  end;
end;

{ TTaurusTLSSslSocketCtx }

constructor TTaurusTLSSslSocketCtx.Create(ASender: TObject; ATLSMeth: PSSL_METHOD);
begin
  FSender:=ASender;
  FSSLCtx:=SSL_CTX_new(ATLSMeth);
//  SetVerifyModes(cVerifyModesDef);   // PALOFF 'Functions called as procedures'
end;

destructor TTaurusTLSSslSocketCtx.Destroy;
begin
  ReleaseCtx;
  SSL_CTX_free(FSSLCtx);
  inherited;
end;

function TTaurusTLSSslSocketCtx.FreezeCtx: TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  InitCtx;
  DoFreeze;
end;

procedure TTaurusTLSSslSocketCtx.DoFreeze;
begin
  Include(FFlags, slfFrozen);
end;

class procedure TTaurusTLSSslSocketCtx.CbCtxKeyLog(const ASSL: PSSL;
  const ALine: PIdAnsiChar);
var
  lInstance: TTaurusTLSSslSocket;
  lConfig: TTaurusTLSSslSocketCtx;
  lErr: integer;

begin
  if not Assigned(ASSL) then // this shouldn't happen ever
    Exit;
  try
    lErr:=GStack.WSGetLastError;
    try
      lInstance:=TTaurusTLSSslSocket.GetInstanceFromSSL(ASSL);
      if not Assigned(lInstance) then
        Exit;

      lConfig:=lInstance.Ctx;
      if Assigned(lConfig) then
        lConfig.DoOnKeyLog(lInstance, ALine);
    finally
      GStack.WSSetLastError(lErr);
    end;
  except //PALOFF "Empty except-block"
    // We must not raise the exception to the OpenSSL stack
  end;
end;

procedure TTaurusTLSSslSocketCtx.CheckFrozen;
begin
  if FLags.IsFrozen then
    ETaurusTLSSslSocketCtxError.RaiseWithMessage(
      { TODO : To make ResourceString }
      'TTaurusTLSSslSocketCtx instance is frozen and cannot be modified.');
end;

procedure TTaurusTLSSslSocketCtx.DoOnKeyLog(ASocket: TTaurusTLSSslSocket;
  ALine: PIdAnsiChar);
begin
  if Assigned(FOnKeyLog) then
    FOnKeyLog(FSender, ASocket, ALine);
end;

procedure TTaurusTLSSslSocketCtx.DoOnMessage(ASocket: TTaurusTLSSslSocket;
  AWriteP, AVersion, AContentType: TIdC_INT; const ABuf: Pointer; ALen: TIdC_SIZET);
var
  lMsg: TTaurusTLSSslMessage; // PALOFF 'Created and freed objects'

begin
  if not Assigned(FOnMessage) then
    Exit;
  lMsg:=TTaurusTLSSslMessage.Create(AWriteP, AVersion, AContentType, ABuf, ALen);
  FOnMessage(FSender, ASocket, lMsg);
end;

procedure TTaurusTLSSslSocketCtx.DoOnPeerCertError(ASocket: TTaurusTLSSslSocket;
  ACertificate: TTaurusTLSX509; const AError: TTaurusTLSX509Error;
  var ASuccess: boolean);
begin
  if Assigned(FOnPeerCertError) and Assigned(ASocket) then
    FOnPeerCertError(FSender, ASocket, ACertificate, AError, ASuccess);
end;

procedure TTaurusTLSSslSocketCtx.DoOnStateChange(ASocket: TTaurusTLSSslSocket;
  AOldState, ANewState: TTaurusTLSSslSocketState);
begin
  if Assigned(FOnStateChange) then
    FOnStateChange(FSender, ASocket, AOldState, ANewState);
end;

procedure TTaurusTLSSslSocketCtx.DoOnStatusInfo(ASocket: TTaurusTLSSslSocket;
  AWhere, ARet: TIdC_INT);
var
  lState: TTaurusTLSSslState;

begin
  if not Assigned(FOnStatusInfo) then
    Exit;

  lState:=TTaurusTLSSslState.Create(AWhere, ARet, ASocket.SSL);
  FOnStatusInfo(FSender, ASocket, lState);
end;

procedure TTaurusTLSSslSocketCtx.DoOnVerifyCertificate(ASocket: TTaurusTLSSslSocket;
  ACtx: PX509_STORE_CTX; var ASuccess, AContinue: boolean);
var
  lValidator: TTaurusTLSX509CertValidator; // PALOFF 'Created and freed objects'

begin
  if not (Assigned(FOnVerifyCertificate) and Assigned(ACtx)) then
    Exit;

  lValidator:=TTaurusTLSX509CertValidator.Create(ACtx);
  try
    FOnVerifyCertificate(FSender, ASocket, lValidator, ASuccess, AContinue);
  finally
    lValidator.Free;
  end;
end;

procedure TTaurusTLSSslSocketCtx.DoOnSecurityCheck(ASocket: TTaurusTLSSslSocket;
  op, bits, nid: TIdC_INT; other: pointer; var AAccept: boolean);
var
  lState: TTaurusTLSSecurityCheckState;

begin
  if not Assigned(FOnSecurityCheck) then
    Exit;
  lState:=TTaurusTLSSecurityCheckState.Create(op,bits,nid, other);
  try
    FOnSecurityCheck(FSender, ASocket, lState, AAccept);
  finally
    lState.Destroy;
  end;
end;

function TTaurusTLSSslSocketCtx.GetHasOnStatusInfo: boolean;
begin
  Result:=Assigned(FOnStatusInfo);
end;

// ITaurusTLSSslSocketCtx
function TTaurusTLSSslSocketCtx.GetCtx: TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
end;

function TTaurusTLSSslSocketCtx.GetFlag(
  const AFlag: TaurusTLSSslSocketCtxFlag): boolean;
begin
  Result:=FFlags.GetFlag(AFlag);
end;

function TTaurusTLSSslSocketCtx.GetHasOnKeyLog: boolean;
begin
  Result:=Assigned(FOnKeyLog);
end;

function TTaurusTLSSslSocketCtx.GetHasOnMessage: boolean;
begin
  Result:=Assigned(FOnMessage);
end;

function TTaurusTLSSslSocketCtx.GetHasOnSecurityCheck: boolean;
begin
  Result:=Assigned(FOnSecurityCheck);
end;

function TTaurusTLSSslSocketCtx.GetHasOnVerifyCertificate: boolean;
begin
  Result:=Assigned(FOnVerifyCertificate);
end;

class function TTaurusTLSSslSocketCtx.GetInstanceFromCtx(
  ACtx: PSSL_CTX): TTaurusTLSSslSocketCtx;
var
  lResult: pointer;

begin
  Result:=nil;
  lResult:=SSL_CTX_get_app_data(ACtx);
  if Assigned(lResult) and (TObject(lResult) is TTaurusTLSSslSocketCtx) then // PALOFF 'Pointer cast to TObject'
    Result:=TTaurusTLSSslSocketCtx(lResult)
  else
    ETaurusTLSSSLSocketDataBindingError.RaiseWithMessageFmt(
      { TODO : To make ResourceString }
      'SSL_CTX object %p is not bound to a valid TTaurusTLSSslSocketCtx instance.',
      [ACtx]);
end;

procedure TTaurusTLSSslSocketCtx.InitCtx;
var
  lBool: TIdC_INT;
  lErr: TIdC_INT;

begin
  // Disabling SSL_MODE_AUTO_RETRY
  SSL_CTX_clear_mode(SSLCtx, SSL_MODE_AUTO_RETRY);

  // Attach Self to the SSL_CTX
  lErr:=SSL_CTX_set_app_data(SSLCtx, Self);
  if lErr  <= 0 then
    { TODO : To make ResourceString }
    ETaurusTLSSSLSocketDataBindingError.RaiseExceptionCode(lErr,
      'Unable to link TTaurusTLSSslSocketCtx instance with SSL_CTX object');

  if Flags.QuietShutdown then
    SSL_CTX_set_quiet_shutdown(SSLCtx, 1);

  if Flags.ReadAheadBuffering then
    lBool:=1
  else
    lBool:=0;
  SSL_CTX_set_read_ahead(SSLCtx, lBool);

  if HasOnKeylog then
    SSL_CTX_set_keylog_callback(SSLCtx, CbCtxKeyLog);
end;

procedure TTaurusTLSSslSocketCtx.ReleaseCtx;
begin
  try
    SSL_CTX_set_keylog_callback(SSLCtx, nil);
  finally
    SSL_CTX_set_app_data(SSLCtx, nil);
  end;
end;

class function TTaurusTLSSslSocketCtx.NormalizeHostName(
  const AValue: RawByteString): RawByteString;
begin
  { TODO : Implement lower-case IDNA conversion. }
{$IFDEF STRING_IS_UNICODE}
  Result:=System.AnsiStrings.LowerCase(AValue);
{$ELSE}
  Result:=LowerCase(AValue);
{$ENDIF}
end;

function TTaurusTLSSslSocketCtx.SetFlags(
  const AValue: TaurusTLSSslSocketCtxFlags): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  CheckFrozen;
  FFlags:=AValue;
end;

function TTaurusTLSSslSocketCtx.SetVerifyModes(
  const AValue: TTaurusTLSVerifyModes): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  CheckFrozen;
  FCertVerifyFlags.Flags:=AValue;
end;

function TTaurusTLSSslSocketCtx.SetSSLCtxOptions(
  const AValue: TTaurusTLSSSLOptionFlags): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if AValue = cDefaultCtxOptions then
    Exit;

  CheckFrozen;
  // Design time defaults: [sslOpNoCompression, sslOpEnableMiddleboxCompat]
  SSL_CTX_set_options(FSSLCtx, AValue.AsInt);
end;

function TTaurusTLSSslSocketCtx.SetCipherList(const AValue: string): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if AValue = '' then
    Exit; // Use defaults

  CheckFrozen;
  if SSL_CTX_set_cipher_list(FSSLCtx, PIdAnsiChar(RawByteString(AValue))) <= 0 then  // PALOFF Possible bad typecast
    ETaurusTLSSslSocketCtxError.RaiseWithMessageFmt(
    { TODO : To make ResourceString }
      'Error setting cipher list ''%s'' to the SSL Context.', [AValue]);
end;

function TTaurusTLSSslSocketCtx.SetCipherSuites(const AValue: string): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if AValue = '' then
    Exit; // Use defaults

  CheckFrozen;
  if SSL_CTX_set_ciphersuites(FSSLCtx, PIdAnsiChar(RawByteString(AValue))) <= 0 then // PALOFF Possible bad typecast
    ETaurusTLSSslSocketCtxError.RaiseWithMessageFmt(
    { TODO : To make ResourceString }
      'Error setting cipher suites ''%s'' to the SSL Context.', [AValue]);
end;

function TTaurusTLSSslSocketCtx.SetKeXGroups(const AValue: string): TTaurusTLSSslSocketCtx;
begin
  // Default value is 'DEFAULT'
  // #define DEFAULT_GROUP_NAME "DEFAULT"

  Result:=Self;
  CheckFrozen;
  if SSL_CTX_set1_groups_list(FSSLCtx, PIdAnsiChar(RawByteString(AValue))) <= 0 then // PALOFF Possible bad typecast
    ETaurusTLSSslSocketCtxError.RaiseWithMessageFmt(
    { TODO : To make ResourceString }
      'Error setting key exchange groups ''%s'' to the SSL Context.', [AValue]);
end;

function TTaurusTLSSslSocketCtx.SetSigAlgorithms(const AValue: string): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if AValue = '' then
    Exit; // Use defaults

  CheckFrozen;
  if SSL_CTX_set1_sigalgs_list(FSSLCtx, PIdAnsiChar(RawByteString(AValue))) <= 0 then // PALOFF Possible bad typecast
    ETaurusTLSSslSocketCtxError.RaiseWithMessageFmt(
    { TODO : To make ResourceString }
      'Error setting signature algorithms ''%s'' to the SSL Context.', [AValue]);
end;

function TTaurusTLSSslSocketCtx.SetMinTLSVersion(
  const AValue: TTaurusTLS2TlsVersion): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if AValue = svSSL_Default then
    Exit;

  CheckFrozen;
  if SSL_CTX_set_min_proto_version(FSSLCtx, AValue.AsInt) <= 0 then
    ETaurusTLSSslSocketCtxError.RaiseWithMessage(RSOSSLMinProtocolError);
end;

function TTaurusTLSSslSocketCtx.SetMaxSendFragment(
  const AValue: TTaurusTLSSslMaxSendFragment): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  CheckFrozen;
  if SSL_CTX_set_max_send_fragment(FSSLCtx, AValue) <= 0 then
    ETaurusTLSSslSocketCtxError.RaiseWithMessageFmt(
      { TODO : To make ResourceString }
      'Error setting max send fragment size %d to the SSL Context.', [AValue]
    );
end;

function TTaurusTLSSslSocketCtx.SetMaxTLSVersion(
  const AValue: TTaurusTLS2TlsVersion): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if AValue = svSSL_Default then
    Exit;

  CheckFrozen;
  if SSL_CTX_set_max_proto_version(FSSLCtx, AValue.AsInt) <= 0 then
    ETaurusTLSSslSocketCtxError.RaiseWithMessage(RSOSSLMaxProtocolError);
end;

function TTaurusTLSSslSocketCtx.SetVerifyParam(
  const AValue: TTaurusTLSCustomX509VerifyParam): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  CheckFrozen;
  if Assigned(AValue) then
    AValue.AttachToSSLCtx(FSSLCtx);
end;

function TTaurusTLSSslSocketCtx.SetTrustStore(const AValue: TTaurusTLS_X509Store): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if not Assigned(AValue) then
    Exit;

  CheckFrozen;
  AValue.AttachToSSLCtx(FSSLCtx);
end;

function TTaurusTLSSslSocketCtx.SetOnKeyLog(
  const AValue: TTaurusTLSOnKeyLog): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if (TMethod(FOnKeyLog).Code = TMethod(AValue).Code) and
     (TMethod(FOnKeyLog).Data = TMethod(AValue).Data) then
    Exit;

  CheckFrozen;
  FOnKeyLog:=AValue;
end;

function TTaurusTLSSslSocketCtx.SetOnMessage(
  const AValue: TTaurusTLSOnSSLMessageCallback): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if (TMethod(FOnMessage).Code = TMethod(AValue).Code) and
     (TMethod(FOnMessage).Data = TMethod(AValue).Data) then
    Exit;

  CheckFrozen;
  FOnMessage:=AValue;
end;

function TTaurusTLSSslSocketCtx.SetOnPeerCertError(
  const AValue: TTaurusTLSOnPeerCertError): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if (TMethod(FOnPeerCertError).Code =TMethod(AValue).Code) and
     (TMethod(FOnPeerCertError).Data =TMethod(AValue).Data) then
    Exit;

  CheckFrozen;
  FOnPeerCertError:=AValue;
end;

function TTaurusTLSSslSocketCtx.SetOnSecurityCheck(
  const AValue: TTaurusTLSOnSecurityCheck): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if (TMethod(FOnSecurityCheck).Code = TMethod(AValue).Code) and
     (TMethod(FOnSecurityCheck).Data = TMethod(AValue).Data) then
    Exit;

  CheckFrozen;
  FOnSecurityCheck:=AValue;
end;

function TTaurusTLSSslSocketCtx.SetOnStateChange(
  const AValue: TTaurusTLSOnStateChange): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if (TMethod(FOnStateChange).Code = TMethod(AValue).Code) and
     (TMethod(FOnStateChange).Data = TMethod(AValue).Data) then
    Exit;

  CheckFrozen;
  FOnStateChange:=AValue;
end;

function TTaurusTLSSslSocketCtx.SetOnStatusInfo(
  const AValue: TTaurusTLSOnSSLStatusInfo): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if (TMethod(FOnStatusInfo).Code = TMethod(AValue).Code) and
     (TMethod(FOnStatusInfo).Data = TMethod(AValue).Data) then
    Exit;

  CheckFrozen;
  FOnStatusInfo:=AValue;
end;

function TTaurusTLSSslSocketCtx.SetOnVerifyCertificate(
  const AValue: TTaurusTLSOnVerifyCallback): TTaurusTLSSslSocketCtx;
begin
  Result:=Self;
  if (TMethod(FOnVerifyCertificate).Code = TMethod(AValue).Code) and
     (TMethod(FOnVerifyCertificate).Data = TMethod(AValue).Data) then
    Exit;

  CheckFrozen;
  FOnVerifyCertificate:=AValue;
end;

{ TTaurusTLSSslClientCtx }

class function TTaurusTLSSslClientCtx.CbCliCert(ASSL: PSSL; var AX509: PX509;
  var APKey: PEVP_PKEY): TIdC_INT;
var
  lInstance: TTaurusTLSSslSocket;
  lContext: TTaurusTLSSslClientCtx;
  lErr: integer;

begin
  Result:=0;
  if not Assigned(ASSL) then // this shouldn't happen ever
    Exit;
  try
    lErr:=GStack.WSGetLastError;
    try
      lInstance:=TTaurusTLSSslSocket.GetInstanceFromSSL(ASSL);
      if not Assigned(lInstance) then
        Exit;

      lContext:=lInstance.Ctx as TTaurusTLSSslClientCtx;
      if Assigned(lContext) then
      begin
        lContext.DoOnClientCertCallback(lInstance, AX509, APKey);
        if Assigned(AX509) and Assigned(APKey) then
          Result:=1;
      end;

    finally
      GStack.WSSetLastError(lErr);
    end;
  except
    Result:=-1;
  end;
end;

class function TTaurusTLSSslClientCtx.cbEchLog(ASSL: PSSL;
  const ALogStr: PAnsiChar): TIdC_UINT;
var
  lInstance: TTaurusTLSSslSocket;
  lContext: TTaurusTLSSslClientCtx;
  lErr: integer;

begin
  Result:=1;
  if not Assigned(ASSL) then // this shouldn't happen ever
    Exit;

  try
    lErr:=GStack.WSGetLastError;
    try
      lInstance:=TTaurusTLSSslSocket.GetInstanceFromSSL(ASSL);
      if not Assigned(lInstance) then
        Exit;

      lContext:=lInstance.Ctx as TTaurusTLSSslClientCtx;
      if Assigned(lContext) then
        lContext.DoOnECHLogCallback(lInstance, ALogStr);

    finally
      GStack.WSSetLastError(lErr);
    end;
  except
    Result:=0;
  end;
end;

procedure TTaurusTLSSslClientCtx.InitCtx;
begin
  inherited;
  if HasOnClientCert then
    SSL_CTX_set_client_cert_cb(SSLCtx, CbCliCert);

  if HasOnECHLog then
    SSL_CTX_ech_set_callback(SSLCtx, cbEchLog);
end;

procedure TTaurusTLSSslClientCtx.ReleaseCtx;
begin
  try
    SSL_CTX_set_client_cert_cb(SSLCtx, nil);
  finally
    inherited;
  end;
end;

procedure TTaurusTLSSslClientCtx.DoOnClientCertCallback(
  ASocket: TTaurusTLSSslSocket; var ACert: PX509; APKey: PEVP_PKEY);
begin
  if Assigned(FOnClientCert) then
    FOnClientCert(Sender, ASocket, ACert, APKey);
end;

procedure TTaurusTLSSslClientCtx.DoOnECHLogCallback(ASocket: TTaurusTLSSslSocket;
  const ALogStr: PAnsiChar);
begin
  if Assigned(FOnECHLog) then
    FOnECHLog(Sender, ASocket, ALogStr);
end;

procedure TTaurusTLSSslClientCtx.BuildIdentity;
var
  lIsIp: boolean;

begin
  if FIdentityBuilt then
    Exit;

  FIdentity:='';
  FIdentityIP:=False;

  // 1. Guard against completely uninitialized configs
  if (FHostname = '') and (FDefaultSNI = '') then
  begin
    FIdentityBuilt:=True;
    Exit;
  end;

  lIsIp:=IsValidIP(string(FHostname));

  // 2. Resolve the logical identity
  if FHostname = '' then
  begin
    // Fallback: If the primary hostname is empty, use the DefaultSNI if available
    FIdentity:=FDefaultSNI;
  end
  else if lIsIp then
  begin
    // If the transport hostname is an IP, we prioritize the enforced SNI (DefaultSNI)
    // if configured. Otherwise, the IP is the target identity.
    if FDefaultSNI <> '' then
      FIdentity:=FDefaultSNI
    else
      FIdentity:=FHostname;
  end
  else
  begin
    // If the transport hostname is a DNS domain name, we use the SNIKind
    // rule to determine if we must force a custom SNI (DefaultSNI).
    if (FSNIKind = skForceSNI) and (FDefaultSNI <> '') then
      FIdentity:=FDefaultSNI
    else
      FIdentity:=FHostname;
  end;

  // 3. Cryptographically check if the resolved identity is an IP address.
  FIdentityIP:=(FIdentity <> '') and IsValidIP(string(FIdentity)); // PALOFF Common subexpression, consider elimination
  FIdentityBuilt:=True;
end;

procedure TTaurusTLSSslClientCtx.ResetIdentity;
begin
  FIdentityBuilt:=False;
end;

function TTaurusTLSSslClientCtx.GetDefaultSNI: string;
begin
  Result:=string(FDefaultSNI);
end;

function TTaurusTLSSslClientCtx.GetECHKind: TTaurusTLSECHCliKind;
begin
  Result:=FECHFlags.Kind;
end;

function TTaurusTLSSslClientCtx.GetECHMethods: TTaurusTLSECHCliMeths;
begin
  Result:=FECHFlags.Methods;
end;

function TTaurusTLSSslClientCtx.GetECHNoOuterVal: TIdC_INT;
begin
  if FECHFlags.UseNoOuter then
    Result:=1
  else
    Result:=0;
end;

function TTaurusTLSSslClientCtx.GetECHOuterSNI: string;
begin
  Result:=string(FECHOuterSNI);
end;

function TTaurusTLSSslClientCtx.GetECHOuterSNIRaw: RawByteString;
begin
  if UseECH and (not FECHFlags.UseNoOuter) then
    Result:=FECHOuterSNI
  else
    Result:='';
end;

function TTaurusTLSSslClientCtx.GetHasOnClientCert: boolean;
begin
  Result:=Assigned(FOnClientCert);
end;

function TTaurusTLSSslClientCtx.GetOnECHLog: boolean;
begin
  Result:=Assigned(FOnECHLog);
end;

function TTaurusTLSSslClientCtx.GetHostName: string;
begin
  Result:=string(FHostname);
end;

function TTaurusTLSSslClientCtx.GetIdentity: RawByteString;
begin
  BuildIdentity;
  Result:=FIdentity;
end;

function TTaurusTLSSslClientCtx.GetIsIdentityIP: boolean;
begin
  BuildIdentity;
  Result:=FIdentityIP;
end;

function TTaurusTLSSslClientCtx.GetUseECH: Boolean;
begin
  Result:=FECHFlags.Enabled;
end;

function TTaurusTLSSslClientCtx.GetUseGrease: Boolean;
begin
  Result:=FECHFlags.UseGrease;
end;

function TTaurusTLSSslClientCtx.GetECHConfigList: string;
begin
  Result:=string(FECHConfigList);
end;

function TTaurusTLSSslClientCtx.SetDefaultSNI(const AValue: string): TTaurusTLSSslClientCtx;
var
  lValue: RawByteString;

begin
  Result:=Self;
  lValue:=NormalizeHostName(RawByteString(AValue)); // PALOFF 'UnicodeString cast to RawByteString'
  if FDefaultSNI = lValue then
    Exit;

  CheckFrozen;
  FDefaultSNI:=lValue;
  ResetIdentity;
end;

function TTaurusTLSSslClientCtx.SetECHOuterSNI(const AValue: string): TTaurusTLSSslClientCtx;
var
  lValue: RawByteString;

begin
  Result:=Self;
  lValue:=NormalizeHostName(RawByteString(AValue)); // PALOFF 'UnicodeString cast to RawByteString'
  if FECHOuterSNI = lValue then
    Exit;

  CheckFrozen;
  FECHOuterSNI:=lValue;
  ResetIdentity;
end;

function TTaurusTLSSslClientCtx.SetHostName(const AValue: string): TTaurusTLSSslClientCtx;
var
  lValue: RawByteString;

begin
  Result:=Self;
  lValue:=NormalizeHostName(RawByteString(AValue)); // PALOFF 'UnicodeString cast to RawByteString'
  if FHostname = lValue then
    Exit;

  CheckFrozen;
  FHostname:=lValue;
end;

function TTaurusTLSSslClientCtx.SetOnClientCert(
  const AValue: TTaurusTLSOnClientCertCallback): TTaurusTLSSslClientCtx;
begin
  Result:=Self;
  if (TMethod(FOnClientCert).Code = TMethod(AValue).Code) and
     (TMethod(FOnClientCert).Data = TMethod(AValue).Data) then
    Exit;

  CheckFrozen;
  FOnClientCert:=AValue;
end;

function TTaurusTLSSslClientCtx.SetOnECHLog(
  const AValue: TTaurusTLSOnECHLog): TTaurusTLSSslClientCtx;
begin
  Result:=Self;
  if (TMethod(FOnECHLog).Code = TMethod(AValue).Code) and
     (TMethod(FOnECHLog).Data = TMethod(AValue).Data) then
    Exit;

  CheckFrozen;
  FOnECHLog:=AValue;
end;

function TTaurusTLSSslClientCtx.SetECHConfigList(const AValue: string): TTaurusTLSSslClientCtx;
var
  lValue: RawByteString;

begin
  Result:=Self;
  lValue:=RawByteString(AValue); // PALOFF 'UnicodeString cast to RawByteString'
  if FECHConfigList = lValue then
    Exit;

  CheckFrozen;
  FECHConfigList:=lValue;
  ResetIdentity;
end;

function TTaurusTLSSslClientCtx.SetECHFlags(
  const AValue: TTaurusTLSECHCliFlags): TTaurusTLSSslClientCtx;
begin
  Result:=Self;
  if FECHFlags.Value = AValue.Value then
    Exit;

  CheckFrozen;
  FECHFlags:=AValue;
  ResetIdentity;
end;

function TTaurusTLSSslClientCtx.SetSNIKind(
  const AValue: TTaurusTLSSNICliKind): TTaurusTLSSslClientCtx;
begin
  Result:=Self;
  if FSNIKind = AValue then
    Exit;

  CheckFrozen;
  FSNIKind:=AValue;
  ResetIdentity;
end;

{ TTaurusTLSSslPeerCtx }

class function TTaurusTLSSslPeerCtx.CbPeerAlpnSelect(ASSL: PSSL;
  var AOut: PIdC_UINT8; var AOutLen: TIdC_UINT8; const AIn: PIdC_UINT8;
  AInLen: TIdC_UINT; AArgs: pointer): TIdC_INT;
var
  lInstance: TTaurusTLSSslSocket;
  lConfig: TTaurusTLSSslPeerCtx;
  lErr: integer;

begin
  Result:=0;
  if not Assigned(ASSL) then // this shouldn't happen ever
    Exit;
  try
    lErr:=GStack.WSGetLastError;
    try
      lInstance:=TTaurusTLSSslSocket.GetInstanceFromSSL(ASSL);
      if not Assigned(lInstance) then
        Exit;

      lConfig:=lInstance.Ctx as TTaurusTLSSslPeerCtx;
      if Assigned(lConfig) then
        lConfig.DoOnAlpnSelect(lInstance, AOut, AOutLen,
          AIn, AInLen, Result);
    finally
      GStack.WSSetLastError(lErr);
    end;
  except
    Result:=0;
  end;
end;

class function TTaurusTLSSslPeerCtx.CbPeerSniSelect(ASSL: PSSL;
  var AAlert: Integer; AArg: Pointer): TIdC_INT;
var
  lInstance: TTaurusTLSSslSocket;
  lConfig: TTaurusTLSSslPeerCtx;
  lErr: integer;

begin
  Result:=0;
  if not Assigned(ASSL) then // this shouldn't happen ever
    Exit;
  try
    lErr:=GStack.WSGetLastError;
    try
      lInstance:=TTaurusTLSSslSocket.GetInstanceFromSSL(ASSL);
      if not Assigned(lInstance) then
        Exit;

      lConfig:=lInstance.Ctx as TTaurusTLSSslPeerCtx;
      if Assigned(lConfig) then
        lConfig.DoOnPeerSniSelect(lInstance, AAlert);

    finally
      GStack.WSSetLastError(lErr);
    end;
  except
    Result:=0;
  end;
end;

class function TTaurusTLSSslPeerCtx.CbPeerSslSessionNew(ASSL: PSSL;
  ASession: PSSL_SESSION): TIdC_INT;
var
  lInstance: TTaurusTLSSslSocket;
  lConfig: TTaurusTLSSslPeerCtx;
  lErr: integer;
  lResult: boolean;

begin
  Result:=1;
  lResult:=True;
  if not Assigned(ASSL) then // this shouldn't happen ever
    Exit;
  try
    lErr:=GStack.WSGetLastError;
    try
      lInstance:=TTaurusTLSSslSocket.GetInstanceFromSSL(ASSL);
      if not Assigned(lInstance) then
        Exit;

      lConfig:=lInstance.Ctx as TTaurusTLSSslPeerCtx;
      if Assigned(lConfig) then
        lConfig.DoOnSSLSessionNew(lInstance, ASession, lResult);

      if lResult then
        Result:=1
      else
        Result:=0;
    finally
      GStack.WSSetLastError(lErr);
    end;
  except
    Result:=0;
  end;
end;

class procedure TTaurusTLSSslPeerCtx.CbPeerSslSessionRemove(ACtx: PSSL_CTX;
  ASession: PSSL_SESSION);
var
  lConfig: TTaurusTLSSslPeerCtx;
  lErr: integer;

begin
  if not Assigned(ACtx) then // this shouldn't happen ever
    Exit;
  try
    lErr:=GStack.WSGetLastError;
    try
      lConfig:=GetInstanceFromCtx(ACtx) as TTaurusTLSSslPeerCtx;
      if Assigned(lConfig)then
        lConfig.DoOnSslSessionRemove(ACtx, ASession);
    finally
      GStack.WSSetLastError(lErr);
    end;
  except //PALOFF "Empty except-block"
    // We must not raise the exception to the OpenSSL stack
  end;
end;

function TTaurusTLSSslPeerCtx.GetHasOnPeerAlpnSelect: boolean;
begin
   Result:=Assigned(OnAlpnSelect);
end;

function TTaurusTLSSslPeerCtx.GetHasOnPeerSslSessionNew: boolean;
begin
   Result:=Assigned(OnSslSessionNew);
end;

function TTaurusTLSSslPeerCtx.GetHasOnPeerSslSessionRemove: boolean;
begin
   Result:=Assigned(OnSslSessionRemove);
end;

function TTaurusTLSSslPeerCtx.GetHasOnPeerSniSelect: boolean;
begin
  Result:=Assigned(OnSniSelect);
end;

procedure TTaurusTLSSslPeerCtx.DoOnAlpnSelect(
  ASocket: TTaurusTLSSslSocket; var AOut: PIdC_UINT8; var AOutLen: TIdC_UINT8;
  const AIn: PIdC_UINT8; const AInLen: TIdC_UINT; var AResultValue: TIdC_INT);
var
  lAlpnSelect: TTaurusTLSAlpnSelector;

begin
  if not (Assigned(ASocket) and Assigned(OnAlpnSelect)) then
    Exit;

  lAlpnSelect:=TTaurusTLSAlpnSelector.Create(AIn, AInLen);

  OnAlpnSelect(Sender, ASocket, lAlpnSelect);

  AResultValue:=lAlpnSelect.ResultValue.AsInt;
  AOut:=lAlpnSelect.SelectedProto;
  AOutLen:=lAlpnSelect.SelectedProtoLen;
end;

procedure TTaurusTLSSslPeerCtx.DoOnPeerSniSelect(
  ASocket: TTaurusTLSSslSocket; var AAlert: TIdC_INT);
begin
  if Assigned(ASocket) and Assigned(OnSniSelect) then
    OnSniSelect(Sender, ASocket, AAlert);
end;

procedure TTaurusTLSSslPeerCtx.DoOnSSLSessionNew(
  ASocket: TTaurusTLSSslSocket; ASession: PSSL_SESSION; var AAccept: boolean);
begin
  if Assigned(ASocket) and Assigned(ASession) then
    FOnSSLSessionNew(Sender, ASession, AAccept);
end;

procedure TTaurusTLSSslPeerCtx.DoOnSSLSessionRemove(
  ACtx: PSSL_CTX; ASession: PSSL_SESSION);
begin
  if Assigned(ACtx) and Assigned(ASession) then
    FOnSslSessionRemove(Sender, ACtx, ASession);
end;

procedure TTaurusTLSSslPeerCtx.InitCtx;
begin
  inherited;

  // Add callbacks
  if HasOnPeerSniSelect then
    SSL_CTX_set_tlsext_servername_callback(SSLCtx, CbPeerSniSelect);

  if HasOnPeerAlpnSelect then
    SSL_CTX_set_alpn_select_cb(SSLCtx, CbPeerAlpnSelect, nil);

  if HasOnPeerSslSessionNew then
    SSL_CTX_sess_set_new_cb(SSLCtx, CbPeerSslSessionNew);

  if HasOnPeerSslSessionRemove then
    SSL_CTX_sess_set_remove_cb(SSLCtx, CbPeerSslSessionRemove);
end;

procedure TTaurusTLSSslPeerCtx.ReleaseCtx;
begin
  // Remove callbacks
  try
    SSL_CTX_set_tlsext_servername_callback(SSLCtx, nil);
    SSL_CTX_set_alpn_select_cb(SSLCtx, nil, nil);
    SSL_CTX_sess_set_new_cb(SSLCtx, nil);
    SSL_CTX_sess_set_remove_cb(SSLCtx, nil);
  finally
    inherited;
  end;
end;

{ TTaurusTLSSslSocket }

{$IFDEF SIGPIPE_MASK}
{ BUGFIX: Fixes issue #217 and #240 }
class constructor TTaurusTLSSslSocket.Create;
begin
  // We initialize the FSigSet once to eliminate the variable setup in each thread.
{$IFDEF DCC}
  sigemptyset(FSigSet);
  sigaddset(FSigSet, SIGPIPE);
{$ELSE}
  FpsigEmptySet(FSigSet);
  FpSigAddSet(FSigSet, SIGPIPE);
{$ENDIF}
end;
{$ENDIF}

constructor TTaurusTLSSslSocket.Create(const AConfigIntf: ITaurusTLSSslSocketCtx);
begin
  Assert(Assigned(AConfigIntf), '''AConfigIntf'' should not be ''nil''.'); //Do not localize
  inherited Create;
  FSocketHandle:=Id_INVALID_SOCKET;
  FContextIntf:=AConfigIntf;
  FCtx:=AConfigIntf.Ctx; // PALOFF 'Mixing interface variables and objects' (Not sure why)
end;

destructor TTaurusTLSSslSocket.Destroy;
begin
  Shutdown;
  if not (FState in cTerminalStates) then
    TransitionTo(seReleased);

  inherited Destroy;
end;

{$IFDEF SIGPIPE_MASK}
{ BUGFIX: Fixes issue #217 and #240 }
class procedure TTaurusTLSSslSocket.MaskSigPipe;
begin
  pthread_sigmask(SIG_BLOCK, @FSigSet, nil);
end;
{$ENDIF}

function TTaurusTLSSslSocket.InitSSL: TTaurusTLSSslSocketState;
var
  lErr: TIdC_INT;

begin
  ClearError;
  CheckActiveState([seIdle]);

  // 1. Allocate the SSL session structure using the pinned context
  FSSL:=SSL_new(FCtx.SSLCtx);
  if not Assigned(FSSL) then
    ETaurusTLSSSLSocketCreateError.RaiseExceptionCode(GetLastError(0),
      RSSSLCreatingSessionError);

  // 2. Bind the Delphi object instance to the SSL handle for callback routing
  lErr:=GetLastError(SSL_set_app_data(FSSL, Self));
  if lErr <= 0 then
    ETaurusTLSSSLSocketDataBindingError.RaiseExceptionCode(lErr,
      RMSG_SslSocketSetAppData_err);

  // 3. Do Socket/Connection specific configuration (Virtual polymorphic hook)
  SetupConnection;

  // 4. Register the callback bridges
  InitSSLCallbacks;

  // 5. For Linux only: mask SIGPIPE signal for the current thread.
{$IFDEF SIGPIPE_MASK}
  MaskSigPipe;
{$ENDIF}
  Result:=seInitializing;
end;

function TTaurusTLSSslSocket.ReleaseSSL: TTaurusTLSSslSocketState;
begin
  ClearError;
  Result:=seReleased;
  if Assigned(FSSL) then
  try
    try
      ReleaseSSLCallbacks;
    except //PALOFF "Empty except-block"
      // We must not raise the exception to the OpenSSL stack
    end;
  finally
    SSL_set_app_data(FSSL, nil);
    SSL_free(FSSL);
    FSSL:=nil;
  end;
end;

function TTaurusTLSSslSocket.BindSocket: TTaurusTLSSslSocketState;
var
  lRet: TIdC_INT;

begin
  ClearError;
  Result:=seError;
  if Assigned(FSSL) and (FSocketHandle <> Id_INVALID_SOCKET) then
  begin
    lRet:=SSL_set_fd(FSSL, FSocketHandle);
    if GetLastError(lRet) <= 0 then
      ETaurusTLSSslSocketBindError.RaiseExceptionCode(lRet,
        RSSSLDataBindingError_2)
    else
      Result:=seHandshaking;
  end
end;

function TTaurusTLSSslSocket.DoHandshake: TTaurusTLSSslSocketState;
begin
  ClearError;
  CheckActiveState([seHandshaking]);

  repeat
    Result:=DoHandshakeIteration;
    if Result = seHandshaking then
    { TODO : IndySleep should be replaced with the smart cross-compiler "spin wait" call. }
      IndySleep(1)
  until Result <> seHandshaking;

  FIsSessionResumed:=Assigned(FSSL) and (State in [seEstablished, seClosed]) and
    (SSL_session_reused(FSSL) > 0);
end;

function TTaurusTLSSslSocket.DoShutdown: TTaurusTLSSslSocketState;
var
  lRet, lErr: Integer;

begin
  if FState = seError then
    Exit(seError)
  else
    Result:=seClosed; // Default next step on successful close_notify exchange

  if not Assigned(FSSL) then
    Exit;

  ClearError;
  lRet:=SSL_shutdown(FSSL);

  // Handle first SSL_shutdown call
  if lRet < 0 then
  begin
    lErr:=GetSSLError(lRet); // Captures error snapshot automatically
    if lErr = SSL_ERROR_SYSCALL then
      Result:=seClosed // Hard socket disconnect
    else
      Result:=seError;  // OpenSSL protocol or cryptographic error
    Exit;
  end

  // lRet = 0 means close_notify sent, awaiting peer response.
  // Execute second call if bi-directional shutdown is required.
  else if (lRet = 0) and (not Ctx.Flags.UniDirectShutdown) then
  begin
    ERR_clear_error;
    SSL_shutdown(FSSL);
    Result:=seClosed
  end;
end;

procedure TTaurusTLSSslSocket.DoStateChangeNotify(ACurrent,
  ATarget: TTaurusTLSSslSocketState);
var
  lContext: TTaurusTLSSslSocketCtx;

begin
  lContext:=FCtx;
  if Assigned(lContext) then
    lContext.DoOnStateChange(Self, ACurrent, ATarget);
end;

function TTaurusTLSSslSocket.GetLastError(ARetCode: Integer): Integer;
begin
  FLastRetCode:=ARetCode;
  FLastSocketError:=GStack.WSGetLastError;

  // 1. Peek at the top error in OpenSSL's thread-local queue WITHOUT popping/clearing it
  Result:=ARetCode;
  FLastQueueError:= ERR_peek_error;

  // 2. Resolve High-Level SSL Error Code
  if Assigned(FSSL) then
  begin
    // If FSSL exists, query SSL_get_error for the high-level classification
    FLastSSLError:=SSL_get_error(FSSL, ARetCode);
  end
  else if FLastSocketError <> 0 then
  begin
    // If no OpenSSL queue error exists but an OS socket error was recorded
    FLastSSLError:=SSL_ERROR_SYSCALL;
  end
  else
    FLastSSLError:=SSL_ERROR_NONE;
end;

function TTaurusTLSSslSocket.GetSSLError(ALastResult: Integer): Integer;
begin
  FLastRetCode := ALastResult;

  // 1. SUCCESS PATH (ALastResult > 0)
  // OpenSSL guarantees SSL_get_error returns SSL_ERROR_NONE when ret > 0.
  if ALastResult > 0 then
  begin
    ClearError; // Reset all snapshot fields to clean state
    Result := SSL_ERROR_NONE;
    Exit;
  end;

  // 2. FAILURE / PENDING PATH (ALastResult <= 0)
  // Capture OS-level socket error at the exact microsecond of failure
  FLastSocketError := GStack.WSGetLastError;

  if Assigned(FSSL) then
  begin
    // Resolves ZERO_RETURN, SYSCALL, WANT_READ, WANT_WRITE, SSL_ERROR_SSL, etc.
    Result := SSL_get_error(FSSL, ALastResult);

    // Peeks at the top error in OpenSSL's C-queue without clearing it
    FLastQueueError := ERR_peek_error;
  end
  else
  begin
    Result := SSL_ERROR_SYSCALL;
    FLastQueueError := ERR_peek_error;
  end;

  FLastSSLError := Result;
end;

procedure TTaurusTLSSslSocket.CheckActiveState(
  const AExpectedStates: TTaurusTLSSslSocketStates);
begin
  if not (FState in AExpectedStates) then
     ETaurusTLSSocketStateError.RaiseWithMessageFmt(
      { TODO : To make ResourceString }
      'Invalid socket operation in the ''%s'' state.', [FState.AsString]);
end;

function TTaurusTLSSslSocket.GetNextStepTarget(ACurrent,
  ATarget: TTaurusTLSSslSocketState): TTaurusTLSSslSocketState;
begin
  if ACurrent in cTerminalStates then
    Exit(ACurrent);

  if ATarget in cTerminalStates then
  begin
    if (ACurrent = seEstablished) and (ATarget = seReleased) then
      Exit(seClosed)
    else
      Exit(ATarget);
  end;

  if ATarget <= ACurrent then
    Exit(ATarget); // Handled/rejected by IsValidTransition

  case ACurrent of
    seIdle:
      Result:=seInitializing; // Step 1 from Idle

    seInitializing:
      Result:=seInitialized;  // Step 2 from Initializing

    seInitialized:
      Result:=seHandshaking;  // Step 3 from Initialized

    seHandshaking:
      Result:=seEstablished;  // Step 4 from Handshaking

    seEstablished:
      Result:=seClosed;      // Step 5 from Established

    seClosed:
      Result:=seReleased;

    seReleased:
      Result:=seReleased;

  else
    Result:=seError;
  end;
end;

function TTaurusTLSSslSocket.IsValidTransition(ACurrent,
  ATarget: TTaurusTLSSslSocketState): Boolean;
begin
  // Global Panic State Rule: seError is valid from any state except Closed and itself
  if ATarget = seError then
    Exit((ACurrent <> seClosed) and (ACurrent <> seError));

  case ACurrent of
    seIdle:
      Result:=ATarget in ([seInitializing]+cTerminalStates);

    seInitializing:
      Result:=ATarget in ([seInitialized]+cTerminalStates);

    seInitialized:
      Result:=ATarget in ([seHandshaking]+cTerminalStates);

    seHandshaking:
      Result:=ATarget in ([seEstablished]+cTerminalStates);

    seEstablished:
      Result:=ATarget in ([seClosed]+cTerminalStates);

    seClosed:
      Result:=ATarget in cTerminalStates;

    seReleased, seError:
      Result:=False; // Terminal states cannot transition out
  else
    Result:=False;
  end;
end;

function TTaurusTLSSslSocket.DoSetState(ATarget: TTaurusTLSSslSocketState): boolean;
begin
  Result:=not (ATarget = FState);
  if Result then
    FState:=ATarget;
end;

procedure TTaurusTLSSslSocket.DoSetState(ATarget: TTaurusTLSSslSocketState;
  ANotify: boolean);
var
  lState: TTaurusTLSSslSocketState;

begin
  lState:=FState;
  if DoSetState(ATarget) and ANotify then
    DoStateChangeNotify(lState, ATarget);
end;

function TTaurusTLSSslSocket.DoTransitionTo(
  ATarget: TTaurusTLSSslSocketState): TTaurusTLSSslSocketState;
var
  lState: TTaurusTLSSslSocketState;

begin
  try
    lState:=FState;
    Result:=ATarget;

    if FState = Result then
      Exit;

    case ATarget of
      seInitializing:
        Result:=InitSSL;

      seInitialized:
        begin
          CheckActiveState([seInitializing]);
          Result:=seInitialized;
        end;

      seHandshaking:
        Result:=BindSocket;

      seEstablished:
        Result:=DoHandshake; // Executes handshake loop; transitions to seEstablished on success

      seClosed:
        Result:=DoShutdown;

      seReleased, seError:
        if lState in [seInitialized..seClosed] then
          ReleaseSSL;

      else
        Result:=seError;
    end;

  except
    on E: Exception do
    begin
      // Exception Safety: If an error occurs during non-terminal transitions,
      // release SSL resources and set state directly to seError
      if not (ATarget in [seClosed, seError]) then
      begin
        ReleaseSSL;
        FState:=seError; // Force state without triggering recursive transitions
      end;
      raise; // Re-raise exception for caller
    end;
  end;
end;

procedure TTaurusTLSSslSocket.TransitionTo(ATarget: TTaurusTLSSslSocketState;
  ASteps: integer);
var
  lState, lNextState: TTaurusTLSSslSocketState;

begin
  // Exit if already in requested target state
  if FState = ATarget then
    Exit;

  try
    repeat
      lState := FState;

      // Resolve the immediate next forward step required to reach ATarget
      lNextState := GetNextStepTarget(lState, ATarget);

      // Validate single-step feasibility using your exact IsValidTransition rules
      if not IsValidTransition(lState, lNextState) then
        { TODO : To make ResourceString }
        ETaurusTLSSocketStateError.RaiseWithMessageFmt(
          'Unable to transition Socket ''%s''''s state from ''%s'' to ''%s''.',
          [ClassName, lState.AsString, lNextState.AsString]);

      // Execute the single step
      lState:=DoTransitionTo(lNextState);

      // Update State and notify
      DoSetState(lState, True);

      // Infinite Loop / Stagnation Guard
      Dec(ASteps);
    until (FState in ([ATarget]+cTerminalStates)) or (ASteps <= 0);

    if ASteps <= 0 then
    begin
      ETaurusTLSSocketStateError.RaiseWithMessageFmt(
        'Infinite state transition loop detected on Socket ''%s'' at state ''%s''.',
        [ClassName, FState.AsString]);
    end;

  except
    on E: Exception do
    begin
      if E is EIdConnClosedGracefully then
        lState:=seReleased
      else
        lState:=seError;

      ReleaseSSL;
      DoSetState(lState, True);
      raise;
    end;
  end;
end;



class function TTaurusTLSSslSocket.CheckForSocketEvent(ASocketHandle: TIdStackSocketHandle;
      AKind: TSocketSelectKinds; AMsec: integer): boolean;
var
  lList: TIdSocketList;
  lReadList, lWriteList, lErrorList: TIdSocketList;

begin
  if ASocketHandle = INVALID_HANDLE_VALUE then
    raise EIdConnClosedGracefully.Create(RSConnectionClosedGracefully);

  lList:=TIdSocketList.CreateSocketList;
  lList.Add(ASocketHandle);
  try
    if sokRead in AKind then
      lReadList:=lList
    else
      lReadList:=nil;

    if sokWrite in AKind then
      lWriteList:=lList
    else
      lWriteList:=nil;

    if sokError in AKind then
      lErrorList:=lList
    else
      lErrorList:=nil;

    Result:=lList.Select(lReadList, lWriteList, lErrorList, AMsec);
  finally
    lList.Free;
  end;
end;

class function TTaurusTLSSslSocket.WaitForSocket(
  ASocketHandle: TIdStackSocketHandle; AKind: TSocketSelectKinds;
  AMsec: integer): boolean;
begin
  Result:=False;

  if AMsec =IdTimeoutDefault then
    AMsec:=IdTimeoutInfinite;

  if TIdAntiFreezeBase.ShouldUse then
  begin
    if AMsec = IdTimeoutInfinite then
    begin
      repeat
        Result:=CheckForSocketEvent(ASocketHandle, AKind, GAntiFreeze.IdleTimeOut);
      until Result;
      Exit;
    end
    else
    while AMSec >= 0 do
    begin
      Result:=CheckForSocketEvent(ASocketHandle, AKind, GAntiFreeze.IdleTimeOut);
      if Result then
        Exit;
      Dec(AMsec, GAntiFreeze.IdleTimeOut);
    end
  end
  else
    Result:=CheckForSocketEvent(ASocketHandle, AKind, AMsec);
end;

function TTaurusTLSSslSocket.WaitForRead(AMsec: integer): boolean;
begin
  Result:=WaitForSocket(FSocketHandle, [sokRead], AMsec);
end;

function TTaurusTLSSslSocket.WaitForWrite(AMsec: integer): boolean;
begin
  Result:=WaitForSocket(FSocketHandle, [sokWrite], AMsec);
end;

procedure TTaurusTLSSslSocket.Connect(const pHandle: TIdStackSocketHandle);
begin
  CheckActiveState([seIdle]);
  FSocketHandle := pHandle;
  TransitionTo(seEstablished);
end;

function TTaurusTLSSslSocket.CheckForError: Integer;
var
  lErrStr: string;

begin
  // 1. EARLY TERMINAL GUARD: Handle sockets that were already closed/erred
  // before the SSL stack executed or during an earlier teardown
  if FState in ([seClosed]+cTerminalStates) then
  begin
    if FLastSocketError <> 0 then
      GStack.RaiseSocketError(FLastSocketError) // Raises EIdSocketError with exact OS error
    else if FLastSSLError <> SSL_ERROR_NONE then
    begin
      lErrStr:=string(ERR_error_string(FLastQueueError, nil));
      ETaurusTLSAPISSLError.RaiseExceptionCode(FLastSSLError, FLastRetCode, lErrStr);
    end
    else
    begin
      // Fallback: Check Indy's GStack for any last socket error
      GStack.CheckForSocketError(Integer(Id_SOCKET_ERROR),
        [Id_WSAESHUTDOWN, Id_WSAECONNABORTED, Id_WSAECONNRESET, Id_WSAETIMEDOUT]);
    end;

    Exit(FLastSocketError);
  end;

  Result:=FLastSSLError;

  // 2. SSL Layer Reports No Error, but OS Socket Handle is Invalid
  if Result = SSL_ERROR_NONE then
  begin
    if FSocketHandle = Id_INVALID_SOCKET then
    begin
      TransitionTo(seClosed);
      { TODO : To make ResourceString }
      ETaurusTLSSSLSocketConnectionReset.RaiseWithMessage(
        'Socket closed before SSL operation completed.');
    end;
    Exit(0); // Healthy session
  end;

  // 3. Handle OS-level Network Resets (SSL_ERROR_SYSCALL)
  if Result = SSL_ERROR_SYSCALL then
  begin
    TransitionTo(seReleased);
    if FLastSocketError <> 0 then
      GStack.RaiseSocketError(FLastSocketError)
    else
      Exit(GStack.CheckForSocketError(Integer(Id_SOCKET_ERROR),
        [Id_WSAESHUTDOWN, Id_WSAECONNABORTED, Id_WSAECONNRESET, Id_WSAETIMEDOUT]));
  end;

  // 4. Handle OpenSSL Protocol / Cryptographic Failures
  TransitionTo(seError);

  if FLastQueueError <> 0 then
    lErrStr:=string(ERR_error_string(FLastQueueError, nil))
  else
    { TODO : To make ResourceString }
    lErrStr:='Unspecified OpenSSL error.';

  ETaurusTLSAPISSLError.RaiseExceptionCode(Result, FLastRetCode, lErrStr);
end;

procedure TTaurusTLSSslSocket.CheckPeerCertificateValidationResult;
var
  lErr: TTaurusTLSX509Error;  // its a record type. No lErr.Free is required.
  lErrCode: TIdC_INT;
  lCert: TTaurusTLSX509; // PALOFF 'Created and freed objects'
  lSuccess: boolean;

begin
  if not Ctx.CertVerifyFlags.VerifyPeer then
    Exit;

  lCert:=nil;
  lErrCode:=SSL_get_verify_result(FSSL);
  lErr:=TTaurusTLSX509Error.Create(lErrCode);
  lSuccess:=lErrCode = X509_V_OK;
  if not lSuccess then
  try
    lCert:=GetPeerCertificate;
    Ctx.DoOnPeerCertError(Self, lCert, lErr, lSuccess);
  finally
    lCert.Free;
  end;
  if not lSuccess then
    ETaurusTLSSSLSocketCertValidationError.RaiseErrorCode(lErrCode,
      lErr.ErrorShortDescription);
end;

procedure TTaurusTLSSslSocket.ClearError;
begin
  ERR_clear_error; // Clear OpenSSL's thread-local error queue

  // Reset local captured snapshot fields
  FLastSSLError := SSL_ERROR_NONE;
  FLastRetCode := 0;
  FLastQueueError := 0;
  FLastSocketError := 0;
end;

function TTaurusTLSSslSocket.Readable(AMsec: integer): boolean;
var
  lSW: TStopWatch;
  lTimeout: integer;
  lByte: byte;
  lRet, lErr: TIdC_INT;

begin
  Result:=False;

  if Assigned(FSSL) and (FState = seEstablished) then
  begin
    lSW:=TStopWatch.StartNew;
    lTimeout:=AMsec;

    repeat
      // 1. Check OpenSSL internal memory queue for decrypted application data
      if SSL_has_pending(FSSL) > 0 then
      begin
        Result:=True;
        Break; // Data ready; exit loop
      end;

      // 2. Check if the OS socket descriptor was closed
      if FSocketHandle = Id_INVALID_SOCKET then
      begin
        Result:=False;
        Break;
      end;

      if AMsec > 0 then
      begin
        lTimeout:=AMsec - Integer(lSW.ElapsedMilliseconds);
        if lTimeout <= 0 then
          Break; // Timeout budget exhausted
      end;

      if not WaitForRead(lTimeout) then
        Break;

      ClearError;

      // 3. Perform a non-destructive 1-byte peek
      lRet:=SSL_peek(FSSL, lByte, 1);
      if lRet > 0 then
      begin
        Result:=True;
        Break; // Application data is ready for Recv
      end;

      lErr:=GetSSLError(lRet);
      case lErr of
        SSL_ERROR_WANT_READ:
          // Suspend thread at OS level via select(). Exit loop if wait fails/times out
          if not WaitForRead(lTimeout) then
            Break; // Timeout budget exhausted

        SSL_ERROR_WANT_WRITE:
          if not WaitForWrite(lTimeout) then
            Break;

        {SSL_ERROR_ZERO_RETURN,} SSL_ERROR_SYSCALL, SSL_ERROR_SSL:
          begin
            // Disconnect or error state detected; set True so Indy invokes
            // Recv to handle graceful shutdown or raise exceptions cleanly.
            Result:=True;
            Break;
          end;
      else
        Break;
      end;

    until False;
  end;
end;

function TTaurusTLSSslSocket.Recv(var ABuffer: TIdBytes;
  const AMSec: Integer): Integer;
var
  lResult: TIdC_SIZET;
  lLen, lRet, lErr: TIdC_INT;
  lTimeout: Integer;
  lIsTimeout: Boolean;
  lSW: TStopWatch;

begin
  lResult:=0;

  lLen:=Length(ABuffer);
  if lLen = 0 then
    Exit(0);

  CheckActiveState([seEstablished]);

  lIsTimeout:=False;
  lSW:=TStopWatch.StartNew;

  repeat
    ClearError;
    lRet:=SSL_read_ex(FSSL, ABuffer[0], Length(ABuffer), lResult);
    Result:=lResult;

    if lRet > 0 then
      Break;

    if AMSec <> IdTimeoutInfinite then
    begin
      lTimeout:=AMSec - Integer(lSW.ElapsedMilliseconds);
      lIsTimeout:=(lTimeout <= 0);
    end
    else
      lTimeout:=IdTimeoutInfinite;

    if lIsTimeout then
      Break;

    // Handle Non-Success / Pending / Error States
    lErr:=GetSSLError(lRet);
    case lErr of
      SSL_ERROR_WANT_READ:
        if SSL_has_pending(FSSL) > 0 then
          Continue // SSL has decoded or raw data in the buffer (Read Ahead is ON)
        else
          lIsTimeout:=not WaitForRead(lTimeout);

      SSL_ERROR_WANT_WRITE:
        lIsTimeout:=not WaitForWrite(lTimeout);

      else
        if lErr <> SSL_ERROR_ZERO_RETURN then
        begin
          Result:=lRet;
          Break;
        end;
    end;
  until lIsTimeout;
end;

function TTaurusTLSSslSocket.Send(const ABuffer: TIdBytes; const AOffset,
  ALength: TIdC_SIZET; const AMSec: Integer): Integer;
var
  lResult: TIdC_SIZET;
  lRet, lErr: TIdC_INT;
  lLen: TIdC_SIZET;
  lTimeout: Integer;
  lIsTimeout: boolean;
  lSW: TStopWatch;

begin
  Result:=0;
  lLen:=Length(ABuffer);
  if (ALength = 0) or (lLen = 0) then
    Exit;

  CheckActiveState([seEstablished]);

  lIsTimeOut:=False;
  lSW:=TStopWatch.StartNew;

  repeat
    ClearError;
    lRet:=SSL_write_ex(FSSL, ABuffer[AOffset], ALength, lResult);
    Result:=lResult;

    if lRet > 0 then
      Break;

    if AMSec <> IdTimeoutInfinite then
    begin
      lTimeout:=AMSec - Integer(lSW.ElapsedMilliseconds);
      lIsTimeout:=(lTimeout <= 0);
    end
    else
      lTimeout:=IdTimeoutInfinite;

    if lIsTimeout then
      Break;

    lErr:=GetSSLError(lRet);
    case lErr of
      SSL_ERROR_WANT_WRITE:
        lIsTimeout:=not WaitForWrite(lTimeout);

      SSL_ERROR_WANT_READ:
        lIsTimeout:=not WaitForRead(lTimeout);

      else
        if lErr <> SSL_ERROR_ZERO_RETURN then
        begin
          Result:=lRet;
          Break;
        end;
    end;
  until lIsTimeout;
end;

procedure TTaurusTLSSslSocket.Shutdown;
begin
  if FState = seEstablished then
  begin
    try
      // Initiates pipeline: seEstablished -> seClosing -> seClosed (or seError on failure)
      TransitionTo(seReleased);
    except
      on E: Exception do
      begin
        // If an exception escapes DoShutdown, force seError state and re-raise
        TransitionTo(seError);
        raise;
      end;
    end;
  end
  else if FState in [seInitialized, seHandshaking] then
  begin
    // For non-established connections being torn down, move directly to seClosed
    TransitionTo(seReleased);
  end;
end;

// callbacks

procedure TTaurusTLSSslSocket.InitSSLCallbacks;
var
  lCertCallback: function(const APreVerify: TIdC_INT;
      ACtx: PX509_STORE_CTX): TIdC_INT; cdecl;

begin
  if FCtx.HasOnStatusInfo then
    SSL_set_info_callback(FSSL, TTaurusTLSSslSocket.CbSslInfo);

  if FCtx.HasOnVerifyCertificate then
    lCertCallback:=TTaurusTLSSslSocket.CbSslVerify
  else
    lCertCallback:=nil;
  SSL_set_verify(FSSL, FCtx.CertVerifyFlags.AsInt, lCertCallback);


  if FCtx.HasOnSecurityCheck then
    SSL_set_security_callback(FSSL,
      TTaurusTLSSslSocket.CbSslSecurityCheck);

  if Ctx.HasOnMessage then
    SSL_set_msg_callback(FSSL,
      TTaurusTLSSslSocket.CbSslMessage);
end;

procedure TTaurusTLSSslSocket.ReleaseSSLCallbacks;
begin
  SSL_set_verify(FSSL, 0, nil);
  SSL_set_info_callback(FSSL, nil);
end;

class function TTaurusTLSSslSocket.GetInstanceFromSSL(ASSL: PSSL): TTaurusTLSSslSocket;
var
  lResult: pointer;

begin
  Result:=nil;
  lResult:=SSL_get_app_data(ASSL);
  if Assigned(lResult) and (TObject(lResult) is TTaurusTLSSslSocket) then // PALOFF 'Pointer cast to TObject'
    Result:=TTaurusTLSSslSocket(lResult)
  else
    { TODO : To make ResourceString }
    ETaurusTLSSSLSocketDataBindingError.RaiseWithMessageFmt(
      'SSL object %p is not bound to a valid TTaurusTLSSslSocket instance.',
      [ASSL]);
end;

function TTaurusTLSSslSocket.GetPeerCertificate: TTaurusTLSX509;
var
  lX509: PX509;

begin
  Result:=nil;
  if State in [seHandshaking, seEstablished] then
  try
    lX509:=SSL_get1_peer_certificate(FSSL);
    if Assigned(lX509) then
      Result:=TTaurusTLSX509.Create(lX509, True);
  except
    FreeAndNil(Result);
  end;
end;

class function TTaurusTLSSslSocket.CbSrvAlpnSelectCallback(ASSL: PSSL;
  var AOutProto: PIdAnsiChar; var AOutLen: TIdC_UINT8;
  const AInProtos: PIdAnsiChar; AInLen: TIdC_UINT; AArg: Pointer): TIdC_INT;
var
  lInstance: TTaurusTLSSslSocket;
  lContext: TTaurusTLSSslSocketCtx;
  lErr: integer;

begin
  Result:=SSL_TLSEXT_ERR_NOACK;
  if not Assigned(ASSL) then // this shouldn't happen ever
    Exit;
  try
    lErr:=GStack.WSGetLastError;
    try
      lInstance:=GetInstanceFromSSL(ASSL);
      if not Assigned(lInstance) then
        Exit;

      lContext:=lInstance.FCtx;
      if Assigned(lContext) then
      { TODO : Call event handler here. }

    finally
      GStack.WSSetLastError(lErr);
    end;
  except
    Result:=SSL_TLSEXT_ERR_ALERT_FATAL;
  end;
end;

class procedure TTaurusTLSSslSocket.CbSSLInfo(const ASSL: PSSL; AWhere,
  ARet: TIdC_INT);
var
  lInstance: TTaurusTLSSslSocket;
  lContext: TTaurusTLSSslSocketCtx;
  lErr: integer;

begin
  if not Assigned(ASSL) then // this shouldn't happen ever
    Exit;
  try
    lErr:=GStack.WSGetLastError;
    try
      lInstance:=GetInstanceFromSSL(ASSL);
      if not Assigned(lInstance) then
        Exit;

      lContext:=lInstance.FCtx;
      if Assigned(lContext) then
        lContext.DoOnStatusInfo(lInstance, AWhere, ARet);
    finally
      GStack.WSSetLastError(lErr);
    end;
  except //PALOFF "Empty except-block"
    // We must not raise the exception to the OpenSSL stack
  end;
end;

class procedure TTaurusTLSSslSocket.CbSslMessage(AWriteP, AVersion,
  AContentType: TIdC_INT; const ABuf: pointer; ALen: TIdC_SIZET; ASSL: PSSL;
  AArg: Pointer);
var
  lErr: TIdC_INT;
  lInstance: TTaurusTLSSslSocket;
  lContext: TTaurusTLSSslSocketCtx;

begin
  if not Assigned(ASSL) then
    Exit;

  LErr:=GStack.WSGetLastError;
  try
    LInstance:=GetInstanceFromSSL(ASSL);
    if not Assigned(lInstance) then
      Exit;

    lContext:=lInstance.FCtx;
    if Assigned(lContext) then
      lContext.DoOnMessage(lInstance, AWriteP, AVersion, AContentType, ABuf, ALen);

  finally
    GStack.WSSetLastError(LErr);
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
  Result:=1; //
  if not Assigned(ASSL) then
    Exit; // ssl parameter can be null if the SSL_CTX is changing before the
          // SSL object is allocated.

  try
    LErr:=GStack.WSGetLastError;
    try
      lInstance:=TTaurusTLSSslSocket(AEx);
        if not Assigned(lInstance) then
          Exit;

        lContext:=lInstance.FCtx;
        if not Assigned(lContext) then
          Exit;

        lResult:=False;
        lContext.DoOnSecurityCheck(lInstance, AOp, ABits, ANid, AOther, lResult);

        if lResult then
          Result:=1
        else
          Result:=0;
    finally
      GStack.WSSetLastError(LErr);
    end;
  except
    Result:=0; // Failed
  end;
end;

class function TTaurusTLSSslSocket.CbSslVerify(const APreVerify: TIdC_INT;
  ACtx: PX509_STORE_CTX): TIdC_INT;
var
  lInstance: TTaurusTLSSslSocket;
  lContext: TTaurusTLSSslSocketCtx;
  lSSL: PSSL;
  lErr: integer;
  lResult, lContinue: boolean;

begin
  Result:=APreVerify;

  if not Assigned(ACtx) then // this shouldn't happen ever
    Exit;

  try
    lErr:=GStack.WSGetLastError;
    try
      lSSL:=X509_STORE_CTX_get_ex_data(ACtx, SSL_get_ex_data_X509_STORE_CTX_idx());
      if not Assigned(lSSL) then
        Exit;

      lResult:=APreVerify = 1;
      lContinue:=True;

      lInstance:=GetInstanceFromSSL(lSSL);
      lContext:=lInstance.FCtx;
      if Assigned(lContext) then
      begin
        lContext.DoOnVerifyCertificate(lInstance, ACtx, lResult, lContinue);
        if lContinue then Result:=1 else Result:=0;
        if lResult then
          X509_STORE_CTX_set_error(ACtx, X509_V_OK);
      end;
    finally
      GStack.WSSetLastError(lErr);
    end;
  except
    Result:=0;
  end;
end;

{ TTaurusTLSSSLSession }

constructor TTaurusTLSSSLSession.Create(ASocket: TTaurusTLSSslSocket);
begin
  inherited Create;
  if Assigned(ASocket) and (ASocket.State in [seEstablished..seReleased]) and
    Assigned(ASocket.SSL) then
    FSession:=SSL_get1_session(ASocket.SSL)
  else
    FSession:=nil;
end;

destructor TTaurusTLSSSLSession.Destroy;
begin
  SSL_SESSION_free(FSession);
  inherited;
end;

{ TTaurusTLSClientSocket }

function TTaurusTLSClientSocket.GetClientCtx: TTaurusTLSSslClientCtx;
begin
  Result:=Ctx as TTaurusTLSSslClientCtx;
end;

procedure TTaurusTLSClientSocket.SetECHStatus(AECHStatus: TTaurusECHClientStatus);
begin
  FECHStatus:=AECHStatus;
end;

procedure TTaurusTLSClientSocket.SetupConnection;
var
  lRetCode: TIdC_INT;
  lContext: TTaurusTLSSslClientCtx;
  lIdentity: RawByteString;
  lECHStore: TTaurusTLSECHStore; // PALOFF 'Created and freed objects'

begin
  lContext:=ClientCtx;
  if not Assigned(lContext) then
    ETaurusTLSClientSSLSocketSetupError.RaiseWithMessage(RSOSSLModeNotSet);

  // Setup session resumption
  if Assigned(FSessionToResume) then
    SSL_set_session(FSSL, FSessionToResume.SSLSession);

  SetECHStatus(echCliNotConfigured);

  // 1. Configure Hostname Verification on FSSL's local parameter block
  // (Moves your previous SetupHostnameVerification logic here, fully self-contained)
  SetupHostnameVerification;

  // 2. Wire-Level SNI Suppression Check
  if lContext.SNIKind = skNoSNI then
    Exit;

  // 3. Retrieve pre-computed logical identity
  lIdentity:=lContext.Identity;

  if (lIdentity <> '') and (not lContext.IsIdentityIP) then
  begin
    if lContext.UseECH then
    begin
      // Real ECH Path
      lECHStore:=TTaurusTLSECHStore.Create;
      try
        lECHStore.SetConfigList(lContext.ECHConfigListRaw);
        lECHStore.Attach(FSSL);
      finally
        lECHStore.Free;
      end;

      // Configure ECH Server Names using pre-computed parameters
      lRetCode:=SSL_ech_set1_server_names(
        FSSL,
        PIdAnsiChar(lIdentity),  // PALOFF Possible bad typecast
        PIdAnsiChar(lContext.ECHOuterSNIRaw),  // PALOFF Possible bad typecast
        lContext.ECHNoOuterVal
      );

      if lRetCode <= 0 then
        ETaurusTLSClientSSLSocketHostNameError.RaiseException(FSSL, lRetCode,
          RMSG_SetECHHostNamesSetup_err);
    end
    else
    begin
      // Standard SNI (or GREASE) Path
      if lContext.UseGREASE then
        SSL_set_options(FSSL, SSL_OP_ECH_GREASE);

      lRetCode:=SSL_set_tlsext_host_name(FSSL, PIdAnsiChar(lIdentity));  // PALOFF Possible bad typecast
      if lRetCode <= 0 then
        ETaurusTLSClientSSLSocketHostNameError.RaiseException(FSSL, lRetCode,
          RSSSLSettingTLSHostNameError_2);
    end;
  end;
end;

procedure TTaurusTLSClientSocket.SetupHostnameVerification;
var
  lParams: TTaurusTLSX509VerifyParamSSL; // PALOFF 'Created and freed objects'
  lTargetName: RawByteString;
  lContext: TTaurusTLSSslClientCtx;
  lIsIP: Boolean;
  lRet: TIdC_INT;

begin
  lContext:=ClientCtx;
  if not lContext.VerifyHostname then
    Exit;

  // 1. Determine the logical identity and IP flag
  lTargetName:=lContext.Identity;
  if lTargetName = '' then
    Exit;

  // 2. Get the connection-specific verification parameters (cloned from SSL_CTX)
  lParams:=TTaurusTLSX509VerifyParamSSL.Create(FSSL);
  try

    lIsIP:=lContext.IsIdentityIP; // Use the pre-computed, cached property

    // 3. Bind the primary identity directly to the connection's parameter block.
    // This preserves all other inherited parameters (CRL flags, depth, etc.)
    if lIsIP then
      // IPv4/IPv6 Literal Validation
      lParams.SetIpAddressA(lTargetName)
    else
    begin
      // Standard DNS / Wildcard Validation
      lParams.AddHostA(lTargetName);
      lRet:=SSL_set_tlsext_host_name(FSSL, PIdAnsiChar(lTargetName));
      if lRet <= 0 then
        ETaurusTLSClientSSLSocketHostNameError.RaiseException(FSSL, lRet,
          RMSG_SetHostNameVerificationSetup_err);
    end;
  finally
    lParams.Free;
  end;
end;

procedure TTaurusTLSClientSocket.Connect(const pHandle: TIdStackSocketHandle;
  ASessionToResume: TTaurusTLSSSLSession);
begin
  FSessionToResume:=ASessionToResume;
  Connect(pHandle);
end;

function TTaurusTLSClientSocket.DoHandshakeIteration: TTaurusTLSSslSocketState;
var
  lRet, lErr: Integer;
  lStatus: TIdC_INT;
  lInner, lOuter: PIdAnsiChar;
  lECHConfigBuf: PByte;
  lECHConfigLen: NativeUInt;
  lNewConfigBase64: string; // PALOFF Managed local variable can be declared inline
  lContext: TTaurusTLSSslClientCtx;

begin
  lContext:=ClientCtx;
  ClearError;
  Result:=seError;

  lRet:=SSL_connect(SSL);

  if lRet > 0 then
  begin
    CheckPeerCertificateValidationResult;
    // Verify ECH status prior to accepting handshake success
    if lContext.UseECH then
    begin
      lInner:=nil;
      lOuter:=nil;
      try
        lStatus:=SSL_ech_get1_status(SSL, @lInner, @lOuter);
        GetSSLError(SSL_ERROR_SSL);

        case lStatus of
        SSL_ECH_STATUS_SUCCESS,
        SSL_ECH_STATUS_BACKEND:
          SetECHStatus(echCliSuccess);

        SSL_ECH_STATUS_GREASE_ECH,
        SSL_ECH_STATUS_FAILED_ECH,
        SSL_ECH_STATUS_FAILED_ECH_BAD_NAME:
          begin
            SetECHStatus(echCliFailed);
            lECHConfigBuf:=nil;
            lECHConfigLen:=0;


            // Attempt to extract the updated keys provided by the server
            if SSL_ech_get1_retry_config(SSL, @lECHConfigBuf, @lECHConfigLen) > 0 then
            begin
              try
                if (lECHConfigBuf <> nil) and (lECHConfigLen > 0) then
                begin
                  lNewConfigBase64:=EncodeConfigList(lECHConfigBuf, lECHConfigLen);
                  ETaurusTLSECHRetryRequired.RaiseWithMessage(
                    'ECH Handshake error. Try to reconnect with updated ECH Config List.',
                    lNewConfigBase64
                  );
                end;
              finally
                OPENSSL_free(lECHConfigBuf);
              end;
            end;

            // If no keys were returned, it is a hard rejection
            ETaurusTLSECHRejectedError.RaiseWithMessage(
              'ECH Handshake failed. The server rejected the key and provided no retry configuration.');
          end;

        SSL_ECH_STATUS_NOT_TRIED,
        SSL_ECH_STATUS_NOT_CONFIGURED:
          begin
            if lContext.ECHFlags.Enforced then
              { TODO : To make ResourceString }
              ETaurusTLSECHDowngradeError.RaiseWithMessage(
                'ECH Handshake bypassed. Possible downgrade attack or configuration mismatch.')
            else
              SetECHStatus(echCliNotConfigured);
          end;

        SSL_ECH_STATUS_BAD_NAME:
          { TODO :
            Need to double check if it needs to raise the exception
            or just fire an OnDebug event }
          { TODO : To make ResourceString }
          ETaurusTLSECHBadNameError.RaiseWithMessage(
            'ECH Handshake completed but the server certificate did not match the inner name.');
        else
          // Covers SSL_ECH_STATUS_FAILED (0), SSL_ECH_STATUS_BAD_CALL (-100), and any other negative codes
          { TODO : To make ResourceString }
          ETaurusTLSECHProtocolError.RaiseWithMessage(
            'ECH Handshake failed due to an internal OpenSSL or protocol error.');
        end;
      finally
        // Clean up ECH status output buffers allocated by OpenSSL
        if Assigned(lInner) then
          OPENSSL_free(lInner);
        if Assigned(lOuter) then
          OPENSSL_free(lOuter);
      end;
    end;

    Result:=seEstablished;
    Exit;
  end;

 lErr:=GetSSLError(lRet);
  case lErr of
  SSL_ERROR_SYSCALL:
    { TODO : To make ResourceString }
    ETaurusTLSSSLSocketConnectionReset.RaiseException(FSSL, lErr,
      'Handshake reset by peer.');

  SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE: // PALOFF 'Empty case labels'
    // Waiting for data
    ;

  else
    { TODO : To make ResourceString }
    ETaurusTLSHandshakeError.RaiseExceptionCode(lErr, lRet, 'Fatal handshake error.');
  end;
end;

function TTaurusTLSClientSocket.DoShutdown: TTaurusTLSSslSocketState;
begin
  try
    Result:=inherited DoShutdown;
  finally
    FreeAndNil(FSessionToResume);
  end;
end;

{ TTaurusTLSBuilderCustomMetaField }

constructor TTaurusTLSBuilderCustomMetaField.Create(
  AParent: TTaurusTLSSslSocketCtxBuilder);
begin
  Assert(Assigned(AParent), 'AParent must not be ''nil''.'); // Do not localize
  FParent:=AParent;
end;

procedure TTaurusTLSBuilderCustomMetaField.Lock;
begin
  Parent.Lock;
end;

procedure TTaurusTLSBuilderCustomMetaField.Unlock;
begin
  Parent.Unlock;
end;

procedure TTaurusTLSBuilderCustomMetaField.SetDirty;
begin
  Parent.SetDirty;
end;

{ TTaurusTLSMetaX509VerifyParam }

constructor TTaurusTLSMetaX509VerifyParam.Create(
  AParent: TTaurusTLSSslSocketCtxBuilder);
begin
  inherited Create(AParent);
  FHosts:=THosts.Create;
  FIpAddresses:=TIPAddresses.Create;
  FEmails:=TEmails.Create;
end;

destructor TTaurusTLSMetaX509VerifyParam.Destroy;
begin
  FreeAndNil(FHosts);
  FreeAndNil(FEmails);
  FreeAndNil(FIpAddresses);
  inherited;
end;

function TTaurusTLSMetaX509VerifyParam.IsPropSet(
  const AProp: TProperty): boolean;
begin
  Result:=AProp in FProps;
end;

function TTaurusTLSMetaX509VerifyParam.GetHost(
  const Item: TIdC_INT): string;
begin
  Lock;
  try
    Result:=FHosts[Item];
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.ResetProp(const AProp: TProperty);
begin
  Exclude(FProps, AProp);
  inherited SetDirty;
end;

procedure TTaurusTLSMetaX509VerifyParam.SetDirty(const AProp: TProperty);
begin
  Include(FProps, AProp);
  inherited SetDirty;
end;

function TTaurusTLSMetaX509VerifyParam.GetHostCount: TIdC_INT;
begin
  Lock;
  try
    Result:=FHosts.Count;
  finally
    Unlock;
  end;
end;

function TTaurusTLSMetaX509VerifyParam.GetEmail(
  const Item: TIdC_INT): string;
begin
  Lock;
  try
    Result:=FEmails[Item];
  finally
    Unlock;
  end;
end;

function TTaurusTLSMetaX509VerifyParam.GetEmailCount: TIdC_INT;
begin
  Lock;
  try
    Result:=FEmails.Count;
  finally
    Unlock;
  end;
end;

function TTaurusTLSMetaX509VerifyParam.GetIpAddress(
  const Item: TIdC_INT): string;
begin
  Lock;
  try
    Result:=FIpAddresses[Item];
  finally
    Unlock;
  end;
end;

function TTaurusTLSMetaX509VerifyParam.GetIpAddressCount: TIdC_INT;
begin
  Lock;
  try
    Result:=FIpAddresses.Count;
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.SetDepth(
  const AValue: TIdC_INT);
begin
  if FDepth = AValue then
    Exit;
  Lock;
  try
    FDepth:=AValue;
    SetDirty(vfDefDepth);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.SetPurpose(
  const AValue: TTaurusTLSX509Purpose);
begin
  if FPurpose = AValue then
    Exit;
  Lock;
  try
    FPurpose:=AValue;
    SetDirty(vfDefPurpose);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.SetSecurityBits(
  const AValue: TTaurusTLSSecurityBits);
begin
  if FSecurityBits = AValue then
    Exit;
  Lock;
  try
    FSecurityBits:=AValue;
    SetDirty(vfDefSecurityBits);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.SetTime(
  const AValue: TDateTime);
begin
  if SameDateTime(FTime, AValue) then
    Exit;
  Lock;
  try
    FTime:=AValue;
    SetDirty(vfDefTime);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.SetVerifyFlags(
  const AValue: TTaurusTLSX509VerifyFlags);
begin
  if FVerifyFlags = AValue then
    Exit;
  Lock;
  try
    FVerifyFlags:=AValue;
    SetDirty(vfDefFlVerify);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.SetHostCheckFlags(
  const AValue: TTaurusTLSX509HostCheckFlags);
begin
  if FHostCheckFlags = AValue then
    Exit;
  Lock;
  try
    FHostCheckFlags:=AValue;
    SetDirty(vfDefFlHostCheck);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.SetInheritanceFlags(
  const AValue: TTaurusTLSX509InheritanceFlags);
begin
  if FInheritanceFlags = AValue then
    Exit;
  Lock;
  try
    FInheritanceFlags:=AValue;
    SetDirty(vfDefFlInheritance);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.AddHost(const AValue: string);
begin
  Lock;
  try
    FHosts.Add(AValue);
    SetDirty(vfDefHosts);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.SetHost(
  const Item: TIdC_INT; const AValue: string);
begin
  Lock;
  try
    if AValue = '' then
      FHosts.Delete(Item)
    else if Item > HostCount then
      FHosts.Add(AValue)
    else
      FHosts[Item]:=AValue;
    SetDirty(vfDefHosts);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.DeleteHost(
  const Item: TIdC_INT);
begin
  Lock;
  try
    FHosts.Delete(Item);
    SetDirty(vfDefHosts);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.AddEMail(const AValue: string);
begin
  Lock;
  try
    FEMails.Add(AValue);
    SetDirty(vfDefEmails);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.SetEmail(
  const Item: TIdC_INT; const AValue: string);
begin
  Lock;
  try
    if AValue = '' then
      FEmails.Delete(Item)
    else if Item > HostCount then
      FEMails.Add(AValue)
    else
      FEMails[Item]:=AValue;
    SetDirty(vfDefEmails);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.DeleteEmail(
  const Item: TIdC_INT);
begin
  Lock;
  try
    FEmails.Delete(Item);
    SetDirty(vfDefEmails);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.AddIpAddress(const AValue: string);
begin
  Lock;
  try
    FIPAddresses.Add(AValue);
    SetDirty(vfDefIPAddresses);
  finally
    Unlock;
  end;
end;

function TTaurusTLSMetaX509VerifyParam.BuildParam: TTaurusTLSX509VerifyParam;
var
  i, lHigh: integer;

begin
  Result:=TTaurusTLSX509VerifyParam.Create;
  try
    if IsSecurityBitsSet then
      Result.SecurityBits:=SecurityBits;

    if IsDepthSet then
      Result.Depth:=Depth;

    if IsPurposeSet then
      Result.Purpose:=Purpose;

    if IsTimeSet then
      Result.Time:=Time;

    if IsVerifyFlagsSet then
      Result.VerifyFlags:=VerifyFlags;

    if IsInheritanceFlagsSet then
      Result.InheritanceFlags:=InheritanceFlags;

    if IsHostCheckFlagsSet then
      Result.HostCheckFlags:=HostCheckFlags;

    // Add hosts
    if IsHostsSet then
      for i:=0 to HostCount-1 do
        Result.AddHost(Hosts[i]);

    // Add IP Address(es)
    if IsIPAddressesSet then
    begin
      lHigh:=IpAddressCount;
      if IsX509StoreMultiIPSupported then
      begin
        for i:=0 to IpAddressCount-1 do
          Result.AddIPAddress(IpAddresses[i]);
        end
        else if lHigh > 0 then
          Result.SetIpAddress(IpAddresses[0]);
    end;

    if IsEmailsSet then
    begin
      lHigh:=EmailCount;
      if IsX509StoreMultiEmailSupported  then
      begin
        for i:=0 to EmailCount-1 do
          Result.AddEmail(Emails[i]);
      end
      else if lHigh > 0 then
        Result.SetEMail(Emails[0])
    end;

  except
    FreeAndNil(Result);
    raise;
  end;

end;

procedure TTaurusTLSMetaX509VerifyParam.SetIpAddress(
  const Item: TIdC_INT; const AValue: string);
begin
  Lock;
  try
    if AValue = '' then
      FIPAddresses.Delete(Item)
    else if Item > HostCount then
      FIPAddresses.Add(AValue)
    else
      FIPAddresses[Item]:=AValue;
    SetDirty(vfDefIPAddresses);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.DeleteIpAddress(
  const Item: TIdC_INT);
begin
  Lock;
  try
    FIpAddresses.Delete(Item);
    SetDirty(vfDefIPAddresses);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.ResetDepth;
begin
  if not IsPropSet(vfDefDepth) then
    Exit;
  Lock;
  try
    ResetProp(vfDefDepth);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.ResetPurspose;
begin
  if not IsPropSet(vfDefPurpose) then
    Exit;
  Lock;
  try
    ResetProp(vfDefPurpose);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.ResetSecurityBits;
begin
  if not IsPropSet(vfDefSecurityBits) then
    Exit;
  Lock;
  try
    ResetProp(vfDefSecurityBits);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.ResetTime;
begin
  if not IsPropSet(vfDefTime) then
    Exit;
  Lock;
  try
    ResetProp(vfDefTime);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.ResetInheritanceFlags;
begin
  if not IsPropSet(vfDefFLInheritance) then
    Exit;
  Lock;
  try
    ResetProp(vfDefFLInheritance);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.ResetHostCheckFlags;
begin
  if not IsPropSet(vfDefFlHostCheck) then
    Exit;
  Lock;
  try
    ResetProp(vfDefFlHostCheck);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.ResetVerifyFlags;
begin
  if not IsPropSet(vfDefFlVerify) then
    Exit;
  Lock;
  try
    ResetProp(vfDefFlVerify);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.ResetHosts;
begin
  if not IsPropSet(vfDefHosts) then
    Exit;
  Lock;
  try
    ResetProp(vfDefHosts);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.ResetEMails;
begin
  if not IsPropSet(vfDefEmails) then
    Exit;
  Lock;
  try
    ResetProp(vfDefEmails);
  finally
    Unlock;
  end;
end;

procedure TTaurusTLSMetaX509VerifyParam.ResetIPAddresses;
begin
  if not IsPropSet(vfDefIPAddresses) then
    Exit;
  Lock;
  try
    ResetProp(vfDefIpAddresses);
  finally
    Unlock;
  end;
end;

end.
