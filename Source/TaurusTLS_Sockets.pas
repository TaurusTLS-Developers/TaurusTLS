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
  TTaurusTLSSslSocketState = (
    seIdle,
    seInitialized,
    seHandshaking,
    seEstablished,
    seClosing,
    seClosed,
    seError
  );
  TTaurusTLSSslSocketStates = set of TTaurusTLSSslSocketState;

  TTaurusTLSSslSocketStateHelper = record helper for TTaurusTLSSslSocketState
  public const
    // Do not localize
    cNames: array[TTaurusTLSSslSocketState] of string = ('Idle', 'Initialized',
      'Handshaking', 'Established', 'Closing', 'Closed', 'Error');  // Do not localize
  private
    function GetAsString: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    property AsString: string read GetAsString;
  end;

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
    property IsMehtodSet: boolean read GetIsMethSet;
    property UseConfigList: boolean read GetUseConfigList;
    property UseGrease: boolean read GetUseGrease;
    property UseGreaseFallback: boolean read GetUseFallback;
    property UseNoOuter: boolean read GetUseNoOuter;
    property Value: TTaurusTLSECHCLiEnums read FValue write SetValue;
  end;

  ETaurusTLSECHCliFlagsError = class(ETaurusTLSError);
  EECHNotSupported = class(ETaurusTLSError);

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
    function GetIsHandshakeStars: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
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
    property IsHandshakeStarts: boolean read GetIsHandshakeStars;
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
      AUi: TTaurusTLSCustomOsslUi); reintroduce; overload; {$IFDEF USE_INLINE}inline; {$ENDIF}
    constructor Create(const AName: string; const AUri: UnicodeString;
      AUi: TTaurusTLSCustomOsslUi); reintroduce; overload; {$IFDEF USE_INLINE}inline; {$ENDIF}
    constructor Create(const AName: string; ABio: TTaurusTLSCustomBIO;
      AUi: TTaurusTLSCustomOsslUi); reintroduce; overload; {$IFDEF USE_INLINE}inline; {$ENDIF}
    constructor CreateMem(const AName: string; AUi: TTaurusTLSCustomOsslUi;
      const AData: TBytes); reintroduce; overload; {$IFDEF USE_INLINE}inline; {$ENDIF}
    constructor CreateMem(const AName: string; AUi: TTaurusTLSCustomOsslUi;
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
    const AError: TTaurusTLSX509Error; out ASuccess: boolean) of object;

  TTaurusTLSOnVerifyCallback = procedure(
    ASender: TObject; ASocket: TTaurusTLSSslSocket;
    ACertValidator: TTaurusTLSX509CertValidator;
    out ASuccess, AContinue: Boolean
  ) of object;

  TTaurusTLSOnClientCertCallback = procedure(ASender: TObject;
    ASocket: TTaurusTLSSslSocket; var ACert: PX509; APKey: PEVP_PKEY
  );

  TTaurusTLSSSLOp = (sslOpRead, sslOpWrite);

  TTaurusTLSOnSSLMessageCallback = procedure(
    ASender: TObject; ASocket: TTaurusTLSSslSocket;
    AOp: TTaurusTLSSSLOp; AVersion: Integer; AContentType: Integer;
    ABuf: Pointer; ALen: NativeUInt) of object;

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

  ETaurusTLSAlpnResultError = class(ETaurusTLSError);

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

  TaurusTLSSslSocketFlag = (
    slfClient,
    slfServer,
    slfVerifyHostname
  );

  TaurusTLSSslSocketFlags = set of TaurusTLSSslSocketFlag;

  TaurusTLSSslSocketFlagsHelper = record helper for TaurusTLSSslSocketFlags
  private
    function GetIsClientSocket: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsServerSocket: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetVerifyHostName: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    property IsClientSocket: boolean read GetIsClientSocket;
    property IsServerSocket: Boolean read GetIsServerSocket;
    property VerifyHostName: boolean read GetVerifyHostName;
  end;

  TTaurusTLSSslSocketCtx = class abstract(TInterfacedObject, ITaurusTLSSslSocketCtx)
  public const
    cVerifyModesDef = [sslvrfPeer];

  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    // For Event parameters
    FSender: TObject;
    FSSLCtx: PSSL_CTX;

    // Common fields
    FFlags: TaurusTLSSslSocketFlags;
    FCertVerifyFlags: TTaurusTLSVerifyModeFlags;
    FSession: PSSL_SESSION;

    // Common Events Events (via SSL_CTX)
    FOnStateChange: TTaurusTLSOnStateChange;
    FOnDebugMessage: TTaurusTLSOnDebugMessage;
    FOnPeerCertError: TTaurusTLSOnPeerCertError;

    // OpenSSL SSL callback events
    FOnVerifyCertificate: TTaurusTLSOnVerifyCallback;
    FOnSecurityCheck: TTaurusTLSOnSecurityCheck;
    FOnStatusInfo: TTaurusTLSOnSSLStatusInfo;
    FOnKeyLog: TTaurusTLSOnKeyLog;

    // SSL_CTX callback method(s)
    class procedure CbCtxKeyLog(const ASSL: PSSL;
      const ALine: PIdAnsiChar); cdecl; static;

    // callback event assignment status flags
    function GetVerifyHostname: boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHasOnStatusInfo: boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHasOnSecurityCheck: boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHasOnVerifyCertificate: boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHasOnKeyLog: boolean;
  protected
    class function NormalizeHostName(const AValue: RawByteString): RawByteString;
      static; {$IFDEF USE_INLINE}inline; {$ENDIF}

    class function GetInstanceFromCtx(ACtx: PSSL_CTX): TTaurusTLSSslSocketCtx;
      static; {$IFDEF USE_INLINE}inline; {$ENDIF}

    // Event handlers
    procedure DoOnStateChange(ASocket: TTaurusTLSSslSocket;
      AOldState, ANewState: TTaurusTLSSslSocketState); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoOnDebug(const AMsg: string); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoOnPeerCertError(ASocket: TTaurusTLSSslSocket;
      ACertificate: TTaurusTLSX509; const AError: TTaurusTLSX509Error;
      out ASuccess: boolean); {$IFDEF USE_INLINE}inline; {$ENDIF}

    // OpenSSL Callback to Event bridges
    procedure DoOnVerifyCertificate(ASocket: TTaurusTLSSslSocket;
      ACtx: PX509_STORE_CTX; out ASuccess, AContinue: boolean);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoOnSecurityCheck(ASocket: TTaurusTLSSslSocket;
      op, bits, nid: TIdC_INT; other: pointer; var AAccept: boolean);
    procedure DoOnStatusInfo(ASocket: TTaurusTLSSslSocket;
      AWhere, ARet: TIdC_INT); {$IFDEF USE_INLINE}inline; {$ENDIF}
    { TODO : This declararion is a subject to change due to security reason. }
    procedure DoOnKeyLog(ASocket: TTaurusTLSSslSocket; ALine: PIdAnsiChar);
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    procedure InitCtxCallbacks; virtual;
    procedure ReleaseCtxCallbacks; virtual;

    // OpenSSL Callback status checkers
    property HasOnStatusInfo: boolean read GetHasOnStatusInfo;
    property HasOnVerifyCertificate: boolean read GetHasOnVerifyCertificate;
    property HasOnSecurityCheck: boolean read GetHasOnSecurityCheck;
    property HasOnKeylog: boolean read GetHasOnKeyLog;

    // IITaurusTLSSocketCtx method(s)
    function GetCtx: TTaurusTLSSslSocketCtx; {$IFDEF USE_INLINE}inline; {$ENDIF}

    // protected setters
    procedure SetCtxOptions(const AValue: TTaurusTLSSSLOptionFlags);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetCipherList(const AValue: string);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetCipherSuites(const AValue: string);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetKeXGroups(const AValue: string);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetSigAlgorithms(const AValue: string);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetMinTLSVersion(const AValue: TTaurusTLSSSLVersion);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetMaxTLSVersion(const AValue: TTaurusTLSSSLVersion);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetVerifyModes(const AValue: TTaurusTLSVerifyModes);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetVerifyParam(const AValue: TTaurusTLSCustomX509VerifyParam);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetTrustStore(const AValue: TaurusTLS_X509Store);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    { TODO : Add more SSL_CTX setters here. }

    property Session: PSSL_SESSION read FSession write FSession;

    property OnStateChange: TTaurusTLSOnStateChange read FOnStateChange
      write FOnStateChange;
    property OnDebugMessage: TTaurusTLSOnDebugMessage read FOnDebugMessage
      write FOnDebugMessage;
    property OnPeerCertError: TTaurusTLSOnPeerCertError read FOnPeerCertError
      write FOnPeerCertError;
    property OnStatusInfo: TTaurusTLSOnSSLStatusInfo read FOnStatusInfo
      write FOnStatusInfo;
    property OnVerifyCertificate: TTaurusTLSOnVerifyCallback read FOnVerifyCertificate
      write FOnVerifyCertificate;

  public
    constructor Create(ASender: TObject; ATLSMeth: PSSL_METHOD);
    destructor Destroy; override;
    procedure CloneSession(ASSL: PSSL); {$IFDEF USE_INLINE}inline; {$ENDIF}

    property Sender: TObject read FSender;
    property SSLCtx: PSSL_CTX read FSSLCtx;
    property CertVerifyFlags: TTaurusTLSVerifyModeFlags
      read FCertVerifyFlags;
    property VerifyHostname: boolean read GetVerifyHostname;
  end;

  ETaurusTLSSslSocketCtxError = class(ETaurusTLSError);

  TTaurusTLSSslClientCtx = class(TTaurusTLSSslSocketCtx)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSessionToResume: PSSL_SESSION;
    FHostname: RawByteString;
    FDefaultSNI: RawByteString;
    FECHFlags: TTaurusTLSECHCliFlags;
    FECHOuterSNI: RawByteString;
    FECHConfigList: RawByteString;
    FIdentity: RawByteString;
    FIdentityIP: boolean;
    FIdentityBuilt: boolean;
    FSNIKind: TTaurusTLSSNICliKind;

    // OpenSSL Callback to Event bridge(s)
    FOnClientCert: TTaurusTLSOnClientCertCallback;

    class function CbCliCert(ASSL: PSSL; var AX509: PX509;
      var APKey: PEVP_PKEY): TIdC_INT; static; cdecl;

    procedure ResetIdentity; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure BuildIdentity; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetECHKind: TTaurusTLSECHCliKind;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetECHMethods: TTaurusTLSECHCliMeths;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetECHConfigList(const AValue: string);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetDefaultSNI: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetDefaultSNI(const AValue: string);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetECHOuterSNI: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetECHOuterSNI(const AValue: string);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetHostName: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetHostName(const AValue: string);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetECHConfigList: string; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIdentity: RawByteString; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetIsIdentityIP: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetECHFlags(const AValue: TTaurusTLSECHCliFlags);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetSNIKind(const AValue: TTaurusTLSSNICliKind);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetECHNoOuterVal: TIdC_INT; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetUseECH: Boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetUseGrease: Boolean;
    function GetECHOuterSNIRaw: RawByteString; {$IFDEF USE_INLINE}inline; {$ENDIF}

    function GetHasOnClientCert: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
  protected
    procedure SetSessionToResume(const ASSL: PSSL);
      {$IFDEF USE_INLINE}inline;{$ENDIF}

    //
    procedure DoOnClientCertCallback(ASocket: TTaurusTLSSslSocket;
      var ACert: PX509; APKey: PEVP_PKEY);

  public
    destructor Destroy; override;

    property HasOnClientCert: boolean read GetHasOnClientCert;
    property SessionToResume: PSSL_SESSION read FSessionToResume;
    property HostName: string read GetHostName write SetHostName;
    property DefaultSNI: string read GetDefaultSNI write SetDefaultSNI;
    property SNIKind: TTaurusTLSSNICliKind read FSNIKind write SetSNIKind;
    property ECHFlags: TTaurusTLSECHCliFlags write SetECHFlags;
    property ECHKind: TTaurusTLSECHCliKind read GetECHKind;
    property ECHMethod: TTaurusTLSECHCliMeths read GetECHMethods;
    property ECHOuterSNI: string read GetECHOuterSNI write SetECHOuterSNI;
    property ECHConfigList: string read GetECHConfigList write SetECHConfigList;

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
    procedure InitCtxCallbacks; override;
    procedure ReleaseCtxCallbacks; override;

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

  TTaurusTLSSslSocketCtxBuilder = class abstract
  private
    FLock: TIdCriticalSection;
    FTLSMeth: PSSL_METHOD;

    FSocketCtx: ITaurusTLSSslSocketCtx;
    FDirty: boolean;

    // standalone SSL_CTX fields
    FMinTLSVersion: TTaurusTLSSSLVersion;
    FMaxTLSVersion: TTaurusTLSSSLVersion;
    FCipherList: string;
    FCipherSuites: string;
    FKeyExchangeGroups: string;
    FSigAlgorithms: string;
    FVerifyModes: TTaurusTLSVerifyModes;
    FSSLContextOptions: TTaurusTLSSSLOptionFlags;

    // Trust Stores collection
    FTrustStores: TTaurusTLSTrustStores;

    // X509 Verify Params fields
    FVfyParamVerifyFlags: TTaurusTLSX509VerifyFlags;
    FVfyParamInhFlags: TTaurusTLSX509InheritanceFlags;
    FVfyParamHostCheckFlags: TTaurusTLSX509HostCheckFlags;
    FVfyParamPurpose: TTaurusTLSX509Purpose;
    FVfyParamDepth: TIdC_INT;
    FVfyParamSecurityBits: TTaurusTLSSecurityBits;
    FVfyParamTime: TDateTime;
    FVfyParamHosts: TStrings;
    FVfyParamEmail: TStrings;
    FVfyParamIpAddress: TStrings;

    // Events
    FOnStateChange: TTaurusTLSOnStateChange;
    FOnDebugMessage: TTaurusTLSOnDebugMessage;
    FOnPeerCertError: TTaurusTLSOnPeerCertError;

    // OpenSSL callback events
    FOnStatusInfo: TTaurusTLSOnSSLStatusInfo;
    FOnSecurityCheck: TTaurusTLSOnSecurityCheck;
    FOnVerifyCertificate: TTaurusTLSOnVerifyCallback;

  protected
    procedure Lock; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure Unlock; {$IFDEF USE_INLINE}inline; {$ENDIF}

    procedure CheckRequirements; virtual;
    function DoNewSocketCtx(ASender: TObject): TTaurusTLSSslSocketCtx; virtual; abstract;
    procedure DoBuildTrustStore(ASocketCtx: TTaurusTLSSslSocketCtx);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoBuildVerifyParam(ASocketCtx: TTaurusTLSSslSocketCtx);
    procedure DoBuild(ASender: TObject; ASocketCtx: TTaurusTLSSslSocketCtx); virtual;

    property TLSMeth: PSSL_METHOD read FTLSMeth;
  public
    constructor Create(ATLSMeth: PSSL_METHOD);
    destructor Destroy; override;
    function Build(ASender : TObject): ITaurusTLSSslSocketCtx; {$IFDEF USE_INLINE}inline; {$ENDIF}

    property IsDirty: boolean read FDirty;
  end;
  ETaurusTLSSslSocketCtxBuildError = class(ETaurusTLSError);

  TTaurusECHClientStatus = (echCliNone, echCliSuccess, echCliFailed,
    echCliRetryConfig, echCliNotConfigured);

  TTaurusTLSSslSocket = class
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
  {$IFDEF DCC}
    [Volatile]
  {$ENDIF}
    FState: TTaurusTLSSslSocketState;
    FSocketHandle: TIdStackSocketHandle;

    // The Dual-Track State Fields
    FContextIntf: ITaurusTLSSslSocketCtx;  // Holds reference count safely
    FCtx: TTaurusTLSSslSocketCtx;
    function GetPerCertificate: TTaurusTLSX509;       // Fast class pointer

    // OpenSSL callback methods
    class procedure CbSslInfo(const ASSL: PSSL;
      AWhere, ARet: TIdC_INT); static; cdecl;
    class procedure CbSslMessage(AWriteP, AVersion,
      AContentType: TIdC_INT; const ABuf: Pointer; ALen: TIdC_SIZET; ASSL: PSSL;
      AArg: Pointer); static; cdecl;
    class function CbSslVerify(const APreVerify: TIdC_INT;
      ACtx: PX509_STORE_CTX): TIdC_INT; static; cdecl;
    class function CbSslSecurityCheck(const ASSL: PSSL; const ACtx: PSSL_CTX;
      AOp, ABits, ANid: TIdC_INT; AOther, AEx: pointer): TIdC_INT; static; cdecl;
    class function CbSrvAlpnSelectCallback(ASSL: PSSL; var AOutProto: PIdAnsiChar;
      var AOutLen: TIdC_UINT8; const AInProtos: PIdAnsiChar;
      AInLen: TIdC_UINT; AArg: Pointer): TIdC_INT; static; cdecl;


  protected
    FSSL: PSSL;
    class function GetInstanceFromSSL(ASSL: PSSL): TTaurusTLSSslSocket; static;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    // Centralized Hostname Verification Helper
    procedure CheckPeerCertificateValidationResult; {$IFDEF USE_INLINE}inline; {$ENDIF}

    function CheckForError(ALastResult: Integer): Integer; virtual;
    function GetSSLError(ALastResult: Integer): Integer; {$IFDEF USE_INLINE}inline; {$ENDIF}

    procedure InitSSL; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure InitSSLCallbacks; virtual;
    procedure SetupConnection; virtual; abstract;
    procedure ReleaseSSL; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure ReleaseSSLCallbacks; virtual;
    procedure BindSocket; {$IFDEF USE_INLINE}inline; {$ENDIF}

    procedure DoHandshake;
    procedure DoHandshakeIteration; virtual; abstract;
    procedure DoShutdown;
    procedure DoSetState(ATarget: TTaurusTLSSslSocketState); virtual;

    function IsValidTransition(ACurrent, ATarget: TTaurusTLSSslSocketState): Boolean; virtual;

    // Event handlers
    procedure DoStateChangeNotify(ACurrent, ATarget: TTaurusTLSSslSocketState); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoDebugLog(const AMessage: string); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure CheckActiveState(const AExpectedStates: TTaurusTLSSslSocketStates); {$IFDEF USE_INLINE}inline; {$ENDIF}

    property SocketHandle: TIdStackSocketHandle read FSocketHandle write FSocketHandle;
    property PeerCertificate: TTaurusTLSX509 read GetPerCertificate;
  public
    // Accepts the interface rather than raw class
    constructor Create(const AConfigIntf: ITaurusTLSSslSocketCtx); virtual;
    destructor Destroy; override;

    procedure TransitionTo(ATarget: TTaurusTLSSslSocketState); virtual;

    procedure Connect(const pHandle: TIdStackSocketHandle); virtual;
    function Send(const ABuffer: TIdBytes; const AOffset, ALength: TIdC_SIZET): TIdC_SIZET; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function Recv(var ABuffer: TIdBytes): TIdC_SIZET; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function Readable: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure Shutdown;

    property SSL: PSSL read FSSL;
    property State: TTaurusTLSSslSocketState read FState;
    property Ctx: TTaurusTLSSslSocketCtx read FCtx;
  end;

  TTaurusTLSClientSocket = class(TTaurusTLSSslSocket)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FECHStatus: TTaurusECHClientStatus;
    function GetClientCtx: TTaurusTLSSslClientCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

  protected
    procedure SetECHStatus(AECHStatus: TTaurusECHClientStatus);
      {$IFDEF USE_INLINE}inline; {$ENDIF}

    procedure SetupConnection; override;
    procedure SetupHostnameVerification;
    procedure DoHandshakeIteration; override;
    property ClientCtx: TTaurusTLSSslClientCtx read GetClientCtx;
  public
    procedure Connect(const pHandle: TIdStackSocketHandle); override;
  end;

  TTaurusTLSPeerSocket = class(TTaurusTLSSslSocket)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
  end;

  /// <summary>
  /// Raised if <c>SSL_set_fd</c> failed.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/SSL_set_fd/">
  /// SSL_set_fd
  /// </seealso>
  ETaurusTLSSslSocketBindError = class(ETaurusTLSAPISSLError);

  ETaurusTLSSocketConfigSSLCtxError = class(ETaurusTLSAPISSLError);
  ETaurusTLSSocketConfigSSLTrustStoreError = class(ETaurusTLSAPISSLError);

  ETaurusTLSCreatingSessionError = class(ETaurusTLSError);
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

  /// <summary>
  /// Raised if certificate validation failed and the message breifly
  /// describes the failure.
  /// </summary>
  ETaurusTLSCertValidationError = class(ETaurusTLSError);

  ETaurusTLSInvalidSocketConfigType = class(ETaurusTLSError);

type
  ETaurusTLSDataBindingError = class(ETaurusTLSAPISSLError);
  ETaurusTLSSettingTLSHostNameError = class(ETaurusTLSAPISSLError);
  ETaurusTLSHandshakeError = class(ETaurusTLSAPISSLError);
  ETaurusTLSClientSocketSSLSetupError = class(ETaurusTLSError);

  // Global support routines

function IsOpenSSLVersion(const AVersion: TTaurusTLSOSSLVersion): boolean;
  {$IFDEF USE_INLINE} inline;{$ENDIF}

function IsECHSupported: boolean; {$IFDEF USE_INLINE} inline;{$ENDIF}

function IsX509StoreMultiIPSupported: boolean; {$IFDEF USE_INLINE} inline;{$ENDIF}

function IsX509StoreMultiEmailSupported: boolean;  {$IFDEF USE_INLINE} inline;{$ENDIF}

implementation

uses
{$IFDEF DCC}
  System.AnsiStrings,
{$ENDIF}
  TaurusTLSHeaders_err,
  TaurusTLSHeaders_sslerr,
  TaurusTLSHeaders_objects,
  TaurusTLS_ResourceStrings,
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
  Result:=IsOpenSSLVersion(cVerMIp);
end;


{ TTaurusTLSSslSocketStateHelper }

function TTaurusTLSSslSocketStateHelper.GetAsString: string;
begin
  Result:=cNames[Self];
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
  FStatusMessage := '';
  FAlertMessage := '';
  lStatusMessage := AnsiStringToString(SSL_state_string_long(FSSL));
  lAlertMessage := AnsiStringToString(SSL_alert_type_string_long(FCode));

  case FStates of
    SSL_CB_ALERT:
      begin
        FStatusMessage := IndyFormat(RSOSSLAlert, [SSL_alert_type_string_long(FCode)]);
        FAlertMessage := lAlertMessage;
      end;
    SSL_CB_READ_ALERT:
      begin
        FStatusMessage := IndyFormat(RSOSSLReadAlert,
          [SSL_alert_type_string_long(FCode)]);
        FAlertMessage := lAlertMessage;
      end;
    SSL_CB_WRITE_ALERT:
      begin
        FStatusMessage := IndyFormat(RSOSSLWriteAlert, [lAlertMessage]);
        FAlertMessage := AnsiStringToString(SSL_alert_desc_string_long(FCode));
      end;
    SSL_CB_ACCEPT_LOOP:
      begin
        FStatusMessage := RSOSSLAcceptLoop;
        FAlertMessage := lStatusMessage;
      end;
    SSL_CB_ACCEPT_EXIT:
      begin
        if FCode < 0 then
        begin
          FStatusMessage := RSOSSLAcceptError;
        end
        else
        begin
          if FCode = 0 then
          begin
            FStatusMessage := RSOSSLAcceptFailed;
          end
          else
          begin
            FStatusMessage := RSOSSLAcceptExit;
          end;
        end;
        FAlertMessage := lStatusMessage;
      end;
    SSL_CB_CONNECT_LOOP:
      begin
        FStatusMessage := RSOSSLConnectLoop;
        FAlertMessage := lStatusMessage;
      end;
    SSL_CB_CONNECT_EXIT:
      begin
        if FCode < 0 then
        begin
          FStatusMessage := RSOSSLConnectError;
        end
        else
        begin
          if FCode = 0 then
          begin
            FStatusMessage := RSOSSLConnectFailed
          end
          else
          begin
            FStatusMessage := RSOSSLConnectExit;
          end;
        end;
        FAlertMessage := lStatusMessage;
      end;
    SSL_CB_HANDSHAKE_START:
      begin
        FStatusMessage := RSOSSLHandshakeStart;
        FAlertMessage := lStatusMessage;
      end;
    SSL_CB_HANDSHAKE_DONE:
      begin
        FStatusMessage := RSOSSLHandshakeDone;
        FAlertMessage := lStatusMessage;
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
  Result:=PIdC_INT(@AValue)^ and cStateFlagsMask;;
{$IFEND}
end;

function TTaurusTLSSslState.GetIsConnect: boolean;
begin
  Result := stfConnect in StateFlags;
end;

function TTaurusTLSSslState.GetIsAccept: boolean;
begin
  Result := stfAccept in StateFlags;
end;

function TTaurusTLSSslState.GetIsInLoop: boolean;
begin
  Result := stfLoop in StateFlags;
end;

function TTaurusTLSSslState.GetIsAlert: boolean;
begin
  Result := stfAlert in StateFlags;
end;

function TTaurusTLSSslState.GetIsRead: boolean;
begin
  Result := stfRead in StateFlags;
end;

function TTaurusTLSSslState.GetIsWrite: boolean;
begin
  Result := stfWrite in StateFlags;
end;

function TTaurusTLSSslState.GetIsHandshakeStars: boolean;
begin
  Result := stfHandShakeStart in StateFlags;
end;

function TTaurusTLSSslState.GetIsHandshakeDone: boolean;
begin
  Result := stfHandShakeDone in StateFlags;
end;

function TTaurusTLSSslState.GetIsReadAlert: boolean;
begin
  Result := IsAlert and IsRead;
end;

function TTaurusTLSSslState.GetIsWriteAlert: boolean;
begin
  Result := IsAlert and IsWrite;
end;

function TTaurusTLSSslState.GetIsAcceptLoop: boolean;
begin
  Result := IsAccept and IsInLoop;
end;

function TTaurusTLSSslState.GetIsAcceptExit: boolean;
begin
  Result := IsAccept and IsExit;
end;

function TTaurusTLSSslState.GetIsConnectLoop: boolean;
begin
  Result := IsConnect and IsInLoop;
end;

function TTaurusTLSSslState.GetIsExit: boolean;
begin
  Result:=stfExit in StateFlags;
end;

function TTaurusTLSSslState.GetIsConnectExit: boolean;
begin
  Result := IsConnect and IsExit;
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
  Result := (FOp and SSL_SECOP_PEER) <> 0;
end;

function TTaurusTLSSecurityCheckState.GetIsCipher: Boolean;
begin
  Result := (FOp and SSL_SECOP_OTHER_TYPE) = SSL_SECOP_OTHER_CIPHER;
end;

function TTaurusTLSSecurityCheckState.GetIsCurve: Boolean;
begin
  Result := (FOp and SSL_SECOP_OTHER_TYPE) = SSL_SECOP_OTHER_CURVE;
end;

function TTaurusTLSSecurityCheckState.GetIsDH: Boolean;
begin
  Result := (FOp and SSL_SECOP_OTHER_TYPE) = SSL_SECOP_OTHER_DH;
end;

function TTaurusTLSSecurityCheckState.GetIsPKey: Boolean;
begin
  Result := (FOp and SSL_SECOP_OTHER_TYPE) = SSL_SECOP_OTHER_PKEY;
end;

function TTaurusTLSSecurityCheckState.GetIsSigAlg: Boolean;
begin
  Result := (FOp and SSL_SECOP_OTHER_TYPE) = SSL_SECOP_OTHER_SIGALG;
end;

function TTaurusTLSSecurityCheckState.GetIsCert: Boolean;
begin
  Result := (FOp and SSL_SECOP_OTHER_TYPE) = SSL_SECOP_OTHER_CERT;
end;

function TTaurusTLSSecurityCheckState.GetNidShortName: string;
var
  lName: PIdAnsiChar;
begin
  Result := '';
  if FNid <> 0 then
  begin
    lName := OBJ_nid2sn(FNid);
    if Assigned(lName) then
      Result := AnsiStringToString(lName);
  end;
end;

function TTaurusTLSSecurityCheckState.GetNidLongName: string;
var
  lName: PIdAnsiChar;
begin
  Result := '';
  if FNid <> 0 then
  begin
    lName := OBJ_nid2ln(FNid);
    if Assigned(lName) then
      Result := AnsiStringToString(lName);
  end;
end;

function TTaurusTLSSecurityCheckState.GetCipherName: string;
var
  lName: PIdAnsiChar;
begin
  Result := '';
  // Verify that the payload is actually a cipher, and that the pointer is valid
  if IsCipher and Assigned(FOther) then
  begin
    lName := SSL_CIPHER_get_name(FOther);
    if Assigned(lName) then
      Result := AnsiStringToString(lName);
  end;
end;

function TTaurusTLSSecurityCheckState.GetCertificate: TTaurusTLSX509;
begin
  if Assigned(FCert) then
    Exit(FCert);

  Result := nil;
  // Verify that the payload is actually a certificate, and that the pointer is valid
  if IsCert and Assigned(FOther) then
    // Instantiates a non-owning wrapper around the unmanaged X509 pointer.
    // The record instance takes takes ownership of this wrapper.
    // The OnSecurityLevel Event handler MAT NOT FREE the certificate instance.
    Result := TTaurusTLSX509.Create(FOther, False);
  FCert:=Result;
end;

{ TTaurusTLSTrustStore }

constructor TTaurusTLSTrustStore.Create(const AName: string;
  const AUri: RawByteString; AUi: TTaurusTLSCustomOsslUi);
begin
  inherited Create(AUri, AUi, cFilter);
  SetName(AName);
end;

constructor TTaurusTLSTrustStore.Create(const AName: string;
  const AUri: UnicodeString; AUi: TTaurusTLSCustomOsslUi);
begin
  inherited Create(AUri, AUi, cFilter);
  SetName(AName);
end;

constructor TTaurusTLSTrustStore.Create(const AName: string;
  ABio: TTaurusTLSCustomBIO; AUi: TTaurusTLSCustomOsslUi);
begin
  inherited Create(ABio, AUi, cFilter);
  SetName(AName);
end;

constructor TTaurusTLSTrustStore.CreateMem(const AName: string;
  AUi: TTaurusTLSCustomOsslUi; const AData: string);
var
  lBio: TTaurusTLSRawByteStringBIO; // PALOFF 'Created and freed objects'

begin
  lBio:=TTaurusTLSRawByteStringBIO.Create(RawByteString(AData)); // PALOFF 'TBytes cast to RawByteString' // Why PAL detects AData as  TBytes ???
  try
    Create(AName, lBio, AUi);
  finally
    lBio.Free;
  end;
end;

constructor TTaurusTLSTrustStore.CreateMem(const AName: string;
  AUi: TTaurusTLSCustomOsslUi; const AData: TBytes);
var
  lBio: TTaurusTLSBytesBio;  // PALOFF 'Created and freed objects'

begin
  lBio:=TTaurusTLSBytesBio.Create(AData);
  try
    Create(AName, lBio, AUi);
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
  Result:=inherited TryAdd(AValue.Name, AValue);
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
      { TODO : To make ResourseString }
      'Invalid ALPN result value: %d.', [AValue]);
  Self:=TTaurusTLSAlpnResult(AValue);
end;

{ TTaurusTLSAlpnSelector }

{$IF POINTERMATH = OFF}
  {$DEFINE ENABLE_POINTERMATH}
  {$POINTERMATH ON}
{$IFEND}
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
        { TODO : To make ResourseString }
        'ALPN Input list corrupted. Unexpected Zero Lenght element found.');

    Inc(lPos);
    lPair.FOffset:=lPos;
    if ((lPos-AInProtos)+lLen) > AInLen then // Boundary check
      ETaurusTLSAlpnResultError.RaiseWithMessage(
        { TODO : To make ResourseString }
        'ALPN Input list corrupted. Element length is out input bounds.');

    SetString(lPair.FValue, PIdAnsiChar(lPos), lLen); // PALOFF PIdC_UINT8 cast to PIdAnsiChar
    FPairs[lCount]:=lPair;

    Inc(lCount);
    Inc(lPos, lLen);
  until (lPos-AInProtos) >= AInLen;

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
  Result := Length(FPairs);
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
    { TODO : To make ResourseString }
    raise ERangeError.CreateFmt('ALPN selection index out of range: %d.', [AItem]);

  lPair:=FPairs[AItem];
  FOutProto:=lPair.FOffset;
  FOutLen:=Length(lPair.FValue);
  FResultValue:=alpnSuccess;
end;

{ TaurusTLSSslSocketFlagsHelper }

function TaurusTLSSslSocketFlagsHelper.GetIsClientSocket: boolean;
begin
  Result:=slfClient in Self;
end;

function TaurusTLSSslSocketFlagsHelper.GetIsServerSocket: boolean;
begin
  Result:=slfServer in Self;
end;

function TaurusTLSSslSocketFlagsHelper.GetVerifyHostName: boolean;
begin
  Result:=slfVerifyHostname in Self;
end;

{ TTaurusTLSSslSocketCtxBuilder }

constructor TTaurusTLSSslSocketCtxBuilder.Create(ATLSMeth: PSSL_METHOD);
begin
  inherited Create;
  FDirty:=True;
  FTLSMeth:=ATLSMeth;
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

procedure TTaurusTLSSslSocketCtxBuilder.DoBuildTrustStore(
  ASocketCtx: TTaurusTLSSslSocketCtx);
var
  lTrustStores: TTaurusTLSTrustStores;
  lX509Store: TaurusTLS_X509Store; // PALOFF 'Created and freed objects'
  lStorePair: TPair<string, TTaurusTLSTrustStore>;

begin
  lTrustStores:=FTrustStores;
  if not (Assigned(lTrustStores) and (lTrustStores.Count > 0)) then
    Exit;

  lX509Store:=TaurusTLS_X509Store.Create;
  try
    for lStorePair in FTrustStores do
      lX509Store.AppendFromOsslStore(lStorePair.Value, [sitCert, sitCRL]);
    lX509Store.AttachToSSLCtx(ASocketCtx.SSLCtx);
  finally
    lX509Store.Free;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.DoBuildVerifyParam(
  ASocketCtx: TTaurusTLSSslSocketCtx);
var
  lVfyParam: TTaurusTLSX509VerifyParam; // PALOFF 'Created and freed objects'
  i, lHigh: integer;

begin
  lVfyParam:=TTaurusTLSX509VerifyParam.Create;
  try
    with lVfyParam do
    begin
      VerifyFlags:=FVfyParamVerifyFlags;
      InheritanceFlags:=FVfyParamInhFlags;
      HostCheckFlags:=FVfyParamHostCheckFlags;
      Purpose:=FVfyParamPurpose;
      Depth:=FVfyParamDepth;
      SecurityBits:=FVfyParamSecurityBits;
      Time:=FVfyParamTime;
      // We do not clear
      if Assigned(FVfyParamHosts) then
        for i:=0 to FVfyParamHosts.Count-1 do
          AddHost(FVfyParamHosts[i]);

      if Assigned(FVfyParamIpAddress) then
      begin
        lHigh:=FVfyParamIpAddress.Count;
        if not (IsX509StoreMultiIPSupported and (lHigh > 0)) then
          SetIpAddress(FVfyParamIpAddress[0])
        else
          for i:=0 to FVfyParamIpAddress.Count-1 do
            AddIPAddress(FVfyParamIpAddress[i]);
      end;

      if Assigned(FVfyParamEmail) then
      begin
        lHigh:=FVfyParamEmail.Count;
        if not (IsX509StoreMultiIPSupported and (lHigh > 0)) then
          SetEMail(FVfyParamEmail[0])
        else
          for i:=0 to FVfyParamEmail.Count-1 do
            AddIPAddress(FVfyParamEmail[i]);
      end;

    end;
    lVfyParam.AttachToSSLCtx(ASocketCtx.SSLCtx);
  finally
    lVfyParam.Free;
  end;
end;

procedure TTaurusTLSSslSocketCtxBuilder.CheckRequirements;
begin

end;

procedure TTaurusTLSSslSocketCtxBuilder.DoBuild(ASender: TObject;
  ASocketCtx: TTaurusTLSSslSocketCtx);
var
  lCtx: PSSL_CTX;

begin
  Assert(Assigned(ASender), '''ASender'' parameter must not be ''nil'' value.'); // Do not localize
  Assert(Assigned(ASocketCtx),
    '''ASocketCtx'' parameter must not be ''nil'' value.'); // Do not localize
  lCtx:=ASocketCtx.SSLCtx;

  DoBuildTrustStore(ASocketCtx);
  DoBuildVerifyParam(ASocketCtx);

  if SSL_CTX_set_min_proto_version(lCtx, FMinTLSVersion.AsInt) <= 0 then
    { TODO : To make ResourseString }
    ETaurusTLSSslSocketCtxBuildError.RaiseWithMessage('Error setting Minimal TLS Version.');

  if SSL_CTX_set_max_proto_version(lCtx, FMaxTLSVersion.AsInt) <= 0 then
    { TODO : To make ResourseString }
    ETaurusTLSSslSocketCtxBuildError.RaiseWithMessage('Error setting Maximal TLS Version.');

  if SSL_CTX_set_cipher_list(lCtx, PAnsiChar(RawByteString(FCipherList))) <= 0 then
    ETaurusTLSSslSocketCtxBuildError.RaiseWithMessageFmt(
    { TODO : To make ResourseString }
      'Error setting list of ciphers: ''%s''.', [FCipherList]);

  if SSL_CTX_set_ciphersuites(lCtx, PAnsiChar(RawByteString(FCipherSuites))) <= 0 then
    ETaurusTLSSslSocketCtxBuildError.RaiseWithMessageFmt(
    { TODO : To make ResourseString }
      'Error setting list of cipher suites: ''%s''.', [FCipherSuites]);

{
      FOnStateChange: TTaurusTLSOnStateChange;
      FOnDebugMessage: TTaurusTLSOnDebugMessage;
      FOnSecurityLevel: TTaurusTLSOnSecurityLevel;
      FOnStatusInfo: TTaurusTLSOnSSLStatusInfo;
      FOnVerifyCertificate: TTaurusTLSOnVerifyCallback;
}
  ASocketCtx.SetVerifyModes(FVerifyModes);
end;

function TTaurusTLSSslSocketCtxBuilder.Build(ASender: TObject): ITaurusTLSSslSocketCtx;
var
  lSocketCtx: TTaurusTLSSslSocketCtx; // PALOFF 'Created and freed objects'

begin
  Lock;
  try
    if (not IsDirty) and Assigned(FSocketCtx) then
      Exit(FSocketCtx);

    lSocketCtx:=nil;
    try
      CheckRequirements;
      lSocketCtx:=DoNewSocketCtx(ASender);
      DoBuild(ASender, lSocketCtx);
      Result:=FSocketCtx;
    except
      lSocketCtx.Free;
      raise;
    end;
  finally
    Unlock;
  end;
end;

{ TTaurusTLSSslSocketCtx }

constructor TTaurusTLSSslSocketCtx.Create(ASender: TObject; ATLSMeth: PSSL_METHOD);
begin
  FSender:=ASender;
  FSSLCtx:=SSL_CTX_new(ATLSMeth);
  SetVerifyModes(cVerifyModesDef);
end;

destructor TTaurusTLSSslSocketCtx.Destroy;
begin
  ReleaseCtxCallbacks;
  SSL_CTX_free(FSSLCtx);
  inherited;
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
  except
    //PALOFF "Empty except-block"
    // We must not raise the exception to the OpenSSL stack
  end;
end;

procedure TTaurusTLSSslSocketCtx.CloneSession(ASSL: PSSL);
begin

end;

procedure TTaurusTLSSslSocketCtx.DoOnDebug(const AMsg: string);
begin
  if Assigned(FOnDebugMessage) then
    FOnDebugMessage(FSender, AMsg);
end;

procedure TTaurusTLSSslSocketCtx.DoOnKeyLog(ASocket: TTaurusTLSSslSocket;
  ALine: PIdAnsiChar);
begin
  if Assigned(FOnKeyLog) then
    FOnKeyLog(FSender, ASocket, ALine);
end;

procedure TTaurusTLSSslSocketCtx.DoOnPeerCertError(ASocket: TTaurusTLSSslSocket;
  ACertificate: TTaurusTLSX509; const AError: TTaurusTLSX509Error;
  out ASuccess: boolean);
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
  ACtx: PX509_STORE_CTX; out ASuccess, AContinue: boolean);
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

function TTaurusTLSSslSocketCtx.GetHasOnKeyLog: boolean;
begin
  Result:=Assigned(FOnKeyLog);
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
  lResult:=SSL_CTX_get_app_data(ACtx);
  if Assigned(lResult) and (TObject(lResult) is TTaurusTLSSslSocketCtx) then // PALOFF 'Pointer cast to TObject'
    Result:=TTaurusTLSSslSocketCtx(lResult)
  else
    ETaurusTLSDataBindingError.RaiseWithMessageFmt(
      { TODO : To make ResourseString }
      'SSL_CTX object %p is not bound to a valid TTaurusTLSSslSocketCtx instance.',
      [ACtx]);
end;

function TTaurusTLSSslSocketCtx.GetVerifyHostname: boolean;
begin
  Result:=slfVerifyHostname in FFlags;
end;

procedure TTaurusTLSSslSocketCtx.InitCtxCallbacks;
begin
  // Attach Self to the SSL_CTX
  if SSL_CTX_set_app_data(SSLCtx, Self) <= 0 then
    ETaurusTLSDataBindingError.RaiseWithMessage(
      { TODO : To make ResourseString }
      'Unable to link TTaurusTLSSslSocketCtx instance with SSL_CTX object');

  if HasOnKeylog then
    SSL_CTX_set_keylog_callback(SSLCtx, CbCtxKeyLog);
end;

procedure TTaurusTLSSslSocketCtx.ReleaseCtxCallbacks;
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

procedure TTaurusTLSSslSocketCtx.SetCipherList(const AValue: string);
begin
  if SSL_CTX_set_cipher_list(FSSLCtx, PIdAnsiChar(RawByteString(AValue))) <=0 then  // PALOFF Possible bad typecast
    ETaurusTLSSslSocketCtxError.RaiseWithMessageFmt(
      'Error setting cipher list ''%s'' to the SSL Context.', [AValue]);
end;

procedure TTaurusTLSSslSocketCtx.SetCipherSuites(const AValue: string);
begin
  if SSL_CTX_set_ciphersuites(FSSLCtx, PIdAnsiChar(RawByteString(AValue))) <=0 then // PALOFF Possible bad typecast
    ETaurusTLSSslSocketCtxError.RaiseWithMessageFmt(
      'Error setting cipher suites ''%s'' to the SSL Context.', [AValue]);
end;

procedure TTaurusTLSSslSocketCtx.SetCtxOptions(
  const AValue: TTaurusTLSSSLOptionFlags);
begin
  SSL_CTX_set_options(FSSLCtx, AValue.AsInt);
end;

procedure TTaurusTLSSslSocketCtx.SetKeXGroups(const AValue: string);
begin
  if SSL_CTX_set1_groups_list(FSSLCtx, PIdAnsiChar(RawByteString(AValue))) <=0 then // PALOFF Possible bad typecast
    ETaurusTLSSslSocketCtxError.RaiseWithMessageFmt(
      'Error setting key exchange groups ''%s'' to the SSL Context.', [AValue]);
end;

procedure TTaurusTLSSslSocketCtx.SetMaxTLSVersion(
  const AValue: TTaurusTLSSSLVersion);
begin
  if SSL_CTX_set_min_proto_version(FSSLCtx, AValue.AsInt) <= 0 then
    ETaurusTLSSslSocketCtxError.RaiseWithMessage(RSOSSLMaxProtocolError);
end;

procedure TTaurusTLSSslSocketCtx.SetMinTLSVersion(
  const AValue: TTaurusTLSSSLVersion);
begin
  if SSL_CTX_set_min_proto_version(FSSLCtx, AValue.AsInt) <= 0 then
    ETaurusTLSSslSocketCtxError.RaiseWithMessage(RSOSSLMinProtocolError);
end;

procedure TTaurusTLSSslSocketCtx.SetSigAlgorithms(const AValue: string);
begin
  if SSL_CTX_set1_sigalgs_list(FSSLCtx, PIdAnsiChar(RawByteString(AValue))) <= 0 then // PALOFF Possible bad typecast
    ETaurusTLSSslSocketCtxError.RaiseWithMessageFmt(
      'Error setting signiture algorithms ''%s'' to the SSL Context.', [AValue]);
end;

procedure TTaurusTLSSslSocketCtx.SetTrustStore(const AValue: TaurusTLS_X509Store);
begin
  AValue.AttachToSSLCtx(FSSLCtx);
end;

procedure TTaurusTLSSslSocketCtx.SetVerifyParam(
  const AValue: TTaurusTLSCustomX509VerifyParam);
begin
  if Assigned(AValue) then
    AValue.AttachToSSLCtx(FSSLCtx);
end;

procedure TTaurusTLSSslSocketCtx.SetVerifyModes(
  const AValue: TTaurusTLSVerifyModes);
var
  lFlags: TTaurusTLSVerifyModeFlags;

begin
  lFlags:=TTaurusTLSVerifyModeFlags.Create(AValue);
  SSL_CTX_set_verify(FSSLCtx, lFlags.AsInt, nil);
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

destructor TTaurusTLSSslClientCtx.Destroy;
begin
  SSL_SESSION_free(FSessionToResume);
  inherited;
end;

procedure TTaurusTLSSslClientCtx.DoOnClientCertCallback(
  ASocket: TTaurusTLSSslSocket; var ACert: PX509; APKey: PEVP_PKEY);
begin
  if Assigned(FOnClientCert) then
    FOnClientCert(Sender, ASocket, ACert, APKey);
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

procedure TTaurusTLSSslClientCtx.SetDefaultSNI(const AValue: string);
begin
  FDefaultSNI:=NormalizeHostName(RawByteString(AValue)); // PALOFF 'UnicodeString cast to RawByteString'
  ResetIdentity;
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

procedure TTaurusTLSSslClientCtx.SetECHOuterSNI(const AValue: string);
begin
  FECHOuterSNI:=NormalizeHostName(RawByteString(AValue)); // PALOFF 'UnicodeString cast to RawByteString'
  ResetIdentity;
end;

function TTaurusTLSSslClientCtx.GetHasOnClientCert: boolean;
begin
  Result:=Assigned(FOnClientCert);
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

procedure TTaurusTLSSslClientCtx.SetHostName(const AValue: string);
var
  lValue: RawByteString;

begin
  lValue:=NormalizeHostName(RawByteString(AValue)); // PALOFF 'UnicodeString cast to RawByteString'
  if FHostname = lValue then
    Exit;
  FHostname:=lValue;
end;

function TTaurusTLSSslClientCtx.GetECHConfigList: string;
begin
  Result:=string(FECHConfigList);
end;

procedure TTaurusTLSSslClientCtx.SetECHConfigList(const AValue: string);
var
  lValue: RawByteString;

begin
  lValue:=NormalizeHostName(RawByteString(AValue)); // PALOFF 'UnicodeString cast to RawByteString'
  if FECHConfigList = lValue then
    Exit;
  FECHConfigList:=lValue;
  ResetIdentity;
end;

procedure TTaurusTLSSslClientCtx.SetECHFlags(
  const AValue: TTaurusTLSECHCliFlags);
begin
  if FECHFlags.Value = AValue.Value then
    Exit;
  FECHFlags:=AValue;
  ResetIdentity;
end;

procedure TTaurusTLSSslClientCtx.SetSessionToResume(
  const ASSL: PSSL);
begin
  if Assigned(ASSL) then
    FSessionToResume:= SSL_get1_session(ASSL);
end;

procedure TTaurusTLSSslClientCtx.SetSNIKind(
  const AValue: TTaurusTLSSNICliKind);
begin
  if FSNIKind = AValue then
    Exit;
  FSNIKind:=AValue;
  ResetIdentity;
end;

(*
procedure TTaurusTLSSslClientCtx.DoCloneSession(ASSL: PSSL);
var
  lSess: PSSL_SESSION;

begin
  if not Assigned(FSessionToResume) then
    Exit;

  lSess:=FSessionToResume;
  if (SSL_SESSION_is_resumable(lSess) and SSL_set_session(ASSL, lSess)) <> 1 then
    ETaurusTLSSSLCopySessionId.RaiseWithMessage(RSOSSLCopySessionIdError);
end;
*)

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
  except
    //PALOFF "Empty except-block"
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

procedure TTaurusTLSSslPeerCtx.InitCtxCallbacks;
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

procedure TTaurusTLSSslPeerCtx.ReleaseCtxCallbacks;
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

constructor TTaurusTLSSslSocket.Create(const AConfigIntf: ITaurusTLSSslSocketCtx);
begin
  Assert(Assigned(AConfigIntf), '''AConfigIntf'' should not be ''nil''.'); //Do not localize
  inherited Create;
  FSocketHandle:=Id_INVALID_SOCKET;
  FContextIntf:=AConfigIntf;
  FCtx:=AConfigIntf.Ctx;
end;

destructor TTaurusTLSSslSocket.Destroy;
begin
  ReleaseSSL;
  inherited;
end;

procedure TTaurusTLSSslSocket.InitSSL;
var
  lErr: TIdC_INT;
  
begin
  try
    // 1. Allocate the SSL session structure using the pinned context [3]
    FSSL:=SSL_new(FCtx.SSLCtx);
    if not Assigned(FSSL) then
      ETaurusTLSCreatingSessionError.RaiseWithMessage(RSSSLCreatingSessionError);

    // 2. Bind the Delphi object instance to the SSL handle for callback routing
    lErr:=SSL_set_app_data(FSSL, Self);
    if lErr <= 0 then
      ETaurusTLSDataBindingError.RaiseException(FSSL, lErr,
        RMSG_SslSocketSetAppData_err);

    // 3. Do Socket/Connection specific configuration (Virtual polymorphic hook) [2.2]
    SetupConnection;

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

procedure TTaurusTLSSslSocket.ReleaseSSL;
begin
  if Assigned(FSSL) then
  try
    try
      ReleaseSSLCallbacks;
    except
      //PALOFF "Empty except-block"
      // Suppress callback unbinding errors locally to ensure we proceed to freeing memory
    end;
  finally
    SSL_set_app_data(FSSL, nil);
    SSL_free(FSSL);
    FSSL:=nil;
  end;
end;

procedure TTaurusTLSSslSocket.BindSocket;
var
  lRet: TIdC_INT;

begin
  if Assigned(FSSL) and (FSocketHandle <> Id_INVALID_SOCKET) then
  begin
    ERR_clear_error;
    lRet:=SSL_set_fd(FSSL, FSocketHandle);
    if lRet <= 0 then
      ETaurusTLSSslSocketBindError.RaiseException(FSSL, lRet,
        RSSSLDataBindingError_2);
  end;
end;

procedure TTaurusTLSSslSocket.DoHandshake;
begin
  CheckActiveState([seHandshaking]);
  repeat
    // Emergency exit on thread termination
    if TThread.CurrentThread.CheckTerminated then
      Break;
    DoHandshakeIteration;
    if State = seHandshaking then
    { TODO : IndySleep should be replaced with the smart cross-compiler "spin wait" call. }
      IndySleep(1);
  until State <> seHandshaking;
end;

procedure TTaurusTLSSslSocket.DoDebugLog(const AMessage: string);
var
  lContext: TTaurusTLSSslSocketCtx;

begin
  lContext:=FCtx;
  if Assigned(lContext) then
    lContext.DoOnDebug(AMessage);
end;

procedure TTaurusTLSSslSocket.DoSetState(ATarget: TTaurusTLSSslSocketState);
var
  lCurrentState: TTaurusTLSSslSocketState;

begin
  lCurrentState:=FState;
  if ATarget = lCurrentState then // guard for notification.
    Exit;

  FState:=ATarget;
  DoStateChangeNotify(lCurrentState, ATarget);
end;

procedure TTaurusTLSSslSocket.DoShutdown;
var
  lRet: Integer;

begin
  try
    try
      ERR_clear_error;
      lRet:=SSL_shutdown(FSSL);

      // 1. Handle C-Style OpenSSL Failures
      if lRet < 0 then
      begin
        // If the first call fails (e.g. session was already broken or uninitialized),
        // transition to closed immediately to safely deallocate the SSL handle and exit.
        TransitionTo(seClosed);
        Exit;
      end;

      if lRet = 0 then
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

procedure TTaurusTLSSslSocket.DoStateChangeNotify(ACurrent,
  ATarget: TTaurusTLSSslSocketState);
var
  lContext: TTaurusTLSSslSocketCtx;

begin
  lContext:=FCtx;
  if Assigned(lContext) then
    lContext.DoOnStateChange(Self, ACurrent, ATarget);
end;

function TTaurusTLSSslSocket.GetSSLError(ALastResult: Integer): Integer;
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

function TTaurusTLSSslSocket.IsValidTransition(ACurrent,
  ATarget: TTaurusTLSSslSocketState): Boolean;
begin
  // Global Panic State Rule: seError is valid from any state except Closed and itself
  if ATarget = seError then
    Exit((ACurrent <> seClosed) and (ACurrent <> seError));

  case ACurrent of
    seIdle:
      Result:=ATarget = seInitialized;
    seInitialized:
      Result:=ATarget in [seHandshaking, seClosed];
    seHandshaking:
      Result:=ATarget in [seEstablished, seClosed];
    seEstablished:
      Result:=ATarget in [seClosing, seClosed];
    seClosing:
      Result:=ATarget = seClosed;
    seClosed, seError:
      Result:=False; // Terminal states cannot transition out
  else
    Result:=False;
  end;
end;

procedure TTaurusTLSSslSocket.TransitionTo(ATarget: TTaurusTLSSslSocketState);
var
  lCurrentState: TTaurusTLSSslSocketState;
begin
  lCurrentState:=State; // Using your internal State property

  // 1. Redundant Transition Guard (Fails fast in Debug, exits silently in Release)
  // Do not localize
  Assert(lCurrentState <> ATarget, 'Redundant state transition: '+lCurrentState.AsString);
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

procedure TTaurusTLSSslSocket.Connect(const pHandle: TIdStackSocketHandle);
begin
  FSocketHandle:=pHandle;
  TransitionTo(seInitialized);
  BindSocket;
  TransitionTo(seHandshaking);
  DoHandshake;
end;

procedure TTaurusTLSSslSocket.CheckActiveState(
  const AExpectedStates: TTaurusTLSSslSocketStates);
begin
  if not (FState in AExpectedStates) then
    ETaurusTLSSocketStateError.RaiseWithMessageFmt(
      'Invalid socket operation in the ''%s'' state.', [FState.AsString]);
end;

function TTaurusTLSSslSocket.CheckForError(ALastResult: Integer): Integer;
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

procedure TTaurusTLSSslSocket.CheckPeerCertificateValidationResult;
var
  lErr: TTaurusTLSX509Error;
  lCert: TTaurusTLSX509; // PALOFF 'Created and freed objects'
  lSuccess: boolean;

begin
  lCert:=nil;
  lErr:=TTaurusTLSX509Error.Create(SSL_get_verify_result(FSSL));
  lSuccess:=lErr.ErrorCode <> X509_V_OK;
  if not lSuccess then
  try
    lCert:=GetPerCertificate;
    Ctx.DoOnPeerCertError(Self, lCert, lErr, lSuccess);
  finally
    lCert.Free;
  end;
  if not lSuccess then
    ETaurusTLSCertValidationError.RaiseWithMessage(lErr.ErrorShortDescription);
end;

function TTaurusTLSSslSocket.Readable: boolean;
begin
  Result:=Assigned(FSSL) and (FState = seEstablished) and
    (SSL_has_pending(FSSL) > 0);
end;

function TTaurusTLSSslSocket.Recv(var ABuffer: TIdBytes): TIdC_SIZET;
var
  lLen, lRet, lErr, lQErr: Integer;
  lSSL: PSSL;

begin
  Result:=0;
  lLen:=Length(ABuffer);

  if lLen = 0 then
    Exit;

  CheckActiveState([seEstablished]); // Security guard

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
          ETaurusTLSConnectionReset.RaiseWithMessage('Connection reset by peer during read.');
        end;
      else
        begin
          TransitionTo(seError);
          raise ETaurusTLSIOError.Create('Fatal read error.');
        end;
      end;
    end
  until False; //PALOFF "Condition evaluates to constant value"
end;

function TTaurusTLSSslSocket.Send(const ABuffer: TIdBytes; const AOffset,
  ALength: TIdC_SIZET): TIdC_SIZET;
var
  lRet, lErr: TIdC_INT;

begin
  Result:=0;
  if (ALength = 0) or (Length(ABuffer) = 0) then
    Exit;

  CheckActiveState([seEstablished]); // Security guard

  // Clear error queue before doing read to avoid getting unhandled previously error
  ERR_clear_error;

  // We trust Indy that AOffset+ALength never exceeds the Length(ABuffer)
  lRet:=SSL_write_ex(FSSL, ABuffer[AOffset], ALength, Result);
  if lRet = 1 then
    Exit
  else
  begin
    lErr:=SSL_get_error(FSSL, lRet);
    if lErr = SSL_ERROR_SYSCALL then
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

procedure TTaurusTLSSslSocket.Shutdown;
begin
  try
    if FState = seEstablished then
    begin
      TransitionTo(seClosing);
      DoShutdown;
    end;
  except
    on E: Exception do
    begin
      TransitionTo(seClosed); // Intercept and force immediate closed state teardown
    end;
  end;
end;

// callbacks

procedure TTaurusTLSSslSocket.InitSSLCallbacks;
begin
  if FCtx.HasOnStatusInfo then
    SSL_set_info_callback(FSSL, TTaurusTLSSslSocket.CbSslInfo);

  if FCtx.HasOnVerifyCertificate then
  begin
    SSL_set_verify(FSSL, FCtx.CertVerifyFlags.AsInt,
      TTaurusTLSSslSocket.CbSslVerify);
  end;

  if FCtx.HasOnSecurityCheck then
    SSL_set_security_callback(FSSL,
      TTaurusTLSSslSocket.CbSslSecurityCheck);
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
  lResult:=SSL_get_app_data(ASSL); 
  if Assigned(lResult) and (TObject(lResult) is TTaurusTLSSslSocket) then // PALOFF 'Pointer cast to TObject'
    Result:=TTaurusTLSSslSocket(lResult)
  else
    ETaurusTLSDataBindingError.RaiseWithMessageFmt(
      { TODO : To make ResourseString }
      'SSL object %p is not bound to a valid TTaurusTLSSslSocket instance.',
      [ASSL]);
end;

function TTaurusTLSSslSocket.GetPerCertificate: TTaurusTLSX509;
var
  lX509: PX509;

begin
  Result:=nil;
  if not (State in [seHandshaking, seEstablished]) then
    Exit;
  try
    lX509:=SSL_get_certificate(FSSL);
    if Assigned(lX509) then
      Result:=TTaurusTLSX509.Create(lX509, False);
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
  except
    //PALOFF "Empty except-block"
    // We must not raise the exception to the OpenSSL stack
  end;
end;

class procedure TTaurusTLSSslSocket.CbSslMessage(AWriteP, AVersion,
  AContentType: TIdC_INT; const ABuf: Pointer; ALen: TIdC_SIZET; ASSL: PSSL;
  AArg: Pointer);
var
  lErr: TIdC_INT;
  lInstance: TTaurusTLSSslSocket;
  lContext: TTaurusTLSSslSocketCtx;

begin
  if not Assigned(ASSL) then
    Exit;

  LErr := GStack.WSGetLastError;
  try
    LInstance:=GetInstanceFromSSL(ASSL);
    if not Assigned(lInstance) then
      Exit;

    lContext:=lInstance.FCtx;
    if Assigned(lContext) then
      { TODO : Call event handler here. }

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
    LErr := GStack.WSGetLastError;
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
    ETaurusTLSClientSocketSSLSetupError.RaiseWithMessage(RSOSSLModeNotSet);

  SetECHStatus(echCliNotConfigured);

  // 1. Configure Hostname Verification on FSSL's local parameter block [1.2]
  // (Moves your previous SetupHostnameVerification logic here, fully self-contained)
  SetupHostnameVerification;

  // 2. Wire-Level SNI Suppression Check [1.2.2]
  if lContext.SNIKind = skNoSNI then
    Exit;

  // 3. Retrieve pre-computed logical identity
  lIdentity := lContext.Identity;

  if (lIdentity <> '') and (not lContext.IsIdentityIP) then
  begin
    if lContext.UseECH then
    begin
      // Real ECH Path
      lECHStore := TTaurusTLSECHStore.Create;
      try
        lECHStore.SetConfigList(lContext.ECHConfigListRaw);
        lECHStore.Attach(FSSL);
      finally
        lECHStore.Free;
      end;

      // Configure ECH Server Names using pre-computed parameters
      lRetCode := SSL_ech_set1_server_names(
        FSSL,
        PIdAnsiChar(lIdentity),  // PALOFF Possible bad typecast
        PIdAnsiChar(lContext.ECHOuterSNIRaw),  // PALOFF Possible bad typecast
        lContext.ECHNoOuterVal
      );

      if lRetCode <= 0 then
        ETaurusTLSSettingTLSHostNameError.RaiseException(FSSL, lRetCode, RSSSLSettingTLSHostNameError_2);
    end
    else
    begin
      // Standard SNI (or GREASE) Path
      if lContext.UseGREASE then
        SSL_set_options(FSSL, SSL_OP_ECH_GREASE);

      lRetCode := SSL_set_tlsext_host_name(FSSL, PIdAnsiChar(lIdentity));  // PALOFF Possible bad typecast
      if lRetCode <= 0 then
        ETaurusTLSSettingTLSHostNameError.RaiseException(FSSL, lRetCode, RSSSLSettingTLSHostNameError_2);
    end;
  end;
end;

procedure TTaurusTLSClientSocket.SetupHostnameVerification;
var
  lParams: TTaurusTLSX509VerifyParamSSL; // PALOFF 'Created and freed objects'
  lTargetName: RawByteString;
  lContext: TTaurusTLSSslClientCtx;
  lIsIP: Boolean;

begin
  lContext := ClientCtx;
  if not lContext.VerifyHostname then
    Exit;

  // 1. Get the connection-specific verification parameters (cloned from SSL_CTX)
  lParams := TTaurusTLSX509VerifyParamSSL.Create(FSSL);
  try
    // 2. Determine the logical identity and IP flag [1.2]
    lTargetName := lContext.Identity;
    if lTargetName = '' then
      Exit;

    lIsIP := lContext.IsIdentityIP; // Use the pre-computed, cached property

    // 3. Bind the primary identity directly to the connection's parameter block.
    // This preserves all other inherited parameters (CRL flags, depth, etc.)
    if lIsIP then
      // IPv4/IPv6 Literal Validation
      lParams.SetIpAddressA(lTargetName)
    else
      // Standard DNS / Wildcard Validation
      lParams.AddHostA(lTargetName);
  finally
    lParams.Free;
  end;
end;

procedure TTaurusTLSClientSocket.Connect(const pHandle: TIdStackSocketHandle);
begin
  // 1. Capture the raw OS socket handle
  SocketHandle:=pHandle;

  // 2. Transition to Initialized (Allocates FSSL, configures SNI/ECH/Verification, binds callbacks) [2.2, 3]
  TransitionTo(seInitialized);

  // 3. Bind the physical socket descriptor to OpenSSL
  BindSocket;

  // 4. Clone the session ID if this is a cloned IOHandler (e.g., FTP data channels)
  Ctx.CloneSession(FSSL);

  // 5. Transition to Handshaking and initiate the Handshake loop
  TransitionTo(seHandshaking);
  DoHandshake;
end;

procedure TTaurusTLSClientSocket.DoHandshakeIteration;
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
  try
    ERR_clear_error;
    lRet:=SSL_connect(SSL);

    if lRet = 1 then
    begin
      CheckPeerCertificateValidationResult;
      // Verify ECH status prior to accepting handshake success
      if lContext.UseECH and (lContext.ECHConfigList <> '') then
      begin
        try
          lStatus:=SSL_ech_get1_status(SSL, @lInner, @lOuter);

          case lStatus of
          SSL_ECH_STATUS_SUCCESS,
          SSL_ECH_STATUS_BACKEND:
            // Success - moving forward.
            ; //PALOFF "empty block"

          SSL_ECH_STATUS_GREASE_ECH,
          SSL_ECH_STATUS_FAILED_ECH,
          SSL_ECH_STATUS_FAILED_ECH_BAD_NAME:
            begin
              SetECHStatus(echCliFailed);
              lECHConfigBuf:=nil;
              lECHConfigLen:=0;

              // Attempt to extract the updated keys provided by the server
              if SSL_ech_get1_retry_config(SSL, @lECHConfigBuf, @lECHConfigLen) = 1 then
              begin
                try
                  if (lECHConfigBuf <> nil) and (lECHConfigLen > 0) then
                  begin
                    lNewConfigBase64:=EncodeConfigList(lECHConfigBuf, lECHConfigLen);
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

              // If no keys were returned, it is a hard rejection
              TransitionTo(seClosed);
              ETaurusTLSECHRejectedError.RaiseWithMessage(
                'ECH Handshake failed. The server rejected the key and provided no retry configuration.');
            end;

          SSL_ECH_STATUS_NOT_TRIED,
          SSL_ECH_STATUS_NOT_CONFIGURED:
            begin
              TransitionTo(seError);
              ETaurusTLSECHDowngradeError.RaiseWithMessage(
                'ECH Handshake bypassed. Possible downgrade attack or configuration mismatch.');
            end;

          SSL_ECH_STATUS_BAD_NAME:
            begin
              { TODO :
                Need to double check if it needs to raise the exception
                or just fire an OnDebug event }
              TransitionTo(seError);
              ETaurusTLSECHBadNameError.RaiseWithMessage(
                'ECH Handshake completed but the server certificate did not match the inner name.');
            end;

          else 
            begin
              // Covers SSL_ECH_STATUS_FAILED (0), SSL_ECH_STATUS_BAD_CALL (-100), and any other negative codes
              TransitionTo(seError);
              ETaurusTLSECHProtocolError.RaiseWithMessage(
                'ECH Handshake failed due to an internal OpenSSL or protocol error.');
            end;
          end;
        finally
          // Clean up ECH status output buffers allocated by OpenSSL
          if Assigned(lInner) then
            OPENSSL_free(lInner);
          if Assigned(lOuter) then
            OPENSSL_free(lOuter);
        end;
      end;

      TransitionTo(seEstablished);

      if lContext.UseECH then
      begin
        // Update the status for successful connections
        lStatus:=SSL_ech_get1_status(SSL, @LInner, @LOuter);
        if lStatus = SSL_ECH_STATUS_SUCCESS then
          SetECHStatus(echCliSuccess)
        else
          SetECHStatus(echCliNone);
      end;

      Exit;
    end;

    lErr:=SSL_get_error(SSL, lRet);
    case lErr of
    SSL_ERROR_SYSCALL:
      begin
        TransitionTo(seClosed); // Triggers immediate teardown
        raise ETaurusTLSConnectionReset.Create('Handshake reset by peer.');
      end;

    SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE:
      // Waiting for data
      ;

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

end.
