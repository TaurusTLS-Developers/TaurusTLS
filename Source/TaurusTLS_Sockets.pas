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
      'Handshaking', 'Established', 'Closing', 'Closed', 'Error');
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

  TTaurusTLSSSLStateFlag  = (
    sfLoop                = 0,    // 1 shl 0  = SSL_CB_LOOP
    sfExit                = 1,    // 1 shl 1  = SSL_CB_EXIT
    sfRead                = 2,    // 1 shl 2  = SSL_CB_READ
    sfWrite               = 3,    // 1 shl 3  = SSL_CB_WRITE
    sfHandShakeStart      = 4,    // 1 shl 4  = SSL_CB_HANDSHAKE_START
    sfHandShakeDone       = 5,    // 1 shl 5  = SSL_CB_HANDSHAKE_DONE
    sfConnect             = 12,   // 1 shl 12 = SSL_ST_CONNECT
    sfAccept              = 13,   // 1 shl 13 = SSL_ST_ACCEPT
    sfAlert               = 14    // 1 shl 14 = SSL_ST_ALERT
  );

  TTaurusTLSSSLStateFlags = set of TTaurusTLSSSLStateFlag;

  TTaurusTLSSSLState = record
  public const
    cLowMin   = Ord(Low(TTaurusTLSSSLStateFlag));
    cLowMax   = Ord(sfHandShakeDone);
    cHighMin  = Ord(sfConnect);
    cHighMax  = Ord(High(TTaurusTLSSSLStateFlag));
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
    function GetStateFlags: TTaurusTLSSSLStateFlags; {$IFDEF USE_INLINE}inline; {$ENDIF}

    procedure Init(const ASSLStates, ACode: TIdC_INT; ASSL: PSSL);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure InitMessages; {$IFDEF USE_INLINE}inline; {$ENDIF}

  public
    constructor Create(const AStates: TTaurusTLSSSLStateFlags; const ACode: TIdC_INT;
      ASSL: PSSL); overload;
    constructor Create(const ASSLStates, ACode: TIdC_INT; ASSL: PSSL); overload;

    class function ToInt(const AValue: TTaurusTLSSSLStateFlags): TIdC_INT; static;
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

    property StateFlags: TTaurusTLSSSLStateFlags read GetStateFlags;
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


  // Forward declaration
  TTaurusTLSBaseSocket = class;

  // Event type declarations

  TTaurusTLSOnSecurityCheck = procedure(
    ASender: TObject;
    ASocket: TTaurusTLSBaseSocket;
    const AState: TTaurusTLSSecurityCheckState;
    var AAccept: Boolean
  ) of object;

  TTaurusTLSOnIOHandlerNotify = procedure(ASender: TObject;
    ASocket: TTaurusTLSBaseSocket) of object;

  TTaurusTLSOnStateChange = procedure(ASender: TObject;
    ASocket: TTaurusTLSBaseSocket; AOldState, ANewState: TTaurusTLSSslSocketState) of object;


  TTaurusTLSOnSSLStatusInfo = procedure(ASender: TObject;
    ASocket: TTaurusTLSBaseSocket; const AState: TTaurusTLSSSLState) of object;

  TTaurusTLSOnDebugMessage = procedure(ASender: TObject;
    const AMessage: String) of object;

  TTaurusTLSOnPeerCertError = procedure(ASender: TObject;
    ASocket: TTaurusTLSBaseSocket; ACertificate: TTaurusTLSX509;
    const AError: TTaurusTLSX509Error; out ASuccess: boolean) of object;

  TTaurusTLSOnVerifyCallback = procedure(
    ASender: TObject; ASocket: TTaurusTLSBaseSocket;
    ACertValidator: TTaurusTLSX509CertValidator;
    out ASuccess, AContinue: Boolean
  ) of object;

  TTaurusTLSSSLOp = (sslOpRead, sslOpWrite);

  TTaurusTLSOnSSLMessageCallback = procedure(
    ASender: TObject; ASocket: TTaurusTLSBaseSocket;
    AOp: TTaurusTLSSSLOp; AVersion: Integer; AContentType: Integer;
    ABuf: Pointer; ALen: NativeUInt) of object;

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

  TTaurusTLSSocketCtx = class;

  ITaurusTLSSocketCtx = interface
  ['{DCD600F0-1D28-482D-A883-A563CFE0D6FC}']
    function GetConfig: TTaurusTLSSocketCtx;
    property Config: TTaurusTLSSocketCtx read GetConfig;
  end;

  TTaurusTLSSocketCtx = class abstract(TInterfacedObject, ITaurusTLSSocketCtx)
  public const
    cVerifyModesDef = [sslvrfPeer, sslvrfHostname];

  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSender: TObject;
    FSSLCtx: PSSL_CTX;

    FCertVerifyFlags: TTaurusTLSVerifyModeFlags;

    FSession: PSSL_SESSION;

    FOnStateChange: TTaurusTLSOnStateChange;
    FOnDebugMessage: TTaurusTLSOnDebugMessage;
    FOnStatusInfo: TTaurusTLSOnSSLStatusInfo;

    // OpenSSL callbacks
    FOnVerifyCertificate: TTaurusTLSOnVerifyCallback;
    FOnPeerCertError: TTaurusTLSOnPeerCertError;
    FOnSecurityCheck: TTaurusTLSOnSecurityCheck;

    // callback event assignment status flags
    function GetVerifyHostname: boolean;
    function GetHasOnStatusInfo: boolean;
    function GetOnSecurityCheck: boolean;
    function GetOnVerifyCertificate: boolean;
      {$IFDEF USE_INLINE}inline; {$ENDIF}

  protected
    class function NormalizeHostName(const AValue: RawByteString): RawByteString;
      static; {$IFDEF USE_INLINE}inline; {$ENDIF}

    // Event handlers
    procedure DoOnStateChange(ASocket: TTaurusTLSBaseSocket;
      AOldState, ANewState: TTaurusTLSSslSocketState); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoOnDebug(const AMsg: string); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoOnPeerCertError(ASocket: TTaurusTLSBaseSocket;
      ACertificate: TTaurusTLSX509; const AError: TTaurusTLSX509Error;
      out ASuccess: boolean); {$IFDEF USE_INLINE}inline; {$ENDIF}

    // OpenSSL Callback wrappers
    procedure DoOnStatusInfo(ASocket: TTaurusTLSBaseSocket;
      AWhere, ARet: TIdC_INT); {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoOnVerifyCertificate(ASocket: TTaurusTLSBaseSocket;
      ACtx: PX509_STORE_CTX; out ASuccess, AContinue: boolean);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoOnSecurityCheck(ASocket: TTaurusTLSBaseSocket;
      op, bits, nid: TIdC_INT; other: pointer; var AAccept: boolean);

    // OpenSSL Callback status checkers
    property HasOnStatusInfo: boolean read GetHasOnStatusInfo;
    property HasOnVerifyCertificate: boolean read GetOnVerifyCertificate;
    property HasOnSecurityCheck: boolean read GetOnSecurityCheck;

    // IITaurusTLSSocketCtx method(s)
    function GetConfig: TTaurusTLSSocketCtx;

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

  ETaurusTLSSocketCtxError = class(ETaurusTLSError);

  TTaurusTLSSocketCtxBuilder = class abstract
  private
    FLock: TIdCriticalSection;
    FTLSMeth: PSSL_METHOD;

    FSocketCtx: ITaurusTLSSocketCtx;
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

    FOnStateChange: TTaurusTLSOnStateChange;
    FOnDebugMessage: TTaurusTLSOnDebugMessage;
    FOnPeerCertError: TTaurusTLSOnPeerCertError;
    FOnStatusInfo: TTaurusTLSOnSSLStatusInfo;
    FOnVerifyCertificate: TTaurusTLSOnVerifyCallback;

  protected
    procedure Lock; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure Unlock; {$IFDEF USE_INLINE}inline; {$ENDIF}

    procedure CheckRequirements; virtual;
    function DoNewSocketCtx(ASender: TObject): TTaurusTLSSocketCtx; virtual; abstract;
    procedure DoBuildTrustStore(ASocketCtx: TTaurusTLSSocketCtx);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure DoBuildVerifyParam(ASocketCtx: TTaurusTLSSocketCtx);
    procedure DoBuild(ASender: TObject; ASocketCtx: TTaurusTLSSocketCtx); virtual;

    property TLSMeth: PSSL_METHOD read FTLSMeth;
  public
    constructor Create(ATLSMeth: PSSL_METHOD);
    destructor Destroy; override;
    function Build(ASender : TObject): ITaurusTLSSocketCtx; {$IFDEF USE_INLINE}inline; {$ENDIF}

    property IsDirty: boolean read FDirty;
  end;

  TTaurusTLSClientSocketCtx = class(TTaurusTLSSocketCtx)
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
  protected
    procedure SetSessionToResume(const ASSL: PSSL);
      {$IFDEF USE_INLINE}inline;
          property OnPeerCertError;
          property OnPeerCertError;{$ENDIF}
  public
    destructor Destroy; override;

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

    property OnStateChange;
    property OnDebugMessage;
    property OnPeerCertError;
    property OnStatusInfo;
    property OnVerifyCertificate;
  end;

  TTaurusTLSPeerSocketCtx = class(TTaurusTLSSocketCtx)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FVerifyClientModes: TTaurusTLSVerifyModes;
    FALPNPreferences: string;
  public
    property VerifyClientModes: TTaurusTLSVerifyModes read FVerifyClientModes
      write FVerifyClientModes;
    property ALPNPreferences: string read FALPNPreferences write FALPNPreferences;
  end;

  TTaurusTLSBaseSocket = class abstract
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
  {$IFDEF DCC}
    [Volatile]
  {$ENDIF}
    FState: TTaurusTLSSslSocketState;
    FSocketHandle: TIdStackSocketHandle;

    // The Dual-Track State Fields
    FConfigIntf: ITaurusTLSSocketCtx;  // Holds reference count safely
    FConfig: TTaurusTLSSocketCtx;
    function GetPerCertificate: TTaurusTLSX509;       // Fast class pointer

    // OpenSSL callback methods
    class procedure SSLInfoCallback(const ASSL: PSSL;
      AWhere, ARet: TIdC_INT); static; cdecl;
    class function SSLVerifyCallback(const APreVerify: TIdC_INT;
      ACtx: PX509_STORE_CTX): TIdC_INT; static; cdecl;
    class function SSLSecurityCheckCallback(const s: PSSL; const ctx: PSSL_CTX;
      op, bits, nid: TIdC_INT; other, ex: pointer): TIdC_INT; static; cdecl;

  protected
    FSSL: PSSL;
    class function GetInstanceFromSSL<T: TTaurusTLSBaseSocket>(
      ASSL: PSSL): T; static; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function GetConfig<T: TTaurusTLSSocketCtx>: T; {$IFDEF USE_INLINE}inline; {$ENDIF}

    // Centralized Hostname Verification Helper
    procedure CheckPeerCertificateValidationResult; {$IFDEF USE_INLINE}inline; {$ENDIF}

    function CheckForError(ALastResult: Integer): Integer; virtual;
    function GetSSLError(ALastResult: Integer): Integer; {$IFDEF USE_INLINE}inline; {$ENDIF}

    procedure InitSSL; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure InitSSLCallbacks; virtual;
    procedure SetupConnection; virtual; abstract;
    procedure ReleaseSSL; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure ReleaseSSLCallbacks; virtual;
    procedure LinkSocket; {$IFDEF USE_INLINE}inline; {$ENDIF}

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
    constructor Create(const AConfigIntf: ITaurusTLSSocketCtx); virtual;
    destructor Destroy; override;

    procedure TransitionTo(ATarget: TTaurusTLSSslSocketState); virtual;

    procedure Connect(const pHandle: TIdStackSocketHandle); virtual;
    function Send(const ABuffer: TIdBytes; const AOffset, ALength: TIdC_SIZET): TIdC_SIZET; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function Recv(var ABuffer: TIdBytes): TIdC_SIZET; {$IFDEF USE_INLINE}inline; {$ENDIF}
    function Readable: boolean; {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure Shutdown;

    property SSL: PSSL read FSSL;
    property State: TTaurusTLSSslSocketState read FState;
    property Config: TTaurusTLSSocketCtx read FConfig;
  end;

  TTaurusECHClientStatus = (echCliNone, echCliSuccess, echCliFailed,
    echCliRetryConfig, echCliNotConfigured);


  TTaurusTLSClientSocket = class(TTaurusTLSBaseSocket)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FECHStatus: TTaurusECHClientStatus;
    function GetClientConfig: TTaurusTLSClientSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
  protected
    procedure SetECHStatus(AECHStatus: TTaurusECHClientStatus);
      {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetupConnection; override;
    procedure SetupHostnameVerification;
    procedure DoHandshakeIteration; override;
    property ClientConfig: TTaurusTLSClientSocketCtx read GetClientConfig;
  public
    procedure Connect(const pHandle: TIdStackSocketHandle); override;
  end;

  TTaurusTLSPeerSocket = class(TTaurusTLSBaseSocket)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    function GetPeerConfig: TTaurusTLSPeerSocketCtx;
      {$IFDEF USE_INLINE}inline; {$ENDIF}
  protected
    procedure DoHandshakeIteration; override;
    property PeerConfig: TTaurusTLSPeerSocketCtx read GetPeerConfig;
  public
    constructor Create(AConfig: TTaurusTLSPeerSocketCtx); reintroduce;
  end;


  ETaurusTLSSocketCtxBuildError = class(ETaurusTLSError);


  /// <summary>
  /// Raised if <c>SSL_set_fd</c> failed.
  /// </summary>
  /// <seealso href="https://docs.openssl.org/3.0/man3/SSL_set_fd/">
  /// SSL_set_fd
  /// </seealso>
  ETaurusTLSFDSetError = class(ETaurusTLSAPISSLError);

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
  ETaurusTLSCouldNotCreateSSLObject = class(ETaurusTLSError);
  ETaurusTLSDataBindingError = class(ETaurusTLSAPISSLError);
  ETaurusTLSSettingTLSHostNameError = class(ETaurusTLSAPISSLError);
  ETaurusTLSSettingSANIPError = class(ETaurusTLSError);
  ETaurusTLSHandshakeError = class(ETaurusTLSAPISSLError);
  ETaurusTLSClientSocketSSLSetupError = class(ETaurusTLSError);
  ETaurusTLSSessionCanNotBeNil = class(ETaurusTLSError);
  ETaurusTLSInvalidSessionValue = class(ETaurusTLSError);
  ETaurusTLSECHConfigOutOfRange = class(ETaurusTLSError);

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
    cDefSNIKind = skHostSNI;
    cDefECHKind = ekNoECH;
  private
    FSNIKind: TTaurusTLSSNICliKind;
    FECHKind: TTaurusTLSECHCliKind;
    procedure SetECHKind(Value: TTaurusTLSECHCliKind);
    procedure SetSNIKind(Value: TTaurusTLSSNICliKind);
    procedure SetConfigList(const Value: string);
  public
    constructor Create;
    procedure Assign(Source: TPersistent); override;

  published
    property SNIKind: TTaurusTLSSNICliKind read FSNIKind
      write SetSNIKind default cDefSNIKind;
    property ECHKind: TTaurusTLSECHCLiKind read FECHKind
      write SetECHKind default cDefECHKind;
  end;

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

{ TTaurusTLSSSLState }

constructor TTaurusTLSSSLState.Create(const ASSLStates, ACode: TIdC_INT;
  ASSL: PSSL);
begin
  Init(ASSLStates, ACode, ASSL);
end;

constructor TTaurusTLSSSLState.Create(const AStates: TTaurusTLSSSLStateFlags;
  const ACode: TIdC_INT; ASSL: PSSL);
begin
  Init(ToInt(AStates), ACode, ASSL);
end;

procedure TTaurusTLSSSLState.Init(const ASSLStates, ACode: TIdC_INT; ASSL: PSSL);
begin
  FStates:=ASSLStates and cStateFlagsMask; // cleanup possible unknown flags
  FCode:=ACode;
  FSSL:=ASSL;
  InitMessages;
end;

procedure TTaurusTLSSSLState.InitMessages;
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

class function TTaurusTLSSSLState.ToInt(
  const AValue: TTaurusTLSSSLStateFlags): TIdC_INT;
begin
{$IF SizeOf(TTaurusTLSSSLStateFlags) = 1}
  Result:=PIdC_INT8(@AValue)^ and cStateFlagsMask;
{$ELSEIF SizeOf(TTaurusTLSSSLStateFlags) = 2}
  Result:=PIdC_INT16(@AValue)^ and cStateFlagsMask;
{$ELSEIF SizeOf(TTaurusTLSSSLStateFlags) = 4}
  Result:=PIdC_INT(@AValue)^ and cStateFlagsMask;;
{$IFEND}
end;

function TTaurusTLSSSLState.GetIsConnect: boolean;
begin
  Result := sfConnect in StateFlags;
end;

function TTaurusTLSSSLState.GetIsAccept: boolean;
begin
  Result := sfAccept in StateFlags;
end;

function TTaurusTLSSSLState.GetIsInLoop: boolean;
begin
  Result := sfLoop in StateFlags;
end;

function TTaurusTLSSSLState.GetIsAlert: boolean;
begin
  Result := sfAlert in StateFlags;
end;

function TTaurusTLSSSLState.GetIsRead: boolean;
begin
  Result := sfRead in StateFlags;
end;

function TTaurusTLSSSLState.GetIsWrite: boolean;
begin
  Result := sfWrite in StateFlags;
end;

function TTaurusTLSSSLState.GetIsHandshakeStars: boolean;
begin
  Result := sfHandShakeStart in StateFlags;
end;

function TTaurusTLSSSLState.GetIsHandshakeDone: boolean;
begin
  Result := sfHandShakeDone in StateFlags;
end;

function TTaurusTLSSSLState.GetIsReadAlert: boolean;
begin
  Result := IsAlert and IsRead;
end;

function TTaurusTLSSSLState.GetIsWriteAlert: boolean;
begin
  Result := IsAlert and IsWrite;
end;

function TTaurusTLSSSLState.GetIsAcceptLoop: boolean;
begin
  Result := IsAccept and IsInLoop;
end;

function TTaurusTLSSSLState.GetIsAcceptExit: boolean;
begin
  Result := IsAccept and IsExit;
end;

function TTaurusTLSSSLState.GetIsConnectLoop: boolean;
begin
  Result := IsConnect and IsInLoop;
end;

function TTaurusTLSSSLState.GetIsExit: boolean;
begin
  Result:=sfExit in StateFlags;
end;

function TTaurusTLSSSLState.GetIsConnectExit: boolean;
begin
  Result := IsConnect and IsExit;
end;

function TTaurusTLSSSLState.GetStateFlags: TTaurusTLSSSLStateFlags;
begin
{$IF SizeOf(TTaurusTLSSSLStateFlags) = 1}
  PIdC_INT8(@Result)^:=FStates;
{$ELSEIF SizeOf(TTaurusTLSSSLStateFlags) = 2}
  PIdC_INT16(@Result)^:=FStates;
{$ELSEIF SizeOf(TTaurusTLSSSLStateFlags) = 4}
  PIdC_INT(@Result)^:=FStates;
{$IFEND}
end;

function TTaurusTLSSSLState.GetAlertMessage: string;
begin
  if FAlertMessage = '' then
    InitMessages;
  Result:=FAlertMessage;
end;

function TTaurusTLSSSLState.GetStateStatusMessage: string;
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
  lBio: TTaurusTLSRawByteStringBIO;

begin
  lBio:=TTaurusTLSRawByteStringBIO.Create(RawByteString(AData));
  try
    Create(AName, lBio, AUi);
  finally
    lBio.Free;
  end;
end;

constructor TTaurusTLSTrustStore.CreateMem(const AName: string;
  AUi: TTaurusTLSCustomOsslUi; const AData: TBytes);
var
  lBio: TTaurusTLSBytesBio;

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

{ TTaurusTLSSocketCtxBuilder }

constructor TTaurusTLSSocketCtxBuilder.Create(ATLSMeth: PSSL_METHOD);
begin
  inherited Create;
  FDirty:=True;
  FTLSMeth:=ATLSMeth;
end;

destructor TTaurusTLSSocketCtxBuilder.Destroy;
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

procedure TTaurusTLSSocketCtxBuilder.Lock;
begin
  FLock.Enter;
end;

procedure TTaurusTLSSocketCtxBuilder.Unlock;
begin
  FLock.Leave;
end;

procedure TTaurusTLSSocketCtxBuilder.DoBuildTrustStore(
  ASocketCtx: TTaurusTLSSocketCtx);
var
  lTrustStores: TTaurusTLSTrustStores;
  lX509Store: TaurusTLS_X509Store;
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

procedure TTaurusTLSSocketCtxBuilder.DoBuildVerifyParam(
  ASocketCtx: TTaurusTLSSocketCtx);
var
  lVfyParam: TTaurusTLSX509VerifyParam;
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

procedure TTaurusTLSSocketCtxBuilder.CheckRequirements;
begin

end;

procedure TTaurusTLSSocketCtxBuilder.DoBuild(ASender: TObject;
  ASocketCtx: TTaurusTLSSocketCtx);
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
    ETaurusTLSSocketCtxBuildError.RaiseWithMessage('Error setting Minimal TLS Version.');

  if SSL_CTX_set_max_proto_version(lCtx, FMaxTLSVersion.AsInt) <= 0 then
    ETaurusTLSSocketCtxBuildError.RaiseWithMessage('Error setting Maximal TLS Version.');

  if SSL_CTX_set_cipher_list(lCtx, PAnsiChar(RawByteString(FCipherList))) <= 0 then
    ETaurusTLSSocketCtxBuildError.RaiseWithMessageFmt(
      'Error setting list of ciphers: ''%s''.', [FCipherList]);

  if SSL_CTX_set_ciphersuites(lCtx, PAnsiChar(RawByteString(FCipherSuites))) <= 0 then
    ETaurusTLSSocketCtxBuildError.RaiseWithMessageFmt(
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

function TTaurusTLSSocketCtxBuilder.Build(ASender: TObject): ITaurusTLSSocketCtx;
var
  lSocketCtx: TTaurusTLSSocketCtx;

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

{ TTaurusTLSSocketCtx }

procedure TTaurusTLSSocketCtx.CloneSession(ASSL: PSSL);
begin

end;

constructor TTaurusTLSSocketCtx.Create(ASender: TObject; ATLSMeth: PSSL_METHOD);
begin
  FSender:=ASender;
  FSSLCtx:=SSL_CTX_new(ATLSMeth);
  SetVerifyModes(cVerifyModesDef);
end;

destructor TTaurusTLSSocketCtx.Destroy;
begin
  SSL_CTX_free(FSSLCtx);
  inherited;
end;

procedure TTaurusTLSSocketCtx.DoOnDebug(const AMsg: string);
begin
  if Assigned(FOnDebugMessage) then
    FOnDebugMessage(FSender, AMsg);
end;

procedure TTaurusTLSSocketCtx.DoOnPeerCertError(ASocket: TTaurusTLSBaseSocket;
  ACertificate: TTaurusTLSX509; const AError: TTaurusTLSX509Error;
  out ASuccess: boolean);
begin
  if Assigned(FOnPeerCertError) and Assigned(ASocket) then
    FOnPeerCertError(FSender, ASocket, ACertificate, AError, ASuccess);
end;

procedure TTaurusTLSSocketCtx.DoOnStateChange(ASocket: TTaurusTLSBaseSocket;
  AOldState, ANewState: TTaurusTLSSslSocketState);
begin
  if Assigned(FOnStateChange) then
    FOnStateChange(FSender, ASocket, AOldState, ANewState);
end;

procedure TTaurusTLSSocketCtx.DoOnStatusInfo(ASocket: TTaurusTLSBaseSocket;
  AWhere, ARet: TIdC_INT);
var
  lState: TTaurusTLSSSLState;

begin
  if not Assigned(FOnStatusInfo) then
    Exit;

  lState:=TTaurusTLSSSLState.Create(AWhere, ARet, ASocket.SSL);
  FOnStatusInfo(FSender, ASocket, lState);
end;

procedure TTaurusTLSSocketCtx.DoOnVerifyCertificate(ASocket: TTaurusTLSBaseSocket;
  ACtx: PX509_STORE_CTX; out ASuccess, AContinue: boolean);
var
  lValidator: TTaurusTLSX509CertValidator;

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

procedure TTaurusTLSSocketCtx.DoOnSecurityCheck(ASocket: TTaurusTLSBaseSocket;
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

function TTaurusTLSSocketCtx.GetConfig: TTaurusTLSSocketCtx;
begin
  Result:=Self;
end;

function TTaurusTLSSocketCtx.GetHasOnStatusInfo: boolean;
begin
  Result:=Assigned(FOnStatusInfo);
end;

function TTaurusTLSSocketCtx.GetOnSecurityCheck: boolean;
begin
  Result:=Assigned(FOnSecurityCheck);
end;

function TTaurusTLSSocketCtx.GetOnVerifyCertificate: boolean;
begin
  Result:=Assigned(FOnVerifyCertificate);
end;

function TTaurusTLSSocketCtx.GetVerifyHostname: boolean;
begin
  Result:=sslvrfHostname in FCertVerifyFlags.Flags;
end;

class function TTaurusTLSSocketCtx.NormalizeHostName(
  const AValue: RawByteString): RawByteString;
begin
  { TODO : Implement lower-case IDNA conversion. }
{$IFDEF STRING_IS_UNICODE}
  Result:=System.AnsiStrings.LowerCase(AValue);
{$ELSE}
  Result:=LowerCase(AValue);
{$ENDIF}
end;

procedure TTaurusTLSSocketCtx.SetCipherList(const AValue: string);
begin
  if SSL_CTX_set_cipher_list(FSSLCtx, PIdAnsiChar(RawByteString(AValue))) <=0 then  // PALOFF Possible bad typecast
    ETaurusTLSSocketCtxError.RaiseWithMessageFmt(
      'Error setting cipher list ''%s'' to the SSL Context.', [AValue]);
end;

procedure TTaurusTLSSocketCtx.SetCipherSuites(const AValue: string);
begin
  if SSL_CTX_set_ciphersuites(FSSLCtx, PIdAnsiChar(RawByteString(AValue))) <=0 then // PALOFF Possible bad typecast
    ETaurusTLSSocketCtxError.RaiseWithMessageFmt(
      'Error setting cipher suites ''%s'' to the SSL Context.', [AValue]);
end;

procedure TTaurusTLSSocketCtx.SetCtxOptions(
  const AValue: TTaurusTLSSSLOptionFlags);
begin
  SSL_CTX_set_options(FSSLCtx, AValue.AsInt);
end;

procedure TTaurusTLSSocketCtx.SetKeXGroups(const AValue: string);
begin
  if SSL_CTX_set1_groups_list(FSSLCtx, PIdAnsiChar(RawByteString(AValue))) <=0 then // PALOFF Possible bad typecast
    ETaurusTLSSocketCtxError.RaiseWithMessageFmt(
      'Error setting key exchange groups ''%s'' to the SSL Context.', [AValue]);
end;

procedure TTaurusTLSSocketCtx.SetMaxTLSVersion(
  const AValue: TTaurusTLSSSLVersion);
begin
  if SSL_CTX_set_min_proto_version(FSSLCtx, AValue.AsInt) <= 0 then
    ETaurusTLSSocketCtxError.RaiseWithMessage(RSOSSLMaxProtocolError);
end;

procedure TTaurusTLSSocketCtx.SetMinTLSVersion(
  const AValue: TTaurusTLSSSLVersion);
begin
  if SSL_CTX_set_min_proto_version(FSSLCtx, AValue.AsInt) <= 0 then
    ETaurusTLSSocketCtxError.RaiseWithMessage(RSOSSLMinProtocolError);
end;

procedure TTaurusTLSSocketCtx.SetSigAlgorithms(const AValue: string);
begin
  if SSL_CTX_set1_sigalgs_list(FSSLCtx, PIdAnsiChar(RawByteString(AValue))) <= 0 then // PALOFF Possible bad typecast
    ETaurusTLSSocketCtxError.RaiseWithMessageFmt(
      'Error setting signiture algorithms ''%s'' to the SSL Context.', [AValue]);
end;

procedure TTaurusTLSSocketCtx.SetTrustStore(const AValue: TaurusTLS_X509Store);
begin
  AValue.AttachToSSLCtx(FSSLCtx);
end;

procedure TTaurusTLSSocketCtx.SetVerifyParam(
  const AValue: TTaurusTLSCustomX509VerifyParam);
begin
  if Assigned(AValue) then
    AValue.AttachToSSLCtx(FSSLCtx);
end;

procedure TTaurusTLSSocketCtx.SetVerifyModes(
  const AValue: TTaurusTLSVerifyModes);
var
  lFlags: TTaurusTLSVerifyModeFlags;

begin
  lFlags:=TTaurusTLSVerifyModeFlags.Create(AValue);
  SSL_CTX_set_verify(FSSLCtx, lFlags.AsInt, nil);
end;

{ TTaurusTLSClientSocketCtx }

destructor TTaurusTLSClientSocketCtx.Destroy;
begin
  SSL_SESSION_free(FSessionToResume);
  inherited;
end;

procedure TTaurusTLSClientSocketCtx.BuildIdentity;
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

procedure TTaurusTLSClientSocketCtx.ResetIdentity;
begin
  FIdentityBuilt:=False;
end;

function TTaurusTLSClientSocketCtx.GetDefaultSNI: string;
begin
  Result:=string(FDefaultSNI);
end;

procedure TTaurusTLSClientSocketCtx.SetDefaultSNI(const AValue: string);
begin
  FDefaultSNI:=NormalizeHostName(RawByteString(AValue));
  ResetIdentity;
end;

function TTaurusTLSClientSocketCtx.GetECHKind: TTaurusTLSECHCliKind;
begin
  Result:=FECHFlags.Kind;
end;

function TTaurusTLSClientSocketCtx.GetECHMethods: TTaurusTLSECHCliMeths;
begin
  Result:=FECHFlags.Methods;
end;

function TTaurusTLSClientSocketCtx.GetECHNoOuterVal: TIdC_INT;
begin
  if FECHFlags.UseNoOuter then
    Result:=1
  else
    Result:=0;
end;

function TTaurusTLSClientSocketCtx.GetECHOuterSNI: string;
begin
  Result:=string(FECHOuterSNI);
end;

function TTaurusTLSClientSocketCtx.GetECHOuterSNIRaw: RawByteString;
begin
  if UseECH and (not FECHFlags.UseNoOuter) then
    Result:=FECHOuterSNI
  else
    Result:='';
end;

procedure TTaurusTLSClientSocketCtx.SetECHOuterSNI(const AValue: string);
begin
  FECHOuterSNI:=NormalizeHostName(RawByteString(AValue));
  ResetIdentity;
end;

function TTaurusTLSClientSocketCtx.GetHostName: string;
begin
  Result:=string(FHostname);
end;

function TTaurusTLSClientSocketCtx.GetIdentity: RawByteString;
begin
  BuildIdentity;
  Result:=FIdentity;
end;

function TTaurusTLSClientSocketCtx.GetIsIdentityIP: boolean;
begin
  BuildIdentity;
  Result:=FIdentityIP;
end;

function TTaurusTLSClientSocketCtx.GetUseECH: Boolean;
begin
  Result:=FECHFlags.Enabled;
end;

function TTaurusTLSClientSocketCtx.GetUseGrease: Boolean;
begin
  Result:=FECHFlags.UseGrease;
end;

procedure TTaurusTLSClientSocketCtx.SetHostName(const AValue: string);
var
  lValue: RawByteString;

begin
  lValue:=NormalizeHostName(RawByteString(AValue));
  if FHostname = lValue then
    Exit;
  FHostname:=lValue;
end;

function TTaurusTLSClientSocketCtx.GetECHConfigList: string;
begin
  Result:=string(FECHConfigList);
end;

procedure TTaurusTLSClientSocketCtx.SetECHConfigList(const AValue: string);
var
  lValue: RawByteString;

begin
  lValue:=NormalizeHostName(RawByteString(AValue));
  if FECHConfigList = lValue then
    Exit;
  FECHConfigList:=lValue;
  ResetIdentity;
end;

procedure TTaurusTLSClientSocketCtx.SetECHFlags(
  const AValue: TTaurusTLSECHCliFlags);
begin
  if FECHFlags.Value = AValue.Value then
    Exit;
  FECHFlags:=AValue;
  ResetIdentity;
end;

procedure TTaurusTLSClientSocketCtx.SetSessionToResume(
  const ASSL: PSSL);
begin
  if Assigned(ASSL) then
    FSessionToResume:= SSL_get1_session(ASSL);
end;

procedure TTaurusTLSClientSocketCtx.SetSNIKind(
  const AValue: TTaurusTLSSNICliKind);
begin
  if FSNIKind = AValue then
    Exit;
  FSNIKind:=AValue;
  ResetIdentity;
end;

(*
procedure TTaurusTLSClientSocketCtx.DoCloneSession(ASSL: PSSL);
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

{ TTaurusTLSBaseSocket }

constructor TTaurusTLSBaseSocket.Create(const AConfigIntf: ITaurusTLSSocketCtx);
begin
  Assert(Assigned(AConfigIntf), '''AConfigIntf'' should not be ''nil''.'); //Do not localize
  inherited Create;
  FSocketHandle:=Id_INVALID_SOCKET;
  FConfigIntf:=AConfigIntf;
  FConfig:=AConfigIntf.Config;
end;

destructor TTaurusTLSBaseSocket.Destroy;
begin
  ReleaseSSL;
  inherited;
end;

procedure TTaurusTLSBaseSocket.InitSSL;
var
  lErr: TIdC_INT;
  
begin
  try
    // 1. Allocate the SSL session structure using the pinned context [3]
    FSSL:=SSL_new(FConfig.SSLCtx);
    if not Assigned(FSSL) then
      ETaurusTLSCreatingSessionError.RaiseWithMessage(RSSSLCreatingSessionError);

    // 2. Bind the Delphi object instance to the SSL handle for callback routing
    lErr:=SSL_set_app_data(FSSL, Self);
    if lErr <= 0 then
      ETaurusTLSDataBindingError.RaiseException(FSSL, lErr, RSSSLDataBindingError);

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

procedure TTaurusTLSBaseSocket.ReleaseSSL;
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

procedure TTaurusTLSBaseSocket.LinkSocket;
var
  lRet: TIdC_INT;

begin
  if Assigned(FSSL) and (FSocketHandle <> Id_INVALID_SOCKET) then
  begin
    ERR_clear_error;
    lRet:=SSL_set_fd(FSSL, FSocketHandle);
    if lRet <= 0 then
      ETaurusTLSFDSetError.RaiseException(FSSL, lRet, RSSSLFDSetError);
  end;
end;

procedure TTaurusTLSBaseSocket.DoHandshake;
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

procedure TTaurusTLSBaseSocket.DoDebugLog(const AMessage: string);
var
  lConfig: TTaurusTLSSocketCtx;

begin
  lConfig:=FConfig;
  if Assigned(lConfig) then
    lConfig.DoOnDebug(AMessage);
end;

procedure TTaurusTLSBaseSocket.DoSetState(ATarget: TTaurusTLSSslSocketState);
var
  lCurrentState: TTaurusTLSSslSocketState;

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

procedure TTaurusTLSBaseSocket.DoStateChangeNotify(ACurrent,
  ATarget: TTaurusTLSSslSocketState);
var
  lConfig: TTaurusTLSSocketCtx;

begin
  lConfig:=FConfig;
  if Assigned(lConfig) then
    lConfig.DoOnStateChange(Self, ACurrent, ATarget);
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

procedure TTaurusTLSBaseSocket.TransitionTo(ATarget: TTaurusTLSSslSocketState);
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

procedure TTaurusTLSBaseSocket.Connect(const pHandle: TIdStackSocketHandle);
begin
  FSocketHandle:=pHandle;
  TransitionTo(seInitialized);
  LinkSocket;
  TransitionTo(seHandshaking);
  DoHandshake;
end;

procedure TTaurusTLSBaseSocket.CheckActiveState(
  const AExpectedStates: TTaurusTLSSslSocketStates);
begin
  if not (FState in AExpectedStates) then
    ETaurusTLSSocketStateError.RaiseWithMessageFmt(
      'Invalid socket operation in the ''%s'' state.', [FState.AsString]);
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

procedure TTaurusTLSBaseSocket.CheckPeerCertificateValidationResult;
var
  lErr: TTaurusTLSX509Error;
  lCert: TTaurusTLSX509;
  lSuccess: boolean;

begin
  lCert:=nil;
  lErr:=TTaurusTLSX509Error.Create(SSL_get_verify_result(FSSL));
  lSuccess:=lErr.ErrorCode <> X509_V_OK;
  if not lSuccess then
  try
    lCert:=GetPerCertificate;
    Config.DoOnPeerCertError(Self, lCert, lErr, lSuccess);
  finally
    lCert.Free;
  end;
  if not lSuccess then
    ETaurusTLSCertValidationError.RaiseWithMessage(lErr.ErrorShortDescription);
end;

function TTaurusTLSBaseSocket.Readable: boolean;
begin
  Result:=Assigned(FSSL) and (FState = seEstablished) and
    (SSL_has_pending(FSSL) > 0);
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

function TTaurusTLSBaseSocket.Send(const ABuffer: TIdBytes; const AOffset,
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

procedure TTaurusTLSBaseSocket.Shutdown;
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

procedure TTaurusTLSBaseSocket.InitSSLCallbacks;
begin
  if FConfig.HasOnStatusInfo then
    SSL_set_info_callback(FSSL, TTaurusTLSBaseSocket.SslInfoCallback);

  if FConfig.HasOnVerifyCertificate then
  begin
    SSL_set_verify(FSSL, FConfig.CertVerifyFlags.AsInt,
      TTaurusTLSBaseSocket.SSLVerifyCallback);
  end;

  if FConfig.HasOnSecurityCheck then
    SSL_set_security_callback(FSSL,
      TTaurusTLSBaseSocket.SSLSecurityCheckCallback);
end;

procedure TTaurusTLSBaseSocket.ReleaseSSLCallbacks;
begin
  SSL_set_verify(FSSL, 0, nil);
  SSL_set_info_callback(FSSL, nil);
end;

function TTaurusTLSBaseSocket.GetConfig<T>: T;
begin
  if FConfig is T then
    Exit(T(FConfig));

  ETaurusTLSInvalidSocketConfigType.RaiseWithMessageFmt(
    'Config type reqested:  ''%s'', actual config type is ''%s''.',
    [T.ClassName, FConfig.ClassName]);
  Result:=Default(T); // workaround for W1035
end;

class function TTaurusTLSBaseSocket.GetInstanceFromSSL<T>(ASSL: PSSL): T;
begin
  Result:=TObject(SSL_get_app_data(ASSL)) as T; // PALOFF Pointer cast to TObject
end;

function TTaurusTLSBaseSocket.GetPerCertificate: TTaurusTLSX509;
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

class procedure TTaurusTLSBaseSocket.SSLInfoCallback(const ASSL: PSSL; AWhere,
  ARet: TIdC_INT);
var
  lInstance: TTaurusTLSBaseSocket;
  lConfig: TTaurusTLSSocketCtx;
  lErr: integer;

begin
  if not Assigned(ASSL) then // this shouldn't happen ever
    Exit;
  try
    lErr:=GStack.WSGetLastError;
    try
      lInstance:=GetInstanceFromSSL<TTaurusTLSBaseSocket>(ASSL);
      if not Assigned(lInstance) then
        Exit;

      lConfig:=lInstance.Config;
      if Assigned(lConfig) then
        lConfig.DoOnStatusInfo(lInstance, AWhere, ARet);
    finally
      GStack.WSSetLastError(lErr);
    end;
  except
    //PALOFF "Empty except-block"
    // We must not raise the exception to the OpenSSL stack
  end;
end;

class function TTaurusTLSBaseSocket.SSLSecurityCheckCallback(const s: PSSL;
  const ctx: PSSL_CTX; op, bits, nid: TIdC_INT; other, ex: pointer): TIdC_INT;
var
  lErr: TIdC_INT;
  lResult: boolean;
  lInstance: TTaurusTLSBaseSocket;
  lConfig: TTaurusTLSSocketCtx;

begin
  Result:=1; //
  if not Assigned(s) then
    Exit; // s parameter can be null if the SSL_CTX is changing before the
          // SSL object is allocated.

  try
    LErr := GStack.WSGetLastError;
    try
      lInstance:=TTaurusTLSBaseSocket(ex);
        if not Assigned(lInstance) then
          Exit;

        lConfig:=lInstance.Config;
        if not Assigned(lConfig) then
          Exit;

        lResult:=False;
        lConfig.DoOnSecurityCheck(lInstance, op, bits, nid, other, lResult);

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

class function TTaurusTLSBaseSocket.SSLVerifyCallback(const APreVerify: TIdC_INT;
  ACtx: PX509_STORE_CTX): TIdC_INT;
var
  lInstance: TTaurusTLSBaseSocket;
  lConfig: TTaurusTLSSocketCtx;
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

      lInstance:=GetInstanceFromSSL<TTaurusTLSBaseSocket>(lSSL);
      lConfig:=lInstance.Config;
      if Assigned(lConfig) then
      begin
        lConfig.DoOnVerifyCertificate(lInstance, ACtx, lResult, lContinue);
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

function TTaurusTLSClientSocket.GetClientConfig: TTaurusTLSClientSocketCtx;
begin
  Result:=Config as TTaurusTLSClientSocketCtx;
end;

procedure TTaurusTLSClientSocket.SetECHStatus(AECHStatus: TTaurusECHClientStatus);
begin
  FECHStatus:=AECHStatus;
end;

procedure TTaurusTLSClientSocket.SetupConnection;
var
  lRetCode: TIdC_INT;
  lConfig: TTaurusTLSClientSocketCtx;
  lIdentity: RawByteString;
  lECHStore: TTaurusTLSECHStore;

begin
  lConfig:=ClientConfig;
  if not Assigned(lConfig) then
    ETaurusTLSClientSocketSSLSetupError.RaiseWithMessage(RSOSSLModeNotSet);

  SetECHStatus(echCliNotConfigured);

  // 1. Configure Hostname Verification on FSSL's local parameter block [1.2]
  // (Moves your previous SetupHostnameVerification logic here, fully self-contained)
  SetupHostnameVerification;

  // 2. Wire-Level SNI Suppression Check [1.2.2]
  if lConfig.SNIKind = skNoSNI then
    Exit;

  // 3. Retrieve pre-computed logical identity
  lIdentity := lConfig.Identity;

  if (lIdentity <> '') and (not lConfig.IsIdentityIP) then
  begin
    if lConfig.UseECH then
    begin
      // Real ECH Path
      lECHStore := TTaurusTLSECHStore.Create;
      try
        lECHStore.SetConfigList(lConfig.ECHConfigListRaw);
        lECHStore.Attach(FSSL);
      finally
        lECHStore.Free;
      end;

      // Configure ECH Server Names using pre-computed parameters
      lRetCode := SSL_ech_set1_server_names(
        FSSL,
        PIdAnsiChar(lIdentity),  // PALOFF Possible bad typecast
        PIdAnsiChar(lConfig.ECHOuterSNIRaw),  // PALOFF Possible bad typecast
        lConfig.ECHNoOuterVal
      );

      if lRetCode <= 0 then
        ETaurusTLSSettingTLSHostNameError.RaiseException(FSSL, lRetCode, RSSSLSettingTLSHostNameError_2);
    end
    else
    begin
      // Standard SNI (or GREASE) Path
      if lConfig.UseGREASE then
        SSL_set_options(FSSL, SSL_OP_ECH_GREASE);

      lRetCode := SSL_set_tlsext_host_name(FSSL, PIdAnsiChar(lIdentity));  // PALOFF Possible bad typecast
      if lRetCode <= 0 then
        ETaurusTLSSettingTLSHostNameError.RaiseException(FSSL, lRetCode, RSSSLSettingTLSHostNameError_2);
    end;
  end;
end;

procedure TTaurusTLSClientSocket.SetupHostnameVerification;
var
  lParams: TTaurusTLSX509VerifyParamSSL;
  lTargetName: RawByteString;
  lClientConfig: TTaurusTLSClientSocketCtx;
  lIsIP: Boolean;

begin
  lClientConfig := GetConfig<TTaurusTLSClientSocketCtx>;
  if not lClientConfig.VerifyHostname then
    Exit;

  // 1. Get the connection-specific verification parameters (cloned from SSL_CTX)
  lParams := TTaurusTLSX509VerifyParamSSL.Create(FSSL);
  try
    // 2. Determine the logical identity and IP flag [1.2]
    lTargetName := lClientConfig.Identity;
    if lTargetName = '' then
      Exit;

    lIsIP := lClientConfig.IsIdentityIP; // Use the pre-computed, cached property

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
  LinkSocket;

  // 4. Clone the session ID if this is a cloned IOHandler (e.g., FTP data channels)
  ClientConfig.CloneSession(FSSL);

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
  lConfig: TTaurusTLSClientSocketCtx;

begin
  lConfig:=ClientConfig;
  try
    ERR_clear_error;
    lRet:=SSL_connect(SSL);

    if lRet = 1 then
    begin
      CheckPeerCertificateValidationResult;
      // Verify ECH status prior to accepting handshake success
      if lConfig.UseECH and (lConfig.ECHConfigList <> '') then
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

      if lConfig.UseECH then
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

{ TTaurusTLSPeerSocket }

constructor TTaurusTLSPeerSocket.Create(AConfig: TTaurusTLSPeerSocketCtx);
begin
  inherited Create(AConfig);
end;

function TTaurusTLSPeerSocket.GetPeerConfig: TTaurusTLSPeerSocketCtx;
begin
  Result:=Config as TTaurusTLSPeerSocketCtx;
end;

procedure TTaurusTLSPeerSocket.DoHandshakeIteration;
var
  lRet, lErr: Integer;

begin
  try
      ERR_clear_error;
      lRet:=SSL_accept(SSL);

      if lRet = 1 then
      begin
        TransitionTo(seEstablished);
        Exit;
      end;

      lErr:=SSL_get_error(SSL, lRet);
      case lErr of
      SSL_ERROR_SYSCALL:
        begin
          TransitionTo(seClosed); // Triggers immediate teardown
          ETaurusTLSConnectionReset.RaiseWithMessage('Handshake reset by peer.');
        end;

        SSL_ERROR_WANT_READ, 
        SSL_ERROR_WANT_WRITE,
        SSL_ERROR_WANT_X509_LOOKUP:
          Exit; // Wait for data from the socket.

      else
        begin
          TransitionTo(seError);
          ETaurusTLSHandshakeError.RaiseWithMessage('Fatal handshake error.');
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
  FSNIKind:=skHostSNI;
  FECHKind:=ekNoECH;
end;

procedure TTaurusSNIClientConfig.SetConfigList(const Value: string);
begin
  FConfigList:=Value;
end;

procedure TTaurusSNIClientConfig.SetECHKind(Value: TTaurusTLSECHCliKind);
begin
  FECHKind:=Value;
end;

procedure TTaurusSNIClientConfig.SetSNIKind(Value: TTaurusTLSSNICliKind);
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

end.
