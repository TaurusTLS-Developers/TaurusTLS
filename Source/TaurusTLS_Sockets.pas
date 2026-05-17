{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/TaurusTLS-Developers/TaurusTLS                * }
{ *                                                                            * }
{ *  Copyright (c) 2026 TaurusTLS Developers, All Rights Reserved              * }
{ ****************************************************************************** }
{$I TaurusTLSCompilerDefines.inc}

unit TaurusTLS_Sockets;

interface

uses
  Classes,
  SysUtils,
  IdCTypes,
  IdGlobal,
  IdStack,
  IdStackConsts,
  IdSocketHandle,
  IdGlobalProtocols,
  TaurusTLS,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_ech,
  TaurusTLSHeaders_ssl,
  TaurusTLSHeaders_ssl3,
  TaurusTLSHeaders_tls1,
  TaurusTLSHeaders_x509,
  TaurusTLSHeaders_x509_vfy,
  TaurusTLS_Utils,
  TaurusTLS_X509,
  TaurusTLS_ECH,
  TaurusTLS_ECHStore,
  TaurusTLS_ResourceStrings,
  TaurusTLSExceptionHandlers;

type
  ETaurusTLSCouldNotCreateSSLObject = class(ETaurusTLSError);
  ETaurusTLSDataBindingError = class(ETaurusTLSAPISSLError);
  ETaurusTLSSettingTLSHostNameError = class(ETaurusTLSAPISSLError);
  ETaurusTLSSettingSANIPError = class(ETaurusTLSError);
  ETaurusTLSHandshakeError = class(ETaurusTLSAPISSLError);
  ETaurusTLSClientSocketSSLSetupError = class(ETaurusTLSError);
  ETaurusTLSSessionCanNotBeNil = class(ETaurusTLSError);
  ETaurusTLSInvalidSessionValue = class(ETaurusTLSError);
  ETaurusTLSSecurityBits = class(ETaurusTLSError);
  ETaurusTLSECHConfigOutOfRange = class(ETaurusTLSError);

  TTaurusTLSReadStatus = (sslDataAvailable, sslNoData, sslEOF, sslUnrecoverableError);

  TTaurusTLSSNIKind = (skNoSNI, skSNIHost, skForceSNI);
  TTaurusTLSECHKind = (ekNoECH, ekTryECH, ekForceECH);

  TTaurusECHStatus = (eshNone, echCliSuccess, echClFfailed, echCliRetryConfig,
    echCliNotConfigured);


  TTaurusTLSSecurityBits = (sbZero, sb80, sb112, sb128, sb192, sb256);
  TTaurusTLSSecurityBitsHelper = record helper for TTaurusTLSSecurityBits
  private
    function GetAsInteger: TIdC_INT; {$IFDEF USE_INLINE} inline;{$ENDIF}
    procedure SetAsInteger(AValue: TIdC_INT); {$IFDEF USE_INLINE} inline;{$ENDIF}
  public
    property AsInteger: TIdC_INT read GetAsInteger write SetAsInteger;
  end;

  TTaurusTLSOpts = class(TPersistent)
  public const
    { TODO : Need to finalize defaults }
    cDefaultVerifyMode = [];
    cDefaultVerifyDepth = 5;
    cDefaultVerifyHostName = True;
    cDefaultCipherList = '';
    cDefaultSecurityBits = sb256;
  private
    FVerifyMode: TTaurusTLSVerifyModeSet;
    FVerifyDepth: Integer;
    FVerifyHostname: Boolean;
    FCipherList: string;
    FSecurityLevel: TTaurusTLSSecurityBits;
  public
    constructor Create;
    procedure Assign(Source: TPersistent); override;
  published
    property VerifyMode: TTaurusTLSVerifyModeSet read FVerifyMode
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
    FForceSNI: string;
    FConfigList: string;
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
    property ForceSNI: string read FForceSNI write FForceSNI;
    property ConfigList: string read FConfigList write SetConfigList;
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
  IdIDN; // For IDNToPunnyCode

{ TTaurusTLSSecurityBitsHelper }

function TTaurusTLSSecurityBitsHelper.GetAsInteger: TIdC_INT;
begin
  Result:=Ord(Self);
end;

procedure TTaurusTLSSecurityBitsHelper.SetAsInteger(AValue: TIdC_INT);
begin
  if not (AValue in [0..5]) then
    raise ETaurusTLSSecurityBits.CreateFmt(RMSG_SecurityBits_Convert_err, [AValue]);
  Self:=TTaurusTLSSecurityBits(AValue);
end;

{ TTaurusTLSOpts }

constructor TTaurusTLSOpts.Create;
begin
  inherited Create;
  FVerifyMode:=cDefaultVerifyMode;
  FVerifyDepth := cDefaultVerifyDepth;
  FVerifyHostname := cDefaultVerifyHostName;
  FCipherList:=cDefaultCipherList;
  FSecurityLevel := cDefaultSecurityBits;
end;

procedure TTaurusTLSOpts.Assign(Source: TPersistent);
begin
  if Source is TTaurusTLSOpts then
  begin
    FVerifyMode := TTaurusTLSOpts(Source).VerifyMode;
    FVerifyDepth := TTaurusTLSOpts(Source).VerifyDepth;
    FVerifyHostname := TTaurusTLSOpts(Source).VerifyHostname;
    FCipherList := TTaurusTLSOpts(Source).CipherList;
    FSecurityLevel := TTaurusTLSOpts(Source).SecurityLevel;
  end
  else inherited Assign(Source);
end;

{ TTaurusSNIClientConfig }

constructor TTaurusSNIClientConfig.Create;
begin
  inherited Create;
  FSNIKind := skSNIHost;
  FECHKind := ekNoECH;
end;

procedure TTaurusSNIClientConfig.SetConfigList(const Value: string);
begin
  FConfigList := Value;
end;

procedure TTaurusSNIClientConfig.SetECHKind(Value: TTaurusTLSECHKind);
begin
  FECHKind := Value;
end;

procedure TTaurusSNIClientConfig.SetSNIKind(Value: TTaurusTLSSNIKind);
begin
  FSNIKind := Value;
end;

procedure TTaurusSNIClientConfig.Assign(Source: TPersistent);
begin
  if Source is TTaurusSNIClientConfig then
  begin
    FSNIKind := TTaurusSNIClientConfig(Source).SNIKind;
    FECHKind := TTaurusSNIClientConfig(Source).ECHKind;
    FForceSNI := TTaurusSNIClientConfig(Source).ForceSNI;
    FConfigList := TTaurusSNIClientConfig(Source).ConfigList;
  end
  else inherited Assign(Source);
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
  FActiveConfig := AValue;
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
