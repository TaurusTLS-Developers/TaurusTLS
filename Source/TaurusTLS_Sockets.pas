{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/TaurusTLS-Developers/TaurusTLS                * }
{ *                                                                            * }
{ *  Copyright (c) 2024 TaurusTLS Developers, All Rights Reserved              * }
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

  TTaurusTLSReadStatus = (sslDataAvailable, sslNoData, sslEOF, sslUnrecoverableError);

  TTaurusTLSBaseSocket = class(TObject)
  protected
    FParent: TObject;
    fSSL: PSSL;
    fSSLContext: PSSL_CTX;
    fHostName: string;
    fVerifyHostname: Boolean;
    fPeerCert: TTaurusTLSX509;
    {$IFDEF UNITTEST}
    fVirtualHandshakeRet: Integer;
    fVirtualSSLErr: Integer;
    {$ENDIF}

    function GetSSLError(retCode: Integer): Integer;
    function GetPeerCert: TTaurusTLSX509; virtual;
    procedure InitSSL(const pHandle: TIdStackSocketHandle); virtual;
    procedure SetupConnection; virtual; abstract;
  public
    constructor Create(AParent: TObject); virtual;
    destructor Destroy; override;

    function Send(const ABuffer: TIdBytes; const AOffset, ALength: TIdC_SIZET): TIdC_SIZET;
    function Recv(var VBuffer: TIdBytes): TIdC_SIZET;
    function Readable: TTaurusTLSReadStatus;

    property SSL: PSSL read fSSL;
    property Parent: TObject read FParent;
    property HostName: string read fHostName write fHostName;
    property VerifyHostname: Boolean read fVerifyHostname write fVerifyHostname;
    property PeerCert: TTaurusTLSX509 read GetPeerCert;
    property SSLContext: PSSL_CTX read fSSLContext write fSSLContext;
    {$IFDEF UNITTEST}
    property VirtualHandshakeRet: Integer read fVirtualHandshakeRet write fVirtualHandshakeRet;
    property VirtualSSLErr: Integer read fVirtualSSLErr write fVirtualSSLErr;
    {$ENDIF}
  end;

  TTaurusTLSClientSocket = class(TTaurusTLSBaseSocket)
  protected
    fECHConfigList: string;
    fECHPublicName: string;
    {$IFDEF UNITTEST}
    fVirtualECHStatus: TIdC_INT;
    fVirtualECHRetryConfig: string;
    {$ENDIF}
    procedure SetupConnection; override;
  public
    procedure Connect(const pHandle: TIdStackSocketHandle);
    property ECHConfigList: string read fECHConfigList write fECHConfigList;
    property ECHPublicName: string read fECHPublicName write fECHPublicName;
    {$IFDEF UNITTEST}
    property VirtualECHStatus: TIdC_INT read fVirtualECHStatus write fVirtualECHStatus;
    property VirtualECHRetryConfig: string read fVirtualECHRetryConfig write fVirtualECHRetryConfig;
    {$ENDIF}
  end;

  TTaurusTLSServerSocket = class(TTaurusTLSBaseSocket)
  protected
    fECHConfig: string;
    fECHPrivateKey: string;
    procedure SetupConnection; override;
  public
    procedure Accept(const pHandle: TIdStackSocketHandle);
    property ECHConfig: string read fECHConfig write fECHConfig;
    property ECHPrivateKey: string read fECHPrivateKey write fECHPrivateKey;
  end;

implementation

{ TTaurusTLSBaseSocket }

constructor TTaurusTLSBaseSocket.Create(AParent: TObject);
begin
  inherited Create;
  FParent := AParent;
  fVerifyHostname := True;
end;

destructor TTaurusTLSBaseSocket.Destroy;
begin
  if fSSL <> nil then
  begin
    SSL_free(fSSL);
    fSSL := nil;
  end;
  FreeAndNil(fPeerCert);
  inherited Destroy;
end;

function TTaurusTLSBaseSocket.GetSSLError(retCode: Integer): Integer;
begin
  Result := SSL_get_error(fSSL, retCode);
end;

function TTaurusTLSBaseSocket.GetPeerCert: TTaurusTLSX509;
var
  LX509: PX509;
begin
  if fPeerCert = nil then
  begin
    LX509 := SSL_get_peer_certificate(fSSL);
    if LX509 <> nil then
    begin
      fPeerCert := TTaurusTLSX509.Create(LX509, False);
    end;
  end;
  Result := fPeerCert;
end;

procedure TTaurusTLSBaseSocket.InitSSL(const pHandle: TIdStackSocketHandle);
begin
  if fSSL <> nil then
  begin
    SSL_free(fSSL);
  end;
  fSSL := SSL_new(fSSLContext);
  if fSSL = nil then
  begin
    ETaurusTLSCouldNotCreateSSLObject.RaiseWithMessage(RSOSSCouldNotCreateSSLObject);
  end;

  if SSL_set_fd(fSSL, pHandle) <= 0 then
  begin
    ETaurusTLSDataBindingError.RaiseException(fSSL, 0, RSSSLDataBindingError);
  end;

  SSL_set_app_data(fSSL, Self);
end;

function TTaurusTLSBaseSocket.Send(const ABuffer: TIdBytes; const AOffset,
  ALength: TIdC_SIZET): TIdC_SIZET;
var
  Lret, LErr: Integer;
  LOffset, LLength, LWritten: TIdC_SIZET;
begin
  Result := 0;
  LOffset := AOffset;
  LLength := ALength;
  repeat
    LWritten := 0;
    Lret := SSL_write_ex(fSSL, ABuffer[LOffset], LLength, LWritten);
    if Lret > 0 then
    begin
      Result := Result + LWritten;
      LOffset := LOffset + LWritten;
      LLength := LLength - LWritten;
      if LLength < 1 then
        break;
      Continue;
    end;
    LErr := GetSSLError(Lret);
    if (LErr = SSL_ERROR_WANT_READ) or (LErr = SSL_ERROR_WANT_WRITE) then
      Continue;

    if LErr <> SSL_ERROR_ZERO_RETURN then
      Result := LRet;
    break;
  until False;
end;

function TTaurusTLSBaseSocket.Recv(var VBuffer: TIdBytes): TIdC_SIZET;
var
  Lret, LErr: Integer;
  LRead: TIdC_SIZET;
begin
  Result := 0;
  repeat
    LRead := 0;
    Lret := SSL_read_ex(fSSL, VBuffer[0], Length(VBuffer), LRead);
    if Lret > 0 then
    begin
      Result := LRead;
      break;
    end;
    LErr := GetSSLError(Lret);
    if (LErr = SSL_ERROR_WANT_READ) or (LErr = SSL_ERROR_WANT_WRITE) then
      Continue;
    break;
  until False;
end;

function TTaurusTLSBaseSocket.Readable: TTaurusTLSReadStatus;
var
  buf: Byte;
  Lr: Integer;
begin
  Result := sslNoData;
  Lr := SSL_peek(fSSL, buf, 1);
  if Lr > 0 then
    Result := sslDataAvailable
  else
  begin
    case GetSSLError(Lr) of
      SSL_ERROR_SSL, SSL_ERROR_SYSCALL:
        if SSL_get_shutdown(fSSL) = SSL_RECEIVED_SHUTDOWN then
          Result := sslEOF
        else
          Result := sslUnrecoverableError;
      SSL_ERROR_ZERO_RETURN:
        if SSL_get_shutdown(fSSL) = SSL_RECEIVED_SHUTDOWN then
          Result := sslEOF;
    end;
  end;
end;

{ TTaurusTLSClientSocket }

procedure TTaurusTLSClientSocket.SetupConnection;
var
  LRetCode: Integer;
  LIdentity: string;
  LIdentityAnsi: RawByteString;
  LECHStore: TClientECHStore;
  LParams: PX509_VERIFY_PARAM;
begin
  LIdentity := fHostName;
  LIdentityAnsi := RawByteString(LIdentity);

  if LIdentityAnsi <> '' then
  begin
    if fECHConfigList <> '' then
    begin
      LECHStore := TClientECHStore.Create;
      try
        LECHStore.SetConfigList(RawByteString(fECHConfigList));
        LECHStore.Attach(fSSL);
      finally
        LECHStore.Free;
      end;

      if fECHPublicName <> '' then
      begin
        SSL_ech_set1_server_names(fSSL, PIdAnsiChar(LIdentityAnsi),
          PIdAnsiChar(AnsiString(fECHPublicName)), 0);
      end
      else
      begin
        LRetCode := SSL_set_tlsext_host_name(fSSL, PIdAnsiChar(LIdentityAnsi));
        if LRetCode <= 0 then
          ETaurusTLSSettingTLSHostNameError.RaiseException(fSSL, LRetCode, RSSSLSettingTLSHostNameError_2);
      end;
    end
    else
    begin
      LRetCode := SSL_set_tlsext_host_name(fSSL, PIdAnsiChar(LIdentityAnsi));
      if LRetCode <= 0 then
        ETaurusTLSSettingTLSHostNameError.RaiseException(fSSL, LRetCode, RSSSLSettingTLSHostNameError_2);
    end;
  end;

  if fVerifyHostname and (LIdentityAnsi <> '') then
  begin
    if IsValidIP(LIdentity) then
    begin
      LParams := SSL_get0_param(fSSL);
      if Assigned(LParams) then
      begin
        if X509_VERIFY_PARAM_set1_ip_asc(LParams, PIdAnsiChar(LIdentityAnsi)) <= 0 then
          ETaurusTLSSettingSANIPError.RaiseWithMessage(RSSLX509_VERIFY_PARAM_set1_ip_asc);
      end;
    end
    else
    begin
      SSL_set_hostflags(fSSL, 0);
      LRetCode := SSL_set1_host(fSSL, PIdAnsiChar(LIdentityAnsi));
      if LRetCode <= 0 then
        ETaurusTLSSettingTLSHostNameError.RaiseException(fSSL, LRetCode, RSSSLSettingTLSHostNameError_2);
    end;
  end;
end;

procedure TTaurusTLSClientSocket.Connect(const pHandle: TIdStackSocketHandle);
var
  LRetCode: TIdC_INT;
  LStatus: TIdC_INT;
  LECHConfigBuf: Pointer;
  LECHConfigLen: TIdC_SIZET;
begin
  InitSSL(pHandle);
  SetupConnection;

  {$IFDEF UNITTEST}
  if fVirtualHandshakeRet <> 0 then
    LRetCode := fVirtualHandshakeRet
  else
  {$ENDIF}
    LRetCode := SSL_connect(fSSL);

  if LRetCode <= 0 then
  begin
    ETaurusTLSHandshakeError.RaiseException(fSSL, LRetCode, RSOSSLConnectError);
  end;

  // ECH Status Check
  {$IFDEF UNITTEST}
  if fVirtualECHStatus <> 0 then
  begin
    LStatus := fVirtualECHStatus;
    if LStatus = SSL_ECH_STATUS_GREASE_ECH then
    begin
       if fVirtualECHRetryConfig <> '' then
         raise ETaurusTLSECHRetryRequired.Create(fVirtualECHRetryConfig, RSMsg_ECHRetryRequired_err);
       raise ETaurusTLSECHRejectedError.Create(RSMsg_ECHRejected_err);
    end;
    if LStatus = SSL_ECH_STATUS_NOT_CONFIGURED then
      raise ETaurusTLSECHDowngradeError.Create(RSMsg_ECHNotConfigured_err);
    if LStatus <> SSL_ECH_STATUS_SUCCESS then
      raise ETaurusTLSECHError.CreateFmt(LStatus, RSMsg_ECHFailed_err, [LStatus]);
    Exit;
  end;
  {$ENDIF}

  LStatus:=SSL_ech_get1_status(fSSL, nil, nil);
  case lStatus of
    SSL_ECH_STATUS_SUCCESS: ; // OK
    SSL_ECH_STATUS_GREASE_ECH:
    begin
      if SSL_ech_get1_retry_config(fSSL, @LECHConfigBuf, @LECHConfigLen) = 1 then
      begin
        try
          raise ETaurusTLSECHRetryRequired.Create(
            EncodeConfigList(LECHConfigBuf, LECHConfigLen),
            RSMsg_ECHRetryRequired_err);
        finally
          OPENSSL_free(LECHConfigBuf);
        end;
      end;
      raise ETaurusTLSECHRejectedError.Create(RSMsg_ECHRejected_err);
    end;
    SSL_ECH_STATUS_NOT_CONFIGURED:
      raise ETaurusTLSECHDowngradeError.Create(RSMsg_ECHNotConfigured_err);
  else
    raise ETaurusTLSECHError.CreateFmt(LStatus, RSMsg_ECHFailed_err, [LStatus]);
  end;
end;

{ TTaurusTLSServerSocket }

procedure TTaurusTLSServerSocket.SetupConnection;
var
  LECHStore: TServerECHStore;
begin
  if fECHConfig <> '' then
  begin
    LECHStore := TServerECHStore.Create;
    try
      LECHStore.ReadPem(fECHConfig, 0);
      LECHStore.Attach(fSSL);
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
  if fVirtualHandshakeRet <> 0 then
    LRetCode := fVirtualHandshakeRet
  else
  {$ENDIF}
    LRetCode := SSL_accept(fSSL);

  if LRetCode <= 0 then
  begin
    ETaurusTLSHandshakeError.RaiseException(fSSL, LRetCode, RSOSSLAcceptError);
  end;
end;

end.
