{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2024 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }
{$I TaurusTLSCompilerDefines.inc}

unit TaurusTLS2;

interface

uses
{$IFDEF WINDOWS}
  {$IFDEF VCL_XE2_OR_ABOVE}
  WinAPI.Windows,
  {$ELSE}
  Windows,
  {$ENDIF}
{$ENDIF}
  Classes,
  IdCTypes,
  IdGlobal,
  IdIOHandler,
  IdSocketHandle,
  IdThread,
  IdSSL,
  IdYarn,
  SysUtils,
  TaurusTLSHeaders_types,
  TaurusTLSExceptionHandlers,
  TaurusTLS_X509,
  TaurusTLSFIPS {Ensure FIPS functions initialised},
  TaurusTLS,
  TaurusTLS_Sockets;

type
  ETaurusTLSSecurityBits = class(Exception);

  TTaurusTLSSecurityBits = (sbZero, sb80, sb112, sb128, sb192, sb256);
  TTaurusTLSSecurityBitsHelper = record helper for TTaurusTLSSecurityBits
  const
    DEF_SECURITY_BITS = sb128;
  private
    function GetAsInteger: TIdC_INT; {$IFDEF USE_INLINE} inline;{$ENDIF}
    procedure SetAsInteger(AValue: TIdC_INT); {$IFDEF USE_INLINE} inline;{$ENDIF}
  public
    property AsInteger: TIdC_INT read GetAsInteger write SetAsInteger;
  end;

type
  /// <summary>
  /// Encrypted Client Hello (ECH) Configuration for Client-side.
  /// </summary>
  TTaurusECHClientConfig = class(TPersistent)
  private
    FEnabled: Boolean;
    FConfigListBase64: string;
    FPublicName: string;
    FForceECH: Boolean;
  public
    procedure Assign(Source: TPersistent); override;
  published
    /// <summary>
    /// Enable or disable ECH.
    /// </summary>
    property Enabled: Boolean read FEnabled write FEnabled default False;
    /// <summary>
    /// The Base64-encoded ECHConfigList.
    /// </summary>
    property ConfigList: string read FConfigListBase64 write FConfigListBase64;
    /// <summary>
    /// Optional Outer SNI (Public Name). If empty, the public_name from the
    /// ECHConfigList is used.
    /// </summary>
    property PublicName: string read FPublicName write FPublicName;
    /// <summary>
    /// If True, the connection will fail if ECH negotiation is unsuccessful.
    /// </summary>
    property ForceECH: Boolean read FForceECH write FForceECH default False;
  end;

  TTaurusTLSBaseOptions = class(TPersistent)
  public type
    /// <summary>
    /// Type used to specify a peer verification value.
    /// </summary>
    TTaurusTLSVerifyMode = (
      /// <summary>
      /// For servers, send certificate. For clients, verify server certificate.
      /// </summary>
      sslvrfPeer,
      /// <summary>
      /// For servers, require client certificate
      /// </summary>
      sslvrfFailIfNoPeerCert,
      /// <summary>
      /// For servers, request client certificate only at initial handshake. Do
      /// not ask for certificate during renegotiation.
      /// </summary>
      sslvrfClientOnce,
      /// <summary>
      /// For servers, server will not send client certificate request during
      /// initial handshake. Send the request during the
      /// SSL_verify_client_post_handshake call.
      /// </summary>
      sslvrfPostHandshake);
    /// <summary>
    /// Controls the peer verification. Can contain the following:<para>
    /// <c>sslvrfPeer</c> For servers, send certificate. For clients, verify
    /// server certificate.
    /// </para>
    /// <para>
    /// <c>sslvrfFailIfNoPeerCert</c> For servers, require client certificate
    /// </para>
    /// <para>
    /// <c>sslvrfClientOnce</c> For servers, request client certificate only
    /// at initial handshake. Do not ask for certificate during renegotiation.
    /// </para>
    /// <para>
    /// <c>sslvrfPostHandshake</c> For servers, server will not send client
    /// certificate request during initial handshake. Send the request during
    /// the SSL_verify_client_post_handshake call.
    /// </para>
    /// </summary>
    TTaurusTLSVerifyModeSet = set of TTaurusTLSVerifyMode;
  end;

  TTaurusTLS2Options = class(TTaurusTLSBaseOptions)
  private
    fVerifyMode: TTaurusTLSVerifyModeSet;
    fVerifyDepth: Integer;
    fVerifyHostname: Boolean;
    fCipherList: string;
    fSecurityLevel: TTaurusTLSSecurityBits;
  public
    constructor Create;
    procedure Assign(Source: TPersistent); override;
  published
    property VerifyMode: TTaurusTLSVerifyModeSet read fVerifyMode
      write fVerifyMode;
    property VerifyDepth: Integer read fVerifyDepth
      write fVerifyDepth default 100;
    property VerifyHostname: Boolean read fVerifyHostname
      write fVerifyHostname default True;
    property CipherList: string read fCipherList write fCipherList;
    property SecurityLevel: TTaurusTLSSecurityBits read fSecurityLevel
      write fSecurityLevel default TTaurusTLSSecurityBits.DEF_SECURITY_BITS;
  end;

  ITaurusTLSCallbackHelper = interface(IInterface)
    ['{F79BDC4C-4B26-446A-8EF1-9B0818321FAF}']
    procedure DoOnDebugMessage(const AWrite: Boolean; AVersion: TTaurusMsgCBVer;
      AContentType: TIdC_INT; const buf: TIdBytes; SSL: PSSL);
    function GetPassword(const AIsWrite: Boolean; out VOk: Boolean): string;
    procedure StatusInfo(const ASSL: PSSL; AWhere, Aret: TIdC_INT);
    function VerifyError(ACertificate: TTaurusTLSX509;
      const AError: TIdC_LONG): Boolean;
    procedure VerifyCallback(const APreverify_ok: TIdC_INT;
      ACertificate: TTaurusTLSX509; const ADepth: Integer;
      const AError: TIdC_LONG; const AMsg, ADescr: String;
      var VContinue: Boolean);
    procedure SecurityLevelCB(const AsslSocket: PSSL; ACtx: PSSL_CTX;
      const op, bits: TIdC_INT; const ACipherNid: TIdC_INT;
      out VAccepted: Boolean);
  end;

  TTaurusTLS2Context = class(TObject)
  private
    fContext: PSSL_CTX;
  public
    constructor Create(AOptions: TTaurusTLS2Options; AMode: TTaurusTLSSSLMode);
    destructor Destroy; override;
    property Context: PSSL_CTX read fContext;
  end;

  TTaurusTLS2IOHandlerSocket = class(TIdSSLIOHandlerSocketBase, ITaurusTLSCallbackHelper)
  private
    fSSLSocket: TTaurusTLSBaseSocket;
    fSSLContext: TTaurusTLS2Context;
    fOptions: TTaurusTLS2Options;
    fECH: TTaurusECHClientConfig;
    fOnSSLNegotiated: TNotifyEvent;
    fMode: TTaurusTLSSSLMode;
    fOnStatusInfo: TOnStatusEvent;
    fOnDebugMessage: TOnDebugMessageEvent;
    fOnVerifyError: TOnVerifyErrorEvent;
    fOnVerifyCallback: TOnVerifyCallbackEvent;
    fOnGetPassword: TOnGetPasswordEvent;
    fOnSecurityLevel: TOnSecurityLevelEvent;
  protected
    procedure InitComponent; override;
    procedure ConnectClient; override;
    procedure SetPassThrough(const Value: Boolean); override;
    function RecvEnc(var VBuffer: TIdBytes): Integer; override;
    function SendEnc(const ABuffer: TIdBytes; const AOffset, ALength: Integer): Integer; override;
    function CheckForError(ALastResult: Integer): Integer; override;
    procedure RaiseError(AError: Integer); override;

    { ITaurusTLSCallbackHelper }
    procedure DoOnDebugMessage(const AWrite: Boolean; AVersion: TTaurusMsgCBVer;
      AContentType: TIdC_INT; const buf: TIdBytes; SSL: PSSL);
    function GetPassword(const AIsWrite: Boolean; out VOk: Boolean): string;
    procedure StatusInfo(const ASSL: PSSL; AWhere, Aret: TIdC_INT);
    function VerifyError(ACertificate: TTaurusTLSX509;
      const AError: TIdC_LONG): Boolean;
    procedure VerifyCallback(const APreverify_ok: TIdC_INT;
      ACertificate: TTaurusTLSX509; const ADepth: Integer;
      const AError: TIdC_LONG; const AMsg, ADescr: String;
      var VContinue: Boolean);
    procedure SecurityLevelCB(const AsslSocket: PSSL; ACtx: PSSL_CTX;
      const op, bits: TIdC_INT; const ACipherNid: TIdC_INT;
      out VAccepted: Boolean);
  public
    destructor Destroy; override;
    procedure Open; override;
    procedure Close; override;
    function Clone: TIdSSLIOHandlerSocketBase; override;
    procedure StartSSL; override;
    function Readable(AMSec: Integer = IdTimeoutDefault): Boolean; override;
    property Mode: TTaurusTLSSSLMode read fMode write fMode;
  published
    property SSLOptions: TTaurusTLS2Options read fOptions;
    property ECH: TTaurusECHClientConfig read fECH;
    property OnSSLNegotiated: TNotifyEvent read fOnSSLNegotiated write fOnSSLNegotiated;
    property OnStatusInfo: TOnStatusEvent read fOnStatusInfo write fOnStatusInfo;
    property OnDebugMessage: TOnDebugMessageEvent read fOnDebugMessage write fOnDebugMessage;
    property OnVerifyError: TOnVerifyErrorEvent read fOnVerifyError write fOnVerifyError;
    property OnVerifyCallback: TOnVerifyCallbackEvent read fOnVerifyCallback write fOnVerifyCallback;
    property OnGetPassword: TOnGetPasswordEvent read fOnGetPassword write fOnGetPassword;
    property OnSecurityLevel: TOnSecurityLevelEvent read fOnSecurityLevel write fOnSecurityLevel;
  end;

  TTaurusTLS2ServerIOHandler = class(TIdServerIOHandlerSSLBase, ITaurusTLSCallbackHelper)
  private
    fSSLContext: TTaurusTLS2Context;
    fOptions: TTaurusTLS2Options;
    fECHConfig: string;
    fECHPrivateKey: string;
    fOnSSLNegotiated: TNotifyEvent;
    fOnStatusInfo: TOnStatusEvent;
    fOnDebugMessage: TOnDebugMessageEvent;
    fOnVerifyError: TOnVerifyErrorEvent;
    fOnVerifyCallback: TOnVerifyCallbackEvent;
    fOnGetPassword: TOnGetPasswordEvent;
    fOnSecurityLevel: TOnSecurityLevelEvent;
  protected
    procedure InitComponent; override;
    function MakeDataChannelIOHandler: TTaurusTLS2IOHandlerSocket;
  public
    destructor Destroy; override;
    procedure Init; override;
    procedure Shutdown; override;
    function Accept(ASocket: TIdSocketHandle; AListenerThread: TIdThread;
      AYarn: TIdYarn): TIdIOHandler; override;

    function MakeFTPSvrPasv: TIdSSLIOHandlerSocketBase; override;
    function MakeFTPSvrPort: TIdSSLIOHandlerSocketBase; override;

    { ITaurusTLSCallbackHelper }
    procedure DoOnDebugMessage(const AWrite: Boolean; AVersion: TTaurusMsgCBVer;
      AContentType: TIdC_INT; const buf: TIdBytes; SSL: PSSL);
    function GetPassword(const AIsWrite: Boolean; out VOk: Boolean): string;
    procedure StatusInfo(const ASSL: PSSL; AWhere, Aret: TIdC_INT);
    function VerifyError(ACertificate: TTaurusTLSX509;
      const AError: TIdC_LONG): Boolean;
    procedure VerifyCallback(const APreverify_ok: TIdC_INT;
      ACertificate: TTaurusTLSX509; const ADepth: Integer;
      const AError: TIdC_LONG; const AMsg, ADescr: String;
      var VContinue: Boolean);
    procedure SecurityLevelCB(const AsslSocket: PSSL; ACtx: PSSL_CTX;
      const op, bits: TIdC_INT; const ACipherNid: TIdC_INT;
      out VAccepted: Boolean);
  published
    property SSLOptions: TTaurusTLS2Options read fOptions;
    property ECHConfig: string read fECHConfig write fECHConfig;
    property ECHPrivateKey: string read fECHPrivateKey write fECHPrivateKey;
    property OnSSLNegotiated: TNotifyEvent read fOnSSLNegotiated write fOnSSLNegotiated;
    property OnStatusInfo: TOnStatusEvent read fOnStatusInfo write fOnStatusInfo;
    property OnDebugMessage: TOnDebugMessageEvent read fOnDebugMessage write fOnDebugMessage;
    property OnVerifyError: TOnVerifyErrorEvent read fOnVerifyError write fOnVerifyError;
    property OnVerifyCallback: TOnVerifyCallbackEvent read fOnVerifyCallback write fOnVerifyCallback;
    property OnGetPassword: TOnGetPasswordEvent read fOnGetPassword write fOnGetPassword;
    property OnSecurityLevel: TOnSecurityLevelEvent read fOnSecurityLevel write fOnSecurityLevel;
  end;

procedure GetStateVars(const SSLSocket: PSSL; const AWhere, Aret: TIdC_INT;
  out VTypeStr, VMsg: String);

implementation

uses
  IdURI,
  TaurusTLSHeaders_objects,
  TaurusTLSHeaders_ssl,
  TaurusTLSHeaders_tls1,
  TaurusTLSHeaders_x509,
  TaurusTLS_Utils,
  TaurusTLS_ResourceStrings;


{ TTaurusTLSSecurityBitsHelper }

function TTaurusTLSSecurityBitsHelper.GetAsInteger: TIdC_INT;
begin
  Result:=Ord(Self);
end;

procedure TTaurusTLSSecurityBitsHelper.SetAsInteger(AValue: TIdC_INT);
{$IFOPT R+}
  {$DEFINE RANGE-CHECK_ON}
{$ENDIF}
{$R-}
begin
  if not (AValue in [Ord(sbZero)..Ord(sb256)]) then
    raise ETaurusTLSSecurityBits.CreateFmt(RMSG_SecurityBits_Convert_err, [AValue]);
  Self:=TTaurusTLSSecurityBits(AValue);
end;
{$IFDEF RANGE-CHECK_ON}
  {$R+}
{$ENDIF}

procedure GetStateVars(const SSLSocket: PSSL; const AWhere, Aret: TIdC_INT;
  out VTypeStr, VMsg: String);
{$IFDEF USE_INLINE}inline; {$ENDIF}
var
  LState, LAlert: String;
begin
  VTypeStr := '';
  VMsg := '';
  LState := AnsiStringToString(SSL_state_string_long(SSLSocket));
  LAlert := AnsiStringToString(SSL_alert_type_string_long(Aret));

  case AWhere of
    SSL_CB_ALERT:
      begin
        VTypeStr := IndyFormat(RSOSSLAlert, [SSL_alert_type_string_long(Aret)]);
        VMsg := LAlert;
      end;
    SSL_CB_READ_ALERT:
      begin
        VTypeStr := IndyFormat(RSOSSLReadAlert,
          [SSL_alert_type_string_long(Aret)]);
        VMsg := LAlert;
      end;
    SSL_CB_WRITE_ALERT:
      begin
        VTypeStr := IndyFormat(RSOSSLWriteAlert, [LAlert]);
        VMsg := AnsiStringToString(SSL_alert_desc_string_long(Aret));
      end;
    SSL_CB_ACCEPT_LOOP:
      begin
        VTypeStr := RSOSSLAcceptLoop;
        VMsg := LState;
      end;
    SSL_CB_ACCEPT_EXIT:
      begin
        if Aret < 0 then
        begin
          VTypeStr := RSOSSLAcceptError;
        end
        else
        begin
          if Aret = 0 then
          begin
            VTypeStr := RSOSSLAcceptFailed;
          end
          else
          begin
            VTypeStr := RSOSSLAcceptExit;
          end;
        end;
        VMsg := LState;
      end;
    SSL_CB_CONNECT_LOOP:
      begin
        VTypeStr := RSOSSLConnectLoop;
        VMsg := LState;
      end;
    SSL_CB_CONNECT_EXIT:
      begin
        if Aret < 0 then
        begin
          VTypeStr := RSOSSLConnectError;
        end
        else
        begin
          if Aret = 0 then
          begin
            VTypeStr := RSOSSLConnectFailed
          end
          else
          begin
            VTypeStr := RSOSSLConnectExit;
          end;
        end;
        VMsg := LState;
      end;
    SSL_CB_HANDSHAKE_START:
      begin
        VTypeStr := RSOSSLHandshakeStart;
        VMsg := LState;
      end;
    SSL_CB_HANDSHAKE_DONE:
      begin
        VTypeStr := RSOSSLHandshakeDone;
        VMsg := LState;
      end;
  end;
end;

{ TTaurusECHClientConfig }

procedure TTaurusECHClientConfig.Assign(Source: TPersistent);
begin
  if Source is TTaurusECHClientConfig then
  begin
    FEnabled := TTaurusECHClientConfig(Source).Enabled;
    FConfigListBase64 := TTaurusECHClientConfig(Source).ConfigList;
    FPublicName := TTaurusECHClientConfig(Source).PublicName;
    FForceECH := TTaurusECHClientConfig(Source).ForceECH;
  end
  else
    inherited Assign(Source);
end;

{ TTaurusTLS2Options }

constructor TTaurusTLS2Options.Create;
begin
  inherited Create;
  fVerifyDepth := 100;
  fVerifyHostname := True;
  fSecurityLevel := TTaurusTLSSecurityBits.DEF_SECURITY_BITS;
end;

procedure TTaurusTLS2Options.Assign(Source: TPersistent);
begin
  if Source is TTaurusTLS2Options then
  begin
    fVerifyMode := TTaurusTLS2Options(Source).VerifyMode;
    fVerifyDepth := TTaurusTLS2Options(Source).VerifyDepth;
    fVerifyHostname := TTaurusTLS2Options(Source).VerifyHostname;
    fCipherList := TTaurusTLS2Options(Source).CipherList;
    fSecurityLevel := TTaurusTLS2Options(Source).SecurityLevel;
  end
  else
    inherited Assign(Source);
end;

{ TTaurusTLS2Context }

constructor TTaurusTLS2Context.Create(AOptions: TTaurusTLS2Options; AMode: TTaurusTLSSSLMode);
var
  LMethod: PSSL_METHOD;
begin
  inherited Create;
  if AMode = sslmServer then
    LMethod := TLS_server_method
  else
    LMethod := TLS_client_method;

  fContext := SSL_CTX_new(LMethod);
  if fContext = nil then
    ETaurusTLSAPICryptoError.RaiseException;

  SSL_CTX_set_min_proto_version(fContext, TLS1_2_VERSION);
  SSL_CTX_set_security_level(fContext, AOptions.SecurityLevel.AsInteger);

  if AOptions.CipherList <> '' then
    SSL_CTX_set_cipher_list(fContext, PIdAnsiChar(AnsiString(AOptions.CipherList)));

  SSL_CTX_set_default_verify_paths(fContext);
end;

destructor TTaurusTLS2Context.Destroy;
begin
  if fContext <> nil then
    SSL_CTX_free(fContext);
  inherited Destroy;
end;

{ TTaurusTLS2IOHandlerSocket }

procedure TTaurusTLS2IOHandlerSocket.InitComponent;
begin
  inherited InitComponent;
  fOptions := TTaurusTLS2Options.Create;
  fECH := TTaurusECHClientConfig.Create;
  fMode := sslmClient;
end;

destructor TTaurusTLS2IOHandlerSocket.Destroy;
begin
  Close;
  FreeAndNil(fOptions);
  FreeAndNil(fECH);
  inherited Destroy;
end;

procedure TTaurusTLS2IOHandlerSocket.Open;
begin
  inherited Open;
  if not PassThrough then
    StartSSL;
end;

procedure TTaurusTLS2IOHandlerSocket.Close;
begin
  FreeAndNil(fSSLSocket);
  FreeAndNil(fSSLContext);
  inherited Close;
end;

procedure TTaurusTLS2IOHandlerSocket.StartSSL;
var
  LSock: TTaurusTLSClientSocket;
  LSvrSock: TTaurusTLSServerSocket;
  LHost: string;
  LURI: TIdURI;
begin
  if fSSLSocket = nil then
  begin
    if fSSLContext = nil then
      fSSLContext := TTaurusTLS2Context.Create(fOptions, fMode);

    if fMode = sslmServer then
    begin
      LSvrSock := TTaurusTLSServerSocket.Create(Self);
      fSSLSocket := LSvrSock;
    end
    else
    begin
      LSock := TTaurusTLSClientSocket.Create(Self);
      fSSLSocket := LSock;
      
      LHost := Host;
      if LHost = '' then
      begin
        if URIToCheck <> '' then
        begin
          LURI := TIdURI.Create(URIToCheck);
          try
            LHost := LURI.Host;
          finally
            LURI.Free;
          end;
        end;
      end;
      LSock.HostName := LHost;

      if fECH.Enabled and (fECH.ConfigList <> '') then
      begin
        LSock.ECHConfigList := fECH.ConfigList;
        LSock.ECHPublicName := fECH.PublicName;
      end;
    end;

    fSSLSocket.SSLContext := fSSLContext.Context;
    fSSLSocket.VerifyHostname := fOptions.VerifyHostname;

    if fMode = sslmServer then
      (fSSLSocket as TTaurusTLSServerSocket).Accept(Binding.Handle)
    else
      (fSSLSocket as TTaurusTLSClientSocket).Connect(Binding.Handle);

    if Assigned(fOnSSLNegotiated) then
      fOnSSLNegotiated(Self);
  end;
end;

procedure TTaurusTLS2IOHandlerSocket.ConnectClient;
begin
  inherited ConnectClient;
  if not PassThrough then
    StartSSL;
end;

function TTaurusTLS2IOHandlerSocket.Clone: TIdSSLIOHandlerSocketBase;
var
  LIO: TTaurusTLS2IOHandlerSocket;
begin
  LIO := TTaurusTLS2IOHandlerSocket.Create(nil);
  try
    LIO.SSLOptions.Assign(fOptions);
    LIO.ECH.Assign(fECH);
    LIO.OnSSLNegotiated := fOnSSLNegotiated;
    LIO.OnStatusInfo := fOnStatusInfo;
    LIO.OnDebugMessage := fOnDebugMessage;
    LIO.OnVerifyError := fOnVerifyError;
    LIO.OnVerifyCallback := fOnVerifyCallback;
    LIO.OnGetPassword := fOnGetPassword;
    LIO.OnSecurityLevel := fOnSecurityLevel;

    LIO.SSLOptions.VerifyHostname := False;
    LIO.OnVerifyError := nil;

    Result := LIO;
  except
    LIO.Free;
    raise;
  end;
end;

procedure TTaurusTLS2IOHandlerSocket.SetPassThrough(const Value: Boolean);
begin
  if Value <> fPassThrough then
  begin
    inherited SetPassThrough(Value);
    if (not fPassThrough) and (Binding <> nil) and Binding.HandleAllocated then
      StartSSL;
  end;
end;

function TTaurusTLS2IOHandlerSocket.RecvEnc(var VBuffer: TIdBytes): Integer;
begin
  if fSSLSocket <> nil then
    Result := fSSLSocket.Recv(VBuffer)
  else
    Result := 0;
end;

function TTaurusTLS2IOHandlerSocket.SendEnc(const ABuffer: TIdBytes; const AOffset,
  ALength: Integer): Integer;
begin
  if fSSLSocket <> nil then
    Result := fSSLSocket.Send(ABuffer, AOffset, ALength)
  else
    Result := 0;
end;

function TTaurusTLS2IOHandlerSocket.Readable(AMSec: Integer): Boolean;
begin
  Result := inherited Readable(AMSec);
  if (not Result) and (not fPassThrough) and (fSSLSocket <> nil) then
    Result := fSSLSocket.Readable = sslDataAvailable;
end;

function TTaurusTLS2IOHandlerSocket.CheckForError(ALastResult: Integer): Integer;
begin
  Result := ALastResult;
end;

procedure TTaurusTLS2IOHandlerSocket.RaiseError(AError: Integer);
begin
  ETaurusTLSAPICryptoError.RaiseException;
end;

{ ITaurusTLSCallbackHelper Implementations }

procedure TTaurusTLS2IOHandlerSocket.DoOnDebugMessage(const AWrite: Boolean; AVersion: TTaurusMsgCBVer;
  AContentType: TIdC_INT; const buf: TIdBytes; SSL: PSSL);
begin
  if Assigned(fOnDebugMessage) then
    fOnDebugMessage(Self, AWrite, AVersion, AContentType, buf, SSL);
end;

function TTaurusTLS2IOHandlerSocket.GetPassword(const AIsWrite: Boolean; out VOk: Boolean): string;
begin
  VOk := False;
  Result := '';
  if Assigned(fOnGetPassword) then
    fOnGetPassword(Self, Result, AIsWrite, VOk);
end;

procedure TTaurusTLS2IOHandlerSocket.StatusInfo(const ASSL: PSSL; AWhere, Aret: TIdC_INT);
var
  LType, LMsg: string;
begin
  if Assigned(fOnStatusInfo) then
  begin
    GetStateVars(ASSL, AWhere, Aret, LType, LMsg);
    fOnStatusInfo(Self, ASSL, AWhere, Aret, LType, LMsg);
  end;
end;

function TTaurusTLS2IOHandlerSocket.VerifyError(ACertificate: TTaurusTLSX509; const AError: TIdC_LONG): Boolean;
begin
  Result := True;
  if Assigned(fOnVerifyError) then
    fOnVerifyError(Self, ACertificate, AError, 
      AnsiStringToString(X509_verify_cert_error_string(AError)),
      CertErrorToLongDescr(AError), Result);
end;

procedure TTaurusTLS2IOHandlerSocket.VerifyCallback(const APreverify_ok: TIdC_INT; ACertificate: TTaurusTLSX509;
  const ADepth: Integer; const AError: TIdC_LONG; const AMsg, ADescr: String; var VContinue: Boolean);
begin
  VContinue := True;
  if Assigned(fOnVerifyCallback) then
    fOnVerifyCallback(Self, APreverify_ok, ACertificate, ADepth, AError, AMsg, ADescr, VContinue);
end;

procedure TTaurusTLS2IOHandlerSocket.SecurityLevelCB(const AsslSocket: PSSL; ACtx: PSSL_CTX; const op, bits: TIdC_INT;
  const ACipherNid: TIdC_INT; out VAccepted: Boolean);
begin
  VAccepted := True;
  if Assigned(fOnSecurityLevel) then
    fOnSecurityLevel(Self, AsslSocket, ACtx, op, bits, ACipherNid, 
      AnsiStringToString(OBJ_nid2ln(ACipherNid)), VAccepted);
end;

{ TTaurusTLS2ServerIOHandler }

procedure TTaurusTLS2ServerIOHandler.InitComponent;
begin
  inherited InitComponent;
  fOptions := TTaurusTLS2Options.Create;
end;

destructor TTaurusTLS2ServerIOHandler.Destroy;
begin
  Shutdown;
  FreeAndNil(fOptions);
  inherited Destroy;
end;

procedure TTaurusTLS2ServerIOHandler.Init;
begin
  if fSSLContext = nil then
    fSSLContext := TTaurusTLS2Context.Create(fOptions, sslmServer);
end;

procedure TTaurusTLS2ServerIOHandler.Shutdown;
begin
  FreeAndNil(fSSLContext);
end;

function TTaurusTLS2ServerIOHandler.Accept(ASocket: TIdSocketHandle; AListenerThread: TIdThread;
  AYarn: TIdYarn): TIdIOHandler;
var
  LIO: TTaurusTLS2IOHandlerSocket;
begin
  LIO := TTaurusTLS2IOHandlerSocket.Create(nil);
  try
    LIO.Mode := sslmServer;
    LIO.SSLOptions.Assign(fOptions);
    LIO.OnSSLNegotiated := fOnSSLNegotiated;
    LIO.OnStatusInfo := fOnStatusInfo;
    LIO.OnDebugMessage := fOnDebugMessage;
    LIO.OnVerifyError := fOnVerifyError;
    LIO.OnVerifyCallback := fOnVerifyCallback;
    LIO.OnGetPassword := fOnGetPassword;
    LIO.OnSecurityLevel := fOnSecurityLevel;

    LIO.PassThrough := True;
    LIO.Open;
    LIO.Binding.Assign(ASocket);
    LIO.AfterAccept;
    Result := LIO;
  except
    LIO.Free;
    raise;
  end;
end;

function TTaurusTLS2ServerIOHandler.MakeDataChannelIOHandler: TTaurusTLS2IOHandlerSocket;
begin
  Result := TTaurusTLS2IOHandlerSocket.Create(nil);
  Result.SSLOptions.Assign(fOptions);
  Result.OnSSLNegotiated := fOnSSLNegotiated;
  Result.OnStatusInfo := fOnStatusInfo;
  Result.OnDebugMessage := fOnDebugMessage;
  Result.OnVerifyError := fOnVerifyError;
  Result.OnVerifyCallback := fOnVerifyCallback;
  Result.OnGetPassword := fOnGetPassword;
  Result.OnSecurityLevel := fOnSecurityLevel;
  Result.PassThrough := True;
end;

function TTaurusTLS2ServerIOHandler.MakeFTPSvrPasv: TIdSSLIOHandlerSocketBase;
begin
  Result := MakeDataChannelIOHandler;
end;

function TTaurusTLS2ServerIOHandler.MakeFTPSvrPort: TIdSSLIOHandlerSocketBase;
begin
  Result := MakeDataChannelIOHandler;
end;

procedure TTaurusTLS2ServerIOHandler.DoOnDebugMessage(const AWrite: Boolean; AVersion: TTaurusMsgCBVer;
  AContentType: TIdC_INT; const buf: TIdBytes; SSL: PSSL);
begin
  if Assigned(fOnDebugMessage) then
    fOnDebugMessage(Self, AWrite, AVersion, AContentType, buf, SSL);
end;

function TTaurusTLS2ServerIOHandler.GetPassword(const AIsWrite: Boolean; out VOk: Boolean): string;
begin
  VOk := False;
  Result := '';
  if Assigned(fOnGetPassword) then
    fOnGetPassword(Self, Result, AIsWrite, VOk);
end;

procedure TTaurusTLS2ServerIOHandler.StatusInfo(const ASSL: PSSL; AWhere, Aret: TIdC_INT);
var
  LType, LMsg: string;
begin
  if Assigned(fOnStatusInfo) then
  begin
    GetStateVars(ASSL, AWhere, Aret, LType, LMsg);
    fOnStatusInfo(Self, ASSL, AWhere, Aret, LType, LMsg);
  end;
end;

function TTaurusTLS2ServerIOHandler.VerifyError(ACertificate: TTaurusTLSX509; const AError: TIdC_LONG): Boolean;
begin
  Result := True;
  if Assigned(fOnVerifyError) then
    fOnVerifyError(Self, ACertificate, AError, 
      AnsiStringToString(X509_verify_cert_error_string(AError)),
      CertErrorToLongDescr(AError), Result);
end;

procedure TTaurusTLS2ServerIOHandler.VerifyCallback(const APreverify_ok: TIdC_INT; ACertificate: TTaurusTLSX509;
  const ADepth: Integer; const AError: TIdC_LONG; const AMsg, ADescr: String; var VContinue: Boolean);
begin
  VContinue := True;
  if Assigned(fOnVerifyCallback) then
    fOnVerifyCallback(Self, APreverify_ok, ACertificate, ADepth, AError, AMsg, ADescr, VContinue);
end;

procedure TTaurusTLS2ServerIOHandler.SecurityLevelCB(const AsslSocket: PSSL; ACtx: PSSL_CTX; const op, bits: TIdC_INT;
  const ACipherNid: TIdC_INT; out VAccepted: Boolean);
begin
  VAccepted := True;
  if Assigned(fOnSecurityLevel) then
    fOnSecurityLevel(Self, AsslSocket, ACtx, op, bits, ACipherNid, 
      AnsiStringToString(OBJ_nid2ln(ACipherNid)), VAccepted);
end;

end.
