program HTTPSDemo;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.Net.URLClient,
  IdGlobal,
  IdStack,
  IdStackConsts,
  IdSocketHandle,
  IdCTypes,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_ssl,
  TaurusTLSHeaders_x509,
  TaurusTLS_types,
  TaurusTLS_Utils,
  TaurusTLS_X509,
  TaurusTLS_Sockets,
  TaurusTLS_SSLStores,
  TaurusTLSExceptionHandlers,
  TaurusTLSLoader;

type
  ECmdParams = class(Exception)
  private const
    cUsageStr =
      '%s'+
      'Usage: DemoHTTPS -d <URL> -m <MODE> [-s <SNI>] [-e <ECHConfig>]'+
      sLineBreak+sLineBreak+
      'Parameters:'+sLineBreak+
      '  -d <URL>       : Target HTTPS address (e.g. https://crypto.cloudflare.com/cdn-cgi/trace)'+sLineBreak+
      '  -m <MODE>      : Direct | SNI | ECHGrease | ECHGreaseDiscover | ECH | ECHNoOuter'+sLineBreak+
      '  -s <SNI>       : (Optional) SNI hostname override or ECH decoy host'+sLineBreak+
      '  -t <SNI>       : (Optional) Path to trusted CA store.'+sLineBreak+
      '  -e <ECHConfig> : (Optional/Required for ECH) Base64-encoded ECHConfigList'+sLineBreak+
      '  -l <PATH>      : (Optional) Path to OpenSSL shared library.'
    ;
  public
    constructor Create(const AMsg: string  = '');
  end;

  EOsslLoad = class(Exception)
  private const
    cMsg =      'Unable to load  OpenSSL shared library.%s';
    cPathSuf =  ' Ensure that the OpenSSL shared library location '+
                'belongs to the PATH environament variable ';
    cMsgSuf =   ' Ensure that the OpenSSL shared library location '+
                'belongs to the ''%s'' ';
  public
    constructor CreatePath(const APath: string = '');
  end;

  TDemoHttpClient = class
  private
    FURL: string;
    FSNIMode: TTaurusTLSSslClientSNIMode;
    FSNI: string;
    FTrustedStore: string;
    FECHConfig: string;
    FRecoveredECHConfig: string;

    procedure HandleVerifyCert(ASender: TObject; ASocket: TTaurusTLSSslSocket;
      ACertValidator: TTaurusTLSX509CertValidator; var ASuccess,
      AContinue: Boolean);
    procedure HandlePeerCertificateError(ASender: TObject;
      ASocket: TTaurusTLSSslSocket; ACertificate: TTaurusTLSX509;
      const AError: TTaurusTLSX509Error; var ASuccess: boolean);
    procedure HandleECHRetry(ASender: TObject; ASocket: TTaurusTLSSslSocket;
      const AECHRetryConfig: string);
    function ExecuteGetRequest(const AHost, APath: string; APort: Word): Boolean;
  public
    constructor Create(const AURL: string; AMode: TTaurusTLSSslClientSNIMode;
      const ASNI, ATrustedStore, AECHConfig: string);
    procedure Run;
  end;

{ ECmdParams }

constructor ECmdParams.Create(const AMsg: string);
var
  lMsg: string;

begin
  if AMsg.IsEmpty then
    lMsg:=''
  else
    lMsg:='Parameter error: '+AMsg+sLineBreak+sLineBreak;

  inherited Create(Format(cUsageStr, [lMsg]));
end;

{ EOsslLoad }

constructor EOsslLoad.CreatePath(const APath: string);
var
  lMsg: string;

begin
  if APath.IsEmpty then
    lMsg:=cPathSuf
  else
    lMsg:=Format(cMsgSuf, [APath]);

  inherited Create(lMsg);
end;

{ TDemoHttpClient }

constructor TDemoHttpClient.Create(const AURL: string;
  AMode: TTaurusTLSSslClientSNIMode; const ASNI, ATrustedStore, AECHConfig: string);
begin
  inherited Create;
  FURL:=AURL;
  FSNIMode:=AMode;
  FSNI:=ASNI;
  FTrustedStore:=ATrustedStore;
  FECHConfig:=AECHConfig;
  FRecoveredECHConfig:='';
end;

procedure TDemoHttpClient.HandleECHRetry(ASender: TObject;
  ASocket: TTaurusTLSSslSocket; const AECHRetryConfig: string);
begin
  FRecoveredECHConfig:=AECHRetryConfig;
  Writeln('>>>> ECH Retry Config received from server:');
  Writeln(StringOfChar('=', 80));
  Writeln(AECHRetryConfig);
  Writeln(StringOfChar('=', 80));
end;

procedure TDemoHttpClient.HandlePeerCertificateError(ASender: TObject;
  ASocket: TTaurusTLSSslSocket; ACertificate: TTaurusTLSX509;
  const AError: TTaurusTLSX509Error; var ASuccess: boolean);
begin
  Writeln('>>>> Peer Certificate Error:');
  Writeln(StringOfChar('=', 80));
  if ASuccess then
    Writeln('Certificate validation succeded.')
  else
    Writeln(Format('Certificate validation error: %x; ''%s''',
      [AError.ErrorCode, AError.ErrorLongDescription]));

  Writeln(StringOfChar('-', 80));
  Writeln(ACertificate.DisplayInfo.Text);
  Writeln(StringOfChar('=', 80));
end;

procedure TDemoHttpClient.HandleVerifyCert(ASender: TObject;
  ASocket: TTaurusTLSSslSocket; ACertValidator: TTaurusTLSX509CertValidator;
  var ASuccess, AContinue: Boolean);
begin
  Writeln('>>>> Peer Certificate Verification callback:');
  Writeln(StringOfChar('=', 80));
  if ASuccess then
    Writeln('Certificate validation succeded.')
  else
    Writeln(Format('Certificate validation error: %x; ''%s''',
      [ACertValidator.ErrorCode, ACertValidator.ErrorLongDescription]));

  Writeln(StringOfChar('-', 80));
  Writeln(ACertValidator.CurrentCertificate.DisplayInfo.Text);
  Writeln(StringOfChar('=', 80));
end;

function TDemoHttpClient.ExecuteGetRequest(const AHost, APath: string;
  APort: Word): Boolean;
var
  lSocketHandle: TIdSocketHandle;
  lBuilder: TTaurusTLSSslClientSocketCtxBuilder;
  lConfigIntf: ITaurusTLSSslSocketCtx;
  lClientSocket: TTaurusTLSClientSocket;
  lTrustStore: TTaurusTLSTrustStore;
  lIP: string;
  lRequest: string;
  lRequestBytes: TIdBytes;
  lBuffer: TIdBytes;
  lBytesRead: Integer;
  lResponse: string;
  lConnected: Boolean;

begin
  Result:=False;
  FRecoveredECHConfig:='';

  // 1. Establish raw TCP connection using Indy socket handle
  lTrustStore:=nil;
  lSocketHandle:=TIdSocketHandle.Create(nil);
  try
    lIP:=GStack.ResolveHost(AHost, Id_IPv4);
    lSocketHandle.AllocateSocket;
    lSocketHandle.IPVersion:=Id_IPv4;
    lSocketHandle.SetPeer(lIP, APort);
    lSocketHandle.Connect;

    // Set socket operational timeouts (10 seconds)
    GStack.SetSocketOption(lSocketHandle.Handle, Id_SOL_SOCKET, Id_SO_RCVTIMEO, 10000);
    GStack.SetSocketOption(lSocketHandle.Handle, Id_SOL_SOCKET, Id_SO_SNDTIMEO, 10000);

    // 3. Configure SSL Client Context via Builder
    lBuilder:=TTaurusTLSSslClientSocketCtxBuilder.Create;
    try
      lBuilder.HostName:=AHost;
      lBuilder.SNIMode:=FSNIMode;
      lBuilder.VerifyHostName:=True;
      lBuilder.VerifyModes:=[sslvrfPeer];

      if not FTrustedStore.IsEmpty then
        lTrustStore:=TTaurusTLSTrustStore.Create(
          TPath.GetFileName(FTrustedStore), FTrustedStore, nil);

      if Assigned(lTrustStore) then
        lBuilder.TrustedStores.Add(lTrustStore);
      lBuilder.TrustedStores.UseSystemCertStore:=True;

      if FSNI <> '' then
      begin
        lBuilder.DefaultSNI:=FSNI;
        lBuilder.ECHOuterSNI:=FSNI;
      end
      else if FSNIMode > csmDisabled then
        lBuilder.DefaultSNI:=AHost;

      if FECHConfig <> '' then
        lBuilder.ECHConfigList:=FECHConfig;

      lBuilder.OnECHConfigRetry:=HandleECHRetry;
      lBuilder.OnPeerCertError:=HandlePeerCertificateError;
      lBuilder.OnVerifyCertificate:=HandleVerifyCert;

      // Compile immutable context snapshot
      lConfigIntf:=lBuilder.Build(Self);
    finally
      lBuilder.Free;
    end;

    // 3. Initialize Client Socket
    lClientSocket:=TTaurusTLSClientSocket.Create(lConfigIntf);
    try
      // 4. Perform TLS Handshake (10 second budget)
      lConnected:=lClientSocket.Connect(lSocketHandle.Handle, 10000);

      if not lConnected then
      begin
        // Handshake did not reach seEstablished
        if (lClientSocket.ECHStatus = echCliRetryConfig) and (FRecoveredECHConfig <> '') then
        begin
          // ECH key rotation / discovery triggered
          Exit(False);
        end;
        raise ETaurusTLSHandshakeError.CreateFmt(
          'TLS Handshake failed. Final socket state: %s', [lClientSocket.State.AsString]
        );
      end;

      Writeln('>> TLS Connection Established.');
      Writeln('>> Negotiated Protocol: ', lClientSocket.State.AsString);
      Writeln('>> ECH Status: ', IntToStr(Ord(lClientSocket.ECHStatus)));

      // 5. Send HTTP/1.0 Request
      lRequest:='GET ' + APath + ' HTTP/1.0'#13#10 +
                  'Host: ' + AHost + #13#10 +
                  'User-Agent: TaurusTLS-Demo/1.0'#13#10 +
                  'Connection: close'#13#10#13#10;
      lRequestBytes:=ToBytes(lRequest, IndyTextEncoding_UTF8);

      lClientSocket.Send(lRequestBytes, 0, Length(lRequestBytes), 10000);

      // 6. Receive HTTP Response
      Writeln('>> Receiving response payload...'#10);
      SetLength(lBuffer, 4096);
      lResponse:='';

      while lClientSocket.Readable(10000) do
      begin
        lBytesRead:=lClientSocket.Recv(lBuffer, 10000);
        if lBytesRead <= 0 then
          Break;
        lResponse:=lResponse + IndyTextEncoding_UTF8.GetString(lBuffer, 0, lBytesRead);
      end;

      Writeln('==================== HTTP RESPONSE ====================');
      Writeln(lResponse);
      Writeln('=======================================================');

      Result:=True;
    finally
      lClientSocket.Free;
    end;

  finally
    lTrustStore.Free;
    lSocketHandle.CloseSocket;
    lSocketHandle.Free;
  end;
end;

procedure TDemoHttpClient.Run;
var
  lURI: TURI;
  lHost: string;
  lPath: string;
  lPort: Word;
  lAttempt: Integer;
  lSuccess: Boolean;

begin
  lURI:=TURI.Create(FURL);
  lHost:=lURI.Host;
  lPort:=lURI.Port;
  if lPort = 0 then
    lPort:=443;

  lPath:=lURI.Path;
  if lPath = '' then
    lPath:='/';
  if lURI.Query <> '' then
    lPath:=lPath + '?' + lURI.Query;

  lSuccess:=False;
  lAttempt:=1;

  while (lAttempt <= 2) and (not lSuccess) do
  begin
    Writeln(Format('--- Connection Attempt %d to https://%s:%d%s ---', [lAttempt, lHost, lPort, lPath]));
    lSuccess:=ExecuteGetRequest(lHost, lPath, lPort);

    if (not lSuccess) and (FRecoveredECHConfig <> '') then
    begin
      Writeln('>> Applying recovered ECH keys and reconnecting...'+
        sLineBreak+sLineBreak);
      FECHConfig:=FRecoveredECHConfig;
      if FSNIMode = csmECHGreaseDiscovery then
        FSNIMode:=csmECH; // Upgrade from discovery probe to real ECH
      Inc(lAttempt);
    end
    else
      Break;
  end;
end;

const
  cCmdSwitch = '-/';
  cModeStrings: array[TTaurusTLSSslClientSNIMode] of string =
    ('Direct', 'SNI', 'ECHGrease', 'ECHGreaseDiscover', 'ECH', 'ECHNoOuter');

procedure PrintUsage(const AMsg: string = ''); inline;
begin
  raise ECmdParams.Create(AMsg);
end;

function GetSNIMode(const AModeStr: string): TTaurusTLSSslClientSNIMode;
var
  lModeFound: boolean;

begin
  lModeFound:=False;

  for Result:= Low(TTaurusTLSSslClientSNIMode) to High(TTaurusTLSSslClientSNIMode) do
  begin
    lModeFound:=SameText(cModeStrings[Result], AModeStr);
    if lModeFound then
      Break;
  end;

  if not lModeFound then
    PrintUsage(Format('The value ''%s'' is not valid MODE name.', [AModeStr]));
end;

procedure CheckOsslVersion(const AVersion: cardinal);
var
  lVer: cardinal;

begin
  lVer:=OpenSSL_version_num;
  if lVer <= AVersion then
    raise Exception.CreateFmt('OpenSSL Version %x loaded, but the Version %x is required.',
      [AVersion, lVer]);
end;

var
  lURL, lModeStr, lSNI, lECHConfig, lOsslPath, lTrustedStore: string;
  lSNIMode: TTaurusTLSSslClientSNIMode;
  lClient: TDemoHttpClient;
  lOsslLoader: IOpenSSLLoader;

begin
  lOsslLoader:=nil;
  try
    try
      if not FindCmdLineSwitch('d', lURL) then
        PrintUsage('Required parameter URL not found in command line');

      if not FindCmdLineSwitch('m', lModeStr) then
        PrintUsage('Required parameter MODE not found in command line');
      lSNIMode:=GetSNIMode(lModeStr);

//      if lSNIMode > csmDisabled then
        FindCmdLineSwitch('s', lSNI);

      FindCmdLineSwitch('e', lECHConfig);
      FindCmdLineSwitch('t', lTrustedStore);
      FindCmdLineSwitch('l', lOsslPath);


      if (lSNIMode in [csmECH, csmECHNoOuter]) and (lECHConfig = '') then
        PrintUsage(Format('ECHConfig parameter (Base64) is required for mode ''%s''.',
          [cModeStrings[lSNIMode]]));

      // Load OpenSSL
      lOsslLoader:=GetOpenSSLLoader;
      lOsslLoader.SetOpenSSLPath(lOsslPath);
      if not lOsslLoader.Load then
        raise EOsslLoad.CreatePath(lOsslPath);



      // Check OpenSSL version. ECH requires OpenSSL 4.0+
      if lSNIMode >= csmECHGrease then
        CheckOsslVersion($40000000);


      // Initialize Indy stack
      TIdStack.IncUsage;
      try
        lClient:=TDemoHttpClient.Create(lURL, lSNIMode, lSNI, lTrustedStore, lECHConfig);
        try
          lClient.Run;
        finally
          lClient.Free;
        end;
      finally
        TIdStack.DecUsage;
      end;

    except
      on E: ECmdParams do
      begin
        Writeln('');
        Writeln(E.Message);
      end;

      on E: Exception do
      begin
        Writeln('');
        Writeln('Fatal Error [', E.ClassName, ']: ', E.Message);
      end;
    end;
  finally
    lOsslLoader:=nil;
    Writeln('Press Enter key to complete...');
    Readln;
  end;
end.
