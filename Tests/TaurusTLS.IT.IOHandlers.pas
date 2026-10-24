unit TaurusTLS.IT.IOHandlers;

{$I ..\Source\TaurusTLSCompilerDefines.inc}
{$I TaurusTLSUTCompilerDefines.inc}
{$I ..\Source\TaurusTLSLinkDefines.inc}

interface

uses
  System.Classes, System.SysUtils, System.SyncObjs,
  DUnitX.TestFramework, IdTCPClient, IdTCPServer, IdContext, IdGlobal,
  IdCTypes, TaurusTLS, TaurusTLS_X509, TaurusTLSHeaders_types,
  TaurusTLS.UT.TestClasses;

type
  /// <summary>Owns a real Indy loopback pair and isolated PEM assets.</summary>
  TIOFixture = class(TOsslAutoloadFixture)
  private
    FDir, FCert, FKey, FError: string;
    FStop: TEvent;
    FGuard: TThread;
    FExpired, FVerifyError, FAlert: Integer;
    FReject: Boolean;
    FClientVer, FServerVer: Integer;
    procedure BeforeTLS(ASender: TTaurusTLSIOHandlerSocket);
    procedure Connected(AContext: TIdContext);
    procedure Execute(AContext: TIdContext);
    procedure Failed(AContext: TIdContext; AException: Exception);
    procedure Verify(ASender: TObject; const APreverify_ok: TIdC_INT;
      ACertificate: TTaurusTLSX509; const ADepth: Integer;
      const AError: TIdC_LONG; const AMsg, ADescr: string;
      var VContinue: Boolean);
    procedure Debug(ASender: TObject; const AWrite: Boolean;
      AVersion: TTaurusMsgCBVer; AContentType: TIdC_INT;
      const buf: TIdBytes; SSL: PSSL);
    procedure StopGuard;
  protected
    FServer: TIdTCPServer;
    FServerIO: TTaurusTLSServerIOHandler;
    FClient: TIdTCPClient;
    FClientIO: TTaurusTLSIOHandlerSocket;
    procedure Start(AClientVer, AServerVer: Integer; ATrust: Boolean = True);
    procedure Connect;
    procedure CheckWorker;
    procedure Exchange(const AText: string);
    procedure Reject;
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure Teardown;
  end;

  [TestFixture('',
    'Checks TLS negotiation and client reconnect with minimum TLS 1.2/1.3 and a trusted test certificate. '
    + 'Requires OpenSSL 3.x/4.x through the base fixture, IPv4 loopback, and a writable temporary directory; PEM assets are embedded.')]
  [Category('Integration,IOHandlers,Integration.Handshake')]
  TIOHandshake = class(TIOFixture)
  public
    /// <summary>Both peers negotiate within the configured minimum and TLS 1.3 maximum.</summary>
    [TestCase('MinTLS12', '12')]
    [TestCase('MinTLS13', '13')]
    procedure Handshake(AVersion: Integer);
    /// <summary>A fresh TLS session works after reusing the client and handlers.</summary>
    [TestCase('MinTLS12', '12')]
    [TestCase('MinTLS13', '13')]
    [Category('Integration,IOHandlers,Integration.Handshake,Integration.Reconnect')]
    procedure Reconnect(AVersion: Integer);
  end;

  [TestFixture('',
    'Checks bidirectional UTF-8 text and binary payloads, including empty text and 64 KiB frames, with minimum TLS 1.2/1.3. '
    + 'Requires OpenSSL 3.x/4.x through the base fixture, IPv4 loopback, and a writable temporary directory; PEM assets are embedded.')]
  [Category('Integration,IOHandlers,Integration.Transfer')]
  TIOTransfer = class(TIOFixture)
  public
    /// <summary>UTF-8 requests and distinct server responses survive TLS framing.</summary>
    [TestCase('MinTLS12', '12')]
    [TestCase('MinTLS13', '13')]
    procedure Text(AVersion: Integer);
    /// <summary>Length-framed binary data includes nulls and spans TLS records.</summary>
    [TestCase('MinTLS12Small', '12,256')]
    [TestCase('MinTLS13Small', '13,256')]
    [TestCase('MinTLS12Large', '12,65536')]
    [TestCase('MinTLS13Large', '13,65536')]
    procedure Bytes(AVersion, ASize: Integer);
  end;

  [TestFixture('',
    'Checks untrusted-certificate rejection and successful negotiation with mixed TLS 1.2/1.3 minima. Expected TLS exceptions must reach the test handlers when debugging. '
    + 'Requires OpenSSL 3.x/4.x through the base fixture, IPv4 loopback, and a writable temporary directory; PEM assets are embedded.')]
  [Category('Integration,IOHandlers,Integration.Rejection')]
  TIORejection = class(TIOFixture)
  public
    /// <summary>Peer verification rejects the untrusted self-signed certificate.</summary>
    [TestCase('BothMinTLS12', '12,12')]
    [TestCase('BothMinTLS13', '13,13')]
    [TestCase('ClientMin12ServerMin13', '12,13')]
    [TestCase('ClientMin13ServerMin12', '13,12')]
    [Category('Integration,IOHandlers,Integration.Rejection,Integration.Certificate')]
    procedure Untrusted(AClientVer, AServerVer: Integer);
    /// <summary>Different minimum versions overlap and negotiate TLS 1.3.</summary>
    [TestCase('ClientMin12ServerMin13', '12,13')]
    [TestCase('ClientMin13ServerMin12', '13,12')]
    [Category('Integration,IOHandlers,Integration.Negotiation')]
    procedure Versions(AClientVer, AServerVer: Integer);
  end;

const
  cLocalhostTldCrt =
    '-----BEGIN CERTIFICATE-----'+sLineBreak+
    'MIIBwjCCAWigAwIBAgIUefCL5hAPyR11ZJUDRzz5DHGsQBYwCgYIKoZIzj0EAwIw'+sLineBreak+
    'HDEaMBgGA1UEAwwRd3d3LmxvY2FsaG9zdC50bGQwHhcNMjYwNTE0MTczMjIzWhcN'+sLineBreak+
    'MzYwNTE0MTczMjIzWjAcMRowGAYDVQQDDBF3d3cubG9jYWxob3N0LnRsZDBZMBMG'+sLineBreak+
    'ByqGSM49AgEGCCqGSM49AwEHA0IABHCfuneqWu2lMoF+2Hij9sdlfYN5tk7BRrUB'+sLineBreak+
    'AfUra3arTImzsr8DOUvFqjmMXrjGvnEXyl8oUxBAI2YKjAM3YXijgYcwgYQwHQYD'+sLineBreak+
    'VR0OBBYEFGRWmsu9oTZKUmbFcg9v0O8zFWUjMB8GA1UdIwQYMBaAFGRWmsu9oTZK'+sLineBreak+
    'UmbFcg9v0O8zFWUjMA8GA1UdEwEB/wQFMAMBAf8wMQYDVR0RBCowKIIRd3d3Lmxv'+sLineBreak+
    'Y2FsaG9zdC50bGSCDWxvY2FsaG9zdC50bGSHBH8AAIEwCgYIKoZIzj0EAwIDSAAw'+sLineBreak+
    'RQIhAKJezDwzxqOXOwjblc5WXIpZYvsWB7+7OWGu3PsVET6xAiAxt13dh1ffXpFf'+sLineBreak+
    'tKlRxKSyH+9cc2lv0mw32ngkmY+zpA=='+sLineBreak+
    '-----END CERTIFICATE-----';

  cLocalhostTldKey =
    '-----BEGIN PRIVATE KEY-----'+sLineBreak+
    'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgbvNy3yYlcNih6Csd'+sLineBreak+
    'o8PRDEodKV03n91BYP/HkJ9FbeShRANCAARwn7p3qlrtpTKBfth4o/bHZX2DebZO'+sLineBreak+
    'wUa1AQH1K2t2q0yJs7K/AzlLxao5jF64xr5xF8pfKFMQQCNmCowDN2F4'+sLineBreak+
    '-----END PRIVATE KEY-----';


implementation

uses
  System.IOUtils, IdIOHandler, IdStack, IdStackConsts, IdException,
  TaurusTLSExceptionHandlers, TaurusTLSHeaders_ssl,
  TaurusTLSHeaders_x509_vfy, TaurusTLSHeaders_tls1,
  TaurusTLSHeaders_err, TaurusTLSHeaders_sslerr;

const
  cWait = 5000;

function IsSSLReason(ACode: TIdC_ULONG; AReason: Integer): Boolean;
begin
  Result := (ERR_GET_LIB(TIdC_INT(ACode)) = ERR_LIB_SSL) and
    (ERR_GET_REASON(TIdC_INT(ACode)) = AReason);
end;

function TLSVersion(AVersion: Integer): TTaurusTLSSSLVersion;
begin
  if AVersion = 12 then
    Result := TLSv1_2
  else if AVersion = 13 then
    Result := TLSv1_3
  else
    raise EArgumentException.Create('Expected TLS version 12 or 13');
end;

procedure TIOFixture.Setup;
begin
  CheckLoaded;
  FExpired := 0;
  FVerifyError := 0;
  FAlert := 0;
  FReject := False;
  FError := '';
  try
    FStop := TEvent.Create(nil, True, False, '');
    FDir := TPath.Combine(TPath.GetTempPath,
      'TaurusTLS_IT_IO_' + TGuid.NewGuid.ToString);
    TDirectory.CreateDirectory(FDir);
    FCert := TPath.Combine(FDir, 'server.pem');
    FKey := TPath.Combine(FDir, 'server.key');
    // This self-signed CA certificate is the explicit test trust anchor.
    // Valid 2026-05-14 through 2036-05-14. Identity matching is not tested.
    TFile.WriteAllText(FCert, cLocalhostTldCrt + sLineBreak, TEncoding.ASCII);
    TFile.WriteAllText(FKey, cLocalhostTldKey + sLineBreak, TEncoding.ASCII);
  except
    Teardown;
    raise;
  end;
end;

procedure TIOFixture.StopGuard;
begin
  if Assigned(FGuard) then
  begin
    FStop.SetEvent;
    FGuard.WaitFor;
    FreeAndNil(FGuard);
  end;
end;

procedure TIOFixture.Teardown;
begin
  // The guard never frees components. Join it before releasing its socket.
  try
    StopGuard;
    try
      if Assigned(FClient) then
        FClient.Disconnect;
    finally
      FreeAndNil(FClient);
      FClientIO := nil;
    end;
  finally
    try
      try
        if Assigned(FServer) then
          FServer.Active := False;
      finally
        FreeAndNil(FServer);
        FServerIO := nil;
      end;
    finally
      FreeAndNil(FStop);
      if (FDir <> '') and TDirectory.Exists(FDir) then
        TDirectory.Delete(FDir, True);
      FDir := '';
    end;
  end;
end;

procedure TIOFixture.BeforeTLS(ASender: TTaurusTLSIOHandlerSocket);
var
  LHandle: TIdStackSocketHandle;
begin
  StopGuard;
  FStop.ResetEvent;
  LHandle := ASender.Binding.Handle;
  // A socket timeout alone does not bound TaurusTLS WANT_READ/WRITE retries.
  // Shutdown interrupts both peers without freeing objects from this thread.
  FGuard := TThread.CreateAnonymousThread(
    procedure
    begin
      if FStop.WaitFor(cWait) = wrTimeout then
      begin
        TInterlocked.Exchange(FExpired, 1);
        try
          GStack.Disconnect(LHandle);
        except
          on E: Exception do
          begin
            TMonitor.Enter(Self);
            try
              FError := 'Deadline shutdown: ' + E.ClassName + ': ' + E.Message;
            finally
              TMonitor.Exit(Self);
            end;
          end;
        end;
      end;
    end);
  FGuard.FreeOnTerminate := False;
  FGuard.Start;
end;

procedure TIOFixture.Start(AClientVer, AServerVer: Integer; ATrust: Boolean);
begin
  FClientVer := AClientVer;
  FServerVer := AServerVer;
  FServer := TIdTCPServer.Create(nil);
  FServerIO := TTaurusTLSServerIOHandler.Create(FServer);
  FServerIO.SSLOptions.Mode := sslmServer;
  FServerIO.SSLOptions.MinTLSVersion := TLSVersion(AServerVer);
  FServerIO.SSLOptions.UseSystemRootCACertificateStore := False;
  FServerIO.SSLOptions.VerifyHostname := False;
  FServerIO.SSLOptions.VerifyMode := [];
  FServerIO.SSLOptions.UseBidirectionalShutdown := False;
  FServerIO.DefaultCert.PublicKey := FCert;
  FServerIO.DefaultCert.PrivateKey := FKey;
  FServerIO.OnDebugMessage := Debug;
  FServer.IOHandler := FServerIO;
  FServer.OnConnect := Connected;
  FServer.OnExecute := Execute;
  FServer.OnException := Failed;
  FServer.TerminateWaitTime := cWait;
  FServer.Bindings.Clear;
  with FServer.Bindings.Add do
  begin
    IPVersion := Id_IPv4;
    IP := '127.0.0.1';
    Port := 0;
  end;
  FServer.Active := True;
  Assert.IsTrue(FServer.Active, 'Loopback server did not activate');
  Assert.IsTrue(FServer.Bindings[0].Port <> 0, 'No loopback port assigned');

  FClient := TIdTCPClient.Create(nil);
  FClientIO := TTaurusTLSIOHandlerSocket.Create(FClient);
  FClientIO.SSLOptions.Mode := sslmClient;
  FClientIO.SSLOptions.MinTLSVersion := TLSVersion(AClientVer);
  FClientIO.SSLOptions.VerifyMode := [sslvrfPeer];
  FClientIO.SSLOptions.VerifyDepth := 4;
  FClientIO.SSLOptions.VerifyHostname := False;
  FClientIO.SSLOptions.UseSystemRootCACertificateStore := False;
  FClientIO.SSLOptions.UseBidirectionalShutdown := False;
  if ATrust then
    FClientIO.ClientCert.RootKey := FCert;
  FClientIO.OnBeforeConnect := BeforeTLS;
  FClientIO.OnVerifyCallback := Verify;
  FClientIO.OnDebugMessage := Debug;
  FClientIO.ReadTimeout := cWait;
  FClientIO.DefStringEncoding := IndyTextEncoding_UTF8;
  FClientIO.PassThrough := False;
  FClient.IOHandler := FClientIO;
  FClient.ConnectTimeout := cWait;
  FClient.ReadTimeout := cWait;
  FClient.Host := '127.0.0.1';
  FClient.IPVersion := Id_IPv4;
  FClient.Port := FServer.Bindings[0].Port;
end;

procedure TIOFixture.Connected(AContext: TIdContext);
var
  LIO: TTaurusTLSIOHandlerSocket;
begin
  LIO := AContext.Connection.IOHandler as TTaurusTLSIOHandlerSocket;
  LIO.ReadTimeout := cWait;
  LIO.DefStringEncoding := IndyTextEncoding_UTF8;
  // Generic TIdTCPServer does not start TLS automatically.
  LIO.PassThrough := False;
  // The greeting synchronizes server handshake completion with the test thread.
  LIO.WriteLn(IntToStr(Ord(LIO.SSLSocket.SSLProtocolVersion)));
end;

procedure TIOFixture.Execute(AContext: TIdContext);
var
  LIO: TIdIOHandler;
  LSize, I: Integer;
  LBytes: TIdBytes;
  LText: string;
begin
  LIO := AContext.Connection.IOHandler;
  case LIO.ReadByte of
    1:
      begin
        LText := LIO.ReadLn;
        if LIO.ReadLnTimedOut then
          raise EInvalidOp.Create('Server text read timed out');
        LIO.WriteLn('ACK: ' + LText);
      end;
    2:
      begin
        LSize := LIO.ReadInt32;
        if (LSize < 0) or (LSize > 65536) then
          raise EInvalidOp.Create('Invalid binary frame size');
        LIO.ReadBytes(LBytes, LSize, False);
        for I := 0 to Length(LBytes) - 1 do
          LBytes[I] := LBytes[I] xor $A5;
        LIO.Write(Int32(Length(LBytes)));
        LIO.Write(LBytes);
      end;
  else
    raise EInvalidOp.Create('Unknown loopback command');
  end;
end;

procedure TIOFixture.Failed(AContext: TIdContext; AException: Exception);
begin
  if AException is EIdConnClosedGracefully then
    Exit;
  if FReject and (AException is ETaurusTLSAcceptError) then
    Exit;
  // Require the SSL library and scenario-specific reason.
  if FReject and (AException is ETaurusTLSAPICryptoError) then
    with ETaurusTLSAPICryptoError(AException) do
      if IsSSLReason(ErrorCode, SSL_R_TLSV1_ALERT_UNKNOWN_CA) then
        Exit;
  TMonitor.Enter(Self);
  try
    if FError = '' then
      FError := AException.ClassName + ': ' + AException.Message;
  finally
    TMonitor.Exit(Self);
  end;
end;

procedure TIOFixture.Verify(ASender: TObject; const APreverify_ok: TIdC_INT;
  ACertificate: TTaurusTLSX509; const ADepth: Integer;
  const AError: TIdC_LONG; const AMsg, ADescr: string;
  var VContinue: Boolean);
begin
  if APreverify_ok = 0 then
    TInterlocked.Exchange(FVerifyError, AError);
  // Observe validation; never turn a failed verification into acceptance.
  VContinue := APreverify_ok = 1;
end;

procedure TIOFixture.Debug(ASender: TObject; const AWrite: Boolean;
  AVersion: TTaurusMsgCBVer; AContentType: TIdC_INT;
  const buf: TIdBytes; SSL: PSSL);
begin
  // TLS alert protocol_version (70), independent of OpenSSL diagnostic wording.
  if (AContentType = 21) and (Length(buf) = 2) and (buf[1] = 70) then
    TInterlocked.Exchange(FAlert, 70);
end;

procedure TIOFixture.CheckWorker;
var
  LError: string;
begin
  Assert.AreEqual(0, TInterlocked.CompareExchange(FExpired, 0, 0),
    'Loopback operation exceeded its deadline');
  TMonitor.Enter(Self);
  try
    LError := FError;
  finally
    TMonitor.Exit(Self);
  end;
  Assert.AreEqual('', LError, 'Unexpected server/guard failure');
end;

procedure TIOFixture.Connect;
var
  LGreeting: string;
  LVersion: Integer;
begin
  FClient.Connect;
  Assert.IsNotNull(FClientIO.SSLSocket, 'No TLS socket');
  Assert.IsFalse(FClientIO.PassThrough, 'Client remained in plaintext mode');
  LVersion := Ord(FClientIO.SSLSocket.SSLProtocolVersion);
  Assert.IsTrue(LVersion >= Ord(TLSVersion(FClientVer)),
    'Negotiated version is below the client minimum');
  Assert.IsTrue(LVersion >= Ord(TLSVersion(FServerVer)),
    'Negotiated version is below the server minimum');
  Assert.IsTrue(LVersion <= Ord(TLSv1_3),
    'Negotiated version exceeds the library maximum');
  LGreeting := FClientIO.ReadLn;
  Assert.IsFalse(FClientIO.ReadLnTimedOut, 'Server handshake greeting timed out');
  Assert.AreEqual(IntToStr(LVersion), LGreeting,
    'Peers must report the same negotiated version');
  Assert.AreEqual(0, TInterlocked.CompareExchange(FVerifyError, 0, 0),
    'Trusted certificate failed verification');
  CheckWorker;
end;

procedure TIOFixture.Exchange(const AText: string);
var
  LReply: string;
begin
  FClientIO.Write(Byte(1));
  FClientIO.WriteLn(AText);
  LReply := FClientIO.ReadLn;
  Assert.IsFalse(FClientIO.ReadLnTimedOut, 'Text response timed out');
  Assert.AreEqual('ACK: ' + AText, LReply);
  CheckWorker;
end;

procedure TIOFixture.Reject;
var
  LRejected: Boolean;
begin
  LRejected := False;
  try
    FClient.Connect;
  except
    on E: ETaurusTLSConnectError do
      LRejected := True;
    on E: ETaurusTLSAPICryptoError do
    begin
      // Accept only the intended SSL reason, never an unrelated crypto error.
      if not IsSSLReason(E.ErrorCode, SSL_R_CERTIFICATE_VERIFY_FAILED) then
        raise;
      LRejected := True;
    end;
  end;
  StopGuard;
  CheckWorker;
  Assert.IsTrue(LRejected, 'Expected TLS handshake rejection');
  // No application data is sent before the failed handshake.
end;

procedure TIOHandshake.Handshake(AVersion: Integer);
begin
  Start(AVersion, AVersion);
  Connect;
  Exchange('Handshake confirmed');
end;

procedure TIOHandshake.Reconnect(AVersion: Integer);
begin
  Start(AVersion, AVersion);
  Connect;
  Exchange('First session');
  StopGuard;
  FClient.Disconnect;
  FClientIO.PassThrough := False;
  Connect;
  Exchange('Second session');
end;

procedure TIOTransfer.Text(AVersion: Integer);
begin
  Start(AVersion, AVersion);
  Connect;
  Exchange('');
  Exchange('Hello TaurusTLS');
  Exchange('Unicode: ' + #$0394 + #$0416 + #$4E2D);
end;

procedure TIOTransfer.Bytes(AVersion, ASize: Integer);
var
  LSent, LReceived: TIdBytes;
  I, LSize: Integer;
begin
  Start(AVersion, AVersion);
  Connect;
  SetLength(LSent, ASize);
  for I := 0 to ASize - 1 do
    LSent[I] := Byte(I and $FF);
  FClientIO.Write(Byte(2));
  FClientIO.Write(Int32(ASize));
  FClientIO.Write(LSent);
  LSize := FClientIO.ReadInt32;
  Assert.AreEqual(ASize, LSize, 'Binary response length');
  FClientIO.ReadBytes(LReceived, LSize, False);
  Assert.AreEqual<Integer>(ASize, Length(LReceived));
  for I := 0 to ASize - 1 do
    if LReceived[I] <> (LSent[I] xor $A5) then
      Assert.Fail(Format('Binary response differs at byte %d', [I]));
  CheckWorker;
end;

procedure TIORejection.Untrusted(AClientVer, AServerVer: Integer);
var
  LError: Integer;
begin
  FReject := True;
  Start(AClientVer, AServerVer, False);
  Reject;
  LError := TInterlocked.CompareExchange(FVerifyError, 0, 0);
  Assert.IsTrue((LError = X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) or
    (LError = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN),
    'Rejection must be caused by the untrusted certificate');
end;

procedure TIORejection.Versions(AClientVer, AServerVer: Integer);
begin
  // Minimum versions 1.2 and 1.3 overlap under the fixed TLS 1.3 maximum.
  Start(AClientVer, AServerVer);
  Connect;
  Exchange('Overlapping protocol ranges');
end;

initialization
  TDUnitX.RegisterTestFixture(TIOHandshake);
  TDUnitX.RegisterTestFixture(TIOTransfer);
  TDUnitX.RegisterTestFixture(TIORejection);

end.
