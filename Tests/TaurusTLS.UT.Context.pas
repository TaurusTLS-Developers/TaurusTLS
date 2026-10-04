unit TaurusTLS.UT.Context;

interface

uses
  DUnitX.TestFramework, TaurusTLS.UT.TestClasses;

type
  [TestFixture]
  [Category('Context')]
  TContextLoadFixture = class(TOsslBaseFixture)
  private
    FDir: string;
    procedure InitWith(const ARootPublicKey, ADHParamsFile: string);
    function WriteFile(const AName, AContent: string): string;
  public
    [SetupFixture]
    procedure SetupFixture;
    [TearDownFixture]
    procedure TearDownFixture;

    [Test]
    procedure DHParamsFile_Missing_Raises;
    [Test]
    procedure DHParamsFile_NotDHParams_Raises;
    [Test]
    procedure DHParamsFile_Valid_Loads;
    [Test]
    procedure RootPublicKey_Missing_Raises;
    [Test]
    procedure RootPublicKey_NotACertificate_Raises;
    [Test]
    procedure RootPublicKey_Valid_Loads;
  end;

implementation

uses
  System.SysUtils, System.IOUtils, TaurusTLS;

const
  cRootCert =
    '-----BEGIN CERTIFICATE-----'#10 +
    'MIIBXjCCAQOgAwIBAgIUfBHbW4VOb8Mf5+lsJJlgNtHfA+gwCgYIKoZIzj0EAwIw'#10 +
    'HDEaMBgGA1UEAwwRVGF1cnVzVExTIFVUIFJvb3QwIBcNMjYwOTI4MjM0MzI0WhgP'#10 +
    'MjEyNjA5MDQyMzQzMjRaMBwxGjAYBgNVBAMMEVRhdXJ1c1RMUyBVVCBSb290MFkw'#10 +
    'EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7WDFb6LPgbH/NIYlo8qJfKeiYh+kVqJO'#10 +
    'RngJ7tHI9BYr4GU8YGO9aySxK0Lm+WnI5EinReDGSK2m1ZQR3Gmv6qMhMB8wHQYD'#10 +
    'VR0OBBYEFKK70hoBrTdbV2OxwRd0N228BHZ0MAoGCCqGSM49BAMCA0kAMEYCIQCB'#10 +
    'GfPq1CkgMslJqqEJZF6bavhjng04I1qQukoPqJaIdgIhAORatv6kybfcnF4GUDWx'#10 +
    'mMPDi486whoidrKba7zdXEtX'#10 +
    '-----END CERTIFICATE-----'#10;

  // RFC 7919 ffdhe2048
  cDHParams =
    '-----BEGIN DH PARAMETERS-----'#10 +
    'MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz'#10 +
    '+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a'#10 +
    '87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7'#10 +
    'YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi'#10 +
    '7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD'#10 +
    'ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg=='#10 +
    '-----END DH PARAMETERS-----'#10;

  cGarbage = 'this is not PEM data'#10;

{ TContextLoadFixture }

procedure TContextLoadFixture.SetupFixture;
begin
  inherited;
  FDir := TPath.Combine(TPath.GetTempPath, 'TaurusTLS.UT.Context.' +
    TGUID.NewGuid.ToString);
  TDirectory.CreateDirectory(FDir);
end;

procedure TContextLoadFixture.TearDownFixture;
begin
  if TDirectory.Exists(FDir) then
    TDirectory.Delete(FDir, True);
  inherited;
end;

procedure TContextLoadFixture.InitWith(const ARootPublicKey,
  ADHParamsFile: string);
begin
  var LCtx := TTaurusTLSContext.Create;
  try
    LCtx.UseSystemRootCACertificateStore := False;
    LCtx.RootPublicKey := ARootPublicKey;
    LCtx.DHParamsFile := ADHParamsFile;
    LCtx.InitContext(sslCtxServer);
    Assert.IsNotNull(LCtx.Context);
  finally
    LCtx.Free;
  end;
end;

function TContextLoadFixture.WriteFile(const AName, AContent: string): string;
begin
  Result := TPath.Combine(FDir, AName);
  TFile.WriteAllText(Result, AContent, TEncoding.ASCII);
end;

procedure TContextLoadFixture.RootPublicKey_Missing_Raises;
begin
  var LFile := TPath.Combine(FDir, 'missing-root.pem');
  Assert.WillRaise(
    procedure
    begin
      InitWith(LFile, '');
    end, ETaurusTLSLoadingRootCertError);
end;

procedure TContextLoadFixture.RootPublicKey_NotACertificate_Raises;
begin
  var LFile := WriteFile('garbage-root.pem', cGarbage);
  Assert.WillRaise(
    procedure
    begin
      InitWith(LFile, '');
    end, ETaurusTLSLoadingRootCertError);
end;

procedure TContextLoadFixture.RootPublicKey_Valid_Loads;
begin
  var LFile := WriteFile('root.pem', cRootCert);
  Assert.WillNotRaiseAny(
    procedure
    begin
      InitWith(LFile, '');
    end);
end;

procedure TContextLoadFixture.DHParamsFile_Missing_Raises;
begin
  var LFile := TPath.Combine(FDir, 'missing-dh.pem');
  Assert.WillRaise(
    procedure
    begin
      InitWith('', LFile);
    end, ETaurusTLSLoadingDHParamsError);
end;

procedure TContextLoadFixture.DHParamsFile_NotDHParams_Raises;
begin
  var LFile := WriteFile('garbage-dh.pem', cGarbage);
  Assert.WillRaise(
    procedure
    begin
      InitWith('', LFile);
    end, ETaurusTLSLoadingDHParamsError);
end;

procedure TContextLoadFixture.DHParamsFile_Valid_Loads;
begin
  var LFile := WriteFile('dh.pem', cDHParams);
  Assert.WillNotRaiseAny(
    procedure
    begin
      InitWith('', LFile);
    end);
end;

initialization
  TDUnitX.RegisterTestFixture(TContextLoadFixture);

end.
