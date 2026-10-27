unit TaurusTLS.UT.LegacyProviders;

interface

{$I ..\Source\TaurusTLSCompilerDefines.inc}
{$I ..\Source\TaurusTLSLinkDefines.inc}

uses
  DUnitX.TestFramework, TaurusTLSHeaders_types, TaurusTLS.UT.TestClasses;

type
  /// <summary>Owns temporary provider config before explicit OpenSSL loading.</summary>
  TProviderConfigFixture = class(TOsslBaseFixture)
  private
    FConfigDirectory, FOriginalPath, FOriginalConfig: string;
    FStateCaptured: Boolean;
    function LegacyModulePath: string;
    function CreateProviderConfig(const AActivate: Boolean): string;
  protected
    procedure ConfigureProviders(const AActivate: Boolean);
  public
    destructor Destroy; override;
    [SetupFixture]
    procedure SetupFixture; virtual;
    [TearDownFixture]
    procedure TearDownFixture;
  end;

  [TestFixture('', 'Checks config-activated default/legacy availability. '
    + 'Creates a temporary non-FIPS config before loading; requires a matching '
    + 'deployed module in shared builds or linked registration in archive builds.')]
  [Category('LegacyProviders,Providers.Configuration')]
  TTaurusTLSLegacyProvidersLoaderFixture = class(TProviderConfigFixture)
  public
    [Test]
    procedure TestIsLegacyProviderLoaded;
    [TestCase('Legacy Providers', 'legacy')]
    [TestCase('Default Providers', 'default')]
    procedure TestProvidersAvailability(AProviderName: string);
{$IFDEF STATICLOAD_OPENSSL}
    [Test]
    procedure StatusAfterUnload;
{$ENDIF}
  end;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  [TestFixture('', 'Checks a configured but inactive legacy module stays unavailable '
    + 'and MD4/DES cannot be fetched. Runtime-loaded shared libraries only; '
    + 'archive/startup-shared default-context absence requires fresh-process validation.')]
  [Category('LegacyProviders,Providers.NoActivation')]
  TLegacyProviderInactiveFixture = class(TProviderConfigFixture)
  public
    [SetupFixture]
    procedure SetupFixture; override;
    [Test]
    procedure LegacyIsNotActivated;
  end;
{$ENDIF}

  [TestFixture('', 'Checks default/legacy digest vectors using fixture-owned config. '
    + 'Requires matching shared provider deployment or archive registration.')]
  [Category('LegacyProviders,Providers.Configuration')]
  TTaurusTLSHashes = class(TProviderConfigFixture)
  public
    [TestCase('Provider.Legacy (MD4): ''''', 'MD4,,31d6cfe0d16ae931b73c59d7e0c089c0')]
    [TestCase('Provider.Legacy (MD4): ''abcd''', 'MD4,61626364,41decd8f579255c5200f86a4bb3ba740')]

    [TestCase('Provider.Legacy (ripemd160): ''''', 'RIPEMD160,,9c1185a5c5e9fc54612808977ee8f548b2258d31')]
    [TestCase('Provider.Legacy (ripemd160): ''abcd''', 'RIPEMD160,61626364,2e7e536fd487deaa943fda5522d917bdb9011b7a')]

    [TestCase('Provider.Legacy (whirlpool): ''''', 'WHIRLPOOL,,'+
      '19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3')]
    [TestCase('Provider.Legacy (whirlpool): ''abcd''', 'WHIRLPOOL,61626364,'+
      'bda164f0b930c43a1bacb5df880b205d15ac847add35145bf25d991ae74f0b72b1ac794f8aacda5fcb3c47038c954742b1857b5856519de4d1e54bfa2fa4eac5')]

    [TestCase('Provider.Default (SHA1): ''''', 'SHA1,,da39a3ee5e6b4b0d3255bfef95601890afd80709')]
    [TestCase('Provider.Default (SHA1): ''abcd''', 'SHA1,61626364,81fe8bfe87576c3ecb22426f8e57847382917acf')]

    [TestCase('Provider.Default (SHA256): ''''', 'SHA256,,'+
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')]
    [TestCase('Provider.Default (SHA256): ''abcd''', 'SHA256,61626364,'+
      '88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589')]
    procedure HashTestHex(const AHashName, AData, AResult: string);
  end;

implementation

uses
  System.SysUtils,
  System.IOUtils,
  IdCTypes,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_err,
  TaurusTLSHeaders_provider
{$IFDEF STATICLOAD_OPENSSL}
  , TaurusTLS_ProviderLegacy
{$ENDIF}
  ;

function TProviderConfigFixture.LegacyModulePath: string;
{$IFNDEF STATICLOAD_OPENSSL}
const
{$IFDEF MSWINDOWS}
  ModuleName = 'legacy.dll';
{$ELSE}
  {$IFDEF MACOS}
  ModuleName = 'legacy.dylib';
  {$ELSE}
  ModuleName = 'legacy.so';
  {$ENDIF}
{$ENDIF}
var
  LSubdirectories: array [0 .. 3] of string;
  LRoot, LSubdirectory, LCandidate: string;
{$ENDIF}
begin
  Result := '';
{$IFNDEF STATICLOAD_OPENSSL}
  // Prefer the module deployed with the selected native distribution.
  // Otherwise omit "module" and let OpenSSL use its standard discovery.
  if Loader.OpenSSLPath = '' then
    Exit;
  LRoot := TPath.GetFullPath(Loader.OpenSSLPath);
  LSubdirectories[0] := 'providers';
  LSubdirectories[1] := 'ossl-modules';
  LSubdirectories[2] := TPath.Combine('lib', 'ossl-modules');
  LSubdirectories[3] := '';
  for LSubdirectory in LSubdirectories do
  begin
    LCandidate := TPath.Combine(TPath.Combine(LRoot, LSubdirectory), ModuleName);
    if TFile.Exists(LCandidate) then
      Exit(LCandidate);
  end;
{$ENDIF}
end;

function TProviderConfigFixture.CreateProviderConfig(const AActivate: Boolean): string;
var
  LContent, LModule: string;
begin
  LContent :=
    'config_diagnostics = 1' + sLineBreak +
    'openssl_conf = provider_test_init' + sLineBreak +
    '[provider_test_init]' + sLineBreak +
    'providers = provider_test_providers' + sLineBreak +
    'alg_section = provider_test_properties' + sLineBreak +
    '[provider_test_providers]' + sLineBreak +
    'default = provider_test_default' + sLineBreak +
    'legacy = provider_test_legacy' + sLineBreak +
    '[provider_test_default]' + sLineBreak +
    'activate = 1' + sLineBreak +
    '[provider_test_legacy]' + sLineBreak;
  if AActivate then
    LContent := LContent + 'activate = 1' + sLineBreak;
  LModule := LegacyModulePath;
  if LModule <> '' then
  begin
    // Quote an actual filesystem path, including OpenSSL's variable/escape syntax.
    LModule := StringReplace(LModule, '\', '\\', [rfReplaceAll]);
    LModule := StringReplace(LModule, '"', '\"', [rfReplaceAll]);
    LModule := StringReplace(LModule, '$', '\$', [rfReplaceAll]);
    LModule := StringReplace(LModule, #13, '\r', [rfReplaceAll]);
    LModule := StringReplace(LModule, #10, '\n', [rfReplaceAll]);
    LContent := LContent + 'module = "' + LModule + '"' + sLineBreak;
  end;
  LContent := LContent +
    '[provider_test_properties]' + sLineBreak +
    'default_properties = ""' + sLineBreak;
  Result := TPath.Combine(FConfigDirectory, 'providers.cnf');
  TFile.WriteAllText(Result, LContent);
end;

procedure TProviderConfigFixture.ConfigureProviders(const AActivate: Boolean);
begin
  Assert.IsFalse(Loader.IsLoaded, 'Provider fixture requires exclusive loader ownership');
  FOriginalPath := Loader.OpenSSLPath;
  FOriginalConfig := Loader.ConfigFile;
  FStateCaptured := True;
  try
    Unload;
    SetupFromCmd;
    FConfigDirectory := TPath.Combine(TPath.GetTempPath,
      'TaurusTLS.Providers.' + TGUID.NewGuid.ToString);
    TDirectory.CreateDirectory(FConfigDirectory);
    Loader.ConfigFile := CreateProviderConfig(AActivate);
    Assert.IsTrue(Load, 'Cannot load OpenSSL with the generated provider configuration');
  except
    // DUnitX does not call fixture teardown after setup fails.
    try
      TearDownFixture;
    except
      on E: Exception do
        Log(TLogLevel.Error, 'Provider fixture setup cleanup: ' + E.Message);
    end;
    raise;
  end;
end;

procedure TProviderConfigFixture.TearDownFixture;
begin
  try
    if FStateCaptured then
    try
      Unload;
    finally
      try
        Loader.ConfigFile := FOriginalConfig;
      finally
        Loader.OpenSSLPath := FOriginalPath;
      end;
    end;
  finally
    FStateCaptured := False;
    if (FConfigDirectory <> '') and TDirectory.Exists(FConfigDirectory) then
      TDirectory.Delete(FConfigDirectory, True);
    FConfigDirectory := '';
  end;
end;

destructor TProviderConfigFixture.Destroy;
begin
  try
    if FStateCaptured or (FConfigDirectory <> '') then
      TearDownFixture;
  finally
    inherited Destroy;
  end;
end;

procedure TProviderConfigFixture.SetupFixture;
begin
  ConfigureProviders(True);
end;

procedure TTaurusTLSLegacyProvidersLoaderFixture.TestIsLegacyProviderLoaded;
begin
{$IFDEF STATICLOAD_OPENSSL}
  Assert.IsTrue(IsLegacyProviderLoaded);
{$ELSE}
  // Shared builds deliberately have no dependency on the legacy wrapper unit.
  Assert.AreEqual(1, OSSL_PROVIDER_available(nil, 'legacy'));
{$ENDIF}
end;

procedure TTaurusTLSLegacyProvidersLoaderFixture.TestProvidersAvailability(
  AProviderName: string);
begin
  Assert.AreEqual(1,
    OSSL_PROVIDER_available(nil, PAnsiChar(UTF8Encode(AProviderName))),
    Format('Configured provider %s is unavailable', [AProviderName]));
end;

{$IFDEF STATICLOAD_OPENSSL}
procedure TTaurusTLSLegacyProvidersLoaderFixture.StatusAfterUnload;
begin
  Assert.IsTrue(IsLegacyProviderLoaded);
  Unload;
  try
    Assert.IsFalse(IsLegacyProviderLoaded, 'Status must respect loader readiness');
  finally
    Assert.IsTrue(Load);
  end;
  Assert.IsTrue(IsLegacyProviderLoaded);
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure TLegacyProviderInactiveFixture.SetupFixture;
begin
  ConfigureProviders(False);
end;

procedure TLegacyProviderInactiveFixture.LegacyIsNotActivated;
var
  LMD: PEVP_MD;
  LCipher: PEVP_CIPHER;
begin
  Assert.AreEqual(1, OSSL_PROVIDER_available(nil, 'default'));
  Assert.AreEqual(0, OSSL_PROVIDER_available(nil, 'legacy'),
    'Listing a provider in config must not activate it without activate');
  LMD := EVP_MD_fetch(nil, 'MD4', nil);
  LCipher := nil;
  try
    LCipher := EVP_CIPHER_fetch(nil, 'DES-ECB', nil);
    Assert.IsNull(LMD, 'Inactive legacy must not supply MD4');
    Assert.IsNull(LCipher, 'Inactive legacy must not supply DES-ECB');
  finally
    EVP_MD_free(LMD);
    EVP_CIPHER_free(LCipher);
    ERR_clear_error;
  end;
end;
{$ENDIF}

procedure TTaurusTLSHashes.HashTestHex(const AHashName, AData,
  AResult: string);
begin
  var lHash: PEVP_MD:=nil;
  var lHashSize: TIdC_SIZET:=0;
  var lHashName:=UTF8Encode(AHashName);

  try
    lHash:=EVP_MD_fetch(nil, PAnsiChar(lHashName), nil);
    Assert.IsNotNull(lHash,
      Format('Unable to fetch Hash ''%s''.', [AHashName]));

    lHashSize:=EVP_MD_get_size(lHash);
    Assert.IsTrue(lHashSize > 0,
      Format('Hash hash must be positive integer, '+
      ' but the ''EVP_MD_get_size'' returns ''%d''.', [lHashSize]));

  finally
    EVP_MD_free(lHash);
  end;

  var lHashReturn: TBytes:=nil;
  SetLength(lHashReturn, lHashSize);

  var lData:=TBytes.FromHexStr(AData);
  var lResult:=TBytes.FromHexStr(AResult);

  var lActualSize: TIdC_SIZET:=0;
  Assert.AreEqual(1, EVP_Q_Digest(nil, PAnsiChar(lHashName), nil,
    PByte(lData), Length(lData), PByte(lHashReturn), @lActualSize),
    Format('OpenSSL fials to query Hash for ''%s''.', [AData]));

  Assert.AreEqual(lHashSize, lActualSize, 'Expected and Actual Hash sizes are not equal.');

  TBytesValidator.AreEqual(lResult, lHashReturn, 0, 0, lActualSize);
end;

initialization
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  TDUnitX.RegisterTestFixture(TLegacyProviderInactiveFixture);
{$ENDIF}
  TDUnitX.RegisterTestFixture(TTaurusTLSLegacyProvidersLoaderFixture);
  TDUnitX.RegisterTestFixture(TTaurusTLSHashes);
end.
