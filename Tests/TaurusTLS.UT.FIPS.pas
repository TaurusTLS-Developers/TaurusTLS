unit TaurusTLS.UT.FIPS;

{$I ..\Source\TaurusTLSCompilerDefines.inc}
{$I ..\Source\TaurusTLSLinkDefines.inc}

interface

uses
  DUnitX.TestFramework,
  TaurusTLS.UT.Loader;

type
  [TestFixture('', 'Checks passive Indy hash/HMAC availability before, during and after explicit loader initialization. '
    + 'Uses the loader fixture controlled OpenSSL configuration and native-library settings; requires no FIPS or legacy provider.')]
  [Category('Loader,Loader.Consumers')]
  TLoaderFIPSReadinessFixture = class(TLoaderBaseFixture)
  private
    procedure CheckUnavailable;
  public
    /// <summary>Availability queries leave inactive and failed loader states untouched.</summary>
    [TestCase('NotLoaded', '0')]
    [TestCase('Failed', '1')]
    [TestCase('Unloaded', '2')]
    procedure Hash_NotReady(const AState: Integer);
    /// <summary>Ready queries follow configured native algorithms across reloads.</summary>
    [Test]
    procedure Hash_Ready;
    /// <summary>Load/unload callbacks must not advertise readiness.</summary>
    [Test]
    procedure Hash_Transitions;
    /// <summary>Loader initialization and unload preserve a selected foreign hash backend.</summary>
    [TestCase('NotLoaded', '0')]
    [TestCase('Ready', '1')]
    procedure Hash_PreservesBackend(const AReady: Integer);
    /// <summary>Loader initialization and unload preserve independently owned NTLM callbacks.</summary>
    [TestCase('NotLoaded', '0')]
    [TestCase('Ready', '1')]
    procedure Hash_PreservesNTLM(const AReady: Integer);
    [Test]
    procedure Hooks_StableAcrossLifecycle;
    [TestCase('NotLoaded', '0')]
    [TestCase('Failed', '1')]
    [TestCase('Unloaded', '2')]
    procedure Operations_NotReady(const AState: Integer);
    [Test]
    procedure Mode_ConfigOwned;
    [Test]
    procedure Mode_SelectedWithoutProvider;
    [Test]
    procedure Hash_SHA256Vector;
    [TestCase('MD5', '0,5CCEC34EA9656392457FA1AC27F08FBC')]
    [TestCase('SHA1', '1,B617318655057264E28BC0B6FB378C8EF146BE00')]
    [TestCase('SHA224', '2,896FB1128ABBDF196832107CD49DF33F47B4B1169912BA4F53684B22')]
    [TestCase('SHA256', '3,B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7')]
    [TestCase('SHA384', '4,AFD03944D84895626B0825F4AB46907F15F9DADBE4101EC682AA034C7CEBC59CFAEA9EA9076EDE7F4AF152E8B2FA9CB6')]
    [TestCase('SHA512', '5,87AA7CDEA5EF619D4FF0B4241A1D6CB02379F4E2CE4EC2787AD0B30545E17CDEDAA833B7D6B8A702038B274EAEA3F4E4BE9D914EEB61F1702E696C203A126854')]
    procedure HMAC_Vectors(const AAlgorithm: Integer; const AExpected: string);
    [Test]
    procedure HMAC_EmptyKeyAndInput;
    [Test]
    procedure Probes_PreserveErrors;
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFDEF UNITTEST}
    [TestCase('DigestInit', '0')]
    [TestCase('HMACInit', '1')]
    [TestCase('DigestFinal', '2')]
    [TestCase('HMACFinal', '3')]
    procedure Operations_CleanupOnFailure(const AOperation: Integer);
{$ENDIF}
{$ENDIF}
  end;


implementation

uses
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  IdFIPS,
  IdHash,
  IdGlobal,
  IdCTypes,
  TaurusTLSLoader,
  TaurusTLSExceptionHandlers,
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_err,
  TaurusTLSHeaders_provider,
  TaurusTLSHeaders_core,
  TaurusTLS_ProviderFIPS,
  TaurusTLSIdFIPS;

type
  TConsumerReadinessObserver = class
  public
    class var Active: Boolean;
    class var LoadCount, UnloadCount: Integer;
    class var Error: string;
    class procedure Action(AAction: TOpenSSLLoadAction);
  end;

class procedure TConsumerReadinessObserver.Action(AAction: TOpenSSLLoadAction);
begin
  if not Active then
    Exit;
  try
    if IdFIPS.LoadHashLibrary() or IdFIPS.IsHashingIntfAvail() or
      IdFIPS.IsHMACAvail() or IdFIPS.IsSHA256HashIntfAvail() or
      IdFIPS.GetFIPSMode() or IdFIPS.SetFIPSMode(True) or
      IdFIPS.SetFIPSMode(False) then
      Error := 'Hash hooks reported ready during a loader transition';
    if AAction = osaLoad then
      Inc(LoadCount)
    else
      Inc(UnloadCount);
  except
    on E: Exception do
    begin
      Error := E.ClassName + ': ' + E.Message;
      raise;
    end;
  end;
end;

procedure TLoaderFIPSReadinessFixture.CheckUnavailable;
begin
  Assert.IsFalse(IdFIPS.LoadHashLibrary(), 'Hash loading hook must be status-only');
  Assert.IsFalse(IdHash.HashFunctionsLoaded, 'Indy must not invoke another loader');
  Assert.IsFalse(IdFIPS.IsHashingIntfAvail(),
    'general hash availability must be false before native runtime readiness');
  Assert.IsFalse(IdFIPS.IsHMACAvail(), 'HMAC availability must be false before native runtime readiness');
  Assert.IsFalse(IdFIPS.IsMD2HashIntfAvail(), 'MD2 hash availability must be false before native runtime readiness');
  Assert.IsFalse(IdFIPS.IsMD4HashIntfAvail(), 'MD4 hash availability must be false before native runtime readiness');
  Assert.IsFalse(IdFIPS.IsMD5HashIntfAvail(), 'MD5 hash availability must be false before native runtime readiness');
  Assert.IsFalse(IdFIPS.IsSHA1HashIntfAvail(), 'SHA1 hash availability must be false before native runtime readiness');
  Assert.IsFalse(IdFIPS.IsSHA224HashIntfAvail(),
    'SHA224 hash availability must be false before native runtime readiness');
  Assert.IsFalse(IdFIPS.IsSHA256HashIntfAvail(),
    'SHA256 hash availability must be false before native runtime readiness');
  Assert.IsFalse(IdFIPS.IsSHA384HashIntfAvail(),
    'SHA384 hash availability must be false before native runtime readiness');
  Assert.IsFalse(IdFIPS.IsSHA512HashIntfAvail(),
    'SHA512 hash availability must be false before native runtime readiness');
  Assert.IsFalse(IdFIPS.IsHMACMD5Avail(), 'HMACMD5 availability must be false before native runtime readiness');
  Assert.IsFalse(IdFIPS.IsHMACSHA1Avail(), 'HMACSHA1 availability must be false before native runtime readiness');
  Assert.IsFalse(IdFIPS.IsHMACSHA224Avail(), 'HMACSHA224 availability must be false before native runtime readiness');
  Assert.IsFalse(IdFIPS.IsHMACSHA256Avail(), 'HMACSHA256 availability must be false before native runtime readiness');
  Assert.IsFalse(IdFIPS.IsHMACSHA384Avail(), 'HMACSHA384 availability must be false before native runtime readiness');
  Assert.IsFalse(IdFIPS.IsHMACSHA512Avail(), 'HMACSHA512 availability must be false before native runtime readiness');
end;

procedure TLoaderFIPSReadinessFixture.Hash_NotReady(const AState: Integer);
var
  LState: TTaurusTLSLoaderState;
  LConfig, LDiagnostics: string;
begin
  case AState of
    1:
      begin
        Loader.ConfigFile := FInvalidSyntaxConfigFile;
        Assert.WillRaise(
          procedure
          begin
            Loader.Load;
          end, ETaurusTLSConfigFileLoadError,
          'Malformed fixture configuration must raise the typed configuration-load error');
      end;
    2:
      begin
        Loader.ConfigFile := FValidConfigFile;
        Assert.IsTrue(Loader.Load, 'Controlled OpenSSL initialization must succeed before exercising Hash NotReady');
        Loader.Unload;
      end;
  end;
  // An accidental Load would raise instead of quietly changing the state.
  LConfig := TPath.Combine(FTempDir, 'missing_consumer_config.cnf');
  Loader.ConfigFile := LConfig;
  LState := Loader.State;
  LDiagnostics := Loader.FailedToLoad.Text;
  CheckUnavailable;
  CheckUnavailable;
  Assert.IsTrue(Loader.State = LState, 'Passive or rejected hook calls must preserve the previous loader state');
  Assert.AreEqual(LConfig, Loader.ConfigFile, 'Passive availability probes must preserve the configured file path');
  Assert.AreEqual(LDiagnostics, Loader.FailedToLoad.Text,
    'Passive availability probes must preserve existing loader diagnostics');
  Assert.AreEqual('', Loader.Version, 'Inactive availability probes must leave runtime version metadata empty');
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Assert.IsFalse(Assigned(OpenSSL_version_num), 'Queries must not bind native APIs');
{$ENDIF}
  if AState = 1 then
    Assert.IsFalse(Loader.Load, 'Query must not reset failed-state retry blocking');
end;

procedure TLoaderFIPSReadinessFixture.Hash_Ready;
var
  I: Integer;
  LMethod: PEVP_MD;
  LAvailable: Boolean;
begin
  Loader.ConfigFile := FValidConfigFile;
  for I := 1 to 2 do
  begin
    Assert.IsTrue(Loader.Load, 'Controlled OpenSSL initialization must succeed before exercising Hash Ready');
    Assert.IsTrue(IdFIPS.LoadHashLibrary(),
      'hash loader readiness must be true for the initialized fixture configuration');
    Assert.IsTrue(IdHash.HashFunctionsLoaded,
      'Indy must report hash functions loaded after explicit runtime initialization');
    Assert.IsTrue(IdFIPS.IsHashingIntfAvail(),
      'general hash availability must be true for the initialized fixture configuration');
    Assert.IsTrue(IdFIPS.IsHMACAvail(), 'HMAC availability must be true for the initialized fixture configuration');
    LMethod := EVP_MD_fetch(nil, 'SHA256', nil);
    try
      LAvailable := Assigned(LMethod);
    finally
      EVP_MD_free(LMethod);
    end;
    Assert.AreEqual(LAvailable, IdFIPS.IsSHA256HashIntfAvail(),
      'Availability must use the configured native algorithm selection');
    LMethod := EVP_MD_fetch(nil, 'MD4', nil);
    try
      LAvailable := Assigned(LMethod);
    finally
      EVP_MD_free(LMethod);
    end;
    Assert.AreEqual(LAvailable, IdFIPS.IsMD4HashIntfAvail(),
      'Loader readiness must not imply MD4 availability');
    Assert.IsTrue(Loader.State = lsLoadedReady, 'The completed load must leave the native runtime ready');
    Assert.AreEqual(FValidConfigFile, Loader.ConfigFile,
      'Repeated loads and availability probes must preserve the fixture configuration');
    Loader.Unload;
    CheckUnavailable;
  end;
end;

procedure TLoaderFIPSReadinessFixture.Hash_Transitions;
begin
  TConsumerReadinessObserver.LoadCount := 0;
  TConsumerReadinessObserver.UnloadCount := 0;
  TConsumerReadinessObserver.Error := '';
  TConsumerReadinessObserver.Active := True;
  try
    Loader.ConfigFile := FValidConfigFile;
    Assert.IsTrue(Loader.Load, 'Controlled OpenSSL initialization must succeed before exercising Hash Transitions');
    Loader.Unload;
    Assert.AreEqual(1, TConsumerReadinessObserver.LoadCount,
      'The readiness observer must receive exactly one load notification');
    Assert.AreEqual(1, TConsumerReadinessObserver.UnloadCount,
      'The readiness observer must receive exactly one unload notification');
    Assert.AreEqual('', TConsumerReadinessObserver.Error,
      'No hook may advertise readiness or raise during lifecycle transitions');
  finally
    TConsumerReadinessObserver.Active := False;
  end;
end;

function UnexpectedHashLoader: Boolean;
begin
  raise Exception.Create('Indy hash loader was not replaced by TaurusTLS');
end;

procedure TLoaderFIPSReadinessFixture.Hash_PreservesBackend(const AReady: Integer);
var
  LSavedHook: TLoadHashLibrary;
begin
  Loader.ConfigFile := FValidConfigFile;
  LSavedHook := IdFIPS.LoadHashLibrary;
  try
    IdFIPS.LoadHashLibrary := UnexpectedHashLoader;
    if AReady <> 0 then
      Assert.IsTrue(Loader.Load, 'Controlled initialization must succeed with a foreign hash callback');
    Assert.IsTrue(@IdFIPS.LoadHashLibrary = @UnexpectedHashLoader,
      'Loader initialization must preserve the selected hash backend');
    Assert.AreEqual(AReady <> 0, Loader.IsLoaded,
      'Checking callback ownership must preserve the requested loader state');
    Loader.Unload;
    Assert.IsTrue(@IdFIPS.LoadHashLibrary = @UnexpectedHashLoader,
      'Loader unload must preserve the selected hash backend');
  finally
    IdFIPS.LoadHashLibrary := LSavedHook;
  end;
end;

procedure TLoaderFIPSReadinessFixture.Hash_PreservesNTLM(const AReady: Integer);
var
  LSavedLoad: TLoadNTLMLibrary;
  LSavedAvailable: TIsNTLMFuncsAvail;
  LSavedLM: TNTLMGetLmChallengeResponse;
  LSavedNT: TNTLMGetNtChallengeResponse;

  procedure CheckOwnership;
  begin
    Assert.IsTrue(@IdFIPS.LoadNTLMLibrary = @UnexpectedHashLoader,
      'Loader lifecycle must preserve the foreign NTLM loading callback');
    Assert.IsTrue(@IdFIPS.IsNTLMFuncsAvail = @UnexpectedHashLoader,
      'Loader lifecycle must preserve the foreign NTLM availability callback');
    Assert.IsFalse(Assigned(IdFIPS.NTLMGetLmChallengeResponse),
      'Loader lifecycle must leave an unassigned LM response callback untouched');
    Assert.IsFalse(Assigned(IdFIPS.NTLMGetNtChallengeResponse),
      'Loader lifecycle must leave an unassigned NT response callback untouched');
  end;

begin
  Loader.ConfigFile := FValidConfigFile;
  LSavedLoad := IdFIPS.LoadNTLMLibrary;
  LSavedAvailable := IdFIPS.IsNTLMFuncsAvail;
  LSavedLM := IdFIPS.NTLMGetLmChallengeResponse;
  LSavedNT := IdFIPS.NTLMGetNtChallengeResponse;
  try
    IdFIPS.LoadNTLMLibrary := UnexpectedHashLoader;
    IdFIPS.IsNTLMFuncsAvail := UnexpectedHashLoader;
    IdFIPS.NTLMGetLmChallengeResponse := nil;
    IdFIPS.NTLMGetNtChallengeResponse := nil;
    if AReady <> 0 then
      Assert.IsTrue(Loader.Load, 'Controlled initialization must succeed with foreign NTLM callbacks');
    CheckOwnership;
    Assert.AreEqual(AReady <> 0, Loader.IsLoaded,
      'Checking callback ownership must preserve the requested loader state');
    Loader.Unload;
    CheckOwnership;
  finally
    IdFIPS.LoadNTLMLibrary := LSavedLoad;
    IdFIPS.IsNTLMFuncsAvail := LSavedAvailable;
    IdFIPS.NTLMGetLmChallengeResponse := LSavedLM;
    IdFIPS.NTLMGetNtChallengeResponse := LSavedNT;
  end;
end;

function BytesHex(const ABytes: TIdBytes): string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to Length(ABytes) - 1 do
    Result := Result + IntToHex(ABytes[I], 2);
end;

procedure TLoaderFIPSReadinessFixture.Hooks_StableAcrossLifecycle;
var
  LGet: TGetFIPSMode;
  LSet: TSetFIPSMode;
  LHash: TGetHashInst;
  LMAC: TGetHMACInst;
  I: Integer;
begin
  LGet := IdFIPS.GetFIPSMode;
  LSet := IdFIPS.SetFIPSMode;
  LHash := IdFIPS.GetSHA256HashInst;
  LMAC := IdFIPS.GetHMACSHA256HashInst;
  Loader.ConfigFile := FValidConfigFile;
  for I := 1 to 2 do
  begin
    Assert.IsTrue(Loader.Load,
      'Controlled OpenSSL initialization must succeed before exercising Hooks StableAcrossLifecycle');
    Assert.IsTrue(@IdFIPS.GetFIPSMode = @LGet, 'Load and unload must preserve the GetFIPSMode callback');
    Assert.IsTrue(@IdFIPS.SetFIPSMode = @LSet, 'Load and unload must preserve the SetFIPSMode callback');
    Assert.IsTrue(@IdFIPS.GetSHA256HashInst = @LHash, 'Load and unload must preserve the GetSHA256HashInst callback');
    Assert.IsTrue(@IdFIPS.GetHMACSHA256HashInst = @LMAC,
      'Load and unload must preserve the GetHMACSHA256HashInst callback');
    Loader.Unload;
    Assert.IsTrue(@IdFIPS.GetFIPSMode = @LGet, 'Load and unload must preserve the GetFIPSMode callback');
    Assert.IsTrue(@IdFIPS.SetFIPSMode = @LSet, 'Load and unload must preserve the SetFIPSMode callback');
    Assert.IsTrue(@IdFIPS.GetSHA256HashInst = @LHash, 'Load and unload must preserve the GetSHA256HashInst callback');
    Assert.IsTrue(@IdFIPS.GetHMACSHA256HashInst = @LMAC,
      'Load and unload must preserve the GetHMACSHA256HashInst callback');
  end;
end;

procedure TLoaderFIPSReadinessFixture.Operations_NotReady(const AState: Integer);
var
  LState: TTaurusTLSLoaderState;
begin
  Loader.ConfigFile := FValidConfigFile;
  case AState of
    1:
      begin
        Loader.ConfigFile := FInvalidSyntaxConfigFile;
        Assert.WillRaise(
          procedure
          begin
            Loader.Load;
          end, ETaurusTLSConfigFileLoadError,
          'Malformed fixture configuration must raise the typed configuration-load error');
      end;
    2:
      begin
        Assert.IsTrue(Loader.Load,
          'Controlled OpenSSL initialization must succeed before exercising Operations NotReady');
        Loader.Unload;
      end;
  end;
  LState := Loader.State;
  Assert.IsFalse(IdFIPS.GetFIPSMode(), 'An inactive or unselected FIPS runtime must not report operational FIPS mode');
  Assert.IsFalse(IdFIPS.SetFIPSMode(True),
    'A missing or inactive FIPS provider must not accept a request to enable FIPS mode');
  Assert.IsFalse(IdFIPS.SetFIPSMode(False),
    'The FIPS setter must reject requests while the native runtime is inactive');
  Assert.WillRaise(
    procedure
    begin
      IdFIPS.GetSHA256HashInst();
    end, ETaurusTLSLoaderError, 'GetSHA256HashInst must reject calls before native runtime readiness');
  Assert.WillRaise(
    procedure
    begin
      IdFIPS.GetHMACSHA256HashInst(nil);
    end, ETaurusTLSLoaderError, 'GetHMACSHA256HashInst must reject calls before native runtime readiness');
  Assert.WillRaise(
    procedure
    begin
      IdFIPS.UpdateHashInst(nil, nil);
    end, ETaurusTLSLoaderError, 'UpdateHashInst must reject calls before native runtime readiness');
  Assert.WillRaise(
    procedure
    begin
      IdFIPS.FinalHashInst(nil);
    end, ETaurusTLSLoaderError, 'FinalHashInst must reject calls before native runtime readiness');
  Assert.WillRaise(
    procedure
    begin
      IdFIPS.UpdateHMACInst(nil, nil);
    end, ETaurusTLSLoaderError, 'UpdateHMACInst must reject calls before native runtime readiness');
  Assert.WillRaise(
    procedure
    begin
      IdFIPS.FinalHMACInst(nil);
    end, ETaurusTLSLoaderError, 'FinalHMACInst must reject calls before native runtime readiness');
  Assert.IsTrue(Loader.State = LState, 'Passive or rejected hook calls must preserve the previous loader state');
end;

procedure TLoaderFIPSReadinessFixture.Mode_ConfigOwned;
var
  LSelected: Integer;
begin
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(Loader.Load, 'Controlled OpenSSL initialization must succeed before exercising Mode ConfigOwned');
  LSelected := EVP_default_properties_is_fips_enabled(nil);
  Assert.AreEqual(0, LSelected, 'Controlled ordinary config must not select FIPS');
  Assert.IsFalse(IdFIPS.GetFIPSMode(), 'An inactive or unselected FIPS runtime must not report operational FIPS mode');
  Assert.IsFalse(IdFIPS.SetFIPSMode(True), 'Setter must not activate/select FIPS');
{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  Assert.IsFalse(IdFIPS.SetFIPSMode(False), 'Static FIPS is unsupported');
{$ELSE}
  Assert.IsTrue(IdFIPS.SetFIPSMode(False), 'Matching configured non-FIPS mode is a no-op');
{$ENDIF}
  Assert.AreEqual(LSelected, EVP_default_properties_is_fips_enabled(nil),
    'FIPS setter calls must preserve the original native policy selection');
end;

procedure TLoaderFIPSReadinessFixture.Mode_SelectedWithoutProvider;
var
  LConfig: string;
  LSelected: Integer;
begin
  LConfig := TPath.Combine(FTempDir, 'selected_fips_without_module.cnf');
  TFile.WriteAllText(LConfig,
    'openssl_conf = init' + sLineBreak +
    '[init]' + sLineBreak +
    'providers = providers' + sLineBreak +
    'alg_section = algorithms' + sLineBreak +
    '[providers]' + sLineBreak +
    'default = default_sect' + sLineBreak +
    '[default_sect]' + sLineBreak +
    'activate = 1' + sLineBreak +
    '[algorithms]' + sLineBreak +
    'default_properties = fips=yes' + sLineBreak, TEncoding.UTF8);
  Loader.ConfigFile := LConfig;
  Assert.IsTrue(Loader.Load, 'Selecting FIPS properties without a module must still initialize the native runtime');
  // This fixture activates only default, even when a fips module is installed.
  // Native default context can retain archive providers; no other fixture activates FIPS.
  LSelected := EVP_default_properties_is_fips_enabled(nil);
  try
    Assert.AreEqual(1, LSelected, 'The controlled missing-provider configuration must select fips=yes');
    Assert.AreEqual(0, OSSL_PROVIDER_available(nil, 'fips'),
      'Queries and rejected operations must not activate the missing FIPS provider');
    Assert.IsFalse(IsFIPSProviderLoaded,
      'The provider facade must report unavailable FIPS without activating it');
    Assert.IsFalse(IdFIPS.GetFIPSMode(), 'Selection alone is not operational FIPS');
    Assert.IsFalse(IdFIPS.SetFIPSMode(True),
      'A missing or inactive FIPS provider must not accept a request to enable FIPS mode');
    Assert.IsFalse(IdFIPS.SetFIPSMode(False), 'Setter must not weaken selected policy');
    Assert.AreEqual(1, EVP_default_properties_is_fips_enabled(nil),
      'Queries and operations must preserve the configured fips=yes selection');
    Assert.IsFalse(IdFIPS.IsSHA256HashIntfAvail(),
      'SHA256 hash availability must be false when the selected native provider cannot supply it');
    Assert.IsFalse(IdFIPS.IsHMACAvail(),
      'HMAC availability must be false when the selected native provider cannot supply it');
    Assert.IsFalse(IdFIPS.IsHMACSHA256Avail(),
      'HMACSHA256 availability must be false when the selected native provider cannot supply it');
    Assert.WillRaise(
      procedure
      begin
        IdFIPS.GetSHA256HashInst();
      end, ETaurusTLSSHA256NotFound,
      'GetSHA256HashInst must reject an algorithm unavailable under the selected provider policy');
    Assert.WillRaise(
      procedure
      begin
        IdFIPS.GetHMACSHA256HashInst(nil);
      end, ETaurusTLSSHA256NotFound,
      'GetHMACSHA256HashInst must reject an algorithm unavailable under the selected provider policy');
    Assert.AreEqual(1, EVP_default_properties_is_fips_enabled(nil),
      'Queries and operations must preserve the configured fips=yes selection');
    Assert.AreEqual(0, OSSL_PROVIDER_available(nil, 'fips'),
      'Queries and rejected operations must not activate the missing FIPS provider');
  finally
    // Test-owned policy only; production never toggles it. Retire it before unload.
    EVP_default_properties_enable_fips(nil, 0);
    ERR_clear_error;
  end;
end;

procedure TLoaderFIPSReadinessFixture.Hash_SHA256Vector;
var
  LContext: TIdHashIntCtx;
  LResult: TIdBytes;
begin
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(Loader.Load, 'Controlled OpenSSL initialization must succeed before exercising Hash SHA256Vector');
  LContext := IdFIPS.GetSHA256HashInst();
  IdFIPS.UpdateHashInst(LContext, ToBytes('a', IndyTextEncoding_ASCII));
  IdFIPS.UpdateHashInst(LContext, ToBytes('bc', IndyTextEncoding_ASCII));
  LResult := IdFIPS.FinalHashInst(LContext);
  Assert.AreEqual('BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD',
    BytesHex(LResult), 'SHA256 over abc must match the known-answer digest');
end;

procedure TLoaderFIPSReadinessFixture.HMAC_Vectors(const AAlgorithm: Integer;
  const AExpected: string);
var
  LKey: TIdBytes;
  LContext: TIdHMACIntCtx;
  LResult: TIdBytes;
begin
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(Loader.Load, 'Controlled OpenSSL initialization must succeed before exercising HMAC Vectors');
  SetLength(LKey, 20);
  FillChar(LKey[0], Length(LKey), $0B);
  // SHA-2 values: RFC 4231 case 1; MD5/SHA1 independently checked with Python hmac.
  case AAlgorithm of
    0: LContext := IdFIPS.GetHMACMD5HashInst(LKey);
    1: LContext := IdFIPS.GetHMACSHA1HashInst(LKey);
    2: LContext := IdFIPS.GetHMACSHA224HashInst(LKey);
    3: LContext := IdFIPS.GetHMACSHA256HashInst(LKey);
    4: LContext := IdFIPS.GetHMACSHA384HashInst(LKey);
  else
    LContext := IdFIPS.GetHMACSHA512HashInst(LKey);
  end;
  IdFIPS.UpdateHMACInst(LContext, ToBytes('Hi ', IndyTextEncoding_ASCII));
  IdFIPS.UpdateHMACInst(LContext, ToBytes('There', IndyTextEncoding_ASCII));
  LResult := IdFIPS.FinalHMACInst(LContext);
  Assert.AreEqual(AExpected, BytesHex(LResult),
    'The selected HMAC algorithm must match its independent known-answer vector');
end;

procedure TLoaderFIPSReadinessFixture.HMAC_EmptyKeyAndInput;
var
  LContext: TIdHMACIntCtx;
begin
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(Loader.Load, 'Controlled OpenSSL initialization must succeed before exercising HMAC EmptyKeyAndInput');
  LContext := IdFIPS.GetHMACSHA256HashInst(nil);
  IdFIPS.UpdateHMACInst(LContext, nil);
  Assert.AreEqual('B613679A0814D9EC772F95D778C35FC5FF1697C493715653C6C712144292C5AD',
    BytesHex(IdFIPS.FinalHMACInst(LContext)),
    'HMAC-SHA256 with an empty key and input must match the known-answer vector');
end;

procedure TLoaderFIPSReadinessFixture.Probes_PreserveErrors;
var
  LMethod: PEVP_MD;
  LFirst, LLast: TIdC_ULONG;
begin
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(Loader.Load, 'Controlled OpenSSL initialization must succeed before exercising Probes PreserveErrors');
  ERR_clear_error;
  LMethod := EVP_MD_fetch(nil, 'TaurusTLS-nonexistent-digest', nil);
  EVP_MD_free(LMethod);
  LFirst := ERR_peek_error;
  LLast := ERR_peek_last_error;
  Assert.IsTrue(LFirst <> 0, 'The fixture must seed a native error before testing error preservation');
  try
    IdFIPS.IsMD2HashIntfAvail();
    IdFIPS.IsMD4HashIntfAvail();
    IdFIPS.IsHMACMD5Avail();
    IdFIPS.IsHMACSHA256Avail();
    IdFIPS.GetFIPSMode();
    Assert.AreEqual(UInt64(LFirst), UInt64(ERR_peek_error),
      'Availability probes must preserve the oldest queued native error');
    Assert.AreEqual(UInt64(LLast), UInt64(ERR_peek_last_error),
      'Availability probes must preserve the newest queued native error');
  finally
    ERR_clear_error;
  end;
  IdFIPS.IsMD2HashIntfAvail();
  Assert.AreEqual(UInt64(0), UInt64(ERR_peek_error), 'Negative probe must not add errors');
end;


{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFDEF UNITTEST}
type
  TFreeDigest = procedure(ctx: PEVP_MD_CTX); cdecl;
  TFreeMAC = procedure(ctx: PEVP_MAC_CTX); cdecl;
  TInitDigest = function(ctx: PEVP_MD_CTX; const MD: PEVP_MD; Engine: PENGINE): TIdC_INT; cdecl;
  TInitMAC = function(ctx: PEVP_MAC_CTX; const Key: PIdAnsiChar;
    KeyLength: TIdC_SIZET; const Params: TaurusTLSHeaders_core.POSSL_PARAM_ARRAY): TIdC_INT; cdecl;
  TFinalDigest = function(ctx: PEVP_MD_CTX; Data: PByte; var Size: TIdC_UINT): TIdC_INT; cdecl;
  TFinalMAC = function(ctx: PEVP_MAC_CTX; Data: PIdAnsiChar;
    var Size: TIdC_SIZET; Capacity: TIdC_SIZET): TIdC_INT; cdecl;

var
  GFreeDigest: TFreeDigest;
  GFreeMAC: TFreeMAC;
  GFreedContexts: Integer;
  GInjectedFailureCalls: Integer;

procedure CountFreeDigest(ctx: PEVP_MD_CTX); cdecl;
begin
  Inc(GFreedContexts);
  GFreeDigest(ctx);
end;

procedure CountFreeMAC(ctx: PEVP_MAC_CTX); cdecl;
begin
  Inc(GFreedContexts);
  GFreeMAC(ctx);
end;

function FailInitDigest(ctx: PEVP_MD_CTX; const MD: PEVP_MD; Engine: PENGINE): TIdC_INT; cdecl;
begin
  Inc(GInjectedFailureCalls);
  Result := 0;
end;

function FailInitMAC(ctx: PEVP_MAC_CTX; const Key: PIdAnsiChar;
  KeyLength: TIdC_SIZET; const Params: TaurusTLSHeaders_core.POSSL_PARAM_ARRAY): TIdC_INT; cdecl;
begin
  Inc(GInjectedFailureCalls);
  Result := 0;
end;

function FailFinalDigest(ctx: PEVP_MD_CTX; Data: PByte; var Size: TIdC_UINT): TIdC_INT; cdecl;
begin
  Inc(GInjectedFailureCalls);
  Result := 0;
end;

function FailFinalMAC(ctx: PEVP_MAC_CTX; Data: PIdAnsiChar;
  var Size: TIdC_SIZET; Capacity: TIdC_SIZET): TIdC_INT; cdecl;
begin
  Inc(GInjectedFailureCalls);
  Result := 0;
end;

procedure TLoaderFIPSReadinessFixture.Operations_CleanupOnFailure(const AOperation: Integer);
var
  LInitDigest: TInitDigest;
  LInitMAC: TInitMAC;
  LFinalDigest: TFinalDigest;
  LFinalMAC: TFinalMAC;
  LContext: Pointer;
begin
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(Loader.Load,
    'Controlled OpenSSL initialization must succeed before exercising Operations CleanupOnFailure');
  GFreeDigest := EVP_MD_CTX_free;
  GFreeMAC := EVP_MAC_CTX_free;
  LInitDigest := EVP_DigestInit_ex;
  LInitMAC := EVP_MAC_init;
  LFinalDigest := EVP_DigestFinal_ex;
  LFinalMAC := EVP_MAC_final;
  GFreedContexts := 0;
  GInjectedFailureCalls := 0;
  try
    EVP_MD_CTX_free := CountFreeDigest;
    EVP_MAC_CTX_free := CountFreeMAC;
    case AOperation of
      0:
        begin
          EVP_DigestInit_ex := FailInitDigest;
          Assert.WillRaise(
            procedure
            begin
              IdFIPS.GetSHA256HashInst();
            end, ETaurusTLSAPICryptoError,
            'The injected GetSHA256HashInst failure must propagate a native crypto error');
        end;
      1:
        begin
          EVP_MAC_init := FailInitMAC;
          Assert.WillRaise(
            procedure
            begin
              IdFIPS.GetHMACSHA256HashInst(nil);
            end, ETaurusTLSAPICryptoError,
            'The injected GetHMACSHA256HashInst failure must propagate a native crypto error');
        end;
      2:
        begin
          LContext := IdFIPS.GetSHA256HashInst();
          EVP_DigestFinal_ex := FailFinalDigest;
          Assert.WillRaise(
            procedure
            begin
              IdFIPS.FinalHashInst(LContext);
            end, ETaurusTLSAPICryptoError, 'The injected FinalHashInst failure must propagate a native crypto error');
        end;
      3:
        begin
          LContext := IdFIPS.GetHMACSHA256HashInst(nil);
          EVP_MAC_final := FailFinalMAC;
          Assert.WillRaise(
            procedure
            begin
              IdFIPS.FinalHMACInst(LContext);
            end, ETaurusTLSAPICryptoError, 'The injected FinalHMACInst failure must propagate a native crypto error');
        end;
    end;
    Assert.AreEqual(1, GInjectedFailureCalls, 'Expected injected native function must execute');
    Assert.AreEqual(1, GFreedContexts, 'Failing operation must free its native context exactly once');
  finally
    EVP_MD_CTX_free := GFreeDigest;
    EVP_MAC_CTX_free := GFreeMAC;
    EVP_DigestInit_ex := LInitDigest;
    EVP_MAC_init := LInitMAC;
    EVP_DigestFinal_ex := LFinalDigest;
    EVP_MAC_final := LFinalMAC;
    ERR_clear_error;
  end;
end;
{$ENDIF}
{$ENDIF}


initialization
  TDUnitX.RegisterTestFixture(TLoaderFIPSReadinessFixture);
  Register_SSLLoaderAction(TConsumerReadinessObserver.Action);

end.
