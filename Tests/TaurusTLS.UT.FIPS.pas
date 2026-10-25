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
    /// <summary>Hook reinstall replaces another backend without implicitly loading it.</summary>
    [TestCase('NotLoaded', '0')]
    [TestCase('Ready', '1')]
    procedure Hash_Reinstall(const AReady: Integer);
    /// <summary>Hash/FIPS setup must leave all NTLM callbacks owned by their backend.</summary>
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
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    [Test]
    procedure Config_MissingFIPSModule;
{$ENDIF}
  end;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  /// <summary>
  /// Real-provider integration: activation/selection, provider identity,
  /// digest/HMAC vectors, policy rejection, self-tests and reload.
  /// </summary>
  /// <remarks>
  /// Requires -fmc:installed-fipsmodule.cnf, matching dynamic libraries and
  /// fips/legacy modules under the config directory/ossl-modules. Without -fmc,
  /// each provider case fails with an actionable prerequisite message.
  /// Run category FIPS.Provider alone in a fresh process. Installed data is read-only.
  /// </remarks>
  [Category('FIPS.Provider')]
  [TestFixture('', 'Checks real FIPS selection, native provider identity, digest/HMAC vectors, rejection, self-tests and reload. '
    + 'Requires -fmc:installed-fipsmodule.cnf, matching libraries via -osp:, and fips/legacy modules under the config directory/ossl-modules. '
    + 'Missing -fmc fails with a prerequisite message. Run FIPS.Provider alone, or explicitly exclude the category. Installed data remains read-only.')]
  TConfiguredFIPSProviderFixture = class(TLoaderBaseFixture)
  private
    FInstalledConfigText: string;
    procedure LoadConfigured(const ASelected: Boolean);
    procedure CheckInstalledConfigUnchanged;
  public
    [TestCase('AvailableNotSelected', 'False')]
    [TestCase('Selected', 'True')]
    procedure Mode_ReflectsSelection(const ASelected: Boolean);
    [Test]
    procedure Digest_UsesFIPS;
    [TestCase('SHA256', '0,B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7')]
    [TestCase('SHA384', '1,AFD03944D84895626B0825F4AB46907F15F9DADBE4101EC682AA034C7CEBC59CFAEA9EA9076EDE7F4AF152E8B2FA9CB6')]
    [TestCase('SHA512', '2,87AA7CDEA5EF619D4FF0B4241A1D6CB02379F4E2CE4EC2787AD0B30545E17CDEDAA833B7D6B8A702038B274EAEA3F4E4BE9D914EEB61F1702E696C203A126854')]
    procedure HMAC_UsesFIPS(const AAlgorithm: Integer; const AExpected: string);
    [Test]
    procedure Policy_RejectsLegacyNTLM;
    [Test]
    procedure Provider_SelfTest;
    [Test]
    procedure Lifecycle_Reload;
  end;
{$ENDIF}

implementation

uses
  System.SysUtils,
  System.IOUtils,
  DUnitX.CommandLine.Options,
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
  TaurusTLSFIPS;

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
  InstallFIPSHooks;
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
  InstallFIPSHooks;
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
  InstallFIPSHooks;
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

procedure TLoaderFIPSReadinessFixture.Hash_Reinstall(const AReady: Integer);
var
  LSavedHook: TLoadHashLibrary;
begin
  Loader.ConfigFile := FValidConfigFile;
  if AReady <> 0 then
    Assert.IsTrue(Loader.Load, 'Controlled OpenSSL initialization must succeed before exercising Hash Reinstall');
  LSavedHook := IdFIPS.LoadHashLibrary;
  try
    IdFIPS.LoadHashLibrary := UnexpectedHashLoader;
    InstallFIPSHooks;
    Assert.AreEqual(AReady <> 0, IdHash.HashFunctionsLoaded,
      'Reinstalled Indy hash readiness must match the fixture loader state');
    Assert.IsTrue(Loader.IsLoaded = (AReady <> 0),
      'Installing hooks must preserve the requested loaded or unloaded state');
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
begin
  Loader.ConfigFile := FValidConfigFile;
  if AReady <> 0 then
    Assert.IsTrue(Loader.Load, 'Controlled OpenSSL initialization must succeed before exercising Hash PreservesNTLM');
  LSavedLoad := IdFIPS.LoadNTLMLibrary;
  LSavedAvailable := IdFIPS.IsNTLMFuncsAvail;
  LSavedLM := IdFIPS.NTLMGetLmChallengeResponse;
  LSavedNT := IdFIPS.NTLMGetNtChallengeResponse;
  try
    IdFIPS.LoadNTLMLibrary := UnexpectedHashLoader;
    IdFIPS.IsNTLMFuncsAvail := UnexpectedHashLoader;
    IdFIPS.NTLMGetLmChallengeResponse := nil;
    IdFIPS.NTLMGetNtChallengeResponse := nil;
    InstallFIPSHooks;
    InstallFIPSHooks;
    Assert.IsTrue(@IdFIPS.LoadNTLMLibrary = @UnexpectedHashLoader,
      'Installing FIPS hooks must preserve the foreign NTLM loading callback');
    Assert.IsTrue(@IdFIPS.IsNTLMFuncsAvail = @UnexpectedHashLoader,
      'Installing FIPS hooks must preserve the foreign NTLM availability callback');
    Assert.IsFalse(Assigned(IdFIPS.NTLMGetLmChallengeResponse),
      'Installing FIPS hooks must leave an unassigned LM response callback untouched');
    Assert.IsFalse(Assigned(IdFIPS.NTLMGetNtChallengeResponse),
      'Installing FIPS hooks must leave an unassigned NT response callback untouched');
    Assert.IsTrue(Loader.IsLoaded = (AReady <> 0),
      'Installing hooks must preserve the requested loaded or unloaded state');
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
  InstallFIPSHooks;
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
  InstallFIPSHooks;
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
  InstallFIPSHooks;
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
  InstallFIPSHooks;
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
  InstallFIPSHooks;
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
  InstallFIPSHooks;
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
  InstallFIPSHooks;
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
  InstallFIPSHooks;
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
procedure TLoaderFIPSReadinessFixture.Config_MissingFIPSModule;
var
  LConfig, LModule: string;
  LRejected: Boolean;
begin
  InstallFIPSHooks;
  LConfig := TPath.Combine(FTempDir, 'missing_fips_module.cnf');
  LModule := StringReplace(TPath.Combine(FTempDir, 'missing-fips-module'), '\', '/', [rfReplaceAll]);
  TFile.WriteAllText(LConfig,
    'config_diagnostics = 1' + sLineBreak +
    'openssl_conf = init' + sLineBreak +
    '[init]' + sLineBreak +
    'providers = providers' + sLineBreak +
    'alg_section = algorithms' + sLineBreak +
    '[providers]' + sLineBreak +
    'fips = missing_fips' + sLineBreak +
    '[missing_fips]' + sLineBreak +
    'module = "' + LModule + '"' + sLineBreak +
    'activate = 1' + sLineBreak +
    '[algorithms]' + sLineBreak +
    'default_properties = fips=yes' + sLineBreak, TEncoding.UTF8);
  Loader.ConfigFile := LConfig;
  LRejected := False;
  try
    Assert.IsTrue(Loader.Load, 'A nonfatal provider activation failure must not prevent native runtime readiness');
  except
    on E: ETaurusTLSConfigFileLoadError do
      LRejected := True;
  end;
  Assert.IsFalse(IdFIPS.GetFIPSMode(), 'An inactive or unselected FIPS runtime must not report operational FIPS mode');
  Assert.IsFalse(IdFIPS.SetFIPSMode(True),
    'A missing or inactive FIPS provider must not accept a request to enable FIPS mode');
  Assert.IsFalse(IdFIPS.SetFIPSMode(False), 'Missing FIPS must not weaken selected policy');
  if LRejected then
  begin
    Assert.IsTrue(Loader.State = lsLoadedFailed, 'A rejected configuration must leave the loader in failed state');
    Assert.IsFalse(IdFIPS.LoadHashLibrary(),
      'hash loader readiness must be false when the selected native provider cannot supply it');
    Assert.IsFalse(Loader.Load, 'Failed-state retry remains blocked');
  end
  else
  begin
    // OpenSSL 4.1 treats module activation failure as nonfatal configuration.
    // Ready libraries do not prove configured providers/algorithms are usable.
    Assert.IsTrue(Loader.State = lsLoadedReady, 'The completed load must leave the native runtime ready');
    Assert.AreEqual(0, OSSL_PROVIDER_available(nil, 'fips'),
      'Queries and rejected operations must not activate the missing FIPS provider');
    Assert.AreEqual(1, EVP_default_properties_is_fips_enabled(nil),
      'Queries and operations must preserve the configured fips=yes selection');
    Assert.IsFalse(IdFIPS.IsSHA256HashIntfAvail(),
      'SHA256 hash availability must be false when the selected native provider cannot supply it');
    Assert.IsFalse(IdFIPS.IsHMACAvail(),
      'HMAC availability must be false when the selected native provider cannot supply it');
    Assert.WillRaise(
      procedure
      begin
        IdFIPS.GetSHA256HashInst();
      end, ETaurusTLSSHA256NotFound,
      'GetSHA256HashInst must reject an algorithm unavailable under the selected provider policy');
  end;
  Loader.Unload;
  Loader.ConfigFile := CreateTempConfigFile(
    'openssl_conf = init' + sLineBreak +
    '[init]' + sLineBreak + 'providers = providers' + sLineBreak +
    'alg_section = algorithms' + sLineBreak +
    '[providers]' + sLineBreak + 'default = default_sect' + sLineBreak +
    '[default_sect]' + sLineBreak + 'activate = 1' + sLineBreak +
    '[algorithms]' + sLineBreak + 'default_properties =' + sLineBreak);
  Assert.IsTrue(Loader.Load, 'Explicit reset permits corrected config');
  Assert.IsTrue(IdFIPS.IsSHA256HashIntfAvail(),
    'SHA256 hash availability must be true for the initialized fixture configuration');
end;
{$ENDIF}

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
  InstallFIPSHooks;
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

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  GInstalledFIPSConfig: string;

function ConfigPath(const APath: string): string;
begin
  Result := StringReplace(TPath.GetFullPath(APath), '\', '/', [rfReplaceAll]);
  if Pos('"', Result) <> 0 then
    raise EArgumentException.Create('OpenSSL test paths cannot contain a double quote');
end;

procedure TConfiguredFIPSProviderFixture.LoadConfigured(const ASelected: Boolean);
var
  LDirectory, LFIPS, LLegacy, LSelection, LConfig: string;
begin
  if GInstalledFIPSConfig = '' then
    Assert.Fail('FIPS.Provider requires -fmc:<installed fipsmodule.cnf>, matching libraries via -osp:, and fips/legacy modules in ossl-modules. Run -i:FIPS.Provider in a fresh process, or explicitly exclude it with -e:FIPS.Provider.');
  Assert.IsFalse(Loader.IsLoaded, 'The provider fixture must start with an unloaded native runtime');
  Assert.IsTrue(TFile.Exists(GInstalledFIPSConfig), 'Installed FIPS config is required');
  LDirectory := TPath.GetDirectoryName(GInstalledFIPSConfig);
{$IFDEF MSWINDOWS}
  LFIPS := TPath.Combine(LDirectory, 'ossl-modules\fips.dll');
  LLegacy := TPath.Combine(LDirectory, 'ossl-modules\legacy.dll');
{$ELSE}
  LFIPS := TPath.Combine(TPath.Combine(LDirectory, 'ossl-modules'), 'fips.so');
  LLegacy := TPath.Combine(TPath.Combine(LDirectory, 'ossl-modules'), 'legacy.so');
{$ENDIF}
  Assert.IsTrue(TFile.Exists(LFIPS), 'Matching installed FIPS module is required');
  Assert.IsTrue(TFile.Exists(LLegacy), 'Matching legacy module is required for policy rejection tests');
  FInstalledConfigText := TFile.ReadAllText(GInstalledFIPSConfig);
  if ASelected then
    LSelection := 'fips=yes'
  else
    LSelection := '';
  LConfig := CreateTempConfigFile(
    'config_diagnostics = 1' + sLineBreak +
    'openssl_conf = fips_test_init' + sLineBreak +
    '.include "' + ConfigPath(GInstalledFIPSConfig) + '"' + sLineBreak +
    '[fips_test_init]' + sLineBreak +
    'providers = fips_test_providers' + sLineBreak +
    'alg_section = fips_test_algorithms' + sLineBreak +
    '[fips_test_providers]' + sLineBreak +
    'default = fips_test_default' + sLineBreak +
    'base = fips_test_base' + sLineBreak +
    'fips = fips_sect' + sLineBreak +
    'legacy = fips_test_legacy' + sLineBreak +
    '[fips_test_default]' + sLineBreak +
    'activate = 1' + sLineBreak +
    '[fips_test_base]' + sLineBreak +
    'activate = 1' + sLineBreak +
    '[fips_sect]' + sLineBreak +
    'module = "' + ConfigPath(LFIPS) + '"' + sLineBreak +
    '[fips_test_legacy]' + sLineBreak +
    'module = "' + ConfigPath(LLegacy) + '"' + sLineBreak +
    'activate = 1' + sLineBreak +
    '[fips_test_algorithms]' + sLineBreak +
    'default_properties = ' + LSelection + sLineBreak, 'fips-provider-test.cnf');
  Loader.ConfigFile := LConfig;
  Assert.IsTrue(Loader.Load, 'Configured FIPS runtime initialization must succeed');
  Assert.AreEqual(1, OSSL_PROVIDER_available(nil, 'fips'),
    'The installed configuration must leave the FIPS provider active');
  Assert.AreEqual(1, OSSL_PROVIDER_available(nil, 'legacy'),
    'Legacy must remain active so rejection tests exercise FIPS policy');
  Assert.AreEqual(Integer(Ord(ASelected)), EVP_default_properties_is_fips_enabled(nil),
    'Native FIPS selection must match the fixture configuration after hook calls');
end;

procedure TConfiguredFIPSProviderFixture.CheckInstalledConfigUnchanged;
begin
  Assert.AreEqual(FInstalledConfigText, TFile.ReadAllText(GInstalledFIPSConfig),
    'Tests must preserve installed FIPS integrity and policy data');
end;

procedure TConfiguredFIPSProviderFixture.Mode_ReflectsSelection(const ASelected: Boolean);
begin
  LoadConfigured(ASelected);
  Assert.AreEqual(ASelected, IdFIPS.GetFIPSMode(),
    'Provider availability alone must not imply selected FIPS mode');
  Assert.IsTrue(IdFIPS.SetFIPSMode(ASelected), 'Matching policy request is a no-op');
  Assert.IsFalse(IdFIPS.SetFIPSMode(not ASelected), 'Changing policy is refused');
  Assert.AreEqual(Integer(Ord(ASelected)), EVP_default_properties_is_fips_enabled(nil),
    'Native FIPS selection must match the fixture configuration after hook calls');
  Assert.AreEqual(1, OSSL_PROVIDER_available(nil, 'fips'),
    'The installed configuration must leave the FIPS provider active');
  CheckInstalledConfigUnchanged;
end;

procedure TConfiguredFIPSProviderFixture.Digest_UsesFIPS;
var
  LContext: TIdHashIntCtx;
  LExpectedMethod: PEVP_MD;
  LResult: TIdBytes;
begin
  LoadConfigured(True);
  Assert.IsTrue(IdFIPS.IsSHA256HashIntfAvail(),
    'SHA256 hash availability must be true for the initialized fixture configuration');
  LExpectedMethod := EVP_MD_fetch(nil, 'SHA256', 'provider=fips');
  try
    Assert.IsTrue(LExpectedMethod <> nil, 'An explicit provider=fips SHA256 fetch must succeed');
    LContext := IdFIPS.GetSHA256HashInst();
    try
      // OpenSSL caches fetched methods. Match the hook context to a fetch that
      // explicitly requires fips, without adding a missing header import.
      Assert.IsTrue(EVP_MD_CTX_md(LContext) = LExpectedMethod,
        'Hook digest must be the native FIPS-provider implementation');
      IdFIPS.UpdateHashInst(LContext, ToBytes('abc', IndyTextEncoding_ASCII));
    except
      EVP_MD_CTX_free(LContext);
      raise;
    end;
    LResult := IdFIPS.FinalHashInst(LContext); // Final owns/free context, even on error.
    Assert.AreEqual('BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD',
      BytesHex(LResult), 'SHA256 over abc must match the known-answer digest');
  finally
    EVP_MD_free(LExpectedMethod);
  end;
  CheckInstalledConfigUnchanged;
end;

procedure TConfiguredFIPSProviderFixture.HMAC_UsesFIPS(const AAlgorithm: Integer;
  const AExpected: string);
var
  LKey, LResult: TIdBytes;
  LContext: TIdHMACIntCtx;
  LProvider: TaurusTLSHeaders_types.POSSL_PROVIDER;
begin
  LoadConfigured(True);
  SetLength(LKey, 20);
  FillChar(LKey[0], Length(LKey), $0B);
  case AAlgorithm of
    0: LContext := IdFIPS.GetHMACSHA256HashInst(LKey);
    1: LContext := IdFIPS.GetHMACSHA384HashInst(LKey);
  else
    LContext := IdFIPS.GetHMACSHA512HashInst(LKey);
  end;
  try
    LProvider := EVP_MAC_get0_provider(EVP_MAC_CTX_get0_mac(LContext));
    Assert.IsTrue(LProvider <> nil, 'The native algorithm must expose its owning provider');
    Assert.AreEqual('fips', string(AnsiString(OSSL_PROVIDER_get0_name(LProvider))),
      'The native HMAC implementation must belong to the FIPS provider');
    IdFIPS.UpdateHMACInst(LContext, ToBytes('Hi There', IndyTextEncoding_ASCII));
  except
    EVP_MAC_CTX_free(LContext);
    raise;
  end;
  LResult := IdFIPS.FinalHMACInst(LContext);
  Assert.AreEqual(AExpected, BytesHex(LResult),
    'The selected HMAC algorithm must match its independent known-answer vector');
  Assert.AreEqual(1, EVP_default_properties_is_fips_enabled(nil),
    'Queries and operations must preserve the configured fips=yes selection');
  CheckInstalledConfigUnchanged;
end;

procedure TConfiguredFIPSProviderFixture.Policy_RejectsLegacyNTLM;
var
  LMD: PEVP_MD;
  LCipher: PEVP_CIPHER;
  LChallenge: TIdBytes;
begin
  LoadConfigured(True);
  // Legacy is deliberately active; configured FIPS selection must still win.
  Assert.IsTrue(IdFIPS.GetFIPSMode(),
    'A ready runtime with the selected installed FIPS provider must report FIPS mode');
  Assert.IsFalse(IdFIPS.IsMD4HashIntfAvail(),
    'MD4 hash availability must be false when the selected native provider cannot supply it');
  Assert.IsFalse(IdFIPS.IsNTLMFuncsAvail(),
    'NTLM function availability must be false when the selected native provider cannot supply it');
  LMD := EVP_MD_fetch(nil, 'MD4', nil);
  try
    Assert.IsTrue(LMD = nil, 'Configured FIPS selection must prevent a native MD4 fetch despite active legacy');
  finally
    EVP_MD_free(LMD);
  end;
  LCipher := EVP_CIPHER_fetch(nil, 'DES-ECB', nil);
  try
    Assert.IsTrue(LCipher = nil,
      'Configured FIPS selection must prevent a native DES-ECB fetch despite active legacy');
  finally
    EVP_CIPHER_free(LCipher);
    ERR_clear_error;
  end;
  Assert.WillRaise(
    procedure
    begin
      IdFIPS.GetMD4HashInst();
    end, ETaurusTLSMD4NotFound,
    'GetMD4HashInst must reject an algorithm unavailable under the selected provider policy');
  SetLength(LChallenge, 8);
  Assert.WillRaise(
    procedure
    begin
      IdFIPS.NTLMGetNtChallengeResponse('Password', LChallenge);
    end, EIdFIPSAlgorithmNotAllowed,
    'NTLMGetNtChallengeResponse must reject the LM/NT response under selected FIPS policy');
  Assert.WillRaise(
    procedure
    begin
      IdFIPS.NTLMGetLmChallengeResponse('Password', LChallenge);
    end, EIdFIPSAlgorithmNotAllowed,
    'NTLMGetLmChallengeResponse must reject the LM/NT response under selected FIPS policy');
  Assert.IsFalse(IdFIPS.SetFIPSMode(False), 'The FIPS setter must not weaken an active configured FIPS policy');
  Assert.AreEqual(1, EVP_default_properties_is_fips_enabled(nil),
    'Queries and operations must preserve the configured fips=yes selection');
  CheckInstalledConfigUnchanged;
end;

procedure TConfiguredFIPSProviderFixture.Provider_SelfTest;
var
  LMAC: PEVP_MAC;
  LProvider: TaurusTLSHeaders_types.POSSL_PROVIDER;
begin
  LoadConfigured(True);
  LMAC := EVP_MAC_fetch(nil, 'HMAC', 'provider=fips');
  try
    Assert.IsTrue(LMAC <> nil, 'An explicit provider=fips HMAC fetch must succeed');
    LProvider := EVP_MAC_get0_provider(LMAC); // Borrowed while LMAC is alive.
    Assert.IsTrue(LProvider <> nil, 'The native algorithm must expose its owning provider');
    Assert.AreEqual(1, OSSL_PROVIDER_self_test(LProvider), 'The loaded FIPS provider must pass its native self-tests');
    Assert.IsTrue(IdFIPS.GetFIPSMode(),
      'A ready runtime with the selected installed FIPS provider must report FIPS mode');
  finally
    EVP_MAC_free(LMAC);
  end;
  CheckInstalledConfigUnchanged;
end;

procedure TConfiguredFIPSProviderFixture.Lifecycle_Reload;
var
  LGet: TGetFIPSMode;
  LSet: TSetFIPSMode;
begin
  LoadConfigured(True);
  LGet := IdFIPS.GetFIPSMode;
  LSet := IdFIPS.SetFIPSMode;
  Assert.IsTrue(IdFIPS.GetFIPSMode(),
    'A ready runtime with the selected installed FIPS provider must report FIPS mode');
  Loader.Unload;
  Assert.IsFalse(IdFIPS.GetFIPSMode(), 'An inactive or unselected FIPS runtime must not report operational FIPS mode');
  Assert.IsFalse(IdFIPS.SetFIPSMode(True),
    'A missing or inactive FIPS provider must not accept a request to enable FIPS mode');
  Assert.IsTrue(@IdFIPS.GetFIPSMode = @LGet, 'Load and unload must preserve the GetFIPSMode callback');
  Assert.IsTrue(@IdFIPS.SetFIPSMode = @LSet, 'Load and unload must preserve the SetFIPSMode callback');
  Assert.IsTrue(Loader.Load, 'Controlled OpenSSL initialization must succeed before exercising Lifecycle Reload');
  Assert.IsTrue(IdFIPS.GetFIPSMode(),
    'A ready runtime with the selected installed FIPS provider must report FIPS mode');
  Assert.IsTrue(@IdFIPS.GetFIPSMode = @LGet, 'Load and unload must preserve the GetFIPSMode callback');
  Assert.IsTrue(@IdFIPS.SetFIPSMode = @LSet, 'Load and unload must preserve the SetFIPSMode callback');
  CheckInstalledConfigUnchanged;
end;

procedure RegisterFIPSProviderOptions;
begin
  TOptionsRegistry.RegisterOption<string>('fips-module-config', 'fmc',
    'Opt in to real FIPS provider tests using installed fipsmodule.cnf; run -i:FIPS.Provider alone',
    procedure(Value: string)
    begin
      if Value = '' then
        raise EArgumentException.Create('-fmc requires an installed fipsmodule.cnf path');
      GInstalledFIPSConfig := TPath.GetFullPath(Value);
      // Fixture registration is unconditional; missing input produces prerequisite failures.
    end);
end;
{$ENDIF}

initialization
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  RegisterFIPSProviderOptions;
  TDUnitX.RegisterTestFixture(TConfiguredFIPSProviderFixture);
{$ENDIF}
  TDUnitX.RegisterTestFixture(TLoaderFIPSReadinessFixture);
  Register_SSLLoaderAction(TConsumerReadinessObserver.Action);

end.
