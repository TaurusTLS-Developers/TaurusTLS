/// <summary>Checks configuration-owned FIPS activation in isolated runner invocations.</summary>
unit TaurusTLS.UT.Providers.FIPS;

{$I ..\Source\TaurusTLSCompilerDefines.inc}
{$I ..\Source\TaurusTLSLinkDefines.inc}

interface

uses
  DUnitX.TestFramework, TaurusTLS.UT.Providers.Common;

type
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  /// <summary>
  /// Real-provider integration: activation/selection, provider identity,
  /// digest/HMAC vectors, policy rejection, self-tests, reload and invalid configs.
  /// Each case runs alone in a fresh invocation of TaurusTLS.UT.Providers.
  /// </summary>
  /// <remarks>
  /// Requires -fmc:installed-fipsmodule.cnf, matching dynamic libraries and
  /// fips/legacy modules under the config directory/ossl-modules. Without -fmc,
  /// each provider case fails with an actionable prerequisite message.
  /// Select one named scenario in a fresh process. Installed data is read-only.
  /// </remarks>
  [Category('FIPS.Provider')]
  [TestFixture('', 'Checks real FIPS selection, native provider identity, digest/HMAC vectors, rejection, self-tests, reload, omitted activation and invalid configurations. '
    + 'Requires -fmc:installed-fipsmodule.cnf, matching libraries via -osp:, and fips/legacy modules under the config directory/ossl-modules. '
    + 'Missing -fmc fails with a prerequisite message. Use -scenario:<name> to run one case per process. Installed data remains read-only.')]
  TConfiguredFIPSProviderFixture = class(TProviderTestFixture)
  private type
    TFIPSProviderConfig = (fcInstalled, fcInactive, fcWrongSection, fcMissingMAC,
      fcInvalidMAC, fcMissingInclude, fcMalformedInclude);
  private
    FInstalledConfigText: string;
    function CreateProviderConfig(const ASelected: Boolean;
      const AVariant: TFIPSProviderConfig = fcInstalled): string;
    procedure LoadConfigured(const ASelected: Boolean);
    procedure CheckUnavailableFIPS(const ASelected: Boolean);
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
    [TestCase('OrdinarySelection', 'False')]
    [TestCase('FIPSSelection', 'True')]
    procedure Provider_NotActivated(const ASelected: Boolean);
    [TestCase('WrongSection', '0')]
    [TestCase('MissingModuleMAC', '1')]
    [TestCase('InvalidModuleMAC', '2')]
    [TestCase('MissingInclude', '3')]
    [TestCase('MalformedInclude', '4')]
    procedure Config_InvalidFIPS(const ACase: Integer);
  end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
type
  [TestFixture]
  [Category('FIPS.Provider')]
  TProviderMissingFIPSFixture = class(TProviderTestFixture)
  public
    [Test]
    procedure Config_MissingFIPSModule;
  end;
{$ENDIF}

implementation

uses
  System.SysUtils, System.Classes, System.IOUtils,
  IdFIPS, IdGlobal, IdCTypes,
  TaurusTLSLoader, TaurusTLSExceptionHandlers,
  TaurusTLSHeaders_crypto, TaurusTLSHeaders_evp, TaurusTLSHeaders_types,
  TaurusTLSHeaders_err, TaurusTLSHeaders_provider, TaurusTLSHeaders_core,
  TaurusTLSIdFIPS, TaurusTLSIdNTLM;

function BytesHex(const ABytes: TIdBytes): string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to Length(ABytes) - 1 do
    Result := Result + IntToHex(ABytes[I], 2);
end;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
function ConfigPath(const APath: string): string;
begin
  Result := StringReplace(TPath.GetFullPath(APath), '\', '/', [rfReplaceAll]);
  if Pos('"', Result) <> 0 then
    raise EArgumentException.Create('OpenSSL test paths cannot contain a double quote');
end;

function TConfiguredFIPSProviderFixture.CreateProviderConfig(const ASelected: Boolean;
  const AVariant: TFIPSProviderConfig): string;
var
  LDirectory, LFIPS, LLegacy, LSelection, LInclude, LValue: string;
  LLines: TStringList;
  I: Integer;
  LChanged: Boolean;
begin
  if InstalledFIPSConfig = '' then
    Assert.Fail('FIPS.Provider requires -fmc:<installed fipsmodule.cnf>, matching libraries via -osp:, and fips/legacy modules in ossl-modules. Use -scenario:<name> in TaurusTLS.UT.Providers.');
  Assert.IsFalse(Loader.IsLoaded, 'The provider fixture must start with an unloaded native runtime');
  Assert.IsTrue(TFile.Exists(InstalledFIPSConfig), 'Installed FIPS config is required');
  LDirectory := TPath.GetDirectoryName(InstalledFIPSConfig);
{$IFDEF MSWINDOWS}
  LFIPS := TPath.Combine(LDirectory, 'ossl-modules\fips.dll');
  LLegacy := TPath.Combine(LDirectory, 'ossl-modules\legacy.dll');
{$ELSE}
  LFIPS := TPath.Combine(TPath.Combine(LDirectory, 'ossl-modules'), 'fips.so');
  LLegacy := TPath.Combine(TPath.Combine(LDirectory, 'ossl-modules'), 'legacy.so');
{$ENDIF}
  Assert.IsTrue(TFile.Exists(LFIPS), 'Matching installed FIPS module is required');
  Assert.IsTrue(TFile.Exists(LLegacy), 'Matching legacy module is required for policy rejection tests');
  FInstalledConfigText := TFile.ReadAllText(InstalledFIPSConfig);
  LInclude := InstalledFIPSConfig;
  if AVariant <> fcInstalled then
  begin
    LInclude := TPath.Combine(FTempDir, 'installed-fips-copy.cnf');
    if AVariant <> fcMissingInclude then
    begin
      LLines := TStringList.Create;
      try
        LLines.Text := FInstalledConfigText;
        LChanged := False;
        for I := LLines.Count - 1 downto 0 do
        begin
          if (AVariant = fcInactive) and SameText(Trim(LLines.Names[I]), 'activate') then
          begin
            LLines.Delete(I); // Omit instead of activate=0 for older OpenSSL.
            LChanged := True;
          end
          else if (AVariant = fcWrongSection) and
            SameText(Trim(LLines[I]), '[fips_sect]') then
          begin
            LLines[I] := '[incorrect_fips_sect]';
            LChanged := True;
          end
          else if (AVariant in [fcMissingMAC, fcInvalidMAC]) and
            SameText(Trim(LLines.Names[I]), 'module-mac') then
          begin
            if AVariant = fcMissingMAC then
              LLines.Delete(I)
            else
            begin
              LValue := Trim(Copy(LLines[I], Pos('=', LLines[I]) + 1, MaxInt));
              Assert.IsNotEmpty(LValue, 'Installed module MAC must be present before constructing a corrupted copy');
              if LValue[1] = '0' then
                LValue[1] := '1'
              else
                LValue[1] := '0';
              LLines[I] := 'module-mac = ' + LValue;
            end;
            LChanged := True;
          end;
        end;
        if AVariant = fcMalformedInclude then
        begin
          LLines.Text := '[fips_sect' + sLineBreak + '= invalid';
          LChanged := True;
        end;
        Assert.IsTrue(LChanged, 'The temporary configuration must contain the requested deliberate defect');
        // OpenSSL configuration parsing does not accept a UTF-8 BOM.
        TFile.WriteAllBytes(LInclude, TEncoding.UTF8.GetBytes(LLines.Text));
      finally
        LLines.Free;
      end;
    end;
  end;
  if ASelected then
    LSelection := 'fips=yes'
  else
    LSelection := '';
  Result := CreateTempConfigFile(
    'config_diagnostics = 1' + sLineBreak +
    'openssl_conf = fips_test_init' + sLineBreak +
    '.include "' + ConfigPath(LInclude) + '"' + sLineBreak +
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
end;

procedure TConfiguredFIPSProviderFixture.LoadConfigured(const ASelected: Boolean);
begin
  Loader.ConfigFile := CreateProviderConfig(ASelected);
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
  Assert.AreEqual(FInstalledConfigText, TFile.ReadAllText(InstalledFIPSConfig),
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

procedure TConfiguredFIPSProviderFixture.CheckUnavailableFIPS(const ASelected: Boolean);
begin
  Assert.IsTrue(Loader.IsLoaded, 'A nonfatal provider failure must leave native libraries ready');
  Assert.AreEqual(0, OSSL_PROVIDER_available(nil, 'fips'),
    'An inactive or invalidly configured FIPS provider must remain unavailable');
  Assert.IsFalse(IdFIPS.GetFIPSMode(),
    'Inactive or invalid FIPS configuration must not report operational FIPS support');
  Assert.IsFalse(IdFIPS.SetFIPSMode(True),
    'The compatibility setter must not activate or repair an unavailable provider');
  Assert.AreEqual(not ASelected, IdFIPS.SetFIPSMode(False),
    'Only an already unselected policy may accept a no-op disable request');
  Assert.AreEqual(Integer(Ord(ASelected)), EVP_default_properties_is_fips_enabled(nil),
    'Queries and setter requests must preserve the fixture-selected native policy');
  if ASelected then
  begin
    Assert.IsFalse(IdFIPS.IsSHA256HashIntfAvail(),
      'Unavailable selected FIPS must not fall back to the default SHA256 implementation');
    Assert.IsFalse(IdFIPS.IsHMACSHA256Avail(),
      'Unavailable selected FIPS must not fall back to ordinary HMAC-SHA256');
    Assert.IsFalse(IdFIPS.IsNTLMFuncsAvail(),
      'Selected FIPS must reject NTLM despite the active legacy provider');
    Assert.WillRaise(
      procedure
      begin
        IdFIPS.GetSHA256HashInst();
      end, ETaurusTLSSHA256NotFound,
      'SHA256 creation must reject unavailable selected FIPS instead of weakening properties');
    Assert.WillRaise(
      procedure
      begin
        IdFIPS.GetHMACSHA256HashInst(nil);
      end, ETaurusTLSSHA256NotFound,
      'HMAC creation must reject unavailable selected FIPS instead of weakening properties');
  end
  else
  begin
    Assert.IsTrue(IdFIPS.IsSHA256HashIntfAvail(),
      'An unselected inactive FIPS provider must leave ordinary SHA256 usable');
    Assert.IsTrue(IdFIPS.IsHMACSHA256Avail(),
      'An unselected inactive FIPS provider must leave ordinary HMAC-SHA256 usable');
    Assert.IsTrue(IdFIPS.IsNTLMFuncsAvail(),
      'Inactive FIPS must leave configured legacy NTLM algorithms usable');
  end;
  Assert.AreEqual(0, OSSL_PROVIDER_available(nil, 'fips'),
    'Availability and operation checks must not implicitly activate the FIPS provider');
end;

procedure TConfiguredFIPSProviderFixture.Provider_NotActivated(const ASelected: Boolean);
begin
  Loader.ConfigFile := CreateProviderConfig(ASelected, fcInactive);
  try
    Assert.IsTrue(Loader.Load,
      'A valid installed FIPS configuration without activation must load successfully');
    Assert.AreEqual(1, OSSL_PROVIDER_available(nil, 'legacy'),
      'Legacy must be active to distinguish policy rejection from missing legacy algorithms');
    CheckUnavailableFIPS(ASelected);
  finally
    CheckInstalledConfigUnchanged;
  end;
end;

procedure TConfiguredFIPSProviderFixture.Config_InvalidFIPS(const ACase: Integer);
var
  LVariant: TFIPSProviderConfig;
  LConfig: string;
  LRejected: Boolean;
begin
  case ACase of
    0: LVariant := fcWrongSection;
    1: LVariant := fcMissingMAC;
    2: LVariant := fcInvalidMAC;
    3: LVariant := fcMissingInclude;
    4: LVariant := fcMalformedInclude;
  else
    raise EArgumentException.Create('Unknown invalid FIPS configuration test case');
  end;
  LConfig := CreateProviderConfig(True, LVariant);
  Loader.ConfigFile := LConfig;
  LRejected := False;
  try
    try
      Assert.IsTrue(Loader.Load,
        'Nonfatal provider configuration failure may leave native libraries ready');
    except
      on E: ETaurusTLSConfigFileLoadError do
      begin
        LRejected := True;
        Assert.IsTrue(Pos(LConfig, E.Message) > 0,
          'A fatal included-configuration error must identify the selected wrapper file');
      end;
    end;
    if LVariant = fcMalformedInclude then
      Assert.IsTrue(LRejected,
        'Malformed included FIPS configuration must raise a typed configuration-load error');
    if LRejected then
    begin
      Assert.IsTrue(Loader.State = lsLoadedFailed,
        'Fatal FIPS configuration failure must publish the failed loader state');
      Assert.IsFalse(IdFIPS.GetFIPSMode(),
        'Failed FIPS configuration must not advertise operational FIPS support');
      Assert.IsFalse(IdFIPS.SetFIPSMode(True),
        'FIPS enabling requests must not recover or reset a failed runtime');
      Assert.IsFalse(IdFIPS.IsSHA256HashIntfAvail(),
        'A failed runtime must not advertise digest availability');
      Assert.IsFalse(IdFIPS.IsHMACSHA256Avail(),
        'A failed runtime must not advertise HMAC availability');
      Assert.IsFalse(Loader.Load,
        'Invalid FIPS configuration must retain failed-state retry blocking until explicit reset');
      Assert.WillRaise(
        procedure
        begin
          IdFIPS.GetSHA256HashInst();
        end, ETaurusTLSLoaderError,
        'Digest creation after fatal FIPS configuration failure must reject inactive native APIs');
    end
    else
      CheckUnavailableFIPS(True);
  finally
    CheckInstalledConfigUnchanged;
  end;
end;

{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure TProviderMissingFIPSFixture.Config_MissingFIPSModule;
var
  LConfig, LModule: string;
  LRejected: Boolean;
begin
  LConfig := TPath.Combine(FTempDir, 'missing_fips_module.cnf');
  LModule := StringReplace(TPath.Combine(FTempDir, 'missing-fips-module'), '\', '/', [rfReplaceAll]);
  TFile.WriteAllBytes(LConfig, TEncoding.UTF8.GetBytes(
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
    'default_properties = fips=yes' + sLineBreak));
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

initialization
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  TDUnitX.RegisterTestFixture(TConfiguredFIPSProviderFixture);
  TDUnitX.RegisterTestFixture(TProviderMissingFIPSFixture);
{$ENDIF}
end.
