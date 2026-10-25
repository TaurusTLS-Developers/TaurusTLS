unit TaurusTLS.UT.NTLM;

interface

{$I ..\Source\TaurusTLSCompilerDefines.inc}
{$I ..\Source\TaurusTLSLinkDefines.inc}

uses
  System.SysUtils,
  System.IOUtils,
  DUnitX.TestFramework,
  IdGlobal,
  IdCTypes,
  TaurusTLSLoader,
  TaurusTLSExceptionHandlers,
  TaurusTLS.UT.TestClasses,
  TaurusTLS.UT.Loader;

type
  [TestFixture('', 'Checks Indy NTLM readiness, configured algorithm availability, hook ownership and rejection paths. '
    + 'Uses controlled temporary OpenSSL configuration and the loader fixture native-library settings.')]
  [Category('Loader,Loader.NTLM')]
  TLoaderNTLMReadinessFixture = class(TLoaderBaseFixture)
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure Teardown;
    [Test]
    procedure Status_NotLoaded;
    [Test]
    procedure Status_Failed;
    [TestCase('SingleCycle', '1')]
    [TestCase('RepeatedCycle', '2')]
    procedure Status_LoadUnload(const ACycles: Integer);
    [TestCase('NotLoaded', '0')]
    [TestCase('Ready', '1')]
    procedure Hooks_Static(const AReady: Integer);
    [TestCase('SingleCycle', '1')]
    [TestCase('RepeatedCycle', '2')]
    procedure Hooks_KeepForeignAssignments(const ACycles: Integer);
    [TestCase('NotLoaded', '0')]
    [TestCase('Ready', '1')]
    procedure Hooks_PreserveHashAndFIPS(const AReady: Integer);
    [Test]
    procedure Hooks_PreserveMD4Policy;
    [Test]
    procedure Funcs_ReflectNativeAlgorithms;
    [Test]
    procedure Funcs_RejectNativePolicy;
    [TestCase('NotLoaded', '0')]
    [TestCase('Failed', '1')]
    procedure Responses_NotReady(const AFailed: Integer);
    [TestCase('Empty', '0')]
    [TestCase('Short', '7')]
    [TestCase('Long', '9')]
    procedure Responses_InvalidChallenge(const ALength: Integer);
  end;



  [TestFixture('', 'Checks LM/NTLMv1 known-answer responses and DES/output boundaries. '
    + 'Creates its own temporary non-FIPS config activating default and legacy, then explicitly loads/unloads OpenSSL. '
    + 'Requires a matching deployed legacy module (beside the configured library path or in OpenSSL search paths), '
    + 'or registered linked legacy code in archive builds. No external config file is required. '
    + 'LM vectors use ASCII passwords; platform-default LM encoding and 14-byte truncation are retained.')]
  [Category('NTLM')]
  TOSSLNTLMFixture = class(TOsslBaseFixture)
  private
    FConfigDirectory: string;
    FOriginalPath: string;
    FOriginalConfig: string;
    FStateCaptured: Boolean;
    function LegacyModulePath: string;
    function CreateNTLMConfig: string;
    class function HexBytes(const AHex: string): TIdBytes; static;
    class procedure AssertBytesEqual(const AExpected, AActual: TIdBytes); static;
  protected
    procedure CheckAlgorithms;
  public
    destructor Destroy; override;
    [SetupFixture]
    procedure SetupFixture;
    [TearDownFixture]
    procedure TearDownFixture;
    // Independent NTLMv1 known-answer vector (password Password, challenge below).
    [AutoNameTestCase('Password,0123456789ABCDEF,67C43011F30298A2AD35ECE64F16331C44BDBED927841F94')]
    [AutoNameTestCase(',0123456789ABCDEF,3A2EB2B1B13B01B8491AB00C070DD7E1DA0B98040B02C03F')]
    procedure NTLMResponse(APassword, AChallengeHex, AExpectedHex: string);

    [AutoNameTestCase('Password,0123456789ABCDEF,98DEF7B87F88AA5DAFE2DF779688A172DEF11C7D5CCDEF13')]
    [AutoNameTestCase(',0123456789ABCDEF,BADA4716C630D691180E163FBDD87CDE5F3231384D879388')]
    [AutoNameTestCase('12345678901234,0123456789ABCDEF,38168116ACE3F33E09EF1267EB1EDE5938DD83CC3D9CCA19')]
    [AutoNameTestCase('123456789012345678,0123456789ABCDEF,38168116ACE3F33E09EF1267EB1EDE5938DD83CC3D9CCA19')]
    procedure LMResponse(APassword, AChallengeHex, AExpectedHex: string);

    // Guards check writes around the 8-byte DES output, not input overreads.
    [AutoNameTestCase('1,1')]
    [AutoNameTestCase('4,4')]
    [AutoNameTestCase('16,16')]
    [AutoNameTestCase('1,16')]
    [AutoNameTestCase('16,1')]
    procedure DESBoundary(ALeftGuard, ARightGuard: Integer);
    [Test]
    procedure ResponseBoundary;
{$IFDEF STRING_IS_UNICODE}
    [Test]
    procedure UnicodeNTResponse;
{$ENDIF}
  end;

implementation

uses
  IdFIPS,
  IdNTLM,
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_types,
  TaurusTLS_NTLM;


type
  TNTLMHookSnapshot = record
    LoadLibrary: TLoadNTLMLibrary;
    Available: TIsNTLMFuncsAvail;
    LMResponse: TNTLMGetLmChallengeResponse;
    NTResponse: TNTLMGetNtChallengeResponse;
  end;

var
  GInitialNTLMHooks: TNTLMHookSnapshot;

function CaptureNTLMHooks: TNTLMHookSnapshot;
begin
  Result.LoadLibrary := IdFIPS.LoadNTLMLibrary;
  Result.Available := IdFIPS.IsNTLMFuncsAvail;
  Result.LMResponse := IdFIPS.NTLMGetLmChallengeResponse;
  Result.NTResponse := IdFIPS.NTLMGetNtChallengeResponse;
end;

procedure AssertNTLMHooks(const AExpected: TNTLMHookSnapshot);
begin
  Assert.IsTrue(@IdFIPS.LoadNTLMLibrary = @AExpected.LoadLibrary,
    'Loader lifecycle must not replace the NTLM loading callback');
  Assert.IsTrue(@IdFIPS.IsNTLMFuncsAvail = @AExpected.Available,
    'Loader lifecycle must not replace NTLM availability');
  Assert.IsTrue(@IdFIPS.NTLMGetLmChallengeResponse = @AExpected.LMResponse,
    'Loader lifecycle must not replace the LM response callback');
  Assert.IsTrue(@IdFIPS.NTLMGetNtChallengeResponse = @AExpected.NTResponse,
    'Loader lifecycle must not replace the NT response callback');
end;

procedure RestoreNTLMHooks(const ASaved: TNTLMHookSnapshot);
begin
  IdFIPS.LoadNTLMLibrary := ASaved.LoadLibrary;
  IdFIPS.IsNTLMFuncsAvail := ASaved.Available;
  IdFIPS.NTLMGetLmChallengeResponse := ASaved.LMResponse;
  IdFIPS.NTLMGetNtChallengeResponse := ASaved.NTResponse;
end;

type
  TNTLMReadinessObserver = class
  public
    class var Active: Boolean;
    class var LoadCount: Integer;
    class var UnloadCount: Integer;
    class var ReadyDuringLoad: Boolean;
    class var ReadyDuringUnload: Boolean;
    class var Error: string;
    class procedure Action(AAction: TOpenSSLLoadAction);
  end;

class procedure TNTLMReadinessObserver.Action(AAction: TOpenSSLLoadAction);
begin
  if not Active then
    Exit;
  try
    case AAction of
      osaLoad:
        begin
          Inc(LoadCount);
          ReadyDuringLoad := IdFIPS.LoadNTLMLibrary();
        end;
      osaUnload:
        begin
          Inc(UnloadCount);
          ReadyDuringUnload := IdFIPS.LoadNTLMLibrary();
        end;
    end;
  except
    on E: Exception do
    begin
      Error := E.ClassName + ': ' + E.Message;
      raise;
    end;
  end;
end;

{ TLoaderNTLMReadinessFixture }

procedure TLoaderNTLMReadinessFixture.Setup;
begin
  inherited Setup;
  AssertNTLMHooks(GInitialNTLMHooks);
  Assert.IsTrue(Assigned(IdFIPS.LoadNTLMLibrary), 'Indy NTLM hook must be installed');
  Assert.IsTrue(Assigned(IdFIPS.IsNTLMFuncsAvail));
  Assert.IsTrue(@IdFIPS.NTLMGetLmChallengeResponse = @SetupLanManagerPassword);
  Assert.IsTrue(@IdFIPS.NTLMGetNtChallengeResponse = @CreateNTPassword);
  TNTLMReadinessObserver.LoadCount := 0;
  TNTLMReadinessObserver.UnloadCount := 0;
  TNTLMReadinessObserver.ReadyDuringLoad := False;
  TNTLMReadinessObserver.ReadyDuringUnload := False;
  TNTLMReadinessObserver.Error := '';
  TNTLMReadinessObserver.Active := True;
end;

procedure TLoaderNTLMReadinessFixture.Teardown;
begin
  try
    inherited Teardown;
  finally
    TNTLMReadinessObserver.Active := False;
  end;
end;

procedure TLoaderNTLMReadinessFixture.Status_NotLoaded;
var
  LConfig: string;
  LDiagnostics: string;
  I: Integer;
begin
  // Loading this sentinel would raise; a passive readiness query must ignore it.
  LConfig := TPath.Combine(FTempDir, 'missing_ntlm_config.cnf');
  Loader.ConfigFile := LConfig;
  LDiagnostics := Loader.FailedToLoad.Text;
  for I := 1 to 2 do
  begin
    Assert.IsFalse(IdFIPS.LoadNTLMLibrary());
    Assert.IsFalse(IdFIPS.IsNTLMFuncsAvail());
  end;
  Assert.IsTrue(Loader.State = lsNotLoaded);
  Assert.AreEqual(LConfig, Loader.ConfigFile);
  Assert.AreEqual(LDiagnostics, Loader.FailedToLoad.Text);
  Assert.AreEqual('', Loader.Version);
  Assert.AreEqual(0, TNTLMReadinessObserver.LoadCount);
  Assert.AreEqual(0, TNTLMReadinessObserver.UnloadCount);
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Assert.IsFalse(Assigned(OpenSSL_version_num), 'Query must not bind native APIs');
{$ENDIF}
end;

procedure TLoaderNTLMReadinessFixture.Status_Failed;
var
  LDiagnostics: string;
  I: Integer;
begin
  Loader.ConfigFile := FInvalidSyntaxConfigFile;
  Assert.WillRaise(
    procedure
    begin
      Loader.Load;
    end,
    ETaurusTLSConfigFileLoadError);
  Assert.IsTrue(Loader.State = lsLoadedFailed);
  LDiagnostics := Loader.FailedToLoad.Text;
  // A corrected property must not let a status query reset the circuit breaker.
  Loader.ConfigFile := FValidConfigFile;
  for I := 1 to 2 do
  begin
    Assert.IsFalse(IdFIPS.LoadNTLMLibrary());
    Assert.IsFalse(IdFIPS.IsNTLMFuncsAvail());
  end;
  Assert.IsTrue(Loader.State = lsLoadedFailed);
  Assert.AreEqual(FValidConfigFile, Loader.ConfigFile);
  Assert.AreEqual(LDiagnostics, Loader.FailedToLoad.Text);
  Assert.IsFalse(Loader.Load, 'Hook must leave retry blocked until explicit Unload');
  Assert.AreEqual(0, TNTLMReadinessObserver.LoadCount);
  Assert.AreEqual(0, TNTLMReadinessObserver.UnloadCount);
  Loader.Unload;
  Assert.IsFalse(IdFIPS.LoadNTLMLibrary(), 'Reset alone must not initialize OpenSSL');
end;

procedure TLoaderNTLMReadinessFixture.Status_LoadUnload(const ACycles: Integer);
var
  I: Integer;
  LConfig: string;
  LVersion: string;
begin
  Loader.ConfigFile := FValidConfigFile;
  for I := 1 to ACycles do
  begin
    Assert.IsFalse(IdFIPS.LoadNTLMLibrary());
    Assert.IsTrue(Loader.Load);
    LConfig := Loader.ConfigFile;
    LVersion := Loader.Version;
    Assert.IsTrue(IdFIPS.LoadNTLMLibrary());
    Assert.IsTrue(IdFIPS.LoadNTLMLibrary());
    Assert.IsTrue(Loader.State = lsLoadedReady);
    Assert.AreEqual(LConfig, Loader.ConfigFile);
    Assert.AreEqual(LVersion, Loader.Version);
    Assert.AreEqual(I, TNTLMReadinessObserver.LoadCount);
    Assert.IsFalse(TNTLMReadinessObserver.ReadyDuringLoad);
    Loader.Unload;
    Assert.IsFalse(IdFIPS.LoadNTLMLibrary());
    Assert.IsFalse(IdFIPS.IsNTLMFuncsAvail());
    Assert.IsTrue(Loader.State = lsNotLoaded);
    Assert.AreEqual(I, TNTLMReadinessObserver.UnloadCount);
    Assert.IsFalse(TNTLMReadinessObserver.ReadyDuringUnload);
    Assert.AreEqual('', TNTLMReadinessObserver.Error,
      'Transition hook query must not recurse into lifecycle operations');
  end;
end;

function UnexpectedNTLMHook: Boolean;
begin
  raise Exception.Create('Foreign NTLM callback must not be invoked by lifecycle setup');
end;

function UnexpectedNTLMResponse(const APassword: string;
  const ANonce: TIdBytes): TIdBytes;
begin
  raise Exception.Create('Foreign NTLM response callback must not be invoked by lifecycle setup');
end;

function PolicyRequiresFIPS: Boolean;
begin
  Result := True;
end;

function UnexpectedHashInstance: TIdHashIntCtx;
begin
  raise Exception.Create('NTLM must not invoke Indy hash callbacks');
end;

procedure TLoaderNTLMReadinessFixture.Hooks_Static(const AReady: Integer);
begin
  AssertNTLMHooks(GInitialNTLMHooks);
  Loader.ConfigFile := FValidConfigFile;
  if AReady <> 0 then
    Assert.IsTrue(Loader.Load);
  AssertNTLMHooks(GInitialNTLMHooks);
  Assert.IsTrue(IdFIPS.LoadNTLMLibrary() = (AReady <> 0));
  Loader.Unload;
  AssertNTLMHooks(GInitialNTLMHooks);
  Assert.IsFalse(IdFIPS.LoadNTLMLibrary());
  Assert.IsFalse(IdFIPS.IsNTLMFuncsAvail());
end;

procedure TLoaderNTLMReadinessFixture.Hooks_KeepForeignAssignments(const ACycles: Integer);
var
  I: Integer;
  LSavedHooks, LForeignHooks: TNTLMHookSnapshot;
  LObserverActive: Boolean;
begin
  Loader.ConfigFile := FValidConfigFile;
  LSavedHooks := CaptureNTLMHooks;
  LObserverActive := TNTLMReadinessObserver.Active;
  try
    // Deliberately simulate another backend. Lifecycle must not write any callback.
    TNTLMReadinessObserver.Active := False;
    IdFIPS.LoadNTLMLibrary := UnexpectedNTLMHook;
    IdFIPS.IsNTLMFuncsAvail := UnexpectedNTLMHook;
    IdFIPS.NTLMGetLmChallengeResponse := UnexpectedNTLMResponse;
    IdFIPS.NTLMGetNtChallengeResponse := UnexpectedNTLMResponse;
    LForeignHooks := CaptureNTLMHooks;
    for I := 1 to ACycles do
    begin
      Assert.IsTrue(Loader.Load);
      AssertNTLMHooks(LForeignHooks);
      Loader.Unload;
      AssertNTLMHooks(LForeignHooks);
    end;
  finally
    RestoreNTLMHooks(LSavedHooks);
    TNTLMReadinessObserver.Active := LObserverActive;
  end;
end;

procedure TLoaderNTLMReadinessFixture.Hooks_PreserveHashAndFIPS(const AReady: Integer);
var
  LSavedHashLoad: TLoadHashLibrary;
  LSavedHashAvailable: TIsHashingIntfAvail;
  LSavedMD4Available: TIsHashingIntfAvail;
  LSavedMD4Instance: TGetHashInst;
  LSavedMode: TGetFIPSMode;
  LState: TTaurusTLSLoaderState;
  LConfig, LDiagnostics: string;
begin
  Loader.ConfigFile := FValidConfigFile;
  if AReady <> 0 then
    Assert.IsTrue(Loader.Load);
  LState := Loader.State;
  LConfig := Loader.ConfigFile;
  LDiagnostics := Loader.FailedToLoad.Text;
  LSavedHashLoad := IdFIPS.LoadHashLibrary;
  LSavedHashAvailable := IdFIPS.IsHashingIntfAvail;
  LSavedMD4Available := IdFIPS.IsMD4HashIntfAvail;
  LSavedMD4Instance := IdFIPS.GetMD4HashInst;
  LSavedMode := IdFIPS.GetFIPSMode;
  try
    IdFIPS.LoadHashLibrary := UnexpectedNTLMHook;
    IdFIPS.IsHashingIntfAvail := UnexpectedNTLMHook;
    IdFIPS.IsMD4HashIntfAvail := UnexpectedNTLMHook;
    IdFIPS.GetMD4HashInst := UnexpectedHashInstance;
    IdFIPS.GetFIPSMode := PolicyRequiresFIPS;
    Assert.IsTrue(IdFIPS.LoadNTLMLibrary() = (AReady <> 0));
    Assert.IsFalse(IdFIPS.IsNTLMFuncsAvail(), 'Installed Indy policy prohibits NTLM');
    AssertNTLMHooks(GInitialNTLMHooks);
    Assert.IsTrue(@IdFIPS.LoadHashLibrary = @UnexpectedNTLMHook);
    Assert.IsTrue(@IdFIPS.IsHashingIntfAvail = @UnexpectedNTLMHook);
    Assert.IsTrue(@IdFIPS.IsMD4HashIntfAvail = @UnexpectedNTLMHook);
    Assert.IsTrue(@IdFIPS.GetMD4HashInst = @UnexpectedHashInstance);
    Assert.IsTrue(@IdFIPS.GetFIPSMode = @PolicyRequiresFIPS);
    Assert.IsTrue(Loader.State = LState);
    Assert.AreEqual(LConfig, Loader.ConfigFile);
    Assert.AreEqual(LDiagnostics, Loader.FailedToLoad.Text);
  finally
    IdFIPS.LoadHashLibrary := LSavedHashLoad;
    IdFIPS.IsHashingIntfAvail := LSavedHashAvailable;
    IdFIPS.IsMD4HashIntfAvail := LSavedMD4Available;
    IdFIPS.GetMD4HashInst := LSavedMD4Instance;
    IdFIPS.GetFIPSMode := LSavedMode;
  end;
end;

procedure TLoaderNTLMReadinessFixture.Hooks_PreserveMD4Policy;
var
  LSavedMode: TGetFIPSMode;
begin
  LSavedMode := IdFIPS.GetFIPSMode;
  try
    IdFIPS.GetFIPSMode := PolicyRequiresFIPS;
    // Policy rejection precedes hashing/DES and must work without native loading.
    Assert.WillRaise(
      procedure
      begin
        IdFIPS.NTLMGetNtChallengeResponse('Password', nil);
      end, EIdFIPSAlgorithmNotAllowed);
    Assert.IsTrue(Loader.State = lsNotLoaded);
  finally
    IdFIPS.GetFIPSMode := LSavedMode;
  end;
end;

function PolicyAllowsOrdinaryCrypto: Boolean;
begin
  Result := False;
end;

procedure TLoaderNTLMReadinessFixture.Funcs_ReflectNativeAlgorithms;
var
  LMD: PEVP_MD;
  LCipher: PEVP_CIPHER;
  LExpected: Boolean;
begin
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(Loader.Load);
  LMD := EVP_MD_fetch(nil, 'MD4', nil);
  try
    LCipher := EVP_CIPHER_fetch(nil, 'DES-ECB', nil);
    try
      LExpected := not IdFIPS.GetFIPSMode() and (LMD <> nil) and (LCipher <> nil);
    finally
      EVP_CIPHER_free(LCipher);
    end;
  finally
    EVP_MD_free(LMD);
  end;
  Assert.AreEqual(LExpected, IdFIPS.IsNTLMFuncsAvail());
  Assert.AreEqual(LExpected, IdNTLM.NTLMFunctionsLoaded);
end;

procedure TLoaderNTLMReadinessFixture.Funcs_RejectNativePolicy;
var
  LSavedMode: TGetFIPSMode;
  LWasFIPS: TIdC_INT;
  LChallenge: TIdBytes;
begin
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(Loader.Load);
  LWasFIPS := EVP_default_properties_is_fips_enabled(nil);
  LSavedMode := IdFIPS.GetFIPSMode;
  SetLength(LChallenge, 8);
  try
    // The native property query must still prohibit MD4/DES when Indy's flag is False.
    IdFIPS.GetFIPSMode := PolicyAllowsOrdinaryCrypto;
    Assert.AreEqual(1, EVP_default_properties_enable_fips(nil, 1));
    Assert.IsFalse(IdFIPS.IsNTLMFuncsAvail());
    Assert.IsFalse(IdNTLM.NTLMFunctionsLoaded);
    Assert.WillRaise(
      procedure
      begin
        IdFIPS.NTLMGetNtChallengeResponse('Password', LChallenge);
      end, ETaurusTLSMD4NotFound);
    Assert.WillRaise(
      procedure
      begin
        IdFIPS.NTLMGetLmChallengeResponse('Password', LChallenge);
      end, ETaurusTLSDES_ECBNotFound);
  finally
    IdFIPS.GetFIPSMode := LSavedMode;
    Assert.AreEqual(1, EVP_default_properties_enable_fips(nil, LWasFIPS));
  end;
end;

procedure TLoaderNTLMReadinessFixture.Responses_NotReady(const AFailed: Integer);
var
  LSavedMode: TGetFIPSMode;
  LChallenge: TIdBytes;
begin
  if AFailed <> 0 then
  begin
    Loader.ConfigFile := FInvalidSyntaxConfigFile;
    Assert.WillRaise(
      procedure
      begin
        Loader.Load;
      end, ETaurusTLSConfigFileLoadError);
  end;
  SetLength(LChallenge, 8);
  LSavedMode := IdFIPS.GetFIPSMode;
  try
    IdFIPS.GetFIPSMode := PolicyAllowsOrdinaryCrypto;
    Assert.IsFalse(IdFIPS.IsNTLMFuncsAvail());
    Assert.WillRaise(
      procedure
      begin
        IdFIPS.NTLMGetNtChallengeResponse('Password', LChallenge);
      end, ETaurusTLSLoaderError);
    Assert.WillRaise(
      procedure
      begin
        IdFIPS.NTLMGetLmChallengeResponse('Password', LChallenge);
      end, ETaurusTLSLoaderError);
    if AFailed <> 0 then
      Assert.IsTrue(Loader.State = lsLoadedFailed)
    else
      Assert.IsTrue(Loader.State = lsNotLoaded);
  finally
    IdFIPS.GetFIPSMode := LSavedMode;
  end;
end;

procedure TLoaderNTLMReadinessFixture.Responses_InvalidChallenge(const ALength: Integer);
var
  LSavedMode: TGetFIPSMode;
  LChallenge: TIdBytes;
begin
  SetLength(LChallenge, ALength);
  LSavedMode := IdFIPS.GetFIPSMode;
  try
    IdFIPS.GetFIPSMode := PolicyAllowsOrdinaryCrypto;
    Assert.WillRaise(
      procedure
      begin
        IdFIPS.NTLMGetNtChallengeResponse('Password', LChallenge);
      end, EArgumentException);
    Assert.WillRaise(
      procedure
      begin
        IdFIPS.NTLMGetLmChallengeResponse('Password', LChallenge);
      end, EArgumentException);
    Assert.IsTrue(Loader.State = lsNotLoaded);
  finally
    IdFIPS.GetFIPSMode := LSavedMode;
  end;
end;

const
  CGuardByte = $A5;
  CDESBlockSize = 8;

function TOSSLNTLMFixture.LegacyModulePath: string;
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

function TOSSLNTLMFixture.CreateNTLMConfig: string;
var
  LContent, LModule: string;
begin
  LContent :=
    'config_diagnostics = 1' + sLineBreak +
    'openssl_conf = ntlm_init' + sLineBreak +
    '[ntlm_init]' + sLineBreak +
    'providers = ntlm_providers' + sLineBreak +
    'alg_section = ntlm_properties' + sLineBreak +
    '[ntlm_providers]' + sLineBreak +
    'default = ntlm_default' + sLineBreak +
    'legacy = ntlm_legacy' + sLineBreak +
    '[ntlm_default]' + sLineBreak +
    'activate = 1' + sLineBreak +
    '[ntlm_legacy]' + sLineBreak +
    'activate = 1' + sLineBreak;
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
    '[ntlm_properties]' + sLineBreak +
    'default_properties = ""' + sLineBreak;
  Result := TPath.Combine(FConfigDirectory, 'ntlm.cnf');
  TFile.WriteAllText(Result, LContent);
end;

procedure TOSSLNTLMFixture.SetupFixture;
begin
  Assert.IsFalse(Loader.IsLoaded, 'NTLM fixture requires exclusive loader ownership');
  FOriginalPath := Loader.OpenSSLPath;
  FOriginalConfig := Loader.ConfigFile;
  FStateCaptured := True;
  try
    Unload;
    SetupFromCmd;
    FConfigDirectory := TPath.Combine(TPath.GetTempPath,
      'TaurusTLS.NTLM.' + TGUID.NewGuid.ToString);
    TDirectory.CreateDirectory(FConfigDirectory);
    Loader.ConfigFile := CreateNTLMConfig;
    Assert.IsTrue(Load, 'Cannot load OpenSSL with the generated NTLM configuration');
    CheckAlgorithms;
  except
    // DUnitX does not call fixture teardown after setup fails.
    try
      TearDownFixture;
    except
      on E: Exception do
        Log(TLogLevel.Error, 'NTLM fixture setup cleanup: ' + E.Message);
    end;
    raise;
  end;
end;

procedure TOSSLNTLMFixture.TearDownFixture;
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

destructor TOSSLNTLMFixture.Destroy;
begin
  try
    if FStateCaptured or (FConfigDirectory <> '') then
      TearDownFixture;
  finally
    inherited Destroy;
  end;
end;

class function TOSSLNTLMFixture.HexBytes(const AHex: string): TIdBytes;
var
  LBytes: TBytes;
  I: Integer;
begin
  LBytes := TBytes.FromHexStr(AHex);
  SetLength(Result, Length(LBytes));
  for I := 0 to High(LBytes) do
    Result[I] := LBytes[I];
end;

class procedure TOSSLNTLMFixture.AssertBytesEqual(
  const AExpected, AActual: TIdBytes);
var
  I: Integer;
begin
  Assert.AreEqual<Integer>(Length(AExpected), Length(AActual),
    'Unexpected output length');
  for I := 0 to High(AExpected) do
    Assert.AreEqual<Byte>(AExpected[I], AActual[I],
      Format('Mismatch at byte %d', [I]));
end;

procedure TOSSLNTLMFixture.CheckAlgorithms;
begin
  Assert.IsTrue(IdFIPS.IsNTLMFuncsAvail(),
    'NTLM requires loaded OpenSSL with MD4 and DES-ECB permitted by configuration.');
end;

procedure TOSSLNTLMFixture.NTLMResponse(
  APassword, AChallengeHex, AExpectedHex: string);
var
  LChallenge, LActual: TIdBytes;
  LSavedLoad: TLoadHashLibrary;
  LSavedAvailable: TIsHashingIntfAvail;
  LSavedMD4: TGetHashInst;
begin
  CheckLoaded;
  CheckAlgorithms;
  LChallenge := HexBytes(AChallengeHex);
  Assert.AreEqual<Integer>(8, Length(LChallenge));
  LSavedLoad := IdFIPS.LoadHashLibrary;
  LSavedAvailable := IdFIPS.IsMD4HashIntfAvail;
  LSavedMD4 := IdFIPS.GetMD4HashInst;
  try
    IdFIPS.LoadHashLibrary := UnexpectedNTLMHook;
    IdFIPS.IsMD4HashIntfAvail := UnexpectedNTLMHook;
    IdFIPS.GetMD4HashInst := UnexpectedHashInstance;
    // A correct NT response must not use Indy's hash backend or Pascal fallback.
    LActual := IdFIPS.NTLMGetNtChallengeResponse(APassword, LChallenge);
    AssertBytesEqual(HexBytes(AExpectedHex), LActual);
  finally
    IdFIPS.LoadHashLibrary := LSavedLoad;
    IdFIPS.IsMD4HashIntfAvail := LSavedAvailable;
    IdFIPS.GetMD4HashInst := LSavedMD4;
  end;
end;

procedure TOSSLNTLMFixture.LMResponse(
  APassword, AChallengeHex, AExpectedHex: string);
var
  LChallenge, LActual: TIdBytes;
begin
  CheckLoaded;
  CheckAlgorithms;
  LChallenge := HexBytes(AChallengeHex);
  Assert.AreEqual<Integer>(8, Length(LChallenge));
  LActual := IdFIPS.NTLMGetLmChallengeResponse(APassword, LChallenge);
  AssertBytesEqual(HexBytes(AExpectedHex), LActual);
end;

procedure TOSSLNTLMFixture.DESBoundary(ALeftGuard, ARightGuard: Integer);
var
  LKey: DES_cblock;
  LInput, LInputBefore, LExpected, LBuffer, LActual: TIdBytes;
  I: Integer;
begin
  CheckLoaded;
  CheckAlgorithms;
  Assert.IsTrue((ALeftGuard > 0) and (ARightGuard > 0));

  // DES 64-bit key 133457799BBCDFF1 stripped of parity bits
  // gives 7-byte NTLM key material 12695BC9B7B7F8.
  // Encrypt_DES is assumed to expand the first seven bytes.
  FillChar(LKey, SizeOf(LKey), 0);
  LActual := HexBytes('12695BC9B7B7F8');
  Move(LActual[0], LKey[0], 7);
  LInput := HexBytes('0123456789ABCDEF');
  LExpected := HexBytes('85E813540F0AB405');
  LInputBefore := Copy(LInput, 0, Length(LInput));

  SetLength(LBuffer, ALeftGuard + CDESBlockSize + ARightGuard);
  FillChar(LBuffer[0], Length(LBuffer), CGuardByte);
  Encrypt_DES(LKey, @LBuffer[ALeftGuard], @LInput[0]);

  for I := 0 to ALeftGuard - 1 do
    Assert.AreEqual<Byte>(CGuardByte, LBuffer[I],
      Format('Left guard changed at %d', [I]));
  for I := ALeftGuard + CDESBlockSize to High(LBuffer) do
    Assert.AreEqual<Byte>(CGuardByte, LBuffer[I],
      Format('Right guard changed at %d', [I]));

  SetLength(LActual, CDESBlockSize);
  Move(LBuffer[ALeftGuard], LActual[0], CDESBlockSize);
  AssertBytesEqual(LExpected, LActual);
  AssertBytesEqual(LInputBefore, LInput); // The plaintext must remain unchanged.
end;

procedure TOSSLNTLMFixture.ResponseBoundary;
const
  GuardSize = 16;
var
  LHash, LKeys, LKeysBefore, LChallenge, LOutput, LExpected, LActual: TIdBytes;
  I: Integer;
begin
  CheckLoaded;
  CheckAlgorithms;
  // MD4(UTF-16LE("Password")), padded to three seven-byte DES keys.
  LHash := HexBytes('A4F49C406510BDCAB6824EE7C30FD8520000000000');
  LChallenge := HexBytes('0123456789ABCDEF');
  LExpected := HexBytes('67C43011F30298A2AD35ECE64F16331C44BDBED927841F94');
  SetLength(LKeys, GuardSize + Length(LHash) + GuardSize);
  FillChar(LKeys[0], Length(LKeys), CGuardByte);
  Move(LHash[0], LKeys[GuardSize], Length(LHash));
  LKeysBefore := Copy(LKeys, 0, Length(LKeys));
  SetLength(LOutput, GuardSize + 24 + GuardSize);
  FillChar(LOutput[0], Length(LOutput), CGuardByte);
  calc_resp(PDES_cblock(@LKeys[GuardSize]), LChallenge, @LOutput[GuardSize]);
  for I := 0 to GuardSize - 1 do
  begin
    Assert.AreEqual<Byte>(CGuardByte, LOutput[I]);
    Assert.AreEqual<Byte>(CGuardByte, LOutput[GuardSize + 24 + I]);
  end;
  LActual := Copy(LOutput, GuardSize, 24);
  AssertBytesEqual(LExpected, LActual);
  AssertBytesEqual(LKeysBefore, LKeys);
end;

{$IFDEF STRING_IS_UNICODE}
procedure TOSSLNTLMFixture.UnicodeNTResponse;
begin
  // Independent Windows CryptoAPI MD4/DES reference, including a UTF-16 surrogate pair.
  NTLMResponse('p' + Char($00E4) + 'ss' + Char($D83D) + Char($DE00),
    '0123456789ABCDEF',
    'F95AA72D259232B97D39EC2BBF317ED1403B0FDF84B476D3');
end;
{$ENDIF}

initialization
  GInitialNTLMHooks := CaptureNTLMHooks;
  Register_SSLLoaderAction(TNTLMReadinessObserver.Action);
  TDUnitX.RegisterTestFixture(TOSSLNTLMFixture);
  TDUnitX.RegisterTestFixture(TLoaderNTLMReadinessFixture);

end.
