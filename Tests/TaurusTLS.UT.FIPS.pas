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

implementation

uses
  System.SysUtils,
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
  Assert.IsFalse(IdFIPS.IsHashingIntfAvail());
  Assert.IsFalse(IdFIPS.IsHMACAvail());
  Assert.IsFalse(IdFIPS.IsMD2HashIntfAvail());
  Assert.IsFalse(IdFIPS.IsMD4HashIntfAvail());
  Assert.IsFalse(IdFIPS.IsMD5HashIntfAvail());
  Assert.IsFalse(IdFIPS.IsSHA1HashIntfAvail());
  Assert.IsFalse(IdFIPS.IsSHA224HashIntfAvail());
  Assert.IsFalse(IdFIPS.IsSHA256HashIntfAvail());
  Assert.IsFalse(IdFIPS.IsSHA384HashIntfAvail());
  Assert.IsFalse(IdFIPS.IsSHA512HashIntfAvail());
  Assert.IsFalse(IdFIPS.IsHMACMD5Avail());
  Assert.IsFalse(IdFIPS.IsHMACSHA1Avail());
  Assert.IsFalse(IdFIPS.IsHMACSHA224Avail());
  Assert.IsFalse(IdFIPS.IsHMACSHA256Avail());
  Assert.IsFalse(IdFIPS.IsHMACSHA384Avail());
  Assert.IsFalse(IdFIPS.IsHMACSHA512Avail());
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
          end, ETaurusTLSConfigFileLoadError);
      end;
    2:
      begin
        Loader.ConfigFile := FValidConfigFile;
        Assert.IsTrue(Loader.Load);
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
  Assert.IsTrue(Loader.State = LState);
  Assert.AreEqual(LConfig, Loader.ConfigFile);
  Assert.AreEqual(LDiagnostics, Loader.FailedToLoad.Text);
  Assert.AreEqual('', Loader.Version);
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
    Assert.IsTrue(Loader.Load);
    Assert.IsTrue(IdFIPS.LoadHashLibrary());
    Assert.IsTrue(IdHash.HashFunctionsLoaded);
    Assert.IsTrue(IdFIPS.IsHashingIntfAvail());
    Assert.IsTrue(IdFIPS.IsHMACAvail());
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
    Assert.IsTrue(Loader.State = lsLoadedReady);
    Assert.AreEqual(FValidConfigFile, Loader.ConfigFile);
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
    Assert.IsTrue(Loader.Load);
    Loader.Unload;
    Assert.AreEqual(1, TConsumerReadinessObserver.LoadCount);
    Assert.AreEqual(1, TConsumerReadinessObserver.UnloadCount);
    Assert.AreEqual('', TConsumerReadinessObserver.Error);
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
    Assert.IsTrue(Loader.Load);
  LSavedHook := IdFIPS.LoadHashLibrary;
  try
    IdFIPS.LoadHashLibrary := UnexpectedHashLoader;
    InstallFIPSHooks;
    Assert.AreEqual(AReady <> 0, IdHash.HashFunctionsLoaded);
    Assert.IsTrue(Loader.IsLoaded = (AReady <> 0));
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
    Assert.IsTrue(Loader.Load);
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
    Assert.IsTrue(@IdFIPS.LoadNTLMLibrary = @UnexpectedHashLoader);
    Assert.IsTrue(@IdFIPS.IsNTLMFuncsAvail = @UnexpectedHashLoader);
    Assert.IsFalse(Assigned(IdFIPS.NTLMGetLmChallengeResponse));
    Assert.IsFalse(Assigned(IdFIPS.NTLMGetNtChallengeResponse));
    Assert.IsTrue(Loader.IsLoaded = (AReady <> 0));
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
    Assert.IsTrue(Loader.Load);
    Assert.IsTrue(@IdFIPS.GetFIPSMode = @LGet);
    Assert.IsTrue(@IdFIPS.SetFIPSMode = @LSet);
    Assert.IsTrue(@IdFIPS.GetSHA256HashInst = @LHash);
    Assert.IsTrue(@IdFIPS.GetHMACSHA256HashInst = @LMAC);
    Loader.Unload;
    Assert.IsTrue(@IdFIPS.GetFIPSMode = @LGet);
    Assert.IsTrue(@IdFIPS.SetFIPSMode = @LSet);
    Assert.IsTrue(@IdFIPS.GetSHA256HashInst = @LHash);
    Assert.IsTrue(@IdFIPS.GetHMACSHA256HashInst = @LMAC);
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
          end, ETaurusTLSConfigFileLoadError);
      end;
    2:
      begin
        Assert.IsTrue(Loader.Load);
        Loader.Unload;
      end;
  end;
  LState := Loader.State;
  Assert.IsFalse(IdFIPS.GetFIPSMode());
  Assert.IsFalse(IdFIPS.SetFIPSMode(True));
  Assert.IsFalse(IdFIPS.SetFIPSMode(False));
  Assert.WillRaise(
    procedure
    begin
      IdFIPS.GetSHA256HashInst();
    end, ETaurusTLSLoaderError);
  Assert.WillRaise(
    procedure
    begin
      IdFIPS.GetHMACSHA256HashInst(nil);
    end, ETaurusTLSLoaderError);
  Assert.WillRaise(
    procedure
    begin
      IdFIPS.UpdateHashInst(nil, nil);
    end, ETaurusTLSLoaderError);
  Assert.WillRaise(
    procedure
    begin
      IdFIPS.FinalHashInst(nil);
    end, ETaurusTLSLoaderError);
  Assert.WillRaise(
    procedure
    begin
      IdFIPS.UpdateHMACInst(nil, nil);
    end, ETaurusTLSLoaderError);
  Assert.WillRaise(
    procedure
    begin
      IdFIPS.FinalHMACInst(nil);
    end, ETaurusTLSLoaderError);
  Assert.IsTrue(Loader.State = LState);
end;

procedure TLoaderFIPSReadinessFixture.Mode_ConfigOwned;
var
  LSelected: Integer;
begin
  InstallFIPSHooks;
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(Loader.Load);
  LSelected := EVP_default_properties_is_fips_enabled(nil);
  Assert.AreEqual(0, LSelected, 'Controlled ordinary config must not select FIPS');
  Assert.IsFalse(IdFIPS.GetFIPSMode());
  Assert.IsFalse(IdFIPS.SetFIPSMode(True), 'Setter must not activate/select FIPS');
{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  Assert.IsFalse(IdFIPS.SetFIPSMode(False), 'Static FIPS is unsupported');
{$ELSE}
  Assert.IsTrue(IdFIPS.SetFIPSMode(False), 'Matching configured non-FIPS mode is a no-op');
{$ENDIF}
  Assert.AreEqual(LSelected, EVP_default_properties_is_fips_enabled(nil));
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
  Assert.IsTrue(Loader.Load);
  // This fixture activates only default, even when a fips module is installed.
  // Native default context can retain archive providers; no other fixture activates FIPS.
  LSelected := EVP_default_properties_is_fips_enabled(nil);
  try
    Assert.AreEqual(1, LSelected);
    Assert.AreEqual(0, OSSL_PROVIDER_available(nil, 'fips'));
    Assert.IsFalse(IdFIPS.GetFIPSMode(), 'Selection alone is not operational FIPS');
    Assert.IsFalse(IdFIPS.SetFIPSMode(True));
    Assert.IsFalse(IdFIPS.SetFIPSMode(False), 'Setter must not weaken selected policy');
    Assert.AreEqual(1, EVP_default_properties_is_fips_enabled(nil));
    Assert.IsFalse(IdFIPS.IsSHA256HashIntfAvail());
    Assert.IsFalse(IdFIPS.IsHMACAvail());
    Assert.IsFalse(IdFIPS.IsHMACSHA256Avail());
    Assert.WillRaise(
      procedure
      begin
        IdFIPS.GetSHA256HashInst();
      end, ETaurusTLSSHA256NotFound);
    Assert.WillRaise(
      procedure
      begin
        IdFIPS.GetHMACSHA256HashInst(nil);
      end, ETaurusTLSSHA256NotFound);
    Assert.AreEqual(1, EVP_default_properties_is_fips_enabled(nil));
    Assert.AreEqual(0, OSSL_PROVIDER_available(nil, 'fips'));
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
  Assert.IsTrue(Loader.Load);
  LContext := IdFIPS.GetSHA256HashInst();
  IdFIPS.UpdateHashInst(LContext, ToBytes('a', IndyTextEncoding_ASCII));
  IdFIPS.UpdateHashInst(LContext, ToBytes('bc', IndyTextEncoding_ASCII));
  LResult := IdFIPS.FinalHashInst(LContext);
  Assert.AreEqual('BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD',
    BytesHex(LResult));
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
  Assert.IsTrue(Loader.Load);
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
  Assert.AreEqual(AExpected, BytesHex(LResult));
end;

procedure TLoaderFIPSReadinessFixture.HMAC_EmptyKeyAndInput;
var
  LContext: TIdHMACIntCtx;
begin
  InstallFIPSHooks;
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(Loader.Load);
  LContext := IdFIPS.GetHMACSHA256HashInst(nil);
  IdFIPS.UpdateHMACInst(LContext, nil);
  Assert.AreEqual('B613679A0814D9EC772F95D778C35FC5FF1697C493715653C6C712144292C5AD',
    BytesHex(IdFIPS.FinalHMACInst(LContext)));
end;

procedure TLoaderFIPSReadinessFixture.Probes_PreserveErrors;
var
  LMethod: PEVP_MD;
  LFirst, LLast: TIdC_ULONG;
begin
  InstallFIPSHooks;
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(Loader.Load);
  ERR_clear_error;
  LMethod := EVP_MD_fetch(nil, 'TaurusTLS-nonexistent-digest', nil);
  EVP_MD_free(LMethod);
  LFirst := ERR_peek_error;
  LLast := ERR_peek_last_error;
  Assert.IsTrue(LFirst <> 0);
  try
    IdFIPS.IsMD2HashIntfAvail();
    IdFIPS.IsMD4HashIntfAvail();
    IdFIPS.IsHMACMD5Avail();
    IdFIPS.IsHMACSHA256Avail();
    IdFIPS.GetFIPSMode();
    Assert.AreEqual(UInt64(LFirst), UInt64(ERR_peek_error));
    Assert.AreEqual(UInt64(LLast), UInt64(ERR_peek_last_error));
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
begin
  InstallFIPSHooks;
  LConfig := TPath.Combine(FTempDir, 'missing_fips_module.cnf');
  LModule := StringReplace(TPath.Combine(FTempDir, 'missing-fips-module'), '\', '/', [rfReplaceAll]);
  TFile.WriteAllText(LConfig,
    'config_diagnostics = 1' + sLineBreak +
    'openssl_conf = init' + sLineBreak +
    '[init]' + sLineBreak +
    'providers = providers' + sLineBreak +
    '[providers]' + sLineBreak +
    'fips = missing_fips' + sLineBreak +
    '[missing_fips]' + sLineBreak +
    'module = "' + LModule + '"' + sLineBreak +
    'activate = 1' + sLineBreak, TEncoding.UTF8);
  Loader.ConfigFile := LConfig;
  Assert.WillRaise(
    procedure
    begin
      Loader.Load;
    end, ETaurusTLSConfigFileLoadError);
  Assert.IsTrue(Loader.State = lsLoadedFailed);
  Assert.IsFalse(IdFIPS.GetFIPSMode());
  Assert.IsFalse(IdFIPS.SetFIPSMode(True));
  Assert.IsFalse(IdFIPS.LoadHashLibrary());
  Assert.IsFalse(Loader.Load, 'Failed-state retry remains blocked');
  Loader.Unload;
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(Loader.Load, 'Explicit reset permits corrected config');
  Assert.IsTrue(IdFIPS.IsSHA256HashIntfAvail());
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
  Result := 0;
end;

function FailInitMAC(ctx: PEVP_MAC_CTX; const Key: PIdAnsiChar;
  KeyLength: TIdC_SIZET; const Params: TaurusTLSHeaders_core.POSSL_PARAM_ARRAY): TIdC_INT; cdecl;
begin
  Result := 0;
end;

function FailFinalDigest(ctx: PEVP_MD_CTX; Data: PByte; var Size: TIdC_UINT): TIdC_INT; cdecl;
begin
  Result := 0;
end;

function FailFinalMAC(ctx: PEVP_MAC_CTX; Data: PIdAnsiChar;
  var Size: TIdC_SIZET; Capacity: TIdC_SIZET): TIdC_INT; cdecl;
begin
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
  Assert.IsTrue(Loader.Load);
  GFreeDigest := EVP_MD_CTX_free;
  GFreeMAC := EVP_MAC_CTX_free;
  LInitDigest := EVP_DigestInit_ex;
  LInitMAC := EVP_MAC_init;
  LFinalDigest := EVP_DigestFinal_ex;
  LFinalMAC := EVP_MAC_final;
  GFreedContexts := 0;
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
            end, ETaurusTLSDigestInitEx);
        end;
      1:
        begin
          EVP_MAC_init := FailInitMAC;
          Assert.WillRaise(
            procedure
            begin
              IdFIPS.GetHMACSHA256HashInst(nil);
            end, ETaurusTLSHMACInitEx);
        end;
      2:
        begin
          LContext := IdFIPS.GetSHA256HashInst();
          EVP_DigestFinal_ex := FailFinalDigest;
          Assert.WillRaise(
            procedure
            begin
              IdFIPS.FinalHashInst(LContext);
            end, ETaurusTLSDigestFinalEx);
        end;
      3:
        begin
          LContext := IdFIPS.GetHMACSHA256HashInst(nil);
          EVP_MAC_final := FailFinalMAC;
          Assert.WillRaise(
            procedure
            begin
              IdFIPS.FinalHMACInst(LContext);
            end, ETaurusTLSHMACFinal);
        end;
    end;
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
