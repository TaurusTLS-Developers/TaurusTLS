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
  [TestFixture('', 'Checks the actual Indy NTLM loading hook against loader readiness without executing NTLM algorithms. '
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
    procedure Hooks_Reinstalled(const AReady: Integer);
  end;



  [TestFixture]
  [Category('NTLM')]
  TOSSLNTLMFixture = class(TOsslBaseFixture)
  private
    class function HexBytes(const AHex: string): TIdBytes; static;
    class procedure AssertBytesEqual(const AExpected, AActual: TIdBytes); static;
  protected
    procedure CheckLegacyProvider;
  public
    // Independent NTLMv1 known-answer vector (password Password, challenge below).
    [AutoNameTestCase('Password,0123456789ABCDEF,67C43011F30298A2AD35ECE64F16331C44BDBED927841F94')]
    procedure NTLMResponse(APassword, AChallengeHex, AExpectedHex: string);

    [AutoNameTestCase('Password,0123456789ABCDEF,98DEF7B87F88AA5DAFE2DF779688A172DEF11C7D5CCDEF13')]
    procedure LMResponse(APassword, AChallengeHex, AExpectedHex: string);

    // Guards check writes around the 8-byte DES output, not input overreads.
    [AutoNameTestCase('1,1')]
    [AutoNameTestCase('4,4')]
    [AutoNameTestCase('16,16')]
    [AutoNameTestCase('1,16')]
    [AutoNameTestCase('16,1')]
    procedure DESBoundary(ALeftGuard, ARightGuard: Integer);
  end;

implementation

uses
  IdFIPS,
  TaurusTLSHeaders_crypto,
  TaurusTLS_LegacyProviders,
  TaurusTLSFIPS,
  TaurusTLS_NTLM;


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
  InstallFIPSHooks;
  Assert.IsTrue(Assigned(IdFIPS.LoadNTLMLibrary), 'Indy NTLM hook must be installed');
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
  FLoader.ConfigFile := LConfig;
  LDiagnostics := FLoader.FailedToLoad.Text;
  for I := 1 to 2 do
    Assert.IsFalse(IdFIPS.LoadNTLMLibrary());
  Assert.IsTrue(FLoader.State = lsNotLoaded);
  Assert.AreEqual(LConfig, FLoader.ConfigFile);
  Assert.AreEqual(LDiagnostics, FLoader.FailedToLoad.Text);
  Assert.AreEqual('', FLoader.Version);
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
  FLoader.ConfigFile := FInvalidSyntaxConfigFile;
  Assert.WillRaise(
    procedure
    begin
      FLoader.Load;
    end,
    ETaurusTLSConfigFileLoadError);
  Assert.IsTrue(FLoader.State = lsLoadedFailed);
  LDiagnostics := FLoader.FailedToLoad.Text;
  // A corrected property must not let a status query reset the circuit breaker.
  FLoader.ConfigFile := FValidConfigFile;
  for I := 1 to 2 do
    Assert.IsFalse(IdFIPS.LoadNTLMLibrary());
  Assert.IsTrue(FLoader.State = lsLoadedFailed);
  Assert.AreEqual(FValidConfigFile, FLoader.ConfigFile);
  Assert.AreEqual(LDiagnostics, FLoader.FailedToLoad.Text);
  Assert.IsFalse(FLoader.Load, 'Hook must leave retry blocked until explicit Unload');
  Assert.AreEqual(0, TNTLMReadinessObserver.LoadCount);
  Assert.AreEqual(0, TNTLMReadinessObserver.UnloadCount);
  FLoader.Unload;
  Assert.IsFalse(IdFIPS.LoadNTLMLibrary(), 'Reset alone must not initialize OpenSSL');
end;

procedure TLoaderNTLMReadinessFixture.Status_LoadUnload(const ACycles: Integer);
var
  I: Integer;
  LConfig: string;
  LVersion: string;
begin
  FLoader.ConfigFile := FValidConfigFile;
  for I := 1 to ACycles do
  begin
    Assert.IsFalse(IdFIPS.LoadNTLMLibrary());
    Assert.IsTrue(FLoader.Load);
    LConfig := FLoader.ConfigFile;
    LVersion := FLoader.Version;
    Assert.IsTrue(IdFIPS.LoadNTLMLibrary());
    Assert.IsTrue(IdFIPS.LoadNTLMLibrary());
    Assert.IsTrue(FLoader.State = lsLoadedReady);
    Assert.AreEqual(LConfig, FLoader.ConfigFile);
    Assert.AreEqual(LVersion, FLoader.Version);
    Assert.AreEqual(I, TNTLMReadinessObserver.LoadCount);
    Assert.IsFalse(TNTLMReadinessObserver.ReadyDuringLoad);
    FLoader.Unload;
    Assert.IsFalse(IdFIPS.LoadNTLMLibrary());
    Assert.IsTrue(FLoader.State = lsNotLoaded);
    Assert.AreEqual(I, TNTLMReadinessObserver.UnloadCount);
    Assert.IsFalse(TNTLMReadinessObserver.ReadyDuringUnload);
    Assert.AreEqual('', TNTLMReadinessObserver.Error,
      'Transition hook query must not recurse into lifecycle operations');
  end;
end;

function UnexpectedNTLMHook: Boolean;
begin
  raise Exception.Create('NTLM hook was not reinstalled');
end;

procedure TLoaderNTLMReadinessFixture.Hooks_Reinstalled(const AReady: Integer);
var
  LSavedHook: TLoadNTLMLibrary;
begin
  FLoader.ConfigFile := FValidConfigFile;
  if AReady <> 0 then
    Assert.IsTrue(FLoader.Load);
  LSavedHook := IdFIPS.LoadNTLMLibrary;
  try
    IdFIPS.LoadNTLMLibrary := UnexpectedNTLMHook;
    InstallFIPSHooks;
    Assert.IsTrue(IdFIPS.LoadNTLMLibrary() = (AReady <> 0));
    if AReady <> 0 then
      Assert.IsTrue(FLoader.State = lsLoadedReady)
    else
      Assert.IsTrue(FLoader.State = lsNotLoaded);
  finally
    IdFIPS.LoadNTLMLibrary := LSavedHook;
  end;
end;

const
  CGuardByte = $A5;
  CDESBlockSize = 8;

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

procedure TOSSLNTLMFixture.CheckLegacyProvider;
begin
  Assert.IsTrue(IsLegacyProviderLoaded,
    'Legacy Provider is not loaded. Unable to continue.')
end;

procedure TOSSLNTLMFixture.NTLMResponse(
  APassword, AChallengeHex, AExpectedHex: string);
var
  LChallenge, LActual: TIdBytes;
begin
  CheckAllFailures;
  CheckLegacyProvider;
  LChallenge := HexBytes(AChallengeHex);
  Assert.AreEqual<Integer>(8, Length(LChallenge));
  LActual := CreateNTPassword(APassword, LChallenge);
  AssertBytesEqual(HexBytes(AExpectedHex), LActual);
end;

procedure TOSSLNTLMFixture.LMResponse(
  APassword, AChallengeHex, AExpectedHex: string);
var
  LChallenge, LActual: TIdBytes;
begin
  CheckAllFailures;
  CheckLegacyProvider;
  LChallenge := HexBytes(AChallengeHex);
  Assert.AreEqual<Integer>(8, Length(LChallenge));
  LActual := SetupLanManagerPassword(APassword, LChallenge);
  AssertBytesEqual(HexBytes(AExpectedHex), LActual);
end;

procedure TOSSLNTLMFixture.DESBoundary(ALeftGuard, ARightGuard: Integer);
var
  LKey: DES_cblock;
  LInput, LInputBefore, LExpected, LBuffer, LActual: TIdBytes;
  I: Integer;
begin
  CheckAllFailures;
  CheckLegacyProvider;
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

initialization
  Register_SSLLoaderAction(TNTLMReadinessObserver.Action);
  TDUnitX.RegisterTestFixture(TOSSLNTLMFixture);
  TDUnitX.RegisterTestFixture(TLoaderNTLMReadinessFixture);

end.
