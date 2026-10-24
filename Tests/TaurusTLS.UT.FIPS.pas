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
  end;

implementation

uses
  System.SysUtils,
  System.IOUtils,
  IdFIPS,
  IdHash,
  TaurusTLSLoader,
  TaurusTLSExceptionHandlers,
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_types,
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
      IdFIPS.IsHMACAvail() or IdFIPS.IsSHA256HashIntfAvail() then
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
        FLoader.ConfigFile := FInvalidSyntaxConfigFile;
        Assert.WillRaise(
          procedure
          begin
            FLoader.Load;
          end, ETaurusTLSConfigFileLoadError);
      end;
    2:
      begin
        FLoader.ConfigFile := FValidConfigFile;
        Assert.IsTrue(FLoader.Load);
        FLoader.Unload;
      end;
  end;
  // An accidental Load would raise instead of quietly changing the state.
  LConfig := TPath.Combine(FTempDir, 'missing_consumer_config.cnf');
  FLoader.ConfigFile := LConfig;
  LState := FLoader.State;
  LDiagnostics := FLoader.FailedToLoad.Text;
  CheckUnavailable;
  CheckUnavailable;
  Assert.IsTrue(FLoader.State = LState);
  Assert.AreEqual(LConfig, FLoader.ConfigFile);
  Assert.AreEqual(LDiagnostics, FLoader.FailedToLoad.Text);
  Assert.AreEqual('', FLoader.Version);
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Assert.IsFalse(Assigned(OpenSSL_version_num), 'Queries must not bind native APIs');
{$ENDIF}
  if AState = 1 then
    Assert.IsFalse(FLoader.Load, 'Query must not reset failed-state retry blocking');
end;

procedure TLoaderFIPSReadinessFixture.Hash_Ready;
var
  I: Integer;
  LMethod: PEVP_MD;
  LAvailable: Boolean;
begin
  InstallFIPSHooks;
  FLoader.ConfigFile := FValidConfigFile;
  for I := 1 to 2 do
  begin
    Assert.IsTrue(FLoader.Load);
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
    Assert.IsTrue(FLoader.State = lsLoadedReady);
    Assert.AreEqual(FValidConfigFile, FLoader.ConfigFile);
    FLoader.Unload;
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
    FLoader.ConfigFile := FValidConfigFile;
    Assert.IsTrue(FLoader.Load);
    FLoader.Unload;
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
  FLoader.ConfigFile := FValidConfigFile;
  if AReady <> 0 then
    Assert.IsTrue(FLoader.Load);
  LSavedHook := IdFIPS.LoadHashLibrary;
  try
    IdFIPS.LoadHashLibrary := UnexpectedHashLoader;
    InstallFIPSHooks;
    Assert.AreEqual(AReady <> 0, IdHash.HashFunctionsLoaded);
    Assert.IsTrue(FLoader.IsLoaded = (AReady <> 0));
  finally
    IdFIPS.LoadHashLibrary := LSavedHook;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TLoaderFIPSReadinessFixture);
  Register_SSLLoaderAction(TConsumerReadinessObserver.Action);

end.
