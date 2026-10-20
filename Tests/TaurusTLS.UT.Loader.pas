unit TaurusTLS.UT.Loader;

{$I ..\Source\TaurusTLSCompilerDefines.inc}
{$I ..\Source\TaurusTLSLinkDefines.inc}

interface

uses
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  DUnitX.TestFramework,
  DUnitX.Types,
  IdGlobal,
  IdCTypes,
  TaurusTLSLoader,
  TaurusTLSExceptionHandlers,
  TaurusTLS_ResourceStrings;

type
  [TestFixture]
  [Category('Loader')]
  TIOpenSSLLoader = class
  private
    FLoader: IOpenSSLLoader;
    FTempDir: string;
    FValidConfigFile: string;
    FInvalidSyntaxConfigFile: string;
    function CreateTempConfigFile(const AContent: string): string;
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure Teardown;

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
    [Test]
    procedure StaticLoaderIsNil;
{$ELSE}
    // Existing configuration & path validation tests
    [Test]
    procedure InitialConfigFileIsEmpty;
    [Test]
    procedure SetConfigFileValidatesInvalidPathCharacters;
    [Test]
    procedure SetConfigFileAcceptsValidFormatWhenUnloaded;
    [Test]
    procedure SetConfigFileRejectsModificationWhenLoaded;
    [Test]
    procedure LoadRejectsDirectoryPath;
    [Test]
    procedure LoadRejectsNonExistentFile;
    [Test]
    procedure LoadWithValidConfigFileSucceeds;
    [Test]
    procedure LoadWithInvalidConfigContentRaisesLoadError;
    [Test]
    procedure UnloadClearsDefaultConfigFile;

    // Lifecycle & Idempotency tests
    [Test]
    procedure DoubleLoadSucceeds;
    [Test]
    procedure DoubleUnloadIsSafe;
    [Test]
    procedure LoadWhenAlreadyLoadedIsIdempotentAndPreservesConfig;

    // Failure & Circuit-Breaker tests
    [Test]
    procedure FailureStatePersistsUntilExplicitUnload;
    [Test]
    procedure UnloadPreservesDiagnosticsOnFailure;

    // Callback lifecycle, ordering & rollback tests
    [Test]
    procedure PostLoadAndPreUnloadLifecycleDispatchesCleanly;
    [Test]
    procedure CallbacksExecuteInReverseOrderOnUnload;
    [Test]
    procedure DoubleLoadAndUnloadDoNotDuplicateCallbacks;
    [Test]
    procedure CallbackRollbackFiresOnLoadFailure;
{$ENDIF}
  end;

implementation

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

procedure TIOpenSSLLoader.SetUp;
begin
end;

procedure TIOpenSSLLoader.TearDown;
begin
end;

function TIOpenSSLLoader.CreateTempConfigFile(const AContent: string): string;
begin
  Result := '';
end;

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
procedure TIOpenSSLLoader.StaticLoaderIsNil;
var
  LLoader: IOpenSSLLoader;
begin
  LLoader := GetOpenSSLLoader;
  Assert.IsNotNull(LLoader, 'Static loader instance must be available');
  Assert.IsFalse(LLoader.IsLoaded, 'Static loader must not be loaded before Load is called');
  Assert.AreEqual('', LLoader.OpenSSLPath, 'OpenSSLPath must be empty in static mode');
  Assert.AreEqual(0, LLoader.FailedToLoad.Count, 'FailedToLoad must be empty in static mode');
end;
{$ENDIF}

{$ELSE}

var
  TTestCallbackLog: TStringList = nil;
  GTestSymbolInjectorActive: Boolean = False;

type
  // Observer A for callback ordering & rollback tests
  TTestCallbackObserverA = class
  public
    class var Active: Boolean;
    class var VerifyHandlesLive: Boolean;
    class procedure ActionProc(AAction: TOpenSSLLoadAction);
  end;

  // Observer B for callback ordering & failure injection tests
  TTestCallbackObserverB = class
  public
    class var Active: Boolean;
    class var ThrowOnLoad: Boolean;
    class procedure ActionProc(AAction: TOpenSSLLoadAction);
  end;

  // Symbol injector for FailedToLoad diagnostic tests
  TTestSymbolInjector = class
  public
    class var Active: Boolean;
  end;

class procedure TTestCallbackObserverA.ActionProc(AAction: TOpenSSLLoadAction);
begin
  if not Active then
    Exit;

  if VerifyHandlesLive then
  begin
    if GetOpenSSLLoader.IsLoaded then
    begin
      if AAction = osaLoad then
        TTestCallbackLog.Add('A:Load:Live')
      else
        TTestCallbackLog.Add('A:Unload:Live');
    end
    else
    begin
      if AAction = osaLoad then
        TTestCallbackLog.Add('A:Load:Dead')
      else
        TTestCallbackLog.Add('A:Unload:Dead');
    end;
  end
  else
  begin
    if AAction = osaLoad then
      TTestCallbackLog.Add('A:Load')
    else
      TTestCallbackLog.Add('A:Unload');
  end;
end;

class procedure TTestCallbackObserverB.ActionProc(AAction: TOpenSSLLoadAction);
begin
  if not Active then
    Exit;

  if (AAction = osaLoad) and ThrowOnLoad then
    raise Exception.Create('Simulated action failure in Observer B');

  if AAction = osaLoad then
    TTestCallbackLog.Add('B:Load')
  else
    TTestCallbackLog.Add('B:Unload');
end;

procedure TestSymbolInjectorLoadProc(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);
begin
  if GTestSymbolInjectorActive and Assigned(AFailed) then
    AFailed.Add('Fake_Diagnostic_Symbol');
end;

const
  cMinimalValidOpenSSLConfig =
    'openssl_conf = default_conf' + sLineBreak +
    sLineBreak +
    '[default_conf]' + sLineBreak +
    'ssl_conf = ssl_sect' + sLineBreak +
    sLineBreak +
    '[ssl_sect]' + sLineBreak +
    'system_default = system_default_sect' + sLineBreak +
    sLineBreak +
    '[system_default_sect]' + sLineBreak +
    'MinProtocol = TLSv1.2' + sLineBreak;

  cMinimalInvalidOpenSSLConfig =
    '[invalid_syntax' + sLineBreak +
    '= broken ===' + sLineBreak;

procedure TIOpenSSLLoader.Setup;
begin
  GTestSymbolInjectorActive := False;
  FLoader := GetOpenSSLLoader;
  if Assigned(FLoader) then
  begin
    try
      FLoader.Unload; // Resets FFailedToLoad and FFailed between tests
    except
    end;
  end;

  FTempDir := TPath.Combine(TPath.GetTempPath, 'TaurusTLS_UT_Loader_' + TGuid.NewGuid.ToString);
  TDirectory.CreateDirectory(FTempDir);

  FValidConfigFile := CreateTempConfigFile(cMinimalValidOpenSSLConfig);
  FInvalidSyntaxConfigFile := CreateTempConfigFile(cMinimalInvalidOpenSSLConfig);

  TTestCallbackLog.Clear;
  TTestCallbackObserverA.Active := False;
  TTestCallbackObserverA.VerifyHandlesLive := False;
  TTestCallbackObserverB.Active := False;
  TTestCallbackObserverB.ThrowOnLoad := False;
  TTestSymbolInjector.Active := False;
end;

procedure TIOpenSSLLoader.Teardown;
begin
  TTestCallbackObserverA.Active := False;
  TTestCallbackObserverA.VerifyHandlesLive := False;
  TTestCallbackObserverB.Active := False;
  TTestCallbackObserverB.ThrowOnLoad := False;
  TTestSymbolInjector.Active := False;

  if Assigned(FLoader) then
  begin
    try
      FLoader.Unload; // Resets FFailedToLoad and FFailed between tests
    except
    end;
  end;

  if Assigned(FLoader) then
  begin
    try
      FLoader.ConfigFile := '';
    except
    end;
  end;

  if TDirectory.Exists(FTempDir) then
  try
    TDirectory.Delete(FTempDir, True);
  except
  end;
end;

function TIOpenSSLLoader.CreateTempConfigFile(const AContent: string): string;
begin
  Result := TPath.Combine(FTempDir, 'cfg_' + TGuid.NewGuid.ToString + '.cnf');
  TFile.WriteAllText(Result, AContent);
end;

// ============================================================================
// Configuration & Path Tests
// ============================================================================

procedure TIOpenSSLLoader.InitialConfigFileIsEmpty;
begin
  Assert.IsNotNull(FLoader);
  Assert.IsFalse(FLoader.IsLoaded);
  Assert.AreEqual('', FLoader.ConfigFile);
end;

procedure TIOpenSSLLoader.SetConfigFileValidatesInvalidPathCharacters;
var
  LInvalidPath: string;
begin
  LInvalidPath := 'bad'#0'path.cnf';
  Assert.WillRaiseWithMessage(
    procedure
    begin
      FLoader.ConfigFile := LInvalidPath;
    end,
    ETaurusTLSConfigFilePathError,
    Format(RSOSSLConfigFilePathInvalid, [LInvalidPath])
  );
end;

procedure TIOpenSSLLoader.SetConfigFileAcceptsValidFormatWhenUnloaded;
var
  LPath: string;
begin
  LPath := 'some_relative\config.cnf';
  FLoader.ConfigFile := LPath;
  Assert.AreEqual(LPath, FLoader.ConfigFile);
  FLoader.ConfigFile := '';
end;

procedure TIOpenSSLLoader.SetConfigFileRejectsModificationWhenLoaded;
begin
  Assert.IsTrue(FLoader.Load, 'Loader.Load failed');
  try
    Assert.IsTrue(FLoader.IsLoaded);
    Assert.WillRaiseWithMessage(
      procedure
      begin
        FLoader.ConfigFile := FValidConfigFile;
      end,
      ETaurusTLSConfigFilePathError,
      RSOSSLConfigFileAlreadyLoaded
    );
  finally
    FLoader.Unload;
  end;
end;

procedure TIOpenSSLLoader.LoadRejectsDirectoryPath;
var
  LNormalizedDir: string;
begin
  LNormalizedDir := TPath.GetFullPath(FTempDir);
  FLoader.ConfigFile := FTempDir;
  Assert.WillRaiseWithMessage(
    procedure
    begin
      FLoader.Load;
    end,
    ETaurusTLSConfigFilePathError,
    Format(RSOSSLConfigFileIsDirectory, [LNormalizedDir])
  );
end;

procedure TIOpenSSLLoader.LoadRejectsNonExistentFile;
var
  LNonExistent: string;
  LNormalized: string;
begin
  LNonExistent := TPath.Combine(FTempDir, 'does_not_exist_' + TGuid.NewGuid.ToString + '.cnf');
  LNormalized := TPath.GetFullPath(LNonExistent);
  FLoader.ConfigFile := LNonExistent;
  Assert.WillRaiseWithMessage(
    procedure
    begin
      FLoader.Load;
    end,
    ETaurusTLSConfigFilePathError,
    Format(RSOSSLConfigFileNotFound, [LNormalized])
  );
end;

procedure TIOpenSSLLoader.LoadWithValidConfigFileSucceeds;
var
  LNormalized: string;
begin
  LNormalized := TPath.GetFullPath(FValidConfigFile);
  FLoader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(FLoader.Load, 'Loader.Load with valid config failed');
  try
    Assert.IsTrue(FLoader.IsLoaded);
    Assert.AreEqual(LNormalized, FLoader.ConfigFile);
  finally
    FLoader.Unload;
  end;
end;

procedure TIOpenSSLLoader.LoadWithInvalidConfigContentRaisesLoadError;
var
  LNormalized: string;
  LExMsgExpected: string;
begin
  LNormalized := TPath.GetFullPath(FInvalidSyntaxConfigFile);
  LExMsgExpected := Format(RSOSSLConfigFileLoadFailed, [LNormalized]);
  FLoader.ConfigFile := FInvalidSyntaxConfigFile;

  try
    FLoader.Load;
    Assert.Fail('Expected ETaurusTLSConfigFileLoadError was not raised');
  except
    on E: ETaurusTLSConfigFileLoadError do
    begin
      Assert.IsTrue(E.Message.StartsWith(LExMsgExpected),
        Format('Exception message "%s" should start with "%s"', [E.Message, LExMsgExpected]));
    end;
  end;

  // Circuit breaker check: subsequent call immediately returns False without re-attempting
  Assert.IsFalse(FLoader.IsLoaded, 'Loader must not be in loaded state after failure');
  Assert.IsFalse(FLoader.Load, 'Subsequent Load call must immediately return False due to FFailedToLoad circuit breaker');
end;

procedure TIOpenSSLLoader.UnloadClearsDefaultConfigFile;
begin
  FLoader.ConfigFile := '';
  Assert.IsTrue(FLoader.Load, 'Loader.Load failed');
  try
    Assert.IsTrue(FLoader.IsLoaded);
    Assert.AreNotEqual('', FLoader.ConfigFile);
  finally
    FLoader.Unload;
  end;
  Assert.IsFalse(FLoader.IsLoaded);
  Assert.AreEqual('', FLoader.ConfigFile);
end;

// ============================================================================
// Lifecycle & Idempotency Tests
// ============================================================================

procedure TIOpenSSLLoader.DoubleLoadSucceeds;
begin
  FLoader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(FLoader.Load, 'Initial Load failed');
  try
    Assert.IsTrue(FLoader.IsLoaded);
    // Second load must be a safe, idempotent success
    Assert.IsTrue(FLoader.Load, 'Second Load call should succeed idempotently');
    Assert.IsTrue(FLoader.IsLoaded);
  finally
    FLoader.Unload;
  end;
end;

procedure TIOpenSSLLoader.DoubleUnloadIsSafe;
begin
  // Unload when already unloaded must be a safe no-op
  FLoader.Unload;
  FLoader.Unload;
  Assert.IsFalse(FLoader.IsLoaded);

  // Load and then double-unload
  FLoader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(FLoader.Load, 'Load failed');
  FLoader.Unload;
  Assert.IsFalse(FLoader.IsLoaded);
  FLoader.Unload;
  Assert.IsFalse(FLoader.IsLoaded);
end;

procedure TIOpenSSLLoader.LoadWhenAlreadyLoadedIsIdempotentAndPreservesConfig;
var
  LNormalized: string;
begin
  LNormalized := TPath.GetFullPath(FValidConfigFile);
  FLoader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(FLoader.Load, 'Initial Load failed');
  try
    Assert.AreEqual(LNormalized, FLoader.ConfigFile);
    // Second Load must not overwrite or wipe out FEffectiveConfigFile
    Assert.IsTrue(FLoader.Load, 'Second Load should succeed');
    Assert.AreEqual(LNormalized, FLoader.ConfigFile, 'FEffectiveConfigFile must be preserved on second Load call');
  finally
    FLoader.Unload;
  end;
end;

// ============================================================================
// Failure & Circuit-Breaker Tests
// ============================================================================

procedure TIOpenSSLLoader.FailureStatePersistsUntilExplicitUnload;
begin
  FLoader.ConfigFile := FInvalidSyntaxConfigFile;
  try
    FLoader.Load;
    Assert.Fail('Expected ETaurusTLSConfigFileLoadError was not raised');
  except
    on ETaurusTLSConfigFileLoadError do ;
  end;

  // 1. IsLoaded is False
  Assert.IsFalse(FLoader.IsLoaded, 'Loader must not be loaded after failure');

  // 2. Subsequent Load calls immediately return False
  Assert.IsFalse(FLoader.Load, 'Subsequent Load must return False while failure state is active');

  // 3. Explicit Unload clears failure circuit breaker
  FLoader.Unload;
  Assert.IsFalse(FLoader.IsLoaded);

  // 4. Subsequent valid load now succeeds
  FLoader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(FLoader.Load, 'Load should succeed after explicit Unload resets failure state');
  try
    Assert.IsTrue(FLoader.IsLoaded);
  finally
    FLoader.Unload;
  end;
end;

procedure TIOpenSSLLoader.UnloadPreservesDiagnosticsOnFailure;
begin
  GTestSymbolInjectorActive := True;
  try
    FLoader.ConfigFile := FInvalidSyntaxConfigFile;
    try
      FLoader.Load;
    except
      on ETaurusTLSConfigFileLoadError do ;
    end;

    // Internal Unload(False) preserved FailedToLoad entries
    Assert.IsTrue(FLoader.FailedToLoad.IndexOf('Fake_Diagnostic_Symbol') >= 0,
      'Internal failure teardown must preserve FailedToLoad diagnostics');

    // Deliberate public Unload() clears FailedToLoad
    FLoader.Unload;
    Assert.AreEqual(0, FLoader.FailedToLoad.Count,
      'Public Unload must clear FailedToLoad diagnostics');
  finally
    GTestSymbolInjectorActive := False;
    FLoader.Unload;
  end;
end;

// ============================================================================
// Callback Lifecycle, Ordering & Rollback Tests
// ============================================================================

procedure TIOpenSSLLoader.PostLoadAndPreUnloadLifecycleDispatchesCleanly;
begin
  TTestCallbackLog.Clear;
  TTestCallbackObserverA.Active := True;
  TTestCallbackObserverA.VerifyHandlesLive := True;
  try
    FLoader.ConfigFile := FValidConfigFile;
    Assert.IsTrue(FLoader.Load, 'Load failed');
    try
      Assert.AreEqual(1, TTestCallbackLog.Count);
      Assert.AreEqual('A:Load:Live', TTestCallbackLog[0],
        'osaLoad must execute post-load while library handles and symbols are active');
    finally
      FLoader.Unload;
    end;

    Assert.AreEqual(2, TTestCallbackLog.Count);
    Assert.AreEqual('A:Unload:Live', TTestCallbackLog[1],
      'osaUnload must execute pre-unload while library handles and symbols are still active');
  finally
    TTestCallbackObserverA.Active := False;
    TTestCallbackObserverA.VerifyHandlesLive := False;
  end;
end;

procedure TIOpenSSLLoader.CallbacksExecuteInReverseOrderOnUnload;
begin
  TTestCallbackLog.Clear;
  TTestCallbackObserverA.Active := True;
  TTestCallbackObserverB.Active := True;
  try
    FLoader.ConfigFile := FValidConfigFile;
    Assert.IsTrue(FLoader.Load, 'Load failed');
    try
      // Load order must be registration order: A then B
      Assert.AreEqual(2, TTestCallbackLog.Count);
      Assert.AreEqual('A:Load', TTestCallbackLog[0]);
      Assert.AreEqual('B:Load', TTestCallbackLog[1]);
    finally
      FLoader.Unload;
    end;

    // Unload order must be strict reverse registration order: B then A
    Assert.AreEqual(4, TTestCallbackLog.Count);
    Assert.AreEqual('A:Load', TTestCallbackLog[0]);
    Assert.AreEqual('B:Load', TTestCallbackLog[1]);
    Assert.AreEqual('B:Unload', TTestCallbackLog[2]);
    Assert.AreEqual('A:Unload', TTestCallbackLog[3]);
  finally
    TTestCallbackObserverA.Active := False;
    TTestCallbackObserverB.Active := False;
  end;
end;

procedure TIOpenSSLLoader.DoubleLoadAndUnloadDoNotDuplicateCallbacks;
begin
  TTestCallbackLog.Clear;
  TTestCallbackObserverA.Active := True;
  try
    FLoader.ConfigFile := FValidConfigFile;
    Assert.IsTrue(FLoader.Load, 'Initial Load failed');
    Assert.IsTrue(FLoader.Load, 'Second Load call should succeed');

    // Only one osaLoad should have been dispatched
    Assert.AreEqual(1, TTestCallbackLog.Count);
    Assert.AreEqual('A:Load', TTestCallbackLog[0]);

    FLoader.Unload;
    FLoader.Unload; // Second Unload call

    // Only one osaUnload should have been dispatched
    Assert.AreEqual(2, TTestCallbackLog.Count);
    Assert.AreEqual('A:Load', TTestCallbackLog[0]);
    Assert.AreEqual('A:Unload', TTestCallbackLog[1]);
  finally
    TTestCallbackObserverA.Active := False;
    FLoader.Unload;
  end;
end;

procedure TIOpenSSLLoader.CallbackRollbackFiresOnLoadFailure;
begin
  TTestCallbackLog.Clear;
  TTestCallbackObserverA.Active := True;
  TTestCallbackObserverB.Active := True;
  TTestCallbackObserverB.ThrowOnLoad := True;
  try
    FLoader.ConfigFile := FValidConfigFile;
    try
      FLoader.Load;
      Assert.Fail('Expected exception from Observer B was not raised');
    except
      on E: Exception do
        Assert.AreEqual('Simulated action failure in Observer B', E.Message);
    end;

    // Observer A ran osaLoad, then Observer B threw during osaLoad.
    // Rollback must have dispatched osaUnload to Observer A.
    Assert.AreEqual(2, TTestCallbackLog.Count);
    Assert.AreEqual('A:Load', TTestCallbackLog[0]);
    Assert.AreEqual('A:Unload', TTestCallbackLog[1]);

    // Loader must be left in unloaded state
    Assert.IsFalse(FLoader.IsLoaded);
  finally
    TTestCallbackObserverB.ThrowOnLoad := False;
    TTestCallbackObserverA.Active := False;
    TTestCallbackObserverB.Active := False;
    FLoader.Unload;
  end;
end;

{$ENDIF}

initialization
  TDUnitX.RegisterTestFixture(TIOpenSSLLoader);
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  TTestCallbackLog := TStringList.Create;
  Register_SSLLoaderAction(TTestCallbackObserverA.ActionProc);
  Register_SSLLoaderAction(TTestCallbackObserverB.ActionProc);
  Register_SSLLoader(TestSymbolInjectorLoadProc, 'LibCrypto');
{$ENDIF}

finalization
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  FreeAndNil(TTestCallbackLog);
{$ENDIF}

end.
