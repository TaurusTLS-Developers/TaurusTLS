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
  TaurusTLS_ResourceStrings,
  TaurusTLSConsts;

type
  /// <summary>
  ///   Base fixture providing shared setup, teardown, and temporary configuration file helpers.
  /// </summary>
  TLoaderBaseFixture = class
  protected
    FLoader: IOpenSSLLoader;
    FTempDir: string;
    FValidConfigFile: string;
    FInvalidSyntaxConfigFile: string;
    FOrigOpenSSLPath: string;
    FOrigSSLLibVersions: string;

    function CreateTempConfigFile(const AContent: string; const AFileName: string = ''): string;
    function HexToBytes(const AHexStr: string): TBytes;
    function HexToUnicodeString(const AHexStr: string): string;
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure Teardown;
  end;

  /// <summary>
  ///   Group 1: Configuration file path validation, syntax errors, and expansion tests.
  /// </summary>
  [TestFixture]
  [Category('Loader,Loader.Config')]
  TLoaderConfigFixture = class(TLoaderBaseFixture)
  public
    /// <summary>Tests that ConfigFile is initially empty and loader is not loaded.</summary>
    [Test]
    procedure Config_Initial;

    /// <summary>Tests that ConfigFile accepts valid path formats prior to loading.</summary>
    [Test]
    procedure Config_SetValid;

    /// <summary>Tests that ConfigFile rejects invalid platform path characters.</summary>
    // 'bad'#0'path.cnf'
    [TestCase('EmbeddedNull', '620061006400000070006100740068002E0063006E006600')]
    {$IFDEF MSWINDOWS}
    // 'bad|path.cnf'
    [TestCase('Pipe',         '6200610064007C0070006100740068002E0063006E006600')]
    // 'bad<path.cnf'
    [TestCase('LessAngle',    '6200610064003C0070006100740068002E0063006E006600')]
    // 'bad>path.cnf'
    [TestCase('GreaterAngle', '6200610064003E0070006100740068002E0063006E006600')]
    // 'bad?path.cnf'
    [TestCase('QuestionMark', '6200610064003F0070006100740068002E0063006E006600')]
    // 'bad*path.cnf'
    [TestCase('Asterisk',     '6200610064002A0070006100740068002E0063006E006600')]
    // 'bad"path.cnf'
    [TestCase('DoubleQuote',  '620061006400220070006100740068002E0063006E006600')]
    {$ENDIF}
    procedure Config_InvalidChars(const AHexPath: string);

    /// <summary>Tests that passing a directory path to ConfigFile is rejected on Load.</summary>
    [Test]
    procedure Config_RejectDir;

    /// <summary>Tests that passing a non-existent file path to ConfigFile is rejected on Load.</summary>
    [Test]
    procedure Config_RejectMissing;

    /// <summary>Tests that loading with a valid configuration file succeeds.</summary>
    [Test]
    procedure Config_ValidLoad;

    /// <summary>Tests that malformed configuration syntax raises ETaurusTLSConfigFileLoadError.</summary>
    [Test]
    procedure Config_InvalidSyntax;

    /// <summary>Tests that Unload clears the active effective configuration filename.</summary>
    [Test]
    procedure Config_UnloadClears;

    /// <summary>Tests that relative configuration paths expand to absolute paths on Load.</summary>
    [TestCase('SubDir', 'sub/test.cnf')]
    [TestCase('CurrentDir', './test.cnf')]
    procedure Config_RelativePath(const ARelPath: string);

    /// <summary>Tests that configuration paths containing Unicode characters are supported.</summary>
    [TestCase('Accents', 'Conf_Test_Unicode.cnf')]
    [TestCase('Cyrillic', 'Конфиг_Тест.cnf')]
    procedure Config_UnicodePath(const AUnicodeFileName: string);
  end;

  /// <summary>
  ///   Group 2: Lifecycle idempotency, state persistence, mutation guards, and circuit breaker tests.
  /// </summary>
  [TestFixture]
  [Category('Loader,Loader.Lifecycle')]
  TLoaderLifecycleFixture = class(TLoaderBaseFixture)
  public
    {$IFDEF OPENSSL_STATIC_LINK_MODEL}
    /// <summary>Verifies that the static loader instance is non-nil, uninitialized, and inert.</summary>
    [Test]
    procedure Static_State;
    {$ENDIF}

    /// <summary>Tests that successive Load calls succeed idempotently.</summary>
    [Test]
    procedure Life_DoubleLoad;

    /// <summary>Tests that successive Unload calls are safe no-ops.</summary>
    [Test]
    procedure Life_DoubleUnload;

    /// <summary>Tests that idempotent Load calls preserve the active configuration.</summary>
    [Test]
    procedure Life_PreserveConfig;

    /// <summary>Tests that failure circuit breaker persists until explicit Unload.</summary>
    [Test]
    procedure Life_CircuitBreaker;

    /// <summary>Tests that ConfigFile modification is rejected while loaded.</summary>
    [Test]
    procedure Life_RejectConfigWhenLoaded;

    /// <summary>Tests that property mutation while failed is accepted, but Load remains blocked.</summary>
    [TestCase('ConfigFile', '0')]
    {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    [TestCase('OpenSSLPath', '1')]
    [TestCase('SSLLibVersions', '2')]
    {$ENDIF}
    procedure Life_MutateWhenFailed(const APropId: Integer);
  end;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  /// <summary>
  ///   Group 3: Lifecycle action callbacks, execution ordering, and rollback tests.
  /// </summary>
  [TestFixture]
  [Category('Loader,Loader.Callbacks')]
  TLoaderCallbacksFixture = class(TLoaderBaseFixture)
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure Teardown;

    /// <summary>Tests that osaLoad and osaUnload fire while handles/symbols are active.</summary>
    [Test]
    procedure CB_DispatchLive;

    /// <summary>Tests that action callbacks execute in strict reverse registration order on unload.</summary>
    [Test]
    procedure CB_ReverseUnload;

    /// <summary>Tests that double load and unload cycles do not duplicate callback triggers.</summary>
    [Test]
    procedure CB_NoDuplicates;

    /// <summary>Tests that granular rollback fires only for executed callbacks on load failure.</summary>
    [Test]
    procedure CB_RollbackOnFail;

    /// <summary>Tests that internal failure teardown preserves FailedToLoad diagnostics.</summary>
    [Test]
    procedure CB_PreserveDiag;
  end;
{$ENDIF}

implementation

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

{ TLoaderBaseFixture }

function TLoaderBaseFixture.HexToBytes(const AHexStr: string): TBytes;
var
  lLen: NativeUInt;
begin
  Assert.IsNotEmpty(AHexStr, 'Parameter ''AHexStr'' must not be empty.');
  lLen := Length(AHexStr);
  Assert.IsFalse(Odd(lLen mod 2), 'HEX String must be divisible by 2.');
  lLen := lLen div 2;
  SetLength(Result, lLen);
  HexToBin(PChar(AHexStr), 0, Result, 0, lLen);
end;

function TLoaderBaseFixture.HexToUnicodeString(const AHexStr: string): string;
var
  LBytes: TBytes;
begin
  LBytes := HexToBytes(AHexStr);
  Result := TEncoding.Unicode.GetString(LBytes);
end;

procedure TLoaderBaseFixture.Setup;
begin
  FLoader := GetOpenSSLLoader;
  if Assigned(FLoader) then
  begin
    FOrigOpenSSLPath := FLoader.OpenSSLPath;
    FOrigSSLLibVersions := FLoader.SSLLibVersions;
    try
      FLoader.Unload;
    except
    end;
    try
      FLoader.ConfigFile := '';
    except
    end;
  end;

  FTempDir := TPath.Combine(TPath.GetTempPath, 'TaurusTLS_UT_Loader_' + TGuid.NewGuid.ToString);
  TDirectory.CreateDirectory(FTempDir);

  FValidConfigFile := CreateTempConfigFile(cMinimalValidOpenSSLConfig);
  FInvalidSyntaxConfigFile := CreateTempConfigFile(cMinimalInvalidOpenSSLConfig);
end;

procedure TLoaderBaseFixture.Teardown;
begin
  if Assigned(FLoader) then
  begin
    try
      FLoader.Unload;
    except
    end;
    try
      FLoader.ConfigFile := '';
    except
    end;
    FLoader.OpenSSLPath := FOrigOpenSSLPath;
    FLoader.SSLLibVersions := FOrigSSLLibVersions;
  end;

  if TDirectory.Exists(FTempDir) then
  try
    TDirectory.Delete(FTempDir, True);
  except
  end;
end;

function TLoaderBaseFixture.CreateTempConfigFile(const AContent,
  AFileName: string): string;
var
  LName: string;
begin
  if AFileName = '' then
    LName := 'cfg_' + TGuid.NewGuid.ToString + '.cnf'
  else
    LName := AFileName;
  Result := TPath.Combine(FTempDir, LName);
  TFile.WriteAllText(Result, AContent);
end;

{ TLoaderConfigFixture }

procedure TLoaderConfigFixture.Config_Initial;
begin
  Assert.IsNotNull(FLoader);
  Assert.IsFalse(FLoader.IsLoaded);
  Assert.AreEqual('', FLoader.ConfigFile);
end;

procedure TLoaderConfigFixture.Config_SetValid;
var
  LPath: string;
begin
  LPath := 'some_relative/config.cnf';
  FLoader.ConfigFile := LPath;
  Assert.AreEqual(LPath, FLoader.ConfigFile);
  FLoader.ConfigFile := '';
end;

procedure TLoaderConfigFixture.Config_InvalidChars(const AHexPath: string);
var
  LPath: string;
begin
  LPath := HexToUnicodeString(AHexPath);
  Assert.WillRaiseWithMessage(
    procedure
    begin
      FLoader.ConfigFile := LPath;
    end,
    ETaurusTLSConfigFilePathError,
    Format(RSOSSLConfigFilePathInvalid, [LPath])
  );
end;

procedure TLoaderConfigFixture.Config_RejectDir;
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

procedure TLoaderConfigFixture.Config_RejectMissing;
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

procedure TLoaderConfigFixture.Config_ValidLoad;
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

procedure TLoaderConfigFixture.Config_InvalidSyntax;
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

  // Circuit breaker: subsequent call immediately returns False without re-attempting
  Assert.IsFalse(FLoader.IsLoaded, 'Loader must not be in loaded state after failure');
  Assert.IsFalse(FLoader.Load, 'Subsequent Load must return False due to FFailedToLoad circuit breaker');
end;

procedure TLoaderConfigFixture.Config_UnloadClears;
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

procedure TLoaderConfigFixture.Config_RelativePath(const ARelPath: string);
var
  LFullPath: string;
  LSubDir: string;
  LNormalized: string;
begin
  LFullPath := TPath.GetFullPath(TPath.Combine(FTempDir, ARelPath));
  LSubDir := TPath.GetDirectoryName(LFullPath);
  if not TDirectory.Exists(LSubDir) then
    TDirectory.CreateDirectory(LSubDir);

  TFile.WriteAllText(LFullPath, cMinimalValidOpenSSLConfig);
  LNormalized := TPath.GetFullPath(LFullPath);

  FLoader.ConfigFile := LFullPath;
  Assert.IsTrue(FLoader.Load, 'Load failed for relative config path');
  try
    Assert.IsTrue(FLoader.IsLoaded);
    Assert.AreEqual(LNormalized, FLoader.ConfigFile);
  finally
    FLoader.Unload;
  end;
end;

procedure TLoaderConfigFixture.Config_UnicodePath(const AUnicodeFileName: string);
var
  LFilePath: string;
  LNormalized: string;
begin
  LFilePath := CreateTempConfigFile(cMinimalValidOpenSSLConfig, AUnicodeFileName);
  LNormalized := TPath.GetFullPath(LFilePath);

  FLoader.ConfigFile := LFilePath;
  Assert.IsTrue(FLoader.Load, 'Load failed with Unicode config filename');
  try
    Assert.IsTrue(FLoader.IsLoaded);
    Assert.AreEqual(LNormalized, FLoader.ConfigFile);
  finally
    FLoader.Unload;
  end;
end;

{ TLoaderLifecycleFixture }

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
procedure TLoaderLifecycleFixture.Static_State;
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

procedure TLoaderLifecycleFixture.Life_DoubleLoad;
begin
  FLoader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(FLoader.Load, 'Initial Load failed');
  try
    Assert.IsTrue(FLoader.IsLoaded);
    Assert.IsTrue(FLoader.Load, 'Second Load call should succeed idempotently');
    Assert.IsTrue(FLoader.IsLoaded);
  finally
    FLoader.Unload;
  end;
end;

procedure TLoaderLifecycleFixture.Life_DoubleUnload;
begin
  FLoader.Unload;
  FLoader.Unload;
  Assert.IsFalse(FLoader.IsLoaded);

  FLoader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(FLoader.Load, 'Load failed');
  FLoader.Unload;
  Assert.IsFalse(FLoader.IsLoaded);
  FLoader.Unload;
  Assert.IsFalse(FLoader.IsLoaded);
end;

procedure TLoaderLifecycleFixture.Life_PreserveConfig;
var
  LNormalized: string;
begin
  LNormalized := TPath.GetFullPath(FValidConfigFile);
  FLoader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(FLoader.Load, 'Initial Load failed');
  try
    Assert.AreEqual(LNormalized, FLoader.ConfigFile);
    Assert.IsTrue(FLoader.Load, 'Second Load should succeed');
    Assert.AreEqual(LNormalized, FLoader.ConfigFile, 'Effective config must be preserved on second Load');
  finally
    FLoader.Unload;
  end;
end;

procedure TLoaderLifecycleFixture.Life_CircuitBreaker;
begin
  FLoader.ConfigFile := FInvalidSyntaxConfigFile;
  try
    FLoader.Load;
    Assert.Fail('Expected ETaurusTLSConfigFileLoadError was not raised');
  except
    on ETaurusTLSConfigFileLoadError do ;
  end;

  Assert.IsFalse(FLoader.IsLoaded, 'Loader must not be loaded after failure');
  Assert.IsFalse(FLoader.Load, 'Subsequent Load must return False while failure state is active');

  FLoader.Unload;
  Assert.IsFalse(FLoader.IsLoaded);

  FLoader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(FLoader.Load, 'Load should succeed after explicit Unload resets failure state');
  try
    Assert.IsTrue(FLoader.IsLoaded);
  finally
    FLoader.Unload;
  end;
end;

procedure TLoaderLifecycleFixture.Life_RejectConfigWhenLoaded;
begin
  // Load with default/empty configuration
  FLoader.ConfigFile := '';
  Assert.IsTrue(FLoader.Load, 'Initial Load failed');
  try
    Assert.IsTrue(FLoader.IsLoaded);
    Assert.WillRaiseWithMessage(
      procedure
      begin
        // Attempt to assign a new configuration while loaded
        FLoader.ConfigFile := FValidConfigFile;
      end,
      ETaurusTLSConfigFilePathError,
      RSOSSLConfigFileAlreadyLoaded
    );
  finally
    FLoader.Unload;
  end;
end;

procedure TLoaderLifecycleFixture.Life_MutateWhenFailed(const APropId: Integer);
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  LOrigPath: string;
  LOrigVersions: string;
{$ENDIF}
begin
  FLoader.ConfigFile := FInvalidSyntaxConfigFile;
  try
    FLoader.Load;
    Assert.Fail('Expected ETaurusTLSConfigFileLoadError was not raised');
  except
    on ETaurusTLSConfigFileLoadError do ;
  end;

  Assert.IsFalse(FLoader.IsLoaded, 'Loader must not be in loaded state after failure');

  case APropId of
    0:
      begin
        FLoader.ConfigFile := FValidConfigFile;
        Assert.AreEqual(FValidConfigFile, FLoader.ConfigFile);
      end;
    {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    1:
      begin
        LOrigPath := FLoader.OpenSSLPath;
        try
          FLoader.OpenSSLPath := FTempDir;
          Assert.AreEqual(IncludeTrailingPathDelimiter(FTempDir), FLoader.OpenSSLPath);
        finally
          FLoader.OpenSSLPath := LOrigPath; // Restore valid library path
        end;
      end;
    2:
      begin
        LOrigVersions := FLoader.SSLLibVersions;
        try
          FLoader.SSLLibVersions := DefaultLibVersions;
          Assert.AreEqual(DefaultLibVersions, FLoader.SSLLibVersions);
        finally
          FLoader.SSLLibVersions := LOrigVersions; // Restore valid versions
        end;
      end;
    {$ENDIF}
  end;

  Assert.IsFalse(FLoader.Load, 'Subsequent Load must return False while circuit breaker is active');

  FLoader.Unload;
  Assert.IsFalse(FLoader.IsLoaded);

  FLoader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(FLoader.Load, 'Load should succeed after explicit Unload resets failure state');
  try
    Assert.IsTrue(FLoader.IsLoaded);
  finally
    FLoader.Unload;
  end;
end;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

{ TLoaderCallbacksFixture }

var
  TTestCallbackLog: TStringList = nil;
  GTestSymbolInjectorActive: Boolean = False;

type
  TTestCallbackObserverA = class
  public
    class var Active: Boolean;
    class var VerifyHandlesLive: Boolean;
    class procedure ActionProc(AAction: TOpenSSLLoadAction);
  end;

  TTestCallbackObserverB = class
  public
    class var Active: Boolean;
    class var ThrowOnLoad: Boolean;
    class procedure ActionProc(AAction: TOpenSSLLoadAction);
  end;

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

procedure TLoaderCallbacksFixture.Setup;
begin
  inherited Setup;
  GTestSymbolInjectorActive := False;
  if Assigned(TTestCallbackLog) then
    TTestCallbackLog.Clear;
  TTestCallbackObserverA.Active := False;
  TTestCallbackObserverA.VerifyHandlesLive := False;
  TTestCallbackObserverB.Active := False;
  TTestCallbackObserverB.ThrowOnLoad := False;
  TTestSymbolInjector.Active := False;
end;

procedure TLoaderCallbacksFixture.Teardown;
begin
  TTestCallbackObserverA.Active := False;
  TTestCallbackObserverA.VerifyHandlesLive := False;
  TTestCallbackObserverB.Active := False;
  TTestCallbackObserverB.ThrowOnLoad := False;
  TTestSymbolInjector.Active := False;
  inherited Teardown;
end;

procedure TLoaderCallbacksFixture.CB_DispatchLive;
begin
  TTestCallbackLog.Clear;
  TTestCallbackObserverA.Active := True;
  TTestCallbackObserverA.VerifyHandlesLive := True;
  try
    FLoader.ConfigFile := FValidConfigFile;
    Assert.IsTrue(FLoader.Load, 'Load failed');
    try
      Assert.AreEqual(1, TTestCallbackLog.Count);
      Assert.AreEqual('A:Load:Live', TTestCallbackLog[0]);
    finally
      FLoader.Unload;
    end;

    Assert.AreEqual(2, TTestCallbackLog.Count);
    Assert.AreEqual('A:Unload:Live', TTestCallbackLog[1]);
  finally
    TTestCallbackObserverA.Active := False;
    TTestCallbackObserverA.VerifyHandlesLive := False;
  end;
end;

procedure TLoaderCallbacksFixture.CB_ReverseUnload;
begin
  TTestCallbackLog.Clear;
  TTestCallbackObserverA.Active := True;
  TTestCallbackObserverB.Active := True;
  try
    FLoader.ConfigFile := FValidConfigFile;
    Assert.IsTrue(FLoader.Load, 'Load failed');
    try
      Assert.AreEqual(2, TTestCallbackLog.Count);
      Assert.AreEqual('A:Load', TTestCallbackLog[0]);
      Assert.AreEqual('B:Load', TTestCallbackLog[1]);
    finally
      FLoader.Unload;
    end;

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

procedure TLoaderCallbacksFixture.CB_NoDuplicates;
begin
  TTestCallbackLog.Clear;
  TTestCallbackObserverA.Active := True;
  try
    FLoader.ConfigFile := FValidConfigFile;
    Assert.IsTrue(FLoader.Load, 'Initial Load failed');
    Assert.IsTrue(FLoader.Load, 'Second Load call should succeed');

    Assert.AreEqual(1, TTestCallbackLog.Count);
    Assert.AreEqual('A:Load', TTestCallbackLog[0]);

    FLoader.Unload;
    FLoader.Unload;

    Assert.AreEqual(2, TTestCallbackLog.Count);
    Assert.AreEqual('A:Load', TTestCallbackLog[0]);
    Assert.AreEqual('A:Unload', TTestCallbackLog[1]);
  finally
    TTestCallbackObserverA.Active := False;
    FLoader.Unload;
  end;
end;

procedure TLoaderCallbacksFixture.CB_RollbackOnFail;
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

    Assert.AreEqual(2, TTestCallbackLog.Count);
    Assert.AreEqual('A:Load', TTestCallbackLog[0]);
    Assert.AreEqual('A:Unload', TTestCallbackLog[1]);
    Assert.IsFalse(FLoader.IsLoaded);
  finally
    TTestCallbackObserverB.ThrowOnLoad := False;
    TTestCallbackObserverA.Active := False;
    TTestCallbackObserverB.Active := False;
    FLoader.Unload;
  end;
end;

procedure TLoaderCallbacksFixture.CB_PreserveDiag;
begin
  GTestSymbolInjectorActive := True;
  try
    FLoader.ConfigFile := FInvalidSyntaxConfigFile;
    try
      FLoader.Load;
    except
      on ETaurusTLSConfigFileLoadError do ;
    end;

    Assert.IsTrue(FLoader.FailedToLoad.IndexOf('Fake_Diagnostic_Symbol') >= 0,
      'Internal failure teardown must preserve FailedToLoad diagnostics');

    FLoader.Unload;
    Assert.AreEqual(0, FLoader.FailedToLoad.Count,
      'Public Unload must clear FailedToLoad diagnostics');
  finally
    GTestSymbolInjectorActive := False;
    FLoader.Unload;
  end;
end;

{$ENDIF}

initialization
  TDUnitX.RegisterTestFixture(TLoaderConfigFixture);
  TDUnitX.RegisterTestFixture(TLoaderLifecycleFixture);
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  TDUnitX.RegisterTestFixture(TLoaderCallbacksFixture);
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
