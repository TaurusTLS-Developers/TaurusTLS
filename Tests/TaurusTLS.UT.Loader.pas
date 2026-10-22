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
    FOrigConfigFile: string;
    FOrigCurrentDir: string;
    FOrigConfEnv: string;
    FOrigModulesEnv: string;
    FHadConfEnv: Boolean;
    FHadModulesEnv: Boolean;
    FStateCaptured: Boolean;
    FLockHeld: Boolean;

    /// <summary>Writes a configuration into the fixture's temporary directory.</summary>
    function CreateTempConfigFile(const AContent: string; const AFileName: string = ''): string;
    /// <summary>Decodes validated hexadecimal byte pairs.</summary>
    function HexToBytes(const AHexStr: string): TBytes;
    /// <summary>Decodes UTF-16LE test data, including embedded null characters.</summary>
    function HexToUnicodeString(const AHexStr: string): string;
  public
    /// <summary>Captures state and establishes an isolated loader environment.</summary>
    [Setup]
    procedure Setup;
    /// <summary>Unloads and restores configuration, paths, and environment.</summary>
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

    /// <summary>Verifies recovery from missing-file and directory path failures.</summary>
    [TestCase('MissingFile', '0')]
    [TestCase('Directory', '1')]
    procedure Config_PathFailureRecovery(const APathKind: Integer);

    /// <summary>Tests that Unload clears the active effective configuration filename.</summary>
    [Test]
    procedure Config_UnloadClears;

    /// <summary>Tests that relative configuration paths expand to absolute paths on Load.</summary>
    [TestCase('SubDir', 'sub/test.cnf')]
    [TestCase('CurrentDir', './test.cnf')]
    procedure Config_RelativePath(const ARelPath: string);

    /// <summary>Tests that configuration paths containing Unicode characters are supported.</summary>
    [TestCase('Accents', 'Conf_éà_Üñîçødé.cnf')]
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

    /// <summary>Verifies stable readiness states through failure, reset, and successful loading.</summary>
    [Test]
    procedure State_Lifecycle;

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

  /// <summary>
  ///   Group 3: Lifecycle action callbacks, execution ordering, and rollback tests.
  /// </summary>
  [TestFixture]
  [Category('Loader,Loader.Callbacks')]
  TLoaderCallbacksFixture = class(TLoaderBaseFixture)
  public
    /// <summary>Initializes the base fixture and resets callback observers and diagnostics injection.</summary>
    [Setup]
    procedure Setup;
    /// <summary>Disables callback observers before restoring the base fixture state.</summary>
    [TearDown]
    procedure Teardown;

    /// <summary>Verifies that OpenSSL routines remain callable during load and unload callbacks in both linking models.</summary>
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
    {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    [Test]
    procedure CB_PreserveDiag;
    {$ENDIF}

    /// <summary>Verifies that callback failure blocks retries until explicit Unload.</summary>
    [Test]
    procedure CB_FailureRecovery;

    /// <summary>Verifies recursive public lifecycle calls raise without altering the outer operation.</summary>
    [TestCase('LoadDuringLoad', '1,0')]
    [TestCase('UnloadDuringLoad', '1,1')]
    [TestCase('RollbackDuringLoad', '1,2')]
    [TestCase('LoadDuringUnload', '2,0')]
    [TestCase('UnloadDuringUnload', '2,1')]
    [TestCase('RollbackDuringUnload', '2,2')]
    procedure State_Recursive(const APhase, AOperation: Integer);

    /// <summary>Verifies an uncaught recursive-call error fails initialization and permits later recovery.</summary>
    [Test]
    procedure State_RecursiveFailure;

    /// <summary>Verifies readiness queries on another thread do not wait for a loading callback.</summary>
    [Test]
    procedure State_ReadDuringLoad;
  end;

implementation

uses
  {$IFDEF MSWINDOWS}
  Winapi.Windows,
  {$ELSE}
  Posix.Stdlib,
  {$ENDIF}
  System.SyncObjs,
  TaurusTLS.UT.Utils,
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_conf;

var
  GLoaderTestLock: TObject;

{ Environment changes are process-wide. The runner must execute these fixtures
  sequentially with other OpenSSL fixtures. The monitor also serializes this base. }

/// <summary>Captures an environment variable without losing its unset state.</summary>
function ReadTestEnv(const AName: string; out AValue: string): Boolean;
{$IFDEF MSWINDOWS}
var
  LSize: DWORD;
begin
  SetLastError(ERROR_SUCCESS);
  LSize := Winapi.Windows.GetEnvironmentVariable(PChar(AName), nil, 0);
  Result := (LSize > 0) or (GetLastError <> ERROR_ENVVAR_NOT_FOUND);
  AValue := System.SysUtils.GetEnvironmentVariable(AName);
end;
{$ELSE}
var
  LValue: MarshaledAString;
begin
  LValue := Posix.Stdlib.getenv(MarshaledAString(UTF8String(AName)));
  Result := LValue <> nil;
  if Result then
    AValue := UTF8ToString(LValue)
  else
    AValue := '';
end;
{$ENDIF}

/// <summary>Sets or removes an environment variable using the platform API.</summary>
procedure WriteTestEnv(const AName, AValue: string; AExists: Boolean);
{$IFDEF MSWINDOWS}
var
  LValue: PChar;
begin
  if AExists then
    LValue := PChar(AValue)
  else
    LValue := nil;
  if not Winapi.Windows.SetEnvironmentVariable(PChar(AName), LValue) then
    RaiseLastOSError;
end;
{$ELSE}
var
  LResult: Integer;
begin
  if AExists then
    LResult := Posix.Stdlib.setenv(MarshaledAString(UTF8String(AName)),
      MarshaledAString(UTF8String(AValue)), 1)
  else
    LResult := Posix.Stdlib.unsetenv(MarshaledAString(UTF8String(AName)));
  if LResult <> 0 then
    raise EInOutError.CreateFmt('Cannot update environment variable %s', [AName]);
end;
{$ENDIF}

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
  Assert.AreEqual(Integer(lLen),
    HexToBin(PChar(AHexStr), 0, Result, 0, lLen), 'Invalid hexadecimal test data');
end;

function TLoaderBaseFixture.HexToUnicodeString(const AHexStr: string): string;
var
  LBytes: TBytes;
begin
  LBytes := HexToBytes(AHexStr);
  Assert.IsFalse(Odd(Length(LBytes)), 'UTF-16LE requires complete code units');
  Result := TEncoding.Unicode.GetString(LBytes);
end;

procedure TLoaderBaseFixture.Setup;
begin
  TMonitor.Enter(GLoaderTestLock);
  FLockHeld := True;
  try
    FLoader := GetOpenSSLLoader;
    Assert.IsNotNull(FLoader);
    Assert.IsFalse(TOsslLoader.Loaded, 'Loader fixtures require exclusive loader ownership');
    FOrigOpenSSLPath := FLoader.OpenSSLPath;
    FOrigSSLLibVersions := FLoader.SSLLibVersions;
    FOrigConfigFile := FLoader.ConfigFile;
    FOrigCurrentDir := GetCurrentDir;
    FHadConfEnv := ReadTestEnv('OPENSSL_CONF', FOrigConfEnv);
    FHadModulesEnv := ReadTestEnv('OPENSSL_MODULES', FOrigModulesEnv);
    FStateCaptured := True;
    FLoader.Unload;
    FLoader.ConfigFile := '';
    if TOsslLoader.Path <> '' then
      FLoader.OpenSSLPath := TOsslLoader.Path;

    FTempDir := TPath.Combine(TPath.GetTempPath, 'TaurusTLS_UT_Loader_' + TGuid.NewGuid.ToString);
    TDirectory.CreateDirectory(FTempDir);
    FValidConfigFile := CreateTempConfigFile(cMinimalValidOpenSSLConfig);
    FInvalidSyntaxConfigFile := CreateTempConfigFile(cMinimalInvalidOpenSSLConfig);
    WriteTestEnv('OPENSSL_CONF', FValidConfigFile, True);
    { No external providers are required by this suite. Prevent machine-specific
      OPENSSL_MODULES values from affecting discovery. }
    WriteTestEnv('OPENSSL_MODULES', FTempDir, True);
  except
    Teardown;
    raise;
  end;
end;

procedure TLoaderBaseFixture.Teardown;
begin
  try
    if FStateCaptured then
    try
      FLoader.Unload;
    finally
      try
        FLoader.ConfigFile := FOrigConfigFile;
      finally
        try
          FLoader.OpenSSLPath := FOrigOpenSSLPath;
        finally
          try
            FLoader.SSLLibVersions := FOrigSSLLibVersions;
          finally
            try
              if not SetCurrentDir(FOrigCurrentDir) then
                raise EInOutError.Create('Cannot restore current directory');
            finally
              try
                WriteTestEnv('OPENSSL_CONF', FOrigConfEnv, FHadConfEnv);
              finally
                WriteTestEnv('OPENSSL_MODULES', FOrigModulesEnv, FHadModulesEnv);
              end;
            end;
          end;
        end;
      end;
    end;
  finally
    FStateCaptured := False;
    try
      if (FTempDir <> '') and TDirectory.Exists(FTempDir) then
        TDirectory.Delete(FTempDir, True);
      FTempDir := '';
    finally
      FLoader := nil;
      if FLockHeld then
      begin
        FLockHeld := False;
        TMonitor.Exit(GLoaderTestLock);
      end;
    end;
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
  Assert.IsTrue(FLoader.State = lsLoadedFailed);
  Assert.IsFalse(FLoader.IsLoaded);
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
  Assert.IsTrue(FLoader.State = lsLoadedFailed);
  Assert.IsFalse(FLoader.IsLoaded);
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
var
  LDefaultConfig: PIdAnsiChar;
  LExpectedPath: string;
begin
  FLoader.ConfigFile := '';
  Assert.IsTrue(FLoader.Load, 'Loader.Load failed');
  try
    Assert.IsTrue(FLoader.IsLoaded);
    // Discovery reports a filename; this does not read the machine's config.
    // Query the native API because its C-runtime environment may differ from
    // the environment seen by Delphi, especially when launched from the IDE.
    LExpectedPath := '';
    LDefaultConfig := CONF_get1_default_config_file();
    if Assigned(LDefaultConfig) then
    try
      LExpectedPath := UTF8ToString(LDefaultConfig);
    finally
      OPENSSL_free(LDefaultConfig);
    end;
    Assert.AreEqual(LExpectedPath, FLoader.ConfigFile,
      'Loader must report the native discovery result');
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

  Assert.IsTrue(SetCurrentDir(FTempDir), 'Cannot set relative-path test directory');
  // The OS may report a physical directory instead of its temporary-path alias.
  LNormalized := TPath.GetFullPath(TPath.Combine(GetCurrentDir, ARelPath));
  FLoader.ConfigFile := ARelPath;
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

procedure TLoaderConfigFixture.Config_PathFailureRecovery(const APathKind: Integer);
begin
  if APathKind = 0 then
    FLoader.ConfigFile := TPath.Combine(FTempDir, 'missing.cnf')
  else
    FLoader.ConfigFile := FTempDir;
  Assert.WillRaise(
    procedure
    begin
      FLoader.Load;
    end, ETaurusTLSConfigFilePathError);
  Assert.IsFalse(FLoader.IsLoaded);
  FLoader.ConfigFile := FValidConfigFile;
  Assert.IsFalse(FLoader.Load, 'Correcting a path must not reset the circuit breaker');
  FLoader.Unload;
  Assert.IsTrue(FLoader.Load, 'Explicit Unload must permit a corrected path to load');
  Assert.IsTrue(FLoader.IsLoaded);
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
  Assert.AreEqual('', LLoader.SSLLibVersions, 'SSLLibVersions must be empty in static mode');
  Assert.AreEqual(0, LLoader.FailedToLoad.Count, 'FailedToLoad must be empty in static mode');
end;
{$ENDIF}

procedure TLoaderLifecycleFixture.State_Lifecycle;
begin
  Assert.IsTrue(FLoader.State = lsNotLoaded);
  Assert.IsFalse(FLoader.IsLoaded);
  FLoader.ConfigFile := FInvalidSyntaxConfigFile;
  Assert.WillRaise(
    procedure
    begin
      FLoader.Load;
    end, ETaurusTLSConfigFileLoadError);
  Assert.IsTrue(FLoader.State = lsLoadedFailed);
  Assert.IsFalse(FLoader.IsLoaded);
  // Binding diagnostics are independent of the circuit breaker.
  FLoader.FailedToLoad.Clear;
  Assert.IsTrue(FLoader.State = lsLoadedFailed,
    'Clearing binding diagnostics must not clear failure state');
  Assert.IsFalse(FLoader.IsLoaded);
  FLoader.ConfigFile := FValidConfigFile;
  Assert.IsFalse(FLoader.Load);
  Assert.IsTrue(FLoader.State = lsLoadedFailed);
  FLoader.Unload;
  Assert.IsTrue(FLoader.State = lsNotLoaded);
  Assert.IsTrue(FLoader.Load);
  Assert.IsTrue(FLoader.State = lsLoadedReady);
  Assert.IsTrue(FLoader.IsLoaded);
  Assert.IsTrue(FLoader.Load);
  Assert.IsTrue(FLoader.State = lsLoadedReady);
  FLoader.Unload(False);
  Assert.IsTrue(FLoader.State = lsLoadedFailed);
  Assert.IsFalse(FLoader.Load);
  FLoader.Unload;
  FLoader.Unload;
  Assert.IsTrue(FLoader.State = lsNotLoaded);
  Assert.IsFalse(FLoader.IsLoaded);
end;

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

{ TLoaderCallbacksFixture }

var
  TTestCallbackLog: TStringList = nil;
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  GTestSymbolInjectorActive: Boolean = False;
  {$ENDIF}

type
  TTestCallbackObserverA = class
  public
    class var Active: Boolean;
    class var VerifyHandlesLive: Boolean;
    class var LoadState: TTaurusTLSLoaderState;
    class var UnloadState: TTaurusTLSLoaderState;
    class var LoadedOnLoad: Boolean;
    class var LoadedOnUnload: Boolean;
    class var RecursivePhase: Integer;
    class var RecursiveOperation: Integer;
    class var RecursiveRejected: Boolean;
    class var PropagateRecursive: Boolean;
    class var QueryDone: TEvent;
    class var QueryThread: TThread;
    class var QueryState: TTaurusTLSLoaderState;
    class var QueryLoaded: Boolean;
    /// <summary>Records lifecycle actions and optionally verifies that OpenSSL routines remain callable.</summary>
    /// <param name="AAction">The load or unload action dispatched by the loader.</param>
    class procedure ActionProc(AAction: TOpenSSLLoadAction);
  end;

  TTestCallbackObserverB = class
  public
    class var Active: Boolean;
    class var ThrowOnLoad: Boolean;
    /// <summary>Records lifecycle actions or raises a simulated load failure to exercise rollback.</summary>
    /// <param name="AAction">The load or unload action dispatched by the loader.</param>
    class procedure ActionProc(AAction: TOpenSSLLoadAction);
  end;

class procedure TTestCallbackObserverA.ActionProc(AAction: TOpenSSLLoadAction);
begin
  if not Active then
    Exit;

  if AAction = osaLoad then
  begin
    LoadState := GetOpenSSLLoader.State;
    LoadedOnLoad := GetOpenSSLLoader.IsLoaded;
    if Assigned(QueryDone) then
    begin
      QueryThread := TThread.CreateAnonymousThread(
        procedure
        begin
          try
            QueryState := GetOpenSSLLoader.State;
            QueryLoaded := GetOpenSSLLoader.IsLoaded;
          finally
            QueryDone.SetEvent;
          end;
        end);
      QueryThread.FreeOnTerminate := False;
      QueryThread.Start;
      Assert.IsTrue(QueryDone.WaitFor(5000) = wrSignaled,
        'Readiness queries must not wait for the lifecycle lock');
    end;
  end
  else
  begin
    UnloadState := GetOpenSSLLoader.State;
    LoadedOnUnload := GetOpenSSLLoader.IsLoaded;
  end;

  if ((RecursivePhase = 1) and (AAction = osaLoad)) or
    ((RecursivePhase = 2) and (AAction = osaUnload)) then
  try
    case RecursiveOperation of
      0: GetOpenSSLLoader.Load;
      1: GetOpenSSLLoader.Unload;
      2: GetOpenSSLLoader.Unload(False);
    end;
  except
    on E: ETaurusTLSLoaderError do
    begin
      RecursiveRejected := True;
      if PropagateRecursive then
        raise;
    end;
  end;

  if VerifyHandlesLive then
  begin
    {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    Assert.IsTrue(Assigned(OpenSSL_version_num), 'Version routine must remain bound');
    {$ENDIF}
    if OpenSSL_version_num() >= min_supported_ssl_version then
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

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
/// <summary>Adds a synthetic missing-symbol diagnostic when injection is enabled.</summary>
/// <param name="ADllHandle">The library handle supplied by the header-binding dispatcher; unused.</param>
/// <param name="LibVersion">The library version supplied by the dispatcher; unused.</param>
/// <param name="AFailed">The diagnostic list that receives the synthetic entry, if assigned.</param>
procedure TestSymbolInjectorLoadProc(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);
begin
  if GTestSymbolInjectorActive and Assigned(AFailed) then
    AFailed.Add('Fake_Diagnostic_Symbol');
end;
{$ENDIF}

procedure TLoaderCallbacksFixture.Setup;
begin
  inherited Setup;
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  GTestSymbolInjectorActive := False;
  {$ENDIF}
  if Assigned(TTestCallbackLog) then
    TTestCallbackLog.Clear;
  TTestCallbackObserverA.Active := False;
  TTestCallbackObserverA.VerifyHandlesLive := False;
  TTestCallbackObserverA.LoadState := lsLoadedFailed;
  TTestCallbackObserverA.UnloadState := lsLoadedFailed;
  TTestCallbackObserverA.RecursivePhase := 0;
  TTestCallbackObserverA.RecursiveRejected := False;
  TTestCallbackObserverA.PropagateRecursive := False;
  TTestCallbackObserverB.Active := False;
  TTestCallbackObserverB.ThrowOnLoad := False;
end;

procedure TLoaderCallbacksFixture.Teardown;
begin
  if Assigned(TTestCallbackObserverA.QueryThread) then
  begin
    // The outer lifecycle operation has released its lock before teardown.
    TTestCallbackObserverA.QueryThread.WaitFor;
    FreeAndNil(TTestCallbackObserverA.QueryThread);
  end;
  FreeAndNil(TTestCallbackObserverA.QueryDone);
  TTestCallbackObserverA.Active := False;
  TTestCallbackObserverA.VerifyHandlesLive := False;
  TTestCallbackObserverB.Active := False;
  TTestCallbackObserverB.ThrowOnLoad := False;
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
      Assert.IsTrue(TTestCallbackObserverA.LoadState = lsNotLoaded);
      Assert.IsFalse(TTestCallbackObserverA.LoadedOnLoad);
      Assert.IsTrue(FLoader.State = lsLoadedReady);
    finally
      FLoader.Unload;
    end;

    Assert.AreEqual(2, TTestCallbackLog.Count);
    Assert.AreEqual('A:Unload:Live', TTestCallbackLog[1]);
    Assert.IsTrue(TTestCallbackObserverA.UnloadState = lsNotLoaded);
    Assert.IsFalse(TTestCallbackObserverA.LoadedOnUnload);
    Assert.IsTrue(FLoader.State = lsNotLoaded);
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
    Assert.IsTrue(FLoader.Load, 'A new load cycle must succeed');
    FLoader.Unload;
    Assert.AreEqual(4, TTestCallbackLog.Count);
    Assert.AreEqual('A:Load', TTestCallbackLog[2]);
    Assert.AreEqual('A:Unload', TTestCallbackLog[3]);
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
    Assert.IsTrue(TTestCallbackObserverA.UnloadState = lsNotLoaded);
    Assert.IsFalse(TTestCallbackObserverA.LoadedOnUnload);
    Assert.IsTrue(FLoader.State = lsLoadedFailed);
    Assert.IsFalse(FLoader.IsLoaded);
  finally
    TTestCallbackObserverB.ThrowOnLoad := False;
    TTestCallbackObserverA.Active := False;
    TTestCallbackObserverB.Active := False;
    FLoader.Unload;
  end;
end;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
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

procedure TLoaderCallbacksFixture.CB_FailureRecovery;
begin
  TTestCallbackObserverA.Active := True;
  TTestCallbackObserverB.Active := True;
  TTestCallbackObserverB.ThrowOnLoad := True;
  FLoader.ConfigFile := FValidConfigFile;
  Assert.WillRaiseWithMessage(
    procedure
    begin
      FLoader.Load;
    end,
    Exception, 'Simulated action failure in Observer B');
  Assert.IsFalse(FLoader.IsLoaded);
  Assert.AreEqual(2, TTestCallbackLog.Count);
  TTestCallbackObserverB.ThrowOnLoad := False;
  Assert.IsFalse(FLoader.Load, 'Callback failure must trip the circuit breaker');
  Assert.AreEqual(2, TTestCallbackLog.Count, 'Blocked load must not dispatch callbacks');
  FLoader.Unload;
  Assert.IsTrue(FLoader.Load, 'Explicit Unload must permit recovery');
  FLoader.Unload;
  Assert.AreEqual(6, TTestCallbackLog.Count);
  Assert.AreEqual('A:Load', TTestCallbackLog[2]);
  Assert.AreEqual('B:Load', TTestCallbackLog[3]);
  Assert.AreEqual('B:Unload', TTestCallbackLog[4]);
  Assert.AreEqual('A:Unload', TTestCallbackLog[5]);
end;

procedure TLoaderCallbacksFixture.State_Recursive(const APhase, AOperation: Integer);
begin
  TTestCallbackObserverA.Active := True;
  TTestCallbackObserverA.RecursivePhase := APhase;
  TTestCallbackObserverA.RecursiveOperation := AOperation;
  FLoader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(FLoader.Load);
  Assert.IsTrue(FLoader.State = lsLoadedReady);
  FLoader.Unload;
  Assert.IsTrue(TTestCallbackObserverA.RecursiveRejected,
    'Recursive lifecycle calls must raise ETaurusTLSLoaderError');
  Assert.IsTrue(FLoader.State = lsNotLoaded);
  Assert.AreEqual(2, TTestCallbackLog.Count, 'Only the outer operation dispatches callbacks');
end;

procedure TLoaderCallbacksFixture.State_RecursiveFailure;
begin
  TTestCallbackObserverA.Active := True;
  TTestCallbackObserverA.RecursivePhase := 1;
  TTestCallbackObserverA.RecursiveOperation := 0;
  TTestCallbackObserverA.PropagateRecursive := True;
  FLoader.ConfigFile := FValidConfigFile;
  Assert.WillRaise(
    procedure
    begin
      FLoader.Load;
    end, ETaurusTLSLoaderError);
  Assert.IsTrue(TTestCallbackObserverA.RecursiveRejected);
  Assert.IsTrue(FLoader.State = lsLoadedFailed);
  Assert.IsFalse(FLoader.Load);
  Assert.AreEqual(0, TTestCallbackLog.Count, 'Failed action did not complete');
  FLoader.Unload;
  TTestCallbackObserverA.RecursivePhase := 0;
  Assert.IsTrue(FLoader.Load);
  Assert.IsTrue(FLoader.State = lsLoadedReady);
  FLoader.Unload;
end;

procedure TLoaderCallbacksFixture.State_ReadDuringLoad;
begin
  TTestCallbackObserverA.Active := True;
  TTestCallbackObserverA.QueryDone := TEvent.Create(nil, True, False, '');
  FLoader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(FLoader.Load);
  TTestCallbackObserverA.QueryThread.WaitFor;
  Assert.IsTrue(TTestCallbackObserverA.QueryState = lsNotLoaded);
  Assert.IsFalse(TTestCallbackObserverA.QueryLoaded);
  Assert.IsTrue(FLoader.State = lsLoadedReady);
end;

initialization
  GLoaderTestLock := TObject.Create;
  TDUnitX.RegisterTestFixture(TLoaderConfigFixture);
  TDUnitX.RegisterTestFixture(TLoaderLifecycleFixture);
  TDUnitX.RegisterTestFixture(TLoaderCallbacksFixture);
  TTestCallbackLog := TStringList.Create;
  Register_SSLLoaderAction(TTestCallbackObserverA.ActionProc);
  Register_SSLLoaderAction(TTestCallbackObserverB.ActionProc);
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Register_SSLLoader(TestSymbolInjectorLoadProc, 'LibCrypto');
{$ENDIF}

finalization
  FreeAndNil(TTestCallbackLog);
  FreeAndNil(GLoaderTestLock);

end.
