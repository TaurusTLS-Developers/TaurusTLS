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
  TaurusTLSConsts,
  TaurusTLS.UT.TestClasses;

type
  /// <summary>
  ///   Base fixture providing shared setup, teardown, and temporary configuration file helpers.
  /// </summary>
  TLoaderBaseFixture = class(TOsslBaseFixture)
  protected
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
  ///   Group 2: Repeated load/unload calls, state persistence, mutation guards, and circuit breaker tests.
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

    /// <summary>Tests that a second Load succeeds without repeating initialization.</summary>
    [Test]
    procedure Life_DoubleLoad;

    /// <summary>Verifies stable readiness states through failure, reset, and successful loading.</summary>
    [Test]
    procedure State_Lifecycle;

    /// <summary>Verifies concurrent queries share one loader and concurrent action registrations are retained.</summary>
    [TestCase('Queries', '0')]
    [TestCase('Registrations', '1')]
    procedure Life_ConcurrentSingleton(const ARegister: Integer);

    /// <summary>Competing Load callers wait for one initialization and share its ready result.</summary>
    [TestCase('Workers2', '2')]
    [TestCase('Workers3', '3')]
    [TestCase('Workers15', '15')]
    [TestCase('Workers32', '32')]
    procedure Life_ConcurrentLoad(const AWorkerCount: Integer);

    {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    /// <summary>Verifies missing libraries fail without dispatching actions and permit explicit recovery.</summary>
    [Test]
    procedure Life_MissingLibraries;
    {$IFDEF MSWINDOWS}
    /// <summary>Verifies a crypto-only deployment releases its partial library handle after failure.</summary>
    [Test]
    procedure Life_PartialLibrary;
    {$ENDIF}
    {$ENDIF}

    /// <summary>Tests that successive Unload calls are safe no-ops.</summary>
    [Test]
    procedure Life_DoubleUnload;

    /// <summary>Tests that repeated Load calls preserve the active configuration.</summary>
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
    [TestCase('RegisterDuringLoad', '1,3')]
    [TestCase('RegisterDuringUnload', '2,3')]
    [TestCase('UnregisterDuringLoad', '1,4')]
    [TestCase('UnregisterDuringUnload', '2,4')]
    procedure State_Recursive(const APhase, AOperation: Integer);

    /// <summary>Ready registration runs immediately; failed registration requires reset.</summary>
    [TestCase('Ready', '0')]
    [TestCase('Failed', '1')]
    procedure CB_RegistrationState(const AFailed: Integer);
    [TestCase('Inactive', '0')]
    [TestCase('Ready', '1')]
    [TestCase('Failed', '2')]
    procedure CB_Unregister(const AState: Integer);
    [Test]
    procedure CB_RegistrationIdentity;
    [TestCase('Load', '0')]
    [TestCase('Unload', '1')]
    procedure CB_ImmediateFailure(const AUnload: Integer);
    [TestCase('LoadDuringAdd', '0,0')]
    [TestCase('UnloadDuringAdd', '0,1')]
    [TestCase('RegisterDuringAdd', '0,2')]
    [TestCase('UnregisterDuringAdd', '0,3')]
    [TestCase('LoadDuringRemove', '1,0')]
    [TestCase('UnloadDuringRemove', '1,1')]
    [TestCase('RegisterDuringRemove', '1,2')]
    [TestCase('UnregisterDuringRemove', '1,3')]
    procedure CB_ImmediateReentry(const AUnload, AOperation: Integer);
    [TestCase('Register', '0')]
    [TestCase('Unregister', '1')]
    procedure CB_ConcurrentMutation(const ARemove: Integer);

    /// <summary>Concurrent workers register/remove distinct actions once without changing readiness.</summary>
    /// <remarks>Worker count and initial readiness are supplied by each test case; no stress loops.</remarks>
    [TestCase('Inactive2', '2,0')]
    [TestCase('Ready2', '2,1')]
    [TestCase('Inactive3', '3,0')]
    [TestCase('Ready3', '3,1')]
    [TestCase('Inactive15', '15,0')]
    [TestCase('Ready15', '15,1')]
    [TestCase('Inactive32', '32,0')]
    [TestCase('Ready32', '32,1')]
    procedure CB_ConcurrentActions(const AWorkerCount, AReady: Integer);

    /// <summary>Verifies an uncaught recursive-call error fails initialization and permits later recovery.</summary>
    [Test]
    procedure State_RecursiveFailure;

    /// <summary>Verifies readiness queries on another thread do not wait for a loading callback.</summary>
    [Test]
    procedure State_ReadDuringLoad;

    /// <summary>Verifies readiness queries on another thread do not wait for an unloading callback.</summary>
    [Test]
    procedure State_ReadDuringUnload;

    /// <summary>Verifies changed values are rejected and repeated inputs are safe during callbacks.</summary>
    [TestCase('LoadConfigChange', '1,0,0')]
    [TestCase('UnloadConfigChange', '2,0,0')]
    [TestCase('RollbackConfigChange', '3,0,0')]
    [TestCase('LoadConfigRepeat', '1,0,1')]
    [TestCase('UnloadConfigRepeat', '2,0,1')]
    [TestCase('RollbackConfigRepeat', '3,0,1')]
    [TestCase('LoadPathChange', '1,1,0')]
    [TestCase('UnloadPathChange', '2,1,0')]
    [TestCase('RollbackPathChange', '3,1,0')]
    [TestCase('LoadPathRepeat', '1,1,1')]
    [TestCase('UnloadPathRepeat', '2,1,1')]
    [TestCase('RollbackPathRepeat', '3,1,1')]
    [TestCase('LoadVersionsChange', '1,2,0')]
    [TestCase('UnloadVersionsChange', '2,2,0')]
    [TestCase('RollbackVersionsChange', '3,2,0')]
    [TestCase('LoadVersionsRepeat', '1,2,1')]
    [TestCase('UnloadVersionsRepeat', '2,2,1')]
    [TestCase('RollbackVersionsRepeat', '3,2,1')]
    procedure Config_CallbackMutation(const APhase, AProperty, ARepeat: Integer);

    /// <summary>Verifies effective filename publication follows successful readiness.</summary>
    [TestCase('Absolute', '0')]
    [TestCase('Relative', '1')]
    procedure Config_Publication(const ARelative: Integer);

    /// <summary>Verifies rollback retains configured input without publishing a ready filename.</summary>
    [Test]
    procedure Config_RollbackPublication;

    /// <summary>Verifies metadata and compatibility queries never initialize OpenSSL.</summary>
    [Test]
    procedure Info_Passive;

    /// <summary>Verifies modern metadata values, callback visibility, and cleanup.</summary>
    [Test]
    procedure Info_NativeValues;

    /// <summary>Verifies configuration directories remain fixed after changing the working directory.</summary>
    [TestCase('Absolute', '0')]
    [TestCase('Relative', '1')]
    [TestCase('UnicodeDirectory', '2')]
    procedure Info_ConfigDirectory(const AKind: Integer);

    /// <summary>Verifies direct and compatibility loads share TLS initialization and ownership.</summary>
    [Test]
    procedure Runtime_SharedLifecycle;

    /// <summary>Verifies TLS runtime resources are released when a later loader action fails.</summary>
    [Test]
    procedure Runtime_ActionFailure;

    {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    /// <summary>Verifies unavailable native metadata is represented by empty values.</summary>
    [TestCase('NullResult', '0')]
    [TestCase('MissingSymbol', '1')]
    procedure Info_Unavailable(const AKind: Integer);

    /// <summary>Verifies empty and relative native discovery filenames have stable directory semantics.</summary>
    [TestCase('Empty', '0')]
    [TestCase('Relative', '1')]
    procedure Info_Discovery(const AKind: Integer);

    /// <summary>Verifies native crypto/SSL initialization failure occurs before runtime callbacks.</summary>
    [TestCase('Crypto', '0')]
    [TestCase('SSL', '1')]
    procedure Runtime_InitFailure(const AKind: Integer);
    {$ENDIF}

    /// <summary>Verifies unload-action failures do not prevent later action cleanup.</summary>
    [Test]
    procedure Life_UnloadActionFailure;

    {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    /// <summary>Verifies all symbol resetters run and readiness fails when cleanup raises.</summary>
    [TestCase('SingleFailure', '0')]
    [TestCase('MultipleFailures', '1')]
    procedure Life_UnloaderFailure(const ASecondFailure: Integer);

    /// <summary>Verifies a load exception survives a subsequent header-cleanup exception.</summary>
    [Test]
    procedure Life_PreserveLoadError;
    {$ENDIF}
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
  TaurusTLSHeaders_conf,
  TaurusTLSHeaders_ssl,
  TaurusTLSHeaders_types,
  TaurusTLS;

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
    Assert.IsNotNull(Loader);
    Assert.IsFalse(Loader.IsLoaded, 'Loader fixtures require exclusive loader ownership');
    FOrigOpenSSLPath := Loader.OpenSSLPath;
    FOrigSSLLibVersions := Loader.SSLLibVersions;
    FOrigConfigFile := Loader.ConfigFile;
    FOrigCurrentDir := GetCurrentDir;
    FHadConfEnv := ReadTestEnv('OPENSSL_CONF', FOrigConfEnv);
    FHadModulesEnv := ReadTestEnv('OPENSSL_MODULES', FOrigModulesEnv);
    FStateCaptured := True;
    Loader.Unload;
    SetupFromCmd;
    // Lifecycle tests select isolated configs instead of the command-line config.
    Loader.ConfigFile := '';

    FTempDir := TPath.Combine(TPath.GetTempPath, 'TaurusTLS_UT_Loader_' + TGuid.NewGuid.ToString);
    TDirectory.CreateDirectory(FTempDir);
    FValidConfigFile := CreateTempConfigFile(cMinimalValidOpenSSLConfig);
    FInvalidSyntaxConfigFile := CreateTempConfigFile(cMinimalInvalidOpenSSLConfig);
    WriteTestEnv('OPENSSL_CONF', FValidConfigFile, True);
    { No external providers are required by this suite. Prevent machine-specific
      OPENSSL_MODULES values from affecting discovery. }
    WriteTestEnv('OPENSSL_MODULES', FTempDir, True);
  except
    try
      Teardown;
    except
      on E: Exception do
        Log(TLogLevel.Error, 'Loader fixture setup cleanup: ' + E.Message);
    end;
    raise;
  end;
end;

procedure TLoaderBaseFixture.Teardown;
begin
  try
    if FStateCaptured then
    try
      Loader.Unload;
    finally
      try
        Loader.ConfigFile := FOrigConfigFile;
      finally
        try
          Loader.OpenSSLPath := FOrigOpenSSLPath;
        finally
          try
            Loader.SSLLibVersions := FOrigSSLLibVersions;
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
  Assert.IsNotNull(Loader);
  Assert.IsFalse(Loader.IsLoaded);
  Assert.AreEqual('', Loader.ConfigFile);
end;

procedure TLoaderConfigFixture.Config_SetValid;
var
  LPath: string;
begin
  LPath := 'some_relative/config.cnf';
  Loader.ConfigFile := LPath;
  Assert.AreEqual(LPath, Loader.ConfigFile);
  Assert.IsTrue(Loader.State = lsNotLoaded, 'Selecting a config must not load OpenSSL');
  Assert.IsFalse(Loader.IsLoaded);
  Loader.ConfigFile := '';
end;

procedure TLoaderConfigFixture.Config_InvalidChars(const AHexPath: string);
var
  LPath: string;
begin
  LPath := HexToUnicodeString(AHexPath);
  Assert.WillRaiseWithMessage(
    procedure
    begin
      Loader.ConfigFile := LPath;
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
  Loader.ConfigFile := FTempDir;
  Assert.WillRaiseWithMessage(
    procedure
    begin
      Loader.Load;
    end,
    ETaurusTLSConfigFilePathError,
    Format(RSOSSLConfigFileIsDirectory, [LNormalizedDir])
  );
  Assert.IsTrue(Loader.State = lsLoadedFailed);
  Assert.IsFalse(Loader.IsLoaded);
end;

procedure TLoaderConfigFixture.Config_RejectMissing;
var
  LNonExistent: string;
  LNormalized: string;
begin
  LNonExistent := TPath.Combine(FTempDir, 'does_not_exist_' + TGuid.NewGuid.ToString + '.cnf');
  LNormalized := TPath.GetFullPath(LNonExistent);
  Loader.ConfigFile := LNonExistent;
  Assert.WillRaiseWithMessage(
    procedure
    begin
      Loader.Load;
    end,
    ETaurusTLSConfigFilePathError,
    Format(RSOSSLConfigFileNotFound, [LNormalized])
  );
  Assert.IsTrue(Loader.State = lsLoadedFailed);
  Assert.IsFalse(Loader.IsLoaded);
end;

procedure TLoaderConfigFixture.Config_ValidLoad;
var
  LNormalized: string;
begin
  LNormalized := TPath.GetFullPath(FValidConfigFile);
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(Loader.Load, 'Loader.Load with valid config failed');
  try
    Assert.IsTrue(Loader.IsLoaded);
    Assert.AreEqual(LNormalized, Loader.ConfigFile);
  finally
    Loader.Unload;
  end;
end;

procedure TLoaderConfigFixture.Config_InvalidSyntax;
var
  LNormalized: string;
  LExMsgExpected: string;
begin
  LNormalized := TPath.GetFullPath(FInvalidSyntaxConfigFile);
  LExMsgExpected := Format(RSOSSLConfigFileLoadFailed, [LNormalized]);
  Loader.ConfigFile := FInvalidSyntaxConfigFile;

  try
    Loader.Load;
    Assert.Fail('Expected ETaurusTLSConfigFileLoadError was not raised');
  except
    on E: ETaurusTLSConfigFileLoadError do
    begin
      Assert.IsTrue(E.Message.StartsWith(LExMsgExpected),
        Format('Exception message "%s" should start with "%s"', [E.Message, LExMsgExpected]));
    end;
  end;

  // Circuit breaker: subsequent call immediately returns False without re-attempting
  Assert.IsFalse(Loader.IsLoaded, 'Loader must not be in loaded state after failure');
  Assert.IsFalse(Loader.Load, 'Subsequent Load must return False due to FFailedToLoad circuit breaker');
end;

procedure TLoaderConfigFixture.Config_UnloadClears;
var
  LDefaultConfig: PIdAnsiChar;
  LExpectedPath: string;
begin
  Loader.ConfigFile := '';
  Assert.IsTrue(Loader.Load, 'Loader.Load failed');
  try
    Assert.IsTrue(Loader.IsLoaded);
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
    Assert.AreEqual(LExpectedPath, Loader.ConfigFile,
      'Loader must report the native discovery result');
  finally
    Loader.Unload;
  end;
  Assert.IsFalse(Loader.IsLoaded);
  Assert.AreEqual('', Loader.ConfigFile);
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
  Loader.ConfigFile := ARelPath;
  Assert.IsTrue(Loader.Load, 'Load failed for relative config path');
  try
    Assert.IsTrue(Loader.IsLoaded);
    Assert.AreEqual(LNormalized, Loader.ConfigFile);
  finally
    Loader.Unload;
  end;
end;

procedure TLoaderConfigFixture.Config_UnicodePath(const AUnicodeFileName: string);
var
  LFilePath: string;
  LNormalized: string;
begin
  LFilePath := CreateTempConfigFile(cMinimalValidOpenSSLConfig, AUnicodeFileName);
  LNormalized := TPath.GetFullPath(LFilePath);

  Loader.ConfigFile := LFilePath;
  Assert.IsTrue(Loader.Load, 'Load failed with Unicode config filename');
  try
    Assert.IsTrue(Loader.IsLoaded);
    Assert.AreEqual(LNormalized, Loader.ConfigFile);
  finally
    Loader.Unload;
  end;
end;

procedure TLoaderConfigFixture.Config_PathFailureRecovery(const APathKind: Integer);
begin
  if APathKind = 0 then
    Loader.ConfigFile := TPath.Combine(FTempDir, 'missing.cnf')
  else
    Loader.ConfigFile := FTempDir;
  Assert.WillRaise(
    procedure
    begin
      Loader.Load;
    end, ETaurusTLSConfigFilePathError);
  Assert.IsFalse(Loader.IsLoaded);
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsFalse(Loader.Load, 'Correcting a path must not reset the circuit breaker');
  Loader.Unload;
  Assert.IsTrue(Loader.Load, 'Explicit Unload must permit a corrected path to load');
  Assert.IsTrue(Loader.IsLoaded);
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
  LLoader.OpenSSLPath := 'ignored-static-path';
  LLoader.SSLLibVersions := 'ignored-static-versions';
  Assert.AreEqual('', LLoader.OpenSSLPath);
  Assert.AreEqual('', LLoader.SSLLibVersions);
  Assert.IsTrue(LLoader.State = lsNotLoaded, 'Inert setters must not initialize OpenSSL');
  Assert.AreEqual(0, LLoader.FailedToLoad.Count, 'FailedToLoad must be empty in static mode');
end;
{$ENDIF}

procedure TLoaderLifecycleFixture.State_Lifecycle;
begin
  Assert.IsTrue(Loader.State = lsNotLoaded);
  Assert.IsFalse(Loader.IsLoaded);
  Loader.ConfigFile := FInvalidSyntaxConfigFile;
  Assert.WillRaise(
    procedure
    begin
      Loader.Load;
    end, ETaurusTLSConfigFileLoadError);
  Assert.IsTrue(Loader.State = lsLoadedFailed);
  Assert.IsFalse(Loader.IsLoaded);
  // Binding diagnostics are independent of the circuit breaker.
  Loader.FailedToLoad.Clear;
  Assert.IsTrue(Loader.State = lsLoadedFailed,
    'Clearing binding diagnostics must not clear failure state');
  Assert.IsFalse(Loader.IsLoaded);
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsFalse(Loader.Load);
  Assert.IsTrue(Loader.State = lsLoadedFailed);
  Loader.Unload;
  Assert.IsTrue(Loader.State = lsNotLoaded);
  Assert.IsTrue(Loader.Load);
  Assert.IsTrue(Loader.State = lsLoadedReady);
  Assert.IsTrue(Loader.IsLoaded);
  Assert.IsTrue(Loader.Load);
  Assert.IsTrue(Loader.State = lsLoadedReady);
  Loader.Unload(False);
  Assert.IsTrue(Loader.State = lsLoadedFailed);
  Assert.IsFalse(Loader.Load);
  Loader.Unload;
  Loader.Unload;
  Assert.IsTrue(Loader.State = lsNotLoaded);
  Assert.IsFalse(Loader.IsLoaded);
end;

procedure TLoaderLifecycleFixture.Life_DoubleLoad;
begin
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(Loader.Load, 'Initial Load failed');
  try
    Assert.IsTrue(Loader.IsLoaded);
    Assert.IsTrue(Loader.Load, 'Second Load call should succeed idempotently');
    Assert.IsTrue(Loader.IsLoaded);
  finally
    Loader.Unload;
  end;
end;

procedure TLoaderLifecycleFixture.Life_DoubleUnload;
begin
  Loader.Unload;
  Loader.Unload;
  Assert.IsFalse(Loader.IsLoaded);

  Loader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(Loader.Load, 'Load failed');
  Loader.Unload;
  Assert.IsFalse(Loader.IsLoaded);
  Loader.Unload;
  Assert.IsFalse(Loader.IsLoaded);
end;

procedure TLoaderLifecycleFixture.Life_PreserveConfig;
var
  LNormalized: string;
begin
  LNormalized := TPath.GetFullPath(FValidConfigFile);
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(Loader.Load, 'Initial Load failed');
  try
    Assert.AreEqual(LNormalized, Loader.ConfigFile);
    Assert.IsTrue(Loader.Load, 'Second Load should succeed');
    Assert.AreEqual(LNormalized, Loader.ConfigFile, 'Effective config must be preserved on second Load');
  finally
    Loader.Unload;
  end;
end;

procedure TLoaderLifecycleFixture.Life_CircuitBreaker;
begin
  Loader.ConfigFile := FInvalidSyntaxConfigFile;
  try
    Loader.Load;
    Assert.Fail('Expected ETaurusTLSConfigFileLoadError was not raised');
  except
    on ETaurusTLSConfigFileLoadError do ;
  end;

  Assert.IsFalse(Loader.IsLoaded, 'Loader must not be loaded after failure');
  Assert.IsFalse(Loader.Load, 'Subsequent Load must return False while failure state is active');

  Loader.Unload;
  Assert.IsFalse(Loader.IsLoaded);

  Loader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(Loader.Load, 'Load should succeed after explicit Unload resets failure state');
  try
    Assert.IsTrue(Loader.IsLoaded);
  finally
    Loader.Unload;
  end;
end;

procedure TLoaderLifecycleFixture.Life_RejectConfigWhenLoaded;
begin
  // Load with default/empty configuration
  Loader.ConfigFile := '';
  Assert.IsTrue(Loader.Load, 'Initial Load failed');
  try
    Assert.IsTrue(Loader.IsLoaded);
    Assert.WillRaiseWithMessage(
      procedure
      begin
        // Attempt to assign a new configuration while loaded
        Loader.ConfigFile := FValidConfigFile;
      end,
      ETaurusTLSConfigFilePathError,
      RSOSSLConfigFileAlreadyLoaded
    );
  finally
    Loader.Unload;
  end;
end;

procedure TLoaderLifecycleFixture.Life_MutateWhenFailed(const APropId: Integer);
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  LOrigPath: string;
  LOrigVersions: string;
{$ENDIF}
begin
  Loader.ConfigFile := FInvalidSyntaxConfigFile;
  try
    Loader.Load;
    Assert.Fail('Expected ETaurusTLSConfigFileLoadError was not raised');
  except
    on ETaurusTLSConfigFileLoadError do ;
  end;

  Assert.IsFalse(Loader.IsLoaded, 'Loader must not be in loaded state after failure');

  case APropId of
    0:
      begin
        Loader.ConfigFile := FValidConfigFile;
        Assert.AreEqual(FValidConfigFile, Loader.ConfigFile);
      end;
    {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    1:
      begin
        LOrigPath := Loader.OpenSSLPath;
        try
          Loader.OpenSSLPath := FTempDir;
          Assert.AreEqual(IncludeTrailingPathDelimiter(FTempDir), Loader.OpenSSLPath);
        finally
          Loader.OpenSSLPath := LOrigPath; // Restore valid library path
        end;
      end;
    2:
      begin
        LOrigVersions := Loader.SSLLibVersions;
        try
          Loader.SSLLibVersions := DefaultLibVersions;
          Assert.AreEqual(DefaultLibVersions, Loader.SSLLibVersions);
        finally
          Loader.SSLLibVersions := LOrigVersions; // Restore valid versions
        end;
      end;
    {$ENDIF}
  end;

  Assert.IsTrue(Loader.State = lsLoadedFailed, 'Changing a property must not reset failure');
  Assert.IsFalse(Loader.Load, 'Subsequent Load must return False while circuit breaker is active');

  Loader.Unload;
  Assert.IsFalse(Loader.IsLoaded);

  Loader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(Loader.Load, 'Load should succeed after explicit Unload resets failure state');
  try
    Assert.IsTrue(Loader.IsLoaded);
  finally
    Loader.Unload;
  end;
end;

{ TLoaderCallbacksFixture }

var
  TTestCallbackLog: TStringList = nil;
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  GTestSymbolInjectorActive: Boolean = False;
  GTestCleanupFaultActive: Boolean = False;
  GTestSecondCleanupFaultActive: Boolean = False;
  GTestCleanupTailCount: Integer = 0;
  GTestInfoUnavailable: Integer = 0;
  GTestDiscoveryOverride: Boolean = False;
  GTestDiscoveryFile: string = '';
  GTestSSLInitFailure: Boolean = False;
  GTestCryptoInitFailure: Boolean = False;
  {$ENDIF}

type
  TActionRegistrationProbe = class
  public
    LoadCount, UnloadCount: Integer;
    ReadyOnLoad, ReadyOnUnload, NativeOnLoad, NativeOnUnload: Boolean;
    FailOnLoad, FailOnUnload, Reenter, ReenterOnUnload, ReentryRejected: Boolean;
    Operation: Integer;
    Name: string;
    Log: TStringList;
    Entered, ReleaseGate: TEvent;
    procedure Action(AAction: TOpenSSLLoadAction);
  end;

  TTestRuntimeObserver = class
  public
    class var Active: Boolean;
    class var ThrowOnLoad: Boolean;
    class var LoadCount: Integer;
    class procedure ActionProc(AAction: TOpenSSLLoadAction);
  end;

  TConcurrentRegistrationObserver = class
  public
    class var Active: Boolean;
    class var ActionLoadCount: Integer;
    class var ActionUnloadCount: Integer;
    class procedure ActionProc(AAction: TOpenSSLLoadAction);
  end;

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
    class var QueryAction: TOpenSSLLoadAction;
    class var QueryCompleted: Boolean;
    class var QueryError: string;
    class var QueryState: TTaurusTLSLoaderState;
    class var QueryLoaded: Boolean;
    class var ConfigOnLoad: string;
    class var ConfigOnUnload: string;
    class var MetadataEmptyOnLoad: Boolean;
    class var MetadataEmptyOnUnload: Boolean;
    class var ProbePhase: Integer;
    class var ProbeProperty: Integer;
    class var ProbeValue: string;
    class var ProbeCompleted: Boolean;
    class var ProbeRejected: Boolean;
    class var ProbeError: string;
    class var ProbeResult: string;
    /// <summary>Records lifecycle actions and optionally verifies that OpenSSL routines remain callable.</summary>
    /// <param name="AAction">The load or unload action dispatched by the loader.</param>
    class procedure ActionProc(AAction: TOpenSSLLoadAction);
  end;

  TTestCallbackObserverB = class
  public
    class var Active: Boolean;
    class var ThrowOnLoad: Boolean;
    class var ThrowOnUnload: Boolean;
    /// <summary>Records lifecycle actions or raises a simulated load failure to exercise rollback.</summary>
    /// <param name="AAction">The load or unload action dispatched by the loader.</param>
    class procedure ActionProc(AAction: TOpenSSLLoadAction);
  end;

class procedure TConcurrentRegistrationObserver.ActionProc(AAction: TOpenSSLLoadAction);
begin
  if not Active then
    Exit;
  case AAction of
    osaLoad: Inc(ActionLoadCount);
    osaUnload: Inc(ActionUnloadCount);
  end;
end;

// Exercise the deprecated compatibility API deliberately.
{$I TaurusTLSSymbolDeprecatedOff.inc}
{$IFDEF FPC}{$WARN 5044 OFF}{$ENDIF}
function LoaderMetadataIsEmpty: Boolean;
var
  LLoader: IOpenSSLLoader;
begin
  LLoader := GetOpenSSLLoader;
  Result := (LLoader.Version = '') and (LLoader.ConfigDirectory = '') and
    (LLoader.ModulesDirectory = '') and (LLoader.EnginesDirectory = '') and
    (OpenSSLVersion = '') and (OpenSSLDir = '') and
    (OpenSSLModulesDir = '') and (OpenSSLEnginesDir = '');
end;

{$I TaurusTLSSymbolDeprecatedOn.inc}

procedure TActionRegistrationProbe.Action(AAction: TOpenSSLLoadAction);
begin
  if AAction = osaLoad then
  begin
    TInterlocked.Increment(LoadCount);
    ReadyOnLoad := GetOpenSSLLoader.IsLoaded;
    NativeOnLoad := OpenSSL_version_num() > 0;
    if Assigned(Log) then
      Log.Add(Name + ':Load');
    if FailOnLoad then
      raise EAbort.Create('Immediate load failure');
  end
  else
  begin
    TInterlocked.Increment(UnloadCount);
    ReadyOnUnload := GetOpenSSLLoader.IsLoaded;
    NativeOnUnload := OpenSSL_version_num() > 0;
    if Assigned(Log) then
      Log.Add(Name + ':Unload');
    if FailOnUnload then
      raise EAbort.Create('Immediate unload failure');
  end;
  if Reenter and (ReenterOnUnload = (AAction = osaUnload)) then
  try
    case Operation of
      0: GetOpenSSLLoader.Load;
      1: GetOpenSSLLoader.Unload;
      2: Register_SSLLoaderAction(Action);
      3: UnRegister_SSLLoaderAction(Action);
    end;
  except
    on E: ETaurusTLSLoaderError do
      ReentryRejected := True;
  end;
  if Assigned(Entered) then
  begin
    Entered.SetEvent;
    if ReleaseGate.WaitFor(10000) <> wrSignaled then
      raise Exception.Create('Immediate callback release timed out');
  end;
end;

class procedure TTestRuntimeObserver.ActionProc(AAction: TOpenSSLLoadAction);
begin
  if not Active or (AAction <> osaLoad) then
    Exit;
  Inc(LoadCount);
  if ThrowOnLoad then
    raise EAbort.Create('Simulated TLS runtime action failure');
end;

class procedure TTestCallbackObserverA.ActionProc(AAction: TOpenSSLLoadAction);
begin
  if not Active then
    Exit;

  if AAction = osaLoad then
  begin
    LoadState := GetOpenSSLLoader.State;
    LoadedOnLoad := GetOpenSSLLoader.IsLoaded;
    ConfigOnLoad := GetOpenSSLLoader.ConfigFile;
    MetadataEmptyOnLoad := LoaderMetadataIsEmpty;
  end
  else
  begin
    UnloadState := GetOpenSSLLoader.State;
    LoadedOnUnload := GetOpenSSLLoader.IsLoaded;
    ConfigOnUnload := GetOpenSSLLoader.ConfigFile;
    MetadataEmptyOnUnload := LoaderMetadataIsEmpty;
  end;

  if Assigned(QueryDone) and (AAction = QueryAction) then
  begin
    QueryThread := TThread.CreateAnonymousThread(
      procedure
      begin
        try
          try
            QueryState := GetOpenSSLLoader.State;
            QueryLoaded := GetOpenSSLLoader.IsLoaded;
          except
            on E: Exception do
              QueryError := E.ClassName + ': ' + E.Message;
          end;
        finally
          QueryDone.SetEvent;
        end;
      end);
    QueryThread.FreeOnTerminate := False;
    QueryThread.Start;
    // Unload suppresses callback exceptions: assert this result in the test instead.
    QueryCompleted := QueryDone.WaitFor(5000) = wrSignaled;
  end;

  if ((ProbePhase = 1) and (AAction = osaLoad)) or
    ((ProbePhase = 2) and (AAction = osaUnload)) then
  begin
    try
      case ProbeProperty of
        0: GetOpenSSLLoader.ConfigFile := ProbeValue;
        1: GetOpenSSLLoader.OpenSSLPath := ProbeValue;
        2: GetOpenSSLLoader.SSLLibVersions := ProbeValue;
      end;
    except
      on E: ETaurusTLSConfigFilePathError do
      begin
        ProbeRejected := True;
        ProbeError := E.Message;
      end;
    end;
    case ProbeProperty of
      0: ProbeResult := GetOpenSSLLoader.ConfigFile;
      1: ProbeResult := GetOpenSSLLoader.OpenSSLPath;
      2: ProbeResult := GetOpenSSLLoader.SSLLibVersions;
    end;
    // Unload callbacks suppress unexpected errors; record completion explicitly.
    ProbeCompleted := True;
  end;

  if ((RecursivePhase = 1) and (AAction = osaLoad)) or
    ((RecursivePhase = 2) and (AAction = osaUnload)) then
  try
    case RecursiveOperation of
      0: GetOpenSSLLoader.Load;
      1: GetOpenSSLLoader.Unload;
      2: GetOpenSSLLoader.Unload(False);
      3: Register_SSLLoaderAction(TTestCallbackObserverB.ActionProc);
      4: UnRegister_SSLLoaderAction(TTestCallbackObserverB.ActionProc);
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
  begin
    TTestCallbackLog.Add('B:Unload');
    if ThrowOnUnload then
      raise Exception.Create('Simulated unload action failure in Observer B');
  end;
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

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$I TaurusTLSUnusedParamOff.inc}
function TestUnavailableInfo(AKind: TIdC_INT): PIdAnsiChar; cdecl;
begin
  Result := nil;
end;

function TestDefaultConfigFile: PIdAnsiChar; cdecl;
begin
  if GTestDiscoveryFile = '' then
    Result := nil
  else
    Result := CRYPTO_strdup(PIdAnsiChar(UTF8String(GTestDiscoveryFile)), nil, 0);
end;

function TestSSLInit(opts: TIdC_UINT64;
  const settings: POPENSSL_INIT_SETTINGS): TIdC_INT; cdecl;
begin
  Result := 0;
end;

procedure TestRuntimeBindings(const ADllHandle: TIdLibHandle;
  LibVersion: TIdC_UINT; const AFailed: TStringList);
begin
  case GTestInfoUnavailable of
    1: OPENSSL_info := TestUnavailableInfo;
    2:
      begin
        OPENSSL_info := TestUnavailableInfo;
        AFailed.Add('OPENSSL_info');
      end;
  end;
  if GTestDiscoveryOverride then
    CONF_get1_default_config_file := TestDefaultConfigFile;
  if GTestCryptoInitFailure then
    OPENSSL_init_crypto := TestSSLInit;
end;

procedure TestSSLBindings(const ADllHandle: TIdLibHandle;
  LibVersion: TIdC_UINT; const AFailed: TStringList);
begin
  if GTestSSLInitFailure then
    OPENSSL_init_ssl := TestSSLInit;
end;
{$I TaurusTLSUnusedParamOn.inc}

/// <summary>Records that cleanup continues past injected header-unloader failures.</summary>
procedure TestCleanupTail;
begin
  if GTestCleanupFaultActive then
    Inc(GTestCleanupTailCount);
end;

/// <summary>Injects a later cleanup error to verify preservation of the first error.</summary>
procedure TestSecondCleanupFault;
begin
  if GTestSecondCleanupFaultActive then
    raise ETaurusTLSLoaderError.Create('Secondary header cleanup failure');
end;

/// <summary>Injects the first header cleanup error before the remaining resetters.</summary>
procedure TestCleanupFault;
begin
  if GTestCleanupFaultActive then
    raise ETaurusTLSLoaderError.Create('Primary header cleanup failure');
end;
{$ENDIF}

procedure TLoaderCallbacksFixture.Setup;
begin
  inherited Setup;
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  GTestSymbolInjectorActive := False;
  GTestCleanupFaultActive := False;
  GTestSecondCleanupFaultActive := False;
  GTestCleanupTailCount := 0;
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
  TTestCallbackObserverA.QueryAction := osaLoad;
  TTestCallbackObserverA.QueryCompleted := False;
  TTestCallbackObserverA.QueryError := '';
  TTestCallbackObserverA.QueryState := lsLoadedFailed;
  TTestCallbackObserverA.QueryLoaded := True;
  TTestCallbackObserverA.ConfigOnLoad := '';
  TTestCallbackObserverA.ConfigOnUnload := '';
  TTestCallbackObserverA.ProbePhase := 0;
  TTestCallbackObserverA.ProbeCompleted := False;
  TTestCallbackObserverA.ProbeRejected := False;
  TTestCallbackObserverA.ProbeError := '';
  TTestCallbackObserverA.ProbeResult := '';
  TTestCallbackObserverB.Active := False;
  TTestCallbackObserverB.ThrowOnLoad := False;
  TTestCallbackObserverB.ThrowOnUnload := False;
  TTestCallbackObserverA.MetadataEmptyOnLoad := False;
  TTestCallbackObserverA.MetadataEmptyOnUnload := False;
  TTestRuntimeObserver.Active := False;
  TTestRuntimeObserver.ThrowOnLoad := False;
  TTestRuntimeObserver.LoadCount := 0;
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  GTestInfoUnavailable := 0;
  GTestDiscoveryOverride := False;
  GTestDiscoveryFile := '';
  GTestSSLInitFailure := False;
  GTestCryptoInitFailure := False;
  {$ENDIF}
end;

procedure TLoaderCallbacksFixture.Teardown;
begin
  TTestRuntimeObserver.Active := False;
  TTestRuntimeObserver.ThrowOnLoad := False;
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  GTestInfoUnavailable := 0;
  GTestDiscoveryOverride := False;
  GTestSSLInitFailure := False;
  GTestCryptoInitFailure := False;
  {$ENDIF}
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  GTestCleanupFaultActive := False;
  GTestSecondCleanupFaultActive := False;
  GTestSymbolInjectorActive := False;
  {$ENDIF}
  TTestCallbackObserverB.ThrowOnUnload := False;
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

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure TLoaderLifecycleFixture.Life_MissingLibraries;
begin
  Loader.OpenSSLPath := FTempDir;
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsFalse(Loader.Load);
  Assert.IsTrue(Loader.State = lsLoadedFailed);
  Assert.IsFalse(Loader.IsLoaded);
  Assert.IsFalse(Assigned(OpenSSL_version_num), 'Headers must remain unbound');
  Loader.OpenSSLPath := FOrigOpenSSLPath;
  Assert.IsFalse(Loader.Load, 'A path change must not reset failure state');
  Loader.Unload;
  Assert.IsTrue(Loader.State = lsNotLoaded);
  Assert.IsTrue(Loader.Load, 'Explicit reset permits loading from the restored path');
end;

{$IFDEF MSWINDOWS}
procedure TLoaderLifecycleFixture.Life_PartialLibrary;
var
  LCryptoFiles: TArray<string>;
  LDistributionPath: string;
  LSourceFile: string;
  LCopyFile: string;
begin
  // The saved original path is for teardown; SetupFromCmd selects this test's path.
  LDistributionPath := Loader.OpenSSLPath;
  Assert.IsTrue(LDistributionPath <> '',
    'Partial-library test requires an OpenSSL distribution directory configured with -osp');
  LCryptoFiles := TDirectory.GetFiles(LDistributionPath, 'libcrypto*.dll');
  Assert.IsTrue(Length(LCryptoFiles) > 0, 'Test distribution must contain a crypto DLL');
  LSourceFile := LCryptoFiles[0];
  LCopyFile := TPath.Combine(FTempDir, TPath.GetFileName(LSourceFile));
  TFile.Copy(LSourceFile, LCopyFile);
  Loader.OpenSSLPath := FTempDir;
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsFalse(Loader.Load, 'Crypto without SSL is a partial load failure');
  Assert.IsTrue(Loader.State = lsLoadedFailed);
  Assert.IsFalse(Loader.IsLoaded);
  Assert.IsFalse(Assigned(OpenSSL_version_num), 'Headers must not bind after partial discovery');
  Assert.IsTrue(Winapi.Windows.GetModuleHandle(PChar(LCopyFile)) = 0,
    'Rollback must release the partially loaded crypto DLL');
  TFile.Delete(LCopyFile);
  Loader.OpenSSLPath := LDistributionPath;
  Assert.IsFalse(Loader.Load);
  Loader.Unload;
  Assert.IsTrue(Loader.Load, 'Recovery must work after the partial load is cleaned up');
end;
{$ENDIF}
{$ENDIF}

procedure TLoaderCallbacksFixture.CB_DispatchLive;
begin
  TTestCallbackLog.Clear;
  TTestCallbackObserverA.Active := True;
  TTestCallbackObserverA.VerifyHandlesLive := True;
  try
    Loader.ConfigFile := FValidConfigFile;
    Assert.IsTrue(Loader.Load, 'Load failed');
    try
      Assert.AreEqual(1, TTestCallbackLog.Count);
      Assert.AreEqual('A:Load:Live', TTestCallbackLog[0]);
      Assert.IsTrue(TTestCallbackObserverA.LoadState = lsNotLoaded);
      Assert.IsFalse(TTestCallbackObserverA.LoadedOnLoad);
      Assert.IsTrue(Loader.State = lsLoadedReady);
    finally
      Loader.Unload;
    end;

    Assert.AreEqual(2, TTestCallbackLog.Count);
    Assert.AreEqual('A:Unload:Live', TTestCallbackLog[1]);
    Assert.IsTrue(TTestCallbackObserverA.UnloadState = lsNotLoaded);
    Assert.IsFalse(TTestCallbackObserverA.LoadedOnUnload);
    Assert.IsTrue(Loader.State = lsNotLoaded);
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
    Loader.ConfigFile := FValidConfigFile;
    Assert.IsTrue(Loader.Load, 'Load failed');
    try
      Assert.AreEqual(2, TTestCallbackLog.Count);
      Assert.AreEqual('A:Load', TTestCallbackLog[0]);
      Assert.AreEqual('B:Load', TTestCallbackLog[1]);
    finally
      Loader.Unload;
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
    Loader.ConfigFile := FValidConfigFile;
    Assert.IsTrue(Loader.Load, 'Initial Load failed');
    Assert.IsTrue(Loader.Load, 'Second Load call should succeed');

    Assert.AreEqual(1, TTestCallbackLog.Count);
    Assert.AreEqual('A:Load', TTestCallbackLog[0]);

    Loader.Unload;
    Loader.Unload;

    Assert.AreEqual(2, TTestCallbackLog.Count);
    Assert.AreEqual('A:Load', TTestCallbackLog[0]);
    Assert.AreEqual('A:Unload', TTestCallbackLog[1]);
    Assert.IsTrue(Loader.Load, 'A new load cycle must succeed');
    Loader.Unload;
    Assert.AreEqual(4, TTestCallbackLog.Count);
    Assert.AreEqual('A:Load', TTestCallbackLog[2]);
    Assert.AreEqual('A:Unload', TTestCallbackLog[3]);
  finally
    TTestCallbackObserverA.Active := False;
    Loader.Unload;
  end;
end;

procedure TLoaderCallbacksFixture.CB_RollbackOnFail;
begin
  TTestCallbackLog.Clear;
  TTestCallbackObserverA.Active := True;
  TTestCallbackObserverB.Active := True;
  TTestCallbackObserverB.ThrowOnLoad := True;
  try
    Loader.ConfigFile := FValidConfigFile;
    try
      Loader.Load;
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
    Assert.IsTrue(Loader.State = lsLoadedFailed);
    Assert.IsFalse(Loader.IsLoaded);
  finally
    TTestCallbackObserverB.ThrowOnLoad := False;
    TTestCallbackObserverA.Active := False;
    TTestCallbackObserverB.Active := False;
    Loader.Unload;
  end;
end;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure TLoaderCallbacksFixture.CB_PreserveDiag;
begin
  GTestSymbolInjectorActive := True;
  try
    Loader.ConfigFile := FInvalidSyntaxConfigFile;
    try
      Loader.Load;
    except
      on ETaurusTLSConfigFileLoadError do ;
    end;

    Assert.IsTrue(Loader.FailedToLoad.IndexOf('Fake_Diagnostic_Symbol') >= 0,
      'Internal failure teardown must preserve FailedToLoad diagnostics');

    Loader.Unload;
    Assert.AreEqual(0, Loader.FailedToLoad.Count,
      'Public Unload must clear FailedToLoad diagnostics');
  finally
    GTestSymbolInjectorActive := False;
    Loader.Unload;
  end;
end;

{$ENDIF}

procedure TLoaderCallbacksFixture.CB_FailureRecovery;
begin
  TTestCallbackObserverA.Active := True;
  TTestCallbackObserverB.Active := True;
  TTestCallbackObserverB.ThrowOnLoad := True;
  Loader.ConfigFile := FValidConfigFile;
  Assert.WillRaiseWithMessage(
    procedure
    begin
      Loader.Load;
    end,
    Exception, 'Simulated action failure in Observer B');
  Assert.IsFalse(Loader.IsLoaded);
  Assert.AreEqual(2, TTestCallbackLog.Count);
  TTestCallbackObserverB.ThrowOnLoad := False;
  Assert.IsFalse(Loader.Load, 'Callback failure must trip the circuit breaker');
  Assert.AreEqual(2, TTestCallbackLog.Count, 'Blocked load must not dispatch callbacks');
  Loader.Unload;
  Assert.IsTrue(Loader.Load, 'Explicit Unload must permit recovery');
  Loader.Unload;
  Assert.AreEqual(6, TTestCallbackLog.Count);
  Assert.AreEqual('A:Load', TTestCallbackLog[2]);
  Assert.AreEqual('B:Load', TTestCallbackLog[3]);
  Assert.AreEqual('B:Unload', TTestCallbackLog[4]);
  Assert.AreEqual('A:Unload', TTestCallbackLog[5]);
end;

procedure TLoaderCallbacksFixture.Config_CallbackMutation(
  const APhase, AProperty, ARepeat: Integer);
var
  LOriginalValue: string;
  LRejectExpected: Boolean;
begin
  Loader.ConfigFile := FValidConfigFile;
  case AProperty of
    0: LOriginalValue := Loader.ConfigFile;
    1: LOriginalValue := Loader.OpenSSLPath;
    2: LOriginalValue := Loader.SSLLibVersions;
  end;
  TTestCallbackObserverA.Active := True;
  if APhase = 1 then
    TTestCallbackObserverA.ProbePhase := 1
  else
    TTestCallbackObserverA.ProbePhase := 2;
  TTestCallbackObserverA.ProbeProperty := AProperty;
  if ARepeat <> 0 then
    TTestCallbackObserverA.ProbeValue := LOriginalValue
  else
    case AProperty of
      0: TTestCallbackObserverA.ProbeValue := TPath.Combine(FTempDir, 'replacement.cnf');
      1: TTestCallbackObserverA.ProbeValue := FTempDir;
      2: TTestCallbackObserverA.ProbeValue := 'replacement-version';
    end;

  if APhase = 3 then
  begin
    TTestCallbackObserverB.Active := True;
    TTestCallbackObserverB.ThrowOnLoad := True;
    Assert.WillRaiseWithMessage(
      procedure
      begin
        Loader.Load;
      end, Exception, 'Simulated action failure in Observer B');
    Assert.IsTrue(Loader.State = lsLoadedFailed);
    Assert.IsFalse(Loader.Load, 'Rejected mutation must not permit a retry');
  end
  else
  begin
    Assert.IsTrue(Loader.Load);
    Assert.IsTrue(Loader.State = lsLoadedReady);
    Loader.Unload;
    Assert.IsTrue(Loader.State = lsNotLoaded);
  end;

  Assert.IsTrue(TTestCallbackObserverA.ProbeCompleted, 'Property probe must finish');
  LRejectExpected := ARepeat = 0;
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  LRejectExpected := LRejectExpected and (AProperty = 0);
  {$ENDIF}
  Assert.IsTrue(TTestCallbackObserverA.ProbeRejected = LRejectExpected,
    'Changed active properties are rejected; repeated inputs and static path/version setters are safe');
  if LRejectExpected then
    Assert.AreEqual(RSOSSLConfigFileAlreadyLoaded, TTestCallbackObserverA.ProbeError);
  Assert.AreEqual(LOriginalValue, TTestCallbackObserverA.ProbeResult,
    'Callbacks must not replace configured values');
  Assert.AreEqual(FValidConfigFile, Loader.ConfigFile);
end;

procedure TLoaderCallbacksFixture.Config_Publication(const ARelative: Integer);
var
  LInput: string;
  LExpected: string;
begin
  if ARelative <> 0 then
  begin
    Assert.IsTrue(SetCurrentDir(FTempDir));
    LInput := TPath.GetFileName(FValidConfigFile);
    LExpected := TPath.GetFullPath(TPath.Combine(GetCurrentDir, LInput));
  end
  else
  begin
    LInput := FValidConfigFile;
    LExpected := TPath.GetFullPath(LInput);
  end;
  Loader.ConfigFile := LInput;
  TTestCallbackObserverA.Active := True;
  Assert.IsTrue(Loader.Load);
  Assert.AreEqual(LInput, TTestCallbackObserverA.ConfigOnLoad,
    'Initialization callbacks see configured input before readiness');
  Assert.IsTrue(TTestCallbackObserverA.LoadState = lsNotLoaded);
  Assert.AreEqual(LExpected, Loader.ConfigFile, 'Ready state exposes the effective full filename');
  Loader.Unload;
  Assert.AreEqual(LInput, TTestCallbackObserverA.ConfigOnUnload);
  Assert.IsTrue(TTestCallbackObserverA.UnloadState = lsNotLoaded);
  Assert.AreEqual(LInput, Loader.ConfigFile, 'Unload retains the configured input');
end;

procedure TLoaderCallbacksFixture.Config_RollbackPublication;
var
  LInput: string;
begin
  Assert.IsTrue(SetCurrentDir(FTempDir));
  LInput := TPath.GetFileName(FValidConfigFile);
  Loader.ConfigFile := LInput;
  TTestCallbackObserverA.Active := True;
  TTestCallbackObserverB.Active := True;
  TTestCallbackObserverB.ThrowOnLoad := True;
  Assert.WillRaiseWithMessage(
    procedure
    begin
      Loader.Load;
    end, Exception, 'Simulated action failure in Observer B');
  Assert.IsTrue(Loader.State = lsLoadedFailed);
  Assert.AreEqual(LInput, TTestCallbackObserverA.ConfigOnLoad);
  Assert.AreEqual(LInput, TTestCallbackObserverA.ConfigOnUnload);
  Assert.AreEqual(LInput, Loader.ConfigFile);
  Assert.IsTrue(TTestCallbackObserverA.UnloadState = lsNotLoaded);
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(Loader.State = lsLoadedFailed);
  Assert.IsFalse(Loader.Load);
  Loader.Unload;
  TTestCallbackObserverB.ThrowOnLoad := False;
  Assert.IsTrue(Loader.Load);
  Assert.AreEqual(TPath.GetFullPath(FValidConfigFile), Loader.ConfigFile);
end;

procedure TLoaderCallbacksFixture.State_Recursive(const APhase, AOperation: Integer);
begin
  TTestCallbackObserverA.Active := True;
  TTestCallbackObserverA.RecursivePhase := APhase;
  TTestCallbackObserverA.RecursiveOperation := AOperation;
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(Loader.Load);
  Assert.IsTrue(Loader.State = lsLoadedReady);
  Loader.Unload;
  Assert.IsTrue(TTestCallbackObserverA.RecursiveRejected,
    'Recursive lifecycle calls must raise ETaurusTLSLoaderError');
  Assert.IsTrue(Loader.State = lsNotLoaded);
  Assert.AreEqual(2, TTestCallbackLog.Count, 'Only the outer operation dispatches callbacks');
end;

procedure TLoaderCallbacksFixture.CB_RegistrationState(const AFailed: Integer);
var
  LProbe: TActionRegistrationProbe;
begin
  LProbe := TActionRegistrationProbe.Create;
  try
    Loader.ConfigFile := FValidConfigFile;
    if AFailed <> 0 then
    begin
      TTestCallbackObserverB.Active := True;
      TTestCallbackObserverB.ThrowOnLoad := True;
      Assert.WillRaise(
        procedure
        begin
          Loader.Load;
        end, Exception, 'The fixture must enter failed state before testing registration');
      TTestCallbackObserverB.ThrowOnLoad := False;
      Assert.WillRaise(
        procedure
        begin
          Register_SSLLoaderAction(LProbe.Action);
        end, ETaurusTLSLoaderError, 'Failed state must reject new registrations until reset');
      Assert.IsTrue(Loader.State = lsLoadedFailed, 'Rejected registration must preserve failure state');
      Assert.AreEqual(0, LProbe.LoadCount, 'Rejected registration must not invoke the callback');
    end
    else
    begin
      Assert.IsTrue(Loader.Load, 'The fixture must be ready before late registration');
      Register_SSLLoaderAction(LProbe.Action);
      Assert.AreEqual(1, LProbe.LoadCount, 'Ready registration must run osaLoad immediately');
      Assert.IsTrue(LProbe.ReadyOnLoad and LProbe.NativeOnLoad,
        'Immediate initialization must see ready state and callable native APIs');
      Assert.IsTrue(Loader.Load, 'A repeated Load must remain successful');
      Assert.AreEqual(1, LProbe.LoadCount, 'Repeated Load must not redispatch the added callback');
    end;
    UnRegister_SSLLoaderAction(LProbe.Action);
    Assert.AreEqual(Integer(Ord(AFailed = 0)), LProbe.UnloadCount,
      'Ready removal must clean up once; a rejected registration has no cleanup');
    if AFailed = 0 then
      Assert.IsTrue(LProbe.ReadyOnUnload and LProbe.NativeOnUnload,
        'Immediate cleanup must retain ready state and callable native APIs');
    Loader.Unload;
    Assert.IsTrue(Loader.Load, 'Explicit reset must allow the following load cycle');
    Assert.AreEqual(Integer(Ord(AFailed = 0)), LProbe.LoadCount,
      'Removed or rejected callbacks must not appear in a later load cycle');
  finally
    UnRegister_SSLLoaderAction(LProbe.Action);
    LProbe.Free;
  end;
end;

procedure TLoaderCallbacksFixture.CB_Unregister(const AState: Integer);
var
  LProbe: TActionRegistrationProbe;
begin
  LProbe := TActionRegistrationProbe.Create;
  try
    Loader.ConfigFile := FValidConfigFile;
    Register_SSLLoaderAction(LProbe.Action);
    if AState = 1 then
      Assert.IsTrue(Loader.Load, 'Ready removal requires an initialized callback')
    else if AState = 2 then
    begin
      TTestCallbackObserverB.Active := True;
      TTestCallbackObserverB.ThrowOnLoad := True;
      Assert.WillRaise(
        procedure
        begin
          Loader.Load;
        end, Exception, 'The earlier action must fail before the new probe is initialized');
      TTestCallbackObserverB.ThrowOnLoad := False;
    end;
    UnRegister_SSLLoaderAction(LProbe.Action);
    UnRegister_SSLLoaderAction(LProbe.Action);
    Assert.AreEqual(Integer(Ord(AState = 1)), LProbe.UnloadCount,
      'Only initialized actions receive cleanup, and repeated removal is a no-op');
    Loader.Unload;
    Assert.IsTrue(Loader.Load, 'Removal must leave later lifecycle cycles usable');
    Assert.AreEqual(Integer(Ord(AState = 1)), LProbe.LoadCount,
      'An action removed while inactive, ready or failed must not be dispatched again');
  finally
    UnRegister_SSLLoaderAction(LProbe.Action);
    LProbe.Free;
  end;
end;

procedure TLoaderCallbacksFixture.CB_RegistrationIdentity;
var
  LFirst, LSecond: TActionRegistrationProbe;
  LLog: TStringList;
begin
  LFirst := TActionRegistrationProbe.Create;
  LSecond := TActionRegistrationProbe.Create;
  LLog := TStringList.Create;
  try
    LFirst.Name := 'A';
    LSecond.Name := 'B';
    LFirst.Log := LLog;
    LSecond.Log := LLog;
    Loader.ConfigFile := FValidConfigFile;
    Register_SSLLoaderAction(nil);
    UnRegister_SSLLoaderAction(nil);
    UnRegister_SSLLoaderAction(LFirst.Action);
    Assert.IsTrue(Loader.Load, 'Missing and nil removals must not disturb lifecycle actions');
    Register_SSLLoaderAction(LFirst.Action);
    Register_SSLLoaderAction(LFirst.Action);
    Register_SSLLoaderAction(LSecond.Action);
    UnRegister_SSLLoaderAction(LFirst.Action);
    Assert.AreEqual(1, LFirst.UnloadCount, 'One removal must remove only one duplicate registration');
    Assert.AreEqual(0, LSecond.UnloadCount, 'Equal method code on a different instance must remain registered');
    Loader.Unload;
    Assert.AreEqual(2, LFirst.UnloadCount, 'The remaining duplicate must participate in normal unload');
    Assert.AreEqual(1, LSecond.UnloadCount, 'A different instance must retain its cleanup callback');
    Assert.AreEqual('B:Unload', LLog[LLog.Count - 2], 'Remaining callbacks must clean up in reverse registration order');
    Assert.AreEqual('A:Unload', LLog[LLog.Count - 1], 'Removal must preserve indexes of earlier callbacks');
    Assert.IsTrue(Loader.Load, 'The registry must remain valid after removing a duplicate');
    Assert.AreEqual(3, LFirst.LoadCount, 'Only the remaining duplicate must run on reload');
    Assert.AreEqual(2, LSecond.LoadCount, 'The second instance must survive the removal and reload');
  finally
    UnRegister_SSLLoaderAction(LSecond.Action);
    UnRegister_SSLLoaderAction(LFirst.Action);
    UnRegister_SSLLoaderAction(LFirst.Action);
    LLog.Free;
    LSecond.Free;
    LFirst.Free;
  end;
end;

procedure TLoaderCallbacksFixture.CB_ImmediateFailure(const AUnload: Integer);
var
  LProbe: TActionRegistrationProbe;
begin
  LProbe := TActionRegistrationProbe.Create;
  try
    Loader.ConfigFile := FValidConfigFile;
    Assert.IsTrue(Loader.Load, 'Immediate failure tests require a ready runtime');
    if AUnload = 0 then
    begin
      LProbe.FailOnLoad := True;
      Assert.WillRaise(
        procedure
        begin
          Register_SSLLoaderAction(LProbe.Action);
        end, EAbort, 'Immediate initialization must propagate the original callback exception');
      UnRegister_SSLLoaderAction(LProbe.Action);
      Assert.AreEqual(0, LProbe.UnloadCount, 'An initialization that failed must not leave a registered action');
      LProbe.FailOnLoad := False;
    end
    else
    begin
      Register_SSLLoaderAction(LProbe.Action);
      LProbe.FailOnUnload := True;
      Assert.WillRaise(
        procedure
        begin
          UnRegister_SSLLoaderAction(LProbe.Action);
        end, EAbort, 'Immediate cleanup must propagate the original callback exception');
      LProbe.FailOnUnload := False;
      UnRegister_SSLLoaderAction(LProbe.Action);
      Assert.AreEqual(1, LProbe.UnloadCount, 'Cleanup failure must still detach the callback');
    end;
    Assert.IsTrue(Loader.IsLoaded, 'An immediate callback failure must preserve the existing ready runtime');
    Register_SSLLoaderAction(LProbe.Action);
    UnRegister_SSLLoaderAction(LProbe.Action);
    Assert.AreEqual(2, LProbe.LoadCount, 'The mutation guard must reset after either callback exception');
    Loader.Unload;
    Assert.AreEqual(Integer(Ord(AUnload <> 0)) + 1, LProbe.UnloadCount,
      'Normal unload must not repeat cleanup of detached callbacks');
  finally
    LProbe.FailOnLoad := False;
    LProbe.FailOnUnload := False;
    UnRegister_SSLLoaderAction(LProbe.Action);
    LProbe.Free;
  end;
end;

procedure TLoaderCallbacksFixture.CB_ImmediateReentry(const AUnload, AOperation: Integer);
var
  LProbe: TActionRegistrationProbe;
begin
  LProbe := TActionRegistrationProbe.Create;
  try
    Loader.ConfigFile := FValidConfigFile;
    Assert.IsTrue(Loader.Load, 'Immediate reentry tests require ready native APIs');
    LProbe.Reenter := True;
    LProbe.ReenterOnUnload := AUnload <> 0;
    LProbe.Operation := AOperation;
    Register_SSLLoaderAction(LProbe.Action);
    UnRegister_SSLLoaderAction(LProbe.Action);
    Assert.IsTrue(LProbe.ReentryRejected,
      'Immediate callbacks must reject recursive Load, Unload, registration and removal');
    Assert.IsTrue(Loader.IsLoaded, 'Rejected reentry must preserve the surrounding ready runtime');
    Assert.AreEqual(1, LProbe.LoadCount, 'Rejected reentry must not duplicate initialization');
    Assert.AreEqual(1, LProbe.UnloadCount, 'Rejected reentry must not duplicate cleanup');
  finally
    LProbe.Reenter := False;
    UnRegister_SSLLoaderAction(LProbe.Action);
    LProbe.Free;
  end;
end;

procedure TLoaderCallbacksFixture.CB_ConcurrentActions(const AWorkerCount, AReady: Integer);
const
  CWaitMilliseconds = 10000;
var
  LStart, LDone: TEvent;
  LWorkers: TArray<TThread>;
  LProbes: TArray<TActionRegistrationProbe>;
  LErrors: TArray<string>;
  LRemaining: Integer;
  I: Integer;

  function CreateWorker(const AIndex: Integer): TThread;
  begin
    Result := TThread.CreateAnonymousThread(
      procedure
      begin
        try
          try
            if LStart.WaitFor(CWaitMilliseconds) <> wrSignaled then
              raise Exception.Create('Action worker start timed out');
            Register_SSLLoaderAction(LProbes[AIndex].Action);
            UnRegister_SSLLoaderAction(LProbes[AIndex].Action);
          except
            on E: Exception do
              LErrors[AIndex] := E.ClassName + ': ' + E.Message;
          end;
        finally
          if TInterlocked.Decrement(LRemaining) = 0 then
            LDone.SetEvent;
        end;
      end);
    Result.FreeOnTerminate := False;
  end;

  procedure CheckCounts;
  var
    J: Integer;
  begin
    for J := 0 to AWorkerCount - 1 do
    begin
      Assert.AreEqual(AReady, LProbes[J].LoadCount,
        Format('Worker %d must initialize its action exactly once while ready, never while inactive', [J]));
      Assert.AreEqual(AReady, LProbes[J].UnloadCount,
        Format('Worker %d must clean up its action exactly once while ready, never while inactive', [J]));
    end;
  end;

begin
  Assert.IsTrue(AWorkerCount >= 2, 'At least two workers are needed for contention');
  Assert.IsTrue(AReady in [0, 1], 'Initial readiness must be zero or one');
  SetLength(LWorkers, AWorkerCount);
  SetLength(LProbes, AWorkerCount);
  SetLength(LErrors, AWorkerCount);
  LRemaining := AWorkerCount;
  LStart := nil;
  LDone := nil;
  try
    LStart := TEvent.Create(nil, True, False, '');
    LDone := TEvent.Create(nil, True, False, '');
    for I := 0 to AWorkerCount - 1 do
      LProbes[I] := TActionRegistrationProbe.Create;
    Loader.ConfigFile := FValidConfigFile;
    if AReady <> 0 then
      Assert.IsTrue(Loader.Load, 'Ready action workers require a loaded runtime');

    for I := 0 to AWorkerCount - 1 do
    begin
      LWorkers[I] := CreateWorker(I);
      LWorkers[I].Start;
    end;
    LStart.SetEvent;
    Assert.IsTrue(LDone.WaitFor(CWaitMilliseconds) = wrSignaled,
      'Concurrent action registration/removal timed out');
    for I := 0 to AWorkerCount - 1 do
    begin
      Assert.AreEqual('', LErrors[I], Format('Action worker %d failed', [I]));
      if AReady <> 0 then
      begin
        Assert.IsTrue(LProbes[I].ReadyOnLoad and LProbes[I].ReadyOnUnload,
          'Immediate callbacks must observe ready state');
        Assert.IsTrue(LProbes[I].NativeOnLoad and LProbes[I].NativeOnUnload,
          'Native APIs must remain callable during immediate callbacks');
      end;
    end;
    CheckCounts;
    if AReady <> 0 then
      Assert.IsTrue(Loader.State = lsLoadedReady, 'Action mutations must preserve ready state')
    else
      Assert.IsTrue(Loader.State = lsNotLoaded, 'Action mutations must not load OpenSSL');

    // A later lifecycle cycle must not invoke any removed action.
    Loader.Unload;
    Assert.IsTrue(Loader.Load, 'Removed actions must not prevent the next load');
    Loader.Unload;
    CheckCounts;
  finally
    if Assigned(LStart) then
      LStart.SetEvent;
    // Owners and synchronization objects outlive every worker, even on assertion failure.
    for I := 0 to High(LWorkers) do
      if Assigned(LWorkers[I]) then
      begin
        LWorkers[I].WaitFor;
        LWorkers[I].Free;
      end;
    for I := 0 to High(LProbes) do
      if Assigned(LProbes[I]) then
      begin
        UnRegister_SSLLoaderAction(LProbes[I].Action);
        LProbes[I].Free;
      end;
    LDone.Free;
    LStart.Free;
  end;
end;

procedure TLoaderCallbacksFixture.CB_ConcurrentMutation(const ARemove: Integer);
var
  LProbe: TActionRegistrationProbe;
  LMutation, LUnload: TThread;
  LMutationDone, LUnloadStarted, LUnloadDone: TEvent;
  LMutationError, LUnloadError: string;
begin
  LProbe := TActionRegistrationProbe.Create;
  LMutation := nil;
  LUnload := nil;
  LMutationDone := TEvent.Create(nil, True, False, '');
  LUnloadStarted := TEvent.Create(nil, True, False, '');
  LUnloadDone := TEvent.Create(nil, True, False, '');
  LProbe.Entered := TEvent.Create(nil, True, False, '');
  LProbe.ReleaseGate := TEvent.Create(nil, True, False, '');
  try
    Loader.ConfigFile := FValidConfigFile;
    Assert.IsTrue(Loader.Load, 'Concurrent mutation tests require a ready runtime');
    if ARemove <> 0 then
    begin
      // Set up the registered action without blocking the test thread.
      LProbe.ReleaseGate.SetEvent;
      Register_SSLLoaderAction(LProbe.Action);
      LProbe.ReleaseGate.ResetEvent;
      LProbe.Entered.ResetEvent;
    end;
    LMutation := TThread.CreateAnonymousThread(
      procedure
      begin
        try
          try
            if ARemove <> 0 then
              UnRegister_SSLLoaderAction(LProbe.Action)
            else
              Register_SSLLoaderAction(LProbe.Action);
          except
            on E: Exception do
              LMutationError := E.ClassName + ': ' + E.Message;
          end;
        finally
          LMutationDone.SetEvent;
        end;
      end);
    LMutation.FreeOnTerminate := False;
    LMutation.Start;
    Assert.IsTrue(LProbe.Entered.WaitFor(10000) = wrSignaled,
      'The immediate action must start before the competing unload');
    LUnload := TThread.CreateAnonymousThread(
      procedure
      begin
        LUnloadStarted.SetEvent;
        try
          try
            Loader.Unload;
          except
            on E: Exception do
              LUnloadError := E.ClassName + ': ' + E.Message;
          end;
        finally
          LUnloadDone.SetEvent;
        end;
      end);
    LUnload.FreeOnTerminate := False;
    LUnload.Start;
    Assert.IsTrue(LUnloadStarted.WaitFor(10000) = wrSignaled, 'The competing unload thread must start');
    Assert.IsTrue(LUnloadDone.WaitFor(100) = wrTimeout,
      'Concurrent unload must wait until the immediate callback returns');
    Assert.IsTrue(Loader.IsLoaded, 'Native readiness must remain visible during the immediate action');
    LProbe.ReleaseGate.SetEvent;
    Assert.IsTrue(LMutationDone.WaitFor(10000) = wrSignaled, 'The immediate action must finish after gate release');
    Assert.IsTrue(LUnloadDone.WaitFor(10000) = wrSignaled, 'Concurrent unload must finish after action completion');
    Assert.AreEqual('', LMutationError, 'Immediate mutation must not race native library release');
    Assert.AreEqual('', LUnloadError, 'The competing unload must complete successfully');
    Assert.AreEqual(1, LProbe.LoadCount, 'Concurrent unload must not duplicate initialization');
    Assert.AreEqual(1, LProbe.UnloadCount, 'Removal and unload must clean up the action exactly once');
    Assert.IsTrue(Loader.State = lsNotLoaded, 'The competing unload must leave the loader inactive');
  finally
    LProbe.ReleaseGate.SetEvent;
    if Assigned(LMutation) then
    begin
      LMutation.WaitFor;
      LMutation.Free;
    end;
    if Assigned(LUnload) then
    begin
      LUnload.WaitFor;
      LUnload.Free;
    end;
    UnRegister_SSLLoaderAction(LProbe.Action);
    LProbe.ReleaseGate.Free;
    LProbe.Entered.Free;
    LUnloadDone.Free;
    LUnloadStarted.Free;
    LMutationDone.Free;
    LProbe.Free;
  end;
end;

procedure TLoaderCallbacksFixture.State_RecursiveFailure;
begin
  TTestCallbackObserverA.Active := True;
  TTestCallbackObserverA.RecursivePhase := 1;
  TTestCallbackObserverA.RecursiveOperation := 0;
  TTestCallbackObserverA.PropagateRecursive := True;
  Loader.ConfigFile := FValidConfigFile;
  Assert.WillRaise(
    procedure
    begin
      Loader.Load;
    end, ETaurusTLSLoaderError);
  Assert.IsTrue(TTestCallbackObserverA.RecursiveRejected);
  Assert.IsTrue(Loader.State = lsLoadedFailed);
  Assert.IsFalse(Loader.Load);
  Assert.AreEqual(0, TTestCallbackLog.Count, 'Failed action did not complete');
  Loader.Unload;
  TTestCallbackObserverA.RecursivePhase := 0;
  Assert.IsTrue(Loader.Load);
  Assert.IsTrue(Loader.State = lsLoadedReady);
  Loader.Unload;
end;

procedure TLoaderCallbacksFixture.State_ReadDuringLoad;
begin
  TTestCallbackObserverA.Active := True;
  TTestCallbackObserverA.QueryAction := osaLoad;
  TTestCallbackObserverA.QueryDone := TEvent.Create(nil, True, False, '');
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(Loader.Load);
  Assert.IsTrue(TTestCallbackObserverA.QueryCompleted,
    'Readiness queries must finish while the load callback is paused');
  TTestCallbackObserverA.QueryThread.WaitFor;
  Assert.AreEqual('', TTestCallbackObserverA.QueryError, 'Readiness query worker failed');
  Assert.IsTrue(TTestCallbackObserverA.QueryState = lsNotLoaded);
  Assert.IsFalse(TTestCallbackObserverA.QueryLoaded);
  Assert.IsTrue(Loader.State = lsLoadedReady);
end;

procedure TLoaderCallbacksFixture.State_ReadDuringUnload;
begin
  TTestCallbackObserverA.Active := True;
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(Loader.Load);
  TTestCallbackObserverA.QueryAction := osaUnload;
  TTestCallbackObserverA.QueryDone := TEvent.Create(nil, True, False, '');
  Loader.Unload;
  Assert.IsTrue(TTestCallbackObserverA.QueryCompleted,
    'Readiness queries must finish while the unload callback is paused');
  TTestCallbackObserverA.QueryThread.WaitFor;
  Assert.AreEqual('', TTestCallbackObserverA.QueryError, 'Readiness query worker failed');
  Assert.IsTrue(TTestCallbackObserverA.QueryState = lsNotLoaded);
  Assert.IsFalse(TTestCallbackObserverA.QueryLoaded);
  Assert.IsTrue(Loader.State = lsNotLoaded);
  Assert.IsFalse(Loader.IsLoaded);
end;

procedure TLoaderCallbacksFixture.Life_UnloadActionFailure;
begin
  TTestCallbackObserverA.Active := True;
  TTestCallbackObserverA.VerifyHandlesLive := True;
  TTestCallbackObserverB.Active := True;
  TTestCallbackObserverB.ThrowOnUnload := True;
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(Loader.Load);
  Loader.Unload;
  Assert.IsTrue(Loader.State = lsNotLoaded);
  Assert.IsFalse(Loader.IsLoaded);
  Assert.AreEqual(4, TTestCallbackLog.Count);
  Assert.AreEqual('B:Unload', TTestCallbackLog[2]);
  Assert.AreEqual('A:Unload:Live', TTestCallbackLog[3],
    'Earlier actions still clean up with routines callable');
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Assert.IsFalse(Assigned(OpenSSL_version_num));
  {$ENDIF}
  TTestCallbackObserverB.ThrowOnUnload := False;
  Assert.IsTrue(Loader.Load);
  Loader.Unload;
end;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure TLoaderCallbacksFixture.Life_UnloaderFailure(const ASecondFailure: Integer);
begin
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(Loader.Load);
  GTestCleanupFaultActive := True;
  GTestSecondCleanupFaultActive := ASecondFailure <> 0;
  Assert.WillRaiseWithMessage(
    procedure
    begin
      Loader.Unload;
    end, ETaurusTLSLoaderError, 'Primary header cleanup failure');
  Assert.AreEqual(1, GTestCleanupTailCount, 'Remaining resetters must still execute');
  Assert.IsFalse(Assigned(OpenSSL_version_num), 'Header reset must finish despite errors');
  Assert.IsTrue(Loader.State = lsLoadedFailed);
  Assert.IsFalse(Loader.Load, 'Cleanup failure must not leave the loader ready');
  GTestCleanupFaultActive := False;
  GTestSecondCleanupFaultActive := False;
  Loader.Unload;
  Assert.IsTrue(Loader.State = lsNotLoaded);
  Assert.IsTrue(Loader.Load, 'Cleanup exceptions must not retain the lifecycle lock');
end;

procedure TLoaderCallbacksFixture.Life_PreserveLoadError;
begin
  TTestCallbackObserverA.Active := True;
  TTestCallbackObserverB.Active := True;
  TTestCallbackObserverB.ThrowOnLoad := True;
  GTestSymbolInjectorActive := True;
  GTestCleanupFaultActive := True;
  Loader.ConfigFile := FValidConfigFile;
  Assert.WillRaiseWithMessage(
    procedure
    begin
      Loader.Load;
    end, Exception, 'Simulated action failure in Observer B');
  Assert.AreEqual(1, GTestCleanupTailCount);
  Assert.IsFalse(Assigned(OpenSSL_version_num));
  Assert.IsTrue(Loader.State = lsLoadedFailed);
  Assert.IsTrue(Loader.FailedToLoad.IndexOf('Fake_Diagnostic_Symbol') >= 0,
    'Failure cleanup must preserve binding diagnostics');
  Assert.AreEqual(2, TTestCallbackLog.Count);
  Assert.AreEqual('A:Unload', TTestCallbackLog[1]);
  Assert.IsFalse(Loader.Load);
  GTestCleanupFaultActive := False;
  GTestSymbolInjectorActive := False;
  TTestCallbackObserverB.ThrowOnLoad := False;
  Loader.Unload;
  Assert.AreEqual(0, Loader.FailedToLoad.Count);
  Assert.IsTrue(Loader.Load);
end;
{$ENDIF}

procedure TLoaderCallbacksFixture.Info_Passive;
begin
  Loader.ConfigFile := FValidConfigFile;
  TTestCallbackObserverA.Active := True;
  TTestCallbackObserverB.Active := True;
  TTestRuntimeObserver.Active := True;
  Assert.IsTrue(LoaderMetadataIsEmpty);
  Assert.IsTrue(LoaderMetadataIsEmpty);
  Assert.IsTrue(Loader.State = lsNotLoaded);
  Assert.AreEqual(FValidConfigFile, Loader.ConfigFile);
  Assert.AreEqual(0, TTestCallbackLog.Count);
  Assert.AreEqual(0, TTestRuntimeObserver.LoadCount,
    'Passive queries and failed native initialization must not invoke runtime actions');
end;

// Keep compatibility-wrapper coverage while callers migrate to the loader.
{$I TaurusTLSSymbolDeprecatedOff.inc}
{$IFDEF FPC}{$WARN 5044 OFF}{$ENDIF}
procedure TLoaderCallbacksFixture.Info_NativeValues;
begin
  Loader.ConfigFile := FValidConfigFile;
  TTestCallbackObserverA.Active := True;
  TTestCallbackObserverB.Active := True;
  Assert.IsTrue(Loader.Load);
  Assert.IsTrue(TTestCallbackObserverA.MetadataEmptyOnLoad);
  Assert.AreEqual(UTF8ToString(OpenSSL_version(OPENSSL_VERSION_CONST)), Loader.Version);
  Assert.AreEqual(ExtractFileDir(Loader.ConfigFile), Loader.ConfigDirectory);
  Assert.AreEqual(UTF8ToString(OPENSSL_info(OPENSSL_INFO_MODULES_DIR)), Loader.ModulesDirectory);
  if OpenSSL_version_num() >= $40000000 then
    Assert.AreEqual('', Loader.EnginesDirectory)
  else
    Assert.AreEqual(UTF8ToString(OPENSSL_info(OPENSSL_INFO_ENGINES_DIR)), Loader.EnginesDirectory);
  Assert.AreEqual(Loader.Version, OpenSSLVersion);
  Assert.AreEqual(Loader.ConfigDirectory, OpenSSLDir);
  Assert.AreEqual(Loader.ModulesDirectory, OpenSSLModulesDir);
  Assert.AreEqual(Loader.EnginesDirectory, OpenSSLEnginesDir);
  Assert.IsTrue(Loader.Load);
  Assert.AreEqual(2, TTestCallbackLog.Count);
  Loader.Unload;
  Assert.IsTrue(TTestCallbackObserverA.MetadataEmptyOnUnload);
  Assert.IsTrue(LoaderMetadataIsEmpty);

  // A later callback failure must not expose metadata from the previous load.
  TTestCallbackObserverB.ThrowOnLoad := True;
  Assert.WillRaise(
    procedure
    begin
      Loader.Load;
    end, Exception);
  Assert.IsTrue(Loader.State = lsLoadedFailed);
  Assert.IsTrue(LoaderMetadataIsEmpty);
  Assert.IsTrue(TTestCallbackObserverA.MetadataEmptyOnLoad);
  Assert.IsTrue(TTestCallbackObserverA.MetadataEmptyOnUnload);
end;

procedure TLoaderCallbacksFixture.Info_ConfigDirectory(const AKind: Integer);
var
  LExpectedDirectory: string;
  LUnicodeDirectory: string;
  LConfig: string;
begin
  Assert.IsTrue(SetCurrentDir(FTempDir));
  case AKind of
    0: LConfig := FValidConfigFile;
    1: LConfig := '.' + PathDelim + ExtractFileName(FValidConfigFile);
  else
    LUnicodeDirectory := TPath.Combine(FTempDir, 'Конфигурация_é');
    TDirectory.CreateDirectory(LUnicodeDirectory);
    LConfig := TPath.Combine(LUnicodeDirectory, 'test.cnf');
    TFile.WriteAllText(LConfig, cMinimalValidOpenSSLConfig);
  end;
  Loader.ConfigFile := LConfig;
  Assert.IsTrue(Loader.Load);
  LExpectedDirectory := ExtractFileDir(Loader.ConfigFile);
  Assert.AreEqual(LExpectedDirectory, Loader.ConfigDirectory);
  Assert.IsTrue(SetCurrentDir(FOrigCurrentDir));
  Assert.AreEqual(LExpectedDirectory, Loader.ConfigDirectory);
  Assert.AreEqual(LExpectedDirectory, OpenSSLDir);
end;

procedure TLoaderCallbacksFixture.Runtime_SharedLifecycle;
var
  LContext: TTaurusTLSContext;
  I: Integer;
begin
  Loader.ConfigFile := FValidConfigFile;
  TTestRuntimeObserver.Active := True;
  for I := 1 to 2 do
  begin
    Assert.IsTrue(Loader.Load);
    Assert.AreEqual(I, TTestRuntimeObserver.LoadCount,
      'Each successful loader cycle must invoke the runtime observer once');
    Assert.IsTrue(LoadOpenSSLLibrary);
    LContext := TTaurusTLSContext.Create;
    try
      LContext.UseSystemRootCACertificateStore := False;
      LContext.InitContext(sslCtxClient);
      Assert.IsNotNull(LContext.Context);
      Assert.AreEqual(I, TTestRuntimeObserver.LoadCount,
        'Creating a TLS context must reuse the initialized runtime');
    finally
      LContext.Free;
    end;
    UnLoadOpenSSLLibrary;
    Assert.IsTrue(Loader.State = lsNotLoaded);
    Assert.IsTrue(LoaderMetadataIsEmpty);
    UnLoadOpenSSLLibrary;
  end;
end;

procedure TLoaderCallbacksFixture.Runtime_ActionFailure;
var
  LContext: TTaurusTLSContext;
begin
  Loader.ConfigFile := FValidConfigFile;
  TTestCallbackObserverA.Active := True;
  TTestRuntimeObserver.Active := True;
  TTestRuntimeObserver.ThrowOnLoad := True;
  Assert.WillRaiseWithMessage(
    procedure
    begin
      Loader.Load;
    end, EAbort, 'Simulated TLS runtime action failure');
  Assert.IsTrue(Loader.State = lsLoadedFailed);
  Assert.IsTrue(LoaderMetadataIsEmpty);
  Assert.AreEqual(0, TTestCallbackLog.Count, 'Later load actions must not run');
  Assert.AreEqual(1, TTestRuntimeObserver.LoadCount,
    'Failed-state retries must not rerun the action; reset permits one successful load');
  Assert.IsFalse(LoadOpenSSLLibrary);
  Assert.AreEqual(1, TTestRuntimeObserver.LoadCount,
    'Failed-state retries must not rerun the action; reset permits one successful load');
  TTestRuntimeObserver.ThrowOnLoad := False;
  UnLoadOpenSSLLibrary;
  Assert.IsTrue(LoadOpenSSLLibrary);
  Assert.AreEqual(2, TTestRuntimeObserver.LoadCount,
    'Explicit reset must permit a second runtime initialization attempt');
  LContext := TTaurusTLSContext.Create;
  try
    LContext.UseSystemRootCACertificateStore := False;
    LContext.InitContext(sslCtxClient);
    Assert.IsNotNull(LContext.Context);
  finally
    LContext.Free;
  end;
end;

{$I TaurusTLSSymbolDeprecatedOn.inc}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure TLoaderCallbacksFixture.Info_Unavailable(const AKind: Integer);
begin
  GTestInfoUnavailable := AKind + 1;
  Loader.ConfigFile := FValidConfigFile;
  Assert.IsTrue(Loader.Load);
  Assert.IsNotEmpty(Loader.Version);
  Assert.AreEqual(ExtractFileDir(Loader.ConfigFile), Loader.ConfigDirectory);
  Assert.AreEqual('', Loader.ModulesDirectory);
  Assert.AreEqual('', Loader.EnginesDirectory);
end;

procedure TLoaderCallbacksFixture.Info_Discovery(const AKind: Integer);
var
  LExpectedDirectory: string;
begin
  GTestDiscoveryOverride := True;
  if AKind = 0 then
    LExpectedDirectory := ''
  else
  begin
    Assert.IsTrue(SetCurrentDir(FTempDir));
    GTestDiscoveryFile := 'sub' + PathDelim + 'test.cnf';
    LExpectedDirectory := TPath.Combine(GetCurrentDir, 'sub');
  end;
  Loader.ConfigFile := '';
  Assert.IsTrue(Loader.Load);
  Assert.AreEqual(GTestDiscoveryFile, Loader.ConfigFile);
  Assert.AreEqual(LExpectedDirectory, Loader.ConfigDirectory);
  Assert.IsTrue(SetCurrentDir(FOrigCurrentDir));
  Assert.AreEqual(LExpectedDirectory, Loader.ConfigDirectory);
end;

procedure TLoaderCallbacksFixture.Runtime_InitFailure(const AKind: Integer);
var
  LExceptionClass: ExceptClass;
begin
  if AKind = 0 then
  begin
    GTestCryptoInitFailure := True;
    LExceptionClass := ETaurusTLSLoaderError;
  end
  else
  begin
    GTestSSLInitFailure := True;
    LExceptionClass := ETaurusTLSOpenSSLInitFailed;
  end;
  Loader.ConfigFile := FValidConfigFile;
  TTestCallbackObserverA.Active := True;
  TTestRuntimeObserver.Active := True;
  Assert.WillRaise(
    procedure
    begin
      Loader.Load;
    end, LExceptionClass);
  Assert.IsTrue(Loader.State = lsLoadedFailed);
  Assert.IsTrue(LoaderMetadataIsEmpty);
  Assert.AreEqual(0, TTestCallbackLog.Count);
  Assert.AreEqual(0, TTestRuntimeObserver.LoadCount,
    'Passive queries and failed native initialization must not invoke runtime actions');
  GTestSSLInitFailure := False;
  GTestCryptoInitFailure := False;
  Loader.Unload;
  Assert.IsTrue(Loader.Load);
  Assert.AreEqual(1, TTestRuntimeObserver.LoadCount,
    'Failed-state retries must not rerun the action; reset permits one successful load');
end;
{$ENDIF}

procedure TLoaderLifecycleFixture.Life_ConcurrentLoad(const AWorkerCount: Integer);
const
  CWaitMilliseconds = 10000;
  CBlockedCheckMilliseconds = 100;
var
  LLoader: IOpenSSLLoader;
  LProbe: TActionRegistrationProbe;
  LAllStarted, LAnyDone, LDone: TEvent;
  LWorkers: TArray<TThread>;
  LResults: TArray<Boolean>;
  LErrors: TArray<string>;
  LStarting, LRemaining: Integer;
  I: Integer;

  function CreateWorker(const AIndex: Integer): TThread;
  begin
    Result := TThread.CreateAnonymousThread(
      procedure
      begin
        try
          try
            if TInterlocked.Decrement(LStarting) = 0 then
              LAllStarted.SetEvent;
            LResults[AIndex] := LLoader.Load;
          except
            on E: Exception do
              LErrors[AIndex] := E.ClassName + ': ' + E.Message;
          end;
        finally
          LAnyDone.SetEvent;
          if TInterlocked.Decrement(LRemaining) = 0 then
            LDone.SetEvent;
        end;
      end);
    Result.FreeOnTerminate := False;
  end;

begin
  Assert.IsTrue(AWorkerCount >= 2, 'At least two Load callers are required');
  LLoader := Loader;
  LLoader.ConfigFile := FValidConfigFile;
  SetLength(LWorkers, AWorkerCount);
  SetLength(LResults, AWorkerCount);
  SetLength(LErrors, AWorkerCount);
  LStarting := AWorkerCount;
  LRemaining := AWorkerCount;
  LAllStarted := nil;
  LAnyDone := nil;
  LDone := nil;
  LProbe := TActionRegistrationProbe.Create;
  try
    LProbe.Entered := TEvent.Create(nil, True, False, '');
    LProbe.ReleaseGate := TEvent.Create(nil, True, False, '');
    LAllStarted := TEvent.Create(nil, True, False, '');
    LAnyDone := TEvent.Create(nil, True, False, '');
    LDone := TEvent.Create(nil, True, False, '');
    Register_SSLLoaderAction(LProbe.Action);

    // Hold the first Load inside initialization before starting its competitors.
    LWorkers[0] := CreateWorker(0);
    LWorkers[0].Start;
    Assert.IsTrue(LProbe.Entered.WaitFor(CWaitMilliseconds) = wrSignaled,
      'The first Load caller must enter its initialization callback');
    for I := 1 to AWorkerCount - 1 do
    begin
      LWorkers[I] := CreateWorker(I);
      LWorkers[I].Start;
    end;
    Assert.IsTrue(LAllStarted.WaitFor(CWaitMilliseconds) = wrSignaled,
      'All competing Load workers must start');
    Assert.IsTrue(LAnyDone.WaitFor(CBlockedCheckMilliseconds) = wrTimeout,
      'No Load caller may return before initialization finishes');

    LProbe.ReleaseGate.SetEvent;
    Assert.IsTrue(LDone.WaitFor(CWaitMilliseconds) = wrSignaled,
      'Load callers must finish after initialization is released');
    for I := 0 to AWorkerCount - 1 do
    begin
      Assert.AreEqual('', LErrors[I], Format('Load worker %d failed', [I]));
      Assert.IsTrue(LResults[I], Format('Load worker %d must succeed', [I]));
    end;
    Assert.IsTrue(LLoader.State = lsLoadedReady);
    Assert.IsTrue(LLoader.IsLoaded);
    Assert.AreEqual(1, LProbe.LoadCount, 'Competing callers must initialize actions once');
    Assert.AreEqual(0, LProbe.UnloadCount, 'Successful Load callers must not trigger cleanup');

    LLoader.Unload;
    Assert.AreEqual(1, LProbe.UnloadCount, 'One global Unload must clean up once');
    Assert.IsTrue(LLoader.State = lsNotLoaded);
    Assert.IsFalse(LLoader.IsLoaded);
  finally
    // Release initialization even if a readiness, timeout or result assertion failed.
    if Assigned(LProbe.ReleaseGate) then
      LProbe.ReleaseGate.SetEvent;
    for I := 0 to High(LWorkers) do
      if Assigned(LWorkers[I]) then
      begin
        LWorkers[I].WaitFor;
        LWorkers[I].Free;
      end;
    UnRegister_SSLLoaderAction(LProbe.Action);
    LDone.Free;
    LAnyDone.Free;
    LAllStarted.Free;
    LProbe.ReleaseGate.Free;
    LProbe.Entered.Free;
    LProbe.Free;
  end;
end;

procedure TLoaderLifecycleFixture.Life_ConcurrentSingleton(const ARegister: Integer);
const
  CWorkerCount = 16;
  CQueryCount = 100;
var
  LStart: TEvent;
  LDone: TEvent;
  LWorkers: TArray<TThread>;
  LResults: TArray<IOpenSSLLoader>;
  LErrors: TArray<string>;
  LRemaining: Integer;
  I: Integer;

  function CreateWorker(const AIndex: Integer): TThread;
  begin
    Result := TThread.CreateAnonymousThread(
      procedure
      var
        LLoader: IOpenSSLLoader;
        J: Integer;
      begin
        try
          try
            if LStart.WaitFor(10000) <> wrSignaled then
              raise Exception.Create('Singleton worker start timed out');
            for J := 1 to CQueryCount do
            begin
              LLoader := GetOpenSSLLoader;
              if LLoader <> Loader then
                raise Exception.Create('Concurrent query returned a different loader');
            end;
            LResults[AIndex] := LLoader;
            if ARegister <> 0 then
              Register_SSLLoaderAction(TConcurrentRegistrationObserver.ActionProc);
          except
            on E: Exception do
              LErrors[AIndex] := E.ClassName + ': ' + E.Message;
          end;
        finally
          if TInterlocked.Decrement(LRemaining) = 0 then
            LDone.SetEvent;
        end;
      end);
    Result.FreeOnTerminate := False;
  end;

begin
  SetLength(LWorkers, CWorkerCount);
  SetLength(LResults, CWorkerCount);
  SetLength(LErrors, CWorkerCount);
  LRemaining := CWorkerCount;
  TConcurrentRegistrationObserver.ActionLoadCount := 0;
  TConcurrentRegistrationObserver.ActionUnloadCount := 0;
  TConcurrentRegistrationObserver.Active := ARegister <> 0;
  LStart := TEvent.Create(nil, True, False, '');
  try
    LDone := TEvent.Create(nil, True, False, '');
    try
      for I := 0 to CWorkerCount - 1 do
      begin
        LWorkers[I] := CreateWorker(I);
        LWorkers[I].Start;
      end;
      LStart.SetEvent;
      Assert.IsTrue(LDone.WaitFor(10000) = wrSignaled, 'Concurrent singleton access timed out');
      for I := 0 to CWorkerCount - 1 do
      begin
        Assert.AreEqual('', LErrors[I], 'Singleton worker failed');
        Assert.IsTrue(LResults[I] = Loader);
      end;
      Assert.IsTrue(Loader.State = lsNotLoaded, 'Queries and registration must not load OpenSSL');
      Assert.AreEqual(0, TConcurrentRegistrationObserver.ActionLoadCount);

      if ARegister <> 0 then
      begin
        Loader.ConfigFile := FValidConfigFile;
        Assert.IsTrue(Loader.Load);
        Assert.AreEqual(CWorkerCount, TConcurrentRegistrationObserver.ActionLoadCount);
        Assert.IsTrue(Loader.Load);
        Assert.AreEqual(CWorkerCount, TConcurrentRegistrationObserver.ActionLoadCount);
        Loader.Unload;
        Assert.AreEqual(CWorkerCount, TConcurrentRegistrationObserver.ActionUnloadCount);
      end;
    finally
      LStart.SetEvent;
      for I := 0 to High(LWorkers) do
        if Assigned(LWorkers[I]) then
        begin
          LWorkers[I].WaitFor;
          LWorkers[I].Free;
        end;
      LDone.Free;
    end;
  finally
    LStart.Free;
    // Registrations persist for the process; later fixtures observe inert callbacks.
    TConcurrentRegistrationObserver.Active := False;
  end;
end;

initialization
  GLoaderTestLock := TObject.Create;
  TDUnitX.RegisterTestFixture(TLoaderConfigFixture);
  TDUnitX.RegisterTestFixture(TLoaderLifecycleFixture);
  TDUnitX.RegisterTestFixture(TLoaderCallbacksFixture);
  TTestCallbackLog := TStringList.Create;
  // Observe the runtime load phase before the later test action callbacks.
  Register_SSLLoaderAction(TTestRuntimeObserver.ActionProc);
  Register_SSLLoaderAction(TTestCallbackObserverA.ActionProc);
  Register_SSLLoaderAction(TTestCallbackObserverB.ActionProc);
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Register_SSLLoader(TestSymbolInjectorLoadProc, 'LibCrypto');
  Register_SSLLoader(TestRuntimeBindings, 'LibCrypto');
  Register_SSLLoader(TestSSLBindings, 'LibSSL');
  Register_SSLUnloader(TestCleanupTail);
  Register_SSLUnloader(TestSecondCleanupFault);
  Register_SSLUnloader(TestCleanupFault);
{$ENDIF}

finalization
  FreeAndNil(TTestCallbackLog);
  FreeAndNil(GLoaderTestLock);

end.
