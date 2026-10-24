program TaurusTLS.Loader.Shutdown;

{ Purpose
  Verify automatic OpenSSL loader cleanup at real process shutdown in an
  application using TaurusTLSLoader without the TaurusTLS unit or DUnitX.
  The program explicitly loads OpenSSL, then exits without calling Unload.
  An independent observer runs after loader unit finalization and checks:
    - Both cleanup callbacks execute once, in reverse registration order.
    - Callbacks see the original singleton and non-ready state, while native
      version and allocation/free APIs remain callable.
    - Readiness and cached runtime metadata are cleared after cleanup.
    - Dynamic builds reset the native version function binding.
  The callback owner and a loader interface remain alive until verification.
  This tests lifecycle cleanup, not singleton destruction without references,
  operating-system module unloading, or competing first-publication races.

  Build
  Use the Delphi IDE, with the TaurusTLS source and Indy unit search paths.
  macOS archive builds need the same static-library search path as TaurusTLS.UT.

  Parameters
  -osp:<directory> is optional. Dynamic builds use the platform library search
  when omitted, or the supplied directory when present. Match the libraries
  to the executable architecture. Static builds ignore the library path.
  --inject-cleanup-failure intentionally raises in the first cleanup callback;
  both callbacks must still execute. Detecting this expected exception while
  all cleanup checks pass is a successful test, reported as PASS with exit 0.
  --exit:Pause waits for Enter after all finalization checks (useful in the IDE).
  --exit:Continue, --exit:, or no exit option returns immediately (the default).
  Example for IDE runs: --inject-cleanup-failure --exit:Pause
  This standalone app does not accept DUnitX runner switches.

  Usage
  Run each check as a fresh process from a terminal so finalization output
  remains visible. Use an external timeout when automating process execution.
  PowerShell, Win32 with a selected OpenSSL distribution:
    & '.\Win32\Debug\TaurusTLS.Loader.Shutdown.exe' '-osp:<Path-to-OpenSSL 32-bit shared libraries>'
    $LASTEXITCODE
  For Win64, use the Win64 executable and OpenSSL 64-bit shared libraries.
  Linux usually uses the system OpenSSL libraries:
    ./TaurusTLS_Loader_Shutdown; echo $?
  Use -osp: to select another directory containing OpenSSL shared libraries:
    ./TaurusTLS_Loader_Shutdown -osp:/path/to/openssl/libraries; echo $?

  macOS builds use statically linked OpenSSL and do not require -osp:.
  Run the deployed executable from <application>.app/Contents/MacOS.
  Append --inject-cleanup-failure to test cleanup after an expected exception.

  Results
  Normal success ends with:
    UNLOAD callback 2
    UNLOAD callback 1
    PASS: loader-only unit finalization completed
  Exit code 0 means success; detected failures print FAIL and exit with code 1.
  The injected-failure check also exits with code 0 when it behaves as expected.
  The additional PASS messages confirm that callback 2 raised the deliberate
  EExpectedCleanupFailure exception, the loader caught it, and callback 1 still
  ran. Final loader state, metadata and binding checks must also pass.
  Missing injection or any unexpected cleanup error is a failure. A startup
  failure skips shutdown verification and retains the original error in the
  output. A crash or timeout is always a failed run.
}

{$APPTYPE CONSOLE}
{$I ..\Source\TaurusTLSCompilerDefines.inc}
{$I ..\Source\TaurusTLSLinkDefines.inc}
{$R *.res}

uses
  System.SysUtils,
  System.IOUtils,
  TaurusTLSLoader,
  TaurusTLSHeaders_crypto,
  TaurusTLS.Loader.ConsoleSupport in 'TaurusTLS.Loader.ConsoleSupport.pas',
  TaurusTLS.Loader.Shutdown.Observer in 'TaurusTLS.Loader.Shutdown.Observer.pas';

type
  EExpectedCleanupFailure = class(Exception);

  TShutdownProbe = class
  private
    FLoader: IOpenSSLLoader;
    FLoadCount: Integer;
    FUnloadCount: Integer;
    FFailure: string;
    FInjectFailure: Boolean;
    FInjectedFailureObserved: Boolean;
    procedure CheckNativeAPI;
    procedure Action(const AIndex: Integer; AAction: TOpenSSLLoadAction);
  public
    constructor Create;
    procedure FirstAction(AAction: TOpenSSLLoadAction);
    procedure SecondAction(AAction: TOpenSSLLoadAction);
    procedure Execute;
    procedure Verify;
  end;

procedure Require(ACondition: Boolean; const AMessage: string);
begin
  if not ACondition then
    raise Exception.Create(AMessage);
end;

constructor TShutdownProbe.Create;
begin
  inherited Create;
  FLoader := GetOpenSSLLoader;
end;

procedure TShutdownProbe.CheckNativeAPI;
var
  LMemory: Pointer;
begin
  Require(OpenSSL_version_num() >= $30000000, 'Native version API is unavailable');
  LMemory := OPENSSL_malloc(32);
  Require(LMemory <> nil, 'Native allocation failed');
  OPENSSL_free(LMemory);
end;

procedure TShutdownProbe.Action(const AIndex: Integer; AAction: TOpenSSLLoadAction);
begin
  // Loader cleanup suppresses callback exceptions, so retain failures explicitly.
  try
    Require(GetOpenSSLLoader = FLoader, 'Callback observed a different singleton');
    Require((FLoader.State = lsNotLoaded) and not FLoader.IsLoaded,
      'Callback observed ready state during a transition');
    CheckNativeAPI;
    case AAction of
      osaLoad:
        begin
          Inc(FLoadCount);
          Require(AIndex = FLoadCount, 'Load callbacks ran out of order');
          Writeln('LOAD callback ', AIndex);
        end;
      osaUnload:
        begin
          Inc(FUnloadCount);
          Require(AIndex = 3 - FUnloadCount, 'Unload callbacks ran out of order');
          Require(MainCompleted, 'Cleanup ran before the program body completed');
          Writeln('UNLOAD callback ', AIndex);
          if FInjectFailure and (AIndex = 2) then
            raise EExpectedCleanupFailure.Create('Injected cleanup failure');
        end;
    end;
  except
    on E: Exception do
    begin
      if E is EExpectedCleanupFailure then
        FInjectedFailureObserved := True
      else if FFailure = '' then
        FFailure := E.ClassName + ': ' + E.Message;
      raise;
    end;
  end;
end;

procedure TShutdownProbe.FirstAction(AAction: TOpenSSLLoadAction);
begin
  Action(1, AAction);
end;

procedure TShutdownProbe.SecondAction(AAction: TOpenSSLLoadAction);
begin
  Action(2, AAction);
end;

procedure TShutdownProbe.Execute;
var
  I: Integer;
  LArgument: string;
  LLibraryPath: string;
begin
  for I := 1 to ParamCount do
  begin
    LArgument := ParamStr(I);
    if ConsumeExitOption(LArgument) then
      Continue;
    if SameText(Copy(LArgument, 1, 5), '-osp:') then
      LLibraryPath := Copy(LArgument, 6, MaxInt)
    else if SameText(LArgument, '--inject-cleanup-failure') then
      FInjectFailure := True
    else
      raise Exception.Create('Unknown argument: ' + LArgument);
  end;
  Require((FLoader.State = lsNotLoaded) and not FLoader.IsLoaded,
    'Loader was already initialized');
  FLoader.OpenSSLPath := LLibraryPath;
  // Explicit configuration avoids machine-wide OPENSSL_CONF and provider policy.
  ConfigFilename := TPath.GetTempFileName;
  TFile.WriteAllText(ConfigFilename,
    'openssl_conf = shutdown_init' + sLineBreak +
    '[shutdown_init]' + sLineBreak +
    'ssl_conf = ssl_settings' + sLineBreak +
    '[ssl_settings]' + sLineBreak +
    'system_default = tls_defaults' + sLineBreak +
    '[tls_defaults]' + sLineBreak +
    'MinProtocol = TLSv1.2' + sLineBreak);
  FLoader.ConfigFile := ConfigFilename;
  Register_SSLLoaderAction(FirstAction);
  Register_SSLLoaderAction(SecondAction);
  Writeln('Executable: ', ParamStr(0));
  Writeln('Process architecture: ', SizeOf(Pointer) * 8, ' bit');
  Writeln('OpenSSL library path: ', FLoader.OpenSSLPath);
  Writeln('Library suffix candidates: ', FLoader.SSLLibVersions);
  Writeln('Working directory: ', GetCurrentDir);
  if not FLoader.Load then
    raise Exception.CreateFmt(
      'Loader.Load returned False: native libraries could not be loaded. ' +
      'Process=%d bit; OpenSSLPath="%s"; suffixes="%s". ' +
      'Check library directory, architecture and DLL dependencies. Binding diagnostics: %s',
      [SizeOf(Pointer) * 8, FLoader.OpenSSLPath, FLoader.SSLLibVersions,
       Trim(FLoader.FailedToLoad.Text)]);
  Require((FLoader.State = lsLoadedReady) and FLoader.IsLoaded,
    'Loader did not publish readiness');
  Require((FLoadCount = 2) and (FUnloadCount = 0) and (FFailure = ''),
    'Unexpected callback results before shutdown');
  CheckNativeAPI;
  Writeln('READY: ', FLoader.Version);
  Writeln('Leaving OpenSSL loaded for unit finalization');
  // Deliberately retain the interface and callback owner; do not call Unload.
end;

procedure TShutdownProbe.Verify;
begin
  Require((FLoadCount = 2) and (FUnloadCount = 2),
    Format('Expected two load/unload callbacks; observed %d/%d',
      [FLoadCount, FUnloadCount]));
  Require(FFailure = '', 'Callback failed: ' + FFailure);
  Require(FInjectedFailureObserved = FInjectFailure,
    'Cleanup failure injection did not match the requested test mode');
  // Use the retained interface: querying the singleton now would recreate it.
  Require((FLoader.State = lsNotLoaded) and not FLoader.IsLoaded,
    'Loader remained ready after finalization');
  Require((FLoader.Version = '') and (FLoader.ConfigDirectory = '') and
    (FLoader.ModulesDirectory = '') and (FLoader.EnginesDirectory = ''),
    'Runtime metadata survived cleanup');
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Require(not Assigned(OpenSSL_version_num), 'Dynamic version symbol was not reset');
{$ENDIF}
  if FInjectFailure then
  begin
    Writeln('PASS: cleanup callback 2 raised EExpectedCleanupFailure: Injected cleanup failure');
    Writeln('PASS: loader caught the expected exception, callback 1 still ran, and all final cleanup checks passed');
  end;
end;

procedure Run;
var
  LProbe: TShutdownProbe;
begin
  LProbe := TShutdownProbe.Create;
  CallbackOwner := LProbe;
  VerifyShutdown := LProbe.Verify;
  LProbe.Execute;
  MainCompleted := True;
end;

begin
  ExitCode := 0;
  try
    Run;
  except
    on E: Exception do
    begin
      ExitCode := 1;
      Writeln('FAIL: ', E.ClassName, ': ', E.Message);
    end;
  end;
end.
