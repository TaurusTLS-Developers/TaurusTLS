program TaurusTLS.Loader.FirstCreation;

{ Purpose
  Force fully constructed loader candidates to compete for first publication.
  Readiness counts down only after each candidate has been constructed.
  Starter releases all candidates, and Finisher counts completed workers.
  Each worker retains its result or exception; exceptions never escape workers.
  Check one shared winner, destruction of every losing candidate, preservation
  through normal unit initialization, and absence of implicit OpenSSL loading.

  Build
  Use the standard UNITTEST conditional define, as in other test projects.
  Add the Tests, Source and Indy directories to the compiler unit search path.
  This support unit registers generic hooks before loader initialization.
  Other UNITTEST projects leave the hooks unassigned; no competition runs.
  No dedicated first-creation define or separate DCU directory is required.
  No native OpenSSL distribution is needed for dynamic builds: this test never
  calls Load. Static targets need their normal archive library search path.

  Usage
    TaurusTLS.Loader.FirstCreation.exe
    TaurusTLS.Loader.FirstCreation.exe --threads:3
    ./TaurusTLS_Loader_FirstCreation --threads:16; echo $?
  --threads:<count> accepts 2 through 64; the default is 3.
  --exit:Pause waits for Enter after all finalization checks (useful in the IDE).
  --exit:Continue, --exit:, or no exit option returns immediately (the default).
  Example for IDE runs: --threads:3 --exit:Pause
  Forced termination on a worker timeout bypasses the pause.
  Each execution tests one first publication. Repeat with fresh processes for
  stress runs. Run outside the debugger and use an external process timeout.
  Internal waits are bounded; a timeout terminates the test process without
  freeing synchronization objects still in use by workers.

  Results
  PASS confirms competing candidates returned the same singleton, losing
  candidates were destroyed, initialization preserved the early winner, and
  the loader remained not loaded. Success exits 0; detected failures exit 1.
}

{$APPTYPE CONSOLE}
{$I TaurusTLSCompilerDefines.inc}
{$I TaurusTLSLinkDefines.inc}
{$IFNDEF UNITTEST}
  {$MESSAGE FATAL 'FirstCreation requires UNITTEST in project conditional defines'}
{$ENDIF}
{$R *.res}

uses
  System.SysUtils,
  TaurusTLSLoader,
  TaurusTLSHeaders_crypto,
  TaurusTLS.Loader.ConsoleSupport in 'TaurusTLS.Loader.ConsoleSupport.pas',
  TaurusTLS.Loader.FirstCreation.Support in 'TaurusTLS.Loader.FirstCreation.Support.pas';

procedure Run;
var
  Loader: IOpenSSLLoader;
  I: Integer;
begin
  Loader := GetOpenSSLLoader;
  VerifyFirstCreation(Loader);
  for I := 1 to 1000 do
    if GetOpenSSLLoader <> Loader then
      raise Exception.Create('Repeated lookup changed singleton identity');
  if (Loader.State <> lsNotLoaded) or Loader.IsLoaded then
    raise Exception.Create('First creation implicitly initialized OpenSSL');
  if (Loader.Version <> '') or (Loader.ConfigDirectory <> '') or
    (Loader.ModulesDirectory <> '') or (Loader.EnginesDirectory <> '') then
    raise Exception.Create('Unloaded singleton published runtime metadata');
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  if Assigned(OpenSSL_version_num) then
    raise Exception.Create('First creation unexpectedly bound native APIs');
{$ENDIF}
  Writeln('PASS: stable singleton identity; no implicit OpenSSL loading');
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
