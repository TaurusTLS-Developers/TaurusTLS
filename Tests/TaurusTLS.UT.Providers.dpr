/// <summary>Runs one OpenSSL provider scenario in a fresh process.</summary>
program TaurusTLS.UT.Providers;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  DUnitX.Loggers.Console,
  DUnitX.Loggers.Xml.NUnit,
  DUnitX.TestFramework,
  TaurusTLS.UT.Providers.Common in 'TaurusTLS.UT.Providers.Common.pas',
  TaurusTLS.UT.Providers.FIPS in 'TaurusTLS.UT.Providers.FIPS.pas',
  TaurusTLS.UT.Providers.Legacy in 'TaurusTLS.UT.Providers.Legacy.pas';

var
  Runner: ITestRunner;
  Results: IRunResults;

begin
  try
    TDUnitX.CheckCommandLine;
    if not SelectProviderScenario then
      Exit;
    Runner := TDUnitX.CreateRunner;
    // Only explicitly registered provider fixtures belong to this runner.
    Runner.UseRTTI := False;
    Runner.FailsOnNoAsserts := True;
    if TDUnitX.Options.ConsoleMode <> TDunitXConsoleMode.Off then
      Runner.AddLogger(TDUnitXConsoleLogger.Create(
        TDUnitX.Options.ConsoleMode = TDunitXConsoleMode.Quiet));
    Runner.AddLogger(TDUnitXXMLNUnitFileLogger.Create(TDUnitX.Options.XMLOutputFile));
    Results := Runner.Execute;
    if not Results.AllPassed or (Results.PassCount <> 1) or
      (Results.IgnoredCount <> 0) or (Results.MemoryLeakCount <> 0) then
    begin
      Writeln('Expected exactly one successful provider scenario. Passed: ',
        Results.PassCount, '; failed: ', Results.FailureCount,
        '; errors: ', Results.ErrorCount, '; ignored: ', Results.IgnoredCount,
        '; leaked: ', Results.MemoryLeakCount);
      System.ExitCode := EXIT_ERRORS;
    end;
  except
    on E: Exception do
    begin
      System.ExitCode := EXIT_ERRORS;
      Writeln(E.ClassName, ': ', E.Message);
    end;
  end;
  if TDUnitX.Options.ExitBehavior = TDUnitXExitBehavior.Pause then
  begin
    Write('Done.. press <Enter> key to quit.');
    Readln;
  end;
end.
