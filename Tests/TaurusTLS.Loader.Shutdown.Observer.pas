unit TaurusTLS.Loader.Shutdown.Observer;

interface

type
  TShutdownVerification = procedure of object;

var
  CallbackOwner: TObject;
  VerifyShutdown: TShutdownVerification;
  MainCompleted: Boolean;
  ConfigFilename: string;

implementation

uses
  System.SysUtils;

procedure CheckShutdown;
begin
  try
    if not MainCompleted then
    begin
      ExitCode := 1;
      Writeln('FAIL: shutdown verification skipped because startup failed; see the preceding error');
    end
    else if not Assigned(VerifyShutdown) then
    begin
      ExitCode := 1;
      Writeln('FAIL: shutdown verification was not installed');
    end
    else
    begin
      VerifyShutdown;
      Writeln('PASS: loader-only unit finalization completed');
    end;
  except
    on E: Exception do
    begin
      ExitCode := 1;
      Writeln('FAIL: ', E.ClassName, ': ', E.Message);
    end;
  end;
  // The observer has no loader dependency and precedes it in the DPR uses list.
  // Release the callback owner and its retained interface only after verification.
  CallbackOwner.Free;
  CallbackOwner := nil;
  if (ConfigFilename <> '') and FileExists(ConfigFilename) then
    if not DeleteFile(ConfigFilename) then
    begin
      ExitCode := 1;
      Writeln('FAIL: could not delete temporary configuration: ', ConfigFilename);
    end;
end;

initialization
  MainCompleted := False;

finalization
  CheckShutdown;
end.

