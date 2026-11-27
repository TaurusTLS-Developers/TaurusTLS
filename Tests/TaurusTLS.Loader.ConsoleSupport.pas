unit TaurusTLS.Loader.ConsoleSupport;

interface

// Returns True for an exit option and validates its value.
function ConsumeExitOption(const AArgument: string): Boolean;

implementation

uses
  System.SysUtils;

var
  PauseAtExit: Boolean;

function ConsumeExitOption(const AArgument: string): Boolean;
var
  Value: string;
begin
  Result := SameText(Copy(AArgument, 1, 7), '--exit:');
  if not Result then
    Exit;
  Value := Copy(AArgument, 8, MaxInt);
  if SameText(Value, 'Pause') then
    PauseAtExit := True
  else if (Value = '') or SameText(Value, 'Continue') then
    PauseAtExit := False
  else
    raise Exception.Create('--exit: accepts Pause, Continue, or a blank value');
end;

procedure PreparePause;
var
  I: Integer;
  Argument: string;
begin
  // Select pause before loader initialization so startup errors stay visible.
  // The application's option parser reports invalid values.
  for I := 1 to ParamCount do
  begin
    Argument := ParamStr(I);
    if SameText(Argument, '--exit:Pause') then
      PauseAtExit := True
    else if SameText(Argument, '--exit:Continue') or SameText(Argument, '--exit:') then
      PauseAtExit := False;
  end;
end;

procedure FinishConsole;
begin
  if PauseAtExit then
  begin
    Writeln('Press Enter to close. Exit code: ', ExitCode);
    Flush(Output);
    Readln;
  end;
end;

initialization
  PreparePause;

finalization
  FinishConsole;
end.

