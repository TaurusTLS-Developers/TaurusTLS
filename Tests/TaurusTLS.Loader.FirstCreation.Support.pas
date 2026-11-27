unit TaurusTLS.Loader.FirstCreation.Support;

// Diagnostic support for the standalone first-creation executable only.
// This unit deliberately has no dependency on TaurusTLSLoader.
interface

uses
  TaurusTLSLoader.TestHooks;

{$IFNDEF UNITTEST}
  {$MESSAGE FATAL 'FirstCreation requires UNITTEST in project conditional defines'}
{$ENDIF}

type
  TLoaderFactory = TLoaderTestFactory;

procedure BeforeFirstAccess(AFactory: TLoaderFactory);
procedure CandidateReady;
procedure CandidateDestroyed;
procedure VerifyFirstCreation(const ALoader: IInterface);

implementation

uses
  System.SysUtils, System.Classes, System.SyncObjs,
  TaurusTLS.Loader.ConsoleSupport,
{$IFDEF MSWINDOWS}
  Winapi.Windows;
{$ELSE}
  Posix.Unistd;
{$ENDIF}

const
  WaitMilliseconds = 15000;

type
  TCreationWorker = class(TThread)
  private
    FFactory: TLoaderFactory;
    FResult: IInterface;
    FError: Exception;
    FReady: Boolean;
  protected
    procedure Execute; override;
  public
    constructor Create(AFactory: TLoaderFactory);
    destructor Destroy; override;
    procedure SignalReady;
  end;

var
  AccessStarted: Integer;
  Running: Integer;
  RemainingReady: Integer;
  RemainingFinished: Integer;
  Constructed: Integer;
  Destroyed: Integer;
  WorkerCount: Integer;
  Readiness: TEvent;
  Starter: TEvent;
  Finisher: TEvent;
  Winner: IInterface;
  Completed: Boolean;

threadvar
  CurrentWorker: TCreationWorker;

procedure Require(ACondition: Boolean; const AMessage: string);
begin
  if not ACondition then
    raise Exception.Create(AMessage);
end;

procedure FatalTimeout(const AMessage: string);
begin
  Writeln('FAIL: ', AMessage);
  // Halt executes Delphi unit finalizers. Terminate directly instead when
  // workers may still access the singleton or gates. Flush diagnostics first.
  Flush(Output);
{$IFDEF MSWINDOWS}
  TerminateProcess(GetCurrentProcess, 1);
{$ELSE}
  Posix.Unistd._exit(1);
{$ENDIF}
  Halt(1);
end;

constructor TCreationWorker.Create(AFactory: TLoaderFactory);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FFactory := AFactory;
end;

destructor TCreationWorker.Destroy;
begin
  FError.Free;
  inherited Destroy;
end;

procedure TCreationWorker.SignalReady;
begin
  if not FReady then
  begin
    FReady := True;
    if TInterlocked.Decrement(RemainingReady) = 0 then
      Readiness.SetEvent;
  end;
end;

procedure TCreationWorker.Execute;
begin
  CurrentWorker := Self;
  try
    try
      FResult := FFactory();
    except
      // Keep one exception per worker; never let it escape the thread.
      FError := Exception(AcquireExceptionObject);
    end;
  finally
    // A construction error must not strand the readiness countdown.
    SignalReady;
    CurrentWorker := nil;
    if TInterlocked.Decrement(RemainingFinished) = 0 then
      Finisher.SetEvent;
  end;
end;

procedure CandidateReady;
begin
  if CurrentWorker <> nil then
  begin
    TInterlocked.Increment(Constructed);
    CurrentWorker.SignalReady;
    Require(Starter.WaitFor(WaitMilliseconds) = wrSignaled,
      'Starter timed out before candidate publication');
  end;
end;

procedure CandidateDestroyed;
begin
  if TInterlocked.CompareExchange(Running, 0, 0) <> 0 then
    TInterlocked.Increment(Destroyed);
end;

function ParseWorkerCount: Integer;
var
  I: Integer;
  Argument: string;
begin
  Result := 3;
  for I := 1 to ParamCount do
  begin
    Argument := ParamStr(I);
    if ConsumeExitOption(Argument) then
      Continue;
    if SameText(Copy(Argument, 1, 10), '--threads:') then
    begin
      Require(TryStrToInt(Copy(Argument, 11, MaxInt), Result),
        '--threads: requires an integer');
      Require((Result >= 2) and (Result <= 64),
        '--threads: must be between 2 and 64');
    end
    else
      raise Exception.Create('Unknown argument: ' + Argument);
  end;
end;

procedure RunCompetition(AFactory: TLoaderFactory);
var
  Workers: array of TCreationWorker;
  I: Integer;
  Created: Integer;
begin
  WorkerCount := ParseWorkerCount;
  RemainingReady := WorkerCount;
  RemainingFinished := WorkerCount;
  Readiness := TEvent.Create(nil, True, False, '');
  Starter := TEvent.Create(nil, True, False, '');
  Finisher := TEvent.Create(nil, True, False, '');
  SetLength(Workers, WorkerCount);
  Created := 0;
  TInterlocked.Exchange(Running, 1);
  try
    try
      for I := 0 to WorkerCount - 1 do
      begin
        Workers[I] := TCreationWorker.Create(AFactory);
        Inc(Created);
        Workers[I].Start;
      end;
      if Readiness.WaitFor(WaitMilliseconds) <> wrSignaled then
        FatalTimeout('Candidates did not reach the readiness countdown');
      Starter.SetEvent;
      if Finisher.WaitFor(WaitMilliseconds) <> wrSignaled then
        FatalTimeout('Workers did not finish first creation');
      for I := 0 to WorkerCount - 1 do
        Workers[I].WaitFor;
      for I := 0 to WorkerCount - 1 do
        if Workers[I].FError <> nil then
          raise Exception.CreateFmt('Worker %d: %s: %s',
            [I + 1, Workers[I].FError.ClassName, Workers[I].FError.Message]);
      Require(Constructed = WorkerCount,
        'Not every worker constructed a competing candidate');
      Require(Destroyed = WorkerCount - 1,
        'Losing candidates were not destroyed exactly once');
      Winner := Workers[0].FResult;
      Require(Winner <> nil, 'First creation returned no loader');
      for I := 1 to WorkerCount - 1 do
        Require(Workers[I].FResult = Winner,
          'Workers observed different singleton interfaces');
      Completed := True;
      Writeln('PASS: ', WorkerCount, ' constructed candidates competed; one shared winner, ',
        Destroyed, ' losing candidates destroyed');
    finally
      Starter.SetEvent;
      // Joining precedes gate and thread destruction, including startup errors.
      if Created <> WorkerCount then
        FatalTimeout('Worker creation did not complete');
      if Finisher.WaitFor(WaitMilliseconds) <> wrSignaled then
        FatalTimeout('Worker join timed out');
      for I := 0 to Created - 1 do
        Workers[I].WaitFor;
    end;
  finally
    TInterlocked.Exchange(Running, 0);
    for I := 0 to Created - 1 do
      Workers[I].Free;
    Finisher.Free;
    Starter.Free;
    Readiness.Free;
  end;
end;

procedure BeforeFirstAccess(AFactory: TLoaderFactory);
begin
  if TInterlocked.CompareExchange(AccessStarted, 1, 0) <> 0 then
    Exit;
  try
    RunCompetition(AFactory);
  except
    on E: Exception do
    begin
      Writeln('FAIL: ', E.ClassName, ': ', E.Message);
      Halt(1);
    end;
  end;
end;

procedure VerifyFirstCreation(const ALoader: IInterface);
begin
  Require(Completed, 'First-creation hooks did not execute; enable UNITTEST and compile the loader from source');
  Require(ALoader = Winner, 'Normal unit initialization replaced the early winner');
  Writeln('PASS: normal unit initialization preserved the early winner');
end;

initialization
  // The DPR lists this unit before the loader, so registration precedes access.
  OnLoaderAccess := BeforeFirstAccess;
  OnLoaderCandidateReady := CandidateReady;
  OnLoaderCandidateDestroyed := CandidateDestroyed;

finalization
  OnLoaderAccess := nil;
  OnLoaderCandidateReady := nil;
  OnLoaderCandidateDestroyed := nil;
end.

