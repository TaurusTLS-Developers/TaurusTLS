# Detailed Design Document: State Machine Unit-Testing (SM-UT)

## 1. Test Mock Infrastructure (`TaurusTLS_StateMachine_Tests.pas`)

To test the state machine statically, we implement a lightweight mock config and a mock socket context descendant that stubs out the abstract cryptographic methods.

~~~pascal
type
  /// <summary>Mock socket config to capture state change and debug events.</summary>
  TTaurusTLSMockSocketConfig = class(TTaurusTLSCustomSocketConfig)
  protected
    procedure DoCloneSession(ASSL: PSSL); override;
  end;

  /// <summary>Mock socket context to expose protected methods for testing.</summary>
  TTaurusTLSMockSocket = class(TTaurusTLSBaseSocket)
  protected
    procedure DoHandshake; override;
    procedure ClosePhysicalSocket; override;
  end;

  /// <summary>Unit test runner class for the state machine.</summary>
  TTaurusTLSStateMachineTests = class
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FConfig: TTaurusTLSMockSocketConfig;
    FSocket: TTaurusTLSMockSocket;
    FStateChanges: TList; // Tracks state transition event history
    FDebugLogs: TStringList;

    procedure HandleStateChange(ASender: TObject; AOldState, ANewState: TTaurusTLSSslState);
    procedure HandleDebugMessage(ASender: TObject; const AMessage: String);
  public
    procedure Setup;
    procedure Teardown;

    // Test cases
    procedure TestTransitionMatrix;
    procedure TestRedundantTransitions;
    procedure TestAPIGuards;
  end;
~~~

---

## 2. Mock Classes Implementation

~~~pascal
{ TTaurusTLSMockSocketConfig }
procedure TTaurusTLSMockSocketConfig.DoCloneSession(ASSL: PSSL);
begin
  // No-op for mock testing
end;

{ TTaurusTLSMockSocket }
procedure TTaurusTLSMockSocket.DoHandshake;
begin
  // Simulates a successful handshake transition to established
  TransitionTo(seEstablished);
end;

procedure TTaurusTLSMockSocket.ClosePhysicalSocket;
begin
  // No-op for mock testing
end;
~~~

---

## 3. Test Cases Implementation

### 3.1. Test Transition Matrix (`TestTransitionMatrix`)
Systematically runs the 7x7 transition matrix. Verifies that all valid transitions succeed and all invalid transitions raise `ETaurusTLSSocketStateError` (or `ETaurusTLSInvalidTransition`).

~~~pascal
procedure TTaurusTLSStateMachineTests.TestTransitionMatrix;
var
  LCurrentState, LTargetState: TTaurusTLSSslState;
  LTransitionSuccess: Boolean;
begin
  for LCurrentState := Low(TTaurusTLSSslState) to High(TTaurusTLSSslState) do
  begin
    for LTargetState := Low(TTaurusTLSSslState) to High(TTaurusTLSSslState) do
    begin
      if LCurrentState = LTargetState then Continue; // Skip self-transitions
      
      Setup;
      try
        // 1. Force the mock socket to the start state of this test step
        // We do this by modifying the volatile FState variable directly (for testing only)
        // or by executing valid transitions sequentially.
        FSocket.DoSetState(LCurrentState);
        FStateChanges.Clear;

        LTransitionSuccess := True;
        try
          FSocket.TransitionTo(LTargetState);
        except
          on E: Exception do
          begin
            LTransitionSuccess := False;
            // Verify that an invalid transition raised the correct exception type
            Assert((E is ETaurusTLSSocketStateError) or (E is ETaurusTLSInvalidTransition), 
              'Wrong exception raised: ' + E.ClassName);
          end;
        end;

        // 2. Validate against the expected transition matrix
        if FSocket.IsValidTransition(LCurrentState, LTargetState) then
        begin
          Assert(LTransitionSuccess, Format('Valid transition failed: %s -> %s', 
            [LCurrentState.AsString, LTargetState.AsString]));
          Assert(FSocket.State = LTargetState, 'State property was not updated correctly.');
          Assert(FStateChanges.Count = 1, 'OnStateChange was not fired.');
        end
        else
        begin
          Assert(not LTransitionSuccess, Format('Invalid transition succeeded: %s -> %s', 
            [LCurrentState.AsString, LTargetState.AsString]));
        end;
      finally
        Teardown;
      end;
    end;
  end;
end;
~~~

### 3.2. Test Redundant Transitions (`TestRedundantTransitions`)
Verifies that attempting to transition to the current active state is safely ignored and logged.

~~~pascal
procedure TTaurusTLSStateMachineTests.TestRedundantTransitions;
begin
  Setup;
  try
    // Set socket to Initialized
    FSocket.TransitionTo(seInitialized);
    FDebugLogs.Clear;

    // Attempt redundant transition
    FSocket.TransitionTo(seInitialized);

    // Assertions
    Assert(FSocket.State = seInitialized, 'State was modified during redundant transition.');
    Assert(FDebugLogs.Count = 1, 'Debug message was not logged.');
    Assert(Pos('Redundant', FDebugLogs[0]) > 0, 'Incorrect debug warning message logged.');
  finally
    Teardown;
  end;
end;
~~~

### 3.3. Test API Guards (`TestAPIGuards`)
Verifies that I/O and negotiation methods raise immediate state errors when invoked outside of their valid state windows.

~~~pascal
procedure TTaurusTLSStateMachineTests.TestAPIGuards;
var
  LTempBytes: TIdBytes;
  LIoErrorRaised: Boolean;
begin
  Setup;
  try
    SetLength(LTempBytes, 10);

    // --- TEST 1: Recv and Send in seIdle (Invalid) ---
    LIoErrorRaised := False;
    try
      FSocket.Recv(LTempBytes);
    except
      on E: ETaurusTLSSocketStateError do
        LIoErrorRaised := True;
    end;
    Assert(LIoErrorRaised, 'Recv did not raise ETaurusTLSSocketStateError in seIdle.');

    LIoErrorRaised := False;
    try
      FSocket.Send(LTempBytes, 0, 10);
    except
      on E: ETaurusTLSSocketStateError do
        LIoErrorRaised := True;
    end;
    Assert(LIoErrorRaised, 'Send did not raise ETaurusTLSSocketStateError in seIdle.');

    // --- TEST 2: ProcessSSL in seIdle (Invalid) ---
    LIoErrorRaised := False;
    try
      FSocket.ProcessSSL;
    except
      on E: ETaurusTLSSocketStateError do
        LIoErrorRaised := True;
    end;
    Assert(LIoErrorRaised, 'ProcessSSL did not raise ETaurusTLSSocketStateError in seIdle.');

  finally
    Teardown;
  end;
end;
~~~