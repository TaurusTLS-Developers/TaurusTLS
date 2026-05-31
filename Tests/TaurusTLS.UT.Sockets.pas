{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/TaurusTLS-Developers/TaurusTLS                * }
{ *                                                                            * }
{ *  Copyright (c) 2024 TaurusTLS Developers, All Rights Reserved              * }
{ ****************************************************************************** }
{$I TaurusTLSUTCompilerDefines.inc}
{$DEFINE UNITTEST}

unit TaurusTLS.UT.Sockets;

interface

uses
  DUnitX.TestFramework,
  System.Classes,
  System.SysUtils,
  System.Generics.Collections,
  IdCTypes,
  IdGlobaL,
  TaurusTLS_Sockets,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_ech,
  TaurusTLSHeaders_ssl,
  TaurusTLSExceptionHandlers,
  TaurusTLS_ECH,
  TaurusTLS.UT.TestClasses;

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
  end;

type
  [TestFixture]
  [Category('Test,TLS.Sockets,TLS.Sockets.SM,TLS.IOHandler')]
  TTaurusTLSSocketsStateMachineFixture = class(TOsslBaseFixture)
  protected type

  protected
    FSSLCtx: PSSL_CTX;
    FSocket: TTaurusTLSMockSocket;
    FStateChanges: TList<TTaurusTLSSslState>; // Tracks state transition event history
    FDebugLogs: TStringList;
    procedure HandleStateChange(ASender: TObject;
      AOldState, ANewState: TTaurusTLSSslState);
    procedure HandleDebugMessage(ASender: TObject; const AMessage: String);
    procedure Reset;
  public
    [Setup]
    procedure Setup;
    [Teardown]
    procedure Teardown;

    // Test cases
    [Test]
    procedure TestTransitionMatrix;
    [Test]
    procedure TestClientHappyPath;
    [Test]
    procedure TestEarlyAbortPaths;
    [Test]
    procedure TestRedundantTransitions;
    [Test]
    procedure TestAPIGuards;  end;


  [TestFixture]
  [Category('TLS.Sockets,TLS.IOHandler')]
  TTaurusTLSSocketsFixture = class(TOsslBaseFixture)
  private
    fSocket: TTaurusTLSClientSocket;
    fCtx: PSSL_CTX;
  public
    [Setup]
    procedure Setup;
    [Teardown]
    procedure Teardown;

  end;

implementation

{ TTaurusTLSSocketsFixture }

procedure TTaurusTLSSocketsFixture.Setup;
begin
  fCtx := SSL_CTX_new(TLS_client_method);
  fSocket := TTaurusTLSClientSocket.Create(nil);
end;

procedure TTaurusTLSSocketsFixture.Teardown;
begin
  FreeAndNil(fSocket);
  if fCtx <> nil then
    SSL_CTX_free(fCtx);
  FCtx:=nil;
end;


{ TTaurusTLSMockSocketConfig }

procedure TTaurusTLSMockSocketConfig.DoCloneSession(ASSL: PSSL);
begin
  // Not to operate in the mock
end;

{ TTaurusTLSMockSocket }

procedure TTaurusTLSMockSocket.DoHandshake;
begin
  TransitionTo(seEstablished);
end;

{ TTaurusTLSSocketsStateMachineFixture }

procedure TTaurusTLSSocketsStateMachineFixture.Setup;
begin
  FStateChanges:=TList<TTaurusTLSSslState>.Create; // Tracks state transition event history
  FDebugLogs:= TStringList.Create;

  FSSLCtx:=SSL_CTX_new(TLS_client_method());
  var lConfig:=TTaurusTLSMockSocketConfig.Create(Self);
  lConfig.SSLCtx:=FSSLCtx;
  lConfig.OnStateChange:=HandleStateChange;
  lConfig.OnDebug:=HandleDebugMessage;
  FSocket:=TTaurusTLSMockSocket.Create(lConfig);
end;

procedure TTaurusTLSSocketsStateMachineFixture.Teardown;
begin
  FreeAndNil(FSocket);
  SSL_CTX_free(FSSLCtx);
  FreeAndNil(FStateChanges);
  FreeAndNil(FDebugLogs);
end;

procedure TTaurusTLSSocketsStateMachineFixture.HandleDebugMessage(
  ASender: TObject; const AMessage: String);
begin
  FDebugLogs.Add(AMessage);
end;

procedure TTaurusTLSSocketsStateMachineFixture.HandleStateChange(
  ASender: TObject; AOldState, ANewState: TTaurusTLSSslState);
begin
  FStateChanges.Add(ANewState);
end;

procedure TTaurusTLSSocketsStateMachineFixture.Reset;
begin
  FStateChanges.Clear;
  FDebugLogs.Clear;
end;

procedure TTaurusTLSSocketsStateMachineFixture.TestAPIGuards;
var
  lTempBytes: TIdBytes;

begin
  SetLength(LTempBytes, 10);

  // --- TEST 1: Recv and Send in seIdle (Invalid) ---
  Assert.WillRaise(
    procedure
    begin
      FSocket.Recv(LTempBytes);
    end,
    ETaurusTLSSocketStateError,
    'Recv did not raise ETaurusTLSSocketStateError in seIdle.'
  );
  Assert.WillRaise(
    procedure
    begin
      FSocket.Send(LTempBytes, 0, Length(LTempBytes));
    end,
    ETaurusTLSSocketStateError,
    'Send did not raise ETaurusTLSSocketStateError in seIdle.'
  );

  // --- TEST 2: ProcessSSL in seIdle (Invalid) ---
  Assert.WillRaise(
    procedure
    begin
      FSocket.ProcessSSL;
    end,
    ETaurusTLSSocketStateError,
    'ProcessSSL did not raise ETaurusTLSSocketStateError in seIdle.'
  );
end;

procedure TTaurusTLSSocketsStateMachineFixture.TestClientHappyPath;
begin
  Assert.AreEqual(seIdle, FSocket.State, 'Initial state must be seIdle.');

  // 1. Transition to Initialized (Triggers InitSSL and FSSL allocation)
  FSocket.TransitionTo(seInitialized);
  Assert.AreEqual(seInitialized, FSocket.State, 'Failed to transition to seInitialized.');
  Assert.IsNotNull(FSocket.SSL, 'FSSL was not allocated during initialization.');

  // 2. Transition to Handshaking
  FSocket.TransitionTo(seHandshaking);
  Assert.AreEqual(seHandshaking, FSocket.State, 'Failed to transition to seHandshaking.');

  // 3. Transition to Established (Handshake complete)
  FSocket.TransitionTo(seEstablished);
  Assert.AreEqual(seEstablished, FSocket.State, 'Failed to transition to seEstablished.');

  // 4. Transition to Closing (Shutdown initiated)
  FSocket.TransitionTo(seClosing);
  Assert.AreEqual(seClosing, FSocket.State, 'Failed to transition to seClosing.');

  // 5. Transition to Closed (Teardown complete, FSSL freed)
  FSocket.TransitionTo(seClosed);
  Assert.AreEqual(seClosed, FSocket.State, 'Failed to transition to seClosed.');
  Assert.IsNull(FSocket.SSL, 'FSSL was not cleanly deallocated.');
end;

procedure TTaurusTLSSocketsStateMachineFixture.TestEarlyAbortPaths;
begin
  FSocket.TransitionTo(seInitialized);
  FSocket.TransitionTo(seClosed);
  Assert.AreEqual(seClosed, FSocket.State, 'Failed to abort from seInitialized.');
  Assert.IsNull(FSocket.SSL, 'FSSL was leaked during early abort.');
end;

procedure TTaurusTLSSocketsStateMachineFixture.TestRedundantTransitions;
begin
  // Set socket to Initialized
  FSocket.TransitionTo(seInitialized);
  FDebugLogs.Clear;

  // Attempt redundant transition
  Assert.WillRaiseWithMessageRegex(
    procedure
    begin
      FSocket.TransitionTo(seInitialized);
    end,
    EAssertionFailed,
    '^Redundant state transition:.*$'
  );

  // Assertions
  Assert.AreEqual(seInitialized, FSocket.State, 'State was modified during redundant transition.');
  // Currently no OnDebug implemented there.
  //  Assert.AreEqual(1, FDebugLogs.Count, 'Debug message was not logged.');
end;

procedure TTaurusTLSSocketsStateMachineFixture.TestTransitionMatrix;
var
  LCurrentState, LTargetState: TTaurusTLSSslState;
  LTransitionSuccess: Boolean;

begin
  for LCurrentState := Low(TTaurusTLSSslState) to High(TTaurusTLSSslState) do
  begin
    for LTargetState := Low(TTaurusTLSSslState) to High(TTaurusTLSSslState) do
    begin
      if LCurrentState = LTargetState then Continue; // Skip self-transitions

      Reset;
      // 1. Force the mock socket to the start state of this test step
      // We do this by modifying the volatile FState variable directly (for testing only)
      // or by executing valid transitions sequentially.
      FSocket.DoSetState(LCurrentState);
      LTransitionSuccess := True;
      try
        FSocket.TransitionTo(LTargetState);
      except
        on E: Exception do
        begin
         LTransitionSuccess := False;
          // Verify that an invalid transition raised the correct exception type
          Assert.IsTrue((E is ETaurusTLSSocketStateError) or (E is ETaurusTLSSocketInitError),
            'Wrong exception raised: ' + E.ClassName);
        end;
      end;

      // 2. Validate against the expected transition matrix
      if FSocket.IsValidTransition(LCurrentState, LTargetState) then
      begin
        Assert.IsTrue(LTransitionSuccess, Format('Valid transition failed: %s -> %s',
          [LCurrentState.AsString, LTargetState.AsString]));
        Assert.AreEqual(LTargetState, FSocket.State,
          Format('State property was not updated correctly.',
          [LCurrentState.AsString, LTargetState.AsString]));
        Assert.IsTrue(FStateChanges.Count >= 1, 'OnStateChange was not fired: ');
      end
      else
      begin
        Assert.IsFalse(LTransitionSuccess, Format('Invalid transition succeeded: %s -> %s',
          [LCurrentState.AsString, LTargetState.AsString]));
      end;
    end;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TTaurusTLSSocketsFixture);
  TDUnitX.RegisterTestFixture(TTaurusTLSSocketsStateMachineFixture);

end.
