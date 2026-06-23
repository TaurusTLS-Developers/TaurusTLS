# Detailed Design Document: Socket Unit-Testing (SO-UT)

## 1. Test Harness Infrastructure (`TaurusTLS_Sockets_Tests.pas`)

To test the blocking sockets of TaurusTLS without relying on physical network resources, we implement a threaded in-memory loopback harness. 

### 1.1. The Handshake Thread Class
This class executes the synchronous, blocking handshake of a socket context in a background thread.

~~~pascal
type
  THandshakeThread = class(TThread)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FSocket: TTaurusTLSBaseSocket;
    FHandle: TIdStackSocketHandle;
    FError: Exception;
  protected
    procedure Execute; override;
  public
    constructor Create(ASocket: TTaurusTLSBaseSocket; AHandle: TIdStackSocketHandle);
    destructor Destroy; override;
    
    property Error: Exception read FError;
  end;

constructor THandshakeThread.Create(ASocket: TTaurusTLSBaseSocket; AHandle: TIdStackSocketHandle);
begin
  inherited Create(True); // Create suspended
  FSocket := ASocket;
  FHandle := AHandle;
  FError := nil;
  FreeOnTerminate := False;
end;

destructor THandshakeThread.Destroy;
begin
  FreeAndNil(FError);
  inherited Destroy;
end;

procedure THandshakeThread.Execute;
begin
  try
    FSocket.Connect(FHandle);
  except
    on E: Exception do
    begin
      FError := AcquireExceptionObject; // Capture the exact exception safely
    end;
  end;
end;
~~~

### 1.2. The In-Memory Socket Test Base Class
This base class manages the setup of the shared `SSL_CTX` containers, test certificate loading, and the background thread execution loop.

~~~pascal
type
  TTaurusTLSSocketTestBase = class
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict{$ENDIF} private
    FClientCtx: PSSL_CTX;
    FServerCtx: PSSL_CTX;
    
    FClientConfig: TaurusTLSClientSocketConfig;
    FServerConfig: TTaurusTLSCustomSocketConfig;
    
    FClientSocket: TTaurusTLSClientSocket;
    FServerSocket: TTaurusTLSPeerSocket;
    
    FClientReadBio: TTaurusTLSMemBio;
    FClientWriteBio: TTaurusTLSMemBio;
    FServerReadBio: TTaurusTLSMemBio;
    FServerWriteBio: TTaurusTLSMemBio;
    
    procedure PumpBytes;
  protected
    procedure SetupContexts; virtual;
    procedure SetupSockets; virtual;
    procedure TeardownContexts; virtual;
    procedure TeardownSockets; virtual;
    
    procedure RunHandshake;
  public
    // Test entry points
    procedure TestSuccessfulHandshake;
    procedure TestECHKeyMismatch;
    procedure TestMTLSFailure;
    procedure TestTCPRSTShield;
  end;
~~~

---

## 2. Helper Implementation: The Bytes Pump

The `PumpBytes` method is called by the main thread. It acts as the "virtual wire," transferring raw encrypted bytes between the socket's memory BIOs in-memory.

~~~pascal
procedure TTaurusTLSSocketTestBase.PumpBytes;
var
  LTempBytes: TIdBytes;
begin
  // 1. Pump bytes: Client Write -> Server Read
  if FClientWriteBio.Pending > 0 then
  begin
    LTempBytes := FClientWriteBio.AsBytes;
    FServerReadBio.AsBytes := LTempBytes;
  end;

  // 2. Pump bytes: Server Write -> Client Read
  if FServerWriteBio.Pending > 0 then
  begin
    LTempBytes := FServerWriteBio.AsBytes;
    FClientReadBio.AsBytes := LTempBytes;
  end;
end;

procedure TTaurusTLSSocketTestBase.RunHandshake;
var
  LClientThread: THandshakeThread;
  LServerThread: THandshakeThread;
begin
  LClientThread := THandshakeThread.Create(FClientSocket, 1); // Mock FD = 1
  LServerThread := THandshakeThread.Create(FServerSocket, 2); // Mock FD = 2
  try
    LClientThread.Start;
    LServerThread.Start;

    // Loop until both threads finish negotiating or fail
    while (not LClientThread.Finished) or (not LServerThread.Finished) do
    begin
      PumpBytes;
      Sleep(5); // Prevent CPU thrashing
    end;

    // Final pump to clear remaining buffers
    PumpBytes;

    // If either thread raised an exception, propagate it to the test runner
    if Assigned(LClientThread.Error) then
      raise LClientThread.Error;
    if Assigned(LServerThread.Error) then
      raise LServerThread.Error;
  finally
    LClientThread.Free;
    LServerThread.Free;
  end;
end;
~~~

---

## 3. Test Cases Implementation

### 3.1. Test Successful Handshake (`TestSuccessfulHandshake`)
Validates a clean, standard TLS 1.3 handshake. Both client and server must land safely in the `seEstablished` state.

~~~pascal
procedure TTaurusTLSSocketTestBase.TestSuccessfulHandshake;
begin
  SetupContexts;
  SetupSockets;
  try
    // Connect SSL handles directly to the memory BIOs instead of physical sockets
    // SSL_set_bio increments BIO ref counts internally
    SSL_set_bio(FClientSocket.SSL, FClientReadBio.Handle, FClientWriteBio.Handle);
    SSL_set_bio(FServerSocket.SSL, FServerReadBio.Handle, FServerWriteBio.Handle);

    RunHandshake;

    // Assertions
    Assert(FClientSocket.State = seEstablished, 'Client failed to establish connection.');
    Assert(FServerSocket.State = seEstablished, 'Server failed to establish connection.');
  finally
    TeardownSockets;
    TeardownContexts;
  end;
end;
~~~

### 3.2. Test ECH Key Mismatch (`TestECHKeyMismatch`)
Forces an ECH key mismatch. Asserts that the client catches the fallback, aborts the handshake, and safely extracts the server's new ECH config.

~~~pascal
procedure TTaurusTLSSocketTestBase.TestECHKeyMismatch;
var
  LECHExceptionRaised: Boolean;
begin
  SetupContexts;
  
  // Configure Client with an invalid ECH Config
  FClientConfig.ECHEnabled := True;
  FClientConfig.ECHConfigList := 'AEX+DQBBNQAgACCuyOX_INVALID_KEY_ecomAAA='; 

  SetupSockets;
  try
    SSL_set_bio(FClientSocket.SSL, FClientReadBio.Handle, FClientWriteBio.Handle);
    SSL_set_bio(FServerSocket.SSL, FServerReadBio.Handle, FServerWriteBio.Handle);

    LECHExceptionRaised := False;
    try
      RunHandshake;
    except
      on E: ETaurusTLSECHRetryRequired do
      begin
        LECHExceptionRaised := True;
        // Verify that the server's correct ECH config list was successfully recovered
        Assert(E.RetryConfigList <> '', 'ECH RetryConfigList was empty.');
        Assert(Pos('cloud', E.RetryConfigList) > 0, 'ECH Config list was invalid.');
      end;
    end;

    Assert(LECHExceptionRaised, 'ETaurusTLSECHRetryRequired exception was not raised.');
    Assert(FClientSocket.State = seClosed, 'Client failed to transition to seClosed on ECH error.');
  finally
    TeardownSockets;
    TeardownContexts;
  end;
end;
~~~

### 3.3. Test mTLS Certificate Failure (`TestMTLSFailure`)
Forces a client certificate validation failure. Asserts that the server rejects the connection and aborts to `seError`.

~~~pascal
procedure TTaurusTLSSocketTestBase.TestMTLSFailure;
var
  LHandshakeFailed: Boolean;
begin
  SetupContexts;
  
  // Require client certificate on the server context
  SSL_CTX_set_verify(FServerCtx, SSL_VERIFY_PEER or SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nil);

  // Client socket config is NOT provided with a client certificate
  SetupSockets;
  try
    SSL_set_bio(FClientSocket.SSL, FClientReadBio.Handle, FClientWriteBio.Handle);
    SSL_set_bio(FServerSocket.SSL, FServerReadBio.Handle, FServerWriteBio.Handle);

    LHandshakeFailed := False;
    try
      RunHandshake;
    except
      on E: Exception do
      begin
        LHandshakeFailed := True;
      end;
    end;

    Assert(LHandshakeFailed, 'Handshake succeeded despite missing client certificate.');
    Assert(FServerSocket.State = seError, 'Server failed to transition to seError.');
  finally
    TeardownSockets;
    TeardownContexts;
  end;
end;
~~~

### 3.4. Test TCP RST Shield (`TestTCPRSTShield`)
Simulates a sudden peer TCP Reset during active connection data exchange. Asserts that the client transitions directly to `seClosed` and frees resources without trying to send `SSL_shutdown` over the dead socket.

~~~pascal
procedure TTaurusTLSSocketTestBase.TestTCPRSTShield;
var
  LTempBuf: TIdBytes;
  LWriteErrorRaised: Boolean;
begin
  // Establish connection first
  TestSuccessfulHandshake; 

  SetupSockets; // Re-instantiate sockets for independent testing
  try
    // Simulate raw socket disconnect by freeing the server's side entirely
    FreeAndNil(FServerSocket); 
    FreeAndNil(FServerReadBio);
    FreeAndNil(FServerWriteBio);

    // Attempt to write data from the client
    SetLength(LTempBuf, 10);
    LWriteErrorRaised := False;
    try
      FClientSocket.Send(LTempBuf, 0, 10);
    except
      on E: ETaurusTLSConnectionReset do
      begin
        LWriteErrorRaised := True;
      end;
    end;

    // Assertions
    Assert(LWriteErrorRaised, 'ETaurusTLSConnectionReset exception was not raised on socket reset.');
    Assert(FClientSocket.State = seClosed, 'Client failed to transition directly to seClosed.');
    Assert(FClientSocket.SSL = nil, 'Client failed to release FSSL immediately.');
  finally
    TeardownSockets;
    TeardownContexts;
  end;
end;
~~~

---

## 4. Test Execution State Transition Matrix

The following state matrix maps the exact expected state paths under each test scenario:

| **Test Case** | **Initial State** | **Transition Path** | **Terminal State** | **Expected Outcome** |
| :--- | :--- | :--- | :--- | :--- |
| **`TestSuccessfulHandshake`** | `seIdle` | `seInitialized` $\rightarrow$ `seHandshaking` $\rightarrow$ `seEstablished` | `seEstablished` | Handshake completes; data exchange ready. |
| **`TestECHKeyMismatch`** | `seIdle` | `seInitialized` $\rightarrow$ `seHandshaking` $\rightarrow$ `seClosed` | `seClosed` | `ETaurusTLSECHRetryRequired` raised; key extracted. |
| **`TestMTLSFailure`** | `seIdle` | `seInitialized` $\rightarrow$ `seHandshaking` $\rightarrow$ `seError` | `seError` | `ETaurusTLSHandshakeError` raised; resources freed. |
| **`TestTCPRSTShield`** | `seEstablished` | `seClosing` (Bypassed) $\rightarrow$ `seClosed` | `seClosed` | `ETaurusTLSConnectionReset` raised; immediate `SSL_free`. |
