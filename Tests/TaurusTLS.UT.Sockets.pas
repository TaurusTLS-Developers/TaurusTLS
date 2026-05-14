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
  Classes,
  SysUtils,
  IdCTypes,
  TaurusTLS_Sockets,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_ech,
  TaurusTLSHeaders_ssl,
  TaurusTLSExceptionHandlers,
  TaurusTLS_ECH,
  TaurusTLS.UT.TestClasses;

type
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

    [Test]
    procedure TestECHRetryException;
    [Test]
    procedure TestECHRejectedException;
    [Test]
    procedure TestECHDowngradeException;
    [Test]
    procedure TestHandshakeFailure;
  end;

implementation

{ TTaurusTLSSocketsFixture }

procedure TTaurusTLSSocketsFixture.Setup;
begin
  fCtx := SSL_CTX_new(TLS_client_method);
  fSocket := TTaurusTLSClientSocket.Create(nil);
  fSocket.SSLContext := fCtx;
end;

procedure TTaurusTLSSocketsFixture.Teardown;
begin
  fSocket.Free;
  if fCtx <> nil then
    SSL_CTX_free(fCtx);
end;

procedure TTaurusTLSSocketsFixture.TestECHRetryException;
const
  MOCK_CONFIG = 'AD8BA...'; // Simulated base64
begin
  fSocket.VirtualHandshakeRet := 1; // Success
  fSocket.VirtualECHStatus := SSL_ECH_STATUS_GREASE_ECH;
  fSocket.VirtualECHRetryConfig := MOCK_CONFIG;

  Assert.WillRaise(
    procedure
    begin
      fSocket.Connect(0); // Handle 0 is enough for simulated handshake
    end,
    ETaurusTLSECHRetryRequired
  );
end;

procedure TTaurusTLSSocketsFixture.TestECHRejectedException;
begin
  fSocket.VirtualHandshakeRet := 1;
  fSocket.VirtualECHStatus := SSL_ECH_STATUS_GREASE_ECH;
  fSocket.VirtualECHRetryConfig := ''; // No config

  Assert.WillRaise(
    procedure
    begin
      fSocket.Connect(0);
    end,
    ETaurusTLSECHRejectedError
  );
end;

procedure TTaurusTLSSocketsFixture.TestECHDowngradeException;
begin
  fSocket.VirtualHandshakeRet := 1;
  fSocket.VirtualECHStatus := SSL_ECH_STATUS_NOT_CONFIGURED;

  Assert.WillRaise(
    procedure
    begin
      fSocket.Connect(0);
    end,
    ETaurusTLSECHDowngradeError
  );
end;

procedure TTaurusTLSSocketsFixture.TestHandshakeFailure;
begin
  fSocket.VirtualHandshakeRet := -1; // Fail
  
  Assert.WillRaise(
    procedure
    begin
      fSocket.Connect(0);
    end,
    ETaurusTLSHandshakeError
  );
end;

initialization
  TDUnitX.RegisterTestFixture(TTaurusTLSSocketsFixture);

end.
