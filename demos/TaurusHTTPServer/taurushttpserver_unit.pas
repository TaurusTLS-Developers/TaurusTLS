{$i TaurusTLSCompilerDefines.inc}

unit taurusHTTPServer_unit;

interface

uses
  Classes, SysUtils,
  IdHTTPServer,
  TaurusTLS,
  TaurusTLSLoader;

type
  THTTPServer = class(TObject)
    FHTTP: TIdHTTPServer;
    FIO: TTaurusTLSServerIOHandler;
  public
    constructor Create;
    destructor Destroy; override;
  end;

implementation

{$IFNDEF FPC}

uses System.Types;
{$ENDIF}
{ THTTPServer }

constructor THTTPServer.Create;
begin
  inherited Create;
  FHTTP := TIdHTTPServer.Create(nil);
  FIO := TTaurusTLSServerIOHandler.Create(nil);
  FIO.DefaultCert.PublicKey := 'domain.crt';
  FIO.DefaultCert.PrivateKey := 'domain.key';
  FHTTP.IOHandler := FIO;
  FHTTP.DefaultPort := 443;
  FHTTP.Active := True;
end;

destructor THTTPServer.Destroy;
begin
  FHTTP.Active := False;
  FreeAndNil(FIO);
  FreeAndNil(FHTTP);
  inherited;
end;

procedure RunProgram;
var
  LHTTP: THTTPServer;
begin
  if GetOpenSSLLoader.Load then
  try
    LHTTP := THTTPServer.Create;
    try
      WriteLn('TaurusHTTPServer');
      WriteLn('Press enter to terminate.');
      ReadLn;
    finally
      FreeAndNil(LHTTP);
    end;
  except
    on E: Exception do
    begin
      WriteLn(E.Message);
      ReadLn;
    end;
  end;
end;

initialization
  RunProgram;
end.
