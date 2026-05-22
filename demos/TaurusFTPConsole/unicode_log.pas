unit unicode_log;

{$I TaurusTLSCompilerDefines.inc}

interface

uses
  Classes,
  IdIntercept, IdGlobal, IdBaseComponent;

type
  TIdUnicodeLogStatusEvent = procedure(ASender: TComponent; const AText: string) of object;
  TIdUnicodeLogDataEvent = procedure(ASender: TComponent; const AData: string) of object;
  TIdUnicodeLog = class(TIdConnectionIntercept)
  protected
    FActive: Boolean;
    FOnStatus : TIdUnicodeLogStatusEvent;
    FOnReceived : TIdUnicodeLogDataEvent;
    FOnSent :  TIdUnicodeLogDataEvent;
    procedure InitComponent; override;
    procedure LogStatus(const AData: string);
    procedure LogReceivedData(const AData: string);
    procedure LogSentData(const AData: string);
    procedure SetActive(const Value: Boolean);
  public
    procedure Connect(AConnection: TComponent); override;
    procedure Disconnect; override;
    procedure Receive(var ABuffer: TIdBytes); override;
    procedure Send(var ABuffer: TIdBytes); override;
  published
    property Active: Boolean read FActive write SetActive default False;
    property OnReceived : TIdUnicodeLogDataEvent read FOnReceived write FOnReceived;
    property OnSent :  TIdUnicodeLogDataEvent read FOnSent write FOnSent;
    property OnStatus : TIdUnicodeLogStatusEvent read FOnStatus write FOnStatus;
  end;

implementation
uses
  IdResourceStringsCore, SysUtils;


{ TIdUnicodeLog }

procedure TIdUnicodeLog.Connect(AConnection: TComponent);
begin
  inherited Connect(AConnection);
  if FActive then begin
    LogStatus(RSLogConnected);
  end;
end;

procedure TIdUnicodeLog.Disconnect;
begin
  if FActive then begin
    LogStatus(RSLogDisconnected);
  end;
  inherited Disconnect;
end;

procedure TIdUnicodeLog.InitComponent;
begin
  inherited;
  FActive := False;
end;

procedure TIdUnicodeLog.LogReceivedData(const AData: string);
begin
  if Assigned(OnReceived) then begin
    OnReceived(Self, AData);
  end;
end;

procedure TIdUnicodeLog.LogSentData(const AData: string);
begin
  if Assigned(OnSent) then begin
    OnSent(Self, AData);
  end;
end;

procedure TIdUnicodeLog.LogStatus(const AData: string);
begin
  if Assigned(OnStatus) then begin
    OnStatus(Self, AData);
  end;
end;

procedure TIdUnicodeLog.Receive(var ABuffer: TIdBytes);
{$IFNDEF USE_INLINE_VAR}
var s : String;
{$ENDIF}
begin
  inherited Receive(ABuffer);
  if FActive then begin
    {$IFDEF USE_INLINE_VAR}
    var s : String;
    {$ENDIF}
    s := BytesToString(ABuffer,IndyTextEncoding_UTF8);
    LogReceivedData(s);
  end;
end;

procedure TIdUnicodeLog.Send(var ABuffer: TIdBytes);
{$IFNDEF USE_INLINE_VAR}
var s : String;
{$ENDIF}
begin
  inherited Send(ABuffer);
  if FActive then begin
    {$IFDEF USE_INLINE_VAR}
    var s : String;
    {$ENDIF}
    s := BytesToString(ABuffer,IndyTextEncoding_UTF8);
    LogSentData(s);
  end;
end;

procedure TIdUnicodeLog.SetActive(const Value: Boolean);
begin
  FActive := Value;
end;

end.
