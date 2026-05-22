{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2026 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }
/// <summary>
///   This unit contains the TTaurusTLSUnicodeLog component. This component
///   triggers events when data is sent and received. The data is translated
///   into unicode or plain depending on what the String type supports.
/// </summary>
/// <remarks>
///   This component was developed primarily to allow the TaurusFTP console
///   client demo program to display the data that was sent and received through
///   the FTP control connection.
/// </remarks>
unit TaurusTLS_Unicode_Log;

{$I TaurusTLSCompilerDefines.inc}

interface

uses
  Classes,
  IdIntercept, IdGlobal, IdBaseComponent;

const

  /// <summary>
  ///   The default value TTaurusTLSUnicodeLog.Active property.
  /// </summary>
  TAURUSTLS_DEF_ACTIVE = False;
type
  /// <summary>
  ///   This event type is trigged when the IOHandler connects or disconnects.
  /// </summary>
  /// <param name="ASender">
  ///   The component that triggered the event
  /// </param>
  /// <param name="AText">
  ///   The connection status
  /// </param>
  TTaurusTLSUnicodeLogStatusEvent = procedure(ASender: TComponent; const AText: string) of object;

  /// <summary>
  ///   This event type is triggered when the IOHandler sends and receives data.
  /// </summary>
  /// <param name="ASender">
  ///   The component that triggered the event.
  /// </param>
  /// <param name="AData">
  ///   The data in Unicode or ASCII if Unicode is not supported.
  /// </param>
  TTaurusTLSUnicodeLogDataEvent = procedure(ASender: TComponent; const AData: string) of object;
/// <summary>
///   The TTaurusTLSUnicodeLog component triggers events when data is sent and
///   received. The data is translated into unicode or plain depending on what
///   the String type supports. <br />
/// </summary>
  TTaurusTLSUnicodeLog = class(TIdConnectionIntercept)
  protected
    FActive: Boolean;
    FOnStatus : TTaurusTLSUnicodeLogStatusEvent;
    FOnReceived : TTaurusTLSUnicodeLogDataEvent;
    FOnSent :  TTaurusTLSUnicodeLogDataEvent;
    procedure InitComponent; override;
    procedure LogStatus(const AData: string);   {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure LogReceivedData(const AData: string);  {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure LogSentData(const AData: string);  {$IFDEF USE_INLINE}inline; {$ENDIF}
    procedure SetActive(const AValue: Boolean);  {$IFDEF USE_INLINE}inline; {$ENDIF}
  public
    /// <summary>
    /// Called by Indy (Internet Direct) when a connection is established by the TIdIOHandler.
    /// </summary>
    /// <remarks>
    /// You should not call this method directly.
    /// </remarks>
    procedure Connect(AConnection: TComponent); override;
    /// <summary>
    /// Called by Indy (Internet Direct) when an IOHandler disconnects.
    /// </summary>
    /// <remarks>
    /// You should not call this method directly.
    /// </remarks>
    procedure Disconnect; override;
    /// <summary>
    /// Called by Indy (Internet Direct) when an IOHandler receives data.
    /// </summary>
    /// <remarks>
    /// You should not call this method directly.
    /// </remarks>
    procedure Receive(var ABuffer: TIdBytes); override;
    /// <summary>
    /// Called by Indy (Internet Direct) when an IOHandler sends data.
    /// </summary>
    /// <remarks>
    /// You should not call this method directly.
    /// </remarks>
    procedure Send(var ABuffer: TIdBytes); override;
  published
    /// <summary>
    ///   This enables the intercept causing it to log when the connection
    ///   status changes or when data is received or sent.
    /// </summary>
    property Active: Boolean read FActive write SetActive default TAURUSTLS_DEF_ACTIVE;
    /// <summary>
    ///   This event is called when data is received.
    /// </summary>
    property OnReceived : TTaurusTLSUnicodeLogDataEvent read FOnReceived write FOnReceived;
    /// <summary>
    ///   This event is called when data is sent. AData is the data as a Unicode
    ///   string.
    /// </summary>
    property OnSent :  TTaurusTLSUnicodeLogDataEvent read FOnSent write FOnSent;
    /// <summary>
    ///   This event is fired when the IOHandler connects or disconnects.
    /// </summary>
    property OnStatus : TTaurusTLSUnicodeLogStatusEvent read FOnStatus write FOnStatus;
  end;

implementation
uses
  IdResourceStringsCore, SysUtils;


{ TTaurusTLSUnicodeLog }

procedure TTaurusTLSUnicodeLog.Connect(AConnection: TComponent);
begin
  inherited Connect(AConnection);
  if FActive then begin
    LogStatus(RSLogConnected);
  end;
end;

procedure TTaurusTLSUnicodeLog.Disconnect;
begin
  if FActive then begin
    LogStatus(RSLogDisconnected);
  end;
  inherited Disconnect;
end;

procedure TTaurusTLSUnicodeLog.InitComponent;
begin
  inherited;
  FActive := TAURUSTLS_DEF_ACTIVE;
end;

procedure TTaurusTLSUnicodeLog.LogReceivedData(const AData: string);
begin
  if Assigned(OnReceived) then begin
    OnReceived(Self, AData);
  end;
end;

procedure TTaurusTLSUnicodeLog.LogSentData(const AData: string);
begin
  if Assigned(OnSent) then begin
    OnSent(Self, AData);
  end;
end;

procedure TTaurusTLSUnicodeLog.LogStatus(const AData: string);
begin
  if Assigned(OnStatus) then begin
    OnStatus(Self, AData);
  end;
end;

procedure TTaurusTLSUnicodeLog.Receive(var ABuffer: TIdBytes);
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

procedure TTaurusTLSUnicodeLog.Send(var ABuffer: TIdBytes);
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

procedure TTaurusTLSUnicodeLog.SetActive(const AValue: Boolean);
begin
  FActive := AValue;
end;

end.
