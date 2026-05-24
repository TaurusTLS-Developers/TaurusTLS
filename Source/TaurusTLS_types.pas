{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2024 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }

{$I TaurusTLSCompilerDefines.inc}

/// <summary>
///   Defines and implements common classes and interfaces used in the TaurusTLS
///   library.
/// </summary>
unit TaurusTLS_types;

interface

uses
  IdGlobal,
  IdCTypes,
  IdSSLOpenSSL,
  TaurusTLSHeaders_ssl3,
  TaurusTLSHeaders_tls1,
  TaurusTLSExceptionHandlers;

type
  TTaurusTLSVerifyMode = (
    /// <summary>
    /// For servers, send certificate. For clients, verify server certificate.
    /// </summary>
    sslvrfPeer,
    /// <summary>
    /// For servers, require client certificate
    /// </summary>
    sslvrfFailIfNoPeerCert,
    /// <summary>
    /// For servers, request client certificate only at initial handshake. Do
    /// not ask for certificate during renegotiation.
    /// </summary>
    sslvrfClientOnce,
    /// <summary>
    /// For servers, server will not send client certificate request during
    /// initial handshake. Send the request during the
    /// SSL_verify_client_post_handshake call.
    /// </summary>
    sslvrfPostHandshake
  );
  /// <summary>
  /// Controls the peer verification. Can contain the following:<para>
  /// <c>sslvrfPeer</c> For servers, send certificate. For clients, verify
  /// server certificate.
  /// </para>
  /// <para>
  /// <c>sslvrfFailIfNoPeerCert</c> For servers, require client certificate
  /// </para>
  /// <para>
  /// <c>sslvrfClientOnce</c> For servers, request client certificate only
  /// at initial handshake. Do not ask for certificate during renegotiation.
  /// </para>
  /// <para>
  /// <c>sslvrfPostHandshake</c> For servers, server will not send client
  /// certificate request during initial handshake. Send the request during
  /// the SSL_verify_client_post_handshake call.
  /// </para>
  /// </summary>
  TTaurusTLSVerifyModes = set of TTaurusTLSVerifyMode;

  ETaurusTLSSecurityBits = class(ETaurusTLSError);

  TTaurusTLSSecurityBits = (sbZero, sb80, sb112, sb128, sb192, sb256);
  TTaurusTLSSecurityBitsHelper = record helper for TTaurusTLSSecurityBits
  private
    function GetAsInt: TIdC_INT; {$IFDEF USE_INLINE} inline;{$ENDIF}
    procedure SetAsInt(AValue: TIdC_INT); {$IFDEF USE_INLINE} inline;{$ENDIF}
  public
    property AsInt: TIdC_INT read GetAsInt write SetAsInt;
  end;

  TTaurusTLSSSLVersion = (
    /// <summary>SSL 2.0</summary>
    SSLv2,
    /// <summary>SSL 2.0 or 3.0</summary>
    SSLv23,
    /// <summary>SSL 3.0</summary>
    SSLv3,
    /// <summary>TLS 1.0</summary>
    TLSv1,
    /// <summary>TLS 1.1</summary>
    TLSv1_1,
    /// <summary>TLS 1.2</summary>
    TLSv1_2,
    /// <summary>TLS 1.3</summary>
    TLSv1_3);

  TTaurusTLSSSLVersionHelper = record helper for TTaurusTLSSSLVersion
  public const
    cMapping: array[TTaurusTLSSSLVersion] of TIdC_LONG = (
      0, 0, SSL3_VERSION, TLS1_VERSION, TLS1_1_VERSION, TLS1_2_VERSION,
      TLS1_3_VERSION
    );

  private
    function GetAsInt: TIdC_LONG; {$IFDEF USE_INLINE} inline;{$ENDIF}
    procedure SetAsInt(AValue: TIdC_LONG); {$IFDEF USE_INLINE} inline;{$ENDIF}
  public
  end;

  ETaurusTLSSSLVersion = class(ETaurusTLSError);

  TTaurusTLSDebugLogFlag = (
    dfSocket,
    dfIOHandler,
    dfOpenSSLDebug,
    dfError,
    dfAccept,
    dfConnect,
    dfSend,
    dfRecv,
    dfClosing,
    dfClosed
  );
  TTaurusTLSDebugLogFlags = set of TTaurusTLSDebugLogFlag;

  /// <summary>
  ///   Read status of TLS Connection.
  /// </summary>
  TTaurusTLSReadStatus = (
    /// <summary>
    ///   if application data pending, or if it looks like we have disconnected
    /// </summary>
   sslDataAvailable,
    /// <summary>
   ///   try again later
   /// </summary>
   sslNoData,
   /// <summary>
   ///   if the connection has been shutdown
   /// </summary>
   sslEOF,
   /// <summary>
   ///   error state indicated
   /// </summary>
   sslUnrecoverableError);

implementation

uses
  TaurusTLS_ResourceStrings;


{ TTaurusTLSSecurityBitsHelper }

function TTaurusTLSSecurityBitsHelper.GetAsInt: TIdC_INT;
begin
  Result:=Ord(Self);
end;

procedure TTaurusTLSSecurityBitsHelper.SetAsInt(AValue: TIdC_INT);
begin
  if not (AValue in [0..5]) then
    raise ETaurusTLSSecurityBits.CreateFmt(RMSG_SecurityBits_Convert_err, [AValue]);
  Self:=TTaurusTLSSecurityBits(AValue);
end;


{ TTaurusTLSSSLVersionHelper }

function TTaurusTLSSSLVersionHelper.GetAsInt: TIdC_LONG;
begin
  Result:=cMapping[Self];
end;

procedure TTaurusTLSSSLVersionHelper.SetAsInt(AValue: TIdC_LONG);
var
  i: TTaurusTLSSSLVersion;

begin
  for i:=Low(TTaurusTLSSSLVersion) to High(TTaurusTLSSSLVersion) do
    if AValue = cMapping[i] then
    begin
      Self:=i;
      Exit;
    end;
  ETaurusTLSSSLVersion.RaiseWithMessageFmt('Fail to set TaurusTLSSSLVersion version '+
    'as integer value: %d.', [AValue]);
end;

end.
