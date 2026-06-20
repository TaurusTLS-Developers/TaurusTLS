{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2026 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }
{$I TaurusTLSCompilerDefines.inc}

/// <summary>
///   Miscelanious ECH (Encrypted Client Hello) functions and classes.
/// </summary>
unit TaurusTLS_ECH;
{$I TaurusTLSLinkDefines.inc}

interface
uses
  Classes,
  SysUtils,
  IdCTypes,
  IdDNSResolver,
  IdGlobal,
  IdHTTP,
  TaurusTLSExceptionHandlers,
  TaurusTLSHeaders_ech,
  TaurusTLSHeaders_hpke,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_ssl;

type
  /// <summary>Base class for all ECH-related runtime errors.</summary>
  ETaurusTLSECHError = class(ETaurusTLSError)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict {$ENDIF}protected
    FECHCode: TIdC_INT;
  public
    constructor Create(AECHCode: TIdC_INT; const AMsg: String);
    constructor CreateFmt(AECHCode: TIdC_INT; const AMsg: String; const AArgs: array of const);
    property ECHCode: TIdC_INT read FECHCode;
  end;

  /// <summary>
  /// Raised when the server rejects the ECH key but provides a new configuration.
  /// (Maps to SSL_ECH_STATUS_GREASE_ECH with a retry config)
  /// </summary>
  ETaurusTLSECHRetryRequired = class(ETaurusTLSECHError)
  {$IFDEF USE_STRICT_PRIVATE_PROTECTED}strict {$ENDIF}protected
    FECHConfigList: String;
  public
    constructor Create(const AMsg, AECHConfig: String);
    class procedure RaiseWithMessage(const AMsg, AECHConfig: String); reintroduce;
    property ECHConfigList: String read FECHConfigList;
  end;

  /// <summary>
  /// Raised when the server rejects the ECH key but provides NO retry configuration.
  /// (Maps to SSL_ECH_STATUS_GREASE_ECH without a retry config)
  /// </summary>
  ETaurusTLSECHRejectedError = class(ETaurusTLSECHError)
    constructor Create(const AMsg: String);
  end;

  /// <summary>
  /// Raised when ECH was requested, but the connection completed without ECH.
  /// This indicates a potential downgrade attack or a server that doesn't support ECH.
  /// (Maps to SSL_ECH_STATUS_NOT_CONFIGURED)
  /// </summary>
  ETaurusTLSECHDowngradeError = class(ETaurusTLSECHError)
    constructor Create(const AMsg: String);
  end;

  ETaurusTLSECHBadNameError = class(ETaurusTLSECHError);
  ETaurusTLSECHProtocolError = class(ETaurusTLSECHError);

type
  TOSSLReadStream = class(TCustomMemoryStream)
  public
    constructor Create(AData: Pointer; ASize: TIdC_SIZET);
  end;

type
  TTaurusTLSDNSResolver  = class(TIdDNSResolver)

  end;
  TTaurusTLSHTTP = class(TIdHTTP)

  end;

/// <summary>
///   This functionr returns true if AStr is a valid Fully-Qualified Domain Name
///   and not an IP address. On Windows, Internationalized Domain Name (IDN) is
///   supported.
/// </summary>
/// <param name="AStr">
///   A hostname to validate
/// </param>
function IsValidFQN(const AStr : String) : Boolean;  {$IFDEF USE_INLINE}inline; {$ENDIF}

/// <summary>
///   This indicates if Encrypted Client Hello (ECH) functions are available.
/// </summary>
/// <returns>
///   true if Encrypted Client Hello (ECH) functions are available.
/// </returns>
/// <remarks>
///   Encrypted Client Hello (ECH) functions are available only for OpenSSL
///   version 4.0.0 or greater.
/// </remarks>
function IsECHSupported : Boolean;  {$IFDEF USE_INLINE}inline; {$ENDIF}

function EncodeConfigList(AConfigList: Pointer; ASize: TIdC_SIZET): string;

implementation
uses IdCoderMIME, IdIDN, TaurusTLSHeaders_crypto;


{
Ok, I'm rephrasing my question. I need to check if the string is a HostName or FQDN, but not an IP address.
It should meet a criteria:

consists of one or more segments divided with . (dot)
each segment should starts with an ASCII letter or _ symbol
each segment should consists of ASCII letters, Numbers, - symbol, or _ symbol (except the first character, see above)
each segment should not exceed 63 symbol length
whole length should not exceed 254 symbols (or 63 symbols for a single segment hostname)
}


function IsValidFQN(const AStr : String) : Boolean;  {$IFDEF USE_INLINE}inline; {$ENDIF}
const
  FQN_SEG_STARTS_WITH = 'abcdefghijklmnopqrstuvwxyz_';
  FQN_SEG_CONSISTSOF = 'abcdefghijklmnopqrstuvwxyz0123456789-_';
  FQN_MAX_SEG_LEN = 63;
  FQN_MAX_WHOLE_LEN = 254;
var
{$IFNDEF USE_INLINE_VAR}
  LStr : String;
{$ENDIF}
  LCurSeg : String;
  LLenCurSeg, i : Integer;
begin
  Result := False;
  if (AStr <> '') and (Length(AStr) <= FQN_MAX_WHOLE_LEN) then
  begin
  {$IFDEF USE_INLINE_VAR}
    var LStr : String;
  {$ENDIF}
    LStr := AStr;
    repeat
      Result := True;
      {$IFNDEF WINDOWS}
      LCurSeg := Fetch(LStr,'.');
      {$ELSE}
       if Assigned(IdnToAscii) then
       begin
         LCurSeg := IDNToPunnyCode(
           {$IFDEF STRING_IS_UNICODE}
           Fetch(LStr,'.')
           {$ELSE}
           TIdUnicodeString(Fetch(LStr,'.')) // explicit convert to Unicode
           {$ENDIF});
       end
       else
       begin
         LCurSeg := Fetch(LStr,'.');
       end;
      {$ENDIF}

      if LCurSeg <> '' then
      begin
        LLenCurSeg := Length(LCurSeg);
        if (LLenCurSeg <= FQN_MAX_SEG_LEN) and (Pos(LCurSeg[1],FQN_SEG_STARTS_WITH) = 0) then
        begin
          Result := False;
        end
        else
        begin
          if LLenCurSeg > 1 then
          begin
            for i := 2 to LLenCurSeg do
            begin
              if Pos(LCurSeg[i],FQN_SEG_CONSISTSOF) = 0  then
              begin
                Result := False;
                break;
              end;

            end;
          end;
        end;
      end;
    until (not Result) or (LStr = '');
  end;
end;

function IsECHSupported : Boolean;  {$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Result := False;
  if Assigned(SSLeay) then
  begin
  {$ENDIF}
     if SSLeay shr 28 > 3 then
     begin
       Result := True;
     end;
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  end;
  {$ENDIF}
end;

  function EncodeConfigList(AConfigList: Pointer; ASize: TIdC_SIZET): string;  {$IFDEF USE_INLINE}inline; {$ENDIF}
  var
    lIn: TOSSLReadStream;
    lOut: TStringStream;
    lEncoder: TIdEncoderMIME;
  begin
    lEncoder := TIdEncoderMIME.Create(nil);
    try
      lIn := TOSSLReadStream.Create(AConfigList, ASize);
      try
        lOut := TStringStream.Create('');
        try
          lEncoder.Encode(lIn, lOut);
          Result := lOut.DataString;
        finally
          lOut.Free;
        end;
      finally
        lIn.Free;
      end;
    finally
      lEncoder.Free;
    end;
  end;


{ TOSSLReadStream }

constructor TOSSLReadStream.Create(AData: Pointer; ASize: TIdC_SIZET);
begin
  inherited Create;
  SetPointer(AData, ASize);
end;

{ ETaurusTLSECHError }

constructor ETaurusTLSECHError.Create(AECHCode: TIdC_INT; const AMsg: String);
begin
  inherited Create(AMsg);
  FECHCode := AECHCode;
end;

constructor ETaurusTLSECHError.CreateFmt(AECHCode: TIdC_INT; const AMsg: String;
  const AArgs: array of const);
begin
  Create(AECHCode, Format(AMsg, AArgs));
end;

{ ETaurusTLSECHRetryRequired }

constructor ETaurusTLSECHRetryRequired.Create(const AMsg, AECHConfig: String);
begin
  inherited Create(SSL_ECH_STATUS_GREASE_ECH, AMsg);
  FECHConfigList := AECHConfig;
end;

class procedure ETaurusTLSECHRetryRequired.RaiseWithMessage(const AMsg,
  AECHConfig: String);
begin
  raise ETaurusTLSECHRetryRequired.Create(AMsg, AECHConfig);
end;

{ ETaurusTLSECHRejectedError }

constructor ETaurusTLSECHRejectedError.Create(const AMsg: String);
begin
  inherited Create(SSL_ECH_STATUS_GREASE_ECH, AMsg);
end;

{ ETaurusTLSECHDowngradeError }

constructor ETaurusTLSECHDowngradeError.Create(const AMsg: String);
begin
  inherited Create(SSL_ECH_STATUS_NOT_CONFIGURED, AMsg);
end;

end.
