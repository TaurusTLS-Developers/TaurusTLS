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

unit TaurusTLS_ECH;

interface
uses
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
function IsValidFQN(const AStr : String) : Boolean; inline;

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
function IsECHSupported : Boolean; inline;

implementation
uses IdIDN, TaurusTLSHeaders_crypto;


{
Ok, I'm rephrasing my question. I need to check if the string is a HostName or FQDN, but not an IP address.
It should meet a criteria:

consists of one or more segments divided with . (dot)
each segment should starts with an ASCII letter or _ symbol
each segment should consists of ASCII letters, Numbers, - symbol, or _ symbol (except the first character, see above)
each segment should not exceed 63 symbol length
whole length should not exceed 254 symbols (or 63 symbols for a single segment hostname)
}


function IsValidFQN(const AStr : String) : Boolean; inline;
const
  FQN_SEG_STARTS_WITH = 'abcdefghijklmnopqrstuvwxyz_';
  FQN_SEG_CONSISTSOF = 'abcdefghijklmnopqrstuvwxyz0123456789-_';
  FQN_MAX_SEG_LEN = 63;
  FQN_MAX_WHOLE_LEN = 254;
var LStr : String;
  LCurSeg : String;
  LLenCurSeg, i : Integer;
begin
  Result := False;
  if (AStr <> '') and (Length(AStr) <= FQN_MAX_WHOLE_LEN) then
  begin
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
           TIdUnicodeString(Fetch(LStr,'.') // explicit convert to Unicode
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

function IsECHSupported : Boolean; inline;
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

end.
