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

function IsECHSupported : Boolean;

implementation
uses TaurusTLSHeaders_crypto;

function IsECHSupported : Boolean;
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
