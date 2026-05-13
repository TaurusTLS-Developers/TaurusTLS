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

unit TaurusTLS2;

interface

uses
{$IFDEF WINDOWS}
  {$IFDEF VCL_XE2_OR_ABOVE}
  WinAPI.Windows,
  {$ELSE}
  Windows,
  {$ENDIF}
{$ENDIF}
  Classes,
  IdCTypes,
  IdGlobal,
  IdStackConsts,
  IdSocketHandle,
  IdComponent,
  IdIOHandler,
  IdGlobalProtocols,
  IdThread,
  IdIOHandlerSocket,
  IdSSL,
  IdYarn,
  SysUtils,
  TaurusTLSExceptionHandlers,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_ssl,
  TaurusTLSHeaders_ssl3,
  TaurusTLSHeaders_tls1,
  TaurusTLS_Utils,
  TaurusTLS_X509,
  TaurusTLSFIPS {Ensure FIPS functions initialised};

implementation

end.
