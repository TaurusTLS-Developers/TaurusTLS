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

unit TaurusTLS2;

interface

uses
{$IFDEF WINDOWS}
  WinAPI.Windows,
{$ENDIF}
  Classes,
  IdCTypes,
  IdGlobal,
  IdIOHandler,
  IdSocketHandle,
  IdThread,
  IdSSL,
  IdYarn,
  SysUtils,
  TaurusTLSHeaders_types,
  TaurusTLSExceptionHandlers,
  TaurusTLS_X509,
  TaurusTLSFIPS {Ensure FIPS functions initialised},
  TaurusTLS,
  TaurusTLS_Sockets;

implementation


end.
