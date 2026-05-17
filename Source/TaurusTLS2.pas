{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/TaurusTLS-Developers/TaurusTLS                * }
{ *                                                                            * }
{ *  Copyright (c) 2024 TaurusTLS Developers, All Rights Reserved              * }
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
