program TaurusTLS.FIPS.Isolation;

{$APPTYPE CONSOLE}
{$I ..\Source\TaurusTLSCompilerDefines.inc}
{$I ..\Source\TaurusTLSLinkDefines.inc}

uses
  System.SysUtils,
  System.IOUtils,
  IdGlobal,
  IdFIPS,
  TaurusTLSLoader,
  TaurusTLSExceptionHandlers,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_err,
  TaurusTLSIdFIPS,
  TaurusTLS.Loader.ConsoleSupport in 'TaurusTLS.Loader.ConsoleSupport.pas';

{$I TaurusTLS.Hooks.Isolation.inc}

