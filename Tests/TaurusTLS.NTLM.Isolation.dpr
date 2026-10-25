program TaurusTLS.NTLM.Isolation;

{$APPTYPE CONSOLE}
{$I ..\Source\TaurusTLSCompilerDefines.inc}
{$I ..\Source\TaurusTLSLinkDefines.inc}
{$DEFINE PROBE_NTLM_ONLY}

uses
  System.SysUtils,
  System.IOUtils,
  IdGlobal,
  IdFIPS,
  TaurusTLSLoader,
  TaurusTLSExceptionHandlers,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_err,
  TaurusTLS_NTLM,
  TaurusTLS.Loader.ConsoleSupport in 'TaurusTLS.Loader.ConsoleSupport.pas';

{$I TaurusTLS.Hooks.Isolation.inc}

