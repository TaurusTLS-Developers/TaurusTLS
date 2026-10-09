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
///   This unit automatically loads or links to the Loads or links the OpenSSL 3
///   <c>legacy</c> provider. To use, just incclude it in one of your program's
///   units Using this unit requires that you deploy the <c>providers</c>
///   directory along with your program if dynamically loading OpenSSL..
/// </summary>
/// <remarks>
///   The legacy provider is needed only if you arfe interoperating with legacy
///   systems that use the algorithms in the legacy provider such as the NTLM
///   Protocol. using the <see cref="TaurusTLS_NTLM" /> support unit.
/// </remarks>
/// <seealso href="https://docs.openssl.org/3.0/man7/OSSL_PROVIDER-legacy/">
///   OpenSSL Legacy Provider
/// </seealso>
unit TaurusTLS_LegacyProviders;

{$I TaurusTLSLinkDefines.inc}

interface

/// <summary>
/// True if the OpenSSL 3 legacy provider was loaded.
/// </summary>
function IsLegacyProviderLoaded: Boolean;

implementation

uses
  IdGlobal,
  IdCTypes,
  TaurusTLSConsts,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSHeaders_core,
  {$ENDIF}
  TaurusTLSHeaders_provider,
  TaurusTLSLoader;

var
  FDefaultProvider: POSSL_PROVIDER = nil;
  FLegacyProvider: POSSL_PROVIDER = nil;

const
  CDefaultProviderName: PIdAnsiChar = 'default';
  CLegacyProviderName: PIdAnsiChar  = 'legacy';

function IsLegacyProviderLoaded: Boolean;
begin
  Result := Assigned(FLegacyProvider);
end;

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function ossl_legacy_provider_init(const handle: POSSL_CORE_HANDLE;
  const in_struct: POSSL_DISPATCH; out out_struct: POSSL_DISPATCH;
  prov_ctx: pointer): TIdC_INT; cdecl; external CLibLegacyProvider;
{$ENDIF}

type

  /// <summary>
  ///   Manager class providing lifecycle callbacks for OpenSSL 3.x+
  ///   legacy and default providers.
  /// </summary>
  TTaurusTLSLegacyProviderManager = class
  public
    class procedure OnLoadAction(AAction: TOpenSSLLoadAction);
    class procedure InitLegacyProvider;
    class procedure UninitLegacyProvider;
  end;

class procedure TTaurusTLSLegacyProviderManager.InitLegacyProvider;
begin
  // 1. In static mode, register the built-in static entry point first
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  OSSL_PROVIDER_add_builtin(nil, CLegacyProviderName, @ossl_legacy_provider_init);
  {$ENDIF}

  // 2. Explicitly retain the default provider so modern algorithms remain available
  if not Assigned(FDefaultProvider) then
    FDefaultProvider := OSSL_PROVIDER_load(nil, CDefaultProviderName);

  // 3. Load the legacy provider
  if not Assigned(FLegacyProvider) then
    FLegacyProvider := OSSL_PROVIDER_load(nil, CLegacyProviderName);
end;

class procedure TTaurusTLSLegacyProviderManager.UninitLegacyProvider;
begin
  if Assigned(FLegacyProvider)then
  begin
    OSSL_PROVIDER_unload(FLegacyProvider);
    FLegacyProvider := nil;
  end;

  if Assigned(FDefaultProvider) then
  begin
    OSSL_PROVIDER_unload(FDefaultProvider);
    FDefaultProvider := nil;
  end
end;

class procedure TTaurusTLSLegacyProviderManager.OnLoadAction(AAction: TOpenSSLLoadAction);
begin
  case AAction of
    osaLoad:   InitLegacyProvider;
    osaUnload: UninitLegacyProvider;
  end;
end;


initialization
{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TTaurusTLSLegacyProviderManager.InitLegacyProvider;
{$ELSE}
  Register_SSLLoaderAction(TTaurusTLSLegacyProviderManager.OnLoadAction);
{$ENDIF}

finalization
  TTaurusTLSLegacyProviderManager.UninitLegacyProvider;
end.
