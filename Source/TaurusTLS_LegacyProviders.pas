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
/// <summary>Links and registers the optional archive legacy provider.</summary>
/// <remarks>
/// Archive applications include this unit before loading OpenSSL. Configuration
/// controls provider activation. Shared-library applications need only the
/// deployed provider module and openssl.cnf; this unit does not load providers.
/// </remarks>
unit TaurusTLS_LegacyProviders;

{$I TaurusTLSLinkDefines.inc}

interface

/// <summary>Reports configured legacy availability while the loader is ready.</summary>
/// <remarks>Does not load OpenSSL or acquire a provider reference.</remarks>
function IsLegacyProviderLoaded: Boolean;

implementation

uses
{$IFDEF STATICLOAD_OPENSSL}
  IdCTypes,
  TaurusTLSConsts,
  TaurusTLSHeaders_core,
  TaurusTLSExceptionHandlers,
  TaurusTLS_ResourceStrings,
{$ENDIF}
  TaurusTLSHeaders_provider,
  TaurusTLSLoader;

function IsLegacyProviderLoaded: Boolean;
begin
  Result := GetOpenSSLLoader.IsLoaded;
  if Result then
    Result := OSSL_PROVIDER_available(nil, 'legacy') = 1;
end;

{$IFDEF STATICLOAD_OPENSSL}
// Keep the archive reference out of the core loader and shared-library builds.
function ossl_legacy_provider_init(const handle: POSSL_CORE_HANDLE;
  const in_struct: POSSL_DISPATCH; var out_struct: POSSL_DISPATCH;
  var prov_ctx: Pointer): TIdC_INT; cdecl; external CLibLegacyProvider;

initialization
  // Register the linked entry point in the default context before config loading.
  // This does not load config, call the entry point or activate the provider.
  // Archive builds still require legacy's "activate = 1" in openssl.cnf; when
  // that config is applied, OpenSSL uses this function instead of an external
  // provider module, so no "module" path is needed. Without config activation,
  // linking this unit alone leaves the legacy provider inactive.
  // Registration is once per unit lifetime and survives static Load/Unload.
  if OSSL_PROVIDER_add_builtin(nil, 'legacy', @ossl_legacy_provider_init) <> 1 then
    ETaurusTLSAPICryptoError.RaiseException(RSLegacyProviderRegisterFailed);
{$ENDIF}
end.
