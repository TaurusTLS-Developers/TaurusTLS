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

/// <summary>Validates OpenSSL FIPS APIs and reports configured provider availability.</summary>
/// <remarks>
/// Registers a loader action to refresh native API support after binding and
/// invalidate it on cleanup. Queries never load OpenSSL or activate providers;
/// applications explicitly initialize the loader and select providers through
/// OpenSSL configuration. Static FIPS is unsupported. This unit does not install
/// Indy callbacks; use TaurusTLSIdFIPS for the Indy hash/HMAC adapter.
/// </remarks>
unit TaurusTLS_ProviderFIPS;

{$I TaurusTLSCompilerDefines.inc}
{$I TaurusTLSLinkDefines.inc}

interface

/// <summary>Reports FIPS provider availability without activating it.</summary>
/// <remarks>Configuration owns activation. Static FIPS is unsupported.</remarks>
function IsFIPSProviderLoaded: Boolean;
/// <summary>Reports validated modern FIPS API support while ready.</summary>
function FIPSPropertyAPIsAvailable: Boolean;

{$IFDEF UNITTEST}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
function FIPSPropertyAPIsAvailableForTests: Boolean;
function FIPSUsesPropertyAPIsForTests: Boolean;
procedure RevalidateFIPSPropertyAPIsForTests;
{$ENDIF}
{$ENDIF}

implementation

uses
  TaurusTLSLoader,
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_provider;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  GFIPSUsesPropertyAPIs: Boolean = False;
  GFIPSPropertyAPIsAvailable: Boolean = False;

type
  TTaurusTLSFIPSAPIState = class
  public
    class procedure OnLoadAction(AAction: TOpenSSLLoadAction);
  end;

class procedure TTaurusTLSFIPSAPIState.OnLoadAction(AAction: TOpenSSLLoadAction);
var
  LLoader: IOpenSSLLoader;
begin
  // Invalidate first, including every unload notification.
  GFIPSUsesPropertyAPIs := False;
  GFIPSPropertyAPIsAvailable := False;
  if AAction <> osaLoad then
    Exit;
  LLoader := GetOpenSSLLoader;
  if LLoader = nil then
    Exit;
  if not Assigned(OpenSSL_version_num) then
    Exit;
  GFIPSUsesPropertyAPIs := OpenSSL_version_num() >= $30000000;
  if not GFIPSUsesPropertyAPIs then
    Exit;
  // Headers have finished binding. Inspect failure diagnostics once here:
  // a missing export may have a non-nil exception-stub address.
  GFIPSPropertyAPIsAvailable :=
    Assigned(EVP_default_properties_enable_fips) and
    Assigned(EVP_default_properties_is_fips_enabled) and
    (LLoader.FailedToLoad.IndexOf('EVP_default_properties_enable_fips') < 0) and
    (LLoader.FailedToLoad.IndexOf('EVP_default_properties_is_fips_enabled') < 0) and
    Assigned(OSSL_PROVIDER_available) and
    (LLoader.FailedToLoad.IndexOf('OSSL_PROVIDER_available') < 0);
end;

function FIPSPropertyAPIsAvailable: Boolean;
begin
  // Repeated mode checks never scan the binding diagnostics.
  Result := GFIPSPropertyAPIsAvailable;
end;

{$IFDEF UNITTEST}
function FIPSPropertyAPIsAvailableForTests: Boolean;
begin
  Result := FIPSPropertyAPIsAvailable;
end;

function FIPSUsesPropertyAPIsForTests: Boolean;
begin
  Result := GFIPSUsesPropertyAPIs;
end;

procedure RevalidateFIPSPropertyAPIsForTests;
begin
  TTaurusTLSFIPSAPIState.OnLoadAction(osaLoad);
end;
{$ENDIF}
{$ENDIF}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function FIPSPropertyAPIsAvailable: Boolean;
begin
  Result := False;
end;
{$ENDIF}

function IsFIPSProviderLoaded: Boolean;
begin
  Result := False;
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  if GetOpenSSLLoader.IsLoaded and FIPSPropertyAPIsAvailable then
    Result := OSSL_PROVIDER_available(nil, 'fips') = 1;
{$ENDIF}
end;

initialization
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  Register_SSLLoaderAction(TTaurusTLSFIPSAPIState.OnLoadAction);
{$ENDIF}

finalization
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  UnRegister_SSLLoaderAction(TTaurusTLSFIPSAPIState.OnLoadAction);
{$ENDIF}
end.
