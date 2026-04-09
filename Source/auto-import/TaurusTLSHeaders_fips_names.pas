{$I TaurusTLSCompilerDefines.inc}
{$I TaurusTLSLinkDefines.inc}
{$IFNDEF USE_OPENSSL}
  { error Should not compile if USE_OPENSSL is not defined!!!}
{$ENDIF}
{******************************************************************************}
{*  TaurusTLS                                                                 *}
{*           https://github.com/JPeterMugaas/TaurusTLS                        *}
{*                                                                            *}
{*  Copyright (c) 2024 TaurusTLS Developers, All Rights Reserved              *}
{*                                                                            *}
{* Portions of this software are Copyright (c) 1993 – 2018,                   *}
{* Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  *}
{******************************************************************************}

unit TaurusTLSHeaders_fips_names;

interface

uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_core;


// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  OSSL_PROV_FIPS_PARAM_MODULE_MAC = 'module-mac';
  OSSL_PROV_FIPS_PARAM_INSTALL_VERSION = 'install-version';
  OSSL_PROV_FIPS_PARAM_INSTALL_MAC = 'install-mac';
  OSSL_PROV_FIPS_PARAM_INSTALL_STATUS = 'install-status';
  OSSL_PROV_FIPS_PARAM_CONDITIONAL_ERRORS = 'conditional-errors';
  OSSL_PROV_FIPS_PARAM_SECURITY_CHECKS = OSSL_PROV_PARAM_SECURITY_CHECKS;
  OSSL_PROV_FIPS_PARAM_TLS1_PRF_EMS_CHECK = OSSL_PROV_PARAM_TLS1_PRF_EMS_CHECK;
  OSSL_PROV_FIPS_PARAM_DRBG_TRUNC_DIGEST = OSSL_PROV_PARAM_DRBG_TRUNC_DIGEST;

implementation

end.