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

unit TaurusTLSHeaders_storeerr;

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
  OSSL_STORE_R_AMBIGUOUS_CONTENT_TYPE = 107;
  OSSL_STORE_R_BAD_PASSWORD_READ = 115;
  OSSL_STORE_R_ERROR_VERIFYING_PKCS12_MAC = 113;
  OSSL_STORE_R_FINGERPRINT_SIZE_DOES_NOT_MATCH_DIGEST = 121;
  OSSL_STORE_R_INVALID_SCHEME = 106;
  OSSL_STORE_R_IS_NOT_A = 112;
  OSSL_STORE_R_LOADER_INCOMPLETE = 116;
  OSSL_STORE_R_LOADING_STARTED = 117;
  OSSL_STORE_R_NOT_A_CERTIFICATE = 100;
  OSSL_STORE_R_NOT_A_CRL = 101;
  OSSL_STORE_R_NOT_A_NAME = 103;
  OSSL_STORE_R_NOT_A_PRIVATE_KEY = 102;
  OSSL_STORE_R_NOT_A_PUBLIC_KEY = 122;
  OSSL_STORE_R_NOT_PARAMETERS = 104;
  OSSL_STORE_R_NO_LOADERS_FOUND = 123;
  OSSL_STORE_R_PASSPHRASE_CALLBACK_ERROR = 114;
  OSSL_STORE_R_PATH_MUST_BE_ABSOLUTE = 108;
  OSSL_STORE_R_SEARCH_ONLY_SUPPORTED_FOR_DIRECTORIES = 119;
  OSSL_STORE_R_UI_PROCESS_INTERRUPTED_OR_CANCELLED = 109;
  OSSL_STORE_R_UNREGISTERED_SCHEME = 105;
  OSSL_STORE_R_UNSUPPORTED_CONTENT_TYPE = 110;
  OSSL_STORE_R_UNSUPPORTED_OPERATION = 118;
  OSSL_STORE_R_UNSUPPORTED_SEARCH_TYPE = 120;
  OSSL_STORE_R_URI_AUTHORITY_UNSUPPORTED = 111;

implementation

end.