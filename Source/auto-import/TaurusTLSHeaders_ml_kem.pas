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

unit TaurusTLSHeaders_ml_kem;

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
  OSSL_ML_KEM_SHARED_SECRET_BYTES = 32;
  OSSL_ML_KEM_512_BITS = 512;
  OSSL_ML_KEM_512_SECURITY_BITS = 128;
  OSSL_ML_KEM_512_CIPHERTEXT_BYTES = 768;
  OSSL_ML_KEM_512_PUBLIC_KEY_BYTES = 800;
  OSSL_ML_KEM_768_BITS = 768;
  OSSL_ML_KEM_768_SECURITY_BITS = 192;
  OSSL_ML_KEM_768_CIPHERTEXT_BYTES = 1088;
  OSSL_ML_KEM_768_PUBLIC_KEY_BYTES = 1184;
  OSSL_ML_KEM_1024_BITS = 1024;
  OSSL_ML_KEM_1024_SECURITY_BITS = 256;
  OSSL_ML_KEM_1024_CIPHERTEXT_BYTES = 1568;
  OSSL_ML_KEM_1024_PUBLIC_KEY_BYTES = 1568;

implementation

end.