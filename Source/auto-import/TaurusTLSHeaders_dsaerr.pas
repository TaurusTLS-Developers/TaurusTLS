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

unit TaurusTLSHeaders_dsaerr;

interface

uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_ossl_types,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_core;




// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  DSA_R_BAD_FFC_PARAMETERS = 114;
  DSA_R_BAD_Q_VALUE = 102;
  DSA_R_BN_DECODE_ERROR = 108;
  DSA_R_BN_ERROR = 109;
  DSA_R_DECODE_ERROR = 104;
  DSA_R_INVALID_DIGEST_TYPE = 106;
  DSA_R_INVALID_PARAMETERS = 112;
  DSA_R_MISSING_PARAMETERS = 101;
  DSA_R_MISSING_PRIVATE_KEY = 111;
  DSA_R_MODULUS_TOO_LARGE = 103;
  DSA_R_NO_PARAMETERS_SET = 107;
  DSA_R_PARAMETER_ENCODING_ERROR = 105;
  DSA_R_P_NOT_PRIME = 115;
  DSA_R_Q_NOT_PRIME = 113;
  DSA_R_SEED_LEN_SMALL = 110;
  DSA_R_TOO_MANY_RETRIES = 116;

implementation

end.