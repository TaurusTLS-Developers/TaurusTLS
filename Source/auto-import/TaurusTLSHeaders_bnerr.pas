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

unit TaurusTLSHeaders_bnerr;

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
  BN_R_ARG2_LT_ARG3 = 100;
  BN_R_BAD_RECIPROCAL = 101;
  BN_R_BIGNUM_TOO_LONG = 114;
  BN_R_BITS_TOO_SMALL = 118;
  BN_R_CALLED_WITH_EVEN_MODULUS = 102;
  BN_R_DIV_BY_ZERO = 103;
  BN_R_ENCODING_ERROR = 104;
  BN_R_EXPAND_ON_STATIC_BIGNUM_DATA = 105;
  BN_R_INPUT_NOT_REDUCED = 110;
  BN_R_INVALID_LENGTH = 106;
  BN_R_INVALID_RANGE = 115;
  BN_R_INVALID_SHIFT = 119;
  BN_R_NOT_A_SQUARE = 111;
  BN_R_NOT_INITIALIZED = 107;
  BN_R_NO_INVERSE = 108;
  BN_R_NO_PRIME_CANDIDATE = 121;
  BN_R_NO_SOLUTION = 116;
  BN_R_NO_SUITABLE_DIGEST = 120;
  BN_R_PRIVATE_KEY_TOO_LARGE = 117;
  BN_R_P_IS_NOT_PRIME = 112;
  BN_R_TOO_MANY_ITERATIONS = 113;
  BN_R_TOO_MANY_TEMPORARY_VARIABLES = 109;

implementation

end.