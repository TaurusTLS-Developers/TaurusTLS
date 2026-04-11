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

unit TaurusTLSHeaders_cryptoerr;

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
  CRYPTO_R_BAD_ALGORITHM_NAME = 117;
  CRYPTO_R_CONFLICTING_NAMES = 118;
  CRYPTO_R_HEX_STRING_TOO_SHORT = 121;
  CRYPTO_R_ILLEGAL_HEX_DIGIT = 102;
  CRYPTO_R_INSUFFICIENT_DATA_SPACE = 106;
  CRYPTO_R_INSUFFICIENT_PARAM_SIZE = 107;
  CRYPTO_R_INSUFFICIENT_SECURE_DATA_SPACE = 108;
  CRYPTO_R_INTEGER_OVERFLOW = 127;
  CRYPTO_R_INVALID_NEGATIVE_VALUE = 122;
  CRYPTO_R_INVALID_NULL_ARGUMENT = 109;
  CRYPTO_R_INVALID_OSSL_PARAM_TYPE = 110;
  CRYPTO_R_NO_PARAMS_TO_MERGE = 131;
  CRYPTO_R_NO_SPACE_FOR_TERMINATING_NULL = 128;
  CRYPTO_R_ODD_NUMBER_OF_DIGITS = 103;
  CRYPTO_R_PARAM_CANNOT_BE_REPRESENTED_EXACTLY = 123;
  CRYPTO_R_PARAM_NOT_INTEGER_TYPE = 124;
  CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE = 129;
  CRYPTO_R_PARAM_UNSIGNED_INTEGER_NEGATIVE_VALUE_UNSUPPORTED = 125;
  CRYPTO_R_PARAM_UNSUPPORTED_FLOATING_POINT_FORMAT = 130;
  CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION = 126;
  CRYPTO_R_PROVIDER_ALREADY_EXISTS = 104;
  CRYPTO_R_PROVIDER_SECTION_ERROR = 105;
  CRYPTO_R_RANDOM_SECTION_ERROR = 119;
  CRYPTO_R_SECURE_MALLOC_FAILURE = 111;
  CRYPTO_R_STRING_TOO_LONG = 112;
  CRYPTO_R_TOO_MANY_BYTES = 113;
  CRYPTO_R_TOO_MANY_NAMES = 132;
  CRYPTO_R_TOO_MANY_RECORDS = 114;
  CRYPTO_R_TOO_SMALL_BUFFER = 116;
  CRYPTO_R_UNKNOWN_NAME_IN_RANDOM_SECTION = 120;
  CRYPTO_R_ZERO_LENGTH_NUMBER = 115;

implementation

end.