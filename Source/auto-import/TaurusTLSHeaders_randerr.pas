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

unit TaurusTLSHeaders_randerr;

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
  RAND_R_ADDITIONAL_INPUT_TOO_LONG = 102;
  RAND_R_ALREADY_INSTANTIATED = 103;
  RAND_R_ARGUMENT_OUT_OF_RANGE = 105;
  RAND_R_CANNOT_OPEN_FILE = 121;
  RAND_R_DRBG_ALREADY_INITIALIZED = 129;
  RAND_R_DRBG_NOT_INITIALISED = 104;
  RAND_R_ENTROPY_INPUT_TOO_LONG = 106;
  RAND_R_ENTROPY_OUT_OF_RANGE = 124;
  RAND_R_ERROR_ENTROPY_POOL_WAS_IGNORED = 127;
  RAND_R_ERROR_INITIALISING_DRBG = 107;
  RAND_R_ERROR_INSTANTIATING_DRBG = 108;
  RAND_R_ERROR_RETRIEVING_ADDITIONAL_INPUT = 109;
  RAND_R_ERROR_RETRIEVING_ENTROPY = 110;
  RAND_R_ERROR_RETRIEVING_NONCE = 111;
  RAND_R_FAILED_TO_CREATE_LOCK = 126;
  RAND_R_FUNC_NOT_IMPLEMENTED = 101;
  RAND_R_FWRITE_ERROR = 123;
  RAND_R_GENERATE_ERROR = 112;
  RAND_R_INSUFFICIENT_DRBG_STRENGTH = 139;
  RAND_R_INTERNAL_ERROR = 113;
  RAND_R_INVALID_PROPERTY_QUERY = 137;
  RAND_R_IN_ERROR_STATE = 114;
  RAND_R_NOT_A_REGULAR_FILE = 122;
  RAND_R_NOT_INSTANTIATED = 115;
  RAND_R_NO_DRBG_IMPLEMENTATION_SELECTED = 128;
  RAND_R_PARENT_LOCKING_NOT_ENABLED = 130;
  RAND_R_PARENT_STRENGTH_TOO_WEAK = 131;
  RAND_R_PERSONALISATION_STRING_TOO_LONG = 116;
  RAND_R_PREDICTION_RESISTANCE_NOT_SUPPORTED = 133;
  RAND_R_PRNG_NOT_SEEDED = 100;
  RAND_R_RANDOM_POOL_IS_EMPTY = 142;
  RAND_R_RANDOM_POOL_OVERFLOW = 125;
  RAND_R_RANDOM_POOL_UNDERFLOW = 134;
  RAND_R_REQUEST_TOO_LARGE_FOR_DRBG = 117;
  RAND_R_RESEED_ERROR = 118;
  RAND_R_SELFTEST_FAILURE = 119;
  RAND_R_TOO_LITTLE_NONCE_REQUESTED = 135;
  RAND_R_TOO_MUCH_NONCE_REQUESTED = 136;
  RAND_R_UNABLE_TO_CREATE_DRBG = 143;
  RAND_R_UNABLE_TO_FETCH_DRBG = 144;
  RAND_R_UNABLE_TO_GET_PARENT_RESEED_PROP_COUNTER = 141;
  RAND_R_UNABLE_TO_GET_PARENT_STRENGTH = 138;
  RAND_R_UNABLE_TO_LOCK_PARENT = 140;
  RAND_R_UNSUPPORTED_DRBG_FLAGS = 132;
  RAND_R_UNSUPPORTED_DRBG_TYPE = 120;

implementation

end.