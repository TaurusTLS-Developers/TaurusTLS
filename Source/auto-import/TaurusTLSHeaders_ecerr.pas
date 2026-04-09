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

unit TaurusTLSHeaders_ecerr;

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
  EC_R_ASN1_ERROR = 115;
  EC_R_BAD_SIGNATURE = 156;
  EC_R_BIGNUM_OUT_OF_RANGE = 144;
  EC_R_BUFFER_TOO_SMALL = 100;
  EC_R_CANNOT_INVERT = 165;
  EC_R_COORDINATES_OUT_OF_RANGE = 146;
  EC_R_CURVE_DOES_NOT_SUPPORT_ECDH = 160;
  EC_R_CURVE_DOES_NOT_SUPPORT_ECDSA = 170;
  EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING = 159;
  EC_R_DECODE_ERROR = 142;
  EC_R_DISCRIMINANT_IS_ZERO = 118;
  EC_R_EC_GROUP_NEW_BY_NAME_FAILURE = 119;
  EC_R_EXPLICIT_PARAMS_NOT_SUPPORTED = 127;
  EC_R_FAILED_MAKING_PUBLIC_KEY = 166;
  EC_R_FIELD_TOO_LARGE = 143;
  EC_R_GF2M_NOT_SUPPORTED = 147;
  EC_R_GROUP2PKPARAMETERS_FAILURE = 120;
  EC_R_I2D_ECPKPARAMETERS_FAILURE = 121;
  EC_R_INCOMPATIBLE_OBJECTS = 101;
  EC_R_INVALID_A = 168;
  EC_R_INVALID_ARGUMENT = 112;
  EC_R_INVALID_B = 169;
  EC_R_INVALID_COFACTOR = 171;
  EC_R_INVALID_COMPRESSED_POINT = 110;
  EC_R_INVALID_COMPRESSION_BIT = 109;
  EC_R_INVALID_CURVE = 141;
  EC_R_INVALID_DIGEST = 151;
  EC_R_INVALID_DIGEST_TYPE = 138;
  EC_R_INVALID_ENCODING = 102;
  EC_R_INVALID_FIELD = 103;
  EC_R_INVALID_FORM = 104;
  EC_R_INVALID_GENERATOR = 173;
  EC_R_INVALID_GROUP_ORDER = 122;
  EC_R_INVALID_KEY = 116;
  EC_R_INVALID_LENGTH = 117;
  EC_R_INVALID_NAMED_GROUP_CONVERSION = 174;
  EC_R_INVALID_OUTPUT_LENGTH = 161;
  EC_R_INVALID_P = 172;
  EC_R_INVALID_PEER_KEY = 133;
  EC_R_INVALID_PENTANOMIAL_BASIS = 132;
  EC_R_INVALID_PRIVATE_KEY = 123;
  EC_R_INVALID_SEED = 175;
  EC_R_INVALID_TRINOMIAL_BASIS = 137;
  EC_R_KDF_PARAMETER_ERROR = 148;
  EC_R_KEYS_NOT_SET = 140;
  EC_R_LADDER_POST_FAILURE = 136;
  EC_R_LADDER_PRE_FAILURE = 153;
  EC_R_LADDER_STEP_FAILURE = 162;
  EC_R_MISSING_OID = 167;
  EC_R_MISSING_PARAMETERS = 124;
  EC_R_MISSING_PRIVATE_KEY = 125;
  EC_R_NEED_NEW_SETUP_VALUES = 157;
  EC_R_NOT_A_NIST_PRIME = 135;
  EC_R_NOT_IMPLEMENTED = 126;
  EC_R_NOT_INITIALIZED = 111;
  EC_R_NO_PARAMETERS_SET = 139;
  EC_R_NO_PRIVATE_VALUE = 154;
  EC_R_OPERATION_NOT_SUPPORTED = 152;
  EC_R_PASSED_NULL_PARAMETER = 134;
  EC_R_PEER_KEY_ERROR = 149;
  EC_R_POINT_ARITHMETIC_FAILURE = 155;
  EC_R_POINT_AT_INFINITY = 106;
  EC_R_POINT_COORDINATES_BLIND_FAILURE = 163;
  EC_R_POINT_IS_NOT_ON_CURVE = 107;
  EC_R_RANDOM_NUMBER_GENERATION_FAILED = 158;
  EC_R_SHARED_INFO_ERROR = 150;
  EC_R_SLOT_FULL = 108;
  EC_R_TOO_MANY_RETRIES = 176;
  EC_R_UNDEFINED_GENERATOR = 113;
  EC_R_UNDEFINED_ORDER = 128;
  EC_R_UNKNOWN_COFACTOR = 164;
  EC_R_UNKNOWN_GROUP = 129;
  EC_R_UNKNOWN_ORDER = 114;
  EC_R_UNSUPPORTED_FIELD = 131;
  EC_R_WRONG_CURVE_PARAMETERS = 145;
  EC_R_WRONG_ORDER = 130;

implementation

end.