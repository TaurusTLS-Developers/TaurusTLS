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

unit TaurusTLSHeaders_dherr;

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
  DH_R_BAD_FFC_PARAMETERS = 127;
  DH_R_BAD_GENERATOR = 101;
  DH_R_BN_DECODE_ERROR = 109;
  DH_R_BN_ERROR = 106;
  DH_R_CHECK_INVALID_J_VALUE = 115;
  DH_R_CHECK_INVALID_Q_VALUE = 116;
  DH_R_CHECK_PUBKEY_INVALID = 122;
  DH_R_CHECK_PUBKEY_TOO_LARGE = 123;
  DH_R_CHECK_PUBKEY_TOO_SMALL = 124;
  DH_R_CHECK_P_NOT_PRIME = 117;
  DH_R_CHECK_P_NOT_SAFE_PRIME = 118;
  DH_R_CHECK_Q_NOT_PRIME = 119;
  DH_R_DECODE_ERROR = 104;
  DH_R_INVALID_PARAMETER_NAME = 110;
  DH_R_INVALID_PARAMETER_NID = 114;
  DH_R_INVALID_PUBKEY = 102;
  DH_R_INVALID_SECRET = 128;
  DH_R_INVALID_SIZE = 129;
  DH_R_KDF_PARAMETER_ERROR = 112;
  DH_R_KEYS_NOT_SET = 108;
  DH_R_MISSING_PUBKEY = 125;
  DH_R_MODULUS_TOO_LARGE = 103;
  DH_R_MODULUS_TOO_SMALL = 126;
  DH_R_NOT_SUITABLE_GENERATOR = 120;
  DH_R_NO_PARAMETERS_SET = 107;
  DH_R_NO_PRIVATE_VALUE = 100;
  DH_R_PARAMETER_ENCODING_ERROR = 105;
  DH_R_PEER_KEY_ERROR = 111;
  DH_R_Q_TOO_LARGE = 130;
  DH_R_SHARED_INFO_ERROR = 113;
  DH_R_UNABLE_TO_CHECK_GENERATOR = 121;

implementation

end.