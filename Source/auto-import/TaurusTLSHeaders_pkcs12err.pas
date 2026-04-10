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

unit TaurusTLSHeaders_pkcs12err;

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
  PKCS12_R_CALLBACK_FAILED = 115;
  PKCS12_R_CANT_PACK_STRUCTURE = 100;
  PKCS12_R_CONTENT_TYPE_NOT_DATA = 121;
  PKCS12_R_DECODE_ERROR = 101;
  PKCS12_R_ENCODE_ERROR = 102;
  PKCS12_R_ENCRYPT_ERROR = 103;
  PKCS12_R_ERROR_SETTING_ENCRYPTED_DATA_TYPE = 120;
  PKCS12_R_INVALID_NULL_ARGUMENT = 104;
  PKCS12_R_INVALID_NULL_PKCS12_POINTER = 105;
  PKCS12_R_INVALID_TYPE = 112;
  PKCS12_R_IV_GEN_ERROR = 106;
  PKCS12_R_KEY_GEN_ERROR = 107;
  PKCS12_R_MAC_ABSENT = 108;
  PKCS12_R_MAC_GENERATION_ERROR = 109;
  PKCS12_R_MAC_SETUP_ERROR = 110;
  PKCS12_R_MAC_STRING_SET_ERROR = 111;
  PKCS12_R_MAC_VERIFY_FAILURE = 113;
  PKCS12_R_PARSE_ERROR = 114;
  PKCS12_R_PKCS12_CIPHERFINAL_ERROR = 116;
  PKCS12_R_UNKNOWN_DIGEST_ALGORITHM = 118;
  PKCS12_R_UNSUPPORTED_PKCS12_MODE = 119;

implementation

end.