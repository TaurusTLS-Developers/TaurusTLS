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

unit TaurusTLSHeaders_pkcs7err;

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
  PKCS7_R_CERTIFICATE_VERIFY_ERROR = 117;
  PKCS7_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER = 144;
  PKCS7_R_CIPHER_NOT_INITIALIZED = 116;
  PKCS7_R_CONTENT_AND_DATA_PRESENT = 118;
  PKCS7_R_CTRL_ERROR = 152;
  PKCS7_R_DECRYPT_ERROR = 119;
  PKCS7_R_DIGEST_FAILURE = 101;
  PKCS7_R_ENCRYPTION_CTRL_FAILURE = 149;
  PKCS7_R_ENCRYPTION_NOT_SUPPORTED_FOR_THIS_KEY_TYPE = 150;
  PKCS7_R_ERROR_ADDING_RECIPIENT = 120;
  PKCS7_R_ERROR_SETTING_CIPHER = 121;
  PKCS7_R_INVALID_NULL_POINTER = 143;
  PKCS7_R_INVALID_SIGNED_DATA_TYPE = 155;
  PKCS7_R_NO_CONTENT = 122;
  PKCS7_R_NO_DEFAULT_DIGEST = 151;
  PKCS7_R_NO_MATCHING_DIGEST_TYPE_FOUND = 154;
  PKCS7_R_NO_RECIPIENT_MATCHES_CERTIFICATE = 115;
  PKCS7_R_NO_SIGNATURES_ON_DATA = 123;
  PKCS7_R_NO_SIGNERS = 142;
  PKCS7_R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE = 104;
  PKCS7_R_PKCS7_ADD_SIGNATURE_ERROR = 124;
  PKCS7_R_PKCS7_ADD_SIGNER_ERROR = 153;
  PKCS7_R_PKCS7_DATASIGN = 145;
  PKCS7_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE = 127;
  PKCS7_R_SIGNATURE_FAILURE = 105;
  PKCS7_R_SIGNER_CERTIFICATE_NOT_FOUND = 128;
  PKCS7_R_SIGNING_CTRL_FAILURE = 147;
  PKCS7_R_SIGNING_NOT_SUPPORTED_FOR_THIS_KEY_TYPE = 148;
  PKCS7_R_SMIME_TEXT_ERROR = 129;
  PKCS7_R_UNABLE_TO_FIND_CERTIFICATE = 106;
  PKCS7_R_UNABLE_TO_FIND_MEM_BIO = 107;
  PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST = 108;
  PKCS7_R_UNKNOWN_DIGEST_TYPE = 109;
  PKCS7_R_UNKNOWN_OPERATION = 110;
  PKCS7_R_UNSUPPORTED_CIPHER_TYPE = 111;
  PKCS7_R_UNSUPPORTED_CONTENT_TYPE = 112;
  PKCS7_R_WRONG_CONTENT_TYPE = 113;
  PKCS7_R_WRONG_PKCS7_TYPE = 114;

implementation

end.