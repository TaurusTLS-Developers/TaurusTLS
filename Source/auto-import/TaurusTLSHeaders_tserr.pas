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

unit TaurusTLSHeaders_tserr;

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
  TS_R_BAD_PKCS7_TYPE = 132;
  TS_R_BAD_TYPE = 133;
  TS_R_CANNOT_LOAD_CERT = 137;
  TS_R_CANNOT_LOAD_KEY = 138;
  TS_R_CERTIFICATE_VERIFY_ERROR = 100;
  TS_R_COULD_NOT_SET_ENGINE = 127;
  TS_R_COULD_NOT_SET_TIME = 115;
  TS_R_DETACHED_CONTENT = 134;
  TS_R_ESS_ADD_SIGNING_CERT_ERROR = 116;
  TS_R_ESS_ADD_SIGNING_CERT_V2_ERROR = 139;
  TS_R_ESS_SIGNING_CERTIFICATE_ERROR = 101;
  TS_R_INVALID_NULL_POINTER = 102;
  TS_R_INVALID_SIGNER_CERTIFICATE_PURPOSE = 117;
  TS_R_MESSAGE_IMPRINT_MISMATCH = 103;
  TS_R_NONCE_MISMATCH = 104;
  TS_R_NONCE_NOT_RETURNED = 105;
  TS_R_NO_CONTENT = 106;
  TS_R_NO_TIME_STAMP_TOKEN = 107;
  TS_R_PKCS7_ADD_SIGNATURE_ERROR = 118;
  TS_R_PKCS7_ADD_SIGNED_ATTR_ERROR = 119;
  TS_R_PKCS7_TO_TS_TST_INFO_FAILED = 129;
  TS_R_POLICY_MISMATCH = 108;
  TS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE = 120;
  TS_R_RESPONSE_SETUP_ERROR = 121;
  TS_R_SIGNATURE_FAILURE = 109;
  TS_R_THERE_MUST_BE_ONE_SIGNER = 110;
  TS_R_TIME_SYSCALL_ERROR = 122;
  TS_R_TOKEN_NOT_PRESENT = 130;
  TS_R_TOKEN_PRESENT = 131;
  TS_R_TSA_NAME_MISMATCH = 111;
  TS_R_TSA_UNTRUSTED = 112;
  TS_R_TST_INFO_SETUP_ERROR = 123;
  TS_R_TS_DATASIGN = 124;
  TS_R_UNACCEPTABLE_POLICY = 125;
  TS_R_UNSUPPORTED_MD_ALGORITHM = 126;
  TS_R_UNSUPPORTED_VERSION = 113;
  TS_R_VAR_BAD_VALUE = 135;
  TS_R_VAR_LOOKUP_FAILURE = 136;
  TS_R_WRONG_CONTENT_TYPE = 114;

implementation

end.