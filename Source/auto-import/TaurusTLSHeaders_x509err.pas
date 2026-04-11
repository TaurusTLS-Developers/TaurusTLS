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

unit TaurusTLSHeaders_x509err;

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
  X509_R_AKID_MISMATCH = 110;
  X509_R_BAD_SELECTOR = 133;
  X509_R_BAD_X509_FILETYPE = 100;
  X509_R_BASE64_DECODE_ERROR = 118;
  X509_R_CANT_CHECK_DH_KEY = 114;
  X509_R_CERTIFICATE_VERIFICATION_FAILED = 139;
  X509_R_CERT_ALREADY_IN_HASH_TABLE = 101;
  X509_R_CRL_ALREADY_DELTA = 127;
  X509_R_CRL_VERIFY_FAILURE = 131;
  X509_R_DUPLICATE_ATTRIBUTE = 140;
  X509_R_ERROR_GETTING_MD_BY_NID = 141;
  X509_R_ERROR_USING_SIGINF_SET = 142;
  X509_R_IDP_MISMATCH = 128;
  X509_R_INVALID_ATTRIBUTES = 138;
  X509_R_INVALID_DIRECTORY = 113;
  X509_R_INVALID_DISTPOINT = 143;
  X509_R_INVALID_FIELD_NAME = 119;
  X509_R_INVALID_TRUST = 123;
  X509_R_ISSUER_MISMATCH = 129;
  X509_R_KEY_TYPE_MISMATCH = 115;
  X509_R_KEY_VALUES_MISMATCH = 116;
  X509_R_LOADING_CERT_DIR = 103;
  X509_R_LOADING_DEFAULTS = 104;
  X509_R_METHOD_NOT_SUPPORTED = 124;
  X509_R_NAME_TOO_LONG = 134;
  X509_R_NEWER_CRL_NOT_NEWER = 132;
  X509_R_NO_CERTIFICATE_FOUND = 135;
  X509_R_NO_CERTIFICATE_OR_CRL_FOUND = 136;
  X509_R_NO_CERT_SET_FOR_US_TO_VERIFY = 105;
  X509_R_NO_CRL_FOUND = 137;
  X509_R_NO_CRL_NUMBER = 130;
  X509_R_PUBLIC_KEY_DECODE_ERROR = 125;
  X509_R_PUBLIC_KEY_ENCODE_ERROR = 126;
  X509_R_SHOULD_RETRY = 106;
  X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN = 107;
  X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY = 108;
  X509_R_UNKNOWN_KEY_TYPE = 117;
  X509_R_UNKNOWN_NID = 109;
  X509_R_UNKNOWN_PURPOSE_ID = 121;
  X509_R_UNKNOWN_SIGID_ALGS = 144;
  X509_R_UNKNOWN_TRUST_ID = 120;
  X509_R_UNSUPPORTED_ALGORITHM = 111;
  X509_R_UNSUPPORTED_VERSION = 145;
  X509_R_WRONG_LOOKUP_TYPE = 112;
  X509_R_WRONG_TYPE = 122;

implementation

end.