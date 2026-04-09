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

unit TaurusTLSHeaders_ocsperr;

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
  OCSP_R_CERTIFICATE_VERIFY_ERROR = 101;
  OCSP_R_DIGEST_ERR = 102;
  OCSP_R_DIGEST_NAME_ERR = 106;
  OCSP_R_DIGEST_SIZE_ERR = 107;
  OCSP_R_ERROR_IN_NEXTUPDATE_FIELD = 122;
  OCSP_R_ERROR_IN_THISUPDATE_FIELD = 123;
  OCSP_R_MISSING_OCSPSIGNING_USAGE = 103;
  OCSP_R_NEXTUPDATE_BEFORE_THISUPDATE = 124;
  OCSP_R_NOT_BASIC_RESPONSE = 104;
  OCSP_R_NO_CERTIFICATES_IN_CHAIN = 105;
  OCSP_R_NO_RESPONSE_DATA = 108;
  OCSP_R_NO_REVOKED_TIME = 109;
  OCSP_R_NO_SIGNER_KEY = 130;
  OCSP_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE = 110;
  OCSP_R_REQUEST_NOT_SIGNED = 128;
  OCSP_R_RESPONSE_CONTAINS_NO_REVOCATION_DATA = 111;
  OCSP_R_ROOT_CA_NOT_TRUSTED = 112;
  OCSP_R_SIGNATURE_FAILURE = 117;
  OCSP_R_SIGNER_CERTIFICATE_NOT_FOUND = 118;
  OCSP_R_STATUS_EXPIRED = 125;
  OCSP_R_STATUS_NOT_YET_VALID = 126;
  OCSP_R_STATUS_TOO_OLD = 127;
  OCSP_R_UNKNOWN_MESSAGE_DIGEST = 119;
  OCSP_R_UNKNOWN_NID = 120;
  OCSP_R_UNSUPPORTED_REQUESTORNAME_TYPE = 129;

implementation

end.