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

unit TaurusTLSHeaders_httperr;

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
  HTTP_R_ASN1_LEN_EXCEEDS_MAX_RESP_LEN = 108;
  HTTP_R_CONNECT_FAILURE = 100;
  HTTP_R_CONTENT_TYPE_MISMATCH = 131;
  HTTP_R_ERROR_PARSING_ASN1_LENGTH = 109;
  HTTP_R_ERROR_PARSING_CONTENT_LENGTH = 119;
  HTTP_R_ERROR_PARSING_URL = 101;
  HTTP_R_ERROR_RECEIVING = 103;
  HTTP_R_ERROR_SENDING = 102;
  HTTP_R_FAILED_READING_DATA = 128;
  HTTP_R_HEADER_PARSE_ERROR = 126;
  HTTP_R_INCONSISTENT_CONTENT_LENGTH = 120;
  HTTP_R_INVALID_PORT_NUMBER = 123;
  HTTP_R_INVALID_URL_PATH = 125;
  HTTP_R_INVALID_URL_SCHEME = 124;
  HTTP_R_MAX_RESP_LEN_EXCEEDED = 117;
  HTTP_R_MISSING_ASN1_ENCODING = 110;
  HTTP_R_MISSING_CONTENT_TYPE = 121;
  HTTP_R_MISSING_REDIRECT_LOCATION = 111;
  HTTP_R_RECEIVED_ERROR = 105;
  HTTP_R_RECEIVED_WRONG_HTTP_VERSION = 106;
  HTTP_R_REDIRECTION_FROM_HTTPS_TO_HTTP = 112;
  HTTP_R_REDIRECTION_NOT_ENABLED = 116;
  HTTP_R_RESPONSE_LINE_TOO_LONG = 113;
  HTTP_R_RESPONSE_PARSE_ERROR = 104;
  HTTP_R_RESPONSE_TOO_MANY_HDRLINES = 130;
  HTTP_R_RETRY_TIMEOUT = 129;
  HTTP_R_SERVER_CANCELED_CONNECTION = 127;
  HTTP_R_SOCK_NOT_SUPPORTED = 122;
  HTTP_R_STATUS_CODE_UNSUPPORTED = 114;
  HTTP_R_TLS_NOT_ENABLED = 107;
  HTTP_R_TOO_MANY_REDIRECTIONS = 115;
  HTTP_R_UNEXPECTED_CONTENT_TYPE = 118;

implementation

end.