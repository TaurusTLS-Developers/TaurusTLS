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

unit TaurusTLSHeaders_pemerr;

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
  PEM_R_BAD_BASE64_DECODE = 100;
  PEM_R_BAD_DECRYPT = 101;
  PEM_R_BAD_END_LINE = 102;
  PEM_R_BAD_IV_CHARS = 103;
  PEM_R_BAD_MAGIC_NUMBER = 116;
  PEM_R_BAD_PASSWORD_READ = 104;
  PEM_R_BAD_VERSION_NUMBER = 117;
  PEM_R_BIO_WRITE_FAILURE = 118;
  PEM_R_CIPHER_IS_NULL = 127;
  PEM_R_ERROR_CONVERTING_PRIVATE_KEY = 115;
  PEM_R_EXPECTING_DSS_KEY_BLOB = 131;
  PEM_R_EXPECTING_PRIVATE_KEY_BLOB = 119;
  PEM_R_EXPECTING_PUBLIC_KEY_BLOB = 120;
  PEM_R_EXPECTING_RSA_KEY_BLOB = 132;
  PEM_R_HEADER_TOO_LONG = 128;
  PEM_R_INCONSISTENT_HEADER = 121;
  PEM_R_KEYBLOB_HEADER_PARSE_ERROR = 122;
  PEM_R_KEYBLOB_TOO_SHORT = 123;
  PEM_R_MISSING_DEK_IV = 129;
  PEM_R_NOT_DEK_INFO = 105;
  PEM_R_NOT_ENCRYPTED = 106;
  PEM_R_NOT_PROC_TYPE = 107;
  PEM_R_NO_START_LINE = 108;
  PEM_R_PROBLEMS_GETTING_PASSWORD = 109;
  PEM_R_PVK_DATA_TOO_SHORT = 124;
  PEM_R_PVK_TOO_SHORT = 125;
  PEM_R_READ_KEY = 111;
  PEM_R_SHORT_HEADER = 112;
  PEM_R_UNEXPECTED_DEK_IV = 130;
  PEM_R_UNSUPPORTED_CIPHER = 113;
  PEM_R_UNSUPPORTED_ENCRYPTION = 114;
  PEM_R_UNSUPPORTED_KEY_COMPONENTS = 126;
  PEM_R_UNSUPPORTED_PUBLIC_KEY_TYPE = 110;
  PEM_R_UNSUPPORTED_PVK_KEY_TYPE = 133;

implementation

end.