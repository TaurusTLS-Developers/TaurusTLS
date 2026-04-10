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

unit TaurusTLSHeaders_cterr;

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
  CT_R_BASE64_DECODE_ERROR = 108;
  CT_R_INVALID_LOG_ID_LENGTH = 100;
  CT_R_LOG_CONF_INVALID = 109;
  CT_R_LOG_CONF_INVALID_KEY = 110;
  CT_R_LOG_CONF_MISSING_DESCRIPTION = 111;
  CT_R_LOG_CONF_MISSING_KEY = 112;
  CT_R_LOG_KEY_INVALID = 113;
  CT_R_SCT_FUTURE_TIMESTAMP = 116;
  CT_R_SCT_INVALID = 104;
  CT_R_SCT_INVALID_SIGNATURE = 107;
  CT_R_SCT_LIST_INVALID = 105;
  CT_R_SCT_LOG_ID_MISMATCH = 114;
  CT_R_SCT_NOT_SET = 106;
  CT_R_SCT_UNSUPPORTED_VERSION = 115;
  CT_R_UNRECOGNIZED_SIGNATURE_NID = 101;
  CT_R_UNSUPPORTED_ENTRY_TYPE = 102;
  CT_R_UNSUPPORTED_VERSION = 103;

implementation

end.