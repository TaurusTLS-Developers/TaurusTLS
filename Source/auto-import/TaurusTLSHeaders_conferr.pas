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

unit TaurusTLSHeaders_conferr;

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
  CONF_R_ERROR_LOADING_DSO = 110;
  CONF_R_INVALID_PRAGMA = 122;
  CONF_R_LIST_CANNOT_BE_NULL = 115;
  CONF_R_MANDATORY_BRACES_IN_VARIABLE_EXPANSION = 123;
  CONF_R_MISSING_CLOSE_SQUARE_BRACKET = 100;
  CONF_R_MISSING_EQUAL_SIGN = 101;
  CONF_R_MISSING_INIT_FUNCTION = 112;
  CONF_R_MODULE_INITIALIZATION_ERROR = 109;
  CONF_R_NO_CLOSE_BRACE = 102;
  CONF_R_NO_CONF = 105;
  CONF_R_NO_CONF_OR_ENVIRONMENT_VARIABLE = 106;
  CONF_R_NO_SECTION = 107;
  CONF_R_NO_SUCH_FILE = 114;
  CONF_R_NO_VALUE = 108;
  CONF_R_NUMBER_TOO_LARGE = 121;
  CONF_R_OPENSSL_CONF_REFERENCES_MISSING_SECTION = 124;
  CONF_R_RECURSIVE_DIRECTORY_INCLUDE = 111;
  CONF_R_RECURSIVE_SECTION_REFERENCE = 126;
  CONF_R_RELATIVE_PATH = 125;
  CONF_R_SSL_COMMAND_SECTION_EMPTY = 117;
  CONF_R_SSL_COMMAND_SECTION_NOT_FOUND = 118;
  CONF_R_SSL_SECTION_EMPTY = 119;
  CONF_R_SSL_SECTION_NOT_FOUND = 120;
  CONF_R_UNABLE_TO_CREATE_NEW_SECTION = 103;
  CONF_R_UNKNOWN_MODULE_NAME = 113;
  CONF_R_VARIABLE_EXPANSION_TOO_LONG = 116;
  CONF_R_VARIABLE_HAS_NO_VALUE = 104;

implementation

end.