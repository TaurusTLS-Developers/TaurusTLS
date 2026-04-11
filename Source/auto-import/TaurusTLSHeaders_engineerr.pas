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

unit TaurusTLSHeaders_engineerr;

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
  ENGINE_R_ALREADY_LOADED = 100;
  ENGINE_R_ARGUMENT_IS_NOT_A_NUMBER = 133;
  ENGINE_R_CMD_NOT_EXECUTABLE = 134;
  ENGINE_R_COMMAND_TAKES_INPUT = 135;
  ENGINE_R_COMMAND_TAKES_NO_INPUT = 136;
  ENGINE_R_CONFLICTING_ENGINE_ID = 103;
  ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED = 119;
  ENGINE_R_DSO_FAILURE = 104;
  ENGINE_R_DSO_NOT_FOUND = 132;
  ENGINE_R_ENGINES_SECTION_ERROR = 148;
  ENGINE_R_ENGINE_CONFIGURATION_ERROR = 102;
  ENGINE_R_ENGINE_IS_NOT_IN_LIST = 105;
  ENGINE_R_ENGINE_SECTION_ERROR = 149;
  ENGINE_R_FAILED_LOADING_PRIVATE_KEY = 128;
  ENGINE_R_FAILED_LOADING_PUBLIC_KEY = 129;
  ENGINE_R_FINISH_FAILED = 106;
  ENGINE_R_ID_OR_NAME_MISSING = 108;
  ENGINE_R_INIT_FAILED = 109;
  ENGINE_R_INTERNAL_LIST_ERROR = 110;
  ENGINE_R_INVALID_ARGUMENT = 143;
  ENGINE_R_INVALID_CMD_NAME = 137;
  ENGINE_R_INVALID_CMD_NUMBER = 138;
  ENGINE_R_INVALID_INIT_VALUE = 151;
  ENGINE_R_INVALID_STRING = 150;
  ENGINE_R_NOT_INITIALISED = 117;
  ENGINE_R_NOT_LOADED = 112;
  ENGINE_R_NO_CONTROL_FUNCTION = 120;
  ENGINE_R_NO_INDEX = 144;
  ENGINE_R_NO_LOAD_FUNCTION = 125;
  ENGINE_R_NO_REFERENCE = 130;
  ENGINE_R_NO_SUCH_ENGINE = 116;
  ENGINE_R_UNIMPLEMENTED_CIPHER = 146;
  ENGINE_R_UNIMPLEMENTED_DIGEST = 147;
  ENGINE_R_UNIMPLEMENTED_PUBLIC_KEY_METHOD = 101;
  ENGINE_R_VERSION_INCOMPATIBILITY = 145;

implementation

end.