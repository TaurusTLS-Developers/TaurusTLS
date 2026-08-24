/// <exclude />
(* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_conferr.h2pas
  It should not be modified directly. All changes should be made to TaurusTLSHeaders_conferr.h2pas
  and this file regenerated. TaurusTLSHeaders_conferr.h2pas is distributed with the full Indy
  Distribution.
*)

{$I TaurusTLSCompilerDefines.inc}
{$I TaurusTLSLinkDefines.inc}
{$IFNDEF USE_OPENSSL}
{ error Should not compile if USE_OPENSSL is not defined!!! }
{$ENDIF}
{ ****************************************************************************** }
{ *  TaurusTLS                                                                 * }
{ *           https://github.com/JPeterMugaas/TaurusTLS                        * }
{ *                                                                            * }
{ *  Copyright (c) 2024 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }

unit TaurusTLSHeaders_conferr;

interface

// Headers for OpenSSL 1.1.1
// conferr.h

uses
  IdCTypes,
  IdGlobal
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  , TaurusTLSConsts
  {$ENDIF};

const
  /// *
  // * CONF function codes.
  // */
  {$EXTERNALSYM CONF_F_CONF_DUMP_FP}
  CONF_F_CONF_DUMP_FP = 104;
  {$EXTERNALSYM CONF_F_CONF_LOAD}
  CONF_F_CONF_LOAD = 100;
  {$EXTERNALSYM CONF_F_CONF_LOAD_FP}
  CONF_F_CONF_LOAD_FP = 103;
  {$EXTERNALSYM CONF_F_CONF_PARSE_LIST}
  CONF_F_CONF_PARSE_LIST = 119;
  {$EXTERNALSYM CONF_F_DEF_LOAD}
  CONF_F_DEF_LOAD = 120;
  {$EXTERNALSYM CONF_F_DEF_LOAD_BIO}
  CONF_F_DEF_LOAD_BIO = 121;
  {$EXTERNALSYM CONF_F_GET_NEXT_FILE}
  CONF_F_GET_NEXT_FILE = 107;
  {$EXTERNALSYM CONF_F_MODULE_ADD}
  CONF_F_MODULE_ADD = 122;
  {$EXTERNALSYM CONF_F_MODULE_INIT}
  CONF_F_MODULE_INIT = 115;
  {$EXTERNALSYM CONF_F_MODULE_LOAD_DSO}
  CONF_F_MODULE_LOAD_DSO = 117;
  {$EXTERNALSYM CONF_F_MODULE_RUN}
  CONF_F_MODULE_RUN = 118;
  {$EXTERNALSYM CONF_F_NCONF_DUMP_BIO}
  CONF_F_NCONF_DUMP_BIO = 105;
  {$EXTERNALSYM CONF_F_NCONF_DUMP_FP}
  CONF_F_NCONF_DUMP_FP = 106;
  {$EXTERNALSYM CONF_F_NCONF_GET_NUMBER_E}
  CONF_F_NCONF_GET_NUMBER_E = 112;
  {$EXTERNALSYM CONF_F_NCONF_GET_SECTION}
  CONF_F_NCONF_GET_SECTION = 108;
  {$EXTERNALSYM CONF_F_NCONF_GET_STRING}
  CONF_F_NCONF_GET_STRING = 109;
  {$EXTERNALSYM CONF_F_NCONF_LOAD}
  CONF_F_NCONF_LOAD = 113;
  {$EXTERNALSYM CONF_F_NCONF_LOAD_BIO}
  CONF_F_NCONF_LOAD_BIO = 110;
  {$EXTERNALSYM CONF_F_NCONF_LOAD_FP}
  CONF_F_NCONF_LOAD_FP = 114;
  {$EXTERNALSYM CONF_F_NCONF_NEW}
  CONF_F_NCONF_NEW = 111;
  {$EXTERNALSYM CONF_F_PROCESS_INCLUDE}
  CONF_F_PROCESS_INCLUDE = 116;
  {$EXTERNALSYM CONF_F_SSL_MODULE_INIT}
  CONF_F_SSL_MODULE_INIT = 123;
  {$EXTERNALSYM CONF_F_STR_COPY}
  CONF_F_STR_COPY = 101;

  /// *
  // * CONF reason codes.
  // */
  {$EXTERNALSYM CONF_R_ERROR_LOADING_DSO}
  CONF_R_ERROR_LOADING_DSO = 110;
  {$EXTERNALSYM CONF_R_LIST_CANNOT_BE_NULL}
  CONF_R_LIST_CANNOT_BE_NULL = 115;
  {$EXTERNALSYM CONF_R_MISSING_CLOSE_SQUARE_BRACKET}
  CONF_R_MISSING_CLOSE_SQUARE_BRACKET = 100;
  {$EXTERNALSYM CONF_R_MISSING_EQUAL_SIGN}
  CONF_R_MISSING_EQUAL_SIGN = 101;
  {$EXTERNALSYM CONF_R_MISSING_INIT_FUNCTION}
  CONF_R_MISSING_INIT_FUNCTION = 112;
  {$EXTERNALSYM CONF_R_MODULE_INITIALIZATION_ERROR}
  CONF_R_MODULE_INITIALIZATION_ERROR = 109;
  {$EXTERNALSYM CONF_R_NO_CLOSE_BRACE}
  CONF_R_NO_CLOSE_BRACE = 102;
  {$EXTERNALSYM CONF_R_NO_CONF}
  CONF_R_NO_CONF = 105;
  {$EXTERNALSYM CONF_R_NO_CONF_OR_ENVIRONMENT_VARIABLE}
  CONF_R_NO_CONF_OR_ENVIRONMENT_VARIABLE = 106;
  {$EXTERNALSYM CONF_R_NO_SECTION}
  CONF_R_NO_SECTION = 107;
  {$EXTERNALSYM CONF_R_NO_SUCH_FILE}
  CONF_R_NO_SUCH_FILE = 114;
  {$EXTERNALSYM CONF_R_NO_VALUE}
  CONF_R_NO_VALUE = 108;
  {$EXTERNALSYM CONF_R_NUMBER_TOO_LARGE}
  CONF_R_NUMBER_TOO_LARGE = 121;
  {$EXTERNALSYM CONF_R_RECURSIVE_DIRECTORY_INCLUDE}
  CONF_R_RECURSIVE_DIRECTORY_INCLUDE = 111;
  {$EXTERNALSYM CONF_R_SSL_COMMAND_SECTION_EMPTY}
  CONF_R_SSL_COMMAND_SECTION_EMPTY = 117;
  {$EXTERNALSYM CONF_R_SSL_COMMAND_SECTION_NOT_FOUND}
  CONF_R_SSL_COMMAND_SECTION_NOT_FOUND = 118;
  {$EXTERNALSYM CONF_R_SSL_SECTION_EMPTY}
  CONF_R_SSL_SECTION_EMPTY = 119;
  {$EXTERNALSYM CONF_R_SSL_SECTION_NOT_FOUND}
  CONF_R_SSL_SECTION_NOT_FOUND = 120;
  {$EXTERNALSYM CONF_R_UNABLE_TO_CREATE_NEW_SECTION}
  CONF_R_UNABLE_TO_CREATE_NEW_SECTION = 103;
  {$EXTERNALSYM CONF_R_UNKNOWN_MODULE_NAME}
  CONF_R_UNKNOWN_MODULE_NAME = 113;
  {$EXTERNALSYM CONF_R_VARIABLE_EXPANSION_TOO_LONG}
  CONF_R_VARIABLE_EXPANSION_TOO_LONG = 116;
  {$EXTERNALSYM CONF_R_VARIABLE_HAS_NO_VALUE}
  CONF_R_VARIABLE_HAS_NO_VALUE = 104;

  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

    The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
    files generated for C++. }

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

var
  {$EXTERNALSYM ERR_load_CONF_strings}
  ERR_load_CONF_strings: function: TIdC_INT;
cdecl = nil;

{$ELSE}
  {$EXTERNALSYM ERR_load_CONF_strings}
function ERR_load_CONF_strings: TIdC_INT cdecl; external CLibCrypto;

{$ENDIF}

implementation

uses
  classes,
  TaurusTLSExceptionHandlers
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    , TaurusTLSLoader
{$ENDIF};

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

const
  ERR_load_CONF_strings_procname = 'ERR_load_CONF_strings';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 

function ERR_ERR_load_CONF_strings: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_load_CONF_strings_procname);
end;

  {$I TaurusTLSNoRetValOn.inc} 
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);

var
  FuncLoadError: boolean;

begin
  ERR_load_CONF_strings := LoadLibFunction(ADllHandle,
    ERR_load_CONF_strings_procname);
  FuncLoadError := not assigned(ERR_load_CONF_strings);
  if FuncLoadError then
  begin
{$IF not defined(ERR_load_CONF_strings_allownil)}
    ERR_load_CONF_strings := ERR_ERR_load_CONF_strings;
{$IFEND}
{$IF declared(ERR_load_CONF_strings_introduced)}
    if LibVersion < ERR_load_CONF_strings_introduced then
    begin
{$IF declared(FC_ERR_load_CONF_strings)}
      ERR_load_CONF_strings := FC_ERR_load_CONF_strings;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(ERR_load_CONF_strings_removed)}
    if ERR_load_CONF_strings_removed <= LibVersion then
    begin
{$IF declared(_ERR_load_CONF_strings)}
      ERR_load_CONF_strings := _ERR_load_CONF_strings;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(ERR_load_CONF_strings_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_load_CONF_strings');
{$IFEND}
  end;

end;
  {$I TaurusTLSUnusedParamOn.inc}

procedure Unload;
begin
  ERR_load_CONF_strings := nil;
end;
  {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization

Register_SSLLoader(Load, 'LibCrypto');
Register_SSLUnloader(Unload);
{$ENDIF}

end.
