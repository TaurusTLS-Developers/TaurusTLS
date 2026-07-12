/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_uierr.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_uierr.h2pas
     and this file regenerated. TaurusTLSHeaders_uierr.h2pas is distributed with the full Indy
     Distribution.
   *)
   
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
unit TaurusTLSHeaders_uierr;

interface

// Headers for OpenSSL 1.1.1
// uierr.h


uses
  IdCTypes,
  IdGlobal
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  , TaurusTLSConsts
  {$ENDIF};

const
  (*
   * UI function codes.
   *)
  {$EXTERNALSYM UI_F_CLOSE_CONSOLE}
  UI_F_CLOSE_CONSOLE = 115;
  {$EXTERNALSYM UI_F_ECHO_CONSOLE}
  UI_F_ECHO_CONSOLE = 116;
  {$EXTERNALSYM UI_F_GENERAL_ALLOCATE_BOOLEAN}
  UI_F_GENERAL_ALLOCATE_BOOLEAN = 108;
  {$EXTERNALSYM UI_F_GENERAL_ALLOCATE_PROMPT}
  UI_F_GENERAL_ALLOCATE_PROMPT = 109;
  {$EXTERNALSYM UI_F_NOECHO_CONSOLE}
  UI_F_NOECHO_CONSOLE = 117;
  {$EXTERNALSYM UI_F_OPEN_CONSOLE}
  UI_F_OPEN_CONSOLE = 114;
  {$EXTERNALSYM UI_F_UI_CONSTRUCT_PROMPT}
  UI_F_UI_CONSTRUCT_PROMPT = 121;
  {$EXTERNALSYM UI_F_UI_CREATE_METHOD}
  UI_F_UI_CREATE_METHOD = 112;
  {$EXTERNALSYM UI_F_UI_CTRL}
  UI_F_UI_CTRL = 111;
  {$EXTERNALSYM UI_F_UI_DUP_ERROR_STRING}
  UI_F_UI_DUP_ERROR_STRING = 101;
  {$EXTERNALSYM UI_F_UI_DUP_INFO_STRING}
  UI_F_UI_DUP_INFO_STRING = 102;
  {$EXTERNALSYM UI_F_UI_DUP_INPUT_BOOLEAN}
  UI_F_UI_DUP_INPUT_BOOLEAN = 110;
  {$EXTERNALSYM UI_F_UI_DUP_INPUT_STRING}
  UI_F_UI_DUP_INPUT_STRING = 103;
  {$EXTERNALSYM UI_F_UI_DUP_USER_DATA}
  UI_F_UI_DUP_USER_DATA = 118;
  {$EXTERNALSYM UI_F_UI_DUP_VERIFY_STRING}
  UI_F_UI_DUP_VERIFY_STRING = 106;
  {$EXTERNALSYM UI_F_UI_GET0_RESULT}
  UI_F_UI_GET0_RESULT = 107;
  {$EXTERNALSYM UI_F_UI_GET_RESULT_LENGTH}
  UI_F_UI_GET_RESULT_LENGTH = 119;
  {$EXTERNALSYM UI_F_UI_NEW_METHOD}
  UI_F_UI_NEW_METHOD = 104;
  {$EXTERNALSYM UI_F_UI_PROCESS}
  UI_F_UI_PROCESS = 113;
  {$EXTERNALSYM UI_F_UI_SET_RESULT}
  UI_F_UI_SET_RESULT = 105;
  {$EXTERNALSYM UI_F_UI_SET_RESULT_EX}
  UI_F_UI_SET_RESULT_EX = 120;

  (*
   * UI reason codes.
   *)
  {$EXTERNALSYM UI_R_COMMON_OK_AND_CANCEL_CHARACTERS}
  UI_R_COMMON_OK_AND_CANCEL_CHARACTERS = 104;
  {$EXTERNALSYM UI_R_INDEX_TOO_LARGE}
  UI_R_INDEX_TOO_LARGE = 102;
  {$EXTERNALSYM UI_R_INDEX_TOO_SMALL}
  UI_R_INDEX_TOO_SMALL = 103;
  {$EXTERNALSYM UI_R_NO_RESULT_BUFFER}
  UI_R_NO_RESULT_BUFFER = 105;
  {$EXTERNALSYM UI_R_PROCESSING_ERROR}
  UI_R_PROCESSING_ERROR = 107;
  {$EXTERNALSYM UI_R_RESULT_TOO_LARGE}
  UI_R_RESULT_TOO_LARGE = 100;
  {$EXTERNALSYM UI_R_RESULT_TOO_SMALL}
  UI_R_RESULT_TOO_SMALL = 101;
  {$EXTERNALSYM UI_R_SYSASSIGN_ERROR}
  UI_R_SYSASSIGN_ERROR = 109;
  {$EXTERNALSYM UI_R_SYSDASSGN_ERROR}
  UI_R_SYSDASSGN_ERROR = 110;
  {$EXTERNALSYM UI_R_SYSQIOW_ERROR}
  UI_R_SYSQIOW_ERROR = 111;
  {$EXTERNALSYM UI_R_UNKNOWN_CONTROL_COMMAND}
  UI_R_UNKNOWN_CONTROL_COMMAND = 106;
  {$EXTERNALSYM UI_R_UNKNOWN_TTYGET_ERRNO_VALUE}
  UI_R_UNKNOWN_TTYGET_ERRNO_VALUE = 108;
  {$EXTERNALSYM UI_R_USER_DATA_DUPLICATION_UNSUPPORTED}
  UI_R_USER_DATA_DUPLICATION_UNSUPPORTED = 112;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM ERR_load_UI_strings}
  ERR_load_UI_strings: function : TIdC_INT; cdecl = nil;

{$ELSE}
  {$EXTERNALSYM ERR_load_UI_strings}
  function ERR_load_UI_strings: TIdC_INT cdecl; external CLibCrypto;

{$ENDIF}

implementation

  uses
    classes, 
    TaurusTLSExceptionHandlers
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    ,TaurusTLSLoader
  {$ENDIF};
  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
const
  ERR_load_UI_strings_procname = 'ERR_load_UI_strings';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_ERR_load_UI_strings: TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_load_UI_strings_procname);
end;



  {$I TaurusTLSNoRetValOn.inc} 
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  ERR_load_UI_strings := LoadLibFunction(ADllHandle, ERR_load_UI_strings_procname);
  FuncLoadError := not assigned(ERR_load_UI_strings);
  if FuncLoadError then
  begin
    {$if not defined(ERR_load_UI_strings_allownil)}
    ERR_load_UI_strings := ERR_ERR_load_UI_strings;
    {$ifend}
    {$if declared(ERR_load_UI_strings_introduced)}
    if LibVersion < ERR_load_UI_strings_introduced then
    begin
      {$if declared(FC_ERR_load_UI_strings)}
      ERR_load_UI_strings := FC_ERR_load_UI_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_load_UI_strings_removed)}
    if ERR_load_UI_strings_removed <= LibVersion then
    begin
      {$if declared(_ERR_load_UI_strings)}
      ERR_load_UI_strings := _ERR_load_UI_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_load_UI_strings_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_load_UI_strings');
    {$ifend}
  end;
end;
  {$I TaurusTLSUnusedParamOn.inc}

procedure Unload;
begin
  ERR_load_UI_strings := nil;
end;
  {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
