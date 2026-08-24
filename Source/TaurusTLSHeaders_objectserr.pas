/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_objectserr.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_objectserr.h2pas
     and this file regenerated. TaurusTLSHeaders_objectserr.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_objectserr;

interface

// Headers for OpenSSL 1.1.1
// objectserr.h


uses
  IdCTypes,
  IdGlobal
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  , TaurusTLSConsts
  {$ENDIF};

const
  (*
   * OBJ function codes.
   *)
  {$EXTERNALSYM OBJ_F_OBJ_ADD_OBJECT}
  OBJ_F_OBJ_ADD_OBJECT =  105;
  {$EXTERNALSYM OBJ_F_OBJ_ADD_SIGID}
  OBJ_F_OBJ_ADD_SIGID =  107;
  {$EXTERNALSYM OBJ_F_OBJ_CREATE}
  OBJ_F_OBJ_CREATE =   100;
  {$EXTERNALSYM OBJ_F_OBJ_DUP}
  OBJ_F_OBJ_DUP =   101;
  {$EXTERNALSYM OBJ_F_OBJ_NAME_NEW_INDEX}
  OBJ_F_OBJ_NAME_NEW_INDEX =  106;
  {$EXTERNALSYM OBJ_F_OBJ_NID2LN}
  OBJ_F_OBJ_NID2LN =   102;
  {$EXTERNALSYM OBJ_F_OBJ_NID2OBJ}
  OBJ_F_OBJ_NID2OBJ =   103;
  {$EXTERNALSYM OBJ_F_OBJ_NID2SN}
  OBJ_F_OBJ_NID2SN =   104;
  {$EXTERNALSYM OBJ_F_OBJ_TXT2OBJ}
  OBJ_F_OBJ_TXT2OBJ =   108;

  (*
   * OBJ reason codes.
   *)
  {$EXTERNALSYM OBJ_R_OID_EXISTS}
  OBJ_R_OID_EXISTS = 102;
  {$EXTERNALSYM OBJ_R_UNKNOWN_NID}
  OBJ_R_UNKNOWN_NID = 101;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM ERR_load_OBJ_strings}
  ERR_load_OBJ_strings: function : TIdC_INT; cdecl = nil;

{$ELSE}
  {$EXTERNALSYM ERR_load_OBJ_strings}
  function ERR_load_OBJ_strings: TIdC_INT cdecl; external CLibCrypto;

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
  ERR_load_OBJ_strings_procname = 'ERR_load_OBJ_strings';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_ERR_load_OBJ_strings: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_load_OBJ_strings_procname);
end;



  {$I TaurusTLSNoRetValOn.inc} 
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  ERR_load_OBJ_strings := LoadLibFunction(ADllHandle, ERR_load_OBJ_strings_procname);
  FuncLoadError := not assigned(ERR_load_OBJ_strings);
  if FuncLoadError then
  begin
    {$if not defined(ERR_load_OBJ_strings_allownil)}
    ERR_load_OBJ_strings := ERR_ERR_load_OBJ_strings;
    {$ifend}
    {$if declared(ERR_load_OBJ_strings_introduced)}
    if LibVersion < ERR_load_OBJ_strings_introduced then
    begin
      {$if declared(FC_ERR_load_OBJ_strings)}
      ERR_load_OBJ_strings := FC_ERR_load_OBJ_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_load_OBJ_strings_removed)}
    if ERR_load_OBJ_strings_removed <= LibVersion then
    begin
      {$if declared(_ERR_load_OBJ_strings)}
      ERR_load_OBJ_strings := _ERR_load_OBJ_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_load_OBJ_strings_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_load_OBJ_strings');
    {$ifend}
  end;
end;

  {$I TaurusTLSUnusedParamOn.inc}

procedure Unload;
begin
  ERR_load_OBJ_strings := nil;
end;
  {$ENDIF}
{$ELSE}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
