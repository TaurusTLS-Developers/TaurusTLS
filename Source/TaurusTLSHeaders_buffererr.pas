/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_buffererr.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_buffererr.h2pas
     and this file regenerated. TaurusTLSHeaders_buffererr.h2pas is distributed with the full Indy
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

unit TaurusTLSHeaders_buffererr;

interface

// Headers for OpenSSL 1.1.1
// buffererr.h


uses
  IdCTypes,
  IdGlobal
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  , TaurusTLSConsts
  {$ENDIF};

const
// BUF function codes.
  {$EXTERNALSYM BUF_F_BUF_MEM_GROW}
  BUF_F_BUF_MEM_GROW = 100;
  {$EXTERNALSYM BUF_F_BUF_MEM_GROW_CLEAN}
  BUF_F_BUF_MEM_GROW_CLEAN = 105;
  {$EXTERNALSYM BUF_F_BUF_MEM_NEW}
  BUF_F_BUF_MEM_NEW = 101;

// BUF reason codes.

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM ERR_load_BUF_strings}
  ERR_load_BUF_strings: function : TIdC_INT; cdecl = nil;

{$ELSE}
  {$EXTERNALSYM ERR_load_BUF_strings}
  function ERR_load_BUF_strings: TIdC_INT cdecl; external CLibCrypto;

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
  ERR_load_BUF_strings_procname = 'ERR_load_BUF_strings';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_ERR_load_BUF_strings: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ERR_load_BUF_strings_procname);
end;



  {$I TaurusTLSNoRetValOn.inc} 
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  ERR_load_BUF_strings := LoadLibFunction(ADllHandle, ERR_load_BUF_strings_procname);
  FuncLoadError := not assigned(ERR_load_BUF_strings);
  if FuncLoadError then
  begin
    {$if not defined(ERR_load_BUF_strings_allownil)}
    ERR_load_BUF_strings := ERR_ERR_load_BUF_strings;
    {$ifend}
    {$if declared(ERR_load_BUF_strings_introduced)}
    if LibVersion < ERR_load_BUF_strings_introduced then
    begin
      {$if declared(FC_ERR_load_BUF_strings)}
      ERR_load_BUF_strings := FC_ERR_load_BUF_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ERR_load_BUF_strings_removed)}
    if ERR_load_BUF_strings_removed <= LibVersion then
    begin
      {$if declared(_ERR_load_BUF_strings)}
      ERR_load_BUF_strings := _ERR_load_BUF_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ERR_load_BUF_strings_allownil)}
    if FuncLoadError then
      AFailed.Add('ERR_load_BUF_strings');
    {$ifend}
  end;
end;
  {$I TaurusTLSUnusedParamOn.inc}

procedure Unload;
begin
  ERR_load_BUF_strings := nil;
end;
  {$ENDIF}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
