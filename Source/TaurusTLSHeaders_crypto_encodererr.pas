/// <exclude />
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

unit TaurusTLSHeaders_crypto_encodererr;

interface
uses
  IdCTypes,
  IdGlobal
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  , TaurusTLSConsts
  {$ENDIF};

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM ossl_err_load_OSSL_ENCODER_strings}
  ossl_err_load_OSSL_ENCODER_strings: function : TIdC_INT; cdecl = nil;

{$ELSE}

  {$EXTERNALSYM ossl_err_load_OSSL_ENCODER_strings}
  function ossl_err_load_OSSL_ENCODER_strings: TIdC_INT cdecl; external CLibCrypto;
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
  ossl_err_load_OSSL_ENCODER_strings_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

const
  ossl_err_load_OSSL_ENCODER_strings_procname = 'ossl_err_load_OSSL_ENCODER_strings';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc}
function  ERR_ossl_err_load_OSSL_ENCODER_strings: TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ossl_err_load_OSSL_ENCODER_strings_procname);
end;



  {$I TaurusTLSNoRetValOn.inc}
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  ossl_err_load_OSSL_ENCODER_strings := LoadLibFunction(ADllHandle, ossl_err_load_OSSL_ENCODER_strings_procname);
  FuncLoadError := not assigned(ossl_err_load_OSSL_ENCODER_strings);
  if FuncLoadError then
  begin
    {$if not defined(ossl_err_load_OSSL_ENCODER_strings_allownil)}
    ossl_err_load_OSSL_ENCODER_strings := ERR_ossl_err_load_OSSL_ENCODER_strings;
    {$ifend}
    {$if declared(ossl_err_load_OSSL_ENCODER_strings_introduced)}
    if LibVersion < ossl_err_load_OSSL_ENCODER_strings_introduced then
    begin
      {$if declared(FC_ossl_err_load_OSSL_ENCODER_strings)}
      ossl_err_load_OSSL_ENCODER_strings := FC_ossl_err_load_OSSL_ENCODER_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ossl_err_load_OSSL_ENCODER_strings_removed)}
    if ossl_err_load_OSSL_ENCODER_strings_removed <= LibVersion then
    begin
      {$if declared(_ossl_err_load_OSSL_ENCODER_strings)}
      ossl_err_load_OSSL_ENCODER_strings := _ossl_err_load_OSSL_ENCODER_strings;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ossl_err_load_OSSL_ENCODER_strings_allownil)}
    if FuncLoadError then
      AFailed.Add('ossl_err_load_OSSL_ENCODER_strings');
    {$ifend}
  end;
end;

  {$I TaurusTLSUnusedParamOn.inc}
procedure Unload;
begin
  ossl_err_load_OSSL_ENCODER_strings := nil;
end;
  {$ENDIF}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
