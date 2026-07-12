/// <exclude />
(* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_asyncerr.h2pas
  It should not be modified directly. All changes should be made to TaurusTLSHeaders_asyncerr.h2pas
  and this file regenerated. TaurusTLSHeaders_asyncerr.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_crypto_encoder;

interface

uses
  IdCTypes,
  IdGlobal,
{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
{$ENDIF}
  TaurusTLSHeaders_types;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM ossl_encoder_get_number}
  ossl_encoder_get_number : function(encoder : POSSL_ENCODER) : TIdC_INT;
    cdecl = nil;
  {$EXTERNALSYM ossl_encoder_store_cache_flush}
  ossl_encoder_store_cache_flush : function(libctx : POSSL_LIB_CTX) : TIdC_INT;
    cdecl = nil;
  {$EXTERNALSYM ossl_encoder_store_remove_all_provided}
  ossl_encoder_store_remove_all_provided : function(prov : POSSL_PROVIDER) :
    TIdC_INT; cdecl = nil;
{$ELSE}
  {$EXTERNALSYM ossl_encoder_get_number}
  function ossl_encoder_get_number(encoder : POSSL_ENCODER) : TIdC_INT;
     cdecl external CLibCrypto;
  {$EXTERNALSYM ossl_encoder_store_cache_flush}
  function ossl_encoder_store_cache_flush(libctx : POSSL_LIB_CTX) : TIdC_INT;
     cdecl external CLibCrypto;
  {$EXTERNALSYM ossl_encoder_store_remove_all_provided}
  function ossl_encoder_store_remove_all_provided (prov : POSSL_PROVIDER) :
    TIdC_INT  cdecl; external CLibCrypto;
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
  ossl_encoder_get_number_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  ossl_encoder_store_cache_flush_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  ossl_encoder_store_remove_all_provided_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

const
  ossl_encoder_get_number_procname = 'ossl_encoder_get_number';
  ossl_encoder_store_cache_flush_procname = 'ossl_encoder_store_cache_flush';
  ossl_encoder_store_remove_all_provided_procname =
    'ossl_encoder_store_remove_all_provided';

  {$IFNDEF _FIXINSIGHT_}
{$I TaurusTLSNoRetValOff.inc}
function ERR_ossl_encoder_get_number(encoder : POSSL_ENCODER) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (ossl_encoder_get_number_procname);
end;

function ERR_ossl_encoder_store_cache_flush(libctx : POSSL_LIB_CTX) : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (ossl_encoder_store_cache_flush_procname);
end;

function ERR_ossl_encoder_store_remove_all_provided (prov : POSSL_PROVIDER) :
  TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (ossl_encoder_store_remove_all_provided_procname);
end;

{$I TaurusTLSNoRetValOn.inc}
{$I TaurusTLSUnusedParamOff.inc}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);

var
  FuncLoadError: boolean;

begin
  ossl_encoder_get_number := LoadLibFunction(ADllHandle,
    ossl_encoder_get_number_procname);
  FuncLoadError := not assigned(ossl_encoder_get_number);
  if FuncLoadError then
  begin
{$IF not defined(ossl_encoder_get_number_allownil)}
    ossl_encoder_get_number := ERR_ossl_encoder_get_number;
{$IFEND}
{$IF declared(ossl_encoder_get_number_introduced)}
    if LibVersion < ossl_encoder_get_number_introduced then
    begin
{$IF declared(FC_ossl_encoder_get_number)}
      ossl_encoder_get_number := FC_ossl_encoder_get_number;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(ossl_encoder_get_number_removed)}
    if ossl_encoder_get_number_removed <= LibVersion then
    begin
{$IF declared(_ossl_encoder_get_number)}
      ossl_encoder_get_number := _ossl_encoder_get_number;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(ossl_encoder_get_number_allownil)}
    if FuncLoadError then
      AFailed.Add('ossl_encoder_get_number');
{$IFEND}
  end;

  ossl_encoder_store_cache_flush := LoadLibFunction(ADllHandle,
    ossl_encoder_store_cache_flush_procname);
  FuncLoadError := not assigned(ossl_encoder_store_cache_flush);
  if FuncLoadError then
  begin
{$IF not defined(ossl_encoder_store_cache_flush_allownil)}
    ossl_encoder_store_cache_flush := ERR_ossl_encoder_store_cache_flush;
{$IFEND}
{$IF declared(ossl_encoder_store_cache_flush_introduced)}
    if LibVersion < ossl_encoder_store_cache_flush_introduced then
    begin
{$IF declared(FC_ossl_encoder_store_cache_flush)}
      ossl_encoder_store_cache_flush := FC_ossl_encoder_store_cache_flush;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(ossl_encoder_store_cache_flush_removed)}
    if ossl_encoder_store_cache_flush_removed <= LibVersion then
    begin
{$IF declared(_ossl_encoder_store_cache_flush)}
      ossl_encoder_store_cache_flush := _ossl_encoder_store_cache_flush;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(ossl_encoder_store_cache_flush_allownil)}
    if FuncLoadError then
      AFailed.Add('ossl_encoder_store_cache_flush');
{$IFEND}
  end;

  ossl_encoder_store_remove_all_provided := LoadLibFunction(ADllHandle, ossl_encoder_store_remove_all_provided_procname);
  FuncLoadError := not assigned(ossl_encoder_store_remove_all_provided);
  if FuncLoadError then
  begin
{$IF not defined(ossl_encoder_store_remove_all_provided_allownil)}
    ossl_encoder_store_remove_all_provided := ERR_ossl_encoder_store_remove_all_provided;
{$IFEND}
{$IF declared(ossl_encoder_store_remove_all_provided_introduced)}
    if LibVersion < ossl_encoder_store_remove_all_provided_introduced then
    begin
{$IF declared(FC_ossl_encoder_store_remove_all_provided)}
      ossl_encoder_store_remove_all_provided := FC_ossl_encoder_store_remove_all_provided;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(ossl_encoder_store_remove_all_provided_removed)}
    if ossl_encoder_store_remove_all_provided_removed <= LibVersion then
    begin
{$IF declared(_ossl_encoder_store_remove_all_provided)}
      ossl_encoder_store_remove_all_provided := _ossl_encoder_store_remove_all_provided;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(ossl_encoder_store_remove_all_provided_allownil)}
    if FuncLoadError then
      AFailed.Add('ossl_encoder_store_remove_all_provided');
{$IFEND}
  end;

end;

{$I TaurusTLSUnusedParamOn.inc}

procedure Unload;
begin
  ossl_encoder_get_number := nil;
  ossl_encoder_store_cache_flush := nil;
  ossl_encoder_store_remove_all_provided := nil;
end;
  {$ENDIF}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization

Register_SSLLoader(Load, 'LibCrypto');
Register_SSLUnloader(Unload);
{$ENDIF}

end.
