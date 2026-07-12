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
{ *  Copyright (c) 2025 TaurusTLS Developers, All Rights Reserved              * }
{ *                                                                            * }
{ * Portions of this software are Copyright (c) 1993 – 2018,                   * }
{ * Chad Z. Hower (Kudzu) and the Indy Pit Crew – http://www.IndyProject.org/  * }
{ ****************************************************************************** }
unit TaurusTLSHeaders_crypto_decoder;

interface

uses
  IdCTypes,
  IdGlobal,
{$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
{$ENDIF}
  TaurusTLSHeaders_core,
  TaurusTLSHeaders_openssl_decoder,
  TaurusTLSHeaders_types;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

{ *
  * These are specially made for the 'file:' provider-native loader, which
  * uses this to install a DER to anything decoder, which doesn't do much
  * except read a DER blob and pass it on as a provider object abstraction
  * (provider-object(7)).
  * }
var
  {$EXTERNALSYM ossl_decoder_from_algorithm}
  ossl_decoder_from_algorithm: function(id: TIdC_INT; algodef: POSSL_ALGORITHM;
    prov: POSSL_PROVIDER): Pointer; cdecl = nil;

  {$EXTERNALSYM ossl_decoder_instance_new_forprov}
  ossl_decoder_instance_new_forprov: function(decoder: POSSL_DECODER;
    provctx: Pointer; input_structure: PIdAnsiChar) : POSSL_DECODER_INSTANCE;
    cdecl = nil;

  {$EXTERNALSYM ossl_decoder_instance_new}
  ossl_decoder_instance_new: function(decoder: POSSL_DECODER;
    decoderctx: Pointer): POSSL_DECODER_INSTANCE; cdecl = nil;
  {$EXTERNALSYM ossl_decoder_instance_free}
  ossl_decoder_instance_free: procedure(decoder_inst: POSSL_DECODER_INSTANCE);
    cdecl = nil;
  {$EXTERNALSYM ossl_decoder_ctx_get_harderr}
  ossl_decoder_ctx_get_harderr: function(ctx: POSSL_DECODER_CTX): TIdC_INT;
    cdecl = nil;
  {$EXTERNALSYM ossl_decoder_ctx_set_harderr}
  ossl_decoder_ctx_set_harderr: procedure(ctx: POSSL_DECODER_CTX); cdecl = nil;
  {$EXTERNALSYM ossl_decoder_instance_dup}
  ossl_decoder_instance_dup: function(src: POSSL_DECODER_INSTANCE)
    : POSSL_DECODER_INSTANCE; cdecl = nil;
  {$EXTERNALSYM ossl_decoder_ctx_add_decoder_inst}
  ossl_decoder_ctx_add_decoder_inst: function(ctx: POSSL_DECODER_CTX;
    di: POSSL_DECODER_INSTANCE): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM ossl_decoder_get_number}
  ossl_decoder_get_number: function(encoder: POSSL_DECODER): TIdC_INT;
    cdecl = nil;
  {$EXTERNALSYM ossl_decoder_store_cache_flush}
  ossl_decoder_store_cache_flush: function(libctx: POSSL_LIB_CTX): TIdC_INT;
    cdecl = nil;
  {$EXTERNALSYM ossl_decoder_store_remove_all_provided}
  ossl_decoder_store_remove_all_provided: function(prov: POSSL_PROVIDER)
    : TIdC_INT; cdecl = nil;

  {$EXTERNALSYM ossl_decoder_cache_new}
  ossl_decoder_cache_new: function(ctx: POSSL_LIB_CTX): Pointer;  cdecl = nil;
  {$EXTERNALSYM ossl_decoder_cache_free}
  ossl_decoder_cache_free: procedure(vcache: Pointer); cdecl = nil;
  {$EXTERNALSYM ossl_decoder_cache_flush}
  ossl_decoder_cache_flush: function(libctx: POSSL_LIB_CTX): TIdC_INT;
     cdecl = nil;
{$ELSE}
  {$EXTERNALSYM ossl_decoder_from_algorithm}
function ossl_decoder_from_algorithm(id: TIdC_INT; algodef: POSSL_ALGORITHM;
  prov: POSSL_PROVIDER): Pointer; cdecl; external CLibCrypto;

  {$EXTERNALSYM ossl_decoder_instance_new_forprov}
function ossl_decoder_instance_new_forprov(decoder: POSSL_DECODER;
  provctx: Pointer; input_structure: PIdAnsiChar): POSSL_DECODER_INSTANCE;
  cdecl; external CLibCrypto;

  {$EXTERNALSYM ossl_decoder_instance_new}
function ossl_decoder_instance_new(decoder: POSSL_DECODER; decoderctx: Pointer)
  : POSSL_DECODER_INSTANCE; cdecl; external CLibCrypto;
  {$EXTERNALSYM ossl_decoder_instance_free}
procedure ossl_decoder_instance_free(decoder_inst: POSSL_DECODER_INSTANCE);
  cdecl; external CLibCrypto;
  {$EXTERNALSYM ossl_decoder_ctx_get_harderr}
function ossl_decoder_ctx_get_harderr(ctx: POSSL_DECODER_CTX): TIdC_INT cdecl;
  external CLibCrypto;
  {$EXTERNALSYM ossl_decoder_ctx_set_harderr}
procedure ossl_decoder_ctx_set_harderr(ctx: POSSL_DECODER_CTX)cdecl;
  external CLibCrypto;
  {$EXTERNALSYM ossl_decoder_instance_dup}
function ossl_decoder_instance_dup(src: POSSL_DECODER_INSTANCE)
  : POSSL_DECODER_INSTANCE cdecl; external CLibCrypto;
  {$EXTERNALSYM ossl_decoder_ctx_add_decoder_inst}
function ossl_decoder_ctx_add_decoder_inst(ctx: POSSL_DECODER_CTX;
  di: POSSL_DECODER_INSTANCE): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM ossl_decoder_get_number}
function ossl_decoder_get_number(encoder: POSSL_DECODER): TIdC_INT cdecl;
  external CLibCrypto;
  {$EXTERNALSYM ossl_decoder_store_cache_flush}
function ossl_decoder_store_cache_flush(libctx: POSSL_LIB_CTX): TIdC_INT cdecl;
  external CLibCrypto;
  {$EXTERNALSYM ossl_decoder_store_remove_all_provided}
function ossl_decoder_store_remove_all_provided(prov: POSSL_PROVIDER)
  : TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM ossl_decoder_cache_new}
function ossl_decoder_cache_new(ctx: POSSL_LIB_CTX): Pointer cdecl;
  external CLibCrypto;
  {$EXTERNALSYM ossl_decoder_cache_free}
procedure ossl_decoder_cache_free(vcache: Pointer)cdecl; external CLibCrypto;
  {$EXTERNALSYM ossl_decoder_cache_flush}
function ossl_decoder_cache_flush(libctx: POSSL_LIB_CTX): TIdC_INT cdecl;
  external CLibCrypto;
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
   ossl_decoder_from_algorithm_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
   ossl_decoder_instance_new_forprov_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
   ossl_decoder_instance_new_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
   ossl_decoder_instance_free_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
   ossl_decoder_ctx_get_harderr_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
   ossl_decoder_ctx_set_harderr_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
   ossl_decoder_instance_dup_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
   ossl_decoder_ctx_add_decoder_inst_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
   ossl_decoder_get_number_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
   ossl_decoder_store_cache_flush_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
   ossl_decoder_store_remove_all_provided_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
   ossl_decoder_cache_new_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
   ossl_decoder_cache_free_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);
   ossl_decoder_cache_flush_introduced = (byte(3) shl 8 or byte(0))
    shl 8 or byte(0);

const
   ossl_decoder_from_algorithm_procname = 'ossl_decoder_from_algorithm';
   ossl_decoder_instance_new_forprov_procname = 'ossl_decoder_instance_new_forprov';
   ossl_decoder_instance_new_procname = 'ossl_decoder_instance_new';
   ossl_decoder_instance_free_procname = 'ossl_decoder_instance_free';
   ossl_decoder_ctx_get_harderr_procname = 'ossl_decoder_ctx_get_harderr';
   ossl_decoder_ctx_set_harderr_procname = 'ossl_decoder_ctx_set_harderr';
   ossl_decoder_instance_dup_procname = 'ossl_decoder_instance_dup';
   ossl_decoder_ctx_add_decoder_inst_procname = 'ossl_decoder_ctx_add_decoder_inst';
   ossl_decoder_get_number_procname = 'ossl_decoder_get_number';
   ossl_decoder_store_cache_flush_procname = 'ossl_decoder_store_cache_flush';
   ossl_decoder_store_remove_all_provided_procname = 'ossl_decoder_store_remove_all_provided';
   ossl_decoder_cache_new_procname = 'ossl_decoder_cache_new';
   ossl_decoder_cache_free_procname = 'ossl_decoder_cache_free';
   ossl_decoder_cache_flush_procname = 'ossl_decoder_cache_flush_procname';

   {$IFNDEF _FIXINSIGHT_}
{$I TaurusTLSNoRetValOff.inc}

function ERR_ossl_decoder_from_algorithm(id: TIdC_INT; algodef: POSSL_ALGORITHM;
  prov: POSSL_PROVIDER): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (ossl_decoder_from_algorithm_procname);
end;

function ERR_ossl_decoder_instance_new_forprov(decoder: POSSL_DECODER;
  provctx: Pointer; input_structure: PIdAnsiChar): POSSL_DECODER_INSTANCE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (ossl_decoder_instance_new_forprov_procname);
end;

function ERR_ossl_decoder_instance_new(decoder: POSSL_DECODER;
  decoderctx: Pointer): POSSL_DECODER_INSTANCE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (ossl_decoder_instance_new_procname);
end;

procedure ERR_ossl_decoder_instance_free(decoder_inst: POSSL_DECODER_INSTANCE); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (ossl_decoder_instance_free_procname);
end;

function ERR_ossl_decoder_ctx_get_harderr(ctx: POSSL_DECODER_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (ossl_decoder_ctx_get_harderr_procname);
end;

procedure ERR_ossl_decoder_ctx_set_harderr(ctx: POSSL_DECODER_CTX); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (ossl_decoder_ctx_set_harderr_procname);
end;

function ERR_ossl_decoder_instance_dup(src: POSSL_DECODER_INSTANCE)
  : POSSL_DECODER_INSTANCE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (ossl_decoder_instance_dup_procname);
end;

function ERR_ossl_decoder_ctx_add_decoder_inst(ctx: POSSL_DECODER_CTX;
  di: POSSL_DECODER_INSTANCE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (ossl_decoder_ctx_add_decoder_inst_procname);
end;

function ERR_ossl_decoder_get_number(encoder: POSSL_DECODER): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (ossl_decoder_get_number_procname);
end;

function ERR_ossl_decoder_store_cache_flush(libctx: POSSL_LIB_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (ossl_decoder_store_cache_flush_procname);
end;

function ERR_ossl_decoder_store_remove_all_provided(prov: POSSL_PROVIDER)
  : TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (ossl_decoder_store_remove_all_provided_procname);
end;

function ERR_ossl_decoder_cache_new(ctx: POSSL_LIB_CTX): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (ossl_decoder_cache_new_procname);
end;

procedure ERR_ossl_decoder_cache_free(vcache: Pointer); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (ossl_decoder_cache_free_procname);
end;

function ERR_ossl_decoder_cache_flush(libctx: POSSL_LIB_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException
    (ossl_decoder_cache_flush_procname);
end;

{$I TaurusTLSNoRetValOn.inc}
{$I TaurusTLSUnusedParamOff.inc}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: boolean;
begin
  ossl_decoder_from_algorithm := LoadLibFunction(ADllHandle,
    ossl_decoder_from_algorithm_procname);
  FuncLoadError := not assigned(ossl_decoder_from_algorithm);
  if FuncLoadError then
  begin
{$IF not defined(ossl_decoder_from_algorithm_allownil)}
    ossl_decoder_from_algorithm := ERR_ossl_decoder_from_algorithm;
{$IFEND}
{$IF declared(ossl_decoder_from_algorithm_introduced)}
    if LibVersion < ossl_decoder_from_algorithm_introduced then
    begin
{$IF declared(FC_ossl_decoder_from_algorithm)}
      ossl_decoder_from_algorithm := FC_ossl_decoder_from_algorithm;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(ossl_decoder_from_algorithm_removed)}
    if ossl_decoder_from_algorithm_removed <= LibVersion then
    begin
{$IF declared(_ossl_decoder_from_algorithm)}
      ossl_decoder_from_algorithm := _ossl_decoder_from_algorithm;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(ossl_decoder_from_algorithm_allownil)}
    if FuncLoadError then
      AFailed.Add('ossl_decoder_from_algorithm');
{$IFEND}
  end;

  ossl_decoder_instance_new_forprov := LoadLibFunction(ADllHandle,
    ossl_decoder_instance_new_forprov_procname);
  FuncLoadError := not assigned(ossl_decoder_instance_new_forprov);
  if FuncLoadError then
  begin
{$IF not defined(ossl_decoder_instance_new_forprov_allownil)}
    ossl_decoder_instance_new_forprov := ERR_ossl_decoder_instance_new_forprov;
{$IFEND}
{$IF declared(ossl_decoder_instance_new_forprov_introduced)}
    if LibVersion < ossl_decoder_instance_new_forprov_introduced then
    begin
{$IF declared(FC_ossl_decoder_instance_new_forprov)}
      ossl_decoder_instance_new_forprov := FC_ossl_decoder_instance_new_forprov;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(ossl_decoder_instance_new_forprov_removed)}
    if ossl_decoder_instance_new_forprov_removed <= LibVersion then
    begin
{$IF declared(_ossl_decoder_instance_new_forprov)}
      ossl_decoder_instance_new_forprov := _ossl_decoder_instance_new_forprov;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(ossl_decoder_instance_new_forprov_allownil)}
    if FuncLoadError then
      AFailed.Add('ossl_decoder_instance_new_forprov');
{$IFEND}
  end;

  ossl_decoder_instance_new := LoadLibFunction(ADllHandle,
    ossl_decoder_instance_new_procname);
  FuncLoadError := not assigned(ossl_decoder_instance_new);
  if FuncLoadError then
  begin
{$IF not defined(ossl_decoder_instance_new_allownil)}
    ossl_decoder_instance_new := ERR_ossl_decoder_instance_new;
{$IFEND}
{$IF declared(ossl_decoder_instance_new_introduced)}
    if LibVersion < ossl_decoder_instance_new_introduced then
    begin
{$IF declared(FC_ossl_decoder_instance_new)}
      ossl_decoder_instance_new := FC_ossl_decoder_instance_new;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(ossl_decoder_instance_new_removed)}
    if ossl_decoder_instance_new_removed <= LibVersion then
    begin
{$IF declared(_ossl_decoder_instance_new)}
      ossl_decoder_instance_new := _ossl_decoder_instance_new;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(ossl_decoder_instance_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ossl_decoder_instance_new');
{$IFEND}
  end;

  ossl_decoder_instance_free := LoadLibFunction(ADllHandle,
    ossl_decoder_instance_free_procname);
  FuncLoadError := not assigned(ossl_decoder_instance_free);
  if FuncLoadError then
  begin
{$IF not defined(ossl_decoder_instance_free_allownil)}
    ossl_decoder_instance_free := ERR_ossl_decoder_instance_free;
{$IFEND}
{$IF declared(ossl_decoder_instance_free_introduced)}
    if LibVersion < ossl_decoder_instance_free_introduced then
    begin
{$IF declared(FC_ossl_decoder_instance_free)}
      ossl_decoder_instance_free := FC_ossl_decoder_instance_free;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(ossl_decoder_instance_free_removed)}
    if ossl_decoder_instance_free_removed <= LibVersion then
    begin
{$IF declared(_ossl_decoder_instance_free)}
      ossl_decoder_instance_free := _ossl_decoder_instance_free;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(ossl_decoder_instance_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ossl_decoder_instance_free');
{$IFEND}
  end;

  ossl_decoder_ctx_get_harderr := LoadLibFunction(ADllHandle,
    ossl_decoder_ctx_get_harderr_procname);
  FuncLoadError := not assigned(ossl_decoder_ctx_get_harderr);
  if FuncLoadError then
  begin
{$IF not defined(ossl_decoder_ctx_get_harderr_allownil)}
    ossl_decoder_ctx_get_harderr := ERR_ossl_decoder_ctx_get_harderr;
{$IFEND}
{$IF declared(ossl_decoder_ctx_get_harderr_introduced)}
    if LibVersion < ossl_decoder_ctx_get_harderr_introduced then
    begin
{$IF declared(FC_ossl_decoder_ctx_get_harderr)}
      ossl_decoder_ctx_get_harderr := FC_ossl_decoder_ctx_get_harderr;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(ossl_decoder_ctx_get_harderr_removed)}
    if ossl_decoder_ctx_get_harderr_removed <= LibVersion then
    begin
{$IF declared(_ossl_decoder_ctx_get_harderr)}
      ossl_decoder_ctx_get_harderr := _ossl_decoder_ctx_get_harderr;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(ossl_decoder_ctx_get_harderr_allownil)}
    if FuncLoadError then
      AFailed.Add('ossl_decoder_ctx_get_harderr');
{$IFEND}
  end;

  ossl_decoder_ctx_set_harderr := LoadLibFunction(ADllHandle,
    ossl_decoder_ctx_set_harderr_procname);
  FuncLoadError := not assigned(ossl_decoder_ctx_set_harderr);
  if FuncLoadError then
  begin
{$IF not defined(ossl_decoder_ctx_set_harderr_allownil)}
    ossl_decoder_ctx_set_harderr := ERR_ossl_decoder_ctx_set_harderr;
{$IFEND}
{$IF declared(ossl_decoder_ctx_set_harderr_introduced)}
    if LibVersion < ossl_decoder_ctx_set_harderr_introduced then
    begin
{$IF declared(FC_ossl_decoder_ctx_set_harderr)}
      ossl_decoder_ctx_set_harderr := FC_ossl_decoder_ctx_set_harderr;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(ossl_decoder_ctx_set_harderr_removed)}
    if ossl_decoder_ctx_set_harderr_removed <= LibVersion then
    begin
{$IF declared(_ossl_decoder_ctx_set_harderr)}
      ossl_decoder_ctx_set_harderr := _ossl_decoder_ctx_set_harderr;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(ossl_decoder_ctx_set_harderr_allownil)}
    if FuncLoadError then
      AFailed.Add('ossl_decoder_ctx_set_harderr');
{$IFEND}
  end;

  ossl_decoder_instance_dup := LoadLibFunction(ADllHandle,
    ossl_decoder_instance_dup_procname);
  FuncLoadError := not assigned(ossl_decoder_instance_dup);
  if FuncLoadError then
  begin
{$IF not defined(ossl_decoder_instance_dup_allownil)}
    ossl_decoder_instance_dup := ERR_ossl_decoder_instance_dup;
{$IFEND}
{$IF declared(ossl_decoder_instance_dup_introduced)}
    if LibVersion < ossl_decoder_instance_dup_introduced then
    begin
{$IF declared(FC_ossl_decoder_instance_dup)}
      ossl_decoder_instance_dup := FC_ossl_decoder_instance_dup;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(ossl_decoder_instance_dup_removed)}
    if ossl_decoder_instance_dup_removed <= LibVersion then
    begin
{$IF declared(_ossl_decoder_instance_dup)}
      ossl_decoder_instance_dup := _ossl_decoder_instance_dup;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(ossl_decoder_instance_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('ossl_decoder_instance_dup');
{$IFEND}
  end;

  ossl_decoder_ctx_add_decoder_inst := LoadLibFunction(ADllHandle,
    ossl_decoder_ctx_add_decoder_inst_procname);
  FuncLoadError := not assigned(ossl_decoder_ctx_add_decoder_inst);
  if FuncLoadError then
  begin
{$IF not defined(ossl_decoder_ctx_add_decoder_inst_allownil)}
    ossl_decoder_ctx_add_decoder_inst := ERR_ossl_decoder_ctx_add_decoder_inst;
{$IFEND}
{$IF declared(ossl_decoder_ctx_add_decoder_inst_introduced)}
    if LibVersion < ossl_decoder_ctx_add_decoder_inst_introduced then
    begin
{$IF declared(FC_ossl_decoder_ctx_add_decoder_inst)}
      ossl_decoder_ctx_add_decoder_inst := FC_ossl_decoder_ctx_add_decoder_inst;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(ossl_decoder_ctx_add_decoder_inst_removed)}
    if ossl_decoder_ctx_add_decoder_inst_removed <= LibVersion then
    begin
{$IF declared(_ossl_decoder_ctx_add_decoder_inst)}
      ossl_decoder_ctx_add_decoder_inst := _ossl_decoder_ctx_add_decoder_inst;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(ossl_decoder_ctx_add_decoder_inst_allownil)}
    if FuncLoadError then
      AFailed.Add('ossl_decoder_ctx_add_decoder_inst');
{$IFEND}
  end;

  ossl_decoder_get_number := LoadLibFunction(ADllHandle,
    ossl_decoder_get_number_procname);
  FuncLoadError := not assigned(ossl_decoder_get_number);
  if FuncLoadError then
  begin
{$IF not defined(ossl_decoder_get_number_allownil)}
    ossl_decoder_get_number := ERR_ossl_decoder_get_number;
{$IFEND}
{$IF declared(ossl_decoder_get_number_introduced)}
    if LibVersion < ossl_decoder_get_number_introduced then
    begin
{$IF declared(FC_ossl_decoder_get_number)}
      ossl_decoder_get_number := FC_ossl_decoder_get_number;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(ossl_decoder_get_number_removed)}
    if ossl_decoder_get_number_removed <= LibVersion then
    begin
{$IF declared(_ossl_decoder_get_number)}
      ossl_decoder_get_number := _ossl_decoder_get_number;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(ossl_decoder_get_number_allownil)}
    if FuncLoadError then
      AFailed.Add('ossl_decoder_get_number');
{$IFEND}
  end;

  ossl_decoder_store_cache_flush := LoadLibFunction(ADllHandle,
    ossl_decoder_store_cache_flush_procname);
  FuncLoadError := not assigned(ossl_decoder_store_cache_flush);
  if FuncLoadError then
  begin
{$IF not defined(ossl_decoder_store_cache_flush_allownil)}
    ossl_decoder_store_cache_flush := ERR_ossl_decoder_store_cache_flush;
{$IFEND}
{$IF declared(ossl_decoder_store_cache_flush_introduced)}
    if LibVersion < ossl_decoder_store_cache_flush_introduced then
    begin
{$IF declared(FC_ossl_decoder_store_cache_flush)}
      ossl_decoder_store_cache_flush := FC_ossl_decoder_store_cache_flush;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(ossl_decoder_store_cache_flush_removed)}
    if ossl_decoder_store_cache_flush_removed <= LibVersion then
    begin
{$IF declared(_ossl_decoder_store_cache_flush)}
      ossl_decoder_store_cache_flush := _ossl_decoder_store_cache_flush;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(ossl_decoder_store_cache_flush_allownil)}
    if FuncLoadError then
      AFailed.Add('ossl_decoder_store_cache_flush');
{$IFEND}
  end;

  ossl_decoder_store_remove_all_provided := LoadLibFunction(ADllHandle,
    ossl_decoder_store_remove_all_provided_procname);
  FuncLoadError := not assigned(ossl_decoder_store_remove_all_provided);
  if FuncLoadError then
  begin
{$IF not defined(ossl_decoder_store_remove_all_provided_allownil)}
    ossl_decoder_store_remove_all_provided := ERR_ossl_decoder_store_remove_all_provided;
{$IFEND}
{$IF declared(ossl_decoder_store_remove_all_provided_introduced)}
    if LibVersion < ossl_decoder_store_remove_all_provided_introduced then
    begin
{$IF declared(FC_ossl_decoder_store_remove_all_provided)}
      ossl_decoder_store_remove_all_provided := FC_ossl_decoder_store_remove_all_provided;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(ossl_decoder_store_remove_all_provided_removed)}
    if ossl_decoder_store_remove_all_provided_removed <= LibVersion then
    begin
{$IF declared(_ossl_decoder_store_remove_all_provided)}
      ossl_decoder_store_remove_all_provided := _ossl_decoder_store_remove_all_provided;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(ossl_decoder_store_remove_all_provided_allownil)}
    if FuncLoadError then
      AFailed.Add('ossl_decoder_store_remove_all_provided');
{$IFEND}
  end;

  ossl_decoder_cache_new := LoadLibFunction(ADllHandle,
    ossl_decoder_cache_new_procname);
  FuncLoadError := not assigned(ossl_decoder_cache_new);
  if FuncLoadError then
  begin
{$IF not defined(ossl_decoder_cache_new_allownil)}
    ossl_decoder_cache_new := ERR_ossl_decoder_cache_new;
{$IFEND}
{$IF declared(ossl_decoder_cache_new_introduced)}
    if LibVersion < ossl_decoder_cache_new_introduced then
    begin
{$IF declared(FC_ossl_decoder_cache_new)}
      ossl_decoder_cache_new := FC_ossl_decoder_cache_new;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(ossl_decoder_cache_new_removed)}
    if ossl_decoder_cache_new_removed <= LibVersion then
    begin
{$IF declared(_ossl_decoder_cache_new)}
      ossl_decoder_cache_new := _ossl_decoder_cache_new;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(ossl_decoder_cache_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ossl_decoder_cache_new');
{$IFEND}
  end;

  ossl_decoder_cache_free := LoadLibFunction(ADllHandle,
    ossl_decoder_cache_free_procname);
  FuncLoadError := not assigned(ossl_decoder_cache_free);
  if FuncLoadError then
  begin
{$IF not defined(ossl_decoder_cache_free_allownil)}
    ossl_decoder_cache_free := ERR_ossl_decoder_cache_free;
{$IFEND}
{$IF declared(ossl_decoder_cache_free_introduced)}
    if LibVersion < ossl_decoder_cache_free_introduced then
    begin
{$IF declared(FC_ossl_decoder_cache_free)}
      ossl_decoder_cache_free := FC_ossl_decoder_cache_free;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(ossl_decoder_cache_free_removed)}
    if ossl_decoder_cache_free_removed <= LibVersion then
    begin
{$IF declared(_ossl_decoder_cache_free)}
      ossl_decoder_cache_free := _ossl_decoder_cache_free;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(ossl_decoder_cache_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ossl_decoder_cache_free');
{$IFEND}
  end;

  ossl_decoder_cache_flush := LoadLibFunction(ADllHandle,
    ossl_decoder_cache_flush_procname);
  FuncLoadError := not assigned(ossl_decoder_cache_flush);
  if FuncLoadError then
  begin
{$IF not defined(ossl_decoder_cache_flush_allownil)}
    ossl_decoder_cache_flush := ERR_ossl_decoder_cache_flush;
{$IFEND}
{$IF declared(ossl_decoder_cache_flush_introduced)}
    if LibVersion < ossl_decoder_cache_flush_introduced then
    begin
{$IF declared(FC_ossl_decoder_cache_flush)}
      ossl_decoder_cache_flush := FC_ossl_decoder_cache_flush;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF declared(ossl_decoder_cache_flush_removed)}
    if ossl_decoder_cache_flush_removed <= LibVersion then
    begin
{$IF declared(_ossl_decoder_cache_flush)}
      ossl_decoder_cache_flush := _ossl_decoder_cache_flush;
{$IFEND}
      FuncLoadError := false;
    end;
{$IFEND}
{$IF not defined(ossl_decoder_cache_flush_allownil)}
    if FuncLoadError then
      AFailed.Add('ossl_decoder_cache_flush');
{$IFEND}
  end;
end;

{$I TaurusTLSUnusedParamOn.inc}

procedure Unload;
begin
   ossl_decoder_from_algorithm := nil;
   ossl_decoder_instance_new_forprov := nil;
   ossl_decoder_instance_new := nil;
   ossl_decoder_instance_free := nil;
   ossl_decoder_ctx_get_harderr := nil;
   ossl_decoder_ctx_set_harderr := nil;
   ossl_decoder_instance_dup := nil;
   ossl_decoder_ctx_add_decoder_inst := nil;
   ossl_decoder_get_number := nil;
   ossl_decoder_store_cache_flush := nil;
   ossl_decoder_store_remove_all_provided := nil;
   ossl_decoder_cache_new := nil;
   ossl_decoder_cache_free := nil;
   ossl_decoder_cache_flush := nil;
end;
  {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization

Register_SSLLoader(Load, 'LibCrypto');
Register_SSLUnloader(Unload);
{$ENDIF}

end.
