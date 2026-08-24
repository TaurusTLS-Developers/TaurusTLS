/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_provider.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_provider.h2pas
     and this file regenerated. TaurusTLSHeaders_provider.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_provider;

interface

{
  Automatically converted by H2Pas 1.0.0 from provider.h
  The following command line parameters were used:
    provider.h
}

uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_core;

type
  {$EXTERNALSYM POSSL_ALGORITHM}
    POSSL_ALGORITHM  = ^OSSL_ALGORITHM;
  {$EXTERNALSYM POSSL_CALLBACK}
    POSSL_CALLBACK  = ^OSSL_CALLBACK;
  {$EXTERNALSYM POSSL_DISPATCH}
    POSSL_DISPATCH  = ^OSSL_DISPATCH;
  {$EXTERNALSYM POSSL_PARAM}
    POSSL_PARAM  = ^OSSL_PARAM;
  {$EXTERNALSYM POSSL_PROVIDER}
    POSSL_PROVIDER  = pointer;
  {$EXTERNALSYM POSSL_provider_init_fn}
    POSSL_provider_init_fn  = ^OSSL_provider_init_fn;

  {$EXTERNALSYM TDo_AllCallback}
    TDo_AllCallback = function (provider:POSSL_PROVIDER; cbdata:pointer):TIdC_LONG; cdecl;

{$IFDEF FPC}
{$PACKRECORDS C}
{$ENDIF}
  {
   * Copyright 2019-2023 The TaurusTLS Project Authors. All Rights Reserved.
   *
   * Licensed under the Apache License 2.0 (the "License").  You may not use
   * this file except in compliance with the License.  You can obtain a copy
   * in the file LICENSE in the source distribution or at
   * https://www.openssl.org/source/license.html
    }
  { Set and Get a library context search path  }
    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  
  {$IFDEF OPENSSL_3_2_ORLATER}
  {$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM OSSL_PROVIDER_set_default_search_path}
  OSSL_PROVIDER_set_default_search_path: function (ctx: POSSL_LIB_CTX; path: PIdAnsiChar): TIdC_INT; cdecl = nil; {introduced 3.0.0}
    { Load and unload a provider  }
  {$EXTERNALSYM OSSL_PROVIDER_load}
  OSSL_PROVIDER_load: function (_para1:POSSL_LIB_CTX; name: PIdAnsiChar):POSSL_PROVIDER; cdecl = nil; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_PROVIDER_try_load}
  OSSL_PROVIDER_try_load: function (_para1:POSSL_LIB_CTX; name: PIdAnsiChar; retain_fallbacks: TIdC_LONG):POSSL_PROVIDER; cdecl = nil; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_PROVIDER_unload}
  OSSL_PROVIDER_unload: function (prov:POSSL_PROVIDER):TIdC_LONG; cdecl = nil; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_PROVIDER_available}
  OSSL_PROVIDER_available: function (_para1:POSSL_LIB_CTX; name:PIdAnsiChar):TIdC_LONG; cdecl = nil; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_PROVIDER_do_all}
  OSSL_PROVIDER_do_all: function (ctx:POSSL_LIB_CTX; cb:TDo_AllCallback; cbdata:pointer):TIdC_LONG; cdecl = nil; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_PROVIDER_gettable_params}
  OSSL_PROVIDER_gettable_params: function (prov:POSSL_PROVIDER):POSSL_PARAM; cdecl = nil; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_PROVIDER_get_params}
  OSSL_PROVIDER_get_params: function (prov:POSSL_PROVIDER; params:POSSL_PARAM):TIdC_LONG; cdecl = nil; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_PROVIDER_self_test}
  OSSL_PROVIDER_self_test: function (prov:POSSL_PROVIDER):TIdC_LONG; cdecl = nil;{introduced 3.0.0}
  {$EXTERNALSYM OSSL_PROVIDER_get_capabilities}
  OSSL_PROVIDER_get_capabilities: function (prov:POSSL_PROVIDER; capability:PIdAnsiChar; cb:POSSL_CALLBACK; arg:pointer):TIdC_LONG; cdecl = nil;{introduced 3.0.0}
  {$EXTERNALSYM OSSL_PROVIDER_query_operation}
  OSSL_PROVIDER_query_operation: function (prov:POSSL_PROVIDER; operation_id:TIdC_LONG; no_cache:PIdC_LONG):POSSL_ALGORITHM; cdecl = nil; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_PROVIDER_unquery_operation}
  OSSL_PROVIDER_unquery_operation: procedure (prov:POSSL_PROVIDER; operation_id:TIdC_LONG; algs:POSSL_ALGORITHM); cdecl = nil; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_PROVIDER_get0_provider_ctx}
  OSSL_PROVIDER_get0_provider_ctx: function (prov:POSSL_PROVIDER):pointer; cdecl = nil; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_PROVIDER_get0_dispatch}
  OSSL_PROVIDER_get0_dispatch: function (prov:POSSL_PROVIDER):POSSL_DISPATCH; cdecl = nil; {introduced 3.0.0}
    { Add a built in providers  }
  {$EXTERNALSYM OSSL_PROVIDER_add_builtin}
  OSSL_PROVIDER_add_builtin: function (_para1:POSSL_LIB_CTX; name:PIdAnsiChar; init_fn:POSSL_provider_init_fn):TIdC_LONG; cdecl = nil; {introduced 3.0.0}

    { Information  }
  {$EXTERNALSYM OSSL_PROVIDER_get0_name}
  OSSL_PROVIDER_get0_name: function (prov:POSSL_PROVIDER):PIdAnsiChar; cdecl = nil; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_PROVIDER_get0_default_search_path}
  OSSL_PROVIDER_get0_default_search_path: function (libctx: POSSL_LIB_CTX): PIdAnsiChar; cdecl = nil; {introduced 3.2.0}
  {$EXTERNALSYM OSSL_PROVIDER_try_load_ex}
  OSSL_PROVIDER_try_load_ex: function (_para1:POSSL_LIB_CTX; name: PIdAnsiChar; params:POSSL_PARAM; retain_fallbacks:TIdC_LONG):POSSL_PROVIDER; cdecl = nil; {introduced 3.2.0}
  {$EXTERNALSYM OSSL_PROVIDER_load_ex}
  OSSL_PROVIDER_load_ex: function (_para1:POSSL_LIB_CTX; name: PIdAnsiChar; params: POSSL_PARAM):POSSL_PROVIDER; cdecl = nil; {introduced 3.2.0}

{$ELSE}
  {$EXTERNALSYM OSSL_PROVIDER_set_default_search_path}
  function OSSL_PROVIDER_set_default_search_path(ctx: POSSL_LIB_CTX; path: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto; {introduced 3.0.0}
    { Load and unload a provider  }
  {$EXTERNALSYM OSSL_PROVIDER_load}
  function OSSL_PROVIDER_load(_para1:POSSL_LIB_CTX; name: PIdAnsiChar):POSSL_PROVIDER cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_PROVIDER_try_load}
  function OSSL_PROVIDER_try_load(_para1:POSSL_LIB_CTX; name: PIdAnsiChar; retain_fallbacks: TIdC_LONG):POSSL_PROVIDER cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_PROVIDER_unload}
  function OSSL_PROVIDER_unload(prov:POSSL_PROVIDER):TIdC_LONG cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_PROVIDER_available}
  function OSSL_PROVIDER_available(_para1:POSSL_LIB_CTX; name:PIdAnsiChar):TIdC_LONG cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_PROVIDER_do_all}
  function OSSL_PROVIDER_do_all(ctx:POSSL_LIB_CTX; cb:TDo_AllCallback; cbdata:pointer):TIdC_LONG cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_PROVIDER_gettable_params}
  function OSSL_PROVIDER_gettable_params(prov:POSSL_PROVIDER):POSSL_PARAM cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_PROVIDER_get_params}
  function OSSL_PROVIDER_get_params(prov:POSSL_PROVIDER; params:POSSL_PARAM):TIdC_LONG cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_PROVIDER_self_test}
  function OSSL_PROVIDER_self_test(prov:POSSL_PROVIDER):TIdC_LONG cdecl; external CLibCrypto;{introduced 3.0.0}
  {$EXTERNALSYM OSSL_PROVIDER_get_capabilities}
  function OSSL_PROVIDER_get_capabilities(prov:POSSL_PROVIDER; capability:PIdAnsiChar; cb:POSSL_CALLBACK; arg:pointer):TIdC_LONG cdecl; external CLibCrypto;{introduced 3.0.0}
  {$EXTERNALSYM OSSL_PROVIDER_query_operation}
  function OSSL_PROVIDER_query_operation(prov:POSSL_PROVIDER; operation_id:TIdC_LONG; no_cache:PIdC_LONG):POSSL_ALGORITHM cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_PROVIDER_unquery_operation}
  procedure OSSL_PROVIDER_unquery_operation(prov:POSSL_PROVIDER; operation_id:TIdC_LONG; algs:POSSL_ALGORITHM) cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_PROVIDER_get0_provider_ctx}
  function OSSL_PROVIDER_get0_provider_ctx(prov:POSSL_PROVIDER):pointer cdecl; external CLibCrypto; {introduced 3.0.0}
  {$EXTERNALSYM OSSL_PROVIDER_get0_dispatch}
  function OSSL_PROVIDER_get0_dispatch(prov:POSSL_PROVIDER):POSSL_DISPATCH cdecl; external CLibCrypto; {introduced 3.0.0}
    { Add a built in providers  }
  {$EXTERNALSYM OSSL_PROVIDER_add_builtin}
  function OSSL_PROVIDER_add_builtin(_para1:POSSL_LIB_CTX; name:PIdAnsiChar; init_fn:POSSL_provider_init_fn):TIdC_LONG cdecl; external CLibCrypto; {introduced 3.0.0}

    { Information  }
  {$EXTERNALSYM OSSL_PROVIDER_get0_name}
  function OSSL_PROVIDER_get0_name(prov:POSSL_PROVIDER):PIdAnsiChar cdecl; external CLibCrypto; {introduced 3.0.0}
    {$IFDEF OPENSSL_3_2_ORLATER}
  {$EXTERNALSYM OSSL_PROVIDER_get0_default_search_path}
  function OSSL_PROVIDER_get0_default_search_path(libctx: POSSL_LIB_CTX): PIdAnsiChar cdecl; external CLibCrypto; {introduced 3.2.0}
  {$EXTERNALSYM OSSL_PROVIDER_try_load_ex}
  function OSSL_PROVIDER_try_load_ex(_para1:POSSL_LIB_CTX; name: PIdAnsiChar; params:POSSL_PARAM; retain_fallbacks:TIdC_LONG):POSSL_PROVIDER cdecl; external CLibCrypto; {introduced 3.2.0}
  {$EXTERNALSYM OSSL_PROVIDER_load_ex}
  function OSSL_PROVIDER_load_ex(_para1:POSSL_LIB_CTX; name: PIdAnsiChar; params: POSSL_PARAM):POSSL_PROVIDER cdecl; external CLibCrypto; {introduced 3.2.0}
    {$ENDIF}

{$ENDIF}

implementation

  uses
    classes, 
    TaurusTLSExceptionHandlers
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    ,TaurusTLSLoader
  {$ENDIF};
  
const
  OSSL_PROVIDER_set_default_search_path_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_PROVIDER_load_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_PROVIDER_try_load_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_PROVIDER_unload_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_PROVIDER_available_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_PROVIDER_do_all_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_PROVIDER_gettable_params_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_PROVIDER_get_params_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_PROVIDER_self_test_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_PROVIDER_get_capabilities_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_PROVIDER_query_operation_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_PROVIDER_unquery_operation_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_PROVIDER_get0_provider_ctx_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_PROVIDER_get0_dispatch_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_PROVIDER_add_builtin_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_PROVIDER_get0_name_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  OSSL_PROVIDER_get0_default_search_path_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  OSSL_PROVIDER_try_load_ex_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
  OSSL_PROVIDER_load_ex_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
const
  OSSL_PROVIDER_set_default_search_path_procname = 'OSSL_PROVIDER_set_default_search_path'; {introduced 3.0.0}
    { Load and unload a provider  }
  OSSL_PROVIDER_load_procname = 'OSSL_PROVIDER_load'; {introduced 3.0.0}
  OSSL_PROVIDER_try_load_procname = 'OSSL_PROVIDER_try_load'; {introduced 3.0.0}
  OSSL_PROVIDER_unload_procname = 'OSSL_PROVIDER_unload'; {introduced 3.0.0}
  OSSL_PROVIDER_available_procname = 'OSSL_PROVIDER_available'; {introduced 3.0.0}
  OSSL_PROVIDER_do_all_procname = 'OSSL_PROVIDER_do_all'; {introduced 3.0.0}
  OSSL_PROVIDER_gettable_params_procname = 'OSSL_PROVIDER_gettable_params'; {introduced 3.0.0}
  OSSL_PROVIDER_get_params_procname = 'OSSL_PROVIDER_get_params'; {introduced 3.0.0}
  OSSL_PROVIDER_self_test_procname = 'OSSL_PROVIDER_self_test';{introduced 3.0.0}
  OSSL_PROVIDER_get_capabilities_procname = 'OSSL_PROVIDER_get_capabilities';{introduced 3.0.0}
  OSSL_PROVIDER_query_operation_procname = 'OSSL_PROVIDER_query_operation'; {introduced 3.0.0}
  OSSL_PROVIDER_unquery_operation_procname = 'OSSL_PROVIDER_unquery_operation'; {introduced 3.0.0}
  OSSL_PROVIDER_get0_provider_ctx_procname = 'OSSL_PROVIDER_get0_provider_ctx'; {introduced 3.0.0}
  OSSL_PROVIDER_get0_dispatch_procname = 'OSSL_PROVIDER_get0_dispatch'; {introduced 3.0.0}
    { Add a built in providers  }
  OSSL_PROVIDER_add_builtin_procname = 'OSSL_PROVIDER_add_builtin'; {introduced 3.0.0}

    { Information  }
  OSSL_PROVIDER_get0_name_procname = 'OSSL_PROVIDER_get0_name'; {introduced 3.0.0}
  OSSL_PROVIDER_get0_default_search_path_procname = 'OSSL_PROVIDER_get0_default_search_path'; {introduced 3.2.0}
  OSSL_PROVIDER_try_load_ex_procname = 'OSSL_PROVIDER_try_load_ex'; {introduced 3.2.0}
  OSSL_PROVIDER_load_ex_procname = 'OSSL_PROVIDER_load_ex'; {introduced 3.2.0}

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_OSSL_PROVIDER_set_default_search_path(ctx: POSSL_LIB_CTX; path: PIdAnsiChar): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_set_default_search_path_procname);
end;

 {introduced 3.0.0}
    { Load and unload a provider  }
function  ERR_OSSL_PROVIDER_load(_para1:POSSL_LIB_CTX; name: PIdAnsiChar):POSSL_PROVIDER; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_load_procname);
end;

 {introduced 3.0.0}
function  ERR_OSSL_PROVIDER_try_load(_para1:POSSL_LIB_CTX; name: PIdAnsiChar;
  retain_fallbacks: TIdC_LONG):POSSL_PROVIDER; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_try_load_procname);
end;

 {introduced 3.0.0}
function  ERR_OSSL_PROVIDER_unload(prov:POSSL_PROVIDER):TIdC_LONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_unload_procname);
end;

 {introduced 3.0.0}
function  ERR_OSSL_PROVIDER_available(_para1:POSSL_LIB_CTX; name:PIdAnsiChar):TIdC_LONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_available_procname);
end;

 {introduced 3.0.0}
function  ERR_OSSL_PROVIDER_do_all(ctx:POSSL_LIB_CTX; cb:TDo_AllCallback; cbdata:pointer):TIdC_LONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_do_all_procname);
end;

 {introduced 3.0.0}
function  ERR_OSSL_PROVIDER_gettable_params(prov:POSSL_PROVIDER):POSSL_PARAM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_gettable_params_procname);
end;

 {introduced 3.0.0}
function  ERR_OSSL_PROVIDER_get_params(prov:POSSL_PROVIDER; params:POSSL_PARAM):TIdC_LONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_get_params_procname);
end;

 {introduced 3.0.0}
function  ERR_OSSL_PROVIDER_self_test(prov:POSSL_PROVIDER):TIdC_LONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_self_test_procname);
end;

{introduced 3.0.0}
function  ERR_OSSL_PROVIDER_get_capabilities(prov:POSSL_PROVIDER; capability:PIdAnsiChar;
  cb:POSSL_CALLBACK; arg:pointer):TIdC_LONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_get_capabilities_procname);
end;

{introduced 3.0.0}
function  ERR_OSSL_PROVIDER_query_operation(prov:POSSL_PROVIDER; operation_id:TIdC_LONG;
  no_cache:PIdC_LONG):POSSL_ALGORITHM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_query_operation_procname);
end;

 {introduced 3.0.0}
procedure  ERR_OSSL_PROVIDER_unquery_operation(prov:POSSL_PROVIDER; operation_id:TIdC_LONG;
  algs:POSSL_ALGORITHM); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_unquery_operation_procname);
end;

 {introduced 3.0.0}
function  ERR_OSSL_PROVIDER_get0_provider_ctx(prov:POSSL_PROVIDER):pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_get0_provider_ctx_procname);
end;

 {introduced 3.0.0}
function  ERR_OSSL_PROVIDER_get0_dispatch(prov:POSSL_PROVIDER):POSSL_DISPATCH; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_get0_dispatch_procname);
end;

 {introduced 3.0.0}
    { Add a built in providers  }
function  ERR_OSSL_PROVIDER_add_builtin(_para1:POSSL_LIB_CTX; name:PIdAnsiChar;
  init_fn:POSSL_provider_init_fn):TIdC_LONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_add_builtin_procname);
end;

 {introduced 3.0.0}

    { Information  }
function  ERR_OSSL_PROVIDER_get0_name(prov:POSSL_PROVIDER):PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_get0_name_procname);
end;

 {introduced 3.0.0}
function  ERR_OSSL_PROVIDER_get0_default_search_path(libctx: POSSL_LIB_CTX): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_get0_default_search_path_procname);
end;

 {introduced 3.2.0}
function  ERR_OSSL_PROVIDER_try_load_ex(_para1:POSSL_LIB_CTX; name: PIdAnsiChar; params:POSSL_PARAM;
  retain_fallbacks:TIdC_LONG):POSSL_PROVIDER; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_try_load_ex_procname);
end;

 {introduced 3.2.0}
function  ERR_OSSL_PROVIDER_load_ex(_para1:POSSL_LIB_CTX; name: PIdAnsiChar;
  params: POSSL_PARAM):POSSL_PROVIDER; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_load_ex_procname);
end;

 {introduced 3.2.0}

  {$I TaurusTLSNoRetValOn.inc}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  OSSL_PROVIDER_set_default_search_path := LoadLibFunction(ADllHandle, OSSL_PROVIDER_set_default_search_path_procname);
  FuncLoadError := not assigned(OSSL_PROVIDER_set_default_search_path);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PROVIDER_set_default_search_path_allownil)}
    OSSL_PROVIDER_set_default_search_path := ERR_OSSL_PROVIDER_set_default_search_path;
    {$ifend}
    {$if declared(OSSL_PROVIDER_set_default_search_path_introduced)}
    if LibVersion < OSSL_PROVIDER_set_default_search_path_introduced then
    begin
      {$if declared(FC_OSSL_PROVIDER_set_default_search_path)}
      OSSL_PROVIDER_set_default_search_path := FC_OSSL_PROVIDER_set_default_search_path;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PROVIDER_set_default_search_path_removed)}
    if OSSL_PROVIDER_set_default_search_path_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PROVIDER_set_default_search_path)}
      OSSL_PROVIDER_set_default_search_path := _OSSL_PROVIDER_set_default_search_path;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PROVIDER_set_default_search_path_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PROVIDER_set_default_search_path');
    {$ifend}
  end;

 {introduced 3.0.0}
  OSSL_PROVIDER_load := LoadLibFunction(ADllHandle, OSSL_PROVIDER_load_procname);
  FuncLoadError := not assigned(OSSL_PROVIDER_load);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PROVIDER_load_allownil)}
    OSSL_PROVIDER_load := ERR_OSSL_PROVIDER_load;
    {$ifend}
    {$if declared(OSSL_PROVIDER_load_introduced)}
    if LibVersion < OSSL_PROVIDER_load_introduced then
    begin
      {$if declared(FC_OSSL_PROVIDER_load)}
      OSSL_PROVIDER_load := FC_OSSL_PROVIDER_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PROVIDER_load_removed)}
    if OSSL_PROVIDER_load_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PROVIDER_load)}
      OSSL_PROVIDER_load := _OSSL_PROVIDER_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PROVIDER_load_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PROVIDER_load');
    {$ifend}
  end;

 {introduced 3.0.0}
  OSSL_PROVIDER_try_load := LoadLibFunction(ADllHandle, OSSL_PROVIDER_try_load_procname);
  FuncLoadError := not assigned(OSSL_PROVIDER_try_load);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PROVIDER_try_load_allownil)}
    OSSL_PROVIDER_try_load := ERR_OSSL_PROVIDER_try_load;
    {$ifend}
    {$if declared(OSSL_PROVIDER_try_load_introduced)}
    if LibVersion < OSSL_PROVIDER_try_load_introduced then
    begin
      {$if declared(FC_OSSL_PROVIDER_try_load)}
      OSSL_PROVIDER_try_load := FC_OSSL_PROVIDER_try_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PROVIDER_try_load_removed)}
    if OSSL_PROVIDER_try_load_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PROVIDER_try_load)}
      OSSL_PROVIDER_try_load := _OSSL_PROVIDER_try_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PROVIDER_try_load_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PROVIDER_try_load');
    {$ifend}
  end;

 {introduced 3.0.0}
  OSSL_PROVIDER_unload := LoadLibFunction(ADllHandle, OSSL_PROVIDER_unload_procname);
  FuncLoadError := not assigned(OSSL_PROVIDER_unload);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PROVIDER_unload_allownil)}
    OSSL_PROVIDER_unload := ERR_OSSL_PROVIDER_unload;
    {$ifend}
    {$if declared(OSSL_PROVIDER_unload_introduced)}
    if LibVersion < OSSL_PROVIDER_unload_introduced then
    begin
      {$if declared(FC_OSSL_PROVIDER_unload)}
      OSSL_PROVIDER_unload := FC_OSSL_PROVIDER_unload;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PROVIDER_unload_removed)}
    if OSSL_PROVIDER_unload_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PROVIDER_unload)}
      OSSL_PROVIDER_unload := _OSSL_PROVIDER_unload;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PROVIDER_unload_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PROVIDER_unload');
    {$ifend}
  end;

 {introduced 3.0.0}
  OSSL_PROVIDER_available := LoadLibFunction(ADllHandle, OSSL_PROVIDER_available_procname);
  FuncLoadError := not assigned(OSSL_PROVIDER_available);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PROVIDER_available_allownil)}
    OSSL_PROVIDER_available := ERR_OSSL_PROVIDER_available;
    {$ifend}
    {$if declared(OSSL_PROVIDER_available_introduced)}
    if LibVersion < OSSL_PROVIDER_available_introduced then
    begin
      {$if declared(FC_OSSL_PROVIDER_available)}
      OSSL_PROVIDER_available := FC_OSSL_PROVIDER_available;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PROVIDER_available_removed)}
    if OSSL_PROVIDER_available_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PROVIDER_available)}
      OSSL_PROVIDER_available := _OSSL_PROVIDER_available;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PROVIDER_available_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PROVIDER_available');
    {$ifend}
  end;

 {introduced 3.0.0}
  OSSL_PROVIDER_do_all := LoadLibFunction(ADllHandle, OSSL_PROVIDER_do_all_procname);
  FuncLoadError := not assigned(OSSL_PROVIDER_do_all);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PROVIDER_do_all_allownil)}
    OSSL_PROVIDER_do_all := ERR_OSSL_PROVIDER_do_all;
    {$ifend}
    {$if declared(OSSL_PROVIDER_do_all_introduced)}
    if LibVersion < OSSL_PROVIDER_do_all_introduced then
    begin
      {$if declared(FC_OSSL_PROVIDER_do_all)}
      OSSL_PROVIDER_do_all := FC_OSSL_PROVIDER_do_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PROVIDER_do_all_removed)}
    if OSSL_PROVIDER_do_all_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PROVIDER_do_all)}
      OSSL_PROVIDER_do_all := _OSSL_PROVIDER_do_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PROVIDER_do_all_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PROVIDER_do_all');
    {$ifend}
  end;

 {introduced 3.0.0}
  OSSL_PROVIDER_gettable_params := LoadLibFunction(ADllHandle, OSSL_PROVIDER_gettable_params_procname);
  FuncLoadError := not assigned(OSSL_PROVIDER_gettable_params);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PROVIDER_gettable_params_allownil)}
    OSSL_PROVIDER_gettable_params := ERR_OSSL_PROVIDER_gettable_params;
    {$ifend}
    {$if declared(OSSL_PROVIDER_gettable_params_introduced)}
    if LibVersion < OSSL_PROVIDER_gettable_params_introduced then
    begin
      {$if declared(FC_OSSL_PROVIDER_gettable_params)}
      OSSL_PROVIDER_gettable_params := FC_OSSL_PROVIDER_gettable_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PROVIDER_gettable_params_removed)}
    if OSSL_PROVIDER_gettable_params_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PROVIDER_gettable_params)}
      OSSL_PROVIDER_gettable_params := _OSSL_PROVIDER_gettable_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PROVIDER_gettable_params_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PROVIDER_gettable_params');
    {$ifend}
  end;

 {introduced 3.0.0}
  OSSL_PROVIDER_get_params := LoadLibFunction(ADllHandle, OSSL_PROVIDER_get_params_procname);
  FuncLoadError := not assigned(OSSL_PROVIDER_get_params);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PROVIDER_get_params_allownil)}
    OSSL_PROVIDER_get_params := ERR_OSSL_PROVIDER_get_params;
    {$ifend}
    {$if declared(OSSL_PROVIDER_get_params_introduced)}
    if LibVersion < OSSL_PROVIDER_get_params_introduced then
    begin
      {$if declared(FC_OSSL_PROVIDER_get_params)}
      OSSL_PROVIDER_get_params := FC_OSSL_PROVIDER_get_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PROVIDER_get_params_removed)}
    if OSSL_PROVIDER_get_params_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PROVIDER_get_params)}
      OSSL_PROVIDER_get_params := _OSSL_PROVIDER_get_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PROVIDER_get_params_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PROVIDER_get_params');
    {$ifend}
  end;

 {introduced 3.0.0}
  OSSL_PROVIDER_self_test := LoadLibFunction(ADllHandle, OSSL_PROVIDER_self_test_procname);
  FuncLoadError := not assigned(OSSL_PROVIDER_self_test);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PROVIDER_self_test_allownil)}
    OSSL_PROVIDER_self_test := ERR_OSSL_PROVIDER_self_test;
    {$ifend}
    {$if declared(OSSL_PROVIDER_self_test_introduced)}
    if LibVersion < OSSL_PROVIDER_self_test_introduced then
    begin
      {$if declared(FC_OSSL_PROVIDER_self_test)}
      OSSL_PROVIDER_self_test := FC_OSSL_PROVIDER_self_test;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PROVIDER_self_test_removed)}
    if OSSL_PROVIDER_self_test_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PROVIDER_self_test)}
      OSSL_PROVIDER_self_test := _OSSL_PROVIDER_self_test;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PROVIDER_self_test_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PROVIDER_self_test');
    {$ifend}
  end;

{introduced 3.0.0}
  OSSL_PROVIDER_get_capabilities := LoadLibFunction(ADllHandle, OSSL_PROVIDER_get_capabilities_procname);
  FuncLoadError := not assigned(OSSL_PROVIDER_get_capabilities);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PROVIDER_get_capabilities_allownil)}
    OSSL_PROVIDER_get_capabilities := ERR_OSSL_PROVIDER_get_capabilities;
    {$ifend}
    {$if declared(OSSL_PROVIDER_get_capabilities_introduced)}
    if LibVersion < OSSL_PROVIDER_get_capabilities_introduced then
    begin
      {$if declared(FC_OSSL_PROVIDER_get_capabilities)}
      OSSL_PROVIDER_get_capabilities := FC_OSSL_PROVIDER_get_capabilities;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PROVIDER_get_capabilities_removed)}
    if OSSL_PROVIDER_get_capabilities_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PROVIDER_get_capabilities)}
      OSSL_PROVIDER_get_capabilities := _OSSL_PROVIDER_get_capabilities;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PROVIDER_get_capabilities_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PROVIDER_get_capabilities');
    {$ifend}
  end;

{introduced 3.0.0}
  OSSL_PROVIDER_query_operation := LoadLibFunction(ADllHandle, OSSL_PROVIDER_query_operation_procname);
  FuncLoadError := not assigned(OSSL_PROVIDER_query_operation);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PROVIDER_query_operation_allownil)}
    OSSL_PROVIDER_query_operation := ERR_OSSL_PROVIDER_query_operation;
    {$ifend}
    {$if declared(OSSL_PROVIDER_query_operation_introduced)}
    if LibVersion < OSSL_PROVIDER_query_operation_introduced then
    begin
      {$if declared(FC_OSSL_PROVIDER_query_operation)}
      OSSL_PROVIDER_query_operation := FC_OSSL_PROVIDER_query_operation;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PROVIDER_query_operation_removed)}
    if OSSL_PROVIDER_query_operation_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PROVIDER_query_operation)}
      OSSL_PROVIDER_query_operation := _OSSL_PROVIDER_query_operation;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PROVIDER_query_operation_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PROVIDER_query_operation');
    {$ifend}
  end;

 {introduced 3.0.0}
  OSSL_PROVIDER_unquery_operation := LoadLibFunction(ADllHandle, OSSL_PROVIDER_unquery_operation_procname);
  FuncLoadError := not assigned(OSSL_PROVIDER_unquery_operation);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PROVIDER_unquery_operation_allownil)}
    OSSL_PROVIDER_unquery_operation := ERR_OSSL_PROVIDER_unquery_operation;
    {$ifend}
    {$if declared(OSSL_PROVIDER_unquery_operation_introduced)}
    if LibVersion < OSSL_PROVIDER_unquery_operation_introduced then
    begin
      {$if declared(FC_OSSL_PROVIDER_unquery_operation)}
      OSSL_PROVIDER_unquery_operation := FC_OSSL_PROVIDER_unquery_operation;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PROVIDER_unquery_operation_removed)}
    if OSSL_PROVIDER_unquery_operation_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PROVIDER_unquery_operation)}
      OSSL_PROVIDER_unquery_operation := _OSSL_PROVIDER_unquery_operation;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PROVIDER_unquery_operation_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PROVIDER_unquery_operation');
    {$ifend}
  end;

 {introduced 3.0.0}
  OSSL_PROVIDER_get0_provider_ctx := LoadLibFunction(ADllHandle, OSSL_PROVIDER_get0_provider_ctx_procname);
  FuncLoadError := not assigned(OSSL_PROVIDER_get0_provider_ctx);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PROVIDER_get0_provider_ctx_allownil)}
    OSSL_PROVIDER_get0_provider_ctx := ERR_OSSL_PROVIDER_get0_provider_ctx;
    {$ifend}
    {$if declared(OSSL_PROVIDER_get0_provider_ctx_introduced)}
    if LibVersion < OSSL_PROVIDER_get0_provider_ctx_introduced then
    begin
      {$if declared(FC_OSSL_PROVIDER_get0_provider_ctx)}
      OSSL_PROVIDER_get0_provider_ctx := FC_OSSL_PROVIDER_get0_provider_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PROVIDER_get0_provider_ctx_removed)}
    if OSSL_PROVIDER_get0_provider_ctx_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PROVIDER_get0_provider_ctx)}
      OSSL_PROVIDER_get0_provider_ctx := _OSSL_PROVIDER_get0_provider_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PROVIDER_get0_provider_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PROVIDER_get0_provider_ctx');
    {$ifend}
  end;

 {introduced 3.0.0}
  OSSL_PROVIDER_get0_dispatch := LoadLibFunction(ADllHandle, OSSL_PROVIDER_get0_dispatch_procname);
  FuncLoadError := not assigned(OSSL_PROVIDER_get0_dispatch);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PROVIDER_get0_dispatch_allownil)}
    OSSL_PROVIDER_get0_dispatch := ERR_OSSL_PROVIDER_get0_dispatch;
    {$ifend}
    {$if declared(OSSL_PROVIDER_get0_dispatch_introduced)}
    if LibVersion < OSSL_PROVIDER_get0_dispatch_introduced then
    begin
      {$if declared(FC_OSSL_PROVIDER_get0_dispatch)}
      OSSL_PROVIDER_get0_dispatch := FC_OSSL_PROVIDER_get0_dispatch;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PROVIDER_get0_dispatch_removed)}
    if OSSL_PROVIDER_get0_dispatch_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PROVIDER_get0_dispatch)}
      OSSL_PROVIDER_get0_dispatch := _OSSL_PROVIDER_get0_dispatch;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PROVIDER_get0_dispatch_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PROVIDER_get0_dispatch');
    {$ifend}
  end;

 {introduced 3.0.0}
  OSSL_PROVIDER_add_builtin := LoadLibFunction(ADllHandle, OSSL_PROVIDER_add_builtin_procname);
  FuncLoadError := not assigned(OSSL_PROVIDER_add_builtin);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PROVIDER_add_builtin_allownil)}
    OSSL_PROVIDER_add_builtin := ERR_OSSL_PROVIDER_add_builtin;
    {$ifend}
    {$if declared(OSSL_PROVIDER_add_builtin_introduced)}
    if LibVersion < OSSL_PROVIDER_add_builtin_introduced then
    begin
      {$if declared(FC_OSSL_PROVIDER_add_builtin)}
      OSSL_PROVIDER_add_builtin := FC_OSSL_PROVIDER_add_builtin;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PROVIDER_add_builtin_removed)}
    if OSSL_PROVIDER_add_builtin_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PROVIDER_add_builtin)}
      OSSL_PROVIDER_add_builtin := _OSSL_PROVIDER_add_builtin;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PROVIDER_add_builtin_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PROVIDER_add_builtin');
    {$ifend}
  end;

 {introduced 3.0.0}
  OSSL_PROVIDER_get0_name := LoadLibFunction(ADllHandle, OSSL_PROVIDER_get0_name_procname);
  FuncLoadError := not assigned(OSSL_PROVIDER_get0_name);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PROVIDER_get0_name_allownil)}
    OSSL_PROVIDER_get0_name := ERR_OSSL_PROVIDER_get0_name;
    {$ifend}
    {$if declared(OSSL_PROVIDER_get0_name_introduced)}
    if LibVersion < OSSL_PROVIDER_get0_name_introduced then
    begin
      {$if declared(FC_OSSL_PROVIDER_get0_name)}
      OSSL_PROVIDER_get0_name := FC_OSSL_PROVIDER_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PROVIDER_get0_name_removed)}
    if OSSL_PROVIDER_get0_name_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PROVIDER_get0_name)}
      OSSL_PROVIDER_get0_name := _OSSL_PROVIDER_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PROVIDER_get0_name_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PROVIDER_get0_name');
    {$ifend}
  end;

 {introduced 3.0.0}
  OSSL_PROVIDER_get0_default_search_path := LoadLibFunction(ADllHandle, OSSL_PROVIDER_get0_default_search_path_procname);
  FuncLoadError := not assigned(OSSL_PROVIDER_get0_default_search_path);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PROVIDER_get0_default_search_path_allownil)}
    OSSL_PROVIDER_get0_default_search_path := ERR_OSSL_PROVIDER_get0_default_search_path;
    {$ifend}
    {$if declared(OSSL_PROVIDER_get0_default_search_path_introduced)}
    if LibVersion < OSSL_PROVIDER_get0_default_search_path_introduced then
    begin
      {$if declared(FC_OSSL_PROVIDER_get0_default_search_path)}
      OSSL_PROVIDER_get0_default_search_path := FC_OSSL_PROVIDER_get0_default_search_path;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PROVIDER_get0_default_search_path_removed)}
    if OSSL_PROVIDER_get0_default_search_path_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PROVIDER_get0_default_search_path)}
      OSSL_PROVIDER_get0_default_search_path := _OSSL_PROVIDER_get0_default_search_path;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PROVIDER_get0_default_search_path_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PROVIDER_get0_default_search_path');
    {$ifend}
  end;

 {introduced 3.2.0}
  OSSL_PROVIDER_try_load_ex := LoadLibFunction(ADllHandle, OSSL_PROVIDER_try_load_ex_procname);
  FuncLoadError := not assigned(OSSL_PROVIDER_try_load_ex);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PROVIDER_try_load_ex_allownil)}
    OSSL_PROVIDER_try_load_ex := ERR_OSSL_PROVIDER_try_load_ex;
    {$ifend}
    {$if declared(OSSL_PROVIDER_try_load_ex_introduced)}
    if LibVersion < OSSL_PROVIDER_try_load_ex_introduced then
    begin
      {$if declared(FC_OSSL_PROVIDER_try_load_ex)}
      OSSL_PROVIDER_try_load_ex := FC_OSSL_PROVIDER_try_load_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PROVIDER_try_load_ex_removed)}
    if OSSL_PROVIDER_try_load_ex_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PROVIDER_try_load_ex)}
      OSSL_PROVIDER_try_load_ex := _OSSL_PROVIDER_try_load_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PROVIDER_try_load_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PROVIDER_try_load_ex');
    {$ifend}
  end;

 {introduced 3.2.0}
  OSSL_PROVIDER_load_ex := LoadLibFunction(ADllHandle, OSSL_PROVIDER_load_ex_procname);
  FuncLoadError := not assigned(OSSL_PROVIDER_load_ex);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PROVIDER_load_ex_allownil)}
    OSSL_PROVIDER_load_ex := ERR_OSSL_PROVIDER_load_ex;
    {$ifend}
    {$if declared(OSSL_PROVIDER_load_ex_introduced)}
    if LibVersion < OSSL_PROVIDER_load_ex_introduced then
    begin
      {$if declared(FC_OSSL_PROVIDER_load_ex)}
      OSSL_PROVIDER_load_ex := FC_OSSL_PROVIDER_load_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PROVIDER_load_ex_removed)}
    if OSSL_PROVIDER_load_ex_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PROVIDER_load_ex)}
      OSSL_PROVIDER_load_ex := _OSSL_PROVIDER_load_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PROVIDER_load_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PROVIDER_load_ex');
    {$ifend}
  end;

 {introduced 3.2.0}
end;

procedure Unload;
begin
  OSSL_PROVIDER_set_default_search_path := nil; {introduced 3.0.0}
  OSSL_PROVIDER_load := nil; {introduced 3.0.0}
  OSSL_PROVIDER_try_load := nil; {introduced 3.0.0}
  OSSL_PROVIDER_unload := nil; {introduced 3.0.0}
  OSSL_PROVIDER_available := nil; {introduced 3.0.0}
  OSSL_PROVIDER_do_all := nil; {introduced 3.0.0}
  OSSL_PROVIDER_gettable_params := nil; {introduced 3.0.0}
  OSSL_PROVIDER_get_params := nil; {introduced 3.0.0}
  OSSL_PROVIDER_self_test := nil;{introduced 3.0.0}
  OSSL_PROVIDER_get_capabilities := nil;{introduced 3.0.0}
  OSSL_PROVIDER_query_operation := nil; {introduced 3.0.0}
  OSSL_PROVIDER_unquery_operation := nil; {introduced 3.0.0}
  OSSL_PROVIDER_get0_provider_ctx := nil; {introduced 3.0.0}
  OSSL_PROVIDER_get0_dispatch := nil; {introduced 3.0.0}
  OSSL_PROVIDER_add_builtin := nil; {introduced 3.0.0}
  OSSL_PROVIDER_get0_name := nil; {introduced 3.0.0}
  OSSL_PROVIDER_get0_default_search_path := nil; {introduced 3.2.0}
  OSSL_PROVIDER_try_load_ex := nil; {introduced 3.2.0}
  OSSL_PROVIDER_load_ex := nil; {introduced 3.2.0}
end;
  {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
