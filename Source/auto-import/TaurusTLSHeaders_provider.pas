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
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // OSSL_PROVIDER_do_all_cb_cb = function(provider: POSSL_PROVIDER; cbdata: Pointer): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // OSSL_PROVIDER_get_capabilities_cb_cb = function(arg1: Possl_param_st; arg2: Pointer): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // OSSL_PROVIDER_add_builtin_init_fn_cb = function(arg1: Possl_core_handle_st; arg2: Possl_dispatch_st; arg3: PPossl_dispatch_st; arg4: PPointer): TIdC_INT; cdecl;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  OSSL_PROVIDER_set_default_search_path: function(arg1: POSSL_LIB_CTX; path: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PROVIDER_set_default_search_path}

  OSSL_PROVIDER_get0_default_search_path: function(libctx: POSSL_LIB_CTX): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_PROVIDER_get0_default_search_path}

  OSSL_PROVIDER_load: function(arg1: POSSL_LIB_CTX; name: PIdAnsiChar): POSSL_PROVIDER; cdecl = nil;
  {$EXTERNALSYM OSSL_PROVIDER_load}

  OSSL_PROVIDER_load_ex: function(arg1: POSSL_LIB_CTX; name: PIdAnsiChar; params: POSSL_PARAM): POSSL_PROVIDER; cdecl = nil;
  {$EXTERNALSYM OSSL_PROVIDER_load_ex}

  OSSL_PROVIDER_try_load: function(arg1: POSSL_LIB_CTX; name: PIdAnsiChar; retain_fallbacks: TIdC_INT): POSSL_PROVIDER; cdecl = nil;
  {$EXTERNALSYM OSSL_PROVIDER_try_load}

  OSSL_PROVIDER_try_load_ex: function(arg1: POSSL_LIB_CTX; name: PIdAnsiChar; params: POSSL_PARAM; retain_fallbacks: TIdC_INT): POSSL_PROVIDER; cdecl = nil;
  {$EXTERNALSYM OSSL_PROVIDER_try_load_ex}

  OSSL_PROVIDER_unload: function(prov: POSSL_PROVIDER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PROVIDER_unload}

  OSSL_PROVIDER_available: function(arg1: POSSL_LIB_CTX; name: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PROVIDER_available}

  OSSL_PROVIDER_do_all: function(ctx: POSSL_LIB_CTX; cb: TOSSL_PROVIDER_do_all_cb_cb; cbdata: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PROVIDER_do_all}

  OSSL_PROVIDER_gettable_params: function(prov: POSSL_PROVIDER): POSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_PROVIDER_gettable_params}

  OSSL_PROVIDER_get_params: function(prov: POSSL_PROVIDER; params: POSSL_PARAM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PROVIDER_get_params}

  OSSL_PROVIDER_self_test: function(prov: POSSL_PROVIDER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PROVIDER_self_test}

  OSSL_PROVIDER_get_capabilities: function(prov: POSSL_PROVIDER; capability: PIdAnsiChar; cb: TOSSL_PROVIDER_get_capabilities_cb_cb; arg: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PROVIDER_get_capabilities}

  OSSL_PROVIDER_add_conf_parameter: function(prov: POSSL_PROVIDER; name: PIdAnsiChar; value: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PROVIDER_add_conf_parameter}

  OSSL_PROVIDER_get_conf_parameters: function(prov: POSSL_PROVIDER; params: POSSL_PARAM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PROVIDER_get_conf_parameters}

  OSSL_PROVIDER_conf_get_bool: function(prov: POSSL_PROVIDER; name: PIdAnsiChar; defval: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PROVIDER_conf_get_bool}

  OSSL_PROVIDER_query_operation: function(prov: POSSL_PROVIDER; operation_id: TIdC_INT; no_cache: PIdC_INT): POSSL_ALGORITHM; cdecl = nil;
  {$EXTERNALSYM OSSL_PROVIDER_query_operation}

  OSSL_PROVIDER_unquery_operation: procedure(prov: POSSL_PROVIDER; operation_id: TIdC_INT; algs: POSSL_ALGORITHM); cdecl = nil;
  {$EXTERNALSYM OSSL_PROVIDER_unquery_operation}

  OSSL_PROVIDER_get0_provider_ctx: function(prov: POSSL_PROVIDER): Pointer; cdecl = nil;
  {$EXTERNALSYM OSSL_PROVIDER_get0_provider_ctx}

  OSSL_PROVIDER_get0_dispatch: function(prov: POSSL_PROVIDER): POSSL_DISPATCH; cdecl = nil;
  {$EXTERNALSYM OSSL_PROVIDER_get0_dispatch}

  OSSL_PROVIDER_add_builtin: function(arg1: POSSL_LIB_CTX; name: PIdAnsiChar; init_fn: TOSSL_PROVIDER_add_builtin_init_fn_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PROVIDER_add_builtin}

  OSSL_PROVIDER_get0_name: function(prov: POSSL_PROVIDER): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_PROVIDER_get0_name}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function OSSL_PROVIDER_set_default_search_path(arg1: POSSL_LIB_CTX; path: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_PROVIDER_get0_default_search_path(libctx: POSSL_LIB_CTX): PIdAnsiChar; cdecl;
function OSSL_PROVIDER_load(arg1: POSSL_LIB_CTX; name: PIdAnsiChar): POSSL_PROVIDER; cdecl;
function OSSL_PROVIDER_load_ex(arg1: POSSL_LIB_CTX; name: PIdAnsiChar; params: POSSL_PARAM): POSSL_PROVIDER; cdecl;
function OSSL_PROVIDER_try_load(arg1: POSSL_LIB_CTX; name: PIdAnsiChar; retain_fallbacks: TIdC_INT): POSSL_PROVIDER; cdecl;
function OSSL_PROVIDER_try_load_ex(arg1: POSSL_LIB_CTX; name: PIdAnsiChar; params: POSSL_PARAM; retain_fallbacks: TIdC_INT): POSSL_PROVIDER; cdecl;
function OSSL_PROVIDER_unload(prov: POSSL_PROVIDER): TIdC_INT; cdecl;
function OSSL_PROVIDER_available(arg1: POSSL_LIB_CTX; name: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_PROVIDER_do_all(ctx: POSSL_LIB_CTX; cb: TOSSL_PROVIDER_do_all_cb_cb; cbdata: Pointer): TIdC_INT; cdecl;
function OSSL_PROVIDER_gettable_params(prov: POSSL_PROVIDER): POSSL_PARAM; cdecl;
function OSSL_PROVIDER_get_params(prov: POSSL_PROVIDER; params: POSSL_PARAM): TIdC_INT; cdecl;
function OSSL_PROVIDER_self_test(prov: POSSL_PROVIDER): TIdC_INT; cdecl;
function OSSL_PROVIDER_get_capabilities(prov: POSSL_PROVIDER; capability: PIdAnsiChar; cb: TOSSL_PROVIDER_get_capabilities_cb_cb; arg: Pointer): TIdC_INT; cdecl;
function OSSL_PROVIDER_add_conf_parameter(prov: POSSL_PROVIDER; name: PIdAnsiChar; value: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_PROVIDER_get_conf_parameters(prov: POSSL_PROVIDER; params: POSSL_PARAM): TIdC_INT; cdecl;
function OSSL_PROVIDER_conf_get_bool(prov: POSSL_PROVIDER; name: PIdAnsiChar; defval: TIdC_INT): TIdC_INT; cdecl;
function OSSL_PROVIDER_query_operation(prov: POSSL_PROVIDER; operation_id: TIdC_INT; no_cache: PIdC_INT): POSSL_ALGORITHM; cdecl;
procedure OSSL_PROVIDER_unquery_operation(prov: POSSL_PROVIDER; operation_id: TIdC_INT; algs: POSSL_ALGORITHM); cdecl;
function OSSL_PROVIDER_get0_provider_ctx(prov: POSSL_PROVIDER): Pointer; cdecl;
function OSSL_PROVIDER_get0_dispatch(prov: POSSL_PROVIDER): POSSL_DISPATCH; cdecl;
function OSSL_PROVIDER_add_builtin(arg1: POSSL_LIB_CTX; name: PIdAnsiChar; init_fn: TOSSL_PROVIDER_add_builtin_init_fn_cb): TIdC_INT; cdecl;
function OSSL_PROVIDER_get0_name(prov: POSSL_PROVIDER): PIdAnsiChar; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

implementation

uses
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  classes,
  TaurusTLSLoader,
  {$ENDIF}
  TaurusTLS_ResourceStrings,
  TaurusTLSExceptionHandlers;

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES IMPORTS
// =============================================================================

function OSSL_PROVIDER_set_default_search_path(arg1: POSSL_LIB_CTX; path: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PROVIDER_set_default_search_path';
function OSSL_PROVIDER_get0_default_search_path(libctx: POSSL_LIB_CTX): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_PROVIDER_get0_default_search_path';
function OSSL_PROVIDER_load(arg1: POSSL_LIB_CTX; name: PIdAnsiChar): POSSL_PROVIDER; cdecl external CLibCrypto name 'OSSL_PROVIDER_load';
function OSSL_PROVIDER_load_ex(arg1: POSSL_LIB_CTX; name: PIdAnsiChar; params: POSSL_PARAM): POSSL_PROVIDER; cdecl external CLibCrypto name 'OSSL_PROVIDER_load_ex';
function OSSL_PROVIDER_try_load(arg1: POSSL_LIB_CTX; name: PIdAnsiChar; retain_fallbacks: TIdC_INT): POSSL_PROVIDER; cdecl external CLibCrypto name 'OSSL_PROVIDER_try_load';
function OSSL_PROVIDER_try_load_ex(arg1: POSSL_LIB_CTX; name: PIdAnsiChar; params: POSSL_PARAM; retain_fallbacks: TIdC_INT): POSSL_PROVIDER; cdecl external CLibCrypto name 'OSSL_PROVIDER_try_load_ex';
function OSSL_PROVIDER_unload(prov: POSSL_PROVIDER): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PROVIDER_unload';
function OSSL_PROVIDER_available(arg1: POSSL_LIB_CTX; name: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PROVIDER_available';
function OSSL_PROVIDER_do_all(ctx: POSSL_LIB_CTX; cb: TOSSL_PROVIDER_do_all_cb_cb; cbdata: Pointer): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PROVIDER_do_all';
function OSSL_PROVIDER_gettable_params(prov: POSSL_PROVIDER): POSSL_PARAM; cdecl external CLibCrypto name 'OSSL_PROVIDER_gettable_params';
function OSSL_PROVIDER_get_params(prov: POSSL_PROVIDER; params: POSSL_PARAM): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PROVIDER_get_params';
function OSSL_PROVIDER_self_test(prov: POSSL_PROVIDER): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PROVIDER_self_test';
function OSSL_PROVIDER_get_capabilities(prov: POSSL_PROVIDER; capability: PIdAnsiChar; cb: TOSSL_PROVIDER_get_capabilities_cb_cb; arg: Pointer): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PROVIDER_get_capabilities';
function OSSL_PROVIDER_add_conf_parameter(prov: POSSL_PROVIDER; name: PIdAnsiChar; value: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PROVIDER_add_conf_parameter';
function OSSL_PROVIDER_get_conf_parameters(prov: POSSL_PROVIDER; params: POSSL_PARAM): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PROVIDER_get_conf_parameters';
function OSSL_PROVIDER_conf_get_bool(prov: POSSL_PROVIDER; name: PIdAnsiChar; defval: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PROVIDER_conf_get_bool';
function OSSL_PROVIDER_query_operation(prov: POSSL_PROVIDER; operation_id: TIdC_INT; no_cache: PIdC_INT): POSSL_ALGORITHM; cdecl external CLibCrypto name 'OSSL_PROVIDER_query_operation';
procedure OSSL_PROVIDER_unquery_operation(prov: POSSL_PROVIDER; operation_id: TIdC_INT; algs: POSSL_ALGORITHM); cdecl external CLibCrypto name 'OSSL_PROVIDER_unquery_operation';
function OSSL_PROVIDER_get0_provider_ctx(prov: POSSL_PROVIDER): Pointer; cdecl external CLibCrypto name 'OSSL_PROVIDER_get0_provider_ctx';
function OSSL_PROVIDER_get0_dispatch(prov: POSSL_PROVIDER): POSSL_DISPATCH; cdecl external CLibCrypto name 'OSSL_PROVIDER_get0_dispatch';
function OSSL_PROVIDER_add_builtin(arg1: POSSL_LIB_CTX; name: PIdAnsiChar; init_fn: TOSSL_PROVIDER_add_builtin_init_fn_cb): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PROVIDER_add_builtin';
function OSSL_PROVIDER_get0_name(prov: POSSL_PROVIDER): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_PROVIDER_get0_name';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  OSSL_PROVIDER_set_default_search_path_procname = 'OSSL_PROVIDER_set_default_search_path';
  OSSL_PROVIDER_set_default_search_path_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PROVIDER_get0_default_search_path_procname = 'OSSL_PROVIDER_get0_default_search_path';
  OSSL_PROVIDER_get0_default_search_path_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_PROVIDER_load_procname = 'OSSL_PROVIDER_load';
  OSSL_PROVIDER_load_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PROVIDER_load_ex_procname = 'OSSL_PROVIDER_load_ex';
  OSSL_PROVIDER_load_ex_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_PROVIDER_try_load_procname = 'OSSL_PROVIDER_try_load';
  OSSL_PROVIDER_try_load_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PROVIDER_try_load_ex_procname = 'OSSL_PROVIDER_try_load_ex';
  OSSL_PROVIDER_try_load_ex_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_PROVIDER_unload_procname = 'OSSL_PROVIDER_unload';
  OSSL_PROVIDER_unload_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PROVIDER_available_procname = 'OSSL_PROVIDER_available';
  OSSL_PROVIDER_available_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PROVIDER_do_all_procname = 'OSSL_PROVIDER_do_all';
  OSSL_PROVIDER_do_all_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PROVIDER_gettable_params_procname = 'OSSL_PROVIDER_gettable_params';
  OSSL_PROVIDER_gettable_params_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PROVIDER_get_params_procname = 'OSSL_PROVIDER_get_params';
  OSSL_PROVIDER_get_params_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PROVIDER_self_test_procname = 'OSSL_PROVIDER_self_test';
  OSSL_PROVIDER_self_test_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PROVIDER_get_capabilities_procname = 'OSSL_PROVIDER_get_capabilities';
  OSSL_PROVIDER_get_capabilities_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PROVIDER_add_conf_parameter_procname = 'OSSL_PROVIDER_add_conf_parameter';
  OSSL_PROVIDER_add_conf_parameter_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_PROVIDER_get_conf_parameters_procname = 'OSSL_PROVIDER_get_conf_parameters';
  OSSL_PROVIDER_get_conf_parameters_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_PROVIDER_conf_get_bool_procname = 'OSSL_PROVIDER_conf_get_bool';
  OSSL_PROVIDER_conf_get_bool_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_PROVIDER_query_operation_procname = 'OSSL_PROVIDER_query_operation';
  OSSL_PROVIDER_query_operation_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PROVIDER_unquery_operation_procname = 'OSSL_PROVIDER_unquery_operation';
  OSSL_PROVIDER_unquery_operation_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PROVIDER_get0_provider_ctx_procname = 'OSSL_PROVIDER_get0_provider_ctx';
  OSSL_PROVIDER_get0_provider_ctx_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PROVIDER_get0_dispatch_procname = 'OSSL_PROVIDER_get0_dispatch';
  OSSL_PROVIDER_get0_dispatch_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PROVIDER_add_builtin_procname = 'OSSL_PROVIDER_add_builtin';
  OSSL_PROVIDER_add_builtin_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PROVIDER_get0_name_procname = 'OSSL_PROVIDER_get0_name';
  OSSL_PROVIDER_get0_name_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_OSSL_PROVIDER_set_default_search_path(arg1: POSSL_LIB_CTX; path: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_set_default_search_path_procname);
end;

function ERR_OSSL_PROVIDER_get0_default_search_path(libctx: POSSL_LIB_CTX): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_get0_default_search_path_procname);
end;

function ERR_OSSL_PROVIDER_load(arg1: POSSL_LIB_CTX; name: PIdAnsiChar): POSSL_PROVIDER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_load_procname);
end;

function ERR_OSSL_PROVIDER_load_ex(arg1: POSSL_LIB_CTX; name: PIdAnsiChar; params: POSSL_PARAM): POSSL_PROVIDER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_load_ex_procname);
end;

function ERR_OSSL_PROVIDER_try_load(arg1: POSSL_LIB_CTX; name: PIdAnsiChar; retain_fallbacks: TIdC_INT): POSSL_PROVIDER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_try_load_procname);
end;

function ERR_OSSL_PROVIDER_try_load_ex(arg1: POSSL_LIB_CTX; name: PIdAnsiChar; params: POSSL_PARAM; retain_fallbacks: TIdC_INT): POSSL_PROVIDER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_try_load_ex_procname);
end;

function ERR_OSSL_PROVIDER_unload(prov: POSSL_PROVIDER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_unload_procname);
end;

function ERR_OSSL_PROVIDER_available(arg1: POSSL_LIB_CTX; name: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_available_procname);
end;

function ERR_OSSL_PROVIDER_do_all(ctx: POSSL_LIB_CTX; cb: TOSSL_PROVIDER_do_all_cb_cb; cbdata: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_do_all_procname);
end;

function ERR_OSSL_PROVIDER_gettable_params(prov: POSSL_PROVIDER): POSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_gettable_params_procname);
end;

function ERR_OSSL_PROVIDER_get_params(prov: POSSL_PROVIDER; params: POSSL_PARAM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_get_params_procname);
end;

function ERR_OSSL_PROVIDER_self_test(prov: POSSL_PROVIDER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_self_test_procname);
end;

function ERR_OSSL_PROVIDER_get_capabilities(prov: POSSL_PROVIDER; capability: PIdAnsiChar; cb: TOSSL_PROVIDER_get_capabilities_cb_cb; arg: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_get_capabilities_procname);
end;

function ERR_OSSL_PROVIDER_add_conf_parameter(prov: POSSL_PROVIDER; name: PIdAnsiChar; value: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_add_conf_parameter_procname);
end;

function ERR_OSSL_PROVIDER_get_conf_parameters(prov: POSSL_PROVIDER; params: POSSL_PARAM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_get_conf_parameters_procname);
end;

function ERR_OSSL_PROVIDER_conf_get_bool(prov: POSSL_PROVIDER; name: PIdAnsiChar; defval: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_conf_get_bool_procname);
end;

function ERR_OSSL_PROVIDER_query_operation(prov: POSSL_PROVIDER; operation_id: TIdC_INT; no_cache: PIdC_INT): POSSL_ALGORITHM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_query_operation_procname);
end;

procedure ERR_OSSL_PROVIDER_unquery_operation(prov: POSSL_PROVIDER; operation_id: TIdC_INT; algs: POSSL_ALGORITHM); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_unquery_operation_procname);
end;

function ERR_OSSL_PROVIDER_get0_provider_ctx(prov: POSSL_PROVIDER): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_get0_provider_ctx_procname);
end;

function ERR_OSSL_PROVIDER_get0_dispatch(prov: POSSL_PROVIDER): POSSL_DISPATCH; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_get0_dispatch_procname);
end;

function ERR_OSSL_PROVIDER_add_builtin(arg1: POSSL_LIB_CTX; name: PIdAnsiChar; init_fn: TOSSL_PROVIDER_add_builtin_init_fn_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_add_builtin_procname);
end;

function ERR_OSSL_PROVIDER_get0_name(prov: POSSL_PROVIDER): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PROVIDER_get0_name_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
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
  
  OSSL_PROVIDER_add_conf_parameter := LoadLibFunction(ADllHandle, OSSL_PROVIDER_add_conf_parameter_procname);
  FuncLoadError := not assigned(OSSL_PROVIDER_add_conf_parameter);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PROVIDER_add_conf_parameter_allownil)}
    OSSL_PROVIDER_add_conf_parameter := ERR_OSSL_PROVIDER_add_conf_parameter;
    {$ifend}
    {$if declared(OSSL_PROVIDER_add_conf_parameter_introduced)}
    if LibVersion < OSSL_PROVIDER_add_conf_parameter_introduced then
    begin
      {$if declared(FC_OSSL_PROVIDER_add_conf_parameter)}
      OSSL_PROVIDER_add_conf_parameter := FC_OSSL_PROVIDER_add_conf_parameter;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PROVIDER_add_conf_parameter_removed)}
    if OSSL_PROVIDER_add_conf_parameter_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PROVIDER_add_conf_parameter)}
      OSSL_PROVIDER_add_conf_parameter := _OSSL_PROVIDER_add_conf_parameter;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PROVIDER_add_conf_parameter_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PROVIDER_add_conf_parameter');
    {$ifend}
  end;
  
  OSSL_PROVIDER_get_conf_parameters := LoadLibFunction(ADllHandle, OSSL_PROVIDER_get_conf_parameters_procname);
  FuncLoadError := not assigned(OSSL_PROVIDER_get_conf_parameters);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PROVIDER_get_conf_parameters_allownil)}
    OSSL_PROVIDER_get_conf_parameters := ERR_OSSL_PROVIDER_get_conf_parameters;
    {$ifend}
    {$if declared(OSSL_PROVIDER_get_conf_parameters_introduced)}
    if LibVersion < OSSL_PROVIDER_get_conf_parameters_introduced then
    begin
      {$if declared(FC_OSSL_PROVIDER_get_conf_parameters)}
      OSSL_PROVIDER_get_conf_parameters := FC_OSSL_PROVIDER_get_conf_parameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PROVIDER_get_conf_parameters_removed)}
    if OSSL_PROVIDER_get_conf_parameters_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PROVIDER_get_conf_parameters)}
      OSSL_PROVIDER_get_conf_parameters := _OSSL_PROVIDER_get_conf_parameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PROVIDER_get_conf_parameters_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PROVIDER_get_conf_parameters');
    {$ifend}
  end;
  
  OSSL_PROVIDER_conf_get_bool := LoadLibFunction(ADllHandle, OSSL_PROVIDER_conf_get_bool_procname);
  FuncLoadError := not assigned(OSSL_PROVIDER_conf_get_bool);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PROVIDER_conf_get_bool_allownil)}
    OSSL_PROVIDER_conf_get_bool := ERR_OSSL_PROVIDER_conf_get_bool;
    {$ifend}
    {$if declared(OSSL_PROVIDER_conf_get_bool_introduced)}
    if LibVersion < OSSL_PROVIDER_conf_get_bool_introduced then
    begin
      {$if declared(FC_OSSL_PROVIDER_conf_get_bool)}
      OSSL_PROVIDER_conf_get_bool := FC_OSSL_PROVIDER_conf_get_bool;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PROVIDER_conf_get_bool_removed)}
    if OSSL_PROVIDER_conf_get_bool_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PROVIDER_conf_get_bool)}
      OSSL_PROVIDER_conf_get_bool := _OSSL_PROVIDER_conf_get_bool;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PROVIDER_conf_get_bool_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PROVIDER_conf_get_bool');
    {$ifend}
  end;
  
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
  
end;

procedure Unload;
begin
  OSSL_PROVIDER_set_default_search_path := nil;
  OSSL_PROVIDER_get0_default_search_path := nil;
  OSSL_PROVIDER_load := nil;
  OSSL_PROVIDER_load_ex := nil;
  OSSL_PROVIDER_try_load := nil;
  OSSL_PROVIDER_try_load_ex := nil;
  OSSL_PROVIDER_unload := nil;
  OSSL_PROVIDER_available := nil;
  OSSL_PROVIDER_do_all := nil;
  OSSL_PROVIDER_gettable_params := nil;
  OSSL_PROVIDER_get_params := nil;
  OSSL_PROVIDER_self_test := nil;
  OSSL_PROVIDER_get_capabilities := nil;
  OSSL_PROVIDER_add_conf_parameter := nil;
  OSSL_PROVIDER_get_conf_parameters := nil;
  OSSL_PROVIDER_conf_get_bool := nil;
  OSSL_PROVIDER_query_operation := nil;
  OSSL_PROVIDER_unquery_operation := nil;
  OSSL_PROVIDER_get0_provider_ctx := nil;
  OSSL_PROVIDER_get0_dispatch := nil;
  OSSL_PROVIDER_add_builtin := nil;
  OSSL_PROVIDER_get0_name := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.