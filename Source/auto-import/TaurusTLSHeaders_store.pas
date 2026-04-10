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

unit TaurusTLSHeaders_store;

interface

uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_core;




// =============================================================================
// TYPE DECLARATIONS
// =============================================================================
type
  Possl_store_ctx_st = ^Tossl_store_ctx_st;
  Tossl_store_ctx_st =   record end;
  {$EXTERNALSYM Possl_store_ctx_st}

  Possl_store_loader_st = ^Tossl_store_loader_st;
  Tossl_store_loader_st =   record end;
  {$EXTERNALSYM Possl_store_loader_st}

  Possl_store_loader_ctx_st = ^Tossl_store_loader_ctx_st;
  Tossl_store_loader_ctx_st =   record end;
  {$EXTERNALSYM Possl_store_loader_ctx_st}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  TOSSL_STORE_post_process_info_fn = function(arg1: POSSL_STORE_INFO; arg2: Pointer): Possl_store_info_st; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // OSSL_STORE_LOADER_do_all_provided_fn_cb = function(loader: POSSL_STORE_LOADER; arg: Pointer): void; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // OSSL_STORE_LOADER_names_do_all_fn_cb = function(name: PIdAnsiChar; data: Pointer): void; cdecl;
  TOSSL_STORE_open_fn = function(loader: POSSL_STORE_LOADER; uri: PIdAnsiChar; ui_method: PUI_METHOD; ui_data: Pointer): Possl_store_loader_ctx_st; cdecl;
  TOSSL_STORE_open_ex_fn = function(loader: POSSL_STORE_LOADER; uri: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; ui_method: PUI_METHOD; ui_data: Pointer): Possl_store_loader_ctx_st; cdecl;
  TOSSL_STORE_attach_fn = function(loader: POSSL_STORE_LOADER; bio: PBIO; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; ui_method: PUI_METHOD; ui_data: Pointer): Possl_store_loader_ctx_st; cdecl;
  TOSSL_STORE_ctrl_fn = function(ctx: POSSL_STORE_LOADER_CTX; cmd: TIdC_INT; args: Tva_list): TIdC_INT; cdecl;
  TOSSL_STORE_expect_fn = function(ctx: POSSL_STORE_LOADER_CTX; expected: TIdC_INT): TIdC_INT; cdecl;
  TOSSL_STORE_find_fn = function(ctx: POSSL_STORE_LOADER_CTX; criteria: POSSL_STORE_SEARCH): TIdC_INT; cdecl;
  TOSSL_STORE_load_fn = function(ctx: POSSL_STORE_LOADER_CTX; ui_method: PUI_METHOD; ui_data: Pointer): Possl_store_info_st; cdecl;
  TOSSL_STORE_eof_fn = function(ctx: POSSL_STORE_LOADER_CTX): TIdC_INT; cdecl;
  TOSSL_STORE_error_fn = function(ctx: POSSL_STORE_LOADER_CTX): TIdC_INT; cdecl;
  TOSSL_STORE_close_fn = function(ctx: POSSL_STORE_LOADER_CTX): TIdC_INT; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  OSSL_STORE_C_USE_SECMEM = 1;
  OSSL_STORE_C_CUSTOM_START = 100;
  OSSL_STORE_INFO_NAME = 1;
  OSSL_STORE_INFO_PARAMS = 2;
  OSSL_STORE_INFO_PUBKEY = 3;
  OSSL_STORE_INFO_PKEY = 4;
  OSSL_STORE_INFO_CERT = 5;
  OSSL_STORE_INFO_CRL = 6;
  OSSL_STORE_SEARCH_BY_NAME = 1;
  OSSL_STORE_SEARCH_BY_ISSUER_SERIAL = 2;
  OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT = 3;
  OSSL_STORE_SEARCH_BY_ALIAS = 4;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  OSSL_STORE_open: function(uri: PIdAnsiChar; ui_method: PUI_METHOD; ui_data: Pointer; post_process: TOSSL_STORE_post_process_info_fn; post_process_data: Pointer): POSSL_STORE_CTX; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_open}

  OSSL_STORE_open_ex: function(uri: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; ui_method: PUI_METHOD; ui_data: Pointer; params: POSSL_PARAM; post_process: TOSSL_STORE_post_process_info_fn; post_process_data: Pointer): POSSL_STORE_CTX; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_open_ex}

  OSSL_STORE_ctrl: function(ctx: POSSL_STORE_CTX; cmd: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM OSSL_STORE_ctrl}

  OSSL_STORE_vctrl: function(ctx: POSSL_STORE_CTX; cmd: TIdC_INT; args: Tva_list): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM OSSL_STORE_vctrl}

  OSSL_STORE_load: function(ctx: POSSL_STORE_CTX): POSSL_STORE_INFO; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_load}

  OSSL_STORE_delete: function(uri: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; ui_method: PUI_METHOD; ui_data: Pointer; params: POSSL_PARAM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_delete}

  OSSL_STORE_eof: function(ctx: POSSL_STORE_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_eof}

  OSSL_STORE_error: function(ctx: POSSL_STORE_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_error}

  OSSL_STORE_close: function(ctx: POSSL_STORE_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_close}

  OSSL_STORE_attach: function(bio: PBIO; scheme: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; ui_method: PUI_METHOD; ui_data: Pointer; params: POSSL_PARAM; post_process: TOSSL_STORE_post_process_info_fn; post_process_data: Pointer): POSSL_STORE_CTX; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_attach}

  OSSL_STORE_INFO_new: function(_type: TIdC_INT; data: Pointer): POSSL_STORE_INFO; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_new}

  OSSL_STORE_INFO_new_NAME: function(name: PIdAnsiChar): POSSL_STORE_INFO; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_new_NAME}

  OSSL_STORE_INFO_set0_NAME_description: function(info: POSSL_STORE_INFO; desc: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_set0_NAME_description}

  OSSL_STORE_INFO_new_PARAMS: function(params: PEVP_PKEY): POSSL_STORE_INFO; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_new_PARAMS}

  OSSL_STORE_INFO_new_PUBKEY: function(pubkey: PEVP_PKEY): POSSL_STORE_INFO; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_new_PUBKEY}

  OSSL_STORE_INFO_new_PKEY: function(pkey: PEVP_PKEY): POSSL_STORE_INFO; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_new_PKEY}

  OSSL_STORE_INFO_new_CERT: function(x509: PX509): POSSL_STORE_INFO; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_new_CERT}

  OSSL_STORE_INFO_new_CRL: function(crl: PX509_CRL): POSSL_STORE_INFO; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_new_CRL}

  OSSL_STORE_INFO_get_type: function(info: POSSL_STORE_INFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get_type}

  OSSL_STORE_INFO_get0_data: function(_type: TIdC_INT; info: POSSL_STORE_INFO): Pointer; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get0_data}

  OSSL_STORE_INFO_get0_NAME: function(info: POSSL_STORE_INFO): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get0_NAME}

  OSSL_STORE_INFO_get1_NAME: function(info: POSSL_STORE_INFO): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get1_NAME}

  OSSL_STORE_INFO_get0_NAME_description: function(info: POSSL_STORE_INFO): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get0_NAME_description}

  OSSL_STORE_INFO_get1_NAME_description: function(info: POSSL_STORE_INFO): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get1_NAME_description}

  OSSL_STORE_INFO_get0_PARAMS: function(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get0_PARAMS}

  OSSL_STORE_INFO_get1_PARAMS: function(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get1_PARAMS}

  OSSL_STORE_INFO_get0_PUBKEY: function(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get0_PUBKEY}

  OSSL_STORE_INFO_get1_PUBKEY: function(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get1_PUBKEY}

  OSSL_STORE_INFO_get0_PKEY: function(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get0_PKEY}

  OSSL_STORE_INFO_get1_PKEY: function(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get1_PKEY}

  OSSL_STORE_INFO_get0_CERT: function(info: POSSL_STORE_INFO): PX509; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get0_CERT}

  OSSL_STORE_INFO_get1_CERT: function(info: POSSL_STORE_INFO): PX509; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get1_CERT}

  OSSL_STORE_INFO_get0_CRL: function(info: POSSL_STORE_INFO): PX509_CRL; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get0_CRL}

  OSSL_STORE_INFO_get1_CRL: function(info: POSSL_STORE_INFO): PX509_CRL; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_get1_CRL}

  OSSL_STORE_INFO_type_string: function(_type: TIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_type_string}

  OSSL_STORE_INFO_free: function(info: POSSL_STORE_INFO): void; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_INFO_free}

  OSSL_STORE_supports_search: function(ctx: POSSL_STORE_CTX; search_type: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_supports_search}

  OSSL_STORE_SEARCH_by_name: function(name: PX509_NAME): POSSL_STORE_SEARCH; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_SEARCH_by_name}

  OSSL_STORE_SEARCH_by_issuer_serial: function(name: PX509_NAME; serial: PASN1_INTEGER): POSSL_STORE_SEARCH; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_SEARCH_by_issuer_serial}

  OSSL_STORE_SEARCH_by_key_fingerprint: function(digest: PEVP_MD; bytes: PIdAnsiChar; len: TIdC_SIZET): POSSL_STORE_SEARCH; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_SEARCH_by_key_fingerprint}

  OSSL_STORE_SEARCH_by_alias: function(alias: PIdAnsiChar): POSSL_STORE_SEARCH; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_SEARCH_by_alias}

  OSSL_STORE_SEARCH_free: function(search: POSSL_STORE_SEARCH): void; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_SEARCH_free}

  OSSL_STORE_SEARCH_get_type: function(criterion: POSSL_STORE_SEARCH): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_SEARCH_get_type}

  OSSL_STORE_SEARCH_get0_name: function(criterion: POSSL_STORE_SEARCH): PX509_NAME; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_SEARCH_get0_name}

  OSSL_STORE_SEARCH_get0_serial: function(criterion: POSSL_STORE_SEARCH): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_SEARCH_get0_serial}

  OSSL_STORE_SEARCH_get0_bytes: function(criterion: POSSL_STORE_SEARCH; length: PIdC_SIZET): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_SEARCH_get0_bytes}

  OSSL_STORE_SEARCH_get0_string: function(criterion: POSSL_STORE_SEARCH): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_SEARCH_get0_string}

  OSSL_STORE_SEARCH_get0_digest: function(criterion: POSSL_STORE_SEARCH): PEVP_MD; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_SEARCH_get0_digest}

  OSSL_STORE_expect: function(ctx: POSSL_STORE_CTX; expected_type: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_expect}

  OSSL_STORE_find: function(ctx: POSSL_STORE_CTX; search: POSSL_STORE_SEARCH): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_find}

  OSSL_STORE_LOADER_fetch: function(libctx: POSSL_LIB_CTX; scheme: PIdAnsiChar; properties: PIdAnsiChar): POSSL_STORE_LOADER; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_LOADER_fetch}

  OSSL_STORE_LOADER_up_ref: function(loader: POSSL_STORE_LOADER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_LOADER_up_ref}

  OSSL_STORE_LOADER_free: function(loader: POSSL_STORE_LOADER): void; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_LOADER_free}

  OSSL_STORE_LOADER_get0_provider: function(loader: POSSL_STORE_LOADER): POSSL_PROVIDER; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_LOADER_get0_provider}

  OSSL_STORE_LOADER_get0_properties: function(loader: POSSL_STORE_LOADER): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_LOADER_get0_properties}

  OSSL_STORE_LOADER_get0_description: function(loader: POSSL_STORE_LOADER): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_LOADER_get0_description}

  OSSL_STORE_LOADER_is_a: function(loader: POSSL_STORE_LOADER; scheme: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_LOADER_is_a}

  OSSL_STORE_LOADER_do_all_provided: function(libctx: POSSL_LIB_CTX; fn: TOSSL_STORE_LOADER_do_all_provided_fn_cb; arg: Pointer): void; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_LOADER_do_all_provided}

  OSSL_STORE_LOADER_names_do_all: function(loader: POSSL_STORE_LOADER; fn: TOSSL_STORE_LOADER_names_do_all_fn_cb; data: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_LOADER_names_do_all}

  OSSL_STORE_LOADER_settable_ctx_params: function(loader: POSSL_STORE_LOADER): POSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_STORE_LOADER_settable_ctx_params}

  OSSL_STORE_LOADER_new: function(e: PENGINE; scheme: PIdAnsiChar): POSSL_STORE_LOADER; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM OSSL_STORE_LOADER_new}

  OSSL_STORE_LOADER_set_open: function(loader: POSSL_STORE_LOADER; open_function: TOSSL_STORE_open_fn): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM OSSL_STORE_LOADER_set_open}

  OSSL_STORE_LOADER_set_open_ex: function(loader: POSSL_STORE_LOADER; open_ex_function: TOSSL_STORE_open_ex_fn): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM OSSL_STORE_LOADER_set_open_ex}

  OSSL_STORE_LOADER_set_attach: function(loader: POSSL_STORE_LOADER; attach_function: TOSSL_STORE_attach_fn): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM OSSL_STORE_LOADER_set_attach}

  OSSL_STORE_LOADER_set_ctrl: function(loader: POSSL_STORE_LOADER; ctrl_function: TOSSL_STORE_ctrl_fn): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM OSSL_STORE_LOADER_set_ctrl}

  OSSL_STORE_LOADER_set_expect: function(loader: POSSL_STORE_LOADER; expect_function: TOSSL_STORE_expect_fn): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM OSSL_STORE_LOADER_set_expect}

  OSSL_STORE_LOADER_set_find: function(loader: POSSL_STORE_LOADER; find_function: TOSSL_STORE_find_fn): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM OSSL_STORE_LOADER_set_find}

  OSSL_STORE_LOADER_set_load: function(loader: POSSL_STORE_LOADER; load_function: TOSSL_STORE_load_fn): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM OSSL_STORE_LOADER_set_load}

  OSSL_STORE_LOADER_set_eof: function(loader: POSSL_STORE_LOADER; eof_function: TOSSL_STORE_close_fn): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM OSSL_STORE_LOADER_set_eof}

  OSSL_STORE_LOADER_set_error: function(loader: POSSL_STORE_LOADER; error_function: TOSSL_STORE_close_fn): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM OSSL_STORE_LOADER_set_error}

  OSSL_STORE_LOADER_set_close: function(loader: POSSL_STORE_LOADER; close_function: TOSSL_STORE_close_fn): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM OSSL_STORE_LOADER_set_close}

  OSSL_STORE_LOADER_get0_engine: function(loader: POSSL_STORE_LOADER): PENGINE; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM OSSL_STORE_LOADER_get0_engine}

  OSSL_STORE_LOADER_get0_scheme: function(loader: POSSL_STORE_LOADER): PIdAnsiChar; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM OSSL_STORE_LOADER_get0_scheme}

  OSSL_STORE_register_loader: function(loader: POSSL_STORE_LOADER): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM OSSL_STORE_register_loader}

  OSSL_STORE_unregister_loader: function(scheme: PIdAnsiChar): POSSL_STORE_LOADER; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM OSSL_STORE_unregister_loader}

  OSSL_STORE_do_all_loaders: function(do_function: TOSSL_STORE_LOADER_do_all_provided_fn_cb; do_arg: Pointer): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM OSSL_STORE_do_all_loaders}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function OSSL_STORE_open(uri: PIdAnsiChar; ui_method: PUI_METHOD; ui_data: Pointer; post_process: TOSSL_STORE_post_process_info_fn; post_process_data: Pointer): POSSL_STORE_CTX; cdecl;
function OSSL_STORE_open_ex(uri: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; ui_method: PUI_METHOD; ui_data: Pointer; params: POSSL_PARAM; post_process: TOSSL_STORE_post_process_info_fn; post_process_data: Pointer): POSSL_STORE_CTX; cdecl;
function OSSL_STORE_ctrl(ctx: POSSL_STORE_CTX; cmd: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function OSSL_STORE_vctrl(ctx: POSSL_STORE_CTX; cmd: TIdC_INT; args: Tva_list): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function OSSL_STORE_load(ctx: POSSL_STORE_CTX): POSSL_STORE_INFO; cdecl;
function OSSL_STORE_delete(uri: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; ui_method: PUI_METHOD; ui_data: Pointer; params: POSSL_PARAM): TIdC_INT; cdecl;
function OSSL_STORE_eof(ctx: POSSL_STORE_CTX): TIdC_INT; cdecl;
function OSSL_STORE_error(ctx: POSSL_STORE_CTX): TIdC_INT; cdecl;
function OSSL_STORE_close(ctx: POSSL_STORE_CTX): TIdC_INT; cdecl;
function OSSL_STORE_attach(bio: PBIO; scheme: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; ui_method: PUI_METHOD; ui_data: Pointer; params: POSSL_PARAM; post_process: TOSSL_STORE_post_process_info_fn; post_process_data: Pointer): POSSL_STORE_CTX; cdecl;
function OSSL_STORE_INFO_new(_type: TIdC_INT; data: Pointer): POSSL_STORE_INFO; cdecl;
function OSSL_STORE_INFO_new_NAME(name: PIdAnsiChar): POSSL_STORE_INFO; cdecl;
function OSSL_STORE_INFO_set0_NAME_description(info: POSSL_STORE_INFO; desc: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_STORE_INFO_new_PARAMS(params: PEVP_PKEY): POSSL_STORE_INFO; cdecl;
function OSSL_STORE_INFO_new_PUBKEY(pubkey: PEVP_PKEY): POSSL_STORE_INFO; cdecl;
function OSSL_STORE_INFO_new_PKEY(pkey: PEVP_PKEY): POSSL_STORE_INFO; cdecl;
function OSSL_STORE_INFO_new_CERT(x509: PX509): POSSL_STORE_INFO; cdecl;
function OSSL_STORE_INFO_new_CRL(crl: PX509_CRL): POSSL_STORE_INFO; cdecl;
function OSSL_STORE_INFO_get_type(info: POSSL_STORE_INFO): TIdC_INT; cdecl;
function OSSL_STORE_INFO_get0_data(_type: TIdC_INT; info: POSSL_STORE_INFO): Pointer; cdecl;
function OSSL_STORE_INFO_get0_NAME(info: POSSL_STORE_INFO): PIdAnsiChar; cdecl;
function OSSL_STORE_INFO_get1_NAME(info: POSSL_STORE_INFO): PIdAnsiChar; cdecl;
function OSSL_STORE_INFO_get0_NAME_description(info: POSSL_STORE_INFO): PIdAnsiChar; cdecl;
function OSSL_STORE_INFO_get1_NAME_description(info: POSSL_STORE_INFO): PIdAnsiChar; cdecl;
function OSSL_STORE_INFO_get0_PARAMS(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl;
function OSSL_STORE_INFO_get1_PARAMS(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl;
function OSSL_STORE_INFO_get0_PUBKEY(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl;
function OSSL_STORE_INFO_get1_PUBKEY(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl;
function OSSL_STORE_INFO_get0_PKEY(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl;
function OSSL_STORE_INFO_get1_PKEY(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl;
function OSSL_STORE_INFO_get0_CERT(info: POSSL_STORE_INFO): PX509; cdecl;
function OSSL_STORE_INFO_get1_CERT(info: POSSL_STORE_INFO): PX509; cdecl;
function OSSL_STORE_INFO_get0_CRL(info: POSSL_STORE_INFO): PX509_CRL; cdecl;
function OSSL_STORE_INFO_get1_CRL(info: POSSL_STORE_INFO): PX509_CRL; cdecl;
function OSSL_STORE_INFO_type_string(_type: TIdC_INT): PIdAnsiChar; cdecl;
function OSSL_STORE_INFO_free(info: POSSL_STORE_INFO): void; cdecl;
function OSSL_STORE_supports_search(ctx: POSSL_STORE_CTX; search_type: TIdC_INT): TIdC_INT; cdecl;
function OSSL_STORE_SEARCH_by_name(name: PX509_NAME): POSSL_STORE_SEARCH; cdecl;
function OSSL_STORE_SEARCH_by_issuer_serial(name: PX509_NAME; serial: PASN1_INTEGER): POSSL_STORE_SEARCH; cdecl;
function OSSL_STORE_SEARCH_by_key_fingerprint(digest: PEVP_MD; bytes: PIdAnsiChar; len: TIdC_SIZET): POSSL_STORE_SEARCH; cdecl;
function OSSL_STORE_SEARCH_by_alias(alias: PIdAnsiChar): POSSL_STORE_SEARCH; cdecl;
function OSSL_STORE_SEARCH_free(search: POSSL_STORE_SEARCH): void; cdecl;
function OSSL_STORE_SEARCH_get_type(criterion: POSSL_STORE_SEARCH): TIdC_INT; cdecl;
function OSSL_STORE_SEARCH_get0_name(criterion: POSSL_STORE_SEARCH): PX509_NAME; cdecl;
function OSSL_STORE_SEARCH_get0_serial(criterion: POSSL_STORE_SEARCH): PASN1_INTEGER; cdecl;
function OSSL_STORE_SEARCH_get0_bytes(criterion: POSSL_STORE_SEARCH; length: PIdC_SIZET): PIdAnsiChar; cdecl;
function OSSL_STORE_SEARCH_get0_string(criterion: POSSL_STORE_SEARCH): PIdAnsiChar; cdecl;
function OSSL_STORE_SEARCH_get0_digest(criterion: POSSL_STORE_SEARCH): PEVP_MD; cdecl;
function OSSL_STORE_expect(ctx: POSSL_STORE_CTX; expected_type: TIdC_INT): TIdC_INT; cdecl;
function OSSL_STORE_find(ctx: POSSL_STORE_CTX; search: POSSL_STORE_SEARCH): TIdC_INT; cdecl;
function OSSL_STORE_LOADER_fetch(libctx: POSSL_LIB_CTX; scheme: PIdAnsiChar; properties: PIdAnsiChar): POSSL_STORE_LOADER; cdecl;
function OSSL_STORE_LOADER_up_ref(loader: POSSL_STORE_LOADER): TIdC_INT; cdecl;
function OSSL_STORE_LOADER_free(loader: POSSL_STORE_LOADER): void; cdecl;
function OSSL_STORE_LOADER_get0_provider(loader: POSSL_STORE_LOADER): POSSL_PROVIDER; cdecl;
function OSSL_STORE_LOADER_get0_properties(loader: POSSL_STORE_LOADER): PIdAnsiChar; cdecl;
function OSSL_STORE_LOADER_get0_description(loader: POSSL_STORE_LOADER): PIdAnsiChar; cdecl;
function OSSL_STORE_LOADER_is_a(loader: POSSL_STORE_LOADER; scheme: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_STORE_LOADER_do_all_provided(libctx: POSSL_LIB_CTX; fn: TOSSL_STORE_LOADER_do_all_provided_fn_cb; arg: Pointer): void; cdecl;
function OSSL_STORE_LOADER_names_do_all(loader: POSSL_STORE_LOADER; fn: TOSSL_STORE_LOADER_names_do_all_fn_cb; data: Pointer): TIdC_INT; cdecl;
function OSSL_STORE_LOADER_settable_ctx_params(loader: POSSL_STORE_LOADER): POSSL_PARAM; cdecl;
function OSSL_STORE_LOADER_new(e: PENGINE; scheme: PIdAnsiChar): POSSL_STORE_LOADER; cdecl; deprecated 'In OpenSSL 3_0_0';
function OSSL_STORE_LOADER_set_open(loader: POSSL_STORE_LOADER; open_function: TOSSL_STORE_open_fn): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function OSSL_STORE_LOADER_set_open_ex(loader: POSSL_STORE_LOADER; open_ex_function: TOSSL_STORE_open_ex_fn): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function OSSL_STORE_LOADER_set_attach(loader: POSSL_STORE_LOADER; attach_function: TOSSL_STORE_attach_fn): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function OSSL_STORE_LOADER_set_ctrl(loader: POSSL_STORE_LOADER; ctrl_function: TOSSL_STORE_ctrl_fn): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function OSSL_STORE_LOADER_set_expect(loader: POSSL_STORE_LOADER; expect_function: TOSSL_STORE_expect_fn): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function OSSL_STORE_LOADER_set_find(loader: POSSL_STORE_LOADER; find_function: TOSSL_STORE_find_fn): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function OSSL_STORE_LOADER_set_load(loader: POSSL_STORE_LOADER; load_function: TOSSL_STORE_load_fn): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function OSSL_STORE_LOADER_set_eof(loader: POSSL_STORE_LOADER; eof_function: TOSSL_STORE_close_fn): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function OSSL_STORE_LOADER_set_error(loader: POSSL_STORE_LOADER; error_function: TOSSL_STORE_close_fn): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function OSSL_STORE_LOADER_set_close(loader: POSSL_STORE_LOADER; close_function: TOSSL_STORE_close_fn): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function OSSL_STORE_LOADER_get0_engine(loader: POSSL_STORE_LOADER): PENGINE; cdecl; deprecated 'In OpenSSL 3_0_0';
function OSSL_STORE_LOADER_get0_scheme(loader: POSSL_STORE_LOADER): PIdAnsiChar; cdecl; deprecated 'In OpenSSL 3_0_0';
function OSSL_STORE_register_loader(loader: POSSL_STORE_LOADER): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function OSSL_STORE_unregister_loader(scheme: PIdAnsiChar): POSSL_STORE_LOADER; cdecl; deprecated 'In OpenSSL 3_0_0';
function OSSL_STORE_do_all_loaders(do_function: TOSSL_STORE_LOADER_do_all_provided_fn_cb; do_arg: Pointer): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
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

function OSSL_STORE_open(uri: PIdAnsiChar; ui_method: PUI_METHOD; ui_data: Pointer; post_process: TOSSL_STORE_post_process_info_fn; post_process_data: Pointer): POSSL_STORE_CTX; cdecl external CLibCrypto name 'OSSL_STORE_open';
function OSSL_STORE_open_ex(uri: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; ui_method: PUI_METHOD; ui_data: Pointer; params: POSSL_PARAM; post_process: TOSSL_STORE_post_process_info_fn; post_process_data: Pointer): POSSL_STORE_CTX; cdecl external CLibCrypto name 'OSSL_STORE_open_ex';
function OSSL_STORE_ctrl(ctx: POSSL_STORE_CTX; cmd: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_ctrl';
function OSSL_STORE_vctrl(ctx: POSSL_STORE_CTX; cmd: TIdC_INT; args: Tva_list): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_vctrl';
function OSSL_STORE_load(ctx: POSSL_STORE_CTX): POSSL_STORE_INFO; cdecl external CLibCrypto name 'OSSL_STORE_load';
function OSSL_STORE_delete(uri: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; ui_method: PUI_METHOD; ui_data: Pointer; params: POSSL_PARAM): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_delete';
function OSSL_STORE_eof(ctx: POSSL_STORE_CTX): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_eof';
function OSSL_STORE_error(ctx: POSSL_STORE_CTX): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_error';
function OSSL_STORE_close(ctx: POSSL_STORE_CTX): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_close';
function OSSL_STORE_attach(bio: PBIO; scheme: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; ui_method: PUI_METHOD; ui_data: Pointer; params: POSSL_PARAM; post_process: TOSSL_STORE_post_process_info_fn; post_process_data: Pointer): POSSL_STORE_CTX; cdecl external CLibCrypto name 'OSSL_STORE_attach';
function OSSL_STORE_INFO_new(_type: TIdC_INT; data: Pointer): POSSL_STORE_INFO; cdecl external CLibCrypto name 'OSSL_STORE_INFO_new';
function OSSL_STORE_INFO_new_NAME(name: PIdAnsiChar): POSSL_STORE_INFO; cdecl external CLibCrypto name 'OSSL_STORE_INFO_new_NAME';
function OSSL_STORE_INFO_set0_NAME_description(info: POSSL_STORE_INFO; desc: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_INFO_set0_NAME_description';
function OSSL_STORE_INFO_new_PARAMS(params: PEVP_PKEY): POSSL_STORE_INFO; cdecl external CLibCrypto name 'OSSL_STORE_INFO_new_PARAMS';
function OSSL_STORE_INFO_new_PUBKEY(pubkey: PEVP_PKEY): POSSL_STORE_INFO; cdecl external CLibCrypto name 'OSSL_STORE_INFO_new_PUBKEY';
function OSSL_STORE_INFO_new_PKEY(pkey: PEVP_PKEY): POSSL_STORE_INFO; cdecl external CLibCrypto name 'OSSL_STORE_INFO_new_PKEY';
function OSSL_STORE_INFO_new_CERT(x509: PX509): POSSL_STORE_INFO; cdecl external CLibCrypto name 'OSSL_STORE_INFO_new_CERT';
function OSSL_STORE_INFO_new_CRL(crl: PX509_CRL): POSSL_STORE_INFO; cdecl external CLibCrypto name 'OSSL_STORE_INFO_new_CRL';
function OSSL_STORE_INFO_get_type(info: POSSL_STORE_INFO): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_INFO_get_type';
function OSSL_STORE_INFO_get0_data(_type: TIdC_INT; info: POSSL_STORE_INFO): Pointer; cdecl external CLibCrypto name 'OSSL_STORE_INFO_get0_data';
function OSSL_STORE_INFO_get0_NAME(info: POSSL_STORE_INFO): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_STORE_INFO_get0_NAME';
function OSSL_STORE_INFO_get1_NAME(info: POSSL_STORE_INFO): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_STORE_INFO_get1_NAME';
function OSSL_STORE_INFO_get0_NAME_description(info: POSSL_STORE_INFO): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_STORE_INFO_get0_NAME_description';
function OSSL_STORE_INFO_get1_NAME_description(info: POSSL_STORE_INFO): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_STORE_INFO_get1_NAME_description';
function OSSL_STORE_INFO_get0_PARAMS(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl external CLibCrypto name 'OSSL_STORE_INFO_get0_PARAMS';
function OSSL_STORE_INFO_get1_PARAMS(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl external CLibCrypto name 'OSSL_STORE_INFO_get1_PARAMS';
function OSSL_STORE_INFO_get0_PUBKEY(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl external CLibCrypto name 'OSSL_STORE_INFO_get0_PUBKEY';
function OSSL_STORE_INFO_get1_PUBKEY(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl external CLibCrypto name 'OSSL_STORE_INFO_get1_PUBKEY';
function OSSL_STORE_INFO_get0_PKEY(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl external CLibCrypto name 'OSSL_STORE_INFO_get0_PKEY';
function OSSL_STORE_INFO_get1_PKEY(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl external CLibCrypto name 'OSSL_STORE_INFO_get1_PKEY';
function OSSL_STORE_INFO_get0_CERT(info: POSSL_STORE_INFO): PX509; cdecl external CLibCrypto name 'OSSL_STORE_INFO_get0_CERT';
function OSSL_STORE_INFO_get1_CERT(info: POSSL_STORE_INFO): PX509; cdecl external CLibCrypto name 'OSSL_STORE_INFO_get1_CERT';
function OSSL_STORE_INFO_get0_CRL(info: POSSL_STORE_INFO): PX509_CRL; cdecl external CLibCrypto name 'OSSL_STORE_INFO_get0_CRL';
function OSSL_STORE_INFO_get1_CRL(info: POSSL_STORE_INFO): PX509_CRL; cdecl external CLibCrypto name 'OSSL_STORE_INFO_get1_CRL';
function OSSL_STORE_INFO_type_string(_type: TIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_STORE_INFO_type_string';
function OSSL_STORE_INFO_free(info: POSSL_STORE_INFO): void; cdecl external CLibCrypto name 'OSSL_STORE_INFO_free';
function OSSL_STORE_supports_search(ctx: POSSL_STORE_CTX; search_type: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_supports_search';
function OSSL_STORE_SEARCH_by_name(name: PX509_NAME): POSSL_STORE_SEARCH; cdecl external CLibCrypto name 'OSSL_STORE_SEARCH_by_name';
function OSSL_STORE_SEARCH_by_issuer_serial(name: PX509_NAME; serial: PASN1_INTEGER): POSSL_STORE_SEARCH; cdecl external CLibCrypto name 'OSSL_STORE_SEARCH_by_issuer_serial';
function OSSL_STORE_SEARCH_by_key_fingerprint(digest: PEVP_MD; bytes: PIdAnsiChar; len: TIdC_SIZET): POSSL_STORE_SEARCH; cdecl external CLibCrypto name 'OSSL_STORE_SEARCH_by_key_fingerprint';
function OSSL_STORE_SEARCH_by_alias(alias: PIdAnsiChar): POSSL_STORE_SEARCH; cdecl external CLibCrypto name 'OSSL_STORE_SEARCH_by_alias';
function OSSL_STORE_SEARCH_free(search: POSSL_STORE_SEARCH): void; cdecl external CLibCrypto name 'OSSL_STORE_SEARCH_free';
function OSSL_STORE_SEARCH_get_type(criterion: POSSL_STORE_SEARCH): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_SEARCH_get_type';
function OSSL_STORE_SEARCH_get0_name(criterion: POSSL_STORE_SEARCH): PX509_NAME; cdecl external CLibCrypto name 'OSSL_STORE_SEARCH_get0_name';
function OSSL_STORE_SEARCH_get0_serial(criterion: POSSL_STORE_SEARCH): PASN1_INTEGER; cdecl external CLibCrypto name 'OSSL_STORE_SEARCH_get0_serial';
function OSSL_STORE_SEARCH_get0_bytes(criterion: POSSL_STORE_SEARCH; length: PIdC_SIZET): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_STORE_SEARCH_get0_bytes';
function OSSL_STORE_SEARCH_get0_string(criterion: POSSL_STORE_SEARCH): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_STORE_SEARCH_get0_string';
function OSSL_STORE_SEARCH_get0_digest(criterion: POSSL_STORE_SEARCH): PEVP_MD; cdecl external CLibCrypto name 'OSSL_STORE_SEARCH_get0_digest';
function OSSL_STORE_expect(ctx: POSSL_STORE_CTX; expected_type: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_expect';
function OSSL_STORE_find(ctx: POSSL_STORE_CTX; search: POSSL_STORE_SEARCH): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_find';
function OSSL_STORE_LOADER_fetch(libctx: POSSL_LIB_CTX; scheme: PIdAnsiChar; properties: PIdAnsiChar): POSSL_STORE_LOADER; cdecl external CLibCrypto name 'OSSL_STORE_LOADER_fetch';
function OSSL_STORE_LOADER_up_ref(loader: POSSL_STORE_LOADER): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_LOADER_up_ref';
function OSSL_STORE_LOADER_free(loader: POSSL_STORE_LOADER): void; cdecl external CLibCrypto name 'OSSL_STORE_LOADER_free';
function OSSL_STORE_LOADER_get0_provider(loader: POSSL_STORE_LOADER): POSSL_PROVIDER; cdecl external CLibCrypto name 'OSSL_STORE_LOADER_get0_provider';
function OSSL_STORE_LOADER_get0_properties(loader: POSSL_STORE_LOADER): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_STORE_LOADER_get0_properties';
function OSSL_STORE_LOADER_get0_description(loader: POSSL_STORE_LOADER): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_STORE_LOADER_get0_description';
function OSSL_STORE_LOADER_is_a(loader: POSSL_STORE_LOADER; scheme: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_LOADER_is_a';
function OSSL_STORE_LOADER_do_all_provided(libctx: POSSL_LIB_CTX; fn: TOSSL_STORE_LOADER_do_all_provided_fn_cb; arg: Pointer): void; cdecl external CLibCrypto name 'OSSL_STORE_LOADER_do_all_provided';
function OSSL_STORE_LOADER_names_do_all(loader: POSSL_STORE_LOADER; fn: TOSSL_STORE_LOADER_names_do_all_fn_cb; data: Pointer): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_LOADER_names_do_all';
function OSSL_STORE_LOADER_settable_ctx_params(loader: POSSL_STORE_LOADER): POSSL_PARAM; cdecl external CLibCrypto name 'OSSL_STORE_LOADER_settable_ctx_params';
function OSSL_STORE_LOADER_new(e: PENGINE; scheme: PIdAnsiChar): POSSL_STORE_LOADER; cdecl external CLibCrypto name 'OSSL_STORE_LOADER_new';
function OSSL_STORE_LOADER_set_open(loader: POSSL_STORE_LOADER; open_function: TOSSL_STORE_open_fn): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_LOADER_set_open';
function OSSL_STORE_LOADER_set_open_ex(loader: POSSL_STORE_LOADER; open_ex_function: TOSSL_STORE_open_ex_fn): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_LOADER_set_open_ex';
function OSSL_STORE_LOADER_set_attach(loader: POSSL_STORE_LOADER; attach_function: TOSSL_STORE_attach_fn): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_LOADER_set_attach';
function OSSL_STORE_LOADER_set_ctrl(loader: POSSL_STORE_LOADER; ctrl_function: TOSSL_STORE_ctrl_fn): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_LOADER_set_ctrl';
function OSSL_STORE_LOADER_set_expect(loader: POSSL_STORE_LOADER; expect_function: TOSSL_STORE_expect_fn): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_LOADER_set_expect';
function OSSL_STORE_LOADER_set_find(loader: POSSL_STORE_LOADER; find_function: TOSSL_STORE_find_fn): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_LOADER_set_find';
function OSSL_STORE_LOADER_set_load(loader: POSSL_STORE_LOADER; load_function: TOSSL_STORE_load_fn): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_LOADER_set_load';
function OSSL_STORE_LOADER_set_eof(loader: POSSL_STORE_LOADER; eof_function: TOSSL_STORE_close_fn): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_LOADER_set_eof';
function OSSL_STORE_LOADER_set_error(loader: POSSL_STORE_LOADER; error_function: TOSSL_STORE_close_fn): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_LOADER_set_error';
function OSSL_STORE_LOADER_set_close(loader: POSSL_STORE_LOADER; close_function: TOSSL_STORE_close_fn): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_LOADER_set_close';
function OSSL_STORE_LOADER_get0_engine(loader: POSSL_STORE_LOADER): PENGINE; cdecl external CLibCrypto name 'OSSL_STORE_LOADER_get0_engine';
function OSSL_STORE_LOADER_get0_scheme(loader: POSSL_STORE_LOADER): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_STORE_LOADER_get0_scheme';
function OSSL_STORE_register_loader(loader: POSSL_STORE_LOADER): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_register_loader';
function OSSL_STORE_unregister_loader(scheme: PIdAnsiChar): POSSL_STORE_LOADER; cdecl external CLibCrypto name 'OSSL_STORE_unregister_loader';
function OSSL_STORE_do_all_loaders(do_function: TOSSL_STORE_LOADER_do_all_provided_fn_cb; do_arg: Pointer): TIdC_INT; cdecl external CLibCrypto name 'OSSL_STORE_do_all_loaders';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  OSSL_STORE_open_procname = 'OSSL_STORE_open';
  OSSL_STORE_open_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_open_ex_procname = 'OSSL_STORE_open_ex';
  OSSL_STORE_open_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_ctrl_procname = 'OSSL_STORE_ctrl';
  OSSL_STORE_ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  OSSL_STORE_ctrl_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_vctrl_procname = 'OSSL_STORE_vctrl';
  OSSL_STORE_vctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  OSSL_STORE_vctrl_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_load_procname = 'OSSL_STORE_load';
  OSSL_STORE_load_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_delete_procname = 'OSSL_STORE_delete';
  OSSL_STORE_delete_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  OSSL_STORE_eof_procname = 'OSSL_STORE_eof';
  OSSL_STORE_eof_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_error_procname = 'OSSL_STORE_error';
  OSSL_STORE_error_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_close_procname = 'OSSL_STORE_close';
  OSSL_STORE_close_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_attach_procname = 'OSSL_STORE_attach';
  OSSL_STORE_attach_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_INFO_new_procname = 'OSSL_STORE_INFO_new';
  OSSL_STORE_INFO_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_INFO_new_NAME_procname = 'OSSL_STORE_INFO_new_NAME';
  OSSL_STORE_INFO_new_NAME_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_INFO_set0_NAME_description_procname = 'OSSL_STORE_INFO_set0_NAME_description';
  OSSL_STORE_INFO_set0_NAME_description_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_INFO_new_PARAMS_procname = 'OSSL_STORE_INFO_new_PARAMS';
  OSSL_STORE_INFO_new_PARAMS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_INFO_new_PUBKEY_procname = 'OSSL_STORE_INFO_new_PUBKEY';
  OSSL_STORE_INFO_new_PUBKEY_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_INFO_new_PKEY_procname = 'OSSL_STORE_INFO_new_PKEY';
  OSSL_STORE_INFO_new_PKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_INFO_new_CERT_procname = 'OSSL_STORE_INFO_new_CERT';
  OSSL_STORE_INFO_new_CERT_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_INFO_new_CRL_procname = 'OSSL_STORE_INFO_new_CRL';
  OSSL_STORE_INFO_new_CRL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_INFO_get_type_procname = 'OSSL_STORE_INFO_get_type';
  OSSL_STORE_INFO_get_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_INFO_get0_data_procname = 'OSSL_STORE_INFO_get0_data';
  OSSL_STORE_INFO_get0_data_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_INFO_get0_NAME_procname = 'OSSL_STORE_INFO_get0_NAME';
  OSSL_STORE_INFO_get0_NAME_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_INFO_get1_NAME_procname = 'OSSL_STORE_INFO_get1_NAME';
  OSSL_STORE_INFO_get1_NAME_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_INFO_get0_NAME_description_procname = 'OSSL_STORE_INFO_get0_NAME_description';
  OSSL_STORE_INFO_get0_NAME_description_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_INFO_get1_NAME_description_procname = 'OSSL_STORE_INFO_get1_NAME_description';
  OSSL_STORE_INFO_get1_NAME_description_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_INFO_get0_PARAMS_procname = 'OSSL_STORE_INFO_get0_PARAMS';
  OSSL_STORE_INFO_get0_PARAMS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_INFO_get1_PARAMS_procname = 'OSSL_STORE_INFO_get1_PARAMS';
  OSSL_STORE_INFO_get1_PARAMS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_INFO_get0_PUBKEY_procname = 'OSSL_STORE_INFO_get0_PUBKEY';
  OSSL_STORE_INFO_get0_PUBKEY_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_INFO_get1_PUBKEY_procname = 'OSSL_STORE_INFO_get1_PUBKEY';
  OSSL_STORE_INFO_get1_PUBKEY_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_INFO_get0_PKEY_procname = 'OSSL_STORE_INFO_get0_PKEY';
  OSSL_STORE_INFO_get0_PKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_INFO_get1_PKEY_procname = 'OSSL_STORE_INFO_get1_PKEY';
  OSSL_STORE_INFO_get1_PKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_INFO_get0_CERT_procname = 'OSSL_STORE_INFO_get0_CERT';
  OSSL_STORE_INFO_get0_CERT_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_INFO_get1_CERT_procname = 'OSSL_STORE_INFO_get1_CERT';
  OSSL_STORE_INFO_get1_CERT_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_INFO_get0_CRL_procname = 'OSSL_STORE_INFO_get0_CRL';
  OSSL_STORE_INFO_get0_CRL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_INFO_get1_CRL_procname = 'OSSL_STORE_INFO_get1_CRL';
  OSSL_STORE_INFO_get1_CRL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_INFO_type_string_procname = 'OSSL_STORE_INFO_type_string';
  OSSL_STORE_INFO_type_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_INFO_free_procname = 'OSSL_STORE_INFO_free';
  OSSL_STORE_INFO_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_supports_search_procname = 'OSSL_STORE_supports_search';
  OSSL_STORE_supports_search_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_SEARCH_by_name_procname = 'OSSL_STORE_SEARCH_by_name';
  OSSL_STORE_SEARCH_by_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_SEARCH_by_issuer_serial_procname = 'OSSL_STORE_SEARCH_by_issuer_serial';
  OSSL_STORE_SEARCH_by_issuer_serial_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_SEARCH_by_key_fingerprint_procname = 'OSSL_STORE_SEARCH_by_key_fingerprint';
  OSSL_STORE_SEARCH_by_key_fingerprint_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_SEARCH_by_alias_procname = 'OSSL_STORE_SEARCH_by_alias';
  OSSL_STORE_SEARCH_by_alias_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_SEARCH_free_procname = 'OSSL_STORE_SEARCH_free';
  OSSL_STORE_SEARCH_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_SEARCH_get_type_procname = 'OSSL_STORE_SEARCH_get_type';
  OSSL_STORE_SEARCH_get_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_SEARCH_get0_name_procname = 'OSSL_STORE_SEARCH_get0_name';
  OSSL_STORE_SEARCH_get0_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_SEARCH_get0_serial_procname = 'OSSL_STORE_SEARCH_get0_serial';
  OSSL_STORE_SEARCH_get0_serial_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_SEARCH_get0_bytes_procname = 'OSSL_STORE_SEARCH_get0_bytes';
  OSSL_STORE_SEARCH_get0_bytes_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_SEARCH_get0_string_procname = 'OSSL_STORE_SEARCH_get0_string';
  OSSL_STORE_SEARCH_get0_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_SEARCH_get0_digest_procname = 'OSSL_STORE_SEARCH_get0_digest';
  OSSL_STORE_SEARCH_get0_digest_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_expect_procname = 'OSSL_STORE_expect';
  OSSL_STORE_expect_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_find_procname = 'OSSL_STORE_find';
  OSSL_STORE_find_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_LOADER_fetch_procname = 'OSSL_STORE_LOADER_fetch';
  OSSL_STORE_LOADER_fetch_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_LOADER_up_ref_procname = 'OSSL_STORE_LOADER_up_ref';
  OSSL_STORE_LOADER_up_ref_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_LOADER_free_procname = 'OSSL_STORE_LOADER_free';
  OSSL_STORE_LOADER_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_STORE_LOADER_get0_provider_procname = 'OSSL_STORE_LOADER_get0_provider';
  OSSL_STORE_LOADER_get0_provider_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_LOADER_get0_properties_procname = 'OSSL_STORE_LOADER_get0_properties';
  OSSL_STORE_LOADER_get0_properties_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_LOADER_get0_description_procname = 'OSSL_STORE_LOADER_get0_description';
  OSSL_STORE_LOADER_get0_description_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_LOADER_is_a_procname = 'OSSL_STORE_LOADER_is_a';
  OSSL_STORE_LOADER_is_a_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_LOADER_do_all_provided_procname = 'OSSL_STORE_LOADER_do_all_provided';
  OSSL_STORE_LOADER_do_all_provided_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_LOADER_names_do_all_procname = 'OSSL_STORE_LOADER_names_do_all';
  OSSL_STORE_LOADER_names_do_all_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_LOADER_settable_ctx_params_procname = 'OSSL_STORE_LOADER_settable_ctx_params';
  OSSL_STORE_LOADER_settable_ctx_params_introduced = (byte(3) shl 8 or byte(6)) shl 8 or byte(0);

  OSSL_STORE_LOADER_new_procname = 'OSSL_STORE_LOADER_new';
  OSSL_STORE_LOADER_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  OSSL_STORE_LOADER_new_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_LOADER_set_open_procname = 'OSSL_STORE_LOADER_set_open';
  OSSL_STORE_LOADER_set_open_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  OSSL_STORE_LOADER_set_open_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_LOADER_set_open_ex_procname = 'OSSL_STORE_LOADER_set_open_ex';
  OSSL_STORE_LOADER_set_open_ex_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_LOADER_set_attach_procname = 'OSSL_STORE_LOADER_set_attach';
  OSSL_STORE_LOADER_set_attach_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_LOADER_set_ctrl_procname = 'OSSL_STORE_LOADER_set_ctrl';
  OSSL_STORE_LOADER_set_ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  OSSL_STORE_LOADER_set_ctrl_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_LOADER_set_expect_procname = 'OSSL_STORE_LOADER_set_expect';
  OSSL_STORE_LOADER_set_expect_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  OSSL_STORE_LOADER_set_expect_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_LOADER_set_find_procname = 'OSSL_STORE_LOADER_set_find';
  OSSL_STORE_LOADER_set_find_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  OSSL_STORE_LOADER_set_find_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_LOADER_set_load_procname = 'OSSL_STORE_LOADER_set_load';
  OSSL_STORE_LOADER_set_load_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  OSSL_STORE_LOADER_set_load_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_LOADER_set_eof_procname = 'OSSL_STORE_LOADER_set_eof';
  OSSL_STORE_LOADER_set_eof_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  OSSL_STORE_LOADER_set_eof_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_LOADER_set_error_procname = 'OSSL_STORE_LOADER_set_error';
  OSSL_STORE_LOADER_set_error_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  OSSL_STORE_LOADER_set_error_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_LOADER_set_close_procname = 'OSSL_STORE_LOADER_set_close';
  OSSL_STORE_LOADER_set_close_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  OSSL_STORE_LOADER_set_close_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_LOADER_get0_engine_procname = 'OSSL_STORE_LOADER_get0_engine';
  OSSL_STORE_LOADER_get0_engine_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  OSSL_STORE_LOADER_get0_engine_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_LOADER_get0_scheme_procname = 'OSSL_STORE_LOADER_get0_scheme';
  OSSL_STORE_LOADER_get0_scheme_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  OSSL_STORE_LOADER_get0_scheme_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_register_loader_procname = 'OSSL_STORE_register_loader';
  OSSL_STORE_register_loader_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  OSSL_STORE_register_loader_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_unregister_loader_procname = 'OSSL_STORE_unregister_loader';
  OSSL_STORE_unregister_loader_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  OSSL_STORE_unregister_loader_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_STORE_do_all_loaders_procname = 'OSSL_STORE_do_all_loaders';
  OSSL_STORE_do_all_loaders_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  OSSL_STORE_do_all_loaders_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_OSSL_STORE_open(uri: PIdAnsiChar; ui_method: PUI_METHOD; ui_data: Pointer; post_process: TOSSL_STORE_post_process_info_fn; post_process_data: Pointer): POSSL_STORE_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_open_procname);
end;

function ERR_OSSL_STORE_open_ex(uri: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; ui_method: PUI_METHOD; ui_data: Pointer; params: POSSL_PARAM; post_process: TOSSL_STORE_post_process_info_fn; post_process_data: Pointer): POSSL_STORE_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_open_ex_procname);
end;

function ERR_OSSL_STORE_ctrl(ctx: POSSL_STORE_CTX; cmd: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_ctrl_procname);
end;

function ERR_OSSL_STORE_vctrl(ctx: POSSL_STORE_CTX; cmd: TIdC_INT; args: Tva_list): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_vctrl_procname);
end;

function ERR_OSSL_STORE_load(ctx: POSSL_STORE_CTX): POSSL_STORE_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_load_procname);
end;

function ERR_OSSL_STORE_delete(uri: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; ui_method: PUI_METHOD; ui_data: Pointer; params: POSSL_PARAM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_delete_procname);
end;

function ERR_OSSL_STORE_eof(ctx: POSSL_STORE_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_eof_procname);
end;

function ERR_OSSL_STORE_error(ctx: POSSL_STORE_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_error_procname);
end;

function ERR_OSSL_STORE_close(ctx: POSSL_STORE_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_close_procname);
end;

function ERR_OSSL_STORE_attach(bio: PBIO; scheme: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; ui_method: PUI_METHOD; ui_data: Pointer; params: POSSL_PARAM; post_process: TOSSL_STORE_post_process_info_fn; post_process_data: Pointer): POSSL_STORE_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_attach_procname);
end;

function ERR_OSSL_STORE_INFO_new(_type: TIdC_INT; data: Pointer): POSSL_STORE_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_new_procname);
end;

function ERR_OSSL_STORE_INFO_new_NAME(name: PIdAnsiChar): POSSL_STORE_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_new_NAME_procname);
end;

function ERR_OSSL_STORE_INFO_set0_NAME_description(info: POSSL_STORE_INFO; desc: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_set0_NAME_description_procname);
end;

function ERR_OSSL_STORE_INFO_new_PARAMS(params: PEVP_PKEY): POSSL_STORE_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_new_PARAMS_procname);
end;

function ERR_OSSL_STORE_INFO_new_PUBKEY(pubkey: PEVP_PKEY): POSSL_STORE_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_new_PUBKEY_procname);
end;

function ERR_OSSL_STORE_INFO_new_PKEY(pkey: PEVP_PKEY): POSSL_STORE_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_new_PKEY_procname);
end;

function ERR_OSSL_STORE_INFO_new_CERT(x509: PX509): POSSL_STORE_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_new_CERT_procname);
end;

function ERR_OSSL_STORE_INFO_new_CRL(crl: PX509_CRL): POSSL_STORE_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_new_CRL_procname);
end;

function ERR_OSSL_STORE_INFO_get_type(info: POSSL_STORE_INFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get_type_procname);
end;

function ERR_OSSL_STORE_INFO_get0_data(_type: TIdC_INT; info: POSSL_STORE_INFO): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get0_data_procname);
end;

function ERR_OSSL_STORE_INFO_get0_NAME(info: POSSL_STORE_INFO): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get0_NAME_procname);
end;

function ERR_OSSL_STORE_INFO_get1_NAME(info: POSSL_STORE_INFO): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get1_NAME_procname);
end;

function ERR_OSSL_STORE_INFO_get0_NAME_description(info: POSSL_STORE_INFO): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get0_NAME_description_procname);
end;

function ERR_OSSL_STORE_INFO_get1_NAME_description(info: POSSL_STORE_INFO): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get1_NAME_description_procname);
end;

function ERR_OSSL_STORE_INFO_get0_PARAMS(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get0_PARAMS_procname);
end;

function ERR_OSSL_STORE_INFO_get1_PARAMS(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get1_PARAMS_procname);
end;

function ERR_OSSL_STORE_INFO_get0_PUBKEY(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get0_PUBKEY_procname);
end;

function ERR_OSSL_STORE_INFO_get1_PUBKEY(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get1_PUBKEY_procname);
end;

function ERR_OSSL_STORE_INFO_get0_PKEY(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get0_PKEY_procname);
end;

function ERR_OSSL_STORE_INFO_get1_PKEY(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get1_PKEY_procname);
end;

function ERR_OSSL_STORE_INFO_get0_CERT(info: POSSL_STORE_INFO): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get0_CERT_procname);
end;

function ERR_OSSL_STORE_INFO_get1_CERT(info: POSSL_STORE_INFO): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get1_CERT_procname);
end;

function ERR_OSSL_STORE_INFO_get0_CRL(info: POSSL_STORE_INFO): PX509_CRL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get0_CRL_procname);
end;

function ERR_OSSL_STORE_INFO_get1_CRL(info: POSSL_STORE_INFO): PX509_CRL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_get1_CRL_procname);
end;

function ERR_OSSL_STORE_INFO_type_string(_type: TIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_type_string_procname);
end;

function ERR_OSSL_STORE_INFO_free(info: POSSL_STORE_INFO): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_INFO_free_procname);
end;

function ERR_OSSL_STORE_supports_search(ctx: POSSL_STORE_CTX; search_type: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_supports_search_procname);
end;

function ERR_OSSL_STORE_SEARCH_by_name(name: PX509_NAME): POSSL_STORE_SEARCH; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_SEARCH_by_name_procname);
end;

function ERR_OSSL_STORE_SEARCH_by_issuer_serial(name: PX509_NAME; serial: PASN1_INTEGER): POSSL_STORE_SEARCH; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_SEARCH_by_issuer_serial_procname);
end;

function ERR_OSSL_STORE_SEARCH_by_key_fingerprint(digest: PEVP_MD; bytes: PIdAnsiChar; len: TIdC_SIZET): POSSL_STORE_SEARCH; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_SEARCH_by_key_fingerprint_procname);
end;

function ERR_OSSL_STORE_SEARCH_by_alias(alias: PIdAnsiChar): POSSL_STORE_SEARCH; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_SEARCH_by_alias_procname);
end;

function ERR_OSSL_STORE_SEARCH_free(search: POSSL_STORE_SEARCH): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_SEARCH_free_procname);
end;

function ERR_OSSL_STORE_SEARCH_get_type(criterion: POSSL_STORE_SEARCH): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_SEARCH_get_type_procname);
end;

function ERR_OSSL_STORE_SEARCH_get0_name(criterion: POSSL_STORE_SEARCH): PX509_NAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_SEARCH_get0_name_procname);
end;

function ERR_OSSL_STORE_SEARCH_get0_serial(criterion: POSSL_STORE_SEARCH): PASN1_INTEGER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_SEARCH_get0_serial_procname);
end;

function ERR_OSSL_STORE_SEARCH_get0_bytes(criterion: POSSL_STORE_SEARCH; length: PIdC_SIZET): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_SEARCH_get0_bytes_procname);
end;

function ERR_OSSL_STORE_SEARCH_get0_string(criterion: POSSL_STORE_SEARCH): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_SEARCH_get0_string_procname);
end;

function ERR_OSSL_STORE_SEARCH_get0_digest(criterion: POSSL_STORE_SEARCH): PEVP_MD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_SEARCH_get0_digest_procname);
end;

function ERR_OSSL_STORE_expect(ctx: POSSL_STORE_CTX; expected_type: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_expect_procname);
end;

function ERR_OSSL_STORE_find(ctx: POSSL_STORE_CTX; search: POSSL_STORE_SEARCH): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_find_procname);
end;

function ERR_OSSL_STORE_LOADER_fetch(libctx: POSSL_LIB_CTX; scheme: PIdAnsiChar; properties: PIdAnsiChar): POSSL_STORE_LOADER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_fetch_procname);
end;

function ERR_OSSL_STORE_LOADER_up_ref(loader: POSSL_STORE_LOADER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_up_ref_procname);
end;

function ERR_OSSL_STORE_LOADER_free(loader: POSSL_STORE_LOADER): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_free_procname);
end;

function ERR_OSSL_STORE_LOADER_get0_provider(loader: POSSL_STORE_LOADER): POSSL_PROVIDER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_get0_provider_procname);
end;

function ERR_OSSL_STORE_LOADER_get0_properties(loader: POSSL_STORE_LOADER): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_get0_properties_procname);
end;

function ERR_OSSL_STORE_LOADER_get0_description(loader: POSSL_STORE_LOADER): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_get0_description_procname);
end;

function ERR_OSSL_STORE_LOADER_is_a(loader: POSSL_STORE_LOADER; scheme: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_is_a_procname);
end;

function ERR_OSSL_STORE_LOADER_do_all_provided(libctx: POSSL_LIB_CTX; fn: TOSSL_STORE_LOADER_do_all_provided_fn_cb; arg: Pointer): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_do_all_provided_procname);
end;

function ERR_OSSL_STORE_LOADER_names_do_all(loader: POSSL_STORE_LOADER; fn: TOSSL_STORE_LOADER_names_do_all_fn_cb; data: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_names_do_all_procname);
end;

function ERR_OSSL_STORE_LOADER_settable_ctx_params(loader: POSSL_STORE_LOADER): POSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_settable_ctx_params_procname);
end;

function ERR_OSSL_STORE_LOADER_new(e: PENGINE; scheme: PIdAnsiChar): POSSL_STORE_LOADER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_new_procname);
end;

function ERR_OSSL_STORE_LOADER_set_open(loader: POSSL_STORE_LOADER; open_function: TOSSL_STORE_open_fn): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_set_open_procname);
end;

function ERR_OSSL_STORE_LOADER_set_open_ex(loader: POSSL_STORE_LOADER; open_ex_function: TOSSL_STORE_open_ex_fn): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_set_open_ex_procname);
end;

function ERR_OSSL_STORE_LOADER_set_attach(loader: POSSL_STORE_LOADER; attach_function: TOSSL_STORE_attach_fn): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_set_attach_procname);
end;

function ERR_OSSL_STORE_LOADER_set_ctrl(loader: POSSL_STORE_LOADER; ctrl_function: TOSSL_STORE_ctrl_fn): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_set_ctrl_procname);
end;

function ERR_OSSL_STORE_LOADER_set_expect(loader: POSSL_STORE_LOADER; expect_function: TOSSL_STORE_expect_fn): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_set_expect_procname);
end;

function ERR_OSSL_STORE_LOADER_set_find(loader: POSSL_STORE_LOADER; find_function: TOSSL_STORE_find_fn): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_set_find_procname);
end;

function ERR_OSSL_STORE_LOADER_set_load(loader: POSSL_STORE_LOADER; load_function: TOSSL_STORE_load_fn): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_set_load_procname);
end;

function ERR_OSSL_STORE_LOADER_set_eof(loader: POSSL_STORE_LOADER; eof_function: TOSSL_STORE_close_fn): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_set_eof_procname);
end;

function ERR_OSSL_STORE_LOADER_set_error(loader: POSSL_STORE_LOADER; error_function: TOSSL_STORE_close_fn): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_set_error_procname);
end;

function ERR_OSSL_STORE_LOADER_set_close(loader: POSSL_STORE_LOADER; close_function: TOSSL_STORE_close_fn): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_set_close_procname);
end;

function ERR_OSSL_STORE_LOADER_get0_engine(loader: POSSL_STORE_LOADER): PENGINE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_get0_engine_procname);
end;

function ERR_OSSL_STORE_LOADER_get0_scheme(loader: POSSL_STORE_LOADER): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_LOADER_get0_scheme_procname);
end;

function ERR_OSSL_STORE_register_loader(loader: POSSL_STORE_LOADER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_register_loader_procname);
end;

function ERR_OSSL_STORE_unregister_loader(scheme: PIdAnsiChar): POSSL_STORE_LOADER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_unregister_loader_procname);
end;

function ERR_OSSL_STORE_do_all_loaders(do_function: TOSSL_STORE_LOADER_do_all_provided_fn_cb; do_arg: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STORE_do_all_loaders_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  OSSL_STORE_open := LoadLibFunction(ADllHandle, OSSL_STORE_open_procname);
  FuncLoadError := not assigned(OSSL_STORE_open);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_open_allownil)}
    OSSL_STORE_open := ERR_OSSL_STORE_open;
    {$ifend}
    {$if declared(OSSL_STORE_open_introduced)}
    if LibVersion < OSSL_STORE_open_introduced then
    begin
      {$if declared(FC_OSSL_STORE_open)}
      OSSL_STORE_open := FC_OSSL_STORE_open;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_open_removed)}
    if OSSL_STORE_open_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_open)}
      OSSL_STORE_open := _OSSL_STORE_open;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_open_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_open');
    {$ifend}
  end;
  
  OSSL_STORE_open_ex := LoadLibFunction(ADllHandle, OSSL_STORE_open_ex_procname);
  FuncLoadError := not assigned(OSSL_STORE_open_ex);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_open_ex_allownil)}
    OSSL_STORE_open_ex := ERR_OSSL_STORE_open_ex;
    {$ifend}
    {$if declared(OSSL_STORE_open_ex_introduced)}
    if LibVersion < OSSL_STORE_open_ex_introduced then
    begin
      {$if declared(FC_OSSL_STORE_open_ex)}
      OSSL_STORE_open_ex := FC_OSSL_STORE_open_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_open_ex_removed)}
    if OSSL_STORE_open_ex_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_open_ex)}
      OSSL_STORE_open_ex := _OSSL_STORE_open_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_open_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_open_ex');
    {$ifend}
  end;
  
  OSSL_STORE_ctrl := LoadLibFunction(ADllHandle, OSSL_STORE_ctrl_procname);
  FuncLoadError := not assigned(OSSL_STORE_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_ctrl_allownil)}
    OSSL_STORE_ctrl := ERR_OSSL_STORE_ctrl;
    {$ifend}
    {$if declared(OSSL_STORE_ctrl_introduced)}
    if LibVersion < OSSL_STORE_ctrl_introduced then
    begin
      {$if declared(FC_OSSL_STORE_ctrl)}
      OSSL_STORE_ctrl := FC_OSSL_STORE_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_ctrl_removed)}
    if OSSL_STORE_ctrl_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_ctrl)}
      OSSL_STORE_ctrl := _OSSL_STORE_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_ctrl');
    {$ifend}
  end;
  
  OSSL_STORE_vctrl := LoadLibFunction(ADllHandle, OSSL_STORE_vctrl_procname);
  FuncLoadError := not assigned(OSSL_STORE_vctrl);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_vctrl_allownil)}
    OSSL_STORE_vctrl := ERR_OSSL_STORE_vctrl;
    {$ifend}
    {$if declared(OSSL_STORE_vctrl_introduced)}
    if LibVersion < OSSL_STORE_vctrl_introduced then
    begin
      {$if declared(FC_OSSL_STORE_vctrl)}
      OSSL_STORE_vctrl := FC_OSSL_STORE_vctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_vctrl_removed)}
    if OSSL_STORE_vctrl_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_vctrl)}
      OSSL_STORE_vctrl := _OSSL_STORE_vctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_vctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_vctrl');
    {$ifend}
  end;
  
  OSSL_STORE_load := LoadLibFunction(ADllHandle, OSSL_STORE_load_procname);
  FuncLoadError := not assigned(OSSL_STORE_load);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_load_allownil)}
    OSSL_STORE_load := ERR_OSSL_STORE_load;
    {$ifend}
    {$if declared(OSSL_STORE_load_introduced)}
    if LibVersion < OSSL_STORE_load_introduced then
    begin
      {$if declared(FC_OSSL_STORE_load)}
      OSSL_STORE_load := FC_OSSL_STORE_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_load_removed)}
    if OSSL_STORE_load_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_load)}
      OSSL_STORE_load := _OSSL_STORE_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_load_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_load');
    {$ifend}
  end;
  
  OSSL_STORE_delete := LoadLibFunction(ADllHandle, OSSL_STORE_delete_procname);
  FuncLoadError := not assigned(OSSL_STORE_delete);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_delete_allownil)}
    OSSL_STORE_delete := ERR_OSSL_STORE_delete;
    {$ifend}
    {$if declared(OSSL_STORE_delete_introduced)}
    if LibVersion < OSSL_STORE_delete_introduced then
    begin
      {$if declared(FC_OSSL_STORE_delete)}
      OSSL_STORE_delete := FC_OSSL_STORE_delete;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_delete_removed)}
    if OSSL_STORE_delete_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_delete)}
      OSSL_STORE_delete := _OSSL_STORE_delete;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_delete_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_delete');
    {$ifend}
  end;
  
  OSSL_STORE_eof := LoadLibFunction(ADllHandle, OSSL_STORE_eof_procname);
  FuncLoadError := not assigned(OSSL_STORE_eof);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_eof_allownil)}
    OSSL_STORE_eof := ERR_OSSL_STORE_eof;
    {$ifend}
    {$if declared(OSSL_STORE_eof_introduced)}
    if LibVersion < OSSL_STORE_eof_introduced then
    begin
      {$if declared(FC_OSSL_STORE_eof)}
      OSSL_STORE_eof := FC_OSSL_STORE_eof;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_eof_removed)}
    if OSSL_STORE_eof_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_eof)}
      OSSL_STORE_eof := _OSSL_STORE_eof;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_eof_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_eof');
    {$ifend}
  end;
  
  OSSL_STORE_error := LoadLibFunction(ADllHandle, OSSL_STORE_error_procname);
  FuncLoadError := not assigned(OSSL_STORE_error);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_error_allownil)}
    OSSL_STORE_error := ERR_OSSL_STORE_error;
    {$ifend}
    {$if declared(OSSL_STORE_error_introduced)}
    if LibVersion < OSSL_STORE_error_introduced then
    begin
      {$if declared(FC_OSSL_STORE_error)}
      OSSL_STORE_error := FC_OSSL_STORE_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_error_removed)}
    if OSSL_STORE_error_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_error)}
      OSSL_STORE_error := _OSSL_STORE_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_error_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_error');
    {$ifend}
  end;
  
  OSSL_STORE_close := LoadLibFunction(ADllHandle, OSSL_STORE_close_procname);
  FuncLoadError := not assigned(OSSL_STORE_close);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_close_allownil)}
    OSSL_STORE_close := ERR_OSSL_STORE_close;
    {$ifend}
    {$if declared(OSSL_STORE_close_introduced)}
    if LibVersion < OSSL_STORE_close_introduced then
    begin
      {$if declared(FC_OSSL_STORE_close)}
      OSSL_STORE_close := FC_OSSL_STORE_close;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_close_removed)}
    if OSSL_STORE_close_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_close)}
      OSSL_STORE_close := _OSSL_STORE_close;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_close_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_close');
    {$ifend}
  end;
  
  OSSL_STORE_attach := LoadLibFunction(ADllHandle, OSSL_STORE_attach_procname);
  FuncLoadError := not assigned(OSSL_STORE_attach);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_attach_allownil)}
    OSSL_STORE_attach := ERR_OSSL_STORE_attach;
    {$ifend}
    {$if declared(OSSL_STORE_attach_introduced)}
    if LibVersion < OSSL_STORE_attach_introduced then
    begin
      {$if declared(FC_OSSL_STORE_attach)}
      OSSL_STORE_attach := FC_OSSL_STORE_attach;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_attach_removed)}
    if OSSL_STORE_attach_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_attach)}
      OSSL_STORE_attach := _OSSL_STORE_attach;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_attach_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_attach');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_new := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_new_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_new_allownil)}
    OSSL_STORE_INFO_new := ERR_OSSL_STORE_INFO_new;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_introduced)}
    if LibVersion < OSSL_STORE_INFO_new_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_new)}
      OSSL_STORE_INFO_new := FC_OSSL_STORE_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_removed)}
    if OSSL_STORE_INFO_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_new)}
      OSSL_STORE_INFO_new := _OSSL_STORE_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_new');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_new_NAME := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_new_NAME_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_new_NAME);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_new_NAME_allownil)}
    OSSL_STORE_INFO_new_NAME := ERR_OSSL_STORE_INFO_new_NAME;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_NAME_introduced)}
    if LibVersion < OSSL_STORE_INFO_new_NAME_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_new_NAME)}
      OSSL_STORE_INFO_new_NAME := FC_OSSL_STORE_INFO_new_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_NAME_removed)}
    if OSSL_STORE_INFO_new_NAME_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_new_NAME)}
      OSSL_STORE_INFO_new_NAME := _OSSL_STORE_INFO_new_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_new_NAME_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_new_NAME');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_set0_NAME_description := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_set0_NAME_description_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_set0_NAME_description);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_set0_NAME_description_allownil)}
    OSSL_STORE_INFO_set0_NAME_description := ERR_OSSL_STORE_INFO_set0_NAME_description;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_set0_NAME_description_introduced)}
    if LibVersion < OSSL_STORE_INFO_set0_NAME_description_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_set0_NAME_description)}
      OSSL_STORE_INFO_set0_NAME_description := FC_OSSL_STORE_INFO_set0_NAME_description;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_set0_NAME_description_removed)}
    if OSSL_STORE_INFO_set0_NAME_description_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_set0_NAME_description)}
      OSSL_STORE_INFO_set0_NAME_description := _OSSL_STORE_INFO_set0_NAME_description;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_set0_NAME_description_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_set0_NAME_description');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_new_PARAMS := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_new_PARAMS_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_new_PARAMS);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_new_PARAMS_allownil)}
    OSSL_STORE_INFO_new_PARAMS := ERR_OSSL_STORE_INFO_new_PARAMS;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_PARAMS_introduced)}
    if LibVersion < OSSL_STORE_INFO_new_PARAMS_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_new_PARAMS)}
      OSSL_STORE_INFO_new_PARAMS := FC_OSSL_STORE_INFO_new_PARAMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_PARAMS_removed)}
    if OSSL_STORE_INFO_new_PARAMS_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_new_PARAMS)}
      OSSL_STORE_INFO_new_PARAMS := _OSSL_STORE_INFO_new_PARAMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_new_PARAMS_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_new_PARAMS');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_new_PUBKEY := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_new_PUBKEY_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_new_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_new_PUBKEY_allownil)}
    OSSL_STORE_INFO_new_PUBKEY := ERR_OSSL_STORE_INFO_new_PUBKEY;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_PUBKEY_introduced)}
    if LibVersion < OSSL_STORE_INFO_new_PUBKEY_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_new_PUBKEY)}
      OSSL_STORE_INFO_new_PUBKEY := FC_OSSL_STORE_INFO_new_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_PUBKEY_removed)}
    if OSSL_STORE_INFO_new_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_new_PUBKEY)}
      OSSL_STORE_INFO_new_PUBKEY := _OSSL_STORE_INFO_new_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_new_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_new_PUBKEY');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_new_PKEY := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_new_PKEY_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_new_PKEY);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_new_PKEY_allownil)}
    OSSL_STORE_INFO_new_PKEY := ERR_OSSL_STORE_INFO_new_PKEY;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_PKEY_introduced)}
    if LibVersion < OSSL_STORE_INFO_new_PKEY_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_new_PKEY)}
      OSSL_STORE_INFO_new_PKEY := FC_OSSL_STORE_INFO_new_PKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_PKEY_removed)}
    if OSSL_STORE_INFO_new_PKEY_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_new_PKEY)}
      OSSL_STORE_INFO_new_PKEY := _OSSL_STORE_INFO_new_PKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_new_PKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_new_PKEY');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_new_CERT := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_new_CERT_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_new_CERT);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_new_CERT_allownil)}
    OSSL_STORE_INFO_new_CERT := ERR_OSSL_STORE_INFO_new_CERT;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_CERT_introduced)}
    if LibVersion < OSSL_STORE_INFO_new_CERT_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_new_CERT)}
      OSSL_STORE_INFO_new_CERT := FC_OSSL_STORE_INFO_new_CERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_CERT_removed)}
    if OSSL_STORE_INFO_new_CERT_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_new_CERT)}
      OSSL_STORE_INFO_new_CERT := _OSSL_STORE_INFO_new_CERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_new_CERT_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_new_CERT');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_new_CRL := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_new_CRL_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_new_CRL);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_new_CRL_allownil)}
    OSSL_STORE_INFO_new_CRL := ERR_OSSL_STORE_INFO_new_CRL;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_CRL_introduced)}
    if LibVersion < OSSL_STORE_INFO_new_CRL_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_new_CRL)}
      OSSL_STORE_INFO_new_CRL := FC_OSSL_STORE_INFO_new_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_new_CRL_removed)}
    if OSSL_STORE_INFO_new_CRL_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_new_CRL)}
      OSSL_STORE_INFO_new_CRL := _OSSL_STORE_INFO_new_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_new_CRL_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_new_CRL');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_get_type := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get_type_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get_type);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get_type_allownil)}
    OSSL_STORE_INFO_get_type := ERR_OSSL_STORE_INFO_get_type;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get_type_introduced)}
    if LibVersion < OSSL_STORE_INFO_get_type_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get_type)}
      OSSL_STORE_INFO_get_type := FC_OSSL_STORE_INFO_get_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get_type_removed)}
    if OSSL_STORE_INFO_get_type_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get_type)}
      OSSL_STORE_INFO_get_type := _OSSL_STORE_INFO_get_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get_type_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get_type');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_get0_data := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get0_data_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get0_data);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get0_data_allownil)}
    OSSL_STORE_INFO_get0_data := ERR_OSSL_STORE_INFO_get0_data;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_data_introduced)}
    if LibVersion < OSSL_STORE_INFO_get0_data_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get0_data)}
      OSSL_STORE_INFO_get0_data := FC_OSSL_STORE_INFO_get0_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_data_removed)}
    if OSSL_STORE_INFO_get0_data_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get0_data)}
      OSSL_STORE_INFO_get0_data := _OSSL_STORE_INFO_get0_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get0_data_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get0_data');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_get0_NAME := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get0_NAME_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get0_NAME);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get0_NAME_allownil)}
    OSSL_STORE_INFO_get0_NAME := ERR_OSSL_STORE_INFO_get0_NAME;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_NAME_introduced)}
    if LibVersion < OSSL_STORE_INFO_get0_NAME_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get0_NAME)}
      OSSL_STORE_INFO_get0_NAME := FC_OSSL_STORE_INFO_get0_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_NAME_removed)}
    if OSSL_STORE_INFO_get0_NAME_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get0_NAME)}
      OSSL_STORE_INFO_get0_NAME := _OSSL_STORE_INFO_get0_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get0_NAME_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get0_NAME');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_get1_NAME := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get1_NAME_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get1_NAME);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get1_NAME_allownil)}
    OSSL_STORE_INFO_get1_NAME := ERR_OSSL_STORE_INFO_get1_NAME;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_NAME_introduced)}
    if LibVersion < OSSL_STORE_INFO_get1_NAME_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get1_NAME)}
      OSSL_STORE_INFO_get1_NAME := FC_OSSL_STORE_INFO_get1_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_NAME_removed)}
    if OSSL_STORE_INFO_get1_NAME_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get1_NAME)}
      OSSL_STORE_INFO_get1_NAME := _OSSL_STORE_INFO_get1_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get1_NAME_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get1_NAME');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_get0_NAME_description := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get0_NAME_description_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get0_NAME_description);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get0_NAME_description_allownil)}
    OSSL_STORE_INFO_get0_NAME_description := ERR_OSSL_STORE_INFO_get0_NAME_description;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_NAME_description_introduced)}
    if LibVersion < OSSL_STORE_INFO_get0_NAME_description_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get0_NAME_description)}
      OSSL_STORE_INFO_get0_NAME_description := FC_OSSL_STORE_INFO_get0_NAME_description;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_NAME_description_removed)}
    if OSSL_STORE_INFO_get0_NAME_description_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get0_NAME_description)}
      OSSL_STORE_INFO_get0_NAME_description := _OSSL_STORE_INFO_get0_NAME_description;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get0_NAME_description_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get0_NAME_description');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_get1_NAME_description := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get1_NAME_description_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get1_NAME_description);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get1_NAME_description_allownil)}
    OSSL_STORE_INFO_get1_NAME_description := ERR_OSSL_STORE_INFO_get1_NAME_description;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_NAME_description_introduced)}
    if LibVersion < OSSL_STORE_INFO_get1_NAME_description_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get1_NAME_description)}
      OSSL_STORE_INFO_get1_NAME_description := FC_OSSL_STORE_INFO_get1_NAME_description;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_NAME_description_removed)}
    if OSSL_STORE_INFO_get1_NAME_description_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get1_NAME_description)}
      OSSL_STORE_INFO_get1_NAME_description := _OSSL_STORE_INFO_get1_NAME_description;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get1_NAME_description_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get1_NAME_description');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_get0_PARAMS := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get0_PARAMS_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get0_PARAMS);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get0_PARAMS_allownil)}
    OSSL_STORE_INFO_get0_PARAMS := ERR_OSSL_STORE_INFO_get0_PARAMS;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_PARAMS_introduced)}
    if LibVersion < OSSL_STORE_INFO_get0_PARAMS_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get0_PARAMS)}
      OSSL_STORE_INFO_get0_PARAMS := FC_OSSL_STORE_INFO_get0_PARAMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_PARAMS_removed)}
    if OSSL_STORE_INFO_get0_PARAMS_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get0_PARAMS)}
      OSSL_STORE_INFO_get0_PARAMS := _OSSL_STORE_INFO_get0_PARAMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get0_PARAMS_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get0_PARAMS');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_get1_PARAMS := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get1_PARAMS_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get1_PARAMS);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get1_PARAMS_allownil)}
    OSSL_STORE_INFO_get1_PARAMS := ERR_OSSL_STORE_INFO_get1_PARAMS;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_PARAMS_introduced)}
    if LibVersion < OSSL_STORE_INFO_get1_PARAMS_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get1_PARAMS)}
      OSSL_STORE_INFO_get1_PARAMS := FC_OSSL_STORE_INFO_get1_PARAMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_PARAMS_removed)}
    if OSSL_STORE_INFO_get1_PARAMS_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get1_PARAMS)}
      OSSL_STORE_INFO_get1_PARAMS := _OSSL_STORE_INFO_get1_PARAMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get1_PARAMS_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get1_PARAMS');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_get0_PUBKEY := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get0_PUBKEY_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get0_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get0_PUBKEY_allownil)}
    OSSL_STORE_INFO_get0_PUBKEY := ERR_OSSL_STORE_INFO_get0_PUBKEY;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_PUBKEY_introduced)}
    if LibVersion < OSSL_STORE_INFO_get0_PUBKEY_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get0_PUBKEY)}
      OSSL_STORE_INFO_get0_PUBKEY := FC_OSSL_STORE_INFO_get0_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_PUBKEY_removed)}
    if OSSL_STORE_INFO_get0_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get0_PUBKEY)}
      OSSL_STORE_INFO_get0_PUBKEY := _OSSL_STORE_INFO_get0_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get0_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get0_PUBKEY');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_get1_PUBKEY := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get1_PUBKEY_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get1_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get1_PUBKEY_allownil)}
    OSSL_STORE_INFO_get1_PUBKEY := ERR_OSSL_STORE_INFO_get1_PUBKEY;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_PUBKEY_introduced)}
    if LibVersion < OSSL_STORE_INFO_get1_PUBKEY_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get1_PUBKEY)}
      OSSL_STORE_INFO_get1_PUBKEY := FC_OSSL_STORE_INFO_get1_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_PUBKEY_removed)}
    if OSSL_STORE_INFO_get1_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get1_PUBKEY)}
      OSSL_STORE_INFO_get1_PUBKEY := _OSSL_STORE_INFO_get1_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get1_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get1_PUBKEY');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_get0_PKEY := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get0_PKEY_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get0_PKEY);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get0_PKEY_allownil)}
    OSSL_STORE_INFO_get0_PKEY := ERR_OSSL_STORE_INFO_get0_PKEY;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_PKEY_introduced)}
    if LibVersion < OSSL_STORE_INFO_get0_PKEY_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get0_PKEY)}
      OSSL_STORE_INFO_get0_PKEY := FC_OSSL_STORE_INFO_get0_PKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_PKEY_removed)}
    if OSSL_STORE_INFO_get0_PKEY_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get0_PKEY)}
      OSSL_STORE_INFO_get0_PKEY := _OSSL_STORE_INFO_get0_PKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get0_PKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get0_PKEY');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_get1_PKEY := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get1_PKEY_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get1_PKEY);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get1_PKEY_allownil)}
    OSSL_STORE_INFO_get1_PKEY := ERR_OSSL_STORE_INFO_get1_PKEY;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_PKEY_introduced)}
    if LibVersion < OSSL_STORE_INFO_get1_PKEY_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get1_PKEY)}
      OSSL_STORE_INFO_get1_PKEY := FC_OSSL_STORE_INFO_get1_PKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_PKEY_removed)}
    if OSSL_STORE_INFO_get1_PKEY_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get1_PKEY)}
      OSSL_STORE_INFO_get1_PKEY := _OSSL_STORE_INFO_get1_PKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get1_PKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get1_PKEY');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_get0_CERT := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get0_CERT_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get0_CERT);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get0_CERT_allownil)}
    OSSL_STORE_INFO_get0_CERT := ERR_OSSL_STORE_INFO_get0_CERT;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_CERT_introduced)}
    if LibVersion < OSSL_STORE_INFO_get0_CERT_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get0_CERT)}
      OSSL_STORE_INFO_get0_CERT := FC_OSSL_STORE_INFO_get0_CERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_CERT_removed)}
    if OSSL_STORE_INFO_get0_CERT_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get0_CERT)}
      OSSL_STORE_INFO_get0_CERT := _OSSL_STORE_INFO_get0_CERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get0_CERT_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get0_CERT');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_get1_CERT := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get1_CERT_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get1_CERT);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get1_CERT_allownil)}
    OSSL_STORE_INFO_get1_CERT := ERR_OSSL_STORE_INFO_get1_CERT;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_CERT_introduced)}
    if LibVersion < OSSL_STORE_INFO_get1_CERT_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get1_CERT)}
      OSSL_STORE_INFO_get1_CERT := FC_OSSL_STORE_INFO_get1_CERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_CERT_removed)}
    if OSSL_STORE_INFO_get1_CERT_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get1_CERT)}
      OSSL_STORE_INFO_get1_CERT := _OSSL_STORE_INFO_get1_CERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get1_CERT_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get1_CERT');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_get0_CRL := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get0_CRL_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get0_CRL);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get0_CRL_allownil)}
    OSSL_STORE_INFO_get0_CRL := ERR_OSSL_STORE_INFO_get0_CRL;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_CRL_introduced)}
    if LibVersion < OSSL_STORE_INFO_get0_CRL_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get0_CRL)}
      OSSL_STORE_INFO_get0_CRL := FC_OSSL_STORE_INFO_get0_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get0_CRL_removed)}
    if OSSL_STORE_INFO_get0_CRL_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get0_CRL)}
      OSSL_STORE_INFO_get0_CRL := _OSSL_STORE_INFO_get0_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get0_CRL_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get0_CRL');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_get1_CRL := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_get1_CRL_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_get1_CRL);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_get1_CRL_allownil)}
    OSSL_STORE_INFO_get1_CRL := ERR_OSSL_STORE_INFO_get1_CRL;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_CRL_introduced)}
    if LibVersion < OSSL_STORE_INFO_get1_CRL_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_get1_CRL)}
      OSSL_STORE_INFO_get1_CRL := FC_OSSL_STORE_INFO_get1_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_get1_CRL_removed)}
    if OSSL_STORE_INFO_get1_CRL_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_get1_CRL)}
      OSSL_STORE_INFO_get1_CRL := _OSSL_STORE_INFO_get1_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_get1_CRL_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_get1_CRL');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_type_string := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_type_string_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_type_string);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_type_string_allownil)}
    OSSL_STORE_INFO_type_string := ERR_OSSL_STORE_INFO_type_string;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_type_string_introduced)}
    if LibVersion < OSSL_STORE_INFO_type_string_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_type_string)}
      OSSL_STORE_INFO_type_string := FC_OSSL_STORE_INFO_type_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_type_string_removed)}
    if OSSL_STORE_INFO_type_string_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_type_string)}
      OSSL_STORE_INFO_type_string := _OSSL_STORE_INFO_type_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_type_string_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_type_string');
    {$ifend}
  end;
  
  OSSL_STORE_INFO_free := LoadLibFunction(ADllHandle, OSSL_STORE_INFO_free_procname);
  FuncLoadError := not assigned(OSSL_STORE_INFO_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_INFO_free_allownil)}
    OSSL_STORE_INFO_free := ERR_OSSL_STORE_INFO_free;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_free_introduced)}
    if LibVersion < OSSL_STORE_INFO_free_introduced then
    begin
      {$if declared(FC_OSSL_STORE_INFO_free)}
      OSSL_STORE_INFO_free := FC_OSSL_STORE_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_INFO_free_removed)}
    if OSSL_STORE_INFO_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_INFO_free)}
      OSSL_STORE_INFO_free := _OSSL_STORE_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_INFO_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_INFO_free');
    {$ifend}
  end;
  
  OSSL_STORE_supports_search := LoadLibFunction(ADllHandle, OSSL_STORE_supports_search_procname);
  FuncLoadError := not assigned(OSSL_STORE_supports_search);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_supports_search_allownil)}
    OSSL_STORE_supports_search := ERR_OSSL_STORE_supports_search;
    {$ifend}
    {$if declared(OSSL_STORE_supports_search_introduced)}
    if LibVersion < OSSL_STORE_supports_search_introduced then
    begin
      {$if declared(FC_OSSL_STORE_supports_search)}
      OSSL_STORE_supports_search := FC_OSSL_STORE_supports_search;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_supports_search_removed)}
    if OSSL_STORE_supports_search_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_supports_search)}
      OSSL_STORE_supports_search := _OSSL_STORE_supports_search;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_supports_search_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_supports_search');
    {$ifend}
  end;
  
  OSSL_STORE_SEARCH_by_name := LoadLibFunction(ADllHandle, OSSL_STORE_SEARCH_by_name_procname);
  FuncLoadError := not assigned(OSSL_STORE_SEARCH_by_name);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_SEARCH_by_name_allownil)}
    OSSL_STORE_SEARCH_by_name := ERR_OSSL_STORE_SEARCH_by_name;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_by_name_introduced)}
    if LibVersion < OSSL_STORE_SEARCH_by_name_introduced then
    begin
      {$if declared(FC_OSSL_STORE_SEARCH_by_name)}
      OSSL_STORE_SEARCH_by_name := FC_OSSL_STORE_SEARCH_by_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_by_name_removed)}
    if OSSL_STORE_SEARCH_by_name_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_SEARCH_by_name)}
      OSSL_STORE_SEARCH_by_name := _OSSL_STORE_SEARCH_by_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_SEARCH_by_name_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_SEARCH_by_name');
    {$ifend}
  end;
  
  OSSL_STORE_SEARCH_by_issuer_serial := LoadLibFunction(ADllHandle, OSSL_STORE_SEARCH_by_issuer_serial_procname);
  FuncLoadError := not assigned(OSSL_STORE_SEARCH_by_issuer_serial);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_SEARCH_by_issuer_serial_allownil)}
    OSSL_STORE_SEARCH_by_issuer_serial := ERR_OSSL_STORE_SEARCH_by_issuer_serial;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_by_issuer_serial_introduced)}
    if LibVersion < OSSL_STORE_SEARCH_by_issuer_serial_introduced then
    begin
      {$if declared(FC_OSSL_STORE_SEARCH_by_issuer_serial)}
      OSSL_STORE_SEARCH_by_issuer_serial := FC_OSSL_STORE_SEARCH_by_issuer_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_by_issuer_serial_removed)}
    if OSSL_STORE_SEARCH_by_issuer_serial_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_SEARCH_by_issuer_serial)}
      OSSL_STORE_SEARCH_by_issuer_serial := _OSSL_STORE_SEARCH_by_issuer_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_SEARCH_by_issuer_serial_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_SEARCH_by_issuer_serial');
    {$ifend}
  end;
  
  OSSL_STORE_SEARCH_by_key_fingerprint := LoadLibFunction(ADllHandle, OSSL_STORE_SEARCH_by_key_fingerprint_procname);
  FuncLoadError := not assigned(OSSL_STORE_SEARCH_by_key_fingerprint);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_SEARCH_by_key_fingerprint_allownil)}
    OSSL_STORE_SEARCH_by_key_fingerprint := ERR_OSSL_STORE_SEARCH_by_key_fingerprint;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_by_key_fingerprint_introduced)}
    if LibVersion < OSSL_STORE_SEARCH_by_key_fingerprint_introduced then
    begin
      {$if declared(FC_OSSL_STORE_SEARCH_by_key_fingerprint)}
      OSSL_STORE_SEARCH_by_key_fingerprint := FC_OSSL_STORE_SEARCH_by_key_fingerprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_by_key_fingerprint_removed)}
    if OSSL_STORE_SEARCH_by_key_fingerprint_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_SEARCH_by_key_fingerprint)}
      OSSL_STORE_SEARCH_by_key_fingerprint := _OSSL_STORE_SEARCH_by_key_fingerprint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_SEARCH_by_key_fingerprint_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_SEARCH_by_key_fingerprint');
    {$ifend}
  end;
  
  OSSL_STORE_SEARCH_by_alias := LoadLibFunction(ADllHandle, OSSL_STORE_SEARCH_by_alias_procname);
  FuncLoadError := not assigned(OSSL_STORE_SEARCH_by_alias);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_SEARCH_by_alias_allownil)}
    OSSL_STORE_SEARCH_by_alias := ERR_OSSL_STORE_SEARCH_by_alias;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_by_alias_introduced)}
    if LibVersion < OSSL_STORE_SEARCH_by_alias_introduced then
    begin
      {$if declared(FC_OSSL_STORE_SEARCH_by_alias)}
      OSSL_STORE_SEARCH_by_alias := FC_OSSL_STORE_SEARCH_by_alias;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_by_alias_removed)}
    if OSSL_STORE_SEARCH_by_alias_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_SEARCH_by_alias)}
      OSSL_STORE_SEARCH_by_alias := _OSSL_STORE_SEARCH_by_alias;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_SEARCH_by_alias_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_SEARCH_by_alias');
    {$ifend}
  end;
  
  OSSL_STORE_SEARCH_free := LoadLibFunction(ADllHandle, OSSL_STORE_SEARCH_free_procname);
  FuncLoadError := not assigned(OSSL_STORE_SEARCH_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_SEARCH_free_allownil)}
    OSSL_STORE_SEARCH_free := ERR_OSSL_STORE_SEARCH_free;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_free_introduced)}
    if LibVersion < OSSL_STORE_SEARCH_free_introduced then
    begin
      {$if declared(FC_OSSL_STORE_SEARCH_free)}
      OSSL_STORE_SEARCH_free := FC_OSSL_STORE_SEARCH_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_free_removed)}
    if OSSL_STORE_SEARCH_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_SEARCH_free)}
      OSSL_STORE_SEARCH_free := _OSSL_STORE_SEARCH_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_SEARCH_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_SEARCH_free');
    {$ifend}
  end;
  
  OSSL_STORE_SEARCH_get_type := LoadLibFunction(ADllHandle, OSSL_STORE_SEARCH_get_type_procname);
  FuncLoadError := not assigned(OSSL_STORE_SEARCH_get_type);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_SEARCH_get_type_allownil)}
    OSSL_STORE_SEARCH_get_type := ERR_OSSL_STORE_SEARCH_get_type;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_get_type_introduced)}
    if LibVersion < OSSL_STORE_SEARCH_get_type_introduced then
    begin
      {$if declared(FC_OSSL_STORE_SEARCH_get_type)}
      OSSL_STORE_SEARCH_get_type := FC_OSSL_STORE_SEARCH_get_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_get_type_removed)}
    if OSSL_STORE_SEARCH_get_type_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_SEARCH_get_type)}
      OSSL_STORE_SEARCH_get_type := _OSSL_STORE_SEARCH_get_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_SEARCH_get_type_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_SEARCH_get_type');
    {$ifend}
  end;
  
  OSSL_STORE_SEARCH_get0_name := LoadLibFunction(ADllHandle, OSSL_STORE_SEARCH_get0_name_procname);
  FuncLoadError := not assigned(OSSL_STORE_SEARCH_get0_name);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_SEARCH_get0_name_allownil)}
    OSSL_STORE_SEARCH_get0_name := ERR_OSSL_STORE_SEARCH_get0_name;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_get0_name_introduced)}
    if LibVersion < OSSL_STORE_SEARCH_get0_name_introduced then
    begin
      {$if declared(FC_OSSL_STORE_SEARCH_get0_name)}
      OSSL_STORE_SEARCH_get0_name := FC_OSSL_STORE_SEARCH_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_get0_name_removed)}
    if OSSL_STORE_SEARCH_get0_name_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_SEARCH_get0_name)}
      OSSL_STORE_SEARCH_get0_name := _OSSL_STORE_SEARCH_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_SEARCH_get0_name_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_SEARCH_get0_name');
    {$ifend}
  end;
  
  OSSL_STORE_SEARCH_get0_serial := LoadLibFunction(ADllHandle, OSSL_STORE_SEARCH_get0_serial_procname);
  FuncLoadError := not assigned(OSSL_STORE_SEARCH_get0_serial);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_SEARCH_get0_serial_allownil)}
    OSSL_STORE_SEARCH_get0_serial := ERR_OSSL_STORE_SEARCH_get0_serial;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_get0_serial_introduced)}
    if LibVersion < OSSL_STORE_SEARCH_get0_serial_introduced then
    begin
      {$if declared(FC_OSSL_STORE_SEARCH_get0_serial)}
      OSSL_STORE_SEARCH_get0_serial := FC_OSSL_STORE_SEARCH_get0_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_get0_serial_removed)}
    if OSSL_STORE_SEARCH_get0_serial_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_SEARCH_get0_serial)}
      OSSL_STORE_SEARCH_get0_serial := _OSSL_STORE_SEARCH_get0_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_SEARCH_get0_serial_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_SEARCH_get0_serial');
    {$ifend}
  end;
  
  OSSL_STORE_SEARCH_get0_bytes := LoadLibFunction(ADllHandle, OSSL_STORE_SEARCH_get0_bytes_procname);
  FuncLoadError := not assigned(OSSL_STORE_SEARCH_get0_bytes);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_SEARCH_get0_bytes_allownil)}
    OSSL_STORE_SEARCH_get0_bytes := ERR_OSSL_STORE_SEARCH_get0_bytes;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_get0_bytes_introduced)}
    if LibVersion < OSSL_STORE_SEARCH_get0_bytes_introduced then
    begin
      {$if declared(FC_OSSL_STORE_SEARCH_get0_bytes)}
      OSSL_STORE_SEARCH_get0_bytes := FC_OSSL_STORE_SEARCH_get0_bytes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_get0_bytes_removed)}
    if OSSL_STORE_SEARCH_get0_bytes_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_SEARCH_get0_bytes)}
      OSSL_STORE_SEARCH_get0_bytes := _OSSL_STORE_SEARCH_get0_bytes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_SEARCH_get0_bytes_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_SEARCH_get0_bytes');
    {$ifend}
  end;
  
  OSSL_STORE_SEARCH_get0_string := LoadLibFunction(ADllHandle, OSSL_STORE_SEARCH_get0_string_procname);
  FuncLoadError := not assigned(OSSL_STORE_SEARCH_get0_string);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_SEARCH_get0_string_allownil)}
    OSSL_STORE_SEARCH_get0_string := ERR_OSSL_STORE_SEARCH_get0_string;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_get0_string_introduced)}
    if LibVersion < OSSL_STORE_SEARCH_get0_string_introduced then
    begin
      {$if declared(FC_OSSL_STORE_SEARCH_get0_string)}
      OSSL_STORE_SEARCH_get0_string := FC_OSSL_STORE_SEARCH_get0_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_get0_string_removed)}
    if OSSL_STORE_SEARCH_get0_string_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_SEARCH_get0_string)}
      OSSL_STORE_SEARCH_get0_string := _OSSL_STORE_SEARCH_get0_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_SEARCH_get0_string_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_SEARCH_get0_string');
    {$ifend}
  end;
  
  OSSL_STORE_SEARCH_get0_digest := LoadLibFunction(ADllHandle, OSSL_STORE_SEARCH_get0_digest_procname);
  FuncLoadError := not assigned(OSSL_STORE_SEARCH_get0_digest);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_SEARCH_get0_digest_allownil)}
    OSSL_STORE_SEARCH_get0_digest := ERR_OSSL_STORE_SEARCH_get0_digest;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_get0_digest_introduced)}
    if LibVersion < OSSL_STORE_SEARCH_get0_digest_introduced then
    begin
      {$if declared(FC_OSSL_STORE_SEARCH_get0_digest)}
      OSSL_STORE_SEARCH_get0_digest := FC_OSSL_STORE_SEARCH_get0_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_SEARCH_get0_digest_removed)}
    if OSSL_STORE_SEARCH_get0_digest_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_SEARCH_get0_digest)}
      OSSL_STORE_SEARCH_get0_digest := _OSSL_STORE_SEARCH_get0_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_SEARCH_get0_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_SEARCH_get0_digest');
    {$ifend}
  end;
  
  OSSL_STORE_expect := LoadLibFunction(ADllHandle, OSSL_STORE_expect_procname);
  FuncLoadError := not assigned(OSSL_STORE_expect);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_expect_allownil)}
    OSSL_STORE_expect := ERR_OSSL_STORE_expect;
    {$ifend}
    {$if declared(OSSL_STORE_expect_introduced)}
    if LibVersion < OSSL_STORE_expect_introduced then
    begin
      {$if declared(FC_OSSL_STORE_expect)}
      OSSL_STORE_expect := FC_OSSL_STORE_expect;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_expect_removed)}
    if OSSL_STORE_expect_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_expect)}
      OSSL_STORE_expect := _OSSL_STORE_expect;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_expect_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_expect');
    {$ifend}
  end;
  
  OSSL_STORE_find := LoadLibFunction(ADllHandle, OSSL_STORE_find_procname);
  FuncLoadError := not assigned(OSSL_STORE_find);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_find_allownil)}
    OSSL_STORE_find := ERR_OSSL_STORE_find;
    {$ifend}
    {$if declared(OSSL_STORE_find_introduced)}
    if LibVersion < OSSL_STORE_find_introduced then
    begin
      {$if declared(FC_OSSL_STORE_find)}
      OSSL_STORE_find := FC_OSSL_STORE_find;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_find_removed)}
    if OSSL_STORE_find_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_find)}
      OSSL_STORE_find := _OSSL_STORE_find;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_find_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_find');
    {$ifend}
  end;
  
  OSSL_STORE_LOADER_fetch := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_fetch_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_fetch);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_fetch_allownil)}
    OSSL_STORE_LOADER_fetch := ERR_OSSL_STORE_LOADER_fetch;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_fetch_introduced)}
    if LibVersion < OSSL_STORE_LOADER_fetch_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_fetch)}
      OSSL_STORE_LOADER_fetch := FC_OSSL_STORE_LOADER_fetch;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_fetch_removed)}
    if OSSL_STORE_LOADER_fetch_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_fetch)}
      OSSL_STORE_LOADER_fetch := _OSSL_STORE_LOADER_fetch;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_fetch_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_fetch');
    {$ifend}
  end;
  
  OSSL_STORE_LOADER_up_ref := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_up_ref_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_up_ref);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_up_ref_allownil)}
    OSSL_STORE_LOADER_up_ref := ERR_OSSL_STORE_LOADER_up_ref;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_up_ref_introduced)}
    if LibVersion < OSSL_STORE_LOADER_up_ref_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_up_ref)}
      OSSL_STORE_LOADER_up_ref := FC_OSSL_STORE_LOADER_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_up_ref_removed)}
    if OSSL_STORE_LOADER_up_ref_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_up_ref)}
      OSSL_STORE_LOADER_up_ref := _OSSL_STORE_LOADER_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_up_ref_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_up_ref');
    {$ifend}
  end;
  
  OSSL_STORE_LOADER_free := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_free_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_free_allownil)}
    OSSL_STORE_LOADER_free := ERR_OSSL_STORE_LOADER_free;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_free_introduced)}
    if LibVersion < OSSL_STORE_LOADER_free_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_free)}
      OSSL_STORE_LOADER_free := FC_OSSL_STORE_LOADER_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_free_removed)}
    if OSSL_STORE_LOADER_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_free)}
      OSSL_STORE_LOADER_free := _OSSL_STORE_LOADER_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_free');
    {$ifend}
  end;
  
  OSSL_STORE_LOADER_get0_provider := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_get0_provider_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_get0_provider);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_get0_provider_allownil)}
    OSSL_STORE_LOADER_get0_provider := ERR_OSSL_STORE_LOADER_get0_provider;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_get0_provider_introduced)}
    if LibVersion < OSSL_STORE_LOADER_get0_provider_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_get0_provider)}
      OSSL_STORE_LOADER_get0_provider := FC_OSSL_STORE_LOADER_get0_provider;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_get0_provider_removed)}
    if OSSL_STORE_LOADER_get0_provider_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_get0_provider)}
      OSSL_STORE_LOADER_get0_provider := _OSSL_STORE_LOADER_get0_provider;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_get0_provider_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_get0_provider');
    {$ifend}
  end;
  
  OSSL_STORE_LOADER_get0_properties := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_get0_properties_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_get0_properties);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_get0_properties_allownil)}
    OSSL_STORE_LOADER_get0_properties := ERR_OSSL_STORE_LOADER_get0_properties;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_get0_properties_introduced)}
    if LibVersion < OSSL_STORE_LOADER_get0_properties_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_get0_properties)}
      OSSL_STORE_LOADER_get0_properties := FC_OSSL_STORE_LOADER_get0_properties;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_get0_properties_removed)}
    if OSSL_STORE_LOADER_get0_properties_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_get0_properties)}
      OSSL_STORE_LOADER_get0_properties := _OSSL_STORE_LOADER_get0_properties;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_get0_properties_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_get0_properties');
    {$ifend}
  end;
  
  OSSL_STORE_LOADER_get0_description := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_get0_description_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_get0_description);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_get0_description_allownil)}
    OSSL_STORE_LOADER_get0_description := ERR_OSSL_STORE_LOADER_get0_description;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_get0_description_introduced)}
    if LibVersion < OSSL_STORE_LOADER_get0_description_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_get0_description)}
      OSSL_STORE_LOADER_get0_description := FC_OSSL_STORE_LOADER_get0_description;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_get0_description_removed)}
    if OSSL_STORE_LOADER_get0_description_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_get0_description)}
      OSSL_STORE_LOADER_get0_description := _OSSL_STORE_LOADER_get0_description;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_get0_description_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_get0_description');
    {$ifend}
  end;
  
  OSSL_STORE_LOADER_is_a := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_is_a_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_is_a);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_is_a_allownil)}
    OSSL_STORE_LOADER_is_a := ERR_OSSL_STORE_LOADER_is_a;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_is_a_introduced)}
    if LibVersion < OSSL_STORE_LOADER_is_a_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_is_a)}
      OSSL_STORE_LOADER_is_a := FC_OSSL_STORE_LOADER_is_a;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_is_a_removed)}
    if OSSL_STORE_LOADER_is_a_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_is_a)}
      OSSL_STORE_LOADER_is_a := _OSSL_STORE_LOADER_is_a;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_is_a_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_is_a');
    {$ifend}
  end;
  
  OSSL_STORE_LOADER_do_all_provided := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_do_all_provided_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_do_all_provided);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_do_all_provided_allownil)}
    OSSL_STORE_LOADER_do_all_provided := ERR_OSSL_STORE_LOADER_do_all_provided;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_do_all_provided_introduced)}
    if LibVersion < OSSL_STORE_LOADER_do_all_provided_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_do_all_provided)}
      OSSL_STORE_LOADER_do_all_provided := FC_OSSL_STORE_LOADER_do_all_provided;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_do_all_provided_removed)}
    if OSSL_STORE_LOADER_do_all_provided_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_do_all_provided)}
      OSSL_STORE_LOADER_do_all_provided := _OSSL_STORE_LOADER_do_all_provided;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_do_all_provided_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_do_all_provided');
    {$ifend}
  end;
  
  OSSL_STORE_LOADER_names_do_all := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_names_do_all_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_names_do_all);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_names_do_all_allownil)}
    OSSL_STORE_LOADER_names_do_all := ERR_OSSL_STORE_LOADER_names_do_all;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_names_do_all_introduced)}
    if LibVersion < OSSL_STORE_LOADER_names_do_all_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_names_do_all)}
      OSSL_STORE_LOADER_names_do_all := FC_OSSL_STORE_LOADER_names_do_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_names_do_all_removed)}
    if OSSL_STORE_LOADER_names_do_all_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_names_do_all)}
      OSSL_STORE_LOADER_names_do_all := _OSSL_STORE_LOADER_names_do_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_names_do_all_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_names_do_all');
    {$ifend}
  end;
  
  OSSL_STORE_LOADER_settable_ctx_params := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_settable_ctx_params_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_settable_ctx_params);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_settable_ctx_params_allownil)}
    OSSL_STORE_LOADER_settable_ctx_params := ERR_OSSL_STORE_LOADER_settable_ctx_params;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_settable_ctx_params_introduced)}
    if LibVersion < OSSL_STORE_LOADER_settable_ctx_params_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_settable_ctx_params)}
      OSSL_STORE_LOADER_settable_ctx_params := FC_OSSL_STORE_LOADER_settable_ctx_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_settable_ctx_params_removed)}
    if OSSL_STORE_LOADER_settable_ctx_params_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_settable_ctx_params)}
      OSSL_STORE_LOADER_settable_ctx_params := _OSSL_STORE_LOADER_settable_ctx_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_settable_ctx_params_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_settable_ctx_params');
    {$ifend}
  end;
  
  OSSL_STORE_LOADER_new := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_new_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_new_allownil)}
    OSSL_STORE_LOADER_new := ERR_OSSL_STORE_LOADER_new;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_new_introduced)}
    if LibVersion < OSSL_STORE_LOADER_new_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_new)}
      OSSL_STORE_LOADER_new := FC_OSSL_STORE_LOADER_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_new_removed)}
    if OSSL_STORE_LOADER_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_new)}
      OSSL_STORE_LOADER_new := _OSSL_STORE_LOADER_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_new');
    {$ifend}
  end;
  
  OSSL_STORE_LOADER_set_open := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_set_open_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_set_open);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_set_open_allownil)}
    OSSL_STORE_LOADER_set_open := ERR_OSSL_STORE_LOADER_set_open;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_set_open_introduced)}
    if LibVersion < OSSL_STORE_LOADER_set_open_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_set_open)}
      OSSL_STORE_LOADER_set_open := FC_OSSL_STORE_LOADER_set_open;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_set_open_removed)}
    if OSSL_STORE_LOADER_set_open_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_set_open)}
      OSSL_STORE_LOADER_set_open := _OSSL_STORE_LOADER_set_open;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_set_open_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_set_open');
    {$ifend}
  end;
  
  OSSL_STORE_LOADER_set_open_ex := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_set_open_ex_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_set_open_ex);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_set_open_ex_allownil)}
    OSSL_STORE_LOADER_set_open_ex := ERR_OSSL_STORE_LOADER_set_open_ex;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_set_open_ex_introduced)}
    if LibVersion < OSSL_STORE_LOADER_set_open_ex_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_set_open_ex)}
      OSSL_STORE_LOADER_set_open_ex := FC_OSSL_STORE_LOADER_set_open_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_set_open_ex_removed)}
    if OSSL_STORE_LOADER_set_open_ex_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_set_open_ex)}
      OSSL_STORE_LOADER_set_open_ex := _OSSL_STORE_LOADER_set_open_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_set_open_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_set_open_ex');
    {$ifend}
  end;
  
  OSSL_STORE_LOADER_set_attach := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_set_attach_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_set_attach);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_set_attach_allownil)}
    OSSL_STORE_LOADER_set_attach := ERR_OSSL_STORE_LOADER_set_attach;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_set_attach_introduced)}
    if LibVersion < OSSL_STORE_LOADER_set_attach_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_set_attach)}
      OSSL_STORE_LOADER_set_attach := FC_OSSL_STORE_LOADER_set_attach;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_set_attach_removed)}
    if OSSL_STORE_LOADER_set_attach_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_set_attach)}
      OSSL_STORE_LOADER_set_attach := _OSSL_STORE_LOADER_set_attach;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_set_attach_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_set_attach');
    {$ifend}
  end;
  
  OSSL_STORE_LOADER_set_ctrl := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_set_ctrl_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_set_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_set_ctrl_allownil)}
    OSSL_STORE_LOADER_set_ctrl := ERR_OSSL_STORE_LOADER_set_ctrl;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_set_ctrl_introduced)}
    if LibVersion < OSSL_STORE_LOADER_set_ctrl_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_set_ctrl)}
      OSSL_STORE_LOADER_set_ctrl := FC_OSSL_STORE_LOADER_set_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_set_ctrl_removed)}
    if OSSL_STORE_LOADER_set_ctrl_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_set_ctrl)}
      OSSL_STORE_LOADER_set_ctrl := _OSSL_STORE_LOADER_set_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_set_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_set_ctrl');
    {$ifend}
  end;
  
  OSSL_STORE_LOADER_set_expect := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_set_expect_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_set_expect);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_set_expect_allownil)}
    OSSL_STORE_LOADER_set_expect := ERR_OSSL_STORE_LOADER_set_expect;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_set_expect_introduced)}
    if LibVersion < OSSL_STORE_LOADER_set_expect_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_set_expect)}
      OSSL_STORE_LOADER_set_expect := FC_OSSL_STORE_LOADER_set_expect;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_set_expect_removed)}
    if OSSL_STORE_LOADER_set_expect_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_set_expect)}
      OSSL_STORE_LOADER_set_expect := _OSSL_STORE_LOADER_set_expect;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_set_expect_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_set_expect');
    {$ifend}
  end;
  
  OSSL_STORE_LOADER_set_find := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_set_find_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_set_find);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_set_find_allownil)}
    OSSL_STORE_LOADER_set_find := ERR_OSSL_STORE_LOADER_set_find;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_set_find_introduced)}
    if LibVersion < OSSL_STORE_LOADER_set_find_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_set_find)}
      OSSL_STORE_LOADER_set_find := FC_OSSL_STORE_LOADER_set_find;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_set_find_removed)}
    if OSSL_STORE_LOADER_set_find_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_set_find)}
      OSSL_STORE_LOADER_set_find := _OSSL_STORE_LOADER_set_find;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_set_find_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_set_find');
    {$ifend}
  end;
  
  OSSL_STORE_LOADER_set_load := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_set_load_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_set_load);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_set_load_allownil)}
    OSSL_STORE_LOADER_set_load := ERR_OSSL_STORE_LOADER_set_load;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_set_load_introduced)}
    if LibVersion < OSSL_STORE_LOADER_set_load_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_set_load)}
      OSSL_STORE_LOADER_set_load := FC_OSSL_STORE_LOADER_set_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_set_load_removed)}
    if OSSL_STORE_LOADER_set_load_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_set_load)}
      OSSL_STORE_LOADER_set_load := _OSSL_STORE_LOADER_set_load;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_set_load_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_set_load');
    {$ifend}
  end;
  
  OSSL_STORE_LOADER_set_eof := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_set_eof_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_set_eof);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_set_eof_allownil)}
    OSSL_STORE_LOADER_set_eof := ERR_OSSL_STORE_LOADER_set_eof;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_set_eof_introduced)}
    if LibVersion < OSSL_STORE_LOADER_set_eof_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_set_eof)}
      OSSL_STORE_LOADER_set_eof := FC_OSSL_STORE_LOADER_set_eof;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_set_eof_removed)}
    if OSSL_STORE_LOADER_set_eof_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_set_eof)}
      OSSL_STORE_LOADER_set_eof := _OSSL_STORE_LOADER_set_eof;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_set_eof_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_set_eof');
    {$ifend}
  end;
  
  OSSL_STORE_LOADER_set_error := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_set_error_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_set_error);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_set_error_allownil)}
    OSSL_STORE_LOADER_set_error := ERR_OSSL_STORE_LOADER_set_error;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_set_error_introduced)}
    if LibVersion < OSSL_STORE_LOADER_set_error_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_set_error)}
      OSSL_STORE_LOADER_set_error := FC_OSSL_STORE_LOADER_set_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_set_error_removed)}
    if OSSL_STORE_LOADER_set_error_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_set_error)}
      OSSL_STORE_LOADER_set_error := _OSSL_STORE_LOADER_set_error;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_set_error_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_set_error');
    {$ifend}
  end;
  
  OSSL_STORE_LOADER_set_close := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_set_close_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_set_close);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_set_close_allownil)}
    OSSL_STORE_LOADER_set_close := ERR_OSSL_STORE_LOADER_set_close;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_set_close_introduced)}
    if LibVersion < OSSL_STORE_LOADER_set_close_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_set_close)}
      OSSL_STORE_LOADER_set_close := FC_OSSL_STORE_LOADER_set_close;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_set_close_removed)}
    if OSSL_STORE_LOADER_set_close_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_set_close)}
      OSSL_STORE_LOADER_set_close := _OSSL_STORE_LOADER_set_close;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_set_close_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_set_close');
    {$ifend}
  end;
  
  OSSL_STORE_LOADER_get0_engine := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_get0_engine_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_get0_engine);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_get0_engine_allownil)}
    OSSL_STORE_LOADER_get0_engine := ERR_OSSL_STORE_LOADER_get0_engine;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_get0_engine_introduced)}
    if LibVersion < OSSL_STORE_LOADER_get0_engine_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_get0_engine)}
      OSSL_STORE_LOADER_get0_engine := FC_OSSL_STORE_LOADER_get0_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_get0_engine_removed)}
    if OSSL_STORE_LOADER_get0_engine_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_get0_engine)}
      OSSL_STORE_LOADER_get0_engine := _OSSL_STORE_LOADER_get0_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_get0_engine_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_get0_engine');
    {$ifend}
  end;
  
  OSSL_STORE_LOADER_get0_scheme := LoadLibFunction(ADllHandle, OSSL_STORE_LOADER_get0_scheme_procname);
  FuncLoadError := not assigned(OSSL_STORE_LOADER_get0_scheme);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_LOADER_get0_scheme_allownil)}
    OSSL_STORE_LOADER_get0_scheme := ERR_OSSL_STORE_LOADER_get0_scheme;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_get0_scheme_introduced)}
    if LibVersion < OSSL_STORE_LOADER_get0_scheme_introduced then
    begin
      {$if declared(FC_OSSL_STORE_LOADER_get0_scheme)}
      OSSL_STORE_LOADER_get0_scheme := FC_OSSL_STORE_LOADER_get0_scheme;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_LOADER_get0_scheme_removed)}
    if OSSL_STORE_LOADER_get0_scheme_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_LOADER_get0_scheme)}
      OSSL_STORE_LOADER_get0_scheme := _OSSL_STORE_LOADER_get0_scheme;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_LOADER_get0_scheme_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_LOADER_get0_scheme');
    {$ifend}
  end;
  
  OSSL_STORE_register_loader := LoadLibFunction(ADllHandle, OSSL_STORE_register_loader_procname);
  FuncLoadError := not assigned(OSSL_STORE_register_loader);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_register_loader_allownil)}
    OSSL_STORE_register_loader := ERR_OSSL_STORE_register_loader;
    {$ifend}
    {$if declared(OSSL_STORE_register_loader_introduced)}
    if LibVersion < OSSL_STORE_register_loader_introduced then
    begin
      {$if declared(FC_OSSL_STORE_register_loader)}
      OSSL_STORE_register_loader := FC_OSSL_STORE_register_loader;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_register_loader_removed)}
    if OSSL_STORE_register_loader_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_register_loader)}
      OSSL_STORE_register_loader := _OSSL_STORE_register_loader;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_register_loader_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_register_loader');
    {$ifend}
  end;
  
  OSSL_STORE_unregister_loader := LoadLibFunction(ADllHandle, OSSL_STORE_unregister_loader_procname);
  FuncLoadError := not assigned(OSSL_STORE_unregister_loader);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_unregister_loader_allownil)}
    OSSL_STORE_unregister_loader := ERR_OSSL_STORE_unregister_loader;
    {$ifend}
    {$if declared(OSSL_STORE_unregister_loader_introduced)}
    if LibVersion < OSSL_STORE_unregister_loader_introduced then
    begin
      {$if declared(FC_OSSL_STORE_unregister_loader)}
      OSSL_STORE_unregister_loader := FC_OSSL_STORE_unregister_loader;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_unregister_loader_removed)}
    if OSSL_STORE_unregister_loader_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_unregister_loader)}
      OSSL_STORE_unregister_loader := _OSSL_STORE_unregister_loader;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_unregister_loader_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_unregister_loader');
    {$ifend}
  end;
  
  OSSL_STORE_do_all_loaders := LoadLibFunction(ADllHandle, OSSL_STORE_do_all_loaders_procname);
  FuncLoadError := not assigned(OSSL_STORE_do_all_loaders);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STORE_do_all_loaders_allownil)}
    OSSL_STORE_do_all_loaders := ERR_OSSL_STORE_do_all_loaders;
    {$ifend}
    {$if declared(OSSL_STORE_do_all_loaders_introduced)}
    if LibVersion < OSSL_STORE_do_all_loaders_introduced then
    begin
      {$if declared(FC_OSSL_STORE_do_all_loaders)}
      OSSL_STORE_do_all_loaders := FC_OSSL_STORE_do_all_loaders;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STORE_do_all_loaders_removed)}
    if OSSL_STORE_do_all_loaders_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STORE_do_all_loaders)}
      OSSL_STORE_do_all_loaders := _OSSL_STORE_do_all_loaders;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STORE_do_all_loaders_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STORE_do_all_loaders');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  OSSL_STORE_open := nil;
  OSSL_STORE_open_ex := nil;
  OSSL_STORE_ctrl := nil;
  OSSL_STORE_vctrl := nil;
  OSSL_STORE_load := nil;
  OSSL_STORE_delete := nil;
  OSSL_STORE_eof := nil;
  OSSL_STORE_error := nil;
  OSSL_STORE_close := nil;
  OSSL_STORE_attach := nil;
  OSSL_STORE_INFO_new := nil;
  OSSL_STORE_INFO_new_NAME := nil;
  OSSL_STORE_INFO_set0_NAME_description := nil;
  OSSL_STORE_INFO_new_PARAMS := nil;
  OSSL_STORE_INFO_new_PUBKEY := nil;
  OSSL_STORE_INFO_new_PKEY := nil;
  OSSL_STORE_INFO_new_CERT := nil;
  OSSL_STORE_INFO_new_CRL := nil;
  OSSL_STORE_INFO_get_type := nil;
  OSSL_STORE_INFO_get0_data := nil;
  OSSL_STORE_INFO_get0_NAME := nil;
  OSSL_STORE_INFO_get1_NAME := nil;
  OSSL_STORE_INFO_get0_NAME_description := nil;
  OSSL_STORE_INFO_get1_NAME_description := nil;
  OSSL_STORE_INFO_get0_PARAMS := nil;
  OSSL_STORE_INFO_get1_PARAMS := nil;
  OSSL_STORE_INFO_get0_PUBKEY := nil;
  OSSL_STORE_INFO_get1_PUBKEY := nil;
  OSSL_STORE_INFO_get0_PKEY := nil;
  OSSL_STORE_INFO_get1_PKEY := nil;
  OSSL_STORE_INFO_get0_CERT := nil;
  OSSL_STORE_INFO_get1_CERT := nil;
  OSSL_STORE_INFO_get0_CRL := nil;
  OSSL_STORE_INFO_get1_CRL := nil;
  OSSL_STORE_INFO_type_string := nil;
  OSSL_STORE_INFO_free := nil;
  OSSL_STORE_supports_search := nil;
  OSSL_STORE_SEARCH_by_name := nil;
  OSSL_STORE_SEARCH_by_issuer_serial := nil;
  OSSL_STORE_SEARCH_by_key_fingerprint := nil;
  OSSL_STORE_SEARCH_by_alias := nil;
  OSSL_STORE_SEARCH_free := nil;
  OSSL_STORE_SEARCH_get_type := nil;
  OSSL_STORE_SEARCH_get0_name := nil;
  OSSL_STORE_SEARCH_get0_serial := nil;
  OSSL_STORE_SEARCH_get0_bytes := nil;
  OSSL_STORE_SEARCH_get0_string := nil;
  OSSL_STORE_SEARCH_get0_digest := nil;
  OSSL_STORE_expect := nil;
  OSSL_STORE_find := nil;
  OSSL_STORE_LOADER_fetch := nil;
  OSSL_STORE_LOADER_up_ref := nil;
  OSSL_STORE_LOADER_free := nil;
  OSSL_STORE_LOADER_get0_provider := nil;
  OSSL_STORE_LOADER_get0_properties := nil;
  OSSL_STORE_LOADER_get0_description := nil;
  OSSL_STORE_LOADER_is_a := nil;
  OSSL_STORE_LOADER_do_all_provided := nil;
  OSSL_STORE_LOADER_names_do_all := nil;
  OSSL_STORE_LOADER_settable_ctx_params := nil;
  OSSL_STORE_LOADER_new := nil;
  OSSL_STORE_LOADER_set_open := nil;
  OSSL_STORE_LOADER_set_open_ex := nil;
  OSSL_STORE_LOADER_set_attach := nil;
  OSSL_STORE_LOADER_set_ctrl := nil;
  OSSL_STORE_LOADER_set_expect := nil;
  OSSL_STORE_LOADER_set_find := nil;
  OSSL_STORE_LOADER_set_load := nil;
  OSSL_STORE_LOADER_set_eof := nil;
  OSSL_STORE_LOADER_set_error := nil;
  OSSL_STORE_LOADER_set_close := nil;
  OSSL_STORE_LOADER_get0_engine := nil;
  OSSL_STORE_LOADER_get0_scheme := nil;
  OSSL_STORE_register_loader := nil;
  OSSL_STORE_unregister_loader := nil;
  OSSL_STORE_do_all_loaders := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.