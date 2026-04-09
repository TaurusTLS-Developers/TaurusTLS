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

unit TaurusTLSHeaders_decoder;

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
  Possl_decoder_instance_st = ^Tossl_decoder_instance_st;
  Tossl_decoder_instance_st = record end;
  {$EXTERNALSYM Possl_decoder_instance_st}

  POSSL_DECODER_INSTANCE = ^TOSSL_DECODER_INSTANCE;
  TOSSL_DECODER_INSTANCE = Tossl_decoder_instance_st;
  {$EXTERNALSYM POSSL_DECODER_INSTANCE}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  TOSSL_DECODER_do_all_provided_fn_cb = procedure(arg1: POSSL_DECODER; arg2: Pointer); cdecl;
  TOSSL_DECODER_names_do_all_fn_cb = procedure(arg1: PIdAnsiChar; arg2: Pointer); cdecl;
  TOSSL_DECODER_CTX_set_pem_password_cb_cb_cb = function: TIdC_INT; cdecl;
  TOSSL_DECODER_CTX_set_passphrase_cb_cb_cb = function: TIdC_INT; cdecl;
  TOSSL_DECODER_CONSTRUCT_func_cb = function(arg1: POSSL_DECODER_INSTANCE; arg2: POSSL_PARAM_ARRAY; arg3: Pointer): TIdC_INT; cdecl;
  TOSSL_DECODER_CLEANUP_func_cb = procedure(arg1: Pointer); cdecl;
  TOSSL_DECODER_export_export_cb_cb = function: TIdC_INT; cdecl;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  OSSL_DECODER_fetch: function(libctx: POSSL_LIB_CTX; name: PIdAnsiChar; properties: PIdAnsiChar): POSSL_DECODER; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_fetch}

  OSSL_DECODER_up_ref: function(encoder: POSSL_DECODER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_up_ref}

  OSSL_DECODER_free: procedure(encoder: POSSL_DECODER); cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_free}

  OSSL_DECODER_get0_provider: function(encoder: POSSL_DECODER): POSSL_PROVIDER; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_get0_provider}

  OSSL_DECODER_get0_properties: function(encoder: POSSL_DECODER): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_get0_properties}

  OSSL_DECODER_get0_name: function(decoder: POSSL_DECODER): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_get0_name}

  OSSL_DECODER_get0_description: function(decoder: POSSL_DECODER): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_get0_description}

  OSSL_DECODER_is_a: function(encoder: POSSL_DECODER; name: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_is_a}

  OSSL_DECODER_do_all_provided: procedure(libctx: POSSL_LIB_CTX; fn: TOSSL_DECODER_do_all_provided_fn_cb; arg: Pointer); cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_do_all_provided}

  OSSL_DECODER_names_do_all: function(encoder: POSSL_DECODER; fn: TOSSL_DECODER_names_do_all_fn_cb; data: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_names_do_all}

  OSSL_DECODER_gettable_params: function(decoder: POSSL_DECODER): POSSL_PARAM_ARRAY; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_gettable_params}

  OSSL_DECODER_get_params: function(decoder: POSSL_DECODER; params: POSSL_PARAM_ARRAY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_get_params}

  OSSL_DECODER_settable_ctx_params: function(encoder: POSSL_DECODER): POSSL_PARAM_ARRAY; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_settable_ctx_params}

  OSSL_DECODER_CTX_new: function: POSSL_DECODER_CTX; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_CTX_new}

  OSSL_DECODER_CTX_set_params: function(ctx: POSSL_DECODER_CTX; params: POSSL_PARAM_ARRAY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_CTX_set_params}

  OSSL_DECODER_CTX_free: procedure(ctx: POSSL_DECODER_CTX); cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_CTX_free}

  OSSL_DECODER_CTX_set_passphrase: function(ctx: POSSL_DECODER_CTX; kstr: PIdAnsiChar; klen: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_CTX_set_passphrase}

  OSSL_DECODER_CTX_set_pem_password_cb: function(ctx: POSSL_DECODER_CTX; cb: TOSSL_DECODER_CTX_set_pem_password_cb_cb_cb; cbarg: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_CTX_set_pem_password_cb}

  OSSL_DECODER_CTX_set_passphrase_cb: function(ctx: POSSL_DECODER_CTX; cb: TOSSL_DECODER_CTX_set_passphrase_cb_cb_cb; cbarg: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_CTX_set_passphrase_cb}

  OSSL_DECODER_CTX_set_passphrase_ui: function(ctx: POSSL_DECODER_CTX; ui_method: PUI_METHOD; ui_data: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_CTX_set_passphrase_ui}

  OSSL_DECODER_CTX_set_selection: function(ctx: POSSL_DECODER_CTX; selection: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_CTX_set_selection}

  OSSL_DECODER_CTX_set_input_type: function(ctx: POSSL_DECODER_CTX; input_type: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_CTX_set_input_type}

  OSSL_DECODER_CTX_set_input_structure: function(ctx: POSSL_DECODER_CTX; input_structure: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_CTX_set_input_structure}

  OSSL_DECODER_CTX_add_decoder: function(ctx: POSSL_DECODER_CTX; decoder: POSSL_DECODER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_CTX_add_decoder}

  OSSL_DECODER_CTX_add_extra: function(ctx: POSSL_DECODER_CTX; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_CTX_add_extra}

  OSSL_DECODER_CTX_get_num_decoders: function(ctx: POSSL_DECODER_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_CTX_get_num_decoders}

  OSSL_DECODER_INSTANCE_get_decoder: function(decoder_inst: POSSL_DECODER_INSTANCE): POSSL_DECODER; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_INSTANCE_get_decoder}

  OSSL_DECODER_INSTANCE_get_decoder_ctx: function(decoder_inst: POSSL_DECODER_INSTANCE): Pointer; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_INSTANCE_get_decoder_ctx}

  OSSL_DECODER_INSTANCE_get_input_type: function(decoder_inst: POSSL_DECODER_INSTANCE): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_INSTANCE_get_input_type}

  OSSL_DECODER_INSTANCE_get_input_structure: function(decoder_inst: POSSL_DECODER_INSTANCE; was_set: PIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_INSTANCE_get_input_structure}

  OSSL_DECODER_CTX_set_construct: function(ctx: POSSL_DECODER_CTX; construct: TOSSL_DECODER_CONSTRUCT_func_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_CTX_set_construct}

  OSSL_DECODER_CTX_set_construct_data: function(ctx: POSSL_DECODER_CTX; construct_data: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_CTX_set_construct_data}

  OSSL_DECODER_CTX_set_cleanup: function(ctx: POSSL_DECODER_CTX; cleanup: TOSSL_DECODER_CLEANUP_func_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_CTX_set_cleanup}

  OSSL_DECODER_CTX_get_construct: function(ctx: POSSL_DECODER_CTX): TOSSL_DECODER_CONSTRUCT_func_cb; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_CTX_get_construct}

  OSSL_DECODER_CTX_get_construct_data: function(ctx: POSSL_DECODER_CTX): Pointer; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_CTX_get_construct_data}

  OSSL_DECODER_CTX_get_cleanup: function(ctx: POSSL_DECODER_CTX): TOSSL_DECODER_CLEANUP_func_cb; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_CTX_get_cleanup}

  OSSL_DECODER_export: function(decoder_inst: POSSL_DECODER_INSTANCE; reference: Pointer; reference_sz: TIdC_SIZET; export_cb: TOSSL_DECODER_export_export_cb_cb; export_cbarg: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_export}

  OSSL_DECODER_from_bio: function(ctx: POSSL_DECODER_CTX; _in: PBIO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_from_bio}

  OSSL_DECODER_from_fp: function(ctx: POSSL_DECODER_CTX; _in: PFILE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_from_fp}

  OSSL_DECODER_from_data: function(ctx: POSSL_DECODER_CTX; pdata: PPIdAnsiChar; pdata_len: PIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_from_data}

  OSSL_DECODER_CTX_new_for_pkey: function(pkey: PPEVP_PKEY; input_type: PIdAnsiChar; input_struct: PIdAnsiChar; keytype: PIdAnsiChar; selection: TIdC_INT; libctx: POSSL_LIB_CTX; propquery: PIdAnsiChar): POSSL_DECODER_CTX; cdecl = nil;
  {$EXTERNALSYM OSSL_DECODER_CTX_new_for_pkey}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function OSSL_DECODER_fetch(libctx: POSSL_LIB_CTX; name: PIdAnsiChar; properties: PIdAnsiChar): POSSL_DECODER; cdecl;
function OSSL_DECODER_up_ref(encoder: POSSL_DECODER): TIdC_INT; cdecl;
procedure OSSL_DECODER_free(encoder: POSSL_DECODER); cdecl;
function OSSL_DECODER_get0_provider(encoder: POSSL_DECODER): POSSL_PROVIDER; cdecl;
function OSSL_DECODER_get0_properties(encoder: POSSL_DECODER): PIdAnsiChar; cdecl;
function OSSL_DECODER_get0_name(decoder: POSSL_DECODER): PIdAnsiChar; cdecl;
function OSSL_DECODER_get0_description(decoder: POSSL_DECODER): PIdAnsiChar; cdecl;
function OSSL_DECODER_is_a(encoder: POSSL_DECODER; name: PIdAnsiChar): TIdC_INT; cdecl;
procedure OSSL_DECODER_do_all_provided(libctx: POSSL_LIB_CTX; fn: TOSSL_DECODER_do_all_provided_fn_cb; arg: Pointer); cdecl;
function OSSL_DECODER_names_do_all(encoder: POSSL_DECODER; fn: TOSSL_DECODER_names_do_all_fn_cb; data: Pointer): TIdC_INT; cdecl;
function OSSL_DECODER_gettable_params(decoder: POSSL_DECODER): POSSL_PARAM_ARRAY; cdecl;
function OSSL_DECODER_get_params(decoder: POSSL_DECODER; params: POSSL_PARAM_ARRAY): TIdC_INT; cdecl;
function OSSL_DECODER_settable_ctx_params(encoder: POSSL_DECODER): POSSL_PARAM_ARRAY; cdecl;
function OSSL_DECODER_CTX_new: POSSL_DECODER_CTX; cdecl;
function OSSL_DECODER_CTX_set_params(ctx: POSSL_DECODER_CTX; params: POSSL_PARAM_ARRAY): TIdC_INT; cdecl;
procedure OSSL_DECODER_CTX_free(ctx: POSSL_DECODER_CTX); cdecl;
function OSSL_DECODER_CTX_set_passphrase(ctx: POSSL_DECODER_CTX; kstr: PIdAnsiChar; klen: TIdC_SIZET): TIdC_INT; cdecl;
function OSSL_DECODER_CTX_set_pem_password_cb(ctx: POSSL_DECODER_CTX; cb: TOSSL_DECODER_CTX_set_pem_password_cb_cb_cb; cbarg: Pointer): TIdC_INT; cdecl;
function OSSL_DECODER_CTX_set_passphrase_cb(ctx: POSSL_DECODER_CTX; cb: TOSSL_DECODER_CTX_set_passphrase_cb_cb_cb; cbarg: Pointer): TIdC_INT; cdecl;
function OSSL_DECODER_CTX_set_passphrase_ui(ctx: POSSL_DECODER_CTX; ui_method: PUI_METHOD; ui_data: Pointer): TIdC_INT; cdecl;
function OSSL_DECODER_CTX_set_selection(ctx: POSSL_DECODER_CTX; selection: TIdC_INT): TIdC_INT; cdecl;
function OSSL_DECODER_CTX_set_input_type(ctx: POSSL_DECODER_CTX; input_type: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_DECODER_CTX_set_input_structure(ctx: POSSL_DECODER_CTX; input_structure: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_DECODER_CTX_add_decoder(ctx: POSSL_DECODER_CTX; decoder: POSSL_DECODER): TIdC_INT; cdecl;
function OSSL_DECODER_CTX_add_extra(ctx: POSSL_DECODER_CTX; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_DECODER_CTX_get_num_decoders(ctx: POSSL_DECODER_CTX): TIdC_INT; cdecl;
function OSSL_DECODER_INSTANCE_get_decoder(decoder_inst: POSSL_DECODER_INSTANCE): POSSL_DECODER; cdecl;
function OSSL_DECODER_INSTANCE_get_decoder_ctx(decoder_inst: POSSL_DECODER_INSTANCE): Pointer; cdecl;
function OSSL_DECODER_INSTANCE_get_input_type(decoder_inst: POSSL_DECODER_INSTANCE): PIdAnsiChar; cdecl;
function OSSL_DECODER_INSTANCE_get_input_structure(decoder_inst: POSSL_DECODER_INSTANCE; was_set: PIdC_INT): PIdAnsiChar; cdecl;
function OSSL_DECODER_CTX_set_construct(ctx: POSSL_DECODER_CTX; construct: TOSSL_DECODER_CONSTRUCT_func_cb): TIdC_INT; cdecl;
function OSSL_DECODER_CTX_set_construct_data(ctx: POSSL_DECODER_CTX; construct_data: Pointer): TIdC_INT; cdecl;
function OSSL_DECODER_CTX_set_cleanup(ctx: POSSL_DECODER_CTX; cleanup: TOSSL_DECODER_CLEANUP_func_cb): TIdC_INT; cdecl;
function OSSL_DECODER_CTX_get_construct(ctx: POSSL_DECODER_CTX): TOSSL_DECODER_CONSTRUCT_func_cb; cdecl;
function OSSL_DECODER_CTX_get_construct_data(ctx: POSSL_DECODER_CTX): Pointer; cdecl;
function OSSL_DECODER_CTX_get_cleanup(ctx: POSSL_DECODER_CTX): TOSSL_DECODER_CLEANUP_func_cb; cdecl;
function OSSL_DECODER_export(decoder_inst: POSSL_DECODER_INSTANCE; reference: Pointer; reference_sz: TIdC_SIZET; export_cb: TOSSL_DECODER_export_export_cb_cb; export_cbarg: Pointer): TIdC_INT; cdecl;
function OSSL_DECODER_from_bio(ctx: POSSL_DECODER_CTX; _in: PBIO): TIdC_INT; cdecl;
function OSSL_DECODER_from_fp(ctx: POSSL_DECODER_CTX; _in: PFILE): TIdC_INT; cdecl;
function OSSL_DECODER_from_data(ctx: POSSL_DECODER_CTX; pdata: PPIdAnsiChar; pdata_len: PIdC_SIZET): TIdC_INT; cdecl;
function OSSL_DECODER_CTX_new_for_pkey(pkey: PPEVP_PKEY; input_type: PIdAnsiChar; input_struct: PIdAnsiChar; keytype: PIdAnsiChar; selection: TIdC_INT; libctx: POSSL_LIB_CTX; propquery: PIdAnsiChar): POSSL_DECODER_CTX; cdecl;
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

function OSSL_DECODER_fetch(libctx: POSSL_LIB_CTX; name: PIdAnsiChar; properties: PIdAnsiChar): POSSL_DECODER; cdecl external CLibCrypto name 'OSSL_DECODER_fetch';
function OSSL_DECODER_up_ref(encoder: POSSL_DECODER): TIdC_INT; cdecl external CLibCrypto name 'OSSL_DECODER_up_ref';
procedure OSSL_DECODER_free(encoder: POSSL_DECODER); cdecl external CLibCrypto name 'OSSL_DECODER_free';
function OSSL_DECODER_get0_provider(encoder: POSSL_DECODER): POSSL_PROVIDER; cdecl external CLibCrypto name 'OSSL_DECODER_get0_provider';
function OSSL_DECODER_get0_properties(encoder: POSSL_DECODER): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_DECODER_get0_properties';
function OSSL_DECODER_get0_name(decoder: POSSL_DECODER): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_DECODER_get0_name';
function OSSL_DECODER_get0_description(decoder: POSSL_DECODER): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_DECODER_get0_description';
function OSSL_DECODER_is_a(encoder: POSSL_DECODER; name: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_DECODER_is_a';
procedure OSSL_DECODER_do_all_provided(libctx: POSSL_LIB_CTX; fn: TOSSL_DECODER_do_all_provided_fn_cb; arg: Pointer); cdecl external CLibCrypto name 'OSSL_DECODER_do_all_provided';
function OSSL_DECODER_names_do_all(encoder: POSSL_DECODER; fn: TOSSL_DECODER_names_do_all_fn_cb; data: Pointer): TIdC_INT; cdecl external CLibCrypto name 'OSSL_DECODER_names_do_all';
function OSSL_DECODER_gettable_params(decoder: POSSL_DECODER): POSSL_PARAM_ARRAY; cdecl external CLibCrypto name 'OSSL_DECODER_gettable_params';
function OSSL_DECODER_get_params(decoder: POSSL_DECODER; params: POSSL_PARAM_ARRAY): TIdC_INT; cdecl external CLibCrypto name 'OSSL_DECODER_get_params';
function OSSL_DECODER_settable_ctx_params(encoder: POSSL_DECODER): POSSL_PARAM_ARRAY; cdecl external CLibCrypto name 'OSSL_DECODER_settable_ctx_params';
function OSSL_DECODER_CTX_new: POSSL_DECODER_CTX; cdecl external CLibCrypto name 'OSSL_DECODER_CTX_new';
function OSSL_DECODER_CTX_set_params(ctx: POSSL_DECODER_CTX; params: POSSL_PARAM_ARRAY): TIdC_INT; cdecl external CLibCrypto name 'OSSL_DECODER_CTX_set_params';
procedure OSSL_DECODER_CTX_free(ctx: POSSL_DECODER_CTX); cdecl external CLibCrypto name 'OSSL_DECODER_CTX_free';
function OSSL_DECODER_CTX_set_passphrase(ctx: POSSL_DECODER_CTX; kstr: PIdAnsiChar; klen: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'OSSL_DECODER_CTX_set_passphrase';
function OSSL_DECODER_CTX_set_pem_password_cb(ctx: POSSL_DECODER_CTX; cb: TOSSL_DECODER_CTX_set_pem_password_cb_cb_cb; cbarg: Pointer): TIdC_INT; cdecl external CLibCrypto name 'OSSL_DECODER_CTX_set_pem_password_cb';
function OSSL_DECODER_CTX_set_passphrase_cb(ctx: POSSL_DECODER_CTX; cb: TOSSL_DECODER_CTX_set_passphrase_cb_cb_cb; cbarg: Pointer): TIdC_INT; cdecl external CLibCrypto name 'OSSL_DECODER_CTX_set_passphrase_cb';
function OSSL_DECODER_CTX_set_passphrase_ui(ctx: POSSL_DECODER_CTX; ui_method: PUI_METHOD; ui_data: Pointer): TIdC_INT; cdecl external CLibCrypto name 'OSSL_DECODER_CTX_set_passphrase_ui';
function OSSL_DECODER_CTX_set_selection(ctx: POSSL_DECODER_CTX; selection: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_DECODER_CTX_set_selection';
function OSSL_DECODER_CTX_set_input_type(ctx: POSSL_DECODER_CTX; input_type: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_DECODER_CTX_set_input_type';
function OSSL_DECODER_CTX_set_input_structure(ctx: POSSL_DECODER_CTX; input_structure: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_DECODER_CTX_set_input_structure';
function OSSL_DECODER_CTX_add_decoder(ctx: POSSL_DECODER_CTX; decoder: POSSL_DECODER): TIdC_INT; cdecl external CLibCrypto name 'OSSL_DECODER_CTX_add_decoder';
function OSSL_DECODER_CTX_add_extra(ctx: POSSL_DECODER_CTX; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_DECODER_CTX_add_extra';
function OSSL_DECODER_CTX_get_num_decoders(ctx: POSSL_DECODER_CTX): TIdC_INT; cdecl external CLibCrypto name 'OSSL_DECODER_CTX_get_num_decoders';
function OSSL_DECODER_INSTANCE_get_decoder(decoder_inst: POSSL_DECODER_INSTANCE): POSSL_DECODER; cdecl external CLibCrypto name 'OSSL_DECODER_INSTANCE_get_decoder';
function OSSL_DECODER_INSTANCE_get_decoder_ctx(decoder_inst: POSSL_DECODER_INSTANCE): Pointer; cdecl external CLibCrypto name 'OSSL_DECODER_INSTANCE_get_decoder_ctx';
function OSSL_DECODER_INSTANCE_get_input_type(decoder_inst: POSSL_DECODER_INSTANCE): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_DECODER_INSTANCE_get_input_type';
function OSSL_DECODER_INSTANCE_get_input_structure(decoder_inst: POSSL_DECODER_INSTANCE; was_set: PIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_DECODER_INSTANCE_get_input_structure';
function OSSL_DECODER_CTX_set_construct(ctx: POSSL_DECODER_CTX; construct: TOSSL_DECODER_CONSTRUCT_func_cb): TIdC_INT; cdecl external CLibCrypto name 'OSSL_DECODER_CTX_set_construct';
function OSSL_DECODER_CTX_set_construct_data(ctx: POSSL_DECODER_CTX; construct_data: Pointer): TIdC_INT; cdecl external CLibCrypto name 'OSSL_DECODER_CTX_set_construct_data';
function OSSL_DECODER_CTX_set_cleanup(ctx: POSSL_DECODER_CTX; cleanup: TOSSL_DECODER_CLEANUP_func_cb): TIdC_INT; cdecl external CLibCrypto name 'OSSL_DECODER_CTX_set_cleanup';
function OSSL_DECODER_CTX_get_construct(ctx: POSSL_DECODER_CTX): TOSSL_DECODER_CONSTRUCT_func_cb; cdecl external CLibCrypto name 'OSSL_DECODER_CTX_get_construct';
function OSSL_DECODER_CTX_get_construct_data(ctx: POSSL_DECODER_CTX): Pointer; cdecl external CLibCrypto name 'OSSL_DECODER_CTX_get_construct_data';
function OSSL_DECODER_CTX_get_cleanup(ctx: POSSL_DECODER_CTX): TOSSL_DECODER_CLEANUP_func_cb; cdecl external CLibCrypto name 'OSSL_DECODER_CTX_get_cleanup';
function OSSL_DECODER_export(decoder_inst: POSSL_DECODER_INSTANCE; reference: Pointer; reference_sz: TIdC_SIZET; export_cb: TOSSL_DECODER_export_export_cb_cb; export_cbarg: Pointer): TIdC_INT; cdecl external CLibCrypto name 'OSSL_DECODER_export';
function OSSL_DECODER_from_bio(ctx: POSSL_DECODER_CTX; _in: PBIO): TIdC_INT; cdecl external CLibCrypto name 'OSSL_DECODER_from_bio';
function OSSL_DECODER_from_fp(ctx: POSSL_DECODER_CTX; _in: PFILE): TIdC_INT; cdecl external CLibCrypto name 'OSSL_DECODER_from_fp';
function OSSL_DECODER_from_data(ctx: POSSL_DECODER_CTX; pdata: PPIdAnsiChar; pdata_len: PIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'OSSL_DECODER_from_data';
function OSSL_DECODER_CTX_new_for_pkey(pkey: PPEVP_PKEY; input_type: PIdAnsiChar; input_struct: PIdAnsiChar; keytype: PIdAnsiChar; selection: TIdC_INT; libctx: POSSL_LIB_CTX; propquery: PIdAnsiChar): POSSL_DECODER_CTX; cdecl external CLibCrypto name 'OSSL_DECODER_CTX_new_for_pkey';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  OSSL_DECODER_fetch_procname = 'OSSL_DECODER_fetch';
  OSSL_DECODER_fetch_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_up_ref_procname = 'OSSL_DECODER_up_ref';
  OSSL_DECODER_up_ref_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_free_procname = 'OSSL_DECODER_free';
  OSSL_DECODER_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_get0_provider_procname = 'OSSL_DECODER_get0_provider';
  OSSL_DECODER_get0_provider_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_get0_properties_procname = 'OSSL_DECODER_get0_properties';
  OSSL_DECODER_get0_properties_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_get0_name_procname = 'OSSL_DECODER_get0_name';
  OSSL_DECODER_get0_name_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_get0_description_procname = 'OSSL_DECODER_get0_description';
  OSSL_DECODER_get0_description_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_is_a_procname = 'OSSL_DECODER_is_a';
  OSSL_DECODER_is_a_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_do_all_provided_procname = 'OSSL_DECODER_do_all_provided';
  OSSL_DECODER_do_all_provided_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_names_do_all_procname = 'OSSL_DECODER_names_do_all';
  OSSL_DECODER_names_do_all_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_gettable_params_procname = 'OSSL_DECODER_gettable_params';
  OSSL_DECODER_gettable_params_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_get_params_procname = 'OSSL_DECODER_get_params';
  OSSL_DECODER_get_params_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_settable_ctx_params_procname = 'OSSL_DECODER_settable_ctx_params';
  OSSL_DECODER_settable_ctx_params_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_CTX_new_procname = 'OSSL_DECODER_CTX_new';
  OSSL_DECODER_CTX_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_CTX_set_params_procname = 'OSSL_DECODER_CTX_set_params';
  OSSL_DECODER_CTX_set_params_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_CTX_free_procname = 'OSSL_DECODER_CTX_free';
  OSSL_DECODER_CTX_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_CTX_set_passphrase_procname = 'OSSL_DECODER_CTX_set_passphrase';
  OSSL_DECODER_CTX_set_passphrase_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_CTX_set_pem_password_cb_procname = 'OSSL_DECODER_CTX_set_pem_password_cb';
  OSSL_DECODER_CTX_set_pem_password_cb_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_CTX_set_passphrase_cb_procname = 'OSSL_DECODER_CTX_set_passphrase_cb';
  OSSL_DECODER_CTX_set_passphrase_cb_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_CTX_set_passphrase_ui_procname = 'OSSL_DECODER_CTX_set_passphrase_ui';
  OSSL_DECODER_CTX_set_passphrase_ui_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_CTX_set_selection_procname = 'OSSL_DECODER_CTX_set_selection';
  OSSL_DECODER_CTX_set_selection_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_CTX_set_input_type_procname = 'OSSL_DECODER_CTX_set_input_type';
  OSSL_DECODER_CTX_set_input_type_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_CTX_set_input_structure_procname = 'OSSL_DECODER_CTX_set_input_structure';
  OSSL_DECODER_CTX_set_input_structure_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_CTX_add_decoder_procname = 'OSSL_DECODER_CTX_add_decoder';
  OSSL_DECODER_CTX_add_decoder_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_CTX_add_extra_procname = 'OSSL_DECODER_CTX_add_extra';
  OSSL_DECODER_CTX_add_extra_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_CTX_get_num_decoders_procname = 'OSSL_DECODER_CTX_get_num_decoders';
  OSSL_DECODER_CTX_get_num_decoders_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_INSTANCE_get_decoder_procname = 'OSSL_DECODER_INSTANCE_get_decoder';
  OSSL_DECODER_INSTANCE_get_decoder_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_INSTANCE_get_decoder_ctx_procname = 'OSSL_DECODER_INSTANCE_get_decoder_ctx';
  OSSL_DECODER_INSTANCE_get_decoder_ctx_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_INSTANCE_get_input_type_procname = 'OSSL_DECODER_INSTANCE_get_input_type';
  OSSL_DECODER_INSTANCE_get_input_type_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_INSTANCE_get_input_structure_procname = 'OSSL_DECODER_INSTANCE_get_input_structure';
  OSSL_DECODER_INSTANCE_get_input_structure_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_CTX_set_construct_procname = 'OSSL_DECODER_CTX_set_construct';
  OSSL_DECODER_CTX_set_construct_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_CTX_set_construct_data_procname = 'OSSL_DECODER_CTX_set_construct_data';
  OSSL_DECODER_CTX_set_construct_data_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_CTX_set_cleanup_procname = 'OSSL_DECODER_CTX_set_cleanup';
  OSSL_DECODER_CTX_set_cleanup_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_CTX_get_construct_procname = 'OSSL_DECODER_CTX_get_construct';
  OSSL_DECODER_CTX_get_construct_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_CTX_get_construct_data_procname = 'OSSL_DECODER_CTX_get_construct_data';
  OSSL_DECODER_CTX_get_construct_data_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_CTX_get_cleanup_procname = 'OSSL_DECODER_CTX_get_cleanup';
  OSSL_DECODER_CTX_get_cleanup_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_export_procname = 'OSSL_DECODER_export';
  OSSL_DECODER_export_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_from_bio_procname = 'OSSL_DECODER_from_bio';
  OSSL_DECODER_from_bio_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_from_fp_procname = 'OSSL_DECODER_from_fp';
  OSSL_DECODER_from_fp_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_from_data_procname = 'OSSL_DECODER_from_data';
  OSSL_DECODER_from_data_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_DECODER_CTX_new_for_pkey_procname = 'OSSL_DECODER_CTX_new_for_pkey';
  OSSL_DECODER_CTX_new_for_pkey_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_OSSL_DECODER_fetch(libctx: POSSL_LIB_CTX; name: PIdAnsiChar; properties: PIdAnsiChar): POSSL_DECODER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_fetch_procname);
end;

function ERR_OSSL_DECODER_up_ref(encoder: POSSL_DECODER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_up_ref_procname);
end;

procedure ERR_OSSL_DECODER_free(encoder: POSSL_DECODER); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_free_procname);
end;

function ERR_OSSL_DECODER_get0_provider(encoder: POSSL_DECODER): POSSL_PROVIDER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_get0_provider_procname);
end;

function ERR_OSSL_DECODER_get0_properties(encoder: POSSL_DECODER): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_get0_properties_procname);
end;

function ERR_OSSL_DECODER_get0_name(decoder: POSSL_DECODER): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_get0_name_procname);
end;

function ERR_OSSL_DECODER_get0_description(decoder: POSSL_DECODER): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_get0_description_procname);
end;

function ERR_OSSL_DECODER_is_a(encoder: POSSL_DECODER; name: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_is_a_procname);
end;

procedure ERR_OSSL_DECODER_do_all_provided(libctx: POSSL_LIB_CTX; fn: TOSSL_DECODER_do_all_provided_fn_cb; arg: Pointer); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_do_all_provided_procname);
end;

function ERR_OSSL_DECODER_names_do_all(encoder: POSSL_DECODER; fn: TOSSL_DECODER_names_do_all_fn_cb; data: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_names_do_all_procname);
end;

function ERR_OSSL_DECODER_gettable_params(decoder: POSSL_DECODER): POSSL_PARAM_ARRAY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_gettable_params_procname);
end;

function ERR_OSSL_DECODER_get_params(decoder: POSSL_DECODER; params: POSSL_PARAM_ARRAY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_get_params_procname);
end;

function ERR_OSSL_DECODER_settable_ctx_params(encoder: POSSL_DECODER): POSSL_PARAM_ARRAY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_settable_ctx_params_procname);
end;

function ERR_OSSL_DECODER_CTX_new: POSSL_DECODER_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_CTX_new_procname);
end;

function ERR_OSSL_DECODER_CTX_set_params(ctx: POSSL_DECODER_CTX; params: POSSL_PARAM_ARRAY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_CTX_set_params_procname);
end;

procedure ERR_OSSL_DECODER_CTX_free(ctx: POSSL_DECODER_CTX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_CTX_free_procname);
end;

function ERR_OSSL_DECODER_CTX_set_passphrase(ctx: POSSL_DECODER_CTX; kstr: PIdAnsiChar; klen: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_CTX_set_passphrase_procname);
end;

function ERR_OSSL_DECODER_CTX_set_pem_password_cb(ctx: POSSL_DECODER_CTX; cb: TOSSL_DECODER_CTX_set_pem_password_cb_cb_cb; cbarg: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_CTX_set_pem_password_cb_procname);
end;

function ERR_OSSL_DECODER_CTX_set_passphrase_cb(ctx: POSSL_DECODER_CTX; cb: TOSSL_DECODER_CTX_set_passphrase_cb_cb_cb; cbarg: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_CTX_set_passphrase_cb_procname);
end;

function ERR_OSSL_DECODER_CTX_set_passphrase_ui(ctx: POSSL_DECODER_CTX; ui_method: PUI_METHOD; ui_data: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_CTX_set_passphrase_ui_procname);
end;

function ERR_OSSL_DECODER_CTX_set_selection(ctx: POSSL_DECODER_CTX; selection: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_CTX_set_selection_procname);
end;

function ERR_OSSL_DECODER_CTX_set_input_type(ctx: POSSL_DECODER_CTX; input_type: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_CTX_set_input_type_procname);
end;

function ERR_OSSL_DECODER_CTX_set_input_structure(ctx: POSSL_DECODER_CTX; input_structure: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_CTX_set_input_structure_procname);
end;

function ERR_OSSL_DECODER_CTX_add_decoder(ctx: POSSL_DECODER_CTX; decoder: POSSL_DECODER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_CTX_add_decoder_procname);
end;

function ERR_OSSL_DECODER_CTX_add_extra(ctx: POSSL_DECODER_CTX; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_CTX_add_extra_procname);
end;

function ERR_OSSL_DECODER_CTX_get_num_decoders(ctx: POSSL_DECODER_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_CTX_get_num_decoders_procname);
end;

function ERR_OSSL_DECODER_INSTANCE_get_decoder(decoder_inst: POSSL_DECODER_INSTANCE): POSSL_DECODER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_INSTANCE_get_decoder_procname);
end;

function ERR_OSSL_DECODER_INSTANCE_get_decoder_ctx(decoder_inst: POSSL_DECODER_INSTANCE): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_INSTANCE_get_decoder_ctx_procname);
end;

function ERR_OSSL_DECODER_INSTANCE_get_input_type(decoder_inst: POSSL_DECODER_INSTANCE): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_INSTANCE_get_input_type_procname);
end;

function ERR_OSSL_DECODER_INSTANCE_get_input_structure(decoder_inst: POSSL_DECODER_INSTANCE; was_set: PIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_INSTANCE_get_input_structure_procname);
end;

function ERR_OSSL_DECODER_CTX_set_construct(ctx: POSSL_DECODER_CTX; construct: TOSSL_DECODER_CONSTRUCT_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_CTX_set_construct_procname);
end;

function ERR_OSSL_DECODER_CTX_set_construct_data(ctx: POSSL_DECODER_CTX; construct_data: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_CTX_set_construct_data_procname);
end;

function ERR_OSSL_DECODER_CTX_set_cleanup(ctx: POSSL_DECODER_CTX; cleanup: TOSSL_DECODER_CLEANUP_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_CTX_set_cleanup_procname);
end;

function ERR_OSSL_DECODER_CTX_get_construct(ctx: POSSL_DECODER_CTX): TOSSL_DECODER_CONSTRUCT_func_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_CTX_get_construct_procname);
end;

function ERR_OSSL_DECODER_CTX_get_construct_data(ctx: POSSL_DECODER_CTX): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_CTX_get_construct_data_procname);
end;

function ERR_OSSL_DECODER_CTX_get_cleanup(ctx: POSSL_DECODER_CTX): TOSSL_DECODER_CLEANUP_func_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_CTX_get_cleanup_procname);
end;

function ERR_OSSL_DECODER_export(decoder_inst: POSSL_DECODER_INSTANCE; reference: Pointer; reference_sz: TIdC_SIZET; export_cb: TOSSL_DECODER_export_export_cb_cb; export_cbarg: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_export_procname);
end;

function ERR_OSSL_DECODER_from_bio(ctx: POSSL_DECODER_CTX; _in: PBIO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_from_bio_procname);
end;

function ERR_OSSL_DECODER_from_fp(ctx: POSSL_DECODER_CTX; _in: PFILE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_from_fp_procname);
end;

function ERR_OSSL_DECODER_from_data(ctx: POSSL_DECODER_CTX; pdata: PPIdAnsiChar; pdata_len: PIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_from_data_procname);
end;

function ERR_OSSL_DECODER_CTX_new_for_pkey(pkey: PPEVP_PKEY; input_type: PIdAnsiChar; input_struct: PIdAnsiChar; keytype: PIdAnsiChar; selection: TIdC_INT; libctx: POSSL_LIB_CTX; propquery: PIdAnsiChar): POSSL_DECODER_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_DECODER_CTX_new_for_pkey_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  OSSL_DECODER_fetch := LoadLibFunction(ADllHandle, OSSL_DECODER_fetch_procname);
  FuncLoadError := not assigned(OSSL_DECODER_fetch);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_fetch_allownil)}
    OSSL_DECODER_fetch := ERR_OSSL_DECODER_fetch;
    {$ifend}
    {$if declared(OSSL_DECODER_fetch_introduced)}
    if LibVersion < OSSL_DECODER_fetch_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_fetch)}
      OSSL_DECODER_fetch := FC_OSSL_DECODER_fetch;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_fetch_removed)}
    if OSSL_DECODER_fetch_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_fetch)}
      OSSL_DECODER_fetch := _OSSL_DECODER_fetch;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_fetch_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_fetch');
    {$ifend}
  end;
  
  OSSL_DECODER_up_ref := LoadLibFunction(ADllHandle, OSSL_DECODER_up_ref_procname);
  FuncLoadError := not assigned(OSSL_DECODER_up_ref);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_up_ref_allownil)}
    OSSL_DECODER_up_ref := ERR_OSSL_DECODER_up_ref;
    {$ifend}
    {$if declared(OSSL_DECODER_up_ref_introduced)}
    if LibVersion < OSSL_DECODER_up_ref_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_up_ref)}
      OSSL_DECODER_up_ref := FC_OSSL_DECODER_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_up_ref_removed)}
    if OSSL_DECODER_up_ref_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_up_ref)}
      OSSL_DECODER_up_ref := _OSSL_DECODER_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_up_ref_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_up_ref');
    {$ifend}
  end;
  
  OSSL_DECODER_free := LoadLibFunction(ADllHandle, OSSL_DECODER_free_procname);
  FuncLoadError := not assigned(OSSL_DECODER_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_free_allownil)}
    OSSL_DECODER_free := ERR_OSSL_DECODER_free;
    {$ifend}
    {$if declared(OSSL_DECODER_free_introduced)}
    if LibVersion < OSSL_DECODER_free_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_free)}
      OSSL_DECODER_free := FC_OSSL_DECODER_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_free_removed)}
    if OSSL_DECODER_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_free)}
      OSSL_DECODER_free := _OSSL_DECODER_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_free');
    {$ifend}
  end;
  
  OSSL_DECODER_get0_provider := LoadLibFunction(ADllHandle, OSSL_DECODER_get0_provider_procname);
  FuncLoadError := not assigned(OSSL_DECODER_get0_provider);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_get0_provider_allownil)}
    OSSL_DECODER_get0_provider := ERR_OSSL_DECODER_get0_provider;
    {$ifend}
    {$if declared(OSSL_DECODER_get0_provider_introduced)}
    if LibVersion < OSSL_DECODER_get0_provider_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_get0_provider)}
      OSSL_DECODER_get0_provider := FC_OSSL_DECODER_get0_provider;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_get0_provider_removed)}
    if OSSL_DECODER_get0_provider_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_get0_provider)}
      OSSL_DECODER_get0_provider := _OSSL_DECODER_get0_provider;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_get0_provider_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_get0_provider');
    {$ifend}
  end;
  
  OSSL_DECODER_get0_properties := LoadLibFunction(ADllHandle, OSSL_DECODER_get0_properties_procname);
  FuncLoadError := not assigned(OSSL_DECODER_get0_properties);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_get0_properties_allownil)}
    OSSL_DECODER_get0_properties := ERR_OSSL_DECODER_get0_properties;
    {$ifend}
    {$if declared(OSSL_DECODER_get0_properties_introduced)}
    if LibVersion < OSSL_DECODER_get0_properties_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_get0_properties)}
      OSSL_DECODER_get0_properties := FC_OSSL_DECODER_get0_properties;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_get0_properties_removed)}
    if OSSL_DECODER_get0_properties_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_get0_properties)}
      OSSL_DECODER_get0_properties := _OSSL_DECODER_get0_properties;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_get0_properties_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_get0_properties');
    {$ifend}
  end;
  
  OSSL_DECODER_get0_name := LoadLibFunction(ADllHandle, OSSL_DECODER_get0_name_procname);
  FuncLoadError := not assigned(OSSL_DECODER_get0_name);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_get0_name_allownil)}
    OSSL_DECODER_get0_name := ERR_OSSL_DECODER_get0_name;
    {$ifend}
    {$if declared(OSSL_DECODER_get0_name_introduced)}
    if LibVersion < OSSL_DECODER_get0_name_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_get0_name)}
      OSSL_DECODER_get0_name := FC_OSSL_DECODER_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_get0_name_removed)}
    if OSSL_DECODER_get0_name_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_get0_name)}
      OSSL_DECODER_get0_name := _OSSL_DECODER_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_get0_name_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_get0_name');
    {$ifend}
  end;
  
  OSSL_DECODER_get0_description := LoadLibFunction(ADllHandle, OSSL_DECODER_get0_description_procname);
  FuncLoadError := not assigned(OSSL_DECODER_get0_description);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_get0_description_allownil)}
    OSSL_DECODER_get0_description := ERR_OSSL_DECODER_get0_description;
    {$ifend}
    {$if declared(OSSL_DECODER_get0_description_introduced)}
    if LibVersion < OSSL_DECODER_get0_description_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_get0_description)}
      OSSL_DECODER_get0_description := FC_OSSL_DECODER_get0_description;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_get0_description_removed)}
    if OSSL_DECODER_get0_description_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_get0_description)}
      OSSL_DECODER_get0_description := _OSSL_DECODER_get0_description;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_get0_description_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_get0_description');
    {$ifend}
  end;
  
  OSSL_DECODER_is_a := LoadLibFunction(ADllHandle, OSSL_DECODER_is_a_procname);
  FuncLoadError := not assigned(OSSL_DECODER_is_a);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_is_a_allownil)}
    OSSL_DECODER_is_a := ERR_OSSL_DECODER_is_a;
    {$ifend}
    {$if declared(OSSL_DECODER_is_a_introduced)}
    if LibVersion < OSSL_DECODER_is_a_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_is_a)}
      OSSL_DECODER_is_a := FC_OSSL_DECODER_is_a;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_is_a_removed)}
    if OSSL_DECODER_is_a_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_is_a)}
      OSSL_DECODER_is_a := _OSSL_DECODER_is_a;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_is_a_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_is_a');
    {$ifend}
  end;
  
  OSSL_DECODER_do_all_provided := LoadLibFunction(ADllHandle, OSSL_DECODER_do_all_provided_procname);
  FuncLoadError := not assigned(OSSL_DECODER_do_all_provided);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_do_all_provided_allownil)}
    OSSL_DECODER_do_all_provided := ERR_OSSL_DECODER_do_all_provided;
    {$ifend}
    {$if declared(OSSL_DECODER_do_all_provided_introduced)}
    if LibVersion < OSSL_DECODER_do_all_provided_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_do_all_provided)}
      OSSL_DECODER_do_all_provided := FC_OSSL_DECODER_do_all_provided;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_do_all_provided_removed)}
    if OSSL_DECODER_do_all_provided_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_do_all_provided)}
      OSSL_DECODER_do_all_provided := _OSSL_DECODER_do_all_provided;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_do_all_provided_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_do_all_provided');
    {$ifend}
  end;
  
  OSSL_DECODER_names_do_all := LoadLibFunction(ADllHandle, OSSL_DECODER_names_do_all_procname);
  FuncLoadError := not assigned(OSSL_DECODER_names_do_all);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_names_do_all_allownil)}
    OSSL_DECODER_names_do_all := ERR_OSSL_DECODER_names_do_all;
    {$ifend}
    {$if declared(OSSL_DECODER_names_do_all_introduced)}
    if LibVersion < OSSL_DECODER_names_do_all_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_names_do_all)}
      OSSL_DECODER_names_do_all := FC_OSSL_DECODER_names_do_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_names_do_all_removed)}
    if OSSL_DECODER_names_do_all_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_names_do_all)}
      OSSL_DECODER_names_do_all := _OSSL_DECODER_names_do_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_names_do_all_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_names_do_all');
    {$ifend}
  end;
  
  OSSL_DECODER_gettable_params := LoadLibFunction(ADllHandle, OSSL_DECODER_gettable_params_procname);
  FuncLoadError := not assigned(OSSL_DECODER_gettable_params);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_gettable_params_allownil)}
    OSSL_DECODER_gettable_params := ERR_OSSL_DECODER_gettable_params;
    {$ifend}
    {$if declared(OSSL_DECODER_gettable_params_introduced)}
    if LibVersion < OSSL_DECODER_gettable_params_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_gettable_params)}
      OSSL_DECODER_gettable_params := FC_OSSL_DECODER_gettable_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_gettable_params_removed)}
    if OSSL_DECODER_gettable_params_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_gettable_params)}
      OSSL_DECODER_gettable_params := _OSSL_DECODER_gettable_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_gettable_params_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_gettable_params');
    {$ifend}
  end;
  
  OSSL_DECODER_get_params := LoadLibFunction(ADllHandle, OSSL_DECODER_get_params_procname);
  FuncLoadError := not assigned(OSSL_DECODER_get_params);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_get_params_allownil)}
    OSSL_DECODER_get_params := ERR_OSSL_DECODER_get_params;
    {$ifend}
    {$if declared(OSSL_DECODER_get_params_introduced)}
    if LibVersion < OSSL_DECODER_get_params_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_get_params)}
      OSSL_DECODER_get_params := FC_OSSL_DECODER_get_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_get_params_removed)}
    if OSSL_DECODER_get_params_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_get_params)}
      OSSL_DECODER_get_params := _OSSL_DECODER_get_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_get_params_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_get_params');
    {$ifend}
  end;
  
  OSSL_DECODER_settable_ctx_params := LoadLibFunction(ADllHandle, OSSL_DECODER_settable_ctx_params_procname);
  FuncLoadError := not assigned(OSSL_DECODER_settable_ctx_params);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_settable_ctx_params_allownil)}
    OSSL_DECODER_settable_ctx_params := ERR_OSSL_DECODER_settable_ctx_params;
    {$ifend}
    {$if declared(OSSL_DECODER_settable_ctx_params_introduced)}
    if LibVersion < OSSL_DECODER_settable_ctx_params_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_settable_ctx_params)}
      OSSL_DECODER_settable_ctx_params := FC_OSSL_DECODER_settable_ctx_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_settable_ctx_params_removed)}
    if OSSL_DECODER_settable_ctx_params_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_settable_ctx_params)}
      OSSL_DECODER_settable_ctx_params := _OSSL_DECODER_settable_ctx_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_settable_ctx_params_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_settable_ctx_params');
    {$ifend}
  end;
  
  OSSL_DECODER_CTX_new := LoadLibFunction(ADllHandle, OSSL_DECODER_CTX_new_procname);
  FuncLoadError := not assigned(OSSL_DECODER_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_CTX_new_allownil)}
    OSSL_DECODER_CTX_new := ERR_OSSL_DECODER_CTX_new;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_new_introduced)}
    if LibVersion < OSSL_DECODER_CTX_new_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_CTX_new)}
      OSSL_DECODER_CTX_new := FC_OSSL_DECODER_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_new_removed)}
    if OSSL_DECODER_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_CTX_new)}
      OSSL_DECODER_CTX_new := _OSSL_DECODER_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_CTX_new');
    {$ifend}
  end;
  
  OSSL_DECODER_CTX_set_params := LoadLibFunction(ADllHandle, OSSL_DECODER_CTX_set_params_procname);
  FuncLoadError := not assigned(OSSL_DECODER_CTX_set_params);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_CTX_set_params_allownil)}
    OSSL_DECODER_CTX_set_params := ERR_OSSL_DECODER_CTX_set_params;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_set_params_introduced)}
    if LibVersion < OSSL_DECODER_CTX_set_params_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_CTX_set_params)}
      OSSL_DECODER_CTX_set_params := FC_OSSL_DECODER_CTX_set_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_set_params_removed)}
    if OSSL_DECODER_CTX_set_params_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_CTX_set_params)}
      OSSL_DECODER_CTX_set_params := _OSSL_DECODER_CTX_set_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_CTX_set_params_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_CTX_set_params');
    {$ifend}
  end;
  
  OSSL_DECODER_CTX_free := LoadLibFunction(ADllHandle, OSSL_DECODER_CTX_free_procname);
  FuncLoadError := not assigned(OSSL_DECODER_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_CTX_free_allownil)}
    OSSL_DECODER_CTX_free := ERR_OSSL_DECODER_CTX_free;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_free_introduced)}
    if LibVersion < OSSL_DECODER_CTX_free_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_CTX_free)}
      OSSL_DECODER_CTX_free := FC_OSSL_DECODER_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_free_removed)}
    if OSSL_DECODER_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_CTX_free)}
      OSSL_DECODER_CTX_free := _OSSL_DECODER_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_CTX_free');
    {$ifend}
  end;
  
  OSSL_DECODER_CTX_set_passphrase := LoadLibFunction(ADllHandle, OSSL_DECODER_CTX_set_passphrase_procname);
  FuncLoadError := not assigned(OSSL_DECODER_CTX_set_passphrase);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_CTX_set_passphrase_allownil)}
    OSSL_DECODER_CTX_set_passphrase := ERR_OSSL_DECODER_CTX_set_passphrase;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_set_passphrase_introduced)}
    if LibVersion < OSSL_DECODER_CTX_set_passphrase_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_CTX_set_passphrase)}
      OSSL_DECODER_CTX_set_passphrase := FC_OSSL_DECODER_CTX_set_passphrase;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_set_passphrase_removed)}
    if OSSL_DECODER_CTX_set_passphrase_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_CTX_set_passphrase)}
      OSSL_DECODER_CTX_set_passphrase := _OSSL_DECODER_CTX_set_passphrase;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_CTX_set_passphrase_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_CTX_set_passphrase');
    {$ifend}
  end;
  
  OSSL_DECODER_CTX_set_pem_password_cb := LoadLibFunction(ADllHandle, OSSL_DECODER_CTX_set_pem_password_cb_procname);
  FuncLoadError := not assigned(OSSL_DECODER_CTX_set_pem_password_cb);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_CTX_set_pem_password_cb_allownil)}
    OSSL_DECODER_CTX_set_pem_password_cb := ERR_OSSL_DECODER_CTX_set_pem_password_cb;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_set_pem_password_cb_introduced)}
    if LibVersion < OSSL_DECODER_CTX_set_pem_password_cb_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_CTX_set_pem_password_cb)}
      OSSL_DECODER_CTX_set_pem_password_cb := FC_OSSL_DECODER_CTX_set_pem_password_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_set_pem_password_cb_removed)}
    if OSSL_DECODER_CTX_set_pem_password_cb_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_CTX_set_pem_password_cb)}
      OSSL_DECODER_CTX_set_pem_password_cb := _OSSL_DECODER_CTX_set_pem_password_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_CTX_set_pem_password_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_CTX_set_pem_password_cb');
    {$ifend}
  end;
  
  OSSL_DECODER_CTX_set_passphrase_cb := LoadLibFunction(ADllHandle, OSSL_DECODER_CTX_set_passphrase_cb_procname);
  FuncLoadError := not assigned(OSSL_DECODER_CTX_set_passphrase_cb);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_CTX_set_passphrase_cb_allownil)}
    OSSL_DECODER_CTX_set_passphrase_cb := ERR_OSSL_DECODER_CTX_set_passphrase_cb;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_set_passphrase_cb_introduced)}
    if LibVersion < OSSL_DECODER_CTX_set_passphrase_cb_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_CTX_set_passphrase_cb)}
      OSSL_DECODER_CTX_set_passphrase_cb := FC_OSSL_DECODER_CTX_set_passphrase_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_set_passphrase_cb_removed)}
    if OSSL_DECODER_CTX_set_passphrase_cb_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_CTX_set_passphrase_cb)}
      OSSL_DECODER_CTX_set_passphrase_cb := _OSSL_DECODER_CTX_set_passphrase_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_CTX_set_passphrase_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_CTX_set_passphrase_cb');
    {$ifend}
  end;
  
  OSSL_DECODER_CTX_set_passphrase_ui := LoadLibFunction(ADllHandle, OSSL_DECODER_CTX_set_passphrase_ui_procname);
  FuncLoadError := not assigned(OSSL_DECODER_CTX_set_passphrase_ui);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_CTX_set_passphrase_ui_allownil)}
    OSSL_DECODER_CTX_set_passphrase_ui := ERR_OSSL_DECODER_CTX_set_passphrase_ui;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_set_passphrase_ui_introduced)}
    if LibVersion < OSSL_DECODER_CTX_set_passphrase_ui_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_CTX_set_passphrase_ui)}
      OSSL_DECODER_CTX_set_passphrase_ui := FC_OSSL_DECODER_CTX_set_passphrase_ui;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_set_passphrase_ui_removed)}
    if OSSL_DECODER_CTX_set_passphrase_ui_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_CTX_set_passphrase_ui)}
      OSSL_DECODER_CTX_set_passphrase_ui := _OSSL_DECODER_CTX_set_passphrase_ui;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_CTX_set_passphrase_ui_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_CTX_set_passphrase_ui');
    {$ifend}
  end;
  
  OSSL_DECODER_CTX_set_selection := LoadLibFunction(ADllHandle, OSSL_DECODER_CTX_set_selection_procname);
  FuncLoadError := not assigned(OSSL_DECODER_CTX_set_selection);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_CTX_set_selection_allownil)}
    OSSL_DECODER_CTX_set_selection := ERR_OSSL_DECODER_CTX_set_selection;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_set_selection_introduced)}
    if LibVersion < OSSL_DECODER_CTX_set_selection_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_CTX_set_selection)}
      OSSL_DECODER_CTX_set_selection := FC_OSSL_DECODER_CTX_set_selection;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_set_selection_removed)}
    if OSSL_DECODER_CTX_set_selection_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_CTX_set_selection)}
      OSSL_DECODER_CTX_set_selection := _OSSL_DECODER_CTX_set_selection;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_CTX_set_selection_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_CTX_set_selection');
    {$ifend}
  end;
  
  OSSL_DECODER_CTX_set_input_type := LoadLibFunction(ADllHandle, OSSL_DECODER_CTX_set_input_type_procname);
  FuncLoadError := not assigned(OSSL_DECODER_CTX_set_input_type);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_CTX_set_input_type_allownil)}
    OSSL_DECODER_CTX_set_input_type := ERR_OSSL_DECODER_CTX_set_input_type;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_set_input_type_introduced)}
    if LibVersion < OSSL_DECODER_CTX_set_input_type_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_CTX_set_input_type)}
      OSSL_DECODER_CTX_set_input_type := FC_OSSL_DECODER_CTX_set_input_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_set_input_type_removed)}
    if OSSL_DECODER_CTX_set_input_type_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_CTX_set_input_type)}
      OSSL_DECODER_CTX_set_input_type := _OSSL_DECODER_CTX_set_input_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_CTX_set_input_type_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_CTX_set_input_type');
    {$ifend}
  end;
  
  OSSL_DECODER_CTX_set_input_structure := LoadLibFunction(ADllHandle, OSSL_DECODER_CTX_set_input_structure_procname);
  FuncLoadError := not assigned(OSSL_DECODER_CTX_set_input_structure);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_CTX_set_input_structure_allownil)}
    OSSL_DECODER_CTX_set_input_structure := ERR_OSSL_DECODER_CTX_set_input_structure;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_set_input_structure_introduced)}
    if LibVersion < OSSL_DECODER_CTX_set_input_structure_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_CTX_set_input_structure)}
      OSSL_DECODER_CTX_set_input_structure := FC_OSSL_DECODER_CTX_set_input_structure;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_set_input_structure_removed)}
    if OSSL_DECODER_CTX_set_input_structure_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_CTX_set_input_structure)}
      OSSL_DECODER_CTX_set_input_structure := _OSSL_DECODER_CTX_set_input_structure;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_CTX_set_input_structure_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_CTX_set_input_structure');
    {$ifend}
  end;
  
  OSSL_DECODER_CTX_add_decoder := LoadLibFunction(ADllHandle, OSSL_DECODER_CTX_add_decoder_procname);
  FuncLoadError := not assigned(OSSL_DECODER_CTX_add_decoder);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_CTX_add_decoder_allownil)}
    OSSL_DECODER_CTX_add_decoder := ERR_OSSL_DECODER_CTX_add_decoder;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_add_decoder_introduced)}
    if LibVersion < OSSL_DECODER_CTX_add_decoder_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_CTX_add_decoder)}
      OSSL_DECODER_CTX_add_decoder := FC_OSSL_DECODER_CTX_add_decoder;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_add_decoder_removed)}
    if OSSL_DECODER_CTX_add_decoder_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_CTX_add_decoder)}
      OSSL_DECODER_CTX_add_decoder := _OSSL_DECODER_CTX_add_decoder;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_CTX_add_decoder_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_CTX_add_decoder');
    {$ifend}
  end;
  
  OSSL_DECODER_CTX_add_extra := LoadLibFunction(ADllHandle, OSSL_DECODER_CTX_add_extra_procname);
  FuncLoadError := not assigned(OSSL_DECODER_CTX_add_extra);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_CTX_add_extra_allownil)}
    OSSL_DECODER_CTX_add_extra := ERR_OSSL_DECODER_CTX_add_extra;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_add_extra_introduced)}
    if LibVersion < OSSL_DECODER_CTX_add_extra_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_CTX_add_extra)}
      OSSL_DECODER_CTX_add_extra := FC_OSSL_DECODER_CTX_add_extra;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_add_extra_removed)}
    if OSSL_DECODER_CTX_add_extra_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_CTX_add_extra)}
      OSSL_DECODER_CTX_add_extra := _OSSL_DECODER_CTX_add_extra;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_CTX_add_extra_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_CTX_add_extra');
    {$ifend}
  end;
  
  OSSL_DECODER_CTX_get_num_decoders := LoadLibFunction(ADllHandle, OSSL_DECODER_CTX_get_num_decoders_procname);
  FuncLoadError := not assigned(OSSL_DECODER_CTX_get_num_decoders);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_CTX_get_num_decoders_allownil)}
    OSSL_DECODER_CTX_get_num_decoders := ERR_OSSL_DECODER_CTX_get_num_decoders;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_get_num_decoders_introduced)}
    if LibVersion < OSSL_DECODER_CTX_get_num_decoders_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_CTX_get_num_decoders)}
      OSSL_DECODER_CTX_get_num_decoders := FC_OSSL_DECODER_CTX_get_num_decoders;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_get_num_decoders_removed)}
    if OSSL_DECODER_CTX_get_num_decoders_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_CTX_get_num_decoders)}
      OSSL_DECODER_CTX_get_num_decoders := _OSSL_DECODER_CTX_get_num_decoders;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_CTX_get_num_decoders_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_CTX_get_num_decoders');
    {$ifend}
  end;
  
  OSSL_DECODER_INSTANCE_get_decoder := LoadLibFunction(ADllHandle, OSSL_DECODER_INSTANCE_get_decoder_procname);
  FuncLoadError := not assigned(OSSL_DECODER_INSTANCE_get_decoder);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_INSTANCE_get_decoder_allownil)}
    OSSL_DECODER_INSTANCE_get_decoder := ERR_OSSL_DECODER_INSTANCE_get_decoder;
    {$ifend}
    {$if declared(OSSL_DECODER_INSTANCE_get_decoder_introduced)}
    if LibVersion < OSSL_DECODER_INSTANCE_get_decoder_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_INSTANCE_get_decoder)}
      OSSL_DECODER_INSTANCE_get_decoder := FC_OSSL_DECODER_INSTANCE_get_decoder;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_INSTANCE_get_decoder_removed)}
    if OSSL_DECODER_INSTANCE_get_decoder_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_INSTANCE_get_decoder)}
      OSSL_DECODER_INSTANCE_get_decoder := _OSSL_DECODER_INSTANCE_get_decoder;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_INSTANCE_get_decoder_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_INSTANCE_get_decoder');
    {$ifend}
  end;
  
  OSSL_DECODER_INSTANCE_get_decoder_ctx := LoadLibFunction(ADllHandle, OSSL_DECODER_INSTANCE_get_decoder_ctx_procname);
  FuncLoadError := not assigned(OSSL_DECODER_INSTANCE_get_decoder_ctx);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_INSTANCE_get_decoder_ctx_allownil)}
    OSSL_DECODER_INSTANCE_get_decoder_ctx := ERR_OSSL_DECODER_INSTANCE_get_decoder_ctx;
    {$ifend}
    {$if declared(OSSL_DECODER_INSTANCE_get_decoder_ctx_introduced)}
    if LibVersion < OSSL_DECODER_INSTANCE_get_decoder_ctx_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_INSTANCE_get_decoder_ctx)}
      OSSL_DECODER_INSTANCE_get_decoder_ctx := FC_OSSL_DECODER_INSTANCE_get_decoder_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_INSTANCE_get_decoder_ctx_removed)}
    if OSSL_DECODER_INSTANCE_get_decoder_ctx_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_INSTANCE_get_decoder_ctx)}
      OSSL_DECODER_INSTANCE_get_decoder_ctx := _OSSL_DECODER_INSTANCE_get_decoder_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_INSTANCE_get_decoder_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_INSTANCE_get_decoder_ctx');
    {$ifend}
  end;
  
  OSSL_DECODER_INSTANCE_get_input_type := LoadLibFunction(ADllHandle, OSSL_DECODER_INSTANCE_get_input_type_procname);
  FuncLoadError := not assigned(OSSL_DECODER_INSTANCE_get_input_type);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_INSTANCE_get_input_type_allownil)}
    OSSL_DECODER_INSTANCE_get_input_type := ERR_OSSL_DECODER_INSTANCE_get_input_type;
    {$ifend}
    {$if declared(OSSL_DECODER_INSTANCE_get_input_type_introduced)}
    if LibVersion < OSSL_DECODER_INSTANCE_get_input_type_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_INSTANCE_get_input_type)}
      OSSL_DECODER_INSTANCE_get_input_type := FC_OSSL_DECODER_INSTANCE_get_input_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_INSTANCE_get_input_type_removed)}
    if OSSL_DECODER_INSTANCE_get_input_type_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_INSTANCE_get_input_type)}
      OSSL_DECODER_INSTANCE_get_input_type := _OSSL_DECODER_INSTANCE_get_input_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_INSTANCE_get_input_type_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_INSTANCE_get_input_type');
    {$ifend}
  end;
  
  OSSL_DECODER_INSTANCE_get_input_structure := LoadLibFunction(ADllHandle, OSSL_DECODER_INSTANCE_get_input_structure_procname);
  FuncLoadError := not assigned(OSSL_DECODER_INSTANCE_get_input_structure);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_INSTANCE_get_input_structure_allownil)}
    OSSL_DECODER_INSTANCE_get_input_structure := ERR_OSSL_DECODER_INSTANCE_get_input_structure;
    {$ifend}
    {$if declared(OSSL_DECODER_INSTANCE_get_input_structure_introduced)}
    if LibVersion < OSSL_DECODER_INSTANCE_get_input_structure_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_INSTANCE_get_input_structure)}
      OSSL_DECODER_INSTANCE_get_input_structure := FC_OSSL_DECODER_INSTANCE_get_input_structure;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_INSTANCE_get_input_structure_removed)}
    if OSSL_DECODER_INSTANCE_get_input_structure_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_INSTANCE_get_input_structure)}
      OSSL_DECODER_INSTANCE_get_input_structure := _OSSL_DECODER_INSTANCE_get_input_structure;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_INSTANCE_get_input_structure_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_INSTANCE_get_input_structure');
    {$ifend}
  end;
  
  OSSL_DECODER_CTX_set_construct := LoadLibFunction(ADllHandle, OSSL_DECODER_CTX_set_construct_procname);
  FuncLoadError := not assigned(OSSL_DECODER_CTX_set_construct);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_CTX_set_construct_allownil)}
    OSSL_DECODER_CTX_set_construct := ERR_OSSL_DECODER_CTX_set_construct;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_set_construct_introduced)}
    if LibVersion < OSSL_DECODER_CTX_set_construct_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_CTX_set_construct)}
      OSSL_DECODER_CTX_set_construct := FC_OSSL_DECODER_CTX_set_construct;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_set_construct_removed)}
    if OSSL_DECODER_CTX_set_construct_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_CTX_set_construct)}
      OSSL_DECODER_CTX_set_construct := _OSSL_DECODER_CTX_set_construct;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_CTX_set_construct_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_CTX_set_construct');
    {$ifend}
  end;
  
  OSSL_DECODER_CTX_set_construct_data := LoadLibFunction(ADllHandle, OSSL_DECODER_CTX_set_construct_data_procname);
  FuncLoadError := not assigned(OSSL_DECODER_CTX_set_construct_data);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_CTX_set_construct_data_allownil)}
    OSSL_DECODER_CTX_set_construct_data := ERR_OSSL_DECODER_CTX_set_construct_data;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_set_construct_data_introduced)}
    if LibVersion < OSSL_DECODER_CTX_set_construct_data_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_CTX_set_construct_data)}
      OSSL_DECODER_CTX_set_construct_data := FC_OSSL_DECODER_CTX_set_construct_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_set_construct_data_removed)}
    if OSSL_DECODER_CTX_set_construct_data_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_CTX_set_construct_data)}
      OSSL_DECODER_CTX_set_construct_data := _OSSL_DECODER_CTX_set_construct_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_CTX_set_construct_data_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_CTX_set_construct_data');
    {$ifend}
  end;
  
  OSSL_DECODER_CTX_set_cleanup := LoadLibFunction(ADllHandle, OSSL_DECODER_CTX_set_cleanup_procname);
  FuncLoadError := not assigned(OSSL_DECODER_CTX_set_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_CTX_set_cleanup_allownil)}
    OSSL_DECODER_CTX_set_cleanup := ERR_OSSL_DECODER_CTX_set_cleanup;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_set_cleanup_introduced)}
    if LibVersion < OSSL_DECODER_CTX_set_cleanup_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_CTX_set_cleanup)}
      OSSL_DECODER_CTX_set_cleanup := FC_OSSL_DECODER_CTX_set_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_set_cleanup_removed)}
    if OSSL_DECODER_CTX_set_cleanup_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_CTX_set_cleanup)}
      OSSL_DECODER_CTX_set_cleanup := _OSSL_DECODER_CTX_set_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_CTX_set_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_CTX_set_cleanup');
    {$ifend}
  end;
  
  OSSL_DECODER_CTX_get_construct := LoadLibFunction(ADllHandle, OSSL_DECODER_CTX_get_construct_procname);
  FuncLoadError := not assigned(OSSL_DECODER_CTX_get_construct);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_CTX_get_construct_allownil)}
    OSSL_DECODER_CTX_get_construct := ERR_OSSL_DECODER_CTX_get_construct;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_get_construct_introduced)}
    if LibVersion < OSSL_DECODER_CTX_get_construct_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_CTX_get_construct)}
      OSSL_DECODER_CTX_get_construct := FC_OSSL_DECODER_CTX_get_construct;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_get_construct_removed)}
    if OSSL_DECODER_CTX_get_construct_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_CTX_get_construct)}
      OSSL_DECODER_CTX_get_construct := _OSSL_DECODER_CTX_get_construct;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_CTX_get_construct_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_CTX_get_construct');
    {$ifend}
  end;
  
  OSSL_DECODER_CTX_get_construct_data := LoadLibFunction(ADllHandle, OSSL_DECODER_CTX_get_construct_data_procname);
  FuncLoadError := not assigned(OSSL_DECODER_CTX_get_construct_data);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_CTX_get_construct_data_allownil)}
    OSSL_DECODER_CTX_get_construct_data := ERR_OSSL_DECODER_CTX_get_construct_data;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_get_construct_data_introduced)}
    if LibVersion < OSSL_DECODER_CTX_get_construct_data_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_CTX_get_construct_data)}
      OSSL_DECODER_CTX_get_construct_data := FC_OSSL_DECODER_CTX_get_construct_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_get_construct_data_removed)}
    if OSSL_DECODER_CTX_get_construct_data_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_CTX_get_construct_data)}
      OSSL_DECODER_CTX_get_construct_data := _OSSL_DECODER_CTX_get_construct_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_CTX_get_construct_data_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_CTX_get_construct_data');
    {$ifend}
  end;
  
  OSSL_DECODER_CTX_get_cleanup := LoadLibFunction(ADllHandle, OSSL_DECODER_CTX_get_cleanup_procname);
  FuncLoadError := not assigned(OSSL_DECODER_CTX_get_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_CTX_get_cleanup_allownil)}
    OSSL_DECODER_CTX_get_cleanup := ERR_OSSL_DECODER_CTX_get_cleanup;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_get_cleanup_introduced)}
    if LibVersion < OSSL_DECODER_CTX_get_cleanup_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_CTX_get_cleanup)}
      OSSL_DECODER_CTX_get_cleanup := FC_OSSL_DECODER_CTX_get_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_get_cleanup_removed)}
    if OSSL_DECODER_CTX_get_cleanup_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_CTX_get_cleanup)}
      OSSL_DECODER_CTX_get_cleanup := _OSSL_DECODER_CTX_get_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_CTX_get_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_CTX_get_cleanup');
    {$ifend}
  end;
  
  OSSL_DECODER_export := LoadLibFunction(ADllHandle, OSSL_DECODER_export_procname);
  FuncLoadError := not assigned(OSSL_DECODER_export);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_export_allownil)}
    OSSL_DECODER_export := ERR_OSSL_DECODER_export;
    {$ifend}
    {$if declared(OSSL_DECODER_export_introduced)}
    if LibVersion < OSSL_DECODER_export_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_export)}
      OSSL_DECODER_export := FC_OSSL_DECODER_export;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_export_removed)}
    if OSSL_DECODER_export_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_export)}
      OSSL_DECODER_export := _OSSL_DECODER_export;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_export_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_export');
    {$ifend}
  end;
  
  OSSL_DECODER_from_bio := LoadLibFunction(ADllHandle, OSSL_DECODER_from_bio_procname);
  FuncLoadError := not assigned(OSSL_DECODER_from_bio);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_from_bio_allownil)}
    OSSL_DECODER_from_bio := ERR_OSSL_DECODER_from_bio;
    {$ifend}
    {$if declared(OSSL_DECODER_from_bio_introduced)}
    if LibVersion < OSSL_DECODER_from_bio_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_from_bio)}
      OSSL_DECODER_from_bio := FC_OSSL_DECODER_from_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_from_bio_removed)}
    if OSSL_DECODER_from_bio_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_from_bio)}
      OSSL_DECODER_from_bio := _OSSL_DECODER_from_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_from_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_from_bio');
    {$ifend}
  end;
  
  OSSL_DECODER_from_fp := LoadLibFunction(ADllHandle, OSSL_DECODER_from_fp_procname);
  FuncLoadError := not assigned(OSSL_DECODER_from_fp);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_from_fp_allownil)}
    OSSL_DECODER_from_fp := ERR_OSSL_DECODER_from_fp;
    {$ifend}
    {$if declared(OSSL_DECODER_from_fp_introduced)}
    if LibVersion < OSSL_DECODER_from_fp_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_from_fp)}
      OSSL_DECODER_from_fp := FC_OSSL_DECODER_from_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_from_fp_removed)}
    if OSSL_DECODER_from_fp_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_from_fp)}
      OSSL_DECODER_from_fp := _OSSL_DECODER_from_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_from_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_from_fp');
    {$ifend}
  end;
  
  OSSL_DECODER_from_data := LoadLibFunction(ADllHandle, OSSL_DECODER_from_data_procname);
  FuncLoadError := not assigned(OSSL_DECODER_from_data);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_from_data_allownil)}
    OSSL_DECODER_from_data := ERR_OSSL_DECODER_from_data;
    {$ifend}
    {$if declared(OSSL_DECODER_from_data_introduced)}
    if LibVersion < OSSL_DECODER_from_data_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_from_data)}
      OSSL_DECODER_from_data := FC_OSSL_DECODER_from_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_from_data_removed)}
    if OSSL_DECODER_from_data_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_from_data)}
      OSSL_DECODER_from_data := _OSSL_DECODER_from_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_from_data_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_from_data');
    {$ifend}
  end;
  
  OSSL_DECODER_CTX_new_for_pkey := LoadLibFunction(ADllHandle, OSSL_DECODER_CTX_new_for_pkey_procname);
  FuncLoadError := not assigned(OSSL_DECODER_CTX_new_for_pkey);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_DECODER_CTX_new_for_pkey_allownil)}
    OSSL_DECODER_CTX_new_for_pkey := ERR_OSSL_DECODER_CTX_new_for_pkey;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_new_for_pkey_introduced)}
    if LibVersion < OSSL_DECODER_CTX_new_for_pkey_introduced then
    begin
      {$if declared(FC_OSSL_DECODER_CTX_new_for_pkey)}
      OSSL_DECODER_CTX_new_for_pkey := FC_OSSL_DECODER_CTX_new_for_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_DECODER_CTX_new_for_pkey_removed)}
    if OSSL_DECODER_CTX_new_for_pkey_removed <= LibVersion then
    begin
      {$if declared(_OSSL_DECODER_CTX_new_for_pkey)}
      OSSL_DECODER_CTX_new_for_pkey := _OSSL_DECODER_CTX_new_for_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_DECODER_CTX_new_for_pkey_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_DECODER_CTX_new_for_pkey');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  OSSL_DECODER_fetch := nil;
  OSSL_DECODER_up_ref := nil;
  OSSL_DECODER_free := nil;
  OSSL_DECODER_get0_provider := nil;
  OSSL_DECODER_get0_properties := nil;
  OSSL_DECODER_get0_name := nil;
  OSSL_DECODER_get0_description := nil;
  OSSL_DECODER_is_a := nil;
  OSSL_DECODER_do_all_provided := nil;
  OSSL_DECODER_names_do_all := nil;
  OSSL_DECODER_gettable_params := nil;
  OSSL_DECODER_get_params := nil;
  OSSL_DECODER_settable_ctx_params := nil;
  OSSL_DECODER_CTX_new := nil;
  OSSL_DECODER_CTX_set_params := nil;
  OSSL_DECODER_CTX_free := nil;
  OSSL_DECODER_CTX_set_passphrase := nil;
  OSSL_DECODER_CTX_set_pem_password_cb := nil;
  OSSL_DECODER_CTX_set_passphrase_cb := nil;
  OSSL_DECODER_CTX_set_passphrase_ui := nil;
  OSSL_DECODER_CTX_set_selection := nil;
  OSSL_DECODER_CTX_set_input_type := nil;
  OSSL_DECODER_CTX_set_input_structure := nil;
  OSSL_DECODER_CTX_add_decoder := nil;
  OSSL_DECODER_CTX_add_extra := nil;
  OSSL_DECODER_CTX_get_num_decoders := nil;
  OSSL_DECODER_INSTANCE_get_decoder := nil;
  OSSL_DECODER_INSTANCE_get_decoder_ctx := nil;
  OSSL_DECODER_INSTANCE_get_input_type := nil;
  OSSL_DECODER_INSTANCE_get_input_structure := nil;
  OSSL_DECODER_CTX_set_construct := nil;
  OSSL_DECODER_CTX_set_construct_data := nil;
  OSSL_DECODER_CTX_set_cleanup := nil;
  OSSL_DECODER_CTX_get_construct := nil;
  OSSL_DECODER_CTX_get_construct_data := nil;
  OSSL_DECODER_CTX_get_cleanup := nil;
  OSSL_DECODER_export := nil;
  OSSL_DECODER_from_bio := nil;
  OSSL_DECODER_from_fp := nil;
  OSSL_DECODER_from_data := nil;
  OSSL_DECODER_CTX_new_for_pkey := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.