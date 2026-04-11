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

unit TaurusTLSHeaders_encoder;

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
// TYPE DECLARATIONS
// =============================================================================
type
  Possl_encoder_instance_st = ^Tossl_encoder_instance_st;
  Tossl_encoder_instance_st =   record end;
  {$EXTERNALSYM Possl_encoder_instance_st}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // OSSL_ENCODER_do_all_provided_fn_cb = procedure(encoder: POSSL_ENCODER; arg: Pointer); cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // OSSL_ENCODER_names_do_all_fn_cb = procedure(name: PIdAnsiChar; data: Pointer); cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // OSSL_ENCODER_CTX_set_pem_password_cb_cb_cb = function(arg1: PIdAnsiChar; arg2: TIdC_INT; arg3: TIdC_INT; arg4: Pointer): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // OSSL_ENCODER_CTX_set_passphrase_cb_cb_cb = function(arg1: PIdAnsiChar; arg2: TIdC_ULONG; arg3: PIdC_ULONG; arg4: Possl_param_st; arg5: Pointer): TIdC_INT; cdecl;
  TOSSL_ENCODER_CONSTRUCT = function(encoder_inst: POSSL_ENCODER_INSTANCE; construct_data: Pointer): Pointer; cdecl;
  TOSSL_ENCODER_CLEANUP = procedure(construct_data: Pointer); cdecl;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  OSSL_ENCODER_fetch: function(libctx: POSSL_LIB_CTX; name: PIdAnsiChar; properties: PIdAnsiChar): POSSL_ENCODER; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_fetch}

  OSSL_ENCODER_up_ref: function(encoder: POSSL_ENCODER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_up_ref}

  OSSL_ENCODER_free: procedure(encoder: POSSL_ENCODER); cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_free}

  OSSL_ENCODER_get0_provider: function(encoder: POSSL_ENCODER): POSSL_PROVIDER; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_get0_provider}

  OSSL_ENCODER_get0_properties: function(encoder: POSSL_ENCODER): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_get0_properties}

  OSSL_ENCODER_get0_name: function(kdf: POSSL_ENCODER): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_get0_name}

  OSSL_ENCODER_get0_description: function(kdf: POSSL_ENCODER): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_get0_description}

  OSSL_ENCODER_is_a: function(encoder: POSSL_ENCODER; name: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_is_a}

  OSSL_ENCODER_do_all_provided: procedure(libctx: POSSL_LIB_CTX; fn: TOSSL_ENCODER_do_all_provided_fn_cb; arg: Pointer); cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_do_all_provided}

  OSSL_ENCODER_names_do_all: function(encoder: POSSL_ENCODER; fn: TOSSL_ENCODER_names_do_all_fn_cb; data: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_names_do_all}

  OSSL_ENCODER_gettable_params: function(encoder: POSSL_ENCODER): POSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_gettable_params}

  OSSL_ENCODER_get_params: function(encoder: POSSL_ENCODER; params: POSSL_PARAM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_get_params}

  OSSL_ENCODER_settable_ctx_params: function(encoder: POSSL_ENCODER): POSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_settable_ctx_params}

  OSSL_ENCODER_CTX_new: function: POSSL_ENCODER_CTX; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_new}

  OSSL_ENCODER_CTX_set_params: function(ctx: POSSL_ENCODER_CTX; params: POSSL_PARAM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_params}

  OSSL_ENCODER_CTX_free: procedure(ctx: POSSL_ENCODER_CTX); cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_free}

  OSSL_ENCODER_CTX_set_passphrase: function(ctx: POSSL_ENCODER_CTX; kstr: PIdAnsiChar; klen: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_passphrase}

  OSSL_ENCODER_CTX_set_pem_password_cb: function(ctx: POSSL_ENCODER_CTX; cb: TOSSL_ENCODER_CTX_set_pem_password_cb_cb_cb; cbarg: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_pem_password_cb}

  OSSL_ENCODER_CTX_set_passphrase_cb: function(ctx: POSSL_ENCODER_CTX; cb: TOSSL_ENCODER_CTX_set_passphrase_cb_cb_cb; cbarg: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_passphrase_cb}

  OSSL_ENCODER_CTX_set_passphrase_ui: function(ctx: POSSL_ENCODER_CTX; ui_method: PUI_METHOD; ui_data: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_passphrase_ui}

  OSSL_ENCODER_CTX_set_cipher: function(ctx: POSSL_ENCODER_CTX; cipher_name: PIdAnsiChar; propquery: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_cipher}

  OSSL_ENCODER_CTX_set_selection: function(ctx: POSSL_ENCODER_CTX; selection: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_selection}

  OSSL_ENCODER_CTX_set_output_type: function(ctx: POSSL_ENCODER_CTX; output_type: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_output_type}

  OSSL_ENCODER_CTX_set_output_structure: function(ctx: POSSL_ENCODER_CTX; output_structure: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_output_structure}

  OSSL_ENCODER_CTX_add_encoder: function(ctx: POSSL_ENCODER_CTX; encoder: POSSL_ENCODER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_add_encoder}

  OSSL_ENCODER_CTX_add_extra: function(ctx: POSSL_ENCODER_CTX; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_add_extra}

  OSSL_ENCODER_CTX_get_num_encoders: function(ctx: POSSL_ENCODER_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_get_num_encoders}

  OSSL_ENCODER_INSTANCE_get_encoder: function(encoder_inst: POSSL_ENCODER_INSTANCE): POSSL_ENCODER; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_INSTANCE_get_encoder}

  OSSL_ENCODER_INSTANCE_get_encoder_ctx: function(encoder_inst: POSSL_ENCODER_INSTANCE): Pointer; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_INSTANCE_get_encoder_ctx}

  OSSL_ENCODER_INSTANCE_get_output_type: function(encoder_inst: POSSL_ENCODER_INSTANCE): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_INSTANCE_get_output_type}

  OSSL_ENCODER_INSTANCE_get_output_structure: function(encoder_inst: POSSL_ENCODER_INSTANCE): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_INSTANCE_get_output_structure}

  OSSL_ENCODER_CTX_set_construct: function(ctx: POSSL_ENCODER_CTX; construct: TOSSL_ENCODER_CONSTRUCT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_construct}

  OSSL_ENCODER_CTX_set_construct_data: function(ctx: POSSL_ENCODER_CTX; construct_data: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_construct_data}

  OSSL_ENCODER_CTX_set_cleanup: function(ctx: POSSL_ENCODER_CTX; cleanup: TOSSL_ENCODER_CLEANUP): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_cleanup}

  OSSL_ENCODER_to_bio: function(ctx: POSSL_ENCODER_CTX; _out: PBIO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_to_bio}

  OSSL_ENCODER_to_fp: function(ctx: POSSL_ENCODER_CTX; fp: PFILE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_to_fp}

  OSSL_ENCODER_to_data: function(ctx: POSSL_ENCODER_CTX; pdata: PPIdAnsiChar; pdata_len: PIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_to_data}

  OSSL_ENCODER_CTX_new_for_pkey: function(pkey: PEVP_PKEY; selection: TIdC_INT; output_type: PIdAnsiChar; output_struct: PIdAnsiChar; propquery: PIdAnsiChar): POSSL_ENCODER_CTX; cdecl = nil;
  {$EXTERNALSYM OSSL_ENCODER_CTX_new_for_pkey}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function OSSL_ENCODER_fetch(libctx: POSSL_LIB_CTX; name: PIdAnsiChar; properties: PIdAnsiChar): POSSL_ENCODER; cdecl;
function OSSL_ENCODER_up_ref(encoder: POSSL_ENCODER): TIdC_INT; cdecl;
procedure OSSL_ENCODER_free(encoder: POSSL_ENCODER); cdecl;
function OSSL_ENCODER_get0_provider(encoder: POSSL_ENCODER): POSSL_PROVIDER; cdecl;
function OSSL_ENCODER_get0_properties(encoder: POSSL_ENCODER): PIdAnsiChar; cdecl;
function OSSL_ENCODER_get0_name(kdf: POSSL_ENCODER): PIdAnsiChar; cdecl;
function OSSL_ENCODER_get0_description(kdf: POSSL_ENCODER): PIdAnsiChar; cdecl;
function OSSL_ENCODER_is_a(encoder: POSSL_ENCODER; name: PIdAnsiChar): TIdC_INT; cdecl;
procedure OSSL_ENCODER_do_all_provided(libctx: POSSL_LIB_CTX; fn: TOSSL_ENCODER_do_all_provided_fn_cb; arg: Pointer); cdecl;
function OSSL_ENCODER_names_do_all(encoder: POSSL_ENCODER; fn: TOSSL_ENCODER_names_do_all_fn_cb; data: Pointer): TIdC_INT; cdecl;
function OSSL_ENCODER_gettable_params(encoder: POSSL_ENCODER): POSSL_PARAM; cdecl;
function OSSL_ENCODER_get_params(encoder: POSSL_ENCODER; params: POSSL_PARAM): TIdC_INT; cdecl;
function OSSL_ENCODER_settable_ctx_params(encoder: POSSL_ENCODER): POSSL_PARAM; cdecl;
function OSSL_ENCODER_CTX_new: POSSL_ENCODER_CTX; cdecl;
function OSSL_ENCODER_CTX_set_params(ctx: POSSL_ENCODER_CTX; params: POSSL_PARAM): TIdC_INT; cdecl;
procedure OSSL_ENCODER_CTX_free(ctx: POSSL_ENCODER_CTX); cdecl;
function OSSL_ENCODER_CTX_set_passphrase(ctx: POSSL_ENCODER_CTX; kstr: PIdAnsiChar; klen: TIdC_SIZET): TIdC_INT; cdecl;
function OSSL_ENCODER_CTX_set_pem_password_cb(ctx: POSSL_ENCODER_CTX; cb: TOSSL_ENCODER_CTX_set_pem_password_cb_cb_cb; cbarg: Pointer): TIdC_INT; cdecl;
function OSSL_ENCODER_CTX_set_passphrase_cb(ctx: POSSL_ENCODER_CTX; cb: TOSSL_ENCODER_CTX_set_passphrase_cb_cb_cb; cbarg: Pointer): TIdC_INT; cdecl;
function OSSL_ENCODER_CTX_set_passphrase_ui(ctx: POSSL_ENCODER_CTX; ui_method: PUI_METHOD; ui_data: Pointer): TIdC_INT; cdecl;
function OSSL_ENCODER_CTX_set_cipher(ctx: POSSL_ENCODER_CTX; cipher_name: PIdAnsiChar; propquery: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_ENCODER_CTX_set_selection(ctx: POSSL_ENCODER_CTX; selection: TIdC_INT): TIdC_INT; cdecl;
function OSSL_ENCODER_CTX_set_output_type(ctx: POSSL_ENCODER_CTX; output_type: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_ENCODER_CTX_set_output_structure(ctx: POSSL_ENCODER_CTX; output_structure: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_ENCODER_CTX_add_encoder(ctx: POSSL_ENCODER_CTX; encoder: POSSL_ENCODER): TIdC_INT; cdecl;
function OSSL_ENCODER_CTX_add_extra(ctx: POSSL_ENCODER_CTX; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_ENCODER_CTX_get_num_encoders(ctx: POSSL_ENCODER_CTX): TIdC_INT; cdecl;
function OSSL_ENCODER_INSTANCE_get_encoder(encoder_inst: POSSL_ENCODER_INSTANCE): POSSL_ENCODER; cdecl;
function OSSL_ENCODER_INSTANCE_get_encoder_ctx(encoder_inst: POSSL_ENCODER_INSTANCE): Pointer; cdecl;
function OSSL_ENCODER_INSTANCE_get_output_type(encoder_inst: POSSL_ENCODER_INSTANCE): PIdAnsiChar; cdecl;
function OSSL_ENCODER_INSTANCE_get_output_structure(encoder_inst: POSSL_ENCODER_INSTANCE): PIdAnsiChar; cdecl;
function OSSL_ENCODER_CTX_set_construct(ctx: POSSL_ENCODER_CTX; construct: TOSSL_ENCODER_CONSTRUCT): TIdC_INT; cdecl;
function OSSL_ENCODER_CTX_set_construct_data(ctx: POSSL_ENCODER_CTX; construct_data: Pointer): TIdC_INT; cdecl;
function OSSL_ENCODER_CTX_set_cleanup(ctx: POSSL_ENCODER_CTX; cleanup: TOSSL_ENCODER_CLEANUP): TIdC_INT; cdecl;
function OSSL_ENCODER_to_bio(ctx: POSSL_ENCODER_CTX; _out: PBIO): TIdC_INT; cdecl;
function OSSL_ENCODER_to_fp(ctx: POSSL_ENCODER_CTX; fp: PFILE): TIdC_INT; cdecl;
function OSSL_ENCODER_to_data(ctx: POSSL_ENCODER_CTX; pdata: PPIdAnsiChar; pdata_len: PIdC_SIZET): TIdC_INT; cdecl;
function OSSL_ENCODER_CTX_new_for_pkey(pkey: PEVP_PKEY; selection: TIdC_INT; output_type: PIdAnsiChar; output_struct: PIdAnsiChar; propquery: PIdAnsiChar): POSSL_ENCODER_CTX; cdecl;
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

function OSSL_ENCODER_fetch(libctx: POSSL_LIB_CTX; name: PIdAnsiChar; properties: PIdAnsiChar): POSSL_ENCODER; cdecl external CLibCrypto name 'OSSL_ENCODER_fetch';
function OSSL_ENCODER_up_ref(encoder: POSSL_ENCODER): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ENCODER_up_ref';
procedure OSSL_ENCODER_free(encoder: POSSL_ENCODER); cdecl external CLibCrypto name 'OSSL_ENCODER_free';
function OSSL_ENCODER_get0_provider(encoder: POSSL_ENCODER): POSSL_PROVIDER; cdecl external CLibCrypto name 'OSSL_ENCODER_get0_provider';
function OSSL_ENCODER_get0_properties(encoder: POSSL_ENCODER): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_ENCODER_get0_properties';
function OSSL_ENCODER_get0_name(kdf: POSSL_ENCODER): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_ENCODER_get0_name';
function OSSL_ENCODER_get0_description(kdf: POSSL_ENCODER): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_ENCODER_get0_description';
function OSSL_ENCODER_is_a(encoder: POSSL_ENCODER; name: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ENCODER_is_a';
procedure OSSL_ENCODER_do_all_provided(libctx: POSSL_LIB_CTX; fn: TOSSL_ENCODER_do_all_provided_fn_cb; arg: Pointer); cdecl external CLibCrypto name 'OSSL_ENCODER_do_all_provided';
function OSSL_ENCODER_names_do_all(encoder: POSSL_ENCODER; fn: TOSSL_ENCODER_names_do_all_fn_cb; data: Pointer): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ENCODER_names_do_all';
function OSSL_ENCODER_gettable_params(encoder: POSSL_ENCODER): POSSL_PARAM; cdecl external CLibCrypto name 'OSSL_ENCODER_gettable_params';
function OSSL_ENCODER_get_params(encoder: POSSL_ENCODER; params: POSSL_PARAM): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ENCODER_get_params';
function OSSL_ENCODER_settable_ctx_params(encoder: POSSL_ENCODER): POSSL_PARAM; cdecl external CLibCrypto name 'OSSL_ENCODER_settable_ctx_params';
function OSSL_ENCODER_CTX_new: POSSL_ENCODER_CTX; cdecl external CLibCrypto name 'OSSL_ENCODER_CTX_new';
function OSSL_ENCODER_CTX_set_params(ctx: POSSL_ENCODER_CTX; params: POSSL_PARAM): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ENCODER_CTX_set_params';
procedure OSSL_ENCODER_CTX_free(ctx: POSSL_ENCODER_CTX); cdecl external CLibCrypto name 'OSSL_ENCODER_CTX_free';
function OSSL_ENCODER_CTX_set_passphrase(ctx: POSSL_ENCODER_CTX; kstr: PIdAnsiChar; klen: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ENCODER_CTX_set_passphrase';
function OSSL_ENCODER_CTX_set_pem_password_cb(ctx: POSSL_ENCODER_CTX; cb: TOSSL_ENCODER_CTX_set_pem_password_cb_cb_cb; cbarg: Pointer): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ENCODER_CTX_set_pem_password_cb';
function OSSL_ENCODER_CTX_set_passphrase_cb(ctx: POSSL_ENCODER_CTX; cb: TOSSL_ENCODER_CTX_set_passphrase_cb_cb_cb; cbarg: Pointer): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ENCODER_CTX_set_passphrase_cb';
function OSSL_ENCODER_CTX_set_passphrase_ui(ctx: POSSL_ENCODER_CTX; ui_method: PUI_METHOD; ui_data: Pointer): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ENCODER_CTX_set_passphrase_ui';
function OSSL_ENCODER_CTX_set_cipher(ctx: POSSL_ENCODER_CTX; cipher_name: PIdAnsiChar; propquery: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ENCODER_CTX_set_cipher';
function OSSL_ENCODER_CTX_set_selection(ctx: POSSL_ENCODER_CTX; selection: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ENCODER_CTX_set_selection';
function OSSL_ENCODER_CTX_set_output_type(ctx: POSSL_ENCODER_CTX; output_type: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ENCODER_CTX_set_output_type';
function OSSL_ENCODER_CTX_set_output_structure(ctx: POSSL_ENCODER_CTX; output_structure: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ENCODER_CTX_set_output_structure';
function OSSL_ENCODER_CTX_add_encoder(ctx: POSSL_ENCODER_CTX; encoder: POSSL_ENCODER): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ENCODER_CTX_add_encoder';
function OSSL_ENCODER_CTX_add_extra(ctx: POSSL_ENCODER_CTX; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ENCODER_CTX_add_extra';
function OSSL_ENCODER_CTX_get_num_encoders(ctx: POSSL_ENCODER_CTX): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ENCODER_CTX_get_num_encoders';
function OSSL_ENCODER_INSTANCE_get_encoder(encoder_inst: POSSL_ENCODER_INSTANCE): POSSL_ENCODER; cdecl external CLibCrypto name 'OSSL_ENCODER_INSTANCE_get_encoder';
function OSSL_ENCODER_INSTANCE_get_encoder_ctx(encoder_inst: POSSL_ENCODER_INSTANCE): Pointer; cdecl external CLibCrypto name 'OSSL_ENCODER_INSTANCE_get_encoder_ctx';
function OSSL_ENCODER_INSTANCE_get_output_type(encoder_inst: POSSL_ENCODER_INSTANCE): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_ENCODER_INSTANCE_get_output_type';
function OSSL_ENCODER_INSTANCE_get_output_structure(encoder_inst: POSSL_ENCODER_INSTANCE): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_ENCODER_INSTANCE_get_output_structure';
function OSSL_ENCODER_CTX_set_construct(ctx: POSSL_ENCODER_CTX; construct: TOSSL_ENCODER_CONSTRUCT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ENCODER_CTX_set_construct';
function OSSL_ENCODER_CTX_set_construct_data(ctx: POSSL_ENCODER_CTX; construct_data: Pointer): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ENCODER_CTX_set_construct_data';
function OSSL_ENCODER_CTX_set_cleanup(ctx: POSSL_ENCODER_CTX; cleanup: TOSSL_ENCODER_CLEANUP): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ENCODER_CTX_set_cleanup';
function OSSL_ENCODER_to_bio(ctx: POSSL_ENCODER_CTX; _out: PBIO): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ENCODER_to_bio';
function OSSL_ENCODER_to_fp(ctx: POSSL_ENCODER_CTX; fp: PFILE): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ENCODER_to_fp';
function OSSL_ENCODER_to_data(ctx: POSSL_ENCODER_CTX; pdata: PPIdAnsiChar; pdata_len: PIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ENCODER_to_data';
function OSSL_ENCODER_CTX_new_for_pkey(pkey: PEVP_PKEY; selection: TIdC_INT; output_type: PIdAnsiChar; output_struct: PIdAnsiChar; propquery: PIdAnsiChar): POSSL_ENCODER_CTX; cdecl external CLibCrypto name 'OSSL_ENCODER_CTX_new_for_pkey';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  OSSL_ENCODER_fetch_procname = 'OSSL_ENCODER_fetch';
  OSSL_ENCODER_fetch_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_up_ref_procname = 'OSSL_ENCODER_up_ref';
  OSSL_ENCODER_up_ref_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_free_procname = 'OSSL_ENCODER_free';
  OSSL_ENCODER_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_get0_provider_procname = 'OSSL_ENCODER_get0_provider';
  OSSL_ENCODER_get0_provider_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_get0_properties_procname = 'OSSL_ENCODER_get0_properties';
  OSSL_ENCODER_get0_properties_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_get0_name_procname = 'OSSL_ENCODER_get0_name';
  OSSL_ENCODER_get0_name_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_get0_description_procname = 'OSSL_ENCODER_get0_description';
  OSSL_ENCODER_get0_description_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_is_a_procname = 'OSSL_ENCODER_is_a';
  OSSL_ENCODER_is_a_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_do_all_provided_procname = 'OSSL_ENCODER_do_all_provided';
  OSSL_ENCODER_do_all_provided_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_names_do_all_procname = 'OSSL_ENCODER_names_do_all';
  OSSL_ENCODER_names_do_all_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_gettable_params_procname = 'OSSL_ENCODER_gettable_params';
  OSSL_ENCODER_gettable_params_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_get_params_procname = 'OSSL_ENCODER_get_params';
  OSSL_ENCODER_get_params_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_settable_ctx_params_procname = 'OSSL_ENCODER_settable_ctx_params';
  OSSL_ENCODER_settable_ctx_params_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_CTX_new_procname = 'OSSL_ENCODER_CTX_new';
  OSSL_ENCODER_CTX_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_CTX_set_params_procname = 'OSSL_ENCODER_CTX_set_params';
  OSSL_ENCODER_CTX_set_params_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_CTX_free_procname = 'OSSL_ENCODER_CTX_free';
  OSSL_ENCODER_CTX_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_CTX_set_passphrase_procname = 'OSSL_ENCODER_CTX_set_passphrase';
  OSSL_ENCODER_CTX_set_passphrase_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_CTX_set_pem_password_cb_procname = 'OSSL_ENCODER_CTX_set_pem_password_cb';
  OSSL_ENCODER_CTX_set_pem_password_cb_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_CTX_set_passphrase_cb_procname = 'OSSL_ENCODER_CTX_set_passphrase_cb';
  OSSL_ENCODER_CTX_set_passphrase_cb_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_CTX_set_passphrase_ui_procname = 'OSSL_ENCODER_CTX_set_passphrase_ui';
  OSSL_ENCODER_CTX_set_passphrase_ui_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_CTX_set_cipher_procname = 'OSSL_ENCODER_CTX_set_cipher';
  OSSL_ENCODER_CTX_set_cipher_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_CTX_set_selection_procname = 'OSSL_ENCODER_CTX_set_selection';
  OSSL_ENCODER_CTX_set_selection_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_CTX_set_output_type_procname = 'OSSL_ENCODER_CTX_set_output_type';
  OSSL_ENCODER_CTX_set_output_type_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_CTX_set_output_structure_procname = 'OSSL_ENCODER_CTX_set_output_structure';
  OSSL_ENCODER_CTX_set_output_structure_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_CTX_add_encoder_procname = 'OSSL_ENCODER_CTX_add_encoder';
  OSSL_ENCODER_CTX_add_encoder_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_CTX_add_extra_procname = 'OSSL_ENCODER_CTX_add_extra';
  OSSL_ENCODER_CTX_add_extra_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_CTX_get_num_encoders_procname = 'OSSL_ENCODER_CTX_get_num_encoders';
  OSSL_ENCODER_CTX_get_num_encoders_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_INSTANCE_get_encoder_procname = 'OSSL_ENCODER_INSTANCE_get_encoder';
  OSSL_ENCODER_INSTANCE_get_encoder_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_INSTANCE_get_encoder_ctx_procname = 'OSSL_ENCODER_INSTANCE_get_encoder_ctx';
  OSSL_ENCODER_INSTANCE_get_encoder_ctx_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_INSTANCE_get_output_type_procname = 'OSSL_ENCODER_INSTANCE_get_output_type';
  OSSL_ENCODER_INSTANCE_get_output_type_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_INSTANCE_get_output_structure_procname = 'OSSL_ENCODER_INSTANCE_get_output_structure';
  OSSL_ENCODER_INSTANCE_get_output_structure_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_CTX_set_construct_procname = 'OSSL_ENCODER_CTX_set_construct';
  OSSL_ENCODER_CTX_set_construct_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_CTX_set_construct_data_procname = 'OSSL_ENCODER_CTX_set_construct_data';
  OSSL_ENCODER_CTX_set_construct_data_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_CTX_set_cleanup_procname = 'OSSL_ENCODER_CTX_set_cleanup';
  OSSL_ENCODER_CTX_set_cleanup_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_to_bio_procname = 'OSSL_ENCODER_to_bio';
  OSSL_ENCODER_to_bio_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_to_fp_procname = 'OSSL_ENCODER_to_fp';
  OSSL_ENCODER_to_fp_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_to_data_procname = 'OSSL_ENCODER_to_data';
  OSSL_ENCODER_to_data_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ENCODER_CTX_new_for_pkey_procname = 'OSSL_ENCODER_CTX_new_for_pkey';
  OSSL_ENCODER_CTX_new_for_pkey_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_OSSL_ENCODER_fetch(libctx: POSSL_LIB_CTX; name: PIdAnsiChar; properties: PIdAnsiChar): POSSL_ENCODER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_fetch_procname);
end;

function ERR_OSSL_ENCODER_up_ref(encoder: POSSL_ENCODER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_up_ref_procname);
end;

procedure ERR_OSSL_ENCODER_free(encoder: POSSL_ENCODER); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_free_procname);
end;

function ERR_OSSL_ENCODER_get0_provider(encoder: POSSL_ENCODER): POSSL_PROVIDER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_get0_provider_procname);
end;

function ERR_OSSL_ENCODER_get0_properties(encoder: POSSL_ENCODER): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_get0_properties_procname);
end;

function ERR_OSSL_ENCODER_get0_name(kdf: POSSL_ENCODER): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_get0_name_procname);
end;

function ERR_OSSL_ENCODER_get0_description(kdf: POSSL_ENCODER): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_get0_description_procname);
end;

function ERR_OSSL_ENCODER_is_a(encoder: POSSL_ENCODER; name: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_is_a_procname);
end;

procedure ERR_OSSL_ENCODER_do_all_provided(libctx: POSSL_LIB_CTX; fn: TOSSL_ENCODER_do_all_provided_fn_cb; arg: Pointer); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_do_all_provided_procname);
end;

function ERR_OSSL_ENCODER_names_do_all(encoder: POSSL_ENCODER; fn: TOSSL_ENCODER_names_do_all_fn_cb; data: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_names_do_all_procname);
end;

function ERR_OSSL_ENCODER_gettable_params(encoder: POSSL_ENCODER): POSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_gettable_params_procname);
end;

function ERR_OSSL_ENCODER_get_params(encoder: POSSL_ENCODER; params: POSSL_PARAM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_get_params_procname);
end;

function ERR_OSSL_ENCODER_settable_ctx_params(encoder: POSSL_ENCODER): POSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_settable_ctx_params_procname);
end;

function ERR_OSSL_ENCODER_CTX_new: POSSL_ENCODER_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_CTX_new_procname);
end;

function ERR_OSSL_ENCODER_CTX_set_params(ctx: POSSL_ENCODER_CTX; params: POSSL_PARAM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_CTX_set_params_procname);
end;

procedure ERR_OSSL_ENCODER_CTX_free(ctx: POSSL_ENCODER_CTX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_CTX_free_procname);
end;

function ERR_OSSL_ENCODER_CTX_set_passphrase(ctx: POSSL_ENCODER_CTX; kstr: PIdAnsiChar; klen: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_CTX_set_passphrase_procname);
end;

function ERR_OSSL_ENCODER_CTX_set_pem_password_cb(ctx: POSSL_ENCODER_CTX; cb: TOSSL_ENCODER_CTX_set_pem_password_cb_cb_cb; cbarg: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_CTX_set_pem_password_cb_procname);
end;

function ERR_OSSL_ENCODER_CTX_set_passphrase_cb(ctx: POSSL_ENCODER_CTX; cb: TOSSL_ENCODER_CTX_set_passphrase_cb_cb_cb; cbarg: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_CTX_set_passphrase_cb_procname);
end;

function ERR_OSSL_ENCODER_CTX_set_passphrase_ui(ctx: POSSL_ENCODER_CTX; ui_method: PUI_METHOD; ui_data: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_CTX_set_passphrase_ui_procname);
end;

function ERR_OSSL_ENCODER_CTX_set_cipher(ctx: POSSL_ENCODER_CTX; cipher_name: PIdAnsiChar; propquery: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_CTX_set_cipher_procname);
end;

function ERR_OSSL_ENCODER_CTX_set_selection(ctx: POSSL_ENCODER_CTX; selection: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_CTX_set_selection_procname);
end;

function ERR_OSSL_ENCODER_CTX_set_output_type(ctx: POSSL_ENCODER_CTX; output_type: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_CTX_set_output_type_procname);
end;

function ERR_OSSL_ENCODER_CTX_set_output_structure(ctx: POSSL_ENCODER_CTX; output_structure: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_CTX_set_output_structure_procname);
end;

function ERR_OSSL_ENCODER_CTX_add_encoder(ctx: POSSL_ENCODER_CTX; encoder: POSSL_ENCODER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_CTX_add_encoder_procname);
end;

function ERR_OSSL_ENCODER_CTX_add_extra(ctx: POSSL_ENCODER_CTX; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_CTX_add_extra_procname);
end;

function ERR_OSSL_ENCODER_CTX_get_num_encoders(ctx: POSSL_ENCODER_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_CTX_get_num_encoders_procname);
end;

function ERR_OSSL_ENCODER_INSTANCE_get_encoder(encoder_inst: POSSL_ENCODER_INSTANCE): POSSL_ENCODER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_INSTANCE_get_encoder_procname);
end;

function ERR_OSSL_ENCODER_INSTANCE_get_encoder_ctx(encoder_inst: POSSL_ENCODER_INSTANCE): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_INSTANCE_get_encoder_ctx_procname);
end;

function ERR_OSSL_ENCODER_INSTANCE_get_output_type(encoder_inst: POSSL_ENCODER_INSTANCE): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_INSTANCE_get_output_type_procname);
end;

function ERR_OSSL_ENCODER_INSTANCE_get_output_structure(encoder_inst: POSSL_ENCODER_INSTANCE): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_INSTANCE_get_output_structure_procname);
end;

function ERR_OSSL_ENCODER_CTX_set_construct(ctx: POSSL_ENCODER_CTX; construct: TOSSL_ENCODER_CONSTRUCT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_CTX_set_construct_procname);
end;

function ERR_OSSL_ENCODER_CTX_set_construct_data(ctx: POSSL_ENCODER_CTX; construct_data: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_CTX_set_construct_data_procname);
end;

function ERR_OSSL_ENCODER_CTX_set_cleanup(ctx: POSSL_ENCODER_CTX; cleanup: TOSSL_ENCODER_CLEANUP): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_CTX_set_cleanup_procname);
end;

function ERR_OSSL_ENCODER_to_bio(ctx: POSSL_ENCODER_CTX; _out: PBIO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_to_bio_procname);
end;

function ERR_OSSL_ENCODER_to_fp(ctx: POSSL_ENCODER_CTX; fp: PFILE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_to_fp_procname);
end;

function ERR_OSSL_ENCODER_to_data(ctx: POSSL_ENCODER_CTX; pdata: PPIdAnsiChar; pdata_len: PIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_to_data_procname);
end;

function ERR_OSSL_ENCODER_CTX_new_for_pkey(pkey: PEVP_PKEY; selection: TIdC_INT; output_type: PIdAnsiChar; output_struct: PIdAnsiChar; propquery: PIdAnsiChar): POSSL_ENCODER_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ENCODER_CTX_new_for_pkey_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  OSSL_ENCODER_fetch := LoadLibFunction(ADllHandle, OSSL_ENCODER_fetch_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_fetch);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_fetch_allownil)}
    OSSL_ENCODER_fetch := ERR_OSSL_ENCODER_fetch;
    {$ifend}
    {$if declared(OSSL_ENCODER_fetch_introduced)}
    if LibVersion < OSSL_ENCODER_fetch_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_fetch)}
      OSSL_ENCODER_fetch := FC_OSSL_ENCODER_fetch;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_fetch_removed)}
    if OSSL_ENCODER_fetch_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_fetch)}
      OSSL_ENCODER_fetch := _OSSL_ENCODER_fetch;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_fetch_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_fetch');
    {$ifend}
  end;
  
  OSSL_ENCODER_up_ref := LoadLibFunction(ADllHandle, OSSL_ENCODER_up_ref_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_up_ref);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_up_ref_allownil)}
    OSSL_ENCODER_up_ref := ERR_OSSL_ENCODER_up_ref;
    {$ifend}
    {$if declared(OSSL_ENCODER_up_ref_introduced)}
    if LibVersion < OSSL_ENCODER_up_ref_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_up_ref)}
      OSSL_ENCODER_up_ref := FC_OSSL_ENCODER_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_up_ref_removed)}
    if OSSL_ENCODER_up_ref_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_up_ref)}
      OSSL_ENCODER_up_ref := _OSSL_ENCODER_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_up_ref_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_up_ref');
    {$ifend}
  end;
  
  OSSL_ENCODER_free := LoadLibFunction(ADllHandle, OSSL_ENCODER_free_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_free_allownil)}
    OSSL_ENCODER_free := ERR_OSSL_ENCODER_free;
    {$ifend}
    {$if declared(OSSL_ENCODER_free_introduced)}
    if LibVersion < OSSL_ENCODER_free_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_free)}
      OSSL_ENCODER_free := FC_OSSL_ENCODER_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_free_removed)}
    if OSSL_ENCODER_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_free)}
      OSSL_ENCODER_free := _OSSL_ENCODER_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_free');
    {$ifend}
  end;
  
  OSSL_ENCODER_get0_provider := LoadLibFunction(ADllHandle, OSSL_ENCODER_get0_provider_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_get0_provider);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_get0_provider_allownil)}
    OSSL_ENCODER_get0_provider := ERR_OSSL_ENCODER_get0_provider;
    {$ifend}
    {$if declared(OSSL_ENCODER_get0_provider_introduced)}
    if LibVersion < OSSL_ENCODER_get0_provider_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_get0_provider)}
      OSSL_ENCODER_get0_provider := FC_OSSL_ENCODER_get0_provider;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_get0_provider_removed)}
    if OSSL_ENCODER_get0_provider_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_get0_provider)}
      OSSL_ENCODER_get0_provider := _OSSL_ENCODER_get0_provider;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_get0_provider_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_get0_provider');
    {$ifend}
  end;
  
  OSSL_ENCODER_get0_properties := LoadLibFunction(ADllHandle, OSSL_ENCODER_get0_properties_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_get0_properties);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_get0_properties_allownil)}
    OSSL_ENCODER_get0_properties := ERR_OSSL_ENCODER_get0_properties;
    {$ifend}
    {$if declared(OSSL_ENCODER_get0_properties_introduced)}
    if LibVersion < OSSL_ENCODER_get0_properties_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_get0_properties)}
      OSSL_ENCODER_get0_properties := FC_OSSL_ENCODER_get0_properties;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_get0_properties_removed)}
    if OSSL_ENCODER_get0_properties_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_get0_properties)}
      OSSL_ENCODER_get0_properties := _OSSL_ENCODER_get0_properties;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_get0_properties_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_get0_properties');
    {$ifend}
  end;
  
  OSSL_ENCODER_get0_name := LoadLibFunction(ADllHandle, OSSL_ENCODER_get0_name_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_get0_name);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_get0_name_allownil)}
    OSSL_ENCODER_get0_name := ERR_OSSL_ENCODER_get0_name;
    {$ifend}
    {$if declared(OSSL_ENCODER_get0_name_introduced)}
    if LibVersion < OSSL_ENCODER_get0_name_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_get0_name)}
      OSSL_ENCODER_get0_name := FC_OSSL_ENCODER_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_get0_name_removed)}
    if OSSL_ENCODER_get0_name_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_get0_name)}
      OSSL_ENCODER_get0_name := _OSSL_ENCODER_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_get0_name_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_get0_name');
    {$ifend}
  end;
  
  OSSL_ENCODER_get0_description := LoadLibFunction(ADllHandle, OSSL_ENCODER_get0_description_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_get0_description);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_get0_description_allownil)}
    OSSL_ENCODER_get0_description := ERR_OSSL_ENCODER_get0_description;
    {$ifend}
    {$if declared(OSSL_ENCODER_get0_description_introduced)}
    if LibVersion < OSSL_ENCODER_get0_description_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_get0_description)}
      OSSL_ENCODER_get0_description := FC_OSSL_ENCODER_get0_description;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_get0_description_removed)}
    if OSSL_ENCODER_get0_description_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_get0_description)}
      OSSL_ENCODER_get0_description := _OSSL_ENCODER_get0_description;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_get0_description_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_get0_description');
    {$ifend}
  end;
  
  OSSL_ENCODER_is_a := LoadLibFunction(ADllHandle, OSSL_ENCODER_is_a_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_is_a);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_is_a_allownil)}
    OSSL_ENCODER_is_a := ERR_OSSL_ENCODER_is_a;
    {$ifend}
    {$if declared(OSSL_ENCODER_is_a_introduced)}
    if LibVersion < OSSL_ENCODER_is_a_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_is_a)}
      OSSL_ENCODER_is_a := FC_OSSL_ENCODER_is_a;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_is_a_removed)}
    if OSSL_ENCODER_is_a_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_is_a)}
      OSSL_ENCODER_is_a := _OSSL_ENCODER_is_a;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_is_a_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_is_a');
    {$ifend}
  end;
  
  OSSL_ENCODER_do_all_provided := LoadLibFunction(ADllHandle, OSSL_ENCODER_do_all_provided_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_do_all_provided);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_do_all_provided_allownil)}
    OSSL_ENCODER_do_all_provided := ERR_OSSL_ENCODER_do_all_provided;
    {$ifend}
    {$if declared(OSSL_ENCODER_do_all_provided_introduced)}
    if LibVersion < OSSL_ENCODER_do_all_provided_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_do_all_provided)}
      OSSL_ENCODER_do_all_provided := FC_OSSL_ENCODER_do_all_provided;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_do_all_provided_removed)}
    if OSSL_ENCODER_do_all_provided_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_do_all_provided)}
      OSSL_ENCODER_do_all_provided := _OSSL_ENCODER_do_all_provided;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_do_all_provided_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_do_all_provided');
    {$ifend}
  end;
  
  OSSL_ENCODER_names_do_all := LoadLibFunction(ADllHandle, OSSL_ENCODER_names_do_all_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_names_do_all);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_names_do_all_allownil)}
    OSSL_ENCODER_names_do_all := ERR_OSSL_ENCODER_names_do_all;
    {$ifend}
    {$if declared(OSSL_ENCODER_names_do_all_introduced)}
    if LibVersion < OSSL_ENCODER_names_do_all_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_names_do_all)}
      OSSL_ENCODER_names_do_all := FC_OSSL_ENCODER_names_do_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_names_do_all_removed)}
    if OSSL_ENCODER_names_do_all_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_names_do_all)}
      OSSL_ENCODER_names_do_all := _OSSL_ENCODER_names_do_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_names_do_all_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_names_do_all');
    {$ifend}
  end;
  
  OSSL_ENCODER_gettable_params := LoadLibFunction(ADllHandle, OSSL_ENCODER_gettable_params_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_gettable_params);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_gettable_params_allownil)}
    OSSL_ENCODER_gettable_params := ERR_OSSL_ENCODER_gettable_params;
    {$ifend}
    {$if declared(OSSL_ENCODER_gettable_params_introduced)}
    if LibVersion < OSSL_ENCODER_gettable_params_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_gettable_params)}
      OSSL_ENCODER_gettable_params := FC_OSSL_ENCODER_gettable_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_gettable_params_removed)}
    if OSSL_ENCODER_gettable_params_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_gettable_params)}
      OSSL_ENCODER_gettable_params := _OSSL_ENCODER_gettable_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_gettable_params_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_gettable_params');
    {$ifend}
  end;
  
  OSSL_ENCODER_get_params := LoadLibFunction(ADllHandle, OSSL_ENCODER_get_params_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_get_params);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_get_params_allownil)}
    OSSL_ENCODER_get_params := ERR_OSSL_ENCODER_get_params;
    {$ifend}
    {$if declared(OSSL_ENCODER_get_params_introduced)}
    if LibVersion < OSSL_ENCODER_get_params_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_get_params)}
      OSSL_ENCODER_get_params := FC_OSSL_ENCODER_get_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_get_params_removed)}
    if OSSL_ENCODER_get_params_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_get_params)}
      OSSL_ENCODER_get_params := _OSSL_ENCODER_get_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_get_params_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_get_params');
    {$ifend}
  end;
  
  OSSL_ENCODER_settable_ctx_params := LoadLibFunction(ADllHandle, OSSL_ENCODER_settable_ctx_params_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_settable_ctx_params);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_settable_ctx_params_allownil)}
    OSSL_ENCODER_settable_ctx_params := ERR_OSSL_ENCODER_settable_ctx_params;
    {$ifend}
    {$if declared(OSSL_ENCODER_settable_ctx_params_introduced)}
    if LibVersion < OSSL_ENCODER_settable_ctx_params_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_settable_ctx_params)}
      OSSL_ENCODER_settable_ctx_params := FC_OSSL_ENCODER_settable_ctx_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_settable_ctx_params_removed)}
    if OSSL_ENCODER_settable_ctx_params_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_settable_ctx_params)}
      OSSL_ENCODER_settable_ctx_params := _OSSL_ENCODER_settable_ctx_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_settable_ctx_params_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_settable_ctx_params');
    {$ifend}
  end;
  
  OSSL_ENCODER_CTX_new := LoadLibFunction(ADllHandle, OSSL_ENCODER_CTX_new_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_CTX_new_allownil)}
    OSSL_ENCODER_CTX_new := ERR_OSSL_ENCODER_CTX_new;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_new_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_new_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_CTX_new)}
      OSSL_ENCODER_CTX_new := FC_OSSL_ENCODER_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_new_removed)}
    if OSSL_ENCODER_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_CTX_new)}
      OSSL_ENCODER_CTX_new := _OSSL_ENCODER_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_new');
    {$ifend}
  end;
  
  OSSL_ENCODER_CTX_set_params := LoadLibFunction(ADllHandle, OSSL_ENCODER_CTX_set_params_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_set_params);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_CTX_set_params_allownil)}
    OSSL_ENCODER_CTX_set_params := ERR_OSSL_ENCODER_CTX_set_params;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_set_params_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_set_params_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_CTX_set_params)}
      OSSL_ENCODER_CTX_set_params := FC_OSSL_ENCODER_CTX_set_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_set_params_removed)}
    if OSSL_ENCODER_CTX_set_params_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_CTX_set_params)}
      OSSL_ENCODER_CTX_set_params := _OSSL_ENCODER_CTX_set_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_CTX_set_params_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_set_params');
    {$ifend}
  end;
  
  OSSL_ENCODER_CTX_free := LoadLibFunction(ADllHandle, OSSL_ENCODER_CTX_free_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_CTX_free_allownil)}
    OSSL_ENCODER_CTX_free := ERR_OSSL_ENCODER_CTX_free;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_free_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_free_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_CTX_free)}
      OSSL_ENCODER_CTX_free := FC_OSSL_ENCODER_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_free_removed)}
    if OSSL_ENCODER_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_CTX_free)}
      OSSL_ENCODER_CTX_free := _OSSL_ENCODER_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_free');
    {$ifend}
  end;
  
  OSSL_ENCODER_CTX_set_passphrase := LoadLibFunction(ADllHandle, OSSL_ENCODER_CTX_set_passphrase_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_set_passphrase);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_CTX_set_passphrase_allownil)}
    OSSL_ENCODER_CTX_set_passphrase := ERR_OSSL_ENCODER_CTX_set_passphrase;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_set_passphrase_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_set_passphrase_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_CTX_set_passphrase)}
      OSSL_ENCODER_CTX_set_passphrase := FC_OSSL_ENCODER_CTX_set_passphrase;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_set_passphrase_removed)}
    if OSSL_ENCODER_CTX_set_passphrase_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_CTX_set_passphrase)}
      OSSL_ENCODER_CTX_set_passphrase := _OSSL_ENCODER_CTX_set_passphrase;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_CTX_set_passphrase_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_set_passphrase');
    {$ifend}
  end;
  
  OSSL_ENCODER_CTX_set_pem_password_cb := LoadLibFunction(ADllHandle, OSSL_ENCODER_CTX_set_pem_password_cb_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_set_pem_password_cb);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_CTX_set_pem_password_cb_allownil)}
    OSSL_ENCODER_CTX_set_pem_password_cb := ERR_OSSL_ENCODER_CTX_set_pem_password_cb;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_set_pem_password_cb_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_set_pem_password_cb_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_CTX_set_pem_password_cb)}
      OSSL_ENCODER_CTX_set_pem_password_cb := FC_OSSL_ENCODER_CTX_set_pem_password_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_set_pem_password_cb_removed)}
    if OSSL_ENCODER_CTX_set_pem_password_cb_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_CTX_set_pem_password_cb)}
      OSSL_ENCODER_CTX_set_pem_password_cb := _OSSL_ENCODER_CTX_set_pem_password_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_CTX_set_pem_password_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_set_pem_password_cb');
    {$ifend}
  end;
  
  OSSL_ENCODER_CTX_set_passphrase_cb := LoadLibFunction(ADllHandle, OSSL_ENCODER_CTX_set_passphrase_cb_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_set_passphrase_cb);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_CTX_set_passphrase_cb_allownil)}
    OSSL_ENCODER_CTX_set_passphrase_cb := ERR_OSSL_ENCODER_CTX_set_passphrase_cb;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_set_passphrase_cb_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_set_passphrase_cb_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_CTX_set_passphrase_cb)}
      OSSL_ENCODER_CTX_set_passphrase_cb := FC_OSSL_ENCODER_CTX_set_passphrase_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_set_passphrase_cb_removed)}
    if OSSL_ENCODER_CTX_set_passphrase_cb_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_CTX_set_passphrase_cb)}
      OSSL_ENCODER_CTX_set_passphrase_cb := _OSSL_ENCODER_CTX_set_passphrase_cb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_CTX_set_passphrase_cb_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_set_passphrase_cb');
    {$ifend}
  end;
  
  OSSL_ENCODER_CTX_set_passphrase_ui := LoadLibFunction(ADllHandle, OSSL_ENCODER_CTX_set_passphrase_ui_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_set_passphrase_ui);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_CTX_set_passphrase_ui_allownil)}
    OSSL_ENCODER_CTX_set_passphrase_ui := ERR_OSSL_ENCODER_CTX_set_passphrase_ui;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_set_passphrase_ui_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_set_passphrase_ui_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_CTX_set_passphrase_ui)}
      OSSL_ENCODER_CTX_set_passphrase_ui := FC_OSSL_ENCODER_CTX_set_passphrase_ui;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_set_passphrase_ui_removed)}
    if OSSL_ENCODER_CTX_set_passphrase_ui_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_CTX_set_passphrase_ui)}
      OSSL_ENCODER_CTX_set_passphrase_ui := _OSSL_ENCODER_CTX_set_passphrase_ui;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_CTX_set_passphrase_ui_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_set_passphrase_ui');
    {$ifend}
  end;
  
  OSSL_ENCODER_CTX_set_cipher := LoadLibFunction(ADllHandle, OSSL_ENCODER_CTX_set_cipher_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_set_cipher);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_CTX_set_cipher_allownil)}
    OSSL_ENCODER_CTX_set_cipher := ERR_OSSL_ENCODER_CTX_set_cipher;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_set_cipher_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_set_cipher_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_CTX_set_cipher)}
      OSSL_ENCODER_CTX_set_cipher := FC_OSSL_ENCODER_CTX_set_cipher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_set_cipher_removed)}
    if OSSL_ENCODER_CTX_set_cipher_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_CTX_set_cipher)}
      OSSL_ENCODER_CTX_set_cipher := _OSSL_ENCODER_CTX_set_cipher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_CTX_set_cipher_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_set_cipher');
    {$ifend}
  end;
  
  OSSL_ENCODER_CTX_set_selection := LoadLibFunction(ADllHandle, OSSL_ENCODER_CTX_set_selection_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_set_selection);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_CTX_set_selection_allownil)}
    OSSL_ENCODER_CTX_set_selection := ERR_OSSL_ENCODER_CTX_set_selection;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_set_selection_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_set_selection_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_CTX_set_selection)}
      OSSL_ENCODER_CTX_set_selection := FC_OSSL_ENCODER_CTX_set_selection;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_set_selection_removed)}
    if OSSL_ENCODER_CTX_set_selection_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_CTX_set_selection)}
      OSSL_ENCODER_CTX_set_selection := _OSSL_ENCODER_CTX_set_selection;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_CTX_set_selection_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_set_selection');
    {$ifend}
  end;
  
  OSSL_ENCODER_CTX_set_output_type := LoadLibFunction(ADllHandle, OSSL_ENCODER_CTX_set_output_type_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_set_output_type);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_CTX_set_output_type_allownil)}
    OSSL_ENCODER_CTX_set_output_type := ERR_OSSL_ENCODER_CTX_set_output_type;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_set_output_type_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_set_output_type_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_CTX_set_output_type)}
      OSSL_ENCODER_CTX_set_output_type := FC_OSSL_ENCODER_CTX_set_output_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_set_output_type_removed)}
    if OSSL_ENCODER_CTX_set_output_type_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_CTX_set_output_type)}
      OSSL_ENCODER_CTX_set_output_type := _OSSL_ENCODER_CTX_set_output_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_CTX_set_output_type_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_set_output_type');
    {$ifend}
  end;
  
  OSSL_ENCODER_CTX_set_output_structure := LoadLibFunction(ADllHandle, OSSL_ENCODER_CTX_set_output_structure_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_set_output_structure);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_CTX_set_output_structure_allownil)}
    OSSL_ENCODER_CTX_set_output_structure := ERR_OSSL_ENCODER_CTX_set_output_structure;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_set_output_structure_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_set_output_structure_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_CTX_set_output_structure)}
      OSSL_ENCODER_CTX_set_output_structure := FC_OSSL_ENCODER_CTX_set_output_structure;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_set_output_structure_removed)}
    if OSSL_ENCODER_CTX_set_output_structure_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_CTX_set_output_structure)}
      OSSL_ENCODER_CTX_set_output_structure := _OSSL_ENCODER_CTX_set_output_structure;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_CTX_set_output_structure_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_set_output_structure');
    {$ifend}
  end;
  
  OSSL_ENCODER_CTX_add_encoder := LoadLibFunction(ADllHandle, OSSL_ENCODER_CTX_add_encoder_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_add_encoder);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_CTX_add_encoder_allownil)}
    OSSL_ENCODER_CTX_add_encoder := ERR_OSSL_ENCODER_CTX_add_encoder;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_add_encoder_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_add_encoder_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_CTX_add_encoder)}
      OSSL_ENCODER_CTX_add_encoder := FC_OSSL_ENCODER_CTX_add_encoder;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_add_encoder_removed)}
    if OSSL_ENCODER_CTX_add_encoder_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_CTX_add_encoder)}
      OSSL_ENCODER_CTX_add_encoder := _OSSL_ENCODER_CTX_add_encoder;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_CTX_add_encoder_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_add_encoder');
    {$ifend}
  end;
  
  OSSL_ENCODER_CTX_add_extra := LoadLibFunction(ADllHandle, OSSL_ENCODER_CTX_add_extra_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_add_extra);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_CTX_add_extra_allownil)}
    OSSL_ENCODER_CTX_add_extra := ERR_OSSL_ENCODER_CTX_add_extra;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_add_extra_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_add_extra_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_CTX_add_extra)}
      OSSL_ENCODER_CTX_add_extra := FC_OSSL_ENCODER_CTX_add_extra;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_add_extra_removed)}
    if OSSL_ENCODER_CTX_add_extra_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_CTX_add_extra)}
      OSSL_ENCODER_CTX_add_extra := _OSSL_ENCODER_CTX_add_extra;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_CTX_add_extra_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_add_extra');
    {$ifend}
  end;
  
  OSSL_ENCODER_CTX_get_num_encoders := LoadLibFunction(ADllHandle, OSSL_ENCODER_CTX_get_num_encoders_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_get_num_encoders);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_CTX_get_num_encoders_allownil)}
    OSSL_ENCODER_CTX_get_num_encoders := ERR_OSSL_ENCODER_CTX_get_num_encoders;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_get_num_encoders_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_get_num_encoders_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_CTX_get_num_encoders)}
      OSSL_ENCODER_CTX_get_num_encoders := FC_OSSL_ENCODER_CTX_get_num_encoders;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_get_num_encoders_removed)}
    if OSSL_ENCODER_CTX_get_num_encoders_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_CTX_get_num_encoders)}
      OSSL_ENCODER_CTX_get_num_encoders := _OSSL_ENCODER_CTX_get_num_encoders;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_CTX_get_num_encoders_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_get_num_encoders');
    {$ifend}
  end;
  
  OSSL_ENCODER_INSTANCE_get_encoder := LoadLibFunction(ADllHandle, OSSL_ENCODER_INSTANCE_get_encoder_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_INSTANCE_get_encoder);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_INSTANCE_get_encoder_allownil)}
    OSSL_ENCODER_INSTANCE_get_encoder := ERR_OSSL_ENCODER_INSTANCE_get_encoder;
    {$ifend}
    {$if declared(OSSL_ENCODER_INSTANCE_get_encoder_introduced)}
    if LibVersion < OSSL_ENCODER_INSTANCE_get_encoder_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_INSTANCE_get_encoder)}
      OSSL_ENCODER_INSTANCE_get_encoder := FC_OSSL_ENCODER_INSTANCE_get_encoder;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_INSTANCE_get_encoder_removed)}
    if OSSL_ENCODER_INSTANCE_get_encoder_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_INSTANCE_get_encoder)}
      OSSL_ENCODER_INSTANCE_get_encoder := _OSSL_ENCODER_INSTANCE_get_encoder;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_INSTANCE_get_encoder_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_INSTANCE_get_encoder');
    {$ifend}
  end;
  
  OSSL_ENCODER_INSTANCE_get_encoder_ctx := LoadLibFunction(ADllHandle, OSSL_ENCODER_INSTANCE_get_encoder_ctx_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_INSTANCE_get_encoder_ctx);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_INSTANCE_get_encoder_ctx_allownil)}
    OSSL_ENCODER_INSTANCE_get_encoder_ctx := ERR_OSSL_ENCODER_INSTANCE_get_encoder_ctx;
    {$ifend}
    {$if declared(OSSL_ENCODER_INSTANCE_get_encoder_ctx_introduced)}
    if LibVersion < OSSL_ENCODER_INSTANCE_get_encoder_ctx_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_INSTANCE_get_encoder_ctx)}
      OSSL_ENCODER_INSTANCE_get_encoder_ctx := FC_OSSL_ENCODER_INSTANCE_get_encoder_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_INSTANCE_get_encoder_ctx_removed)}
    if OSSL_ENCODER_INSTANCE_get_encoder_ctx_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_INSTANCE_get_encoder_ctx)}
      OSSL_ENCODER_INSTANCE_get_encoder_ctx := _OSSL_ENCODER_INSTANCE_get_encoder_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_INSTANCE_get_encoder_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_INSTANCE_get_encoder_ctx');
    {$ifend}
  end;
  
  OSSL_ENCODER_INSTANCE_get_output_type := LoadLibFunction(ADllHandle, OSSL_ENCODER_INSTANCE_get_output_type_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_INSTANCE_get_output_type);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_INSTANCE_get_output_type_allownil)}
    OSSL_ENCODER_INSTANCE_get_output_type := ERR_OSSL_ENCODER_INSTANCE_get_output_type;
    {$ifend}
    {$if declared(OSSL_ENCODER_INSTANCE_get_output_type_introduced)}
    if LibVersion < OSSL_ENCODER_INSTANCE_get_output_type_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_INSTANCE_get_output_type)}
      OSSL_ENCODER_INSTANCE_get_output_type := FC_OSSL_ENCODER_INSTANCE_get_output_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_INSTANCE_get_output_type_removed)}
    if OSSL_ENCODER_INSTANCE_get_output_type_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_INSTANCE_get_output_type)}
      OSSL_ENCODER_INSTANCE_get_output_type := _OSSL_ENCODER_INSTANCE_get_output_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_INSTANCE_get_output_type_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_INSTANCE_get_output_type');
    {$ifend}
  end;
  
  OSSL_ENCODER_INSTANCE_get_output_structure := LoadLibFunction(ADllHandle, OSSL_ENCODER_INSTANCE_get_output_structure_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_INSTANCE_get_output_structure);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_INSTANCE_get_output_structure_allownil)}
    OSSL_ENCODER_INSTANCE_get_output_structure := ERR_OSSL_ENCODER_INSTANCE_get_output_structure;
    {$ifend}
    {$if declared(OSSL_ENCODER_INSTANCE_get_output_structure_introduced)}
    if LibVersion < OSSL_ENCODER_INSTANCE_get_output_structure_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_INSTANCE_get_output_structure)}
      OSSL_ENCODER_INSTANCE_get_output_structure := FC_OSSL_ENCODER_INSTANCE_get_output_structure;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_INSTANCE_get_output_structure_removed)}
    if OSSL_ENCODER_INSTANCE_get_output_structure_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_INSTANCE_get_output_structure)}
      OSSL_ENCODER_INSTANCE_get_output_structure := _OSSL_ENCODER_INSTANCE_get_output_structure;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_INSTANCE_get_output_structure_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_INSTANCE_get_output_structure');
    {$ifend}
  end;
  
  OSSL_ENCODER_CTX_set_construct := LoadLibFunction(ADllHandle, OSSL_ENCODER_CTX_set_construct_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_set_construct);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_CTX_set_construct_allownil)}
    OSSL_ENCODER_CTX_set_construct := ERR_OSSL_ENCODER_CTX_set_construct;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_set_construct_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_set_construct_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_CTX_set_construct)}
      OSSL_ENCODER_CTX_set_construct := FC_OSSL_ENCODER_CTX_set_construct;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_set_construct_removed)}
    if OSSL_ENCODER_CTX_set_construct_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_CTX_set_construct)}
      OSSL_ENCODER_CTX_set_construct := _OSSL_ENCODER_CTX_set_construct;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_CTX_set_construct_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_set_construct');
    {$ifend}
  end;
  
  OSSL_ENCODER_CTX_set_construct_data := LoadLibFunction(ADllHandle, OSSL_ENCODER_CTX_set_construct_data_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_set_construct_data);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_CTX_set_construct_data_allownil)}
    OSSL_ENCODER_CTX_set_construct_data := ERR_OSSL_ENCODER_CTX_set_construct_data;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_set_construct_data_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_set_construct_data_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_CTX_set_construct_data)}
      OSSL_ENCODER_CTX_set_construct_data := FC_OSSL_ENCODER_CTX_set_construct_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_set_construct_data_removed)}
    if OSSL_ENCODER_CTX_set_construct_data_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_CTX_set_construct_data)}
      OSSL_ENCODER_CTX_set_construct_data := _OSSL_ENCODER_CTX_set_construct_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_CTX_set_construct_data_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_set_construct_data');
    {$ifend}
  end;
  
  OSSL_ENCODER_CTX_set_cleanup := LoadLibFunction(ADllHandle, OSSL_ENCODER_CTX_set_cleanup_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_set_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_CTX_set_cleanup_allownil)}
    OSSL_ENCODER_CTX_set_cleanup := ERR_OSSL_ENCODER_CTX_set_cleanup;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_set_cleanup_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_set_cleanup_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_CTX_set_cleanup)}
      OSSL_ENCODER_CTX_set_cleanup := FC_OSSL_ENCODER_CTX_set_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_set_cleanup_removed)}
    if OSSL_ENCODER_CTX_set_cleanup_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_CTX_set_cleanup)}
      OSSL_ENCODER_CTX_set_cleanup := _OSSL_ENCODER_CTX_set_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_CTX_set_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_set_cleanup');
    {$ifend}
  end;
  
  OSSL_ENCODER_to_bio := LoadLibFunction(ADllHandle, OSSL_ENCODER_to_bio_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_to_bio);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_to_bio_allownil)}
    OSSL_ENCODER_to_bio := ERR_OSSL_ENCODER_to_bio;
    {$ifend}
    {$if declared(OSSL_ENCODER_to_bio_introduced)}
    if LibVersion < OSSL_ENCODER_to_bio_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_to_bio)}
      OSSL_ENCODER_to_bio := FC_OSSL_ENCODER_to_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_to_bio_removed)}
    if OSSL_ENCODER_to_bio_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_to_bio)}
      OSSL_ENCODER_to_bio := _OSSL_ENCODER_to_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_to_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_to_bio');
    {$ifend}
  end;
  
  OSSL_ENCODER_to_fp := LoadLibFunction(ADllHandle, OSSL_ENCODER_to_fp_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_to_fp);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_to_fp_allownil)}
    OSSL_ENCODER_to_fp := ERR_OSSL_ENCODER_to_fp;
    {$ifend}
    {$if declared(OSSL_ENCODER_to_fp_introduced)}
    if LibVersion < OSSL_ENCODER_to_fp_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_to_fp)}
      OSSL_ENCODER_to_fp := FC_OSSL_ENCODER_to_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_to_fp_removed)}
    if OSSL_ENCODER_to_fp_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_to_fp)}
      OSSL_ENCODER_to_fp := _OSSL_ENCODER_to_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_to_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_to_fp');
    {$ifend}
  end;
  
  OSSL_ENCODER_to_data := LoadLibFunction(ADllHandle, OSSL_ENCODER_to_data_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_to_data);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_to_data_allownil)}
    OSSL_ENCODER_to_data := ERR_OSSL_ENCODER_to_data;
    {$ifend}
    {$if declared(OSSL_ENCODER_to_data_introduced)}
    if LibVersion < OSSL_ENCODER_to_data_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_to_data)}
      OSSL_ENCODER_to_data := FC_OSSL_ENCODER_to_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_to_data_removed)}
    if OSSL_ENCODER_to_data_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_to_data)}
      OSSL_ENCODER_to_data := _OSSL_ENCODER_to_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_to_data_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_to_data');
    {$ifend}
  end;
  
  OSSL_ENCODER_CTX_new_for_pkey := LoadLibFunction(ADllHandle, OSSL_ENCODER_CTX_new_for_pkey_procname);
  FuncLoadError := not assigned(OSSL_ENCODER_CTX_new_for_pkey);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ENCODER_CTX_new_for_pkey_allownil)}
    OSSL_ENCODER_CTX_new_for_pkey := ERR_OSSL_ENCODER_CTX_new_for_pkey;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_new_for_pkey_introduced)}
    if LibVersion < OSSL_ENCODER_CTX_new_for_pkey_introduced then
    begin
      {$if declared(FC_OSSL_ENCODER_CTX_new_for_pkey)}
      OSSL_ENCODER_CTX_new_for_pkey := FC_OSSL_ENCODER_CTX_new_for_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ENCODER_CTX_new_for_pkey_removed)}
    if OSSL_ENCODER_CTX_new_for_pkey_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ENCODER_CTX_new_for_pkey)}
      OSSL_ENCODER_CTX_new_for_pkey := _OSSL_ENCODER_CTX_new_for_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ENCODER_CTX_new_for_pkey_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ENCODER_CTX_new_for_pkey');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  OSSL_ENCODER_fetch := nil;
  OSSL_ENCODER_up_ref := nil;
  OSSL_ENCODER_free := nil;
  OSSL_ENCODER_get0_provider := nil;
  OSSL_ENCODER_get0_properties := nil;
  OSSL_ENCODER_get0_name := nil;
  OSSL_ENCODER_get0_description := nil;
  OSSL_ENCODER_is_a := nil;
  OSSL_ENCODER_do_all_provided := nil;
  OSSL_ENCODER_names_do_all := nil;
  OSSL_ENCODER_gettable_params := nil;
  OSSL_ENCODER_get_params := nil;
  OSSL_ENCODER_settable_ctx_params := nil;
  OSSL_ENCODER_CTX_new := nil;
  OSSL_ENCODER_CTX_set_params := nil;
  OSSL_ENCODER_CTX_free := nil;
  OSSL_ENCODER_CTX_set_passphrase := nil;
  OSSL_ENCODER_CTX_set_pem_password_cb := nil;
  OSSL_ENCODER_CTX_set_passphrase_cb := nil;
  OSSL_ENCODER_CTX_set_passphrase_ui := nil;
  OSSL_ENCODER_CTX_set_cipher := nil;
  OSSL_ENCODER_CTX_set_selection := nil;
  OSSL_ENCODER_CTX_set_output_type := nil;
  OSSL_ENCODER_CTX_set_output_structure := nil;
  OSSL_ENCODER_CTX_add_encoder := nil;
  OSSL_ENCODER_CTX_add_extra := nil;
  OSSL_ENCODER_CTX_get_num_encoders := nil;
  OSSL_ENCODER_INSTANCE_get_encoder := nil;
  OSSL_ENCODER_INSTANCE_get_encoder_ctx := nil;
  OSSL_ENCODER_INSTANCE_get_output_type := nil;
  OSSL_ENCODER_INSTANCE_get_output_structure := nil;
  OSSL_ENCODER_CTX_set_construct := nil;
  OSSL_ENCODER_CTX_set_construct_data := nil;
  OSSL_ENCODER_CTX_set_cleanup := nil;
  OSSL_ENCODER_to_bio := nil;
  OSSL_ENCODER_to_fp := nil;
  OSSL_ENCODER_to_data := nil;
  OSSL_ENCODER_CTX_new_for_pkey := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.