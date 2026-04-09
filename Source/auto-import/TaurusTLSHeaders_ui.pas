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

unit TaurusTLSHeaders_ui;

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
  Pui_string_st = ^Tui_string_st;
  Tui_string_st = record end;
  {$EXTERNALSYM Pui_string_st}

  PUI_STRING = ^TUI_STRING;
  TUI_STRING = Tui_string_st;
  {$EXTERNALSYM PUI_STRING}

  Pstack_st_UI_STRING = ^Tstack_st_UI_STRING;
  Tstack_st_UI_STRING = record end;
  {$EXTERNALSYM Pstack_st_UI_STRING}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  TUI_ctrl_f_cb = procedure; cdecl;
  Tsk_UI_STRING_compfunc_func_cb = function(arg1: PPUI_STRING; arg2: PPUI_STRING): TIdC_INT; cdecl;
  Tsk_UI_STRING_freefunc_func_cb = procedure(arg1: PUI_STRING); cdecl;
  Tsk_UI_STRING_copyfunc_func_cb = function(arg1: PUI_STRING): PUI_STRING; cdecl;
  TUI_method_set_opener_opener_cb = function(arg1: PUI): TIdC_INT; cdecl;
  TUI_method_set_writer_writer_cb = function(arg1: PUI; arg2: PUI_STRING): TIdC_INT; cdecl;
  TUI_method_set_data_duplicator_duplicator_cb = function(arg1: PUI; arg2: Pointer): Pointer; cdecl;
  TUI_method_set_data_duplicator_destructor_cb = procedure(arg1: PUI; arg2: Pointer); cdecl;
  TUI_method_set_prompt_constructor_prompt_constructor_cb = function(arg1: PUI; arg2: PIdAnsiChar; arg3: PIdAnsiChar): PIdAnsiChar; cdecl;
  TUI_UTIL_wrap_read_pem_callback_cb_cb = function: TIdC_INT; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  UI_INPUT_FLAG_ECHO = $01;
  UI_INPUT_FLAG_DEFAULT_PWD = $02;
  UI_INPUT_FLAG_USER_BASE = 16;
  UI_CTRL_PRINT_ERRORS = 1;
  UI_CTRL_IS_REDOABLE = 2;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  UI_new: function: PUI; cdecl = nil;
  {$EXTERNALSYM UI_new}

  UI_new_method: function(method: PUI_METHOD): PUI; cdecl = nil;
  {$EXTERNALSYM UI_new_method}

  UI_free: procedure(ui: PUI); cdecl = nil;
  {$EXTERNALSYM UI_free}

  UI_add_input_string: function(ui: PUI; prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_add_input_string}

  UI_dup_input_string: function(ui: PUI; prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_dup_input_string}

  UI_add_verify_string: function(ui: PUI; prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT; test_buf: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_add_verify_string}

  UI_dup_verify_string: function(ui: PUI; prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT; test_buf: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_dup_verify_string}

  UI_add_input_boolean: function(ui: PUI; prompt: PIdAnsiChar; action_desc: PIdAnsiChar; ok_chars: PIdAnsiChar; cancel_chars: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_add_input_boolean}

  UI_dup_input_boolean: function(ui: PUI; prompt: PIdAnsiChar; action_desc: PIdAnsiChar; ok_chars: PIdAnsiChar; cancel_chars: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_dup_input_boolean}

  UI_add_info_string: function(ui: PUI; text: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_add_info_string}

  UI_dup_info_string: function(ui: PUI; text: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_dup_info_string}

  UI_add_error_string: function(ui: PUI; text: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_add_error_string}

  UI_dup_error_string: function(ui: PUI; text: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_dup_error_string}

  UI_construct_prompt: function(ui_method: PUI; phrase_desc: PIdAnsiChar; object_name: PIdAnsiChar): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM UI_construct_prompt}

  UI_add_user_data: function(ui: PUI; user_data: Pointer): Pointer; cdecl = nil;
  {$EXTERNALSYM UI_add_user_data}

  UI_dup_user_data: function(ui: PUI; user_data: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_dup_user_data}

  UI_get0_user_data: function(ui: PUI): Pointer; cdecl = nil;
  {$EXTERNALSYM UI_get0_user_data}

  UI_get0_result: function(ui: PUI; i: TIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM UI_get0_result}

  UI_get_result_length: function(ui: PUI; i: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_get_result_length}

  UI_process: function(ui: PUI): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_process}

  UI_ctrl: function(ui: PUI; cmd: TIdC_INT; i: TIdC_LONG; p: Pointer; f: TUI_ctrl_f_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_ctrl}

  UI_set_ex_data: function(r: PUI; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_set_ex_data}

  UI_get_ex_data: function(r: PUI; idx: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM UI_get_ex_data}

  UI_set_default_method: procedure(meth: PUI_METHOD); cdecl = nil;
  {$EXTERNALSYM UI_set_default_method}

  UI_get_default_method: function: PUI_METHOD; cdecl = nil;
  {$EXTERNALSYM UI_get_default_method}

  UI_get_method: function(ui: PUI): PUI_METHOD; cdecl = nil;
  {$EXTERNALSYM UI_get_method}

  UI_set_method: function(ui: PUI; meth: PUI_METHOD): PUI_METHOD; cdecl = nil;
  {$EXTERNALSYM UI_set_method}

  UI_OpenSSL: function: PUI_METHOD; cdecl = nil;
  {$EXTERNALSYM UI_OpenSSL}

  UI_null: function: PUI_METHOD; cdecl = nil;
  {$EXTERNALSYM UI_null}

  UI_create_method: function(name: PIdAnsiChar): PUI_METHOD; cdecl = nil;
  {$EXTERNALSYM UI_create_method}

  UI_destroy_method: procedure(ui_method: PUI_METHOD); cdecl = nil;
  {$EXTERNALSYM UI_destroy_method}

  UI_method_set_opener: function(method: PUI_METHOD; opener: TUI_method_set_opener_opener_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_method_set_opener}

  UI_method_set_writer: function(method: PUI_METHOD; writer: TUI_method_set_writer_writer_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_method_set_writer}

  UI_method_set_flusher: function(method: PUI_METHOD; flusher: TUI_method_set_opener_opener_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_method_set_flusher}

  UI_method_set_reader: function(method: PUI_METHOD; reader: TUI_method_set_writer_writer_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_method_set_reader}

  UI_method_set_closer: function(method: PUI_METHOD; closer: TUI_method_set_opener_opener_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_method_set_closer}

  UI_method_set_data_duplicator: function(method: PUI_METHOD; duplicator: TUI_method_set_data_duplicator_duplicator_cb; destructor: TUI_method_set_data_duplicator_destructor_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_method_set_data_duplicator}

  UI_method_set_prompt_constructor: function(method: PUI_METHOD; prompt_constructor: TUI_method_set_prompt_constructor_prompt_constructor_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_method_set_prompt_constructor}

  UI_method_set_ex_data: function(method: PUI_METHOD; idx: TIdC_INT; data: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_method_set_ex_data}

  UI_method_get_opener: function(method: PUI_METHOD): TUI_method_set_opener_opener_cb; cdecl = nil;
  {$EXTERNALSYM UI_method_get_opener}

  UI_method_get_writer: function(method: PUI_METHOD): TUI_method_set_writer_writer_cb; cdecl = nil;
  {$EXTERNALSYM UI_method_get_writer}

  UI_method_get_flusher: function(method: PUI_METHOD): TUI_method_set_opener_opener_cb; cdecl = nil;
  {$EXTERNALSYM UI_method_get_flusher}

  UI_method_get_reader: function(method: PUI_METHOD): TUI_method_set_writer_writer_cb; cdecl = nil;
  {$EXTERNALSYM UI_method_get_reader}

  UI_method_get_closer: function(method: PUI_METHOD): TUI_method_set_opener_opener_cb; cdecl = nil;
  {$EXTERNALSYM UI_method_get_closer}

  UI_method_get_prompt_constructor: function(method: PUI_METHOD): TUI_method_set_prompt_constructor_prompt_constructor_cb; cdecl = nil;
  {$EXTERNALSYM UI_method_get_prompt_constructor}

  UI_method_get_data_duplicator: function(method: PUI_METHOD): TUI_method_set_data_duplicator_duplicator_cb; cdecl = nil;
  {$EXTERNALSYM UI_method_get_data_duplicator}

  UI_method_get_data_destructor: function(method: PUI_METHOD): TUI_method_set_data_duplicator_destructor_cb; cdecl = nil;
  {$EXTERNALSYM UI_method_get_data_destructor}

  UI_method_get_ex_data: function(method: PUI_METHOD; idx: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM UI_method_get_ex_data}

  UI_get_string_type: function(uis: PUI_STRING): TUI_string_types; cdecl = nil;
  {$EXTERNALSYM UI_get_string_type}

  UI_get_input_flags: function(uis: PUI_STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_get_input_flags}

  UI_get0_output_string: function(uis: PUI_STRING): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM UI_get0_output_string}

  UI_get0_action_string: function(uis: PUI_STRING): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM UI_get0_action_string}

  UI_get0_result_string: function(uis: PUI_STRING): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM UI_get0_result_string}

  UI_get_result_string_length: function(uis: PUI_STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_get_result_string_length}

  UI_get0_test_string: function(uis: PUI_STRING): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM UI_get0_test_string}

  UI_get_result_minsize: function(uis: PUI_STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_get_result_minsize}

  UI_get_result_maxsize: function(uis: PUI_STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_get_result_maxsize}

  UI_set_result: function(ui: PUI; uis: PUI_STRING; result: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_set_result}

  UI_set_result_ex: function(ui: PUI; uis: PUI_STRING; result: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_set_result_ex}

  UI_UTIL_read_pw_string: function(buf: PIdAnsiChar; length: TIdC_INT; prompt: PIdAnsiChar; verify: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_UTIL_read_pw_string}

  UI_UTIL_read_pw: function(buf: PIdAnsiChar; buff: PIdAnsiChar; size: TIdC_INT; prompt: PIdAnsiChar; verify: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM UI_UTIL_read_pw}

  UI_UTIL_wrap_read_pem_callback: function(cb: TUI_UTIL_wrap_read_pem_callback_cb_cb; rwflag: TIdC_INT): PUI_METHOD; cdecl = nil;
  {$EXTERNALSYM UI_UTIL_wrap_read_pem_callback}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function UI_new: PUI; cdecl;
function UI_new_method(method: PUI_METHOD): PUI; cdecl;
procedure UI_free(ui: PUI); cdecl;
function UI_add_input_string(ui: PUI; prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT): TIdC_INT; cdecl;
function UI_dup_input_string(ui: PUI; prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT): TIdC_INT; cdecl;
function UI_add_verify_string(ui: PUI; prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT; test_buf: PIdAnsiChar): TIdC_INT; cdecl;
function UI_dup_verify_string(ui: PUI; prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT; test_buf: PIdAnsiChar): TIdC_INT; cdecl;
function UI_add_input_boolean(ui: PUI; prompt: PIdAnsiChar; action_desc: PIdAnsiChar; ok_chars: PIdAnsiChar; cancel_chars: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar): TIdC_INT; cdecl;
function UI_dup_input_boolean(ui: PUI; prompt: PIdAnsiChar; action_desc: PIdAnsiChar; ok_chars: PIdAnsiChar; cancel_chars: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar): TIdC_INT; cdecl;
function UI_add_info_string(ui: PUI; text: PIdAnsiChar): TIdC_INT; cdecl;
function UI_dup_info_string(ui: PUI; text: PIdAnsiChar): TIdC_INT; cdecl;
function UI_add_error_string(ui: PUI; text: PIdAnsiChar): TIdC_INT; cdecl;
function UI_dup_error_string(ui: PUI; text: PIdAnsiChar): TIdC_INT; cdecl;
function UI_construct_prompt(ui_method: PUI; phrase_desc: PIdAnsiChar; object_name: PIdAnsiChar): PIdAnsiChar; cdecl;
function UI_add_user_data(ui: PUI; user_data: Pointer): Pointer; cdecl;
function UI_dup_user_data(ui: PUI; user_data: Pointer): TIdC_INT; cdecl;
function UI_get0_user_data(ui: PUI): Pointer; cdecl;
function UI_get0_result(ui: PUI; i: TIdC_INT): PIdAnsiChar; cdecl;
function UI_get_result_length(ui: PUI; i: TIdC_INT): TIdC_INT; cdecl;
function UI_process(ui: PUI): TIdC_INT; cdecl;
function UI_ctrl(ui: PUI; cmd: TIdC_INT; i: TIdC_LONG; p: Pointer; f: TUI_ctrl_f_cb): TIdC_INT; cdecl;
function UI_set_ex_data(r: PUI; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl;
function UI_get_ex_data(r: PUI; idx: TIdC_INT): Pointer; cdecl;
procedure UI_set_default_method(meth: PUI_METHOD); cdecl;
function UI_get_default_method: PUI_METHOD; cdecl;
function UI_get_method(ui: PUI): PUI_METHOD; cdecl;
function UI_set_method(ui: PUI; meth: PUI_METHOD): PUI_METHOD; cdecl;
function UI_OpenSSL: PUI_METHOD; cdecl;
function UI_null: PUI_METHOD; cdecl;
function UI_create_method(name: PIdAnsiChar): PUI_METHOD; cdecl;
procedure UI_destroy_method(ui_method: PUI_METHOD); cdecl;
function UI_method_set_opener(method: PUI_METHOD; opener: TUI_method_set_opener_opener_cb): TIdC_INT; cdecl;
function UI_method_set_writer(method: PUI_METHOD; writer: TUI_method_set_writer_writer_cb): TIdC_INT; cdecl;
function UI_method_set_flusher(method: PUI_METHOD; flusher: TUI_method_set_opener_opener_cb): TIdC_INT; cdecl;
function UI_method_set_reader(method: PUI_METHOD; reader: TUI_method_set_writer_writer_cb): TIdC_INT; cdecl;
function UI_method_set_closer(method: PUI_METHOD; closer: TUI_method_set_opener_opener_cb): TIdC_INT; cdecl;
function UI_method_set_data_duplicator(method: PUI_METHOD; duplicator: TUI_method_set_data_duplicator_duplicator_cb; destructor: TUI_method_set_data_duplicator_destructor_cb): TIdC_INT; cdecl;
function UI_method_set_prompt_constructor(method: PUI_METHOD; prompt_constructor: TUI_method_set_prompt_constructor_prompt_constructor_cb): TIdC_INT; cdecl;
function UI_method_set_ex_data(method: PUI_METHOD; idx: TIdC_INT; data: Pointer): TIdC_INT; cdecl;
function UI_method_get_opener(method: PUI_METHOD): TUI_method_set_opener_opener_cb; cdecl;
function UI_method_get_writer(method: PUI_METHOD): TUI_method_set_writer_writer_cb; cdecl;
function UI_method_get_flusher(method: PUI_METHOD): TUI_method_set_opener_opener_cb; cdecl;
function UI_method_get_reader(method: PUI_METHOD): TUI_method_set_writer_writer_cb; cdecl;
function UI_method_get_closer(method: PUI_METHOD): TUI_method_set_opener_opener_cb; cdecl;
function UI_method_get_prompt_constructor(method: PUI_METHOD): TUI_method_set_prompt_constructor_prompt_constructor_cb; cdecl;
function UI_method_get_data_duplicator(method: PUI_METHOD): TUI_method_set_data_duplicator_duplicator_cb; cdecl;
function UI_method_get_data_destructor(method: PUI_METHOD): TUI_method_set_data_duplicator_destructor_cb; cdecl;
function UI_method_get_ex_data(method: PUI_METHOD; idx: TIdC_INT): Pointer; cdecl;
function UI_get_string_type(uis: PUI_STRING): TUI_string_types; cdecl;
function UI_get_input_flags(uis: PUI_STRING): TIdC_INT; cdecl;
function UI_get0_output_string(uis: PUI_STRING): PIdAnsiChar; cdecl;
function UI_get0_action_string(uis: PUI_STRING): PIdAnsiChar; cdecl;
function UI_get0_result_string(uis: PUI_STRING): PIdAnsiChar; cdecl;
function UI_get_result_string_length(uis: PUI_STRING): TIdC_INT; cdecl;
function UI_get0_test_string(uis: PUI_STRING): PIdAnsiChar; cdecl;
function UI_get_result_minsize(uis: PUI_STRING): TIdC_INT; cdecl;
function UI_get_result_maxsize(uis: PUI_STRING): TIdC_INT; cdecl;
function UI_set_result(ui: PUI; uis: PUI_STRING; result: PIdAnsiChar): TIdC_INT; cdecl;
function UI_set_result_ex(ui: PUI; uis: PUI_STRING; result: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function UI_UTIL_read_pw_string(buf: PIdAnsiChar; length: TIdC_INT; prompt: PIdAnsiChar; verify: TIdC_INT): TIdC_INT; cdecl;
function UI_UTIL_read_pw(buf: PIdAnsiChar; buff: PIdAnsiChar; size: TIdC_INT; prompt: PIdAnsiChar; verify: TIdC_INT): TIdC_INT; cdecl;
function UI_UTIL_wrap_read_pem_callback(cb: TUI_UTIL_wrap_read_pem_callback_cb_cb; rwflag: TIdC_INT): PUI_METHOD; cdecl;
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

function UI_new: PUI; cdecl external CLibCrypto name 'UI_new';
function UI_new_method(method: PUI_METHOD): PUI; cdecl external CLibCrypto name 'UI_new_method';
procedure UI_free(ui: PUI); cdecl external CLibCrypto name 'UI_free';
function UI_add_input_string(ui: PUI; prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'UI_add_input_string';
function UI_dup_input_string(ui: PUI; prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'UI_dup_input_string';
function UI_add_verify_string(ui: PUI; prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT; test_buf: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'UI_add_verify_string';
function UI_dup_verify_string(ui: PUI; prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT; test_buf: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'UI_dup_verify_string';
function UI_add_input_boolean(ui: PUI; prompt: PIdAnsiChar; action_desc: PIdAnsiChar; ok_chars: PIdAnsiChar; cancel_chars: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'UI_add_input_boolean';
function UI_dup_input_boolean(ui: PUI; prompt: PIdAnsiChar; action_desc: PIdAnsiChar; ok_chars: PIdAnsiChar; cancel_chars: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'UI_dup_input_boolean';
function UI_add_info_string(ui: PUI; text: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'UI_add_info_string';
function UI_dup_info_string(ui: PUI; text: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'UI_dup_info_string';
function UI_add_error_string(ui: PUI; text: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'UI_add_error_string';
function UI_dup_error_string(ui: PUI; text: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'UI_dup_error_string';
function UI_construct_prompt(ui_method: PUI; phrase_desc: PIdAnsiChar; object_name: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'UI_construct_prompt';
function UI_add_user_data(ui: PUI; user_data: Pointer): Pointer; cdecl external CLibCrypto name 'UI_add_user_data';
function UI_dup_user_data(ui: PUI; user_data: Pointer): TIdC_INT; cdecl external CLibCrypto name 'UI_dup_user_data';
function UI_get0_user_data(ui: PUI): Pointer; cdecl external CLibCrypto name 'UI_get0_user_data';
function UI_get0_result(ui: PUI; i: TIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'UI_get0_result';
function UI_get_result_length(ui: PUI; i: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'UI_get_result_length';
function UI_process(ui: PUI): TIdC_INT; cdecl external CLibCrypto name 'UI_process';
function UI_ctrl(ui: PUI; cmd: TIdC_INT; i: TIdC_LONG; p: Pointer; f: TUI_ctrl_f_cb): TIdC_INT; cdecl external CLibCrypto name 'UI_ctrl';
function UI_set_ex_data(r: PUI; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl external CLibCrypto name 'UI_set_ex_data';
function UI_get_ex_data(r: PUI; idx: TIdC_INT): Pointer; cdecl external CLibCrypto name 'UI_get_ex_data';
procedure UI_set_default_method(meth: PUI_METHOD); cdecl external CLibCrypto name 'UI_set_default_method';
function UI_get_default_method: PUI_METHOD; cdecl external CLibCrypto name 'UI_get_default_method';
function UI_get_method(ui: PUI): PUI_METHOD; cdecl external CLibCrypto name 'UI_get_method';
function UI_set_method(ui: PUI; meth: PUI_METHOD): PUI_METHOD; cdecl external CLibCrypto name 'UI_set_method';
function UI_OpenSSL: PUI_METHOD; cdecl external CLibCrypto name 'UI_OpenSSL';
function UI_null: PUI_METHOD; cdecl external CLibCrypto name 'UI_null';
function UI_create_method(name: PIdAnsiChar): PUI_METHOD; cdecl external CLibCrypto name 'UI_create_method';
procedure UI_destroy_method(ui_method: PUI_METHOD); cdecl external CLibCrypto name 'UI_destroy_method';
function UI_method_set_opener(method: PUI_METHOD; opener: TUI_method_set_opener_opener_cb): TIdC_INT; cdecl external CLibCrypto name 'UI_method_set_opener';
function UI_method_set_writer(method: PUI_METHOD; writer: TUI_method_set_writer_writer_cb): TIdC_INT; cdecl external CLibCrypto name 'UI_method_set_writer';
function UI_method_set_flusher(method: PUI_METHOD; flusher: TUI_method_set_opener_opener_cb): TIdC_INT; cdecl external CLibCrypto name 'UI_method_set_flusher';
function UI_method_set_reader(method: PUI_METHOD; reader: TUI_method_set_writer_writer_cb): TIdC_INT; cdecl external CLibCrypto name 'UI_method_set_reader';
function UI_method_set_closer(method: PUI_METHOD; closer: TUI_method_set_opener_opener_cb): TIdC_INT; cdecl external CLibCrypto name 'UI_method_set_closer';
function UI_method_set_data_duplicator(method: PUI_METHOD; duplicator: TUI_method_set_data_duplicator_duplicator_cb; destructor: TUI_method_set_data_duplicator_destructor_cb): TIdC_INT; cdecl external CLibCrypto name 'UI_method_set_data_duplicator';
function UI_method_set_prompt_constructor(method: PUI_METHOD; prompt_constructor: TUI_method_set_prompt_constructor_prompt_constructor_cb): TIdC_INT; cdecl external CLibCrypto name 'UI_method_set_prompt_constructor';
function UI_method_set_ex_data(method: PUI_METHOD; idx: TIdC_INT; data: Pointer): TIdC_INT; cdecl external CLibCrypto name 'UI_method_set_ex_data';
function UI_method_get_opener(method: PUI_METHOD): TUI_method_set_opener_opener_cb; cdecl external CLibCrypto name 'UI_method_get_opener';
function UI_method_get_writer(method: PUI_METHOD): TUI_method_set_writer_writer_cb; cdecl external CLibCrypto name 'UI_method_get_writer';
function UI_method_get_flusher(method: PUI_METHOD): TUI_method_set_opener_opener_cb; cdecl external CLibCrypto name 'UI_method_get_flusher';
function UI_method_get_reader(method: PUI_METHOD): TUI_method_set_writer_writer_cb; cdecl external CLibCrypto name 'UI_method_get_reader';
function UI_method_get_closer(method: PUI_METHOD): TUI_method_set_opener_opener_cb; cdecl external CLibCrypto name 'UI_method_get_closer';
function UI_method_get_prompt_constructor(method: PUI_METHOD): TUI_method_set_prompt_constructor_prompt_constructor_cb; cdecl external CLibCrypto name 'UI_method_get_prompt_constructor';
function UI_method_get_data_duplicator(method: PUI_METHOD): TUI_method_set_data_duplicator_duplicator_cb; cdecl external CLibCrypto name 'UI_method_get_data_duplicator';
function UI_method_get_data_destructor(method: PUI_METHOD): TUI_method_set_data_duplicator_destructor_cb; cdecl external CLibCrypto name 'UI_method_get_data_destructor';
function UI_method_get_ex_data(method: PUI_METHOD; idx: TIdC_INT): Pointer; cdecl external CLibCrypto name 'UI_method_get_ex_data';
function UI_get_string_type(uis: PUI_STRING): TUI_string_types; cdecl external CLibCrypto name 'UI_get_string_type';
function UI_get_input_flags(uis: PUI_STRING): TIdC_INT; cdecl external CLibCrypto name 'UI_get_input_flags';
function UI_get0_output_string(uis: PUI_STRING): PIdAnsiChar; cdecl external CLibCrypto name 'UI_get0_output_string';
function UI_get0_action_string(uis: PUI_STRING): PIdAnsiChar; cdecl external CLibCrypto name 'UI_get0_action_string';
function UI_get0_result_string(uis: PUI_STRING): PIdAnsiChar; cdecl external CLibCrypto name 'UI_get0_result_string';
function UI_get_result_string_length(uis: PUI_STRING): TIdC_INT; cdecl external CLibCrypto name 'UI_get_result_string_length';
function UI_get0_test_string(uis: PUI_STRING): PIdAnsiChar; cdecl external CLibCrypto name 'UI_get0_test_string';
function UI_get_result_minsize(uis: PUI_STRING): TIdC_INT; cdecl external CLibCrypto name 'UI_get_result_minsize';
function UI_get_result_maxsize(uis: PUI_STRING): TIdC_INT; cdecl external CLibCrypto name 'UI_get_result_maxsize';
function UI_set_result(ui: PUI; uis: PUI_STRING; result: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'UI_set_result';
function UI_set_result_ex(ui: PUI; uis: PUI_STRING; result: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'UI_set_result_ex';
function UI_UTIL_read_pw_string(buf: PIdAnsiChar; length: TIdC_INT; prompt: PIdAnsiChar; verify: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'UI_UTIL_read_pw_string';
function UI_UTIL_read_pw(buf: PIdAnsiChar; buff: PIdAnsiChar; size: TIdC_INT; prompt: PIdAnsiChar; verify: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'UI_UTIL_read_pw';
function UI_UTIL_wrap_read_pem_callback(cb: TUI_UTIL_wrap_read_pem_callback_cb_cb; rwflag: TIdC_INT): PUI_METHOD; cdecl external CLibCrypto name 'UI_UTIL_wrap_read_pem_callback';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  UI_new_procname = 'UI_new';
  UI_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_new_method_procname = 'UI_new_method';
  UI_new_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_free_procname = 'UI_free';
  UI_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_add_input_string_procname = 'UI_add_input_string';
  UI_add_input_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_dup_input_string_procname = 'UI_dup_input_string';
  UI_dup_input_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_add_verify_string_procname = 'UI_add_verify_string';
  UI_add_verify_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_dup_verify_string_procname = 'UI_dup_verify_string';
  UI_dup_verify_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_add_input_boolean_procname = 'UI_add_input_boolean';
  UI_add_input_boolean_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_dup_input_boolean_procname = 'UI_dup_input_boolean';
  UI_dup_input_boolean_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_add_info_string_procname = 'UI_add_info_string';
  UI_add_info_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_dup_info_string_procname = 'UI_dup_info_string';
  UI_dup_info_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_add_error_string_procname = 'UI_add_error_string';
  UI_add_error_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_dup_error_string_procname = 'UI_dup_error_string';
  UI_dup_error_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_construct_prompt_procname = 'UI_construct_prompt';
  UI_construct_prompt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_add_user_data_procname = 'UI_add_user_data';
  UI_add_user_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_dup_user_data_procname = 'UI_dup_user_data';
  UI_dup_user_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  UI_get0_user_data_procname = 'UI_get0_user_data';
  UI_get0_user_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_get0_result_procname = 'UI_get0_result';
  UI_get0_result_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_get_result_length_procname = 'UI_get_result_length';
  UI_get_result_length_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  UI_process_procname = 'UI_process';
  UI_process_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_ctrl_procname = 'UI_ctrl';
  UI_ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_set_ex_data_procname = 'UI_set_ex_data';
  UI_set_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_get_ex_data_procname = 'UI_get_ex_data';
  UI_get_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_set_default_method_procname = 'UI_set_default_method';
  UI_set_default_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_get_default_method_procname = 'UI_get_default_method';
  UI_get_default_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_get_method_procname = 'UI_get_method';
  UI_get_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_set_method_procname = 'UI_set_method';
  UI_set_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_OpenSSL_procname = 'UI_OpenSSL';
  UI_OpenSSL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_null_procname = 'UI_null';
  UI_null_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  UI_create_method_procname = 'UI_create_method';
  UI_create_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_destroy_method_procname = 'UI_destroy_method';
  UI_destroy_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_method_set_opener_procname = 'UI_method_set_opener';
  UI_method_set_opener_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_method_set_writer_procname = 'UI_method_set_writer';
  UI_method_set_writer_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_method_set_flusher_procname = 'UI_method_set_flusher';
  UI_method_set_flusher_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_method_set_reader_procname = 'UI_method_set_reader';
  UI_method_set_reader_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_method_set_closer_procname = 'UI_method_set_closer';
  UI_method_set_closer_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_method_set_data_duplicator_procname = 'UI_method_set_data_duplicator';
  UI_method_set_data_duplicator_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  UI_method_set_prompt_constructor_procname = 'UI_method_set_prompt_constructor';
  UI_method_set_prompt_constructor_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_method_set_ex_data_procname = 'UI_method_set_ex_data';
  UI_method_set_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  UI_method_get_opener_procname = 'UI_method_get_opener';
  UI_method_get_opener_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_method_get_writer_procname = 'UI_method_get_writer';
  UI_method_get_writer_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_method_get_flusher_procname = 'UI_method_get_flusher';
  UI_method_get_flusher_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_method_get_reader_procname = 'UI_method_get_reader';
  UI_method_get_reader_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_method_get_closer_procname = 'UI_method_get_closer';
  UI_method_get_closer_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_method_get_prompt_constructor_procname = 'UI_method_get_prompt_constructor';
  UI_method_get_prompt_constructor_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_method_get_data_duplicator_procname = 'UI_method_get_data_duplicator';
  UI_method_get_data_duplicator_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  UI_method_get_data_destructor_procname = 'UI_method_get_data_destructor';
  UI_method_get_data_destructor_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  UI_method_get_ex_data_procname = 'UI_method_get_ex_data';
  UI_method_get_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  UI_get_string_type_procname = 'UI_get_string_type';
  UI_get_string_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_get_input_flags_procname = 'UI_get_input_flags';
  UI_get_input_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_get0_output_string_procname = 'UI_get0_output_string';
  UI_get0_output_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_get0_action_string_procname = 'UI_get0_action_string';
  UI_get0_action_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_get0_result_string_procname = 'UI_get0_result_string';
  UI_get0_result_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_get_result_string_length_procname = 'UI_get_result_string_length';
  UI_get_result_string_length_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  UI_get0_test_string_procname = 'UI_get0_test_string';
  UI_get0_test_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_get_result_minsize_procname = 'UI_get_result_minsize';
  UI_get_result_minsize_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_get_result_maxsize_procname = 'UI_get_result_maxsize';
  UI_get_result_maxsize_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_set_result_procname = 'UI_set_result';
  UI_set_result_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_set_result_ex_procname = 'UI_set_result_ex';
  UI_set_result_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  UI_UTIL_read_pw_string_procname = 'UI_UTIL_read_pw_string';
  UI_UTIL_read_pw_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_UTIL_read_pw_procname = 'UI_UTIL_read_pw';
  UI_UTIL_read_pw_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  UI_UTIL_wrap_read_pem_callback_procname = 'UI_UTIL_wrap_read_pem_callback';
  UI_UTIL_wrap_read_pem_callback_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_UI_new: PUI; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_new_procname);
end;

function ERR_UI_new_method(method: PUI_METHOD): PUI; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_new_method_procname);
end;

procedure ERR_UI_free(ui: PUI); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_free_procname);
end;

function ERR_UI_add_input_string(ui: PUI; prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_add_input_string_procname);
end;

function ERR_UI_dup_input_string(ui: PUI; prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_dup_input_string_procname);
end;

function ERR_UI_add_verify_string(ui: PUI; prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT; test_buf: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_add_verify_string_procname);
end;

function ERR_UI_dup_verify_string(ui: PUI; prompt: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar; minsize: TIdC_INT; maxsize: TIdC_INT; test_buf: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_dup_verify_string_procname);
end;

function ERR_UI_add_input_boolean(ui: PUI; prompt: PIdAnsiChar; action_desc: PIdAnsiChar; ok_chars: PIdAnsiChar; cancel_chars: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_add_input_boolean_procname);
end;

function ERR_UI_dup_input_boolean(ui: PUI; prompt: PIdAnsiChar; action_desc: PIdAnsiChar; ok_chars: PIdAnsiChar; cancel_chars: PIdAnsiChar; flags: TIdC_INT; result_buf: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_dup_input_boolean_procname);
end;

function ERR_UI_add_info_string(ui: PUI; text: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_add_info_string_procname);
end;

function ERR_UI_dup_info_string(ui: PUI; text: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_dup_info_string_procname);
end;

function ERR_UI_add_error_string(ui: PUI; text: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_add_error_string_procname);
end;

function ERR_UI_dup_error_string(ui: PUI; text: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_dup_error_string_procname);
end;

function ERR_UI_construct_prompt(ui_method: PUI; phrase_desc: PIdAnsiChar; object_name: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_construct_prompt_procname);
end;

function ERR_UI_add_user_data(ui: PUI; user_data: Pointer): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_add_user_data_procname);
end;

function ERR_UI_dup_user_data(ui: PUI; user_data: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_dup_user_data_procname);
end;

function ERR_UI_get0_user_data(ui: PUI): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get0_user_data_procname);
end;

function ERR_UI_get0_result(ui: PUI; i: TIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get0_result_procname);
end;

function ERR_UI_get_result_length(ui: PUI; i: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get_result_length_procname);
end;

function ERR_UI_process(ui: PUI): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_process_procname);
end;

function ERR_UI_ctrl(ui: PUI; cmd: TIdC_INT; i: TIdC_LONG; p: Pointer; f: TUI_ctrl_f_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_ctrl_procname);
end;

function ERR_UI_set_ex_data(r: PUI; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_set_ex_data_procname);
end;

function ERR_UI_get_ex_data(r: PUI; idx: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get_ex_data_procname);
end;

procedure ERR_UI_set_default_method(meth: PUI_METHOD); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_set_default_method_procname);
end;

function ERR_UI_get_default_method: PUI_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get_default_method_procname);
end;

function ERR_UI_get_method(ui: PUI): PUI_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get_method_procname);
end;

function ERR_UI_set_method(ui: PUI; meth: PUI_METHOD): PUI_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_set_method_procname);
end;

function ERR_UI_OpenSSL: PUI_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_OpenSSL_procname);
end;

function ERR_UI_null: PUI_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_null_procname);
end;

function ERR_UI_create_method(name: PIdAnsiChar): PUI_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_create_method_procname);
end;

procedure ERR_UI_destroy_method(ui_method: PUI_METHOD); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_destroy_method_procname);
end;

function ERR_UI_method_set_opener(method: PUI_METHOD; opener: TUI_method_set_opener_opener_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_set_opener_procname);
end;

function ERR_UI_method_set_writer(method: PUI_METHOD; writer: TUI_method_set_writer_writer_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_set_writer_procname);
end;

function ERR_UI_method_set_flusher(method: PUI_METHOD; flusher: TUI_method_set_opener_opener_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_set_flusher_procname);
end;

function ERR_UI_method_set_reader(method: PUI_METHOD; reader: TUI_method_set_writer_writer_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_set_reader_procname);
end;

function ERR_UI_method_set_closer(method: PUI_METHOD; closer: TUI_method_set_opener_opener_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_set_closer_procname);
end;

function ERR_UI_method_set_data_duplicator(method: PUI_METHOD; duplicator: TUI_method_set_data_duplicator_duplicator_cb; destructor: TUI_method_set_data_duplicator_destructor_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_set_data_duplicator_procname);
end;

function ERR_UI_method_set_prompt_constructor(method: PUI_METHOD; prompt_constructor: TUI_method_set_prompt_constructor_prompt_constructor_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_set_prompt_constructor_procname);
end;

function ERR_UI_method_set_ex_data(method: PUI_METHOD; idx: TIdC_INT; data: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_set_ex_data_procname);
end;

function ERR_UI_method_get_opener(method: PUI_METHOD): TUI_method_set_opener_opener_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_get_opener_procname);
end;

function ERR_UI_method_get_writer(method: PUI_METHOD): TUI_method_set_writer_writer_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_get_writer_procname);
end;

function ERR_UI_method_get_flusher(method: PUI_METHOD): TUI_method_set_opener_opener_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_get_flusher_procname);
end;

function ERR_UI_method_get_reader(method: PUI_METHOD): TUI_method_set_writer_writer_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_get_reader_procname);
end;

function ERR_UI_method_get_closer(method: PUI_METHOD): TUI_method_set_opener_opener_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_get_closer_procname);
end;

function ERR_UI_method_get_prompt_constructor(method: PUI_METHOD): TUI_method_set_prompt_constructor_prompt_constructor_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_get_prompt_constructor_procname);
end;

function ERR_UI_method_get_data_duplicator(method: PUI_METHOD): TUI_method_set_data_duplicator_duplicator_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_get_data_duplicator_procname);
end;

function ERR_UI_method_get_data_destructor(method: PUI_METHOD): TUI_method_set_data_duplicator_destructor_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_get_data_destructor_procname);
end;

function ERR_UI_method_get_ex_data(method: PUI_METHOD; idx: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_method_get_ex_data_procname);
end;

function ERR_UI_get_string_type(uis: PUI_STRING): TUI_string_types; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get_string_type_procname);
end;

function ERR_UI_get_input_flags(uis: PUI_STRING): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get_input_flags_procname);
end;

function ERR_UI_get0_output_string(uis: PUI_STRING): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get0_output_string_procname);
end;

function ERR_UI_get0_action_string(uis: PUI_STRING): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get0_action_string_procname);
end;

function ERR_UI_get0_result_string(uis: PUI_STRING): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get0_result_string_procname);
end;

function ERR_UI_get_result_string_length(uis: PUI_STRING): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get_result_string_length_procname);
end;

function ERR_UI_get0_test_string(uis: PUI_STRING): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get0_test_string_procname);
end;

function ERR_UI_get_result_minsize(uis: PUI_STRING): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get_result_minsize_procname);
end;

function ERR_UI_get_result_maxsize(uis: PUI_STRING): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_get_result_maxsize_procname);
end;

function ERR_UI_set_result(ui: PUI; uis: PUI_STRING; result: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_set_result_procname);
end;

function ERR_UI_set_result_ex(ui: PUI; uis: PUI_STRING; result: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_set_result_ex_procname);
end;

function ERR_UI_UTIL_read_pw_string(buf: PIdAnsiChar; length: TIdC_INT; prompt: PIdAnsiChar; verify: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_UTIL_read_pw_string_procname);
end;

function ERR_UI_UTIL_read_pw(buf: PIdAnsiChar; buff: PIdAnsiChar; size: TIdC_INT; prompt: PIdAnsiChar; verify: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_UTIL_read_pw_procname);
end;

function ERR_UI_UTIL_wrap_read_pem_callback(cb: TUI_UTIL_wrap_read_pem_callback_cb_cb; rwflag: TIdC_INT): PUI_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UI_UTIL_wrap_read_pem_callback_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  UI_new := LoadLibFunction(ADllHandle, UI_new_procname);
  FuncLoadError := not assigned(UI_new);
  if FuncLoadError then
  begin
    {$if not defined(UI_new_allownil)}
    UI_new := ERR_UI_new;
    {$ifend}
    {$if declared(UI_new_introduced)}
    if LibVersion < UI_new_introduced then
    begin
      {$if declared(FC_UI_new)}
      UI_new := FC_UI_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_new_removed)}
    if UI_new_removed <= LibVersion then
    begin
      {$if declared(_UI_new)}
      UI_new := _UI_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_new_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_new');
    {$ifend}
  end;
  
  UI_new_method := LoadLibFunction(ADllHandle, UI_new_method_procname);
  FuncLoadError := not assigned(UI_new_method);
  if FuncLoadError then
  begin
    {$if not defined(UI_new_method_allownil)}
    UI_new_method := ERR_UI_new_method;
    {$ifend}
    {$if declared(UI_new_method_introduced)}
    if LibVersion < UI_new_method_introduced then
    begin
      {$if declared(FC_UI_new_method)}
      UI_new_method := FC_UI_new_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_new_method_removed)}
    if UI_new_method_removed <= LibVersion then
    begin
      {$if declared(_UI_new_method)}
      UI_new_method := _UI_new_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_new_method_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_new_method');
    {$ifend}
  end;
  
  UI_free := LoadLibFunction(ADllHandle, UI_free_procname);
  FuncLoadError := not assigned(UI_free);
  if FuncLoadError then
  begin
    {$if not defined(UI_free_allownil)}
    UI_free := ERR_UI_free;
    {$ifend}
    {$if declared(UI_free_introduced)}
    if LibVersion < UI_free_introduced then
    begin
      {$if declared(FC_UI_free)}
      UI_free := FC_UI_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_free_removed)}
    if UI_free_removed <= LibVersion then
    begin
      {$if declared(_UI_free)}
      UI_free := _UI_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_free_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_free');
    {$ifend}
  end;
  
  UI_add_input_string := LoadLibFunction(ADllHandle, UI_add_input_string_procname);
  FuncLoadError := not assigned(UI_add_input_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_add_input_string_allownil)}
    UI_add_input_string := ERR_UI_add_input_string;
    {$ifend}
    {$if declared(UI_add_input_string_introduced)}
    if LibVersion < UI_add_input_string_introduced then
    begin
      {$if declared(FC_UI_add_input_string)}
      UI_add_input_string := FC_UI_add_input_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_add_input_string_removed)}
    if UI_add_input_string_removed <= LibVersion then
    begin
      {$if declared(_UI_add_input_string)}
      UI_add_input_string := _UI_add_input_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_add_input_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_add_input_string');
    {$ifend}
  end;
  
  UI_dup_input_string := LoadLibFunction(ADllHandle, UI_dup_input_string_procname);
  FuncLoadError := not assigned(UI_dup_input_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_dup_input_string_allownil)}
    UI_dup_input_string := ERR_UI_dup_input_string;
    {$ifend}
    {$if declared(UI_dup_input_string_introduced)}
    if LibVersion < UI_dup_input_string_introduced then
    begin
      {$if declared(FC_UI_dup_input_string)}
      UI_dup_input_string := FC_UI_dup_input_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_dup_input_string_removed)}
    if UI_dup_input_string_removed <= LibVersion then
    begin
      {$if declared(_UI_dup_input_string)}
      UI_dup_input_string := _UI_dup_input_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_dup_input_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_dup_input_string');
    {$ifend}
  end;
  
  UI_add_verify_string := LoadLibFunction(ADllHandle, UI_add_verify_string_procname);
  FuncLoadError := not assigned(UI_add_verify_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_add_verify_string_allownil)}
    UI_add_verify_string := ERR_UI_add_verify_string;
    {$ifend}
    {$if declared(UI_add_verify_string_introduced)}
    if LibVersion < UI_add_verify_string_introduced then
    begin
      {$if declared(FC_UI_add_verify_string)}
      UI_add_verify_string := FC_UI_add_verify_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_add_verify_string_removed)}
    if UI_add_verify_string_removed <= LibVersion then
    begin
      {$if declared(_UI_add_verify_string)}
      UI_add_verify_string := _UI_add_verify_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_add_verify_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_add_verify_string');
    {$ifend}
  end;
  
  UI_dup_verify_string := LoadLibFunction(ADllHandle, UI_dup_verify_string_procname);
  FuncLoadError := not assigned(UI_dup_verify_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_dup_verify_string_allownil)}
    UI_dup_verify_string := ERR_UI_dup_verify_string;
    {$ifend}
    {$if declared(UI_dup_verify_string_introduced)}
    if LibVersion < UI_dup_verify_string_introduced then
    begin
      {$if declared(FC_UI_dup_verify_string)}
      UI_dup_verify_string := FC_UI_dup_verify_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_dup_verify_string_removed)}
    if UI_dup_verify_string_removed <= LibVersion then
    begin
      {$if declared(_UI_dup_verify_string)}
      UI_dup_verify_string := _UI_dup_verify_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_dup_verify_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_dup_verify_string');
    {$ifend}
  end;
  
  UI_add_input_boolean := LoadLibFunction(ADllHandle, UI_add_input_boolean_procname);
  FuncLoadError := not assigned(UI_add_input_boolean);
  if FuncLoadError then
  begin
    {$if not defined(UI_add_input_boolean_allownil)}
    UI_add_input_boolean := ERR_UI_add_input_boolean;
    {$ifend}
    {$if declared(UI_add_input_boolean_introduced)}
    if LibVersion < UI_add_input_boolean_introduced then
    begin
      {$if declared(FC_UI_add_input_boolean)}
      UI_add_input_boolean := FC_UI_add_input_boolean;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_add_input_boolean_removed)}
    if UI_add_input_boolean_removed <= LibVersion then
    begin
      {$if declared(_UI_add_input_boolean)}
      UI_add_input_boolean := _UI_add_input_boolean;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_add_input_boolean_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_add_input_boolean');
    {$ifend}
  end;
  
  UI_dup_input_boolean := LoadLibFunction(ADllHandle, UI_dup_input_boolean_procname);
  FuncLoadError := not assigned(UI_dup_input_boolean);
  if FuncLoadError then
  begin
    {$if not defined(UI_dup_input_boolean_allownil)}
    UI_dup_input_boolean := ERR_UI_dup_input_boolean;
    {$ifend}
    {$if declared(UI_dup_input_boolean_introduced)}
    if LibVersion < UI_dup_input_boolean_introduced then
    begin
      {$if declared(FC_UI_dup_input_boolean)}
      UI_dup_input_boolean := FC_UI_dup_input_boolean;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_dup_input_boolean_removed)}
    if UI_dup_input_boolean_removed <= LibVersion then
    begin
      {$if declared(_UI_dup_input_boolean)}
      UI_dup_input_boolean := _UI_dup_input_boolean;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_dup_input_boolean_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_dup_input_boolean');
    {$ifend}
  end;
  
  UI_add_info_string := LoadLibFunction(ADllHandle, UI_add_info_string_procname);
  FuncLoadError := not assigned(UI_add_info_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_add_info_string_allownil)}
    UI_add_info_string := ERR_UI_add_info_string;
    {$ifend}
    {$if declared(UI_add_info_string_introduced)}
    if LibVersion < UI_add_info_string_introduced then
    begin
      {$if declared(FC_UI_add_info_string)}
      UI_add_info_string := FC_UI_add_info_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_add_info_string_removed)}
    if UI_add_info_string_removed <= LibVersion then
    begin
      {$if declared(_UI_add_info_string)}
      UI_add_info_string := _UI_add_info_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_add_info_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_add_info_string');
    {$ifend}
  end;
  
  UI_dup_info_string := LoadLibFunction(ADllHandle, UI_dup_info_string_procname);
  FuncLoadError := not assigned(UI_dup_info_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_dup_info_string_allownil)}
    UI_dup_info_string := ERR_UI_dup_info_string;
    {$ifend}
    {$if declared(UI_dup_info_string_introduced)}
    if LibVersion < UI_dup_info_string_introduced then
    begin
      {$if declared(FC_UI_dup_info_string)}
      UI_dup_info_string := FC_UI_dup_info_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_dup_info_string_removed)}
    if UI_dup_info_string_removed <= LibVersion then
    begin
      {$if declared(_UI_dup_info_string)}
      UI_dup_info_string := _UI_dup_info_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_dup_info_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_dup_info_string');
    {$ifend}
  end;
  
  UI_add_error_string := LoadLibFunction(ADllHandle, UI_add_error_string_procname);
  FuncLoadError := not assigned(UI_add_error_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_add_error_string_allownil)}
    UI_add_error_string := ERR_UI_add_error_string;
    {$ifend}
    {$if declared(UI_add_error_string_introduced)}
    if LibVersion < UI_add_error_string_introduced then
    begin
      {$if declared(FC_UI_add_error_string)}
      UI_add_error_string := FC_UI_add_error_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_add_error_string_removed)}
    if UI_add_error_string_removed <= LibVersion then
    begin
      {$if declared(_UI_add_error_string)}
      UI_add_error_string := _UI_add_error_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_add_error_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_add_error_string');
    {$ifend}
  end;
  
  UI_dup_error_string := LoadLibFunction(ADllHandle, UI_dup_error_string_procname);
  FuncLoadError := not assigned(UI_dup_error_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_dup_error_string_allownil)}
    UI_dup_error_string := ERR_UI_dup_error_string;
    {$ifend}
    {$if declared(UI_dup_error_string_introduced)}
    if LibVersion < UI_dup_error_string_introduced then
    begin
      {$if declared(FC_UI_dup_error_string)}
      UI_dup_error_string := FC_UI_dup_error_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_dup_error_string_removed)}
    if UI_dup_error_string_removed <= LibVersion then
    begin
      {$if declared(_UI_dup_error_string)}
      UI_dup_error_string := _UI_dup_error_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_dup_error_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_dup_error_string');
    {$ifend}
  end;
  
  UI_construct_prompt := LoadLibFunction(ADllHandle, UI_construct_prompt_procname);
  FuncLoadError := not assigned(UI_construct_prompt);
  if FuncLoadError then
  begin
    {$if not defined(UI_construct_prompt_allownil)}
    UI_construct_prompt := ERR_UI_construct_prompt;
    {$ifend}
    {$if declared(UI_construct_prompt_introduced)}
    if LibVersion < UI_construct_prompt_introduced then
    begin
      {$if declared(FC_UI_construct_prompt)}
      UI_construct_prompt := FC_UI_construct_prompt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_construct_prompt_removed)}
    if UI_construct_prompt_removed <= LibVersion then
    begin
      {$if declared(_UI_construct_prompt)}
      UI_construct_prompt := _UI_construct_prompt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_construct_prompt_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_construct_prompt');
    {$ifend}
  end;
  
  UI_add_user_data := LoadLibFunction(ADllHandle, UI_add_user_data_procname);
  FuncLoadError := not assigned(UI_add_user_data);
  if FuncLoadError then
  begin
    {$if not defined(UI_add_user_data_allownil)}
    UI_add_user_data := ERR_UI_add_user_data;
    {$ifend}
    {$if declared(UI_add_user_data_introduced)}
    if LibVersion < UI_add_user_data_introduced then
    begin
      {$if declared(FC_UI_add_user_data)}
      UI_add_user_data := FC_UI_add_user_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_add_user_data_removed)}
    if UI_add_user_data_removed <= LibVersion then
    begin
      {$if declared(_UI_add_user_data)}
      UI_add_user_data := _UI_add_user_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_add_user_data_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_add_user_data');
    {$ifend}
  end;
  
  UI_dup_user_data := LoadLibFunction(ADllHandle, UI_dup_user_data_procname);
  FuncLoadError := not assigned(UI_dup_user_data);
  if FuncLoadError then
  begin
    {$if not defined(UI_dup_user_data_allownil)}
    UI_dup_user_data := ERR_UI_dup_user_data;
    {$ifend}
    {$if declared(UI_dup_user_data_introduced)}
    if LibVersion < UI_dup_user_data_introduced then
    begin
      {$if declared(FC_UI_dup_user_data)}
      UI_dup_user_data := FC_UI_dup_user_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_dup_user_data_removed)}
    if UI_dup_user_data_removed <= LibVersion then
    begin
      {$if declared(_UI_dup_user_data)}
      UI_dup_user_data := _UI_dup_user_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_dup_user_data_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_dup_user_data');
    {$ifend}
  end;
  
  UI_get0_user_data := LoadLibFunction(ADllHandle, UI_get0_user_data_procname);
  FuncLoadError := not assigned(UI_get0_user_data);
  if FuncLoadError then
  begin
    {$if not defined(UI_get0_user_data_allownil)}
    UI_get0_user_data := ERR_UI_get0_user_data;
    {$ifend}
    {$if declared(UI_get0_user_data_introduced)}
    if LibVersion < UI_get0_user_data_introduced then
    begin
      {$if declared(FC_UI_get0_user_data)}
      UI_get0_user_data := FC_UI_get0_user_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get0_user_data_removed)}
    if UI_get0_user_data_removed <= LibVersion then
    begin
      {$if declared(_UI_get0_user_data)}
      UI_get0_user_data := _UI_get0_user_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get0_user_data_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get0_user_data');
    {$ifend}
  end;
  
  UI_get0_result := LoadLibFunction(ADllHandle, UI_get0_result_procname);
  FuncLoadError := not assigned(UI_get0_result);
  if FuncLoadError then
  begin
    {$if not defined(UI_get0_result_allownil)}
    UI_get0_result := ERR_UI_get0_result;
    {$ifend}
    {$if declared(UI_get0_result_introduced)}
    if LibVersion < UI_get0_result_introduced then
    begin
      {$if declared(FC_UI_get0_result)}
      UI_get0_result := FC_UI_get0_result;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get0_result_removed)}
    if UI_get0_result_removed <= LibVersion then
    begin
      {$if declared(_UI_get0_result)}
      UI_get0_result := _UI_get0_result;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get0_result_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get0_result');
    {$ifend}
  end;
  
  UI_get_result_length := LoadLibFunction(ADllHandle, UI_get_result_length_procname);
  FuncLoadError := not assigned(UI_get_result_length);
  if FuncLoadError then
  begin
    {$if not defined(UI_get_result_length_allownil)}
    UI_get_result_length := ERR_UI_get_result_length;
    {$ifend}
    {$if declared(UI_get_result_length_introduced)}
    if LibVersion < UI_get_result_length_introduced then
    begin
      {$if declared(FC_UI_get_result_length)}
      UI_get_result_length := FC_UI_get_result_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get_result_length_removed)}
    if UI_get_result_length_removed <= LibVersion then
    begin
      {$if declared(_UI_get_result_length)}
      UI_get_result_length := _UI_get_result_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get_result_length_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_result_length');
    {$ifend}
  end;
  
  UI_process := LoadLibFunction(ADllHandle, UI_process_procname);
  FuncLoadError := not assigned(UI_process);
  if FuncLoadError then
  begin
    {$if not defined(UI_process_allownil)}
    UI_process := ERR_UI_process;
    {$ifend}
    {$if declared(UI_process_introduced)}
    if LibVersion < UI_process_introduced then
    begin
      {$if declared(FC_UI_process)}
      UI_process := FC_UI_process;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_process_removed)}
    if UI_process_removed <= LibVersion then
    begin
      {$if declared(_UI_process)}
      UI_process := _UI_process;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_process_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_process');
    {$ifend}
  end;
  
  UI_ctrl := LoadLibFunction(ADllHandle, UI_ctrl_procname);
  FuncLoadError := not assigned(UI_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(UI_ctrl_allownil)}
    UI_ctrl := ERR_UI_ctrl;
    {$ifend}
    {$if declared(UI_ctrl_introduced)}
    if LibVersion < UI_ctrl_introduced then
    begin
      {$if declared(FC_UI_ctrl)}
      UI_ctrl := FC_UI_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_ctrl_removed)}
    if UI_ctrl_removed <= LibVersion then
    begin
      {$if declared(_UI_ctrl)}
      UI_ctrl := _UI_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_ctrl');
    {$ifend}
  end;
  
  UI_set_ex_data := LoadLibFunction(ADllHandle, UI_set_ex_data_procname);
  FuncLoadError := not assigned(UI_set_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(UI_set_ex_data_allownil)}
    UI_set_ex_data := ERR_UI_set_ex_data;
    {$ifend}
    {$if declared(UI_set_ex_data_introduced)}
    if LibVersion < UI_set_ex_data_introduced then
    begin
      {$if declared(FC_UI_set_ex_data)}
      UI_set_ex_data := FC_UI_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_set_ex_data_removed)}
    if UI_set_ex_data_removed <= LibVersion then
    begin
      {$if declared(_UI_set_ex_data)}
      UI_set_ex_data := _UI_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_set_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_set_ex_data');
    {$ifend}
  end;
  
  UI_get_ex_data := LoadLibFunction(ADllHandle, UI_get_ex_data_procname);
  FuncLoadError := not assigned(UI_get_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(UI_get_ex_data_allownil)}
    UI_get_ex_data := ERR_UI_get_ex_data;
    {$ifend}
    {$if declared(UI_get_ex_data_introduced)}
    if LibVersion < UI_get_ex_data_introduced then
    begin
      {$if declared(FC_UI_get_ex_data)}
      UI_get_ex_data := FC_UI_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get_ex_data_removed)}
    if UI_get_ex_data_removed <= LibVersion then
    begin
      {$if declared(_UI_get_ex_data)}
      UI_get_ex_data := _UI_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_ex_data');
    {$ifend}
  end;
  
  UI_set_default_method := LoadLibFunction(ADllHandle, UI_set_default_method_procname);
  FuncLoadError := not assigned(UI_set_default_method);
  if FuncLoadError then
  begin
    {$if not defined(UI_set_default_method_allownil)}
    UI_set_default_method := ERR_UI_set_default_method;
    {$ifend}
    {$if declared(UI_set_default_method_introduced)}
    if LibVersion < UI_set_default_method_introduced then
    begin
      {$if declared(FC_UI_set_default_method)}
      UI_set_default_method := FC_UI_set_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_set_default_method_removed)}
    if UI_set_default_method_removed <= LibVersion then
    begin
      {$if declared(_UI_set_default_method)}
      UI_set_default_method := _UI_set_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_set_default_method_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_set_default_method');
    {$ifend}
  end;
  
  UI_get_default_method := LoadLibFunction(ADllHandle, UI_get_default_method_procname);
  FuncLoadError := not assigned(UI_get_default_method);
  if FuncLoadError then
  begin
    {$if not defined(UI_get_default_method_allownil)}
    UI_get_default_method := ERR_UI_get_default_method;
    {$ifend}
    {$if declared(UI_get_default_method_introduced)}
    if LibVersion < UI_get_default_method_introduced then
    begin
      {$if declared(FC_UI_get_default_method)}
      UI_get_default_method := FC_UI_get_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get_default_method_removed)}
    if UI_get_default_method_removed <= LibVersion then
    begin
      {$if declared(_UI_get_default_method)}
      UI_get_default_method := _UI_get_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get_default_method_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_default_method');
    {$ifend}
  end;
  
  UI_get_method := LoadLibFunction(ADllHandle, UI_get_method_procname);
  FuncLoadError := not assigned(UI_get_method);
  if FuncLoadError then
  begin
    {$if not defined(UI_get_method_allownil)}
    UI_get_method := ERR_UI_get_method;
    {$ifend}
    {$if declared(UI_get_method_introduced)}
    if LibVersion < UI_get_method_introduced then
    begin
      {$if declared(FC_UI_get_method)}
      UI_get_method := FC_UI_get_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get_method_removed)}
    if UI_get_method_removed <= LibVersion then
    begin
      {$if declared(_UI_get_method)}
      UI_get_method := _UI_get_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get_method_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_method');
    {$ifend}
  end;
  
  UI_set_method := LoadLibFunction(ADllHandle, UI_set_method_procname);
  FuncLoadError := not assigned(UI_set_method);
  if FuncLoadError then
  begin
    {$if not defined(UI_set_method_allownil)}
    UI_set_method := ERR_UI_set_method;
    {$ifend}
    {$if declared(UI_set_method_introduced)}
    if LibVersion < UI_set_method_introduced then
    begin
      {$if declared(FC_UI_set_method)}
      UI_set_method := FC_UI_set_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_set_method_removed)}
    if UI_set_method_removed <= LibVersion then
    begin
      {$if declared(_UI_set_method)}
      UI_set_method := _UI_set_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_set_method_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_set_method');
    {$ifend}
  end;
  
  UI_OpenSSL := LoadLibFunction(ADllHandle, UI_OpenSSL_procname);
  FuncLoadError := not assigned(UI_OpenSSL);
  if FuncLoadError then
  begin
    {$if not defined(UI_OpenSSL_allownil)}
    UI_OpenSSL := ERR_UI_OpenSSL;
    {$ifend}
    {$if declared(UI_OpenSSL_introduced)}
    if LibVersion < UI_OpenSSL_introduced then
    begin
      {$if declared(FC_UI_OpenSSL)}
      UI_OpenSSL := FC_UI_OpenSSL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_OpenSSL_removed)}
    if UI_OpenSSL_removed <= LibVersion then
    begin
      {$if declared(_UI_OpenSSL)}
      UI_OpenSSL := _UI_OpenSSL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_OpenSSL_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_OpenSSL');
    {$ifend}
  end;
  
  UI_null := LoadLibFunction(ADllHandle, UI_null_procname);
  FuncLoadError := not assigned(UI_null);
  if FuncLoadError then
  begin
    {$if not defined(UI_null_allownil)}
    UI_null := ERR_UI_null;
    {$ifend}
    {$if declared(UI_null_introduced)}
    if LibVersion < UI_null_introduced then
    begin
      {$if declared(FC_UI_null)}
      UI_null := FC_UI_null;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_null_removed)}
    if UI_null_removed <= LibVersion then
    begin
      {$if declared(_UI_null)}
      UI_null := _UI_null;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_null_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_null');
    {$ifend}
  end;
  
  UI_create_method := LoadLibFunction(ADllHandle, UI_create_method_procname);
  FuncLoadError := not assigned(UI_create_method);
  if FuncLoadError then
  begin
    {$if not defined(UI_create_method_allownil)}
    UI_create_method := ERR_UI_create_method;
    {$ifend}
    {$if declared(UI_create_method_introduced)}
    if LibVersion < UI_create_method_introduced then
    begin
      {$if declared(FC_UI_create_method)}
      UI_create_method := FC_UI_create_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_create_method_removed)}
    if UI_create_method_removed <= LibVersion then
    begin
      {$if declared(_UI_create_method)}
      UI_create_method := _UI_create_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_create_method_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_create_method');
    {$ifend}
  end;
  
  UI_destroy_method := LoadLibFunction(ADllHandle, UI_destroy_method_procname);
  FuncLoadError := not assigned(UI_destroy_method);
  if FuncLoadError then
  begin
    {$if not defined(UI_destroy_method_allownil)}
    UI_destroy_method := ERR_UI_destroy_method;
    {$ifend}
    {$if declared(UI_destroy_method_introduced)}
    if LibVersion < UI_destroy_method_introduced then
    begin
      {$if declared(FC_UI_destroy_method)}
      UI_destroy_method := FC_UI_destroy_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_destroy_method_removed)}
    if UI_destroy_method_removed <= LibVersion then
    begin
      {$if declared(_UI_destroy_method)}
      UI_destroy_method := _UI_destroy_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_destroy_method_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_destroy_method');
    {$ifend}
  end;
  
  UI_method_set_opener := LoadLibFunction(ADllHandle, UI_method_set_opener_procname);
  FuncLoadError := not assigned(UI_method_set_opener);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_set_opener_allownil)}
    UI_method_set_opener := ERR_UI_method_set_opener;
    {$ifend}
    {$if declared(UI_method_set_opener_introduced)}
    if LibVersion < UI_method_set_opener_introduced then
    begin
      {$if declared(FC_UI_method_set_opener)}
      UI_method_set_opener := FC_UI_method_set_opener;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_set_opener_removed)}
    if UI_method_set_opener_removed <= LibVersion then
    begin
      {$if declared(_UI_method_set_opener)}
      UI_method_set_opener := _UI_method_set_opener;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_set_opener_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_set_opener');
    {$ifend}
  end;
  
  UI_method_set_writer := LoadLibFunction(ADllHandle, UI_method_set_writer_procname);
  FuncLoadError := not assigned(UI_method_set_writer);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_set_writer_allownil)}
    UI_method_set_writer := ERR_UI_method_set_writer;
    {$ifend}
    {$if declared(UI_method_set_writer_introduced)}
    if LibVersion < UI_method_set_writer_introduced then
    begin
      {$if declared(FC_UI_method_set_writer)}
      UI_method_set_writer := FC_UI_method_set_writer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_set_writer_removed)}
    if UI_method_set_writer_removed <= LibVersion then
    begin
      {$if declared(_UI_method_set_writer)}
      UI_method_set_writer := _UI_method_set_writer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_set_writer_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_set_writer');
    {$ifend}
  end;
  
  UI_method_set_flusher := LoadLibFunction(ADllHandle, UI_method_set_flusher_procname);
  FuncLoadError := not assigned(UI_method_set_flusher);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_set_flusher_allownil)}
    UI_method_set_flusher := ERR_UI_method_set_flusher;
    {$ifend}
    {$if declared(UI_method_set_flusher_introduced)}
    if LibVersion < UI_method_set_flusher_introduced then
    begin
      {$if declared(FC_UI_method_set_flusher)}
      UI_method_set_flusher := FC_UI_method_set_flusher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_set_flusher_removed)}
    if UI_method_set_flusher_removed <= LibVersion then
    begin
      {$if declared(_UI_method_set_flusher)}
      UI_method_set_flusher := _UI_method_set_flusher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_set_flusher_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_set_flusher');
    {$ifend}
  end;
  
  UI_method_set_reader := LoadLibFunction(ADllHandle, UI_method_set_reader_procname);
  FuncLoadError := not assigned(UI_method_set_reader);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_set_reader_allownil)}
    UI_method_set_reader := ERR_UI_method_set_reader;
    {$ifend}
    {$if declared(UI_method_set_reader_introduced)}
    if LibVersion < UI_method_set_reader_introduced then
    begin
      {$if declared(FC_UI_method_set_reader)}
      UI_method_set_reader := FC_UI_method_set_reader;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_set_reader_removed)}
    if UI_method_set_reader_removed <= LibVersion then
    begin
      {$if declared(_UI_method_set_reader)}
      UI_method_set_reader := _UI_method_set_reader;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_set_reader_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_set_reader');
    {$ifend}
  end;
  
  UI_method_set_closer := LoadLibFunction(ADllHandle, UI_method_set_closer_procname);
  FuncLoadError := not assigned(UI_method_set_closer);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_set_closer_allownil)}
    UI_method_set_closer := ERR_UI_method_set_closer;
    {$ifend}
    {$if declared(UI_method_set_closer_introduced)}
    if LibVersion < UI_method_set_closer_introduced then
    begin
      {$if declared(FC_UI_method_set_closer)}
      UI_method_set_closer := FC_UI_method_set_closer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_set_closer_removed)}
    if UI_method_set_closer_removed <= LibVersion then
    begin
      {$if declared(_UI_method_set_closer)}
      UI_method_set_closer := _UI_method_set_closer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_set_closer_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_set_closer');
    {$ifend}
  end;
  
  UI_method_set_data_duplicator := LoadLibFunction(ADllHandle, UI_method_set_data_duplicator_procname);
  FuncLoadError := not assigned(UI_method_set_data_duplicator);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_set_data_duplicator_allownil)}
    UI_method_set_data_duplicator := ERR_UI_method_set_data_duplicator;
    {$ifend}
    {$if declared(UI_method_set_data_duplicator_introduced)}
    if LibVersion < UI_method_set_data_duplicator_introduced then
    begin
      {$if declared(FC_UI_method_set_data_duplicator)}
      UI_method_set_data_duplicator := FC_UI_method_set_data_duplicator;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_set_data_duplicator_removed)}
    if UI_method_set_data_duplicator_removed <= LibVersion then
    begin
      {$if declared(_UI_method_set_data_duplicator)}
      UI_method_set_data_duplicator := _UI_method_set_data_duplicator;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_set_data_duplicator_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_set_data_duplicator');
    {$ifend}
  end;
  
  UI_method_set_prompt_constructor := LoadLibFunction(ADllHandle, UI_method_set_prompt_constructor_procname);
  FuncLoadError := not assigned(UI_method_set_prompt_constructor);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_set_prompt_constructor_allownil)}
    UI_method_set_prompt_constructor := ERR_UI_method_set_prompt_constructor;
    {$ifend}
    {$if declared(UI_method_set_prompt_constructor_introduced)}
    if LibVersion < UI_method_set_prompt_constructor_introduced then
    begin
      {$if declared(FC_UI_method_set_prompt_constructor)}
      UI_method_set_prompt_constructor := FC_UI_method_set_prompt_constructor;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_set_prompt_constructor_removed)}
    if UI_method_set_prompt_constructor_removed <= LibVersion then
    begin
      {$if declared(_UI_method_set_prompt_constructor)}
      UI_method_set_prompt_constructor := _UI_method_set_prompt_constructor;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_set_prompt_constructor_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_set_prompt_constructor');
    {$ifend}
  end;
  
  UI_method_set_ex_data := LoadLibFunction(ADllHandle, UI_method_set_ex_data_procname);
  FuncLoadError := not assigned(UI_method_set_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_set_ex_data_allownil)}
    UI_method_set_ex_data := ERR_UI_method_set_ex_data;
    {$ifend}
    {$if declared(UI_method_set_ex_data_introduced)}
    if LibVersion < UI_method_set_ex_data_introduced then
    begin
      {$if declared(FC_UI_method_set_ex_data)}
      UI_method_set_ex_data := FC_UI_method_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_set_ex_data_removed)}
    if UI_method_set_ex_data_removed <= LibVersion then
    begin
      {$if declared(_UI_method_set_ex_data)}
      UI_method_set_ex_data := _UI_method_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_set_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_set_ex_data');
    {$ifend}
  end;
  
  UI_method_get_opener := LoadLibFunction(ADllHandle, UI_method_get_opener_procname);
  FuncLoadError := not assigned(UI_method_get_opener);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_get_opener_allownil)}
    UI_method_get_opener := ERR_UI_method_get_opener;
    {$ifend}
    {$if declared(UI_method_get_opener_introduced)}
    if LibVersion < UI_method_get_opener_introduced then
    begin
      {$if declared(FC_UI_method_get_opener)}
      UI_method_get_opener := FC_UI_method_get_opener;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_get_opener_removed)}
    if UI_method_get_opener_removed <= LibVersion then
    begin
      {$if declared(_UI_method_get_opener)}
      UI_method_get_opener := _UI_method_get_opener;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_get_opener_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_opener');
    {$ifend}
  end;
  
  UI_method_get_writer := LoadLibFunction(ADllHandle, UI_method_get_writer_procname);
  FuncLoadError := not assigned(UI_method_get_writer);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_get_writer_allownil)}
    UI_method_get_writer := ERR_UI_method_get_writer;
    {$ifend}
    {$if declared(UI_method_get_writer_introduced)}
    if LibVersion < UI_method_get_writer_introduced then
    begin
      {$if declared(FC_UI_method_get_writer)}
      UI_method_get_writer := FC_UI_method_get_writer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_get_writer_removed)}
    if UI_method_get_writer_removed <= LibVersion then
    begin
      {$if declared(_UI_method_get_writer)}
      UI_method_get_writer := _UI_method_get_writer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_get_writer_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_writer');
    {$ifend}
  end;
  
  UI_method_get_flusher := LoadLibFunction(ADllHandle, UI_method_get_flusher_procname);
  FuncLoadError := not assigned(UI_method_get_flusher);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_get_flusher_allownil)}
    UI_method_get_flusher := ERR_UI_method_get_flusher;
    {$ifend}
    {$if declared(UI_method_get_flusher_introduced)}
    if LibVersion < UI_method_get_flusher_introduced then
    begin
      {$if declared(FC_UI_method_get_flusher)}
      UI_method_get_flusher := FC_UI_method_get_flusher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_get_flusher_removed)}
    if UI_method_get_flusher_removed <= LibVersion then
    begin
      {$if declared(_UI_method_get_flusher)}
      UI_method_get_flusher := _UI_method_get_flusher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_get_flusher_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_flusher');
    {$ifend}
  end;
  
  UI_method_get_reader := LoadLibFunction(ADllHandle, UI_method_get_reader_procname);
  FuncLoadError := not assigned(UI_method_get_reader);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_get_reader_allownil)}
    UI_method_get_reader := ERR_UI_method_get_reader;
    {$ifend}
    {$if declared(UI_method_get_reader_introduced)}
    if LibVersion < UI_method_get_reader_introduced then
    begin
      {$if declared(FC_UI_method_get_reader)}
      UI_method_get_reader := FC_UI_method_get_reader;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_get_reader_removed)}
    if UI_method_get_reader_removed <= LibVersion then
    begin
      {$if declared(_UI_method_get_reader)}
      UI_method_get_reader := _UI_method_get_reader;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_get_reader_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_reader');
    {$ifend}
  end;
  
  UI_method_get_closer := LoadLibFunction(ADllHandle, UI_method_get_closer_procname);
  FuncLoadError := not assigned(UI_method_get_closer);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_get_closer_allownil)}
    UI_method_get_closer := ERR_UI_method_get_closer;
    {$ifend}
    {$if declared(UI_method_get_closer_introduced)}
    if LibVersion < UI_method_get_closer_introduced then
    begin
      {$if declared(FC_UI_method_get_closer)}
      UI_method_get_closer := FC_UI_method_get_closer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_get_closer_removed)}
    if UI_method_get_closer_removed <= LibVersion then
    begin
      {$if declared(_UI_method_get_closer)}
      UI_method_get_closer := _UI_method_get_closer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_get_closer_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_closer');
    {$ifend}
  end;
  
  UI_method_get_prompt_constructor := LoadLibFunction(ADllHandle, UI_method_get_prompt_constructor_procname);
  FuncLoadError := not assigned(UI_method_get_prompt_constructor);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_get_prompt_constructor_allownil)}
    UI_method_get_prompt_constructor := ERR_UI_method_get_prompt_constructor;
    {$ifend}
    {$if declared(UI_method_get_prompt_constructor_introduced)}
    if LibVersion < UI_method_get_prompt_constructor_introduced then
    begin
      {$if declared(FC_UI_method_get_prompt_constructor)}
      UI_method_get_prompt_constructor := FC_UI_method_get_prompt_constructor;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_get_prompt_constructor_removed)}
    if UI_method_get_prompt_constructor_removed <= LibVersion then
    begin
      {$if declared(_UI_method_get_prompt_constructor)}
      UI_method_get_prompt_constructor := _UI_method_get_prompt_constructor;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_get_prompt_constructor_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_prompt_constructor');
    {$ifend}
  end;
  
  UI_method_get_data_duplicator := LoadLibFunction(ADllHandle, UI_method_get_data_duplicator_procname);
  FuncLoadError := not assigned(UI_method_get_data_duplicator);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_get_data_duplicator_allownil)}
    UI_method_get_data_duplicator := ERR_UI_method_get_data_duplicator;
    {$ifend}
    {$if declared(UI_method_get_data_duplicator_introduced)}
    if LibVersion < UI_method_get_data_duplicator_introduced then
    begin
      {$if declared(FC_UI_method_get_data_duplicator)}
      UI_method_get_data_duplicator := FC_UI_method_get_data_duplicator;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_get_data_duplicator_removed)}
    if UI_method_get_data_duplicator_removed <= LibVersion then
    begin
      {$if declared(_UI_method_get_data_duplicator)}
      UI_method_get_data_duplicator := _UI_method_get_data_duplicator;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_get_data_duplicator_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_data_duplicator');
    {$ifend}
  end;
  
  UI_method_get_data_destructor := LoadLibFunction(ADllHandle, UI_method_get_data_destructor_procname);
  FuncLoadError := not assigned(UI_method_get_data_destructor);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_get_data_destructor_allownil)}
    UI_method_get_data_destructor := ERR_UI_method_get_data_destructor;
    {$ifend}
    {$if declared(UI_method_get_data_destructor_introduced)}
    if LibVersion < UI_method_get_data_destructor_introduced then
    begin
      {$if declared(FC_UI_method_get_data_destructor)}
      UI_method_get_data_destructor := FC_UI_method_get_data_destructor;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_get_data_destructor_removed)}
    if UI_method_get_data_destructor_removed <= LibVersion then
    begin
      {$if declared(_UI_method_get_data_destructor)}
      UI_method_get_data_destructor := _UI_method_get_data_destructor;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_get_data_destructor_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_data_destructor');
    {$ifend}
  end;
  
  UI_method_get_ex_data := LoadLibFunction(ADllHandle, UI_method_get_ex_data_procname);
  FuncLoadError := not assigned(UI_method_get_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(UI_method_get_ex_data_allownil)}
    UI_method_get_ex_data := ERR_UI_method_get_ex_data;
    {$ifend}
    {$if declared(UI_method_get_ex_data_introduced)}
    if LibVersion < UI_method_get_ex_data_introduced then
    begin
      {$if declared(FC_UI_method_get_ex_data)}
      UI_method_get_ex_data := FC_UI_method_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_method_get_ex_data_removed)}
    if UI_method_get_ex_data_removed <= LibVersion then
    begin
      {$if declared(_UI_method_get_ex_data)}
      UI_method_get_ex_data := _UI_method_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_method_get_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_method_get_ex_data');
    {$ifend}
  end;
  
  UI_get_string_type := LoadLibFunction(ADllHandle, UI_get_string_type_procname);
  FuncLoadError := not assigned(UI_get_string_type);
  if FuncLoadError then
  begin
    {$if not defined(UI_get_string_type_allownil)}
    UI_get_string_type := ERR_UI_get_string_type;
    {$ifend}
    {$if declared(UI_get_string_type_introduced)}
    if LibVersion < UI_get_string_type_introduced then
    begin
      {$if declared(FC_UI_get_string_type)}
      UI_get_string_type := FC_UI_get_string_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get_string_type_removed)}
    if UI_get_string_type_removed <= LibVersion then
    begin
      {$if declared(_UI_get_string_type)}
      UI_get_string_type := _UI_get_string_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get_string_type_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_string_type');
    {$ifend}
  end;
  
  UI_get_input_flags := LoadLibFunction(ADllHandle, UI_get_input_flags_procname);
  FuncLoadError := not assigned(UI_get_input_flags);
  if FuncLoadError then
  begin
    {$if not defined(UI_get_input_flags_allownil)}
    UI_get_input_flags := ERR_UI_get_input_flags;
    {$ifend}
    {$if declared(UI_get_input_flags_introduced)}
    if LibVersion < UI_get_input_flags_introduced then
    begin
      {$if declared(FC_UI_get_input_flags)}
      UI_get_input_flags := FC_UI_get_input_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get_input_flags_removed)}
    if UI_get_input_flags_removed <= LibVersion then
    begin
      {$if declared(_UI_get_input_flags)}
      UI_get_input_flags := _UI_get_input_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get_input_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_input_flags');
    {$ifend}
  end;
  
  UI_get0_output_string := LoadLibFunction(ADllHandle, UI_get0_output_string_procname);
  FuncLoadError := not assigned(UI_get0_output_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_get0_output_string_allownil)}
    UI_get0_output_string := ERR_UI_get0_output_string;
    {$ifend}
    {$if declared(UI_get0_output_string_introduced)}
    if LibVersion < UI_get0_output_string_introduced then
    begin
      {$if declared(FC_UI_get0_output_string)}
      UI_get0_output_string := FC_UI_get0_output_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get0_output_string_removed)}
    if UI_get0_output_string_removed <= LibVersion then
    begin
      {$if declared(_UI_get0_output_string)}
      UI_get0_output_string := _UI_get0_output_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get0_output_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get0_output_string');
    {$ifend}
  end;
  
  UI_get0_action_string := LoadLibFunction(ADllHandle, UI_get0_action_string_procname);
  FuncLoadError := not assigned(UI_get0_action_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_get0_action_string_allownil)}
    UI_get0_action_string := ERR_UI_get0_action_string;
    {$ifend}
    {$if declared(UI_get0_action_string_introduced)}
    if LibVersion < UI_get0_action_string_introduced then
    begin
      {$if declared(FC_UI_get0_action_string)}
      UI_get0_action_string := FC_UI_get0_action_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get0_action_string_removed)}
    if UI_get0_action_string_removed <= LibVersion then
    begin
      {$if declared(_UI_get0_action_string)}
      UI_get0_action_string := _UI_get0_action_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get0_action_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get0_action_string');
    {$ifend}
  end;
  
  UI_get0_result_string := LoadLibFunction(ADllHandle, UI_get0_result_string_procname);
  FuncLoadError := not assigned(UI_get0_result_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_get0_result_string_allownil)}
    UI_get0_result_string := ERR_UI_get0_result_string;
    {$ifend}
    {$if declared(UI_get0_result_string_introduced)}
    if LibVersion < UI_get0_result_string_introduced then
    begin
      {$if declared(FC_UI_get0_result_string)}
      UI_get0_result_string := FC_UI_get0_result_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get0_result_string_removed)}
    if UI_get0_result_string_removed <= LibVersion then
    begin
      {$if declared(_UI_get0_result_string)}
      UI_get0_result_string := _UI_get0_result_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get0_result_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get0_result_string');
    {$ifend}
  end;
  
  UI_get_result_string_length := LoadLibFunction(ADllHandle, UI_get_result_string_length_procname);
  FuncLoadError := not assigned(UI_get_result_string_length);
  if FuncLoadError then
  begin
    {$if not defined(UI_get_result_string_length_allownil)}
    UI_get_result_string_length := ERR_UI_get_result_string_length;
    {$ifend}
    {$if declared(UI_get_result_string_length_introduced)}
    if LibVersion < UI_get_result_string_length_introduced then
    begin
      {$if declared(FC_UI_get_result_string_length)}
      UI_get_result_string_length := FC_UI_get_result_string_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get_result_string_length_removed)}
    if UI_get_result_string_length_removed <= LibVersion then
    begin
      {$if declared(_UI_get_result_string_length)}
      UI_get_result_string_length := _UI_get_result_string_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get_result_string_length_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_result_string_length');
    {$ifend}
  end;
  
  UI_get0_test_string := LoadLibFunction(ADllHandle, UI_get0_test_string_procname);
  FuncLoadError := not assigned(UI_get0_test_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_get0_test_string_allownil)}
    UI_get0_test_string := ERR_UI_get0_test_string;
    {$ifend}
    {$if declared(UI_get0_test_string_introduced)}
    if LibVersion < UI_get0_test_string_introduced then
    begin
      {$if declared(FC_UI_get0_test_string)}
      UI_get0_test_string := FC_UI_get0_test_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get0_test_string_removed)}
    if UI_get0_test_string_removed <= LibVersion then
    begin
      {$if declared(_UI_get0_test_string)}
      UI_get0_test_string := _UI_get0_test_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get0_test_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get0_test_string');
    {$ifend}
  end;
  
  UI_get_result_minsize := LoadLibFunction(ADllHandle, UI_get_result_minsize_procname);
  FuncLoadError := not assigned(UI_get_result_minsize);
  if FuncLoadError then
  begin
    {$if not defined(UI_get_result_minsize_allownil)}
    UI_get_result_minsize := ERR_UI_get_result_minsize;
    {$ifend}
    {$if declared(UI_get_result_minsize_introduced)}
    if LibVersion < UI_get_result_minsize_introduced then
    begin
      {$if declared(FC_UI_get_result_minsize)}
      UI_get_result_minsize := FC_UI_get_result_minsize;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get_result_minsize_removed)}
    if UI_get_result_minsize_removed <= LibVersion then
    begin
      {$if declared(_UI_get_result_minsize)}
      UI_get_result_minsize := _UI_get_result_minsize;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get_result_minsize_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_result_minsize');
    {$ifend}
  end;
  
  UI_get_result_maxsize := LoadLibFunction(ADllHandle, UI_get_result_maxsize_procname);
  FuncLoadError := not assigned(UI_get_result_maxsize);
  if FuncLoadError then
  begin
    {$if not defined(UI_get_result_maxsize_allownil)}
    UI_get_result_maxsize := ERR_UI_get_result_maxsize;
    {$ifend}
    {$if declared(UI_get_result_maxsize_introduced)}
    if LibVersion < UI_get_result_maxsize_introduced then
    begin
      {$if declared(FC_UI_get_result_maxsize)}
      UI_get_result_maxsize := FC_UI_get_result_maxsize;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_get_result_maxsize_removed)}
    if UI_get_result_maxsize_removed <= LibVersion then
    begin
      {$if declared(_UI_get_result_maxsize)}
      UI_get_result_maxsize := _UI_get_result_maxsize;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_get_result_maxsize_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_get_result_maxsize');
    {$ifend}
  end;
  
  UI_set_result := LoadLibFunction(ADllHandle, UI_set_result_procname);
  FuncLoadError := not assigned(UI_set_result);
  if FuncLoadError then
  begin
    {$if not defined(UI_set_result_allownil)}
    UI_set_result := ERR_UI_set_result;
    {$ifend}
    {$if declared(UI_set_result_introduced)}
    if LibVersion < UI_set_result_introduced then
    begin
      {$if declared(FC_UI_set_result)}
      UI_set_result := FC_UI_set_result;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_set_result_removed)}
    if UI_set_result_removed <= LibVersion then
    begin
      {$if declared(_UI_set_result)}
      UI_set_result := _UI_set_result;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_set_result_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_set_result');
    {$ifend}
  end;
  
  UI_set_result_ex := LoadLibFunction(ADllHandle, UI_set_result_ex_procname);
  FuncLoadError := not assigned(UI_set_result_ex);
  if FuncLoadError then
  begin
    {$if not defined(UI_set_result_ex_allownil)}
    UI_set_result_ex := ERR_UI_set_result_ex;
    {$ifend}
    {$if declared(UI_set_result_ex_introduced)}
    if LibVersion < UI_set_result_ex_introduced then
    begin
      {$if declared(FC_UI_set_result_ex)}
      UI_set_result_ex := FC_UI_set_result_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_set_result_ex_removed)}
    if UI_set_result_ex_removed <= LibVersion then
    begin
      {$if declared(_UI_set_result_ex)}
      UI_set_result_ex := _UI_set_result_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_set_result_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_set_result_ex');
    {$ifend}
  end;
  
  UI_UTIL_read_pw_string := LoadLibFunction(ADllHandle, UI_UTIL_read_pw_string_procname);
  FuncLoadError := not assigned(UI_UTIL_read_pw_string);
  if FuncLoadError then
  begin
    {$if not defined(UI_UTIL_read_pw_string_allownil)}
    UI_UTIL_read_pw_string := ERR_UI_UTIL_read_pw_string;
    {$ifend}
    {$if declared(UI_UTIL_read_pw_string_introduced)}
    if LibVersion < UI_UTIL_read_pw_string_introduced then
    begin
      {$if declared(FC_UI_UTIL_read_pw_string)}
      UI_UTIL_read_pw_string := FC_UI_UTIL_read_pw_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_UTIL_read_pw_string_removed)}
    if UI_UTIL_read_pw_string_removed <= LibVersion then
    begin
      {$if declared(_UI_UTIL_read_pw_string)}
      UI_UTIL_read_pw_string := _UI_UTIL_read_pw_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_UTIL_read_pw_string_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_UTIL_read_pw_string');
    {$ifend}
  end;
  
  UI_UTIL_read_pw := LoadLibFunction(ADllHandle, UI_UTIL_read_pw_procname);
  FuncLoadError := not assigned(UI_UTIL_read_pw);
  if FuncLoadError then
  begin
    {$if not defined(UI_UTIL_read_pw_allownil)}
    UI_UTIL_read_pw := ERR_UI_UTIL_read_pw;
    {$ifend}
    {$if declared(UI_UTIL_read_pw_introduced)}
    if LibVersion < UI_UTIL_read_pw_introduced then
    begin
      {$if declared(FC_UI_UTIL_read_pw)}
      UI_UTIL_read_pw := FC_UI_UTIL_read_pw;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_UTIL_read_pw_removed)}
    if UI_UTIL_read_pw_removed <= LibVersion then
    begin
      {$if declared(_UI_UTIL_read_pw)}
      UI_UTIL_read_pw := _UI_UTIL_read_pw;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_UTIL_read_pw_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_UTIL_read_pw');
    {$ifend}
  end;
  
  UI_UTIL_wrap_read_pem_callback := LoadLibFunction(ADllHandle, UI_UTIL_wrap_read_pem_callback_procname);
  FuncLoadError := not assigned(UI_UTIL_wrap_read_pem_callback);
  if FuncLoadError then
  begin
    {$if not defined(UI_UTIL_wrap_read_pem_callback_allownil)}
    UI_UTIL_wrap_read_pem_callback := ERR_UI_UTIL_wrap_read_pem_callback;
    {$ifend}
    {$if declared(UI_UTIL_wrap_read_pem_callback_introduced)}
    if LibVersion < UI_UTIL_wrap_read_pem_callback_introduced then
    begin
      {$if declared(FC_UI_UTIL_wrap_read_pem_callback)}
      UI_UTIL_wrap_read_pem_callback := FC_UI_UTIL_wrap_read_pem_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UI_UTIL_wrap_read_pem_callback_removed)}
    if UI_UTIL_wrap_read_pem_callback_removed <= LibVersion then
    begin
      {$if declared(_UI_UTIL_wrap_read_pem_callback)}
      UI_UTIL_wrap_read_pem_callback := _UI_UTIL_wrap_read_pem_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UI_UTIL_wrap_read_pem_callback_allownil)}
    if FuncLoadError then
      AFailed.Add('UI_UTIL_wrap_read_pem_callback');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  UI_new := nil;
  UI_new_method := nil;
  UI_free := nil;
  UI_add_input_string := nil;
  UI_dup_input_string := nil;
  UI_add_verify_string := nil;
  UI_dup_verify_string := nil;
  UI_add_input_boolean := nil;
  UI_dup_input_boolean := nil;
  UI_add_info_string := nil;
  UI_dup_info_string := nil;
  UI_add_error_string := nil;
  UI_dup_error_string := nil;
  UI_construct_prompt := nil;
  UI_add_user_data := nil;
  UI_dup_user_data := nil;
  UI_get0_user_data := nil;
  UI_get0_result := nil;
  UI_get_result_length := nil;
  UI_process := nil;
  UI_ctrl := nil;
  UI_set_ex_data := nil;
  UI_get_ex_data := nil;
  UI_set_default_method := nil;
  UI_get_default_method := nil;
  UI_get_method := nil;
  UI_set_method := nil;
  UI_OpenSSL := nil;
  UI_null := nil;
  UI_create_method := nil;
  UI_destroy_method := nil;
  UI_method_set_opener := nil;
  UI_method_set_writer := nil;
  UI_method_set_flusher := nil;
  UI_method_set_reader := nil;
  UI_method_set_closer := nil;
  UI_method_set_data_duplicator := nil;
  UI_method_set_prompt_constructor := nil;
  UI_method_set_ex_data := nil;
  UI_method_get_opener := nil;
  UI_method_get_writer := nil;
  UI_method_get_flusher := nil;
  UI_method_get_reader := nil;
  UI_method_get_closer := nil;
  UI_method_get_prompt_constructor := nil;
  UI_method_get_data_duplicator := nil;
  UI_method_get_data_destructor := nil;
  UI_method_get_ex_data := nil;
  UI_get_string_type := nil;
  UI_get_input_flags := nil;
  UI_get0_output_string := nil;
  UI_get0_action_string := nil;
  UI_get0_result_string := nil;
  UI_get_result_string_length := nil;
  UI_get0_test_string := nil;
  UI_get_result_minsize := nil;
  UI_get_result_maxsize := nil;
  UI_set_result := nil;
  UI_set_result_ex := nil;
  UI_UTIL_read_pw_string := nil;
  UI_UTIL_read_pw := nil;
  UI_UTIL_wrap_read_pem_callback := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.