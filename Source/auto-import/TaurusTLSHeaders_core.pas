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

unit TaurusTLSHeaders_core;

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
  Possl_core_handle_st = ^Tossl_core_handle_st;
  Tossl_core_handle_st = record end;
  {$EXTERNALSYM Possl_core_handle_st}

  POSSL_CORE_HANDLE = ^TOSSL_CORE_HANDLE;
  TOSSL_CORE_HANDLE = Tossl_core_handle_st;
  {$EXTERNALSYM POSSL_CORE_HANDLE}

  Popenssl_core_ctx_st = ^Topenssl_core_ctx_st;
  Topenssl_core_ctx_st = record end;
  {$EXTERNALSYM Popenssl_core_ctx_st}

  POPENSSL_CORE_CTX = ^TOPENSSL_CORE_CTX;
  TOPENSSL_CORE_CTX = Topenssl_core_ctx_st;
  {$EXTERNALSYM POPENSSL_CORE_CTX}

  Possl_core_bio_st = ^Tossl_core_bio_st;
  Tossl_core_bio_st = record end;
  {$EXTERNALSYM Possl_core_bio_st}

  POSSL_CORE_BIO = ^TOSSL_CORE_BIO;
  TOSSL_CORE_BIO = Tossl_core_bio_st;
  {$EXTERNALSYM POSSL_CORE_BIO}

  Possl_dispatch_st = ^Tossl_dispatch_st;
  Tossl_dispatch_st = record end;
  {$EXTERNALSYM Possl_dispatch_st}

  Possl_item_st = ^Tossl_item_st;
  Tossl_item_st = record end;
  {$EXTERNALSYM Possl_item_st}

  Possl_algorithm_st = ^Tossl_algorithm_st;
  Tossl_algorithm_st = record end;
  {$EXTERNALSYM Possl_algorithm_st}

  Possl_param_st = ^Tossl_param_st;
  Tossl_param_st = record end;
  {$EXTERNALSYM Possl_param_st}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  TOSSL_thread_stop_handler_fn_func_cb = procedure(arg1: Pointer); cdecl;
  TOSSL_provider_init_fn_func_cb = function(arg1: POSSL_CORE_HANDLE; arg2: POSSL_DISPATCH; arg3: PPOSSL_DISPATCH; arg4: PPointer): TIdC_INT; cdecl;
  TOSSL_CALLBACK_func_cb = function(arg1: POSSL_PARAM_ARRAY; arg2: Pointer): TIdC_INT; cdecl;
  TOSSL_INOUT_CALLBACK_func_cb = function(arg1: POSSL_PARAM_ARRAY; arg2: POSSL_PARAM_ARRAY; arg3: Pointer): TIdC_INT; cdecl;
  TOSSL_PASSPHRASE_CALLBACK_func_cb = function(arg1: PIdAnsiChar; arg2: TIdC_SIZET; arg3: PIdC_SIZET; arg4: POSSL_PARAM_ARRAY; arg5: Pointer): TIdC_INT; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  OSSL_DISPATCH_END = {0,NULL};
  OSSL_PARAM_INTEGER = 1;
  OSSL_PARAM_UNSIGNED_INTEGER = 2;
  OSSL_PARAM_REAL = 3;
  OSSL_PARAM_UTF8_STRING = 4;
  OSSL_PARAM_OCTET_STRING = 5;
  OSSL_PARAM_UTF8_PTR = 6;
  OSSL_PARAM_OCTET_PTR = 7;

implementation

end.