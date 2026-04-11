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
  TaurusTLSHeaders_ossl_types,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_core,
  ossl_types;



// =============================================================================
// TYPE DECLARATIONS
// =============================================================================
type
  Popenssl_core_ctx_st = ^Topenssl_core_ctx_st;
  Topenssl_core_ctx_st =   record end;
  {$EXTERNALSYM Popenssl_core_ctx_st}

  Possl_core_bio_st = ^Tossl_core_bio_st;
  Tossl_core_bio_st =   record end;
  {$EXTERNALSYM Possl_core_bio_st}

  Possl_item_st = ^Tossl_item_st;
  Tossl_item_st =   record
    id: TIdC_UINT;
    ptr: Pointer;
  end;
  {$EXTERNALSYM Possl_item_st}

  Possl_algorithm_st = ^Tossl_algorithm_st;
  Tossl_algorithm_st =   record
    algorithm_names: PIdAnsiChar;
    property_definition: PIdAnsiChar;
    _implementation: POSSL_DISPATCH;
    algorithm_description: PIdAnsiChar;
  end;
  {$EXTERNALSYM Possl_algorithm_st}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // OSSL_CORE_BIO_func_cb = procedure; cdecl;
  TOSSL_thread_stop_handler_fn = procedure(arg: Pointer); cdecl;
  TOSSL_provider_init_fn = function(handle: POSSL_CORE_HANDLE; _in: POSSL_DISPATCH; _out: PPOSSL_DISPATCH; provctx: PPointer): TIdC_INT; cdecl;
  TOSSL_CALLBACK = function(params: POSSL_PARAM; arg: Pointer): TIdC_INT; cdecl;
  TOSSL_INOUT_CALLBACK = function(in_params: POSSL_PARAM; out_params: POSSL_PARAM; arg: Pointer): TIdC_INT; cdecl;
  TOSSL_PASSPHRASE_CALLBACK = function(pass: PIdAnsiChar; pass_size: TIdC_SIZET; pass_len: PIdC_SIZET; params: POSSL_PARAM; arg: Pointer): TIdC_INT; cdecl;

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