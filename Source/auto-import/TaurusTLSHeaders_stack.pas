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

unit TaurusTLSHeaders_stack;

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
  Pstack_st = ^Tstack_st;
  Tstack_st = record end;
  {$EXTERNALSYM Pstack_st}

  POPENSSL_STACK = ^TOPENSSL_STACK;
  TOPENSSL_STACK = Tstack_st;
  {$EXTERNALSYM POPENSSL_STACK}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  TOPENSSL_sk_compfunc_func_cb = function(arg1: Pointer; arg2: Pointer): TIdC_INT; cdecl;
  TOPENSSL_sk_freefunc_func_cb = procedure(arg1: Pointer); cdecl;
  TOPENSSL_sk_freefunc_thunk_func_cb = procedure(arg1: TOPENSSL_sk_freefunc_func_cb; arg2: Pointer); cdecl;
  TOPENSSL_sk_copyfunc_func_cb = function(arg1: Pointer): Pointer; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  _STACK = OPENSSL_STACK;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  OPENSSL_sk_num: function(arg1: POPENSSL_STACK): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_num}

  OPENSSL_sk_value: function(arg1: POPENSSL_STACK; arg2: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_value}

  OPENSSL_sk_set: function(st: POPENSSL_STACK; i: TIdC_INT; data: Pointer): Pointer; cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_set}

  OPENSSL_sk_new: function(cmp: TOPENSSL_sk_compfunc_func_cb): POPENSSL_STACK; cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_new}

  OPENSSL_sk_new_null: function: POPENSSL_STACK; cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_new_null}

  OPENSSL_sk_new_reserve: function(c: TOPENSSL_sk_compfunc_func_cb; n: TIdC_INT): POPENSSL_STACK; cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_new_reserve}

  OPENSSL_sk_set_thunks: function(st: POPENSSL_STACK; f_thunk: TOPENSSL_sk_freefunc_thunk_func_cb): POPENSSL_STACK; cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_set_thunks}

  OPENSSL_sk_reserve: function(st: POPENSSL_STACK; n: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_reserve}

  OPENSSL_sk_free: procedure(arg1: POPENSSL_STACK); cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_free}

  OPENSSL_sk_pop_free: procedure(st: POPENSSL_STACK; func: TOPENSSL_sk_freefunc_func_cb); cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_pop_free}

  OPENSSL_sk_deep_copy: function(arg1: POPENSSL_STACK; c: TOPENSSL_sk_copyfunc_func_cb; f: TOPENSSL_sk_freefunc_func_cb): POPENSSL_STACK; cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_deep_copy}

  OPENSSL_sk_insert: function(sk: POPENSSL_STACK; data: Pointer; where: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_insert}

  OPENSSL_sk_delete: function(st: POPENSSL_STACK; loc: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_delete}

  OPENSSL_sk_delete_ptr: function(st: POPENSSL_STACK; p: Pointer): Pointer; cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_delete_ptr}

  OPENSSL_sk_find: function(st: POPENSSL_STACK; data: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_find}

  OPENSSL_sk_find_ex: function(st: POPENSSL_STACK; data: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_find_ex}

  OPENSSL_sk_find_all: function(st: POPENSSL_STACK; data: Pointer; pnum: PIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_find_all}

  OPENSSL_sk_push: function(st: POPENSSL_STACK; data: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_push}

  OPENSSL_sk_unshift: function(st: POPENSSL_STACK; data: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_unshift}

  OPENSSL_sk_shift: function(st: POPENSSL_STACK): Pointer; cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_shift}

  OPENSSL_sk_pop: function(st: POPENSSL_STACK): Pointer; cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_pop}

  OPENSSL_sk_zero: procedure(st: POPENSSL_STACK); cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_zero}

  OPENSSL_sk_set_cmp_func: function(sk: POPENSSL_STACK; cmp: TOPENSSL_sk_compfunc_func_cb): TOPENSSL_sk_compfunc_func_cb; cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_set_cmp_func}

  OPENSSL_sk_dup: function(st: POPENSSL_STACK): POPENSSL_STACK; cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_dup}

  OPENSSL_sk_sort: procedure(st: POPENSSL_STACK); cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_sort}

  OPENSSL_sk_is_sorted: function(st: POPENSSL_STACK): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_sk_is_sorted}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function OPENSSL_sk_num(arg1: POPENSSL_STACK): TIdC_INT; cdecl;
function OPENSSL_sk_value(arg1: POPENSSL_STACK; arg2: TIdC_INT): Pointer; cdecl;
function OPENSSL_sk_set(st: POPENSSL_STACK; i: TIdC_INT; data: Pointer): Pointer; cdecl;
function OPENSSL_sk_new(cmp: TOPENSSL_sk_compfunc_func_cb): POPENSSL_STACK; cdecl;
function OPENSSL_sk_new_null: POPENSSL_STACK; cdecl;
function OPENSSL_sk_new_reserve(c: TOPENSSL_sk_compfunc_func_cb; n: TIdC_INT): POPENSSL_STACK; cdecl;
function OPENSSL_sk_set_thunks(st: POPENSSL_STACK; f_thunk: TOPENSSL_sk_freefunc_thunk_func_cb): POPENSSL_STACK; cdecl;
function OPENSSL_sk_reserve(st: POPENSSL_STACK; n: TIdC_INT): TIdC_INT; cdecl;
procedure OPENSSL_sk_free(arg1: POPENSSL_STACK); cdecl;
procedure OPENSSL_sk_pop_free(st: POPENSSL_STACK; func: TOPENSSL_sk_freefunc_func_cb); cdecl;
function OPENSSL_sk_deep_copy(arg1: POPENSSL_STACK; c: TOPENSSL_sk_copyfunc_func_cb; f: TOPENSSL_sk_freefunc_func_cb): POPENSSL_STACK; cdecl;
function OPENSSL_sk_insert(sk: POPENSSL_STACK; data: Pointer; where: TIdC_INT): TIdC_INT; cdecl;
function OPENSSL_sk_delete(st: POPENSSL_STACK; loc: TIdC_INT): Pointer; cdecl;
function OPENSSL_sk_delete_ptr(st: POPENSSL_STACK; p: Pointer): Pointer; cdecl;
function OPENSSL_sk_find(st: POPENSSL_STACK; data: Pointer): TIdC_INT; cdecl;
function OPENSSL_sk_find_ex(st: POPENSSL_STACK; data: Pointer): TIdC_INT; cdecl;
function OPENSSL_sk_find_all(st: POPENSSL_STACK; data: Pointer; pnum: PIdC_INT): TIdC_INT; cdecl;
function OPENSSL_sk_push(st: POPENSSL_STACK; data: Pointer): TIdC_INT; cdecl;
function OPENSSL_sk_unshift(st: POPENSSL_STACK; data: Pointer): TIdC_INT; cdecl;
function OPENSSL_sk_shift(st: POPENSSL_STACK): Pointer; cdecl;
function OPENSSL_sk_pop(st: POPENSSL_STACK): Pointer; cdecl;
procedure OPENSSL_sk_zero(st: POPENSSL_STACK); cdecl;
function OPENSSL_sk_set_cmp_func(sk: POPENSSL_STACK; cmp: TOPENSSL_sk_compfunc_func_cb): TOPENSSL_sk_compfunc_func_cb; cdecl;
function OPENSSL_sk_dup(st: POPENSSL_STACK): POPENSSL_STACK; cdecl;
procedure OPENSSL_sk_sort(st: POPENSSL_STACK); cdecl;
function OPENSSL_sk_is_sorted(st: POPENSSL_STACK): TIdC_INT; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

function sk_num(arg1: POPENSSL_STACK): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function sk_value(arg1: POPENSSL_STACK; arg2: TIdC_INT): Pointer; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function sk_set(st: POPENSSL_STACK; i: TIdC_INT; data: Pointer): Pointer; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function sk_new(cmp: TOPENSSL_sk_compfunc_func_cb): POPENSSL_STACK; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function sk_new_null: POPENSSL_STACK; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

procedure sk_free(arg1: POPENSSL_STACK); cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

procedure sk_pop_free(st: POPENSSL_STACK; func: TOPENSSL_sk_freefunc_func_cb); cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function sk_deep_copy(arg1: POPENSSL_STACK; c: TOPENSSL_sk_copyfunc_func_cb; f: TOPENSSL_sk_freefunc_func_cb): POPENSSL_STACK; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function sk_insert(sk: POPENSSL_STACK; data: Pointer; where: TIdC_INT): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function sk_delete(st: POPENSSL_STACK; loc: TIdC_INT): Pointer; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function sk_delete_ptr(st: POPENSSL_STACK; p: Pointer): Pointer; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function sk_find(st: POPENSSL_STACK; data: Pointer): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function sk_find_ex(st: POPENSSL_STACK; data: Pointer): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function sk_push(st: POPENSSL_STACK; data: Pointer): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function sk_unshift(st: POPENSSL_STACK; data: Pointer): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function sk_shift(st: POPENSSL_STACK): Pointer; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function sk_pop(st: POPENSSL_STACK): Pointer; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

procedure sk_zero(st: POPENSSL_STACK); cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function sk_set_cmp_func(sk: POPENSSL_STACK; cmp: TOPENSSL_sk_compfunc_func_cb): TOPENSSL_sk_compfunc_func_cb; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function sk_dup(st: POPENSSL_STACK): POPENSSL_STACK; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

procedure sk_sort(st: POPENSSL_STACK); cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function sk_is_sorted(st: POPENSSL_STACK): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}


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

function OPENSSL_sk_num(arg1: POPENSSL_STACK): TIdC_INT; cdecl external CLibCrypto name 'OPENSSL_sk_num';
function OPENSSL_sk_value(arg1: POPENSSL_STACK; arg2: TIdC_INT): Pointer; cdecl external CLibCrypto name 'OPENSSL_sk_value';
function OPENSSL_sk_set(st: POPENSSL_STACK; i: TIdC_INT; data: Pointer): Pointer; cdecl external CLibCrypto name 'OPENSSL_sk_set';
function OPENSSL_sk_new(cmp: TOPENSSL_sk_compfunc_func_cb): POPENSSL_STACK; cdecl external CLibCrypto name 'OPENSSL_sk_new';
function OPENSSL_sk_new_null: POPENSSL_STACK; cdecl external CLibCrypto name 'OPENSSL_sk_new_null';
function OPENSSL_sk_new_reserve(c: TOPENSSL_sk_compfunc_func_cb; n: TIdC_INT): POPENSSL_STACK; cdecl external CLibCrypto name 'OPENSSL_sk_new_reserve';
function OPENSSL_sk_set_thunks(st: POPENSSL_STACK; f_thunk: TOPENSSL_sk_freefunc_thunk_func_cb): POPENSSL_STACK; cdecl external CLibCrypto name 'OPENSSL_sk_set_thunks';
function OPENSSL_sk_reserve(st: POPENSSL_STACK; n: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OPENSSL_sk_reserve';
procedure OPENSSL_sk_free(arg1: POPENSSL_STACK); cdecl external CLibCrypto name 'OPENSSL_sk_free';
procedure OPENSSL_sk_pop_free(st: POPENSSL_STACK; func: TOPENSSL_sk_freefunc_func_cb); cdecl external CLibCrypto name 'OPENSSL_sk_pop_free';
function OPENSSL_sk_deep_copy(arg1: POPENSSL_STACK; c: TOPENSSL_sk_copyfunc_func_cb; f: TOPENSSL_sk_freefunc_func_cb): POPENSSL_STACK; cdecl external CLibCrypto name 'OPENSSL_sk_deep_copy';
function OPENSSL_sk_insert(sk: POPENSSL_STACK; data: Pointer; where: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OPENSSL_sk_insert';
function OPENSSL_sk_delete(st: POPENSSL_STACK; loc: TIdC_INT): Pointer; cdecl external CLibCrypto name 'OPENSSL_sk_delete';
function OPENSSL_sk_delete_ptr(st: POPENSSL_STACK; p: Pointer): Pointer; cdecl external CLibCrypto name 'OPENSSL_sk_delete_ptr';
function OPENSSL_sk_find(st: POPENSSL_STACK; data: Pointer): TIdC_INT; cdecl external CLibCrypto name 'OPENSSL_sk_find';
function OPENSSL_sk_find_ex(st: POPENSSL_STACK; data: Pointer): TIdC_INT; cdecl external CLibCrypto name 'OPENSSL_sk_find_ex';
function OPENSSL_sk_find_all(st: POPENSSL_STACK; data: Pointer; pnum: PIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OPENSSL_sk_find_all';
function OPENSSL_sk_push(st: POPENSSL_STACK; data: Pointer): TIdC_INT; cdecl external CLibCrypto name 'OPENSSL_sk_push';
function OPENSSL_sk_unshift(st: POPENSSL_STACK; data: Pointer): TIdC_INT; cdecl external CLibCrypto name 'OPENSSL_sk_unshift';
function OPENSSL_sk_shift(st: POPENSSL_STACK): Pointer; cdecl external CLibCrypto name 'OPENSSL_sk_shift';
function OPENSSL_sk_pop(st: POPENSSL_STACK): Pointer; cdecl external CLibCrypto name 'OPENSSL_sk_pop';
procedure OPENSSL_sk_zero(st: POPENSSL_STACK); cdecl external CLibCrypto name 'OPENSSL_sk_zero';
function OPENSSL_sk_set_cmp_func(sk: POPENSSL_STACK; cmp: TOPENSSL_sk_compfunc_func_cb): TOPENSSL_sk_compfunc_func_cb; cdecl external CLibCrypto name 'OPENSSL_sk_set_cmp_func';
function OPENSSL_sk_dup(st: POPENSSL_STACK): POPENSSL_STACK; cdecl external CLibCrypto name 'OPENSSL_sk_dup';
procedure OPENSSL_sk_sort(st: POPENSSL_STACK); cdecl external CLibCrypto name 'OPENSSL_sk_sort';
function OPENSSL_sk_is_sorted(st: POPENSSL_STACK): TIdC_INT; cdecl external CLibCrypto name 'OPENSSL_sk_is_sorted';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  OPENSSL_sk_num_procname = 'OPENSSL_sk_num';
  OPENSSL_sk_num_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_sk_value_procname = 'OPENSSL_sk_value';
  OPENSSL_sk_value_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_sk_set_procname = 'OPENSSL_sk_set';
  OPENSSL_sk_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_sk_new_procname = 'OPENSSL_sk_new';
  OPENSSL_sk_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_sk_new_null_procname = 'OPENSSL_sk_new_null';
  OPENSSL_sk_new_null_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_sk_new_reserve_procname = 'OPENSSL_sk_new_reserve';
  OPENSSL_sk_new_reserve_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OPENSSL_sk_set_thunks_procname = 'OPENSSL_sk_set_thunks';
  OPENSSL_sk_set_thunks_introduced = (byte(3) shl 8 or byte(6)) shl 8 or byte(0);

  OPENSSL_sk_reserve_procname = 'OPENSSL_sk_reserve';
  OPENSSL_sk_reserve_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OPENSSL_sk_free_procname = 'OPENSSL_sk_free';
  OPENSSL_sk_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_sk_pop_free_procname = 'OPENSSL_sk_pop_free';
  OPENSSL_sk_pop_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_sk_deep_copy_procname = 'OPENSSL_sk_deep_copy';
  OPENSSL_sk_deep_copy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_sk_insert_procname = 'OPENSSL_sk_insert';
  OPENSSL_sk_insert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_sk_delete_procname = 'OPENSSL_sk_delete';
  OPENSSL_sk_delete_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_sk_delete_ptr_procname = 'OPENSSL_sk_delete_ptr';
  OPENSSL_sk_delete_ptr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_sk_find_procname = 'OPENSSL_sk_find';
  OPENSSL_sk_find_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_sk_find_ex_procname = 'OPENSSL_sk_find_ex';
  OPENSSL_sk_find_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_sk_find_all_procname = 'OPENSSL_sk_find_all';
  OPENSSL_sk_find_all_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OPENSSL_sk_push_procname = 'OPENSSL_sk_push';
  OPENSSL_sk_push_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_sk_unshift_procname = 'OPENSSL_sk_unshift';
  OPENSSL_sk_unshift_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_sk_shift_procname = 'OPENSSL_sk_shift';
  OPENSSL_sk_shift_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_sk_pop_procname = 'OPENSSL_sk_pop';
  OPENSSL_sk_pop_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_sk_zero_procname = 'OPENSSL_sk_zero';
  OPENSSL_sk_zero_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_sk_set_cmp_func_procname = 'OPENSSL_sk_set_cmp_func';
  OPENSSL_sk_set_cmp_func_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_sk_dup_procname = 'OPENSSL_sk_dup';
  OPENSSL_sk_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_sk_sort_procname = 'OPENSSL_sk_sort';
  OPENSSL_sk_sort_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_sk_is_sorted_procname = 'OPENSSL_sk_is_sorted';
  OPENSSL_sk_is_sorted_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function sk_num(arg1: POPENSSL_STACK): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    sk_num OPENSSL_sk_num
  }
end;

function sk_value(arg1: POPENSSL_STACK; arg2: TIdC_INT): Pointer; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    sk_value OPENSSL_sk_value
  }
end;

function sk_set(st: POPENSSL_STACK; i: TIdC_INT; data: Pointer): Pointer; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    sk_set OPENSSL_sk_set
  }
end;

function sk_new(cmp: TOPENSSL_sk_compfunc_func_cb): POPENSSL_STACK; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    sk_new OPENSSL_sk_new
  }
end;

function sk_new_null: POPENSSL_STACK; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    sk_new_null OPENSSL_sk_new_null
  }
end;

procedure sk_free(arg1: POPENSSL_STACK); cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    sk_free OPENSSL_sk_free
  }
end;

procedure sk_pop_free(st: POPENSSL_STACK; func: TOPENSSL_sk_freefunc_func_cb); cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    sk_pop_free OPENSSL_sk_pop_free
  }
end;

function sk_deep_copy(arg1: POPENSSL_STACK; c: TOPENSSL_sk_copyfunc_func_cb; f: TOPENSSL_sk_freefunc_func_cb): POPENSSL_STACK; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    sk_deep_copy OPENSSL_sk_deep_copy
  }
end;

function sk_insert(sk: POPENSSL_STACK; data: Pointer; where: TIdC_INT): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    sk_insert OPENSSL_sk_insert
  }
end;

function sk_delete(st: POPENSSL_STACK; loc: TIdC_INT): Pointer; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    sk_delete OPENSSL_sk_delete
  }
end;

function sk_delete_ptr(st: POPENSSL_STACK; p: Pointer): Pointer; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    sk_delete_ptr OPENSSL_sk_delete_ptr
  }
end;

function sk_find(st: POPENSSL_STACK; data: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    sk_find OPENSSL_sk_find
  }
end;

function sk_find_ex(st: POPENSSL_STACK; data: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    sk_find_ex OPENSSL_sk_find_ex
  }
end;

function sk_push(st: POPENSSL_STACK; data: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    sk_push OPENSSL_sk_push
  }
end;

function sk_unshift(st: POPENSSL_STACK; data: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    sk_unshift OPENSSL_sk_unshift
  }
end;

function sk_shift(st: POPENSSL_STACK): Pointer; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    sk_shift OPENSSL_sk_shift
  }
end;

function sk_pop(st: POPENSSL_STACK): Pointer; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    sk_pop OPENSSL_sk_pop
  }
end;

procedure sk_zero(st: POPENSSL_STACK); cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    sk_zero OPENSSL_sk_zero
  }
end;

function sk_set_cmp_func(sk: POPENSSL_STACK; cmp: TOPENSSL_sk_compfunc_func_cb): TOPENSSL_sk_compfunc_func_cb; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    sk_set_cmp_func OPENSSL_sk_set_cmp_func
  }
end;

function sk_dup(st: POPENSSL_STACK): POPENSSL_STACK; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    sk_dup OPENSSL_sk_dup
  }
end;

procedure sk_sort(st: POPENSSL_STACK); cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    sk_sort OPENSSL_sk_sort
  }
end;

function sk_is_sorted(st: POPENSSL_STACK): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    sk_is_sorted OPENSSL_sk_is_sorted
  }
end;

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_OPENSSL_sk_num(arg1: POPENSSL_STACK): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_num_procname);
end;

function ERR_OPENSSL_sk_value(arg1: POPENSSL_STACK; arg2: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_value_procname);
end;

function ERR_OPENSSL_sk_set(st: POPENSSL_STACK; i: TIdC_INT; data: Pointer): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_set_procname);
end;

function ERR_OPENSSL_sk_new(cmp: TOPENSSL_sk_compfunc_func_cb): POPENSSL_STACK; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_new_procname);
end;

function ERR_OPENSSL_sk_new_null: POPENSSL_STACK; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_new_null_procname);
end;

function ERR_OPENSSL_sk_new_reserve(c: TOPENSSL_sk_compfunc_func_cb; n: TIdC_INT): POPENSSL_STACK; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_new_reserve_procname);
end;

function ERR_OPENSSL_sk_set_thunks(st: POPENSSL_STACK; f_thunk: TOPENSSL_sk_freefunc_thunk_func_cb): POPENSSL_STACK; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_set_thunks_procname);
end;

function ERR_OPENSSL_sk_reserve(st: POPENSSL_STACK; n: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_reserve_procname);
end;

procedure ERR_OPENSSL_sk_free(arg1: POPENSSL_STACK); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_free_procname);
end;

procedure ERR_OPENSSL_sk_pop_free(st: POPENSSL_STACK; func: TOPENSSL_sk_freefunc_func_cb); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_pop_free_procname);
end;

function ERR_OPENSSL_sk_deep_copy(arg1: POPENSSL_STACK; c: TOPENSSL_sk_copyfunc_func_cb; f: TOPENSSL_sk_freefunc_func_cb): POPENSSL_STACK; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_deep_copy_procname);
end;

function ERR_OPENSSL_sk_insert(sk: POPENSSL_STACK; data: Pointer; where: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_insert_procname);
end;

function ERR_OPENSSL_sk_delete(st: POPENSSL_STACK; loc: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_delete_procname);
end;

function ERR_OPENSSL_sk_delete_ptr(st: POPENSSL_STACK; p: Pointer): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_delete_ptr_procname);
end;

function ERR_OPENSSL_sk_find(st: POPENSSL_STACK; data: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_find_procname);
end;

function ERR_OPENSSL_sk_find_ex(st: POPENSSL_STACK; data: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_find_ex_procname);
end;

function ERR_OPENSSL_sk_find_all(st: POPENSSL_STACK; data: Pointer; pnum: PIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_find_all_procname);
end;

function ERR_OPENSSL_sk_push(st: POPENSSL_STACK; data: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_push_procname);
end;

function ERR_OPENSSL_sk_unshift(st: POPENSSL_STACK; data: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_unshift_procname);
end;

function ERR_OPENSSL_sk_shift(st: POPENSSL_STACK): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_shift_procname);
end;

function ERR_OPENSSL_sk_pop(st: POPENSSL_STACK): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_pop_procname);
end;

procedure ERR_OPENSSL_sk_zero(st: POPENSSL_STACK); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_zero_procname);
end;

function ERR_OPENSSL_sk_set_cmp_func(sk: POPENSSL_STACK; cmp: TOPENSSL_sk_compfunc_func_cb): TOPENSSL_sk_compfunc_func_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_set_cmp_func_procname);
end;

function ERR_OPENSSL_sk_dup(st: POPENSSL_STACK): POPENSSL_STACK; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_dup_procname);
end;

procedure ERR_OPENSSL_sk_sort(st: POPENSSL_STACK); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_sort_procname);
end;

function ERR_OPENSSL_sk_is_sorted(st: POPENSSL_STACK): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_sk_is_sorted_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  OPENSSL_sk_num := LoadLibFunction(ADllHandle, OPENSSL_sk_num_procname);
  FuncLoadError := not assigned(OPENSSL_sk_num);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_num_allownil)}
    OPENSSL_sk_num := ERR_OPENSSL_sk_num;
    {$ifend}
    {$if declared(OPENSSL_sk_num_introduced)}
    if LibVersion < OPENSSL_sk_num_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_num)}
      OPENSSL_sk_num := FC_OPENSSL_sk_num;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_num_removed)}
    if OPENSSL_sk_num_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_num)}
      OPENSSL_sk_num := _OPENSSL_sk_num;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_num_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_num');
    {$ifend}
  end;
  
  OPENSSL_sk_value := LoadLibFunction(ADllHandle, OPENSSL_sk_value_procname);
  FuncLoadError := not assigned(OPENSSL_sk_value);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_value_allownil)}
    OPENSSL_sk_value := ERR_OPENSSL_sk_value;
    {$ifend}
    {$if declared(OPENSSL_sk_value_introduced)}
    if LibVersion < OPENSSL_sk_value_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_value)}
      OPENSSL_sk_value := FC_OPENSSL_sk_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_value_removed)}
    if OPENSSL_sk_value_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_value)}
      OPENSSL_sk_value := _OPENSSL_sk_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_value_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_value');
    {$ifend}
  end;
  
  OPENSSL_sk_set := LoadLibFunction(ADllHandle, OPENSSL_sk_set_procname);
  FuncLoadError := not assigned(OPENSSL_sk_set);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_set_allownil)}
    OPENSSL_sk_set := ERR_OPENSSL_sk_set;
    {$ifend}
    {$if declared(OPENSSL_sk_set_introduced)}
    if LibVersion < OPENSSL_sk_set_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_set)}
      OPENSSL_sk_set := FC_OPENSSL_sk_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_set_removed)}
    if OPENSSL_sk_set_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_set)}
      OPENSSL_sk_set := _OPENSSL_sk_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_set_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_set');
    {$ifend}
  end;
  
  OPENSSL_sk_new := LoadLibFunction(ADllHandle, OPENSSL_sk_new_procname);
  FuncLoadError := not assigned(OPENSSL_sk_new);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_new_allownil)}
    OPENSSL_sk_new := ERR_OPENSSL_sk_new;
    {$ifend}
    {$if declared(OPENSSL_sk_new_introduced)}
    if LibVersion < OPENSSL_sk_new_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_new)}
      OPENSSL_sk_new := FC_OPENSSL_sk_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_new_removed)}
    if OPENSSL_sk_new_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_new)}
      OPENSSL_sk_new := _OPENSSL_sk_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_new');
    {$ifend}
  end;
  
  OPENSSL_sk_new_null := LoadLibFunction(ADllHandle, OPENSSL_sk_new_null_procname);
  FuncLoadError := not assigned(OPENSSL_sk_new_null);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_new_null_allownil)}
    OPENSSL_sk_new_null := ERR_OPENSSL_sk_new_null;
    {$ifend}
    {$if declared(OPENSSL_sk_new_null_introduced)}
    if LibVersion < OPENSSL_sk_new_null_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_new_null)}
      OPENSSL_sk_new_null := FC_OPENSSL_sk_new_null;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_new_null_removed)}
    if OPENSSL_sk_new_null_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_new_null)}
      OPENSSL_sk_new_null := _OPENSSL_sk_new_null;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_new_null_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_new_null');
    {$ifend}
  end;
  
  OPENSSL_sk_new_reserve := LoadLibFunction(ADllHandle, OPENSSL_sk_new_reserve_procname);
  FuncLoadError := not assigned(OPENSSL_sk_new_reserve);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_new_reserve_allownil)}
    OPENSSL_sk_new_reserve := ERR_OPENSSL_sk_new_reserve;
    {$ifend}
    {$if declared(OPENSSL_sk_new_reserve_introduced)}
    if LibVersion < OPENSSL_sk_new_reserve_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_new_reserve)}
      OPENSSL_sk_new_reserve := FC_OPENSSL_sk_new_reserve;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_new_reserve_removed)}
    if OPENSSL_sk_new_reserve_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_new_reserve)}
      OPENSSL_sk_new_reserve := _OPENSSL_sk_new_reserve;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_new_reserve_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_new_reserve');
    {$ifend}
  end;
  
  OPENSSL_sk_set_thunks := LoadLibFunction(ADllHandle, OPENSSL_sk_set_thunks_procname);
  FuncLoadError := not assigned(OPENSSL_sk_set_thunks);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_set_thunks_allownil)}
    OPENSSL_sk_set_thunks := ERR_OPENSSL_sk_set_thunks;
    {$ifend}
    {$if declared(OPENSSL_sk_set_thunks_introduced)}
    if LibVersion < OPENSSL_sk_set_thunks_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_set_thunks)}
      OPENSSL_sk_set_thunks := FC_OPENSSL_sk_set_thunks;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_set_thunks_removed)}
    if OPENSSL_sk_set_thunks_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_set_thunks)}
      OPENSSL_sk_set_thunks := _OPENSSL_sk_set_thunks;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_set_thunks_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_set_thunks');
    {$ifend}
  end;
  
  OPENSSL_sk_reserve := LoadLibFunction(ADllHandle, OPENSSL_sk_reserve_procname);
  FuncLoadError := not assigned(OPENSSL_sk_reserve);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_reserve_allownil)}
    OPENSSL_sk_reserve := ERR_OPENSSL_sk_reserve;
    {$ifend}
    {$if declared(OPENSSL_sk_reserve_introduced)}
    if LibVersion < OPENSSL_sk_reserve_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_reserve)}
      OPENSSL_sk_reserve := FC_OPENSSL_sk_reserve;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_reserve_removed)}
    if OPENSSL_sk_reserve_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_reserve)}
      OPENSSL_sk_reserve := _OPENSSL_sk_reserve;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_reserve_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_reserve');
    {$ifend}
  end;
  
  OPENSSL_sk_free := LoadLibFunction(ADllHandle, OPENSSL_sk_free_procname);
  FuncLoadError := not assigned(OPENSSL_sk_free);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_free_allownil)}
    OPENSSL_sk_free := ERR_OPENSSL_sk_free;
    {$ifend}
    {$if declared(OPENSSL_sk_free_introduced)}
    if LibVersion < OPENSSL_sk_free_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_free)}
      OPENSSL_sk_free := FC_OPENSSL_sk_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_free_removed)}
    if OPENSSL_sk_free_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_free)}
      OPENSSL_sk_free := _OPENSSL_sk_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_free');
    {$ifend}
  end;
  
  OPENSSL_sk_pop_free := LoadLibFunction(ADllHandle, OPENSSL_sk_pop_free_procname);
  FuncLoadError := not assigned(OPENSSL_sk_pop_free);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_pop_free_allownil)}
    OPENSSL_sk_pop_free := ERR_OPENSSL_sk_pop_free;
    {$ifend}
    {$if declared(OPENSSL_sk_pop_free_introduced)}
    if LibVersion < OPENSSL_sk_pop_free_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_pop_free)}
      OPENSSL_sk_pop_free := FC_OPENSSL_sk_pop_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_pop_free_removed)}
    if OPENSSL_sk_pop_free_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_pop_free)}
      OPENSSL_sk_pop_free := _OPENSSL_sk_pop_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_pop_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_pop_free');
    {$ifend}
  end;
  
  OPENSSL_sk_deep_copy := LoadLibFunction(ADllHandle, OPENSSL_sk_deep_copy_procname);
  FuncLoadError := not assigned(OPENSSL_sk_deep_copy);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_deep_copy_allownil)}
    OPENSSL_sk_deep_copy := ERR_OPENSSL_sk_deep_copy;
    {$ifend}
    {$if declared(OPENSSL_sk_deep_copy_introduced)}
    if LibVersion < OPENSSL_sk_deep_copy_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_deep_copy)}
      OPENSSL_sk_deep_copy := FC_OPENSSL_sk_deep_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_deep_copy_removed)}
    if OPENSSL_sk_deep_copy_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_deep_copy)}
      OPENSSL_sk_deep_copy := _OPENSSL_sk_deep_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_deep_copy_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_deep_copy');
    {$ifend}
  end;
  
  OPENSSL_sk_insert := LoadLibFunction(ADllHandle, OPENSSL_sk_insert_procname);
  FuncLoadError := not assigned(OPENSSL_sk_insert);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_insert_allownil)}
    OPENSSL_sk_insert := ERR_OPENSSL_sk_insert;
    {$ifend}
    {$if declared(OPENSSL_sk_insert_introduced)}
    if LibVersion < OPENSSL_sk_insert_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_insert)}
      OPENSSL_sk_insert := FC_OPENSSL_sk_insert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_insert_removed)}
    if OPENSSL_sk_insert_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_insert)}
      OPENSSL_sk_insert := _OPENSSL_sk_insert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_insert_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_insert');
    {$ifend}
  end;
  
  OPENSSL_sk_delete := LoadLibFunction(ADllHandle, OPENSSL_sk_delete_procname);
  FuncLoadError := not assigned(OPENSSL_sk_delete);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_delete_allownil)}
    OPENSSL_sk_delete := ERR_OPENSSL_sk_delete;
    {$ifend}
    {$if declared(OPENSSL_sk_delete_introduced)}
    if LibVersion < OPENSSL_sk_delete_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_delete)}
      OPENSSL_sk_delete := FC_OPENSSL_sk_delete;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_delete_removed)}
    if OPENSSL_sk_delete_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_delete)}
      OPENSSL_sk_delete := _OPENSSL_sk_delete;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_delete_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_delete');
    {$ifend}
  end;
  
  OPENSSL_sk_delete_ptr := LoadLibFunction(ADllHandle, OPENSSL_sk_delete_ptr_procname);
  FuncLoadError := not assigned(OPENSSL_sk_delete_ptr);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_delete_ptr_allownil)}
    OPENSSL_sk_delete_ptr := ERR_OPENSSL_sk_delete_ptr;
    {$ifend}
    {$if declared(OPENSSL_sk_delete_ptr_introduced)}
    if LibVersion < OPENSSL_sk_delete_ptr_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_delete_ptr)}
      OPENSSL_sk_delete_ptr := FC_OPENSSL_sk_delete_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_delete_ptr_removed)}
    if OPENSSL_sk_delete_ptr_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_delete_ptr)}
      OPENSSL_sk_delete_ptr := _OPENSSL_sk_delete_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_delete_ptr_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_delete_ptr');
    {$ifend}
  end;
  
  OPENSSL_sk_find := LoadLibFunction(ADllHandle, OPENSSL_sk_find_procname);
  FuncLoadError := not assigned(OPENSSL_sk_find);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_find_allownil)}
    OPENSSL_sk_find := ERR_OPENSSL_sk_find;
    {$ifend}
    {$if declared(OPENSSL_sk_find_introduced)}
    if LibVersion < OPENSSL_sk_find_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_find)}
      OPENSSL_sk_find := FC_OPENSSL_sk_find;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_find_removed)}
    if OPENSSL_sk_find_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_find)}
      OPENSSL_sk_find := _OPENSSL_sk_find;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_find_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_find');
    {$ifend}
  end;
  
  OPENSSL_sk_find_ex := LoadLibFunction(ADllHandle, OPENSSL_sk_find_ex_procname);
  FuncLoadError := not assigned(OPENSSL_sk_find_ex);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_find_ex_allownil)}
    OPENSSL_sk_find_ex := ERR_OPENSSL_sk_find_ex;
    {$ifend}
    {$if declared(OPENSSL_sk_find_ex_introduced)}
    if LibVersion < OPENSSL_sk_find_ex_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_find_ex)}
      OPENSSL_sk_find_ex := FC_OPENSSL_sk_find_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_find_ex_removed)}
    if OPENSSL_sk_find_ex_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_find_ex)}
      OPENSSL_sk_find_ex := _OPENSSL_sk_find_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_find_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_find_ex');
    {$ifend}
  end;
  
  OPENSSL_sk_find_all := LoadLibFunction(ADllHandle, OPENSSL_sk_find_all_procname);
  FuncLoadError := not assigned(OPENSSL_sk_find_all);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_find_all_allownil)}
    OPENSSL_sk_find_all := ERR_OPENSSL_sk_find_all;
    {$ifend}
    {$if declared(OPENSSL_sk_find_all_introduced)}
    if LibVersion < OPENSSL_sk_find_all_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_find_all)}
      OPENSSL_sk_find_all := FC_OPENSSL_sk_find_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_find_all_removed)}
    if OPENSSL_sk_find_all_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_find_all)}
      OPENSSL_sk_find_all := _OPENSSL_sk_find_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_find_all_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_find_all');
    {$ifend}
  end;
  
  OPENSSL_sk_push := LoadLibFunction(ADllHandle, OPENSSL_sk_push_procname);
  FuncLoadError := not assigned(OPENSSL_sk_push);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_push_allownil)}
    OPENSSL_sk_push := ERR_OPENSSL_sk_push;
    {$ifend}
    {$if declared(OPENSSL_sk_push_introduced)}
    if LibVersion < OPENSSL_sk_push_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_push)}
      OPENSSL_sk_push := FC_OPENSSL_sk_push;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_push_removed)}
    if OPENSSL_sk_push_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_push)}
      OPENSSL_sk_push := _OPENSSL_sk_push;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_push_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_push');
    {$ifend}
  end;
  
  OPENSSL_sk_unshift := LoadLibFunction(ADllHandle, OPENSSL_sk_unshift_procname);
  FuncLoadError := not assigned(OPENSSL_sk_unshift);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_unshift_allownil)}
    OPENSSL_sk_unshift := ERR_OPENSSL_sk_unshift;
    {$ifend}
    {$if declared(OPENSSL_sk_unshift_introduced)}
    if LibVersion < OPENSSL_sk_unshift_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_unshift)}
      OPENSSL_sk_unshift := FC_OPENSSL_sk_unshift;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_unshift_removed)}
    if OPENSSL_sk_unshift_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_unshift)}
      OPENSSL_sk_unshift := _OPENSSL_sk_unshift;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_unshift_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_unshift');
    {$ifend}
  end;
  
  OPENSSL_sk_shift := LoadLibFunction(ADllHandle, OPENSSL_sk_shift_procname);
  FuncLoadError := not assigned(OPENSSL_sk_shift);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_shift_allownil)}
    OPENSSL_sk_shift := ERR_OPENSSL_sk_shift;
    {$ifend}
    {$if declared(OPENSSL_sk_shift_introduced)}
    if LibVersion < OPENSSL_sk_shift_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_shift)}
      OPENSSL_sk_shift := FC_OPENSSL_sk_shift;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_shift_removed)}
    if OPENSSL_sk_shift_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_shift)}
      OPENSSL_sk_shift := _OPENSSL_sk_shift;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_shift_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_shift');
    {$ifend}
  end;
  
  OPENSSL_sk_pop := LoadLibFunction(ADllHandle, OPENSSL_sk_pop_procname);
  FuncLoadError := not assigned(OPENSSL_sk_pop);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_pop_allownil)}
    OPENSSL_sk_pop := ERR_OPENSSL_sk_pop;
    {$ifend}
    {$if declared(OPENSSL_sk_pop_introduced)}
    if LibVersion < OPENSSL_sk_pop_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_pop)}
      OPENSSL_sk_pop := FC_OPENSSL_sk_pop;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_pop_removed)}
    if OPENSSL_sk_pop_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_pop)}
      OPENSSL_sk_pop := _OPENSSL_sk_pop;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_pop_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_pop');
    {$ifend}
  end;
  
  OPENSSL_sk_zero := LoadLibFunction(ADllHandle, OPENSSL_sk_zero_procname);
  FuncLoadError := not assigned(OPENSSL_sk_zero);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_zero_allownil)}
    OPENSSL_sk_zero := ERR_OPENSSL_sk_zero;
    {$ifend}
    {$if declared(OPENSSL_sk_zero_introduced)}
    if LibVersion < OPENSSL_sk_zero_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_zero)}
      OPENSSL_sk_zero := FC_OPENSSL_sk_zero;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_zero_removed)}
    if OPENSSL_sk_zero_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_zero)}
      OPENSSL_sk_zero := _OPENSSL_sk_zero;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_zero_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_zero');
    {$ifend}
  end;
  
  OPENSSL_sk_set_cmp_func := LoadLibFunction(ADllHandle, OPENSSL_sk_set_cmp_func_procname);
  FuncLoadError := not assigned(OPENSSL_sk_set_cmp_func);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_set_cmp_func_allownil)}
    OPENSSL_sk_set_cmp_func := ERR_OPENSSL_sk_set_cmp_func;
    {$ifend}
    {$if declared(OPENSSL_sk_set_cmp_func_introduced)}
    if LibVersion < OPENSSL_sk_set_cmp_func_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_set_cmp_func)}
      OPENSSL_sk_set_cmp_func := FC_OPENSSL_sk_set_cmp_func;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_set_cmp_func_removed)}
    if OPENSSL_sk_set_cmp_func_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_set_cmp_func)}
      OPENSSL_sk_set_cmp_func := _OPENSSL_sk_set_cmp_func;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_set_cmp_func_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_set_cmp_func');
    {$ifend}
  end;
  
  OPENSSL_sk_dup := LoadLibFunction(ADllHandle, OPENSSL_sk_dup_procname);
  FuncLoadError := not assigned(OPENSSL_sk_dup);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_dup_allownil)}
    OPENSSL_sk_dup := ERR_OPENSSL_sk_dup;
    {$ifend}
    {$if declared(OPENSSL_sk_dup_introduced)}
    if LibVersion < OPENSSL_sk_dup_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_dup)}
      OPENSSL_sk_dup := FC_OPENSSL_sk_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_dup_removed)}
    if OPENSSL_sk_dup_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_dup)}
      OPENSSL_sk_dup := _OPENSSL_sk_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_dup');
    {$ifend}
  end;
  
  OPENSSL_sk_sort := LoadLibFunction(ADllHandle, OPENSSL_sk_sort_procname);
  FuncLoadError := not assigned(OPENSSL_sk_sort);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_sort_allownil)}
    OPENSSL_sk_sort := ERR_OPENSSL_sk_sort;
    {$ifend}
    {$if declared(OPENSSL_sk_sort_introduced)}
    if LibVersion < OPENSSL_sk_sort_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_sort)}
      OPENSSL_sk_sort := FC_OPENSSL_sk_sort;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_sort_removed)}
    if OPENSSL_sk_sort_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_sort)}
      OPENSSL_sk_sort := _OPENSSL_sk_sort;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_sort_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_sort');
    {$ifend}
  end;
  
  OPENSSL_sk_is_sorted := LoadLibFunction(ADllHandle, OPENSSL_sk_is_sorted_procname);
  FuncLoadError := not assigned(OPENSSL_sk_is_sorted);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_sk_is_sorted_allownil)}
    OPENSSL_sk_is_sorted := ERR_OPENSSL_sk_is_sorted;
    {$ifend}
    {$if declared(OPENSSL_sk_is_sorted_introduced)}
    if LibVersion < OPENSSL_sk_is_sorted_introduced then
    begin
      {$if declared(FC_OPENSSL_sk_is_sorted)}
      OPENSSL_sk_is_sorted := FC_OPENSSL_sk_is_sorted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_sk_is_sorted_removed)}
    if OPENSSL_sk_is_sorted_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_sk_is_sorted)}
      OPENSSL_sk_is_sorted := _OPENSSL_sk_is_sorted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_sk_is_sorted_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_sk_is_sorted');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  OPENSSL_sk_num := nil;
  OPENSSL_sk_value := nil;
  OPENSSL_sk_set := nil;
  OPENSSL_sk_new := nil;
  OPENSSL_sk_new_null := nil;
  OPENSSL_sk_new_reserve := nil;
  OPENSSL_sk_set_thunks := nil;
  OPENSSL_sk_reserve := nil;
  OPENSSL_sk_free := nil;
  OPENSSL_sk_pop_free := nil;
  OPENSSL_sk_deep_copy := nil;
  OPENSSL_sk_insert := nil;
  OPENSSL_sk_delete := nil;
  OPENSSL_sk_delete_ptr := nil;
  OPENSSL_sk_find := nil;
  OPENSSL_sk_find_ex := nil;
  OPENSSL_sk_find_all := nil;
  OPENSSL_sk_push := nil;
  OPENSSL_sk_unshift := nil;
  OPENSSL_sk_shift := nil;
  OPENSSL_sk_pop := nil;
  OPENSSL_sk_zero := nil;
  OPENSSL_sk_set_cmp_func := nil;
  OPENSSL_sk_dup := nil;
  OPENSSL_sk_sort := nil;
  OPENSSL_sk_is_sorted := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.