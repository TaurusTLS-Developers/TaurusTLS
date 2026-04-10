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

unit TaurusTLSHeaders_params;

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
// CONSTANTS DECLARATIONS
// =============================================================================
const
  OSSL_PARAM_UNMODIFIED = ((size_t)-1);
  OSSL_PARAM_END = {NULL,0,NULL,0,0};

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  OSSL_PARAM_locate: function(p: POSSL_PARAM; key: PIdAnsiChar): POSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_locate}

  OSSL_PARAM_locate_const: function(p: POSSL_PARAM; key: PIdAnsiChar): POSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_locate_const}

  OSSL_PARAM_construct_int: function(key: PIdAnsiChar; buf: PIdC_INT): TOSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_construct_int}

  OSSL_PARAM_construct_uint: function(key: PIdAnsiChar; buf: PIdC_UINT): TOSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_construct_uint}

  OSSL_PARAM_construct_long: function(key: PIdAnsiChar; buf: PIdC_LONG): TOSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_construct_long}

  OSSL_PARAM_construct_ulong: function(key: PIdAnsiChar; buf: PIdC_ULONG): TOSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_construct_ulong}

  OSSL_PARAM_construct_int32: function(key: PIdAnsiChar; buf: PIdC_INT32): TOSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_construct_int32}

  OSSL_PARAM_construct_uint32: function(key: PIdAnsiChar; buf: PIdC_UINT32): TOSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_construct_uint32}

  OSSL_PARAM_construct_int64: function(key: PIdAnsiChar; buf: PIdC_INT64): TOSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_construct_int64}

  OSSL_PARAM_construct_uint64: function(key: PIdAnsiChar; buf: PIdC_UINT64): TOSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_construct_uint64}

  OSSL_PARAM_construct_size_t: function(key: PIdAnsiChar; buf: PIdC_SIZET): TOSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_construct_size_t}

  OSSL_PARAM_construct_time_t: function(key: PIdAnsiChar; buf: PIdC_TIMET): TOSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_construct_time_t}

  OSSL_PARAM_construct_BN: function(key: PIdAnsiChar; buf: PIdAnsiChar; bsize: TIdC_SIZET): TOSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_construct_BN}

  OSSL_PARAM_construct_double: function(key: PIdAnsiChar; buf: PIdC_DOUBLE): TOSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_construct_double}

  OSSL_PARAM_construct_utf8_string: function(key: PIdAnsiChar; buf: PIdAnsiChar; bsize: TIdC_SIZET): TOSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_construct_utf8_string}

  OSSL_PARAM_construct_utf8_ptr: function(key: PIdAnsiChar; buf: PPIdAnsiChar; bsize: TIdC_SIZET): TOSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_construct_utf8_ptr}

  OSSL_PARAM_construct_octet_string: function(key: PIdAnsiChar; buf: Pointer; bsize: TIdC_SIZET): TOSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_construct_octet_string}

  OSSL_PARAM_construct_octet_ptr: function(key: PIdAnsiChar; buf: PPointer; bsize: TIdC_SIZET): TOSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_construct_octet_ptr}

  OSSL_PARAM_construct_end: function: TOSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_construct_end}

  OSSL_PARAM_allocate_from_text: function(_to: POSSL_PARAM; paramdefs: POSSL_PARAM; key: PIdAnsiChar; value: PIdAnsiChar; value_n: TIdC_SIZET; found: PIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_allocate_from_text}

  OSSL_PARAM_print_to_bio: function(params: POSSL_PARAM; bio: PBIO; print_values: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_print_to_bio}

  OSSL_PARAM_get_int: function(p: POSSL_PARAM; val: PIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_get_int}

  OSSL_PARAM_get_uint: function(p: POSSL_PARAM; val: PIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_get_uint}

  OSSL_PARAM_get_long: function(p: POSSL_PARAM; val: PIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_get_long}

  OSSL_PARAM_get_ulong: function(p: POSSL_PARAM; val: PIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_get_ulong}

  OSSL_PARAM_get_int32: function(p: POSSL_PARAM; val: PIdC_INT32): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_get_int32}

  OSSL_PARAM_get_uint32: function(p: POSSL_PARAM; val: PIdC_UINT32): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_get_uint32}

  OSSL_PARAM_get_int64: function(p: POSSL_PARAM; val: PIdC_INT64): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_get_int64}

  OSSL_PARAM_get_uint64: function(p: POSSL_PARAM; val: PIdC_UINT64): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_get_uint64}

  OSSL_PARAM_get_size_t: function(p: POSSL_PARAM; val: PIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_get_size_t}

  OSSL_PARAM_get_time_t: function(p: POSSL_PARAM; val: PIdC_TIMET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_get_time_t}

  OSSL_PARAM_set_int: function(p: POSSL_PARAM; val: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_set_int}

  OSSL_PARAM_set_uint: function(p: POSSL_PARAM; val: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_set_uint}

  OSSL_PARAM_set_long: function(p: POSSL_PARAM; val: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_set_long}

  OSSL_PARAM_set_ulong: function(p: POSSL_PARAM; val: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_set_ulong}

  OSSL_PARAM_set_int32: function(p: POSSL_PARAM; val: TIdC_INT32): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_set_int32}

  OSSL_PARAM_set_uint32: function(p: POSSL_PARAM; val: TIdC_UINT32): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_set_uint32}

  OSSL_PARAM_set_int64: function(p: POSSL_PARAM; val: TIdC_INT64): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_set_int64}

  OSSL_PARAM_set_uint64: function(p: POSSL_PARAM; val: TIdC_UINT64): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_set_uint64}

  OSSL_PARAM_set_size_t: function(p: POSSL_PARAM; val: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_set_size_t}

  OSSL_PARAM_set_time_t: function(p: POSSL_PARAM; val: TIdC_TIMET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_set_time_t}

  OSSL_PARAM_get_double: function(p: POSSL_PARAM; val: PIdC_DOUBLE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_get_double}

  OSSL_PARAM_set_double: function(p: POSSL_PARAM; val: TIdC_DOUBLE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_set_double}

  OSSL_PARAM_get_BN: function(p: POSSL_PARAM; val: PPBIGNUM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_get_BN}

  OSSL_PARAM_set_BN: function(p: POSSL_PARAM; val: PBIGNUM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_set_BN}

  OSSL_PARAM_get_utf8_string: function(p: POSSL_PARAM; val: PPIdAnsiChar; max_len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_get_utf8_string}

  OSSL_PARAM_set_utf8_string: function(p: POSSL_PARAM; val: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_set_utf8_string}

  OSSL_PARAM_get_octet_string: function(p: POSSL_PARAM; val: PPointer; max_len: TIdC_SIZET; used_len: PIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_get_octet_string}

  OSSL_PARAM_set_octet_string: function(p: POSSL_PARAM; val: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_set_octet_string}

  OSSL_PARAM_get_utf8_ptr: function(p: POSSL_PARAM; val: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_get_utf8_ptr}

  OSSL_PARAM_set_utf8_ptr: function(p: POSSL_PARAM; val: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_set_utf8_ptr}

  OSSL_PARAM_get_octet_ptr: function(p: POSSL_PARAM; val: PPointer; used_len: PIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_get_octet_ptr}

  OSSL_PARAM_set_octet_ptr: function(p: POSSL_PARAM; val: Pointer; used_len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_set_octet_ptr}

  OSSL_PARAM_get_utf8_string_ptr: function(p: POSSL_PARAM; val: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_get_utf8_string_ptr}

  OSSL_PARAM_get_octet_string_ptr: function(p: POSSL_PARAM; val: PPointer; used_len: PIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_get_octet_string_ptr}

  OSSL_PARAM_modified: function(p: POSSL_PARAM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_modified}

  OSSL_PARAM_set_all_unmodified: function(p: POSSL_PARAM): void; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_set_all_unmodified}

  OSSL_PARAM_dup: function(p: POSSL_PARAM): POSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_dup}

  OSSL_PARAM_merge: function(p1: POSSL_PARAM; p2: POSSL_PARAM): POSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_merge}

  OSSL_PARAM_free: function(p: POSSL_PARAM): void; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_free}

  OSSL_PARAM_set_octet_string_or_ptr: function(p: POSSL_PARAM; val: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_set_octet_string_or_ptr}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function OSSL_PARAM_locate(p: POSSL_PARAM; key: PIdAnsiChar): POSSL_PARAM; cdecl;
function OSSL_PARAM_locate_const(p: POSSL_PARAM; key: PIdAnsiChar): POSSL_PARAM; cdecl;
function OSSL_PARAM_construct_int(key: PIdAnsiChar; buf: PIdC_INT): TOSSL_PARAM; cdecl;
function OSSL_PARAM_construct_uint(key: PIdAnsiChar; buf: PIdC_UINT): TOSSL_PARAM; cdecl;
function OSSL_PARAM_construct_long(key: PIdAnsiChar; buf: PIdC_LONG): TOSSL_PARAM; cdecl;
function OSSL_PARAM_construct_ulong(key: PIdAnsiChar; buf: PIdC_ULONG): TOSSL_PARAM; cdecl;
function OSSL_PARAM_construct_int32(key: PIdAnsiChar; buf: PIdC_INT32): TOSSL_PARAM; cdecl;
function OSSL_PARAM_construct_uint32(key: PIdAnsiChar; buf: PIdC_UINT32): TOSSL_PARAM; cdecl;
function OSSL_PARAM_construct_int64(key: PIdAnsiChar; buf: PIdC_INT64): TOSSL_PARAM; cdecl;
function OSSL_PARAM_construct_uint64(key: PIdAnsiChar; buf: PIdC_UINT64): TOSSL_PARAM; cdecl;
function OSSL_PARAM_construct_size_t(key: PIdAnsiChar; buf: PIdC_SIZET): TOSSL_PARAM; cdecl;
function OSSL_PARAM_construct_time_t(key: PIdAnsiChar; buf: PIdC_TIMET): TOSSL_PARAM; cdecl;
function OSSL_PARAM_construct_BN(key: PIdAnsiChar; buf: PIdAnsiChar; bsize: TIdC_SIZET): TOSSL_PARAM; cdecl;
function OSSL_PARAM_construct_double(key: PIdAnsiChar; buf: PIdC_DOUBLE): TOSSL_PARAM; cdecl;
function OSSL_PARAM_construct_utf8_string(key: PIdAnsiChar; buf: PIdAnsiChar; bsize: TIdC_SIZET): TOSSL_PARAM; cdecl;
function OSSL_PARAM_construct_utf8_ptr(key: PIdAnsiChar; buf: PPIdAnsiChar; bsize: TIdC_SIZET): TOSSL_PARAM; cdecl;
function OSSL_PARAM_construct_octet_string(key: PIdAnsiChar; buf: Pointer; bsize: TIdC_SIZET): TOSSL_PARAM; cdecl;
function OSSL_PARAM_construct_octet_ptr(key: PIdAnsiChar; buf: PPointer; bsize: TIdC_SIZET): TOSSL_PARAM; cdecl;
function OSSL_PARAM_construct_end: TOSSL_PARAM; cdecl;
function OSSL_PARAM_allocate_from_text(_to: POSSL_PARAM; paramdefs: POSSL_PARAM; key: PIdAnsiChar; value: PIdAnsiChar; value_n: TIdC_SIZET; found: PIdC_INT): TIdC_INT; cdecl;
function OSSL_PARAM_print_to_bio(params: POSSL_PARAM; bio: PBIO; print_values: TIdC_INT): TIdC_INT; cdecl;
function OSSL_PARAM_get_int(p: POSSL_PARAM; val: PIdC_INT): TIdC_INT; cdecl;
function OSSL_PARAM_get_uint(p: POSSL_PARAM; val: PIdC_UINT): TIdC_INT; cdecl;
function OSSL_PARAM_get_long(p: POSSL_PARAM; val: PIdC_LONG): TIdC_INT; cdecl;
function OSSL_PARAM_get_ulong(p: POSSL_PARAM; val: PIdC_ULONG): TIdC_INT; cdecl;
function OSSL_PARAM_get_int32(p: POSSL_PARAM; val: PIdC_INT32): TIdC_INT; cdecl;
function OSSL_PARAM_get_uint32(p: POSSL_PARAM; val: PIdC_UINT32): TIdC_INT; cdecl;
function OSSL_PARAM_get_int64(p: POSSL_PARAM; val: PIdC_INT64): TIdC_INT; cdecl;
function OSSL_PARAM_get_uint64(p: POSSL_PARAM; val: PIdC_UINT64): TIdC_INT; cdecl;
function OSSL_PARAM_get_size_t(p: POSSL_PARAM; val: PIdC_SIZET): TIdC_INT; cdecl;
function OSSL_PARAM_get_time_t(p: POSSL_PARAM; val: PIdC_TIMET): TIdC_INT; cdecl;
function OSSL_PARAM_set_int(p: POSSL_PARAM; val: TIdC_INT): TIdC_INT; cdecl;
function OSSL_PARAM_set_uint(p: POSSL_PARAM; val: TIdC_UINT): TIdC_INT; cdecl;
function OSSL_PARAM_set_long(p: POSSL_PARAM; val: TIdC_LONG): TIdC_INT; cdecl;
function OSSL_PARAM_set_ulong(p: POSSL_PARAM; val: TIdC_ULONG): TIdC_INT; cdecl;
function OSSL_PARAM_set_int32(p: POSSL_PARAM; val: TIdC_INT32): TIdC_INT; cdecl;
function OSSL_PARAM_set_uint32(p: POSSL_PARAM; val: TIdC_UINT32): TIdC_INT; cdecl;
function OSSL_PARAM_set_int64(p: POSSL_PARAM; val: TIdC_INT64): TIdC_INT; cdecl;
function OSSL_PARAM_set_uint64(p: POSSL_PARAM; val: TIdC_UINT64): TIdC_INT; cdecl;
function OSSL_PARAM_set_size_t(p: POSSL_PARAM; val: TIdC_SIZET): TIdC_INT; cdecl;
function OSSL_PARAM_set_time_t(p: POSSL_PARAM; val: TIdC_TIMET): TIdC_INT; cdecl;
function OSSL_PARAM_get_double(p: POSSL_PARAM; val: PIdC_DOUBLE): TIdC_INT; cdecl;
function OSSL_PARAM_set_double(p: POSSL_PARAM; val: TIdC_DOUBLE): TIdC_INT; cdecl;
function OSSL_PARAM_get_BN(p: POSSL_PARAM; val: PPBIGNUM): TIdC_INT; cdecl;
function OSSL_PARAM_set_BN(p: POSSL_PARAM; val: PBIGNUM): TIdC_INT; cdecl;
function OSSL_PARAM_get_utf8_string(p: POSSL_PARAM; val: PPIdAnsiChar; max_len: TIdC_SIZET): TIdC_INT; cdecl;
function OSSL_PARAM_set_utf8_string(p: POSSL_PARAM; val: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_PARAM_get_octet_string(p: POSSL_PARAM; val: PPointer; max_len: TIdC_SIZET; used_len: PIdC_SIZET): TIdC_INT; cdecl;
function OSSL_PARAM_set_octet_string(p: POSSL_PARAM; val: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl;
function OSSL_PARAM_get_utf8_ptr(p: POSSL_PARAM; val: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_PARAM_set_utf8_ptr(p: POSSL_PARAM; val: PIdAnsiChar): TIdC_INT; cdecl;
function OSSL_PARAM_get_octet_ptr(p: POSSL_PARAM; val: PPointer; used_len: PIdC_SIZET): TIdC_INT; cdecl;
function OSSL_PARAM_set_octet_ptr(p: POSSL_PARAM; val: Pointer; used_len: TIdC_SIZET): TIdC_INT; cdecl;
function OSSL_PARAM_get_utf8_string_ptr(p: POSSL_PARAM; val: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_PARAM_get_octet_string_ptr(p: POSSL_PARAM; val: PPointer; used_len: PIdC_SIZET): TIdC_INT; cdecl;
function OSSL_PARAM_modified(p: POSSL_PARAM): TIdC_INT; cdecl;
function OSSL_PARAM_set_all_unmodified(p: POSSL_PARAM): void; cdecl;
function OSSL_PARAM_dup(p: POSSL_PARAM): POSSL_PARAM; cdecl;
function OSSL_PARAM_merge(p1: POSSL_PARAM; p2: POSSL_PARAM): POSSL_PARAM; cdecl;
function OSSL_PARAM_free(p: POSSL_PARAM): void; cdecl;
function OSSL_PARAM_set_octet_string_or_ptr(p: POSSL_PARAM; val: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OSSL_PARAM_BN(key: Pointer; bn: Pointer; sz: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OSSL_PARAM_utf8_string(key: Pointer; addr: Pointer; sz: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OSSL_PARAM_octet_string(key: Pointer; addr: Pointer; sz: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OSSL_PARAM_utf8_ptr(key: Pointer; addr: Pointer; sz: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function OSSL_PARAM_octet_ptr(key: Pointer; addr: Pointer; sz: Pointer): TIdC_INT; cdecl;


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

function OSSL_PARAM_locate(p: POSSL_PARAM; key: PIdAnsiChar): POSSL_PARAM; cdecl external CLibCrypto name 'OSSL_PARAM_locate';
function OSSL_PARAM_locate_const(p: POSSL_PARAM; key: PIdAnsiChar): POSSL_PARAM; cdecl external CLibCrypto name 'OSSL_PARAM_locate_const';
function OSSL_PARAM_construct_int(key: PIdAnsiChar; buf: PIdC_INT): TOSSL_PARAM; cdecl external CLibCrypto name 'OSSL_PARAM_construct_int';
function OSSL_PARAM_construct_uint(key: PIdAnsiChar; buf: PIdC_UINT): TOSSL_PARAM; cdecl external CLibCrypto name 'OSSL_PARAM_construct_uint';
function OSSL_PARAM_construct_long(key: PIdAnsiChar; buf: PIdC_LONG): TOSSL_PARAM; cdecl external CLibCrypto name 'OSSL_PARAM_construct_long';
function OSSL_PARAM_construct_ulong(key: PIdAnsiChar; buf: PIdC_ULONG): TOSSL_PARAM; cdecl external CLibCrypto name 'OSSL_PARAM_construct_ulong';
function OSSL_PARAM_construct_int32(key: PIdAnsiChar; buf: PIdC_INT32): TOSSL_PARAM; cdecl external CLibCrypto name 'OSSL_PARAM_construct_int32';
function OSSL_PARAM_construct_uint32(key: PIdAnsiChar; buf: PIdC_UINT32): TOSSL_PARAM; cdecl external CLibCrypto name 'OSSL_PARAM_construct_uint32';
function OSSL_PARAM_construct_int64(key: PIdAnsiChar; buf: PIdC_INT64): TOSSL_PARAM; cdecl external CLibCrypto name 'OSSL_PARAM_construct_int64';
function OSSL_PARAM_construct_uint64(key: PIdAnsiChar; buf: PIdC_UINT64): TOSSL_PARAM; cdecl external CLibCrypto name 'OSSL_PARAM_construct_uint64';
function OSSL_PARAM_construct_size_t(key: PIdAnsiChar; buf: PIdC_SIZET): TOSSL_PARAM; cdecl external CLibCrypto name 'OSSL_PARAM_construct_size_t';
function OSSL_PARAM_construct_time_t(key: PIdAnsiChar; buf: PIdC_TIMET): TOSSL_PARAM; cdecl external CLibCrypto name 'OSSL_PARAM_construct_time_t';
function OSSL_PARAM_construct_BN(key: PIdAnsiChar; buf: PIdAnsiChar; bsize: TIdC_SIZET): TOSSL_PARAM; cdecl external CLibCrypto name 'OSSL_PARAM_construct_BN';
function OSSL_PARAM_construct_double(key: PIdAnsiChar; buf: PIdC_DOUBLE): TOSSL_PARAM; cdecl external CLibCrypto name 'OSSL_PARAM_construct_double';
function OSSL_PARAM_construct_utf8_string(key: PIdAnsiChar; buf: PIdAnsiChar; bsize: TIdC_SIZET): TOSSL_PARAM; cdecl external CLibCrypto name 'OSSL_PARAM_construct_utf8_string';
function OSSL_PARAM_construct_utf8_ptr(key: PIdAnsiChar; buf: PPIdAnsiChar; bsize: TIdC_SIZET): TOSSL_PARAM; cdecl external CLibCrypto name 'OSSL_PARAM_construct_utf8_ptr';
function OSSL_PARAM_construct_octet_string(key: PIdAnsiChar; buf: Pointer; bsize: TIdC_SIZET): TOSSL_PARAM; cdecl external CLibCrypto name 'OSSL_PARAM_construct_octet_string';
function OSSL_PARAM_construct_octet_ptr(key: PIdAnsiChar; buf: PPointer; bsize: TIdC_SIZET): TOSSL_PARAM; cdecl external CLibCrypto name 'OSSL_PARAM_construct_octet_ptr';
function OSSL_PARAM_construct_end: TOSSL_PARAM; cdecl external CLibCrypto name 'OSSL_PARAM_construct_end';
function OSSL_PARAM_allocate_from_text(_to: POSSL_PARAM; paramdefs: POSSL_PARAM; key: PIdAnsiChar; value: PIdAnsiChar; value_n: TIdC_SIZET; found: PIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_allocate_from_text';
function OSSL_PARAM_print_to_bio(params: POSSL_PARAM; bio: PBIO; print_values: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_print_to_bio';
function OSSL_PARAM_get_int(p: POSSL_PARAM; val: PIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_get_int';
function OSSL_PARAM_get_uint(p: POSSL_PARAM; val: PIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_get_uint';
function OSSL_PARAM_get_long(p: POSSL_PARAM; val: PIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_get_long';
function OSSL_PARAM_get_ulong(p: POSSL_PARAM; val: PIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_get_ulong';
function OSSL_PARAM_get_int32(p: POSSL_PARAM; val: PIdC_INT32): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_get_int32';
function OSSL_PARAM_get_uint32(p: POSSL_PARAM; val: PIdC_UINT32): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_get_uint32';
function OSSL_PARAM_get_int64(p: POSSL_PARAM; val: PIdC_INT64): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_get_int64';
function OSSL_PARAM_get_uint64(p: POSSL_PARAM; val: PIdC_UINT64): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_get_uint64';
function OSSL_PARAM_get_size_t(p: POSSL_PARAM; val: PIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_get_size_t';
function OSSL_PARAM_get_time_t(p: POSSL_PARAM; val: PIdC_TIMET): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_get_time_t';
function OSSL_PARAM_set_int(p: POSSL_PARAM; val: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_set_int';
function OSSL_PARAM_set_uint(p: POSSL_PARAM; val: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_set_uint';
function OSSL_PARAM_set_long(p: POSSL_PARAM; val: TIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_set_long';
function OSSL_PARAM_set_ulong(p: POSSL_PARAM; val: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_set_ulong';
function OSSL_PARAM_set_int32(p: POSSL_PARAM; val: TIdC_INT32): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_set_int32';
function OSSL_PARAM_set_uint32(p: POSSL_PARAM; val: TIdC_UINT32): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_set_uint32';
function OSSL_PARAM_set_int64(p: POSSL_PARAM; val: TIdC_INT64): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_set_int64';
function OSSL_PARAM_set_uint64(p: POSSL_PARAM; val: TIdC_UINT64): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_set_uint64';
function OSSL_PARAM_set_size_t(p: POSSL_PARAM; val: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_set_size_t';
function OSSL_PARAM_set_time_t(p: POSSL_PARAM; val: TIdC_TIMET): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_set_time_t';
function OSSL_PARAM_get_double(p: POSSL_PARAM; val: PIdC_DOUBLE): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_get_double';
function OSSL_PARAM_set_double(p: POSSL_PARAM; val: TIdC_DOUBLE): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_set_double';
function OSSL_PARAM_get_BN(p: POSSL_PARAM; val: PPBIGNUM): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_get_BN';
function OSSL_PARAM_set_BN(p: POSSL_PARAM; val: PBIGNUM): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_set_BN';
function OSSL_PARAM_get_utf8_string(p: POSSL_PARAM; val: PPIdAnsiChar; max_len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_get_utf8_string';
function OSSL_PARAM_set_utf8_string(p: POSSL_PARAM; val: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_set_utf8_string';
function OSSL_PARAM_get_octet_string(p: POSSL_PARAM; val: PPointer; max_len: TIdC_SIZET; used_len: PIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_get_octet_string';
function OSSL_PARAM_set_octet_string(p: POSSL_PARAM; val: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_set_octet_string';
function OSSL_PARAM_get_utf8_ptr(p: POSSL_PARAM; val: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_get_utf8_ptr';
function OSSL_PARAM_set_utf8_ptr(p: POSSL_PARAM; val: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_set_utf8_ptr';
function OSSL_PARAM_get_octet_ptr(p: POSSL_PARAM; val: PPointer; used_len: PIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_get_octet_ptr';
function OSSL_PARAM_set_octet_ptr(p: POSSL_PARAM; val: Pointer; used_len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_set_octet_ptr';
function OSSL_PARAM_get_utf8_string_ptr(p: POSSL_PARAM; val: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_get_utf8_string_ptr';
function OSSL_PARAM_get_octet_string_ptr(p: POSSL_PARAM; val: PPointer; used_len: PIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_get_octet_string_ptr';
function OSSL_PARAM_modified(p: POSSL_PARAM): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_modified';
function OSSL_PARAM_set_all_unmodified(p: POSSL_PARAM): void; cdecl external CLibCrypto name 'OSSL_PARAM_set_all_unmodified';
function OSSL_PARAM_dup(p: POSSL_PARAM): POSSL_PARAM; cdecl external CLibCrypto name 'OSSL_PARAM_dup';
function OSSL_PARAM_merge(p1: POSSL_PARAM; p2: POSSL_PARAM): POSSL_PARAM; cdecl external CLibCrypto name 'OSSL_PARAM_merge';
function OSSL_PARAM_free(p: POSSL_PARAM): void; cdecl external CLibCrypto name 'OSSL_PARAM_free';
function OSSL_PARAM_set_octet_string_or_ptr(p: POSSL_PARAM; val: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_set_octet_string_or_ptr';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  OSSL_PARAM_locate_procname = 'OSSL_PARAM_locate';
  OSSL_PARAM_locate_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_locate_const_procname = 'OSSL_PARAM_locate_const';
  OSSL_PARAM_locate_const_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_construct_int_procname = 'OSSL_PARAM_construct_int';
  OSSL_PARAM_construct_int_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_construct_uint_procname = 'OSSL_PARAM_construct_uint';
  OSSL_PARAM_construct_uint_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_construct_long_procname = 'OSSL_PARAM_construct_long';
  OSSL_PARAM_construct_long_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_construct_ulong_procname = 'OSSL_PARAM_construct_ulong';
  OSSL_PARAM_construct_ulong_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_construct_int32_procname = 'OSSL_PARAM_construct_int32';
  OSSL_PARAM_construct_int32_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_construct_uint32_procname = 'OSSL_PARAM_construct_uint32';
  OSSL_PARAM_construct_uint32_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_construct_int64_procname = 'OSSL_PARAM_construct_int64';
  OSSL_PARAM_construct_int64_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_construct_uint64_procname = 'OSSL_PARAM_construct_uint64';
  OSSL_PARAM_construct_uint64_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_construct_size_t_procname = 'OSSL_PARAM_construct_size_t';
  OSSL_PARAM_construct_size_t_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_construct_time_t_procname = 'OSSL_PARAM_construct_time_t';
  OSSL_PARAM_construct_time_t_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_construct_BN_procname = 'OSSL_PARAM_construct_BN';
  OSSL_PARAM_construct_BN_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_construct_double_procname = 'OSSL_PARAM_construct_double';
  OSSL_PARAM_construct_double_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_construct_utf8_string_procname = 'OSSL_PARAM_construct_utf8_string';
  OSSL_PARAM_construct_utf8_string_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_construct_utf8_ptr_procname = 'OSSL_PARAM_construct_utf8_ptr';
  OSSL_PARAM_construct_utf8_ptr_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_construct_octet_string_procname = 'OSSL_PARAM_construct_octet_string';
  OSSL_PARAM_construct_octet_string_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_construct_octet_ptr_procname = 'OSSL_PARAM_construct_octet_ptr';
  OSSL_PARAM_construct_octet_ptr_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_construct_end_procname = 'OSSL_PARAM_construct_end';
  OSSL_PARAM_construct_end_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_allocate_from_text_procname = 'OSSL_PARAM_allocate_from_text';
  OSSL_PARAM_allocate_from_text_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_print_to_bio_procname = 'OSSL_PARAM_print_to_bio';
  OSSL_PARAM_print_to_bio_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_PARAM_get_int_procname = 'OSSL_PARAM_get_int';
  OSSL_PARAM_get_int_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_get_uint_procname = 'OSSL_PARAM_get_uint';
  OSSL_PARAM_get_uint_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_get_long_procname = 'OSSL_PARAM_get_long';
  OSSL_PARAM_get_long_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_get_ulong_procname = 'OSSL_PARAM_get_ulong';
  OSSL_PARAM_get_ulong_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_get_int32_procname = 'OSSL_PARAM_get_int32';
  OSSL_PARAM_get_int32_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_get_uint32_procname = 'OSSL_PARAM_get_uint32';
  OSSL_PARAM_get_uint32_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_get_int64_procname = 'OSSL_PARAM_get_int64';
  OSSL_PARAM_get_int64_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_get_uint64_procname = 'OSSL_PARAM_get_uint64';
  OSSL_PARAM_get_uint64_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_get_size_t_procname = 'OSSL_PARAM_get_size_t';
  OSSL_PARAM_get_size_t_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_get_time_t_procname = 'OSSL_PARAM_get_time_t';
  OSSL_PARAM_get_time_t_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_set_int_procname = 'OSSL_PARAM_set_int';
  OSSL_PARAM_set_int_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_set_uint_procname = 'OSSL_PARAM_set_uint';
  OSSL_PARAM_set_uint_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_set_long_procname = 'OSSL_PARAM_set_long';
  OSSL_PARAM_set_long_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_set_ulong_procname = 'OSSL_PARAM_set_ulong';
  OSSL_PARAM_set_ulong_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_set_int32_procname = 'OSSL_PARAM_set_int32';
  OSSL_PARAM_set_int32_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_set_uint32_procname = 'OSSL_PARAM_set_uint32';
  OSSL_PARAM_set_uint32_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_set_int64_procname = 'OSSL_PARAM_set_int64';
  OSSL_PARAM_set_int64_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_set_uint64_procname = 'OSSL_PARAM_set_uint64';
  OSSL_PARAM_set_uint64_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_set_size_t_procname = 'OSSL_PARAM_set_size_t';
  OSSL_PARAM_set_size_t_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_set_time_t_procname = 'OSSL_PARAM_set_time_t';
  OSSL_PARAM_set_time_t_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_get_double_procname = 'OSSL_PARAM_get_double';
  OSSL_PARAM_get_double_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_set_double_procname = 'OSSL_PARAM_set_double';
  OSSL_PARAM_set_double_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_get_BN_procname = 'OSSL_PARAM_get_BN';
  OSSL_PARAM_get_BN_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_set_BN_procname = 'OSSL_PARAM_set_BN';
  OSSL_PARAM_set_BN_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_get_utf8_string_procname = 'OSSL_PARAM_get_utf8_string';
  OSSL_PARAM_get_utf8_string_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_set_utf8_string_procname = 'OSSL_PARAM_set_utf8_string';
  OSSL_PARAM_set_utf8_string_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_get_octet_string_procname = 'OSSL_PARAM_get_octet_string';
  OSSL_PARAM_get_octet_string_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_set_octet_string_procname = 'OSSL_PARAM_set_octet_string';
  OSSL_PARAM_set_octet_string_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_get_utf8_ptr_procname = 'OSSL_PARAM_get_utf8_ptr';
  OSSL_PARAM_get_utf8_ptr_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_set_utf8_ptr_procname = 'OSSL_PARAM_set_utf8_ptr';
  OSSL_PARAM_set_utf8_ptr_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_get_octet_ptr_procname = 'OSSL_PARAM_get_octet_ptr';
  OSSL_PARAM_get_octet_ptr_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_set_octet_ptr_procname = 'OSSL_PARAM_set_octet_ptr';
  OSSL_PARAM_set_octet_ptr_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_get_utf8_string_ptr_procname = 'OSSL_PARAM_get_utf8_string_ptr';
  OSSL_PARAM_get_utf8_string_ptr_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_get_octet_string_ptr_procname = 'OSSL_PARAM_get_octet_string_ptr';
  OSSL_PARAM_get_octet_string_ptr_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_modified_procname = 'OSSL_PARAM_modified';
  OSSL_PARAM_modified_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_set_all_unmodified_procname = 'OSSL_PARAM_set_all_unmodified';
  OSSL_PARAM_set_all_unmodified_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_dup_procname = 'OSSL_PARAM_dup';
  OSSL_PARAM_dup_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_merge_procname = 'OSSL_PARAM_merge';
  OSSL_PARAM_merge_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_free_procname = 'OSSL_PARAM_free';
  OSSL_PARAM_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_set_octet_string_or_ptr_procname = 'OSSL_PARAM_set_octet_string_or_ptr';
  OSSL_PARAM_set_octet_string_or_ptr_introduced = (byte(3) shl 8 or byte(6)) shl 8 or byte(0);

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function OSSL_PARAM_BN(key: Pointer; bn: Pointer; sz: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OSSL_PARAM_BN(key, bn, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (bn), (sz))
  }
end;

function OSSL_PARAM_utf8_string(key: Pointer; addr: Pointer; sz: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OSSL_PARAM_utf8_string(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UTF8_STRING, (addr), sz)
  }
end;

function OSSL_PARAM_octet_string(key: Pointer; addr: Pointer; sz: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OSSL_PARAM_octet_string(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_OCTET_STRING, (addr), sz)
  }
end;

function OSSL_PARAM_utf8_ptr(key: Pointer; addr: Pointer; sz: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OSSL_PARAM_utf8_ptr(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_UTF8_PTR, (addr), sz)
  }
end;

function OSSL_PARAM_octet_ptr(key: Pointer; addr: Pointer; sz: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OSSL_PARAM_octet_ptr(key, addr, sz) \
    OSSL_PARAM_DEFN((key), OSSL_PARAM_OCTET_PTR, (addr), sz)
  }
end;

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_OSSL_PARAM_locate(p: POSSL_PARAM; key: PIdAnsiChar): POSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_locate_procname);
end;

function ERR_OSSL_PARAM_locate_const(p: POSSL_PARAM; key: PIdAnsiChar): POSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_locate_const_procname);
end;

function ERR_OSSL_PARAM_construct_int(key: PIdAnsiChar; buf: PIdC_INT): TOSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_construct_int_procname);
end;

function ERR_OSSL_PARAM_construct_uint(key: PIdAnsiChar; buf: PIdC_UINT): TOSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_construct_uint_procname);
end;

function ERR_OSSL_PARAM_construct_long(key: PIdAnsiChar; buf: PIdC_LONG): TOSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_construct_long_procname);
end;

function ERR_OSSL_PARAM_construct_ulong(key: PIdAnsiChar; buf: PIdC_ULONG): TOSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_construct_ulong_procname);
end;

function ERR_OSSL_PARAM_construct_int32(key: PIdAnsiChar; buf: PIdC_INT32): TOSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_construct_int32_procname);
end;

function ERR_OSSL_PARAM_construct_uint32(key: PIdAnsiChar; buf: PIdC_UINT32): TOSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_construct_uint32_procname);
end;

function ERR_OSSL_PARAM_construct_int64(key: PIdAnsiChar; buf: PIdC_INT64): TOSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_construct_int64_procname);
end;

function ERR_OSSL_PARAM_construct_uint64(key: PIdAnsiChar; buf: PIdC_UINT64): TOSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_construct_uint64_procname);
end;

function ERR_OSSL_PARAM_construct_size_t(key: PIdAnsiChar; buf: PIdC_SIZET): TOSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_construct_size_t_procname);
end;

function ERR_OSSL_PARAM_construct_time_t(key: PIdAnsiChar; buf: PIdC_TIMET): TOSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_construct_time_t_procname);
end;

function ERR_OSSL_PARAM_construct_BN(key: PIdAnsiChar; buf: PIdAnsiChar; bsize: TIdC_SIZET): TOSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_construct_BN_procname);
end;

function ERR_OSSL_PARAM_construct_double(key: PIdAnsiChar; buf: PIdC_DOUBLE): TOSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_construct_double_procname);
end;

function ERR_OSSL_PARAM_construct_utf8_string(key: PIdAnsiChar; buf: PIdAnsiChar; bsize: TIdC_SIZET): TOSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_construct_utf8_string_procname);
end;

function ERR_OSSL_PARAM_construct_utf8_ptr(key: PIdAnsiChar; buf: PPIdAnsiChar; bsize: TIdC_SIZET): TOSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_construct_utf8_ptr_procname);
end;

function ERR_OSSL_PARAM_construct_octet_string(key: PIdAnsiChar; buf: Pointer; bsize: TIdC_SIZET): TOSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_construct_octet_string_procname);
end;

function ERR_OSSL_PARAM_construct_octet_ptr(key: PIdAnsiChar; buf: PPointer; bsize: TIdC_SIZET): TOSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_construct_octet_ptr_procname);
end;

function ERR_OSSL_PARAM_construct_end: TOSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_construct_end_procname);
end;

function ERR_OSSL_PARAM_allocate_from_text(_to: POSSL_PARAM; paramdefs: POSSL_PARAM; key: PIdAnsiChar; value: PIdAnsiChar; value_n: TIdC_SIZET; found: PIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_allocate_from_text_procname);
end;

function ERR_OSSL_PARAM_print_to_bio(params: POSSL_PARAM; bio: PBIO; print_values: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_print_to_bio_procname);
end;

function ERR_OSSL_PARAM_get_int(p: POSSL_PARAM; val: PIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_get_int_procname);
end;

function ERR_OSSL_PARAM_get_uint(p: POSSL_PARAM; val: PIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_get_uint_procname);
end;

function ERR_OSSL_PARAM_get_long(p: POSSL_PARAM; val: PIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_get_long_procname);
end;

function ERR_OSSL_PARAM_get_ulong(p: POSSL_PARAM; val: PIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_get_ulong_procname);
end;

function ERR_OSSL_PARAM_get_int32(p: POSSL_PARAM; val: PIdC_INT32): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_get_int32_procname);
end;

function ERR_OSSL_PARAM_get_uint32(p: POSSL_PARAM; val: PIdC_UINT32): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_get_uint32_procname);
end;

function ERR_OSSL_PARAM_get_int64(p: POSSL_PARAM; val: PIdC_INT64): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_get_int64_procname);
end;

function ERR_OSSL_PARAM_get_uint64(p: POSSL_PARAM; val: PIdC_UINT64): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_get_uint64_procname);
end;

function ERR_OSSL_PARAM_get_size_t(p: POSSL_PARAM; val: PIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_get_size_t_procname);
end;

function ERR_OSSL_PARAM_get_time_t(p: POSSL_PARAM; val: PIdC_TIMET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_get_time_t_procname);
end;

function ERR_OSSL_PARAM_set_int(p: POSSL_PARAM; val: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_set_int_procname);
end;

function ERR_OSSL_PARAM_set_uint(p: POSSL_PARAM; val: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_set_uint_procname);
end;

function ERR_OSSL_PARAM_set_long(p: POSSL_PARAM; val: TIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_set_long_procname);
end;

function ERR_OSSL_PARAM_set_ulong(p: POSSL_PARAM; val: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_set_ulong_procname);
end;

function ERR_OSSL_PARAM_set_int32(p: POSSL_PARAM; val: TIdC_INT32): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_set_int32_procname);
end;

function ERR_OSSL_PARAM_set_uint32(p: POSSL_PARAM; val: TIdC_UINT32): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_set_uint32_procname);
end;

function ERR_OSSL_PARAM_set_int64(p: POSSL_PARAM; val: TIdC_INT64): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_set_int64_procname);
end;

function ERR_OSSL_PARAM_set_uint64(p: POSSL_PARAM; val: TIdC_UINT64): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_set_uint64_procname);
end;

function ERR_OSSL_PARAM_set_size_t(p: POSSL_PARAM; val: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_set_size_t_procname);
end;

function ERR_OSSL_PARAM_set_time_t(p: POSSL_PARAM; val: TIdC_TIMET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_set_time_t_procname);
end;

function ERR_OSSL_PARAM_get_double(p: POSSL_PARAM; val: PIdC_DOUBLE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_get_double_procname);
end;

function ERR_OSSL_PARAM_set_double(p: POSSL_PARAM; val: TIdC_DOUBLE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_set_double_procname);
end;

function ERR_OSSL_PARAM_get_BN(p: POSSL_PARAM; val: PPBIGNUM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_get_BN_procname);
end;

function ERR_OSSL_PARAM_set_BN(p: POSSL_PARAM; val: PBIGNUM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_set_BN_procname);
end;

function ERR_OSSL_PARAM_get_utf8_string(p: POSSL_PARAM; val: PPIdAnsiChar; max_len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_get_utf8_string_procname);
end;

function ERR_OSSL_PARAM_set_utf8_string(p: POSSL_PARAM; val: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_set_utf8_string_procname);
end;

function ERR_OSSL_PARAM_get_octet_string(p: POSSL_PARAM; val: PPointer; max_len: TIdC_SIZET; used_len: PIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_get_octet_string_procname);
end;

function ERR_OSSL_PARAM_set_octet_string(p: POSSL_PARAM; val: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_set_octet_string_procname);
end;

function ERR_OSSL_PARAM_get_utf8_ptr(p: POSSL_PARAM; val: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_get_utf8_ptr_procname);
end;

function ERR_OSSL_PARAM_set_utf8_ptr(p: POSSL_PARAM; val: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_set_utf8_ptr_procname);
end;

function ERR_OSSL_PARAM_get_octet_ptr(p: POSSL_PARAM; val: PPointer; used_len: PIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_get_octet_ptr_procname);
end;

function ERR_OSSL_PARAM_set_octet_ptr(p: POSSL_PARAM; val: Pointer; used_len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_set_octet_ptr_procname);
end;

function ERR_OSSL_PARAM_get_utf8_string_ptr(p: POSSL_PARAM; val: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_get_utf8_string_ptr_procname);
end;

function ERR_OSSL_PARAM_get_octet_string_ptr(p: POSSL_PARAM; val: PPointer; used_len: PIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_get_octet_string_ptr_procname);
end;

function ERR_OSSL_PARAM_modified(p: POSSL_PARAM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_modified_procname);
end;

function ERR_OSSL_PARAM_set_all_unmodified(p: POSSL_PARAM): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_set_all_unmodified_procname);
end;

function ERR_OSSL_PARAM_dup(p: POSSL_PARAM): POSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_dup_procname);
end;

function ERR_OSSL_PARAM_merge(p1: POSSL_PARAM; p2: POSSL_PARAM): POSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_merge_procname);
end;

function ERR_OSSL_PARAM_free(p: POSSL_PARAM): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_free_procname);
end;

function ERR_OSSL_PARAM_set_octet_string_or_ptr(p: POSSL_PARAM; val: Pointer; len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_set_octet_string_or_ptr_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  OSSL_PARAM_locate := LoadLibFunction(ADllHandle, OSSL_PARAM_locate_procname);
  FuncLoadError := not assigned(OSSL_PARAM_locate);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_locate_allownil)}
    OSSL_PARAM_locate := ERR_OSSL_PARAM_locate;
    {$ifend}
    {$if declared(OSSL_PARAM_locate_introduced)}
    if LibVersion < OSSL_PARAM_locate_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_locate)}
      OSSL_PARAM_locate := FC_OSSL_PARAM_locate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_locate_removed)}
    if OSSL_PARAM_locate_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_locate)}
      OSSL_PARAM_locate := _OSSL_PARAM_locate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_locate_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_locate');
    {$ifend}
  end;
  
  OSSL_PARAM_locate_const := LoadLibFunction(ADllHandle, OSSL_PARAM_locate_const_procname);
  FuncLoadError := not assigned(OSSL_PARAM_locate_const);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_locate_const_allownil)}
    OSSL_PARAM_locate_const := ERR_OSSL_PARAM_locate_const;
    {$ifend}
    {$if declared(OSSL_PARAM_locate_const_introduced)}
    if LibVersion < OSSL_PARAM_locate_const_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_locate_const)}
      OSSL_PARAM_locate_const := FC_OSSL_PARAM_locate_const;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_locate_const_removed)}
    if OSSL_PARAM_locate_const_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_locate_const)}
      OSSL_PARAM_locate_const := _OSSL_PARAM_locate_const;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_locate_const_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_locate_const');
    {$ifend}
  end;
  
  OSSL_PARAM_construct_int := LoadLibFunction(ADllHandle, OSSL_PARAM_construct_int_procname);
  FuncLoadError := not assigned(OSSL_PARAM_construct_int);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_construct_int_allownil)}
    OSSL_PARAM_construct_int := ERR_OSSL_PARAM_construct_int;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_int_introduced)}
    if LibVersion < OSSL_PARAM_construct_int_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_construct_int)}
      OSSL_PARAM_construct_int := FC_OSSL_PARAM_construct_int;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_int_removed)}
    if OSSL_PARAM_construct_int_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_construct_int)}
      OSSL_PARAM_construct_int := _OSSL_PARAM_construct_int;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_construct_int_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_construct_int');
    {$ifend}
  end;
  
  OSSL_PARAM_construct_uint := LoadLibFunction(ADllHandle, OSSL_PARAM_construct_uint_procname);
  FuncLoadError := not assigned(OSSL_PARAM_construct_uint);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_construct_uint_allownil)}
    OSSL_PARAM_construct_uint := ERR_OSSL_PARAM_construct_uint;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_uint_introduced)}
    if LibVersion < OSSL_PARAM_construct_uint_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_construct_uint)}
      OSSL_PARAM_construct_uint := FC_OSSL_PARAM_construct_uint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_uint_removed)}
    if OSSL_PARAM_construct_uint_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_construct_uint)}
      OSSL_PARAM_construct_uint := _OSSL_PARAM_construct_uint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_construct_uint_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_construct_uint');
    {$ifend}
  end;
  
  OSSL_PARAM_construct_long := LoadLibFunction(ADllHandle, OSSL_PARAM_construct_long_procname);
  FuncLoadError := not assigned(OSSL_PARAM_construct_long);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_construct_long_allownil)}
    OSSL_PARAM_construct_long := ERR_OSSL_PARAM_construct_long;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_long_introduced)}
    if LibVersion < OSSL_PARAM_construct_long_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_construct_long)}
      OSSL_PARAM_construct_long := FC_OSSL_PARAM_construct_long;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_long_removed)}
    if OSSL_PARAM_construct_long_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_construct_long)}
      OSSL_PARAM_construct_long := _OSSL_PARAM_construct_long;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_construct_long_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_construct_long');
    {$ifend}
  end;
  
  OSSL_PARAM_construct_ulong := LoadLibFunction(ADllHandle, OSSL_PARAM_construct_ulong_procname);
  FuncLoadError := not assigned(OSSL_PARAM_construct_ulong);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_construct_ulong_allownil)}
    OSSL_PARAM_construct_ulong := ERR_OSSL_PARAM_construct_ulong;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_ulong_introduced)}
    if LibVersion < OSSL_PARAM_construct_ulong_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_construct_ulong)}
      OSSL_PARAM_construct_ulong := FC_OSSL_PARAM_construct_ulong;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_ulong_removed)}
    if OSSL_PARAM_construct_ulong_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_construct_ulong)}
      OSSL_PARAM_construct_ulong := _OSSL_PARAM_construct_ulong;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_construct_ulong_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_construct_ulong');
    {$ifend}
  end;
  
  OSSL_PARAM_construct_int32 := LoadLibFunction(ADllHandle, OSSL_PARAM_construct_int32_procname);
  FuncLoadError := not assigned(OSSL_PARAM_construct_int32);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_construct_int32_allownil)}
    OSSL_PARAM_construct_int32 := ERR_OSSL_PARAM_construct_int32;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_int32_introduced)}
    if LibVersion < OSSL_PARAM_construct_int32_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_construct_int32)}
      OSSL_PARAM_construct_int32 := FC_OSSL_PARAM_construct_int32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_int32_removed)}
    if OSSL_PARAM_construct_int32_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_construct_int32)}
      OSSL_PARAM_construct_int32 := _OSSL_PARAM_construct_int32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_construct_int32_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_construct_int32');
    {$ifend}
  end;
  
  OSSL_PARAM_construct_uint32 := LoadLibFunction(ADllHandle, OSSL_PARAM_construct_uint32_procname);
  FuncLoadError := not assigned(OSSL_PARAM_construct_uint32);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_construct_uint32_allownil)}
    OSSL_PARAM_construct_uint32 := ERR_OSSL_PARAM_construct_uint32;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_uint32_introduced)}
    if LibVersion < OSSL_PARAM_construct_uint32_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_construct_uint32)}
      OSSL_PARAM_construct_uint32 := FC_OSSL_PARAM_construct_uint32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_uint32_removed)}
    if OSSL_PARAM_construct_uint32_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_construct_uint32)}
      OSSL_PARAM_construct_uint32 := _OSSL_PARAM_construct_uint32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_construct_uint32_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_construct_uint32');
    {$ifend}
  end;
  
  OSSL_PARAM_construct_int64 := LoadLibFunction(ADllHandle, OSSL_PARAM_construct_int64_procname);
  FuncLoadError := not assigned(OSSL_PARAM_construct_int64);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_construct_int64_allownil)}
    OSSL_PARAM_construct_int64 := ERR_OSSL_PARAM_construct_int64;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_int64_introduced)}
    if LibVersion < OSSL_PARAM_construct_int64_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_construct_int64)}
      OSSL_PARAM_construct_int64 := FC_OSSL_PARAM_construct_int64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_int64_removed)}
    if OSSL_PARAM_construct_int64_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_construct_int64)}
      OSSL_PARAM_construct_int64 := _OSSL_PARAM_construct_int64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_construct_int64_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_construct_int64');
    {$ifend}
  end;
  
  OSSL_PARAM_construct_uint64 := LoadLibFunction(ADllHandle, OSSL_PARAM_construct_uint64_procname);
  FuncLoadError := not assigned(OSSL_PARAM_construct_uint64);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_construct_uint64_allownil)}
    OSSL_PARAM_construct_uint64 := ERR_OSSL_PARAM_construct_uint64;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_uint64_introduced)}
    if LibVersion < OSSL_PARAM_construct_uint64_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_construct_uint64)}
      OSSL_PARAM_construct_uint64 := FC_OSSL_PARAM_construct_uint64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_uint64_removed)}
    if OSSL_PARAM_construct_uint64_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_construct_uint64)}
      OSSL_PARAM_construct_uint64 := _OSSL_PARAM_construct_uint64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_construct_uint64_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_construct_uint64');
    {$ifend}
  end;
  
  OSSL_PARAM_construct_size_t := LoadLibFunction(ADllHandle, OSSL_PARAM_construct_size_t_procname);
  FuncLoadError := not assigned(OSSL_PARAM_construct_size_t);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_construct_size_t_allownil)}
    OSSL_PARAM_construct_size_t := ERR_OSSL_PARAM_construct_size_t;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_size_t_introduced)}
    if LibVersion < OSSL_PARAM_construct_size_t_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_construct_size_t)}
      OSSL_PARAM_construct_size_t := FC_OSSL_PARAM_construct_size_t;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_size_t_removed)}
    if OSSL_PARAM_construct_size_t_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_construct_size_t)}
      OSSL_PARAM_construct_size_t := _OSSL_PARAM_construct_size_t;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_construct_size_t_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_construct_size_t');
    {$ifend}
  end;
  
  OSSL_PARAM_construct_time_t := LoadLibFunction(ADllHandle, OSSL_PARAM_construct_time_t_procname);
  FuncLoadError := not assigned(OSSL_PARAM_construct_time_t);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_construct_time_t_allownil)}
    OSSL_PARAM_construct_time_t := ERR_OSSL_PARAM_construct_time_t;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_time_t_introduced)}
    if LibVersion < OSSL_PARAM_construct_time_t_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_construct_time_t)}
      OSSL_PARAM_construct_time_t := FC_OSSL_PARAM_construct_time_t;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_time_t_removed)}
    if OSSL_PARAM_construct_time_t_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_construct_time_t)}
      OSSL_PARAM_construct_time_t := _OSSL_PARAM_construct_time_t;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_construct_time_t_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_construct_time_t');
    {$ifend}
  end;
  
  OSSL_PARAM_construct_BN := LoadLibFunction(ADllHandle, OSSL_PARAM_construct_BN_procname);
  FuncLoadError := not assigned(OSSL_PARAM_construct_BN);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_construct_BN_allownil)}
    OSSL_PARAM_construct_BN := ERR_OSSL_PARAM_construct_BN;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_BN_introduced)}
    if LibVersion < OSSL_PARAM_construct_BN_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_construct_BN)}
      OSSL_PARAM_construct_BN := FC_OSSL_PARAM_construct_BN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_BN_removed)}
    if OSSL_PARAM_construct_BN_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_construct_BN)}
      OSSL_PARAM_construct_BN := _OSSL_PARAM_construct_BN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_construct_BN_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_construct_BN');
    {$ifend}
  end;
  
  OSSL_PARAM_construct_double := LoadLibFunction(ADllHandle, OSSL_PARAM_construct_double_procname);
  FuncLoadError := not assigned(OSSL_PARAM_construct_double);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_construct_double_allownil)}
    OSSL_PARAM_construct_double := ERR_OSSL_PARAM_construct_double;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_double_introduced)}
    if LibVersion < OSSL_PARAM_construct_double_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_construct_double)}
      OSSL_PARAM_construct_double := FC_OSSL_PARAM_construct_double;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_double_removed)}
    if OSSL_PARAM_construct_double_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_construct_double)}
      OSSL_PARAM_construct_double := _OSSL_PARAM_construct_double;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_construct_double_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_construct_double');
    {$ifend}
  end;
  
  OSSL_PARAM_construct_utf8_string := LoadLibFunction(ADllHandle, OSSL_PARAM_construct_utf8_string_procname);
  FuncLoadError := not assigned(OSSL_PARAM_construct_utf8_string);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_construct_utf8_string_allownil)}
    OSSL_PARAM_construct_utf8_string := ERR_OSSL_PARAM_construct_utf8_string;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_utf8_string_introduced)}
    if LibVersion < OSSL_PARAM_construct_utf8_string_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_construct_utf8_string)}
      OSSL_PARAM_construct_utf8_string := FC_OSSL_PARAM_construct_utf8_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_utf8_string_removed)}
    if OSSL_PARAM_construct_utf8_string_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_construct_utf8_string)}
      OSSL_PARAM_construct_utf8_string := _OSSL_PARAM_construct_utf8_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_construct_utf8_string_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_construct_utf8_string');
    {$ifend}
  end;
  
  OSSL_PARAM_construct_utf8_ptr := LoadLibFunction(ADllHandle, OSSL_PARAM_construct_utf8_ptr_procname);
  FuncLoadError := not assigned(OSSL_PARAM_construct_utf8_ptr);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_construct_utf8_ptr_allownil)}
    OSSL_PARAM_construct_utf8_ptr := ERR_OSSL_PARAM_construct_utf8_ptr;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_utf8_ptr_introduced)}
    if LibVersion < OSSL_PARAM_construct_utf8_ptr_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_construct_utf8_ptr)}
      OSSL_PARAM_construct_utf8_ptr := FC_OSSL_PARAM_construct_utf8_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_utf8_ptr_removed)}
    if OSSL_PARAM_construct_utf8_ptr_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_construct_utf8_ptr)}
      OSSL_PARAM_construct_utf8_ptr := _OSSL_PARAM_construct_utf8_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_construct_utf8_ptr_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_construct_utf8_ptr');
    {$ifend}
  end;
  
  OSSL_PARAM_construct_octet_string := LoadLibFunction(ADllHandle, OSSL_PARAM_construct_octet_string_procname);
  FuncLoadError := not assigned(OSSL_PARAM_construct_octet_string);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_construct_octet_string_allownil)}
    OSSL_PARAM_construct_octet_string := ERR_OSSL_PARAM_construct_octet_string;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_octet_string_introduced)}
    if LibVersion < OSSL_PARAM_construct_octet_string_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_construct_octet_string)}
      OSSL_PARAM_construct_octet_string := FC_OSSL_PARAM_construct_octet_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_octet_string_removed)}
    if OSSL_PARAM_construct_octet_string_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_construct_octet_string)}
      OSSL_PARAM_construct_octet_string := _OSSL_PARAM_construct_octet_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_construct_octet_string_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_construct_octet_string');
    {$ifend}
  end;
  
  OSSL_PARAM_construct_octet_ptr := LoadLibFunction(ADllHandle, OSSL_PARAM_construct_octet_ptr_procname);
  FuncLoadError := not assigned(OSSL_PARAM_construct_octet_ptr);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_construct_octet_ptr_allownil)}
    OSSL_PARAM_construct_octet_ptr := ERR_OSSL_PARAM_construct_octet_ptr;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_octet_ptr_introduced)}
    if LibVersion < OSSL_PARAM_construct_octet_ptr_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_construct_octet_ptr)}
      OSSL_PARAM_construct_octet_ptr := FC_OSSL_PARAM_construct_octet_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_octet_ptr_removed)}
    if OSSL_PARAM_construct_octet_ptr_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_construct_octet_ptr)}
      OSSL_PARAM_construct_octet_ptr := _OSSL_PARAM_construct_octet_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_construct_octet_ptr_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_construct_octet_ptr');
    {$ifend}
  end;
  
  OSSL_PARAM_construct_end := LoadLibFunction(ADllHandle, OSSL_PARAM_construct_end_procname);
  FuncLoadError := not assigned(OSSL_PARAM_construct_end);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_construct_end_allownil)}
    OSSL_PARAM_construct_end := ERR_OSSL_PARAM_construct_end;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_end_introduced)}
    if LibVersion < OSSL_PARAM_construct_end_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_construct_end)}
      OSSL_PARAM_construct_end := FC_OSSL_PARAM_construct_end;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_construct_end_removed)}
    if OSSL_PARAM_construct_end_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_construct_end)}
      OSSL_PARAM_construct_end := _OSSL_PARAM_construct_end;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_construct_end_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_construct_end');
    {$ifend}
  end;
  
  OSSL_PARAM_allocate_from_text := LoadLibFunction(ADllHandle, OSSL_PARAM_allocate_from_text_procname);
  FuncLoadError := not assigned(OSSL_PARAM_allocate_from_text);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_allocate_from_text_allownil)}
    OSSL_PARAM_allocate_from_text := ERR_OSSL_PARAM_allocate_from_text;
    {$ifend}
    {$if declared(OSSL_PARAM_allocate_from_text_introduced)}
    if LibVersion < OSSL_PARAM_allocate_from_text_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_allocate_from_text)}
      OSSL_PARAM_allocate_from_text := FC_OSSL_PARAM_allocate_from_text;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_allocate_from_text_removed)}
    if OSSL_PARAM_allocate_from_text_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_allocate_from_text)}
      OSSL_PARAM_allocate_from_text := _OSSL_PARAM_allocate_from_text;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_allocate_from_text_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_allocate_from_text');
    {$ifend}
  end;
  
  OSSL_PARAM_print_to_bio := LoadLibFunction(ADllHandle, OSSL_PARAM_print_to_bio_procname);
  FuncLoadError := not assigned(OSSL_PARAM_print_to_bio);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_print_to_bio_allownil)}
    OSSL_PARAM_print_to_bio := ERR_OSSL_PARAM_print_to_bio;
    {$ifend}
    {$if declared(OSSL_PARAM_print_to_bio_introduced)}
    if LibVersion < OSSL_PARAM_print_to_bio_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_print_to_bio)}
      OSSL_PARAM_print_to_bio := FC_OSSL_PARAM_print_to_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_print_to_bio_removed)}
    if OSSL_PARAM_print_to_bio_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_print_to_bio)}
      OSSL_PARAM_print_to_bio := _OSSL_PARAM_print_to_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_print_to_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_print_to_bio');
    {$ifend}
  end;
  
  OSSL_PARAM_get_int := LoadLibFunction(ADllHandle, OSSL_PARAM_get_int_procname);
  FuncLoadError := not assigned(OSSL_PARAM_get_int);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_get_int_allownil)}
    OSSL_PARAM_get_int := ERR_OSSL_PARAM_get_int;
    {$ifend}
    {$if declared(OSSL_PARAM_get_int_introduced)}
    if LibVersion < OSSL_PARAM_get_int_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_get_int)}
      OSSL_PARAM_get_int := FC_OSSL_PARAM_get_int;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_get_int_removed)}
    if OSSL_PARAM_get_int_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_get_int)}
      OSSL_PARAM_get_int := _OSSL_PARAM_get_int;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_get_int_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_get_int');
    {$ifend}
  end;
  
  OSSL_PARAM_get_uint := LoadLibFunction(ADllHandle, OSSL_PARAM_get_uint_procname);
  FuncLoadError := not assigned(OSSL_PARAM_get_uint);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_get_uint_allownil)}
    OSSL_PARAM_get_uint := ERR_OSSL_PARAM_get_uint;
    {$ifend}
    {$if declared(OSSL_PARAM_get_uint_introduced)}
    if LibVersion < OSSL_PARAM_get_uint_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_get_uint)}
      OSSL_PARAM_get_uint := FC_OSSL_PARAM_get_uint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_get_uint_removed)}
    if OSSL_PARAM_get_uint_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_get_uint)}
      OSSL_PARAM_get_uint := _OSSL_PARAM_get_uint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_get_uint_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_get_uint');
    {$ifend}
  end;
  
  OSSL_PARAM_get_long := LoadLibFunction(ADllHandle, OSSL_PARAM_get_long_procname);
  FuncLoadError := not assigned(OSSL_PARAM_get_long);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_get_long_allownil)}
    OSSL_PARAM_get_long := ERR_OSSL_PARAM_get_long;
    {$ifend}
    {$if declared(OSSL_PARAM_get_long_introduced)}
    if LibVersion < OSSL_PARAM_get_long_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_get_long)}
      OSSL_PARAM_get_long := FC_OSSL_PARAM_get_long;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_get_long_removed)}
    if OSSL_PARAM_get_long_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_get_long)}
      OSSL_PARAM_get_long := _OSSL_PARAM_get_long;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_get_long_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_get_long');
    {$ifend}
  end;
  
  OSSL_PARAM_get_ulong := LoadLibFunction(ADllHandle, OSSL_PARAM_get_ulong_procname);
  FuncLoadError := not assigned(OSSL_PARAM_get_ulong);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_get_ulong_allownil)}
    OSSL_PARAM_get_ulong := ERR_OSSL_PARAM_get_ulong;
    {$ifend}
    {$if declared(OSSL_PARAM_get_ulong_introduced)}
    if LibVersion < OSSL_PARAM_get_ulong_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_get_ulong)}
      OSSL_PARAM_get_ulong := FC_OSSL_PARAM_get_ulong;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_get_ulong_removed)}
    if OSSL_PARAM_get_ulong_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_get_ulong)}
      OSSL_PARAM_get_ulong := _OSSL_PARAM_get_ulong;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_get_ulong_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_get_ulong');
    {$ifend}
  end;
  
  OSSL_PARAM_get_int32 := LoadLibFunction(ADllHandle, OSSL_PARAM_get_int32_procname);
  FuncLoadError := not assigned(OSSL_PARAM_get_int32);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_get_int32_allownil)}
    OSSL_PARAM_get_int32 := ERR_OSSL_PARAM_get_int32;
    {$ifend}
    {$if declared(OSSL_PARAM_get_int32_introduced)}
    if LibVersion < OSSL_PARAM_get_int32_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_get_int32)}
      OSSL_PARAM_get_int32 := FC_OSSL_PARAM_get_int32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_get_int32_removed)}
    if OSSL_PARAM_get_int32_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_get_int32)}
      OSSL_PARAM_get_int32 := _OSSL_PARAM_get_int32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_get_int32_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_get_int32');
    {$ifend}
  end;
  
  OSSL_PARAM_get_uint32 := LoadLibFunction(ADllHandle, OSSL_PARAM_get_uint32_procname);
  FuncLoadError := not assigned(OSSL_PARAM_get_uint32);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_get_uint32_allownil)}
    OSSL_PARAM_get_uint32 := ERR_OSSL_PARAM_get_uint32;
    {$ifend}
    {$if declared(OSSL_PARAM_get_uint32_introduced)}
    if LibVersion < OSSL_PARAM_get_uint32_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_get_uint32)}
      OSSL_PARAM_get_uint32 := FC_OSSL_PARAM_get_uint32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_get_uint32_removed)}
    if OSSL_PARAM_get_uint32_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_get_uint32)}
      OSSL_PARAM_get_uint32 := _OSSL_PARAM_get_uint32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_get_uint32_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_get_uint32');
    {$ifend}
  end;
  
  OSSL_PARAM_get_int64 := LoadLibFunction(ADllHandle, OSSL_PARAM_get_int64_procname);
  FuncLoadError := not assigned(OSSL_PARAM_get_int64);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_get_int64_allownil)}
    OSSL_PARAM_get_int64 := ERR_OSSL_PARAM_get_int64;
    {$ifend}
    {$if declared(OSSL_PARAM_get_int64_introduced)}
    if LibVersion < OSSL_PARAM_get_int64_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_get_int64)}
      OSSL_PARAM_get_int64 := FC_OSSL_PARAM_get_int64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_get_int64_removed)}
    if OSSL_PARAM_get_int64_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_get_int64)}
      OSSL_PARAM_get_int64 := _OSSL_PARAM_get_int64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_get_int64_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_get_int64');
    {$ifend}
  end;
  
  OSSL_PARAM_get_uint64 := LoadLibFunction(ADllHandle, OSSL_PARAM_get_uint64_procname);
  FuncLoadError := not assigned(OSSL_PARAM_get_uint64);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_get_uint64_allownil)}
    OSSL_PARAM_get_uint64 := ERR_OSSL_PARAM_get_uint64;
    {$ifend}
    {$if declared(OSSL_PARAM_get_uint64_introduced)}
    if LibVersion < OSSL_PARAM_get_uint64_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_get_uint64)}
      OSSL_PARAM_get_uint64 := FC_OSSL_PARAM_get_uint64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_get_uint64_removed)}
    if OSSL_PARAM_get_uint64_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_get_uint64)}
      OSSL_PARAM_get_uint64 := _OSSL_PARAM_get_uint64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_get_uint64_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_get_uint64');
    {$ifend}
  end;
  
  OSSL_PARAM_get_size_t := LoadLibFunction(ADllHandle, OSSL_PARAM_get_size_t_procname);
  FuncLoadError := not assigned(OSSL_PARAM_get_size_t);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_get_size_t_allownil)}
    OSSL_PARAM_get_size_t := ERR_OSSL_PARAM_get_size_t;
    {$ifend}
    {$if declared(OSSL_PARAM_get_size_t_introduced)}
    if LibVersion < OSSL_PARAM_get_size_t_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_get_size_t)}
      OSSL_PARAM_get_size_t := FC_OSSL_PARAM_get_size_t;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_get_size_t_removed)}
    if OSSL_PARAM_get_size_t_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_get_size_t)}
      OSSL_PARAM_get_size_t := _OSSL_PARAM_get_size_t;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_get_size_t_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_get_size_t');
    {$ifend}
  end;
  
  OSSL_PARAM_get_time_t := LoadLibFunction(ADllHandle, OSSL_PARAM_get_time_t_procname);
  FuncLoadError := not assigned(OSSL_PARAM_get_time_t);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_get_time_t_allownil)}
    OSSL_PARAM_get_time_t := ERR_OSSL_PARAM_get_time_t;
    {$ifend}
    {$if declared(OSSL_PARAM_get_time_t_introduced)}
    if LibVersion < OSSL_PARAM_get_time_t_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_get_time_t)}
      OSSL_PARAM_get_time_t := FC_OSSL_PARAM_get_time_t;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_get_time_t_removed)}
    if OSSL_PARAM_get_time_t_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_get_time_t)}
      OSSL_PARAM_get_time_t := _OSSL_PARAM_get_time_t;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_get_time_t_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_get_time_t');
    {$ifend}
  end;
  
  OSSL_PARAM_set_int := LoadLibFunction(ADllHandle, OSSL_PARAM_set_int_procname);
  FuncLoadError := not assigned(OSSL_PARAM_set_int);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_set_int_allownil)}
    OSSL_PARAM_set_int := ERR_OSSL_PARAM_set_int;
    {$ifend}
    {$if declared(OSSL_PARAM_set_int_introduced)}
    if LibVersion < OSSL_PARAM_set_int_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_set_int)}
      OSSL_PARAM_set_int := FC_OSSL_PARAM_set_int;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_set_int_removed)}
    if OSSL_PARAM_set_int_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_set_int)}
      OSSL_PARAM_set_int := _OSSL_PARAM_set_int;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_set_int_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_set_int');
    {$ifend}
  end;
  
  OSSL_PARAM_set_uint := LoadLibFunction(ADllHandle, OSSL_PARAM_set_uint_procname);
  FuncLoadError := not assigned(OSSL_PARAM_set_uint);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_set_uint_allownil)}
    OSSL_PARAM_set_uint := ERR_OSSL_PARAM_set_uint;
    {$ifend}
    {$if declared(OSSL_PARAM_set_uint_introduced)}
    if LibVersion < OSSL_PARAM_set_uint_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_set_uint)}
      OSSL_PARAM_set_uint := FC_OSSL_PARAM_set_uint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_set_uint_removed)}
    if OSSL_PARAM_set_uint_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_set_uint)}
      OSSL_PARAM_set_uint := _OSSL_PARAM_set_uint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_set_uint_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_set_uint');
    {$ifend}
  end;
  
  OSSL_PARAM_set_long := LoadLibFunction(ADllHandle, OSSL_PARAM_set_long_procname);
  FuncLoadError := not assigned(OSSL_PARAM_set_long);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_set_long_allownil)}
    OSSL_PARAM_set_long := ERR_OSSL_PARAM_set_long;
    {$ifend}
    {$if declared(OSSL_PARAM_set_long_introduced)}
    if LibVersion < OSSL_PARAM_set_long_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_set_long)}
      OSSL_PARAM_set_long := FC_OSSL_PARAM_set_long;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_set_long_removed)}
    if OSSL_PARAM_set_long_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_set_long)}
      OSSL_PARAM_set_long := _OSSL_PARAM_set_long;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_set_long_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_set_long');
    {$ifend}
  end;
  
  OSSL_PARAM_set_ulong := LoadLibFunction(ADllHandle, OSSL_PARAM_set_ulong_procname);
  FuncLoadError := not assigned(OSSL_PARAM_set_ulong);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_set_ulong_allownil)}
    OSSL_PARAM_set_ulong := ERR_OSSL_PARAM_set_ulong;
    {$ifend}
    {$if declared(OSSL_PARAM_set_ulong_introduced)}
    if LibVersion < OSSL_PARAM_set_ulong_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_set_ulong)}
      OSSL_PARAM_set_ulong := FC_OSSL_PARAM_set_ulong;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_set_ulong_removed)}
    if OSSL_PARAM_set_ulong_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_set_ulong)}
      OSSL_PARAM_set_ulong := _OSSL_PARAM_set_ulong;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_set_ulong_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_set_ulong');
    {$ifend}
  end;
  
  OSSL_PARAM_set_int32 := LoadLibFunction(ADllHandle, OSSL_PARAM_set_int32_procname);
  FuncLoadError := not assigned(OSSL_PARAM_set_int32);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_set_int32_allownil)}
    OSSL_PARAM_set_int32 := ERR_OSSL_PARAM_set_int32;
    {$ifend}
    {$if declared(OSSL_PARAM_set_int32_introduced)}
    if LibVersion < OSSL_PARAM_set_int32_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_set_int32)}
      OSSL_PARAM_set_int32 := FC_OSSL_PARAM_set_int32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_set_int32_removed)}
    if OSSL_PARAM_set_int32_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_set_int32)}
      OSSL_PARAM_set_int32 := _OSSL_PARAM_set_int32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_set_int32_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_set_int32');
    {$ifend}
  end;
  
  OSSL_PARAM_set_uint32 := LoadLibFunction(ADllHandle, OSSL_PARAM_set_uint32_procname);
  FuncLoadError := not assigned(OSSL_PARAM_set_uint32);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_set_uint32_allownil)}
    OSSL_PARAM_set_uint32 := ERR_OSSL_PARAM_set_uint32;
    {$ifend}
    {$if declared(OSSL_PARAM_set_uint32_introduced)}
    if LibVersion < OSSL_PARAM_set_uint32_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_set_uint32)}
      OSSL_PARAM_set_uint32 := FC_OSSL_PARAM_set_uint32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_set_uint32_removed)}
    if OSSL_PARAM_set_uint32_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_set_uint32)}
      OSSL_PARAM_set_uint32 := _OSSL_PARAM_set_uint32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_set_uint32_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_set_uint32');
    {$ifend}
  end;
  
  OSSL_PARAM_set_int64 := LoadLibFunction(ADllHandle, OSSL_PARAM_set_int64_procname);
  FuncLoadError := not assigned(OSSL_PARAM_set_int64);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_set_int64_allownil)}
    OSSL_PARAM_set_int64 := ERR_OSSL_PARAM_set_int64;
    {$ifend}
    {$if declared(OSSL_PARAM_set_int64_introduced)}
    if LibVersion < OSSL_PARAM_set_int64_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_set_int64)}
      OSSL_PARAM_set_int64 := FC_OSSL_PARAM_set_int64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_set_int64_removed)}
    if OSSL_PARAM_set_int64_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_set_int64)}
      OSSL_PARAM_set_int64 := _OSSL_PARAM_set_int64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_set_int64_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_set_int64');
    {$ifend}
  end;
  
  OSSL_PARAM_set_uint64 := LoadLibFunction(ADllHandle, OSSL_PARAM_set_uint64_procname);
  FuncLoadError := not assigned(OSSL_PARAM_set_uint64);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_set_uint64_allownil)}
    OSSL_PARAM_set_uint64 := ERR_OSSL_PARAM_set_uint64;
    {$ifend}
    {$if declared(OSSL_PARAM_set_uint64_introduced)}
    if LibVersion < OSSL_PARAM_set_uint64_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_set_uint64)}
      OSSL_PARAM_set_uint64 := FC_OSSL_PARAM_set_uint64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_set_uint64_removed)}
    if OSSL_PARAM_set_uint64_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_set_uint64)}
      OSSL_PARAM_set_uint64 := _OSSL_PARAM_set_uint64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_set_uint64_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_set_uint64');
    {$ifend}
  end;
  
  OSSL_PARAM_set_size_t := LoadLibFunction(ADllHandle, OSSL_PARAM_set_size_t_procname);
  FuncLoadError := not assigned(OSSL_PARAM_set_size_t);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_set_size_t_allownil)}
    OSSL_PARAM_set_size_t := ERR_OSSL_PARAM_set_size_t;
    {$ifend}
    {$if declared(OSSL_PARAM_set_size_t_introduced)}
    if LibVersion < OSSL_PARAM_set_size_t_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_set_size_t)}
      OSSL_PARAM_set_size_t := FC_OSSL_PARAM_set_size_t;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_set_size_t_removed)}
    if OSSL_PARAM_set_size_t_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_set_size_t)}
      OSSL_PARAM_set_size_t := _OSSL_PARAM_set_size_t;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_set_size_t_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_set_size_t');
    {$ifend}
  end;
  
  OSSL_PARAM_set_time_t := LoadLibFunction(ADllHandle, OSSL_PARAM_set_time_t_procname);
  FuncLoadError := not assigned(OSSL_PARAM_set_time_t);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_set_time_t_allownil)}
    OSSL_PARAM_set_time_t := ERR_OSSL_PARAM_set_time_t;
    {$ifend}
    {$if declared(OSSL_PARAM_set_time_t_introduced)}
    if LibVersion < OSSL_PARAM_set_time_t_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_set_time_t)}
      OSSL_PARAM_set_time_t := FC_OSSL_PARAM_set_time_t;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_set_time_t_removed)}
    if OSSL_PARAM_set_time_t_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_set_time_t)}
      OSSL_PARAM_set_time_t := _OSSL_PARAM_set_time_t;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_set_time_t_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_set_time_t');
    {$ifend}
  end;
  
  OSSL_PARAM_get_double := LoadLibFunction(ADllHandle, OSSL_PARAM_get_double_procname);
  FuncLoadError := not assigned(OSSL_PARAM_get_double);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_get_double_allownil)}
    OSSL_PARAM_get_double := ERR_OSSL_PARAM_get_double;
    {$ifend}
    {$if declared(OSSL_PARAM_get_double_introduced)}
    if LibVersion < OSSL_PARAM_get_double_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_get_double)}
      OSSL_PARAM_get_double := FC_OSSL_PARAM_get_double;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_get_double_removed)}
    if OSSL_PARAM_get_double_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_get_double)}
      OSSL_PARAM_get_double := _OSSL_PARAM_get_double;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_get_double_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_get_double');
    {$ifend}
  end;
  
  OSSL_PARAM_set_double := LoadLibFunction(ADllHandle, OSSL_PARAM_set_double_procname);
  FuncLoadError := not assigned(OSSL_PARAM_set_double);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_set_double_allownil)}
    OSSL_PARAM_set_double := ERR_OSSL_PARAM_set_double;
    {$ifend}
    {$if declared(OSSL_PARAM_set_double_introduced)}
    if LibVersion < OSSL_PARAM_set_double_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_set_double)}
      OSSL_PARAM_set_double := FC_OSSL_PARAM_set_double;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_set_double_removed)}
    if OSSL_PARAM_set_double_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_set_double)}
      OSSL_PARAM_set_double := _OSSL_PARAM_set_double;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_set_double_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_set_double');
    {$ifend}
  end;
  
  OSSL_PARAM_get_BN := LoadLibFunction(ADllHandle, OSSL_PARAM_get_BN_procname);
  FuncLoadError := not assigned(OSSL_PARAM_get_BN);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_get_BN_allownil)}
    OSSL_PARAM_get_BN := ERR_OSSL_PARAM_get_BN;
    {$ifend}
    {$if declared(OSSL_PARAM_get_BN_introduced)}
    if LibVersion < OSSL_PARAM_get_BN_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_get_BN)}
      OSSL_PARAM_get_BN := FC_OSSL_PARAM_get_BN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_get_BN_removed)}
    if OSSL_PARAM_get_BN_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_get_BN)}
      OSSL_PARAM_get_BN := _OSSL_PARAM_get_BN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_get_BN_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_get_BN');
    {$ifend}
  end;
  
  OSSL_PARAM_set_BN := LoadLibFunction(ADllHandle, OSSL_PARAM_set_BN_procname);
  FuncLoadError := not assigned(OSSL_PARAM_set_BN);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_set_BN_allownil)}
    OSSL_PARAM_set_BN := ERR_OSSL_PARAM_set_BN;
    {$ifend}
    {$if declared(OSSL_PARAM_set_BN_introduced)}
    if LibVersion < OSSL_PARAM_set_BN_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_set_BN)}
      OSSL_PARAM_set_BN := FC_OSSL_PARAM_set_BN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_set_BN_removed)}
    if OSSL_PARAM_set_BN_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_set_BN)}
      OSSL_PARAM_set_BN := _OSSL_PARAM_set_BN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_set_BN_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_set_BN');
    {$ifend}
  end;
  
  OSSL_PARAM_get_utf8_string := LoadLibFunction(ADllHandle, OSSL_PARAM_get_utf8_string_procname);
  FuncLoadError := not assigned(OSSL_PARAM_get_utf8_string);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_get_utf8_string_allownil)}
    OSSL_PARAM_get_utf8_string := ERR_OSSL_PARAM_get_utf8_string;
    {$ifend}
    {$if declared(OSSL_PARAM_get_utf8_string_introduced)}
    if LibVersion < OSSL_PARAM_get_utf8_string_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_get_utf8_string)}
      OSSL_PARAM_get_utf8_string := FC_OSSL_PARAM_get_utf8_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_get_utf8_string_removed)}
    if OSSL_PARAM_get_utf8_string_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_get_utf8_string)}
      OSSL_PARAM_get_utf8_string := _OSSL_PARAM_get_utf8_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_get_utf8_string_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_get_utf8_string');
    {$ifend}
  end;
  
  OSSL_PARAM_set_utf8_string := LoadLibFunction(ADllHandle, OSSL_PARAM_set_utf8_string_procname);
  FuncLoadError := not assigned(OSSL_PARAM_set_utf8_string);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_set_utf8_string_allownil)}
    OSSL_PARAM_set_utf8_string := ERR_OSSL_PARAM_set_utf8_string;
    {$ifend}
    {$if declared(OSSL_PARAM_set_utf8_string_introduced)}
    if LibVersion < OSSL_PARAM_set_utf8_string_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_set_utf8_string)}
      OSSL_PARAM_set_utf8_string := FC_OSSL_PARAM_set_utf8_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_set_utf8_string_removed)}
    if OSSL_PARAM_set_utf8_string_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_set_utf8_string)}
      OSSL_PARAM_set_utf8_string := _OSSL_PARAM_set_utf8_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_set_utf8_string_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_set_utf8_string');
    {$ifend}
  end;
  
  OSSL_PARAM_get_octet_string := LoadLibFunction(ADllHandle, OSSL_PARAM_get_octet_string_procname);
  FuncLoadError := not assigned(OSSL_PARAM_get_octet_string);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_get_octet_string_allownil)}
    OSSL_PARAM_get_octet_string := ERR_OSSL_PARAM_get_octet_string;
    {$ifend}
    {$if declared(OSSL_PARAM_get_octet_string_introduced)}
    if LibVersion < OSSL_PARAM_get_octet_string_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_get_octet_string)}
      OSSL_PARAM_get_octet_string := FC_OSSL_PARAM_get_octet_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_get_octet_string_removed)}
    if OSSL_PARAM_get_octet_string_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_get_octet_string)}
      OSSL_PARAM_get_octet_string := _OSSL_PARAM_get_octet_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_get_octet_string_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_get_octet_string');
    {$ifend}
  end;
  
  OSSL_PARAM_set_octet_string := LoadLibFunction(ADllHandle, OSSL_PARAM_set_octet_string_procname);
  FuncLoadError := not assigned(OSSL_PARAM_set_octet_string);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_set_octet_string_allownil)}
    OSSL_PARAM_set_octet_string := ERR_OSSL_PARAM_set_octet_string;
    {$ifend}
    {$if declared(OSSL_PARAM_set_octet_string_introduced)}
    if LibVersion < OSSL_PARAM_set_octet_string_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_set_octet_string)}
      OSSL_PARAM_set_octet_string := FC_OSSL_PARAM_set_octet_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_set_octet_string_removed)}
    if OSSL_PARAM_set_octet_string_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_set_octet_string)}
      OSSL_PARAM_set_octet_string := _OSSL_PARAM_set_octet_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_set_octet_string_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_set_octet_string');
    {$ifend}
  end;
  
  OSSL_PARAM_get_utf8_ptr := LoadLibFunction(ADllHandle, OSSL_PARAM_get_utf8_ptr_procname);
  FuncLoadError := not assigned(OSSL_PARAM_get_utf8_ptr);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_get_utf8_ptr_allownil)}
    OSSL_PARAM_get_utf8_ptr := ERR_OSSL_PARAM_get_utf8_ptr;
    {$ifend}
    {$if declared(OSSL_PARAM_get_utf8_ptr_introduced)}
    if LibVersion < OSSL_PARAM_get_utf8_ptr_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_get_utf8_ptr)}
      OSSL_PARAM_get_utf8_ptr := FC_OSSL_PARAM_get_utf8_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_get_utf8_ptr_removed)}
    if OSSL_PARAM_get_utf8_ptr_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_get_utf8_ptr)}
      OSSL_PARAM_get_utf8_ptr := _OSSL_PARAM_get_utf8_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_get_utf8_ptr_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_get_utf8_ptr');
    {$ifend}
  end;
  
  OSSL_PARAM_set_utf8_ptr := LoadLibFunction(ADllHandle, OSSL_PARAM_set_utf8_ptr_procname);
  FuncLoadError := not assigned(OSSL_PARAM_set_utf8_ptr);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_set_utf8_ptr_allownil)}
    OSSL_PARAM_set_utf8_ptr := ERR_OSSL_PARAM_set_utf8_ptr;
    {$ifend}
    {$if declared(OSSL_PARAM_set_utf8_ptr_introduced)}
    if LibVersion < OSSL_PARAM_set_utf8_ptr_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_set_utf8_ptr)}
      OSSL_PARAM_set_utf8_ptr := FC_OSSL_PARAM_set_utf8_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_set_utf8_ptr_removed)}
    if OSSL_PARAM_set_utf8_ptr_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_set_utf8_ptr)}
      OSSL_PARAM_set_utf8_ptr := _OSSL_PARAM_set_utf8_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_set_utf8_ptr_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_set_utf8_ptr');
    {$ifend}
  end;
  
  OSSL_PARAM_get_octet_ptr := LoadLibFunction(ADllHandle, OSSL_PARAM_get_octet_ptr_procname);
  FuncLoadError := not assigned(OSSL_PARAM_get_octet_ptr);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_get_octet_ptr_allownil)}
    OSSL_PARAM_get_octet_ptr := ERR_OSSL_PARAM_get_octet_ptr;
    {$ifend}
    {$if declared(OSSL_PARAM_get_octet_ptr_introduced)}
    if LibVersion < OSSL_PARAM_get_octet_ptr_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_get_octet_ptr)}
      OSSL_PARAM_get_octet_ptr := FC_OSSL_PARAM_get_octet_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_get_octet_ptr_removed)}
    if OSSL_PARAM_get_octet_ptr_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_get_octet_ptr)}
      OSSL_PARAM_get_octet_ptr := _OSSL_PARAM_get_octet_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_get_octet_ptr_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_get_octet_ptr');
    {$ifend}
  end;
  
  OSSL_PARAM_set_octet_ptr := LoadLibFunction(ADllHandle, OSSL_PARAM_set_octet_ptr_procname);
  FuncLoadError := not assigned(OSSL_PARAM_set_octet_ptr);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_set_octet_ptr_allownil)}
    OSSL_PARAM_set_octet_ptr := ERR_OSSL_PARAM_set_octet_ptr;
    {$ifend}
    {$if declared(OSSL_PARAM_set_octet_ptr_introduced)}
    if LibVersion < OSSL_PARAM_set_octet_ptr_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_set_octet_ptr)}
      OSSL_PARAM_set_octet_ptr := FC_OSSL_PARAM_set_octet_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_set_octet_ptr_removed)}
    if OSSL_PARAM_set_octet_ptr_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_set_octet_ptr)}
      OSSL_PARAM_set_octet_ptr := _OSSL_PARAM_set_octet_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_set_octet_ptr_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_set_octet_ptr');
    {$ifend}
  end;
  
  OSSL_PARAM_get_utf8_string_ptr := LoadLibFunction(ADllHandle, OSSL_PARAM_get_utf8_string_ptr_procname);
  FuncLoadError := not assigned(OSSL_PARAM_get_utf8_string_ptr);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_get_utf8_string_ptr_allownil)}
    OSSL_PARAM_get_utf8_string_ptr := ERR_OSSL_PARAM_get_utf8_string_ptr;
    {$ifend}
    {$if declared(OSSL_PARAM_get_utf8_string_ptr_introduced)}
    if LibVersion < OSSL_PARAM_get_utf8_string_ptr_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_get_utf8_string_ptr)}
      OSSL_PARAM_get_utf8_string_ptr := FC_OSSL_PARAM_get_utf8_string_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_get_utf8_string_ptr_removed)}
    if OSSL_PARAM_get_utf8_string_ptr_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_get_utf8_string_ptr)}
      OSSL_PARAM_get_utf8_string_ptr := _OSSL_PARAM_get_utf8_string_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_get_utf8_string_ptr_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_get_utf8_string_ptr');
    {$ifend}
  end;
  
  OSSL_PARAM_get_octet_string_ptr := LoadLibFunction(ADllHandle, OSSL_PARAM_get_octet_string_ptr_procname);
  FuncLoadError := not assigned(OSSL_PARAM_get_octet_string_ptr);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_get_octet_string_ptr_allownil)}
    OSSL_PARAM_get_octet_string_ptr := ERR_OSSL_PARAM_get_octet_string_ptr;
    {$ifend}
    {$if declared(OSSL_PARAM_get_octet_string_ptr_introduced)}
    if LibVersion < OSSL_PARAM_get_octet_string_ptr_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_get_octet_string_ptr)}
      OSSL_PARAM_get_octet_string_ptr := FC_OSSL_PARAM_get_octet_string_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_get_octet_string_ptr_removed)}
    if OSSL_PARAM_get_octet_string_ptr_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_get_octet_string_ptr)}
      OSSL_PARAM_get_octet_string_ptr := _OSSL_PARAM_get_octet_string_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_get_octet_string_ptr_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_get_octet_string_ptr');
    {$ifend}
  end;
  
  OSSL_PARAM_modified := LoadLibFunction(ADllHandle, OSSL_PARAM_modified_procname);
  FuncLoadError := not assigned(OSSL_PARAM_modified);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_modified_allownil)}
    OSSL_PARAM_modified := ERR_OSSL_PARAM_modified;
    {$ifend}
    {$if declared(OSSL_PARAM_modified_introduced)}
    if LibVersion < OSSL_PARAM_modified_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_modified)}
      OSSL_PARAM_modified := FC_OSSL_PARAM_modified;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_modified_removed)}
    if OSSL_PARAM_modified_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_modified)}
      OSSL_PARAM_modified := _OSSL_PARAM_modified;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_modified_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_modified');
    {$ifend}
  end;
  
  OSSL_PARAM_set_all_unmodified := LoadLibFunction(ADllHandle, OSSL_PARAM_set_all_unmodified_procname);
  FuncLoadError := not assigned(OSSL_PARAM_set_all_unmodified);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_set_all_unmodified_allownil)}
    OSSL_PARAM_set_all_unmodified := ERR_OSSL_PARAM_set_all_unmodified;
    {$ifend}
    {$if declared(OSSL_PARAM_set_all_unmodified_introduced)}
    if LibVersion < OSSL_PARAM_set_all_unmodified_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_set_all_unmodified)}
      OSSL_PARAM_set_all_unmodified := FC_OSSL_PARAM_set_all_unmodified;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_set_all_unmodified_removed)}
    if OSSL_PARAM_set_all_unmodified_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_set_all_unmodified)}
      OSSL_PARAM_set_all_unmodified := _OSSL_PARAM_set_all_unmodified;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_set_all_unmodified_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_set_all_unmodified');
    {$ifend}
  end;
  
  OSSL_PARAM_dup := LoadLibFunction(ADllHandle, OSSL_PARAM_dup_procname);
  FuncLoadError := not assigned(OSSL_PARAM_dup);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_dup_allownil)}
    OSSL_PARAM_dup := ERR_OSSL_PARAM_dup;
    {$ifend}
    {$if declared(OSSL_PARAM_dup_introduced)}
    if LibVersion < OSSL_PARAM_dup_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_dup)}
      OSSL_PARAM_dup := FC_OSSL_PARAM_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_dup_removed)}
    if OSSL_PARAM_dup_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_dup)}
      OSSL_PARAM_dup := _OSSL_PARAM_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_dup');
    {$ifend}
  end;
  
  OSSL_PARAM_merge := LoadLibFunction(ADllHandle, OSSL_PARAM_merge_procname);
  FuncLoadError := not assigned(OSSL_PARAM_merge);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_merge_allownil)}
    OSSL_PARAM_merge := ERR_OSSL_PARAM_merge;
    {$ifend}
    {$if declared(OSSL_PARAM_merge_introduced)}
    if LibVersion < OSSL_PARAM_merge_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_merge)}
      OSSL_PARAM_merge := FC_OSSL_PARAM_merge;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_merge_removed)}
    if OSSL_PARAM_merge_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_merge)}
      OSSL_PARAM_merge := _OSSL_PARAM_merge;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_merge_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_merge');
    {$ifend}
  end;
  
  OSSL_PARAM_free := LoadLibFunction(ADllHandle, OSSL_PARAM_free_procname);
  FuncLoadError := not assigned(OSSL_PARAM_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_free_allownil)}
    OSSL_PARAM_free := ERR_OSSL_PARAM_free;
    {$ifend}
    {$if declared(OSSL_PARAM_free_introduced)}
    if LibVersion < OSSL_PARAM_free_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_free)}
      OSSL_PARAM_free := FC_OSSL_PARAM_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_free_removed)}
    if OSSL_PARAM_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_free)}
      OSSL_PARAM_free := _OSSL_PARAM_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_free');
    {$ifend}
  end;
  
  OSSL_PARAM_set_octet_string_or_ptr := LoadLibFunction(ADllHandle, OSSL_PARAM_set_octet_string_or_ptr_procname);
  FuncLoadError := not assigned(OSSL_PARAM_set_octet_string_or_ptr);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_set_octet_string_or_ptr_allownil)}
    OSSL_PARAM_set_octet_string_or_ptr := ERR_OSSL_PARAM_set_octet_string_or_ptr;
    {$ifend}
    {$if declared(OSSL_PARAM_set_octet_string_or_ptr_introduced)}
    if LibVersion < OSSL_PARAM_set_octet_string_or_ptr_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_set_octet_string_or_ptr)}
      OSSL_PARAM_set_octet_string_or_ptr := FC_OSSL_PARAM_set_octet_string_or_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_set_octet_string_or_ptr_removed)}
    if OSSL_PARAM_set_octet_string_or_ptr_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_set_octet_string_or_ptr)}
      OSSL_PARAM_set_octet_string_or_ptr := _OSSL_PARAM_set_octet_string_or_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_set_octet_string_or_ptr_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_set_octet_string_or_ptr');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  OSSL_PARAM_locate := nil;
  OSSL_PARAM_locate_const := nil;
  OSSL_PARAM_construct_int := nil;
  OSSL_PARAM_construct_uint := nil;
  OSSL_PARAM_construct_long := nil;
  OSSL_PARAM_construct_ulong := nil;
  OSSL_PARAM_construct_int32 := nil;
  OSSL_PARAM_construct_uint32 := nil;
  OSSL_PARAM_construct_int64 := nil;
  OSSL_PARAM_construct_uint64 := nil;
  OSSL_PARAM_construct_size_t := nil;
  OSSL_PARAM_construct_time_t := nil;
  OSSL_PARAM_construct_BN := nil;
  OSSL_PARAM_construct_double := nil;
  OSSL_PARAM_construct_utf8_string := nil;
  OSSL_PARAM_construct_utf8_ptr := nil;
  OSSL_PARAM_construct_octet_string := nil;
  OSSL_PARAM_construct_octet_ptr := nil;
  OSSL_PARAM_construct_end := nil;
  OSSL_PARAM_allocate_from_text := nil;
  OSSL_PARAM_print_to_bio := nil;
  OSSL_PARAM_get_int := nil;
  OSSL_PARAM_get_uint := nil;
  OSSL_PARAM_get_long := nil;
  OSSL_PARAM_get_ulong := nil;
  OSSL_PARAM_get_int32 := nil;
  OSSL_PARAM_get_uint32 := nil;
  OSSL_PARAM_get_int64 := nil;
  OSSL_PARAM_get_uint64 := nil;
  OSSL_PARAM_get_size_t := nil;
  OSSL_PARAM_get_time_t := nil;
  OSSL_PARAM_set_int := nil;
  OSSL_PARAM_set_uint := nil;
  OSSL_PARAM_set_long := nil;
  OSSL_PARAM_set_ulong := nil;
  OSSL_PARAM_set_int32 := nil;
  OSSL_PARAM_set_uint32 := nil;
  OSSL_PARAM_set_int64 := nil;
  OSSL_PARAM_set_uint64 := nil;
  OSSL_PARAM_set_size_t := nil;
  OSSL_PARAM_set_time_t := nil;
  OSSL_PARAM_get_double := nil;
  OSSL_PARAM_set_double := nil;
  OSSL_PARAM_get_BN := nil;
  OSSL_PARAM_set_BN := nil;
  OSSL_PARAM_get_utf8_string := nil;
  OSSL_PARAM_set_utf8_string := nil;
  OSSL_PARAM_get_octet_string := nil;
  OSSL_PARAM_set_octet_string := nil;
  OSSL_PARAM_get_utf8_ptr := nil;
  OSSL_PARAM_set_utf8_ptr := nil;
  OSSL_PARAM_get_octet_ptr := nil;
  OSSL_PARAM_set_octet_ptr := nil;
  OSSL_PARAM_get_utf8_string_ptr := nil;
  OSSL_PARAM_get_octet_string_ptr := nil;
  OSSL_PARAM_modified := nil;
  OSSL_PARAM_set_all_unmodified := nil;
  OSSL_PARAM_dup := nil;
  OSSL_PARAM_merge := nil;
  OSSL_PARAM_free := nil;
  OSSL_PARAM_set_octet_string_or_ptr := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.