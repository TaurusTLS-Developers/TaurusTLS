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

unit TaurusTLSHeaders_param_build;

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




{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  OSSL_PARAM_BLD_new: function: POSSL_PARAM_BLD; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_BLD_new}

  OSSL_PARAM_BLD_to_param: function(bld: POSSL_PARAM_BLD): POSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_BLD_to_param}

  OSSL_PARAM_BLD_free: procedure(bld: POSSL_PARAM_BLD); cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_BLD_free}

  OSSL_PARAM_BLD_push_int: function(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_BLD_push_int}

  OSSL_PARAM_BLD_push_uint: function(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_BLD_push_uint}

  OSSL_PARAM_BLD_push_long: function(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_BLD_push_long}

  OSSL_PARAM_BLD_push_ulong: function(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_BLD_push_ulong}

  OSSL_PARAM_BLD_push_int32: function(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_INT32): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_BLD_push_int32}

  OSSL_PARAM_BLD_push_uint32: function(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_UINT32): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_BLD_push_uint32}

  OSSL_PARAM_BLD_push_int64: function(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_INT64): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_BLD_push_int64}

  OSSL_PARAM_BLD_push_uint64: function(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_UINT64): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_BLD_push_uint64}

  OSSL_PARAM_BLD_push_size_t: function(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_BLD_push_size_t}

  OSSL_PARAM_BLD_push_time_t: function(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_TIMET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_BLD_push_time_t}

  OSSL_PARAM_BLD_push_double: function(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_DOUBLE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_BLD_push_double}

  OSSL_PARAM_BLD_push_BN: function(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; bn: PBIGNUM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_BLD_push_BN}

  OSSL_PARAM_BLD_push_BN_pad: function(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; bn: PBIGNUM; sz: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_BLD_push_BN_pad}

  OSSL_PARAM_BLD_push_utf8_string: function(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; buf: PIdAnsiChar; bsize: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_BLD_push_utf8_string}

  OSSL_PARAM_BLD_push_utf8_ptr: function(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; buf: PIdAnsiChar; bsize: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_BLD_push_utf8_ptr}

  OSSL_PARAM_BLD_push_octet_string: function(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; buf: Pointer; bsize: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_BLD_push_octet_string}

  OSSL_PARAM_BLD_push_octet_ptr: function(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; buf: Pointer; bsize: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_PARAM_BLD_push_octet_ptr}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function OSSL_PARAM_BLD_new: POSSL_PARAM_BLD; cdecl;
function OSSL_PARAM_BLD_to_param(bld: POSSL_PARAM_BLD): POSSL_PARAM; cdecl;
procedure OSSL_PARAM_BLD_free(bld: POSSL_PARAM_BLD); cdecl;
function OSSL_PARAM_BLD_push_int(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_INT): TIdC_INT; cdecl;
function OSSL_PARAM_BLD_push_uint(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_UINT): TIdC_INT; cdecl;
function OSSL_PARAM_BLD_push_long(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_LONG): TIdC_INT; cdecl;
function OSSL_PARAM_BLD_push_ulong(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_ULONG): TIdC_INT; cdecl;
function OSSL_PARAM_BLD_push_int32(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_INT32): TIdC_INT; cdecl;
function OSSL_PARAM_BLD_push_uint32(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_UINT32): TIdC_INT; cdecl;
function OSSL_PARAM_BLD_push_int64(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_INT64): TIdC_INT; cdecl;
function OSSL_PARAM_BLD_push_uint64(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_UINT64): TIdC_INT; cdecl;
function OSSL_PARAM_BLD_push_size_t(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_SIZET): TIdC_INT; cdecl;
function OSSL_PARAM_BLD_push_time_t(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_TIMET): TIdC_INT; cdecl;
function OSSL_PARAM_BLD_push_double(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_DOUBLE): TIdC_INT; cdecl;
function OSSL_PARAM_BLD_push_BN(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; bn: PBIGNUM): TIdC_INT; cdecl;
function OSSL_PARAM_BLD_push_BN_pad(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; bn: PBIGNUM; sz: TIdC_SIZET): TIdC_INT; cdecl;
function OSSL_PARAM_BLD_push_utf8_string(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; buf: PIdAnsiChar; bsize: TIdC_SIZET): TIdC_INT; cdecl;
function OSSL_PARAM_BLD_push_utf8_ptr(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; buf: PIdAnsiChar; bsize: TIdC_SIZET): TIdC_INT; cdecl;
function OSSL_PARAM_BLD_push_octet_string(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; buf: Pointer; bsize: TIdC_SIZET): TIdC_INT; cdecl;
function OSSL_PARAM_BLD_push_octet_ptr(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; buf: Pointer; bsize: TIdC_SIZET): TIdC_INT; cdecl;
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

function OSSL_PARAM_BLD_new: POSSL_PARAM_BLD; cdecl external CLibCrypto name 'OSSL_PARAM_BLD_new';
function OSSL_PARAM_BLD_to_param(bld: POSSL_PARAM_BLD): POSSL_PARAM; cdecl external CLibCrypto name 'OSSL_PARAM_BLD_to_param';
procedure OSSL_PARAM_BLD_free(bld: POSSL_PARAM_BLD); cdecl external CLibCrypto name 'OSSL_PARAM_BLD_free';
function OSSL_PARAM_BLD_push_int(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_BLD_push_int';
function OSSL_PARAM_BLD_push_uint(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_BLD_push_uint';
function OSSL_PARAM_BLD_push_long(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_BLD_push_long';
function OSSL_PARAM_BLD_push_ulong(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_BLD_push_ulong';
function OSSL_PARAM_BLD_push_int32(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_INT32): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_BLD_push_int32';
function OSSL_PARAM_BLD_push_uint32(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_UINT32): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_BLD_push_uint32';
function OSSL_PARAM_BLD_push_int64(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_INT64): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_BLD_push_int64';
function OSSL_PARAM_BLD_push_uint64(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_UINT64): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_BLD_push_uint64';
function OSSL_PARAM_BLD_push_size_t(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_BLD_push_size_t';
function OSSL_PARAM_BLD_push_time_t(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_TIMET): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_BLD_push_time_t';
function OSSL_PARAM_BLD_push_double(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_DOUBLE): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_BLD_push_double';
function OSSL_PARAM_BLD_push_BN(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; bn: PBIGNUM): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_BLD_push_BN';
function OSSL_PARAM_BLD_push_BN_pad(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; bn: PBIGNUM; sz: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_BLD_push_BN_pad';
function OSSL_PARAM_BLD_push_utf8_string(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; buf: PIdAnsiChar; bsize: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_BLD_push_utf8_string';
function OSSL_PARAM_BLD_push_utf8_ptr(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; buf: PIdAnsiChar; bsize: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_BLD_push_utf8_ptr';
function OSSL_PARAM_BLD_push_octet_string(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; buf: Pointer; bsize: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_BLD_push_octet_string';
function OSSL_PARAM_BLD_push_octet_ptr(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; buf: Pointer; bsize: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'OSSL_PARAM_BLD_push_octet_ptr';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  OSSL_PARAM_BLD_new_procname = 'OSSL_PARAM_BLD_new';
  OSSL_PARAM_BLD_new_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_BLD_to_param_procname = 'OSSL_PARAM_BLD_to_param';
  OSSL_PARAM_BLD_to_param_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_BLD_free_procname = 'OSSL_PARAM_BLD_free';
  OSSL_PARAM_BLD_free_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_BLD_push_int_procname = 'OSSL_PARAM_BLD_push_int';
  OSSL_PARAM_BLD_push_int_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_BLD_push_uint_procname = 'OSSL_PARAM_BLD_push_uint';
  OSSL_PARAM_BLD_push_uint_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_BLD_push_long_procname = 'OSSL_PARAM_BLD_push_long';
  OSSL_PARAM_BLD_push_long_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_BLD_push_ulong_procname = 'OSSL_PARAM_BLD_push_ulong';
  OSSL_PARAM_BLD_push_ulong_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_BLD_push_int32_procname = 'OSSL_PARAM_BLD_push_int32';
  OSSL_PARAM_BLD_push_int32_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_BLD_push_uint32_procname = 'OSSL_PARAM_BLD_push_uint32';
  OSSL_PARAM_BLD_push_uint32_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_BLD_push_int64_procname = 'OSSL_PARAM_BLD_push_int64';
  OSSL_PARAM_BLD_push_int64_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_BLD_push_uint64_procname = 'OSSL_PARAM_BLD_push_uint64';
  OSSL_PARAM_BLD_push_uint64_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_BLD_push_size_t_procname = 'OSSL_PARAM_BLD_push_size_t';
  OSSL_PARAM_BLD_push_size_t_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_BLD_push_time_t_procname = 'OSSL_PARAM_BLD_push_time_t';
  OSSL_PARAM_BLD_push_time_t_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_BLD_push_double_procname = 'OSSL_PARAM_BLD_push_double';
  OSSL_PARAM_BLD_push_double_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_BLD_push_BN_procname = 'OSSL_PARAM_BLD_push_BN';
  OSSL_PARAM_BLD_push_BN_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_BLD_push_BN_pad_procname = 'OSSL_PARAM_BLD_push_BN_pad';
  OSSL_PARAM_BLD_push_BN_pad_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_BLD_push_utf8_string_procname = 'OSSL_PARAM_BLD_push_utf8_string';
  OSSL_PARAM_BLD_push_utf8_string_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_BLD_push_utf8_ptr_procname = 'OSSL_PARAM_BLD_push_utf8_ptr';
  OSSL_PARAM_BLD_push_utf8_ptr_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_BLD_push_octet_string_procname = 'OSSL_PARAM_BLD_push_octet_string';
  OSSL_PARAM_BLD_push_octet_string_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_PARAM_BLD_push_octet_ptr_procname = 'OSSL_PARAM_BLD_push_octet_ptr';
  OSSL_PARAM_BLD_push_octet_ptr_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_OSSL_PARAM_BLD_new: POSSL_PARAM_BLD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_BLD_new_procname);
end;

function ERR_OSSL_PARAM_BLD_to_param(bld: POSSL_PARAM_BLD): POSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_BLD_to_param_procname);
end;

procedure ERR_OSSL_PARAM_BLD_free(bld: POSSL_PARAM_BLD); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_BLD_free_procname);
end;

function ERR_OSSL_PARAM_BLD_push_int(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_BLD_push_int_procname);
end;

function ERR_OSSL_PARAM_BLD_push_uint(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_BLD_push_uint_procname);
end;

function ERR_OSSL_PARAM_BLD_push_long(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_BLD_push_long_procname);
end;

function ERR_OSSL_PARAM_BLD_push_ulong(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_BLD_push_ulong_procname);
end;

function ERR_OSSL_PARAM_BLD_push_int32(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_INT32): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_BLD_push_int32_procname);
end;

function ERR_OSSL_PARAM_BLD_push_uint32(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_UINT32): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_BLD_push_uint32_procname);
end;

function ERR_OSSL_PARAM_BLD_push_int64(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_INT64): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_BLD_push_int64_procname);
end;

function ERR_OSSL_PARAM_BLD_push_uint64(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_UINT64): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_BLD_push_uint64_procname);
end;

function ERR_OSSL_PARAM_BLD_push_size_t(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_BLD_push_size_t_procname);
end;

function ERR_OSSL_PARAM_BLD_push_time_t(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_TIMET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_BLD_push_time_t_procname);
end;

function ERR_OSSL_PARAM_BLD_push_double(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; val: TIdC_DOUBLE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_BLD_push_double_procname);
end;

function ERR_OSSL_PARAM_BLD_push_BN(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; bn: PBIGNUM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_BLD_push_BN_procname);
end;

function ERR_OSSL_PARAM_BLD_push_BN_pad(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; bn: PBIGNUM; sz: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_BLD_push_BN_pad_procname);
end;

function ERR_OSSL_PARAM_BLD_push_utf8_string(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; buf: PIdAnsiChar; bsize: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_BLD_push_utf8_string_procname);
end;

function ERR_OSSL_PARAM_BLD_push_utf8_ptr(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; buf: PIdAnsiChar; bsize: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_BLD_push_utf8_ptr_procname);
end;

function ERR_OSSL_PARAM_BLD_push_octet_string(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; buf: Pointer; bsize: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_BLD_push_octet_string_procname);
end;

function ERR_OSSL_PARAM_BLD_push_octet_ptr(bld: POSSL_PARAM_BLD; key: PIdAnsiChar; buf: Pointer; bsize: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_PARAM_BLD_push_octet_ptr_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  OSSL_PARAM_BLD_new := LoadLibFunction(ADllHandle, OSSL_PARAM_BLD_new_procname);
  FuncLoadError := not assigned(OSSL_PARAM_BLD_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_BLD_new_allownil)}
    OSSL_PARAM_BLD_new := ERR_OSSL_PARAM_BLD_new;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_new_introduced)}
    if LibVersion < OSSL_PARAM_BLD_new_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_BLD_new)}
      OSSL_PARAM_BLD_new := FC_OSSL_PARAM_BLD_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_new_removed)}
    if OSSL_PARAM_BLD_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_BLD_new)}
      OSSL_PARAM_BLD_new := _OSSL_PARAM_BLD_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_BLD_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_BLD_new');
    {$ifend}
  end;
  
  OSSL_PARAM_BLD_to_param := LoadLibFunction(ADllHandle, OSSL_PARAM_BLD_to_param_procname);
  FuncLoadError := not assigned(OSSL_PARAM_BLD_to_param);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_BLD_to_param_allownil)}
    OSSL_PARAM_BLD_to_param := ERR_OSSL_PARAM_BLD_to_param;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_to_param_introduced)}
    if LibVersion < OSSL_PARAM_BLD_to_param_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_BLD_to_param)}
      OSSL_PARAM_BLD_to_param := FC_OSSL_PARAM_BLD_to_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_to_param_removed)}
    if OSSL_PARAM_BLD_to_param_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_BLD_to_param)}
      OSSL_PARAM_BLD_to_param := _OSSL_PARAM_BLD_to_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_BLD_to_param_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_BLD_to_param');
    {$ifend}
  end;
  
  OSSL_PARAM_BLD_free := LoadLibFunction(ADllHandle, OSSL_PARAM_BLD_free_procname);
  FuncLoadError := not assigned(OSSL_PARAM_BLD_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_BLD_free_allownil)}
    OSSL_PARAM_BLD_free := ERR_OSSL_PARAM_BLD_free;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_free_introduced)}
    if LibVersion < OSSL_PARAM_BLD_free_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_BLD_free)}
      OSSL_PARAM_BLD_free := FC_OSSL_PARAM_BLD_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_free_removed)}
    if OSSL_PARAM_BLD_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_BLD_free)}
      OSSL_PARAM_BLD_free := _OSSL_PARAM_BLD_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_BLD_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_BLD_free');
    {$ifend}
  end;
  
  OSSL_PARAM_BLD_push_int := LoadLibFunction(ADllHandle, OSSL_PARAM_BLD_push_int_procname);
  FuncLoadError := not assigned(OSSL_PARAM_BLD_push_int);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_BLD_push_int_allownil)}
    OSSL_PARAM_BLD_push_int := ERR_OSSL_PARAM_BLD_push_int;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_int_introduced)}
    if LibVersion < OSSL_PARAM_BLD_push_int_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_BLD_push_int)}
      OSSL_PARAM_BLD_push_int := FC_OSSL_PARAM_BLD_push_int;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_int_removed)}
    if OSSL_PARAM_BLD_push_int_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_BLD_push_int)}
      OSSL_PARAM_BLD_push_int := _OSSL_PARAM_BLD_push_int;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_BLD_push_int_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_BLD_push_int');
    {$ifend}
  end;
  
  OSSL_PARAM_BLD_push_uint := LoadLibFunction(ADllHandle, OSSL_PARAM_BLD_push_uint_procname);
  FuncLoadError := not assigned(OSSL_PARAM_BLD_push_uint);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_BLD_push_uint_allownil)}
    OSSL_PARAM_BLD_push_uint := ERR_OSSL_PARAM_BLD_push_uint;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_uint_introduced)}
    if LibVersion < OSSL_PARAM_BLD_push_uint_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_BLD_push_uint)}
      OSSL_PARAM_BLD_push_uint := FC_OSSL_PARAM_BLD_push_uint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_uint_removed)}
    if OSSL_PARAM_BLD_push_uint_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_BLD_push_uint)}
      OSSL_PARAM_BLD_push_uint := _OSSL_PARAM_BLD_push_uint;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_BLD_push_uint_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_BLD_push_uint');
    {$ifend}
  end;
  
  OSSL_PARAM_BLD_push_long := LoadLibFunction(ADllHandle, OSSL_PARAM_BLD_push_long_procname);
  FuncLoadError := not assigned(OSSL_PARAM_BLD_push_long);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_BLD_push_long_allownil)}
    OSSL_PARAM_BLD_push_long := ERR_OSSL_PARAM_BLD_push_long;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_long_introduced)}
    if LibVersion < OSSL_PARAM_BLD_push_long_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_BLD_push_long)}
      OSSL_PARAM_BLD_push_long := FC_OSSL_PARAM_BLD_push_long;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_long_removed)}
    if OSSL_PARAM_BLD_push_long_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_BLD_push_long)}
      OSSL_PARAM_BLD_push_long := _OSSL_PARAM_BLD_push_long;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_BLD_push_long_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_BLD_push_long');
    {$ifend}
  end;
  
  OSSL_PARAM_BLD_push_ulong := LoadLibFunction(ADllHandle, OSSL_PARAM_BLD_push_ulong_procname);
  FuncLoadError := not assigned(OSSL_PARAM_BLD_push_ulong);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_BLD_push_ulong_allownil)}
    OSSL_PARAM_BLD_push_ulong := ERR_OSSL_PARAM_BLD_push_ulong;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_ulong_introduced)}
    if LibVersion < OSSL_PARAM_BLD_push_ulong_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_BLD_push_ulong)}
      OSSL_PARAM_BLD_push_ulong := FC_OSSL_PARAM_BLD_push_ulong;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_ulong_removed)}
    if OSSL_PARAM_BLD_push_ulong_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_BLD_push_ulong)}
      OSSL_PARAM_BLD_push_ulong := _OSSL_PARAM_BLD_push_ulong;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_BLD_push_ulong_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_BLD_push_ulong');
    {$ifend}
  end;
  
  OSSL_PARAM_BLD_push_int32 := LoadLibFunction(ADllHandle, OSSL_PARAM_BLD_push_int32_procname);
  FuncLoadError := not assigned(OSSL_PARAM_BLD_push_int32);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_BLD_push_int32_allownil)}
    OSSL_PARAM_BLD_push_int32 := ERR_OSSL_PARAM_BLD_push_int32;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_int32_introduced)}
    if LibVersion < OSSL_PARAM_BLD_push_int32_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_BLD_push_int32)}
      OSSL_PARAM_BLD_push_int32 := FC_OSSL_PARAM_BLD_push_int32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_int32_removed)}
    if OSSL_PARAM_BLD_push_int32_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_BLD_push_int32)}
      OSSL_PARAM_BLD_push_int32 := _OSSL_PARAM_BLD_push_int32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_BLD_push_int32_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_BLD_push_int32');
    {$ifend}
  end;
  
  OSSL_PARAM_BLD_push_uint32 := LoadLibFunction(ADllHandle, OSSL_PARAM_BLD_push_uint32_procname);
  FuncLoadError := not assigned(OSSL_PARAM_BLD_push_uint32);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_BLD_push_uint32_allownil)}
    OSSL_PARAM_BLD_push_uint32 := ERR_OSSL_PARAM_BLD_push_uint32;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_uint32_introduced)}
    if LibVersion < OSSL_PARAM_BLD_push_uint32_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_BLD_push_uint32)}
      OSSL_PARAM_BLD_push_uint32 := FC_OSSL_PARAM_BLD_push_uint32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_uint32_removed)}
    if OSSL_PARAM_BLD_push_uint32_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_BLD_push_uint32)}
      OSSL_PARAM_BLD_push_uint32 := _OSSL_PARAM_BLD_push_uint32;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_BLD_push_uint32_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_BLD_push_uint32');
    {$ifend}
  end;
  
  OSSL_PARAM_BLD_push_int64 := LoadLibFunction(ADllHandle, OSSL_PARAM_BLD_push_int64_procname);
  FuncLoadError := not assigned(OSSL_PARAM_BLD_push_int64);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_BLD_push_int64_allownil)}
    OSSL_PARAM_BLD_push_int64 := ERR_OSSL_PARAM_BLD_push_int64;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_int64_introduced)}
    if LibVersion < OSSL_PARAM_BLD_push_int64_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_BLD_push_int64)}
      OSSL_PARAM_BLD_push_int64 := FC_OSSL_PARAM_BLD_push_int64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_int64_removed)}
    if OSSL_PARAM_BLD_push_int64_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_BLD_push_int64)}
      OSSL_PARAM_BLD_push_int64 := _OSSL_PARAM_BLD_push_int64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_BLD_push_int64_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_BLD_push_int64');
    {$ifend}
  end;
  
  OSSL_PARAM_BLD_push_uint64 := LoadLibFunction(ADllHandle, OSSL_PARAM_BLD_push_uint64_procname);
  FuncLoadError := not assigned(OSSL_PARAM_BLD_push_uint64);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_BLD_push_uint64_allownil)}
    OSSL_PARAM_BLD_push_uint64 := ERR_OSSL_PARAM_BLD_push_uint64;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_uint64_introduced)}
    if LibVersion < OSSL_PARAM_BLD_push_uint64_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_BLD_push_uint64)}
      OSSL_PARAM_BLD_push_uint64 := FC_OSSL_PARAM_BLD_push_uint64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_uint64_removed)}
    if OSSL_PARAM_BLD_push_uint64_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_BLD_push_uint64)}
      OSSL_PARAM_BLD_push_uint64 := _OSSL_PARAM_BLD_push_uint64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_BLD_push_uint64_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_BLD_push_uint64');
    {$ifend}
  end;
  
  OSSL_PARAM_BLD_push_size_t := LoadLibFunction(ADllHandle, OSSL_PARAM_BLD_push_size_t_procname);
  FuncLoadError := not assigned(OSSL_PARAM_BLD_push_size_t);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_BLD_push_size_t_allownil)}
    OSSL_PARAM_BLD_push_size_t := ERR_OSSL_PARAM_BLD_push_size_t;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_size_t_introduced)}
    if LibVersion < OSSL_PARAM_BLD_push_size_t_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_BLD_push_size_t)}
      OSSL_PARAM_BLD_push_size_t := FC_OSSL_PARAM_BLD_push_size_t;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_size_t_removed)}
    if OSSL_PARAM_BLD_push_size_t_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_BLD_push_size_t)}
      OSSL_PARAM_BLD_push_size_t := _OSSL_PARAM_BLD_push_size_t;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_BLD_push_size_t_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_BLD_push_size_t');
    {$ifend}
  end;
  
  OSSL_PARAM_BLD_push_time_t := LoadLibFunction(ADllHandle, OSSL_PARAM_BLD_push_time_t_procname);
  FuncLoadError := not assigned(OSSL_PARAM_BLD_push_time_t);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_BLD_push_time_t_allownil)}
    OSSL_PARAM_BLD_push_time_t := ERR_OSSL_PARAM_BLD_push_time_t;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_time_t_introduced)}
    if LibVersion < OSSL_PARAM_BLD_push_time_t_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_BLD_push_time_t)}
      OSSL_PARAM_BLD_push_time_t := FC_OSSL_PARAM_BLD_push_time_t;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_time_t_removed)}
    if OSSL_PARAM_BLD_push_time_t_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_BLD_push_time_t)}
      OSSL_PARAM_BLD_push_time_t := _OSSL_PARAM_BLD_push_time_t;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_BLD_push_time_t_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_BLD_push_time_t');
    {$ifend}
  end;
  
  OSSL_PARAM_BLD_push_double := LoadLibFunction(ADllHandle, OSSL_PARAM_BLD_push_double_procname);
  FuncLoadError := not assigned(OSSL_PARAM_BLD_push_double);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_BLD_push_double_allownil)}
    OSSL_PARAM_BLD_push_double := ERR_OSSL_PARAM_BLD_push_double;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_double_introduced)}
    if LibVersion < OSSL_PARAM_BLD_push_double_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_BLD_push_double)}
      OSSL_PARAM_BLD_push_double := FC_OSSL_PARAM_BLD_push_double;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_double_removed)}
    if OSSL_PARAM_BLD_push_double_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_BLD_push_double)}
      OSSL_PARAM_BLD_push_double := _OSSL_PARAM_BLD_push_double;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_BLD_push_double_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_BLD_push_double');
    {$ifend}
  end;
  
  OSSL_PARAM_BLD_push_BN := LoadLibFunction(ADllHandle, OSSL_PARAM_BLD_push_BN_procname);
  FuncLoadError := not assigned(OSSL_PARAM_BLD_push_BN);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_BLD_push_BN_allownil)}
    OSSL_PARAM_BLD_push_BN := ERR_OSSL_PARAM_BLD_push_BN;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_BN_introduced)}
    if LibVersion < OSSL_PARAM_BLD_push_BN_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_BLD_push_BN)}
      OSSL_PARAM_BLD_push_BN := FC_OSSL_PARAM_BLD_push_BN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_BN_removed)}
    if OSSL_PARAM_BLD_push_BN_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_BLD_push_BN)}
      OSSL_PARAM_BLD_push_BN := _OSSL_PARAM_BLD_push_BN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_BLD_push_BN_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_BLD_push_BN');
    {$ifend}
  end;
  
  OSSL_PARAM_BLD_push_BN_pad := LoadLibFunction(ADllHandle, OSSL_PARAM_BLD_push_BN_pad_procname);
  FuncLoadError := not assigned(OSSL_PARAM_BLD_push_BN_pad);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_BLD_push_BN_pad_allownil)}
    OSSL_PARAM_BLD_push_BN_pad := ERR_OSSL_PARAM_BLD_push_BN_pad;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_BN_pad_introduced)}
    if LibVersion < OSSL_PARAM_BLD_push_BN_pad_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_BLD_push_BN_pad)}
      OSSL_PARAM_BLD_push_BN_pad := FC_OSSL_PARAM_BLD_push_BN_pad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_BN_pad_removed)}
    if OSSL_PARAM_BLD_push_BN_pad_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_BLD_push_BN_pad)}
      OSSL_PARAM_BLD_push_BN_pad := _OSSL_PARAM_BLD_push_BN_pad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_BLD_push_BN_pad_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_BLD_push_BN_pad');
    {$ifend}
  end;
  
  OSSL_PARAM_BLD_push_utf8_string := LoadLibFunction(ADllHandle, OSSL_PARAM_BLD_push_utf8_string_procname);
  FuncLoadError := not assigned(OSSL_PARAM_BLD_push_utf8_string);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_BLD_push_utf8_string_allownil)}
    OSSL_PARAM_BLD_push_utf8_string := ERR_OSSL_PARAM_BLD_push_utf8_string;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_utf8_string_introduced)}
    if LibVersion < OSSL_PARAM_BLD_push_utf8_string_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_BLD_push_utf8_string)}
      OSSL_PARAM_BLD_push_utf8_string := FC_OSSL_PARAM_BLD_push_utf8_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_utf8_string_removed)}
    if OSSL_PARAM_BLD_push_utf8_string_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_BLD_push_utf8_string)}
      OSSL_PARAM_BLD_push_utf8_string := _OSSL_PARAM_BLD_push_utf8_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_BLD_push_utf8_string_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_BLD_push_utf8_string');
    {$ifend}
  end;
  
  OSSL_PARAM_BLD_push_utf8_ptr := LoadLibFunction(ADllHandle, OSSL_PARAM_BLD_push_utf8_ptr_procname);
  FuncLoadError := not assigned(OSSL_PARAM_BLD_push_utf8_ptr);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_BLD_push_utf8_ptr_allownil)}
    OSSL_PARAM_BLD_push_utf8_ptr := ERR_OSSL_PARAM_BLD_push_utf8_ptr;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_utf8_ptr_introduced)}
    if LibVersion < OSSL_PARAM_BLD_push_utf8_ptr_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_BLD_push_utf8_ptr)}
      OSSL_PARAM_BLD_push_utf8_ptr := FC_OSSL_PARAM_BLD_push_utf8_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_utf8_ptr_removed)}
    if OSSL_PARAM_BLD_push_utf8_ptr_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_BLD_push_utf8_ptr)}
      OSSL_PARAM_BLD_push_utf8_ptr := _OSSL_PARAM_BLD_push_utf8_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_BLD_push_utf8_ptr_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_BLD_push_utf8_ptr');
    {$ifend}
  end;
  
  OSSL_PARAM_BLD_push_octet_string := LoadLibFunction(ADllHandle, OSSL_PARAM_BLD_push_octet_string_procname);
  FuncLoadError := not assigned(OSSL_PARAM_BLD_push_octet_string);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_BLD_push_octet_string_allownil)}
    OSSL_PARAM_BLD_push_octet_string := ERR_OSSL_PARAM_BLD_push_octet_string;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_octet_string_introduced)}
    if LibVersion < OSSL_PARAM_BLD_push_octet_string_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_BLD_push_octet_string)}
      OSSL_PARAM_BLD_push_octet_string := FC_OSSL_PARAM_BLD_push_octet_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_octet_string_removed)}
    if OSSL_PARAM_BLD_push_octet_string_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_BLD_push_octet_string)}
      OSSL_PARAM_BLD_push_octet_string := _OSSL_PARAM_BLD_push_octet_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_BLD_push_octet_string_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_BLD_push_octet_string');
    {$ifend}
  end;
  
  OSSL_PARAM_BLD_push_octet_ptr := LoadLibFunction(ADllHandle, OSSL_PARAM_BLD_push_octet_ptr_procname);
  FuncLoadError := not assigned(OSSL_PARAM_BLD_push_octet_ptr);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_PARAM_BLD_push_octet_ptr_allownil)}
    OSSL_PARAM_BLD_push_octet_ptr := ERR_OSSL_PARAM_BLD_push_octet_ptr;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_octet_ptr_introduced)}
    if LibVersion < OSSL_PARAM_BLD_push_octet_ptr_introduced then
    begin
      {$if declared(FC_OSSL_PARAM_BLD_push_octet_ptr)}
      OSSL_PARAM_BLD_push_octet_ptr := FC_OSSL_PARAM_BLD_push_octet_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_PARAM_BLD_push_octet_ptr_removed)}
    if OSSL_PARAM_BLD_push_octet_ptr_removed <= LibVersion then
    begin
      {$if declared(_OSSL_PARAM_BLD_push_octet_ptr)}
      OSSL_PARAM_BLD_push_octet_ptr := _OSSL_PARAM_BLD_push_octet_ptr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_PARAM_BLD_push_octet_ptr_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_PARAM_BLD_push_octet_ptr');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  OSSL_PARAM_BLD_new := nil;
  OSSL_PARAM_BLD_to_param := nil;
  OSSL_PARAM_BLD_free := nil;
  OSSL_PARAM_BLD_push_int := nil;
  OSSL_PARAM_BLD_push_uint := nil;
  OSSL_PARAM_BLD_push_long := nil;
  OSSL_PARAM_BLD_push_ulong := nil;
  OSSL_PARAM_BLD_push_int32 := nil;
  OSSL_PARAM_BLD_push_uint32 := nil;
  OSSL_PARAM_BLD_push_int64 := nil;
  OSSL_PARAM_BLD_push_uint64 := nil;
  OSSL_PARAM_BLD_push_size_t := nil;
  OSSL_PARAM_BLD_push_time_t := nil;
  OSSL_PARAM_BLD_push_double := nil;
  OSSL_PARAM_BLD_push_BN := nil;
  OSSL_PARAM_BLD_push_BN_pad := nil;
  OSSL_PARAM_BLD_push_utf8_string := nil;
  OSSL_PARAM_BLD_push_utf8_ptr := nil;
  OSSL_PARAM_BLD_push_octet_string := nil;
  OSSL_PARAM_BLD_push_octet_ptr := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.