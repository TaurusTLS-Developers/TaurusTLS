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

unit TaurusTLSHeaders_safestack;

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
  POPENSSL_STRING = ^TOPENSSL_STRING;
  TOPENSSL_STRING = PIdAnsiChar;
  {$EXTERNALSYM POPENSSL_STRING}

  POPENSSL_CSTRING = ^TOPENSSL_CSTRING;
  TOPENSSL_CSTRING = PIdAnsiChar;
  {$EXTERNALSYM POPENSSL_CSTRING}

  Pstack_st_OPENSSL_STRING = ^Tstack_st_OPENSSL_STRING;
  Tstack_st_OPENSSL_STRING = record end;
  {$EXTERNALSYM Pstack_st_OPENSSL_STRING}

  Pstack_st_OPENSSL_CSTRING = ^Tstack_st_OPENSSL_CSTRING;
  Tstack_st_OPENSSL_CSTRING = record end;
  {$EXTERNALSYM Pstack_st_OPENSSL_CSTRING}

  POPENSSL_BLOCK = ^TOPENSSL_BLOCK;
  TOPENSSL_BLOCK = Pointer;
  {$EXTERNALSYM POPENSSL_BLOCK}

  Pstack_st_OPENSSL_BLOCK = ^Tstack_st_OPENSSL_BLOCK;
  Tstack_st_OPENSSL_BLOCK = record end;
  {$EXTERNALSYM Pstack_st_OPENSSL_BLOCK}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  Tsk_OPENSSL_STRING_compfunc_func_cb = function(arg1: PPIdAnsiChar; arg2: PPIdAnsiChar): TIdC_INT; cdecl;
  Tsk_OPENSSL_STRING_freefunc_func_cb = procedure(arg1: PIdAnsiChar); cdecl;
  Tsk_OPENSSL_STRING_copyfunc_func_cb = function(arg1: PIdAnsiChar): PIdAnsiChar; cdecl;
  Tsk_OPENSSL_BLOCK_compfunc_func_cb = function(arg1: PPointer; arg2: PPointer): TIdC_INT; cdecl;
  Tsk_OPENSSL_BLOCK_freefunc_func_cb = procedure(arg1: Pointer); cdecl;
  Tsk_OPENSSL_BLOCK_copyfunc_func_cb = function(arg1: Pointer): Pointer; cdecl;

implementation

end.