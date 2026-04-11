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

unit TaurusTLSHeaders_comp;

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
  Pssl_comp_st = ^Tssl_comp_st;
  Tssl_comp_st =   record end;
  {$EXTERNALSYM Pssl_comp_st}


{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  COMP_CTX_new: function(meth: PCOMP_METHOD): PCOMP_CTX; cdecl = nil;
  {$EXTERNALSYM COMP_CTX_new}

  COMP_CTX_get_method: function(ctx: PCOMP_CTX): PCOMP_METHOD; cdecl = nil;
  {$EXTERNALSYM COMP_CTX_get_method}

  COMP_CTX_get_type: function(comp: PCOMP_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM COMP_CTX_get_type}

  COMP_get_type: function(meth: PCOMP_METHOD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM COMP_get_type}

  COMP_get_name: function(meth: PCOMP_METHOD): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM COMP_get_name}

  COMP_CTX_free: procedure(ctx: PCOMP_CTX); cdecl = nil;
  {$EXTERNALSYM COMP_CTX_free}

  COMP_compress_block: function(ctx: PCOMP_CTX; _out: PIdAnsiChar; olen: TIdC_INT; _in: PIdAnsiChar; ilen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM COMP_compress_block}

  COMP_expand_block: function(ctx: PCOMP_CTX; _out: PIdAnsiChar; olen: TIdC_INT; _in: PIdAnsiChar; ilen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM COMP_expand_block}

  COMP_zlib: function: PCOMP_METHOD; cdecl = nil;
  {$EXTERNALSYM COMP_zlib}

  COMP_zlib_oneshot: function: PCOMP_METHOD; cdecl = nil;
  {$EXTERNALSYM COMP_zlib_oneshot}

  COMP_brotli: function: PCOMP_METHOD; cdecl = nil;
  {$EXTERNALSYM COMP_brotli}

  COMP_brotli_oneshot: function: PCOMP_METHOD; cdecl = nil;
  {$EXTERNALSYM COMP_brotli_oneshot}

  COMP_zstd: function: PCOMP_METHOD; cdecl = nil;
  {$EXTERNALSYM COMP_zstd}

  COMP_zstd_oneshot: function: PCOMP_METHOD; cdecl = nil;
  {$EXTERNALSYM COMP_zstd_oneshot}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function COMP_CTX_new(meth: PCOMP_METHOD): PCOMP_CTX; cdecl;
function COMP_CTX_get_method(ctx: PCOMP_CTX): PCOMP_METHOD; cdecl;
function COMP_CTX_get_type(comp: PCOMP_CTX): TIdC_INT; cdecl;
function COMP_get_type(meth: PCOMP_METHOD): TIdC_INT; cdecl;
function COMP_get_name(meth: PCOMP_METHOD): PIdAnsiChar; cdecl;
procedure COMP_CTX_free(ctx: PCOMP_CTX); cdecl;
function COMP_compress_block(ctx: PCOMP_CTX; _out: PIdAnsiChar; olen: TIdC_INT; _in: PIdAnsiChar; ilen: TIdC_INT): TIdC_INT; cdecl;
function COMP_expand_block(ctx: PCOMP_CTX; _out: PIdAnsiChar; olen: TIdC_INT; _in: PIdAnsiChar; ilen: TIdC_INT): TIdC_INT; cdecl;
function COMP_zlib: PCOMP_METHOD; cdecl;
function COMP_zlib_oneshot: PCOMP_METHOD; cdecl;
function COMP_brotli: PCOMP_METHOD; cdecl;
function COMP_brotli_oneshot: PCOMP_METHOD; cdecl;
function COMP_zstd: PCOMP_METHOD; cdecl;
function COMP_zstd_oneshot: PCOMP_METHOD; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// OPENSSL STACK DEFINITIONS
// =============================================================================
type
  { TODO 1 -copenssl stack SSL_COMP definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_SSL_COMP = Pointer;
  {$EXTERNALSYM PSTACK_OF_SSL_COMP}

  { Original Stack Macros for SSL_COMP:
    SKM_DEFINE_STACK_OF_INTERNAL(SSL_COMP, SSL_COMP, SSL_COMP)
    sk_SSL_COMP_num(sk) OPENSSL_sk_num(ossl_check_const_SSL_COMP_sk_type(sk))
    sk_SSL_COMP_value(sk, idx) ((SSL_COMP *)OPENSSL_sk_value(ossl_check_const_SSL_COMP_sk_type(sk), (idx)))
    sk_SSL_COMP_new(cmp) ((STACK_OF(SSL_COMP) *)OPENSSL_sk_new(ossl_check_SSL_COMP_compfunc_type(cmp)))
    sk_SSL_COMP_new_null() ((STACK_OF(SSL_COMP) *)OPENSSL_sk_new_null())
    sk_SSL_COMP_new_reserve(cmp, n) ((STACK_OF(SSL_COMP) *)OPENSSL_sk_new_reserve(ossl_check_SSL_COMP_compfunc_type(cmp), (n)))
    sk_SSL_COMP_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_SSL_COMP_sk_type(sk), (n))
    sk_SSL_COMP_free(sk) OPENSSL_sk_free(ossl_check_SSL_COMP_sk_type(sk))
    sk_SSL_COMP_zero(sk) OPENSSL_sk_zero(ossl_check_SSL_COMP_sk_type(sk))
    sk_SSL_COMP_delete(sk, i) ((SSL_COMP *)OPENSSL_sk_delete(ossl_check_SSL_COMP_sk_type(sk), (i)))
    sk_SSL_COMP_delete_ptr(sk, ptr) ((SSL_COMP *)OPENSSL_sk_delete_ptr(ossl_check_SSL_COMP_sk_type(sk), ossl_check_SSL_COMP_type(ptr)))
    sk_SSL_COMP_push(sk, ptr) OPENSSL_sk_push(ossl_check_SSL_COMP_sk_type(sk), ossl_check_SSL_COMP_type(ptr))
    sk_SSL_COMP_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_SSL_COMP_sk_type(sk), ossl_check_SSL_COMP_type(ptr))
    sk_SSL_COMP_pop(sk) ((SSL_COMP *)OPENSSL_sk_pop(ossl_check_SSL_COMP_sk_type(sk)))
    sk_SSL_COMP_shift(sk) ((SSL_COMP *)OPENSSL_sk_shift(ossl_check_SSL_COMP_sk_type(sk)))
    sk_SSL_COMP_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_SSL_COMP_sk_type(sk), ossl_check_SSL_COMP_freefunc_type(freefunc))
    sk_SSL_COMP_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_SSL_COMP_sk_type(sk), ossl_check_SSL_COMP_type(ptr), (idx))
    sk_SSL_COMP_set(sk, idx, ptr) ((SSL_COMP *)OPENSSL_sk_set(ossl_check_SSL_COMP_sk_type(sk), (idx), ossl_check_SSL_COMP_type(ptr)))
    sk_SSL_COMP_find(sk, ptr) OPENSSL_sk_find(ossl_check_SSL_COMP_sk_type(sk), ossl_check_SSL_COMP_type(ptr))
    sk_SSL_COMP_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_SSL_COMP_sk_type(sk), ossl_check_SSL_COMP_type(ptr))
    sk_SSL_COMP_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_SSL_COMP_sk_type(sk), ossl_check_SSL_COMP_type(ptr), pnum)
    sk_SSL_COMP_sort(sk) OPENSSL_sk_sort(ossl_check_SSL_COMP_sk_type(sk))
    sk_SSL_COMP_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_SSL_COMP_sk_type(sk))
    sk_SSL_COMP_dup(sk) ((STACK_OF(SSL_COMP) *)OPENSSL_sk_dup(ossl_check_const_SSL_COMP_sk_type(sk)))
    sk_SSL_COMP_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(SSL_COMP) *)OPENSSL_sk_deep_copy(ossl_check_const_SSL_COMP_sk_type(sk), ossl_check_SSL_COMP_copyfunc_type(copyfunc), ossl_check_SSL_COMP_freefunc_type(freefunc)))
    sk_SSL_COMP_set_cmp_func(sk, cmp) ((sk_SSL_COMP_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_SSL_COMP_sk_type(sk), ossl_check_SSL_COMP_compfunc_type(cmp)))
  }


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

function COMP_CTX_new(meth: PCOMP_METHOD): PCOMP_CTX; cdecl external CLibCrypto name 'COMP_CTX_new';
function COMP_CTX_get_method(ctx: PCOMP_CTX): PCOMP_METHOD; cdecl external CLibCrypto name 'COMP_CTX_get_method';
function COMP_CTX_get_type(comp: PCOMP_CTX): TIdC_INT; cdecl external CLibCrypto name 'COMP_CTX_get_type';
function COMP_get_type(meth: PCOMP_METHOD): TIdC_INT; cdecl external CLibCrypto name 'COMP_get_type';
function COMP_get_name(meth: PCOMP_METHOD): PIdAnsiChar; cdecl external CLibCrypto name 'COMP_get_name';
procedure COMP_CTX_free(ctx: PCOMP_CTX); cdecl external CLibCrypto name 'COMP_CTX_free';
function COMP_compress_block(ctx: PCOMP_CTX; _out: PIdAnsiChar; olen: TIdC_INT; _in: PIdAnsiChar; ilen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'COMP_compress_block';
function COMP_expand_block(ctx: PCOMP_CTX; _out: PIdAnsiChar; olen: TIdC_INT; _in: PIdAnsiChar; ilen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'COMP_expand_block';
function COMP_zlib: PCOMP_METHOD; cdecl external CLibCrypto name 'COMP_zlib';
function COMP_zlib_oneshot: PCOMP_METHOD; cdecl external CLibCrypto name 'COMP_zlib_oneshot';
function COMP_brotli: PCOMP_METHOD; cdecl external CLibCrypto name 'COMP_brotli';
function COMP_brotli_oneshot: PCOMP_METHOD; cdecl external CLibCrypto name 'COMP_brotli_oneshot';
function COMP_zstd: PCOMP_METHOD; cdecl external CLibCrypto name 'COMP_zstd';
function COMP_zstd_oneshot: PCOMP_METHOD; cdecl external CLibCrypto name 'COMP_zstd_oneshot';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  COMP_CTX_new_procname = 'COMP_CTX_new';
  COMP_CTX_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  COMP_CTX_get_method_procname = 'COMP_CTX_get_method';
  COMP_CTX_get_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  COMP_CTX_get_type_procname = 'COMP_CTX_get_type';
  COMP_CTX_get_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  COMP_get_type_procname = 'COMP_get_type';
  COMP_get_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  COMP_get_name_procname = 'COMP_get_name';
  COMP_get_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  COMP_CTX_free_procname = 'COMP_CTX_free';
  COMP_CTX_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  COMP_compress_block_procname = 'COMP_compress_block';
  COMP_compress_block_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  COMP_expand_block_procname = 'COMP_expand_block';
  COMP_expand_block_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  COMP_zlib_procname = 'COMP_zlib';
  COMP_zlib_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  COMP_zlib_oneshot_procname = 'COMP_zlib_oneshot';
  COMP_zlib_oneshot_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  COMP_brotli_procname = 'COMP_brotli';
  COMP_brotli_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  COMP_brotli_oneshot_procname = 'COMP_brotli_oneshot';
  COMP_brotli_oneshot_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  COMP_zstd_procname = 'COMP_zstd';
  COMP_zstd_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  COMP_zstd_oneshot_procname = 'COMP_zstd_oneshot';
  COMP_zstd_oneshot_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_COMP_CTX_new(meth: PCOMP_METHOD): PCOMP_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(COMP_CTX_new_procname);
end;

function ERR_COMP_CTX_get_method(ctx: PCOMP_CTX): PCOMP_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(COMP_CTX_get_method_procname);
end;

function ERR_COMP_CTX_get_type(comp: PCOMP_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(COMP_CTX_get_type_procname);
end;

function ERR_COMP_get_type(meth: PCOMP_METHOD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(COMP_get_type_procname);
end;

function ERR_COMP_get_name(meth: PCOMP_METHOD): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(COMP_get_name_procname);
end;

procedure ERR_COMP_CTX_free(ctx: PCOMP_CTX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(COMP_CTX_free_procname);
end;

function ERR_COMP_compress_block(ctx: PCOMP_CTX; _out: PIdAnsiChar; olen: TIdC_INT; _in: PIdAnsiChar; ilen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(COMP_compress_block_procname);
end;

function ERR_COMP_expand_block(ctx: PCOMP_CTX; _out: PIdAnsiChar; olen: TIdC_INT; _in: PIdAnsiChar; ilen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(COMP_expand_block_procname);
end;

function ERR_COMP_zlib: PCOMP_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(COMP_zlib_procname);
end;

function ERR_COMP_zlib_oneshot: PCOMP_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(COMP_zlib_oneshot_procname);
end;

function ERR_COMP_brotli: PCOMP_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(COMP_brotli_procname);
end;

function ERR_COMP_brotli_oneshot: PCOMP_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(COMP_brotli_oneshot_procname);
end;

function ERR_COMP_zstd: PCOMP_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(COMP_zstd_procname);
end;

function ERR_COMP_zstd_oneshot: PCOMP_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(COMP_zstd_oneshot_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  COMP_CTX_new := LoadLibFunction(ADllHandle, COMP_CTX_new_procname);
  FuncLoadError := not assigned(COMP_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(COMP_CTX_new_allownil)}
    COMP_CTX_new := ERR_COMP_CTX_new;
    {$ifend}
    {$if declared(COMP_CTX_new_introduced)}
    if LibVersion < COMP_CTX_new_introduced then
    begin
      {$if declared(FC_COMP_CTX_new)}
      COMP_CTX_new := FC_COMP_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(COMP_CTX_new_removed)}
    if COMP_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_COMP_CTX_new)}
      COMP_CTX_new := _COMP_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(COMP_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('COMP_CTX_new');
    {$ifend}
  end;
  
  COMP_CTX_get_method := LoadLibFunction(ADllHandle, COMP_CTX_get_method_procname);
  FuncLoadError := not assigned(COMP_CTX_get_method);
  if FuncLoadError then
  begin
    {$if not defined(COMP_CTX_get_method_allownil)}
    COMP_CTX_get_method := ERR_COMP_CTX_get_method;
    {$ifend}
    {$if declared(COMP_CTX_get_method_introduced)}
    if LibVersion < COMP_CTX_get_method_introduced then
    begin
      {$if declared(FC_COMP_CTX_get_method)}
      COMP_CTX_get_method := FC_COMP_CTX_get_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(COMP_CTX_get_method_removed)}
    if COMP_CTX_get_method_removed <= LibVersion then
    begin
      {$if declared(_COMP_CTX_get_method)}
      COMP_CTX_get_method := _COMP_CTX_get_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(COMP_CTX_get_method_allownil)}
    if FuncLoadError then
      AFailed.Add('COMP_CTX_get_method');
    {$ifend}
  end;
  
  COMP_CTX_get_type := LoadLibFunction(ADllHandle, COMP_CTX_get_type_procname);
  FuncLoadError := not assigned(COMP_CTX_get_type);
  if FuncLoadError then
  begin
    {$if not defined(COMP_CTX_get_type_allownil)}
    COMP_CTX_get_type := ERR_COMP_CTX_get_type;
    {$ifend}
    {$if declared(COMP_CTX_get_type_introduced)}
    if LibVersion < COMP_CTX_get_type_introduced then
    begin
      {$if declared(FC_COMP_CTX_get_type)}
      COMP_CTX_get_type := FC_COMP_CTX_get_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(COMP_CTX_get_type_removed)}
    if COMP_CTX_get_type_removed <= LibVersion then
    begin
      {$if declared(_COMP_CTX_get_type)}
      COMP_CTX_get_type := _COMP_CTX_get_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(COMP_CTX_get_type_allownil)}
    if FuncLoadError then
      AFailed.Add('COMP_CTX_get_type');
    {$ifend}
  end;
  
  COMP_get_type := LoadLibFunction(ADllHandle, COMP_get_type_procname);
  FuncLoadError := not assigned(COMP_get_type);
  if FuncLoadError then
  begin
    {$if not defined(COMP_get_type_allownil)}
    COMP_get_type := ERR_COMP_get_type;
    {$ifend}
    {$if declared(COMP_get_type_introduced)}
    if LibVersion < COMP_get_type_introduced then
    begin
      {$if declared(FC_COMP_get_type)}
      COMP_get_type := FC_COMP_get_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(COMP_get_type_removed)}
    if COMP_get_type_removed <= LibVersion then
    begin
      {$if declared(_COMP_get_type)}
      COMP_get_type := _COMP_get_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(COMP_get_type_allownil)}
    if FuncLoadError then
      AFailed.Add('COMP_get_type');
    {$ifend}
  end;
  
  COMP_get_name := LoadLibFunction(ADllHandle, COMP_get_name_procname);
  FuncLoadError := not assigned(COMP_get_name);
  if FuncLoadError then
  begin
    {$if not defined(COMP_get_name_allownil)}
    COMP_get_name := ERR_COMP_get_name;
    {$ifend}
    {$if declared(COMP_get_name_introduced)}
    if LibVersion < COMP_get_name_introduced then
    begin
      {$if declared(FC_COMP_get_name)}
      COMP_get_name := FC_COMP_get_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(COMP_get_name_removed)}
    if COMP_get_name_removed <= LibVersion then
    begin
      {$if declared(_COMP_get_name)}
      COMP_get_name := _COMP_get_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(COMP_get_name_allownil)}
    if FuncLoadError then
      AFailed.Add('COMP_get_name');
    {$ifend}
  end;
  
  COMP_CTX_free := LoadLibFunction(ADllHandle, COMP_CTX_free_procname);
  FuncLoadError := not assigned(COMP_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(COMP_CTX_free_allownil)}
    COMP_CTX_free := ERR_COMP_CTX_free;
    {$ifend}
    {$if declared(COMP_CTX_free_introduced)}
    if LibVersion < COMP_CTX_free_introduced then
    begin
      {$if declared(FC_COMP_CTX_free)}
      COMP_CTX_free := FC_COMP_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(COMP_CTX_free_removed)}
    if COMP_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_COMP_CTX_free)}
      COMP_CTX_free := _COMP_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(COMP_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('COMP_CTX_free');
    {$ifend}
  end;
  
  COMP_compress_block := LoadLibFunction(ADllHandle, COMP_compress_block_procname);
  FuncLoadError := not assigned(COMP_compress_block);
  if FuncLoadError then
  begin
    {$if not defined(COMP_compress_block_allownil)}
    COMP_compress_block := ERR_COMP_compress_block;
    {$ifend}
    {$if declared(COMP_compress_block_introduced)}
    if LibVersion < COMP_compress_block_introduced then
    begin
      {$if declared(FC_COMP_compress_block)}
      COMP_compress_block := FC_COMP_compress_block;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(COMP_compress_block_removed)}
    if COMP_compress_block_removed <= LibVersion then
    begin
      {$if declared(_COMP_compress_block)}
      COMP_compress_block := _COMP_compress_block;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(COMP_compress_block_allownil)}
    if FuncLoadError then
      AFailed.Add('COMP_compress_block');
    {$ifend}
  end;
  
  COMP_expand_block := LoadLibFunction(ADllHandle, COMP_expand_block_procname);
  FuncLoadError := not assigned(COMP_expand_block);
  if FuncLoadError then
  begin
    {$if not defined(COMP_expand_block_allownil)}
    COMP_expand_block := ERR_COMP_expand_block;
    {$ifend}
    {$if declared(COMP_expand_block_introduced)}
    if LibVersion < COMP_expand_block_introduced then
    begin
      {$if declared(FC_COMP_expand_block)}
      COMP_expand_block := FC_COMP_expand_block;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(COMP_expand_block_removed)}
    if COMP_expand_block_removed <= LibVersion then
    begin
      {$if declared(_COMP_expand_block)}
      COMP_expand_block := _COMP_expand_block;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(COMP_expand_block_allownil)}
    if FuncLoadError then
      AFailed.Add('COMP_expand_block');
    {$ifend}
  end;
  
  COMP_zlib := LoadLibFunction(ADllHandle, COMP_zlib_procname);
  FuncLoadError := not assigned(COMP_zlib);
  if FuncLoadError then
  begin
    {$if not defined(COMP_zlib_allownil)}
    COMP_zlib := ERR_COMP_zlib;
    {$ifend}
    {$if declared(COMP_zlib_introduced)}
    if LibVersion < COMP_zlib_introduced then
    begin
      {$if declared(FC_COMP_zlib)}
      COMP_zlib := FC_COMP_zlib;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(COMP_zlib_removed)}
    if COMP_zlib_removed <= LibVersion then
    begin
      {$if declared(_COMP_zlib)}
      COMP_zlib := _COMP_zlib;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(COMP_zlib_allownil)}
    if FuncLoadError then
      AFailed.Add('COMP_zlib');
    {$ifend}
  end;
  
  COMP_zlib_oneshot := LoadLibFunction(ADllHandle, COMP_zlib_oneshot_procname);
  FuncLoadError := not assigned(COMP_zlib_oneshot);
  if FuncLoadError then
  begin
    {$if not defined(COMP_zlib_oneshot_allownil)}
    COMP_zlib_oneshot := ERR_COMP_zlib_oneshot;
    {$ifend}
    {$if declared(COMP_zlib_oneshot_introduced)}
    if LibVersion < COMP_zlib_oneshot_introduced then
    begin
      {$if declared(FC_COMP_zlib_oneshot)}
      COMP_zlib_oneshot := FC_COMP_zlib_oneshot;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(COMP_zlib_oneshot_removed)}
    if COMP_zlib_oneshot_removed <= LibVersion then
    begin
      {$if declared(_COMP_zlib_oneshot)}
      COMP_zlib_oneshot := _COMP_zlib_oneshot;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(COMP_zlib_oneshot_allownil)}
    if FuncLoadError then
      AFailed.Add('COMP_zlib_oneshot');
    {$ifend}
  end;
  
  COMP_brotli := LoadLibFunction(ADllHandle, COMP_brotli_procname);
  FuncLoadError := not assigned(COMP_brotli);
  if FuncLoadError then
  begin
    {$if not defined(COMP_brotli_allownil)}
    COMP_brotli := ERR_COMP_brotli;
    {$ifend}
    {$if declared(COMP_brotli_introduced)}
    if LibVersion < COMP_brotli_introduced then
    begin
      {$if declared(FC_COMP_brotli)}
      COMP_brotli := FC_COMP_brotli;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(COMP_brotli_removed)}
    if COMP_brotli_removed <= LibVersion then
    begin
      {$if declared(_COMP_brotli)}
      COMP_brotli := _COMP_brotli;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(COMP_brotli_allownil)}
    if FuncLoadError then
      AFailed.Add('COMP_brotli');
    {$ifend}
  end;
  
  COMP_brotli_oneshot := LoadLibFunction(ADllHandle, COMP_brotli_oneshot_procname);
  FuncLoadError := not assigned(COMP_brotli_oneshot);
  if FuncLoadError then
  begin
    {$if not defined(COMP_brotli_oneshot_allownil)}
    COMP_brotli_oneshot := ERR_COMP_brotli_oneshot;
    {$ifend}
    {$if declared(COMP_brotli_oneshot_introduced)}
    if LibVersion < COMP_brotli_oneshot_introduced then
    begin
      {$if declared(FC_COMP_brotli_oneshot)}
      COMP_brotli_oneshot := FC_COMP_brotli_oneshot;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(COMP_brotli_oneshot_removed)}
    if COMP_brotli_oneshot_removed <= LibVersion then
    begin
      {$if declared(_COMP_brotli_oneshot)}
      COMP_brotli_oneshot := _COMP_brotli_oneshot;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(COMP_brotli_oneshot_allownil)}
    if FuncLoadError then
      AFailed.Add('COMP_brotli_oneshot');
    {$ifend}
  end;
  
  COMP_zstd := LoadLibFunction(ADllHandle, COMP_zstd_procname);
  FuncLoadError := not assigned(COMP_zstd);
  if FuncLoadError then
  begin
    {$if not defined(COMP_zstd_allownil)}
    COMP_zstd := ERR_COMP_zstd;
    {$ifend}
    {$if declared(COMP_zstd_introduced)}
    if LibVersion < COMP_zstd_introduced then
    begin
      {$if declared(FC_COMP_zstd)}
      COMP_zstd := FC_COMP_zstd;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(COMP_zstd_removed)}
    if COMP_zstd_removed <= LibVersion then
    begin
      {$if declared(_COMP_zstd)}
      COMP_zstd := _COMP_zstd;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(COMP_zstd_allownil)}
    if FuncLoadError then
      AFailed.Add('COMP_zstd');
    {$ifend}
  end;
  
  COMP_zstd_oneshot := LoadLibFunction(ADllHandle, COMP_zstd_oneshot_procname);
  FuncLoadError := not assigned(COMP_zstd_oneshot);
  if FuncLoadError then
  begin
    {$if not defined(COMP_zstd_oneshot_allownil)}
    COMP_zstd_oneshot := ERR_COMP_zstd_oneshot;
    {$ifend}
    {$if declared(COMP_zstd_oneshot_introduced)}
    if LibVersion < COMP_zstd_oneshot_introduced then
    begin
      {$if declared(FC_COMP_zstd_oneshot)}
      COMP_zstd_oneshot := FC_COMP_zstd_oneshot;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(COMP_zstd_oneshot_removed)}
    if COMP_zstd_oneshot_removed <= LibVersion then
    begin
      {$if declared(_COMP_zstd_oneshot)}
      COMP_zstd_oneshot := _COMP_zstd_oneshot;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(COMP_zstd_oneshot_allownil)}
    if FuncLoadError then
      AFailed.Add('COMP_zstd_oneshot');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  COMP_CTX_new := nil;
  COMP_CTX_get_method := nil;
  COMP_CTX_get_type := nil;
  COMP_get_type := nil;
  COMP_get_name := nil;
  COMP_CTX_free := nil;
  COMP_compress_block := nil;
  COMP_expand_block := nil;
  COMP_zlib := nil;
  COMP_zlib_oneshot := nil;
  COMP_brotli := nil;
  COMP_brotli_oneshot := nil;
  COMP_zstd := nil;
  COMP_zstd_oneshot := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.