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

unit TaurusTLSHeaders_ess;

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
  PESS_issuer_serial = ^TESS_issuer_serial;
  TESS_issuer_serial =   record end;
  {$EXTERNALSYM PESS_issuer_serial}

  PESS_cert_id = ^TESS_cert_id;
  TESS_cert_id =   record end;
  {$EXTERNALSYM PESS_cert_id}

  PESS_signing_cert = ^TESS_signing_cert;
  TESS_signing_cert =   record end;
  {$EXTERNALSYM PESS_signing_cert}

  PESS_signing_cert_v2_st = ^TESS_signing_cert_v2_st;
  TESS_signing_cert_v2_st =   record end;
  {$EXTERNALSYM PESS_signing_cert_v2_st}

  PESS_cert_id_v2_st = ^TESS_cert_id_v2_st;
  TESS_cert_id_v2_st =   record end;
  {$EXTERNALSYM PESS_cert_id_v2_st}


{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  ESS_ISSUER_SERIAL_new: function: PESS_ISSUER_SERIAL; cdecl = nil;
  {$EXTERNALSYM ESS_ISSUER_SERIAL_new}

  ESS_ISSUER_SERIAL_free: procedure(a: PESS_ISSUER_SERIAL); cdecl = nil;
  {$EXTERNALSYM ESS_ISSUER_SERIAL_free}

  d2i_ESS_ISSUER_SERIAL: function(a: PPESS_ISSUER_SERIAL; _in: PPIdAnsiChar; len: TIdC_LONG): PESS_ISSUER_SERIAL; cdecl = nil;
  {$EXTERNALSYM d2i_ESS_ISSUER_SERIAL}

  i2d_ESS_ISSUER_SERIAL: function(a: PESS_ISSUER_SERIAL; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ESS_ISSUER_SERIAL}

  ESS_ISSUER_SERIAL_dup: function(a: PESS_ISSUER_SERIAL): PESS_ISSUER_SERIAL; cdecl = nil;
  {$EXTERNALSYM ESS_ISSUER_SERIAL_dup}

  ESS_CERT_ID_new: function: PESS_CERT_ID; cdecl = nil;
  {$EXTERNALSYM ESS_CERT_ID_new}

  ESS_CERT_ID_free: procedure(a: PESS_CERT_ID); cdecl = nil;
  {$EXTERNALSYM ESS_CERT_ID_free}

  d2i_ESS_CERT_ID: function(a: PPESS_CERT_ID; _in: PPIdAnsiChar; len: TIdC_LONG): PESS_CERT_ID; cdecl = nil;
  {$EXTERNALSYM d2i_ESS_CERT_ID}

  i2d_ESS_CERT_ID: function(a: PESS_CERT_ID; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ESS_CERT_ID}

  ESS_CERT_ID_dup: function(a: PESS_CERT_ID): PESS_CERT_ID; cdecl = nil;
  {$EXTERNALSYM ESS_CERT_ID_dup}

  ESS_SIGNING_CERT_new: function: PESS_SIGNING_CERT; cdecl = nil;
  {$EXTERNALSYM ESS_SIGNING_CERT_new}

  ESS_SIGNING_CERT_free: procedure(a: PESS_SIGNING_CERT); cdecl = nil;
  {$EXTERNALSYM ESS_SIGNING_CERT_free}

  d2i_ESS_SIGNING_CERT: function(a: PPESS_SIGNING_CERT; _in: PPIdAnsiChar; len: TIdC_LONG): PESS_SIGNING_CERT; cdecl = nil;
  {$EXTERNALSYM d2i_ESS_SIGNING_CERT}

  i2d_ESS_SIGNING_CERT: function(a: PESS_SIGNING_CERT; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ESS_SIGNING_CERT}

  ESS_SIGNING_CERT_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ESS_SIGNING_CERT_it}

  ESS_SIGNING_CERT_dup: function(a: PESS_SIGNING_CERT): PESS_SIGNING_CERT; cdecl = nil;
  {$EXTERNALSYM ESS_SIGNING_CERT_dup}

  ESS_CERT_ID_V2_new: function: PESS_CERT_ID_V2; cdecl = nil;
  {$EXTERNALSYM ESS_CERT_ID_V2_new}

  ESS_CERT_ID_V2_free: procedure(a: PESS_CERT_ID_V2); cdecl = nil;
  {$EXTERNALSYM ESS_CERT_ID_V2_free}

  d2i_ESS_CERT_ID_V2: function(a: PPESS_CERT_ID_V2; _in: PPIdAnsiChar; len: TIdC_LONG): PESS_CERT_ID_V2; cdecl = nil;
  {$EXTERNALSYM d2i_ESS_CERT_ID_V2}

  i2d_ESS_CERT_ID_V2: function(a: PESS_CERT_ID_V2; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ESS_CERT_ID_V2}

  ESS_CERT_ID_V2_dup: function(a: PESS_CERT_ID_V2): PESS_CERT_ID_V2; cdecl = nil;
  {$EXTERNALSYM ESS_CERT_ID_V2_dup}

  ESS_SIGNING_CERT_V2_new: function: PESS_SIGNING_CERT_V2; cdecl = nil;
  {$EXTERNALSYM ESS_SIGNING_CERT_V2_new}

  ESS_SIGNING_CERT_V2_free: procedure(a: PESS_SIGNING_CERT_V2); cdecl = nil;
  {$EXTERNALSYM ESS_SIGNING_CERT_V2_free}

  d2i_ESS_SIGNING_CERT_V2: function(a: PPESS_SIGNING_CERT_V2; _in: PPIdAnsiChar; len: TIdC_LONG): PESS_SIGNING_CERT_V2; cdecl = nil;
  {$EXTERNALSYM d2i_ESS_SIGNING_CERT_V2}

  i2d_ESS_SIGNING_CERT_V2: function(a: PESS_SIGNING_CERT_V2; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ESS_SIGNING_CERT_V2}

  ESS_SIGNING_CERT_V2_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ESS_SIGNING_CERT_V2_it}

  ESS_SIGNING_CERT_V2_dup: function(a: PESS_SIGNING_CERT_V2): PESS_SIGNING_CERT_V2; cdecl = nil;
  {$EXTERNALSYM ESS_SIGNING_CERT_V2_dup}

  OSSL_ESS_signing_cert_new_init: function(signcert: PX509; certs: Pstack_st_X509; set_issuer_serial: TIdC_INT): PESS_SIGNING_CERT; cdecl = nil;
  {$EXTERNALSYM OSSL_ESS_signing_cert_new_init}

  OSSL_ESS_signing_cert_v2_new_init: function(hash_alg: PEVP_MD; signcert: PX509; certs: Pstack_st_X509; set_issuer_serial: TIdC_INT): PESS_SIGNING_CERT_V2; cdecl = nil;
  {$EXTERNALSYM OSSL_ESS_signing_cert_v2_new_init}

  OSSL_ESS_check_signing_certs: function(ss: PESS_SIGNING_CERT; ssv2: PESS_SIGNING_CERT_V2; chain: Pstack_st_X509; require_signing_cert: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ESS_check_signing_certs}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function ESS_ISSUER_SERIAL_new: PESS_ISSUER_SERIAL; cdecl;
procedure ESS_ISSUER_SERIAL_free(a: PESS_ISSUER_SERIAL); cdecl;
function d2i_ESS_ISSUER_SERIAL(a: PPESS_ISSUER_SERIAL; _in: PPIdAnsiChar; len: TIdC_LONG): PESS_ISSUER_SERIAL; cdecl;
function i2d_ESS_ISSUER_SERIAL(a: PESS_ISSUER_SERIAL; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ESS_ISSUER_SERIAL_dup(a: PESS_ISSUER_SERIAL): PESS_ISSUER_SERIAL; cdecl;
function ESS_CERT_ID_new: PESS_CERT_ID; cdecl;
procedure ESS_CERT_ID_free(a: PESS_CERT_ID); cdecl;
function d2i_ESS_CERT_ID(a: PPESS_CERT_ID; _in: PPIdAnsiChar; len: TIdC_LONG): PESS_CERT_ID; cdecl;
function i2d_ESS_CERT_ID(a: PESS_CERT_ID; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ESS_CERT_ID_dup(a: PESS_CERT_ID): PESS_CERT_ID; cdecl;
function ESS_SIGNING_CERT_new: PESS_SIGNING_CERT; cdecl;
procedure ESS_SIGNING_CERT_free(a: PESS_SIGNING_CERT); cdecl;
function d2i_ESS_SIGNING_CERT(a: PPESS_SIGNING_CERT; _in: PPIdAnsiChar; len: TIdC_LONG): PESS_SIGNING_CERT; cdecl;
function i2d_ESS_SIGNING_CERT(a: PESS_SIGNING_CERT; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ESS_SIGNING_CERT_it: PASN1_ITEM; cdecl;
function ESS_SIGNING_CERT_dup(a: PESS_SIGNING_CERT): PESS_SIGNING_CERT; cdecl;
function ESS_CERT_ID_V2_new: PESS_CERT_ID_V2; cdecl;
procedure ESS_CERT_ID_V2_free(a: PESS_CERT_ID_V2); cdecl;
function d2i_ESS_CERT_ID_V2(a: PPESS_CERT_ID_V2; _in: PPIdAnsiChar; len: TIdC_LONG): PESS_CERT_ID_V2; cdecl;
function i2d_ESS_CERT_ID_V2(a: PESS_CERT_ID_V2; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ESS_CERT_ID_V2_dup(a: PESS_CERT_ID_V2): PESS_CERT_ID_V2; cdecl;
function ESS_SIGNING_CERT_V2_new: PESS_SIGNING_CERT_V2; cdecl;
procedure ESS_SIGNING_CERT_V2_free(a: PESS_SIGNING_CERT_V2); cdecl;
function d2i_ESS_SIGNING_CERT_V2(a: PPESS_SIGNING_CERT_V2; _in: PPIdAnsiChar; len: TIdC_LONG): PESS_SIGNING_CERT_V2; cdecl;
function i2d_ESS_SIGNING_CERT_V2(a: PESS_SIGNING_CERT_V2; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ESS_SIGNING_CERT_V2_it: PASN1_ITEM; cdecl;
function ESS_SIGNING_CERT_V2_dup(a: PESS_SIGNING_CERT_V2): PESS_SIGNING_CERT_V2; cdecl;
function OSSL_ESS_signing_cert_new_init(signcert: PX509; certs: Pstack_st_X509; set_issuer_serial: TIdC_INT): PESS_SIGNING_CERT; cdecl;
function OSSL_ESS_signing_cert_v2_new_init(hash_alg: PEVP_MD; signcert: PX509; certs: Pstack_st_X509; set_issuer_serial: TIdC_INT): PESS_SIGNING_CERT_V2; cdecl;
function OSSL_ESS_check_signing_certs(ss: PESS_SIGNING_CERT; ssv2: PESS_SIGNING_CERT_V2; chain: Pstack_st_X509; require_signing_cert: TIdC_INT): TIdC_INT; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// OPENSSL STACK DEFINITIONS
// =============================================================================
type
  { TODO 1 -copenssl stack ESS_CERT_ID definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_ESS_CERT_ID = Pointer;
  {$EXTERNALSYM PSTACK_OF_ESS_CERT_ID}

  { Original Stack Macros for ESS_CERT_ID:
    SKM_DEFINE_STACK_OF_INTERNAL(ESS_CERT_ID, ESS_CERT_ID, ESS_CERT_ID)
    sk_ESS_CERT_ID_num(sk) OPENSSL_sk_num(ossl_check_const_ESS_CERT_ID_sk_type(sk))
    sk_ESS_CERT_ID_value(sk, idx) ((ESS_CERT_ID *)OPENSSL_sk_value(ossl_check_const_ESS_CERT_ID_sk_type(sk), (idx)))
    sk_ESS_CERT_ID_new(cmp) ((STACK_OF(ESS_CERT_ID) *)OPENSSL_sk_new(ossl_check_ESS_CERT_ID_compfunc_type(cmp)))
    sk_ESS_CERT_ID_new_null() ((STACK_OF(ESS_CERT_ID) *)OPENSSL_sk_new_null())
    sk_ESS_CERT_ID_new_reserve(cmp, n) ((STACK_OF(ESS_CERT_ID) *)OPENSSL_sk_new_reserve(ossl_check_ESS_CERT_ID_compfunc_type(cmp), (n)))
    sk_ESS_CERT_ID_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_ESS_CERT_ID_sk_type(sk), (n))
    sk_ESS_CERT_ID_free(sk) OPENSSL_sk_free(ossl_check_ESS_CERT_ID_sk_type(sk))
    sk_ESS_CERT_ID_zero(sk) OPENSSL_sk_zero(ossl_check_ESS_CERT_ID_sk_type(sk))
    sk_ESS_CERT_ID_delete(sk, i) ((ESS_CERT_ID *)OPENSSL_sk_delete(ossl_check_ESS_CERT_ID_sk_type(sk), (i)))
    sk_ESS_CERT_ID_delete_ptr(sk, ptr) ((ESS_CERT_ID *)OPENSSL_sk_delete_ptr(ossl_check_ESS_CERT_ID_sk_type(sk), ossl_check_ESS_CERT_ID_type(ptr)))
    sk_ESS_CERT_ID_push(sk, ptr) OPENSSL_sk_push(ossl_check_ESS_CERT_ID_sk_type(sk), ossl_check_ESS_CERT_ID_type(ptr))
    sk_ESS_CERT_ID_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_ESS_CERT_ID_sk_type(sk), ossl_check_ESS_CERT_ID_type(ptr))
    sk_ESS_CERT_ID_pop(sk) ((ESS_CERT_ID *)OPENSSL_sk_pop(ossl_check_ESS_CERT_ID_sk_type(sk)))
    sk_ESS_CERT_ID_shift(sk) ((ESS_CERT_ID *)OPENSSL_sk_shift(ossl_check_ESS_CERT_ID_sk_type(sk)))
    sk_ESS_CERT_ID_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_ESS_CERT_ID_sk_type(sk), ossl_check_ESS_CERT_ID_freefunc_type(freefunc))
    sk_ESS_CERT_ID_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_ESS_CERT_ID_sk_type(sk), ossl_check_ESS_CERT_ID_type(ptr), (idx))
    sk_ESS_CERT_ID_set(sk, idx, ptr) ((ESS_CERT_ID *)OPENSSL_sk_set(ossl_check_ESS_CERT_ID_sk_type(sk), (idx), ossl_check_ESS_CERT_ID_type(ptr)))
    sk_ESS_CERT_ID_find(sk, ptr) OPENSSL_sk_find(ossl_check_ESS_CERT_ID_sk_type(sk), ossl_check_ESS_CERT_ID_type(ptr))
    sk_ESS_CERT_ID_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_ESS_CERT_ID_sk_type(sk), ossl_check_ESS_CERT_ID_type(ptr))
    sk_ESS_CERT_ID_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_ESS_CERT_ID_sk_type(sk), ossl_check_ESS_CERT_ID_type(ptr), pnum)
    sk_ESS_CERT_ID_sort(sk) OPENSSL_sk_sort(ossl_check_ESS_CERT_ID_sk_type(sk))
    sk_ESS_CERT_ID_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_ESS_CERT_ID_sk_type(sk))
    sk_ESS_CERT_ID_dup(sk) ((STACK_OF(ESS_CERT_ID) *)OPENSSL_sk_dup(ossl_check_const_ESS_CERT_ID_sk_type(sk)))
    sk_ESS_CERT_ID_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(ESS_CERT_ID) *)OPENSSL_sk_deep_copy(ossl_check_const_ESS_CERT_ID_sk_type(sk), ossl_check_ESS_CERT_ID_copyfunc_type(copyfunc), ossl_check_ESS_CERT_ID_freefunc_type(freefunc)))
    sk_ESS_CERT_ID_set_cmp_func(sk, cmp) ((sk_ESS_CERT_ID_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_ESS_CERT_ID_sk_type(sk), ossl_check_ESS_CERT_ID_compfunc_type(cmp)))
    sk_ESS_CERT_ID_V2_num(sk) OPENSSL_sk_num(ossl_check_const_ESS_CERT_ID_V2_sk_type(sk))
    sk_ESS_CERT_ID_V2_value(sk, idx) ((ESS_CERT_ID_V2 *)OPENSSL_sk_value(ossl_check_const_ESS_CERT_ID_V2_sk_type(sk), (idx)))
    sk_ESS_CERT_ID_V2_new(cmp) ((STACK_OF(ESS_CERT_ID_V2) *)OPENSSL_sk_new(ossl_check_ESS_CERT_ID_V2_compfunc_type(cmp)))
    sk_ESS_CERT_ID_V2_new_null() ((STACK_OF(ESS_CERT_ID_V2) *)OPENSSL_sk_new_null())
    sk_ESS_CERT_ID_V2_new_reserve(cmp, n) ((STACK_OF(ESS_CERT_ID_V2) *)OPENSSL_sk_new_reserve(ossl_check_ESS_CERT_ID_V2_compfunc_type(cmp), (n)))
    sk_ESS_CERT_ID_V2_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_ESS_CERT_ID_V2_sk_type(sk), (n))
    sk_ESS_CERT_ID_V2_free(sk) OPENSSL_sk_free(ossl_check_ESS_CERT_ID_V2_sk_type(sk))
    sk_ESS_CERT_ID_V2_zero(sk) OPENSSL_sk_zero(ossl_check_ESS_CERT_ID_V2_sk_type(sk))
    sk_ESS_CERT_ID_V2_delete(sk, i) ((ESS_CERT_ID_V2 *)OPENSSL_sk_delete(ossl_check_ESS_CERT_ID_V2_sk_type(sk), (i)))
    sk_ESS_CERT_ID_V2_delete_ptr(sk, ptr) ((ESS_CERT_ID_V2 *)OPENSSL_sk_delete_ptr(ossl_check_ESS_CERT_ID_V2_sk_type(sk), ossl_check_ESS_CERT_ID_V2_type(ptr)))
    sk_ESS_CERT_ID_V2_push(sk, ptr) OPENSSL_sk_push(ossl_check_ESS_CERT_ID_V2_sk_type(sk), ossl_check_ESS_CERT_ID_V2_type(ptr))
    sk_ESS_CERT_ID_V2_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_ESS_CERT_ID_V2_sk_type(sk), ossl_check_ESS_CERT_ID_V2_type(ptr))
    sk_ESS_CERT_ID_V2_pop(sk) ((ESS_CERT_ID_V2 *)OPENSSL_sk_pop(ossl_check_ESS_CERT_ID_V2_sk_type(sk)))
    sk_ESS_CERT_ID_V2_shift(sk) ((ESS_CERT_ID_V2 *)OPENSSL_sk_shift(ossl_check_ESS_CERT_ID_V2_sk_type(sk)))
    sk_ESS_CERT_ID_V2_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_ESS_CERT_ID_V2_sk_type(sk), ossl_check_ESS_CERT_ID_V2_freefunc_type(freefunc))
    sk_ESS_CERT_ID_V2_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_ESS_CERT_ID_V2_sk_type(sk), ossl_check_ESS_CERT_ID_V2_type(ptr), (idx))
    sk_ESS_CERT_ID_V2_set(sk, idx, ptr) ((ESS_CERT_ID_V2 *)OPENSSL_sk_set(ossl_check_ESS_CERT_ID_V2_sk_type(sk), (idx), ossl_check_ESS_CERT_ID_V2_type(ptr)))
    sk_ESS_CERT_ID_V2_find(sk, ptr) OPENSSL_sk_find(ossl_check_ESS_CERT_ID_V2_sk_type(sk), ossl_check_ESS_CERT_ID_V2_type(ptr))
    sk_ESS_CERT_ID_V2_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_ESS_CERT_ID_V2_sk_type(sk), ossl_check_ESS_CERT_ID_V2_type(ptr))
    sk_ESS_CERT_ID_V2_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_ESS_CERT_ID_V2_sk_type(sk), ossl_check_ESS_CERT_ID_V2_type(ptr), pnum)
    sk_ESS_CERT_ID_V2_sort(sk) OPENSSL_sk_sort(ossl_check_ESS_CERT_ID_V2_sk_type(sk))
    sk_ESS_CERT_ID_V2_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_ESS_CERT_ID_V2_sk_type(sk))
    sk_ESS_CERT_ID_V2_dup(sk) ((STACK_OF(ESS_CERT_ID_V2) *)OPENSSL_sk_dup(ossl_check_const_ESS_CERT_ID_V2_sk_type(sk)))
    sk_ESS_CERT_ID_V2_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(ESS_CERT_ID_V2) *)OPENSSL_sk_deep_copy(ossl_check_const_ESS_CERT_ID_V2_sk_type(sk), ossl_check_ESS_CERT_ID_V2_copyfunc_type(copyfunc), ossl_check_ESS_CERT_ID_V2_freefunc_type(freefunc)))
    sk_ESS_CERT_ID_V2_set_cmp_func(sk, cmp) ((sk_ESS_CERT_ID_V2_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_ESS_CERT_ID_V2_sk_type(sk), ossl_check_ESS_CERT_ID_V2_compfunc_type(cmp)))
  }

  { TODO 1 -copenssl stack ESS_CERT_ID_V2 definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_ESS_CERT_ID_V2 = Pointer;
  {$EXTERNALSYM PSTACK_OF_ESS_CERT_ID_V2}

  { Original Stack Macros for ESS_CERT_ID_V2:
    SKM_DEFINE_STACK_OF_INTERNAL(ESS_CERT_ID_V2, ESS_CERT_ID_V2, ESS_CERT_ID_V2)
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

function ESS_ISSUER_SERIAL_new: PESS_ISSUER_SERIAL; cdecl external CLibCrypto name 'ESS_ISSUER_SERIAL_new';
procedure ESS_ISSUER_SERIAL_free(a: PESS_ISSUER_SERIAL); cdecl external CLibCrypto name 'ESS_ISSUER_SERIAL_free';
function d2i_ESS_ISSUER_SERIAL(a: PPESS_ISSUER_SERIAL; _in: PPIdAnsiChar; len: TIdC_LONG): PESS_ISSUER_SERIAL; cdecl external CLibCrypto name 'd2i_ESS_ISSUER_SERIAL';
function i2d_ESS_ISSUER_SERIAL(a: PESS_ISSUER_SERIAL; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ESS_ISSUER_SERIAL';
function ESS_ISSUER_SERIAL_dup(a: PESS_ISSUER_SERIAL): PESS_ISSUER_SERIAL; cdecl external CLibCrypto name 'ESS_ISSUER_SERIAL_dup';
function ESS_CERT_ID_new: PESS_CERT_ID; cdecl external CLibCrypto name 'ESS_CERT_ID_new';
procedure ESS_CERT_ID_free(a: PESS_CERT_ID); cdecl external CLibCrypto name 'ESS_CERT_ID_free';
function d2i_ESS_CERT_ID(a: PPESS_CERT_ID; _in: PPIdAnsiChar; len: TIdC_LONG): PESS_CERT_ID; cdecl external CLibCrypto name 'd2i_ESS_CERT_ID';
function i2d_ESS_CERT_ID(a: PESS_CERT_ID; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ESS_CERT_ID';
function ESS_CERT_ID_dup(a: PESS_CERT_ID): PESS_CERT_ID; cdecl external CLibCrypto name 'ESS_CERT_ID_dup';
function ESS_SIGNING_CERT_new: PESS_SIGNING_CERT; cdecl external CLibCrypto name 'ESS_SIGNING_CERT_new';
procedure ESS_SIGNING_CERT_free(a: PESS_SIGNING_CERT); cdecl external CLibCrypto name 'ESS_SIGNING_CERT_free';
function d2i_ESS_SIGNING_CERT(a: PPESS_SIGNING_CERT; _in: PPIdAnsiChar; len: TIdC_LONG): PESS_SIGNING_CERT; cdecl external CLibCrypto name 'd2i_ESS_SIGNING_CERT';
function i2d_ESS_SIGNING_CERT(a: PESS_SIGNING_CERT; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ESS_SIGNING_CERT';
function ESS_SIGNING_CERT_it: PASN1_ITEM; cdecl external CLibCrypto name 'ESS_SIGNING_CERT_it';
function ESS_SIGNING_CERT_dup(a: PESS_SIGNING_CERT): PESS_SIGNING_CERT; cdecl external CLibCrypto name 'ESS_SIGNING_CERT_dup';
function ESS_CERT_ID_V2_new: PESS_CERT_ID_V2; cdecl external CLibCrypto name 'ESS_CERT_ID_V2_new';
procedure ESS_CERT_ID_V2_free(a: PESS_CERT_ID_V2); cdecl external CLibCrypto name 'ESS_CERT_ID_V2_free';
function d2i_ESS_CERT_ID_V2(a: PPESS_CERT_ID_V2; _in: PPIdAnsiChar; len: TIdC_LONG): PESS_CERT_ID_V2; cdecl external CLibCrypto name 'd2i_ESS_CERT_ID_V2';
function i2d_ESS_CERT_ID_V2(a: PESS_CERT_ID_V2; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ESS_CERT_ID_V2';
function ESS_CERT_ID_V2_dup(a: PESS_CERT_ID_V2): PESS_CERT_ID_V2; cdecl external CLibCrypto name 'ESS_CERT_ID_V2_dup';
function ESS_SIGNING_CERT_V2_new: PESS_SIGNING_CERT_V2; cdecl external CLibCrypto name 'ESS_SIGNING_CERT_V2_new';
procedure ESS_SIGNING_CERT_V2_free(a: PESS_SIGNING_CERT_V2); cdecl external CLibCrypto name 'ESS_SIGNING_CERT_V2_free';
function d2i_ESS_SIGNING_CERT_V2(a: PPESS_SIGNING_CERT_V2; _in: PPIdAnsiChar; len: TIdC_LONG): PESS_SIGNING_CERT_V2; cdecl external CLibCrypto name 'd2i_ESS_SIGNING_CERT_V2';
function i2d_ESS_SIGNING_CERT_V2(a: PESS_SIGNING_CERT_V2; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ESS_SIGNING_CERT_V2';
function ESS_SIGNING_CERT_V2_it: PASN1_ITEM; cdecl external CLibCrypto name 'ESS_SIGNING_CERT_V2_it';
function ESS_SIGNING_CERT_V2_dup(a: PESS_SIGNING_CERT_V2): PESS_SIGNING_CERT_V2; cdecl external CLibCrypto name 'ESS_SIGNING_CERT_V2_dup';
function OSSL_ESS_signing_cert_new_init(signcert: PX509; certs: Pstack_st_X509; set_issuer_serial: TIdC_INT): PESS_SIGNING_CERT; cdecl external CLibCrypto name 'OSSL_ESS_signing_cert_new_init';
function OSSL_ESS_signing_cert_v2_new_init(hash_alg: PEVP_MD; signcert: PX509; certs: Pstack_st_X509; set_issuer_serial: TIdC_INT): PESS_SIGNING_CERT_V2; cdecl external CLibCrypto name 'OSSL_ESS_signing_cert_v2_new_init';
function OSSL_ESS_check_signing_certs(ss: PESS_SIGNING_CERT; ssv2: PESS_SIGNING_CERT_V2; chain: Pstack_st_X509; require_signing_cert: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ESS_check_signing_certs';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  ESS_ISSUER_SERIAL_new_procname = 'ESS_ISSUER_SERIAL_new';
  ESS_ISSUER_SERIAL_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ESS_ISSUER_SERIAL_free_procname = 'ESS_ISSUER_SERIAL_free';
  ESS_ISSUER_SERIAL_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ESS_ISSUER_SERIAL_procname = 'd2i_ESS_ISSUER_SERIAL';
  d2i_ESS_ISSUER_SERIAL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ESS_ISSUER_SERIAL_procname = 'i2d_ESS_ISSUER_SERIAL';
  i2d_ESS_ISSUER_SERIAL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ESS_ISSUER_SERIAL_dup_procname = 'ESS_ISSUER_SERIAL_dup';
  ESS_ISSUER_SERIAL_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ESS_CERT_ID_new_procname = 'ESS_CERT_ID_new';
  ESS_CERT_ID_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ESS_CERT_ID_free_procname = 'ESS_CERT_ID_free';
  ESS_CERT_ID_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ESS_CERT_ID_procname = 'd2i_ESS_CERT_ID';
  d2i_ESS_CERT_ID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ESS_CERT_ID_procname = 'i2d_ESS_CERT_ID';
  i2d_ESS_CERT_ID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ESS_CERT_ID_dup_procname = 'ESS_CERT_ID_dup';
  ESS_CERT_ID_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ESS_SIGNING_CERT_new_procname = 'ESS_SIGNING_CERT_new';
  ESS_SIGNING_CERT_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ESS_SIGNING_CERT_free_procname = 'ESS_SIGNING_CERT_free';
  ESS_SIGNING_CERT_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ESS_SIGNING_CERT_procname = 'd2i_ESS_SIGNING_CERT';
  d2i_ESS_SIGNING_CERT_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ESS_SIGNING_CERT_procname = 'i2d_ESS_SIGNING_CERT';
  i2d_ESS_SIGNING_CERT_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ESS_SIGNING_CERT_it_procname = 'ESS_SIGNING_CERT_it';
  ESS_SIGNING_CERT_it_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ESS_SIGNING_CERT_dup_procname = 'ESS_SIGNING_CERT_dup';
  ESS_SIGNING_CERT_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ESS_CERT_ID_V2_new_procname = 'ESS_CERT_ID_V2_new';
  ESS_CERT_ID_V2_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ESS_CERT_ID_V2_free_procname = 'ESS_CERT_ID_V2_free';
  ESS_CERT_ID_V2_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  d2i_ESS_CERT_ID_V2_procname = 'd2i_ESS_CERT_ID_V2';
  d2i_ESS_CERT_ID_V2_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  i2d_ESS_CERT_ID_V2_procname = 'i2d_ESS_CERT_ID_V2';
  i2d_ESS_CERT_ID_V2_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ESS_CERT_ID_V2_dup_procname = 'ESS_CERT_ID_V2_dup';
  ESS_CERT_ID_V2_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ESS_SIGNING_CERT_V2_new_procname = 'ESS_SIGNING_CERT_V2_new';
  ESS_SIGNING_CERT_V2_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ESS_SIGNING_CERT_V2_free_procname = 'ESS_SIGNING_CERT_V2_free';
  ESS_SIGNING_CERT_V2_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  d2i_ESS_SIGNING_CERT_V2_procname = 'd2i_ESS_SIGNING_CERT_V2';
  d2i_ESS_SIGNING_CERT_V2_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  i2d_ESS_SIGNING_CERT_V2_procname = 'i2d_ESS_SIGNING_CERT_V2';
  i2d_ESS_SIGNING_CERT_V2_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ESS_SIGNING_CERT_V2_it_procname = 'ESS_SIGNING_CERT_V2_it';
  ESS_SIGNING_CERT_V2_it_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ESS_SIGNING_CERT_V2_dup_procname = 'ESS_SIGNING_CERT_V2_dup';
  ESS_SIGNING_CERT_V2_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  OSSL_ESS_signing_cert_new_init_procname = 'OSSL_ESS_signing_cert_new_init';
  OSSL_ESS_signing_cert_new_init_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ESS_signing_cert_v2_new_init_procname = 'OSSL_ESS_signing_cert_v2_new_init';
  OSSL_ESS_signing_cert_v2_new_init_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_ESS_check_signing_certs_procname = 'OSSL_ESS_check_signing_certs';
  OSSL_ESS_check_signing_certs_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_ESS_ISSUER_SERIAL_new: PESS_ISSUER_SERIAL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_ISSUER_SERIAL_new_procname);
end;

procedure ERR_ESS_ISSUER_SERIAL_free(a: PESS_ISSUER_SERIAL); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_ISSUER_SERIAL_free_procname);
end;

function ERR_d2i_ESS_ISSUER_SERIAL(a: PPESS_ISSUER_SERIAL; _in: PPIdAnsiChar; len: TIdC_LONG): PESS_ISSUER_SERIAL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ESS_ISSUER_SERIAL_procname);
end;

function ERR_i2d_ESS_ISSUER_SERIAL(a: PESS_ISSUER_SERIAL; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ESS_ISSUER_SERIAL_procname);
end;

function ERR_ESS_ISSUER_SERIAL_dup(a: PESS_ISSUER_SERIAL): PESS_ISSUER_SERIAL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_ISSUER_SERIAL_dup_procname);
end;

function ERR_ESS_CERT_ID_new: PESS_CERT_ID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_CERT_ID_new_procname);
end;

procedure ERR_ESS_CERT_ID_free(a: PESS_CERT_ID); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_CERT_ID_free_procname);
end;

function ERR_d2i_ESS_CERT_ID(a: PPESS_CERT_ID; _in: PPIdAnsiChar; len: TIdC_LONG): PESS_CERT_ID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ESS_CERT_ID_procname);
end;

function ERR_i2d_ESS_CERT_ID(a: PESS_CERT_ID; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ESS_CERT_ID_procname);
end;

function ERR_ESS_CERT_ID_dup(a: PESS_CERT_ID): PESS_CERT_ID; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_CERT_ID_dup_procname);
end;

function ERR_ESS_SIGNING_CERT_new: PESS_SIGNING_CERT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_SIGNING_CERT_new_procname);
end;

procedure ERR_ESS_SIGNING_CERT_free(a: PESS_SIGNING_CERT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_SIGNING_CERT_free_procname);
end;

function ERR_d2i_ESS_SIGNING_CERT(a: PPESS_SIGNING_CERT; _in: PPIdAnsiChar; len: TIdC_LONG): PESS_SIGNING_CERT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ESS_SIGNING_CERT_procname);
end;

function ERR_i2d_ESS_SIGNING_CERT(a: PESS_SIGNING_CERT; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ESS_SIGNING_CERT_procname);
end;

function ERR_ESS_SIGNING_CERT_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_SIGNING_CERT_it_procname);
end;

function ERR_ESS_SIGNING_CERT_dup(a: PESS_SIGNING_CERT): PESS_SIGNING_CERT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_SIGNING_CERT_dup_procname);
end;

function ERR_ESS_CERT_ID_V2_new: PESS_CERT_ID_V2; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_CERT_ID_V2_new_procname);
end;

procedure ERR_ESS_CERT_ID_V2_free(a: PESS_CERT_ID_V2); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_CERT_ID_V2_free_procname);
end;

function ERR_d2i_ESS_CERT_ID_V2(a: PPESS_CERT_ID_V2; _in: PPIdAnsiChar; len: TIdC_LONG): PESS_CERT_ID_V2; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ESS_CERT_ID_V2_procname);
end;

function ERR_i2d_ESS_CERT_ID_V2(a: PESS_CERT_ID_V2; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ESS_CERT_ID_V2_procname);
end;

function ERR_ESS_CERT_ID_V2_dup(a: PESS_CERT_ID_V2): PESS_CERT_ID_V2; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_CERT_ID_V2_dup_procname);
end;

function ERR_ESS_SIGNING_CERT_V2_new: PESS_SIGNING_CERT_V2; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_SIGNING_CERT_V2_new_procname);
end;

procedure ERR_ESS_SIGNING_CERT_V2_free(a: PESS_SIGNING_CERT_V2); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_SIGNING_CERT_V2_free_procname);
end;

function ERR_d2i_ESS_SIGNING_CERT_V2(a: PPESS_SIGNING_CERT_V2; _in: PPIdAnsiChar; len: TIdC_LONG): PESS_SIGNING_CERT_V2; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ESS_SIGNING_CERT_V2_procname);
end;

function ERR_i2d_ESS_SIGNING_CERT_V2(a: PESS_SIGNING_CERT_V2; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ESS_SIGNING_CERT_V2_procname);
end;

function ERR_ESS_SIGNING_CERT_V2_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_SIGNING_CERT_V2_it_procname);
end;

function ERR_ESS_SIGNING_CERT_V2_dup(a: PESS_SIGNING_CERT_V2): PESS_SIGNING_CERT_V2; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ESS_SIGNING_CERT_V2_dup_procname);
end;

function ERR_OSSL_ESS_signing_cert_new_init(signcert: PX509; certs: Pstack_st_X509; set_issuer_serial: TIdC_INT): PESS_SIGNING_CERT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ESS_signing_cert_new_init_procname);
end;

function ERR_OSSL_ESS_signing_cert_v2_new_init(hash_alg: PEVP_MD; signcert: PX509; certs: Pstack_st_X509; set_issuer_serial: TIdC_INT): PESS_SIGNING_CERT_V2; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ESS_signing_cert_v2_new_init_procname);
end;

function ERR_OSSL_ESS_check_signing_certs(ss: PESS_SIGNING_CERT; ssv2: PESS_SIGNING_CERT_V2; chain: Pstack_st_X509; require_signing_cert: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ESS_check_signing_certs_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  ESS_ISSUER_SERIAL_new := LoadLibFunction(ADllHandle, ESS_ISSUER_SERIAL_new_procname);
  FuncLoadError := not assigned(ESS_ISSUER_SERIAL_new);
  if FuncLoadError then
  begin
    {$if not defined(ESS_ISSUER_SERIAL_new_allownil)}
    ESS_ISSUER_SERIAL_new := ERR_ESS_ISSUER_SERIAL_new;
    {$ifend}
    {$if declared(ESS_ISSUER_SERIAL_new_introduced)}
    if LibVersion < ESS_ISSUER_SERIAL_new_introduced then
    begin
      {$if declared(FC_ESS_ISSUER_SERIAL_new)}
      ESS_ISSUER_SERIAL_new := FC_ESS_ISSUER_SERIAL_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_ISSUER_SERIAL_new_removed)}
    if ESS_ISSUER_SERIAL_new_removed <= LibVersion then
    begin
      {$if declared(_ESS_ISSUER_SERIAL_new)}
      ESS_ISSUER_SERIAL_new := _ESS_ISSUER_SERIAL_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_ISSUER_SERIAL_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_ISSUER_SERIAL_new');
    {$ifend}
  end;
  
  ESS_ISSUER_SERIAL_free := LoadLibFunction(ADllHandle, ESS_ISSUER_SERIAL_free_procname);
  FuncLoadError := not assigned(ESS_ISSUER_SERIAL_free);
  if FuncLoadError then
  begin
    {$if not defined(ESS_ISSUER_SERIAL_free_allownil)}
    ESS_ISSUER_SERIAL_free := ERR_ESS_ISSUER_SERIAL_free;
    {$ifend}
    {$if declared(ESS_ISSUER_SERIAL_free_introduced)}
    if LibVersion < ESS_ISSUER_SERIAL_free_introduced then
    begin
      {$if declared(FC_ESS_ISSUER_SERIAL_free)}
      ESS_ISSUER_SERIAL_free := FC_ESS_ISSUER_SERIAL_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_ISSUER_SERIAL_free_removed)}
    if ESS_ISSUER_SERIAL_free_removed <= LibVersion then
    begin
      {$if declared(_ESS_ISSUER_SERIAL_free)}
      ESS_ISSUER_SERIAL_free := _ESS_ISSUER_SERIAL_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_ISSUER_SERIAL_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_ISSUER_SERIAL_free');
    {$ifend}
  end;
  
  d2i_ESS_ISSUER_SERIAL := LoadLibFunction(ADllHandle, d2i_ESS_ISSUER_SERIAL_procname);
  FuncLoadError := not assigned(d2i_ESS_ISSUER_SERIAL);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ESS_ISSUER_SERIAL_allownil)}
    d2i_ESS_ISSUER_SERIAL := ERR_d2i_ESS_ISSUER_SERIAL;
    {$ifend}
    {$if declared(d2i_ESS_ISSUER_SERIAL_introduced)}
    if LibVersion < d2i_ESS_ISSUER_SERIAL_introduced then
    begin
      {$if declared(FC_d2i_ESS_ISSUER_SERIAL)}
      d2i_ESS_ISSUER_SERIAL := FC_d2i_ESS_ISSUER_SERIAL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ESS_ISSUER_SERIAL_removed)}
    if d2i_ESS_ISSUER_SERIAL_removed <= LibVersion then
    begin
      {$if declared(_d2i_ESS_ISSUER_SERIAL)}
      d2i_ESS_ISSUER_SERIAL := _d2i_ESS_ISSUER_SERIAL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ESS_ISSUER_SERIAL_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ESS_ISSUER_SERIAL');
    {$ifend}
  end;
  
  i2d_ESS_ISSUER_SERIAL := LoadLibFunction(ADllHandle, i2d_ESS_ISSUER_SERIAL_procname);
  FuncLoadError := not assigned(i2d_ESS_ISSUER_SERIAL);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ESS_ISSUER_SERIAL_allownil)}
    i2d_ESS_ISSUER_SERIAL := ERR_i2d_ESS_ISSUER_SERIAL;
    {$ifend}
    {$if declared(i2d_ESS_ISSUER_SERIAL_introduced)}
    if LibVersion < i2d_ESS_ISSUER_SERIAL_introduced then
    begin
      {$if declared(FC_i2d_ESS_ISSUER_SERIAL)}
      i2d_ESS_ISSUER_SERIAL := FC_i2d_ESS_ISSUER_SERIAL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ESS_ISSUER_SERIAL_removed)}
    if i2d_ESS_ISSUER_SERIAL_removed <= LibVersion then
    begin
      {$if declared(_i2d_ESS_ISSUER_SERIAL)}
      i2d_ESS_ISSUER_SERIAL := _i2d_ESS_ISSUER_SERIAL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ESS_ISSUER_SERIAL_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ESS_ISSUER_SERIAL');
    {$ifend}
  end;
  
  ESS_ISSUER_SERIAL_dup := LoadLibFunction(ADllHandle, ESS_ISSUER_SERIAL_dup_procname);
  FuncLoadError := not assigned(ESS_ISSUER_SERIAL_dup);
  if FuncLoadError then
  begin
    {$if not defined(ESS_ISSUER_SERIAL_dup_allownil)}
    ESS_ISSUER_SERIAL_dup := ERR_ESS_ISSUER_SERIAL_dup;
    {$ifend}
    {$if declared(ESS_ISSUER_SERIAL_dup_introduced)}
    if LibVersion < ESS_ISSUER_SERIAL_dup_introduced then
    begin
      {$if declared(FC_ESS_ISSUER_SERIAL_dup)}
      ESS_ISSUER_SERIAL_dup := FC_ESS_ISSUER_SERIAL_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_ISSUER_SERIAL_dup_removed)}
    if ESS_ISSUER_SERIAL_dup_removed <= LibVersion then
    begin
      {$if declared(_ESS_ISSUER_SERIAL_dup)}
      ESS_ISSUER_SERIAL_dup := _ESS_ISSUER_SERIAL_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_ISSUER_SERIAL_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_ISSUER_SERIAL_dup');
    {$ifend}
  end;
  
  ESS_CERT_ID_new := LoadLibFunction(ADllHandle, ESS_CERT_ID_new_procname);
  FuncLoadError := not assigned(ESS_CERT_ID_new);
  if FuncLoadError then
  begin
    {$if not defined(ESS_CERT_ID_new_allownil)}
    ESS_CERT_ID_new := ERR_ESS_CERT_ID_new;
    {$ifend}
    {$if declared(ESS_CERT_ID_new_introduced)}
    if LibVersion < ESS_CERT_ID_new_introduced then
    begin
      {$if declared(FC_ESS_CERT_ID_new)}
      ESS_CERT_ID_new := FC_ESS_CERT_ID_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_CERT_ID_new_removed)}
    if ESS_CERT_ID_new_removed <= LibVersion then
    begin
      {$if declared(_ESS_CERT_ID_new)}
      ESS_CERT_ID_new := _ESS_CERT_ID_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_CERT_ID_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_CERT_ID_new');
    {$ifend}
  end;
  
  ESS_CERT_ID_free := LoadLibFunction(ADllHandle, ESS_CERT_ID_free_procname);
  FuncLoadError := not assigned(ESS_CERT_ID_free);
  if FuncLoadError then
  begin
    {$if not defined(ESS_CERT_ID_free_allownil)}
    ESS_CERT_ID_free := ERR_ESS_CERT_ID_free;
    {$ifend}
    {$if declared(ESS_CERT_ID_free_introduced)}
    if LibVersion < ESS_CERT_ID_free_introduced then
    begin
      {$if declared(FC_ESS_CERT_ID_free)}
      ESS_CERT_ID_free := FC_ESS_CERT_ID_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_CERT_ID_free_removed)}
    if ESS_CERT_ID_free_removed <= LibVersion then
    begin
      {$if declared(_ESS_CERT_ID_free)}
      ESS_CERT_ID_free := _ESS_CERT_ID_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_CERT_ID_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_CERT_ID_free');
    {$ifend}
  end;
  
  d2i_ESS_CERT_ID := LoadLibFunction(ADllHandle, d2i_ESS_CERT_ID_procname);
  FuncLoadError := not assigned(d2i_ESS_CERT_ID);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ESS_CERT_ID_allownil)}
    d2i_ESS_CERT_ID := ERR_d2i_ESS_CERT_ID;
    {$ifend}
    {$if declared(d2i_ESS_CERT_ID_introduced)}
    if LibVersion < d2i_ESS_CERT_ID_introduced then
    begin
      {$if declared(FC_d2i_ESS_CERT_ID)}
      d2i_ESS_CERT_ID := FC_d2i_ESS_CERT_ID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ESS_CERT_ID_removed)}
    if d2i_ESS_CERT_ID_removed <= LibVersion then
    begin
      {$if declared(_d2i_ESS_CERT_ID)}
      d2i_ESS_CERT_ID := _d2i_ESS_CERT_ID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ESS_CERT_ID_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ESS_CERT_ID');
    {$ifend}
  end;
  
  i2d_ESS_CERT_ID := LoadLibFunction(ADllHandle, i2d_ESS_CERT_ID_procname);
  FuncLoadError := not assigned(i2d_ESS_CERT_ID);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ESS_CERT_ID_allownil)}
    i2d_ESS_CERT_ID := ERR_i2d_ESS_CERT_ID;
    {$ifend}
    {$if declared(i2d_ESS_CERT_ID_introduced)}
    if LibVersion < i2d_ESS_CERT_ID_introduced then
    begin
      {$if declared(FC_i2d_ESS_CERT_ID)}
      i2d_ESS_CERT_ID := FC_i2d_ESS_CERT_ID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ESS_CERT_ID_removed)}
    if i2d_ESS_CERT_ID_removed <= LibVersion then
    begin
      {$if declared(_i2d_ESS_CERT_ID)}
      i2d_ESS_CERT_ID := _i2d_ESS_CERT_ID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ESS_CERT_ID_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ESS_CERT_ID');
    {$ifend}
  end;
  
  ESS_CERT_ID_dup := LoadLibFunction(ADllHandle, ESS_CERT_ID_dup_procname);
  FuncLoadError := not assigned(ESS_CERT_ID_dup);
  if FuncLoadError then
  begin
    {$if not defined(ESS_CERT_ID_dup_allownil)}
    ESS_CERT_ID_dup := ERR_ESS_CERT_ID_dup;
    {$ifend}
    {$if declared(ESS_CERT_ID_dup_introduced)}
    if LibVersion < ESS_CERT_ID_dup_introduced then
    begin
      {$if declared(FC_ESS_CERT_ID_dup)}
      ESS_CERT_ID_dup := FC_ESS_CERT_ID_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_CERT_ID_dup_removed)}
    if ESS_CERT_ID_dup_removed <= LibVersion then
    begin
      {$if declared(_ESS_CERT_ID_dup)}
      ESS_CERT_ID_dup := _ESS_CERT_ID_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_CERT_ID_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_CERT_ID_dup');
    {$ifend}
  end;
  
  ESS_SIGNING_CERT_new := LoadLibFunction(ADllHandle, ESS_SIGNING_CERT_new_procname);
  FuncLoadError := not assigned(ESS_SIGNING_CERT_new);
  if FuncLoadError then
  begin
    {$if not defined(ESS_SIGNING_CERT_new_allownil)}
    ESS_SIGNING_CERT_new := ERR_ESS_SIGNING_CERT_new;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_new_introduced)}
    if LibVersion < ESS_SIGNING_CERT_new_introduced then
    begin
      {$if declared(FC_ESS_SIGNING_CERT_new)}
      ESS_SIGNING_CERT_new := FC_ESS_SIGNING_CERT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_new_removed)}
    if ESS_SIGNING_CERT_new_removed <= LibVersion then
    begin
      {$if declared(_ESS_SIGNING_CERT_new)}
      ESS_SIGNING_CERT_new := _ESS_SIGNING_CERT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_SIGNING_CERT_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_SIGNING_CERT_new');
    {$ifend}
  end;
  
  ESS_SIGNING_CERT_free := LoadLibFunction(ADllHandle, ESS_SIGNING_CERT_free_procname);
  FuncLoadError := not assigned(ESS_SIGNING_CERT_free);
  if FuncLoadError then
  begin
    {$if not defined(ESS_SIGNING_CERT_free_allownil)}
    ESS_SIGNING_CERT_free := ERR_ESS_SIGNING_CERT_free;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_free_introduced)}
    if LibVersion < ESS_SIGNING_CERT_free_introduced then
    begin
      {$if declared(FC_ESS_SIGNING_CERT_free)}
      ESS_SIGNING_CERT_free := FC_ESS_SIGNING_CERT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_free_removed)}
    if ESS_SIGNING_CERT_free_removed <= LibVersion then
    begin
      {$if declared(_ESS_SIGNING_CERT_free)}
      ESS_SIGNING_CERT_free := _ESS_SIGNING_CERT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_SIGNING_CERT_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_SIGNING_CERT_free');
    {$ifend}
  end;
  
  d2i_ESS_SIGNING_CERT := LoadLibFunction(ADllHandle, d2i_ESS_SIGNING_CERT_procname);
  FuncLoadError := not assigned(d2i_ESS_SIGNING_CERT);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ESS_SIGNING_CERT_allownil)}
    d2i_ESS_SIGNING_CERT := ERR_d2i_ESS_SIGNING_CERT;
    {$ifend}
    {$if declared(d2i_ESS_SIGNING_CERT_introduced)}
    if LibVersion < d2i_ESS_SIGNING_CERT_introduced then
    begin
      {$if declared(FC_d2i_ESS_SIGNING_CERT)}
      d2i_ESS_SIGNING_CERT := FC_d2i_ESS_SIGNING_CERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ESS_SIGNING_CERT_removed)}
    if d2i_ESS_SIGNING_CERT_removed <= LibVersion then
    begin
      {$if declared(_d2i_ESS_SIGNING_CERT)}
      d2i_ESS_SIGNING_CERT := _d2i_ESS_SIGNING_CERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ESS_SIGNING_CERT_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ESS_SIGNING_CERT');
    {$ifend}
  end;
  
  i2d_ESS_SIGNING_CERT := LoadLibFunction(ADllHandle, i2d_ESS_SIGNING_CERT_procname);
  FuncLoadError := not assigned(i2d_ESS_SIGNING_CERT);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ESS_SIGNING_CERT_allownil)}
    i2d_ESS_SIGNING_CERT := ERR_i2d_ESS_SIGNING_CERT;
    {$ifend}
    {$if declared(i2d_ESS_SIGNING_CERT_introduced)}
    if LibVersion < i2d_ESS_SIGNING_CERT_introduced then
    begin
      {$if declared(FC_i2d_ESS_SIGNING_CERT)}
      i2d_ESS_SIGNING_CERT := FC_i2d_ESS_SIGNING_CERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ESS_SIGNING_CERT_removed)}
    if i2d_ESS_SIGNING_CERT_removed <= LibVersion then
    begin
      {$if declared(_i2d_ESS_SIGNING_CERT)}
      i2d_ESS_SIGNING_CERT := _i2d_ESS_SIGNING_CERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ESS_SIGNING_CERT_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ESS_SIGNING_CERT');
    {$ifend}
  end;
  
  ESS_SIGNING_CERT_it := LoadLibFunction(ADllHandle, ESS_SIGNING_CERT_it_procname);
  FuncLoadError := not assigned(ESS_SIGNING_CERT_it);
  if FuncLoadError then
  begin
    {$if not defined(ESS_SIGNING_CERT_it_allownil)}
    ESS_SIGNING_CERT_it := ERR_ESS_SIGNING_CERT_it;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_it_introduced)}
    if LibVersion < ESS_SIGNING_CERT_it_introduced then
    begin
      {$if declared(FC_ESS_SIGNING_CERT_it)}
      ESS_SIGNING_CERT_it := FC_ESS_SIGNING_CERT_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_it_removed)}
    if ESS_SIGNING_CERT_it_removed <= LibVersion then
    begin
      {$if declared(_ESS_SIGNING_CERT_it)}
      ESS_SIGNING_CERT_it := _ESS_SIGNING_CERT_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_SIGNING_CERT_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_SIGNING_CERT_it');
    {$ifend}
  end;
  
  ESS_SIGNING_CERT_dup := LoadLibFunction(ADllHandle, ESS_SIGNING_CERT_dup_procname);
  FuncLoadError := not assigned(ESS_SIGNING_CERT_dup);
  if FuncLoadError then
  begin
    {$if not defined(ESS_SIGNING_CERT_dup_allownil)}
    ESS_SIGNING_CERT_dup := ERR_ESS_SIGNING_CERT_dup;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_dup_introduced)}
    if LibVersion < ESS_SIGNING_CERT_dup_introduced then
    begin
      {$if declared(FC_ESS_SIGNING_CERT_dup)}
      ESS_SIGNING_CERT_dup := FC_ESS_SIGNING_CERT_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_dup_removed)}
    if ESS_SIGNING_CERT_dup_removed <= LibVersion then
    begin
      {$if declared(_ESS_SIGNING_CERT_dup)}
      ESS_SIGNING_CERT_dup := _ESS_SIGNING_CERT_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_SIGNING_CERT_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_SIGNING_CERT_dup');
    {$ifend}
  end;
  
  ESS_CERT_ID_V2_new := LoadLibFunction(ADllHandle, ESS_CERT_ID_V2_new_procname);
  FuncLoadError := not assigned(ESS_CERT_ID_V2_new);
  if FuncLoadError then
  begin
    {$if not defined(ESS_CERT_ID_V2_new_allownil)}
    ESS_CERT_ID_V2_new := ERR_ESS_CERT_ID_V2_new;
    {$ifend}
    {$if declared(ESS_CERT_ID_V2_new_introduced)}
    if LibVersion < ESS_CERT_ID_V2_new_introduced then
    begin
      {$if declared(FC_ESS_CERT_ID_V2_new)}
      ESS_CERT_ID_V2_new := FC_ESS_CERT_ID_V2_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_CERT_ID_V2_new_removed)}
    if ESS_CERT_ID_V2_new_removed <= LibVersion then
    begin
      {$if declared(_ESS_CERT_ID_V2_new)}
      ESS_CERT_ID_V2_new := _ESS_CERT_ID_V2_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_CERT_ID_V2_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_CERT_ID_V2_new');
    {$ifend}
  end;
  
  ESS_CERT_ID_V2_free := LoadLibFunction(ADllHandle, ESS_CERT_ID_V2_free_procname);
  FuncLoadError := not assigned(ESS_CERT_ID_V2_free);
  if FuncLoadError then
  begin
    {$if not defined(ESS_CERT_ID_V2_free_allownil)}
    ESS_CERT_ID_V2_free := ERR_ESS_CERT_ID_V2_free;
    {$ifend}
    {$if declared(ESS_CERT_ID_V2_free_introduced)}
    if LibVersion < ESS_CERT_ID_V2_free_introduced then
    begin
      {$if declared(FC_ESS_CERT_ID_V2_free)}
      ESS_CERT_ID_V2_free := FC_ESS_CERT_ID_V2_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_CERT_ID_V2_free_removed)}
    if ESS_CERT_ID_V2_free_removed <= LibVersion then
    begin
      {$if declared(_ESS_CERT_ID_V2_free)}
      ESS_CERT_ID_V2_free := _ESS_CERT_ID_V2_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_CERT_ID_V2_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_CERT_ID_V2_free');
    {$ifend}
  end;
  
  d2i_ESS_CERT_ID_V2 := LoadLibFunction(ADllHandle, d2i_ESS_CERT_ID_V2_procname);
  FuncLoadError := not assigned(d2i_ESS_CERT_ID_V2);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ESS_CERT_ID_V2_allownil)}
    d2i_ESS_CERT_ID_V2 := ERR_d2i_ESS_CERT_ID_V2;
    {$ifend}
    {$if declared(d2i_ESS_CERT_ID_V2_introduced)}
    if LibVersion < d2i_ESS_CERT_ID_V2_introduced then
    begin
      {$if declared(FC_d2i_ESS_CERT_ID_V2)}
      d2i_ESS_CERT_ID_V2 := FC_d2i_ESS_CERT_ID_V2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ESS_CERT_ID_V2_removed)}
    if d2i_ESS_CERT_ID_V2_removed <= LibVersion then
    begin
      {$if declared(_d2i_ESS_CERT_ID_V2)}
      d2i_ESS_CERT_ID_V2 := _d2i_ESS_CERT_ID_V2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ESS_CERT_ID_V2_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ESS_CERT_ID_V2');
    {$ifend}
  end;
  
  i2d_ESS_CERT_ID_V2 := LoadLibFunction(ADllHandle, i2d_ESS_CERT_ID_V2_procname);
  FuncLoadError := not assigned(i2d_ESS_CERT_ID_V2);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ESS_CERT_ID_V2_allownil)}
    i2d_ESS_CERT_ID_V2 := ERR_i2d_ESS_CERT_ID_V2;
    {$ifend}
    {$if declared(i2d_ESS_CERT_ID_V2_introduced)}
    if LibVersion < i2d_ESS_CERT_ID_V2_introduced then
    begin
      {$if declared(FC_i2d_ESS_CERT_ID_V2)}
      i2d_ESS_CERT_ID_V2 := FC_i2d_ESS_CERT_ID_V2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ESS_CERT_ID_V2_removed)}
    if i2d_ESS_CERT_ID_V2_removed <= LibVersion then
    begin
      {$if declared(_i2d_ESS_CERT_ID_V2)}
      i2d_ESS_CERT_ID_V2 := _i2d_ESS_CERT_ID_V2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ESS_CERT_ID_V2_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ESS_CERT_ID_V2');
    {$ifend}
  end;
  
  ESS_CERT_ID_V2_dup := LoadLibFunction(ADllHandle, ESS_CERT_ID_V2_dup_procname);
  FuncLoadError := not assigned(ESS_CERT_ID_V2_dup);
  if FuncLoadError then
  begin
    {$if not defined(ESS_CERT_ID_V2_dup_allownil)}
    ESS_CERT_ID_V2_dup := ERR_ESS_CERT_ID_V2_dup;
    {$ifend}
    {$if declared(ESS_CERT_ID_V2_dup_introduced)}
    if LibVersion < ESS_CERT_ID_V2_dup_introduced then
    begin
      {$if declared(FC_ESS_CERT_ID_V2_dup)}
      ESS_CERT_ID_V2_dup := FC_ESS_CERT_ID_V2_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_CERT_ID_V2_dup_removed)}
    if ESS_CERT_ID_V2_dup_removed <= LibVersion then
    begin
      {$if declared(_ESS_CERT_ID_V2_dup)}
      ESS_CERT_ID_V2_dup := _ESS_CERT_ID_V2_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_CERT_ID_V2_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_CERT_ID_V2_dup');
    {$ifend}
  end;
  
  ESS_SIGNING_CERT_V2_new := LoadLibFunction(ADllHandle, ESS_SIGNING_CERT_V2_new_procname);
  FuncLoadError := not assigned(ESS_SIGNING_CERT_V2_new);
  if FuncLoadError then
  begin
    {$if not defined(ESS_SIGNING_CERT_V2_new_allownil)}
    ESS_SIGNING_CERT_V2_new := ERR_ESS_SIGNING_CERT_V2_new;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_V2_new_introduced)}
    if LibVersion < ESS_SIGNING_CERT_V2_new_introduced then
    begin
      {$if declared(FC_ESS_SIGNING_CERT_V2_new)}
      ESS_SIGNING_CERT_V2_new := FC_ESS_SIGNING_CERT_V2_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_V2_new_removed)}
    if ESS_SIGNING_CERT_V2_new_removed <= LibVersion then
    begin
      {$if declared(_ESS_SIGNING_CERT_V2_new)}
      ESS_SIGNING_CERT_V2_new := _ESS_SIGNING_CERT_V2_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_SIGNING_CERT_V2_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_SIGNING_CERT_V2_new');
    {$ifend}
  end;
  
  ESS_SIGNING_CERT_V2_free := LoadLibFunction(ADllHandle, ESS_SIGNING_CERT_V2_free_procname);
  FuncLoadError := not assigned(ESS_SIGNING_CERT_V2_free);
  if FuncLoadError then
  begin
    {$if not defined(ESS_SIGNING_CERT_V2_free_allownil)}
    ESS_SIGNING_CERT_V2_free := ERR_ESS_SIGNING_CERT_V2_free;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_V2_free_introduced)}
    if LibVersion < ESS_SIGNING_CERT_V2_free_introduced then
    begin
      {$if declared(FC_ESS_SIGNING_CERT_V2_free)}
      ESS_SIGNING_CERT_V2_free := FC_ESS_SIGNING_CERT_V2_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_V2_free_removed)}
    if ESS_SIGNING_CERT_V2_free_removed <= LibVersion then
    begin
      {$if declared(_ESS_SIGNING_CERT_V2_free)}
      ESS_SIGNING_CERT_V2_free := _ESS_SIGNING_CERT_V2_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_SIGNING_CERT_V2_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_SIGNING_CERT_V2_free');
    {$ifend}
  end;
  
  d2i_ESS_SIGNING_CERT_V2 := LoadLibFunction(ADllHandle, d2i_ESS_SIGNING_CERT_V2_procname);
  FuncLoadError := not assigned(d2i_ESS_SIGNING_CERT_V2);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ESS_SIGNING_CERT_V2_allownil)}
    d2i_ESS_SIGNING_CERT_V2 := ERR_d2i_ESS_SIGNING_CERT_V2;
    {$ifend}
    {$if declared(d2i_ESS_SIGNING_CERT_V2_introduced)}
    if LibVersion < d2i_ESS_SIGNING_CERT_V2_introduced then
    begin
      {$if declared(FC_d2i_ESS_SIGNING_CERT_V2)}
      d2i_ESS_SIGNING_CERT_V2 := FC_d2i_ESS_SIGNING_CERT_V2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ESS_SIGNING_CERT_V2_removed)}
    if d2i_ESS_SIGNING_CERT_V2_removed <= LibVersion then
    begin
      {$if declared(_d2i_ESS_SIGNING_CERT_V2)}
      d2i_ESS_SIGNING_CERT_V2 := _d2i_ESS_SIGNING_CERT_V2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ESS_SIGNING_CERT_V2_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ESS_SIGNING_CERT_V2');
    {$ifend}
  end;
  
  i2d_ESS_SIGNING_CERT_V2 := LoadLibFunction(ADllHandle, i2d_ESS_SIGNING_CERT_V2_procname);
  FuncLoadError := not assigned(i2d_ESS_SIGNING_CERT_V2);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ESS_SIGNING_CERT_V2_allownil)}
    i2d_ESS_SIGNING_CERT_V2 := ERR_i2d_ESS_SIGNING_CERT_V2;
    {$ifend}
    {$if declared(i2d_ESS_SIGNING_CERT_V2_introduced)}
    if LibVersion < i2d_ESS_SIGNING_CERT_V2_introduced then
    begin
      {$if declared(FC_i2d_ESS_SIGNING_CERT_V2)}
      i2d_ESS_SIGNING_CERT_V2 := FC_i2d_ESS_SIGNING_CERT_V2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ESS_SIGNING_CERT_V2_removed)}
    if i2d_ESS_SIGNING_CERT_V2_removed <= LibVersion then
    begin
      {$if declared(_i2d_ESS_SIGNING_CERT_V2)}
      i2d_ESS_SIGNING_CERT_V2 := _i2d_ESS_SIGNING_CERT_V2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ESS_SIGNING_CERT_V2_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ESS_SIGNING_CERT_V2');
    {$ifend}
  end;
  
  ESS_SIGNING_CERT_V2_it := LoadLibFunction(ADllHandle, ESS_SIGNING_CERT_V2_it_procname);
  FuncLoadError := not assigned(ESS_SIGNING_CERT_V2_it);
  if FuncLoadError then
  begin
    {$if not defined(ESS_SIGNING_CERT_V2_it_allownil)}
    ESS_SIGNING_CERT_V2_it := ERR_ESS_SIGNING_CERT_V2_it;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_V2_it_introduced)}
    if LibVersion < ESS_SIGNING_CERT_V2_it_introduced then
    begin
      {$if declared(FC_ESS_SIGNING_CERT_V2_it)}
      ESS_SIGNING_CERT_V2_it := FC_ESS_SIGNING_CERT_V2_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_V2_it_removed)}
    if ESS_SIGNING_CERT_V2_it_removed <= LibVersion then
    begin
      {$if declared(_ESS_SIGNING_CERT_V2_it)}
      ESS_SIGNING_CERT_V2_it := _ESS_SIGNING_CERT_V2_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_SIGNING_CERT_V2_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_SIGNING_CERT_V2_it');
    {$ifend}
  end;
  
  ESS_SIGNING_CERT_V2_dup := LoadLibFunction(ADllHandle, ESS_SIGNING_CERT_V2_dup_procname);
  FuncLoadError := not assigned(ESS_SIGNING_CERT_V2_dup);
  if FuncLoadError then
  begin
    {$if not defined(ESS_SIGNING_CERT_V2_dup_allownil)}
    ESS_SIGNING_CERT_V2_dup := ERR_ESS_SIGNING_CERT_V2_dup;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_V2_dup_introduced)}
    if LibVersion < ESS_SIGNING_CERT_V2_dup_introduced then
    begin
      {$if declared(FC_ESS_SIGNING_CERT_V2_dup)}
      ESS_SIGNING_CERT_V2_dup := FC_ESS_SIGNING_CERT_V2_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ESS_SIGNING_CERT_V2_dup_removed)}
    if ESS_SIGNING_CERT_V2_dup_removed <= LibVersion then
    begin
      {$if declared(_ESS_SIGNING_CERT_V2_dup)}
      ESS_SIGNING_CERT_V2_dup := _ESS_SIGNING_CERT_V2_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ESS_SIGNING_CERT_V2_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('ESS_SIGNING_CERT_V2_dup');
    {$ifend}
  end;
  
  OSSL_ESS_signing_cert_new_init := LoadLibFunction(ADllHandle, OSSL_ESS_signing_cert_new_init_procname);
  FuncLoadError := not assigned(OSSL_ESS_signing_cert_new_init);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ESS_signing_cert_new_init_allownil)}
    OSSL_ESS_signing_cert_new_init := ERR_OSSL_ESS_signing_cert_new_init;
    {$ifend}
    {$if declared(OSSL_ESS_signing_cert_new_init_introduced)}
    if LibVersion < OSSL_ESS_signing_cert_new_init_introduced then
    begin
      {$if declared(FC_OSSL_ESS_signing_cert_new_init)}
      OSSL_ESS_signing_cert_new_init := FC_OSSL_ESS_signing_cert_new_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ESS_signing_cert_new_init_removed)}
    if OSSL_ESS_signing_cert_new_init_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ESS_signing_cert_new_init)}
      OSSL_ESS_signing_cert_new_init := _OSSL_ESS_signing_cert_new_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ESS_signing_cert_new_init_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ESS_signing_cert_new_init');
    {$ifend}
  end;
  
  OSSL_ESS_signing_cert_v2_new_init := LoadLibFunction(ADllHandle, OSSL_ESS_signing_cert_v2_new_init_procname);
  FuncLoadError := not assigned(OSSL_ESS_signing_cert_v2_new_init);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ESS_signing_cert_v2_new_init_allownil)}
    OSSL_ESS_signing_cert_v2_new_init := ERR_OSSL_ESS_signing_cert_v2_new_init;
    {$ifend}
    {$if declared(OSSL_ESS_signing_cert_v2_new_init_introduced)}
    if LibVersion < OSSL_ESS_signing_cert_v2_new_init_introduced then
    begin
      {$if declared(FC_OSSL_ESS_signing_cert_v2_new_init)}
      OSSL_ESS_signing_cert_v2_new_init := FC_OSSL_ESS_signing_cert_v2_new_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ESS_signing_cert_v2_new_init_removed)}
    if OSSL_ESS_signing_cert_v2_new_init_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ESS_signing_cert_v2_new_init)}
      OSSL_ESS_signing_cert_v2_new_init := _OSSL_ESS_signing_cert_v2_new_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ESS_signing_cert_v2_new_init_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ESS_signing_cert_v2_new_init');
    {$ifend}
  end;
  
  OSSL_ESS_check_signing_certs := LoadLibFunction(ADllHandle, OSSL_ESS_check_signing_certs_procname);
  FuncLoadError := not assigned(OSSL_ESS_check_signing_certs);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ESS_check_signing_certs_allownil)}
    OSSL_ESS_check_signing_certs := ERR_OSSL_ESS_check_signing_certs;
    {$ifend}
    {$if declared(OSSL_ESS_check_signing_certs_introduced)}
    if LibVersion < OSSL_ESS_check_signing_certs_introduced then
    begin
      {$if declared(FC_OSSL_ESS_check_signing_certs)}
      OSSL_ESS_check_signing_certs := FC_OSSL_ESS_check_signing_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ESS_check_signing_certs_removed)}
    if OSSL_ESS_check_signing_certs_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ESS_check_signing_certs)}
      OSSL_ESS_check_signing_certs := _OSSL_ESS_check_signing_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ESS_check_signing_certs_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ESS_check_signing_certs');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  ESS_ISSUER_SERIAL_new := nil;
  ESS_ISSUER_SERIAL_free := nil;
  d2i_ESS_ISSUER_SERIAL := nil;
  i2d_ESS_ISSUER_SERIAL := nil;
  ESS_ISSUER_SERIAL_dup := nil;
  ESS_CERT_ID_new := nil;
  ESS_CERT_ID_free := nil;
  d2i_ESS_CERT_ID := nil;
  i2d_ESS_CERT_ID := nil;
  ESS_CERT_ID_dup := nil;
  ESS_SIGNING_CERT_new := nil;
  ESS_SIGNING_CERT_free := nil;
  d2i_ESS_SIGNING_CERT := nil;
  i2d_ESS_SIGNING_CERT := nil;
  ESS_SIGNING_CERT_it := nil;
  ESS_SIGNING_CERT_dup := nil;
  ESS_CERT_ID_V2_new := nil;
  ESS_CERT_ID_V2_free := nil;
  d2i_ESS_CERT_ID_V2 := nil;
  i2d_ESS_CERT_ID_V2 := nil;
  ESS_CERT_ID_V2_dup := nil;
  ESS_SIGNING_CERT_V2_new := nil;
  ESS_SIGNING_CERT_V2_free := nil;
  d2i_ESS_SIGNING_CERT_V2 := nil;
  i2d_ESS_SIGNING_CERT_V2 := nil;
  ESS_SIGNING_CERT_V2_it := nil;
  ESS_SIGNING_CERT_V2_dup := nil;
  OSSL_ESS_signing_cert_new_init := nil;
  OSSL_ESS_signing_cert_v2_new_init := nil;
  OSSL_ESS_check_signing_certs := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.