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

unit TaurusTLSHeaders_asn1t;

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
  PASN1_TEMPLATE_st = ^TASN1_TEMPLATE_st;
  TASN1_TEMPLATE_st = record end;
  {$EXTERNALSYM PASN1_TEMPLATE_st}

  PASN1_ADB_TABLE_st = ^TASN1_ADB_TABLE_st;
  TASN1_ADB_TABLE_st = record end;
  {$EXTERNALSYM PASN1_ADB_TABLE_st}

  PASN1_ADB_TABLE = ^TASN1_ADB_TABLE;
  TASN1_ADB_TABLE = TASN1_ADB_TABLE_st;
  {$EXTERNALSYM PASN1_ADB_TABLE}

  PASN1_ADB_st = ^TASN1_ADB_st;
  TASN1_ADB_st = record end;
  {$EXTERNALSYM PASN1_ADB_st}

  PASN1_ITEM_st = ^TASN1_ITEM_st;
  TASN1_ITEM_st = record end;
  {$EXTERNALSYM PASN1_ITEM_st}

  PASN1_TLC_st = ^TASN1_TLC_st;
  TASN1_TLC_st = record end;
  {$EXTERNALSYM PASN1_TLC_st}

  PASN1_EXTERN_FUNCS_st = ^TASN1_EXTERN_FUNCS_st;
  TASN1_EXTERN_FUNCS_st = record end;
  {$EXTERNALSYM PASN1_EXTERN_FUNCS_st}

  PASN1_EXTERN_FUNCS = ^TASN1_EXTERN_FUNCS;
  TASN1_EXTERN_FUNCS = TASN1_EXTERN_FUNCS_st;
  {$EXTERNALSYM PASN1_EXTERN_FUNCS}

  PASN1_PRIMITIVE_FUNCS_st = ^TASN1_PRIMITIVE_FUNCS_st;
  TASN1_PRIMITIVE_FUNCS_st = record end;
  {$EXTERNALSYM PASN1_PRIMITIVE_FUNCS_st}

  PASN1_PRIMITIVE_FUNCS = ^TASN1_PRIMITIVE_FUNCS;
  TASN1_PRIMITIVE_FUNCS = TASN1_PRIMITIVE_FUNCS_st;
  {$EXTERNALSYM PASN1_PRIMITIVE_FUNCS}

  PASN1_AUX_st = ^TASN1_AUX_st;
  TASN1_AUX_st = record end;
  {$EXTERNALSYM PASN1_AUX_st}

  PASN1_AUX = ^TASN1_AUX;
  TASN1_AUX = TASN1_AUX_st;
  {$EXTERNALSYM PASN1_AUX}

  PASN1_PRINT_ARG_st = ^TASN1_PRINT_ARG_st;
  TASN1_PRINT_ARG_st = record end;
  {$EXTERNALSYM PASN1_PRINT_ARG_st}

  PASN1_PRINT_ARG = ^TASN1_PRINT_ARG;
  TASN1_PRINT_ARG = TASN1_PRINT_ARG_st;
  {$EXTERNALSYM PASN1_PRINT_ARG}

  PASN1_STREAM_ARG_st = ^TASN1_STREAM_ARG_st;
  TASN1_STREAM_ARG_st = record end;
  {$EXTERNALSYM PASN1_STREAM_ARG_st}

  PASN1_STREAM_ARG = ^TASN1_STREAM_ARG;
  TASN1_STREAM_ARG = TASN1_STREAM_ARG_st;
  {$EXTERNALSYM PASN1_STREAM_ARG}

  Pstack_st_ASN1_VALUE = ^Tstack_st_ASN1_VALUE;
  Tstack_st_ASN1_VALUE = record end;
  {$EXTERNALSYM Pstack_st_ASN1_VALUE}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  TASN1_ex_d2i_func_cb = function(arg1: PPASN1_VALUE; arg2: PPIdAnsiChar; arg3: TIdC_LONG; arg4: PASN1_ITEM; arg5: TIdC_INT; arg6: TIdC_INT; arg7: TIdC_CHAR; arg8: PASN1_TLC): TIdC_INT; cdecl;
  TASN1_ex_d2i_ex_func_cb = function(arg1: PPASN1_VALUE; arg2: PPIdAnsiChar; arg3: TIdC_LONG; arg4: PASN1_ITEM; arg5: TIdC_INT; arg6: TIdC_INT; arg7: TIdC_CHAR; arg8: PASN1_TLC; arg9: POSSL_LIB_CTX; arg10: PIdAnsiChar): TIdC_INT; cdecl;
  TASN1_ex_i2d_func_cb = function(arg1: PPASN1_VALUE; arg2: PPIdAnsiChar; arg3: PASN1_ITEM; arg4: TIdC_INT; arg5: TIdC_INT): TIdC_INT; cdecl;
  TASN1_ex_new_func_func_cb = function(arg1: PPASN1_VALUE; arg2: PASN1_ITEM): TIdC_INT; cdecl;
  TASN1_ex_new_ex_func_func_cb = function(arg1: PPASN1_VALUE; arg2: PASN1_ITEM; arg3: POSSL_LIB_CTX; arg4: PIdAnsiChar): TIdC_INT; cdecl;
  TASN1_ex_free_func_func_cb = procedure(arg1: PPASN1_VALUE; arg2: PASN1_ITEM); cdecl;
  TASN1_ex_print_func_func_cb = function(arg1: PBIO; arg2: PPASN1_VALUE; arg3: TIdC_INT; arg4: PIdAnsiChar; arg5: PASN1_PCTX): TIdC_INT; cdecl;
  TASN1_primitive_i2c_func_cb = function(arg1: PPASN1_VALUE; arg2: PIdAnsiChar; arg3: PIdC_INT; arg4: PASN1_ITEM): TIdC_INT; cdecl;
  TASN1_primitive_c2i_func_cb = function(arg1: PPASN1_VALUE; arg2: PIdAnsiChar; arg3: TIdC_INT; arg4: TIdC_INT; arg5: PIdAnsiChar; arg6: PASN1_ITEM): TIdC_INT; cdecl;
  TASN1_primitive_print_func_cb = function(arg1: PBIO; arg2: PPASN1_VALUE; arg3: PASN1_ITEM; arg4: TIdC_INT; arg5: PASN1_PCTX): TIdC_INT; cdecl;
  TASN1_aux_cb_func_cb = function(arg1: TIdC_INT; arg2: PPASN1_VALUE; arg3: PASN1_ITEM; arg4: Pointer): TIdC_INT; cdecl;
  Tsk_ASN1_VALUE_compfunc_func_cb = function(arg1: PPASN1_VALUE; arg2: PPASN1_VALUE): TIdC_INT; cdecl;
  Tsk_ASN1_VALUE_freefunc_func_cb = procedure(arg1: PASN1_VALUE); cdecl;
  Tsk_ASN1_VALUE_copyfunc_func_cb = function(arg1: PASN1_VALUE): PASN1_VALUE; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  ASN1_ITYPE_PRIMITIVE = $0;
  ASN1_ITYPE_SEQUENCE = $1;
  ASN1_ITYPE_CHOICE = $2;
  ASN1_ITYPE_EXTERN = $4;
  ASN1_ITYPE_MSTRING = $5;
  ASN1_ITYPE_NDEF_SEQUENCE = $6;
  ASN1_TFLG_OPTIONAL = ($1);
  ASN1_TFLG_SET_OF = ($1 shl 1);
  ASN1_TFLG_SEQUENCE_OF = ($2 shl 1);
  ASN1_TFLG_SET_ORDER = ($3 shl 1);
  ASN1_TFLG_SK_MASK = ($3 shl 1);
  ASN1_TFLG_IMPTAG = ($1 shl 3);
  ASN1_TFLG_EXPTAG = ($2 shl 3);
  ASN1_TFLG_TAG_MASK = ($3 shl 3);
  ASN1_TFLG_IMPLICIT = (ASN1_TFLG_IMPTAG or ASN1_TFLG_CONTEXT);
  ASN1_TFLG_EXPLICIT = (ASN1_TFLG_EXPTAG or ASN1_TFLG_CONTEXT);
  ASN1_TFLG_UNIVERSAL = ($0 shl 6);
  ASN1_TFLG_APPLICATION = ($1 shl 6);
  ASN1_TFLG_CONTEXT = ($2 shl 6);
  ASN1_TFLG_PRIVATE = ($3 shl 6);
  ASN1_TFLG_TAG_CLASS = ($3 shl 6);
  ASN1_TFLG_ADB_MASK = ($3 shl 8);
  ASN1_TFLG_ADB_OID = ($1 shl 8);
  ASN1_TFLG_ADB_INT = ($1 shl 9);
  ASN1_TFLG_NDEF = ($1 shl 11);
  ASN1_TFLG_EMBED = ($1 shl 12);
  ASN1_AFLG_REFCOUNT = 1;
  ASN1_AFLG_ENCODING = 2;
  ASN1_AFLG_BROKEN = 4;
  ASN1_AFLG_CONST_CB = 8;
  ASN1_OP_NEW_PRE = 0;
  ASN1_OP_NEW_POST = 1;
  ASN1_OP_FREE_PRE = 2;
  ASN1_OP_FREE_POST = 3;
  ASN1_OP_D2I_PRE = 4;
  ASN1_OP_D2I_POST = 5;
  ASN1_OP_I2D_PRE = 6;
  ASN1_OP_I2D_POST = 7;
  ASN1_OP_PRINT_PRE = 8;
  ASN1_OP_PRINT_POST = 9;
  ASN1_OP_STREAM_PRE = 10;
  ASN1_OP_STREAM_POST = 11;
  ASN1_OP_DETACHED_PRE = 12;
  ASN1_OP_DETACHED_POST = 13;
  ASN1_OP_DUP_PRE = 14;
  ASN1_OP_DUP_POST = 15;
  ASN1_OP_GET0_LIBCTX = 16;
  ASN1_OP_GET0_PROPQ = 17;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  ASN1_BOOLEAN_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_BOOLEAN_it}

  ASN1_TBOOLEAN_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_TBOOLEAN_it}

  ASN1_FBOOLEAN_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_FBOOLEAN_it}

  ASN1_SEQUENCE_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ASN1_SEQUENCE_it}

  CBIGNUM_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM CBIGNUM_it}

  BIGNUM_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM BIGNUM_it}

  INT32_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM INT32_it}

  ZINT32_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ZINT32_it}

  UINT32_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM UINT32_it}

  ZUINT32_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ZUINT32_it}

  INT64_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM INT64_it}

  ZINT64_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ZINT64_it}

  UINT64_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM UINT64_it}

  ZUINT64_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ZUINT64_it}

  LONG_it: function: PASN1_ITEM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM LONG_it}

  ZLONG_it: function: PASN1_ITEM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ZLONG_it}

  ASN1_item_ex_new: function(pval: PPASN1_VALUE; it: PASN1_ITEM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_item_ex_new}

  ASN1_item_ex_free: procedure(pval: PPASN1_VALUE; it: PASN1_ITEM); cdecl = nil;
  {$EXTERNALSYM ASN1_item_ex_free}

  ASN1_item_ex_d2i: function(pval: PPASN1_VALUE; _in: PPIdAnsiChar; len: TIdC_LONG; it: PASN1_ITEM; tag: TIdC_INT; aclass: TIdC_INT; opt: TIdC_CHAR; ctx: PASN1_TLC): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_item_ex_d2i}

  ASN1_item_ex_i2d: function(pval: PPASN1_VALUE; _out: PPIdAnsiChar; it: PASN1_ITEM; tag: TIdC_INT; aclass: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_item_ex_i2d}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function ASN1_BOOLEAN_it: PASN1_ITEM; cdecl;
function ASN1_TBOOLEAN_it: PASN1_ITEM; cdecl;
function ASN1_FBOOLEAN_it: PASN1_ITEM; cdecl;
function ASN1_SEQUENCE_it: PASN1_ITEM; cdecl;
function CBIGNUM_it: PASN1_ITEM; cdecl;
function BIGNUM_it: PASN1_ITEM; cdecl;
function INT32_it: PASN1_ITEM; cdecl;
function ZINT32_it: PASN1_ITEM; cdecl;
function UINT32_it: PASN1_ITEM; cdecl;
function ZUINT32_it: PASN1_ITEM; cdecl;
function INT64_it: PASN1_ITEM; cdecl;
function ZINT64_it: PASN1_ITEM; cdecl;
function UINT64_it: PASN1_ITEM; cdecl;
function ZUINT64_it: PASN1_ITEM; cdecl;
function LONG_it: PASN1_ITEM; cdecl; deprecated 'In OpenSSL 3_0_0';
function ZLONG_it: PASN1_ITEM; cdecl; deprecated 'In OpenSSL 3_0_0';
function ASN1_item_ex_new(pval: PPASN1_VALUE; it: PASN1_ITEM): TIdC_INT; cdecl;
procedure ASN1_item_ex_free(pval: PPASN1_VALUE; it: PASN1_ITEM); cdecl;
function ASN1_item_ex_d2i(pval: PPASN1_VALUE; _in: PPIdAnsiChar; len: TIdC_LONG; it: PASN1_ITEM; tag: TIdC_INT; aclass: TIdC_INT; opt: TIdC_CHAR; ctx: PASN1_TLC): TIdC_INT; cdecl;
function ASN1_item_ex_i2d(pval: PPASN1_VALUE; _out: PPIdAnsiChar; it: PASN1_ITEM; tag: TIdC_INT; aclass: TIdC_INT): TIdC_INT; cdecl;
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

function ASN1_BOOLEAN_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_BOOLEAN_it';
function ASN1_TBOOLEAN_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_TBOOLEAN_it';
function ASN1_FBOOLEAN_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_FBOOLEAN_it';
function ASN1_SEQUENCE_it: PASN1_ITEM; cdecl external CLibCrypto name 'ASN1_SEQUENCE_it';
function CBIGNUM_it: PASN1_ITEM; cdecl external CLibCrypto name 'CBIGNUM_it';
function BIGNUM_it: PASN1_ITEM; cdecl external CLibCrypto name 'BIGNUM_it';
function INT32_it: PASN1_ITEM; cdecl external CLibCrypto name 'INT32_it';
function ZINT32_it: PASN1_ITEM; cdecl external CLibCrypto name 'ZINT32_it';
function UINT32_it: PASN1_ITEM; cdecl external CLibCrypto name 'UINT32_it';
function ZUINT32_it: PASN1_ITEM; cdecl external CLibCrypto name 'ZUINT32_it';
function INT64_it: PASN1_ITEM; cdecl external CLibCrypto name 'INT64_it';
function ZINT64_it: PASN1_ITEM; cdecl external CLibCrypto name 'ZINT64_it';
function UINT64_it: PASN1_ITEM; cdecl external CLibCrypto name 'UINT64_it';
function ZUINT64_it: PASN1_ITEM; cdecl external CLibCrypto name 'ZUINT64_it';
function LONG_it: PASN1_ITEM; cdecl external CLibCrypto name 'LONG_it';
function ZLONG_it: PASN1_ITEM; cdecl external CLibCrypto name 'ZLONG_it';
function ASN1_item_ex_new(pval: PPASN1_VALUE; it: PASN1_ITEM): TIdC_INT; cdecl external CLibCrypto name 'ASN1_item_ex_new';
procedure ASN1_item_ex_free(pval: PPASN1_VALUE; it: PASN1_ITEM); cdecl external CLibCrypto name 'ASN1_item_ex_free';
function ASN1_item_ex_d2i(pval: PPASN1_VALUE; _in: PPIdAnsiChar; len: TIdC_LONG; it: PASN1_ITEM; tag: TIdC_INT; aclass: TIdC_INT; opt: TIdC_CHAR; ctx: PASN1_TLC): TIdC_INT; cdecl external CLibCrypto name 'ASN1_item_ex_d2i';
function ASN1_item_ex_i2d(pval: PPASN1_VALUE; _out: PPIdAnsiChar; it: PASN1_ITEM; tag: TIdC_INT; aclass: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'ASN1_item_ex_i2d';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  ASN1_BOOLEAN_it_procname = 'ASN1_BOOLEAN_it';
  ASN1_BOOLEAN_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_TBOOLEAN_it_procname = 'ASN1_TBOOLEAN_it';
  ASN1_TBOOLEAN_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_FBOOLEAN_it_procname = 'ASN1_FBOOLEAN_it';
  ASN1_FBOOLEAN_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_SEQUENCE_it_procname = 'ASN1_SEQUENCE_it';
  ASN1_SEQUENCE_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CBIGNUM_it_procname = 'CBIGNUM_it';
  CBIGNUM_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIGNUM_it_procname = 'BIGNUM_it';
  BIGNUM_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  INT32_it_procname = 'INT32_it';
  INT32_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0f);

  ZINT32_it_procname = 'ZINT32_it';
  ZINT32_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0f);

  UINT32_it_procname = 'UINT32_it';
  UINT32_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0f);

  ZUINT32_it_procname = 'ZUINT32_it';
  ZUINT32_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0f);

  INT64_it_procname = 'INT64_it';
  INT64_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0f);

  ZINT64_it_procname = 'ZINT64_it';
  ZINT64_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0f);

  UINT64_it_procname = 'UINT64_it';
  UINT64_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0f);

  ZUINT64_it_procname = 'ZUINT64_it';
  ZUINT64_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0f);

  LONG_it_procname = 'LONG_it';
  LONG_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  LONG_it_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ZLONG_it_procname = 'ZLONG_it';
  ZLONG_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ZLONG_it_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ASN1_item_ex_new_procname = 'ASN1_item_ex_new';
  ASN1_item_ex_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_item_ex_free_procname = 'ASN1_item_ex_free';
  ASN1_item_ex_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_item_ex_d2i_procname = 'ASN1_item_ex_d2i';
  ASN1_item_ex_d2i_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_item_ex_i2d_procname = 'ASN1_item_ex_i2d';
  ASN1_item_ex_i2d_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_ASN1_BOOLEAN_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_BOOLEAN_it_procname);
end;

function ERR_ASN1_TBOOLEAN_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_TBOOLEAN_it_procname);
end;

function ERR_ASN1_FBOOLEAN_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_FBOOLEAN_it_procname);
end;

function ERR_ASN1_SEQUENCE_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_SEQUENCE_it_procname);
end;

function ERR_CBIGNUM_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CBIGNUM_it_procname);
end;

function ERR_BIGNUM_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIGNUM_it_procname);
end;

function ERR_INT32_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(INT32_it_procname);
end;

function ERR_ZINT32_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ZINT32_it_procname);
end;

function ERR_UINT32_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UINT32_it_procname);
end;

function ERR_ZUINT32_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ZUINT32_it_procname);
end;

function ERR_INT64_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(INT64_it_procname);
end;

function ERR_ZINT64_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ZINT64_it_procname);
end;

function ERR_UINT64_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(UINT64_it_procname);
end;

function ERR_ZUINT64_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ZUINT64_it_procname);
end;

function ERR_LONG_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(LONG_it_procname);
end;

function ERR_ZLONG_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ZLONG_it_procname);
end;

function ERR_ASN1_item_ex_new(pval: PPASN1_VALUE; it: PASN1_ITEM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_ex_new_procname);
end;

procedure ERR_ASN1_item_ex_free(pval: PPASN1_VALUE; it: PASN1_ITEM); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_ex_free_procname);
end;

function ERR_ASN1_item_ex_d2i(pval: PPASN1_VALUE; _in: PPIdAnsiChar; len: TIdC_LONG; it: PASN1_ITEM; tag: TIdC_INT; aclass: TIdC_INT; opt: TIdC_CHAR; ctx: PASN1_TLC): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_ex_d2i_procname);
end;

function ERR_ASN1_item_ex_i2d(pval: PPASN1_VALUE; _out: PPIdAnsiChar; it: PASN1_ITEM; tag: TIdC_INT; aclass: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_ex_i2d_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  ASN1_BOOLEAN_it := LoadLibFunction(ADllHandle, ASN1_BOOLEAN_it_procname);
  FuncLoadError := not assigned(ASN1_BOOLEAN_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_BOOLEAN_it_allownil)}
    ASN1_BOOLEAN_it := ERR_ASN1_BOOLEAN_it;
    {$ifend}
    {$if declared(ASN1_BOOLEAN_it_introduced)}
    if LibVersion < ASN1_BOOLEAN_it_introduced then
    begin
      {$if declared(FC_ASN1_BOOLEAN_it)}
      ASN1_BOOLEAN_it := FC_ASN1_BOOLEAN_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_BOOLEAN_it_removed)}
    if ASN1_BOOLEAN_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_BOOLEAN_it)}
      ASN1_BOOLEAN_it := _ASN1_BOOLEAN_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_BOOLEAN_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_BOOLEAN_it');
    {$ifend}
  end;
  
  ASN1_TBOOLEAN_it := LoadLibFunction(ADllHandle, ASN1_TBOOLEAN_it_procname);
  FuncLoadError := not assigned(ASN1_TBOOLEAN_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_TBOOLEAN_it_allownil)}
    ASN1_TBOOLEAN_it := ERR_ASN1_TBOOLEAN_it;
    {$ifend}
    {$if declared(ASN1_TBOOLEAN_it_introduced)}
    if LibVersion < ASN1_TBOOLEAN_it_introduced then
    begin
      {$if declared(FC_ASN1_TBOOLEAN_it)}
      ASN1_TBOOLEAN_it := FC_ASN1_TBOOLEAN_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_TBOOLEAN_it_removed)}
    if ASN1_TBOOLEAN_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_TBOOLEAN_it)}
      ASN1_TBOOLEAN_it := _ASN1_TBOOLEAN_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_TBOOLEAN_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_TBOOLEAN_it');
    {$ifend}
  end;
  
  ASN1_FBOOLEAN_it := LoadLibFunction(ADllHandle, ASN1_FBOOLEAN_it_procname);
  FuncLoadError := not assigned(ASN1_FBOOLEAN_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_FBOOLEAN_it_allownil)}
    ASN1_FBOOLEAN_it := ERR_ASN1_FBOOLEAN_it;
    {$ifend}
    {$if declared(ASN1_FBOOLEAN_it_introduced)}
    if LibVersion < ASN1_FBOOLEAN_it_introduced then
    begin
      {$if declared(FC_ASN1_FBOOLEAN_it)}
      ASN1_FBOOLEAN_it := FC_ASN1_FBOOLEAN_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_FBOOLEAN_it_removed)}
    if ASN1_FBOOLEAN_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_FBOOLEAN_it)}
      ASN1_FBOOLEAN_it := _ASN1_FBOOLEAN_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_FBOOLEAN_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_FBOOLEAN_it');
    {$ifend}
  end;
  
  ASN1_SEQUENCE_it := LoadLibFunction(ADllHandle, ASN1_SEQUENCE_it_procname);
  FuncLoadError := not assigned(ASN1_SEQUENCE_it);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_SEQUENCE_it_allownil)}
    ASN1_SEQUENCE_it := ERR_ASN1_SEQUENCE_it;
    {$ifend}
    {$if declared(ASN1_SEQUENCE_it_introduced)}
    if LibVersion < ASN1_SEQUENCE_it_introduced then
    begin
      {$if declared(FC_ASN1_SEQUENCE_it)}
      ASN1_SEQUENCE_it := FC_ASN1_SEQUENCE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_SEQUENCE_it_removed)}
    if ASN1_SEQUENCE_it_removed <= LibVersion then
    begin
      {$if declared(_ASN1_SEQUENCE_it)}
      ASN1_SEQUENCE_it := _ASN1_SEQUENCE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_SEQUENCE_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_SEQUENCE_it');
    {$ifend}
  end;
  
  CBIGNUM_it := LoadLibFunction(ADllHandle, CBIGNUM_it_procname);
  FuncLoadError := not assigned(CBIGNUM_it);
  if FuncLoadError then
  begin
    {$if not defined(CBIGNUM_it_allownil)}
    CBIGNUM_it := ERR_CBIGNUM_it;
    {$ifend}
    {$if declared(CBIGNUM_it_introduced)}
    if LibVersion < CBIGNUM_it_introduced then
    begin
      {$if declared(FC_CBIGNUM_it)}
      CBIGNUM_it := FC_CBIGNUM_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CBIGNUM_it_removed)}
    if CBIGNUM_it_removed <= LibVersion then
    begin
      {$if declared(_CBIGNUM_it)}
      CBIGNUM_it := _CBIGNUM_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CBIGNUM_it_allownil)}
    if FuncLoadError then
      AFailed.Add('CBIGNUM_it');
    {$ifend}
  end;
  
  BIGNUM_it := LoadLibFunction(ADllHandle, BIGNUM_it_procname);
  FuncLoadError := not assigned(BIGNUM_it);
  if FuncLoadError then
  begin
    {$if not defined(BIGNUM_it_allownil)}
    BIGNUM_it := ERR_BIGNUM_it;
    {$ifend}
    {$if declared(BIGNUM_it_introduced)}
    if LibVersion < BIGNUM_it_introduced then
    begin
      {$if declared(FC_BIGNUM_it)}
      BIGNUM_it := FC_BIGNUM_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIGNUM_it_removed)}
    if BIGNUM_it_removed <= LibVersion then
    begin
      {$if declared(_BIGNUM_it)}
      BIGNUM_it := _BIGNUM_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIGNUM_it_allownil)}
    if FuncLoadError then
      AFailed.Add('BIGNUM_it');
    {$ifend}
  end;
  
  INT32_it := LoadLibFunction(ADllHandle, INT32_it_procname);
  FuncLoadError := not assigned(INT32_it);
  if FuncLoadError then
  begin
    {$if not defined(INT32_it_allownil)}
    INT32_it := ERR_INT32_it;
    {$ifend}
    {$if declared(INT32_it_introduced)}
    if LibVersion < INT32_it_introduced then
    begin
      {$if declared(FC_INT32_it)}
      INT32_it := FC_INT32_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(INT32_it_removed)}
    if INT32_it_removed <= LibVersion then
    begin
      {$if declared(_INT32_it)}
      INT32_it := _INT32_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(INT32_it_allownil)}
    if FuncLoadError then
      AFailed.Add('INT32_it');
    {$ifend}
  end;
  
  ZINT32_it := LoadLibFunction(ADllHandle, ZINT32_it_procname);
  FuncLoadError := not assigned(ZINT32_it);
  if FuncLoadError then
  begin
    {$if not defined(ZINT32_it_allownil)}
    ZINT32_it := ERR_ZINT32_it;
    {$ifend}
    {$if declared(ZINT32_it_introduced)}
    if LibVersion < ZINT32_it_introduced then
    begin
      {$if declared(FC_ZINT32_it)}
      ZINT32_it := FC_ZINT32_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ZINT32_it_removed)}
    if ZINT32_it_removed <= LibVersion then
    begin
      {$if declared(_ZINT32_it)}
      ZINT32_it := _ZINT32_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ZINT32_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ZINT32_it');
    {$ifend}
  end;
  
  UINT32_it := LoadLibFunction(ADllHandle, UINT32_it_procname);
  FuncLoadError := not assigned(UINT32_it);
  if FuncLoadError then
  begin
    {$if not defined(UINT32_it_allownil)}
    UINT32_it := ERR_UINT32_it;
    {$ifend}
    {$if declared(UINT32_it_introduced)}
    if LibVersion < UINT32_it_introduced then
    begin
      {$if declared(FC_UINT32_it)}
      UINT32_it := FC_UINT32_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UINT32_it_removed)}
    if UINT32_it_removed <= LibVersion then
    begin
      {$if declared(_UINT32_it)}
      UINT32_it := _UINT32_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UINT32_it_allownil)}
    if FuncLoadError then
      AFailed.Add('UINT32_it');
    {$ifend}
  end;
  
  ZUINT32_it := LoadLibFunction(ADllHandle, ZUINT32_it_procname);
  FuncLoadError := not assigned(ZUINT32_it);
  if FuncLoadError then
  begin
    {$if not defined(ZUINT32_it_allownil)}
    ZUINT32_it := ERR_ZUINT32_it;
    {$ifend}
    {$if declared(ZUINT32_it_introduced)}
    if LibVersion < ZUINT32_it_introduced then
    begin
      {$if declared(FC_ZUINT32_it)}
      ZUINT32_it := FC_ZUINT32_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ZUINT32_it_removed)}
    if ZUINT32_it_removed <= LibVersion then
    begin
      {$if declared(_ZUINT32_it)}
      ZUINT32_it := _ZUINT32_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ZUINT32_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ZUINT32_it');
    {$ifend}
  end;
  
  INT64_it := LoadLibFunction(ADllHandle, INT64_it_procname);
  FuncLoadError := not assigned(INT64_it);
  if FuncLoadError then
  begin
    {$if not defined(INT64_it_allownil)}
    INT64_it := ERR_INT64_it;
    {$ifend}
    {$if declared(INT64_it_introduced)}
    if LibVersion < INT64_it_introduced then
    begin
      {$if declared(FC_INT64_it)}
      INT64_it := FC_INT64_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(INT64_it_removed)}
    if INT64_it_removed <= LibVersion then
    begin
      {$if declared(_INT64_it)}
      INT64_it := _INT64_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(INT64_it_allownil)}
    if FuncLoadError then
      AFailed.Add('INT64_it');
    {$ifend}
  end;
  
  ZINT64_it := LoadLibFunction(ADllHandle, ZINT64_it_procname);
  FuncLoadError := not assigned(ZINT64_it);
  if FuncLoadError then
  begin
    {$if not defined(ZINT64_it_allownil)}
    ZINT64_it := ERR_ZINT64_it;
    {$ifend}
    {$if declared(ZINT64_it_introduced)}
    if LibVersion < ZINT64_it_introduced then
    begin
      {$if declared(FC_ZINT64_it)}
      ZINT64_it := FC_ZINT64_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ZINT64_it_removed)}
    if ZINT64_it_removed <= LibVersion then
    begin
      {$if declared(_ZINT64_it)}
      ZINT64_it := _ZINT64_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ZINT64_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ZINT64_it');
    {$ifend}
  end;
  
  UINT64_it := LoadLibFunction(ADllHandle, UINT64_it_procname);
  FuncLoadError := not assigned(UINT64_it);
  if FuncLoadError then
  begin
    {$if not defined(UINT64_it_allownil)}
    UINT64_it := ERR_UINT64_it;
    {$ifend}
    {$if declared(UINT64_it_introduced)}
    if LibVersion < UINT64_it_introduced then
    begin
      {$if declared(FC_UINT64_it)}
      UINT64_it := FC_UINT64_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(UINT64_it_removed)}
    if UINT64_it_removed <= LibVersion then
    begin
      {$if declared(_UINT64_it)}
      UINT64_it := _UINT64_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(UINT64_it_allownil)}
    if FuncLoadError then
      AFailed.Add('UINT64_it');
    {$ifend}
  end;
  
  ZUINT64_it := LoadLibFunction(ADllHandle, ZUINT64_it_procname);
  FuncLoadError := not assigned(ZUINT64_it);
  if FuncLoadError then
  begin
    {$if not defined(ZUINT64_it_allownil)}
    ZUINT64_it := ERR_ZUINT64_it;
    {$ifend}
    {$if declared(ZUINT64_it_introduced)}
    if LibVersion < ZUINT64_it_introduced then
    begin
      {$if declared(FC_ZUINT64_it)}
      ZUINT64_it := FC_ZUINT64_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ZUINT64_it_removed)}
    if ZUINT64_it_removed <= LibVersion then
    begin
      {$if declared(_ZUINT64_it)}
      ZUINT64_it := _ZUINT64_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ZUINT64_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ZUINT64_it');
    {$ifend}
  end;
  
  LONG_it := LoadLibFunction(ADllHandle, LONG_it_procname);
  FuncLoadError := not assigned(LONG_it);
  if FuncLoadError then
  begin
    {$if not defined(LONG_it_allownil)}
    LONG_it := ERR_LONG_it;
    {$ifend}
    {$if declared(LONG_it_introduced)}
    if LibVersion < LONG_it_introduced then
    begin
      {$if declared(FC_LONG_it)}
      LONG_it := FC_LONG_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(LONG_it_removed)}
    if LONG_it_removed <= LibVersion then
    begin
      {$if declared(_LONG_it)}
      LONG_it := _LONG_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(LONG_it_allownil)}
    if FuncLoadError then
      AFailed.Add('LONG_it');
    {$ifend}
  end;
  
  ZLONG_it := LoadLibFunction(ADllHandle, ZLONG_it_procname);
  FuncLoadError := not assigned(ZLONG_it);
  if FuncLoadError then
  begin
    {$if not defined(ZLONG_it_allownil)}
    ZLONG_it := ERR_ZLONG_it;
    {$ifend}
    {$if declared(ZLONG_it_introduced)}
    if LibVersion < ZLONG_it_introduced then
    begin
      {$if declared(FC_ZLONG_it)}
      ZLONG_it := FC_ZLONG_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ZLONG_it_removed)}
    if ZLONG_it_removed <= LibVersion then
    begin
      {$if declared(_ZLONG_it)}
      ZLONG_it := _ZLONG_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ZLONG_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ZLONG_it');
    {$ifend}
  end;
  
  ASN1_item_ex_new := LoadLibFunction(ADllHandle, ASN1_item_ex_new_procname);
  FuncLoadError := not assigned(ASN1_item_ex_new);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_ex_new_allownil)}
    ASN1_item_ex_new := ERR_ASN1_item_ex_new;
    {$ifend}
    {$if declared(ASN1_item_ex_new_introduced)}
    if LibVersion < ASN1_item_ex_new_introduced then
    begin
      {$if declared(FC_ASN1_item_ex_new)}
      ASN1_item_ex_new := FC_ASN1_item_ex_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_ex_new_removed)}
    if ASN1_item_ex_new_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_ex_new)}
      ASN1_item_ex_new := _ASN1_item_ex_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_ex_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_ex_new');
    {$ifend}
  end;
  
  ASN1_item_ex_free := LoadLibFunction(ADllHandle, ASN1_item_ex_free_procname);
  FuncLoadError := not assigned(ASN1_item_ex_free);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_ex_free_allownil)}
    ASN1_item_ex_free := ERR_ASN1_item_ex_free;
    {$ifend}
    {$if declared(ASN1_item_ex_free_introduced)}
    if LibVersion < ASN1_item_ex_free_introduced then
    begin
      {$if declared(FC_ASN1_item_ex_free)}
      ASN1_item_ex_free := FC_ASN1_item_ex_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_ex_free_removed)}
    if ASN1_item_ex_free_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_ex_free)}
      ASN1_item_ex_free := _ASN1_item_ex_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_ex_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_ex_free');
    {$ifend}
  end;
  
  ASN1_item_ex_d2i := LoadLibFunction(ADllHandle, ASN1_item_ex_d2i_procname);
  FuncLoadError := not assigned(ASN1_item_ex_d2i);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_ex_d2i_allownil)}
    ASN1_item_ex_d2i := ERR_ASN1_item_ex_d2i;
    {$ifend}
    {$if declared(ASN1_item_ex_d2i_introduced)}
    if LibVersion < ASN1_item_ex_d2i_introduced then
    begin
      {$if declared(FC_ASN1_item_ex_d2i)}
      ASN1_item_ex_d2i := FC_ASN1_item_ex_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_ex_d2i_removed)}
    if ASN1_item_ex_d2i_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_ex_d2i)}
      ASN1_item_ex_d2i := _ASN1_item_ex_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_ex_d2i_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_ex_d2i');
    {$ifend}
  end;
  
  ASN1_item_ex_i2d := LoadLibFunction(ADllHandle, ASN1_item_ex_i2d_procname);
  FuncLoadError := not assigned(ASN1_item_ex_i2d);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_ex_i2d_allownil)}
    ASN1_item_ex_i2d := ERR_ASN1_item_ex_i2d;
    {$ifend}
    {$if declared(ASN1_item_ex_i2d_introduced)}
    if LibVersion < ASN1_item_ex_i2d_introduced then
    begin
      {$if declared(FC_ASN1_item_ex_i2d)}
      ASN1_item_ex_i2d := FC_ASN1_item_ex_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_ex_i2d_removed)}
    if ASN1_item_ex_i2d_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_ex_i2d)}
      ASN1_item_ex_i2d := _ASN1_item_ex_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_ex_i2d_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_ex_i2d');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  ASN1_BOOLEAN_it := nil;
  ASN1_TBOOLEAN_it := nil;
  ASN1_FBOOLEAN_it := nil;
  ASN1_SEQUENCE_it := nil;
  CBIGNUM_it := nil;
  BIGNUM_it := nil;
  INT32_it := nil;
  ZINT32_it := nil;
  UINT32_it := nil;
  ZUINT32_it := nil;
  INT64_it := nil;
  ZINT64_it := nil;
  UINT64_it := nil;
  ZUINT64_it := nil;
  LONG_it := nil;
  ZLONG_it := nil;
  ASN1_item_ex_new := nil;
  ASN1_item_ex_free := nil;
  ASN1_item_ex_d2i := nil;
  ASN1_item_ex_i2d := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.