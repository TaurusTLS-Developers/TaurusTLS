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

unit TaurusTLSHeaders_objects;

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
  Pobj_name_st = ^Tobj_name_st;
  Tobj_name_st = record end;
  {$EXTERNALSYM Pobj_name_st}

  POBJ_NAME = ^TOBJ_NAME;
  TOBJ_NAME = Tobj_name_st;
  {$EXTERNALSYM POBJ_NAME}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  TOBJ_NAME_new_index_hash_func_cb = function(arg1: PIdAnsiChar): TIdC_ULONG; cdecl;
  TOBJ_NAME_new_index_cmp_func_cb = function(arg1: PIdAnsiChar; arg2: PIdAnsiChar): TIdC_INT; cdecl;
  TOBJ_NAME_new_index_free_func_cb = procedure(arg1: PIdAnsiChar; arg2: TIdC_INT; arg3: PIdAnsiChar); cdecl;
  TOBJ_NAME_do_all_fn_cb = procedure(arg1: POBJ_NAME; arg2: Pointer); cdecl;
  TOBJ_bsearch__cmp_cb = function(arg1: Pointer; arg2: Pointer): TIdC_INT; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  OBJ_NAME_TYPE_UNDEF = $00;
  OBJ_NAME_TYPE_MD_METH = $01;
  OBJ_NAME_TYPE_CIPHER_METH = $02;
  OBJ_NAME_TYPE_PKEY_METH = $03;
  OBJ_NAME_TYPE_COMP_METH = $04;
  OBJ_NAME_TYPE_MAC_METH = $05;
  OBJ_NAME_TYPE_KDF_METH = $06;
  OBJ_NAME_TYPE_NUM = $07;
  OBJ_NAME_ALIAS = $8000;
  OBJ_BSEARCH_VALUE_ON_NOMATCH = $01;
  OBJ_BSEARCH_FIRST_VALUE_ON_MATCH = $02;
  SN_ac_auditEntity = SN_ac_auditIdentity;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  OBJ_NAME_init: function: TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OBJ_NAME_init}

  OBJ_NAME_new_index: function(hash_func: TOBJ_NAME_new_index_hash_func_cb; cmp_func: TOBJ_NAME_new_index_cmp_func_cb; free_func: TOBJ_NAME_new_index_free_func_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OBJ_NAME_new_index}

  OBJ_NAME_get: function(name: PIdAnsiChar; _type: TIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OBJ_NAME_get}

  OBJ_NAME_add: function(name: PIdAnsiChar; _type: TIdC_INT; data: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OBJ_NAME_add}

  OBJ_NAME_remove: function(name: PIdAnsiChar; _type: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OBJ_NAME_remove}

  OBJ_NAME_cleanup: procedure(_type: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM OBJ_NAME_cleanup}

  OBJ_NAME_do_all: procedure(_type: TIdC_INT; fn: TOBJ_NAME_do_all_fn_cb; arg: Pointer); cdecl = nil;
  {$EXTERNALSYM OBJ_NAME_do_all}

  OBJ_NAME_do_all_sorted: procedure(_type: TIdC_INT; fn: TOBJ_NAME_do_all_fn_cb; arg: Pointer); cdecl = nil;
  {$EXTERNALSYM OBJ_NAME_do_all_sorted}

  OBJ_dup: function(a: PASN1_OBJECT): PASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM OBJ_dup}

  OBJ_nid2obj: function(n: TIdC_INT): PASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM OBJ_nid2obj}

  OBJ_nid2ln: function(n: TIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OBJ_nid2ln}

  OBJ_nid2sn: function(n: TIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OBJ_nid2sn}

  OBJ_obj2nid: function(o: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OBJ_obj2nid}

  OBJ_txt2obj: function(s: PIdAnsiChar; no_name: TIdC_INT): PASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM OBJ_txt2obj}

  OBJ_obj2txt: function(buf: PIdAnsiChar; buf_len: TIdC_INT; a: PASN1_OBJECT; no_name: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OBJ_obj2txt}

  OBJ_txt2nid: function(s: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OBJ_txt2nid}

  OBJ_ln2nid: function(s: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OBJ_ln2nid}

  OBJ_sn2nid: function(s: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OBJ_sn2nid}

  OBJ_cmp: function(a: PASN1_OBJECT; b: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OBJ_cmp}

  OBJ_bsearch_: function(key: Pointer; base: Pointer; num: TIdC_INT; size: TIdC_INT; cmp: TOBJ_bsearch__cmp_cb): Pointer; cdecl = nil;
  {$EXTERNALSYM OBJ_bsearch_}

  OBJ_bsearch_ex_: function(key: Pointer; base: Pointer; num: TIdC_INT; size: TIdC_INT; cmp: TOBJ_bsearch__cmp_cb; flags: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM OBJ_bsearch_ex_}

  OBJ_new_nid: function(num: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OBJ_new_nid}

  OBJ_add_object: function(obj: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OBJ_add_object}

  OBJ_create: function(oid: PIdAnsiChar; sn: PIdAnsiChar; ln: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OBJ_create}

  OBJ_create_objects: function(_in: PBIO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OBJ_create_objects}

  OBJ_length: function(obj: PASN1_OBJECT): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM OBJ_length}

  OBJ_get0_data: function(obj: PASN1_OBJECT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OBJ_get0_data}

  OBJ_find_sigid_algs: function(signid: TIdC_INT; pdig_nid: PIdC_INT; ppkey_nid: PIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OBJ_find_sigid_algs}

  OBJ_find_sigid_by_algs: function(psignid: PIdC_INT; dig_nid: TIdC_INT; pkey_nid: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OBJ_find_sigid_by_algs}

  OBJ_add_sigid: function(signid: TIdC_INT; dig_id: TIdC_INT; pkey_id: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OBJ_add_sigid}

  OBJ_sigid_free: procedure; cdecl = nil;
  {$EXTERNALSYM OBJ_sigid_free}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function OBJ_NAME_init: TIdC_INT; cdecl;
function OBJ_NAME_new_index(hash_func: TOBJ_NAME_new_index_hash_func_cb; cmp_func: TOBJ_NAME_new_index_cmp_func_cb; free_func: TOBJ_NAME_new_index_free_func_cb): TIdC_INT; cdecl;
function OBJ_NAME_get(name: PIdAnsiChar; _type: TIdC_INT): PIdAnsiChar; cdecl;
function OBJ_NAME_add(name: PIdAnsiChar; _type: TIdC_INT; data: PIdAnsiChar): TIdC_INT; cdecl;
function OBJ_NAME_remove(name: PIdAnsiChar; _type: TIdC_INT): TIdC_INT; cdecl;
procedure OBJ_NAME_cleanup(_type: TIdC_INT); cdecl;
procedure OBJ_NAME_do_all(_type: TIdC_INT; fn: TOBJ_NAME_do_all_fn_cb; arg: Pointer); cdecl;
procedure OBJ_NAME_do_all_sorted(_type: TIdC_INT; fn: TOBJ_NAME_do_all_fn_cb; arg: Pointer); cdecl;
function OBJ_dup(a: PASN1_OBJECT): PASN1_OBJECT; cdecl;
function OBJ_nid2obj(n: TIdC_INT): PASN1_OBJECT; cdecl;
function OBJ_nid2ln(n: TIdC_INT): PIdAnsiChar; cdecl;
function OBJ_nid2sn(n: TIdC_INT): PIdAnsiChar; cdecl;
function OBJ_obj2nid(o: PASN1_OBJECT): TIdC_INT; cdecl;
function OBJ_txt2obj(s: PIdAnsiChar; no_name: TIdC_INT): PASN1_OBJECT; cdecl;
function OBJ_obj2txt(buf: PIdAnsiChar; buf_len: TIdC_INT; a: PASN1_OBJECT; no_name: TIdC_INT): TIdC_INT; cdecl;
function OBJ_txt2nid(s: PIdAnsiChar): TIdC_INT; cdecl;
function OBJ_ln2nid(s: PIdAnsiChar): TIdC_INT; cdecl;
function OBJ_sn2nid(s: PIdAnsiChar): TIdC_INT; cdecl;
function OBJ_cmp(a: PASN1_OBJECT; b: PASN1_OBJECT): TIdC_INT; cdecl;
function OBJ_bsearch_(key: Pointer; base: Pointer; num: TIdC_INT; size: TIdC_INT; cmp: TOBJ_bsearch__cmp_cb): Pointer; cdecl;
function OBJ_bsearch_ex_(key: Pointer; base: Pointer; num: TIdC_INT; size: TIdC_INT; cmp: TOBJ_bsearch__cmp_cb; flags: TIdC_INT): Pointer; cdecl;
function OBJ_new_nid(num: TIdC_INT): TIdC_INT; cdecl;
function OBJ_add_object(obj: PASN1_OBJECT): TIdC_INT; cdecl;
function OBJ_create(oid: PIdAnsiChar; sn: PIdAnsiChar; ln: PIdAnsiChar): TIdC_INT; cdecl;
function OBJ_create_objects(_in: PBIO): TIdC_INT; cdecl;
function OBJ_length(obj: PASN1_OBJECT): TIdC_SIZET; cdecl;
function OBJ_get0_data(obj: PASN1_OBJECT): PIdAnsiChar; cdecl;
function OBJ_find_sigid_algs(signid: TIdC_INT; pdig_nid: PIdC_INT; ppkey_nid: PIdC_INT): TIdC_INT; cdecl;
function OBJ_find_sigid_by_algs(psignid: PIdC_INT; dig_nid: TIdC_INT; pkey_nid: TIdC_INT): TIdC_INT; cdecl;
function OBJ_add_sigid(signid: TIdC_INT; dig_id: TIdC_INT; pkey_id: TIdC_INT): TIdC_INT; cdecl;
procedure OBJ_sigid_free; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

function OBJ_cleanup: TIdC_INT; cdecl; deprecated 'In OpenSSL 1_1_0';
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

function OBJ_NAME_init: TIdC_INT; cdecl external CLibCrypto name 'OBJ_NAME_init';
function OBJ_NAME_new_index(hash_func: TOBJ_NAME_new_index_hash_func_cb; cmp_func: TOBJ_NAME_new_index_cmp_func_cb; free_func: TOBJ_NAME_new_index_free_func_cb): TIdC_INT; cdecl external CLibCrypto name 'OBJ_NAME_new_index';
function OBJ_NAME_get(name: PIdAnsiChar; _type: TIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'OBJ_NAME_get';
function OBJ_NAME_add(name: PIdAnsiChar; _type: TIdC_INT; data: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OBJ_NAME_add';
function OBJ_NAME_remove(name: PIdAnsiChar; _type: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OBJ_NAME_remove';
procedure OBJ_NAME_cleanup(_type: TIdC_INT); cdecl external CLibCrypto name 'OBJ_NAME_cleanup';
procedure OBJ_NAME_do_all(_type: TIdC_INT; fn: TOBJ_NAME_do_all_fn_cb; arg: Pointer); cdecl external CLibCrypto name 'OBJ_NAME_do_all';
procedure OBJ_NAME_do_all_sorted(_type: TIdC_INT; fn: TOBJ_NAME_do_all_fn_cb; arg: Pointer); cdecl external CLibCrypto name 'OBJ_NAME_do_all_sorted';
function OBJ_dup(a: PASN1_OBJECT): PASN1_OBJECT; cdecl external CLibCrypto name 'OBJ_dup';
function OBJ_nid2obj(n: TIdC_INT): PASN1_OBJECT; cdecl external CLibCrypto name 'OBJ_nid2obj';
function OBJ_nid2ln(n: TIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'OBJ_nid2ln';
function OBJ_nid2sn(n: TIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'OBJ_nid2sn';
function OBJ_obj2nid(o: PASN1_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'OBJ_obj2nid';
function OBJ_txt2obj(s: PIdAnsiChar; no_name: TIdC_INT): PASN1_OBJECT; cdecl external CLibCrypto name 'OBJ_txt2obj';
function OBJ_obj2txt(buf: PIdAnsiChar; buf_len: TIdC_INT; a: PASN1_OBJECT; no_name: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OBJ_obj2txt';
function OBJ_txt2nid(s: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OBJ_txt2nid';
function OBJ_ln2nid(s: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OBJ_ln2nid';
function OBJ_sn2nid(s: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OBJ_sn2nid';
function OBJ_cmp(a: PASN1_OBJECT; b: PASN1_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'OBJ_cmp';
function OBJ_bsearch_(key: Pointer; base: Pointer; num: TIdC_INT; size: TIdC_INT; cmp: TOBJ_bsearch__cmp_cb): Pointer; cdecl external CLibCrypto name 'OBJ_bsearch_';
function OBJ_bsearch_ex_(key: Pointer; base: Pointer; num: TIdC_INT; size: TIdC_INT; cmp: TOBJ_bsearch__cmp_cb; flags: TIdC_INT): Pointer; cdecl external CLibCrypto name 'OBJ_bsearch_ex_';
function OBJ_new_nid(num: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OBJ_new_nid';
function OBJ_add_object(obj: PASN1_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'OBJ_add_object';
function OBJ_create(oid: PIdAnsiChar; sn: PIdAnsiChar; ln: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'OBJ_create';
function OBJ_create_objects(_in: PBIO): TIdC_INT; cdecl external CLibCrypto name 'OBJ_create_objects';
function OBJ_length(obj: PASN1_OBJECT): TIdC_SIZET; cdecl external CLibCrypto name 'OBJ_length';
function OBJ_get0_data(obj: PASN1_OBJECT): PIdAnsiChar; cdecl external CLibCrypto name 'OBJ_get0_data';
function OBJ_find_sigid_algs(signid: TIdC_INT; pdig_nid: PIdC_INT; ppkey_nid: PIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OBJ_find_sigid_algs';
function OBJ_find_sigid_by_algs(psignid: PIdC_INT; dig_nid: TIdC_INT; pkey_nid: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OBJ_find_sigid_by_algs';
function OBJ_add_sigid(signid: TIdC_INT; dig_id: TIdC_INT; pkey_id: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OBJ_add_sigid';
procedure OBJ_sigid_free; cdecl external CLibCrypto name 'OBJ_sigid_free';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  OBJ_NAME_init_procname = 'OBJ_NAME_init';
  OBJ_NAME_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_NAME_new_index_procname = 'OBJ_NAME_new_index';
  OBJ_NAME_new_index_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_NAME_get_procname = 'OBJ_NAME_get';
  OBJ_NAME_get_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_NAME_add_procname = 'OBJ_NAME_add';
  OBJ_NAME_add_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_NAME_remove_procname = 'OBJ_NAME_remove';
  OBJ_NAME_remove_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_NAME_cleanup_procname = 'OBJ_NAME_cleanup';
  OBJ_NAME_cleanup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_NAME_do_all_procname = 'OBJ_NAME_do_all';
  OBJ_NAME_do_all_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_NAME_do_all_sorted_procname = 'OBJ_NAME_do_all_sorted';
  OBJ_NAME_do_all_sorted_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_dup_procname = 'OBJ_dup';
  OBJ_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_nid2obj_procname = 'OBJ_nid2obj';
  OBJ_nid2obj_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_nid2ln_procname = 'OBJ_nid2ln';
  OBJ_nid2ln_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_nid2sn_procname = 'OBJ_nid2sn';
  OBJ_nid2sn_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_obj2nid_procname = 'OBJ_obj2nid';
  OBJ_obj2nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_txt2obj_procname = 'OBJ_txt2obj';
  OBJ_txt2obj_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_obj2txt_procname = 'OBJ_obj2txt';
  OBJ_obj2txt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_txt2nid_procname = 'OBJ_txt2nid';
  OBJ_txt2nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_ln2nid_procname = 'OBJ_ln2nid';
  OBJ_ln2nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_sn2nid_procname = 'OBJ_sn2nid';
  OBJ_sn2nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_cmp_procname = 'OBJ_cmp';
  OBJ_cmp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_bsearch__procname = 'OBJ_bsearch_';
  OBJ_bsearch__introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_bsearch_ex__procname = 'OBJ_bsearch_ex_';
  OBJ_bsearch_ex__introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_new_nid_procname = 'OBJ_new_nid';
  OBJ_new_nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_add_object_procname = 'OBJ_add_object';
  OBJ_add_object_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_create_procname = 'OBJ_create';
  OBJ_create_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_create_objects_procname = 'OBJ_create_objects';
  OBJ_create_objects_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_length_procname = 'OBJ_length';
  OBJ_length_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_get0_data_procname = 'OBJ_get0_data';
  OBJ_get0_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_find_sigid_algs_procname = 'OBJ_find_sigid_algs';
  OBJ_find_sigid_algs_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_find_sigid_by_algs_procname = 'OBJ_find_sigid_by_algs';
  OBJ_find_sigid_by_algs_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_add_sigid_procname = 'OBJ_add_sigid';
  OBJ_add_sigid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OBJ_sigid_free_procname = 'OBJ_sigid_free';
  OBJ_sigid_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function OBJ_cleanup: TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OBJ_cleanup() \
    while (0)         \
    continue
  }
end;

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_OBJ_NAME_init: TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_NAME_init_procname);
end;

function ERR_OBJ_NAME_new_index(hash_func: TOBJ_NAME_new_index_hash_func_cb; cmp_func: TOBJ_NAME_new_index_cmp_func_cb; free_func: TOBJ_NAME_new_index_free_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_NAME_new_index_procname);
end;

function ERR_OBJ_NAME_get(name: PIdAnsiChar; _type: TIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_NAME_get_procname);
end;

function ERR_OBJ_NAME_add(name: PIdAnsiChar; _type: TIdC_INT; data: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_NAME_add_procname);
end;

function ERR_OBJ_NAME_remove(name: PIdAnsiChar; _type: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_NAME_remove_procname);
end;

procedure ERR_OBJ_NAME_cleanup(_type: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_NAME_cleanup_procname);
end;

procedure ERR_OBJ_NAME_do_all(_type: TIdC_INT; fn: TOBJ_NAME_do_all_fn_cb; arg: Pointer); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_NAME_do_all_procname);
end;

procedure ERR_OBJ_NAME_do_all_sorted(_type: TIdC_INT; fn: TOBJ_NAME_do_all_fn_cb; arg: Pointer); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_NAME_do_all_sorted_procname);
end;

function ERR_OBJ_dup(a: PASN1_OBJECT): PASN1_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_dup_procname);
end;

function ERR_OBJ_nid2obj(n: TIdC_INT): PASN1_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_nid2obj_procname);
end;

function ERR_OBJ_nid2ln(n: TIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_nid2ln_procname);
end;

function ERR_OBJ_nid2sn(n: TIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_nid2sn_procname);
end;

function ERR_OBJ_obj2nid(o: PASN1_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_obj2nid_procname);
end;

function ERR_OBJ_txt2obj(s: PIdAnsiChar; no_name: TIdC_INT): PASN1_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_txt2obj_procname);
end;

function ERR_OBJ_obj2txt(buf: PIdAnsiChar; buf_len: TIdC_INT; a: PASN1_OBJECT; no_name: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_obj2txt_procname);
end;

function ERR_OBJ_txt2nid(s: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_txt2nid_procname);
end;

function ERR_OBJ_ln2nid(s: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_ln2nid_procname);
end;

function ERR_OBJ_sn2nid(s: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_sn2nid_procname);
end;

function ERR_OBJ_cmp(a: PASN1_OBJECT; b: PASN1_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_cmp_procname);
end;

function ERR_OBJ_bsearch_(key: Pointer; base: Pointer; num: TIdC_INT; size: TIdC_INT; cmp: TOBJ_bsearch__cmp_cb): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_bsearch__procname);
end;

function ERR_OBJ_bsearch_ex_(key: Pointer; base: Pointer; num: TIdC_INT; size: TIdC_INT; cmp: TOBJ_bsearch__cmp_cb; flags: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_bsearch_ex__procname);
end;

function ERR_OBJ_new_nid(num: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_new_nid_procname);
end;

function ERR_OBJ_add_object(obj: PASN1_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_add_object_procname);
end;

function ERR_OBJ_create(oid: PIdAnsiChar; sn: PIdAnsiChar; ln: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_create_procname);
end;

function ERR_OBJ_create_objects(_in: PBIO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_create_objects_procname);
end;

function ERR_OBJ_length(obj: PASN1_OBJECT): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_length_procname);
end;

function ERR_OBJ_get0_data(obj: PASN1_OBJECT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_get0_data_procname);
end;

function ERR_OBJ_find_sigid_algs(signid: TIdC_INT; pdig_nid: PIdC_INT; ppkey_nid: PIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_find_sigid_algs_procname);
end;

function ERR_OBJ_find_sigid_by_algs(psignid: PIdC_INT; dig_nid: TIdC_INT; pkey_nid: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_find_sigid_by_algs_procname);
end;

function ERR_OBJ_add_sigid(signid: TIdC_INT; dig_id: TIdC_INT; pkey_id: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_add_sigid_procname);
end;

procedure ERR_OBJ_sigid_free; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OBJ_sigid_free_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  OBJ_NAME_init := LoadLibFunction(ADllHandle, OBJ_NAME_init_procname);
  FuncLoadError := not assigned(OBJ_NAME_init);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_NAME_init_allownil)}
    OBJ_NAME_init := ERR_OBJ_NAME_init;
    {$ifend}
    {$if declared(OBJ_NAME_init_introduced)}
    if LibVersion < OBJ_NAME_init_introduced then
    begin
      {$if declared(FC_OBJ_NAME_init)}
      OBJ_NAME_init := FC_OBJ_NAME_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_NAME_init_removed)}
    if OBJ_NAME_init_removed <= LibVersion then
    begin
      {$if declared(_OBJ_NAME_init)}
      OBJ_NAME_init := _OBJ_NAME_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_NAME_init_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_NAME_init');
    {$ifend}
  end;
  
  OBJ_NAME_new_index := LoadLibFunction(ADllHandle, OBJ_NAME_new_index_procname);
  FuncLoadError := not assigned(OBJ_NAME_new_index);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_NAME_new_index_allownil)}
    OBJ_NAME_new_index := ERR_OBJ_NAME_new_index;
    {$ifend}
    {$if declared(OBJ_NAME_new_index_introduced)}
    if LibVersion < OBJ_NAME_new_index_introduced then
    begin
      {$if declared(FC_OBJ_NAME_new_index)}
      OBJ_NAME_new_index := FC_OBJ_NAME_new_index;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_NAME_new_index_removed)}
    if OBJ_NAME_new_index_removed <= LibVersion then
    begin
      {$if declared(_OBJ_NAME_new_index)}
      OBJ_NAME_new_index := _OBJ_NAME_new_index;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_NAME_new_index_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_NAME_new_index');
    {$ifend}
  end;
  
  OBJ_NAME_get := LoadLibFunction(ADllHandle, OBJ_NAME_get_procname);
  FuncLoadError := not assigned(OBJ_NAME_get);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_NAME_get_allownil)}
    OBJ_NAME_get := ERR_OBJ_NAME_get;
    {$ifend}
    {$if declared(OBJ_NAME_get_introduced)}
    if LibVersion < OBJ_NAME_get_introduced then
    begin
      {$if declared(FC_OBJ_NAME_get)}
      OBJ_NAME_get := FC_OBJ_NAME_get;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_NAME_get_removed)}
    if OBJ_NAME_get_removed <= LibVersion then
    begin
      {$if declared(_OBJ_NAME_get)}
      OBJ_NAME_get := _OBJ_NAME_get;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_NAME_get_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_NAME_get');
    {$ifend}
  end;
  
  OBJ_NAME_add := LoadLibFunction(ADllHandle, OBJ_NAME_add_procname);
  FuncLoadError := not assigned(OBJ_NAME_add);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_NAME_add_allownil)}
    OBJ_NAME_add := ERR_OBJ_NAME_add;
    {$ifend}
    {$if declared(OBJ_NAME_add_introduced)}
    if LibVersion < OBJ_NAME_add_introduced then
    begin
      {$if declared(FC_OBJ_NAME_add)}
      OBJ_NAME_add := FC_OBJ_NAME_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_NAME_add_removed)}
    if OBJ_NAME_add_removed <= LibVersion then
    begin
      {$if declared(_OBJ_NAME_add)}
      OBJ_NAME_add := _OBJ_NAME_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_NAME_add_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_NAME_add');
    {$ifend}
  end;
  
  OBJ_NAME_remove := LoadLibFunction(ADllHandle, OBJ_NAME_remove_procname);
  FuncLoadError := not assigned(OBJ_NAME_remove);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_NAME_remove_allownil)}
    OBJ_NAME_remove := ERR_OBJ_NAME_remove;
    {$ifend}
    {$if declared(OBJ_NAME_remove_introduced)}
    if LibVersion < OBJ_NAME_remove_introduced then
    begin
      {$if declared(FC_OBJ_NAME_remove)}
      OBJ_NAME_remove := FC_OBJ_NAME_remove;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_NAME_remove_removed)}
    if OBJ_NAME_remove_removed <= LibVersion then
    begin
      {$if declared(_OBJ_NAME_remove)}
      OBJ_NAME_remove := _OBJ_NAME_remove;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_NAME_remove_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_NAME_remove');
    {$ifend}
  end;
  
  OBJ_NAME_cleanup := LoadLibFunction(ADllHandle, OBJ_NAME_cleanup_procname);
  FuncLoadError := not assigned(OBJ_NAME_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_NAME_cleanup_allownil)}
    OBJ_NAME_cleanup := ERR_OBJ_NAME_cleanup;
    {$ifend}
    {$if declared(OBJ_NAME_cleanup_introduced)}
    if LibVersion < OBJ_NAME_cleanup_introduced then
    begin
      {$if declared(FC_OBJ_NAME_cleanup)}
      OBJ_NAME_cleanup := FC_OBJ_NAME_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_NAME_cleanup_removed)}
    if OBJ_NAME_cleanup_removed <= LibVersion then
    begin
      {$if declared(_OBJ_NAME_cleanup)}
      OBJ_NAME_cleanup := _OBJ_NAME_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_NAME_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_NAME_cleanup');
    {$ifend}
  end;
  
  OBJ_NAME_do_all := LoadLibFunction(ADllHandle, OBJ_NAME_do_all_procname);
  FuncLoadError := not assigned(OBJ_NAME_do_all);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_NAME_do_all_allownil)}
    OBJ_NAME_do_all := ERR_OBJ_NAME_do_all;
    {$ifend}
    {$if declared(OBJ_NAME_do_all_introduced)}
    if LibVersion < OBJ_NAME_do_all_introduced then
    begin
      {$if declared(FC_OBJ_NAME_do_all)}
      OBJ_NAME_do_all := FC_OBJ_NAME_do_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_NAME_do_all_removed)}
    if OBJ_NAME_do_all_removed <= LibVersion then
    begin
      {$if declared(_OBJ_NAME_do_all)}
      OBJ_NAME_do_all := _OBJ_NAME_do_all;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_NAME_do_all_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_NAME_do_all');
    {$ifend}
  end;
  
  OBJ_NAME_do_all_sorted := LoadLibFunction(ADllHandle, OBJ_NAME_do_all_sorted_procname);
  FuncLoadError := not assigned(OBJ_NAME_do_all_sorted);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_NAME_do_all_sorted_allownil)}
    OBJ_NAME_do_all_sorted := ERR_OBJ_NAME_do_all_sorted;
    {$ifend}
    {$if declared(OBJ_NAME_do_all_sorted_introduced)}
    if LibVersion < OBJ_NAME_do_all_sorted_introduced then
    begin
      {$if declared(FC_OBJ_NAME_do_all_sorted)}
      OBJ_NAME_do_all_sorted := FC_OBJ_NAME_do_all_sorted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_NAME_do_all_sorted_removed)}
    if OBJ_NAME_do_all_sorted_removed <= LibVersion then
    begin
      {$if declared(_OBJ_NAME_do_all_sorted)}
      OBJ_NAME_do_all_sorted := _OBJ_NAME_do_all_sorted;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_NAME_do_all_sorted_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_NAME_do_all_sorted');
    {$ifend}
  end;
  
  OBJ_dup := LoadLibFunction(ADllHandle, OBJ_dup_procname);
  FuncLoadError := not assigned(OBJ_dup);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_dup_allownil)}
    OBJ_dup := ERR_OBJ_dup;
    {$ifend}
    {$if declared(OBJ_dup_introduced)}
    if LibVersion < OBJ_dup_introduced then
    begin
      {$if declared(FC_OBJ_dup)}
      OBJ_dup := FC_OBJ_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_dup_removed)}
    if OBJ_dup_removed <= LibVersion then
    begin
      {$if declared(_OBJ_dup)}
      OBJ_dup := _OBJ_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_dup');
    {$ifend}
  end;
  
  OBJ_nid2obj := LoadLibFunction(ADllHandle, OBJ_nid2obj_procname);
  FuncLoadError := not assigned(OBJ_nid2obj);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_nid2obj_allownil)}
    OBJ_nid2obj := ERR_OBJ_nid2obj;
    {$ifend}
    {$if declared(OBJ_nid2obj_introduced)}
    if LibVersion < OBJ_nid2obj_introduced then
    begin
      {$if declared(FC_OBJ_nid2obj)}
      OBJ_nid2obj := FC_OBJ_nid2obj;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_nid2obj_removed)}
    if OBJ_nid2obj_removed <= LibVersion then
    begin
      {$if declared(_OBJ_nid2obj)}
      OBJ_nid2obj := _OBJ_nid2obj;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_nid2obj_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_nid2obj');
    {$ifend}
  end;
  
  OBJ_nid2ln := LoadLibFunction(ADllHandle, OBJ_nid2ln_procname);
  FuncLoadError := not assigned(OBJ_nid2ln);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_nid2ln_allownil)}
    OBJ_nid2ln := ERR_OBJ_nid2ln;
    {$ifend}
    {$if declared(OBJ_nid2ln_introduced)}
    if LibVersion < OBJ_nid2ln_introduced then
    begin
      {$if declared(FC_OBJ_nid2ln)}
      OBJ_nid2ln := FC_OBJ_nid2ln;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_nid2ln_removed)}
    if OBJ_nid2ln_removed <= LibVersion then
    begin
      {$if declared(_OBJ_nid2ln)}
      OBJ_nid2ln := _OBJ_nid2ln;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_nid2ln_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_nid2ln');
    {$ifend}
  end;
  
  OBJ_nid2sn := LoadLibFunction(ADllHandle, OBJ_nid2sn_procname);
  FuncLoadError := not assigned(OBJ_nid2sn);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_nid2sn_allownil)}
    OBJ_nid2sn := ERR_OBJ_nid2sn;
    {$ifend}
    {$if declared(OBJ_nid2sn_introduced)}
    if LibVersion < OBJ_nid2sn_introduced then
    begin
      {$if declared(FC_OBJ_nid2sn)}
      OBJ_nid2sn := FC_OBJ_nid2sn;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_nid2sn_removed)}
    if OBJ_nid2sn_removed <= LibVersion then
    begin
      {$if declared(_OBJ_nid2sn)}
      OBJ_nid2sn := _OBJ_nid2sn;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_nid2sn_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_nid2sn');
    {$ifend}
  end;
  
  OBJ_obj2nid := LoadLibFunction(ADllHandle, OBJ_obj2nid_procname);
  FuncLoadError := not assigned(OBJ_obj2nid);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_obj2nid_allownil)}
    OBJ_obj2nid := ERR_OBJ_obj2nid;
    {$ifend}
    {$if declared(OBJ_obj2nid_introduced)}
    if LibVersion < OBJ_obj2nid_introduced then
    begin
      {$if declared(FC_OBJ_obj2nid)}
      OBJ_obj2nid := FC_OBJ_obj2nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_obj2nid_removed)}
    if OBJ_obj2nid_removed <= LibVersion then
    begin
      {$if declared(_OBJ_obj2nid)}
      OBJ_obj2nid := _OBJ_obj2nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_obj2nid_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_obj2nid');
    {$ifend}
  end;
  
  OBJ_txt2obj := LoadLibFunction(ADllHandle, OBJ_txt2obj_procname);
  FuncLoadError := not assigned(OBJ_txt2obj);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_txt2obj_allownil)}
    OBJ_txt2obj := ERR_OBJ_txt2obj;
    {$ifend}
    {$if declared(OBJ_txt2obj_introduced)}
    if LibVersion < OBJ_txt2obj_introduced then
    begin
      {$if declared(FC_OBJ_txt2obj)}
      OBJ_txt2obj := FC_OBJ_txt2obj;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_txt2obj_removed)}
    if OBJ_txt2obj_removed <= LibVersion then
    begin
      {$if declared(_OBJ_txt2obj)}
      OBJ_txt2obj := _OBJ_txt2obj;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_txt2obj_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_txt2obj');
    {$ifend}
  end;
  
  OBJ_obj2txt := LoadLibFunction(ADllHandle, OBJ_obj2txt_procname);
  FuncLoadError := not assigned(OBJ_obj2txt);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_obj2txt_allownil)}
    OBJ_obj2txt := ERR_OBJ_obj2txt;
    {$ifend}
    {$if declared(OBJ_obj2txt_introduced)}
    if LibVersion < OBJ_obj2txt_introduced then
    begin
      {$if declared(FC_OBJ_obj2txt)}
      OBJ_obj2txt := FC_OBJ_obj2txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_obj2txt_removed)}
    if OBJ_obj2txt_removed <= LibVersion then
    begin
      {$if declared(_OBJ_obj2txt)}
      OBJ_obj2txt := _OBJ_obj2txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_obj2txt_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_obj2txt');
    {$ifend}
  end;
  
  OBJ_txt2nid := LoadLibFunction(ADllHandle, OBJ_txt2nid_procname);
  FuncLoadError := not assigned(OBJ_txt2nid);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_txt2nid_allownil)}
    OBJ_txt2nid := ERR_OBJ_txt2nid;
    {$ifend}
    {$if declared(OBJ_txt2nid_introduced)}
    if LibVersion < OBJ_txt2nid_introduced then
    begin
      {$if declared(FC_OBJ_txt2nid)}
      OBJ_txt2nid := FC_OBJ_txt2nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_txt2nid_removed)}
    if OBJ_txt2nid_removed <= LibVersion then
    begin
      {$if declared(_OBJ_txt2nid)}
      OBJ_txt2nid := _OBJ_txt2nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_txt2nid_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_txt2nid');
    {$ifend}
  end;
  
  OBJ_ln2nid := LoadLibFunction(ADllHandle, OBJ_ln2nid_procname);
  FuncLoadError := not assigned(OBJ_ln2nid);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_ln2nid_allownil)}
    OBJ_ln2nid := ERR_OBJ_ln2nid;
    {$ifend}
    {$if declared(OBJ_ln2nid_introduced)}
    if LibVersion < OBJ_ln2nid_introduced then
    begin
      {$if declared(FC_OBJ_ln2nid)}
      OBJ_ln2nid := FC_OBJ_ln2nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_ln2nid_removed)}
    if OBJ_ln2nid_removed <= LibVersion then
    begin
      {$if declared(_OBJ_ln2nid)}
      OBJ_ln2nid := _OBJ_ln2nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_ln2nid_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_ln2nid');
    {$ifend}
  end;
  
  OBJ_sn2nid := LoadLibFunction(ADllHandle, OBJ_sn2nid_procname);
  FuncLoadError := not assigned(OBJ_sn2nid);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_sn2nid_allownil)}
    OBJ_sn2nid := ERR_OBJ_sn2nid;
    {$ifend}
    {$if declared(OBJ_sn2nid_introduced)}
    if LibVersion < OBJ_sn2nid_introduced then
    begin
      {$if declared(FC_OBJ_sn2nid)}
      OBJ_sn2nid := FC_OBJ_sn2nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_sn2nid_removed)}
    if OBJ_sn2nid_removed <= LibVersion then
    begin
      {$if declared(_OBJ_sn2nid)}
      OBJ_sn2nid := _OBJ_sn2nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_sn2nid_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_sn2nid');
    {$ifend}
  end;
  
  OBJ_cmp := LoadLibFunction(ADllHandle, OBJ_cmp_procname);
  FuncLoadError := not assigned(OBJ_cmp);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_cmp_allownil)}
    OBJ_cmp := ERR_OBJ_cmp;
    {$ifend}
    {$if declared(OBJ_cmp_introduced)}
    if LibVersion < OBJ_cmp_introduced then
    begin
      {$if declared(FC_OBJ_cmp)}
      OBJ_cmp := FC_OBJ_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_cmp_removed)}
    if OBJ_cmp_removed <= LibVersion then
    begin
      {$if declared(_OBJ_cmp)}
      OBJ_cmp := _OBJ_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_cmp');
    {$ifend}
  end;
  
  OBJ_bsearch_ := LoadLibFunction(ADllHandle, OBJ_bsearch__procname);
  FuncLoadError := not assigned(OBJ_bsearch_);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_bsearch__allownil)}
    OBJ_bsearch_ := ERR_OBJ_bsearch_;
    {$ifend}
    {$if declared(OBJ_bsearch__introduced)}
    if LibVersion < OBJ_bsearch__introduced then
    begin
      {$if declared(FC_OBJ_bsearch_)}
      OBJ_bsearch_ := FC_OBJ_bsearch_;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_bsearch__removed)}
    if OBJ_bsearch__removed <= LibVersion then
    begin
      {$if declared(_OBJ_bsearch_)}
      OBJ_bsearch_ := _OBJ_bsearch_;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_bsearch__allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_bsearch_');
    {$ifend}
  end;
  
  OBJ_bsearch_ex_ := LoadLibFunction(ADllHandle, OBJ_bsearch_ex__procname);
  FuncLoadError := not assigned(OBJ_bsearch_ex_);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_bsearch_ex__allownil)}
    OBJ_bsearch_ex_ := ERR_OBJ_bsearch_ex_;
    {$ifend}
    {$if declared(OBJ_bsearch_ex__introduced)}
    if LibVersion < OBJ_bsearch_ex__introduced then
    begin
      {$if declared(FC_OBJ_bsearch_ex_)}
      OBJ_bsearch_ex_ := FC_OBJ_bsearch_ex_;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_bsearch_ex__removed)}
    if OBJ_bsearch_ex__removed <= LibVersion then
    begin
      {$if declared(_OBJ_bsearch_ex_)}
      OBJ_bsearch_ex_ := _OBJ_bsearch_ex_;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_bsearch_ex__allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_bsearch_ex_');
    {$ifend}
  end;
  
  OBJ_new_nid := LoadLibFunction(ADllHandle, OBJ_new_nid_procname);
  FuncLoadError := not assigned(OBJ_new_nid);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_new_nid_allownil)}
    OBJ_new_nid := ERR_OBJ_new_nid;
    {$ifend}
    {$if declared(OBJ_new_nid_introduced)}
    if LibVersion < OBJ_new_nid_introduced then
    begin
      {$if declared(FC_OBJ_new_nid)}
      OBJ_new_nid := FC_OBJ_new_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_new_nid_removed)}
    if OBJ_new_nid_removed <= LibVersion then
    begin
      {$if declared(_OBJ_new_nid)}
      OBJ_new_nid := _OBJ_new_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_new_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_new_nid');
    {$ifend}
  end;
  
  OBJ_add_object := LoadLibFunction(ADllHandle, OBJ_add_object_procname);
  FuncLoadError := not assigned(OBJ_add_object);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_add_object_allownil)}
    OBJ_add_object := ERR_OBJ_add_object;
    {$ifend}
    {$if declared(OBJ_add_object_introduced)}
    if LibVersion < OBJ_add_object_introduced then
    begin
      {$if declared(FC_OBJ_add_object)}
      OBJ_add_object := FC_OBJ_add_object;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_add_object_removed)}
    if OBJ_add_object_removed <= LibVersion then
    begin
      {$if declared(_OBJ_add_object)}
      OBJ_add_object := _OBJ_add_object;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_add_object_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_add_object');
    {$ifend}
  end;
  
  OBJ_create := LoadLibFunction(ADllHandle, OBJ_create_procname);
  FuncLoadError := not assigned(OBJ_create);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_create_allownil)}
    OBJ_create := ERR_OBJ_create;
    {$ifend}
    {$if declared(OBJ_create_introduced)}
    if LibVersion < OBJ_create_introduced then
    begin
      {$if declared(FC_OBJ_create)}
      OBJ_create := FC_OBJ_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_create_removed)}
    if OBJ_create_removed <= LibVersion then
    begin
      {$if declared(_OBJ_create)}
      OBJ_create := _OBJ_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_create_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_create');
    {$ifend}
  end;
  
  OBJ_create_objects := LoadLibFunction(ADllHandle, OBJ_create_objects_procname);
  FuncLoadError := not assigned(OBJ_create_objects);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_create_objects_allownil)}
    OBJ_create_objects := ERR_OBJ_create_objects;
    {$ifend}
    {$if declared(OBJ_create_objects_introduced)}
    if LibVersion < OBJ_create_objects_introduced then
    begin
      {$if declared(FC_OBJ_create_objects)}
      OBJ_create_objects := FC_OBJ_create_objects;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_create_objects_removed)}
    if OBJ_create_objects_removed <= LibVersion then
    begin
      {$if declared(_OBJ_create_objects)}
      OBJ_create_objects := _OBJ_create_objects;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_create_objects_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_create_objects');
    {$ifend}
  end;
  
  OBJ_length := LoadLibFunction(ADllHandle, OBJ_length_procname);
  FuncLoadError := not assigned(OBJ_length);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_length_allownil)}
    OBJ_length := ERR_OBJ_length;
    {$ifend}
    {$if declared(OBJ_length_introduced)}
    if LibVersion < OBJ_length_introduced then
    begin
      {$if declared(FC_OBJ_length)}
      OBJ_length := FC_OBJ_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_length_removed)}
    if OBJ_length_removed <= LibVersion then
    begin
      {$if declared(_OBJ_length)}
      OBJ_length := _OBJ_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_length_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_length');
    {$ifend}
  end;
  
  OBJ_get0_data := LoadLibFunction(ADllHandle, OBJ_get0_data_procname);
  FuncLoadError := not assigned(OBJ_get0_data);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_get0_data_allownil)}
    OBJ_get0_data := ERR_OBJ_get0_data;
    {$ifend}
    {$if declared(OBJ_get0_data_introduced)}
    if LibVersion < OBJ_get0_data_introduced then
    begin
      {$if declared(FC_OBJ_get0_data)}
      OBJ_get0_data := FC_OBJ_get0_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_get0_data_removed)}
    if OBJ_get0_data_removed <= LibVersion then
    begin
      {$if declared(_OBJ_get0_data)}
      OBJ_get0_data := _OBJ_get0_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_get0_data_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_get0_data');
    {$ifend}
  end;
  
  OBJ_find_sigid_algs := LoadLibFunction(ADllHandle, OBJ_find_sigid_algs_procname);
  FuncLoadError := not assigned(OBJ_find_sigid_algs);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_find_sigid_algs_allownil)}
    OBJ_find_sigid_algs := ERR_OBJ_find_sigid_algs;
    {$ifend}
    {$if declared(OBJ_find_sigid_algs_introduced)}
    if LibVersion < OBJ_find_sigid_algs_introduced then
    begin
      {$if declared(FC_OBJ_find_sigid_algs)}
      OBJ_find_sigid_algs := FC_OBJ_find_sigid_algs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_find_sigid_algs_removed)}
    if OBJ_find_sigid_algs_removed <= LibVersion then
    begin
      {$if declared(_OBJ_find_sigid_algs)}
      OBJ_find_sigid_algs := _OBJ_find_sigid_algs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_find_sigid_algs_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_find_sigid_algs');
    {$ifend}
  end;
  
  OBJ_find_sigid_by_algs := LoadLibFunction(ADllHandle, OBJ_find_sigid_by_algs_procname);
  FuncLoadError := not assigned(OBJ_find_sigid_by_algs);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_find_sigid_by_algs_allownil)}
    OBJ_find_sigid_by_algs := ERR_OBJ_find_sigid_by_algs;
    {$ifend}
    {$if declared(OBJ_find_sigid_by_algs_introduced)}
    if LibVersion < OBJ_find_sigid_by_algs_introduced then
    begin
      {$if declared(FC_OBJ_find_sigid_by_algs)}
      OBJ_find_sigid_by_algs := FC_OBJ_find_sigid_by_algs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_find_sigid_by_algs_removed)}
    if OBJ_find_sigid_by_algs_removed <= LibVersion then
    begin
      {$if declared(_OBJ_find_sigid_by_algs)}
      OBJ_find_sigid_by_algs := _OBJ_find_sigid_by_algs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_find_sigid_by_algs_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_find_sigid_by_algs');
    {$ifend}
  end;
  
  OBJ_add_sigid := LoadLibFunction(ADllHandle, OBJ_add_sigid_procname);
  FuncLoadError := not assigned(OBJ_add_sigid);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_add_sigid_allownil)}
    OBJ_add_sigid := ERR_OBJ_add_sigid;
    {$ifend}
    {$if declared(OBJ_add_sigid_introduced)}
    if LibVersion < OBJ_add_sigid_introduced then
    begin
      {$if declared(FC_OBJ_add_sigid)}
      OBJ_add_sigid := FC_OBJ_add_sigid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_add_sigid_removed)}
    if OBJ_add_sigid_removed <= LibVersion then
    begin
      {$if declared(_OBJ_add_sigid)}
      OBJ_add_sigid := _OBJ_add_sigid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_add_sigid_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_add_sigid');
    {$ifend}
  end;
  
  OBJ_sigid_free := LoadLibFunction(ADllHandle, OBJ_sigid_free_procname);
  FuncLoadError := not assigned(OBJ_sigid_free);
  if FuncLoadError then
  begin
    {$if not defined(OBJ_sigid_free_allownil)}
    OBJ_sigid_free := ERR_OBJ_sigid_free;
    {$ifend}
    {$if declared(OBJ_sigid_free_introduced)}
    if LibVersion < OBJ_sigid_free_introduced then
    begin
      {$if declared(FC_OBJ_sigid_free)}
      OBJ_sigid_free := FC_OBJ_sigid_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OBJ_sigid_free_removed)}
    if OBJ_sigid_free_removed <= LibVersion then
    begin
      {$if declared(_OBJ_sigid_free)}
      OBJ_sigid_free := _OBJ_sigid_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OBJ_sigid_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OBJ_sigid_free');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  OBJ_NAME_init := nil;
  OBJ_NAME_new_index := nil;
  OBJ_NAME_get := nil;
  OBJ_NAME_add := nil;
  OBJ_NAME_remove := nil;
  OBJ_NAME_cleanup := nil;
  OBJ_NAME_do_all := nil;
  OBJ_NAME_do_all_sorted := nil;
  OBJ_dup := nil;
  OBJ_nid2obj := nil;
  OBJ_nid2ln := nil;
  OBJ_nid2sn := nil;
  OBJ_obj2nid := nil;
  OBJ_txt2obj := nil;
  OBJ_obj2txt := nil;
  OBJ_txt2nid := nil;
  OBJ_ln2nid := nil;
  OBJ_sn2nid := nil;
  OBJ_cmp := nil;
  OBJ_bsearch_ := nil;
  OBJ_bsearch_ex_ := nil;
  OBJ_new_nid := nil;
  OBJ_add_object := nil;
  OBJ_create := nil;
  OBJ_create_objects := nil;
  OBJ_length := nil;
  OBJ_get0_data := nil;
  OBJ_find_sigid_algs := nil;
  OBJ_find_sigid_by_algs := nil;
  OBJ_add_sigid := nil;
  OBJ_sigid_free := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.