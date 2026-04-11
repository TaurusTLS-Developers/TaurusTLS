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

unit TaurusTLSHeaders_ct;

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
// ENUM TYPE DECLARATIONS
// =============================================================================
type
  // Enum: ct_log_entry_type_t
  Tct_log_entry_type_t = (
    CT_LOG_ENTRY_TYPE_NOT_SET = -1,
    CT_LOG_ENTRY_TYPE_X509 = 0,
    CT_LOG_ENTRY_TYPE_PRECERT = 1
  );

  // Enum: sct_version_t
  Tsct_version_t = (
    SCT_VERSION_NOT_SET = -1,
    SCT_VERSION_V1 = 0
  );

  // Enum: sct_source_t
  Tsct_source_t = (
    SCT_SOURCE_UNKNOWN = 0,
    SCT_SOURCE_TLS_EXTENSION = 1,
    SCT_SOURCE_X509V3_EXTENSION = 2,
    SCT_SOURCE_OCSP_STAPLED_RESPONSE = 3
  );

  // Enum: sct_validation_status_t
  Tsct_validation_status_t = (
    SCT_VALIDATION_STATUS_NOT_SET = 0,
    SCT_VALIDATION_STATUS_UNKNOWN_LOG = 1,
    SCT_VALIDATION_STATUS_VALID = 2,
    SCT_VALIDATION_STATUS_INVALID = 3,
    SCT_VALIDATION_STATUS_UNVERIFIED = 4,
    SCT_VALIDATION_STATUS_UNKNOWN_VERSION = 5
  );


// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  SCT_MIN_RSA_BITS = 2048;
  CT_V1_HASHLEN = SHA256_DIGEST_LENGTH;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  CT_POLICY_EVAL_CTX_new_ex: function(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCT_POLICY_EVAL_CTX; cdecl = nil;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_new_ex}

  CT_POLICY_EVAL_CTX_new: function: PCT_POLICY_EVAL_CTX; cdecl = nil;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_new}

  CT_POLICY_EVAL_CTX_free: procedure(ctx: PCT_POLICY_EVAL_CTX); cdecl = nil;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_free}

  CT_POLICY_EVAL_CTX_get0_cert: function(ctx: PCT_POLICY_EVAL_CTX): PX509; cdecl = nil;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_get0_cert}

  CT_POLICY_EVAL_CTX_set1_cert: function(ctx: PCT_POLICY_EVAL_CTX; cert: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_set1_cert}

  CT_POLICY_EVAL_CTX_get0_issuer: function(ctx: PCT_POLICY_EVAL_CTX): PX509; cdecl = nil;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_get0_issuer}

  CT_POLICY_EVAL_CTX_set1_issuer: function(ctx: PCT_POLICY_EVAL_CTX; issuer: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_set1_issuer}

  CT_POLICY_EVAL_CTX_get0_log_store: function(ctx: PCT_POLICY_EVAL_CTX): PCTLOG_STORE; cdecl = nil;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_get0_log_store}

  CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE: procedure(ctx: PCT_POLICY_EVAL_CTX; log_store: PCTLOG_STORE); cdecl = nil;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE}

  CT_POLICY_EVAL_CTX_get_time: function(ctx: PCT_POLICY_EVAL_CTX): TIdC_UINT64; cdecl = nil;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_get_time}

  CT_POLICY_EVAL_CTX_set_time: procedure(ctx: PCT_POLICY_EVAL_CTX; time_in_ms: TIdC_UINT64); cdecl = nil;
  {$EXTERNALSYM CT_POLICY_EVAL_CTX_set_time}

  SCT_new: function: PSCT; cdecl = nil;
  {$EXTERNALSYM SCT_new}

  SCT_new_from_base64: function(version: TIdC_UINT8; logid_base64: PIdAnsiChar; entry_type: Tct_log_entry_type_t; timestamp: TIdC_UINT64; extensions_base64: PIdAnsiChar; signature_base64: PIdAnsiChar): PSCT; cdecl = nil;
  {$EXTERNALSYM SCT_new_from_base64}

  SCT_free: procedure(sct: PSCT); cdecl = nil;
  {$EXTERNALSYM SCT_free}

  SCT_LIST_free: procedure(a: Pstack_st_SCT); cdecl = nil;
  {$EXTERNALSYM SCT_LIST_free}

  SCT_get_version: function(sct: PSCT): Tsct_version_t; cdecl = nil;
  {$EXTERNALSYM SCT_get_version}

  SCT_set_version: function(sct: PSCT; version: Tsct_version_t): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SCT_set_version}

  SCT_get_log_entry_type: function(sct: PSCT): Tct_log_entry_type_t; cdecl = nil;
  {$EXTERNALSYM SCT_get_log_entry_type}

  SCT_set_log_entry_type: function(sct: PSCT; entry_type: Tct_log_entry_type_t): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SCT_set_log_entry_type}

  SCT_get0_log_id: function(sct: PSCT; log_id: PPIdAnsiChar): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM SCT_get0_log_id}

  SCT_set0_log_id: function(sct: PSCT; log_id: PIdAnsiChar; log_id_len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SCT_set0_log_id}

  SCT_set1_log_id: function(sct: PSCT; log_id: PIdAnsiChar; log_id_len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SCT_set1_log_id}

  SCT_get_timestamp: function(sct: PSCT): TIdC_UINT64; cdecl = nil;
  {$EXTERNALSYM SCT_get_timestamp}

  SCT_set_timestamp: procedure(sct: PSCT; timestamp: TIdC_UINT64); cdecl = nil;
  {$EXTERNALSYM SCT_set_timestamp}

  SCT_get_signature_nid: function(sct: PSCT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SCT_get_signature_nid}

  SCT_set_signature_nid: function(sct: PSCT; nid: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SCT_set_signature_nid}

  SCT_get0_extensions: function(sct: PSCT; ext: PPIdAnsiChar): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM SCT_get0_extensions}

  SCT_set0_extensions: procedure(sct: PSCT; ext: PIdAnsiChar; ext_len: TIdC_SIZET); cdecl = nil;
  {$EXTERNALSYM SCT_set0_extensions}

  SCT_set1_extensions: function(sct: PSCT; ext: PIdAnsiChar; ext_len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SCT_set1_extensions}

  SCT_get0_signature: function(sct: PSCT; sig: PPIdAnsiChar): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM SCT_get0_signature}

  SCT_set0_signature: procedure(sct: PSCT; sig: PIdAnsiChar; sig_len: TIdC_SIZET); cdecl = nil;
  {$EXTERNALSYM SCT_set0_signature}

  SCT_set1_signature: function(sct: PSCT; sig: PIdAnsiChar; sig_len: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SCT_set1_signature}

  SCT_get_source: function(sct: PSCT): Tsct_source_t; cdecl = nil;
  {$EXTERNALSYM SCT_get_source}

  SCT_set_source: function(sct: PSCT; source: Tsct_source_t): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SCT_set_source}

  SCT_validation_status_string: function(sct: PSCT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM SCT_validation_status_string}

  SCT_print: procedure(sct: PSCT; _out: PBIO; indent: TIdC_INT; logs: PCTLOG_STORE); cdecl = nil;
  {$EXTERNALSYM SCT_print}

  SCT_LIST_print: procedure(sct_list: Pstack_st_SCT; _out: PBIO; indent: TIdC_INT; separator: PIdAnsiChar; logs: PCTLOG_STORE); cdecl = nil;
  {$EXTERNALSYM SCT_LIST_print}

  SCT_get_validation_status: function(sct: PSCT): Tsct_validation_status_t; cdecl = nil;
  {$EXTERNALSYM SCT_get_validation_status}

  SCT_validate: function(sct: PSCT; ctx: PCT_POLICY_EVAL_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SCT_validate}

  SCT_LIST_validate: function(scts: Pstack_st_SCT; ctx: PCT_POLICY_EVAL_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SCT_LIST_validate}

  i2o_SCT_LIST: function(a: Pstack_st_SCT; pp: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2o_SCT_LIST}

  o2i_SCT_LIST: function(a: PPstack_st_SCT; pp: PPIdAnsiChar; len: TIdC_SIZET): Pstack_st_SCT; cdecl = nil;
  {$EXTERNALSYM o2i_SCT_LIST}

  i2d_SCT_LIST: function(a: Pstack_st_SCT; pp: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_SCT_LIST}

  d2i_SCT_LIST: function(a: PPstack_st_SCT; pp: PPIdAnsiChar; len: TIdC_LONG): Pstack_st_SCT; cdecl = nil;
  {$EXTERNALSYM d2i_SCT_LIST}

  i2o_SCT: function(sct: PSCT; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2o_SCT}

  o2i_SCT: function(psct: PPSCT; _in: PPIdAnsiChar; len: TIdC_SIZET): PSCT; cdecl = nil;
  {$EXTERNALSYM o2i_SCT}

  CTLOG_new_ex: function(public_key: PEVP_PKEY; name: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCTLOG; cdecl = nil;
  {$EXTERNALSYM CTLOG_new_ex}

  CTLOG_new: function(public_key: PEVP_PKEY; name: PIdAnsiChar): PCTLOG; cdecl = nil;
  {$EXTERNALSYM CTLOG_new}

  CTLOG_new_from_base64_ex: function(ct_log: PPCTLOG; pkey_base64: PIdAnsiChar; name: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CTLOG_new_from_base64_ex}

  CTLOG_new_from_base64: function(ct_log: PPCTLOG; pkey_base64: PIdAnsiChar; name: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CTLOG_new_from_base64}

  CTLOG_free: procedure(log: PCTLOG); cdecl = nil;
  {$EXTERNALSYM CTLOG_free}

  CTLOG_get0_name: function(log: PCTLOG): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM CTLOG_get0_name}

  CTLOG_get0_log_id: procedure(log: PCTLOG; log_id: PPIdC_UINT8; log_id_len: PIdC_SIZET); cdecl = nil;
  {$EXTERNALSYM CTLOG_get0_log_id}

  CTLOG_get0_public_key: function(log: PCTLOG): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM CTLOG_get0_public_key}

  CTLOG_STORE_new_ex: function(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCTLOG_STORE; cdecl = nil;
  {$EXTERNALSYM CTLOG_STORE_new_ex}

  CTLOG_STORE_new: function: PCTLOG_STORE; cdecl = nil;
  {$EXTERNALSYM CTLOG_STORE_new}

  CTLOG_STORE_free: procedure(store: PCTLOG_STORE); cdecl = nil;
  {$EXTERNALSYM CTLOG_STORE_free}

  CTLOG_STORE_get0_log_by_id: function(store: PCTLOG_STORE; log_id: PIdC_UINT8; log_id_len: TIdC_SIZET): PCTLOG; cdecl = nil;
  {$EXTERNALSYM CTLOG_STORE_get0_log_by_id}

  CTLOG_STORE_load_file: function(store: PCTLOG_STORE; _file: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CTLOG_STORE_load_file}

  CTLOG_STORE_load_default_file: function(store: PCTLOG_STORE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CTLOG_STORE_load_default_file}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function CT_POLICY_EVAL_CTX_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCT_POLICY_EVAL_CTX; cdecl;
function CT_POLICY_EVAL_CTX_new: PCT_POLICY_EVAL_CTX; cdecl;
procedure CT_POLICY_EVAL_CTX_free(ctx: PCT_POLICY_EVAL_CTX); cdecl;
function CT_POLICY_EVAL_CTX_get0_cert(ctx: PCT_POLICY_EVAL_CTX): PX509; cdecl;
function CT_POLICY_EVAL_CTX_set1_cert(ctx: PCT_POLICY_EVAL_CTX; cert: PX509): TIdC_INT; cdecl;
function CT_POLICY_EVAL_CTX_get0_issuer(ctx: PCT_POLICY_EVAL_CTX): PX509; cdecl;
function CT_POLICY_EVAL_CTX_set1_issuer(ctx: PCT_POLICY_EVAL_CTX; issuer: PX509): TIdC_INT; cdecl;
function CT_POLICY_EVAL_CTX_get0_log_store(ctx: PCT_POLICY_EVAL_CTX): PCTLOG_STORE; cdecl;
procedure CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE(ctx: PCT_POLICY_EVAL_CTX; log_store: PCTLOG_STORE); cdecl;
function CT_POLICY_EVAL_CTX_get_time(ctx: PCT_POLICY_EVAL_CTX): TIdC_UINT64; cdecl;
procedure CT_POLICY_EVAL_CTX_set_time(ctx: PCT_POLICY_EVAL_CTX; time_in_ms: TIdC_UINT64); cdecl;
function SCT_new: PSCT; cdecl;
function SCT_new_from_base64(version: TIdC_UINT8; logid_base64: PIdAnsiChar; entry_type: Tct_log_entry_type_t; timestamp: TIdC_UINT64; extensions_base64: PIdAnsiChar; signature_base64: PIdAnsiChar): PSCT; cdecl;
procedure SCT_free(sct: PSCT); cdecl;
procedure SCT_LIST_free(a: Pstack_st_SCT); cdecl;
function SCT_get_version(sct: PSCT): Tsct_version_t; cdecl;
function SCT_set_version(sct: PSCT; version: Tsct_version_t): TIdC_INT; cdecl;
function SCT_get_log_entry_type(sct: PSCT): Tct_log_entry_type_t; cdecl;
function SCT_set_log_entry_type(sct: PSCT; entry_type: Tct_log_entry_type_t): TIdC_INT; cdecl;
function SCT_get0_log_id(sct: PSCT; log_id: PPIdAnsiChar): TIdC_SIZET; cdecl;
function SCT_set0_log_id(sct: PSCT; log_id: PIdAnsiChar; log_id_len: TIdC_SIZET): TIdC_INT; cdecl;
function SCT_set1_log_id(sct: PSCT; log_id: PIdAnsiChar; log_id_len: TIdC_SIZET): TIdC_INT; cdecl;
function SCT_get_timestamp(sct: PSCT): TIdC_UINT64; cdecl;
procedure SCT_set_timestamp(sct: PSCT; timestamp: TIdC_UINT64); cdecl;
function SCT_get_signature_nid(sct: PSCT): TIdC_INT; cdecl;
function SCT_set_signature_nid(sct: PSCT; nid: TIdC_INT): TIdC_INT; cdecl;
function SCT_get0_extensions(sct: PSCT; ext: PPIdAnsiChar): TIdC_SIZET; cdecl;
procedure SCT_set0_extensions(sct: PSCT; ext: PIdAnsiChar; ext_len: TIdC_SIZET); cdecl;
function SCT_set1_extensions(sct: PSCT; ext: PIdAnsiChar; ext_len: TIdC_SIZET): TIdC_INT; cdecl;
function SCT_get0_signature(sct: PSCT; sig: PPIdAnsiChar): TIdC_SIZET; cdecl;
procedure SCT_set0_signature(sct: PSCT; sig: PIdAnsiChar; sig_len: TIdC_SIZET); cdecl;
function SCT_set1_signature(sct: PSCT; sig: PIdAnsiChar; sig_len: TIdC_SIZET): TIdC_INT; cdecl;
function SCT_get_source(sct: PSCT): Tsct_source_t; cdecl;
function SCT_set_source(sct: PSCT; source: Tsct_source_t): TIdC_INT; cdecl;
function SCT_validation_status_string(sct: PSCT): PIdAnsiChar; cdecl;
procedure SCT_print(sct: PSCT; _out: PBIO; indent: TIdC_INT; logs: PCTLOG_STORE); cdecl;
procedure SCT_LIST_print(sct_list: Pstack_st_SCT; _out: PBIO; indent: TIdC_INT; separator: PIdAnsiChar; logs: PCTLOG_STORE); cdecl;
function SCT_get_validation_status(sct: PSCT): Tsct_validation_status_t; cdecl;
function SCT_validate(sct: PSCT; ctx: PCT_POLICY_EVAL_CTX): TIdC_INT; cdecl;
function SCT_LIST_validate(scts: Pstack_st_SCT; ctx: PCT_POLICY_EVAL_CTX): TIdC_INT; cdecl;
function i2o_SCT_LIST(a: Pstack_st_SCT; pp: PPIdAnsiChar): TIdC_INT; cdecl;
function o2i_SCT_LIST(a: PPstack_st_SCT; pp: PPIdAnsiChar; len: TIdC_SIZET): Pstack_st_SCT; cdecl;
function i2d_SCT_LIST(a: Pstack_st_SCT; pp: PPIdAnsiChar): TIdC_INT; cdecl;
function d2i_SCT_LIST(a: PPstack_st_SCT; pp: PPIdAnsiChar; len: TIdC_LONG): Pstack_st_SCT; cdecl;
function i2o_SCT(sct: PSCT; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function o2i_SCT(psct: PPSCT; _in: PPIdAnsiChar; len: TIdC_SIZET): PSCT; cdecl;
function CTLOG_new_ex(public_key: PEVP_PKEY; name: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCTLOG; cdecl;
function CTLOG_new(public_key: PEVP_PKEY; name: PIdAnsiChar): PCTLOG; cdecl;
function CTLOG_new_from_base64_ex(ct_log: PPCTLOG; pkey_base64: PIdAnsiChar; name: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function CTLOG_new_from_base64(ct_log: PPCTLOG; pkey_base64: PIdAnsiChar; name: PIdAnsiChar): TIdC_INT; cdecl;
procedure CTLOG_free(log: PCTLOG); cdecl;
function CTLOG_get0_name(log: PCTLOG): PIdAnsiChar; cdecl;
procedure CTLOG_get0_log_id(log: PCTLOG; log_id: PPIdC_UINT8; log_id_len: PIdC_SIZET); cdecl;
function CTLOG_get0_public_key(log: PCTLOG): PEVP_PKEY; cdecl;
function CTLOG_STORE_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCTLOG_STORE; cdecl;
function CTLOG_STORE_new: PCTLOG_STORE; cdecl;
procedure CTLOG_STORE_free(store: PCTLOG_STORE); cdecl;
function CTLOG_STORE_get0_log_by_id(store: PCTLOG_STORE; log_id: PIdC_UINT8; log_id_len: TIdC_SIZET): PCTLOG; cdecl;
function CTLOG_STORE_load_file(store: PCTLOG_STORE; _file: PIdAnsiChar): TIdC_INT; cdecl;
function CTLOG_STORE_load_default_file(store: PCTLOG_STORE): TIdC_INT; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// OPENSSL STACK DEFINITIONS
// =============================================================================
type
  { TODO 1 -copenssl stack SCT definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_SCT = Pointer;
  {$EXTERNALSYM PSTACK_OF_SCT}

  { Original Stack Macros for SCT:
    SKM_DEFINE_STACK_OF_INTERNAL(SCT, SCT, SCT)
    sk_SCT_num(sk) OPENSSL_sk_num(ossl_check_const_SCT_sk_type(sk))
    sk_SCT_value(sk, idx) ((SCT *)OPENSSL_sk_value(ossl_check_const_SCT_sk_type(sk), (idx)))
    sk_SCT_new(cmp) ((STACK_OF(SCT) *)OPENSSL_sk_new(ossl_check_SCT_compfunc_type(cmp)))
    sk_SCT_new_null() ((STACK_OF(SCT) *)OPENSSL_sk_new_null())
    sk_SCT_new_reserve(cmp, n) ((STACK_OF(SCT) *)OPENSSL_sk_new_reserve(ossl_check_SCT_compfunc_type(cmp), (n)))
    sk_SCT_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_SCT_sk_type(sk), (n))
    sk_SCT_free(sk) OPENSSL_sk_free(ossl_check_SCT_sk_type(sk))
    sk_SCT_zero(sk) OPENSSL_sk_zero(ossl_check_SCT_sk_type(sk))
    sk_SCT_delete(sk, i) ((SCT *)OPENSSL_sk_delete(ossl_check_SCT_sk_type(sk), (i)))
    sk_SCT_delete_ptr(sk, ptr) ((SCT *)OPENSSL_sk_delete_ptr(ossl_check_SCT_sk_type(sk), ossl_check_SCT_type(ptr)))
    sk_SCT_push(sk, ptr) OPENSSL_sk_push(ossl_check_SCT_sk_type(sk), ossl_check_SCT_type(ptr))
    sk_SCT_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_SCT_sk_type(sk), ossl_check_SCT_type(ptr))
    sk_SCT_pop(sk) ((SCT *)OPENSSL_sk_pop(ossl_check_SCT_sk_type(sk)))
    sk_SCT_shift(sk) ((SCT *)OPENSSL_sk_shift(ossl_check_SCT_sk_type(sk)))
    sk_SCT_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_SCT_sk_type(sk), ossl_check_SCT_freefunc_type(freefunc))
    sk_SCT_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_SCT_sk_type(sk), ossl_check_SCT_type(ptr), (idx))
    sk_SCT_set(sk, idx, ptr) ((SCT *)OPENSSL_sk_set(ossl_check_SCT_sk_type(sk), (idx), ossl_check_SCT_type(ptr)))
    sk_SCT_find(sk, ptr) OPENSSL_sk_find(ossl_check_SCT_sk_type(sk), ossl_check_SCT_type(ptr))
    sk_SCT_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_SCT_sk_type(sk), ossl_check_SCT_type(ptr))
    sk_SCT_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_SCT_sk_type(sk), ossl_check_SCT_type(ptr), pnum)
    sk_SCT_sort(sk) OPENSSL_sk_sort(ossl_check_SCT_sk_type(sk))
    sk_SCT_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_SCT_sk_type(sk))
    sk_SCT_dup(sk) ((STACK_OF(SCT) *)OPENSSL_sk_dup(ossl_check_const_SCT_sk_type(sk)))
    sk_SCT_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(SCT) *)OPENSSL_sk_deep_copy(ossl_check_const_SCT_sk_type(sk), ossl_check_SCT_copyfunc_type(copyfunc), ossl_check_SCT_freefunc_type(freefunc)))
    sk_SCT_set_cmp_func(sk, cmp) ((sk_SCT_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_SCT_sk_type(sk), ossl_check_SCT_compfunc_type(cmp)))
  }

  { TODO 1 -copenssl stack CTLOG definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_CTLOG = Pointer;
  {$EXTERNALSYM PSTACK_OF_CTLOG}

  { Original Stack Macros for CTLOG:
    SKM_DEFINE_STACK_OF_INTERNAL(CTLOG, CTLOG, CTLOG)
    sk_CTLOG_num(sk) OPENSSL_sk_num(ossl_check_const_CTLOG_sk_type(sk))
    sk_CTLOG_value(sk, idx) ((CTLOG *)OPENSSL_sk_value(ossl_check_const_CTLOG_sk_type(sk), (idx)))
    sk_CTLOG_new(cmp) ((STACK_OF(CTLOG) *)OPENSSL_sk_new(ossl_check_CTLOG_compfunc_type(cmp)))
    sk_CTLOG_new_null() ((STACK_OF(CTLOG) *)OPENSSL_sk_new_null())
    sk_CTLOG_new_reserve(cmp, n) ((STACK_OF(CTLOG) *)OPENSSL_sk_new_reserve(ossl_check_CTLOG_compfunc_type(cmp), (n)))
    sk_CTLOG_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_CTLOG_sk_type(sk), (n))
    sk_CTLOG_free(sk) OPENSSL_sk_free(ossl_check_CTLOG_sk_type(sk))
    sk_CTLOG_zero(sk) OPENSSL_sk_zero(ossl_check_CTLOG_sk_type(sk))
    sk_CTLOG_delete(sk, i) ((CTLOG *)OPENSSL_sk_delete(ossl_check_CTLOG_sk_type(sk), (i)))
    sk_CTLOG_delete_ptr(sk, ptr) ((CTLOG *)OPENSSL_sk_delete_ptr(ossl_check_CTLOG_sk_type(sk), ossl_check_CTLOG_type(ptr)))
    sk_CTLOG_push(sk, ptr) OPENSSL_sk_push(ossl_check_CTLOG_sk_type(sk), ossl_check_CTLOG_type(ptr))
    sk_CTLOG_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_CTLOG_sk_type(sk), ossl_check_CTLOG_type(ptr))
    sk_CTLOG_pop(sk) ((CTLOG *)OPENSSL_sk_pop(ossl_check_CTLOG_sk_type(sk)))
    sk_CTLOG_shift(sk) ((CTLOG *)OPENSSL_sk_shift(ossl_check_CTLOG_sk_type(sk)))
    sk_CTLOG_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_CTLOG_sk_type(sk), ossl_check_CTLOG_freefunc_type(freefunc))
    sk_CTLOG_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_CTLOG_sk_type(sk), ossl_check_CTLOG_type(ptr), (idx))
    sk_CTLOG_set(sk, idx, ptr) ((CTLOG *)OPENSSL_sk_set(ossl_check_CTLOG_sk_type(sk), (idx), ossl_check_CTLOG_type(ptr)))
    sk_CTLOG_find(sk, ptr) OPENSSL_sk_find(ossl_check_CTLOG_sk_type(sk), ossl_check_CTLOG_type(ptr))
    sk_CTLOG_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_CTLOG_sk_type(sk), ossl_check_CTLOG_type(ptr))
    sk_CTLOG_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_CTLOG_sk_type(sk), ossl_check_CTLOG_type(ptr), pnum)
    sk_CTLOG_sort(sk) OPENSSL_sk_sort(ossl_check_CTLOG_sk_type(sk))
    sk_CTLOG_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_CTLOG_sk_type(sk))
    sk_CTLOG_dup(sk) ((STACK_OF(CTLOG) *)OPENSSL_sk_dup(ossl_check_const_CTLOG_sk_type(sk)))
    sk_CTLOG_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(CTLOG) *)OPENSSL_sk_deep_copy(ossl_check_const_CTLOG_sk_type(sk), ossl_check_CTLOG_copyfunc_type(copyfunc), ossl_check_CTLOG_freefunc_type(freefunc)))
    sk_CTLOG_set_cmp_func(sk, cmp) ((sk_CTLOG_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_CTLOG_sk_type(sk), ossl_check_CTLOG_compfunc_type(cmp)))
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

function CT_POLICY_EVAL_CTX_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCT_POLICY_EVAL_CTX; cdecl external CLibCrypto name 'CT_POLICY_EVAL_CTX_new_ex';
function CT_POLICY_EVAL_CTX_new: PCT_POLICY_EVAL_CTX; cdecl external CLibCrypto name 'CT_POLICY_EVAL_CTX_new';
procedure CT_POLICY_EVAL_CTX_free(ctx: PCT_POLICY_EVAL_CTX); cdecl external CLibCrypto name 'CT_POLICY_EVAL_CTX_free';
function CT_POLICY_EVAL_CTX_get0_cert(ctx: PCT_POLICY_EVAL_CTX): PX509; cdecl external CLibCrypto name 'CT_POLICY_EVAL_CTX_get0_cert';
function CT_POLICY_EVAL_CTX_set1_cert(ctx: PCT_POLICY_EVAL_CTX; cert: PX509): TIdC_INT; cdecl external CLibCrypto name 'CT_POLICY_EVAL_CTX_set1_cert';
function CT_POLICY_EVAL_CTX_get0_issuer(ctx: PCT_POLICY_EVAL_CTX): PX509; cdecl external CLibCrypto name 'CT_POLICY_EVAL_CTX_get0_issuer';
function CT_POLICY_EVAL_CTX_set1_issuer(ctx: PCT_POLICY_EVAL_CTX; issuer: PX509): TIdC_INT; cdecl external CLibCrypto name 'CT_POLICY_EVAL_CTX_set1_issuer';
function CT_POLICY_EVAL_CTX_get0_log_store(ctx: PCT_POLICY_EVAL_CTX): PCTLOG_STORE; cdecl external CLibCrypto name 'CT_POLICY_EVAL_CTX_get0_log_store';
procedure CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE(ctx: PCT_POLICY_EVAL_CTX; log_store: PCTLOG_STORE); cdecl external CLibCrypto name 'CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE';
function CT_POLICY_EVAL_CTX_get_time(ctx: PCT_POLICY_EVAL_CTX): TIdC_UINT64; cdecl external CLibCrypto name 'CT_POLICY_EVAL_CTX_get_time';
procedure CT_POLICY_EVAL_CTX_set_time(ctx: PCT_POLICY_EVAL_CTX; time_in_ms: TIdC_UINT64); cdecl external CLibCrypto name 'CT_POLICY_EVAL_CTX_set_time';
function SCT_new: PSCT; cdecl external CLibCrypto name 'SCT_new';
function SCT_new_from_base64(version: TIdC_UINT8; logid_base64: PIdAnsiChar; entry_type: Tct_log_entry_type_t; timestamp: TIdC_UINT64; extensions_base64: PIdAnsiChar; signature_base64: PIdAnsiChar): PSCT; cdecl external CLibCrypto name 'SCT_new_from_base64';
procedure SCT_free(sct: PSCT); cdecl external CLibCrypto name 'SCT_free';
procedure SCT_LIST_free(a: Pstack_st_SCT); cdecl external CLibCrypto name 'SCT_LIST_free';
function SCT_get_version(sct: PSCT): Tsct_version_t; cdecl external CLibCrypto name 'SCT_get_version';
function SCT_set_version(sct: PSCT; version: Tsct_version_t): TIdC_INT; cdecl external CLibCrypto name 'SCT_set_version';
function SCT_get_log_entry_type(sct: PSCT): Tct_log_entry_type_t; cdecl external CLibCrypto name 'SCT_get_log_entry_type';
function SCT_set_log_entry_type(sct: PSCT; entry_type: Tct_log_entry_type_t): TIdC_INT; cdecl external CLibCrypto name 'SCT_set_log_entry_type';
function SCT_get0_log_id(sct: PSCT; log_id: PPIdAnsiChar): TIdC_SIZET; cdecl external CLibCrypto name 'SCT_get0_log_id';
function SCT_set0_log_id(sct: PSCT; log_id: PIdAnsiChar; log_id_len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'SCT_set0_log_id';
function SCT_set1_log_id(sct: PSCT; log_id: PIdAnsiChar; log_id_len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'SCT_set1_log_id';
function SCT_get_timestamp(sct: PSCT): TIdC_UINT64; cdecl external CLibCrypto name 'SCT_get_timestamp';
procedure SCT_set_timestamp(sct: PSCT; timestamp: TIdC_UINT64); cdecl external CLibCrypto name 'SCT_set_timestamp';
function SCT_get_signature_nid(sct: PSCT): TIdC_INT; cdecl external CLibCrypto name 'SCT_get_signature_nid';
function SCT_set_signature_nid(sct: PSCT; nid: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'SCT_set_signature_nid';
function SCT_get0_extensions(sct: PSCT; ext: PPIdAnsiChar): TIdC_SIZET; cdecl external CLibCrypto name 'SCT_get0_extensions';
procedure SCT_set0_extensions(sct: PSCT; ext: PIdAnsiChar; ext_len: TIdC_SIZET); cdecl external CLibCrypto name 'SCT_set0_extensions';
function SCT_set1_extensions(sct: PSCT; ext: PIdAnsiChar; ext_len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'SCT_set1_extensions';
function SCT_get0_signature(sct: PSCT; sig: PPIdAnsiChar): TIdC_SIZET; cdecl external CLibCrypto name 'SCT_get0_signature';
procedure SCT_set0_signature(sct: PSCT; sig: PIdAnsiChar; sig_len: TIdC_SIZET); cdecl external CLibCrypto name 'SCT_set0_signature';
function SCT_set1_signature(sct: PSCT; sig: PIdAnsiChar; sig_len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'SCT_set1_signature';
function SCT_get_source(sct: PSCT): Tsct_source_t; cdecl external CLibCrypto name 'SCT_get_source';
function SCT_set_source(sct: PSCT; source: Tsct_source_t): TIdC_INT; cdecl external CLibCrypto name 'SCT_set_source';
function SCT_validation_status_string(sct: PSCT): PIdAnsiChar; cdecl external CLibCrypto name 'SCT_validation_status_string';
procedure SCT_print(sct: PSCT; _out: PBIO; indent: TIdC_INT; logs: PCTLOG_STORE); cdecl external CLibCrypto name 'SCT_print';
procedure SCT_LIST_print(sct_list: Pstack_st_SCT; _out: PBIO; indent: TIdC_INT; separator: PIdAnsiChar; logs: PCTLOG_STORE); cdecl external CLibCrypto name 'SCT_LIST_print';
function SCT_get_validation_status(sct: PSCT): Tsct_validation_status_t; cdecl external CLibCrypto name 'SCT_get_validation_status';
function SCT_validate(sct: PSCT; ctx: PCT_POLICY_EVAL_CTX): TIdC_INT; cdecl external CLibCrypto name 'SCT_validate';
function SCT_LIST_validate(scts: Pstack_st_SCT; ctx: PCT_POLICY_EVAL_CTX): TIdC_INT; cdecl external CLibCrypto name 'SCT_LIST_validate';
function i2o_SCT_LIST(a: Pstack_st_SCT; pp: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2o_SCT_LIST';
function o2i_SCT_LIST(a: PPstack_st_SCT; pp: PPIdAnsiChar; len: TIdC_SIZET): Pstack_st_SCT; cdecl external CLibCrypto name 'o2i_SCT_LIST';
function i2d_SCT_LIST(a: Pstack_st_SCT; pp: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_SCT_LIST';
function d2i_SCT_LIST(a: PPstack_st_SCT; pp: PPIdAnsiChar; len: TIdC_LONG): Pstack_st_SCT; cdecl external CLibCrypto name 'd2i_SCT_LIST';
function i2o_SCT(sct: PSCT; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2o_SCT';
function o2i_SCT(psct: PPSCT; _in: PPIdAnsiChar; len: TIdC_SIZET): PSCT; cdecl external CLibCrypto name 'o2i_SCT';
function CTLOG_new_ex(public_key: PEVP_PKEY; name: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCTLOG; cdecl external CLibCrypto name 'CTLOG_new_ex';
function CTLOG_new(public_key: PEVP_PKEY; name: PIdAnsiChar): PCTLOG; cdecl external CLibCrypto name 'CTLOG_new';
function CTLOG_new_from_base64_ex(ct_log: PPCTLOG; pkey_base64: PIdAnsiChar; name: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'CTLOG_new_from_base64_ex';
function CTLOG_new_from_base64(ct_log: PPCTLOG; pkey_base64: PIdAnsiChar; name: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'CTLOG_new_from_base64';
procedure CTLOG_free(log: PCTLOG); cdecl external CLibCrypto name 'CTLOG_free';
function CTLOG_get0_name(log: PCTLOG): PIdAnsiChar; cdecl external CLibCrypto name 'CTLOG_get0_name';
procedure CTLOG_get0_log_id(log: PCTLOG; log_id: PPIdC_UINT8; log_id_len: PIdC_SIZET); cdecl external CLibCrypto name 'CTLOG_get0_log_id';
function CTLOG_get0_public_key(log: PCTLOG): PEVP_PKEY; cdecl external CLibCrypto name 'CTLOG_get0_public_key';
function CTLOG_STORE_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCTLOG_STORE; cdecl external CLibCrypto name 'CTLOG_STORE_new_ex';
function CTLOG_STORE_new: PCTLOG_STORE; cdecl external CLibCrypto name 'CTLOG_STORE_new';
procedure CTLOG_STORE_free(store: PCTLOG_STORE); cdecl external CLibCrypto name 'CTLOG_STORE_free';
function CTLOG_STORE_get0_log_by_id(store: PCTLOG_STORE; log_id: PIdC_UINT8; log_id_len: TIdC_SIZET): PCTLOG; cdecl external CLibCrypto name 'CTLOG_STORE_get0_log_by_id';
function CTLOG_STORE_load_file(store: PCTLOG_STORE; _file: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'CTLOG_STORE_load_file';
function CTLOG_STORE_load_default_file(store: PCTLOG_STORE): TIdC_INT; cdecl external CLibCrypto name 'CTLOG_STORE_load_default_file';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  CT_POLICY_EVAL_CTX_new_ex_procname = 'CT_POLICY_EVAL_CTX_new_ex';
  CT_POLICY_EVAL_CTX_new_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CT_POLICY_EVAL_CTX_new_procname = 'CT_POLICY_EVAL_CTX_new';
  CT_POLICY_EVAL_CTX_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CT_POLICY_EVAL_CTX_free_procname = 'CT_POLICY_EVAL_CTX_free';
  CT_POLICY_EVAL_CTX_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CT_POLICY_EVAL_CTX_get0_cert_procname = 'CT_POLICY_EVAL_CTX_get0_cert';
  CT_POLICY_EVAL_CTX_get0_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CT_POLICY_EVAL_CTX_set1_cert_procname = 'CT_POLICY_EVAL_CTX_set1_cert';
  CT_POLICY_EVAL_CTX_set1_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CT_POLICY_EVAL_CTX_get0_issuer_procname = 'CT_POLICY_EVAL_CTX_get0_issuer';
  CT_POLICY_EVAL_CTX_get0_issuer_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CT_POLICY_EVAL_CTX_set1_issuer_procname = 'CT_POLICY_EVAL_CTX_set1_issuer';
  CT_POLICY_EVAL_CTX_set1_issuer_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CT_POLICY_EVAL_CTX_get0_log_store_procname = 'CT_POLICY_EVAL_CTX_get0_log_store';
  CT_POLICY_EVAL_CTX_get0_log_store_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE_procname = 'CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE';
  CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CT_POLICY_EVAL_CTX_get_time_procname = 'CT_POLICY_EVAL_CTX_get_time';
  CT_POLICY_EVAL_CTX_get_time_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0d);

  CT_POLICY_EVAL_CTX_set_time_procname = 'CT_POLICY_EVAL_CTX_set_time';
  CT_POLICY_EVAL_CTX_set_time_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0d);

  SCT_new_procname = 'SCT_new';
  SCT_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_new_from_base64_procname = 'SCT_new_from_base64';
  SCT_new_from_base64_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_free_procname = 'SCT_free';
  SCT_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_LIST_free_procname = 'SCT_LIST_free';
  SCT_LIST_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_get_version_procname = 'SCT_get_version';
  SCT_get_version_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_set_version_procname = 'SCT_set_version';
  SCT_set_version_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_get_log_entry_type_procname = 'SCT_get_log_entry_type';
  SCT_get_log_entry_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_set_log_entry_type_procname = 'SCT_set_log_entry_type';
  SCT_set_log_entry_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_get0_log_id_procname = 'SCT_get0_log_id';
  SCT_get0_log_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_set0_log_id_procname = 'SCT_set0_log_id';
  SCT_set0_log_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_set1_log_id_procname = 'SCT_set1_log_id';
  SCT_set1_log_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_get_timestamp_procname = 'SCT_get_timestamp';
  SCT_get_timestamp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_set_timestamp_procname = 'SCT_set_timestamp';
  SCT_set_timestamp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_get_signature_nid_procname = 'SCT_get_signature_nid';
  SCT_get_signature_nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_set_signature_nid_procname = 'SCT_set_signature_nid';
  SCT_set_signature_nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_get0_extensions_procname = 'SCT_get0_extensions';
  SCT_get0_extensions_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_set0_extensions_procname = 'SCT_set0_extensions';
  SCT_set0_extensions_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_set1_extensions_procname = 'SCT_set1_extensions';
  SCT_set1_extensions_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_get0_signature_procname = 'SCT_get0_signature';
  SCT_get0_signature_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_set0_signature_procname = 'SCT_set0_signature';
  SCT_set0_signature_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_set1_signature_procname = 'SCT_set1_signature';
  SCT_set1_signature_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_get_source_procname = 'SCT_get_source';
  SCT_get_source_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_set_source_procname = 'SCT_set_source';
  SCT_set_source_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_validation_status_string_procname = 'SCT_validation_status_string';
  SCT_validation_status_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_print_procname = 'SCT_print';
  SCT_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_LIST_print_procname = 'SCT_LIST_print';
  SCT_LIST_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_get_validation_status_procname = 'SCT_get_validation_status';
  SCT_get_validation_status_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_validate_procname = 'SCT_validate';
  SCT_validate_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SCT_LIST_validate_procname = 'SCT_LIST_validate';
  SCT_LIST_validate_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2o_SCT_LIST_procname = 'i2o_SCT_LIST';
  i2o_SCT_LIST_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  o2i_SCT_LIST_procname = 'o2i_SCT_LIST';
  o2i_SCT_LIST_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_SCT_LIST_procname = 'i2d_SCT_LIST';
  i2d_SCT_LIST_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_SCT_LIST_procname = 'd2i_SCT_LIST';
  d2i_SCT_LIST_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2o_SCT_procname = 'i2o_SCT';
  i2o_SCT_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  o2i_SCT_procname = 'o2i_SCT';
  o2i_SCT_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CTLOG_new_ex_procname = 'CTLOG_new_ex';
  CTLOG_new_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CTLOG_new_procname = 'CTLOG_new';
  CTLOG_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CTLOG_new_from_base64_ex_procname = 'CTLOG_new_from_base64_ex';
  CTLOG_new_from_base64_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CTLOG_new_from_base64_procname = 'CTLOG_new_from_base64';
  CTLOG_new_from_base64_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CTLOG_free_procname = 'CTLOG_free';
  CTLOG_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CTLOG_get0_name_procname = 'CTLOG_get0_name';
  CTLOG_get0_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CTLOG_get0_log_id_procname = 'CTLOG_get0_log_id';
  CTLOG_get0_log_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CTLOG_get0_public_key_procname = 'CTLOG_get0_public_key';
  CTLOG_get0_public_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CTLOG_STORE_new_ex_procname = 'CTLOG_STORE_new_ex';
  CTLOG_STORE_new_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CTLOG_STORE_new_procname = 'CTLOG_STORE_new';
  CTLOG_STORE_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CTLOG_STORE_free_procname = 'CTLOG_STORE_free';
  CTLOG_STORE_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CTLOG_STORE_get0_log_by_id_procname = 'CTLOG_STORE_get0_log_by_id';
  CTLOG_STORE_get0_log_by_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CTLOG_STORE_load_file_procname = 'CTLOG_STORE_load_file';
  CTLOG_STORE_load_file_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CTLOG_STORE_load_default_file_procname = 'CTLOG_STORE_load_default_file';
  CTLOG_STORE_load_default_file_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_CT_POLICY_EVAL_CTX_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCT_POLICY_EVAL_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CT_POLICY_EVAL_CTX_new_ex_procname);
end;

function ERR_CT_POLICY_EVAL_CTX_new: PCT_POLICY_EVAL_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CT_POLICY_EVAL_CTX_new_procname);
end;

procedure ERR_CT_POLICY_EVAL_CTX_free(ctx: PCT_POLICY_EVAL_CTX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CT_POLICY_EVAL_CTX_free_procname);
end;

function ERR_CT_POLICY_EVAL_CTX_get0_cert(ctx: PCT_POLICY_EVAL_CTX): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CT_POLICY_EVAL_CTX_get0_cert_procname);
end;

function ERR_CT_POLICY_EVAL_CTX_set1_cert(ctx: PCT_POLICY_EVAL_CTX; cert: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CT_POLICY_EVAL_CTX_set1_cert_procname);
end;

function ERR_CT_POLICY_EVAL_CTX_get0_issuer(ctx: PCT_POLICY_EVAL_CTX): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CT_POLICY_EVAL_CTX_get0_issuer_procname);
end;

function ERR_CT_POLICY_EVAL_CTX_set1_issuer(ctx: PCT_POLICY_EVAL_CTX; issuer: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CT_POLICY_EVAL_CTX_set1_issuer_procname);
end;

function ERR_CT_POLICY_EVAL_CTX_get0_log_store(ctx: PCT_POLICY_EVAL_CTX): PCTLOG_STORE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CT_POLICY_EVAL_CTX_get0_log_store_procname);
end;

procedure ERR_CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE(ctx: PCT_POLICY_EVAL_CTX; log_store: PCTLOG_STORE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE_procname);
end;

function ERR_CT_POLICY_EVAL_CTX_get_time(ctx: PCT_POLICY_EVAL_CTX): TIdC_UINT64; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CT_POLICY_EVAL_CTX_get_time_procname);
end;

procedure ERR_CT_POLICY_EVAL_CTX_set_time(ctx: PCT_POLICY_EVAL_CTX; time_in_ms: TIdC_UINT64); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CT_POLICY_EVAL_CTX_set_time_procname);
end;

function ERR_SCT_new: PSCT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_new_procname);
end;

function ERR_SCT_new_from_base64(version: TIdC_UINT8; logid_base64: PIdAnsiChar; entry_type: Tct_log_entry_type_t; timestamp: TIdC_UINT64; extensions_base64: PIdAnsiChar; signature_base64: PIdAnsiChar): PSCT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_new_from_base64_procname);
end;

procedure ERR_SCT_free(sct: PSCT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_free_procname);
end;

procedure ERR_SCT_LIST_free(a: Pstack_st_SCT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_LIST_free_procname);
end;

function ERR_SCT_get_version(sct: PSCT): Tsct_version_t; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_get_version_procname);
end;

function ERR_SCT_set_version(sct: PSCT; version: Tsct_version_t): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_set_version_procname);
end;

function ERR_SCT_get_log_entry_type(sct: PSCT): Tct_log_entry_type_t; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_get_log_entry_type_procname);
end;

function ERR_SCT_set_log_entry_type(sct: PSCT; entry_type: Tct_log_entry_type_t): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_set_log_entry_type_procname);
end;

function ERR_SCT_get0_log_id(sct: PSCT; log_id: PPIdAnsiChar): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_get0_log_id_procname);
end;

function ERR_SCT_set0_log_id(sct: PSCT; log_id: PIdAnsiChar; log_id_len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_set0_log_id_procname);
end;

function ERR_SCT_set1_log_id(sct: PSCT; log_id: PIdAnsiChar; log_id_len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_set1_log_id_procname);
end;

function ERR_SCT_get_timestamp(sct: PSCT): TIdC_UINT64; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_get_timestamp_procname);
end;

procedure ERR_SCT_set_timestamp(sct: PSCT; timestamp: TIdC_UINT64); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_set_timestamp_procname);
end;

function ERR_SCT_get_signature_nid(sct: PSCT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_get_signature_nid_procname);
end;

function ERR_SCT_set_signature_nid(sct: PSCT; nid: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_set_signature_nid_procname);
end;

function ERR_SCT_get0_extensions(sct: PSCT; ext: PPIdAnsiChar): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_get0_extensions_procname);
end;

procedure ERR_SCT_set0_extensions(sct: PSCT; ext: PIdAnsiChar; ext_len: TIdC_SIZET); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_set0_extensions_procname);
end;

function ERR_SCT_set1_extensions(sct: PSCT; ext: PIdAnsiChar; ext_len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_set1_extensions_procname);
end;

function ERR_SCT_get0_signature(sct: PSCT; sig: PPIdAnsiChar): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_get0_signature_procname);
end;

procedure ERR_SCT_set0_signature(sct: PSCT; sig: PIdAnsiChar; sig_len: TIdC_SIZET); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_set0_signature_procname);
end;

function ERR_SCT_set1_signature(sct: PSCT; sig: PIdAnsiChar; sig_len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_set1_signature_procname);
end;

function ERR_SCT_get_source(sct: PSCT): Tsct_source_t; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_get_source_procname);
end;

function ERR_SCT_set_source(sct: PSCT; source: Tsct_source_t): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_set_source_procname);
end;

function ERR_SCT_validation_status_string(sct: PSCT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_validation_status_string_procname);
end;

procedure ERR_SCT_print(sct: PSCT; _out: PBIO; indent: TIdC_INT; logs: PCTLOG_STORE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_print_procname);
end;

procedure ERR_SCT_LIST_print(sct_list: Pstack_st_SCT; _out: PBIO; indent: TIdC_INT; separator: PIdAnsiChar; logs: PCTLOG_STORE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_LIST_print_procname);
end;

function ERR_SCT_get_validation_status(sct: PSCT): Tsct_validation_status_t; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_get_validation_status_procname);
end;

function ERR_SCT_validate(sct: PSCT; ctx: PCT_POLICY_EVAL_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_validate_procname);
end;

function ERR_SCT_LIST_validate(scts: Pstack_st_SCT; ctx: PCT_POLICY_EVAL_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCT_LIST_validate_procname);
end;

function ERR_i2o_SCT_LIST(a: Pstack_st_SCT; pp: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2o_SCT_LIST_procname);
end;

function ERR_o2i_SCT_LIST(a: PPstack_st_SCT; pp: PPIdAnsiChar; len: TIdC_SIZET): Pstack_st_SCT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(o2i_SCT_LIST_procname);
end;

function ERR_i2d_SCT_LIST(a: Pstack_st_SCT; pp: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_SCT_LIST_procname);
end;

function ERR_d2i_SCT_LIST(a: PPstack_st_SCT; pp: PPIdAnsiChar; len: TIdC_LONG): Pstack_st_SCT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_SCT_LIST_procname);
end;

function ERR_i2o_SCT(sct: PSCT; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2o_SCT_procname);
end;

function ERR_o2i_SCT(psct: PPSCT; _in: PPIdAnsiChar; len: TIdC_SIZET): PSCT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(o2i_SCT_procname);
end;

function ERR_CTLOG_new_ex(public_key: PEVP_PKEY; name: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCTLOG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CTLOG_new_ex_procname);
end;

function ERR_CTLOG_new(public_key: PEVP_PKEY; name: PIdAnsiChar): PCTLOG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CTLOG_new_procname);
end;

function ERR_CTLOG_new_from_base64_ex(ct_log: PPCTLOG; pkey_base64: PIdAnsiChar; name: PIdAnsiChar; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CTLOG_new_from_base64_ex_procname);
end;

function ERR_CTLOG_new_from_base64(ct_log: PPCTLOG; pkey_base64: PIdAnsiChar; name: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CTLOG_new_from_base64_procname);
end;

procedure ERR_CTLOG_free(log: PCTLOG); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CTLOG_free_procname);
end;

function ERR_CTLOG_get0_name(log: PCTLOG): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CTLOG_get0_name_procname);
end;

procedure ERR_CTLOG_get0_log_id(log: PCTLOG; log_id: PPIdC_UINT8; log_id_len: PIdC_SIZET); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CTLOG_get0_log_id_procname);
end;

function ERR_CTLOG_get0_public_key(log: PCTLOG): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CTLOG_get0_public_key_procname);
end;

function ERR_CTLOG_STORE_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCTLOG_STORE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CTLOG_STORE_new_ex_procname);
end;

function ERR_CTLOG_STORE_new: PCTLOG_STORE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CTLOG_STORE_new_procname);
end;

procedure ERR_CTLOG_STORE_free(store: PCTLOG_STORE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CTLOG_STORE_free_procname);
end;

function ERR_CTLOG_STORE_get0_log_by_id(store: PCTLOG_STORE; log_id: PIdC_UINT8; log_id_len: TIdC_SIZET): PCTLOG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CTLOG_STORE_get0_log_by_id_procname);
end;

function ERR_CTLOG_STORE_load_file(store: PCTLOG_STORE; _file: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CTLOG_STORE_load_file_procname);
end;

function ERR_CTLOG_STORE_load_default_file(store: PCTLOG_STORE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CTLOG_STORE_load_default_file_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  CT_POLICY_EVAL_CTX_new_ex := LoadLibFunction(ADllHandle, CT_POLICY_EVAL_CTX_new_ex_procname);
  FuncLoadError := not assigned(CT_POLICY_EVAL_CTX_new_ex);
  if FuncLoadError then
  begin
    {$if not defined(CT_POLICY_EVAL_CTX_new_ex_allownil)}
    CT_POLICY_EVAL_CTX_new_ex := ERR_CT_POLICY_EVAL_CTX_new_ex;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_new_ex_introduced)}
    if LibVersion < CT_POLICY_EVAL_CTX_new_ex_introduced then
    begin
      {$if declared(FC_CT_POLICY_EVAL_CTX_new_ex)}
      CT_POLICY_EVAL_CTX_new_ex := FC_CT_POLICY_EVAL_CTX_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_new_ex_removed)}
    if CT_POLICY_EVAL_CTX_new_ex_removed <= LibVersion then
    begin
      {$if declared(_CT_POLICY_EVAL_CTX_new_ex)}
      CT_POLICY_EVAL_CTX_new_ex := _CT_POLICY_EVAL_CTX_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CT_POLICY_EVAL_CTX_new_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('CT_POLICY_EVAL_CTX_new_ex');
    {$ifend}
  end;
  
  CT_POLICY_EVAL_CTX_new := LoadLibFunction(ADllHandle, CT_POLICY_EVAL_CTX_new_procname);
  FuncLoadError := not assigned(CT_POLICY_EVAL_CTX_new);
  if FuncLoadError then
  begin
    {$if not defined(CT_POLICY_EVAL_CTX_new_allownil)}
    CT_POLICY_EVAL_CTX_new := ERR_CT_POLICY_EVAL_CTX_new;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_new_introduced)}
    if LibVersion < CT_POLICY_EVAL_CTX_new_introduced then
    begin
      {$if declared(FC_CT_POLICY_EVAL_CTX_new)}
      CT_POLICY_EVAL_CTX_new := FC_CT_POLICY_EVAL_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_new_removed)}
    if CT_POLICY_EVAL_CTX_new_removed <= LibVersion then
    begin
      {$if declared(_CT_POLICY_EVAL_CTX_new)}
      CT_POLICY_EVAL_CTX_new := _CT_POLICY_EVAL_CTX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CT_POLICY_EVAL_CTX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('CT_POLICY_EVAL_CTX_new');
    {$ifend}
  end;
  
  CT_POLICY_EVAL_CTX_free := LoadLibFunction(ADllHandle, CT_POLICY_EVAL_CTX_free_procname);
  FuncLoadError := not assigned(CT_POLICY_EVAL_CTX_free);
  if FuncLoadError then
  begin
    {$if not defined(CT_POLICY_EVAL_CTX_free_allownil)}
    CT_POLICY_EVAL_CTX_free := ERR_CT_POLICY_EVAL_CTX_free;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_free_introduced)}
    if LibVersion < CT_POLICY_EVAL_CTX_free_introduced then
    begin
      {$if declared(FC_CT_POLICY_EVAL_CTX_free)}
      CT_POLICY_EVAL_CTX_free := FC_CT_POLICY_EVAL_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_free_removed)}
    if CT_POLICY_EVAL_CTX_free_removed <= LibVersion then
    begin
      {$if declared(_CT_POLICY_EVAL_CTX_free)}
      CT_POLICY_EVAL_CTX_free := _CT_POLICY_EVAL_CTX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CT_POLICY_EVAL_CTX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('CT_POLICY_EVAL_CTX_free');
    {$ifend}
  end;
  
  CT_POLICY_EVAL_CTX_get0_cert := LoadLibFunction(ADllHandle, CT_POLICY_EVAL_CTX_get0_cert_procname);
  FuncLoadError := not assigned(CT_POLICY_EVAL_CTX_get0_cert);
  if FuncLoadError then
  begin
    {$if not defined(CT_POLICY_EVAL_CTX_get0_cert_allownil)}
    CT_POLICY_EVAL_CTX_get0_cert := ERR_CT_POLICY_EVAL_CTX_get0_cert;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_get0_cert_introduced)}
    if LibVersion < CT_POLICY_EVAL_CTX_get0_cert_introduced then
    begin
      {$if declared(FC_CT_POLICY_EVAL_CTX_get0_cert)}
      CT_POLICY_EVAL_CTX_get0_cert := FC_CT_POLICY_EVAL_CTX_get0_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_get0_cert_removed)}
    if CT_POLICY_EVAL_CTX_get0_cert_removed <= LibVersion then
    begin
      {$if declared(_CT_POLICY_EVAL_CTX_get0_cert)}
      CT_POLICY_EVAL_CTX_get0_cert := _CT_POLICY_EVAL_CTX_get0_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CT_POLICY_EVAL_CTX_get0_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('CT_POLICY_EVAL_CTX_get0_cert');
    {$ifend}
  end;
  
  CT_POLICY_EVAL_CTX_set1_cert := LoadLibFunction(ADllHandle, CT_POLICY_EVAL_CTX_set1_cert_procname);
  FuncLoadError := not assigned(CT_POLICY_EVAL_CTX_set1_cert);
  if FuncLoadError then
  begin
    {$if not defined(CT_POLICY_EVAL_CTX_set1_cert_allownil)}
    CT_POLICY_EVAL_CTX_set1_cert := ERR_CT_POLICY_EVAL_CTX_set1_cert;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_set1_cert_introduced)}
    if LibVersion < CT_POLICY_EVAL_CTX_set1_cert_introduced then
    begin
      {$if declared(FC_CT_POLICY_EVAL_CTX_set1_cert)}
      CT_POLICY_EVAL_CTX_set1_cert := FC_CT_POLICY_EVAL_CTX_set1_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_set1_cert_removed)}
    if CT_POLICY_EVAL_CTX_set1_cert_removed <= LibVersion then
    begin
      {$if declared(_CT_POLICY_EVAL_CTX_set1_cert)}
      CT_POLICY_EVAL_CTX_set1_cert := _CT_POLICY_EVAL_CTX_set1_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CT_POLICY_EVAL_CTX_set1_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('CT_POLICY_EVAL_CTX_set1_cert');
    {$ifend}
  end;
  
  CT_POLICY_EVAL_CTX_get0_issuer := LoadLibFunction(ADllHandle, CT_POLICY_EVAL_CTX_get0_issuer_procname);
  FuncLoadError := not assigned(CT_POLICY_EVAL_CTX_get0_issuer);
  if FuncLoadError then
  begin
    {$if not defined(CT_POLICY_EVAL_CTX_get0_issuer_allownil)}
    CT_POLICY_EVAL_CTX_get0_issuer := ERR_CT_POLICY_EVAL_CTX_get0_issuer;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_get0_issuer_introduced)}
    if LibVersion < CT_POLICY_EVAL_CTX_get0_issuer_introduced then
    begin
      {$if declared(FC_CT_POLICY_EVAL_CTX_get0_issuer)}
      CT_POLICY_EVAL_CTX_get0_issuer := FC_CT_POLICY_EVAL_CTX_get0_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_get0_issuer_removed)}
    if CT_POLICY_EVAL_CTX_get0_issuer_removed <= LibVersion then
    begin
      {$if declared(_CT_POLICY_EVAL_CTX_get0_issuer)}
      CT_POLICY_EVAL_CTX_get0_issuer := _CT_POLICY_EVAL_CTX_get0_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CT_POLICY_EVAL_CTX_get0_issuer_allownil)}
    if FuncLoadError then
      AFailed.Add('CT_POLICY_EVAL_CTX_get0_issuer');
    {$ifend}
  end;
  
  CT_POLICY_EVAL_CTX_set1_issuer := LoadLibFunction(ADllHandle, CT_POLICY_EVAL_CTX_set1_issuer_procname);
  FuncLoadError := not assigned(CT_POLICY_EVAL_CTX_set1_issuer);
  if FuncLoadError then
  begin
    {$if not defined(CT_POLICY_EVAL_CTX_set1_issuer_allownil)}
    CT_POLICY_EVAL_CTX_set1_issuer := ERR_CT_POLICY_EVAL_CTX_set1_issuer;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_set1_issuer_introduced)}
    if LibVersion < CT_POLICY_EVAL_CTX_set1_issuer_introduced then
    begin
      {$if declared(FC_CT_POLICY_EVAL_CTX_set1_issuer)}
      CT_POLICY_EVAL_CTX_set1_issuer := FC_CT_POLICY_EVAL_CTX_set1_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_set1_issuer_removed)}
    if CT_POLICY_EVAL_CTX_set1_issuer_removed <= LibVersion then
    begin
      {$if declared(_CT_POLICY_EVAL_CTX_set1_issuer)}
      CT_POLICY_EVAL_CTX_set1_issuer := _CT_POLICY_EVAL_CTX_set1_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CT_POLICY_EVAL_CTX_set1_issuer_allownil)}
    if FuncLoadError then
      AFailed.Add('CT_POLICY_EVAL_CTX_set1_issuer');
    {$ifend}
  end;
  
  CT_POLICY_EVAL_CTX_get0_log_store := LoadLibFunction(ADllHandle, CT_POLICY_EVAL_CTX_get0_log_store_procname);
  FuncLoadError := not assigned(CT_POLICY_EVAL_CTX_get0_log_store);
  if FuncLoadError then
  begin
    {$if not defined(CT_POLICY_EVAL_CTX_get0_log_store_allownil)}
    CT_POLICY_EVAL_CTX_get0_log_store := ERR_CT_POLICY_EVAL_CTX_get0_log_store;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_get0_log_store_introduced)}
    if LibVersion < CT_POLICY_EVAL_CTX_get0_log_store_introduced then
    begin
      {$if declared(FC_CT_POLICY_EVAL_CTX_get0_log_store)}
      CT_POLICY_EVAL_CTX_get0_log_store := FC_CT_POLICY_EVAL_CTX_get0_log_store;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_get0_log_store_removed)}
    if CT_POLICY_EVAL_CTX_get0_log_store_removed <= LibVersion then
    begin
      {$if declared(_CT_POLICY_EVAL_CTX_get0_log_store)}
      CT_POLICY_EVAL_CTX_get0_log_store := _CT_POLICY_EVAL_CTX_get0_log_store;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CT_POLICY_EVAL_CTX_get0_log_store_allownil)}
    if FuncLoadError then
      AFailed.Add('CT_POLICY_EVAL_CTX_get0_log_store');
    {$ifend}
  end;
  
  CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE := LoadLibFunction(ADllHandle, CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE_procname);
  FuncLoadError := not assigned(CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE);
  if FuncLoadError then
  begin
    {$if not defined(CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE_allownil)}
    CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE := ERR_CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE_introduced)}
    if LibVersion < CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE_introduced then
    begin
      {$if declared(FC_CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE)}
      CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE := FC_CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE_removed)}
    if CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE_removed <= LibVersion then
    begin
      {$if declared(_CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE)}
      CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE := _CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE_allownil)}
    if FuncLoadError then
      AFailed.Add('CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE');
    {$ifend}
  end;
  
  CT_POLICY_EVAL_CTX_get_time := LoadLibFunction(ADllHandle, CT_POLICY_EVAL_CTX_get_time_procname);
  FuncLoadError := not assigned(CT_POLICY_EVAL_CTX_get_time);
  if FuncLoadError then
  begin
    {$if not defined(CT_POLICY_EVAL_CTX_get_time_allownil)}
    CT_POLICY_EVAL_CTX_get_time := ERR_CT_POLICY_EVAL_CTX_get_time;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_get_time_introduced)}
    if LibVersion < CT_POLICY_EVAL_CTX_get_time_introduced then
    begin
      {$if declared(FC_CT_POLICY_EVAL_CTX_get_time)}
      CT_POLICY_EVAL_CTX_get_time := FC_CT_POLICY_EVAL_CTX_get_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_get_time_removed)}
    if CT_POLICY_EVAL_CTX_get_time_removed <= LibVersion then
    begin
      {$if declared(_CT_POLICY_EVAL_CTX_get_time)}
      CT_POLICY_EVAL_CTX_get_time := _CT_POLICY_EVAL_CTX_get_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CT_POLICY_EVAL_CTX_get_time_allownil)}
    if FuncLoadError then
      AFailed.Add('CT_POLICY_EVAL_CTX_get_time');
    {$ifend}
  end;
  
  CT_POLICY_EVAL_CTX_set_time := LoadLibFunction(ADllHandle, CT_POLICY_EVAL_CTX_set_time_procname);
  FuncLoadError := not assigned(CT_POLICY_EVAL_CTX_set_time);
  if FuncLoadError then
  begin
    {$if not defined(CT_POLICY_EVAL_CTX_set_time_allownil)}
    CT_POLICY_EVAL_CTX_set_time := ERR_CT_POLICY_EVAL_CTX_set_time;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_set_time_introduced)}
    if LibVersion < CT_POLICY_EVAL_CTX_set_time_introduced then
    begin
      {$if declared(FC_CT_POLICY_EVAL_CTX_set_time)}
      CT_POLICY_EVAL_CTX_set_time := FC_CT_POLICY_EVAL_CTX_set_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CT_POLICY_EVAL_CTX_set_time_removed)}
    if CT_POLICY_EVAL_CTX_set_time_removed <= LibVersion then
    begin
      {$if declared(_CT_POLICY_EVAL_CTX_set_time)}
      CT_POLICY_EVAL_CTX_set_time := _CT_POLICY_EVAL_CTX_set_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CT_POLICY_EVAL_CTX_set_time_allownil)}
    if FuncLoadError then
      AFailed.Add('CT_POLICY_EVAL_CTX_set_time');
    {$ifend}
  end;
  
  SCT_new := LoadLibFunction(ADllHandle, SCT_new_procname);
  FuncLoadError := not assigned(SCT_new);
  if FuncLoadError then
  begin
    {$if not defined(SCT_new_allownil)}
    SCT_new := ERR_SCT_new;
    {$ifend}
    {$if declared(SCT_new_introduced)}
    if LibVersion < SCT_new_introduced then
    begin
      {$if declared(FC_SCT_new)}
      SCT_new := FC_SCT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_new_removed)}
    if SCT_new_removed <= LibVersion then
    begin
      {$if declared(_SCT_new)}
      SCT_new := _SCT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_new_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_new');
    {$ifend}
  end;
  
  SCT_new_from_base64 := LoadLibFunction(ADllHandle, SCT_new_from_base64_procname);
  FuncLoadError := not assigned(SCT_new_from_base64);
  if FuncLoadError then
  begin
    {$if not defined(SCT_new_from_base64_allownil)}
    SCT_new_from_base64 := ERR_SCT_new_from_base64;
    {$ifend}
    {$if declared(SCT_new_from_base64_introduced)}
    if LibVersion < SCT_new_from_base64_introduced then
    begin
      {$if declared(FC_SCT_new_from_base64)}
      SCT_new_from_base64 := FC_SCT_new_from_base64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_new_from_base64_removed)}
    if SCT_new_from_base64_removed <= LibVersion then
    begin
      {$if declared(_SCT_new_from_base64)}
      SCT_new_from_base64 := _SCT_new_from_base64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_new_from_base64_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_new_from_base64');
    {$ifend}
  end;
  
  SCT_free := LoadLibFunction(ADllHandle, SCT_free_procname);
  FuncLoadError := not assigned(SCT_free);
  if FuncLoadError then
  begin
    {$if not defined(SCT_free_allownil)}
    SCT_free := ERR_SCT_free;
    {$ifend}
    {$if declared(SCT_free_introduced)}
    if LibVersion < SCT_free_introduced then
    begin
      {$if declared(FC_SCT_free)}
      SCT_free := FC_SCT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_free_removed)}
    if SCT_free_removed <= LibVersion then
    begin
      {$if declared(_SCT_free)}
      SCT_free := _SCT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_free_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_free');
    {$ifend}
  end;
  
  SCT_LIST_free := LoadLibFunction(ADllHandle, SCT_LIST_free_procname);
  FuncLoadError := not assigned(SCT_LIST_free);
  if FuncLoadError then
  begin
    {$if not defined(SCT_LIST_free_allownil)}
    SCT_LIST_free := ERR_SCT_LIST_free;
    {$ifend}
    {$if declared(SCT_LIST_free_introduced)}
    if LibVersion < SCT_LIST_free_introduced then
    begin
      {$if declared(FC_SCT_LIST_free)}
      SCT_LIST_free := FC_SCT_LIST_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_LIST_free_removed)}
    if SCT_LIST_free_removed <= LibVersion then
    begin
      {$if declared(_SCT_LIST_free)}
      SCT_LIST_free := _SCT_LIST_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_LIST_free_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_LIST_free');
    {$ifend}
  end;
  
  SCT_get_version := LoadLibFunction(ADllHandle, SCT_get_version_procname);
  FuncLoadError := not assigned(SCT_get_version);
  if FuncLoadError then
  begin
    {$if not defined(SCT_get_version_allownil)}
    SCT_get_version := ERR_SCT_get_version;
    {$ifend}
    {$if declared(SCT_get_version_introduced)}
    if LibVersion < SCT_get_version_introduced then
    begin
      {$if declared(FC_SCT_get_version)}
      SCT_get_version := FC_SCT_get_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_get_version_removed)}
    if SCT_get_version_removed <= LibVersion then
    begin
      {$if declared(_SCT_get_version)}
      SCT_get_version := _SCT_get_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_get_version_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_get_version');
    {$ifend}
  end;
  
  SCT_set_version := LoadLibFunction(ADllHandle, SCT_set_version_procname);
  FuncLoadError := not assigned(SCT_set_version);
  if FuncLoadError then
  begin
    {$if not defined(SCT_set_version_allownil)}
    SCT_set_version := ERR_SCT_set_version;
    {$ifend}
    {$if declared(SCT_set_version_introduced)}
    if LibVersion < SCT_set_version_introduced then
    begin
      {$if declared(FC_SCT_set_version)}
      SCT_set_version := FC_SCT_set_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_set_version_removed)}
    if SCT_set_version_removed <= LibVersion then
    begin
      {$if declared(_SCT_set_version)}
      SCT_set_version := _SCT_set_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_set_version_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_set_version');
    {$ifend}
  end;
  
  SCT_get_log_entry_type := LoadLibFunction(ADllHandle, SCT_get_log_entry_type_procname);
  FuncLoadError := not assigned(SCT_get_log_entry_type);
  if FuncLoadError then
  begin
    {$if not defined(SCT_get_log_entry_type_allownil)}
    SCT_get_log_entry_type := ERR_SCT_get_log_entry_type;
    {$ifend}
    {$if declared(SCT_get_log_entry_type_introduced)}
    if LibVersion < SCT_get_log_entry_type_introduced then
    begin
      {$if declared(FC_SCT_get_log_entry_type)}
      SCT_get_log_entry_type := FC_SCT_get_log_entry_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_get_log_entry_type_removed)}
    if SCT_get_log_entry_type_removed <= LibVersion then
    begin
      {$if declared(_SCT_get_log_entry_type)}
      SCT_get_log_entry_type := _SCT_get_log_entry_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_get_log_entry_type_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_get_log_entry_type');
    {$ifend}
  end;
  
  SCT_set_log_entry_type := LoadLibFunction(ADllHandle, SCT_set_log_entry_type_procname);
  FuncLoadError := not assigned(SCT_set_log_entry_type);
  if FuncLoadError then
  begin
    {$if not defined(SCT_set_log_entry_type_allownil)}
    SCT_set_log_entry_type := ERR_SCT_set_log_entry_type;
    {$ifend}
    {$if declared(SCT_set_log_entry_type_introduced)}
    if LibVersion < SCT_set_log_entry_type_introduced then
    begin
      {$if declared(FC_SCT_set_log_entry_type)}
      SCT_set_log_entry_type := FC_SCT_set_log_entry_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_set_log_entry_type_removed)}
    if SCT_set_log_entry_type_removed <= LibVersion then
    begin
      {$if declared(_SCT_set_log_entry_type)}
      SCT_set_log_entry_type := _SCT_set_log_entry_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_set_log_entry_type_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_set_log_entry_type');
    {$ifend}
  end;
  
  SCT_get0_log_id := LoadLibFunction(ADllHandle, SCT_get0_log_id_procname);
  FuncLoadError := not assigned(SCT_get0_log_id);
  if FuncLoadError then
  begin
    {$if not defined(SCT_get0_log_id_allownil)}
    SCT_get0_log_id := ERR_SCT_get0_log_id;
    {$ifend}
    {$if declared(SCT_get0_log_id_introduced)}
    if LibVersion < SCT_get0_log_id_introduced then
    begin
      {$if declared(FC_SCT_get0_log_id)}
      SCT_get0_log_id := FC_SCT_get0_log_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_get0_log_id_removed)}
    if SCT_get0_log_id_removed <= LibVersion then
    begin
      {$if declared(_SCT_get0_log_id)}
      SCT_get0_log_id := _SCT_get0_log_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_get0_log_id_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_get0_log_id');
    {$ifend}
  end;
  
  SCT_set0_log_id := LoadLibFunction(ADllHandle, SCT_set0_log_id_procname);
  FuncLoadError := not assigned(SCT_set0_log_id);
  if FuncLoadError then
  begin
    {$if not defined(SCT_set0_log_id_allownil)}
    SCT_set0_log_id := ERR_SCT_set0_log_id;
    {$ifend}
    {$if declared(SCT_set0_log_id_introduced)}
    if LibVersion < SCT_set0_log_id_introduced then
    begin
      {$if declared(FC_SCT_set0_log_id)}
      SCT_set0_log_id := FC_SCT_set0_log_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_set0_log_id_removed)}
    if SCT_set0_log_id_removed <= LibVersion then
    begin
      {$if declared(_SCT_set0_log_id)}
      SCT_set0_log_id := _SCT_set0_log_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_set0_log_id_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_set0_log_id');
    {$ifend}
  end;
  
  SCT_set1_log_id := LoadLibFunction(ADllHandle, SCT_set1_log_id_procname);
  FuncLoadError := not assigned(SCT_set1_log_id);
  if FuncLoadError then
  begin
    {$if not defined(SCT_set1_log_id_allownil)}
    SCT_set1_log_id := ERR_SCT_set1_log_id;
    {$ifend}
    {$if declared(SCT_set1_log_id_introduced)}
    if LibVersion < SCT_set1_log_id_introduced then
    begin
      {$if declared(FC_SCT_set1_log_id)}
      SCT_set1_log_id := FC_SCT_set1_log_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_set1_log_id_removed)}
    if SCT_set1_log_id_removed <= LibVersion then
    begin
      {$if declared(_SCT_set1_log_id)}
      SCT_set1_log_id := _SCT_set1_log_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_set1_log_id_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_set1_log_id');
    {$ifend}
  end;
  
  SCT_get_timestamp := LoadLibFunction(ADllHandle, SCT_get_timestamp_procname);
  FuncLoadError := not assigned(SCT_get_timestamp);
  if FuncLoadError then
  begin
    {$if not defined(SCT_get_timestamp_allownil)}
    SCT_get_timestamp := ERR_SCT_get_timestamp;
    {$ifend}
    {$if declared(SCT_get_timestamp_introduced)}
    if LibVersion < SCT_get_timestamp_introduced then
    begin
      {$if declared(FC_SCT_get_timestamp)}
      SCT_get_timestamp := FC_SCT_get_timestamp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_get_timestamp_removed)}
    if SCT_get_timestamp_removed <= LibVersion then
    begin
      {$if declared(_SCT_get_timestamp)}
      SCT_get_timestamp := _SCT_get_timestamp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_get_timestamp_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_get_timestamp');
    {$ifend}
  end;
  
  SCT_set_timestamp := LoadLibFunction(ADllHandle, SCT_set_timestamp_procname);
  FuncLoadError := not assigned(SCT_set_timestamp);
  if FuncLoadError then
  begin
    {$if not defined(SCT_set_timestamp_allownil)}
    SCT_set_timestamp := ERR_SCT_set_timestamp;
    {$ifend}
    {$if declared(SCT_set_timestamp_introduced)}
    if LibVersion < SCT_set_timestamp_introduced then
    begin
      {$if declared(FC_SCT_set_timestamp)}
      SCT_set_timestamp := FC_SCT_set_timestamp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_set_timestamp_removed)}
    if SCT_set_timestamp_removed <= LibVersion then
    begin
      {$if declared(_SCT_set_timestamp)}
      SCT_set_timestamp := _SCT_set_timestamp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_set_timestamp_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_set_timestamp');
    {$ifend}
  end;
  
  SCT_get_signature_nid := LoadLibFunction(ADllHandle, SCT_get_signature_nid_procname);
  FuncLoadError := not assigned(SCT_get_signature_nid);
  if FuncLoadError then
  begin
    {$if not defined(SCT_get_signature_nid_allownil)}
    SCT_get_signature_nid := ERR_SCT_get_signature_nid;
    {$ifend}
    {$if declared(SCT_get_signature_nid_introduced)}
    if LibVersion < SCT_get_signature_nid_introduced then
    begin
      {$if declared(FC_SCT_get_signature_nid)}
      SCT_get_signature_nid := FC_SCT_get_signature_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_get_signature_nid_removed)}
    if SCT_get_signature_nid_removed <= LibVersion then
    begin
      {$if declared(_SCT_get_signature_nid)}
      SCT_get_signature_nid := _SCT_get_signature_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_get_signature_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_get_signature_nid');
    {$ifend}
  end;
  
  SCT_set_signature_nid := LoadLibFunction(ADllHandle, SCT_set_signature_nid_procname);
  FuncLoadError := not assigned(SCT_set_signature_nid);
  if FuncLoadError then
  begin
    {$if not defined(SCT_set_signature_nid_allownil)}
    SCT_set_signature_nid := ERR_SCT_set_signature_nid;
    {$ifend}
    {$if declared(SCT_set_signature_nid_introduced)}
    if LibVersion < SCT_set_signature_nid_introduced then
    begin
      {$if declared(FC_SCT_set_signature_nid)}
      SCT_set_signature_nid := FC_SCT_set_signature_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_set_signature_nid_removed)}
    if SCT_set_signature_nid_removed <= LibVersion then
    begin
      {$if declared(_SCT_set_signature_nid)}
      SCT_set_signature_nid := _SCT_set_signature_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_set_signature_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_set_signature_nid');
    {$ifend}
  end;
  
  SCT_get0_extensions := LoadLibFunction(ADllHandle, SCT_get0_extensions_procname);
  FuncLoadError := not assigned(SCT_get0_extensions);
  if FuncLoadError then
  begin
    {$if not defined(SCT_get0_extensions_allownil)}
    SCT_get0_extensions := ERR_SCT_get0_extensions;
    {$ifend}
    {$if declared(SCT_get0_extensions_introduced)}
    if LibVersion < SCT_get0_extensions_introduced then
    begin
      {$if declared(FC_SCT_get0_extensions)}
      SCT_get0_extensions := FC_SCT_get0_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_get0_extensions_removed)}
    if SCT_get0_extensions_removed <= LibVersion then
    begin
      {$if declared(_SCT_get0_extensions)}
      SCT_get0_extensions := _SCT_get0_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_get0_extensions_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_get0_extensions');
    {$ifend}
  end;
  
  SCT_set0_extensions := LoadLibFunction(ADllHandle, SCT_set0_extensions_procname);
  FuncLoadError := not assigned(SCT_set0_extensions);
  if FuncLoadError then
  begin
    {$if not defined(SCT_set0_extensions_allownil)}
    SCT_set0_extensions := ERR_SCT_set0_extensions;
    {$ifend}
    {$if declared(SCT_set0_extensions_introduced)}
    if LibVersion < SCT_set0_extensions_introduced then
    begin
      {$if declared(FC_SCT_set0_extensions)}
      SCT_set0_extensions := FC_SCT_set0_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_set0_extensions_removed)}
    if SCT_set0_extensions_removed <= LibVersion then
    begin
      {$if declared(_SCT_set0_extensions)}
      SCT_set0_extensions := _SCT_set0_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_set0_extensions_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_set0_extensions');
    {$ifend}
  end;
  
  SCT_set1_extensions := LoadLibFunction(ADllHandle, SCT_set1_extensions_procname);
  FuncLoadError := not assigned(SCT_set1_extensions);
  if FuncLoadError then
  begin
    {$if not defined(SCT_set1_extensions_allownil)}
    SCT_set1_extensions := ERR_SCT_set1_extensions;
    {$ifend}
    {$if declared(SCT_set1_extensions_introduced)}
    if LibVersion < SCT_set1_extensions_introduced then
    begin
      {$if declared(FC_SCT_set1_extensions)}
      SCT_set1_extensions := FC_SCT_set1_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_set1_extensions_removed)}
    if SCT_set1_extensions_removed <= LibVersion then
    begin
      {$if declared(_SCT_set1_extensions)}
      SCT_set1_extensions := _SCT_set1_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_set1_extensions_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_set1_extensions');
    {$ifend}
  end;
  
  SCT_get0_signature := LoadLibFunction(ADllHandle, SCT_get0_signature_procname);
  FuncLoadError := not assigned(SCT_get0_signature);
  if FuncLoadError then
  begin
    {$if not defined(SCT_get0_signature_allownil)}
    SCT_get0_signature := ERR_SCT_get0_signature;
    {$ifend}
    {$if declared(SCT_get0_signature_introduced)}
    if LibVersion < SCT_get0_signature_introduced then
    begin
      {$if declared(FC_SCT_get0_signature)}
      SCT_get0_signature := FC_SCT_get0_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_get0_signature_removed)}
    if SCT_get0_signature_removed <= LibVersion then
    begin
      {$if declared(_SCT_get0_signature)}
      SCT_get0_signature := _SCT_get0_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_get0_signature_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_get0_signature');
    {$ifend}
  end;
  
  SCT_set0_signature := LoadLibFunction(ADllHandle, SCT_set0_signature_procname);
  FuncLoadError := not assigned(SCT_set0_signature);
  if FuncLoadError then
  begin
    {$if not defined(SCT_set0_signature_allownil)}
    SCT_set0_signature := ERR_SCT_set0_signature;
    {$ifend}
    {$if declared(SCT_set0_signature_introduced)}
    if LibVersion < SCT_set0_signature_introduced then
    begin
      {$if declared(FC_SCT_set0_signature)}
      SCT_set0_signature := FC_SCT_set0_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_set0_signature_removed)}
    if SCT_set0_signature_removed <= LibVersion then
    begin
      {$if declared(_SCT_set0_signature)}
      SCT_set0_signature := _SCT_set0_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_set0_signature_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_set0_signature');
    {$ifend}
  end;
  
  SCT_set1_signature := LoadLibFunction(ADllHandle, SCT_set1_signature_procname);
  FuncLoadError := not assigned(SCT_set1_signature);
  if FuncLoadError then
  begin
    {$if not defined(SCT_set1_signature_allownil)}
    SCT_set1_signature := ERR_SCT_set1_signature;
    {$ifend}
    {$if declared(SCT_set1_signature_introduced)}
    if LibVersion < SCT_set1_signature_introduced then
    begin
      {$if declared(FC_SCT_set1_signature)}
      SCT_set1_signature := FC_SCT_set1_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_set1_signature_removed)}
    if SCT_set1_signature_removed <= LibVersion then
    begin
      {$if declared(_SCT_set1_signature)}
      SCT_set1_signature := _SCT_set1_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_set1_signature_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_set1_signature');
    {$ifend}
  end;
  
  SCT_get_source := LoadLibFunction(ADllHandle, SCT_get_source_procname);
  FuncLoadError := not assigned(SCT_get_source);
  if FuncLoadError then
  begin
    {$if not defined(SCT_get_source_allownil)}
    SCT_get_source := ERR_SCT_get_source;
    {$ifend}
    {$if declared(SCT_get_source_introduced)}
    if LibVersion < SCT_get_source_introduced then
    begin
      {$if declared(FC_SCT_get_source)}
      SCT_get_source := FC_SCT_get_source;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_get_source_removed)}
    if SCT_get_source_removed <= LibVersion then
    begin
      {$if declared(_SCT_get_source)}
      SCT_get_source := _SCT_get_source;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_get_source_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_get_source');
    {$ifend}
  end;
  
  SCT_set_source := LoadLibFunction(ADllHandle, SCT_set_source_procname);
  FuncLoadError := not assigned(SCT_set_source);
  if FuncLoadError then
  begin
    {$if not defined(SCT_set_source_allownil)}
    SCT_set_source := ERR_SCT_set_source;
    {$ifend}
    {$if declared(SCT_set_source_introduced)}
    if LibVersion < SCT_set_source_introduced then
    begin
      {$if declared(FC_SCT_set_source)}
      SCT_set_source := FC_SCT_set_source;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_set_source_removed)}
    if SCT_set_source_removed <= LibVersion then
    begin
      {$if declared(_SCT_set_source)}
      SCT_set_source := _SCT_set_source;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_set_source_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_set_source');
    {$ifend}
  end;
  
  SCT_validation_status_string := LoadLibFunction(ADllHandle, SCT_validation_status_string_procname);
  FuncLoadError := not assigned(SCT_validation_status_string);
  if FuncLoadError then
  begin
    {$if not defined(SCT_validation_status_string_allownil)}
    SCT_validation_status_string := ERR_SCT_validation_status_string;
    {$ifend}
    {$if declared(SCT_validation_status_string_introduced)}
    if LibVersion < SCT_validation_status_string_introduced then
    begin
      {$if declared(FC_SCT_validation_status_string)}
      SCT_validation_status_string := FC_SCT_validation_status_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_validation_status_string_removed)}
    if SCT_validation_status_string_removed <= LibVersion then
    begin
      {$if declared(_SCT_validation_status_string)}
      SCT_validation_status_string := _SCT_validation_status_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_validation_status_string_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_validation_status_string');
    {$ifend}
  end;
  
  SCT_print := LoadLibFunction(ADllHandle, SCT_print_procname);
  FuncLoadError := not assigned(SCT_print);
  if FuncLoadError then
  begin
    {$if not defined(SCT_print_allownil)}
    SCT_print := ERR_SCT_print;
    {$ifend}
    {$if declared(SCT_print_introduced)}
    if LibVersion < SCT_print_introduced then
    begin
      {$if declared(FC_SCT_print)}
      SCT_print := FC_SCT_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_print_removed)}
    if SCT_print_removed <= LibVersion then
    begin
      {$if declared(_SCT_print)}
      SCT_print := _SCT_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_print_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_print');
    {$ifend}
  end;
  
  SCT_LIST_print := LoadLibFunction(ADllHandle, SCT_LIST_print_procname);
  FuncLoadError := not assigned(SCT_LIST_print);
  if FuncLoadError then
  begin
    {$if not defined(SCT_LIST_print_allownil)}
    SCT_LIST_print := ERR_SCT_LIST_print;
    {$ifend}
    {$if declared(SCT_LIST_print_introduced)}
    if LibVersion < SCT_LIST_print_introduced then
    begin
      {$if declared(FC_SCT_LIST_print)}
      SCT_LIST_print := FC_SCT_LIST_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_LIST_print_removed)}
    if SCT_LIST_print_removed <= LibVersion then
    begin
      {$if declared(_SCT_LIST_print)}
      SCT_LIST_print := _SCT_LIST_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_LIST_print_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_LIST_print');
    {$ifend}
  end;
  
  SCT_get_validation_status := LoadLibFunction(ADllHandle, SCT_get_validation_status_procname);
  FuncLoadError := not assigned(SCT_get_validation_status);
  if FuncLoadError then
  begin
    {$if not defined(SCT_get_validation_status_allownil)}
    SCT_get_validation_status := ERR_SCT_get_validation_status;
    {$ifend}
    {$if declared(SCT_get_validation_status_introduced)}
    if LibVersion < SCT_get_validation_status_introduced then
    begin
      {$if declared(FC_SCT_get_validation_status)}
      SCT_get_validation_status := FC_SCT_get_validation_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_get_validation_status_removed)}
    if SCT_get_validation_status_removed <= LibVersion then
    begin
      {$if declared(_SCT_get_validation_status)}
      SCT_get_validation_status := _SCT_get_validation_status;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_get_validation_status_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_get_validation_status');
    {$ifend}
  end;
  
  SCT_validate := LoadLibFunction(ADllHandle, SCT_validate_procname);
  FuncLoadError := not assigned(SCT_validate);
  if FuncLoadError then
  begin
    {$if not defined(SCT_validate_allownil)}
    SCT_validate := ERR_SCT_validate;
    {$ifend}
    {$if declared(SCT_validate_introduced)}
    if LibVersion < SCT_validate_introduced then
    begin
      {$if declared(FC_SCT_validate)}
      SCT_validate := FC_SCT_validate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_validate_removed)}
    if SCT_validate_removed <= LibVersion then
    begin
      {$if declared(_SCT_validate)}
      SCT_validate := _SCT_validate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_validate_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_validate');
    {$ifend}
  end;
  
  SCT_LIST_validate := LoadLibFunction(ADllHandle, SCT_LIST_validate_procname);
  FuncLoadError := not assigned(SCT_LIST_validate);
  if FuncLoadError then
  begin
    {$if not defined(SCT_LIST_validate_allownil)}
    SCT_LIST_validate := ERR_SCT_LIST_validate;
    {$ifend}
    {$if declared(SCT_LIST_validate_introduced)}
    if LibVersion < SCT_LIST_validate_introduced then
    begin
      {$if declared(FC_SCT_LIST_validate)}
      SCT_LIST_validate := FC_SCT_LIST_validate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCT_LIST_validate_removed)}
    if SCT_LIST_validate_removed <= LibVersion then
    begin
      {$if declared(_SCT_LIST_validate)}
      SCT_LIST_validate := _SCT_LIST_validate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCT_LIST_validate_allownil)}
    if FuncLoadError then
      AFailed.Add('SCT_LIST_validate');
    {$ifend}
  end;
  
  i2o_SCT_LIST := LoadLibFunction(ADllHandle, i2o_SCT_LIST_procname);
  FuncLoadError := not assigned(i2o_SCT_LIST);
  if FuncLoadError then
  begin
    {$if not defined(i2o_SCT_LIST_allownil)}
    i2o_SCT_LIST := ERR_i2o_SCT_LIST;
    {$ifend}
    {$if declared(i2o_SCT_LIST_introduced)}
    if LibVersion < i2o_SCT_LIST_introduced then
    begin
      {$if declared(FC_i2o_SCT_LIST)}
      i2o_SCT_LIST := FC_i2o_SCT_LIST;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2o_SCT_LIST_removed)}
    if i2o_SCT_LIST_removed <= LibVersion then
    begin
      {$if declared(_i2o_SCT_LIST)}
      i2o_SCT_LIST := _i2o_SCT_LIST;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2o_SCT_LIST_allownil)}
    if FuncLoadError then
      AFailed.Add('i2o_SCT_LIST');
    {$ifend}
  end;
  
  o2i_SCT_LIST := LoadLibFunction(ADllHandle, o2i_SCT_LIST_procname);
  FuncLoadError := not assigned(o2i_SCT_LIST);
  if FuncLoadError then
  begin
    {$if not defined(o2i_SCT_LIST_allownil)}
    o2i_SCT_LIST := ERR_o2i_SCT_LIST;
    {$ifend}
    {$if declared(o2i_SCT_LIST_introduced)}
    if LibVersion < o2i_SCT_LIST_introduced then
    begin
      {$if declared(FC_o2i_SCT_LIST)}
      o2i_SCT_LIST := FC_o2i_SCT_LIST;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(o2i_SCT_LIST_removed)}
    if o2i_SCT_LIST_removed <= LibVersion then
    begin
      {$if declared(_o2i_SCT_LIST)}
      o2i_SCT_LIST := _o2i_SCT_LIST;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(o2i_SCT_LIST_allownil)}
    if FuncLoadError then
      AFailed.Add('o2i_SCT_LIST');
    {$ifend}
  end;
  
  i2d_SCT_LIST := LoadLibFunction(ADllHandle, i2d_SCT_LIST_procname);
  FuncLoadError := not assigned(i2d_SCT_LIST);
  if FuncLoadError then
  begin
    {$if not defined(i2d_SCT_LIST_allownil)}
    i2d_SCT_LIST := ERR_i2d_SCT_LIST;
    {$ifend}
    {$if declared(i2d_SCT_LIST_introduced)}
    if LibVersion < i2d_SCT_LIST_introduced then
    begin
      {$if declared(FC_i2d_SCT_LIST)}
      i2d_SCT_LIST := FC_i2d_SCT_LIST;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_SCT_LIST_removed)}
    if i2d_SCT_LIST_removed <= LibVersion then
    begin
      {$if declared(_i2d_SCT_LIST)}
      i2d_SCT_LIST := _i2d_SCT_LIST;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_SCT_LIST_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_SCT_LIST');
    {$ifend}
  end;
  
  d2i_SCT_LIST := LoadLibFunction(ADllHandle, d2i_SCT_LIST_procname);
  FuncLoadError := not assigned(d2i_SCT_LIST);
  if FuncLoadError then
  begin
    {$if not defined(d2i_SCT_LIST_allownil)}
    d2i_SCT_LIST := ERR_d2i_SCT_LIST;
    {$ifend}
    {$if declared(d2i_SCT_LIST_introduced)}
    if LibVersion < d2i_SCT_LIST_introduced then
    begin
      {$if declared(FC_d2i_SCT_LIST)}
      d2i_SCT_LIST := FC_d2i_SCT_LIST;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_SCT_LIST_removed)}
    if d2i_SCT_LIST_removed <= LibVersion then
    begin
      {$if declared(_d2i_SCT_LIST)}
      d2i_SCT_LIST := _d2i_SCT_LIST;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_SCT_LIST_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_SCT_LIST');
    {$ifend}
  end;
  
  i2o_SCT := LoadLibFunction(ADllHandle, i2o_SCT_procname);
  FuncLoadError := not assigned(i2o_SCT);
  if FuncLoadError then
  begin
    {$if not defined(i2o_SCT_allownil)}
    i2o_SCT := ERR_i2o_SCT;
    {$ifend}
    {$if declared(i2o_SCT_introduced)}
    if LibVersion < i2o_SCT_introduced then
    begin
      {$if declared(FC_i2o_SCT)}
      i2o_SCT := FC_i2o_SCT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2o_SCT_removed)}
    if i2o_SCT_removed <= LibVersion then
    begin
      {$if declared(_i2o_SCT)}
      i2o_SCT := _i2o_SCT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2o_SCT_allownil)}
    if FuncLoadError then
      AFailed.Add('i2o_SCT');
    {$ifend}
  end;
  
  o2i_SCT := LoadLibFunction(ADllHandle, o2i_SCT_procname);
  FuncLoadError := not assigned(o2i_SCT);
  if FuncLoadError then
  begin
    {$if not defined(o2i_SCT_allownil)}
    o2i_SCT := ERR_o2i_SCT;
    {$ifend}
    {$if declared(o2i_SCT_introduced)}
    if LibVersion < o2i_SCT_introduced then
    begin
      {$if declared(FC_o2i_SCT)}
      o2i_SCT := FC_o2i_SCT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(o2i_SCT_removed)}
    if o2i_SCT_removed <= LibVersion then
    begin
      {$if declared(_o2i_SCT)}
      o2i_SCT := _o2i_SCT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(o2i_SCT_allownil)}
    if FuncLoadError then
      AFailed.Add('o2i_SCT');
    {$ifend}
  end;
  
  CTLOG_new_ex := LoadLibFunction(ADllHandle, CTLOG_new_ex_procname);
  FuncLoadError := not assigned(CTLOG_new_ex);
  if FuncLoadError then
  begin
    {$if not defined(CTLOG_new_ex_allownil)}
    CTLOG_new_ex := ERR_CTLOG_new_ex;
    {$ifend}
    {$if declared(CTLOG_new_ex_introduced)}
    if LibVersion < CTLOG_new_ex_introduced then
    begin
      {$if declared(FC_CTLOG_new_ex)}
      CTLOG_new_ex := FC_CTLOG_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CTLOG_new_ex_removed)}
    if CTLOG_new_ex_removed <= LibVersion then
    begin
      {$if declared(_CTLOG_new_ex)}
      CTLOG_new_ex := _CTLOG_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CTLOG_new_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('CTLOG_new_ex');
    {$ifend}
  end;
  
  CTLOG_new := LoadLibFunction(ADllHandle, CTLOG_new_procname);
  FuncLoadError := not assigned(CTLOG_new);
  if FuncLoadError then
  begin
    {$if not defined(CTLOG_new_allownil)}
    CTLOG_new := ERR_CTLOG_new;
    {$ifend}
    {$if declared(CTLOG_new_introduced)}
    if LibVersion < CTLOG_new_introduced then
    begin
      {$if declared(FC_CTLOG_new)}
      CTLOG_new := FC_CTLOG_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CTLOG_new_removed)}
    if CTLOG_new_removed <= LibVersion then
    begin
      {$if declared(_CTLOG_new)}
      CTLOG_new := _CTLOG_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CTLOG_new_allownil)}
    if FuncLoadError then
      AFailed.Add('CTLOG_new');
    {$ifend}
  end;
  
  CTLOG_new_from_base64_ex := LoadLibFunction(ADllHandle, CTLOG_new_from_base64_ex_procname);
  FuncLoadError := not assigned(CTLOG_new_from_base64_ex);
  if FuncLoadError then
  begin
    {$if not defined(CTLOG_new_from_base64_ex_allownil)}
    CTLOG_new_from_base64_ex := ERR_CTLOG_new_from_base64_ex;
    {$ifend}
    {$if declared(CTLOG_new_from_base64_ex_introduced)}
    if LibVersion < CTLOG_new_from_base64_ex_introduced then
    begin
      {$if declared(FC_CTLOG_new_from_base64_ex)}
      CTLOG_new_from_base64_ex := FC_CTLOG_new_from_base64_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CTLOG_new_from_base64_ex_removed)}
    if CTLOG_new_from_base64_ex_removed <= LibVersion then
    begin
      {$if declared(_CTLOG_new_from_base64_ex)}
      CTLOG_new_from_base64_ex := _CTLOG_new_from_base64_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CTLOG_new_from_base64_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('CTLOG_new_from_base64_ex');
    {$ifend}
  end;
  
  CTLOG_new_from_base64 := LoadLibFunction(ADllHandle, CTLOG_new_from_base64_procname);
  FuncLoadError := not assigned(CTLOG_new_from_base64);
  if FuncLoadError then
  begin
    {$if not defined(CTLOG_new_from_base64_allownil)}
    CTLOG_new_from_base64 := ERR_CTLOG_new_from_base64;
    {$ifend}
    {$if declared(CTLOG_new_from_base64_introduced)}
    if LibVersion < CTLOG_new_from_base64_introduced then
    begin
      {$if declared(FC_CTLOG_new_from_base64)}
      CTLOG_new_from_base64 := FC_CTLOG_new_from_base64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CTLOG_new_from_base64_removed)}
    if CTLOG_new_from_base64_removed <= LibVersion then
    begin
      {$if declared(_CTLOG_new_from_base64)}
      CTLOG_new_from_base64 := _CTLOG_new_from_base64;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CTLOG_new_from_base64_allownil)}
    if FuncLoadError then
      AFailed.Add('CTLOG_new_from_base64');
    {$ifend}
  end;
  
  CTLOG_free := LoadLibFunction(ADllHandle, CTLOG_free_procname);
  FuncLoadError := not assigned(CTLOG_free);
  if FuncLoadError then
  begin
    {$if not defined(CTLOG_free_allownil)}
    CTLOG_free := ERR_CTLOG_free;
    {$ifend}
    {$if declared(CTLOG_free_introduced)}
    if LibVersion < CTLOG_free_introduced then
    begin
      {$if declared(FC_CTLOG_free)}
      CTLOG_free := FC_CTLOG_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CTLOG_free_removed)}
    if CTLOG_free_removed <= LibVersion then
    begin
      {$if declared(_CTLOG_free)}
      CTLOG_free := _CTLOG_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CTLOG_free_allownil)}
    if FuncLoadError then
      AFailed.Add('CTLOG_free');
    {$ifend}
  end;
  
  CTLOG_get0_name := LoadLibFunction(ADllHandle, CTLOG_get0_name_procname);
  FuncLoadError := not assigned(CTLOG_get0_name);
  if FuncLoadError then
  begin
    {$if not defined(CTLOG_get0_name_allownil)}
    CTLOG_get0_name := ERR_CTLOG_get0_name;
    {$ifend}
    {$if declared(CTLOG_get0_name_introduced)}
    if LibVersion < CTLOG_get0_name_introduced then
    begin
      {$if declared(FC_CTLOG_get0_name)}
      CTLOG_get0_name := FC_CTLOG_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CTLOG_get0_name_removed)}
    if CTLOG_get0_name_removed <= LibVersion then
    begin
      {$if declared(_CTLOG_get0_name)}
      CTLOG_get0_name := _CTLOG_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CTLOG_get0_name_allownil)}
    if FuncLoadError then
      AFailed.Add('CTLOG_get0_name');
    {$ifend}
  end;
  
  CTLOG_get0_log_id := LoadLibFunction(ADllHandle, CTLOG_get0_log_id_procname);
  FuncLoadError := not assigned(CTLOG_get0_log_id);
  if FuncLoadError then
  begin
    {$if not defined(CTLOG_get0_log_id_allownil)}
    CTLOG_get0_log_id := ERR_CTLOG_get0_log_id;
    {$ifend}
    {$if declared(CTLOG_get0_log_id_introduced)}
    if LibVersion < CTLOG_get0_log_id_introduced then
    begin
      {$if declared(FC_CTLOG_get0_log_id)}
      CTLOG_get0_log_id := FC_CTLOG_get0_log_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CTLOG_get0_log_id_removed)}
    if CTLOG_get0_log_id_removed <= LibVersion then
    begin
      {$if declared(_CTLOG_get0_log_id)}
      CTLOG_get0_log_id := _CTLOG_get0_log_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CTLOG_get0_log_id_allownil)}
    if FuncLoadError then
      AFailed.Add('CTLOG_get0_log_id');
    {$ifend}
  end;
  
  CTLOG_get0_public_key := LoadLibFunction(ADllHandle, CTLOG_get0_public_key_procname);
  FuncLoadError := not assigned(CTLOG_get0_public_key);
  if FuncLoadError then
  begin
    {$if not defined(CTLOG_get0_public_key_allownil)}
    CTLOG_get0_public_key := ERR_CTLOG_get0_public_key;
    {$ifend}
    {$if declared(CTLOG_get0_public_key_introduced)}
    if LibVersion < CTLOG_get0_public_key_introduced then
    begin
      {$if declared(FC_CTLOG_get0_public_key)}
      CTLOG_get0_public_key := FC_CTLOG_get0_public_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CTLOG_get0_public_key_removed)}
    if CTLOG_get0_public_key_removed <= LibVersion then
    begin
      {$if declared(_CTLOG_get0_public_key)}
      CTLOG_get0_public_key := _CTLOG_get0_public_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CTLOG_get0_public_key_allownil)}
    if FuncLoadError then
      AFailed.Add('CTLOG_get0_public_key');
    {$ifend}
  end;
  
  CTLOG_STORE_new_ex := LoadLibFunction(ADllHandle, CTLOG_STORE_new_ex_procname);
  FuncLoadError := not assigned(CTLOG_STORE_new_ex);
  if FuncLoadError then
  begin
    {$if not defined(CTLOG_STORE_new_ex_allownil)}
    CTLOG_STORE_new_ex := ERR_CTLOG_STORE_new_ex;
    {$ifend}
    {$if declared(CTLOG_STORE_new_ex_introduced)}
    if LibVersion < CTLOG_STORE_new_ex_introduced then
    begin
      {$if declared(FC_CTLOG_STORE_new_ex)}
      CTLOG_STORE_new_ex := FC_CTLOG_STORE_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CTLOG_STORE_new_ex_removed)}
    if CTLOG_STORE_new_ex_removed <= LibVersion then
    begin
      {$if declared(_CTLOG_STORE_new_ex)}
      CTLOG_STORE_new_ex := _CTLOG_STORE_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CTLOG_STORE_new_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('CTLOG_STORE_new_ex');
    {$ifend}
  end;
  
  CTLOG_STORE_new := LoadLibFunction(ADllHandle, CTLOG_STORE_new_procname);
  FuncLoadError := not assigned(CTLOG_STORE_new);
  if FuncLoadError then
  begin
    {$if not defined(CTLOG_STORE_new_allownil)}
    CTLOG_STORE_new := ERR_CTLOG_STORE_new;
    {$ifend}
    {$if declared(CTLOG_STORE_new_introduced)}
    if LibVersion < CTLOG_STORE_new_introduced then
    begin
      {$if declared(FC_CTLOG_STORE_new)}
      CTLOG_STORE_new := FC_CTLOG_STORE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CTLOG_STORE_new_removed)}
    if CTLOG_STORE_new_removed <= LibVersion then
    begin
      {$if declared(_CTLOG_STORE_new)}
      CTLOG_STORE_new := _CTLOG_STORE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CTLOG_STORE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('CTLOG_STORE_new');
    {$ifend}
  end;
  
  CTLOG_STORE_free := LoadLibFunction(ADllHandle, CTLOG_STORE_free_procname);
  FuncLoadError := not assigned(CTLOG_STORE_free);
  if FuncLoadError then
  begin
    {$if not defined(CTLOG_STORE_free_allownil)}
    CTLOG_STORE_free := ERR_CTLOG_STORE_free;
    {$ifend}
    {$if declared(CTLOG_STORE_free_introduced)}
    if LibVersion < CTLOG_STORE_free_introduced then
    begin
      {$if declared(FC_CTLOG_STORE_free)}
      CTLOG_STORE_free := FC_CTLOG_STORE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CTLOG_STORE_free_removed)}
    if CTLOG_STORE_free_removed <= LibVersion then
    begin
      {$if declared(_CTLOG_STORE_free)}
      CTLOG_STORE_free := _CTLOG_STORE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CTLOG_STORE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('CTLOG_STORE_free');
    {$ifend}
  end;
  
  CTLOG_STORE_get0_log_by_id := LoadLibFunction(ADllHandle, CTLOG_STORE_get0_log_by_id_procname);
  FuncLoadError := not assigned(CTLOG_STORE_get0_log_by_id);
  if FuncLoadError then
  begin
    {$if not defined(CTLOG_STORE_get0_log_by_id_allownil)}
    CTLOG_STORE_get0_log_by_id := ERR_CTLOG_STORE_get0_log_by_id;
    {$ifend}
    {$if declared(CTLOG_STORE_get0_log_by_id_introduced)}
    if LibVersion < CTLOG_STORE_get0_log_by_id_introduced then
    begin
      {$if declared(FC_CTLOG_STORE_get0_log_by_id)}
      CTLOG_STORE_get0_log_by_id := FC_CTLOG_STORE_get0_log_by_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CTLOG_STORE_get0_log_by_id_removed)}
    if CTLOG_STORE_get0_log_by_id_removed <= LibVersion then
    begin
      {$if declared(_CTLOG_STORE_get0_log_by_id)}
      CTLOG_STORE_get0_log_by_id := _CTLOG_STORE_get0_log_by_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CTLOG_STORE_get0_log_by_id_allownil)}
    if FuncLoadError then
      AFailed.Add('CTLOG_STORE_get0_log_by_id');
    {$ifend}
  end;
  
  CTLOG_STORE_load_file := LoadLibFunction(ADllHandle, CTLOG_STORE_load_file_procname);
  FuncLoadError := not assigned(CTLOG_STORE_load_file);
  if FuncLoadError then
  begin
    {$if not defined(CTLOG_STORE_load_file_allownil)}
    CTLOG_STORE_load_file := ERR_CTLOG_STORE_load_file;
    {$ifend}
    {$if declared(CTLOG_STORE_load_file_introduced)}
    if LibVersion < CTLOG_STORE_load_file_introduced then
    begin
      {$if declared(FC_CTLOG_STORE_load_file)}
      CTLOG_STORE_load_file := FC_CTLOG_STORE_load_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CTLOG_STORE_load_file_removed)}
    if CTLOG_STORE_load_file_removed <= LibVersion then
    begin
      {$if declared(_CTLOG_STORE_load_file)}
      CTLOG_STORE_load_file := _CTLOG_STORE_load_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CTLOG_STORE_load_file_allownil)}
    if FuncLoadError then
      AFailed.Add('CTLOG_STORE_load_file');
    {$ifend}
  end;
  
  CTLOG_STORE_load_default_file := LoadLibFunction(ADllHandle, CTLOG_STORE_load_default_file_procname);
  FuncLoadError := not assigned(CTLOG_STORE_load_default_file);
  if FuncLoadError then
  begin
    {$if not defined(CTLOG_STORE_load_default_file_allownil)}
    CTLOG_STORE_load_default_file := ERR_CTLOG_STORE_load_default_file;
    {$ifend}
    {$if declared(CTLOG_STORE_load_default_file_introduced)}
    if LibVersion < CTLOG_STORE_load_default_file_introduced then
    begin
      {$if declared(FC_CTLOG_STORE_load_default_file)}
      CTLOG_STORE_load_default_file := FC_CTLOG_STORE_load_default_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CTLOG_STORE_load_default_file_removed)}
    if CTLOG_STORE_load_default_file_removed <= LibVersion then
    begin
      {$if declared(_CTLOG_STORE_load_default_file)}
      CTLOG_STORE_load_default_file := _CTLOG_STORE_load_default_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CTLOG_STORE_load_default_file_allownil)}
    if FuncLoadError then
      AFailed.Add('CTLOG_STORE_load_default_file');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  CT_POLICY_EVAL_CTX_new_ex := nil;
  CT_POLICY_EVAL_CTX_new := nil;
  CT_POLICY_EVAL_CTX_free := nil;
  CT_POLICY_EVAL_CTX_get0_cert := nil;
  CT_POLICY_EVAL_CTX_set1_cert := nil;
  CT_POLICY_EVAL_CTX_get0_issuer := nil;
  CT_POLICY_EVAL_CTX_set1_issuer := nil;
  CT_POLICY_EVAL_CTX_get0_log_store := nil;
  CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE := nil;
  CT_POLICY_EVAL_CTX_get_time := nil;
  CT_POLICY_EVAL_CTX_set_time := nil;
  SCT_new := nil;
  SCT_new_from_base64 := nil;
  SCT_free := nil;
  SCT_LIST_free := nil;
  SCT_get_version := nil;
  SCT_set_version := nil;
  SCT_get_log_entry_type := nil;
  SCT_set_log_entry_type := nil;
  SCT_get0_log_id := nil;
  SCT_set0_log_id := nil;
  SCT_set1_log_id := nil;
  SCT_get_timestamp := nil;
  SCT_set_timestamp := nil;
  SCT_get_signature_nid := nil;
  SCT_set_signature_nid := nil;
  SCT_get0_extensions := nil;
  SCT_set0_extensions := nil;
  SCT_set1_extensions := nil;
  SCT_get0_signature := nil;
  SCT_set0_signature := nil;
  SCT_set1_signature := nil;
  SCT_get_source := nil;
  SCT_set_source := nil;
  SCT_validation_status_string := nil;
  SCT_print := nil;
  SCT_LIST_print := nil;
  SCT_get_validation_status := nil;
  SCT_validate := nil;
  SCT_LIST_validate := nil;
  i2o_SCT_LIST := nil;
  o2i_SCT_LIST := nil;
  i2d_SCT_LIST := nil;
  d2i_SCT_LIST := nil;
  i2o_SCT := nil;
  o2i_SCT := nil;
  CTLOG_new_ex := nil;
  CTLOG_new := nil;
  CTLOG_new_from_base64_ex := nil;
  CTLOG_new_from_base64 := nil;
  CTLOG_free := nil;
  CTLOG_get0_name := nil;
  CTLOG_get0_log_id := nil;
  CTLOG_get0_public_key := nil;
  CTLOG_STORE_new_ex := nil;
  CTLOG_STORE_new := nil;
  CTLOG_STORE_free := nil;
  CTLOG_STORE_get0_log_by_id := nil;
  CTLOG_STORE_load_file := nil;
  CTLOG_STORE_load_default_file := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.