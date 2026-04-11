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

unit TaurusTLSHeaders_engine;

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
  PENGINE_CMD_DEFN_st = ^TENGINE_CMD_DEFN_st;
  TENGINE_CMD_DEFN_st =   record
    cmd_num: TIdC_UINT;
    cmd_name: PIdAnsiChar;
    cmd_desc: PIdAnsiChar;
    cmd_flags: TIdC_UINT;
  end;
  {$EXTERNALSYM PENGINE_CMD_DEFN_st}

  Pst_dynamic_MEM_fns = ^Tst_dynamic_MEM_fns;
  Tst_dynamic_MEM_fns =   record
    malloc_fn: Tdyn_MEM_malloc_fn;
    realloc_fn: Tdyn_MEM_realloc_fn;
    free_fn: Tdyn_MEM_free_fn;
  end;
  {$EXTERNALSYM Pst_dynamic_MEM_fns}

  Pst_dynamic_fns = ^Tst_dynamic_fns;
  Tst_dynamic_fns =   record
    static_state: Pointer;
    mem_fns: Tdynamic_MEM_fns;
  end;
  {$EXTERNALSYM Pst_dynamic_fns}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  TENGINE_GEN_FUNC_PTR = function: TIdC_INT; cdecl;
  TENGINE_GEN_INT_FUNC_PTR = function(arg1: PENGINE): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // ENGINE_CTRL_FUNC_PTR_func_cb = procedure; cdecl;
  TENGINE_CTRL_FUNC_PTR = function(arg1: PENGINE; arg2: TIdC_INT; arg3: TIdC_LONG; arg4: Pointer; f: TENGINE_CTRL_FUNC_PTR_func_cb): TIdC_INT; cdecl;
  TENGINE_LOAD_KEY_PTR = function(arg1: PENGINE; arg2: PIdAnsiChar; ui_method: PUI_METHOD; callback_data: Pointer): Pevp_pkey_st; cdecl;
  TENGINE_SSL_CLIENT_CERT_PTR = function(arg1: PENGINE; ssl: PSSL; ca_dn: Pstack_st_X509_NAME; pcert: PPX509; pkey: PPEVP_PKEY; pother: PPstack_st_X509; ui_method: PUI_METHOD; callback_data: Pointer): TIdC_INT; cdecl;
  TENGINE_CIPHERS_PTR = function(arg1: PENGINE; arg2: PPEVP_CIPHER; arg3: PPIdC_INT; arg4: TIdC_INT): TIdC_INT; cdecl;
  TENGINE_DIGESTS_PTR = function(arg1: PENGINE; arg2: PPEVP_MD; arg3: PPIdC_INT; arg4: TIdC_INT): TIdC_INT; cdecl;
  TENGINE_PKEY_METHS_PTR = function(arg1: PENGINE; arg2: PPEVP_PKEY_METHOD; arg3: PPIdC_INT; arg4: TIdC_INT): TIdC_INT; cdecl;
  TENGINE_PKEY_ASN1_METHS_PTR = function(arg1: PENGINE; arg2: PPEVP_PKEY_ASN1_METHOD; arg3: PPIdC_INT; arg4: TIdC_INT): TIdC_INT; cdecl;
  Tdyn_MEM_malloc_fn = function(arg1: TIdC_SIZET; arg2: PIdAnsiChar; arg3: TIdC_INT): Pointer; cdecl;
  Tdyn_MEM_realloc_fn = function(arg1: Pointer; arg2: TIdC_SIZET; arg3: PIdAnsiChar; arg4: TIdC_INT): Pointer; cdecl;
  Tdyn_MEM_free_fn = procedure(arg1: Pointer; arg2: PIdAnsiChar; arg3: TIdC_INT); cdecl;
  Tdynamic_v_check_fn = function(ossl_version: TIdC_ULONG): TIdC_ULONG; cdecl;
  Tdynamic_bind_engine = function(e: PENGINE; id: PIdAnsiChar; fns: Pdynamic_fns): TIdC_INT; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  ENGINE_METHOD_RSA = (unsignedint)$0001;
  ENGINE_METHOD_DSA = (unsignedint)$0002;
  ENGINE_METHOD_DH = (unsignedint)$0004;
  ENGINE_METHOD_RAND = (unsignedint)$0008;
  ENGINE_METHOD_CIPHERS = (unsignedint)$0040;
  ENGINE_METHOD_DIGESTS = (unsignedint)$0080;
  ENGINE_METHOD_PKEY_METHS = (unsignedint)$0200;
  ENGINE_METHOD_PKEY_ASN1_METHS = (unsignedint)$0400;
  ENGINE_METHOD_EC = (unsignedint)$0800;
  ENGINE_METHOD_ALL = (unsignedint)$FFFF;
  ENGINE_METHOD_NONE = (unsignedint)$0000;
  ENGINE_TABLE_FLAG_NOINIT = (unsignedint)$0001;
  ENGINE_FLAGS_MANUAL_CMD_CTRL = (int)$0002;
  ENGINE_FLAGS_BY_ID_COPY = (int)$0004;
  ENGINE_FLAGS_NO_REGISTER_ALL = (int)$0008;
  ENGINE_CMD_FLAG_NUMERIC = (unsignedint)$0001;
  ENGINE_CMD_FLAG_STRING = (unsignedint)$0002;
  ENGINE_CMD_FLAG_NO_INPUT = (unsignedint)$0004;
  ENGINE_CMD_FLAG_INTERNAL = (unsignedint)$0008;
  ENGINE_CTRL_SET_LOGSTREAM = 1;
  ENGINE_CTRL_SET_PASSWORD_CALLBACK = 2;
  ENGINE_CTRL_HUP = 3;
  ENGINE_CTRL_SET_USER_INTERFACE = 4;
  ENGINE_CTRL_SET_CALLBACK_DATA = 5;
  ENGINE_CTRL_LOAD_CONFIGURATION = 6;
  ENGINE_CTRL_LOAD_SECTION = 7;
  ENGINE_CTRL_HAS_CTRL_FUNCTION = 10;
  ENGINE_CTRL_GET_FIRST_CMD_TYPE = 11;
  ENGINE_CTRL_GET_NEXT_CMD_TYPE = 12;
  ENGINE_CTRL_GET_CMD_FROM_NAME = 13;
  ENGINE_CTRL_GET_NAME_LEN_FROM_CMD = 14;
  ENGINE_CTRL_GET_NAME_FROM_CMD = 15;
  ENGINE_CTRL_GET_DESC_LEN_FROM_CMD = 16;
  ENGINE_CTRL_GET_DESC_FROM_CMD = 17;
  ENGINE_CTRL_GET_CMD_FLAGS = 18;
  ENGINE_CMD_BASE = 200;
  ENGINE_CTRL_CHIL_SET_FORKCHECK = 100;
  ENGINE_CTRL_CHIL_NO_LOCKING = 101;
  OSSL_DYNAMIC_VERSION = (unsignedlong)$00030000;
  OSSL_DYNAMIC_OLDEST = (unsignedlong)$00030000;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  ENGINE_get_first: function: PENGINE; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_first}

  ENGINE_get_last: function: PENGINE; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_last}

  ENGINE_get_next: function(e: PENGINE): PENGINE; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_next}

  ENGINE_get_prev: function(e: PENGINE): PENGINE; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_prev}

  ENGINE_add: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_add}

  ENGINE_remove: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_remove}

  ENGINE_by_id: function(id: PIdAnsiChar): PENGINE; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_by_id}

  ENGINE_load_builtin_engines: procedure; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_load_builtin_engines}

  ENGINE_get_table_flags: function: TIdC_UINT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_table_flags}

  ENGINE_set_table_flags: procedure(flags: TIdC_UINT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_table_flags}

  ENGINE_register_RSA: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_register_RSA}

  ENGINE_unregister_RSA: procedure(e: PENGINE); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_unregister_RSA}

  ENGINE_register_all_RSA: procedure; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_register_all_RSA}

  ENGINE_register_DSA: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_register_DSA}

  ENGINE_unregister_DSA: procedure(e: PENGINE); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_unregister_DSA}

  ENGINE_register_all_DSA: procedure; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_register_all_DSA}

  ENGINE_register_EC: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_register_EC}

  ENGINE_unregister_EC: procedure(e: PENGINE); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_unregister_EC}

  ENGINE_register_all_EC: procedure; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_register_all_EC}

  ENGINE_register_DH: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_register_DH}

  ENGINE_unregister_DH: procedure(e: PENGINE); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_unregister_DH}

  ENGINE_register_all_DH: procedure; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_register_all_DH}

  ENGINE_register_RAND: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_register_RAND}

  ENGINE_unregister_RAND: procedure(e: PENGINE); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_unregister_RAND}

  ENGINE_register_all_RAND: procedure; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_register_all_RAND}

  ENGINE_register_ciphers: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_register_ciphers}

  ENGINE_unregister_ciphers: procedure(e: PENGINE); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_unregister_ciphers}

  ENGINE_register_all_ciphers: procedure; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_register_all_ciphers}

  ENGINE_register_digests: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_register_digests}

  ENGINE_unregister_digests: procedure(e: PENGINE); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_unregister_digests}

  ENGINE_register_all_digests: procedure; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_register_all_digests}

  ENGINE_register_pkey_meths: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_register_pkey_meths}

  ENGINE_unregister_pkey_meths: procedure(e: PENGINE); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_unregister_pkey_meths}

  ENGINE_register_all_pkey_meths: procedure; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_register_all_pkey_meths}

  ENGINE_register_pkey_asn1_meths: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_register_pkey_asn1_meths}

  ENGINE_unregister_pkey_asn1_meths: procedure(e: PENGINE); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_unregister_pkey_asn1_meths}

  ENGINE_register_all_pkey_asn1_meths: procedure; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_register_all_pkey_asn1_meths}

  ENGINE_register_complete: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_register_complete}

  ENGINE_register_all_complete: function: TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_register_all_complete}

  ENGINE_ctrl: function(e: PENGINE; cmd: TIdC_INT; i: TIdC_LONG; p: Pointer; f: TENGINE_CTRL_FUNC_PTR_func_cb): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_ctrl}

  ENGINE_cmd_is_executable: function(e: PENGINE; cmd: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_cmd_is_executable}

  ENGINE_ctrl_cmd: function(e: PENGINE; cmd_name: PIdAnsiChar; i: TIdC_LONG; p: Pointer; f: TENGINE_CTRL_FUNC_PTR_func_cb; cmd_optional: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_ctrl_cmd}

  ENGINE_ctrl_cmd_string: function(e: PENGINE; cmd_name: PIdAnsiChar; arg: PIdAnsiChar; cmd_optional: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_ctrl_cmd_string}

  ENGINE_new: function: PENGINE; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_new}

  ENGINE_free: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_free}

  ENGINE_up_ref: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_up_ref}

  ENGINE_set_id: function(e: PENGINE; id: PIdAnsiChar): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_id}

  ENGINE_set_name: function(e: PENGINE; name: PIdAnsiChar): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_name}

  ENGINE_set_RSA: function(e: PENGINE; rsa_meth: PRSA_METHOD): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_RSA}

  ENGINE_set_DSA: function(e: PENGINE; dsa_meth: PDSA_METHOD): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_DSA}

  ENGINE_set_EC: function(e: PENGINE; ecdsa_meth: PEC_KEY_METHOD): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_EC}

  ENGINE_set_DH: function(e: PENGINE; dh_meth: PDH_METHOD): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_DH}

  ENGINE_set_RAND: function(e: PENGINE; rand_meth: PRAND_METHOD): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_RAND}

  ENGINE_set_destroy_function: function(e: PENGINE; destroy_f: TENGINE_GEN_INT_FUNC_PTR): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_destroy_function}

  ENGINE_set_init_function: function(e: PENGINE; init_f: TENGINE_GEN_INT_FUNC_PTR): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_init_function}

  ENGINE_set_finish_function: function(e: PENGINE; finish_f: TENGINE_GEN_INT_FUNC_PTR): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_finish_function}

  ENGINE_set_ctrl_function: function(e: PENGINE; ctrl_f: TENGINE_CTRL_FUNC_PTR): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_ctrl_function}

  ENGINE_set_load_privkey_function: function(e: PENGINE; loadpriv_f: TENGINE_LOAD_KEY_PTR): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_load_privkey_function}

  ENGINE_set_load_pubkey_function: function(e: PENGINE; loadpub_f: TENGINE_LOAD_KEY_PTR): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_load_pubkey_function}

  ENGINE_set_load_ssl_client_cert_function: function(e: PENGINE; loadssl_f: TENGINE_SSL_CLIENT_CERT_PTR): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_load_ssl_client_cert_function}

  ENGINE_set_ciphers: function(e: PENGINE; f: TENGINE_CIPHERS_PTR): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_ciphers}

  ENGINE_set_digests: function(e: PENGINE; f: TENGINE_DIGESTS_PTR): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_digests}

  ENGINE_set_pkey_meths: function(e: PENGINE; f: TENGINE_PKEY_METHS_PTR): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_pkey_meths}

  ENGINE_set_pkey_asn1_meths: function(e: PENGINE; f: TENGINE_PKEY_ASN1_METHS_PTR): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_pkey_asn1_meths}

  ENGINE_set_flags: function(e: PENGINE; flags: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_flags}

  ENGINE_set_cmd_defns: function(e: PENGINE; defns: PENGINE_CMD_DEFN): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_cmd_defns}

  ENGINE_set_ex_data: function(e: PENGINE; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_ex_data}

  ENGINE_get_ex_data: function(e: PENGINE; idx: TIdC_INT): Pointer; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_ex_data}

  ENGINE_get_id: function(e: PENGINE): PIdAnsiChar; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_id}

  ENGINE_get_name: function(e: PENGINE): PIdAnsiChar; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_name}

  ENGINE_get_RSA: function(e: PENGINE): PRSA_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_RSA}

  ENGINE_get_DSA: function(e: PENGINE): PDSA_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_DSA}

  ENGINE_get_EC: function(e: PENGINE): PEC_KEY_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_EC}

  ENGINE_get_DH: function(e: PENGINE): PDH_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_DH}

  ENGINE_get_RAND: function(e: PENGINE): PRAND_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_RAND}

  ENGINE_get_destroy_function: function(e: PENGINE): TENGINE_GEN_INT_FUNC_PTR; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_destroy_function}

  ENGINE_get_init_function: function(e: PENGINE): TENGINE_GEN_INT_FUNC_PTR; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_init_function}

  ENGINE_get_finish_function: function(e: PENGINE): TENGINE_GEN_INT_FUNC_PTR; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_finish_function}

  ENGINE_get_ctrl_function: function(e: PENGINE): TENGINE_CTRL_FUNC_PTR; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_ctrl_function}

  ENGINE_get_load_privkey_function: function(e: PENGINE): TENGINE_LOAD_KEY_PTR; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_load_privkey_function}

  ENGINE_get_load_pubkey_function: function(e: PENGINE): TENGINE_LOAD_KEY_PTR; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_load_pubkey_function}

  ENGINE_get_ssl_client_cert_function: function(e: PENGINE): TENGINE_SSL_CLIENT_CERT_PTR; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_ssl_client_cert_function}

  ENGINE_get_ciphers: function(e: PENGINE): TENGINE_CIPHERS_PTR; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_ciphers}

  ENGINE_get_digests: function(e: PENGINE): TENGINE_DIGESTS_PTR; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_digests}

  ENGINE_get_pkey_meths: function(e: PENGINE): TENGINE_PKEY_METHS_PTR; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_pkey_meths}

  ENGINE_get_pkey_asn1_meths: function(e: PENGINE): TENGINE_PKEY_ASN1_METHS_PTR; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_pkey_asn1_meths}

  ENGINE_get_cipher: function(e: PENGINE; nid: TIdC_INT): PEVP_CIPHER; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_cipher}

  ENGINE_get_digest: function(e: PENGINE; nid: TIdC_INT): PEVP_MD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_digest}

  ENGINE_get_pkey_meth: function(e: PENGINE; nid: TIdC_INT): PEVP_PKEY_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_pkey_meth}

  ENGINE_get_pkey_asn1_meth: function(e: PENGINE; nid: TIdC_INT): PEVP_PKEY_ASN1_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_pkey_asn1_meth}

  ENGINE_get_pkey_asn1_meth_str: function(e: PENGINE; str: PIdAnsiChar; len: TIdC_INT): PEVP_PKEY_ASN1_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_pkey_asn1_meth_str}

  ENGINE_pkey_asn1_find_str: function(pe: PPENGINE; str: PIdAnsiChar; len: TIdC_INT): PEVP_PKEY_ASN1_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_pkey_asn1_find_str}

  ENGINE_get_cmd_defns: function(e: PENGINE): PENGINE_CMD_DEFN; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_cmd_defns}

  ENGINE_get_flags: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_flags}

  ENGINE_init: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_init}

  ENGINE_finish: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_finish}

  ENGINE_load_private_key: function(e: PENGINE; key_id: PIdAnsiChar; ui_method: PUI_METHOD; callback_data: Pointer): PEVP_PKEY; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_load_private_key}

  ENGINE_load_public_key: function(e: PENGINE; key_id: PIdAnsiChar; ui_method: PUI_METHOD; callback_data: Pointer): PEVP_PKEY; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_load_public_key}

  ENGINE_load_ssl_client_cert: function(e: PENGINE; s: PSSL; ca_dn: Pstack_st_X509_NAME; pcert: PPX509; ppkey: PPEVP_PKEY; pother: PPstack_st_X509; ui_method: PUI_METHOD; callback_data: Pointer): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_load_ssl_client_cert}

  ENGINE_get_default_RSA: function: PENGINE; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_default_RSA}

  ENGINE_get_default_DSA: function: PENGINE; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_default_DSA}

  ENGINE_get_default_EC: function: PENGINE; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_default_EC}

  ENGINE_get_default_DH: function: PENGINE; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_default_DH}

  ENGINE_get_default_RAND: function: PENGINE; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_default_RAND}

  ENGINE_get_cipher_engine: function(nid: TIdC_INT): PENGINE; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_cipher_engine}

  ENGINE_get_digest_engine: function(nid: TIdC_INT): PENGINE; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_digest_engine}

  ENGINE_get_pkey_meth_engine: function(nid: TIdC_INT): PENGINE; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_pkey_meth_engine}

  ENGINE_get_pkey_asn1_meth_engine: function(nid: TIdC_INT): PENGINE; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_get_pkey_asn1_meth_engine}

  ENGINE_set_default_RSA: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_default_RSA}

  ENGINE_set_default_string: function(e: PENGINE; def_list: PIdAnsiChar): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_default_string}

  ENGINE_set_default_DSA: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_default_DSA}

  ENGINE_set_default_EC: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_default_EC}

  ENGINE_set_default_DH: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_default_DH}

  ENGINE_set_default_RAND: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_default_RAND}

  ENGINE_set_default_ciphers: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_default_ciphers}

  ENGINE_set_default_digests: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_default_digests}

  ENGINE_set_default_pkey_meths: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_default_pkey_meths}

  ENGINE_set_default_pkey_asn1_meths: function(e: PENGINE): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_default_pkey_asn1_meths}

  ENGINE_set_default: function(e: PENGINE; flags: TIdC_UINT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_set_default}

  ENGINE_add_conf_module: procedure; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ENGINE_add_conf_module}

  ENGINE_get_static_state: function: Pointer; cdecl = nil;
  {$EXTERNALSYM ENGINE_get_static_state}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function ENGINE_get_first: PENGINE; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_last: PENGINE; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_next(e: PENGINE): PENGINE; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_prev(e: PENGINE): PENGINE; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_add(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_remove(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_by_id(id: PIdAnsiChar): PENGINE; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure ENGINE_load_builtin_engines; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_table_flags: TIdC_UINT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure ENGINE_set_table_flags(flags: TIdC_UINT); cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_register_RSA(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure ENGINE_unregister_RSA(e: PENGINE); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure ENGINE_register_all_RSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_register_DSA(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure ENGINE_unregister_DSA(e: PENGINE); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure ENGINE_register_all_DSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_register_EC(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure ENGINE_unregister_EC(e: PENGINE); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure ENGINE_register_all_EC; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_register_DH(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure ENGINE_unregister_DH(e: PENGINE); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure ENGINE_register_all_DH; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_register_RAND(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure ENGINE_unregister_RAND(e: PENGINE); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure ENGINE_register_all_RAND; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_register_ciphers(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure ENGINE_unregister_ciphers(e: PENGINE); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure ENGINE_register_all_ciphers; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_register_digests(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure ENGINE_unregister_digests(e: PENGINE); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure ENGINE_register_all_digests; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_register_pkey_meths(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure ENGINE_unregister_pkey_meths(e: PENGINE); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure ENGINE_register_all_pkey_meths; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_register_pkey_asn1_meths(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure ENGINE_unregister_pkey_asn1_meths(e: PENGINE); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure ENGINE_register_all_pkey_asn1_meths; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_register_complete(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_register_all_complete: TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_ctrl(e: PENGINE; cmd: TIdC_INT; i: TIdC_LONG; p: Pointer; f: TENGINE_CTRL_FUNC_PTR_func_cb): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_cmd_is_executable(e: PENGINE; cmd: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_ctrl_cmd(e: PENGINE; cmd_name: PIdAnsiChar; i: TIdC_LONG; p: Pointer; f: TENGINE_CTRL_FUNC_PTR_func_cb; cmd_optional: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_ctrl_cmd_string(e: PENGINE; cmd_name: PIdAnsiChar; arg: PIdAnsiChar; cmd_optional: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_new: PENGINE; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_free(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_up_ref(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_id(e: PENGINE; id: PIdAnsiChar): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_name(e: PENGINE; name: PIdAnsiChar): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_RSA(e: PENGINE; rsa_meth: PRSA_METHOD): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_DSA(e: PENGINE; dsa_meth: PDSA_METHOD): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_EC(e: PENGINE; ecdsa_meth: PEC_KEY_METHOD): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_DH(e: PENGINE; dh_meth: PDH_METHOD): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_RAND(e: PENGINE; rand_meth: PRAND_METHOD): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_destroy_function(e: PENGINE; destroy_f: TENGINE_GEN_INT_FUNC_PTR): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_init_function(e: PENGINE; init_f: TENGINE_GEN_INT_FUNC_PTR): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_finish_function(e: PENGINE; finish_f: TENGINE_GEN_INT_FUNC_PTR): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_ctrl_function(e: PENGINE; ctrl_f: TENGINE_CTRL_FUNC_PTR): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_load_privkey_function(e: PENGINE; loadpriv_f: TENGINE_LOAD_KEY_PTR): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_load_pubkey_function(e: PENGINE; loadpub_f: TENGINE_LOAD_KEY_PTR): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_load_ssl_client_cert_function(e: PENGINE; loadssl_f: TENGINE_SSL_CLIENT_CERT_PTR): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_ciphers(e: PENGINE; f: TENGINE_CIPHERS_PTR): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_digests(e: PENGINE; f: TENGINE_DIGESTS_PTR): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_pkey_meths(e: PENGINE; f: TENGINE_PKEY_METHS_PTR): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_pkey_asn1_meths(e: PENGINE; f: TENGINE_PKEY_ASN1_METHS_PTR): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_flags(e: PENGINE; flags: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_cmd_defns(e: PENGINE; defns: PENGINE_CMD_DEFN): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_ex_data(e: PENGINE; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_ex_data(e: PENGINE; idx: TIdC_INT): Pointer; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_id(e: PENGINE): PIdAnsiChar; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_name(e: PENGINE): PIdAnsiChar; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_RSA(e: PENGINE): PRSA_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_DSA(e: PENGINE): PDSA_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_EC(e: PENGINE): PEC_KEY_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_DH(e: PENGINE): PDH_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_RAND(e: PENGINE): PRAND_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_destroy_function(e: PENGINE): TENGINE_GEN_INT_FUNC_PTR; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_init_function(e: PENGINE): TENGINE_GEN_INT_FUNC_PTR; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_finish_function(e: PENGINE): TENGINE_GEN_INT_FUNC_PTR; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_ctrl_function(e: PENGINE): TENGINE_CTRL_FUNC_PTR; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_load_privkey_function(e: PENGINE): TENGINE_LOAD_KEY_PTR; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_load_pubkey_function(e: PENGINE): TENGINE_LOAD_KEY_PTR; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_ssl_client_cert_function(e: PENGINE): TENGINE_SSL_CLIENT_CERT_PTR; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_ciphers(e: PENGINE): TENGINE_CIPHERS_PTR; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_digests(e: PENGINE): TENGINE_DIGESTS_PTR; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_pkey_meths(e: PENGINE): TENGINE_PKEY_METHS_PTR; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_pkey_asn1_meths(e: PENGINE): TENGINE_PKEY_ASN1_METHS_PTR; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_cipher(e: PENGINE; nid: TIdC_INT): PEVP_CIPHER; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_digest(e: PENGINE; nid: TIdC_INT): PEVP_MD; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_pkey_meth(e: PENGINE; nid: TIdC_INT): PEVP_PKEY_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_pkey_asn1_meth(e: PENGINE; nid: TIdC_INT): PEVP_PKEY_ASN1_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_pkey_asn1_meth_str(e: PENGINE; str: PIdAnsiChar; len: TIdC_INT): PEVP_PKEY_ASN1_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_pkey_asn1_find_str(pe: PPENGINE; str: PIdAnsiChar; len: TIdC_INT): PEVP_PKEY_ASN1_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_cmd_defns(e: PENGINE): PENGINE_CMD_DEFN; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_flags(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_init(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_finish(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_load_private_key(e: PENGINE; key_id: PIdAnsiChar; ui_method: PUI_METHOD; callback_data: Pointer): PEVP_PKEY; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_load_public_key(e: PENGINE; key_id: PIdAnsiChar; ui_method: PUI_METHOD; callback_data: Pointer): PEVP_PKEY; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_load_ssl_client_cert(e: PENGINE; s: PSSL; ca_dn: Pstack_st_X509_NAME; pcert: PPX509; ppkey: PPEVP_PKEY; pother: PPstack_st_X509; ui_method: PUI_METHOD; callback_data: Pointer): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_default_RSA: PENGINE; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_default_DSA: PENGINE; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_default_EC: PENGINE; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_default_DH: PENGINE; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_default_RAND: PENGINE; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_cipher_engine(nid: TIdC_INT): PENGINE; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_digest_engine(nid: TIdC_INT): PENGINE; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_pkey_meth_engine(nid: TIdC_INT): PENGINE; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_pkey_asn1_meth_engine(nid: TIdC_INT): PENGINE; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_default_RSA(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_default_string(e: PENGINE; def_list: PIdAnsiChar): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_default_DSA(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_default_EC(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_default_DH(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_default_RAND(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_default_ciphers(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_default_digests(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_default_pkey_meths(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_default_pkey_asn1_meths(e: PENGINE): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_set_default(e: PENGINE; flags: TIdC_UINT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure ENGINE_add_conf_module; cdecl; deprecated 'In OpenSSL 3_0_0';
function ENGINE_get_static_state: Pointer; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function ENGINE_cleanup: TIdC_INT; cdecl;


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

function ENGINE_get_first: PENGINE; cdecl external CLibCrypto name 'ENGINE_get_first';
function ENGINE_get_last: PENGINE; cdecl external CLibCrypto name 'ENGINE_get_last';
function ENGINE_get_next(e: PENGINE): PENGINE; cdecl external CLibCrypto name 'ENGINE_get_next';
function ENGINE_get_prev(e: PENGINE): PENGINE; cdecl external CLibCrypto name 'ENGINE_get_prev';
function ENGINE_add(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_add';
function ENGINE_remove(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_remove';
function ENGINE_by_id(id: PIdAnsiChar): PENGINE; cdecl external CLibCrypto name 'ENGINE_by_id';
procedure ENGINE_load_builtin_engines; cdecl external CLibCrypto name 'ENGINE_load_builtin_engines';
function ENGINE_get_table_flags: TIdC_UINT; cdecl external CLibCrypto name 'ENGINE_get_table_flags';
procedure ENGINE_set_table_flags(flags: TIdC_UINT); cdecl external CLibCrypto name 'ENGINE_set_table_flags';
function ENGINE_register_RSA(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_register_RSA';
procedure ENGINE_unregister_RSA(e: PENGINE); cdecl external CLibCrypto name 'ENGINE_unregister_RSA';
procedure ENGINE_register_all_RSA; cdecl external CLibCrypto name 'ENGINE_register_all_RSA';
function ENGINE_register_DSA(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_register_DSA';
procedure ENGINE_unregister_DSA(e: PENGINE); cdecl external CLibCrypto name 'ENGINE_unregister_DSA';
procedure ENGINE_register_all_DSA; cdecl external CLibCrypto name 'ENGINE_register_all_DSA';
function ENGINE_register_EC(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_register_EC';
procedure ENGINE_unregister_EC(e: PENGINE); cdecl external CLibCrypto name 'ENGINE_unregister_EC';
procedure ENGINE_register_all_EC; cdecl external CLibCrypto name 'ENGINE_register_all_EC';
function ENGINE_register_DH(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_register_DH';
procedure ENGINE_unregister_DH(e: PENGINE); cdecl external CLibCrypto name 'ENGINE_unregister_DH';
procedure ENGINE_register_all_DH; cdecl external CLibCrypto name 'ENGINE_register_all_DH';
function ENGINE_register_RAND(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_register_RAND';
procedure ENGINE_unregister_RAND(e: PENGINE); cdecl external CLibCrypto name 'ENGINE_unregister_RAND';
procedure ENGINE_register_all_RAND; cdecl external CLibCrypto name 'ENGINE_register_all_RAND';
function ENGINE_register_ciphers(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_register_ciphers';
procedure ENGINE_unregister_ciphers(e: PENGINE); cdecl external CLibCrypto name 'ENGINE_unregister_ciphers';
procedure ENGINE_register_all_ciphers; cdecl external CLibCrypto name 'ENGINE_register_all_ciphers';
function ENGINE_register_digests(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_register_digests';
procedure ENGINE_unregister_digests(e: PENGINE); cdecl external CLibCrypto name 'ENGINE_unregister_digests';
procedure ENGINE_register_all_digests; cdecl external CLibCrypto name 'ENGINE_register_all_digests';
function ENGINE_register_pkey_meths(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_register_pkey_meths';
procedure ENGINE_unregister_pkey_meths(e: PENGINE); cdecl external CLibCrypto name 'ENGINE_unregister_pkey_meths';
procedure ENGINE_register_all_pkey_meths; cdecl external CLibCrypto name 'ENGINE_register_all_pkey_meths';
function ENGINE_register_pkey_asn1_meths(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_register_pkey_asn1_meths';
procedure ENGINE_unregister_pkey_asn1_meths(e: PENGINE); cdecl external CLibCrypto name 'ENGINE_unregister_pkey_asn1_meths';
procedure ENGINE_register_all_pkey_asn1_meths; cdecl external CLibCrypto name 'ENGINE_register_all_pkey_asn1_meths';
function ENGINE_register_complete(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_register_complete';
function ENGINE_register_all_complete: TIdC_INT; cdecl external CLibCrypto name 'ENGINE_register_all_complete';
function ENGINE_ctrl(e: PENGINE; cmd: TIdC_INT; i: TIdC_LONG; p: Pointer; f: TENGINE_CTRL_FUNC_PTR_func_cb): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_ctrl';
function ENGINE_cmd_is_executable(e: PENGINE; cmd: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_cmd_is_executable';
function ENGINE_ctrl_cmd(e: PENGINE; cmd_name: PIdAnsiChar; i: TIdC_LONG; p: Pointer; f: TENGINE_CTRL_FUNC_PTR_func_cb; cmd_optional: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_ctrl_cmd';
function ENGINE_ctrl_cmd_string(e: PENGINE; cmd_name: PIdAnsiChar; arg: PIdAnsiChar; cmd_optional: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_ctrl_cmd_string';
function ENGINE_new: PENGINE; cdecl external CLibCrypto name 'ENGINE_new';
function ENGINE_free(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_free';
function ENGINE_up_ref(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_up_ref';
function ENGINE_set_id(e: PENGINE; id: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_id';
function ENGINE_set_name(e: PENGINE; name: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_name';
function ENGINE_set_RSA(e: PENGINE; rsa_meth: PRSA_METHOD): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_RSA';
function ENGINE_set_DSA(e: PENGINE; dsa_meth: PDSA_METHOD): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_DSA';
function ENGINE_set_EC(e: PENGINE; ecdsa_meth: PEC_KEY_METHOD): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_EC';
function ENGINE_set_DH(e: PENGINE; dh_meth: PDH_METHOD): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_DH';
function ENGINE_set_RAND(e: PENGINE; rand_meth: PRAND_METHOD): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_RAND';
function ENGINE_set_destroy_function(e: PENGINE; destroy_f: TENGINE_GEN_INT_FUNC_PTR): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_destroy_function';
function ENGINE_set_init_function(e: PENGINE; init_f: TENGINE_GEN_INT_FUNC_PTR): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_init_function';
function ENGINE_set_finish_function(e: PENGINE; finish_f: TENGINE_GEN_INT_FUNC_PTR): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_finish_function';
function ENGINE_set_ctrl_function(e: PENGINE; ctrl_f: TENGINE_CTRL_FUNC_PTR): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_ctrl_function';
function ENGINE_set_load_privkey_function(e: PENGINE; loadpriv_f: TENGINE_LOAD_KEY_PTR): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_load_privkey_function';
function ENGINE_set_load_pubkey_function(e: PENGINE; loadpub_f: TENGINE_LOAD_KEY_PTR): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_load_pubkey_function';
function ENGINE_set_load_ssl_client_cert_function(e: PENGINE; loadssl_f: TENGINE_SSL_CLIENT_CERT_PTR): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_load_ssl_client_cert_function';
function ENGINE_set_ciphers(e: PENGINE; f: TENGINE_CIPHERS_PTR): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_ciphers';
function ENGINE_set_digests(e: PENGINE; f: TENGINE_DIGESTS_PTR): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_digests';
function ENGINE_set_pkey_meths(e: PENGINE; f: TENGINE_PKEY_METHS_PTR): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_pkey_meths';
function ENGINE_set_pkey_asn1_meths(e: PENGINE; f: TENGINE_PKEY_ASN1_METHS_PTR): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_pkey_asn1_meths';
function ENGINE_set_flags(e: PENGINE; flags: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_flags';
function ENGINE_set_cmd_defns(e: PENGINE; defns: PENGINE_CMD_DEFN): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_cmd_defns';
function ENGINE_set_ex_data(e: PENGINE; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_ex_data';
function ENGINE_get_ex_data(e: PENGINE; idx: TIdC_INT): Pointer; cdecl external CLibCrypto name 'ENGINE_get_ex_data';
function ENGINE_get_id(e: PENGINE): PIdAnsiChar; cdecl external CLibCrypto name 'ENGINE_get_id';
function ENGINE_get_name(e: PENGINE): PIdAnsiChar; cdecl external CLibCrypto name 'ENGINE_get_name';
function ENGINE_get_RSA(e: PENGINE): PRSA_METHOD; cdecl external CLibCrypto name 'ENGINE_get_RSA';
function ENGINE_get_DSA(e: PENGINE): PDSA_METHOD; cdecl external CLibCrypto name 'ENGINE_get_DSA';
function ENGINE_get_EC(e: PENGINE): PEC_KEY_METHOD; cdecl external CLibCrypto name 'ENGINE_get_EC';
function ENGINE_get_DH(e: PENGINE): PDH_METHOD; cdecl external CLibCrypto name 'ENGINE_get_DH';
function ENGINE_get_RAND(e: PENGINE): PRAND_METHOD; cdecl external CLibCrypto name 'ENGINE_get_RAND';
function ENGINE_get_destroy_function(e: PENGINE): TENGINE_GEN_INT_FUNC_PTR; cdecl external CLibCrypto name 'ENGINE_get_destroy_function';
function ENGINE_get_init_function(e: PENGINE): TENGINE_GEN_INT_FUNC_PTR; cdecl external CLibCrypto name 'ENGINE_get_init_function';
function ENGINE_get_finish_function(e: PENGINE): TENGINE_GEN_INT_FUNC_PTR; cdecl external CLibCrypto name 'ENGINE_get_finish_function';
function ENGINE_get_ctrl_function(e: PENGINE): TENGINE_CTRL_FUNC_PTR; cdecl external CLibCrypto name 'ENGINE_get_ctrl_function';
function ENGINE_get_load_privkey_function(e: PENGINE): TENGINE_LOAD_KEY_PTR; cdecl external CLibCrypto name 'ENGINE_get_load_privkey_function';
function ENGINE_get_load_pubkey_function(e: PENGINE): TENGINE_LOAD_KEY_PTR; cdecl external CLibCrypto name 'ENGINE_get_load_pubkey_function';
function ENGINE_get_ssl_client_cert_function(e: PENGINE): TENGINE_SSL_CLIENT_CERT_PTR; cdecl external CLibCrypto name 'ENGINE_get_ssl_client_cert_function';
function ENGINE_get_ciphers(e: PENGINE): TENGINE_CIPHERS_PTR; cdecl external CLibCrypto name 'ENGINE_get_ciphers';
function ENGINE_get_digests(e: PENGINE): TENGINE_DIGESTS_PTR; cdecl external CLibCrypto name 'ENGINE_get_digests';
function ENGINE_get_pkey_meths(e: PENGINE): TENGINE_PKEY_METHS_PTR; cdecl external CLibCrypto name 'ENGINE_get_pkey_meths';
function ENGINE_get_pkey_asn1_meths(e: PENGINE): TENGINE_PKEY_ASN1_METHS_PTR; cdecl external CLibCrypto name 'ENGINE_get_pkey_asn1_meths';
function ENGINE_get_cipher(e: PENGINE; nid: TIdC_INT): PEVP_CIPHER; cdecl external CLibCrypto name 'ENGINE_get_cipher';
function ENGINE_get_digest(e: PENGINE; nid: TIdC_INT): PEVP_MD; cdecl external CLibCrypto name 'ENGINE_get_digest';
function ENGINE_get_pkey_meth(e: PENGINE; nid: TIdC_INT): PEVP_PKEY_METHOD; cdecl external CLibCrypto name 'ENGINE_get_pkey_meth';
function ENGINE_get_pkey_asn1_meth(e: PENGINE; nid: TIdC_INT): PEVP_PKEY_ASN1_METHOD; cdecl external CLibCrypto name 'ENGINE_get_pkey_asn1_meth';
function ENGINE_get_pkey_asn1_meth_str(e: PENGINE; str: PIdAnsiChar; len: TIdC_INT): PEVP_PKEY_ASN1_METHOD; cdecl external CLibCrypto name 'ENGINE_get_pkey_asn1_meth_str';
function ENGINE_pkey_asn1_find_str(pe: PPENGINE; str: PIdAnsiChar; len: TIdC_INT): PEVP_PKEY_ASN1_METHOD; cdecl external CLibCrypto name 'ENGINE_pkey_asn1_find_str';
function ENGINE_get_cmd_defns(e: PENGINE): PENGINE_CMD_DEFN; cdecl external CLibCrypto name 'ENGINE_get_cmd_defns';
function ENGINE_get_flags(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_get_flags';
function ENGINE_init(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_init';
function ENGINE_finish(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_finish';
function ENGINE_load_private_key(e: PENGINE; key_id: PIdAnsiChar; ui_method: PUI_METHOD; callback_data: Pointer): PEVP_PKEY; cdecl external CLibCrypto name 'ENGINE_load_private_key';
function ENGINE_load_public_key(e: PENGINE; key_id: PIdAnsiChar; ui_method: PUI_METHOD; callback_data: Pointer): PEVP_PKEY; cdecl external CLibCrypto name 'ENGINE_load_public_key';
function ENGINE_load_ssl_client_cert(e: PENGINE; s: PSSL; ca_dn: Pstack_st_X509_NAME; pcert: PPX509; ppkey: PPEVP_PKEY; pother: PPstack_st_X509; ui_method: PUI_METHOD; callback_data: Pointer): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_load_ssl_client_cert';
function ENGINE_get_default_RSA: PENGINE; cdecl external CLibCrypto name 'ENGINE_get_default_RSA';
function ENGINE_get_default_DSA: PENGINE; cdecl external CLibCrypto name 'ENGINE_get_default_DSA';
function ENGINE_get_default_EC: PENGINE; cdecl external CLibCrypto name 'ENGINE_get_default_EC';
function ENGINE_get_default_DH: PENGINE; cdecl external CLibCrypto name 'ENGINE_get_default_DH';
function ENGINE_get_default_RAND: PENGINE; cdecl external CLibCrypto name 'ENGINE_get_default_RAND';
function ENGINE_get_cipher_engine(nid: TIdC_INT): PENGINE; cdecl external CLibCrypto name 'ENGINE_get_cipher_engine';
function ENGINE_get_digest_engine(nid: TIdC_INT): PENGINE; cdecl external CLibCrypto name 'ENGINE_get_digest_engine';
function ENGINE_get_pkey_meth_engine(nid: TIdC_INT): PENGINE; cdecl external CLibCrypto name 'ENGINE_get_pkey_meth_engine';
function ENGINE_get_pkey_asn1_meth_engine(nid: TIdC_INT): PENGINE; cdecl external CLibCrypto name 'ENGINE_get_pkey_asn1_meth_engine';
function ENGINE_set_default_RSA(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_default_RSA';
function ENGINE_set_default_string(e: PENGINE; def_list: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_default_string';
function ENGINE_set_default_DSA(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_default_DSA';
function ENGINE_set_default_EC(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_default_EC';
function ENGINE_set_default_DH(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_default_DH';
function ENGINE_set_default_RAND(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_default_RAND';
function ENGINE_set_default_ciphers(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_default_ciphers';
function ENGINE_set_default_digests(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_default_digests';
function ENGINE_set_default_pkey_meths(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_default_pkey_meths';
function ENGINE_set_default_pkey_asn1_meths(e: PENGINE): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_default_pkey_asn1_meths';
function ENGINE_set_default(e: PENGINE; flags: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'ENGINE_set_default';
procedure ENGINE_add_conf_module; cdecl external CLibCrypto name 'ENGINE_add_conf_module';
function ENGINE_get_static_state: Pointer; cdecl external CLibCrypto name 'ENGINE_get_static_state';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  ENGINE_get_first_procname = 'ENGINE_get_first';
  ENGINE_get_first_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_first_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_last_procname = 'ENGINE_get_last';
  ENGINE_get_last_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_last_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_next_procname = 'ENGINE_get_next';
  ENGINE_get_next_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_next_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_prev_procname = 'ENGINE_get_prev';
  ENGINE_get_prev_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_prev_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_add_procname = 'ENGINE_add';
  ENGINE_add_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_add_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_remove_procname = 'ENGINE_remove';
  ENGINE_remove_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_remove_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_by_id_procname = 'ENGINE_by_id';
  ENGINE_by_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_by_id_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_load_builtin_engines_procname = 'ENGINE_load_builtin_engines';
  ENGINE_load_builtin_engines_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_load_builtin_engines_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_table_flags_procname = 'ENGINE_get_table_flags';
  ENGINE_get_table_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_table_flags_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_table_flags_procname = 'ENGINE_set_table_flags';
  ENGINE_set_table_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_table_flags_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_register_RSA_procname = 'ENGINE_register_RSA';
  ENGINE_register_RSA_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_register_RSA_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_unregister_RSA_procname = 'ENGINE_unregister_RSA';
  ENGINE_unregister_RSA_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_unregister_RSA_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_register_all_RSA_procname = 'ENGINE_register_all_RSA';
  ENGINE_register_all_RSA_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_register_all_RSA_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_register_DSA_procname = 'ENGINE_register_DSA';
  ENGINE_register_DSA_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_register_DSA_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_unregister_DSA_procname = 'ENGINE_unregister_DSA';
  ENGINE_unregister_DSA_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_unregister_DSA_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_register_all_DSA_procname = 'ENGINE_register_all_DSA';
  ENGINE_register_all_DSA_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_register_all_DSA_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_register_EC_procname = 'ENGINE_register_EC';
  ENGINE_register_EC_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_register_EC_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_unregister_EC_procname = 'ENGINE_unregister_EC';
  ENGINE_unregister_EC_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_unregister_EC_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_register_all_EC_procname = 'ENGINE_register_all_EC';
  ENGINE_register_all_EC_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_register_all_EC_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_register_DH_procname = 'ENGINE_register_DH';
  ENGINE_register_DH_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_register_DH_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_unregister_DH_procname = 'ENGINE_unregister_DH';
  ENGINE_unregister_DH_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_unregister_DH_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_register_all_DH_procname = 'ENGINE_register_all_DH';
  ENGINE_register_all_DH_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_register_all_DH_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_register_RAND_procname = 'ENGINE_register_RAND';
  ENGINE_register_RAND_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_register_RAND_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_unregister_RAND_procname = 'ENGINE_unregister_RAND';
  ENGINE_unregister_RAND_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_unregister_RAND_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_register_all_RAND_procname = 'ENGINE_register_all_RAND';
  ENGINE_register_all_RAND_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_register_all_RAND_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_register_ciphers_procname = 'ENGINE_register_ciphers';
  ENGINE_register_ciphers_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_register_ciphers_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_unregister_ciphers_procname = 'ENGINE_unregister_ciphers';
  ENGINE_unregister_ciphers_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_unregister_ciphers_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_register_all_ciphers_procname = 'ENGINE_register_all_ciphers';
  ENGINE_register_all_ciphers_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_register_all_ciphers_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_register_digests_procname = 'ENGINE_register_digests';
  ENGINE_register_digests_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_register_digests_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_unregister_digests_procname = 'ENGINE_unregister_digests';
  ENGINE_unregister_digests_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_unregister_digests_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_register_all_digests_procname = 'ENGINE_register_all_digests';
  ENGINE_register_all_digests_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_register_all_digests_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_register_pkey_meths_procname = 'ENGINE_register_pkey_meths';
  ENGINE_register_pkey_meths_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_register_pkey_meths_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_unregister_pkey_meths_procname = 'ENGINE_unregister_pkey_meths';
  ENGINE_unregister_pkey_meths_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_unregister_pkey_meths_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_register_all_pkey_meths_procname = 'ENGINE_register_all_pkey_meths';
  ENGINE_register_all_pkey_meths_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_register_all_pkey_meths_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_register_pkey_asn1_meths_procname = 'ENGINE_register_pkey_asn1_meths';
  ENGINE_register_pkey_asn1_meths_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_register_pkey_asn1_meths_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_unregister_pkey_asn1_meths_procname = 'ENGINE_unregister_pkey_asn1_meths';
  ENGINE_unregister_pkey_asn1_meths_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_unregister_pkey_asn1_meths_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_register_all_pkey_asn1_meths_procname = 'ENGINE_register_all_pkey_asn1_meths';
  ENGINE_register_all_pkey_asn1_meths_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_register_all_pkey_asn1_meths_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_register_complete_procname = 'ENGINE_register_complete';
  ENGINE_register_complete_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_register_complete_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_register_all_complete_procname = 'ENGINE_register_all_complete';
  ENGINE_register_all_complete_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_register_all_complete_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_ctrl_procname = 'ENGINE_ctrl';
  ENGINE_ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_ctrl_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_cmd_is_executable_procname = 'ENGINE_cmd_is_executable';
  ENGINE_cmd_is_executable_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_cmd_is_executable_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_ctrl_cmd_procname = 'ENGINE_ctrl_cmd';
  ENGINE_ctrl_cmd_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_ctrl_cmd_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_ctrl_cmd_string_procname = 'ENGINE_ctrl_cmd_string';
  ENGINE_ctrl_cmd_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_ctrl_cmd_string_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_new_procname = 'ENGINE_new';
  ENGINE_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_new_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_free_procname = 'ENGINE_free';
  ENGINE_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_free_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_up_ref_procname = 'ENGINE_up_ref';
  ENGINE_up_ref_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_up_ref_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_id_procname = 'ENGINE_set_id';
  ENGINE_set_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_id_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_name_procname = 'ENGINE_set_name';
  ENGINE_set_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_name_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_RSA_procname = 'ENGINE_set_RSA';
  ENGINE_set_RSA_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_RSA_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_DSA_procname = 'ENGINE_set_DSA';
  ENGINE_set_DSA_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_DSA_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_EC_procname = 'ENGINE_set_EC';
  ENGINE_set_EC_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_EC_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_DH_procname = 'ENGINE_set_DH';
  ENGINE_set_DH_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_DH_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_RAND_procname = 'ENGINE_set_RAND';
  ENGINE_set_RAND_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_RAND_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_destroy_function_procname = 'ENGINE_set_destroy_function';
  ENGINE_set_destroy_function_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_destroy_function_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_init_function_procname = 'ENGINE_set_init_function';
  ENGINE_set_init_function_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_init_function_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_finish_function_procname = 'ENGINE_set_finish_function';
  ENGINE_set_finish_function_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_finish_function_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_ctrl_function_procname = 'ENGINE_set_ctrl_function';
  ENGINE_set_ctrl_function_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_ctrl_function_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_load_privkey_function_procname = 'ENGINE_set_load_privkey_function';
  ENGINE_set_load_privkey_function_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_load_privkey_function_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_load_pubkey_function_procname = 'ENGINE_set_load_pubkey_function';
  ENGINE_set_load_pubkey_function_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_load_pubkey_function_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_load_ssl_client_cert_function_procname = 'ENGINE_set_load_ssl_client_cert_function';
  ENGINE_set_load_ssl_client_cert_function_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_load_ssl_client_cert_function_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_ciphers_procname = 'ENGINE_set_ciphers';
  ENGINE_set_ciphers_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_ciphers_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_digests_procname = 'ENGINE_set_digests';
  ENGINE_set_digests_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_digests_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_pkey_meths_procname = 'ENGINE_set_pkey_meths';
  ENGINE_set_pkey_meths_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_pkey_meths_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_pkey_asn1_meths_procname = 'ENGINE_set_pkey_asn1_meths';
  ENGINE_set_pkey_asn1_meths_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_pkey_asn1_meths_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_flags_procname = 'ENGINE_set_flags';
  ENGINE_set_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_flags_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_cmd_defns_procname = 'ENGINE_set_cmd_defns';
  ENGINE_set_cmd_defns_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_cmd_defns_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_ex_data_procname = 'ENGINE_set_ex_data';
  ENGINE_set_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_ex_data_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_ex_data_procname = 'ENGINE_get_ex_data';
  ENGINE_get_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_ex_data_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_id_procname = 'ENGINE_get_id';
  ENGINE_get_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_id_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_name_procname = 'ENGINE_get_name';
  ENGINE_get_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_name_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_RSA_procname = 'ENGINE_get_RSA';
  ENGINE_get_RSA_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_RSA_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_DSA_procname = 'ENGINE_get_DSA';
  ENGINE_get_DSA_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_DSA_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_EC_procname = 'ENGINE_get_EC';
  ENGINE_get_EC_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_EC_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_DH_procname = 'ENGINE_get_DH';
  ENGINE_get_DH_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_DH_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_RAND_procname = 'ENGINE_get_RAND';
  ENGINE_get_RAND_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_RAND_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_destroy_function_procname = 'ENGINE_get_destroy_function';
  ENGINE_get_destroy_function_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_destroy_function_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_init_function_procname = 'ENGINE_get_init_function';
  ENGINE_get_init_function_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_init_function_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_finish_function_procname = 'ENGINE_get_finish_function';
  ENGINE_get_finish_function_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_finish_function_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_ctrl_function_procname = 'ENGINE_get_ctrl_function';
  ENGINE_get_ctrl_function_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_ctrl_function_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_load_privkey_function_procname = 'ENGINE_get_load_privkey_function';
  ENGINE_get_load_privkey_function_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_load_privkey_function_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_load_pubkey_function_procname = 'ENGINE_get_load_pubkey_function';
  ENGINE_get_load_pubkey_function_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_load_pubkey_function_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_ssl_client_cert_function_procname = 'ENGINE_get_ssl_client_cert_function';
  ENGINE_get_ssl_client_cert_function_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_ssl_client_cert_function_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_ciphers_procname = 'ENGINE_get_ciphers';
  ENGINE_get_ciphers_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_ciphers_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_digests_procname = 'ENGINE_get_digests';
  ENGINE_get_digests_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_digests_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_pkey_meths_procname = 'ENGINE_get_pkey_meths';
  ENGINE_get_pkey_meths_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_pkey_meths_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_pkey_asn1_meths_procname = 'ENGINE_get_pkey_asn1_meths';
  ENGINE_get_pkey_asn1_meths_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_pkey_asn1_meths_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_cipher_procname = 'ENGINE_get_cipher';
  ENGINE_get_cipher_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_cipher_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_digest_procname = 'ENGINE_get_digest';
  ENGINE_get_digest_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_digest_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_pkey_meth_procname = 'ENGINE_get_pkey_meth';
  ENGINE_get_pkey_meth_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_pkey_meth_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_pkey_asn1_meth_procname = 'ENGINE_get_pkey_asn1_meth';
  ENGINE_get_pkey_asn1_meth_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_pkey_asn1_meth_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_pkey_asn1_meth_str_procname = 'ENGINE_get_pkey_asn1_meth_str';
  ENGINE_get_pkey_asn1_meth_str_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_pkey_asn1_meth_str_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_pkey_asn1_find_str_procname = 'ENGINE_pkey_asn1_find_str';
  ENGINE_pkey_asn1_find_str_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_pkey_asn1_find_str_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_cmd_defns_procname = 'ENGINE_get_cmd_defns';
  ENGINE_get_cmd_defns_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_cmd_defns_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_flags_procname = 'ENGINE_get_flags';
  ENGINE_get_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_flags_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_init_procname = 'ENGINE_init';
  ENGINE_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_init_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_finish_procname = 'ENGINE_finish';
  ENGINE_finish_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_finish_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_load_private_key_procname = 'ENGINE_load_private_key';
  ENGINE_load_private_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_load_private_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_load_public_key_procname = 'ENGINE_load_public_key';
  ENGINE_load_public_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_load_public_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_load_ssl_client_cert_procname = 'ENGINE_load_ssl_client_cert';
  ENGINE_load_ssl_client_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_load_ssl_client_cert_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_default_RSA_procname = 'ENGINE_get_default_RSA';
  ENGINE_get_default_RSA_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_default_RSA_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_default_DSA_procname = 'ENGINE_get_default_DSA';
  ENGINE_get_default_DSA_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_default_DSA_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_default_EC_procname = 'ENGINE_get_default_EC';
  ENGINE_get_default_EC_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_default_EC_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_default_DH_procname = 'ENGINE_get_default_DH';
  ENGINE_get_default_DH_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_default_DH_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_default_RAND_procname = 'ENGINE_get_default_RAND';
  ENGINE_get_default_RAND_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_default_RAND_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_cipher_engine_procname = 'ENGINE_get_cipher_engine';
  ENGINE_get_cipher_engine_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_cipher_engine_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_digest_engine_procname = 'ENGINE_get_digest_engine';
  ENGINE_get_digest_engine_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_digest_engine_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_pkey_meth_engine_procname = 'ENGINE_get_pkey_meth_engine';
  ENGINE_get_pkey_meth_engine_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_pkey_meth_engine_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_pkey_asn1_meth_engine_procname = 'ENGINE_get_pkey_asn1_meth_engine';
  ENGINE_get_pkey_asn1_meth_engine_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_get_pkey_asn1_meth_engine_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_default_RSA_procname = 'ENGINE_set_default_RSA';
  ENGINE_set_default_RSA_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_default_RSA_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_default_string_procname = 'ENGINE_set_default_string';
  ENGINE_set_default_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_default_string_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_default_DSA_procname = 'ENGINE_set_default_DSA';
  ENGINE_set_default_DSA_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_default_DSA_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_default_EC_procname = 'ENGINE_set_default_EC';
  ENGINE_set_default_EC_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_default_EC_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_default_DH_procname = 'ENGINE_set_default_DH';
  ENGINE_set_default_DH_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_default_DH_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_default_RAND_procname = 'ENGINE_set_default_RAND';
  ENGINE_set_default_RAND_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_default_RAND_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_default_ciphers_procname = 'ENGINE_set_default_ciphers';
  ENGINE_set_default_ciphers_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_default_ciphers_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_default_digests_procname = 'ENGINE_set_default_digests';
  ENGINE_set_default_digests_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_default_digests_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_default_pkey_meths_procname = 'ENGINE_set_default_pkey_meths';
  ENGINE_set_default_pkey_meths_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_default_pkey_meths_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_default_pkey_asn1_meths_procname = 'ENGINE_set_default_pkey_asn1_meths';
  ENGINE_set_default_pkey_asn1_meths_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_default_pkey_asn1_meths_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_set_default_procname = 'ENGINE_set_default';
  ENGINE_set_default_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_set_default_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_add_conf_module_procname = 'ENGINE_add_conf_module';
  ENGINE_add_conf_module_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ENGINE_add_conf_module_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ENGINE_get_static_state_procname = 'ENGINE_get_static_state';
  ENGINE_get_static_state_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function ENGINE_cleanup: TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    ENGINE_cleanup() \
    while (0)            \
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

function ERR_ENGINE_get_first: PENGINE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_first_procname);
end;

function ERR_ENGINE_get_last: PENGINE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_last_procname);
end;

function ERR_ENGINE_get_next(e: PENGINE): PENGINE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_next_procname);
end;

function ERR_ENGINE_get_prev(e: PENGINE): PENGINE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_prev_procname);
end;

function ERR_ENGINE_add(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_add_procname);
end;

function ERR_ENGINE_remove(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_remove_procname);
end;

function ERR_ENGINE_by_id(id: PIdAnsiChar): PENGINE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_by_id_procname);
end;

procedure ERR_ENGINE_load_builtin_engines; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_load_builtin_engines_procname);
end;

function ERR_ENGINE_get_table_flags: TIdC_UINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_table_flags_procname);
end;

procedure ERR_ENGINE_set_table_flags(flags: TIdC_UINT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_table_flags_procname);
end;

function ERR_ENGINE_register_RSA(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_RSA_procname);
end;

procedure ERR_ENGINE_unregister_RSA(e: PENGINE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_unregister_RSA_procname);
end;

procedure ERR_ENGINE_register_all_RSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_all_RSA_procname);
end;

function ERR_ENGINE_register_DSA(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_DSA_procname);
end;

procedure ERR_ENGINE_unregister_DSA(e: PENGINE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_unregister_DSA_procname);
end;

procedure ERR_ENGINE_register_all_DSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_all_DSA_procname);
end;

function ERR_ENGINE_register_EC(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_EC_procname);
end;

procedure ERR_ENGINE_unregister_EC(e: PENGINE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_unregister_EC_procname);
end;

procedure ERR_ENGINE_register_all_EC; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_all_EC_procname);
end;

function ERR_ENGINE_register_DH(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_DH_procname);
end;

procedure ERR_ENGINE_unregister_DH(e: PENGINE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_unregister_DH_procname);
end;

procedure ERR_ENGINE_register_all_DH; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_all_DH_procname);
end;

function ERR_ENGINE_register_RAND(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_RAND_procname);
end;

procedure ERR_ENGINE_unregister_RAND(e: PENGINE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_unregister_RAND_procname);
end;

procedure ERR_ENGINE_register_all_RAND; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_all_RAND_procname);
end;

function ERR_ENGINE_register_ciphers(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_ciphers_procname);
end;

procedure ERR_ENGINE_unregister_ciphers(e: PENGINE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_unregister_ciphers_procname);
end;

procedure ERR_ENGINE_register_all_ciphers; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_all_ciphers_procname);
end;

function ERR_ENGINE_register_digests(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_digests_procname);
end;

procedure ERR_ENGINE_unregister_digests(e: PENGINE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_unregister_digests_procname);
end;

procedure ERR_ENGINE_register_all_digests; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_all_digests_procname);
end;

function ERR_ENGINE_register_pkey_meths(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_pkey_meths_procname);
end;

procedure ERR_ENGINE_unregister_pkey_meths(e: PENGINE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_unregister_pkey_meths_procname);
end;

procedure ERR_ENGINE_register_all_pkey_meths; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_all_pkey_meths_procname);
end;

function ERR_ENGINE_register_pkey_asn1_meths(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_pkey_asn1_meths_procname);
end;

procedure ERR_ENGINE_unregister_pkey_asn1_meths(e: PENGINE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_unregister_pkey_asn1_meths_procname);
end;

procedure ERR_ENGINE_register_all_pkey_asn1_meths; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_all_pkey_asn1_meths_procname);
end;

function ERR_ENGINE_register_complete(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_complete_procname);
end;

function ERR_ENGINE_register_all_complete: TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_register_all_complete_procname);
end;

function ERR_ENGINE_ctrl(e: PENGINE; cmd: TIdC_INT; i: TIdC_LONG; p: Pointer; f: TENGINE_CTRL_FUNC_PTR_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_ctrl_procname);
end;

function ERR_ENGINE_cmd_is_executable(e: PENGINE; cmd: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_cmd_is_executable_procname);
end;

function ERR_ENGINE_ctrl_cmd(e: PENGINE; cmd_name: PIdAnsiChar; i: TIdC_LONG; p: Pointer; f: TENGINE_CTRL_FUNC_PTR_func_cb; cmd_optional: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_ctrl_cmd_procname);
end;

function ERR_ENGINE_ctrl_cmd_string(e: PENGINE; cmd_name: PIdAnsiChar; arg: PIdAnsiChar; cmd_optional: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_ctrl_cmd_string_procname);
end;

function ERR_ENGINE_new: PENGINE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_new_procname);
end;

function ERR_ENGINE_free(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_free_procname);
end;

function ERR_ENGINE_up_ref(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_up_ref_procname);
end;

function ERR_ENGINE_set_id(e: PENGINE; id: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_id_procname);
end;

function ERR_ENGINE_set_name(e: PENGINE; name: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_name_procname);
end;

function ERR_ENGINE_set_RSA(e: PENGINE; rsa_meth: PRSA_METHOD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_RSA_procname);
end;

function ERR_ENGINE_set_DSA(e: PENGINE; dsa_meth: PDSA_METHOD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_DSA_procname);
end;

function ERR_ENGINE_set_EC(e: PENGINE; ecdsa_meth: PEC_KEY_METHOD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_EC_procname);
end;

function ERR_ENGINE_set_DH(e: PENGINE; dh_meth: PDH_METHOD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_DH_procname);
end;

function ERR_ENGINE_set_RAND(e: PENGINE; rand_meth: PRAND_METHOD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_RAND_procname);
end;

function ERR_ENGINE_set_destroy_function(e: PENGINE; destroy_f: TENGINE_GEN_INT_FUNC_PTR): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_destroy_function_procname);
end;

function ERR_ENGINE_set_init_function(e: PENGINE; init_f: TENGINE_GEN_INT_FUNC_PTR): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_init_function_procname);
end;

function ERR_ENGINE_set_finish_function(e: PENGINE; finish_f: TENGINE_GEN_INT_FUNC_PTR): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_finish_function_procname);
end;

function ERR_ENGINE_set_ctrl_function(e: PENGINE; ctrl_f: TENGINE_CTRL_FUNC_PTR): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_ctrl_function_procname);
end;

function ERR_ENGINE_set_load_privkey_function(e: PENGINE; loadpriv_f: TENGINE_LOAD_KEY_PTR): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_load_privkey_function_procname);
end;

function ERR_ENGINE_set_load_pubkey_function(e: PENGINE; loadpub_f: TENGINE_LOAD_KEY_PTR): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_load_pubkey_function_procname);
end;

function ERR_ENGINE_set_load_ssl_client_cert_function(e: PENGINE; loadssl_f: TENGINE_SSL_CLIENT_CERT_PTR): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_load_ssl_client_cert_function_procname);
end;

function ERR_ENGINE_set_ciphers(e: PENGINE; f: TENGINE_CIPHERS_PTR): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_ciphers_procname);
end;

function ERR_ENGINE_set_digests(e: PENGINE; f: TENGINE_DIGESTS_PTR): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_digests_procname);
end;

function ERR_ENGINE_set_pkey_meths(e: PENGINE; f: TENGINE_PKEY_METHS_PTR): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_pkey_meths_procname);
end;

function ERR_ENGINE_set_pkey_asn1_meths(e: PENGINE; f: TENGINE_PKEY_ASN1_METHS_PTR): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_pkey_asn1_meths_procname);
end;

function ERR_ENGINE_set_flags(e: PENGINE; flags: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_flags_procname);
end;

function ERR_ENGINE_set_cmd_defns(e: PENGINE; defns: PENGINE_CMD_DEFN): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_cmd_defns_procname);
end;

function ERR_ENGINE_set_ex_data(e: PENGINE; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_ex_data_procname);
end;

function ERR_ENGINE_get_ex_data(e: PENGINE; idx: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_ex_data_procname);
end;

function ERR_ENGINE_get_id(e: PENGINE): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_id_procname);
end;

function ERR_ENGINE_get_name(e: PENGINE): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_name_procname);
end;

function ERR_ENGINE_get_RSA(e: PENGINE): PRSA_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_RSA_procname);
end;

function ERR_ENGINE_get_DSA(e: PENGINE): PDSA_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_DSA_procname);
end;

function ERR_ENGINE_get_EC(e: PENGINE): PEC_KEY_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_EC_procname);
end;

function ERR_ENGINE_get_DH(e: PENGINE): PDH_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_DH_procname);
end;

function ERR_ENGINE_get_RAND(e: PENGINE): PRAND_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_RAND_procname);
end;

function ERR_ENGINE_get_destroy_function(e: PENGINE): TENGINE_GEN_INT_FUNC_PTR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_destroy_function_procname);
end;

function ERR_ENGINE_get_init_function(e: PENGINE): TENGINE_GEN_INT_FUNC_PTR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_init_function_procname);
end;

function ERR_ENGINE_get_finish_function(e: PENGINE): TENGINE_GEN_INT_FUNC_PTR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_finish_function_procname);
end;

function ERR_ENGINE_get_ctrl_function(e: PENGINE): TENGINE_CTRL_FUNC_PTR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_ctrl_function_procname);
end;

function ERR_ENGINE_get_load_privkey_function(e: PENGINE): TENGINE_LOAD_KEY_PTR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_load_privkey_function_procname);
end;

function ERR_ENGINE_get_load_pubkey_function(e: PENGINE): TENGINE_LOAD_KEY_PTR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_load_pubkey_function_procname);
end;

function ERR_ENGINE_get_ssl_client_cert_function(e: PENGINE): TENGINE_SSL_CLIENT_CERT_PTR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_ssl_client_cert_function_procname);
end;

function ERR_ENGINE_get_ciphers(e: PENGINE): TENGINE_CIPHERS_PTR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_ciphers_procname);
end;

function ERR_ENGINE_get_digests(e: PENGINE): TENGINE_DIGESTS_PTR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_digests_procname);
end;

function ERR_ENGINE_get_pkey_meths(e: PENGINE): TENGINE_PKEY_METHS_PTR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_pkey_meths_procname);
end;

function ERR_ENGINE_get_pkey_asn1_meths(e: PENGINE): TENGINE_PKEY_ASN1_METHS_PTR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_pkey_asn1_meths_procname);
end;

function ERR_ENGINE_get_cipher(e: PENGINE; nid: TIdC_INT): PEVP_CIPHER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_cipher_procname);
end;

function ERR_ENGINE_get_digest(e: PENGINE; nid: TIdC_INT): PEVP_MD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_digest_procname);
end;

function ERR_ENGINE_get_pkey_meth(e: PENGINE; nid: TIdC_INT): PEVP_PKEY_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_pkey_meth_procname);
end;

function ERR_ENGINE_get_pkey_asn1_meth(e: PENGINE; nid: TIdC_INT): PEVP_PKEY_ASN1_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_pkey_asn1_meth_procname);
end;

function ERR_ENGINE_get_pkey_asn1_meth_str(e: PENGINE; str: PIdAnsiChar; len: TIdC_INT): PEVP_PKEY_ASN1_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_pkey_asn1_meth_str_procname);
end;

function ERR_ENGINE_pkey_asn1_find_str(pe: PPENGINE; str: PIdAnsiChar; len: TIdC_INT): PEVP_PKEY_ASN1_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_pkey_asn1_find_str_procname);
end;

function ERR_ENGINE_get_cmd_defns(e: PENGINE): PENGINE_CMD_DEFN; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_cmd_defns_procname);
end;

function ERR_ENGINE_get_flags(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_flags_procname);
end;

function ERR_ENGINE_init(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_init_procname);
end;

function ERR_ENGINE_finish(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_finish_procname);
end;

function ERR_ENGINE_load_private_key(e: PENGINE; key_id: PIdAnsiChar; ui_method: PUI_METHOD; callback_data: Pointer): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_load_private_key_procname);
end;

function ERR_ENGINE_load_public_key(e: PENGINE; key_id: PIdAnsiChar; ui_method: PUI_METHOD; callback_data: Pointer): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_load_public_key_procname);
end;

function ERR_ENGINE_load_ssl_client_cert(e: PENGINE; s: PSSL; ca_dn: Pstack_st_X509_NAME; pcert: PPX509; ppkey: PPEVP_PKEY; pother: PPstack_st_X509; ui_method: PUI_METHOD; callback_data: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_load_ssl_client_cert_procname);
end;

function ERR_ENGINE_get_default_RSA: PENGINE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_default_RSA_procname);
end;

function ERR_ENGINE_get_default_DSA: PENGINE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_default_DSA_procname);
end;

function ERR_ENGINE_get_default_EC: PENGINE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_default_EC_procname);
end;

function ERR_ENGINE_get_default_DH: PENGINE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_default_DH_procname);
end;

function ERR_ENGINE_get_default_RAND: PENGINE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_default_RAND_procname);
end;

function ERR_ENGINE_get_cipher_engine(nid: TIdC_INT): PENGINE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_cipher_engine_procname);
end;

function ERR_ENGINE_get_digest_engine(nid: TIdC_INT): PENGINE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_digest_engine_procname);
end;

function ERR_ENGINE_get_pkey_meth_engine(nid: TIdC_INT): PENGINE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_pkey_meth_engine_procname);
end;

function ERR_ENGINE_get_pkey_asn1_meth_engine(nid: TIdC_INT): PENGINE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_pkey_asn1_meth_engine_procname);
end;

function ERR_ENGINE_set_default_RSA(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_default_RSA_procname);
end;

function ERR_ENGINE_set_default_string(e: PENGINE; def_list: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_default_string_procname);
end;

function ERR_ENGINE_set_default_DSA(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_default_DSA_procname);
end;

function ERR_ENGINE_set_default_EC(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_default_EC_procname);
end;

function ERR_ENGINE_set_default_DH(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_default_DH_procname);
end;

function ERR_ENGINE_set_default_RAND(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_default_RAND_procname);
end;

function ERR_ENGINE_set_default_ciphers(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_default_ciphers_procname);
end;

function ERR_ENGINE_set_default_digests(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_default_digests_procname);
end;

function ERR_ENGINE_set_default_pkey_meths(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_default_pkey_meths_procname);
end;

function ERR_ENGINE_set_default_pkey_asn1_meths(e: PENGINE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_default_pkey_asn1_meths_procname);
end;

function ERR_ENGINE_set_default(e: PENGINE; flags: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_set_default_procname);
end;

procedure ERR_ENGINE_add_conf_module; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_add_conf_module_procname);
end;

function ERR_ENGINE_get_static_state: Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ENGINE_get_static_state_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  ENGINE_get_first := LoadLibFunction(ADllHandle, ENGINE_get_first_procname);
  FuncLoadError := not assigned(ENGINE_get_first);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_first_allownil)}
    ENGINE_get_first := ERR_ENGINE_get_first;
    {$ifend}
    {$if declared(ENGINE_get_first_introduced)}
    if LibVersion < ENGINE_get_first_introduced then
    begin
      {$if declared(FC_ENGINE_get_first)}
      ENGINE_get_first := FC_ENGINE_get_first;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_first_removed)}
    if ENGINE_get_first_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_first)}
      ENGINE_get_first := _ENGINE_get_first;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_first_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_first');
    {$ifend}
  end;
  
  ENGINE_get_last := LoadLibFunction(ADllHandle, ENGINE_get_last_procname);
  FuncLoadError := not assigned(ENGINE_get_last);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_last_allownil)}
    ENGINE_get_last := ERR_ENGINE_get_last;
    {$ifend}
    {$if declared(ENGINE_get_last_introduced)}
    if LibVersion < ENGINE_get_last_introduced then
    begin
      {$if declared(FC_ENGINE_get_last)}
      ENGINE_get_last := FC_ENGINE_get_last;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_last_removed)}
    if ENGINE_get_last_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_last)}
      ENGINE_get_last := _ENGINE_get_last;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_last_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_last');
    {$ifend}
  end;
  
  ENGINE_get_next := LoadLibFunction(ADllHandle, ENGINE_get_next_procname);
  FuncLoadError := not assigned(ENGINE_get_next);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_next_allownil)}
    ENGINE_get_next := ERR_ENGINE_get_next;
    {$ifend}
    {$if declared(ENGINE_get_next_introduced)}
    if LibVersion < ENGINE_get_next_introduced then
    begin
      {$if declared(FC_ENGINE_get_next)}
      ENGINE_get_next := FC_ENGINE_get_next;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_next_removed)}
    if ENGINE_get_next_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_next)}
      ENGINE_get_next := _ENGINE_get_next;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_next_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_next');
    {$ifend}
  end;
  
  ENGINE_get_prev := LoadLibFunction(ADllHandle, ENGINE_get_prev_procname);
  FuncLoadError := not assigned(ENGINE_get_prev);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_prev_allownil)}
    ENGINE_get_prev := ERR_ENGINE_get_prev;
    {$ifend}
    {$if declared(ENGINE_get_prev_introduced)}
    if LibVersion < ENGINE_get_prev_introduced then
    begin
      {$if declared(FC_ENGINE_get_prev)}
      ENGINE_get_prev := FC_ENGINE_get_prev;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_prev_removed)}
    if ENGINE_get_prev_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_prev)}
      ENGINE_get_prev := _ENGINE_get_prev;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_prev_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_prev');
    {$ifend}
  end;
  
  ENGINE_add := LoadLibFunction(ADllHandle, ENGINE_add_procname);
  FuncLoadError := not assigned(ENGINE_add);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_add_allownil)}
    ENGINE_add := ERR_ENGINE_add;
    {$ifend}
    {$if declared(ENGINE_add_introduced)}
    if LibVersion < ENGINE_add_introduced then
    begin
      {$if declared(FC_ENGINE_add)}
      ENGINE_add := FC_ENGINE_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_add_removed)}
    if ENGINE_add_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_add)}
      ENGINE_add := _ENGINE_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_add_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_add');
    {$ifend}
  end;
  
  ENGINE_remove := LoadLibFunction(ADllHandle, ENGINE_remove_procname);
  FuncLoadError := not assigned(ENGINE_remove);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_remove_allownil)}
    ENGINE_remove := ERR_ENGINE_remove;
    {$ifend}
    {$if declared(ENGINE_remove_introduced)}
    if LibVersion < ENGINE_remove_introduced then
    begin
      {$if declared(FC_ENGINE_remove)}
      ENGINE_remove := FC_ENGINE_remove;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_remove_removed)}
    if ENGINE_remove_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_remove)}
      ENGINE_remove := _ENGINE_remove;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_remove_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_remove');
    {$ifend}
  end;
  
  ENGINE_by_id := LoadLibFunction(ADllHandle, ENGINE_by_id_procname);
  FuncLoadError := not assigned(ENGINE_by_id);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_by_id_allownil)}
    ENGINE_by_id := ERR_ENGINE_by_id;
    {$ifend}
    {$if declared(ENGINE_by_id_introduced)}
    if LibVersion < ENGINE_by_id_introduced then
    begin
      {$if declared(FC_ENGINE_by_id)}
      ENGINE_by_id := FC_ENGINE_by_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_by_id_removed)}
    if ENGINE_by_id_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_by_id)}
      ENGINE_by_id := _ENGINE_by_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_by_id_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_by_id');
    {$ifend}
  end;
  
  ENGINE_load_builtin_engines := LoadLibFunction(ADllHandle, ENGINE_load_builtin_engines_procname);
  FuncLoadError := not assigned(ENGINE_load_builtin_engines);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_load_builtin_engines_allownil)}
    ENGINE_load_builtin_engines := ERR_ENGINE_load_builtin_engines;
    {$ifend}
    {$if declared(ENGINE_load_builtin_engines_introduced)}
    if LibVersion < ENGINE_load_builtin_engines_introduced then
    begin
      {$if declared(FC_ENGINE_load_builtin_engines)}
      ENGINE_load_builtin_engines := FC_ENGINE_load_builtin_engines;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_load_builtin_engines_removed)}
    if ENGINE_load_builtin_engines_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_load_builtin_engines)}
      ENGINE_load_builtin_engines := _ENGINE_load_builtin_engines;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_load_builtin_engines_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_load_builtin_engines');
    {$ifend}
  end;
  
  ENGINE_get_table_flags := LoadLibFunction(ADllHandle, ENGINE_get_table_flags_procname);
  FuncLoadError := not assigned(ENGINE_get_table_flags);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_table_flags_allownil)}
    ENGINE_get_table_flags := ERR_ENGINE_get_table_flags;
    {$ifend}
    {$if declared(ENGINE_get_table_flags_introduced)}
    if LibVersion < ENGINE_get_table_flags_introduced then
    begin
      {$if declared(FC_ENGINE_get_table_flags)}
      ENGINE_get_table_flags := FC_ENGINE_get_table_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_table_flags_removed)}
    if ENGINE_get_table_flags_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_table_flags)}
      ENGINE_get_table_flags := _ENGINE_get_table_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_table_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_table_flags');
    {$ifend}
  end;
  
  ENGINE_set_table_flags := LoadLibFunction(ADllHandle, ENGINE_set_table_flags_procname);
  FuncLoadError := not assigned(ENGINE_set_table_flags);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_table_flags_allownil)}
    ENGINE_set_table_flags := ERR_ENGINE_set_table_flags;
    {$ifend}
    {$if declared(ENGINE_set_table_flags_introduced)}
    if LibVersion < ENGINE_set_table_flags_introduced then
    begin
      {$if declared(FC_ENGINE_set_table_flags)}
      ENGINE_set_table_flags := FC_ENGINE_set_table_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_table_flags_removed)}
    if ENGINE_set_table_flags_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_table_flags)}
      ENGINE_set_table_flags := _ENGINE_set_table_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_table_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_table_flags');
    {$ifend}
  end;
  
  ENGINE_register_RSA := LoadLibFunction(ADllHandle, ENGINE_register_RSA_procname);
  FuncLoadError := not assigned(ENGINE_register_RSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_RSA_allownil)}
    ENGINE_register_RSA := ERR_ENGINE_register_RSA;
    {$ifend}
    {$if declared(ENGINE_register_RSA_introduced)}
    if LibVersion < ENGINE_register_RSA_introduced then
    begin
      {$if declared(FC_ENGINE_register_RSA)}
      ENGINE_register_RSA := FC_ENGINE_register_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_RSA_removed)}
    if ENGINE_register_RSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_RSA)}
      ENGINE_register_RSA := _ENGINE_register_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_RSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_RSA');
    {$ifend}
  end;
  
  ENGINE_unregister_RSA := LoadLibFunction(ADllHandle, ENGINE_unregister_RSA_procname);
  FuncLoadError := not assigned(ENGINE_unregister_RSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_unregister_RSA_allownil)}
    ENGINE_unregister_RSA := ERR_ENGINE_unregister_RSA;
    {$ifend}
    {$if declared(ENGINE_unregister_RSA_introduced)}
    if LibVersion < ENGINE_unregister_RSA_introduced then
    begin
      {$if declared(FC_ENGINE_unregister_RSA)}
      ENGINE_unregister_RSA := FC_ENGINE_unregister_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_unregister_RSA_removed)}
    if ENGINE_unregister_RSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_unregister_RSA)}
      ENGINE_unregister_RSA := _ENGINE_unregister_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_unregister_RSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_unregister_RSA');
    {$ifend}
  end;
  
  ENGINE_register_all_RSA := LoadLibFunction(ADllHandle, ENGINE_register_all_RSA_procname);
  FuncLoadError := not assigned(ENGINE_register_all_RSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_all_RSA_allownil)}
    ENGINE_register_all_RSA := ERR_ENGINE_register_all_RSA;
    {$ifend}
    {$if declared(ENGINE_register_all_RSA_introduced)}
    if LibVersion < ENGINE_register_all_RSA_introduced then
    begin
      {$if declared(FC_ENGINE_register_all_RSA)}
      ENGINE_register_all_RSA := FC_ENGINE_register_all_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_all_RSA_removed)}
    if ENGINE_register_all_RSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_all_RSA)}
      ENGINE_register_all_RSA := _ENGINE_register_all_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_all_RSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_all_RSA');
    {$ifend}
  end;
  
  ENGINE_register_DSA := LoadLibFunction(ADllHandle, ENGINE_register_DSA_procname);
  FuncLoadError := not assigned(ENGINE_register_DSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_DSA_allownil)}
    ENGINE_register_DSA := ERR_ENGINE_register_DSA;
    {$ifend}
    {$if declared(ENGINE_register_DSA_introduced)}
    if LibVersion < ENGINE_register_DSA_introduced then
    begin
      {$if declared(FC_ENGINE_register_DSA)}
      ENGINE_register_DSA := FC_ENGINE_register_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_DSA_removed)}
    if ENGINE_register_DSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_DSA)}
      ENGINE_register_DSA := _ENGINE_register_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_DSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_DSA');
    {$ifend}
  end;
  
  ENGINE_unregister_DSA := LoadLibFunction(ADllHandle, ENGINE_unregister_DSA_procname);
  FuncLoadError := not assigned(ENGINE_unregister_DSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_unregister_DSA_allownil)}
    ENGINE_unregister_DSA := ERR_ENGINE_unregister_DSA;
    {$ifend}
    {$if declared(ENGINE_unregister_DSA_introduced)}
    if LibVersion < ENGINE_unregister_DSA_introduced then
    begin
      {$if declared(FC_ENGINE_unregister_DSA)}
      ENGINE_unregister_DSA := FC_ENGINE_unregister_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_unregister_DSA_removed)}
    if ENGINE_unregister_DSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_unregister_DSA)}
      ENGINE_unregister_DSA := _ENGINE_unregister_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_unregister_DSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_unregister_DSA');
    {$ifend}
  end;
  
  ENGINE_register_all_DSA := LoadLibFunction(ADllHandle, ENGINE_register_all_DSA_procname);
  FuncLoadError := not assigned(ENGINE_register_all_DSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_all_DSA_allownil)}
    ENGINE_register_all_DSA := ERR_ENGINE_register_all_DSA;
    {$ifend}
    {$if declared(ENGINE_register_all_DSA_introduced)}
    if LibVersion < ENGINE_register_all_DSA_introduced then
    begin
      {$if declared(FC_ENGINE_register_all_DSA)}
      ENGINE_register_all_DSA := FC_ENGINE_register_all_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_all_DSA_removed)}
    if ENGINE_register_all_DSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_all_DSA)}
      ENGINE_register_all_DSA := _ENGINE_register_all_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_all_DSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_all_DSA');
    {$ifend}
  end;
  
  ENGINE_register_EC := LoadLibFunction(ADllHandle, ENGINE_register_EC_procname);
  FuncLoadError := not assigned(ENGINE_register_EC);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_EC_allownil)}
    ENGINE_register_EC := ERR_ENGINE_register_EC;
    {$ifend}
    {$if declared(ENGINE_register_EC_introduced)}
    if LibVersion < ENGINE_register_EC_introduced then
    begin
      {$if declared(FC_ENGINE_register_EC)}
      ENGINE_register_EC := FC_ENGINE_register_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_EC_removed)}
    if ENGINE_register_EC_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_EC)}
      ENGINE_register_EC := _ENGINE_register_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_EC_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_EC');
    {$ifend}
  end;
  
  ENGINE_unregister_EC := LoadLibFunction(ADllHandle, ENGINE_unregister_EC_procname);
  FuncLoadError := not assigned(ENGINE_unregister_EC);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_unregister_EC_allownil)}
    ENGINE_unregister_EC := ERR_ENGINE_unregister_EC;
    {$ifend}
    {$if declared(ENGINE_unregister_EC_introduced)}
    if LibVersion < ENGINE_unregister_EC_introduced then
    begin
      {$if declared(FC_ENGINE_unregister_EC)}
      ENGINE_unregister_EC := FC_ENGINE_unregister_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_unregister_EC_removed)}
    if ENGINE_unregister_EC_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_unregister_EC)}
      ENGINE_unregister_EC := _ENGINE_unregister_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_unregister_EC_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_unregister_EC');
    {$ifend}
  end;
  
  ENGINE_register_all_EC := LoadLibFunction(ADllHandle, ENGINE_register_all_EC_procname);
  FuncLoadError := not assigned(ENGINE_register_all_EC);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_all_EC_allownil)}
    ENGINE_register_all_EC := ERR_ENGINE_register_all_EC;
    {$ifend}
    {$if declared(ENGINE_register_all_EC_introduced)}
    if LibVersion < ENGINE_register_all_EC_introduced then
    begin
      {$if declared(FC_ENGINE_register_all_EC)}
      ENGINE_register_all_EC := FC_ENGINE_register_all_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_all_EC_removed)}
    if ENGINE_register_all_EC_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_all_EC)}
      ENGINE_register_all_EC := _ENGINE_register_all_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_all_EC_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_all_EC');
    {$ifend}
  end;
  
  ENGINE_register_DH := LoadLibFunction(ADllHandle, ENGINE_register_DH_procname);
  FuncLoadError := not assigned(ENGINE_register_DH);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_DH_allownil)}
    ENGINE_register_DH := ERR_ENGINE_register_DH;
    {$ifend}
    {$if declared(ENGINE_register_DH_introduced)}
    if LibVersion < ENGINE_register_DH_introduced then
    begin
      {$if declared(FC_ENGINE_register_DH)}
      ENGINE_register_DH := FC_ENGINE_register_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_DH_removed)}
    if ENGINE_register_DH_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_DH)}
      ENGINE_register_DH := _ENGINE_register_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_DH_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_DH');
    {$ifend}
  end;
  
  ENGINE_unregister_DH := LoadLibFunction(ADllHandle, ENGINE_unregister_DH_procname);
  FuncLoadError := not assigned(ENGINE_unregister_DH);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_unregister_DH_allownil)}
    ENGINE_unregister_DH := ERR_ENGINE_unregister_DH;
    {$ifend}
    {$if declared(ENGINE_unregister_DH_introduced)}
    if LibVersion < ENGINE_unregister_DH_introduced then
    begin
      {$if declared(FC_ENGINE_unregister_DH)}
      ENGINE_unregister_DH := FC_ENGINE_unregister_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_unregister_DH_removed)}
    if ENGINE_unregister_DH_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_unregister_DH)}
      ENGINE_unregister_DH := _ENGINE_unregister_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_unregister_DH_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_unregister_DH');
    {$ifend}
  end;
  
  ENGINE_register_all_DH := LoadLibFunction(ADllHandle, ENGINE_register_all_DH_procname);
  FuncLoadError := not assigned(ENGINE_register_all_DH);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_all_DH_allownil)}
    ENGINE_register_all_DH := ERR_ENGINE_register_all_DH;
    {$ifend}
    {$if declared(ENGINE_register_all_DH_introduced)}
    if LibVersion < ENGINE_register_all_DH_introduced then
    begin
      {$if declared(FC_ENGINE_register_all_DH)}
      ENGINE_register_all_DH := FC_ENGINE_register_all_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_all_DH_removed)}
    if ENGINE_register_all_DH_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_all_DH)}
      ENGINE_register_all_DH := _ENGINE_register_all_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_all_DH_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_all_DH');
    {$ifend}
  end;
  
  ENGINE_register_RAND := LoadLibFunction(ADllHandle, ENGINE_register_RAND_procname);
  FuncLoadError := not assigned(ENGINE_register_RAND);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_RAND_allownil)}
    ENGINE_register_RAND := ERR_ENGINE_register_RAND;
    {$ifend}
    {$if declared(ENGINE_register_RAND_introduced)}
    if LibVersion < ENGINE_register_RAND_introduced then
    begin
      {$if declared(FC_ENGINE_register_RAND)}
      ENGINE_register_RAND := FC_ENGINE_register_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_RAND_removed)}
    if ENGINE_register_RAND_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_RAND)}
      ENGINE_register_RAND := _ENGINE_register_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_RAND_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_RAND');
    {$ifend}
  end;
  
  ENGINE_unregister_RAND := LoadLibFunction(ADllHandle, ENGINE_unregister_RAND_procname);
  FuncLoadError := not assigned(ENGINE_unregister_RAND);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_unregister_RAND_allownil)}
    ENGINE_unregister_RAND := ERR_ENGINE_unregister_RAND;
    {$ifend}
    {$if declared(ENGINE_unregister_RAND_introduced)}
    if LibVersion < ENGINE_unregister_RAND_introduced then
    begin
      {$if declared(FC_ENGINE_unregister_RAND)}
      ENGINE_unregister_RAND := FC_ENGINE_unregister_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_unregister_RAND_removed)}
    if ENGINE_unregister_RAND_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_unregister_RAND)}
      ENGINE_unregister_RAND := _ENGINE_unregister_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_unregister_RAND_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_unregister_RAND');
    {$ifend}
  end;
  
  ENGINE_register_all_RAND := LoadLibFunction(ADllHandle, ENGINE_register_all_RAND_procname);
  FuncLoadError := not assigned(ENGINE_register_all_RAND);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_all_RAND_allownil)}
    ENGINE_register_all_RAND := ERR_ENGINE_register_all_RAND;
    {$ifend}
    {$if declared(ENGINE_register_all_RAND_introduced)}
    if LibVersion < ENGINE_register_all_RAND_introduced then
    begin
      {$if declared(FC_ENGINE_register_all_RAND)}
      ENGINE_register_all_RAND := FC_ENGINE_register_all_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_all_RAND_removed)}
    if ENGINE_register_all_RAND_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_all_RAND)}
      ENGINE_register_all_RAND := _ENGINE_register_all_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_all_RAND_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_all_RAND');
    {$ifend}
  end;
  
  ENGINE_register_ciphers := LoadLibFunction(ADllHandle, ENGINE_register_ciphers_procname);
  FuncLoadError := not assigned(ENGINE_register_ciphers);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_ciphers_allownil)}
    ENGINE_register_ciphers := ERR_ENGINE_register_ciphers;
    {$ifend}
    {$if declared(ENGINE_register_ciphers_introduced)}
    if LibVersion < ENGINE_register_ciphers_introduced then
    begin
      {$if declared(FC_ENGINE_register_ciphers)}
      ENGINE_register_ciphers := FC_ENGINE_register_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_ciphers_removed)}
    if ENGINE_register_ciphers_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_ciphers)}
      ENGINE_register_ciphers := _ENGINE_register_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_ciphers_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_ciphers');
    {$ifend}
  end;
  
  ENGINE_unregister_ciphers := LoadLibFunction(ADllHandle, ENGINE_unregister_ciphers_procname);
  FuncLoadError := not assigned(ENGINE_unregister_ciphers);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_unregister_ciphers_allownil)}
    ENGINE_unregister_ciphers := ERR_ENGINE_unregister_ciphers;
    {$ifend}
    {$if declared(ENGINE_unregister_ciphers_introduced)}
    if LibVersion < ENGINE_unregister_ciphers_introduced then
    begin
      {$if declared(FC_ENGINE_unregister_ciphers)}
      ENGINE_unregister_ciphers := FC_ENGINE_unregister_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_unregister_ciphers_removed)}
    if ENGINE_unregister_ciphers_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_unregister_ciphers)}
      ENGINE_unregister_ciphers := _ENGINE_unregister_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_unregister_ciphers_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_unregister_ciphers');
    {$ifend}
  end;
  
  ENGINE_register_all_ciphers := LoadLibFunction(ADllHandle, ENGINE_register_all_ciphers_procname);
  FuncLoadError := not assigned(ENGINE_register_all_ciphers);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_all_ciphers_allownil)}
    ENGINE_register_all_ciphers := ERR_ENGINE_register_all_ciphers;
    {$ifend}
    {$if declared(ENGINE_register_all_ciphers_introduced)}
    if LibVersion < ENGINE_register_all_ciphers_introduced then
    begin
      {$if declared(FC_ENGINE_register_all_ciphers)}
      ENGINE_register_all_ciphers := FC_ENGINE_register_all_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_all_ciphers_removed)}
    if ENGINE_register_all_ciphers_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_all_ciphers)}
      ENGINE_register_all_ciphers := _ENGINE_register_all_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_all_ciphers_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_all_ciphers');
    {$ifend}
  end;
  
  ENGINE_register_digests := LoadLibFunction(ADllHandle, ENGINE_register_digests_procname);
  FuncLoadError := not assigned(ENGINE_register_digests);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_digests_allownil)}
    ENGINE_register_digests := ERR_ENGINE_register_digests;
    {$ifend}
    {$if declared(ENGINE_register_digests_introduced)}
    if LibVersion < ENGINE_register_digests_introduced then
    begin
      {$if declared(FC_ENGINE_register_digests)}
      ENGINE_register_digests := FC_ENGINE_register_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_digests_removed)}
    if ENGINE_register_digests_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_digests)}
      ENGINE_register_digests := _ENGINE_register_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_digests_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_digests');
    {$ifend}
  end;
  
  ENGINE_unregister_digests := LoadLibFunction(ADllHandle, ENGINE_unregister_digests_procname);
  FuncLoadError := not assigned(ENGINE_unregister_digests);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_unregister_digests_allownil)}
    ENGINE_unregister_digests := ERR_ENGINE_unregister_digests;
    {$ifend}
    {$if declared(ENGINE_unregister_digests_introduced)}
    if LibVersion < ENGINE_unregister_digests_introduced then
    begin
      {$if declared(FC_ENGINE_unregister_digests)}
      ENGINE_unregister_digests := FC_ENGINE_unregister_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_unregister_digests_removed)}
    if ENGINE_unregister_digests_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_unregister_digests)}
      ENGINE_unregister_digests := _ENGINE_unregister_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_unregister_digests_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_unregister_digests');
    {$ifend}
  end;
  
  ENGINE_register_all_digests := LoadLibFunction(ADllHandle, ENGINE_register_all_digests_procname);
  FuncLoadError := not assigned(ENGINE_register_all_digests);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_all_digests_allownil)}
    ENGINE_register_all_digests := ERR_ENGINE_register_all_digests;
    {$ifend}
    {$if declared(ENGINE_register_all_digests_introduced)}
    if LibVersion < ENGINE_register_all_digests_introduced then
    begin
      {$if declared(FC_ENGINE_register_all_digests)}
      ENGINE_register_all_digests := FC_ENGINE_register_all_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_all_digests_removed)}
    if ENGINE_register_all_digests_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_all_digests)}
      ENGINE_register_all_digests := _ENGINE_register_all_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_all_digests_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_all_digests');
    {$ifend}
  end;
  
  ENGINE_register_pkey_meths := LoadLibFunction(ADllHandle, ENGINE_register_pkey_meths_procname);
  FuncLoadError := not assigned(ENGINE_register_pkey_meths);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_pkey_meths_allownil)}
    ENGINE_register_pkey_meths := ERR_ENGINE_register_pkey_meths;
    {$ifend}
    {$if declared(ENGINE_register_pkey_meths_introduced)}
    if LibVersion < ENGINE_register_pkey_meths_introduced then
    begin
      {$if declared(FC_ENGINE_register_pkey_meths)}
      ENGINE_register_pkey_meths := FC_ENGINE_register_pkey_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_pkey_meths_removed)}
    if ENGINE_register_pkey_meths_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_pkey_meths)}
      ENGINE_register_pkey_meths := _ENGINE_register_pkey_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_pkey_meths_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_pkey_meths');
    {$ifend}
  end;
  
  ENGINE_unregister_pkey_meths := LoadLibFunction(ADllHandle, ENGINE_unregister_pkey_meths_procname);
  FuncLoadError := not assigned(ENGINE_unregister_pkey_meths);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_unregister_pkey_meths_allownil)}
    ENGINE_unregister_pkey_meths := ERR_ENGINE_unregister_pkey_meths;
    {$ifend}
    {$if declared(ENGINE_unregister_pkey_meths_introduced)}
    if LibVersion < ENGINE_unregister_pkey_meths_introduced then
    begin
      {$if declared(FC_ENGINE_unregister_pkey_meths)}
      ENGINE_unregister_pkey_meths := FC_ENGINE_unregister_pkey_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_unregister_pkey_meths_removed)}
    if ENGINE_unregister_pkey_meths_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_unregister_pkey_meths)}
      ENGINE_unregister_pkey_meths := _ENGINE_unregister_pkey_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_unregister_pkey_meths_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_unregister_pkey_meths');
    {$ifend}
  end;
  
  ENGINE_register_all_pkey_meths := LoadLibFunction(ADllHandle, ENGINE_register_all_pkey_meths_procname);
  FuncLoadError := not assigned(ENGINE_register_all_pkey_meths);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_all_pkey_meths_allownil)}
    ENGINE_register_all_pkey_meths := ERR_ENGINE_register_all_pkey_meths;
    {$ifend}
    {$if declared(ENGINE_register_all_pkey_meths_introduced)}
    if LibVersion < ENGINE_register_all_pkey_meths_introduced then
    begin
      {$if declared(FC_ENGINE_register_all_pkey_meths)}
      ENGINE_register_all_pkey_meths := FC_ENGINE_register_all_pkey_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_all_pkey_meths_removed)}
    if ENGINE_register_all_pkey_meths_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_all_pkey_meths)}
      ENGINE_register_all_pkey_meths := _ENGINE_register_all_pkey_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_all_pkey_meths_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_all_pkey_meths');
    {$ifend}
  end;
  
  ENGINE_register_pkey_asn1_meths := LoadLibFunction(ADllHandle, ENGINE_register_pkey_asn1_meths_procname);
  FuncLoadError := not assigned(ENGINE_register_pkey_asn1_meths);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_pkey_asn1_meths_allownil)}
    ENGINE_register_pkey_asn1_meths := ERR_ENGINE_register_pkey_asn1_meths;
    {$ifend}
    {$if declared(ENGINE_register_pkey_asn1_meths_introduced)}
    if LibVersion < ENGINE_register_pkey_asn1_meths_introduced then
    begin
      {$if declared(FC_ENGINE_register_pkey_asn1_meths)}
      ENGINE_register_pkey_asn1_meths := FC_ENGINE_register_pkey_asn1_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_pkey_asn1_meths_removed)}
    if ENGINE_register_pkey_asn1_meths_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_pkey_asn1_meths)}
      ENGINE_register_pkey_asn1_meths := _ENGINE_register_pkey_asn1_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_pkey_asn1_meths_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_pkey_asn1_meths');
    {$ifend}
  end;
  
  ENGINE_unregister_pkey_asn1_meths := LoadLibFunction(ADllHandle, ENGINE_unregister_pkey_asn1_meths_procname);
  FuncLoadError := not assigned(ENGINE_unregister_pkey_asn1_meths);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_unregister_pkey_asn1_meths_allownil)}
    ENGINE_unregister_pkey_asn1_meths := ERR_ENGINE_unregister_pkey_asn1_meths;
    {$ifend}
    {$if declared(ENGINE_unregister_pkey_asn1_meths_introduced)}
    if LibVersion < ENGINE_unregister_pkey_asn1_meths_introduced then
    begin
      {$if declared(FC_ENGINE_unregister_pkey_asn1_meths)}
      ENGINE_unregister_pkey_asn1_meths := FC_ENGINE_unregister_pkey_asn1_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_unregister_pkey_asn1_meths_removed)}
    if ENGINE_unregister_pkey_asn1_meths_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_unregister_pkey_asn1_meths)}
      ENGINE_unregister_pkey_asn1_meths := _ENGINE_unregister_pkey_asn1_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_unregister_pkey_asn1_meths_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_unregister_pkey_asn1_meths');
    {$ifend}
  end;
  
  ENGINE_register_all_pkey_asn1_meths := LoadLibFunction(ADllHandle, ENGINE_register_all_pkey_asn1_meths_procname);
  FuncLoadError := not assigned(ENGINE_register_all_pkey_asn1_meths);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_all_pkey_asn1_meths_allownil)}
    ENGINE_register_all_pkey_asn1_meths := ERR_ENGINE_register_all_pkey_asn1_meths;
    {$ifend}
    {$if declared(ENGINE_register_all_pkey_asn1_meths_introduced)}
    if LibVersion < ENGINE_register_all_pkey_asn1_meths_introduced then
    begin
      {$if declared(FC_ENGINE_register_all_pkey_asn1_meths)}
      ENGINE_register_all_pkey_asn1_meths := FC_ENGINE_register_all_pkey_asn1_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_all_pkey_asn1_meths_removed)}
    if ENGINE_register_all_pkey_asn1_meths_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_all_pkey_asn1_meths)}
      ENGINE_register_all_pkey_asn1_meths := _ENGINE_register_all_pkey_asn1_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_all_pkey_asn1_meths_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_all_pkey_asn1_meths');
    {$ifend}
  end;
  
  ENGINE_register_complete := LoadLibFunction(ADllHandle, ENGINE_register_complete_procname);
  FuncLoadError := not assigned(ENGINE_register_complete);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_complete_allownil)}
    ENGINE_register_complete := ERR_ENGINE_register_complete;
    {$ifend}
    {$if declared(ENGINE_register_complete_introduced)}
    if LibVersion < ENGINE_register_complete_introduced then
    begin
      {$if declared(FC_ENGINE_register_complete)}
      ENGINE_register_complete := FC_ENGINE_register_complete;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_complete_removed)}
    if ENGINE_register_complete_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_complete)}
      ENGINE_register_complete := _ENGINE_register_complete;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_complete_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_complete');
    {$ifend}
  end;
  
  ENGINE_register_all_complete := LoadLibFunction(ADllHandle, ENGINE_register_all_complete_procname);
  FuncLoadError := not assigned(ENGINE_register_all_complete);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_register_all_complete_allownil)}
    ENGINE_register_all_complete := ERR_ENGINE_register_all_complete;
    {$ifend}
    {$if declared(ENGINE_register_all_complete_introduced)}
    if LibVersion < ENGINE_register_all_complete_introduced then
    begin
      {$if declared(FC_ENGINE_register_all_complete)}
      ENGINE_register_all_complete := FC_ENGINE_register_all_complete;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_register_all_complete_removed)}
    if ENGINE_register_all_complete_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_register_all_complete)}
      ENGINE_register_all_complete := _ENGINE_register_all_complete;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_register_all_complete_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_register_all_complete');
    {$ifend}
  end;
  
  ENGINE_ctrl := LoadLibFunction(ADllHandle, ENGINE_ctrl_procname);
  FuncLoadError := not assigned(ENGINE_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_ctrl_allownil)}
    ENGINE_ctrl := ERR_ENGINE_ctrl;
    {$ifend}
    {$if declared(ENGINE_ctrl_introduced)}
    if LibVersion < ENGINE_ctrl_introduced then
    begin
      {$if declared(FC_ENGINE_ctrl)}
      ENGINE_ctrl := FC_ENGINE_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_ctrl_removed)}
    if ENGINE_ctrl_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_ctrl)}
      ENGINE_ctrl := _ENGINE_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_ctrl');
    {$ifend}
  end;
  
  ENGINE_cmd_is_executable := LoadLibFunction(ADllHandle, ENGINE_cmd_is_executable_procname);
  FuncLoadError := not assigned(ENGINE_cmd_is_executable);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_cmd_is_executable_allownil)}
    ENGINE_cmd_is_executable := ERR_ENGINE_cmd_is_executable;
    {$ifend}
    {$if declared(ENGINE_cmd_is_executable_introduced)}
    if LibVersion < ENGINE_cmd_is_executable_introduced then
    begin
      {$if declared(FC_ENGINE_cmd_is_executable)}
      ENGINE_cmd_is_executable := FC_ENGINE_cmd_is_executable;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_cmd_is_executable_removed)}
    if ENGINE_cmd_is_executable_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_cmd_is_executable)}
      ENGINE_cmd_is_executable := _ENGINE_cmd_is_executable;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_cmd_is_executable_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_cmd_is_executable');
    {$ifend}
  end;
  
  ENGINE_ctrl_cmd := LoadLibFunction(ADllHandle, ENGINE_ctrl_cmd_procname);
  FuncLoadError := not assigned(ENGINE_ctrl_cmd);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_ctrl_cmd_allownil)}
    ENGINE_ctrl_cmd := ERR_ENGINE_ctrl_cmd;
    {$ifend}
    {$if declared(ENGINE_ctrl_cmd_introduced)}
    if LibVersion < ENGINE_ctrl_cmd_introduced then
    begin
      {$if declared(FC_ENGINE_ctrl_cmd)}
      ENGINE_ctrl_cmd := FC_ENGINE_ctrl_cmd;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_ctrl_cmd_removed)}
    if ENGINE_ctrl_cmd_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_ctrl_cmd)}
      ENGINE_ctrl_cmd := _ENGINE_ctrl_cmd;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_ctrl_cmd_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_ctrl_cmd');
    {$ifend}
  end;
  
  ENGINE_ctrl_cmd_string := LoadLibFunction(ADllHandle, ENGINE_ctrl_cmd_string_procname);
  FuncLoadError := not assigned(ENGINE_ctrl_cmd_string);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_ctrl_cmd_string_allownil)}
    ENGINE_ctrl_cmd_string := ERR_ENGINE_ctrl_cmd_string;
    {$ifend}
    {$if declared(ENGINE_ctrl_cmd_string_introduced)}
    if LibVersion < ENGINE_ctrl_cmd_string_introduced then
    begin
      {$if declared(FC_ENGINE_ctrl_cmd_string)}
      ENGINE_ctrl_cmd_string := FC_ENGINE_ctrl_cmd_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_ctrl_cmd_string_removed)}
    if ENGINE_ctrl_cmd_string_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_ctrl_cmd_string)}
      ENGINE_ctrl_cmd_string := _ENGINE_ctrl_cmd_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_ctrl_cmd_string_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_ctrl_cmd_string');
    {$ifend}
  end;
  
  ENGINE_new := LoadLibFunction(ADllHandle, ENGINE_new_procname);
  FuncLoadError := not assigned(ENGINE_new);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_new_allownil)}
    ENGINE_new := ERR_ENGINE_new;
    {$ifend}
    {$if declared(ENGINE_new_introduced)}
    if LibVersion < ENGINE_new_introduced then
    begin
      {$if declared(FC_ENGINE_new)}
      ENGINE_new := FC_ENGINE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_new_removed)}
    if ENGINE_new_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_new)}
      ENGINE_new := _ENGINE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_new');
    {$ifend}
  end;
  
  ENGINE_free := LoadLibFunction(ADllHandle, ENGINE_free_procname);
  FuncLoadError := not assigned(ENGINE_free);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_free_allownil)}
    ENGINE_free := ERR_ENGINE_free;
    {$ifend}
    {$if declared(ENGINE_free_introduced)}
    if LibVersion < ENGINE_free_introduced then
    begin
      {$if declared(FC_ENGINE_free)}
      ENGINE_free := FC_ENGINE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_free_removed)}
    if ENGINE_free_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_free)}
      ENGINE_free := _ENGINE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_free');
    {$ifend}
  end;
  
  ENGINE_up_ref := LoadLibFunction(ADllHandle, ENGINE_up_ref_procname);
  FuncLoadError := not assigned(ENGINE_up_ref);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_up_ref_allownil)}
    ENGINE_up_ref := ERR_ENGINE_up_ref;
    {$ifend}
    {$if declared(ENGINE_up_ref_introduced)}
    if LibVersion < ENGINE_up_ref_introduced then
    begin
      {$if declared(FC_ENGINE_up_ref)}
      ENGINE_up_ref := FC_ENGINE_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_up_ref_removed)}
    if ENGINE_up_ref_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_up_ref)}
      ENGINE_up_ref := _ENGINE_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_up_ref_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_up_ref');
    {$ifend}
  end;
  
  ENGINE_set_id := LoadLibFunction(ADllHandle, ENGINE_set_id_procname);
  FuncLoadError := not assigned(ENGINE_set_id);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_id_allownil)}
    ENGINE_set_id := ERR_ENGINE_set_id;
    {$ifend}
    {$if declared(ENGINE_set_id_introduced)}
    if LibVersion < ENGINE_set_id_introduced then
    begin
      {$if declared(FC_ENGINE_set_id)}
      ENGINE_set_id := FC_ENGINE_set_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_id_removed)}
    if ENGINE_set_id_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_id)}
      ENGINE_set_id := _ENGINE_set_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_id_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_id');
    {$ifend}
  end;
  
  ENGINE_set_name := LoadLibFunction(ADllHandle, ENGINE_set_name_procname);
  FuncLoadError := not assigned(ENGINE_set_name);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_name_allownil)}
    ENGINE_set_name := ERR_ENGINE_set_name;
    {$ifend}
    {$if declared(ENGINE_set_name_introduced)}
    if LibVersion < ENGINE_set_name_introduced then
    begin
      {$if declared(FC_ENGINE_set_name)}
      ENGINE_set_name := FC_ENGINE_set_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_name_removed)}
    if ENGINE_set_name_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_name)}
      ENGINE_set_name := _ENGINE_set_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_name_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_name');
    {$ifend}
  end;
  
  ENGINE_set_RSA := LoadLibFunction(ADllHandle, ENGINE_set_RSA_procname);
  FuncLoadError := not assigned(ENGINE_set_RSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_RSA_allownil)}
    ENGINE_set_RSA := ERR_ENGINE_set_RSA;
    {$ifend}
    {$if declared(ENGINE_set_RSA_introduced)}
    if LibVersion < ENGINE_set_RSA_introduced then
    begin
      {$if declared(FC_ENGINE_set_RSA)}
      ENGINE_set_RSA := FC_ENGINE_set_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_RSA_removed)}
    if ENGINE_set_RSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_RSA)}
      ENGINE_set_RSA := _ENGINE_set_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_RSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_RSA');
    {$ifend}
  end;
  
  ENGINE_set_DSA := LoadLibFunction(ADllHandle, ENGINE_set_DSA_procname);
  FuncLoadError := not assigned(ENGINE_set_DSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_DSA_allownil)}
    ENGINE_set_DSA := ERR_ENGINE_set_DSA;
    {$ifend}
    {$if declared(ENGINE_set_DSA_introduced)}
    if LibVersion < ENGINE_set_DSA_introduced then
    begin
      {$if declared(FC_ENGINE_set_DSA)}
      ENGINE_set_DSA := FC_ENGINE_set_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_DSA_removed)}
    if ENGINE_set_DSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_DSA)}
      ENGINE_set_DSA := _ENGINE_set_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_DSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_DSA');
    {$ifend}
  end;
  
  ENGINE_set_EC := LoadLibFunction(ADllHandle, ENGINE_set_EC_procname);
  FuncLoadError := not assigned(ENGINE_set_EC);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_EC_allownil)}
    ENGINE_set_EC := ERR_ENGINE_set_EC;
    {$ifend}
    {$if declared(ENGINE_set_EC_introduced)}
    if LibVersion < ENGINE_set_EC_introduced then
    begin
      {$if declared(FC_ENGINE_set_EC)}
      ENGINE_set_EC := FC_ENGINE_set_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_EC_removed)}
    if ENGINE_set_EC_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_EC)}
      ENGINE_set_EC := _ENGINE_set_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_EC_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_EC');
    {$ifend}
  end;
  
  ENGINE_set_DH := LoadLibFunction(ADllHandle, ENGINE_set_DH_procname);
  FuncLoadError := not assigned(ENGINE_set_DH);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_DH_allownil)}
    ENGINE_set_DH := ERR_ENGINE_set_DH;
    {$ifend}
    {$if declared(ENGINE_set_DH_introduced)}
    if LibVersion < ENGINE_set_DH_introduced then
    begin
      {$if declared(FC_ENGINE_set_DH)}
      ENGINE_set_DH := FC_ENGINE_set_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_DH_removed)}
    if ENGINE_set_DH_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_DH)}
      ENGINE_set_DH := _ENGINE_set_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_DH_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_DH');
    {$ifend}
  end;
  
  ENGINE_set_RAND := LoadLibFunction(ADllHandle, ENGINE_set_RAND_procname);
  FuncLoadError := not assigned(ENGINE_set_RAND);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_RAND_allownil)}
    ENGINE_set_RAND := ERR_ENGINE_set_RAND;
    {$ifend}
    {$if declared(ENGINE_set_RAND_introduced)}
    if LibVersion < ENGINE_set_RAND_introduced then
    begin
      {$if declared(FC_ENGINE_set_RAND)}
      ENGINE_set_RAND := FC_ENGINE_set_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_RAND_removed)}
    if ENGINE_set_RAND_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_RAND)}
      ENGINE_set_RAND := _ENGINE_set_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_RAND_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_RAND');
    {$ifend}
  end;
  
  ENGINE_set_destroy_function := LoadLibFunction(ADllHandle, ENGINE_set_destroy_function_procname);
  FuncLoadError := not assigned(ENGINE_set_destroy_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_destroy_function_allownil)}
    ENGINE_set_destroy_function := ERR_ENGINE_set_destroy_function;
    {$ifend}
    {$if declared(ENGINE_set_destroy_function_introduced)}
    if LibVersion < ENGINE_set_destroy_function_introduced then
    begin
      {$if declared(FC_ENGINE_set_destroy_function)}
      ENGINE_set_destroy_function := FC_ENGINE_set_destroy_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_destroy_function_removed)}
    if ENGINE_set_destroy_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_destroy_function)}
      ENGINE_set_destroy_function := _ENGINE_set_destroy_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_destroy_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_destroy_function');
    {$ifend}
  end;
  
  ENGINE_set_init_function := LoadLibFunction(ADllHandle, ENGINE_set_init_function_procname);
  FuncLoadError := not assigned(ENGINE_set_init_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_init_function_allownil)}
    ENGINE_set_init_function := ERR_ENGINE_set_init_function;
    {$ifend}
    {$if declared(ENGINE_set_init_function_introduced)}
    if LibVersion < ENGINE_set_init_function_introduced then
    begin
      {$if declared(FC_ENGINE_set_init_function)}
      ENGINE_set_init_function := FC_ENGINE_set_init_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_init_function_removed)}
    if ENGINE_set_init_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_init_function)}
      ENGINE_set_init_function := _ENGINE_set_init_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_init_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_init_function');
    {$ifend}
  end;
  
  ENGINE_set_finish_function := LoadLibFunction(ADllHandle, ENGINE_set_finish_function_procname);
  FuncLoadError := not assigned(ENGINE_set_finish_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_finish_function_allownil)}
    ENGINE_set_finish_function := ERR_ENGINE_set_finish_function;
    {$ifend}
    {$if declared(ENGINE_set_finish_function_introduced)}
    if LibVersion < ENGINE_set_finish_function_introduced then
    begin
      {$if declared(FC_ENGINE_set_finish_function)}
      ENGINE_set_finish_function := FC_ENGINE_set_finish_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_finish_function_removed)}
    if ENGINE_set_finish_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_finish_function)}
      ENGINE_set_finish_function := _ENGINE_set_finish_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_finish_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_finish_function');
    {$ifend}
  end;
  
  ENGINE_set_ctrl_function := LoadLibFunction(ADllHandle, ENGINE_set_ctrl_function_procname);
  FuncLoadError := not assigned(ENGINE_set_ctrl_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_ctrl_function_allownil)}
    ENGINE_set_ctrl_function := ERR_ENGINE_set_ctrl_function;
    {$ifend}
    {$if declared(ENGINE_set_ctrl_function_introduced)}
    if LibVersion < ENGINE_set_ctrl_function_introduced then
    begin
      {$if declared(FC_ENGINE_set_ctrl_function)}
      ENGINE_set_ctrl_function := FC_ENGINE_set_ctrl_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_ctrl_function_removed)}
    if ENGINE_set_ctrl_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_ctrl_function)}
      ENGINE_set_ctrl_function := _ENGINE_set_ctrl_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_ctrl_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_ctrl_function');
    {$ifend}
  end;
  
  ENGINE_set_load_privkey_function := LoadLibFunction(ADllHandle, ENGINE_set_load_privkey_function_procname);
  FuncLoadError := not assigned(ENGINE_set_load_privkey_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_load_privkey_function_allownil)}
    ENGINE_set_load_privkey_function := ERR_ENGINE_set_load_privkey_function;
    {$ifend}
    {$if declared(ENGINE_set_load_privkey_function_introduced)}
    if LibVersion < ENGINE_set_load_privkey_function_introduced then
    begin
      {$if declared(FC_ENGINE_set_load_privkey_function)}
      ENGINE_set_load_privkey_function := FC_ENGINE_set_load_privkey_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_load_privkey_function_removed)}
    if ENGINE_set_load_privkey_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_load_privkey_function)}
      ENGINE_set_load_privkey_function := _ENGINE_set_load_privkey_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_load_privkey_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_load_privkey_function');
    {$ifend}
  end;
  
  ENGINE_set_load_pubkey_function := LoadLibFunction(ADllHandle, ENGINE_set_load_pubkey_function_procname);
  FuncLoadError := not assigned(ENGINE_set_load_pubkey_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_load_pubkey_function_allownil)}
    ENGINE_set_load_pubkey_function := ERR_ENGINE_set_load_pubkey_function;
    {$ifend}
    {$if declared(ENGINE_set_load_pubkey_function_introduced)}
    if LibVersion < ENGINE_set_load_pubkey_function_introduced then
    begin
      {$if declared(FC_ENGINE_set_load_pubkey_function)}
      ENGINE_set_load_pubkey_function := FC_ENGINE_set_load_pubkey_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_load_pubkey_function_removed)}
    if ENGINE_set_load_pubkey_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_load_pubkey_function)}
      ENGINE_set_load_pubkey_function := _ENGINE_set_load_pubkey_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_load_pubkey_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_load_pubkey_function');
    {$ifend}
  end;
  
  ENGINE_set_load_ssl_client_cert_function := LoadLibFunction(ADllHandle, ENGINE_set_load_ssl_client_cert_function_procname);
  FuncLoadError := not assigned(ENGINE_set_load_ssl_client_cert_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_load_ssl_client_cert_function_allownil)}
    ENGINE_set_load_ssl_client_cert_function := ERR_ENGINE_set_load_ssl_client_cert_function;
    {$ifend}
    {$if declared(ENGINE_set_load_ssl_client_cert_function_introduced)}
    if LibVersion < ENGINE_set_load_ssl_client_cert_function_introduced then
    begin
      {$if declared(FC_ENGINE_set_load_ssl_client_cert_function)}
      ENGINE_set_load_ssl_client_cert_function := FC_ENGINE_set_load_ssl_client_cert_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_load_ssl_client_cert_function_removed)}
    if ENGINE_set_load_ssl_client_cert_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_load_ssl_client_cert_function)}
      ENGINE_set_load_ssl_client_cert_function := _ENGINE_set_load_ssl_client_cert_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_load_ssl_client_cert_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_load_ssl_client_cert_function');
    {$ifend}
  end;
  
  ENGINE_set_ciphers := LoadLibFunction(ADllHandle, ENGINE_set_ciphers_procname);
  FuncLoadError := not assigned(ENGINE_set_ciphers);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_ciphers_allownil)}
    ENGINE_set_ciphers := ERR_ENGINE_set_ciphers;
    {$ifend}
    {$if declared(ENGINE_set_ciphers_introduced)}
    if LibVersion < ENGINE_set_ciphers_introduced then
    begin
      {$if declared(FC_ENGINE_set_ciphers)}
      ENGINE_set_ciphers := FC_ENGINE_set_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_ciphers_removed)}
    if ENGINE_set_ciphers_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_ciphers)}
      ENGINE_set_ciphers := _ENGINE_set_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_ciphers_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_ciphers');
    {$ifend}
  end;
  
  ENGINE_set_digests := LoadLibFunction(ADllHandle, ENGINE_set_digests_procname);
  FuncLoadError := not assigned(ENGINE_set_digests);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_digests_allownil)}
    ENGINE_set_digests := ERR_ENGINE_set_digests;
    {$ifend}
    {$if declared(ENGINE_set_digests_introduced)}
    if LibVersion < ENGINE_set_digests_introduced then
    begin
      {$if declared(FC_ENGINE_set_digests)}
      ENGINE_set_digests := FC_ENGINE_set_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_digests_removed)}
    if ENGINE_set_digests_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_digests)}
      ENGINE_set_digests := _ENGINE_set_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_digests_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_digests');
    {$ifend}
  end;
  
  ENGINE_set_pkey_meths := LoadLibFunction(ADllHandle, ENGINE_set_pkey_meths_procname);
  FuncLoadError := not assigned(ENGINE_set_pkey_meths);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_pkey_meths_allownil)}
    ENGINE_set_pkey_meths := ERR_ENGINE_set_pkey_meths;
    {$ifend}
    {$if declared(ENGINE_set_pkey_meths_introduced)}
    if LibVersion < ENGINE_set_pkey_meths_introduced then
    begin
      {$if declared(FC_ENGINE_set_pkey_meths)}
      ENGINE_set_pkey_meths := FC_ENGINE_set_pkey_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_pkey_meths_removed)}
    if ENGINE_set_pkey_meths_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_pkey_meths)}
      ENGINE_set_pkey_meths := _ENGINE_set_pkey_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_pkey_meths_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_pkey_meths');
    {$ifend}
  end;
  
  ENGINE_set_pkey_asn1_meths := LoadLibFunction(ADllHandle, ENGINE_set_pkey_asn1_meths_procname);
  FuncLoadError := not assigned(ENGINE_set_pkey_asn1_meths);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_pkey_asn1_meths_allownil)}
    ENGINE_set_pkey_asn1_meths := ERR_ENGINE_set_pkey_asn1_meths;
    {$ifend}
    {$if declared(ENGINE_set_pkey_asn1_meths_introduced)}
    if LibVersion < ENGINE_set_pkey_asn1_meths_introduced then
    begin
      {$if declared(FC_ENGINE_set_pkey_asn1_meths)}
      ENGINE_set_pkey_asn1_meths := FC_ENGINE_set_pkey_asn1_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_pkey_asn1_meths_removed)}
    if ENGINE_set_pkey_asn1_meths_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_pkey_asn1_meths)}
      ENGINE_set_pkey_asn1_meths := _ENGINE_set_pkey_asn1_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_pkey_asn1_meths_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_pkey_asn1_meths');
    {$ifend}
  end;
  
  ENGINE_set_flags := LoadLibFunction(ADllHandle, ENGINE_set_flags_procname);
  FuncLoadError := not assigned(ENGINE_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_flags_allownil)}
    ENGINE_set_flags := ERR_ENGINE_set_flags;
    {$ifend}
    {$if declared(ENGINE_set_flags_introduced)}
    if LibVersion < ENGINE_set_flags_introduced then
    begin
      {$if declared(FC_ENGINE_set_flags)}
      ENGINE_set_flags := FC_ENGINE_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_flags_removed)}
    if ENGINE_set_flags_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_flags)}
      ENGINE_set_flags := _ENGINE_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_flags');
    {$ifend}
  end;
  
  ENGINE_set_cmd_defns := LoadLibFunction(ADllHandle, ENGINE_set_cmd_defns_procname);
  FuncLoadError := not assigned(ENGINE_set_cmd_defns);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_cmd_defns_allownil)}
    ENGINE_set_cmd_defns := ERR_ENGINE_set_cmd_defns;
    {$ifend}
    {$if declared(ENGINE_set_cmd_defns_introduced)}
    if LibVersion < ENGINE_set_cmd_defns_introduced then
    begin
      {$if declared(FC_ENGINE_set_cmd_defns)}
      ENGINE_set_cmd_defns := FC_ENGINE_set_cmd_defns;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_cmd_defns_removed)}
    if ENGINE_set_cmd_defns_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_cmd_defns)}
      ENGINE_set_cmd_defns := _ENGINE_set_cmd_defns;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_cmd_defns_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_cmd_defns');
    {$ifend}
  end;
  
  ENGINE_set_ex_data := LoadLibFunction(ADllHandle, ENGINE_set_ex_data_procname);
  FuncLoadError := not assigned(ENGINE_set_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_ex_data_allownil)}
    ENGINE_set_ex_data := ERR_ENGINE_set_ex_data;
    {$ifend}
    {$if declared(ENGINE_set_ex_data_introduced)}
    if LibVersion < ENGINE_set_ex_data_introduced then
    begin
      {$if declared(FC_ENGINE_set_ex_data)}
      ENGINE_set_ex_data := FC_ENGINE_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_ex_data_removed)}
    if ENGINE_set_ex_data_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_ex_data)}
      ENGINE_set_ex_data := _ENGINE_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_ex_data');
    {$ifend}
  end;
  
  ENGINE_get_ex_data := LoadLibFunction(ADllHandle, ENGINE_get_ex_data_procname);
  FuncLoadError := not assigned(ENGINE_get_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_ex_data_allownil)}
    ENGINE_get_ex_data := ERR_ENGINE_get_ex_data;
    {$ifend}
    {$if declared(ENGINE_get_ex_data_introduced)}
    if LibVersion < ENGINE_get_ex_data_introduced then
    begin
      {$if declared(FC_ENGINE_get_ex_data)}
      ENGINE_get_ex_data := FC_ENGINE_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_ex_data_removed)}
    if ENGINE_get_ex_data_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_ex_data)}
      ENGINE_get_ex_data := _ENGINE_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_ex_data');
    {$ifend}
  end;
  
  ENGINE_get_id := LoadLibFunction(ADllHandle, ENGINE_get_id_procname);
  FuncLoadError := not assigned(ENGINE_get_id);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_id_allownil)}
    ENGINE_get_id := ERR_ENGINE_get_id;
    {$ifend}
    {$if declared(ENGINE_get_id_introduced)}
    if LibVersion < ENGINE_get_id_introduced then
    begin
      {$if declared(FC_ENGINE_get_id)}
      ENGINE_get_id := FC_ENGINE_get_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_id_removed)}
    if ENGINE_get_id_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_id)}
      ENGINE_get_id := _ENGINE_get_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_id_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_id');
    {$ifend}
  end;
  
  ENGINE_get_name := LoadLibFunction(ADllHandle, ENGINE_get_name_procname);
  FuncLoadError := not assigned(ENGINE_get_name);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_name_allownil)}
    ENGINE_get_name := ERR_ENGINE_get_name;
    {$ifend}
    {$if declared(ENGINE_get_name_introduced)}
    if LibVersion < ENGINE_get_name_introduced then
    begin
      {$if declared(FC_ENGINE_get_name)}
      ENGINE_get_name := FC_ENGINE_get_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_name_removed)}
    if ENGINE_get_name_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_name)}
      ENGINE_get_name := _ENGINE_get_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_name_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_name');
    {$ifend}
  end;
  
  ENGINE_get_RSA := LoadLibFunction(ADllHandle, ENGINE_get_RSA_procname);
  FuncLoadError := not assigned(ENGINE_get_RSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_RSA_allownil)}
    ENGINE_get_RSA := ERR_ENGINE_get_RSA;
    {$ifend}
    {$if declared(ENGINE_get_RSA_introduced)}
    if LibVersion < ENGINE_get_RSA_introduced then
    begin
      {$if declared(FC_ENGINE_get_RSA)}
      ENGINE_get_RSA := FC_ENGINE_get_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_RSA_removed)}
    if ENGINE_get_RSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_RSA)}
      ENGINE_get_RSA := _ENGINE_get_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_RSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_RSA');
    {$ifend}
  end;
  
  ENGINE_get_DSA := LoadLibFunction(ADllHandle, ENGINE_get_DSA_procname);
  FuncLoadError := not assigned(ENGINE_get_DSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_DSA_allownil)}
    ENGINE_get_DSA := ERR_ENGINE_get_DSA;
    {$ifend}
    {$if declared(ENGINE_get_DSA_introduced)}
    if LibVersion < ENGINE_get_DSA_introduced then
    begin
      {$if declared(FC_ENGINE_get_DSA)}
      ENGINE_get_DSA := FC_ENGINE_get_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_DSA_removed)}
    if ENGINE_get_DSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_DSA)}
      ENGINE_get_DSA := _ENGINE_get_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_DSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_DSA');
    {$ifend}
  end;
  
  ENGINE_get_EC := LoadLibFunction(ADllHandle, ENGINE_get_EC_procname);
  FuncLoadError := not assigned(ENGINE_get_EC);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_EC_allownil)}
    ENGINE_get_EC := ERR_ENGINE_get_EC;
    {$ifend}
    {$if declared(ENGINE_get_EC_introduced)}
    if LibVersion < ENGINE_get_EC_introduced then
    begin
      {$if declared(FC_ENGINE_get_EC)}
      ENGINE_get_EC := FC_ENGINE_get_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_EC_removed)}
    if ENGINE_get_EC_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_EC)}
      ENGINE_get_EC := _ENGINE_get_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_EC_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_EC');
    {$ifend}
  end;
  
  ENGINE_get_DH := LoadLibFunction(ADllHandle, ENGINE_get_DH_procname);
  FuncLoadError := not assigned(ENGINE_get_DH);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_DH_allownil)}
    ENGINE_get_DH := ERR_ENGINE_get_DH;
    {$ifend}
    {$if declared(ENGINE_get_DH_introduced)}
    if LibVersion < ENGINE_get_DH_introduced then
    begin
      {$if declared(FC_ENGINE_get_DH)}
      ENGINE_get_DH := FC_ENGINE_get_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_DH_removed)}
    if ENGINE_get_DH_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_DH)}
      ENGINE_get_DH := _ENGINE_get_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_DH_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_DH');
    {$ifend}
  end;
  
  ENGINE_get_RAND := LoadLibFunction(ADllHandle, ENGINE_get_RAND_procname);
  FuncLoadError := not assigned(ENGINE_get_RAND);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_RAND_allownil)}
    ENGINE_get_RAND := ERR_ENGINE_get_RAND;
    {$ifend}
    {$if declared(ENGINE_get_RAND_introduced)}
    if LibVersion < ENGINE_get_RAND_introduced then
    begin
      {$if declared(FC_ENGINE_get_RAND)}
      ENGINE_get_RAND := FC_ENGINE_get_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_RAND_removed)}
    if ENGINE_get_RAND_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_RAND)}
      ENGINE_get_RAND := _ENGINE_get_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_RAND_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_RAND');
    {$ifend}
  end;
  
  ENGINE_get_destroy_function := LoadLibFunction(ADllHandle, ENGINE_get_destroy_function_procname);
  FuncLoadError := not assigned(ENGINE_get_destroy_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_destroy_function_allownil)}
    ENGINE_get_destroy_function := ERR_ENGINE_get_destroy_function;
    {$ifend}
    {$if declared(ENGINE_get_destroy_function_introduced)}
    if LibVersion < ENGINE_get_destroy_function_introduced then
    begin
      {$if declared(FC_ENGINE_get_destroy_function)}
      ENGINE_get_destroy_function := FC_ENGINE_get_destroy_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_destroy_function_removed)}
    if ENGINE_get_destroy_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_destroy_function)}
      ENGINE_get_destroy_function := _ENGINE_get_destroy_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_destroy_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_destroy_function');
    {$ifend}
  end;
  
  ENGINE_get_init_function := LoadLibFunction(ADllHandle, ENGINE_get_init_function_procname);
  FuncLoadError := not assigned(ENGINE_get_init_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_init_function_allownil)}
    ENGINE_get_init_function := ERR_ENGINE_get_init_function;
    {$ifend}
    {$if declared(ENGINE_get_init_function_introduced)}
    if LibVersion < ENGINE_get_init_function_introduced then
    begin
      {$if declared(FC_ENGINE_get_init_function)}
      ENGINE_get_init_function := FC_ENGINE_get_init_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_init_function_removed)}
    if ENGINE_get_init_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_init_function)}
      ENGINE_get_init_function := _ENGINE_get_init_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_init_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_init_function');
    {$ifend}
  end;
  
  ENGINE_get_finish_function := LoadLibFunction(ADllHandle, ENGINE_get_finish_function_procname);
  FuncLoadError := not assigned(ENGINE_get_finish_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_finish_function_allownil)}
    ENGINE_get_finish_function := ERR_ENGINE_get_finish_function;
    {$ifend}
    {$if declared(ENGINE_get_finish_function_introduced)}
    if LibVersion < ENGINE_get_finish_function_introduced then
    begin
      {$if declared(FC_ENGINE_get_finish_function)}
      ENGINE_get_finish_function := FC_ENGINE_get_finish_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_finish_function_removed)}
    if ENGINE_get_finish_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_finish_function)}
      ENGINE_get_finish_function := _ENGINE_get_finish_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_finish_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_finish_function');
    {$ifend}
  end;
  
  ENGINE_get_ctrl_function := LoadLibFunction(ADllHandle, ENGINE_get_ctrl_function_procname);
  FuncLoadError := not assigned(ENGINE_get_ctrl_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_ctrl_function_allownil)}
    ENGINE_get_ctrl_function := ERR_ENGINE_get_ctrl_function;
    {$ifend}
    {$if declared(ENGINE_get_ctrl_function_introduced)}
    if LibVersion < ENGINE_get_ctrl_function_introduced then
    begin
      {$if declared(FC_ENGINE_get_ctrl_function)}
      ENGINE_get_ctrl_function := FC_ENGINE_get_ctrl_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_ctrl_function_removed)}
    if ENGINE_get_ctrl_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_ctrl_function)}
      ENGINE_get_ctrl_function := _ENGINE_get_ctrl_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_ctrl_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_ctrl_function');
    {$ifend}
  end;
  
  ENGINE_get_load_privkey_function := LoadLibFunction(ADllHandle, ENGINE_get_load_privkey_function_procname);
  FuncLoadError := not assigned(ENGINE_get_load_privkey_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_load_privkey_function_allownil)}
    ENGINE_get_load_privkey_function := ERR_ENGINE_get_load_privkey_function;
    {$ifend}
    {$if declared(ENGINE_get_load_privkey_function_introduced)}
    if LibVersion < ENGINE_get_load_privkey_function_introduced then
    begin
      {$if declared(FC_ENGINE_get_load_privkey_function)}
      ENGINE_get_load_privkey_function := FC_ENGINE_get_load_privkey_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_load_privkey_function_removed)}
    if ENGINE_get_load_privkey_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_load_privkey_function)}
      ENGINE_get_load_privkey_function := _ENGINE_get_load_privkey_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_load_privkey_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_load_privkey_function');
    {$ifend}
  end;
  
  ENGINE_get_load_pubkey_function := LoadLibFunction(ADllHandle, ENGINE_get_load_pubkey_function_procname);
  FuncLoadError := not assigned(ENGINE_get_load_pubkey_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_load_pubkey_function_allownil)}
    ENGINE_get_load_pubkey_function := ERR_ENGINE_get_load_pubkey_function;
    {$ifend}
    {$if declared(ENGINE_get_load_pubkey_function_introduced)}
    if LibVersion < ENGINE_get_load_pubkey_function_introduced then
    begin
      {$if declared(FC_ENGINE_get_load_pubkey_function)}
      ENGINE_get_load_pubkey_function := FC_ENGINE_get_load_pubkey_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_load_pubkey_function_removed)}
    if ENGINE_get_load_pubkey_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_load_pubkey_function)}
      ENGINE_get_load_pubkey_function := _ENGINE_get_load_pubkey_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_load_pubkey_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_load_pubkey_function');
    {$ifend}
  end;
  
  ENGINE_get_ssl_client_cert_function := LoadLibFunction(ADllHandle, ENGINE_get_ssl_client_cert_function_procname);
  FuncLoadError := not assigned(ENGINE_get_ssl_client_cert_function);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_ssl_client_cert_function_allownil)}
    ENGINE_get_ssl_client_cert_function := ERR_ENGINE_get_ssl_client_cert_function;
    {$ifend}
    {$if declared(ENGINE_get_ssl_client_cert_function_introduced)}
    if LibVersion < ENGINE_get_ssl_client_cert_function_introduced then
    begin
      {$if declared(FC_ENGINE_get_ssl_client_cert_function)}
      ENGINE_get_ssl_client_cert_function := FC_ENGINE_get_ssl_client_cert_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_ssl_client_cert_function_removed)}
    if ENGINE_get_ssl_client_cert_function_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_ssl_client_cert_function)}
      ENGINE_get_ssl_client_cert_function := _ENGINE_get_ssl_client_cert_function;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_ssl_client_cert_function_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_ssl_client_cert_function');
    {$ifend}
  end;
  
  ENGINE_get_ciphers := LoadLibFunction(ADllHandle, ENGINE_get_ciphers_procname);
  FuncLoadError := not assigned(ENGINE_get_ciphers);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_ciphers_allownil)}
    ENGINE_get_ciphers := ERR_ENGINE_get_ciphers;
    {$ifend}
    {$if declared(ENGINE_get_ciphers_introduced)}
    if LibVersion < ENGINE_get_ciphers_introduced then
    begin
      {$if declared(FC_ENGINE_get_ciphers)}
      ENGINE_get_ciphers := FC_ENGINE_get_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_ciphers_removed)}
    if ENGINE_get_ciphers_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_ciphers)}
      ENGINE_get_ciphers := _ENGINE_get_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_ciphers_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_ciphers');
    {$ifend}
  end;
  
  ENGINE_get_digests := LoadLibFunction(ADllHandle, ENGINE_get_digests_procname);
  FuncLoadError := not assigned(ENGINE_get_digests);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_digests_allownil)}
    ENGINE_get_digests := ERR_ENGINE_get_digests;
    {$ifend}
    {$if declared(ENGINE_get_digests_introduced)}
    if LibVersion < ENGINE_get_digests_introduced then
    begin
      {$if declared(FC_ENGINE_get_digests)}
      ENGINE_get_digests := FC_ENGINE_get_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_digests_removed)}
    if ENGINE_get_digests_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_digests)}
      ENGINE_get_digests := _ENGINE_get_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_digests_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_digests');
    {$ifend}
  end;
  
  ENGINE_get_pkey_meths := LoadLibFunction(ADllHandle, ENGINE_get_pkey_meths_procname);
  FuncLoadError := not assigned(ENGINE_get_pkey_meths);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_pkey_meths_allownil)}
    ENGINE_get_pkey_meths := ERR_ENGINE_get_pkey_meths;
    {$ifend}
    {$if declared(ENGINE_get_pkey_meths_introduced)}
    if LibVersion < ENGINE_get_pkey_meths_introduced then
    begin
      {$if declared(FC_ENGINE_get_pkey_meths)}
      ENGINE_get_pkey_meths := FC_ENGINE_get_pkey_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_pkey_meths_removed)}
    if ENGINE_get_pkey_meths_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_pkey_meths)}
      ENGINE_get_pkey_meths := _ENGINE_get_pkey_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_pkey_meths_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_pkey_meths');
    {$ifend}
  end;
  
  ENGINE_get_pkey_asn1_meths := LoadLibFunction(ADllHandle, ENGINE_get_pkey_asn1_meths_procname);
  FuncLoadError := not assigned(ENGINE_get_pkey_asn1_meths);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_pkey_asn1_meths_allownil)}
    ENGINE_get_pkey_asn1_meths := ERR_ENGINE_get_pkey_asn1_meths;
    {$ifend}
    {$if declared(ENGINE_get_pkey_asn1_meths_introduced)}
    if LibVersion < ENGINE_get_pkey_asn1_meths_introduced then
    begin
      {$if declared(FC_ENGINE_get_pkey_asn1_meths)}
      ENGINE_get_pkey_asn1_meths := FC_ENGINE_get_pkey_asn1_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_pkey_asn1_meths_removed)}
    if ENGINE_get_pkey_asn1_meths_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_pkey_asn1_meths)}
      ENGINE_get_pkey_asn1_meths := _ENGINE_get_pkey_asn1_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_pkey_asn1_meths_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_pkey_asn1_meths');
    {$ifend}
  end;
  
  ENGINE_get_cipher := LoadLibFunction(ADllHandle, ENGINE_get_cipher_procname);
  FuncLoadError := not assigned(ENGINE_get_cipher);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_cipher_allownil)}
    ENGINE_get_cipher := ERR_ENGINE_get_cipher;
    {$ifend}
    {$if declared(ENGINE_get_cipher_introduced)}
    if LibVersion < ENGINE_get_cipher_introduced then
    begin
      {$if declared(FC_ENGINE_get_cipher)}
      ENGINE_get_cipher := FC_ENGINE_get_cipher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_cipher_removed)}
    if ENGINE_get_cipher_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_cipher)}
      ENGINE_get_cipher := _ENGINE_get_cipher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_cipher_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_cipher');
    {$ifend}
  end;
  
  ENGINE_get_digest := LoadLibFunction(ADllHandle, ENGINE_get_digest_procname);
  FuncLoadError := not assigned(ENGINE_get_digest);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_digest_allownil)}
    ENGINE_get_digest := ERR_ENGINE_get_digest;
    {$ifend}
    {$if declared(ENGINE_get_digest_introduced)}
    if LibVersion < ENGINE_get_digest_introduced then
    begin
      {$if declared(FC_ENGINE_get_digest)}
      ENGINE_get_digest := FC_ENGINE_get_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_digest_removed)}
    if ENGINE_get_digest_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_digest)}
      ENGINE_get_digest := _ENGINE_get_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_digest');
    {$ifend}
  end;
  
  ENGINE_get_pkey_meth := LoadLibFunction(ADllHandle, ENGINE_get_pkey_meth_procname);
  FuncLoadError := not assigned(ENGINE_get_pkey_meth);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_pkey_meth_allownil)}
    ENGINE_get_pkey_meth := ERR_ENGINE_get_pkey_meth;
    {$ifend}
    {$if declared(ENGINE_get_pkey_meth_introduced)}
    if LibVersion < ENGINE_get_pkey_meth_introduced then
    begin
      {$if declared(FC_ENGINE_get_pkey_meth)}
      ENGINE_get_pkey_meth := FC_ENGINE_get_pkey_meth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_pkey_meth_removed)}
    if ENGINE_get_pkey_meth_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_pkey_meth)}
      ENGINE_get_pkey_meth := _ENGINE_get_pkey_meth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_pkey_meth_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_pkey_meth');
    {$ifend}
  end;
  
  ENGINE_get_pkey_asn1_meth := LoadLibFunction(ADllHandle, ENGINE_get_pkey_asn1_meth_procname);
  FuncLoadError := not assigned(ENGINE_get_pkey_asn1_meth);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_pkey_asn1_meth_allownil)}
    ENGINE_get_pkey_asn1_meth := ERR_ENGINE_get_pkey_asn1_meth;
    {$ifend}
    {$if declared(ENGINE_get_pkey_asn1_meth_introduced)}
    if LibVersion < ENGINE_get_pkey_asn1_meth_introduced then
    begin
      {$if declared(FC_ENGINE_get_pkey_asn1_meth)}
      ENGINE_get_pkey_asn1_meth := FC_ENGINE_get_pkey_asn1_meth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_pkey_asn1_meth_removed)}
    if ENGINE_get_pkey_asn1_meth_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_pkey_asn1_meth)}
      ENGINE_get_pkey_asn1_meth := _ENGINE_get_pkey_asn1_meth;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_pkey_asn1_meth_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_pkey_asn1_meth');
    {$ifend}
  end;
  
  ENGINE_get_pkey_asn1_meth_str := LoadLibFunction(ADllHandle, ENGINE_get_pkey_asn1_meth_str_procname);
  FuncLoadError := not assigned(ENGINE_get_pkey_asn1_meth_str);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_pkey_asn1_meth_str_allownil)}
    ENGINE_get_pkey_asn1_meth_str := ERR_ENGINE_get_pkey_asn1_meth_str;
    {$ifend}
    {$if declared(ENGINE_get_pkey_asn1_meth_str_introduced)}
    if LibVersion < ENGINE_get_pkey_asn1_meth_str_introduced then
    begin
      {$if declared(FC_ENGINE_get_pkey_asn1_meth_str)}
      ENGINE_get_pkey_asn1_meth_str := FC_ENGINE_get_pkey_asn1_meth_str;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_pkey_asn1_meth_str_removed)}
    if ENGINE_get_pkey_asn1_meth_str_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_pkey_asn1_meth_str)}
      ENGINE_get_pkey_asn1_meth_str := _ENGINE_get_pkey_asn1_meth_str;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_pkey_asn1_meth_str_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_pkey_asn1_meth_str');
    {$ifend}
  end;
  
  ENGINE_pkey_asn1_find_str := LoadLibFunction(ADllHandle, ENGINE_pkey_asn1_find_str_procname);
  FuncLoadError := not assigned(ENGINE_pkey_asn1_find_str);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_pkey_asn1_find_str_allownil)}
    ENGINE_pkey_asn1_find_str := ERR_ENGINE_pkey_asn1_find_str;
    {$ifend}
    {$if declared(ENGINE_pkey_asn1_find_str_introduced)}
    if LibVersion < ENGINE_pkey_asn1_find_str_introduced then
    begin
      {$if declared(FC_ENGINE_pkey_asn1_find_str)}
      ENGINE_pkey_asn1_find_str := FC_ENGINE_pkey_asn1_find_str;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_pkey_asn1_find_str_removed)}
    if ENGINE_pkey_asn1_find_str_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_pkey_asn1_find_str)}
      ENGINE_pkey_asn1_find_str := _ENGINE_pkey_asn1_find_str;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_pkey_asn1_find_str_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_pkey_asn1_find_str');
    {$ifend}
  end;
  
  ENGINE_get_cmd_defns := LoadLibFunction(ADllHandle, ENGINE_get_cmd_defns_procname);
  FuncLoadError := not assigned(ENGINE_get_cmd_defns);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_cmd_defns_allownil)}
    ENGINE_get_cmd_defns := ERR_ENGINE_get_cmd_defns;
    {$ifend}
    {$if declared(ENGINE_get_cmd_defns_introduced)}
    if LibVersion < ENGINE_get_cmd_defns_introduced then
    begin
      {$if declared(FC_ENGINE_get_cmd_defns)}
      ENGINE_get_cmd_defns := FC_ENGINE_get_cmd_defns;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_cmd_defns_removed)}
    if ENGINE_get_cmd_defns_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_cmd_defns)}
      ENGINE_get_cmd_defns := _ENGINE_get_cmd_defns;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_cmd_defns_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_cmd_defns');
    {$ifend}
  end;
  
  ENGINE_get_flags := LoadLibFunction(ADllHandle, ENGINE_get_flags_procname);
  FuncLoadError := not assigned(ENGINE_get_flags);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_flags_allownil)}
    ENGINE_get_flags := ERR_ENGINE_get_flags;
    {$ifend}
    {$if declared(ENGINE_get_flags_introduced)}
    if LibVersion < ENGINE_get_flags_introduced then
    begin
      {$if declared(FC_ENGINE_get_flags)}
      ENGINE_get_flags := FC_ENGINE_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_flags_removed)}
    if ENGINE_get_flags_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_flags)}
      ENGINE_get_flags := _ENGINE_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_flags');
    {$ifend}
  end;
  
  ENGINE_init := LoadLibFunction(ADllHandle, ENGINE_init_procname);
  FuncLoadError := not assigned(ENGINE_init);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_init_allownil)}
    ENGINE_init := ERR_ENGINE_init;
    {$ifend}
    {$if declared(ENGINE_init_introduced)}
    if LibVersion < ENGINE_init_introduced then
    begin
      {$if declared(FC_ENGINE_init)}
      ENGINE_init := FC_ENGINE_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_init_removed)}
    if ENGINE_init_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_init)}
      ENGINE_init := _ENGINE_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_init_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_init');
    {$ifend}
  end;
  
  ENGINE_finish := LoadLibFunction(ADllHandle, ENGINE_finish_procname);
  FuncLoadError := not assigned(ENGINE_finish);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_finish_allownil)}
    ENGINE_finish := ERR_ENGINE_finish;
    {$ifend}
    {$if declared(ENGINE_finish_introduced)}
    if LibVersion < ENGINE_finish_introduced then
    begin
      {$if declared(FC_ENGINE_finish)}
      ENGINE_finish := FC_ENGINE_finish;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_finish_removed)}
    if ENGINE_finish_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_finish)}
      ENGINE_finish := _ENGINE_finish;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_finish_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_finish');
    {$ifend}
  end;
  
  ENGINE_load_private_key := LoadLibFunction(ADllHandle, ENGINE_load_private_key_procname);
  FuncLoadError := not assigned(ENGINE_load_private_key);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_load_private_key_allownil)}
    ENGINE_load_private_key := ERR_ENGINE_load_private_key;
    {$ifend}
    {$if declared(ENGINE_load_private_key_introduced)}
    if LibVersion < ENGINE_load_private_key_introduced then
    begin
      {$if declared(FC_ENGINE_load_private_key)}
      ENGINE_load_private_key := FC_ENGINE_load_private_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_load_private_key_removed)}
    if ENGINE_load_private_key_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_load_private_key)}
      ENGINE_load_private_key := _ENGINE_load_private_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_load_private_key_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_load_private_key');
    {$ifend}
  end;
  
  ENGINE_load_public_key := LoadLibFunction(ADllHandle, ENGINE_load_public_key_procname);
  FuncLoadError := not assigned(ENGINE_load_public_key);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_load_public_key_allownil)}
    ENGINE_load_public_key := ERR_ENGINE_load_public_key;
    {$ifend}
    {$if declared(ENGINE_load_public_key_introduced)}
    if LibVersion < ENGINE_load_public_key_introduced then
    begin
      {$if declared(FC_ENGINE_load_public_key)}
      ENGINE_load_public_key := FC_ENGINE_load_public_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_load_public_key_removed)}
    if ENGINE_load_public_key_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_load_public_key)}
      ENGINE_load_public_key := _ENGINE_load_public_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_load_public_key_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_load_public_key');
    {$ifend}
  end;
  
  ENGINE_load_ssl_client_cert := LoadLibFunction(ADllHandle, ENGINE_load_ssl_client_cert_procname);
  FuncLoadError := not assigned(ENGINE_load_ssl_client_cert);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_load_ssl_client_cert_allownil)}
    ENGINE_load_ssl_client_cert := ERR_ENGINE_load_ssl_client_cert;
    {$ifend}
    {$if declared(ENGINE_load_ssl_client_cert_introduced)}
    if LibVersion < ENGINE_load_ssl_client_cert_introduced then
    begin
      {$if declared(FC_ENGINE_load_ssl_client_cert)}
      ENGINE_load_ssl_client_cert := FC_ENGINE_load_ssl_client_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_load_ssl_client_cert_removed)}
    if ENGINE_load_ssl_client_cert_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_load_ssl_client_cert)}
      ENGINE_load_ssl_client_cert := _ENGINE_load_ssl_client_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_load_ssl_client_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_load_ssl_client_cert');
    {$ifend}
  end;
  
  ENGINE_get_default_RSA := LoadLibFunction(ADllHandle, ENGINE_get_default_RSA_procname);
  FuncLoadError := not assigned(ENGINE_get_default_RSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_default_RSA_allownil)}
    ENGINE_get_default_RSA := ERR_ENGINE_get_default_RSA;
    {$ifend}
    {$if declared(ENGINE_get_default_RSA_introduced)}
    if LibVersion < ENGINE_get_default_RSA_introduced then
    begin
      {$if declared(FC_ENGINE_get_default_RSA)}
      ENGINE_get_default_RSA := FC_ENGINE_get_default_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_default_RSA_removed)}
    if ENGINE_get_default_RSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_default_RSA)}
      ENGINE_get_default_RSA := _ENGINE_get_default_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_default_RSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_default_RSA');
    {$ifend}
  end;
  
  ENGINE_get_default_DSA := LoadLibFunction(ADllHandle, ENGINE_get_default_DSA_procname);
  FuncLoadError := not assigned(ENGINE_get_default_DSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_default_DSA_allownil)}
    ENGINE_get_default_DSA := ERR_ENGINE_get_default_DSA;
    {$ifend}
    {$if declared(ENGINE_get_default_DSA_introduced)}
    if LibVersion < ENGINE_get_default_DSA_introduced then
    begin
      {$if declared(FC_ENGINE_get_default_DSA)}
      ENGINE_get_default_DSA := FC_ENGINE_get_default_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_default_DSA_removed)}
    if ENGINE_get_default_DSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_default_DSA)}
      ENGINE_get_default_DSA := _ENGINE_get_default_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_default_DSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_default_DSA');
    {$ifend}
  end;
  
  ENGINE_get_default_EC := LoadLibFunction(ADllHandle, ENGINE_get_default_EC_procname);
  FuncLoadError := not assigned(ENGINE_get_default_EC);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_default_EC_allownil)}
    ENGINE_get_default_EC := ERR_ENGINE_get_default_EC;
    {$ifend}
    {$if declared(ENGINE_get_default_EC_introduced)}
    if LibVersion < ENGINE_get_default_EC_introduced then
    begin
      {$if declared(FC_ENGINE_get_default_EC)}
      ENGINE_get_default_EC := FC_ENGINE_get_default_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_default_EC_removed)}
    if ENGINE_get_default_EC_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_default_EC)}
      ENGINE_get_default_EC := _ENGINE_get_default_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_default_EC_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_default_EC');
    {$ifend}
  end;
  
  ENGINE_get_default_DH := LoadLibFunction(ADllHandle, ENGINE_get_default_DH_procname);
  FuncLoadError := not assigned(ENGINE_get_default_DH);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_default_DH_allownil)}
    ENGINE_get_default_DH := ERR_ENGINE_get_default_DH;
    {$ifend}
    {$if declared(ENGINE_get_default_DH_introduced)}
    if LibVersion < ENGINE_get_default_DH_introduced then
    begin
      {$if declared(FC_ENGINE_get_default_DH)}
      ENGINE_get_default_DH := FC_ENGINE_get_default_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_default_DH_removed)}
    if ENGINE_get_default_DH_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_default_DH)}
      ENGINE_get_default_DH := _ENGINE_get_default_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_default_DH_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_default_DH');
    {$ifend}
  end;
  
  ENGINE_get_default_RAND := LoadLibFunction(ADllHandle, ENGINE_get_default_RAND_procname);
  FuncLoadError := not assigned(ENGINE_get_default_RAND);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_default_RAND_allownil)}
    ENGINE_get_default_RAND := ERR_ENGINE_get_default_RAND;
    {$ifend}
    {$if declared(ENGINE_get_default_RAND_introduced)}
    if LibVersion < ENGINE_get_default_RAND_introduced then
    begin
      {$if declared(FC_ENGINE_get_default_RAND)}
      ENGINE_get_default_RAND := FC_ENGINE_get_default_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_default_RAND_removed)}
    if ENGINE_get_default_RAND_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_default_RAND)}
      ENGINE_get_default_RAND := _ENGINE_get_default_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_default_RAND_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_default_RAND');
    {$ifend}
  end;
  
  ENGINE_get_cipher_engine := LoadLibFunction(ADllHandle, ENGINE_get_cipher_engine_procname);
  FuncLoadError := not assigned(ENGINE_get_cipher_engine);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_cipher_engine_allownil)}
    ENGINE_get_cipher_engine := ERR_ENGINE_get_cipher_engine;
    {$ifend}
    {$if declared(ENGINE_get_cipher_engine_introduced)}
    if LibVersion < ENGINE_get_cipher_engine_introduced then
    begin
      {$if declared(FC_ENGINE_get_cipher_engine)}
      ENGINE_get_cipher_engine := FC_ENGINE_get_cipher_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_cipher_engine_removed)}
    if ENGINE_get_cipher_engine_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_cipher_engine)}
      ENGINE_get_cipher_engine := _ENGINE_get_cipher_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_cipher_engine_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_cipher_engine');
    {$ifend}
  end;
  
  ENGINE_get_digest_engine := LoadLibFunction(ADllHandle, ENGINE_get_digest_engine_procname);
  FuncLoadError := not assigned(ENGINE_get_digest_engine);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_digest_engine_allownil)}
    ENGINE_get_digest_engine := ERR_ENGINE_get_digest_engine;
    {$ifend}
    {$if declared(ENGINE_get_digest_engine_introduced)}
    if LibVersion < ENGINE_get_digest_engine_introduced then
    begin
      {$if declared(FC_ENGINE_get_digest_engine)}
      ENGINE_get_digest_engine := FC_ENGINE_get_digest_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_digest_engine_removed)}
    if ENGINE_get_digest_engine_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_digest_engine)}
      ENGINE_get_digest_engine := _ENGINE_get_digest_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_digest_engine_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_digest_engine');
    {$ifend}
  end;
  
  ENGINE_get_pkey_meth_engine := LoadLibFunction(ADllHandle, ENGINE_get_pkey_meth_engine_procname);
  FuncLoadError := not assigned(ENGINE_get_pkey_meth_engine);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_pkey_meth_engine_allownil)}
    ENGINE_get_pkey_meth_engine := ERR_ENGINE_get_pkey_meth_engine;
    {$ifend}
    {$if declared(ENGINE_get_pkey_meth_engine_introduced)}
    if LibVersion < ENGINE_get_pkey_meth_engine_introduced then
    begin
      {$if declared(FC_ENGINE_get_pkey_meth_engine)}
      ENGINE_get_pkey_meth_engine := FC_ENGINE_get_pkey_meth_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_pkey_meth_engine_removed)}
    if ENGINE_get_pkey_meth_engine_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_pkey_meth_engine)}
      ENGINE_get_pkey_meth_engine := _ENGINE_get_pkey_meth_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_pkey_meth_engine_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_pkey_meth_engine');
    {$ifend}
  end;
  
  ENGINE_get_pkey_asn1_meth_engine := LoadLibFunction(ADllHandle, ENGINE_get_pkey_asn1_meth_engine_procname);
  FuncLoadError := not assigned(ENGINE_get_pkey_asn1_meth_engine);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_pkey_asn1_meth_engine_allownil)}
    ENGINE_get_pkey_asn1_meth_engine := ERR_ENGINE_get_pkey_asn1_meth_engine;
    {$ifend}
    {$if declared(ENGINE_get_pkey_asn1_meth_engine_introduced)}
    if LibVersion < ENGINE_get_pkey_asn1_meth_engine_introduced then
    begin
      {$if declared(FC_ENGINE_get_pkey_asn1_meth_engine)}
      ENGINE_get_pkey_asn1_meth_engine := FC_ENGINE_get_pkey_asn1_meth_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_pkey_asn1_meth_engine_removed)}
    if ENGINE_get_pkey_asn1_meth_engine_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_pkey_asn1_meth_engine)}
      ENGINE_get_pkey_asn1_meth_engine := _ENGINE_get_pkey_asn1_meth_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_pkey_asn1_meth_engine_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_pkey_asn1_meth_engine');
    {$ifend}
  end;
  
  ENGINE_set_default_RSA := LoadLibFunction(ADllHandle, ENGINE_set_default_RSA_procname);
  FuncLoadError := not assigned(ENGINE_set_default_RSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_default_RSA_allownil)}
    ENGINE_set_default_RSA := ERR_ENGINE_set_default_RSA;
    {$ifend}
    {$if declared(ENGINE_set_default_RSA_introduced)}
    if LibVersion < ENGINE_set_default_RSA_introduced then
    begin
      {$if declared(FC_ENGINE_set_default_RSA)}
      ENGINE_set_default_RSA := FC_ENGINE_set_default_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_default_RSA_removed)}
    if ENGINE_set_default_RSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_default_RSA)}
      ENGINE_set_default_RSA := _ENGINE_set_default_RSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_default_RSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_default_RSA');
    {$ifend}
  end;
  
  ENGINE_set_default_string := LoadLibFunction(ADllHandle, ENGINE_set_default_string_procname);
  FuncLoadError := not assigned(ENGINE_set_default_string);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_default_string_allownil)}
    ENGINE_set_default_string := ERR_ENGINE_set_default_string;
    {$ifend}
    {$if declared(ENGINE_set_default_string_introduced)}
    if LibVersion < ENGINE_set_default_string_introduced then
    begin
      {$if declared(FC_ENGINE_set_default_string)}
      ENGINE_set_default_string := FC_ENGINE_set_default_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_default_string_removed)}
    if ENGINE_set_default_string_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_default_string)}
      ENGINE_set_default_string := _ENGINE_set_default_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_default_string_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_default_string');
    {$ifend}
  end;
  
  ENGINE_set_default_DSA := LoadLibFunction(ADllHandle, ENGINE_set_default_DSA_procname);
  FuncLoadError := not assigned(ENGINE_set_default_DSA);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_default_DSA_allownil)}
    ENGINE_set_default_DSA := ERR_ENGINE_set_default_DSA;
    {$ifend}
    {$if declared(ENGINE_set_default_DSA_introduced)}
    if LibVersion < ENGINE_set_default_DSA_introduced then
    begin
      {$if declared(FC_ENGINE_set_default_DSA)}
      ENGINE_set_default_DSA := FC_ENGINE_set_default_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_default_DSA_removed)}
    if ENGINE_set_default_DSA_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_default_DSA)}
      ENGINE_set_default_DSA := _ENGINE_set_default_DSA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_default_DSA_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_default_DSA');
    {$ifend}
  end;
  
  ENGINE_set_default_EC := LoadLibFunction(ADllHandle, ENGINE_set_default_EC_procname);
  FuncLoadError := not assigned(ENGINE_set_default_EC);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_default_EC_allownil)}
    ENGINE_set_default_EC := ERR_ENGINE_set_default_EC;
    {$ifend}
    {$if declared(ENGINE_set_default_EC_introduced)}
    if LibVersion < ENGINE_set_default_EC_introduced then
    begin
      {$if declared(FC_ENGINE_set_default_EC)}
      ENGINE_set_default_EC := FC_ENGINE_set_default_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_default_EC_removed)}
    if ENGINE_set_default_EC_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_default_EC)}
      ENGINE_set_default_EC := _ENGINE_set_default_EC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_default_EC_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_default_EC');
    {$ifend}
  end;
  
  ENGINE_set_default_DH := LoadLibFunction(ADllHandle, ENGINE_set_default_DH_procname);
  FuncLoadError := not assigned(ENGINE_set_default_DH);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_default_DH_allownil)}
    ENGINE_set_default_DH := ERR_ENGINE_set_default_DH;
    {$ifend}
    {$if declared(ENGINE_set_default_DH_introduced)}
    if LibVersion < ENGINE_set_default_DH_introduced then
    begin
      {$if declared(FC_ENGINE_set_default_DH)}
      ENGINE_set_default_DH := FC_ENGINE_set_default_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_default_DH_removed)}
    if ENGINE_set_default_DH_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_default_DH)}
      ENGINE_set_default_DH := _ENGINE_set_default_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_default_DH_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_default_DH');
    {$ifend}
  end;
  
  ENGINE_set_default_RAND := LoadLibFunction(ADllHandle, ENGINE_set_default_RAND_procname);
  FuncLoadError := not assigned(ENGINE_set_default_RAND);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_default_RAND_allownil)}
    ENGINE_set_default_RAND := ERR_ENGINE_set_default_RAND;
    {$ifend}
    {$if declared(ENGINE_set_default_RAND_introduced)}
    if LibVersion < ENGINE_set_default_RAND_introduced then
    begin
      {$if declared(FC_ENGINE_set_default_RAND)}
      ENGINE_set_default_RAND := FC_ENGINE_set_default_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_default_RAND_removed)}
    if ENGINE_set_default_RAND_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_default_RAND)}
      ENGINE_set_default_RAND := _ENGINE_set_default_RAND;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_default_RAND_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_default_RAND');
    {$ifend}
  end;
  
  ENGINE_set_default_ciphers := LoadLibFunction(ADllHandle, ENGINE_set_default_ciphers_procname);
  FuncLoadError := not assigned(ENGINE_set_default_ciphers);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_default_ciphers_allownil)}
    ENGINE_set_default_ciphers := ERR_ENGINE_set_default_ciphers;
    {$ifend}
    {$if declared(ENGINE_set_default_ciphers_introduced)}
    if LibVersion < ENGINE_set_default_ciphers_introduced then
    begin
      {$if declared(FC_ENGINE_set_default_ciphers)}
      ENGINE_set_default_ciphers := FC_ENGINE_set_default_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_default_ciphers_removed)}
    if ENGINE_set_default_ciphers_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_default_ciphers)}
      ENGINE_set_default_ciphers := _ENGINE_set_default_ciphers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_default_ciphers_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_default_ciphers');
    {$ifend}
  end;
  
  ENGINE_set_default_digests := LoadLibFunction(ADllHandle, ENGINE_set_default_digests_procname);
  FuncLoadError := not assigned(ENGINE_set_default_digests);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_default_digests_allownil)}
    ENGINE_set_default_digests := ERR_ENGINE_set_default_digests;
    {$ifend}
    {$if declared(ENGINE_set_default_digests_introduced)}
    if LibVersion < ENGINE_set_default_digests_introduced then
    begin
      {$if declared(FC_ENGINE_set_default_digests)}
      ENGINE_set_default_digests := FC_ENGINE_set_default_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_default_digests_removed)}
    if ENGINE_set_default_digests_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_default_digests)}
      ENGINE_set_default_digests := _ENGINE_set_default_digests;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_default_digests_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_default_digests');
    {$ifend}
  end;
  
  ENGINE_set_default_pkey_meths := LoadLibFunction(ADllHandle, ENGINE_set_default_pkey_meths_procname);
  FuncLoadError := not assigned(ENGINE_set_default_pkey_meths);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_default_pkey_meths_allownil)}
    ENGINE_set_default_pkey_meths := ERR_ENGINE_set_default_pkey_meths;
    {$ifend}
    {$if declared(ENGINE_set_default_pkey_meths_introduced)}
    if LibVersion < ENGINE_set_default_pkey_meths_introduced then
    begin
      {$if declared(FC_ENGINE_set_default_pkey_meths)}
      ENGINE_set_default_pkey_meths := FC_ENGINE_set_default_pkey_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_default_pkey_meths_removed)}
    if ENGINE_set_default_pkey_meths_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_default_pkey_meths)}
      ENGINE_set_default_pkey_meths := _ENGINE_set_default_pkey_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_default_pkey_meths_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_default_pkey_meths');
    {$ifend}
  end;
  
  ENGINE_set_default_pkey_asn1_meths := LoadLibFunction(ADllHandle, ENGINE_set_default_pkey_asn1_meths_procname);
  FuncLoadError := not assigned(ENGINE_set_default_pkey_asn1_meths);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_default_pkey_asn1_meths_allownil)}
    ENGINE_set_default_pkey_asn1_meths := ERR_ENGINE_set_default_pkey_asn1_meths;
    {$ifend}
    {$if declared(ENGINE_set_default_pkey_asn1_meths_introduced)}
    if LibVersion < ENGINE_set_default_pkey_asn1_meths_introduced then
    begin
      {$if declared(FC_ENGINE_set_default_pkey_asn1_meths)}
      ENGINE_set_default_pkey_asn1_meths := FC_ENGINE_set_default_pkey_asn1_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_default_pkey_asn1_meths_removed)}
    if ENGINE_set_default_pkey_asn1_meths_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_default_pkey_asn1_meths)}
      ENGINE_set_default_pkey_asn1_meths := _ENGINE_set_default_pkey_asn1_meths;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_default_pkey_asn1_meths_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_default_pkey_asn1_meths');
    {$ifend}
  end;
  
  ENGINE_set_default := LoadLibFunction(ADllHandle, ENGINE_set_default_procname);
  FuncLoadError := not assigned(ENGINE_set_default);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_set_default_allownil)}
    ENGINE_set_default := ERR_ENGINE_set_default;
    {$ifend}
    {$if declared(ENGINE_set_default_introduced)}
    if LibVersion < ENGINE_set_default_introduced then
    begin
      {$if declared(FC_ENGINE_set_default)}
      ENGINE_set_default := FC_ENGINE_set_default;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_set_default_removed)}
    if ENGINE_set_default_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_set_default)}
      ENGINE_set_default := _ENGINE_set_default;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_set_default_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_set_default');
    {$ifend}
  end;
  
  ENGINE_add_conf_module := LoadLibFunction(ADllHandle, ENGINE_add_conf_module_procname);
  FuncLoadError := not assigned(ENGINE_add_conf_module);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_add_conf_module_allownil)}
    ENGINE_add_conf_module := ERR_ENGINE_add_conf_module;
    {$ifend}
    {$if declared(ENGINE_add_conf_module_introduced)}
    if LibVersion < ENGINE_add_conf_module_introduced then
    begin
      {$if declared(FC_ENGINE_add_conf_module)}
      ENGINE_add_conf_module := FC_ENGINE_add_conf_module;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_add_conf_module_removed)}
    if ENGINE_add_conf_module_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_add_conf_module)}
      ENGINE_add_conf_module := _ENGINE_add_conf_module;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_add_conf_module_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_add_conf_module');
    {$ifend}
  end;
  
  ENGINE_get_static_state := LoadLibFunction(ADllHandle, ENGINE_get_static_state_procname);
  FuncLoadError := not assigned(ENGINE_get_static_state);
  if FuncLoadError then
  begin
    {$if not defined(ENGINE_get_static_state_allownil)}
    ENGINE_get_static_state := ERR_ENGINE_get_static_state;
    {$ifend}
    {$if declared(ENGINE_get_static_state_introduced)}
    if LibVersion < ENGINE_get_static_state_introduced then
    begin
      {$if declared(FC_ENGINE_get_static_state)}
      ENGINE_get_static_state := FC_ENGINE_get_static_state;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ENGINE_get_static_state_removed)}
    if ENGINE_get_static_state_removed <= LibVersion then
    begin
      {$if declared(_ENGINE_get_static_state)}
      ENGINE_get_static_state := _ENGINE_get_static_state;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ENGINE_get_static_state_allownil)}
    if FuncLoadError then
      AFailed.Add('ENGINE_get_static_state');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  ENGINE_get_first := nil;
  ENGINE_get_last := nil;
  ENGINE_get_next := nil;
  ENGINE_get_prev := nil;
  ENGINE_add := nil;
  ENGINE_remove := nil;
  ENGINE_by_id := nil;
  ENGINE_load_builtin_engines := nil;
  ENGINE_get_table_flags := nil;
  ENGINE_set_table_flags := nil;
  ENGINE_register_RSA := nil;
  ENGINE_unregister_RSA := nil;
  ENGINE_register_all_RSA := nil;
  ENGINE_register_DSA := nil;
  ENGINE_unregister_DSA := nil;
  ENGINE_register_all_DSA := nil;
  ENGINE_register_EC := nil;
  ENGINE_unregister_EC := nil;
  ENGINE_register_all_EC := nil;
  ENGINE_register_DH := nil;
  ENGINE_unregister_DH := nil;
  ENGINE_register_all_DH := nil;
  ENGINE_register_RAND := nil;
  ENGINE_unregister_RAND := nil;
  ENGINE_register_all_RAND := nil;
  ENGINE_register_ciphers := nil;
  ENGINE_unregister_ciphers := nil;
  ENGINE_register_all_ciphers := nil;
  ENGINE_register_digests := nil;
  ENGINE_unregister_digests := nil;
  ENGINE_register_all_digests := nil;
  ENGINE_register_pkey_meths := nil;
  ENGINE_unregister_pkey_meths := nil;
  ENGINE_register_all_pkey_meths := nil;
  ENGINE_register_pkey_asn1_meths := nil;
  ENGINE_unregister_pkey_asn1_meths := nil;
  ENGINE_register_all_pkey_asn1_meths := nil;
  ENGINE_register_complete := nil;
  ENGINE_register_all_complete := nil;
  ENGINE_ctrl := nil;
  ENGINE_cmd_is_executable := nil;
  ENGINE_ctrl_cmd := nil;
  ENGINE_ctrl_cmd_string := nil;
  ENGINE_new := nil;
  ENGINE_free := nil;
  ENGINE_up_ref := nil;
  ENGINE_set_id := nil;
  ENGINE_set_name := nil;
  ENGINE_set_RSA := nil;
  ENGINE_set_DSA := nil;
  ENGINE_set_EC := nil;
  ENGINE_set_DH := nil;
  ENGINE_set_RAND := nil;
  ENGINE_set_destroy_function := nil;
  ENGINE_set_init_function := nil;
  ENGINE_set_finish_function := nil;
  ENGINE_set_ctrl_function := nil;
  ENGINE_set_load_privkey_function := nil;
  ENGINE_set_load_pubkey_function := nil;
  ENGINE_set_load_ssl_client_cert_function := nil;
  ENGINE_set_ciphers := nil;
  ENGINE_set_digests := nil;
  ENGINE_set_pkey_meths := nil;
  ENGINE_set_pkey_asn1_meths := nil;
  ENGINE_set_flags := nil;
  ENGINE_set_cmd_defns := nil;
  ENGINE_set_ex_data := nil;
  ENGINE_get_ex_data := nil;
  ENGINE_get_id := nil;
  ENGINE_get_name := nil;
  ENGINE_get_RSA := nil;
  ENGINE_get_DSA := nil;
  ENGINE_get_EC := nil;
  ENGINE_get_DH := nil;
  ENGINE_get_RAND := nil;
  ENGINE_get_destroy_function := nil;
  ENGINE_get_init_function := nil;
  ENGINE_get_finish_function := nil;
  ENGINE_get_ctrl_function := nil;
  ENGINE_get_load_privkey_function := nil;
  ENGINE_get_load_pubkey_function := nil;
  ENGINE_get_ssl_client_cert_function := nil;
  ENGINE_get_ciphers := nil;
  ENGINE_get_digests := nil;
  ENGINE_get_pkey_meths := nil;
  ENGINE_get_pkey_asn1_meths := nil;
  ENGINE_get_cipher := nil;
  ENGINE_get_digest := nil;
  ENGINE_get_pkey_meth := nil;
  ENGINE_get_pkey_asn1_meth := nil;
  ENGINE_get_pkey_asn1_meth_str := nil;
  ENGINE_pkey_asn1_find_str := nil;
  ENGINE_get_cmd_defns := nil;
  ENGINE_get_flags := nil;
  ENGINE_init := nil;
  ENGINE_finish := nil;
  ENGINE_load_private_key := nil;
  ENGINE_load_public_key := nil;
  ENGINE_load_ssl_client_cert := nil;
  ENGINE_get_default_RSA := nil;
  ENGINE_get_default_DSA := nil;
  ENGINE_get_default_EC := nil;
  ENGINE_get_default_DH := nil;
  ENGINE_get_default_RAND := nil;
  ENGINE_get_cipher_engine := nil;
  ENGINE_get_digest_engine := nil;
  ENGINE_get_pkey_meth_engine := nil;
  ENGINE_get_pkey_asn1_meth_engine := nil;
  ENGINE_set_default_RSA := nil;
  ENGINE_set_default_string := nil;
  ENGINE_set_default_DSA := nil;
  ENGINE_set_default_EC := nil;
  ENGINE_set_default_DH := nil;
  ENGINE_set_default_RAND := nil;
  ENGINE_set_default_ciphers := nil;
  ENGINE_set_default_digests := nil;
  ENGINE_set_default_pkey_meths := nil;
  ENGINE_set_default_pkey_asn1_meths := nil;
  ENGINE_set_default := nil;
  ENGINE_add_conf_module := nil;
  ENGINE_get_static_state := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.