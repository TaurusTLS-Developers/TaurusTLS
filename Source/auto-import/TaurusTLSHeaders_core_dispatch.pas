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

unit TaurusTLSHeaders_core_dispatch;

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
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  TOSSL_FUNC_func_cb = procedure; cdecl;
  TOSSL_FUNC_core_gettable_params_fn_func_cb = function(arg1: POSSL_CORE_HANDLE): POSSL_PARAM_ARRAY; cdecl;
  TOSSL_FUNC_core_get_params_fn_func_cb = function(arg1: POSSL_CORE_HANDLE; arg2: POSSL_PARAM_ARRAY): TIdC_INT; cdecl;
  TOSSL_FUNC_core_thread_start_fn_func_cb = procedure(arg1: Pointer); cdecl;
  TOSSL_FUNC_core_thread_start_fn_func_cb = function(arg1: POSSL_CORE_HANDLE; arg2: TOSSL_FUNC_core_thread_start_fn_func_cb; arg3: Pointer): TIdC_INT; cdecl;
  TOSSL_FUNC_core_get_libctx_fn_func_cb = function(arg1: POSSL_CORE_HANDLE): POPENSSL_CORE_CTX; cdecl;
  TOSSL_FUNC_core_new_error_fn_func_cb = procedure(arg1: POSSL_CORE_HANDLE); cdecl;
  TOSSL_FUNC_core_set_error_debug_fn_func_cb = procedure(arg1: POSSL_CORE_HANDLE; arg2: PIdAnsiChar; arg3: TIdC_INT; arg4: PIdAnsiChar); cdecl;
  TOSSL_FUNC_core_vset_error_fn_func_cb = procedure(arg1: POSSL_CORE_HANDLE; arg2: UInt32; arg3: PIdAnsiChar; arg4: Tva_list); cdecl;
  TOSSL_FUNC_core_set_error_mark_fn_func_cb = function(arg1: POSSL_CORE_HANDLE): TIdC_INT; cdecl;
  TOSSL_FUNC_core_obj_add_sigid_fn_func_cb = function(arg1: POSSL_CORE_HANDLE; arg2: PIdAnsiChar; arg3: PIdAnsiChar; arg4: PIdAnsiChar): TIdC_INT; cdecl;
  TOSSL_FUNC_CRYPTO_malloc_fn_func_cb = function(arg1: TIdC_SIZET; arg2: PIdAnsiChar; arg3: TIdC_INT): Pointer; cdecl;
  TOSSL_FUNC_CRYPTO_free_fn_func_cb = procedure(arg1: Pointer; arg2: PIdAnsiChar; arg3: TIdC_INT); cdecl;
  TOSSL_FUNC_CRYPTO_clear_free_fn_func_cb = procedure(arg1: Pointer; arg2: TIdC_SIZET; arg3: PIdAnsiChar; arg4: TIdC_INT); cdecl;
  TOSSL_FUNC_CRYPTO_realloc_fn_func_cb = function(arg1: Pointer; arg2: TIdC_SIZET; arg3: PIdAnsiChar; arg4: TIdC_INT): Pointer; cdecl;
  TOSSL_FUNC_CRYPTO_clear_realloc_fn_func_cb = function(arg1: Pointer; arg2: TIdC_SIZET; arg3: TIdC_SIZET; arg4: PIdAnsiChar; arg5: TIdC_INT): Pointer; cdecl;
  TOSSL_FUNC_CRYPTO_secure_allocated_fn_func_cb = function(arg1: Pointer): TIdC_INT; cdecl;
  TOSSL_FUNC_OPENSSL_cleanse_fn_func_cb = procedure(arg1: Pointer; arg2: TIdC_SIZET); cdecl;
  TOSSL_FUNC_BIO_new_file_fn_func_cb = function(arg1: PIdAnsiChar; arg2: PIdAnsiChar): POSSL_CORE_BIO; cdecl;
  TOSSL_FUNC_BIO_new_membuf_fn_func_cb = function(arg1: Pointer; arg2: TIdC_INT): POSSL_CORE_BIO; cdecl;
  TOSSL_FUNC_BIO_read_ex_fn_func_cb = function(arg1: POSSL_CORE_BIO; arg2: Pointer; arg3: TIdC_SIZET; arg4: PIdC_SIZET): TIdC_INT; cdecl;
  TOSSL_FUNC_BIO_gets_fn_func_cb = function(arg1: POSSL_CORE_BIO; arg2: PIdAnsiChar; arg3: TIdC_INT): TIdC_INT; cdecl;
  TOSSL_FUNC_BIO_puts_fn_func_cb = function(arg1: POSSL_CORE_BIO; arg2: PIdAnsiChar): TIdC_INT; cdecl;
  TOSSL_FUNC_BIO_up_ref_fn_func_cb = function(arg1: POSSL_CORE_BIO): TIdC_INT; cdecl;
  TOSSL_FUNC_BIO_vprintf_fn_func_cb = function(arg1: POSSL_CORE_BIO; arg2: PIdAnsiChar; arg3: Tva_list): TIdC_INT; cdecl;
  TOSSL_FUNC_BIO_vsnprintf_fn_func_cb = function(arg1: PIdAnsiChar; arg2: TIdC_SIZET; arg3: PIdAnsiChar; arg4: Tva_list): TIdC_INT; cdecl;
  TOSSL_FUNC_BIO_ctrl_fn_func_cb = function(arg1: POSSL_CORE_BIO; arg2: TIdC_INT; arg3: TIdC_LONG; arg4: Pointer): TIdC_INT; cdecl;
  TOSSL_FUNC_indicator_cb_fn_func_cb = procedure(arg1: POPENSSL_CORE_CTX; arg2: PPOSSL_INDICATOR_CALLBACK); cdecl;
  TOSSL_FUNC_self_test_cb_fn_func_cb = procedure(arg1: POPENSSL_CORE_CTX; arg2: PPOSSL_CALLBACK; arg3: PPointer); cdecl;
  TOSSL_FUNC_get_entropy_fn_func_cb = function(arg1: POSSL_CORE_HANDLE; arg2: PPIdAnsiChar; arg3: TIdC_INT; arg4: TIdC_SIZET; arg5: TIdC_SIZET): TIdC_SIZET; cdecl;
  TOSSL_FUNC_cleanup_entropy_fn_func_cb = procedure(arg1: POSSL_CORE_HANDLE; arg2: PIdAnsiChar; arg3: TIdC_SIZET); cdecl;
  TOSSL_FUNC_get_nonce_fn_func_cb = function(arg1: POSSL_CORE_HANDLE; arg2: PPIdAnsiChar; arg3: TIdC_SIZET; arg4: TIdC_SIZET; arg5: Pointer; arg6: TIdC_SIZET): TIdC_SIZET; cdecl;
  TOSSL_FUNC_provider_register_child_cb_fn_func_cb = function(arg1: Possl_core_handle_st; arg2: Pointer): TIdC_INT; cdecl;
  TOSSL_FUNC_provider_register_child_cb_fn_func_cb = function(arg1: PIdAnsiChar; arg2: Pointer): TIdC_INT; cdecl;
  TOSSL_FUNC_provider_register_child_cb_fn_func_cb = function(arg1: POSSL_CORE_HANDLE; arg2: TOSSL_FUNC_provider_register_child_cb_fn_func_cb; arg3: TOSSL_FUNC_provider_register_child_cb_fn_func_cb; arg4: TOSSL_FUNC_provider_register_child_cb_fn_func_cb; arg5: Pointer): TIdC_INT; cdecl;
  TOSSL_FUNC_provider_name_fn_func_cb = function(arg1: POSSL_CORE_HANDLE): PIdAnsiChar; cdecl;
  TOSSL_FUNC_provider_get0_provider_ctx_fn_func_cb = function(arg1: POSSL_CORE_HANDLE): Pointer; cdecl;
  TOSSL_FUNC_provider_get0_dispatch_fn_func_cb = function(arg1: POSSL_CORE_HANDLE): POSSL_DISPATCH; cdecl;
  TOSSL_FUNC_provider_up_ref_fn_func_cb = function(arg1: POSSL_CORE_HANDLE; arg2: TIdC_INT): TIdC_INT; cdecl;
  TOSSL_FUNC_provider_gettable_params_fn_func_cb = function(arg1: Pointer): POSSL_PARAM_ARRAY; cdecl;
  TOSSL_FUNC_provider_get_params_fn_func_cb = function(arg1: Pointer; arg2: POSSL_PARAM_ARRAY): TIdC_INT; cdecl;
  TOSSL_FUNC_provider_query_operation_fn_func_cb = function(arg1: Pointer; arg2: TIdC_INT; arg3: PIdC_INT): POSSL_ALGORITHM; cdecl;
  TOSSL_FUNC_provider_unquery_operation_fn_func_cb = procedure(arg1: Pointer; arg2: TIdC_INT; arg3: POSSL_ALGORITHM); cdecl;
  TOSSL_FUNC_provider_get_reason_strings_fn_func_cb = function(arg1: Pointer): POSSL_ITEM; cdecl;
  TOSSL_FUNC_provider_get_capabilities_fn_func_cb = function(arg1: Possl_param_st; arg2: Pointer): TIdC_INT; cdecl;
  TOSSL_FUNC_provider_get_capabilities_fn_func_cb = function(arg1: Pointer; arg2: PIdAnsiChar; arg3: TOSSL_FUNC_provider_get_capabilities_fn_func_cb; arg4: Pointer): TIdC_INT; cdecl;
  TOSSL_FUNC_provider_random_bytes_fn_func_cb = function(arg1: Pointer; arg2: TIdC_INT; arg3: Pointer; arg4: TIdC_SIZET; arg5: TIdC_UINT): TIdC_INT; cdecl;
  TOSSL_FUNC_SSL_QUIC_TLS_crypto_send_fn_func_cb = function(arg1: PSSL; arg2: PIdAnsiChar; arg3: TIdC_SIZET; arg4: PIdC_SIZET; arg5: Pointer): TIdC_INT; cdecl;
  TOSSL_FUNC_SSL_QUIC_TLS_crypto_recv_rcd_fn_func_cb = function(arg1: PSSL; arg2: PPIdAnsiChar; arg3: PIdC_SIZET; arg4: Pointer): TIdC_INT; cdecl;
  TOSSL_FUNC_SSL_QUIC_TLS_crypto_release_rcd_fn_func_cb = function(arg1: PSSL; arg2: TIdC_SIZET; arg3: Pointer): TIdC_INT; cdecl;
  TOSSL_FUNC_SSL_QUIC_TLS_yield_secret_fn_func_cb = function(arg1: PSSL; arg2: UInt32; arg3: TIdC_INT; arg4: PIdAnsiChar; arg5: TIdC_SIZET; arg6: Pointer): TIdC_INT; cdecl;
  TOSSL_FUNC_SSL_QUIC_TLS_got_transport_params_fn_func_cb = function(arg1: PSSL; arg2: PIdAnsiChar; arg3: TIdC_SIZET; arg4: Pointer): TIdC_INT; cdecl;
  TOSSL_FUNC_SSL_QUIC_TLS_alert_fn_func_cb = function(arg1: PSSL; arg2: TIdC_UCHAR; arg3: Pointer): TIdC_INT; cdecl;
  TOSSL_FUNC_digest_newctx_fn_func_cb = function(arg1: Pointer): Pointer; cdecl;
  TOSSL_FUNC_digest_update_fn_func_cb = function(arg1: Pointer; arg2: PIdAnsiChar; arg3: TIdC_SIZET): TIdC_INT; cdecl;
  TOSSL_FUNC_digest_final_fn_func_cb = function(arg1: Pointer; arg2: PIdAnsiChar; arg3: PIdC_SIZET; arg4: TIdC_SIZET): TIdC_INT; cdecl;
  TOSSL_FUNC_digest_digest_fn_func_cb = function(arg1: Pointer; arg2: PIdAnsiChar; arg3: TIdC_SIZET; arg4: PIdAnsiChar; arg5: PIdC_SIZET; arg6: TIdC_SIZET): TIdC_INT; cdecl;
  TOSSL_FUNC_digest_copyctx_fn_func_cb = procedure(arg1: Pointer; arg2: Pointer); cdecl;
  TOSSL_FUNC_digest_get_params_fn_func_cb = function(arg1: POSSL_PARAM_ARRAY): TIdC_INT; cdecl;
  TOSSL_FUNC_digest_settable_ctx_params_fn_func_cb = function(arg1: Pointer; arg2: Pointer): POSSL_PARAM_ARRAY; cdecl;
  TOSSL_FUNC_cipher_encrypt_init_fn_func_cb = function(arg1: Pointer; arg2: PIdAnsiChar; arg3: TIdC_SIZET; arg4: PIdAnsiChar; arg5: TIdC_SIZET; arg6: POSSL_PARAM_ARRAY): TIdC_INT; cdecl;
  TOSSL_FUNC_cipher_update_fn_func_cb = function(arg1: Pointer; arg2: PIdAnsiChar; arg3: PIdC_SIZET; arg4: TIdC_SIZET; arg5: PIdAnsiChar; arg6: TIdC_SIZET): TIdC_INT; cdecl;
  TOSSL_FUNC_cipher_pipeline_encrypt_init_fn_func_cb = function(arg1: Pointer; arg2: PIdAnsiChar; arg3: TIdC_SIZET; arg4: TIdC_SIZET; arg5: PPIdAnsiChar; arg6: TIdC_SIZET; arg7: POSSL_PARAM_ARRAY): TIdC_INT; cdecl;
  TOSSL_FUNC_cipher_pipeline_update_fn_func_cb = function(arg1: Pointer; arg2: TIdC_SIZET; arg3: PPIdAnsiChar; arg4: PIdC_SIZET; arg5: PIdC_SIZET; arg6: PPIdAnsiChar; arg7: PIdC_SIZET): TIdC_INT; cdecl;
  TOSSL_FUNC_cipher_pipeline_final_fn_func_cb = function(arg1: Pointer; arg2: TIdC_SIZET; arg3: PPIdAnsiChar; arg4: PIdC_SIZET; arg5: PIdC_SIZET): TIdC_INT; cdecl;
  TOSSL_FUNC_cipher_encrypt_skey_init_fn_func_cb = function(arg1: Pointer; arg2: Pointer; arg3: PIdAnsiChar; arg4: TIdC_SIZET; arg5: POSSL_PARAM_ARRAY): TIdC_INT; cdecl;
  TOSSL_FUNC_mac_init_fn_func_cb = function(arg1: Pointer; arg2: PIdAnsiChar; arg3: TIdC_SIZET; arg4: POSSL_PARAM_ARRAY): TIdC_INT; cdecl;
  TOSSL_FUNC_mac_init_skey_fn_func_cb = function(arg1: Pointer; arg2: Pointer; arg3: POSSL_PARAM_ARRAY): TIdC_INT; cdecl;
  TOSSL_FUNC_skeymgmt_import_fn_func_cb = function(arg1: Pointer; arg2: TIdC_INT; arg3: POSSL_PARAM_ARRAY): Pointer; cdecl;
  TOSSL_FUNC_skeymgmt_export_fn_func_cb = function(arg1: Pointer; arg2: TIdC_INT; arg3: TOSSL_FUNC_provider_get_capabilities_fn_func_cb; arg4: Pointer): TIdC_INT; cdecl;
  TOSSL_FUNC_skeymgmt_generate_fn_func_cb = function(arg1: Pointer; arg2: POSSL_PARAM_ARRAY): Pointer; cdecl;
  TOSSL_FUNC_skeymgmt_get_key_id_fn_func_cb = function(arg1: Pointer): PIdAnsiChar; cdecl;
  TOSSL_FUNC_kdf_set_skey_fn_func_cb = function(arg1: Pointer; arg2: Pointer; arg3: PIdAnsiChar): TIdC_INT; cdecl;
  TOSSL_FUNC_kdf_derive_skey_fn_func_cb = function(arg1: Pointer; arg2: PIdAnsiChar; arg3: Pointer; arg4: TOSSL_FUNC_skeymgmt_import_fn_func_cb; arg5: TIdC_SIZET; arg6: POSSL_PARAM_ARRAY): Pointer; cdecl;
  TOSSL_FUNC_rand_newctx_fn_func_cb = function(arg1: Pointer; arg2: Pointer; arg3: POSSL_DISPATCH): Pointer; cdecl;
  TOSSL_FUNC_rand_instantiate_fn_func_cb = function(arg1: Pointer; arg2: TIdC_UINT; arg3: TIdC_INT; arg4: PIdAnsiChar; arg5: TIdC_SIZET; arg6: POSSL_PARAM_ARRAY): TIdC_INT; cdecl;
  TOSSL_FUNC_rand_generate_fn_func_cb = function(arg1: Pointer; arg2: PIdAnsiChar; arg3: TIdC_SIZET; arg4: TIdC_UINT; arg5: TIdC_INT; arg6: PIdAnsiChar; arg7: TIdC_SIZET): TIdC_INT; cdecl;
  TOSSL_FUNC_rand_reseed_fn_func_cb = function(arg1: Pointer; arg2: TIdC_INT; arg3: PIdAnsiChar; arg4: TIdC_SIZET; arg5: PIdAnsiChar; arg6: TIdC_SIZET): TIdC_INT; cdecl;
  TOSSL_FUNC_rand_nonce_fn_func_cb = function(arg1: Pointer; arg2: PIdAnsiChar; arg3: TIdC_UINT; arg4: TIdC_SIZET; arg5: TIdC_SIZET): TIdC_SIZET; cdecl;
  TOSSL_FUNC_rand_set_callbacks_fn_func_cb = function(arg1: Possl_param_st; arg2: Possl_param_st; arg3: Pointer): TIdC_INT; cdecl;
  TOSSL_FUNC_rand_set_callbacks_fn_func_cb = procedure(arg1: Pointer; arg2: TOSSL_FUNC_rand_set_callbacks_fn_func_cb; arg3: TOSSL_FUNC_provider_get_capabilities_fn_func_cb; arg4: TOSSL_FUNC_rand_set_callbacks_fn_func_cb; arg5: TOSSL_FUNC_provider_get_capabilities_fn_func_cb; arg6: Pointer); cdecl;
  TOSSL_FUNC_rand_get_seed_fn_func_cb = function(arg1: Pointer; arg2: PPIdAnsiChar; arg3: TIdC_INT; arg4: TIdC_SIZET; arg5: TIdC_SIZET; arg6: TIdC_INT; arg7: PIdAnsiChar; arg8: TIdC_SIZET): TIdC_SIZET; cdecl;
  TOSSL_FUNC_rand_clear_seed_fn_func_cb = procedure(arg1: Pointer; arg2: PIdAnsiChar; arg3: TIdC_SIZET); cdecl;
  TOSSL_FUNC_keymgmt_gen_set_template_fn_func_cb = function(arg1: Pointer; arg2: Pointer): TIdC_INT; cdecl;
  TOSSL_FUNC_keymgmt_gen_fn_func_cb = function(arg1: Pointer; arg2: TOSSL_FUNC_provider_get_capabilities_fn_func_cb; arg3: Pointer): Pointer; cdecl;
  TOSSL_FUNC_keymgmt_load_fn_func_cb = function(arg1: Pointer; arg2: TIdC_SIZET): Pointer; cdecl;
  TOSSL_FUNC_keymgmt_query_operation_name_fn_func_cb = function(arg1: TIdC_INT): PIdAnsiChar; cdecl;
  TOSSL_FUNC_keymgmt_has_fn_func_cb = function(arg1: Pointer; arg2: TIdC_INT): TIdC_INT; cdecl;
  TOSSL_FUNC_keymgmt_validate_fn_func_cb = function(arg1: Pointer; arg2: TIdC_INT; arg3: TIdC_INT): TIdC_INT; cdecl;
  TOSSL_FUNC_keymgmt_match_fn_func_cb = function(arg1: Pointer; arg2: Pointer; arg3: TIdC_INT): TIdC_INT; cdecl;
  TOSSL_FUNC_keymgmt_import_fn_func_cb = function(arg1: Pointer; arg2: TIdC_INT; arg3: POSSL_PARAM_ARRAY): TIdC_INT; cdecl;
  TOSSL_FUNC_keymgmt_import_types_fn_func_cb = function(arg1: TIdC_INT): POSSL_PARAM_ARRAY; cdecl;
  TOSSL_FUNC_keymgmt_dup_fn_func_cb = function(arg1: Pointer; arg2: TIdC_INT): Pointer; cdecl;
  TOSSL_FUNC_keymgmt_import_types_ex_fn_func_cb = function(arg1: Pointer; arg2: TIdC_INT): POSSL_PARAM_ARRAY; cdecl;
  TOSSL_FUNC_signature_newctx_fn_func_cb = function(arg1: Pointer; arg2: PIdAnsiChar): Pointer; cdecl;
  TOSSL_FUNC_signature_verify_fn_func_cb = function(arg1: Pointer; arg2: PIdAnsiChar; arg3: TIdC_SIZET; arg4: PIdAnsiChar; arg5: TIdC_SIZET): TIdC_INT; cdecl;
  TOSSL_FUNC_signature_digest_sign_init_fn_func_cb = function(arg1: Pointer; arg2: PIdAnsiChar; arg3: Pointer; arg4: POSSL_PARAM_ARRAY): TIdC_INT; cdecl;
  TOSSL_FUNC_signature_query_key_types_fn_func_cb = function: PPIdAnsiChar; cdecl;
  TOSSL_FUNC_kem_auth_encapsulate_init_fn_func_cb = function(arg1: Pointer; arg2: Pointer; arg3: Pointer; arg4: POSSL_PARAM_ARRAY): TIdC_INT; cdecl;
  TOSSL_FUNC_kem_encapsulate_fn_func_cb = function(arg1: Pointer; arg2: PIdAnsiChar; arg3: PIdC_SIZET; arg4: PIdAnsiChar; arg5: PIdC_SIZET): TIdC_INT; cdecl;
  TOSSL_FUNC_kem_decapsulate_fn_func_cb = function(arg1: Pointer; arg2: PIdAnsiChar; arg3: PIdC_SIZET; arg4: PIdAnsiChar; arg5: TIdC_SIZET): TIdC_INT; cdecl;
  TOSSL_FUNC_encoder_encode_fn_func_cb = function(arg1: PIdAnsiChar; arg2: TIdC_ULONG; arg3: PIdC_ULONG; arg4: Possl_param_st; arg5: Pointer): TIdC_INT; cdecl;
  TOSSL_FUNC_encoder_encode_fn_func_cb = function(arg1: Pointer; arg2: POSSL_CORE_BIO; arg3: Pointer; arg4: POSSL_PARAM_ARRAY; arg5: TIdC_INT; arg6: TOSSL_FUNC_encoder_encode_fn_func_cb; arg7: Pointer): TIdC_INT; cdecl;
  TOSSL_FUNC_decoder_decode_fn_func_cb = function(arg1: Pointer; arg2: POSSL_CORE_BIO; arg3: TIdC_INT; arg4: TOSSL_FUNC_provider_get_capabilities_fn_func_cb; arg5: Pointer; arg6: TOSSL_FUNC_encoder_encode_fn_func_cb; arg7: Pointer): TIdC_INT; cdecl;
  TOSSL_FUNC_decoder_export_object_fn_func_cb = function(arg1: Pointer; arg2: Pointer; arg3: TIdC_SIZET; arg4: TOSSL_FUNC_provider_get_capabilities_fn_func_cb; arg5: Pointer): TIdC_INT; cdecl;
  TOSSL_FUNC_store_attach_fn_func_cb = function(arg1: Pointer; arg2: POSSL_CORE_BIO): Pointer; cdecl;
  TOSSL_FUNC_store_load_fn_func_cb = function(arg1: Pointer; arg2: TOSSL_FUNC_provider_get_capabilities_fn_func_cb; arg3: Pointer; arg4: TOSSL_FUNC_encoder_encode_fn_func_cb; arg5: Pointer): TIdC_INT; cdecl;
  TOSSL_FUNC_store_delete_fn_func_cb = function(arg1: Pointer; arg2: PIdAnsiChar; arg3: POSSL_PARAM_ARRAY; arg4: TOSSL_FUNC_encoder_encode_fn_func_cb; arg5: Pointer): TIdC_INT; cdecl;
  TOSSL_FUNC_store_open_ex_fn_func_cb = function(arg1: Pointer; arg2: PIdAnsiChar; arg3: POSSL_PARAM_ARRAY; arg4: TOSSL_FUNC_encoder_encode_fn_func_cb; arg5: Pointer): Pointer; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  OSSL_FUNC_CORE_GETTABLE_PARAMS = 1;
  OSSL_FUNC_CORE_GET_PARAMS = 2;
  OSSL_FUNC_CORE_THREAD_START = 3;
  OSSL_FUNC_CORE_GET_LIBCTX = 4;
  OSSL_FUNC_CORE_NEW_ERROR = 5;
  OSSL_FUNC_CORE_SET_ERROR_DEBUG = 6;
  OSSL_FUNC_CORE_VSET_ERROR = 7;
  OSSL_FUNC_CORE_SET_ERROR_MARK = 8;
  OSSL_FUNC_CORE_CLEAR_LAST_ERROR_MARK = 9;
  OSSL_FUNC_CORE_POP_ERROR_TO_MARK = 10;
  OSSL_FUNC_CORE_OBJ_ADD_SIGID = 11;
  OSSL_FUNC_CORE_OBJ_CREATE = 12;
  OSSL_FUNC_CRYPTO_MALLOC = 20;
  OSSL_FUNC_CRYPTO_ZALLOC = 21;
  OSSL_FUNC_CRYPTO_FREE = 22;
  OSSL_FUNC_CRYPTO_CLEAR_FREE = 23;
  OSSL_FUNC_CRYPTO_REALLOC = 24;
  OSSL_FUNC_CRYPTO_CLEAR_REALLOC = 25;
  OSSL_FUNC_CRYPTO_SECURE_MALLOC = 26;
  OSSL_FUNC_CRYPTO_SECURE_ZALLOC = 27;
  OSSL_FUNC_CRYPTO_SECURE_FREE = 28;
  OSSL_FUNC_CRYPTO_SECURE_CLEAR_FREE = 29;
  OSSL_FUNC_CRYPTO_SECURE_ALLOCATED = 30;
  OSSL_FUNC_OPENSSL_CLEANSE = 31;
  OSSL_FUNC_BIO_NEW_FILE = 40;
  OSSL_FUNC_BIO_NEW_MEMBUF = 41;
  OSSL_FUNC_BIO_READ_EX = 42;
  OSSL_FUNC_BIO_WRITE_EX = 43;
  OSSL_FUNC_BIO_UP_REF = 44;
  OSSL_FUNC_BIO_FREE = 45;
  OSSL_FUNC_BIO_VPRINTF = 46;
  OSSL_FUNC_BIO_VSNPRINTF = 47;
  OSSL_FUNC_BIO_PUTS = 48;
  OSSL_FUNC_BIO_GETS = 49;
  OSSL_FUNC_BIO_CTRL = 50;
  OSSL_FUNC_CLEANUP_USER_ENTROPY = 96;
  OSSL_FUNC_CLEANUP_USER_NONCE = 97;
  OSSL_FUNC_GET_USER_ENTROPY = 98;
  OSSL_FUNC_GET_USER_NONCE = 99;
  OSSL_FUNC_INDICATOR_CB = 95;
  OSSL_FUNC_SELF_TEST_CB = 100;
  OSSL_FUNC_GET_ENTROPY = 101;
  OSSL_FUNC_CLEANUP_ENTROPY = 102;
  OSSL_FUNC_GET_NONCE = 103;
  OSSL_FUNC_CLEANUP_NONCE = 104;
  OSSL_FUNC_PROVIDER_REGISTER_CHILD_CB = 105;
  OSSL_FUNC_PROVIDER_DEREGISTER_CHILD_CB = 106;
  OSSL_FUNC_PROVIDER_NAME = 107;
  OSSL_FUNC_PROVIDER_GET0_PROVIDER_CTX = 108;
  OSSL_FUNC_PROVIDER_GET0_DISPATCH = 109;
  OSSL_FUNC_PROVIDER_UP_REF = 110;
  OSSL_FUNC_PROVIDER_FREE = 111;
  OSSL_FUNC_CORE_COUNT_TO_MARK = 120;
  OSSL_FUNC_PROVIDER_TEARDOWN = 1024;
  OSSL_FUNC_PROVIDER_GETTABLE_PARAMS = 1025;
  OSSL_FUNC_PROVIDER_GET_PARAMS = 1026;
  OSSL_FUNC_PROVIDER_QUERY_OPERATION = 1027;
  OSSL_FUNC_PROVIDER_UNQUERY_OPERATION = 1028;
  OSSL_FUNC_PROVIDER_GET_REASON_STRINGS = 1029;
  OSSL_FUNC_PROVIDER_GET_CAPABILITIES = 1030;
  OSSL_FUNC_PROVIDER_SELF_TEST = 1031;
  OSSL_FUNC_PROVIDER_RANDOM_BYTES = 1032;
  OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND = 2001;
  OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD = 2002;
  OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD = 2003;
  OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET = 2004;
  OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS = 2005;
  OSSL_FUNC_SSL_QUIC_TLS_ALERT = 2006;
  OSSL_OP_DIGEST = 1;
  OSSL_OP_CIPHER = 2;
  OSSL_OP_MAC = 3;
  OSSL_OP_KDF = 4;
  OSSL_OP_RAND = 5;
  OSSL_OP_KEYMGMT = 10;
  OSSL_OP_KEYEXCH = 11;
  OSSL_OP_SIGNATURE = 12;
  OSSL_OP_ASYM_CIPHER = 13;
  OSSL_OP_KEM = 14;
  OSSL_OP_SKEYMGMT = 15;
  OSSL_OP_ENCODER = 20;
  OSSL_OP_DECODER = 21;
  OSSL_OP_STORE = 22;
  OSSL_OP__HIGHEST = 22;
  OSSL_FUNC_DIGEST_NEWCTX = 1;
  OSSL_FUNC_DIGEST_INIT = 2;
  OSSL_FUNC_DIGEST_UPDATE = 3;
  OSSL_FUNC_DIGEST_FINAL = 4;
  OSSL_FUNC_DIGEST_DIGEST = 5;
  OSSL_FUNC_DIGEST_FREECTX = 6;
  OSSL_FUNC_DIGEST_DUPCTX = 7;
  OSSL_FUNC_DIGEST_GET_PARAMS = 8;
  OSSL_FUNC_DIGEST_SET_CTX_PARAMS = 9;
  OSSL_FUNC_DIGEST_GET_CTX_PARAMS = 10;
  OSSL_FUNC_DIGEST_GETTABLE_PARAMS = 11;
  OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS = 12;
  OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS = 13;
  OSSL_FUNC_DIGEST_SQUEEZE = 14;
  OSSL_FUNC_DIGEST_COPYCTX = 15;
  OSSL_FUNC_CIPHER_NEWCTX = 1;
  OSSL_FUNC_CIPHER_ENCRYPT_INIT = 2;
  OSSL_FUNC_CIPHER_DECRYPT_INIT = 3;
  OSSL_FUNC_CIPHER_UPDATE = 4;
  OSSL_FUNC_CIPHER_FINAL = 5;
  OSSL_FUNC_CIPHER_CIPHER = 6;
  OSSL_FUNC_CIPHER_FREECTX = 7;
  OSSL_FUNC_CIPHER_DUPCTX = 8;
  OSSL_FUNC_CIPHER_GET_PARAMS = 9;
  OSSL_FUNC_CIPHER_GET_CTX_PARAMS = 10;
  OSSL_FUNC_CIPHER_SET_CTX_PARAMS = 11;
  OSSL_FUNC_CIPHER_GETTABLE_PARAMS = 12;
  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS = 13;
  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS = 14;
  OSSL_FUNC_CIPHER_PIPELINE_ENCRYPT_INIT = 15;
  OSSL_FUNC_CIPHER_PIPELINE_DECRYPT_INIT = 16;
  OSSL_FUNC_CIPHER_PIPELINE_UPDATE = 17;
  OSSL_FUNC_CIPHER_PIPELINE_FINAL = 18;
  OSSL_FUNC_CIPHER_ENCRYPT_SKEY_INIT = 19;
  OSSL_FUNC_CIPHER_DECRYPT_SKEY_INIT = 20;
  OSSL_FUNC_MAC_NEWCTX = 1;
  OSSL_FUNC_MAC_DUPCTX = 2;
  OSSL_FUNC_MAC_FREECTX = 3;
  OSSL_FUNC_MAC_INIT = 4;
  OSSL_FUNC_MAC_UPDATE = 5;
  OSSL_FUNC_MAC_FINAL = 6;
  OSSL_FUNC_MAC_GET_PARAMS = 7;
  OSSL_FUNC_MAC_GET_CTX_PARAMS = 8;
  OSSL_FUNC_MAC_SET_CTX_PARAMS = 9;
  OSSL_FUNC_MAC_GETTABLE_PARAMS = 10;
  OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS = 11;
  OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS = 12;
  OSSL_FUNC_MAC_INIT_SKEY = 13;
  OSSL_SKEYMGMT_SELECT_PARAMETERS = $01;
  OSSL_SKEYMGMT_SELECT_SECRET_KEY = $02;
  OSSL_SKEYMGMT_SELECT_ALL = (OSSL_SKEYMGMT_SELECT_PARAMETERS or OSSL_SKEYMGMT_SELECT_SECRET_KEY);
  OSSL_FUNC_SKEYMGMT_FREE = 1;
  OSSL_FUNC_SKEYMGMT_IMPORT = 2;
  OSSL_FUNC_SKEYMGMT_EXPORT = 3;
  OSSL_FUNC_SKEYMGMT_GENERATE = 4;
  OSSL_FUNC_SKEYMGMT_GET_KEY_ID = 5;
  OSSL_FUNC_SKEYMGMT_IMP_SETTABLE_PARAMS = 6;
  OSSL_FUNC_SKEYMGMT_GEN_SETTABLE_PARAMS = 7;
  OSSL_FUNC_KDF_NEWCTX = 1;
  OSSL_FUNC_KDF_DUPCTX = 2;
  OSSL_FUNC_KDF_FREECTX = 3;
  OSSL_FUNC_KDF_RESET = 4;
  OSSL_FUNC_KDF_DERIVE = 5;
  OSSL_FUNC_KDF_GETTABLE_PARAMS = 6;
  OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS = 7;
  OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS = 8;
  OSSL_FUNC_KDF_GET_PARAMS = 9;
  OSSL_FUNC_KDF_GET_CTX_PARAMS = 10;
  OSSL_FUNC_KDF_SET_CTX_PARAMS = 11;
  OSSL_FUNC_KDF_SET_SKEY = 12;
  OSSL_FUNC_KDF_DERIVE_SKEY = 13;
  OSSL_FUNC_RAND_NEWCTX = 1;
  OSSL_FUNC_RAND_FREECTX = 2;
  OSSL_FUNC_RAND_INSTANTIATE = 3;
  OSSL_FUNC_RAND_UNINSTANTIATE = 4;
  OSSL_FUNC_RAND_GENERATE = 5;
  OSSL_FUNC_RAND_RESEED = 6;
  OSSL_FUNC_RAND_NONCE = 7;
  OSSL_FUNC_RAND_ENABLE_LOCKING = 8;
  OSSL_FUNC_RAND_LOCK = 9;
  OSSL_FUNC_RAND_UNLOCK = 10;
  OSSL_FUNC_RAND_GETTABLE_PARAMS = 11;
  OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS = 12;
  OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS = 13;
  OSSL_FUNC_RAND_GET_PARAMS = 14;
  OSSL_FUNC_RAND_GET_CTX_PARAMS = 15;
  OSSL_FUNC_RAND_SET_CTX_PARAMS = 16;
  OSSL_FUNC_RAND_VERIFY_ZEROIZATION = 17;
  OSSL_FUNC_RAND_GET_SEED = 18;
  OSSL_FUNC_RAND_CLEAR_SEED = 19;
  OSSL_KEYMGMT_SELECT_PRIVATE_KEY = $01;
  OSSL_KEYMGMT_SELECT_PUBLIC_KEY = $02;
  OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS = $04;
  OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS = $80;
  OSSL_KEYMGMT_SELECT_ALL_PARAMETERS = (OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS or OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS);
  OSSL_KEYMGMT_SELECT_KEYPAIR = (OSSL_KEYMGMT_SELECT_PRIVATE_KEY or OSSL_KEYMGMT_SELECT_PUBLIC_KEY);
  OSSL_KEYMGMT_SELECT_ALL = (OSSL_KEYMGMT_SELECT_KEYPAIR or OSSL_KEYMGMT_SELECT_ALL_PARAMETERS);
  OSSL_KEYMGMT_VALIDATE_FULL_CHECK = 0;
  OSSL_KEYMGMT_VALIDATE_QUICK_CHECK = 1;
  OSSL_FUNC_KEYMGMT_NEW = 1;
  OSSL_FUNC_KEYMGMT_GEN_INIT = 2;
  OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE = 3;
  OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS = 4;
  OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS = 5;
  OSSL_FUNC_KEYMGMT_GEN = 6;
  OSSL_FUNC_KEYMGMT_GEN_CLEANUP = 7;
  OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS = 15;
  OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS = 16;
  OSSL_FUNC_KEYMGMT_LOAD = 8;
  OSSL_FUNC_KEYMGMT_FREE = 10;
  OSSL_FUNC_KEYMGMT_GET_PARAMS = 11;
  OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS = 12;
  OSSL_FUNC_KEYMGMT_SET_PARAMS = 13;
  OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS = 14;
  OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME = 20;
  OSSL_FUNC_KEYMGMT_HAS = 21;
  OSSL_FUNC_KEYMGMT_VALIDATE = 22;
  OSSL_FUNC_KEYMGMT_MATCH = 23;
  OSSL_FUNC_KEYMGMT_IMPORT = 40;
  OSSL_FUNC_KEYMGMT_IMPORT_TYPES = 41;
  OSSL_FUNC_KEYMGMT_EXPORT = 42;
  OSSL_FUNC_KEYMGMT_EXPORT_TYPES = 43;
  OSSL_FUNC_KEYMGMT_DUP = 44;
  OSSL_FUNC_KEYMGMT_IMPORT_TYPES_EX = 45;
  OSSL_FUNC_KEYMGMT_EXPORT_TYPES_EX = 46;
  OSSL_FUNC_KEYEXCH_NEWCTX = 1;
  OSSL_FUNC_KEYEXCH_INIT = 2;
  OSSL_FUNC_KEYEXCH_DERIVE = 3;
  OSSL_FUNC_KEYEXCH_SET_PEER = 4;
  OSSL_FUNC_KEYEXCH_FREECTX = 5;
  OSSL_FUNC_KEYEXCH_DUPCTX = 6;
  OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS = 7;
  OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS = 8;
  OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS = 9;
  OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS = 10;
  OSSL_FUNC_KEYEXCH_DERIVE_SKEY = 11;
  OSSL_FUNC_SIGNATURE_NEWCTX = 1;
  OSSL_FUNC_SIGNATURE_SIGN_INIT = 2;
  OSSL_FUNC_SIGNATURE_SIGN = 3;
  OSSL_FUNC_SIGNATURE_VERIFY_INIT = 4;
  OSSL_FUNC_SIGNATURE_VERIFY = 5;
  OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT = 6;
  OSSL_FUNC_SIGNATURE_VERIFY_RECOVER = 7;
  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT = 8;
  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE = 9;
  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL = 10;
  OSSL_FUNC_SIGNATURE_DIGEST_SIGN = 11;
  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT = 12;
  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE = 13;
  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL = 14;
  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY = 15;
  OSSL_FUNC_SIGNATURE_FREECTX = 16;
  OSSL_FUNC_SIGNATURE_DUPCTX = 17;
  OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS = 18;
  OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS = 19;
  OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS = 20;
  OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS = 21;
  OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS = 22;
  OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS = 23;
  OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS = 24;
  OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS = 25;
  OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES = 26;
  OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT = 27;
  OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE = 28;
  OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL = 29;
  OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT = 30;
  OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE = 31;
  OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL = 32;
  OSSL_FUNC_ASYM_CIPHER_NEWCTX = 1;
  OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT = 2;
  OSSL_FUNC_ASYM_CIPHER_ENCRYPT = 3;
  OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT = 4;
  OSSL_FUNC_ASYM_CIPHER_DECRYPT = 5;
  OSSL_FUNC_ASYM_CIPHER_FREECTX = 6;
  OSSL_FUNC_ASYM_CIPHER_DUPCTX = 7;
  OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS = 8;
  OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS = 9;
  OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS = 10;
  OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS = 11;
  OSSL_FUNC_KEM_NEWCTX = 1;
  OSSL_FUNC_KEM_ENCAPSULATE_INIT = 2;
  OSSL_FUNC_KEM_ENCAPSULATE = 3;
  OSSL_FUNC_KEM_DECAPSULATE_INIT = 4;
  OSSL_FUNC_KEM_DECAPSULATE = 5;
  OSSL_FUNC_KEM_FREECTX = 6;
  OSSL_FUNC_KEM_DUPCTX = 7;
  OSSL_FUNC_KEM_GET_CTX_PARAMS = 8;
  OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS = 9;
  OSSL_FUNC_KEM_SET_CTX_PARAMS = 10;
  OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS = 11;
  OSSL_FUNC_KEM_AUTH_ENCAPSULATE_INIT = 12;
  OSSL_FUNC_KEM_AUTH_DECAPSULATE_INIT = 13;
  OSSL_FUNC_ENCODER_NEWCTX = 1;
  OSSL_FUNC_ENCODER_FREECTX = 2;
  OSSL_FUNC_ENCODER_GET_PARAMS = 3;
  OSSL_FUNC_ENCODER_GETTABLE_PARAMS = 4;
  OSSL_FUNC_ENCODER_SET_CTX_PARAMS = 5;
  OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS = 6;
  OSSL_FUNC_ENCODER_DOES_SELECTION = 10;
  OSSL_FUNC_ENCODER_ENCODE = 11;
  OSSL_FUNC_ENCODER_IMPORT_OBJECT = 20;
  OSSL_FUNC_ENCODER_FREE_OBJECT = 21;
  OSSL_FUNC_DECODER_NEWCTX = 1;
  OSSL_FUNC_DECODER_FREECTX = 2;
  OSSL_FUNC_DECODER_GET_PARAMS = 3;
  OSSL_FUNC_DECODER_GETTABLE_PARAMS = 4;
  OSSL_FUNC_DECODER_SET_CTX_PARAMS = 5;
  OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS = 6;
  OSSL_FUNC_DECODER_DOES_SELECTION = 10;
  OSSL_FUNC_DECODER_DECODE = 11;
  OSSL_FUNC_DECODER_EXPORT_OBJECT = 20;
  OSSL_FUNC_STORE_OPEN = 1;
  OSSL_FUNC_STORE_ATTACH = 2;
  OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS = 3;
  OSSL_FUNC_STORE_SET_CTX_PARAMS = 4;
  OSSL_FUNC_STORE_LOAD = 5;
  OSSL_FUNC_STORE_EOF = 6;
  OSSL_FUNC_STORE_CLOSE = 7;
  OSSL_FUNC_STORE_EXPORT_OBJECT = 8;
  OSSL_FUNC_STORE_DELETE = 9;
  OSSL_FUNC_STORE_OPEN_EX = 10;

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

function OSSL_CORE_MAKE_FUNC(_type: Pointer; name: Pointer; args: Pointer): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}


implementation

uses
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
  classes,
  TaurusTLSLoader,
  {$ENDIF}
  TaurusTLS_ResourceStrings,
  TaurusTLSExceptionHandlers;

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function OSSL_CORE_MAKE_FUNC(_type: Pointer; name: Pointer; args: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    OSSL_CORE_MAKE_FUNC(type, name, args)          \
    typedef type(OSSL_FUNC_##name##_fn) args;          \
    static ossl_unused ossl_inline                     \
        OSSL_FUNC_##name##_fn *                        \
        OSSL_FUNC_##name(const OSSL_DISPATCH *opf)     \
    {                                                  \
        return (OSSL_FUNC_##name##_fn *)opf->function; \
    }
  }
end;

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

end.