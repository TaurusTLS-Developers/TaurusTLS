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

unit TaurusTLSHeaders_types;

interface

uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_ossl_types;



// =============================================================================
// TYPE DECLARATIONS
// =============================================================================
type
  Possl_provider_st = ^Tossl_provider_st;
  Tossl_provider_st =   record end;
  {$EXTERNALSYM Possl_provider_st}

  Pasn1_type_st = ^Tasn1_type_st;
  Tasn1_type_st =   record end;
  {$EXTERNALSYM Pasn1_type_st}

  Pasn1_object_st = ^Tasn1_object_st;
  Tasn1_object_st =   record end;
  {$EXTERNALSYM Pasn1_object_st}

  Pasn1_string_table_st = ^Tasn1_string_table_st;
  Tasn1_string_table_st =   record end;
  {$EXTERNALSYM Pasn1_string_table_st}

  PASN1_ITEM_st = ^TASN1_ITEM_st;
  TASN1_ITEM_st =   record end;
  {$EXTERNALSYM PASN1_ITEM_st}

  Pasn1_pctx_st = ^Tasn1_pctx_st;
  Tasn1_pctx_st =   record end;
  {$EXTERNALSYM Pasn1_pctx_st}

  Pasn1_sctx_st = ^Tasn1_sctx_st;
  Tasn1_sctx_st =   record end;
  {$EXTERNALSYM Pasn1_sctx_st}

  Pbn_blinding_st = ^Tbn_blinding_st;
  Tbn_blinding_st =   record end;
  {$EXTERNALSYM Pbn_blinding_st}

  Pbn_recp_ctx_st = ^Tbn_recp_ctx_st;
  Tbn_recp_ctx_st =   record end;
  {$EXTERNALSYM Pbn_recp_ctx_st}

  Pbuf_mem_st = ^Tbuf_mem_st;
  Tbuf_mem_st =   record end;
  {$EXTERNALSYM Pbuf_mem_st}

  Pstack_st_BIGNUM = ^Tstack_st_BIGNUM;
  Tstack_st_BIGNUM =   record end;
  {$EXTERNALSYM Pstack_st_BIGNUM}

  Pstack_st_BIGNUM_const = ^Tstack_st_BIGNUM_const;
  Tstack_st_BIGNUM_const =   record end;
  {$EXTERNALSYM Pstack_st_BIGNUM_const}

  Perr_state_st = ^Terr_state_st;
  Terr_state_st =   record end;
  {$EXTERNALSYM Perr_state_st}

  Pevp_cipher_st = ^Tevp_cipher_st;
  Tevp_cipher_st =   record end;
  {$EXTERNALSYM Pevp_cipher_st}

  Pevp_cipher_ctx_st = ^Tevp_cipher_ctx_st;
  Tevp_cipher_ctx_st =   record end;
  {$EXTERNALSYM Pevp_cipher_ctx_st}

  Pevp_md_st = ^Tevp_md_st;
  Tevp_md_st =   record end;
  {$EXTERNALSYM Pevp_md_st}

  Pevp_md_ctx_st = ^Tevp_md_ctx_st;
  Tevp_md_ctx_st =   record end;
  {$EXTERNALSYM Pevp_md_ctx_st}

  Pevp_mac_st = ^Tevp_mac_st;
  Tevp_mac_st =   record end;
  {$EXTERNALSYM Pevp_mac_st}

  Pevp_mac_ctx_st = ^Tevp_mac_ctx_st;
  Tevp_mac_ctx_st =   record end;
  {$EXTERNALSYM Pevp_mac_ctx_st}

  Pevp_skey_st = ^Tevp_skey_st;
  Tevp_skey_st =   record end;
  {$EXTERNALSYM Pevp_skey_st}

  Pevp_pkey_asn1_method_st = ^Tevp_pkey_asn1_method_st;
  Tevp_pkey_asn1_method_st =   record end;
  {$EXTERNALSYM Pevp_pkey_asn1_method_st}

  Pevp_pkey_method_st = ^Tevp_pkey_method_st;
  Tevp_pkey_method_st =   record end;
  {$EXTERNALSYM Pevp_pkey_method_st}

  Pevp_pkey_ctx_st = ^Tevp_pkey_ctx_st;
  Tevp_pkey_ctx_st =   record end;
  {$EXTERNALSYM Pevp_pkey_ctx_st}

  Pevp_keymgmt_st = ^Tevp_keymgmt_st;
  Tevp_keymgmt_st =   record end;
  {$EXTERNALSYM Pevp_keymgmt_st}

  Pevp_kdf_st = ^Tevp_kdf_st;
  Tevp_kdf_st =   record end;
  {$EXTERNALSYM Pevp_kdf_st}

  Pevp_kdf_ctx_st = ^Tevp_kdf_ctx_st;
  Tevp_kdf_ctx_st =   record end;
  {$EXTERNALSYM Pevp_kdf_ctx_st}

  Pevp_rand_st = ^Tevp_rand_st;
  Tevp_rand_st =   record end;
  {$EXTERNALSYM Pevp_rand_st}

  Pevp_rand_ctx_st = ^Tevp_rand_ctx_st;
  Tevp_rand_ctx_st =   record end;
  {$EXTERNALSYM Pevp_rand_ctx_st}

  Pevp_keyexch_st = ^Tevp_keyexch_st;
  Tevp_keyexch_st =   record end;
  {$EXTERNALSYM Pevp_keyexch_st}

  Pevp_signature_st = ^Tevp_signature_st;
  Tevp_signature_st =   record end;
  {$EXTERNALSYM Pevp_signature_st}

  Pevp_skeymgmt_st = ^Tevp_skeymgmt_st;
  Tevp_skeymgmt_st =   record end;
  {$EXTERNALSYM Pevp_skeymgmt_st}

  Pevp_asym_cipher_st = ^Tevp_asym_cipher_st;
  Tevp_asym_cipher_st =   record end;
  {$EXTERNALSYM Pevp_asym_cipher_st}

  Pevp_kem_st = ^Tevp_kem_st;
  Tevp_kem_st =   record end;
  {$EXTERNALSYM Pevp_kem_st}

  Pevp_Encode_Ctx_st = ^Tevp_Encode_Ctx_st;
  Tevp_Encode_Ctx_st =   record end;
  {$EXTERNALSYM Pevp_Encode_Ctx_st}

  Phmac_ctx_st = ^Thmac_ctx_st;
  Thmac_ctx_st =   record end;
  {$EXTERNALSYM Phmac_ctx_st}

  Pdh_method = ^Tdh_method;
  Tdh_method =   record end;
  {$EXTERNALSYM Pdh_method}

  Pdsa_method = ^Tdsa_method;
  Tdsa_method =   record end;
  {$EXTERNALSYM Pdsa_method}

  Prsa_meth_st = ^Trsa_meth_st;
  Trsa_meth_st =   record end;
  {$EXTERNALSYM Prsa_meth_st}

  Prsa_pss_params_st = ^Trsa_pss_params_st;
  Trsa_pss_params_st =   record end;
  {$EXTERNALSYM Prsa_pss_params_st}

  Prsa_oaep_params_st = ^Trsa_oaep_params_st;
  Trsa_oaep_params_st =   record end;
  {$EXTERNALSYM Prsa_oaep_params_st}

  Pec_key_method_st = ^Tec_key_method_st;
  Tec_key_method_st =   record end;
  {$EXTERNALSYM Pec_key_method_st}

  Prand_meth_st = ^Trand_meth_st;
  Trand_meth_st =   record end;
  {$EXTERNALSYM Prand_meth_st}

  Prand_drbg_st = ^Trand_drbg_st;
  Trand_drbg_st =   record end;
  {$EXTERNALSYM Prand_drbg_st}

  Pssl_dane_st = ^Tssl_dane_st;
  Tssl_dane_st =   record end;
  {$EXTERNALSYM Pssl_dane_st}

  Px509_st = ^Tx509_st;
  Tx509_st =   record end;
  {$EXTERNALSYM Px509_st}

  PX509_algor_st = ^TX509_algor_st;
  TX509_algor_st =   record end;
  {$EXTERNALSYM PX509_algor_st}

  PX509_crl_st = ^TX509_crl_st;
  TX509_crl_st =   record end;
  {$EXTERNALSYM PX509_crl_st}

  Px509_crl_method_st = ^Tx509_crl_method_st;
  Tx509_crl_method_st =   record end;
  {$EXTERNALSYM Px509_crl_method_st}

  Px509_revoked_st = ^Tx509_revoked_st;
  Tx509_revoked_st =   record end;
  {$EXTERNALSYM Px509_revoked_st}

  PX509_name_st = ^TX509_name_st;
  TX509_name_st =   record end;
  {$EXTERNALSYM PX509_name_st}

  PX509_pubkey_st = ^TX509_pubkey_st;
  TX509_pubkey_st =   record end;
  {$EXTERNALSYM PX509_pubkey_st}

  Px509_store_st = ^Tx509_store_st;
  Tx509_store_st =   record end;
  {$EXTERNALSYM Px509_store_st}

  Px509_store_ctx_st = ^Tx509_store_ctx_st;
  Tx509_store_ctx_st =   record end;
  {$EXTERNALSYM Px509_store_ctx_st}

  Px509_object_st = ^Tx509_object_st;
  Tx509_object_st =   record end;
  {$EXTERNALSYM Px509_object_st}

  Px509_lookup_st = ^Tx509_lookup_st;
  Tx509_lookup_st =   record end;
  {$EXTERNALSYM Px509_lookup_st}

  Px509_lookup_method_st = ^Tx509_lookup_method_st;
  Tx509_lookup_method_st =   record end;
  {$EXTERNALSYM Px509_lookup_method_st}

  PX509_VERIFY_PARAM_st = ^TX509_VERIFY_PARAM_st;
  TX509_VERIFY_PARAM_st =   record end;
  {$EXTERNALSYM PX509_VERIFY_PARAM_st}

  Px509_sig_info_st = ^Tx509_sig_info_st;
  Tx509_sig_info_st =   record end;
  {$EXTERNALSYM Px509_sig_info_st}

  Ppkcs8_priv_key_info_st = ^Tpkcs8_priv_key_info_st;
  Tpkcs8_priv_key_info_st =   record end;
  {$EXTERNALSYM Ppkcs8_priv_key_info_st}

  Pv3_ext_ctx = ^Tv3_ext_ctx;
  Tv3_ext_ctx =   record end;
  {$EXTERNALSYM Pv3_ext_ctx}

  Pconf_st = ^Tconf_st;
  Tconf_st =   record end;
  {$EXTERNALSYM Pconf_st}

  Possl_init_settings_st = ^Tossl_init_settings_st;
  Tossl_init_settings_st =   record end;
  {$EXTERNALSYM Possl_init_settings_st}

  Pui_st = ^Tui_st;
  Tui_st =   record end;
  {$EXTERNALSYM Pui_st}

  Pui_method_st = ^Tui_method_st;
  Tui_method_st =   record end;
  {$EXTERNALSYM Pui_method_st}

  Pengine_st = ^Tengine_st;
  Tengine_st =   record end;
  {$EXTERNALSYM Pengine_st}

  Pcomp_ctx_st = ^Tcomp_ctx_st;
  Tcomp_ctx_st =   record end;
  {$EXTERNALSYM Pcomp_ctx_st}

  Pcomp_method_st = ^Tcomp_method_st;
  Tcomp_method_st =   record end;
  {$EXTERNALSYM Pcomp_method_st}

  PX509_POLICY_NODE_st = ^TX509_POLICY_NODE_st;
  TX509_POLICY_NODE_st =   record end;
  {$EXTERNALSYM PX509_POLICY_NODE_st}

  PX509_POLICY_LEVEL_st = ^TX509_POLICY_LEVEL_st;
  TX509_POLICY_LEVEL_st =   record end;
  {$EXTERNALSYM PX509_POLICY_LEVEL_st}

  PX509_POLICY_TREE_st = ^TX509_POLICY_TREE_st;
  TX509_POLICY_TREE_st =   record end;
  {$EXTERNALSYM PX509_POLICY_TREE_st}

  PX509_POLICY_CACHE_st = ^TX509_POLICY_CACHE_st;
  TX509_POLICY_CACHE_st =   record end;
  {$EXTERNALSYM PX509_POLICY_CACHE_st}

  PAUTHORITY_KEYID_st = ^TAUTHORITY_KEYID_st;
  TAUTHORITY_KEYID_st =   record end;
  {$EXTERNALSYM PAUTHORITY_KEYID_st}

  PDIST_POINT_st = ^TDIST_POINT_st;
  TDIST_POINT_st =   record end;
  {$EXTERNALSYM PDIST_POINT_st}

  PISSUING_DIST_POINT_st = ^TISSUING_DIST_POINT_st;
  TISSUING_DIST_POINT_st =   record end;
  {$EXTERNALSYM PISSUING_DIST_POINT_st}

  PNAME_CONSTRAINTS_st = ^TNAME_CONSTRAINTS_st;
  TNAME_CONSTRAINTS_st =   record end;
  {$EXTERNALSYM PNAME_CONSTRAINTS_st}

  Pcrypto_ex_data_st = ^Tcrypto_ex_data_st;
  Tcrypto_ex_data_st =   record end;
  {$EXTERNALSYM Pcrypto_ex_data_st}

  Possl_http_req_ctx_st = ^Tossl_http_req_ctx_st;
  Tossl_http_req_ctx_st =   record end;
  {$EXTERNALSYM Possl_http_req_ctx_st}

  Pocsp_response_st = ^Tocsp_response_st;
  Tocsp_response_st =   record end;
  {$EXTERNALSYM Pocsp_response_st}

  Pocsp_responder_id_st = ^Tocsp_responder_id_st;
  Tocsp_responder_id_st =   record end;
  {$EXTERNALSYM Pocsp_responder_id_st}

  Psct_st = ^Tsct_st;
  Tsct_st =   record end;
  {$EXTERNALSYM Psct_st}

  Psct_ctx_st = ^Tsct_ctx_st;
  Tsct_ctx_st =   record end;
  {$EXTERNALSYM Psct_ctx_st}

  Pctlog_st = ^Tctlog_st;
  Tctlog_st =   record end;
  {$EXTERNALSYM Pctlog_st}

  Pctlog_store_st = ^Tctlog_store_st;
  Tctlog_store_st =   record end;
  {$EXTERNALSYM Pctlog_store_st}

  Pct_policy_eval_ctx_st = ^Tct_policy_eval_ctx_st;
  Tct_policy_eval_ctx_st =   record end;
  {$EXTERNALSYM Pct_policy_eval_ctx_st}

  Possl_store_search_st = ^Tossl_store_search_st;
  Tossl_store_search_st =   record end;
  {$EXTERNALSYM Possl_store_search_st}

  Possl_lib_ctx_st = ^Tossl_lib_ctx_st;
  Tossl_lib_ctx_st =   record end;
  {$EXTERNALSYM Possl_lib_ctx_st}

  Possl_item_st = ^Tossl_item_st;
  Tossl_item_st =   record end;
  {$EXTERNALSYM Possl_item_st}

  Possl_algorithm_st = ^Tossl_algorithm_st;
  Tossl_algorithm_st =   record end;
  {$EXTERNALSYM Possl_algorithm_st}

  Possl_param_bld_st = ^Tossl_param_bld_st;
  Tossl_param_bld_st =   record end;
  {$EXTERNALSYM Possl_param_bld_st}

  Possl_encoder_st = ^Tossl_encoder_st;
  Tossl_encoder_st =   record end;
  {$EXTERNALSYM Possl_encoder_st}

  Possl_encoder_ctx_st = ^Tossl_encoder_ctx_st;
  Tossl_encoder_ctx_st =   record end;
  {$EXTERNALSYM Possl_encoder_ctx_st}

  Possl_decoder_st = ^Tossl_decoder_st;
  Tossl_decoder_st =   record end;
  {$EXTERNALSYM Possl_decoder_st}

  Possl_decoder_ctx_st = ^Tossl_decoder_ctx_st;
  Tossl_decoder_ctx_st =   record end;
  {$EXTERNALSYM Possl_decoder_ctx_st}

  Possl_self_test_st = ^Tossl_self_test_st;
  Tossl_self_test_st =   record end;
  {$EXTERNALSYM Possl_self_test_st}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  Tpem_password_cb = function(buf: PIdAnsiChar; size: TIdC_INT; rwflag: TIdC_INT; userdata: Pointer): TIdC_INT; cdecl;

implementation

end.