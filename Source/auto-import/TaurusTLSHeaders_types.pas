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
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_core;

// =============================================================================
// TYPE DECLARATIONS
// =============================================================================
type
  Possl_provider_st = ^Tossl_provider_st;
  Tossl_provider_st = record end;
  {$EXTERNALSYM Possl_provider_st}

  POSSL_PROVIDER = ^TOSSL_PROVIDER;
  TOSSL_PROVIDER = Tossl_provider_st;
  {$EXTERNALSYM POSSL_PROVIDER}

  Pasn1_string_st = ^Tasn1_string_st;
  Tasn1_string_st = record end;
  {$EXTERNALSYM Pasn1_string_st}

  PASN1_INTEGER = ^TASN1_INTEGER;
  TASN1_INTEGER = Tasn1_string_st;
  {$EXTERNALSYM PASN1_INTEGER}

  PASN1_ENUMERATED = ^TASN1_ENUMERATED;
  TASN1_ENUMERATED = Tasn1_string_st;
  {$EXTERNALSYM PASN1_ENUMERATED}

  PASN1_BIT_STRING = ^TASN1_BIT_STRING;
  TASN1_BIT_STRING = Tasn1_string_st;
  {$EXTERNALSYM PASN1_BIT_STRING}

  PASN1_OCTET_STRING = ^TASN1_OCTET_STRING;
  TASN1_OCTET_STRING = Tasn1_string_st;
  {$EXTERNALSYM PASN1_OCTET_STRING}

  PASN1_PRINTABLESTRING = ^TASN1_PRINTABLESTRING;
  TASN1_PRINTABLESTRING = Tasn1_string_st;
  {$EXTERNALSYM PASN1_PRINTABLESTRING}

  PASN1_T61STRING = ^TASN1_T61STRING;
  TASN1_T61STRING = Tasn1_string_st;
  {$EXTERNALSYM PASN1_T61STRING}

  PASN1_IA5STRING = ^TASN1_IA5STRING;
  TASN1_IA5STRING = Tasn1_string_st;
  {$EXTERNALSYM PASN1_IA5STRING}

  PASN1_GENERALSTRING = ^TASN1_GENERALSTRING;
  TASN1_GENERALSTRING = Tasn1_string_st;
  {$EXTERNALSYM PASN1_GENERALSTRING}

  PASN1_UNIVERSALSTRING = ^TASN1_UNIVERSALSTRING;
  TASN1_UNIVERSALSTRING = Tasn1_string_st;
  {$EXTERNALSYM PASN1_UNIVERSALSTRING}

  PASN1_BMPSTRING = ^TASN1_BMPSTRING;
  TASN1_BMPSTRING = Tasn1_string_st;
  {$EXTERNALSYM PASN1_BMPSTRING}

  PASN1_UTCTIME = ^TASN1_UTCTIME;
  TASN1_UTCTIME = Tasn1_string_st;
  {$EXTERNALSYM PASN1_UTCTIME}

  PASN1_TIME = ^TASN1_TIME;
  TASN1_TIME = Tasn1_string_st;
  {$EXTERNALSYM PASN1_TIME}

  PASN1_GENERALIZEDTIME = ^TASN1_GENERALIZEDTIME;
  TASN1_GENERALIZEDTIME = Tasn1_string_st;
  {$EXTERNALSYM PASN1_GENERALIZEDTIME}

  PASN1_VISIBLESTRING = ^TASN1_VISIBLESTRING;
  TASN1_VISIBLESTRING = Tasn1_string_st;
  {$EXTERNALSYM PASN1_VISIBLESTRING}

  PASN1_UTF8STRING = ^TASN1_UTF8STRING;
  TASN1_UTF8STRING = Tasn1_string_st;
  {$EXTERNALSYM PASN1_UTF8STRING}

  PASN1_STRING = ^TASN1_STRING;
  TASN1_STRING = Tasn1_string_st;
  {$EXTERNALSYM PASN1_STRING}

  PASN1_BOOLEAN = ^TASN1_BOOLEAN;
  TASN1_BOOLEAN = TIdC_INT;
  {$EXTERNALSYM PASN1_BOOLEAN}

  PASN1_NULL = ^TASN1_NULL;
  TASN1_NULL = TIdC_INT;
  {$EXTERNALSYM PASN1_NULL}

  Pasn1_type_st = ^Tasn1_type_st;
  Tasn1_type_st = record end;
  {$EXTERNALSYM Pasn1_type_st}

  PASN1_TYPE = ^TASN1_TYPE;
  TASN1_TYPE = Tasn1_type_st;
  {$EXTERNALSYM PASN1_TYPE}

  Pasn1_object_st = ^Tasn1_object_st;
  Tasn1_object_st = record end;
  {$EXTERNALSYM Pasn1_object_st}

  PASN1_OBJECT = ^TASN1_OBJECT;
  TASN1_OBJECT = Tasn1_object_st;
  {$EXTERNALSYM PASN1_OBJECT}

  Pasn1_string_table_st = ^Tasn1_string_table_st;
  Tasn1_string_table_st = record end;
  {$EXTERNALSYM Pasn1_string_table_st}

  PASN1_STRING_TABLE = ^TASN1_STRING_TABLE;
  TASN1_STRING_TABLE = Tasn1_string_table_st;
  {$EXTERNALSYM PASN1_STRING_TABLE}

  PASN1_ITEM_st = ^TASN1_ITEM_st;
  TASN1_ITEM_st = record end;
  {$EXTERNALSYM PASN1_ITEM_st}

  PASN1_ITEM = ^TASN1_ITEM;
  TASN1_ITEM = TASN1_ITEM_st;
  {$EXTERNALSYM PASN1_ITEM}

  Pasn1_pctx_st = ^Tasn1_pctx_st;
  Tasn1_pctx_st = record end;
  {$EXTERNALSYM Pasn1_pctx_st}

  PASN1_PCTX = ^TASN1_PCTX;
  TASN1_PCTX = Tasn1_pctx_st;
  {$EXTERNALSYM PASN1_PCTX}

  Pasn1_sctx_st = ^Tasn1_sctx_st;
  Tasn1_sctx_st = record end;
  {$EXTERNALSYM Pasn1_sctx_st}

  PASN1_SCTX = ^TASN1_SCTX;
  TASN1_SCTX = Tasn1_sctx_st;
  {$EXTERNALSYM PASN1_SCTX}

  Pbio_st = ^Tbio_st;
  Tbio_st = record end;
  {$EXTERNALSYM Pbio_st}

  PBIO = ^TBIO;
  TBIO = Tbio_st;
  {$EXTERNALSYM PBIO}

  Pbignum_st = ^Tbignum_st;
  Tbignum_st = record end;
  {$EXTERNALSYM Pbignum_st}

  PBIGNUM = ^TBIGNUM;
  TBIGNUM = Tbignum_st;
  {$EXTERNALSYM PBIGNUM}

  Pbignum_ctx = ^Tbignum_ctx;
  Tbignum_ctx = record end;
  {$EXTERNALSYM Pbignum_ctx}

  PBN_CTX = ^TBN_CTX;
  TBN_CTX = Tbignum_ctx;
  {$EXTERNALSYM PBN_CTX}

  Pbn_blinding_st = ^Tbn_blinding_st;
  Tbn_blinding_st = record end;
  {$EXTERNALSYM Pbn_blinding_st}

  PBN_BLINDING = ^TBN_BLINDING;
  TBN_BLINDING = Tbn_blinding_st;
  {$EXTERNALSYM PBN_BLINDING}

  Pbn_mont_ctx_st = ^Tbn_mont_ctx_st;
  Tbn_mont_ctx_st = record end;
  {$EXTERNALSYM Pbn_mont_ctx_st}

  PBN_MONT_CTX = ^TBN_MONT_CTX;
  TBN_MONT_CTX = Tbn_mont_ctx_st;
  {$EXTERNALSYM PBN_MONT_CTX}

  Pbn_recp_ctx_st = ^Tbn_recp_ctx_st;
  Tbn_recp_ctx_st = record end;
  {$EXTERNALSYM Pbn_recp_ctx_st}

  PBN_RECP_CTX = ^TBN_RECP_CTX;
  TBN_RECP_CTX = Tbn_recp_ctx_st;
  {$EXTERNALSYM PBN_RECP_CTX}

  Pbn_gencb_st = ^Tbn_gencb_st;
  Tbn_gencb_st = record end;
  {$EXTERNALSYM Pbn_gencb_st}

  PBN_GENCB = ^TBN_GENCB;
  TBN_GENCB = Tbn_gencb_st;
  {$EXTERNALSYM PBN_GENCB}

  Pbuf_mem_st = ^Tbuf_mem_st;
  Tbuf_mem_st = record end;
  {$EXTERNALSYM Pbuf_mem_st}

  PBUF_MEM = ^TBUF_MEM;
  TBUF_MEM = Tbuf_mem_st;
  {$EXTERNALSYM PBUF_MEM}

  Pstack_st_BIGNUM = ^Tstack_st_BIGNUM;
  Tstack_st_BIGNUM = record end;
  {$EXTERNALSYM Pstack_st_BIGNUM}

  Pstack_st_BIGNUM_const = ^Tstack_st_BIGNUM_const;
  Tstack_st_BIGNUM_const = record end;
  {$EXTERNALSYM Pstack_st_BIGNUM_const}

  Perr_state_st = ^Terr_state_st;
  Terr_state_st = record end;
  {$EXTERNALSYM Perr_state_st}

  PERR_STATE = ^TERR_STATE;
  TERR_STATE = Terr_state_st;
  {$EXTERNALSYM PERR_STATE}

  Pevp_cipher_st = ^Tevp_cipher_st;
  Tevp_cipher_st = record end;
  {$EXTERNALSYM Pevp_cipher_st}

  PEVP_CIPHER = ^TEVP_CIPHER;
  TEVP_CIPHER = Tevp_cipher_st;
  {$EXTERNALSYM PEVP_CIPHER}

  Pevp_cipher_ctx_st = ^Tevp_cipher_ctx_st;
  Tevp_cipher_ctx_st = record end;
  {$EXTERNALSYM Pevp_cipher_ctx_st}

  PEVP_CIPHER_CTX = ^TEVP_CIPHER_CTX;
  TEVP_CIPHER_CTX = Tevp_cipher_ctx_st;
  {$EXTERNALSYM PEVP_CIPHER_CTX}

  Pevp_md_st = ^Tevp_md_st;
  Tevp_md_st = record end;
  {$EXTERNALSYM Pevp_md_st}

  PEVP_MD = ^TEVP_MD;
  TEVP_MD = Tevp_md_st;
  {$EXTERNALSYM PEVP_MD}

  Pevp_md_ctx_st = ^Tevp_md_ctx_st;
  Tevp_md_ctx_st = record end;
  {$EXTERNALSYM Pevp_md_ctx_st}

  PEVP_MD_CTX = ^TEVP_MD_CTX;
  TEVP_MD_CTX = Tevp_md_ctx_st;
  {$EXTERNALSYM PEVP_MD_CTX}

  Pevp_mac_st = ^Tevp_mac_st;
  Tevp_mac_st = record end;
  {$EXTERNALSYM Pevp_mac_st}

  PEVP_MAC = ^TEVP_MAC;
  TEVP_MAC = Tevp_mac_st;
  {$EXTERNALSYM PEVP_MAC}

  Pevp_mac_ctx_st = ^Tevp_mac_ctx_st;
  Tevp_mac_ctx_st = record end;
  {$EXTERNALSYM Pevp_mac_ctx_st}

  PEVP_MAC_CTX = ^TEVP_MAC_CTX;
  TEVP_MAC_CTX = Tevp_mac_ctx_st;
  {$EXTERNALSYM PEVP_MAC_CTX}

  Pevp_pkey_st = ^Tevp_pkey_st;
  Tevp_pkey_st = record end;
  {$EXTERNALSYM Pevp_pkey_st}

  PEVP_PKEY = ^TEVP_PKEY;
  TEVP_PKEY = Tevp_pkey_st;
  {$EXTERNALSYM PEVP_PKEY}

  Pevp_skey_st = ^Tevp_skey_st;
  Tevp_skey_st = record end;
  {$EXTERNALSYM Pevp_skey_st}

  PEVP_SKEY = ^TEVP_SKEY;
  TEVP_SKEY = Tevp_skey_st;
  {$EXTERNALSYM PEVP_SKEY}

  Pevp_pkey_asn1_method_st = ^Tevp_pkey_asn1_method_st;
  Tevp_pkey_asn1_method_st = record end;
  {$EXTERNALSYM Pevp_pkey_asn1_method_st}

  PEVP_PKEY_ASN1_METHOD = ^TEVP_PKEY_ASN1_METHOD;
  TEVP_PKEY_ASN1_METHOD = Tevp_pkey_asn1_method_st;
  {$EXTERNALSYM PEVP_PKEY_ASN1_METHOD}

  Pevp_pkey_method_st = ^Tevp_pkey_method_st;
  Tevp_pkey_method_st = record end;
  {$EXTERNALSYM Pevp_pkey_method_st}

  PEVP_PKEY_METHOD = ^TEVP_PKEY_METHOD;
  TEVP_PKEY_METHOD = Tevp_pkey_method_st;
  {$EXTERNALSYM PEVP_PKEY_METHOD}

  Pevp_pkey_ctx_st = ^Tevp_pkey_ctx_st;
  Tevp_pkey_ctx_st = record end;
  {$EXTERNALSYM Pevp_pkey_ctx_st}

  PEVP_PKEY_CTX = ^TEVP_PKEY_CTX;
  TEVP_PKEY_CTX = Tevp_pkey_ctx_st;
  {$EXTERNALSYM PEVP_PKEY_CTX}

  Pevp_keymgmt_st = ^Tevp_keymgmt_st;
  Tevp_keymgmt_st = record end;
  {$EXTERNALSYM Pevp_keymgmt_st}

  PEVP_KEYMGMT = ^TEVP_KEYMGMT;
  TEVP_KEYMGMT = Tevp_keymgmt_st;
  {$EXTERNALSYM PEVP_KEYMGMT}

  Pevp_kdf_st = ^Tevp_kdf_st;
  Tevp_kdf_st = record end;
  {$EXTERNALSYM Pevp_kdf_st}

  PEVP_KDF = ^TEVP_KDF;
  TEVP_KDF = Tevp_kdf_st;
  {$EXTERNALSYM PEVP_KDF}

  Pevp_kdf_ctx_st = ^Tevp_kdf_ctx_st;
  Tevp_kdf_ctx_st = record end;
  {$EXTERNALSYM Pevp_kdf_ctx_st}

  PEVP_KDF_CTX = ^TEVP_KDF_CTX;
  TEVP_KDF_CTX = Tevp_kdf_ctx_st;
  {$EXTERNALSYM PEVP_KDF_CTX}

  Pevp_rand_st = ^Tevp_rand_st;
  Tevp_rand_st = record end;
  {$EXTERNALSYM Pevp_rand_st}

  PEVP_RAND = ^TEVP_RAND;
  TEVP_RAND = Tevp_rand_st;
  {$EXTERNALSYM PEVP_RAND}

  Pevp_rand_ctx_st = ^Tevp_rand_ctx_st;
  Tevp_rand_ctx_st = record end;
  {$EXTERNALSYM Pevp_rand_ctx_st}

  PEVP_RAND_CTX = ^TEVP_RAND_CTX;
  TEVP_RAND_CTX = Tevp_rand_ctx_st;
  {$EXTERNALSYM PEVP_RAND_CTX}

  Pevp_keyexch_st = ^Tevp_keyexch_st;
  Tevp_keyexch_st = record end;
  {$EXTERNALSYM Pevp_keyexch_st}

  PEVP_KEYEXCH = ^TEVP_KEYEXCH;
  TEVP_KEYEXCH = Tevp_keyexch_st;
  {$EXTERNALSYM PEVP_KEYEXCH}

  Pevp_signature_st = ^Tevp_signature_st;
  Tevp_signature_st = record end;
  {$EXTERNALSYM Pevp_signature_st}

  PEVP_SIGNATURE = ^TEVP_SIGNATURE;
  TEVP_SIGNATURE = Tevp_signature_st;
  {$EXTERNALSYM PEVP_SIGNATURE}

  Pevp_skeymgmt_st = ^Tevp_skeymgmt_st;
  Tevp_skeymgmt_st = record end;
  {$EXTERNALSYM Pevp_skeymgmt_st}

  PEVP_SKEYMGMT = ^TEVP_SKEYMGMT;
  TEVP_SKEYMGMT = Tevp_skeymgmt_st;
  {$EXTERNALSYM PEVP_SKEYMGMT}

  Pevp_asym_cipher_st = ^Tevp_asym_cipher_st;
  Tevp_asym_cipher_st = record end;
  {$EXTERNALSYM Pevp_asym_cipher_st}

  PEVP_ASYM_CIPHER = ^TEVP_ASYM_CIPHER;
  TEVP_ASYM_CIPHER = Tevp_asym_cipher_st;
  {$EXTERNALSYM PEVP_ASYM_CIPHER}

  Pevp_kem_st = ^Tevp_kem_st;
  Tevp_kem_st = record end;
  {$EXTERNALSYM Pevp_kem_st}

  PEVP_KEM = ^TEVP_KEM;
  TEVP_KEM = Tevp_kem_st;
  {$EXTERNALSYM PEVP_KEM}

  Pevp_Encode_Ctx_st = ^Tevp_Encode_Ctx_st;
  Tevp_Encode_Ctx_st = record end;
  {$EXTERNALSYM Pevp_Encode_Ctx_st}

  PEVP_ENCODE_CTX = ^TEVP_ENCODE_CTX;
  TEVP_ENCODE_CTX = Tevp_Encode_Ctx_st;
  {$EXTERNALSYM PEVP_ENCODE_CTX}

  Phmac_ctx_st = ^Thmac_ctx_st;
  Thmac_ctx_st = record end;
  {$EXTERNALSYM Phmac_ctx_st}

  PHMAC_CTX = ^THMAC_CTX;
  THMAC_CTX = Thmac_ctx_st;
  {$EXTERNALSYM PHMAC_CTX}

  Pdh_st = ^Tdh_st;
  Tdh_st = record end;
  {$EXTERNALSYM Pdh_st}

  PDH = ^TDH;
  TDH = Tdh_st;
  {$EXTERNALSYM PDH}

  Pdh_method = ^Tdh_method;
  Tdh_method = record end;
  {$EXTERNALSYM Pdh_method}

  { TODO 1 -cID Collision detected : Review it and update. }
  // Collision with dh_method:
  // typedef struct dh_method DH_METHOD

  Pdsa_st = ^Tdsa_st;
  Tdsa_st = record end;
  {$EXTERNALSYM Pdsa_st}

  PDSA = ^TDSA;
  TDSA = Tdsa_st;
  {$EXTERNALSYM PDSA}

  Pdsa_method = ^Tdsa_method;
  Tdsa_method = record end;
  {$EXTERNALSYM Pdsa_method}

  { TODO 1 -cID Collision detected : Review it and update. }
  // Collision with dsa_method:
  // typedef struct dsa_method DSA_METHOD

  Prsa_st = ^Trsa_st;
  Trsa_st = record end;
  {$EXTERNALSYM Prsa_st}

  PRSA = ^TRSA;
  TRSA = Trsa_st;
  {$EXTERNALSYM PRSA}

  Prsa_meth_st = ^Trsa_meth_st;
  Trsa_meth_st = record end;
  {$EXTERNALSYM Prsa_meth_st}

  PRSA_METHOD = ^TRSA_METHOD;
  TRSA_METHOD = Trsa_meth_st;
  {$EXTERNALSYM PRSA_METHOD}

  Prsa_pss_params_st = ^Trsa_pss_params_st;
  Trsa_pss_params_st = record end;
  {$EXTERNALSYM Prsa_pss_params_st}

  PRSA_PSS_PARAMS = ^TRSA_PSS_PARAMS;
  TRSA_PSS_PARAMS = Trsa_pss_params_st;
  {$EXTERNALSYM PRSA_PSS_PARAMS}

  Prsa_oaep_params_st = ^Trsa_oaep_params_st;
  Trsa_oaep_params_st = record end;
  {$EXTERNALSYM Prsa_oaep_params_st}

  PRSA_OAEP_PARAMS = ^TRSA_OAEP_PARAMS;
  TRSA_OAEP_PARAMS = Trsa_oaep_params_st;
  {$EXTERNALSYM PRSA_OAEP_PARAMS}

  Pec_key_st = ^Tec_key_st;
  Tec_key_st = record end;
  {$EXTERNALSYM Pec_key_st}

  PEC_KEY = ^TEC_KEY;
  TEC_KEY = Tec_key_st;
  {$EXTERNALSYM PEC_KEY}

  Pec_key_method_st = ^Tec_key_method_st;
  Tec_key_method_st = record end;
  {$EXTERNALSYM Pec_key_method_st}

  PEC_KEY_METHOD = ^TEC_KEY_METHOD;
  TEC_KEY_METHOD = Tec_key_method_st;
  {$EXTERNALSYM PEC_KEY_METHOD}

  Prand_meth_st = ^Trand_meth_st;
  Trand_meth_st = record end;
  {$EXTERNALSYM Prand_meth_st}

  PRAND_METHOD = ^TRAND_METHOD;
  TRAND_METHOD = Trand_meth_st;
  {$EXTERNALSYM PRAND_METHOD}

  Prand_drbg_st = ^Trand_drbg_st;
  Trand_drbg_st = record end;
  {$EXTERNALSYM Prand_drbg_st}

  PRAND_DRBG = ^TRAND_DRBG;
  TRAND_DRBG = Trand_drbg_st;
  {$EXTERNALSYM PRAND_DRBG}

  Pssl_dane_st = ^Tssl_dane_st;
  Tssl_dane_st = record end;
  {$EXTERNALSYM Pssl_dane_st}

  PSSL_DANE = ^TSSL_DANE;
  TSSL_DANE = Tssl_dane_st;
  {$EXTERNALSYM PSSL_DANE}

  Px509_st = ^Tx509_st;
  Tx509_st = record end;
  {$EXTERNALSYM Px509_st}

  PX509 = ^TX509;
  TX509 = Tx509_st;
  {$EXTERNALSYM PX509}

  PX509_algor_st = ^TX509_algor_st;
  TX509_algor_st = record end;
  {$EXTERNALSYM PX509_algor_st}

  PX509_ALGOR = ^TX509_ALGOR;
  TX509_ALGOR = TX509_algor_st;
  {$EXTERNALSYM PX509_ALGOR}

  PX509_crl_st = ^TX509_crl_st;
  TX509_crl_st = record end;
  {$EXTERNALSYM PX509_crl_st}

  PX509_CRL = ^TX509_CRL;
  TX509_CRL = TX509_crl_st;
  {$EXTERNALSYM PX509_CRL}

  Px509_crl_method_st = ^Tx509_crl_method_st;
  Tx509_crl_method_st = record end;
  {$EXTERNALSYM Px509_crl_method_st}

  PX509_CRL_METHOD = ^TX509_CRL_METHOD;
  TX509_CRL_METHOD = Tx509_crl_method_st;
  {$EXTERNALSYM PX509_CRL_METHOD}

  Px509_revoked_st = ^Tx509_revoked_st;
  Tx509_revoked_st = record end;
  {$EXTERNALSYM Px509_revoked_st}

  PX509_REVOKED = ^TX509_REVOKED;
  TX509_REVOKED = Tx509_revoked_st;
  {$EXTERNALSYM PX509_REVOKED}

  PX509_name_st = ^TX509_name_st;
  TX509_name_st = record end;
  {$EXTERNALSYM PX509_name_st}

  PX509_NAME = ^TX509_NAME;
  TX509_NAME = TX509_name_st;
  {$EXTERNALSYM PX509_NAME}

  PX509_pubkey_st = ^TX509_pubkey_st;
  TX509_pubkey_st = record end;
  {$EXTERNALSYM PX509_pubkey_st}

  PX509_PUBKEY = ^TX509_PUBKEY;
  TX509_PUBKEY = TX509_pubkey_st;
  {$EXTERNALSYM PX509_PUBKEY}

  Px509_store_st = ^Tx509_store_st;
  Tx509_store_st = record end;
  {$EXTERNALSYM Px509_store_st}

  PX509_STORE = ^TX509_STORE;
  TX509_STORE = Tx509_store_st;
  {$EXTERNALSYM PX509_STORE}

  Px509_store_ctx_st = ^Tx509_store_ctx_st;
  Tx509_store_ctx_st = record end;
  {$EXTERNALSYM Px509_store_ctx_st}

  PX509_STORE_CTX = ^TX509_STORE_CTX;
  TX509_STORE_CTX = Tx509_store_ctx_st;
  {$EXTERNALSYM PX509_STORE_CTX}

  Px509_object_st = ^Tx509_object_st;
  Tx509_object_st = record end;
  {$EXTERNALSYM Px509_object_st}

  PX509_OBJECT = ^TX509_OBJECT;
  TX509_OBJECT = Tx509_object_st;
  {$EXTERNALSYM PX509_OBJECT}

  Px509_lookup_st = ^Tx509_lookup_st;
  Tx509_lookup_st = record end;
  {$EXTERNALSYM Px509_lookup_st}

  PX509_LOOKUP = ^TX509_LOOKUP;
  TX509_LOOKUP = Tx509_lookup_st;
  {$EXTERNALSYM PX509_LOOKUP}

  Px509_lookup_method_st = ^Tx509_lookup_method_st;
  Tx509_lookup_method_st = record end;
  {$EXTERNALSYM Px509_lookup_method_st}

  PX509_LOOKUP_METHOD = ^TX509_LOOKUP_METHOD;
  TX509_LOOKUP_METHOD = Tx509_lookup_method_st;
  {$EXTERNALSYM PX509_LOOKUP_METHOD}

  PX509_VERIFY_PARAM_st = ^TX509_VERIFY_PARAM_st;
  TX509_VERIFY_PARAM_st = record end;
  {$EXTERNALSYM PX509_VERIFY_PARAM_st}

  PX509_VERIFY_PARAM = ^TX509_VERIFY_PARAM;
  TX509_VERIFY_PARAM = TX509_VERIFY_PARAM_st;
  {$EXTERNALSYM PX509_VERIFY_PARAM}

  Px509_sig_info_st = ^Tx509_sig_info_st;
  Tx509_sig_info_st = record end;
  {$EXTERNALSYM Px509_sig_info_st}

  PX509_SIG_INFO = ^TX509_SIG_INFO;
  TX509_SIG_INFO = Tx509_sig_info_st;
  {$EXTERNALSYM PX509_SIG_INFO}

  Ppkcs8_priv_key_info_st = ^Tpkcs8_priv_key_info_st;
  Tpkcs8_priv_key_info_st = record end;
  {$EXTERNALSYM Ppkcs8_priv_key_info_st}

  PPKCS8_PRIV_KEY_INFO = ^TPKCS8_PRIV_KEY_INFO;
  TPKCS8_PRIV_KEY_INFO = Tpkcs8_priv_key_info_st;
  {$EXTERNALSYM PPKCS8_PRIV_KEY_INFO}

  Pv3_ext_ctx = ^Tv3_ext_ctx;
  Tv3_ext_ctx = record end;
  {$EXTERNALSYM Pv3_ext_ctx}

  PX509V3_CTX = ^TX509V3_CTX;
  TX509V3_CTX = Tv3_ext_ctx;
  {$EXTERNALSYM PX509V3_CTX}

  Pconf_st = ^Tconf_st;
  Tconf_st = record end;
  {$EXTERNALSYM Pconf_st}

  PCONF = ^TCONF;
  TCONF = Tconf_st;
  {$EXTERNALSYM PCONF}

  Possl_init_settings_st = ^Tossl_init_settings_st;
  Tossl_init_settings_st = record end;
  {$EXTERNALSYM Possl_init_settings_st}

  POPENSSL_INIT_SETTINGS = ^TOPENSSL_INIT_SETTINGS;
  TOPENSSL_INIT_SETTINGS = Tossl_init_settings_st;
  {$EXTERNALSYM POPENSSL_INIT_SETTINGS}

  Pui_st = ^Tui_st;
  Tui_st = record end;
  {$EXTERNALSYM Pui_st}

  PUI = ^TUI;
  TUI = Tui_st;
  {$EXTERNALSYM PUI}

  Pui_method_st = ^Tui_method_st;
  Tui_method_st = record end;
  {$EXTERNALSYM Pui_method_st}

  PUI_METHOD = ^TUI_METHOD;
  TUI_METHOD = Tui_method_st;
  {$EXTERNALSYM PUI_METHOD}

  Pengine_st = ^Tengine_st;
  Tengine_st = record end;
  {$EXTERNALSYM Pengine_st}

  PENGINE = ^TENGINE;
  TENGINE = Tengine_st;
  {$EXTERNALSYM PENGINE}

  Pssl_st = ^Tssl_st;
  Tssl_st = record end;
  {$EXTERNALSYM Pssl_st}

  PSSL = ^TSSL;
  TSSL = Tssl_st;
  {$EXTERNALSYM PSSL}

  Pssl_ctx_st = ^Tssl_ctx_st;
  Tssl_ctx_st = record end;
  {$EXTERNALSYM Pssl_ctx_st}

  PSSL_CTX = ^TSSL_CTX;
  TSSL_CTX = Tssl_ctx_st;
  {$EXTERNALSYM PSSL_CTX}

  Pcomp_ctx_st = ^Tcomp_ctx_st;
  Tcomp_ctx_st = record end;
  {$EXTERNALSYM Pcomp_ctx_st}

  PCOMP_CTX = ^TCOMP_CTX;
  TCOMP_CTX = Tcomp_ctx_st;
  {$EXTERNALSYM PCOMP_CTX}

  Pcomp_method_st = ^Tcomp_method_st;
  Tcomp_method_st = record end;
  {$EXTERNALSYM Pcomp_method_st}

  PCOMP_METHOD = ^TCOMP_METHOD;
  TCOMP_METHOD = Tcomp_method_st;
  {$EXTERNALSYM PCOMP_METHOD}

  PX509_POLICY_NODE_st = ^TX509_POLICY_NODE_st;
  TX509_POLICY_NODE_st = record end;
  {$EXTERNALSYM PX509_POLICY_NODE_st}

  PX509_POLICY_NODE = ^TX509_POLICY_NODE;
  TX509_POLICY_NODE = TX509_POLICY_NODE_st;
  {$EXTERNALSYM PX509_POLICY_NODE}

  PX509_POLICY_LEVEL_st = ^TX509_POLICY_LEVEL_st;
  TX509_POLICY_LEVEL_st = record end;
  {$EXTERNALSYM PX509_POLICY_LEVEL_st}

  PX509_POLICY_LEVEL = ^TX509_POLICY_LEVEL;
  TX509_POLICY_LEVEL = TX509_POLICY_LEVEL_st;
  {$EXTERNALSYM PX509_POLICY_LEVEL}

  PX509_POLICY_TREE_st = ^TX509_POLICY_TREE_st;
  TX509_POLICY_TREE_st = record end;
  {$EXTERNALSYM PX509_POLICY_TREE_st}

  PX509_POLICY_TREE = ^TX509_POLICY_TREE;
  TX509_POLICY_TREE = TX509_POLICY_TREE_st;
  {$EXTERNALSYM PX509_POLICY_TREE}

  PX509_POLICY_CACHE_st = ^TX509_POLICY_CACHE_st;
  TX509_POLICY_CACHE_st = record end;
  {$EXTERNALSYM PX509_POLICY_CACHE_st}

  PX509_POLICY_CACHE = ^TX509_POLICY_CACHE;
  TX509_POLICY_CACHE = TX509_POLICY_CACHE_st;
  {$EXTERNALSYM PX509_POLICY_CACHE}

  PAUTHORITY_KEYID_st = ^TAUTHORITY_KEYID_st;
  TAUTHORITY_KEYID_st = record end;
  {$EXTERNALSYM PAUTHORITY_KEYID_st}

  PAUTHORITY_KEYID = ^TAUTHORITY_KEYID;
  TAUTHORITY_KEYID = TAUTHORITY_KEYID_st;
  {$EXTERNALSYM PAUTHORITY_KEYID}

  PDIST_POINT_st = ^TDIST_POINT_st;
  TDIST_POINT_st = record end;
  {$EXTERNALSYM PDIST_POINT_st}

  PDIST_POINT = ^TDIST_POINT;
  TDIST_POINT = TDIST_POINT_st;
  {$EXTERNALSYM PDIST_POINT}

  PISSUING_DIST_POINT_st = ^TISSUING_DIST_POINT_st;
  TISSUING_DIST_POINT_st = record end;
  {$EXTERNALSYM PISSUING_DIST_POINT_st}

  PISSUING_DIST_POINT = ^TISSUING_DIST_POINT;
  TISSUING_DIST_POINT = TISSUING_DIST_POINT_st;
  {$EXTERNALSYM PISSUING_DIST_POINT}

  PNAME_CONSTRAINTS_st = ^TNAME_CONSTRAINTS_st;
  TNAME_CONSTRAINTS_st = record end;
  {$EXTERNALSYM PNAME_CONSTRAINTS_st}

  PNAME_CONSTRAINTS = ^TNAME_CONSTRAINTS;
  TNAME_CONSTRAINTS = TNAME_CONSTRAINTS_st;
  {$EXTERNALSYM PNAME_CONSTRAINTS}

  Pcrypto_ex_data_st = ^Tcrypto_ex_data_st;
  Tcrypto_ex_data_st = record end;
  {$EXTERNALSYM Pcrypto_ex_data_st}

  PCRYPTO_EX_DATA = ^TCRYPTO_EX_DATA;
  TCRYPTO_EX_DATA = Tcrypto_ex_data_st;
  {$EXTERNALSYM PCRYPTO_EX_DATA}

  Possl_http_req_ctx_st = ^Tossl_http_req_ctx_st;
  Tossl_http_req_ctx_st = record end;
  {$EXTERNALSYM Possl_http_req_ctx_st}

  POSSL_HTTP_REQ_CTX = ^TOSSL_HTTP_REQ_CTX;
  TOSSL_HTTP_REQ_CTX = Tossl_http_req_ctx_st;
  {$EXTERNALSYM POSSL_HTTP_REQ_CTX}

  Pocsp_response_st = ^Tocsp_response_st;
  Tocsp_response_st = record end;
  {$EXTERNALSYM Pocsp_response_st}

  POCSP_RESPONSE = ^TOCSP_RESPONSE;
  TOCSP_RESPONSE = Tocsp_response_st;
  {$EXTERNALSYM POCSP_RESPONSE}

  Pocsp_responder_id_st = ^Tocsp_responder_id_st;
  Tocsp_responder_id_st = record end;
  {$EXTERNALSYM Pocsp_responder_id_st}

  POCSP_RESPID = ^TOCSP_RESPID;
  TOCSP_RESPID = Tocsp_responder_id_st;
  {$EXTERNALSYM POCSP_RESPID}

  Psct_st = ^Tsct_st;
  Tsct_st = record end;
  {$EXTERNALSYM Psct_st}

  PSCT = ^TSCT;
  TSCT = Tsct_st;
  {$EXTERNALSYM PSCT}

  Psct_ctx_st = ^Tsct_ctx_st;
  Tsct_ctx_st = record end;
  {$EXTERNALSYM Psct_ctx_st}

  PSCT_CTX = ^TSCT_CTX;
  TSCT_CTX = Tsct_ctx_st;
  {$EXTERNALSYM PSCT_CTX}

  Pctlog_st = ^Tctlog_st;
  Tctlog_st = record end;
  {$EXTERNALSYM Pctlog_st}

  PCTLOG = ^TCTLOG;
  TCTLOG = Tctlog_st;
  {$EXTERNALSYM PCTLOG}

  Pctlog_store_st = ^Tctlog_store_st;
  Tctlog_store_st = record end;
  {$EXTERNALSYM Pctlog_store_st}

  PCTLOG_STORE = ^TCTLOG_STORE;
  TCTLOG_STORE = Tctlog_store_st;
  {$EXTERNALSYM PCTLOG_STORE}

  Pct_policy_eval_ctx_st = ^Tct_policy_eval_ctx_st;
  Tct_policy_eval_ctx_st = record end;
  {$EXTERNALSYM Pct_policy_eval_ctx_st}

  PCT_POLICY_EVAL_CTX = ^TCT_POLICY_EVAL_CTX;
  TCT_POLICY_EVAL_CTX = Tct_policy_eval_ctx_st;
  {$EXTERNALSYM PCT_POLICY_EVAL_CTX}

  Possl_store_info_st = ^Tossl_store_info_st;
  Tossl_store_info_st = record end;
  {$EXTERNALSYM Possl_store_info_st}

  POSSL_STORE_INFO = ^TOSSL_STORE_INFO;
  TOSSL_STORE_INFO = Tossl_store_info_st;
  {$EXTERNALSYM POSSL_STORE_INFO}

  Possl_store_search_st = ^Tossl_store_search_st;
  Tossl_store_search_st = record end;
  {$EXTERNALSYM Possl_store_search_st}

  POSSL_STORE_SEARCH = ^TOSSL_STORE_SEARCH;
  TOSSL_STORE_SEARCH = Tossl_store_search_st;
  {$EXTERNALSYM POSSL_STORE_SEARCH}

  Possl_lib_ctx_st = ^Tossl_lib_ctx_st;
  Tossl_lib_ctx_st = record end;
  {$EXTERNALSYM Possl_lib_ctx_st}

  POSSL_LIB_CTX = ^TOSSL_LIB_CTX;
  TOSSL_LIB_CTX = Tossl_lib_ctx_st;
  {$EXTERNALSYM POSSL_LIB_CTX}

  Possl_dispatch_st = ^Tossl_dispatch_st;
  Tossl_dispatch_st = record end;
  {$EXTERNALSYM Possl_dispatch_st}

  POSSL_DISPATCH = ^TOSSL_DISPATCH;
  TOSSL_DISPATCH = Tossl_dispatch_st;
  {$EXTERNALSYM POSSL_DISPATCH}

  Possl_item_st = ^Tossl_item_st;
  Tossl_item_st = record end;
  {$EXTERNALSYM Possl_item_st}

  POSSL_ITEM = ^TOSSL_ITEM;
  TOSSL_ITEM = Tossl_item_st;
  {$EXTERNALSYM POSSL_ITEM}

  Possl_algorithm_st = ^Tossl_algorithm_st;
  Tossl_algorithm_st = record end;
  {$EXTERNALSYM Possl_algorithm_st}

  POSSL_ALGORITHM = ^TOSSL_ALGORITHM;
  TOSSL_ALGORITHM = Tossl_algorithm_st;
  {$EXTERNALSYM POSSL_ALGORITHM}

  Possl_param_st = ^Tossl_param_st;
  Tossl_param_st = record end;
  {$EXTERNALSYM Possl_param_st}

  POSSL_PARAM_ARRAY = ^TOSSL_PARAM;
  TOSSL_PARAM = Tossl_param_st;
  {$EXTERNALSYM POSSL_PARAM_ARRAY}

  Possl_param_bld_st = ^Tossl_param_bld_st;
  Tossl_param_bld_st = record end;
  {$EXTERNALSYM Possl_param_bld_st}

  POSSL_PARAM_BLD = ^TOSSL_PARAM_BLD;
  TOSSL_PARAM_BLD = Tossl_param_bld_st;
  {$EXTERNALSYM POSSL_PARAM_BLD}

  Possl_encoder_st = ^Tossl_encoder_st;
  Tossl_encoder_st = record end;
  {$EXTERNALSYM Possl_encoder_st}

  POSSL_ENCODER = ^TOSSL_ENCODER;
  TOSSL_ENCODER = Tossl_encoder_st;
  {$EXTERNALSYM POSSL_ENCODER}

  Possl_encoder_ctx_st = ^Tossl_encoder_ctx_st;
  Tossl_encoder_ctx_st = record end;
  {$EXTERNALSYM Possl_encoder_ctx_st}

  POSSL_ENCODER_CTX = ^TOSSL_ENCODER_CTX;
  TOSSL_ENCODER_CTX = Tossl_encoder_ctx_st;
  {$EXTERNALSYM POSSL_ENCODER_CTX}

  Possl_decoder_st = ^Tossl_decoder_st;
  Tossl_decoder_st = record end;
  {$EXTERNALSYM Possl_decoder_st}

  POSSL_DECODER = ^TOSSL_DECODER;
  TOSSL_DECODER = Tossl_decoder_st;
  {$EXTERNALSYM POSSL_DECODER}

  Possl_decoder_ctx_st = ^Tossl_decoder_ctx_st;
  Tossl_decoder_ctx_st = record end;
  {$EXTERNALSYM Possl_decoder_ctx_st}

  POSSL_DECODER_CTX = ^TOSSL_DECODER_CTX;
  TOSSL_DECODER_CTX = Tossl_decoder_ctx_st;
  {$EXTERNALSYM POSSL_DECODER_CTX}

  Possl_self_test_st = ^Tossl_self_test_st;
  Tossl_self_test_st = record end;
  {$EXTERNALSYM Possl_self_test_st}

  POSSL_SELF_TEST = ^TOSSL_SELF_TEST;
  TOSSL_SELF_TEST = Tossl_self_test_st;
  {$EXTERNALSYM POSSL_SELF_TEST}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  Tpem_password_cb_func_cb = function(arg1: PIdAnsiChar; arg2: TIdC_INT; arg3: TIdC_INT; arg4: Pointer): TIdC_INT; cdecl;

implementation

end.