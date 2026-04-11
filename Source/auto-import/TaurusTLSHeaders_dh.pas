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

unit TaurusTLSHeaders_dh;

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
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // DH_meth_get_generate_key_func_cb = function(arg1: Pdh_st): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // DH_meth_get_compute_key_func_cb = function(arg1: PIdAnsiChar; arg2: Pbignum_st; arg3: Pdh_st): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // DH_meth_get_bn_mod_exp_func_cb = function(arg1: Pdh_st; arg2: Pbignum_st; arg3: Pbignum_st; arg4: Pbignum_st; arg5: Pbignum_st; arg6: Pbignum_ctx; arg7: Pbn_mont_ctx_st): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // DH_meth_get_generate_params_func_cb = function(arg1: Pdh_st; arg2: TIdC_INT; arg3: TIdC_INT; arg4: Pbn_gencb_st): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // DH_generate_parameters_callback_cb = procedure(arg1: TIdC_INT; arg2: TIdC_INT; arg3: Pointer); cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  DH_PARAMGEN_TYPE_GENERATOR = 0;
  DH_PARAMGEN_TYPE_FIPS_186_2 = 1;
  DH_PARAMGEN_TYPE_FIPS_186_4 = 2;
  DH_PARAMGEN_TYPE_GROUP = 3;
  EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN = (EVP_PKEY_ALG_CTRL+1);
  EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR = (EVP_PKEY_ALG_CTRL+2);
  EVP_PKEY_CTRL_DH_RFC5114 = (EVP_PKEY_ALG_CTRL+3);
  EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN = (EVP_PKEY_ALG_CTRL+4);
  EVP_PKEY_CTRL_DH_PARAMGEN_TYPE = (EVP_PKEY_ALG_CTRL+5);
  EVP_PKEY_CTRL_DH_KDF_TYPE = (EVP_PKEY_ALG_CTRL+6);
  EVP_PKEY_CTRL_DH_KDF_MD = (EVP_PKEY_ALG_CTRL+7);
  EVP_PKEY_CTRL_GET_DH_KDF_MD = (EVP_PKEY_ALG_CTRL+8);
  EVP_PKEY_CTRL_DH_KDF_OUTLEN = (EVP_PKEY_ALG_CTRL+9);
  EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN = (EVP_PKEY_ALG_CTRL+10);
  EVP_PKEY_CTRL_DH_KDF_UKM = (EVP_PKEY_ALG_CTRL+11);
  EVP_PKEY_CTRL_GET_DH_KDF_UKM = (EVP_PKEY_ALG_CTRL+12);
  EVP_PKEY_CTRL_DH_KDF_OID = (EVP_PKEY_ALG_CTRL+13);
  EVP_PKEY_CTRL_GET_DH_KDF_OID = (EVP_PKEY_ALG_CTRL+14);
  EVP_PKEY_CTRL_DH_NID = (EVP_PKEY_ALG_CTRL+15);
  EVP_PKEY_CTRL_DH_PAD = (EVP_PKEY_ALG_CTRL+16);
  EVP_PKEY_DH_KDF_NONE = 1;
  EVP_PKEY_DH_KDF_X9_42 = 2;
  OPENSSL_DH_MAX_MODULUS_BITS = 10000;
  OPENSSL_DH_CHECK_MAX_MODULUS_BITS = 32768;
  OPENSSL_DH_FIPS_MIN_MODULUS_BITS = 1024;
  DH_FLAG_CACHE_MONT_P = $01;
  DH_FLAG_TYPE_MASK = $F000;
  DH_FLAG_TYPE_DH = $0000;
  DH_FLAG_TYPE_DHX = $1000;
  DH_FLAG_NO_EXP_CONSTTIME = $00;
  DH_FLAG_FIPS_METHOD = $0400;
  DH_FLAG_NON_FIPS_ALLOW = $0400;
  DH_GENERATOR_2 = 2;
  DH_GENERATOR_3 = 3;
  DH_GENERATOR_5 = 5;
  DH_CHECK_P_NOT_PRIME = $01;
  DH_CHECK_P_NOT_SAFE_PRIME = $02;
  DH_UNABLE_TO_CHECK_GENERATOR = $04;
  DH_NOT_SUITABLE_GENERATOR = $08;
  DH_CHECK_Q_NOT_PRIME = $10;
  DH_CHECK_INVALID_Q_VALUE = $20;
  DH_CHECK_INVALID_J_VALUE = $40;
  DH_MODULUS_TOO_SMALL = $80;
  DH_MODULUS_TOO_LARGE = $100;
  DH_CHECK_PUBKEY_TOO_SMALL = $01;
  DH_CHECK_PUBKEY_TOO_LARGE = $02;
  DH_CHECK_PUBKEY_INVALID = $04;
  DH_CHECK_P_NOT_STRONG_PRIME = DH_CHECK_P_NOT_SAFE_PRIME;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  EVP_PKEY_CTX_set_dh_paramgen_type: function(ctx: PEVP_PKEY_CTX; typ: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_dh_paramgen_type}

  EVP_PKEY_CTX_set_dh_paramgen_gindex: function(ctx: PEVP_PKEY_CTX; gindex: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_dh_paramgen_gindex}

  EVP_PKEY_CTX_set_dh_paramgen_seed: function(ctx: PEVP_PKEY_CTX; seed: PIdAnsiChar; seedlen: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_dh_paramgen_seed}

  EVP_PKEY_CTX_set_dh_paramgen_prime_len: function(ctx: PEVP_PKEY_CTX; pbits: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_dh_paramgen_prime_len}

  EVP_PKEY_CTX_set_dh_paramgen_subprime_len: function(ctx: PEVP_PKEY_CTX; qlen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_dh_paramgen_subprime_len}

  EVP_PKEY_CTX_set_dh_paramgen_generator: function(ctx: PEVP_PKEY_CTX; gen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_dh_paramgen_generator}

  EVP_PKEY_CTX_set_dh_nid: function(ctx: PEVP_PKEY_CTX; nid: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_dh_nid}

  EVP_PKEY_CTX_set_dh_rfc5114: function(ctx: PEVP_PKEY_CTX; gen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_dh_rfc5114}

  EVP_PKEY_CTX_set_dhx_rfc5114: function(ctx: PEVP_PKEY_CTX; gen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_dhx_rfc5114}

  EVP_PKEY_CTX_set_dh_pad: function(ctx: PEVP_PKEY_CTX; pad: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_dh_pad}

  EVP_PKEY_CTX_set_dh_kdf_type: function(ctx: PEVP_PKEY_CTX; kdf: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_dh_kdf_type}

  EVP_PKEY_CTX_get_dh_kdf_type: function(ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_get_dh_kdf_type}

  EVP_PKEY_CTX_set0_dh_kdf_oid: function(ctx: PEVP_PKEY_CTX; oid: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set0_dh_kdf_oid}

  EVP_PKEY_CTX_get0_dh_kdf_oid: function(ctx: PEVP_PKEY_CTX; oid: PPASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_get0_dh_kdf_oid}

  EVP_PKEY_CTX_set_dh_kdf_md: function(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_dh_kdf_md}

  EVP_PKEY_CTX_get_dh_kdf_md: function(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_get_dh_kdf_md}

  EVP_PKEY_CTX_set_dh_kdf_outlen: function(ctx: PEVP_PKEY_CTX; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_dh_kdf_outlen}

  EVP_PKEY_CTX_get_dh_kdf_outlen: function(ctx: PEVP_PKEY_CTX; len: PIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_get_dh_kdf_outlen}

  EVP_PKEY_CTX_set0_dh_kdf_ukm: function(ctx: PEVP_PKEY_CTX; ukm: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set0_dh_kdf_ukm}

  EVP_PKEY_CTX_get0_dh_kdf_ukm: function(ctx: PEVP_PKEY_CTX; ukm: PPIdAnsiChar): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EVP_PKEY_CTX_get0_dh_kdf_ukm}

  DHparams_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM DHparams_it}

  DHparams_dup: function(a: PDH): PDH; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DHparams_dup}

  DH_OpenSSL: function: PDH_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_OpenSSL}

  DH_set_default_method: procedure(meth: PDH_METHOD); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_set_default_method}

  DH_get_default_method: function: PDH_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_get_default_method}

  DH_set_method: function(dh: PDH; meth: PDH_METHOD): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_set_method}

  DH_new_method: function(engine: PENGINE): PDH; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_new_method}

  DH_new: function: PDH; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_new}

  DH_free: procedure(dh: PDH); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_free}

  DH_up_ref: function(dh: PDH): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_up_ref}

  DH_bits: function(dh: PDH): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_bits}

  DH_size: function(dh: PDH): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_size}

  DH_security_bits: function(dh: PDH): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_security_bits}

  DH_set_ex_data: function(d: PDH; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_set_ex_data}

  DH_get_ex_data: function(d: PDH; idx: TIdC_INT): Pointer; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_get_ex_data}

  DH_generate_parameters_ex: function(dh: PDH; prime_len: TIdC_INT; generator: TIdC_INT; cb: PBN_GENCB): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_generate_parameters_ex}

  DH_check_params_ex: function(dh: PDH): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_check_params_ex}

  DH_check_ex: function(dh: PDH): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_check_ex}

  DH_check_pub_key_ex: function(dh: PDH; pub_key: PBIGNUM): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_check_pub_key_ex}

  DH_check_params: function(dh: PDH; ret: PIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_check_params}

  DH_check: function(dh: PDH; codes: PIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_check}

  DH_check_pub_key: function(dh: PDH; pub_key: PBIGNUM; codes: PIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_check_pub_key}

  DH_generate_key: function(dh: PDH): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_generate_key}

  DH_compute_key: function(key: PIdAnsiChar; pub_key: PBIGNUM; dh: PDH): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_compute_key}

  DH_compute_key_padded: function(key: PIdAnsiChar; pub_key: PBIGNUM; dh: PDH): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_compute_key_padded}

  d2i_DHparams: function(a: PPDH; _in: PPIdAnsiChar; len: TIdC_LONG): PDH; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM d2i_DHparams}

  i2d_DHparams: function(a: PDH; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM i2d_DHparams}

  d2i_DHxparams: function(a: PPDH; _in: PPIdAnsiChar; len: TIdC_LONG): PDH; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM d2i_DHxparams}

  i2d_DHxparams: function(a: PDH; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM i2d_DHxparams}

  DHparams_print_fp: function(fp: PFILE; x: PDH): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DHparams_print_fp}

  DHparams_print: function(bp: PBIO; x: PDH): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DHparams_print}

  DH_get_1024_160: function: PDH; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_get_1024_160}

  DH_get_2048_224: function: PDH; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_get_2048_224}

  DH_get_2048_256: function: PDH; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_get_2048_256}

  DH_new_by_nid: function(nid: TIdC_INT): PDH; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_new_by_nid}

  DH_get_nid: function(dh: PDH): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_get_nid}

  DH_KDF_X9_42: function(_out: PIdAnsiChar; outlen: TIdC_SIZET; Z: PIdAnsiChar; Zlen: TIdC_SIZET; key_oid: PASN1_OBJECT; ukm: PIdAnsiChar; ukmlen: TIdC_SIZET; md: PEVP_MD): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_KDF_X9_42}

  DH_get0_pqg: procedure(dh: PDH; p: PPBIGNUM; q: PPBIGNUM; g: PPBIGNUM); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_get0_pqg}

  DH_set0_pqg: function(dh: PDH; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_set0_pqg}

  DH_get0_key: procedure(dh: PDH; pub_key: PPBIGNUM; priv_key: PPBIGNUM); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_get0_key}

  DH_set0_key: function(dh: PDH; pub_key: PBIGNUM; priv_key: PBIGNUM): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_set0_key}

  DH_get0_p: function(dh: PDH): PBIGNUM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_get0_p}

  DH_get0_q: function(dh: PDH): PBIGNUM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_get0_q}

  DH_get0_g: function(dh: PDH): PBIGNUM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_get0_g}

  DH_get0_priv_key: function(dh: PDH): PBIGNUM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_get0_priv_key}

  DH_get0_pub_key: function(dh: PDH): PBIGNUM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_get0_pub_key}

  DH_clear_flags: procedure(dh: PDH; flags: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_clear_flags}

  DH_test_flags: function(dh: PDH; flags: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_test_flags}

  DH_set_flags: procedure(dh: PDH; flags: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_set_flags}

  DH_get0_engine: function(d: PDH): PENGINE; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_get0_engine}

  DH_get_length: function(dh: PDH): TIdC_LONG; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_get_length}

  DH_set_length: function(dh: PDH; length: TIdC_LONG): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_set_length}

  DH_meth_new: function(name: PIdAnsiChar; flags: TIdC_INT): PDH_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_meth_new}

  DH_meth_free: procedure(dhm: PDH_METHOD); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_meth_free}

  DH_meth_dup: function(dhm: PDH_METHOD): PDH_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_meth_dup}

  DH_meth_get0_name: function(dhm: PDH_METHOD): PIdAnsiChar; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_meth_get0_name}

  DH_meth_set1_name: function(dhm: PDH_METHOD; name: PIdAnsiChar): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_meth_set1_name}

  DH_meth_get_flags: function(dhm: PDH_METHOD): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_meth_get_flags}

  DH_meth_set_flags: function(dhm: PDH_METHOD; flags: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_meth_set_flags}

  DH_meth_get0_app_data: function(dhm: PDH_METHOD): Pointer; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_meth_get0_app_data}

  DH_meth_set0_app_data: function(dhm: PDH_METHOD; app_data: Pointer): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_meth_set0_app_data}

  DH_meth_get_generate_key: function(dhm: PDH_METHOD): TDH_meth_get_generate_key_func_cb; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_meth_get_generate_key}

  DH_meth_set_generate_key: function(dhm: PDH_METHOD; generate_key: TDH_meth_get_generate_key_func_cb): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_meth_set_generate_key}

  DH_meth_get_compute_key: function(dhm: PDH_METHOD): TDH_meth_get_compute_key_func_cb; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_meth_get_compute_key}

  DH_meth_set_compute_key: function(dhm: PDH_METHOD; compute_key: TDH_meth_get_compute_key_func_cb): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_meth_set_compute_key}

  DH_meth_get_bn_mod_exp: function(dhm: PDH_METHOD): TDH_meth_get_bn_mod_exp_func_cb; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_meth_get_bn_mod_exp}

  DH_meth_set_bn_mod_exp: function(dhm: PDH_METHOD; bn_mod_exp: TDH_meth_get_bn_mod_exp_func_cb): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_meth_set_bn_mod_exp}

  DH_meth_get_init: function(dhm: PDH_METHOD): TDH_meth_get_generate_key_func_cb; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_meth_get_init}

  DH_meth_set_init: function(dhm: PDH_METHOD; init: TDH_meth_get_generate_key_func_cb): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_meth_set_init}

  DH_meth_get_finish: function(dhm: PDH_METHOD): TDH_meth_get_generate_key_func_cb; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_meth_get_finish}

  DH_meth_set_finish: function(dhm: PDH_METHOD; finish: TDH_meth_get_generate_key_func_cb): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_meth_set_finish}

  DH_meth_get_generate_params: function(dhm: PDH_METHOD): TDH_meth_get_generate_params_func_cb; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_meth_get_generate_params}

  DH_meth_set_generate_params: function(dhm: PDH_METHOD; generate_params: TDH_meth_get_generate_params_func_cb): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM DH_meth_set_generate_params}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function EVP_PKEY_CTX_set_dh_paramgen_type(ctx: PEVP_PKEY_CTX; typ: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_dh_paramgen_gindex(ctx: PEVP_PKEY_CTX; gindex: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_dh_paramgen_seed(ctx: PEVP_PKEY_CTX; seed: PIdAnsiChar; seedlen: TIdC_SIZET): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx: PEVP_PKEY_CTX; pbits: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_dh_paramgen_subprime_len(ctx: PEVP_PKEY_CTX; qlen: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_dh_paramgen_generator(ctx: PEVP_PKEY_CTX; gen: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_dh_nid(ctx: PEVP_PKEY_CTX; nid: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_dh_rfc5114(ctx: PEVP_PKEY_CTX; gen: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_dhx_rfc5114(ctx: PEVP_PKEY_CTX; gen: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_dh_pad(ctx: PEVP_PKEY_CTX; pad: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_dh_kdf_type(ctx: PEVP_PKEY_CTX; kdf: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_get_dh_kdf_type(ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set0_dh_kdf_oid(ctx: PEVP_PKEY_CTX; oid: PASN1_OBJECT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_get0_dh_kdf_oid(ctx: PEVP_PKEY_CTX; oid: PPASN1_OBJECT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_dh_kdf_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl;
function EVP_PKEY_CTX_get_dh_kdf_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_dh_kdf_outlen(ctx: PEVP_PKEY_CTX; len: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_get_dh_kdf_outlen(ctx: PEVP_PKEY_CTX; len: PIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set0_dh_kdf_ukm(ctx: PEVP_PKEY_CTX; ukm: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_get0_dh_kdf_ukm(ctx: PEVP_PKEY_CTX; ukm: PPIdAnsiChar): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DHparams_it: PASN1_ITEM; cdecl;
function DHparams_dup(a: PDH): PDH; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_OpenSSL: PDH_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DH_set_default_method(meth: PDH_METHOD); cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_get_default_method: PDH_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_set_method(dh: PDH; meth: PDH_METHOD): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_new_method(engine: PENGINE): PDH; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_new: PDH; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DH_free(dh: PDH); cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_up_ref(dh: PDH): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_bits(dh: PDH): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_size(dh: PDH): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_security_bits(dh: PDH): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_set_ex_data(d: PDH; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_get_ex_data(d: PDH; idx: TIdC_INT): Pointer; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_generate_parameters_ex(dh: PDH; prime_len: TIdC_INT; generator: TIdC_INT; cb: PBN_GENCB): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_check_params_ex(dh: PDH): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_check_ex(dh: PDH): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_check_pub_key_ex(dh: PDH; pub_key: PBIGNUM): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_check_params(dh: PDH; ret: PIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_check(dh: PDH; codes: PIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_check_pub_key(dh: PDH; pub_key: PBIGNUM; codes: PIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_generate_key(dh: PDH): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_compute_key(key: PIdAnsiChar; pub_key: PBIGNUM; dh: PDH): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_compute_key_padded(key: PIdAnsiChar; pub_key: PBIGNUM; dh: PDH): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function d2i_DHparams(a: PPDH; _in: PPIdAnsiChar; len: TIdC_LONG): PDH; cdecl; deprecated 'In OpenSSL 3_0_0';
function i2d_DHparams(a: PDH; _out: PPIdAnsiChar): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function d2i_DHxparams(a: PPDH; _in: PPIdAnsiChar; len: TIdC_LONG): PDH; cdecl; deprecated 'In OpenSSL 3_0_0';
function i2d_DHxparams(a: PDH; _out: PPIdAnsiChar): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DHparams_print_fp(fp: PFILE; x: PDH): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DHparams_print(bp: PBIO; x: PDH): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_get_1024_160: PDH; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_get_2048_224: PDH; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_get_2048_256: PDH; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_new_by_nid(nid: TIdC_INT): PDH; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_get_nid(dh: PDH): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_KDF_X9_42(_out: PIdAnsiChar; outlen: TIdC_SIZET; Z: PIdAnsiChar; Zlen: TIdC_SIZET; key_oid: PASN1_OBJECT; ukm: PIdAnsiChar; ukmlen: TIdC_SIZET; md: PEVP_MD): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DH_get0_pqg(dh: PDH; p: PPBIGNUM; q: PPBIGNUM; g: PPBIGNUM); cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_set0_pqg(dh: PDH; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DH_get0_key(dh: PDH; pub_key: PPBIGNUM; priv_key: PPBIGNUM); cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_set0_key(dh: PDH; pub_key: PBIGNUM; priv_key: PBIGNUM): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_get0_p(dh: PDH): PBIGNUM; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_get0_q(dh: PDH): PBIGNUM; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_get0_g(dh: PDH): PBIGNUM; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_get0_priv_key(dh: PDH): PBIGNUM; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_get0_pub_key(dh: PDH): PBIGNUM; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DH_clear_flags(dh: PDH; flags: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_test_flags(dh: PDH; flags: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DH_set_flags(dh: PDH; flags: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_get0_engine(d: PDH): PENGINE; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_get_length(dh: PDH): TIdC_LONG; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_set_length(dh: PDH; length: TIdC_LONG): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_meth_new(name: PIdAnsiChar; flags: TIdC_INT): PDH_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure DH_meth_free(dhm: PDH_METHOD); cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_meth_dup(dhm: PDH_METHOD): PDH_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_meth_get0_name(dhm: PDH_METHOD): PIdAnsiChar; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_meth_set1_name(dhm: PDH_METHOD; name: PIdAnsiChar): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_meth_get_flags(dhm: PDH_METHOD): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_meth_set_flags(dhm: PDH_METHOD; flags: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_meth_get0_app_data(dhm: PDH_METHOD): Pointer; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_meth_set0_app_data(dhm: PDH_METHOD; app_data: Pointer): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_meth_get_generate_key(dhm: PDH_METHOD): TDH_meth_get_generate_key_func_cb; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_meth_set_generate_key(dhm: PDH_METHOD; generate_key: TDH_meth_get_generate_key_func_cb): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_meth_get_compute_key(dhm: PDH_METHOD): TDH_meth_get_compute_key_func_cb; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_meth_set_compute_key(dhm: PDH_METHOD; compute_key: TDH_meth_get_compute_key_func_cb): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_meth_get_bn_mod_exp(dhm: PDH_METHOD): TDH_meth_get_bn_mod_exp_func_cb; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_meth_set_bn_mod_exp(dhm: PDH_METHOD; bn_mod_exp: TDH_meth_get_bn_mod_exp_func_cb): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_meth_get_init(dhm: PDH_METHOD): TDH_meth_get_generate_key_func_cb; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_meth_set_init(dhm: PDH_METHOD; init: TDH_meth_get_generate_key_func_cb): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_meth_get_finish(dhm: PDH_METHOD): TDH_meth_get_generate_key_func_cb; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_meth_set_finish(dhm: PDH_METHOD; finish: TDH_meth_get_generate_key_func_cb): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_meth_get_generate_params(dhm: PDH_METHOD): TDH_meth_get_generate_params_func_cb; cdecl; deprecated 'In OpenSSL 3_0_0';
function DH_meth_set_generate_params(dhm: PDH_METHOD; generate_params: TDH_meth_get_generate_params_func_cb): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
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

function EVP_PKEY_CTX_set_dh_paramgen_type(ctx: PEVP_PKEY_CTX; typ: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_dh_paramgen_type';
function EVP_PKEY_CTX_set_dh_paramgen_gindex(ctx: PEVP_PKEY_CTX; gindex: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_dh_paramgen_gindex';
function EVP_PKEY_CTX_set_dh_paramgen_seed(ctx: PEVP_PKEY_CTX; seed: PIdAnsiChar; seedlen: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_dh_paramgen_seed';
function EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx: PEVP_PKEY_CTX; pbits: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_dh_paramgen_prime_len';
function EVP_PKEY_CTX_set_dh_paramgen_subprime_len(ctx: PEVP_PKEY_CTX; qlen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_dh_paramgen_subprime_len';
function EVP_PKEY_CTX_set_dh_paramgen_generator(ctx: PEVP_PKEY_CTX; gen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_dh_paramgen_generator';
function EVP_PKEY_CTX_set_dh_nid(ctx: PEVP_PKEY_CTX; nid: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_dh_nid';
function EVP_PKEY_CTX_set_dh_rfc5114(ctx: PEVP_PKEY_CTX; gen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_dh_rfc5114';
function EVP_PKEY_CTX_set_dhx_rfc5114(ctx: PEVP_PKEY_CTX; gen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_dhx_rfc5114';
function EVP_PKEY_CTX_set_dh_pad(ctx: PEVP_PKEY_CTX; pad: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_dh_pad';
function EVP_PKEY_CTX_set_dh_kdf_type(ctx: PEVP_PKEY_CTX; kdf: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_dh_kdf_type';
function EVP_PKEY_CTX_get_dh_kdf_type(ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_get_dh_kdf_type';
function EVP_PKEY_CTX_set0_dh_kdf_oid(ctx: PEVP_PKEY_CTX; oid: PASN1_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set0_dh_kdf_oid';
function EVP_PKEY_CTX_get0_dh_kdf_oid(ctx: PEVP_PKEY_CTX; oid: PPASN1_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_get0_dh_kdf_oid';
function EVP_PKEY_CTX_set_dh_kdf_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_dh_kdf_md';
function EVP_PKEY_CTX_get_dh_kdf_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_get_dh_kdf_md';
function EVP_PKEY_CTX_set_dh_kdf_outlen(ctx: PEVP_PKEY_CTX; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_dh_kdf_outlen';
function EVP_PKEY_CTX_get_dh_kdf_outlen(ctx: PEVP_PKEY_CTX; len: PIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_get_dh_kdf_outlen';
function EVP_PKEY_CTX_set0_dh_kdf_ukm(ctx: PEVP_PKEY_CTX; ukm: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set0_dh_kdf_ukm';
function EVP_PKEY_CTX_get0_dh_kdf_ukm(ctx: PEVP_PKEY_CTX; ukm: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_get0_dh_kdf_ukm';
function DHparams_it: PASN1_ITEM; cdecl external CLibCrypto name 'DHparams_it';
function DHparams_dup(a: PDH): PDH; cdecl external CLibCrypto name 'DHparams_dup';
function DH_OpenSSL: PDH_METHOD; cdecl external CLibCrypto name 'DH_OpenSSL';
procedure DH_set_default_method(meth: PDH_METHOD); cdecl external CLibCrypto name 'DH_set_default_method';
function DH_get_default_method: PDH_METHOD; cdecl external CLibCrypto name 'DH_get_default_method';
function DH_set_method(dh: PDH; meth: PDH_METHOD): TIdC_INT; cdecl external CLibCrypto name 'DH_set_method';
function DH_new_method(engine: PENGINE): PDH; cdecl external CLibCrypto name 'DH_new_method';
function DH_new: PDH; cdecl external CLibCrypto name 'DH_new';
procedure DH_free(dh: PDH); cdecl external CLibCrypto name 'DH_free';
function DH_up_ref(dh: PDH): TIdC_INT; cdecl external CLibCrypto name 'DH_up_ref';
function DH_bits(dh: PDH): TIdC_INT; cdecl external CLibCrypto name 'DH_bits';
function DH_size(dh: PDH): TIdC_INT; cdecl external CLibCrypto name 'DH_size';
function DH_security_bits(dh: PDH): TIdC_INT; cdecl external CLibCrypto name 'DH_security_bits';
function DH_set_ex_data(d: PDH; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl external CLibCrypto name 'DH_set_ex_data';
function DH_get_ex_data(d: PDH; idx: TIdC_INT): Pointer; cdecl external CLibCrypto name 'DH_get_ex_data';
function DH_generate_parameters_ex(dh: PDH; prime_len: TIdC_INT; generator: TIdC_INT; cb: PBN_GENCB): TIdC_INT; cdecl external CLibCrypto name 'DH_generate_parameters_ex';
function DH_check_params_ex(dh: PDH): TIdC_INT; cdecl external CLibCrypto name 'DH_check_params_ex';
function DH_check_ex(dh: PDH): TIdC_INT; cdecl external CLibCrypto name 'DH_check_ex';
function DH_check_pub_key_ex(dh: PDH; pub_key: PBIGNUM): TIdC_INT; cdecl external CLibCrypto name 'DH_check_pub_key_ex';
function DH_check_params(dh: PDH; ret: PIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'DH_check_params';
function DH_check(dh: PDH; codes: PIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'DH_check';
function DH_check_pub_key(dh: PDH; pub_key: PBIGNUM; codes: PIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'DH_check_pub_key';
function DH_generate_key(dh: PDH): TIdC_INT; cdecl external CLibCrypto name 'DH_generate_key';
function DH_compute_key(key: PIdAnsiChar; pub_key: PBIGNUM; dh: PDH): TIdC_INT; cdecl external CLibCrypto name 'DH_compute_key';
function DH_compute_key_padded(key: PIdAnsiChar; pub_key: PBIGNUM; dh: PDH): TIdC_INT; cdecl external CLibCrypto name 'DH_compute_key_padded';
function d2i_DHparams(a: PPDH; _in: PPIdAnsiChar; len: TIdC_LONG): PDH; cdecl external CLibCrypto name 'd2i_DHparams';
function i2d_DHparams(a: PDH; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_DHparams';
function d2i_DHxparams(a: PPDH; _in: PPIdAnsiChar; len: TIdC_LONG): PDH; cdecl external CLibCrypto name 'd2i_DHxparams';
function i2d_DHxparams(a: PDH; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_DHxparams';
function DHparams_print_fp(fp: PFILE; x: PDH): TIdC_INT; cdecl external CLibCrypto name 'DHparams_print_fp';
function DHparams_print(bp: PBIO; x: PDH): TIdC_INT; cdecl external CLibCrypto name 'DHparams_print';
function DH_get_1024_160: PDH; cdecl external CLibCrypto name 'DH_get_1024_160';
function DH_get_2048_224: PDH; cdecl external CLibCrypto name 'DH_get_2048_224';
function DH_get_2048_256: PDH; cdecl external CLibCrypto name 'DH_get_2048_256';
function DH_new_by_nid(nid: TIdC_INT): PDH; cdecl external CLibCrypto name 'DH_new_by_nid';
function DH_get_nid(dh: PDH): TIdC_INT; cdecl external CLibCrypto name 'DH_get_nid';
function DH_KDF_X9_42(_out: PIdAnsiChar; outlen: TIdC_SIZET; Z: PIdAnsiChar; Zlen: TIdC_SIZET; key_oid: PASN1_OBJECT; ukm: PIdAnsiChar; ukmlen: TIdC_SIZET; md: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'DH_KDF_X9_42';
procedure DH_get0_pqg(dh: PDH; p: PPBIGNUM; q: PPBIGNUM; g: PPBIGNUM); cdecl external CLibCrypto name 'DH_get0_pqg';
function DH_set0_pqg(dh: PDH; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TIdC_INT; cdecl external CLibCrypto name 'DH_set0_pqg';
procedure DH_get0_key(dh: PDH; pub_key: PPBIGNUM; priv_key: PPBIGNUM); cdecl external CLibCrypto name 'DH_get0_key';
function DH_set0_key(dh: PDH; pub_key: PBIGNUM; priv_key: PBIGNUM): TIdC_INT; cdecl external CLibCrypto name 'DH_set0_key';
function DH_get0_p(dh: PDH): PBIGNUM; cdecl external CLibCrypto name 'DH_get0_p';
function DH_get0_q(dh: PDH): PBIGNUM; cdecl external CLibCrypto name 'DH_get0_q';
function DH_get0_g(dh: PDH): PBIGNUM; cdecl external CLibCrypto name 'DH_get0_g';
function DH_get0_priv_key(dh: PDH): PBIGNUM; cdecl external CLibCrypto name 'DH_get0_priv_key';
function DH_get0_pub_key(dh: PDH): PBIGNUM; cdecl external CLibCrypto name 'DH_get0_pub_key';
procedure DH_clear_flags(dh: PDH; flags: TIdC_INT); cdecl external CLibCrypto name 'DH_clear_flags';
function DH_test_flags(dh: PDH; flags: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'DH_test_flags';
procedure DH_set_flags(dh: PDH; flags: TIdC_INT); cdecl external CLibCrypto name 'DH_set_flags';
function DH_get0_engine(d: PDH): PENGINE; cdecl external CLibCrypto name 'DH_get0_engine';
function DH_get_length(dh: PDH): TIdC_LONG; cdecl external CLibCrypto name 'DH_get_length';
function DH_set_length(dh: PDH; length: TIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'DH_set_length';
function DH_meth_new(name: PIdAnsiChar; flags: TIdC_INT): PDH_METHOD; cdecl external CLibCrypto name 'DH_meth_new';
procedure DH_meth_free(dhm: PDH_METHOD); cdecl external CLibCrypto name 'DH_meth_free';
function DH_meth_dup(dhm: PDH_METHOD): PDH_METHOD; cdecl external CLibCrypto name 'DH_meth_dup';
function DH_meth_get0_name(dhm: PDH_METHOD): PIdAnsiChar; cdecl external CLibCrypto name 'DH_meth_get0_name';
function DH_meth_set1_name(dhm: PDH_METHOD; name: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'DH_meth_set1_name';
function DH_meth_get_flags(dhm: PDH_METHOD): TIdC_INT; cdecl external CLibCrypto name 'DH_meth_get_flags';
function DH_meth_set_flags(dhm: PDH_METHOD; flags: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'DH_meth_set_flags';
function DH_meth_get0_app_data(dhm: PDH_METHOD): Pointer; cdecl external CLibCrypto name 'DH_meth_get0_app_data';
function DH_meth_set0_app_data(dhm: PDH_METHOD; app_data: Pointer): TIdC_INT; cdecl external CLibCrypto name 'DH_meth_set0_app_data';
function DH_meth_get_generate_key(dhm: PDH_METHOD): TDH_meth_get_generate_key_func_cb; cdecl external CLibCrypto name 'DH_meth_get_generate_key';
function DH_meth_set_generate_key(dhm: PDH_METHOD; generate_key: TDH_meth_get_generate_key_func_cb): TIdC_INT; cdecl external CLibCrypto name 'DH_meth_set_generate_key';
function DH_meth_get_compute_key(dhm: PDH_METHOD): TDH_meth_get_compute_key_func_cb; cdecl external CLibCrypto name 'DH_meth_get_compute_key';
function DH_meth_set_compute_key(dhm: PDH_METHOD; compute_key: TDH_meth_get_compute_key_func_cb): TIdC_INT; cdecl external CLibCrypto name 'DH_meth_set_compute_key';
function DH_meth_get_bn_mod_exp(dhm: PDH_METHOD): TDH_meth_get_bn_mod_exp_func_cb; cdecl external CLibCrypto name 'DH_meth_get_bn_mod_exp';
function DH_meth_set_bn_mod_exp(dhm: PDH_METHOD; bn_mod_exp: TDH_meth_get_bn_mod_exp_func_cb): TIdC_INT; cdecl external CLibCrypto name 'DH_meth_set_bn_mod_exp';
function DH_meth_get_init(dhm: PDH_METHOD): TDH_meth_get_generate_key_func_cb; cdecl external CLibCrypto name 'DH_meth_get_init';
function DH_meth_set_init(dhm: PDH_METHOD; init: TDH_meth_get_generate_key_func_cb): TIdC_INT; cdecl external CLibCrypto name 'DH_meth_set_init';
function DH_meth_get_finish(dhm: PDH_METHOD): TDH_meth_get_generate_key_func_cb; cdecl external CLibCrypto name 'DH_meth_get_finish';
function DH_meth_set_finish(dhm: PDH_METHOD; finish: TDH_meth_get_generate_key_func_cb): TIdC_INT; cdecl external CLibCrypto name 'DH_meth_set_finish';
function DH_meth_get_generate_params(dhm: PDH_METHOD): TDH_meth_get_generate_params_func_cb; cdecl external CLibCrypto name 'DH_meth_get_generate_params';
function DH_meth_set_generate_params(dhm: PDH_METHOD; generate_params: TDH_meth_get_generate_params_func_cb): TIdC_INT; cdecl external CLibCrypto name 'DH_meth_set_generate_params';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  EVP_PKEY_CTX_set_dh_paramgen_type_procname = 'EVP_PKEY_CTX_set_dh_paramgen_type';
  EVP_PKEY_CTX_set_dh_paramgen_type_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_dh_paramgen_gindex_procname = 'EVP_PKEY_CTX_set_dh_paramgen_gindex';
  EVP_PKEY_CTX_set_dh_paramgen_gindex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_dh_paramgen_seed_procname = 'EVP_PKEY_CTX_set_dh_paramgen_seed';
  EVP_PKEY_CTX_set_dh_paramgen_seed_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_dh_paramgen_prime_len_procname = 'EVP_PKEY_CTX_set_dh_paramgen_prime_len';
  EVP_PKEY_CTX_set_dh_paramgen_prime_len_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_dh_paramgen_subprime_len_procname = 'EVP_PKEY_CTX_set_dh_paramgen_subprime_len';
  EVP_PKEY_CTX_set_dh_paramgen_subprime_len_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_dh_paramgen_generator_procname = 'EVP_PKEY_CTX_set_dh_paramgen_generator';
  EVP_PKEY_CTX_set_dh_paramgen_generator_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_dh_nid_procname = 'EVP_PKEY_CTX_set_dh_nid';
  EVP_PKEY_CTX_set_dh_nid_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_dh_rfc5114_procname = 'EVP_PKEY_CTX_set_dh_rfc5114';
  EVP_PKEY_CTX_set_dh_rfc5114_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_dhx_rfc5114_procname = 'EVP_PKEY_CTX_set_dhx_rfc5114';
  EVP_PKEY_CTX_set_dhx_rfc5114_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_dh_pad_procname = 'EVP_PKEY_CTX_set_dh_pad';
  EVP_PKEY_CTX_set_dh_pad_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_dh_kdf_type_procname = 'EVP_PKEY_CTX_set_dh_kdf_type';
  EVP_PKEY_CTX_set_dh_kdf_type_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_get_dh_kdf_type_procname = 'EVP_PKEY_CTX_get_dh_kdf_type';
  EVP_PKEY_CTX_get_dh_kdf_type_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set0_dh_kdf_oid_procname = 'EVP_PKEY_CTX_set0_dh_kdf_oid';
  EVP_PKEY_CTX_set0_dh_kdf_oid_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_get0_dh_kdf_oid_procname = 'EVP_PKEY_CTX_get0_dh_kdf_oid';
  EVP_PKEY_CTX_get0_dh_kdf_oid_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_dh_kdf_md_procname = 'EVP_PKEY_CTX_set_dh_kdf_md';
  EVP_PKEY_CTX_set_dh_kdf_md_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_get_dh_kdf_md_procname = 'EVP_PKEY_CTX_get_dh_kdf_md';
  EVP_PKEY_CTX_get_dh_kdf_md_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_dh_kdf_outlen_procname = 'EVP_PKEY_CTX_set_dh_kdf_outlen';
  EVP_PKEY_CTX_set_dh_kdf_outlen_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_get_dh_kdf_outlen_procname = 'EVP_PKEY_CTX_get_dh_kdf_outlen';
  EVP_PKEY_CTX_get_dh_kdf_outlen_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set0_dh_kdf_ukm_procname = 'EVP_PKEY_CTX_set0_dh_kdf_ukm';
  EVP_PKEY_CTX_set0_dh_kdf_ukm_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_get0_dh_kdf_ukm_procname = 'EVP_PKEY_CTX_get0_dh_kdf_ukm';
  EVP_PKEY_CTX_get0_dh_kdf_ukm_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DHparams_it_procname = 'DHparams_it';
  DHparams_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  DHparams_dup_procname = 'DHparams_dup';
  DHparams_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DHparams_dup_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_OpenSSL_procname = 'DH_OpenSSL';
  DH_OpenSSL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_OpenSSL_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_set_default_method_procname = 'DH_set_default_method';
  DH_set_default_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_set_default_method_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_get_default_method_procname = 'DH_get_default_method';
  DH_get_default_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_get_default_method_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_set_method_procname = 'DH_set_method';
  DH_set_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_set_method_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_new_method_procname = 'DH_new_method';
  DH_new_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_new_method_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_new_procname = 'DH_new';
  DH_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_new_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_free_procname = 'DH_free';
  DH_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_free_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_up_ref_procname = 'DH_up_ref';
  DH_up_ref_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_up_ref_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_bits_procname = 'DH_bits';
  DH_bits_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_bits_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_size_procname = 'DH_size';
  DH_size_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_size_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_security_bits_procname = 'DH_security_bits';
  DH_security_bits_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_security_bits_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_set_ex_data_procname = 'DH_set_ex_data';
  DH_set_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_set_ex_data_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_get_ex_data_procname = 'DH_get_ex_data';
  DH_get_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_get_ex_data_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_generate_parameters_ex_procname = 'DH_generate_parameters_ex';
  DH_generate_parameters_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_generate_parameters_ex_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_check_params_ex_procname = 'DH_check_params_ex';
  DH_check_params_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  DH_check_params_ex_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_check_ex_procname = 'DH_check_ex';
  DH_check_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  DH_check_ex_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_check_pub_key_ex_procname = 'DH_check_pub_key_ex';
  DH_check_pub_key_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  DH_check_pub_key_ex_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_check_params_procname = 'DH_check_params';
  DH_check_params_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0d);
  DH_check_params_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_check_procname = 'DH_check';
  DH_check_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_check_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_check_pub_key_procname = 'DH_check_pub_key';
  DH_check_pub_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_check_pub_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_generate_key_procname = 'DH_generate_key';
  DH_generate_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_generate_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_compute_key_procname = 'DH_compute_key';
  DH_compute_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_compute_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_compute_key_padded_procname = 'DH_compute_key_padded';
  DH_compute_key_padded_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_compute_key_padded_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_DHparams_procname = 'd2i_DHparams';
  d2i_DHparams_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  d2i_DHparams_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_DHparams_procname = 'i2d_DHparams';
  i2d_DHparams_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2d_DHparams_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_DHxparams_procname = 'd2i_DHxparams';
  d2i_DHxparams_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  d2i_DHxparams_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_DHxparams_procname = 'i2d_DHxparams';
  i2d_DHxparams_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2d_DHxparams_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DHparams_print_fp_procname = 'DHparams_print_fp';
  DHparams_print_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DHparams_print_fp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DHparams_print_procname = 'DHparams_print';
  DHparams_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DHparams_print_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_get_1024_160_procname = 'DH_get_1024_160';
  DH_get_1024_160_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_get_1024_160_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_get_2048_224_procname = 'DH_get_2048_224';
  DH_get_2048_224_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_get_2048_224_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_get_2048_256_procname = 'DH_get_2048_256';
  DH_get_2048_256_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_get_2048_256_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_new_by_nid_procname = 'DH_new_by_nid';
  DH_new_by_nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  DH_new_by_nid_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_get_nid_procname = 'DH_get_nid';
  DH_get_nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  DH_get_nid_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_KDF_X9_42_procname = 'DH_KDF_X9_42';
  DH_KDF_X9_42_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_KDF_X9_42_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_get0_pqg_procname = 'DH_get0_pqg';
  DH_get0_pqg_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_get0_pqg_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_set0_pqg_procname = 'DH_set0_pqg';
  DH_set0_pqg_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_set0_pqg_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_get0_key_procname = 'DH_get0_key';
  DH_get0_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_get0_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_set0_key_procname = 'DH_set0_key';
  DH_set0_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_set0_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_get0_p_procname = 'DH_get0_p';
  DH_get0_p_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  DH_get0_p_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_get0_q_procname = 'DH_get0_q';
  DH_get0_q_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  DH_get0_q_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_get0_g_procname = 'DH_get0_g';
  DH_get0_g_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  DH_get0_g_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_get0_priv_key_procname = 'DH_get0_priv_key';
  DH_get0_priv_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  DH_get0_priv_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_get0_pub_key_procname = 'DH_get0_pub_key';
  DH_get0_pub_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  DH_get0_pub_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_clear_flags_procname = 'DH_clear_flags';
  DH_clear_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_clear_flags_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_test_flags_procname = 'DH_test_flags';
  DH_test_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_test_flags_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_set_flags_procname = 'DH_set_flags';
  DH_set_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_set_flags_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_get0_engine_procname = 'DH_get0_engine';
  DH_get0_engine_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_get0_engine_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_get_length_procname = 'DH_get_length';
  DH_get_length_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_get_length_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_set_length_procname = 'DH_set_length';
  DH_set_length_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_set_length_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_meth_new_procname = 'DH_meth_new';
  DH_meth_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_new_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_meth_free_procname = 'DH_meth_free';
  DH_meth_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_free_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_meth_dup_procname = 'DH_meth_dup';
  DH_meth_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_dup_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_meth_get0_name_procname = 'DH_meth_get0_name';
  DH_meth_get0_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_get0_name_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_meth_set1_name_procname = 'DH_meth_set1_name';
  DH_meth_set1_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_set1_name_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_meth_get_flags_procname = 'DH_meth_get_flags';
  DH_meth_get_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_get_flags_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_meth_set_flags_procname = 'DH_meth_set_flags';
  DH_meth_set_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_set_flags_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_meth_get0_app_data_procname = 'DH_meth_get0_app_data';
  DH_meth_get0_app_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_get0_app_data_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_meth_set0_app_data_procname = 'DH_meth_set0_app_data';
  DH_meth_set0_app_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_set0_app_data_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_meth_get_generate_key_procname = 'DH_meth_get_generate_key';
  DH_meth_get_generate_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_get_generate_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_meth_set_generate_key_procname = 'DH_meth_set_generate_key';
  DH_meth_set_generate_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_set_generate_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_meth_get_compute_key_procname = 'DH_meth_get_compute_key';
  DH_meth_get_compute_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_get_compute_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_meth_set_compute_key_procname = 'DH_meth_set_compute_key';
  DH_meth_set_compute_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_set_compute_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_meth_get_bn_mod_exp_procname = 'DH_meth_get_bn_mod_exp';
  DH_meth_get_bn_mod_exp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_get_bn_mod_exp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_meth_set_bn_mod_exp_procname = 'DH_meth_set_bn_mod_exp';
  DH_meth_set_bn_mod_exp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_set_bn_mod_exp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_meth_get_init_procname = 'DH_meth_get_init';
  DH_meth_get_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_get_init_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_meth_set_init_procname = 'DH_meth_set_init';
  DH_meth_set_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_set_init_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_meth_get_finish_procname = 'DH_meth_get_finish';
  DH_meth_get_finish_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_get_finish_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_meth_set_finish_procname = 'DH_meth_set_finish';
  DH_meth_set_finish_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_set_finish_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_meth_get_generate_params_procname = 'DH_meth_get_generate_params';
  DH_meth_get_generate_params_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_get_generate_params_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  DH_meth_set_generate_params_procname = 'DH_meth_set_generate_params';
  DH_meth_set_generate_params_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_set_generate_params_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_EVP_PKEY_CTX_set_dh_paramgen_type(ctx: PEVP_PKEY_CTX; typ: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_dh_paramgen_type_procname);
end;

function ERR_EVP_PKEY_CTX_set_dh_paramgen_gindex(ctx: PEVP_PKEY_CTX; gindex: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_dh_paramgen_gindex_procname);
end;

function ERR_EVP_PKEY_CTX_set_dh_paramgen_seed(ctx: PEVP_PKEY_CTX; seed: PIdAnsiChar; seedlen: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_dh_paramgen_seed_procname);
end;

function ERR_EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx: PEVP_PKEY_CTX; pbits: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_dh_paramgen_prime_len_procname);
end;

function ERR_EVP_PKEY_CTX_set_dh_paramgen_subprime_len(ctx: PEVP_PKEY_CTX; qlen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_dh_paramgen_subprime_len_procname);
end;

function ERR_EVP_PKEY_CTX_set_dh_paramgen_generator(ctx: PEVP_PKEY_CTX; gen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_dh_paramgen_generator_procname);
end;

function ERR_EVP_PKEY_CTX_set_dh_nid(ctx: PEVP_PKEY_CTX; nid: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_dh_nid_procname);
end;

function ERR_EVP_PKEY_CTX_set_dh_rfc5114(ctx: PEVP_PKEY_CTX; gen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_dh_rfc5114_procname);
end;

function ERR_EVP_PKEY_CTX_set_dhx_rfc5114(ctx: PEVP_PKEY_CTX; gen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_dhx_rfc5114_procname);
end;

function ERR_EVP_PKEY_CTX_set_dh_pad(ctx: PEVP_PKEY_CTX; pad: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_dh_pad_procname);
end;

function ERR_EVP_PKEY_CTX_set_dh_kdf_type(ctx: PEVP_PKEY_CTX; kdf: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_dh_kdf_type_procname);
end;

function ERR_EVP_PKEY_CTX_get_dh_kdf_type(ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_get_dh_kdf_type_procname);
end;

function ERR_EVP_PKEY_CTX_set0_dh_kdf_oid(ctx: PEVP_PKEY_CTX; oid: PASN1_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set0_dh_kdf_oid_procname);
end;

function ERR_EVP_PKEY_CTX_get0_dh_kdf_oid(ctx: PEVP_PKEY_CTX; oid: PPASN1_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_get0_dh_kdf_oid_procname);
end;

function ERR_EVP_PKEY_CTX_set_dh_kdf_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_dh_kdf_md_procname);
end;

function ERR_EVP_PKEY_CTX_get_dh_kdf_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_get_dh_kdf_md_procname);
end;

function ERR_EVP_PKEY_CTX_set_dh_kdf_outlen(ctx: PEVP_PKEY_CTX; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_dh_kdf_outlen_procname);
end;

function ERR_EVP_PKEY_CTX_get_dh_kdf_outlen(ctx: PEVP_PKEY_CTX; len: PIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_get_dh_kdf_outlen_procname);
end;

function ERR_EVP_PKEY_CTX_set0_dh_kdf_ukm(ctx: PEVP_PKEY_CTX; ukm: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set0_dh_kdf_ukm_procname);
end;

function ERR_EVP_PKEY_CTX_get0_dh_kdf_ukm(ctx: PEVP_PKEY_CTX; ukm: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_get0_dh_kdf_ukm_procname);
end;

function ERR_DHparams_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DHparams_it_procname);
end;

function ERR_DHparams_dup(a: PDH): PDH; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DHparams_dup_procname);
end;

function ERR_DH_OpenSSL: PDH_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_OpenSSL_procname);
end;

procedure ERR_DH_set_default_method(meth: PDH_METHOD); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_set_default_method_procname);
end;

function ERR_DH_get_default_method: PDH_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get_default_method_procname);
end;

function ERR_DH_set_method(dh: PDH; meth: PDH_METHOD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_set_method_procname);
end;

function ERR_DH_new_method(engine: PENGINE): PDH; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_new_method_procname);
end;

function ERR_DH_new: PDH; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_new_procname);
end;

procedure ERR_DH_free(dh: PDH); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_free_procname);
end;

function ERR_DH_up_ref(dh: PDH): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_up_ref_procname);
end;

function ERR_DH_bits(dh: PDH): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_bits_procname);
end;

function ERR_DH_size(dh: PDH): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_size_procname);
end;

function ERR_DH_security_bits(dh: PDH): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_security_bits_procname);
end;

function ERR_DH_set_ex_data(d: PDH; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_set_ex_data_procname);
end;

function ERR_DH_get_ex_data(d: PDH; idx: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get_ex_data_procname);
end;

function ERR_DH_generate_parameters_ex(dh: PDH; prime_len: TIdC_INT; generator: TIdC_INT; cb: PBN_GENCB): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_generate_parameters_ex_procname);
end;

function ERR_DH_check_params_ex(dh: PDH): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_check_params_ex_procname);
end;

function ERR_DH_check_ex(dh: PDH): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_check_ex_procname);
end;

function ERR_DH_check_pub_key_ex(dh: PDH; pub_key: PBIGNUM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_check_pub_key_ex_procname);
end;

function ERR_DH_check_params(dh: PDH; ret: PIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_check_params_procname);
end;

function ERR_DH_check(dh: PDH; codes: PIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_check_procname);
end;

function ERR_DH_check_pub_key(dh: PDH; pub_key: PBIGNUM; codes: PIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_check_pub_key_procname);
end;

function ERR_DH_generate_key(dh: PDH): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_generate_key_procname);
end;

function ERR_DH_compute_key(key: PIdAnsiChar; pub_key: PBIGNUM; dh: PDH): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_compute_key_procname);
end;

function ERR_DH_compute_key_padded(key: PIdAnsiChar; pub_key: PBIGNUM; dh: PDH): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_compute_key_padded_procname);
end;

function ERR_d2i_DHparams(a: PPDH; _in: PPIdAnsiChar; len: TIdC_LONG): PDH; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_DHparams_procname);
end;

function ERR_i2d_DHparams(a: PDH; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_DHparams_procname);
end;

function ERR_d2i_DHxparams(a: PPDH; _in: PPIdAnsiChar; len: TIdC_LONG): PDH; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_DHxparams_procname);
end;

function ERR_i2d_DHxparams(a: PDH; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_DHxparams_procname);
end;

function ERR_DHparams_print_fp(fp: PFILE; x: PDH): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DHparams_print_fp_procname);
end;

function ERR_DHparams_print(bp: PBIO; x: PDH): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DHparams_print_procname);
end;

function ERR_DH_get_1024_160: PDH; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get_1024_160_procname);
end;

function ERR_DH_get_2048_224: PDH; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get_2048_224_procname);
end;

function ERR_DH_get_2048_256: PDH; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get_2048_256_procname);
end;

function ERR_DH_new_by_nid(nid: TIdC_INT): PDH; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_new_by_nid_procname);
end;

function ERR_DH_get_nid(dh: PDH): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get_nid_procname);
end;

function ERR_DH_KDF_X9_42(_out: PIdAnsiChar; outlen: TIdC_SIZET; Z: PIdAnsiChar; Zlen: TIdC_SIZET; key_oid: PASN1_OBJECT; ukm: PIdAnsiChar; ukmlen: TIdC_SIZET; md: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_KDF_X9_42_procname);
end;

procedure ERR_DH_get0_pqg(dh: PDH; p: PPBIGNUM; q: PPBIGNUM; g: PPBIGNUM); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get0_pqg_procname);
end;

function ERR_DH_set0_pqg(dh: PDH; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_set0_pqg_procname);
end;

procedure ERR_DH_get0_key(dh: PDH; pub_key: PPBIGNUM; priv_key: PPBIGNUM); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get0_key_procname);
end;

function ERR_DH_set0_key(dh: PDH; pub_key: PBIGNUM; priv_key: PBIGNUM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_set0_key_procname);
end;

function ERR_DH_get0_p(dh: PDH): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get0_p_procname);
end;

function ERR_DH_get0_q(dh: PDH): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get0_q_procname);
end;

function ERR_DH_get0_g(dh: PDH): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get0_g_procname);
end;

function ERR_DH_get0_priv_key(dh: PDH): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get0_priv_key_procname);
end;

function ERR_DH_get0_pub_key(dh: PDH): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get0_pub_key_procname);
end;

procedure ERR_DH_clear_flags(dh: PDH; flags: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_clear_flags_procname);
end;

function ERR_DH_test_flags(dh: PDH; flags: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_test_flags_procname);
end;

procedure ERR_DH_set_flags(dh: PDH; flags: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_set_flags_procname);
end;

function ERR_DH_get0_engine(d: PDH): PENGINE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get0_engine_procname);
end;

function ERR_DH_get_length(dh: PDH): TIdC_LONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get_length_procname);
end;

function ERR_DH_set_length(dh: PDH; length: TIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_set_length_procname);
end;

function ERR_DH_meth_new(name: PIdAnsiChar; flags: TIdC_INT): PDH_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_new_procname);
end;

procedure ERR_DH_meth_free(dhm: PDH_METHOD); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_free_procname);
end;

function ERR_DH_meth_dup(dhm: PDH_METHOD): PDH_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_dup_procname);
end;

function ERR_DH_meth_get0_name(dhm: PDH_METHOD): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_get0_name_procname);
end;

function ERR_DH_meth_set1_name(dhm: PDH_METHOD; name: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_set1_name_procname);
end;

function ERR_DH_meth_get_flags(dhm: PDH_METHOD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_get_flags_procname);
end;

function ERR_DH_meth_set_flags(dhm: PDH_METHOD; flags: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_set_flags_procname);
end;

function ERR_DH_meth_get0_app_data(dhm: PDH_METHOD): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_get0_app_data_procname);
end;

function ERR_DH_meth_set0_app_data(dhm: PDH_METHOD; app_data: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_set0_app_data_procname);
end;

function ERR_DH_meth_get_generate_key(dhm: PDH_METHOD): TDH_meth_get_generate_key_func_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_get_generate_key_procname);
end;

function ERR_DH_meth_set_generate_key(dhm: PDH_METHOD; generate_key: TDH_meth_get_generate_key_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_set_generate_key_procname);
end;

function ERR_DH_meth_get_compute_key(dhm: PDH_METHOD): TDH_meth_get_compute_key_func_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_get_compute_key_procname);
end;

function ERR_DH_meth_set_compute_key(dhm: PDH_METHOD; compute_key: TDH_meth_get_compute_key_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_set_compute_key_procname);
end;

function ERR_DH_meth_get_bn_mod_exp(dhm: PDH_METHOD): TDH_meth_get_bn_mod_exp_func_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_get_bn_mod_exp_procname);
end;

function ERR_DH_meth_set_bn_mod_exp(dhm: PDH_METHOD; bn_mod_exp: TDH_meth_get_bn_mod_exp_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_set_bn_mod_exp_procname);
end;

function ERR_DH_meth_get_init(dhm: PDH_METHOD): TDH_meth_get_generate_key_func_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_get_init_procname);
end;

function ERR_DH_meth_set_init(dhm: PDH_METHOD; init: TDH_meth_get_generate_key_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_set_init_procname);
end;

function ERR_DH_meth_get_finish(dhm: PDH_METHOD): TDH_meth_get_generate_key_func_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_get_finish_procname);
end;

function ERR_DH_meth_set_finish(dhm: PDH_METHOD; finish: TDH_meth_get_generate_key_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_set_finish_procname);
end;

function ERR_DH_meth_get_generate_params(dhm: PDH_METHOD): TDH_meth_get_generate_params_func_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_get_generate_params_procname);
end;

function ERR_DH_meth_set_generate_params(dhm: PDH_METHOD; generate_params: TDH_meth_get_generate_params_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_set_generate_params_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  EVP_PKEY_CTX_set_dh_paramgen_type := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_dh_paramgen_type_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_dh_paramgen_type);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_dh_paramgen_type_allownil)}
    EVP_PKEY_CTX_set_dh_paramgen_type := ERR_EVP_PKEY_CTX_set_dh_paramgen_type;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dh_paramgen_type_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_dh_paramgen_type_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_dh_paramgen_type)}
      EVP_PKEY_CTX_set_dh_paramgen_type := FC_EVP_PKEY_CTX_set_dh_paramgen_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dh_paramgen_type_removed)}
    if EVP_PKEY_CTX_set_dh_paramgen_type_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_dh_paramgen_type)}
      EVP_PKEY_CTX_set_dh_paramgen_type := _EVP_PKEY_CTX_set_dh_paramgen_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_dh_paramgen_type_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_dh_paramgen_type');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_dh_paramgen_gindex := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_dh_paramgen_gindex_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_dh_paramgen_gindex);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_dh_paramgen_gindex_allownil)}
    EVP_PKEY_CTX_set_dh_paramgen_gindex := ERR_EVP_PKEY_CTX_set_dh_paramgen_gindex;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dh_paramgen_gindex_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_dh_paramgen_gindex_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_dh_paramgen_gindex)}
      EVP_PKEY_CTX_set_dh_paramgen_gindex := FC_EVP_PKEY_CTX_set_dh_paramgen_gindex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dh_paramgen_gindex_removed)}
    if EVP_PKEY_CTX_set_dh_paramgen_gindex_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_dh_paramgen_gindex)}
      EVP_PKEY_CTX_set_dh_paramgen_gindex := _EVP_PKEY_CTX_set_dh_paramgen_gindex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_dh_paramgen_gindex_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_dh_paramgen_gindex');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_dh_paramgen_seed := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_dh_paramgen_seed_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_dh_paramgen_seed);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_dh_paramgen_seed_allownil)}
    EVP_PKEY_CTX_set_dh_paramgen_seed := ERR_EVP_PKEY_CTX_set_dh_paramgen_seed;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dh_paramgen_seed_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_dh_paramgen_seed_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_dh_paramgen_seed)}
      EVP_PKEY_CTX_set_dh_paramgen_seed := FC_EVP_PKEY_CTX_set_dh_paramgen_seed;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dh_paramgen_seed_removed)}
    if EVP_PKEY_CTX_set_dh_paramgen_seed_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_dh_paramgen_seed)}
      EVP_PKEY_CTX_set_dh_paramgen_seed := _EVP_PKEY_CTX_set_dh_paramgen_seed;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_dh_paramgen_seed_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_dh_paramgen_seed');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_dh_paramgen_prime_len := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_dh_paramgen_prime_len_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_dh_paramgen_prime_len);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_dh_paramgen_prime_len_allownil)}
    EVP_PKEY_CTX_set_dh_paramgen_prime_len := ERR_EVP_PKEY_CTX_set_dh_paramgen_prime_len;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dh_paramgen_prime_len_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_dh_paramgen_prime_len_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_dh_paramgen_prime_len)}
      EVP_PKEY_CTX_set_dh_paramgen_prime_len := FC_EVP_PKEY_CTX_set_dh_paramgen_prime_len;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dh_paramgen_prime_len_removed)}
    if EVP_PKEY_CTX_set_dh_paramgen_prime_len_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_dh_paramgen_prime_len)}
      EVP_PKEY_CTX_set_dh_paramgen_prime_len := _EVP_PKEY_CTX_set_dh_paramgen_prime_len;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_dh_paramgen_prime_len_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_dh_paramgen_prime_len');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_dh_paramgen_subprime_len := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_dh_paramgen_subprime_len_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_dh_paramgen_subprime_len);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_dh_paramgen_subprime_len_allownil)}
    EVP_PKEY_CTX_set_dh_paramgen_subprime_len := ERR_EVP_PKEY_CTX_set_dh_paramgen_subprime_len;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dh_paramgen_subprime_len_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_dh_paramgen_subprime_len_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_dh_paramgen_subprime_len)}
      EVP_PKEY_CTX_set_dh_paramgen_subprime_len := FC_EVP_PKEY_CTX_set_dh_paramgen_subprime_len;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dh_paramgen_subprime_len_removed)}
    if EVP_PKEY_CTX_set_dh_paramgen_subprime_len_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_dh_paramgen_subprime_len)}
      EVP_PKEY_CTX_set_dh_paramgen_subprime_len := _EVP_PKEY_CTX_set_dh_paramgen_subprime_len;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_dh_paramgen_subprime_len_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_dh_paramgen_subprime_len');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_dh_paramgen_generator := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_dh_paramgen_generator_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_dh_paramgen_generator);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_dh_paramgen_generator_allownil)}
    EVP_PKEY_CTX_set_dh_paramgen_generator := ERR_EVP_PKEY_CTX_set_dh_paramgen_generator;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dh_paramgen_generator_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_dh_paramgen_generator_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_dh_paramgen_generator)}
      EVP_PKEY_CTX_set_dh_paramgen_generator := FC_EVP_PKEY_CTX_set_dh_paramgen_generator;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dh_paramgen_generator_removed)}
    if EVP_PKEY_CTX_set_dh_paramgen_generator_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_dh_paramgen_generator)}
      EVP_PKEY_CTX_set_dh_paramgen_generator := _EVP_PKEY_CTX_set_dh_paramgen_generator;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_dh_paramgen_generator_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_dh_paramgen_generator');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_dh_nid := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_dh_nid_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_dh_nid);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_dh_nid_allownil)}
    EVP_PKEY_CTX_set_dh_nid := ERR_EVP_PKEY_CTX_set_dh_nid;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dh_nid_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_dh_nid_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_dh_nid)}
      EVP_PKEY_CTX_set_dh_nid := FC_EVP_PKEY_CTX_set_dh_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dh_nid_removed)}
    if EVP_PKEY_CTX_set_dh_nid_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_dh_nid)}
      EVP_PKEY_CTX_set_dh_nid := _EVP_PKEY_CTX_set_dh_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_dh_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_dh_nid');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_dh_rfc5114 := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_dh_rfc5114_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_dh_rfc5114);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_dh_rfc5114_allownil)}
    EVP_PKEY_CTX_set_dh_rfc5114 := ERR_EVP_PKEY_CTX_set_dh_rfc5114;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dh_rfc5114_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_dh_rfc5114_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_dh_rfc5114)}
      EVP_PKEY_CTX_set_dh_rfc5114 := FC_EVP_PKEY_CTX_set_dh_rfc5114;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dh_rfc5114_removed)}
    if EVP_PKEY_CTX_set_dh_rfc5114_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_dh_rfc5114)}
      EVP_PKEY_CTX_set_dh_rfc5114 := _EVP_PKEY_CTX_set_dh_rfc5114;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_dh_rfc5114_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_dh_rfc5114');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_dhx_rfc5114 := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_dhx_rfc5114_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_dhx_rfc5114);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_dhx_rfc5114_allownil)}
    EVP_PKEY_CTX_set_dhx_rfc5114 := ERR_EVP_PKEY_CTX_set_dhx_rfc5114;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dhx_rfc5114_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_dhx_rfc5114_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_dhx_rfc5114)}
      EVP_PKEY_CTX_set_dhx_rfc5114 := FC_EVP_PKEY_CTX_set_dhx_rfc5114;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dhx_rfc5114_removed)}
    if EVP_PKEY_CTX_set_dhx_rfc5114_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_dhx_rfc5114)}
      EVP_PKEY_CTX_set_dhx_rfc5114 := _EVP_PKEY_CTX_set_dhx_rfc5114;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_dhx_rfc5114_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_dhx_rfc5114');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_dh_pad := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_dh_pad_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_dh_pad);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_dh_pad_allownil)}
    EVP_PKEY_CTX_set_dh_pad := ERR_EVP_PKEY_CTX_set_dh_pad;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dh_pad_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_dh_pad_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_dh_pad)}
      EVP_PKEY_CTX_set_dh_pad := FC_EVP_PKEY_CTX_set_dh_pad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dh_pad_removed)}
    if EVP_PKEY_CTX_set_dh_pad_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_dh_pad)}
      EVP_PKEY_CTX_set_dh_pad := _EVP_PKEY_CTX_set_dh_pad;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_dh_pad_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_dh_pad');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_dh_kdf_type := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_dh_kdf_type_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_dh_kdf_type);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_dh_kdf_type_allownil)}
    EVP_PKEY_CTX_set_dh_kdf_type := ERR_EVP_PKEY_CTX_set_dh_kdf_type;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dh_kdf_type_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_dh_kdf_type_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_dh_kdf_type)}
      EVP_PKEY_CTX_set_dh_kdf_type := FC_EVP_PKEY_CTX_set_dh_kdf_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dh_kdf_type_removed)}
    if EVP_PKEY_CTX_set_dh_kdf_type_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_dh_kdf_type)}
      EVP_PKEY_CTX_set_dh_kdf_type := _EVP_PKEY_CTX_set_dh_kdf_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_dh_kdf_type_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_dh_kdf_type');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_get_dh_kdf_type := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_get_dh_kdf_type_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_get_dh_kdf_type);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_get_dh_kdf_type_allownil)}
    EVP_PKEY_CTX_get_dh_kdf_type := ERR_EVP_PKEY_CTX_get_dh_kdf_type;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_dh_kdf_type_introduced)}
    if LibVersion < EVP_PKEY_CTX_get_dh_kdf_type_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_get_dh_kdf_type)}
      EVP_PKEY_CTX_get_dh_kdf_type := FC_EVP_PKEY_CTX_get_dh_kdf_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_dh_kdf_type_removed)}
    if EVP_PKEY_CTX_get_dh_kdf_type_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_get_dh_kdf_type)}
      EVP_PKEY_CTX_get_dh_kdf_type := _EVP_PKEY_CTX_get_dh_kdf_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_get_dh_kdf_type_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_get_dh_kdf_type');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set0_dh_kdf_oid := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set0_dh_kdf_oid_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set0_dh_kdf_oid);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set0_dh_kdf_oid_allownil)}
    EVP_PKEY_CTX_set0_dh_kdf_oid := ERR_EVP_PKEY_CTX_set0_dh_kdf_oid;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set0_dh_kdf_oid_introduced)}
    if LibVersion < EVP_PKEY_CTX_set0_dh_kdf_oid_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set0_dh_kdf_oid)}
      EVP_PKEY_CTX_set0_dh_kdf_oid := FC_EVP_PKEY_CTX_set0_dh_kdf_oid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set0_dh_kdf_oid_removed)}
    if EVP_PKEY_CTX_set0_dh_kdf_oid_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set0_dh_kdf_oid)}
      EVP_PKEY_CTX_set0_dh_kdf_oid := _EVP_PKEY_CTX_set0_dh_kdf_oid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set0_dh_kdf_oid_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set0_dh_kdf_oid');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_get0_dh_kdf_oid := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_get0_dh_kdf_oid_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_get0_dh_kdf_oid);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_get0_dh_kdf_oid_allownil)}
    EVP_PKEY_CTX_get0_dh_kdf_oid := ERR_EVP_PKEY_CTX_get0_dh_kdf_oid;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get0_dh_kdf_oid_introduced)}
    if LibVersion < EVP_PKEY_CTX_get0_dh_kdf_oid_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_get0_dh_kdf_oid)}
      EVP_PKEY_CTX_get0_dh_kdf_oid := FC_EVP_PKEY_CTX_get0_dh_kdf_oid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get0_dh_kdf_oid_removed)}
    if EVP_PKEY_CTX_get0_dh_kdf_oid_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_get0_dh_kdf_oid)}
      EVP_PKEY_CTX_get0_dh_kdf_oid := _EVP_PKEY_CTX_get0_dh_kdf_oid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_get0_dh_kdf_oid_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_get0_dh_kdf_oid');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_dh_kdf_md := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_dh_kdf_md_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_dh_kdf_md);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_dh_kdf_md_allownil)}
    EVP_PKEY_CTX_set_dh_kdf_md := ERR_EVP_PKEY_CTX_set_dh_kdf_md;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dh_kdf_md_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_dh_kdf_md_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_dh_kdf_md)}
      EVP_PKEY_CTX_set_dh_kdf_md := FC_EVP_PKEY_CTX_set_dh_kdf_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dh_kdf_md_removed)}
    if EVP_PKEY_CTX_set_dh_kdf_md_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_dh_kdf_md)}
      EVP_PKEY_CTX_set_dh_kdf_md := _EVP_PKEY_CTX_set_dh_kdf_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_dh_kdf_md_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_dh_kdf_md');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_get_dh_kdf_md := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_get_dh_kdf_md_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_get_dh_kdf_md);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_get_dh_kdf_md_allownil)}
    EVP_PKEY_CTX_get_dh_kdf_md := ERR_EVP_PKEY_CTX_get_dh_kdf_md;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_dh_kdf_md_introduced)}
    if LibVersion < EVP_PKEY_CTX_get_dh_kdf_md_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_get_dh_kdf_md)}
      EVP_PKEY_CTX_get_dh_kdf_md := FC_EVP_PKEY_CTX_get_dh_kdf_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_dh_kdf_md_removed)}
    if EVP_PKEY_CTX_get_dh_kdf_md_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_get_dh_kdf_md)}
      EVP_PKEY_CTX_get_dh_kdf_md := _EVP_PKEY_CTX_get_dh_kdf_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_get_dh_kdf_md_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_get_dh_kdf_md');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_dh_kdf_outlen := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_dh_kdf_outlen_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_dh_kdf_outlen);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_dh_kdf_outlen_allownil)}
    EVP_PKEY_CTX_set_dh_kdf_outlen := ERR_EVP_PKEY_CTX_set_dh_kdf_outlen;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dh_kdf_outlen_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_dh_kdf_outlen_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_dh_kdf_outlen)}
      EVP_PKEY_CTX_set_dh_kdf_outlen := FC_EVP_PKEY_CTX_set_dh_kdf_outlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_dh_kdf_outlen_removed)}
    if EVP_PKEY_CTX_set_dh_kdf_outlen_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_dh_kdf_outlen)}
      EVP_PKEY_CTX_set_dh_kdf_outlen := _EVP_PKEY_CTX_set_dh_kdf_outlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_dh_kdf_outlen_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_dh_kdf_outlen');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_get_dh_kdf_outlen := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_get_dh_kdf_outlen_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_get_dh_kdf_outlen);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_get_dh_kdf_outlen_allownil)}
    EVP_PKEY_CTX_get_dh_kdf_outlen := ERR_EVP_PKEY_CTX_get_dh_kdf_outlen;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_dh_kdf_outlen_introduced)}
    if LibVersion < EVP_PKEY_CTX_get_dh_kdf_outlen_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_get_dh_kdf_outlen)}
      EVP_PKEY_CTX_get_dh_kdf_outlen := FC_EVP_PKEY_CTX_get_dh_kdf_outlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_dh_kdf_outlen_removed)}
    if EVP_PKEY_CTX_get_dh_kdf_outlen_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_get_dh_kdf_outlen)}
      EVP_PKEY_CTX_get_dh_kdf_outlen := _EVP_PKEY_CTX_get_dh_kdf_outlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_get_dh_kdf_outlen_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_get_dh_kdf_outlen');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set0_dh_kdf_ukm := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set0_dh_kdf_ukm_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set0_dh_kdf_ukm);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set0_dh_kdf_ukm_allownil)}
    EVP_PKEY_CTX_set0_dh_kdf_ukm := ERR_EVP_PKEY_CTX_set0_dh_kdf_ukm;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set0_dh_kdf_ukm_introduced)}
    if LibVersion < EVP_PKEY_CTX_set0_dh_kdf_ukm_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set0_dh_kdf_ukm)}
      EVP_PKEY_CTX_set0_dh_kdf_ukm := FC_EVP_PKEY_CTX_set0_dh_kdf_ukm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set0_dh_kdf_ukm_removed)}
    if EVP_PKEY_CTX_set0_dh_kdf_ukm_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set0_dh_kdf_ukm)}
      EVP_PKEY_CTX_set0_dh_kdf_ukm := _EVP_PKEY_CTX_set0_dh_kdf_ukm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set0_dh_kdf_ukm_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set0_dh_kdf_ukm');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_get0_dh_kdf_ukm := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_get0_dh_kdf_ukm_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_get0_dh_kdf_ukm);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_get0_dh_kdf_ukm_allownil)}
    EVP_PKEY_CTX_get0_dh_kdf_ukm := ERR_EVP_PKEY_CTX_get0_dh_kdf_ukm;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get0_dh_kdf_ukm_introduced)}
    if LibVersion < EVP_PKEY_CTX_get0_dh_kdf_ukm_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_get0_dh_kdf_ukm)}
      EVP_PKEY_CTX_get0_dh_kdf_ukm := FC_EVP_PKEY_CTX_get0_dh_kdf_ukm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get0_dh_kdf_ukm_removed)}
    if EVP_PKEY_CTX_get0_dh_kdf_ukm_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_get0_dh_kdf_ukm)}
      EVP_PKEY_CTX_get0_dh_kdf_ukm := _EVP_PKEY_CTX_get0_dh_kdf_ukm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_get0_dh_kdf_ukm_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_get0_dh_kdf_ukm');
    {$ifend}
  end;
  
  DHparams_it := LoadLibFunction(ADllHandle, DHparams_it_procname);
  FuncLoadError := not assigned(DHparams_it);
  if FuncLoadError then
  begin
    {$if not defined(DHparams_it_allownil)}
    DHparams_it := ERR_DHparams_it;
    {$ifend}
    {$if declared(DHparams_it_introduced)}
    if LibVersion < DHparams_it_introduced then
    begin
      {$if declared(FC_DHparams_it)}
      DHparams_it := FC_DHparams_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DHparams_it_removed)}
    if DHparams_it_removed <= LibVersion then
    begin
      {$if declared(_DHparams_it)}
      DHparams_it := _DHparams_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DHparams_it_allownil)}
    if FuncLoadError then
      AFailed.Add('DHparams_it');
    {$ifend}
  end;
  
  DHparams_dup := LoadLibFunction(ADllHandle, DHparams_dup_procname);
  FuncLoadError := not assigned(DHparams_dup);
  if FuncLoadError then
  begin
    {$if not defined(DHparams_dup_allownil)}
    DHparams_dup := ERR_DHparams_dup;
    {$ifend}
    {$if declared(DHparams_dup_introduced)}
    if LibVersion < DHparams_dup_introduced then
    begin
      {$if declared(FC_DHparams_dup)}
      DHparams_dup := FC_DHparams_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DHparams_dup_removed)}
    if DHparams_dup_removed <= LibVersion then
    begin
      {$if declared(_DHparams_dup)}
      DHparams_dup := _DHparams_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DHparams_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('DHparams_dup');
    {$ifend}
  end;
  
  DH_OpenSSL := LoadLibFunction(ADllHandle, DH_OpenSSL_procname);
  FuncLoadError := not assigned(DH_OpenSSL);
  if FuncLoadError then
  begin
    {$if not defined(DH_OpenSSL_allownil)}
    DH_OpenSSL := ERR_DH_OpenSSL;
    {$ifend}
    {$if declared(DH_OpenSSL_introduced)}
    if LibVersion < DH_OpenSSL_introduced then
    begin
      {$if declared(FC_DH_OpenSSL)}
      DH_OpenSSL := FC_DH_OpenSSL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_OpenSSL_removed)}
    if DH_OpenSSL_removed <= LibVersion then
    begin
      {$if declared(_DH_OpenSSL)}
      DH_OpenSSL := _DH_OpenSSL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_OpenSSL_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_OpenSSL');
    {$ifend}
  end;
  
  DH_set_default_method := LoadLibFunction(ADllHandle, DH_set_default_method_procname);
  FuncLoadError := not assigned(DH_set_default_method);
  if FuncLoadError then
  begin
    {$if not defined(DH_set_default_method_allownil)}
    DH_set_default_method := ERR_DH_set_default_method;
    {$ifend}
    {$if declared(DH_set_default_method_introduced)}
    if LibVersion < DH_set_default_method_introduced then
    begin
      {$if declared(FC_DH_set_default_method)}
      DH_set_default_method := FC_DH_set_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_set_default_method_removed)}
    if DH_set_default_method_removed <= LibVersion then
    begin
      {$if declared(_DH_set_default_method)}
      DH_set_default_method := _DH_set_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_set_default_method_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_set_default_method');
    {$ifend}
  end;
  
  DH_get_default_method := LoadLibFunction(ADllHandle, DH_get_default_method_procname);
  FuncLoadError := not assigned(DH_get_default_method);
  if FuncLoadError then
  begin
    {$if not defined(DH_get_default_method_allownil)}
    DH_get_default_method := ERR_DH_get_default_method;
    {$ifend}
    {$if declared(DH_get_default_method_introduced)}
    if LibVersion < DH_get_default_method_introduced then
    begin
      {$if declared(FC_DH_get_default_method)}
      DH_get_default_method := FC_DH_get_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_get_default_method_removed)}
    if DH_get_default_method_removed <= LibVersion then
    begin
      {$if declared(_DH_get_default_method)}
      DH_get_default_method := _DH_get_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_get_default_method_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_get_default_method');
    {$ifend}
  end;
  
  DH_set_method := LoadLibFunction(ADllHandle, DH_set_method_procname);
  FuncLoadError := not assigned(DH_set_method);
  if FuncLoadError then
  begin
    {$if not defined(DH_set_method_allownil)}
    DH_set_method := ERR_DH_set_method;
    {$ifend}
    {$if declared(DH_set_method_introduced)}
    if LibVersion < DH_set_method_introduced then
    begin
      {$if declared(FC_DH_set_method)}
      DH_set_method := FC_DH_set_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_set_method_removed)}
    if DH_set_method_removed <= LibVersion then
    begin
      {$if declared(_DH_set_method)}
      DH_set_method := _DH_set_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_set_method_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_set_method');
    {$ifend}
  end;
  
  DH_new_method := LoadLibFunction(ADllHandle, DH_new_method_procname);
  FuncLoadError := not assigned(DH_new_method);
  if FuncLoadError then
  begin
    {$if not defined(DH_new_method_allownil)}
    DH_new_method := ERR_DH_new_method;
    {$ifend}
    {$if declared(DH_new_method_introduced)}
    if LibVersion < DH_new_method_introduced then
    begin
      {$if declared(FC_DH_new_method)}
      DH_new_method := FC_DH_new_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_new_method_removed)}
    if DH_new_method_removed <= LibVersion then
    begin
      {$if declared(_DH_new_method)}
      DH_new_method := _DH_new_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_new_method_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_new_method');
    {$ifend}
  end;
  
  DH_new := LoadLibFunction(ADllHandle, DH_new_procname);
  FuncLoadError := not assigned(DH_new);
  if FuncLoadError then
  begin
    {$if not defined(DH_new_allownil)}
    DH_new := ERR_DH_new;
    {$ifend}
    {$if declared(DH_new_introduced)}
    if LibVersion < DH_new_introduced then
    begin
      {$if declared(FC_DH_new)}
      DH_new := FC_DH_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_new_removed)}
    if DH_new_removed <= LibVersion then
    begin
      {$if declared(_DH_new)}
      DH_new := _DH_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_new_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_new');
    {$ifend}
  end;
  
  DH_free := LoadLibFunction(ADllHandle, DH_free_procname);
  FuncLoadError := not assigned(DH_free);
  if FuncLoadError then
  begin
    {$if not defined(DH_free_allownil)}
    DH_free := ERR_DH_free;
    {$ifend}
    {$if declared(DH_free_introduced)}
    if LibVersion < DH_free_introduced then
    begin
      {$if declared(FC_DH_free)}
      DH_free := FC_DH_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_free_removed)}
    if DH_free_removed <= LibVersion then
    begin
      {$if declared(_DH_free)}
      DH_free := _DH_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_free_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_free');
    {$ifend}
  end;
  
  DH_up_ref := LoadLibFunction(ADllHandle, DH_up_ref_procname);
  FuncLoadError := not assigned(DH_up_ref);
  if FuncLoadError then
  begin
    {$if not defined(DH_up_ref_allownil)}
    DH_up_ref := ERR_DH_up_ref;
    {$ifend}
    {$if declared(DH_up_ref_introduced)}
    if LibVersion < DH_up_ref_introduced then
    begin
      {$if declared(FC_DH_up_ref)}
      DH_up_ref := FC_DH_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_up_ref_removed)}
    if DH_up_ref_removed <= LibVersion then
    begin
      {$if declared(_DH_up_ref)}
      DH_up_ref := _DH_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_up_ref_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_up_ref');
    {$ifend}
  end;
  
  DH_bits := LoadLibFunction(ADllHandle, DH_bits_procname);
  FuncLoadError := not assigned(DH_bits);
  if FuncLoadError then
  begin
    {$if not defined(DH_bits_allownil)}
    DH_bits := ERR_DH_bits;
    {$ifend}
    {$if declared(DH_bits_introduced)}
    if LibVersion < DH_bits_introduced then
    begin
      {$if declared(FC_DH_bits)}
      DH_bits := FC_DH_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_bits_removed)}
    if DH_bits_removed <= LibVersion then
    begin
      {$if declared(_DH_bits)}
      DH_bits := _DH_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_bits_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_bits');
    {$ifend}
  end;
  
  DH_size := LoadLibFunction(ADllHandle, DH_size_procname);
  FuncLoadError := not assigned(DH_size);
  if FuncLoadError then
  begin
    {$if not defined(DH_size_allownil)}
    DH_size := ERR_DH_size;
    {$ifend}
    {$if declared(DH_size_introduced)}
    if LibVersion < DH_size_introduced then
    begin
      {$if declared(FC_DH_size)}
      DH_size := FC_DH_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_size_removed)}
    if DH_size_removed <= LibVersion then
    begin
      {$if declared(_DH_size)}
      DH_size := _DH_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_size_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_size');
    {$ifend}
  end;
  
  DH_security_bits := LoadLibFunction(ADllHandle, DH_security_bits_procname);
  FuncLoadError := not assigned(DH_security_bits);
  if FuncLoadError then
  begin
    {$if not defined(DH_security_bits_allownil)}
    DH_security_bits := ERR_DH_security_bits;
    {$ifend}
    {$if declared(DH_security_bits_introduced)}
    if LibVersion < DH_security_bits_introduced then
    begin
      {$if declared(FC_DH_security_bits)}
      DH_security_bits := FC_DH_security_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_security_bits_removed)}
    if DH_security_bits_removed <= LibVersion then
    begin
      {$if declared(_DH_security_bits)}
      DH_security_bits := _DH_security_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_security_bits_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_security_bits');
    {$ifend}
  end;
  
  DH_set_ex_data := LoadLibFunction(ADllHandle, DH_set_ex_data_procname);
  FuncLoadError := not assigned(DH_set_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(DH_set_ex_data_allownil)}
    DH_set_ex_data := ERR_DH_set_ex_data;
    {$ifend}
    {$if declared(DH_set_ex_data_introduced)}
    if LibVersion < DH_set_ex_data_introduced then
    begin
      {$if declared(FC_DH_set_ex_data)}
      DH_set_ex_data := FC_DH_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_set_ex_data_removed)}
    if DH_set_ex_data_removed <= LibVersion then
    begin
      {$if declared(_DH_set_ex_data)}
      DH_set_ex_data := _DH_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_set_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_set_ex_data');
    {$ifend}
  end;
  
  DH_get_ex_data := LoadLibFunction(ADllHandle, DH_get_ex_data_procname);
  FuncLoadError := not assigned(DH_get_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(DH_get_ex_data_allownil)}
    DH_get_ex_data := ERR_DH_get_ex_data;
    {$ifend}
    {$if declared(DH_get_ex_data_introduced)}
    if LibVersion < DH_get_ex_data_introduced then
    begin
      {$if declared(FC_DH_get_ex_data)}
      DH_get_ex_data := FC_DH_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_get_ex_data_removed)}
    if DH_get_ex_data_removed <= LibVersion then
    begin
      {$if declared(_DH_get_ex_data)}
      DH_get_ex_data := _DH_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_get_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_get_ex_data');
    {$ifend}
  end;
  
  DH_generate_parameters_ex := LoadLibFunction(ADllHandle, DH_generate_parameters_ex_procname);
  FuncLoadError := not assigned(DH_generate_parameters_ex);
  if FuncLoadError then
  begin
    {$if not defined(DH_generate_parameters_ex_allownil)}
    DH_generate_parameters_ex := ERR_DH_generate_parameters_ex;
    {$ifend}
    {$if declared(DH_generate_parameters_ex_introduced)}
    if LibVersion < DH_generate_parameters_ex_introduced then
    begin
      {$if declared(FC_DH_generate_parameters_ex)}
      DH_generate_parameters_ex := FC_DH_generate_parameters_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_generate_parameters_ex_removed)}
    if DH_generate_parameters_ex_removed <= LibVersion then
    begin
      {$if declared(_DH_generate_parameters_ex)}
      DH_generate_parameters_ex := _DH_generate_parameters_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_generate_parameters_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_generate_parameters_ex');
    {$ifend}
  end;
  
  DH_check_params_ex := LoadLibFunction(ADllHandle, DH_check_params_ex_procname);
  FuncLoadError := not assigned(DH_check_params_ex);
  if FuncLoadError then
  begin
    {$if not defined(DH_check_params_ex_allownil)}
    DH_check_params_ex := ERR_DH_check_params_ex;
    {$ifend}
    {$if declared(DH_check_params_ex_introduced)}
    if LibVersion < DH_check_params_ex_introduced then
    begin
      {$if declared(FC_DH_check_params_ex)}
      DH_check_params_ex := FC_DH_check_params_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_check_params_ex_removed)}
    if DH_check_params_ex_removed <= LibVersion then
    begin
      {$if declared(_DH_check_params_ex)}
      DH_check_params_ex := _DH_check_params_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_check_params_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_check_params_ex');
    {$ifend}
  end;
  
  DH_check_ex := LoadLibFunction(ADllHandle, DH_check_ex_procname);
  FuncLoadError := not assigned(DH_check_ex);
  if FuncLoadError then
  begin
    {$if not defined(DH_check_ex_allownil)}
    DH_check_ex := ERR_DH_check_ex;
    {$ifend}
    {$if declared(DH_check_ex_introduced)}
    if LibVersion < DH_check_ex_introduced then
    begin
      {$if declared(FC_DH_check_ex)}
      DH_check_ex := FC_DH_check_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_check_ex_removed)}
    if DH_check_ex_removed <= LibVersion then
    begin
      {$if declared(_DH_check_ex)}
      DH_check_ex := _DH_check_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_check_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_check_ex');
    {$ifend}
  end;
  
  DH_check_pub_key_ex := LoadLibFunction(ADllHandle, DH_check_pub_key_ex_procname);
  FuncLoadError := not assigned(DH_check_pub_key_ex);
  if FuncLoadError then
  begin
    {$if not defined(DH_check_pub_key_ex_allownil)}
    DH_check_pub_key_ex := ERR_DH_check_pub_key_ex;
    {$ifend}
    {$if declared(DH_check_pub_key_ex_introduced)}
    if LibVersion < DH_check_pub_key_ex_introduced then
    begin
      {$if declared(FC_DH_check_pub_key_ex)}
      DH_check_pub_key_ex := FC_DH_check_pub_key_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_check_pub_key_ex_removed)}
    if DH_check_pub_key_ex_removed <= LibVersion then
    begin
      {$if declared(_DH_check_pub_key_ex)}
      DH_check_pub_key_ex := _DH_check_pub_key_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_check_pub_key_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_check_pub_key_ex');
    {$ifend}
  end;
  
  DH_check_params := LoadLibFunction(ADllHandle, DH_check_params_procname);
  FuncLoadError := not assigned(DH_check_params);
  if FuncLoadError then
  begin
    {$if not defined(DH_check_params_allownil)}
    DH_check_params := ERR_DH_check_params;
    {$ifend}
    {$if declared(DH_check_params_introduced)}
    if LibVersion < DH_check_params_introduced then
    begin
      {$if declared(FC_DH_check_params)}
      DH_check_params := FC_DH_check_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_check_params_removed)}
    if DH_check_params_removed <= LibVersion then
    begin
      {$if declared(_DH_check_params)}
      DH_check_params := _DH_check_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_check_params_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_check_params');
    {$ifend}
  end;
  
  DH_check := LoadLibFunction(ADllHandle, DH_check_procname);
  FuncLoadError := not assigned(DH_check);
  if FuncLoadError then
  begin
    {$if not defined(DH_check_allownil)}
    DH_check := ERR_DH_check;
    {$ifend}
    {$if declared(DH_check_introduced)}
    if LibVersion < DH_check_introduced then
    begin
      {$if declared(FC_DH_check)}
      DH_check := FC_DH_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_check_removed)}
    if DH_check_removed <= LibVersion then
    begin
      {$if declared(_DH_check)}
      DH_check := _DH_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_check_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_check');
    {$ifend}
  end;
  
  DH_check_pub_key := LoadLibFunction(ADllHandle, DH_check_pub_key_procname);
  FuncLoadError := not assigned(DH_check_pub_key);
  if FuncLoadError then
  begin
    {$if not defined(DH_check_pub_key_allownil)}
    DH_check_pub_key := ERR_DH_check_pub_key;
    {$ifend}
    {$if declared(DH_check_pub_key_introduced)}
    if LibVersion < DH_check_pub_key_introduced then
    begin
      {$if declared(FC_DH_check_pub_key)}
      DH_check_pub_key := FC_DH_check_pub_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_check_pub_key_removed)}
    if DH_check_pub_key_removed <= LibVersion then
    begin
      {$if declared(_DH_check_pub_key)}
      DH_check_pub_key := _DH_check_pub_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_check_pub_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_check_pub_key');
    {$ifend}
  end;
  
  DH_generate_key := LoadLibFunction(ADllHandle, DH_generate_key_procname);
  FuncLoadError := not assigned(DH_generate_key);
  if FuncLoadError then
  begin
    {$if not defined(DH_generate_key_allownil)}
    DH_generate_key := ERR_DH_generate_key;
    {$ifend}
    {$if declared(DH_generate_key_introduced)}
    if LibVersion < DH_generate_key_introduced then
    begin
      {$if declared(FC_DH_generate_key)}
      DH_generate_key := FC_DH_generate_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_generate_key_removed)}
    if DH_generate_key_removed <= LibVersion then
    begin
      {$if declared(_DH_generate_key)}
      DH_generate_key := _DH_generate_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_generate_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_generate_key');
    {$ifend}
  end;
  
  DH_compute_key := LoadLibFunction(ADllHandle, DH_compute_key_procname);
  FuncLoadError := not assigned(DH_compute_key);
  if FuncLoadError then
  begin
    {$if not defined(DH_compute_key_allownil)}
    DH_compute_key := ERR_DH_compute_key;
    {$ifend}
    {$if declared(DH_compute_key_introduced)}
    if LibVersion < DH_compute_key_introduced then
    begin
      {$if declared(FC_DH_compute_key)}
      DH_compute_key := FC_DH_compute_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_compute_key_removed)}
    if DH_compute_key_removed <= LibVersion then
    begin
      {$if declared(_DH_compute_key)}
      DH_compute_key := _DH_compute_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_compute_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_compute_key');
    {$ifend}
  end;
  
  DH_compute_key_padded := LoadLibFunction(ADllHandle, DH_compute_key_padded_procname);
  FuncLoadError := not assigned(DH_compute_key_padded);
  if FuncLoadError then
  begin
    {$if not defined(DH_compute_key_padded_allownil)}
    DH_compute_key_padded := ERR_DH_compute_key_padded;
    {$ifend}
    {$if declared(DH_compute_key_padded_introduced)}
    if LibVersion < DH_compute_key_padded_introduced then
    begin
      {$if declared(FC_DH_compute_key_padded)}
      DH_compute_key_padded := FC_DH_compute_key_padded;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_compute_key_padded_removed)}
    if DH_compute_key_padded_removed <= LibVersion then
    begin
      {$if declared(_DH_compute_key_padded)}
      DH_compute_key_padded := _DH_compute_key_padded;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_compute_key_padded_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_compute_key_padded');
    {$ifend}
  end;
  
  d2i_DHparams := LoadLibFunction(ADllHandle, d2i_DHparams_procname);
  FuncLoadError := not assigned(d2i_DHparams);
  if FuncLoadError then
  begin
    {$if not defined(d2i_DHparams_allownil)}
    d2i_DHparams := ERR_d2i_DHparams;
    {$ifend}
    {$if declared(d2i_DHparams_introduced)}
    if LibVersion < d2i_DHparams_introduced then
    begin
      {$if declared(FC_d2i_DHparams)}
      d2i_DHparams := FC_d2i_DHparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_DHparams_removed)}
    if d2i_DHparams_removed <= LibVersion then
    begin
      {$if declared(_d2i_DHparams)}
      d2i_DHparams := _d2i_DHparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_DHparams_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_DHparams');
    {$ifend}
  end;
  
  i2d_DHparams := LoadLibFunction(ADllHandle, i2d_DHparams_procname);
  FuncLoadError := not assigned(i2d_DHparams);
  if FuncLoadError then
  begin
    {$if not defined(i2d_DHparams_allownil)}
    i2d_DHparams := ERR_i2d_DHparams;
    {$ifend}
    {$if declared(i2d_DHparams_introduced)}
    if LibVersion < i2d_DHparams_introduced then
    begin
      {$if declared(FC_i2d_DHparams)}
      i2d_DHparams := FC_i2d_DHparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_DHparams_removed)}
    if i2d_DHparams_removed <= LibVersion then
    begin
      {$if declared(_i2d_DHparams)}
      i2d_DHparams := _i2d_DHparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_DHparams_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_DHparams');
    {$ifend}
  end;
  
  d2i_DHxparams := LoadLibFunction(ADllHandle, d2i_DHxparams_procname);
  FuncLoadError := not assigned(d2i_DHxparams);
  if FuncLoadError then
  begin
    {$if not defined(d2i_DHxparams_allownil)}
    d2i_DHxparams := ERR_d2i_DHxparams;
    {$ifend}
    {$if declared(d2i_DHxparams_introduced)}
    if LibVersion < d2i_DHxparams_introduced then
    begin
      {$if declared(FC_d2i_DHxparams)}
      d2i_DHxparams := FC_d2i_DHxparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_DHxparams_removed)}
    if d2i_DHxparams_removed <= LibVersion then
    begin
      {$if declared(_d2i_DHxparams)}
      d2i_DHxparams := _d2i_DHxparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_DHxparams_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_DHxparams');
    {$ifend}
  end;
  
  i2d_DHxparams := LoadLibFunction(ADllHandle, i2d_DHxparams_procname);
  FuncLoadError := not assigned(i2d_DHxparams);
  if FuncLoadError then
  begin
    {$if not defined(i2d_DHxparams_allownil)}
    i2d_DHxparams := ERR_i2d_DHxparams;
    {$ifend}
    {$if declared(i2d_DHxparams_introduced)}
    if LibVersion < i2d_DHxparams_introduced then
    begin
      {$if declared(FC_i2d_DHxparams)}
      i2d_DHxparams := FC_i2d_DHxparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_DHxparams_removed)}
    if i2d_DHxparams_removed <= LibVersion then
    begin
      {$if declared(_i2d_DHxparams)}
      i2d_DHxparams := _i2d_DHxparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_DHxparams_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_DHxparams');
    {$ifend}
  end;
  
  DHparams_print_fp := LoadLibFunction(ADllHandle, DHparams_print_fp_procname);
  FuncLoadError := not assigned(DHparams_print_fp);
  if FuncLoadError then
  begin
    {$if not defined(DHparams_print_fp_allownil)}
    DHparams_print_fp := ERR_DHparams_print_fp;
    {$ifend}
    {$if declared(DHparams_print_fp_introduced)}
    if LibVersion < DHparams_print_fp_introduced then
    begin
      {$if declared(FC_DHparams_print_fp)}
      DHparams_print_fp := FC_DHparams_print_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DHparams_print_fp_removed)}
    if DHparams_print_fp_removed <= LibVersion then
    begin
      {$if declared(_DHparams_print_fp)}
      DHparams_print_fp := _DHparams_print_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DHparams_print_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('DHparams_print_fp');
    {$ifend}
  end;
  
  DHparams_print := LoadLibFunction(ADllHandle, DHparams_print_procname);
  FuncLoadError := not assigned(DHparams_print);
  if FuncLoadError then
  begin
    {$if not defined(DHparams_print_allownil)}
    DHparams_print := ERR_DHparams_print;
    {$ifend}
    {$if declared(DHparams_print_introduced)}
    if LibVersion < DHparams_print_introduced then
    begin
      {$if declared(FC_DHparams_print)}
      DHparams_print := FC_DHparams_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DHparams_print_removed)}
    if DHparams_print_removed <= LibVersion then
    begin
      {$if declared(_DHparams_print)}
      DHparams_print := _DHparams_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DHparams_print_allownil)}
    if FuncLoadError then
      AFailed.Add('DHparams_print');
    {$ifend}
  end;
  
  DH_get_1024_160 := LoadLibFunction(ADllHandle, DH_get_1024_160_procname);
  FuncLoadError := not assigned(DH_get_1024_160);
  if FuncLoadError then
  begin
    {$if not defined(DH_get_1024_160_allownil)}
    DH_get_1024_160 := ERR_DH_get_1024_160;
    {$ifend}
    {$if declared(DH_get_1024_160_introduced)}
    if LibVersion < DH_get_1024_160_introduced then
    begin
      {$if declared(FC_DH_get_1024_160)}
      DH_get_1024_160 := FC_DH_get_1024_160;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_get_1024_160_removed)}
    if DH_get_1024_160_removed <= LibVersion then
    begin
      {$if declared(_DH_get_1024_160)}
      DH_get_1024_160 := _DH_get_1024_160;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_get_1024_160_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_get_1024_160');
    {$ifend}
  end;
  
  DH_get_2048_224 := LoadLibFunction(ADllHandle, DH_get_2048_224_procname);
  FuncLoadError := not assigned(DH_get_2048_224);
  if FuncLoadError then
  begin
    {$if not defined(DH_get_2048_224_allownil)}
    DH_get_2048_224 := ERR_DH_get_2048_224;
    {$ifend}
    {$if declared(DH_get_2048_224_introduced)}
    if LibVersion < DH_get_2048_224_introduced then
    begin
      {$if declared(FC_DH_get_2048_224)}
      DH_get_2048_224 := FC_DH_get_2048_224;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_get_2048_224_removed)}
    if DH_get_2048_224_removed <= LibVersion then
    begin
      {$if declared(_DH_get_2048_224)}
      DH_get_2048_224 := _DH_get_2048_224;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_get_2048_224_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_get_2048_224');
    {$ifend}
  end;
  
  DH_get_2048_256 := LoadLibFunction(ADllHandle, DH_get_2048_256_procname);
  FuncLoadError := not assigned(DH_get_2048_256);
  if FuncLoadError then
  begin
    {$if not defined(DH_get_2048_256_allownil)}
    DH_get_2048_256 := ERR_DH_get_2048_256;
    {$ifend}
    {$if declared(DH_get_2048_256_introduced)}
    if LibVersion < DH_get_2048_256_introduced then
    begin
      {$if declared(FC_DH_get_2048_256)}
      DH_get_2048_256 := FC_DH_get_2048_256;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_get_2048_256_removed)}
    if DH_get_2048_256_removed <= LibVersion then
    begin
      {$if declared(_DH_get_2048_256)}
      DH_get_2048_256 := _DH_get_2048_256;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_get_2048_256_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_get_2048_256');
    {$ifend}
  end;
  
  DH_new_by_nid := LoadLibFunction(ADllHandle, DH_new_by_nid_procname);
  FuncLoadError := not assigned(DH_new_by_nid);
  if FuncLoadError then
  begin
    {$if not defined(DH_new_by_nid_allownil)}
    DH_new_by_nid := ERR_DH_new_by_nid;
    {$ifend}
    {$if declared(DH_new_by_nid_introduced)}
    if LibVersion < DH_new_by_nid_introduced then
    begin
      {$if declared(FC_DH_new_by_nid)}
      DH_new_by_nid := FC_DH_new_by_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_new_by_nid_removed)}
    if DH_new_by_nid_removed <= LibVersion then
    begin
      {$if declared(_DH_new_by_nid)}
      DH_new_by_nid := _DH_new_by_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_new_by_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_new_by_nid');
    {$ifend}
  end;
  
  DH_get_nid := LoadLibFunction(ADllHandle, DH_get_nid_procname);
  FuncLoadError := not assigned(DH_get_nid);
  if FuncLoadError then
  begin
    {$if not defined(DH_get_nid_allownil)}
    DH_get_nid := ERR_DH_get_nid;
    {$ifend}
    {$if declared(DH_get_nid_introduced)}
    if LibVersion < DH_get_nid_introduced then
    begin
      {$if declared(FC_DH_get_nid)}
      DH_get_nid := FC_DH_get_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_get_nid_removed)}
    if DH_get_nid_removed <= LibVersion then
    begin
      {$if declared(_DH_get_nid)}
      DH_get_nid := _DH_get_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_get_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_get_nid');
    {$ifend}
  end;
  
  DH_KDF_X9_42 := LoadLibFunction(ADllHandle, DH_KDF_X9_42_procname);
  FuncLoadError := not assigned(DH_KDF_X9_42);
  if FuncLoadError then
  begin
    {$if not defined(DH_KDF_X9_42_allownil)}
    DH_KDF_X9_42 := ERR_DH_KDF_X9_42;
    {$ifend}
    {$if declared(DH_KDF_X9_42_introduced)}
    if LibVersion < DH_KDF_X9_42_introduced then
    begin
      {$if declared(FC_DH_KDF_X9_42)}
      DH_KDF_X9_42 := FC_DH_KDF_X9_42;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_KDF_X9_42_removed)}
    if DH_KDF_X9_42_removed <= LibVersion then
    begin
      {$if declared(_DH_KDF_X9_42)}
      DH_KDF_X9_42 := _DH_KDF_X9_42;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_KDF_X9_42_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_KDF_X9_42');
    {$ifend}
  end;
  
  DH_get0_pqg := LoadLibFunction(ADllHandle, DH_get0_pqg_procname);
  FuncLoadError := not assigned(DH_get0_pqg);
  if FuncLoadError then
  begin
    {$if not defined(DH_get0_pqg_allownil)}
    DH_get0_pqg := ERR_DH_get0_pqg;
    {$ifend}
    {$if declared(DH_get0_pqg_introduced)}
    if LibVersion < DH_get0_pqg_introduced then
    begin
      {$if declared(FC_DH_get0_pqg)}
      DH_get0_pqg := FC_DH_get0_pqg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_get0_pqg_removed)}
    if DH_get0_pqg_removed <= LibVersion then
    begin
      {$if declared(_DH_get0_pqg)}
      DH_get0_pqg := _DH_get0_pqg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_get0_pqg_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_get0_pqg');
    {$ifend}
  end;
  
  DH_set0_pqg := LoadLibFunction(ADllHandle, DH_set0_pqg_procname);
  FuncLoadError := not assigned(DH_set0_pqg);
  if FuncLoadError then
  begin
    {$if not defined(DH_set0_pqg_allownil)}
    DH_set0_pqg := ERR_DH_set0_pqg;
    {$ifend}
    {$if declared(DH_set0_pqg_introduced)}
    if LibVersion < DH_set0_pqg_introduced then
    begin
      {$if declared(FC_DH_set0_pqg)}
      DH_set0_pqg := FC_DH_set0_pqg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_set0_pqg_removed)}
    if DH_set0_pqg_removed <= LibVersion then
    begin
      {$if declared(_DH_set0_pqg)}
      DH_set0_pqg := _DH_set0_pqg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_set0_pqg_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_set0_pqg');
    {$ifend}
  end;
  
  DH_get0_key := LoadLibFunction(ADllHandle, DH_get0_key_procname);
  FuncLoadError := not assigned(DH_get0_key);
  if FuncLoadError then
  begin
    {$if not defined(DH_get0_key_allownil)}
    DH_get0_key := ERR_DH_get0_key;
    {$ifend}
    {$if declared(DH_get0_key_introduced)}
    if LibVersion < DH_get0_key_introduced then
    begin
      {$if declared(FC_DH_get0_key)}
      DH_get0_key := FC_DH_get0_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_get0_key_removed)}
    if DH_get0_key_removed <= LibVersion then
    begin
      {$if declared(_DH_get0_key)}
      DH_get0_key := _DH_get0_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_get0_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_get0_key');
    {$ifend}
  end;
  
  DH_set0_key := LoadLibFunction(ADllHandle, DH_set0_key_procname);
  FuncLoadError := not assigned(DH_set0_key);
  if FuncLoadError then
  begin
    {$if not defined(DH_set0_key_allownil)}
    DH_set0_key := ERR_DH_set0_key;
    {$ifend}
    {$if declared(DH_set0_key_introduced)}
    if LibVersion < DH_set0_key_introduced then
    begin
      {$if declared(FC_DH_set0_key)}
      DH_set0_key := FC_DH_set0_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_set0_key_removed)}
    if DH_set0_key_removed <= LibVersion then
    begin
      {$if declared(_DH_set0_key)}
      DH_set0_key := _DH_set0_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_set0_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_set0_key');
    {$ifend}
  end;
  
  DH_get0_p := LoadLibFunction(ADllHandle, DH_get0_p_procname);
  FuncLoadError := not assigned(DH_get0_p);
  if FuncLoadError then
  begin
    {$if not defined(DH_get0_p_allownil)}
    DH_get0_p := ERR_DH_get0_p;
    {$ifend}
    {$if declared(DH_get0_p_introduced)}
    if LibVersion < DH_get0_p_introduced then
    begin
      {$if declared(FC_DH_get0_p)}
      DH_get0_p := FC_DH_get0_p;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_get0_p_removed)}
    if DH_get0_p_removed <= LibVersion then
    begin
      {$if declared(_DH_get0_p)}
      DH_get0_p := _DH_get0_p;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_get0_p_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_get0_p');
    {$ifend}
  end;
  
  DH_get0_q := LoadLibFunction(ADllHandle, DH_get0_q_procname);
  FuncLoadError := not assigned(DH_get0_q);
  if FuncLoadError then
  begin
    {$if not defined(DH_get0_q_allownil)}
    DH_get0_q := ERR_DH_get0_q;
    {$ifend}
    {$if declared(DH_get0_q_introduced)}
    if LibVersion < DH_get0_q_introduced then
    begin
      {$if declared(FC_DH_get0_q)}
      DH_get0_q := FC_DH_get0_q;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_get0_q_removed)}
    if DH_get0_q_removed <= LibVersion then
    begin
      {$if declared(_DH_get0_q)}
      DH_get0_q := _DH_get0_q;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_get0_q_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_get0_q');
    {$ifend}
  end;
  
  DH_get0_g := LoadLibFunction(ADllHandle, DH_get0_g_procname);
  FuncLoadError := not assigned(DH_get0_g);
  if FuncLoadError then
  begin
    {$if not defined(DH_get0_g_allownil)}
    DH_get0_g := ERR_DH_get0_g;
    {$ifend}
    {$if declared(DH_get0_g_introduced)}
    if LibVersion < DH_get0_g_introduced then
    begin
      {$if declared(FC_DH_get0_g)}
      DH_get0_g := FC_DH_get0_g;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_get0_g_removed)}
    if DH_get0_g_removed <= LibVersion then
    begin
      {$if declared(_DH_get0_g)}
      DH_get0_g := _DH_get0_g;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_get0_g_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_get0_g');
    {$ifend}
  end;
  
  DH_get0_priv_key := LoadLibFunction(ADllHandle, DH_get0_priv_key_procname);
  FuncLoadError := not assigned(DH_get0_priv_key);
  if FuncLoadError then
  begin
    {$if not defined(DH_get0_priv_key_allownil)}
    DH_get0_priv_key := ERR_DH_get0_priv_key;
    {$ifend}
    {$if declared(DH_get0_priv_key_introduced)}
    if LibVersion < DH_get0_priv_key_introduced then
    begin
      {$if declared(FC_DH_get0_priv_key)}
      DH_get0_priv_key := FC_DH_get0_priv_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_get0_priv_key_removed)}
    if DH_get0_priv_key_removed <= LibVersion then
    begin
      {$if declared(_DH_get0_priv_key)}
      DH_get0_priv_key := _DH_get0_priv_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_get0_priv_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_get0_priv_key');
    {$ifend}
  end;
  
  DH_get0_pub_key := LoadLibFunction(ADllHandle, DH_get0_pub_key_procname);
  FuncLoadError := not assigned(DH_get0_pub_key);
  if FuncLoadError then
  begin
    {$if not defined(DH_get0_pub_key_allownil)}
    DH_get0_pub_key := ERR_DH_get0_pub_key;
    {$ifend}
    {$if declared(DH_get0_pub_key_introduced)}
    if LibVersion < DH_get0_pub_key_introduced then
    begin
      {$if declared(FC_DH_get0_pub_key)}
      DH_get0_pub_key := FC_DH_get0_pub_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_get0_pub_key_removed)}
    if DH_get0_pub_key_removed <= LibVersion then
    begin
      {$if declared(_DH_get0_pub_key)}
      DH_get0_pub_key := _DH_get0_pub_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_get0_pub_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_get0_pub_key');
    {$ifend}
  end;
  
  DH_clear_flags := LoadLibFunction(ADllHandle, DH_clear_flags_procname);
  FuncLoadError := not assigned(DH_clear_flags);
  if FuncLoadError then
  begin
    {$if not defined(DH_clear_flags_allownil)}
    DH_clear_flags := ERR_DH_clear_flags;
    {$ifend}
    {$if declared(DH_clear_flags_introduced)}
    if LibVersion < DH_clear_flags_introduced then
    begin
      {$if declared(FC_DH_clear_flags)}
      DH_clear_flags := FC_DH_clear_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_clear_flags_removed)}
    if DH_clear_flags_removed <= LibVersion then
    begin
      {$if declared(_DH_clear_flags)}
      DH_clear_flags := _DH_clear_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_clear_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_clear_flags');
    {$ifend}
  end;
  
  DH_test_flags := LoadLibFunction(ADllHandle, DH_test_flags_procname);
  FuncLoadError := not assigned(DH_test_flags);
  if FuncLoadError then
  begin
    {$if not defined(DH_test_flags_allownil)}
    DH_test_flags := ERR_DH_test_flags;
    {$ifend}
    {$if declared(DH_test_flags_introduced)}
    if LibVersion < DH_test_flags_introduced then
    begin
      {$if declared(FC_DH_test_flags)}
      DH_test_flags := FC_DH_test_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_test_flags_removed)}
    if DH_test_flags_removed <= LibVersion then
    begin
      {$if declared(_DH_test_flags)}
      DH_test_flags := _DH_test_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_test_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_test_flags');
    {$ifend}
  end;
  
  DH_set_flags := LoadLibFunction(ADllHandle, DH_set_flags_procname);
  FuncLoadError := not assigned(DH_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(DH_set_flags_allownil)}
    DH_set_flags := ERR_DH_set_flags;
    {$ifend}
    {$if declared(DH_set_flags_introduced)}
    if LibVersion < DH_set_flags_introduced then
    begin
      {$if declared(FC_DH_set_flags)}
      DH_set_flags := FC_DH_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_set_flags_removed)}
    if DH_set_flags_removed <= LibVersion then
    begin
      {$if declared(_DH_set_flags)}
      DH_set_flags := _DH_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_set_flags');
    {$ifend}
  end;
  
  DH_get0_engine := LoadLibFunction(ADllHandle, DH_get0_engine_procname);
  FuncLoadError := not assigned(DH_get0_engine);
  if FuncLoadError then
  begin
    {$if not defined(DH_get0_engine_allownil)}
    DH_get0_engine := ERR_DH_get0_engine;
    {$ifend}
    {$if declared(DH_get0_engine_introduced)}
    if LibVersion < DH_get0_engine_introduced then
    begin
      {$if declared(FC_DH_get0_engine)}
      DH_get0_engine := FC_DH_get0_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_get0_engine_removed)}
    if DH_get0_engine_removed <= LibVersion then
    begin
      {$if declared(_DH_get0_engine)}
      DH_get0_engine := _DH_get0_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_get0_engine_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_get0_engine');
    {$ifend}
  end;
  
  DH_get_length := LoadLibFunction(ADllHandle, DH_get_length_procname);
  FuncLoadError := not assigned(DH_get_length);
  if FuncLoadError then
  begin
    {$if not defined(DH_get_length_allownil)}
    DH_get_length := ERR_DH_get_length;
    {$ifend}
    {$if declared(DH_get_length_introduced)}
    if LibVersion < DH_get_length_introduced then
    begin
      {$if declared(FC_DH_get_length)}
      DH_get_length := FC_DH_get_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_get_length_removed)}
    if DH_get_length_removed <= LibVersion then
    begin
      {$if declared(_DH_get_length)}
      DH_get_length := _DH_get_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_get_length_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_get_length');
    {$ifend}
  end;
  
  DH_set_length := LoadLibFunction(ADllHandle, DH_set_length_procname);
  FuncLoadError := not assigned(DH_set_length);
  if FuncLoadError then
  begin
    {$if not defined(DH_set_length_allownil)}
    DH_set_length := ERR_DH_set_length;
    {$ifend}
    {$if declared(DH_set_length_introduced)}
    if LibVersion < DH_set_length_introduced then
    begin
      {$if declared(FC_DH_set_length)}
      DH_set_length := FC_DH_set_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_set_length_removed)}
    if DH_set_length_removed <= LibVersion then
    begin
      {$if declared(_DH_set_length)}
      DH_set_length := _DH_set_length;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_set_length_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_set_length');
    {$ifend}
  end;
  
  DH_meth_new := LoadLibFunction(ADllHandle, DH_meth_new_procname);
  FuncLoadError := not assigned(DH_meth_new);
  if FuncLoadError then
  begin
    {$if not defined(DH_meth_new_allownil)}
    DH_meth_new := ERR_DH_meth_new;
    {$ifend}
    {$if declared(DH_meth_new_introduced)}
    if LibVersion < DH_meth_new_introduced then
    begin
      {$if declared(FC_DH_meth_new)}
      DH_meth_new := FC_DH_meth_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_meth_new_removed)}
    if DH_meth_new_removed <= LibVersion then
    begin
      {$if declared(_DH_meth_new)}
      DH_meth_new := _DH_meth_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_meth_new_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_meth_new');
    {$ifend}
  end;
  
  DH_meth_free := LoadLibFunction(ADllHandle, DH_meth_free_procname);
  FuncLoadError := not assigned(DH_meth_free);
  if FuncLoadError then
  begin
    {$if not defined(DH_meth_free_allownil)}
    DH_meth_free := ERR_DH_meth_free;
    {$ifend}
    {$if declared(DH_meth_free_introduced)}
    if LibVersion < DH_meth_free_introduced then
    begin
      {$if declared(FC_DH_meth_free)}
      DH_meth_free := FC_DH_meth_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_meth_free_removed)}
    if DH_meth_free_removed <= LibVersion then
    begin
      {$if declared(_DH_meth_free)}
      DH_meth_free := _DH_meth_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_meth_free_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_meth_free');
    {$ifend}
  end;
  
  DH_meth_dup := LoadLibFunction(ADllHandle, DH_meth_dup_procname);
  FuncLoadError := not assigned(DH_meth_dup);
  if FuncLoadError then
  begin
    {$if not defined(DH_meth_dup_allownil)}
    DH_meth_dup := ERR_DH_meth_dup;
    {$ifend}
    {$if declared(DH_meth_dup_introduced)}
    if LibVersion < DH_meth_dup_introduced then
    begin
      {$if declared(FC_DH_meth_dup)}
      DH_meth_dup := FC_DH_meth_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_meth_dup_removed)}
    if DH_meth_dup_removed <= LibVersion then
    begin
      {$if declared(_DH_meth_dup)}
      DH_meth_dup := _DH_meth_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_meth_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_meth_dup');
    {$ifend}
  end;
  
  DH_meth_get0_name := LoadLibFunction(ADllHandle, DH_meth_get0_name_procname);
  FuncLoadError := not assigned(DH_meth_get0_name);
  if FuncLoadError then
  begin
    {$if not defined(DH_meth_get0_name_allownil)}
    DH_meth_get0_name := ERR_DH_meth_get0_name;
    {$ifend}
    {$if declared(DH_meth_get0_name_introduced)}
    if LibVersion < DH_meth_get0_name_introduced then
    begin
      {$if declared(FC_DH_meth_get0_name)}
      DH_meth_get0_name := FC_DH_meth_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_meth_get0_name_removed)}
    if DH_meth_get0_name_removed <= LibVersion then
    begin
      {$if declared(_DH_meth_get0_name)}
      DH_meth_get0_name := _DH_meth_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_meth_get0_name_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_meth_get0_name');
    {$ifend}
  end;
  
  DH_meth_set1_name := LoadLibFunction(ADllHandle, DH_meth_set1_name_procname);
  FuncLoadError := not assigned(DH_meth_set1_name);
  if FuncLoadError then
  begin
    {$if not defined(DH_meth_set1_name_allownil)}
    DH_meth_set1_name := ERR_DH_meth_set1_name;
    {$ifend}
    {$if declared(DH_meth_set1_name_introduced)}
    if LibVersion < DH_meth_set1_name_introduced then
    begin
      {$if declared(FC_DH_meth_set1_name)}
      DH_meth_set1_name := FC_DH_meth_set1_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_meth_set1_name_removed)}
    if DH_meth_set1_name_removed <= LibVersion then
    begin
      {$if declared(_DH_meth_set1_name)}
      DH_meth_set1_name := _DH_meth_set1_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_meth_set1_name_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_meth_set1_name');
    {$ifend}
  end;
  
  DH_meth_get_flags := LoadLibFunction(ADllHandle, DH_meth_get_flags_procname);
  FuncLoadError := not assigned(DH_meth_get_flags);
  if FuncLoadError then
  begin
    {$if not defined(DH_meth_get_flags_allownil)}
    DH_meth_get_flags := ERR_DH_meth_get_flags;
    {$ifend}
    {$if declared(DH_meth_get_flags_introduced)}
    if LibVersion < DH_meth_get_flags_introduced then
    begin
      {$if declared(FC_DH_meth_get_flags)}
      DH_meth_get_flags := FC_DH_meth_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_meth_get_flags_removed)}
    if DH_meth_get_flags_removed <= LibVersion then
    begin
      {$if declared(_DH_meth_get_flags)}
      DH_meth_get_flags := _DH_meth_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_meth_get_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_meth_get_flags');
    {$ifend}
  end;
  
  DH_meth_set_flags := LoadLibFunction(ADllHandle, DH_meth_set_flags_procname);
  FuncLoadError := not assigned(DH_meth_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(DH_meth_set_flags_allownil)}
    DH_meth_set_flags := ERR_DH_meth_set_flags;
    {$ifend}
    {$if declared(DH_meth_set_flags_introduced)}
    if LibVersion < DH_meth_set_flags_introduced then
    begin
      {$if declared(FC_DH_meth_set_flags)}
      DH_meth_set_flags := FC_DH_meth_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_meth_set_flags_removed)}
    if DH_meth_set_flags_removed <= LibVersion then
    begin
      {$if declared(_DH_meth_set_flags)}
      DH_meth_set_flags := _DH_meth_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_meth_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_meth_set_flags');
    {$ifend}
  end;
  
  DH_meth_get0_app_data := LoadLibFunction(ADllHandle, DH_meth_get0_app_data_procname);
  FuncLoadError := not assigned(DH_meth_get0_app_data);
  if FuncLoadError then
  begin
    {$if not defined(DH_meth_get0_app_data_allownil)}
    DH_meth_get0_app_data := ERR_DH_meth_get0_app_data;
    {$ifend}
    {$if declared(DH_meth_get0_app_data_introduced)}
    if LibVersion < DH_meth_get0_app_data_introduced then
    begin
      {$if declared(FC_DH_meth_get0_app_data)}
      DH_meth_get0_app_data := FC_DH_meth_get0_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_meth_get0_app_data_removed)}
    if DH_meth_get0_app_data_removed <= LibVersion then
    begin
      {$if declared(_DH_meth_get0_app_data)}
      DH_meth_get0_app_data := _DH_meth_get0_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_meth_get0_app_data_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_meth_get0_app_data');
    {$ifend}
  end;
  
  DH_meth_set0_app_data := LoadLibFunction(ADllHandle, DH_meth_set0_app_data_procname);
  FuncLoadError := not assigned(DH_meth_set0_app_data);
  if FuncLoadError then
  begin
    {$if not defined(DH_meth_set0_app_data_allownil)}
    DH_meth_set0_app_data := ERR_DH_meth_set0_app_data;
    {$ifend}
    {$if declared(DH_meth_set0_app_data_introduced)}
    if LibVersion < DH_meth_set0_app_data_introduced then
    begin
      {$if declared(FC_DH_meth_set0_app_data)}
      DH_meth_set0_app_data := FC_DH_meth_set0_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_meth_set0_app_data_removed)}
    if DH_meth_set0_app_data_removed <= LibVersion then
    begin
      {$if declared(_DH_meth_set0_app_data)}
      DH_meth_set0_app_data := _DH_meth_set0_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_meth_set0_app_data_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_meth_set0_app_data');
    {$ifend}
  end;
  
  DH_meth_get_generate_key := LoadLibFunction(ADllHandle, DH_meth_get_generate_key_procname);
  FuncLoadError := not assigned(DH_meth_get_generate_key);
  if FuncLoadError then
  begin
    {$if not defined(DH_meth_get_generate_key_allownil)}
    DH_meth_get_generate_key := ERR_DH_meth_get_generate_key;
    {$ifend}
    {$if declared(DH_meth_get_generate_key_introduced)}
    if LibVersion < DH_meth_get_generate_key_introduced then
    begin
      {$if declared(FC_DH_meth_get_generate_key)}
      DH_meth_get_generate_key := FC_DH_meth_get_generate_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_meth_get_generate_key_removed)}
    if DH_meth_get_generate_key_removed <= LibVersion then
    begin
      {$if declared(_DH_meth_get_generate_key)}
      DH_meth_get_generate_key := _DH_meth_get_generate_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_meth_get_generate_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_meth_get_generate_key');
    {$ifend}
  end;
  
  DH_meth_set_generate_key := LoadLibFunction(ADllHandle, DH_meth_set_generate_key_procname);
  FuncLoadError := not assigned(DH_meth_set_generate_key);
  if FuncLoadError then
  begin
    {$if not defined(DH_meth_set_generate_key_allownil)}
    DH_meth_set_generate_key := ERR_DH_meth_set_generate_key;
    {$ifend}
    {$if declared(DH_meth_set_generate_key_introduced)}
    if LibVersion < DH_meth_set_generate_key_introduced then
    begin
      {$if declared(FC_DH_meth_set_generate_key)}
      DH_meth_set_generate_key := FC_DH_meth_set_generate_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_meth_set_generate_key_removed)}
    if DH_meth_set_generate_key_removed <= LibVersion then
    begin
      {$if declared(_DH_meth_set_generate_key)}
      DH_meth_set_generate_key := _DH_meth_set_generate_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_meth_set_generate_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_meth_set_generate_key');
    {$ifend}
  end;
  
  DH_meth_get_compute_key := LoadLibFunction(ADllHandle, DH_meth_get_compute_key_procname);
  FuncLoadError := not assigned(DH_meth_get_compute_key);
  if FuncLoadError then
  begin
    {$if not defined(DH_meth_get_compute_key_allownil)}
    DH_meth_get_compute_key := ERR_DH_meth_get_compute_key;
    {$ifend}
    {$if declared(DH_meth_get_compute_key_introduced)}
    if LibVersion < DH_meth_get_compute_key_introduced then
    begin
      {$if declared(FC_DH_meth_get_compute_key)}
      DH_meth_get_compute_key := FC_DH_meth_get_compute_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_meth_get_compute_key_removed)}
    if DH_meth_get_compute_key_removed <= LibVersion then
    begin
      {$if declared(_DH_meth_get_compute_key)}
      DH_meth_get_compute_key := _DH_meth_get_compute_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_meth_get_compute_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_meth_get_compute_key');
    {$ifend}
  end;
  
  DH_meth_set_compute_key := LoadLibFunction(ADllHandle, DH_meth_set_compute_key_procname);
  FuncLoadError := not assigned(DH_meth_set_compute_key);
  if FuncLoadError then
  begin
    {$if not defined(DH_meth_set_compute_key_allownil)}
    DH_meth_set_compute_key := ERR_DH_meth_set_compute_key;
    {$ifend}
    {$if declared(DH_meth_set_compute_key_introduced)}
    if LibVersion < DH_meth_set_compute_key_introduced then
    begin
      {$if declared(FC_DH_meth_set_compute_key)}
      DH_meth_set_compute_key := FC_DH_meth_set_compute_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_meth_set_compute_key_removed)}
    if DH_meth_set_compute_key_removed <= LibVersion then
    begin
      {$if declared(_DH_meth_set_compute_key)}
      DH_meth_set_compute_key := _DH_meth_set_compute_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_meth_set_compute_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_meth_set_compute_key');
    {$ifend}
  end;
  
  DH_meth_get_bn_mod_exp := LoadLibFunction(ADllHandle, DH_meth_get_bn_mod_exp_procname);
  FuncLoadError := not assigned(DH_meth_get_bn_mod_exp);
  if FuncLoadError then
  begin
    {$if not defined(DH_meth_get_bn_mod_exp_allownil)}
    DH_meth_get_bn_mod_exp := ERR_DH_meth_get_bn_mod_exp;
    {$ifend}
    {$if declared(DH_meth_get_bn_mod_exp_introduced)}
    if LibVersion < DH_meth_get_bn_mod_exp_introduced then
    begin
      {$if declared(FC_DH_meth_get_bn_mod_exp)}
      DH_meth_get_bn_mod_exp := FC_DH_meth_get_bn_mod_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_meth_get_bn_mod_exp_removed)}
    if DH_meth_get_bn_mod_exp_removed <= LibVersion then
    begin
      {$if declared(_DH_meth_get_bn_mod_exp)}
      DH_meth_get_bn_mod_exp := _DH_meth_get_bn_mod_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_meth_get_bn_mod_exp_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_meth_get_bn_mod_exp');
    {$ifend}
  end;
  
  DH_meth_set_bn_mod_exp := LoadLibFunction(ADllHandle, DH_meth_set_bn_mod_exp_procname);
  FuncLoadError := not assigned(DH_meth_set_bn_mod_exp);
  if FuncLoadError then
  begin
    {$if not defined(DH_meth_set_bn_mod_exp_allownil)}
    DH_meth_set_bn_mod_exp := ERR_DH_meth_set_bn_mod_exp;
    {$ifend}
    {$if declared(DH_meth_set_bn_mod_exp_introduced)}
    if LibVersion < DH_meth_set_bn_mod_exp_introduced then
    begin
      {$if declared(FC_DH_meth_set_bn_mod_exp)}
      DH_meth_set_bn_mod_exp := FC_DH_meth_set_bn_mod_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_meth_set_bn_mod_exp_removed)}
    if DH_meth_set_bn_mod_exp_removed <= LibVersion then
    begin
      {$if declared(_DH_meth_set_bn_mod_exp)}
      DH_meth_set_bn_mod_exp := _DH_meth_set_bn_mod_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_meth_set_bn_mod_exp_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_meth_set_bn_mod_exp');
    {$ifend}
  end;
  
  DH_meth_get_init := LoadLibFunction(ADllHandle, DH_meth_get_init_procname);
  FuncLoadError := not assigned(DH_meth_get_init);
  if FuncLoadError then
  begin
    {$if not defined(DH_meth_get_init_allownil)}
    DH_meth_get_init := ERR_DH_meth_get_init;
    {$ifend}
    {$if declared(DH_meth_get_init_introduced)}
    if LibVersion < DH_meth_get_init_introduced then
    begin
      {$if declared(FC_DH_meth_get_init)}
      DH_meth_get_init := FC_DH_meth_get_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_meth_get_init_removed)}
    if DH_meth_get_init_removed <= LibVersion then
    begin
      {$if declared(_DH_meth_get_init)}
      DH_meth_get_init := _DH_meth_get_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_meth_get_init_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_meth_get_init');
    {$ifend}
  end;
  
  DH_meth_set_init := LoadLibFunction(ADllHandle, DH_meth_set_init_procname);
  FuncLoadError := not assigned(DH_meth_set_init);
  if FuncLoadError then
  begin
    {$if not defined(DH_meth_set_init_allownil)}
    DH_meth_set_init := ERR_DH_meth_set_init;
    {$ifend}
    {$if declared(DH_meth_set_init_introduced)}
    if LibVersion < DH_meth_set_init_introduced then
    begin
      {$if declared(FC_DH_meth_set_init)}
      DH_meth_set_init := FC_DH_meth_set_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_meth_set_init_removed)}
    if DH_meth_set_init_removed <= LibVersion then
    begin
      {$if declared(_DH_meth_set_init)}
      DH_meth_set_init := _DH_meth_set_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_meth_set_init_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_meth_set_init');
    {$ifend}
  end;
  
  DH_meth_get_finish := LoadLibFunction(ADllHandle, DH_meth_get_finish_procname);
  FuncLoadError := not assigned(DH_meth_get_finish);
  if FuncLoadError then
  begin
    {$if not defined(DH_meth_get_finish_allownil)}
    DH_meth_get_finish := ERR_DH_meth_get_finish;
    {$ifend}
    {$if declared(DH_meth_get_finish_introduced)}
    if LibVersion < DH_meth_get_finish_introduced then
    begin
      {$if declared(FC_DH_meth_get_finish)}
      DH_meth_get_finish := FC_DH_meth_get_finish;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_meth_get_finish_removed)}
    if DH_meth_get_finish_removed <= LibVersion then
    begin
      {$if declared(_DH_meth_get_finish)}
      DH_meth_get_finish := _DH_meth_get_finish;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_meth_get_finish_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_meth_get_finish');
    {$ifend}
  end;
  
  DH_meth_set_finish := LoadLibFunction(ADllHandle, DH_meth_set_finish_procname);
  FuncLoadError := not assigned(DH_meth_set_finish);
  if FuncLoadError then
  begin
    {$if not defined(DH_meth_set_finish_allownil)}
    DH_meth_set_finish := ERR_DH_meth_set_finish;
    {$ifend}
    {$if declared(DH_meth_set_finish_introduced)}
    if LibVersion < DH_meth_set_finish_introduced then
    begin
      {$if declared(FC_DH_meth_set_finish)}
      DH_meth_set_finish := FC_DH_meth_set_finish;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_meth_set_finish_removed)}
    if DH_meth_set_finish_removed <= LibVersion then
    begin
      {$if declared(_DH_meth_set_finish)}
      DH_meth_set_finish := _DH_meth_set_finish;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_meth_set_finish_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_meth_set_finish');
    {$ifend}
  end;
  
  DH_meth_get_generate_params := LoadLibFunction(ADllHandle, DH_meth_get_generate_params_procname);
  FuncLoadError := not assigned(DH_meth_get_generate_params);
  if FuncLoadError then
  begin
    {$if not defined(DH_meth_get_generate_params_allownil)}
    DH_meth_get_generate_params := ERR_DH_meth_get_generate_params;
    {$ifend}
    {$if declared(DH_meth_get_generate_params_introduced)}
    if LibVersion < DH_meth_get_generate_params_introduced then
    begin
      {$if declared(FC_DH_meth_get_generate_params)}
      DH_meth_get_generate_params := FC_DH_meth_get_generate_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_meth_get_generate_params_removed)}
    if DH_meth_get_generate_params_removed <= LibVersion then
    begin
      {$if declared(_DH_meth_get_generate_params)}
      DH_meth_get_generate_params := _DH_meth_get_generate_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_meth_get_generate_params_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_meth_get_generate_params');
    {$ifend}
  end;
  
  DH_meth_set_generate_params := LoadLibFunction(ADllHandle, DH_meth_set_generate_params_procname);
  FuncLoadError := not assigned(DH_meth_set_generate_params);
  if FuncLoadError then
  begin
    {$if not defined(DH_meth_set_generate_params_allownil)}
    DH_meth_set_generate_params := ERR_DH_meth_set_generate_params;
    {$ifend}
    {$if declared(DH_meth_set_generate_params_introduced)}
    if LibVersion < DH_meth_set_generate_params_introduced then
    begin
      {$if declared(FC_DH_meth_set_generate_params)}
      DH_meth_set_generate_params := FC_DH_meth_set_generate_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DH_meth_set_generate_params_removed)}
    if DH_meth_set_generate_params_removed <= LibVersion then
    begin
      {$if declared(_DH_meth_set_generate_params)}
      DH_meth_set_generate_params := _DH_meth_set_generate_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DH_meth_set_generate_params_allownil)}
    if FuncLoadError then
      AFailed.Add('DH_meth_set_generate_params');
    {$ifend}
  end;
  
  
end;

procedure Unload;
begin
  EVP_PKEY_CTX_set_dh_paramgen_type := nil;
  EVP_PKEY_CTX_set_dh_paramgen_gindex := nil;
  EVP_PKEY_CTX_set_dh_paramgen_seed := nil;
  EVP_PKEY_CTX_set_dh_paramgen_prime_len := nil;
  EVP_PKEY_CTX_set_dh_paramgen_subprime_len := nil;
  EVP_PKEY_CTX_set_dh_paramgen_generator := nil;
  EVP_PKEY_CTX_set_dh_nid := nil;
  EVP_PKEY_CTX_set_dh_rfc5114 := nil;
  EVP_PKEY_CTX_set_dhx_rfc5114 := nil;
  EVP_PKEY_CTX_set_dh_pad := nil;
  EVP_PKEY_CTX_set_dh_kdf_type := nil;
  EVP_PKEY_CTX_get_dh_kdf_type := nil;
  EVP_PKEY_CTX_set0_dh_kdf_oid := nil;
  EVP_PKEY_CTX_get0_dh_kdf_oid := nil;
  EVP_PKEY_CTX_set_dh_kdf_md := nil;
  EVP_PKEY_CTX_get_dh_kdf_md := nil;
  EVP_PKEY_CTX_set_dh_kdf_outlen := nil;
  EVP_PKEY_CTX_get_dh_kdf_outlen := nil;
  EVP_PKEY_CTX_set0_dh_kdf_ukm := nil;
  EVP_PKEY_CTX_get0_dh_kdf_ukm := nil;
  DHparams_it := nil;
  DHparams_dup := nil;
  DH_OpenSSL := nil;
  DH_set_default_method := nil;
  DH_get_default_method := nil;
  DH_set_method := nil;
  DH_new_method := nil;
  DH_new := nil;
  DH_free := nil;
  DH_up_ref := nil;
  DH_bits := nil;
  DH_size := nil;
  DH_security_bits := nil;
  DH_set_ex_data := nil;
  DH_get_ex_data := nil;
  DH_generate_parameters_ex := nil;
  DH_check_params_ex := nil;
  DH_check_ex := nil;
  DH_check_pub_key_ex := nil;
  DH_check_params := nil;
  DH_check := nil;
  DH_check_pub_key := nil;
  DH_generate_key := nil;
  DH_compute_key := nil;
  DH_compute_key_padded := nil;
  d2i_DHparams := nil;
  i2d_DHparams := nil;
  d2i_DHxparams := nil;
  i2d_DHxparams := nil;
  DHparams_print_fp := nil;
  DHparams_print := nil;
  DH_get_1024_160 := nil;
  DH_get_2048_224 := nil;
  DH_get_2048_256 := nil;
  DH_new_by_nid := nil;
  DH_get_nid := nil;
  DH_KDF_X9_42 := nil;
  DH_get0_pqg := nil;
  DH_set0_pqg := nil;
  DH_get0_key := nil;
  DH_set0_key := nil;
  DH_get0_p := nil;
  DH_get0_q := nil;
  DH_get0_g := nil;
  DH_get0_priv_key := nil;
  DH_get0_pub_key := nil;
  DH_clear_flags := nil;
  DH_test_flags := nil;
  DH_set_flags := nil;
  DH_get0_engine := nil;
  DH_get_length := nil;
  DH_set_length := nil;
  DH_meth_new := nil;
  DH_meth_free := nil;
  DH_meth_dup := nil;
  DH_meth_get0_name := nil;
  DH_meth_set1_name := nil;
  DH_meth_get_flags := nil;
  DH_meth_set_flags := nil;
  DH_meth_get0_app_data := nil;
  DH_meth_set0_app_data := nil;
  DH_meth_get_generate_key := nil;
  DH_meth_set_generate_key := nil;
  DH_meth_get_compute_key := nil;
  DH_meth_set_compute_key := nil;
  DH_meth_get_bn_mod_exp := nil;
  DH_meth_set_bn_mod_exp := nil;
  DH_meth_get_init := nil;
  DH_meth_set_init := nil;
  DH_meth_get_finish := nil;
  DH_meth_set_finish := nil;
  DH_meth_get_generate_params := nil;
  DH_meth_set_generate_params := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.