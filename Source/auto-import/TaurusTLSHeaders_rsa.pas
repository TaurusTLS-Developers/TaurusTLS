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

unit TaurusTLSHeaders_rsa;

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
  Prsa_pss_params_st = ^Trsa_pss_params_st;
  Trsa_pss_params_st =   record
    hashAlgorithm: PX509_ALGOR;
    maskGenAlgorithm: PX509_ALGOR;
    saltLength: PASN1_INTEGER;
    trailerField: PASN1_INTEGER;
    maskHash: PX509_ALGOR;
  end;
  {$EXTERNALSYM Prsa_pss_params_st}

  Prsa_oaep_params_st = ^Trsa_oaep_params_st;
  Trsa_oaep_params_st =   record
    hashFunc: PX509_ALGOR;
    maskGenFunc: PX509_ALGOR;
    pSourceFunc: PX509_ALGOR;
    maskHash: PX509_ALGOR;
  end;
  {$EXTERNALSYM Prsa_oaep_params_st}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // RSA_generate_key_callback_cb = function(arg1: TIdC_INT; arg2: TIdC_INT; arg3: Pointer): void; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // RSA_meth_get_pub_enc_func_cb = function(arg1: TIdC_INT; arg2: PIdAnsiChar; arg3: PIdAnsiChar; arg4: Prsa_st; arg5: TIdC_INT): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // RSA_meth_get_mod_exp_func_cb = function(arg1: Pbignum_st; arg2: Pbignum_st; arg3: Prsa_st; arg4: Pbignum_ctx): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // RSA_meth_get_bn_mod_exp_func_cb = function(arg1: Pbignum_st; arg2: Pbignum_st; arg3: Pbignum_st; arg4: Pbignum_st; arg5: Pbignum_ctx; arg6: Pbn_mont_ctx_st): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // RSA_meth_get_init_func_cb = function(arg1: Prsa_st): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // RSA_meth_get_sign_func_cb = function(arg1: TIdC_INT; arg2: PIdAnsiChar; arg3: TIdC_UINT; arg4: PIdAnsiChar; arg5: PIdC_UINT; arg6: Prsa_st): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // RSA_meth_get_verify_func_cb = function(arg1: TIdC_INT; arg2: PIdAnsiChar; arg3: TIdC_UINT; arg4: PIdAnsiChar; arg5: TIdC_UINT; arg6: Prsa_st): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // RSA_meth_get_keygen_func_cb = function(arg1: Prsa_st; arg2: TIdC_INT; arg3: Pbignum_st; arg4: Pbn_gencb_st): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // RSA_meth_get_multi_prime_keygen_func_cb = function(arg1: Prsa_st; arg2: TIdC_INT; arg3: TIdC_INT; arg4: Pbignum_st; arg5: Pbn_gencb_st): TIdC_INT; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  OPENSSL_RSA_MAX_MODULUS_BITS = 16384;
  RSA_3 = $3;
  RSA_F4 = $10001;
  OPENSSL_RSA_FIPS_MIN_MODULUS_BITS = 2048;
  OPENSSL_RSA_SMALL_MODULUS_BITS = 3072;
  OPENSSL_RSA_MAX_PUBEXP_BITS = 64;
  RSA_ASN1_VERSION_DEFAULT = 0;
  RSA_ASN1_VERSION_MULTI = 1;
  RSA_DEFAULT_PRIME_NUM = 2;
  RSA_METHOD_FLAG_NO_CHECK = $0001;
  RSA_FLAG_CACHE_PUBLIC = $0002;
  RSA_FLAG_CACHE_PRIVATE = $0004;
  RSA_FLAG_BLINDING = $0008;
  RSA_FLAG_THREAD_SAFE = $0010;
  RSA_FLAG_EXT_PKEY = $0020;
  RSA_FLAG_NO_BLINDING = $0080;
  RSA_FLAG_NO_CONSTTIME = $0000;
  RSA_FLAG_NO_EXP_CONSTTIME = RSA_FLAG_NO_CONSTTIME;
  RSA_FLAG_TYPE_MASK = $F000;
  RSA_FLAG_TYPE_RSA = $0000;
  RSA_FLAG_TYPE_RSASSAPSS = $1000;
  RSA_FLAG_TYPE_RSAESOAEP = $2000;
  RSA_PSS_SALTLEN_DIGEST = -1;
  RSA_PSS_SALTLEN_AUTO = -2;
  RSA_PSS_SALTLEN_MAX = -3;
  RSA_PSS_SALTLEN_AUTO_DIGEST_MAX = -4;
  RSA_PSS_SALTLEN_MAX_SIGN = -2;
  EVP_PKEY_CTRL_RSA_PADDING = (EVP_PKEY_ALG_CTRL+1);
  EVP_PKEY_CTRL_RSA_PSS_SALTLEN = (EVP_PKEY_ALG_CTRL+2);
  EVP_PKEY_CTRL_RSA_KEYGEN_BITS = (EVP_PKEY_ALG_CTRL+3);
  EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP = (EVP_PKEY_ALG_CTRL+4);
  EVP_PKEY_CTRL_RSA_MGF1_MD = (EVP_PKEY_ALG_CTRL+5);
  EVP_PKEY_CTRL_GET_RSA_PADDING = (EVP_PKEY_ALG_CTRL+6);
  EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN = (EVP_PKEY_ALG_CTRL+7);
  EVP_PKEY_CTRL_GET_RSA_MGF1_MD = (EVP_PKEY_ALG_CTRL+8);
  EVP_PKEY_CTRL_RSA_OAEP_MD = (EVP_PKEY_ALG_CTRL+9);
  EVP_PKEY_CTRL_RSA_OAEP_LABEL = (EVP_PKEY_ALG_CTRL+10);
  EVP_PKEY_CTRL_GET_RSA_OAEP_MD = (EVP_PKEY_ALG_CTRL+11);
  EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL = (EVP_PKEY_ALG_CTRL+12);
  EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES = (EVP_PKEY_ALG_CTRL+13);
  EVP_PKEY_CTRL_RSA_IMPLICIT_REJECTION = (EVP_PKEY_ALG_CTRL+14);
  RSA_PKCS1_PADDING = 1;
  RSA_NO_PADDING = 3;
  RSA_PKCS1_OAEP_PADDING = 4;
  RSA_X931_PADDING = 5;
  RSA_PKCS1_PSS_PADDING = 6;
  RSA_PKCS1_WITH_TLS_PADDING = 7;
  RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING = 8;
  RSA_PKCS1_PADDING_SIZE = 11;
  RSA_FLAG_FIPS_METHOD = $0400;
  RSA_FLAG_NON_FIPS_ALLOW = $0400;
  RSA_FLAG_CHECKED = $0800;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  EVP_PKEY_CTX_set_rsa_padding: function(ctx: PEVP_PKEY_CTX; pad_mode: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_padding}

  EVP_PKEY_CTX_get_rsa_padding: function(ctx: PEVP_PKEY_CTX; pad_mode: PIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_get_rsa_padding}

  EVP_PKEY_CTX_set_rsa_pss_saltlen: function(ctx: PEVP_PKEY_CTX; saltlen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_pss_saltlen}

  EVP_PKEY_CTX_get_rsa_pss_saltlen: function(ctx: PEVP_PKEY_CTX; saltlen: PIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_get_rsa_pss_saltlen}

  EVP_PKEY_CTX_set_rsa_keygen_bits: function(ctx: PEVP_PKEY_CTX; bits: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_keygen_bits}

  EVP_PKEY_CTX_set1_rsa_keygen_pubexp: function(ctx: PEVP_PKEY_CTX; pubexp: PBIGNUM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set1_rsa_keygen_pubexp}

  EVP_PKEY_CTX_set_rsa_keygen_primes: function(ctx: PEVP_PKEY_CTX; primes: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_keygen_primes}

  EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen: function(ctx: PEVP_PKEY_CTX; saltlen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen}

  EVP_PKEY_CTX_set_rsa_keygen_pubexp: function(ctx: PEVP_PKEY_CTX; pubexp: PBIGNUM): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_keygen_pubexp}

  EVP_PKEY_CTX_set_rsa_mgf1_md: function(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_mgf1_md}

  EVP_PKEY_CTX_set_rsa_mgf1_md_name: function(ctx: PEVP_PKEY_CTX; mdname: PIdAnsiChar; mdprops: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_mgf1_md_name}

  EVP_PKEY_CTX_get_rsa_mgf1_md: function(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_get_rsa_mgf1_md}

  EVP_PKEY_CTX_get_rsa_mgf1_md_name: function(ctx: PEVP_PKEY_CTX; name: PIdAnsiChar; namelen: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_get_rsa_mgf1_md_name}

  EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md: function(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md}

  EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name: function(ctx: PEVP_PKEY_CTX; mdname: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name}

  EVP_PKEY_CTX_set_rsa_pss_keygen_md: function(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_pss_keygen_md}

  EVP_PKEY_CTX_set_rsa_pss_keygen_md_name: function(ctx: PEVP_PKEY_CTX; mdname: PIdAnsiChar; mdprops: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_pss_keygen_md_name}

  EVP_PKEY_CTX_set_rsa_oaep_md: function(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_oaep_md}

  EVP_PKEY_CTX_set_rsa_oaep_md_name: function(ctx: PEVP_PKEY_CTX; mdname: PIdAnsiChar; mdprops: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_oaep_md_name}

  EVP_PKEY_CTX_get_rsa_oaep_md: function(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_get_rsa_oaep_md}

  EVP_PKEY_CTX_get_rsa_oaep_md_name: function(ctx: PEVP_PKEY_CTX; name: PIdAnsiChar; namelen: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_get_rsa_oaep_md_name}

  EVP_PKEY_CTX_set0_rsa_oaep_label: function(ctx: PEVP_PKEY_CTX; _label: Pointer; llen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set0_rsa_oaep_label}

  EVP_PKEY_CTX_get0_rsa_oaep_label: function(ctx: PEVP_PKEY_CTX; _label: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_get0_rsa_oaep_label}

  RSA_new: function: PRSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_new}

  RSA_new_method: function(engine: PENGINE): PRSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_new_method}

  RSA_bits: function(rsa: PRSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_bits}

  RSA_size: function(rsa: PRSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_size}

  RSA_security_bits: function(rsa: PRSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_security_bits}

  RSA_set0_key: function(r: PRSA; n: PBIGNUM; e: PBIGNUM; d: PBIGNUM): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_set0_key}

  RSA_set0_factors: function(r: PRSA; p: PBIGNUM; q: PBIGNUM): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_set0_factors}

  RSA_set0_crt_params: function(r: PRSA; dmp1: PBIGNUM; dmq1: PBIGNUM; iqmp: PBIGNUM): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_set0_crt_params}

  RSA_set0_multi_prime_params: function(r: PRSA; primes: PPBIGNUM; exps: PPBIGNUM; coeffs: PPBIGNUM; pnum: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_set0_multi_prime_params}

  RSA_get0_key: function(r: PRSA; n: PPBIGNUM; e: PPBIGNUM; d: PPBIGNUM): void; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_get0_key}

  RSA_get0_factors: function(r: PRSA; p: PPBIGNUM; q: PPBIGNUM): void; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_get0_factors}

  RSA_get_multi_prime_extra_count: function(r: PRSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_get_multi_prime_extra_count}

  RSA_get0_multi_prime_factors: function(r: PRSA; primes: PPBIGNUM): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_get0_multi_prime_factors}

  RSA_get0_crt_params: function(r: PRSA; dmp1: PPBIGNUM; dmq1: PPBIGNUM; iqmp: PPBIGNUM): void; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_get0_crt_params}

  RSA_get0_multi_prime_crt_params: function(r: PRSA; exps: PPBIGNUM; coeffs: PPBIGNUM): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_get0_multi_prime_crt_params}

  RSA_get0_n: function(d: PRSA): PBIGNUM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_get0_n}

  RSA_get0_e: function(d: PRSA): PBIGNUM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_get0_e}

  RSA_get0_d: function(d: PRSA): PBIGNUM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_get0_d}

  RSA_get0_p: function(d: PRSA): PBIGNUM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_get0_p}

  RSA_get0_q: function(d: PRSA): PBIGNUM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_get0_q}

  RSA_get0_dmp1: function(r: PRSA): PBIGNUM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_get0_dmp1}

  RSA_get0_dmq1: function(r: PRSA): PBIGNUM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_get0_dmq1}

  RSA_get0_iqmp: function(r: PRSA): PBIGNUM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_get0_iqmp}

  RSA_get0_pss_params: function(r: PRSA): PRSA_PSS_PARAMS; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_get0_pss_params}

  RSA_clear_flags: function(r: PRSA; flags: TIdC_INT): void; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_clear_flags}

  RSA_test_flags: function(r: PRSA; flags: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_test_flags}

  RSA_set_flags: function(r: PRSA; flags: TIdC_INT): void; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_set_flags}

  RSA_get_version: function(r: PRSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_get_version}

  RSA_get0_engine: function(r: PRSA): PENGINE; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_get0_engine}

  RSA_generate_key_ex: function(rsa: PRSA; bits: TIdC_INT; e: PBIGNUM; cb: PBN_GENCB): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_generate_key_ex}

  RSA_generate_multi_prime_key: function(rsa: PRSA; bits: TIdC_INT; primes: TIdC_INT; e: PBIGNUM; cb: PBN_GENCB): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_generate_multi_prime_key}

  RSA_X931_derive_ex: function(rsa: PRSA; p1: PBIGNUM; p2: PBIGNUM; q1: PBIGNUM; q2: PBIGNUM; Xp1: PBIGNUM; Xp2: PBIGNUM; Xp: PBIGNUM; Xq1: PBIGNUM; Xq2: PBIGNUM; Xq: PBIGNUM; e: PBIGNUM; cb: PBN_GENCB): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_X931_derive_ex}

  RSA_X931_generate_key_ex: function(rsa: PRSA; bits: TIdC_INT; e: PBIGNUM; cb: PBN_GENCB): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_X931_generate_key_ex}

  RSA_check_key: function(arg1: PRSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_check_key}

  RSA_check_key_ex: function(arg1: PRSA; cb: PBN_GENCB): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_check_key_ex}

  RSA_public_encrypt: function(flen: TIdC_INT; from: PIdAnsiChar; _to: PIdAnsiChar; rsa: PRSA; padding: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_public_encrypt}

  RSA_private_encrypt: function(flen: TIdC_INT; from: PIdAnsiChar; _to: PIdAnsiChar; rsa: PRSA; padding: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_private_encrypt}

  RSA_public_decrypt: function(flen: TIdC_INT; from: PIdAnsiChar; _to: PIdAnsiChar; rsa: PRSA; padding: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_public_decrypt}

  RSA_private_decrypt: function(flen: TIdC_INT; from: PIdAnsiChar; _to: PIdAnsiChar; rsa: PRSA; padding: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_private_decrypt}

  RSA_free: function(r: PRSA): void; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_free}

  RSA_up_ref: function(r: PRSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_up_ref}

  RSA_flags: function(r: PRSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_flags}

  RSA_set_default_method: function(meth: PRSA_METHOD): void; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_set_default_method}

  RSA_get_default_method: function: PRSA_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_get_default_method}

  RSA_null_method: function: PRSA_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_null_method}

  RSA_get_method: function(rsa: PRSA): PRSA_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_get_method}

  RSA_set_method: function(rsa: PRSA; meth: PRSA_METHOD): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_set_method}

  RSA_PKCS1_OpenSSL: function: PRSA_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_PKCS1_OpenSSL}

  d2i_RSAPublicKey: function(a: PPRSA; _in: PPIdAnsiChar; len: TIdC_LONG): PRSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM d2i_RSAPublicKey}

  i2d_RSAPublicKey: function(a: PRSA; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM i2d_RSAPublicKey}

  RSAPublicKey_it: function: PASN1_ITEM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSAPublicKey_it}

  d2i_RSAPrivateKey: function(a: PPRSA; _in: PPIdAnsiChar; len: TIdC_LONG): PRSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM d2i_RSAPrivateKey}

  i2d_RSAPrivateKey: function(a: PRSA; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM i2d_RSAPrivateKey}

  RSAPrivateKey_it: function: PASN1_ITEM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSAPrivateKey_it}

  RSA_pkey_ctx_ctrl: function(ctx: PEVP_PKEY_CTX; optype: TIdC_INT; cmd: TIdC_INT; p1: TIdC_INT; p2: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_pkey_ctx_ctrl}

  RSA_PSS_PARAMS_new: function: PRSA_PSS_PARAMS; cdecl = nil;
  {$EXTERNALSYM RSA_PSS_PARAMS_new}

  RSA_PSS_PARAMS_free: function(a: PRSA_PSS_PARAMS): void; cdecl = nil;
  {$EXTERNALSYM RSA_PSS_PARAMS_free}

  d2i_RSA_PSS_PARAMS: function(a: PPRSA_PSS_PARAMS; _in: PPIdAnsiChar; len: TIdC_LONG): PRSA_PSS_PARAMS; cdecl = nil;
  {$EXTERNALSYM d2i_RSA_PSS_PARAMS}

  i2d_RSA_PSS_PARAMS: function(a: PRSA_PSS_PARAMS; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_RSA_PSS_PARAMS}

  RSA_PSS_PARAMS_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM RSA_PSS_PARAMS_it}

  RSA_PSS_PARAMS_dup: function(a: PRSA_PSS_PARAMS): PRSA_PSS_PARAMS; cdecl = nil;
  {$EXTERNALSYM RSA_PSS_PARAMS_dup}

  RSA_OAEP_PARAMS_new: function: PRSA_OAEP_PARAMS; cdecl = nil;
  {$EXTERNALSYM RSA_OAEP_PARAMS_new}

  RSA_OAEP_PARAMS_free: function(a: PRSA_OAEP_PARAMS): void; cdecl = nil;
  {$EXTERNALSYM RSA_OAEP_PARAMS_free}

  d2i_RSA_OAEP_PARAMS: function(a: PPRSA_OAEP_PARAMS; _in: PPIdAnsiChar; len: TIdC_LONG): PRSA_OAEP_PARAMS; cdecl = nil;
  {$EXTERNALSYM d2i_RSA_OAEP_PARAMS}

  i2d_RSA_OAEP_PARAMS: function(a: PRSA_OAEP_PARAMS; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_RSA_OAEP_PARAMS}

  RSA_OAEP_PARAMS_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM RSA_OAEP_PARAMS_it}

  RSA_print_fp: function(fp: PFILE; r: PRSA; offset: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_print_fp}

  RSA_print: function(bp: PBIO; r: PRSA; offset: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_print}

  RSA_sign: function(_type: TIdC_INT; m: PIdAnsiChar; m_length: TIdC_UINT; sigret: PIdAnsiChar; siglen: PIdC_UINT; rsa: PRSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_sign}

  RSA_verify: function(_type: TIdC_INT; m: PIdAnsiChar; m_length: TIdC_UINT; sigbuf: PIdAnsiChar; siglen: TIdC_UINT; rsa: PRSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_verify}

  RSA_sign_ASN1_OCTET_STRING: function(_type: TIdC_INT; m: PIdAnsiChar; m_length: TIdC_UINT; sigret: PIdAnsiChar; siglen: PIdC_UINT; rsa: PRSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_sign_ASN1_OCTET_STRING}

  RSA_verify_ASN1_OCTET_STRING: function(_type: TIdC_INT; m: PIdAnsiChar; m_length: TIdC_UINT; sigbuf: PIdAnsiChar; siglen: TIdC_UINT; rsa: PRSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_verify_ASN1_OCTET_STRING}

  RSA_blinding_on: function(rsa: PRSA; ctx: PBN_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_blinding_on}

  RSA_blinding_off: function(rsa: PRSA): void; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_blinding_off}

  RSA_setup_blinding: function(rsa: PRSA; ctx: PBN_CTX): PBN_BLINDING; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_setup_blinding}

  RSA_padding_add_PKCS1_type_1: function(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_padding_add_PKCS1_type_1}

  RSA_padding_check_PKCS1_type_1: function(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_padding_check_PKCS1_type_1}

  RSA_padding_add_PKCS1_type_2: function(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_padding_add_PKCS1_type_2}

  RSA_padding_check_PKCS1_type_2: function(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_padding_check_PKCS1_type_2}

  PKCS1_MGF1: function(mask: PIdAnsiChar; len: TIdC_LONG; seed: PIdAnsiChar; seedlen: TIdC_LONG; dgst: PEVP_MD): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PKCS1_MGF1}

  RSA_padding_add_PKCS1_OAEP: function(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT; p: PIdAnsiChar; pl: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_padding_add_PKCS1_OAEP}

  RSA_padding_check_PKCS1_OAEP: function(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT; rsa_len: TIdC_INT; p: PIdAnsiChar; pl: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_padding_check_PKCS1_OAEP}

  RSA_padding_add_PKCS1_OAEP_mgf1: function(_to: PIdAnsiChar; tlen: TIdC_INT; from: PIdAnsiChar; flen: TIdC_INT; param: PIdAnsiChar; plen: TIdC_INT; md: PEVP_MD; mgf1md: PEVP_MD): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_padding_add_PKCS1_OAEP_mgf1}

  RSA_padding_check_PKCS1_OAEP_mgf1: function(_to: PIdAnsiChar; tlen: TIdC_INT; from: PIdAnsiChar; flen: TIdC_INT; num: TIdC_INT; param: PIdAnsiChar; plen: TIdC_INT; md: PEVP_MD; mgf1md: PEVP_MD): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_padding_check_PKCS1_OAEP_mgf1}

  RSA_padding_add_none: function(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_padding_add_none}

  RSA_padding_check_none: function(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_padding_check_none}

  RSA_padding_add_X931: function(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_padding_add_X931}

  RSA_padding_check_X931: function(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_padding_check_X931}

  RSA_X931_hash_id: function(nid: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_X931_hash_id}

  RSA_verify_PKCS1_PSS: function(rsa: PRSA; mHash: PIdAnsiChar; Hash: PEVP_MD; EM: PIdAnsiChar; sLen: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_verify_PKCS1_PSS}

  RSA_padding_add_PKCS1_PSS: function(rsa: PRSA; EM: PIdAnsiChar; mHash: PIdAnsiChar; Hash: PEVP_MD; sLen: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_padding_add_PKCS1_PSS}

  RSA_verify_PKCS1_PSS_mgf1: function(rsa: PRSA; mHash: PIdAnsiChar; Hash: PEVP_MD; mgf1Hash: PEVP_MD; EM: PIdAnsiChar; sLen: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_verify_PKCS1_PSS_mgf1}

  RSA_padding_add_PKCS1_PSS_mgf1: function(rsa: PRSA; EM: PIdAnsiChar; mHash: PIdAnsiChar; Hash: PEVP_MD; mgf1Hash: PEVP_MD; sLen: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_padding_add_PKCS1_PSS_mgf1}

  RSA_set_ex_data: function(r: PRSA; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_set_ex_data}

  RSA_get_ex_data: function(r: PRSA; idx: TIdC_INT): Pointer; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_get_ex_data}

  RSAPublicKey_dup: function(a: PRSA): PRSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSAPublicKey_dup}

  RSAPrivateKey_dup: function(a: PRSA): PRSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSAPrivateKey_dup}

  RSA_meth_new: function(name: PIdAnsiChar; flags: TIdC_INT): PRSA_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_new}

  RSA_meth_free: function(meth: PRSA_METHOD): void; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_free}

  RSA_meth_dup: function(meth: PRSA_METHOD): PRSA_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_dup}

  RSA_meth_get0_name: function(meth: PRSA_METHOD): PIdAnsiChar; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_get0_name}

  RSA_meth_set1_name: function(meth: PRSA_METHOD; name: PIdAnsiChar): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_set1_name}

  RSA_meth_get_flags: function(meth: PRSA_METHOD): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_get_flags}

  RSA_meth_set_flags: function(meth: PRSA_METHOD; flags: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_set_flags}

  RSA_meth_get0_app_data: function(meth: PRSA_METHOD): Pointer; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_get0_app_data}

  RSA_meth_set0_app_data: function(meth: PRSA_METHOD; app_data: Pointer): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_set0_app_data}

  RSA_meth_get_pub_enc: function(meth: PRSA_METHOD): TRSA_meth_get_pub_enc_func_cb; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_get_pub_enc}

  RSA_meth_set_pub_enc: function(rsa: PRSA_METHOD; pub_enc: TRSA_meth_get_pub_enc_func_cb): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_set_pub_enc}

  RSA_meth_get_pub_dec: function(meth: PRSA_METHOD): TRSA_meth_get_pub_enc_func_cb; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_get_pub_dec}

  RSA_meth_set_pub_dec: function(rsa: PRSA_METHOD; pub_dec: TRSA_meth_get_pub_enc_func_cb): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_set_pub_dec}

  RSA_meth_get_priv_enc: function(meth: PRSA_METHOD): TRSA_meth_get_pub_enc_func_cb; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_get_priv_enc}

  RSA_meth_set_priv_enc: function(rsa: PRSA_METHOD; priv_enc: TRSA_meth_get_pub_enc_func_cb): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_set_priv_enc}

  RSA_meth_get_priv_dec: function(meth: PRSA_METHOD): TRSA_meth_get_pub_enc_func_cb; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_get_priv_dec}

  RSA_meth_set_priv_dec: function(rsa: PRSA_METHOD; priv_dec: TRSA_meth_get_pub_enc_func_cb): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_set_priv_dec}

  RSA_meth_get_mod_exp: function(meth: PRSA_METHOD): TRSA_meth_get_mod_exp_func_cb; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_get_mod_exp}

  RSA_meth_set_mod_exp: function(rsa: PRSA_METHOD; mod_exp: TRSA_meth_get_mod_exp_func_cb): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_set_mod_exp}

  RSA_meth_get_bn_mod_exp: function(meth: PRSA_METHOD): TRSA_meth_get_bn_mod_exp_func_cb; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_get_bn_mod_exp}

  RSA_meth_set_bn_mod_exp: function(rsa: PRSA_METHOD; bn_mod_exp: TRSA_meth_get_bn_mod_exp_func_cb): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_set_bn_mod_exp}

  RSA_meth_get_init: function(meth: PRSA_METHOD): TRSA_meth_get_init_func_cb; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_get_init}

  RSA_meth_set_init: function(rsa: PRSA_METHOD; init: TRSA_meth_get_init_func_cb): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_set_init}

  RSA_meth_get_finish: function(meth: PRSA_METHOD): TRSA_meth_get_init_func_cb; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_get_finish}

  RSA_meth_set_finish: function(rsa: PRSA_METHOD; finish: TRSA_meth_get_init_func_cb): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_set_finish}

  RSA_meth_get_sign: function(meth: PRSA_METHOD): TRSA_meth_get_sign_func_cb; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_get_sign}

  RSA_meth_set_sign: function(rsa: PRSA_METHOD; sign: TRSA_meth_get_sign_func_cb): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_set_sign}

  RSA_meth_get_verify: function(meth: PRSA_METHOD): TRSA_meth_get_verify_func_cb; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_get_verify}

  RSA_meth_set_verify: function(rsa: PRSA_METHOD; verify: TRSA_meth_get_verify_func_cb): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_set_verify}

  RSA_meth_get_keygen: function(meth: PRSA_METHOD): TRSA_meth_get_keygen_func_cb; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_get_keygen}

  RSA_meth_set_keygen: function(rsa: PRSA_METHOD; keygen: TRSA_meth_get_keygen_func_cb): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_set_keygen}

  RSA_meth_get_multi_prime_keygen: function(meth: PRSA_METHOD): TRSA_meth_get_multi_prime_keygen_func_cb; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_get_multi_prime_keygen}

  RSA_meth_set_multi_prime_keygen: function(meth: PRSA_METHOD; keygen: TRSA_meth_get_multi_prime_keygen_func_cb): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM RSA_meth_set_multi_prime_keygen}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function EVP_PKEY_CTX_set_rsa_padding(ctx: PEVP_PKEY_CTX; pad_mode: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_get_rsa_padding(ctx: PEVP_PKEY_CTX; pad_mode: PIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx: PEVP_PKEY_CTX; saltlen: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx: PEVP_PKEY_CTX; saltlen: PIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_rsa_keygen_bits(ctx: PEVP_PKEY_CTX; bits: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx: PEVP_PKEY_CTX; pubexp: PBIGNUM): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_rsa_keygen_primes(ctx: PEVP_PKEY_CTX; primes: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx: PEVP_PKEY_CTX; saltlen: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx: PEVP_PKEY_CTX; pubexp: PBIGNUM): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EVP_PKEY_CTX_set_rsa_mgf1_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx: PEVP_PKEY_CTX; mdname: PIdAnsiChar; mdprops: PIdAnsiChar): TIdC_INT; cdecl;
function EVP_PKEY_CTX_get_rsa_mgf1_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TIdC_INT; cdecl;
function EVP_PKEY_CTX_get_rsa_mgf1_md_name(ctx: PEVP_PKEY_CTX; name: PIdAnsiChar; namelen: TIdC_SIZET): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(ctx: PEVP_PKEY_CTX; mdname: PIdAnsiChar): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(ctx: PEVP_PKEY_CTX; mdname: PIdAnsiChar; mdprops: PIdAnsiChar): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_rsa_oaep_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_rsa_oaep_md_name(ctx: PEVP_PKEY_CTX; mdname: PIdAnsiChar; mdprops: PIdAnsiChar): TIdC_INT; cdecl;
function EVP_PKEY_CTX_get_rsa_oaep_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TIdC_INT; cdecl;
function EVP_PKEY_CTX_get_rsa_oaep_md_name(ctx: PEVP_PKEY_CTX; name: PIdAnsiChar; namelen: TIdC_SIZET): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set0_rsa_oaep_label(ctx: PEVP_PKEY_CTX; _label: Pointer; llen: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_get0_rsa_oaep_label(ctx: PEVP_PKEY_CTX; _label: PPIdAnsiChar): TIdC_INT; cdecl;
function RSA_new: PRSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_new_method(engine: PENGINE): PRSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_bits(rsa: PRSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_size(rsa: PRSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_security_bits(rsa: PRSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_set0_key(r: PRSA; n: PBIGNUM; e: PBIGNUM; d: PBIGNUM): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_set0_factors(r: PRSA; p: PBIGNUM; q: PBIGNUM): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_set0_crt_params(r: PRSA; dmp1: PBIGNUM; dmq1: PBIGNUM; iqmp: PBIGNUM): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_set0_multi_prime_params(r: PRSA; primes: PPBIGNUM; exps: PPBIGNUM; coeffs: PPBIGNUM; pnum: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_get0_key(r: PRSA; n: PPBIGNUM; e: PPBIGNUM; d: PPBIGNUM): void; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_get0_factors(r: PRSA; p: PPBIGNUM; q: PPBIGNUM): void; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_get_multi_prime_extra_count(r: PRSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_get0_multi_prime_factors(r: PRSA; primes: PPBIGNUM): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_get0_crt_params(r: PRSA; dmp1: PPBIGNUM; dmq1: PPBIGNUM; iqmp: PPBIGNUM): void; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_get0_multi_prime_crt_params(r: PRSA; exps: PPBIGNUM; coeffs: PPBIGNUM): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_get0_n(d: PRSA): PBIGNUM; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_get0_e(d: PRSA): PBIGNUM; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_get0_d(d: PRSA): PBIGNUM; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_get0_p(d: PRSA): PBIGNUM; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_get0_q(d: PRSA): PBIGNUM; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_get0_dmp1(r: PRSA): PBIGNUM; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_get0_dmq1(r: PRSA): PBIGNUM; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_get0_iqmp(r: PRSA): PBIGNUM; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_get0_pss_params(r: PRSA): PRSA_PSS_PARAMS; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_clear_flags(r: PRSA; flags: TIdC_INT): void; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_test_flags(r: PRSA; flags: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_set_flags(r: PRSA; flags: TIdC_INT): void; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_get_version(r: PRSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_get0_engine(r: PRSA): PENGINE; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_generate_key_ex(rsa: PRSA; bits: TIdC_INT; e: PBIGNUM; cb: PBN_GENCB): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_generate_multi_prime_key(rsa: PRSA; bits: TIdC_INT; primes: TIdC_INT; e: PBIGNUM; cb: PBN_GENCB): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_X931_derive_ex(rsa: PRSA; p1: PBIGNUM; p2: PBIGNUM; q1: PBIGNUM; q2: PBIGNUM; Xp1: PBIGNUM; Xp2: PBIGNUM; Xp: PBIGNUM; Xq1: PBIGNUM; Xq2: PBIGNUM; Xq: PBIGNUM; e: PBIGNUM; cb: PBN_GENCB): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_X931_generate_key_ex(rsa: PRSA; bits: TIdC_INT; e: PBIGNUM; cb: PBN_GENCB): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_check_key(arg1: PRSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_check_key_ex(arg1: PRSA; cb: PBN_GENCB): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_public_encrypt(flen: TIdC_INT; from: PIdAnsiChar; _to: PIdAnsiChar; rsa: PRSA; padding: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_private_encrypt(flen: TIdC_INT; from: PIdAnsiChar; _to: PIdAnsiChar; rsa: PRSA; padding: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_public_decrypt(flen: TIdC_INT; from: PIdAnsiChar; _to: PIdAnsiChar; rsa: PRSA; padding: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_private_decrypt(flen: TIdC_INT; from: PIdAnsiChar; _to: PIdAnsiChar; rsa: PRSA; padding: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_free(r: PRSA): void; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_up_ref(r: PRSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_flags(r: PRSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_set_default_method(meth: PRSA_METHOD): void; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_get_default_method: PRSA_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_null_method: PRSA_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_get_method(rsa: PRSA): PRSA_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_set_method(rsa: PRSA; meth: PRSA_METHOD): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_PKCS1_OpenSSL: PRSA_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function d2i_RSAPublicKey(a: PPRSA; _in: PPIdAnsiChar; len: TIdC_LONG): PRSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function i2d_RSAPublicKey(a: PRSA; _out: PPIdAnsiChar): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSAPublicKey_it: PASN1_ITEM; cdecl; deprecated 'In OpenSSL 3_0_0';
function d2i_RSAPrivateKey(a: PPRSA; _in: PPIdAnsiChar; len: TIdC_LONG): PRSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function i2d_RSAPrivateKey(a: PRSA; _out: PPIdAnsiChar): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSAPrivateKey_it: PASN1_ITEM; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_pkey_ctx_ctrl(ctx: PEVP_PKEY_CTX; optype: TIdC_INT; cmd: TIdC_INT; p1: TIdC_INT; p2: Pointer): TIdC_INT; cdecl;
function RSA_PSS_PARAMS_new: PRSA_PSS_PARAMS; cdecl;
function RSA_PSS_PARAMS_free(a: PRSA_PSS_PARAMS): void; cdecl;
function d2i_RSA_PSS_PARAMS(a: PPRSA_PSS_PARAMS; _in: PPIdAnsiChar; len: TIdC_LONG): PRSA_PSS_PARAMS; cdecl;
function i2d_RSA_PSS_PARAMS(a: PRSA_PSS_PARAMS; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function RSA_PSS_PARAMS_it: PASN1_ITEM; cdecl;
function RSA_PSS_PARAMS_dup(a: PRSA_PSS_PARAMS): PRSA_PSS_PARAMS; cdecl;
function RSA_OAEP_PARAMS_new: PRSA_OAEP_PARAMS; cdecl;
function RSA_OAEP_PARAMS_free(a: PRSA_OAEP_PARAMS): void; cdecl;
function d2i_RSA_OAEP_PARAMS(a: PPRSA_OAEP_PARAMS; _in: PPIdAnsiChar; len: TIdC_LONG): PRSA_OAEP_PARAMS; cdecl;
function i2d_RSA_OAEP_PARAMS(a: PRSA_OAEP_PARAMS; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function RSA_OAEP_PARAMS_it: PASN1_ITEM; cdecl;
function RSA_print_fp(fp: PFILE; r: PRSA; offset: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_print(bp: PBIO; r: PRSA; offset: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_sign(_type: TIdC_INT; m: PIdAnsiChar; m_length: TIdC_UINT; sigret: PIdAnsiChar; siglen: PIdC_UINT; rsa: PRSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_verify(_type: TIdC_INT; m: PIdAnsiChar; m_length: TIdC_UINT; sigbuf: PIdAnsiChar; siglen: TIdC_UINT; rsa: PRSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_sign_ASN1_OCTET_STRING(_type: TIdC_INT; m: PIdAnsiChar; m_length: TIdC_UINT; sigret: PIdAnsiChar; siglen: PIdC_UINT; rsa: PRSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_verify_ASN1_OCTET_STRING(_type: TIdC_INT; m: PIdAnsiChar; m_length: TIdC_UINT; sigbuf: PIdAnsiChar; siglen: TIdC_UINT; rsa: PRSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_blinding_on(rsa: PRSA; ctx: PBN_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_blinding_off(rsa: PRSA): void; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_setup_blinding(rsa: PRSA; ctx: PBN_CTX): PBN_BLINDING; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_padding_add_PKCS1_type_1(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_padding_check_PKCS1_type_1(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_padding_add_PKCS1_type_2(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_padding_check_PKCS1_type_2(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function PKCS1_MGF1(mask: PIdAnsiChar; len: TIdC_LONG; seed: PIdAnsiChar; seedlen: TIdC_LONG; dgst: PEVP_MD): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_padding_add_PKCS1_OAEP(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT; p: PIdAnsiChar; pl: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_padding_check_PKCS1_OAEP(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT; rsa_len: TIdC_INT; p: PIdAnsiChar; pl: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_padding_add_PKCS1_OAEP_mgf1(_to: PIdAnsiChar; tlen: TIdC_INT; from: PIdAnsiChar; flen: TIdC_INT; param: PIdAnsiChar; plen: TIdC_INT; md: PEVP_MD; mgf1md: PEVP_MD): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_padding_check_PKCS1_OAEP_mgf1(_to: PIdAnsiChar; tlen: TIdC_INT; from: PIdAnsiChar; flen: TIdC_INT; num: TIdC_INT; param: PIdAnsiChar; plen: TIdC_INT; md: PEVP_MD; mgf1md: PEVP_MD): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_padding_add_none(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_padding_check_none(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_padding_add_X931(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_padding_check_X931(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_X931_hash_id(nid: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_verify_PKCS1_PSS(rsa: PRSA; mHash: PIdAnsiChar; Hash: PEVP_MD; EM: PIdAnsiChar; sLen: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_padding_add_PKCS1_PSS(rsa: PRSA; EM: PIdAnsiChar; mHash: PIdAnsiChar; Hash: PEVP_MD; sLen: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_verify_PKCS1_PSS_mgf1(rsa: PRSA; mHash: PIdAnsiChar; Hash: PEVP_MD; mgf1Hash: PEVP_MD; EM: PIdAnsiChar; sLen: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_padding_add_PKCS1_PSS_mgf1(rsa: PRSA; EM: PIdAnsiChar; mHash: PIdAnsiChar; Hash: PEVP_MD; mgf1Hash: PEVP_MD; sLen: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_set_ex_data(r: PRSA; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_get_ex_data(r: PRSA; idx: TIdC_INT): Pointer; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSAPublicKey_dup(a: PRSA): PRSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSAPrivateKey_dup(a: PRSA): PRSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_new(name: PIdAnsiChar; flags: TIdC_INT): PRSA_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_free(meth: PRSA_METHOD): void; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_dup(meth: PRSA_METHOD): PRSA_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_get0_name(meth: PRSA_METHOD): PIdAnsiChar; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_set1_name(meth: PRSA_METHOD; name: PIdAnsiChar): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_get_flags(meth: PRSA_METHOD): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_set_flags(meth: PRSA_METHOD; flags: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_get0_app_data(meth: PRSA_METHOD): Pointer; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_set0_app_data(meth: PRSA_METHOD; app_data: Pointer): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_get_pub_enc(meth: PRSA_METHOD): TRSA_meth_get_pub_enc_func_cb; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_set_pub_enc(rsa: PRSA_METHOD; pub_enc: TRSA_meth_get_pub_enc_func_cb): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_get_pub_dec(meth: PRSA_METHOD): TRSA_meth_get_pub_enc_func_cb; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_set_pub_dec(rsa: PRSA_METHOD; pub_dec: TRSA_meth_get_pub_enc_func_cb): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_get_priv_enc(meth: PRSA_METHOD): TRSA_meth_get_pub_enc_func_cb; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_set_priv_enc(rsa: PRSA_METHOD; priv_enc: TRSA_meth_get_pub_enc_func_cb): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_get_priv_dec(meth: PRSA_METHOD): TRSA_meth_get_pub_enc_func_cb; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_set_priv_dec(rsa: PRSA_METHOD; priv_dec: TRSA_meth_get_pub_enc_func_cb): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_get_mod_exp(meth: PRSA_METHOD): TRSA_meth_get_mod_exp_func_cb; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_set_mod_exp(rsa: PRSA_METHOD; mod_exp: TRSA_meth_get_mod_exp_func_cb): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_get_bn_mod_exp(meth: PRSA_METHOD): TRSA_meth_get_bn_mod_exp_func_cb; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_set_bn_mod_exp(rsa: PRSA_METHOD; bn_mod_exp: TRSA_meth_get_bn_mod_exp_func_cb): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_get_init(meth: PRSA_METHOD): TRSA_meth_get_init_func_cb; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_set_init(rsa: PRSA_METHOD; init: TRSA_meth_get_init_func_cb): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_get_finish(meth: PRSA_METHOD): TRSA_meth_get_init_func_cb; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_set_finish(rsa: PRSA_METHOD; finish: TRSA_meth_get_init_func_cb): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_get_sign(meth: PRSA_METHOD): TRSA_meth_get_sign_func_cb; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_set_sign(rsa: PRSA_METHOD; sign: TRSA_meth_get_sign_func_cb): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_get_verify(meth: PRSA_METHOD): TRSA_meth_get_verify_func_cb; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_set_verify(rsa: PRSA_METHOD; verify: TRSA_meth_get_verify_func_cb): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_get_keygen(meth: PRSA_METHOD): TRSA_meth_get_keygen_func_cb; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_set_keygen(rsa: PRSA_METHOD; keygen: TRSA_meth_get_keygen_func_cb): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_get_multi_prime_keygen(meth: PRSA_METHOD): TRSA_meth_get_multi_prime_keygen_func_cb; cdecl; deprecated 'In OpenSSL 3_0_0';
function RSA_meth_set_multi_prime_keygen(meth: PRSA_METHOD; keygen: TRSA_meth_get_multi_prime_keygen_func_cb): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function EVP_RSA_gen(bits: Pointer): TIdC_INT; cdecl;


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

function EVP_PKEY_CTX_set_rsa_padding(ctx: PEVP_PKEY_CTX; pad_mode: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_padding';
function EVP_PKEY_CTX_get_rsa_padding(ctx: PEVP_PKEY_CTX; pad_mode: PIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_get_rsa_padding';
function EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx: PEVP_PKEY_CTX; saltlen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_pss_saltlen';
function EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx: PEVP_PKEY_CTX; saltlen: PIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_get_rsa_pss_saltlen';
function EVP_PKEY_CTX_set_rsa_keygen_bits(ctx: PEVP_PKEY_CTX; bits: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_keygen_bits';
function EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx: PEVP_PKEY_CTX; pubexp: PBIGNUM): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set1_rsa_keygen_pubexp';
function EVP_PKEY_CTX_set_rsa_keygen_primes(ctx: PEVP_PKEY_CTX; primes: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_keygen_primes';
function EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx: PEVP_PKEY_CTX; saltlen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen';
function EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx: PEVP_PKEY_CTX; pubexp: PBIGNUM): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_keygen_pubexp';
function EVP_PKEY_CTX_set_rsa_mgf1_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_mgf1_md';
function EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx: PEVP_PKEY_CTX; mdname: PIdAnsiChar; mdprops: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_mgf1_md_name';
function EVP_PKEY_CTX_get_rsa_mgf1_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_get_rsa_mgf1_md';
function EVP_PKEY_CTX_get_rsa_mgf1_md_name(ctx: PEVP_PKEY_CTX; name: PIdAnsiChar; namelen: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_get_rsa_mgf1_md_name';
function EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md';
function EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(ctx: PEVP_PKEY_CTX; mdname: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name';
function EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_pss_keygen_md';
function EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(ctx: PEVP_PKEY_CTX; mdname: PIdAnsiChar; mdprops: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_pss_keygen_md_name';
function EVP_PKEY_CTX_set_rsa_oaep_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_oaep_md';
function EVP_PKEY_CTX_set_rsa_oaep_md_name(ctx: PEVP_PKEY_CTX; mdname: PIdAnsiChar; mdprops: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_oaep_md_name';
function EVP_PKEY_CTX_get_rsa_oaep_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_get_rsa_oaep_md';
function EVP_PKEY_CTX_get_rsa_oaep_md_name(ctx: PEVP_PKEY_CTX; name: PIdAnsiChar; namelen: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_get_rsa_oaep_md_name';
function EVP_PKEY_CTX_set0_rsa_oaep_label(ctx: PEVP_PKEY_CTX; _label: Pointer; llen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set0_rsa_oaep_label';
function EVP_PKEY_CTX_get0_rsa_oaep_label(ctx: PEVP_PKEY_CTX; _label: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_get0_rsa_oaep_label';
function RSA_new: PRSA; cdecl external CLibCrypto name 'RSA_new';
function RSA_new_method(engine: PENGINE): PRSA; cdecl external CLibCrypto name 'RSA_new_method';
function RSA_bits(rsa: PRSA): TIdC_INT; cdecl external CLibCrypto name 'RSA_bits';
function RSA_size(rsa: PRSA): TIdC_INT; cdecl external CLibCrypto name 'RSA_size';
function RSA_security_bits(rsa: PRSA): TIdC_INT; cdecl external CLibCrypto name 'RSA_security_bits';
function RSA_set0_key(r: PRSA; n: PBIGNUM; e: PBIGNUM; d: PBIGNUM): TIdC_INT; cdecl external CLibCrypto name 'RSA_set0_key';
function RSA_set0_factors(r: PRSA; p: PBIGNUM; q: PBIGNUM): TIdC_INT; cdecl external CLibCrypto name 'RSA_set0_factors';
function RSA_set0_crt_params(r: PRSA; dmp1: PBIGNUM; dmq1: PBIGNUM; iqmp: PBIGNUM): TIdC_INT; cdecl external CLibCrypto name 'RSA_set0_crt_params';
function RSA_set0_multi_prime_params(r: PRSA; primes: PPBIGNUM; exps: PPBIGNUM; coeffs: PPBIGNUM; pnum: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RSA_set0_multi_prime_params';
function RSA_get0_key(r: PRSA; n: PPBIGNUM; e: PPBIGNUM; d: PPBIGNUM): void; cdecl external CLibCrypto name 'RSA_get0_key';
function RSA_get0_factors(r: PRSA; p: PPBIGNUM; q: PPBIGNUM): void; cdecl external CLibCrypto name 'RSA_get0_factors';
function RSA_get_multi_prime_extra_count(r: PRSA): TIdC_INT; cdecl external CLibCrypto name 'RSA_get_multi_prime_extra_count';
function RSA_get0_multi_prime_factors(r: PRSA; primes: PPBIGNUM): TIdC_INT; cdecl external CLibCrypto name 'RSA_get0_multi_prime_factors';
function RSA_get0_crt_params(r: PRSA; dmp1: PPBIGNUM; dmq1: PPBIGNUM; iqmp: PPBIGNUM): void; cdecl external CLibCrypto name 'RSA_get0_crt_params';
function RSA_get0_multi_prime_crt_params(r: PRSA; exps: PPBIGNUM; coeffs: PPBIGNUM): TIdC_INT; cdecl external CLibCrypto name 'RSA_get0_multi_prime_crt_params';
function RSA_get0_n(d: PRSA): PBIGNUM; cdecl external CLibCrypto name 'RSA_get0_n';
function RSA_get0_e(d: PRSA): PBIGNUM; cdecl external CLibCrypto name 'RSA_get0_e';
function RSA_get0_d(d: PRSA): PBIGNUM; cdecl external CLibCrypto name 'RSA_get0_d';
function RSA_get0_p(d: PRSA): PBIGNUM; cdecl external CLibCrypto name 'RSA_get0_p';
function RSA_get0_q(d: PRSA): PBIGNUM; cdecl external CLibCrypto name 'RSA_get0_q';
function RSA_get0_dmp1(r: PRSA): PBIGNUM; cdecl external CLibCrypto name 'RSA_get0_dmp1';
function RSA_get0_dmq1(r: PRSA): PBIGNUM; cdecl external CLibCrypto name 'RSA_get0_dmq1';
function RSA_get0_iqmp(r: PRSA): PBIGNUM; cdecl external CLibCrypto name 'RSA_get0_iqmp';
function RSA_get0_pss_params(r: PRSA): PRSA_PSS_PARAMS; cdecl external CLibCrypto name 'RSA_get0_pss_params';
function RSA_clear_flags(r: PRSA; flags: TIdC_INT): void; cdecl external CLibCrypto name 'RSA_clear_flags';
function RSA_test_flags(r: PRSA; flags: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RSA_test_flags';
function RSA_set_flags(r: PRSA; flags: TIdC_INT): void; cdecl external CLibCrypto name 'RSA_set_flags';
function RSA_get_version(r: PRSA): TIdC_INT; cdecl external CLibCrypto name 'RSA_get_version';
function RSA_get0_engine(r: PRSA): PENGINE; cdecl external CLibCrypto name 'RSA_get0_engine';
function RSA_generate_key_ex(rsa: PRSA; bits: TIdC_INT; e: PBIGNUM; cb: PBN_GENCB): TIdC_INT; cdecl external CLibCrypto name 'RSA_generate_key_ex';
function RSA_generate_multi_prime_key(rsa: PRSA; bits: TIdC_INT; primes: TIdC_INT; e: PBIGNUM; cb: PBN_GENCB): TIdC_INT; cdecl external CLibCrypto name 'RSA_generate_multi_prime_key';
function RSA_X931_derive_ex(rsa: PRSA; p1: PBIGNUM; p2: PBIGNUM; q1: PBIGNUM; q2: PBIGNUM; Xp1: PBIGNUM; Xp2: PBIGNUM; Xp: PBIGNUM; Xq1: PBIGNUM; Xq2: PBIGNUM; Xq: PBIGNUM; e: PBIGNUM; cb: PBN_GENCB): TIdC_INT; cdecl external CLibCrypto name 'RSA_X931_derive_ex';
function RSA_X931_generate_key_ex(rsa: PRSA; bits: TIdC_INT; e: PBIGNUM; cb: PBN_GENCB): TIdC_INT; cdecl external CLibCrypto name 'RSA_X931_generate_key_ex';
function RSA_check_key(arg1: PRSA): TIdC_INT; cdecl external CLibCrypto name 'RSA_check_key';
function RSA_check_key_ex(arg1: PRSA; cb: PBN_GENCB): TIdC_INT; cdecl external CLibCrypto name 'RSA_check_key_ex';
function RSA_public_encrypt(flen: TIdC_INT; from: PIdAnsiChar; _to: PIdAnsiChar; rsa: PRSA; padding: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RSA_public_encrypt';
function RSA_private_encrypt(flen: TIdC_INT; from: PIdAnsiChar; _to: PIdAnsiChar; rsa: PRSA; padding: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RSA_private_encrypt';
function RSA_public_decrypt(flen: TIdC_INT; from: PIdAnsiChar; _to: PIdAnsiChar; rsa: PRSA; padding: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RSA_public_decrypt';
function RSA_private_decrypt(flen: TIdC_INT; from: PIdAnsiChar; _to: PIdAnsiChar; rsa: PRSA; padding: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RSA_private_decrypt';
function RSA_free(r: PRSA): void; cdecl external CLibCrypto name 'RSA_free';
function RSA_up_ref(r: PRSA): TIdC_INT; cdecl external CLibCrypto name 'RSA_up_ref';
function RSA_flags(r: PRSA): TIdC_INT; cdecl external CLibCrypto name 'RSA_flags';
function RSA_set_default_method(meth: PRSA_METHOD): void; cdecl external CLibCrypto name 'RSA_set_default_method';
function RSA_get_default_method: PRSA_METHOD; cdecl external CLibCrypto name 'RSA_get_default_method';
function RSA_null_method: PRSA_METHOD; cdecl external CLibCrypto name 'RSA_null_method';
function RSA_get_method(rsa: PRSA): PRSA_METHOD; cdecl external CLibCrypto name 'RSA_get_method';
function RSA_set_method(rsa: PRSA; meth: PRSA_METHOD): TIdC_INT; cdecl external CLibCrypto name 'RSA_set_method';
function RSA_PKCS1_OpenSSL: PRSA_METHOD; cdecl external CLibCrypto name 'RSA_PKCS1_OpenSSL';
function d2i_RSAPublicKey(a: PPRSA; _in: PPIdAnsiChar; len: TIdC_LONG): PRSA; cdecl external CLibCrypto name 'd2i_RSAPublicKey';
function i2d_RSAPublicKey(a: PRSA; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_RSAPublicKey';
function RSAPublicKey_it: PASN1_ITEM; cdecl external CLibCrypto name 'RSAPublicKey_it';
function d2i_RSAPrivateKey(a: PPRSA; _in: PPIdAnsiChar; len: TIdC_LONG): PRSA; cdecl external CLibCrypto name 'd2i_RSAPrivateKey';
function i2d_RSAPrivateKey(a: PRSA; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_RSAPrivateKey';
function RSAPrivateKey_it: PASN1_ITEM; cdecl external CLibCrypto name 'RSAPrivateKey_it';
function RSA_pkey_ctx_ctrl(ctx: PEVP_PKEY_CTX; optype: TIdC_INT; cmd: TIdC_INT; p1: TIdC_INT; p2: Pointer): TIdC_INT; cdecl external CLibCrypto name 'RSA_pkey_ctx_ctrl';
function RSA_PSS_PARAMS_new: PRSA_PSS_PARAMS; cdecl external CLibCrypto name 'RSA_PSS_PARAMS_new';
function RSA_PSS_PARAMS_free(a: PRSA_PSS_PARAMS): void; cdecl external CLibCrypto name 'RSA_PSS_PARAMS_free';
function d2i_RSA_PSS_PARAMS(a: PPRSA_PSS_PARAMS; _in: PPIdAnsiChar; len: TIdC_LONG): PRSA_PSS_PARAMS; cdecl external CLibCrypto name 'd2i_RSA_PSS_PARAMS';
function i2d_RSA_PSS_PARAMS(a: PRSA_PSS_PARAMS; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_RSA_PSS_PARAMS';
function RSA_PSS_PARAMS_it: PASN1_ITEM; cdecl external CLibCrypto name 'RSA_PSS_PARAMS_it';
function RSA_PSS_PARAMS_dup(a: PRSA_PSS_PARAMS): PRSA_PSS_PARAMS; cdecl external CLibCrypto name 'RSA_PSS_PARAMS_dup';
function RSA_OAEP_PARAMS_new: PRSA_OAEP_PARAMS; cdecl external CLibCrypto name 'RSA_OAEP_PARAMS_new';
function RSA_OAEP_PARAMS_free(a: PRSA_OAEP_PARAMS): void; cdecl external CLibCrypto name 'RSA_OAEP_PARAMS_free';
function d2i_RSA_OAEP_PARAMS(a: PPRSA_OAEP_PARAMS; _in: PPIdAnsiChar; len: TIdC_LONG): PRSA_OAEP_PARAMS; cdecl external CLibCrypto name 'd2i_RSA_OAEP_PARAMS';
function i2d_RSA_OAEP_PARAMS(a: PRSA_OAEP_PARAMS; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_RSA_OAEP_PARAMS';
function RSA_OAEP_PARAMS_it: PASN1_ITEM; cdecl external CLibCrypto name 'RSA_OAEP_PARAMS_it';
function RSA_print_fp(fp: PFILE; r: PRSA; offset: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RSA_print_fp';
function RSA_print(bp: PBIO; r: PRSA; offset: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RSA_print';
function RSA_sign(_type: TIdC_INT; m: PIdAnsiChar; m_length: TIdC_UINT; sigret: PIdAnsiChar; siglen: PIdC_UINT; rsa: PRSA): TIdC_INT; cdecl external CLibCrypto name 'RSA_sign';
function RSA_verify(_type: TIdC_INT; m: PIdAnsiChar; m_length: TIdC_UINT; sigbuf: PIdAnsiChar; siglen: TIdC_UINT; rsa: PRSA): TIdC_INT; cdecl external CLibCrypto name 'RSA_verify';
function RSA_sign_ASN1_OCTET_STRING(_type: TIdC_INT; m: PIdAnsiChar; m_length: TIdC_UINT; sigret: PIdAnsiChar; siglen: PIdC_UINT; rsa: PRSA): TIdC_INT; cdecl external CLibCrypto name 'RSA_sign_ASN1_OCTET_STRING';
function RSA_verify_ASN1_OCTET_STRING(_type: TIdC_INT; m: PIdAnsiChar; m_length: TIdC_UINT; sigbuf: PIdAnsiChar; siglen: TIdC_UINT; rsa: PRSA): TIdC_INT; cdecl external CLibCrypto name 'RSA_verify_ASN1_OCTET_STRING';
function RSA_blinding_on(rsa: PRSA; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'RSA_blinding_on';
function RSA_blinding_off(rsa: PRSA): void; cdecl external CLibCrypto name 'RSA_blinding_off';
function RSA_setup_blinding(rsa: PRSA; ctx: PBN_CTX): PBN_BLINDING; cdecl external CLibCrypto name 'RSA_setup_blinding';
function RSA_padding_add_PKCS1_type_1(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RSA_padding_add_PKCS1_type_1';
function RSA_padding_check_PKCS1_type_1(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RSA_padding_check_PKCS1_type_1';
function RSA_padding_add_PKCS1_type_2(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RSA_padding_add_PKCS1_type_2';
function RSA_padding_check_PKCS1_type_2(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RSA_padding_check_PKCS1_type_2';
function PKCS1_MGF1(mask: PIdAnsiChar; len: TIdC_LONG; seed: PIdAnsiChar; seedlen: TIdC_LONG; dgst: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'PKCS1_MGF1';
function RSA_padding_add_PKCS1_OAEP(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT; p: PIdAnsiChar; pl: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RSA_padding_add_PKCS1_OAEP';
function RSA_padding_check_PKCS1_OAEP(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT; rsa_len: TIdC_INT; p: PIdAnsiChar; pl: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RSA_padding_check_PKCS1_OAEP';
function RSA_padding_add_PKCS1_OAEP_mgf1(_to: PIdAnsiChar; tlen: TIdC_INT; from: PIdAnsiChar; flen: TIdC_INT; param: PIdAnsiChar; plen: TIdC_INT; md: PEVP_MD; mgf1md: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'RSA_padding_add_PKCS1_OAEP_mgf1';
function RSA_padding_check_PKCS1_OAEP_mgf1(_to: PIdAnsiChar; tlen: TIdC_INT; from: PIdAnsiChar; flen: TIdC_INT; num: TIdC_INT; param: PIdAnsiChar; plen: TIdC_INT; md: PEVP_MD; mgf1md: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'RSA_padding_check_PKCS1_OAEP_mgf1';
function RSA_padding_add_none(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RSA_padding_add_none';
function RSA_padding_check_none(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RSA_padding_check_none';
function RSA_padding_add_X931(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RSA_padding_add_X931';
function RSA_padding_check_X931(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RSA_padding_check_X931';
function RSA_X931_hash_id(nid: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RSA_X931_hash_id';
function RSA_verify_PKCS1_PSS(rsa: PRSA; mHash: PIdAnsiChar; Hash: PEVP_MD; EM: PIdAnsiChar; sLen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RSA_verify_PKCS1_PSS';
function RSA_padding_add_PKCS1_PSS(rsa: PRSA; EM: PIdAnsiChar; mHash: PIdAnsiChar; Hash: PEVP_MD; sLen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RSA_padding_add_PKCS1_PSS';
function RSA_verify_PKCS1_PSS_mgf1(rsa: PRSA; mHash: PIdAnsiChar; Hash: PEVP_MD; mgf1Hash: PEVP_MD; EM: PIdAnsiChar; sLen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RSA_verify_PKCS1_PSS_mgf1';
function RSA_padding_add_PKCS1_PSS_mgf1(rsa: PRSA; EM: PIdAnsiChar; mHash: PIdAnsiChar; Hash: PEVP_MD; mgf1Hash: PEVP_MD; sLen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RSA_padding_add_PKCS1_PSS_mgf1';
function RSA_set_ex_data(r: PRSA; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl external CLibCrypto name 'RSA_set_ex_data';
function RSA_get_ex_data(r: PRSA; idx: TIdC_INT): Pointer; cdecl external CLibCrypto name 'RSA_get_ex_data';
function RSAPublicKey_dup(a: PRSA): PRSA; cdecl external CLibCrypto name 'RSAPublicKey_dup';
function RSAPrivateKey_dup(a: PRSA): PRSA; cdecl external CLibCrypto name 'RSAPrivateKey_dup';
function RSA_meth_new(name: PIdAnsiChar; flags: TIdC_INT): PRSA_METHOD; cdecl external CLibCrypto name 'RSA_meth_new';
function RSA_meth_free(meth: PRSA_METHOD): void; cdecl external CLibCrypto name 'RSA_meth_free';
function RSA_meth_dup(meth: PRSA_METHOD): PRSA_METHOD; cdecl external CLibCrypto name 'RSA_meth_dup';
function RSA_meth_get0_name(meth: PRSA_METHOD): PIdAnsiChar; cdecl external CLibCrypto name 'RSA_meth_get0_name';
function RSA_meth_set1_name(meth: PRSA_METHOD; name: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'RSA_meth_set1_name';
function RSA_meth_get_flags(meth: PRSA_METHOD): TIdC_INT; cdecl external CLibCrypto name 'RSA_meth_get_flags';
function RSA_meth_set_flags(meth: PRSA_METHOD; flags: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'RSA_meth_set_flags';
function RSA_meth_get0_app_data(meth: PRSA_METHOD): Pointer; cdecl external CLibCrypto name 'RSA_meth_get0_app_data';
function RSA_meth_set0_app_data(meth: PRSA_METHOD; app_data: Pointer): TIdC_INT; cdecl external CLibCrypto name 'RSA_meth_set0_app_data';
function RSA_meth_get_pub_enc(meth: PRSA_METHOD): TRSA_meth_get_pub_enc_func_cb; cdecl external CLibCrypto name 'RSA_meth_get_pub_enc';
function RSA_meth_set_pub_enc(rsa: PRSA_METHOD; pub_enc: TRSA_meth_get_pub_enc_func_cb): TIdC_INT; cdecl external CLibCrypto name 'RSA_meth_set_pub_enc';
function RSA_meth_get_pub_dec(meth: PRSA_METHOD): TRSA_meth_get_pub_enc_func_cb; cdecl external CLibCrypto name 'RSA_meth_get_pub_dec';
function RSA_meth_set_pub_dec(rsa: PRSA_METHOD; pub_dec: TRSA_meth_get_pub_enc_func_cb): TIdC_INT; cdecl external CLibCrypto name 'RSA_meth_set_pub_dec';
function RSA_meth_get_priv_enc(meth: PRSA_METHOD): TRSA_meth_get_pub_enc_func_cb; cdecl external CLibCrypto name 'RSA_meth_get_priv_enc';
function RSA_meth_set_priv_enc(rsa: PRSA_METHOD; priv_enc: TRSA_meth_get_pub_enc_func_cb): TIdC_INT; cdecl external CLibCrypto name 'RSA_meth_set_priv_enc';
function RSA_meth_get_priv_dec(meth: PRSA_METHOD): TRSA_meth_get_pub_enc_func_cb; cdecl external CLibCrypto name 'RSA_meth_get_priv_dec';
function RSA_meth_set_priv_dec(rsa: PRSA_METHOD; priv_dec: TRSA_meth_get_pub_enc_func_cb): TIdC_INT; cdecl external CLibCrypto name 'RSA_meth_set_priv_dec';
function RSA_meth_get_mod_exp(meth: PRSA_METHOD): TRSA_meth_get_mod_exp_func_cb; cdecl external CLibCrypto name 'RSA_meth_get_mod_exp';
function RSA_meth_set_mod_exp(rsa: PRSA_METHOD; mod_exp: TRSA_meth_get_mod_exp_func_cb): TIdC_INT; cdecl external CLibCrypto name 'RSA_meth_set_mod_exp';
function RSA_meth_get_bn_mod_exp(meth: PRSA_METHOD): TRSA_meth_get_bn_mod_exp_func_cb; cdecl external CLibCrypto name 'RSA_meth_get_bn_mod_exp';
function RSA_meth_set_bn_mod_exp(rsa: PRSA_METHOD; bn_mod_exp: TRSA_meth_get_bn_mod_exp_func_cb): TIdC_INT; cdecl external CLibCrypto name 'RSA_meth_set_bn_mod_exp';
function RSA_meth_get_init(meth: PRSA_METHOD): TRSA_meth_get_init_func_cb; cdecl external CLibCrypto name 'RSA_meth_get_init';
function RSA_meth_set_init(rsa: PRSA_METHOD; init: TRSA_meth_get_init_func_cb): TIdC_INT; cdecl external CLibCrypto name 'RSA_meth_set_init';
function RSA_meth_get_finish(meth: PRSA_METHOD): TRSA_meth_get_init_func_cb; cdecl external CLibCrypto name 'RSA_meth_get_finish';
function RSA_meth_set_finish(rsa: PRSA_METHOD; finish: TRSA_meth_get_init_func_cb): TIdC_INT; cdecl external CLibCrypto name 'RSA_meth_set_finish';
function RSA_meth_get_sign(meth: PRSA_METHOD): TRSA_meth_get_sign_func_cb; cdecl external CLibCrypto name 'RSA_meth_get_sign';
function RSA_meth_set_sign(rsa: PRSA_METHOD; sign: TRSA_meth_get_sign_func_cb): TIdC_INT; cdecl external CLibCrypto name 'RSA_meth_set_sign';
function RSA_meth_get_verify(meth: PRSA_METHOD): TRSA_meth_get_verify_func_cb; cdecl external CLibCrypto name 'RSA_meth_get_verify';
function RSA_meth_set_verify(rsa: PRSA_METHOD; verify: TRSA_meth_get_verify_func_cb): TIdC_INT; cdecl external CLibCrypto name 'RSA_meth_set_verify';
function RSA_meth_get_keygen(meth: PRSA_METHOD): TRSA_meth_get_keygen_func_cb; cdecl external CLibCrypto name 'RSA_meth_get_keygen';
function RSA_meth_set_keygen(rsa: PRSA_METHOD; keygen: TRSA_meth_get_keygen_func_cb): TIdC_INT; cdecl external CLibCrypto name 'RSA_meth_set_keygen';
function RSA_meth_get_multi_prime_keygen(meth: PRSA_METHOD): TRSA_meth_get_multi_prime_keygen_func_cb; cdecl external CLibCrypto name 'RSA_meth_get_multi_prime_keygen';
function RSA_meth_set_multi_prime_keygen(meth: PRSA_METHOD; keygen: TRSA_meth_get_multi_prime_keygen_func_cb): TIdC_INT; cdecl external CLibCrypto name 'RSA_meth_set_multi_prime_keygen';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  EVP_PKEY_CTX_set_rsa_padding_procname = 'EVP_PKEY_CTX_set_rsa_padding';
  EVP_PKEY_CTX_set_rsa_padding_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_get_rsa_padding_procname = 'EVP_PKEY_CTX_get_rsa_padding';
  EVP_PKEY_CTX_get_rsa_padding_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_rsa_pss_saltlen_procname = 'EVP_PKEY_CTX_set_rsa_pss_saltlen';
  EVP_PKEY_CTX_set_rsa_pss_saltlen_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_get_rsa_pss_saltlen_procname = 'EVP_PKEY_CTX_get_rsa_pss_saltlen';
  EVP_PKEY_CTX_get_rsa_pss_saltlen_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_rsa_keygen_bits_procname = 'EVP_PKEY_CTX_set_rsa_keygen_bits';
  EVP_PKEY_CTX_set_rsa_keygen_bits_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set1_rsa_keygen_pubexp_procname = 'EVP_PKEY_CTX_set1_rsa_keygen_pubexp';
  EVP_PKEY_CTX_set1_rsa_keygen_pubexp_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_rsa_keygen_primes_procname = 'EVP_PKEY_CTX_set_rsa_keygen_primes';
  EVP_PKEY_CTX_set_rsa_keygen_primes_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen_procname = 'EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen';
  EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_rsa_keygen_pubexp_procname = 'EVP_PKEY_CTX_set_rsa_keygen_pubexp';
  EVP_PKEY_CTX_set_rsa_keygen_pubexp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_rsa_mgf1_md_procname = 'EVP_PKEY_CTX_set_rsa_mgf1_md';
  EVP_PKEY_CTX_set_rsa_mgf1_md_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_rsa_mgf1_md_name_procname = 'EVP_PKEY_CTX_set_rsa_mgf1_md_name';
  EVP_PKEY_CTX_set_rsa_mgf1_md_name_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_get_rsa_mgf1_md_procname = 'EVP_PKEY_CTX_get_rsa_mgf1_md';
  EVP_PKEY_CTX_get_rsa_mgf1_md_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_get_rsa_mgf1_md_name_procname = 'EVP_PKEY_CTX_get_rsa_mgf1_md_name';
  EVP_PKEY_CTX_get_rsa_mgf1_md_name_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_procname = 'EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md';
  EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name_procname = 'EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name';
  EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_rsa_pss_keygen_md_procname = 'EVP_PKEY_CTX_set_rsa_pss_keygen_md';
  EVP_PKEY_CTX_set_rsa_pss_keygen_md_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_rsa_pss_keygen_md_name_procname = 'EVP_PKEY_CTX_set_rsa_pss_keygen_md_name';
  EVP_PKEY_CTX_set_rsa_pss_keygen_md_name_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_rsa_oaep_md_procname = 'EVP_PKEY_CTX_set_rsa_oaep_md';
  EVP_PKEY_CTX_set_rsa_oaep_md_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_rsa_oaep_md_name_procname = 'EVP_PKEY_CTX_set_rsa_oaep_md_name';
  EVP_PKEY_CTX_set_rsa_oaep_md_name_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_get_rsa_oaep_md_procname = 'EVP_PKEY_CTX_get_rsa_oaep_md';
  EVP_PKEY_CTX_get_rsa_oaep_md_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_get_rsa_oaep_md_name_procname = 'EVP_PKEY_CTX_get_rsa_oaep_md_name';
  EVP_PKEY_CTX_get_rsa_oaep_md_name_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set0_rsa_oaep_label_procname = 'EVP_PKEY_CTX_set0_rsa_oaep_label';
  EVP_PKEY_CTX_set0_rsa_oaep_label_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_get0_rsa_oaep_label_procname = 'EVP_PKEY_CTX_get0_rsa_oaep_label';
  EVP_PKEY_CTX_get0_rsa_oaep_label_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_new_procname = 'RSA_new';
  RSA_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_new_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_new_method_procname = 'RSA_new_method';
  RSA_new_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_new_method_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_bits_procname = 'RSA_bits';
  RSA_bits_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_bits_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_size_procname = 'RSA_size';
  RSA_size_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_size_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_security_bits_procname = 'RSA_security_bits';
  RSA_security_bits_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_security_bits_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_set0_key_procname = 'RSA_set0_key';
  RSA_set0_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_set0_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_set0_factors_procname = 'RSA_set0_factors';
  RSA_set0_factors_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_set0_factors_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_set0_crt_params_procname = 'RSA_set0_crt_params';
  RSA_set0_crt_params_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_set0_crt_params_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_set0_multi_prime_params_procname = 'RSA_set0_multi_prime_params';
  RSA_set0_multi_prime_params_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  RSA_set0_multi_prime_params_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_get0_key_procname = 'RSA_get0_key';
  RSA_get0_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_get0_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_get0_factors_procname = 'RSA_get0_factors';
  RSA_get0_factors_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_get0_factors_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_get_multi_prime_extra_count_procname = 'RSA_get_multi_prime_extra_count';
  RSA_get_multi_prime_extra_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  RSA_get_multi_prime_extra_count_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_get0_multi_prime_factors_procname = 'RSA_get0_multi_prime_factors';
  RSA_get0_multi_prime_factors_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  RSA_get0_multi_prime_factors_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_get0_crt_params_procname = 'RSA_get0_crt_params';
  RSA_get0_crt_params_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_get0_crt_params_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_get0_multi_prime_crt_params_procname = 'RSA_get0_multi_prime_crt_params';
  RSA_get0_multi_prime_crt_params_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  RSA_get0_multi_prime_crt_params_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_get0_n_procname = 'RSA_get0_n';
  RSA_get0_n_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  RSA_get0_n_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_get0_e_procname = 'RSA_get0_e';
  RSA_get0_e_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  RSA_get0_e_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_get0_d_procname = 'RSA_get0_d';
  RSA_get0_d_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  RSA_get0_d_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_get0_p_procname = 'RSA_get0_p';
  RSA_get0_p_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  RSA_get0_p_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_get0_q_procname = 'RSA_get0_q';
  RSA_get0_q_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  RSA_get0_q_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_get0_dmp1_procname = 'RSA_get0_dmp1';
  RSA_get0_dmp1_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  RSA_get0_dmp1_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_get0_dmq1_procname = 'RSA_get0_dmq1';
  RSA_get0_dmq1_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  RSA_get0_dmq1_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_get0_iqmp_procname = 'RSA_get0_iqmp';
  RSA_get0_iqmp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  RSA_get0_iqmp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_get0_pss_params_procname = 'RSA_get0_pss_params';
  RSA_get0_pss_params_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1e);
  RSA_get0_pss_params_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_clear_flags_procname = 'RSA_clear_flags';
  RSA_clear_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_clear_flags_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_test_flags_procname = 'RSA_test_flags';
  RSA_test_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_test_flags_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_set_flags_procname = 'RSA_set_flags';
  RSA_set_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_set_flags_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_get_version_procname = 'RSA_get_version';
  RSA_get_version_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  RSA_get_version_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_get0_engine_procname = 'RSA_get0_engine';
  RSA_get0_engine_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_get0_engine_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_generate_key_ex_procname = 'RSA_generate_key_ex';
  RSA_generate_key_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_generate_key_ex_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_generate_multi_prime_key_procname = 'RSA_generate_multi_prime_key';
  RSA_generate_multi_prime_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  RSA_generate_multi_prime_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_X931_derive_ex_procname = 'RSA_X931_derive_ex';
  RSA_X931_derive_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_X931_derive_ex_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_X931_generate_key_ex_procname = 'RSA_X931_generate_key_ex';
  RSA_X931_generate_key_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_X931_generate_key_ex_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_check_key_procname = 'RSA_check_key';
  RSA_check_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_check_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_check_key_ex_procname = 'RSA_check_key_ex';
  RSA_check_key_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_check_key_ex_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_public_encrypt_procname = 'RSA_public_encrypt';
  RSA_public_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_public_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_private_encrypt_procname = 'RSA_private_encrypt';
  RSA_private_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_private_encrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_public_decrypt_procname = 'RSA_public_decrypt';
  RSA_public_decrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_public_decrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_private_decrypt_procname = 'RSA_private_decrypt';
  RSA_private_decrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_private_decrypt_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_free_procname = 'RSA_free';
  RSA_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_free_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_up_ref_procname = 'RSA_up_ref';
  RSA_up_ref_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_up_ref_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_flags_procname = 'RSA_flags';
  RSA_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_flags_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_set_default_method_procname = 'RSA_set_default_method';
  RSA_set_default_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_set_default_method_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_get_default_method_procname = 'RSA_get_default_method';
  RSA_get_default_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_get_default_method_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_null_method_procname = 'RSA_null_method';
  RSA_null_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_null_method_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_get_method_procname = 'RSA_get_method';
  RSA_get_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_get_method_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_set_method_procname = 'RSA_set_method';
  RSA_set_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_set_method_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_PKCS1_OpenSSL_procname = 'RSA_PKCS1_OpenSSL';
  RSA_PKCS1_OpenSSL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_PKCS1_OpenSSL_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_RSAPublicKey_procname = 'd2i_RSAPublicKey';
  d2i_RSAPublicKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  d2i_RSAPublicKey_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_RSAPublicKey_procname = 'i2d_RSAPublicKey';
  i2d_RSAPublicKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2d_RSAPublicKey_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSAPublicKey_it_procname = 'RSAPublicKey_it';
  RSAPublicKey_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSAPublicKey_it_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_RSAPrivateKey_procname = 'd2i_RSAPrivateKey';
  d2i_RSAPrivateKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  d2i_RSAPrivateKey_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_RSAPrivateKey_procname = 'i2d_RSAPrivateKey';
  i2d_RSAPrivateKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2d_RSAPrivateKey_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSAPrivateKey_it_procname = 'RSAPrivateKey_it';
  RSAPrivateKey_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSAPrivateKey_it_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_pkey_ctx_ctrl_procname = 'RSA_pkey_ctx_ctrl';
  RSA_pkey_ctx_ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  RSA_PSS_PARAMS_new_procname = 'RSA_PSS_PARAMS_new';
  RSA_PSS_PARAMS_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  RSA_PSS_PARAMS_free_procname = 'RSA_PSS_PARAMS_free';
  RSA_PSS_PARAMS_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_RSA_PSS_PARAMS_procname = 'd2i_RSA_PSS_PARAMS';
  d2i_RSA_PSS_PARAMS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_RSA_PSS_PARAMS_procname = 'i2d_RSA_PSS_PARAMS';
  i2d_RSA_PSS_PARAMS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  RSA_PSS_PARAMS_it_procname = 'RSA_PSS_PARAMS_it';
  RSA_PSS_PARAMS_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  RSA_PSS_PARAMS_dup_procname = 'RSA_PSS_PARAMS_dup';
  RSA_PSS_PARAMS_dup_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_OAEP_PARAMS_new_procname = 'RSA_OAEP_PARAMS_new';
  RSA_OAEP_PARAMS_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  RSA_OAEP_PARAMS_free_procname = 'RSA_OAEP_PARAMS_free';
  RSA_OAEP_PARAMS_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_RSA_OAEP_PARAMS_procname = 'd2i_RSA_OAEP_PARAMS';
  d2i_RSA_OAEP_PARAMS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_RSA_OAEP_PARAMS_procname = 'i2d_RSA_OAEP_PARAMS';
  i2d_RSA_OAEP_PARAMS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  RSA_OAEP_PARAMS_it_procname = 'RSA_OAEP_PARAMS_it';
  RSA_OAEP_PARAMS_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  RSA_print_fp_procname = 'RSA_print_fp';
  RSA_print_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_print_fp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_print_procname = 'RSA_print';
  RSA_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_print_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_sign_procname = 'RSA_sign';
  RSA_sign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_sign_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_verify_procname = 'RSA_verify';
  RSA_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_verify_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_sign_ASN1_OCTET_STRING_procname = 'RSA_sign_ASN1_OCTET_STRING';
  RSA_sign_ASN1_OCTET_STRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_sign_ASN1_OCTET_STRING_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_verify_ASN1_OCTET_STRING_procname = 'RSA_verify_ASN1_OCTET_STRING';
  RSA_verify_ASN1_OCTET_STRING_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_verify_ASN1_OCTET_STRING_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_blinding_on_procname = 'RSA_blinding_on';
  RSA_blinding_on_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_blinding_on_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_blinding_off_procname = 'RSA_blinding_off';
  RSA_blinding_off_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_blinding_off_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_setup_blinding_procname = 'RSA_setup_blinding';
  RSA_setup_blinding_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_setup_blinding_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_padding_add_PKCS1_type_1_procname = 'RSA_padding_add_PKCS1_type_1';
  RSA_padding_add_PKCS1_type_1_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_padding_add_PKCS1_type_1_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_padding_check_PKCS1_type_1_procname = 'RSA_padding_check_PKCS1_type_1';
  RSA_padding_check_PKCS1_type_1_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_padding_check_PKCS1_type_1_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_padding_add_PKCS1_type_2_procname = 'RSA_padding_add_PKCS1_type_2';
  RSA_padding_add_PKCS1_type_2_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_padding_add_PKCS1_type_2_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_padding_check_PKCS1_type_2_procname = 'RSA_padding_check_PKCS1_type_2';
  RSA_padding_check_PKCS1_type_2_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_padding_check_PKCS1_type_2_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS1_MGF1_procname = 'PKCS1_MGF1';
  PKCS1_MGF1_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PKCS1_MGF1_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_padding_add_PKCS1_OAEP_procname = 'RSA_padding_add_PKCS1_OAEP';
  RSA_padding_add_PKCS1_OAEP_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_padding_add_PKCS1_OAEP_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_padding_check_PKCS1_OAEP_procname = 'RSA_padding_check_PKCS1_OAEP';
  RSA_padding_check_PKCS1_OAEP_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_padding_check_PKCS1_OAEP_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_padding_add_PKCS1_OAEP_mgf1_procname = 'RSA_padding_add_PKCS1_OAEP_mgf1';
  RSA_padding_add_PKCS1_OAEP_mgf1_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_padding_add_PKCS1_OAEP_mgf1_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_padding_check_PKCS1_OAEP_mgf1_procname = 'RSA_padding_check_PKCS1_OAEP_mgf1';
  RSA_padding_check_PKCS1_OAEP_mgf1_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_padding_check_PKCS1_OAEP_mgf1_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_padding_add_none_procname = 'RSA_padding_add_none';
  RSA_padding_add_none_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_padding_add_none_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_padding_check_none_procname = 'RSA_padding_check_none';
  RSA_padding_check_none_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_padding_check_none_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_padding_add_X931_procname = 'RSA_padding_add_X931';
  RSA_padding_add_X931_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_padding_add_X931_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_padding_check_X931_procname = 'RSA_padding_check_X931';
  RSA_padding_check_X931_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_padding_check_X931_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_X931_hash_id_procname = 'RSA_X931_hash_id';
  RSA_X931_hash_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_X931_hash_id_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_verify_PKCS1_PSS_procname = 'RSA_verify_PKCS1_PSS';
  RSA_verify_PKCS1_PSS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_verify_PKCS1_PSS_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_padding_add_PKCS1_PSS_procname = 'RSA_padding_add_PKCS1_PSS';
  RSA_padding_add_PKCS1_PSS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_padding_add_PKCS1_PSS_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_verify_PKCS1_PSS_mgf1_procname = 'RSA_verify_PKCS1_PSS_mgf1';
  RSA_verify_PKCS1_PSS_mgf1_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_verify_PKCS1_PSS_mgf1_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_padding_add_PKCS1_PSS_mgf1_procname = 'RSA_padding_add_PKCS1_PSS_mgf1';
  RSA_padding_add_PKCS1_PSS_mgf1_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_padding_add_PKCS1_PSS_mgf1_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_set_ex_data_procname = 'RSA_set_ex_data';
  RSA_set_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_set_ex_data_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_get_ex_data_procname = 'RSA_get_ex_data';
  RSA_get_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_get_ex_data_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSAPublicKey_dup_procname = 'RSAPublicKey_dup';
  RSAPublicKey_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSAPublicKey_dup_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSAPrivateKey_dup_procname = 'RSAPrivateKey_dup';
  RSAPrivateKey_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSAPrivateKey_dup_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_new_procname = 'RSA_meth_new';
  RSA_meth_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_new_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_free_procname = 'RSA_meth_free';
  RSA_meth_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_free_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_dup_procname = 'RSA_meth_dup';
  RSA_meth_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_dup_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_get0_name_procname = 'RSA_meth_get0_name';
  RSA_meth_get0_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_get0_name_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_set1_name_procname = 'RSA_meth_set1_name';
  RSA_meth_set1_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_set1_name_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_get_flags_procname = 'RSA_meth_get_flags';
  RSA_meth_get_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_get_flags_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_set_flags_procname = 'RSA_meth_set_flags';
  RSA_meth_set_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_set_flags_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_get0_app_data_procname = 'RSA_meth_get0_app_data';
  RSA_meth_get0_app_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_get0_app_data_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_set0_app_data_procname = 'RSA_meth_set0_app_data';
  RSA_meth_set0_app_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_set0_app_data_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_get_pub_enc_procname = 'RSA_meth_get_pub_enc';
  RSA_meth_get_pub_enc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_get_pub_enc_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_set_pub_enc_procname = 'RSA_meth_set_pub_enc';
  RSA_meth_set_pub_enc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_set_pub_enc_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_get_pub_dec_procname = 'RSA_meth_get_pub_dec';
  RSA_meth_get_pub_dec_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_get_pub_dec_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_set_pub_dec_procname = 'RSA_meth_set_pub_dec';
  RSA_meth_set_pub_dec_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_set_pub_dec_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_get_priv_enc_procname = 'RSA_meth_get_priv_enc';
  RSA_meth_get_priv_enc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_get_priv_enc_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_set_priv_enc_procname = 'RSA_meth_set_priv_enc';
  RSA_meth_set_priv_enc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_set_priv_enc_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_get_priv_dec_procname = 'RSA_meth_get_priv_dec';
  RSA_meth_get_priv_dec_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_get_priv_dec_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_set_priv_dec_procname = 'RSA_meth_set_priv_dec';
  RSA_meth_set_priv_dec_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_set_priv_dec_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_get_mod_exp_procname = 'RSA_meth_get_mod_exp';
  RSA_meth_get_mod_exp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_get_mod_exp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_set_mod_exp_procname = 'RSA_meth_set_mod_exp';
  RSA_meth_set_mod_exp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_set_mod_exp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_get_bn_mod_exp_procname = 'RSA_meth_get_bn_mod_exp';
  RSA_meth_get_bn_mod_exp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_get_bn_mod_exp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_set_bn_mod_exp_procname = 'RSA_meth_set_bn_mod_exp';
  RSA_meth_set_bn_mod_exp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_set_bn_mod_exp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_get_init_procname = 'RSA_meth_get_init';
  RSA_meth_get_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_get_init_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_set_init_procname = 'RSA_meth_set_init';
  RSA_meth_set_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_set_init_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_get_finish_procname = 'RSA_meth_get_finish';
  RSA_meth_get_finish_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_get_finish_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_set_finish_procname = 'RSA_meth_set_finish';
  RSA_meth_set_finish_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_set_finish_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_get_sign_procname = 'RSA_meth_get_sign';
  RSA_meth_get_sign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_get_sign_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_set_sign_procname = 'RSA_meth_set_sign';
  RSA_meth_set_sign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_set_sign_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_get_verify_procname = 'RSA_meth_get_verify';
  RSA_meth_get_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_get_verify_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_set_verify_procname = 'RSA_meth_set_verify';
  RSA_meth_set_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_set_verify_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_get_keygen_procname = 'RSA_meth_get_keygen';
  RSA_meth_get_keygen_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_get_keygen_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_set_keygen_procname = 'RSA_meth_set_keygen';
  RSA_meth_set_keygen_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  RSA_meth_set_keygen_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_get_multi_prime_keygen_procname = 'RSA_meth_get_multi_prime_keygen';
  RSA_meth_get_multi_prime_keygen_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  RSA_meth_get_multi_prime_keygen_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  RSA_meth_set_multi_prime_keygen_procname = 'RSA_meth_set_multi_prime_keygen';
  RSA_meth_set_multi_prime_keygen_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  RSA_meth_set_multi_prime_keygen_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function EVP_RSA_gen(bits: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    EVP_RSA_gen(bits) \
    EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)(0 + (bits)))
  }
end;

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_EVP_PKEY_CTX_set_rsa_padding(ctx: PEVP_PKEY_CTX; pad_mode: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_rsa_padding_procname);
end;

function ERR_EVP_PKEY_CTX_get_rsa_padding(ctx: PEVP_PKEY_CTX; pad_mode: PIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_get_rsa_padding_procname);
end;

function ERR_EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx: PEVP_PKEY_CTX; saltlen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_rsa_pss_saltlen_procname);
end;

function ERR_EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx: PEVP_PKEY_CTX; saltlen: PIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_get_rsa_pss_saltlen_procname);
end;

function ERR_EVP_PKEY_CTX_set_rsa_keygen_bits(ctx: PEVP_PKEY_CTX; bits: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_rsa_keygen_bits_procname);
end;

function ERR_EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx: PEVP_PKEY_CTX; pubexp: PBIGNUM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set1_rsa_keygen_pubexp_procname);
end;

function ERR_EVP_PKEY_CTX_set_rsa_keygen_primes(ctx: PEVP_PKEY_CTX; primes: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_rsa_keygen_primes_procname);
end;

function ERR_EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx: PEVP_PKEY_CTX; saltlen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen_procname);
end;

function ERR_EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx: PEVP_PKEY_CTX; pubexp: PBIGNUM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_rsa_keygen_pubexp_procname);
end;

function ERR_EVP_PKEY_CTX_set_rsa_mgf1_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_rsa_mgf1_md_procname);
end;

function ERR_EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx: PEVP_PKEY_CTX; mdname: PIdAnsiChar; mdprops: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_rsa_mgf1_md_name_procname);
end;

function ERR_EVP_PKEY_CTX_get_rsa_mgf1_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_get_rsa_mgf1_md_procname);
end;

function ERR_EVP_PKEY_CTX_get_rsa_mgf1_md_name(ctx: PEVP_PKEY_CTX; name: PIdAnsiChar; namelen: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_get_rsa_mgf1_md_name_procname);
end;

function ERR_EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_procname);
end;

function ERR_EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(ctx: PEVP_PKEY_CTX; mdname: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name_procname);
end;

function ERR_EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_rsa_pss_keygen_md_procname);
end;

function ERR_EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(ctx: PEVP_PKEY_CTX; mdname: PIdAnsiChar; mdprops: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_rsa_pss_keygen_md_name_procname);
end;

function ERR_EVP_PKEY_CTX_set_rsa_oaep_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_rsa_oaep_md_procname);
end;

function ERR_EVP_PKEY_CTX_set_rsa_oaep_md_name(ctx: PEVP_PKEY_CTX; mdname: PIdAnsiChar; mdprops: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_rsa_oaep_md_name_procname);
end;

function ERR_EVP_PKEY_CTX_get_rsa_oaep_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_get_rsa_oaep_md_procname);
end;

function ERR_EVP_PKEY_CTX_get_rsa_oaep_md_name(ctx: PEVP_PKEY_CTX; name: PIdAnsiChar; namelen: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_get_rsa_oaep_md_name_procname);
end;

function ERR_EVP_PKEY_CTX_set0_rsa_oaep_label(ctx: PEVP_PKEY_CTX; _label: Pointer; llen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set0_rsa_oaep_label_procname);
end;

function ERR_EVP_PKEY_CTX_get0_rsa_oaep_label(ctx: PEVP_PKEY_CTX; _label: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_get0_rsa_oaep_label_procname);
end;

function ERR_RSA_new: PRSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_new_procname);
end;

function ERR_RSA_new_method(engine: PENGINE): PRSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_new_method_procname);
end;

function ERR_RSA_bits(rsa: PRSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_bits_procname);
end;

function ERR_RSA_size(rsa: PRSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_size_procname);
end;

function ERR_RSA_security_bits(rsa: PRSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_security_bits_procname);
end;

function ERR_RSA_set0_key(r: PRSA; n: PBIGNUM; e: PBIGNUM; d: PBIGNUM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_set0_key_procname);
end;

function ERR_RSA_set0_factors(r: PRSA; p: PBIGNUM; q: PBIGNUM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_set0_factors_procname);
end;

function ERR_RSA_set0_crt_params(r: PRSA; dmp1: PBIGNUM; dmq1: PBIGNUM; iqmp: PBIGNUM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_set0_crt_params_procname);
end;

function ERR_RSA_set0_multi_prime_params(r: PRSA; primes: PPBIGNUM; exps: PPBIGNUM; coeffs: PPBIGNUM; pnum: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_set0_multi_prime_params_procname);
end;

function ERR_RSA_get0_key(r: PRSA; n: PPBIGNUM; e: PPBIGNUM; d: PPBIGNUM): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_key_procname);
end;

function ERR_RSA_get0_factors(r: PRSA; p: PPBIGNUM; q: PPBIGNUM): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_factors_procname);
end;

function ERR_RSA_get_multi_prime_extra_count(r: PRSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get_multi_prime_extra_count_procname);
end;

function ERR_RSA_get0_multi_prime_factors(r: PRSA; primes: PPBIGNUM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_multi_prime_factors_procname);
end;

function ERR_RSA_get0_crt_params(r: PRSA; dmp1: PPBIGNUM; dmq1: PPBIGNUM; iqmp: PPBIGNUM): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_crt_params_procname);
end;

function ERR_RSA_get0_multi_prime_crt_params(r: PRSA; exps: PPBIGNUM; coeffs: PPBIGNUM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_multi_prime_crt_params_procname);
end;

function ERR_RSA_get0_n(d: PRSA): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_n_procname);
end;

function ERR_RSA_get0_e(d: PRSA): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_e_procname);
end;

function ERR_RSA_get0_d(d: PRSA): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_d_procname);
end;

function ERR_RSA_get0_p(d: PRSA): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_p_procname);
end;

function ERR_RSA_get0_q(d: PRSA): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_q_procname);
end;

function ERR_RSA_get0_dmp1(r: PRSA): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_dmp1_procname);
end;

function ERR_RSA_get0_dmq1(r: PRSA): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_dmq1_procname);
end;

function ERR_RSA_get0_iqmp(r: PRSA): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_iqmp_procname);
end;

function ERR_RSA_get0_pss_params(r: PRSA): PRSA_PSS_PARAMS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_pss_params_procname);
end;

function ERR_RSA_clear_flags(r: PRSA; flags: TIdC_INT): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_clear_flags_procname);
end;

function ERR_RSA_test_flags(r: PRSA; flags: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_test_flags_procname);
end;

function ERR_RSA_set_flags(r: PRSA; flags: TIdC_INT): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_set_flags_procname);
end;

function ERR_RSA_get_version(r: PRSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get_version_procname);
end;

function ERR_RSA_get0_engine(r: PRSA): PENGINE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_engine_procname);
end;

function ERR_RSA_generate_key_ex(rsa: PRSA; bits: TIdC_INT; e: PBIGNUM; cb: PBN_GENCB): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_generate_key_ex_procname);
end;

function ERR_RSA_generate_multi_prime_key(rsa: PRSA; bits: TIdC_INT; primes: TIdC_INT; e: PBIGNUM; cb: PBN_GENCB): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_generate_multi_prime_key_procname);
end;

function ERR_RSA_X931_derive_ex(rsa: PRSA; p1: PBIGNUM; p2: PBIGNUM; q1: PBIGNUM; q2: PBIGNUM; Xp1: PBIGNUM; Xp2: PBIGNUM; Xp: PBIGNUM; Xq1: PBIGNUM; Xq2: PBIGNUM; Xq: PBIGNUM; e: PBIGNUM; cb: PBN_GENCB): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_X931_derive_ex_procname);
end;

function ERR_RSA_X931_generate_key_ex(rsa: PRSA; bits: TIdC_INT; e: PBIGNUM; cb: PBN_GENCB): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_X931_generate_key_ex_procname);
end;

function ERR_RSA_check_key(arg1: PRSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_check_key_procname);
end;

function ERR_RSA_check_key_ex(arg1: PRSA; cb: PBN_GENCB): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_check_key_ex_procname);
end;

function ERR_RSA_public_encrypt(flen: TIdC_INT; from: PIdAnsiChar; _to: PIdAnsiChar; rsa: PRSA; padding: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_public_encrypt_procname);
end;

function ERR_RSA_private_encrypt(flen: TIdC_INT; from: PIdAnsiChar; _to: PIdAnsiChar; rsa: PRSA; padding: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_private_encrypt_procname);
end;

function ERR_RSA_public_decrypt(flen: TIdC_INT; from: PIdAnsiChar; _to: PIdAnsiChar; rsa: PRSA; padding: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_public_decrypt_procname);
end;

function ERR_RSA_private_decrypt(flen: TIdC_INT; from: PIdAnsiChar; _to: PIdAnsiChar; rsa: PRSA; padding: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_private_decrypt_procname);
end;

function ERR_RSA_free(r: PRSA): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_free_procname);
end;

function ERR_RSA_up_ref(r: PRSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_up_ref_procname);
end;

function ERR_RSA_flags(r: PRSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_flags_procname);
end;

function ERR_RSA_set_default_method(meth: PRSA_METHOD): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_set_default_method_procname);
end;

function ERR_RSA_get_default_method: PRSA_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get_default_method_procname);
end;

function ERR_RSA_null_method: PRSA_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_null_method_procname);
end;

function ERR_RSA_get_method(rsa: PRSA): PRSA_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get_method_procname);
end;

function ERR_RSA_set_method(rsa: PRSA; meth: PRSA_METHOD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_set_method_procname);
end;

function ERR_RSA_PKCS1_OpenSSL: PRSA_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_PKCS1_OpenSSL_procname);
end;

function ERR_d2i_RSAPublicKey(a: PPRSA; _in: PPIdAnsiChar; len: TIdC_LONG): PRSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_RSAPublicKey_procname);
end;

function ERR_i2d_RSAPublicKey(a: PRSA; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_RSAPublicKey_procname);
end;

function ERR_RSAPublicKey_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSAPublicKey_it_procname);
end;

function ERR_d2i_RSAPrivateKey(a: PPRSA; _in: PPIdAnsiChar; len: TIdC_LONG): PRSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_RSAPrivateKey_procname);
end;

function ERR_i2d_RSAPrivateKey(a: PRSA; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_RSAPrivateKey_procname);
end;

function ERR_RSAPrivateKey_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSAPrivateKey_it_procname);
end;

function ERR_RSA_pkey_ctx_ctrl(ctx: PEVP_PKEY_CTX; optype: TIdC_INT; cmd: TIdC_INT; p1: TIdC_INT; p2: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_pkey_ctx_ctrl_procname);
end;

function ERR_RSA_PSS_PARAMS_new: PRSA_PSS_PARAMS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_PSS_PARAMS_new_procname);
end;

function ERR_RSA_PSS_PARAMS_free(a: PRSA_PSS_PARAMS): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_PSS_PARAMS_free_procname);
end;

function ERR_d2i_RSA_PSS_PARAMS(a: PPRSA_PSS_PARAMS; _in: PPIdAnsiChar; len: TIdC_LONG): PRSA_PSS_PARAMS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_RSA_PSS_PARAMS_procname);
end;

function ERR_i2d_RSA_PSS_PARAMS(a: PRSA_PSS_PARAMS; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_RSA_PSS_PARAMS_procname);
end;

function ERR_RSA_PSS_PARAMS_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_PSS_PARAMS_it_procname);
end;

function ERR_RSA_PSS_PARAMS_dup(a: PRSA_PSS_PARAMS): PRSA_PSS_PARAMS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_PSS_PARAMS_dup_procname);
end;

function ERR_RSA_OAEP_PARAMS_new: PRSA_OAEP_PARAMS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_OAEP_PARAMS_new_procname);
end;

function ERR_RSA_OAEP_PARAMS_free(a: PRSA_OAEP_PARAMS): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_OAEP_PARAMS_free_procname);
end;

function ERR_d2i_RSA_OAEP_PARAMS(a: PPRSA_OAEP_PARAMS; _in: PPIdAnsiChar; len: TIdC_LONG): PRSA_OAEP_PARAMS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_RSA_OAEP_PARAMS_procname);
end;

function ERR_i2d_RSA_OAEP_PARAMS(a: PRSA_OAEP_PARAMS; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_RSA_OAEP_PARAMS_procname);
end;

function ERR_RSA_OAEP_PARAMS_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_OAEP_PARAMS_it_procname);
end;

function ERR_RSA_print_fp(fp: PFILE; r: PRSA; offset: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_print_fp_procname);
end;

function ERR_RSA_print(bp: PBIO; r: PRSA; offset: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_print_procname);
end;

function ERR_RSA_sign(_type: TIdC_INT; m: PIdAnsiChar; m_length: TIdC_UINT; sigret: PIdAnsiChar; siglen: PIdC_UINT; rsa: PRSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_sign_procname);
end;

function ERR_RSA_verify(_type: TIdC_INT; m: PIdAnsiChar; m_length: TIdC_UINT; sigbuf: PIdAnsiChar; siglen: TIdC_UINT; rsa: PRSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_verify_procname);
end;

function ERR_RSA_sign_ASN1_OCTET_STRING(_type: TIdC_INT; m: PIdAnsiChar; m_length: TIdC_UINT; sigret: PIdAnsiChar; siglen: PIdC_UINT; rsa: PRSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_sign_ASN1_OCTET_STRING_procname);
end;

function ERR_RSA_verify_ASN1_OCTET_STRING(_type: TIdC_INT; m: PIdAnsiChar; m_length: TIdC_UINT; sigbuf: PIdAnsiChar; siglen: TIdC_UINT; rsa: PRSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_verify_ASN1_OCTET_STRING_procname);
end;

function ERR_RSA_blinding_on(rsa: PRSA; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_blinding_on_procname);
end;

function ERR_RSA_blinding_off(rsa: PRSA): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_blinding_off_procname);
end;

function ERR_RSA_setup_blinding(rsa: PRSA; ctx: PBN_CTX): PBN_BLINDING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_setup_blinding_procname);
end;

function ERR_RSA_padding_add_PKCS1_type_1(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_add_PKCS1_type_1_procname);
end;

function ERR_RSA_padding_check_PKCS1_type_1(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_check_PKCS1_type_1_procname);
end;

function ERR_RSA_padding_add_PKCS1_type_2(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_add_PKCS1_type_2_procname);
end;

function ERR_RSA_padding_check_PKCS1_type_2(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_check_PKCS1_type_2_procname);
end;

function ERR_PKCS1_MGF1(mask: PIdAnsiChar; len: TIdC_LONG; seed: PIdAnsiChar; seedlen: TIdC_LONG; dgst: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS1_MGF1_procname);
end;

function ERR_RSA_padding_add_PKCS1_OAEP(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT; p: PIdAnsiChar; pl: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_add_PKCS1_OAEP_procname);
end;

function ERR_RSA_padding_check_PKCS1_OAEP(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT; rsa_len: TIdC_INT; p: PIdAnsiChar; pl: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_check_PKCS1_OAEP_procname);
end;

function ERR_RSA_padding_add_PKCS1_OAEP_mgf1(_to: PIdAnsiChar; tlen: TIdC_INT; from: PIdAnsiChar; flen: TIdC_INT; param: PIdAnsiChar; plen: TIdC_INT; md: PEVP_MD; mgf1md: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_add_PKCS1_OAEP_mgf1_procname);
end;

function ERR_RSA_padding_check_PKCS1_OAEP_mgf1(_to: PIdAnsiChar; tlen: TIdC_INT; from: PIdAnsiChar; flen: TIdC_INT; num: TIdC_INT; param: PIdAnsiChar; plen: TIdC_INT; md: PEVP_MD; mgf1md: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_check_PKCS1_OAEP_mgf1_procname);
end;

function ERR_RSA_padding_add_none(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_add_none_procname);
end;

function ERR_RSA_padding_check_none(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_check_none_procname);
end;

function ERR_RSA_padding_add_X931(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_add_X931_procname);
end;

function ERR_RSA_padding_check_X931(_to: PIdAnsiChar; tlen: TIdC_INT; f: PIdAnsiChar; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_check_X931_procname);
end;

function ERR_RSA_X931_hash_id(nid: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_X931_hash_id_procname);
end;

function ERR_RSA_verify_PKCS1_PSS(rsa: PRSA; mHash: PIdAnsiChar; Hash: PEVP_MD; EM: PIdAnsiChar; sLen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_verify_PKCS1_PSS_procname);
end;

function ERR_RSA_padding_add_PKCS1_PSS(rsa: PRSA; EM: PIdAnsiChar; mHash: PIdAnsiChar; Hash: PEVP_MD; sLen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_add_PKCS1_PSS_procname);
end;

function ERR_RSA_verify_PKCS1_PSS_mgf1(rsa: PRSA; mHash: PIdAnsiChar; Hash: PEVP_MD; mgf1Hash: PEVP_MD; EM: PIdAnsiChar; sLen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_verify_PKCS1_PSS_mgf1_procname);
end;

function ERR_RSA_padding_add_PKCS1_PSS_mgf1(rsa: PRSA; EM: PIdAnsiChar; mHash: PIdAnsiChar; Hash: PEVP_MD; mgf1Hash: PEVP_MD; sLen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_add_PKCS1_PSS_mgf1_procname);
end;

function ERR_RSA_set_ex_data(r: PRSA; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_set_ex_data_procname);
end;

function ERR_RSA_get_ex_data(r: PRSA; idx: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get_ex_data_procname);
end;

function ERR_RSAPublicKey_dup(a: PRSA): PRSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSAPublicKey_dup_procname);
end;

function ERR_RSAPrivateKey_dup(a: PRSA): PRSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSAPrivateKey_dup_procname);
end;

function ERR_RSA_meth_new(name: PIdAnsiChar; flags: TIdC_INT): PRSA_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_new_procname);
end;

function ERR_RSA_meth_free(meth: PRSA_METHOD): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_free_procname);
end;

function ERR_RSA_meth_dup(meth: PRSA_METHOD): PRSA_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_dup_procname);
end;

function ERR_RSA_meth_get0_name(meth: PRSA_METHOD): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_get0_name_procname);
end;

function ERR_RSA_meth_set1_name(meth: PRSA_METHOD; name: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set1_name_procname);
end;

function ERR_RSA_meth_get_flags(meth: PRSA_METHOD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_get_flags_procname);
end;

function ERR_RSA_meth_set_flags(meth: PRSA_METHOD; flags: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set_flags_procname);
end;

function ERR_RSA_meth_get0_app_data(meth: PRSA_METHOD): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_get0_app_data_procname);
end;

function ERR_RSA_meth_set0_app_data(meth: PRSA_METHOD; app_data: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set0_app_data_procname);
end;

function ERR_RSA_meth_get_pub_enc(meth: PRSA_METHOD): TRSA_meth_get_pub_enc_func_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_get_pub_enc_procname);
end;

function ERR_RSA_meth_set_pub_enc(rsa: PRSA_METHOD; pub_enc: TRSA_meth_get_pub_enc_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set_pub_enc_procname);
end;

function ERR_RSA_meth_get_pub_dec(meth: PRSA_METHOD): TRSA_meth_get_pub_enc_func_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_get_pub_dec_procname);
end;

function ERR_RSA_meth_set_pub_dec(rsa: PRSA_METHOD; pub_dec: TRSA_meth_get_pub_enc_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set_pub_dec_procname);
end;

function ERR_RSA_meth_get_priv_enc(meth: PRSA_METHOD): TRSA_meth_get_pub_enc_func_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_get_priv_enc_procname);
end;

function ERR_RSA_meth_set_priv_enc(rsa: PRSA_METHOD; priv_enc: TRSA_meth_get_pub_enc_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set_priv_enc_procname);
end;

function ERR_RSA_meth_get_priv_dec(meth: PRSA_METHOD): TRSA_meth_get_pub_enc_func_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_get_priv_dec_procname);
end;

function ERR_RSA_meth_set_priv_dec(rsa: PRSA_METHOD; priv_dec: TRSA_meth_get_pub_enc_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set_priv_dec_procname);
end;

function ERR_RSA_meth_get_mod_exp(meth: PRSA_METHOD): TRSA_meth_get_mod_exp_func_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_get_mod_exp_procname);
end;

function ERR_RSA_meth_set_mod_exp(rsa: PRSA_METHOD; mod_exp: TRSA_meth_get_mod_exp_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set_mod_exp_procname);
end;

function ERR_RSA_meth_get_bn_mod_exp(meth: PRSA_METHOD): TRSA_meth_get_bn_mod_exp_func_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_get_bn_mod_exp_procname);
end;

function ERR_RSA_meth_set_bn_mod_exp(rsa: PRSA_METHOD; bn_mod_exp: TRSA_meth_get_bn_mod_exp_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set_bn_mod_exp_procname);
end;

function ERR_RSA_meth_get_init(meth: PRSA_METHOD): TRSA_meth_get_init_func_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_get_init_procname);
end;

function ERR_RSA_meth_set_init(rsa: PRSA_METHOD; init: TRSA_meth_get_init_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set_init_procname);
end;

function ERR_RSA_meth_get_finish(meth: PRSA_METHOD): TRSA_meth_get_init_func_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_get_finish_procname);
end;

function ERR_RSA_meth_set_finish(rsa: PRSA_METHOD; finish: TRSA_meth_get_init_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set_finish_procname);
end;

function ERR_RSA_meth_get_sign(meth: PRSA_METHOD): TRSA_meth_get_sign_func_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_get_sign_procname);
end;

function ERR_RSA_meth_set_sign(rsa: PRSA_METHOD; sign: TRSA_meth_get_sign_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set_sign_procname);
end;

function ERR_RSA_meth_get_verify(meth: PRSA_METHOD): TRSA_meth_get_verify_func_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_get_verify_procname);
end;

function ERR_RSA_meth_set_verify(rsa: PRSA_METHOD; verify: TRSA_meth_get_verify_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set_verify_procname);
end;

function ERR_RSA_meth_get_keygen(meth: PRSA_METHOD): TRSA_meth_get_keygen_func_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_get_keygen_procname);
end;

function ERR_RSA_meth_set_keygen(rsa: PRSA_METHOD; keygen: TRSA_meth_get_keygen_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set_keygen_procname);
end;

function ERR_RSA_meth_get_multi_prime_keygen(meth: PRSA_METHOD): TRSA_meth_get_multi_prime_keygen_func_cb; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_get_multi_prime_keygen_procname);
end;

function ERR_RSA_meth_set_multi_prime_keygen(meth: PRSA_METHOD; keygen: TRSA_meth_get_multi_prime_keygen_func_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set_multi_prime_keygen_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  EVP_PKEY_CTX_set_rsa_padding := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_rsa_padding_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_rsa_padding);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_rsa_padding_allownil)}
    EVP_PKEY_CTX_set_rsa_padding := ERR_EVP_PKEY_CTX_set_rsa_padding;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_padding_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_rsa_padding_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_rsa_padding)}
      EVP_PKEY_CTX_set_rsa_padding := FC_EVP_PKEY_CTX_set_rsa_padding;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_padding_removed)}
    if EVP_PKEY_CTX_set_rsa_padding_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_rsa_padding)}
      EVP_PKEY_CTX_set_rsa_padding := _EVP_PKEY_CTX_set_rsa_padding;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_rsa_padding_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_rsa_padding');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_get_rsa_padding := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_get_rsa_padding_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_get_rsa_padding);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_get_rsa_padding_allownil)}
    EVP_PKEY_CTX_get_rsa_padding := ERR_EVP_PKEY_CTX_get_rsa_padding;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_rsa_padding_introduced)}
    if LibVersion < EVP_PKEY_CTX_get_rsa_padding_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_get_rsa_padding)}
      EVP_PKEY_CTX_get_rsa_padding := FC_EVP_PKEY_CTX_get_rsa_padding;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_rsa_padding_removed)}
    if EVP_PKEY_CTX_get_rsa_padding_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_get_rsa_padding)}
      EVP_PKEY_CTX_get_rsa_padding := _EVP_PKEY_CTX_get_rsa_padding;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_get_rsa_padding_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_get_rsa_padding');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_rsa_pss_saltlen := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_rsa_pss_saltlen_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_rsa_pss_saltlen);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_rsa_pss_saltlen_allownil)}
    EVP_PKEY_CTX_set_rsa_pss_saltlen := ERR_EVP_PKEY_CTX_set_rsa_pss_saltlen;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_pss_saltlen_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_rsa_pss_saltlen_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_rsa_pss_saltlen)}
      EVP_PKEY_CTX_set_rsa_pss_saltlen := FC_EVP_PKEY_CTX_set_rsa_pss_saltlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_pss_saltlen_removed)}
    if EVP_PKEY_CTX_set_rsa_pss_saltlen_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_rsa_pss_saltlen)}
      EVP_PKEY_CTX_set_rsa_pss_saltlen := _EVP_PKEY_CTX_set_rsa_pss_saltlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_rsa_pss_saltlen_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_rsa_pss_saltlen');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_get_rsa_pss_saltlen := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_get_rsa_pss_saltlen_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_get_rsa_pss_saltlen);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_get_rsa_pss_saltlen_allownil)}
    EVP_PKEY_CTX_get_rsa_pss_saltlen := ERR_EVP_PKEY_CTX_get_rsa_pss_saltlen;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_rsa_pss_saltlen_introduced)}
    if LibVersion < EVP_PKEY_CTX_get_rsa_pss_saltlen_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_get_rsa_pss_saltlen)}
      EVP_PKEY_CTX_get_rsa_pss_saltlen := FC_EVP_PKEY_CTX_get_rsa_pss_saltlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_rsa_pss_saltlen_removed)}
    if EVP_PKEY_CTX_get_rsa_pss_saltlen_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_get_rsa_pss_saltlen)}
      EVP_PKEY_CTX_get_rsa_pss_saltlen := _EVP_PKEY_CTX_get_rsa_pss_saltlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_get_rsa_pss_saltlen_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_get_rsa_pss_saltlen');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_rsa_keygen_bits := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_rsa_keygen_bits_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_rsa_keygen_bits);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_rsa_keygen_bits_allownil)}
    EVP_PKEY_CTX_set_rsa_keygen_bits := ERR_EVP_PKEY_CTX_set_rsa_keygen_bits;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_keygen_bits_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_rsa_keygen_bits_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_rsa_keygen_bits)}
      EVP_PKEY_CTX_set_rsa_keygen_bits := FC_EVP_PKEY_CTX_set_rsa_keygen_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_keygen_bits_removed)}
    if EVP_PKEY_CTX_set_rsa_keygen_bits_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_rsa_keygen_bits)}
      EVP_PKEY_CTX_set_rsa_keygen_bits := _EVP_PKEY_CTX_set_rsa_keygen_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_rsa_keygen_bits_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_rsa_keygen_bits');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set1_rsa_keygen_pubexp := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set1_rsa_keygen_pubexp_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set1_rsa_keygen_pubexp);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set1_rsa_keygen_pubexp_allownil)}
    EVP_PKEY_CTX_set1_rsa_keygen_pubexp := ERR_EVP_PKEY_CTX_set1_rsa_keygen_pubexp;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set1_rsa_keygen_pubexp_introduced)}
    if LibVersion < EVP_PKEY_CTX_set1_rsa_keygen_pubexp_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set1_rsa_keygen_pubexp)}
      EVP_PKEY_CTX_set1_rsa_keygen_pubexp := FC_EVP_PKEY_CTX_set1_rsa_keygen_pubexp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set1_rsa_keygen_pubexp_removed)}
    if EVP_PKEY_CTX_set1_rsa_keygen_pubexp_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set1_rsa_keygen_pubexp)}
      EVP_PKEY_CTX_set1_rsa_keygen_pubexp := _EVP_PKEY_CTX_set1_rsa_keygen_pubexp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set1_rsa_keygen_pubexp_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set1_rsa_keygen_pubexp');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_rsa_keygen_primes := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_rsa_keygen_primes_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_rsa_keygen_primes);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_rsa_keygen_primes_allownil)}
    EVP_PKEY_CTX_set_rsa_keygen_primes := ERR_EVP_PKEY_CTX_set_rsa_keygen_primes;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_keygen_primes_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_rsa_keygen_primes_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_rsa_keygen_primes)}
      EVP_PKEY_CTX_set_rsa_keygen_primes := FC_EVP_PKEY_CTX_set_rsa_keygen_primes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_keygen_primes_removed)}
    if EVP_PKEY_CTX_set_rsa_keygen_primes_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_rsa_keygen_primes)}
      EVP_PKEY_CTX_set_rsa_keygen_primes := _EVP_PKEY_CTX_set_rsa_keygen_primes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_rsa_keygen_primes_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_rsa_keygen_primes');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen_allownil)}
    EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen := ERR_EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen)}
      EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen := FC_EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen_removed)}
    if EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen)}
      EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen := _EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_rsa_keygen_pubexp := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_rsa_keygen_pubexp_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_rsa_keygen_pubexp);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_rsa_keygen_pubexp_allownil)}
    EVP_PKEY_CTX_set_rsa_keygen_pubexp := ERR_EVP_PKEY_CTX_set_rsa_keygen_pubexp;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_keygen_pubexp_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_rsa_keygen_pubexp_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_rsa_keygen_pubexp)}
      EVP_PKEY_CTX_set_rsa_keygen_pubexp := FC_EVP_PKEY_CTX_set_rsa_keygen_pubexp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_keygen_pubexp_removed)}
    if EVP_PKEY_CTX_set_rsa_keygen_pubexp_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_rsa_keygen_pubexp)}
      EVP_PKEY_CTX_set_rsa_keygen_pubexp := _EVP_PKEY_CTX_set_rsa_keygen_pubexp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_rsa_keygen_pubexp_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_rsa_keygen_pubexp');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_rsa_mgf1_md := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_rsa_mgf1_md_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_rsa_mgf1_md);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_rsa_mgf1_md_allownil)}
    EVP_PKEY_CTX_set_rsa_mgf1_md := ERR_EVP_PKEY_CTX_set_rsa_mgf1_md;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_mgf1_md_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_rsa_mgf1_md_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_rsa_mgf1_md)}
      EVP_PKEY_CTX_set_rsa_mgf1_md := FC_EVP_PKEY_CTX_set_rsa_mgf1_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_mgf1_md_removed)}
    if EVP_PKEY_CTX_set_rsa_mgf1_md_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_rsa_mgf1_md)}
      EVP_PKEY_CTX_set_rsa_mgf1_md := _EVP_PKEY_CTX_set_rsa_mgf1_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_rsa_mgf1_md_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_rsa_mgf1_md');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_rsa_mgf1_md_name := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_rsa_mgf1_md_name_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_rsa_mgf1_md_name);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_rsa_mgf1_md_name_allownil)}
    EVP_PKEY_CTX_set_rsa_mgf1_md_name := ERR_EVP_PKEY_CTX_set_rsa_mgf1_md_name;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_mgf1_md_name_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_rsa_mgf1_md_name_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_rsa_mgf1_md_name)}
      EVP_PKEY_CTX_set_rsa_mgf1_md_name := FC_EVP_PKEY_CTX_set_rsa_mgf1_md_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_mgf1_md_name_removed)}
    if EVP_PKEY_CTX_set_rsa_mgf1_md_name_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_rsa_mgf1_md_name)}
      EVP_PKEY_CTX_set_rsa_mgf1_md_name := _EVP_PKEY_CTX_set_rsa_mgf1_md_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_rsa_mgf1_md_name_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_rsa_mgf1_md_name');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_get_rsa_mgf1_md := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_get_rsa_mgf1_md_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_get_rsa_mgf1_md);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_get_rsa_mgf1_md_allownil)}
    EVP_PKEY_CTX_get_rsa_mgf1_md := ERR_EVP_PKEY_CTX_get_rsa_mgf1_md;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_rsa_mgf1_md_introduced)}
    if LibVersion < EVP_PKEY_CTX_get_rsa_mgf1_md_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_get_rsa_mgf1_md)}
      EVP_PKEY_CTX_get_rsa_mgf1_md := FC_EVP_PKEY_CTX_get_rsa_mgf1_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_rsa_mgf1_md_removed)}
    if EVP_PKEY_CTX_get_rsa_mgf1_md_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_get_rsa_mgf1_md)}
      EVP_PKEY_CTX_get_rsa_mgf1_md := _EVP_PKEY_CTX_get_rsa_mgf1_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_get_rsa_mgf1_md_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_get_rsa_mgf1_md');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_get_rsa_mgf1_md_name := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_get_rsa_mgf1_md_name_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_get_rsa_mgf1_md_name);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_get_rsa_mgf1_md_name_allownil)}
    EVP_PKEY_CTX_get_rsa_mgf1_md_name := ERR_EVP_PKEY_CTX_get_rsa_mgf1_md_name;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_rsa_mgf1_md_name_introduced)}
    if LibVersion < EVP_PKEY_CTX_get_rsa_mgf1_md_name_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_get_rsa_mgf1_md_name)}
      EVP_PKEY_CTX_get_rsa_mgf1_md_name := FC_EVP_PKEY_CTX_get_rsa_mgf1_md_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_rsa_mgf1_md_name_removed)}
    if EVP_PKEY_CTX_get_rsa_mgf1_md_name_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_get_rsa_mgf1_md_name)}
      EVP_PKEY_CTX_get_rsa_mgf1_md_name := _EVP_PKEY_CTX_get_rsa_mgf1_md_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_get_rsa_mgf1_md_name_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_get_rsa_mgf1_md_name');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_allownil)}
    EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md := ERR_EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md)}
      EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md := FC_EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_removed)}
    if EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md)}
      EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md := _EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name_allownil)}
    EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name := ERR_EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name)}
      EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name := FC_EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name_removed)}
    if EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name)}
      EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name := _EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_rsa_pss_keygen_md := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_rsa_pss_keygen_md_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_rsa_pss_keygen_md);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_rsa_pss_keygen_md_allownil)}
    EVP_PKEY_CTX_set_rsa_pss_keygen_md := ERR_EVP_PKEY_CTX_set_rsa_pss_keygen_md;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_pss_keygen_md_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_rsa_pss_keygen_md_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_rsa_pss_keygen_md)}
      EVP_PKEY_CTX_set_rsa_pss_keygen_md := FC_EVP_PKEY_CTX_set_rsa_pss_keygen_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_pss_keygen_md_removed)}
    if EVP_PKEY_CTX_set_rsa_pss_keygen_md_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_rsa_pss_keygen_md)}
      EVP_PKEY_CTX_set_rsa_pss_keygen_md := _EVP_PKEY_CTX_set_rsa_pss_keygen_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_rsa_pss_keygen_md_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_rsa_pss_keygen_md');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_rsa_pss_keygen_md_name := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_rsa_pss_keygen_md_name_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_rsa_pss_keygen_md_name);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_rsa_pss_keygen_md_name_allownil)}
    EVP_PKEY_CTX_set_rsa_pss_keygen_md_name := ERR_EVP_PKEY_CTX_set_rsa_pss_keygen_md_name;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_pss_keygen_md_name_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_rsa_pss_keygen_md_name_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_rsa_pss_keygen_md_name)}
      EVP_PKEY_CTX_set_rsa_pss_keygen_md_name := FC_EVP_PKEY_CTX_set_rsa_pss_keygen_md_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_pss_keygen_md_name_removed)}
    if EVP_PKEY_CTX_set_rsa_pss_keygen_md_name_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_rsa_pss_keygen_md_name)}
      EVP_PKEY_CTX_set_rsa_pss_keygen_md_name := _EVP_PKEY_CTX_set_rsa_pss_keygen_md_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_rsa_pss_keygen_md_name_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_rsa_pss_keygen_md_name');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_rsa_oaep_md := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_rsa_oaep_md_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_rsa_oaep_md);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_rsa_oaep_md_allownil)}
    EVP_PKEY_CTX_set_rsa_oaep_md := ERR_EVP_PKEY_CTX_set_rsa_oaep_md;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_oaep_md_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_rsa_oaep_md_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_rsa_oaep_md)}
      EVP_PKEY_CTX_set_rsa_oaep_md := FC_EVP_PKEY_CTX_set_rsa_oaep_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_oaep_md_removed)}
    if EVP_PKEY_CTX_set_rsa_oaep_md_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_rsa_oaep_md)}
      EVP_PKEY_CTX_set_rsa_oaep_md := _EVP_PKEY_CTX_set_rsa_oaep_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_rsa_oaep_md_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_rsa_oaep_md');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_rsa_oaep_md_name := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_rsa_oaep_md_name_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_rsa_oaep_md_name);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_rsa_oaep_md_name_allownil)}
    EVP_PKEY_CTX_set_rsa_oaep_md_name := ERR_EVP_PKEY_CTX_set_rsa_oaep_md_name;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_oaep_md_name_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_rsa_oaep_md_name_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_rsa_oaep_md_name)}
      EVP_PKEY_CTX_set_rsa_oaep_md_name := FC_EVP_PKEY_CTX_set_rsa_oaep_md_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_rsa_oaep_md_name_removed)}
    if EVP_PKEY_CTX_set_rsa_oaep_md_name_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_rsa_oaep_md_name)}
      EVP_PKEY_CTX_set_rsa_oaep_md_name := _EVP_PKEY_CTX_set_rsa_oaep_md_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_rsa_oaep_md_name_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_rsa_oaep_md_name');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_get_rsa_oaep_md := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_get_rsa_oaep_md_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_get_rsa_oaep_md);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_get_rsa_oaep_md_allownil)}
    EVP_PKEY_CTX_get_rsa_oaep_md := ERR_EVP_PKEY_CTX_get_rsa_oaep_md;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_rsa_oaep_md_introduced)}
    if LibVersion < EVP_PKEY_CTX_get_rsa_oaep_md_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_get_rsa_oaep_md)}
      EVP_PKEY_CTX_get_rsa_oaep_md := FC_EVP_PKEY_CTX_get_rsa_oaep_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_rsa_oaep_md_removed)}
    if EVP_PKEY_CTX_get_rsa_oaep_md_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_get_rsa_oaep_md)}
      EVP_PKEY_CTX_get_rsa_oaep_md := _EVP_PKEY_CTX_get_rsa_oaep_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_get_rsa_oaep_md_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_get_rsa_oaep_md');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_get_rsa_oaep_md_name := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_get_rsa_oaep_md_name_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_get_rsa_oaep_md_name);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_get_rsa_oaep_md_name_allownil)}
    EVP_PKEY_CTX_get_rsa_oaep_md_name := ERR_EVP_PKEY_CTX_get_rsa_oaep_md_name;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_rsa_oaep_md_name_introduced)}
    if LibVersion < EVP_PKEY_CTX_get_rsa_oaep_md_name_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_get_rsa_oaep_md_name)}
      EVP_PKEY_CTX_get_rsa_oaep_md_name := FC_EVP_PKEY_CTX_get_rsa_oaep_md_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_rsa_oaep_md_name_removed)}
    if EVP_PKEY_CTX_get_rsa_oaep_md_name_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_get_rsa_oaep_md_name)}
      EVP_PKEY_CTX_get_rsa_oaep_md_name := _EVP_PKEY_CTX_get_rsa_oaep_md_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_get_rsa_oaep_md_name_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_get_rsa_oaep_md_name');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set0_rsa_oaep_label := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set0_rsa_oaep_label_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set0_rsa_oaep_label);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set0_rsa_oaep_label_allownil)}
    EVP_PKEY_CTX_set0_rsa_oaep_label := ERR_EVP_PKEY_CTX_set0_rsa_oaep_label;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set0_rsa_oaep_label_introduced)}
    if LibVersion < EVP_PKEY_CTX_set0_rsa_oaep_label_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set0_rsa_oaep_label)}
      EVP_PKEY_CTX_set0_rsa_oaep_label := FC_EVP_PKEY_CTX_set0_rsa_oaep_label;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set0_rsa_oaep_label_removed)}
    if EVP_PKEY_CTX_set0_rsa_oaep_label_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set0_rsa_oaep_label)}
      EVP_PKEY_CTX_set0_rsa_oaep_label := _EVP_PKEY_CTX_set0_rsa_oaep_label;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set0_rsa_oaep_label_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set0_rsa_oaep_label');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_get0_rsa_oaep_label := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_get0_rsa_oaep_label_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_get0_rsa_oaep_label);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_get0_rsa_oaep_label_allownil)}
    EVP_PKEY_CTX_get0_rsa_oaep_label := ERR_EVP_PKEY_CTX_get0_rsa_oaep_label;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get0_rsa_oaep_label_introduced)}
    if LibVersion < EVP_PKEY_CTX_get0_rsa_oaep_label_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_get0_rsa_oaep_label)}
      EVP_PKEY_CTX_get0_rsa_oaep_label := FC_EVP_PKEY_CTX_get0_rsa_oaep_label;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get0_rsa_oaep_label_removed)}
    if EVP_PKEY_CTX_get0_rsa_oaep_label_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_get0_rsa_oaep_label)}
      EVP_PKEY_CTX_get0_rsa_oaep_label := _EVP_PKEY_CTX_get0_rsa_oaep_label;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_get0_rsa_oaep_label_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_get0_rsa_oaep_label');
    {$ifend}
  end;
  
  RSA_new := LoadLibFunction(ADllHandle, RSA_new_procname);
  FuncLoadError := not assigned(RSA_new);
  if FuncLoadError then
  begin
    {$if not defined(RSA_new_allownil)}
    RSA_new := ERR_RSA_new;
    {$ifend}
    {$if declared(RSA_new_introduced)}
    if LibVersion < RSA_new_introduced then
    begin
      {$if declared(FC_RSA_new)}
      RSA_new := FC_RSA_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_new_removed)}
    if RSA_new_removed <= LibVersion then
    begin
      {$if declared(_RSA_new)}
      RSA_new := _RSA_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_new_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_new');
    {$ifend}
  end;
  
  RSA_new_method := LoadLibFunction(ADllHandle, RSA_new_method_procname);
  FuncLoadError := not assigned(RSA_new_method);
  if FuncLoadError then
  begin
    {$if not defined(RSA_new_method_allownil)}
    RSA_new_method := ERR_RSA_new_method;
    {$ifend}
    {$if declared(RSA_new_method_introduced)}
    if LibVersion < RSA_new_method_introduced then
    begin
      {$if declared(FC_RSA_new_method)}
      RSA_new_method := FC_RSA_new_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_new_method_removed)}
    if RSA_new_method_removed <= LibVersion then
    begin
      {$if declared(_RSA_new_method)}
      RSA_new_method := _RSA_new_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_new_method_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_new_method');
    {$ifend}
  end;
  
  RSA_bits := LoadLibFunction(ADllHandle, RSA_bits_procname);
  FuncLoadError := not assigned(RSA_bits);
  if FuncLoadError then
  begin
    {$if not defined(RSA_bits_allownil)}
    RSA_bits := ERR_RSA_bits;
    {$ifend}
    {$if declared(RSA_bits_introduced)}
    if LibVersion < RSA_bits_introduced then
    begin
      {$if declared(FC_RSA_bits)}
      RSA_bits := FC_RSA_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_bits_removed)}
    if RSA_bits_removed <= LibVersion then
    begin
      {$if declared(_RSA_bits)}
      RSA_bits := _RSA_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_bits_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_bits');
    {$ifend}
  end;
  
  RSA_size := LoadLibFunction(ADllHandle, RSA_size_procname);
  FuncLoadError := not assigned(RSA_size);
  if FuncLoadError then
  begin
    {$if not defined(RSA_size_allownil)}
    RSA_size := ERR_RSA_size;
    {$ifend}
    {$if declared(RSA_size_introduced)}
    if LibVersion < RSA_size_introduced then
    begin
      {$if declared(FC_RSA_size)}
      RSA_size := FC_RSA_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_size_removed)}
    if RSA_size_removed <= LibVersion then
    begin
      {$if declared(_RSA_size)}
      RSA_size := _RSA_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_size_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_size');
    {$ifend}
  end;
  
  RSA_security_bits := LoadLibFunction(ADllHandle, RSA_security_bits_procname);
  FuncLoadError := not assigned(RSA_security_bits);
  if FuncLoadError then
  begin
    {$if not defined(RSA_security_bits_allownil)}
    RSA_security_bits := ERR_RSA_security_bits;
    {$ifend}
    {$if declared(RSA_security_bits_introduced)}
    if LibVersion < RSA_security_bits_introduced then
    begin
      {$if declared(FC_RSA_security_bits)}
      RSA_security_bits := FC_RSA_security_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_security_bits_removed)}
    if RSA_security_bits_removed <= LibVersion then
    begin
      {$if declared(_RSA_security_bits)}
      RSA_security_bits := _RSA_security_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_security_bits_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_security_bits');
    {$ifend}
  end;
  
  RSA_set0_key := LoadLibFunction(ADllHandle, RSA_set0_key_procname);
  FuncLoadError := not assigned(RSA_set0_key);
  if FuncLoadError then
  begin
    {$if not defined(RSA_set0_key_allownil)}
    RSA_set0_key := ERR_RSA_set0_key;
    {$ifend}
    {$if declared(RSA_set0_key_introduced)}
    if LibVersion < RSA_set0_key_introduced then
    begin
      {$if declared(FC_RSA_set0_key)}
      RSA_set0_key := FC_RSA_set0_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_set0_key_removed)}
    if RSA_set0_key_removed <= LibVersion then
    begin
      {$if declared(_RSA_set0_key)}
      RSA_set0_key := _RSA_set0_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_set0_key_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_set0_key');
    {$ifend}
  end;
  
  RSA_set0_factors := LoadLibFunction(ADllHandle, RSA_set0_factors_procname);
  FuncLoadError := not assigned(RSA_set0_factors);
  if FuncLoadError then
  begin
    {$if not defined(RSA_set0_factors_allownil)}
    RSA_set0_factors := ERR_RSA_set0_factors;
    {$ifend}
    {$if declared(RSA_set0_factors_introduced)}
    if LibVersion < RSA_set0_factors_introduced then
    begin
      {$if declared(FC_RSA_set0_factors)}
      RSA_set0_factors := FC_RSA_set0_factors;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_set0_factors_removed)}
    if RSA_set0_factors_removed <= LibVersion then
    begin
      {$if declared(_RSA_set0_factors)}
      RSA_set0_factors := _RSA_set0_factors;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_set0_factors_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_set0_factors');
    {$ifend}
  end;
  
  RSA_set0_crt_params := LoadLibFunction(ADllHandle, RSA_set0_crt_params_procname);
  FuncLoadError := not assigned(RSA_set0_crt_params);
  if FuncLoadError then
  begin
    {$if not defined(RSA_set0_crt_params_allownil)}
    RSA_set0_crt_params := ERR_RSA_set0_crt_params;
    {$ifend}
    {$if declared(RSA_set0_crt_params_introduced)}
    if LibVersion < RSA_set0_crt_params_introduced then
    begin
      {$if declared(FC_RSA_set0_crt_params)}
      RSA_set0_crt_params := FC_RSA_set0_crt_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_set0_crt_params_removed)}
    if RSA_set0_crt_params_removed <= LibVersion then
    begin
      {$if declared(_RSA_set0_crt_params)}
      RSA_set0_crt_params := _RSA_set0_crt_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_set0_crt_params_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_set0_crt_params');
    {$ifend}
  end;
  
  RSA_set0_multi_prime_params := LoadLibFunction(ADllHandle, RSA_set0_multi_prime_params_procname);
  FuncLoadError := not assigned(RSA_set0_multi_prime_params);
  if FuncLoadError then
  begin
    {$if not defined(RSA_set0_multi_prime_params_allownil)}
    RSA_set0_multi_prime_params := ERR_RSA_set0_multi_prime_params;
    {$ifend}
    {$if declared(RSA_set0_multi_prime_params_introduced)}
    if LibVersion < RSA_set0_multi_prime_params_introduced then
    begin
      {$if declared(FC_RSA_set0_multi_prime_params)}
      RSA_set0_multi_prime_params := FC_RSA_set0_multi_prime_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_set0_multi_prime_params_removed)}
    if RSA_set0_multi_prime_params_removed <= LibVersion then
    begin
      {$if declared(_RSA_set0_multi_prime_params)}
      RSA_set0_multi_prime_params := _RSA_set0_multi_prime_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_set0_multi_prime_params_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_set0_multi_prime_params');
    {$ifend}
  end;
  
  RSA_get0_key := LoadLibFunction(ADllHandle, RSA_get0_key_procname);
  FuncLoadError := not assigned(RSA_get0_key);
  if FuncLoadError then
  begin
    {$if not defined(RSA_get0_key_allownil)}
    RSA_get0_key := ERR_RSA_get0_key;
    {$ifend}
    {$if declared(RSA_get0_key_introduced)}
    if LibVersion < RSA_get0_key_introduced then
    begin
      {$if declared(FC_RSA_get0_key)}
      RSA_get0_key := FC_RSA_get0_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_get0_key_removed)}
    if RSA_get0_key_removed <= LibVersion then
    begin
      {$if declared(_RSA_get0_key)}
      RSA_get0_key := _RSA_get0_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_get0_key_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_get0_key');
    {$ifend}
  end;
  
  RSA_get0_factors := LoadLibFunction(ADllHandle, RSA_get0_factors_procname);
  FuncLoadError := not assigned(RSA_get0_factors);
  if FuncLoadError then
  begin
    {$if not defined(RSA_get0_factors_allownil)}
    RSA_get0_factors := ERR_RSA_get0_factors;
    {$ifend}
    {$if declared(RSA_get0_factors_introduced)}
    if LibVersion < RSA_get0_factors_introduced then
    begin
      {$if declared(FC_RSA_get0_factors)}
      RSA_get0_factors := FC_RSA_get0_factors;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_get0_factors_removed)}
    if RSA_get0_factors_removed <= LibVersion then
    begin
      {$if declared(_RSA_get0_factors)}
      RSA_get0_factors := _RSA_get0_factors;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_get0_factors_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_get0_factors');
    {$ifend}
  end;
  
  RSA_get_multi_prime_extra_count := LoadLibFunction(ADllHandle, RSA_get_multi_prime_extra_count_procname);
  FuncLoadError := not assigned(RSA_get_multi_prime_extra_count);
  if FuncLoadError then
  begin
    {$if not defined(RSA_get_multi_prime_extra_count_allownil)}
    RSA_get_multi_prime_extra_count := ERR_RSA_get_multi_prime_extra_count;
    {$ifend}
    {$if declared(RSA_get_multi_prime_extra_count_introduced)}
    if LibVersion < RSA_get_multi_prime_extra_count_introduced then
    begin
      {$if declared(FC_RSA_get_multi_prime_extra_count)}
      RSA_get_multi_prime_extra_count := FC_RSA_get_multi_prime_extra_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_get_multi_prime_extra_count_removed)}
    if RSA_get_multi_prime_extra_count_removed <= LibVersion then
    begin
      {$if declared(_RSA_get_multi_prime_extra_count)}
      RSA_get_multi_prime_extra_count := _RSA_get_multi_prime_extra_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_get_multi_prime_extra_count_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_get_multi_prime_extra_count');
    {$ifend}
  end;
  
  RSA_get0_multi_prime_factors := LoadLibFunction(ADllHandle, RSA_get0_multi_prime_factors_procname);
  FuncLoadError := not assigned(RSA_get0_multi_prime_factors);
  if FuncLoadError then
  begin
    {$if not defined(RSA_get0_multi_prime_factors_allownil)}
    RSA_get0_multi_prime_factors := ERR_RSA_get0_multi_prime_factors;
    {$ifend}
    {$if declared(RSA_get0_multi_prime_factors_introduced)}
    if LibVersion < RSA_get0_multi_prime_factors_introduced then
    begin
      {$if declared(FC_RSA_get0_multi_prime_factors)}
      RSA_get0_multi_prime_factors := FC_RSA_get0_multi_prime_factors;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_get0_multi_prime_factors_removed)}
    if RSA_get0_multi_prime_factors_removed <= LibVersion then
    begin
      {$if declared(_RSA_get0_multi_prime_factors)}
      RSA_get0_multi_prime_factors := _RSA_get0_multi_prime_factors;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_get0_multi_prime_factors_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_get0_multi_prime_factors');
    {$ifend}
  end;
  
  RSA_get0_crt_params := LoadLibFunction(ADllHandle, RSA_get0_crt_params_procname);
  FuncLoadError := not assigned(RSA_get0_crt_params);
  if FuncLoadError then
  begin
    {$if not defined(RSA_get0_crt_params_allownil)}
    RSA_get0_crt_params := ERR_RSA_get0_crt_params;
    {$ifend}
    {$if declared(RSA_get0_crt_params_introduced)}
    if LibVersion < RSA_get0_crt_params_introduced then
    begin
      {$if declared(FC_RSA_get0_crt_params)}
      RSA_get0_crt_params := FC_RSA_get0_crt_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_get0_crt_params_removed)}
    if RSA_get0_crt_params_removed <= LibVersion then
    begin
      {$if declared(_RSA_get0_crt_params)}
      RSA_get0_crt_params := _RSA_get0_crt_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_get0_crt_params_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_get0_crt_params');
    {$ifend}
  end;
  
  RSA_get0_multi_prime_crt_params := LoadLibFunction(ADllHandle, RSA_get0_multi_prime_crt_params_procname);
  FuncLoadError := not assigned(RSA_get0_multi_prime_crt_params);
  if FuncLoadError then
  begin
    {$if not defined(RSA_get0_multi_prime_crt_params_allownil)}
    RSA_get0_multi_prime_crt_params := ERR_RSA_get0_multi_prime_crt_params;
    {$ifend}
    {$if declared(RSA_get0_multi_prime_crt_params_introduced)}
    if LibVersion < RSA_get0_multi_prime_crt_params_introduced then
    begin
      {$if declared(FC_RSA_get0_multi_prime_crt_params)}
      RSA_get0_multi_prime_crt_params := FC_RSA_get0_multi_prime_crt_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_get0_multi_prime_crt_params_removed)}
    if RSA_get0_multi_prime_crt_params_removed <= LibVersion then
    begin
      {$if declared(_RSA_get0_multi_prime_crt_params)}
      RSA_get0_multi_prime_crt_params := _RSA_get0_multi_prime_crt_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_get0_multi_prime_crt_params_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_get0_multi_prime_crt_params');
    {$ifend}
  end;
  
  RSA_get0_n := LoadLibFunction(ADllHandle, RSA_get0_n_procname);
  FuncLoadError := not assigned(RSA_get0_n);
  if FuncLoadError then
  begin
    {$if not defined(RSA_get0_n_allownil)}
    RSA_get0_n := ERR_RSA_get0_n;
    {$ifend}
    {$if declared(RSA_get0_n_introduced)}
    if LibVersion < RSA_get0_n_introduced then
    begin
      {$if declared(FC_RSA_get0_n)}
      RSA_get0_n := FC_RSA_get0_n;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_get0_n_removed)}
    if RSA_get0_n_removed <= LibVersion then
    begin
      {$if declared(_RSA_get0_n)}
      RSA_get0_n := _RSA_get0_n;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_get0_n_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_get0_n');
    {$ifend}
  end;
  
  RSA_get0_e := LoadLibFunction(ADllHandle, RSA_get0_e_procname);
  FuncLoadError := not assigned(RSA_get0_e);
  if FuncLoadError then
  begin
    {$if not defined(RSA_get0_e_allownil)}
    RSA_get0_e := ERR_RSA_get0_e;
    {$ifend}
    {$if declared(RSA_get0_e_introduced)}
    if LibVersion < RSA_get0_e_introduced then
    begin
      {$if declared(FC_RSA_get0_e)}
      RSA_get0_e := FC_RSA_get0_e;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_get0_e_removed)}
    if RSA_get0_e_removed <= LibVersion then
    begin
      {$if declared(_RSA_get0_e)}
      RSA_get0_e := _RSA_get0_e;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_get0_e_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_get0_e');
    {$ifend}
  end;
  
  RSA_get0_d := LoadLibFunction(ADllHandle, RSA_get0_d_procname);
  FuncLoadError := not assigned(RSA_get0_d);
  if FuncLoadError then
  begin
    {$if not defined(RSA_get0_d_allownil)}
    RSA_get0_d := ERR_RSA_get0_d;
    {$ifend}
    {$if declared(RSA_get0_d_introduced)}
    if LibVersion < RSA_get0_d_introduced then
    begin
      {$if declared(FC_RSA_get0_d)}
      RSA_get0_d := FC_RSA_get0_d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_get0_d_removed)}
    if RSA_get0_d_removed <= LibVersion then
    begin
      {$if declared(_RSA_get0_d)}
      RSA_get0_d := _RSA_get0_d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_get0_d_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_get0_d');
    {$ifend}
  end;
  
  RSA_get0_p := LoadLibFunction(ADllHandle, RSA_get0_p_procname);
  FuncLoadError := not assigned(RSA_get0_p);
  if FuncLoadError then
  begin
    {$if not defined(RSA_get0_p_allownil)}
    RSA_get0_p := ERR_RSA_get0_p;
    {$ifend}
    {$if declared(RSA_get0_p_introduced)}
    if LibVersion < RSA_get0_p_introduced then
    begin
      {$if declared(FC_RSA_get0_p)}
      RSA_get0_p := FC_RSA_get0_p;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_get0_p_removed)}
    if RSA_get0_p_removed <= LibVersion then
    begin
      {$if declared(_RSA_get0_p)}
      RSA_get0_p := _RSA_get0_p;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_get0_p_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_get0_p');
    {$ifend}
  end;
  
  RSA_get0_q := LoadLibFunction(ADllHandle, RSA_get0_q_procname);
  FuncLoadError := not assigned(RSA_get0_q);
  if FuncLoadError then
  begin
    {$if not defined(RSA_get0_q_allownil)}
    RSA_get0_q := ERR_RSA_get0_q;
    {$ifend}
    {$if declared(RSA_get0_q_introduced)}
    if LibVersion < RSA_get0_q_introduced then
    begin
      {$if declared(FC_RSA_get0_q)}
      RSA_get0_q := FC_RSA_get0_q;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_get0_q_removed)}
    if RSA_get0_q_removed <= LibVersion then
    begin
      {$if declared(_RSA_get0_q)}
      RSA_get0_q := _RSA_get0_q;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_get0_q_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_get0_q');
    {$ifend}
  end;
  
  RSA_get0_dmp1 := LoadLibFunction(ADllHandle, RSA_get0_dmp1_procname);
  FuncLoadError := not assigned(RSA_get0_dmp1);
  if FuncLoadError then
  begin
    {$if not defined(RSA_get0_dmp1_allownil)}
    RSA_get0_dmp1 := ERR_RSA_get0_dmp1;
    {$ifend}
    {$if declared(RSA_get0_dmp1_introduced)}
    if LibVersion < RSA_get0_dmp1_introduced then
    begin
      {$if declared(FC_RSA_get0_dmp1)}
      RSA_get0_dmp1 := FC_RSA_get0_dmp1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_get0_dmp1_removed)}
    if RSA_get0_dmp1_removed <= LibVersion then
    begin
      {$if declared(_RSA_get0_dmp1)}
      RSA_get0_dmp1 := _RSA_get0_dmp1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_get0_dmp1_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_get0_dmp1');
    {$ifend}
  end;
  
  RSA_get0_dmq1 := LoadLibFunction(ADllHandle, RSA_get0_dmq1_procname);
  FuncLoadError := not assigned(RSA_get0_dmq1);
  if FuncLoadError then
  begin
    {$if not defined(RSA_get0_dmq1_allownil)}
    RSA_get0_dmq1 := ERR_RSA_get0_dmq1;
    {$ifend}
    {$if declared(RSA_get0_dmq1_introduced)}
    if LibVersion < RSA_get0_dmq1_introduced then
    begin
      {$if declared(FC_RSA_get0_dmq1)}
      RSA_get0_dmq1 := FC_RSA_get0_dmq1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_get0_dmq1_removed)}
    if RSA_get0_dmq1_removed <= LibVersion then
    begin
      {$if declared(_RSA_get0_dmq1)}
      RSA_get0_dmq1 := _RSA_get0_dmq1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_get0_dmq1_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_get0_dmq1');
    {$ifend}
  end;
  
  RSA_get0_iqmp := LoadLibFunction(ADllHandle, RSA_get0_iqmp_procname);
  FuncLoadError := not assigned(RSA_get0_iqmp);
  if FuncLoadError then
  begin
    {$if not defined(RSA_get0_iqmp_allownil)}
    RSA_get0_iqmp := ERR_RSA_get0_iqmp;
    {$ifend}
    {$if declared(RSA_get0_iqmp_introduced)}
    if LibVersion < RSA_get0_iqmp_introduced then
    begin
      {$if declared(FC_RSA_get0_iqmp)}
      RSA_get0_iqmp := FC_RSA_get0_iqmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_get0_iqmp_removed)}
    if RSA_get0_iqmp_removed <= LibVersion then
    begin
      {$if declared(_RSA_get0_iqmp)}
      RSA_get0_iqmp := _RSA_get0_iqmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_get0_iqmp_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_get0_iqmp');
    {$ifend}
  end;
  
  RSA_get0_pss_params := LoadLibFunction(ADllHandle, RSA_get0_pss_params_procname);
  FuncLoadError := not assigned(RSA_get0_pss_params);
  if FuncLoadError then
  begin
    {$if not defined(RSA_get0_pss_params_allownil)}
    RSA_get0_pss_params := ERR_RSA_get0_pss_params;
    {$ifend}
    {$if declared(RSA_get0_pss_params_introduced)}
    if LibVersion < RSA_get0_pss_params_introduced then
    begin
      {$if declared(FC_RSA_get0_pss_params)}
      RSA_get0_pss_params := FC_RSA_get0_pss_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_get0_pss_params_removed)}
    if RSA_get0_pss_params_removed <= LibVersion then
    begin
      {$if declared(_RSA_get0_pss_params)}
      RSA_get0_pss_params := _RSA_get0_pss_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_get0_pss_params_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_get0_pss_params');
    {$ifend}
  end;
  
  RSA_clear_flags := LoadLibFunction(ADllHandle, RSA_clear_flags_procname);
  FuncLoadError := not assigned(RSA_clear_flags);
  if FuncLoadError then
  begin
    {$if not defined(RSA_clear_flags_allownil)}
    RSA_clear_flags := ERR_RSA_clear_flags;
    {$ifend}
    {$if declared(RSA_clear_flags_introduced)}
    if LibVersion < RSA_clear_flags_introduced then
    begin
      {$if declared(FC_RSA_clear_flags)}
      RSA_clear_flags := FC_RSA_clear_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_clear_flags_removed)}
    if RSA_clear_flags_removed <= LibVersion then
    begin
      {$if declared(_RSA_clear_flags)}
      RSA_clear_flags := _RSA_clear_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_clear_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_clear_flags');
    {$ifend}
  end;
  
  RSA_test_flags := LoadLibFunction(ADllHandle, RSA_test_flags_procname);
  FuncLoadError := not assigned(RSA_test_flags);
  if FuncLoadError then
  begin
    {$if not defined(RSA_test_flags_allownil)}
    RSA_test_flags := ERR_RSA_test_flags;
    {$ifend}
    {$if declared(RSA_test_flags_introduced)}
    if LibVersion < RSA_test_flags_introduced then
    begin
      {$if declared(FC_RSA_test_flags)}
      RSA_test_flags := FC_RSA_test_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_test_flags_removed)}
    if RSA_test_flags_removed <= LibVersion then
    begin
      {$if declared(_RSA_test_flags)}
      RSA_test_flags := _RSA_test_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_test_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_test_flags');
    {$ifend}
  end;
  
  RSA_set_flags := LoadLibFunction(ADllHandle, RSA_set_flags_procname);
  FuncLoadError := not assigned(RSA_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(RSA_set_flags_allownil)}
    RSA_set_flags := ERR_RSA_set_flags;
    {$ifend}
    {$if declared(RSA_set_flags_introduced)}
    if LibVersion < RSA_set_flags_introduced then
    begin
      {$if declared(FC_RSA_set_flags)}
      RSA_set_flags := FC_RSA_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_set_flags_removed)}
    if RSA_set_flags_removed <= LibVersion then
    begin
      {$if declared(_RSA_set_flags)}
      RSA_set_flags := _RSA_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_set_flags');
    {$ifend}
  end;
  
  RSA_get_version := LoadLibFunction(ADllHandle, RSA_get_version_procname);
  FuncLoadError := not assigned(RSA_get_version);
  if FuncLoadError then
  begin
    {$if not defined(RSA_get_version_allownil)}
    RSA_get_version := ERR_RSA_get_version;
    {$ifend}
    {$if declared(RSA_get_version_introduced)}
    if LibVersion < RSA_get_version_introduced then
    begin
      {$if declared(FC_RSA_get_version)}
      RSA_get_version := FC_RSA_get_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_get_version_removed)}
    if RSA_get_version_removed <= LibVersion then
    begin
      {$if declared(_RSA_get_version)}
      RSA_get_version := _RSA_get_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_get_version_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_get_version');
    {$ifend}
  end;
  
  RSA_get0_engine := LoadLibFunction(ADllHandle, RSA_get0_engine_procname);
  FuncLoadError := not assigned(RSA_get0_engine);
  if FuncLoadError then
  begin
    {$if not defined(RSA_get0_engine_allownil)}
    RSA_get0_engine := ERR_RSA_get0_engine;
    {$ifend}
    {$if declared(RSA_get0_engine_introduced)}
    if LibVersion < RSA_get0_engine_introduced then
    begin
      {$if declared(FC_RSA_get0_engine)}
      RSA_get0_engine := FC_RSA_get0_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_get0_engine_removed)}
    if RSA_get0_engine_removed <= LibVersion then
    begin
      {$if declared(_RSA_get0_engine)}
      RSA_get0_engine := _RSA_get0_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_get0_engine_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_get0_engine');
    {$ifend}
  end;
  
  
  RSA_generate_key_ex := LoadLibFunction(ADllHandle, RSA_generate_key_ex_procname);
  FuncLoadError := not assigned(RSA_generate_key_ex);
  if FuncLoadError then
  begin
    {$if not defined(RSA_generate_key_ex_allownil)}
    RSA_generate_key_ex := ERR_RSA_generate_key_ex;
    {$ifend}
    {$if declared(RSA_generate_key_ex_introduced)}
    if LibVersion < RSA_generate_key_ex_introduced then
    begin
      {$if declared(FC_RSA_generate_key_ex)}
      RSA_generate_key_ex := FC_RSA_generate_key_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_generate_key_ex_removed)}
    if RSA_generate_key_ex_removed <= LibVersion then
    begin
      {$if declared(_RSA_generate_key_ex)}
      RSA_generate_key_ex := _RSA_generate_key_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_generate_key_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_generate_key_ex');
    {$ifend}
  end;
  
  RSA_generate_multi_prime_key := LoadLibFunction(ADllHandle, RSA_generate_multi_prime_key_procname);
  FuncLoadError := not assigned(RSA_generate_multi_prime_key);
  if FuncLoadError then
  begin
    {$if not defined(RSA_generate_multi_prime_key_allownil)}
    RSA_generate_multi_prime_key := ERR_RSA_generate_multi_prime_key;
    {$ifend}
    {$if declared(RSA_generate_multi_prime_key_introduced)}
    if LibVersion < RSA_generate_multi_prime_key_introduced then
    begin
      {$if declared(FC_RSA_generate_multi_prime_key)}
      RSA_generate_multi_prime_key := FC_RSA_generate_multi_prime_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_generate_multi_prime_key_removed)}
    if RSA_generate_multi_prime_key_removed <= LibVersion then
    begin
      {$if declared(_RSA_generate_multi_prime_key)}
      RSA_generate_multi_prime_key := _RSA_generate_multi_prime_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_generate_multi_prime_key_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_generate_multi_prime_key');
    {$ifend}
  end;
  
  RSA_X931_derive_ex := LoadLibFunction(ADllHandle, RSA_X931_derive_ex_procname);
  FuncLoadError := not assigned(RSA_X931_derive_ex);
  if FuncLoadError then
  begin
    {$if not defined(RSA_X931_derive_ex_allownil)}
    RSA_X931_derive_ex := ERR_RSA_X931_derive_ex;
    {$ifend}
    {$if declared(RSA_X931_derive_ex_introduced)}
    if LibVersion < RSA_X931_derive_ex_introduced then
    begin
      {$if declared(FC_RSA_X931_derive_ex)}
      RSA_X931_derive_ex := FC_RSA_X931_derive_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_X931_derive_ex_removed)}
    if RSA_X931_derive_ex_removed <= LibVersion then
    begin
      {$if declared(_RSA_X931_derive_ex)}
      RSA_X931_derive_ex := _RSA_X931_derive_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_X931_derive_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_X931_derive_ex');
    {$ifend}
  end;
  
  RSA_X931_generate_key_ex := LoadLibFunction(ADllHandle, RSA_X931_generate_key_ex_procname);
  FuncLoadError := not assigned(RSA_X931_generate_key_ex);
  if FuncLoadError then
  begin
    {$if not defined(RSA_X931_generate_key_ex_allownil)}
    RSA_X931_generate_key_ex := ERR_RSA_X931_generate_key_ex;
    {$ifend}
    {$if declared(RSA_X931_generate_key_ex_introduced)}
    if LibVersion < RSA_X931_generate_key_ex_introduced then
    begin
      {$if declared(FC_RSA_X931_generate_key_ex)}
      RSA_X931_generate_key_ex := FC_RSA_X931_generate_key_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_X931_generate_key_ex_removed)}
    if RSA_X931_generate_key_ex_removed <= LibVersion then
    begin
      {$if declared(_RSA_X931_generate_key_ex)}
      RSA_X931_generate_key_ex := _RSA_X931_generate_key_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_X931_generate_key_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_X931_generate_key_ex');
    {$ifend}
  end;
  
  RSA_check_key := LoadLibFunction(ADllHandle, RSA_check_key_procname);
  FuncLoadError := not assigned(RSA_check_key);
  if FuncLoadError then
  begin
    {$if not defined(RSA_check_key_allownil)}
    RSA_check_key := ERR_RSA_check_key;
    {$ifend}
    {$if declared(RSA_check_key_introduced)}
    if LibVersion < RSA_check_key_introduced then
    begin
      {$if declared(FC_RSA_check_key)}
      RSA_check_key := FC_RSA_check_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_check_key_removed)}
    if RSA_check_key_removed <= LibVersion then
    begin
      {$if declared(_RSA_check_key)}
      RSA_check_key := _RSA_check_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_check_key_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_check_key');
    {$ifend}
  end;
  
  RSA_check_key_ex := LoadLibFunction(ADllHandle, RSA_check_key_ex_procname);
  FuncLoadError := not assigned(RSA_check_key_ex);
  if FuncLoadError then
  begin
    {$if not defined(RSA_check_key_ex_allownil)}
    RSA_check_key_ex := ERR_RSA_check_key_ex;
    {$ifend}
    {$if declared(RSA_check_key_ex_introduced)}
    if LibVersion < RSA_check_key_ex_introduced then
    begin
      {$if declared(FC_RSA_check_key_ex)}
      RSA_check_key_ex := FC_RSA_check_key_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_check_key_ex_removed)}
    if RSA_check_key_ex_removed <= LibVersion then
    begin
      {$if declared(_RSA_check_key_ex)}
      RSA_check_key_ex := _RSA_check_key_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_check_key_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_check_key_ex');
    {$ifend}
  end;
  
  RSA_public_encrypt := LoadLibFunction(ADllHandle, RSA_public_encrypt_procname);
  FuncLoadError := not assigned(RSA_public_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(RSA_public_encrypt_allownil)}
    RSA_public_encrypt := ERR_RSA_public_encrypt;
    {$ifend}
    {$if declared(RSA_public_encrypt_introduced)}
    if LibVersion < RSA_public_encrypt_introduced then
    begin
      {$if declared(FC_RSA_public_encrypt)}
      RSA_public_encrypt := FC_RSA_public_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_public_encrypt_removed)}
    if RSA_public_encrypt_removed <= LibVersion then
    begin
      {$if declared(_RSA_public_encrypt)}
      RSA_public_encrypt := _RSA_public_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_public_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_public_encrypt');
    {$ifend}
  end;
  
  RSA_private_encrypt := LoadLibFunction(ADllHandle, RSA_private_encrypt_procname);
  FuncLoadError := not assigned(RSA_private_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(RSA_private_encrypt_allownil)}
    RSA_private_encrypt := ERR_RSA_private_encrypt;
    {$ifend}
    {$if declared(RSA_private_encrypt_introduced)}
    if LibVersion < RSA_private_encrypt_introduced then
    begin
      {$if declared(FC_RSA_private_encrypt)}
      RSA_private_encrypt := FC_RSA_private_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_private_encrypt_removed)}
    if RSA_private_encrypt_removed <= LibVersion then
    begin
      {$if declared(_RSA_private_encrypt)}
      RSA_private_encrypt := _RSA_private_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_private_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_private_encrypt');
    {$ifend}
  end;
  
  RSA_public_decrypt := LoadLibFunction(ADllHandle, RSA_public_decrypt_procname);
  FuncLoadError := not assigned(RSA_public_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(RSA_public_decrypt_allownil)}
    RSA_public_decrypt := ERR_RSA_public_decrypt;
    {$ifend}
    {$if declared(RSA_public_decrypt_introduced)}
    if LibVersion < RSA_public_decrypt_introduced then
    begin
      {$if declared(FC_RSA_public_decrypt)}
      RSA_public_decrypt := FC_RSA_public_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_public_decrypt_removed)}
    if RSA_public_decrypt_removed <= LibVersion then
    begin
      {$if declared(_RSA_public_decrypt)}
      RSA_public_decrypt := _RSA_public_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_public_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_public_decrypt');
    {$ifend}
  end;
  
  RSA_private_decrypt := LoadLibFunction(ADllHandle, RSA_private_decrypt_procname);
  FuncLoadError := not assigned(RSA_private_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(RSA_private_decrypt_allownil)}
    RSA_private_decrypt := ERR_RSA_private_decrypt;
    {$ifend}
    {$if declared(RSA_private_decrypt_introduced)}
    if LibVersion < RSA_private_decrypt_introduced then
    begin
      {$if declared(FC_RSA_private_decrypt)}
      RSA_private_decrypt := FC_RSA_private_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_private_decrypt_removed)}
    if RSA_private_decrypt_removed <= LibVersion then
    begin
      {$if declared(_RSA_private_decrypt)}
      RSA_private_decrypt := _RSA_private_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_private_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_private_decrypt');
    {$ifend}
  end;
  
  RSA_free := LoadLibFunction(ADllHandle, RSA_free_procname);
  FuncLoadError := not assigned(RSA_free);
  if FuncLoadError then
  begin
    {$if not defined(RSA_free_allownil)}
    RSA_free := ERR_RSA_free;
    {$ifend}
    {$if declared(RSA_free_introduced)}
    if LibVersion < RSA_free_introduced then
    begin
      {$if declared(FC_RSA_free)}
      RSA_free := FC_RSA_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_free_removed)}
    if RSA_free_removed <= LibVersion then
    begin
      {$if declared(_RSA_free)}
      RSA_free := _RSA_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_free_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_free');
    {$ifend}
  end;
  
  RSA_up_ref := LoadLibFunction(ADllHandle, RSA_up_ref_procname);
  FuncLoadError := not assigned(RSA_up_ref);
  if FuncLoadError then
  begin
    {$if not defined(RSA_up_ref_allownil)}
    RSA_up_ref := ERR_RSA_up_ref;
    {$ifend}
    {$if declared(RSA_up_ref_introduced)}
    if LibVersion < RSA_up_ref_introduced then
    begin
      {$if declared(FC_RSA_up_ref)}
      RSA_up_ref := FC_RSA_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_up_ref_removed)}
    if RSA_up_ref_removed <= LibVersion then
    begin
      {$if declared(_RSA_up_ref)}
      RSA_up_ref := _RSA_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_up_ref_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_up_ref');
    {$ifend}
  end;
  
  RSA_flags := LoadLibFunction(ADllHandle, RSA_flags_procname);
  FuncLoadError := not assigned(RSA_flags);
  if FuncLoadError then
  begin
    {$if not defined(RSA_flags_allownil)}
    RSA_flags := ERR_RSA_flags;
    {$ifend}
    {$if declared(RSA_flags_introduced)}
    if LibVersion < RSA_flags_introduced then
    begin
      {$if declared(FC_RSA_flags)}
      RSA_flags := FC_RSA_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_flags_removed)}
    if RSA_flags_removed <= LibVersion then
    begin
      {$if declared(_RSA_flags)}
      RSA_flags := _RSA_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_flags');
    {$ifend}
  end;
  
  RSA_set_default_method := LoadLibFunction(ADllHandle, RSA_set_default_method_procname);
  FuncLoadError := not assigned(RSA_set_default_method);
  if FuncLoadError then
  begin
    {$if not defined(RSA_set_default_method_allownil)}
    RSA_set_default_method := ERR_RSA_set_default_method;
    {$ifend}
    {$if declared(RSA_set_default_method_introduced)}
    if LibVersion < RSA_set_default_method_introduced then
    begin
      {$if declared(FC_RSA_set_default_method)}
      RSA_set_default_method := FC_RSA_set_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_set_default_method_removed)}
    if RSA_set_default_method_removed <= LibVersion then
    begin
      {$if declared(_RSA_set_default_method)}
      RSA_set_default_method := _RSA_set_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_set_default_method_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_set_default_method');
    {$ifend}
  end;
  
  RSA_get_default_method := LoadLibFunction(ADllHandle, RSA_get_default_method_procname);
  FuncLoadError := not assigned(RSA_get_default_method);
  if FuncLoadError then
  begin
    {$if not defined(RSA_get_default_method_allownil)}
    RSA_get_default_method := ERR_RSA_get_default_method;
    {$ifend}
    {$if declared(RSA_get_default_method_introduced)}
    if LibVersion < RSA_get_default_method_introduced then
    begin
      {$if declared(FC_RSA_get_default_method)}
      RSA_get_default_method := FC_RSA_get_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_get_default_method_removed)}
    if RSA_get_default_method_removed <= LibVersion then
    begin
      {$if declared(_RSA_get_default_method)}
      RSA_get_default_method := _RSA_get_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_get_default_method_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_get_default_method');
    {$ifend}
  end;
  
  RSA_null_method := LoadLibFunction(ADllHandle, RSA_null_method_procname);
  FuncLoadError := not assigned(RSA_null_method);
  if FuncLoadError then
  begin
    {$if not defined(RSA_null_method_allownil)}
    RSA_null_method := ERR_RSA_null_method;
    {$ifend}
    {$if declared(RSA_null_method_introduced)}
    if LibVersion < RSA_null_method_introduced then
    begin
      {$if declared(FC_RSA_null_method)}
      RSA_null_method := FC_RSA_null_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_null_method_removed)}
    if RSA_null_method_removed <= LibVersion then
    begin
      {$if declared(_RSA_null_method)}
      RSA_null_method := _RSA_null_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_null_method_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_null_method');
    {$ifend}
  end;
  
  RSA_get_method := LoadLibFunction(ADllHandle, RSA_get_method_procname);
  FuncLoadError := not assigned(RSA_get_method);
  if FuncLoadError then
  begin
    {$if not defined(RSA_get_method_allownil)}
    RSA_get_method := ERR_RSA_get_method;
    {$ifend}
    {$if declared(RSA_get_method_introduced)}
    if LibVersion < RSA_get_method_introduced then
    begin
      {$if declared(FC_RSA_get_method)}
      RSA_get_method := FC_RSA_get_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_get_method_removed)}
    if RSA_get_method_removed <= LibVersion then
    begin
      {$if declared(_RSA_get_method)}
      RSA_get_method := _RSA_get_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_get_method_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_get_method');
    {$ifend}
  end;
  
  RSA_set_method := LoadLibFunction(ADllHandle, RSA_set_method_procname);
  FuncLoadError := not assigned(RSA_set_method);
  if FuncLoadError then
  begin
    {$if not defined(RSA_set_method_allownil)}
    RSA_set_method := ERR_RSA_set_method;
    {$ifend}
    {$if declared(RSA_set_method_introduced)}
    if LibVersion < RSA_set_method_introduced then
    begin
      {$if declared(FC_RSA_set_method)}
      RSA_set_method := FC_RSA_set_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_set_method_removed)}
    if RSA_set_method_removed <= LibVersion then
    begin
      {$if declared(_RSA_set_method)}
      RSA_set_method := _RSA_set_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_set_method_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_set_method');
    {$ifend}
  end;
  
  RSA_PKCS1_OpenSSL := LoadLibFunction(ADllHandle, RSA_PKCS1_OpenSSL_procname);
  FuncLoadError := not assigned(RSA_PKCS1_OpenSSL);
  if FuncLoadError then
  begin
    {$if not defined(RSA_PKCS1_OpenSSL_allownil)}
    RSA_PKCS1_OpenSSL := ERR_RSA_PKCS1_OpenSSL;
    {$ifend}
    {$if declared(RSA_PKCS1_OpenSSL_introduced)}
    if LibVersion < RSA_PKCS1_OpenSSL_introduced then
    begin
      {$if declared(FC_RSA_PKCS1_OpenSSL)}
      RSA_PKCS1_OpenSSL := FC_RSA_PKCS1_OpenSSL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_PKCS1_OpenSSL_removed)}
    if RSA_PKCS1_OpenSSL_removed <= LibVersion then
    begin
      {$if declared(_RSA_PKCS1_OpenSSL)}
      RSA_PKCS1_OpenSSL := _RSA_PKCS1_OpenSSL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_PKCS1_OpenSSL_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_PKCS1_OpenSSL');
    {$ifend}
  end;
  
  d2i_RSAPublicKey := LoadLibFunction(ADllHandle, d2i_RSAPublicKey_procname);
  FuncLoadError := not assigned(d2i_RSAPublicKey);
  if FuncLoadError then
  begin
    {$if not defined(d2i_RSAPublicKey_allownil)}
    d2i_RSAPublicKey := ERR_d2i_RSAPublicKey;
    {$ifend}
    {$if declared(d2i_RSAPublicKey_introduced)}
    if LibVersion < d2i_RSAPublicKey_introduced then
    begin
      {$if declared(FC_d2i_RSAPublicKey)}
      d2i_RSAPublicKey := FC_d2i_RSAPublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_RSAPublicKey_removed)}
    if d2i_RSAPublicKey_removed <= LibVersion then
    begin
      {$if declared(_d2i_RSAPublicKey)}
      d2i_RSAPublicKey := _d2i_RSAPublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_RSAPublicKey_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_RSAPublicKey');
    {$ifend}
  end;
  
  i2d_RSAPublicKey := LoadLibFunction(ADllHandle, i2d_RSAPublicKey_procname);
  FuncLoadError := not assigned(i2d_RSAPublicKey);
  if FuncLoadError then
  begin
    {$if not defined(i2d_RSAPublicKey_allownil)}
    i2d_RSAPublicKey := ERR_i2d_RSAPublicKey;
    {$ifend}
    {$if declared(i2d_RSAPublicKey_introduced)}
    if LibVersion < i2d_RSAPublicKey_introduced then
    begin
      {$if declared(FC_i2d_RSAPublicKey)}
      i2d_RSAPublicKey := FC_i2d_RSAPublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_RSAPublicKey_removed)}
    if i2d_RSAPublicKey_removed <= LibVersion then
    begin
      {$if declared(_i2d_RSAPublicKey)}
      i2d_RSAPublicKey := _i2d_RSAPublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_RSAPublicKey_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_RSAPublicKey');
    {$ifend}
  end;
  
  RSAPublicKey_it := LoadLibFunction(ADllHandle, RSAPublicKey_it_procname);
  FuncLoadError := not assigned(RSAPublicKey_it);
  if FuncLoadError then
  begin
    {$if not defined(RSAPublicKey_it_allownil)}
    RSAPublicKey_it := ERR_RSAPublicKey_it;
    {$ifend}
    {$if declared(RSAPublicKey_it_introduced)}
    if LibVersion < RSAPublicKey_it_introduced then
    begin
      {$if declared(FC_RSAPublicKey_it)}
      RSAPublicKey_it := FC_RSAPublicKey_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSAPublicKey_it_removed)}
    if RSAPublicKey_it_removed <= LibVersion then
    begin
      {$if declared(_RSAPublicKey_it)}
      RSAPublicKey_it := _RSAPublicKey_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSAPublicKey_it_allownil)}
    if FuncLoadError then
      AFailed.Add('RSAPublicKey_it');
    {$ifend}
  end;
  
  d2i_RSAPrivateKey := LoadLibFunction(ADllHandle, d2i_RSAPrivateKey_procname);
  FuncLoadError := not assigned(d2i_RSAPrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(d2i_RSAPrivateKey_allownil)}
    d2i_RSAPrivateKey := ERR_d2i_RSAPrivateKey;
    {$ifend}
    {$if declared(d2i_RSAPrivateKey_introduced)}
    if LibVersion < d2i_RSAPrivateKey_introduced then
    begin
      {$if declared(FC_d2i_RSAPrivateKey)}
      d2i_RSAPrivateKey := FC_d2i_RSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_RSAPrivateKey_removed)}
    if d2i_RSAPrivateKey_removed <= LibVersion then
    begin
      {$if declared(_d2i_RSAPrivateKey)}
      d2i_RSAPrivateKey := _d2i_RSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_RSAPrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_RSAPrivateKey');
    {$ifend}
  end;
  
  i2d_RSAPrivateKey := LoadLibFunction(ADllHandle, i2d_RSAPrivateKey_procname);
  FuncLoadError := not assigned(i2d_RSAPrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(i2d_RSAPrivateKey_allownil)}
    i2d_RSAPrivateKey := ERR_i2d_RSAPrivateKey;
    {$ifend}
    {$if declared(i2d_RSAPrivateKey_introduced)}
    if LibVersion < i2d_RSAPrivateKey_introduced then
    begin
      {$if declared(FC_i2d_RSAPrivateKey)}
      i2d_RSAPrivateKey := FC_i2d_RSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_RSAPrivateKey_removed)}
    if i2d_RSAPrivateKey_removed <= LibVersion then
    begin
      {$if declared(_i2d_RSAPrivateKey)}
      i2d_RSAPrivateKey := _i2d_RSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_RSAPrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_RSAPrivateKey');
    {$ifend}
  end;
  
  RSAPrivateKey_it := LoadLibFunction(ADllHandle, RSAPrivateKey_it_procname);
  FuncLoadError := not assigned(RSAPrivateKey_it);
  if FuncLoadError then
  begin
    {$if not defined(RSAPrivateKey_it_allownil)}
    RSAPrivateKey_it := ERR_RSAPrivateKey_it;
    {$ifend}
    {$if declared(RSAPrivateKey_it_introduced)}
    if LibVersion < RSAPrivateKey_it_introduced then
    begin
      {$if declared(FC_RSAPrivateKey_it)}
      RSAPrivateKey_it := FC_RSAPrivateKey_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSAPrivateKey_it_removed)}
    if RSAPrivateKey_it_removed <= LibVersion then
    begin
      {$if declared(_RSAPrivateKey_it)}
      RSAPrivateKey_it := _RSAPrivateKey_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSAPrivateKey_it_allownil)}
    if FuncLoadError then
      AFailed.Add('RSAPrivateKey_it');
    {$ifend}
  end;
  
  RSA_pkey_ctx_ctrl := LoadLibFunction(ADllHandle, RSA_pkey_ctx_ctrl_procname);
  FuncLoadError := not assigned(RSA_pkey_ctx_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(RSA_pkey_ctx_ctrl_allownil)}
    RSA_pkey_ctx_ctrl := ERR_RSA_pkey_ctx_ctrl;
    {$ifend}
    {$if declared(RSA_pkey_ctx_ctrl_introduced)}
    if LibVersion < RSA_pkey_ctx_ctrl_introduced then
    begin
      {$if declared(FC_RSA_pkey_ctx_ctrl)}
      RSA_pkey_ctx_ctrl := FC_RSA_pkey_ctx_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_pkey_ctx_ctrl_removed)}
    if RSA_pkey_ctx_ctrl_removed <= LibVersion then
    begin
      {$if declared(_RSA_pkey_ctx_ctrl)}
      RSA_pkey_ctx_ctrl := _RSA_pkey_ctx_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_pkey_ctx_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_pkey_ctx_ctrl');
    {$ifend}
  end;
  
  RSA_PSS_PARAMS_new := LoadLibFunction(ADllHandle, RSA_PSS_PARAMS_new_procname);
  FuncLoadError := not assigned(RSA_PSS_PARAMS_new);
  if FuncLoadError then
  begin
    {$if not defined(RSA_PSS_PARAMS_new_allownil)}
    RSA_PSS_PARAMS_new := ERR_RSA_PSS_PARAMS_new;
    {$ifend}
    {$if declared(RSA_PSS_PARAMS_new_introduced)}
    if LibVersion < RSA_PSS_PARAMS_new_introduced then
    begin
      {$if declared(FC_RSA_PSS_PARAMS_new)}
      RSA_PSS_PARAMS_new := FC_RSA_PSS_PARAMS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_PSS_PARAMS_new_removed)}
    if RSA_PSS_PARAMS_new_removed <= LibVersion then
    begin
      {$if declared(_RSA_PSS_PARAMS_new)}
      RSA_PSS_PARAMS_new := _RSA_PSS_PARAMS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_PSS_PARAMS_new_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_PSS_PARAMS_new');
    {$ifend}
  end;
  
  RSA_PSS_PARAMS_free := LoadLibFunction(ADllHandle, RSA_PSS_PARAMS_free_procname);
  FuncLoadError := not assigned(RSA_PSS_PARAMS_free);
  if FuncLoadError then
  begin
    {$if not defined(RSA_PSS_PARAMS_free_allownil)}
    RSA_PSS_PARAMS_free := ERR_RSA_PSS_PARAMS_free;
    {$ifend}
    {$if declared(RSA_PSS_PARAMS_free_introduced)}
    if LibVersion < RSA_PSS_PARAMS_free_introduced then
    begin
      {$if declared(FC_RSA_PSS_PARAMS_free)}
      RSA_PSS_PARAMS_free := FC_RSA_PSS_PARAMS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_PSS_PARAMS_free_removed)}
    if RSA_PSS_PARAMS_free_removed <= LibVersion then
    begin
      {$if declared(_RSA_PSS_PARAMS_free)}
      RSA_PSS_PARAMS_free := _RSA_PSS_PARAMS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_PSS_PARAMS_free_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_PSS_PARAMS_free');
    {$ifend}
  end;
  
  d2i_RSA_PSS_PARAMS := LoadLibFunction(ADllHandle, d2i_RSA_PSS_PARAMS_procname);
  FuncLoadError := not assigned(d2i_RSA_PSS_PARAMS);
  if FuncLoadError then
  begin
    {$if not defined(d2i_RSA_PSS_PARAMS_allownil)}
    d2i_RSA_PSS_PARAMS := ERR_d2i_RSA_PSS_PARAMS;
    {$ifend}
    {$if declared(d2i_RSA_PSS_PARAMS_introduced)}
    if LibVersion < d2i_RSA_PSS_PARAMS_introduced then
    begin
      {$if declared(FC_d2i_RSA_PSS_PARAMS)}
      d2i_RSA_PSS_PARAMS := FC_d2i_RSA_PSS_PARAMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_RSA_PSS_PARAMS_removed)}
    if d2i_RSA_PSS_PARAMS_removed <= LibVersion then
    begin
      {$if declared(_d2i_RSA_PSS_PARAMS)}
      d2i_RSA_PSS_PARAMS := _d2i_RSA_PSS_PARAMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_RSA_PSS_PARAMS_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_RSA_PSS_PARAMS');
    {$ifend}
  end;
  
  i2d_RSA_PSS_PARAMS := LoadLibFunction(ADllHandle, i2d_RSA_PSS_PARAMS_procname);
  FuncLoadError := not assigned(i2d_RSA_PSS_PARAMS);
  if FuncLoadError then
  begin
    {$if not defined(i2d_RSA_PSS_PARAMS_allownil)}
    i2d_RSA_PSS_PARAMS := ERR_i2d_RSA_PSS_PARAMS;
    {$ifend}
    {$if declared(i2d_RSA_PSS_PARAMS_introduced)}
    if LibVersion < i2d_RSA_PSS_PARAMS_introduced then
    begin
      {$if declared(FC_i2d_RSA_PSS_PARAMS)}
      i2d_RSA_PSS_PARAMS := FC_i2d_RSA_PSS_PARAMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_RSA_PSS_PARAMS_removed)}
    if i2d_RSA_PSS_PARAMS_removed <= LibVersion then
    begin
      {$if declared(_i2d_RSA_PSS_PARAMS)}
      i2d_RSA_PSS_PARAMS := _i2d_RSA_PSS_PARAMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_RSA_PSS_PARAMS_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_RSA_PSS_PARAMS');
    {$ifend}
  end;
  
  RSA_PSS_PARAMS_it := LoadLibFunction(ADllHandle, RSA_PSS_PARAMS_it_procname);
  FuncLoadError := not assigned(RSA_PSS_PARAMS_it);
  if FuncLoadError then
  begin
    {$if not defined(RSA_PSS_PARAMS_it_allownil)}
    RSA_PSS_PARAMS_it := ERR_RSA_PSS_PARAMS_it;
    {$ifend}
    {$if declared(RSA_PSS_PARAMS_it_introduced)}
    if LibVersion < RSA_PSS_PARAMS_it_introduced then
    begin
      {$if declared(FC_RSA_PSS_PARAMS_it)}
      RSA_PSS_PARAMS_it := FC_RSA_PSS_PARAMS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_PSS_PARAMS_it_removed)}
    if RSA_PSS_PARAMS_it_removed <= LibVersion then
    begin
      {$if declared(_RSA_PSS_PARAMS_it)}
      RSA_PSS_PARAMS_it := _RSA_PSS_PARAMS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_PSS_PARAMS_it_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_PSS_PARAMS_it');
    {$ifend}
  end;
  
  RSA_PSS_PARAMS_dup := LoadLibFunction(ADllHandle, RSA_PSS_PARAMS_dup_procname);
  FuncLoadError := not assigned(RSA_PSS_PARAMS_dup);
  if FuncLoadError then
  begin
    {$if not defined(RSA_PSS_PARAMS_dup_allownil)}
    RSA_PSS_PARAMS_dup := ERR_RSA_PSS_PARAMS_dup;
    {$ifend}
    {$if declared(RSA_PSS_PARAMS_dup_introduced)}
    if LibVersion < RSA_PSS_PARAMS_dup_introduced then
    begin
      {$if declared(FC_RSA_PSS_PARAMS_dup)}
      RSA_PSS_PARAMS_dup := FC_RSA_PSS_PARAMS_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_PSS_PARAMS_dup_removed)}
    if RSA_PSS_PARAMS_dup_removed <= LibVersion then
    begin
      {$if declared(_RSA_PSS_PARAMS_dup)}
      RSA_PSS_PARAMS_dup := _RSA_PSS_PARAMS_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_PSS_PARAMS_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_PSS_PARAMS_dup');
    {$ifend}
  end;
  
  RSA_OAEP_PARAMS_new := LoadLibFunction(ADllHandle, RSA_OAEP_PARAMS_new_procname);
  FuncLoadError := not assigned(RSA_OAEP_PARAMS_new);
  if FuncLoadError then
  begin
    {$if not defined(RSA_OAEP_PARAMS_new_allownil)}
    RSA_OAEP_PARAMS_new := ERR_RSA_OAEP_PARAMS_new;
    {$ifend}
    {$if declared(RSA_OAEP_PARAMS_new_introduced)}
    if LibVersion < RSA_OAEP_PARAMS_new_introduced then
    begin
      {$if declared(FC_RSA_OAEP_PARAMS_new)}
      RSA_OAEP_PARAMS_new := FC_RSA_OAEP_PARAMS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_OAEP_PARAMS_new_removed)}
    if RSA_OAEP_PARAMS_new_removed <= LibVersion then
    begin
      {$if declared(_RSA_OAEP_PARAMS_new)}
      RSA_OAEP_PARAMS_new := _RSA_OAEP_PARAMS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_OAEP_PARAMS_new_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_OAEP_PARAMS_new');
    {$ifend}
  end;
  
  RSA_OAEP_PARAMS_free := LoadLibFunction(ADllHandle, RSA_OAEP_PARAMS_free_procname);
  FuncLoadError := not assigned(RSA_OAEP_PARAMS_free);
  if FuncLoadError then
  begin
    {$if not defined(RSA_OAEP_PARAMS_free_allownil)}
    RSA_OAEP_PARAMS_free := ERR_RSA_OAEP_PARAMS_free;
    {$ifend}
    {$if declared(RSA_OAEP_PARAMS_free_introduced)}
    if LibVersion < RSA_OAEP_PARAMS_free_introduced then
    begin
      {$if declared(FC_RSA_OAEP_PARAMS_free)}
      RSA_OAEP_PARAMS_free := FC_RSA_OAEP_PARAMS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_OAEP_PARAMS_free_removed)}
    if RSA_OAEP_PARAMS_free_removed <= LibVersion then
    begin
      {$if declared(_RSA_OAEP_PARAMS_free)}
      RSA_OAEP_PARAMS_free := _RSA_OAEP_PARAMS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_OAEP_PARAMS_free_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_OAEP_PARAMS_free');
    {$ifend}
  end;
  
  d2i_RSA_OAEP_PARAMS := LoadLibFunction(ADllHandle, d2i_RSA_OAEP_PARAMS_procname);
  FuncLoadError := not assigned(d2i_RSA_OAEP_PARAMS);
  if FuncLoadError then
  begin
    {$if not defined(d2i_RSA_OAEP_PARAMS_allownil)}
    d2i_RSA_OAEP_PARAMS := ERR_d2i_RSA_OAEP_PARAMS;
    {$ifend}
    {$if declared(d2i_RSA_OAEP_PARAMS_introduced)}
    if LibVersion < d2i_RSA_OAEP_PARAMS_introduced then
    begin
      {$if declared(FC_d2i_RSA_OAEP_PARAMS)}
      d2i_RSA_OAEP_PARAMS := FC_d2i_RSA_OAEP_PARAMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_RSA_OAEP_PARAMS_removed)}
    if d2i_RSA_OAEP_PARAMS_removed <= LibVersion then
    begin
      {$if declared(_d2i_RSA_OAEP_PARAMS)}
      d2i_RSA_OAEP_PARAMS := _d2i_RSA_OAEP_PARAMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_RSA_OAEP_PARAMS_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_RSA_OAEP_PARAMS');
    {$ifend}
  end;
  
  i2d_RSA_OAEP_PARAMS := LoadLibFunction(ADllHandle, i2d_RSA_OAEP_PARAMS_procname);
  FuncLoadError := not assigned(i2d_RSA_OAEP_PARAMS);
  if FuncLoadError then
  begin
    {$if not defined(i2d_RSA_OAEP_PARAMS_allownil)}
    i2d_RSA_OAEP_PARAMS := ERR_i2d_RSA_OAEP_PARAMS;
    {$ifend}
    {$if declared(i2d_RSA_OAEP_PARAMS_introduced)}
    if LibVersion < i2d_RSA_OAEP_PARAMS_introduced then
    begin
      {$if declared(FC_i2d_RSA_OAEP_PARAMS)}
      i2d_RSA_OAEP_PARAMS := FC_i2d_RSA_OAEP_PARAMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_RSA_OAEP_PARAMS_removed)}
    if i2d_RSA_OAEP_PARAMS_removed <= LibVersion then
    begin
      {$if declared(_i2d_RSA_OAEP_PARAMS)}
      i2d_RSA_OAEP_PARAMS := _i2d_RSA_OAEP_PARAMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_RSA_OAEP_PARAMS_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_RSA_OAEP_PARAMS');
    {$ifend}
  end;
  
  RSA_OAEP_PARAMS_it := LoadLibFunction(ADllHandle, RSA_OAEP_PARAMS_it_procname);
  FuncLoadError := not assigned(RSA_OAEP_PARAMS_it);
  if FuncLoadError then
  begin
    {$if not defined(RSA_OAEP_PARAMS_it_allownil)}
    RSA_OAEP_PARAMS_it := ERR_RSA_OAEP_PARAMS_it;
    {$ifend}
    {$if declared(RSA_OAEP_PARAMS_it_introduced)}
    if LibVersion < RSA_OAEP_PARAMS_it_introduced then
    begin
      {$if declared(FC_RSA_OAEP_PARAMS_it)}
      RSA_OAEP_PARAMS_it := FC_RSA_OAEP_PARAMS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_OAEP_PARAMS_it_removed)}
    if RSA_OAEP_PARAMS_it_removed <= LibVersion then
    begin
      {$if declared(_RSA_OAEP_PARAMS_it)}
      RSA_OAEP_PARAMS_it := _RSA_OAEP_PARAMS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_OAEP_PARAMS_it_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_OAEP_PARAMS_it');
    {$ifend}
  end;
  
  RSA_print_fp := LoadLibFunction(ADllHandle, RSA_print_fp_procname);
  FuncLoadError := not assigned(RSA_print_fp);
  if FuncLoadError then
  begin
    {$if not defined(RSA_print_fp_allownil)}
    RSA_print_fp := ERR_RSA_print_fp;
    {$ifend}
    {$if declared(RSA_print_fp_introduced)}
    if LibVersion < RSA_print_fp_introduced then
    begin
      {$if declared(FC_RSA_print_fp)}
      RSA_print_fp := FC_RSA_print_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_print_fp_removed)}
    if RSA_print_fp_removed <= LibVersion then
    begin
      {$if declared(_RSA_print_fp)}
      RSA_print_fp := _RSA_print_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_print_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_print_fp');
    {$ifend}
  end;
  
  RSA_print := LoadLibFunction(ADllHandle, RSA_print_procname);
  FuncLoadError := not assigned(RSA_print);
  if FuncLoadError then
  begin
    {$if not defined(RSA_print_allownil)}
    RSA_print := ERR_RSA_print;
    {$ifend}
    {$if declared(RSA_print_introduced)}
    if LibVersion < RSA_print_introduced then
    begin
      {$if declared(FC_RSA_print)}
      RSA_print := FC_RSA_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_print_removed)}
    if RSA_print_removed <= LibVersion then
    begin
      {$if declared(_RSA_print)}
      RSA_print := _RSA_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_print_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_print');
    {$ifend}
  end;
  
  RSA_sign := LoadLibFunction(ADllHandle, RSA_sign_procname);
  FuncLoadError := not assigned(RSA_sign);
  if FuncLoadError then
  begin
    {$if not defined(RSA_sign_allownil)}
    RSA_sign := ERR_RSA_sign;
    {$ifend}
    {$if declared(RSA_sign_introduced)}
    if LibVersion < RSA_sign_introduced then
    begin
      {$if declared(FC_RSA_sign)}
      RSA_sign := FC_RSA_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_sign_removed)}
    if RSA_sign_removed <= LibVersion then
    begin
      {$if declared(_RSA_sign)}
      RSA_sign := _RSA_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_sign');
    {$ifend}
  end;
  
  RSA_verify := LoadLibFunction(ADllHandle, RSA_verify_procname);
  FuncLoadError := not assigned(RSA_verify);
  if FuncLoadError then
  begin
    {$if not defined(RSA_verify_allownil)}
    RSA_verify := ERR_RSA_verify;
    {$ifend}
    {$if declared(RSA_verify_introduced)}
    if LibVersion < RSA_verify_introduced then
    begin
      {$if declared(FC_RSA_verify)}
      RSA_verify := FC_RSA_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_verify_removed)}
    if RSA_verify_removed <= LibVersion then
    begin
      {$if declared(_RSA_verify)}
      RSA_verify := _RSA_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_verify');
    {$ifend}
  end;
  
  RSA_sign_ASN1_OCTET_STRING := LoadLibFunction(ADllHandle, RSA_sign_ASN1_OCTET_STRING_procname);
  FuncLoadError := not assigned(RSA_sign_ASN1_OCTET_STRING);
  if FuncLoadError then
  begin
    {$if not defined(RSA_sign_ASN1_OCTET_STRING_allownil)}
    RSA_sign_ASN1_OCTET_STRING := ERR_RSA_sign_ASN1_OCTET_STRING;
    {$ifend}
    {$if declared(RSA_sign_ASN1_OCTET_STRING_introduced)}
    if LibVersion < RSA_sign_ASN1_OCTET_STRING_introduced then
    begin
      {$if declared(FC_RSA_sign_ASN1_OCTET_STRING)}
      RSA_sign_ASN1_OCTET_STRING := FC_RSA_sign_ASN1_OCTET_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_sign_ASN1_OCTET_STRING_removed)}
    if RSA_sign_ASN1_OCTET_STRING_removed <= LibVersion then
    begin
      {$if declared(_RSA_sign_ASN1_OCTET_STRING)}
      RSA_sign_ASN1_OCTET_STRING := _RSA_sign_ASN1_OCTET_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_sign_ASN1_OCTET_STRING_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_sign_ASN1_OCTET_STRING');
    {$ifend}
  end;
  
  RSA_verify_ASN1_OCTET_STRING := LoadLibFunction(ADllHandle, RSA_verify_ASN1_OCTET_STRING_procname);
  FuncLoadError := not assigned(RSA_verify_ASN1_OCTET_STRING);
  if FuncLoadError then
  begin
    {$if not defined(RSA_verify_ASN1_OCTET_STRING_allownil)}
    RSA_verify_ASN1_OCTET_STRING := ERR_RSA_verify_ASN1_OCTET_STRING;
    {$ifend}
    {$if declared(RSA_verify_ASN1_OCTET_STRING_introduced)}
    if LibVersion < RSA_verify_ASN1_OCTET_STRING_introduced then
    begin
      {$if declared(FC_RSA_verify_ASN1_OCTET_STRING)}
      RSA_verify_ASN1_OCTET_STRING := FC_RSA_verify_ASN1_OCTET_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_verify_ASN1_OCTET_STRING_removed)}
    if RSA_verify_ASN1_OCTET_STRING_removed <= LibVersion then
    begin
      {$if declared(_RSA_verify_ASN1_OCTET_STRING)}
      RSA_verify_ASN1_OCTET_STRING := _RSA_verify_ASN1_OCTET_STRING;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_verify_ASN1_OCTET_STRING_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_verify_ASN1_OCTET_STRING');
    {$ifend}
  end;
  
  RSA_blinding_on := LoadLibFunction(ADllHandle, RSA_blinding_on_procname);
  FuncLoadError := not assigned(RSA_blinding_on);
  if FuncLoadError then
  begin
    {$if not defined(RSA_blinding_on_allownil)}
    RSA_blinding_on := ERR_RSA_blinding_on;
    {$ifend}
    {$if declared(RSA_blinding_on_introduced)}
    if LibVersion < RSA_blinding_on_introduced then
    begin
      {$if declared(FC_RSA_blinding_on)}
      RSA_blinding_on := FC_RSA_blinding_on;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_blinding_on_removed)}
    if RSA_blinding_on_removed <= LibVersion then
    begin
      {$if declared(_RSA_blinding_on)}
      RSA_blinding_on := _RSA_blinding_on;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_blinding_on_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_blinding_on');
    {$ifend}
  end;
  
  RSA_blinding_off := LoadLibFunction(ADllHandle, RSA_blinding_off_procname);
  FuncLoadError := not assigned(RSA_blinding_off);
  if FuncLoadError then
  begin
    {$if not defined(RSA_blinding_off_allownil)}
    RSA_blinding_off := ERR_RSA_blinding_off;
    {$ifend}
    {$if declared(RSA_blinding_off_introduced)}
    if LibVersion < RSA_blinding_off_introduced then
    begin
      {$if declared(FC_RSA_blinding_off)}
      RSA_blinding_off := FC_RSA_blinding_off;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_blinding_off_removed)}
    if RSA_blinding_off_removed <= LibVersion then
    begin
      {$if declared(_RSA_blinding_off)}
      RSA_blinding_off := _RSA_blinding_off;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_blinding_off_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_blinding_off');
    {$ifend}
  end;
  
  RSA_setup_blinding := LoadLibFunction(ADllHandle, RSA_setup_blinding_procname);
  FuncLoadError := not assigned(RSA_setup_blinding);
  if FuncLoadError then
  begin
    {$if not defined(RSA_setup_blinding_allownil)}
    RSA_setup_blinding := ERR_RSA_setup_blinding;
    {$ifend}
    {$if declared(RSA_setup_blinding_introduced)}
    if LibVersion < RSA_setup_blinding_introduced then
    begin
      {$if declared(FC_RSA_setup_blinding)}
      RSA_setup_blinding := FC_RSA_setup_blinding;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_setup_blinding_removed)}
    if RSA_setup_blinding_removed <= LibVersion then
    begin
      {$if declared(_RSA_setup_blinding)}
      RSA_setup_blinding := _RSA_setup_blinding;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_setup_blinding_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_setup_blinding');
    {$ifend}
  end;
  
  RSA_padding_add_PKCS1_type_1 := LoadLibFunction(ADllHandle, RSA_padding_add_PKCS1_type_1_procname);
  FuncLoadError := not assigned(RSA_padding_add_PKCS1_type_1);
  if FuncLoadError then
  begin
    {$if not defined(RSA_padding_add_PKCS1_type_1_allownil)}
    RSA_padding_add_PKCS1_type_1 := ERR_RSA_padding_add_PKCS1_type_1;
    {$ifend}
    {$if declared(RSA_padding_add_PKCS1_type_1_introduced)}
    if LibVersion < RSA_padding_add_PKCS1_type_1_introduced then
    begin
      {$if declared(FC_RSA_padding_add_PKCS1_type_1)}
      RSA_padding_add_PKCS1_type_1 := FC_RSA_padding_add_PKCS1_type_1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_padding_add_PKCS1_type_1_removed)}
    if RSA_padding_add_PKCS1_type_1_removed <= LibVersion then
    begin
      {$if declared(_RSA_padding_add_PKCS1_type_1)}
      RSA_padding_add_PKCS1_type_1 := _RSA_padding_add_PKCS1_type_1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_padding_add_PKCS1_type_1_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_padding_add_PKCS1_type_1');
    {$ifend}
  end;
  
  RSA_padding_check_PKCS1_type_1 := LoadLibFunction(ADllHandle, RSA_padding_check_PKCS1_type_1_procname);
  FuncLoadError := not assigned(RSA_padding_check_PKCS1_type_1);
  if FuncLoadError then
  begin
    {$if not defined(RSA_padding_check_PKCS1_type_1_allownil)}
    RSA_padding_check_PKCS1_type_1 := ERR_RSA_padding_check_PKCS1_type_1;
    {$ifend}
    {$if declared(RSA_padding_check_PKCS1_type_1_introduced)}
    if LibVersion < RSA_padding_check_PKCS1_type_1_introduced then
    begin
      {$if declared(FC_RSA_padding_check_PKCS1_type_1)}
      RSA_padding_check_PKCS1_type_1 := FC_RSA_padding_check_PKCS1_type_1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_padding_check_PKCS1_type_1_removed)}
    if RSA_padding_check_PKCS1_type_1_removed <= LibVersion then
    begin
      {$if declared(_RSA_padding_check_PKCS1_type_1)}
      RSA_padding_check_PKCS1_type_1 := _RSA_padding_check_PKCS1_type_1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_padding_check_PKCS1_type_1_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_padding_check_PKCS1_type_1');
    {$ifend}
  end;
  
  RSA_padding_add_PKCS1_type_2 := LoadLibFunction(ADllHandle, RSA_padding_add_PKCS1_type_2_procname);
  FuncLoadError := not assigned(RSA_padding_add_PKCS1_type_2);
  if FuncLoadError then
  begin
    {$if not defined(RSA_padding_add_PKCS1_type_2_allownil)}
    RSA_padding_add_PKCS1_type_2 := ERR_RSA_padding_add_PKCS1_type_2;
    {$ifend}
    {$if declared(RSA_padding_add_PKCS1_type_2_introduced)}
    if LibVersion < RSA_padding_add_PKCS1_type_2_introduced then
    begin
      {$if declared(FC_RSA_padding_add_PKCS1_type_2)}
      RSA_padding_add_PKCS1_type_2 := FC_RSA_padding_add_PKCS1_type_2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_padding_add_PKCS1_type_2_removed)}
    if RSA_padding_add_PKCS1_type_2_removed <= LibVersion then
    begin
      {$if declared(_RSA_padding_add_PKCS1_type_2)}
      RSA_padding_add_PKCS1_type_2 := _RSA_padding_add_PKCS1_type_2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_padding_add_PKCS1_type_2_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_padding_add_PKCS1_type_2');
    {$ifend}
  end;
  
  RSA_padding_check_PKCS1_type_2 := LoadLibFunction(ADllHandle, RSA_padding_check_PKCS1_type_2_procname);
  FuncLoadError := not assigned(RSA_padding_check_PKCS1_type_2);
  if FuncLoadError then
  begin
    {$if not defined(RSA_padding_check_PKCS1_type_2_allownil)}
    RSA_padding_check_PKCS1_type_2 := ERR_RSA_padding_check_PKCS1_type_2;
    {$ifend}
    {$if declared(RSA_padding_check_PKCS1_type_2_introduced)}
    if LibVersion < RSA_padding_check_PKCS1_type_2_introduced then
    begin
      {$if declared(FC_RSA_padding_check_PKCS1_type_2)}
      RSA_padding_check_PKCS1_type_2 := FC_RSA_padding_check_PKCS1_type_2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_padding_check_PKCS1_type_2_removed)}
    if RSA_padding_check_PKCS1_type_2_removed <= LibVersion then
    begin
      {$if declared(_RSA_padding_check_PKCS1_type_2)}
      RSA_padding_check_PKCS1_type_2 := _RSA_padding_check_PKCS1_type_2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_padding_check_PKCS1_type_2_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_padding_check_PKCS1_type_2');
    {$ifend}
  end;
  
  PKCS1_MGF1 := LoadLibFunction(ADllHandle, PKCS1_MGF1_procname);
  FuncLoadError := not assigned(PKCS1_MGF1);
  if FuncLoadError then
  begin
    {$if not defined(PKCS1_MGF1_allownil)}
    PKCS1_MGF1 := ERR_PKCS1_MGF1;
    {$ifend}
    {$if declared(PKCS1_MGF1_introduced)}
    if LibVersion < PKCS1_MGF1_introduced then
    begin
      {$if declared(FC_PKCS1_MGF1)}
      PKCS1_MGF1 := FC_PKCS1_MGF1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS1_MGF1_removed)}
    if PKCS1_MGF1_removed <= LibVersion then
    begin
      {$if declared(_PKCS1_MGF1)}
      PKCS1_MGF1 := _PKCS1_MGF1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS1_MGF1_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS1_MGF1');
    {$ifend}
  end;
  
  RSA_padding_add_PKCS1_OAEP := LoadLibFunction(ADllHandle, RSA_padding_add_PKCS1_OAEP_procname);
  FuncLoadError := not assigned(RSA_padding_add_PKCS1_OAEP);
  if FuncLoadError then
  begin
    {$if not defined(RSA_padding_add_PKCS1_OAEP_allownil)}
    RSA_padding_add_PKCS1_OAEP := ERR_RSA_padding_add_PKCS1_OAEP;
    {$ifend}
    {$if declared(RSA_padding_add_PKCS1_OAEP_introduced)}
    if LibVersion < RSA_padding_add_PKCS1_OAEP_introduced then
    begin
      {$if declared(FC_RSA_padding_add_PKCS1_OAEP)}
      RSA_padding_add_PKCS1_OAEP := FC_RSA_padding_add_PKCS1_OAEP;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_padding_add_PKCS1_OAEP_removed)}
    if RSA_padding_add_PKCS1_OAEP_removed <= LibVersion then
    begin
      {$if declared(_RSA_padding_add_PKCS1_OAEP)}
      RSA_padding_add_PKCS1_OAEP := _RSA_padding_add_PKCS1_OAEP;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_padding_add_PKCS1_OAEP_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_padding_add_PKCS1_OAEP');
    {$ifend}
  end;
  
  RSA_padding_check_PKCS1_OAEP := LoadLibFunction(ADllHandle, RSA_padding_check_PKCS1_OAEP_procname);
  FuncLoadError := not assigned(RSA_padding_check_PKCS1_OAEP);
  if FuncLoadError then
  begin
    {$if not defined(RSA_padding_check_PKCS1_OAEP_allownil)}
    RSA_padding_check_PKCS1_OAEP := ERR_RSA_padding_check_PKCS1_OAEP;
    {$ifend}
    {$if declared(RSA_padding_check_PKCS1_OAEP_introduced)}
    if LibVersion < RSA_padding_check_PKCS1_OAEP_introduced then
    begin
      {$if declared(FC_RSA_padding_check_PKCS1_OAEP)}
      RSA_padding_check_PKCS1_OAEP := FC_RSA_padding_check_PKCS1_OAEP;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_padding_check_PKCS1_OAEP_removed)}
    if RSA_padding_check_PKCS1_OAEP_removed <= LibVersion then
    begin
      {$if declared(_RSA_padding_check_PKCS1_OAEP)}
      RSA_padding_check_PKCS1_OAEP := _RSA_padding_check_PKCS1_OAEP;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_padding_check_PKCS1_OAEP_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_padding_check_PKCS1_OAEP');
    {$ifend}
  end;
  
  RSA_padding_add_PKCS1_OAEP_mgf1 := LoadLibFunction(ADllHandle, RSA_padding_add_PKCS1_OAEP_mgf1_procname);
  FuncLoadError := not assigned(RSA_padding_add_PKCS1_OAEP_mgf1);
  if FuncLoadError then
  begin
    {$if not defined(RSA_padding_add_PKCS1_OAEP_mgf1_allownil)}
    RSA_padding_add_PKCS1_OAEP_mgf1 := ERR_RSA_padding_add_PKCS1_OAEP_mgf1;
    {$ifend}
    {$if declared(RSA_padding_add_PKCS1_OAEP_mgf1_introduced)}
    if LibVersion < RSA_padding_add_PKCS1_OAEP_mgf1_introduced then
    begin
      {$if declared(FC_RSA_padding_add_PKCS1_OAEP_mgf1)}
      RSA_padding_add_PKCS1_OAEP_mgf1 := FC_RSA_padding_add_PKCS1_OAEP_mgf1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_padding_add_PKCS1_OAEP_mgf1_removed)}
    if RSA_padding_add_PKCS1_OAEP_mgf1_removed <= LibVersion then
    begin
      {$if declared(_RSA_padding_add_PKCS1_OAEP_mgf1)}
      RSA_padding_add_PKCS1_OAEP_mgf1 := _RSA_padding_add_PKCS1_OAEP_mgf1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_padding_add_PKCS1_OAEP_mgf1_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_padding_add_PKCS1_OAEP_mgf1');
    {$ifend}
  end;
  
  RSA_padding_check_PKCS1_OAEP_mgf1 := LoadLibFunction(ADllHandle, RSA_padding_check_PKCS1_OAEP_mgf1_procname);
  FuncLoadError := not assigned(RSA_padding_check_PKCS1_OAEP_mgf1);
  if FuncLoadError then
  begin
    {$if not defined(RSA_padding_check_PKCS1_OAEP_mgf1_allownil)}
    RSA_padding_check_PKCS1_OAEP_mgf1 := ERR_RSA_padding_check_PKCS1_OAEP_mgf1;
    {$ifend}
    {$if declared(RSA_padding_check_PKCS1_OAEP_mgf1_introduced)}
    if LibVersion < RSA_padding_check_PKCS1_OAEP_mgf1_introduced then
    begin
      {$if declared(FC_RSA_padding_check_PKCS1_OAEP_mgf1)}
      RSA_padding_check_PKCS1_OAEP_mgf1 := FC_RSA_padding_check_PKCS1_OAEP_mgf1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_padding_check_PKCS1_OAEP_mgf1_removed)}
    if RSA_padding_check_PKCS1_OAEP_mgf1_removed <= LibVersion then
    begin
      {$if declared(_RSA_padding_check_PKCS1_OAEP_mgf1)}
      RSA_padding_check_PKCS1_OAEP_mgf1 := _RSA_padding_check_PKCS1_OAEP_mgf1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_padding_check_PKCS1_OAEP_mgf1_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_padding_check_PKCS1_OAEP_mgf1');
    {$ifend}
  end;
  
  RSA_padding_add_none := LoadLibFunction(ADllHandle, RSA_padding_add_none_procname);
  FuncLoadError := not assigned(RSA_padding_add_none);
  if FuncLoadError then
  begin
    {$if not defined(RSA_padding_add_none_allownil)}
    RSA_padding_add_none := ERR_RSA_padding_add_none;
    {$ifend}
    {$if declared(RSA_padding_add_none_introduced)}
    if LibVersion < RSA_padding_add_none_introduced then
    begin
      {$if declared(FC_RSA_padding_add_none)}
      RSA_padding_add_none := FC_RSA_padding_add_none;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_padding_add_none_removed)}
    if RSA_padding_add_none_removed <= LibVersion then
    begin
      {$if declared(_RSA_padding_add_none)}
      RSA_padding_add_none := _RSA_padding_add_none;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_padding_add_none_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_padding_add_none');
    {$ifend}
  end;
  
  RSA_padding_check_none := LoadLibFunction(ADllHandle, RSA_padding_check_none_procname);
  FuncLoadError := not assigned(RSA_padding_check_none);
  if FuncLoadError then
  begin
    {$if not defined(RSA_padding_check_none_allownil)}
    RSA_padding_check_none := ERR_RSA_padding_check_none;
    {$ifend}
    {$if declared(RSA_padding_check_none_introduced)}
    if LibVersion < RSA_padding_check_none_introduced then
    begin
      {$if declared(FC_RSA_padding_check_none)}
      RSA_padding_check_none := FC_RSA_padding_check_none;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_padding_check_none_removed)}
    if RSA_padding_check_none_removed <= LibVersion then
    begin
      {$if declared(_RSA_padding_check_none)}
      RSA_padding_check_none := _RSA_padding_check_none;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_padding_check_none_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_padding_check_none');
    {$ifend}
  end;
  
  RSA_padding_add_X931 := LoadLibFunction(ADllHandle, RSA_padding_add_X931_procname);
  FuncLoadError := not assigned(RSA_padding_add_X931);
  if FuncLoadError then
  begin
    {$if not defined(RSA_padding_add_X931_allownil)}
    RSA_padding_add_X931 := ERR_RSA_padding_add_X931;
    {$ifend}
    {$if declared(RSA_padding_add_X931_introduced)}
    if LibVersion < RSA_padding_add_X931_introduced then
    begin
      {$if declared(FC_RSA_padding_add_X931)}
      RSA_padding_add_X931 := FC_RSA_padding_add_X931;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_padding_add_X931_removed)}
    if RSA_padding_add_X931_removed <= LibVersion then
    begin
      {$if declared(_RSA_padding_add_X931)}
      RSA_padding_add_X931 := _RSA_padding_add_X931;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_padding_add_X931_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_padding_add_X931');
    {$ifend}
  end;
  
  RSA_padding_check_X931 := LoadLibFunction(ADllHandle, RSA_padding_check_X931_procname);
  FuncLoadError := not assigned(RSA_padding_check_X931);
  if FuncLoadError then
  begin
    {$if not defined(RSA_padding_check_X931_allownil)}
    RSA_padding_check_X931 := ERR_RSA_padding_check_X931;
    {$ifend}
    {$if declared(RSA_padding_check_X931_introduced)}
    if LibVersion < RSA_padding_check_X931_introduced then
    begin
      {$if declared(FC_RSA_padding_check_X931)}
      RSA_padding_check_X931 := FC_RSA_padding_check_X931;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_padding_check_X931_removed)}
    if RSA_padding_check_X931_removed <= LibVersion then
    begin
      {$if declared(_RSA_padding_check_X931)}
      RSA_padding_check_X931 := _RSA_padding_check_X931;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_padding_check_X931_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_padding_check_X931');
    {$ifend}
  end;
  
  RSA_X931_hash_id := LoadLibFunction(ADllHandle, RSA_X931_hash_id_procname);
  FuncLoadError := not assigned(RSA_X931_hash_id);
  if FuncLoadError then
  begin
    {$if not defined(RSA_X931_hash_id_allownil)}
    RSA_X931_hash_id := ERR_RSA_X931_hash_id;
    {$ifend}
    {$if declared(RSA_X931_hash_id_introduced)}
    if LibVersion < RSA_X931_hash_id_introduced then
    begin
      {$if declared(FC_RSA_X931_hash_id)}
      RSA_X931_hash_id := FC_RSA_X931_hash_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_X931_hash_id_removed)}
    if RSA_X931_hash_id_removed <= LibVersion then
    begin
      {$if declared(_RSA_X931_hash_id)}
      RSA_X931_hash_id := _RSA_X931_hash_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_X931_hash_id_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_X931_hash_id');
    {$ifend}
  end;
  
  RSA_verify_PKCS1_PSS := LoadLibFunction(ADllHandle, RSA_verify_PKCS1_PSS_procname);
  FuncLoadError := not assigned(RSA_verify_PKCS1_PSS);
  if FuncLoadError then
  begin
    {$if not defined(RSA_verify_PKCS1_PSS_allownil)}
    RSA_verify_PKCS1_PSS := ERR_RSA_verify_PKCS1_PSS;
    {$ifend}
    {$if declared(RSA_verify_PKCS1_PSS_introduced)}
    if LibVersion < RSA_verify_PKCS1_PSS_introduced then
    begin
      {$if declared(FC_RSA_verify_PKCS1_PSS)}
      RSA_verify_PKCS1_PSS := FC_RSA_verify_PKCS1_PSS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_verify_PKCS1_PSS_removed)}
    if RSA_verify_PKCS1_PSS_removed <= LibVersion then
    begin
      {$if declared(_RSA_verify_PKCS1_PSS)}
      RSA_verify_PKCS1_PSS := _RSA_verify_PKCS1_PSS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_verify_PKCS1_PSS_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_verify_PKCS1_PSS');
    {$ifend}
  end;
  
  RSA_padding_add_PKCS1_PSS := LoadLibFunction(ADllHandle, RSA_padding_add_PKCS1_PSS_procname);
  FuncLoadError := not assigned(RSA_padding_add_PKCS1_PSS);
  if FuncLoadError then
  begin
    {$if not defined(RSA_padding_add_PKCS1_PSS_allownil)}
    RSA_padding_add_PKCS1_PSS := ERR_RSA_padding_add_PKCS1_PSS;
    {$ifend}
    {$if declared(RSA_padding_add_PKCS1_PSS_introduced)}
    if LibVersion < RSA_padding_add_PKCS1_PSS_introduced then
    begin
      {$if declared(FC_RSA_padding_add_PKCS1_PSS)}
      RSA_padding_add_PKCS1_PSS := FC_RSA_padding_add_PKCS1_PSS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_padding_add_PKCS1_PSS_removed)}
    if RSA_padding_add_PKCS1_PSS_removed <= LibVersion then
    begin
      {$if declared(_RSA_padding_add_PKCS1_PSS)}
      RSA_padding_add_PKCS1_PSS := _RSA_padding_add_PKCS1_PSS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_padding_add_PKCS1_PSS_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_padding_add_PKCS1_PSS');
    {$ifend}
  end;
  
  RSA_verify_PKCS1_PSS_mgf1 := LoadLibFunction(ADllHandle, RSA_verify_PKCS1_PSS_mgf1_procname);
  FuncLoadError := not assigned(RSA_verify_PKCS1_PSS_mgf1);
  if FuncLoadError then
  begin
    {$if not defined(RSA_verify_PKCS1_PSS_mgf1_allownil)}
    RSA_verify_PKCS1_PSS_mgf1 := ERR_RSA_verify_PKCS1_PSS_mgf1;
    {$ifend}
    {$if declared(RSA_verify_PKCS1_PSS_mgf1_introduced)}
    if LibVersion < RSA_verify_PKCS1_PSS_mgf1_introduced then
    begin
      {$if declared(FC_RSA_verify_PKCS1_PSS_mgf1)}
      RSA_verify_PKCS1_PSS_mgf1 := FC_RSA_verify_PKCS1_PSS_mgf1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_verify_PKCS1_PSS_mgf1_removed)}
    if RSA_verify_PKCS1_PSS_mgf1_removed <= LibVersion then
    begin
      {$if declared(_RSA_verify_PKCS1_PSS_mgf1)}
      RSA_verify_PKCS1_PSS_mgf1 := _RSA_verify_PKCS1_PSS_mgf1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_verify_PKCS1_PSS_mgf1_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_verify_PKCS1_PSS_mgf1');
    {$ifend}
  end;
  
  RSA_padding_add_PKCS1_PSS_mgf1 := LoadLibFunction(ADllHandle, RSA_padding_add_PKCS1_PSS_mgf1_procname);
  FuncLoadError := not assigned(RSA_padding_add_PKCS1_PSS_mgf1);
  if FuncLoadError then
  begin
    {$if not defined(RSA_padding_add_PKCS1_PSS_mgf1_allownil)}
    RSA_padding_add_PKCS1_PSS_mgf1 := ERR_RSA_padding_add_PKCS1_PSS_mgf1;
    {$ifend}
    {$if declared(RSA_padding_add_PKCS1_PSS_mgf1_introduced)}
    if LibVersion < RSA_padding_add_PKCS1_PSS_mgf1_introduced then
    begin
      {$if declared(FC_RSA_padding_add_PKCS1_PSS_mgf1)}
      RSA_padding_add_PKCS1_PSS_mgf1 := FC_RSA_padding_add_PKCS1_PSS_mgf1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_padding_add_PKCS1_PSS_mgf1_removed)}
    if RSA_padding_add_PKCS1_PSS_mgf1_removed <= LibVersion then
    begin
      {$if declared(_RSA_padding_add_PKCS1_PSS_mgf1)}
      RSA_padding_add_PKCS1_PSS_mgf1 := _RSA_padding_add_PKCS1_PSS_mgf1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_padding_add_PKCS1_PSS_mgf1_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_padding_add_PKCS1_PSS_mgf1');
    {$ifend}
  end;
  
  RSA_set_ex_data := LoadLibFunction(ADllHandle, RSA_set_ex_data_procname);
  FuncLoadError := not assigned(RSA_set_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(RSA_set_ex_data_allownil)}
    RSA_set_ex_data := ERR_RSA_set_ex_data;
    {$ifend}
    {$if declared(RSA_set_ex_data_introduced)}
    if LibVersion < RSA_set_ex_data_introduced then
    begin
      {$if declared(FC_RSA_set_ex_data)}
      RSA_set_ex_data := FC_RSA_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_set_ex_data_removed)}
    if RSA_set_ex_data_removed <= LibVersion then
    begin
      {$if declared(_RSA_set_ex_data)}
      RSA_set_ex_data := _RSA_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_set_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_set_ex_data');
    {$ifend}
  end;
  
  RSA_get_ex_data := LoadLibFunction(ADllHandle, RSA_get_ex_data_procname);
  FuncLoadError := not assigned(RSA_get_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(RSA_get_ex_data_allownil)}
    RSA_get_ex_data := ERR_RSA_get_ex_data;
    {$ifend}
    {$if declared(RSA_get_ex_data_introduced)}
    if LibVersion < RSA_get_ex_data_introduced then
    begin
      {$if declared(FC_RSA_get_ex_data)}
      RSA_get_ex_data := FC_RSA_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_get_ex_data_removed)}
    if RSA_get_ex_data_removed <= LibVersion then
    begin
      {$if declared(_RSA_get_ex_data)}
      RSA_get_ex_data := _RSA_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_get_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_get_ex_data');
    {$ifend}
  end;
  
  RSAPublicKey_dup := LoadLibFunction(ADllHandle, RSAPublicKey_dup_procname);
  FuncLoadError := not assigned(RSAPublicKey_dup);
  if FuncLoadError then
  begin
    {$if not defined(RSAPublicKey_dup_allownil)}
    RSAPublicKey_dup := ERR_RSAPublicKey_dup;
    {$ifend}
    {$if declared(RSAPublicKey_dup_introduced)}
    if LibVersion < RSAPublicKey_dup_introduced then
    begin
      {$if declared(FC_RSAPublicKey_dup)}
      RSAPublicKey_dup := FC_RSAPublicKey_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSAPublicKey_dup_removed)}
    if RSAPublicKey_dup_removed <= LibVersion then
    begin
      {$if declared(_RSAPublicKey_dup)}
      RSAPublicKey_dup := _RSAPublicKey_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSAPublicKey_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('RSAPublicKey_dup');
    {$ifend}
  end;
  
  RSAPrivateKey_dup := LoadLibFunction(ADllHandle, RSAPrivateKey_dup_procname);
  FuncLoadError := not assigned(RSAPrivateKey_dup);
  if FuncLoadError then
  begin
    {$if not defined(RSAPrivateKey_dup_allownil)}
    RSAPrivateKey_dup := ERR_RSAPrivateKey_dup;
    {$ifend}
    {$if declared(RSAPrivateKey_dup_introduced)}
    if LibVersion < RSAPrivateKey_dup_introduced then
    begin
      {$if declared(FC_RSAPrivateKey_dup)}
      RSAPrivateKey_dup := FC_RSAPrivateKey_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSAPrivateKey_dup_removed)}
    if RSAPrivateKey_dup_removed <= LibVersion then
    begin
      {$if declared(_RSAPrivateKey_dup)}
      RSAPrivateKey_dup := _RSAPrivateKey_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSAPrivateKey_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('RSAPrivateKey_dup');
    {$ifend}
  end;
  
  RSA_meth_new := LoadLibFunction(ADllHandle, RSA_meth_new_procname);
  FuncLoadError := not assigned(RSA_meth_new);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_new_allownil)}
    RSA_meth_new := ERR_RSA_meth_new;
    {$ifend}
    {$if declared(RSA_meth_new_introduced)}
    if LibVersion < RSA_meth_new_introduced then
    begin
      {$if declared(FC_RSA_meth_new)}
      RSA_meth_new := FC_RSA_meth_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_new_removed)}
    if RSA_meth_new_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_new)}
      RSA_meth_new := _RSA_meth_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_new_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_new');
    {$ifend}
  end;
  
  RSA_meth_free := LoadLibFunction(ADllHandle, RSA_meth_free_procname);
  FuncLoadError := not assigned(RSA_meth_free);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_free_allownil)}
    RSA_meth_free := ERR_RSA_meth_free;
    {$ifend}
    {$if declared(RSA_meth_free_introduced)}
    if LibVersion < RSA_meth_free_introduced then
    begin
      {$if declared(FC_RSA_meth_free)}
      RSA_meth_free := FC_RSA_meth_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_free_removed)}
    if RSA_meth_free_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_free)}
      RSA_meth_free := _RSA_meth_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_free_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_free');
    {$ifend}
  end;
  
  RSA_meth_dup := LoadLibFunction(ADllHandle, RSA_meth_dup_procname);
  FuncLoadError := not assigned(RSA_meth_dup);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_dup_allownil)}
    RSA_meth_dup := ERR_RSA_meth_dup;
    {$ifend}
    {$if declared(RSA_meth_dup_introduced)}
    if LibVersion < RSA_meth_dup_introduced then
    begin
      {$if declared(FC_RSA_meth_dup)}
      RSA_meth_dup := FC_RSA_meth_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_dup_removed)}
    if RSA_meth_dup_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_dup)}
      RSA_meth_dup := _RSA_meth_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_dup');
    {$ifend}
  end;
  
  RSA_meth_get0_name := LoadLibFunction(ADllHandle, RSA_meth_get0_name_procname);
  FuncLoadError := not assigned(RSA_meth_get0_name);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_get0_name_allownil)}
    RSA_meth_get0_name := ERR_RSA_meth_get0_name;
    {$ifend}
    {$if declared(RSA_meth_get0_name_introduced)}
    if LibVersion < RSA_meth_get0_name_introduced then
    begin
      {$if declared(FC_RSA_meth_get0_name)}
      RSA_meth_get0_name := FC_RSA_meth_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_get0_name_removed)}
    if RSA_meth_get0_name_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_get0_name)}
      RSA_meth_get0_name := _RSA_meth_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_get0_name_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_get0_name');
    {$ifend}
  end;
  
  RSA_meth_set1_name := LoadLibFunction(ADllHandle, RSA_meth_set1_name_procname);
  FuncLoadError := not assigned(RSA_meth_set1_name);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_set1_name_allownil)}
    RSA_meth_set1_name := ERR_RSA_meth_set1_name;
    {$ifend}
    {$if declared(RSA_meth_set1_name_introduced)}
    if LibVersion < RSA_meth_set1_name_introduced then
    begin
      {$if declared(FC_RSA_meth_set1_name)}
      RSA_meth_set1_name := FC_RSA_meth_set1_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_set1_name_removed)}
    if RSA_meth_set1_name_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_set1_name)}
      RSA_meth_set1_name := _RSA_meth_set1_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_set1_name_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_set1_name');
    {$ifend}
  end;
  
  RSA_meth_get_flags := LoadLibFunction(ADllHandle, RSA_meth_get_flags_procname);
  FuncLoadError := not assigned(RSA_meth_get_flags);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_get_flags_allownil)}
    RSA_meth_get_flags := ERR_RSA_meth_get_flags;
    {$ifend}
    {$if declared(RSA_meth_get_flags_introduced)}
    if LibVersion < RSA_meth_get_flags_introduced then
    begin
      {$if declared(FC_RSA_meth_get_flags)}
      RSA_meth_get_flags := FC_RSA_meth_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_get_flags_removed)}
    if RSA_meth_get_flags_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_get_flags)}
      RSA_meth_get_flags := _RSA_meth_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_get_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_get_flags');
    {$ifend}
  end;
  
  RSA_meth_set_flags := LoadLibFunction(ADllHandle, RSA_meth_set_flags_procname);
  FuncLoadError := not assigned(RSA_meth_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_set_flags_allownil)}
    RSA_meth_set_flags := ERR_RSA_meth_set_flags;
    {$ifend}
    {$if declared(RSA_meth_set_flags_introduced)}
    if LibVersion < RSA_meth_set_flags_introduced then
    begin
      {$if declared(FC_RSA_meth_set_flags)}
      RSA_meth_set_flags := FC_RSA_meth_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_set_flags_removed)}
    if RSA_meth_set_flags_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_set_flags)}
      RSA_meth_set_flags := _RSA_meth_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_set_flags');
    {$ifend}
  end;
  
  RSA_meth_get0_app_data := LoadLibFunction(ADllHandle, RSA_meth_get0_app_data_procname);
  FuncLoadError := not assigned(RSA_meth_get0_app_data);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_get0_app_data_allownil)}
    RSA_meth_get0_app_data := ERR_RSA_meth_get0_app_data;
    {$ifend}
    {$if declared(RSA_meth_get0_app_data_introduced)}
    if LibVersion < RSA_meth_get0_app_data_introduced then
    begin
      {$if declared(FC_RSA_meth_get0_app_data)}
      RSA_meth_get0_app_data := FC_RSA_meth_get0_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_get0_app_data_removed)}
    if RSA_meth_get0_app_data_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_get0_app_data)}
      RSA_meth_get0_app_data := _RSA_meth_get0_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_get0_app_data_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_get0_app_data');
    {$ifend}
  end;
  
  RSA_meth_set0_app_data := LoadLibFunction(ADllHandle, RSA_meth_set0_app_data_procname);
  FuncLoadError := not assigned(RSA_meth_set0_app_data);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_set0_app_data_allownil)}
    RSA_meth_set0_app_data := ERR_RSA_meth_set0_app_data;
    {$ifend}
    {$if declared(RSA_meth_set0_app_data_introduced)}
    if LibVersion < RSA_meth_set0_app_data_introduced then
    begin
      {$if declared(FC_RSA_meth_set0_app_data)}
      RSA_meth_set0_app_data := FC_RSA_meth_set0_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_set0_app_data_removed)}
    if RSA_meth_set0_app_data_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_set0_app_data)}
      RSA_meth_set0_app_data := _RSA_meth_set0_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_set0_app_data_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_set0_app_data');
    {$ifend}
  end;
  
  RSA_meth_get_pub_enc := LoadLibFunction(ADllHandle, RSA_meth_get_pub_enc_procname);
  FuncLoadError := not assigned(RSA_meth_get_pub_enc);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_get_pub_enc_allownil)}
    RSA_meth_get_pub_enc := ERR_RSA_meth_get_pub_enc;
    {$ifend}
    {$if declared(RSA_meth_get_pub_enc_introduced)}
    if LibVersion < RSA_meth_get_pub_enc_introduced then
    begin
      {$if declared(FC_RSA_meth_get_pub_enc)}
      RSA_meth_get_pub_enc := FC_RSA_meth_get_pub_enc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_get_pub_enc_removed)}
    if RSA_meth_get_pub_enc_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_get_pub_enc)}
      RSA_meth_get_pub_enc := _RSA_meth_get_pub_enc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_get_pub_enc_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_get_pub_enc');
    {$ifend}
  end;
  
  RSA_meth_set_pub_enc := LoadLibFunction(ADllHandle, RSA_meth_set_pub_enc_procname);
  FuncLoadError := not assigned(RSA_meth_set_pub_enc);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_set_pub_enc_allownil)}
    RSA_meth_set_pub_enc := ERR_RSA_meth_set_pub_enc;
    {$ifend}
    {$if declared(RSA_meth_set_pub_enc_introduced)}
    if LibVersion < RSA_meth_set_pub_enc_introduced then
    begin
      {$if declared(FC_RSA_meth_set_pub_enc)}
      RSA_meth_set_pub_enc := FC_RSA_meth_set_pub_enc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_set_pub_enc_removed)}
    if RSA_meth_set_pub_enc_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_set_pub_enc)}
      RSA_meth_set_pub_enc := _RSA_meth_set_pub_enc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_set_pub_enc_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_set_pub_enc');
    {$ifend}
  end;
  
  RSA_meth_get_pub_dec := LoadLibFunction(ADllHandle, RSA_meth_get_pub_dec_procname);
  FuncLoadError := not assigned(RSA_meth_get_pub_dec);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_get_pub_dec_allownil)}
    RSA_meth_get_pub_dec := ERR_RSA_meth_get_pub_dec;
    {$ifend}
    {$if declared(RSA_meth_get_pub_dec_introduced)}
    if LibVersion < RSA_meth_get_pub_dec_introduced then
    begin
      {$if declared(FC_RSA_meth_get_pub_dec)}
      RSA_meth_get_pub_dec := FC_RSA_meth_get_pub_dec;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_get_pub_dec_removed)}
    if RSA_meth_get_pub_dec_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_get_pub_dec)}
      RSA_meth_get_pub_dec := _RSA_meth_get_pub_dec;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_get_pub_dec_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_get_pub_dec');
    {$ifend}
  end;
  
  RSA_meth_set_pub_dec := LoadLibFunction(ADllHandle, RSA_meth_set_pub_dec_procname);
  FuncLoadError := not assigned(RSA_meth_set_pub_dec);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_set_pub_dec_allownil)}
    RSA_meth_set_pub_dec := ERR_RSA_meth_set_pub_dec;
    {$ifend}
    {$if declared(RSA_meth_set_pub_dec_introduced)}
    if LibVersion < RSA_meth_set_pub_dec_introduced then
    begin
      {$if declared(FC_RSA_meth_set_pub_dec)}
      RSA_meth_set_pub_dec := FC_RSA_meth_set_pub_dec;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_set_pub_dec_removed)}
    if RSA_meth_set_pub_dec_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_set_pub_dec)}
      RSA_meth_set_pub_dec := _RSA_meth_set_pub_dec;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_set_pub_dec_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_set_pub_dec');
    {$ifend}
  end;
  
  RSA_meth_get_priv_enc := LoadLibFunction(ADllHandle, RSA_meth_get_priv_enc_procname);
  FuncLoadError := not assigned(RSA_meth_get_priv_enc);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_get_priv_enc_allownil)}
    RSA_meth_get_priv_enc := ERR_RSA_meth_get_priv_enc;
    {$ifend}
    {$if declared(RSA_meth_get_priv_enc_introduced)}
    if LibVersion < RSA_meth_get_priv_enc_introduced then
    begin
      {$if declared(FC_RSA_meth_get_priv_enc)}
      RSA_meth_get_priv_enc := FC_RSA_meth_get_priv_enc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_get_priv_enc_removed)}
    if RSA_meth_get_priv_enc_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_get_priv_enc)}
      RSA_meth_get_priv_enc := _RSA_meth_get_priv_enc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_get_priv_enc_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_get_priv_enc');
    {$ifend}
  end;
  
  RSA_meth_set_priv_enc := LoadLibFunction(ADllHandle, RSA_meth_set_priv_enc_procname);
  FuncLoadError := not assigned(RSA_meth_set_priv_enc);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_set_priv_enc_allownil)}
    RSA_meth_set_priv_enc := ERR_RSA_meth_set_priv_enc;
    {$ifend}
    {$if declared(RSA_meth_set_priv_enc_introduced)}
    if LibVersion < RSA_meth_set_priv_enc_introduced then
    begin
      {$if declared(FC_RSA_meth_set_priv_enc)}
      RSA_meth_set_priv_enc := FC_RSA_meth_set_priv_enc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_set_priv_enc_removed)}
    if RSA_meth_set_priv_enc_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_set_priv_enc)}
      RSA_meth_set_priv_enc := _RSA_meth_set_priv_enc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_set_priv_enc_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_set_priv_enc');
    {$ifend}
  end;
  
  RSA_meth_get_priv_dec := LoadLibFunction(ADllHandle, RSA_meth_get_priv_dec_procname);
  FuncLoadError := not assigned(RSA_meth_get_priv_dec);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_get_priv_dec_allownil)}
    RSA_meth_get_priv_dec := ERR_RSA_meth_get_priv_dec;
    {$ifend}
    {$if declared(RSA_meth_get_priv_dec_introduced)}
    if LibVersion < RSA_meth_get_priv_dec_introduced then
    begin
      {$if declared(FC_RSA_meth_get_priv_dec)}
      RSA_meth_get_priv_dec := FC_RSA_meth_get_priv_dec;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_get_priv_dec_removed)}
    if RSA_meth_get_priv_dec_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_get_priv_dec)}
      RSA_meth_get_priv_dec := _RSA_meth_get_priv_dec;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_get_priv_dec_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_get_priv_dec');
    {$ifend}
  end;
  
  RSA_meth_set_priv_dec := LoadLibFunction(ADllHandle, RSA_meth_set_priv_dec_procname);
  FuncLoadError := not assigned(RSA_meth_set_priv_dec);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_set_priv_dec_allownil)}
    RSA_meth_set_priv_dec := ERR_RSA_meth_set_priv_dec;
    {$ifend}
    {$if declared(RSA_meth_set_priv_dec_introduced)}
    if LibVersion < RSA_meth_set_priv_dec_introduced then
    begin
      {$if declared(FC_RSA_meth_set_priv_dec)}
      RSA_meth_set_priv_dec := FC_RSA_meth_set_priv_dec;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_set_priv_dec_removed)}
    if RSA_meth_set_priv_dec_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_set_priv_dec)}
      RSA_meth_set_priv_dec := _RSA_meth_set_priv_dec;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_set_priv_dec_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_set_priv_dec');
    {$ifend}
  end;
  
  RSA_meth_get_mod_exp := LoadLibFunction(ADllHandle, RSA_meth_get_mod_exp_procname);
  FuncLoadError := not assigned(RSA_meth_get_mod_exp);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_get_mod_exp_allownil)}
    RSA_meth_get_mod_exp := ERR_RSA_meth_get_mod_exp;
    {$ifend}
    {$if declared(RSA_meth_get_mod_exp_introduced)}
    if LibVersion < RSA_meth_get_mod_exp_introduced then
    begin
      {$if declared(FC_RSA_meth_get_mod_exp)}
      RSA_meth_get_mod_exp := FC_RSA_meth_get_mod_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_get_mod_exp_removed)}
    if RSA_meth_get_mod_exp_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_get_mod_exp)}
      RSA_meth_get_mod_exp := _RSA_meth_get_mod_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_get_mod_exp_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_get_mod_exp');
    {$ifend}
  end;
  
  RSA_meth_set_mod_exp := LoadLibFunction(ADllHandle, RSA_meth_set_mod_exp_procname);
  FuncLoadError := not assigned(RSA_meth_set_mod_exp);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_set_mod_exp_allownil)}
    RSA_meth_set_mod_exp := ERR_RSA_meth_set_mod_exp;
    {$ifend}
    {$if declared(RSA_meth_set_mod_exp_introduced)}
    if LibVersion < RSA_meth_set_mod_exp_introduced then
    begin
      {$if declared(FC_RSA_meth_set_mod_exp)}
      RSA_meth_set_mod_exp := FC_RSA_meth_set_mod_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_set_mod_exp_removed)}
    if RSA_meth_set_mod_exp_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_set_mod_exp)}
      RSA_meth_set_mod_exp := _RSA_meth_set_mod_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_set_mod_exp_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_set_mod_exp');
    {$ifend}
  end;
  
  RSA_meth_get_bn_mod_exp := LoadLibFunction(ADllHandle, RSA_meth_get_bn_mod_exp_procname);
  FuncLoadError := not assigned(RSA_meth_get_bn_mod_exp);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_get_bn_mod_exp_allownil)}
    RSA_meth_get_bn_mod_exp := ERR_RSA_meth_get_bn_mod_exp;
    {$ifend}
    {$if declared(RSA_meth_get_bn_mod_exp_introduced)}
    if LibVersion < RSA_meth_get_bn_mod_exp_introduced then
    begin
      {$if declared(FC_RSA_meth_get_bn_mod_exp)}
      RSA_meth_get_bn_mod_exp := FC_RSA_meth_get_bn_mod_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_get_bn_mod_exp_removed)}
    if RSA_meth_get_bn_mod_exp_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_get_bn_mod_exp)}
      RSA_meth_get_bn_mod_exp := _RSA_meth_get_bn_mod_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_get_bn_mod_exp_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_get_bn_mod_exp');
    {$ifend}
  end;
  
  RSA_meth_set_bn_mod_exp := LoadLibFunction(ADllHandle, RSA_meth_set_bn_mod_exp_procname);
  FuncLoadError := not assigned(RSA_meth_set_bn_mod_exp);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_set_bn_mod_exp_allownil)}
    RSA_meth_set_bn_mod_exp := ERR_RSA_meth_set_bn_mod_exp;
    {$ifend}
    {$if declared(RSA_meth_set_bn_mod_exp_introduced)}
    if LibVersion < RSA_meth_set_bn_mod_exp_introduced then
    begin
      {$if declared(FC_RSA_meth_set_bn_mod_exp)}
      RSA_meth_set_bn_mod_exp := FC_RSA_meth_set_bn_mod_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_set_bn_mod_exp_removed)}
    if RSA_meth_set_bn_mod_exp_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_set_bn_mod_exp)}
      RSA_meth_set_bn_mod_exp := _RSA_meth_set_bn_mod_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_set_bn_mod_exp_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_set_bn_mod_exp');
    {$ifend}
  end;
  
  RSA_meth_get_init := LoadLibFunction(ADllHandle, RSA_meth_get_init_procname);
  FuncLoadError := not assigned(RSA_meth_get_init);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_get_init_allownil)}
    RSA_meth_get_init := ERR_RSA_meth_get_init;
    {$ifend}
    {$if declared(RSA_meth_get_init_introduced)}
    if LibVersion < RSA_meth_get_init_introduced then
    begin
      {$if declared(FC_RSA_meth_get_init)}
      RSA_meth_get_init := FC_RSA_meth_get_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_get_init_removed)}
    if RSA_meth_get_init_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_get_init)}
      RSA_meth_get_init := _RSA_meth_get_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_get_init_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_get_init');
    {$ifend}
  end;
  
  RSA_meth_set_init := LoadLibFunction(ADllHandle, RSA_meth_set_init_procname);
  FuncLoadError := not assigned(RSA_meth_set_init);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_set_init_allownil)}
    RSA_meth_set_init := ERR_RSA_meth_set_init;
    {$ifend}
    {$if declared(RSA_meth_set_init_introduced)}
    if LibVersion < RSA_meth_set_init_introduced then
    begin
      {$if declared(FC_RSA_meth_set_init)}
      RSA_meth_set_init := FC_RSA_meth_set_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_set_init_removed)}
    if RSA_meth_set_init_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_set_init)}
      RSA_meth_set_init := _RSA_meth_set_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_set_init_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_set_init');
    {$ifend}
  end;
  
  RSA_meth_get_finish := LoadLibFunction(ADllHandle, RSA_meth_get_finish_procname);
  FuncLoadError := not assigned(RSA_meth_get_finish);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_get_finish_allownil)}
    RSA_meth_get_finish := ERR_RSA_meth_get_finish;
    {$ifend}
    {$if declared(RSA_meth_get_finish_introduced)}
    if LibVersion < RSA_meth_get_finish_introduced then
    begin
      {$if declared(FC_RSA_meth_get_finish)}
      RSA_meth_get_finish := FC_RSA_meth_get_finish;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_get_finish_removed)}
    if RSA_meth_get_finish_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_get_finish)}
      RSA_meth_get_finish := _RSA_meth_get_finish;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_get_finish_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_get_finish');
    {$ifend}
  end;
  
  RSA_meth_set_finish := LoadLibFunction(ADllHandle, RSA_meth_set_finish_procname);
  FuncLoadError := not assigned(RSA_meth_set_finish);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_set_finish_allownil)}
    RSA_meth_set_finish := ERR_RSA_meth_set_finish;
    {$ifend}
    {$if declared(RSA_meth_set_finish_introduced)}
    if LibVersion < RSA_meth_set_finish_introduced then
    begin
      {$if declared(FC_RSA_meth_set_finish)}
      RSA_meth_set_finish := FC_RSA_meth_set_finish;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_set_finish_removed)}
    if RSA_meth_set_finish_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_set_finish)}
      RSA_meth_set_finish := _RSA_meth_set_finish;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_set_finish_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_set_finish');
    {$ifend}
  end;
  
  RSA_meth_get_sign := LoadLibFunction(ADllHandle, RSA_meth_get_sign_procname);
  FuncLoadError := not assigned(RSA_meth_get_sign);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_get_sign_allownil)}
    RSA_meth_get_sign := ERR_RSA_meth_get_sign;
    {$ifend}
    {$if declared(RSA_meth_get_sign_introduced)}
    if LibVersion < RSA_meth_get_sign_introduced then
    begin
      {$if declared(FC_RSA_meth_get_sign)}
      RSA_meth_get_sign := FC_RSA_meth_get_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_get_sign_removed)}
    if RSA_meth_get_sign_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_get_sign)}
      RSA_meth_get_sign := _RSA_meth_get_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_get_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_get_sign');
    {$ifend}
  end;
  
  RSA_meth_set_sign := LoadLibFunction(ADllHandle, RSA_meth_set_sign_procname);
  FuncLoadError := not assigned(RSA_meth_set_sign);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_set_sign_allownil)}
    RSA_meth_set_sign := ERR_RSA_meth_set_sign;
    {$ifend}
    {$if declared(RSA_meth_set_sign_introduced)}
    if LibVersion < RSA_meth_set_sign_introduced then
    begin
      {$if declared(FC_RSA_meth_set_sign)}
      RSA_meth_set_sign := FC_RSA_meth_set_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_set_sign_removed)}
    if RSA_meth_set_sign_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_set_sign)}
      RSA_meth_set_sign := _RSA_meth_set_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_set_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_set_sign');
    {$ifend}
  end;
  
  RSA_meth_get_verify := LoadLibFunction(ADllHandle, RSA_meth_get_verify_procname);
  FuncLoadError := not assigned(RSA_meth_get_verify);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_get_verify_allownil)}
    RSA_meth_get_verify := ERR_RSA_meth_get_verify;
    {$ifend}
    {$if declared(RSA_meth_get_verify_introduced)}
    if LibVersion < RSA_meth_get_verify_introduced then
    begin
      {$if declared(FC_RSA_meth_get_verify)}
      RSA_meth_get_verify := FC_RSA_meth_get_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_get_verify_removed)}
    if RSA_meth_get_verify_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_get_verify)}
      RSA_meth_get_verify := _RSA_meth_get_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_get_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_get_verify');
    {$ifend}
  end;
  
  RSA_meth_set_verify := LoadLibFunction(ADllHandle, RSA_meth_set_verify_procname);
  FuncLoadError := not assigned(RSA_meth_set_verify);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_set_verify_allownil)}
    RSA_meth_set_verify := ERR_RSA_meth_set_verify;
    {$ifend}
    {$if declared(RSA_meth_set_verify_introduced)}
    if LibVersion < RSA_meth_set_verify_introduced then
    begin
      {$if declared(FC_RSA_meth_set_verify)}
      RSA_meth_set_verify := FC_RSA_meth_set_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_set_verify_removed)}
    if RSA_meth_set_verify_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_set_verify)}
      RSA_meth_set_verify := _RSA_meth_set_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_set_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_set_verify');
    {$ifend}
  end;
  
  RSA_meth_get_keygen := LoadLibFunction(ADllHandle, RSA_meth_get_keygen_procname);
  FuncLoadError := not assigned(RSA_meth_get_keygen);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_get_keygen_allownil)}
    RSA_meth_get_keygen := ERR_RSA_meth_get_keygen;
    {$ifend}
    {$if declared(RSA_meth_get_keygen_introduced)}
    if LibVersion < RSA_meth_get_keygen_introduced then
    begin
      {$if declared(FC_RSA_meth_get_keygen)}
      RSA_meth_get_keygen := FC_RSA_meth_get_keygen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_get_keygen_removed)}
    if RSA_meth_get_keygen_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_get_keygen)}
      RSA_meth_get_keygen := _RSA_meth_get_keygen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_get_keygen_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_get_keygen');
    {$ifend}
  end;
  
  RSA_meth_set_keygen := LoadLibFunction(ADllHandle, RSA_meth_set_keygen_procname);
  FuncLoadError := not assigned(RSA_meth_set_keygen);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_set_keygen_allownil)}
    RSA_meth_set_keygen := ERR_RSA_meth_set_keygen;
    {$ifend}
    {$if declared(RSA_meth_set_keygen_introduced)}
    if LibVersion < RSA_meth_set_keygen_introduced then
    begin
      {$if declared(FC_RSA_meth_set_keygen)}
      RSA_meth_set_keygen := FC_RSA_meth_set_keygen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_set_keygen_removed)}
    if RSA_meth_set_keygen_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_set_keygen)}
      RSA_meth_set_keygen := _RSA_meth_set_keygen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_set_keygen_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_set_keygen');
    {$ifend}
  end;
  
  RSA_meth_get_multi_prime_keygen := LoadLibFunction(ADllHandle, RSA_meth_get_multi_prime_keygen_procname);
  FuncLoadError := not assigned(RSA_meth_get_multi_prime_keygen);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_get_multi_prime_keygen_allownil)}
    RSA_meth_get_multi_prime_keygen := ERR_RSA_meth_get_multi_prime_keygen;
    {$ifend}
    {$if declared(RSA_meth_get_multi_prime_keygen_introduced)}
    if LibVersion < RSA_meth_get_multi_prime_keygen_introduced then
    begin
      {$if declared(FC_RSA_meth_get_multi_prime_keygen)}
      RSA_meth_get_multi_prime_keygen := FC_RSA_meth_get_multi_prime_keygen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_get_multi_prime_keygen_removed)}
    if RSA_meth_get_multi_prime_keygen_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_get_multi_prime_keygen)}
      RSA_meth_get_multi_prime_keygen := _RSA_meth_get_multi_prime_keygen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_get_multi_prime_keygen_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_get_multi_prime_keygen');
    {$ifend}
  end;
  
  RSA_meth_set_multi_prime_keygen := LoadLibFunction(ADllHandle, RSA_meth_set_multi_prime_keygen_procname);
  FuncLoadError := not assigned(RSA_meth_set_multi_prime_keygen);
  if FuncLoadError then
  begin
    {$if not defined(RSA_meth_set_multi_prime_keygen_allownil)}
    RSA_meth_set_multi_prime_keygen := ERR_RSA_meth_set_multi_prime_keygen;
    {$ifend}
    {$if declared(RSA_meth_set_multi_prime_keygen_introduced)}
    if LibVersion < RSA_meth_set_multi_prime_keygen_introduced then
    begin
      {$if declared(FC_RSA_meth_set_multi_prime_keygen)}
      RSA_meth_set_multi_prime_keygen := FC_RSA_meth_set_multi_prime_keygen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(RSA_meth_set_multi_prime_keygen_removed)}
    if RSA_meth_set_multi_prime_keygen_removed <= LibVersion then
    begin
      {$if declared(_RSA_meth_set_multi_prime_keygen)}
      RSA_meth_set_multi_prime_keygen := _RSA_meth_set_multi_prime_keygen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(RSA_meth_set_multi_prime_keygen_allownil)}
    if FuncLoadError then
      AFailed.Add('RSA_meth_set_multi_prime_keygen');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  EVP_PKEY_CTX_set_rsa_padding := nil;
  EVP_PKEY_CTX_get_rsa_padding := nil;
  EVP_PKEY_CTX_set_rsa_pss_saltlen := nil;
  EVP_PKEY_CTX_get_rsa_pss_saltlen := nil;
  EVP_PKEY_CTX_set_rsa_keygen_bits := nil;
  EVP_PKEY_CTX_set1_rsa_keygen_pubexp := nil;
  EVP_PKEY_CTX_set_rsa_keygen_primes := nil;
  EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen := nil;
  EVP_PKEY_CTX_set_rsa_keygen_pubexp := nil;
  EVP_PKEY_CTX_set_rsa_mgf1_md := nil;
  EVP_PKEY_CTX_set_rsa_mgf1_md_name := nil;
  EVP_PKEY_CTX_get_rsa_mgf1_md := nil;
  EVP_PKEY_CTX_get_rsa_mgf1_md_name := nil;
  EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md := nil;
  EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name := nil;
  EVP_PKEY_CTX_set_rsa_pss_keygen_md := nil;
  EVP_PKEY_CTX_set_rsa_pss_keygen_md_name := nil;
  EVP_PKEY_CTX_set_rsa_oaep_md := nil;
  EVP_PKEY_CTX_set_rsa_oaep_md_name := nil;
  EVP_PKEY_CTX_get_rsa_oaep_md := nil;
  EVP_PKEY_CTX_get_rsa_oaep_md_name := nil;
  EVP_PKEY_CTX_set0_rsa_oaep_label := nil;
  EVP_PKEY_CTX_get0_rsa_oaep_label := nil;
  RSA_new := nil;
  RSA_new_method := nil;
  RSA_bits := nil;
  RSA_size := nil;
  RSA_security_bits := nil;
  RSA_set0_key := nil;
  RSA_set0_factors := nil;
  RSA_set0_crt_params := nil;
  RSA_set0_multi_prime_params := nil;
  RSA_get0_key := nil;
  RSA_get0_factors := nil;
  RSA_get_multi_prime_extra_count := nil;
  RSA_get0_multi_prime_factors := nil;
  RSA_get0_crt_params := nil;
  RSA_get0_multi_prime_crt_params := nil;
  RSA_get0_n := nil;
  RSA_get0_e := nil;
  RSA_get0_d := nil;
  RSA_get0_p := nil;
  RSA_get0_q := nil;
  RSA_get0_dmp1 := nil;
  RSA_get0_dmq1 := nil;
  RSA_get0_iqmp := nil;
  RSA_get0_pss_params := nil;
  RSA_clear_flags := nil;
  RSA_test_flags := nil;
  RSA_set_flags := nil;
  RSA_get_version := nil;
  RSA_get0_engine := nil;
  RSA_generate_key_ex := nil;
  RSA_generate_multi_prime_key := nil;
  RSA_X931_derive_ex := nil;
  RSA_X931_generate_key_ex := nil;
  RSA_check_key := nil;
  RSA_check_key_ex := nil;
  RSA_public_encrypt := nil;
  RSA_private_encrypt := nil;
  RSA_public_decrypt := nil;
  RSA_private_decrypt := nil;
  RSA_free := nil;
  RSA_up_ref := nil;
  RSA_flags := nil;
  RSA_set_default_method := nil;
  RSA_get_default_method := nil;
  RSA_null_method := nil;
  RSA_get_method := nil;
  RSA_set_method := nil;
  RSA_PKCS1_OpenSSL := nil;
  d2i_RSAPublicKey := nil;
  i2d_RSAPublicKey := nil;
  RSAPublicKey_it := nil;
  d2i_RSAPrivateKey := nil;
  i2d_RSAPrivateKey := nil;
  RSAPrivateKey_it := nil;
  RSA_pkey_ctx_ctrl := nil;
  RSA_PSS_PARAMS_new := nil;
  RSA_PSS_PARAMS_free := nil;
  d2i_RSA_PSS_PARAMS := nil;
  i2d_RSA_PSS_PARAMS := nil;
  RSA_PSS_PARAMS_it := nil;
  RSA_PSS_PARAMS_dup := nil;
  RSA_OAEP_PARAMS_new := nil;
  RSA_OAEP_PARAMS_free := nil;
  d2i_RSA_OAEP_PARAMS := nil;
  i2d_RSA_OAEP_PARAMS := nil;
  RSA_OAEP_PARAMS_it := nil;
  RSA_print_fp := nil;
  RSA_print := nil;
  RSA_sign := nil;
  RSA_verify := nil;
  RSA_sign_ASN1_OCTET_STRING := nil;
  RSA_verify_ASN1_OCTET_STRING := nil;
  RSA_blinding_on := nil;
  RSA_blinding_off := nil;
  RSA_setup_blinding := nil;
  RSA_padding_add_PKCS1_type_1 := nil;
  RSA_padding_check_PKCS1_type_1 := nil;
  RSA_padding_add_PKCS1_type_2 := nil;
  RSA_padding_check_PKCS1_type_2 := nil;
  PKCS1_MGF1 := nil;
  RSA_padding_add_PKCS1_OAEP := nil;
  RSA_padding_check_PKCS1_OAEP := nil;
  RSA_padding_add_PKCS1_OAEP_mgf1 := nil;
  RSA_padding_check_PKCS1_OAEP_mgf1 := nil;
  RSA_padding_add_none := nil;
  RSA_padding_check_none := nil;
  RSA_padding_add_X931 := nil;
  RSA_padding_check_X931 := nil;
  RSA_X931_hash_id := nil;
  RSA_verify_PKCS1_PSS := nil;
  RSA_padding_add_PKCS1_PSS := nil;
  RSA_verify_PKCS1_PSS_mgf1 := nil;
  RSA_padding_add_PKCS1_PSS_mgf1 := nil;
  RSA_set_ex_data := nil;
  RSA_get_ex_data := nil;
  RSAPublicKey_dup := nil;
  RSAPrivateKey_dup := nil;
  RSA_meth_new := nil;
  RSA_meth_free := nil;
  RSA_meth_dup := nil;
  RSA_meth_get0_name := nil;
  RSA_meth_set1_name := nil;
  RSA_meth_get_flags := nil;
  RSA_meth_set_flags := nil;
  RSA_meth_get0_app_data := nil;
  RSA_meth_set0_app_data := nil;
  RSA_meth_get_pub_enc := nil;
  RSA_meth_set_pub_enc := nil;
  RSA_meth_get_pub_dec := nil;
  RSA_meth_set_pub_dec := nil;
  RSA_meth_get_priv_enc := nil;
  RSA_meth_set_priv_enc := nil;
  RSA_meth_get_priv_dec := nil;
  RSA_meth_set_priv_dec := nil;
  RSA_meth_get_mod_exp := nil;
  RSA_meth_set_mod_exp := nil;
  RSA_meth_get_bn_mod_exp := nil;
  RSA_meth_set_bn_mod_exp := nil;
  RSA_meth_get_init := nil;
  RSA_meth_set_init := nil;
  RSA_meth_get_finish := nil;
  RSA_meth_set_finish := nil;
  RSA_meth_get_sign := nil;
  RSA_meth_set_sign := nil;
  RSA_meth_get_verify := nil;
  RSA_meth_set_verify := nil;
  RSA_meth_get_keygen := nil;
  RSA_meth_set_keygen := nil;
  RSA_meth_get_multi_prime_keygen := nil;
  RSA_meth_set_multi_prime_keygen := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.