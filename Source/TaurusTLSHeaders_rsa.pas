/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_rsa.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_rsa.h2pas
     and this file regenerated. TaurusTLSHeaders_rsa.h2pas is distributed with the full Indy
     Distribution.
   *)
   
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

// Headers for OpenSSL 1.1.1
// rsa.h


uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_evp;

(* The types RSA and RSA_METHOD are defined in ossl_typ.h *)

const
  {$EXTERNALSYM OPENSSL_RSA_MAX_MODULUS_BITS}
  OPENSSL_RSA_MAX_MODULUS_BITS =  16384;
  {$EXTERNALSYM OPENSSL_RSA_FIPS_MIN_MODULUS_BITS}
  OPENSSL_RSA_FIPS_MIN_MODULUS_BITS = 1024;
  {$EXTERNALSYM OPENSSL_RSA_SMALL_MODULUS_BITS}
  OPENSSL_RSA_SMALL_MODULUS_BITS = 3072;
  (* exponent limit enforced for "large" modulus only *)
  {$EXTERNALSYM OPENSSL_RSA_MAX_PUBEXP_BITS}
  OPENSSL_RSA_MAX_PUBEXP_BITS =  64;

  {$EXTERNALSYM RSA_3}
  RSA_3 =  TIdC_Long($3);
  {$EXTERNALSYM RSA_F4}
  RSA_F4 = TIdC_Long($10001);

  (* based on RFC 8017 appendix A.1.2 *)
  {$EXTERNALSYM RSA_ASN1_VERSION_DEFAULT}
  RSA_ASN1_VERSION_DEFAULT = 0;
  {$EXTERNALSYM RSA_ASN1_VERSION_MULTI}
  RSA_ASN1_VERSION_MULTI =   1;
  {$EXTERNALSYM RSA_DEFAULT_PRIME_NUM}
  RSA_DEFAULT_PRIME_NUM =    2;

  {$EXTERNALSYM RSA_METHOD_FLAG_NO_CHECK}
  RSA_METHOD_FLAG_NO_CHECK = $0001; (* don't check pub/private match *)
  {$EXTERNALSYM RSA_FLAG_CACHE_PUBLIC}
  RSA_FLAG_CACHE_PUBLIC =    $0002;
  {$EXTERNALSYM RSA_FLAG_CACHE_PRIVATE}
  RSA_FLAG_CACHE_PRIVATE =   $0004;
  {$EXTERNALSYM RSA_FLAG_BLINDING}
  RSA_FLAG_BLINDING =        $0008;
  {$EXTERNALSYM RSA_FLAG_THREAD_SAFE}
  RSA_FLAG_THREAD_SAFE =     $0010;
  (*
   * This flag means the private key operations will be handled by rsa_mod_exp
   * and that they do not depend on the private key components being present:
   * for example a key stored in external hardware. Without this flag
   * bn_mod_exp gets called when private key components are absent.
   *)
  {$EXTERNALSYM RSA_FLAG_EXT_PKEY}
  RSA_FLAG_EXT_PKEY =        $0020;
  (*
   * new with 0.9.6j and 0.9.7b; the built-in
   * RSA implementation now uses blinding by
   * default (ignoring RSA_FLAG_BLINDING),
   * but other engines might not need it
   *)
  {$EXTERNALSYM RSA_FLAG_NO_BLINDING}
  RSA_FLAG_NO_BLINDING =     $0080;
  (*
   * Does nothing. Previously this switched off constant time behaviour.
   *)
  {$EXTERNALSYM RSA_FLAG_NO_CONSTTIME}
  RSA_FLAG_NO_CONSTTIME =    $0000;

  (* Salt length matches digest *)
  {$EXTERNALSYM RSA_PSS_SALTLEN_DIGEST}
  RSA_PSS_SALTLEN_DIGEST = -1;
  (* Verify only: auto detect salt length *)
  {$EXTERNALSYM RSA_PSS_SALTLEN_AUTO}
  RSA_PSS_SALTLEN_AUTO = -2;
  (* Set salt length to maximum possible *)
  {$EXTERNALSYM RSA_PSS_SALTLEN_MAX}
  RSA_PSS_SALTLEN_MAX = -3;
  (* Old compatible max salt length for sign only *)
  {$EXTERNALSYM RSA_PSS_SALTLEN_MAX_SIGN}
  RSA_PSS_SALTLEN_MAX_SIGN = -2;

  {$EXTERNALSYM EVP_PKEY_CTRL_RSA_PADDING}
  EVP_PKEY_CTRL_RSA_PADDING = EVP_PKEY_ALG_CTRL + 1;
  {$EXTERNALSYM EVP_PKEY_CTRL_RSA_PSS_SALTLEN}
  EVP_PKEY_CTRL_RSA_PSS_SALTLEN = EVP_PKEY_ALG_CTRL + 2;

  {$EXTERNALSYM EVP_PKEY_CTRL_RSA_KEYGEN_BITS}
  EVP_PKEY_CTRL_RSA_KEYGEN_BITS = EVP_PKEY_ALG_CTRL + 3;
  {$EXTERNALSYM EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP}
  EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP = EVP_PKEY_ALG_CTRL + 4;
  {$EXTERNALSYM EVP_PKEY_CTRL_RSA_MGF1_MD}
  EVP_PKEY_CTRL_RSA_MGF1_MD = EVP_PKEY_ALG_CTRL + 5;

  {$EXTERNALSYM EVP_PKEY_CTRL_GET_RSA_PADDING}
  EVP_PKEY_CTRL_GET_RSA_PADDING =  EVP_PKEY_ALG_CTRL + 6;
  {$EXTERNALSYM EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN}
  EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN = EVP_PKEY_ALG_CTRL + 7;
  {$EXTERNALSYM EVP_PKEY_CTRL_GET_RSA_MGF1_MD}
  EVP_PKEY_CTRL_GET_RSA_MGF1_MD =  EVP_PKEY_ALG_CTRL + 8;

  {$EXTERNALSYM EVP_PKEY_CTRL_RSA_OAEP_MD}
  EVP_PKEY_CTRL_RSA_OAEP_MD = EVP_PKEY_ALG_CTRL + 9;
  {$EXTERNALSYM EVP_PKEY_CTRL_RSA_OAEP_LABEL}
  EVP_PKEY_CTRL_RSA_OAEP_LABEL = EVP_PKEY_ALG_CTRL + 10;

  {$EXTERNALSYM EVP_PKEY_CTRL_GET_RSA_OAEP_MD}
  EVP_PKEY_CTRL_GET_RSA_OAEP_MD = EVP_PKEY_ALG_CTRL + 11;
  {$EXTERNALSYM EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL}
  EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL = EVP_PKEY_ALG_CTRL + 12;

  {$EXTERNALSYM EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES}
  EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES = EVP_PKEY_ALG_CTRL + 13;

  {$EXTERNALSYM RSA_PKCS1_PADDING}
  RSA_PKCS1_PADDING =   1;
  {$EXTERNALSYM RSA_SSLV23_PADDING}
  RSA_SSLV23_PADDING =  2;
  {$EXTERNALSYM RSA_NO_PADDING}
  RSA_NO_PADDING =   3;
  {$EXTERNALSYM RSA_PKCS1_OAEP_PADDING}
  RSA_PKCS1_OAEP_PADDING = 4;
  {$EXTERNALSYM RSA_X931_PADDING}
  RSA_X931_PADDING =   5;
  {$EXTERNALSYM RSA_PKCS1_PSS_PADDING}
  RSA_PKCS1_PSS_PADDING =  6; (* EVP_PKEY_ only *)
  {$EXTERNALSYM RSA_PKCS1_PADDING_SIZE}
  RSA_PKCS1_PADDING_SIZE = 11;

  (*
   * If this flag is set the RSA method is FIPS compliant and can be used in
   * FIPS mode. This is set in the validated module method. If an application
   * sets this flag in its own methods it is its responsibility to ensure the
   * result is compliant.
   *)
  {$EXTERNALSYM RSA_FLAG_FIPS_METHOD}
  RSA_FLAG_FIPS_METHOD = $0400;
  (*
   * If this flag is set the operations normally disabled in FIPS mode are
   * permitted it is then the applications responsibility to ensure that the
   * usage is compliant.
   *)
  {$EXTERNALSYM RSA_FLAG_NON_FIPS_ALLOW}
  RSA_FLAG_NON_FIPS_ALLOW = $0400;
  (*
   * Application has decided PRNG is good enough to generate a key: don't
   * check.
   *)
  {$EXTERNALSYM RSA_FLAG_CHECKED}
  RSA_FLAG_CHECKED = $0800;

type
  {$EXTERNALSYM rsa_pss_params_st}
  rsa_pss_params_st = record
    hashAlgorithm: PX509_ALGOR;
    maskGenAlgorithm: PX509_ALGOR;
    saltLength: PASN1_INTEGER;
    trailerField: PASN1_INTEGER;
    (* Decoded hash algorithm from maskGenAlgorithm *)
    maskHash: PX509_ALGOR;
  end;
  {$EXTERNALSYM RSA_PSS_PARAMS}
  RSA_PSS_PARAMS = rsa_pss_params_st;
  // DECLARE_ASN1_FUNCTIONS(RSA_PSS_PARAMS)

  {$EXTERNALSYM rsa_oaep_params_st}
  rsa_oaep_params_st = record
    hashFunc: PX509_ALGOR;
    maskGenFunc: PX509_ALGOR;
    pSourceFunc: PX509_ALGOR;
    (* Decoded hash algorithm from maskGenFunc *)
    maskHash: PX509_ALGOR;
  end;
  {$EXTERNALSYM RSA_OAEP_PARAMS}
  RSA_OAEP_PARAMS = rsa_oaep_params_st;
  //DECLARE_ASN1_FUNCTIONS(RSA_OAEP_PARAMS)

  //DECLARE_ASN1_ENCODE_FUNCTIONS_const(RSA, RSAPublicKey)
  //DECLARE_ASN1_ENCODE_FUNCTIONS_const(RSA, RSAPrivateKey)

  {$EXTERNALSYM RSA_meth_set_priv_dec_priv_dec}
  RSA_meth_set_priv_dec_priv_dec = function(flen: TIdC_INT; const from: PByte;
    to_: PByte; rsa: PRSA; padding: TIdC_INT): TIdC_INT; cdecl;

  {$EXTERNALSYM RSA_meth_set_mod_exp_mod_exp}
  RSA_meth_set_mod_exp_mod_exp = function(r0: PBIGNUM; const i: PBIGNUM;
    rsa: PRSA; ctx: PBN_CTX): TIdC_INT; cdecl;

  {$EXTERNALSYM RSA_meth_set_bn_mod_exp_bn_mod_exp}
  RSA_meth_set_bn_mod_exp_bn_mod_exp = function(r: PBIGNUM; const a: PBIGNUM;
    const p: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTx; m_ctx: PBN_MONT_CTx): TIdC_INT; cdecl;

  {$EXTERNALSYM RSA_meth_set_init_init}
  RSA_meth_set_init_init = function(rsa: PRSA): TIdC_INT; cdecl;

  {$EXTERNALSYM RSA_meth_set_finish_finish}
  RSA_meth_set_finish_finish = function(rsa: PRSA): TIdC_INT; cdecl;

  {$EXTERNALSYM RSA_meth_set_sign_sign}
  RSA_meth_set_sign_sign = function(type_: TIdC_INT; const m: PByte;
    m_length: TIdC_UINT; sigret: PByte; siglen: PIdC_UINT; const rsa: PRSA): TIdC_INT; cdecl;

  {$EXTERNALSYM RSA_meth_set_verify_verify}
  RSA_meth_set_verify_verify = function(dtype: TIdC_INT; const m: PByte;
    m_length: TIdC_UINT; const sigbuf: PByte; siglen: TIdC_UINT; const rsa: PRSA): TIdC_INT; cdecl;

  {$EXTERNALSYM RSA_meth_set_keygen_keygen}
  RSA_meth_set_keygen_keygen = function(rsa: PRSA; bits: TIdC_INT; e: PBIGNUM; cb: PBN_GENCb): TIdC_INT; cdecl;

  {$EXTERNALSYM RSA_meth_set_multi_prime_keygen_keygen}
  RSA_meth_set_multi_prime_keygen_keygen = function(rsa: PRSA; bits: TIdC_INT;
    primes: TIdC_INT; e: PBIGNUM; cb: PBN_GENCb): TIdC_INT; cdecl;

//# define EVP_PKEY_CTX_set_rsa_padding(ctx, pad) \
//        RSA_pkey_ctx_ctrl(ctx, -1, EVP_PKEY_CTRL_RSA_PADDING, pad, NULL)
//
//# define EVP_PKEY_CTX_get_rsa_padding(ctx, ppad) \
//        RSA_pkey_ctx_ctrl(ctx, -1, EVP_PKEY_CTRL_GET_RSA_PADDING, 0, ppad)
//
//# define EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, len) \
//        RSA_pkey_ctx_ctrl(ctx, (EVP_PKEY_OP_SIGN|EVP_PKEY_OP_VERIFY), \
//                          EVP_PKEY_CTRL_RSA_PSS_SALTLEN, len, NULL)

//# define EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx, len) \
//        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA_PSS, EVP_PKEY_OP_KEYGEN, \
//                          EVP_PKEY_CTRL_RSA_PSS_SALTLEN, len, NULL)
//
//# define EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, plen) \
//        RSA_pkey_ctx_ctrl(ctx, (EVP_PKEY_OP_SIGN|EVP_PKEY_OP_VERIFY), \
//                          EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN, 0, plen)
//
//# define EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) \
//        RSA_pkey_ctx_ctrl(ctx, EVP_PKEY_OP_KEYGEN, \
//                          EVP_PKEY_CTRL_RSA_KEYGEN_BITS, bits, NULL)
//
//# define EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, pubexp) \
//        RSA_pkey_ctx_ctrl(ctx, EVP_PKEY_OP_KEYGEN, \
//                          EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP, 0, pubexp)
//
//# define EVP_PKEY_CTX_set_rsa_keygen_primes(ctx, primes) \
//        RSA_pkey_ctx_ctrl(ctx, EVP_PKEY_OP_KEYGEN, \
//                          EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES, primes, NULL)
//
//# define  EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) \
//        RSA_pkey_ctx_ctrl(ctx, EVP_PKEY_OP_TYPE_SIG | EVP_PKEY_OP_TYPE_CRYPT, \
//                          EVP_PKEY_CTRL_RSA_MGF1_MD, 0, (void *)(md))
//
//# define  EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx, md) \
//        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA_PSS, EVP_PKEY_OP_KEYGEN, \
//                          EVP_PKEY_CTRL_RSA_MGF1_MD, 0, (void *)(md))
//
//# define  EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) \
//        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,  \
//                          EVP_PKEY_CTRL_RSA_OAEP_MD, 0, (void *)(md))
//
//# define  EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, pmd) \
//        RSA_pkey_ctx_ctrl(ctx, EVP_PKEY_OP_TYPE_SIG | EVP_PKEY_OP_TYPE_CRYPT, \
//                          EVP_PKEY_CTRL_GET_RSA_MGF1_MD, 0, (void *)(pmd))
//
//# define  EVP_PKEY_CTX_get_rsa_oaep_md(ctx, pmd) \
//        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,  \
//                          EVP_PKEY_CTRL_GET_RSA_OAEP_MD, 0, (void *)(pmd))
//
//# define  EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, l, llen) \
//        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,  \
//                          EVP_PKEY_CTRL_RSA_OAEP_LABEL, llen, (void *)(l))
//
//# define  EVP_PKEY_CTX_get0_rsa_oaep_label(ctx, l) \
//        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,  \
//                          EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL, 0, (void *)(l))
//
//# define  EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx, md) \
//        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA_PSS,  \
//                          EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_MD,  \
//                          0, (void *)(md))

//# define RSA_set_app_data(s,arg)         RSA_set_ex_data(s,0,arg)
//# define RSA_get_app_data(s)             RSA_get_ex_data(s,0)

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  
//  {$EXTERNALSYM RSA_padding_add_SSLv23}
//  {$EXTERNALSYM RSA_padding_check_SSLv23}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM RSA_new}
  RSA_new: function : PRSA; cdecl = nil;
  {$EXTERNALSYM RSA_new_method}
  RSA_new_method: function (engine: PENGINE): PRSA; cdecl = nil;
  {$EXTERNALSYM RSA_bits}
  RSA_bits: function (const rsa: PRSA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_size}
  RSA_size: function (const rsa: PRSA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_security_bits}
  RSA_security_bits: function (const rsa: PRSA): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM RSA_set0_key}
  RSA_set0_key: function (r: PRSA; n: PBIGNUM; e: PBIGNUM; d: PBIGNUM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_set0_factors}
  RSA_set0_factors: function (r: PRSA; p: PBIGNUM; q: PBIGNUM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_set0_crt_params}
  RSA_set0_crt_params: function (r: PRSA; dmp1: PBIGNUM; dmq1: PBIGNUM; iqmp: PBIGNUM): TIdC_INT; cdecl = nil;
  //function RSA_set0_multi_prime_params(r: PRSA; primes: array of PBIGNUM; exps: array of PBIGNUM; coeffs: array of PBIGNUM; pnum: TIdC_INT): TIdC_INT;

  {$EXTERNALSYM RSA_get0_key}
  RSA_get0_key: procedure (const r: PRSA; const n: PPBIGNUM; const e: PPBIGNUM; const d: PPBIGNUM); cdecl = nil;
  {$EXTERNALSYM RSA_get0_factors}
  RSA_get0_factors: procedure (const r: PRSA; const p: PPBIGNUM; const q: PPBIGNUM); cdecl = nil;
  {$EXTERNALSYM RSA_get_multi_prime_extra_count}
  RSA_get_multi_prime_extra_count: function (const r: PRSA): TIdC_INT; cdecl = nil;
  //function RSA_get0_multi_prime_factors(const r: PRSA; const primes: array of PBIGNUM): TIdC_INT;
  {$EXTERNALSYM RSA_get0_crt_params}
  RSA_get0_crt_params: procedure (const r: PRSA; const dmp1: PPBIGNUM; const dmq1: PPBIGNUM; const iqmp: PPBIGNUM); cdecl = nil;

  //function RSA_get0_multi_prime_crt_params(const r: PRSA; const exps: array of PBIGNUM; const coeffs: array of PBIGNUM): TIdC_INT;

  {$EXTERNALSYM RSA_get0_n}
  RSA_get0_n: function (const d: PRSA): PBIGNUM; cdecl = nil;
  {$EXTERNALSYM RSA_get0_e}
  RSA_get0_e: function (const d: PRSA): PBIGNUM; cdecl = nil;
  {$EXTERNALSYM RSA_get0_d}
  RSA_get0_d: function (const d: PRSA): PBIGNUM; cdecl = nil;
  {$EXTERNALSYM RSA_get0_p}
  RSA_get0_p: function (const d: PRSA): PBIGNUM; cdecl = nil;
  {$EXTERNALSYM RSA_get0_q}
  RSA_get0_q: function (const d: PRSA): PBIGNUM; cdecl = nil;
  {$EXTERNALSYM RSA_get0_dmp1}
  RSA_get0_dmp1: function (const r: PRSA): PBIGNUM; cdecl = nil;
  {$EXTERNALSYM RSA_get0_dmq1}
  RSA_get0_dmq1: function (const r: PRSA): PBIGNUM; cdecl = nil;
  {$EXTERNALSYM RSA_get0_iqmp}
  RSA_get0_iqmp: function (const r: PRSA): PBIGNUM; cdecl = nil;

  {$EXTERNALSYM RSA_clear_flags}
  RSA_clear_flags: procedure (r: PRSA; flags: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM RSA_test_flags}
  RSA_test_flags: function (const r: PRSA; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_set_flags}
  RSA_set_flags: procedure (r: PRSA; flags: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM RSA_get_version}
  RSA_get_version: function (r: PRSA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_get0_engine}
  RSA_get0_engine: function (const r: PRSA): PENGINE; cdecl = nil;

  (* New version *)
  {$EXTERNALSYM RSA_generate_key_ex}
  RSA_generate_key_ex: function (rsa: PRSA; bits: TIdC_INT; e: PBIGNUM; cb: PBN_GENCB): TIdC_INT; cdecl = nil;
  (* Multi-prime version *)
  {$EXTERNALSYM RSA_generate_multi_prime_key}
  RSA_generate_multi_prime_key: function (rsa: PRSA; bits: TIdC_INT; primes: TIdC_INT; e: PBIGNUM; cb: PBN_GENCB): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_X931_derive_ex}
  RSA_X931_derive_ex: function (rsa: PRSA; p1: PBIGNUM; p2: PBIGNUM; q1: PBIGNUM; q2: PBIGNUM; const Xp1: PBIGNUM; const Xp2: PBIGNUM; const Xp: PBIGNUM; const Xq1: PBIGNUM; const Xq2: PBIGNUM; const Xq: PBIGNUM; const e: PBIGNUM; cb: PBN_GENCB): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_X931_generate_key_ex}
  RSA_X931_generate_key_ex: function (rsa: PRSA; bits: TIdC_INT; const e: PBIGNUM; cb: PBN_GENCB): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM RSA_check_key}
  RSA_check_key: function (const v1: PRSA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_check_key_ex}
  RSA_check_key_ex: function (const v1: PRSA; cb: PBN_GENCB): TIdC_INT; cdecl = nil;
  (* next 4 return -1 on error *)
  {$EXTERNALSYM RSA_public_encrypt}
  RSA_public_encrypt: function (flen: TIdC_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_private_encrypt}
  RSA_private_encrypt: function (flen: TIdC_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_public_decrypt}
  RSA_public_decrypt: function (flen: TIdC_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_private_decrypt}
  RSA_private_decrypt: function (flen: TIdC_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TIdC_INT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM RSA_free}
  RSA_free: procedure (r: PRSA); cdecl = nil;
  (* "up" the RSA object's reference count *)
  {$EXTERNALSYM RSA_up_ref}
  RSA_up_ref: function (r: PRSA): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM RSA_flags}
  RSA_flags: function (const r: PRSA): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM RSA_set_default_method}
  RSA_set_default_method: procedure (const meth: PRSA_METHOD); cdecl = nil;
  {$EXTERNALSYM RSA_get_default_method}
  RSA_get_default_method: function : PRSA_METHOD; cdecl = nil;
  {$EXTERNALSYM RSA_null_method}
  RSA_null_method: function : PRSA_METHOD; cdecl = nil;
  {$EXTERNALSYM RSA_get_method}
  RSA_get_method: function (const rsa: PRSA): PRSA_METHOD; cdecl = nil;
  {$EXTERNALSYM RSA_set_method}
  RSA_set_method: function (rsa: PRSA; const meth: PRSA_METHOD): TIdC_INT; cdecl = nil;

  (* these are the actual RSA functions *)
  {$EXTERNALSYM RSA_PKCS1_OpenSSL}
  RSA_PKCS1_OpenSSL: function : PRSA_METHOD; cdecl = nil;

  {$EXTERNALSYM RSA_pkey_ctx_ctrl}
  RSA_pkey_ctx_ctrl: function (ctx: PEVP_PKEY_CTX; optype: TIdC_INT; cmd: TIdC_INT; p1: TIdC_INT; p2: Pointer): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM RSA_print}
  RSA_print: function (bp: PBIO; const r: PRSA; offset: TIdC_INT): TIdC_INT; cdecl = nil;

  (*
   * The following 2 functions sign and verify a X509_SIG ASN1 object inside
   * PKCS#1 padded RSA encryption
   *)
  {$EXTERNALSYM RSA_sign}
  RSA_sign: function (type_: TIdC_INT; const m: PByte; m_length: TIdC_UINT; sigret: PByte; siglen: PIdC_UINT; rsa: PRSA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_verify}
  RSA_verify: function (type_: TIdC_INT; const m: PByte; m_length: TIdC_UINT; const sigbuf: PByte; siglen: TIdC_UINT; rsa: PRSA): TIdC_INT; cdecl = nil;

  (*
   * The following 2 function sign and verify a ASN1_OCTET_STRING object inside
   * PKCS#1 padded RSA encryption
   *)
  {$EXTERNALSYM RSA_sign_ASN1_OCTET_STRING}
  RSA_sign_ASN1_OCTET_STRING: function (type_: TIdC_INT; const m: PByte; m_length: TIdC_UINT; sigret: PByte; siglen: PIdC_UINT; rsa: PRSA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_verify_ASN1_OCTET_STRING}
  RSA_verify_ASN1_OCTET_STRING: function (type_: TIdC_INT; const m: PByte; m_length: TIdC_UINT; sigbuf: PByte; siglen: TIdC_UINT; rsa: PRSA): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM RSA_blinding_on}
  RSA_blinding_on: function (rsa: PRSA; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_blinding_off}
  RSA_blinding_off: procedure (rsa: PRSA); cdecl = nil;
  {$EXTERNALSYM RSA_setup_blinding}
  RSA_setup_blinding: function (rsa: PRSA; ctx: PBN_CTX): PBN_BLINDING; cdecl = nil;
  {$EXTERNALSYM RSA_padding_add_PKCS1_type_1}
  RSA_padding_add_PKCS1_type_1: function (to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_padding_check_PKCS1_type_1}
  RSA_padding_check_PKCS1_type_1: function (to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_padding_add_PKCS1_type_2}
  RSA_padding_add_PKCS1_type_2: function (to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_padding_check_PKCS1_type_2}
  RSA_padding_check_PKCS1_type_2: function (to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS1_MGF1}
  PKCS1_MGF1: function (mask: PByte; len: TIdC_LONG; const seed: PByte; seedlen: TIdC_LONG; const dgst: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_padding_add_PKCS1_OAEP}
  RSA_padding_add_PKCS1_OAEP: function (to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT; const p: PByte; pl: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_padding_check_PKCS1_OAEP}
  RSA_padding_check_PKCS1_OAEP: function (to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT; rsa_len: TIdC_INT; const p: PByte; pl: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_padding_add_PKCS1_OAEP_mgf1}
  RSA_padding_add_PKCS1_OAEP_mgf1: function (to_: PByte; tlen: TIdC_INT; const from: PByte; flen: TIdC_INT; const param: PByte; plen: TIdC_INT; const md: PEVP_MD; const mgf1md: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_padding_check_PKCS1_OAEP_mgf1}
  RSA_padding_check_PKCS1_OAEP_mgf1: function (to_: PByte; tlen: TIdC_INT; const from: PByte; flen: TIdC_INT; num: TIdC_INT; const param: PByte; plen: TIdC_INT; const md: PEVP_MD; const mgf1md: PEVP_MD): TIdC_INT; cdecl = nil;
//  RSA_padding_add_SSLv23: function (to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT): TIdC_INT; cdecl = nil;  //Discontinued in TaurusTLS 3.x
//  RSA_padding_check_SSLv23: function (to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT; cdecl = nil;  //Discontinued in TaurusTLS 3.x
  {$EXTERNALSYM RSA_padding_add_none}
  RSA_padding_add_none: function (to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_padding_check_none}
  RSA_padding_check_none: function (to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_padding_add_X931}
  RSA_padding_add_X931: function (to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_padding_check_X931}
  RSA_padding_check_X931: function (to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_X931_hash_id}
  RSA_X931_hash_id: function (nid: TIdC_INT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM RSA_verify_PKCS1_PSS}
  RSA_verify_PKCS1_PSS: function (rsa: PRSA; const mHash: PByte; const Hash: PEVP_MD; const EM: PByte; sLen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_padding_add_PKCS1_PSS}
  RSA_padding_add_PKCS1_PSS: function (rsa: PRSA; EM: PByte; const mHash: PByte; const Hash: PEVP_MD; sLen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_verify_PKCS1_PSS_mgf1}
  RSA_verify_PKCS1_PSS_mgf1: function (rsa: PRSA; const mHash: PByte; const Hash: PEVP_MD; const mgf1Hash: PEVP_MD; const EM: PByte; sLen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_padding_add_PKCS1_PSS_mgf1}
  RSA_padding_add_PKCS1_PSS_mgf1: function (rsa: PRSA; EM: PByte; const mHash: PByte; const Hash: PEVP_MD; const mgf1Hash: PEVP_MD; sLen: TIdC_INT): TIdC_INT; cdecl = nil;

  //#define RSA_get_ex_new_index(l, p, newf, dupf, freef) \
  //    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_RSA, l, p, newf, dupf, freef)

  {$EXTERNALSYM RSA_set_ex_data}
  RSA_set_ex_data: function (r: PRSA; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_get_ex_data}
  RSA_get_ex_data: function (const r: PRSA; idx: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM RSAPublicKey_dup}
  RSAPublicKey_dup: function (rsa: PRSA): PRSA; cdecl = nil;
  {$EXTERNALSYM RSAPrivateKey_dup}
  RSAPrivateKey_dup: function (rsa: PRSA): PRSA; cdecl = nil;

  {$EXTERNALSYM RSA_meth_new}
  RSA_meth_new: function (const name: PIdAnsiChar; flags: TIdC_INT): PRSA_METHOD; cdecl = nil;
  {$EXTERNALSYM RSA_meth_free}
  RSA_meth_free: procedure (meth: PRSA_METHOD); cdecl = nil;
  {$EXTERNALSYM RSA_meth_dup}
  RSA_meth_dup: function (const meth: PRSA_METHOD): PRSA_METHOD; cdecl = nil;
  {$EXTERNALSYM RSA_meth_get0_name}
  RSA_meth_get0_name: function (const meth: PRSA_METHOD): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM RSA_meth_set1_name}
  RSA_meth_set1_name: function (meth: PRSA_METHOD; const name: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_meth_get_flags}
  RSA_meth_get_flags: function (const meth: PRSA_METHOD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_meth_set_flags}
  RSA_meth_set_flags: function (meth: PRSA_METHOD; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM RSA_meth_get0_app_data}
  RSA_meth_get0_app_data: function (const meth: PRSA_METHOD): Pointer; cdecl = nil;
  {$EXTERNALSYM RSA_meth_set0_app_data}
  RSA_meth_set0_app_data: function (meth: PRSA_METHOD; app_data: Pointer): TIdC_INT; cdecl = nil;

  //int (*RSA_meth_get_pub_enc(const RSA_METHOD *meth))
  //    (int flen, const unsigned char *from,
  //     unsigned char *to_, RSA *rsa, int padding);
  //int RSA_meth_set_pub_enc(RSA_METHOD *rsa,
  //                         int (*pub_enc) (int flen, const unsigned char *from,
  //                                         unsigned char *to_, RSA *rsa,
  //                                         int padding));
  //int (*RSA_meth_get_pub_dec(const RSA_METHOD *meth))
  //    (int flen, const unsigned char *from,
  //     unsigned char *to_, RSA *rsa, int padding);
  //int RSA_meth_set_pub_dec(RSA_METHOD *rsa,
  //                         int (*pub_dec) (int flen, const unsigned char *from,
  //                                         unsigned char *to_, RSA *rsa,
  //                                         int padding));
  //int (*RSA_meth_get_priv_enc(const RSA_METHOD *meth))
  //    (int flen, const unsigned char *from,
  //     unsigned char *to_, RSA *rsa, int padding);
  //int RSA_meth_set_priv_enc(RSA_METHOD *rsa,
  //                          int (*priv_enc) (int flen, const unsigned char *from,
  //                                           unsigned char *to_, RSA *rsa,
  //                                           int padding));
  //int (*RSA_meth_get_priv_dec(const RSA_METHOD *meth))
  //    (int flen, const unsigned char *from,
  //     unsigned char *to_, RSA *rsa, int padding);
  {$EXTERNALSYM RSA_meth_set_priv_dec}
  RSA_meth_set_priv_dec: function (rsa: PRSA_METHOD; priv_dec: RSA_meth_set_priv_dec_priv_dec): TIdC_INT; cdecl = nil;

  //int (*RSA_meth_get_mod_exp(const RSA_METHOD *meth))
  //    (BIGNUM *r0, const BIGNUM *i, RSA *rsa, BN_CTX *ctx);
  {$EXTERNALSYM RSA_meth_set_mod_exp}
  RSA_meth_set_mod_exp: function (rsa: PRSA_METHOD; mod_exp: RSA_meth_set_mod_exp_mod_exp): TIdC_INT; cdecl = nil;
  //int (*RSA_meth_get_bn_mod_exp(const RSA_METHOD *meth))
  //    (BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
  //     const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
  {$EXTERNALSYM RSA_meth_set_bn_mod_exp}
  RSA_meth_set_bn_mod_exp: function (rsa: PRSA_METHOD; bn_mod_exp: RSA_meth_set_bn_mod_exp_bn_mod_exp): TIdC_INT; cdecl = nil;
  //int (*RSA_meth_get_init(const RSA_METHOD *meth)) (RSA *rsa);
  {$EXTERNALSYM RSA_meth_set_init}
  RSA_meth_set_init: function (rsa: PRSA_METHOD; init: RSA_meth_set_init_init): TIdC_INT; cdecl = nil;
  //int (*RSA_meth_get_finish(const RSA_METHOD *meth)) (RSA *rsa);
  {$EXTERNALSYM RSA_meth_set_finish}
  RSA_meth_set_finish: function (rsa: PRSA_METHOD; finish: RSA_meth_set_finish_finish): TIdC_INT; cdecl = nil;
  //int (*RSA_meth_get_sign(const RSA_METHOD *meth))
  //    (int type_,
  //     const unsigned char *m, unsigned int m_length,
  //     unsigned char *sigret, unsigned int *siglen,
  //     const RSA *rsa);
  {$EXTERNALSYM RSA_meth_set_sign}
  RSA_meth_set_sign: function (rsa: PRSA_METHOD; sign: RSA_meth_set_sign_sign): TIdC_INT; cdecl = nil;
  //int (*RSA_meth_get_verify(const RSA_METHOD *meth))
  //    (int dtype, const unsigned char *m,
  //     unsigned int m_length, const unsigned char *sigbuf,
  //     unsigned int siglen, const RSA *rsa);
  {$EXTERNALSYM RSA_meth_set_verify}
  RSA_meth_set_verify: function (rsa: PRSA_METHOD; verify: RSA_meth_set_verify_verify): TIdC_INT; cdecl = nil;
  //int (*RSA_meth_get_keygen(const RSA_METHOD *meth))
  //    (RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
  {$EXTERNALSYM RSA_meth_set_keygen}
  RSA_meth_set_keygen: function (rsa: PRSA_METHOD; keygen: RSA_meth_set_keygen_keygen): TIdC_INT; cdecl = nil;
  //int (*RSA_meth_get_multi_prime_keygen(const RSA_METHOD *meth))
  //    (RSA *rsa, int bits, int primes, BIGNUM *e, BN_GENCB *cb);
  {$EXTERNALSYM RSA_meth_set_multi_prime_keygen}
  RSA_meth_set_multi_prime_keygen: function (meth: PRSA_METHOD; keygen: RSA_meth_set_multi_prime_keygen_keygen): TIdC_INT; cdecl = nil;

{$ELSE}
  {$EXTERNALSYM RSA_new}
  function RSA_new: PRSA cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_new_method}
  function RSA_new_method(engine: PENGINE): PRSA cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_bits}
  function RSA_bits(const rsa: PRSA): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_size}
  function RSA_size(const rsa: PRSA): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_security_bits}
  function RSA_security_bits(const rsa: PRSA): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM RSA_set0_key}
  function RSA_set0_key(r: PRSA; n: PBIGNUM; e: PBIGNUM; d: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_set0_factors}
  function RSA_set0_factors(r: PRSA; p: PBIGNUM; q: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_set0_crt_params}
  function RSA_set0_crt_params(r: PRSA; dmp1: PBIGNUM; dmq1: PBIGNUM; iqmp: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  //function RSA_set0_multi_prime_params(r: PRSA; primes: array of PBIGNUM; exps: array of PBIGNUM; coeffs: array of PBIGNUM; pnum: TIdC_INT): TIdC_INT;

  {$EXTERNALSYM RSA_get0_key}
  procedure RSA_get0_key(const r: PRSA; const n: PPBIGNUM; const e: PPBIGNUM; const d: PPBIGNUM) cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_get0_factors}
  procedure RSA_get0_factors(const r: PRSA; const p: PPBIGNUM; const q: PPBIGNUM) cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_get_multi_prime_extra_count}
  function RSA_get_multi_prime_extra_count(const r: PRSA): TIdC_INT cdecl; external CLibCrypto;
  //function RSA_get0_multi_prime_factors(const r: PRSA; const primes: array of PBIGNUM): TIdC_INT;
  {$EXTERNALSYM RSA_get0_crt_params}
  procedure RSA_get0_crt_params(const r: PRSA; const dmp1: PPBIGNUM; const dmq1: PPBIGNUM; const iqmp: PPBIGNUM) cdecl; external CLibCrypto;

  //function RSA_get0_multi_prime_crt_params(const r: PRSA; const exps: array of PBIGNUM; const coeffs: array of PBIGNUM): TIdC_INT;

  {$EXTERNALSYM RSA_get0_n}
  function RSA_get0_n(const d: PRSA): PBIGNUM cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_get0_e}
  function RSA_get0_e(const d: PRSA): PBIGNUM cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_get0_d}
  function RSA_get0_d(const d: PRSA): PBIGNUM cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_get0_p}
  function RSA_get0_p(const d: PRSA): PBIGNUM cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_get0_q}
  function RSA_get0_q(const d: PRSA): PBIGNUM cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_get0_dmp1}
  function RSA_get0_dmp1(const r: PRSA): PBIGNUM cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_get0_dmq1}
  function RSA_get0_dmq1(const r: PRSA): PBIGNUM cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_get0_iqmp}
  function RSA_get0_iqmp(const r: PRSA): PBIGNUM cdecl; external CLibCrypto;

  {$EXTERNALSYM RSA_clear_flags}
  procedure RSA_clear_flags(r: PRSA; flags: TIdC_INT) cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_test_flags}
  function RSA_test_flags(const r: PRSA; flags: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_set_flags}
  procedure RSA_set_flags(r: PRSA; flags: TIdC_INT) cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_get_version}
  function RSA_get_version(r: PRSA): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_get0_engine}
  function RSA_get0_engine(const r: PRSA): PENGINE cdecl; external CLibCrypto;

  (* New version *)
  {$EXTERNALSYM RSA_generate_key_ex}
  function RSA_generate_key_ex(rsa: PRSA; bits: TIdC_INT; e: PBIGNUM; cb: PBN_GENCB): TIdC_INT cdecl; external CLibCrypto;
  (* Multi-prime version *)
  {$EXTERNALSYM RSA_generate_multi_prime_key}
  function RSA_generate_multi_prime_key(rsa: PRSA; bits: TIdC_INT; primes: TIdC_INT; e: PBIGNUM; cb: PBN_GENCB): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_X931_derive_ex}
  function RSA_X931_derive_ex(rsa: PRSA; p1: PBIGNUM; p2: PBIGNUM; q1: PBIGNUM; q2: PBIGNUM; const Xp1: PBIGNUM; const Xp2: PBIGNUM; const Xp: PBIGNUM; const Xq1: PBIGNUM; const Xq2: PBIGNUM; const Xq: PBIGNUM; const e: PBIGNUM; cb: PBN_GENCB): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_X931_generate_key_ex}
  function RSA_X931_generate_key_ex(rsa: PRSA; bits: TIdC_INT; const e: PBIGNUM; cb: PBN_GENCB): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM RSA_check_key}
  function RSA_check_key(const v1: PRSA): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_check_key_ex}
  function RSA_check_key_ex(const v1: PRSA; cb: PBN_GENCB): TIdC_INT cdecl; external CLibCrypto;
  (* next 4 return -1 on error *)
  {$EXTERNALSYM RSA_public_encrypt}
  function RSA_public_encrypt(flen: TIdC_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_private_encrypt}
  function RSA_private_encrypt(flen: TIdC_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_public_decrypt}
  function RSA_public_decrypt(flen: TIdC_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_private_decrypt}
  function RSA_private_decrypt(flen: TIdC_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM RSA_free}
  procedure RSA_free(r: PRSA) cdecl; external CLibCrypto;
  (* "up" the RSA object's reference count *)
  {$EXTERNALSYM RSA_up_ref}
  function RSA_up_ref(r: PRSA): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM RSA_flags}
  function RSA_flags(const r: PRSA): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM RSA_set_default_method}
  procedure RSA_set_default_method(const meth: PRSA_METHOD) cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_get_default_method}
  function RSA_get_default_method: PRSA_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_null_method}
  function RSA_null_method: PRSA_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_get_method}
  function RSA_get_method(const rsa: PRSA): PRSA_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_set_method}
  function RSA_set_method(rsa: PRSA; const meth: PRSA_METHOD): TIdC_INT cdecl; external CLibCrypto;

  (* these are the actual RSA functions *)
  {$EXTERNALSYM RSA_PKCS1_OpenSSL}
  function RSA_PKCS1_OpenSSL: PRSA_METHOD cdecl; external CLibCrypto;

  {$EXTERNALSYM RSA_pkey_ctx_ctrl}
  function RSA_pkey_ctx_ctrl(ctx: PEVP_PKEY_CTX; optype: TIdC_INT; cmd: TIdC_INT; p1: TIdC_INT; p2: Pointer): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM RSA_print}
  function RSA_print(bp: PBIO; const r: PRSA; offset: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  (*
   * The following 2 functions sign and verify a X509_SIG ASN1 object inside
   * PKCS#1 padded RSA encryption
   *)
  {$EXTERNALSYM RSA_sign}
  function RSA_sign(type_: TIdC_INT; const m: PByte; m_length: TIdC_UINT; sigret: PByte; siglen: PIdC_UINT; rsa: PRSA): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_verify}
  function RSA_verify(type_: TIdC_INT; const m: PByte; m_length: TIdC_UINT; const sigbuf: PByte; siglen: TIdC_UINT; rsa: PRSA): TIdC_INT cdecl; external CLibCrypto;

  (*
   * The following 2 function sign and verify a ASN1_OCTET_STRING object inside
   * PKCS#1 padded RSA encryption
   *)
  {$EXTERNALSYM RSA_sign_ASN1_OCTET_STRING}
  function RSA_sign_ASN1_OCTET_STRING(type_: TIdC_INT; const m: PByte; m_length: TIdC_UINT; sigret: PByte; siglen: PIdC_UINT; rsa: PRSA): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_verify_ASN1_OCTET_STRING}
  function RSA_verify_ASN1_OCTET_STRING(type_: TIdC_INT; const m: PByte; m_length: TIdC_UINT; sigbuf: PByte; siglen: TIdC_UINT; rsa: PRSA): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM RSA_blinding_on}
  function RSA_blinding_on(rsa: PRSA; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_blinding_off}
  procedure RSA_blinding_off(rsa: PRSA) cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_setup_blinding}
  function RSA_setup_blinding(rsa: PRSA; ctx: PBN_CTX): PBN_BLINDING cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_padding_add_PKCS1_type_1}
  function RSA_padding_add_PKCS1_type_1(to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_padding_check_PKCS1_type_1}
  function RSA_padding_check_PKCS1_type_1(to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_padding_add_PKCS1_type_2}
  function RSA_padding_add_PKCS1_type_2(to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_padding_check_PKCS1_type_2}
  function RSA_padding_check_PKCS1_type_2(to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS1_MGF1}
  function PKCS1_MGF1(mask: PByte; len: TIdC_LONG; const seed: PByte; seedlen: TIdC_LONG; const dgst: PEVP_MD): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_padding_add_PKCS1_OAEP}
  function RSA_padding_add_PKCS1_OAEP(to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT; const p: PByte; pl: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_padding_check_PKCS1_OAEP}
  function RSA_padding_check_PKCS1_OAEP(to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT; rsa_len: TIdC_INT; const p: PByte; pl: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_padding_add_PKCS1_OAEP_mgf1}
  function RSA_padding_add_PKCS1_OAEP_mgf1(to_: PByte; tlen: TIdC_INT; const from: PByte; flen: TIdC_INT; const param: PByte; plen: TIdC_INT; const md: PEVP_MD; const mgf1md: PEVP_MD): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_padding_check_PKCS1_OAEP_mgf1}
  function RSA_padding_check_PKCS1_OAEP_mgf1(to_: PByte; tlen: TIdC_INT; const from: PByte; flen: TIdC_INT; num: TIdC_INT; const param: PByte; plen: TIdC_INT; const md: PEVP_MD; const mgf1md: PEVP_MD): TIdC_INT cdecl; external CLibCrypto;
//  function RSA_padding_add_SSLv23(to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
//  function RSA_padding_check_SSLv23(to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_padding_add_none}
  function RSA_padding_add_none(to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_padding_check_none}
  function RSA_padding_check_none(to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_padding_add_X931}
  function RSA_padding_add_X931(to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_padding_check_X931}
  function RSA_padding_check_X931(to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_X931_hash_id}
  function RSA_X931_hash_id(nid: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM RSA_verify_PKCS1_PSS}
  function RSA_verify_PKCS1_PSS(rsa: PRSA; const mHash: PByte; const Hash: PEVP_MD; const EM: PByte; sLen: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_padding_add_PKCS1_PSS}
  function RSA_padding_add_PKCS1_PSS(rsa: PRSA; EM: PByte; const mHash: PByte; const Hash: PEVP_MD; sLen: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_verify_PKCS1_PSS_mgf1}
  function RSA_verify_PKCS1_PSS_mgf1(rsa: PRSA; const mHash: PByte; const Hash: PEVP_MD; const mgf1Hash: PEVP_MD; const EM: PByte; sLen: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_padding_add_PKCS1_PSS_mgf1}
  function RSA_padding_add_PKCS1_PSS_mgf1(rsa: PRSA; EM: PByte; const mHash: PByte; const Hash: PEVP_MD; const mgf1Hash: PEVP_MD; sLen: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  //#define RSA_get_ex_new_index(l, p, newf, dupf, freef) \
  //    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_RSA, l, p, newf, dupf, freef)

  {$EXTERNALSYM RSA_set_ex_data}
  function RSA_set_ex_data(r: PRSA; idx: TIdC_INT; arg: Pointer): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_get_ex_data}
  function RSA_get_ex_data(const r: PRSA; idx: TIdC_INT): Pointer cdecl; external CLibCrypto;
  {$EXTERNALSYM RSAPublicKey_dup}
  function RSAPublicKey_dup(rsa: PRSA): PRSA cdecl; external CLibCrypto;
  {$EXTERNALSYM RSAPrivateKey_dup}
  function RSAPrivateKey_dup(rsa: PRSA): PRSA cdecl; external CLibCrypto;

  {$EXTERNALSYM RSA_meth_new}
  function RSA_meth_new(const name: PIdAnsiChar; flags: TIdC_INT): PRSA_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_meth_free}
  procedure RSA_meth_free(meth: PRSA_METHOD) cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_meth_dup}
  function RSA_meth_dup(const meth: PRSA_METHOD): PRSA_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_meth_get0_name}
  function RSA_meth_get0_name(const meth: PRSA_METHOD): PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_meth_set1_name}
  function RSA_meth_set1_name(meth: PRSA_METHOD; const name: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_meth_get_flags}
  function RSA_meth_get_flags(const meth: PRSA_METHOD): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_meth_set_flags}
  function RSA_meth_set_flags(meth: PRSA_METHOD; flags: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_meth_get0_app_data}
  function RSA_meth_get0_app_data(const meth: PRSA_METHOD): Pointer cdecl; external CLibCrypto;
  {$EXTERNALSYM RSA_meth_set0_app_data}
  function RSA_meth_set0_app_data(meth: PRSA_METHOD; app_data: Pointer): TIdC_INT cdecl; external CLibCrypto;

  //int (*RSA_meth_get_pub_enc(const RSA_METHOD *meth))
  //    (int flen, const unsigned char *from,
  //     unsigned char *to_, RSA *rsa, int padding);
  //int RSA_meth_set_pub_enc(RSA_METHOD *rsa,
  //                         int (*pub_enc) (int flen, const unsigned char *from,
  //                                         unsigned char *to_, RSA *rsa,
  //                                         int padding));
  //int (*RSA_meth_get_pub_dec(const RSA_METHOD *meth))
  //    (int flen, const unsigned char *from,
  //     unsigned char *to_, RSA *rsa, int padding);
  //int RSA_meth_set_pub_dec(RSA_METHOD *rsa,
  //                         int (*pub_dec) (int flen, const unsigned char *from,
  //                                         unsigned char *to_, RSA *rsa,
  //                                         int padding));
  //int (*RSA_meth_get_priv_enc(const RSA_METHOD *meth))
  //    (int flen, const unsigned char *from,
  //     unsigned char *to_, RSA *rsa, int padding);
  //int RSA_meth_set_priv_enc(RSA_METHOD *rsa,
  //                          int (*priv_enc) (int flen, const unsigned char *from,
  //                                           unsigned char *to_, RSA *rsa,
  //                                           int padding));
  //int (*RSA_meth_get_priv_dec(const RSA_METHOD *meth))
  //    (int flen, const unsigned char *from,
  //     unsigned char *to_, RSA *rsa, int padding);
  {$EXTERNALSYM RSA_meth_set_priv_dec}
  function RSA_meth_set_priv_dec(rsa: PRSA_METHOD; priv_dec: RSA_meth_set_priv_dec_priv_dec): TIdC_INT cdecl; external CLibCrypto;

  //int (*RSA_meth_get_mod_exp(const RSA_METHOD *meth))
  //    (BIGNUM *r0, const BIGNUM *i, RSA *rsa, BN_CTX *ctx);
  {$EXTERNALSYM RSA_meth_set_mod_exp}
  function RSA_meth_set_mod_exp(rsa: PRSA_METHOD; mod_exp: RSA_meth_set_mod_exp_mod_exp): TIdC_INT cdecl; external CLibCrypto;
  //int (*RSA_meth_get_bn_mod_exp(const RSA_METHOD *meth))
  //    (BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
  //     const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
  {$EXTERNALSYM RSA_meth_set_bn_mod_exp}
  function RSA_meth_set_bn_mod_exp(rsa: PRSA_METHOD; bn_mod_exp: RSA_meth_set_bn_mod_exp_bn_mod_exp): TIdC_INT cdecl; external CLibCrypto;
  //int (*RSA_meth_get_init(const RSA_METHOD *meth)) (RSA *rsa);
  {$EXTERNALSYM RSA_meth_set_init}
  function RSA_meth_set_init(rsa: PRSA_METHOD; init: RSA_meth_set_init_init): TIdC_INT cdecl; external CLibCrypto;
  //int (*RSA_meth_get_finish(const RSA_METHOD *meth)) (RSA *rsa);
  {$EXTERNALSYM RSA_meth_set_finish}
  function RSA_meth_set_finish(rsa: PRSA_METHOD; finish: RSA_meth_set_finish_finish): TIdC_INT cdecl; external CLibCrypto;
  //int (*RSA_meth_get_sign(const RSA_METHOD *meth))
  //    (int type_,
  //     const unsigned char *m, unsigned int m_length,
  //     unsigned char *sigret, unsigned int *siglen,
  //     const RSA *rsa);
  {$EXTERNALSYM RSA_meth_set_sign}
  function RSA_meth_set_sign(rsa: PRSA_METHOD; sign: RSA_meth_set_sign_sign): TIdC_INT cdecl; external CLibCrypto;
  //int (*RSA_meth_get_verify(const RSA_METHOD *meth))
  //    (int dtype, const unsigned char *m,
  //     unsigned int m_length, const unsigned char *sigbuf,
  //     unsigned int siglen, const RSA *rsa);
  {$EXTERNALSYM RSA_meth_set_verify}
  function RSA_meth_set_verify(rsa: PRSA_METHOD; verify: RSA_meth_set_verify_verify): TIdC_INT cdecl; external CLibCrypto;
  //int (*RSA_meth_get_keygen(const RSA_METHOD *meth))
  //    (RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
  {$EXTERNALSYM RSA_meth_set_keygen}
  function RSA_meth_set_keygen(rsa: PRSA_METHOD; keygen: RSA_meth_set_keygen_keygen): TIdC_INT cdecl; external CLibCrypto;
  //int (*RSA_meth_get_multi_prime_keygen(const RSA_METHOD *meth))
  //    (RSA *rsa, int bits, int primes, BIGNUM *e, BN_GENCB *cb);
  {$EXTERNALSYM RSA_meth_set_multi_prime_keygen}
  function RSA_meth_set_multi_prime_keygen(meth: PRSA_METHOD; keygen: RSA_meth_set_multi_prime_keygen_keygen): TIdC_INT cdecl; external CLibCrypto;

{$ENDIF}
  {$EXTERNALSYM RSA_get_ex_new_index}
function RSA_get_ex_new_index(l : TIdC_LONG; p : PRSA;
    newf : CRYPTO_EX_new; dupf : CRYPTO_EX_dup; freef : CRYPTO_EX_FREE) : TIdC_INT;

implementation

  uses
    classes, 
    TaurusTLSExceptionHandlers
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    ,TaurusTLSLoader
  {$ENDIF};

  //#define RSA_get_ex_new_index(l, p, newf, dupf, freef) \
  //    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_RSA, l, p, newf, dupf, freef)
function RSA_get_ex_new_index(l : TIdC_LONG; p : PRSA;
    newf : CRYPTO_EX_new; dupf : CRYPTO_EX_dup; freef : CRYPTO_EX_FREE) : TIdC_INT;
{$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_RSA, l, p, newf, dupf, freef);
end;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
const
  RSA_new_procname = 'RSA_new';
  RSA_new_method_procname = 'RSA_new_method';
  RSA_bits_procname = 'RSA_bits';
  RSA_size_procname = 'RSA_size';
  RSA_security_bits_procname = 'RSA_security_bits';

  RSA_set0_key_procname = 'RSA_set0_key';
  RSA_set0_factors_procname = 'RSA_set0_factors';
  RSA_set0_crt_params_procname = 'RSA_set0_crt_params';
  //function RSA_set0_multi_prime_params(r: PRSA; primes: array of PBIGNUM; exps: array of PBIGNUM; coeffs: array of PBIGNUM; pnum: TIdC_INT): TIdC_INT;

  RSA_get0_key_procname = 'RSA_get0_key';
  RSA_get0_factors_procname = 'RSA_get0_factors';
  RSA_get_multi_prime_extra_count_procname = 'RSA_get_multi_prime_extra_count';
  //function RSA_get0_multi_prime_factors(const r: PRSA; const primes: array of PBIGNUM): TIdC_INT;
  RSA_get0_crt_params_procname = 'RSA_get0_crt_params';

  //function RSA_get0_multi_prime_crt_params(const r: PRSA; const exps: array of PBIGNUM; const coeffs: array of PBIGNUM): TIdC_INT;

  RSA_get0_n_procname = 'RSA_get0_n';
  RSA_get0_e_procname = 'RSA_get0_e';
  RSA_get0_d_procname = 'RSA_get0_d';
  RSA_get0_p_procname = 'RSA_get0_p';
  RSA_get0_q_procname = 'RSA_get0_q';
  RSA_get0_dmp1_procname = 'RSA_get0_dmp1';
  RSA_get0_dmq1_procname = 'RSA_get0_dmq1';
  RSA_get0_iqmp_procname = 'RSA_get0_iqmp';

  RSA_clear_flags_procname = 'RSA_clear_flags';
  RSA_test_flags_procname = 'RSA_test_flags';
  RSA_set_flags_procname = 'RSA_set_flags';
  RSA_get_version_procname = 'RSA_get_version';
  RSA_get0_engine_procname = 'RSA_get0_engine';

  (* New version *)
  RSA_generate_key_ex_procname = 'RSA_generate_key_ex';
  (* Multi-prime version *)
  RSA_generate_multi_prime_key_procname = 'RSA_generate_multi_prime_key';
  RSA_X931_derive_ex_procname = 'RSA_X931_derive_ex';
  RSA_X931_generate_key_ex_procname = 'RSA_X931_generate_key_ex';

  RSA_check_key_procname = 'RSA_check_key';
  RSA_check_key_ex_procname = 'RSA_check_key_ex';
  (* next 4 return -1 on error *)
  RSA_public_encrypt_procname = 'RSA_public_encrypt';
  RSA_private_encrypt_procname = 'RSA_private_encrypt';
  RSA_public_decrypt_procname = 'RSA_public_decrypt';
  RSA_private_decrypt_procname = 'RSA_private_decrypt';

  RSA_free_procname = 'RSA_free';
  (* "up" the RSA object's reference count *)
  RSA_up_ref_procname = 'RSA_up_ref';

  RSA_flags_procname = 'RSA_flags';

  RSA_set_default_method_procname = 'RSA_set_default_method';
  RSA_get_default_method_procname = 'RSA_get_default_method';
  RSA_null_method_procname = 'RSA_null_method';
  RSA_get_method_procname = 'RSA_get_method';
  RSA_set_method_procname = 'RSA_set_method';

  (* these are the actual RSA functions *)
  RSA_PKCS1_OpenSSL_procname = 'RSA_PKCS1_OpenSSL';

  RSA_pkey_ctx_ctrl_procname = 'RSA_pkey_ctx_ctrl';

  RSA_print_procname = 'RSA_print';

  (*
   * The following 2 functions sign and verify a X509_SIG ASN1 object inside
   * PKCS#1 padded RSA encryption
   *)
  RSA_sign_procname = 'RSA_sign';
  RSA_verify_procname = 'RSA_verify';

  (*
   * The following 2 function sign and verify a ASN1_OCTET_STRING object inside
   * PKCS#1 padded RSA encryption
   *)
  RSA_sign_ASN1_OCTET_STRING_procname = 'RSA_sign_ASN1_OCTET_STRING';
  RSA_verify_ASN1_OCTET_STRING_procname = 'RSA_verify_ASN1_OCTET_STRING';

  RSA_blinding_on_procname = 'RSA_blinding_on';
  RSA_blinding_off_procname = 'RSA_blinding_off';
  RSA_setup_blinding_procname = 'RSA_setup_blinding';
  RSA_padding_add_PKCS1_type_1_procname = 'RSA_padding_add_PKCS1_type_1';
  RSA_padding_check_PKCS1_type_1_procname = 'RSA_padding_check_PKCS1_type_1';
  RSA_padding_add_PKCS1_type_2_procname = 'RSA_padding_add_PKCS1_type_2';
  RSA_padding_check_PKCS1_type_2_procname = 'RSA_padding_check_PKCS1_type_2';
  PKCS1_MGF1_procname = 'PKCS1_MGF1';
  RSA_padding_add_PKCS1_OAEP_procname = 'RSA_padding_add_PKCS1_OAEP';
  RSA_padding_check_PKCS1_OAEP_procname = 'RSA_padding_check_PKCS1_OAEP';
  RSA_padding_add_PKCS1_OAEP_mgf1_procname = 'RSA_padding_add_PKCS1_OAEP_mgf1';
  RSA_padding_check_PKCS1_OAEP_mgf1_procname = 'RSA_padding_check_PKCS1_OAEP_mgf1';
//  RSA_padding_add_SSLv23_procname = 'RSA_padding_add_SSLv23';
//  RSA_padding_check_SSLv23_procname = 'RSA_padding_check_SSLv23';
  RSA_padding_add_none_procname = 'RSA_padding_add_none';
  RSA_padding_check_none_procname = 'RSA_padding_check_none';
  RSA_padding_add_X931_procname = 'RSA_padding_add_X931';
  RSA_padding_check_X931_procname = 'RSA_padding_check_X931';
  RSA_X931_hash_id_procname = 'RSA_X931_hash_id';

  RSA_verify_PKCS1_PSS_procname = 'RSA_verify_PKCS1_PSS';
  RSA_padding_add_PKCS1_PSS_procname = 'RSA_padding_add_PKCS1_PSS';
  RSA_verify_PKCS1_PSS_mgf1_procname = 'RSA_verify_PKCS1_PSS_mgf1';
  RSA_padding_add_PKCS1_PSS_mgf1_procname = 'RSA_padding_add_PKCS1_PSS_mgf1';

  //#define RSA_get_ex_new_index(l, p, newf, dupf, freef) \
  //    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_RSA, l, p, newf, dupf, freef)

  RSA_set_ex_data_procname = 'RSA_set_ex_data';
  RSA_get_ex_data_procname = 'RSA_get_ex_data';
  RSAPublicKey_dup_procname = 'RSAPublicKey_dup';
  RSAPrivateKey_dup_procname = 'RSAPrivateKey_dup';

  RSA_meth_new_procname = 'RSA_meth_new';
  RSA_meth_free_procname = 'RSA_meth_free';
  RSA_meth_dup_procname = 'RSA_meth_dup';
  RSA_meth_get0_name_procname = 'RSA_meth_get0_name';
  RSA_meth_set1_name_procname = 'RSA_meth_set1_name';
  RSA_meth_get_flags_procname = 'RSA_meth_get_flags';
  RSA_meth_set_flags_procname = 'RSA_meth_set_flags';
  RSA_meth_get0_app_data_procname = 'RSA_meth_get0_app_data';
  RSA_meth_set0_app_data_procname = 'RSA_meth_set0_app_data';

  //int (*RSA_meth_get_pub_enc(const RSA_METHOD *meth))
  //    (int flen, const unsigned char *from,
  //     unsigned char *to_, RSA *rsa, int padding);
  //int RSA_meth_set_pub_enc(RSA_METHOD *rsa,
  //                         int (*pub_enc) (int flen, const unsigned char *from,
  //                                         unsigned char *to_, RSA *rsa,
  //                                         int padding));
  //int (*RSA_meth_get_pub_dec(const RSA_METHOD *meth))
  //    (int flen, const unsigned char *from,
  //     unsigned char *to_, RSA *rsa, int padding);
  //int RSA_meth_set_pub_dec(RSA_METHOD *rsa,
  //                         int (*pub_dec) (int flen, const unsigned char *from,
  //                                         unsigned char *to_, RSA *rsa,
  //                                         int padding));
  //int (*RSA_meth_get_priv_enc(const RSA_METHOD *meth))
  //    (int flen, const unsigned char *from,
  //     unsigned char *to_, RSA *rsa, int padding);
  //int RSA_meth_set_priv_enc(RSA_METHOD *rsa,
  //                          int (*priv_enc) (int flen, const unsigned char *from,
  //                                           unsigned char *to_, RSA *rsa,
  //                                           int padding));
  //int (*RSA_meth_get_priv_dec(const RSA_METHOD *meth))
  //    (int flen, const unsigned char *from,
  //     unsigned char *to_, RSA *rsa, int padding);
  RSA_meth_set_priv_dec_procname = 'RSA_meth_set_priv_dec';

  //int (*RSA_meth_get_mod_exp(const RSA_METHOD *meth))
  //    (BIGNUM *r0, const BIGNUM *i, RSA *rsa, BN_CTX *ctx);
  RSA_meth_set_mod_exp_procname = 'RSA_meth_set_mod_exp';
  //int (*RSA_meth_get_bn_mod_exp(const RSA_METHOD *meth))
  //    (BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
  //     const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
  RSA_meth_set_bn_mod_exp_procname = 'RSA_meth_set_bn_mod_exp';
  //int (*RSA_meth_get_init(const RSA_METHOD *meth)) (RSA *rsa);
  RSA_meth_set_init_procname = 'RSA_meth_set_init';
  //int (*RSA_meth_get_finish(const RSA_METHOD *meth)) (RSA *rsa);
  RSA_meth_set_finish_procname = 'RSA_meth_set_finish';
  //int (*RSA_meth_get_sign(const RSA_METHOD *meth))
  //    (int type_,
  //     const unsigned char *m, unsigned int m_length,
  //     unsigned char *sigret, unsigned int *siglen,
  //     const RSA *rsa);
  RSA_meth_set_sign_procname = 'RSA_meth_set_sign';
  //int (*RSA_meth_get_verify(const RSA_METHOD *meth))
  //    (int dtype, const unsigned char *m,
  //     unsigned int m_length, const unsigned char *sigbuf,
  //     unsigned int siglen, const RSA *rsa);
  RSA_meth_set_verify_procname = 'RSA_meth_set_verify';
  //int (*RSA_meth_get_keygen(const RSA_METHOD *meth))
  //    (RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
  RSA_meth_set_keygen_procname = 'RSA_meth_set_keygen';
  //int (*RSA_meth_get_multi_prime_keygen(const RSA_METHOD *meth))
  //    (RSA *rsa, int bits, int primes, BIGNUM *e, BN_GENCB *cb);
  RSA_meth_set_multi_prime_keygen_procname = 'RSA_meth_set_multi_prime_keygen';

  RSA_get0_engine_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 

function  ERR_RSA_new: PRSA; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_new_procname);
end;


function  ERR_RSA_new_method(engine: PENGINE): PRSA;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_new_method_procname);
end;


function  ERR_RSA_bits(const rsa: PRSA): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_bits_procname);
end;


function  ERR_RSA_size(const rsa: PRSA): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_size_procname);
end;


function  ERR_RSA_security_bits(const rsa: PRSA): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_security_bits_procname);
end;



function  ERR_RSA_set0_key(r: PRSA; n: PBIGNUM; e: PBIGNUM; d: PBIGNUM): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_set0_key_procname);
end;


function  ERR_RSA_set0_factors(r: PRSA; p: PBIGNUM; q: PBIGNUM): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_set0_factors_procname);
end;


function  ERR_RSA_set0_crt_params(r: PRSA; dmp1: PBIGNUM; dmq1: PBIGNUM; iqmp: PBIGNUM): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_set0_crt_params_procname);
end;


  //function RSA_set0_multi_prime_params(r: PRSA; primes: array of PBIGNUM; exps: array of PBIGNUM; coeffs: array of PBIGNUM; pnum: TIdC_INT): TIdC_INT;

procedure  ERR_RSA_get0_key(const r: PRSA; const n: PPBIGNUM; const e: PPBIGNUM; const d: PPBIGNUM);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_key_procname);
end;


procedure  ERR_RSA_get0_factors(const r: PRSA; const p: PPBIGNUM; const q: PPBIGNUM);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_factors_procname);
end;


function  ERR_RSA_get_multi_prime_extra_count(const r: PRSA): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get_multi_prime_extra_count_procname);
end;


  //function RSA_get0_multi_prime_factors(const r: PRSA; const primes: array of PBIGNUM): TIdC_INT;
procedure  ERR_RSA_get0_crt_params(const r: PRSA; const dmp1: PPBIGNUM; const dmq1: PPBIGNUM; const iqmp: PPBIGNUM);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_crt_params_procname);
end;



  //function RSA_get0_multi_prime_crt_params(const r: PRSA; const exps: array of PBIGNUM; const coeffs: array of PBIGNUM): TIdC_INT;

function  ERR_RSA_get0_n(const d: PRSA): PBIGNUM;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_n_procname);
end;


function  ERR_RSA_get0_e(const d: PRSA): PBIGNUM;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_e_procname);
end;


function  ERR_RSA_get0_d(const d: PRSA): PBIGNUM;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_d_procname);
end;


function  ERR_RSA_get0_p(const d: PRSA): PBIGNUM;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_p_procname);
end;


function  ERR_RSA_get0_q(const d: PRSA): PBIGNUM;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_q_procname);
end;


function  ERR_RSA_get0_dmp1(const r: PRSA): PBIGNUM;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_dmp1_procname);
end;


function  ERR_RSA_get0_dmq1(const r: PRSA): PBIGNUM;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_dmq1_procname);
end;


function  ERR_RSA_get0_iqmp(const r: PRSA): PBIGNUM;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_iqmp_procname);
end;



procedure  ERR_RSA_clear_flags(r: PRSA; flags: TIdC_INT);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_clear_flags_procname);
end;


function  ERR_RSA_test_flags(const r: PRSA; flags: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_test_flags_procname);
end;


procedure  ERR_RSA_set_flags(r: PRSA; flags: TIdC_INT);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_set_flags_procname);
end;


function  ERR_RSA_get_version(r: PRSA): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get_version_procname);
end;


function  ERR_RSA_get0_engine(const r: PRSA): PENGINE;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get0_engine_procname);
end;



  (* New version *)
function  ERR_RSA_generate_key_ex(rsa: PRSA; bits: TIdC_INT; e: PBIGNUM; cb: PBN_GENCB): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_generate_key_ex_procname);
end;


  (* Multi-prime version *)
function  ERR_RSA_generate_multi_prime_key(rsa: PRSA; bits: TIdC_INT; primes: TIdC_INT; e: PBIGNUM; cb: PBN_GENCB): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_generate_multi_prime_key_procname);
end;


function  ERR_RSA_X931_derive_ex(rsa: PRSA; p1: PBIGNUM; p2: PBIGNUM; q1: PBIGNUM; q2: PBIGNUM; const Xp1: PBIGNUM; const Xp2: PBIGNUM; const Xp: PBIGNUM; const Xq1: PBIGNUM; const Xq2: PBIGNUM; const Xq: PBIGNUM; const e: PBIGNUM; cb: PBN_GENCB): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_X931_derive_ex_procname);
end;


function  ERR_RSA_X931_generate_key_ex(rsa: PRSA; bits: TIdC_INT; const e: PBIGNUM; cb: PBN_GENCB): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_X931_generate_key_ex_procname);
end;



function  ERR_RSA_check_key(const v1: PRSA): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_check_key_procname);
end;


function  ERR_RSA_check_key_ex(const v1: PRSA; cb: PBN_GENCB): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_check_key_ex_procname);
end;


  (* next 4 return -1 on error *)
function  ERR_RSA_public_encrypt(flen: TIdC_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_public_encrypt_procname);
end;


function  ERR_RSA_private_encrypt(flen: TIdC_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_private_encrypt_procname);
end;


function  ERR_RSA_public_decrypt(flen: TIdC_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_public_decrypt_procname);
end;


function  ERR_RSA_private_decrypt(flen: TIdC_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_private_decrypt_procname);
end;



procedure  ERR_RSA_free(r: PRSA);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_free_procname);
end;


  (* "up" the RSA object's reference count *)
function  ERR_RSA_up_ref(r: PRSA): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_up_ref_procname);
end;



function  ERR_RSA_flags(const r: PRSA): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_flags_procname);
end;



procedure  ERR_RSA_set_default_method(const meth: PRSA_METHOD);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_set_default_method_procname);
end;


function  ERR_RSA_get_default_method: PRSA_METHOD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get_default_method_procname);
end;


function  ERR_RSA_null_method: PRSA_METHOD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_null_method_procname);
end;


function  ERR_RSA_get_method(const rsa: PRSA): PRSA_METHOD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get_method_procname);
end;


function  ERR_RSA_set_method(rsa: PRSA; const meth: PRSA_METHOD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_set_method_procname);
end;



  (* these are the actual RSA functions *)
function  ERR_RSA_PKCS1_OpenSSL: PRSA_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_PKCS1_OpenSSL_procname);
end;



function  ERR_RSA_pkey_ctx_ctrl(ctx: PEVP_PKEY_CTX; optype: TIdC_INT; cmd: TIdC_INT; p1: TIdC_INT; p2: Pointer): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_pkey_ctx_ctrl_procname);
end;



function  ERR_RSA_print(bp: PBIO; const r: PRSA; offset: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_print_procname);
end;



  (*
   * The following 2 functions sign and verify a X509_SIG ASN1 object inside
   * PKCS#1 padded RSA encryption
   *)
function  ERR_RSA_sign(type_: TIdC_INT; const m: PByte; m_length: TIdC_UINT; sigret: PByte; siglen: PIdC_UINT; rsa: PRSA): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_sign_procname);
end;


function  ERR_RSA_verify(type_: TIdC_INT; const m: PByte; m_length: TIdC_UINT; const sigbuf: PByte; siglen: TIdC_UINT; rsa: PRSA): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_verify_procname);
end;



  (*
   * The following 2 function sign and verify a ASN1_OCTET_STRING object inside
   * PKCS#1 padded RSA encryption
   *)
function  ERR_RSA_sign_ASN1_OCTET_STRING(type_: TIdC_INT; const m: PByte; m_length: TIdC_UINT; sigret: PByte; siglen: PIdC_UINT; rsa: PRSA): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_sign_ASN1_OCTET_STRING_procname);
end;


function  ERR_RSA_verify_ASN1_OCTET_STRING(type_: TIdC_INT; const m: PByte; m_length: TIdC_UINT; sigbuf: PByte; siglen: TIdC_UINT; rsa: PRSA): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_verify_ASN1_OCTET_STRING_procname);
end;



function  ERR_RSA_blinding_on(rsa: PRSA; ctx: PBN_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_blinding_on_procname);
end;


procedure  ERR_RSA_blinding_off(rsa: PRSA);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_blinding_off_procname);
end;


function  ERR_RSA_setup_blinding(rsa: PRSA; ctx: PBN_CTX): PBN_BLINDING;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_setup_blinding_procname);
end;


function  ERR_RSA_padding_add_PKCS1_type_1(to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_add_PKCS1_type_1_procname);
end;


function  ERR_RSA_padding_check_PKCS1_type_1(to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_check_PKCS1_type_1_procname);
end;


function  ERR_RSA_padding_add_PKCS1_type_2(to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_add_PKCS1_type_2_procname);
end;


function  ERR_RSA_padding_check_PKCS1_type_2(to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_check_PKCS1_type_2_procname);
end;


function  ERR_PKCS1_MGF1(mask: PByte; len: TIdC_LONG; const seed: PByte; seedlen: TIdC_LONG; const dgst: PEVP_MD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS1_MGF1_procname);
end;


function  ERR_RSA_padding_add_PKCS1_OAEP(to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT; const p: PByte; pl: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_add_PKCS1_OAEP_procname);
end;


function  ERR_RSA_padding_check_PKCS1_OAEP(to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT; rsa_len: TIdC_INT; const p: PByte; pl: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_check_PKCS1_OAEP_procname);
end;


function  ERR_RSA_padding_add_PKCS1_OAEP_mgf1(to_: PByte; tlen: TIdC_INT; const from: PByte; flen: TIdC_INT; const param: PByte; plen: TIdC_INT; const md: PEVP_MD; const mgf1md: PEVP_MD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_add_PKCS1_OAEP_mgf1_procname);
end;


function  ERR_RSA_padding_check_PKCS1_OAEP_mgf1(to_: PByte; tlen: TIdC_INT; const from: PByte; flen: TIdC_INT; num: TIdC_INT; const param: PByte; plen: TIdC_INT; const md: PEVP_MD; const mgf1md: PEVP_MD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_check_PKCS1_OAEP_mgf1_procname);
end;

{
function  ERR_RSA_padding_add_SSLv23(to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_add_SSLv23_procname);
end;
}
{
function  ERR_RSA_padding_check_SSLv23(to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_check_SSLv23_procname);
end; }


function  ERR_RSA_padding_add_none(to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_add_none_procname);
end;


function  ERR_RSA_padding_check_none(to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_check_none_procname);
end;


function  ERR_RSA_padding_add_X931(to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_add_X931_procname);
end;


function  ERR_RSA_padding_check_X931(to_: PByte; tlen: TIdC_INT; const f: PByte; fl: TIdC_INT; rsa_len: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_check_X931_procname);
end;


function  ERR_RSA_X931_hash_id(nid: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_X931_hash_id_procname);
end;



function  ERR_RSA_verify_PKCS1_PSS(rsa: PRSA; const mHash: PByte; const Hash: PEVP_MD; const EM: PByte; sLen: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_verify_PKCS1_PSS_procname);
end;


function  ERR_RSA_padding_add_PKCS1_PSS(rsa: PRSA; EM: PByte; const mHash: PByte; const Hash: PEVP_MD; sLen: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_add_PKCS1_PSS_procname);
end;


function  ERR_RSA_verify_PKCS1_PSS_mgf1(rsa: PRSA; const mHash: PByte; const Hash: PEVP_MD; const mgf1Hash: PEVP_MD; const EM: PByte; sLen: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_verify_PKCS1_PSS_mgf1_procname);
end;


function  ERR_RSA_padding_add_PKCS1_PSS_mgf1(rsa: PRSA; EM: PByte; const mHash: PByte; const Hash: PEVP_MD; const mgf1Hash: PEVP_MD; sLen: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_padding_add_PKCS1_PSS_mgf1_procname);
end;

function  ERR_RSA_set_ex_data(r: PRSA; idx: TIdC_INT; arg: Pointer): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_set_ex_data_procname);
end;


function  ERR_RSA_get_ex_data(const r: PRSA; idx: TIdC_INT): Pointer;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_get_ex_data_procname);
end;


function  ERR_RSAPublicKey_dup(rsa: PRSA): PRSA;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSAPublicKey_dup_procname);
end;


function  ERR_RSAPrivateKey_dup(rsa: PRSA): PRSA;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSAPrivateKey_dup_procname);
end;



function  ERR_RSA_meth_new(const name: PIdAnsiChar; flags: TIdC_INT): PRSA_METHOD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_new_procname);
end;


procedure  ERR_RSA_meth_free(meth: PRSA_METHOD);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_free_procname);
end;


function  ERR_RSA_meth_dup(const meth: PRSA_METHOD): PRSA_METHOD;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_dup_procname);
end;


function  ERR_RSA_meth_get0_name(const meth: PRSA_METHOD): PIdAnsiChar;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_get0_name_procname);
end;


function  ERR_RSA_meth_set1_name(meth: PRSA_METHOD; const name: PIdAnsiChar): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set1_name_procname);
end;


function  ERR_RSA_meth_get_flags(const meth: PRSA_METHOD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_get_flags_procname);
end;


function  ERR_RSA_meth_set_flags(meth: PRSA_METHOD; flags: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set_flags_procname);
end;


function  ERR_RSA_meth_get0_app_data(const meth: PRSA_METHOD): Pointer;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_get0_app_data_procname);
end;


function  ERR_RSA_meth_set0_app_data(meth: PRSA_METHOD; app_data: Pointer): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set0_app_data_procname);
end;



  //int (*RSA_meth_get_pub_enc(const RSA_METHOD *meth))
  //    (int flen, const unsigned char *from,
  //     unsigned char *to_, RSA *rsa, int padding);
  //int RSA_meth_set_pub_enc(RSA_METHOD *rsa,
  //                         int (*pub_enc) (int flen, const unsigned char *from,
  //                                         unsigned char *to_, RSA *rsa,
  //                                         int padding));
  //int (*RSA_meth_get_pub_dec(const RSA_METHOD *meth))
  //    (int flen, const unsigned char *from,
  //     unsigned char *to_, RSA *rsa, int padding);
  //int RSA_meth_set_pub_dec(RSA_METHOD *rsa,
  //                         int (*pub_dec) (int flen, const unsigned char *from,
  //                                         unsigned char *to_, RSA *rsa,
  //                                         int padding));
  //int (*RSA_meth_get_priv_enc(const RSA_METHOD *meth))
  //    (int flen, const unsigned char *from,
  //     unsigned char *to_, RSA *rsa, int padding);
  //int RSA_meth_set_priv_enc(RSA_METHOD *rsa,
  //                          int (*priv_enc) (int flen, const unsigned char *from,
  //                                           unsigned char *to_, RSA *rsa,
  //                                           int padding));
  //int (*RSA_meth_get_priv_dec(const RSA_METHOD *meth))
  //    (int flen, const unsigned char *from,
  //     unsigned char *to_, RSA *rsa, int padding);
function  ERR_RSA_meth_set_priv_dec(rsa: PRSA_METHOD; priv_dec: RSA_meth_set_priv_dec_priv_dec): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set_priv_dec_procname);
end;



  //int (*RSA_meth_get_mod_exp(const RSA_METHOD *meth))
  //    (BIGNUM *r0, const BIGNUM *i, RSA *rsa, BN_CTX *ctx);
function  ERR_RSA_meth_set_mod_exp(rsa: PRSA_METHOD; mod_exp: RSA_meth_set_mod_exp_mod_exp): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set_mod_exp_procname);
end;


  //int (*RSA_meth_get_bn_mod_exp(const RSA_METHOD *meth))
  //    (BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
  //     const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
function  ERR_RSA_meth_set_bn_mod_exp(rsa: PRSA_METHOD; bn_mod_exp: RSA_meth_set_bn_mod_exp_bn_mod_exp): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set_bn_mod_exp_procname);
end;


  //int (*RSA_meth_get_init(const RSA_METHOD *meth)) (RSA *rsa);
function  ERR_RSA_meth_set_init(rsa: PRSA_METHOD; init: RSA_meth_set_init_init): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set_init_procname);
end;


  //int (*RSA_meth_get_finish(const RSA_METHOD *meth)) (RSA *rsa);
function  ERR_RSA_meth_set_finish(rsa: PRSA_METHOD; finish: RSA_meth_set_finish_finish): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set_finish_procname);
end;


  //int (*RSA_meth_get_sign(const RSA_METHOD *meth))
  //    (int type_,
  //     const unsigned char *m, unsigned int m_length,
  //     unsigned char *sigret, unsigned int *siglen,
  //     const RSA *rsa);
function  ERR_RSA_meth_set_sign(rsa: PRSA_METHOD; sign: RSA_meth_set_sign_sign): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set_sign_procname);
end;


  //int (*RSA_meth_get_verify(const RSA_METHOD *meth))
  //    (int dtype, const unsigned char *m,
  //     unsigned int m_length, const unsigned char *sigbuf,
  //     unsigned int siglen, const RSA *rsa);
function  ERR_RSA_meth_set_verify(rsa: PRSA_METHOD; verify: RSA_meth_set_verify_verify): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set_verify_procname);
end;


  //int (*RSA_meth_get_keygen(const RSA_METHOD *meth))
  //    (RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
function  ERR_RSA_meth_set_keygen(rsa: PRSA_METHOD; keygen: RSA_meth_set_keygen_keygen): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set_keygen_procname);
end;


  //int (*RSA_meth_get_multi_prime_keygen(const RSA_METHOD *meth))
  //    (RSA *rsa, int bits, int primes, BIGNUM *e, BN_GENCB *cb);
function  ERR_RSA_meth_set_multi_prime_keygen(meth: PRSA_METHOD; keygen: RSA_meth_set_multi_prime_keygen_keygen): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(RSA_meth_set_multi_prime_keygen_procname);
end;


  {$I TaurusTLSNoRetValOn.inc}

  {$I TaurusTLSUnusedParamOff.inc}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
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


//  RSA_padding_add_SSLv23 := LoadLibFunction(ADllHandle, RSA_padding_add_SSLv23_procname);
//  FuncLoadError := not assigned(RSA_padding_add_SSLv23);
//  if FuncLoadError then
//  begin
//    {$if not defined(RSA_padding_add_SSLv23_allownil)}
//    RSA_padding_add_SSLv23 := ERR_RSA_padding_add_SSLv23;
//    {$ifend}
//    {$if declared(RSA_padding_add_SSLv23_introduced)}
//    if LibVersion < RSA_padding_add_SSLv23_introduced then
//    begin
//      {$if declared(FC_RSA_padding_add_SSLv23)}
//      RSA_padding_add_SSLv23 := FC_RSA_padding_add_SSLv23;
//      {$ifend}
//      FuncLoadError := false;
//    end;
//    {$ifend}
//    {$if declared(RSA_padding_add_SSLv23_removed)}
//    if RSA_padding_add_SSLv23_removed <= LibVersion then
//    begin
//      {$if declared(_RSA_padding_add_SSLv23)}
//      RSA_padding_add_SSLv23 := _RSA_padding_add_SSLv23;
//      {$ifend}
//      FuncLoadError := false;
//    end;
//    {$ifend}
//    {$if not defined(RSA_padding_add_SSLv23_allownil)}
//    if FuncLoadError then
//      AFailed.Add('RSA_padding_add_SSLv23');
//    {$ifend}
//  end;


//  RSA_padding_check_SSLv23 := LoadLibFunction(ADllHandle, RSA_padding_check_SSLv23_procname);
//  FuncLoadError := not assigned(RSA_padding_check_SSLv23);
//  if FuncLoadError then
//  begin
//    {$if not defined(RSA_padding_check_SSLv23_allownil)}
//    RSA_padding_check_SSLv23 := ERR_RSA_padding_check_SSLv23;
//    {$ifend}
//    {$if declared(RSA_padding_check_SSLv23_introduced)}
//    if LibVersion < RSA_padding_check_SSLv23_introduced then
//    begin
//      {$if declared(FC_RSA_padding_check_SSLv23)}
//      RSA_padding_check_SSLv23 := FC_RSA_padding_check_SSLv23;
//      {$ifend}
//      FuncLoadError := false;
//    end;
//    {$ifend}
//    {$if declared(RSA_padding_check_SSLv23_removed)}
//    if RSA_padding_check_SSLv23_removed <= LibVersion then
//    begin
//      {$if declared(_RSA_padding_check_SSLv23)}
//      RSA_padding_check_SSLv23 := _RSA_padding_check_SSLv23;
//      {$ifend}
//      FuncLoadError := false;
//    end;
//    {$ifend}
//    {$if not defined(RSA_padding_check_SSLv23_allownil)}
//    if FuncLoadError then
//      AFailed.Add('RSA_padding_check_SSLv23');
//    {$ifend}
//  end;


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
{$I TaurusTLSUnusedParamOn.inc}

procedure Unload;
begin
  RSA_new := nil;
  RSA_new_method := nil;
  RSA_bits := nil;
  RSA_size := nil;
  RSA_security_bits := nil;
  RSA_set0_key := nil;
  RSA_set0_factors := nil;
  RSA_set0_crt_params := nil;
  RSA_get0_key := nil;
  RSA_get0_factors := nil;
  RSA_get_multi_prime_extra_count := nil;
  RSA_get0_crt_params := nil;
  RSA_get0_n := nil;
  RSA_get0_e := nil;
  RSA_get0_d := nil;
  RSA_get0_p := nil;
  RSA_get0_q := nil;
  RSA_get0_dmp1 := nil;
  RSA_get0_dmq1 := nil;
  RSA_get0_iqmp := nil;
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
  RSA_pkey_ctx_ctrl := nil;
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
//  RSA_padding_add_SSLv23 := nil;
//  RSA_padding_check_SSLv23 := nil;
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
  RSA_meth_set_priv_dec := nil;
  RSA_meth_set_mod_exp := nil;
  RSA_meth_set_bn_mod_exp := nil;
  RSA_meth_set_init := nil;
  RSA_meth_set_finish := nil;
  RSA_meth_set_sign := nil;
  RSA_meth_set_verify := nil;
  RSA_meth_set_keygen := nil;
  RSA_meth_set_multi_prime_keygen := nil;
end;
  {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
