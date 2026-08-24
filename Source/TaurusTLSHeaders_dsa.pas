/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_dsa.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_dsa.h2pas
     and this file regenerated. TaurusTLSHeaders_dsa.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_dsa;

interface

// Headers for OpenSSL 1.1.1
// dsa.h


uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_evp;

const
  {$EXTERNALSYM OPENSSL_DSA_MAX_MODULUS_BITS}
  OPENSSL_DSA_MAX_MODULUS_BITS = 10000;
  {$EXTERNALSYM OPENSSL_DSA_FIPS_MIN_MODULUS_BITS}
  OPENSSL_DSA_FIPS_MIN_MODULUS_BITS = 1024;
  {$EXTERNALSYM DSA_FLAG_CACHE_MONT_P}
  DSA_FLAG_CACHE_MONT_P = $01;
  {$EXTERNALSYM DSA_FLAG_NO_EXP_CONSTTIME}
  DSA_FLAG_NO_EXP_CONSTTIME = $00;
  {$EXTERNALSYM DSA_FLAG_FIPS_METHOD}
  DSA_FLAG_FIPS_METHOD = $0400;
  {$EXTERNALSYM DSA_FLAG_NON_FIPS_ALLOW}
  DSA_FLAG_NON_FIPS_ALLOW = $0400;
  {$EXTERNALSYM DSA_FLAG_FIPS_CHECKED}
  DSA_FLAG_FIPS_CHECKED = $0800;

  {$EXTERNALSYM DSS_prime_checks}
  DSS_prime_checks = 64;

  {$EXTERNALSYM EVP_PKEY_CTRL_DSA_PARAMGEN_BITS}
  EVP_PKEY_CTRL_DSA_PARAMGEN_BITS = EVP_PKEY_ALG_CTRL + 1;
  {$EXTERNALSYM EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS}
  EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS = EVP_PKEY_ALG_CTRL + 2;
  {$EXTERNALSYM EVP_PKEY_CTRL_DSA_PARAMGEN_MD}
  EVP_PKEY_CTRL_DSA_PARAMGEN_MD = EVP_PKEY_ALG_CTRL + 3;

type
  {$EXTERNALSYM DSA_SIG}
  DSA_SIG = record end; // DSA_SIG_st
  {$EXTERNALSYM PDSA_SIG}
  PDSA_SIG = ^DSA_SIG;
  {$EXTERNALSYM PPDSA_SIG}
  PPDSA_SIG = ^PDSA_SIG;

  {$EXTERNALSYM DSA_meth_sign_cb}
  DSA_meth_sign_cb = function (const v1: PByte; v2: TIdC_INT; v3: PDSA): PDSA_SIG cdecl;
  {$EXTERNALSYM DSA_meth_sign_setup_cb}
  DSA_meth_sign_setup_cb = function (v1: PDSA; v2: PBN_CTX;
    v3: PPBIGNUM; v4: PPBIGNUM): TIdC_INT cdecl;
  {$EXTERNALSYM DSA_meth_verify_cb}
  DSA_meth_verify_cb = function (const v1: PByte; v2: TIdC_INT;
    v3: PDSA_SIG; v4: PDSA): TIdC_INT cdecl;
  {$EXTERNALSYM DSA_meth_mod_exp_cb}
  DSA_meth_mod_exp_cb = function (v1: PDSA; v2: PBIGNUM;
    const v3: PBIGNUM; const v4: PBIGNUM; const v5: PBIGNUM; const v6: PBIGNUM;
    const v7: PBIGNUM; v8: PBN_CTX; v9: PBN_MONT_CTX): TIdC_INT cdecl;
  {$EXTERNALSYM DSA_meth_bn_mod_exp_cb}
  DSA_meth_bn_mod_exp_cb = function (v1: PDSA; v2: PBIGNUM;
    const v3: PBIGNUM; const v4: PBIGNUM; const v5: PBIGNUM; v6: PBN_CTX; v7: PBN_MONT_CTX): TIdC_INT cdecl;
  {$EXTERNALSYM DSA_meth_init_cb}
  DSA_meth_init_cb = function(v1: PDSA): TIdC_INT cdecl;
  {$EXTERNALSYM DSA_meth_finish_cb}
  DSA_meth_finish_cb = function (v1: PDSA): TIdC_INT cdecl;
  {$EXTERNALSYM DSA_meth_paramgen_cb}
  DSA_meth_paramgen_cb = function (v1: PDSA; v2: TIdC_INT;
    const v3: PByte; v4: TIdC_INT; v5: PIdC_INT; v6: PIdC_ULONG; v7: PBN_GENCB): TIdC_INT cdecl;
  {$EXTERNALSYM DSA_meth_keygen_cb}
  DSA_meth_keygen_cb = function (v1: PDSA): TIdC_INT cdecl;

//# define d2i_DSAparams_fp(fp,x) (DSA *)ASN1_d2i_fp((char *(*)())DSA_new, \
//                (char *(*)())d2i_DSAparams,(fp),(unsigned char **)(x))
//# define i2d_DSAparams_fp(fp,x) ASN1_i2d_fp(i2d_DSAparams,(fp), \
//                (unsigned char *)(x))
//# define d2i_DSAparams_bio(bp,x) ASN1_d2i_bio_of(DSA,DSA_new,d2i_DSAparams,bp,x)
//# define i2d_DSAparams_bio(bp,x) ASN1_i2d_bio_of_const(DSA,i2d_DSAparams,bp,x)

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM DSAparams_dup}
  DSAparams_dup: function (x: PDSA): PDSA; cdecl = nil;
  {$EXTERNALSYM DSA_SIG_new}
  DSA_SIG_new: function : PDSA_SIG; cdecl = nil;
  {$EXTERNALSYM DSA_SIG_free}
  DSA_SIG_free: procedure (a: PDSA_SIG); cdecl = nil;
  {$EXTERNALSYM i2d_DSA_SIG}
  i2d_DSA_SIG: function (const a: PDSA_SIG; pp: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_DSA_SIG}
  d2i_DSA_SIG: function (v: PPDSA_SIG; const pp: PPByte; _length: TIdC_LONG): PDSA_SIG; cdecl = nil;
  {$EXTERNALSYM DSA_SIG_get0}
  DSA_SIG_get0: procedure (const sig: PDSA_SIG; const pr: PPBIGNUM; const ps: PPBIGNUM); cdecl = nil;
  {$EXTERNALSYM DSA_SIG_set0}
  DSA_SIG_set0: function (sig: PDSA_SIG; r: PBIGNUM; s: PBIGNUM): TIdC_INT; cdecl = nil;
  
  {$EXTERNALSYM DSA_do_sign}
  DSA_do_sign: function (const dgst: PByte; dlen: TIdC_INT; dsa: PDSA): PDSA_SIG; cdecl = nil;
  {$EXTERNALSYM DSA_do_verify}
  DSA_do_verify: function (const dgst: PByte; dgst_len: TIdC_INT; sig: PDSA_SIG; dsa: PDSA): TIdC_INT; cdecl = nil;
  
  {$EXTERNALSYM DSA_TaurusTLS}
  DSA_TaurusTLS: function : PDSA_METHOD; cdecl = nil;
  {$EXTERNALSYM DSA_set_default_method}
  DSA_set_default_method: procedure (const v1: PDSA_METHOD); cdecl = nil;
  {$EXTERNALSYM DSA_get_default_method}
  DSA_get_default_method: function : PDSA_METHOD; cdecl = nil;
  {$EXTERNALSYM DSA_set_method}
  DSA_set_method: function (dsa: PDSA; const v1: PDSA_METHOD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DSA_get_method}
  DSA_get_method: function (d: PDSA): PDSA_METHOD; cdecl = nil;

  {$EXTERNALSYM DSA_new}
  DSA_new: function : PDSA; cdecl = nil;
  {$EXTERNALSYM DSA_new_method}
  DSA_new_method: function (engine: PENGINE): PDSA; cdecl = nil;
  {$EXTERNALSYM DSA_free}
  DSA_free: procedure (r: PDSA); cdecl = nil;
  (* "up" the DSA object's reference count *)
  {$EXTERNALSYM DSA_up_ref}
  DSA_up_ref: function (r: PDSA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DSA_size}
  DSA_size: function (const v1: PDSA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DSA_bits}
  DSA_bits: function (const d: PDSA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DSA_security_bits}
  DSA_security_bits: function (const d: PDSA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DSA_sign}
  DSA_sign: function (type_: TIdC_INT; const dgst: PByte; dlen: TIdC_INT; sig: PByte; siglen: PIdC_UINT; dsa: PDSA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DSA_verify}
  DSA_verify: function (type_: TIdC_INT; const dgst: PByte; dgst_len: TIdC_INT; const sigbuf: PByte; siglen: TIdC_INT; dsa: PDSA): TIdC_INT; cdecl = nil;
  //#define DSA_get_ex_new_index(l, p, newf, dupf, freef) \
  //    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DSA, l, p, newf, dupf, freef)
  {$EXTERNALSYM DSA_set_ex_data}
  DSA_set_ex_data: function (d: PDSA; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DSA_get_ex_data}
  DSA_get_ex_data: function (d: PDSA; idx: TIdC_INT): Pointer; cdecl = nil;
  
  {$EXTERNALSYM d2i_DSAPublicKey}
  d2i_DSAPublicKey: function (a: PPDSA; const pp: PPByte; _length: TIdC_LONG): PDSA; cdecl = nil;
  {$EXTERNALSYM d2i_DSAPrivateKey}
  d2i_DSAPrivateKey: function (a: PPDSA; const pp: PPByte; _length: TIdC_LONG): PDSA; cdecl = nil;
  {$EXTERNALSYM d2i_DSAparams}
  d2i_DSAparams: function (a: PPDSA; const pp: PPByte; _length: TIdC_LONG): PDSA; cdecl = nil;

  {$EXTERNALSYM DSA_generate_parameters_ex}
  DSA_generate_parameters_ex: function (dsa: PDSA; bits: TIdC_INT; const seed: PByte; seed_len: TIdC_INT; counter_ret: PIdC_INT; h_ret: PIdC_ULONG; cb: PBN_GENCB): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM DSA_generate_key}
  DSA_generate_key: function (a: PDSA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_DSAPublicKey}
  i2d_DSAPublicKey: function (const a: PDSA; pp: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_DSAPrivateKey}
  i2d_DSAPrivateKey: function (const a: PDSA; pp: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_DSAparams}
  i2d_DSAparams: function (const a: PDSA; pp: PPByte): TIdC_INT; cdecl = nil;
  
  {$EXTERNALSYM DSAparams_print}
  DSAparams_print: function (bp: PBIO; const x: PDSA): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DSA_print}
  DSA_print: function (bp: PBIO; const x: PDSA; off: TIdC_INT): TIdC_INT; cdecl = nil;
//  function DSAparams_print_fp(fp: PFile; const x: PDSA): TIdC_INT;
//  function DSA_print_fp(bp: PFile; const x: PDSA; off: TIdC_INT): TIdC_INT;

  //# define DSA_is_prime(n, callback, cb_arg) \
  //        BN_is_prime(n, DSS_prime_checks, callback, NULL, cb_arg)

  (*
   * Convert DSA structure (key or just parameters) into DH structure (be
   * careful to avoid small subgroup attacks when using this!)
   *)
  {$EXTERNALSYM DSA_dup_DH}
  DSA_dup_DH: function (const r: PDSA): PDH; cdecl = nil;

  //# define EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, nbits) \
  //        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN, \
  //                                EVP_PKEY_CTRL_DSA_PARAMGEN_BITS, nbits, NULL)
  //# define EVP_PKEY_CTX_set_dsa_paramgen_q_bits(ctx, qbits) \
  //        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN, \
  //                                EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS, qbits, NULL)
  //# define EVP_PKEY_CTX_set_dsa_paramgen_md(ctx, md) \
  //        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN, \
  //                                EVP_PKEY_CTRL_DSA_PARAMGEN_MD, 0, (void *)(md))

  {$EXTERNALSYM DSA_get0_pqg}
  DSA_get0_pqg: procedure (const d: PDSA; const p: PPBIGNUM; const q: PPBIGNUM; const g: PPBIGNUM); cdecl = nil;
  {$EXTERNALSYM DSA_set0_pqg}
  DSA_set0_pqg: function (d: PDSA; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DSA_get0_key}
  DSA_get0_key: procedure (const d: PDSA; const pub_key: PPBIGNUM; const priv_key: PPBIGNUM); cdecl = nil;
  {$EXTERNALSYM DSA_set0_key}
  DSA_set0_key: function (d: PDSA; pub_key: PBIGNUM; priv_key: PBIGNUM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DSA_get0_p}
  DSA_get0_p: function (const d: PDSA): PBIGNUM; cdecl = nil;
  {$EXTERNALSYM DSA_get0_q}
  DSA_get0_q: function (const d: PDSA): PBIGNUM; cdecl = nil;
  {$EXTERNALSYM DSA_get0_g}
  DSA_get0_g: function (const d: PDSA): PBIGNUM; cdecl = nil;
  {$EXTERNALSYM DSA_get0_pub_key}
  DSA_get0_pub_key: function (const d: PDSA): PBIGNUM; cdecl = nil;
  {$EXTERNALSYM DSA_get0_priv_key}
  DSA_get0_priv_key: function (const d: PDSA): PBIGNUM; cdecl = nil;
  {$EXTERNALSYM DSA_clear_flags}
  DSA_clear_flags: procedure (d: PDSA; flags: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM DSA_test_flags}
  DSA_test_flags: function (const d: PDSA; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DSA_set_flags}
  DSA_set_flags: procedure (d: PDSA; flags: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM DSA_get0_engine}
  DSA_get0_engine: function (d: PDSA): PENGINE; cdecl = nil;
  
  {$EXTERNALSYM DSA_meth_new}
  DSA_meth_new: function (const name: PIdAnsiChar; flags: TIdC_INT): PDSA_METHOD; cdecl = nil;
  {$EXTERNALSYM DSA_meth_free}
  DSA_meth_free: procedure (dsam: PDSA_METHOD); cdecl = nil;
  {$EXTERNALSYM DSA_meth_dup}
  DSA_meth_dup: function (const dsam: PDSA_METHOD): PDSA_METHOD; cdecl = nil;
  {$EXTERNALSYM DSA_meth_get0_name}
  DSA_meth_get0_name: function (const dsam: PDSA_METHOD): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM DSA_meth_set1_name}
  DSA_meth_set1_name: function (dsam: PDSA_METHOD; const name: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DSA_meth_get_flags}
  DSA_meth_get_flags: function (const dsam: PDSA_METHOD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DSA_meth_set_flags}
  DSA_meth_set_flags: function (dsam: PDSA_METHOD; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DSA_meth_get0_app_data}
  DSA_meth_get0_app_data: function (const dsam: PDSA_METHOD): Pointer; cdecl = nil;
  {$EXTERNALSYM DSA_meth_set0_app_data}
  DSA_meth_set0_app_data: function (dsam: PDSA_METHOD; app_data: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DSA_meth_get_sign}
  DSA_meth_get_sign: function (const dsam: PDSA_METHOD): DSA_meth_sign_cb; cdecl = nil;
  {$EXTERNALSYM DSA_meth_set_sign}
  DSA_meth_set_sign: function (dsam: PDSA_METHOD; sign: DSA_meth_sign_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DSA_meth_get_sign_setup}
  DSA_meth_get_sign_setup: function (const dsam: PDSA_METHOD): DSA_meth_sign_setup_cb; cdecl = nil;
  {$EXTERNALSYM DSA_meth_set_sign_setup}
  DSA_meth_set_sign_setup: function (dsam: PDSA_METHOD; sign_setup: DSA_meth_sign_setup_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DSA_meth_get_verify}
  DSA_meth_get_verify: function (const dsam: PDSA_METHOD): DSA_meth_verify_cb; cdecl = nil;
  {$EXTERNALSYM DSA_meth_set_verify}
  DSA_meth_set_verify: function (dsam: PDSA_METHOD; verify: DSA_meth_verify_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DSA_meth_get_mod_exp}
  DSA_meth_get_mod_exp: function (const dsam: PDSA_METHOD): DSA_meth_mod_exp_cb; cdecl = nil;
  {$EXTERNALSYM DSA_meth_set_mod_exp}
  DSA_meth_set_mod_exp: function (dsam: PDSA_METHOD; mod_exp: DSA_meth_mod_exp_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DSA_meth_get_bn_mod_exp}
  DSA_meth_get_bn_mod_exp: function (const dsam: PDSA_METHOD): DSA_meth_bn_mod_exp_cb; cdecl = nil;
  {$EXTERNALSYM DSA_meth_set_bn_mod_exp}
  DSA_meth_set_bn_mod_exp: function (dsam: PDSA_METHOD; bn_mod_exp: DSA_meth_bn_mod_exp_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DSA_meth_get_init}
  DSA_meth_get_init: function (const dsam: PDSA_METHOD): DSA_meth_init_cb; cdecl = nil;
  {$EXTERNALSYM DSA_meth_set_init}
  DSA_meth_set_init: function (dsam: PDSA_METHOD; init: DSA_meth_init_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DSA_meth_get_finish}
  DSA_meth_get_finish: function (const dsam: PDSA_METHOD): DSA_meth_finish_cb; cdecl = nil;
  {$EXTERNALSYM DSA_meth_set_finish}
  DSA_meth_set_finish: function (dsam: PDSA_METHOD; finish: DSA_meth_finish_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DSA_meth_get_paramgen}
  DSA_meth_get_paramgen: function (const dsam: PDSA_METHOD): DSA_meth_paramgen_cb; cdecl = nil;
  {$EXTERNALSYM DSA_meth_set_paramgen}
  DSA_meth_set_paramgen: function (dsam: PDSA_METHOD; paramgen: DSA_meth_paramgen_cb): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DSA_meth_get_keygen}
  DSA_meth_get_keygen: function (const dsam: PDSA_METHOD): DSA_meth_keygen_cb; cdecl = nil;
  {$EXTERNALSYM DSA_meth_set_keygen}
  DSA_meth_set_keygen: function (dsam: PDSA_METHOD; keygen: DSA_meth_keygen_cb): TIdC_INT; cdecl = nil;

{$ELSE}
  {$EXTERNALSYM DSAparams_dup}
  function DSAparams_dup(x: PDSA): PDSA cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_SIG_new}
  function DSA_SIG_new: PDSA_SIG cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_SIG_free}
  procedure DSA_SIG_free(a: PDSA_SIG) cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_DSA_SIG}
  function i2d_DSA_SIG(const a: PDSA_SIG; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_DSA_SIG}
  function d2i_DSA_SIG(v: PPDSA_SIG; const pp: PPByte; _length: TIdC_LONG): PDSA_SIG cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_SIG_get0}
  procedure DSA_SIG_get0(const sig: PDSA_SIG; const pr: PPBIGNUM; const ps: PPBIGNUM) cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_SIG_set0}
  function DSA_SIG_set0(sig: PDSA_SIG; r: PBIGNUM; s: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  
  {$EXTERNALSYM DSA_do_sign}
  function DSA_do_sign(const dgst: PByte; dlen: TIdC_INT; dsa: PDSA): PDSA_SIG cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_do_verify}
  function DSA_do_verify(const dgst: PByte; dgst_len: TIdC_INT; sig: PDSA_SIG; dsa: PDSA): TIdC_INT cdecl; external CLibCrypto;
  
  {$EXTERNALSYM DSA_TaurusTLS}
  function DSA_TaurusTLS: PDSA_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_set_default_method}
  procedure DSA_set_default_method(const v1: PDSA_METHOD) cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_get_default_method}
  function DSA_get_default_method: PDSA_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_set_method}
  function DSA_set_method(dsa: PDSA; const v1: PDSA_METHOD): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_get_method}
  function DSA_get_method(d: PDSA): PDSA_METHOD cdecl; external CLibCrypto;

  {$EXTERNALSYM DSA_new}
  function DSA_new: PDSA cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_new_method}
  function DSA_new_method(engine: PENGINE): PDSA cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_free}
  procedure DSA_free(r: PDSA) cdecl; external CLibCrypto;
  (* "up" the DSA object's reference count *)
  {$EXTERNALSYM DSA_up_ref}
  function DSA_up_ref(r: PDSA): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_size}
  function DSA_size(const v1: PDSA): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_bits}
  function DSA_bits(const d: PDSA): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_security_bits}
  function DSA_security_bits(const d: PDSA): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_sign}
  function DSA_sign(type_: TIdC_INT; const dgst: PByte; dlen: TIdC_INT; sig: PByte; siglen: PIdC_UINT; dsa: PDSA): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_verify}
  function DSA_verify(type_: TIdC_INT; const dgst: PByte; dgst_len: TIdC_INT; const sigbuf: PByte; siglen: TIdC_INT; dsa: PDSA): TIdC_INT cdecl; external CLibCrypto;
  //#define DSA_get_ex_new_index(l, p, newf, dupf, freef) \
  //    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DSA, l, p, newf, dupf, freef)
  {$EXTERNALSYM DSA_set_ex_data}
  function DSA_set_ex_data(d: PDSA; idx: TIdC_INT; arg: Pointer): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_get_ex_data}
  function DSA_get_ex_data(d: PDSA; idx: TIdC_INT): Pointer cdecl; external CLibCrypto;
  
  {$EXTERNALSYM d2i_DSAPublicKey}
  function d2i_DSAPublicKey(a: PPDSA; const pp: PPByte; _length: TIdC_LONG): PDSA cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_DSAPrivateKey}
  function d2i_DSAPrivateKey(a: PPDSA; const pp: PPByte; _length: TIdC_LONG): PDSA cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_DSAparams}
  function d2i_DSAparams(a: PPDSA; const pp: PPByte; _length: TIdC_LONG): PDSA cdecl; external CLibCrypto;

  {$EXTERNALSYM DSA_generate_parameters_ex}
  function DSA_generate_parameters_ex(dsa: PDSA; bits: TIdC_INT; const seed: PByte; seed_len: TIdC_INT; counter_ret: PIdC_INT; h_ret: PIdC_ULONG; cb: PBN_GENCB): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM DSA_generate_key}
  function DSA_generate_key(a: PDSA): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_DSAPublicKey}
  function i2d_DSAPublicKey(const a: PDSA; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_DSAPrivateKey}
  function i2d_DSAPrivateKey(const a: PDSA; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_DSAparams}
  function i2d_DSAparams(const a: PDSA; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  
  {$EXTERNALSYM DSAparams_print}
  function DSAparams_print(bp: PBIO; const x: PDSA): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_print}
  function DSA_print(bp: PBIO; const x: PDSA; off: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
//  function DSAparams_print_fp(fp: PFile; const x: PDSA): TIdC_INT;
//  function DSA_print_fp(bp: PFile; const x: PDSA; off: TIdC_INT): TIdC_INT;

  //# define DSA_is_prime(n, callback, cb_arg) \
  //        BN_is_prime(n, DSS_prime_checks, callback, NULL, cb_arg)

  (*
   * Convert DSA structure (key or just parameters) into DH structure (be
   * careful to avoid small subgroup attacks when using this!)
   *)
  {$EXTERNALSYM DSA_dup_DH}
  function DSA_dup_DH(const r: PDSA): PDH cdecl; external CLibCrypto;

  //# define EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, nbits) \
  //        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN, \
  //                                EVP_PKEY_CTRL_DSA_PARAMGEN_BITS, nbits, NULL)
  //# define EVP_PKEY_CTX_set_dsa_paramgen_q_bits(ctx, qbits) \
  //        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN, \
  //                                EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS, qbits, NULL)
  //# define EVP_PKEY_CTX_set_dsa_paramgen_md(ctx, md) \
  //        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN, \
  //                                EVP_PKEY_CTRL_DSA_PARAMGEN_MD, 0, (void *)(md))

  {$EXTERNALSYM DSA_get0_pqg}
  procedure DSA_get0_pqg(const d: PDSA; const p: PPBIGNUM; const q: PPBIGNUM; const g: PPBIGNUM) cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_set0_pqg}
  function DSA_set0_pqg(d: PDSA; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_get0_key}
  procedure DSA_get0_key(const d: PDSA; const pub_key: PPBIGNUM; const priv_key: PPBIGNUM) cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_set0_key}
  function DSA_set0_key(d: PDSA; pub_key: PBIGNUM; priv_key: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_get0_p}
  function DSA_get0_p(const d: PDSA): PBIGNUM cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_get0_q}
  function DSA_get0_q(const d: PDSA): PBIGNUM cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_get0_g}
  function DSA_get0_g(const d: PDSA): PBIGNUM cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_get0_pub_key}
  function DSA_get0_pub_key(const d: PDSA): PBIGNUM cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_get0_priv_key}
  function DSA_get0_priv_key(const d: PDSA): PBIGNUM cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_clear_flags}
  procedure DSA_clear_flags(d: PDSA; flags: TIdC_INT) cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_test_flags}
  function DSA_test_flags(const d: PDSA; flags: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_set_flags}
  procedure DSA_set_flags(d: PDSA; flags: TIdC_INT) cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_get0_engine}
  function DSA_get0_engine(d: PDSA): PENGINE cdecl; external CLibCrypto;
  
  {$EXTERNALSYM DSA_meth_new}
  function DSA_meth_new(const name: PIdAnsiChar; flags: TIdC_INT): PDSA_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_free}
  procedure DSA_meth_free(dsam: PDSA_METHOD) cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_dup}
  function DSA_meth_dup(const dsam: PDSA_METHOD): PDSA_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_get0_name}
  function DSA_meth_get0_name(const dsam: PDSA_METHOD): PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_set1_name}
  function DSA_meth_set1_name(dsam: PDSA_METHOD; const name: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_get_flags}
  function DSA_meth_get_flags(const dsam: PDSA_METHOD): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_set_flags}
  function DSA_meth_set_flags(dsam: PDSA_METHOD; flags: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_get0_app_data}
  function DSA_meth_get0_app_data(const dsam: PDSA_METHOD): Pointer cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_set0_app_data}
  function DSA_meth_set0_app_data(dsam: PDSA_METHOD; app_data: Pointer): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_get_sign}
  function DSA_meth_get_sign(const dsam: PDSA_METHOD): DSA_meth_sign_cb cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_set_sign}
  function DSA_meth_set_sign(dsam: PDSA_METHOD; sign: DSA_meth_sign_cb): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_get_sign_setup}
  function DSA_meth_get_sign_setup(const dsam: PDSA_METHOD): DSA_meth_sign_setup_cb cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_set_sign_setup}
  function DSA_meth_set_sign_setup(dsam: PDSA_METHOD; sign_setup: DSA_meth_sign_setup_cb): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_get_verify}
  function DSA_meth_get_verify(const dsam: PDSA_METHOD): DSA_meth_verify_cb cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_set_verify}
  function DSA_meth_set_verify(dsam: PDSA_METHOD; verify: DSA_meth_verify_cb): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_get_mod_exp}
  function DSA_meth_get_mod_exp(const dsam: PDSA_METHOD): DSA_meth_mod_exp_cb cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_set_mod_exp}
  function DSA_meth_set_mod_exp(dsam: PDSA_METHOD; mod_exp: DSA_meth_mod_exp_cb): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_get_bn_mod_exp}
  function DSA_meth_get_bn_mod_exp(const dsam: PDSA_METHOD): DSA_meth_bn_mod_exp_cb cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_set_bn_mod_exp}
  function DSA_meth_set_bn_mod_exp(dsam: PDSA_METHOD; bn_mod_exp: DSA_meth_bn_mod_exp_cb): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_get_init}
  function DSA_meth_get_init(const dsam: PDSA_METHOD): DSA_meth_init_cb cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_set_init}
  function DSA_meth_set_init(dsam: PDSA_METHOD; init: DSA_meth_init_cb): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_get_finish}
  function DSA_meth_get_finish(const dsam: PDSA_METHOD): DSA_meth_finish_cb cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_set_finish}
  function DSA_meth_set_finish(dsam: PDSA_METHOD; finish: DSA_meth_finish_cb): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_get_paramgen}
  function DSA_meth_get_paramgen(const dsam: PDSA_METHOD): DSA_meth_paramgen_cb cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_set_paramgen}
  function DSA_meth_set_paramgen(dsam: PDSA_METHOD; paramgen: DSA_meth_paramgen_cb): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_get_keygen}
  function DSA_meth_get_keygen(const dsam: PDSA_METHOD): DSA_meth_keygen_cb cdecl; external CLibCrypto;
  {$EXTERNALSYM DSA_meth_set_keygen}
  function DSA_meth_set_keygen(dsam: PDSA_METHOD; keygen: DSA_meth_keygen_cb): TIdC_INT cdecl; external CLibCrypto;

{$ENDIF}

  {$EXTERNALSYM DSA_get_ex_new_index}
function DSA_get_ex_new_index(l : TIdC_LONG; p : PDSA;
    newf : CRYPTO_EX_new; dupf : CRYPTO_EX_dup; freef : CRYPTO_EX_FREE) : TIdC_INT;


implementation

  uses
    classes, 
    TaurusTLSExceptionHandlers
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    ,TaurusTLSLoader
  {$ENDIF};
  
  //#define DSA_get_ex_new_index(l, p, newf, dupf, freef) \
  //    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DSA, l, p, newf, dupf, freef)
function DSA_get_ex_new_index(l : TIdC_LONG; p : PDSA;
    newf : CRYPTO_EX_new; dupf : CRYPTO_EX_dup; freef : CRYPTO_EX_FREE) : TIdC_INT;
{$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DSA, l, p, newf, dupf, freef);
end;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
const
  DSAparams_dup_procname = 'DSAparams_dup';
  DSA_SIG_new_procname = 'DSA_SIG_new';
  DSA_SIG_free_procname = 'DSA_SIG_free';
  i2d_DSA_SIG_procname = 'i2d_DSA_SIG';
  d2i_DSA_SIG_procname = 'd2i_DSA_SIG';
  DSA_SIG_get0_procname = 'DSA_SIG_get0';
  DSA_SIG_set0_procname = 'DSA_SIG_set0';
  
  DSA_do_sign_procname = 'DSA_do_sign';
  DSA_do_verify_procname = 'DSA_do_verify';
  
  DSA_TaurusTLS_procname = 'DSA_TaurusTLS';
  DSA_set_default_method_procname = 'DSA_set_default_method';
  DSA_get_default_method_procname = 'DSA_get_default_method';
  DSA_set_method_procname = 'DSA_set_method';
  DSA_get_method_procname = 'DSA_get_method';

  DSA_new_procname = 'DSA_new';
  DSA_new_method_procname = 'DSA_new_method';
  DSA_free_procname = 'DSA_free';
  (* "up" the DSA object's reference count *)
  DSA_up_ref_procname = 'DSA_up_ref';
  DSA_size_procname = 'DSA_size';
  DSA_bits_procname = 'DSA_bits';
  DSA_security_bits_procname = 'DSA_security_bits';
  DSA_sign_procname = 'DSA_sign';
  DSA_verify_procname = 'DSA_verify';
  //#define DSA_get_ex_new_index(l, p, newf, dupf, freef) \
  //    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DSA, l, p, newf, dupf, freef)
  DSA_set_ex_data_procname = 'DSA_set_ex_data';
  DSA_get_ex_data_procname = 'DSA_get_ex_data';
  
  d2i_DSAPublicKey_procname = 'd2i_DSAPublicKey';
  d2i_DSAPrivateKey_procname = 'd2i_DSAPrivateKey';
  d2i_DSAparams_procname = 'd2i_DSAparams';

  DSA_generate_parameters_ex_procname = 'DSA_generate_parameters_ex';

  DSA_generate_key_procname = 'DSA_generate_key';
  i2d_DSAPublicKey_procname = 'i2d_DSAPublicKey';
  i2d_DSAPrivateKey_procname = 'i2d_DSAPrivateKey';
  i2d_DSAparams_procname = 'i2d_DSAparams';
  
  DSAparams_print_procname = 'DSAparams_print';
  DSA_print_procname = 'DSA_print';
//  function DSAparams_print_fp(fp: PFile; const x: PDSA): TIdC_INT;
//  function DSA_print_fp(bp: PFile; const x: PDSA; off: TIdC_INT): TIdC_INT;

  //# define DSA_is_prime(n, callback, cb_arg) \
  //        BN_is_prime(n, DSS_prime_checks, callback, NULL, cb_arg)

  (*
   * Convert DSA structure (key or just parameters) into DH structure (be
   * careful to avoid small subgroup attacks when using this!)
   *)
  DSA_dup_DH_procname = 'DSA_dup_DH';

  //# define EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, nbits) \
  //        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN, \
  //                                EVP_PKEY_CTRL_DSA_PARAMGEN_BITS, nbits, NULL)
  //# define EVP_PKEY_CTX_set_dsa_paramgen_q_bits(ctx, qbits) \
  //        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN, \
  //                                EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS, qbits, NULL)
  //# define EVP_PKEY_CTX_set_dsa_paramgen_md(ctx, md) \
  //        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN, \
  //                                EVP_PKEY_CTRL_DSA_PARAMGEN_MD, 0, (void *)(md))

  DSA_get0_pqg_procname = 'DSA_get0_pqg';
  DSA_set0_pqg_procname = 'DSA_set0_pqg';
  DSA_get0_key_procname = 'DSA_get0_key';
  DSA_set0_key_procname = 'DSA_set0_key';
  DSA_get0_p_procname = 'DSA_get0_p';
  DSA_get0_q_procname = 'DSA_get0_q';
  DSA_get0_g_procname = 'DSA_get0_g';
  DSA_get0_pub_key_procname = 'DSA_get0_pub_key';
  DSA_get0_priv_key_procname = 'DSA_get0_priv_key';
  DSA_clear_flags_procname = 'DSA_clear_flags';
  DSA_test_flags_procname = 'DSA_test_flags';
  DSA_set_flags_procname = 'DSA_set_flags';
  DSA_get0_engine_procname = 'DSA_get0_engine';
  
  DSA_meth_new_procname = 'DSA_meth_new';
  DSA_meth_free_procname = 'DSA_meth_free';
  DSA_meth_dup_procname = 'DSA_meth_dup';
  DSA_meth_get0_name_procname = 'DSA_meth_get0_name';
  DSA_meth_set1_name_procname = 'DSA_meth_set1_name';
  DSA_meth_get_flags_procname = 'DSA_meth_get_flags';
  DSA_meth_set_flags_procname = 'DSA_meth_set_flags';
  DSA_meth_get0_app_data_procname = 'DSA_meth_get0_app_data';
  DSA_meth_set0_app_data_procname = 'DSA_meth_set0_app_data';
  DSA_meth_get_sign_procname = 'DSA_meth_get_sign';
  DSA_meth_set_sign_procname = 'DSA_meth_set_sign';
  DSA_meth_get_sign_setup_procname = 'DSA_meth_get_sign_setup';
  DSA_meth_set_sign_setup_procname = 'DSA_meth_set_sign_setup';
  DSA_meth_get_verify_procname = 'DSA_meth_get_verify';
  DSA_meth_set_verify_procname = 'DSA_meth_set_verify';
  DSA_meth_get_mod_exp_procname = 'DSA_meth_get_mod_exp';
  DSA_meth_set_mod_exp_procname = 'DSA_meth_set_mod_exp';
  DSA_meth_get_bn_mod_exp_procname = 'DSA_meth_get_bn_mod_exp';
  DSA_meth_set_bn_mod_exp_procname = 'DSA_meth_set_bn_mod_exp';
  DSA_meth_get_init_procname = 'DSA_meth_get_init';
  DSA_meth_set_init_procname = 'DSA_meth_set_init';
  DSA_meth_get_finish_procname = 'DSA_meth_get_finish';
  DSA_meth_set_finish_procname = 'DSA_meth_set_finish';
  DSA_meth_get_paramgen_procname = 'DSA_meth_get_paramgen';
  DSA_meth_set_paramgen_procname = 'DSA_meth_set_paramgen';
  DSA_meth_get_keygen_procname = 'DSA_meth_get_keygen';
  DSA_meth_set_keygen_procname = 'DSA_meth_set_keygen';

   {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_DSAparams_dup(x: PDSA): PDSA; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSAparams_dup_procname);
end;


function  ERR_DSA_SIG_new: PDSA_SIG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_SIG_new_procname);
end;


procedure  ERR_DSA_SIG_free(a: PDSA_SIG); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_SIG_free_procname);
end;


function  ERR_i2d_DSA_SIG(const a: PDSA_SIG; pp: PPByte): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_DSA_SIG_procname);
end;


function  ERR_d2i_DSA_SIG(v: PPDSA_SIG; const pp: PPByte; _length: TIdC_LONG): PDSA_SIG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_DSA_SIG_procname);
end;


procedure  ERR_DSA_SIG_get0(const sig: PDSA_SIG; const pr: PPBIGNUM; const ps: PPBIGNUM); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_SIG_get0_procname);
end;


function  ERR_DSA_SIG_set0(sig: PDSA_SIG; r: PBIGNUM; s: PBIGNUM): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_SIG_set0_procname);
end;



function  ERR_DSA_do_sign(const dgst: PByte; dlen: TIdC_INT; dsa: PDSA): PDSA_SIG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_do_sign_procname);
end;


function  ERR_DSA_do_verify(const dgst: PByte; dgst_len: TIdC_INT; sig: PDSA_SIG; dsa: PDSA): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_do_verify_procname);
end;



function  ERR_DSA_TaurusTLS: PDSA_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_TaurusTLS_procname);
end;


procedure  ERR_DSA_set_default_method(const v1: PDSA_METHOD); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_set_default_method_procname);
end;


function  ERR_DSA_get_default_method: PDSA_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_get_default_method_procname);
end;


function  ERR_DSA_set_method(dsa: PDSA; const v1: PDSA_METHOD): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_set_method_procname);
end;


function  ERR_DSA_get_method(d: PDSA): PDSA_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_get_method_procname);
end;



function  ERR_DSA_new: PDSA; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_new_procname);
end;


function  ERR_DSA_new_method(engine: PENGINE): PDSA; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_new_method_procname);
end;


procedure  ERR_DSA_free(r: PDSA); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_free_procname);
end;


  (* "up" the DSA object's reference count *)
function  ERR_DSA_up_ref(r: PDSA): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_up_ref_procname);
end;


function  ERR_DSA_size(const v1: PDSA): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_size_procname);
end;


function  ERR_DSA_bits(const d: PDSA): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_bits_procname);
end;


function  ERR_DSA_security_bits(const d: PDSA): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_security_bits_procname);
end;


function  ERR_DSA_sign(type_: TIdC_INT; const dgst: PByte; dlen: TIdC_INT; sig: PByte;
  siglen: PIdC_UINT; dsa: PDSA): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_sign_procname);
end;


function  ERR_DSA_verify(type_: TIdC_INT; const dgst: PByte; dgst_len: TIdC_INT; const sigbuf: PByte;
  siglen: TIdC_INT; dsa: PDSA): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_verify_procname);
end;


function  ERR_DSA_set_ex_data(d: PDSA; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_set_ex_data_procname);
end;


function  ERR_DSA_get_ex_data(d: PDSA; idx: TIdC_INT): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_get_ex_data_procname);
end;



function  ERR_d2i_DSAPublicKey(a: PPDSA; const pp: PPByte; _length: TIdC_LONG): PDSA; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_DSAPublicKey_procname);
end;


function  ERR_d2i_DSAPrivateKey(a: PPDSA; const pp: PPByte; _length: TIdC_LONG): PDSA; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_DSAPrivateKey_procname);
end;


function  ERR_d2i_DSAparams(a: PPDSA; const pp: PPByte; _length: TIdC_LONG): PDSA; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_DSAparams_procname);
end;



function  ERR_DSA_generate_parameters_ex(dsa: PDSA; bits: TIdC_INT; const seed: PByte; seed_len: TIdC_INT;
  counter_ret: PIdC_INT; h_ret: PIdC_ULONG; cb: PBN_GENCB): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_generate_parameters_ex_procname);
end;



function  ERR_DSA_generate_key(a: PDSA): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_generate_key_procname);
end;


function  ERR_i2d_DSAPublicKey(const a: PDSA; pp: PPByte): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_DSAPublicKey_procname);
end;


function  ERR_i2d_DSAPrivateKey(const a: PDSA; pp: PPByte): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_DSAPrivateKey_procname);
end;


function  ERR_i2d_DSAparams(const a: PDSA; pp: PPByte): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_DSAparams_procname);
end;



function  ERR_DSAparams_print(bp: PBIO; const x: PDSA): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSAparams_print_procname);
end;


function  ERR_DSA_print(bp: PBIO; const x: PDSA; off: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_print_procname);
end;


//  function DSAparams_print_fp(fp: PFile; const x: PDSA): TIdC_INT;
//  function DSA_print_fp(bp: PFile; const x: PDSA; off: TIdC_INT): TIdC_INT;

  //# define DSA_is_prime(n, callback, cb_arg) \
  //        BN_is_prime(n, DSS_prime_checks, callback, NULL, cb_arg)

  (*
   * Convert DSA structure (key or just parameters) into DH structure (be
   * careful to avoid small subgroup attacks when using this!)
   *)
function  ERR_DSA_dup_DH(const r: PDSA): PDH; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_dup_DH_procname);
end;



  //# define EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, nbits) \
  //        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN, \
  //                                EVP_PKEY_CTRL_DSA_PARAMGEN_BITS, nbits, NULL)
  //# define EVP_PKEY_CTX_set_dsa_paramgen_q_bits(ctx, qbits) \
  //        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN, \
  //                                EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS, qbits, NULL)
  //# define EVP_PKEY_CTX_set_dsa_paramgen_md(ctx, md) \
  //        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN, \
  //                                EVP_PKEY_CTRL_DSA_PARAMGEN_MD, 0, (void *)(md))

procedure  ERR_DSA_get0_pqg(const d: PDSA; const p: PPBIGNUM; const q: PPBIGNUM; const g: PPBIGNUM); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_get0_pqg_procname);
end;


function  ERR_DSA_set0_pqg(d: PDSA; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_set0_pqg_procname);
end;


procedure  ERR_DSA_get0_key(const d: PDSA; const pub_key: PPBIGNUM; const priv_key: PPBIGNUM); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_get0_key_procname);
end;


function  ERR_DSA_set0_key(d: PDSA; pub_key: PBIGNUM; priv_key: PBIGNUM): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_set0_key_procname);
end;


function  ERR_DSA_get0_p(const d: PDSA): PBIGNUM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_get0_p_procname);
end;


function  ERR_DSA_get0_q(const d: PDSA): PBIGNUM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_get0_q_procname);
end;


function  ERR_DSA_get0_g(const d: PDSA): PBIGNUM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_get0_g_procname);
end;


function  ERR_DSA_get0_pub_key(const d: PDSA): PBIGNUM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_get0_pub_key_procname);
end;


function  ERR_DSA_get0_priv_key(const d: PDSA): PBIGNUM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_get0_priv_key_procname);
end;


procedure  ERR_DSA_clear_flags(d: PDSA; flags: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_clear_flags_procname);
end;


function  ERR_DSA_test_flags(const d: PDSA; flags: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_test_flags_procname);
end;


procedure  ERR_DSA_set_flags(d: PDSA; flags: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_set_flags_procname);
end;


function  ERR_DSA_get0_engine(d: PDSA): PENGINE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_get0_engine_procname);
end;



function  ERR_DSA_meth_new(const name: PIdAnsiChar; flags: TIdC_INT): PDSA_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_new_procname);
end;


procedure  ERR_DSA_meth_free(dsam: PDSA_METHOD); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_free_procname);
end;


function  ERR_DSA_meth_dup(const dsam: PDSA_METHOD): PDSA_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_dup_procname);
end;


function  ERR_DSA_meth_get0_name(const dsam: PDSA_METHOD): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_get0_name_procname);
end;


function  ERR_DSA_meth_set1_name(dsam: PDSA_METHOD; const name: PIdAnsiChar): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_set1_name_procname);
end;


function  ERR_DSA_meth_get_flags(const dsam: PDSA_METHOD): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_get_flags_procname);
end;


function  ERR_DSA_meth_set_flags(dsam: PDSA_METHOD; flags: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_set_flags_procname);
end;


function  ERR_DSA_meth_get0_app_data(const dsam: PDSA_METHOD): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_get0_app_data_procname);
end;


function  ERR_DSA_meth_set0_app_data(dsam: PDSA_METHOD; app_data: Pointer): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_set0_app_data_procname);
end;


function  ERR_DSA_meth_get_sign(const dsam: PDSA_METHOD): DSA_meth_sign_cb; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_get_sign_procname);
end;


function  ERR_DSA_meth_set_sign(dsam: PDSA_METHOD; sign: DSA_meth_sign_cb): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_set_sign_procname);
end;


function  ERR_DSA_meth_get_sign_setup(const dsam: PDSA_METHOD): DSA_meth_sign_setup_cb; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_get_sign_setup_procname);
end;


function  ERR_DSA_meth_set_sign_setup(dsam: PDSA_METHOD; sign_setup: DSA_meth_sign_setup_cb): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_set_sign_setup_procname);
end;


function  ERR_DSA_meth_get_verify(const dsam: PDSA_METHOD): DSA_meth_verify_cb; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_get_verify_procname);
end;


function  ERR_DSA_meth_set_verify(dsam: PDSA_METHOD; verify: DSA_meth_verify_cb): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_set_verify_procname);
end;


function  ERR_DSA_meth_get_mod_exp(const dsam: PDSA_METHOD): DSA_meth_mod_exp_cb; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_get_mod_exp_procname);
end;


function  ERR_DSA_meth_set_mod_exp(dsam: PDSA_METHOD; mod_exp: DSA_meth_mod_exp_cb): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_set_mod_exp_procname);
end;


function  ERR_DSA_meth_get_bn_mod_exp(const dsam: PDSA_METHOD): DSA_meth_bn_mod_exp_cb; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_get_bn_mod_exp_procname);
end;


function  ERR_DSA_meth_set_bn_mod_exp(dsam: PDSA_METHOD; bn_mod_exp: DSA_meth_bn_mod_exp_cb): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_set_bn_mod_exp_procname);
end;


function  ERR_DSA_meth_get_init(const dsam: PDSA_METHOD): DSA_meth_init_cb; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_get_init_procname);
end;


function  ERR_DSA_meth_set_init(dsam: PDSA_METHOD; init: DSA_meth_init_cb): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_set_init_procname);
end;


function  ERR_DSA_meth_get_finish(const dsam: PDSA_METHOD): DSA_meth_finish_cb; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_get_finish_procname);
end;


function  ERR_DSA_meth_set_finish(dsam: PDSA_METHOD; finish: DSA_meth_finish_cb): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_set_finish_procname);
end;


function  ERR_DSA_meth_get_paramgen(const dsam: PDSA_METHOD): DSA_meth_paramgen_cb; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_get_paramgen_procname);
end;


function  ERR_DSA_meth_set_paramgen(dsam: PDSA_METHOD; paramgen: DSA_meth_paramgen_cb): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_set_paramgen_procname);
end;


function  ERR_DSA_meth_get_keygen(const dsam: PDSA_METHOD): DSA_meth_keygen_cb; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_get_keygen_procname);
end;


function  ERR_DSA_meth_set_keygen(dsam: PDSA_METHOD; keygen: DSA_meth_keygen_cb): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DSA_meth_set_keygen_procname);
end;



  {$I TaurusTLSNoRetValOn.inc} 
  {$I TaurusTLSUnusedParamOff.inc}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  DSAparams_dup := LoadLibFunction(ADllHandle, DSAparams_dup_procname);
  FuncLoadError := not assigned(DSAparams_dup);
  if FuncLoadError then
  begin
    {$if not defined(DSAparams_dup_allownil)}
    DSAparams_dup := ERR_DSAparams_dup;
    {$ifend}
    {$if declared(DSAparams_dup_introduced)}
    if LibVersion < DSAparams_dup_introduced then
    begin
      {$if declared(FC_DSAparams_dup)}
      DSAparams_dup := FC_DSAparams_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSAparams_dup_removed)}
    if DSAparams_dup_removed <= LibVersion then
    begin
      {$if declared(_DSAparams_dup)}
      DSAparams_dup := _DSAparams_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSAparams_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('DSAparams_dup');
    {$ifend}
  end;


  DSA_SIG_new := LoadLibFunction(ADllHandle, DSA_SIG_new_procname);
  FuncLoadError := not assigned(DSA_SIG_new);
  if FuncLoadError then
  begin
    {$if not defined(DSA_SIG_new_allownil)}
    DSA_SIG_new := ERR_DSA_SIG_new;
    {$ifend}
    {$if declared(DSA_SIG_new_introduced)}
    if LibVersion < DSA_SIG_new_introduced then
    begin
      {$if declared(FC_DSA_SIG_new)}
      DSA_SIG_new := FC_DSA_SIG_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_SIG_new_removed)}
    if DSA_SIG_new_removed <= LibVersion then
    begin
      {$if declared(_DSA_SIG_new)}
      DSA_SIG_new := _DSA_SIG_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_SIG_new_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_SIG_new');
    {$ifend}
  end;


  DSA_SIG_free := LoadLibFunction(ADllHandle, DSA_SIG_free_procname);
  FuncLoadError := not assigned(DSA_SIG_free);
  if FuncLoadError then
  begin
    {$if not defined(DSA_SIG_free_allownil)}
    DSA_SIG_free := ERR_DSA_SIG_free;
    {$ifend}
    {$if declared(DSA_SIG_free_introduced)}
    if LibVersion < DSA_SIG_free_introduced then
    begin
      {$if declared(FC_DSA_SIG_free)}
      DSA_SIG_free := FC_DSA_SIG_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_SIG_free_removed)}
    if DSA_SIG_free_removed <= LibVersion then
    begin
      {$if declared(_DSA_SIG_free)}
      DSA_SIG_free := _DSA_SIG_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_SIG_free_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_SIG_free');
    {$ifend}
  end;


  i2d_DSA_SIG := LoadLibFunction(ADllHandle, i2d_DSA_SIG_procname);
  FuncLoadError := not assigned(i2d_DSA_SIG);
  if FuncLoadError then
  begin
    {$if not defined(i2d_DSA_SIG_allownil)}
    i2d_DSA_SIG := ERR_i2d_DSA_SIG;
    {$ifend}
    {$if declared(i2d_DSA_SIG_introduced)}
    if LibVersion < i2d_DSA_SIG_introduced then
    begin
      {$if declared(FC_i2d_DSA_SIG)}
      i2d_DSA_SIG := FC_i2d_DSA_SIG;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_DSA_SIG_removed)}
    if i2d_DSA_SIG_removed <= LibVersion then
    begin
      {$if declared(_i2d_DSA_SIG)}
      i2d_DSA_SIG := _i2d_DSA_SIG;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_DSA_SIG_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_DSA_SIG');
    {$ifend}
  end;


  d2i_DSA_SIG := LoadLibFunction(ADllHandle, d2i_DSA_SIG_procname);
  FuncLoadError := not assigned(d2i_DSA_SIG);
  if FuncLoadError then
  begin
    {$if not defined(d2i_DSA_SIG_allownil)}
    d2i_DSA_SIG := ERR_d2i_DSA_SIG;
    {$ifend}
    {$if declared(d2i_DSA_SIG_introduced)}
    if LibVersion < d2i_DSA_SIG_introduced then
    begin
      {$if declared(FC_d2i_DSA_SIG)}
      d2i_DSA_SIG := FC_d2i_DSA_SIG;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_DSA_SIG_removed)}
    if d2i_DSA_SIG_removed <= LibVersion then
    begin
      {$if declared(_d2i_DSA_SIG)}
      d2i_DSA_SIG := _d2i_DSA_SIG;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_DSA_SIG_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_DSA_SIG');
    {$ifend}
  end;


  DSA_SIG_get0 := LoadLibFunction(ADllHandle, DSA_SIG_get0_procname);
  FuncLoadError := not assigned(DSA_SIG_get0);
  if FuncLoadError then
  begin
    {$if not defined(DSA_SIG_get0_allownil)}
    DSA_SIG_get0 := ERR_DSA_SIG_get0;
    {$ifend}
    {$if declared(DSA_SIG_get0_introduced)}
    if LibVersion < DSA_SIG_get0_introduced then
    begin
      {$if declared(FC_DSA_SIG_get0)}
      DSA_SIG_get0 := FC_DSA_SIG_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_SIG_get0_removed)}
    if DSA_SIG_get0_removed <= LibVersion then
    begin
      {$if declared(_DSA_SIG_get0)}
      DSA_SIG_get0 := _DSA_SIG_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_SIG_get0_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_SIG_get0');
    {$ifend}
  end;


  DSA_SIG_set0 := LoadLibFunction(ADllHandle, DSA_SIG_set0_procname);
  FuncLoadError := not assigned(DSA_SIG_set0);
  if FuncLoadError then
  begin
    {$if not defined(DSA_SIG_set0_allownil)}
    DSA_SIG_set0 := ERR_DSA_SIG_set0;
    {$ifend}
    {$if declared(DSA_SIG_set0_introduced)}
    if LibVersion < DSA_SIG_set0_introduced then
    begin
      {$if declared(FC_DSA_SIG_set0)}
      DSA_SIG_set0 := FC_DSA_SIG_set0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_SIG_set0_removed)}
    if DSA_SIG_set0_removed <= LibVersion then
    begin
      {$if declared(_DSA_SIG_set0)}
      DSA_SIG_set0 := _DSA_SIG_set0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_SIG_set0_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_SIG_set0');
    {$ifend}
  end;


  DSA_do_sign := LoadLibFunction(ADllHandle, DSA_do_sign_procname);
  FuncLoadError := not assigned(DSA_do_sign);
  if FuncLoadError then
  begin
    {$if not defined(DSA_do_sign_allownil)}
    DSA_do_sign := ERR_DSA_do_sign;
    {$ifend}
    {$if declared(DSA_do_sign_introduced)}
    if LibVersion < DSA_do_sign_introduced then
    begin
      {$if declared(FC_DSA_do_sign)}
      DSA_do_sign := FC_DSA_do_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_do_sign_removed)}
    if DSA_do_sign_removed <= LibVersion then
    begin
      {$if declared(_DSA_do_sign)}
      DSA_do_sign := _DSA_do_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_do_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_do_sign');
    {$ifend}
  end;


  DSA_do_verify := LoadLibFunction(ADllHandle, DSA_do_verify_procname);
  FuncLoadError := not assigned(DSA_do_verify);
  if FuncLoadError then
  begin
    {$if not defined(DSA_do_verify_allownil)}
    DSA_do_verify := ERR_DSA_do_verify;
    {$ifend}
    {$if declared(DSA_do_verify_introduced)}
    if LibVersion < DSA_do_verify_introduced then
    begin
      {$if declared(FC_DSA_do_verify)}
      DSA_do_verify := FC_DSA_do_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_do_verify_removed)}
    if DSA_do_verify_removed <= LibVersion then
    begin
      {$if declared(_DSA_do_verify)}
      DSA_do_verify := _DSA_do_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_do_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_do_verify');
    {$ifend}
  end;


  DSA_TaurusTLS := LoadLibFunction(ADllHandle, DSA_TaurusTLS_procname);
  FuncLoadError := not assigned(DSA_TaurusTLS);
  if FuncLoadError then
  begin
    {$if not defined(DSA_TaurusTLS_allownil)}
    DSA_TaurusTLS := ERR_DSA_TaurusTLS;
    {$ifend}
    {$if declared(DSA_TaurusTLS_introduced)}
    if LibVersion < DSA_TaurusTLS_introduced then
    begin
      {$if declared(FC_DSA_TaurusTLS)}
      DSA_TaurusTLS := FC_DSA_TaurusTLS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_TaurusTLS_removed)}
    if DSA_TaurusTLS_removed <= LibVersion then
    begin
      {$if declared(_DSA_TaurusTLS)}
      DSA_TaurusTLS := _DSA_TaurusTLS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_TaurusTLS_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_TaurusTLS');
    {$ifend}
  end;


  DSA_set_default_method := LoadLibFunction(ADllHandle, DSA_set_default_method_procname);
  FuncLoadError := not assigned(DSA_set_default_method);
  if FuncLoadError then
  begin
    {$if not defined(DSA_set_default_method_allownil)}
    DSA_set_default_method := ERR_DSA_set_default_method;
    {$ifend}
    {$if declared(DSA_set_default_method_introduced)}
    if LibVersion < DSA_set_default_method_introduced then
    begin
      {$if declared(FC_DSA_set_default_method)}
      DSA_set_default_method := FC_DSA_set_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_set_default_method_removed)}
    if DSA_set_default_method_removed <= LibVersion then
    begin
      {$if declared(_DSA_set_default_method)}
      DSA_set_default_method := _DSA_set_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_set_default_method_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_set_default_method');
    {$ifend}
  end;


  DSA_get_default_method := LoadLibFunction(ADllHandle, DSA_get_default_method_procname);
  FuncLoadError := not assigned(DSA_get_default_method);
  if FuncLoadError then
  begin
    {$if not defined(DSA_get_default_method_allownil)}
    DSA_get_default_method := ERR_DSA_get_default_method;
    {$ifend}
    {$if declared(DSA_get_default_method_introduced)}
    if LibVersion < DSA_get_default_method_introduced then
    begin
      {$if declared(FC_DSA_get_default_method)}
      DSA_get_default_method := FC_DSA_get_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_get_default_method_removed)}
    if DSA_get_default_method_removed <= LibVersion then
    begin
      {$if declared(_DSA_get_default_method)}
      DSA_get_default_method := _DSA_get_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_get_default_method_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_get_default_method');
    {$ifend}
  end;


  DSA_set_method := LoadLibFunction(ADllHandle, DSA_set_method_procname);
  FuncLoadError := not assigned(DSA_set_method);
  if FuncLoadError then
  begin
    {$if not defined(DSA_set_method_allownil)}
    DSA_set_method := ERR_DSA_set_method;
    {$ifend}
    {$if declared(DSA_set_method_introduced)}
    if LibVersion < DSA_set_method_introduced then
    begin
      {$if declared(FC_DSA_set_method)}
      DSA_set_method := FC_DSA_set_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_set_method_removed)}
    if DSA_set_method_removed <= LibVersion then
    begin
      {$if declared(_DSA_set_method)}
      DSA_set_method := _DSA_set_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_set_method_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_set_method');
    {$ifend}
  end;


  DSA_get_method := LoadLibFunction(ADllHandle, DSA_get_method_procname);
  FuncLoadError := not assigned(DSA_get_method);
  if FuncLoadError then
  begin
    {$if not defined(DSA_get_method_allownil)}
    DSA_get_method := ERR_DSA_get_method;
    {$ifend}
    {$if declared(DSA_get_method_introduced)}
    if LibVersion < DSA_get_method_introduced then
    begin
      {$if declared(FC_DSA_get_method)}
      DSA_get_method := FC_DSA_get_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_get_method_removed)}
    if DSA_get_method_removed <= LibVersion then
    begin
      {$if declared(_DSA_get_method)}
      DSA_get_method := _DSA_get_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_get_method_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_get_method');
    {$ifend}
  end;


  DSA_new := LoadLibFunction(ADllHandle, DSA_new_procname);
  FuncLoadError := not assigned(DSA_new);
  if FuncLoadError then
  begin
    {$if not defined(DSA_new_allownil)}
    DSA_new := ERR_DSA_new;
    {$ifend}
    {$if declared(DSA_new_introduced)}
    if LibVersion < DSA_new_introduced then
    begin
      {$if declared(FC_DSA_new)}
      DSA_new := FC_DSA_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_new_removed)}
    if DSA_new_removed <= LibVersion then
    begin
      {$if declared(_DSA_new)}
      DSA_new := _DSA_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_new_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_new');
    {$ifend}
  end;


  DSA_new_method := LoadLibFunction(ADllHandle, DSA_new_method_procname);
  FuncLoadError := not assigned(DSA_new_method);
  if FuncLoadError then
  begin
    {$if not defined(DSA_new_method_allownil)}
    DSA_new_method := ERR_DSA_new_method;
    {$ifend}
    {$if declared(DSA_new_method_introduced)}
    if LibVersion < DSA_new_method_introduced then
    begin
      {$if declared(FC_DSA_new_method)}
      DSA_new_method := FC_DSA_new_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_new_method_removed)}
    if DSA_new_method_removed <= LibVersion then
    begin
      {$if declared(_DSA_new_method)}
      DSA_new_method := _DSA_new_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_new_method_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_new_method');
    {$ifend}
  end;


  DSA_free := LoadLibFunction(ADllHandle, DSA_free_procname);
  FuncLoadError := not assigned(DSA_free);
  if FuncLoadError then
  begin
    {$if not defined(DSA_free_allownil)}
    DSA_free := ERR_DSA_free;
    {$ifend}
    {$if declared(DSA_free_introduced)}
    if LibVersion < DSA_free_introduced then
    begin
      {$if declared(FC_DSA_free)}
      DSA_free := FC_DSA_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_free_removed)}
    if DSA_free_removed <= LibVersion then
    begin
      {$if declared(_DSA_free)}
      DSA_free := _DSA_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_free_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_free');
    {$ifend}
  end;


  DSA_up_ref := LoadLibFunction(ADllHandle, DSA_up_ref_procname);
  FuncLoadError := not assigned(DSA_up_ref);
  if FuncLoadError then
  begin
    {$if not defined(DSA_up_ref_allownil)}
    DSA_up_ref := ERR_DSA_up_ref;
    {$ifend}
    {$if declared(DSA_up_ref_introduced)}
    if LibVersion < DSA_up_ref_introduced then
    begin
      {$if declared(FC_DSA_up_ref)}
      DSA_up_ref := FC_DSA_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_up_ref_removed)}
    if DSA_up_ref_removed <= LibVersion then
    begin
      {$if declared(_DSA_up_ref)}
      DSA_up_ref := _DSA_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_up_ref_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_up_ref');
    {$ifend}
  end;


  DSA_size := LoadLibFunction(ADllHandle, DSA_size_procname);
  FuncLoadError := not assigned(DSA_size);
  if FuncLoadError then
  begin
    {$if not defined(DSA_size_allownil)}
    DSA_size := ERR_DSA_size;
    {$ifend}
    {$if declared(DSA_size_introduced)}
    if LibVersion < DSA_size_introduced then
    begin
      {$if declared(FC_DSA_size)}
      DSA_size := FC_DSA_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_size_removed)}
    if DSA_size_removed <= LibVersion then
    begin
      {$if declared(_DSA_size)}
      DSA_size := _DSA_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_size_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_size');
    {$ifend}
  end;


  DSA_bits := LoadLibFunction(ADllHandle, DSA_bits_procname);
  FuncLoadError := not assigned(DSA_bits);
  if FuncLoadError then
  begin
    {$if not defined(DSA_bits_allownil)}
    DSA_bits := ERR_DSA_bits;
    {$ifend}
    {$if declared(DSA_bits_introduced)}
    if LibVersion < DSA_bits_introduced then
    begin
      {$if declared(FC_DSA_bits)}
      DSA_bits := FC_DSA_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_bits_removed)}
    if DSA_bits_removed <= LibVersion then
    begin
      {$if declared(_DSA_bits)}
      DSA_bits := _DSA_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_bits_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_bits');
    {$ifend}
  end;


  DSA_security_bits := LoadLibFunction(ADllHandle, DSA_security_bits_procname);
  FuncLoadError := not assigned(DSA_security_bits);
  if FuncLoadError then
  begin
    {$if not defined(DSA_security_bits_allownil)}
    DSA_security_bits := ERR_DSA_security_bits;
    {$ifend}
    {$if declared(DSA_security_bits_introduced)}
    if LibVersion < DSA_security_bits_introduced then
    begin
      {$if declared(FC_DSA_security_bits)}
      DSA_security_bits := FC_DSA_security_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_security_bits_removed)}
    if DSA_security_bits_removed <= LibVersion then
    begin
      {$if declared(_DSA_security_bits)}
      DSA_security_bits := _DSA_security_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_security_bits_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_security_bits');
    {$ifend}
  end;


  DSA_sign := LoadLibFunction(ADllHandle, DSA_sign_procname);
  FuncLoadError := not assigned(DSA_sign);
  if FuncLoadError then
  begin
    {$if not defined(DSA_sign_allownil)}
    DSA_sign := ERR_DSA_sign;
    {$ifend}
    {$if declared(DSA_sign_introduced)}
    if LibVersion < DSA_sign_introduced then
    begin
      {$if declared(FC_DSA_sign)}
      DSA_sign := FC_DSA_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_sign_removed)}
    if DSA_sign_removed <= LibVersion then
    begin
      {$if declared(_DSA_sign)}
      DSA_sign := _DSA_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_sign');
    {$ifend}
  end;


  DSA_verify := LoadLibFunction(ADllHandle, DSA_verify_procname);
  FuncLoadError := not assigned(DSA_verify);
  if FuncLoadError then
  begin
    {$if not defined(DSA_verify_allownil)}
    DSA_verify := ERR_DSA_verify;
    {$ifend}
    {$if declared(DSA_verify_introduced)}
    if LibVersion < DSA_verify_introduced then
    begin
      {$if declared(FC_DSA_verify)}
      DSA_verify := FC_DSA_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_verify_removed)}
    if DSA_verify_removed <= LibVersion then
    begin
      {$if declared(_DSA_verify)}
      DSA_verify := _DSA_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_verify');
    {$ifend}
  end;


  DSA_set_ex_data := LoadLibFunction(ADllHandle, DSA_set_ex_data_procname);
  FuncLoadError := not assigned(DSA_set_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(DSA_set_ex_data_allownil)}
    DSA_set_ex_data := ERR_DSA_set_ex_data;
    {$ifend}
    {$if declared(DSA_set_ex_data_introduced)}
    if LibVersion < DSA_set_ex_data_introduced then
    begin
      {$if declared(FC_DSA_set_ex_data)}
      DSA_set_ex_data := FC_DSA_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_set_ex_data_removed)}
    if DSA_set_ex_data_removed <= LibVersion then
    begin
      {$if declared(_DSA_set_ex_data)}
      DSA_set_ex_data := _DSA_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_set_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_set_ex_data');
    {$ifend}
  end;


  DSA_get_ex_data := LoadLibFunction(ADllHandle, DSA_get_ex_data_procname);
  FuncLoadError := not assigned(DSA_get_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(DSA_get_ex_data_allownil)}
    DSA_get_ex_data := ERR_DSA_get_ex_data;
    {$ifend}
    {$if declared(DSA_get_ex_data_introduced)}
    if LibVersion < DSA_get_ex_data_introduced then
    begin
      {$if declared(FC_DSA_get_ex_data)}
      DSA_get_ex_data := FC_DSA_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_get_ex_data_removed)}
    if DSA_get_ex_data_removed <= LibVersion then
    begin
      {$if declared(_DSA_get_ex_data)}
      DSA_get_ex_data := _DSA_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_get_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_get_ex_data');
    {$ifend}
  end;


  d2i_DSAPublicKey := LoadLibFunction(ADllHandle, d2i_DSAPublicKey_procname);
  FuncLoadError := not assigned(d2i_DSAPublicKey);
  if FuncLoadError then
  begin
    {$if not defined(d2i_DSAPublicKey_allownil)}
    d2i_DSAPublicKey := ERR_d2i_DSAPublicKey;
    {$ifend}
    {$if declared(d2i_DSAPublicKey_introduced)}
    if LibVersion < d2i_DSAPublicKey_introduced then
    begin
      {$if declared(FC_d2i_DSAPublicKey)}
      d2i_DSAPublicKey := FC_d2i_DSAPublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_DSAPublicKey_removed)}
    if d2i_DSAPublicKey_removed <= LibVersion then
    begin
      {$if declared(_d2i_DSAPublicKey)}
      d2i_DSAPublicKey := _d2i_DSAPublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_DSAPublicKey_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_DSAPublicKey');
    {$ifend}
  end;


  d2i_DSAPrivateKey := LoadLibFunction(ADllHandle, d2i_DSAPrivateKey_procname);
  FuncLoadError := not assigned(d2i_DSAPrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(d2i_DSAPrivateKey_allownil)}
    d2i_DSAPrivateKey := ERR_d2i_DSAPrivateKey;
    {$ifend}
    {$if declared(d2i_DSAPrivateKey_introduced)}
    if LibVersion < d2i_DSAPrivateKey_introduced then
    begin
      {$if declared(FC_d2i_DSAPrivateKey)}
      d2i_DSAPrivateKey := FC_d2i_DSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_DSAPrivateKey_removed)}
    if d2i_DSAPrivateKey_removed <= LibVersion then
    begin
      {$if declared(_d2i_DSAPrivateKey)}
      d2i_DSAPrivateKey := _d2i_DSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_DSAPrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_DSAPrivateKey');
    {$ifend}
  end;


  d2i_DSAparams := LoadLibFunction(ADllHandle, d2i_DSAparams_procname);
  FuncLoadError := not assigned(d2i_DSAparams);
  if FuncLoadError then
  begin
    {$if not defined(d2i_DSAparams_allownil)}
    d2i_DSAparams := ERR_d2i_DSAparams;
    {$ifend}
    {$if declared(d2i_DSAparams_introduced)}
    if LibVersion < d2i_DSAparams_introduced then
    begin
      {$if declared(FC_d2i_DSAparams)}
      d2i_DSAparams := FC_d2i_DSAparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_DSAparams_removed)}
    if d2i_DSAparams_removed <= LibVersion then
    begin
      {$if declared(_d2i_DSAparams)}
      d2i_DSAparams := _d2i_DSAparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_DSAparams_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_DSAparams');
    {$ifend}
  end;


  DSA_generate_parameters_ex := LoadLibFunction(ADllHandle, DSA_generate_parameters_ex_procname);
  FuncLoadError := not assigned(DSA_generate_parameters_ex);
  if FuncLoadError then
  begin
    {$if not defined(DSA_generate_parameters_ex_allownil)}
    DSA_generate_parameters_ex := ERR_DSA_generate_parameters_ex;
    {$ifend}
    {$if declared(DSA_generate_parameters_ex_introduced)}
    if LibVersion < DSA_generate_parameters_ex_introduced then
    begin
      {$if declared(FC_DSA_generate_parameters_ex)}
      DSA_generate_parameters_ex := FC_DSA_generate_parameters_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_generate_parameters_ex_removed)}
    if DSA_generate_parameters_ex_removed <= LibVersion then
    begin
      {$if declared(_DSA_generate_parameters_ex)}
      DSA_generate_parameters_ex := _DSA_generate_parameters_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_generate_parameters_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_generate_parameters_ex');
    {$ifend}
  end;


  DSA_generate_key := LoadLibFunction(ADllHandle, DSA_generate_key_procname);
  FuncLoadError := not assigned(DSA_generate_key);
  if FuncLoadError then
  begin
    {$if not defined(DSA_generate_key_allownil)}
    DSA_generate_key := ERR_DSA_generate_key;
    {$ifend}
    {$if declared(DSA_generate_key_introduced)}
    if LibVersion < DSA_generate_key_introduced then
    begin
      {$if declared(FC_DSA_generate_key)}
      DSA_generate_key := FC_DSA_generate_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_generate_key_removed)}
    if DSA_generate_key_removed <= LibVersion then
    begin
      {$if declared(_DSA_generate_key)}
      DSA_generate_key := _DSA_generate_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_generate_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_generate_key');
    {$ifend}
  end;


  i2d_DSAPublicKey := LoadLibFunction(ADllHandle, i2d_DSAPublicKey_procname);
  FuncLoadError := not assigned(i2d_DSAPublicKey);
  if FuncLoadError then
  begin
    {$if not defined(i2d_DSAPublicKey_allownil)}
    i2d_DSAPublicKey := ERR_i2d_DSAPublicKey;
    {$ifend}
    {$if declared(i2d_DSAPublicKey_introduced)}
    if LibVersion < i2d_DSAPublicKey_introduced then
    begin
      {$if declared(FC_i2d_DSAPublicKey)}
      i2d_DSAPublicKey := FC_i2d_DSAPublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_DSAPublicKey_removed)}
    if i2d_DSAPublicKey_removed <= LibVersion then
    begin
      {$if declared(_i2d_DSAPublicKey)}
      i2d_DSAPublicKey := _i2d_DSAPublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_DSAPublicKey_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_DSAPublicKey');
    {$ifend}
  end;


  i2d_DSAPrivateKey := LoadLibFunction(ADllHandle, i2d_DSAPrivateKey_procname);
  FuncLoadError := not assigned(i2d_DSAPrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(i2d_DSAPrivateKey_allownil)}
    i2d_DSAPrivateKey := ERR_i2d_DSAPrivateKey;
    {$ifend}
    {$if declared(i2d_DSAPrivateKey_introduced)}
    if LibVersion < i2d_DSAPrivateKey_introduced then
    begin
      {$if declared(FC_i2d_DSAPrivateKey)}
      i2d_DSAPrivateKey := FC_i2d_DSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_DSAPrivateKey_removed)}
    if i2d_DSAPrivateKey_removed <= LibVersion then
    begin
      {$if declared(_i2d_DSAPrivateKey)}
      i2d_DSAPrivateKey := _i2d_DSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_DSAPrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_DSAPrivateKey');
    {$ifend}
  end;


  i2d_DSAparams := LoadLibFunction(ADllHandle, i2d_DSAparams_procname);
  FuncLoadError := not assigned(i2d_DSAparams);
  if FuncLoadError then
  begin
    {$if not defined(i2d_DSAparams_allownil)}
    i2d_DSAparams := ERR_i2d_DSAparams;
    {$ifend}
    {$if declared(i2d_DSAparams_introduced)}
    if LibVersion < i2d_DSAparams_introduced then
    begin
      {$if declared(FC_i2d_DSAparams)}
      i2d_DSAparams := FC_i2d_DSAparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_DSAparams_removed)}
    if i2d_DSAparams_removed <= LibVersion then
    begin
      {$if declared(_i2d_DSAparams)}
      i2d_DSAparams := _i2d_DSAparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_DSAparams_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_DSAparams');
    {$ifend}
  end;


  DSAparams_print := LoadLibFunction(ADllHandle, DSAparams_print_procname);
  FuncLoadError := not assigned(DSAparams_print);
  if FuncLoadError then
  begin
    {$if not defined(DSAparams_print_allownil)}
    DSAparams_print := ERR_DSAparams_print;
    {$ifend}
    {$if declared(DSAparams_print_introduced)}
    if LibVersion < DSAparams_print_introduced then
    begin
      {$if declared(FC_DSAparams_print)}
      DSAparams_print := FC_DSAparams_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSAparams_print_removed)}
    if DSAparams_print_removed <= LibVersion then
    begin
      {$if declared(_DSAparams_print)}
      DSAparams_print := _DSAparams_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSAparams_print_allownil)}
    if FuncLoadError then
      AFailed.Add('DSAparams_print');
    {$ifend}
  end;


  DSA_print := LoadLibFunction(ADllHandle, DSA_print_procname);
  FuncLoadError := not assigned(DSA_print);
  if FuncLoadError then
  begin
    {$if not defined(DSA_print_allownil)}
    DSA_print := ERR_DSA_print;
    {$ifend}
    {$if declared(DSA_print_introduced)}
    if LibVersion < DSA_print_introduced then
    begin
      {$if declared(FC_DSA_print)}
      DSA_print := FC_DSA_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_print_removed)}
    if DSA_print_removed <= LibVersion then
    begin
      {$if declared(_DSA_print)}
      DSA_print := _DSA_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_print_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_print');
    {$ifend}
  end;


  DSA_dup_DH := LoadLibFunction(ADllHandle, DSA_dup_DH_procname);
  FuncLoadError := not assigned(DSA_dup_DH);
  if FuncLoadError then
  begin
    {$if not defined(DSA_dup_DH_allownil)}
    DSA_dup_DH := ERR_DSA_dup_DH;
    {$ifend}
    {$if declared(DSA_dup_DH_introduced)}
    if LibVersion < DSA_dup_DH_introduced then
    begin
      {$if declared(FC_DSA_dup_DH)}
      DSA_dup_DH := FC_DSA_dup_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_dup_DH_removed)}
    if DSA_dup_DH_removed <= LibVersion then
    begin
      {$if declared(_DSA_dup_DH)}
      DSA_dup_DH := _DSA_dup_DH;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_dup_DH_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_dup_DH');
    {$ifend}
  end;


  DSA_get0_pqg := LoadLibFunction(ADllHandle, DSA_get0_pqg_procname);
  FuncLoadError := not assigned(DSA_get0_pqg);
  if FuncLoadError then
  begin
    {$if not defined(DSA_get0_pqg_allownil)}
    DSA_get0_pqg := ERR_DSA_get0_pqg;
    {$ifend}
    {$if declared(DSA_get0_pqg_introduced)}
    if LibVersion < DSA_get0_pqg_introduced then
    begin
      {$if declared(FC_DSA_get0_pqg)}
      DSA_get0_pqg := FC_DSA_get0_pqg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_get0_pqg_removed)}
    if DSA_get0_pqg_removed <= LibVersion then
    begin
      {$if declared(_DSA_get0_pqg)}
      DSA_get0_pqg := _DSA_get0_pqg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_get0_pqg_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_get0_pqg');
    {$ifend}
  end;


  DSA_set0_pqg := LoadLibFunction(ADllHandle, DSA_set0_pqg_procname);
  FuncLoadError := not assigned(DSA_set0_pqg);
  if FuncLoadError then
  begin
    {$if not defined(DSA_set0_pqg_allownil)}
    DSA_set0_pqg := ERR_DSA_set0_pqg;
    {$ifend}
    {$if declared(DSA_set0_pqg_introduced)}
    if LibVersion < DSA_set0_pqg_introduced then
    begin
      {$if declared(FC_DSA_set0_pqg)}
      DSA_set0_pqg := FC_DSA_set0_pqg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_set0_pqg_removed)}
    if DSA_set0_pqg_removed <= LibVersion then
    begin
      {$if declared(_DSA_set0_pqg)}
      DSA_set0_pqg := _DSA_set0_pqg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_set0_pqg_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_set0_pqg');
    {$ifend}
  end;


  DSA_get0_key := LoadLibFunction(ADllHandle, DSA_get0_key_procname);
  FuncLoadError := not assigned(DSA_get0_key);
  if FuncLoadError then
  begin
    {$if not defined(DSA_get0_key_allownil)}
    DSA_get0_key := ERR_DSA_get0_key;
    {$ifend}
    {$if declared(DSA_get0_key_introduced)}
    if LibVersion < DSA_get0_key_introduced then
    begin
      {$if declared(FC_DSA_get0_key)}
      DSA_get0_key := FC_DSA_get0_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_get0_key_removed)}
    if DSA_get0_key_removed <= LibVersion then
    begin
      {$if declared(_DSA_get0_key)}
      DSA_get0_key := _DSA_get0_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_get0_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_get0_key');
    {$ifend}
  end;


  DSA_set0_key := LoadLibFunction(ADllHandle, DSA_set0_key_procname);
  FuncLoadError := not assigned(DSA_set0_key);
  if FuncLoadError then
  begin
    {$if not defined(DSA_set0_key_allownil)}
    DSA_set0_key := ERR_DSA_set0_key;
    {$ifend}
    {$if declared(DSA_set0_key_introduced)}
    if LibVersion < DSA_set0_key_introduced then
    begin
      {$if declared(FC_DSA_set0_key)}
      DSA_set0_key := FC_DSA_set0_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_set0_key_removed)}
    if DSA_set0_key_removed <= LibVersion then
    begin
      {$if declared(_DSA_set0_key)}
      DSA_set0_key := _DSA_set0_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_set0_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_set0_key');
    {$ifend}
  end;


  DSA_get0_p := LoadLibFunction(ADllHandle, DSA_get0_p_procname);
  FuncLoadError := not assigned(DSA_get0_p);
  if FuncLoadError then
  begin
    {$if not defined(DSA_get0_p_allownil)}
    DSA_get0_p := ERR_DSA_get0_p;
    {$ifend}
    {$if declared(DSA_get0_p_introduced)}
    if LibVersion < DSA_get0_p_introduced then
    begin
      {$if declared(FC_DSA_get0_p)}
      DSA_get0_p := FC_DSA_get0_p;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_get0_p_removed)}
    if DSA_get0_p_removed <= LibVersion then
    begin
      {$if declared(_DSA_get0_p)}
      DSA_get0_p := _DSA_get0_p;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_get0_p_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_get0_p');
    {$ifend}
  end;


  DSA_get0_q := LoadLibFunction(ADllHandle, DSA_get0_q_procname);
  FuncLoadError := not assigned(DSA_get0_q);
  if FuncLoadError then
  begin
    {$if not defined(DSA_get0_q_allownil)}
    DSA_get0_q := ERR_DSA_get0_q;
    {$ifend}
    {$if declared(DSA_get0_q_introduced)}
    if LibVersion < DSA_get0_q_introduced then
    begin
      {$if declared(FC_DSA_get0_q)}
      DSA_get0_q := FC_DSA_get0_q;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_get0_q_removed)}
    if DSA_get0_q_removed <= LibVersion then
    begin
      {$if declared(_DSA_get0_q)}
      DSA_get0_q := _DSA_get0_q;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_get0_q_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_get0_q');
    {$ifend}
  end;


  DSA_get0_g := LoadLibFunction(ADllHandle, DSA_get0_g_procname);
  FuncLoadError := not assigned(DSA_get0_g);
  if FuncLoadError then
  begin
    {$if not defined(DSA_get0_g_allownil)}
    DSA_get0_g := ERR_DSA_get0_g;
    {$ifend}
    {$if declared(DSA_get0_g_introduced)}
    if LibVersion < DSA_get0_g_introduced then
    begin
      {$if declared(FC_DSA_get0_g)}
      DSA_get0_g := FC_DSA_get0_g;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_get0_g_removed)}
    if DSA_get0_g_removed <= LibVersion then
    begin
      {$if declared(_DSA_get0_g)}
      DSA_get0_g := _DSA_get0_g;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_get0_g_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_get0_g');
    {$ifend}
  end;


  DSA_get0_pub_key := LoadLibFunction(ADllHandle, DSA_get0_pub_key_procname);
  FuncLoadError := not assigned(DSA_get0_pub_key);
  if FuncLoadError then
  begin
    {$if not defined(DSA_get0_pub_key_allownil)}
    DSA_get0_pub_key := ERR_DSA_get0_pub_key;
    {$ifend}
    {$if declared(DSA_get0_pub_key_introduced)}
    if LibVersion < DSA_get0_pub_key_introduced then
    begin
      {$if declared(FC_DSA_get0_pub_key)}
      DSA_get0_pub_key := FC_DSA_get0_pub_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_get0_pub_key_removed)}
    if DSA_get0_pub_key_removed <= LibVersion then
    begin
      {$if declared(_DSA_get0_pub_key)}
      DSA_get0_pub_key := _DSA_get0_pub_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_get0_pub_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_get0_pub_key');
    {$ifend}
  end;


  DSA_get0_priv_key := LoadLibFunction(ADllHandle, DSA_get0_priv_key_procname);
  FuncLoadError := not assigned(DSA_get0_priv_key);
  if FuncLoadError then
  begin
    {$if not defined(DSA_get0_priv_key_allownil)}
    DSA_get0_priv_key := ERR_DSA_get0_priv_key;
    {$ifend}
    {$if declared(DSA_get0_priv_key_introduced)}
    if LibVersion < DSA_get0_priv_key_introduced then
    begin
      {$if declared(FC_DSA_get0_priv_key)}
      DSA_get0_priv_key := FC_DSA_get0_priv_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_get0_priv_key_removed)}
    if DSA_get0_priv_key_removed <= LibVersion then
    begin
      {$if declared(_DSA_get0_priv_key)}
      DSA_get0_priv_key := _DSA_get0_priv_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_get0_priv_key_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_get0_priv_key');
    {$ifend}
  end;


  DSA_clear_flags := LoadLibFunction(ADllHandle, DSA_clear_flags_procname);
  FuncLoadError := not assigned(DSA_clear_flags);
  if FuncLoadError then
  begin
    {$if not defined(DSA_clear_flags_allownil)}
    DSA_clear_flags := ERR_DSA_clear_flags;
    {$ifend}
    {$if declared(DSA_clear_flags_introduced)}
    if LibVersion < DSA_clear_flags_introduced then
    begin
      {$if declared(FC_DSA_clear_flags)}
      DSA_clear_flags := FC_DSA_clear_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_clear_flags_removed)}
    if DSA_clear_flags_removed <= LibVersion then
    begin
      {$if declared(_DSA_clear_flags)}
      DSA_clear_flags := _DSA_clear_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_clear_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_clear_flags');
    {$ifend}
  end;


  DSA_test_flags := LoadLibFunction(ADllHandle, DSA_test_flags_procname);
  FuncLoadError := not assigned(DSA_test_flags);
  if FuncLoadError then
  begin
    {$if not defined(DSA_test_flags_allownil)}
    DSA_test_flags := ERR_DSA_test_flags;
    {$ifend}
    {$if declared(DSA_test_flags_introduced)}
    if LibVersion < DSA_test_flags_introduced then
    begin
      {$if declared(FC_DSA_test_flags)}
      DSA_test_flags := FC_DSA_test_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_test_flags_removed)}
    if DSA_test_flags_removed <= LibVersion then
    begin
      {$if declared(_DSA_test_flags)}
      DSA_test_flags := _DSA_test_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_test_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_test_flags');
    {$ifend}
  end;


  DSA_set_flags := LoadLibFunction(ADllHandle, DSA_set_flags_procname);
  FuncLoadError := not assigned(DSA_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(DSA_set_flags_allownil)}
    DSA_set_flags := ERR_DSA_set_flags;
    {$ifend}
    {$if declared(DSA_set_flags_introduced)}
    if LibVersion < DSA_set_flags_introduced then
    begin
      {$if declared(FC_DSA_set_flags)}
      DSA_set_flags := FC_DSA_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_set_flags_removed)}
    if DSA_set_flags_removed <= LibVersion then
    begin
      {$if declared(_DSA_set_flags)}
      DSA_set_flags := _DSA_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_set_flags');
    {$ifend}
  end;


  DSA_get0_engine := LoadLibFunction(ADllHandle, DSA_get0_engine_procname);
  FuncLoadError := not assigned(DSA_get0_engine);
  if FuncLoadError then
  begin
    {$if not defined(DSA_get0_engine_allownil)}
    DSA_get0_engine := ERR_DSA_get0_engine;
    {$ifend}
    {$if declared(DSA_get0_engine_introduced)}
    if LibVersion < DSA_get0_engine_introduced then
    begin
      {$if declared(FC_DSA_get0_engine)}
      DSA_get0_engine := FC_DSA_get0_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_get0_engine_removed)}
    if DSA_get0_engine_removed <= LibVersion then
    begin
      {$if declared(_DSA_get0_engine)}
      DSA_get0_engine := _DSA_get0_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_get0_engine_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_get0_engine');
    {$ifend}
  end;


  DSA_meth_new := LoadLibFunction(ADllHandle, DSA_meth_new_procname);
  FuncLoadError := not assigned(DSA_meth_new);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_new_allownil)}
    DSA_meth_new := ERR_DSA_meth_new;
    {$ifend}
    {$if declared(DSA_meth_new_introduced)}
    if LibVersion < DSA_meth_new_introduced then
    begin
      {$if declared(FC_DSA_meth_new)}
      DSA_meth_new := FC_DSA_meth_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_new_removed)}
    if DSA_meth_new_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_new)}
      DSA_meth_new := _DSA_meth_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_new_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_new');
    {$ifend}
  end;


  DSA_meth_free := LoadLibFunction(ADllHandle, DSA_meth_free_procname);
  FuncLoadError := not assigned(DSA_meth_free);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_free_allownil)}
    DSA_meth_free := ERR_DSA_meth_free;
    {$ifend}
    {$if declared(DSA_meth_free_introduced)}
    if LibVersion < DSA_meth_free_introduced then
    begin
      {$if declared(FC_DSA_meth_free)}
      DSA_meth_free := FC_DSA_meth_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_free_removed)}
    if DSA_meth_free_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_free)}
      DSA_meth_free := _DSA_meth_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_free_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_free');
    {$ifend}
  end;


  DSA_meth_dup := LoadLibFunction(ADllHandle, DSA_meth_dup_procname);
  FuncLoadError := not assigned(DSA_meth_dup);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_dup_allownil)}
    DSA_meth_dup := ERR_DSA_meth_dup;
    {$ifend}
    {$if declared(DSA_meth_dup_introduced)}
    if LibVersion < DSA_meth_dup_introduced then
    begin
      {$if declared(FC_DSA_meth_dup)}
      DSA_meth_dup := FC_DSA_meth_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_dup_removed)}
    if DSA_meth_dup_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_dup)}
      DSA_meth_dup := _DSA_meth_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_dup');
    {$ifend}
  end;


  DSA_meth_get0_name := LoadLibFunction(ADllHandle, DSA_meth_get0_name_procname);
  FuncLoadError := not assigned(DSA_meth_get0_name);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_get0_name_allownil)}
    DSA_meth_get0_name := ERR_DSA_meth_get0_name;
    {$ifend}
    {$if declared(DSA_meth_get0_name_introduced)}
    if LibVersion < DSA_meth_get0_name_introduced then
    begin
      {$if declared(FC_DSA_meth_get0_name)}
      DSA_meth_get0_name := FC_DSA_meth_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_get0_name_removed)}
    if DSA_meth_get0_name_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_get0_name)}
      DSA_meth_get0_name := _DSA_meth_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_get0_name_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_get0_name');
    {$ifend}
  end;


  DSA_meth_set1_name := LoadLibFunction(ADllHandle, DSA_meth_set1_name_procname);
  FuncLoadError := not assigned(DSA_meth_set1_name);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_set1_name_allownil)}
    DSA_meth_set1_name := ERR_DSA_meth_set1_name;
    {$ifend}
    {$if declared(DSA_meth_set1_name_introduced)}
    if LibVersion < DSA_meth_set1_name_introduced then
    begin
      {$if declared(FC_DSA_meth_set1_name)}
      DSA_meth_set1_name := FC_DSA_meth_set1_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_set1_name_removed)}
    if DSA_meth_set1_name_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_set1_name)}
      DSA_meth_set1_name := _DSA_meth_set1_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_set1_name_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_set1_name');
    {$ifend}
  end;


  DSA_meth_get_flags := LoadLibFunction(ADllHandle, DSA_meth_get_flags_procname);
  FuncLoadError := not assigned(DSA_meth_get_flags);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_get_flags_allownil)}
    DSA_meth_get_flags := ERR_DSA_meth_get_flags;
    {$ifend}
    {$if declared(DSA_meth_get_flags_introduced)}
    if LibVersion < DSA_meth_get_flags_introduced then
    begin
      {$if declared(FC_DSA_meth_get_flags)}
      DSA_meth_get_flags := FC_DSA_meth_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_get_flags_removed)}
    if DSA_meth_get_flags_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_get_flags)}
      DSA_meth_get_flags := _DSA_meth_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_get_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_get_flags');
    {$ifend}
  end;


  DSA_meth_set_flags := LoadLibFunction(ADllHandle, DSA_meth_set_flags_procname);
  FuncLoadError := not assigned(DSA_meth_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_set_flags_allownil)}
    DSA_meth_set_flags := ERR_DSA_meth_set_flags;
    {$ifend}
    {$if declared(DSA_meth_set_flags_introduced)}
    if LibVersion < DSA_meth_set_flags_introduced then
    begin
      {$if declared(FC_DSA_meth_set_flags)}
      DSA_meth_set_flags := FC_DSA_meth_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_set_flags_removed)}
    if DSA_meth_set_flags_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_set_flags)}
      DSA_meth_set_flags := _DSA_meth_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_set_flags');
    {$ifend}
  end;


  DSA_meth_get0_app_data := LoadLibFunction(ADllHandle, DSA_meth_get0_app_data_procname);
  FuncLoadError := not assigned(DSA_meth_get0_app_data);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_get0_app_data_allownil)}
    DSA_meth_get0_app_data := ERR_DSA_meth_get0_app_data;
    {$ifend}
    {$if declared(DSA_meth_get0_app_data_introduced)}
    if LibVersion < DSA_meth_get0_app_data_introduced then
    begin
      {$if declared(FC_DSA_meth_get0_app_data)}
      DSA_meth_get0_app_data := FC_DSA_meth_get0_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_get0_app_data_removed)}
    if DSA_meth_get0_app_data_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_get0_app_data)}
      DSA_meth_get0_app_data := _DSA_meth_get0_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_get0_app_data_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_get0_app_data');
    {$ifend}
  end;


  DSA_meth_set0_app_data := LoadLibFunction(ADllHandle, DSA_meth_set0_app_data_procname);
  FuncLoadError := not assigned(DSA_meth_set0_app_data);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_set0_app_data_allownil)}
    DSA_meth_set0_app_data := ERR_DSA_meth_set0_app_data;
    {$ifend}
    {$if declared(DSA_meth_set0_app_data_introduced)}
    if LibVersion < DSA_meth_set0_app_data_introduced then
    begin
      {$if declared(FC_DSA_meth_set0_app_data)}
      DSA_meth_set0_app_data := FC_DSA_meth_set0_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_set0_app_data_removed)}
    if DSA_meth_set0_app_data_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_set0_app_data)}
      DSA_meth_set0_app_data := _DSA_meth_set0_app_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_set0_app_data_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_set0_app_data');
    {$ifend}
  end;


  DSA_meth_get_sign := LoadLibFunction(ADllHandle, DSA_meth_get_sign_procname);
  FuncLoadError := not assigned(DSA_meth_get_sign);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_get_sign_allownil)}
    DSA_meth_get_sign := ERR_DSA_meth_get_sign;
    {$ifend}
    {$if declared(DSA_meth_get_sign_introduced)}
    if LibVersion < DSA_meth_get_sign_introduced then
    begin
      {$if declared(FC_DSA_meth_get_sign)}
      DSA_meth_get_sign := FC_DSA_meth_get_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_get_sign_removed)}
    if DSA_meth_get_sign_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_get_sign)}
      DSA_meth_get_sign := _DSA_meth_get_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_get_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_get_sign');
    {$ifend}
  end;


  DSA_meth_set_sign := LoadLibFunction(ADllHandle, DSA_meth_set_sign_procname);
  FuncLoadError := not assigned(DSA_meth_set_sign);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_set_sign_allownil)}
    DSA_meth_set_sign := ERR_DSA_meth_set_sign;
    {$ifend}
    {$if declared(DSA_meth_set_sign_introduced)}
    if LibVersion < DSA_meth_set_sign_introduced then
    begin
      {$if declared(FC_DSA_meth_set_sign)}
      DSA_meth_set_sign := FC_DSA_meth_set_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_set_sign_removed)}
    if DSA_meth_set_sign_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_set_sign)}
      DSA_meth_set_sign := _DSA_meth_set_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_set_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_set_sign');
    {$ifend}
  end;


  DSA_meth_get_sign_setup := LoadLibFunction(ADllHandle, DSA_meth_get_sign_setup_procname);
  FuncLoadError := not assigned(DSA_meth_get_sign_setup);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_get_sign_setup_allownil)}
    DSA_meth_get_sign_setup := ERR_DSA_meth_get_sign_setup;
    {$ifend}
    {$if declared(DSA_meth_get_sign_setup_introduced)}
    if LibVersion < DSA_meth_get_sign_setup_introduced then
    begin
      {$if declared(FC_DSA_meth_get_sign_setup)}
      DSA_meth_get_sign_setup := FC_DSA_meth_get_sign_setup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_get_sign_setup_removed)}
    if DSA_meth_get_sign_setup_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_get_sign_setup)}
      DSA_meth_get_sign_setup := _DSA_meth_get_sign_setup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_get_sign_setup_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_get_sign_setup');
    {$ifend}
  end;


  DSA_meth_set_sign_setup := LoadLibFunction(ADllHandle, DSA_meth_set_sign_setup_procname);
  FuncLoadError := not assigned(DSA_meth_set_sign_setup);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_set_sign_setup_allownil)}
    DSA_meth_set_sign_setup := ERR_DSA_meth_set_sign_setup;
    {$ifend}
    {$if declared(DSA_meth_set_sign_setup_introduced)}
    if LibVersion < DSA_meth_set_sign_setup_introduced then
    begin
      {$if declared(FC_DSA_meth_set_sign_setup)}
      DSA_meth_set_sign_setup := FC_DSA_meth_set_sign_setup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_set_sign_setup_removed)}
    if DSA_meth_set_sign_setup_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_set_sign_setup)}
      DSA_meth_set_sign_setup := _DSA_meth_set_sign_setup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_set_sign_setup_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_set_sign_setup');
    {$ifend}
  end;


  DSA_meth_get_verify := LoadLibFunction(ADllHandle, DSA_meth_get_verify_procname);
  FuncLoadError := not assigned(DSA_meth_get_verify);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_get_verify_allownil)}
    DSA_meth_get_verify := ERR_DSA_meth_get_verify;
    {$ifend}
    {$if declared(DSA_meth_get_verify_introduced)}
    if LibVersion < DSA_meth_get_verify_introduced then
    begin
      {$if declared(FC_DSA_meth_get_verify)}
      DSA_meth_get_verify := FC_DSA_meth_get_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_get_verify_removed)}
    if DSA_meth_get_verify_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_get_verify)}
      DSA_meth_get_verify := _DSA_meth_get_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_get_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_get_verify');
    {$ifend}
  end;


  DSA_meth_set_verify := LoadLibFunction(ADllHandle, DSA_meth_set_verify_procname);
  FuncLoadError := not assigned(DSA_meth_set_verify);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_set_verify_allownil)}
    DSA_meth_set_verify := ERR_DSA_meth_set_verify;
    {$ifend}
    {$if declared(DSA_meth_set_verify_introduced)}
    if LibVersion < DSA_meth_set_verify_introduced then
    begin
      {$if declared(FC_DSA_meth_set_verify)}
      DSA_meth_set_verify := FC_DSA_meth_set_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_set_verify_removed)}
    if DSA_meth_set_verify_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_set_verify)}
      DSA_meth_set_verify := _DSA_meth_set_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_set_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_set_verify');
    {$ifend}
  end;


  DSA_meth_get_mod_exp := LoadLibFunction(ADllHandle, DSA_meth_get_mod_exp_procname);
  FuncLoadError := not assigned(DSA_meth_get_mod_exp);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_get_mod_exp_allownil)}
    DSA_meth_get_mod_exp := ERR_DSA_meth_get_mod_exp;
    {$ifend}
    {$if declared(DSA_meth_get_mod_exp_introduced)}
    if LibVersion < DSA_meth_get_mod_exp_introduced then
    begin
      {$if declared(FC_DSA_meth_get_mod_exp)}
      DSA_meth_get_mod_exp := FC_DSA_meth_get_mod_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_get_mod_exp_removed)}
    if DSA_meth_get_mod_exp_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_get_mod_exp)}
      DSA_meth_get_mod_exp := _DSA_meth_get_mod_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_get_mod_exp_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_get_mod_exp');
    {$ifend}
  end;


  DSA_meth_set_mod_exp := LoadLibFunction(ADllHandle, DSA_meth_set_mod_exp_procname);
  FuncLoadError := not assigned(DSA_meth_set_mod_exp);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_set_mod_exp_allownil)}
    DSA_meth_set_mod_exp := ERR_DSA_meth_set_mod_exp;
    {$ifend}
    {$if declared(DSA_meth_set_mod_exp_introduced)}
    if LibVersion < DSA_meth_set_mod_exp_introduced then
    begin
      {$if declared(FC_DSA_meth_set_mod_exp)}
      DSA_meth_set_mod_exp := FC_DSA_meth_set_mod_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_set_mod_exp_removed)}
    if DSA_meth_set_mod_exp_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_set_mod_exp)}
      DSA_meth_set_mod_exp := _DSA_meth_set_mod_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_set_mod_exp_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_set_mod_exp');
    {$ifend}
  end;


  DSA_meth_get_bn_mod_exp := LoadLibFunction(ADllHandle, DSA_meth_get_bn_mod_exp_procname);
  FuncLoadError := not assigned(DSA_meth_get_bn_mod_exp);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_get_bn_mod_exp_allownil)}
    DSA_meth_get_bn_mod_exp := ERR_DSA_meth_get_bn_mod_exp;
    {$ifend}
    {$if declared(DSA_meth_get_bn_mod_exp_introduced)}
    if LibVersion < DSA_meth_get_bn_mod_exp_introduced then
    begin
      {$if declared(FC_DSA_meth_get_bn_mod_exp)}
      DSA_meth_get_bn_mod_exp := FC_DSA_meth_get_bn_mod_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_get_bn_mod_exp_removed)}
    if DSA_meth_get_bn_mod_exp_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_get_bn_mod_exp)}
      DSA_meth_get_bn_mod_exp := _DSA_meth_get_bn_mod_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_get_bn_mod_exp_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_get_bn_mod_exp');
    {$ifend}
  end;


  DSA_meth_set_bn_mod_exp := LoadLibFunction(ADllHandle, DSA_meth_set_bn_mod_exp_procname);
  FuncLoadError := not assigned(DSA_meth_set_bn_mod_exp);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_set_bn_mod_exp_allownil)}
    DSA_meth_set_bn_mod_exp := ERR_DSA_meth_set_bn_mod_exp;
    {$ifend}
    {$if declared(DSA_meth_set_bn_mod_exp_introduced)}
    if LibVersion < DSA_meth_set_bn_mod_exp_introduced then
    begin
      {$if declared(FC_DSA_meth_set_bn_mod_exp)}
      DSA_meth_set_bn_mod_exp := FC_DSA_meth_set_bn_mod_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_set_bn_mod_exp_removed)}
    if DSA_meth_set_bn_mod_exp_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_set_bn_mod_exp)}
      DSA_meth_set_bn_mod_exp := _DSA_meth_set_bn_mod_exp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_set_bn_mod_exp_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_set_bn_mod_exp');
    {$ifend}
  end;


  DSA_meth_get_init := LoadLibFunction(ADllHandle, DSA_meth_get_init_procname);
  FuncLoadError := not assigned(DSA_meth_get_init);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_get_init_allownil)}
    DSA_meth_get_init := ERR_DSA_meth_get_init;
    {$ifend}
    {$if declared(DSA_meth_get_init_introduced)}
    if LibVersion < DSA_meth_get_init_introduced then
    begin
      {$if declared(FC_DSA_meth_get_init)}
      DSA_meth_get_init := FC_DSA_meth_get_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_get_init_removed)}
    if DSA_meth_get_init_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_get_init)}
      DSA_meth_get_init := _DSA_meth_get_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_get_init_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_get_init');
    {$ifend}
  end;


  DSA_meth_set_init := LoadLibFunction(ADllHandle, DSA_meth_set_init_procname);
  FuncLoadError := not assigned(DSA_meth_set_init);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_set_init_allownil)}
    DSA_meth_set_init := ERR_DSA_meth_set_init;
    {$ifend}
    {$if declared(DSA_meth_set_init_introduced)}
    if LibVersion < DSA_meth_set_init_introduced then
    begin
      {$if declared(FC_DSA_meth_set_init)}
      DSA_meth_set_init := FC_DSA_meth_set_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_set_init_removed)}
    if DSA_meth_set_init_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_set_init)}
      DSA_meth_set_init := _DSA_meth_set_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_set_init_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_set_init');
    {$ifend}
  end;


  DSA_meth_get_finish := LoadLibFunction(ADllHandle, DSA_meth_get_finish_procname);
  FuncLoadError := not assigned(DSA_meth_get_finish);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_get_finish_allownil)}
    DSA_meth_get_finish := ERR_DSA_meth_get_finish;
    {$ifend}
    {$if declared(DSA_meth_get_finish_introduced)}
    if LibVersion < DSA_meth_get_finish_introduced then
    begin
      {$if declared(FC_DSA_meth_get_finish)}
      DSA_meth_get_finish := FC_DSA_meth_get_finish;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_get_finish_removed)}
    if DSA_meth_get_finish_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_get_finish)}
      DSA_meth_get_finish := _DSA_meth_get_finish;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_get_finish_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_get_finish');
    {$ifend}
  end;


  DSA_meth_set_finish := LoadLibFunction(ADllHandle, DSA_meth_set_finish_procname);
  FuncLoadError := not assigned(DSA_meth_set_finish);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_set_finish_allownil)}
    DSA_meth_set_finish := ERR_DSA_meth_set_finish;
    {$ifend}
    {$if declared(DSA_meth_set_finish_introduced)}
    if LibVersion < DSA_meth_set_finish_introduced then
    begin
      {$if declared(FC_DSA_meth_set_finish)}
      DSA_meth_set_finish := FC_DSA_meth_set_finish;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_set_finish_removed)}
    if DSA_meth_set_finish_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_set_finish)}
      DSA_meth_set_finish := _DSA_meth_set_finish;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_set_finish_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_set_finish');
    {$ifend}
  end;


  DSA_meth_get_paramgen := LoadLibFunction(ADllHandle, DSA_meth_get_paramgen_procname);
  FuncLoadError := not assigned(DSA_meth_get_paramgen);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_get_paramgen_allownil)}
    DSA_meth_get_paramgen := ERR_DSA_meth_get_paramgen;
    {$ifend}
    {$if declared(DSA_meth_get_paramgen_introduced)}
    if LibVersion < DSA_meth_get_paramgen_introduced then
    begin
      {$if declared(FC_DSA_meth_get_paramgen)}
      DSA_meth_get_paramgen := FC_DSA_meth_get_paramgen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_get_paramgen_removed)}
    if DSA_meth_get_paramgen_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_get_paramgen)}
      DSA_meth_get_paramgen := _DSA_meth_get_paramgen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_get_paramgen_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_get_paramgen');
    {$ifend}
  end;


  DSA_meth_set_paramgen := LoadLibFunction(ADllHandle, DSA_meth_set_paramgen_procname);
  FuncLoadError := not assigned(DSA_meth_set_paramgen);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_set_paramgen_allownil)}
    DSA_meth_set_paramgen := ERR_DSA_meth_set_paramgen;
    {$ifend}
    {$if declared(DSA_meth_set_paramgen_introduced)}
    if LibVersion < DSA_meth_set_paramgen_introduced then
    begin
      {$if declared(FC_DSA_meth_set_paramgen)}
      DSA_meth_set_paramgen := FC_DSA_meth_set_paramgen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_set_paramgen_removed)}
    if DSA_meth_set_paramgen_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_set_paramgen)}
      DSA_meth_set_paramgen := _DSA_meth_set_paramgen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_set_paramgen_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_set_paramgen');
    {$ifend}
  end;


  DSA_meth_get_keygen := LoadLibFunction(ADllHandle, DSA_meth_get_keygen_procname);
  FuncLoadError := not assigned(DSA_meth_get_keygen);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_get_keygen_allownil)}
    DSA_meth_get_keygen := ERR_DSA_meth_get_keygen;
    {$ifend}
    {$if declared(DSA_meth_get_keygen_introduced)}
    if LibVersion < DSA_meth_get_keygen_introduced then
    begin
      {$if declared(FC_DSA_meth_get_keygen)}
      DSA_meth_get_keygen := FC_DSA_meth_get_keygen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_get_keygen_removed)}
    if DSA_meth_get_keygen_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_get_keygen)}
      DSA_meth_get_keygen := _DSA_meth_get_keygen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_get_keygen_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_get_keygen');
    {$ifend}
  end;


  DSA_meth_set_keygen := LoadLibFunction(ADllHandle, DSA_meth_set_keygen_procname);
  FuncLoadError := not assigned(DSA_meth_set_keygen);
  if FuncLoadError then
  begin
    {$if not defined(DSA_meth_set_keygen_allownil)}
    DSA_meth_set_keygen := ERR_DSA_meth_set_keygen;
    {$ifend}
    {$if declared(DSA_meth_set_keygen_introduced)}
    if LibVersion < DSA_meth_set_keygen_introduced then
    begin
      {$if declared(FC_DSA_meth_set_keygen)}
      DSA_meth_set_keygen := FC_DSA_meth_set_keygen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DSA_meth_set_keygen_removed)}
    if DSA_meth_set_keygen_removed <= LibVersion then
    begin
      {$if declared(_DSA_meth_set_keygen)}
      DSA_meth_set_keygen := _DSA_meth_set_keygen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DSA_meth_set_keygen_allownil)}
    if FuncLoadError then
      AFailed.Add('DSA_meth_set_keygen');
    {$ifend}
  end;
end;
  {$I TaurusTLSUnusedParamOff.inc}

procedure Unload;
begin
  DSAparams_dup := nil;
  DSA_SIG_new := nil;
  DSA_SIG_free := nil;
  i2d_DSA_SIG := nil;
  d2i_DSA_SIG := nil;
  DSA_SIG_get0 := nil;
  DSA_SIG_set0 := nil;
  DSA_do_sign := nil;
  DSA_do_verify := nil;
  DSA_TaurusTLS := nil;
  DSA_set_default_method := nil;
  DSA_get_default_method := nil;
  DSA_set_method := nil;
  DSA_get_method := nil;
  DSA_new := nil;
  DSA_new_method := nil;
  DSA_free := nil;
  DSA_up_ref := nil;
  DSA_size := nil;
  DSA_bits := nil;
  DSA_security_bits := nil;
  DSA_sign := nil;
  DSA_verify := nil;
  DSA_set_ex_data := nil;
  DSA_get_ex_data := nil;
  d2i_DSAPublicKey := nil;
  d2i_DSAPrivateKey := nil;
  d2i_DSAparams := nil;
  DSA_generate_parameters_ex := nil;
  DSA_generate_key := nil;
  i2d_DSAPublicKey := nil;
  i2d_DSAPrivateKey := nil;
  i2d_DSAparams := nil;
  DSAparams_print := nil;
  DSA_print := nil;
  DSA_dup_DH := nil;
  DSA_get0_pqg := nil;
  DSA_set0_pqg := nil;
  DSA_get0_key := nil;
  DSA_set0_key := nil;
  DSA_get0_p := nil;
  DSA_get0_q := nil;
  DSA_get0_g := nil;
  DSA_get0_pub_key := nil;
  DSA_get0_priv_key := nil;
  DSA_clear_flags := nil;
  DSA_test_flags := nil;
  DSA_set_flags := nil;
  DSA_get0_engine := nil;
  DSA_meth_new := nil;
  DSA_meth_free := nil;
  DSA_meth_dup := nil;
  DSA_meth_get0_name := nil;
  DSA_meth_set1_name := nil;
  DSA_meth_get_flags := nil;
  DSA_meth_set_flags := nil;
  DSA_meth_get0_app_data := nil;
  DSA_meth_set0_app_data := nil;
  DSA_meth_get_sign := nil;
  DSA_meth_set_sign := nil;
  DSA_meth_get_sign_setup := nil;
  DSA_meth_set_sign_setup := nil;
  DSA_meth_get_verify := nil;
  DSA_meth_set_verify := nil;
  DSA_meth_get_mod_exp := nil;
  DSA_meth_set_mod_exp := nil;
  DSA_meth_get_bn_mod_exp := nil;
  DSA_meth_set_bn_mod_exp := nil;
  DSA_meth_get_init := nil;
  DSA_meth_set_init := nil;
  DSA_meth_get_finish := nil;
  DSA_meth_set_finish := nil;
  DSA_meth_get_paramgen := nil;
  DSA_meth_set_paramgen := nil;
  DSA_meth_get_keygen := nil;
  DSA_meth_set_keygen := nil;
end;
  {$ENDIF}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
