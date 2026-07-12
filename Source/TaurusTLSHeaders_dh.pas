/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_dh.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_dh.h2pas
     and this file regenerated. TaurusTLSHeaders_dh.h2pas is distributed with the full Indy
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

unit TaurusTLSHeaders_dh;

interface

// Headers for OpenSSL 1.1.1
// dh.h


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
  {$EXTERNALSYM OPENSSL_DH_MAX_MODULUS_BITS}
  OPENSSL_DH_MAX_MODULUS_BITS      = 10000;
  {$EXTERNALSYM OPENSSL_DH_FIPS_MIN_MODULUS_BITS}
  OPENSSL_DH_FIPS_MIN_MODULUS_BITS =  1024;

  {$EXTERNALSYM DH_FLAG_CACHE_MONT_P}
  DH_FLAG_CACHE_MONT_P   =   $01;
  {$EXTERNALSYM DH_FLAG_FIPS_METHOD}
  DH_FLAG_FIPS_METHOD    = $0400;
  {$EXTERNALSYM DH_FLAG_NON_FIPS_ALLOW}
  DH_FLAG_NON_FIPS_ALLOW = $0400;

  {$EXTERNALSYM DH_GENERATOR_2}
  DH_GENERATOR_2 = 2;
  {$EXTERNALSYM DH_GENERATOR_5}
  DH_GENERATOR_5 = 5;

  {$EXTERNALSYM DH_CHECK_P_NOT_PRIME}
  DH_CHECK_P_NOT_PRIME         = $01;
  {$EXTERNALSYM DH_CHECK_P_NOT_SAFE_PRIME}
  DH_CHECK_P_NOT_SAFE_PRIME    = $02;
  {$EXTERNALSYM DH_UNABLE_TO_CHECK_GENERATOR}
  DH_UNABLE_TO_CHECK_GENERATOR = $04;
  {$EXTERNALSYM DH_NOT_SUITABLE_GENERATOR}
  DH_NOT_SUITABLE_GENERATOR    = $08;
  {$EXTERNALSYM DH_CHECK_Q_NOT_PRIME}
  DH_CHECK_Q_NOT_PRIME         = $10;
  {$EXTERNALSYM DH_CHECK_INVALID_Q_VALUE}
  DH_CHECK_INVALID_Q_VALUE     = $20;
  {$EXTERNALSYM DH_CHECK_INVALID_J_VALUE}
  DH_CHECK_INVALID_J_VALUE     = $40;
  {$EXTERNALSYM DH_CHECK_PUBKEY_TOO_SMALL}
  DH_CHECK_PUBKEY_TOO_SMALL    = $01;
  {$EXTERNALSYM DH_CHECK_PUBKEY_TOO_LARGE}
  DH_CHECK_PUBKEY_TOO_LARGE    = $02;
  {$EXTERNALSYM DH_CHECK_PUBKEY_INVALID}
  DH_CHECK_PUBKEY_INVALID      = $04;
  {$EXTERNALSYM DH_CHECK_P_NOT_STRONG_PRIME}
  DH_CHECK_P_NOT_STRONG_PRIME  = DH_CHECK_P_NOT_SAFE_PRIME;

  {$EXTERNALSYM EVP_PKEY_DH_KDF_NONE}
  EVP_PKEY_DH_KDF_NONE  = 1;
  {$EXTERNALSYM EVP_PKEY_DH_KDF_X9_42}
  EVP_PKEY_DH_KDF_X9_42 = 2;

  {$EXTERNALSYM EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN}
  EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN    = (EVP_PKEY_ALG_CTRL + 1);
  {$EXTERNALSYM EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR}
  EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR    = (EVP_PKEY_ALG_CTRL + 2);
  {$EXTERNALSYM EVP_PKEY_CTRL_DH_RFC5114}
  EVP_PKEY_CTRL_DH_RFC5114               = (EVP_PKEY_ALG_CTRL + 3);
  {$EXTERNALSYM EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN}
  EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN = (EVP_PKEY_ALG_CTRL + 4);
  {$EXTERNALSYM EVP_PKEY_CTRL_DH_PARAMGEN_TYPE}
  EVP_PKEY_CTRL_DH_PARAMGEN_TYPE         = (EVP_PKEY_ALG_CTRL + 5);
  {$EXTERNALSYM EVP_PKEY_CTRL_DH_KDF_TYPE}
  EVP_PKEY_CTRL_DH_KDF_TYPE              = (EVP_PKEY_ALG_CTRL + 6);
  {$EXTERNALSYM EVP_PKEY_CTRL_DH_KDF_MD}
  EVP_PKEY_CTRL_DH_KDF_MD                = (EVP_PKEY_ALG_CTRL + 7);
  {$EXTERNALSYM EVP_PKEY_CTRL_GET_DH_KDF_MD}
  EVP_PKEY_CTRL_GET_DH_KDF_MD            = (EVP_PKEY_ALG_CTRL + 8);
  {$EXTERNALSYM EVP_PKEY_CTRL_DH_KDF_OUTLEN}
  EVP_PKEY_CTRL_DH_KDF_OUTLEN            = (EVP_PKEY_ALG_CTRL + 9);
  {$EXTERNALSYM EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN}
  EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN        = (EVP_PKEY_ALG_CTRL + 10);
  {$EXTERNALSYM EVP_PKEY_CTRL_DH_KDF_UKM}
  EVP_PKEY_CTRL_DH_KDF_UKM               = (EVP_PKEY_ALG_CTRL + 11);
  {$EXTERNALSYM EVP_PKEY_CTRL_GET_DH_KDF_UKM}
  EVP_PKEY_CTRL_GET_DH_KDF_UKM           = (EVP_PKEY_ALG_CTRL + 12);
  {$EXTERNALSYM EVP_PKEY_CTRL_DH_KDF_OID}
  EVP_PKEY_CTRL_DH_KDF_OID               = (EVP_PKEY_ALG_CTRL + 13);
  {$EXTERNALSYM EVP_PKEY_CTRL_GET_DH_KDF_OID}
  EVP_PKEY_CTRL_GET_DH_KDF_OID           = (EVP_PKEY_ALG_CTRL + 14);
  {$EXTERNALSYM EVP_PKEY_CTRL_DH_NID}
  EVP_PKEY_CTRL_DH_NID                   = (EVP_PKEY_ALG_CTRL + 15);
  {$EXTERNALSYM EVP_PKEY_CTRL_DH_PAD}
  EVP_PKEY_CTRL_DH_PAD                   = (EVP_PKEY_ALG_CTRL + 16);

type
  {$EXTERNALSYM DH_meth_generate_key_cb}
  DH_meth_generate_key_cb = function(dh: PDH): TIdC_INT cdecl;
  {$EXTERNALSYM DH_meth_compute_key_cb}
  DH_meth_compute_key_cb = function(key: PByte; const pub_key: PBIGNUM; dh: PDH): TIdC_INT cdecl;
  {$EXTERNALSYM DH_meth_bn_mod_exp_cb}
  DH_meth_bn_mod_exp_cb = function(
    const dh: PDH; r: PBIGNUM; const a: PBIGNUM;
    const p: PBIGNUM; const m: PBIGNUM;
    ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TIdC_INT cdecl;
  {$EXTERNALSYM DH_meth_init_cb}
  DH_meth_init_cb = function(dh: PDH): TIdC_INT cdecl;
  {$EXTERNALSYM DH_meth_finish_cb}
  DH_meth_finish_cb = function(dh: PDH): TIdC_INT cdecl;
  {$EXTERNALSYM DH_meth_generate_params_cb}
  DH_meth_generate_params_cb = function(dh: PDH; prime_len: TIdC_INT; generator: TIdC_INT; cb: PBN_GENCB): TIdC_INT cdecl;

{
  # define DH_CHECK_P_NOT_STRONG_PRIME     DH_CHECK_P_NOT_SAFE_PRIME

  # define d2i_DHparams_fp(fp,x) \
      (DH *)ASN1_d2i_fp((char *(*)())DH_new, \
                        (char *(*)())d2i_DHparams, \
                        (fp), \
                        (unsigned char **)(x))
  # define i2d_DHparams_fp(fp,x) \
      ASN1_i2d_fp(i2d_DHparams,(fp), (unsigned char *)(x))
  # define d2i_DHparams_bio(bp,x) \
      ASN1_d2i_bio_of(DH, DH_new, d2i_DHparams, bp, x)
  # define i2d_DHparams_bio(bp,x) \
      ASN1_i2d_bio_of_const(DH,i2d_DHparams,bp,x)

  # define d2i_DHxparams_fp(fp,x) \
      (DH *)ASN1_d2i_fp((char *(*)())DH_new, \
                        (char *(*)())d2i_DHxparams, \
                        (fp), \
                        (unsigned char **)(x))
  # define i2d_DHxparams_fp(fp,x) \
      ASN1_i2d_fp(i2d_DHxparams,(fp), (unsigned char *)(x))
  # define d2i_DHxparams_bio(bp,x) \
      ASN1_d2i_bio_of(DH, DH_new, d2i_DHxparams, bp, x)
  # define i2d_DHxparams_bio(bp,x) \
      ASN1_i2d_bio_of_const(DH, i2d_DHxparams, bp, x)
}

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM DHparams_dup}
  DHparams_dup: function (dh: PDH): PDH; cdecl = nil;

  {$EXTERNALSYM DH_OpenSSL}
  DH_OpenSSL: function : PDH_Method; cdecl = nil;

  {$EXTERNALSYM DH_set_default_method}
  DH_set_default_method: procedure (const meth: PDH_Method); cdecl = nil;
  {$EXTERNALSYM DH_get_default_method}
  DH_get_default_method: function : PDH_Method; cdecl = nil;
  {$EXTERNALSYM DH_set_method}
  DH_set_method: function (dh: PDH; const meth: PDH_Method): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DH_new_method}
  DH_new_method: function (engine: PENGINE): PDH; cdecl = nil;

  {$EXTERNALSYM DH_new}
  DH_new: function : PDH; cdecl = nil;
  {$EXTERNALSYM DH_free}
  DH_free: procedure (dh: PDH); cdecl = nil;
  {$EXTERNALSYM DH_up_ref}
  DH_up_ref: function (dh: PDH): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DH_bits}
  DH_bits: function (const dh: PDH): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_size}
  DH_size: function (const dh: PDH): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DH_security_bits}
  DH_security_bits: function (const dh: PDH): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_set_ex_data}
  DH_set_ex_data: function (d: PDH; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DH_get_ex_data}
  DH_get_ex_data: function (d: PDH; idx: TIdC_INT): Pointer; cdecl = nil;

  {$EXTERNALSYM DH_generate_parameters_ex}
  DH_generate_parameters_ex: function (dh: PDH; prime_len: TIdC_INT; generator: TIdC_INT; cb: PBN_GENCB): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM DH_check_params_ex}
  DH_check_params_ex: function (const dh: PDH): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_check_ex}
  DH_check_ex: function (const dh: PDH): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_check_pub_key_ex}
  DH_check_pub_key_ex: function (const dh: PDH; const pub_key: PBIGNUM): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_check_params}
  DH_check_params: function (const dh: PDH; ret: PIdC_INT): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_check}
  DH_check: function (const dh: PDH; codes: PIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DH_check_pub_key}
  DH_check_pub_key: function (const dh: PDH; const pub_key: PBIGNUM; codes: PIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DH_generate_key}
  DH_generate_key: function (dh: PDH): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DH_compute_key}
  DH_compute_key: function (key: PByte; const pub_key: PBIGNUM; dh: PDH): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DH_compute_key_padded}
  DH_compute_key_padded: function (key: PByte; const pub_key: PBIGNUM; dh: PDH): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_DHparams}
  d2i_DHparams: function (a: PPDH; const pp: PPByte; _length: TIdC_LONG): PDH; cdecl = nil;
  {$EXTERNALSYM i2d_DHparams}
  i2d_DHparams: function (const a: PDH; pp: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_DHxparams}
  d2i_DHxparams: function (a: PPDH; const pp: PPByte; _length: TIdC_LONG): PDH; cdecl = nil;
  {$EXTERNALSYM i2d_DHxparams}
  i2d_DHxparams: function (const a: PDH; pp: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM DHparams_print}
  DHparams_print: function (bp: PBIO; const x: PDH): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM DH_get_1024_160}
  DH_get_1024_160: function : PDH; cdecl = nil;
  {$EXTERNALSYM DH_get_2048_224}
  DH_get_2048_224: function : PDH; cdecl = nil;
  {$EXTERNALSYM DH_get_2048_256}
  DH_get_2048_256: function : PDH; cdecl = nil;

  {$EXTERNALSYM DH_new_by_nid}
  DH_new_by_nid: function (nid: TIdC_INT): PDH; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_get_nid}
  DH_get_nid: function (const dh: PDH): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM DH_KDF_X9_42}
  DH_KDF_X9_42: function ( out_: PByte; outlen: TIdC_SIZET; const Z: PByte; Zlen: TIdC_SIZET; key_oid: PASN1_OBJECT; const ukm: PByte; ukmlen: TIdC_SIZET; const md: PEVP_MD): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM DH_get0_pqg}
  DH_get0_pqg: procedure (const dh: PDH; const p: PPBIGNUM; const q: PPBIGNUM; const g: PPBIGNUM); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_set0_pqg}
  DH_set0_pqg: function (dh: PDH; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_get0_key}
  DH_get0_key: procedure (const dh: PDH; const pub_key: PPBIGNUM; const priv_key: PPBIGNUM); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_set0_key}
  DH_set0_key: function (dh: PDH; pub_key: PBIGNUM; priv_key: PBIGNUM): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_get0_p}
  DH_get0_p: function (const dh: PDH): PBIGNUM; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_get0_q}
  DH_get0_q: function (const dh: PDH): PBIGNUM; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_get0_g}
  DH_get0_g: function (const dh: PDH): PBIGNUM; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_get0_priv_key}
  DH_get0_priv_key: function (const dh: PDH): PBIGNUM; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_get0_pub_key}
  DH_get0_pub_key: function (const dh: PDH): PBIGNUM; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_clear_flags}
  DH_clear_flags: procedure (dh: PDH; flags: TIdC_INT); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_test_flags}
  DH_test_flags: function (const dh: PDH; flags: TIdC_INT): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_set_flags}
  DH_set_flags: procedure (dh: PDH; flags: TIdC_INT); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_get0_engine}
  DH_get0_engine: function (d: PDH): PENGINE; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_get_length}
  DH_get_length: function (const dh: PDH): TIdC_LONG; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_set_length}
  DH_set_length: function (dh: PDH; _length: TIdC_LONG): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM DH_meth_new}
  DH_meth_new: function (const name: PIdAnsiChar; flags: TIdC_INT): PDH_Method; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_free}
  DH_meth_free: procedure (dhm: PDH_Method); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_dup}
  DH_meth_dup: function (const dhm: PDH_Method): PDH_Method; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_get0_name}
  DH_meth_get0_name: function (const dhm: PDH_Method): PIdAnsiChar; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_set1_name}
  DH_meth_set1_name: function (dhm: PDH_Method; const name: PIdAnsiChar): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_get_flags}
  DH_meth_get_flags: function (const dhm: PDH_Method): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_set_flags}
  DH_meth_set_flags: function (const dhm: PDH_Method; flags: TIdC_INT): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_get0_app_data}
  DH_meth_get0_app_data: function (const dhm: PDH_Method): Pointer; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_set0_app_data}
  DH_meth_set0_app_data: function (const dhm: PDH_Method; app_data: Pointer): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM DH_meth_get_generate_key}
  DH_meth_get_generate_key: function (const dhm: PDH_Method): DH_meth_generate_key_cb; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_set_generate_key}
  DH_meth_set_generate_key: function (const dhm: PDH_Method; generate_key: DH_meth_generate_key_cb): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM DH_meth_get_compute_key}
  DH_meth_get_compute_key: function (const dhm: PDH_Method): DH_meth_compute_key_cb; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_set_compute_key}
  DH_meth_set_compute_key: function (const dhm: PDH_Method; compute_key: DH_meth_compute_key_cb): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM DH_meth_get_bn_mod_exp}
  DH_meth_get_bn_mod_exp: function (const dhm: PDH_Method): DH_meth_bn_mod_exp_cb; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_set_bn_mod_exp}
  DH_meth_set_bn_mod_exp: function (const dhm: PDH_Method; bn_mod_expr: DH_meth_bn_mod_exp_cb): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM DH_meth_get_init}
  DH_meth_get_init: function (const dhm: PDH_Method): DH_meth_init_cb; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_set_init}
  DH_meth_set_init: function (const dhm: PDH_Method; init: DH_meth_init_cb): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM DH_meth_get_finish}
  DH_meth_get_finish: function (const dhm: PDH_Method): DH_meth_finish_cb; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_set_finish}
  DH_meth_set_finish: function (const dhm: PDH_Method; finish: DH_meth_finish_cb): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM DH_meth_get_generate_params}
  DH_meth_get_generate_params: function (const dhm: PDH_Method): DH_meth_generate_params_cb; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_set_generate_params}
  DH_meth_set_generate_params: function (const dhm: PDH_Method; generate_params: DH_meth_generate_params_cb): TIdC_INT; cdecl = nil; {introduced 1.1.0}

{
# define EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, len) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN, \
                        EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN, len, NULL)

# define EVP_PKEY_CTX_set_dh_paramgen_subprime_len(ctx, len) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN, \
                        EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN, len, NULL)

# define EVP_PKEY_CTX_set_dh_paramgen_type(ctx, typ) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN, \
                        EVP_PKEY_CTRL_DH_PARAMGEN_TYPE, typ, NULL)

# define EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, gen) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN, \
                        EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR, gen, NULL)

# define EVP_PKEY_CTX_set_dh_rfc5114(ctx, gen) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_PARAMGEN, \
                        EVP_PKEY_CTRL_DH_RFC5114, gen, NULL)

# define EVP_PKEY_CTX_set_dhx_rfc5114(ctx, gen) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_PARAMGEN, \
                        EVP_PKEY_CTRL_DH_RFC5114, gen, NULL)

# define EVP_PKEY_CTX_set_dh_nid(ctx, nid) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, \
                        EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN, \
                        EVP_PKEY_CTRL_DH_NID, nid, NULL)

# define EVP_PKEY_CTX_set_dh_pad(ctx, pad) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_DERIVE, \
                          EVP_PKEY_CTRL_DH_PAD, pad, NULL)

# define EVP_PKEY_CTX_set_dh_kdf_type(ctx, kdf) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_DH_KDF_TYPE, kdf, NULL)

# define EVP_PKEY_CTX_get_dh_kdf_type(ctx) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_DH_KDF_TYPE, -2, NULL)

# define EVP_PKEY_CTX_set0_dh_kdf_oid(ctx, oid) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_DH_KDF_OID, 0, (void *)(oid))

# define EVP_PKEY_CTX_get0_dh_kdf_oid(ctx, poid) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_GET_DH_KDF_OID, 0, (void *)(poid))

# define EVP_PKEY_CTX_set_dh_kdf_md(ctx, md) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_DH_KDF_MD, 0, (void *)(md))

# define EVP_PKEY_CTX_get_dh_kdf_md(ctx, pmd) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_GET_DH_KDF_MD, 0, (void *)(pmd))

# define EVP_PKEY_CTX_set_dh_kdf_outlen(ctx, len) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_DH_KDF_OUTLEN, len, NULL)

# define EVP_PKEY_CTX_get_dh_kdf_outlen(ctx, plen) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                        EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN, 0, (void *)(plen))

# define EVP_PKEY_CTX_set0_dh_kdf_ukm(ctx, p, plen) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_DH_KDF_UKM, plen, (void *)(p))

# define EVP_PKEY_CTX_get0_dh_kdf_ukm(ctx, p) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_GET_DH_KDF_UKM, 0, (void *)(p))
}

{$ELSE}
  {$EXTERNALSYM DHparams_dup}
  function DHparams_dup(dh: PDH): PDH cdecl; external CLibCrypto;

  {$EXTERNALSYM DH_OpenSSL}
  function DH_OpenSSL: PDH_Method cdecl; external CLibCrypto;

  {$EXTERNALSYM DH_set_default_method}
  procedure DH_set_default_method(const meth: PDH_Method) cdecl; external CLibCrypto;
  {$EXTERNALSYM DH_get_default_method}
  function DH_get_default_method: PDH_Method cdecl; external CLibCrypto;
  {$EXTERNALSYM DH_set_method}
  function DH_set_method(dh: PDH; const meth: PDH_Method): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DH_new_method}
  function DH_new_method(engine: PENGINE): PDH cdecl; external CLibCrypto;

  {$EXTERNALSYM DH_new}
  function DH_new: PDH cdecl; external CLibCrypto;
  {$EXTERNALSYM DH_free}
  procedure DH_free(dh: PDH) cdecl; external CLibCrypto;
  {$EXTERNALSYM DH_up_ref}
  function DH_up_ref(dh: PDH): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DH_bits}
  function DH_bits(const dh: PDH): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_size}
  function DH_size(const dh: PDH): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DH_security_bits}
  function DH_security_bits(const dh: PDH): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_set_ex_data}
  function DH_set_ex_data(d: PDH; idx: TIdC_INT; arg: Pointer): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DH_get_ex_data}
  function DH_get_ex_data(d: PDH; idx: TIdC_INT): Pointer cdecl; external CLibCrypto;

  {$EXTERNALSYM DH_generate_parameters_ex}
  function DH_generate_parameters_ex(dh: PDH; prime_len: TIdC_INT; generator: TIdC_INT; cb: PBN_GENCB): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM DH_check_params_ex}
  function DH_check_params_ex(const dh: PDH): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_check_ex}
  function DH_check_ex(const dh: PDH): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_check_pub_key_ex}
  function DH_check_pub_key_ex(const dh: PDH; const pub_key: PBIGNUM): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_check_params}
  function DH_check_params(const dh: PDH; ret: PIdC_INT): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_check}
  function DH_check(const dh: PDH; codes: PIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DH_check_pub_key}
  function DH_check_pub_key(const dh: PDH; const pub_key: PBIGNUM; codes: PIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DH_generate_key}
  function DH_generate_key(dh: PDH): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DH_compute_key}
  function DH_compute_key(key: PByte; const pub_key: PBIGNUM; dh: PDH): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DH_compute_key_padded}
  function DH_compute_key_padded(key: PByte; const pub_key: PBIGNUM; dh: PDH): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_DHparams}
  function d2i_DHparams(a: PPDH; const pp: PPByte; _length: TIdC_LONG): PDH cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_DHparams}
  function i2d_DHparams(const a: PDH; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_DHxparams}
  function d2i_DHxparams(a: PPDH; const pp: PPByte; _length: TIdC_LONG): PDH cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_DHxparams}
  function i2d_DHxparams(const a: PDH; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM DHparams_print}
  function DHparams_print(bp: PBIO; const x: PDH): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM DH_get_1024_160}
  function DH_get_1024_160: PDH cdecl; external CLibCrypto;
  {$EXTERNALSYM DH_get_2048_224}
  function DH_get_2048_224: PDH cdecl; external CLibCrypto;
  {$EXTERNALSYM DH_get_2048_256}
  function DH_get_2048_256: PDH cdecl; external CLibCrypto;

  {$EXTERNALSYM DH_new_by_nid}
  function DH_new_by_nid(nid: TIdC_INT): PDH cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_get_nid}
  function DH_get_nid(const dh: PDH): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM DH_KDF_X9_42}
  function DH_KDF_X9_42( out_: PByte; outlen: TIdC_SIZET; const Z: PByte; Zlen: TIdC_SIZET; key_oid: PASN1_OBJECT; const ukm: PByte; ukmlen: TIdC_SIZET; const md: PEVP_MD): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM DH_get0_pqg}
  procedure DH_get0_pqg(const dh: PDH; const p: PPBIGNUM; const q: PPBIGNUM; const g: PPBIGNUM) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_set0_pqg}
  function DH_set0_pqg(dh: PDH; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_get0_key}
  procedure DH_get0_key(const dh: PDH; const pub_key: PPBIGNUM; const priv_key: PPBIGNUM) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_set0_key}
  function DH_set0_key(dh: PDH; pub_key: PBIGNUM; priv_key: PBIGNUM): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_get0_p}
  function DH_get0_p(const dh: PDH): PBIGNUM cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_get0_q}
  function DH_get0_q(const dh: PDH): PBIGNUM cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_get0_g}
  function DH_get0_g(const dh: PDH): PBIGNUM cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_get0_priv_key}
  function DH_get0_priv_key(const dh: PDH): PBIGNUM cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_get0_pub_key}
  function DH_get0_pub_key(const dh: PDH): PBIGNUM cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_clear_flags}
  procedure DH_clear_flags(dh: PDH; flags: TIdC_INT) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_test_flags}
  function DH_test_flags(const dh: PDH; flags: TIdC_INT): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_set_flags}
  procedure DH_set_flags(dh: PDH; flags: TIdC_INT) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_get0_engine}
  function DH_get0_engine(d: PDH): PENGINE cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_get_length}
  function DH_get_length(const dh: PDH): TIdC_LONG cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_set_length}
  function DH_set_length(dh: PDH; _length: TIdC_LONG): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM DH_meth_new}
  function DH_meth_new(const name: PIdAnsiChar; flags: TIdC_INT): PDH_Method cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_free}
  procedure DH_meth_free(dhm: PDH_Method) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_dup}
  function DH_meth_dup(const dhm: PDH_Method): PDH_Method cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_get0_name}
  function DH_meth_get0_name(const dhm: PDH_Method): PIdAnsiChar cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_set1_name}
  function DH_meth_set1_name(dhm: PDH_Method; const name: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_get_flags}
  function DH_meth_get_flags(const dhm: PDH_Method): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_set_flags}
  function DH_meth_set_flags(const dhm: PDH_Method; flags: TIdC_INT): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_get0_app_data}
  function DH_meth_get0_app_data(const dhm: PDH_Method): Pointer cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_set0_app_data}
  function DH_meth_set0_app_data(const dhm: PDH_Method; app_data: Pointer): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM DH_meth_get_generate_key}
  function DH_meth_get_generate_key(const dhm: PDH_Method): DH_meth_generate_key_cb cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_set_generate_key}
  function DH_meth_set_generate_key(const dhm: PDH_Method; generate_key: DH_meth_generate_key_cb): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM DH_meth_get_compute_key}
  function DH_meth_get_compute_key(const dhm: PDH_Method): DH_meth_compute_key_cb cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_set_compute_key}
  function DH_meth_set_compute_key(const dhm: PDH_Method; compute_key: DH_meth_compute_key_cb): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM DH_meth_get_bn_mod_exp}
  function DH_meth_get_bn_mod_exp(const dhm: PDH_Method): DH_meth_bn_mod_exp_cb cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_set_bn_mod_exp}
  function DH_meth_set_bn_mod_exp(const dhm: PDH_Method; bn_mod_expr: DH_meth_bn_mod_exp_cb): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM DH_meth_get_init}
  function DH_meth_get_init(const dhm: PDH_Method): DH_meth_init_cb cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_set_init}
  function DH_meth_set_init(const dhm: PDH_Method; init: DH_meth_init_cb): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM DH_meth_get_finish}
  function DH_meth_get_finish(const dhm: PDH_Method): DH_meth_finish_cb cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_set_finish}
  function DH_meth_set_finish(const dhm: PDH_Method; finish: DH_meth_finish_cb): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM DH_meth_get_generate_params}
  function DH_meth_get_generate_params(const dhm: PDH_Method): DH_meth_generate_params_cb cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM DH_meth_set_generate_params}
  function DH_meth_set_generate_params(const dhm: PDH_Method; generate_params: DH_meth_generate_params_cb): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

{
# define EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, len) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN, \
                        EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN, len, NULL)

# define EVP_PKEY_CTX_set_dh_paramgen_subprime_len(ctx, len) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN, \
                        EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN, len, NULL)

# define EVP_PKEY_CTX_set_dh_paramgen_type(ctx, typ) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN, \
                        EVP_PKEY_CTRL_DH_PARAMGEN_TYPE, typ, NULL)

# define EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, gen) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN, \
                        EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR, gen, NULL)

# define EVP_PKEY_CTX_set_dh_rfc5114(ctx, gen) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_PARAMGEN, \
                        EVP_PKEY_CTRL_DH_RFC5114, gen, NULL)

# define EVP_PKEY_CTX_set_dhx_rfc5114(ctx, gen) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_PARAMGEN, \
                        EVP_PKEY_CTRL_DH_RFC5114, gen, NULL)

# define EVP_PKEY_CTX_set_dh_nid(ctx, nid) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, \
                        EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN, \
                        EVP_PKEY_CTRL_DH_NID, nid, NULL)

# define EVP_PKEY_CTX_set_dh_pad(ctx, pad) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_DERIVE, \
                          EVP_PKEY_CTRL_DH_PAD, pad, NULL)

# define EVP_PKEY_CTX_set_dh_kdf_type(ctx, kdf) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_DH_KDF_TYPE, kdf, NULL)

# define EVP_PKEY_CTX_get_dh_kdf_type(ctx) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_DH_KDF_TYPE, -2, NULL)

# define EVP_PKEY_CTX_set0_dh_kdf_oid(ctx, oid) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_DH_KDF_OID, 0, (void *)(oid))

# define EVP_PKEY_CTX_get0_dh_kdf_oid(ctx, poid) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_GET_DH_KDF_OID, 0, (void *)(poid))

# define EVP_PKEY_CTX_set_dh_kdf_md(ctx, md) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_DH_KDF_MD, 0, (void *)(md))

# define EVP_PKEY_CTX_get_dh_kdf_md(ctx, pmd) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_GET_DH_KDF_MD, 0, (void *)(pmd))

# define EVP_PKEY_CTX_set_dh_kdf_outlen(ctx, len) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_DH_KDF_OUTLEN, len, NULL)

# define EVP_PKEY_CTX_get_dh_kdf_outlen(ctx, plen) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                        EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN, 0, (void *)(plen))

# define EVP_PKEY_CTX_set0_dh_kdf_ukm(ctx, p, plen) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_DH_KDF_UKM, plen, (void *)(p))

# define EVP_PKEY_CTX_get0_dh_kdf_ukm(ctx, p) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_GET_DH_KDF_UKM, 0, (void *)(p))
}

{$ENDIF}

  {$EXTERNALSYM d2i_DHparams_bio}
function d2i_DHparams_bio(bp: PBIO; x: PPDH): PDH;
  {$EXTERNALSYM DH_get_ex_new_index}
function DH_get_ex_new_index(l : TIdC_LONG; p : PDH;
    newf : CRYPTO_EX_new; dupf : CRYPTO_EX_dup; freef : CRYPTO_EX_FREE) : TIdC_INT;

implementation

  uses
    classes, 
    TaurusTLSExceptionHandlers,
    TaurusTLSHeaders_asn1
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    ,TaurusTLSLoader
  {$ENDIF};

//#   define DH_get_ex_new_index(l, p, newf, dupf, freef) \
//        CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DH, l, p, newf, dupf, freef)

function DH_get_ex_new_index(l : TIdC_LONG; p : PDH;
    newf : CRYPTO_EX_new; dupf : CRYPTO_EX_dup; freef : CRYPTO_EX_FREE) : TIdC_INT;
{$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DH, l, p, newf, dupf, freef);
end;

function d2i_DHparams_bio(bp: PBIO; x: PPDH): PDH;
{$IFDEF USE_INLINE} inline; {$ENDIF}
begin
    Result := PDH(ASN1_d2i_bio(@DH_new, @d2i_DHparams, bp, PPointer(x)));
end;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
const
  DH_bits_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_security_bits_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_check_params_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_check_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_check_pub_key_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_check_params_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_new_by_nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_get_nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_get0_pqg_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_set0_pqg_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_get0_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_set0_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_get0_p_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_get0_q_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_get0_g_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_get0_priv_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_get0_pub_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_clear_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_test_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_set_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_get0_engine_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_get0_engine_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  DH_get_length_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_set_length_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_get0_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_set1_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_get_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_set_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_get0_app_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_set0_app_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_get_generate_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_set_generate_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_get_compute_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_set_compute_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_get_bn_mod_exp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_set_bn_mod_exp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_get_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_set_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_get_finish_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_set_finish_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_get_generate_params_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  DH_meth_set_generate_params_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

const
  DHparams_dup_procname = 'DHparams_dup';

  DH_OpenSSL_procname = 'DH_OpenSSL';

  DH_set_default_method_procname = 'DH_set_default_method';
  DH_get_default_method_procname = 'DH_get_default_method';
  DH_set_method_procname = 'DH_set_method';
  DH_new_method_procname = 'DH_new_method';

  DH_new_procname = 'DH_new';
  DH_free_procname = 'DH_free';
  DH_up_ref_procname = 'DH_up_ref';
  DH_bits_procname = 'DH_bits'; {introduced 1.1.0}
  DH_size_procname = 'DH_size';
  DH_security_bits_procname = 'DH_security_bits'; {introduced 1.1.0}
  DH_set_ex_data_procname = 'DH_set_ex_data';
  DH_get_ex_data_procname = 'DH_get_ex_data';

  DH_generate_parameters_ex_procname = 'DH_generate_parameters_ex';

  DH_check_params_ex_procname = 'DH_check_params_ex'; {introduced 1.1.0}
  DH_check_ex_procname = 'DH_check_ex'; {introduced 1.1.0}
  DH_check_pub_key_ex_procname = 'DH_check_pub_key_ex'; {introduced 1.1.0}
  DH_check_params_procname = 'DH_check_params'; {introduced 1.1.0}
  DH_check_procname = 'DH_check';
  DH_check_pub_key_procname = 'DH_check_pub_key';
  DH_generate_key_procname = 'DH_generate_key';
  DH_compute_key_procname = 'DH_compute_key';
  DH_compute_key_padded_procname = 'DH_compute_key_padded';
  d2i_DHparams_procname = 'd2i_DHparams';
  i2d_DHparams_procname = 'i2d_DHparams';
  d2i_DHxparams_procname = 'd2i_DHxparams';
  i2d_DHxparams_procname = 'i2d_DHxparams';
  DHparams_print_procname = 'DHparams_print';

  DH_get_1024_160_procname = 'DH_get_1024_160';
  DH_get_2048_224_procname = 'DH_get_2048_224';
  DH_get_2048_256_procname = 'DH_get_2048_256';

  DH_new_by_nid_procname = 'DH_new_by_nid'; {introduced 1.1.0}
  DH_get_nid_procname = 'DH_get_nid'; {introduced 1.1.0}

  DH_KDF_X9_42_procname = 'DH_KDF_X9_42';

  DH_get0_pqg_procname = 'DH_get0_pqg'; {introduced 1.1.0}
  DH_set0_pqg_procname = 'DH_set0_pqg'; {introduced 1.1.0}
  DH_get0_key_procname = 'DH_get0_key'; {introduced 1.1.0}
  DH_set0_key_procname = 'DH_set0_key'; {introduced 1.1.0}
  DH_get0_p_procname = 'DH_get0_p'; {introduced 1.1.0}
  DH_get0_q_procname = 'DH_get0_q'; {introduced 1.1.0}
  DH_get0_g_procname = 'DH_get0_g'; {introduced 1.1.0}
  DH_get0_priv_key_procname = 'DH_get0_priv_key'; {introduced 1.1.0}
  DH_get0_pub_key_procname = 'DH_get0_pub_key'; {introduced 1.1.0}
  DH_clear_flags_procname = 'DH_clear_flags'; {introduced 1.1.0}
  DH_test_flags_procname = 'DH_test_flags'; {introduced 1.1.0}
  DH_set_flags_procname = 'DH_set_flags'; {introduced 1.1.0}
  DH_get0_engine_procname = 'DH_get0_engine'; {introduced 1.1.0}
  DH_get_length_procname = 'DH_get_length'; {introduced 1.1.0}
  DH_set_length_procname = 'DH_set_length'; {introduced 1.1.0}

  DH_meth_new_procname = 'DH_meth_new'; {introduced 1.1.0}
  DH_meth_free_procname = 'DH_meth_free'; {introduced 1.1.0}
  DH_meth_dup_procname = 'DH_meth_dup'; {introduced 1.1.0}
  DH_meth_get0_name_procname = 'DH_meth_get0_name'; {introduced 1.1.0}
  DH_meth_set1_name_procname = 'DH_meth_set1_name'; {introduced 1.1.0}
  DH_meth_get_flags_procname = 'DH_meth_get_flags'; {introduced 1.1.0}
  DH_meth_set_flags_procname = 'DH_meth_set_flags'; {introduced 1.1.0}
  DH_meth_get0_app_data_procname = 'DH_meth_get0_app_data'; {introduced 1.1.0}
  DH_meth_set0_app_data_procname = 'DH_meth_set0_app_data'; {introduced 1.1.0}

  DH_meth_get_generate_key_procname = 'DH_meth_get_generate_key'; {introduced 1.1.0}
  DH_meth_set_generate_key_procname = 'DH_meth_set_generate_key'; {introduced 1.1.0}

  DH_meth_get_compute_key_procname = 'DH_meth_get_compute_key'; {introduced 1.1.0}
  DH_meth_set_compute_key_procname = 'DH_meth_set_compute_key'; {introduced 1.1.0}

  DH_meth_get_bn_mod_exp_procname = 'DH_meth_get_bn_mod_exp'; {introduced 1.1.0}
  DH_meth_set_bn_mod_exp_procname = 'DH_meth_set_bn_mod_exp'; {introduced 1.1.0}

  DH_meth_get_init_procname = 'DH_meth_get_init'; {introduced 1.1.0}
  DH_meth_set_init_procname = 'DH_meth_set_init'; {introduced 1.1.0}

  DH_meth_get_finish_procname = 'DH_meth_get_finish'; {introduced 1.1.0}
  DH_meth_set_finish_procname = 'DH_meth_set_finish'; {introduced 1.1.0}

  DH_meth_get_generate_params_procname = 'DH_meth_get_generate_params'; {introduced 1.1.0}
  DH_meth_set_generate_params_procname = 'DH_meth_set_generate_params'; {introduced 1.1.0}

{
# define EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, len) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN, \
                        EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN, len, NULL)

# define EVP_PKEY_CTX_set_dh_paramgen_subprime_len(ctx, len) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN, \
                        EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN, len, NULL)

# define EVP_PKEY_CTX_set_dh_paramgen_type(ctx, typ) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN, \
                        EVP_PKEY_CTRL_DH_PARAMGEN_TYPE, typ, NULL)

# define EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, gen) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN, \
                        EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR, gen, NULL)

# define EVP_PKEY_CTX_set_dh_rfc5114(ctx, gen) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_PARAMGEN, \
                        EVP_PKEY_CTRL_DH_RFC5114, gen, NULL)

# define EVP_PKEY_CTX_set_dhx_rfc5114(ctx, gen) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_PARAMGEN, \
                        EVP_PKEY_CTRL_DH_RFC5114, gen, NULL)

# define EVP_PKEY_CTX_set_dh_nid(ctx, nid) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, \
                        EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN, \
                        EVP_PKEY_CTRL_DH_NID, nid, NULL)

# define EVP_PKEY_CTX_set_dh_pad(ctx, pad) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_DERIVE, \
                          EVP_PKEY_CTRL_DH_PAD, pad, NULL)

# define EVP_PKEY_CTX_set_dh_kdf_type(ctx, kdf) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_DH_KDF_TYPE, kdf, NULL)

# define EVP_PKEY_CTX_get_dh_kdf_type(ctx) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_DH_KDF_TYPE, -2, NULL)

# define EVP_PKEY_CTX_set0_dh_kdf_oid(ctx, oid) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_DH_KDF_OID, 0, (void *)(oid))

# define EVP_PKEY_CTX_get0_dh_kdf_oid(ctx, poid) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_GET_DH_KDF_OID, 0, (void *)(poid))

# define EVP_PKEY_CTX_set_dh_kdf_md(ctx, md) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_DH_KDF_MD, 0, (void *)(md))

# define EVP_PKEY_CTX_get_dh_kdf_md(ctx, pmd) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_GET_DH_KDF_MD, 0, (void *)(pmd))

# define EVP_PKEY_CTX_set_dh_kdf_outlen(ctx, len) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_DH_KDF_OUTLEN, len, NULL)

# define EVP_PKEY_CTX_get_dh_kdf_outlen(ctx, plen) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                        EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN, 0, (void *)(plen))

# define EVP_PKEY_CTX_set0_dh_kdf_ukm(ctx, p, plen) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_DH_KDF_UKM, plen, (void *)(p))

# define EVP_PKEY_CTX_get0_dh_kdf_ukm(ctx, p) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_GET_DH_KDF_UKM, 0, (void *)(p))
}
  {$IFNDEF _FIXINSIGHT_}
{$I TaurusTLSNoRetValOff.inc}
function  ERR_DHparams_dup(dh: PDH): PDH; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DHparams_dup_procname);
end;


function  ERR_DH_OpenSSL: PDH_Method; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_OpenSSL_procname);
end;


procedure  ERR_DH_set_default_method(const meth: PDH_Method); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_set_default_method_procname);
end;


function  ERR_DH_get_default_method: PDH_Method; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get_default_method_procname);
end;


function  ERR_DH_set_method(dh: PDH; const meth: PDH_Method): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_set_method_procname);
end;


function  ERR_DH_new_method(engine: PENGINE): PDH; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_new_method_procname);
end;



function  ERR_DH_new: PDH; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_new_procname);
end;


procedure  ERR_DH_free(dh: PDH); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_free_procname);
end;


function  ERR_DH_up_ref(dh: PDH): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_up_ref_procname);
end;


function  ERR_DH_bits(const dh: PDH): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_bits_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_size(const dh: PDH): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_size_procname);
end;


function  ERR_DH_security_bits(const dh: PDH): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_security_bits_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_set_ex_data(d: PDH; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_set_ex_data_procname);
end;


function  ERR_DH_get_ex_data(d: PDH; idx: TIdC_INT): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get_ex_data_procname);
end;



function  ERR_DH_generate_parameters_ex(dh: PDH; prime_len: TIdC_INT; generator: TIdC_INT;
  cb: PBN_GENCB): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_generate_parameters_ex_procname);
end;



function  ERR_DH_check_params_ex(const dh: PDH): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_check_params_ex_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_check_ex(const dh: PDH): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_check_ex_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_check_pub_key_ex(const dh: PDH; const pub_key: PBIGNUM): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_check_pub_key_ex_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_check_params(const dh: PDH; ret: PIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_check_params_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_check(const dh: PDH; codes: PIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_check_procname);
end;


function  ERR_DH_check_pub_key(const dh: PDH; const pub_key: PBIGNUM; codes: PIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_check_pub_key_procname);
end;


function  ERR_DH_generate_key(dh: PDH): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_generate_key_procname);
end;


function  ERR_DH_compute_key(key: PByte; const pub_key: PBIGNUM; dh: PDH): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_compute_key_procname);
end;


function  ERR_DH_compute_key_padded(key: PByte; const pub_key: PBIGNUM; dh: PDH): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_compute_key_padded_procname);
end;


function  ERR_d2i_DHparams(a: PPDH; const pp: PPByte; _length: TIdC_LONG): PDH; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_DHparams_procname);
end;


function  ERR_i2d_DHparams(const a: PDH; pp: PPByte): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_DHparams_procname);
end;


function  ERR_d2i_DHxparams(a: PPDH; const pp: PPByte; _length: TIdC_LONG): PDH; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_DHxparams_procname);
end;


function  ERR_i2d_DHxparams(const a: PDH; pp: PPByte): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_DHxparams_procname);
end;


function  ERR_DHparams_print(bp: PBIO; const x: PDH): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DHparams_print_procname);
end;



function  ERR_DH_get_1024_160: PDH; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get_1024_160_procname);
end;


function  ERR_DH_get_2048_224: PDH; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get_2048_224_procname);
end;


function  ERR_DH_get_2048_256: PDH; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get_2048_256_procname);
end;



function  ERR_DH_new_by_nid(nid: TIdC_INT): PDH; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_new_by_nid_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_get_nid(const dh: PDH): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get_nid_procname);
end;

 {introduced 1.1.0}

function  ERR_DH_KDF_X9_42( out_: PByte; outlen: TIdC_SIZET; const Z: PByte; Zlen: TIdC_SIZET;
  key_oid: PASN1_OBJECT; const ukm: PByte; ukmlen: TIdC_SIZET; const md: PEVP_MD): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_KDF_X9_42_procname);
end;



procedure  ERR_DH_get0_pqg(const dh: PDH; const p: PPBIGNUM; const q: PPBIGNUM; const g: PPBIGNUM); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get0_pqg_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_set0_pqg(dh: PDH; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_set0_pqg_procname);
end;

 {introduced 1.1.0}
procedure  ERR_DH_get0_key(const dh: PDH; const pub_key: PPBIGNUM; const priv_key: PPBIGNUM); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get0_key_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_set0_key(dh: PDH; pub_key: PBIGNUM; priv_key: PBIGNUM): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_set0_key_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_get0_p(const dh: PDH): PBIGNUM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get0_p_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_get0_q(const dh: PDH): PBIGNUM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get0_q_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_get0_g(const dh: PDH): PBIGNUM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get0_g_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_get0_priv_key(const dh: PDH): PBIGNUM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get0_priv_key_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_get0_pub_key(const dh: PDH): PBIGNUM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get0_pub_key_procname);
end;

 {introduced 1.1.0}
procedure  ERR_DH_clear_flags(dh: PDH; flags: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_clear_flags_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_test_flags(const dh: PDH; flags: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_test_flags_procname);
end;

 {introduced 1.1.0}
procedure  ERR_DH_set_flags(dh: PDH; flags: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_set_flags_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_get0_engine(d: PDH): PENGINE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get0_engine_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_get_length(const dh: PDH): TIdC_LONG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_get_length_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_set_length(dh: PDH; _length: TIdC_LONG): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_set_length_procname);
end;

 {introduced 1.1.0}

function  ERR_DH_meth_new(const name: PIdAnsiChar; flags: TIdC_INT): PDH_Method; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_new_procname);
end;

 {introduced 1.1.0}
procedure  ERR_DH_meth_free(dhm: PDH_Method); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_free_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_meth_dup(const dhm: PDH_Method): PDH_Method; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_dup_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_meth_get0_name(const dhm: PDH_Method): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_get0_name_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_meth_set1_name(dhm: PDH_Method; const name: PIdAnsiChar): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_set1_name_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_meth_get_flags(const dhm: PDH_Method): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_get_flags_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_meth_set_flags(const dhm: PDH_Method; flags: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_set_flags_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_meth_get0_app_data(const dhm: PDH_Method): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_get0_app_data_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_meth_set0_app_data(const dhm: PDH_Method; app_data: Pointer): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_set0_app_data_procname);
end;

 {introduced 1.1.0}

function  ERR_DH_meth_get_generate_key(const dhm: PDH_Method): DH_meth_generate_key_cb; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_get_generate_key_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_meth_set_generate_key(const dhm: PDH_Method; generate_key: DH_meth_generate_key_cb): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_set_generate_key_procname);
end;

 {introduced 1.1.0}

function  ERR_DH_meth_get_compute_key(const dhm: PDH_Method): DH_meth_compute_key_cb; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_get_compute_key_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_meth_set_compute_key(const dhm: PDH_Method; compute_key: DH_meth_compute_key_cb): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_set_compute_key_procname);
end;

 {introduced 1.1.0}

function  ERR_DH_meth_get_bn_mod_exp(const dhm: PDH_Method): DH_meth_bn_mod_exp_cb; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_get_bn_mod_exp_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_meth_set_bn_mod_exp(const dhm: PDH_Method; bn_mod_expr: DH_meth_bn_mod_exp_cb): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_set_bn_mod_exp_procname);
end;

 {introduced 1.1.0}

function  ERR_DH_meth_get_init(const dhm: PDH_Method): DH_meth_init_cb; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_get_init_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_meth_set_init(const dhm: PDH_Method; init: DH_meth_init_cb): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_set_init_procname);
end;

 {introduced 1.1.0}

function  ERR_DH_meth_get_finish(const dhm: PDH_Method): DH_meth_finish_cb; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_get_finish_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_meth_set_finish(const dhm: PDH_Method; finish: DH_meth_finish_cb): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_set_finish_procname);
end;

 {introduced 1.1.0}

function  ERR_DH_meth_get_generate_params(const dhm: PDH_Method): DH_meth_generate_params_cb; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_get_generate_params_procname);
end;

 {introduced 1.1.0}
function  ERR_DH_meth_set_generate_params(const dhm: PDH_Method;
  generate_params: DH_meth_generate_params_cb): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DH_meth_set_generate_params_procname);
end;

 {introduced 1.1.0}

{
# define EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, len) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN, \
                        EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN, len, NULL)

# define EVP_PKEY_CTX_set_dh_paramgen_subprime_len(ctx, len) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN, \
                        EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN, len, NULL)

# define EVP_PKEY_CTX_set_dh_paramgen_type(ctx, typ) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN, \
                        EVP_PKEY_CTRL_DH_PARAMGEN_TYPE, typ, NULL)

# define EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, gen) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN, \
                        EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR, gen, NULL)

# define EVP_PKEY_CTX_set_dh_rfc5114(ctx, gen) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_PARAMGEN, \
                        EVP_PKEY_CTRL_DH_RFC5114, gen, NULL)

# define EVP_PKEY_CTX_set_dhx_rfc5114(ctx, gen) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_PARAMGEN, \
                        EVP_PKEY_CTRL_DH_RFC5114, gen, NULL)

# define EVP_PKEY_CTX_set_dh_nid(ctx, nid) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, \
                        EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN, \
                        EVP_PKEY_CTRL_DH_NID, nid, NULL)

# define EVP_PKEY_CTX_set_dh_pad(ctx, pad) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_DERIVE, \
                          EVP_PKEY_CTRL_DH_PAD, pad, NULL)

# define EVP_PKEY_CTX_set_dh_kdf_type(ctx, kdf) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_DH_KDF_TYPE, kdf, NULL)

# define EVP_PKEY_CTX_get_dh_kdf_type(ctx) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_DH_KDF_TYPE, -2, NULL)

# define EVP_PKEY_CTX_set0_dh_kdf_oid(ctx, oid) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_DH_KDF_OID, 0, (void *)(oid))

# define EVP_PKEY_CTX_get0_dh_kdf_oid(ctx, poid) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_GET_DH_KDF_OID, 0, (void *)(poid))

# define EVP_PKEY_CTX_set_dh_kdf_md(ctx, md) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_DH_KDF_MD, 0, (void *)(md))

# define EVP_PKEY_CTX_get_dh_kdf_md(ctx, pmd) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_GET_DH_KDF_MD, 0, (void *)(pmd))

# define EVP_PKEY_CTX_set_dh_kdf_outlen(ctx, len) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_DH_KDF_OUTLEN, len, NULL)

# define EVP_PKEY_CTX_get_dh_kdf_outlen(ctx, plen) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                        EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN, 0, (void *)(plen))

# define EVP_PKEY_CTX_set0_dh_kdf_ukm(ctx, p, plen) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_DH_KDF_UKM, plen, (void *)(p))

# define EVP_PKEY_CTX_get0_dh_kdf_ukm(ctx, p) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_GET_DH_KDF_UKM, 0, (void *)(p))
}

{$I TaurusTLSNoRetValOn.inc}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
end;

procedure Unload;
begin
  DHparams_dup := nil;
  DH_OpenSSL := nil;
  DH_set_default_method := nil;
  DH_get_default_method := nil;
  DH_set_method := nil;
  DH_new_method := nil;
  DH_new := nil;
  DH_free := nil;
  DH_up_ref := nil;
  DH_bits := nil; {introduced 1.1.0}
  DH_size := nil;
  DH_security_bits := nil; {introduced 1.1.0}
  DH_set_ex_data := nil;
  DH_get_ex_data := nil;
  DH_generate_parameters_ex := nil;
  DH_check_params_ex := nil; {introduced 1.1.0}
  DH_check_ex := nil; {introduced 1.1.0}
  DH_check_pub_key_ex := nil; {introduced 1.1.0}
  DH_check_params := nil; {introduced 1.1.0}
  DH_check := nil;
  DH_check_pub_key := nil;
  DH_generate_key := nil;
  DH_compute_key := nil;
  DH_compute_key_padded := nil;
  d2i_DHparams := nil;
  i2d_DHparams := nil;
  d2i_DHxparams := nil;
  i2d_DHxparams := nil;
  DHparams_print := nil;
  DH_get_1024_160 := nil;
  DH_get_2048_224 := nil;
  DH_get_2048_256 := nil;
  DH_new_by_nid := nil; {introduced 1.1.0}
  DH_get_nid := nil; {introduced 1.1.0}
  DH_KDF_X9_42 := nil;
  DH_get0_pqg := nil; {introduced 1.1.0}
  DH_set0_pqg := nil; {introduced 1.1.0}
  DH_get0_key := nil; {introduced 1.1.0}
  DH_set0_key := nil; {introduced 1.1.0}
  DH_get0_p := nil; {introduced 1.1.0}
  DH_get0_q := nil; {introduced 1.1.0}
  DH_get0_g := nil; {introduced 1.1.0}
  DH_get0_priv_key := nil; {introduced 1.1.0}
  DH_get0_pub_key := nil; {introduced 1.1.0}
  DH_clear_flags := nil; {introduced 1.1.0}
  DH_test_flags := nil; {introduced 1.1.0}
  DH_set_flags := nil; {introduced 1.1.0}
  DH_get0_engine := nil; {introduced 1.1.0}
  DH_get_length := nil; {introduced 1.1.0}
  DH_set_length := nil; {introduced 1.1.0}
  DH_meth_new := nil; {introduced 1.1.0}
  DH_meth_free := nil; {introduced 1.1.0}
  DH_meth_dup := nil; {introduced 1.1.0}
  DH_meth_get0_name := nil; {introduced 1.1.0}
  DH_meth_set1_name := nil; {introduced 1.1.0}
  DH_meth_get_flags := nil; {introduced 1.1.0}
  DH_meth_set_flags := nil; {introduced 1.1.0}
  DH_meth_get0_app_data := nil; {introduced 1.1.0}
  DH_meth_set0_app_data := nil; {introduced 1.1.0}
  DH_meth_get_generate_key := nil; {introduced 1.1.0}
  DH_meth_set_generate_key := nil; {introduced 1.1.0}
  DH_meth_get_compute_key := nil; {introduced 1.1.0}
  DH_meth_set_compute_key := nil; {introduced 1.1.0}
  DH_meth_get_bn_mod_exp := nil; {introduced 1.1.0}
  DH_meth_set_bn_mod_exp := nil; {introduced 1.1.0}
  DH_meth_get_init := nil; {introduced 1.1.0}
  DH_meth_set_init := nil; {introduced 1.1.0}
  DH_meth_get_finish := nil; {introduced 1.1.0}
  DH_meth_set_finish := nil; {introduced 1.1.0}
  DH_meth_get_generate_params := nil; {introduced 1.1.0}
  DH_meth_set_generate_params := nil; {introduced 1.1.0}
end;
  {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
