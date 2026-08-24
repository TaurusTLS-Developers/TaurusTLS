/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_ec.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_ec.h2pas
     and this file regenerated. TaurusTLSHeaders_ec.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_ec;

interface

// Headers for OpenSSL 1.1.1
// ec.h


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
  {$EXTERNALSYM OPENSSL_EC_EXPLICIT_CURVE}
  OPENSSL_EC_EXPLICIT_CURVE = $000;
  {$EXTERNALSYM OPENSSL_EC_NAMED_CURVE}
  OPENSSL_EC_NAMED_CURVE    = $001;
  {$EXTERNALSYM EC_PKEY_NO_PARAMETERS}
  EC_PKEY_NO_PARAMETERS = $001;
  {$EXTERNALSYM EC_PKEY_NO_PUBKEY}
  EC_PKEY_NO_PUBKEY     = $002;
  {$EXTERNALSYM EC_FLAG_NON_FIPS_ALLOW}
  EC_FLAG_NON_FIPS_ALLOW = $1;
  {$EXTERNALSYM EC_FLAG_FIPS_CHECKED}
  EC_FLAG_FIPS_CHECKED   = $2;
  {$EXTERNALSYM EC_FLAG_COFACTOR_ECDH}
  EC_FLAG_COFACTOR_ECDH  = $1000;
  {$EXTERNALSYM EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID}
  EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID = (EVP_PKEY_ALG_CTRL + 1);
  {$EXTERNALSYM EVP_PKEY_CTRL_EC_PARAM_ENC}
  EVP_PKEY_CTRL_EC_PARAM_ENC          = (EVP_PKEY_ALG_CTRL + 2);
  {$EXTERNALSYM EVP_PKEY_CTRL_EC_ECDH_COFACTOR}
  EVP_PKEY_CTRL_EC_ECDH_COFACTOR      = (EVP_PKEY_ALG_CTRL + 3);
  {$EXTERNALSYM EVP_PKEY_CTRL_EC_KDF_TYPE}
  EVP_PKEY_CTRL_EC_KDF_TYPE           = (EVP_PKEY_ALG_CTRL + 4);
  {$EXTERNALSYM EVP_PKEY_CTRL_EC_KDF_MD}
  EVP_PKEY_CTRL_EC_KDF_MD             = (EVP_PKEY_ALG_CTRL + 5);
  {$EXTERNALSYM EVP_PKEY_CTRL_GET_EC_KDF_MD}
  EVP_PKEY_CTRL_GET_EC_KDF_MD         = (EVP_PKEY_ALG_CTRL + 6);
  {$EXTERNALSYM EVP_PKEY_CTRL_EC_KDF_OUTLEN}
  EVP_PKEY_CTRL_EC_KDF_OUTLEN         = (EVP_PKEY_ALG_CTRL + 7);
  {$EXTERNALSYM EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN}
  EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN     = (EVP_PKEY_ALG_CTRL + 8);
  {$EXTERNALSYM EVP_PKEY_CTRL_EC_KDF_UKM}
  EVP_PKEY_CTRL_EC_KDF_UKM            = (EVP_PKEY_ALG_CTRL + 9);
  {$EXTERNALSYM EVP_PKEY_CTRL_GET_EC_KDF_UKM}
  EVP_PKEY_CTRL_GET_EC_KDF_UKM        = (EVP_PKEY_ALG_CTRL + 10);
  {$EXTERNALSYM EVP_PKEY_CTRL_SET1_ID}
  EVP_PKEY_CTRL_SET1_ID               = (EVP_PKEY_ALG_CTRL + 11);
  {$EXTERNALSYM EVP_PKEY_CTRL_GET1_ID}
  EVP_PKEY_CTRL_GET1_ID               = (EVP_PKEY_ALG_CTRL + 12);
  {$EXTERNALSYM EVP_PKEY_CTRL_GET1_ID_LEN}
  EVP_PKEY_CTRL_GET1_ID_LEN           = (EVP_PKEY_ALG_CTRL + 13);
  {$EXTERNALSYM EVP_PKEY_ECDH_KDF_NONE}
  EVP_PKEY_ECDH_KDF_NONE              = 1;
  {$EXTERNALSYM EVP_PKEY_ECDH_KDF_X9_63}
  EVP_PKEY_ECDH_KDF_X9_63             = 2;
  {$EXTERNALSYM EVP_PKEY_ECDH_KDF_X9_62}
  EVP_PKEY_ECDH_KDF_X9_62             = EVP_PKEY_ECDH_KDF_X9_63;

type
  {$MINENUMSIZE 4}
  {$EXTERNALSYM point_conversion_form_t}
  point_conversion_form_t = (
  {$EXTERNALSYM POINT_CONVERSION_COMPRESSED}
    POINT_CONVERSION_COMPRESSED = 2,
  {$EXTERNALSYM POINT_CONVERSION_UNCOMPRESSED}
    POINT_CONVERSION_UNCOMPRESSED = 4,
  {$EXTERNALSYM POINT_CONVERSION_HYBRID}
    POINT_CONVERSION_HYBRID = 6
  );

  {$EXTERNALSYM EC_METHOD}
  EC_METHOD = record end; // ec_method_st
  {$EXTERNALSYM PEC_METHOD}
  PEC_METHOD = ^EC_METHOD;

  {$EXTERNALSYM EC_GROUP}
  EC_GROUP = record end; // ec_group_st
  {$EXTERNALSYM PEC_GROUP}
  PEC_GROUP = ^EC_GROUP;
  {$EXTERNALSYM PPEC_GROUP}
  PPEC_GROUP = ^PEC_GROUP;

  {$EXTERNALSYM EC_POINT}
  EC_POINT = record end; // ec_point_st
  {$EXTERNALSYM PEC_POINT}
  PEC_POINT = ^EC_POINT;
  {$EXTERNALSYM PPEC_POINT}
  PPEC_POINT = ^PEC_POINT;

  {$EXTERNALSYM ECPKPARAMETERS}
  ECPKPARAMETERS = record end; // ecpk_parameters_st
  {$EXTERNALSYM PECPKPARAMETERS}
  PECPKPARAMETERS = ^ECPKPARAMETERS;

  {$EXTERNALSYM ECPARAMETERS}
  ECPARAMETERS = record end; // ec_parameters_st
  {$EXTERNALSYM PECPARAMETERS}
  PECPARAMETERS = ^ECPARAMETERS;

  {$EXTERNALSYM EC_builtin_curve}
  EC_builtin_curve = record
    nid: TIdC_INT;
    comment: PIdAnsiChar;
  end;
  {$EXTERNALSYM PEC_builtin_curve}
  PEC_builtin_curve = ^EC_builtin_curve;

  {$EXTERNALSYM ECDSA_SIG}
  ECDSA_SIG = record end; // ECDSA_SIG_st
  {$EXTERNALSYM PECDSA_SIG}
  PECDSA_SIG = ^ECDSA_SIG;
  {$EXTERNALSYM PPECDSA_SIG}
  PPECDSA_SIG = ^PECDSA_SIG;

  {$EXTERNALSYM ECDH_compute_key_KDF}
  ECDH_compute_key_KDF = function(const in_: Pointer; inlen: TIdC_SIZET; out_: Pointer; outlen: PIdC_SIZET): Pointer; cdecl;

  {$EXTERNALSYM EC_KEY_METHOD_init_init}
  EC_KEY_METHOD_init_init = function(key: PEC_KEY): TIdC_INT; cdecl;
  {$EXTERNALSYM EC_KEY_METHOD_init_finish}
  EC_KEY_METHOD_init_finish = procedure(key: PEC_KEY); cdecl;
  {$EXTERNALSYM EC_KEY_METHOD_init_copy}
  EC_KEY_METHOD_init_copy = function(dest: PEC_KEY; const src: PEC_KEY): TIdC_INT; cdecl;
  {$EXTERNALSYM EC_KEY_METHOD_init_set_group}
  EC_KEY_METHOD_init_set_group = function(key: PEC_KEY; const grp: PEC_GROUP): TIdC_INT; cdecl;
  {$EXTERNALSYM EC_KEY_METHOD_init_set_private}
  EC_KEY_METHOD_init_set_private = function(key: PEC_KEY; const priv_key: PBIGNUM): TIdC_INT; cdecl;
  {$EXTERNALSYM EC_KEY_METHOD_init_set_public}
  EC_KEY_METHOD_init_set_public = function(key: PEC_KEY; const pub_key: PEC_POINT): TIdC_INT; cdecl;

  {$EXTERNALSYM EC_KEY_METHOD_keygen_keygen}
  EC_KEY_METHOD_keygen_keygen = function(key: PEC_KEY): TIdC_INT; cdecl;

  {$EXTERNALSYM EC_KEY_METHOD_compute_key_ckey}
  EC_KEY_METHOD_compute_key_ckey = function(psec: PPByte; pseclen: PIdC_SIZET; const pub_key: PEC_POINT; const ecdh: PEC_KEY): TIdC_INT; cdecl;

  {$EXTERNALSYM EC_KEY_METHOD_sign_sign}
  EC_KEY_METHOD_sign_sign = function(type_: TIdC_INT; const dgst: PByte; dlen: TIdC_INT; sig: PByte; siglen: PIdC_UINT; const kinv: PBIGNUM; const r: PBIGNUM; eckey: PEC_KEY): TIdC_INT; cdecl;
  {$EXTERNALSYM EC_KEY_METHOD_sign_sign_setup}
  EC_KEY_METHOD_sign_sign_setup = function(eckey: PEC_KEY; ctx_in: PBN_CTX; kinvp: PPBIGNUM; rp: PPBIGNUM): TIdC_INT; cdecl;
  {$EXTERNALSYM EC_KEY_METHOD_sign_sign_sig}
  EC_KEY_METHOD_sign_sign_sig = function(const dgst: PByte; dgst_len: TIdC_INT; const in_kinv: PBIGNUM; const in_r: PBIGNUM; eckey: PEC_KEY): PECDSA_SIG; cdecl;

  {$EXTERNALSYM EC_KEY_METHOD_verify_verify}
  EC_KEY_METHOD_verify_verify = function(type_: TIdC_INT; const dgst: PByte; dgst_len: TIdC_INT; const sigbuf: PByte; sig_len: TIdC_INT; eckey: PEC_KEY): TIdC_INT; cdecl;
  {$EXTERNALSYM EC_KEY_METHOD_verify_verify_sig}
  EC_KEY_METHOD_verify_verify_sig = function(const dgst: PByte; dgst_len: TIdC_INT; const sig: PECDSA_SIG; eckey: PEC_KEY): TIdC_INT; cdecl;

  {$EXTERNALSYM PEC_KEY_METHOD_init_init}
  PEC_KEY_METHOD_init_init = ^EC_KEY_METHOD_init_init;
  {$EXTERNALSYM PEC_KEY_METHOD_init_finish}
  PEC_KEY_METHOD_init_finish = ^EC_KEY_METHOD_init_finish;
  {$EXTERNALSYM PEC_KEY_METHOD_init_copy}
  PEC_KEY_METHOD_init_copy = ^EC_KEY_METHOD_init_copy;
  {$EXTERNALSYM PEC_KEY_METHOD_init_set_group}
  PEC_KEY_METHOD_init_set_group = ^EC_KEY_METHOD_init_set_group;
  {$EXTERNALSYM PEC_KEY_METHOD_init_set_private}
  PEC_KEY_METHOD_init_set_private = ^EC_KEY_METHOD_init_set_private;
  {$EXTERNALSYM PEC_KEY_METHOD_init_set_public}
  PEC_KEY_METHOD_init_set_public = ^EC_KEY_METHOD_init_set_public;

  {$EXTERNALSYM PEC_KEY_METHOD_keygen_keygen}
  PEC_KEY_METHOD_keygen_keygen = ^EC_KEY_METHOD_keygen_keygen;

  {$EXTERNALSYM PEC_KEY_METHOD_compute_key_ckey}
  PEC_KEY_METHOD_compute_key_ckey = ^EC_KEY_METHOD_compute_key_ckey;

  {$EXTERNALSYM PEC_KEY_METHOD_sign_sign}
  PEC_KEY_METHOD_sign_sign = ^EC_KEY_METHOD_sign_sign;
  {$EXTERNALSYM PEC_KEY_METHOD_sign_sign_setup}
  PEC_KEY_METHOD_sign_sign_setup = ^EC_KEY_METHOD_sign_sign_setup;
  {$EXTERNALSYM PEC_KEY_METHOD_sign_sign_sig}
  PEC_KEY_METHOD_sign_sign_sig = ^EC_KEY_METHOD_sign_sign_sig;

  {$EXTERNALSYM PEC_KEY_METHOD_verify_verify}
  PEC_KEY_METHOD_verify_verify = ^EC_KEY_METHOD_verify_verify;
  {$EXTERNALSYM PEC_KEY_METHOD_verify_verify_sig}
  PEC_KEY_METHOD_verify_verify_sig = ^EC_KEY_METHOD_verify_verify_sig;

    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM EC_GFp_simple_method}
  EC_GFp_simple_method: function : PEC_METHOD; cdecl = nil;
  {$EXTERNALSYM EC_GFp_mont_method}
  EC_GFp_mont_method: function : PEC_METHOD; cdecl = nil;
  {$EXTERNALSYM EC_GFp_nist_method}
  EC_GFp_nist_method: function : PEC_METHOD; cdecl = nil;
  {$IFDEF OPENSSL_NO_EC_NISTP_64_GCC_128}
  {$EXTERNALSYM EC_GFp_nistp224_method}
  EC_GFp_nistp224_method: function : PEC_METHOD; cdecl = nil; {introduced 1.1.0 removed 3.0.0}
  {$EXTERNALSYM EC_GFp_nistp256_method}
  EC_GFp_nistp256_method: function : PEC_METHOD; cdecl = nil; {introduced 1.1.0 removed 3.0.0}
  {$EXTERNALSYM EC_GFp_nistp521_method}
  EC_GFp_nistp521_method: function : PEC_METHOD; cdecl = nil; {introduced 1.1.0 removed 3.0.0}
  {$ENDIF}

  {$EXTERNALSYM EC_GF2m_simple_method}
  EC_GF2m_simple_method: function : PEC_METHOD; cdecl = nil;

  {$EXTERNALSYM EC_GROUP_new}
  EC_GROUP_new: function (const meth: PEC_METHOD): PEC_GROUP; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_free}
  EC_GROUP_free: procedure (group: PEC_GROUP); cdecl = nil;
  {$EXTERNALSYM EC_GROUP_clear_free}
  EC_GROUP_clear_free: procedure (group: PEC_GROUP); cdecl = nil;
  {$EXTERNALSYM EC_GROUP_copy}
  EC_GROUP_copy: function (dst: PEC_GROUP; const src: PEC_GROUP): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_dup}
  EC_GROUP_dup: function (const src: PEC_GROUP): PEC_GROUP; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_method_of}
  EC_GROUP_method_of: function (const group: PEC_GROUP): PEC_GROUP; cdecl = nil;
  {$EXTERNALSYM EC_METHOD_get_field_type}
  EC_METHOD_get_field_type: function (const meth: PEC_METHOD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_set_generator}
  EC_GROUP_set_generator: function (group: PEC_GROUP; const generator: PEC_POINT; const order: PBIGNUM; const cofactor: PBIGNUM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get0_generator}
  EC_GROUP_get0_generator: function (const group: PEC_GROUP): PEC_POINT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get_mont_data}
  EC_GROUP_get_mont_data: function (const group: PEC_GROUP): PBN_MONT_CTX; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get_order}
  EC_GROUP_get_order: function (const group: PEC_GROUP; order: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get0_order}
  EC_GROUP_get0_order: function (const group: PEC_GROUP): PBIGNUM; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_GROUP_order_bits}
  EC_GROUP_order_bits: function (const group: PEC_GROUP): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_GROUP_get_cofactor}
  EC_GROUP_get_cofactor: function (const group: PEC_GROUP; cofactor: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get0_cofactor}
  EC_GROUP_get0_cofactor: function (const group: PEC_GROUP): PBIGNUM; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_GROUP_set_curve_name}
  EC_GROUP_set_curve_name: procedure (group: PEC_GROUP; nid: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get_curve_name}
  EC_GROUP_get_curve_name: function (const group: PEC_GROUP): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EC_GROUP_set_asn1_flag}
  EC_GROUP_set_asn1_flag: procedure (group: PEC_GROUP; flag: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get_asn1_flag}
  EC_GROUP_get_asn1_flag: function (const group: PEC_GROUP): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EC_GROUP_set_point_conversion_form}
  EC_GROUP_set_point_conversion_form: procedure (group: PEC_GROUP; form: point_conversion_form_t); cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get_point_conversion_form}
  EC_GROUP_get_point_conversion_form: function (const group: PEC_GROUP): point_conversion_form_t; cdecl = nil;

  {$EXTERNALSYM EC_GROUP_get0_seed}
  EC_GROUP_get0_seed: function (const x: PEC_GROUP): PByte; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get_seed_len}
  EC_GROUP_get_seed_len: function (const x: PEC_GROUP): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_set_seed}
  EC_GROUP_set_seed: function (x: PEC_GROUP; const p: PByte; len: TIdC_SIZET): TIdC_SIZET; cdecl = nil;

  {$EXTERNALSYM EC_GROUP_set_curve}
  EC_GROUP_set_curve: function (group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_GROUP_get_curve}
  EC_GROUP_get_curve: function (const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_GROUP_set_curve_GFp}
  EC_GROUP_set_curve_GFp: function (group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get_curve_GFp}
  EC_GROUP_get_curve_GFp: function (const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_set_curve_GF2m}
  EC_GROUP_set_curve_GF2m: function (group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b:PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get_curve_GF2m}
  EC_GROUP_get_curve_GF2m: function (const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EC_GROUP_get_degree}
  EC_GROUP_get_degree: function (const group: PEC_GROUP): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_check}
  EC_GROUP_check: function (const group: PEC_GROUP; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_check_discriminant}
  EC_GROUP_check_discriminant: function (const group: PEC_GROUP; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_cmp}
  EC_GROUP_cmp: function (const a: PEC_GROUP; const b: PEC_GROUP; ctx: PBN_CTX): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EC_GROUP_new_curve_GFp}
  EC_GROUP_new_curve_GFp: function (const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_new_curve_GF2m}
  EC_GROUP_new_curve_GF2m: function (const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_new_by_curve_name}
  EC_GROUP_new_by_curve_name: function (nid: TIdC_INT): PEC_GROUP; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_new_from_ecparameters}
  EC_GROUP_new_from_ecparameters: function (const params: PECPARAMETERS): PEC_GROUP; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_GROUP_get_ecparameters}
  EC_GROUP_get_ecparameters: function (const group: PEC_GROUP; params: PECPARAMETERS): PECPARAMETERS; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_GROUP_new_from_ecpkparameters}
  EC_GROUP_new_from_ecpkparameters: function (const params: PECPKPARAMETERS): PEC_GROUP; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_GROUP_get_ecpkparameters}
  EC_GROUP_get_ecpkparameters: function (const group: PEC_GROUP; params: PECPKPARAMETERS): PECPKPARAMETERS; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EC_get_builtin_curves}
  EC_get_builtin_curves: function (r: PEC_builtin_curve; nitems: TIdC_SIZET): TIdC_SIZET; cdecl = nil;

  {$EXTERNALSYM EC_curve_nid2nist}
  EC_curve_nid2nist: function (nid: TIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM EC_curve_nist2nid}
  EC_curve_nist2nid: function (const name: PIdAnsiChar): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EC_POINT_new}
  EC_POINT_new: function (const group: PEC_GROUP): PEC_POINT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_free}
  EC_POINT_free: procedure (point: PEC_POINT); cdecl = nil;
  {$EXTERNALSYM EC_POINT_clear_free}
  EC_POINT_clear_free: procedure (point: PEC_POINT); cdecl = nil;
  {$EXTERNALSYM EC_POINT_copy}
  EC_POINT_copy: function (dst: PEC_POINT; const src: PEC_POINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_dup}
  EC_POINT_dup: function (const src: PEC_POINT; const group: PEC_GROUP): PEC_POINT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_method_of}
  EC_POINT_method_of: function (const point: PEC_POINT): PEC_METHOD; cdecl = nil;
  {$EXTERNALSYM EC_POINT_set_to_infinity}
  EC_POINT_set_to_infinity: function (const group: PEC_GROUP; point: PEC_POINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_set_Jprojective_coordinates_GFp}
  EC_POINT_set_Jprojective_coordinates_GFp: function (const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; const z: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_get_Jprojective_coordinates_GFp}
  EC_POINT_get_Jprojective_coordinates_GFp: function (const group: PEC_METHOD; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_set_affine_coordinates}
  EC_POINT_set_affine_coordinates: function (const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_POINT_get_affine_coordinates}
  EC_POINT_get_affine_coordinates: function (const group: PEC_GROUP; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_POINT_set_affine_coordinates_GFp}
  EC_POINT_set_affine_coordinates_GFp: function (const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_get_affine_coordinates_GFp}
  EC_POINT_get_affine_coordinates_GFp: function (const group: PEC_GROUP; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_set_compressed_coordinates}
  EC_POINT_set_compressed_coordinates: function (const group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TIdC_INT; ctx: PBN_CTX): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_POINT_set_compressed_coordinates_GFp}
  EC_POINT_set_compressed_coordinates_GFp: function (const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; y_bit: TIdC_INT; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_set_affine_coordinates_GF2m}
  EC_POINT_set_affine_coordinates_GF2m: function (const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_get_affine_coordinates_GF2m}
  EC_POINT_get_affine_coordinates_GF2m: function (const group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_set_compressed_coordinates_GF2m}
  EC_POINT_set_compressed_coordinates_GF2m: function (const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; y_bit: TIdC_INT; ctx: PBN_CTX): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EC_POINT_point2oct}
  EC_POINT_point2oct: function (const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; buf: PByte; len: TIdC_SIZET; ctx: PBN_CTX): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM EC_POINT_oct2point}
  EC_POINT_oct2point: function (const group: PEC_GROUP; p: PEC_POINT; const buf: PByte; len: TIdC_SIZET; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_point2buf}
  EC_POINT_point2buf: function (const group: PEC_GROUP; const point: PEC_POINT; form: point_conversion_form_t; pbuf: PPByte; ctx: PBN_CTX): TIdC_SIZET; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_POINT_point2bn}
  EC_POINT_point2bn: function (const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; bn: PBIGNUM; ctx: PBN_CTX): PBIGNUM; cdecl = nil;
  {$EXTERNALSYM EC_POINT_bn2point}
  EC_POINT_bn2point: function (const group: PEC_GROUP; const bn: PBIGNUM; p: PEC_POINT; ctx: PBN_CTX): PEC_POINT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_point2hex}
  EC_POINT_point2hex: function (const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; ctx: PBN_CTX): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM EC_POINT_hex2point}
  EC_POINT_hex2point: function (const group: PEC_GROUP; const buf: PIdAnsiChar; p: PEC_POINT; ctx: PBN_CTX): PEC_POINT; cdecl = nil;

  {$EXTERNALSYM EC_POINT_add}
  EC_POINT_add: function (const group: PEC_GROUP; r: PEC_POINT; const a: PEC_POINT; const b: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_dbl}
  EC_POINT_dbl: function (const group: PEC_GROUP; r: PEC_POINT; const a: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_invert}
  EC_POINT_invert: function (const group: PEC_GROUP; a: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_is_at_infinity}
  EC_POINT_is_at_infinity: function (const group: PEC_GROUP; const p: PEC_POINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_is_on_curve}
  EC_POINT_is_on_curve: function (const group: PEC_GROUP; const point: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_cmp}
  EC_POINT_cmp: function (const group: PEC_GROUP; const a: PEC_POINT; const b: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_make_affine}
  EC_POINT_make_affine: function (const group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINTs_make_affine}
  EC_POINTs_make_affine: function (const group: PEC_METHOD; num: TIdC_SIZET; points: PPEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINTs_mul}
  EC_POINTs_mul: function (const group: PEC_GROUP; r: PEC_POINT; const n: PBIGNUM; num: TIdC_SIZET; const p: PPEC_POINT; const m: PPBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_mul}
  EC_POINT_mul: function (const group: PEC_GROUP; r: PEC_POINT; const n: PBIGNUM; const q: PEC_POINT; const m: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EC_GROUP_precompute_mult}
  EC_GROUP_precompute_mult: function (group: PEC_GROUP; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_have_precompute_mult}
  EC_GROUP_have_precompute_mult: function (const group: PEC_GROUP): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM ECPKPARAMETERS_it}
  ECPKPARAMETERS_it: function : PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ECPKPARAMETERS_new}
  ECPKPARAMETERS_new: function : PECPKPARAMETERS; cdecl = nil;
  {$EXTERNALSYM ECPKPARAMETERS_free}
  ECPKPARAMETERS_free: procedure (a: PECPKPARAMETERS); cdecl = nil;

  {$EXTERNALSYM ECPARAMETERS_it}
  ECPARAMETERS_it: function : PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ECPARAMETERS_new}
  ECPARAMETERS_new: function : PECPARAMETERS; cdecl = nil;
  {$EXTERNALSYM ECPARAMETERS_free}
  ECPARAMETERS_free: procedure (a: PECPARAMETERS); cdecl = nil;

  {$EXTERNALSYM EC_GROUP_get_basis_type}
  EC_GROUP_get_basis_type: function (const group: PEC_GROUP): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get_trinomial_basis}
  EC_GROUP_get_trinomial_basis: function (const group: PEC_GROUP; k: PIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get_pentanomial_basis}
  EC_GROUP_get_pentanomial_basis: function (const group: PEC_GROUP; k1: PIdC_UINT; k2: PIdC_UINT; k3: PIdC_UINT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM d2i_ECPKParameters}
  d2i_ECPKParameters: function (group: PPEC_GROUP; const in_: PPByte; len: TIdC_LONG): PEC_GROUP; cdecl = nil;
  {$EXTERNALSYM i2d_ECPKParameters}
  i2d_ECPKParameters: function (const group: PEC_GROUP; out_: PPByte): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM ECPKParameters_print}
  ECPKParameters_print: function (bp: PBIO; const x: PEC_GROUP; off: TIdC_INT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EC_KEY_new}
  EC_KEY_new: function : PEC_KEY; cdecl = nil;
  {$EXTERNALSYM EC_KEY_get_flags}
  EC_KEY_get_flags: function (const key: PEC_KEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_KEY_set_flags}
  EC_KEY_set_flags: procedure (key: PEC_KEY; flags: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM EC_KEY_clear_flags}
  EC_KEY_clear_flags: procedure (key: PEC_KEY; flags: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM EC_KEY_new_by_curve_name}
  EC_KEY_new_by_curve_name: function (nid: TIdC_INT): PEC_KEY; cdecl = nil;
  {$EXTERNALSYM EC_KEY_free}
  EC_KEY_free: procedure (key: PEC_KEY); cdecl = nil;
  {$EXTERNALSYM EC_KEY_copy}
  EC_KEY_copy: function (dst: PEC_KEY; const src: PEC_KEY): PEC_KEY; cdecl = nil;
  {$EXTERNALSYM EC_KEY_dup}
  EC_KEY_dup: function (const src: PEC_KEY): PEC_KEY; cdecl = nil;
  {$EXTERNALSYM EC_KEY_up_ref}
  EC_KEY_up_ref: function (key: PEC_KEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_KEY_get0_engine}
  EC_KEY_get0_engine: function (const eckey: PEC_KEY): PENGINE; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_get0_group}
  EC_KEY_get0_group: function (const key: PEC_KEY): PEC_GROUP; cdecl = nil;
  {$EXTERNALSYM EC_KEY_set_group}
  EC_KEY_set_group: function (key: PEC_KEY; const group: PEC_GROUP): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_KEY_get0_private_key}
  EC_KEY_get0_private_key: function (const key: PEC_KEY): PBIGNUM; cdecl = nil;
  {$EXTERNALSYM EC_KEY_set_private_key}
  EC_KEY_set_private_key: function (const key: PEC_KEY; const prv: PBIGNUM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_KEY_get0_public_key}
  EC_KEY_get0_public_key: function (const key: PEC_KEY): PEC_POINT; cdecl = nil;
  {$EXTERNALSYM EC_KEY_set_public_key}
  EC_KEY_set_public_key: function (key: PEC_KEY; const pub: PEC_POINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_KEY_get_enc_flags}
  EC_KEY_get_enc_flags: function (const key: PEC_KEY): TIdC_UINT; cdecl = nil;
  {$EXTERNALSYM EC_KEY_set_enc_flags}
  EC_KEY_set_enc_flags: procedure (eckey: PEC_KEY; flags: TIdC_UINT); cdecl = nil;
  {$EXTERNALSYM EC_KEY_get_conv_form}
  EC_KEY_get_conv_form: function (const key: PEC_KEY): point_conversion_form_t; cdecl = nil;
  {$EXTERNALSYM EC_KEY_set_conv_form}
  EC_KEY_set_conv_form: procedure (eckey: PEC_KEY; cform: point_conversion_form_t); cdecl = nil;
  {$EXTERNALSYM EC_KEY_set_ex_data}
  EC_KEY_set_ex_data: function (key: PEC_KEY; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_get_ex_data}
  EC_KEY_get_ex_data: function (const key: PEC_KEY; idx: TIdC_INT): Pointer; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_set_asn1_flag}
  EC_KEY_set_asn1_flag: procedure (eckey: PEC_KEY; asn1_flag: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM EC_KEY_precompute_mult}
  EC_KEY_precompute_mult: function (key: PEC_KEY; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_KEY_generate_key}
  EC_KEY_generate_key: function (key: PEC_KEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_KEY_check_key}
  EC_KEY_check_key: function (const key: PEC_KEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_KEY_can_sign}
  EC_KEY_can_sign: function (const eckey: PEC_KEY): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_set_public_key_affine_coordinates}
  EC_KEY_set_public_key_affine_coordinates: function (key: PEC_KEY; x: PBIGNUM; y: PBIGNUM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_KEY_key2buf}
  EC_KEY_key2buf: function (const key: PEC_KEY; form: point_conversion_form_t; pbuf: PPByte; ctx: PBN_CTX): TIdC_SIZET; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_oct2key}
  EC_KEY_oct2key: function (key: PEC_KEY; const buf: PByte; len: TIdC_SIZET; ctx: PBN_CTX): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_oct2priv}
  EC_KEY_oct2priv: function (key: PEC_KEY; const buf: PByte; len: TIdC_SIZET): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_priv2oct}
  EC_KEY_priv2oct: function (const key: PEC_KEY; buf: PByte; len: TIdC_SIZET): TIdC_SIZET; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_priv2buf}
  EC_KEY_priv2buf: function (const eckey: PEC_KEY; buf: PPByte): TIdC_SIZET; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM d2i_ECPrivateKey}
  d2i_ECPrivateKey: function (key: PPEC_KEY; const in_: PPByte; len: TIdC_LONG): PEC_KEY; cdecl = nil;
  {$EXTERNALSYM i2d_ECPrivateKey}
  i2d_ECPrivateKey: function (key: PEC_KEY; out_: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM o2i_ECPublicKey}
  o2i_ECPublicKey: function (key: PPEC_KEY; const in_: PPByte; len: TIdC_LONG): PEC_KEY; cdecl = nil;
  {$EXTERNALSYM i2o_ECPublicKey}
  i2o_ECPublicKey: function (const key: PEC_KEY; out_: PPByte): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM ECParameters_print}
  ECParameters_print: function (bp: PBIO; const key: PEC_KEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_KEY_print}
  EC_KEY_print: function (bp: PBIO; const key: PEC_KEY; off: TIdC_INT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EC_KEY_OpenSSL}
  EC_KEY_OpenSSL: function : PEC_KEY_METHOD; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_get_default_method}
  EC_KEY_get_default_method: function : PEC_KEY_METHOD; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_set_default_method}
  EC_KEY_set_default_method: procedure (const meth: PEC_KEY_METHOD); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_get_method}
  EC_KEY_get_method: function (const key: PEC_KEY): PEC_KEY_METHOD; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_set_method}
  EC_KEY_set_method: function (key: PEC_KEY; const meth: PEC_KEY_METHOD): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_new_method}
  EC_KEY_new_method: function (engine: PENGINE): PEC_KEY; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM ECDH_KDF_X9_62}
  ECDH_KDF_X9_62: function (out_: PByte; outlen: TIdC_SIZET; const Z: PByte; Zlen: TIdC_SIZET; const sinfo: PByte; sinfolen: TIdC_SIZET; const md: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ECDH_compute_key}
  ECDH_compute_key: function (out_: Pointer; oulen: TIdC_SIZET; const pub_key: PEC_POINT; const ecdh: PEC_KEY; kdf: ECDH_compute_key_KDF): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM ECDSA_SIG_new}
  ECDSA_SIG_new: function : PECDSA_SIG; cdecl = nil;
  {$EXTERNALSYM ECDSA_SIG_free}
  ECDSA_SIG_free: procedure (sig: PECDSA_SIG); cdecl = nil;
  {$EXTERNALSYM i2d_ECDSA_SIG}
  i2d_ECDSA_SIG: function (const sig: PECDSA_SIG; pp: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_ECDSA_SIG}
  d2i_ECDSA_SIG: function (sig: PPECDSA_SIG; const pp: PPByte; len: TIdC_LONG): PECDSA_SIG; cdecl = nil;
  {$EXTERNALSYM ECDSA_SIG_get0}
  ECDSA_SIG_get0: procedure (const sig: PECDSA_SIG; const pr: PPBIGNUM; const ps: PPBIGNUM); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ECDSA_SIG_get0_r}
  ECDSA_SIG_get0_r: function (const sig: PECDSA_SIG): PBIGNUM; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ECDSA_SIG_get0_s}
  ECDSA_SIG_get0_s: function (const sig: PECDSA_SIG): PBIGNUM; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ECDSA_SIG_set0}
  ECDSA_SIG_set0: function (sig: PECDSA_SIG; r: PBIGNUM; s: PBIGNUM): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM ECDSA_do_sign}
  ECDSA_do_sign: function (const dgst: PByte; dgst_len: TIdC_INT; eckey: PEC_KEY): PECDSA_SIG; cdecl = nil;
  {$EXTERNALSYM ECDSA_do_sign_ex}
  ECDSA_do_sign_ex: function (const dgst: PByte; dgst_len: TIdC_INT; const kinv: PBIGNUM; const rp: PBIGNUM; eckey: PEC_KEY): PECDSA_SIG; cdecl = nil;
  {$EXTERNALSYM ECDSA_do_verify}
  ECDSA_do_verify: function (const dgst: PByte; dgst_len: TIdC_INT; const sig: PECDSA_SIG; eckey: PEC_KEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ECDSA_sign_setup}
  ECDSA_sign_setup: function (eckey: PEC_KEY; ctx: PBN_CTX; kiv: PPBIGNUM; rp: PPBIGNUM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ECDSA_sign}
  ECDSA_sign: function (type_: TIdC_INT; const dgst: PByte; dgstlen: TIdC_INT; sig: PByte; siglen: PIdC_UINT; eckey: PEC_KEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ECDSA_sign_ex}
  ECDSA_sign_ex: function (type_: TIdC_INT; const dgst: PByte; dgstlen: TIdC_INT; sig: PByte; siglen: PIdC_UINT; const kinv: PBIGNUM; const rp: PBIGNUM; eckey: PEC_KEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ECDSA_verify}
  ECDSA_verify: function (type_: TIdC_INT; const dgst: PByte; dgstlen: TIdC_INT; const sig: PByte; siglen: TIdC_INT; eckey: PEC_KEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ECDSA_size}
  ECDSA_size: function (const eckey: PEC_KEY): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM EC_KEY_METHOD_new}
  EC_KEY_METHOD_new: function (const meth: PEC_KEY_METHOD): PEC_KEY_METHOD; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_METHOD_free}
  EC_KEY_METHOD_free: procedure (meth: PEC_KEY_METHOD); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_METHOD_set_init}
  EC_KEY_METHOD_set_init: procedure (meth: PEC_KEY_METHOD; init: EC_KEY_METHOD_init_init; finish: EC_KEY_METHOD_init_finish; _copy: EC_KEY_METHOD_init_copy; set_group: EC_KEY_METHOD_init_set_group; set_private: EC_KEY_METHOD_init_set_private; set_public: EC_KEY_METHOD_init_set_public); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_METHOD_set_keygen}
  EC_KEY_METHOD_set_keygen: procedure (meth: PEC_KEY_METHOD; keygen: EC_KEY_METHOD_keygen_keygen); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_METHOD_set_compute_key}
  EC_KEY_METHOD_set_compute_key: procedure (meth: PEC_KEY_METHOD; ckey: EC_KEY_METHOD_compute_key_ckey); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_METHOD_set_sign}
  EC_KEY_METHOD_set_sign: procedure (meth: PEC_KEY_METHOD; sign: EC_KEY_METHOD_sign_sign; sign_setup: EC_KEY_METHOD_sign_sign_setup; sign_sig: EC_KEY_METHOD_sign_sign_sig); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_METHOD_set_verify}
  EC_KEY_METHOD_set_verify: procedure (meth: PEC_KEY_METHOD; verify: EC_KEY_METHOD_verify_verify; verify_sig: EC_KEY_METHOD_verify_verify_sig); cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM EC_KEY_METHOD_get_init}
  EC_KEY_METHOD_get_init: procedure (const meth: PEC_KEY_METHOD; pinit: PEC_KEY_METHOD_init_init; pfinish: PEC_KEY_METHOD_init_finish; p_copy: PEC_KEY_METHOD_init_copy; pset_group: PEC_KEY_METHOD_init_set_group; pset_private: PEC_KEY_METHOD_init_set_private; pset_public: PEC_KEY_METHOD_init_set_public); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_METHOD_get_keygen}
  EC_KEY_METHOD_get_keygen: procedure (const meth: PEC_KEY_METHOD; pkeygen: PEC_KEY_METHOD_keygen_keygen); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_METHOD_get_compute_key}
  EC_KEY_METHOD_get_compute_key: procedure (const meth: PEC_KEY_METHOD; pck: PEC_KEY_METHOD_compute_key_ckey); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_METHOD_get_sign}
  EC_KEY_METHOD_get_sign: procedure (const meth: PEC_KEY_METHOD; psign: PEC_KEY_METHOD_sign_sign; psign_setup: PEC_KEY_METHOD_sign_sign_setup; psign_sig: PEC_KEY_METHOD_sign_sign_sig); cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_METHOD_get_verify}
  EC_KEY_METHOD_get_verify: procedure (const meth: PEC_KEY_METHOD; pverify: PEC_KEY_METHOD_verify_verify; pverify_sig: PEC_KEY_METHOD_verify_verify_sig); cdecl = nil; {introduced 1.1.0}

{$ELSE}
  {$EXTERNALSYM EC_GFp_simple_method}
  function EC_GFp_simple_method: PEC_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GFp_mont_method}
  function EC_GFp_mont_method: PEC_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GFp_nist_method}
  function EC_GFp_nist_method: PEC_METHOD cdecl; external CLibCrypto;

  {$EXTERNALSYM EC_GF2m_simple_method}
  function EC_GF2m_simple_method: PEC_METHOD cdecl; external CLibCrypto;

  {$EXTERNALSYM EC_GROUP_new}
  function EC_GROUP_new(const meth: PEC_METHOD): PEC_GROUP cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_free}
  procedure EC_GROUP_free(group: PEC_GROUP) cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_clear_free}
  procedure EC_GROUP_clear_free(group: PEC_GROUP) cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_copy}
  function EC_GROUP_copy(dst: PEC_GROUP; const src: PEC_GROUP): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_dup}
  function EC_GROUP_dup(const src: PEC_GROUP): PEC_GROUP cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_method_of}
  function EC_GROUP_method_of(const group: PEC_GROUP): PEC_GROUP cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_METHOD_get_field_type}
  function EC_METHOD_get_field_type(const meth: PEC_METHOD): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_set_generator}
  function EC_GROUP_set_generator(group: PEC_GROUP; const generator: PEC_POINT; const order: PBIGNUM; const cofactor: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_get0_generator}
  function EC_GROUP_get0_generator(const group: PEC_GROUP): PEC_POINT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_get_mont_data}
  function EC_GROUP_get_mont_data(const group: PEC_GROUP): PBN_MONT_CTX cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_get_order}
  function EC_GROUP_get_order(const group: PEC_GROUP; order: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_get0_order}
  function EC_GROUP_get0_order(const group: PEC_GROUP): PBIGNUM cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_GROUP_order_bits}
  function EC_GROUP_order_bits(const group: PEC_GROUP): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_GROUP_get_cofactor}
  function EC_GROUP_get_cofactor(const group: PEC_GROUP; cofactor: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_get0_cofactor}
  function EC_GROUP_get0_cofactor(const group: PEC_GROUP): PBIGNUM cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_GROUP_set_curve_name}
  procedure EC_GROUP_set_curve_name(group: PEC_GROUP; nid: TIdC_INT) cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_get_curve_name}
  function EC_GROUP_get_curve_name(const group: PEC_GROUP): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EC_GROUP_set_asn1_flag}
  procedure EC_GROUP_set_asn1_flag(group: PEC_GROUP; flag: TIdC_INT) cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_get_asn1_flag}
  function EC_GROUP_get_asn1_flag(const group: PEC_GROUP): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EC_GROUP_set_point_conversion_form}
  procedure EC_GROUP_set_point_conversion_form(group: PEC_GROUP; form: point_conversion_form_t) cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_get_point_conversion_form}
  function EC_GROUP_get_point_conversion_form(const group: PEC_GROUP): point_conversion_form_t cdecl; external CLibCrypto;

  {$EXTERNALSYM EC_GROUP_get0_seed}
  function EC_GROUP_get0_seed(const x: PEC_GROUP): PByte cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_get_seed_len}
  function EC_GROUP_get_seed_len(const x: PEC_GROUP): TIdC_SIZET cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_set_seed}
  function EC_GROUP_set_seed(x: PEC_GROUP; const p: PByte; len: TIdC_SIZET): TIdC_SIZET cdecl; external CLibCrypto;

  {$EXTERNALSYM EC_GROUP_set_curve}
  function EC_GROUP_set_curve(group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_GROUP_get_curve}
  function EC_GROUP_get_curve(const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_GROUP_set_curve_GFp}
  function EC_GROUP_set_curve_GFp(group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_get_curve_GFp}
  function EC_GROUP_get_curve_GFp(const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_set_curve_GF2m}
  function EC_GROUP_set_curve_GF2m(group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b:PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_get_curve_GF2m}
  function EC_GROUP_get_curve_GF2m(const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EC_GROUP_get_degree}
  function EC_GROUP_get_degree(const group: PEC_GROUP): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_check}
  function EC_GROUP_check(const group: PEC_GROUP; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_check_discriminant}
  function EC_GROUP_check_discriminant(const group: PEC_GROUP; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_cmp}
  function EC_GROUP_cmp(const a: PEC_GROUP; const b: PEC_GROUP; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EC_GROUP_new_curve_GFp}
  function EC_GROUP_new_curve_GFp(const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_new_curve_GF2m}
  function EC_GROUP_new_curve_GF2m(const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_new_by_curve_name}
  function EC_GROUP_new_by_curve_name(nid: TIdC_INT): PEC_GROUP cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_new_from_ecparameters}
  function EC_GROUP_new_from_ecparameters(const params: PECPARAMETERS): PEC_GROUP cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_GROUP_get_ecparameters}
  function EC_GROUP_get_ecparameters(const group: PEC_GROUP; params: PECPARAMETERS): PECPARAMETERS cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_GROUP_new_from_ecpkparameters}
  function EC_GROUP_new_from_ecpkparameters(const params: PECPKPARAMETERS): PEC_GROUP cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_GROUP_get_ecpkparameters}
  function EC_GROUP_get_ecpkparameters(const group: PEC_GROUP; params: PECPKPARAMETERS): PECPKPARAMETERS cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EC_get_builtin_curves}
  function EC_get_builtin_curves(r: PEC_builtin_curve; nitems: TIdC_SIZET): TIdC_SIZET cdecl; external CLibCrypto;

  {$EXTERNALSYM EC_curve_nid2nist}
  function EC_curve_nid2nist(nid: TIdC_INT): PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_curve_nist2nid}
  function EC_curve_nist2nid(const name: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EC_POINT_new}
  function EC_POINT_new(const group: PEC_GROUP): PEC_POINT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_free}
  procedure EC_POINT_free(point: PEC_POINT) cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_clear_free}
  procedure EC_POINT_clear_free(point: PEC_POINT) cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_copy}
  function EC_POINT_copy(dst: PEC_POINT; const src: PEC_POINT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_dup}
  function EC_POINT_dup(const src: PEC_POINT; const group: PEC_GROUP): PEC_POINT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_method_of}
  function EC_POINT_method_of(const point: PEC_POINT): PEC_METHOD cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_set_to_infinity}
  function EC_POINT_set_to_infinity(const group: PEC_GROUP; point: PEC_POINT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_set_Jprojective_coordinates_GFp}
  function EC_POINT_set_Jprojective_coordinates_GFp(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; const z: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_get_Jprojective_coordinates_GFp}
  function EC_POINT_get_Jprojective_coordinates_GFp(const group: PEC_METHOD; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_set_affine_coordinates}
  function EC_POINT_set_affine_coordinates(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_POINT_get_affine_coordinates}
  function EC_POINT_get_affine_coordinates(const group: PEC_GROUP; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_POINT_set_affine_coordinates_GFp}
  function EC_POINT_set_affine_coordinates_GFp(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_get_affine_coordinates_GFp}
  function EC_POINT_get_affine_coordinates_GFp(const group: PEC_GROUP; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_set_compressed_coordinates}
  function EC_POINT_set_compressed_coordinates(const group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TIdC_INT; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_POINT_set_compressed_coordinates_GFp}
  function EC_POINT_set_compressed_coordinates_GFp(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; y_bit: TIdC_INT; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_set_affine_coordinates_GF2m}
  function EC_POINT_set_affine_coordinates_GF2m(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_get_affine_coordinates_GF2m}
  function EC_POINT_get_affine_coordinates_GF2m(const group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_set_compressed_coordinates_GF2m}
  function EC_POINT_set_compressed_coordinates_GF2m(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; y_bit: TIdC_INT; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EC_POINT_point2oct}
  function EC_POINT_point2oct(const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; buf: PByte; len: TIdC_SIZET; ctx: PBN_CTX): TIdC_SIZET cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_oct2point}
  function EC_POINT_oct2point(const group: PEC_GROUP; p: PEC_POINT; const buf: PByte; len: TIdC_SIZET; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_point2buf}
  function EC_POINT_point2buf(const group: PEC_GROUP; const point: PEC_POINT; form: point_conversion_form_t; pbuf: PPByte; ctx: PBN_CTX): TIdC_SIZET cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_POINT_point2bn}
  function EC_POINT_point2bn(const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; bn: PBIGNUM; ctx: PBN_CTX): PBIGNUM cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_bn2point}
  function EC_POINT_bn2point(const group: PEC_GROUP; const bn: PBIGNUM; p: PEC_POINT; ctx: PBN_CTX): PEC_POINT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_point2hex}
  function EC_POINT_point2hex(const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; ctx: PBN_CTX): PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_hex2point}
  function EC_POINT_hex2point(const group: PEC_GROUP; const buf: PIdAnsiChar; p: PEC_POINT; ctx: PBN_CTX): PEC_POINT cdecl; external CLibCrypto;

  {$EXTERNALSYM EC_POINT_add}
  function EC_POINT_add(const group: PEC_GROUP; r: PEC_POINT; const a: PEC_POINT; const b: PEC_POINT; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_dbl}
  function EC_POINT_dbl(const group: PEC_GROUP; r: PEC_POINT; const a: PEC_POINT; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_invert}
  function EC_POINT_invert(const group: PEC_GROUP; a: PEC_POINT; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_is_at_infinity}
  function EC_POINT_is_at_infinity(const group: PEC_GROUP; const p: PEC_POINT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_is_on_curve}
  function EC_POINT_is_on_curve(const group: PEC_GROUP; const point: PEC_POINT; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_cmp}
  function EC_POINT_cmp(const group: PEC_GROUP; const a: PEC_POINT; const b: PEC_POINT; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_make_affine}
  function EC_POINT_make_affine(const group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINTs_make_affine}
  function EC_POINTs_make_affine(const group: PEC_METHOD; num: TIdC_SIZET; points: PPEC_POINT; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINTs_mul}
  function EC_POINTs_mul(const group: PEC_GROUP; r: PEC_POINT; const n: PBIGNUM; num: TIdC_SIZET; const p: PPEC_POINT; const m: PPBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_POINT_mul}
  function EC_POINT_mul(const group: PEC_GROUP; r: PEC_POINT; const n: PBIGNUM; const q: PEC_POINT; const m: PBIGNUM; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EC_GROUP_precompute_mult}
  function EC_GROUP_precompute_mult(group: PEC_GROUP; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_have_precompute_mult}
  function EC_GROUP_have_precompute_mult(const group: PEC_GROUP): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM ECPKPARAMETERS_it}
  function ECPKPARAMETERS_it: PASN1_ITEM cdecl; external CLibCrypto;
  {$EXTERNALSYM ECPKPARAMETERS_new}
  function ECPKPARAMETERS_new: PECPKPARAMETERS cdecl; external CLibCrypto;
  {$EXTERNALSYM ECPKPARAMETERS_free}
  procedure ECPKPARAMETERS_free(a: PECPKPARAMETERS) cdecl; external CLibCrypto;

  {$EXTERNALSYM ECPARAMETERS_it}
  function ECPARAMETERS_it: PASN1_ITEM cdecl; external CLibCrypto;
  {$EXTERNALSYM ECPARAMETERS_new}
  function ECPARAMETERS_new: PECPARAMETERS cdecl; external CLibCrypto;
  {$EXTERNALSYM ECPARAMETERS_free}
  procedure ECPARAMETERS_free(a: PECPARAMETERS) cdecl; external CLibCrypto;

  {$EXTERNALSYM EC_GROUP_get_basis_type}
  function EC_GROUP_get_basis_type(const group: PEC_GROUP): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_get_trinomial_basis}
  function EC_GROUP_get_trinomial_basis(const group: PEC_GROUP; k: PIdC_UINT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_GROUP_get_pentanomial_basis}
  function EC_GROUP_get_pentanomial_basis(const group: PEC_GROUP; k1: PIdC_UINT; k2: PIdC_UINT; k3: PIdC_UINT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM d2i_ECPKParameters}
  function d2i_ECPKParameters(group: PPEC_GROUP; const in_: PPByte; len: TIdC_LONG): PEC_GROUP cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_ECPKParameters}
  function i2d_ECPKParameters(const group: PEC_GROUP; out_: PPByte): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM ECPKParameters_print}
  function ECPKParameters_print(bp: PBIO; const x: PEC_GROUP; off: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EC_KEY_new}
  function EC_KEY_new: PEC_KEY cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_KEY_get_flags}
  function EC_KEY_get_flags(const key: PEC_KEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_KEY_set_flags}
  procedure EC_KEY_set_flags(key: PEC_KEY; flags: TIdC_INT) cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_KEY_clear_flags}
  procedure EC_KEY_clear_flags(key: PEC_KEY; flags: TIdC_INT) cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_KEY_new_by_curve_name}
  function EC_KEY_new_by_curve_name(nid: TIdC_INT): PEC_KEY cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_KEY_free}
  procedure EC_KEY_free(key: PEC_KEY) cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_KEY_copy}
  function EC_KEY_copy(dst: PEC_KEY; const src: PEC_KEY): PEC_KEY cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_KEY_dup}
  function EC_KEY_dup(const src: PEC_KEY): PEC_KEY cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_KEY_up_ref}
  function EC_KEY_up_ref(key: PEC_KEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_KEY_get0_engine}
  function EC_KEY_get0_engine(const eckey: PEC_KEY): PENGINE cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_get0_group}
  function EC_KEY_get0_group(const key: PEC_KEY): PEC_GROUP cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_KEY_set_group}
  function EC_KEY_set_group(key: PEC_KEY; const group: PEC_GROUP): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_KEY_get0_private_key}
  function EC_KEY_get0_private_key(const key: PEC_KEY): PBIGNUM cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_KEY_set_private_key}
  function EC_KEY_set_private_key(const key: PEC_KEY; const prv: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_KEY_get0_public_key}
  function EC_KEY_get0_public_key(const key: PEC_KEY): PEC_POINT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_KEY_set_public_key}
  function EC_KEY_set_public_key(key: PEC_KEY; const pub: PEC_POINT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_KEY_get_enc_flags}
  function EC_KEY_get_enc_flags(const key: PEC_KEY): TIdC_UINT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_KEY_set_enc_flags}
  procedure EC_KEY_set_enc_flags(eckey: PEC_KEY; flags: TIdC_UINT) cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_KEY_get_conv_form}
  function EC_KEY_get_conv_form(const key: PEC_KEY): point_conversion_form_t cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_KEY_set_conv_form}
  procedure EC_KEY_set_conv_form(eckey: PEC_KEY; cform: point_conversion_form_t) cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_KEY_set_ex_data}
  function EC_KEY_set_ex_data(key: PEC_KEY; idx: TIdC_INT; arg: Pointer): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_get_ex_data}
  function EC_KEY_get_ex_data(const key: PEC_KEY; idx: TIdC_INT): Pointer cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_set_asn1_flag}
  procedure EC_KEY_set_asn1_flag(eckey: PEC_KEY; asn1_flag: TIdC_INT) cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_KEY_precompute_mult}
  function EC_KEY_precompute_mult(key: PEC_KEY; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_KEY_generate_key}
  function EC_KEY_generate_key(key: PEC_KEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_KEY_check_key}
  function EC_KEY_check_key(const key: PEC_KEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_KEY_can_sign}
  function EC_KEY_can_sign(const eckey: PEC_KEY): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_set_public_key_affine_coordinates}
  function EC_KEY_set_public_key_affine_coordinates(key: PEC_KEY; x: PBIGNUM; y: PBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_KEY_key2buf}
  function EC_KEY_key2buf(const key: PEC_KEY; form: point_conversion_form_t; pbuf: PPByte; ctx: PBN_CTX): TIdC_SIZET cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_oct2key}
  function EC_KEY_oct2key(key: PEC_KEY; const buf: PByte; len: TIdC_SIZET; ctx: PBN_CTX): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_oct2priv}
  function EC_KEY_oct2priv(key: PEC_KEY; const buf: PByte; len: TIdC_SIZET): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_priv2oct}
  function EC_KEY_priv2oct(const key: PEC_KEY; buf: PByte; len: TIdC_SIZET): TIdC_SIZET cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_priv2buf}
  function EC_KEY_priv2buf(const eckey: PEC_KEY; buf: PPByte): TIdC_SIZET cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM d2i_ECPrivateKey}
  function d2i_ECPrivateKey(key: PPEC_KEY; const in_: PPByte; len: TIdC_LONG): PEC_KEY cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_ECPrivateKey}
  function i2d_ECPrivateKey(key: PEC_KEY; out_: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM o2i_ECPublicKey}
  function o2i_ECPublicKey(key: PPEC_KEY; const in_: PPByte; len: TIdC_LONG): PEC_KEY cdecl; external CLibCrypto;
  {$EXTERNALSYM i2o_ECPublicKey}
  function i2o_ECPublicKey(const key: PEC_KEY; out_: PPByte): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM ECParameters_print}
  function ECParameters_print(bp: PBIO; const key: PEC_KEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM EC_KEY_print}
  function EC_KEY_print(bp: PBIO; const key: PEC_KEY; off: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EC_KEY_OpenSSL}
  function EC_KEY_OpenSSL: PEC_KEY_METHOD cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_get_default_method}
  function EC_KEY_get_default_method: PEC_KEY_METHOD cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_set_default_method}
  procedure EC_KEY_set_default_method(const meth: PEC_KEY_METHOD) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_get_method}
  function EC_KEY_get_method(const key: PEC_KEY): PEC_KEY_METHOD cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_set_method}
  function EC_KEY_set_method(key: PEC_KEY; const meth: PEC_KEY_METHOD): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_new_method}
  function EC_KEY_new_method(engine: PENGINE): PEC_KEY cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM ECDH_KDF_X9_62}
  function ECDH_KDF_X9_62(out_: PByte; outlen: TIdC_SIZET; const Z: PByte; Zlen: TIdC_SIZET; const sinfo: PByte; sinfolen: TIdC_SIZET; const md: PEVP_MD): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ECDH_compute_key}
  function ECDH_compute_key(out_: Pointer; oulen: TIdC_SIZET; const pub_key: PEC_POINT; const ecdh: PEC_KEY; kdf: ECDH_compute_key_KDF): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM ECDSA_SIG_new}
  function ECDSA_SIG_new: PECDSA_SIG cdecl; external CLibCrypto;
  {$EXTERNALSYM ECDSA_SIG_free}
  procedure ECDSA_SIG_free(sig: PECDSA_SIG) cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_ECDSA_SIG}
  function i2d_ECDSA_SIG(const sig: PECDSA_SIG; pp: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_ECDSA_SIG}
  function d2i_ECDSA_SIG(sig: PPECDSA_SIG; const pp: PPByte; len: TIdC_LONG): PECDSA_SIG cdecl; external CLibCrypto;
  {$EXTERNALSYM ECDSA_SIG_get0}
  procedure ECDSA_SIG_get0(const sig: PECDSA_SIG; const pr: PPBIGNUM; const ps: PPBIGNUM) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ECDSA_SIG_get0_r}
  function ECDSA_SIG_get0_r(const sig: PECDSA_SIG): PBIGNUM cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ECDSA_SIG_get0_s}
  function ECDSA_SIG_get0_s(const sig: PECDSA_SIG): PBIGNUM cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ECDSA_SIG_set0}
  function ECDSA_SIG_set0(sig: PECDSA_SIG; r: PBIGNUM; s: PBIGNUM): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM ECDSA_do_sign}
  function ECDSA_do_sign(const dgst: PByte; dgst_len: TIdC_INT; eckey: PEC_KEY): PECDSA_SIG cdecl; external CLibCrypto;
  {$EXTERNALSYM ECDSA_do_sign_ex}
  function ECDSA_do_sign_ex(const dgst: PByte; dgst_len: TIdC_INT; const kinv: PBIGNUM; const rp: PBIGNUM; eckey: PEC_KEY): PECDSA_SIG cdecl; external CLibCrypto;
  {$EXTERNALSYM ECDSA_do_verify}
  function ECDSA_do_verify(const dgst: PByte; dgst_len: TIdC_INT; const sig: PECDSA_SIG; eckey: PEC_KEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ECDSA_sign_setup}
  function ECDSA_sign_setup(eckey: PEC_KEY; ctx: PBN_CTX; kiv: PPBIGNUM; rp: PPBIGNUM): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ECDSA_sign}
  function ECDSA_sign(type_: TIdC_INT; const dgst: PByte; dgstlen: TIdC_INT; sig: PByte; siglen: PIdC_UINT; eckey: PEC_KEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ECDSA_sign_ex}
  function ECDSA_sign_ex(type_: TIdC_INT; const dgst: PByte; dgstlen: TIdC_INT; sig: PByte; siglen: PIdC_UINT; const kinv: PBIGNUM; const rp: PBIGNUM; eckey: PEC_KEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ECDSA_verify}
  function ECDSA_verify(type_: TIdC_INT; const dgst: PByte; dgstlen: TIdC_INT; const sig: PByte; siglen: TIdC_INT; eckey: PEC_KEY): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM ECDSA_size}
  function ECDSA_size(const eckey: PEC_KEY): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM EC_KEY_METHOD_new}
  function EC_KEY_METHOD_new(const meth: PEC_KEY_METHOD): PEC_KEY_METHOD cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_METHOD_free}
  procedure EC_KEY_METHOD_free(meth: PEC_KEY_METHOD) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_METHOD_set_init}
  procedure EC_KEY_METHOD_set_init(meth: PEC_KEY_METHOD; init: EC_KEY_METHOD_init_init; finish: EC_KEY_METHOD_init_finish; _copy: EC_KEY_METHOD_init_copy; set_group: EC_KEY_METHOD_init_set_group; set_private: EC_KEY_METHOD_init_set_private; set_public: EC_KEY_METHOD_init_set_public) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_METHOD_set_keygen}
  procedure EC_KEY_METHOD_set_keygen(meth: PEC_KEY_METHOD; keygen: EC_KEY_METHOD_keygen_keygen) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_METHOD_set_compute_key}
  procedure EC_KEY_METHOD_set_compute_key(meth: PEC_KEY_METHOD; ckey: EC_KEY_METHOD_compute_key_ckey) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_METHOD_set_sign}
  procedure EC_KEY_METHOD_set_sign(meth: PEC_KEY_METHOD; sign: EC_KEY_METHOD_sign_sign; sign_setup: EC_KEY_METHOD_sign_sign_setup; sign_sig: EC_KEY_METHOD_sign_sign_sig) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_METHOD_set_verify}
  procedure EC_KEY_METHOD_set_verify(meth: PEC_KEY_METHOD; verify: EC_KEY_METHOD_verify_verify; verify_sig: EC_KEY_METHOD_verify_verify_sig) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM EC_KEY_METHOD_get_init}
  procedure EC_KEY_METHOD_get_init(const meth: PEC_KEY_METHOD; pinit: PEC_KEY_METHOD_init_init; pfinish: PEC_KEY_METHOD_init_finish; p_copy: PEC_KEY_METHOD_init_copy; pset_group: PEC_KEY_METHOD_init_set_group; pset_private: PEC_KEY_METHOD_init_set_private; pset_public: PEC_KEY_METHOD_init_set_public) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_METHOD_get_keygen}
  procedure EC_KEY_METHOD_get_keygen(const meth: PEC_KEY_METHOD; pkeygen: PEC_KEY_METHOD_keygen_keygen) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_METHOD_get_compute_key}
  procedure EC_KEY_METHOD_get_compute_key(const meth: PEC_KEY_METHOD; pck: PEC_KEY_METHOD_compute_key_ckey) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_METHOD_get_sign}
  procedure EC_KEY_METHOD_get_sign(const meth: PEC_KEY_METHOD; psign: PEC_KEY_METHOD_sign_sign; psign_setup: PEC_KEY_METHOD_sign_sign_setup; psign_sig: PEC_KEY_METHOD_sign_sign_sig) cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM EC_KEY_METHOD_get_verify}
  procedure EC_KEY_METHOD_get_verify(const meth: PEC_KEY_METHOD; pverify: PEC_KEY_METHOD_verify_verify; pverify_sig: PEC_KEY_METHOD_verify_verify_sig) cdecl; external CLibCrypto; {introduced 1.1.0}

{$ENDIF}

  {$EXTERNALSYM EC_KEY_get_ex_new_index}
function EC_KEY_get_ex_new_index(l : TIdC_LONG; p : PEC_KEY;
    newf : CRYPTO_EX_new; dupf : CRYPTO_EX_dup; freef : CRYPTO_EX_FREE) : TIdC_INT;

implementation

  uses
    classes, 
    TaurusTLSExceptionHandlers
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    ,TaurusTLSLoader
  {$ENDIF};

//#  define EC_KEY_get_ex_new_index(l, p, newf, dupf, freef) \
//    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_EC_KEY, l, p, newf, dupf, freef)
function EC_KEY_get_ex_new_index(l : TIdC_LONG; p : PEC_KEY;
    newf : CRYPTO_EX_new; dupf : CRYPTO_EX_dup; freef : CRYPTO_EX_FREE) : TIdC_INT;
{$IFDEF USE_INLINE}inline; {$ENDIF}
begin
  Result := CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_EC_KEY, l, p, newf, dupf, freef);
end;

const
 {$IFDEF OPENSSL_NO_EC_NISTP_64_GCC_128}
  EC_GFp_nistp224_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_GFp_nistp256_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_GFp_nistp521_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  {$ENDIF}
  EC_GROUP_get0_order_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_GROUP_order_bits_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_GROUP_get0_cofactor_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_GROUP_set_curve_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_GROUP_get_curve_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_GROUP_new_from_ecparameters_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_GROUP_get_ecparameters_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_GROUP_new_from_ecpkparameters_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_GROUP_get_ecpkparameters_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_POINT_set_affine_coordinates_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_POINT_get_affine_coordinates_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_POINT_set_compressed_coordinates_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_POINT_point2buf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_get0_engine_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_get0_engine_removed = (byte(4) shl 8 or byte(0)) shl 8 or byte(0);
  EC_KEY_set_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_get_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_can_sign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_key2buf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_oct2key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_oct2priv_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_priv2oct_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_priv2buf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_OpenSSL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_get_default_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_set_default_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_get_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_set_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_new_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ECDSA_SIG_get0_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ECDSA_SIG_get0_r_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ECDSA_SIG_get0_s_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ECDSA_SIG_set0_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_METHOD_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_METHOD_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_METHOD_set_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_METHOD_set_keygen_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_METHOD_set_compute_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_METHOD_set_sign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_METHOD_set_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_METHOD_get_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_METHOD_get_keygen_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_METHOD_get_compute_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_METHOD_get_sign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_METHOD_get_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  {$IFDEF OPENSSL_NO_EC_NISTP_64_GCC_128}
  EC_GFp_nistp224_method_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EC_GFp_nistp256_method_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  EC_GFp_nistp521_method_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);
  {$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
const
  EC_GFp_simple_method_procname = 'EC_GFp_simple_method';
  EC_GFp_mont_method_procname = 'EC_GFp_mont_method';
  EC_GFp_nist_method_procname = 'EC_GFp_nist_method';
  {$IFDEF OPENSSL_NO_EC_NISTP_64_GCC_128}
  EC_GFp_nistp224_method_procname = 'EC_GFp_nistp224_method'; {introduced 1.1.0 removed 3.0.0}
  EC_GFp_nistp256_method_procname = 'EC_GFp_nistp256_method'; {introduced 1.1.0 removed 3.0.0}
  EC_GFp_nistp521_method_procname = 'EC_GFp_nistp521_method'; {introduced 1.1.0 removed 3.0.0}
  {$ENDIF}

  EC_GF2m_simple_method_procname = 'EC_GF2m_simple_method';

  EC_GROUP_new_procname = 'EC_GROUP_new';
  EC_GROUP_free_procname = 'EC_GROUP_free';
  EC_GROUP_clear_free_procname = 'EC_GROUP_clear_free';
  EC_GROUP_copy_procname = 'EC_GROUP_copy';
  EC_GROUP_dup_procname = 'EC_GROUP_dup';
  EC_GROUP_method_of_procname = 'EC_GROUP_method_of';
  EC_METHOD_get_field_type_procname = 'EC_METHOD_get_field_type';
  EC_GROUP_set_generator_procname = 'EC_GROUP_set_generator';
  EC_GROUP_get0_generator_procname = 'EC_GROUP_get0_generator';
  EC_GROUP_get_mont_data_procname = 'EC_GROUP_get_mont_data';
  EC_GROUP_get_order_procname = 'EC_GROUP_get_order';
  EC_GROUP_get0_order_procname = 'EC_GROUP_get0_order'; {introduced 1.1.0}
  EC_GROUP_order_bits_procname = 'EC_GROUP_order_bits'; {introduced 1.1.0}
  EC_GROUP_get_cofactor_procname = 'EC_GROUP_get_cofactor';
  EC_GROUP_get0_cofactor_procname = 'EC_GROUP_get0_cofactor'; {introduced 1.1.0}
  EC_GROUP_set_curve_name_procname = 'EC_GROUP_set_curve_name';
  EC_GROUP_get_curve_name_procname = 'EC_GROUP_get_curve_name';

  EC_GROUP_set_asn1_flag_procname = 'EC_GROUP_set_asn1_flag';
  EC_GROUP_get_asn1_flag_procname = 'EC_GROUP_get_asn1_flag';

  EC_GROUP_set_point_conversion_form_procname = 'EC_GROUP_set_point_conversion_form';
  EC_GROUP_get_point_conversion_form_procname = 'EC_GROUP_get_point_conversion_form';

  EC_GROUP_get0_seed_procname = 'EC_GROUP_get0_seed';
  EC_GROUP_get_seed_len_procname = 'EC_GROUP_get_seed_len';
  EC_GROUP_set_seed_procname = 'EC_GROUP_set_seed';

  EC_GROUP_set_curve_procname = 'EC_GROUP_set_curve'; {introduced 1.1.0}
  EC_GROUP_get_curve_procname = 'EC_GROUP_get_curve'; {introduced 1.1.0}
  EC_GROUP_set_curve_GFp_procname = 'EC_GROUP_set_curve_GFp';
  EC_GROUP_get_curve_GFp_procname = 'EC_GROUP_get_curve_GFp';
  EC_GROUP_set_curve_GF2m_procname = 'EC_GROUP_set_curve_GF2m';
  EC_GROUP_get_curve_GF2m_procname = 'EC_GROUP_get_curve_GF2m';

  EC_GROUP_get_degree_procname = 'EC_GROUP_get_degree';
  EC_GROUP_check_procname = 'EC_GROUP_check';
  EC_GROUP_check_discriminant_procname = 'EC_GROUP_check_discriminant';
  EC_GROUP_cmp_procname = 'EC_GROUP_cmp';

  EC_GROUP_new_curve_GFp_procname = 'EC_GROUP_new_curve_GFp';
  EC_GROUP_new_curve_GF2m_procname = 'EC_GROUP_new_curve_GF2m';
  EC_GROUP_new_by_curve_name_procname = 'EC_GROUP_new_by_curve_name';
  EC_GROUP_new_from_ecparameters_procname = 'EC_GROUP_new_from_ecparameters'; {introduced 1.1.0}
  EC_GROUP_get_ecparameters_procname = 'EC_GROUP_get_ecparameters'; {introduced 1.1.0}
  EC_GROUP_new_from_ecpkparameters_procname = 'EC_GROUP_new_from_ecpkparameters'; {introduced 1.1.0}
  EC_GROUP_get_ecpkparameters_procname = 'EC_GROUP_get_ecpkparameters'; {introduced 1.1.0}

  EC_get_builtin_curves_procname = 'EC_get_builtin_curves';

  EC_curve_nid2nist_procname = 'EC_curve_nid2nist';
  EC_curve_nist2nid_procname = 'EC_curve_nist2nid';

  EC_POINT_new_procname = 'EC_POINT_new';
  EC_POINT_free_procname = 'EC_POINT_free';
  EC_POINT_clear_free_procname = 'EC_POINT_clear_free';
  EC_POINT_copy_procname = 'EC_POINT_copy';
  EC_POINT_dup_procname = 'EC_POINT_dup';
  EC_POINT_method_of_procname = 'EC_POINT_method_of';
  EC_POINT_set_to_infinity_procname = 'EC_POINT_set_to_infinity';
  EC_POINT_set_Jprojective_coordinates_GFp_procname = 'EC_POINT_set_Jprojective_coordinates_GFp';
  EC_POINT_get_Jprojective_coordinates_GFp_procname = 'EC_POINT_get_Jprojective_coordinates_GFp';
  EC_POINT_set_affine_coordinates_procname = 'EC_POINT_set_affine_coordinates'; {introduced 1.1.0}
  EC_POINT_get_affine_coordinates_procname = 'EC_POINT_get_affine_coordinates'; {introduced 1.1.0}
  EC_POINT_set_affine_coordinates_GFp_procname = 'EC_POINT_set_affine_coordinates_GFp';
  EC_POINT_get_affine_coordinates_GFp_procname = 'EC_POINT_get_affine_coordinates_GFp';
  EC_POINT_set_compressed_coordinates_procname = 'EC_POINT_set_compressed_coordinates'; {introduced 1.1.0}
  EC_POINT_set_compressed_coordinates_GFp_procname = 'EC_POINT_set_compressed_coordinates_GFp';
  EC_POINT_set_affine_coordinates_GF2m_procname = 'EC_POINT_set_affine_coordinates_GF2m';
  EC_POINT_get_affine_coordinates_GF2m_procname = 'EC_POINT_get_affine_coordinates_GF2m';
  EC_POINT_set_compressed_coordinates_GF2m_procname = 'EC_POINT_set_compressed_coordinates_GF2m';

  EC_POINT_point2oct_procname = 'EC_POINT_point2oct';
  EC_POINT_oct2point_procname = 'EC_POINT_oct2point';
  EC_POINT_point2buf_procname = 'EC_POINT_point2buf'; {introduced 1.1.0}
  EC_POINT_point2bn_procname = 'EC_POINT_point2bn';
  EC_POINT_bn2point_procname = 'EC_POINT_bn2point';
  EC_POINT_point2hex_procname = 'EC_POINT_point2hex';
  EC_POINT_hex2point_procname = 'EC_POINT_hex2point';

  EC_POINT_add_procname = 'EC_POINT_add';
  EC_POINT_dbl_procname = 'EC_POINT_dbl';
  EC_POINT_invert_procname = 'EC_POINT_invert';
  EC_POINT_is_at_infinity_procname = 'EC_POINT_is_at_infinity';
  EC_POINT_is_on_curve_procname = 'EC_POINT_is_on_curve';
  EC_POINT_cmp_procname = 'EC_POINT_cmp';
  EC_POINT_make_affine_procname = 'EC_POINT_make_affine';
  EC_POINTs_make_affine_procname = 'EC_POINTs_make_affine';
  EC_POINTs_mul_procname = 'EC_POINTs_mul';
  EC_POINT_mul_procname = 'EC_POINT_mul';

  EC_GROUP_precompute_mult_procname = 'EC_GROUP_precompute_mult';
  EC_GROUP_have_precompute_mult_procname = 'EC_GROUP_have_precompute_mult';

  ECPKPARAMETERS_it_procname = 'ECPKPARAMETERS_it';
  ECPKPARAMETERS_new_procname = 'ECPKPARAMETERS_new';
  ECPKPARAMETERS_free_procname = 'ECPKPARAMETERS_free';

  ECPARAMETERS_it_procname = 'ECPARAMETERS_it';
  ECPARAMETERS_new_procname = 'ECPARAMETERS_new';
  ECPARAMETERS_free_procname = 'ECPARAMETERS_free';

  EC_GROUP_get_basis_type_procname = 'EC_GROUP_get_basis_type';
  EC_GROUP_get_trinomial_basis_procname = 'EC_GROUP_get_trinomial_basis';
  EC_GROUP_get_pentanomial_basis_procname = 'EC_GROUP_get_pentanomial_basis';

  d2i_ECPKParameters_procname = 'd2i_ECPKParameters';
  i2d_ECPKParameters_procname = 'i2d_ECPKParameters';

  ECPKParameters_print_procname = 'ECPKParameters_print';

  EC_KEY_new_procname = 'EC_KEY_new';
  EC_KEY_get_flags_procname = 'EC_KEY_get_flags';
  EC_KEY_set_flags_procname = 'EC_KEY_set_flags';
  EC_KEY_clear_flags_procname = 'EC_KEY_clear_flags';
  EC_KEY_new_by_curve_name_procname = 'EC_KEY_new_by_curve_name';
  EC_KEY_free_procname = 'EC_KEY_free';
  EC_KEY_copy_procname = 'EC_KEY_copy';
  EC_KEY_dup_procname = 'EC_KEY_dup';
  EC_KEY_up_ref_procname = 'EC_KEY_up_ref';
  EC_KEY_get0_engine_procname = 'EC_KEY_get0_engine'; {introduced 1.1.0}
  EC_KEY_get0_group_procname = 'EC_KEY_get0_group';
  EC_KEY_set_group_procname = 'EC_KEY_set_group';
  EC_KEY_get0_private_key_procname = 'EC_KEY_get0_private_key';
  EC_KEY_set_private_key_procname = 'EC_KEY_set_private_key';
  EC_KEY_get0_public_key_procname = 'EC_KEY_get0_public_key';
  EC_KEY_set_public_key_procname = 'EC_KEY_set_public_key';
  EC_KEY_get_enc_flags_procname = 'EC_KEY_get_enc_flags';
  EC_KEY_set_enc_flags_procname = 'EC_KEY_set_enc_flags';
  EC_KEY_get_conv_form_procname = 'EC_KEY_get_conv_form';
  EC_KEY_set_conv_form_procname = 'EC_KEY_set_conv_form';
  EC_KEY_set_ex_data_procname = 'EC_KEY_set_ex_data'; {introduced 1.1.0}
  EC_KEY_get_ex_data_procname = 'EC_KEY_get_ex_data'; {introduced 1.1.0}
  EC_KEY_set_asn1_flag_procname = 'EC_KEY_set_asn1_flag';
  EC_KEY_precompute_mult_procname = 'EC_KEY_precompute_mult';
  EC_KEY_generate_key_procname = 'EC_KEY_generate_key';
  EC_KEY_check_key_procname = 'EC_KEY_check_key';
  EC_KEY_can_sign_procname = 'EC_KEY_can_sign'; {introduced 1.1.0}
  EC_KEY_set_public_key_affine_coordinates_procname = 'EC_KEY_set_public_key_affine_coordinates';
  EC_KEY_key2buf_procname = 'EC_KEY_key2buf'; {introduced 1.1.0}
  EC_KEY_oct2key_procname = 'EC_KEY_oct2key'; {introduced 1.1.0}
  EC_KEY_oct2priv_procname = 'EC_KEY_oct2priv'; {introduced 1.1.0}
  EC_KEY_priv2oct_procname = 'EC_KEY_priv2oct'; {introduced 1.1.0}
  EC_KEY_priv2buf_procname = 'EC_KEY_priv2buf'; {introduced 1.1.0}

  d2i_ECPrivateKey_procname = 'd2i_ECPrivateKey';
  i2d_ECPrivateKey_procname = 'i2d_ECPrivateKey';
  o2i_ECPublicKey_procname = 'o2i_ECPublicKey';
  i2o_ECPublicKey_procname = 'i2o_ECPublicKey';

  ECParameters_print_procname = 'ECParameters_print';
  EC_KEY_print_procname = 'EC_KEY_print';

  EC_KEY_OpenSSL_procname = 'EC_KEY_OpenSSL'; {introduced 1.1.0}
  EC_KEY_get_default_method_procname = 'EC_KEY_get_default_method'; {introduced 1.1.0}
  EC_KEY_set_default_method_procname = 'EC_KEY_set_default_method'; {introduced 1.1.0}
  EC_KEY_get_method_procname = 'EC_KEY_get_method'; {introduced 1.1.0}
  EC_KEY_set_method_procname = 'EC_KEY_set_method'; {introduced 1.1.0}
  EC_KEY_new_method_procname = 'EC_KEY_new_method'; {introduced 1.1.0}

  ECDH_KDF_X9_62_procname = 'ECDH_KDF_X9_62';
  ECDH_compute_key_procname = 'ECDH_compute_key';

  ECDSA_SIG_new_procname = 'ECDSA_SIG_new';
  ECDSA_SIG_free_procname = 'ECDSA_SIG_free';
  i2d_ECDSA_SIG_procname = 'i2d_ECDSA_SIG';
  d2i_ECDSA_SIG_procname = 'd2i_ECDSA_SIG';
  ECDSA_SIG_get0_procname = 'ECDSA_SIG_get0'; {introduced 1.1.0}
  ECDSA_SIG_get0_r_procname = 'ECDSA_SIG_get0_r'; {introduced 1.1.0}
  ECDSA_SIG_get0_s_procname = 'ECDSA_SIG_get0_s'; {introduced 1.1.0}
  ECDSA_SIG_set0_procname = 'ECDSA_SIG_set0'; {introduced 1.1.0}
  ECDSA_do_sign_procname = 'ECDSA_do_sign';
  ECDSA_do_sign_ex_procname = 'ECDSA_do_sign_ex';
  ECDSA_do_verify_procname = 'ECDSA_do_verify';
  ECDSA_sign_setup_procname = 'ECDSA_sign_setup';
  ECDSA_sign_procname = 'ECDSA_sign';
  ECDSA_sign_ex_procname = 'ECDSA_sign_ex';
  ECDSA_verify_procname = 'ECDSA_verify';
  ECDSA_size_procname = 'ECDSA_size';

  EC_KEY_METHOD_new_procname = 'EC_KEY_METHOD_new'; {introduced 1.1.0}
  EC_KEY_METHOD_free_procname = 'EC_KEY_METHOD_free'; {introduced 1.1.0}
  EC_KEY_METHOD_set_init_procname = 'EC_KEY_METHOD_set_init'; {introduced 1.1.0}
  EC_KEY_METHOD_set_keygen_procname = 'EC_KEY_METHOD_set_keygen'; {introduced 1.1.0}
  EC_KEY_METHOD_set_compute_key_procname = 'EC_KEY_METHOD_set_compute_key'; {introduced 1.1.0}
  EC_KEY_METHOD_set_sign_procname = 'EC_KEY_METHOD_set_sign'; {introduced 1.1.0}
  EC_KEY_METHOD_set_verify_procname = 'EC_KEY_METHOD_set_verify'; {introduced 1.1.0}

  EC_KEY_METHOD_get_init_procname = 'EC_KEY_METHOD_get_init'; {introduced 1.1.0}
  EC_KEY_METHOD_get_keygen_procname = 'EC_KEY_METHOD_get_keygen'; {introduced 1.1.0}
  EC_KEY_METHOD_get_compute_key_procname = 'EC_KEY_METHOD_get_compute_key'; {introduced 1.1.0}
  EC_KEY_METHOD_get_sign_procname = 'EC_KEY_METHOD_get_sign'; {introduced 1.1.0}
  EC_KEY_METHOD_get_verify_procname = 'EC_KEY_METHOD_get_verify'; {introduced 1.1.0}

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc} 
function  ERR_EC_GFp_simple_method: PEC_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GFp_simple_method_procname);
end;


function  ERR_EC_GFp_mont_method: PEC_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GFp_mont_method_procname);
end;


function  ERR_EC_GFp_nist_method: PEC_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GFp_nist_method_procname);
end;

 {$IFDEF OPENSSL_NO_EC_NISTP_64_GCC_128}
function  ERR_EC_GFp_nistp224_method: PEC_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GFp_nistp224_method_procname);
end;


function  ERR_EC_GFp_nistp256_method: PEC_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GFp_nistp256_method_procname);
end;


function  ERR_EC_GFp_nistp521_method: PEC_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GFp_nistp521_method_procname);
end;
{$ENDIF}


function  ERR_EC_GF2m_simple_method: PEC_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GF2m_simple_method_procname);
end;



function  ERR_EC_GROUP_new(const meth: PEC_METHOD): PEC_GROUP; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_new_procname);
end;


procedure  ERR_EC_GROUP_free(group: PEC_GROUP); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_free_procname);
end;


procedure  ERR_EC_GROUP_clear_free(group: PEC_GROUP); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_clear_free_procname);
end;


function  ERR_EC_GROUP_copy(dst: PEC_GROUP; const src: PEC_GROUP): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_copy_procname);
end;


function  ERR_EC_GROUP_dup(const src: PEC_GROUP): PEC_GROUP; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_dup_procname);
end;


function  ERR_EC_GROUP_method_of(const group: PEC_GROUP): PEC_GROUP; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_method_of_procname);
end;


function  ERR_EC_METHOD_get_field_type(const meth: PEC_METHOD): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_METHOD_get_field_type_procname);
end;


function  ERR_EC_GROUP_set_generator(group: PEC_GROUP; const generator: PEC_POINT;
  const order: PBIGNUM; const cofactor: PBIGNUM): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_set_generator_procname);
end;


function  ERR_EC_GROUP_get0_generator(const group: PEC_GROUP): PEC_POINT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get0_generator_procname);
end;


function  ERR_EC_GROUP_get_mont_data(const group: PEC_GROUP): PBN_MONT_CTX; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_mont_data_procname);
end;


function  ERR_EC_GROUP_get_order(const group: PEC_GROUP; order: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_order_procname);
end;


function  ERR_EC_GROUP_get0_order(const group: PEC_GROUP): PBIGNUM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get0_order_procname);
end;

 {introduced 1.1.0}
function  ERR_EC_GROUP_order_bits(const group: PEC_GROUP): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_order_bits_procname);
end;

 {introduced 1.1.0}
function  ERR_EC_GROUP_get_cofactor(const group: PEC_GROUP; cofactor: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_cofactor_procname);
end;


function  ERR_EC_GROUP_get0_cofactor(const group: PEC_GROUP): PBIGNUM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get0_cofactor_procname);
end;

 {introduced 1.1.0}
procedure  ERR_EC_GROUP_set_curve_name(group: PEC_GROUP; nid: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_set_curve_name_procname);
end;


function  ERR_EC_GROUP_get_curve_name(const group: PEC_GROUP): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_curve_name_procname);
end;



procedure  ERR_EC_GROUP_set_asn1_flag(group: PEC_GROUP; flag: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_set_asn1_flag_procname);
end;


function  ERR_EC_GROUP_get_asn1_flag(const group: PEC_GROUP): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_asn1_flag_procname);
end;



procedure  ERR_EC_GROUP_set_point_conversion_form(group: PEC_GROUP; form: point_conversion_form_t); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_set_point_conversion_form_procname);
end;


function  ERR_EC_GROUP_get_point_conversion_form(const group: PEC_GROUP): point_conversion_form_t; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_point_conversion_form_procname);
end;



function  ERR_EC_GROUP_get0_seed(const x: PEC_GROUP): PByte; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get0_seed_procname);
end;


function  ERR_EC_GROUP_get_seed_len(const x: PEC_GROUP): TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_seed_len_procname);
end;


function  ERR_EC_GROUP_set_seed(x: PEC_GROUP; const p: PByte; len: TIdC_SIZET): TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_set_seed_procname);
end;



function  ERR_EC_GROUP_set_curve(group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM;
  const b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_set_curve_procname);
end;

 {introduced 1.1.0}
function  ERR_EC_GROUP_get_curve(const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM;
  b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_curve_procname);
end;

 {introduced 1.1.0}
function  ERR_EC_GROUP_set_curve_GFp(group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM;
  const b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_set_curve_GFp_procname);
end;


function  ERR_EC_GROUP_get_curve_GFp(const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM;
  b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_curve_GFp_procname);
end;


function  ERR_EC_GROUP_set_curve_GF2m(group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM;
  const b:PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_set_curve_GF2m_procname);
end;


function  ERR_EC_GROUP_get_curve_GF2m(const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM;
  ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_curve_GF2m_procname);
end;



function  ERR_EC_GROUP_get_degree(const group: PEC_GROUP): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_degree_procname);
end;


function  ERR_EC_GROUP_check(const group: PEC_GROUP; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_check_procname);
end;


function  ERR_EC_GROUP_check_discriminant(const group: PEC_GROUP; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_check_discriminant_procname);
end;


function  ERR_EC_GROUP_cmp(const a: PEC_GROUP; const b: PEC_GROUP; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_cmp_procname);
end;



function  ERR_EC_GROUP_new_curve_GFp(const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM;
  ctx: PBN_CTX): PEC_GROUP; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_new_curve_GFp_procname);
end;


function  ERR_EC_GROUP_new_curve_GF2m(const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM;
  ctx: PBN_CTX): PEC_GROUP; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_new_curve_GF2m_procname);
end;


function  ERR_EC_GROUP_new_by_curve_name(nid: TIdC_INT): PEC_GROUP; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_new_by_curve_name_procname);
end;


function  ERR_EC_GROUP_new_from_ecparameters(const params: PECPARAMETERS): PEC_GROUP; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_new_from_ecparameters_procname);
end;

 {introduced 1.1.0}
function  ERR_EC_GROUP_get_ecparameters(const group: PEC_GROUP; params: PECPARAMETERS): PECPARAMETERS; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_ecparameters_procname);
end;

 {introduced 1.1.0}
function  ERR_EC_GROUP_new_from_ecpkparameters(const params: PECPKPARAMETERS): PEC_GROUP; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_new_from_ecpkparameters_procname);
end;

 {introduced 1.1.0}
function  ERR_EC_GROUP_get_ecpkparameters(const group: PEC_GROUP; params: PECPKPARAMETERS): PECPKPARAMETERS; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_ecpkparameters_procname);
end;

 {introduced 1.1.0}

function  ERR_EC_get_builtin_curves(r: PEC_builtin_curve; nitems: TIdC_SIZET): TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_get_builtin_curves_procname);
end;



function  ERR_EC_curve_nid2nist(nid: TIdC_INT): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_curve_nid2nist_procname);
end;


function  ERR_EC_curve_nist2nid(const name: PIdAnsiChar): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_curve_nist2nid_procname);
end;



function  ERR_EC_POINT_new(const group: PEC_GROUP): PEC_POINT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_new_procname);
end;


procedure  ERR_EC_POINT_free(point: PEC_POINT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_free_procname);
end;


procedure  ERR_EC_POINT_clear_free(point: PEC_POINT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_clear_free_procname);
end;


function  ERR_EC_POINT_copy(dst: PEC_POINT; const src: PEC_POINT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_copy_procname);
end;


function  ERR_EC_POINT_dup(const src: PEC_POINT; const group: PEC_GROUP): PEC_POINT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_dup_procname);
end;


function  ERR_EC_POINT_method_of(const point: PEC_POINT): PEC_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_method_of_procname);
end;


function  ERR_EC_POINT_set_to_infinity(const group: PEC_GROUP; point: PEC_POINT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_set_to_infinity_procname);
end;


function  ERR_EC_POINT_set_Jprojective_coordinates_GFp(const group: PEC_GROUP; p: PEC_POINT;
  const x: PBIGNUM; const y: PBIGNUM; const z: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_set_Jprojective_coordinates_GFp_procname);
end;


function  ERR_EC_POINT_get_Jprojective_coordinates_GFp(const group: PEC_METHOD;
  const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_get_Jprojective_coordinates_GFp_procname);
end;


function  ERR_EC_POINT_set_affine_coordinates(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM;
  const y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_set_affine_coordinates_procname);
end;

 {introduced 1.1.0}
function  ERR_EC_POINT_get_affine_coordinates(const group: PEC_GROUP; const p: PEC_POINT;
  x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_get_affine_coordinates_procname);
end;

 {introduced 1.1.0}
function  ERR_EC_POINT_set_affine_coordinates_GFp(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM;
  const y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_set_affine_coordinates_GFp_procname);
end;


function  ERR_EC_POINT_get_affine_coordinates_GFp(const group: PEC_GROUP; const p: PEC_POINT; x: PBIGNUM;
  y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_get_affine_coordinates_GFp_procname);
end;


function  ERR_EC_POINT_set_compressed_coordinates(const group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM;
  y_bit: TIdC_INT; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_set_compressed_coordinates_procname);
end;

 {introduced 1.1.0}
function  ERR_EC_POINT_set_compressed_coordinates_GFp(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM;
  y_bit: TIdC_INT; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_set_compressed_coordinates_GFp_procname);
end;


function  ERR_EC_POINT_set_affine_coordinates_GF2m(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM;
  const y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_set_affine_coordinates_GF2m_procname);
end;


function  ERR_EC_POINT_get_affine_coordinates_GF2m(const group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM;
  y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_get_affine_coordinates_GF2m_procname);
end;


function  ERR_EC_POINT_set_compressed_coordinates_GF2m(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM;
  y_bit: TIdC_INT; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_set_compressed_coordinates_GF2m_procname);
end;



function  ERR_EC_POINT_point2oct(const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t;
  buf: PByte; len: TIdC_SIZET; ctx: PBN_CTX): TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_point2oct_procname);
end;


function  ERR_EC_POINT_oct2point(const group: PEC_GROUP; p: PEC_POINT; const buf: PByte; len: TIdC_SIZET;
  ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_oct2point_procname);
end;


function  ERR_EC_POINT_point2buf(const group: PEC_GROUP; const point: PEC_POINT; form: point_conversion_form_t;
  pbuf: PPByte; ctx: PBN_CTX): TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_point2buf_procname);
end;

 {introduced 1.1.0}
function  ERR_EC_POINT_point2bn(const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t;
  bn: PBIGNUM; ctx: PBN_CTX): PBIGNUM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_point2bn_procname);
end;


function  ERR_EC_POINT_bn2point(const group: PEC_GROUP; const bn: PBIGNUM; p: PEC_POINT;
  ctx: PBN_CTX): PEC_POINT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_bn2point_procname);
end;


function  ERR_EC_POINT_point2hex(const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t;
  ctx: PBN_CTX): PIdAnsiChar; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_point2hex_procname);
end;


function  ERR_EC_POINT_hex2point(const group: PEC_GROUP; const buf: PIdAnsiChar; p: PEC_POINT;
  ctx: PBN_CTX): PEC_POINT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_hex2point_procname);
end;



function  ERR_EC_POINT_add(const group: PEC_GROUP; r: PEC_POINT; const a: PEC_POINT; const b: PEC_POINT;
  ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_add_procname);
end;


function  ERR_EC_POINT_dbl(const group: PEC_GROUP; r: PEC_POINT; const a: PEC_POINT;
  ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_dbl_procname);
end;


function  ERR_EC_POINT_invert(const group: PEC_GROUP; a: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_invert_procname);
end;


function  ERR_EC_POINT_is_at_infinity(const group: PEC_GROUP; const p: PEC_POINT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_is_at_infinity_procname);
end;


function  ERR_EC_POINT_is_on_curve(const group: PEC_GROUP; const point: PEC_POINT;
  ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_is_on_curve_procname);
end;


function  ERR_EC_POINT_cmp(const group: PEC_GROUP; const a: PEC_POINT; const b: PEC_POINT;
  ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_cmp_procname);
end;


function  ERR_EC_POINT_make_affine(const group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_make_affine_procname);
end;


function  ERR_EC_POINTs_make_affine(const group: PEC_METHOD; num: TIdC_SIZET; points: PPEC_POINT;
  ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINTs_make_affine_procname);
end;


function  ERR_EC_POINTs_mul(const group: PEC_GROUP; r: PEC_POINT; const n: PBIGNUM; num: TIdC_SIZET;
  const p: PPEC_POINT; const m: PPBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINTs_mul_procname);
end;


function  ERR_EC_POINT_mul(const group: PEC_GROUP; r: PEC_POINT; const n: PBIGNUM; const q: PEC_POINT;
  const m: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_mul_procname);
end;



function  ERR_EC_GROUP_precompute_mult(group: PEC_GROUP; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_precompute_mult_procname);
end;


function  ERR_EC_GROUP_have_precompute_mult(const group: PEC_GROUP): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_have_precompute_mult_procname);
end;



function  ERR_ECPKPARAMETERS_it: PASN1_ITEM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECPKPARAMETERS_it_procname);
end;


function  ERR_ECPKPARAMETERS_new: PECPKPARAMETERS; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECPKPARAMETERS_new_procname);
end;


procedure  ERR_ECPKPARAMETERS_free(a: PECPKPARAMETERS); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECPKPARAMETERS_free_procname);
end;



function  ERR_ECPARAMETERS_it: PASN1_ITEM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECPARAMETERS_it_procname);
end;


function  ERR_ECPARAMETERS_new: PECPARAMETERS; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECPARAMETERS_new_procname);
end;


procedure  ERR_ECPARAMETERS_free(a: PECPARAMETERS); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECPARAMETERS_free_procname);
end;



function  ERR_EC_GROUP_get_basis_type(const group: PEC_GROUP): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_basis_type_procname);
end;


function  ERR_EC_GROUP_get_trinomial_basis(const group: PEC_GROUP; k: PIdC_UINT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_trinomial_basis_procname);
end;


function  ERR_EC_GROUP_get_pentanomial_basis(const group: PEC_GROUP; k1: PIdC_UINT; k2: PIdC_UINT;
  k3: PIdC_UINT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_pentanomial_basis_procname);
end;



function  ERR_d2i_ECPKParameters(group: PPEC_GROUP; const in_: PPByte; len: TIdC_LONG): PEC_GROUP; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ECPKParameters_procname);
end;


function  ERR_i2d_ECPKParameters(const group: PEC_GROUP; out_: PPByte): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ECPKParameters_procname);
end;



function  ERR_ECPKParameters_print(bp: PBIO; const x: PEC_GROUP; off: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECPKParameters_print_procname);
end;



function  ERR_EC_KEY_new: PEC_KEY; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_new_procname);
end;


function  ERR_EC_KEY_get_flags(const key: PEC_KEY): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_get_flags_procname);
end;


procedure  ERR_EC_KEY_set_flags(key: PEC_KEY; flags: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_set_flags_procname);
end;


procedure  ERR_EC_KEY_clear_flags(key: PEC_KEY; flags: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_clear_flags_procname);
end;


function  ERR_EC_KEY_new_by_curve_name(nid: TIdC_INT): PEC_KEY; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_new_by_curve_name_procname);
end;


procedure  ERR_EC_KEY_free(key: PEC_KEY); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_free_procname);
end;


function  ERR_EC_KEY_copy(dst: PEC_KEY; const src: PEC_KEY): PEC_KEY; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_copy_procname);
end;


function  ERR_EC_KEY_dup(const src: PEC_KEY): PEC_KEY; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_dup_procname);
end;


function  ERR_EC_KEY_up_ref(key: PEC_KEY): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_up_ref_procname);
end;


function  ERR_EC_KEY_get0_engine(const eckey: PEC_KEY): PENGINE; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_get0_engine_procname);
end;

 {introduced 1.1.0}
function  ERR_EC_KEY_get0_group(const key: PEC_KEY): PEC_GROUP; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_get0_group_procname);
end;


function  ERR_EC_KEY_set_group(key: PEC_KEY; const group: PEC_GROUP): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_set_group_procname);
end;


function  ERR_EC_KEY_get0_private_key(const key: PEC_KEY): PBIGNUM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_get0_private_key_procname);
end;


function  ERR_EC_KEY_set_private_key(const key: PEC_KEY; const prv: PBIGNUM): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_set_private_key_procname);
end;


function  ERR_EC_KEY_get0_public_key(const key: PEC_KEY): PEC_POINT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_get0_public_key_procname);
end;


function  ERR_EC_KEY_set_public_key(key: PEC_KEY; const pub: PEC_POINT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_set_public_key_procname);
end;


function  ERR_EC_KEY_get_enc_flags(const key: PEC_KEY): TIdC_UINT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_get_enc_flags_procname);
end;


procedure  ERR_EC_KEY_set_enc_flags(eckey: PEC_KEY; flags: TIdC_UINT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_set_enc_flags_procname);
end;


function  ERR_EC_KEY_get_conv_form(const key: PEC_KEY): point_conversion_form_t; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_get_conv_form_procname);
end;


procedure  ERR_EC_KEY_set_conv_form(eckey: PEC_KEY; cform: point_conversion_form_t); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_set_conv_form_procname);
end;


function  ERR_EC_KEY_set_ex_data(key: PEC_KEY; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_set_ex_data_procname);
end;

 {introduced 1.1.0}
function  ERR_EC_KEY_get_ex_data(const key: PEC_KEY; idx: TIdC_INT): Pointer; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_get_ex_data_procname);
end;

 {introduced 1.1.0}
procedure  ERR_EC_KEY_set_asn1_flag(eckey: PEC_KEY; asn1_flag: TIdC_INT); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_set_asn1_flag_procname);
end;


function  ERR_EC_KEY_precompute_mult(key: PEC_KEY; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_precompute_mult_procname);
end;


function  ERR_EC_KEY_generate_key(key: PEC_KEY): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_generate_key_procname);
end;


function  ERR_EC_KEY_check_key(const key: PEC_KEY): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_check_key_procname);
end;


function  ERR_EC_KEY_can_sign(const eckey: PEC_KEY): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_can_sign_procname);
end;

 {introduced 1.1.0}
function  ERR_EC_KEY_set_public_key_affine_coordinates(key: PEC_KEY; x: PBIGNUM; y: PBIGNUM): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_set_public_key_affine_coordinates_procname);
end;


function  ERR_EC_KEY_key2buf(const key: PEC_KEY; form: point_conversion_form_t; pbuf: PPByte;
  ctx: PBN_CTX): TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_key2buf_procname);
end;

 {introduced 1.1.0}
function  ERR_EC_KEY_oct2key(key: PEC_KEY; const buf: PByte; len: TIdC_SIZET; ctx: PBN_CTX): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_oct2key_procname);
end;

 {introduced 1.1.0}
function  ERR_EC_KEY_oct2priv(key: PEC_KEY; const buf: PByte; len: TIdC_SIZET): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_oct2priv_procname);
end;

 {introduced 1.1.0}
function  ERR_EC_KEY_priv2oct(const key: PEC_KEY; buf: PByte; len: TIdC_SIZET): TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_priv2oct_procname);
end;

 {introduced 1.1.0}
function  ERR_EC_KEY_priv2buf(const eckey: PEC_KEY; buf: PPByte): TIdC_SIZET; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_priv2buf_procname);
end;

 {introduced 1.1.0}

function  ERR_d2i_ECPrivateKey(key: PPEC_KEY; const in_: PPByte; len: TIdC_LONG): PEC_KEY; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ECPrivateKey_procname);
end;


function  ERR_i2d_ECPrivateKey(key: PEC_KEY; out_: PPByte): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ECPrivateKey_procname);
end;


function  ERR_o2i_ECPublicKey(key: PPEC_KEY; const in_: PPByte; len: TIdC_LONG): PEC_KEY; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(o2i_ECPublicKey_procname);
end;


function  ERR_i2o_ECPublicKey(const key: PEC_KEY; out_: PPByte): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2o_ECPublicKey_procname);
end;



function  ERR_ECParameters_print(bp: PBIO; const key: PEC_KEY): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECParameters_print_procname);
end;


function  ERR_EC_KEY_print(bp: PBIO; const key: PEC_KEY; off: TIdC_INT): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_print_procname);
end;

function  ERR_EC_KEY_OpenSSL: PEC_KEY_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_OpenSSL_procname);
end;

 {introduced 1.1.0}
function  ERR_EC_KEY_get_default_method: PEC_KEY_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_get_default_method_procname);
end;

 {introduced 1.1.0}
procedure  ERR_EC_KEY_set_default_method(const meth: PEC_KEY_METHOD); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_set_default_method_procname);
end;

 {introduced 1.1.0}
function  ERR_EC_KEY_get_method(const key: PEC_KEY): PEC_KEY_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_get_method_procname);
end;

 {introduced 1.1.0}
function  ERR_EC_KEY_set_method(key: PEC_KEY; const meth: PEC_KEY_METHOD): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_set_method_procname);
end;

 {introduced 1.1.0}
function  ERR_EC_KEY_new_method(engine: PENGINE): PEC_KEY; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_new_method_procname);
end;

 {introduced 1.1.0}

function  ERR_ECDH_KDF_X9_62(out_: PByte; outlen: TIdC_SIZET; const Z: PByte; Zlen: TIdC_SIZET;
  const sinfo: PByte; sinfolen: TIdC_SIZET; const md: PEVP_MD): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDH_KDF_X9_62_procname);
end;


function  ERR_ECDH_compute_key(out_: Pointer; oulen: TIdC_SIZET; const pub_key: PEC_POINT;
  const ecdh: PEC_KEY; kdf: ECDH_compute_key_KDF): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDH_compute_key_procname);
end;



function  ERR_ECDSA_SIG_new: PECDSA_SIG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_SIG_new_procname);
end;


procedure  ERR_ECDSA_SIG_free(sig: PECDSA_SIG); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_SIG_free_procname);
end;


function  ERR_i2d_ECDSA_SIG(const sig: PECDSA_SIG; pp: PPByte): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ECDSA_SIG_procname);
end;


function  ERR_d2i_ECDSA_SIG(sig: PPECDSA_SIG; const pp: PPByte; len: TIdC_LONG): PECDSA_SIG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ECDSA_SIG_procname);
end;


procedure  ERR_ECDSA_SIG_get0(const sig: PECDSA_SIG; const pr: PPBIGNUM; const ps: PPBIGNUM); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_SIG_get0_procname);
end;

 {introduced 1.1.0}
function  ERR_ECDSA_SIG_get0_r(const sig: PECDSA_SIG): PBIGNUM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_SIG_get0_r_procname);
end;

 {introduced 1.1.0}
function  ERR_ECDSA_SIG_get0_s(const sig: PECDSA_SIG): PBIGNUM; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_SIG_get0_s_procname);
end;

 {introduced 1.1.0}
function  ERR_ECDSA_SIG_set0(sig: PECDSA_SIG; r: PBIGNUM; s: PBIGNUM): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_SIG_set0_procname);
end;

 {introduced 1.1.0}
function  ERR_ECDSA_do_sign(const dgst: PByte; dgst_len: TIdC_INT; eckey: PEC_KEY): PECDSA_SIG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_do_sign_procname);
end;


function  ERR_ECDSA_do_sign_ex(const dgst: PByte; dgst_len: TIdC_INT; const kinv: PBIGNUM;
  const rp: PBIGNUM; eckey: PEC_KEY): PECDSA_SIG; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_do_sign_ex_procname);
end;


function  ERR_ECDSA_do_verify(const dgst: PByte; dgst_len: TIdC_INT; const sig: PECDSA_SIG;
  eckey: PEC_KEY): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_do_verify_procname);
end;


function  ERR_ECDSA_sign_setup(eckey: PEC_KEY; ctx: PBN_CTX; kiv: PPBIGNUM; rp: PPBIGNUM): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_sign_setup_procname);
end;


function  ERR_ECDSA_sign(type_: TIdC_INT; const dgst: PByte; dgstlen: TIdC_INT; sig: PByte;
  siglen: PIdC_UINT; eckey: PEC_KEY): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_sign_procname);
end;


function  ERR_ECDSA_sign_ex(type_: TIdC_INT; const dgst: PByte; dgstlen: TIdC_INT; sig: PByte;
  siglen: PIdC_UINT; const kinv: PBIGNUM; const rp: PBIGNUM; eckey: PEC_KEY): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_sign_ex_procname);
end;


function  ERR_ECDSA_verify(type_: TIdC_INT; const dgst: PByte; dgstlen: TIdC_INT; const sig: PByte;
  siglen: TIdC_INT; eckey: PEC_KEY): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_verify_procname);
end;


function  ERR_ECDSA_size(const eckey: PEC_KEY): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_size_procname);
end;



function  ERR_EC_KEY_METHOD_new(const meth: PEC_KEY_METHOD): PEC_KEY_METHOD; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_METHOD_new_procname);
end;

 {introduced 1.1.0}
procedure  ERR_EC_KEY_METHOD_free(meth: PEC_KEY_METHOD); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_METHOD_free_procname);
end;

 {introduced 1.1.0}
procedure  ERR_EC_KEY_METHOD_set_init(meth: PEC_KEY_METHOD; init: EC_KEY_METHOD_init_init; finish: EC_KEY_METHOD_init_finish; _copy: EC_KEY_METHOD_init_copy; set_group: EC_KEY_METHOD_init_set_group;
  set_private: EC_KEY_METHOD_init_set_private; set_public: EC_KEY_METHOD_init_set_public); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_METHOD_set_init_procname);
end;

 {introduced 1.1.0}
procedure  ERR_EC_KEY_METHOD_set_keygen(meth: PEC_KEY_METHOD; keygen: EC_KEY_METHOD_keygen_keygen); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_METHOD_set_keygen_procname);
end;

 {introduced 1.1.0}
procedure  ERR_EC_KEY_METHOD_set_compute_key(meth: PEC_KEY_METHOD; ckey: EC_KEY_METHOD_compute_key_ckey); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_METHOD_set_compute_key_procname);
end;

 {introduced 1.1.0}
procedure  ERR_EC_KEY_METHOD_set_sign(meth: PEC_KEY_METHOD; sign: EC_KEY_METHOD_sign_sign;
  sign_setup: EC_KEY_METHOD_sign_sign_setup; sign_sig: EC_KEY_METHOD_sign_sign_sig); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_METHOD_set_sign_procname);
end;

 {introduced 1.1.0}
procedure  ERR_EC_KEY_METHOD_set_verify(meth: PEC_KEY_METHOD; verify: EC_KEY_METHOD_verify_verify;
  verify_sig: EC_KEY_METHOD_verify_verify_sig); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_METHOD_set_verify_procname);
end;

 {introduced 1.1.0}

procedure  ERR_EC_KEY_METHOD_get_init(const meth: PEC_KEY_METHOD; pinit: PEC_KEY_METHOD_init_init;
  pfinish: PEC_KEY_METHOD_init_finish; p_copy: PEC_KEY_METHOD_init_copy; pset_group: PEC_KEY_METHOD_init_set_group;
  pset_private: PEC_KEY_METHOD_init_set_private; pset_public: PEC_KEY_METHOD_init_set_public); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_METHOD_get_init_procname);
end;

 {introduced 1.1.0}
procedure  ERR_EC_KEY_METHOD_get_keygen(const meth: PEC_KEY_METHOD; pkeygen: PEC_KEY_METHOD_keygen_keygen); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_METHOD_get_keygen_procname);
end;

 {introduced 1.1.0}
procedure  ERR_EC_KEY_METHOD_get_compute_key(const meth: PEC_KEY_METHOD; pck: PEC_KEY_METHOD_compute_key_ckey); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_METHOD_get_compute_key_procname);
end;

 {introduced 1.1.0}
procedure  ERR_EC_KEY_METHOD_get_sign(const meth: PEC_KEY_METHOD; psign: PEC_KEY_METHOD_sign_sign;
  psign_setup: PEC_KEY_METHOD_sign_sign_setup; psign_sig: PEC_KEY_METHOD_sign_sign_sig); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_METHOD_get_sign_procname);
end;

 {introduced 1.1.0}
procedure  ERR_EC_KEY_METHOD_get_verify(const meth: PEC_KEY_METHOD; pverify: PEC_KEY_METHOD_verify_verify;
  pverify_sig: PEC_KEY_METHOD_verify_verify_sig); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_METHOD_get_verify_procname);
end;

 {introduced 1.1.0}

  {$I TaurusTLSNoRetValOn.inc}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
  EC_GFp_simple_method := LoadLibFunction(ADllHandle, EC_GFp_simple_method_procname);
  FuncLoadError := not assigned(EC_GFp_simple_method);
  if FuncLoadError then
  begin
    {$if not defined(EC_GFp_simple_method_allownil)}
    EC_GFp_simple_method := ERR_EC_GFp_simple_method;
    {$ifend}
    {$if declared(EC_GFp_simple_method_introduced)}
    if LibVersion < EC_GFp_simple_method_introduced then
    begin
      {$if declared(FC_EC_GFp_simple_method)}
      EC_GFp_simple_method := FC_EC_GFp_simple_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GFp_simple_method_removed)}
    if EC_GFp_simple_method_removed <= LibVersion then
    begin
      {$if declared(_EC_GFp_simple_method)}
      EC_GFp_simple_method := _EC_GFp_simple_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GFp_simple_method_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GFp_simple_method');
    {$ifend}
  end;


  EC_GFp_mont_method := LoadLibFunction(ADllHandle, EC_GFp_mont_method_procname);
  FuncLoadError := not assigned(EC_GFp_mont_method);
  if FuncLoadError then
  begin
    {$if not defined(EC_GFp_mont_method_allownil)}
    EC_GFp_mont_method := ERR_EC_GFp_mont_method;
    {$ifend}
    {$if declared(EC_GFp_mont_method_introduced)}
    if LibVersion < EC_GFp_mont_method_introduced then
    begin
      {$if declared(FC_EC_GFp_mont_method)}
      EC_GFp_mont_method := FC_EC_GFp_mont_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GFp_mont_method_removed)}
    if EC_GFp_mont_method_removed <= LibVersion then
    begin
      {$if declared(_EC_GFp_mont_method)}
      EC_GFp_mont_method := _EC_GFp_mont_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GFp_mont_method_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GFp_mont_method');
    {$ifend}
  end;


  EC_GFp_nist_method := LoadLibFunction(ADllHandle, EC_GFp_nist_method_procname);
  FuncLoadError := not assigned(EC_GFp_nist_method);
  if FuncLoadError then
  begin
    {$if not defined(EC_GFp_nist_method_allownil)}
    EC_GFp_nist_method := ERR_EC_GFp_nist_method;
    {$ifend}
    {$if declared(EC_GFp_nist_method_introduced)}
    if LibVersion < EC_GFp_nist_method_introduced then
    begin
      {$if declared(FC_EC_GFp_nist_method)}
      EC_GFp_nist_method := FC_EC_GFp_nist_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GFp_nist_method_removed)}
    if EC_GFp_nist_method_removed <= LibVersion then
    begin
      {$if declared(_EC_GFp_nist_method)}
      EC_GFp_nist_method := _EC_GFp_nist_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GFp_nist_method_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GFp_nist_method');
    {$ifend}
  end;

   {$IFDEF OPENSSL_NO_EC_NISTP_64_GCC_128}
  EC_GFp_nistp224_method := LoadLibFunction(ADllHandle, EC_GFp_nistp224_method_procname);
  FuncLoadError := not assigned(EC_GFp_nistp224_method);
  if FuncLoadError then
  begin
    {$if not defined(EC_GFp_nistp224_method_allownil)}
    EC_GFp_nistp224_method := ERR_EC_GFp_nistp224_method;
    {$ifend}
    {$if declared(EC_GFp_nistp224_method_introduced)}
    if LibVersion < EC_GFp_nistp224_method_introduced then
    begin
      {$if declared(FC_EC_GFp_nistp224_method)}
      EC_GFp_nistp224_method := FC_EC_GFp_nistp224_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GFp_nistp224_method_removed)}
    if EC_GFp_nistp224_method_removed <= LibVersion then
    begin
      {$if declared(_EC_GFp_nistp224_method)}
      EC_GFp_nistp224_method := _EC_GFp_nistp224_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GFp_nistp224_method_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GFp_nistp224_method');
    {$ifend}
  end;

 
  EC_GFp_nistp256_method := LoadLibFunction(ADllHandle, EC_GFp_nistp256_method_procname);
  FuncLoadError := not assigned(EC_GFp_nistp256_method);
  if FuncLoadError then
  begin
    {$if not defined(EC_GFp_nistp256_method_allownil)}
    EC_GFp_nistp256_method := ERR_EC_GFp_nistp256_method;
    {$ifend}
    {$if declared(EC_GFp_nistp256_method_introduced)}
    if LibVersion < EC_GFp_nistp256_method_introduced then
    begin
      {$if declared(FC_EC_GFp_nistp256_method)}
      EC_GFp_nistp256_method := FC_EC_GFp_nistp256_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GFp_nistp256_method_removed)}
    if EC_GFp_nistp256_method_removed <= LibVersion then
    begin
      {$if declared(_EC_GFp_nistp256_method)}
      EC_GFp_nistp256_method := _EC_GFp_nistp256_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GFp_nistp256_method_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GFp_nistp256_method');
    {$ifend}
  end;

 
  EC_GFp_nistp521_method := LoadLibFunction(ADllHandle, EC_GFp_nistp521_method_procname);
  FuncLoadError := not assigned(EC_GFp_nistp521_method);
  if FuncLoadError then
  begin
    {$if not defined(EC_GFp_nistp521_method_allownil)}
    EC_GFp_nistp521_method := ERR_EC_GFp_nistp521_method;
    {$ifend}
    {$if declared(EC_GFp_nistp521_method_introduced)}
    if LibVersion < EC_GFp_nistp521_method_introduced then
    begin
      {$if declared(FC_EC_GFp_nistp521_method)}
      EC_GFp_nistp521_method := FC_EC_GFp_nistp521_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GFp_nistp521_method_removed)}
    if EC_GFp_nistp521_method_removed <= LibVersion then
    begin
      {$if declared(_EC_GFp_nistp521_method)}
      EC_GFp_nistp521_method := _EC_GFp_nistp521_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GFp_nistp521_method_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GFp_nistp521_method');
    {$ifend}
  end;
  {$ENDIF}

  EC_GF2m_simple_method := LoadLibFunction(ADllHandle, EC_GF2m_simple_method_procname);
  FuncLoadError := not assigned(EC_GF2m_simple_method);
  if FuncLoadError then
  begin
    {$if not defined(EC_GF2m_simple_method_allownil)}
    EC_GF2m_simple_method := ERR_EC_GF2m_simple_method;
    {$ifend}
    {$if declared(EC_GF2m_simple_method_introduced)}
    if LibVersion < EC_GF2m_simple_method_introduced then
    begin
      {$if declared(FC_EC_GF2m_simple_method)}
      EC_GF2m_simple_method := FC_EC_GF2m_simple_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GF2m_simple_method_removed)}
    if EC_GF2m_simple_method_removed <= LibVersion then
    begin
      {$if declared(_EC_GF2m_simple_method)}
      EC_GF2m_simple_method := _EC_GF2m_simple_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GF2m_simple_method_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GF2m_simple_method');
    {$ifend}
  end;


  EC_GROUP_new := LoadLibFunction(ADllHandle, EC_GROUP_new_procname);
  FuncLoadError := not assigned(EC_GROUP_new);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_new_allownil)}
    EC_GROUP_new := ERR_EC_GROUP_new;
    {$ifend}
    {$if declared(EC_GROUP_new_introduced)}
    if LibVersion < EC_GROUP_new_introduced then
    begin
      {$if declared(FC_EC_GROUP_new)}
      EC_GROUP_new := FC_EC_GROUP_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_new_removed)}
    if EC_GROUP_new_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_new)}
      EC_GROUP_new := _EC_GROUP_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_new_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_new');
    {$ifend}
  end;


  EC_GROUP_free := LoadLibFunction(ADllHandle, EC_GROUP_free_procname);
  FuncLoadError := not assigned(EC_GROUP_free);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_free_allownil)}
    EC_GROUP_free := ERR_EC_GROUP_free;
    {$ifend}
    {$if declared(EC_GROUP_free_introduced)}
    if LibVersion < EC_GROUP_free_introduced then
    begin
      {$if declared(FC_EC_GROUP_free)}
      EC_GROUP_free := FC_EC_GROUP_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_free_removed)}
    if EC_GROUP_free_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_free)}
      EC_GROUP_free := _EC_GROUP_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_free_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_free');
    {$ifend}
  end;


  EC_GROUP_clear_free := LoadLibFunction(ADllHandle, EC_GROUP_clear_free_procname);
  FuncLoadError := not assigned(EC_GROUP_clear_free);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_clear_free_allownil)}
    EC_GROUP_clear_free := ERR_EC_GROUP_clear_free;
    {$ifend}
    {$if declared(EC_GROUP_clear_free_introduced)}
    if LibVersion < EC_GROUP_clear_free_introduced then
    begin
      {$if declared(FC_EC_GROUP_clear_free)}
      EC_GROUP_clear_free := FC_EC_GROUP_clear_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_clear_free_removed)}
    if EC_GROUP_clear_free_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_clear_free)}
      EC_GROUP_clear_free := _EC_GROUP_clear_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_clear_free_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_clear_free');
    {$ifend}
  end;


  EC_GROUP_copy := LoadLibFunction(ADllHandle, EC_GROUP_copy_procname);
  FuncLoadError := not assigned(EC_GROUP_copy);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_copy_allownil)}
    EC_GROUP_copy := ERR_EC_GROUP_copy;
    {$ifend}
    {$if declared(EC_GROUP_copy_introduced)}
    if LibVersion < EC_GROUP_copy_introduced then
    begin
      {$if declared(FC_EC_GROUP_copy)}
      EC_GROUP_copy := FC_EC_GROUP_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_copy_removed)}
    if EC_GROUP_copy_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_copy)}
      EC_GROUP_copy := _EC_GROUP_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_copy_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_copy');
    {$ifend}
  end;


  EC_GROUP_dup := LoadLibFunction(ADllHandle, EC_GROUP_dup_procname);
  FuncLoadError := not assigned(EC_GROUP_dup);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_dup_allownil)}
    EC_GROUP_dup := ERR_EC_GROUP_dup;
    {$ifend}
    {$if declared(EC_GROUP_dup_introduced)}
    if LibVersion < EC_GROUP_dup_introduced then
    begin
      {$if declared(FC_EC_GROUP_dup)}
      EC_GROUP_dup := FC_EC_GROUP_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_dup_removed)}
    if EC_GROUP_dup_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_dup)}
      EC_GROUP_dup := _EC_GROUP_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_dup');
    {$ifend}
  end;


  EC_GROUP_method_of := LoadLibFunction(ADllHandle, EC_GROUP_method_of_procname);
  FuncLoadError := not assigned(EC_GROUP_method_of);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_method_of_allownil)}
    EC_GROUP_method_of := ERR_EC_GROUP_method_of;
    {$ifend}
    {$if declared(EC_GROUP_method_of_introduced)}
    if LibVersion < EC_GROUP_method_of_introduced then
    begin
      {$if declared(FC_EC_GROUP_method_of)}
      EC_GROUP_method_of := FC_EC_GROUP_method_of;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_method_of_removed)}
    if EC_GROUP_method_of_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_method_of)}
      EC_GROUP_method_of := _EC_GROUP_method_of;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_method_of_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_method_of');
    {$ifend}
  end;


  EC_METHOD_get_field_type := LoadLibFunction(ADllHandle, EC_METHOD_get_field_type_procname);
  FuncLoadError := not assigned(EC_METHOD_get_field_type);
  if FuncLoadError then
  begin
    {$if not defined(EC_METHOD_get_field_type_allownil)}
    EC_METHOD_get_field_type := ERR_EC_METHOD_get_field_type;
    {$ifend}
    {$if declared(EC_METHOD_get_field_type_introduced)}
    if LibVersion < EC_METHOD_get_field_type_introduced then
    begin
      {$if declared(FC_EC_METHOD_get_field_type)}
      EC_METHOD_get_field_type := FC_EC_METHOD_get_field_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_METHOD_get_field_type_removed)}
    if EC_METHOD_get_field_type_removed <= LibVersion then
    begin
      {$if declared(_EC_METHOD_get_field_type)}
      EC_METHOD_get_field_type := _EC_METHOD_get_field_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_METHOD_get_field_type_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_METHOD_get_field_type');
    {$ifend}
  end;


  EC_GROUP_set_generator := LoadLibFunction(ADllHandle, EC_GROUP_set_generator_procname);
  FuncLoadError := not assigned(EC_GROUP_set_generator);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_set_generator_allownil)}
    EC_GROUP_set_generator := ERR_EC_GROUP_set_generator;
    {$ifend}
    {$if declared(EC_GROUP_set_generator_introduced)}
    if LibVersion < EC_GROUP_set_generator_introduced then
    begin
      {$if declared(FC_EC_GROUP_set_generator)}
      EC_GROUP_set_generator := FC_EC_GROUP_set_generator;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_set_generator_removed)}
    if EC_GROUP_set_generator_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_set_generator)}
      EC_GROUP_set_generator := _EC_GROUP_set_generator;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_set_generator_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_set_generator');
    {$ifend}
  end;


  EC_GROUP_get0_generator := LoadLibFunction(ADllHandle, EC_GROUP_get0_generator_procname);
  FuncLoadError := not assigned(EC_GROUP_get0_generator);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_get0_generator_allownil)}
    EC_GROUP_get0_generator := ERR_EC_GROUP_get0_generator;
    {$ifend}
    {$if declared(EC_GROUP_get0_generator_introduced)}
    if LibVersion < EC_GROUP_get0_generator_introduced then
    begin
      {$if declared(FC_EC_GROUP_get0_generator)}
      EC_GROUP_get0_generator := FC_EC_GROUP_get0_generator;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_get0_generator_removed)}
    if EC_GROUP_get0_generator_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_get0_generator)}
      EC_GROUP_get0_generator := _EC_GROUP_get0_generator;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_get0_generator_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_get0_generator');
    {$ifend}
  end;


  EC_GROUP_get_mont_data := LoadLibFunction(ADllHandle, EC_GROUP_get_mont_data_procname);
  FuncLoadError := not assigned(EC_GROUP_get_mont_data);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_get_mont_data_allownil)}
    EC_GROUP_get_mont_data := ERR_EC_GROUP_get_mont_data;
    {$ifend}
    {$if declared(EC_GROUP_get_mont_data_introduced)}
    if LibVersion < EC_GROUP_get_mont_data_introduced then
    begin
      {$if declared(FC_EC_GROUP_get_mont_data)}
      EC_GROUP_get_mont_data := FC_EC_GROUP_get_mont_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_get_mont_data_removed)}
    if EC_GROUP_get_mont_data_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_get_mont_data)}
      EC_GROUP_get_mont_data := _EC_GROUP_get_mont_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_get_mont_data_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_get_mont_data');
    {$ifend}
  end;


  EC_GROUP_get_order := LoadLibFunction(ADllHandle, EC_GROUP_get_order_procname);
  FuncLoadError := not assigned(EC_GROUP_get_order);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_get_order_allownil)}
    EC_GROUP_get_order := ERR_EC_GROUP_get_order;
    {$ifend}
    {$if declared(EC_GROUP_get_order_introduced)}
    if LibVersion < EC_GROUP_get_order_introduced then
    begin
      {$if declared(FC_EC_GROUP_get_order)}
      EC_GROUP_get_order := FC_EC_GROUP_get_order;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_get_order_removed)}
    if EC_GROUP_get_order_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_get_order)}
      EC_GROUP_get_order := _EC_GROUP_get_order;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_get_order_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_get_order');
    {$ifend}
  end;


  EC_GROUP_get0_order := LoadLibFunction(ADllHandle, EC_GROUP_get0_order_procname);
  FuncLoadError := not assigned(EC_GROUP_get0_order);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_get0_order_allownil)}
    EC_GROUP_get0_order := ERR_EC_GROUP_get0_order;
    {$ifend}
    {$if declared(EC_GROUP_get0_order_introduced)}
    if LibVersion < EC_GROUP_get0_order_introduced then
    begin
      {$if declared(FC_EC_GROUP_get0_order)}
      EC_GROUP_get0_order := FC_EC_GROUP_get0_order;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_get0_order_removed)}
    if EC_GROUP_get0_order_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_get0_order)}
      EC_GROUP_get0_order := _EC_GROUP_get0_order;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_get0_order_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_get0_order');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_GROUP_order_bits := LoadLibFunction(ADllHandle, EC_GROUP_order_bits_procname);
  FuncLoadError := not assigned(EC_GROUP_order_bits);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_order_bits_allownil)}
    EC_GROUP_order_bits := ERR_EC_GROUP_order_bits;
    {$ifend}
    {$if declared(EC_GROUP_order_bits_introduced)}
    if LibVersion < EC_GROUP_order_bits_introduced then
    begin
      {$if declared(FC_EC_GROUP_order_bits)}
      EC_GROUP_order_bits := FC_EC_GROUP_order_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_order_bits_removed)}
    if EC_GROUP_order_bits_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_order_bits)}
      EC_GROUP_order_bits := _EC_GROUP_order_bits;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_order_bits_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_order_bits');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_GROUP_get_cofactor := LoadLibFunction(ADllHandle, EC_GROUP_get_cofactor_procname);
  FuncLoadError := not assigned(EC_GROUP_get_cofactor);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_get_cofactor_allownil)}
    EC_GROUP_get_cofactor := ERR_EC_GROUP_get_cofactor;
    {$ifend}
    {$if declared(EC_GROUP_get_cofactor_introduced)}
    if LibVersion < EC_GROUP_get_cofactor_introduced then
    begin
      {$if declared(FC_EC_GROUP_get_cofactor)}
      EC_GROUP_get_cofactor := FC_EC_GROUP_get_cofactor;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_get_cofactor_removed)}
    if EC_GROUP_get_cofactor_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_get_cofactor)}
      EC_GROUP_get_cofactor := _EC_GROUP_get_cofactor;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_get_cofactor_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_get_cofactor');
    {$ifend}
  end;


  EC_GROUP_get0_cofactor := LoadLibFunction(ADllHandle, EC_GROUP_get0_cofactor_procname);
  FuncLoadError := not assigned(EC_GROUP_get0_cofactor);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_get0_cofactor_allownil)}
    EC_GROUP_get0_cofactor := ERR_EC_GROUP_get0_cofactor;
    {$ifend}
    {$if declared(EC_GROUP_get0_cofactor_introduced)}
    if LibVersion < EC_GROUP_get0_cofactor_introduced then
    begin
      {$if declared(FC_EC_GROUP_get0_cofactor)}
      EC_GROUP_get0_cofactor := FC_EC_GROUP_get0_cofactor;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_get0_cofactor_removed)}
    if EC_GROUP_get0_cofactor_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_get0_cofactor)}
      EC_GROUP_get0_cofactor := _EC_GROUP_get0_cofactor;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_get0_cofactor_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_get0_cofactor');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_GROUP_set_curve_name := LoadLibFunction(ADllHandle, EC_GROUP_set_curve_name_procname);
  FuncLoadError := not assigned(EC_GROUP_set_curve_name);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_set_curve_name_allownil)}
    EC_GROUP_set_curve_name := ERR_EC_GROUP_set_curve_name;
    {$ifend}
    {$if declared(EC_GROUP_set_curve_name_introduced)}
    if LibVersion < EC_GROUP_set_curve_name_introduced then
    begin
      {$if declared(FC_EC_GROUP_set_curve_name)}
      EC_GROUP_set_curve_name := FC_EC_GROUP_set_curve_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_set_curve_name_removed)}
    if EC_GROUP_set_curve_name_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_set_curve_name)}
      EC_GROUP_set_curve_name := _EC_GROUP_set_curve_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_set_curve_name_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_set_curve_name');
    {$ifend}
  end;


  EC_GROUP_get_curve_name := LoadLibFunction(ADllHandle, EC_GROUP_get_curve_name_procname);
  FuncLoadError := not assigned(EC_GROUP_get_curve_name);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_get_curve_name_allownil)}
    EC_GROUP_get_curve_name := ERR_EC_GROUP_get_curve_name;
    {$ifend}
    {$if declared(EC_GROUP_get_curve_name_introduced)}
    if LibVersion < EC_GROUP_get_curve_name_introduced then
    begin
      {$if declared(FC_EC_GROUP_get_curve_name)}
      EC_GROUP_get_curve_name := FC_EC_GROUP_get_curve_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_get_curve_name_removed)}
    if EC_GROUP_get_curve_name_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_get_curve_name)}
      EC_GROUP_get_curve_name := _EC_GROUP_get_curve_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_get_curve_name_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_get_curve_name');
    {$ifend}
  end;


  EC_GROUP_set_asn1_flag := LoadLibFunction(ADllHandle, EC_GROUP_set_asn1_flag_procname);
  FuncLoadError := not assigned(EC_GROUP_set_asn1_flag);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_set_asn1_flag_allownil)}
    EC_GROUP_set_asn1_flag := ERR_EC_GROUP_set_asn1_flag;
    {$ifend}
    {$if declared(EC_GROUP_set_asn1_flag_introduced)}
    if LibVersion < EC_GROUP_set_asn1_flag_introduced then
    begin
      {$if declared(FC_EC_GROUP_set_asn1_flag)}
      EC_GROUP_set_asn1_flag := FC_EC_GROUP_set_asn1_flag;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_set_asn1_flag_removed)}
    if EC_GROUP_set_asn1_flag_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_set_asn1_flag)}
      EC_GROUP_set_asn1_flag := _EC_GROUP_set_asn1_flag;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_set_asn1_flag_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_set_asn1_flag');
    {$ifend}
  end;


  EC_GROUP_get_asn1_flag := LoadLibFunction(ADllHandle, EC_GROUP_get_asn1_flag_procname);
  FuncLoadError := not assigned(EC_GROUP_get_asn1_flag);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_get_asn1_flag_allownil)}
    EC_GROUP_get_asn1_flag := ERR_EC_GROUP_get_asn1_flag;
    {$ifend}
    {$if declared(EC_GROUP_get_asn1_flag_introduced)}
    if LibVersion < EC_GROUP_get_asn1_flag_introduced then
    begin
      {$if declared(FC_EC_GROUP_get_asn1_flag)}
      EC_GROUP_get_asn1_flag := FC_EC_GROUP_get_asn1_flag;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_get_asn1_flag_removed)}
    if EC_GROUP_get_asn1_flag_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_get_asn1_flag)}
      EC_GROUP_get_asn1_flag := _EC_GROUP_get_asn1_flag;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_get_asn1_flag_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_get_asn1_flag');
    {$ifend}
  end;


  EC_GROUP_set_point_conversion_form := LoadLibFunction(ADllHandle, EC_GROUP_set_point_conversion_form_procname);
  FuncLoadError := not assigned(EC_GROUP_set_point_conversion_form);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_set_point_conversion_form_allownil)}
    EC_GROUP_set_point_conversion_form := ERR_EC_GROUP_set_point_conversion_form;
    {$ifend}
    {$if declared(EC_GROUP_set_point_conversion_form_introduced)}
    if LibVersion < EC_GROUP_set_point_conversion_form_introduced then
    begin
      {$if declared(FC_EC_GROUP_set_point_conversion_form)}
      EC_GROUP_set_point_conversion_form := FC_EC_GROUP_set_point_conversion_form;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_set_point_conversion_form_removed)}
    if EC_GROUP_set_point_conversion_form_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_set_point_conversion_form)}
      EC_GROUP_set_point_conversion_form := _EC_GROUP_set_point_conversion_form;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_set_point_conversion_form_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_set_point_conversion_form');
    {$ifend}
  end;


  EC_GROUP_get_point_conversion_form := LoadLibFunction(ADllHandle, EC_GROUP_get_point_conversion_form_procname);
  FuncLoadError := not assigned(EC_GROUP_get_point_conversion_form);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_get_point_conversion_form_allownil)}
    EC_GROUP_get_point_conversion_form := ERR_EC_GROUP_get_point_conversion_form;
    {$ifend}
    {$if declared(EC_GROUP_get_point_conversion_form_introduced)}
    if LibVersion < EC_GROUP_get_point_conversion_form_introduced then
    begin
      {$if declared(FC_EC_GROUP_get_point_conversion_form)}
      EC_GROUP_get_point_conversion_form := FC_EC_GROUP_get_point_conversion_form;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_get_point_conversion_form_removed)}
    if EC_GROUP_get_point_conversion_form_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_get_point_conversion_form)}
      EC_GROUP_get_point_conversion_form := _EC_GROUP_get_point_conversion_form;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_get_point_conversion_form_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_get_point_conversion_form');
    {$ifend}
  end;


  EC_GROUP_get0_seed := LoadLibFunction(ADllHandle, EC_GROUP_get0_seed_procname);
  FuncLoadError := not assigned(EC_GROUP_get0_seed);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_get0_seed_allownil)}
    EC_GROUP_get0_seed := ERR_EC_GROUP_get0_seed;
    {$ifend}
    {$if declared(EC_GROUP_get0_seed_introduced)}
    if LibVersion < EC_GROUP_get0_seed_introduced then
    begin
      {$if declared(FC_EC_GROUP_get0_seed)}
      EC_GROUP_get0_seed := FC_EC_GROUP_get0_seed;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_get0_seed_removed)}
    if EC_GROUP_get0_seed_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_get0_seed)}
      EC_GROUP_get0_seed := _EC_GROUP_get0_seed;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_get0_seed_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_get0_seed');
    {$ifend}
  end;


  EC_GROUP_get_seed_len := LoadLibFunction(ADllHandle, EC_GROUP_get_seed_len_procname);
  FuncLoadError := not assigned(EC_GROUP_get_seed_len);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_get_seed_len_allownil)}
    EC_GROUP_get_seed_len := ERR_EC_GROUP_get_seed_len;
    {$ifend}
    {$if declared(EC_GROUP_get_seed_len_introduced)}
    if LibVersion < EC_GROUP_get_seed_len_introduced then
    begin
      {$if declared(FC_EC_GROUP_get_seed_len)}
      EC_GROUP_get_seed_len := FC_EC_GROUP_get_seed_len;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_get_seed_len_removed)}
    if EC_GROUP_get_seed_len_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_get_seed_len)}
      EC_GROUP_get_seed_len := _EC_GROUP_get_seed_len;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_get_seed_len_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_get_seed_len');
    {$ifend}
  end;


  EC_GROUP_set_seed := LoadLibFunction(ADllHandle, EC_GROUP_set_seed_procname);
  FuncLoadError := not assigned(EC_GROUP_set_seed);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_set_seed_allownil)}
    EC_GROUP_set_seed := ERR_EC_GROUP_set_seed;
    {$ifend}
    {$if declared(EC_GROUP_set_seed_introduced)}
    if LibVersion < EC_GROUP_set_seed_introduced then
    begin
      {$if declared(FC_EC_GROUP_set_seed)}
      EC_GROUP_set_seed := FC_EC_GROUP_set_seed;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_set_seed_removed)}
    if EC_GROUP_set_seed_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_set_seed)}
      EC_GROUP_set_seed := _EC_GROUP_set_seed;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_set_seed_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_set_seed');
    {$ifend}
  end;


  EC_GROUP_set_curve := LoadLibFunction(ADllHandle, EC_GROUP_set_curve_procname);
  FuncLoadError := not assigned(EC_GROUP_set_curve);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_set_curve_allownil)}
    EC_GROUP_set_curve := ERR_EC_GROUP_set_curve;
    {$ifend}
    {$if declared(EC_GROUP_set_curve_introduced)}
    if LibVersion < EC_GROUP_set_curve_introduced then
    begin
      {$if declared(FC_EC_GROUP_set_curve)}
      EC_GROUP_set_curve := FC_EC_GROUP_set_curve;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_set_curve_removed)}
    if EC_GROUP_set_curve_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_set_curve)}
      EC_GROUP_set_curve := _EC_GROUP_set_curve;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_set_curve_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_set_curve');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_GROUP_get_curve := LoadLibFunction(ADllHandle, EC_GROUP_get_curve_procname);
  FuncLoadError := not assigned(EC_GROUP_get_curve);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_get_curve_allownil)}
    EC_GROUP_get_curve := ERR_EC_GROUP_get_curve;
    {$ifend}
    {$if declared(EC_GROUP_get_curve_introduced)}
    if LibVersion < EC_GROUP_get_curve_introduced then
    begin
      {$if declared(FC_EC_GROUP_get_curve)}
      EC_GROUP_get_curve := FC_EC_GROUP_get_curve;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_get_curve_removed)}
    if EC_GROUP_get_curve_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_get_curve)}
      EC_GROUP_get_curve := _EC_GROUP_get_curve;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_get_curve_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_get_curve');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_GROUP_set_curve_GFp := LoadLibFunction(ADllHandle, EC_GROUP_set_curve_GFp_procname);
  FuncLoadError := not assigned(EC_GROUP_set_curve_GFp);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_set_curve_GFp_allownil)}
    EC_GROUP_set_curve_GFp := ERR_EC_GROUP_set_curve_GFp;
    {$ifend}
    {$if declared(EC_GROUP_set_curve_GFp_introduced)}
    if LibVersion < EC_GROUP_set_curve_GFp_introduced then
    begin
      {$if declared(FC_EC_GROUP_set_curve_GFp)}
      EC_GROUP_set_curve_GFp := FC_EC_GROUP_set_curve_GFp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_set_curve_GFp_removed)}
    if EC_GROUP_set_curve_GFp_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_set_curve_GFp)}
      EC_GROUP_set_curve_GFp := _EC_GROUP_set_curve_GFp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_set_curve_GFp_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_set_curve_GFp');
    {$ifend}
  end;


  EC_GROUP_get_curve_GFp := LoadLibFunction(ADllHandle, EC_GROUP_get_curve_GFp_procname);
  FuncLoadError := not assigned(EC_GROUP_get_curve_GFp);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_get_curve_GFp_allownil)}
    EC_GROUP_get_curve_GFp := ERR_EC_GROUP_get_curve_GFp;
    {$ifend}
    {$if declared(EC_GROUP_get_curve_GFp_introduced)}
    if LibVersion < EC_GROUP_get_curve_GFp_introduced then
    begin
      {$if declared(FC_EC_GROUP_get_curve_GFp)}
      EC_GROUP_get_curve_GFp := FC_EC_GROUP_get_curve_GFp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_get_curve_GFp_removed)}
    if EC_GROUP_get_curve_GFp_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_get_curve_GFp)}
      EC_GROUP_get_curve_GFp := _EC_GROUP_get_curve_GFp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_get_curve_GFp_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_get_curve_GFp');
    {$ifend}
  end;


  EC_GROUP_set_curve_GF2m := LoadLibFunction(ADllHandle, EC_GROUP_set_curve_GF2m_procname);
  FuncLoadError := not assigned(EC_GROUP_set_curve_GF2m);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_set_curve_GF2m_allownil)}
    EC_GROUP_set_curve_GF2m := ERR_EC_GROUP_set_curve_GF2m;
    {$ifend}
    {$if declared(EC_GROUP_set_curve_GF2m_introduced)}
    if LibVersion < EC_GROUP_set_curve_GF2m_introduced then
    begin
      {$if declared(FC_EC_GROUP_set_curve_GF2m)}
      EC_GROUP_set_curve_GF2m := FC_EC_GROUP_set_curve_GF2m;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_set_curve_GF2m_removed)}
    if EC_GROUP_set_curve_GF2m_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_set_curve_GF2m)}
      EC_GROUP_set_curve_GF2m := _EC_GROUP_set_curve_GF2m;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_set_curve_GF2m_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_set_curve_GF2m');
    {$ifend}
  end;


  EC_GROUP_get_curve_GF2m := LoadLibFunction(ADllHandle, EC_GROUP_get_curve_GF2m_procname);
  FuncLoadError := not assigned(EC_GROUP_get_curve_GF2m);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_get_curve_GF2m_allownil)}
    EC_GROUP_get_curve_GF2m := ERR_EC_GROUP_get_curve_GF2m;
    {$ifend}
    {$if declared(EC_GROUP_get_curve_GF2m_introduced)}
    if LibVersion < EC_GROUP_get_curve_GF2m_introduced then
    begin
      {$if declared(FC_EC_GROUP_get_curve_GF2m)}
      EC_GROUP_get_curve_GF2m := FC_EC_GROUP_get_curve_GF2m;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_get_curve_GF2m_removed)}
    if EC_GROUP_get_curve_GF2m_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_get_curve_GF2m)}
      EC_GROUP_get_curve_GF2m := _EC_GROUP_get_curve_GF2m;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_get_curve_GF2m_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_get_curve_GF2m');
    {$ifend}
  end;


  EC_GROUP_get_degree := LoadLibFunction(ADllHandle, EC_GROUP_get_degree_procname);
  FuncLoadError := not assigned(EC_GROUP_get_degree);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_get_degree_allownil)}
    EC_GROUP_get_degree := ERR_EC_GROUP_get_degree;
    {$ifend}
    {$if declared(EC_GROUP_get_degree_introduced)}
    if LibVersion < EC_GROUP_get_degree_introduced then
    begin
      {$if declared(FC_EC_GROUP_get_degree)}
      EC_GROUP_get_degree := FC_EC_GROUP_get_degree;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_get_degree_removed)}
    if EC_GROUP_get_degree_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_get_degree)}
      EC_GROUP_get_degree := _EC_GROUP_get_degree;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_get_degree_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_get_degree');
    {$ifend}
  end;


  EC_GROUP_check := LoadLibFunction(ADllHandle, EC_GROUP_check_procname);
  FuncLoadError := not assigned(EC_GROUP_check);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_check_allownil)}
    EC_GROUP_check := ERR_EC_GROUP_check;
    {$ifend}
    {$if declared(EC_GROUP_check_introduced)}
    if LibVersion < EC_GROUP_check_introduced then
    begin
      {$if declared(FC_EC_GROUP_check)}
      EC_GROUP_check := FC_EC_GROUP_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_check_removed)}
    if EC_GROUP_check_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_check)}
      EC_GROUP_check := _EC_GROUP_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_check_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_check');
    {$ifend}
  end;


  EC_GROUP_check_discriminant := LoadLibFunction(ADllHandle, EC_GROUP_check_discriminant_procname);
  FuncLoadError := not assigned(EC_GROUP_check_discriminant);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_check_discriminant_allownil)}
    EC_GROUP_check_discriminant := ERR_EC_GROUP_check_discriminant;
    {$ifend}
    {$if declared(EC_GROUP_check_discriminant_introduced)}
    if LibVersion < EC_GROUP_check_discriminant_introduced then
    begin
      {$if declared(FC_EC_GROUP_check_discriminant)}
      EC_GROUP_check_discriminant := FC_EC_GROUP_check_discriminant;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_check_discriminant_removed)}
    if EC_GROUP_check_discriminant_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_check_discriminant)}
      EC_GROUP_check_discriminant := _EC_GROUP_check_discriminant;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_check_discriminant_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_check_discriminant');
    {$ifend}
  end;


  EC_GROUP_cmp := LoadLibFunction(ADllHandle, EC_GROUP_cmp_procname);
  FuncLoadError := not assigned(EC_GROUP_cmp);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_cmp_allownil)}
    EC_GROUP_cmp := ERR_EC_GROUP_cmp;
    {$ifend}
    {$if declared(EC_GROUP_cmp_introduced)}
    if LibVersion < EC_GROUP_cmp_introduced then
    begin
      {$if declared(FC_EC_GROUP_cmp)}
      EC_GROUP_cmp := FC_EC_GROUP_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_cmp_removed)}
    if EC_GROUP_cmp_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_cmp)}
      EC_GROUP_cmp := _EC_GROUP_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_cmp');
    {$ifend}
  end;


  EC_GROUP_new_curve_GFp := LoadLibFunction(ADllHandle, EC_GROUP_new_curve_GFp_procname);
  FuncLoadError := not assigned(EC_GROUP_new_curve_GFp);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_new_curve_GFp_allownil)}
    EC_GROUP_new_curve_GFp := ERR_EC_GROUP_new_curve_GFp;
    {$ifend}
    {$if declared(EC_GROUP_new_curve_GFp_introduced)}
    if LibVersion < EC_GROUP_new_curve_GFp_introduced then
    begin
      {$if declared(FC_EC_GROUP_new_curve_GFp)}
      EC_GROUP_new_curve_GFp := FC_EC_GROUP_new_curve_GFp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_new_curve_GFp_removed)}
    if EC_GROUP_new_curve_GFp_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_new_curve_GFp)}
      EC_GROUP_new_curve_GFp := _EC_GROUP_new_curve_GFp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_new_curve_GFp_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_new_curve_GFp');
    {$ifend}
  end;


  EC_GROUP_new_curve_GF2m := LoadLibFunction(ADllHandle, EC_GROUP_new_curve_GF2m_procname);
  FuncLoadError := not assigned(EC_GROUP_new_curve_GF2m);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_new_curve_GF2m_allownil)}
    EC_GROUP_new_curve_GF2m := ERR_EC_GROUP_new_curve_GF2m;
    {$ifend}
    {$if declared(EC_GROUP_new_curve_GF2m_introduced)}
    if LibVersion < EC_GROUP_new_curve_GF2m_introduced then
    begin
      {$if declared(FC_EC_GROUP_new_curve_GF2m)}
      EC_GROUP_new_curve_GF2m := FC_EC_GROUP_new_curve_GF2m;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_new_curve_GF2m_removed)}
    if EC_GROUP_new_curve_GF2m_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_new_curve_GF2m)}
      EC_GROUP_new_curve_GF2m := _EC_GROUP_new_curve_GF2m;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_new_curve_GF2m_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_new_curve_GF2m');
    {$ifend}
  end;


  EC_GROUP_new_by_curve_name := LoadLibFunction(ADllHandle, EC_GROUP_new_by_curve_name_procname);
  FuncLoadError := not assigned(EC_GROUP_new_by_curve_name);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_new_by_curve_name_allownil)}
    EC_GROUP_new_by_curve_name := ERR_EC_GROUP_new_by_curve_name;
    {$ifend}
    {$if declared(EC_GROUP_new_by_curve_name_introduced)}
    if LibVersion < EC_GROUP_new_by_curve_name_introduced then
    begin
      {$if declared(FC_EC_GROUP_new_by_curve_name)}
      EC_GROUP_new_by_curve_name := FC_EC_GROUP_new_by_curve_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_new_by_curve_name_removed)}
    if EC_GROUP_new_by_curve_name_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_new_by_curve_name)}
      EC_GROUP_new_by_curve_name := _EC_GROUP_new_by_curve_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_new_by_curve_name_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_new_by_curve_name');
    {$ifend}
  end;


  EC_GROUP_new_from_ecparameters := LoadLibFunction(ADllHandle, EC_GROUP_new_from_ecparameters_procname);
  FuncLoadError := not assigned(EC_GROUP_new_from_ecparameters);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_new_from_ecparameters_allownil)}
    EC_GROUP_new_from_ecparameters := ERR_EC_GROUP_new_from_ecparameters;
    {$ifend}
    {$if declared(EC_GROUP_new_from_ecparameters_introduced)}
    if LibVersion < EC_GROUP_new_from_ecparameters_introduced then
    begin
      {$if declared(FC_EC_GROUP_new_from_ecparameters)}
      EC_GROUP_new_from_ecparameters := FC_EC_GROUP_new_from_ecparameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_new_from_ecparameters_removed)}
    if EC_GROUP_new_from_ecparameters_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_new_from_ecparameters)}
      EC_GROUP_new_from_ecparameters := _EC_GROUP_new_from_ecparameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_new_from_ecparameters_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_new_from_ecparameters');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_GROUP_get_ecparameters := LoadLibFunction(ADllHandle, EC_GROUP_get_ecparameters_procname);
  FuncLoadError := not assigned(EC_GROUP_get_ecparameters);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_get_ecparameters_allownil)}
    EC_GROUP_get_ecparameters := ERR_EC_GROUP_get_ecparameters;
    {$ifend}
    {$if declared(EC_GROUP_get_ecparameters_introduced)}
    if LibVersion < EC_GROUP_get_ecparameters_introduced then
    begin
      {$if declared(FC_EC_GROUP_get_ecparameters)}
      EC_GROUP_get_ecparameters := FC_EC_GROUP_get_ecparameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_get_ecparameters_removed)}
    if EC_GROUP_get_ecparameters_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_get_ecparameters)}
      EC_GROUP_get_ecparameters := _EC_GROUP_get_ecparameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_get_ecparameters_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_get_ecparameters');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_GROUP_new_from_ecpkparameters := LoadLibFunction(ADllHandle, EC_GROUP_new_from_ecpkparameters_procname);
  FuncLoadError := not assigned(EC_GROUP_new_from_ecpkparameters);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_new_from_ecpkparameters_allownil)}
    EC_GROUP_new_from_ecpkparameters := ERR_EC_GROUP_new_from_ecpkparameters;
    {$ifend}
    {$if declared(EC_GROUP_new_from_ecpkparameters_introduced)}
    if LibVersion < EC_GROUP_new_from_ecpkparameters_introduced then
    begin
      {$if declared(FC_EC_GROUP_new_from_ecpkparameters)}
      EC_GROUP_new_from_ecpkparameters := FC_EC_GROUP_new_from_ecpkparameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_new_from_ecpkparameters_removed)}
    if EC_GROUP_new_from_ecpkparameters_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_new_from_ecpkparameters)}
      EC_GROUP_new_from_ecpkparameters := _EC_GROUP_new_from_ecpkparameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_new_from_ecpkparameters_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_new_from_ecpkparameters');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_GROUP_get_ecpkparameters := LoadLibFunction(ADllHandle, EC_GROUP_get_ecpkparameters_procname);
  FuncLoadError := not assigned(EC_GROUP_get_ecpkparameters);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_get_ecpkparameters_allownil)}
    EC_GROUP_get_ecpkparameters := ERR_EC_GROUP_get_ecpkparameters;
    {$ifend}
    {$if declared(EC_GROUP_get_ecpkparameters_introduced)}
    if LibVersion < EC_GROUP_get_ecpkparameters_introduced then
    begin
      {$if declared(FC_EC_GROUP_get_ecpkparameters)}
      EC_GROUP_get_ecpkparameters := FC_EC_GROUP_get_ecpkparameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_get_ecpkparameters_removed)}
    if EC_GROUP_get_ecpkparameters_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_get_ecpkparameters)}
      EC_GROUP_get_ecpkparameters := _EC_GROUP_get_ecpkparameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_get_ecpkparameters_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_get_ecpkparameters');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_get_builtin_curves := LoadLibFunction(ADllHandle, EC_get_builtin_curves_procname);
  FuncLoadError := not assigned(EC_get_builtin_curves);
  if FuncLoadError then
  begin
    {$if not defined(EC_get_builtin_curves_allownil)}
    EC_get_builtin_curves := ERR_EC_get_builtin_curves;
    {$ifend}
    {$if declared(EC_get_builtin_curves_introduced)}
    if LibVersion < EC_get_builtin_curves_introduced then
    begin
      {$if declared(FC_EC_get_builtin_curves)}
      EC_get_builtin_curves := FC_EC_get_builtin_curves;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_get_builtin_curves_removed)}
    if EC_get_builtin_curves_removed <= LibVersion then
    begin
      {$if declared(_EC_get_builtin_curves)}
      EC_get_builtin_curves := _EC_get_builtin_curves;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_get_builtin_curves_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_get_builtin_curves');
    {$ifend}
  end;


  EC_curve_nid2nist := LoadLibFunction(ADllHandle, EC_curve_nid2nist_procname);
  FuncLoadError := not assigned(EC_curve_nid2nist);
  if FuncLoadError then
  begin
    {$if not defined(EC_curve_nid2nist_allownil)}
    EC_curve_nid2nist := ERR_EC_curve_nid2nist;
    {$ifend}
    {$if declared(EC_curve_nid2nist_introduced)}
    if LibVersion < EC_curve_nid2nist_introduced then
    begin
      {$if declared(FC_EC_curve_nid2nist)}
      EC_curve_nid2nist := FC_EC_curve_nid2nist;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_curve_nid2nist_removed)}
    if EC_curve_nid2nist_removed <= LibVersion then
    begin
      {$if declared(_EC_curve_nid2nist)}
      EC_curve_nid2nist := _EC_curve_nid2nist;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_curve_nid2nist_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_curve_nid2nist');
    {$ifend}
  end;


  EC_curve_nist2nid := LoadLibFunction(ADllHandle, EC_curve_nist2nid_procname);
  FuncLoadError := not assigned(EC_curve_nist2nid);
  if FuncLoadError then
  begin
    {$if not defined(EC_curve_nist2nid_allownil)}
    EC_curve_nist2nid := ERR_EC_curve_nist2nid;
    {$ifend}
    {$if declared(EC_curve_nist2nid_introduced)}
    if LibVersion < EC_curve_nist2nid_introduced then
    begin
      {$if declared(FC_EC_curve_nist2nid)}
      EC_curve_nist2nid := FC_EC_curve_nist2nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_curve_nist2nid_removed)}
    if EC_curve_nist2nid_removed <= LibVersion then
    begin
      {$if declared(_EC_curve_nist2nid)}
      EC_curve_nist2nid := _EC_curve_nist2nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_curve_nist2nid_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_curve_nist2nid');
    {$ifend}
  end;


  EC_POINT_new := LoadLibFunction(ADllHandle, EC_POINT_new_procname);
  FuncLoadError := not assigned(EC_POINT_new);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_new_allownil)}
    EC_POINT_new := ERR_EC_POINT_new;
    {$ifend}
    {$if declared(EC_POINT_new_introduced)}
    if LibVersion < EC_POINT_new_introduced then
    begin
      {$if declared(FC_EC_POINT_new)}
      EC_POINT_new := FC_EC_POINT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_new_removed)}
    if EC_POINT_new_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_new)}
      EC_POINT_new := _EC_POINT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_new_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_new');
    {$ifend}
  end;


  EC_POINT_free := LoadLibFunction(ADllHandle, EC_POINT_free_procname);
  FuncLoadError := not assigned(EC_POINT_free);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_free_allownil)}
    EC_POINT_free := ERR_EC_POINT_free;
    {$ifend}
    {$if declared(EC_POINT_free_introduced)}
    if LibVersion < EC_POINT_free_introduced then
    begin
      {$if declared(FC_EC_POINT_free)}
      EC_POINT_free := FC_EC_POINT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_free_removed)}
    if EC_POINT_free_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_free)}
      EC_POINT_free := _EC_POINT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_free_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_free');
    {$ifend}
  end;


  EC_POINT_clear_free := LoadLibFunction(ADllHandle, EC_POINT_clear_free_procname);
  FuncLoadError := not assigned(EC_POINT_clear_free);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_clear_free_allownil)}
    EC_POINT_clear_free := ERR_EC_POINT_clear_free;
    {$ifend}
    {$if declared(EC_POINT_clear_free_introduced)}
    if LibVersion < EC_POINT_clear_free_introduced then
    begin
      {$if declared(FC_EC_POINT_clear_free)}
      EC_POINT_clear_free := FC_EC_POINT_clear_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_clear_free_removed)}
    if EC_POINT_clear_free_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_clear_free)}
      EC_POINT_clear_free := _EC_POINT_clear_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_clear_free_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_clear_free');
    {$ifend}
  end;


  EC_POINT_copy := LoadLibFunction(ADllHandle, EC_POINT_copy_procname);
  FuncLoadError := not assigned(EC_POINT_copy);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_copy_allownil)}
    EC_POINT_copy := ERR_EC_POINT_copy;
    {$ifend}
    {$if declared(EC_POINT_copy_introduced)}
    if LibVersion < EC_POINT_copy_introduced then
    begin
      {$if declared(FC_EC_POINT_copy)}
      EC_POINT_copy := FC_EC_POINT_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_copy_removed)}
    if EC_POINT_copy_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_copy)}
      EC_POINT_copy := _EC_POINT_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_copy_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_copy');
    {$ifend}
  end;


  EC_POINT_dup := LoadLibFunction(ADllHandle, EC_POINT_dup_procname);
  FuncLoadError := not assigned(EC_POINT_dup);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_dup_allownil)}
    EC_POINT_dup := ERR_EC_POINT_dup;
    {$ifend}
    {$if declared(EC_POINT_dup_introduced)}
    if LibVersion < EC_POINT_dup_introduced then
    begin
      {$if declared(FC_EC_POINT_dup)}
      EC_POINT_dup := FC_EC_POINT_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_dup_removed)}
    if EC_POINT_dup_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_dup)}
      EC_POINT_dup := _EC_POINT_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_dup');
    {$ifend}
  end;


  EC_POINT_method_of := LoadLibFunction(ADllHandle, EC_POINT_method_of_procname);
  FuncLoadError := not assigned(EC_POINT_method_of);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_method_of_allownil)}
    EC_POINT_method_of := ERR_EC_POINT_method_of;
    {$ifend}
    {$if declared(EC_POINT_method_of_introduced)}
    if LibVersion < EC_POINT_method_of_introduced then
    begin
      {$if declared(FC_EC_POINT_method_of)}
      EC_POINT_method_of := FC_EC_POINT_method_of;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_method_of_removed)}
    if EC_POINT_method_of_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_method_of)}
      EC_POINT_method_of := _EC_POINT_method_of;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_method_of_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_method_of');
    {$ifend}
  end;


  EC_POINT_set_to_infinity := LoadLibFunction(ADllHandle, EC_POINT_set_to_infinity_procname);
  FuncLoadError := not assigned(EC_POINT_set_to_infinity);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_set_to_infinity_allownil)}
    EC_POINT_set_to_infinity := ERR_EC_POINT_set_to_infinity;
    {$ifend}
    {$if declared(EC_POINT_set_to_infinity_introduced)}
    if LibVersion < EC_POINT_set_to_infinity_introduced then
    begin
      {$if declared(FC_EC_POINT_set_to_infinity)}
      EC_POINT_set_to_infinity := FC_EC_POINT_set_to_infinity;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_set_to_infinity_removed)}
    if EC_POINT_set_to_infinity_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_set_to_infinity)}
      EC_POINT_set_to_infinity := _EC_POINT_set_to_infinity;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_set_to_infinity_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_set_to_infinity');
    {$ifend}
  end;


  EC_POINT_set_Jprojective_coordinates_GFp := LoadLibFunction(ADllHandle, EC_POINT_set_Jprojective_coordinates_GFp_procname);
  FuncLoadError := not assigned(EC_POINT_set_Jprojective_coordinates_GFp);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_set_Jprojective_coordinates_GFp_allownil)}
    EC_POINT_set_Jprojective_coordinates_GFp := ERR_EC_POINT_set_Jprojective_coordinates_GFp;
    {$ifend}
    {$if declared(EC_POINT_set_Jprojective_coordinates_GFp_introduced)}
    if LibVersion < EC_POINT_set_Jprojective_coordinates_GFp_introduced then
    begin
      {$if declared(FC_EC_POINT_set_Jprojective_coordinates_GFp)}
      EC_POINT_set_Jprojective_coordinates_GFp := FC_EC_POINT_set_Jprojective_coordinates_GFp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_set_Jprojective_coordinates_GFp_removed)}
    if EC_POINT_set_Jprojective_coordinates_GFp_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_set_Jprojective_coordinates_GFp)}
      EC_POINT_set_Jprojective_coordinates_GFp := _EC_POINT_set_Jprojective_coordinates_GFp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_set_Jprojective_coordinates_GFp_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_set_Jprojective_coordinates_GFp');
    {$ifend}
  end;


  EC_POINT_get_Jprojective_coordinates_GFp := LoadLibFunction(ADllHandle, EC_POINT_get_Jprojective_coordinates_GFp_procname);
  FuncLoadError := not assigned(EC_POINT_get_Jprojective_coordinates_GFp);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_get_Jprojective_coordinates_GFp_allownil)}
    EC_POINT_get_Jprojective_coordinates_GFp := ERR_EC_POINT_get_Jprojective_coordinates_GFp;
    {$ifend}
    {$if declared(EC_POINT_get_Jprojective_coordinates_GFp_introduced)}
    if LibVersion < EC_POINT_get_Jprojective_coordinates_GFp_introduced then
    begin
      {$if declared(FC_EC_POINT_get_Jprojective_coordinates_GFp)}
      EC_POINT_get_Jprojective_coordinates_GFp := FC_EC_POINT_get_Jprojective_coordinates_GFp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_get_Jprojective_coordinates_GFp_removed)}
    if EC_POINT_get_Jprojective_coordinates_GFp_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_get_Jprojective_coordinates_GFp)}
      EC_POINT_get_Jprojective_coordinates_GFp := _EC_POINT_get_Jprojective_coordinates_GFp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_get_Jprojective_coordinates_GFp_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_get_Jprojective_coordinates_GFp');
    {$ifend}
  end;


  EC_POINT_set_affine_coordinates := LoadLibFunction(ADllHandle, EC_POINT_set_affine_coordinates_procname);
  FuncLoadError := not assigned(EC_POINT_set_affine_coordinates);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_set_affine_coordinates_allownil)}
    EC_POINT_set_affine_coordinates := ERR_EC_POINT_set_affine_coordinates;
    {$ifend}
    {$if declared(EC_POINT_set_affine_coordinates_introduced)}
    if LibVersion < EC_POINT_set_affine_coordinates_introduced then
    begin
      {$if declared(FC_EC_POINT_set_affine_coordinates)}
      EC_POINT_set_affine_coordinates := FC_EC_POINT_set_affine_coordinates;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_set_affine_coordinates_removed)}
    if EC_POINT_set_affine_coordinates_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_set_affine_coordinates)}
      EC_POINT_set_affine_coordinates := _EC_POINT_set_affine_coordinates;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_set_affine_coordinates_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_set_affine_coordinates');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_POINT_get_affine_coordinates := LoadLibFunction(ADllHandle, EC_POINT_get_affine_coordinates_procname);
  FuncLoadError := not assigned(EC_POINT_get_affine_coordinates);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_get_affine_coordinates_allownil)}
    EC_POINT_get_affine_coordinates := ERR_EC_POINT_get_affine_coordinates;
    {$ifend}
    {$if declared(EC_POINT_get_affine_coordinates_introduced)}
    if LibVersion < EC_POINT_get_affine_coordinates_introduced then
    begin
      {$if declared(FC_EC_POINT_get_affine_coordinates)}
      EC_POINT_get_affine_coordinates := FC_EC_POINT_get_affine_coordinates;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_get_affine_coordinates_removed)}
    if EC_POINT_get_affine_coordinates_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_get_affine_coordinates)}
      EC_POINT_get_affine_coordinates := _EC_POINT_get_affine_coordinates;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_get_affine_coordinates_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_get_affine_coordinates');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_POINT_set_affine_coordinates_GFp := LoadLibFunction(ADllHandle, EC_POINT_set_affine_coordinates_GFp_procname);
  FuncLoadError := not assigned(EC_POINT_set_affine_coordinates_GFp);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_set_affine_coordinates_GFp_allownil)}
    EC_POINT_set_affine_coordinates_GFp := ERR_EC_POINT_set_affine_coordinates_GFp;
    {$ifend}
    {$if declared(EC_POINT_set_affine_coordinates_GFp_introduced)}
    if LibVersion < EC_POINT_set_affine_coordinates_GFp_introduced then
    begin
      {$if declared(FC_EC_POINT_set_affine_coordinates_GFp)}
      EC_POINT_set_affine_coordinates_GFp := FC_EC_POINT_set_affine_coordinates_GFp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_set_affine_coordinates_GFp_removed)}
    if EC_POINT_set_affine_coordinates_GFp_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_set_affine_coordinates_GFp)}
      EC_POINT_set_affine_coordinates_GFp := _EC_POINT_set_affine_coordinates_GFp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_set_affine_coordinates_GFp_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_set_affine_coordinates_GFp');
    {$ifend}
  end;


  EC_POINT_get_affine_coordinates_GFp := LoadLibFunction(ADllHandle, EC_POINT_get_affine_coordinates_GFp_procname);
  FuncLoadError := not assigned(EC_POINT_get_affine_coordinates_GFp);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_get_affine_coordinates_GFp_allownil)}
    EC_POINT_get_affine_coordinates_GFp := ERR_EC_POINT_get_affine_coordinates_GFp;
    {$ifend}
    {$if declared(EC_POINT_get_affine_coordinates_GFp_introduced)}
    if LibVersion < EC_POINT_get_affine_coordinates_GFp_introduced then
    begin
      {$if declared(FC_EC_POINT_get_affine_coordinates_GFp)}
      EC_POINT_get_affine_coordinates_GFp := FC_EC_POINT_get_affine_coordinates_GFp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_get_affine_coordinates_GFp_removed)}
    if EC_POINT_get_affine_coordinates_GFp_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_get_affine_coordinates_GFp)}
      EC_POINT_get_affine_coordinates_GFp := _EC_POINT_get_affine_coordinates_GFp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_get_affine_coordinates_GFp_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_get_affine_coordinates_GFp');
    {$ifend}
  end;


  EC_POINT_set_compressed_coordinates := LoadLibFunction(ADllHandle, EC_POINT_set_compressed_coordinates_procname);
  FuncLoadError := not assigned(EC_POINT_set_compressed_coordinates);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_set_compressed_coordinates_allownil)}
    EC_POINT_set_compressed_coordinates := ERR_EC_POINT_set_compressed_coordinates;
    {$ifend}
    {$if declared(EC_POINT_set_compressed_coordinates_introduced)}
    if LibVersion < EC_POINT_set_compressed_coordinates_introduced then
    begin
      {$if declared(FC_EC_POINT_set_compressed_coordinates)}
      EC_POINT_set_compressed_coordinates := FC_EC_POINT_set_compressed_coordinates;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_set_compressed_coordinates_removed)}
    if EC_POINT_set_compressed_coordinates_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_set_compressed_coordinates)}
      EC_POINT_set_compressed_coordinates := _EC_POINT_set_compressed_coordinates;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_set_compressed_coordinates_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_set_compressed_coordinates');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_POINT_set_compressed_coordinates_GFp := LoadLibFunction(ADllHandle, EC_POINT_set_compressed_coordinates_GFp_procname);
  FuncLoadError := not assigned(EC_POINT_set_compressed_coordinates_GFp);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_set_compressed_coordinates_GFp_allownil)}
    EC_POINT_set_compressed_coordinates_GFp := ERR_EC_POINT_set_compressed_coordinates_GFp;
    {$ifend}
    {$if declared(EC_POINT_set_compressed_coordinates_GFp_introduced)}
    if LibVersion < EC_POINT_set_compressed_coordinates_GFp_introduced then
    begin
      {$if declared(FC_EC_POINT_set_compressed_coordinates_GFp)}
      EC_POINT_set_compressed_coordinates_GFp := FC_EC_POINT_set_compressed_coordinates_GFp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_set_compressed_coordinates_GFp_removed)}
    if EC_POINT_set_compressed_coordinates_GFp_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_set_compressed_coordinates_GFp)}
      EC_POINT_set_compressed_coordinates_GFp := _EC_POINT_set_compressed_coordinates_GFp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_set_compressed_coordinates_GFp_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_set_compressed_coordinates_GFp');
    {$ifend}
  end;


  EC_POINT_set_affine_coordinates_GF2m := LoadLibFunction(ADllHandle, EC_POINT_set_affine_coordinates_GF2m_procname);
  FuncLoadError := not assigned(EC_POINT_set_affine_coordinates_GF2m);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_set_affine_coordinates_GF2m_allownil)}
    EC_POINT_set_affine_coordinates_GF2m := ERR_EC_POINT_set_affine_coordinates_GF2m;
    {$ifend}
    {$if declared(EC_POINT_set_affine_coordinates_GF2m_introduced)}
    if LibVersion < EC_POINT_set_affine_coordinates_GF2m_introduced then
    begin
      {$if declared(FC_EC_POINT_set_affine_coordinates_GF2m)}
      EC_POINT_set_affine_coordinates_GF2m := FC_EC_POINT_set_affine_coordinates_GF2m;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_set_affine_coordinates_GF2m_removed)}
    if EC_POINT_set_affine_coordinates_GF2m_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_set_affine_coordinates_GF2m)}
      EC_POINT_set_affine_coordinates_GF2m := _EC_POINT_set_affine_coordinates_GF2m;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_set_affine_coordinates_GF2m_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_set_affine_coordinates_GF2m');
    {$ifend}
  end;


  EC_POINT_get_affine_coordinates_GF2m := LoadLibFunction(ADllHandle, EC_POINT_get_affine_coordinates_GF2m_procname);
  FuncLoadError := not assigned(EC_POINT_get_affine_coordinates_GF2m);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_get_affine_coordinates_GF2m_allownil)}
    EC_POINT_get_affine_coordinates_GF2m := ERR_EC_POINT_get_affine_coordinates_GF2m;
    {$ifend}
    {$if declared(EC_POINT_get_affine_coordinates_GF2m_introduced)}
    if LibVersion < EC_POINT_get_affine_coordinates_GF2m_introduced then
    begin
      {$if declared(FC_EC_POINT_get_affine_coordinates_GF2m)}
      EC_POINT_get_affine_coordinates_GF2m := FC_EC_POINT_get_affine_coordinates_GF2m;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_get_affine_coordinates_GF2m_removed)}
    if EC_POINT_get_affine_coordinates_GF2m_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_get_affine_coordinates_GF2m)}
      EC_POINT_get_affine_coordinates_GF2m := _EC_POINT_get_affine_coordinates_GF2m;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_get_affine_coordinates_GF2m_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_get_affine_coordinates_GF2m');
    {$ifend}
  end;


  EC_POINT_set_compressed_coordinates_GF2m := LoadLibFunction(ADllHandle, EC_POINT_set_compressed_coordinates_GF2m_procname);
  FuncLoadError := not assigned(EC_POINT_set_compressed_coordinates_GF2m);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_set_compressed_coordinates_GF2m_allownil)}
    EC_POINT_set_compressed_coordinates_GF2m := ERR_EC_POINT_set_compressed_coordinates_GF2m;
    {$ifend}
    {$if declared(EC_POINT_set_compressed_coordinates_GF2m_introduced)}
    if LibVersion < EC_POINT_set_compressed_coordinates_GF2m_introduced then
    begin
      {$if declared(FC_EC_POINT_set_compressed_coordinates_GF2m)}
      EC_POINT_set_compressed_coordinates_GF2m := FC_EC_POINT_set_compressed_coordinates_GF2m;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_set_compressed_coordinates_GF2m_removed)}
    if EC_POINT_set_compressed_coordinates_GF2m_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_set_compressed_coordinates_GF2m)}
      EC_POINT_set_compressed_coordinates_GF2m := _EC_POINT_set_compressed_coordinates_GF2m;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_set_compressed_coordinates_GF2m_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_set_compressed_coordinates_GF2m');
    {$ifend}
  end;


  EC_POINT_point2oct := LoadLibFunction(ADllHandle, EC_POINT_point2oct_procname);
  FuncLoadError := not assigned(EC_POINT_point2oct);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_point2oct_allownil)}
    EC_POINT_point2oct := ERR_EC_POINT_point2oct;
    {$ifend}
    {$if declared(EC_POINT_point2oct_introduced)}
    if LibVersion < EC_POINT_point2oct_introduced then
    begin
      {$if declared(FC_EC_POINT_point2oct)}
      EC_POINT_point2oct := FC_EC_POINT_point2oct;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_point2oct_removed)}
    if EC_POINT_point2oct_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_point2oct)}
      EC_POINT_point2oct := _EC_POINT_point2oct;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_point2oct_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_point2oct');
    {$ifend}
  end;


  EC_POINT_oct2point := LoadLibFunction(ADllHandle, EC_POINT_oct2point_procname);
  FuncLoadError := not assigned(EC_POINT_oct2point);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_oct2point_allownil)}
    EC_POINT_oct2point := ERR_EC_POINT_oct2point;
    {$ifend}
    {$if declared(EC_POINT_oct2point_introduced)}
    if LibVersion < EC_POINT_oct2point_introduced then
    begin
      {$if declared(FC_EC_POINT_oct2point)}
      EC_POINT_oct2point := FC_EC_POINT_oct2point;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_oct2point_removed)}
    if EC_POINT_oct2point_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_oct2point)}
      EC_POINT_oct2point := _EC_POINT_oct2point;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_oct2point_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_oct2point');
    {$ifend}
  end;


  EC_POINT_point2buf := LoadLibFunction(ADllHandle, EC_POINT_point2buf_procname);
  FuncLoadError := not assigned(EC_POINT_point2buf);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_point2buf_allownil)}
    EC_POINT_point2buf := ERR_EC_POINT_point2buf;
    {$ifend}
    {$if declared(EC_POINT_point2buf_introduced)}
    if LibVersion < EC_POINT_point2buf_introduced then
    begin
      {$if declared(FC_EC_POINT_point2buf)}
      EC_POINT_point2buf := FC_EC_POINT_point2buf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_point2buf_removed)}
    if EC_POINT_point2buf_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_point2buf)}
      EC_POINT_point2buf := _EC_POINT_point2buf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_point2buf_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_point2buf');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_POINT_point2bn := LoadLibFunction(ADllHandle, EC_POINT_point2bn_procname);
  FuncLoadError := not assigned(EC_POINT_point2bn);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_point2bn_allownil)}
    EC_POINT_point2bn := ERR_EC_POINT_point2bn;
    {$ifend}
    {$if declared(EC_POINT_point2bn_introduced)}
    if LibVersion < EC_POINT_point2bn_introduced then
    begin
      {$if declared(FC_EC_POINT_point2bn)}
      EC_POINT_point2bn := FC_EC_POINT_point2bn;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_point2bn_removed)}
    if EC_POINT_point2bn_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_point2bn)}
      EC_POINT_point2bn := _EC_POINT_point2bn;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_point2bn_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_point2bn');
    {$ifend}
  end;


  EC_POINT_bn2point := LoadLibFunction(ADllHandle, EC_POINT_bn2point_procname);
  FuncLoadError := not assigned(EC_POINT_bn2point);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_bn2point_allownil)}
    EC_POINT_bn2point := ERR_EC_POINT_bn2point;
    {$ifend}
    {$if declared(EC_POINT_bn2point_introduced)}
    if LibVersion < EC_POINT_bn2point_introduced then
    begin
      {$if declared(FC_EC_POINT_bn2point)}
      EC_POINT_bn2point := FC_EC_POINT_bn2point;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_bn2point_removed)}
    if EC_POINT_bn2point_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_bn2point)}
      EC_POINT_bn2point := _EC_POINT_bn2point;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_bn2point_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_bn2point');
    {$ifend}
  end;


  EC_POINT_point2hex := LoadLibFunction(ADllHandle, EC_POINT_point2hex_procname);
  FuncLoadError := not assigned(EC_POINT_point2hex);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_point2hex_allownil)}
    EC_POINT_point2hex := ERR_EC_POINT_point2hex;
    {$ifend}
    {$if declared(EC_POINT_point2hex_introduced)}
    if LibVersion < EC_POINT_point2hex_introduced then
    begin
      {$if declared(FC_EC_POINT_point2hex)}
      EC_POINT_point2hex := FC_EC_POINT_point2hex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_point2hex_removed)}
    if EC_POINT_point2hex_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_point2hex)}
      EC_POINT_point2hex := _EC_POINT_point2hex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_point2hex_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_point2hex');
    {$ifend}
  end;


  EC_POINT_hex2point := LoadLibFunction(ADllHandle, EC_POINT_hex2point_procname);
  FuncLoadError := not assigned(EC_POINT_hex2point);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_hex2point_allownil)}
    EC_POINT_hex2point := ERR_EC_POINT_hex2point;
    {$ifend}
    {$if declared(EC_POINT_hex2point_introduced)}
    if LibVersion < EC_POINT_hex2point_introduced then
    begin
      {$if declared(FC_EC_POINT_hex2point)}
      EC_POINT_hex2point := FC_EC_POINT_hex2point;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_hex2point_removed)}
    if EC_POINT_hex2point_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_hex2point)}
      EC_POINT_hex2point := _EC_POINT_hex2point;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_hex2point_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_hex2point');
    {$ifend}
  end;


  EC_POINT_add := LoadLibFunction(ADllHandle, EC_POINT_add_procname);
  FuncLoadError := not assigned(EC_POINT_add);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_add_allownil)}
    EC_POINT_add := ERR_EC_POINT_add;
    {$ifend}
    {$if declared(EC_POINT_add_introduced)}
    if LibVersion < EC_POINT_add_introduced then
    begin
      {$if declared(FC_EC_POINT_add)}
      EC_POINT_add := FC_EC_POINT_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_add_removed)}
    if EC_POINT_add_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_add)}
      EC_POINT_add := _EC_POINT_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_add_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_add');
    {$ifend}
  end;


  EC_POINT_dbl := LoadLibFunction(ADllHandle, EC_POINT_dbl_procname);
  FuncLoadError := not assigned(EC_POINT_dbl);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_dbl_allownil)}
    EC_POINT_dbl := ERR_EC_POINT_dbl;
    {$ifend}
    {$if declared(EC_POINT_dbl_introduced)}
    if LibVersion < EC_POINT_dbl_introduced then
    begin
      {$if declared(FC_EC_POINT_dbl)}
      EC_POINT_dbl := FC_EC_POINT_dbl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_dbl_removed)}
    if EC_POINT_dbl_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_dbl)}
      EC_POINT_dbl := _EC_POINT_dbl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_dbl_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_dbl');
    {$ifend}
  end;


  EC_POINT_invert := LoadLibFunction(ADllHandle, EC_POINT_invert_procname);
  FuncLoadError := not assigned(EC_POINT_invert);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_invert_allownil)}
    EC_POINT_invert := ERR_EC_POINT_invert;
    {$ifend}
    {$if declared(EC_POINT_invert_introduced)}
    if LibVersion < EC_POINT_invert_introduced then
    begin
      {$if declared(FC_EC_POINT_invert)}
      EC_POINT_invert := FC_EC_POINT_invert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_invert_removed)}
    if EC_POINT_invert_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_invert)}
      EC_POINT_invert := _EC_POINT_invert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_invert_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_invert');
    {$ifend}
  end;


  EC_POINT_is_at_infinity := LoadLibFunction(ADllHandle, EC_POINT_is_at_infinity_procname);
  FuncLoadError := not assigned(EC_POINT_is_at_infinity);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_is_at_infinity_allownil)}
    EC_POINT_is_at_infinity := ERR_EC_POINT_is_at_infinity;
    {$ifend}
    {$if declared(EC_POINT_is_at_infinity_introduced)}
    if LibVersion < EC_POINT_is_at_infinity_introduced then
    begin
      {$if declared(FC_EC_POINT_is_at_infinity)}
      EC_POINT_is_at_infinity := FC_EC_POINT_is_at_infinity;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_is_at_infinity_removed)}
    if EC_POINT_is_at_infinity_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_is_at_infinity)}
      EC_POINT_is_at_infinity := _EC_POINT_is_at_infinity;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_is_at_infinity_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_is_at_infinity');
    {$ifend}
  end;


  EC_POINT_is_on_curve := LoadLibFunction(ADllHandle, EC_POINT_is_on_curve_procname);
  FuncLoadError := not assigned(EC_POINT_is_on_curve);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_is_on_curve_allownil)}
    EC_POINT_is_on_curve := ERR_EC_POINT_is_on_curve;
    {$ifend}
    {$if declared(EC_POINT_is_on_curve_introduced)}
    if LibVersion < EC_POINT_is_on_curve_introduced then
    begin
      {$if declared(FC_EC_POINT_is_on_curve)}
      EC_POINT_is_on_curve := FC_EC_POINT_is_on_curve;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_is_on_curve_removed)}
    if EC_POINT_is_on_curve_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_is_on_curve)}
      EC_POINT_is_on_curve := _EC_POINT_is_on_curve;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_is_on_curve_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_is_on_curve');
    {$ifend}
  end;


  EC_POINT_cmp := LoadLibFunction(ADllHandle, EC_POINT_cmp_procname);
  FuncLoadError := not assigned(EC_POINT_cmp);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_cmp_allownil)}
    EC_POINT_cmp := ERR_EC_POINT_cmp;
    {$ifend}
    {$if declared(EC_POINT_cmp_introduced)}
    if LibVersion < EC_POINT_cmp_introduced then
    begin
      {$if declared(FC_EC_POINT_cmp)}
      EC_POINT_cmp := FC_EC_POINT_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_cmp_removed)}
    if EC_POINT_cmp_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_cmp)}
      EC_POINT_cmp := _EC_POINT_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_cmp');
    {$ifend}
  end;


  EC_POINT_make_affine := LoadLibFunction(ADllHandle, EC_POINT_make_affine_procname);
  FuncLoadError := not assigned(EC_POINT_make_affine);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_make_affine_allownil)}
    EC_POINT_make_affine := ERR_EC_POINT_make_affine;
    {$ifend}
    {$if declared(EC_POINT_make_affine_introduced)}
    if LibVersion < EC_POINT_make_affine_introduced then
    begin
      {$if declared(FC_EC_POINT_make_affine)}
      EC_POINT_make_affine := FC_EC_POINT_make_affine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_make_affine_removed)}
    if EC_POINT_make_affine_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_make_affine)}
      EC_POINT_make_affine := _EC_POINT_make_affine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_make_affine_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_make_affine');
    {$ifend}
  end;


  EC_POINTs_make_affine := LoadLibFunction(ADllHandle, EC_POINTs_make_affine_procname);
  FuncLoadError := not assigned(EC_POINTs_make_affine);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINTs_make_affine_allownil)}
    EC_POINTs_make_affine := ERR_EC_POINTs_make_affine;
    {$ifend}
    {$if declared(EC_POINTs_make_affine_introduced)}
    if LibVersion < EC_POINTs_make_affine_introduced then
    begin
      {$if declared(FC_EC_POINTs_make_affine)}
      EC_POINTs_make_affine := FC_EC_POINTs_make_affine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINTs_make_affine_removed)}
    if EC_POINTs_make_affine_removed <= LibVersion then
    begin
      {$if declared(_EC_POINTs_make_affine)}
      EC_POINTs_make_affine := _EC_POINTs_make_affine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINTs_make_affine_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINTs_make_affine');
    {$ifend}
  end;


  EC_POINTs_mul := LoadLibFunction(ADllHandle, EC_POINTs_mul_procname);
  FuncLoadError := not assigned(EC_POINTs_mul);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINTs_mul_allownil)}
    EC_POINTs_mul := ERR_EC_POINTs_mul;
    {$ifend}
    {$if declared(EC_POINTs_mul_introduced)}
    if LibVersion < EC_POINTs_mul_introduced then
    begin
      {$if declared(FC_EC_POINTs_mul)}
      EC_POINTs_mul := FC_EC_POINTs_mul;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINTs_mul_removed)}
    if EC_POINTs_mul_removed <= LibVersion then
    begin
      {$if declared(_EC_POINTs_mul)}
      EC_POINTs_mul := _EC_POINTs_mul;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINTs_mul_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINTs_mul');
    {$ifend}
  end;


  EC_POINT_mul := LoadLibFunction(ADllHandle, EC_POINT_mul_procname);
  FuncLoadError := not assigned(EC_POINT_mul);
  if FuncLoadError then
  begin
    {$if not defined(EC_POINT_mul_allownil)}
    EC_POINT_mul := ERR_EC_POINT_mul;
    {$ifend}
    {$if declared(EC_POINT_mul_introduced)}
    if LibVersion < EC_POINT_mul_introduced then
    begin
      {$if declared(FC_EC_POINT_mul)}
      EC_POINT_mul := FC_EC_POINT_mul;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_POINT_mul_removed)}
    if EC_POINT_mul_removed <= LibVersion then
    begin
      {$if declared(_EC_POINT_mul)}
      EC_POINT_mul := _EC_POINT_mul;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_POINT_mul_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_POINT_mul');
    {$ifend}
  end;


  EC_GROUP_precompute_mult := LoadLibFunction(ADllHandle, EC_GROUP_precompute_mult_procname);
  FuncLoadError := not assigned(EC_GROUP_precompute_mult);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_precompute_mult_allownil)}
    EC_GROUP_precompute_mult := ERR_EC_GROUP_precompute_mult;
    {$ifend}
    {$if declared(EC_GROUP_precompute_mult_introduced)}
    if LibVersion < EC_GROUP_precompute_mult_introduced then
    begin
      {$if declared(FC_EC_GROUP_precompute_mult)}
      EC_GROUP_precompute_mult := FC_EC_GROUP_precompute_mult;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_precompute_mult_removed)}
    if EC_GROUP_precompute_mult_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_precompute_mult)}
      EC_GROUP_precompute_mult := _EC_GROUP_precompute_mult;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_precompute_mult_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_precompute_mult');
    {$ifend}
  end;


  EC_GROUP_have_precompute_mult := LoadLibFunction(ADllHandle, EC_GROUP_have_precompute_mult_procname);
  FuncLoadError := not assigned(EC_GROUP_have_precompute_mult);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_have_precompute_mult_allownil)}
    EC_GROUP_have_precompute_mult := ERR_EC_GROUP_have_precompute_mult;
    {$ifend}
    {$if declared(EC_GROUP_have_precompute_mult_introduced)}
    if LibVersion < EC_GROUP_have_precompute_mult_introduced then
    begin
      {$if declared(FC_EC_GROUP_have_precompute_mult)}
      EC_GROUP_have_precompute_mult := FC_EC_GROUP_have_precompute_mult;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_have_precompute_mult_removed)}
    if EC_GROUP_have_precompute_mult_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_have_precompute_mult)}
      EC_GROUP_have_precompute_mult := _EC_GROUP_have_precompute_mult;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_have_precompute_mult_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_have_precompute_mult');
    {$ifend}
  end;


  ECPKPARAMETERS_it := LoadLibFunction(ADllHandle, ECPKPARAMETERS_it_procname);
  FuncLoadError := not assigned(ECPKPARAMETERS_it);
  if FuncLoadError then
  begin
    {$if not defined(ECPKPARAMETERS_it_allownil)}
    ECPKPARAMETERS_it := ERR_ECPKPARAMETERS_it;
    {$ifend}
    {$if declared(ECPKPARAMETERS_it_introduced)}
    if LibVersion < ECPKPARAMETERS_it_introduced then
    begin
      {$if declared(FC_ECPKPARAMETERS_it)}
      ECPKPARAMETERS_it := FC_ECPKPARAMETERS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECPKPARAMETERS_it_removed)}
    if ECPKPARAMETERS_it_removed <= LibVersion then
    begin
      {$if declared(_ECPKPARAMETERS_it)}
      ECPKPARAMETERS_it := _ECPKPARAMETERS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECPKPARAMETERS_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ECPKPARAMETERS_it');
    {$ifend}
  end;


  ECPKPARAMETERS_new := LoadLibFunction(ADllHandle, ECPKPARAMETERS_new_procname);
  FuncLoadError := not assigned(ECPKPARAMETERS_new);
  if FuncLoadError then
  begin
    {$if not defined(ECPKPARAMETERS_new_allownil)}
    ECPKPARAMETERS_new := ERR_ECPKPARAMETERS_new;
    {$ifend}
    {$if declared(ECPKPARAMETERS_new_introduced)}
    if LibVersion < ECPKPARAMETERS_new_introduced then
    begin
      {$if declared(FC_ECPKPARAMETERS_new)}
      ECPKPARAMETERS_new := FC_ECPKPARAMETERS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECPKPARAMETERS_new_removed)}
    if ECPKPARAMETERS_new_removed <= LibVersion then
    begin
      {$if declared(_ECPKPARAMETERS_new)}
      ECPKPARAMETERS_new := _ECPKPARAMETERS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECPKPARAMETERS_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ECPKPARAMETERS_new');
    {$ifend}
  end;


  ECPKPARAMETERS_free := LoadLibFunction(ADllHandle, ECPKPARAMETERS_free_procname);
  FuncLoadError := not assigned(ECPKPARAMETERS_free);
  if FuncLoadError then
  begin
    {$if not defined(ECPKPARAMETERS_free_allownil)}
    ECPKPARAMETERS_free := ERR_ECPKPARAMETERS_free;
    {$ifend}
    {$if declared(ECPKPARAMETERS_free_introduced)}
    if LibVersion < ECPKPARAMETERS_free_introduced then
    begin
      {$if declared(FC_ECPKPARAMETERS_free)}
      ECPKPARAMETERS_free := FC_ECPKPARAMETERS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECPKPARAMETERS_free_removed)}
    if ECPKPARAMETERS_free_removed <= LibVersion then
    begin
      {$if declared(_ECPKPARAMETERS_free)}
      ECPKPARAMETERS_free := _ECPKPARAMETERS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECPKPARAMETERS_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ECPKPARAMETERS_free');
    {$ifend}
  end;


  ECPARAMETERS_it := LoadLibFunction(ADllHandle, ECPARAMETERS_it_procname);
  FuncLoadError := not assigned(ECPARAMETERS_it);
  if FuncLoadError then
  begin
    {$if not defined(ECPARAMETERS_it_allownil)}
    ECPARAMETERS_it := ERR_ECPARAMETERS_it;
    {$ifend}
    {$if declared(ECPARAMETERS_it_introduced)}
    if LibVersion < ECPARAMETERS_it_introduced then
    begin
      {$if declared(FC_ECPARAMETERS_it)}
      ECPARAMETERS_it := FC_ECPARAMETERS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECPARAMETERS_it_removed)}
    if ECPARAMETERS_it_removed <= LibVersion then
    begin
      {$if declared(_ECPARAMETERS_it)}
      ECPARAMETERS_it := _ECPARAMETERS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECPARAMETERS_it_allownil)}
    if FuncLoadError then
      AFailed.Add('ECPARAMETERS_it');
    {$ifend}
  end;


  ECPARAMETERS_new := LoadLibFunction(ADllHandle, ECPARAMETERS_new_procname);
  FuncLoadError := not assigned(ECPARAMETERS_new);
  if FuncLoadError then
  begin
    {$if not defined(ECPARAMETERS_new_allownil)}
    ECPARAMETERS_new := ERR_ECPARAMETERS_new;
    {$ifend}
    {$if declared(ECPARAMETERS_new_introduced)}
    if LibVersion < ECPARAMETERS_new_introduced then
    begin
      {$if declared(FC_ECPARAMETERS_new)}
      ECPARAMETERS_new := FC_ECPARAMETERS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECPARAMETERS_new_removed)}
    if ECPARAMETERS_new_removed <= LibVersion then
    begin
      {$if declared(_ECPARAMETERS_new)}
      ECPARAMETERS_new := _ECPARAMETERS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECPARAMETERS_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ECPARAMETERS_new');
    {$ifend}
  end;


  ECPARAMETERS_free := LoadLibFunction(ADllHandle, ECPARAMETERS_free_procname);
  FuncLoadError := not assigned(ECPARAMETERS_free);
  if FuncLoadError then
  begin
    {$if not defined(ECPARAMETERS_free_allownil)}
    ECPARAMETERS_free := ERR_ECPARAMETERS_free;
    {$ifend}
    {$if declared(ECPARAMETERS_free_introduced)}
    if LibVersion < ECPARAMETERS_free_introduced then
    begin
      {$if declared(FC_ECPARAMETERS_free)}
      ECPARAMETERS_free := FC_ECPARAMETERS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECPARAMETERS_free_removed)}
    if ECPARAMETERS_free_removed <= LibVersion then
    begin
      {$if declared(_ECPARAMETERS_free)}
      ECPARAMETERS_free := _ECPARAMETERS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECPARAMETERS_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ECPARAMETERS_free');
    {$ifend}
  end;


  EC_GROUP_get_basis_type := LoadLibFunction(ADllHandle, EC_GROUP_get_basis_type_procname);
  FuncLoadError := not assigned(EC_GROUP_get_basis_type);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_get_basis_type_allownil)}
    EC_GROUP_get_basis_type := ERR_EC_GROUP_get_basis_type;
    {$ifend}
    {$if declared(EC_GROUP_get_basis_type_introduced)}
    if LibVersion < EC_GROUP_get_basis_type_introduced then
    begin
      {$if declared(FC_EC_GROUP_get_basis_type)}
      EC_GROUP_get_basis_type := FC_EC_GROUP_get_basis_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_get_basis_type_removed)}
    if EC_GROUP_get_basis_type_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_get_basis_type)}
      EC_GROUP_get_basis_type := _EC_GROUP_get_basis_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_get_basis_type_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_get_basis_type');
    {$ifend}
  end;


  EC_GROUP_get_trinomial_basis := LoadLibFunction(ADllHandle, EC_GROUP_get_trinomial_basis_procname);
  FuncLoadError := not assigned(EC_GROUP_get_trinomial_basis);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_get_trinomial_basis_allownil)}
    EC_GROUP_get_trinomial_basis := ERR_EC_GROUP_get_trinomial_basis;
    {$ifend}
    {$if declared(EC_GROUP_get_trinomial_basis_introduced)}
    if LibVersion < EC_GROUP_get_trinomial_basis_introduced then
    begin
      {$if declared(FC_EC_GROUP_get_trinomial_basis)}
      EC_GROUP_get_trinomial_basis := FC_EC_GROUP_get_trinomial_basis;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_get_trinomial_basis_removed)}
    if EC_GROUP_get_trinomial_basis_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_get_trinomial_basis)}
      EC_GROUP_get_trinomial_basis := _EC_GROUP_get_trinomial_basis;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_get_trinomial_basis_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_get_trinomial_basis');
    {$ifend}
  end;


  EC_GROUP_get_pentanomial_basis := LoadLibFunction(ADllHandle, EC_GROUP_get_pentanomial_basis_procname);
  FuncLoadError := not assigned(EC_GROUP_get_pentanomial_basis);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_get_pentanomial_basis_allownil)}
    EC_GROUP_get_pentanomial_basis := ERR_EC_GROUP_get_pentanomial_basis;
    {$ifend}
    {$if declared(EC_GROUP_get_pentanomial_basis_introduced)}
    if LibVersion < EC_GROUP_get_pentanomial_basis_introduced then
    begin
      {$if declared(FC_EC_GROUP_get_pentanomial_basis)}
      EC_GROUP_get_pentanomial_basis := FC_EC_GROUP_get_pentanomial_basis;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_get_pentanomial_basis_removed)}
    if EC_GROUP_get_pentanomial_basis_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_get_pentanomial_basis)}
      EC_GROUP_get_pentanomial_basis := _EC_GROUP_get_pentanomial_basis;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_get_pentanomial_basis_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_get_pentanomial_basis');
    {$ifend}
  end;


  d2i_ECPKParameters := LoadLibFunction(ADllHandle, d2i_ECPKParameters_procname);
  FuncLoadError := not assigned(d2i_ECPKParameters);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ECPKParameters_allownil)}
    d2i_ECPKParameters := ERR_d2i_ECPKParameters;
    {$ifend}
    {$if declared(d2i_ECPKParameters_introduced)}
    if LibVersion < d2i_ECPKParameters_introduced then
    begin
      {$if declared(FC_d2i_ECPKParameters)}
      d2i_ECPKParameters := FC_d2i_ECPKParameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ECPKParameters_removed)}
    if d2i_ECPKParameters_removed <= LibVersion then
    begin
      {$if declared(_d2i_ECPKParameters)}
      d2i_ECPKParameters := _d2i_ECPKParameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ECPKParameters_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ECPKParameters');
    {$ifend}
  end;


  i2d_ECPKParameters := LoadLibFunction(ADllHandle, i2d_ECPKParameters_procname);
  FuncLoadError := not assigned(i2d_ECPKParameters);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ECPKParameters_allownil)}
    i2d_ECPKParameters := ERR_i2d_ECPKParameters;
    {$ifend}
    {$if declared(i2d_ECPKParameters_introduced)}
    if LibVersion < i2d_ECPKParameters_introduced then
    begin
      {$if declared(FC_i2d_ECPKParameters)}
      i2d_ECPKParameters := FC_i2d_ECPKParameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ECPKParameters_removed)}
    if i2d_ECPKParameters_removed <= LibVersion then
    begin
      {$if declared(_i2d_ECPKParameters)}
      i2d_ECPKParameters := _i2d_ECPKParameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ECPKParameters_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ECPKParameters');
    {$ifend}
  end;


  ECPKParameters_print := LoadLibFunction(ADllHandle, ECPKParameters_print_procname);
  FuncLoadError := not assigned(ECPKParameters_print);
  if FuncLoadError then
  begin
    {$if not defined(ECPKParameters_print_allownil)}
    ECPKParameters_print := ERR_ECPKParameters_print;
    {$ifend}
    {$if declared(ECPKParameters_print_introduced)}
    if LibVersion < ECPKParameters_print_introduced then
    begin
      {$if declared(FC_ECPKParameters_print)}
      ECPKParameters_print := FC_ECPKParameters_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECPKParameters_print_removed)}
    if ECPKParameters_print_removed <= LibVersion then
    begin
      {$if declared(_ECPKParameters_print)}
      ECPKParameters_print := _ECPKParameters_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECPKParameters_print_allownil)}
    if FuncLoadError then
      AFailed.Add('ECPKParameters_print');
    {$ifend}
  end;


  EC_KEY_new := LoadLibFunction(ADllHandle, EC_KEY_new_procname);
  FuncLoadError := not assigned(EC_KEY_new);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_new_allownil)}
    EC_KEY_new := ERR_EC_KEY_new;
    {$ifend}
    {$if declared(EC_KEY_new_introduced)}
    if LibVersion < EC_KEY_new_introduced then
    begin
      {$if declared(FC_EC_KEY_new)}
      EC_KEY_new := FC_EC_KEY_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_new_removed)}
    if EC_KEY_new_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_new)}
      EC_KEY_new := _EC_KEY_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_new_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_new');
    {$ifend}
  end;


  EC_KEY_get_flags := LoadLibFunction(ADllHandle, EC_KEY_get_flags_procname);
  FuncLoadError := not assigned(EC_KEY_get_flags);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_get_flags_allownil)}
    EC_KEY_get_flags := ERR_EC_KEY_get_flags;
    {$ifend}
    {$if declared(EC_KEY_get_flags_introduced)}
    if LibVersion < EC_KEY_get_flags_introduced then
    begin
      {$if declared(FC_EC_KEY_get_flags)}
      EC_KEY_get_flags := FC_EC_KEY_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_get_flags_removed)}
    if EC_KEY_get_flags_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_get_flags)}
      EC_KEY_get_flags := _EC_KEY_get_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_get_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_get_flags');
    {$ifend}
  end;


  EC_KEY_set_flags := LoadLibFunction(ADllHandle, EC_KEY_set_flags_procname);
  FuncLoadError := not assigned(EC_KEY_set_flags);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_set_flags_allownil)}
    EC_KEY_set_flags := ERR_EC_KEY_set_flags;
    {$ifend}
    {$if declared(EC_KEY_set_flags_introduced)}
    if LibVersion < EC_KEY_set_flags_introduced then
    begin
      {$if declared(FC_EC_KEY_set_flags)}
      EC_KEY_set_flags := FC_EC_KEY_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_set_flags_removed)}
    if EC_KEY_set_flags_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_set_flags)}
      EC_KEY_set_flags := _EC_KEY_set_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_set_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_set_flags');
    {$ifend}
  end;


  EC_KEY_clear_flags := LoadLibFunction(ADllHandle, EC_KEY_clear_flags_procname);
  FuncLoadError := not assigned(EC_KEY_clear_flags);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_clear_flags_allownil)}
    EC_KEY_clear_flags := ERR_EC_KEY_clear_flags;
    {$ifend}
    {$if declared(EC_KEY_clear_flags_introduced)}
    if LibVersion < EC_KEY_clear_flags_introduced then
    begin
      {$if declared(FC_EC_KEY_clear_flags)}
      EC_KEY_clear_flags := FC_EC_KEY_clear_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_clear_flags_removed)}
    if EC_KEY_clear_flags_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_clear_flags)}
      EC_KEY_clear_flags := _EC_KEY_clear_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_clear_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_clear_flags');
    {$ifend}
  end;


  EC_KEY_new_by_curve_name := LoadLibFunction(ADllHandle, EC_KEY_new_by_curve_name_procname);
  FuncLoadError := not assigned(EC_KEY_new_by_curve_name);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_new_by_curve_name_allownil)}
    EC_KEY_new_by_curve_name := ERR_EC_KEY_new_by_curve_name;
    {$ifend}
    {$if declared(EC_KEY_new_by_curve_name_introduced)}
    if LibVersion < EC_KEY_new_by_curve_name_introduced then
    begin
      {$if declared(FC_EC_KEY_new_by_curve_name)}
      EC_KEY_new_by_curve_name := FC_EC_KEY_new_by_curve_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_new_by_curve_name_removed)}
    if EC_KEY_new_by_curve_name_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_new_by_curve_name)}
      EC_KEY_new_by_curve_name := _EC_KEY_new_by_curve_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_new_by_curve_name_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_new_by_curve_name');
    {$ifend}
  end;


  EC_KEY_free := LoadLibFunction(ADllHandle, EC_KEY_free_procname);
  FuncLoadError := not assigned(EC_KEY_free);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_free_allownil)}
    EC_KEY_free := ERR_EC_KEY_free;
    {$ifend}
    {$if declared(EC_KEY_free_introduced)}
    if LibVersion < EC_KEY_free_introduced then
    begin
      {$if declared(FC_EC_KEY_free)}
      EC_KEY_free := FC_EC_KEY_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_free_removed)}
    if EC_KEY_free_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_free)}
      EC_KEY_free := _EC_KEY_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_free_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_free');
    {$ifend}
  end;


  EC_KEY_copy := LoadLibFunction(ADllHandle, EC_KEY_copy_procname);
  FuncLoadError := not assigned(EC_KEY_copy);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_copy_allownil)}
    EC_KEY_copy := ERR_EC_KEY_copy;
    {$ifend}
    {$if declared(EC_KEY_copy_introduced)}
    if LibVersion < EC_KEY_copy_introduced then
    begin
      {$if declared(FC_EC_KEY_copy)}
      EC_KEY_copy := FC_EC_KEY_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_copy_removed)}
    if EC_KEY_copy_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_copy)}
      EC_KEY_copy := _EC_KEY_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_copy_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_copy');
    {$ifend}
  end;


  EC_KEY_dup := LoadLibFunction(ADllHandle, EC_KEY_dup_procname);
  FuncLoadError := not assigned(EC_KEY_dup);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_dup_allownil)}
    EC_KEY_dup := ERR_EC_KEY_dup;
    {$ifend}
    {$if declared(EC_KEY_dup_introduced)}
    if LibVersion < EC_KEY_dup_introduced then
    begin
      {$if declared(FC_EC_KEY_dup)}
      EC_KEY_dup := FC_EC_KEY_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_dup_removed)}
    if EC_KEY_dup_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_dup)}
      EC_KEY_dup := _EC_KEY_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_dup');
    {$ifend}
  end;


  EC_KEY_up_ref := LoadLibFunction(ADllHandle, EC_KEY_up_ref_procname);
  FuncLoadError := not assigned(EC_KEY_up_ref);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_up_ref_allownil)}
    EC_KEY_up_ref := ERR_EC_KEY_up_ref;
    {$ifend}
    {$if declared(EC_KEY_up_ref_introduced)}
    if LibVersion < EC_KEY_up_ref_introduced then
    begin
      {$if declared(FC_EC_KEY_up_ref)}
      EC_KEY_up_ref := FC_EC_KEY_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_up_ref_removed)}
    if EC_KEY_up_ref_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_up_ref)}
      EC_KEY_up_ref := _EC_KEY_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_up_ref_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_up_ref');
    {$ifend}
  end;


  EC_KEY_get0_engine := LoadLibFunction(ADllHandle, EC_KEY_get0_engine_procname);
  FuncLoadError := not assigned(EC_KEY_get0_engine);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_get0_engine_allownil)}
    EC_KEY_get0_engine := ERR_EC_KEY_get0_engine;
    {$ifend}
    {$if declared(EC_KEY_get0_engine_introduced)}
    if LibVersion < EC_KEY_get0_engine_introduced then
    begin
      {$if declared(FC_EC_KEY_get0_engine)}
      EC_KEY_get0_engine := FC_EC_KEY_get0_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_get0_engine_removed)}
    if EC_KEY_get0_engine_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_get0_engine)}
      EC_KEY_get0_engine := _EC_KEY_get0_engine;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_get0_engine_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_get0_engine');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_KEY_get0_group := LoadLibFunction(ADllHandle, EC_KEY_get0_group_procname);
  FuncLoadError := not assigned(EC_KEY_get0_group);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_get0_group_allownil)}
    EC_KEY_get0_group := ERR_EC_KEY_get0_group;
    {$ifend}
    {$if declared(EC_KEY_get0_group_introduced)}
    if LibVersion < EC_KEY_get0_group_introduced then
    begin
      {$if declared(FC_EC_KEY_get0_group)}
      EC_KEY_get0_group := FC_EC_KEY_get0_group;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_get0_group_removed)}
    if EC_KEY_get0_group_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_get0_group)}
      EC_KEY_get0_group := _EC_KEY_get0_group;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_get0_group_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_get0_group');
    {$ifend}
  end;


  EC_KEY_set_group := LoadLibFunction(ADllHandle, EC_KEY_set_group_procname);
  FuncLoadError := not assigned(EC_KEY_set_group);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_set_group_allownil)}
    EC_KEY_set_group := ERR_EC_KEY_set_group;
    {$ifend}
    {$if declared(EC_KEY_set_group_introduced)}
    if LibVersion < EC_KEY_set_group_introduced then
    begin
      {$if declared(FC_EC_KEY_set_group)}
      EC_KEY_set_group := FC_EC_KEY_set_group;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_set_group_removed)}
    if EC_KEY_set_group_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_set_group)}
      EC_KEY_set_group := _EC_KEY_set_group;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_set_group_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_set_group');
    {$ifend}
  end;


  EC_KEY_get0_private_key := LoadLibFunction(ADllHandle, EC_KEY_get0_private_key_procname);
  FuncLoadError := not assigned(EC_KEY_get0_private_key);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_get0_private_key_allownil)}
    EC_KEY_get0_private_key := ERR_EC_KEY_get0_private_key;
    {$ifend}
    {$if declared(EC_KEY_get0_private_key_introduced)}
    if LibVersion < EC_KEY_get0_private_key_introduced then
    begin
      {$if declared(FC_EC_KEY_get0_private_key)}
      EC_KEY_get0_private_key := FC_EC_KEY_get0_private_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_get0_private_key_removed)}
    if EC_KEY_get0_private_key_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_get0_private_key)}
      EC_KEY_get0_private_key := _EC_KEY_get0_private_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_get0_private_key_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_get0_private_key');
    {$ifend}
  end;


  EC_KEY_set_private_key := LoadLibFunction(ADllHandle, EC_KEY_set_private_key_procname);
  FuncLoadError := not assigned(EC_KEY_set_private_key);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_set_private_key_allownil)}
    EC_KEY_set_private_key := ERR_EC_KEY_set_private_key;
    {$ifend}
    {$if declared(EC_KEY_set_private_key_introduced)}
    if LibVersion < EC_KEY_set_private_key_introduced then
    begin
      {$if declared(FC_EC_KEY_set_private_key)}
      EC_KEY_set_private_key := FC_EC_KEY_set_private_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_set_private_key_removed)}
    if EC_KEY_set_private_key_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_set_private_key)}
      EC_KEY_set_private_key := _EC_KEY_set_private_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_set_private_key_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_set_private_key');
    {$ifend}
  end;


  EC_KEY_get0_public_key := LoadLibFunction(ADllHandle, EC_KEY_get0_public_key_procname);
  FuncLoadError := not assigned(EC_KEY_get0_public_key);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_get0_public_key_allownil)}
    EC_KEY_get0_public_key := ERR_EC_KEY_get0_public_key;
    {$ifend}
    {$if declared(EC_KEY_get0_public_key_introduced)}
    if LibVersion < EC_KEY_get0_public_key_introduced then
    begin
      {$if declared(FC_EC_KEY_get0_public_key)}
      EC_KEY_get0_public_key := FC_EC_KEY_get0_public_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_get0_public_key_removed)}
    if EC_KEY_get0_public_key_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_get0_public_key)}
      EC_KEY_get0_public_key := _EC_KEY_get0_public_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_get0_public_key_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_get0_public_key');
    {$ifend}
  end;


  EC_KEY_set_public_key := LoadLibFunction(ADllHandle, EC_KEY_set_public_key_procname);
  FuncLoadError := not assigned(EC_KEY_set_public_key);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_set_public_key_allownil)}
    EC_KEY_set_public_key := ERR_EC_KEY_set_public_key;
    {$ifend}
    {$if declared(EC_KEY_set_public_key_introduced)}
    if LibVersion < EC_KEY_set_public_key_introduced then
    begin
      {$if declared(FC_EC_KEY_set_public_key)}
      EC_KEY_set_public_key := FC_EC_KEY_set_public_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_set_public_key_removed)}
    if EC_KEY_set_public_key_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_set_public_key)}
      EC_KEY_set_public_key := _EC_KEY_set_public_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_set_public_key_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_set_public_key');
    {$ifend}
  end;


  EC_KEY_get_enc_flags := LoadLibFunction(ADllHandle, EC_KEY_get_enc_flags_procname);
  FuncLoadError := not assigned(EC_KEY_get_enc_flags);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_get_enc_flags_allownil)}
    EC_KEY_get_enc_flags := ERR_EC_KEY_get_enc_flags;
    {$ifend}
    {$if declared(EC_KEY_get_enc_flags_introduced)}
    if LibVersion < EC_KEY_get_enc_flags_introduced then
    begin
      {$if declared(FC_EC_KEY_get_enc_flags)}
      EC_KEY_get_enc_flags := FC_EC_KEY_get_enc_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_get_enc_flags_removed)}
    if EC_KEY_get_enc_flags_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_get_enc_flags)}
      EC_KEY_get_enc_flags := _EC_KEY_get_enc_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_get_enc_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_get_enc_flags');
    {$ifend}
  end;


  EC_KEY_set_enc_flags := LoadLibFunction(ADllHandle, EC_KEY_set_enc_flags_procname);
  FuncLoadError := not assigned(EC_KEY_set_enc_flags);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_set_enc_flags_allownil)}
    EC_KEY_set_enc_flags := ERR_EC_KEY_set_enc_flags;
    {$ifend}
    {$if declared(EC_KEY_set_enc_flags_introduced)}
    if LibVersion < EC_KEY_set_enc_flags_introduced then
    begin
      {$if declared(FC_EC_KEY_set_enc_flags)}
      EC_KEY_set_enc_flags := FC_EC_KEY_set_enc_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_set_enc_flags_removed)}
    if EC_KEY_set_enc_flags_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_set_enc_flags)}
      EC_KEY_set_enc_flags := _EC_KEY_set_enc_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_set_enc_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_set_enc_flags');
    {$ifend}
  end;


  EC_KEY_get_conv_form := LoadLibFunction(ADllHandle, EC_KEY_get_conv_form_procname);
  FuncLoadError := not assigned(EC_KEY_get_conv_form);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_get_conv_form_allownil)}
    EC_KEY_get_conv_form := ERR_EC_KEY_get_conv_form;
    {$ifend}
    {$if declared(EC_KEY_get_conv_form_introduced)}
    if LibVersion < EC_KEY_get_conv_form_introduced then
    begin
      {$if declared(FC_EC_KEY_get_conv_form)}
      EC_KEY_get_conv_form := FC_EC_KEY_get_conv_form;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_get_conv_form_removed)}
    if EC_KEY_get_conv_form_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_get_conv_form)}
      EC_KEY_get_conv_form := _EC_KEY_get_conv_form;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_get_conv_form_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_get_conv_form');
    {$ifend}
  end;


  EC_KEY_set_conv_form := LoadLibFunction(ADllHandle, EC_KEY_set_conv_form_procname);
  FuncLoadError := not assigned(EC_KEY_set_conv_form);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_set_conv_form_allownil)}
    EC_KEY_set_conv_form := ERR_EC_KEY_set_conv_form;
    {$ifend}
    {$if declared(EC_KEY_set_conv_form_introduced)}
    if LibVersion < EC_KEY_set_conv_form_introduced then
    begin
      {$if declared(FC_EC_KEY_set_conv_form)}
      EC_KEY_set_conv_form := FC_EC_KEY_set_conv_form;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_set_conv_form_removed)}
    if EC_KEY_set_conv_form_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_set_conv_form)}
      EC_KEY_set_conv_form := _EC_KEY_set_conv_form;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_set_conv_form_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_set_conv_form');
    {$ifend}
  end;


  EC_KEY_set_ex_data := LoadLibFunction(ADllHandle, EC_KEY_set_ex_data_procname);
  FuncLoadError := not assigned(EC_KEY_set_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_set_ex_data_allownil)}
    EC_KEY_set_ex_data := ERR_EC_KEY_set_ex_data;
    {$ifend}
    {$if declared(EC_KEY_set_ex_data_introduced)}
    if LibVersion < EC_KEY_set_ex_data_introduced then
    begin
      {$if declared(FC_EC_KEY_set_ex_data)}
      EC_KEY_set_ex_data := FC_EC_KEY_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_set_ex_data_removed)}
    if EC_KEY_set_ex_data_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_set_ex_data)}
      EC_KEY_set_ex_data := _EC_KEY_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_set_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_set_ex_data');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_KEY_get_ex_data := LoadLibFunction(ADllHandle, EC_KEY_get_ex_data_procname);
  FuncLoadError := not assigned(EC_KEY_get_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_get_ex_data_allownil)}
    EC_KEY_get_ex_data := ERR_EC_KEY_get_ex_data;
    {$ifend}
    {$if declared(EC_KEY_get_ex_data_introduced)}
    if LibVersion < EC_KEY_get_ex_data_introduced then
    begin
      {$if declared(FC_EC_KEY_get_ex_data)}
      EC_KEY_get_ex_data := FC_EC_KEY_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_get_ex_data_removed)}
    if EC_KEY_get_ex_data_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_get_ex_data)}
      EC_KEY_get_ex_data := _EC_KEY_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_get_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_get_ex_data');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_KEY_set_asn1_flag := LoadLibFunction(ADllHandle, EC_KEY_set_asn1_flag_procname);
  FuncLoadError := not assigned(EC_KEY_set_asn1_flag);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_set_asn1_flag_allownil)}
    EC_KEY_set_asn1_flag := ERR_EC_KEY_set_asn1_flag;
    {$ifend}
    {$if declared(EC_KEY_set_asn1_flag_introduced)}
    if LibVersion < EC_KEY_set_asn1_flag_introduced then
    begin
      {$if declared(FC_EC_KEY_set_asn1_flag)}
      EC_KEY_set_asn1_flag := FC_EC_KEY_set_asn1_flag;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_set_asn1_flag_removed)}
    if EC_KEY_set_asn1_flag_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_set_asn1_flag)}
      EC_KEY_set_asn1_flag := _EC_KEY_set_asn1_flag;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_set_asn1_flag_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_set_asn1_flag');
    {$ifend}
  end;


  EC_KEY_precompute_mult := LoadLibFunction(ADllHandle, EC_KEY_precompute_mult_procname);
  FuncLoadError := not assigned(EC_KEY_precompute_mult);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_precompute_mult_allownil)}
    EC_KEY_precompute_mult := ERR_EC_KEY_precompute_mult;
    {$ifend}
    {$if declared(EC_KEY_precompute_mult_introduced)}
    if LibVersion < EC_KEY_precompute_mult_introduced then
    begin
      {$if declared(FC_EC_KEY_precompute_mult)}
      EC_KEY_precompute_mult := FC_EC_KEY_precompute_mult;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_precompute_mult_removed)}
    if EC_KEY_precompute_mult_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_precompute_mult)}
      EC_KEY_precompute_mult := _EC_KEY_precompute_mult;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_precompute_mult_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_precompute_mult');
    {$ifend}
  end;


  EC_KEY_generate_key := LoadLibFunction(ADllHandle, EC_KEY_generate_key_procname);
  FuncLoadError := not assigned(EC_KEY_generate_key);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_generate_key_allownil)}
    EC_KEY_generate_key := ERR_EC_KEY_generate_key;
    {$ifend}
    {$if declared(EC_KEY_generate_key_introduced)}
    if LibVersion < EC_KEY_generate_key_introduced then
    begin
      {$if declared(FC_EC_KEY_generate_key)}
      EC_KEY_generate_key := FC_EC_KEY_generate_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_generate_key_removed)}
    if EC_KEY_generate_key_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_generate_key)}
      EC_KEY_generate_key := _EC_KEY_generate_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_generate_key_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_generate_key');
    {$ifend}
  end;


  EC_KEY_check_key := LoadLibFunction(ADllHandle, EC_KEY_check_key_procname);
  FuncLoadError := not assigned(EC_KEY_check_key);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_check_key_allownil)}
    EC_KEY_check_key := ERR_EC_KEY_check_key;
    {$ifend}
    {$if declared(EC_KEY_check_key_introduced)}
    if LibVersion < EC_KEY_check_key_introduced then
    begin
      {$if declared(FC_EC_KEY_check_key)}
      EC_KEY_check_key := FC_EC_KEY_check_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_check_key_removed)}
    if EC_KEY_check_key_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_check_key)}
      EC_KEY_check_key := _EC_KEY_check_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_check_key_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_check_key');
    {$ifend}
  end;


  EC_KEY_can_sign := LoadLibFunction(ADllHandle, EC_KEY_can_sign_procname);
  FuncLoadError := not assigned(EC_KEY_can_sign);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_can_sign_allownil)}
    EC_KEY_can_sign := ERR_EC_KEY_can_sign;
    {$ifend}
    {$if declared(EC_KEY_can_sign_introduced)}
    if LibVersion < EC_KEY_can_sign_introduced then
    begin
      {$if declared(FC_EC_KEY_can_sign)}
      EC_KEY_can_sign := FC_EC_KEY_can_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_can_sign_removed)}
    if EC_KEY_can_sign_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_can_sign)}
      EC_KEY_can_sign := _EC_KEY_can_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_can_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_can_sign');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_KEY_set_public_key_affine_coordinates := LoadLibFunction(ADllHandle, EC_KEY_set_public_key_affine_coordinates_procname);
  FuncLoadError := not assigned(EC_KEY_set_public_key_affine_coordinates);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_set_public_key_affine_coordinates_allownil)}
    EC_KEY_set_public_key_affine_coordinates := ERR_EC_KEY_set_public_key_affine_coordinates;
    {$ifend}
    {$if declared(EC_KEY_set_public_key_affine_coordinates_introduced)}
    if LibVersion < EC_KEY_set_public_key_affine_coordinates_introduced then
    begin
      {$if declared(FC_EC_KEY_set_public_key_affine_coordinates)}
      EC_KEY_set_public_key_affine_coordinates := FC_EC_KEY_set_public_key_affine_coordinates;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_set_public_key_affine_coordinates_removed)}
    if EC_KEY_set_public_key_affine_coordinates_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_set_public_key_affine_coordinates)}
      EC_KEY_set_public_key_affine_coordinates := _EC_KEY_set_public_key_affine_coordinates;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_set_public_key_affine_coordinates_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_set_public_key_affine_coordinates');
    {$ifend}
  end;


  EC_KEY_key2buf := LoadLibFunction(ADllHandle, EC_KEY_key2buf_procname);
  FuncLoadError := not assigned(EC_KEY_key2buf);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_key2buf_allownil)}
    EC_KEY_key2buf := ERR_EC_KEY_key2buf;
    {$ifend}
    {$if declared(EC_KEY_key2buf_introduced)}
    if LibVersion < EC_KEY_key2buf_introduced then
    begin
      {$if declared(FC_EC_KEY_key2buf)}
      EC_KEY_key2buf := FC_EC_KEY_key2buf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_key2buf_removed)}
    if EC_KEY_key2buf_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_key2buf)}
      EC_KEY_key2buf := _EC_KEY_key2buf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_key2buf_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_key2buf');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_KEY_oct2key := LoadLibFunction(ADllHandle, EC_KEY_oct2key_procname);
  FuncLoadError := not assigned(EC_KEY_oct2key);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_oct2key_allownil)}
    EC_KEY_oct2key := ERR_EC_KEY_oct2key;
    {$ifend}
    {$if declared(EC_KEY_oct2key_introduced)}
    if LibVersion < EC_KEY_oct2key_introduced then
    begin
      {$if declared(FC_EC_KEY_oct2key)}
      EC_KEY_oct2key := FC_EC_KEY_oct2key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_oct2key_removed)}
    if EC_KEY_oct2key_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_oct2key)}
      EC_KEY_oct2key := _EC_KEY_oct2key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_oct2key_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_oct2key');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_KEY_oct2priv := LoadLibFunction(ADllHandle, EC_KEY_oct2priv_procname);
  FuncLoadError := not assigned(EC_KEY_oct2priv);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_oct2priv_allownil)}
    EC_KEY_oct2priv := ERR_EC_KEY_oct2priv;
    {$ifend}
    {$if declared(EC_KEY_oct2priv_introduced)}
    if LibVersion < EC_KEY_oct2priv_introduced then
    begin
      {$if declared(FC_EC_KEY_oct2priv)}
      EC_KEY_oct2priv := FC_EC_KEY_oct2priv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_oct2priv_removed)}
    if EC_KEY_oct2priv_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_oct2priv)}
      EC_KEY_oct2priv := _EC_KEY_oct2priv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_oct2priv_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_oct2priv');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_KEY_priv2oct := LoadLibFunction(ADllHandle, EC_KEY_priv2oct_procname);
  FuncLoadError := not assigned(EC_KEY_priv2oct);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_priv2oct_allownil)}
    EC_KEY_priv2oct := ERR_EC_KEY_priv2oct;
    {$ifend}
    {$if declared(EC_KEY_priv2oct_introduced)}
    if LibVersion < EC_KEY_priv2oct_introduced then
    begin
      {$if declared(FC_EC_KEY_priv2oct)}
      EC_KEY_priv2oct := FC_EC_KEY_priv2oct;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_priv2oct_removed)}
    if EC_KEY_priv2oct_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_priv2oct)}
      EC_KEY_priv2oct := _EC_KEY_priv2oct;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_priv2oct_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_priv2oct');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_KEY_priv2buf := LoadLibFunction(ADllHandle, EC_KEY_priv2buf_procname);
  FuncLoadError := not assigned(EC_KEY_priv2buf);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_priv2buf_allownil)}
    EC_KEY_priv2buf := ERR_EC_KEY_priv2buf;
    {$ifend}
    {$if declared(EC_KEY_priv2buf_introduced)}
    if LibVersion < EC_KEY_priv2buf_introduced then
    begin
      {$if declared(FC_EC_KEY_priv2buf)}
      EC_KEY_priv2buf := FC_EC_KEY_priv2buf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_priv2buf_removed)}
    if EC_KEY_priv2buf_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_priv2buf)}
      EC_KEY_priv2buf := _EC_KEY_priv2buf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_priv2buf_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_priv2buf');
    {$ifend}
  end;

 {introduced 1.1.0}
  d2i_ECPrivateKey := LoadLibFunction(ADllHandle, d2i_ECPrivateKey_procname);
  FuncLoadError := not assigned(d2i_ECPrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ECPrivateKey_allownil)}
    d2i_ECPrivateKey := ERR_d2i_ECPrivateKey;
    {$ifend}
    {$if declared(d2i_ECPrivateKey_introduced)}
    if LibVersion < d2i_ECPrivateKey_introduced then
    begin
      {$if declared(FC_d2i_ECPrivateKey)}
      d2i_ECPrivateKey := FC_d2i_ECPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ECPrivateKey_removed)}
    if d2i_ECPrivateKey_removed <= LibVersion then
    begin
      {$if declared(_d2i_ECPrivateKey)}
      d2i_ECPrivateKey := _d2i_ECPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ECPrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ECPrivateKey');
    {$ifend}
  end;


  i2d_ECPrivateKey := LoadLibFunction(ADllHandle, i2d_ECPrivateKey_procname);
  FuncLoadError := not assigned(i2d_ECPrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ECPrivateKey_allownil)}
    i2d_ECPrivateKey := ERR_i2d_ECPrivateKey;
    {$ifend}
    {$if declared(i2d_ECPrivateKey_introduced)}
    if LibVersion < i2d_ECPrivateKey_introduced then
    begin
      {$if declared(FC_i2d_ECPrivateKey)}
      i2d_ECPrivateKey := FC_i2d_ECPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ECPrivateKey_removed)}
    if i2d_ECPrivateKey_removed <= LibVersion then
    begin
      {$if declared(_i2d_ECPrivateKey)}
      i2d_ECPrivateKey := _i2d_ECPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ECPrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ECPrivateKey');
    {$ifend}
  end;


  o2i_ECPublicKey := LoadLibFunction(ADllHandle, o2i_ECPublicKey_procname);
  FuncLoadError := not assigned(o2i_ECPublicKey);
  if FuncLoadError then
  begin
    {$if not defined(o2i_ECPublicKey_allownil)}
    o2i_ECPublicKey := ERR_o2i_ECPublicKey;
    {$ifend}
    {$if declared(o2i_ECPublicKey_introduced)}
    if LibVersion < o2i_ECPublicKey_introduced then
    begin
      {$if declared(FC_o2i_ECPublicKey)}
      o2i_ECPublicKey := FC_o2i_ECPublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(o2i_ECPublicKey_removed)}
    if o2i_ECPublicKey_removed <= LibVersion then
    begin
      {$if declared(_o2i_ECPublicKey)}
      o2i_ECPublicKey := _o2i_ECPublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(o2i_ECPublicKey_allownil)}
    if FuncLoadError then
      AFailed.Add('o2i_ECPublicKey');
    {$ifend}
  end;


  i2o_ECPublicKey := LoadLibFunction(ADllHandle, i2o_ECPublicKey_procname);
  FuncLoadError := not assigned(i2o_ECPublicKey);
  if FuncLoadError then
  begin
    {$if not defined(i2o_ECPublicKey_allownil)}
    i2o_ECPublicKey := ERR_i2o_ECPublicKey;
    {$ifend}
    {$if declared(i2o_ECPublicKey_introduced)}
    if LibVersion < i2o_ECPublicKey_introduced then
    begin
      {$if declared(FC_i2o_ECPublicKey)}
      i2o_ECPublicKey := FC_i2o_ECPublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2o_ECPublicKey_removed)}
    if i2o_ECPublicKey_removed <= LibVersion then
    begin
      {$if declared(_i2o_ECPublicKey)}
      i2o_ECPublicKey := _i2o_ECPublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2o_ECPublicKey_allownil)}
    if FuncLoadError then
      AFailed.Add('i2o_ECPublicKey');
    {$ifend}
  end;


  ECParameters_print := LoadLibFunction(ADllHandle, ECParameters_print_procname);
  FuncLoadError := not assigned(ECParameters_print);
  if FuncLoadError then
  begin
    {$if not defined(ECParameters_print_allownil)}
    ECParameters_print := ERR_ECParameters_print;
    {$ifend}
    {$if declared(ECParameters_print_introduced)}
    if LibVersion < ECParameters_print_introduced then
    begin
      {$if declared(FC_ECParameters_print)}
      ECParameters_print := FC_ECParameters_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECParameters_print_removed)}
    if ECParameters_print_removed <= LibVersion then
    begin
      {$if declared(_ECParameters_print)}
      ECParameters_print := _ECParameters_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECParameters_print_allownil)}
    if FuncLoadError then
      AFailed.Add('ECParameters_print');
    {$ifend}
  end;


  EC_KEY_print := LoadLibFunction(ADllHandle, EC_KEY_print_procname);
  FuncLoadError := not assigned(EC_KEY_print);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_print_allownil)}
    EC_KEY_print := ERR_EC_KEY_print;
    {$ifend}
    {$if declared(EC_KEY_print_introduced)}
    if LibVersion < EC_KEY_print_introduced then
    begin
      {$if declared(FC_EC_KEY_print)}
      EC_KEY_print := FC_EC_KEY_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_print_removed)}
    if EC_KEY_print_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_print)}
      EC_KEY_print := _EC_KEY_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_print_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_print');
    {$ifend}
  end;


  EC_KEY_OpenSSL := LoadLibFunction(ADllHandle, EC_KEY_OpenSSL_procname);
  FuncLoadError := not assigned(EC_KEY_OpenSSL);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_OpenSSL_allownil)}
    EC_KEY_OpenSSL := ERR_EC_KEY_OpenSSL;
    {$ifend}
    {$if declared(EC_KEY_OpenSSL_introduced)}
    if LibVersion < EC_KEY_OpenSSL_introduced then
    begin
      {$if declared(FC_EC_KEY_OpenSSL)}
      EC_KEY_OpenSSL := FC_EC_KEY_OpenSSL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_OpenSSL_removed)}
    if EC_KEY_OpenSSL_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_OpenSSL)}
      EC_KEY_OpenSSL := _EC_KEY_OpenSSL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_OpenSSL_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_OpenSSL');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_KEY_get_default_method := LoadLibFunction(ADllHandle, EC_KEY_get_default_method_procname);
  FuncLoadError := not assigned(EC_KEY_get_default_method);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_get_default_method_allownil)}
    EC_KEY_get_default_method := ERR_EC_KEY_get_default_method;
    {$ifend}
    {$if declared(EC_KEY_get_default_method_introduced)}
    if LibVersion < EC_KEY_get_default_method_introduced then
    begin
      {$if declared(FC_EC_KEY_get_default_method)}
      EC_KEY_get_default_method := FC_EC_KEY_get_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_get_default_method_removed)}
    if EC_KEY_get_default_method_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_get_default_method)}
      EC_KEY_get_default_method := _EC_KEY_get_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_get_default_method_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_get_default_method');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_KEY_set_default_method := LoadLibFunction(ADllHandle, EC_KEY_set_default_method_procname);
  FuncLoadError := not assigned(EC_KEY_set_default_method);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_set_default_method_allownil)}
    EC_KEY_set_default_method := ERR_EC_KEY_set_default_method;
    {$ifend}
    {$if declared(EC_KEY_set_default_method_introduced)}
    if LibVersion < EC_KEY_set_default_method_introduced then
    begin
      {$if declared(FC_EC_KEY_set_default_method)}
      EC_KEY_set_default_method := FC_EC_KEY_set_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_set_default_method_removed)}
    if EC_KEY_set_default_method_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_set_default_method)}
      EC_KEY_set_default_method := _EC_KEY_set_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_set_default_method_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_set_default_method');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_KEY_get_method := LoadLibFunction(ADllHandle, EC_KEY_get_method_procname);
  FuncLoadError := not assigned(EC_KEY_get_method);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_get_method_allownil)}
    EC_KEY_get_method := ERR_EC_KEY_get_method;
    {$ifend}
    {$if declared(EC_KEY_get_method_introduced)}
    if LibVersion < EC_KEY_get_method_introduced then
    begin
      {$if declared(FC_EC_KEY_get_method)}
      EC_KEY_get_method := FC_EC_KEY_get_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_get_method_removed)}
    if EC_KEY_get_method_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_get_method)}
      EC_KEY_get_method := _EC_KEY_get_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_get_method_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_get_method');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_KEY_set_method := LoadLibFunction(ADllHandle, EC_KEY_set_method_procname);
  FuncLoadError := not assigned(EC_KEY_set_method);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_set_method_allownil)}
    EC_KEY_set_method := ERR_EC_KEY_set_method;
    {$ifend}
    {$if declared(EC_KEY_set_method_introduced)}
    if LibVersion < EC_KEY_set_method_introduced then
    begin
      {$if declared(FC_EC_KEY_set_method)}
      EC_KEY_set_method := FC_EC_KEY_set_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_set_method_removed)}
    if EC_KEY_set_method_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_set_method)}
      EC_KEY_set_method := _EC_KEY_set_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_set_method_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_set_method');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_KEY_new_method := LoadLibFunction(ADllHandle, EC_KEY_new_method_procname);
  FuncLoadError := not assigned(EC_KEY_new_method);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_new_method_allownil)}
    EC_KEY_new_method := ERR_EC_KEY_new_method;
    {$ifend}
    {$if declared(EC_KEY_new_method_introduced)}
    if LibVersion < EC_KEY_new_method_introduced then
    begin
      {$if declared(FC_EC_KEY_new_method)}
      EC_KEY_new_method := FC_EC_KEY_new_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_new_method_removed)}
    if EC_KEY_new_method_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_new_method)}
      EC_KEY_new_method := _EC_KEY_new_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_new_method_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_new_method');
    {$ifend}
  end;

 {introduced 1.1.0}
  ECDH_KDF_X9_62 := LoadLibFunction(ADllHandle, ECDH_KDF_X9_62_procname);
  FuncLoadError := not assigned(ECDH_KDF_X9_62);
  if FuncLoadError then
  begin
    {$if not defined(ECDH_KDF_X9_62_allownil)}
    ECDH_KDF_X9_62 := ERR_ECDH_KDF_X9_62;
    {$ifend}
    {$if declared(ECDH_KDF_X9_62_introduced)}
    if LibVersion < ECDH_KDF_X9_62_introduced then
    begin
      {$if declared(FC_ECDH_KDF_X9_62)}
      ECDH_KDF_X9_62 := FC_ECDH_KDF_X9_62;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECDH_KDF_X9_62_removed)}
    if ECDH_KDF_X9_62_removed <= LibVersion then
    begin
      {$if declared(_ECDH_KDF_X9_62)}
      ECDH_KDF_X9_62 := _ECDH_KDF_X9_62;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECDH_KDF_X9_62_allownil)}
    if FuncLoadError then
      AFailed.Add('ECDH_KDF_X9_62');
    {$ifend}
  end;


  ECDH_compute_key := LoadLibFunction(ADllHandle, ECDH_compute_key_procname);
  FuncLoadError := not assigned(ECDH_compute_key);
  if FuncLoadError then
  begin
    {$if not defined(ECDH_compute_key_allownil)}
    ECDH_compute_key := ERR_ECDH_compute_key;
    {$ifend}
    {$if declared(ECDH_compute_key_introduced)}
    if LibVersion < ECDH_compute_key_introduced then
    begin
      {$if declared(FC_ECDH_compute_key)}
      ECDH_compute_key := FC_ECDH_compute_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECDH_compute_key_removed)}
    if ECDH_compute_key_removed <= LibVersion then
    begin
      {$if declared(_ECDH_compute_key)}
      ECDH_compute_key := _ECDH_compute_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECDH_compute_key_allownil)}
    if FuncLoadError then
      AFailed.Add('ECDH_compute_key');
    {$ifend}
  end;


  ECDSA_SIG_new := LoadLibFunction(ADllHandle, ECDSA_SIG_new_procname);
  FuncLoadError := not assigned(ECDSA_SIG_new);
  if FuncLoadError then
  begin
    {$if not defined(ECDSA_SIG_new_allownil)}
    ECDSA_SIG_new := ERR_ECDSA_SIG_new;
    {$ifend}
    {$if declared(ECDSA_SIG_new_introduced)}
    if LibVersion < ECDSA_SIG_new_introduced then
    begin
      {$if declared(FC_ECDSA_SIG_new)}
      ECDSA_SIG_new := FC_ECDSA_SIG_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECDSA_SIG_new_removed)}
    if ECDSA_SIG_new_removed <= LibVersion then
    begin
      {$if declared(_ECDSA_SIG_new)}
      ECDSA_SIG_new := _ECDSA_SIG_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECDSA_SIG_new_allownil)}
    if FuncLoadError then
      AFailed.Add('ECDSA_SIG_new');
    {$ifend}
  end;


  ECDSA_SIG_free := LoadLibFunction(ADllHandle, ECDSA_SIG_free_procname);
  FuncLoadError := not assigned(ECDSA_SIG_free);
  if FuncLoadError then
  begin
    {$if not defined(ECDSA_SIG_free_allownil)}
    ECDSA_SIG_free := ERR_ECDSA_SIG_free;
    {$ifend}
    {$if declared(ECDSA_SIG_free_introduced)}
    if LibVersion < ECDSA_SIG_free_introduced then
    begin
      {$if declared(FC_ECDSA_SIG_free)}
      ECDSA_SIG_free := FC_ECDSA_SIG_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECDSA_SIG_free_removed)}
    if ECDSA_SIG_free_removed <= LibVersion then
    begin
      {$if declared(_ECDSA_SIG_free)}
      ECDSA_SIG_free := _ECDSA_SIG_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECDSA_SIG_free_allownil)}
    if FuncLoadError then
      AFailed.Add('ECDSA_SIG_free');
    {$ifend}
  end;


  i2d_ECDSA_SIG := LoadLibFunction(ADllHandle, i2d_ECDSA_SIG_procname);
  FuncLoadError := not assigned(i2d_ECDSA_SIG);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ECDSA_SIG_allownil)}
    i2d_ECDSA_SIG := ERR_i2d_ECDSA_SIG;
    {$ifend}
    {$if declared(i2d_ECDSA_SIG_introduced)}
    if LibVersion < i2d_ECDSA_SIG_introduced then
    begin
      {$if declared(FC_i2d_ECDSA_SIG)}
      i2d_ECDSA_SIG := FC_i2d_ECDSA_SIG;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ECDSA_SIG_removed)}
    if i2d_ECDSA_SIG_removed <= LibVersion then
    begin
      {$if declared(_i2d_ECDSA_SIG)}
      i2d_ECDSA_SIG := _i2d_ECDSA_SIG;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ECDSA_SIG_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ECDSA_SIG');
    {$ifend}
  end;


  d2i_ECDSA_SIG := LoadLibFunction(ADllHandle, d2i_ECDSA_SIG_procname);
  FuncLoadError := not assigned(d2i_ECDSA_SIG);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ECDSA_SIG_allownil)}
    d2i_ECDSA_SIG := ERR_d2i_ECDSA_SIG;
    {$ifend}
    {$if declared(d2i_ECDSA_SIG_introduced)}
    if LibVersion < d2i_ECDSA_SIG_introduced then
    begin
      {$if declared(FC_d2i_ECDSA_SIG)}
      d2i_ECDSA_SIG := FC_d2i_ECDSA_SIG;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ECDSA_SIG_removed)}
    if d2i_ECDSA_SIG_removed <= LibVersion then
    begin
      {$if declared(_d2i_ECDSA_SIG)}
      d2i_ECDSA_SIG := _d2i_ECDSA_SIG;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ECDSA_SIG_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ECDSA_SIG');
    {$ifend}
  end;


  ECDSA_SIG_get0 := LoadLibFunction(ADllHandle, ECDSA_SIG_get0_procname);
  FuncLoadError := not assigned(ECDSA_SIG_get0);
  if FuncLoadError then
  begin
    {$if not defined(ECDSA_SIG_get0_allownil)}
    ECDSA_SIG_get0 := ERR_ECDSA_SIG_get0;
    {$ifend}
    {$if declared(ECDSA_SIG_get0_introduced)}
    if LibVersion < ECDSA_SIG_get0_introduced then
    begin
      {$if declared(FC_ECDSA_SIG_get0)}
      ECDSA_SIG_get0 := FC_ECDSA_SIG_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECDSA_SIG_get0_removed)}
    if ECDSA_SIG_get0_removed <= LibVersion then
    begin
      {$if declared(_ECDSA_SIG_get0)}
      ECDSA_SIG_get0 := _ECDSA_SIG_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECDSA_SIG_get0_allownil)}
    if FuncLoadError then
      AFailed.Add('ECDSA_SIG_get0');
    {$ifend}
  end;

 {introduced 1.1.0}
  ECDSA_SIG_get0_r := LoadLibFunction(ADllHandle, ECDSA_SIG_get0_r_procname);
  FuncLoadError := not assigned(ECDSA_SIG_get0_r);
  if FuncLoadError then
  begin
    {$if not defined(ECDSA_SIG_get0_r_allownil)}
    ECDSA_SIG_get0_r := ERR_ECDSA_SIG_get0_r;
    {$ifend}
    {$if declared(ECDSA_SIG_get0_r_introduced)}
    if LibVersion < ECDSA_SIG_get0_r_introduced then
    begin
      {$if declared(FC_ECDSA_SIG_get0_r)}
      ECDSA_SIG_get0_r := FC_ECDSA_SIG_get0_r;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECDSA_SIG_get0_r_removed)}
    if ECDSA_SIG_get0_r_removed <= LibVersion then
    begin
      {$if declared(_ECDSA_SIG_get0_r)}
      ECDSA_SIG_get0_r := _ECDSA_SIG_get0_r;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECDSA_SIG_get0_r_allownil)}
    if FuncLoadError then
      AFailed.Add('ECDSA_SIG_get0_r');
    {$ifend}
  end;

 {introduced 1.1.0}
  ECDSA_SIG_get0_s := LoadLibFunction(ADllHandle, ECDSA_SIG_get0_s_procname);
  FuncLoadError := not assigned(ECDSA_SIG_get0_s);
  if FuncLoadError then
  begin
    {$if not defined(ECDSA_SIG_get0_s_allownil)}
    ECDSA_SIG_get0_s := ERR_ECDSA_SIG_get0_s;
    {$ifend}
    {$if declared(ECDSA_SIG_get0_s_introduced)}
    if LibVersion < ECDSA_SIG_get0_s_introduced then
    begin
      {$if declared(FC_ECDSA_SIG_get0_s)}
      ECDSA_SIG_get0_s := FC_ECDSA_SIG_get0_s;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECDSA_SIG_get0_s_removed)}
    if ECDSA_SIG_get0_s_removed <= LibVersion then
    begin
      {$if declared(_ECDSA_SIG_get0_s)}
      ECDSA_SIG_get0_s := _ECDSA_SIG_get0_s;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECDSA_SIG_get0_s_allownil)}
    if FuncLoadError then
      AFailed.Add('ECDSA_SIG_get0_s');
    {$ifend}
  end;

 {introduced 1.1.0}
  ECDSA_SIG_set0 := LoadLibFunction(ADllHandle, ECDSA_SIG_set0_procname);
  FuncLoadError := not assigned(ECDSA_SIG_set0);
  if FuncLoadError then
  begin
    {$if not defined(ECDSA_SIG_set0_allownil)}
    ECDSA_SIG_set0 := ERR_ECDSA_SIG_set0;
    {$ifend}
    {$if declared(ECDSA_SIG_set0_introduced)}
    if LibVersion < ECDSA_SIG_set0_introduced then
    begin
      {$if declared(FC_ECDSA_SIG_set0)}
      ECDSA_SIG_set0 := FC_ECDSA_SIG_set0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECDSA_SIG_set0_removed)}
    if ECDSA_SIG_set0_removed <= LibVersion then
    begin
      {$if declared(_ECDSA_SIG_set0)}
      ECDSA_SIG_set0 := _ECDSA_SIG_set0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECDSA_SIG_set0_allownil)}
    if FuncLoadError then
      AFailed.Add('ECDSA_SIG_set0');
    {$ifend}
  end;

 {introduced 1.1.0}
  ECDSA_do_sign := LoadLibFunction(ADllHandle, ECDSA_do_sign_procname);
  FuncLoadError := not assigned(ECDSA_do_sign);
  if FuncLoadError then
  begin
    {$if not defined(ECDSA_do_sign_allownil)}
    ECDSA_do_sign := ERR_ECDSA_do_sign;
    {$ifend}
    {$if declared(ECDSA_do_sign_introduced)}
    if LibVersion < ECDSA_do_sign_introduced then
    begin
      {$if declared(FC_ECDSA_do_sign)}
      ECDSA_do_sign := FC_ECDSA_do_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECDSA_do_sign_removed)}
    if ECDSA_do_sign_removed <= LibVersion then
    begin
      {$if declared(_ECDSA_do_sign)}
      ECDSA_do_sign := _ECDSA_do_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECDSA_do_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('ECDSA_do_sign');
    {$ifend}
  end;


  ECDSA_do_sign_ex := LoadLibFunction(ADllHandle, ECDSA_do_sign_ex_procname);
  FuncLoadError := not assigned(ECDSA_do_sign_ex);
  if FuncLoadError then
  begin
    {$if not defined(ECDSA_do_sign_ex_allownil)}
    ECDSA_do_sign_ex := ERR_ECDSA_do_sign_ex;
    {$ifend}
    {$if declared(ECDSA_do_sign_ex_introduced)}
    if LibVersion < ECDSA_do_sign_ex_introduced then
    begin
      {$if declared(FC_ECDSA_do_sign_ex)}
      ECDSA_do_sign_ex := FC_ECDSA_do_sign_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECDSA_do_sign_ex_removed)}
    if ECDSA_do_sign_ex_removed <= LibVersion then
    begin
      {$if declared(_ECDSA_do_sign_ex)}
      ECDSA_do_sign_ex := _ECDSA_do_sign_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECDSA_do_sign_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('ECDSA_do_sign_ex');
    {$ifend}
  end;


  ECDSA_do_verify := LoadLibFunction(ADllHandle, ECDSA_do_verify_procname);
  FuncLoadError := not assigned(ECDSA_do_verify);
  if FuncLoadError then
  begin
    {$if not defined(ECDSA_do_verify_allownil)}
    ECDSA_do_verify := ERR_ECDSA_do_verify;
    {$ifend}
    {$if declared(ECDSA_do_verify_introduced)}
    if LibVersion < ECDSA_do_verify_introduced then
    begin
      {$if declared(FC_ECDSA_do_verify)}
      ECDSA_do_verify := FC_ECDSA_do_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECDSA_do_verify_removed)}
    if ECDSA_do_verify_removed <= LibVersion then
    begin
      {$if declared(_ECDSA_do_verify)}
      ECDSA_do_verify := _ECDSA_do_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECDSA_do_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('ECDSA_do_verify');
    {$ifend}
  end;


  ECDSA_sign_setup := LoadLibFunction(ADllHandle, ECDSA_sign_setup_procname);
  FuncLoadError := not assigned(ECDSA_sign_setup);
  if FuncLoadError then
  begin
    {$if not defined(ECDSA_sign_setup_allownil)}
    ECDSA_sign_setup := ERR_ECDSA_sign_setup;
    {$ifend}
    {$if declared(ECDSA_sign_setup_introduced)}
    if LibVersion < ECDSA_sign_setup_introduced then
    begin
      {$if declared(FC_ECDSA_sign_setup)}
      ECDSA_sign_setup := FC_ECDSA_sign_setup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECDSA_sign_setup_removed)}
    if ECDSA_sign_setup_removed <= LibVersion then
    begin
      {$if declared(_ECDSA_sign_setup)}
      ECDSA_sign_setup := _ECDSA_sign_setup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECDSA_sign_setup_allownil)}
    if FuncLoadError then
      AFailed.Add('ECDSA_sign_setup');
    {$ifend}
  end;


  ECDSA_sign := LoadLibFunction(ADllHandle, ECDSA_sign_procname);
  FuncLoadError := not assigned(ECDSA_sign);
  if FuncLoadError then
  begin
    {$if not defined(ECDSA_sign_allownil)}
    ECDSA_sign := ERR_ECDSA_sign;
    {$ifend}
    {$if declared(ECDSA_sign_introduced)}
    if LibVersion < ECDSA_sign_introduced then
    begin
      {$if declared(FC_ECDSA_sign)}
      ECDSA_sign := FC_ECDSA_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECDSA_sign_removed)}
    if ECDSA_sign_removed <= LibVersion then
    begin
      {$if declared(_ECDSA_sign)}
      ECDSA_sign := _ECDSA_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECDSA_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('ECDSA_sign');
    {$ifend}
  end;


  ECDSA_sign_ex := LoadLibFunction(ADllHandle, ECDSA_sign_ex_procname);
  FuncLoadError := not assigned(ECDSA_sign_ex);
  if FuncLoadError then
  begin
    {$if not defined(ECDSA_sign_ex_allownil)}
    ECDSA_sign_ex := ERR_ECDSA_sign_ex;
    {$ifend}
    {$if declared(ECDSA_sign_ex_introduced)}
    if LibVersion < ECDSA_sign_ex_introduced then
    begin
      {$if declared(FC_ECDSA_sign_ex)}
      ECDSA_sign_ex := FC_ECDSA_sign_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECDSA_sign_ex_removed)}
    if ECDSA_sign_ex_removed <= LibVersion then
    begin
      {$if declared(_ECDSA_sign_ex)}
      ECDSA_sign_ex := _ECDSA_sign_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECDSA_sign_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('ECDSA_sign_ex');
    {$ifend}
  end;


  ECDSA_verify := LoadLibFunction(ADllHandle, ECDSA_verify_procname);
  FuncLoadError := not assigned(ECDSA_verify);
  if FuncLoadError then
  begin
    {$if not defined(ECDSA_verify_allownil)}
    ECDSA_verify := ERR_ECDSA_verify;
    {$ifend}
    {$if declared(ECDSA_verify_introduced)}
    if LibVersion < ECDSA_verify_introduced then
    begin
      {$if declared(FC_ECDSA_verify)}
      ECDSA_verify := FC_ECDSA_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECDSA_verify_removed)}
    if ECDSA_verify_removed <= LibVersion then
    begin
      {$if declared(_ECDSA_verify)}
      ECDSA_verify := _ECDSA_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECDSA_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('ECDSA_verify');
    {$ifend}
  end;


  ECDSA_size := LoadLibFunction(ADllHandle, ECDSA_size_procname);
  FuncLoadError := not assigned(ECDSA_size);
  if FuncLoadError then
  begin
    {$if not defined(ECDSA_size_allownil)}
    ECDSA_size := ERR_ECDSA_size;
    {$ifend}
    {$if declared(ECDSA_size_introduced)}
    if LibVersion < ECDSA_size_introduced then
    begin
      {$if declared(FC_ECDSA_size)}
      ECDSA_size := FC_ECDSA_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECDSA_size_removed)}
    if ECDSA_size_removed <= LibVersion then
    begin
      {$if declared(_ECDSA_size)}
      ECDSA_size := _ECDSA_size;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECDSA_size_allownil)}
    if FuncLoadError then
      AFailed.Add('ECDSA_size');
    {$ifend}
  end;


  EC_KEY_METHOD_new := LoadLibFunction(ADllHandle, EC_KEY_METHOD_new_procname);
  FuncLoadError := not assigned(EC_KEY_METHOD_new);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_METHOD_new_allownil)}
    EC_KEY_METHOD_new := ERR_EC_KEY_METHOD_new;
    {$ifend}
    {$if declared(EC_KEY_METHOD_new_introduced)}
    if LibVersion < EC_KEY_METHOD_new_introduced then
    begin
      {$if declared(FC_EC_KEY_METHOD_new)}
      EC_KEY_METHOD_new := FC_EC_KEY_METHOD_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_METHOD_new_removed)}
    if EC_KEY_METHOD_new_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_METHOD_new)}
      EC_KEY_METHOD_new := _EC_KEY_METHOD_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_METHOD_new_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_METHOD_new');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_KEY_METHOD_free := LoadLibFunction(ADllHandle, EC_KEY_METHOD_free_procname);
  FuncLoadError := not assigned(EC_KEY_METHOD_free);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_METHOD_free_allownil)}
    EC_KEY_METHOD_free := ERR_EC_KEY_METHOD_free;
    {$ifend}
    {$if declared(EC_KEY_METHOD_free_introduced)}
    if LibVersion < EC_KEY_METHOD_free_introduced then
    begin
      {$if declared(FC_EC_KEY_METHOD_free)}
      EC_KEY_METHOD_free := FC_EC_KEY_METHOD_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_METHOD_free_removed)}
    if EC_KEY_METHOD_free_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_METHOD_free)}
      EC_KEY_METHOD_free := _EC_KEY_METHOD_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_METHOD_free_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_METHOD_free');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_KEY_METHOD_set_init := LoadLibFunction(ADllHandle, EC_KEY_METHOD_set_init_procname);
  FuncLoadError := not assigned(EC_KEY_METHOD_set_init);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_METHOD_set_init_allownil)}
    EC_KEY_METHOD_set_init := ERR_EC_KEY_METHOD_set_init;
    {$ifend}
    {$if declared(EC_KEY_METHOD_set_init_introduced)}
    if LibVersion < EC_KEY_METHOD_set_init_introduced then
    begin
      {$if declared(FC_EC_KEY_METHOD_set_init)}
      EC_KEY_METHOD_set_init := FC_EC_KEY_METHOD_set_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_METHOD_set_init_removed)}
    if EC_KEY_METHOD_set_init_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_METHOD_set_init)}
      EC_KEY_METHOD_set_init := _EC_KEY_METHOD_set_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_METHOD_set_init_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_METHOD_set_init');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_KEY_METHOD_set_keygen := LoadLibFunction(ADllHandle, EC_KEY_METHOD_set_keygen_procname);
  FuncLoadError := not assigned(EC_KEY_METHOD_set_keygen);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_METHOD_set_keygen_allownil)}
    EC_KEY_METHOD_set_keygen := ERR_EC_KEY_METHOD_set_keygen;
    {$ifend}
    {$if declared(EC_KEY_METHOD_set_keygen_introduced)}
    if LibVersion < EC_KEY_METHOD_set_keygen_introduced then
    begin
      {$if declared(FC_EC_KEY_METHOD_set_keygen)}
      EC_KEY_METHOD_set_keygen := FC_EC_KEY_METHOD_set_keygen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_METHOD_set_keygen_removed)}
    if EC_KEY_METHOD_set_keygen_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_METHOD_set_keygen)}
      EC_KEY_METHOD_set_keygen := _EC_KEY_METHOD_set_keygen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_METHOD_set_keygen_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_METHOD_set_keygen');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_KEY_METHOD_set_compute_key := LoadLibFunction(ADllHandle, EC_KEY_METHOD_set_compute_key_procname);
  FuncLoadError := not assigned(EC_KEY_METHOD_set_compute_key);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_METHOD_set_compute_key_allownil)}
    EC_KEY_METHOD_set_compute_key := ERR_EC_KEY_METHOD_set_compute_key;
    {$ifend}
    {$if declared(EC_KEY_METHOD_set_compute_key_introduced)}
    if LibVersion < EC_KEY_METHOD_set_compute_key_introduced then
    begin
      {$if declared(FC_EC_KEY_METHOD_set_compute_key)}
      EC_KEY_METHOD_set_compute_key := FC_EC_KEY_METHOD_set_compute_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_METHOD_set_compute_key_removed)}
    if EC_KEY_METHOD_set_compute_key_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_METHOD_set_compute_key)}
      EC_KEY_METHOD_set_compute_key := _EC_KEY_METHOD_set_compute_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_METHOD_set_compute_key_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_METHOD_set_compute_key');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_KEY_METHOD_set_sign := LoadLibFunction(ADllHandle, EC_KEY_METHOD_set_sign_procname);
  FuncLoadError := not assigned(EC_KEY_METHOD_set_sign);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_METHOD_set_sign_allownil)}
    EC_KEY_METHOD_set_sign := ERR_EC_KEY_METHOD_set_sign;
    {$ifend}
    {$if declared(EC_KEY_METHOD_set_sign_introduced)}
    if LibVersion < EC_KEY_METHOD_set_sign_introduced then
    begin
      {$if declared(FC_EC_KEY_METHOD_set_sign)}
      EC_KEY_METHOD_set_sign := FC_EC_KEY_METHOD_set_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_METHOD_set_sign_removed)}
    if EC_KEY_METHOD_set_sign_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_METHOD_set_sign)}
      EC_KEY_METHOD_set_sign := _EC_KEY_METHOD_set_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_METHOD_set_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_METHOD_set_sign');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_KEY_METHOD_set_verify := LoadLibFunction(ADllHandle, EC_KEY_METHOD_set_verify_procname);
  FuncLoadError := not assigned(EC_KEY_METHOD_set_verify);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_METHOD_set_verify_allownil)}
    EC_KEY_METHOD_set_verify := ERR_EC_KEY_METHOD_set_verify;
    {$ifend}
    {$if declared(EC_KEY_METHOD_set_verify_introduced)}
    if LibVersion < EC_KEY_METHOD_set_verify_introduced then
    begin
      {$if declared(FC_EC_KEY_METHOD_set_verify)}
      EC_KEY_METHOD_set_verify := FC_EC_KEY_METHOD_set_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_METHOD_set_verify_removed)}
    if EC_KEY_METHOD_set_verify_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_METHOD_set_verify)}
      EC_KEY_METHOD_set_verify := _EC_KEY_METHOD_set_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_METHOD_set_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_METHOD_set_verify');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_KEY_METHOD_get_init := LoadLibFunction(ADllHandle, EC_KEY_METHOD_get_init_procname);
  FuncLoadError := not assigned(EC_KEY_METHOD_get_init);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_METHOD_get_init_allownil)}
    EC_KEY_METHOD_get_init := ERR_EC_KEY_METHOD_get_init;
    {$ifend}
    {$if declared(EC_KEY_METHOD_get_init_introduced)}
    if LibVersion < EC_KEY_METHOD_get_init_introduced then
    begin
      {$if declared(FC_EC_KEY_METHOD_get_init)}
      EC_KEY_METHOD_get_init := FC_EC_KEY_METHOD_get_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_METHOD_get_init_removed)}
    if EC_KEY_METHOD_get_init_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_METHOD_get_init)}
      EC_KEY_METHOD_get_init := _EC_KEY_METHOD_get_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_METHOD_get_init_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_METHOD_get_init');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_KEY_METHOD_get_keygen := LoadLibFunction(ADllHandle, EC_KEY_METHOD_get_keygen_procname);
  FuncLoadError := not assigned(EC_KEY_METHOD_get_keygen);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_METHOD_get_keygen_allownil)}
    EC_KEY_METHOD_get_keygen := ERR_EC_KEY_METHOD_get_keygen;
    {$ifend}
    {$if declared(EC_KEY_METHOD_get_keygen_introduced)}
    if LibVersion < EC_KEY_METHOD_get_keygen_introduced then
    begin
      {$if declared(FC_EC_KEY_METHOD_get_keygen)}
      EC_KEY_METHOD_get_keygen := FC_EC_KEY_METHOD_get_keygen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_METHOD_get_keygen_removed)}
    if EC_KEY_METHOD_get_keygen_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_METHOD_get_keygen)}
      EC_KEY_METHOD_get_keygen := _EC_KEY_METHOD_get_keygen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_METHOD_get_keygen_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_METHOD_get_keygen');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_KEY_METHOD_get_compute_key := LoadLibFunction(ADllHandle, EC_KEY_METHOD_get_compute_key_procname);
  FuncLoadError := not assigned(EC_KEY_METHOD_get_compute_key);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_METHOD_get_compute_key_allownil)}
    EC_KEY_METHOD_get_compute_key := ERR_EC_KEY_METHOD_get_compute_key;
    {$ifend}
    {$if declared(EC_KEY_METHOD_get_compute_key_introduced)}
    if LibVersion < EC_KEY_METHOD_get_compute_key_introduced then
    begin
      {$if declared(FC_EC_KEY_METHOD_get_compute_key)}
      EC_KEY_METHOD_get_compute_key := FC_EC_KEY_METHOD_get_compute_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_METHOD_get_compute_key_removed)}
    if EC_KEY_METHOD_get_compute_key_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_METHOD_get_compute_key)}
      EC_KEY_METHOD_get_compute_key := _EC_KEY_METHOD_get_compute_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_METHOD_get_compute_key_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_METHOD_get_compute_key');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_KEY_METHOD_get_sign := LoadLibFunction(ADllHandle, EC_KEY_METHOD_get_sign_procname);
  FuncLoadError := not assigned(EC_KEY_METHOD_get_sign);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_METHOD_get_sign_allownil)}
    EC_KEY_METHOD_get_sign := ERR_EC_KEY_METHOD_get_sign;
    {$ifend}
    {$if declared(EC_KEY_METHOD_get_sign_introduced)}
    if LibVersion < EC_KEY_METHOD_get_sign_introduced then
    begin
      {$if declared(FC_EC_KEY_METHOD_get_sign)}
      EC_KEY_METHOD_get_sign := FC_EC_KEY_METHOD_get_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_METHOD_get_sign_removed)}
    if EC_KEY_METHOD_get_sign_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_METHOD_get_sign)}
      EC_KEY_METHOD_get_sign := _EC_KEY_METHOD_get_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_METHOD_get_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_METHOD_get_sign');
    {$ifend}
  end;

 {introduced 1.1.0}
  EC_KEY_METHOD_get_verify := LoadLibFunction(ADllHandle, EC_KEY_METHOD_get_verify_procname);
  FuncLoadError := not assigned(EC_KEY_METHOD_get_verify);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_METHOD_get_verify_allownil)}
    EC_KEY_METHOD_get_verify := ERR_EC_KEY_METHOD_get_verify;
    {$ifend}
    {$if declared(EC_KEY_METHOD_get_verify_introduced)}
    if LibVersion < EC_KEY_METHOD_get_verify_introduced then
    begin
      {$if declared(FC_EC_KEY_METHOD_get_verify)}
      EC_KEY_METHOD_get_verify := FC_EC_KEY_METHOD_get_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_METHOD_get_verify_removed)}
    if EC_KEY_METHOD_get_verify_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_METHOD_get_verify)}
      EC_KEY_METHOD_get_verify := _EC_KEY_METHOD_get_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_METHOD_get_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_METHOD_get_verify');
    {$ifend}
  end;

 {introduced 1.1.0}
end;

procedure Unload;
begin
  EC_GFp_simple_method := nil;
  EC_GFp_mont_method := nil;
  EC_GFp_nist_method := nil;
   {$IFDEF OPENSSL_NO_EC_NISTP_64_GCC_128}
  EC_GFp_nistp224_method := nil; {introduced 1.1.0 removed 3.0.0}
  EC_GFp_nistp256_method := nil; {introduced 1.1.0 removed 3.0.0}
  EC_GFp_nistp521_method := nil; {introduced 1.1.0 removed 3.0.0}
  {$ENDIF}
  EC_GF2m_simple_method := nil;
  EC_GROUP_new := nil;
  EC_GROUP_free := nil;
  EC_GROUP_clear_free := nil;
  EC_GROUP_copy := nil;
  EC_GROUP_dup := nil;
  EC_GROUP_method_of := nil;
  EC_METHOD_get_field_type := nil;
  EC_GROUP_set_generator := nil;
  EC_GROUP_get0_generator := nil;
  EC_GROUP_get_mont_data := nil;
  EC_GROUP_get_order := nil;
  EC_GROUP_get0_order := nil; {introduced 1.1.0}
  EC_GROUP_order_bits := nil; {introduced 1.1.0}
  EC_GROUP_get_cofactor := nil;
  EC_GROUP_get0_cofactor := nil; {introduced 1.1.0}
  EC_GROUP_set_curve_name := nil;
  EC_GROUP_get_curve_name := nil;
  EC_GROUP_set_asn1_flag := nil;
  EC_GROUP_get_asn1_flag := nil;
  EC_GROUP_set_point_conversion_form := nil;
  EC_GROUP_get_point_conversion_form := nil;
  EC_GROUP_get0_seed := nil;
  EC_GROUP_get_seed_len := nil;
  EC_GROUP_set_seed := nil;
  EC_GROUP_set_curve := nil; {introduced 1.1.0}
  EC_GROUP_get_curve := nil; {introduced 1.1.0}
  EC_GROUP_set_curve_GFp := nil;
  EC_GROUP_get_curve_GFp := nil;
  EC_GROUP_set_curve_GF2m := nil;
  EC_GROUP_get_curve_GF2m := nil;
  EC_GROUP_get_degree := nil;
  EC_GROUP_check := nil;
  EC_GROUP_check_discriminant := nil;
  EC_GROUP_cmp := nil;
  EC_GROUP_new_curve_GFp := nil;
  EC_GROUP_new_curve_GF2m := nil;
  EC_GROUP_new_by_curve_name := nil;
  EC_GROUP_new_from_ecparameters := nil; {introduced 1.1.0}
  EC_GROUP_get_ecparameters := nil; {introduced 1.1.0}
  EC_GROUP_new_from_ecpkparameters := nil; {introduced 1.1.0}
  EC_GROUP_get_ecpkparameters := nil; {introduced 1.1.0}
  EC_get_builtin_curves := nil;
  EC_curve_nid2nist := nil;
  EC_curve_nist2nid := nil;
  EC_POINT_new := nil;
  EC_POINT_free := nil;
  EC_POINT_clear_free := nil;
  EC_POINT_copy := nil;
  EC_POINT_dup := nil;
  EC_POINT_method_of := nil;
  EC_POINT_set_to_infinity := nil;
  EC_POINT_set_Jprojective_coordinates_GFp := nil;
  EC_POINT_get_Jprojective_coordinates_GFp := nil;
  EC_POINT_set_affine_coordinates := nil; {introduced 1.1.0}
  EC_POINT_get_affine_coordinates := nil; {introduced 1.1.0}
  EC_POINT_set_affine_coordinates_GFp := nil;
  EC_POINT_get_affine_coordinates_GFp := nil;
  EC_POINT_set_compressed_coordinates := nil; {introduced 1.1.0}
  EC_POINT_set_compressed_coordinates_GFp := nil;
  EC_POINT_set_affine_coordinates_GF2m := nil;
  EC_POINT_get_affine_coordinates_GF2m := nil;
  EC_POINT_set_compressed_coordinates_GF2m := nil;
  EC_POINT_point2oct := nil;
  EC_POINT_oct2point := nil;
  EC_POINT_point2buf := nil; {introduced 1.1.0}
  EC_POINT_point2bn := nil;
  EC_POINT_bn2point := nil;
  EC_POINT_point2hex := nil;
  EC_POINT_hex2point := nil;
  EC_POINT_add := nil;
  EC_POINT_dbl := nil;
  EC_POINT_invert := nil;
  EC_POINT_is_at_infinity := nil;
  EC_POINT_is_on_curve := nil;
  EC_POINT_cmp := nil;
  EC_POINT_make_affine := nil;
  EC_POINTs_make_affine := nil;
  EC_POINTs_mul := nil;
  EC_POINT_mul := nil;
  EC_GROUP_precompute_mult := nil;
  EC_GROUP_have_precompute_mult := nil;
  ECPKPARAMETERS_it := nil;
  ECPKPARAMETERS_new := nil;
  ECPKPARAMETERS_free := nil;
  ECPARAMETERS_it := nil;
  ECPARAMETERS_new := nil;
  ECPARAMETERS_free := nil;
  EC_GROUP_get_basis_type := nil;
  EC_GROUP_get_trinomial_basis := nil;
  EC_GROUP_get_pentanomial_basis := nil;
  d2i_ECPKParameters := nil;
  i2d_ECPKParameters := nil;
  ECPKParameters_print := nil;
  EC_KEY_new := nil;
  EC_KEY_get_flags := nil;
  EC_KEY_set_flags := nil;
  EC_KEY_clear_flags := nil;
  EC_KEY_new_by_curve_name := nil;
  EC_KEY_free := nil;
  EC_KEY_copy := nil;
  EC_KEY_dup := nil;
  EC_KEY_up_ref := nil;
  EC_KEY_get0_engine := nil; {introduced 1.1.0}
  EC_KEY_get0_group := nil;
  EC_KEY_set_group := nil;
  EC_KEY_get0_private_key := nil;
  EC_KEY_set_private_key := nil;
  EC_KEY_get0_public_key := nil;
  EC_KEY_set_public_key := nil;
  EC_KEY_get_enc_flags := nil;
  EC_KEY_set_enc_flags := nil;
  EC_KEY_get_conv_form := nil;
  EC_KEY_set_conv_form := nil;
  EC_KEY_set_ex_data := nil; {introduced 1.1.0}
  EC_KEY_get_ex_data := nil; {introduced 1.1.0}
  EC_KEY_set_asn1_flag := nil;
  EC_KEY_precompute_mult := nil;
  EC_KEY_generate_key := nil;
  EC_KEY_check_key := nil;
  EC_KEY_can_sign := nil; {introduced 1.1.0}
  EC_KEY_set_public_key_affine_coordinates := nil;
  EC_KEY_key2buf := nil; {introduced 1.1.0}
  EC_KEY_oct2key := nil; {introduced 1.1.0}
  EC_KEY_oct2priv := nil; {introduced 1.1.0}
  EC_KEY_priv2oct := nil; {introduced 1.1.0}
  EC_KEY_priv2buf := nil; {introduced 1.1.0}
  d2i_ECPrivateKey := nil;
  i2d_ECPrivateKey := nil;
  o2i_ECPublicKey := nil;
  i2o_ECPublicKey := nil;
  ECParameters_print := nil;
  EC_KEY_print := nil;
  EC_KEY_OpenSSL := nil; {introduced 1.1.0}
  EC_KEY_get_default_method := nil; {introduced 1.1.0}
  EC_KEY_set_default_method := nil; {introduced 1.1.0}
  EC_KEY_get_method := nil; {introduced 1.1.0}
  EC_KEY_set_method := nil; {introduced 1.1.0}
  EC_KEY_new_method := nil; {introduced 1.1.0}
  ECDH_KDF_X9_62 := nil;
  ECDH_compute_key := nil;
  ECDSA_SIG_new := nil;
  ECDSA_SIG_free := nil;
  i2d_ECDSA_SIG := nil;
  d2i_ECDSA_SIG := nil;
  ECDSA_SIG_get0 := nil; {introduced 1.1.0}
  ECDSA_SIG_get0_r := nil; {introduced 1.1.0}
  ECDSA_SIG_get0_s := nil; {introduced 1.1.0}
  ECDSA_SIG_set0 := nil; {introduced 1.1.0}
  ECDSA_do_sign := nil;
  ECDSA_do_sign_ex := nil;
  ECDSA_do_verify := nil;
  ECDSA_sign_setup := nil;
  ECDSA_sign := nil;
  ECDSA_sign_ex := nil;
  ECDSA_verify := nil;
  ECDSA_size := nil;
  EC_KEY_METHOD_new := nil; {introduced 1.1.0}
  EC_KEY_METHOD_free := nil; {introduced 1.1.0}
  EC_KEY_METHOD_set_init := nil; {introduced 1.1.0}
  EC_KEY_METHOD_set_keygen := nil; {introduced 1.1.0}
  EC_KEY_METHOD_set_compute_key := nil; {introduced 1.1.0}
  EC_KEY_METHOD_set_sign := nil; {introduced 1.1.0}
  EC_KEY_METHOD_set_verify := nil; {introduced 1.1.0}
  EC_KEY_METHOD_get_init := nil; {introduced 1.1.0}
  EC_KEY_METHOD_get_keygen := nil; {introduced 1.1.0}
  EC_KEY_METHOD_get_compute_key := nil; {introduced 1.1.0}
  EC_KEY_METHOD_get_sign := nil; {introduced 1.1.0}
  EC_KEY_METHOD_get_verify := nil; {introduced 1.1.0}
end;
  {$ENDIF}
{$ELSE}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
