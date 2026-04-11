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
  Pec_method_st = ^Tec_method_st;
  Tec_method_st =   record end;
  {$EXTERNALSYM Pec_method_st}

  Pec_group_st = ^Tec_group_st;
  Tec_group_st =   record end;
  {$EXTERNALSYM Pec_group_st}

  Pec_point_st = ^Tec_point_st;
  Tec_point_st =   record end;
  {$EXTERNALSYM Pec_point_st}

  Pecpk_parameters_st = ^Tecpk_parameters_st;
  Tecpk_parameters_st =   record end;
  {$EXTERNALSYM Pecpk_parameters_st}

  Pec_parameters_st = ^Tec_parameters_st;
  Tec_parameters_st =   record end;
  {$EXTERNALSYM Pec_parameters_st}

  PEC_builtin_curve = ^TEC_builtin_curve;
  TEC_builtin_curve =   record
    nid: TIdC_INT;
    comment: PIdAnsiChar;
  end;
  {$EXTERNALSYM PEC_builtin_curve}

  PECDSA_SIG_st = ^TECDSA_SIG_st;
  TECDSA_SIG_st =   record end;
  {$EXTERNALSYM PECDSA_SIG_st}


// =============================================================================
// ENUM TYPE DECLARATIONS
// =============================================================================
type
  // Enum: point_conversion_form_t
  Tpoint_conversion_form_t = (
    POINT_CONVERSION_COMPRESSED = 2,
    POINT_CONVERSION_UNCOMPRESSED = 4,
    POINT_CONVERSION_HYBRID = 6
  );


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // ECDH_compute_key_KDF_cb = function(_in: Pointer; inlen: TIdC_SIZET; _out: Pointer; outlen: PIdC_SIZET): Pointer; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // EC_KEY_METHOD_set_init_init_cb = function(key: PEC_KEY): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // EC_KEY_METHOD_set_init_finish_cb = procedure(key: PEC_KEY); cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // EC_KEY_METHOD_set_init_copy_cb = function(dest: PEC_KEY; src: PEC_KEY): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // EC_KEY_METHOD_set_init_set_group_cb = function(key: PEC_KEY; grp: PEC_GROUP): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // EC_KEY_METHOD_set_init_set_private_cb = function(key: PEC_KEY; priv_key: PBIGNUM): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // EC_KEY_METHOD_set_init_set_public_cb = function(key: PEC_KEY; pub_key: PEC_POINT): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // EC_KEY_METHOD_set_compute_key_ckey_cb = function(psec: PPIdAnsiChar; pseclen: PIdC_SIZET; pub_key: PEC_POINT; ecdh: PEC_KEY): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // EC_KEY_METHOD_set_sign_sign_cb = function(_type: TIdC_INT; dgst: PIdAnsiChar; dlen: TIdC_INT; sig: PIdAnsiChar; siglen: PIdC_UINT; kinv: PBIGNUM; r: PBIGNUM; eckey: PEC_KEY): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // EC_KEY_METHOD_set_sign_sign_setup_cb = function(eckey: PEC_KEY; ctx_in: PBN_CTX; kinvp: PPBIGNUM; rp: PPBIGNUM): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // EC_KEY_METHOD_set_sign_sign_sig_cb = function(dgst: PIdAnsiChar; dgst_len: TIdC_INT; in_kinv: PBIGNUM; in_r: PBIGNUM; eckey: PEC_KEY): PECDSA_SIG; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // EC_KEY_METHOD_set_verify_verify_cb = function(_type: TIdC_INT; dgst: PIdAnsiChar; dgst_len: TIdC_INT; sigbuf: PIdAnsiChar; sig_len: TIdC_INT; eckey: PEC_KEY): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // EC_KEY_METHOD_set_verify_verify_sig_cb = function(dgst: PIdAnsiChar; dgst_len: TIdC_INT; sig: PECDSA_SIG; eckey: PEC_KEY): TIdC_INT; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  OPENSSL_EC_EXPLICIT_CURVE = $000;
  OPENSSL_EC_NAMED_CURVE = $001;
  EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID = (EVP_PKEY_ALG_CTRL+1);
  EVP_PKEY_CTRL_EC_PARAM_ENC = (EVP_PKEY_ALG_CTRL+2);
  EVP_PKEY_CTRL_EC_ECDH_COFACTOR = (EVP_PKEY_ALG_CTRL+3);
  EVP_PKEY_CTRL_EC_KDF_TYPE = (EVP_PKEY_ALG_CTRL+4);
  EVP_PKEY_CTRL_EC_KDF_MD = (EVP_PKEY_ALG_CTRL+5);
  EVP_PKEY_CTRL_GET_EC_KDF_MD = (EVP_PKEY_ALG_CTRL+6);
  EVP_PKEY_CTRL_EC_KDF_OUTLEN = (EVP_PKEY_ALG_CTRL+7);
  EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN = (EVP_PKEY_ALG_CTRL+8);
  EVP_PKEY_CTRL_EC_KDF_UKM = (EVP_PKEY_ALG_CTRL+9);
  EVP_PKEY_CTRL_GET_EC_KDF_UKM = (EVP_PKEY_ALG_CTRL+10);
  EVP_PKEY_ECDH_KDF_NONE = 1;
  EVP_PKEY_ECDH_KDF_X9_63 = 2;
  EVP_PKEY_ECDH_KDF_X9_62 = EVP_PKEY_ECDH_KDF_X9_63;
  OPENSSL_ECC_MAX_FIELD_BITS = 661;
  EC_PKEY_NO_PARAMETERS = $001;
  EC_PKEY_NO_PUBKEY = $002;
  EC_FLAG_SM2_RANGE = $0004;
  EC_FLAG_COFACTOR_ECDH = $1000;
  EC_FLAG_CHECK_NAMED_GROUP = $2000;
  EC_FLAG_CHECK_NAMED_GROUP_NIST = $4000;
  EC_FLAG_CHECK_NAMED_GROUP_MASK = (EC_FLAG_CHECK_NAMED_GROUP or EC_FLAG_CHECK_NAMED_GROUP_NIST);
  EC_FLAG_NON_FIPS_ALLOW = $0000;
  EC_FLAG_FIPS_CHECKED = $0000;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  EVP_PKEY_CTX_set_ec_paramgen_curve_nid: function(ctx: PEVP_PKEY_CTX; nid: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_ec_paramgen_curve_nid}

  EVP_PKEY_CTX_set_ec_param_enc: function(ctx: PEVP_PKEY_CTX; param_enc: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_ec_param_enc}

  EVP_PKEY_CTX_set_ecdh_cofactor_mode: function(ctx: PEVP_PKEY_CTX; cofactor_mode: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_ecdh_cofactor_mode}

  EVP_PKEY_CTX_get_ecdh_cofactor_mode: function(ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_get_ecdh_cofactor_mode}

  EVP_PKEY_CTX_set_ecdh_kdf_type: function(ctx: PEVP_PKEY_CTX; kdf: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_ecdh_kdf_type}

  EVP_PKEY_CTX_get_ecdh_kdf_type: function(ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_get_ecdh_kdf_type}

  EVP_PKEY_CTX_set_ecdh_kdf_md: function(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_ecdh_kdf_md}

  EVP_PKEY_CTX_get_ecdh_kdf_md: function(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_get_ecdh_kdf_md}

  EVP_PKEY_CTX_set_ecdh_kdf_outlen: function(ctx: PEVP_PKEY_CTX; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set_ecdh_kdf_outlen}

  EVP_PKEY_CTX_get_ecdh_kdf_outlen: function(ctx: PEVP_PKEY_CTX; len: PIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_get_ecdh_kdf_outlen}

  EVP_PKEY_CTX_set0_ecdh_kdf_ukm: function(ctx: PEVP_PKEY_CTX; ukm: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_CTX_set0_ecdh_kdf_ukm}

  EVP_PKEY_CTX_get0_ecdh_kdf_ukm: function(ctx: PEVP_PKEY_CTX; ukm: PPIdAnsiChar): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EVP_PKEY_CTX_get0_ecdh_kdf_ukm}

  OSSL_EC_curve_nid2name: function(nid: TIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OSSL_EC_curve_nid2name}

  EC_GFp_simple_method: function: PEC_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_GFp_simple_method}

  EC_GFp_mont_method: function: PEC_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_GFp_mont_method}

  EC_GFp_nist_method: function: PEC_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_GFp_nist_method}

  EC_GF2m_simple_method: function: PEC_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_GF2m_simple_method}

  EC_GROUP_new: function(meth: PEC_METHOD): PEC_GROUP; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_GROUP_new}

  EC_GROUP_clear_free: procedure(group: PEC_GROUP); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_GROUP_clear_free}

  EC_GROUP_method_of: function(group: PEC_GROUP): PEC_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_GROUP_method_of}

  EC_METHOD_get_field_type: function(meth: PEC_METHOD): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_METHOD_get_field_type}

  EC_GROUP_free: procedure(group: PEC_GROUP); cdecl = nil;
  {$EXTERNALSYM EC_GROUP_free}

  EC_GROUP_copy: function(dst: PEC_GROUP; src: PEC_GROUP): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_copy}

  EC_GROUP_dup: function(src: PEC_GROUP): PEC_GROUP; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_dup}

  EC_GROUP_set_generator: function(group: PEC_GROUP; generator: PEC_POINT; order: PBIGNUM; cofactor: PBIGNUM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_set_generator}

  EC_GROUP_get0_generator: function(group: PEC_GROUP): PEC_POINT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get0_generator}

  EC_GROUP_get_mont_data: function(group: PEC_GROUP): PBN_MONT_CTX; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get_mont_data}

  EC_GROUP_get_order: function(group: PEC_GROUP; order: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get_order}

  EC_GROUP_get0_order: function(group: PEC_GROUP): PBIGNUM; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get0_order}

  EC_GROUP_order_bits: function(group: PEC_GROUP): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_order_bits}

  EC_GROUP_get_cofactor: function(group: PEC_GROUP; cofactor: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get_cofactor}

  EC_GROUP_get0_cofactor: function(group: PEC_GROUP): PBIGNUM; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get0_cofactor}

  EC_GROUP_set_curve_name: procedure(group: PEC_GROUP; nid: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM EC_GROUP_set_curve_name}

  EC_GROUP_get_curve_name: function(group: PEC_GROUP): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get_curve_name}

  EC_GROUP_get0_field: function(group: PEC_GROUP): PBIGNUM; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get0_field}

  EC_GROUP_get_field_type: function(group: PEC_GROUP): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get_field_type}

  EC_GROUP_set_asn1_flag: procedure(group: PEC_GROUP; flag: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM EC_GROUP_set_asn1_flag}

  EC_GROUP_get_asn1_flag: function(group: PEC_GROUP): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get_asn1_flag}

  EC_GROUP_set_point_conversion_form: procedure(group: PEC_GROUP; form: Tpoint_conversion_form_t); cdecl = nil;
  {$EXTERNALSYM EC_GROUP_set_point_conversion_form}

  EC_GROUP_get_point_conversion_form: function(arg1: PEC_GROUP): Tpoint_conversion_form_t; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get_point_conversion_form}

  EC_GROUP_get0_seed: function(x: PEC_GROUP): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get0_seed}

  EC_GROUP_get_seed_len: function(arg1: PEC_GROUP): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get_seed_len}

  EC_GROUP_set_seed: function(arg1: PEC_GROUP; arg2: PIdAnsiChar; len: TIdC_SIZET): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_set_seed}

  EC_GROUP_set_curve: function(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_set_curve}

  EC_GROUP_get_curve: function(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get_curve}

  EC_GROUP_set_curve_GFp: function(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_GROUP_set_curve_GFp}

  EC_GROUP_get_curve_GFp: function(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_GROUP_get_curve_GFp}

  EC_GROUP_set_curve_GF2m: function(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_GROUP_set_curve_GF2m}

  EC_GROUP_get_curve_GF2m: function(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_GROUP_get_curve_GF2m}

  EC_GROUP_get_degree: function(group: PEC_GROUP): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get_degree}

  EC_GROUP_check: function(group: PEC_GROUP; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_check}

  EC_GROUP_check_discriminant: function(group: PEC_GROUP; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_check_discriminant}

  EC_GROUP_cmp: function(a: PEC_GROUP; b: PEC_GROUP; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_cmp}

  EC_GROUP_new_curve_GFp: function(p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_new_curve_GFp}

  EC_GROUP_new_curve_GF2m: function(p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_new_curve_GF2m}

  EC_GROUP_new_from_params: function(params: POSSL_PARAM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEC_GROUP; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_new_from_params}

  EC_GROUP_to_params: function(group: PEC_GROUP; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; bnctx: PBN_CTX): POSSL_PARAM; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_to_params}

  EC_GROUP_new_by_curve_name_ex: function(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; nid: TIdC_INT): PEC_GROUP; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_new_by_curve_name_ex}

  EC_GROUP_new_by_curve_name: function(nid: TIdC_INT): PEC_GROUP; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_new_by_curve_name}

  EC_GROUP_new_from_ecparameters: function(params: PECPARAMETERS): PEC_GROUP; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_new_from_ecparameters}

  EC_GROUP_get_ecparameters: function(group: PEC_GROUP; params: PECPARAMETERS): PECPARAMETERS; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get_ecparameters}

  EC_GROUP_new_from_ecpkparameters: function(params: PECPKPARAMETERS): PEC_GROUP; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_new_from_ecpkparameters}

  EC_GROUP_get_ecpkparameters: function(group: PEC_GROUP; params: PECPKPARAMETERS): PECPKPARAMETERS; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get_ecpkparameters}

  EC_get_builtin_curves: function(r: PEC_builtin_curve; nitems: TIdC_SIZET): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM EC_get_builtin_curves}

  EC_curve_nid2nist: function(nid: TIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM EC_curve_nid2nist}

  EC_curve_nist2nid: function(name: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_curve_nist2nid}

  EC_GROUP_check_named_curve: function(group: PEC_GROUP; nist_only: TIdC_INT; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_check_named_curve}

  EC_POINT_new: function(group: PEC_GROUP): PEC_POINT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_new}

  EC_POINT_free: procedure(point: PEC_POINT); cdecl = nil;
  {$EXTERNALSYM EC_POINT_free}

  EC_POINT_clear_free: procedure(point: PEC_POINT); cdecl = nil;
  {$EXTERNALSYM EC_POINT_clear_free}

  EC_POINT_copy: function(dst: PEC_POINT; src: PEC_POINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_copy}

  EC_POINT_dup: function(src: PEC_POINT; group: PEC_GROUP): PEC_POINT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_dup}

  EC_POINT_set_to_infinity: function(group: PEC_GROUP; point: PEC_POINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_set_to_infinity}

  EC_POINT_method_of: function(point: PEC_POINT): PEC_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_POINT_method_of}

  EC_POINT_set_Jprojective_coordinates_GFp: function(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_POINT_set_Jprojective_coordinates_GFp}

  EC_POINT_get_Jprojective_coordinates_GFp: function(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_POINT_get_Jprojective_coordinates_GFp}

  EC_POINT_set_affine_coordinates: function(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_set_affine_coordinates}

  EC_POINT_get_affine_coordinates: function(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_get_affine_coordinates}

  EC_POINT_set_affine_coordinates_GFp: function(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_POINT_set_affine_coordinates_GFp}

  EC_POINT_get_affine_coordinates_GFp: function(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_POINT_get_affine_coordinates_GFp}

  EC_POINT_set_compressed_coordinates: function(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TIdC_INT; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_set_compressed_coordinates}

  EC_POINT_set_compressed_coordinates_GFp: function(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TIdC_INT; ctx: PBN_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_POINT_set_compressed_coordinates_GFp}

  EC_POINT_set_affine_coordinates_GF2m: function(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_POINT_set_affine_coordinates_GF2m}

  EC_POINT_get_affine_coordinates_GF2m: function(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_POINT_get_affine_coordinates_GF2m}

  EC_POINT_set_compressed_coordinates_GF2m: function(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TIdC_INT; ctx: PBN_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_POINT_set_compressed_coordinates_GF2m}

  EC_POINT_point2oct: function(group: PEC_GROUP; p: PEC_POINT; form: Tpoint_conversion_form_t; buf: PIdAnsiChar; len: TIdC_SIZET; ctx: PBN_CTX): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM EC_POINT_point2oct}

  EC_POINT_oct2point: function(group: PEC_GROUP; p: PEC_POINT; buf: PIdAnsiChar; len: TIdC_SIZET; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_oct2point}

  EC_POINT_point2buf: function(group: PEC_GROUP; point: PEC_POINT; form: Tpoint_conversion_form_t; pbuf: PPIdAnsiChar; ctx: PBN_CTX): TIdC_SIZET; cdecl = nil;
  {$EXTERNALSYM EC_POINT_point2buf}

  EC_POINT_point2bn: function(arg1: PEC_GROUP; arg2: PEC_POINT; form: Tpoint_conversion_form_t; arg4: PBIGNUM; arg5: PBN_CTX): PBIGNUM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_POINT_point2bn}

  EC_POINT_bn2point: function(arg1: PEC_GROUP; arg2: PBIGNUM; arg3: PEC_POINT; arg4: PBN_CTX): PEC_POINT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_POINT_bn2point}

  EC_POINT_point2hex: function(arg1: PEC_GROUP; arg2: PEC_POINT; form: Tpoint_conversion_form_t; arg4: PBN_CTX): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM EC_POINT_point2hex}

  EC_POINT_hex2point: function(arg1: PEC_GROUP; arg2: PIdAnsiChar; arg3: PEC_POINT; arg4: PBN_CTX): PEC_POINT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_hex2point}

  EC_POINT_add: function(group: PEC_GROUP; r: PEC_POINT; a: PEC_POINT; b: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_add}

  EC_POINT_dbl: function(group: PEC_GROUP; r: PEC_POINT; a: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_dbl}

  EC_POINT_invert: function(group: PEC_GROUP; a: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_invert}

  EC_POINT_is_at_infinity: function(group: PEC_GROUP; p: PEC_POINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_is_at_infinity}

  EC_POINT_is_on_curve: function(group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_is_on_curve}

  EC_POINT_cmp: function(group: PEC_GROUP; a: PEC_POINT; b: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_cmp}

  EC_POINT_make_affine: function(group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_POINT_make_affine}

  EC_POINTs_make_affine: function(group: PEC_GROUP; num: TIdC_SIZET; points: PPEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_POINTs_make_affine}

  EC_POINTs_mul: function(group: PEC_GROUP; r: PEC_POINT; n: PBIGNUM; num: TIdC_SIZET; p: PPEC_POINT; m: PPBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_POINTs_mul}

  EC_POINT_mul: function(group: PEC_GROUP; r: PEC_POINT; n: PBIGNUM; q: PEC_POINT; m: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_POINT_mul}

  EC_GROUP_precompute_mult: function(group: PEC_GROUP; ctx: PBN_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_GROUP_precompute_mult}

  EC_GROUP_have_precompute_mult: function(group: PEC_GROUP): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_GROUP_have_precompute_mult}

  ECPKPARAMETERS_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ECPKPARAMETERS_it}

  ECPKPARAMETERS_new: function: PECPKPARAMETERS; cdecl = nil;
  {$EXTERNALSYM ECPKPARAMETERS_new}

  ECPKPARAMETERS_free: procedure(a: PECPKPARAMETERS); cdecl = nil;
  {$EXTERNALSYM ECPKPARAMETERS_free}

  ECPARAMETERS_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM ECPARAMETERS_it}

  ECPARAMETERS_new: function: PECPARAMETERS; cdecl = nil;
  {$EXTERNALSYM ECPARAMETERS_new}

  ECPARAMETERS_free: procedure(a: PECPARAMETERS); cdecl = nil;
  {$EXTERNALSYM ECPARAMETERS_free}

  EC_GROUP_get_basis_type: function(arg1: PEC_GROUP): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get_basis_type}

  EC_GROUP_get_trinomial_basis: function(arg1: PEC_GROUP; k: PIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get_trinomial_basis}

  EC_GROUP_get_pentanomial_basis: function(arg1: PEC_GROUP; k1: PIdC_UINT; k2: PIdC_UINT; k3: PIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EC_GROUP_get_pentanomial_basis}

  d2i_ECPKParameters: function(arg1: PPEC_GROUP; _in: PPIdAnsiChar; len: TIdC_LONG): PEC_GROUP; cdecl = nil;
  {$EXTERNALSYM d2i_ECPKParameters}

  i2d_ECPKParameters: function(arg1: PEC_GROUP; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ECPKParameters}

  ECPKParameters_print: function(bp: PBIO; x: PEC_GROUP; off: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ECPKParameters_print}

  ECPKParameters_print_fp: function(fp: PFILE; x: PEC_GROUP; off: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ECPKParameters_print_fp}

  EC_KEY_new_ex: function(ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEC_KEY; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_new_ex}

  EC_KEY_new: function: PEC_KEY; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_new}

  EC_KEY_get_flags: function(key: PEC_KEY): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_get_flags}

  EC_KEY_set_flags: procedure(key: PEC_KEY; flags: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_set_flags}

  EC_KEY_clear_flags: procedure(key: PEC_KEY; flags: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_clear_flags}

  EC_KEY_decoded_from_explicit_params: function(key: PEC_KEY): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_decoded_from_explicit_params}

  EC_KEY_new_by_curve_name_ex: function(ctx: POSSL_LIB_CTX; propq: PIdAnsiChar; nid: TIdC_INT): PEC_KEY; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_new_by_curve_name_ex}

  EC_KEY_new_by_curve_name: function(nid: TIdC_INT): PEC_KEY; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_new_by_curve_name}

  EC_KEY_free: procedure(key: PEC_KEY); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_free}

  EC_KEY_copy: function(dst: PEC_KEY; src: PEC_KEY): PEC_KEY; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_copy}

  EC_KEY_dup: function(src: PEC_KEY): PEC_KEY; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_dup}

  EC_KEY_up_ref: function(key: PEC_KEY): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_up_ref}

  EC_KEY_get0_engine: function(eckey: PEC_KEY): PENGINE; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_get0_engine}

  EC_KEY_get0_group: function(key: PEC_KEY): PEC_GROUP; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_get0_group}

  EC_KEY_set_group: function(key: PEC_KEY; group: PEC_GROUP): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_set_group}

  EC_KEY_get0_private_key: function(key: PEC_KEY): PBIGNUM; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_get0_private_key}

  EC_KEY_set_private_key: function(key: PEC_KEY; prv: PBIGNUM): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_set_private_key}

  EC_KEY_get0_public_key: function(key: PEC_KEY): PEC_POINT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_get0_public_key}

  EC_KEY_set_public_key: function(key: PEC_KEY; pub: PEC_POINT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_set_public_key}

  EC_KEY_get_enc_flags: function(key: PEC_KEY): TIdC_UINT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_get_enc_flags}

  EC_KEY_set_enc_flags: procedure(eckey: PEC_KEY; flags: TIdC_UINT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_set_enc_flags}

  EC_KEY_get_conv_form: function(key: PEC_KEY): Tpoint_conversion_form_t; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_get_conv_form}

  EC_KEY_set_conv_form: procedure(eckey: PEC_KEY; cform: Tpoint_conversion_form_t); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_set_conv_form}

  EC_KEY_set_ex_data: function(key: PEC_KEY; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_set_ex_data}

  EC_KEY_get_ex_data: function(key: PEC_KEY; idx: TIdC_INT): Pointer; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_get_ex_data}

  EC_KEY_set_asn1_flag: procedure(eckey: PEC_KEY; asn1_flag: TIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_set_asn1_flag}

  EC_KEY_precompute_mult: function(key: PEC_KEY; ctx: PBN_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_precompute_mult}

  EC_KEY_generate_key: function(key: PEC_KEY): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_generate_key}

  EC_KEY_check_key: function(key: PEC_KEY): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_check_key}

  EC_KEY_can_sign: function(eckey: PEC_KEY): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_can_sign}

  EC_KEY_set_public_key_affine_coordinates: function(key: PEC_KEY; x: PBIGNUM; y: PBIGNUM): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_set_public_key_affine_coordinates}

  EC_KEY_key2buf: function(key: PEC_KEY; form: Tpoint_conversion_form_t; pbuf: PPIdAnsiChar; ctx: PBN_CTX): TIdC_SIZET; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_key2buf}

  EC_KEY_oct2key: function(key: PEC_KEY; buf: PIdAnsiChar; len: TIdC_SIZET; ctx: PBN_CTX): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_oct2key}

  EC_KEY_oct2priv: function(key: PEC_KEY; buf: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_oct2priv}

  EC_KEY_priv2oct: function(key: PEC_KEY; buf: PIdAnsiChar; len: TIdC_SIZET): TIdC_SIZET; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_priv2oct}

  EC_KEY_priv2buf: function(eckey: PEC_KEY; pbuf: PPIdAnsiChar): TIdC_SIZET; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_priv2buf}

  d2i_ECPrivateKey: function(key: PPEC_KEY; _in: PPIdAnsiChar; len: TIdC_LONG): PEC_KEY; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM d2i_ECPrivateKey}

  i2d_ECPrivateKey: function(key: PEC_KEY; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM i2d_ECPrivateKey}

  d2i_ECParameters: function(key: PPEC_KEY; _in: PPIdAnsiChar; len: TIdC_LONG): PEC_KEY; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM d2i_ECParameters}

  i2d_ECParameters: function(key: PEC_KEY; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM i2d_ECParameters}

  o2i_ECPublicKey: function(key: PPEC_KEY; _in: PPIdAnsiChar; len: TIdC_LONG): PEC_KEY; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM o2i_ECPublicKey}

  i2o_ECPublicKey: function(key: PEC_KEY; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM i2o_ECPublicKey}

  ECParameters_print: function(bp: PBIO; key: PEC_KEY): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ECParameters_print}

  EC_KEY_print: function(bp: PBIO; key: PEC_KEY; off: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_print}

  ECParameters_print_fp: function(fp: PFILE; key: PEC_KEY): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ECParameters_print_fp}

  EC_KEY_print_fp: function(fp: PFILE; key: PEC_KEY; off: TIdC_INT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_print_fp}

  EC_KEY_OpenSSL: function: PEC_KEY_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_OpenSSL}

  EC_KEY_get_default_method: function: PEC_KEY_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_get_default_method}

  EC_KEY_set_default_method: procedure(meth: PEC_KEY_METHOD); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_set_default_method}

  EC_KEY_get_method: function(key: PEC_KEY): PEC_KEY_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_get_method}

  EC_KEY_set_method: function(key: PEC_KEY; meth: PEC_KEY_METHOD): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_set_method}

  EC_KEY_new_method: function(engine: PENGINE): PEC_KEY; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_new_method}

  ECDH_KDF_X9_62: function(_out: PIdAnsiChar; outlen: TIdC_SIZET; Z: PIdAnsiChar; Zlen: TIdC_SIZET; sinfo: PIdAnsiChar; sinfolen: TIdC_SIZET; md: PEVP_MD): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ECDH_KDF_X9_62}

  ECDH_compute_key: function(_out: Pointer; outlen: TIdC_SIZET; pub_key: PEC_POINT; ecdh: PEC_KEY; KDF: TECDH_compute_key_KDF_cb): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ECDH_compute_key}

  ECDSA_SIG_new: function: PECDSA_SIG; cdecl = nil;
  {$EXTERNALSYM ECDSA_SIG_new}

  ECDSA_SIG_free: procedure(sig: PECDSA_SIG); cdecl = nil;
  {$EXTERNALSYM ECDSA_SIG_free}

  d2i_ECDSA_SIG: function(a: PPECDSA_SIG; _in: PPIdAnsiChar; len: TIdC_LONG): PECDSA_SIG; cdecl = nil;
  {$EXTERNALSYM d2i_ECDSA_SIG}

  i2d_ECDSA_SIG: function(a: PECDSA_SIG; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_ECDSA_SIG}

  ECDSA_SIG_get0: procedure(sig: PECDSA_SIG; pr: PPBIGNUM; ps: PPBIGNUM); cdecl = nil;
  {$EXTERNALSYM ECDSA_SIG_get0}

  ECDSA_SIG_get0_r: function(sig: PECDSA_SIG): PBIGNUM; cdecl = nil;
  {$EXTERNALSYM ECDSA_SIG_get0_r}

  ECDSA_SIG_get0_s: function(sig: PECDSA_SIG): PBIGNUM; cdecl = nil;
  {$EXTERNALSYM ECDSA_SIG_get0_s}

  ECDSA_SIG_set0: function(sig: PECDSA_SIG; r: PBIGNUM; s: PBIGNUM): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ECDSA_SIG_set0}

  ECDSA_do_sign: function(dgst: PIdAnsiChar; dgst_len: TIdC_INT; eckey: PEC_KEY): PECDSA_SIG; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ECDSA_do_sign}

  ECDSA_do_sign_ex: function(dgst: PIdAnsiChar; dgstlen: TIdC_INT; kinv: PBIGNUM; rp: PBIGNUM; eckey: PEC_KEY): PECDSA_SIG; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ECDSA_do_sign_ex}

  ECDSA_do_verify: function(dgst: PIdAnsiChar; dgst_len: TIdC_INT; sig: PECDSA_SIG; eckey: PEC_KEY): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ECDSA_do_verify}

  ECDSA_sign_setup: function(eckey: PEC_KEY; ctx: PBN_CTX; kinv: PPBIGNUM; rp: PPBIGNUM): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ECDSA_sign_setup}

  ECDSA_sign: function(_type: TIdC_INT; dgst: PIdAnsiChar; dgstlen: TIdC_INT; sig: PIdAnsiChar; siglen: PIdC_UINT; eckey: PEC_KEY): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ECDSA_sign}

  ECDSA_sign_ex: function(_type: TIdC_INT; dgst: PIdAnsiChar; dgstlen: TIdC_INT; sig: PIdAnsiChar; siglen: PIdC_UINT; kinv: PBIGNUM; rp: PBIGNUM; eckey: PEC_KEY): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ECDSA_sign_ex}

  ECDSA_verify: function(_type: TIdC_INT; dgst: PIdAnsiChar; dgstlen: TIdC_INT; sig: PIdAnsiChar; siglen: TIdC_INT; eckey: PEC_KEY): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ECDSA_verify}

  ECDSA_size: function(eckey: PEC_KEY): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ECDSA_size}

  EC_KEY_METHOD_new: function(meth: PEC_KEY_METHOD): PEC_KEY_METHOD; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_METHOD_new}

  EC_KEY_METHOD_free: procedure(meth: PEC_KEY_METHOD); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_METHOD_free}

  EC_KEY_METHOD_set_init: procedure(meth: PEC_KEY_METHOD; init: TEC_KEY_METHOD_set_init_init_cb; finish: TEC_KEY_METHOD_set_init_finish_cb; copy: TEC_KEY_METHOD_set_init_copy_cb; set_group: TEC_KEY_METHOD_set_init_set_group_cb; set_private: TEC_KEY_METHOD_set_init_set_private_cb; set_public: TEC_KEY_METHOD_set_init_set_public_cb); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_METHOD_set_init}

  EC_KEY_METHOD_set_keygen: procedure(meth: PEC_KEY_METHOD; keygen: TEC_KEY_METHOD_set_init_init_cb); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_METHOD_set_keygen}

  EC_KEY_METHOD_set_compute_key: procedure(meth: PEC_KEY_METHOD; ckey: TEC_KEY_METHOD_set_compute_key_ckey_cb); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_METHOD_set_compute_key}

  EC_KEY_METHOD_set_sign: procedure(meth: PEC_KEY_METHOD; sign: TEC_KEY_METHOD_set_sign_sign_cb; sign_setup: TEC_KEY_METHOD_set_sign_sign_setup_cb; sign_sig: TEC_KEY_METHOD_set_sign_sign_sig_cb); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_METHOD_set_sign}

  EC_KEY_METHOD_set_verify: procedure(meth: PEC_KEY_METHOD; verify: TEC_KEY_METHOD_set_verify_verify_cb; verify_sig: TEC_KEY_METHOD_set_verify_verify_sig_cb); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_METHOD_set_verify}

  EC_KEY_METHOD_get_init: procedure(meth: PEC_KEY_METHOD; pinit: PPIdC_INT; pfinish: PPointer; pcopy: PPIdC_INT; pset_group: PPIdC_INT; pset_private: PPIdC_INT; pset_public: PPIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_METHOD_get_init}

  EC_KEY_METHOD_get_keygen: procedure(meth: PEC_KEY_METHOD; pkeygen: PPIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_METHOD_get_keygen}

  EC_KEY_METHOD_get_compute_key: procedure(meth: PEC_KEY_METHOD; pck: PPIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_METHOD_get_compute_key}

  EC_KEY_METHOD_get_sign: procedure(meth: PEC_KEY_METHOD; psign: PPIdC_INT; psign_setup: PPIdC_INT; psign_sig: PPECDSA_SIG); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_METHOD_get_sign}

  EC_KEY_METHOD_get_verify: procedure(meth: PEC_KEY_METHOD; pverify: PPIdC_INT; pverify_sig: PPIdC_INT); cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM EC_KEY_METHOD_get_verify}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx: PEVP_PKEY_CTX; nid: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_ec_param_enc(ctx: PEVP_PKEY_CTX; param_enc: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx: PEVP_PKEY_CTX; cofactor_mode: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_get_ecdh_cofactor_mode(ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_ecdh_kdf_type(ctx: PEVP_PKEY_CTX; kdf: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_get_ecdh_kdf_type(ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_ecdh_kdf_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl;
function EVP_PKEY_CTX_get_ecdh_kdf_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set_ecdh_kdf_outlen(ctx: PEVP_PKEY_CTX; len: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_get_ecdh_kdf_outlen(ctx: PEVP_PKEY_CTX; len: PIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_set0_ecdh_kdf_ukm(ctx: PEVP_PKEY_CTX; ukm: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_CTX_get0_ecdh_kdf_ukm(ctx: PEVP_PKEY_CTX; ukm: PPIdAnsiChar): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function OSSL_EC_curve_nid2name(nid: TIdC_INT): PIdAnsiChar; cdecl;
function EC_GFp_simple_method: PEC_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_GFp_mont_method: PEC_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_GFp_nist_method: PEC_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_GF2m_simple_method: PEC_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_GROUP_new(meth: PEC_METHOD): PEC_GROUP; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure EC_GROUP_clear_free(group: PEC_GROUP); cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_GROUP_method_of(group: PEC_GROUP): PEC_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_METHOD_get_field_type(meth: PEC_METHOD): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure EC_GROUP_free(group: PEC_GROUP); cdecl;
function EC_GROUP_copy(dst: PEC_GROUP; src: PEC_GROUP): TIdC_INT; cdecl;
function EC_GROUP_dup(src: PEC_GROUP): PEC_GROUP; cdecl;
function EC_GROUP_set_generator(group: PEC_GROUP; generator: PEC_POINT; order: PBIGNUM; cofactor: PBIGNUM): TIdC_INT; cdecl;
function EC_GROUP_get0_generator(group: PEC_GROUP): PEC_POINT; cdecl;
function EC_GROUP_get_mont_data(group: PEC_GROUP): PBN_MONT_CTX; cdecl;
function EC_GROUP_get_order(group: PEC_GROUP; order: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl;
function EC_GROUP_get0_order(group: PEC_GROUP): PBIGNUM; cdecl;
function EC_GROUP_order_bits(group: PEC_GROUP): TIdC_INT; cdecl;
function EC_GROUP_get_cofactor(group: PEC_GROUP; cofactor: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl;
function EC_GROUP_get0_cofactor(group: PEC_GROUP): PBIGNUM; cdecl;
procedure EC_GROUP_set_curve_name(group: PEC_GROUP; nid: TIdC_INT); cdecl;
function EC_GROUP_get_curve_name(group: PEC_GROUP): TIdC_INT; cdecl;
function EC_GROUP_get0_field(group: PEC_GROUP): PBIGNUM; cdecl;
function EC_GROUP_get_field_type(group: PEC_GROUP): TIdC_INT; cdecl;
procedure EC_GROUP_set_asn1_flag(group: PEC_GROUP; flag: TIdC_INT); cdecl;
function EC_GROUP_get_asn1_flag(group: PEC_GROUP): TIdC_INT; cdecl;
procedure EC_GROUP_set_point_conversion_form(group: PEC_GROUP; form: Tpoint_conversion_form_t); cdecl;
function EC_GROUP_get_point_conversion_form(arg1: PEC_GROUP): Tpoint_conversion_form_t; cdecl;
function EC_GROUP_get0_seed(x: PEC_GROUP): PIdAnsiChar; cdecl;
function EC_GROUP_get_seed_len(arg1: PEC_GROUP): TIdC_SIZET; cdecl;
function EC_GROUP_set_seed(arg1: PEC_GROUP; arg2: PIdAnsiChar; len: TIdC_SIZET): TIdC_SIZET; cdecl;
function EC_GROUP_set_curve(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl;
function EC_GROUP_get_curve(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl;
function EC_GROUP_set_curve_GFp(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_GROUP_get_curve_GFp(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_GROUP_set_curve_GF2m(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_GROUP_get_curve_GF2m(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_GROUP_get_degree(group: PEC_GROUP): TIdC_INT; cdecl;
function EC_GROUP_check(group: PEC_GROUP; ctx: PBN_CTX): TIdC_INT; cdecl;
function EC_GROUP_check_discriminant(group: PEC_GROUP; ctx: PBN_CTX): TIdC_INT; cdecl;
function EC_GROUP_cmp(a: PEC_GROUP; b: PEC_GROUP; ctx: PBN_CTX): TIdC_INT; cdecl;
function EC_GROUP_new_curve_GFp(p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl;
function EC_GROUP_new_curve_GF2m(p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl;
function EC_GROUP_new_from_params(params: POSSL_PARAM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEC_GROUP; cdecl;
function EC_GROUP_to_params(group: PEC_GROUP; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; bnctx: PBN_CTX): POSSL_PARAM; cdecl;
function EC_GROUP_new_by_curve_name_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; nid: TIdC_INT): PEC_GROUP; cdecl;
function EC_GROUP_new_by_curve_name(nid: TIdC_INT): PEC_GROUP; cdecl;
function EC_GROUP_new_from_ecparameters(params: PECPARAMETERS): PEC_GROUP; cdecl;
function EC_GROUP_get_ecparameters(group: PEC_GROUP; params: PECPARAMETERS): PECPARAMETERS; cdecl;
function EC_GROUP_new_from_ecpkparameters(params: PECPKPARAMETERS): PEC_GROUP; cdecl;
function EC_GROUP_get_ecpkparameters(group: PEC_GROUP; params: PECPKPARAMETERS): PECPKPARAMETERS; cdecl;
function EC_get_builtin_curves(r: PEC_builtin_curve; nitems: TIdC_SIZET): TIdC_SIZET; cdecl;
function EC_curve_nid2nist(nid: TIdC_INT): PIdAnsiChar; cdecl;
function EC_curve_nist2nid(name: PIdAnsiChar): TIdC_INT; cdecl;
function EC_GROUP_check_named_curve(group: PEC_GROUP; nist_only: TIdC_INT; ctx: PBN_CTX): TIdC_INT; cdecl;
function EC_POINT_new(group: PEC_GROUP): PEC_POINT; cdecl;
procedure EC_POINT_free(point: PEC_POINT); cdecl;
procedure EC_POINT_clear_free(point: PEC_POINT); cdecl;
function EC_POINT_copy(dst: PEC_POINT; src: PEC_POINT): TIdC_INT; cdecl;
function EC_POINT_dup(src: PEC_POINT; group: PEC_GROUP): PEC_POINT; cdecl;
function EC_POINT_set_to_infinity(group: PEC_GROUP; point: PEC_POINT): TIdC_INT; cdecl;
function EC_POINT_method_of(point: PEC_POINT): PEC_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_POINT_set_Jprojective_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_POINT_get_Jprojective_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_POINT_set_affine_coordinates(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl;
function EC_POINT_get_affine_coordinates(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl;
function EC_POINT_set_affine_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_POINT_get_affine_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_POINT_set_compressed_coordinates(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TIdC_INT; ctx: PBN_CTX): TIdC_INT; cdecl;
function EC_POINT_set_compressed_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TIdC_INT; ctx: PBN_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_POINT_set_affine_coordinates_GF2m(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_POINT_get_affine_coordinates_GF2m(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_POINT_set_compressed_coordinates_GF2m(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TIdC_INT; ctx: PBN_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_POINT_point2oct(group: PEC_GROUP; p: PEC_POINT; form: Tpoint_conversion_form_t; buf: PIdAnsiChar; len: TIdC_SIZET; ctx: PBN_CTX): TIdC_SIZET; cdecl;
function EC_POINT_oct2point(group: PEC_GROUP; p: PEC_POINT; buf: PIdAnsiChar; len: TIdC_SIZET; ctx: PBN_CTX): TIdC_INT; cdecl;
function EC_POINT_point2buf(group: PEC_GROUP; point: PEC_POINT; form: Tpoint_conversion_form_t; pbuf: PPIdAnsiChar; ctx: PBN_CTX): TIdC_SIZET; cdecl;
function EC_POINT_point2bn(arg1: PEC_GROUP; arg2: PEC_POINT; form: Tpoint_conversion_form_t; arg4: PBIGNUM; arg5: PBN_CTX): PBIGNUM; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_POINT_bn2point(arg1: PEC_GROUP; arg2: PBIGNUM; arg3: PEC_POINT; arg4: PBN_CTX): PEC_POINT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_POINT_point2hex(arg1: PEC_GROUP; arg2: PEC_POINT; form: Tpoint_conversion_form_t; arg4: PBN_CTX): PIdAnsiChar; cdecl;
function EC_POINT_hex2point(arg1: PEC_GROUP; arg2: PIdAnsiChar; arg3: PEC_POINT; arg4: PBN_CTX): PEC_POINT; cdecl;
function EC_POINT_add(group: PEC_GROUP; r: PEC_POINT; a: PEC_POINT; b: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl;
function EC_POINT_dbl(group: PEC_GROUP; r: PEC_POINT; a: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl;
function EC_POINT_invert(group: PEC_GROUP; a: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl;
function EC_POINT_is_at_infinity(group: PEC_GROUP; p: PEC_POINT): TIdC_INT; cdecl;
function EC_POINT_is_on_curve(group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl;
function EC_POINT_cmp(group: PEC_GROUP; a: PEC_POINT; b: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl;
function EC_POINT_make_affine(group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_POINTs_make_affine(group: PEC_GROUP; num: TIdC_SIZET; points: PPEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_POINTs_mul(group: PEC_GROUP; r: PEC_POINT; n: PBIGNUM; num: TIdC_SIZET; p: PPEC_POINT; m: PPBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_POINT_mul(group: PEC_GROUP; r: PEC_POINT; n: PBIGNUM; q: PEC_POINT; m: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl;
function EC_GROUP_precompute_mult(group: PEC_GROUP; ctx: PBN_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_GROUP_have_precompute_mult(group: PEC_GROUP): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ECPKPARAMETERS_it: PASN1_ITEM; cdecl;
function ECPKPARAMETERS_new: PECPKPARAMETERS; cdecl;
procedure ECPKPARAMETERS_free(a: PECPKPARAMETERS); cdecl;
function ECPARAMETERS_it: PASN1_ITEM; cdecl;
function ECPARAMETERS_new: PECPARAMETERS; cdecl;
procedure ECPARAMETERS_free(a: PECPARAMETERS); cdecl;
function EC_GROUP_get_basis_type(arg1: PEC_GROUP): TIdC_INT; cdecl;
function EC_GROUP_get_trinomial_basis(arg1: PEC_GROUP; k: PIdC_UINT): TIdC_INT; cdecl;
function EC_GROUP_get_pentanomial_basis(arg1: PEC_GROUP; k1: PIdC_UINT; k2: PIdC_UINT; k3: PIdC_UINT): TIdC_INT; cdecl;
function d2i_ECPKParameters(arg1: PPEC_GROUP; _in: PPIdAnsiChar; len: TIdC_LONG): PEC_GROUP; cdecl;
function i2d_ECPKParameters(arg1: PEC_GROUP; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function ECPKParameters_print(bp: PBIO; x: PEC_GROUP; off: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ECPKParameters_print_fp(fp: PFILE; x: PEC_GROUP; off: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_new_ex(ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEC_KEY; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_new: PEC_KEY; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_get_flags(key: PEC_KEY): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure EC_KEY_set_flags(key: PEC_KEY; flags: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure EC_KEY_clear_flags(key: PEC_KEY; flags: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_decoded_from_explicit_params(key: PEC_KEY): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_new_by_curve_name_ex(ctx: POSSL_LIB_CTX; propq: PIdAnsiChar; nid: TIdC_INT): PEC_KEY; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_new_by_curve_name(nid: TIdC_INT): PEC_KEY; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure EC_KEY_free(key: PEC_KEY); cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_copy(dst: PEC_KEY; src: PEC_KEY): PEC_KEY; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_dup(src: PEC_KEY): PEC_KEY; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_up_ref(key: PEC_KEY): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_get0_engine(eckey: PEC_KEY): PENGINE; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_get0_group(key: PEC_KEY): PEC_GROUP; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_set_group(key: PEC_KEY; group: PEC_GROUP): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_get0_private_key(key: PEC_KEY): PBIGNUM; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_set_private_key(key: PEC_KEY; prv: PBIGNUM): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_get0_public_key(key: PEC_KEY): PEC_POINT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_set_public_key(key: PEC_KEY; pub: PEC_POINT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_get_enc_flags(key: PEC_KEY): TIdC_UINT; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure EC_KEY_set_enc_flags(eckey: PEC_KEY; flags: TIdC_UINT); cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_get_conv_form(key: PEC_KEY): Tpoint_conversion_form_t; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure EC_KEY_set_conv_form(eckey: PEC_KEY; cform: Tpoint_conversion_form_t); cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_set_ex_data(key: PEC_KEY; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_get_ex_data(key: PEC_KEY; idx: TIdC_INT): Pointer; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure EC_KEY_set_asn1_flag(eckey: PEC_KEY; asn1_flag: TIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_precompute_mult(key: PEC_KEY; ctx: PBN_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_generate_key(key: PEC_KEY): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_check_key(key: PEC_KEY): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_can_sign(eckey: PEC_KEY): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_set_public_key_affine_coordinates(key: PEC_KEY; x: PBIGNUM; y: PBIGNUM): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_key2buf(key: PEC_KEY; form: Tpoint_conversion_form_t; pbuf: PPIdAnsiChar; ctx: PBN_CTX): TIdC_SIZET; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_oct2key(key: PEC_KEY; buf: PIdAnsiChar; len: TIdC_SIZET; ctx: PBN_CTX): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_oct2priv(key: PEC_KEY; buf: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_priv2oct(key: PEC_KEY; buf: PIdAnsiChar; len: TIdC_SIZET): TIdC_SIZET; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_priv2buf(eckey: PEC_KEY; pbuf: PPIdAnsiChar): TIdC_SIZET; cdecl; deprecated 'In OpenSSL 3_0_0';
function d2i_ECPrivateKey(key: PPEC_KEY; _in: PPIdAnsiChar; len: TIdC_LONG): PEC_KEY; cdecl; deprecated 'In OpenSSL 3_0_0';
function i2d_ECPrivateKey(key: PEC_KEY; _out: PPIdAnsiChar): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function d2i_ECParameters(key: PPEC_KEY; _in: PPIdAnsiChar; len: TIdC_LONG): PEC_KEY; cdecl; deprecated 'In OpenSSL 3_0_0';
function i2d_ECParameters(key: PEC_KEY; _out: PPIdAnsiChar): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function o2i_ECPublicKey(key: PPEC_KEY; _in: PPIdAnsiChar; len: TIdC_LONG): PEC_KEY; cdecl; deprecated 'In OpenSSL 3_0_0';
function i2o_ECPublicKey(key: PEC_KEY; _out: PPIdAnsiChar): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ECParameters_print(bp: PBIO; key: PEC_KEY): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_print(bp: PBIO; key: PEC_KEY; off: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ECParameters_print_fp(fp: PFILE; key: PEC_KEY): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_print_fp(fp: PFILE; key: PEC_KEY; off: TIdC_INT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_OpenSSL: PEC_KEY_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_get_default_method: PEC_KEY_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure EC_KEY_set_default_method(meth: PEC_KEY_METHOD); cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_get_method(key: PEC_KEY): PEC_KEY_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_set_method(key: PEC_KEY; meth: PEC_KEY_METHOD): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_new_method(engine: PENGINE): PEC_KEY; cdecl; deprecated 'In OpenSSL 3_0_0';
function ECDH_KDF_X9_62(_out: PIdAnsiChar; outlen: TIdC_SIZET; Z: PIdAnsiChar; Zlen: TIdC_SIZET; sinfo: PIdAnsiChar; sinfolen: TIdC_SIZET; md: PEVP_MD): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ECDH_compute_key(_out: Pointer; outlen: TIdC_SIZET; pub_key: PEC_POINT; ecdh: PEC_KEY; KDF: TECDH_compute_key_KDF_cb): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ECDSA_SIG_new: PECDSA_SIG; cdecl;
procedure ECDSA_SIG_free(sig: PECDSA_SIG); cdecl;
function d2i_ECDSA_SIG(a: PPECDSA_SIG; _in: PPIdAnsiChar; len: TIdC_LONG): PECDSA_SIG; cdecl;
function i2d_ECDSA_SIG(a: PECDSA_SIG; _out: PPIdAnsiChar): TIdC_INT; cdecl;
procedure ECDSA_SIG_get0(sig: PECDSA_SIG; pr: PPBIGNUM; ps: PPBIGNUM); cdecl;
function ECDSA_SIG_get0_r(sig: PECDSA_SIG): PBIGNUM; cdecl;
function ECDSA_SIG_get0_s(sig: PECDSA_SIG): PBIGNUM; cdecl;
function ECDSA_SIG_set0(sig: PECDSA_SIG; r: PBIGNUM; s: PBIGNUM): TIdC_INT; cdecl;
function ECDSA_do_sign(dgst: PIdAnsiChar; dgst_len: TIdC_INT; eckey: PEC_KEY): PECDSA_SIG; cdecl; deprecated 'In OpenSSL 3_0_0';
function ECDSA_do_sign_ex(dgst: PIdAnsiChar; dgstlen: TIdC_INT; kinv: PBIGNUM; rp: PBIGNUM; eckey: PEC_KEY): PECDSA_SIG; cdecl; deprecated 'In OpenSSL 3_0_0';
function ECDSA_do_verify(dgst: PIdAnsiChar; dgst_len: TIdC_INT; sig: PECDSA_SIG; eckey: PEC_KEY): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ECDSA_sign_setup(eckey: PEC_KEY; ctx: PBN_CTX; kinv: PPBIGNUM; rp: PPBIGNUM): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ECDSA_sign(_type: TIdC_INT; dgst: PIdAnsiChar; dgstlen: TIdC_INT; sig: PIdAnsiChar; siglen: PIdC_UINT; eckey: PEC_KEY): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ECDSA_sign_ex(_type: TIdC_INT; dgst: PIdAnsiChar; dgstlen: TIdC_INT; sig: PIdAnsiChar; siglen: PIdC_UINT; kinv: PBIGNUM; rp: PBIGNUM; eckey: PEC_KEY): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ECDSA_verify(_type: TIdC_INT; dgst: PIdAnsiChar; dgstlen: TIdC_INT; sig: PIdAnsiChar; siglen: TIdC_INT; eckey: PEC_KEY): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ECDSA_size(eckey: PEC_KEY): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function EC_KEY_METHOD_new(meth: PEC_KEY_METHOD): PEC_KEY_METHOD; cdecl; deprecated 'In OpenSSL 3_0_0';
procedure EC_KEY_METHOD_free(meth: PEC_KEY_METHOD); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure EC_KEY_METHOD_set_init(meth: PEC_KEY_METHOD; init: TEC_KEY_METHOD_set_init_init_cb; finish: TEC_KEY_METHOD_set_init_finish_cb; copy: TEC_KEY_METHOD_set_init_copy_cb; set_group: TEC_KEY_METHOD_set_init_set_group_cb; set_private: TEC_KEY_METHOD_set_init_set_private_cb; set_public: TEC_KEY_METHOD_set_init_set_public_cb); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure EC_KEY_METHOD_set_keygen(meth: PEC_KEY_METHOD; keygen: TEC_KEY_METHOD_set_init_init_cb); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure EC_KEY_METHOD_set_compute_key(meth: PEC_KEY_METHOD; ckey: TEC_KEY_METHOD_set_compute_key_ckey_cb); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure EC_KEY_METHOD_set_sign(meth: PEC_KEY_METHOD; sign: TEC_KEY_METHOD_set_sign_sign_cb; sign_setup: TEC_KEY_METHOD_set_sign_sign_setup_cb; sign_sig: TEC_KEY_METHOD_set_sign_sign_sig_cb); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure EC_KEY_METHOD_set_verify(meth: PEC_KEY_METHOD; verify: TEC_KEY_METHOD_set_verify_verify_cb; verify_sig: TEC_KEY_METHOD_set_verify_verify_sig_cb); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure EC_KEY_METHOD_get_init(meth: PEC_KEY_METHOD; pinit: PPIdC_INT; pfinish: PPointer; pcopy: PPIdC_INT; pset_group: PPIdC_INT; pset_private: PPIdC_INT; pset_public: PPIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure EC_KEY_METHOD_get_keygen(meth: PEC_KEY_METHOD; pkeygen: PPIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure EC_KEY_METHOD_get_compute_key(meth: PEC_KEY_METHOD; pck: PPIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure EC_KEY_METHOD_get_sign(meth: PEC_KEY_METHOD; psign: PPIdC_INT; psign_setup: PPIdC_INT; psign_sig: PPECDSA_SIG); cdecl; deprecated 'In OpenSSL 3_0_0';
procedure EC_KEY_METHOD_get_verify(meth: PEC_KEY_METHOD; pverify: PPIdC_INT; pverify_sig: PPIdC_INT); cdecl; deprecated 'In OpenSSL 3_0_0';
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function EVP_EC_gen(curve: Pointer): TIdC_INT; cdecl;


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

function EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx: PEVP_PKEY_CTX; nid: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_ec_paramgen_curve_nid';
function EVP_PKEY_CTX_set_ec_param_enc(ctx: PEVP_PKEY_CTX; param_enc: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_ec_param_enc';
function EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx: PEVP_PKEY_CTX; cofactor_mode: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_ecdh_cofactor_mode';
function EVP_PKEY_CTX_get_ecdh_cofactor_mode(ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_get_ecdh_cofactor_mode';
function EVP_PKEY_CTX_set_ecdh_kdf_type(ctx: PEVP_PKEY_CTX; kdf: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_ecdh_kdf_type';
function EVP_PKEY_CTX_get_ecdh_kdf_type(ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_get_ecdh_kdf_type';
function EVP_PKEY_CTX_set_ecdh_kdf_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_ecdh_kdf_md';
function EVP_PKEY_CTX_get_ecdh_kdf_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_get_ecdh_kdf_md';
function EVP_PKEY_CTX_set_ecdh_kdf_outlen(ctx: PEVP_PKEY_CTX; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set_ecdh_kdf_outlen';
function EVP_PKEY_CTX_get_ecdh_kdf_outlen(ctx: PEVP_PKEY_CTX; len: PIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_get_ecdh_kdf_outlen';
function EVP_PKEY_CTX_set0_ecdh_kdf_ukm(ctx: PEVP_PKEY_CTX; ukm: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_set0_ecdh_kdf_ukm';
function EVP_PKEY_CTX_get0_ecdh_kdf_ukm(ctx: PEVP_PKEY_CTX; ukm: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_CTX_get0_ecdh_kdf_ukm';
function OSSL_EC_curve_nid2name(nid: TIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'OSSL_EC_curve_nid2name';
function EC_GFp_simple_method: PEC_METHOD; cdecl external CLibCrypto name 'EC_GFp_simple_method';
function EC_GFp_mont_method: PEC_METHOD; cdecl external CLibCrypto name 'EC_GFp_mont_method';
function EC_GFp_nist_method: PEC_METHOD; cdecl external CLibCrypto name 'EC_GFp_nist_method';
function EC_GF2m_simple_method: PEC_METHOD; cdecl external CLibCrypto name 'EC_GF2m_simple_method';
function EC_GROUP_new(meth: PEC_METHOD): PEC_GROUP; cdecl external CLibCrypto name 'EC_GROUP_new';
procedure EC_GROUP_clear_free(group: PEC_GROUP); cdecl external CLibCrypto name 'EC_GROUP_clear_free';
function EC_GROUP_method_of(group: PEC_GROUP): PEC_METHOD; cdecl external CLibCrypto name 'EC_GROUP_method_of';
function EC_METHOD_get_field_type(meth: PEC_METHOD): TIdC_INT; cdecl external CLibCrypto name 'EC_METHOD_get_field_type';
procedure EC_GROUP_free(group: PEC_GROUP); cdecl external CLibCrypto name 'EC_GROUP_free';
function EC_GROUP_copy(dst: PEC_GROUP; src: PEC_GROUP): TIdC_INT; cdecl external CLibCrypto name 'EC_GROUP_copy';
function EC_GROUP_dup(src: PEC_GROUP): PEC_GROUP; cdecl external CLibCrypto name 'EC_GROUP_dup';
function EC_GROUP_set_generator(group: PEC_GROUP; generator: PEC_POINT; order: PBIGNUM; cofactor: PBIGNUM): TIdC_INT; cdecl external CLibCrypto name 'EC_GROUP_set_generator';
function EC_GROUP_get0_generator(group: PEC_GROUP): PEC_POINT; cdecl external CLibCrypto name 'EC_GROUP_get0_generator';
function EC_GROUP_get_mont_data(group: PEC_GROUP): PBN_MONT_CTX; cdecl external CLibCrypto name 'EC_GROUP_get_mont_data';
function EC_GROUP_get_order(group: PEC_GROUP; order: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_GROUP_get_order';
function EC_GROUP_get0_order(group: PEC_GROUP): PBIGNUM; cdecl external CLibCrypto name 'EC_GROUP_get0_order';
function EC_GROUP_order_bits(group: PEC_GROUP): TIdC_INT; cdecl external CLibCrypto name 'EC_GROUP_order_bits';
function EC_GROUP_get_cofactor(group: PEC_GROUP; cofactor: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_GROUP_get_cofactor';
function EC_GROUP_get0_cofactor(group: PEC_GROUP): PBIGNUM; cdecl external CLibCrypto name 'EC_GROUP_get0_cofactor';
procedure EC_GROUP_set_curve_name(group: PEC_GROUP; nid: TIdC_INT); cdecl external CLibCrypto name 'EC_GROUP_set_curve_name';
function EC_GROUP_get_curve_name(group: PEC_GROUP): TIdC_INT; cdecl external CLibCrypto name 'EC_GROUP_get_curve_name';
function EC_GROUP_get0_field(group: PEC_GROUP): PBIGNUM; cdecl external CLibCrypto name 'EC_GROUP_get0_field';
function EC_GROUP_get_field_type(group: PEC_GROUP): TIdC_INT; cdecl external CLibCrypto name 'EC_GROUP_get_field_type';
procedure EC_GROUP_set_asn1_flag(group: PEC_GROUP; flag: TIdC_INT); cdecl external CLibCrypto name 'EC_GROUP_set_asn1_flag';
function EC_GROUP_get_asn1_flag(group: PEC_GROUP): TIdC_INT; cdecl external CLibCrypto name 'EC_GROUP_get_asn1_flag';
procedure EC_GROUP_set_point_conversion_form(group: PEC_GROUP; form: Tpoint_conversion_form_t); cdecl external CLibCrypto name 'EC_GROUP_set_point_conversion_form';
function EC_GROUP_get_point_conversion_form(arg1: PEC_GROUP): Tpoint_conversion_form_t; cdecl external CLibCrypto name 'EC_GROUP_get_point_conversion_form';
function EC_GROUP_get0_seed(x: PEC_GROUP): PIdAnsiChar; cdecl external CLibCrypto name 'EC_GROUP_get0_seed';
function EC_GROUP_get_seed_len(arg1: PEC_GROUP): TIdC_SIZET; cdecl external CLibCrypto name 'EC_GROUP_get_seed_len';
function EC_GROUP_set_seed(arg1: PEC_GROUP; arg2: PIdAnsiChar; len: TIdC_SIZET): TIdC_SIZET; cdecl external CLibCrypto name 'EC_GROUP_set_seed';
function EC_GROUP_set_curve(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_GROUP_set_curve';
function EC_GROUP_get_curve(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_GROUP_get_curve';
function EC_GROUP_set_curve_GFp(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_GROUP_set_curve_GFp';
function EC_GROUP_get_curve_GFp(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_GROUP_get_curve_GFp';
function EC_GROUP_set_curve_GF2m(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_GROUP_set_curve_GF2m';
function EC_GROUP_get_curve_GF2m(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_GROUP_get_curve_GF2m';
function EC_GROUP_get_degree(group: PEC_GROUP): TIdC_INT; cdecl external CLibCrypto name 'EC_GROUP_get_degree';
function EC_GROUP_check(group: PEC_GROUP; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_GROUP_check';
function EC_GROUP_check_discriminant(group: PEC_GROUP; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_GROUP_check_discriminant';
function EC_GROUP_cmp(a: PEC_GROUP; b: PEC_GROUP; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_GROUP_cmp';
function EC_GROUP_new_curve_GFp(p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl external CLibCrypto name 'EC_GROUP_new_curve_GFp';
function EC_GROUP_new_curve_GF2m(p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl external CLibCrypto name 'EC_GROUP_new_curve_GF2m';
function EC_GROUP_new_from_params(params: POSSL_PARAM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEC_GROUP; cdecl external CLibCrypto name 'EC_GROUP_new_from_params';
function EC_GROUP_to_params(group: PEC_GROUP; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; bnctx: PBN_CTX): POSSL_PARAM; cdecl external CLibCrypto name 'EC_GROUP_to_params';
function EC_GROUP_new_by_curve_name_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; nid: TIdC_INT): PEC_GROUP; cdecl external CLibCrypto name 'EC_GROUP_new_by_curve_name_ex';
function EC_GROUP_new_by_curve_name(nid: TIdC_INT): PEC_GROUP; cdecl external CLibCrypto name 'EC_GROUP_new_by_curve_name';
function EC_GROUP_new_from_ecparameters(params: PECPARAMETERS): PEC_GROUP; cdecl external CLibCrypto name 'EC_GROUP_new_from_ecparameters';
function EC_GROUP_get_ecparameters(group: PEC_GROUP; params: PECPARAMETERS): PECPARAMETERS; cdecl external CLibCrypto name 'EC_GROUP_get_ecparameters';
function EC_GROUP_new_from_ecpkparameters(params: PECPKPARAMETERS): PEC_GROUP; cdecl external CLibCrypto name 'EC_GROUP_new_from_ecpkparameters';
function EC_GROUP_get_ecpkparameters(group: PEC_GROUP; params: PECPKPARAMETERS): PECPKPARAMETERS; cdecl external CLibCrypto name 'EC_GROUP_get_ecpkparameters';
function EC_get_builtin_curves(r: PEC_builtin_curve; nitems: TIdC_SIZET): TIdC_SIZET; cdecl external CLibCrypto name 'EC_get_builtin_curves';
function EC_curve_nid2nist(nid: TIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'EC_curve_nid2nist';
function EC_curve_nist2nid(name: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'EC_curve_nist2nid';
function EC_GROUP_check_named_curve(group: PEC_GROUP; nist_only: TIdC_INT; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_GROUP_check_named_curve';
function EC_POINT_new(group: PEC_GROUP): PEC_POINT; cdecl external CLibCrypto name 'EC_POINT_new';
procedure EC_POINT_free(point: PEC_POINT); cdecl external CLibCrypto name 'EC_POINT_free';
procedure EC_POINT_clear_free(point: PEC_POINT); cdecl external CLibCrypto name 'EC_POINT_clear_free';
function EC_POINT_copy(dst: PEC_POINT; src: PEC_POINT): TIdC_INT; cdecl external CLibCrypto name 'EC_POINT_copy';
function EC_POINT_dup(src: PEC_POINT; group: PEC_GROUP): PEC_POINT; cdecl external CLibCrypto name 'EC_POINT_dup';
function EC_POINT_set_to_infinity(group: PEC_GROUP; point: PEC_POINT): TIdC_INT; cdecl external CLibCrypto name 'EC_POINT_set_to_infinity';
function EC_POINT_method_of(point: PEC_POINT): PEC_METHOD; cdecl external CLibCrypto name 'EC_POINT_method_of';
function EC_POINT_set_Jprojective_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_POINT_set_Jprojective_coordinates_GFp';
function EC_POINT_get_Jprojective_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_POINT_get_Jprojective_coordinates_GFp';
function EC_POINT_set_affine_coordinates(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_POINT_set_affine_coordinates';
function EC_POINT_get_affine_coordinates(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_POINT_get_affine_coordinates';
function EC_POINT_set_affine_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_POINT_set_affine_coordinates_GFp';
function EC_POINT_get_affine_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_POINT_get_affine_coordinates_GFp';
function EC_POINT_set_compressed_coordinates(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TIdC_INT; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_POINT_set_compressed_coordinates';
function EC_POINT_set_compressed_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TIdC_INT; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_POINT_set_compressed_coordinates_GFp';
function EC_POINT_set_affine_coordinates_GF2m(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_POINT_set_affine_coordinates_GF2m';
function EC_POINT_get_affine_coordinates_GF2m(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_POINT_get_affine_coordinates_GF2m';
function EC_POINT_set_compressed_coordinates_GF2m(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TIdC_INT; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_POINT_set_compressed_coordinates_GF2m';
function EC_POINT_point2oct(group: PEC_GROUP; p: PEC_POINT; form: Tpoint_conversion_form_t; buf: PIdAnsiChar; len: TIdC_SIZET; ctx: PBN_CTX): TIdC_SIZET; cdecl external CLibCrypto name 'EC_POINT_point2oct';
function EC_POINT_oct2point(group: PEC_GROUP; p: PEC_POINT; buf: PIdAnsiChar; len: TIdC_SIZET; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_POINT_oct2point';
function EC_POINT_point2buf(group: PEC_GROUP; point: PEC_POINT; form: Tpoint_conversion_form_t; pbuf: PPIdAnsiChar; ctx: PBN_CTX): TIdC_SIZET; cdecl external CLibCrypto name 'EC_POINT_point2buf';
function EC_POINT_point2bn(arg1: PEC_GROUP; arg2: PEC_POINT; form: Tpoint_conversion_form_t; arg4: PBIGNUM; arg5: PBN_CTX): PBIGNUM; cdecl external CLibCrypto name 'EC_POINT_point2bn';
function EC_POINT_bn2point(arg1: PEC_GROUP; arg2: PBIGNUM; arg3: PEC_POINT; arg4: PBN_CTX): PEC_POINT; cdecl external CLibCrypto name 'EC_POINT_bn2point';
function EC_POINT_point2hex(arg1: PEC_GROUP; arg2: PEC_POINT; form: Tpoint_conversion_form_t; arg4: PBN_CTX): PIdAnsiChar; cdecl external CLibCrypto name 'EC_POINT_point2hex';
function EC_POINT_hex2point(arg1: PEC_GROUP; arg2: PIdAnsiChar; arg3: PEC_POINT; arg4: PBN_CTX): PEC_POINT; cdecl external CLibCrypto name 'EC_POINT_hex2point';
function EC_POINT_add(group: PEC_GROUP; r: PEC_POINT; a: PEC_POINT; b: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_POINT_add';
function EC_POINT_dbl(group: PEC_GROUP; r: PEC_POINT; a: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_POINT_dbl';
function EC_POINT_invert(group: PEC_GROUP; a: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_POINT_invert';
function EC_POINT_is_at_infinity(group: PEC_GROUP; p: PEC_POINT): TIdC_INT; cdecl external CLibCrypto name 'EC_POINT_is_at_infinity';
function EC_POINT_is_on_curve(group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_POINT_is_on_curve';
function EC_POINT_cmp(group: PEC_GROUP; a: PEC_POINT; b: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_POINT_cmp';
function EC_POINT_make_affine(group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_POINT_make_affine';
function EC_POINTs_make_affine(group: PEC_GROUP; num: TIdC_SIZET; points: PPEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_POINTs_make_affine';
function EC_POINTs_mul(group: PEC_GROUP; r: PEC_POINT; n: PBIGNUM; num: TIdC_SIZET; p: PPEC_POINT; m: PPBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_POINTs_mul';
function EC_POINT_mul(group: PEC_GROUP; r: PEC_POINT; n: PBIGNUM; q: PEC_POINT; m: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_POINT_mul';
function EC_GROUP_precompute_mult(group: PEC_GROUP; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_GROUP_precompute_mult';
function EC_GROUP_have_precompute_mult(group: PEC_GROUP): TIdC_INT; cdecl external CLibCrypto name 'EC_GROUP_have_precompute_mult';
function ECPKPARAMETERS_it: PASN1_ITEM; cdecl external CLibCrypto name 'ECPKPARAMETERS_it';
function ECPKPARAMETERS_new: PECPKPARAMETERS; cdecl external CLibCrypto name 'ECPKPARAMETERS_new';
procedure ECPKPARAMETERS_free(a: PECPKPARAMETERS); cdecl external CLibCrypto name 'ECPKPARAMETERS_free';
function ECPARAMETERS_it: PASN1_ITEM; cdecl external CLibCrypto name 'ECPARAMETERS_it';
function ECPARAMETERS_new: PECPARAMETERS; cdecl external CLibCrypto name 'ECPARAMETERS_new';
procedure ECPARAMETERS_free(a: PECPARAMETERS); cdecl external CLibCrypto name 'ECPARAMETERS_free';
function EC_GROUP_get_basis_type(arg1: PEC_GROUP): TIdC_INT; cdecl external CLibCrypto name 'EC_GROUP_get_basis_type';
function EC_GROUP_get_trinomial_basis(arg1: PEC_GROUP; k: PIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'EC_GROUP_get_trinomial_basis';
function EC_GROUP_get_pentanomial_basis(arg1: PEC_GROUP; k1: PIdC_UINT; k2: PIdC_UINT; k3: PIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'EC_GROUP_get_pentanomial_basis';
function d2i_ECPKParameters(arg1: PPEC_GROUP; _in: PPIdAnsiChar; len: TIdC_LONG): PEC_GROUP; cdecl external CLibCrypto name 'd2i_ECPKParameters';
function i2d_ECPKParameters(arg1: PEC_GROUP; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ECPKParameters';
function ECPKParameters_print(bp: PBIO; x: PEC_GROUP; off: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'ECPKParameters_print';
function ECPKParameters_print_fp(fp: PFILE; x: PEC_GROUP; off: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'ECPKParameters_print_fp';
function EC_KEY_new_ex(ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEC_KEY; cdecl external CLibCrypto name 'EC_KEY_new_ex';
function EC_KEY_new: PEC_KEY; cdecl external CLibCrypto name 'EC_KEY_new';
function EC_KEY_get_flags(key: PEC_KEY): TIdC_INT; cdecl external CLibCrypto name 'EC_KEY_get_flags';
procedure EC_KEY_set_flags(key: PEC_KEY; flags: TIdC_INT); cdecl external CLibCrypto name 'EC_KEY_set_flags';
procedure EC_KEY_clear_flags(key: PEC_KEY; flags: TIdC_INT); cdecl external CLibCrypto name 'EC_KEY_clear_flags';
function EC_KEY_decoded_from_explicit_params(key: PEC_KEY): TIdC_INT; cdecl external CLibCrypto name 'EC_KEY_decoded_from_explicit_params';
function EC_KEY_new_by_curve_name_ex(ctx: POSSL_LIB_CTX; propq: PIdAnsiChar; nid: TIdC_INT): PEC_KEY; cdecl external CLibCrypto name 'EC_KEY_new_by_curve_name_ex';
function EC_KEY_new_by_curve_name(nid: TIdC_INT): PEC_KEY; cdecl external CLibCrypto name 'EC_KEY_new_by_curve_name';
procedure EC_KEY_free(key: PEC_KEY); cdecl external CLibCrypto name 'EC_KEY_free';
function EC_KEY_copy(dst: PEC_KEY; src: PEC_KEY): PEC_KEY; cdecl external CLibCrypto name 'EC_KEY_copy';
function EC_KEY_dup(src: PEC_KEY): PEC_KEY; cdecl external CLibCrypto name 'EC_KEY_dup';
function EC_KEY_up_ref(key: PEC_KEY): TIdC_INT; cdecl external CLibCrypto name 'EC_KEY_up_ref';
function EC_KEY_get0_engine(eckey: PEC_KEY): PENGINE; cdecl external CLibCrypto name 'EC_KEY_get0_engine';
function EC_KEY_get0_group(key: PEC_KEY): PEC_GROUP; cdecl external CLibCrypto name 'EC_KEY_get0_group';
function EC_KEY_set_group(key: PEC_KEY; group: PEC_GROUP): TIdC_INT; cdecl external CLibCrypto name 'EC_KEY_set_group';
function EC_KEY_get0_private_key(key: PEC_KEY): PBIGNUM; cdecl external CLibCrypto name 'EC_KEY_get0_private_key';
function EC_KEY_set_private_key(key: PEC_KEY; prv: PBIGNUM): TIdC_INT; cdecl external CLibCrypto name 'EC_KEY_set_private_key';
function EC_KEY_get0_public_key(key: PEC_KEY): PEC_POINT; cdecl external CLibCrypto name 'EC_KEY_get0_public_key';
function EC_KEY_set_public_key(key: PEC_KEY; pub: PEC_POINT): TIdC_INT; cdecl external CLibCrypto name 'EC_KEY_set_public_key';
function EC_KEY_get_enc_flags(key: PEC_KEY): TIdC_UINT; cdecl external CLibCrypto name 'EC_KEY_get_enc_flags';
procedure EC_KEY_set_enc_flags(eckey: PEC_KEY; flags: TIdC_UINT); cdecl external CLibCrypto name 'EC_KEY_set_enc_flags';
function EC_KEY_get_conv_form(key: PEC_KEY): Tpoint_conversion_form_t; cdecl external CLibCrypto name 'EC_KEY_get_conv_form';
procedure EC_KEY_set_conv_form(eckey: PEC_KEY; cform: Tpoint_conversion_form_t); cdecl external CLibCrypto name 'EC_KEY_set_conv_form';
function EC_KEY_set_ex_data(key: PEC_KEY; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl external CLibCrypto name 'EC_KEY_set_ex_data';
function EC_KEY_get_ex_data(key: PEC_KEY; idx: TIdC_INT): Pointer; cdecl external CLibCrypto name 'EC_KEY_get_ex_data';
procedure EC_KEY_set_asn1_flag(eckey: PEC_KEY; asn1_flag: TIdC_INT); cdecl external CLibCrypto name 'EC_KEY_set_asn1_flag';
function EC_KEY_precompute_mult(key: PEC_KEY; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_KEY_precompute_mult';
function EC_KEY_generate_key(key: PEC_KEY): TIdC_INT; cdecl external CLibCrypto name 'EC_KEY_generate_key';
function EC_KEY_check_key(key: PEC_KEY): TIdC_INT; cdecl external CLibCrypto name 'EC_KEY_check_key';
function EC_KEY_can_sign(eckey: PEC_KEY): TIdC_INT; cdecl external CLibCrypto name 'EC_KEY_can_sign';
function EC_KEY_set_public_key_affine_coordinates(key: PEC_KEY; x: PBIGNUM; y: PBIGNUM): TIdC_INT; cdecl external CLibCrypto name 'EC_KEY_set_public_key_affine_coordinates';
function EC_KEY_key2buf(key: PEC_KEY; form: Tpoint_conversion_form_t; pbuf: PPIdAnsiChar; ctx: PBN_CTX): TIdC_SIZET; cdecl external CLibCrypto name 'EC_KEY_key2buf';
function EC_KEY_oct2key(key: PEC_KEY; buf: PIdAnsiChar; len: TIdC_SIZET; ctx: PBN_CTX): TIdC_INT; cdecl external CLibCrypto name 'EC_KEY_oct2key';
function EC_KEY_oct2priv(key: PEC_KEY; buf: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'EC_KEY_oct2priv';
function EC_KEY_priv2oct(key: PEC_KEY; buf: PIdAnsiChar; len: TIdC_SIZET): TIdC_SIZET; cdecl external CLibCrypto name 'EC_KEY_priv2oct';
function EC_KEY_priv2buf(eckey: PEC_KEY; pbuf: PPIdAnsiChar): TIdC_SIZET; cdecl external CLibCrypto name 'EC_KEY_priv2buf';
function d2i_ECPrivateKey(key: PPEC_KEY; _in: PPIdAnsiChar; len: TIdC_LONG): PEC_KEY; cdecl external CLibCrypto name 'd2i_ECPrivateKey';
function i2d_ECPrivateKey(key: PEC_KEY; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ECPrivateKey';
function d2i_ECParameters(key: PPEC_KEY; _in: PPIdAnsiChar; len: TIdC_LONG): PEC_KEY; cdecl external CLibCrypto name 'd2i_ECParameters';
function i2d_ECParameters(key: PEC_KEY; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ECParameters';
function o2i_ECPublicKey(key: PPEC_KEY; _in: PPIdAnsiChar; len: TIdC_LONG): PEC_KEY; cdecl external CLibCrypto name 'o2i_ECPublicKey';
function i2o_ECPublicKey(key: PEC_KEY; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2o_ECPublicKey';
function ECParameters_print(bp: PBIO; key: PEC_KEY): TIdC_INT; cdecl external CLibCrypto name 'ECParameters_print';
function EC_KEY_print(bp: PBIO; key: PEC_KEY; off: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EC_KEY_print';
function ECParameters_print_fp(fp: PFILE; key: PEC_KEY): TIdC_INT; cdecl external CLibCrypto name 'ECParameters_print_fp';
function EC_KEY_print_fp(fp: PFILE; key: PEC_KEY; off: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EC_KEY_print_fp';
function EC_KEY_OpenSSL: PEC_KEY_METHOD; cdecl external CLibCrypto name 'EC_KEY_OpenSSL';
function EC_KEY_get_default_method: PEC_KEY_METHOD; cdecl external CLibCrypto name 'EC_KEY_get_default_method';
procedure EC_KEY_set_default_method(meth: PEC_KEY_METHOD); cdecl external CLibCrypto name 'EC_KEY_set_default_method';
function EC_KEY_get_method(key: PEC_KEY): PEC_KEY_METHOD; cdecl external CLibCrypto name 'EC_KEY_get_method';
function EC_KEY_set_method(key: PEC_KEY; meth: PEC_KEY_METHOD): TIdC_INT; cdecl external CLibCrypto name 'EC_KEY_set_method';
function EC_KEY_new_method(engine: PENGINE): PEC_KEY; cdecl external CLibCrypto name 'EC_KEY_new_method';
function ECDH_KDF_X9_62(_out: PIdAnsiChar; outlen: TIdC_SIZET; Z: PIdAnsiChar; Zlen: TIdC_SIZET; sinfo: PIdAnsiChar; sinfolen: TIdC_SIZET; md: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'ECDH_KDF_X9_62';
function ECDH_compute_key(_out: Pointer; outlen: TIdC_SIZET; pub_key: PEC_POINT; ecdh: PEC_KEY; KDF: TECDH_compute_key_KDF_cb): TIdC_INT; cdecl external CLibCrypto name 'ECDH_compute_key';
function ECDSA_SIG_new: PECDSA_SIG; cdecl external CLibCrypto name 'ECDSA_SIG_new';
procedure ECDSA_SIG_free(sig: PECDSA_SIG); cdecl external CLibCrypto name 'ECDSA_SIG_free';
function d2i_ECDSA_SIG(a: PPECDSA_SIG; _in: PPIdAnsiChar; len: TIdC_LONG): PECDSA_SIG; cdecl external CLibCrypto name 'd2i_ECDSA_SIG';
function i2d_ECDSA_SIG(a: PECDSA_SIG; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_ECDSA_SIG';
procedure ECDSA_SIG_get0(sig: PECDSA_SIG; pr: PPBIGNUM; ps: PPBIGNUM); cdecl external CLibCrypto name 'ECDSA_SIG_get0';
function ECDSA_SIG_get0_r(sig: PECDSA_SIG): PBIGNUM; cdecl external CLibCrypto name 'ECDSA_SIG_get0_r';
function ECDSA_SIG_get0_s(sig: PECDSA_SIG): PBIGNUM; cdecl external CLibCrypto name 'ECDSA_SIG_get0_s';
function ECDSA_SIG_set0(sig: PECDSA_SIG; r: PBIGNUM; s: PBIGNUM): TIdC_INT; cdecl external CLibCrypto name 'ECDSA_SIG_set0';
function ECDSA_do_sign(dgst: PIdAnsiChar; dgst_len: TIdC_INT; eckey: PEC_KEY): PECDSA_SIG; cdecl external CLibCrypto name 'ECDSA_do_sign';
function ECDSA_do_sign_ex(dgst: PIdAnsiChar; dgstlen: TIdC_INT; kinv: PBIGNUM; rp: PBIGNUM; eckey: PEC_KEY): PECDSA_SIG; cdecl external CLibCrypto name 'ECDSA_do_sign_ex';
function ECDSA_do_verify(dgst: PIdAnsiChar; dgst_len: TIdC_INT; sig: PECDSA_SIG; eckey: PEC_KEY): TIdC_INT; cdecl external CLibCrypto name 'ECDSA_do_verify';
function ECDSA_sign_setup(eckey: PEC_KEY; ctx: PBN_CTX; kinv: PPBIGNUM; rp: PPBIGNUM): TIdC_INT; cdecl external CLibCrypto name 'ECDSA_sign_setup';
function ECDSA_sign(_type: TIdC_INT; dgst: PIdAnsiChar; dgstlen: TIdC_INT; sig: PIdAnsiChar; siglen: PIdC_UINT; eckey: PEC_KEY): TIdC_INT; cdecl external CLibCrypto name 'ECDSA_sign';
function ECDSA_sign_ex(_type: TIdC_INT; dgst: PIdAnsiChar; dgstlen: TIdC_INT; sig: PIdAnsiChar; siglen: PIdC_UINT; kinv: PBIGNUM; rp: PBIGNUM; eckey: PEC_KEY): TIdC_INT; cdecl external CLibCrypto name 'ECDSA_sign_ex';
function ECDSA_verify(_type: TIdC_INT; dgst: PIdAnsiChar; dgstlen: TIdC_INT; sig: PIdAnsiChar; siglen: TIdC_INT; eckey: PEC_KEY): TIdC_INT; cdecl external CLibCrypto name 'ECDSA_verify';
function ECDSA_size(eckey: PEC_KEY): TIdC_INT; cdecl external CLibCrypto name 'ECDSA_size';
function EC_KEY_METHOD_new(meth: PEC_KEY_METHOD): PEC_KEY_METHOD; cdecl external CLibCrypto name 'EC_KEY_METHOD_new';
procedure EC_KEY_METHOD_free(meth: PEC_KEY_METHOD); cdecl external CLibCrypto name 'EC_KEY_METHOD_free';
procedure EC_KEY_METHOD_set_init(meth: PEC_KEY_METHOD; init: TEC_KEY_METHOD_set_init_init_cb; finish: TEC_KEY_METHOD_set_init_finish_cb; copy: TEC_KEY_METHOD_set_init_copy_cb; set_group: TEC_KEY_METHOD_set_init_set_group_cb; set_private: TEC_KEY_METHOD_set_init_set_private_cb; set_public: TEC_KEY_METHOD_set_init_set_public_cb); cdecl external CLibCrypto name 'EC_KEY_METHOD_set_init';
procedure EC_KEY_METHOD_set_keygen(meth: PEC_KEY_METHOD; keygen: TEC_KEY_METHOD_set_init_init_cb); cdecl external CLibCrypto name 'EC_KEY_METHOD_set_keygen';
procedure EC_KEY_METHOD_set_compute_key(meth: PEC_KEY_METHOD; ckey: TEC_KEY_METHOD_set_compute_key_ckey_cb); cdecl external CLibCrypto name 'EC_KEY_METHOD_set_compute_key';
procedure EC_KEY_METHOD_set_sign(meth: PEC_KEY_METHOD; sign: TEC_KEY_METHOD_set_sign_sign_cb; sign_setup: TEC_KEY_METHOD_set_sign_sign_setup_cb; sign_sig: TEC_KEY_METHOD_set_sign_sign_sig_cb); cdecl external CLibCrypto name 'EC_KEY_METHOD_set_sign';
procedure EC_KEY_METHOD_set_verify(meth: PEC_KEY_METHOD; verify: TEC_KEY_METHOD_set_verify_verify_cb; verify_sig: TEC_KEY_METHOD_set_verify_verify_sig_cb); cdecl external CLibCrypto name 'EC_KEY_METHOD_set_verify';
procedure EC_KEY_METHOD_get_init(meth: PEC_KEY_METHOD; pinit: PPIdC_INT; pfinish: PPointer; pcopy: PPIdC_INT; pset_group: PPIdC_INT; pset_private: PPIdC_INT; pset_public: PPIdC_INT); cdecl external CLibCrypto name 'EC_KEY_METHOD_get_init';
procedure EC_KEY_METHOD_get_keygen(meth: PEC_KEY_METHOD; pkeygen: PPIdC_INT); cdecl external CLibCrypto name 'EC_KEY_METHOD_get_keygen';
procedure EC_KEY_METHOD_get_compute_key(meth: PEC_KEY_METHOD; pck: PPIdC_INT); cdecl external CLibCrypto name 'EC_KEY_METHOD_get_compute_key';
procedure EC_KEY_METHOD_get_sign(meth: PEC_KEY_METHOD; psign: PPIdC_INT; psign_setup: PPIdC_INT; psign_sig: PPECDSA_SIG); cdecl external CLibCrypto name 'EC_KEY_METHOD_get_sign';
procedure EC_KEY_METHOD_get_verify(meth: PEC_KEY_METHOD; pverify: PPIdC_INT; pverify_sig: PPIdC_INT); cdecl external CLibCrypto name 'EC_KEY_METHOD_get_verify';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  EVP_PKEY_CTX_set_ec_paramgen_curve_nid_procname = 'EVP_PKEY_CTX_set_ec_paramgen_curve_nid';
  EVP_PKEY_CTX_set_ec_paramgen_curve_nid_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_ec_param_enc_procname = 'EVP_PKEY_CTX_set_ec_param_enc';
  EVP_PKEY_CTX_set_ec_param_enc_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_ecdh_cofactor_mode_procname = 'EVP_PKEY_CTX_set_ecdh_cofactor_mode';
  EVP_PKEY_CTX_set_ecdh_cofactor_mode_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_get_ecdh_cofactor_mode_procname = 'EVP_PKEY_CTX_get_ecdh_cofactor_mode';
  EVP_PKEY_CTX_get_ecdh_cofactor_mode_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_ecdh_kdf_type_procname = 'EVP_PKEY_CTX_set_ecdh_kdf_type';
  EVP_PKEY_CTX_set_ecdh_kdf_type_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_get_ecdh_kdf_type_procname = 'EVP_PKEY_CTX_get_ecdh_kdf_type';
  EVP_PKEY_CTX_get_ecdh_kdf_type_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_ecdh_kdf_md_procname = 'EVP_PKEY_CTX_set_ecdh_kdf_md';
  EVP_PKEY_CTX_set_ecdh_kdf_md_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_get_ecdh_kdf_md_procname = 'EVP_PKEY_CTX_get_ecdh_kdf_md';
  EVP_PKEY_CTX_get_ecdh_kdf_md_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set_ecdh_kdf_outlen_procname = 'EVP_PKEY_CTX_set_ecdh_kdf_outlen';
  EVP_PKEY_CTX_set_ecdh_kdf_outlen_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_get_ecdh_kdf_outlen_procname = 'EVP_PKEY_CTX_get_ecdh_kdf_outlen';
  EVP_PKEY_CTX_get_ecdh_kdf_outlen_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_set0_ecdh_kdf_ukm_procname = 'EVP_PKEY_CTX_set0_ecdh_kdf_ukm';
  EVP_PKEY_CTX_set0_ecdh_kdf_ukm_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY_CTX_get0_ecdh_kdf_ukm_procname = 'EVP_PKEY_CTX_get0_ecdh_kdf_ukm';
  EVP_PKEY_CTX_get0_ecdh_kdf_ukm_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  OSSL_EC_curve_nid2name_procname = 'OSSL_EC_curve_nid2name';
  OSSL_EC_curve_nid2name_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_GFp_simple_method_procname = 'EC_GFp_simple_method';
  EC_GFp_simple_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_GFp_simple_method_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_GFp_mont_method_procname = 'EC_GFp_mont_method';
  EC_GFp_mont_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_GFp_mont_method_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_GFp_nist_method_procname = 'EC_GFp_nist_method';
  EC_GFp_nist_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_GFp_nist_method_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_GF2m_simple_method_procname = 'EC_GF2m_simple_method';
  EC_GF2m_simple_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_GF2m_simple_method_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_GROUP_new_procname = 'EC_GROUP_new';
  EC_GROUP_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_GROUP_new_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_GROUP_clear_free_procname = 'EC_GROUP_clear_free';
  EC_GROUP_clear_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_GROUP_clear_free_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_GROUP_method_of_procname = 'EC_GROUP_method_of';
  EC_GROUP_method_of_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_GROUP_method_of_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_METHOD_get_field_type_procname = 'EC_METHOD_get_field_type';
  EC_METHOD_get_field_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_METHOD_get_field_type_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_GROUP_free_procname = 'EC_GROUP_free';
  EC_GROUP_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_copy_procname = 'EC_GROUP_copy';
  EC_GROUP_copy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_dup_procname = 'EC_GROUP_dup';
  EC_GROUP_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_set_generator_procname = 'EC_GROUP_set_generator';
  EC_GROUP_set_generator_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_get0_generator_procname = 'EC_GROUP_get0_generator';
  EC_GROUP_get0_generator_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_get_mont_data_procname = 'EC_GROUP_get_mont_data';
  EC_GROUP_get_mont_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_get_order_procname = 'EC_GROUP_get_order';
  EC_GROUP_get_order_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_get0_order_procname = 'EC_GROUP_get0_order';
  EC_GROUP_get0_order_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_order_bits_procname = 'EC_GROUP_order_bits';
  EC_GROUP_order_bits_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_get_cofactor_procname = 'EC_GROUP_get_cofactor';
  EC_GROUP_get_cofactor_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_get0_cofactor_procname = 'EC_GROUP_get0_cofactor';
  EC_GROUP_get0_cofactor_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_set_curve_name_procname = 'EC_GROUP_set_curve_name';
  EC_GROUP_set_curve_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_get_curve_name_procname = 'EC_GROUP_get_curve_name';
  EC_GROUP_get_curve_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_get0_field_procname = 'EC_GROUP_get0_field';
  EC_GROUP_get0_field_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_GROUP_get_field_type_procname = 'EC_GROUP_get_field_type';
  EC_GROUP_get_field_type_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_GROUP_set_asn1_flag_procname = 'EC_GROUP_set_asn1_flag';
  EC_GROUP_set_asn1_flag_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_get_asn1_flag_procname = 'EC_GROUP_get_asn1_flag';
  EC_GROUP_get_asn1_flag_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_set_point_conversion_form_procname = 'EC_GROUP_set_point_conversion_form';
  EC_GROUP_set_point_conversion_form_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_get_point_conversion_form_procname = 'EC_GROUP_get_point_conversion_form';
  EC_GROUP_get_point_conversion_form_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_get0_seed_procname = 'EC_GROUP_get0_seed';
  EC_GROUP_get0_seed_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_get_seed_len_procname = 'EC_GROUP_get_seed_len';
  EC_GROUP_get_seed_len_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_set_seed_procname = 'EC_GROUP_set_seed';
  EC_GROUP_set_seed_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_set_curve_procname = 'EC_GROUP_set_curve';
  EC_GROUP_set_curve_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  EC_GROUP_get_curve_procname = 'EC_GROUP_get_curve';
  EC_GROUP_get_curve_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  EC_GROUP_set_curve_GFp_procname = 'EC_GROUP_set_curve_GFp';
  EC_GROUP_set_curve_GFp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_GROUP_set_curve_GFp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_GROUP_get_curve_GFp_procname = 'EC_GROUP_get_curve_GFp';
  EC_GROUP_get_curve_GFp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_GROUP_get_curve_GFp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_GROUP_set_curve_GF2m_procname = 'EC_GROUP_set_curve_GF2m';
  EC_GROUP_set_curve_GF2m_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_GROUP_set_curve_GF2m_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_GROUP_get_curve_GF2m_procname = 'EC_GROUP_get_curve_GF2m';
  EC_GROUP_get_curve_GF2m_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_GROUP_get_curve_GF2m_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_GROUP_get_degree_procname = 'EC_GROUP_get_degree';
  EC_GROUP_get_degree_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_check_procname = 'EC_GROUP_check';
  EC_GROUP_check_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_check_discriminant_procname = 'EC_GROUP_check_discriminant';
  EC_GROUP_check_discriminant_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_cmp_procname = 'EC_GROUP_cmp';
  EC_GROUP_cmp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_new_curve_GFp_procname = 'EC_GROUP_new_curve_GFp';
  EC_GROUP_new_curve_GFp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_new_curve_GF2m_procname = 'EC_GROUP_new_curve_GF2m';
  EC_GROUP_new_curve_GF2m_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_new_from_params_procname = 'EC_GROUP_new_from_params';
  EC_GROUP_new_from_params_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_GROUP_to_params_procname = 'EC_GROUP_to_params';
  EC_GROUP_to_params_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  EC_GROUP_new_by_curve_name_ex_procname = 'EC_GROUP_new_by_curve_name_ex';
  EC_GROUP_new_by_curve_name_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_GROUP_new_by_curve_name_procname = 'EC_GROUP_new_by_curve_name';
  EC_GROUP_new_by_curve_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_new_from_ecparameters_procname = 'EC_GROUP_new_from_ecparameters';
  EC_GROUP_new_from_ecparameters_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_get_ecparameters_procname = 'EC_GROUP_get_ecparameters';
  EC_GROUP_get_ecparameters_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_new_from_ecpkparameters_procname = 'EC_GROUP_new_from_ecpkparameters';
  EC_GROUP_new_from_ecpkparameters_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_get_ecpkparameters_procname = 'EC_GROUP_get_ecpkparameters';
  EC_GROUP_get_ecpkparameters_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_get_builtin_curves_procname = 'EC_get_builtin_curves';
  EC_get_builtin_curves_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_curve_nid2nist_procname = 'EC_curve_nid2nist';
  EC_curve_nid2nist_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_curve_nist2nid_procname = 'EC_curve_nist2nid';
  EC_curve_nist2nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_check_named_curve_procname = 'EC_GROUP_check_named_curve';
  EC_GROUP_check_named_curve_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_POINT_new_procname = 'EC_POINT_new';
  EC_POINT_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_POINT_free_procname = 'EC_POINT_free';
  EC_POINT_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_POINT_clear_free_procname = 'EC_POINT_clear_free';
  EC_POINT_clear_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_POINT_copy_procname = 'EC_POINT_copy';
  EC_POINT_copy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_POINT_dup_procname = 'EC_POINT_dup';
  EC_POINT_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_POINT_set_to_infinity_procname = 'EC_POINT_set_to_infinity';
  EC_POINT_set_to_infinity_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_POINT_method_of_procname = 'EC_POINT_method_of';
  EC_POINT_method_of_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_POINT_method_of_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_POINT_set_Jprojective_coordinates_GFp_procname = 'EC_POINT_set_Jprojective_coordinates_GFp';
  EC_POINT_set_Jprojective_coordinates_GFp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_POINT_set_Jprojective_coordinates_GFp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_POINT_get_Jprojective_coordinates_GFp_procname = 'EC_POINT_get_Jprojective_coordinates_GFp';
  EC_POINT_get_Jprojective_coordinates_GFp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_POINT_get_Jprojective_coordinates_GFp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_POINT_set_affine_coordinates_procname = 'EC_POINT_set_affine_coordinates';
  EC_POINT_set_affine_coordinates_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  EC_POINT_get_affine_coordinates_procname = 'EC_POINT_get_affine_coordinates';
  EC_POINT_get_affine_coordinates_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  EC_POINT_set_affine_coordinates_GFp_procname = 'EC_POINT_set_affine_coordinates_GFp';
  EC_POINT_set_affine_coordinates_GFp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_POINT_set_affine_coordinates_GFp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_POINT_get_affine_coordinates_GFp_procname = 'EC_POINT_get_affine_coordinates_GFp';
  EC_POINT_get_affine_coordinates_GFp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_POINT_get_affine_coordinates_GFp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_POINT_set_compressed_coordinates_procname = 'EC_POINT_set_compressed_coordinates';
  EC_POINT_set_compressed_coordinates_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  EC_POINT_set_compressed_coordinates_GFp_procname = 'EC_POINT_set_compressed_coordinates_GFp';
  EC_POINT_set_compressed_coordinates_GFp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_POINT_set_compressed_coordinates_GFp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_POINT_set_affine_coordinates_GF2m_procname = 'EC_POINT_set_affine_coordinates_GF2m';
  EC_POINT_set_affine_coordinates_GF2m_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_POINT_set_affine_coordinates_GF2m_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_POINT_get_affine_coordinates_GF2m_procname = 'EC_POINT_get_affine_coordinates_GF2m';
  EC_POINT_get_affine_coordinates_GF2m_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_POINT_get_affine_coordinates_GF2m_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_POINT_set_compressed_coordinates_GF2m_procname = 'EC_POINT_set_compressed_coordinates_GF2m';
  EC_POINT_set_compressed_coordinates_GF2m_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_POINT_set_compressed_coordinates_GF2m_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_POINT_point2oct_procname = 'EC_POINT_point2oct';
  EC_POINT_point2oct_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_POINT_oct2point_procname = 'EC_POINT_oct2point';
  EC_POINT_oct2point_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_POINT_point2buf_procname = 'EC_POINT_point2buf';
  EC_POINT_point2buf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_POINT_point2bn_procname = 'EC_POINT_point2bn';
  EC_POINT_point2bn_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_POINT_point2bn_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_POINT_bn2point_procname = 'EC_POINT_bn2point';
  EC_POINT_bn2point_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_POINT_bn2point_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_POINT_point2hex_procname = 'EC_POINT_point2hex';
  EC_POINT_point2hex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_POINT_hex2point_procname = 'EC_POINT_hex2point';
  EC_POINT_hex2point_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_POINT_add_procname = 'EC_POINT_add';
  EC_POINT_add_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_POINT_dbl_procname = 'EC_POINT_dbl';
  EC_POINT_dbl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_POINT_invert_procname = 'EC_POINT_invert';
  EC_POINT_invert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_POINT_is_at_infinity_procname = 'EC_POINT_is_at_infinity';
  EC_POINT_is_at_infinity_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_POINT_is_on_curve_procname = 'EC_POINT_is_on_curve';
  EC_POINT_is_on_curve_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_POINT_cmp_procname = 'EC_POINT_cmp';
  EC_POINT_cmp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_POINT_make_affine_procname = 'EC_POINT_make_affine';
  EC_POINT_make_affine_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_POINT_make_affine_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_POINTs_make_affine_procname = 'EC_POINTs_make_affine';
  EC_POINTs_make_affine_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_POINTs_make_affine_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_POINTs_mul_procname = 'EC_POINTs_mul';
  EC_POINTs_mul_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_POINTs_mul_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_POINT_mul_procname = 'EC_POINT_mul';
  EC_POINT_mul_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_precompute_mult_procname = 'EC_GROUP_precompute_mult';
  EC_GROUP_precompute_mult_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_GROUP_precompute_mult_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_GROUP_have_precompute_mult_procname = 'EC_GROUP_have_precompute_mult';
  EC_GROUP_have_precompute_mult_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_GROUP_have_precompute_mult_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ECPKPARAMETERS_it_procname = 'ECPKPARAMETERS_it';
  ECPKPARAMETERS_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ECPKPARAMETERS_new_procname = 'ECPKPARAMETERS_new';
  ECPKPARAMETERS_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ECPKPARAMETERS_free_procname = 'ECPKPARAMETERS_free';
  ECPKPARAMETERS_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ECPARAMETERS_it_procname = 'ECPARAMETERS_it';
  ECPARAMETERS_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ECPARAMETERS_new_procname = 'ECPARAMETERS_new';
  ECPARAMETERS_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ECPARAMETERS_free_procname = 'ECPARAMETERS_free';
  ECPARAMETERS_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_get_basis_type_procname = 'EC_GROUP_get_basis_type';
  EC_GROUP_get_basis_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_get_trinomial_basis_procname = 'EC_GROUP_get_trinomial_basis';
  EC_GROUP_get_trinomial_basis_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EC_GROUP_get_pentanomial_basis_procname = 'EC_GROUP_get_pentanomial_basis';
  EC_GROUP_get_pentanomial_basis_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ECPKParameters_procname = 'd2i_ECPKParameters';
  d2i_ECPKParameters_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ECPKParameters_procname = 'i2d_ECPKParameters';
  i2d_ECPKParameters_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ECPKParameters_print_procname = 'ECPKParameters_print';
  ECPKParameters_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ECPKParameters_print_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ECPKParameters_print_fp_procname = 'ECPKParameters_print_fp';
  ECPKParameters_print_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ECPKParameters_print_fp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_new_ex_procname = 'EC_KEY_new_ex';
  EC_KEY_new_ex_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_new_procname = 'EC_KEY_new';
  EC_KEY_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_new_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_get_flags_procname = 'EC_KEY_get_flags';
  EC_KEY_get_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_get_flags_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_set_flags_procname = 'EC_KEY_set_flags';
  EC_KEY_set_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_set_flags_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_clear_flags_procname = 'EC_KEY_clear_flags';
  EC_KEY_clear_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_clear_flags_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_decoded_from_explicit_params_procname = 'EC_KEY_decoded_from_explicit_params';
  EC_KEY_decoded_from_explicit_params_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1h);
  EC_KEY_decoded_from_explicit_params_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_new_by_curve_name_ex_procname = 'EC_KEY_new_by_curve_name_ex';
  EC_KEY_new_by_curve_name_ex_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_new_by_curve_name_procname = 'EC_KEY_new_by_curve_name';
  EC_KEY_new_by_curve_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_new_by_curve_name_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_free_procname = 'EC_KEY_free';
  EC_KEY_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_free_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_copy_procname = 'EC_KEY_copy';
  EC_KEY_copy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_copy_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_dup_procname = 'EC_KEY_dup';
  EC_KEY_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_dup_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_up_ref_procname = 'EC_KEY_up_ref';
  EC_KEY_up_ref_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_up_ref_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_get0_engine_procname = 'EC_KEY_get0_engine';
  EC_KEY_get0_engine_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);
  EC_KEY_get0_engine_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_get0_group_procname = 'EC_KEY_get0_group';
  EC_KEY_get0_group_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_get0_group_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_set_group_procname = 'EC_KEY_set_group';
  EC_KEY_set_group_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_set_group_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_get0_private_key_procname = 'EC_KEY_get0_private_key';
  EC_KEY_get0_private_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_get0_private_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_set_private_key_procname = 'EC_KEY_set_private_key';
  EC_KEY_set_private_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_set_private_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_get0_public_key_procname = 'EC_KEY_get0_public_key';
  EC_KEY_get0_public_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_get0_public_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_set_public_key_procname = 'EC_KEY_set_public_key';
  EC_KEY_set_public_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_set_public_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_get_enc_flags_procname = 'EC_KEY_get_enc_flags';
  EC_KEY_get_enc_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_get_enc_flags_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_set_enc_flags_procname = 'EC_KEY_set_enc_flags';
  EC_KEY_set_enc_flags_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_set_enc_flags_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_get_conv_form_procname = 'EC_KEY_get_conv_form';
  EC_KEY_get_conv_form_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_get_conv_form_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_set_conv_form_procname = 'EC_KEY_set_conv_form';
  EC_KEY_set_conv_form_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_set_conv_form_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_set_ex_data_procname = 'EC_KEY_set_ex_data';
  EC_KEY_set_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_set_ex_data_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_get_ex_data_procname = 'EC_KEY_get_ex_data';
  EC_KEY_get_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_get_ex_data_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_set_asn1_flag_procname = 'EC_KEY_set_asn1_flag';
  EC_KEY_set_asn1_flag_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_set_asn1_flag_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_precompute_mult_procname = 'EC_KEY_precompute_mult';
  EC_KEY_precompute_mult_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_precompute_mult_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_generate_key_procname = 'EC_KEY_generate_key';
  EC_KEY_generate_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_generate_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_check_key_procname = 'EC_KEY_check_key';
  EC_KEY_check_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_check_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_can_sign_procname = 'EC_KEY_can_sign';
  EC_KEY_can_sign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_can_sign_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_set_public_key_affine_coordinates_procname = 'EC_KEY_set_public_key_affine_coordinates';
  EC_KEY_set_public_key_affine_coordinates_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_set_public_key_affine_coordinates_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_key2buf_procname = 'EC_KEY_key2buf';
  EC_KEY_key2buf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_key2buf_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_oct2key_procname = 'EC_KEY_oct2key';
  EC_KEY_oct2key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_oct2key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_oct2priv_procname = 'EC_KEY_oct2priv';
  EC_KEY_oct2priv_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_oct2priv_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_priv2oct_procname = 'EC_KEY_priv2oct';
  EC_KEY_priv2oct_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_priv2oct_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_priv2buf_procname = 'EC_KEY_priv2buf';
  EC_KEY_priv2buf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_priv2buf_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_ECPrivateKey_procname = 'd2i_ECPrivateKey';
  d2i_ECPrivateKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  d2i_ECPrivateKey_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_ECPrivateKey_procname = 'i2d_ECPrivateKey';
  i2d_ECPrivateKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2d_ECPrivateKey_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_ECParameters_procname = 'd2i_ECParameters';
  d2i_ECParameters_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  d2i_ECParameters_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_ECParameters_procname = 'i2d_ECParameters';
  i2d_ECParameters_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2d_ECParameters_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  o2i_ECPublicKey_procname = 'o2i_ECPublicKey';
  o2i_ECPublicKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  o2i_ECPublicKey_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2o_ECPublicKey_procname = 'i2o_ECPublicKey';
  i2o_ECPublicKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2o_ECPublicKey_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ECParameters_print_procname = 'ECParameters_print';
  ECParameters_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ECParameters_print_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_print_procname = 'EC_KEY_print';
  EC_KEY_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_print_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ECParameters_print_fp_procname = 'ECParameters_print_fp';
  ECParameters_print_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ECParameters_print_fp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_print_fp_procname = 'EC_KEY_print_fp';
  EC_KEY_print_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_print_fp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_OpenSSL_procname = 'EC_KEY_OpenSSL';
  EC_KEY_OpenSSL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_OpenSSL_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_get_default_method_procname = 'EC_KEY_get_default_method';
  EC_KEY_get_default_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_get_default_method_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_set_default_method_procname = 'EC_KEY_set_default_method';
  EC_KEY_set_default_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_set_default_method_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_get_method_procname = 'EC_KEY_get_method';
  EC_KEY_get_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_get_method_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_set_method_procname = 'EC_KEY_set_method';
  EC_KEY_set_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_set_method_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_new_method_procname = 'EC_KEY_new_method';
  EC_KEY_new_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_new_method_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ECDH_KDF_X9_62_procname = 'ECDH_KDF_X9_62';
  ECDH_KDF_X9_62_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ECDH_KDF_X9_62_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ECDH_compute_key_procname = 'ECDH_compute_key';
  ECDH_compute_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ECDH_compute_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ECDSA_SIG_new_procname = 'ECDSA_SIG_new';
  ECDSA_SIG_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ECDSA_SIG_free_procname = 'ECDSA_SIG_free';
  ECDSA_SIG_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_ECDSA_SIG_procname = 'd2i_ECDSA_SIG';
  d2i_ECDSA_SIG_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_ECDSA_SIG_procname = 'i2d_ECDSA_SIG';
  i2d_ECDSA_SIG_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ECDSA_SIG_get0_procname = 'ECDSA_SIG_get0';
  ECDSA_SIG_get0_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ECDSA_SIG_get0_r_procname = 'ECDSA_SIG_get0_r';
  ECDSA_SIG_get0_r_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ECDSA_SIG_get0_s_procname = 'ECDSA_SIG_get0_s';
  ECDSA_SIG_get0_s_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  ECDSA_SIG_set0_procname = 'ECDSA_SIG_set0';
  ECDSA_SIG_set0_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ECDSA_do_sign_procname = 'ECDSA_do_sign';
  ECDSA_do_sign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ECDSA_do_sign_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ECDSA_do_sign_ex_procname = 'ECDSA_do_sign_ex';
  ECDSA_do_sign_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ECDSA_do_sign_ex_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ECDSA_do_verify_procname = 'ECDSA_do_verify';
  ECDSA_do_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ECDSA_do_verify_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ECDSA_sign_setup_procname = 'ECDSA_sign_setup';
  ECDSA_sign_setup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ECDSA_sign_setup_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ECDSA_sign_procname = 'ECDSA_sign';
  ECDSA_sign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ECDSA_sign_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ECDSA_sign_ex_procname = 'ECDSA_sign_ex';
  ECDSA_sign_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ECDSA_sign_ex_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ECDSA_verify_procname = 'ECDSA_verify';
  ECDSA_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ECDSA_verify_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ECDSA_size_procname = 'ECDSA_size';
  ECDSA_size_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ECDSA_size_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_METHOD_new_procname = 'EC_KEY_METHOD_new';
  EC_KEY_METHOD_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_METHOD_new_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_METHOD_free_procname = 'EC_KEY_METHOD_free';
  EC_KEY_METHOD_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_METHOD_free_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_METHOD_set_init_procname = 'EC_KEY_METHOD_set_init';
  EC_KEY_METHOD_set_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_METHOD_set_init_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_METHOD_set_keygen_procname = 'EC_KEY_METHOD_set_keygen';
  EC_KEY_METHOD_set_keygen_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_METHOD_set_keygen_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_METHOD_set_compute_key_procname = 'EC_KEY_METHOD_set_compute_key';
  EC_KEY_METHOD_set_compute_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_METHOD_set_compute_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_METHOD_set_sign_procname = 'EC_KEY_METHOD_set_sign';
  EC_KEY_METHOD_set_sign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_METHOD_set_sign_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_METHOD_set_verify_procname = 'EC_KEY_METHOD_set_verify';
  EC_KEY_METHOD_set_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_METHOD_set_verify_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_METHOD_get_init_procname = 'EC_KEY_METHOD_get_init';
  EC_KEY_METHOD_get_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_METHOD_get_init_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_METHOD_get_keygen_procname = 'EC_KEY_METHOD_get_keygen';
  EC_KEY_METHOD_get_keygen_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_METHOD_get_keygen_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_METHOD_get_compute_key_procname = 'EC_KEY_METHOD_get_compute_key';
  EC_KEY_METHOD_get_compute_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_METHOD_get_compute_key_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_METHOD_get_sign_procname = 'EC_KEY_METHOD_get_sign';
  EC_KEY_METHOD_get_sign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_METHOD_get_sign_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EC_KEY_METHOD_get_verify_procname = 'EC_KEY_METHOD_get_verify';
  EC_KEY_METHOD_get_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  EC_KEY_METHOD_get_verify_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function EVP_EC_gen(curve: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    EVP_EC_gen(curve) \
    EVP_PKEY_Q_keygen(NULL, NULL, "EC", (char *)(strstr(curve, "")))
  }
end;

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx: PEVP_PKEY_CTX; nid: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_ec_paramgen_curve_nid_procname);
end;

function ERR_EVP_PKEY_CTX_set_ec_param_enc(ctx: PEVP_PKEY_CTX; param_enc: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_ec_param_enc_procname);
end;

function ERR_EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx: PEVP_PKEY_CTX; cofactor_mode: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_ecdh_cofactor_mode_procname);
end;

function ERR_EVP_PKEY_CTX_get_ecdh_cofactor_mode(ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_get_ecdh_cofactor_mode_procname);
end;

function ERR_EVP_PKEY_CTX_set_ecdh_kdf_type(ctx: PEVP_PKEY_CTX; kdf: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_ecdh_kdf_type_procname);
end;

function ERR_EVP_PKEY_CTX_get_ecdh_kdf_type(ctx: PEVP_PKEY_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_get_ecdh_kdf_type_procname);
end;

function ERR_EVP_PKEY_CTX_set_ecdh_kdf_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_ecdh_kdf_md_procname);
end;

function ERR_EVP_PKEY_CTX_get_ecdh_kdf_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_get_ecdh_kdf_md_procname);
end;

function ERR_EVP_PKEY_CTX_set_ecdh_kdf_outlen(ctx: PEVP_PKEY_CTX; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set_ecdh_kdf_outlen_procname);
end;

function ERR_EVP_PKEY_CTX_get_ecdh_kdf_outlen(ctx: PEVP_PKEY_CTX; len: PIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_get_ecdh_kdf_outlen_procname);
end;

function ERR_EVP_PKEY_CTX_set0_ecdh_kdf_ukm(ctx: PEVP_PKEY_CTX; ukm: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_set0_ecdh_kdf_ukm_procname);
end;

function ERR_EVP_PKEY_CTX_get0_ecdh_kdf_ukm(ctx: PEVP_PKEY_CTX; ukm: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_CTX_get0_ecdh_kdf_ukm_procname);
end;

function ERR_OSSL_EC_curve_nid2name(nid: TIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_EC_curve_nid2name_procname);
end;

function ERR_EC_GFp_simple_method: PEC_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GFp_simple_method_procname);
end;

function ERR_EC_GFp_mont_method: PEC_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GFp_mont_method_procname);
end;

function ERR_EC_GFp_nist_method: PEC_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GFp_nist_method_procname);
end;

function ERR_EC_GF2m_simple_method: PEC_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GF2m_simple_method_procname);
end;

function ERR_EC_GROUP_new(meth: PEC_METHOD): PEC_GROUP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_new_procname);
end;

procedure ERR_EC_GROUP_clear_free(group: PEC_GROUP); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_clear_free_procname);
end;

function ERR_EC_GROUP_method_of(group: PEC_GROUP): PEC_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_method_of_procname);
end;

function ERR_EC_METHOD_get_field_type(meth: PEC_METHOD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_METHOD_get_field_type_procname);
end;

procedure ERR_EC_GROUP_free(group: PEC_GROUP); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_free_procname);
end;

function ERR_EC_GROUP_copy(dst: PEC_GROUP; src: PEC_GROUP): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_copy_procname);
end;

function ERR_EC_GROUP_dup(src: PEC_GROUP): PEC_GROUP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_dup_procname);
end;

function ERR_EC_GROUP_set_generator(group: PEC_GROUP; generator: PEC_POINT; order: PBIGNUM; cofactor: PBIGNUM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_set_generator_procname);
end;

function ERR_EC_GROUP_get0_generator(group: PEC_GROUP): PEC_POINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get0_generator_procname);
end;

function ERR_EC_GROUP_get_mont_data(group: PEC_GROUP): PBN_MONT_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_mont_data_procname);
end;

function ERR_EC_GROUP_get_order(group: PEC_GROUP; order: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_order_procname);
end;

function ERR_EC_GROUP_get0_order(group: PEC_GROUP): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get0_order_procname);
end;

function ERR_EC_GROUP_order_bits(group: PEC_GROUP): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_order_bits_procname);
end;

function ERR_EC_GROUP_get_cofactor(group: PEC_GROUP; cofactor: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_cofactor_procname);
end;

function ERR_EC_GROUP_get0_cofactor(group: PEC_GROUP): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get0_cofactor_procname);
end;

procedure ERR_EC_GROUP_set_curve_name(group: PEC_GROUP; nid: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_set_curve_name_procname);
end;

function ERR_EC_GROUP_get_curve_name(group: PEC_GROUP): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_curve_name_procname);
end;

function ERR_EC_GROUP_get0_field(group: PEC_GROUP): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get0_field_procname);
end;

function ERR_EC_GROUP_get_field_type(group: PEC_GROUP): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_field_type_procname);
end;

procedure ERR_EC_GROUP_set_asn1_flag(group: PEC_GROUP; flag: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_set_asn1_flag_procname);
end;

function ERR_EC_GROUP_get_asn1_flag(group: PEC_GROUP): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_asn1_flag_procname);
end;

procedure ERR_EC_GROUP_set_point_conversion_form(group: PEC_GROUP; form: Tpoint_conversion_form_t); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_set_point_conversion_form_procname);
end;

function ERR_EC_GROUP_get_point_conversion_form(arg1: PEC_GROUP): Tpoint_conversion_form_t; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_point_conversion_form_procname);
end;

function ERR_EC_GROUP_get0_seed(x: PEC_GROUP): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get0_seed_procname);
end;

function ERR_EC_GROUP_get_seed_len(arg1: PEC_GROUP): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_seed_len_procname);
end;

function ERR_EC_GROUP_set_seed(arg1: PEC_GROUP; arg2: PIdAnsiChar; len: TIdC_SIZET): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_set_seed_procname);
end;

function ERR_EC_GROUP_set_curve(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_set_curve_procname);
end;

function ERR_EC_GROUP_get_curve(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_curve_procname);
end;

function ERR_EC_GROUP_set_curve_GFp(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_set_curve_GFp_procname);
end;

function ERR_EC_GROUP_get_curve_GFp(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_curve_GFp_procname);
end;

function ERR_EC_GROUP_set_curve_GF2m(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_set_curve_GF2m_procname);
end;

function ERR_EC_GROUP_get_curve_GF2m(group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_curve_GF2m_procname);
end;

function ERR_EC_GROUP_get_degree(group: PEC_GROUP): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_degree_procname);
end;

function ERR_EC_GROUP_check(group: PEC_GROUP; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_check_procname);
end;

function ERR_EC_GROUP_check_discriminant(group: PEC_GROUP; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_check_discriminant_procname);
end;

function ERR_EC_GROUP_cmp(a: PEC_GROUP; b: PEC_GROUP; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_cmp_procname);
end;

function ERR_EC_GROUP_new_curve_GFp(p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_new_curve_GFp_procname);
end;

function ERR_EC_GROUP_new_curve_GF2m(p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_new_curve_GF2m_procname);
end;

function ERR_EC_GROUP_new_from_params(params: POSSL_PARAM; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEC_GROUP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_new_from_params_procname);
end;

function ERR_EC_GROUP_to_params(group: PEC_GROUP; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; bnctx: PBN_CTX): POSSL_PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_to_params_procname);
end;

function ERR_EC_GROUP_new_by_curve_name_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; nid: TIdC_INT): PEC_GROUP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_new_by_curve_name_ex_procname);
end;

function ERR_EC_GROUP_new_by_curve_name(nid: TIdC_INT): PEC_GROUP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_new_by_curve_name_procname);
end;

function ERR_EC_GROUP_new_from_ecparameters(params: PECPARAMETERS): PEC_GROUP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_new_from_ecparameters_procname);
end;

function ERR_EC_GROUP_get_ecparameters(group: PEC_GROUP; params: PECPARAMETERS): PECPARAMETERS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_ecparameters_procname);
end;

function ERR_EC_GROUP_new_from_ecpkparameters(params: PECPKPARAMETERS): PEC_GROUP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_new_from_ecpkparameters_procname);
end;

function ERR_EC_GROUP_get_ecpkparameters(group: PEC_GROUP; params: PECPKPARAMETERS): PECPKPARAMETERS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_ecpkparameters_procname);
end;

function ERR_EC_get_builtin_curves(r: PEC_builtin_curve; nitems: TIdC_SIZET): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_get_builtin_curves_procname);
end;

function ERR_EC_curve_nid2nist(nid: TIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_curve_nid2nist_procname);
end;

function ERR_EC_curve_nist2nid(name: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_curve_nist2nid_procname);
end;

function ERR_EC_GROUP_check_named_curve(group: PEC_GROUP; nist_only: TIdC_INT; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_check_named_curve_procname);
end;

function ERR_EC_POINT_new(group: PEC_GROUP): PEC_POINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_new_procname);
end;

procedure ERR_EC_POINT_free(point: PEC_POINT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_free_procname);
end;

procedure ERR_EC_POINT_clear_free(point: PEC_POINT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_clear_free_procname);
end;

function ERR_EC_POINT_copy(dst: PEC_POINT; src: PEC_POINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_copy_procname);
end;

function ERR_EC_POINT_dup(src: PEC_POINT; group: PEC_GROUP): PEC_POINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_dup_procname);
end;

function ERR_EC_POINT_set_to_infinity(group: PEC_GROUP; point: PEC_POINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_set_to_infinity_procname);
end;

function ERR_EC_POINT_method_of(point: PEC_POINT): PEC_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_method_of_procname);
end;

function ERR_EC_POINT_set_Jprojective_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_set_Jprojective_coordinates_GFp_procname);
end;

function ERR_EC_POINT_get_Jprojective_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_get_Jprojective_coordinates_GFp_procname);
end;

function ERR_EC_POINT_set_affine_coordinates(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_set_affine_coordinates_procname);
end;

function ERR_EC_POINT_get_affine_coordinates(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_get_affine_coordinates_procname);
end;

function ERR_EC_POINT_set_affine_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_set_affine_coordinates_GFp_procname);
end;

function ERR_EC_POINT_get_affine_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_get_affine_coordinates_GFp_procname);
end;

function ERR_EC_POINT_set_compressed_coordinates(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TIdC_INT; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_set_compressed_coordinates_procname);
end;

function ERR_EC_POINT_set_compressed_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TIdC_INT; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_set_compressed_coordinates_GFp_procname);
end;

function ERR_EC_POINT_set_affine_coordinates_GF2m(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_set_affine_coordinates_GF2m_procname);
end;

function ERR_EC_POINT_get_affine_coordinates_GF2m(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_get_affine_coordinates_GF2m_procname);
end;

function ERR_EC_POINT_set_compressed_coordinates_GF2m(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TIdC_INT; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_set_compressed_coordinates_GF2m_procname);
end;

function ERR_EC_POINT_point2oct(group: PEC_GROUP; p: PEC_POINT; form: Tpoint_conversion_form_t; buf: PIdAnsiChar; len: TIdC_SIZET; ctx: PBN_CTX): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_point2oct_procname);
end;

function ERR_EC_POINT_oct2point(group: PEC_GROUP; p: PEC_POINT; buf: PIdAnsiChar; len: TIdC_SIZET; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_oct2point_procname);
end;

function ERR_EC_POINT_point2buf(group: PEC_GROUP; point: PEC_POINT; form: Tpoint_conversion_form_t; pbuf: PPIdAnsiChar; ctx: PBN_CTX): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_point2buf_procname);
end;

function ERR_EC_POINT_point2bn(arg1: PEC_GROUP; arg2: PEC_POINT; form: Tpoint_conversion_form_t; arg4: PBIGNUM; arg5: PBN_CTX): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_point2bn_procname);
end;

function ERR_EC_POINT_bn2point(arg1: PEC_GROUP; arg2: PBIGNUM; arg3: PEC_POINT; arg4: PBN_CTX): PEC_POINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_bn2point_procname);
end;

function ERR_EC_POINT_point2hex(arg1: PEC_GROUP; arg2: PEC_POINT; form: Tpoint_conversion_form_t; arg4: PBN_CTX): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_point2hex_procname);
end;

function ERR_EC_POINT_hex2point(arg1: PEC_GROUP; arg2: PIdAnsiChar; arg3: PEC_POINT; arg4: PBN_CTX): PEC_POINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_hex2point_procname);
end;

function ERR_EC_POINT_add(group: PEC_GROUP; r: PEC_POINT; a: PEC_POINT; b: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_add_procname);
end;

function ERR_EC_POINT_dbl(group: PEC_GROUP; r: PEC_POINT; a: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_dbl_procname);
end;

function ERR_EC_POINT_invert(group: PEC_GROUP; a: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_invert_procname);
end;

function ERR_EC_POINT_is_at_infinity(group: PEC_GROUP; p: PEC_POINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_is_at_infinity_procname);
end;

function ERR_EC_POINT_is_on_curve(group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_is_on_curve_procname);
end;

function ERR_EC_POINT_cmp(group: PEC_GROUP; a: PEC_POINT; b: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_cmp_procname);
end;

function ERR_EC_POINT_make_affine(group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_make_affine_procname);
end;

function ERR_EC_POINTs_make_affine(group: PEC_GROUP; num: TIdC_SIZET; points: PPEC_POINT; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINTs_make_affine_procname);
end;

function ERR_EC_POINTs_mul(group: PEC_GROUP; r: PEC_POINT; n: PBIGNUM; num: TIdC_SIZET; p: PPEC_POINT; m: PPBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINTs_mul_procname);
end;

function ERR_EC_POINT_mul(group: PEC_GROUP; r: PEC_POINT; n: PBIGNUM; q: PEC_POINT; m: PBIGNUM; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_POINT_mul_procname);
end;

function ERR_EC_GROUP_precompute_mult(group: PEC_GROUP; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_precompute_mult_procname);
end;

function ERR_EC_GROUP_have_precompute_mult(group: PEC_GROUP): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_have_precompute_mult_procname);
end;

function ERR_ECPKPARAMETERS_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECPKPARAMETERS_it_procname);
end;

function ERR_ECPKPARAMETERS_new: PECPKPARAMETERS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECPKPARAMETERS_new_procname);
end;

procedure ERR_ECPKPARAMETERS_free(a: PECPKPARAMETERS); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECPKPARAMETERS_free_procname);
end;

function ERR_ECPARAMETERS_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECPARAMETERS_it_procname);
end;

function ERR_ECPARAMETERS_new: PECPARAMETERS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECPARAMETERS_new_procname);
end;

procedure ERR_ECPARAMETERS_free(a: PECPARAMETERS); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECPARAMETERS_free_procname);
end;

function ERR_EC_GROUP_get_basis_type(arg1: PEC_GROUP): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_basis_type_procname);
end;

function ERR_EC_GROUP_get_trinomial_basis(arg1: PEC_GROUP; k: PIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_trinomial_basis_procname);
end;

function ERR_EC_GROUP_get_pentanomial_basis(arg1: PEC_GROUP; k1: PIdC_UINT; k2: PIdC_UINT; k3: PIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_GROUP_get_pentanomial_basis_procname);
end;

function ERR_d2i_ECPKParameters(arg1: PPEC_GROUP; _in: PPIdAnsiChar; len: TIdC_LONG): PEC_GROUP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ECPKParameters_procname);
end;

function ERR_i2d_ECPKParameters(arg1: PEC_GROUP; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ECPKParameters_procname);
end;

function ERR_ECPKParameters_print(bp: PBIO; x: PEC_GROUP; off: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECPKParameters_print_procname);
end;

function ERR_ECPKParameters_print_fp(fp: PFILE; x: PEC_GROUP; off: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECPKParameters_print_fp_procname);
end;

function ERR_EC_KEY_new_ex(ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEC_KEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_new_ex_procname);
end;

function ERR_EC_KEY_new: PEC_KEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_new_procname);
end;

function ERR_EC_KEY_get_flags(key: PEC_KEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_get_flags_procname);
end;

procedure ERR_EC_KEY_set_flags(key: PEC_KEY; flags: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_set_flags_procname);
end;

procedure ERR_EC_KEY_clear_flags(key: PEC_KEY; flags: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_clear_flags_procname);
end;

function ERR_EC_KEY_decoded_from_explicit_params(key: PEC_KEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_decoded_from_explicit_params_procname);
end;

function ERR_EC_KEY_new_by_curve_name_ex(ctx: POSSL_LIB_CTX; propq: PIdAnsiChar; nid: TIdC_INT): PEC_KEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_new_by_curve_name_ex_procname);
end;

function ERR_EC_KEY_new_by_curve_name(nid: TIdC_INT): PEC_KEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_new_by_curve_name_procname);
end;

procedure ERR_EC_KEY_free(key: PEC_KEY); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_free_procname);
end;

function ERR_EC_KEY_copy(dst: PEC_KEY; src: PEC_KEY): PEC_KEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_copy_procname);
end;

function ERR_EC_KEY_dup(src: PEC_KEY): PEC_KEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_dup_procname);
end;

function ERR_EC_KEY_up_ref(key: PEC_KEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_up_ref_procname);
end;

function ERR_EC_KEY_get0_engine(eckey: PEC_KEY): PENGINE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_get0_engine_procname);
end;

function ERR_EC_KEY_get0_group(key: PEC_KEY): PEC_GROUP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_get0_group_procname);
end;

function ERR_EC_KEY_set_group(key: PEC_KEY; group: PEC_GROUP): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_set_group_procname);
end;

function ERR_EC_KEY_get0_private_key(key: PEC_KEY): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_get0_private_key_procname);
end;

function ERR_EC_KEY_set_private_key(key: PEC_KEY; prv: PBIGNUM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_set_private_key_procname);
end;

function ERR_EC_KEY_get0_public_key(key: PEC_KEY): PEC_POINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_get0_public_key_procname);
end;

function ERR_EC_KEY_set_public_key(key: PEC_KEY; pub: PEC_POINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_set_public_key_procname);
end;

function ERR_EC_KEY_get_enc_flags(key: PEC_KEY): TIdC_UINT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_get_enc_flags_procname);
end;

procedure ERR_EC_KEY_set_enc_flags(eckey: PEC_KEY; flags: TIdC_UINT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_set_enc_flags_procname);
end;

function ERR_EC_KEY_get_conv_form(key: PEC_KEY): Tpoint_conversion_form_t; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_get_conv_form_procname);
end;

procedure ERR_EC_KEY_set_conv_form(eckey: PEC_KEY; cform: Tpoint_conversion_form_t); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_set_conv_form_procname);
end;

function ERR_EC_KEY_set_ex_data(key: PEC_KEY; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_set_ex_data_procname);
end;

function ERR_EC_KEY_get_ex_data(key: PEC_KEY; idx: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_get_ex_data_procname);
end;

procedure ERR_EC_KEY_set_asn1_flag(eckey: PEC_KEY; asn1_flag: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_set_asn1_flag_procname);
end;

function ERR_EC_KEY_precompute_mult(key: PEC_KEY; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_precompute_mult_procname);
end;

function ERR_EC_KEY_generate_key(key: PEC_KEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_generate_key_procname);
end;

function ERR_EC_KEY_check_key(key: PEC_KEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_check_key_procname);
end;

function ERR_EC_KEY_can_sign(eckey: PEC_KEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_can_sign_procname);
end;

function ERR_EC_KEY_set_public_key_affine_coordinates(key: PEC_KEY; x: PBIGNUM; y: PBIGNUM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_set_public_key_affine_coordinates_procname);
end;

function ERR_EC_KEY_key2buf(key: PEC_KEY; form: Tpoint_conversion_form_t; pbuf: PPIdAnsiChar; ctx: PBN_CTX): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_key2buf_procname);
end;

function ERR_EC_KEY_oct2key(key: PEC_KEY; buf: PIdAnsiChar; len: TIdC_SIZET; ctx: PBN_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_oct2key_procname);
end;

function ERR_EC_KEY_oct2priv(key: PEC_KEY; buf: PIdAnsiChar; len: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_oct2priv_procname);
end;

function ERR_EC_KEY_priv2oct(key: PEC_KEY; buf: PIdAnsiChar; len: TIdC_SIZET): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_priv2oct_procname);
end;

function ERR_EC_KEY_priv2buf(eckey: PEC_KEY; pbuf: PPIdAnsiChar): TIdC_SIZET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_priv2buf_procname);
end;

function ERR_d2i_ECPrivateKey(key: PPEC_KEY; _in: PPIdAnsiChar; len: TIdC_LONG): PEC_KEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ECPrivateKey_procname);
end;

function ERR_i2d_ECPrivateKey(key: PEC_KEY; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ECPrivateKey_procname);
end;

function ERR_d2i_ECParameters(key: PPEC_KEY; _in: PPIdAnsiChar; len: TIdC_LONG): PEC_KEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ECParameters_procname);
end;

function ERR_i2d_ECParameters(key: PEC_KEY; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ECParameters_procname);
end;

function ERR_o2i_ECPublicKey(key: PPEC_KEY; _in: PPIdAnsiChar; len: TIdC_LONG): PEC_KEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(o2i_ECPublicKey_procname);
end;

function ERR_i2o_ECPublicKey(key: PEC_KEY; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2o_ECPublicKey_procname);
end;

function ERR_ECParameters_print(bp: PBIO; key: PEC_KEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECParameters_print_procname);
end;

function ERR_EC_KEY_print(bp: PBIO; key: PEC_KEY; off: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_print_procname);
end;

function ERR_ECParameters_print_fp(fp: PFILE; key: PEC_KEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECParameters_print_fp_procname);
end;

function ERR_EC_KEY_print_fp(fp: PFILE; key: PEC_KEY; off: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_print_fp_procname);
end;

function ERR_EC_KEY_OpenSSL: PEC_KEY_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_OpenSSL_procname);
end;

function ERR_EC_KEY_get_default_method: PEC_KEY_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_get_default_method_procname);
end;

procedure ERR_EC_KEY_set_default_method(meth: PEC_KEY_METHOD); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_set_default_method_procname);
end;

function ERR_EC_KEY_get_method(key: PEC_KEY): PEC_KEY_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_get_method_procname);
end;

function ERR_EC_KEY_set_method(key: PEC_KEY; meth: PEC_KEY_METHOD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_set_method_procname);
end;

function ERR_EC_KEY_new_method(engine: PENGINE): PEC_KEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_new_method_procname);
end;

function ERR_ECDH_KDF_X9_62(_out: PIdAnsiChar; outlen: TIdC_SIZET; Z: PIdAnsiChar; Zlen: TIdC_SIZET; sinfo: PIdAnsiChar; sinfolen: TIdC_SIZET; md: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDH_KDF_X9_62_procname);
end;

function ERR_ECDH_compute_key(_out: Pointer; outlen: TIdC_SIZET; pub_key: PEC_POINT; ecdh: PEC_KEY; KDF: TECDH_compute_key_KDF_cb): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDH_compute_key_procname);
end;

function ERR_ECDSA_SIG_new: PECDSA_SIG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_SIG_new_procname);
end;

procedure ERR_ECDSA_SIG_free(sig: PECDSA_SIG); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_SIG_free_procname);
end;

function ERR_d2i_ECDSA_SIG(a: PPECDSA_SIG; _in: PPIdAnsiChar; len: TIdC_LONG): PECDSA_SIG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ECDSA_SIG_procname);
end;

function ERR_i2d_ECDSA_SIG(a: PECDSA_SIG; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ECDSA_SIG_procname);
end;

procedure ERR_ECDSA_SIG_get0(sig: PECDSA_SIG; pr: PPBIGNUM; ps: PPBIGNUM); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_SIG_get0_procname);
end;

function ERR_ECDSA_SIG_get0_r(sig: PECDSA_SIG): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_SIG_get0_r_procname);
end;

function ERR_ECDSA_SIG_get0_s(sig: PECDSA_SIG): PBIGNUM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_SIG_get0_s_procname);
end;

function ERR_ECDSA_SIG_set0(sig: PECDSA_SIG; r: PBIGNUM; s: PBIGNUM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_SIG_set0_procname);
end;

function ERR_ECDSA_do_sign(dgst: PIdAnsiChar; dgst_len: TIdC_INT; eckey: PEC_KEY): PECDSA_SIG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_do_sign_procname);
end;

function ERR_ECDSA_do_sign_ex(dgst: PIdAnsiChar; dgstlen: TIdC_INT; kinv: PBIGNUM; rp: PBIGNUM; eckey: PEC_KEY): PECDSA_SIG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_do_sign_ex_procname);
end;

function ERR_ECDSA_do_verify(dgst: PIdAnsiChar; dgst_len: TIdC_INT; sig: PECDSA_SIG; eckey: PEC_KEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_do_verify_procname);
end;

function ERR_ECDSA_sign_setup(eckey: PEC_KEY; ctx: PBN_CTX; kinv: PPBIGNUM; rp: PPBIGNUM): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_sign_setup_procname);
end;

function ERR_ECDSA_sign(_type: TIdC_INT; dgst: PIdAnsiChar; dgstlen: TIdC_INT; sig: PIdAnsiChar; siglen: PIdC_UINT; eckey: PEC_KEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_sign_procname);
end;

function ERR_ECDSA_sign_ex(_type: TIdC_INT; dgst: PIdAnsiChar; dgstlen: TIdC_INT; sig: PIdAnsiChar; siglen: PIdC_UINT; kinv: PBIGNUM; rp: PBIGNUM; eckey: PEC_KEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_sign_ex_procname);
end;

function ERR_ECDSA_verify(_type: TIdC_INT; dgst: PIdAnsiChar; dgstlen: TIdC_INT; sig: PIdAnsiChar; siglen: TIdC_INT; eckey: PEC_KEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_verify_procname);
end;

function ERR_ECDSA_size(eckey: PEC_KEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ECDSA_size_procname);
end;

function ERR_EC_KEY_METHOD_new(meth: PEC_KEY_METHOD): PEC_KEY_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_METHOD_new_procname);
end;

procedure ERR_EC_KEY_METHOD_free(meth: PEC_KEY_METHOD); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_METHOD_free_procname);
end;

procedure ERR_EC_KEY_METHOD_set_init(meth: PEC_KEY_METHOD; init: TEC_KEY_METHOD_set_init_init_cb; finish: TEC_KEY_METHOD_set_init_finish_cb; copy: TEC_KEY_METHOD_set_init_copy_cb; set_group: TEC_KEY_METHOD_set_init_set_group_cb; set_private: TEC_KEY_METHOD_set_init_set_private_cb; set_public: TEC_KEY_METHOD_set_init_set_public_cb); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_METHOD_set_init_procname);
end;

procedure ERR_EC_KEY_METHOD_set_keygen(meth: PEC_KEY_METHOD; keygen: TEC_KEY_METHOD_set_init_init_cb); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_METHOD_set_keygen_procname);
end;

procedure ERR_EC_KEY_METHOD_set_compute_key(meth: PEC_KEY_METHOD; ckey: TEC_KEY_METHOD_set_compute_key_ckey_cb); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_METHOD_set_compute_key_procname);
end;

procedure ERR_EC_KEY_METHOD_set_sign(meth: PEC_KEY_METHOD; sign: TEC_KEY_METHOD_set_sign_sign_cb; sign_setup: TEC_KEY_METHOD_set_sign_sign_setup_cb; sign_sig: TEC_KEY_METHOD_set_sign_sign_sig_cb); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_METHOD_set_sign_procname);
end;

procedure ERR_EC_KEY_METHOD_set_verify(meth: PEC_KEY_METHOD; verify: TEC_KEY_METHOD_set_verify_verify_cb; verify_sig: TEC_KEY_METHOD_set_verify_verify_sig_cb); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_METHOD_set_verify_procname);
end;

procedure ERR_EC_KEY_METHOD_get_init(meth: PEC_KEY_METHOD; pinit: PPIdC_INT; pfinish: PPointer; pcopy: PPIdC_INT; pset_group: PPIdC_INT; pset_private: PPIdC_INT; pset_public: PPIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_METHOD_get_init_procname);
end;

procedure ERR_EC_KEY_METHOD_get_keygen(meth: PEC_KEY_METHOD; pkeygen: PPIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_METHOD_get_keygen_procname);
end;

procedure ERR_EC_KEY_METHOD_get_compute_key(meth: PEC_KEY_METHOD; pck: PPIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_METHOD_get_compute_key_procname);
end;

procedure ERR_EC_KEY_METHOD_get_sign(meth: PEC_KEY_METHOD; psign: PPIdC_INT; psign_setup: PPIdC_INT; psign_sig: PPECDSA_SIG); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_METHOD_get_sign_procname);
end;

procedure ERR_EC_KEY_METHOD_get_verify(meth: PEC_KEY_METHOD; pverify: PPIdC_INT; pverify_sig: PPIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EC_KEY_METHOD_get_verify_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  EVP_PKEY_CTX_set_ec_paramgen_curve_nid := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_ec_paramgen_curve_nid_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_ec_paramgen_curve_nid);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_ec_paramgen_curve_nid_allownil)}
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid := ERR_EVP_PKEY_CTX_set_ec_paramgen_curve_nid;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_ec_paramgen_curve_nid_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_ec_paramgen_curve_nid_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_ec_paramgen_curve_nid)}
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid := FC_EVP_PKEY_CTX_set_ec_paramgen_curve_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_ec_paramgen_curve_nid_removed)}
    if EVP_PKEY_CTX_set_ec_paramgen_curve_nid_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_ec_paramgen_curve_nid)}
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid := _EVP_PKEY_CTX_set_ec_paramgen_curve_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_ec_paramgen_curve_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_ec_paramgen_curve_nid');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_ec_param_enc := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_ec_param_enc_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_ec_param_enc);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_ec_param_enc_allownil)}
    EVP_PKEY_CTX_set_ec_param_enc := ERR_EVP_PKEY_CTX_set_ec_param_enc;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_ec_param_enc_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_ec_param_enc_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_ec_param_enc)}
      EVP_PKEY_CTX_set_ec_param_enc := FC_EVP_PKEY_CTX_set_ec_param_enc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_ec_param_enc_removed)}
    if EVP_PKEY_CTX_set_ec_param_enc_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_ec_param_enc)}
      EVP_PKEY_CTX_set_ec_param_enc := _EVP_PKEY_CTX_set_ec_param_enc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_ec_param_enc_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_ec_param_enc');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_ecdh_cofactor_mode := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_ecdh_cofactor_mode_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_ecdh_cofactor_mode);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_ecdh_cofactor_mode_allownil)}
    EVP_PKEY_CTX_set_ecdh_cofactor_mode := ERR_EVP_PKEY_CTX_set_ecdh_cofactor_mode;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_ecdh_cofactor_mode_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_ecdh_cofactor_mode_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_ecdh_cofactor_mode)}
      EVP_PKEY_CTX_set_ecdh_cofactor_mode := FC_EVP_PKEY_CTX_set_ecdh_cofactor_mode;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_ecdh_cofactor_mode_removed)}
    if EVP_PKEY_CTX_set_ecdh_cofactor_mode_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_ecdh_cofactor_mode)}
      EVP_PKEY_CTX_set_ecdh_cofactor_mode := _EVP_PKEY_CTX_set_ecdh_cofactor_mode;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_ecdh_cofactor_mode_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_ecdh_cofactor_mode');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_get_ecdh_cofactor_mode := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_get_ecdh_cofactor_mode_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_get_ecdh_cofactor_mode);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_get_ecdh_cofactor_mode_allownil)}
    EVP_PKEY_CTX_get_ecdh_cofactor_mode := ERR_EVP_PKEY_CTX_get_ecdh_cofactor_mode;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_ecdh_cofactor_mode_introduced)}
    if LibVersion < EVP_PKEY_CTX_get_ecdh_cofactor_mode_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_get_ecdh_cofactor_mode)}
      EVP_PKEY_CTX_get_ecdh_cofactor_mode := FC_EVP_PKEY_CTX_get_ecdh_cofactor_mode;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_ecdh_cofactor_mode_removed)}
    if EVP_PKEY_CTX_get_ecdh_cofactor_mode_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_get_ecdh_cofactor_mode)}
      EVP_PKEY_CTX_get_ecdh_cofactor_mode := _EVP_PKEY_CTX_get_ecdh_cofactor_mode;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_get_ecdh_cofactor_mode_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_get_ecdh_cofactor_mode');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_ecdh_kdf_type := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_ecdh_kdf_type_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_ecdh_kdf_type);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_ecdh_kdf_type_allownil)}
    EVP_PKEY_CTX_set_ecdh_kdf_type := ERR_EVP_PKEY_CTX_set_ecdh_kdf_type;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_ecdh_kdf_type_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_ecdh_kdf_type_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_ecdh_kdf_type)}
      EVP_PKEY_CTX_set_ecdh_kdf_type := FC_EVP_PKEY_CTX_set_ecdh_kdf_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_ecdh_kdf_type_removed)}
    if EVP_PKEY_CTX_set_ecdh_kdf_type_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_ecdh_kdf_type)}
      EVP_PKEY_CTX_set_ecdh_kdf_type := _EVP_PKEY_CTX_set_ecdh_kdf_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_ecdh_kdf_type_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_ecdh_kdf_type');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_get_ecdh_kdf_type := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_get_ecdh_kdf_type_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_get_ecdh_kdf_type);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_get_ecdh_kdf_type_allownil)}
    EVP_PKEY_CTX_get_ecdh_kdf_type := ERR_EVP_PKEY_CTX_get_ecdh_kdf_type;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_ecdh_kdf_type_introduced)}
    if LibVersion < EVP_PKEY_CTX_get_ecdh_kdf_type_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_get_ecdh_kdf_type)}
      EVP_PKEY_CTX_get_ecdh_kdf_type := FC_EVP_PKEY_CTX_get_ecdh_kdf_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_ecdh_kdf_type_removed)}
    if EVP_PKEY_CTX_get_ecdh_kdf_type_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_get_ecdh_kdf_type)}
      EVP_PKEY_CTX_get_ecdh_kdf_type := _EVP_PKEY_CTX_get_ecdh_kdf_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_get_ecdh_kdf_type_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_get_ecdh_kdf_type');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_ecdh_kdf_md := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_ecdh_kdf_md_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_ecdh_kdf_md);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_ecdh_kdf_md_allownil)}
    EVP_PKEY_CTX_set_ecdh_kdf_md := ERR_EVP_PKEY_CTX_set_ecdh_kdf_md;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_ecdh_kdf_md_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_ecdh_kdf_md_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_ecdh_kdf_md)}
      EVP_PKEY_CTX_set_ecdh_kdf_md := FC_EVP_PKEY_CTX_set_ecdh_kdf_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_ecdh_kdf_md_removed)}
    if EVP_PKEY_CTX_set_ecdh_kdf_md_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_ecdh_kdf_md)}
      EVP_PKEY_CTX_set_ecdh_kdf_md := _EVP_PKEY_CTX_set_ecdh_kdf_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_ecdh_kdf_md_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_ecdh_kdf_md');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_get_ecdh_kdf_md := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_get_ecdh_kdf_md_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_get_ecdh_kdf_md);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_get_ecdh_kdf_md_allownil)}
    EVP_PKEY_CTX_get_ecdh_kdf_md := ERR_EVP_PKEY_CTX_get_ecdh_kdf_md;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_ecdh_kdf_md_introduced)}
    if LibVersion < EVP_PKEY_CTX_get_ecdh_kdf_md_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_get_ecdh_kdf_md)}
      EVP_PKEY_CTX_get_ecdh_kdf_md := FC_EVP_PKEY_CTX_get_ecdh_kdf_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_ecdh_kdf_md_removed)}
    if EVP_PKEY_CTX_get_ecdh_kdf_md_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_get_ecdh_kdf_md)}
      EVP_PKEY_CTX_get_ecdh_kdf_md := _EVP_PKEY_CTX_get_ecdh_kdf_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_get_ecdh_kdf_md_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_get_ecdh_kdf_md');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set_ecdh_kdf_outlen := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set_ecdh_kdf_outlen_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_ecdh_kdf_outlen);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set_ecdh_kdf_outlen_allownil)}
    EVP_PKEY_CTX_set_ecdh_kdf_outlen := ERR_EVP_PKEY_CTX_set_ecdh_kdf_outlen;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_ecdh_kdf_outlen_introduced)}
    if LibVersion < EVP_PKEY_CTX_set_ecdh_kdf_outlen_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set_ecdh_kdf_outlen)}
      EVP_PKEY_CTX_set_ecdh_kdf_outlen := FC_EVP_PKEY_CTX_set_ecdh_kdf_outlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set_ecdh_kdf_outlen_removed)}
    if EVP_PKEY_CTX_set_ecdh_kdf_outlen_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set_ecdh_kdf_outlen)}
      EVP_PKEY_CTX_set_ecdh_kdf_outlen := _EVP_PKEY_CTX_set_ecdh_kdf_outlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set_ecdh_kdf_outlen_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set_ecdh_kdf_outlen');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_get_ecdh_kdf_outlen := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_get_ecdh_kdf_outlen_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_get_ecdh_kdf_outlen);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_get_ecdh_kdf_outlen_allownil)}
    EVP_PKEY_CTX_get_ecdh_kdf_outlen := ERR_EVP_PKEY_CTX_get_ecdh_kdf_outlen;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_ecdh_kdf_outlen_introduced)}
    if LibVersion < EVP_PKEY_CTX_get_ecdh_kdf_outlen_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_get_ecdh_kdf_outlen)}
      EVP_PKEY_CTX_get_ecdh_kdf_outlen := FC_EVP_PKEY_CTX_get_ecdh_kdf_outlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get_ecdh_kdf_outlen_removed)}
    if EVP_PKEY_CTX_get_ecdh_kdf_outlen_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_get_ecdh_kdf_outlen)}
      EVP_PKEY_CTX_get_ecdh_kdf_outlen := _EVP_PKEY_CTX_get_ecdh_kdf_outlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_get_ecdh_kdf_outlen_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_get_ecdh_kdf_outlen');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_set0_ecdh_kdf_ukm := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_set0_ecdh_kdf_ukm_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_set0_ecdh_kdf_ukm);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_set0_ecdh_kdf_ukm_allownil)}
    EVP_PKEY_CTX_set0_ecdh_kdf_ukm := ERR_EVP_PKEY_CTX_set0_ecdh_kdf_ukm;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set0_ecdh_kdf_ukm_introduced)}
    if LibVersion < EVP_PKEY_CTX_set0_ecdh_kdf_ukm_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_set0_ecdh_kdf_ukm)}
      EVP_PKEY_CTX_set0_ecdh_kdf_ukm := FC_EVP_PKEY_CTX_set0_ecdh_kdf_ukm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_set0_ecdh_kdf_ukm_removed)}
    if EVP_PKEY_CTX_set0_ecdh_kdf_ukm_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_set0_ecdh_kdf_ukm)}
      EVP_PKEY_CTX_set0_ecdh_kdf_ukm := _EVP_PKEY_CTX_set0_ecdh_kdf_ukm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_set0_ecdh_kdf_ukm_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_set0_ecdh_kdf_ukm');
    {$ifend}
  end;
  
  EVP_PKEY_CTX_get0_ecdh_kdf_ukm := LoadLibFunction(ADllHandle, EVP_PKEY_CTX_get0_ecdh_kdf_ukm_procname);
  FuncLoadError := not assigned(EVP_PKEY_CTX_get0_ecdh_kdf_ukm);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_CTX_get0_ecdh_kdf_ukm_allownil)}
    EVP_PKEY_CTX_get0_ecdh_kdf_ukm := ERR_EVP_PKEY_CTX_get0_ecdh_kdf_ukm;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get0_ecdh_kdf_ukm_introduced)}
    if LibVersion < EVP_PKEY_CTX_get0_ecdh_kdf_ukm_introduced then
    begin
      {$if declared(FC_EVP_PKEY_CTX_get0_ecdh_kdf_ukm)}
      EVP_PKEY_CTX_get0_ecdh_kdf_ukm := FC_EVP_PKEY_CTX_get0_ecdh_kdf_ukm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_CTX_get0_ecdh_kdf_ukm_removed)}
    if EVP_PKEY_CTX_get0_ecdh_kdf_ukm_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_CTX_get0_ecdh_kdf_ukm)}
      EVP_PKEY_CTX_get0_ecdh_kdf_ukm := _EVP_PKEY_CTX_get0_ecdh_kdf_ukm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_CTX_get0_ecdh_kdf_ukm_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_CTX_get0_ecdh_kdf_ukm');
    {$ifend}
  end;
  
  OSSL_EC_curve_nid2name := LoadLibFunction(ADllHandle, OSSL_EC_curve_nid2name_procname);
  FuncLoadError := not assigned(OSSL_EC_curve_nid2name);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_EC_curve_nid2name_allownil)}
    OSSL_EC_curve_nid2name := ERR_OSSL_EC_curve_nid2name;
    {$ifend}
    {$if declared(OSSL_EC_curve_nid2name_introduced)}
    if LibVersion < OSSL_EC_curve_nid2name_introduced then
    begin
      {$if declared(FC_OSSL_EC_curve_nid2name)}
      OSSL_EC_curve_nid2name := FC_OSSL_EC_curve_nid2name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_EC_curve_nid2name_removed)}
    if OSSL_EC_curve_nid2name_removed <= LibVersion then
    begin
      {$if declared(_OSSL_EC_curve_nid2name)}
      OSSL_EC_curve_nid2name := _OSSL_EC_curve_nid2name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_EC_curve_nid2name_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_EC_curve_nid2name');
    {$ifend}
  end;
  
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
  
  EC_GROUP_get0_field := LoadLibFunction(ADllHandle, EC_GROUP_get0_field_procname);
  FuncLoadError := not assigned(EC_GROUP_get0_field);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_get0_field_allownil)}
    EC_GROUP_get0_field := ERR_EC_GROUP_get0_field;
    {$ifend}
    {$if declared(EC_GROUP_get0_field_introduced)}
    if LibVersion < EC_GROUP_get0_field_introduced then
    begin
      {$if declared(FC_EC_GROUP_get0_field)}
      EC_GROUP_get0_field := FC_EC_GROUP_get0_field;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_get0_field_removed)}
    if EC_GROUP_get0_field_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_get0_field)}
      EC_GROUP_get0_field := _EC_GROUP_get0_field;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_get0_field_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_get0_field');
    {$ifend}
  end;
  
  EC_GROUP_get_field_type := LoadLibFunction(ADllHandle, EC_GROUP_get_field_type_procname);
  FuncLoadError := not assigned(EC_GROUP_get_field_type);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_get_field_type_allownil)}
    EC_GROUP_get_field_type := ERR_EC_GROUP_get_field_type;
    {$ifend}
    {$if declared(EC_GROUP_get_field_type_introduced)}
    if LibVersion < EC_GROUP_get_field_type_introduced then
    begin
      {$if declared(FC_EC_GROUP_get_field_type)}
      EC_GROUP_get_field_type := FC_EC_GROUP_get_field_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_get_field_type_removed)}
    if EC_GROUP_get_field_type_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_get_field_type)}
      EC_GROUP_get_field_type := _EC_GROUP_get_field_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_get_field_type_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_get_field_type');
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
  
  EC_GROUP_new_from_params := LoadLibFunction(ADllHandle, EC_GROUP_new_from_params_procname);
  FuncLoadError := not assigned(EC_GROUP_new_from_params);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_new_from_params_allownil)}
    EC_GROUP_new_from_params := ERR_EC_GROUP_new_from_params;
    {$ifend}
    {$if declared(EC_GROUP_new_from_params_introduced)}
    if LibVersion < EC_GROUP_new_from_params_introduced then
    begin
      {$if declared(FC_EC_GROUP_new_from_params)}
      EC_GROUP_new_from_params := FC_EC_GROUP_new_from_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_new_from_params_removed)}
    if EC_GROUP_new_from_params_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_new_from_params)}
      EC_GROUP_new_from_params := _EC_GROUP_new_from_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_new_from_params_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_new_from_params');
    {$ifend}
  end;
  
  EC_GROUP_to_params := LoadLibFunction(ADllHandle, EC_GROUP_to_params_procname);
  FuncLoadError := not assigned(EC_GROUP_to_params);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_to_params_allownil)}
    EC_GROUP_to_params := ERR_EC_GROUP_to_params;
    {$ifend}
    {$if declared(EC_GROUP_to_params_introduced)}
    if LibVersion < EC_GROUP_to_params_introduced then
    begin
      {$if declared(FC_EC_GROUP_to_params)}
      EC_GROUP_to_params := FC_EC_GROUP_to_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_to_params_removed)}
    if EC_GROUP_to_params_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_to_params)}
      EC_GROUP_to_params := _EC_GROUP_to_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_to_params_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_to_params');
    {$ifend}
  end;
  
  EC_GROUP_new_by_curve_name_ex := LoadLibFunction(ADllHandle, EC_GROUP_new_by_curve_name_ex_procname);
  FuncLoadError := not assigned(EC_GROUP_new_by_curve_name_ex);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_new_by_curve_name_ex_allownil)}
    EC_GROUP_new_by_curve_name_ex := ERR_EC_GROUP_new_by_curve_name_ex;
    {$ifend}
    {$if declared(EC_GROUP_new_by_curve_name_ex_introduced)}
    if LibVersion < EC_GROUP_new_by_curve_name_ex_introduced then
    begin
      {$if declared(FC_EC_GROUP_new_by_curve_name_ex)}
      EC_GROUP_new_by_curve_name_ex := FC_EC_GROUP_new_by_curve_name_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_new_by_curve_name_ex_removed)}
    if EC_GROUP_new_by_curve_name_ex_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_new_by_curve_name_ex)}
      EC_GROUP_new_by_curve_name_ex := _EC_GROUP_new_by_curve_name_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_new_by_curve_name_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_new_by_curve_name_ex');
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
  
  EC_GROUP_check_named_curve := LoadLibFunction(ADllHandle, EC_GROUP_check_named_curve_procname);
  FuncLoadError := not assigned(EC_GROUP_check_named_curve);
  if FuncLoadError then
  begin
    {$if not defined(EC_GROUP_check_named_curve_allownil)}
    EC_GROUP_check_named_curve := ERR_EC_GROUP_check_named_curve;
    {$ifend}
    {$if declared(EC_GROUP_check_named_curve_introduced)}
    if LibVersion < EC_GROUP_check_named_curve_introduced then
    begin
      {$if declared(FC_EC_GROUP_check_named_curve)}
      EC_GROUP_check_named_curve := FC_EC_GROUP_check_named_curve;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_GROUP_check_named_curve_removed)}
    if EC_GROUP_check_named_curve_removed <= LibVersion then
    begin
      {$if declared(_EC_GROUP_check_named_curve)}
      EC_GROUP_check_named_curve := _EC_GROUP_check_named_curve;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_GROUP_check_named_curve_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_GROUP_check_named_curve');
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
  
  ECPKParameters_print_fp := LoadLibFunction(ADllHandle, ECPKParameters_print_fp_procname);
  FuncLoadError := not assigned(ECPKParameters_print_fp);
  if FuncLoadError then
  begin
    {$if not defined(ECPKParameters_print_fp_allownil)}
    ECPKParameters_print_fp := ERR_ECPKParameters_print_fp;
    {$ifend}
    {$if declared(ECPKParameters_print_fp_introduced)}
    if LibVersion < ECPKParameters_print_fp_introduced then
    begin
      {$if declared(FC_ECPKParameters_print_fp)}
      ECPKParameters_print_fp := FC_ECPKParameters_print_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECPKParameters_print_fp_removed)}
    if ECPKParameters_print_fp_removed <= LibVersion then
    begin
      {$if declared(_ECPKParameters_print_fp)}
      ECPKParameters_print_fp := _ECPKParameters_print_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECPKParameters_print_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('ECPKParameters_print_fp');
    {$ifend}
  end;
  
  EC_KEY_new_ex := LoadLibFunction(ADllHandle, EC_KEY_new_ex_procname);
  FuncLoadError := not assigned(EC_KEY_new_ex);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_new_ex_allownil)}
    EC_KEY_new_ex := ERR_EC_KEY_new_ex;
    {$ifend}
    {$if declared(EC_KEY_new_ex_introduced)}
    if LibVersion < EC_KEY_new_ex_introduced then
    begin
      {$if declared(FC_EC_KEY_new_ex)}
      EC_KEY_new_ex := FC_EC_KEY_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_new_ex_removed)}
    if EC_KEY_new_ex_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_new_ex)}
      EC_KEY_new_ex := _EC_KEY_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_new_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_new_ex');
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
  
  EC_KEY_decoded_from_explicit_params := LoadLibFunction(ADllHandle, EC_KEY_decoded_from_explicit_params_procname);
  FuncLoadError := not assigned(EC_KEY_decoded_from_explicit_params);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_decoded_from_explicit_params_allownil)}
    EC_KEY_decoded_from_explicit_params := ERR_EC_KEY_decoded_from_explicit_params;
    {$ifend}
    {$if declared(EC_KEY_decoded_from_explicit_params_introduced)}
    if LibVersion < EC_KEY_decoded_from_explicit_params_introduced then
    begin
      {$if declared(FC_EC_KEY_decoded_from_explicit_params)}
      EC_KEY_decoded_from_explicit_params := FC_EC_KEY_decoded_from_explicit_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_decoded_from_explicit_params_removed)}
    if EC_KEY_decoded_from_explicit_params_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_decoded_from_explicit_params)}
      EC_KEY_decoded_from_explicit_params := _EC_KEY_decoded_from_explicit_params;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_decoded_from_explicit_params_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_decoded_from_explicit_params');
    {$ifend}
  end;
  
  EC_KEY_new_by_curve_name_ex := LoadLibFunction(ADllHandle, EC_KEY_new_by_curve_name_ex_procname);
  FuncLoadError := not assigned(EC_KEY_new_by_curve_name_ex);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_new_by_curve_name_ex_allownil)}
    EC_KEY_new_by_curve_name_ex := ERR_EC_KEY_new_by_curve_name_ex;
    {$ifend}
    {$if declared(EC_KEY_new_by_curve_name_ex_introduced)}
    if LibVersion < EC_KEY_new_by_curve_name_ex_introduced then
    begin
      {$if declared(FC_EC_KEY_new_by_curve_name_ex)}
      EC_KEY_new_by_curve_name_ex := FC_EC_KEY_new_by_curve_name_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_new_by_curve_name_ex_removed)}
    if EC_KEY_new_by_curve_name_ex_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_new_by_curve_name_ex)}
      EC_KEY_new_by_curve_name_ex := _EC_KEY_new_by_curve_name_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_new_by_curve_name_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_new_by_curve_name_ex');
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
  
  d2i_ECParameters := LoadLibFunction(ADllHandle, d2i_ECParameters_procname);
  FuncLoadError := not assigned(d2i_ECParameters);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ECParameters_allownil)}
    d2i_ECParameters := ERR_d2i_ECParameters;
    {$ifend}
    {$if declared(d2i_ECParameters_introduced)}
    if LibVersion < d2i_ECParameters_introduced then
    begin
      {$if declared(FC_d2i_ECParameters)}
      d2i_ECParameters := FC_d2i_ECParameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ECParameters_removed)}
    if d2i_ECParameters_removed <= LibVersion then
    begin
      {$if declared(_d2i_ECParameters)}
      d2i_ECParameters := _d2i_ECParameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ECParameters_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ECParameters');
    {$ifend}
  end;
  
  i2d_ECParameters := LoadLibFunction(ADllHandle, i2d_ECParameters_procname);
  FuncLoadError := not assigned(i2d_ECParameters);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ECParameters_allownil)}
    i2d_ECParameters := ERR_i2d_ECParameters;
    {$ifend}
    {$if declared(i2d_ECParameters_introduced)}
    if LibVersion < i2d_ECParameters_introduced then
    begin
      {$if declared(FC_i2d_ECParameters)}
      i2d_ECParameters := FC_i2d_ECParameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ECParameters_removed)}
    if i2d_ECParameters_removed <= LibVersion then
    begin
      {$if declared(_i2d_ECParameters)}
      i2d_ECParameters := _i2d_ECParameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ECParameters_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ECParameters');
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
  
  ECParameters_print_fp := LoadLibFunction(ADllHandle, ECParameters_print_fp_procname);
  FuncLoadError := not assigned(ECParameters_print_fp);
  if FuncLoadError then
  begin
    {$if not defined(ECParameters_print_fp_allownil)}
    ECParameters_print_fp := ERR_ECParameters_print_fp;
    {$ifend}
    {$if declared(ECParameters_print_fp_introduced)}
    if LibVersion < ECParameters_print_fp_introduced then
    begin
      {$if declared(FC_ECParameters_print_fp)}
      ECParameters_print_fp := FC_ECParameters_print_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ECParameters_print_fp_removed)}
    if ECParameters_print_fp_removed <= LibVersion then
    begin
      {$if declared(_ECParameters_print_fp)}
      ECParameters_print_fp := _ECParameters_print_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ECParameters_print_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('ECParameters_print_fp');
    {$ifend}
  end;
  
  EC_KEY_print_fp := LoadLibFunction(ADllHandle, EC_KEY_print_fp_procname);
  FuncLoadError := not assigned(EC_KEY_print_fp);
  if FuncLoadError then
  begin
    {$if not defined(EC_KEY_print_fp_allownil)}
    EC_KEY_print_fp := ERR_EC_KEY_print_fp;
    {$ifend}
    {$if declared(EC_KEY_print_fp_introduced)}
    if LibVersion < EC_KEY_print_fp_introduced then
    begin
      {$if declared(FC_EC_KEY_print_fp)}
      EC_KEY_print_fp := FC_EC_KEY_print_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EC_KEY_print_fp_removed)}
    if EC_KEY_print_fp_removed <= LibVersion then
    begin
      {$if declared(_EC_KEY_print_fp)}
      EC_KEY_print_fp := _EC_KEY_print_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EC_KEY_print_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('EC_KEY_print_fp');
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
  
end;

procedure Unload;
begin
  EVP_PKEY_CTX_set_ec_paramgen_curve_nid := nil;
  EVP_PKEY_CTX_set_ec_param_enc := nil;
  EVP_PKEY_CTX_set_ecdh_cofactor_mode := nil;
  EVP_PKEY_CTX_get_ecdh_cofactor_mode := nil;
  EVP_PKEY_CTX_set_ecdh_kdf_type := nil;
  EVP_PKEY_CTX_get_ecdh_kdf_type := nil;
  EVP_PKEY_CTX_set_ecdh_kdf_md := nil;
  EVP_PKEY_CTX_get_ecdh_kdf_md := nil;
  EVP_PKEY_CTX_set_ecdh_kdf_outlen := nil;
  EVP_PKEY_CTX_get_ecdh_kdf_outlen := nil;
  EVP_PKEY_CTX_set0_ecdh_kdf_ukm := nil;
  EVP_PKEY_CTX_get0_ecdh_kdf_ukm := nil;
  OSSL_EC_curve_nid2name := nil;
  EC_GFp_simple_method := nil;
  EC_GFp_mont_method := nil;
  EC_GFp_nist_method := nil;
  EC_GF2m_simple_method := nil;
  EC_GROUP_new := nil;
  EC_GROUP_clear_free := nil;
  EC_GROUP_method_of := nil;
  EC_METHOD_get_field_type := nil;
  EC_GROUP_free := nil;
  EC_GROUP_copy := nil;
  EC_GROUP_dup := nil;
  EC_GROUP_set_generator := nil;
  EC_GROUP_get0_generator := nil;
  EC_GROUP_get_mont_data := nil;
  EC_GROUP_get_order := nil;
  EC_GROUP_get0_order := nil;
  EC_GROUP_order_bits := nil;
  EC_GROUP_get_cofactor := nil;
  EC_GROUP_get0_cofactor := nil;
  EC_GROUP_set_curve_name := nil;
  EC_GROUP_get_curve_name := nil;
  EC_GROUP_get0_field := nil;
  EC_GROUP_get_field_type := nil;
  EC_GROUP_set_asn1_flag := nil;
  EC_GROUP_get_asn1_flag := nil;
  EC_GROUP_set_point_conversion_form := nil;
  EC_GROUP_get_point_conversion_form := nil;
  EC_GROUP_get0_seed := nil;
  EC_GROUP_get_seed_len := nil;
  EC_GROUP_set_seed := nil;
  EC_GROUP_set_curve := nil;
  EC_GROUP_get_curve := nil;
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
  EC_GROUP_new_from_params := nil;
  EC_GROUP_to_params := nil;
  EC_GROUP_new_by_curve_name_ex := nil;
  EC_GROUP_new_by_curve_name := nil;
  EC_GROUP_new_from_ecparameters := nil;
  EC_GROUP_get_ecparameters := nil;
  EC_GROUP_new_from_ecpkparameters := nil;
  EC_GROUP_get_ecpkparameters := nil;
  EC_get_builtin_curves := nil;
  EC_curve_nid2nist := nil;
  EC_curve_nist2nid := nil;
  EC_GROUP_check_named_curve := nil;
  EC_POINT_new := nil;
  EC_POINT_free := nil;
  EC_POINT_clear_free := nil;
  EC_POINT_copy := nil;
  EC_POINT_dup := nil;
  EC_POINT_set_to_infinity := nil;
  EC_POINT_method_of := nil;
  EC_POINT_set_Jprojective_coordinates_GFp := nil;
  EC_POINT_get_Jprojective_coordinates_GFp := nil;
  EC_POINT_set_affine_coordinates := nil;
  EC_POINT_get_affine_coordinates := nil;
  EC_POINT_set_affine_coordinates_GFp := nil;
  EC_POINT_get_affine_coordinates_GFp := nil;
  EC_POINT_set_compressed_coordinates := nil;
  EC_POINT_set_compressed_coordinates_GFp := nil;
  EC_POINT_set_affine_coordinates_GF2m := nil;
  EC_POINT_get_affine_coordinates_GF2m := nil;
  EC_POINT_set_compressed_coordinates_GF2m := nil;
  EC_POINT_point2oct := nil;
  EC_POINT_oct2point := nil;
  EC_POINT_point2buf := nil;
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
  ECPKParameters_print_fp := nil;
  EC_KEY_new_ex := nil;
  EC_KEY_new := nil;
  EC_KEY_get_flags := nil;
  EC_KEY_set_flags := nil;
  EC_KEY_clear_flags := nil;
  EC_KEY_decoded_from_explicit_params := nil;
  EC_KEY_new_by_curve_name_ex := nil;
  EC_KEY_new_by_curve_name := nil;
  EC_KEY_free := nil;
  EC_KEY_copy := nil;
  EC_KEY_dup := nil;
  EC_KEY_up_ref := nil;
  EC_KEY_get0_engine := nil;
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
  EC_KEY_set_ex_data := nil;
  EC_KEY_get_ex_data := nil;
  EC_KEY_set_asn1_flag := nil;
  EC_KEY_precompute_mult := nil;
  EC_KEY_generate_key := nil;
  EC_KEY_check_key := nil;
  EC_KEY_can_sign := nil;
  EC_KEY_set_public_key_affine_coordinates := nil;
  EC_KEY_key2buf := nil;
  EC_KEY_oct2key := nil;
  EC_KEY_oct2priv := nil;
  EC_KEY_priv2oct := nil;
  EC_KEY_priv2buf := nil;
  d2i_ECPrivateKey := nil;
  i2d_ECPrivateKey := nil;
  d2i_ECParameters := nil;
  i2d_ECParameters := nil;
  o2i_ECPublicKey := nil;
  i2o_ECPublicKey := nil;
  ECParameters_print := nil;
  EC_KEY_print := nil;
  ECParameters_print_fp := nil;
  EC_KEY_print_fp := nil;
  EC_KEY_OpenSSL := nil;
  EC_KEY_get_default_method := nil;
  EC_KEY_set_default_method := nil;
  EC_KEY_get_method := nil;
  EC_KEY_set_method := nil;
  EC_KEY_new_method := nil;
  ECDH_KDF_X9_62 := nil;
  ECDH_compute_key := nil;
  ECDSA_SIG_new := nil;
  ECDSA_SIG_free := nil;
  d2i_ECDSA_SIG := nil;
  i2d_ECDSA_SIG := nil;
  ECDSA_SIG_get0 := nil;
  ECDSA_SIG_get0_r := nil;
  ECDSA_SIG_get0_s := nil;
  ECDSA_SIG_set0 := nil;
  ECDSA_do_sign := nil;
  ECDSA_do_sign_ex := nil;
  ECDSA_do_verify := nil;
  ECDSA_sign_setup := nil;
  ECDSA_sign := nil;
  ECDSA_sign_ex := nil;
  ECDSA_verify := nil;
  ECDSA_size := nil;
  EC_KEY_METHOD_new := nil;
  EC_KEY_METHOD_free := nil;
  EC_KEY_METHOD_set_init := nil;
  EC_KEY_METHOD_set_keygen := nil;
  EC_KEY_METHOD_set_compute_key := nil;
  EC_KEY_METHOD_set_sign := nil;
  EC_KEY_METHOD_set_verify := nil;
  EC_KEY_METHOD_get_init := nil;
  EC_KEY_METHOD_get_keygen := nil;
  EC_KEY_METHOD_get_compute_key := nil;
  EC_KEY_METHOD_get_sign := nil;
  EC_KEY_METHOD_get_verify := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.