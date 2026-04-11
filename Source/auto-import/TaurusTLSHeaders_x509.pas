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

unit TaurusTLSHeaders_x509;

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
  PX509_algor_st = ^TX509_algor_st;
  TX509_algor_st =   record
    algorithm: PASN1_OBJECT;
    parameter: PASN1_TYPE;
  end;
  {$EXTERNALSYM PX509_algor_st}

  PX509_val_st = ^TX509_val_st;
  TX509_val_st =   record
    notBefore: PASN1_TIME;
    notAfter: PASN1_TIME;
  end;
  {$EXTERNALSYM PX509_val_st}

  PX509_sig_st = ^TX509_sig_st;
  TX509_sig_st =   record end;
  {$EXTERNALSYM PX509_sig_st}

  PX509_name_entry_st = ^TX509_name_entry_st;
  TX509_name_entry_st =   record end;
  {$EXTERNALSYM PX509_name_entry_st}

  PX509_extension_st = ^TX509_extension_st;
  TX509_extension_st =   record end;
  {$EXTERNALSYM PX509_extension_st}

  Px509_attributes_st = ^Tx509_attributes_st;
  Tx509_attributes_st =   record end;
  {$EXTERNALSYM Px509_attributes_st}

  PX509_req_info_st = ^TX509_req_info_st;
  TX509_req_info_st =   record end;
  {$EXTERNALSYM PX509_req_info_st}

  PX509_req_st = ^TX509_req_st;
  TX509_req_st =   record end;
  {$EXTERNALSYM PX509_req_st}

  Px509_cert_aux_st = ^Tx509_cert_aux_st;
  Tx509_cert_aux_st =   record end;
  {$EXTERNALSYM Px509_cert_aux_st}

  Px509_cinf_st = ^Tx509_cinf_st;
  Tx509_cinf_st =   record end;
  {$EXTERNALSYM Px509_cinf_st}

  PX509_crl_info_st = ^TX509_crl_info_st;
  TX509_crl_info_st =   record end;
  {$EXTERNALSYM PX509_crl_info_st}

  Pprivate_key_st = ^Tprivate_key_st;
  Tprivate_key_st =   record
    version: TIdC_INT;
    enc_algor: PX509_ALGOR;
    enc_pkey: PASN1_OCTET_STRING;
    dec_pkey: PEVP_PKEY;
    key_length: TIdC_INT;
    key_data: PIdAnsiChar;
    key_free: TIdC_INT;
    cipher: TEVP_CIPHER_INFO;
  end;
  {$EXTERNALSYM Pprivate_key_st}

  PX509_info_st = ^TX509_info_st;
  TX509_info_st =   record
    x509: PX509;
    crl: PX509_CRL;
    x_pkey: PX509_PKEY;
    enc_cipher: TEVP_CIPHER_INFO;
    enc_len: TIdC_INT;
    enc_data: PIdAnsiChar;
  end;
  {$EXTERNALSYM PX509_info_st}

  PNetscape_spkac_st = ^TNetscape_spkac_st;
  TNetscape_spkac_st =   record
    pubkey: PX509_PUBKEY;
    challenge: PASN1_IA5STRING;
  end;
  {$EXTERNALSYM PNetscape_spkac_st}

  PNetscape_spki_st = ^TNetscape_spki_st;
  TNetscape_spki_st =   record
    spkac: PNETSCAPE_SPKAC;
    sig_algor: TX509_ALGOR;
    signature: PASN1_BIT_STRING;
  end;
  {$EXTERNALSYM PNetscape_spki_st}

  PNetscape_certificate_sequence = ^TNetscape_certificate_sequence;
  TNetscape_certificate_sequence =   record
    _type: PASN1_OBJECT;
    certs: Pstack_st_X509;
  end;
  {$EXTERNALSYM PNetscape_certificate_sequence}

  PPBEPARAM_st = ^TPBEPARAM_st;
  TPBEPARAM_st =   record
    salt: PASN1_OCTET_STRING;
    iter: PASN1_INTEGER;
  end;
  {$EXTERNALSYM PPBEPARAM_st}

  PPBE2PARAM_st = ^TPBE2PARAM_st;
  TPBE2PARAM_st =   record
    keyfunc: PX509_ALGOR;
    encryption: PX509_ALGOR;
  end;
  {$EXTERNALSYM PPBE2PARAM_st}

  PPBKDF2PARAM_st = ^TPBKDF2PARAM_st;
  TPBKDF2PARAM_st =   record
    salt: PASN1_TYPE;
    iter: PASN1_INTEGER;
    keylength: PASN1_INTEGER;
    prf: PX509_ALGOR;
  end;
  {$EXTERNALSYM PPBKDF2PARAM_st}

  PPBMAC1PARAM = ^TPBMAC1PARAM;
  TPBMAC1PARAM =   record
    keyDerivationFunc: PX509_ALGOR;
    messageAuthScheme: PX509_ALGOR;
  end;
  {$EXTERNALSYM PPBMAC1PARAM}

  PSCRYPT_PARAMS_st = ^TSCRYPT_PARAMS_st;
  TSCRYPT_PARAMS_st =   record
    salt: PASN1_OCTET_STRING;
    costParameter: PASN1_INTEGER;
    blockSize: PASN1_INTEGER;
    parallelizationParameter: PASN1_INTEGER;
    keyLength: PASN1_INTEGER;
  end;
  {$EXTERNALSYM PSCRYPT_PARAMS_st}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // X509_CRL_METHOD_new_crl_init_cb = function(crl: PX509_CRL): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // X509_CRL_METHOD_new_crl_lookup_cb = function(crl: PX509_CRL; ret: PPX509_REVOKED; serial: PASN1_INTEGER; issuer: PX509_NAME): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // X509_CRL_METHOD_new_crl_verify_cb = function(crl: PX509_CRL; pk: PEVP_PKEY): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // ASN1_verify_i2d_cb = function(arg1: Pointer; arg2: PPIdAnsiChar): TIdC_INT; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  X509_SIG_INFO_VALID = $1;
  X509_SIG_INFO_TLS = $2;
  X509_FILETYPE_PEM = 1;
  X509_FILETYPE_ASN1 = 2;
  X509_FILETYPE_DEFAULT = 3;
  X509v3_KU_DIGITAL_SIGNATURE = $0080;
  X509v3_KU_NON_REPUDIATION = $0040;
  X509v3_KU_KEY_ENCIPHERMENT = $0020;
  X509v3_KU_DATA_ENCIPHERMENT = $0010;
  X509v3_KU_KEY_AGREEMENT = $0008;
  X509v3_KU_KEY_CERT_SIGN = $0004;
  X509v3_KU_CRL_SIGN = $0002;
  X509v3_KU_ENCIPHER_ONLY = $0001;
  X509v3_KU_DECIPHER_ONLY = $8000;
  X509v3_KU_UNDEF = $ffff;
  X509_EX_V_NETSCAPE_HACK = $8000;
  X509_EX_V_INIT = $0001;
  X509_FLAG_COMPAT = 0;
  X509_FLAG_NO_HEADER = 1;
  X509_FLAG_NO_VERSION = (1 shl 1);
  X509_FLAG_NO_SERIAL = (1 shl 2);
  X509_FLAG_NO_SIGNAME = (1 shl 3);
  X509_FLAG_NO_ISSUER = (1 shl 4);
  X509_FLAG_NO_VALIDITY = (1 shl 5);
  X509_FLAG_NO_SUBJECT = (1 shl 6);
  X509_FLAG_NO_PUBKEY = (1 shl 7);
  X509_FLAG_NO_EXTENSIONS = (1 shl 8);
  X509_FLAG_NO_SIGDUMP = (1 shl 9);
  X509_FLAG_NO_AUX = (1 shl 10);
  X509_FLAG_NO_ATTRIBUTES = (1 shl 11);
  X509_FLAG_NO_IDS = (1 shl 12);
  X509_FLAG_EXTENSIONS_ONLY_KID = (1 shl 13);
  XN_FLAG_SEP_MASK = ($f shl 16);
  XN_FLAG_COMPAT = 0;
  XN_FLAG_SEP_COMMA_PLUS = (1 shl 16);
  XN_FLAG_SEP_CPLUS_SPC = (2 shl 16);
  XN_FLAG_SEP_SPLUS_SPC = (3 shl 16);
  XN_FLAG_SEP_MULTILINE = (4 shl 16);
  XN_FLAG_DN_REV = (1 shl 20);
  XN_FLAG_FN_MASK = ($3 shl 21);
  XN_FLAG_FN_SN = 0;
  XN_FLAG_FN_LN = (1 shl 21);
  XN_FLAG_FN_OID = (2 shl 21);
  XN_FLAG_FN_NONE = (3 shl 21);
  XN_FLAG_SPC_EQ = (1 shl 23);
  XN_FLAG_DUMP_UNKNOWN_FIELDS = (1 shl 24);
  XN_FLAG_FN_ALIGN = (1 shl 25);
  XN_FLAG_RFC2253 = (ASN1_STRFLGS_RFC2253 or XN_FLAG_SEP_COMMA_PLUS or XN_FLAG_DN_REV or XN_FLAG_FN_SN or XN_FLAG_DUMP_UNKNOWN_FIELDS);
  XN_FLAG_ONELINE = (ASN1_STRFLGS_RFC2253 or ASN1_STRFLGS_ESC_QUOTE or XN_FLAG_SEP_CPLUS_SPC or XN_FLAG_SPC_EQ or XN_FLAG_FN_SN);
  XN_FLAG_MULTILINE = (ASN1_STRFLGS_ESC_CTRL or ASN1_STRFLGS_ESC_MSB or XN_FLAG_SEP_MULTILINE or XN_FLAG_SPC_EQ or XN_FLAG_FN_LN or XN_FLAG_FN_ALIGN);
  X509_EXT_PACK_UNKNOWN = 1;
  X509_EXT_PACK_STRING = 2;
  X509_VERSION_1 = 0;
  X509_VERSION_2 = 1;
  X509_VERSION_3 = 2;
  X509_REQ_VERSION_1 = 0;
  X509_CRL_VERSION_1 = 0;
  X509_CRL_VERSION_2 = 1;
  X509_ADD_FLAG_DEFAULT = 0;
  X509_ADD_FLAG_UP_REF = $1;
  X509_ADD_FLAG_PREPEND = $2;
  X509_ADD_FLAG_NO_DUP = $4;
  X509_ADD_FLAG_NO_SS = $8;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  X509_CRL_set_default_method: procedure(meth: PX509_CRL_METHOD); cdecl = nil;
  {$EXTERNALSYM X509_CRL_set_default_method}

  X509_CRL_METHOD_new: function(crl_init: TX509_CRL_METHOD_new_crl_init_cb; crl_free: TX509_CRL_METHOD_new_crl_init_cb; crl_lookup: TX509_CRL_METHOD_new_crl_lookup_cb; crl_verify: TX509_CRL_METHOD_new_crl_verify_cb): PX509_CRL_METHOD; cdecl = nil;
  {$EXTERNALSYM X509_CRL_METHOD_new}

  X509_CRL_METHOD_free: procedure(m: PX509_CRL_METHOD); cdecl = nil;
  {$EXTERNALSYM X509_CRL_METHOD_free}

  X509_CRL_set_meth_data: procedure(crl: PX509_CRL; dat: Pointer); cdecl = nil;
  {$EXTERNALSYM X509_CRL_set_meth_data}

  X509_CRL_get_meth_data: function(crl: PX509_CRL): Pointer; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get_meth_data}

  X509_verify_cert_error_string: function(n: TIdC_LONG): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_verify_cert_error_string}

  X509_verify: function(a: PX509; r: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_verify}

  X509_self_signed: function(cert: PX509; verify_signature: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_self_signed}

  X509_REQ_verify_ex: function(a: PX509_REQ; r: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_verify_ex}

  X509_REQ_verify: function(a: PX509_REQ; r: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_verify}

  X509_CRL_verify: function(a: PX509_CRL; r: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_verify}

  NETSCAPE_SPKI_verify: function(a: PNETSCAPE_SPKI; r: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM NETSCAPE_SPKI_verify}

  NETSCAPE_SPKI_b64_decode: function(str: PIdAnsiChar; len: TIdC_INT): PNETSCAPE_SPKI; cdecl = nil;
  {$EXTERNALSYM NETSCAPE_SPKI_b64_decode}

  NETSCAPE_SPKI_b64_encode: function(x: PNETSCAPE_SPKI): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM NETSCAPE_SPKI_b64_encode}

  NETSCAPE_SPKI_get_pubkey: function(x: PNETSCAPE_SPKI): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM NETSCAPE_SPKI_get_pubkey}

  NETSCAPE_SPKI_set_pubkey: function(x: PNETSCAPE_SPKI; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM NETSCAPE_SPKI_set_pubkey}

  NETSCAPE_SPKI_print: function(_out: PBIO; spki: PNETSCAPE_SPKI): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM NETSCAPE_SPKI_print}

  X509_signature_dump: function(bp: PBIO; sig: PASN1_STRING; indent: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_signature_dump}

  X509_signature_print: function(bp: PBIO; alg: PX509_ALGOR; sig: PASN1_STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_signature_print}

  X509_sign: function(x: PX509; pkey: PEVP_PKEY; md: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_sign}

  X509_sign_ctx: function(x: PX509; ctx: PEVP_MD_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_sign_ctx}

  X509_REQ_sign: function(x: PX509_REQ; pkey: PEVP_PKEY; md: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_sign}

  X509_REQ_sign_ctx: function(x: PX509_REQ; ctx: PEVP_MD_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_sign_ctx}

  X509_CRL_sign: function(x: PX509_CRL; pkey: PEVP_PKEY; md: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_sign}

  X509_CRL_sign_ctx: function(x: PX509_CRL; ctx: PEVP_MD_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_sign_ctx}

  NETSCAPE_SPKI_sign: function(x: PNETSCAPE_SPKI; pkey: PEVP_PKEY; md: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM NETSCAPE_SPKI_sign}

  X509_pubkey_digest: function(data: PX509; _type: PEVP_MD; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_pubkey_digest}

  X509_digest: function(data: PX509; _type: PEVP_MD; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_digest}

  X509_digest_sig: function(cert: PX509; md_used: PPEVP_MD; md_is_fallback: PIdC_INT): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM X509_digest_sig}

  X509_CRL_digest: function(data: PX509_CRL; _type: PEVP_MD; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_digest}

  X509_REQ_digest: function(data: PX509_REQ; _type: PEVP_MD; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_digest}

  X509_NAME_digest: function(data: PX509_NAME; _type: PEVP_MD; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_digest}

  X509_load_http: function(url: PIdAnsiChar; bio: PBIO; rbio: PBIO; timeout: TIdC_INT): PX509; cdecl = nil;
  {$EXTERNALSYM X509_load_http}

  X509_CRL_load_http: function(url: PIdAnsiChar; bio: PBIO; rbio: PBIO; timeout: TIdC_INT): PX509_CRL; cdecl = nil;
  {$EXTERNALSYM X509_CRL_load_http}

  d2i_X509_fp: function(fp: PFILE; x509: PPX509): PX509; cdecl = nil;
  {$EXTERNALSYM d2i_X509_fp}

  i2d_X509_fp: function(fp: PFILE; x509: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_fp}

  d2i_X509_CRL_fp: function(fp: PFILE; crl: PPX509_CRL): PX509_CRL; cdecl = nil;
  {$EXTERNALSYM d2i_X509_CRL_fp}

  i2d_X509_CRL_fp: function(fp: PFILE; crl: PX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_CRL_fp}

  d2i_X509_REQ_fp: function(fp: PFILE; req: PPX509_REQ): PX509_REQ; cdecl = nil;
  {$EXTERNALSYM d2i_X509_REQ_fp}

  i2d_X509_REQ_fp: function(fp: PFILE; req: PX509_REQ): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_REQ_fp}

  d2i_RSAPrivateKey_fp: function(fp: PFILE; rsa: PPRSA): PRSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM d2i_RSAPrivateKey_fp}

  i2d_RSAPrivateKey_fp: function(fp: PFILE; rsa: PRSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM i2d_RSAPrivateKey_fp}

  d2i_RSAPublicKey_fp: function(fp: PFILE; rsa: PPRSA): PRSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM d2i_RSAPublicKey_fp}

  i2d_RSAPublicKey_fp: function(fp: PFILE; rsa: PRSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM i2d_RSAPublicKey_fp}

  d2i_RSA_PUBKEY_fp: function(fp: PFILE; rsa: PPRSA): PRSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM d2i_RSA_PUBKEY_fp}

  i2d_RSA_PUBKEY_fp: function(fp: PFILE; rsa: PRSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM i2d_RSA_PUBKEY_fp}

  d2i_DSA_PUBKEY_fp: function(fp: PFILE; dsa: PPDSA): PDSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM d2i_DSA_PUBKEY_fp}

  i2d_DSA_PUBKEY_fp: function(fp: PFILE; dsa: PDSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM i2d_DSA_PUBKEY_fp}

  d2i_DSAPrivateKey_fp: function(fp: PFILE; dsa: PPDSA): PDSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM d2i_DSAPrivateKey_fp}

  i2d_DSAPrivateKey_fp: function(fp: PFILE; dsa: PDSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM i2d_DSAPrivateKey_fp}

  d2i_EC_PUBKEY_fp: function(fp: PFILE; eckey: PPEC_KEY): PEC_KEY; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM d2i_EC_PUBKEY_fp}

  i2d_EC_PUBKEY_fp: function(fp: PFILE; eckey: PEC_KEY): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM i2d_EC_PUBKEY_fp}

  d2i_ECPrivateKey_fp: function(fp: PFILE; eckey: PPEC_KEY): PEC_KEY; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM d2i_ECPrivateKey_fp}

  i2d_ECPrivateKey_fp: function(fp: PFILE; eckey: PEC_KEY): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM i2d_ECPrivateKey_fp}

  d2i_PKCS8_fp: function(fp: PFILE; p8: PPX509_SIG): PX509_SIG; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS8_fp}

  i2d_PKCS8_fp: function(fp: PFILE; p8: PX509_SIG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS8_fp}

  d2i_X509_PUBKEY_fp: function(fp: PFILE; xpk: PPX509_PUBKEY): PX509_PUBKEY; cdecl = nil;
  {$EXTERNALSYM d2i_X509_PUBKEY_fp}

  i2d_X509_PUBKEY_fp: function(fp: PFILE; xpk: PX509_PUBKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_PUBKEY_fp}

  d2i_PKCS8_PRIV_KEY_INFO_fp: function(fp: PFILE; p8inf: PPPKCS8_PRIV_KEY_INFO): PPKCS8_PRIV_KEY_INFO; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS8_PRIV_KEY_INFO_fp}

  i2d_PKCS8_PRIV_KEY_INFO_fp: function(fp: PFILE; p8inf: PPKCS8_PRIV_KEY_INFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS8_PRIV_KEY_INFO_fp}

  i2d_PKCS8PrivateKeyInfo_fp: function(fp: PFILE; key: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS8PrivateKeyInfo_fp}

  i2d_PrivateKey_fp: function(fp: PFILE; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PrivateKey_fp}

  d2i_PrivateKey_ex_fp: function(fp: PFILE; a: PPEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM d2i_PrivateKey_ex_fp}

  d2i_PrivateKey_fp: function(fp: PFILE; a: PPEVP_PKEY): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM d2i_PrivateKey_fp}

  i2d_PUBKEY_fp: function(fp: PFILE; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PUBKEY_fp}

  d2i_PUBKEY_ex_fp: function(fp: PFILE; a: PPEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM d2i_PUBKEY_ex_fp}

  d2i_PUBKEY_fp: function(fp: PFILE; a: PPEVP_PKEY): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM d2i_PUBKEY_fp}

  d2i_X509_bio: function(bp: PBIO; x509: PPX509): PX509; cdecl = nil;
  {$EXTERNALSYM d2i_X509_bio}

  i2d_X509_bio: function(bp: PBIO; x509: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_bio}

  d2i_X509_CRL_bio: function(bp: PBIO; crl: PPX509_CRL): PX509_CRL; cdecl = nil;
  {$EXTERNALSYM d2i_X509_CRL_bio}

  i2d_X509_CRL_bio: function(bp: PBIO; crl: PX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_CRL_bio}

  d2i_X509_REQ_bio: function(bp: PBIO; req: PPX509_REQ): PX509_REQ; cdecl = nil;
  {$EXTERNALSYM d2i_X509_REQ_bio}

  i2d_X509_REQ_bio: function(bp: PBIO; req: PX509_REQ): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_REQ_bio}

  d2i_RSAPrivateKey_bio: function(bp: PBIO; rsa: PPRSA): PRSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM d2i_RSAPrivateKey_bio}

  i2d_RSAPrivateKey_bio: function(bp: PBIO; rsa: PRSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM i2d_RSAPrivateKey_bio}

  d2i_RSAPublicKey_bio: function(bp: PBIO; rsa: PPRSA): PRSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM d2i_RSAPublicKey_bio}

  i2d_RSAPublicKey_bio: function(bp: PBIO; rsa: PRSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM i2d_RSAPublicKey_bio}

  d2i_RSA_PUBKEY_bio: function(bp: PBIO; rsa: PPRSA): PRSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM d2i_RSA_PUBKEY_bio}

  i2d_RSA_PUBKEY_bio: function(bp: PBIO; rsa: PRSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM i2d_RSA_PUBKEY_bio}

  d2i_DSA_PUBKEY_bio: function(bp: PBIO; dsa: PPDSA): PDSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM d2i_DSA_PUBKEY_bio}

  i2d_DSA_PUBKEY_bio: function(bp: PBIO; dsa: PDSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM i2d_DSA_PUBKEY_bio}

  d2i_DSAPrivateKey_bio: function(bp: PBIO; dsa: PPDSA): PDSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM d2i_DSAPrivateKey_bio}

  i2d_DSAPrivateKey_bio: function(bp: PBIO; dsa: PDSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM i2d_DSAPrivateKey_bio}

  d2i_EC_PUBKEY_bio: function(bp: PBIO; eckey: PPEC_KEY): PEC_KEY; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM d2i_EC_PUBKEY_bio}

  i2d_EC_PUBKEY_bio: function(bp: PBIO; eckey: PEC_KEY): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM i2d_EC_PUBKEY_bio}

  d2i_ECPrivateKey_bio: function(bp: PBIO; eckey: PPEC_KEY): PEC_KEY; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM d2i_ECPrivateKey_bio}

  i2d_ECPrivateKey_bio: function(bp: PBIO; eckey: PEC_KEY): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM i2d_ECPrivateKey_bio}

  d2i_PKCS8_bio: function(bp: PBIO; p8: PPX509_SIG): PX509_SIG; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS8_bio}

  i2d_PKCS8_bio: function(bp: PBIO; p8: PX509_SIG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS8_bio}

  d2i_X509_PUBKEY_bio: function(bp: PBIO; xpk: PPX509_PUBKEY): PX509_PUBKEY; cdecl = nil;
  {$EXTERNALSYM d2i_X509_PUBKEY_bio}

  i2d_X509_PUBKEY_bio: function(bp: PBIO; xpk: PX509_PUBKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_PUBKEY_bio}

  d2i_PKCS8_PRIV_KEY_INFO_bio: function(bp: PBIO; p8inf: PPPKCS8_PRIV_KEY_INFO): PPKCS8_PRIV_KEY_INFO; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS8_PRIV_KEY_INFO_bio}

  i2d_PKCS8_PRIV_KEY_INFO_bio: function(bp: PBIO; p8inf: PPKCS8_PRIV_KEY_INFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS8_PRIV_KEY_INFO_bio}

  i2d_PKCS8PrivateKeyInfo_bio: function(bp: PBIO; key: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS8PrivateKeyInfo_bio}

  i2d_PrivateKey_bio: function(bp: PBIO; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PrivateKey_bio}

  d2i_PrivateKey_ex_bio: function(bp: PBIO; a: PPEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM d2i_PrivateKey_ex_bio}

  d2i_PrivateKey_bio: function(bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM d2i_PrivateKey_bio}

  i2d_PUBKEY_bio: function(bp: PBIO; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PUBKEY_bio}

  d2i_PUBKEY_ex_bio: function(bp: PBIO; a: PPEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM d2i_PUBKEY_ex_bio}

  d2i_PUBKEY_bio: function(bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM d2i_PUBKEY_bio}

  X509_dup: function(a: PX509): PX509; cdecl = nil;
  {$EXTERNALSYM X509_dup}

  X509_ALGOR_dup: function(a: PX509_ALGOR): PX509_ALGOR; cdecl = nil;
  {$EXTERNALSYM X509_ALGOR_dup}

  X509_ATTRIBUTE_dup: function(a: PX509_ATTRIBUTE): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM X509_ATTRIBUTE_dup}

  X509_CRL_dup: function(a: PX509_CRL): PX509_CRL; cdecl = nil;
  {$EXTERNALSYM X509_CRL_dup}

  X509_EXTENSION_dup: function(a: PX509_EXTENSION): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_EXTENSION_dup}

  X509_PUBKEY_dup: function(a: PX509_PUBKEY): PX509_PUBKEY; cdecl = nil;
  {$EXTERNALSYM X509_PUBKEY_dup}

  X509_REQ_dup: function(a: PX509_REQ): PX509_REQ; cdecl = nil;
  {$EXTERNALSYM X509_REQ_dup}

  X509_REVOKED_dup: function(a: PX509_REVOKED): PX509_REVOKED; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_dup}

  X509_ALGOR_set0: function(alg: PX509_ALGOR; aobj: PASN1_OBJECT; ptype: TIdC_INT; pval: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ALGOR_set0}

  X509_ALGOR_get0: procedure(paobj: PPASN1_OBJECT; pptype: PIdC_INT; ppval: PPointer; algor: PX509_ALGOR); cdecl = nil;
  {$EXTERNALSYM X509_ALGOR_get0}

  X509_ALGOR_set_md: procedure(alg: PX509_ALGOR; md: PEVP_MD); cdecl = nil;
  {$EXTERNALSYM X509_ALGOR_set_md}

  X509_ALGOR_cmp: function(a: PX509_ALGOR; b: PX509_ALGOR): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ALGOR_cmp}

  X509_ALGOR_copy: function(dest: PX509_ALGOR; src: PX509_ALGOR): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ALGOR_copy}

  X509_NAME_dup: function(a: PX509_NAME): PX509_NAME; cdecl = nil;
  {$EXTERNALSYM X509_NAME_dup}

  X509_NAME_ENTRY_dup: function(a: PX509_NAME_ENTRY): PX509_NAME_ENTRY; cdecl = nil;
  {$EXTERNALSYM X509_NAME_ENTRY_dup}

  X509_cmp_time: function(s: PASN1_TIME; t: PIdC_TIMET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_cmp_time}

  X509_cmp_current_time: function(s: PASN1_TIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_cmp_current_time}

  X509_cmp_timeframe: function(vpm: PX509_VERIFY_PARAM; start: PASN1_TIME; _end: PASN1_TIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_cmp_timeframe}

  X509_time_adj: function(s: PASN1_TIME; adj: TIdC_LONG; t: PIdC_TIMET): PASN1_TIME; cdecl = nil;
  {$EXTERNALSYM X509_time_adj}

  X509_time_adj_ex: function(s: PASN1_TIME; offset_day: TIdC_INT; offset_sec: TIdC_LONG; t: PIdC_TIMET): PASN1_TIME; cdecl = nil;
  {$EXTERNALSYM X509_time_adj_ex}

  X509_gmtime_adj: function(s: PASN1_TIME; adj: TIdC_LONG): PASN1_TIME; cdecl = nil;
  {$EXTERNALSYM X509_gmtime_adj}

  X509_get_default_cert_area: function: PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_get_default_cert_area}

  X509_get_default_cert_dir: function: PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_get_default_cert_dir}

  X509_get_default_cert_file: function: PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_get_default_cert_file}

  X509_get_default_cert_dir_env: function: PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_get_default_cert_dir_env}

  X509_get_default_cert_file_env: function: PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_get_default_cert_file_env}

  X509_get_default_private_dir: function: PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_get_default_private_dir}

  X509_to_X509_REQ: function(x: PX509; pkey: PEVP_PKEY; md: PEVP_MD): PX509_REQ; cdecl = nil;
  {$EXTERNALSYM X509_to_X509_REQ}

  X509_REQ_to_X509: function(r: PX509_REQ; days: TIdC_INT; pkey: PEVP_PKEY): PX509; cdecl = nil;
  {$EXTERNALSYM X509_REQ_to_X509}

  X509_ALGOR_new: function: PX509_ALGOR; cdecl = nil;
  {$EXTERNALSYM X509_ALGOR_new}

  X509_ALGOR_free: procedure(a: PX509_ALGOR); cdecl = nil;
  {$EXTERNALSYM X509_ALGOR_free}

  d2i_X509_ALGOR: function(a: PPX509_ALGOR; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_ALGOR; cdecl = nil;
  {$EXTERNALSYM d2i_X509_ALGOR}

  i2d_X509_ALGOR: function(a: PX509_ALGOR; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_ALGOR}

  X509_ALGOR_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM X509_ALGOR_it}

  d2i_X509_ALGORS: function(a: PPX509_ALGORS; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_ALGORS; cdecl = nil;
  {$EXTERNALSYM d2i_X509_ALGORS}

  i2d_X509_ALGORS: function(a: PX509_ALGORS; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_ALGORS}

  X509_ALGORS_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM X509_ALGORS_it}

  X509_VAL_new: function: PX509_VAL; cdecl = nil;
  {$EXTERNALSYM X509_VAL_new}

  X509_VAL_free: procedure(a: PX509_VAL); cdecl = nil;
  {$EXTERNALSYM X509_VAL_free}

  d2i_X509_VAL: function(a: PPX509_VAL; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_VAL; cdecl = nil;
  {$EXTERNALSYM d2i_X509_VAL}

  i2d_X509_VAL: function(a: PX509_VAL; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_VAL}

  X509_VAL_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM X509_VAL_it}

  X509_PUBKEY_new: function: PX509_PUBKEY; cdecl = nil;
  {$EXTERNALSYM X509_PUBKEY_new}

  X509_PUBKEY_free: procedure(a: PX509_PUBKEY); cdecl = nil;
  {$EXTERNALSYM X509_PUBKEY_free}

  d2i_X509_PUBKEY: function(a: PPX509_PUBKEY; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_PUBKEY; cdecl = nil;
  {$EXTERNALSYM d2i_X509_PUBKEY}

  i2d_X509_PUBKEY: function(a: PX509_PUBKEY; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_PUBKEY}

  X509_PUBKEY_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM X509_PUBKEY_it}

  X509_PUBKEY_new_ex: function(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_PUBKEY; cdecl = nil;
  {$EXTERNALSYM X509_PUBKEY_new_ex}

  X509_PUBKEY_set: function(x: PPX509_PUBKEY; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_PUBKEY_set}

  X509_PUBKEY_get0: function(key: PX509_PUBKEY): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM X509_PUBKEY_get0}

  X509_PUBKEY_get: function(key: PX509_PUBKEY): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM X509_PUBKEY_get}

  X509_get_pubkey_parameters: function(pkey: PEVP_PKEY; chain: Pstack_st_X509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_get_pubkey_parameters}

  X509_get_pathlen: function(x: PX509): TIdC_LONG; cdecl = nil;
  {$EXTERNALSYM X509_get_pathlen}

  d2i_PUBKEY: function(a: PPEVP_PKEY; _in: PPIdAnsiChar; len: TIdC_LONG): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM d2i_PUBKEY}

  i2d_PUBKEY: function(a: PEVP_PKEY; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PUBKEY}

  d2i_PUBKEY_ex: function(a: PPEVP_PKEY; pp: PPIdAnsiChar; length: TIdC_LONG; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM d2i_PUBKEY_ex}

  d2i_RSA_PUBKEY: function(a: PPRSA; _in: PPIdAnsiChar; len: TIdC_LONG): PRSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM d2i_RSA_PUBKEY}

  i2d_RSA_PUBKEY: function(a: PRSA; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM i2d_RSA_PUBKEY}

  d2i_DSA_PUBKEY: function(a: PPDSA; _in: PPIdAnsiChar; len: TIdC_LONG): PDSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM d2i_DSA_PUBKEY}

  i2d_DSA_PUBKEY: function(a: PDSA; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM i2d_DSA_PUBKEY}

  d2i_EC_PUBKEY: function(a: PPEC_KEY; _in: PPIdAnsiChar; len: TIdC_LONG): PEC_KEY; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM d2i_EC_PUBKEY}

  i2d_EC_PUBKEY: function(a: PEC_KEY; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM i2d_EC_PUBKEY}

  X509_SIG_new: function: PX509_SIG; cdecl = nil;
  {$EXTERNALSYM X509_SIG_new}

  X509_SIG_free: procedure(a: PX509_SIG); cdecl = nil;
  {$EXTERNALSYM X509_SIG_free}

  d2i_X509_SIG: function(a: PPX509_SIG; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_SIG; cdecl = nil;
  {$EXTERNALSYM d2i_X509_SIG}

  i2d_X509_SIG: function(a: PX509_SIG; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_SIG}

  X509_SIG_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM X509_SIG_it}

  X509_SIG_get0: procedure(sig: PX509_SIG; palg: PPX509_ALGOR; pdigest: PPASN1_OCTET_STRING); cdecl = nil;
  {$EXTERNALSYM X509_SIG_get0}

  X509_SIG_getm: procedure(sig: PX509_SIG; palg: PPX509_ALGOR; pdigest: PPASN1_OCTET_STRING); cdecl = nil;
  {$EXTERNALSYM X509_SIG_getm}

  X509_REQ_INFO_new: function: PX509_REQ_INFO; cdecl = nil;
  {$EXTERNALSYM X509_REQ_INFO_new}

  X509_REQ_INFO_free: procedure(a: PX509_REQ_INFO); cdecl = nil;
  {$EXTERNALSYM X509_REQ_INFO_free}

  d2i_X509_REQ_INFO: function(a: PPX509_REQ_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_REQ_INFO; cdecl = nil;
  {$EXTERNALSYM d2i_X509_REQ_INFO}

  i2d_X509_REQ_INFO: function(a: PX509_REQ_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_REQ_INFO}

  X509_REQ_INFO_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM X509_REQ_INFO_it}

  X509_REQ_new: function: PX509_REQ; cdecl = nil;
  {$EXTERNALSYM X509_REQ_new}

  X509_REQ_free: procedure(a: PX509_REQ); cdecl = nil;
  {$EXTERNALSYM X509_REQ_free}

  d2i_X509_REQ: function(a: PPX509_REQ; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_REQ; cdecl = nil;
  {$EXTERNALSYM d2i_X509_REQ}

  i2d_X509_REQ: function(a: PX509_REQ; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_REQ}

  X509_REQ_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM X509_REQ_it}

  X509_REQ_new_ex: function(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_REQ; cdecl = nil;
  {$EXTERNALSYM X509_REQ_new_ex}

  X509_ATTRIBUTE_new: function: PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM X509_ATTRIBUTE_new}

  X509_ATTRIBUTE_free: procedure(a: PX509_ATTRIBUTE); cdecl = nil;
  {$EXTERNALSYM X509_ATTRIBUTE_free}

  d2i_X509_ATTRIBUTE: function(a: PPX509_ATTRIBUTE; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM d2i_X509_ATTRIBUTE}

  i2d_X509_ATTRIBUTE: function(a: PX509_ATTRIBUTE; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_ATTRIBUTE}

  X509_ATTRIBUTE_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM X509_ATTRIBUTE_it}

  X509_ATTRIBUTE_create: function(nid: TIdC_INT; atrtype: TIdC_INT; value: Pointer): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM X509_ATTRIBUTE_create}

  X509_EXTENSION_new: function: PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_EXTENSION_new}

  X509_EXTENSION_free: procedure(a: PX509_EXTENSION); cdecl = nil;
  {$EXTERNALSYM X509_EXTENSION_free}

  d2i_X509_EXTENSION: function(a: PPX509_EXTENSION; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM d2i_X509_EXTENSION}

  i2d_X509_EXTENSION: function(a: PX509_EXTENSION; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_EXTENSION}

  X509_EXTENSION_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM X509_EXTENSION_it}

  d2i_X509_EXTENSIONS: function(a: PPX509_EXTENSIONS; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_EXTENSIONS; cdecl = nil;
  {$EXTERNALSYM d2i_X509_EXTENSIONS}

  i2d_X509_EXTENSIONS: function(a: PX509_EXTENSIONS; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_EXTENSIONS}

  X509_EXTENSIONS_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM X509_EXTENSIONS_it}

  X509_NAME_ENTRY_new: function: PX509_NAME_ENTRY; cdecl = nil;
  {$EXTERNALSYM X509_NAME_ENTRY_new}

  X509_NAME_ENTRY_free: procedure(a: PX509_NAME_ENTRY); cdecl = nil;
  {$EXTERNALSYM X509_NAME_ENTRY_free}

  d2i_X509_NAME_ENTRY: function(a: PPX509_NAME_ENTRY; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_NAME_ENTRY; cdecl = nil;
  {$EXTERNALSYM d2i_X509_NAME_ENTRY}

  i2d_X509_NAME_ENTRY: function(a: PX509_NAME_ENTRY; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_NAME_ENTRY}

  X509_NAME_ENTRY_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM X509_NAME_ENTRY_it}

  X509_NAME_new: function: PX509_NAME; cdecl = nil;
  {$EXTERNALSYM X509_NAME_new}

  X509_NAME_free: procedure(a: PX509_NAME); cdecl = nil;
  {$EXTERNALSYM X509_NAME_free}

  d2i_X509_NAME: function(a: PPX509_NAME; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_NAME; cdecl = nil;
  {$EXTERNALSYM d2i_X509_NAME}

  i2d_X509_NAME: function(a: PX509_NAME; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_NAME}

  X509_NAME_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM X509_NAME_it}

  X509_NAME_set: function(xn: PPX509_NAME; name: PX509_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_set}

  X509_CINF_new: function: PX509_CINF; cdecl = nil;
  {$EXTERNALSYM X509_CINF_new}

  X509_CINF_free: procedure(a: PX509_CINF); cdecl = nil;
  {$EXTERNALSYM X509_CINF_free}

  d2i_X509_CINF: function(a: PPX509_CINF; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_CINF; cdecl = nil;
  {$EXTERNALSYM d2i_X509_CINF}

  i2d_X509_CINF: function(a: PX509_CINF; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_CINF}

  X509_CINF_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM X509_CINF_it}

  X509_new: function: PX509; cdecl = nil;
  {$EXTERNALSYM X509_new}

  X509_free: procedure(a: PX509); cdecl = nil;
  {$EXTERNALSYM X509_free}

  d2i_X509: function(a: PPX509; _in: PPIdAnsiChar; len: TIdC_LONG): PX509; cdecl = nil;
  {$EXTERNALSYM d2i_X509}

  i2d_X509: function(a: PX509; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509}

  X509_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM X509_it}

  X509_new_ex: function(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509; cdecl = nil;
  {$EXTERNALSYM X509_new_ex}

  X509_CERT_AUX_new: function: PX509_CERT_AUX; cdecl = nil;
  {$EXTERNALSYM X509_CERT_AUX_new}

  X509_CERT_AUX_free: procedure(a: PX509_CERT_AUX); cdecl = nil;
  {$EXTERNALSYM X509_CERT_AUX_free}

  d2i_X509_CERT_AUX: function(a: PPX509_CERT_AUX; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_CERT_AUX; cdecl = nil;
  {$EXTERNALSYM d2i_X509_CERT_AUX}

  i2d_X509_CERT_AUX: function(a: PX509_CERT_AUX; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_CERT_AUX}

  X509_CERT_AUX_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM X509_CERT_AUX_it}

  X509_set_ex_data: function(r: PX509; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_set_ex_data}

  X509_get_ex_data: function(r: PX509; idx: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM X509_get_ex_data}

  d2i_X509_AUX: function(a: PPX509; _in: PPIdAnsiChar; len: TIdC_LONG): PX509; cdecl = nil;
  {$EXTERNALSYM d2i_X509_AUX}

  i2d_X509_AUX: function(a: PX509; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_AUX}

  i2d_re_X509_tbs: function(x: PX509; pp: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_re_X509_tbs}

  X509_SIG_INFO_get: function(siginf: PX509_SIG_INFO; mdnid: PIdC_INT; pknid: PIdC_INT; secbits: PIdC_INT; flags: PIdC_UINT32): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_SIG_INFO_get}

  X509_SIG_INFO_set: procedure(siginf: PX509_SIG_INFO; mdnid: TIdC_INT; pknid: TIdC_INT; secbits: TIdC_INT; flags: TIdC_UINT32); cdecl = nil;
  {$EXTERNALSYM X509_SIG_INFO_set}

  X509_get_signature_info: function(x: PX509; mdnid: PIdC_INT; pknid: PIdC_INT; secbits: PIdC_INT; flags: PIdC_UINT32): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_get_signature_info}

  X509_get0_signature: procedure(psig: PPASN1_BIT_STRING; palg: PPX509_ALGOR; x: PX509); cdecl = nil;
  {$EXTERNALSYM X509_get0_signature}

  X509_get_signature_nid: function(x: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_get_signature_nid}

  X509_set0_distinguishing_id: procedure(x: PX509; d_id: PASN1_OCTET_STRING); cdecl = nil;
  {$EXTERNALSYM X509_set0_distinguishing_id}

  X509_get0_distinguishing_id: function(x: PX509): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM X509_get0_distinguishing_id}

  X509_REQ_set0_distinguishing_id: procedure(x: PX509_REQ; d_id: PASN1_OCTET_STRING); cdecl = nil;
  {$EXTERNALSYM X509_REQ_set0_distinguishing_id}

  X509_REQ_get0_distinguishing_id: function(x: PX509_REQ): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM X509_REQ_get0_distinguishing_id}

  X509_alias_set1: function(x: PX509; name: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_alias_set1}

  X509_keyid_set1: function(x: PX509; id: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_keyid_set1}

  X509_alias_get0: function(x: PX509; len: PIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_alias_get0}

  X509_keyid_get0: function(x: PX509; len: PIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_keyid_get0}

  X509_REVOKED_new: function: PX509_REVOKED; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_new}

  X509_REVOKED_free: procedure(a: PX509_REVOKED); cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_free}

  d2i_X509_REVOKED: function(a: PPX509_REVOKED; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_REVOKED; cdecl = nil;
  {$EXTERNALSYM d2i_X509_REVOKED}

  i2d_X509_REVOKED: function(a: PX509_REVOKED; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_REVOKED}

  X509_REVOKED_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_it}

  X509_CRL_INFO_new: function: PX509_CRL_INFO; cdecl = nil;
  {$EXTERNALSYM X509_CRL_INFO_new}

  X509_CRL_INFO_free: procedure(a: PX509_CRL_INFO); cdecl = nil;
  {$EXTERNALSYM X509_CRL_INFO_free}

  d2i_X509_CRL_INFO: function(a: PPX509_CRL_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_CRL_INFO; cdecl = nil;
  {$EXTERNALSYM d2i_X509_CRL_INFO}

  i2d_X509_CRL_INFO: function(a: PX509_CRL_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_CRL_INFO}

  X509_CRL_INFO_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM X509_CRL_INFO_it}

  X509_CRL_new: function: PX509_CRL; cdecl = nil;
  {$EXTERNALSYM X509_CRL_new}

  X509_CRL_free: procedure(a: PX509_CRL); cdecl = nil;
  {$EXTERNALSYM X509_CRL_free}

  d2i_X509_CRL: function(a: PPX509_CRL; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_CRL; cdecl = nil;
  {$EXTERNALSYM d2i_X509_CRL}

  i2d_X509_CRL: function(a: PX509_CRL; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_CRL}

  X509_CRL_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM X509_CRL_it}

  X509_CRL_new_ex: function(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_CRL; cdecl = nil;
  {$EXTERNALSYM X509_CRL_new_ex}

  X509_CRL_add0_revoked: function(crl: PX509_CRL; rev: PX509_REVOKED): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_add0_revoked}

  X509_CRL_get0_by_serial: function(crl: PX509_CRL; ret: PPX509_REVOKED; serial: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get0_by_serial}

  X509_CRL_get0_by_cert: function(crl: PX509_CRL; ret: PPX509_REVOKED; x: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get0_by_cert}

  X509_PKEY_new: function: PX509_PKEY; cdecl = nil;
  {$EXTERNALSYM X509_PKEY_new}

  X509_PKEY_free: procedure(a: PX509_PKEY); cdecl = nil;
  {$EXTERNALSYM X509_PKEY_free}

  NETSCAPE_SPKI_new: function: PNETSCAPE_SPKI; cdecl = nil;
  {$EXTERNALSYM NETSCAPE_SPKI_new}

  NETSCAPE_SPKI_free: procedure(a: PNETSCAPE_SPKI); cdecl = nil;
  {$EXTERNALSYM NETSCAPE_SPKI_free}

  d2i_NETSCAPE_SPKI: function(a: PPNETSCAPE_SPKI; _in: PPIdAnsiChar; len: TIdC_LONG): PNETSCAPE_SPKI; cdecl = nil;
  {$EXTERNALSYM d2i_NETSCAPE_SPKI}

  i2d_NETSCAPE_SPKI: function(a: PNETSCAPE_SPKI; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_NETSCAPE_SPKI}

  NETSCAPE_SPKI_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM NETSCAPE_SPKI_it}

  NETSCAPE_SPKAC_new: function: PNETSCAPE_SPKAC; cdecl = nil;
  {$EXTERNALSYM NETSCAPE_SPKAC_new}

  NETSCAPE_SPKAC_free: procedure(a: PNETSCAPE_SPKAC); cdecl = nil;
  {$EXTERNALSYM NETSCAPE_SPKAC_free}

  d2i_NETSCAPE_SPKAC: function(a: PPNETSCAPE_SPKAC; _in: PPIdAnsiChar; len: TIdC_LONG): PNETSCAPE_SPKAC; cdecl = nil;
  {$EXTERNALSYM d2i_NETSCAPE_SPKAC}

  i2d_NETSCAPE_SPKAC: function(a: PNETSCAPE_SPKAC; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_NETSCAPE_SPKAC}

  NETSCAPE_SPKAC_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM NETSCAPE_SPKAC_it}

  NETSCAPE_CERT_SEQUENCE_new: function: PNETSCAPE_CERT_SEQUENCE; cdecl = nil;
  {$EXTERNALSYM NETSCAPE_CERT_SEQUENCE_new}

  NETSCAPE_CERT_SEQUENCE_free: procedure(a: PNETSCAPE_CERT_SEQUENCE); cdecl = nil;
  {$EXTERNALSYM NETSCAPE_CERT_SEQUENCE_free}

  d2i_NETSCAPE_CERT_SEQUENCE: function(a: PPNETSCAPE_CERT_SEQUENCE; _in: PPIdAnsiChar; len: TIdC_LONG): PNETSCAPE_CERT_SEQUENCE; cdecl = nil;
  {$EXTERNALSYM d2i_NETSCAPE_CERT_SEQUENCE}

  i2d_NETSCAPE_CERT_SEQUENCE: function(a: PNETSCAPE_CERT_SEQUENCE; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_NETSCAPE_CERT_SEQUENCE}

  NETSCAPE_CERT_SEQUENCE_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM NETSCAPE_CERT_SEQUENCE_it}

  X509_INFO_new: function: PX509_INFO; cdecl = nil;
  {$EXTERNALSYM X509_INFO_new}

  X509_INFO_free: procedure(a: PX509_INFO); cdecl = nil;
  {$EXTERNALSYM X509_INFO_free}

  X509_NAME_oneline: function(a: PX509_NAME; buf: PIdAnsiChar; size: TIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_NAME_oneline}

  ASN1_verify: function(i2d: TASN1_verify_i2d_cb; algor1: PX509_ALGOR; signature: PASN1_BIT_STRING; data: PIdAnsiChar; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ASN1_verify}

  ASN1_digest: function(i2d: TASN1_verify_i2d_cb; _type: PEVP_MD; data: PIdAnsiChar; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ASN1_digest}

  ASN1_sign: function(i2d: TASN1_verify_i2d_cb; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: PIdAnsiChar; pkey: PEVP_PKEY; _type: PEVP_MD): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM ASN1_sign}

  ASN1_item_digest: function(it: PASN1_ITEM; _type: PEVP_MD; data: Pointer; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_item_digest}

  ASN1_item_verify: function(it: PASN1_ITEM; alg: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_item_verify}

  ASN1_item_verify_ctx: function(it: PASN1_ITEM; alg: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; ctx: PEVP_MD_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_item_verify_ctx}

  ASN1_item_sign: function(it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY; md: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_item_sign}

  ASN1_item_sign_ctx: function(it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; ctx: PEVP_MD_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM ASN1_item_sign_ctx}

  X509_get_version: function(x: PX509): TIdC_LONG; cdecl = nil;
  {$EXTERNALSYM X509_get_version}

  X509_set_version: function(x: PX509; version: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_set_version}

  X509_set_serialNumber: function(x: PX509; serial: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_set_serialNumber}

  X509_get_serialNumber: function(x: PX509): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM X509_get_serialNumber}

  X509_get0_serialNumber: function(x: PX509): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM X509_get0_serialNumber}

  X509_set_issuer_name: function(x: PX509; name: PX509_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_set_issuer_name}

  X509_get_issuer_name: function(a: PX509): PX509_NAME; cdecl = nil;
  {$EXTERNALSYM X509_get_issuer_name}

  X509_set_subject_name: function(x: PX509; name: PX509_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_set_subject_name}

  X509_get_subject_name: function(a: PX509): PX509_NAME; cdecl = nil;
  {$EXTERNALSYM X509_get_subject_name}

  X509_get0_notBefore: function(x: PX509): PASN1_TIME; cdecl = nil;
  {$EXTERNALSYM X509_get0_notBefore}

  X509_getm_notBefore: function(x: PX509): PASN1_TIME; cdecl = nil;
  {$EXTERNALSYM X509_getm_notBefore}

  X509_set1_notBefore: function(x: PX509; tm: PASN1_TIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_set1_notBefore}

  X509_get0_notAfter: function(x: PX509): PASN1_TIME; cdecl = nil;
  {$EXTERNALSYM X509_get0_notAfter}

  X509_getm_notAfter: function(x: PX509): PASN1_TIME; cdecl = nil;
  {$EXTERNALSYM X509_getm_notAfter}

  X509_set1_notAfter: function(x: PX509; tm: PASN1_TIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_set1_notAfter}

  X509_set_pubkey: function(x: PX509; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_set_pubkey}

  X509_up_ref: function(x: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_up_ref}

  X509_get_signature_type: function(x: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_get_signature_type}

  X509_get_X509_PUBKEY: function(x: PX509): PX509_PUBKEY; cdecl = nil;
  {$EXTERNALSYM X509_get_X509_PUBKEY}

  X509_get0_extensions: function(x: PX509): Pstack_st_X509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_get0_extensions}

  X509_get0_uids: procedure(x: PX509; piuid: PPASN1_BIT_STRING; psuid: PPASN1_BIT_STRING); cdecl = nil;
  {$EXTERNALSYM X509_get0_uids}

  X509_get0_tbs_sigalg: function(x: PX509): PX509_ALGOR; cdecl = nil;
  {$EXTERNALSYM X509_get0_tbs_sigalg}

  X509_get0_pubkey: function(x: PX509): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM X509_get0_pubkey}

  X509_get_pubkey: function(x: PX509): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM X509_get_pubkey}

  X509_get0_pubkey_bitstr: function(x: PX509): PASN1_BIT_STRING; cdecl = nil;
  {$EXTERNALSYM X509_get0_pubkey_bitstr}

  X509_REQ_get_version: function(req: PX509_REQ): TIdC_LONG; cdecl = nil;
  {$EXTERNALSYM X509_REQ_get_version}

  X509_REQ_set_version: function(x: PX509_REQ; version: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_set_version}

  X509_REQ_get_subject_name: function(req: PX509_REQ): PX509_NAME; cdecl = nil;
  {$EXTERNALSYM X509_REQ_get_subject_name}

  X509_REQ_set_subject_name: function(req: PX509_REQ; name: PX509_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_set_subject_name}

  X509_REQ_get0_signature: procedure(req: PX509_REQ; psig: PPASN1_BIT_STRING; palg: PPX509_ALGOR); cdecl = nil;
  {$EXTERNALSYM X509_REQ_get0_signature}

  X509_REQ_set0_signature: procedure(req: PX509_REQ; psig: PASN1_BIT_STRING); cdecl = nil;
  {$EXTERNALSYM X509_REQ_set0_signature}

  X509_REQ_set1_signature_algo: function(req: PX509_REQ; palg: PX509_ALGOR): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_set1_signature_algo}

  X509_REQ_get_signature_nid: function(req: PX509_REQ): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_get_signature_nid}

  i2d_re_X509_REQ_tbs: function(req: PX509_REQ; pp: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_re_X509_REQ_tbs}

  X509_REQ_set_pubkey: function(x: PX509_REQ; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_set_pubkey}

  X509_REQ_get_pubkey: function(req: PX509_REQ): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM X509_REQ_get_pubkey}

  X509_REQ_get0_pubkey: function(req: PX509_REQ): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM X509_REQ_get0_pubkey}

  X509_REQ_get_X509_PUBKEY: function(req: PX509_REQ): PX509_PUBKEY; cdecl = nil;
  {$EXTERNALSYM X509_REQ_get_X509_PUBKEY}

  X509_REQ_extension_nid: function(nid: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_extension_nid}

  X509_REQ_get_extension_nids: function: PIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_get_extension_nids}

  X509_REQ_set_extension_nids: procedure(nids: PIdC_INT); cdecl = nil;
  {$EXTERNALSYM X509_REQ_set_extension_nids}

  X509_REQ_get_extensions: function(req: PX509_REQ): Pstack_st_X509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_REQ_get_extensions}

  X509_REQ_add_extensions_nid: function(req: PX509_REQ; exts: Pstack_st_X509_EXTENSION; nid: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_add_extensions_nid}

  X509_REQ_add_extensions: function(req: PX509_REQ; ext: Pstack_st_X509_EXTENSION): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_add_extensions}

  X509_REQ_get_attr_count: function(req: PX509_REQ): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_get_attr_count}

  X509_REQ_get_attr_by_NID: function(req: PX509_REQ; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_get_attr_by_NID}

  X509_REQ_get_attr_by_OBJ: function(req: PX509_REQ; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_get_attr_by_OBJ}

  X509_REQ_get_attr: function(req: PX509_REQ; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM X509_REQ_get_attr}

  X509_REQ_delete_attr: function(req: PX509_REQ; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM X509_REQ_delete_attr}

  X509_REQ_add1_attr: function(req: PX509_REQ; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_add1_attr}

  X509_REQ_add1_attr_by_OBJ: function(req: PX509_REQ; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_add1_attr_by_OBJ}

  X509_REQ_add1_attr_by_NID: function(req: PX509_REQ; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_add1_attr_by_NID}

  X509_REQ_add1_attr_by_txt: function(req: PX509_REQ; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_add1_attr_by_txt}

  X509_CRL_set_version: function(x: PX509_CRL; version: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_set_version}

  X509_CRL_set_issuer_name: function(x: PX509_CRL; name: PX509_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_set_issuer_name}

  X509_CRL_set1_lastUpdate: function(x: PX509_CRL; tm: PASN1_TIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_set1_lastUpdate}

  X509_CRL_set1_nextUpdate: function(x: PX509_CRL; tm: PASN1_TIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_set1_nextUpdate}

  X509_CRL_sort: function(crl: PX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_sort}

  X509_CRL_up_ref: function(crl: PX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_up_ref}

  X509_CRL_get_version: function(crl: PX509_CRL): TIdC_LONG; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get_version}

  X509_CRL_get0_lastUpdate: function(crl: PX509_CRL): PASN1_TIME; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get0_lastUpdate}

  X509_CRL_get0_nextUpdate: function(crl: PX509_CRL): PASN1_TIME; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get0_nextUpdate}

  X509_CRL_get_issuer: function(crl: PX509_CRL): PX509_NAME; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get_issuer}

  X509_CRL_get0_extensions: function(crl: PX509_CRL): Pstack_st_X509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get0_extensions}

  X509_CRL_get_REVOKED: function(crl: PX509_CRL): Pstack_st_X509_REVOKED; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get_REVOKED}

  X509_CRL_get0_tbs_sigalg: function(crl: PX509_CRL): PX509_ALGOR; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get0_tbs_sigalg}

  X509_CRL_get0_signature: procedure(crl: PX509_CRL; psig: PPASN1_BIT_STRING; palg: PPX509_ALGOR); cdecl = nil;
  {$EXTERNALSYM X509_CRL_get0_signature}

  X509_CRL_get_signature_nid: function(crl: PX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get_signature_nid}

  i2d_re_X509_CRL_tbs: function(req: PX509_CRL; pp: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_re_X509_CRL_tbs}

  X509_REVOKED_get0_serialNumber: function(x: PX509_REVOKED): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_get0_serialNumber}

  X509_REVOKED_set_serialNumber: function(x: PX509_REVOKED; serial: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_set_serialNumber}

  X509_REVOKED_get0_revocationDate: function(x: PX509_REVOKED): PASN1_TIME; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_get0_revocationDate}

  X509_REVOKED_set_revocationDate: function(r: PX509_REVOKED; tm: PASN1_TIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_set_revocationDate}

  X509_REVOKED_get0_extensions: function(r: PX509_REVOKED): Pstack_st_X509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_get0_extensions}

  X509_CRL_diff: function(base: PX509_CRL; newer: PX509_CRL; skey: PEVP_PKEY; md: PEVP_MD; flags: TIdC_UINT): PX509_CRL; cdecl = nil;
  {$EXTERNALSYM X509_CRL_diff}

  X509_REQ_check_private_key: function(req: PX509_REQ; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_check_private_key}

  X509_check_private_key: function(cert: PX509; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_check_private_key}

  X509_chain_check_suiteb: function(perror_depth: PIdC_INT; x: PX509; chain: Pstack_st_X509; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_chain_check_suiteb}

  X509_CRL_check_suiteb: function(crl: PX509_CRL; pk: PEVP_PKEY; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_check_suiteb}

  OSSL_STACK_OF_X509_free: procedure(certs: Pstack_st_X509); cdecl = nil;
  {$EXTERNALSYM OSSL_STACK_OF_X509_free}

  X509_chain_up_ref: function(chain: Pstack_st_X509): Pstack_st_X509; cdecl = nil;
  {$EXTERNALSYM X509_chain_up_ref}

  X509_issuer_and_serial_cmp: function(a: PX509; b: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_issuer_and_serial_cmp}

  X509_issuer_and_serial_hash: function(a: PX509): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM X509_issuer_and_serial_hash}

  X509_issuer_name_cmp: function(a: PX509; b: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_issuer_name_cmp}

  X509_issuer_name_hash: function(a: PX509): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM X509_issuer_name_hash}

  X509_subject_name_cmp: function(a: PX509; b: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_subject_name_cmp}

  X509_subject_name_hash: function(x: PX509): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM X509_subject_name_hash}

  X509_issuer_name_hash_old: function(a: PX509): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM X509_issuer_name_hash_old}

  X509_subject_name_hash_old: function(x: PX509): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM X509_subject_name_hash_old}

  X509_add_cert: function(sk: Pstack_st_X509; cert: PX509; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_add_cert}

  X509_add_certs: function(sk: Pstack_st_X509; certs: Pstack_st_X509; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_add_certs}

  X509_cmp: function(a: PX509; b: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_cmp}

  X509_NAME_cmp: function(a: PX509_NAME; b: PX509_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_cmp}

  X509_certificate_type: function(x: PX509; pubkey: PEVP_PKEY): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM X509_certificate_type}

  X509_NAME_hash_ex: function(x: PX509_NAME; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; ok: PIdC_INT): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM X509_NAME_hash_ex}

  X509_NAME_hash_old: function(x: PX509_NAME): TIdC_ULONG; cdecl = nil;
  {$EXTERNALSYM X509_NAME_hash_old}

  X509_CRL_cmp: function(a: PX509_CRL; b: PX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_cmp}

  X509_CRL_match: function(a: PX509_CRL; b: PX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_match}

  X509_aux_print: function(_out: PBIO; x: PX509; indent: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_aux_print}

  X509_print_ex_fp: function(bp: PFILE; x: PX509; nmflag: TIdC_ULONG; cflag: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_print_ex_fp}

  X509_print_fp: function(bp: PFILE; x: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_print_fp}

  X509_CRL_print_fp: function(bp: PFILE; x: PX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_print_fp}

  X509_REQ_print_fp: function(bp: PFILE; req: PX509_REQ): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_print_fp}

  X509_NAME_print_ex_fp: function(fp: PFILE; nm: PX509_NAME; indent: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_print_ex_fp}

  X509_NAME_print: function(bp: PBIO; name: PX509_NAME; obase: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_print}

  X509_NAME_print_ex: function(_out: PBIO; nm: PX509_NAME; indent: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_print_ex}

  X509_print_ex: function(bp: PBIO; x: PX509; nmflag: TIdC_ULONG; cflag: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_print_ex}

  X509_print: function(bp: PBIO; x: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_print}

  X509_ocspid_print: function(bp: PBIO; x: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ocspid_print}

  X509_CRL_print_ex: function(_out: PBIO; x: PX509_CRL; nmflag: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_print_ex}

  X509_CRL_print: function(bp: PBIO; x: PX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_print}

  X509_REQ_print_ex: function(bp: PBIO; x: PX509_REQ; nmflag: TIdC_ULONG; cflag: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_print_ex}

  X509_REQ_print: function(bp: PBIO; req: PX509_REQ): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REQ_print}

  X509_NAME_entry_count: function(name: PX509_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_entry_count}

  X509_NAME_get_text_by_NID: function(name: PX509_NAME; nid: TIdC_INT; buf: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_get_text_by_NID}

  X509_NAME_get_text_by_OBJ: function(name: PX509_NAME; obj: PASN1_OBJECT; buf: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_get_text_by_OBJ}

  X509_NAME_get_index_by_NID: function(name: PX509_NAME; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_get_index_by_NID}

  X509_NAME_get_index_by_OBJ: function(name: PX509_NAME; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_get_index_by_OBJ}

  X509_NAME_get_entry: function(name: PX509_NAME; loc: TIdC_INT): PX509_NAME_ENTRY; cdecl = nil;
  {$EXTERNALSYM X509_NAME_get_entry}

  X509_NAME_delete_entry: function(name: PX509_NAME; loc: TIdC_INT): PX509_NAME_ENTRY; cdecl = nil;
  {$EXTERNALSYM X509_NAME_delete_entry}

  X509_NAME_add_entry: function(name: PX509_NAME; ne: PX509_NAME_ENTRY; loc: TIdC_INT; _set: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_add_entry}

  X509_NAME_add_entry_by_OBJ: function(name: PX509_NAME; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT; loc: TIdC_INT; _set: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_add_entry_by_OBJ}

  X509_NAME_add_entry_by_NID: function(name: PX509_NAME; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT; loc: TIdC_INT; _set: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_add_entry_by_NID}

  X509_NAME_ENTRY_create_by_txt: function(ne: PPX509_NAME_ENTRY; field: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): PX509_NAME_ENTRY; cdecl = nil;
  {$EXTERNALSYM X509_NAME_ENTRY_create_by_txt}

  X509_NAME_ENTRY_create_by_NID: function(ne: PPX509_NAME_ENTRY; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): PX509_NAME_ENTRY; cdecl = nil;
  {$EXTERNALSYM X509_NAME_ENTRY_create_by_NID}

  X509_NAME_add_entry_by_txt: function(name: PX509_NAME; field: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT; loc: TIdC_INT; _set: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_add_entry_by_txt}

  X509_NAME_ENTRY_create_by_OBJ: function(ne: PPX509_NAME_ENTRY; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): PX509_NAME_ENTRY; cdecl = nil;
  {$EXTERNALSYM X509_NAME_ENTRY_create_by_OBJ}

  X509_NAME_ENTRY_set_object: function(ne: PX509_NAME_ENTRY; obj: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_ENTRY_set_object}

  X509_NAME_ENTRY_set_data: function(ne: PX509_NAME_ENTRY; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_ENTRY_set_data}

  X509_NAME_ENTRY_get_object: function(ne: PX509_NAME_ENTRY): PASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_ENTRY_get_object}

  X509_NAME_ENTRY_get_data: function(ne: PX509_NAME_ENTRY): PASN1_STRING; cdecl = nil;
  {$EXTERNALSYM X509_NAME_ENTRY_get_data}

  X509_NAME_ENTRY_set: function(ne: PX509_NAME_ENTRY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_ENTRY_set}

  X509_NAME_get0_der: function(nm: PX509_NAME; pder: PPIdAnsiChar; pderlen: PIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_NAME_get0_der}

  X509v3_get_ext_count: function(x: Pstack_st_X509_EXTENSION): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509v3_get_ext_count}

  X509v3_get_ext_by_NID: function(x: Pstack_st_X509_EXTENSION; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509v3_get_ext_by_NID}

  X509v3_get_ext_by_OBJ: function(x: Pstack_st_X509_EXTENSION; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509v3_get_ext_by_OBJ}

  X509v3_get_ext_by_critical: function(x: Pstack_st_X509_EXTENSION; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509v3_get_ext_by_critical}

  X509v3_get_ext: function(x: Pstack_st_X509_EXTENSION; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509v3_get_ext}

  X509v3_delete_ext: function(x: Pstack_st_X509_EXTENSION; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509v3_delete_ext}

  X509v3_add_ext: function(x: PPstack_st_X509_EXTENSION; ex: PX509_EXTENSION; loc: TIdC_INT): Pstack_st_X509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509v3_add_ext}

  X509v3_add_extensions: function(target: PPstack_st_X509_EXTENSION; exts: Pstack_st_X509_EXTENSION): Pstack_st_X509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509v3_add_extensions}

  X509_get_ext_count: function(x: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_get_ext_count}

  X509_get_ext_by_NID: function(x: PX509; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_get_ext_by_NID}

  X509_get_ext_by_OBJ: function(x: PX509; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_get_ext_by_OBJ}

  X509_get_ext_by_critical: function(x: PX509; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_get_ext_by_critical}

  X509_get_ext: function(x: PX509; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_get_ext}

  X509_delete_ext: function(x: PX509; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_delete_ext}

  X509_add_ext: function(x: PX509; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_add_ext}

  X509_get_ext_d2i: function(x: PX509; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM X509_get_ext_d2i}

  X509_add1_ext_i2d: function(x: PX509; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_add1_ext_i2d}

  X509_CRL_get_ext_count: function(x: PX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get_ext_count}

  X509_CRL_get_ext_by_NID: function(x: PX509_CRL; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get_ext_by_NID}

  X509_CRL_get_ext_by_OBJ: function(x: PX509_CRL; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get_ext_by_OBJ}

  X509_CRL_get_ext_by_critical: function(x: PX509_CRL; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get_ext_by_critical}

  X509_CRL_get_ext: function(x: PX509_CRL; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get_ext}

  X509_CRL_delete_ext: function(x: PX509_CRL; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_CRL_delete_ext}

  X509_CRL_add_ext: function(x: PX509_CRL; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_add_ext}

  X509_CRL_get_ext_d2i: function(x: PX509_CRL; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM X509_CRL_get_ext_d2i}

  X509_CRL_add1_ext_i2d: function(x: PX509_CRL; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_CRL_add1_ext_i2d}

  X509_REVOKED_get_ext_count: function(x: PX509_REVOKED): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_get_ext_count}

  X509_REVOKED_get_ext_by_NID: function(x: PX509_REVOKED; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_get_ext_by_NID}

  X509_REVOKED_get_ext_by_OBJ: function(x: PX509_REVOKED; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_get_ext_by_OBJ}

  X509_REVOKED_get_ext_by_critical: function(x: PX509_REVOKED; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_get_ext_by_critical}

  X509_REVOKED_get_ext: function(x: PX509_REVOKED; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_get_ext}

  X509_REVOKED_delete_ext: function(x: PX509_REVOKED; loc: TIdC_INT): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_delete_ext}

  X509_REVOKED_add_ext: function(x: PX509_REVOKED; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_add_ext}

  X509_REVOKED_get_ext_d2i: function(x: PX509_REVOKED; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_get_ext_d2i}

  X509_REVOKED_add1_ext_i2d: function(x: PX509_REVOKED; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_REVOKED_add1_ext_i2d}

  X509_EXTENSION_create_by_NID: function(ex: PPX509_EXTENSION; nid: TIdC_INT; crit: TIdC_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_EXTENSION_create_by_NID}

  X509_EXTENSION_create_by_OBJ: function(ex: PPX509_EXTENSION; obj: PASN1_OBJECT; crit: TIdC_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_EXTENSION_create_by_OBJ}

  X509_EXTENSION_set_object: function(ex: PX509_EXTENSION; obj: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_EXTENSION_set_object}

  X509_EXTENSION_set_critical: function(ex: PX509_EXTENSION; crit: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_EXTENSION_set_critical}

  X509_EXTENSION_set_data: function(ex: PX509_EXTENSION; data: PASN1_OCTET_STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_EXTENSION_set_data}

  X509_EXTENSION_get_object: function(ex: PX509_EXTENSION): PASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM X509_EXTENSION_get_object}

  X509_EXTENSION_get_data: function(ne: PX509_EXTENSION): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM X509_EXTENSION_get_data}

  X509_EXTENSION_get_critical: function(ex: PX509_EXTENSION): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_EXTENSION_get_critical}

  X509at_get_attr_count: function(x: Pstack_st_X509_ATTRIBUTE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509at_get_attr_count}

  X509at_get_attr_by_NID: function(x: Pstack_st_X509_ATTRIBUTE; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509at_get_attr_by_NID}

  X509at_get_attr_by_OBJ: function(sk: Pstack_st_X509_ATTRIBUTE; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509at_get_attr_by_OBJ}

  X509at_get_attr: function(x: Pstack_st_X509_ATTRIBUTE; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM X509at_get_attr}

  X509at_delete_attr: function(x: Pstack_st_X509_ATTRIBUTE; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM X509at_delete_attr}

  X509at_add1_attr: function(x: PPstack_st_X509_ATTRIBUTE; attr: PX509_ATTRIBUTE): Pstack_st_X509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM X509at_add1_attr}

  X509at_add1_attr_by_OBJ: function(x: PPstack_st_X509_ATTRIBUTE; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): Pstack_st_X509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM X509at_add1_attr_by_OBJ}

  X509at_add1_attr_by_NID: function(x: PPstack_st_X509_ATTRIBUTE; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): Pstack_st_X509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM X509at_add1_attr_by_NID}

  X509at_add1_attr_by_txt: function(x: PPstack_st_X509_ATTRIBUTE; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): Pstack_st_X509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM X509at_add1_attr_by_txt}

  X509at_get0_data_by_OBJ: function(x: Pstack_st_X509_ATTRIBUTE; obj: PASN1_OBJECT; lastpos: TIdC_INT; _type: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM X509at_get0_data_by_OBJ}

  X509_ATTRIBUTE_create_by_NID: function(attr: PPX509_ATTRIBUTE; nid: TIdC_INT; atrtype: TIdC_INT; data: Pointer; len: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM X509_ATTRIBUTE_create_by_NID}

  X509_ATTRIBUTE_create_by_OBJ: function(attr: PPX509_ATTRIBUTE; obj: PASN1_OBJECT; atrtype: TIdC_INT; data: Pointer; len: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM X509_ATTRIBUTE_create_by_OBJ}

  X509_ATTRIBUTE_create_by_txt: function(attr: PPX509_ATTRIBUTE; atrname: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM X509_ATTRIBUTE_create_by_txt}

  X509_ATTRIBUTE_set1_object: function(attr: PX509_ATTRIBUTE; obj: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ATTRIBUTE_set1_object}

  X509_ATTRIBUTE_set1_data: function(attr: PX509_ATTRIBUTE; attrtype: TIdC_INT; data: Pointer; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ATTRIBUTE_set1_data}

  X509_ATTRIBUTE_get0_data: function(attr: PX509_ATTRIBUTE; idx: TIdC_INT; atrtype: TIdC_INT; data: Pointer): Pointer; cdecl = nil;
  {$EXTERNALSYM X509_ATTRIBUTE_get0_data}

  X509_ATTRIBUTE_count: function(attr: PX509_ATTRIBUTE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ATTRIBUTE_count}

  X509_ATTRIBUTE_get0_object: function(attr: PX509_ATTRIBUTE): PASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM X509_ATTRIBUTE_get0_object}

  X509_ATTRIBUTE_get0_type: function(attr: PX509_ATTRIBUTE; idx: TIdC_INT): PASN1_TYPE; cdecl = nil;
  {$EXTERNALSYM X509_ATTRIBUTE_get0_type}

  EVP_PKEY_get_attr_count: function(key: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_get_attr_count}

  EVP_PKEY_get_attr_by_NID: function(key: PEVP_PKEY; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_get_attr_by_NID}

  EVP_PKEY_get_attr_by_OBJ: function(key: PEVP_PKEY; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_get_attr_by_OBJ}

  EVP_PKEY_get_attr: function(key: PEVP_PKEY; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_get_attr}

  EVP_PKEY_delete_attr: function(key: PEVP_PKEY; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_delete_attr}

  EVP_PKEY_add1_attr: function(key: PEVP_PKEY; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_add1_attr}

  EVP_PKEY_add1_attr_by_OBJ: function(key: PEVP_PKEY; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_add1_attr_by_OBJ}

  EVP_PKEY_add1_attr_by_NID: function(key: PEVP_PKEY; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_add1_attr_by_NID}

  EVP_PKEY_add1_attr_by_txt: function(key: PEVP_PKEY; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY_add1_attr_by_txt}

  X509_find_by_issuer_and_serial: function(sk: Pstack_st_X509; name: PX509_NAME; serial: PASN1_INTEGER): PX509; cdecl = nil;
  {$EXTERNALSYM X509_find_by_issuer_and_serial}

  X509_find_by_subject: function(sk: Pstack_st_X509; name: PX509_NAME): PX509; cdecl = nil;
  {$EXTERNALSYM X509_find_by_subject}

  PBEPARAM_new: function: PPBEPARAM; cdecl = nil;
  {$EXTERNALSYM PBEPARAM_new}

  PBEPARAM_free: procedure(a: PPBEPARAM); cdecl = nil;
  {$EXTERNALSYM PBEPARAM_free}

  d2i_PBEPARAM: function(a: PPPBEPARAM; _in: PPIdAnsiChar; len: TIdC_LONG): PPBEPARAM; cdecl = nil;
  {$EXTERNALSYM d2i_PBEPARAM}

  i2d_PBEPARAM: function(a: PPBEPARAM; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PBEPARAM}

  PBEPARAM_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PBEPARAM_it}

  PBE2PARAM_new: function: PPBE2PARAM; cdecl = nil;
  {$EXTERNALSYM PBE2PARAM_new}

  PBE2PARAM_free: procedure(a: PPBE2PARAM); cdecl = nil;
  {$EXTERNALSYM PBE2PARAM_free}

  d2i_PBE2PARAM: function(a: PPPBE2PARAM; _in: PPIdAnsiChar; len: TIdC_LONG): PPBE2PARAM; cdecl = nil;
  {$EXTERNALSYM d2i_PBE2PARAM}

  i2d_PBE2PARAM: function(a: PPBE2PARAM; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PBE2PARAM}

  PBE2PARAM_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PBE2PARAM_it}

  PBKDF2PARAM_new: function: PPBKDF2PARAM; cdecl = nil;
  {$EXTERNALSYM PBKDF2PARAM_new}

  PBKDF2PARAM_free: procedure(a: PPBKDF2PARAM); cdecl = nil;
  {$EXTERNALSYM PBKDF2PARAM_free}

  d2i_PBKDF2PARAM: function(a: PPPBKDF2PARAM; _in: PPIdAnsiChar; len: TIdC_LONG): PPBKDF2PARAM; cdecl = nil;
  {$EXTERNALSYM d2i_PBKDF2PARAM}

  i2d_PBKDF2PARAM: function(a: PPBKDF2PARAM; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PBKDF2PARAM}

  PBKDF2PARAM_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PBKDF2PARAM_it}

  PBMAC1PARAM_new: function: PPBMAC1PARAM; cdecl = nil;
  {$EXTERNALSYM PBMAC1PARAM_new}

  PBMAC1PARAM_free: procedure(a: PPBMAC1PARAM); cdecl = nil;
  {$EXTERNALSYM PBMAC1PARAM_free}

  d2i_PBMAC1PARAM: function(a: PPPBMAC1PARAM; _in: PPIdAnsiChar; len: TIdC_LONG): PPBMAC1PARAM; cdecl = nil;
  {$EXTERNALSYM d2i_PBMAC1PARAM}

  i2d_PBMAC1PARAM: function(a: PPBMAC1PARAM; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PBMAC1PARAM}

  PBMAC1PARAM_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PBMAC1PARAM_it}

  SCRYPT_PARAMS_new: function: PSCRYPT_PARAMS; cdecl = nil;
  {$EXTERNALSYM SCRYPT_PARAMS_new}

  SCRYPT_PARAMS_free: procedure(a: PSCRYPT_PARAMS); cdecl = nil;
  {$EXTERNALSYM SCRYPT_PARAMS_free}

  d2i_SCRYPT_PARAMS: function(a: PPSCRYPT_PARAMS; _in: PPIdAnsiChar; len: TIdC_LONG): PSCRYPT_PARAMS; cdecl = nil;
  {$EXTERNALSYM d2i_SCRYPT_PARAMS}

  i2d_SCRYPT_PARAMS: function(a: PSCRYPT_PARAMS; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_SCRYPT_PARAMS}

  SCRYPT_PARAMS_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM SCRYPT_PARAMS_it}

  PKCS5_pbe_set0_algor: function(algor: PX509_ALGOR; alg: TIdC_INT; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS5_pbe_set0_algor}

  PKCS5_pbe_set0_algor_ex: function(algor: PX509_ALGOR; alg: TIdC_INT; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; libctx: POSSL_LIB_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS5_pbe_set0_algor_ex}

  PKCS5_pbe_set: function(alg: TIdC_INT; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT): PX509_ALGOR; cdecl = nil;
  {$EXTERNALSYM PKCS5_pbe_set}

  PKCS5_pbe_set_ex: function(alg: TIdC_INT; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; libctx: POSSL_LIB_CTX): PX509_ALGOR; cdecl = nil;
  {$EXTERNALSYM PKCS5_pbe_set_ex}

  PKCS5_pbe2_set: function(cipher: PEVP_CIPHER; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT): PX509_ALGOR; cdecl = nil;
  {$EXTERNALSYM PKCS5_pbe2_set}

  PKCS5_pbe2_set_iv: function(cipher: PEVP_CIPHER; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; aiv: PIdAnsiChar; prf_nid: TIdC_INT): PX509_ALGOR; cdecl = nil;
  {$EXTERNALSYM PKCS5_pbe2_set_iv}

  PKCS5_pbe2_set_iv_ex: function(cipher: PEVP_CIPHER; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; aiv: PIdAnsiChar; prf_nid: TIdC_INT; libctx: POSSL_LIB_CTX): PX509_ALGOR; cdecl = nil;
  {$EXTERNALSYM PKCS5_pbe2_set_iv_ex}

  PKCS5_pbe2_set_scrypt: function(cipher: PEVP_CIPHER; salt: PIdAnsiChar; saltlen: TIdC_INT; aiv: PIdAnsiChar; N: TIdC_UINT64; r: TIdC_UINT64; p: TIdC_UINT64): PX509_ALGOR; cdecl = nil;
  {$EXTERNALSYM PKCS5_pbe2_set_scrypt}

  PKCS5_pbkdf2_set: function(iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; prf_nid: TIdC_INT; keylen: TIdC_INT): PX509_ALGOR; cdecl = nil;
  {$EXTERNALSYM PKCS5_pbkdf2_set}

  PKCS5_pbkdf2_set_ex: function(iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; prf_nid: TIdC_INT; keylen: TIdC_INT; libctx: POSSL_LIB_CTX): PX509_ALGOR; cdecl = nil;
  {$EXTERNALSYM PKCS5_pbkdf2_set_ex}

  PBMAC1_get1_pbkdf2_param: function(macalg: PX509_ALGOR): PPBKDF2PARAM; cdecl = nil;
  {$EXTERNALSYM PBMAC1_get1_pbkdf2_param}

  PKCS8_PRIV_KEY_INFO_new: function: PPKCS8_PRIV_KEY_INFO; cdecl = nil;
  {$EXTERNALSYM PKCS8_PRIV_KEY_INFO_new}

  PKCS8_PRIV_KEY_INFO_free: procedure(a: PPKCS8_PRIV_KEY_INFO); cdecl = nil;
  {$EXTERNALSYM PKCS8_PRIV_KEY_INFO_free}

  d2i_PKCS8_PRIV_KEY_INFO: function(a: PPPKCS8_PRIV_KEY_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS8_PRIV_KEY_INFO; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS8_PRIV_KEY_INFO}

  i2d_PKCS8_PRIV_KEY_INFO: function(a: PPKCS8_PRIV_KEY_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS8_PRIV_KEY_INFO}

  PKCS8_PRIV_KEY_INFO_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PKCS8_PRIV_KEY_INFO_it}

  EVP_PKCS82PKEY: function(p8: PPKCS8_PRIV_KEY_INFO): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM EVP_PKCS82PKEY}

  EVP_PKCS82PKEY_ex: function(p8: PPKCS8_PRIV_KEY_INFO; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM EVP_PKCS82PKEY_ex}

  EVP_PKEY2PKCS8: function(pkey: PEVP_PKEY): PPKCS8_PRIV_KEY_INFO; cdecl = nil;
  {$EXTERNALSYM EVP_PKEY2PKCS8}

  PKCS8_pkey_set0: function(priv: PPKCS8_PRIV_KEY_INFO; aobj: PASN1_OBJECT; version: TIdC_INT; ptype: TIdC_INT; pval: Pointer; penc: PIdAnsiChar; penclen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS8_pkey_set0}

  PKCS8_pkey_get0: function(ppkalg: PPASN1_OBJECT; pk: PPIdAnsiChar; ppklen: PIdC_INT; pa: PPX509_ALGOR; p8: PPKCS8_PRIV_KEY_INFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS8_pkey_get0}

  PKCS8_pkey_get0_attrs: function(p8: PPKCS8_PRIV_KEY_INFO): Pstack_st_X509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM PKCS8_pkey_get0_attrs}

  PKCS8_pkey_add1_attr: function(p8: PPKCS8_PRIV_KEY_INFO; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS8_pkey_add1_attr}

  PKCS8_pkey_add1_attr_by_NID: function(p8: PPKCS8_PRIV_KEY_INFO; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS8_pkey_add1_attr_by_NID}

  PKCS8_pkey_add1_attr_by_OBJ: function(p8: PPKCS8_PRIV_KEY_INFO; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS8_pkey_add1_attr_by_OBJ}

  X509_PUBKEY_set0_public_key: procedure(pub: PX509_PUBKEY; penc: PIdAnsiChar; penclen: TIdC_INT); cdecl = nil;
  {$EXTERNALSYM X509_PUBKEY_set0_public_key}

  X509_PUBKEY_set0_param: function(pub: PX509_PUBKEY; aobj: PASN1_OBJECT; ptype: TIdC_INT; pval: Pointer; penc: PIdAnsiChar; penclen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_PUBKEY_set0_param}

  X509_PUBKEY_get0_param: function(ppkalg: PPASN1_OBJECT; pk: PPIdAnsiChar; ppklen: PIdC_INT; pa: PPX509_ALGOR; pub: PX509_PUBKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_PUBKEY_get0_param}

  X509_PUBKEY_eq: function(a: PX509_PUBKEY; b: PX509_PUBKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_PUBKEY_eq}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

procedure X509_CRL_set_default_method(meth: PX509_CRL_METHOD); cdecl;
function X509_CRL_METHOD_new(crl_init: TX509_CRL_METHOD_new_crl_init_cb; crl_free: TX509_CRL_METHOD_new_crl_init_cb; crl_lookup: TX509_CRL_METHOD_new_crl_lookup_cb; crl_verify: TX509_CRL_METHOD_new_crl_verify_cb): PX509_CRL_METHOD; cdecl;
procedure X509_CRL_METHOD_free(m: PX509_CRL_METHOD); cdecl;
procedure X509_CRL_set_meth_data(crl: PX509_CRL; dat: Pointer); cdecl;
function X509_CRL_get_meth_data(crl: PX509_CRL): Pointer; cdecl;
function X509_verify_cert_error_string(n: TIdC_LONG): PIdAnsiChar; cdecl;
function X509_verify(a: PX509; r: PEVP_PKEY): TIdC_INT; cdecl;
function X509_self_signed(cert: PX509; verify_signature: TIdC_INT): TIdC_INT; cdecl;
function X509_REQ_verify_ex(a: PX509_REQ; r: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function X509_REQ_verify(a: PX509_REQ; r: PEVP_PKEY): TIdC_INT; cdecl;
function X509_CRL_verify(a: PX509_CRL; r: PEVP_PKEY): TIdC_INT; cdecl;
function NETSCAPE_SPKI_verify(a: PNETSCAPE_SPKI; r: PEVP_PKEY): TIdC_INT; cdecl;
function NETSCAPE_SPKI_b64_decode(str: PIdAnsiChar; len: TIdC_INT): PNETSCAPE_SPKI; cdecl;
function NETSCAPE_SPKI_b64_encode(x: PNETSCAPE_SPKI): PIdAnsiChar; cdecl;
function NETSCAPE_SPKI_get_pubkey(x: PNETSCAPE_SPKI): PEVP_PKEY; cdecl;
function NETSCAPE_SPKI_set_pubkey(x: PNETSCAPE_SPKI; pkey: PEVP_PKEY): TIdC_INT; cdecl;
function NETSCAPE_SPKI_print(_out: PBIO; spki: PNETSCAPE_SPKI): TIdC_INT; cdecl;
function X509_signature_dump(bp: PBIO; sig: PASN1_STRING; indent: TIdC_INT): TIdC_INT; cdecl;
function X509_signature_print(bp: PBIO; alg: PX509_ALGOR; sig: PASN1_STRING): TIdC_INT; cdecl;
function X509_sign(x: PX509; pkey: PEVP_PKEY; md: PEVP_MD): TIdC_INT; cdecl;
function X509_sign_ctx(x: PX509; ctx: PEVP_MD_CTX): TIdC_INT; cdecl;
function X509_REQ_sign(x: PX509_REQ; pkey: PEVP_PKEY; md: PEVP_MD): TIdC_INT; cdecl;
function X509_REQ_sign_ctx(x: PX509_REQ; ctx: PEVP_MD_CTX): TIdC_INT; cdecl;
function X509_CRL_sign(x: PX509_CRL; pkey: PEVP_PKEY; md: PEVP_MD): TIdC_INT; cdecl;
function X509_CRL_sign_ctx(x: PX509_CRL; ctx: PEVP_MD_CTX): TIdC_INT; cdecl;
function NETSCAPE_SPKI_sign(x: PNETSCAPE_SPKI; pkey: PEVP_PKEY; md: PEVP_MD): TIdC_INT; cdecl;
function X509_pubkey_digest(data: PX509; _type: PEVP_MD; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl;
function X509_digest(data: PX509; _type: PEVP_MD; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl;
function X509_digest_sig(cert: PX509; md_used: PPEVP_MD; md_is_fallback: PIdC_INT): PASN1_OCTET_STRING; cdecl;
function X509_CRL_digest(data: PX509_CRL; _type: PEVP_MD; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl;
function X509_REQ_digest(data: PX509_REQ; _type: PEVP_MD; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl;
function X509_NAME_digest(data: PX509_NAME; _type: PEVP_MD; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl;
function X509_load_http(url: PIdAnsiChar; bio: PBIO; rbio: PBIO; timeout: TIdC_INT): PX509; cdecl;
function X509_CRL_load_http(url: PIdAnsiChar; bio: PBIO; rbio: PBIO; timeout: TIdC_INT): PX509_CRL; cdecl;
function d2i_X509_fp(fp: PFILE; x509: PPX509): PX509; cdecl;
function i2d_X509_fp(fp: PFILE; x509: PX509): TIdC_INT; cdecl;
function d2i_X509_CRL_fp(fp: PFILE; crl: PPX509_CRL): PX509_CRL; cdecl;
function i2d_X509_CRL_fp(fp: PFILE; crl: PX509_CRL): TIdC_INT; cdecl;
function d2i_X509_REQ_fp(fp: PFILE; req: PPX509_REQ): PX509_REQ; cdecl;
function i2d_X509_REQ_fp(fp: PFILE; req: PX509_REQ): TIdC_INT; cdecl;
function d2i_RSAPrivateKey_fp(fp: PFILE; rsa: PPRSA): PRSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function i2d_RSAPrivateKey_fp(fp: PFILE; rsa: PRSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function d2i_RSAPublicKey_fp(fp: PFILE; rsa: PPRSA): PRSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function i2d_RSAPublicKey_fp(fp: PFILE; rsa: PRSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function d2i_RSA_PUBKEY_fp(fp: PFILE; rsa: PPRSA): PRSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function i2d_RSA_PUBKEY_fp(fp: PFILE; rsa: PRSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function d2i_DSA_PUBKEY_fp(fp: PFILE; dsa: PPDSA): PDSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function i2d_DSA_PUBKEY_fp(fp: PFILE; dsa: PDSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function d2i_DSAPrivateKey_fp(fp: PFILE; dsa: PPDSA): PDSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function i2d_DSAPrivateKey_fp(fp: PFILE; dsa: PDSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function d2i_EC_PUBKEY_fp(fp: PFILE; eckey: PPEC_KEY): PEC_KEY; cdecl; deprecated 'In OpenSSL 3_0_0';
function i2d_EC_PUBKEY_fp(fp: PFILE; eckey: PEC_KEY): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function d2i_ECPrivateKey_fp(fp: PFILE; eckey: PPEC_KEY): PEC_KEY; cdecl; deprecated 'In OpenSSL 3_0_0';
function i2d_ECPrivateKey_fp(fp: PFILE; eckey: PEC_KEY): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function d2i_PKCS8_fp(fp: PFILE; p8: PPX509_SIG): PX509_SIG; cdecl;
function i2d_PKCS8_fp(fp: PFILE; p8: PX509_SIG): TIdC_INT; cdecl;
function d2i_X509_PUBKEY_fp(fp: PFILE; xpk: PPX509_PUBKEY): PX509_PUBKEY; cdecl;
function i2d_X509_PUBKEY_fp(fp: PFILE; xpk: PX509_PUBKEY): TIdC_INT; cdecl;
function d2i_PKCS8_PRIV_KEY_INFO_fp(fp: PFILE; p8inf: PPPKCS8_PRIV_KEY_INFO): PPKCS8_PRIV_KEY_INFO; cdecl;
function i2d_PKCS8_PRIV_KEY_INFO_fp(fp: PFILE; p8inf: PPKCS8_PRIV_KEY_INFO): TIdC_INT; cdecl;
function i2d_PKCS8PrivateKeyInfo_fp(fp: PFILE; key: PEVP_PKEY): TIdC_INT; cdecl;
function i2d_PrivateKey_fp(fp: PFILE; pkey: PEVP_PKEY): TIdC_INT; cdecl;
function d2i_PrivateKey_ex_fp(fp: PFILE; a: PPEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl;
function d2i_PrivateKey_fp(fp: PFILE; a: PPEVP_PKEY): PEVP_PKEY; cdecl;
function i2d_PUBKEY_fp(fp: PFILE; pkey: PEVP_PKEY): TIdC_INT; cdecl;
function d2i_PUBKEY_ex_fp(fp: PFILE; a: PPEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl;
function d2i_PUBKEY_fp(fp: PFILE; a: PPEVP_PKEY): PEVP_PKEY; cdecl;
function d2i_X509_bio(bp: PBIO; x509: PPX509): PX509; cdecl;
function i2d_X509_bio(bp: PBIO; x509: PX509): TIdC_INT; cdecl;
function d2i_X509_CRL_bio(bp: PBIO; crl: PPX509_CRL): PX509_CRL; cdecl;
function i2d_X509_CRL_bio(bp: PBIO; crl: PX509_CRL): TIdC_INT; cdecl;
function d2i_X509_REQ_bio(bp: PBIO; req: PPX509_REQ): PX509_REQ; cdecl;
function i2d_X509_REQ_bio(bp: PBIO; req: PX509_REQ): TIdC_INT; cdecl;
function d2i_RSAPrivateKey_bio(bp: PBIO; rsa: PPRSA): PRSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function i2d_RSAPrivateKey_bio(bp: PBIO; rsa: PRSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function d2i_RSAPublicKey_bio(bp: PBIO; rsa: PPRSA): PRSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function i2d_RSAPublicKey_bio(bp: PBIO; rsa: PRSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function d2i_RSA_PUBKEY_bio(bp: PBIO; rsa: PPRSA): PRSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function i2d_RSA_PUBKEY_bio(bp: PBIO; rsa: PRSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function d2i_DSA_PUBKEY_bio(bp: PBIO; dsa: PPDSA): PDSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function i2d_DSA_PUBKEY_bio(bp: PBIO; dsa: PDSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function d2i_DSAPrivateKey_bio(bp: PBIO; dsa: PPDSA): PDSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function i2d_DSAPrivateKey_bio(bp: PBIO; dsa: PDSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function d2i_EC_PUBKEY_bio(bp: PBIO; eckey: PPEC_KEY): PEC_KEY; cdecl; deprecated 'In OpenSSL 3_0_0';
function i2d_EC_PUBKEY_bio(bp: PBIO; eckey: PEC_KEY): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function d2i_ECPrivateKey_bio(bp: PBIO; eckey: PPEC_KEY): PEC_KEY; cdecl; deprecated 'In OpenSSL 3_0_0';
function i2d_ECPrivateKey_bio(bp: PBIO; eckey: PEC_KEY): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function d2i_PKCS8_bio(bp: PBIO; p8: PPX509_SIG): PX509_SIG; cdecl;
function i2d_PKCS8_bio(bp: PBIO; p8: PX509_SIG): TIdC_INT; cdecl;
function d2i_X509_PUBKEY_bio(bp: PBIO; xpk: PPX509_PUBKEY): PX509_PUBKEY; cdecl;
function i2d_X509_PUBKEY_bio(bp: PBIO; xpk: PX509_PUBKEY): TIdC_INT; cdecl;
function d2i_PKCS8_PRIV_KEY_INFO_bio(bp: PBIO; p8inf: PPPKCS8_PRIV_KEY_INFO): PPKCS8_PRIV_KEY_INFO; cdecl;
function i2d_PKCS8_PRIV_KEY_INFO_bio(bp: PBIO; p8inf: PPKCS8_PRIV_KEY_INFO): TIdC_INT; cdecl;
function i2d_PKCS8PrivateKeyInfo_bio(bp: PBIO; key: PEVP_PKEY): TIdC_INT; cdecl;
function i2d_PrivateKey_bio(bp: PBIO; pkey: PEVP_PKEY): TIdC_INT; cdecl;
function d2i_PrivateKey_ex_bio(bp: PBIO; a: PPEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl;
function d2i_PrivateKey_bio(bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY; cdecl;
function i2d_PUBKEY_bio(bp: PBIO; pkey: PEVP_PKEY): TIdC_INT; cdecl;
function d2i_PUBKEY_ex_bio(bp: PBIO; a: PPEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl;
function d2i_PUBKEY_bio(bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY; cdecl;
function X509_dup(a: PX509): PX509; cdecl;
function X509_ALGOR_dup(a: PX509_ALGOR): PX509_ALGOR; cdecl;
function X509_ATTRIBUTE_dup(a: PX509_ATTRIBUTE): PX509_ATTRIBUTE; cdecl;
function X509_CRL_dup(a: PX509_CRL): PX509_CRL; cdecl;
function X509_EXTENSION_dup(a: PX509_EXTENSION): PX509_EXTENSION; cdecl;
function X509_PUBKEY_dup(a: PX509_PUBKEY): PX509_PUBKEY; cdecl;
function X509_REQ_dup(a: PX509_REQ): PX509_REQ; cdecl;
function X509_REVOKED_dup(a: PX509_REVOKED): PX509_REVOKED; cdecl;
function X509_ALGOR_set0(alg: PX509_ALGOR; aobj: PASN1_OBJECT; ptype: TIdC_INT; pval: Pointer): TIdC_INT; cdecl;
procedure X509_ALGOR_get0(paobj: PPASN1_OBJECT; pptype: PIdC_INT; ppval: PPointer; algor: PX509_ALGOR); cdecl;
procedure X509_ALGOR_set_md(alg: PX509_ALGOR; md: PEVP_MD); cdecl;
function X509_ALGOR_cmp(a: PX509_ALGOR; b: PX509_ALGOR): TIdC_INT; cdecl;
function X509_ALGOR_copy(dest: PX509_ALGOR; src: PX509_ALGOR): TIdC_INT; cdecl;
function X509_NAME_dup(a: PX509_NAME): PX509_NAME; cdecl;
function X509_NAME_ENTRY_dup(a: PX509_NAME_ENTRY): PX509_NAME_ENTRY; cdecl;
function X509_cmp_time(s: PASN1_TIME; t: PIdC_TIMET): TIdC_INT; cdecl;
function X509_cmp_current_time(s: PASN1_TIME): TIdC_INT; cdecl;
function X509_cmp_timeframe(vpm: PX509_VERIFY_PARAM; start: PASN1_TIME; _end: PASN1_TIME): TIdC_INT; cdecl;
function X509_time_adj(s: PASN1_TIME; adj: TIdC_LONG; t: PIdC_TIMET): PASN1_TIME; cdecl;
function X509_time_adj_ex(s: PASN1_TIME; offset_day: TIdC_INT; offset_sec: TIdC_LONG; t: PIdC_TIMET): PASN1_TIME; cdecl;
function X509_gmtime_adj(s: PASN1_TIME; adj: TIdC_LONG): PASN1_TIME; cdecl;
function X509_get_default_cert_area: PIdAnsiChar; cdecl;
function X509_get_default_cert_dir: PIdAnsiChar; cdecl;
function X509_get_default_cert_file: PIdAnsiChar; cdecl;
function X509_get_default_cert_dir_env: PIdAnsiChar; cdecl;
function X509_get_default_cert_file_env: PIdAnsiChar; cdecl;
function X509_get_default_private_dir: PIdAnsiChar; cdecl;
function X509_to_X509_REQ(x: PX509; pkey: PEVP_PKEY; md: PEVP_MD): PX509_REQ; cdecl;
function X509_REQ_to_X509(r: PX509_REQ; days: TIdC_INT; pkey: PEVP_PKEY): PX509; cdecl;
function X509_ALGOR_new: PX509_ALGOR; cdecl;
procedure X509_ALGOR_free(a: PX509_ALGOR); cdecl;
function d2i_X509_ALGOR(a: PPX509_ALGOR; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_ALGOR; cdecl;
function i2d_X509_ALGOR(a: PX509_ALGOR; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function X509_ALGOR_it: PASN1_ITEM; cdecl;
function d2i_X509_ALGORS(a: PPX509_ALGORS; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_ALGORS; cdecl;
function i2d_X509_ALGORS(a: PX509_ALGORS; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function X509_ALGORS_it: PASN1_ITEM; cdecl;
function X509_VAL_new: PX509_VAL; cdecl;
procedure X509_VAL_free(a: PX509_VAL); cdecl;
function d2i_X509_VAL(a: PPX509_VAL; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_VAL; cdecl;
function i2d_X509_VAL(a: PX509_VAL; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function X509_VAL_it: PASN1_ITEM; cdecl;
function X509_PUBKEY_new: PX509_PUBKEY; cdecl;
procedure X509_PUBKEY_free(a: PX509_PUBKEY); cdecl;
function d2i_X509_PUBKEY(a: PPX509_PUBKEY; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_PUBKEY; cdecl;
function i2d_X509_PUBKEY(a: PX509_PUBKEY; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function X509_PUBKEY_it: PASN1_ITEM; cdecl;
function X509_PUBKEY_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_PUBKEY; cdecl;
function X509_PUBKEY_set(x: PPX509_PUBKEY; pkey: PEVP_PKEY): TIdC_INT; cdecl;
function X509_PUBKEY_get0(key: PX509_PUBKEY): PEVP_PKEY; cdecl;
function X509_PUBKEY_get(key: PX509_PUBKEY): PEVP_PKEY; cdecl;
function X509_get_pubkey_parameters(pkey: PEVP_PKEY; chain: Pstack_st_X509): TIdC_INT; cdecl;
function X509_get_pathlen(x: PX509): TIdC_LONG; cdecl;
function d2i_PUBKEY(a: PPEVP_PKEY; _in: PPIdAnsiChar; len: TIdC_LONG): PEVP_PKEY; cdecl;
function i2d_PUBKEY(a: PEVP_PKEY; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function d2i_PUBKEY_ex(a: PPEVP_PKEY; pp: PPIdAnsiChar; length: TIdC_LONG; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl;
function d2i_RSA_PUBKEY(a: PPRSA; _in: PPIdAnsiChar; len: TIdC_LONG): PRSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function i2d_RSA_PUBKEY(a: PRSA; _out: PPIdAnsiChar): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function d2i_DSA_PUBKEY(a: PPDSA; _in: PPIdAnsiChar; len: TIdC_LONG): PDSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function i2d_DSA_PUBKEY(a: PDSA; _out: PPIdAnsiChar): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function d2i_EC_PUBKEY(a: PPEC_KEY; _in: PPIdAnsiChar; len: TIdC_LONG): PEC_KEY; cdecl; deprecated 'In OpenSSL 3_0_0';
function i2d_EC_PUBKEY(a: PEC_KEY; _out: PPIdAnsiChar): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function X509_SIG_new: PX509_SIG; cdecl;
procedure X509_SIG_free(a: PX509_SIG); cdecl;
function d2i_X509_SIG(a: PPX509_SIG; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_SIG; cdecl;
function i2d_X509_SIG(a: PX509_SIG; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function X509_SIG_it: PASN1_ITEM; cdecl;
procedure X509_SIG_get0(sig: PX509_SIG; palg: PPX509_ALGOR; pdigest: PPASN1_OCTET_STRING); cdecl;
procedure X509_SIG_getm(sig: PX509_SIG; palg: PPX509_ALGOR; pdigest: PPASN1_OCTET_STRING); cdecl;
function X509_REQ_INFO_new: PX509_REQ_INFO; cdecl;
procedure X509_REQ_INFO_free(a: PX509_REQ_INFO); cdecl;
function d2i_X509_REQ_INFO(a: PPX509_REQ_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_REQ_INFO; cdecl;
function i2d_X509_REQ_INFO(a: PX509_REQ_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function X509_REQ_INFO_it: PASN1_ITEM; cdecl;
function X509_REQ_new: PX509_REQ; cdecl;
procedure X509_REQ_free(a: PX509_REQ); cdecl;
function d2i_X509_REQ(a: PPX509_REQ; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_REQ; cdecl;
function i2d_X509_REQ(a: PX509_REQ; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function X509_REQ_it: PASN1_ITEM; cdecl;
function X509_REQ_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_REQ; cdecl;
function X509_ATTRIBUTE_new: PX509_ATTRIBUTE; cdecl;
procedure X509_ATTRIBUTE_free(a: PX509_ATTRIBUTE); cdecl;
function d2i_X509_ATTRIBUTE(a: PPX509_ATTRIBUTE; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_ATTRIBUTE; cdecl;
function i2d_X509_ATTRIBUTE(a: PX509_ATTRIBUTE; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function X509_ATTRIBUTE_it: PASN1_ITEM; cdecl;
function X509_ATTRIBUTE_create(nid: TIdC_INT; atrtype: TIdC_INT; value: Pointer): PX509_ATTRIBUTE; cdecl;
function X509_EXTENSION_new: PX509_EXTENSION; cdecl;
procedure X509_EXTENSION_free(a: PX509_EXTENSION); cdecl;
function d2i_X509_EXTENSION(a: PPX509_EXTENSION; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_EXTENSION; cdecl;
function i2d_X509_EXTENSION(a: PX509_EXTENSION; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function X509_EXTENSION_it: PASN1_ITEM; cdecl;
function d2i_X509_EXTENSIONS(a: PPX509_EXTENSIONS; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_EXTENSIONS; cdecl;
function i2d_X509_EXTENSIONS(a: PX509_EXTENSIONS; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function X509_EXTENSIONS_it: PASN1_ITEM; cdecl;
function X509_NAME_ENTRY_new: PX509_NAME_ENTRY; cdecl;
procedure X509_NAME_ENTRY_free(a: PX509_NAME_ENTRY); cdecl;
function d2i_X509_NAME_ENTRY(a: PPX509_NAME_ENTRY; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_NAME_ENTRY; cdecl;
function i2d_X509_NAME_ENTRY(a: PX509_NAME_ENTRY; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function X509_NAME_ENTRY_it: PASN1_ITEM; cdecl;
function X509_NAME_new: PX509_NAME; cdecl;
procedure X509_NAME_free(a: PX509_NAME); cdecl;
function d2i_X509_NAME(a: PPX509_NAME; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_NAME; cdecl;
function i2d_X509_NAME(a: PX509_NAME; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function X509_NAME_it: PASN1_ITEM; cdecl;
function X509_NAME_set(xn: PPX509_NAME; name: PX509_NAME): TIdC_INT; cdecl;
function X509_CINF_new: PX509_CINF; cdecl;
procedure X509_CINF_free(a: PX509_CINF); cdecl;
function d2i_X509_CINF(a: PPX509_CINF; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_CINF; cdecl;
function i2d_X509_CINF(a: PX509_CINF; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function X509_CINF_it: PASN1_ITEM; cdecl;
function X509_new: PX509; cdecl;
procedure X509_free(a: PX509); cdecl;
function d2i_X509(a: PPX509; _in: PPIdAnsiChar; len: TIdC_LONG): PX509; cdecl;
function i2d_X509(a: PX509; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function X509_it: PASN1_ITEM; cdecl;
function X509_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509; cdecl;
function X509_CERT_AUX_new: PX509_CERT_AUX; cdecl;
procedure X509_CERT_AUX_free(a: PX509_CERT_AUX); cdecl;
function d2i_X509_CERT_AUX(a: PPX509_CERT_AUX; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_CERT_AUX; cdecl;
function i2d_X509_CERT_AUX(a: PX509_CERT_AUX; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function X509_CERT_AUX_it: PASN1_ITEM; cdecl;
function X509_set_ex_data(r: PX509; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl;
function X509_get_ex_data(r: PX509; idx: TIdC_INT): Pointer; cdecl;
function d2i_X509_AUX(a: PPX509; _in: PPIdAnsiChar; len: TIdC_LONG): PX509; cdecl;
function i2d_X509_AUX(a: PX509; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function i2d_re_X509_tbs(x: PX509; pp: PPIdAnsiChar): TIdC_INT; cdecl;
function X509_SIG_INFO_get(siginf: PX509_SIG_INFO; mdnid: PIdC_INT; pknid: PIdC_INT; secbits: PIdC_INT; flags: PIdC_UINT32): TIdC_INT; cdecl;
procedure X509_SIG_INFO_set(siginf: PX509_SIG_INFO; mdnid: TIdC_INT; pknid: TIdC_INT; secbits: TIdC_INT; flags: TIdC_UINT32); cdecl;
function X509_get_signature_info(x: PX509; mdnid: PIdC_INT; pknid: PIdC_INT; secbits: PIdC_INT; flags: PIdC_UINT32): TIdC_INT; cdecl;
procedure X509_get0_signature(psig: PPASN1_BIT_STRING; palg: PPX509_ALGOR; x: PX509); cdecl;
function X509_get_signature_nid(x: PX509): TIdC_INT; cdecl;
procedure X509_set0_distinguishing_id(x: PX509; d_id: PASN1_OCTET_STRING); cdecl;
function X509_get0_distinguishing_id(x: PX509): PASN1_OCTET_STRING; cdecl;
procedure X509_REQ_set0_distinguishing_id(x: PX509_REQ; d_id: PASN1_OCTET_STRING); cdecl;
function X509_REQ_get0_distinguishing_id(x: PX509_REQ): PASN1_OCTET_STRING; cdecl;
function X509_alias_set1(x: PX509; name: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function X509_keyid_set1(x: PX509; id: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function X509_alias_get0(x: PX509; len: PIdC_INT): PIdAnsiChar; cdecl;
function X509_keyid_get0(x: PX509; len: PIdC_INT): PIdAnsiChar; cdecl;
function X509_REVOKED_new: PX509_REVOKED; cdecl;
procedure X509_REVOKED_free(a: PX509_REVOKED); cdecl;
function d2i_X509_REVOKED(a: PPX509_REVOKED; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_REVOKED; cdecl;
function i2d_X509_REVOKED(a: PX509_REVOKED; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function X509_REVOKED_it: PASN1_ITEM; cdecl;
function X509_CRL_INFO_new: PX509_CRL_INFO; cdecl;
procedure X509_CRL_INFO_free(a: PX509_CRL_INFO); cdecl;
function d2i_X509_CRL_INFO(a: PPX509_CRL_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_CRL_INFO; cdecl;
function i2d_X509_CRL_INFO(a: PX509_CRL_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function X509_CRL_INFO_it: PASN1_ITEM; cdecl;
function X509_CRL_new: PX509_CRL; cdecl;
procedure X509_CRL_free(a: PX509_CRL); cdecl;
function d2i_X509_CRL(a: PPX509_CRL; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_CRL; cdecl;
function i2d_X509_CRL(a: PX509_CRL; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function X509_CRL_it: PASN1_ITEM; cdecl;
function X509_CRL_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_CRL; cdecl;
function X509_CRL_add0_revoked(crl: PX509_CRL; rev: PX509_REVOKED): TIdC_INT; cdecl;
function X509_CRL_get0_by_serial(crl: PX509_CRL; ret: PPX509_REVOKED; serial: PASN1_INTEGER): TIdC_INT; cdecl;
function X509_CRL_get0_by_cert(crl: PX509_CRL; ret: PPX509_REVOKED; x: PX509): TIdC_INT; cdecl;
function X509_PKEY_new: PX509_PKEY; cdecl;
procedure X509_PKEY_free(a: PX509_PKEY); cdecl;
function NETSCAPE_SPKI_new: PNETSCAPE_SPKI; cdecl;
procedure NETSCAPE_SPKI_free(a: PNETSCAPE_SPKI); cdecl;
function d2i_NETSCAPE_SPKI(a: PPNETSCAPE_SPKI; _in: PPIdAnsiChar; len: TIdC_LONG): PNETSCAPE_SPKI; cdecl;
function i2d_NETSCAPE_SPKI(a: PNETSCAPE_SPKI; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function NETSCAPE_SPKI_it: PASN1_ITEM; cdecl;
function NETSCAPE_SPKAC_new: PNETSCAPE_SPKAC; cdecl;
procedure NETSCAPE_SPKAC_free(a: PNETSCAPE_SPKAC); cdecl;
function d2i_NETSCAPE_SPKAC(a: PPNETSCAPE_SPKAC; _in: PPIdAnsiChar; len: TIdC_LONG): PNETSCAPE_SPKAC; cdecl;
function i2d_NETSCAPE_SPKAC(a: PNETSCAPE_SPKAC; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function NETSCAPE_SPKAC_it: PASN1_ITEM; cdecl;
function NETSCAPE_CERT_SEQUENCE_new: PNETSCAPE_CERT_SEQUENCE; cdecl;
procedure NETSCAPE_CERT_SEQUENCE_free(a: PNETSCAPE_CERT_SEQUENCE); cdecl;
function d2i_NETSCAPE_CERT_SEQUENCE(a: PPNETSCAPE_CERT_SEQUENCE; _in: PPIdAnsiChar; len: TIdC_LONG): PNETSCAPE_CERT_SEQUENCE; cdecl;
function i2d_NETSCAPE_CERT_SEQUENCE(a: PNETSCAPE_CERT_SEQUENCE; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function NETSCAPE_CERT_SEQUENCE_it: PASN1_ITEM; cdecl;
function X509_INFO_new: PX509_INFO; cdecl;
procedure X509_INFO_free(a: PX509_INFO); cdecl;
function X509_NAME_oneline(a: PX509_NAME; buf: PIdAnsiChar; size: TIdC_INT): PIdAnsiChar; cdecl;
function ASN1_verify(i2d: TASN1_verify_i2d_cb; algor1: PX509_ALGOR; signature: PASN1_BIT_STRING; data: PIdAnsiChar; pkey: PEVP_PKEY): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ASN1_digest(i2d: TASN1_verify_i2d_cb; _type: PEVP_MD; data: PIdAnsiChar; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ASN1_sign(i2d: TASN1_verify_i2d_cb; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: PIdAnsiChar; pkey: PEVP_PKEY; _type: PEVP_MD): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function ASN1_item_digest(it: PASN1_ITEM; _type: PEVP_MD; data: Pointer; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl;
function ASN1_item_verify(it: PASN1_ITEM; alg: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY): TIdC_INT; cdecl;
function ASN1_item_verify_ctx(it: PASN1_ITEM; alg: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; ctx: PEVP_MD_CTX): TIdC_INT; cdecl;
function ASN1_item_sign(it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY; md: PEVP_MD): TIdC_INT; cdecl;
function ASN1_item_sign_ctx(it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; ctx: PEVP_MD_CTX): TIdC_INT; cdecl;
function X509_get_version(x: PX509): TIdC_LONG; cdecl;
function X509_set_version(x: PX509; version: TIdC_LONG): TIdC_INT; cdecl;
function X509_set_serialNumber(x: PX509; serial: PASN1_INTEGER): TIdC_INT; cdecl;
function X509_get_serialNumber(x: PX509): PASN1_INTEGER; cdecl;
function X509_get0_serialNumber(x: PX509): PASN1_INTEGER; cdecl;
function X509_set_issuer_name(x: PX509; name: PX509_NAME): TIdC_INT; cdecl;
function X509_get_issuer_name(a: PX509): PX509_NAME; cdecl;
function X509_set_subject_name(x: PX509; name: PX509_NAME): TIdC_INT; cdecl;
function X509_get_subject_name(a: PX509): PX509_NAME; cdecl;
function X509_get0_notBefore(x: PX509): PASN1_TIME; cdecl;
function X509_getm_notBefore(x: PX509): PASN1_TIME; cdecl;
function X509_set1_notBefore(x: PX509; tm: PASN1_TIME): TIdC_INT; cdecl;
function X509_get0_notAfter(x: PX509): PASN1_TIME; cdecl;
function X509_getm_notAfter(x: PX509): PASN1_TIME; cdecl;
function X509_set1_notAfter(x: PX509; tm: PASN1_TIME): TIdC_INT; cdecl;
function X509_set_pubkey(x: PX509; pkey: PEVP_PKEY): TIdC_INT; cdecl;
function X509_up_ref(x: PX509): TIdC_INT; cdecl;
function X509_get_signature_type(x: PX509): TIdC_INT; cdecl;
function X509_get_X509_PUBKEY(x: PX509): PX509_PUBKEY; cdecl;
function X509_get0_extensions(x: PX509): Pstack_st_X509_EXTENSION; cdecl;
procedure X509_get0_uids(x: PX509; piuid: PPASN1_BIT_STRING; psuid: PPASN1_BIT_STRING); cdecl;
function X509_get0_tbs_sigalg(x: PX509): PX509_ALGOR; cdecl;
function X509_get0_pubkey(x: PX509): PEVP_PKEY; cdecl;
function X509_get_pubkey(x: PX509): PEVP_PKEY; cdecl;
function X509_get0_pubkey_bitstr(x: PX509): PASN1_BIT_STRING; cdecl;
function X509_REQ_get_version(req: PX509_REQ): TIdC_LONG; cdecl;
function X509_REQ_set_version(x: PX509_REQ; version: TIdC_LONG): TIdC_INT; cdecl;
function X509_REQ_get_subject_name(req: PX509_REQ): PX509_NAME; cdecl;
function X509_REQ_set_subject_name(req: PX509_REQ; name: PX509_NAME): TIdC_INT; cdecl;
procedure X509_REQ_get0_signature(req: PX509_REQ; psig: PPASN1_BIT_STRING; palg: PPX509_ALGOR); cdecl;
procedure X509_REQ_set0_signature(req: PX509_REQ; psig: PASN1_BIT_STRING); cdecl;
function X509_REQ_set1_signature_algo(req: PX509_REQ; palg: PX509_ALGOR): TIdC_INT; cdecl;
function X509_REQ_get_signature_nid(req: PX509_REQ): TIdC_INT; cdecl;
function i2d_re_X509_REQ_tbs(req: PX509_REQ; pp: PPIdAnsiChar): TIdC_INT; cdecl;
function X509_REQ_set_pubkey(x: PX509_REQ; pkey: PEVP_PKEY): TIdC_INT; cdecl;
function X509_REQ_get_pubkey(req: PX509_REQ): PEVP_PKEY; cdecl;
function X509_REQ_get0_pubkey(req: PX509_REQ): PEVP_PKEY; cdecl;
function X509_REQ_get_X509_PUBKEY(req: PX509_REQ): PX509_PUBKEY; cdecl;
function X509_REQ_extension_nid(nid: TIdC_INT): TIdC_INT; cdecl;
function X509_REQ_get_extension_nids: PIdC_INT; cdecl;
procedure X509_REQ_set_extension_nids(nids: PIdC_INT); cdecl;
function X509_REQ_get_extensions(req: PX509_REQ): Pstack_st_X509_EXTENSION; cdecl;
function X509_REQ_add_extensions_nid(req: PX509_REQ; exts: Pstack_st_X509_EXTENSION; nid: TIdC_INT): TIdC_INT; cdecl;
function X509_REQ_add_extensions(req: PX509_REQ; ext: Pstack_st_X509_EXTENSION): TIdC_INT; cdecl;
function X509_REQ_get_attr_count(req: PX509_REQ): TIdC_INT; cdecl;
function X509_REQ_get_attr_by_NID(req: PX509_REQ; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function X509_REQ_get_attr_by_OBJ(req: PX509_REQ; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function X509_REQ_get_attr(req: PX509_REQ; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl;
function X509_REQ_delete_attr(req: PX509_REQ; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl;
function X509_REQ_add1_attr(req: PX509_REQ; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl;
function X509_REQ_add1_attr_by_OBJ(req: PX509_REQ; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function X509_REQ_add1_attr_by_NID(req: PX509_REQ; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function X509_REQ_add1_attr_by_txt(req: PX509_REQ; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function X509_CRL_set_version(x: PX509_CRL; version: TIdC_LONG): TIdC_INT; cdecl;
function X509_CRL_set_issuer_name(x: PX509_CRL; name: PX509_NAME): TIdC_INT; cdecl;
function X509_CRL_set1_lastUpdate(x: PX509_CRL; tm: PASN1_TIME): TIdC_INT; cdecl;
function X509_CRL_set1_nextUpdate(x: PX509_CRL; tm: PASN1_TIME): TIdC_INT; cdecl;
function X509_CRL_sort(crl: PX509_CRL): TIdC_INT; cdecl;
function X509_CRL_up_ref(crl: PX509_CRL): TIdC_INT; cdecl;
function X509_CRL_get_version(crl: PX509_CRL): TIdC_LONG; cdecl;
function X509_CRL_get0_lastUpdate(crl: PX509_CRL): PASN1_TIME; cdecl;
function X509_CRL_get0_nextUpdate(crl: PX509_CRL): PASN1_TIME; cdecl;
function X509_CRL_get_issuer(crl: PX509_CRL): PX509_NAME; cdecl;
function X509_CRL_get0_extensions(crl: PX509_CRL): Pstack_st_X509_EXTENSION; cdecl;
function X509_CRL_get_REVOKED(crl: PX509_CRL): Pstack_st_X509_REVOKED; cdecl;
function X509_CRL_get0_tbs_sigalg(crl: PX509_CRL): PX509_ALGOR; cdecl;
procedure X509_CRL_get0_signature(crl: PX509_CRL; psig: PPASN1_BIT_STRING; palg: PPX509_ALGOR); cdecl;
function X509_CRL_get_signature_nid(crl: PX509_CRL): TIdC_INT; cdecl;
function i2d_re_X509_CRL_tbs(req: PX509_CRL; pp: PPIdAnsiChar): TIdC_INT; cdecl;
function X509_REVOKED_get0_serialNumber(x: PX509_REVOKED): PASN1_INTEGER; cdecl;
function X509_REVOKED_set_serialNumber(x: PX509_REVOKED; serial: PASN1_INTEGER): TIdC_INT; cdecl;
function X509_REVOKED_get0_revocationDate(x: PX509_REVOKED): PASN1_TIME; cdecl;
function X509_REVOKED_set_revocationDate(r: PX509_REVOKED; tm: PASN1_TIME): TIdC_INT; cdecl;
function X509_REVOKED_get0_extensions(r: PX509_REVOKED): Pstack_st_X509_EXTENSION; cdecl;
function X509_CRL_diff(base: PX509_CRL; newer: PX509_CRL; skey: PEVP_PKEY; md: PEVP_MD; flags: TIdC_UINT): PX509_CRL; cdecl;
function X509_REQ_check_private_key(req: PX509_REQ; pkey: PEVP_PKEY): TIdC_INT; cdecl;
function X509_check_private_key(cert: PX509; pkey: PEVP_PKEY): TIdC_INT; cdecl;
function X509_chain_check_suiteb(perror_depth: PIdC_INT; x: PX509; chain: Pstack_st_X509; flags: TIdC_ULONG): TIdC_INT; cdecl;
function X509_CRL_check_suiteb(crl: PX509_CRL; pk: PEVP_PKEY; flags: TIdC_ULONG): TIdC_INT; cdecl;
procedure OSSL_STACK_OF_X509_free(certs: Pstack_st_X509); cdecl;
function X509_chain_up_ref(chain: Pstack_st_X509): Pstack_st_X509; cdecl;
function X509_issuer_and_serial_cmp(a: PX509; b: PX509): TIdC_INT; cdecl;
function X509_issuer_and_serial_hash(a: PX509): TIdC_ULONG; cdecl;
function X509_issuer_name_cmp(a: PX509; b: PX509): TIdC_INT; cdecl;
function X509_issuer_name_hash(a: PX509): TIdC_ULONG; cdecl;
function X509_subject_name_cmp(a: PX509; b: PX509): TIdC_INT; cdecl;
function X509_subject_name_hash(x: PX509): TIdC_ULONG; cdecl;
function X509_issuer_name_hash_old(a: PX509): TIdC_ULONG; cdecl;
function X509_subject_name_hash_old(x: PX509): TIdC_ULONG; cdecl;
function X509_add_cert(sk: Pstack_st_X509; cert: PX509; flags: TIdC_INT): TIdC_INT; cdecl;
function X509_add_certs(sk: Pstack_st_X509; certs: Pstack_st_X509; flags: TIdC_INT): TIdC_INT; cdecl;
function X509_cmp(a: PX509; b: PX509): TIdC_INT; cdecl;
function X509_NAME_cmp(a: PX509_NAME; b: PX509_NAME): TIdC_INT; cdecl;
function X509_certificate_type(x: PX509; pubkey: PEVP_PKEY): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function X509_NAME_hash_ex(x: PX509_NAME; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; ok: PIdC_INT): TIdC_ULONG; cdecl;
function X509_NAME_hash_old(x: PX509_NAME): TIdC_ULONG; cdecl;
function X509_CRL_cmp(a: PX509_CRL; b: PX509_CRL): TIdC_INT; cdecl;
function X509_CRL_match(a: PX509_CRL; b: PX509_CRL): TIdC_INT; cdecl;
function X509_aux_print(_out: PBIO; x: PX509; indent: TIdC_INT): TIdC_INT; cdecl;
function X509_print_ex_fp(bp: PFILE; x: PX509; nmflag: TIdC_ULONG; cflag: TIdC_ULONG): TIdC_INT; cdecl;
function X509_print_fp(bp: PFILE; x: PX509): TIdC_INT; cdecl;
function X509_CRL_print_fp(bp: PFILE; x: PX509_CRL): TIdC_INT; cdecl;
function X509_REQ_print_fp(bp: PFILE; req: PX509_REQ): TIdC_INT; cdecl;
function X509_NAME_print_ex_fp(fp: PFILE; nm: PX509_NAME; indent: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl;
function X509_NAME_print(bp: PBIO; name: PX509_NAME; obase: TIdC_INT): TIdC_INT; cdecl;
function X509_NAME_print_ex(_out: PBIO; nm: PX509_NAME; indent: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl;
function X509_print_ex(bp: PBIO; x: PX509; nmflag: TIdC_ULONG; cflag: TIdC_ULONG): TIdC_INT; cdecl;
function X509_print(bp: PBIO; x: PX509): TIdC_INT; cdecl;
function X509_ocspid_print(bp: PBIO; x: PX509): TIdC_INT; cdecl;
function X509_CRL_print_ex(_out: PBIO; x: PX509_CRL; nmflag: TIdC_ULONG): TIdC_INT; cdecl;
function X509_CRL_print(bp: PBIO; x: PX509_CRL): TIdC_INT; cdecl;
function X509_REQ_print_ex(bp: PBIO; x: PX509_REQ; nmflag: TIdC_ULONG; cflag: TIdC_ULONG): TIdC_INT; cdecl;
function X509_REQ_print(bp: PBIO; req: PX509_REQ): TIdC_INT; cdecl;
function X509_NAME_entry_count(name: PX509_NAME): TIdC_INT; cdecl;
function X509_NAME_get_text_by_NID(name: PX509_NAME; nid: TIdC_INT; buf: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function X509_NAME_get_text_by_OBJ(name: PX509_NAME; obj: PASN1_OBJECT; buf: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function X509_NAME_get_index_by_NID(name: PX509_NAME; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function X509_NAME_get_index_by_OBJ(name: PX509_NAME; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function X509_NAME_get_entry(name: PX509_NAME; loc: TIdC_INT): PX509_NAME_ENTRY; cdecl;
function X509_NAME_delete_entry(name: PX509_NAME; loc: TIdC_INT): PX509_NAME_ENTRY; cdecl;
function X509_NAME_add_entry(name: PX509_NAME; ne: PX509_NAME_ENTRY; loc: TIdC_INT; _set: TIdC_INT): TIdC_INT; cdecl;
function X509_NAME_add_entry_by_OBJ(name: PX509_NAME; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT; loc: TIdC_INT; _set: TIdC_INT): TIdC_INT; cdecl;
function X509_NAME_add_entry_by_NID(name: PX509_NAME; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT; loc: TIdC_INT; _set: TIdC_INT): TIdC_INT; cdecl;
function X509_NAME_ENTRY_create_by_txt(ne: PPX509_NAME_ENTRY; field: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): PX509_NAME_ENTRY; cdecl;
function X509_NAME_ENTRY_create_by_NID(ne: PPX509_NAME_ENTRY; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): PX509_NAME_ENTRY; cdecl;
function X509_NAME_add_entry_by_txt(name: PX509_NAME; field: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT; loc: TIdC_INT; _set: TIdC_INT): TIdC_INT; cdecl;
function X509_NAME_ENTRY_create_by_OBJ(ne: PPX509_NAME_ENTRY; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): PX509_NAME_ENTRY; cdecl;
function X509_NAME_ENTRY_set_object(ne: PX509_NAME_ENTRY; obj: PASN1_OBJECT): TIdC_INT; cdecl;
function X509_NAME_ENTRY_set_data(ne: PX509_NAME_ENTRY; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function X509_NAME_ENTRY_get_object(ne: PX509_NAME_ENTRY): PASN1_OBJECT; cdecl;
function X509_NAME_ENTRY_get_data(ne: PX509_NAME_ENTRY): PASN1_STRING; cdecl;
function X509_NAME_ENTRY_set(ne: PX509_NAME_ENTRY): TIdC_INT; cdecl;
function X509_NAME_get0_der(nm: PX509_NAME; pder: PPIdAnsiChar; pderlen: PIdC_SIZET): TIdC_INT; cdecl;
function X509v3_get_ext_count(x: Pstack_st_X509_EXTENSION): TIdC_INT; cdecl;
function X509v3_get_ext_by_NID(x: Pstack_st_X509_EXTENSION; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function X509v3_get_ext_by_OBJ(x: Pstack_st_X509_EXTENSION; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function X509v3_get_ext_by_critical(x: Pstack_st_X509_EXTENSION; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function X509v3_get_ext(x: Pstack_st_X509_EXTENSION; loc: TIdC_INT): PX509_EXTENSION; cdecl;
function X509v3_delete_ext(x: Pstack_st_X509_EXTENSION; loc: TIdC_INT): PX509_EXTENSION; cdecl;
function X509v3_add_ext(x: PPstack_st_X509_EXTENSION; ex: PX509_EXTENSION; loc: TIdC_INT): Pstack_st_X509_EXTENSION; cdecl;
function X509v3_add_extensions(target: PPstack_st_X509_EXTENSION; exts: Pstack_st_X509_EXTENSION): Pstack_st_X509_EXTENSION; cdecl;
function X509_get_ext_count(x: PX509): TIdC_INT; cdecl;
function X509_get_ext_by_NID(x: PX509; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function X509_get_ext_by_OBJ(x: PX509; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function X509_get_ext_by_critical(x: PX509; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function X509_get_ext(x: PX509; loc: TIdC_INT): PX509_EXTENSION; cdecl;
function X509_delete_ext(x: PX509; loc: TIdC_INT): PX509_EXTENSION; cdecl;
function X509_add_ext(x: PX509; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl;
function X509_get_ext_d2i(x: PX509; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl;
function X509_add1_ext_i2d(x: PX509; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl;
function X509_CRL_get_ext_count(x: PX509_CRL): TIdC_INT; cdecl;
function X509_CRL_get_ext_by_NID(x: PX509_CRL; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function X509_CRL_get_ext_by_OBJ(x: PX509_CRL; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function X509_CRL_get_ext_by_critical(x: PX509_CRL; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function X509_CRL_get_ext(x: PX509_CRL; loc: TIdC_INT): PX509_EXTENSION; cdecl;
function X509_CRL_delete_ext(x: PX509_CRL; loc: TIdC_INT): PX509_EXTENSION; cdecl;
function X509_CRL_add_ext(x: PX509_CRL; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl;
function X509_CRL_get_ext_d2i(x: PX509_CRL; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl;
function X509_CRL_add1_ext_i2d(x: PX509_CRL; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl;
function X509_REVOKED_get_ext_count(x: PX509_REVOKED): TIdC_INT; cdecl;
function X509_REVOKED_get_ext_by_NID(x: PX509_REVOKED; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function X509_REVOKED_get_ext_by_OBJ(x: PX509_REVOKED; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function X509_REVOKED_get_ext_by_critical(x: PX509_REVOKED; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function X509_REVOKED_get_ext(x: PX509_REVOKED; loc: TIdC_INT): PX509_EXTENSION; cdecl;
function X509_REVOKED_delete_ext(x: PX509_REVOKED; loc: TIdC_INT): PX509_EXTENSION; cdecl;
function X509_REVOKED_add_ext(x: PX509_REVOKED; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl;
function X509_REVOKED_get_ext_d2i(x: PX509_REVOKED; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl;
function X509_REVOKED_add1_ext_i2d(x: PX509_REVOKED; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl;
function X509_EXTENSION_create_by_NID(ex: PPX509_EXTENSION; nid: TIdC_INT; crit: TIdC_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION; cdecl;
function X509_EXTENSION_create_by_OBJ(ex: PPX509_EXTENSION; obj: PASN1_OBJECT; crit: TIdC_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION; cdecl;
function X509_EXTENSION_set_object(ex: PX509_EXTENSION; obj: PASN1_OBJECT): TIdC_INT; cdecl;
function X509_EXTENSION_set_critical(ex: PX509_EXTENSION; crit: TIdC_INT): TIdC_INT; cdecl;
function X509_EXTENSION_set_data(ex: PX509_EXTENSION; data: PASN1_OCTET_STRING): TIdC_INT; cdecl;
function X509_EXTENSION_get_object(ex: PX509_EXTENSION): PASN1_OBJECT; cdecl;
function X509_EXTENSION_get_data(ne: PX509_EXTENSION): PASN1_OCTET_STRING; cdecl;
function X509_EXTENSION_get_critical(ex: PX509_EXTENSION): TIdC_INT; cdecl;
function X509at_get_attr_count(x: Pstack_st_X509_ATTRIBUTE): TIdC_INT; cdecl;
function X509at_get_attr_by_NID(x: Pstack_st_X509_ATTRIBUTE; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function X509at_get_attr_by_OBJ(sk: Pstack_st_X509_ATTRIBUTE; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function X509at_get_attr(x: Pstack_st_X509_ATTRIBUTE; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl;
function X509at_delete_attr(x: Pstack_st_X509_ATTRIBUTE; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl;
function X509at_add1_attr(x: PPstack_st_X509_ATTRIBUTE; attr: PX509_ATTRIBUTE): Pstack_st_X509_ATTRIBUTE; cdecl;
function X509at_add1_attr_by_OBJ(x: PPstack_st_X509_ATTRIBUTE; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): Pstack_st_X509_ATTRIBUTE; cdecl;
function X509at_add1_attr_by_NID(x: PPstack_st_X509_ATTRIBUTE; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): Pstack_st_X509_ATTRIBUTE; cdecl;
function X509at_add1_attr_by_txt(x: PPstack_st_X509_ATTRIBUTE; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): Pstack_st_X509_ATTRIBUTE; cdecl;
function X509at_get0_data_by_OBJ(x: Pstack_st_X509_ATTRIBUTE; obj: PASN1_OBJECT; lastpos: TIdC_INT; _type: TIdC_INT): Pointer; cdecl;
function X509_ATTRIBUTE_create_by_NID(attr: PPX509_ATTRIBUTE; nid: TIdC_INT; atrtype: TIdC_INT; data: Pointer; len: TIdC_INT): PX509_ATTRIBUTE; cdecl;
function X509_ATTRIBUTE_create_by_OBJ(attr: PPX509_ATTRIBUTE; obj: PASN1_OBJECT; atrtype: TIdC_INT; data: Pointer; len: TIdC_INT): PX509_ATTRIBUTE; cdecl;
function X509_ATTRIBUTE_create_by_txt(attr: PPX509_ATTRIBUTE; atrname: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): PX509_ATTRIBUTE; cdecl;
function X509_ATTRIBUTE_set1_object(attr: PX509_ATTRIBUTE; obj: PASN1_OBJECT): TIdC_INT; cdecl;
function X509_ATTRIBUTE_set1_data(attr: PX509_ATTRIBUTE; attrtype: TIdC_INT; data: Pointer; len: TIdC_INT): TIdC_INT; cdecl;
function X509_ATTRIBUTE_get0_data(attr: PX509_ATTRIBUTE; idx: TIdC_INT; atrtype: TIdC_INT; data: Pointer): Pointer; cdecl;
function X509_ATTRIBUTE_count(attr: PX509_ATTRIBUTE): TIdC_INT; cdecl;
function X509_ATTRIBUTE_get0_object(attr: PX509_ATTRIBUTE): PASN1_OBJECT; cdecl;
function X509_ATTRIBUTE_get0_type(attr: PX509_ATTRIBUTE; idx: TIdC_INT): PASN1_TYPE; cdecl;
function EVP_PKEY_get_attr_count(key: PEVP_PKEY): TIdC_INT; cdecl;
function EVP_PKEY_get_attr_by_NID(key: PEVP_PKEY; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_get_attr_by_OBJ(key: PEVP_PKEY; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_get_attr(key: PEVP_PKEY; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl;
function EVP_PKEY_delete_attr(key: PEVP_PKEY; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl;
function EVP_PKEY_add1_attr(key: PEVP_PKEY; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl;
function EVP_PKEY_add1_attr_by_OBJ(key: PEVP_PKEY; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_add1_attr_by_NID(key: PEVP_PKEY; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function EVP_PKEY_add1_attr_by_txt(key: PEVP_PKEY; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function X509_find_by_issuer_and_serial(sk: Pstack_st_X509; name: PX509_NAME; serial: PASN1_INTEGER): PX509; cdecl;
function X509_find_by_subject(sk: Pstack_st_X509; name: PX509_NAME): PX509; cdecl;
function PBEPARAM_new: PPBEPARAM; cdecl;
procedure PBEPARAM_free(a: PPBEPARAM); cdecl;
function d2i_PBEPARAM(a: PPPBEPARAM; _in: PPIdAnsiChar; len: TIdC_LONG): PPBEPARAM; cdecl;
function i2d_PBEPARAM(a: PPBEPARAM; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function PBEPARAM_it: PASN1_ITEM; cdecl;
function PBE2PARAM_new: PPBE2PARAM; cdecl;
procedure PBE2PARAM_free(a: PPBE2PARAM); cdecl;
function d2i_PBE2PARAM(a: PPPBE2PARAM; _in: PPIdAnsiChar; len: TIdC_LONG): PPBE2PARAM; cdecl;
function i2d_PBE2PARAM(a: PPBE2PARAM; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function PBE2PARAM_it: PASN1_ITEM; cdecl;
function PBKDF2PARAM_new: PPBKDF2PARAM; cdecl;
procedure PBKDF2PARAM_free(a: PPBKDF2PARAM); cdecl;
function d2i_PBKDF2PARAM(a: PPPBKDF2PARAM; _in: PPIdAnsiChar; len: TIdC_LONG): PPBKDF2PARAM; cdecl;
function i2d_PBKDF2PARAM(a: PPBKDF2PARAM; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function PBKDF2PARAM_it: PASN1_ITEM; cdecl;
function PBMAC1PARAM_new: PPBMAC1PARAM; cdecl;
procedure PBMAC1PARAM_free(a: PPBMAC1PARAM); cdecl;
function d2i_PBMAC1PARAM(a: PPPBMAC1PARAM; _in: PPIdAnsiChar; len: TIdC_LONG): PPBMAC1PARAM; cdecl;
function i2d_PBMAC1PARAM(a: PPBMAC1PARAM; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function PBMAC1PARAM_it: PASN1_ITEM; cdecl;
function SCRYPT_PARAMS_new: PSCRYPT_PARAMS; cdecl;
procedure SCRYPT_PARAMS_free(a: PSCRYPT_PARAMS); cdecl;
function d2i_SCRYPT_PARAMS(a: PPSCRYPT_PARAMS; _in: PPIdAnsiChar; len: TIdC_LONG): PSCRYPT_PARAMS; cdecl;
function i2d_SCRYPT_PARAMS(a: PSCRYPT_PARAMS; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function SCRYPT_PARAMS_it: PASN1_ITEM; cdecl;
function PKCS5_pbe_set0_algor(algor: PX509_ALGOR; alg: TIdC_INT; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT): TIdC_INT; cdecl;
function PKCS5_pbe_set0_algor_ex(algor: PX509_ALGOR; alg: TIdC_INT; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; libctx: POSSL_LIB_CTX): TIdC_INT; cdecl;
function PKCS5_pbe_set(alg: TIdC_INT; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT): PX509_ALGOR; cdecl;
function PKCS5_pbe_set_ex(alg: TIdC_INT; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; libctx: POSSL_LIB_CTX): PX509_ALGOR; cdecl;
function PKCS5_pbe2_set(cipher: PEVP_CIPHER; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT): PX509_ALGOR; cdecl;
function PKCS5_pbe2_set_iv(cipher: PEVP_CIPHER; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; aiv: PIdAnsiChar; prf_nid: TIdC_INT): PX509_ALGOR; cdecl;
function PKCS5_pbe2_set_iv_ex(cipher: PEVP_CIPHER; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; aiv: PIdAnsiChar; prf_nid: TIdC_INT; libctx: POSSL_LIB_CTX): PX509_ALGOR; cdecl;
function PKCS5_pbe2_set_scrypt(cipher: PEVP_CIPHER; salt: PIdAnsiChar; saltlen: TIdC_INT; aiv: PIdAnsiChar; N: TIdC_UINT64; r: TIdC_UINT64; p: TIdC_UINT64): PX509_ALGOR; cdecl;
function PKCS5_pbkdf2_set(iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; prf_nid: TIdC_INT; keylen: TIdC_INT): PX509_ALGOR; cdecl;
function PKCS5_pbkdf2_set_ex(iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; prf_nid: TIdC_INT; keylen: TIdC_INT; libctx: POSSL_LIB_CTX): PX509_ALGOR; cdecl;
function PBMAC1_get1_pbkdf2_param(macalg: PX509_ALGOR): PPBKDF2PARAM; cdecl;
function PKCS8_PRIV_KEY_INFO_new: PPKCS8_PRIV_KEY_INFO; cdecl;
procedure PKCS8_PRIV_KEY_INFO_free(a: PPKCS8_PRIV_KEY_INFO); cdecl;
function d2i_PKCS8_PRIV_KEY_INFO(a: PPPKCS8_PRIV_KEY_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS8_PRIV_KEY_INFO; cdecl;
function i2d_PKCS8_PRIV_KEY_INFO(a: PPKCS8_PRIV_KEY_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function PKCS8_PRIV_KEY_INFO_it: PASN1_ITEM; cdecl;
function EVP_PKCS82PKEY(p8: PPKCS8_PRIV_KEY_INFO): PEVP_PKEY; cdecl;
function EVP_PKCS82PKEY_ex(p8: PPKCS8_PRIV_KEY_INFO; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl;
function EVP_PKEY2PKCS8(pkey: PEVP_PKEY): PPKCS8_PRIV_KEY_INFO; cdecl;
function PKCS8_pkey_set0(priv: PPKCS8_PRIV_KEY_INFO; aobj: PASN1_OBJECT; version: TIdC_INT; ptype: TIdC_INT; pval: Pointer; penc: PIdAnsiChar; penclen: TIdC_INT): TIdC_INT; cdecl;
function PKCS8_pkey_get0(ppkalg: PPASN1_OBJECT; pk: PPIdAnsiChar; ppklen: PIdC_INT; pa: PPX509_ALGOR; p8: PPKCS8_PRIV_KEY_INFO): TIdC_INT; cdecl;
function PKCS8_pkey_get0_attrs(p8: PPKCS8_PRIV_KEY_INFO): Pstack_st_X509_ATTRIBUTE; cdecl;
function PKCS8_pkey_add1_attr(p8: PPKCS8_PRIV_KEY_INFO; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl;
function PKCS8_pkey_add1_attr_by_NID(p8: PPKCS8_PRIV_KEY_INFO; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function PKCS8_pkey_add1_attr_by_OBJ(p8: PPKCS8_PRIV_KEY_INFO; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
procedure X509_PUBKEY_set0_public_key(pub: PX509_PUBKEY; penc: PIdAnsiChar; penclen: TIdC_INT); cdecl;
function X509_PUBKEY_set0_param(pub: PX509_PUBKEY; aobj: PASN1_OBJECT; ptype: TIdC_INT; pval: Pointer; penc: PIdAnsiChar; penclen: TIdC_INT): TIdC_INT; cdecl;
function X509_PUBKEY_get0_param(ppkalg: PPASN1_OBJECT; pk: PPIdAnsiChar; ppklen: PIdC_INT; pa: PPX509_ALGOR; pub: PX509_PUBKEY): TIdC_INT; cdecl;
function X509_PUBKEY_eq(a: PX509_PUBKEY; b: PX509_PUBKEY): TIdC_INT; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_http_nbio(rctx: Pointer; pcert: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_CRL_http_nbio(rctx: Pointer; pcrl: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_NAME_hash(x: Pointer): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_get_notBefore(x: PX509): PASN1_TIME; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_get_notAfter(x: PX509): PASN1_TIME; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_set_notBefore(x: PX509; tm: PASN1_TIME): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_set_notAfter(x: PX509; tm: PASN1_TIME): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_CRL_set_lastUpdate(x: PX509_CRL; tm: PASN1_TIME): TIdC_INT; cdecl;

  { TODO 1 -cID Macro/Inline Routine : Manual implementation required. }
  // function X509_CRL_set_nextUpdate(x: PX509_CRL; tm: PASN1_TIME): TIdC_INT; cdecl;


// =============================================================================
// OPENSSL STACK DEFINITIONS
// =============================================================================
type
  { TODO 1 -copenssl stack X509_NAME definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_X509_NAME = Pointer;
  {$EXTERNALSYM PSTACK_OF_X509_NAME}

  { Original Stack Macros for X509_NAME:
    SKM_DEFINE_STACK_OF_INTERNAL(X509_NAME, X509_NAME, X509_NAME)
    sk_X509_NAME_num(sk) OPENSSL_sk_num(ossl_check_const_X509_NAME_sk_type(sk))
    sk_X509_NAME_value(sk, idx) ((X509_NAME *)OPENSSL_sk_value(ossl_check_const_X509_NAME_sk_type(sk), (idx)))
    sk_X509_NAME_new(cmp) ((STACK_OF(X509_NAME) *)OPENSSL_sk_new(ossl_check_X509_NAME_compfunc_type(cmp)))
    sk_X509_NAME_new_null() ((STACK_OF(X509_NAME) *)OPENSSL_sk_new_null())
    sk_X509_NAME_new_reserve(cmp, n) ((STACK_OF(X509_NAME) *)OPENSSL_sk_new_reserve(ossl_check_X509_NAME_compfunc_type(cmp), (n)))
    sk_X509_NAME_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_X509_NAME_sk_type(sk), (n))
    sk_X509_NAME_free(sk) OPENSSL_sk_free(ossl_check_X509_NAME_sk_type(sk))
    sk_X509_NAME_zero(sk) OPENSSL_sk_zero(ossl_check_X509_NAME_sk_type(sk))
    sk_X509_NAME_delete(sk, i) ((X509_NAME *)OPENSSL_sk_delete(ossl_check_X509_NAME_sk_type(sk), (i)))
    sk_X509_NAME_delete_ptr(sk, ptr) ((X509_NAME *)OPENSSL_sk_delete_ptr(ossl_check_X509_NAME_sk_type(sk), ossl_check_X509_NAME_type(ptr)))
    sk_X509_NAME_push(sk, ptr) OPENSSL_sk_push(ossl_check_X509_NAME_sk_type(sk), ossl_check_X509_NAME_type(ptr))
    sk_X509_NAME_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_X509_NAME_sk_type(sk), ossl_check_X509_NAME_type(ptr))
    sk_X509_NAME_pop(sk) ((X509_NAME *)OPENSSL_sk_pop(ossl_check_X509_NAME_sk_type(sk)))
    sk_X509_NAME_shift(sk) ((X509_NAME *)OPENSSL_sk_shift(ossl_check_X509_NAME_sk_type(sk)))
    sk_X509_NAME_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_X509_NAME_sk_type(sk), ossl_check_X509_NAME_freefunc_type(freefunc))
    sk_X509_NAME_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_X509_NAME_sk_type(sk), ossl_check_X509_NAME_type(ptr), (idx))
    sk_X509_NAME_set(sk, idx, ptr) ((X509_NAME *)OPENSSL_sk_set(ossl_check_X509_NAME_sk_type(sk), (idx), ossl_check_X509_NAME_type(ptr)))
    sk_X509_NAME_find(sk, ptr) OPENSSL_sk_find(ossl_check_X509_NAME_sk_type(sk), ossl_check_X509_NAME_type(ptr))
    sk_X509_NAME_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_X509_NAME_sk_type(sk), ossl_check_X509_NAME_type(ptr))
    sk_X509_NAME_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_X509_NAME_sk_type(sk), ossl_check_X509_NAME_type(ptr), pnum)
    sk_X509_NAME_sort(sk) OPENSSL_sk_sort(ossl_check_X509_NAME_sk_type(sk))
    sk_X509_NAME_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_X509_NAME_sk_type(sk))
    sk_X509_NAME_dup(sk) ((STACK_OF(X509_NAME) *)OPENSSL_sk_dup(ossl_check_const_X509_NAME_sk_type(sk)))
    sk_X509_NAME_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(X509_NAME) *)OPENSSL_sk_deep_copy(ossl_check_const_X509_NAME_sk_type(sk), ossl_check_X509_NAME_copyfunc_type(copyfunc), ossl_check_X509_NAME_freefunc_type(freefunc)))
    sk_X509_NAME_set_cmp_func(sk, cmp) ((sk_X509_NAME_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_X509_NAME_sk_type(sk), ossl_check_X509_NAME_compfunc_type(cmp)))
    sk_X509_NAME_ENTRY_num(sk) OPENSSL_sk_num(ossl_check_const_X509_NAME_ENTRY_sk_type(sk))
    sk_X509_NAME_ENTRY_value(sk, idx) ((X509_NAME_ENTRY *)OPENSSL_sk_value(ossl_check_const_X509_NAME_ENTRY_sk_type(sk), (idx)))
    sk_X509_NAME_ENTRY_new(cmp) ((STACK_OF(X509_NAME_ENTRY) *)OPENSSL_sk_new(ossl_check_X509_NAME_ENTRY_compfunc_type(cmp)))
    sk_X509_NAME_ENTRY_new_null() ((STACK_OF(X509_NAME_ENTRY) *)OPENSSL_sk_new_null())
    sk_X509_NAME_ENTRY_new_reserve(cmp, n) ((STACK_OF(X509_NAME_ENTRY) *)OPENSSL_sk_new_reserve(ossl_check_X509_NAME_ENTRY_compfunc_type(cmp), (n)))
    sk_X509_NAME_ENTRY_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_X509_NAME_ENTRY_sk_type(sk), (n))
    sk_X509_NAME_ENTRY_free(sk) OPENSSL_sk_free(ossl_check_X509_NAME_ENTRY_sk_type(sk))
    sk_X509_NAME_ENTRY_zero(sk) OPENSSL_sk_zero(ossl_check_X509_NAME_ENTRY_sk_type(sk))
    sk_X509_NAME_ENTRY_delete(sk, i) ((X509_NAME_ENTRY *)OPENSSL_sk_delete(ossl_check_X509_NAME_ENTRY_sk_type(sk), (i)))
    sk_X509_NAME_ENTRY_delete_ptr(sk, ptr) ((X509_NAME_ENTRY *)OPENSSL_sk_delete_ptr(ossl_check_X509_NAME_ENTRY_sk_type(sk), ossl_check_X509_NAME_ENTRY_type(ptr)))
    sk_X509_NAME_ENTRY_push(sk, ptr) OPENSSL_sk_push(ossl_check_X509_NAME_ENTRY_sk_type(sk), ossl_check_X509_NAME_ENTRY_type(ptr))
    sk_X509_NAME_ENTRY_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_X509_NAME_ENTRY_sk_type(sk), ossl_check_X509_NAME_ENTRY_type(ptr))
    sk_X509_NAME_ENTRY_pop(sk) ((X509_NAME_ENTRY *)OPENSSL_sk_pop(ossl_check_X509_NAME_ENTRY_sk_type(sk)))
    sk_X509_NAME_ENTRY_shift(sk) ((X509_NAME_ENTRY *)OPENSSL_sk_shift(ossl_check_X509_NAME_ENTRY_sk_type(sk)))
    sk_X509_NAME_ENTRY_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_X509_NAME_ENTRY_sk_type(sk), ossl_check_X509_NAME_ENTRY_freefunc_type(freefunc))
    sk_X509_NAME_ENTRY_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_X509_NAME_ENTRY_sk_type(sk), ossl_check_X509_NAME_ENTRY_type(ptr), (idx))
    sk_X509_NAME_ENTRY_set(sk, idx, ptr) ((X509_NAME_ENTRY *)OPENSSL_sk_set(ossl_check_X509_NAME_ENTRY_sk_type(sk), (idx), ossl_check_X509_NAME_ENTRY_type(ptr)))
    sk_X509_NAME_ENTRY_find(sk, ptr) OPENSSL_sk_find(ossl_check_X509_NAME_ENTRY_sk_type(sk), ossl_check_X509_NAME_ENTRY_type(ptr))
    sk_X509_NAME_ENTRY_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_X509_NAME_ENTRY_sk_type(sk), ossl_check_X509_NAME_ENTRY_type(ptr))
    sk_X509_NAME_ENTRY_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_X509_NAME_ENTRY_sk_type(sk), ossl_check_X509_NAME_ENTRY_type(ptr), pnum)
    sk_X509_NAME_ENTRY_sort(sk) OPENSSL_sk_sort(ossl_check_X509_NAME_ENTRY_sk_type(sk))
    sk_X509_NAME_ENTRY_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_X509_NAME_ENTRY_sk_type(sk))
    sk_X509_NAME_ENTRY_dup(sk) ((STACK_OF(X509_NAME_ENTRY) *)OPENSSL_sk_dup(ossl_check_const_X509_NAME_ENTRY_sk_type(sk)))
    sk_X509_NAME_ENTRY_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(X509_NAME_ENTRY) *)OPENSSL_sk_deep_copy(ossl_check_const_X509_NAME_ENTRY_sk_type(sk), ossl_check_X509_NAME_ENTRY_copyfunc_type(copyfunc), ossl_check_X509_NAME_ENTRY_freefunc_type(freefunc)))
    sk_X509_NAME_ENTRY_set_cmp_func(sk, cmp) ((sk_X509_NAME_ENTRY_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_X509_NAME_ENTRY_sk_type(sk), ossl_check_X509_NAME_ENTRY_compfunc_type(cmp)))
  }

  { TODO 1 -copenssl stack X509 definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_X509 = Pointer;
  {$EXTERNALSYM PSTACK_OF_X509}

  { Original Stack Macros for X509:
    SKM_DEFINE_STACK_OF_INTERNAL(X509, X509, X509)
    sk_X509_num(sk) OPENSSL_sk_num(ossl_check_const_X509_sk_type(sk))
    sk_X509_value(sk, idx) ((X509 *)OPENSSL_sk_value(ossl_check_const_X509_sk_type(sk), (idx)))
    sk_X509_new(cmp) ((STACK_OF(X509) *)OPENSSL_sk_new(ossl_check_X509_compfunc_type(cmp)))
    sk_X509_new_null() ((STACK_OF(X509) *)OPENSSL_sk_new_null())
    sk_X509_new_reserve(cmp, n) ((STACK_OF(X509) *)OPENSSL_sk_new_reserve(ossl_check_X509_compfunc_type(cmp), (n)))
    sk_X509_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_X509_sk_type(sk), (n))
    sk_X509_free(sk) OPENSSL_sk_free(ossl_check_X509_sk_type(sk))
    sk_X509_zero(sk) OPENSSL_sk_zero(ossl_check_X509_sk_type(sk))
    sk_X509_delete(sk, i) ((X509 *)OPENSSL_sk_delete(ossl_check_X509_sk_type(sk), (i)))
    sk_X509_delete_ptr(sk, ptr) ((X509 *)OPENSSL_sk_delete_ptr(ossl_check_X509_sk_type(sk), ossl_check_X509_type(ptr)))
    sk_X509_push(sk, ptr) OPENSSL_sk_push(ossl_check_X509_sk_type(sk), ossl_check_X509_type(ptr))
    sk_X509_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_X509_sk_type(sk), ossl_check_X509_type(ptr))
    sk_X509_pop(sk) ((X509 *)OPENSSL_sk_pop(ossl_check_X509_sk_type(sk)))
    sk_X509_shift(sk) ((X509 *)OPENSSL_sk_shift(ossl_check_X509_sk_type(sk)))
    sk_X509_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_X509_sk_type(sk), ossl_check_X509_freefunc_type(freefunc))
    sk_X509_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_X509_sk_type(sk), ossl_check_X509_type(ptr), (idx))
    sk_X509_set(sk, idx, ptr) ((X509 *)OPENSSL_sk_set(ossl_check_X509_sk_type(sk), (idx), ossl_check_X509_type(ptr)))
    sk_X509_find(sk, ptr) OPENSSL_sk_find(ossl_check_X509_sk_type(sk), ossl_check_X509_type(ptr))
    sk_X509_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_X509_sk_type(sk), ossl_check_X509_type(ptr))
    sk_X509_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_X509_sk_type(sk), ossl_check_X509_type(ptr), pnum)
    sk_X509_sort(sk) OPENSSL_sk_sort(ossl_check_X509_sk_type(sk))
    sk_X509_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_X509_sk_type(sk))
    sk_X509_dup(sk) ((STACK_OF(X509) *)OPENSSL_sk_dup(ossl_check_const_X509_sk_type(sk)))
    sk_X509_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(X509) *)OPENSSL_sk_deep_copy(ossl_check_const_X509_sk_type(sk), ossl_check_X509_copyfunc_type(copyfunc), ossl_check_X509_freefunc_type(freefunc)))
    sk_X509_set_cmp_func(sk, cmp) ((sk_X509_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_X509_sk_type(sk), ossl_check_X509_compfunc_type(cmp)))
    sk_X509_REVOKED_num(sk) OPENSSL_sk_num(ossl_check_const_X509_REVOKED_sk_type(sk))
    sk_X509_REVOKED_value(sk, idx) ((X509_REVOKED *)OPENSSL_sk_value(ossl_check_const_X509_REVOKED_sk_type(sk), (idx)))
    sk_X509_REVOKED_new(cmp) ((STACK_OF(X509_REVOKED) *)OPENSSL_sk_new(ossl_check_X509_REVOKED_compfunc_type(cmp)))
    sk_X509_REVOKED_new_null() ((STACK_OF(X509_REVOKED) *)OPENSSL_sk_new_null())
    sk_X509_REVOKED_new_reserve(cmp, n) ((STACK_OF(X509_REVOKED) *)OPENSSL_sk_new_reserve(ossl_check_X509_REVOKED_compfunc_type(cmp), (n)))
    sk_X509_REVOKED_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_X509_REVOKED_sk_type(sk), (n))
    sk_X509_REVOKED_free(sk) OPENSSL_sk_free(ossl_check_X509_REVOKED_sk_type(sk))
    sk_X509_REVOKED_zero(sk) OPENSSL_sk_zero(ossl_check_X509_REVOKED_sk_type(sk))
    sk_X509_REVOKED_delete(sk, i) ((X509_REVOKED *)OPENSSL_sk_delete(ossl_check_X509_REVOKED_sk_type(sk), (i)))
    sk_X509_REVOKED_delete_ptr(sk, ptr) ((X509_REVOKED *)OPENSSL_sk_delete_ptr(ossl_check_X509_REVOKED_sk_type(sk), ossl_check_X509_REVOKED_type(ptr)))
    sk_X509_REVOKED_push(sk, ptr) OPENSSL_sk_push(ossl_check_X509_REVOKED_sk_type(sk), ossl_check_X509_REVOKED_type(ptr))
    sk_X509_REVOKED_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_X509_REVOKED_sk_type(sk), ossl_check_X509_REVOKED_type(ptr))
    sk_X509_REVOKED_pop(sk) ((X509_REVOKED *)OPENSSL_sk_pop(ossl_check_X509_REVOKED_sk_type(sk)))
    sk_X509_REVOKED_shift(sk) ((X509_REVOKED *)OPENSSL_sk_shift(ossl_check_X509_REVOKED_sk_type(sk)))
    sk_X509_REVOKED_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_X509_REVOKED_sk_type(sk), ossl_check_X509_REVOKED_freefunc_type(freefunc))
    sk_X509_REVOKED_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_X509_REVOKED_sk_type(sk), ossl_check_X509_REVOKED_type(ptr), (idx))
    sk_X509_REVOKED_set(sk, idx, ptr) ((X509_REVOKED *)OPENSSL_sk_set(ossl_check_X509_REVOKED_sk_type(sk), (idx), ossl_check_X509_REVOKED_type(ptr)))
    sk_X509_REVOKED_find(sk, ptr) OPENSSL_sk_find(ossl_check_X509_REVOKED_sk_type(sk), ossl_check_X509_REVOKED_type(ptr))
    sk_X509_REVOKED_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_X509_REVOKED_sk_type(sk), ossl_check_X509_REVOKED_type(ptr))
    sk_X509_REVOKED_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_X509_REVOKED_sk_type(sk), ossl_check_X509_REVOKED_type(ptr), pnum)
    sk_X509_REVOKED_sort(sk) OPENSSL_sk_sort(ossl_check_X509_REVOKED_sk_type(sk))
    sk_X509_REVOKED_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_X509_REVOKED_sk_type(sk))
    sk_X509_REVOKED_dup(sk) ((STACK_OF(X509_REVOKED) *)OPENSSL_sk_dup(ossl_check_const_X509_REVOKED_sk_type(sk)))
    sk_X509_REVOKED_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(X509_REVOKED) *)OPENSSL_sk_deep_copy(ossl_check_const_X509_REVOKED_sk_type(sk), ossl_check_X509_REVOKED_copyfunc_type(copyfunc), ossl_check_X509_REVOKED_freefunc_type(freefunc)))
    sk_X509_REVOKED_set_cmp_func(sk, cmp) ((sk_X509_REVOKED_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_X509_REVOKED_sk_type(sk), ossl_check_X509_REVOKED_compfunc_type(cmp)))
    sk_X509_CRL_num(sk) OPENSSL_sk_num(ossl_check_const_X509_CRL_sk_type(sk))
    sk_X509_CRL_value(sk, idx) ((X509_CRL *)OPENSSL_sk_value(ossl_check_const_X509_CRL_sk_type(sk), (idx)))
    sk_X509_CRL_new(cmp) ((STACK_OF(X509_CRL) *)OPENSSL_sk_new(ossl_check_X509_CRL_compfunc_type(cmp)))
    sk_X509_CRL_new_null() ((STACK_OF(X509_CRL) *)OPENSSL_sk_new_null())
    sk_X509_CRL_new_reserve(cmp, n) ((STACK_OF(X509_CRL) *)OPENSSL_sk_new_reserve(ossl_check_X509_CRL_compfunc_type(cmp), (n)))
    sk_X509_CRL_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_X509_CRL_sk_type(sk), (n))
    sk_X509_CRL_free(sk) OPENSSL_sk_free(ossl_check_X509_CRL_sk_type(sk))
    sk_X509_CRL_zero(sk) OPENSSL_sk_zero(ossl_check_X509_CRL_sk_type(sk))
    sk_X509_CRL_delete(sk, i) ((X509_CRL *)OPENSSL_sk_delete(ossl_check_X509_CRL_sk_type(sk), (i)))
    sk_X509_CRL_delete_ptr(sk, ptr) ((X509_CRL *)OPENSSL_sk_delete_ptr(ossl_check_X509_CRL_sk_type(sk), ossl_check_X509_CRL_type(ptr)))
    sk_X509_CRL_push(sk, ptr) OPENSSL_sk_push(ossl_check_X509_CRL_sk_type(sk), ossl_check_X509_CRL_type(ptr))
    sk_X509_CRL_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_X509_CRL_sk_type(sk), ossl_check_X509_CRL_type(ptr))
    sk_X509_CRL_pop(sk) ((X509_CRL *)OPENSSL_sk_pop(ossl_check_X509_CRL_sk_type(sk)))
    sk_X509_CRL_shift(sk) ((X509_CRL *)OPENSSL_sk_shift(ossl_check_X509_CRL_sk_type(sk)))
    sk_X509_CRL_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_X509_CRL_sk_type(sk), ossl_check_X509_CRL_freefunc_type(freefunc))
    sk_X509_CRL_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_X509_CRL_sk_type(sk), ossl_check_X509_CRL_type(ptr), (idx))
    sk_X509_CRL_set(sk, idx, ptr) ((X509_CRL *)OPENSSL_sk_set(ossl_check_X509_CRL_sk_type(sk), (idx), ossl_check_X509_CRL_type(ptr)))
    sk_X509_CRL_find(sk, ptr) OPENSSL_sk_find(ossl_check_X509_CRL_sk_type(sk), ossl_check_X509_CRL_type(ptr))
    sk_X509_CRL_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_X509_CRL_sk_type(sk), ossl_check_X509_CRL_type(ptr))
    sk_X509_CRL_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_X509_CRL_sk_type(sk), ossl_check_X509_CRL_type(ptr), pnum)
    sk_X509_CRL_sort(sk) OPENSSL_sk_sort(ossl_check_X509_CRL_sk_type(sk))
    sk_X509_CRL_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_X509_CRL_sk_type(sk))
    sk_X509_CRL_dup(sk) ((STACK_OF(X509_CRL) *)OPENSSL_sk_dup(ossl_check_const_X509_CRL_sk_type(sk)))
    sk_X509_CRL_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(X509_CRL) *)OPENSSL_sk_deep_copy(ossl_check_const_X509_CRL_sk_type(sk), ossl_check_X509_CRL_copyfunc_type(copyfunc), ossl_check_X509_CRL_freefunc_type(freefunc)))
    sk_X509_CRL_set_cmp_func(sk, cmp) ((sk_X509_CRL_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_X509_CRL_sk_type(sk), ossl_check_X509_CRL_compfunc_type(cmp)))
    sk_X509_EXTENSION_num(sk) OPENSSL_sk_num(ossl_check_const_X509_EXTENSION_sk_type(sk))
    sk_X509_EXTENSION_value(sk, idx) ((X509_EXTENSION *)OPENSSL_sk_value(ossl_check_const_X509_EXTENSION_sk_type(sk), (idx)))
    sk_X509_EXTENSION_new(cmp) ((STACK_OF(X509_EXTENSION) *)OPENSSL_sk_new(ossl_check_X509_EXTENSION_compfunc_type(cmp)))
    sk_X509_EXTENSION_new_null() ((STACK_OF(X509_EXTENSION) *)OPENSSL_sk_new_null())
    sk_X509_EXTENSION_new_reserve(cmp, n) ((STACK_OF(X509_EXTENSION) *)OPENSSL_sk_new_reserve(ossl_check_X509_EXTENSION_compfunc_type(cmp), (n)))
    sk_X509_EXTENSION_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_X509_EXTENSION_sk_type(sk), (n))
    sk_X509_EXTENSION_free(sk) OPENSSL_sk_free(ossl_check_X509_EXTENSION_sk_type(sk))
    sk_X509_EXTENSION_zero(sk) OPENSSL_sk_zero(ossl_check_X509_EXTENSION_sk_type(sk))
    sk_X509_EXTENSION_delete(sk, i) ((X509_EXTENSION *)OPENSSL_sk_delete(ossl_check_X509_EXTENSION_sk_type(sk), (i)))
    sk_X509_EXTENSION_delete_ptr(sk, ptr) ((X509_EXTENSION *)OPENSSL_sk_delete_ptr(ossl_check_X509_EXTENSION_sk_type(sk), ossl_check_X509_EXTENSION_type(ptr)))
    sk_X509_EXTENSION_push(sk, ptr) OPENSSL_sk_push(ossl_check_X509_EXTENSION_sk_type(sk), ossl_check_X509_EXTENSION_type(ptr))
    sk_X509_EXTENSION_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_X509_EXTENSION_sk_type(sk), ossl_check_X509_EXTENSION_type(ptr))
    sk_X509_EXTENSION_pop(sk) ((X509_EXTENSION *)OPENSSL_sk_pop(ossl_check_X509_EXTENSION_sk_type(sk)))
    sk_X509_EXTENSION_shift(sk) ((X509_EXTENSION *)OPENSSL_sk_shift(ossl_check_X509_EXTENSION_sk_type(sk)))
    sk_X509_EXTENSION_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_X509_EXTENSION_sk_type(sk), ossl_check_X509_EXTENSION_freefunc_type(freefunc))
    sk_X509_EXTENSION_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_X509_EXTENSION_sk_type(sk), ossl_check_X509_EXTENSION_type(ptr), (idx))
    sk_X509_EXTENSION_set(sk, idx, ptr) ((X509_EXTENSION *)OPENSSL_sk_set(ossl_check_X509_EXTENSION_sk_type(sk), (idx), ossl_check_X509_EXTENSION_type(ptr)))
    sk_X509_EXTENSION_find(sk, ptr) OPENSSL_sk_find(ossl_check_X509_EXTENSION_sk_type(sk), ossl_check_X509_EXTENSION_type(ptr))
    sk_X509_EXTENSION_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_X509_EXTENSION_sk_type(sk), ossl_check_X509_EXTENSION_type(ptr))
    sk_X509_EXTENSION_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_X509_EXTENSION_sk_type(sk), ossl_check_X509_EXTENSION_type(ptr), pnum)
    sk_X509_EXTENSION_sort(sk) OPENSSL_sk_sort(ossl_check_X509_EXTENSION_sk_type(sk))
    sk_X509_EXTENSION_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_X509_EXTENSION_sk_type(sk))
    sk_X509_EXTENSION_dup(sk) ((STACK_OF(X509_EXTENSION) *)OPENSSL_sk_dup(ossl_check_const_X509_EXTENSION_sk_type(sk)))
    sk_X509_EXTENSION_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(X509_EXTENSION) *)OPENSSL_sk_deep_copy(ossl_check_const_X509_EXTENSION_sk_type(sk), ossl_check_X509_EXTENSION_copyfunc_type(copyfunc), ossl_check_X509_EXTENSION_freefunc_type(freefunc)))
    sk_X509_EXTENSION_set_cmp_func(sk, cmp) ((sk_X509_EXTENSION_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_X509_EXTENSION_sk_type(sk), ossl_check_X509_EXTENSION_compfunc_type(cmp)))
    sk_X509_ATTRIBUTE_num(sk) OPENSSL_sk_num(ossl_check_const_X509_ATTRIBUTE_sk_type(sk))
    sk_X509_ATTRIBUTE_value(sk, idx) ((X509_ATTRIBUTE *)OPENSSL_sk_value(ossl_check_const_X509_ATTRIBUTE_sk_type(sk), (idx)))
    sk_X509_ATTRIBUTE_new(cmp) ((STACK_OF(X509_ATTRIBUTE) *)OPENSSL_sk_new(ossl_check_X509_ATTRIBUTE_compfunc_type(cmp)))
    sk_X509_ATTRIBUTE_new_null() ((STACK_OF(X509_ATTRIBUTE) *)OPENSSL_sk_new_null())
    sk_X509_ATTRIBUTE_new_reserve(cmp, n) ((STACK_OF(X509_ATTRIBUTE) *)OPENSSL_sk_new_reserve(ossl_check_X509_ATTRIBUTE_compfunc_type(cmp), (n)))
    sk_X509_ATTRIBUTE_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_X509_ATTRIBUTE_sk_type(sk), (n))
    sk_X509_ATTRIBUTE_free(sk) OPENSSL_sk_free(ossl_check_X509_ATTRIBUTE_sk_type(sk))
    sk_X509_ATTRIBUTE_zero(sk) OPENSSL_sk_zero(ossl_check_X509_ATTRIBUTE_sk_type(sk))
    sk_X509_ATTRIBUTE_delete(sk, i) ((X509_ATTRIBUTE *)OPENSSL_sk_delete(ossl_check_X509_ATTRIBUTE_sk_type(sk), (i)))
    sk_X509_ATTRIBUTE_delete_ptr(sk, ptr) ((X509_ATTRIBUTE *)OPENSSL_sk_delete_ptr(ossl_check_X509_ATTRIBUTE_sk_type(sk), ossl_check_X509_ATTRIBUTE_type(ptr)))
    sk_X509_ATTRIBUTE_push(sk, ptr) OPENSSL_sk_push(ossl_check_X509_ATTRIBUTE_sk_type(sk), ossl_check_X509_ATTRIBUTE_type(ptr))
    sk_X509_ATTRIBUTE_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_X509_ATTRIBUTE_sk_type(sk), ossl_check_X509_ATTRIBUTE_type(ptr))
    sk_X509_ATTRIBUTE_pop(sk) ((X509_ATTRIBUTE *)OPENSSL_sk_pop(ossl_check_X509_ATTRIBUTE_sk_type(sk)))
    sk_X509_ATTRIBUTE_shift(sk) ((X509_ATTRIBUTE *)OPENSSL_sk_shift(ossl_check_X509_ATTRIBUTE_sk_type(sk)))
    sk_X509_ATTRIBUTE_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_X509_ATTRIBUTE_sk_type(sk), ossl_check_X509_ATTRIBUTE_freefunc_type(freefunc))
    sk_X509_ATTRIBUTE_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_X509_ATTRIBUTE_sk_type(sk), ossl_check_X509_ATTRIBUTE_type(ptr), (idx))
    sk_X509_ATTRIBUTE_set(sk, idx, ptr) ((X509_ATTRIBUTE *)OPENSSL_sk_set(ossl_check_X509_ATTRIBUTE_sk_type(sk), (idx), ossl_check_X509_ATTRIBUTE_type(ptr)))
    sk_X509_ATTRIBUTE_find(sk, ptr) OPENSSL_sk_find(ossl_check_X509_ATTRIBUTE_sk_type(sk), ossl_check_X509_ATTRIBUTE_type(ptr))
    sk_X509_ATTRIBUTE_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_X509_ATTRIBUTE_sk_type(sk), ossl_check_X509_ATTRIBUTE_type(ptr))
    sk_X509_ATTRIBUTE_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_X509_ATTRIBUTE_sk_type(sk), ossl_check_X509_ATTRIBUTE_type(ptr), pnum)
    sk_X509_ATTRIBUTE_sort(sk) OPENSSL_sk_sort(ossl_check_X509_ATTRIBUTE_sk_type(sk))
    sk_X509_ATTRIBUTE_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_X509_ATTRIBUTE_sk_type(sk))
    sk_X509_ATTRIBUTE_dup(sk) ((STACK_OF(X509_ATTRIBUTE) *)OPENSSL_sk_dup(ossl_check_const_X509_ATTRIBUTE_sk_type(sk)))
    sk_X509_ATTRIBUTE_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(X509_ATTRIBUTE) *)OPENSSL_sk_deep_copy(ossl_check_const_X509_ATTRIBUTE_sk_type(sk), ossl_check_X509_ATTRIBUTE_copyfunc_type(copyfunc), ossl_check_X509_ATTRIBUTE_freefunc_type(freefunc)))
    sk_X509_ATTRIBUTE_set_cmp_func(sk, cmp) ((sk_X509_ATTRIBUTE_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_X509_ATTRIBUTE_sk_type(sk), ossl_check_X509_ATTRIBUTE_compfunc_type(cmp)))
    sk_X509_INFO_num(sk) OPENSSL_sk_num(ossl_check_const_X509_INFO_sk_type(sk))
    sk_X509_INFO_value(sk, idx) ((X509_INFO *)OPENSSL_sk_value(ossl_check_const_X509_INFO_sk_type(sk), (idx)))
    sk_X509_INFO_new(cmp) ((STACK_OF(X509_INFO) *)OPENSSL_sk_new(ossl_check_X509_INFO_compfunc_type(cmp)))
    sk_X509_INFO_new_null() ((STACK_OF(X509_INFO) *)OPENSSL_sk_new_null())
    sk_X509_INFO_new_reserve(cmp, n) ((STACK_OF(X509_INFO) *)OPENSSL_sk_new_reserve(ossl_check_X509_INFO_compfunc_type(cmp), (n)))
    sk_X509_INFO_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_X509_INFO_sk_type(sk), (n))
    sk_X509_INFO_free(sk) OPENSSL_sk_free(ossl_check_X509_INFO_sk_type(sk))
    sk_X509_INFO_zero(sk) OPENSSL_sk_zero(ossl_check_X509_INFO_sk_type(sk))
    sk_X509_INFO_delete(sk, i) ((X509_INFO *)OPENSSL_sk_delete(ossl_check_X509_INFO_sk_type(sk), (i)))
    sk_X509_INFO_delete_ptr(sk, ptr) ((X509_INFO *)OPENSSL_sk_delete_ptr(ossl_check_X509_INFO_sk_type(sk), ossl_check_X509_INFO_type(ptr)))
    sk_X509_INFO_push(sk, ptr) OPENSSL_sk_push(ossl_check_X509_INFO_sk_type(sk), ossl_check_X509_INFO_type(ptr))
    sk_X509_INFO_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_X509_INFO_sk_type(sk), ossl_check_X509_INFO_type(ptr))
    sk_X509_INFO_pop(sk) ((X509_INFO *)OPENSSL_sk_pop(ossl_check_X509_INFO_sk_type(sk)))
    sk_X509_INFO_shift(sk) ((X509_INFO *)OPENSSL_sk_shift(ossl_check_X509_INFO_sk_type(sk)))
    sk_X509_INFO_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_X509_INFO_sk_type(sk), ossl_check_X509_INFO_freefunc_type(freefunc))
    sk_X509_INFO_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_X509_INFO_sk_type(sk), ossl_check_X509_INFO_type(ptr), (idx))
    sk_X509_INFO_set(sk, idx, ptr) ((X509_INFO *)OPENSSL_sk_set(ossl_check_X509_INFO_sk_type(sk), (idx), ossl_check_X509_INFO_type(ptr)))
    sk_X509_INFO_find(sk, ptr) OPENSSL_sk_find(ossl_check_X509_INFO_sk_type(sk), ossl_check_X509_INFO_type(ptr))
    sk_X509_INFO_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_X509_INFO_sk_type(sk), ossl_check_X509_INFO_type(ptr))
    sk_X509_INFO_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_X509_INFO_sk_type(sk), ossl_check_X509_INFO_type(ptr), pnum)
    sk_X509_INFO_sort(sk) OPENSSL_sk_sort(ossl_check_X509_INFO_sk_type(sk))
    sk_X509_INFO_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_X509_INFO_sk_type(sk))
    sk_X509_INFO_dup(sk) ((STACK_OF(X509_INFO) *)OPENSSL_sk_dup(ossl_check_const_X509_INFO_sk_type(sk)))
    sk_X509_INFO_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(X509_INFO) *)OPENSSL_sk_deep_copy(ossl_check_const_X509_INFO_sk_type(sk), ossl_check_X509_INFO_copyfunc_type(copyfunc), ossl_check_X509_INFO_freefunc_type(freefunc)))
    sk_X509_INFO_set_cmp_func(sk, cmp) ((sk_X509_INFO_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_X509_INFO_sk_type(sk), ossl_check_X509_INFO_compfunc_type(cmp)))
  }

  { TODO 1 -copenssl stack X509_REVOKED definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_X509_REVOKED = Pointer;
  {$EXTERNALSYM PSTACK_OF_X509_REVOKED}

  { Original Stack Macros for X509_REVOKED:
    SKM_DEFINE_STACK_OF_INTERNAL(X509_REVOKED, X509_REVOKED, X509_REVOKED)
  }

  { TODO 1 -copenssl stack X509_CRL definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_X509_CRL = Pointer;
  {$EXTERNALSYM PSTACK_OF_X509_CRL}

  { Original Stack Macros for X509_CRL:
    SKM_DEFINE_STACK_OF_INTERNAL(X509_CRL, X509_CRL, X509_CRL)
  }

  { TODO 1 -copenssl stack X509_NAME_ENTRY definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_X509_NAME_ENTRY = Pointer;
  {$EXTERNALSYM PSTACK_OF_X509_NAME_ENTRY}

  { Original Stack Macros for X509_NAME_ENTRY:
    SKM_DEFINE_STACK_OF_INTERNAL(X509_NAME_ENTRY, X509_NAME_ENTRY, X509_NAME_ENTRY)
  }

  { TODO 1 -copenssl stack X509_EXTENSION definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_X509_EXTENSION = Pointer;
  {$EXTERNALSYM PSTACK_OF_X509_EXTENSION}

  { Original Stack Macros for X509_EXTENSION:
    SKM_DEFINE_STACK_OF_INTERNAL(X509_EXTENSION, X509_EXTENSION, X509_EXTENSION)
  }

  { TODO 1 -copenssl stack X509_ATTRIBUTE definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_X509_ATTRIBUTE = Pointer;
  {$EXTERNALSYM PSTACK_OF_X509_ATTRIBUTE}

  { Original Stack Macros for X509_ATTRIBUTE:
    SKM_DEFINE_STACK_OF_INTERNAL(X509_ATTRIBUTE, X509_ATTRIBUTE, X509_ATTRIBUTE)
  }

  { TODO 1 -copenssl stack X509_INFO definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_X509_INFO = Pointer;
  {$EXTERNALSYM PSTACK_OF_X509_INFO}

  { Original Stack Macros for X509_INFO:
    SKM_DEFINE_STACK_OF_INTERNAL(X509_INFO, X509_INFO, X509_INFO)
  }


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

procedure X509_CRL_set_default_method(meth: PX509_CRL_METHOD); cdecl external CLibCrypto name 'X509_CRL_set_default_method';
function X509_CRL_METHOD_new(crl_init: TX509_CRL_METHOD_new_crl_init_cb; crl_free: TX509_CRL_METHOD_new_crl_init_cb; crl_lookup: TX509_CRL_METHOD_new_crl_lookup_cb; crl_verify: TX509_CRL_METHOD_new_crl_verify_cb): PX509_CRL_METHOD; cdecl external CLibCrypto name 'X509_CRL_METHOD_new';
procedure X509_CRL_METHOD_free(m: PX509_CRL_METHOD); cdecl external CLibCrypto name 'X509_CRL_METHOD_free';
procedure X509_CRL_set_meth_data(crl: PX509_CRL; dat: Pointer); cdecl external CLibCrypto name 'X509_CRL_set_meth_data';
function X509_CRL_get_meth_data(crl: PX509_CRL): Pointer; cdecl external CLibCrypto name 'X509_CRL_get_meth_data';
function X509_verify_cert_error_string(n: TIdC_LONG): PIdAnsiChar; cdecl external CLibCrypto name 'X509_verify_cert_error_string';
function X509_verify(a: PX509; r: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'X509_verify';
function X509_self_signed(cert: PX509; verify_signature: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_self_signed';
function X509_REQ_verify_ex(a: PX509_REQ; r: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'X509_REQ_verify_ex';
function X509_REQ_verify(a: PX509_REQ; r: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'X509_REQ_verify';
function X509_CRL_verify(a: PX509_CRL; r: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_verify';
function NETSCAPE_SPKI_verify(a: PNETSCAPE_SPKI; r: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'NETSCAPE_SPKI_verify';
function NETSCAPE_SPKI_b64_decode(str: PIdAnsiChar; len: TIdC_INT): PNETSCAPE_SPKI; cdecl external CLibCrypto name 'NETSCAPE_SPKI_b64_decode';
function NETSCAPE_SPKI_b64_encode(x: PNETSCAPE_SPKI): PIdAnsiChar; cdecl external CLibCrypto name 'NETSCAPE_SPKI_b64_encode';
function NETSCAPE_SPKI_get_pubkey(x: PNETSCAPE_SPKI): PEVP_PKEY; cdecl external CLibCrypto name 'NETSCAPE_SPKI_get_pubkey';
function NETSCAPE_SPKI_set_pubkey(x: PNETSCAPE_SPKI; pkey: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'NETSCAPE_SPKI_set_pubkey';
function NETSCAPE_SPKI_print(_out: PBIO; spki: PNETSCAPE_SPKI): TIdC_INT; cdecl external CLibCrypto name 'NETSCAPE_SPKI_print';
function X509_signature_dump(bp: PBIO; sig: PASN1_STRING; indent: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_signature_dump';
function X509_signature_print(bp: PBIO; alg: PX509_ALGOR; sig: PASN1_STRING): TIdC_INT; cdecl external CLibCrypto name 'X509_signature_print';
function X509_sign(x: PX509; pkey: PEVP_PKEY; md: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'X509_sign';
function X509_sign_ctx(x: PX509; ctx: PEVP_MD_CTX): TIdC_INT; cdecl external CLibCrypto name 'X509_sign_ctx';
function X509_REQ_sign(x: PX509_REQ; pkey: PEVP_PKEY; md: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'X509_REQ_sign';
function X509_REQ_sign_ctx(x: PX509_REQ; ctx: PEVP_MD_CTX): TIdC_INT; cdecl external CLibCrypto name 'X509_REQ_sign_ctx';
function X509_CRL_sign(x: PX509_CRL; pkey: PEVP_PKEY; md: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_sign';
function X509_CRL_sign_ctx(x: PX509_CRL; ctx: PEVP_MD_CTX): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_sign_ctx';
function NETSCAPE_SPKI_sign(x: PNETSCAPE_SPKI; pkey: PEVP_PKEY; md: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'NETSCAPE_SPKI_sign';
function X509_pubkey_digest(data: PX509; _type: PEVP_MD; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'X509_pubkey_digest';
function X509_digest(data: PX509; _type: PEVP_MD; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'X509_digest';
function X509_digest_sig(cert: PX509; md_used: PPEVP_MD; md_is_fallback: PIdC_INT): PASN1_OCTET_STRING; cdecl external CLibCrypto name 'X509_digest_sig';
function X509_CRL_digest(data: PX509_CRL; _type: PEVP_MD; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_digest';
function X509_REQ_digest(data: PX509_REQ; _type: PEVP_MD; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'X509_REQ_digest';
function X509_NAME_digest(data: PX509_NAME; _type: PEVP_MD; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'X509_NAME_digest';
function X509_load_http(url: PIdAnsiChar; bio: PBIO; rbio: PBIO; timeout: TIdC_INT): PX509; cdecl external CLibCrypto name 'X509_load_http';
function X509_CRL_load_http(url: PIdAnsiChar; bio: PBIO; rbio: PBIO; timeout: TIdC_INT): PX509_CRL; cdecl external CLibCrypto name 'X509_CRL_load_http';
function d2i_X509_fp(fp: PFILE; x509: PPX509): PX509; cdecl external CLibCrypto name 'd2i_X509_fp';
function i2d_X509_fp(fp: PFILE; x509: PX509): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_fp';
function d2i_X509_CRL_fp(fp: PFILE; crl: PPX509_CRL): PX509_CRL; cdecl external CLibCrypto name 'd2i_X509_CRL_fp';
function i2d_X509_CRL_fp(fp: PFILE; crl: PX509_CRL): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_CRL_fp';
function d2i_X509_REQ_fp(fp: PFILE; req: PPX509_REQ): PX509_REQ; cdecl external CLibCrypto name 'd2i_X509_REQ_fp';
function i2d_X509_REQ_fp(fp: PFILE; req: PX509_REQ): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_REQ_fp';
function d2i_RSAPrivateKey_fp(fp: PFILE; rsa: PPRSA): PRSA; cdecl external CLibCrypto name 'd2i_RSAPrivateKey_fp';
function i2d_RSAPrivateKey_fp(fp: PFILE; rsa: PRSA): TIdC_INT; cdecl external CLibCrypto name 'i2d_RSAPrivateKey_fp';
function d2i_RSAPublicKey_fp(fp: PFILE; rsa: PPRSA): PRSA; cdecl external CLibCrypto name 'd2i_RSAPublicKey_fp';
function i2d_RSAPublicKey_fp(fp: PFILE; rsa: PRSA): TIdC_INT; cdecl external CLibCrypto name 'i2d_RSAPublicKey_fp';
function d2i_RSA_PUBKEY_fp(fp: PFILE; rsa: PPRSA): PRSA; cdecl external CLibCrypto name 'd2i_RSA_PUBKEY_fp';
function i2d_RSA_PUBKEY_fp(fp: PFILE; rsa: PRSA): TIdC_INT; cdecl external CLibCrypto name 'i2d_RSA_PUBKEY_fp';
function d2i_DSA_PUBKEY_fp(fp: PFILE; dsa: PPDSA): PDSA; cdecl external CLibCrypto name 'd2i_DSA_PUBKEY_fp';
function i2d_DSA_PUBKEY_fp(fp: PFILE; dsa: PDSA): TIdC_INT; cdecl external CLibCrypto name 'i2d_DSA_PUBKEY_fp';
function d2i_DSAPrivateKey_fp(fp: PFILE; dsa: PPDSA): PDSA; cdecl external CLibCrypto name 'd2i_DSAPrivateKey_fp';
function i2d_DSAPrivateKey_fp(fp: PFILE; dsa: PDSA): TIdC_INT; cdecl external CLibCrypto name 'i2d_DSAPrivateKey_fp';
function d2i_EC_PUBKEY_fp(fp: PFILE; eckey: PPEC_KEY): PEC_KEY; cdecl external CLibCrypto name 'd2i_EC_PUBKEY_fp';
function i2d_EC_PUBKEY_fp(fp: PFILE; eckey: PEC_KEY): TIdC_INT; cdecl external CLibCrypto name 'i2d_EC_PUBKEY_fp';
function d2i_ECPrivateKey_fp(fp: PFILE; eckey: PPEC_KEY): PEC_KEY; cdecl external CLibCrypto name 'd2i_ECPrivateKey_fp';
function i2d_ECPrivateKey_fp(fp: PFILE; eckey: PEC_KEY): TIdC_INT; cdecl external CLibCrypto name 'i2d_ECPrivateKey_fp';
function d2i_PKCS8_fp(fp: PFILE; p8: PPX509_SIG): PX509_SIG; cdecl external CLibCrypto name 'd2i_PKCS8_fp';
function i2d_PKCS8_fp(fp: PFILE; p8: PX509_SIG): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS8_fp';
function d2i_X509_PUBKEY_fp(fp: PFILE; xpk: PPX509_PUBKEY): PX509_PUBKEY; cdecl external CLibCrypto name 'd2i_X509_PUBKEY_fp';
function i2d_X509_PUBKEY_fp(fp: PFILE; xpk: PX509_PUBKEY): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_PUBKEY_fp';
function d2i_PKCS8_PRIV_KEY_INFO_fp(fp: PFILE; p8inf: PPPKCS8_PRIV_KEY_INFO): PPKCS8_PRIV_KEY_INFO; cdecl external CLibCrypto name 'd2i_PKCS8_PRIV_KEY_INFO_fp';
function i2d_PKCS8_PRIV_KEY_INFO_fp(fp: PFILE; p8inf: PPKCS8_PRIV_KEY_INFO): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS8_PRIV_KEY_INFO_fp';
function i2d_PKCS8PrivateKeyInfo_fp(fp: PFILE; key: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS8PrivateKeyInfo_fp';
function i2d_PrivateKey_fp(fp: PFILE; pkey: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'i2d_PrivateKey_fp';
function d2i_PrivateKey_ex_fp(fp: PFILE; a: PPEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl external CLibCrypto name 'd2i_PrivateKey_ex_fp';
function d2i_PrivateKey_fp(fp: PFILE; a: PPEVP_PKEY): PEVP_PKEY; cdecl external CLibCrypto name 'd2i_PrivateKey_fp';
function i2d_PUBKEY_fp(fp: PFILE; pkey: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'i2d_PUBKEY_fp';
function d2i_PUBKEY_ex_fp(fp: PFILE; a: PPEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl external CLibCrypto name 'd2i_PUBKEY_ex_fp';
function d2i_PUBKEY_fp(fp: PFILE; a: PPEVP_PKEY): PEVP_PKEY; cdecl external CLibCrypto name 'd2i_PUBKEY_fp';
function d2i_X509_bio(bp: PBIO; x509: PPX509): PX509; cdecl external CLibCrypto name 'd2i_X509_bio';
function i2d_X509_bio(bp: PBIO; x509: PX509): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_bio';
function d2i_X509_CRL_bio(bp: PBIO; crl: PPX509_CRL): PX509_CRL; cdecl external CLibCrypto name 'd2i_X509_CRL_bio';
function i2d_X509_CRL_bio(bp: PBIO; crl: PX509_CRL): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_CRL_bio';
function d2i_X509_REQ_bio(bp: PBIO; req: PPX509_REQ): PX509_REQ; cdecl external CLibCrypto name 'd2i_X509_REQ_bio';
function i2d_X509_REQ_bio(bp: PBIO; req: PX509_REQ): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_REQ_bio';
function d2i_RSAPrivateKey_bio(bp: PBIO; rsa: PPRSA): PRSA; cdecl external CLibCrypto name 'd2i_RSAPrivateKey_bio';
function i2d_RSAPrivateKey_bio(bp: PBIO; rsa: PRSA): TIdC_INT; cdecl external CLibCrypto name 'i2d_RSAPrivateKey_bio';
function d2i_RSAPublicKey_bio(bp: PBIO; rsa: PPRSA): PRSA; cdecl external CLibCrypto name 'd2i_RSAPublicKey_bio';
function i2d_RSAPublicKey_bio(bp: PBIO; rsa: PRSA): TIdC_INT; cdecl external CLibCrypto name 'i2d_RSAPublicKey_bio';
function d2i_RSA_PUBKEY_bio(bp: PBIO; rsa: PPRSA): PRSA; cdecl external CLibCrypto name 'd2i_RSA_PUBKEY_bio';
function i2d_RSA_PUBKEY_bio(bp: PBIO; rsa: PRSA): TIdC_INT; cdecl external CLibCrypto name 'i2d_RSA_PUBKEY_bio';
function d2i_DSA_PUBKEY_bio(bp: PBIO; dsa: PPDSA): PDSA; cdecl external CLibCrypto name 'd2i_DSA_PUBKEY_bio';
function i2d_DSA_PUBKEY_bio(bp: PBIO; dsa: PDSA): TIdC_INT; cdecl external CLibCrypto name 'i2d_DSA_PUBKEY_bio';
function d2i_DSAPrivateKey_bio(bp: PBIO; dsa: PPDSA): PDSA; cdecl external CLibCrypto name 'd2i_DSAPrivateKey_bio';
function i2d_DSAPrivateKey_bio(bp: PBIO; dsa: PDSA): TIdC_INT; cdecl external CLibCrypto name 'i2d_DSAPrivateKey_bio';
function d2i_EC_PUBKEY_bio(bp: PBIO; eckey: PPEC_KEY): PEC_KEY; cdecl external CLibCrypto name 'd2i_EC_PUBKEY_bio';
function i2d_EC_PUBKEY_bio(bp: PBIO; eckey: PEC_KEY): TIdC_INT; cdecl external CLibCrypto name 'i2d_EC_PUBKEY_bio';
function d2i_ECPrivateKey_bio(bp: PBIO; eckey: PPEC_KEY): PEC_KEY; cdecl external CLibCrypto name 'd2i_ECPrivateKey_bio';
function i2d_ECPrivateKey_bio(bp: PBIO; eckey: PEC_KEY): TIdC_INT; cdecl external CLibCrypto name 'i2d_ECPrivateKey_bio';
function d2i_PKCS8_bio(bp: PBIO; p8: PPX509_SIG): PX509_SIG; cdecl external CLibCrypto name 'd2i_PKCS8_bio';
function i2d_PKCS8_bio(bp: PBIO; p8: PX509_SIG): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS8_bio';
function d2i_X509_PUBKEY_bio(bp: PBIO; xpk: PPX509_PUBKEY): PX509_PUBKEY; cdecl external CLibCrypto name 'd2i_X509_PUBKEY_bio';
function i2d_X509_PUBKEY_bio(bp: PBIO; xpk: PX509_PUBKEY): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_PUBKEY_bio';
function d2i_PKCS8_PRIV_KEY_INFO_bio(bp: PBIO; p8inf: PPPKCS8_PRIV_KEY_INFO): PPKCS8_PRIV_KEY_INFO; cdecl external CLibCrypto name 'd2i_PKCS8_PRIV_KEY_INFO_bio';
function i2d_PKCS8_PRIV_KEY_INFO_bio(bp: PBIO; p8inf: PPKCS8_PRIV_KEY_INFO): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS8_PRIV_KEY_INFO_bio';
function i2d_PKCS8PrivateKeyInfo_bio(bp: PBIO; key: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS8PrivateKeyInfo_bio';
function i2d_PrivateKey_bio(bp: PBIO; pkey: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'i2d_PrivateKey_bio';
function d2i_PrivateKey_ex_bio(bp: PBIO; a: PPEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl external CLibCrypto name 'd2i_PrivateKey_ex_bio';
function d2i_PrivateKey_bio(bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY; cdecl external CLibCrypto name 'd2i_PrivateKey_bio';
function i2d_PUBKEY_bio(bp: PBIO; pkey: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'i2d_PUBKEY_bio';
function d2i_PUBKEY_ex_bio(bp: PBIO; a: PPEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl external CLibCrypto name 'd2i_PUBKEY_ex_bio';
function d2i_PUBKEY_bio(bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY; cdecl external CLibCrypto name 'd2i_PUBKEY_bio';
function X509_dup(a: PX509): PX509; cdecl external CLibCrypto name 'X509_dup';
function X509_ALGOR_dup(a: PX509_ALGOR): PX509_ALGOR; cdecl external CLibCrypto name 'X509_ALGOR_dup';
function X509_ATTRIBUTE_dup(a: PX509_ATTRIBUTE): PX509_ATTRIBUTE; cdecl external CLibCrypto name 'X509_ATTRIBUTE_dup';
function X509_CRL_dup(a: PX509_CRL): PX509_CRL; cdecl external CLibCrypto name 'X509_CRL_dup';
function X509_EXTENSION_dup(a: PX509_EXTENSION): PX509_EXTENSION; cdecl external CLibCrypto name 'X509_EXTENSION_dup';
function X509_PUBKEY_dup(a: PX509_PUBKEY): PX509_PUBKEY; cdecl external CLibCrypto name 'X509_PUBKEY_dup';
function X509_REQ_dup(a: PX509_REQ): PX509_REQ; cdecl external CLibCrypto name 'X509_REQ_dup';
function X509_REVOKED_dup(a: PX509_REVOKED): PX509_REVOKED; cdecl external CLibCrypto name 'X509_REVOKED_dup';
function X509_ALGOR_set0(alg: PX509_ALGOR; aobj: PASN1_OBJECT; ptype: TIdC_INT; pval: Pointer): TIdC_INT; cdecl external CLibCrypto name 'X509_ALGOR_set0';
procedure X509_ALGOR_get0(paobj: PPASN1_OBJECT; pptype: PIdC_INT; ppval: PPointer; algor: PX509_ALGOR); cdecl external CLibCrypto name 'X509_ALGOR_get0';
procedure X509_ALGOR_set_md(alg: PX509_ALGOR; md: PEVP_MD); cdecl external CLibCrypto name 'X509_ALGOR_set_md';
function X509_ALGOR_cmp(a: PX509_ALGOR; b: PX509_ALGOR): TIdC_INT; cdecl external CLibCrypto name 'X509_ALGOR_cmp';
function X509_ALGOR_copy(dest: PX509_ALGOR; src: PX509_ALGOR): TIdC_INT; cdecl external CLibCrypto name 'X509_ALGOR_copy';
function X509_NAME_dup(a: PX509_NAME): PX509_NAME; cdecl external CLibCrypto name 'X509_NAME_dup';
function X509_NAME_ENTRY_dup(a: PX509_NAME_ENTRY): PX509_NAME_ENTRY; cdecl external CLibCrypto name 'X509_NAME_ENTRY_dup';
function X509_cmp_time(s: PASN1_TIME; t: PIdC_TIMET): TIdC_INT; cdecl external CLibCrypto name 'X509_cmp_time';
function X509_cmp_current_time(s: PASN1_TIME): TIdC_INT; cdecl external CLibCrypto name 'X509_cmp_current_time';
function X509_cmp_timeframe(vpm: PX509_VERIFY_PARAM; start: PASN1_TIME; _end: PASN1_TIME): TIdC_INT; cdecl external CLibCrypto name 'X509_cmp_timeframe';
function X509_time_adj(s: PASN1_TIME; adj: TIdC_LONG; t: PIdC_TIMET): PASN1_TIME; cdecl external CLibCrypto name 'X509_time_adj';
function X509_time_adj_ex(s: PASN1_TIME; offset_day: TIdC_INT; offset_sec: TIdC_LONG; t: PIdC_TIMET): PASN1_TIME; cdecl external CLibCrypto name 'X509_time_adj_ex';
function X509_gmtime_adj(s: PASN1_TIME; adj: TIdC_LONG): PASN1_TIME; cdecl external CLibCrypto name 'X509_gmtime_adj';
function X509_get_default_cert_area: PIdAnsiChar; cdecl external CLibCrypto name 'X509_get_default_cert_area';
function X509_get_default_cert_dir: PIdAnsiChar; cdecl external CLibCrypto name 'X509_get_default_cert_dir';
function X509_get_default_cert_file: PIdAnsiChar; cdecl external CLibCrypto name 'X509_get_default_cert_file';
function X509_get_default_cert_dir_env: PIdAnsiChar; cdecl external CLibCrypto name 'X509_get_default_cert_dir_env';
function X509_get_default_cert_file_env: PIdAnsiChar; cdecl external CLibCrypto name 'X509_get_default_cert_file_env';
function X509_get_default_private_dir: PIdAnsiChar; cdecl external CLibCrypto name 'X509_get_default_private_dir';
function X509_to_X509_REQ(x: PX509; pkey: PEVP_PKEY; md: PEVP_MD): PX509_REQ; cdecl external CLibCrypto name 'X509_to_X509_REQ';
function X509_REQ_to_X509(r: PX509_REQ; days: TIdC_INT; pkey: PEVP_PKEY): PX509; cdecl external CLibCrypto name 'X509_REQ_to_X509';
function X509_ALGOR_new: PX509_ALGOR; cdecl external CLibCrypto name 'X509_ALGOR_new';
procedure X509_ALGOR_free(a: PX509_ALGOR); cdecl external CLibCrypto name 'X509_ALGOR_free';
function d2i_X509_ALGOR(a: PPX509_ALGOR; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_ALGOR; cdecl external CLibCrypto name 'd2i_X509_ALGOR';
function i2d_X509_ALGOR(a: PX509_ALGOR; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_ALGOR';
function X509_ALGOR_it: PASN1_ITEM; cdecl external CLibCrypto name 'X509_ALGOR_it';
function d2i_X509_ALGORS(a: PPX509_ALGORS; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_ALGORS; cdecl external CLibCrypto name 'd2i_X509_ALGORS';
function i2d_X509_ALGORS(a: PX509_ALGORS; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_ALGORS';
function X509_ALGORS_it: PASN1_ITEM; cdecl external CLibCrypto name 'X509_ALGORS_it';
function X509_VAL_new: PX509_VAL; cdecl external CLibCrypto name 'X509_VAL_new';
procedure X509_VAL_free(a: PX509_VAL); cdecl external CLibCrypto name 'X509_VAL_free';
function d2i_X509_VAL(a: PPX509_VAL; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_VAL; cdecl external CLibCrypto name 'd2i_X509_VAL';
function i2d_X509_VAL(a: PX509_VAL; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_VAL';
function X509_VAL_it: PASN1_ITEM; cdecl external CLibCrypto name 'X509_VAL_it';
function X509_PUBKEY_new: PX509_PUBKEY; cdecl external CLibCrypto name 'X509_PUBKEY_new';
procedure X509_PUBKEY_free(a: PX509_PUBKEY); cdecl external CLibCrypto name 'X509_PUBKEY_free';
function d2i_X509_PUBKEY(a: PPX509_PUBKEY; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_PUBKEY; cdecl external CLibCrypto name 'd2i_X509_PUBKEY';
function i2d_X509_PUBKEY(a: PX509_PUBKEY; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_PUBKEY';
function X509_PUBKEY_it: PASN1_ITEM; cdecl external CLibCrypto name 'X509_PUBKEY_it';
function X509_PUBKEY_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_PUBKEY; cdecl external CLibCrypto name 'X509_PUBKEY_new_ex';
function X509_PUBKEY_set(x: PPX509_PUBKEY; pkey: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'X509_PUBKEY_set';
function X509_PUBKEY_get0(key: PX509_PUBKEY): PEVP_PKEY; cdecl external CLibCrypto name 'X509_PUBKEY_get0';
function X509_PUBKEY_get(key: PX509_PUBKEY): PEVP_PKEY; cdecl external CLibCrypto name 'X509_PUBKEY_get';
function X509_get_pubkey_parameters(pkey: PEVP_PKEY; chain: Pstack_st_X509): TIdC_INT; cdecl external CLibCrypto name 'X509_get_pubkey_parameters';
function X509_get_pathlen(x: PX509): TIdC_LONG; cdecl external CLibCrypto name 'X509_get_pathlen';
function d2i_PUBKEY(a: PPEVP_PKEY; _in: PPIdAnsiChar; len: TIdC_LONG): PEVP_PKEY; cdecl external CLibCrypto name 'd2i_PUBKEY';
function i2d_PUBKEY(a: PEVP_PKEY; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_PUBKEY';
function d2i_PUBKEY_ex(a: PPEVP_PKEY; pp: PPIdAnsiChar; length: TIdC_LONG; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl external CLibCrypto name 'd2i_PUBKEY_ex';
function d2i_RSA_PUBKEY(a: PPRSA; _in: PPIdAnsiChar; len: TIdC_LONG): PRSA; cdecl external CLibCrypto name 'd2i_RSA_PUBKEY';
function i2d_RSA_PUBKEY(a: PRSA; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_RSA_PUBKEY';
function d2i_DSA_PUBKEY(a: PPDSA; _in: PPIdAnsiChar; len: TIdC_LONG): PDSA; cdecl external CLibCrypto name 'd2i_DSA_PUBKEY';
function i2d_DSA_PUBKEY(a: PDSA; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_DSA_PUBKEY';
function d2i_EC_PUBKEY(a: PPEC_KEY; _in: PPIdAnsiChar; len: TIdC_LONG): PEC_KEY; cdecl external CLibCrypto name 'd2i_EC_PUBKEY';
function i2d_EC_PUBKEY(a: PEC_KEY; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_EC_PUBKEY';
function X509_SIG_new: PX509_SIG; cdecl external CLibCrypto name 'X509_SIG_new';
procedure X509_SIG_free(a: PX509_SIG); cdecl external CLibCrypto name 'X509_SIG_free';
function d2i_X509_SIG(a: PPX509_SIG; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_SIG; cdecl external CLibCrypto name 'd2i_X509_SIG';
function i2d_X509_SIG(a: PX509_SIG; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_SIG';
function X509_SIG_it: PASN1_ITEM; cdecl external CLibCrypto name 'X509_SIG_it';
procedure X509_SIG_get0(sig: PX509_SIG; palg: PPX509_ALGOR; pdigest: PPASN1_OCTET_STRING); cdecl external CLibCrypto name 'X509_SIG_get0';
procedure X509_SIG_getm(sig: PX509_SIG; palg: PPX509_ALGOR; pdigest: PPASN1_OCTET_STRING); cdecl external CLibCrypto name 'X509_SIG_getm';
function X509_REQ_INFO_new: PX509_REQ_INFO; cdecl external CLibCrypto name 'X509_REQ_INFO_new';
procedure X509_REQ_INFO_free(a: PX509_REQ_INFO); cdecl external CLibCrypto name 'X509_REQ_INFO_free';
function d2i_X509_REQ_INFO(a: PPX509_REQ_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_REQ_INFO; cdecl external CLibCrypto name 'd2i_X509_REQ_INFO';
function i2d_X509_REQ_INFO(a: PX509_REQ_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_REQ_INFO';
function X509_REQ_INFO_it: PASN1_ITEM; cdecl external CLibCrypto name 'X509_REQ_INFO_it';
function X509_REQ_new: PX509_REQ; cdecl external CLibCrypto name 'X509_REQ_new';
procedure X509_REQ_free(a: PX509_REQ); cdecl external CLibCrypto name 'X509_REQ_free';
function d2i_X509_REQ(a: PPX509_REQ; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_REQ; cdecl external CLibCrypto name 'd2i_X509_REQ';
function i2d_X509_REQ(a: PX509_REQ; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_REQ';
function X509_REQ_it: PASN1_ITEM; cdecl external CLibCrypto name 'X509_REQ_it';
function X509_REQ_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_REQ; cdecl external CLibCrypto name 'X509_REQ_new_ex';
function X509_ATTRIBUTE_new: PX509_ATTRIBUTE; cdecl external CLibCrypto name 'X509_ATTRIBUTE_new';
procedure X509_ATTRIBUTE_free(a: PX509_ATTRIBUTE); cdecl external CLibCrypto name 'X509_ATTRIBUTE_free';
function d2i_X509_ATTRIBUTE(a: PPX509_ATTRIBUTE; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_ATTRIBUTE; cdecl external CLibCrypto name 'd2i_X509_ATTRIBUTE';
function i2d_X509_ATTRIBUTE(a: PX509_ATTRIBUTE; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_ATTRIBUTE';
function X509_ATTRIBUTE_it: PASN1_ITEM; cdecl external CLibCrypto name 'X509_ATTRIBUTE_it';
function X509_ATTRIBUTE_create(nid: TIdC_INT; atrtype: TIdC_INT; value: Pointer): PX509_ATTRIBUTE; cdecl external CLibCrypto name 'X509_ATTRIBUTE_create';
function X509_EXTENSION_new: PX509_EXTENSION; cdecl external CLibCrypto name 'X509_EXTENSION_new';
procedure X509_EXTENSION_free(a: PX509_EXTENSION); cdecl external CLibCrypto name 'X509_EXTENSION_free';
function d2i_X509_EXTENSION(a: PPX509_EXTENSION; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_EXTENSION; cdecl external CLibCrypto name 'd2i_X509_EXTENSION';
function i2d_X509_EXTENSION(a: PX509_EXTENSION; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_EXTENSION';
function X509_EXTENSION_it: PASN1_ITEM; cdecl external CLibCrypto name 'X509_EXTENSION_it';
function d2i_X509_EXTENSIONS(a: PPX509_EXTENSIONS; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_EXTENSIONS; cdecl external CLibCrypto name 'd2i_X509_EXTENSIONS';
function i2d_X509_EXTENSIONS(a: PX509_EXTENSIONS; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_EXTENSIONS';
function X509_EXTENSIONS_it: PASN1_ITEM; cdecl external CLibCrypto name 'X509_EXTENSIONS_it';
function X509_NAME_ENTRY_new: PX509_NAME_ENTRY; cdecl external CLibCrypto name 'X509_NAME_ENTRY_new';
procedure X509_NAME_ENTRY_free(a: PX509_NAME_ENTRY); cdecl external CLibCrypto name 'X509_NAME_ENTRY_free';
function d2i_X509_NAME_ENTRY(a: PPX509_NAME_ENTRY; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_NAME_ENTRY; cdecl external CLibCrypto name 'd2i_X509_NAME_ENTRY';
function i2d_X509_NAME_ENTRY(a: PX509_NAME_ENTRY; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_NAME_ENTRY';
function X509_NAME_ENTRY_it: PASN1_ITEM; cdecl external CLibCrypto name 'X509_NAME_ENTRY_it';
function X509_NAME_new: PX509_NAME; cdecl external CLibCrypto name 'X509_NAME_new';
procedure X509_NAME_free(a: PX509_NAME); cdecl external CLibCrypto name 'X509_NAME_free';
function d2i_X509_NAME(a: PPX509_NAME; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_NAME; cdecl external CLibCrypto name 'd2i_X509_NAME';
function i2d_X509_NAME(a: PX509_NAME; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_NAME';
function X509_NAME_it: PASN1_ITEM; cdecl external CLibCrypto name 'X509_NAME_it';
function X509_NAME_set(xn: PPX509_NAME; name: PX509_NAME): TIdC_INT; cdecl external CLibCrypto name 'X509_NAME_set';
function X509_CINF_new: PX509_CINF; cdecl external CLibCrypto name 'X509_CINF_new';
procedure X509_CINF_free(a: PX509_CINF); cdecl external CLibCrypto name 'X509_CINF_free';
function d2i_X509_CINF(a: PPX509_CINF; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_CINF; cdecl external CLibCrypto name 'd2i_X509_CINF';
function i2d_X509_CINF(a: PX509_CINF; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_CINF';
function X509_CINF_it: PASN1_ITEM; cdecl external CLibCrypto name 'X509_CINF_it';
function X509_new: PX509; cdecl external CLibCrypto name 'X509_new';
procedure X509_free(a: PX509); cdecl external CLibCrypto name 'X509_free';
function d2i_X509(a: PPX509; _in: PPIdAnsiChar; len: TIdC_LONG): PX509; cdecl external CLibCrypto name 'd2i_X509';
function i2d_X509(a: PX509; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509';
function X509_it: PASN1_ITEM; cdecl external CLibCrypto name 'X509_it';
function X509_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509; cdecl external CLibCrypto name 'X509_new_ex';
function X509_CERT_AUX_new: PX509_CERT_AUX; cdecl external CLibCrypto name 'X509_CERT_AUX_new';
procedure X509_CERT_AUX_free(a: PX509_CERT_AUX); cdecl external CLibCrypto name 'X509_CERT_AUX_free';
function d2i_X509_CERT_AUX(a: PPX509_CERT_AUX; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_CERT_AUX; cdecl external CLibCrypto name 'd2i_X509_CERT_AUX';
function i2d_X509_CERT_AUX(a: PX509_CERT_AUX; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_CERT_AUX';
function X509_CERT_AUX_it: PASN1_ITEM; cdecl external CLibCrypto name 'X509_CERT_AUX_it';
function X509_set_ex_data(r: PX509; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl external CLibCrypto name 'X509_set_ex_data';
function X509_get_ex_data(r: PX509; idx: TIdC_INT): Pointer; cdecl external CLibCrypto name 'X509_get_ex_data';
function d2i_X509_AUX(a: PPX509; _in: PPIdAnsiChar; len: TIdC_LONG): PX509; cdecl external CLibCrypto name 'd2i_X509_AUX';
function i2d_X509_AUX(a: PX509; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_AUX';
function i2d_re_X509_tbs(x: PX509; pp: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_re_X509_tbs';
function X509_SIG_INFO_get(siginf: PX509_SIG_INFO; mdnid: PIdC_INT; pknid: PIdC_INT; secbits: PIdC_INT; flags: PIdC_UINT32): TIdC_INT; cdecl external CLibCrypto name 'X509_SIG_INFO_get';
procedure X509_SIG_INFO_set(siginf: PX509_SIG_INFO; mdnid: TIdC_INT; pknid: TIdC_INT; secbits: TIdC_INT; flags: TIdC_UINT32); cdecl external CLibCrypto name 'X509_SIG_INFO_set';
function X509_get_signature_info(x: PX509; mdnid: PIdC_INT; pknid: PIdC_INT; secbits: PIdC_INT; flags: PIdC_UINT32): TIdC_INT; cdecl external CLibCrypto name 'X509_get_signature_info';
procedure X509_get0_signature(psig: PPASN1_BIT_STRING; palg: PPX509_ALGOR; x: PX509); cdecl external CLibCrypto name 'X509_get0_signature';
function X509_get_signature_nid(x: PX509): TIdC_INT; cdecl external CLibCrypto name 'X509_get_signature_nid';
procedure X509_set0_distinguishing_id(x: PX509; d_id: PASN1_OCTET_STRING); cdecl external CLibCrypto name 'X509_set0_distinguishing_id';
function X509_get0_distinguishing_id(x: PX509): PASN1_OCTET_STRING; cdecl external CLibCrypto name 'X509_get0_distinguishing_id';
procedure X509_REQ_set0_distinguishing_id(x: PX509_REQ; d_id: PASN1_OCTET_STRING); cdecl external CLibCrypto name 'X509_REQ_set0_distinguishing_id';
function X509_REQ_get0_distinguishing_id(x: PX509_REQ): PASN1_OCTET_STRING; cdecl external CLibCrypto name 'X509_REQ_get0_distinguishing_id';
function X509_alias_set1(x: PX509; name: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_alias_set1';
function X509_keyid_set1(x: PX509; id: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_keyid_set1';
function X509_alias_get0(x: PX509; len: PIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'X509_alias_get0';
function X509_keyid_get0(x: PX509; len: PIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'X509_keyid_get0';
function X509_REVOKED_new: PX509_REVOKED; cdecl external CLibCrypto name 'X509_REVOKED_new';
procedure X509_REVOKED_free(a: PX509_REVOKED); cdecl external CLibCrypto name 'X509_REVOKED_free';
function d2i_X509_REVOKED(a: PPX509_REVOKED; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_REVOKED; cdecl external CLibCrypto name 'd2i_X509_REVOKED';
function i2d_X509_REVOKED(a: PX509_REVOKED; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_REVOKED';
function X509_REVOKED_it: PASN1_ITEM; cdecl external CLibCrypto name 'X509_REVOKED_it';
function X509_CRL_INFO_new: PX509_CRL_INFO; cdecl external CLibCrypto name 'X509_CRL_INFO_new';
procedure X509_CRL_INFO_free(a: PX509_CRL_INFO); cdecl external CLibCrypto name 'X509_CRL_INFO_free';
function d2i_X509_CRL_INFO(a: PPX509_CRL_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_CRL_INFO; cdecl external CLibCrypto name 'd2i_X509_CRL_INFO';
function i2d_X509_CRL_INFO(a: PX509_CRL_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_CRL_INFO';
function X509_CRL_INFO_it: PASN1_ITEM; cdecl external CLibCrypto name 'X509_CRL_INFO_it';
function X509_CRL_new: PX509_CRL; cdecl external CLibCrypto name 'X509_CRL_new';
procedure X509_CRL_free(a: PX509_CRL); cdecl external CLibCrypto name 'X509_CRL_free';
function d2i_X509_CRL(a: PPX509_CRL; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_CRL; cdecl external CLibCrypto name 'd2i_X509_CRL';
function i2d_X509_CRL(a: PX509_CRL; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_CRL';
function X509_CRL_it: PASN1_ITEM; cdecl external CLibCrypto name 'X509_CRL_it';
function X509_CRL_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_CRL; cdecl external CLibCrypto name 'X509_CRL_new_ex';
function X509_CRL_add0_revoked(crl: PX509_CRL; rev: PX509_REVOKED): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_add0_revoked';
function X509_CRL_get0_by_serial(crl: PX509_CRL; ret: PPX509_REVOKED; serial: PASN1_INTEGER): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_get0_by_serial';
function X509_CRL_get0_by_cert(crl: PX509_CRL; ret: PPX509_REVOKED; x: PX509): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_get0_by_cert';
function X509_PKEY_new: PX509_PKEY; cdecl external CLibCrypto name 'X509_PKEY_new';
procedure X509_PKEY_free(a: PX509_PKEY); cdecl external CLibCrypto name 'X509_PKEY_free';
function NETSCAPE_SPKI_new: PNETSCAPE_SPKI; cdecl external CLibCrypto name 'NETSCAPE_SPKI_new';
procedure NETSCAPE_SPKI_free(a: PNETSCAPE_SPKI); cdecl external CLibCrypto name 'NETSCAPE_SPKI_free';
function d2i_NETSCAPE_SPKI(a: PPNETSCAPE_SPKI; _in: PPIdAnsiChar; len: TIdC_LONG): PNETSCAPE_SPKI; cdecl external CLibCrypto name 'd2i_NETSCAPE_SPKI';
function i2d_NETSCAPE_SPKI(a: PNETSCAPE_SPKI; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_NETSCAPE_SPKI';
function NETSCAPE_SPKI_it: PASN1_ITEM; cdecl external CLibCrypto name 'NETSCAPE_SPKI_it';
function NETSCAPE_SPKAC_new: PNETSCAPE_SPKAC; cdecl external CLibCrypto name 'NETSCAPE_SPKAC_new';
procedure NETSCAPE_SPKAC_free(a: PNETSCAPE_SPKAC); cdecl external CLibCrypto name 'NETSCAPE_SPKAC_free';
function d2i_NETSCAPE_SPKAC(a: PPNETSCAPE_SPKAC; _in: PPIdAnsiChar; len: TIdC_LONG): PNETSCAPE_SPKAC; cdecl external CLibCrypto name 'd2i_NETSCAPE_SPKAC';
function i2d_NETSCAPE_SPKAC(a: PNETSCAPE_SPKAC; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_NETSCAPE_SPKAC';
function NETSCAPE_SPKAC_it: PASN1_ITEM; cdecl external CLibCrypto name 'NETSCAPE_SPKAC_it';
function NETSCAPE_CERT_SEQUENCE_new: PNETSCAPE_CERT_SEQUENCE; cdecl external CLibCrypto name 'NETSCAPE_CERT_SEQUENCE_new';
procedure NETSCAPE_CERT_SEQUENCE_free(a: PNETSCAPE_CERT_SEQUENCE); cdecl external CLibCrypto name 'NETSCAPE_CERT_SEQUENCE_free';
function d2i_NETSCAPE_CERT_SEQUENCE(a: PPNETSCAPE_CERT_SEQUENCE; _in: PPIdAnsiChar; len: TIdC_LONG): PNETSCAPE_CERT_SEQUENCE; cdecl external CLibCrypto name 'd2i_NETSCAPE_CERT_SEQUENCE';
function i2d_NETSCAPE_CERT_SEQUENCE(a: PNETSCAPE_CERT_SEQUENCE; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_NETSCAPE_CERT_SEQUENCE';
function NETSCAPE_CERT_SEQUENCE_it: PASN1_ITEM; cdecl external CLibCrypto name 'NETSCAPE_CERT_SEQUENCE_it';
function X509_INFO_new: PX509_INFO; cdecl external CLibCrypto name 'X509_INFO_new';
procedure X509_INFO_free(a: PX509_INFO); cdecl external CLibCrypto name 'X509_INFO_free';
function X509_NAME_oneline(a: PX509_NAME; buf: PIdAnsiChar; size: TIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'X509_NAME_oneline';
function ASN1_verify(i2d: TASN1_verify_i2d_cb; algor1: PX509_ALGOR; signature: PASN1_BIT_STRING; data: PIdAnsiChar; pkey: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'ASN1_verify';
function ASN1_digest(i2d: TASN1_verify_i2d_cb; _type: PEVP_MD; data: PIdAnsiChar; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'ASN1_digest';
function ASN1_sign(i2d: TASN1_verify_i2d_cb; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: PIdAnsiChar; pkey: PEVP_PKEY; _type: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'ASN1_sign';
function ASN1_item_digest(it: PASN1_ITEM; _type: PEVP_MD; data: Pointer; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'ASN1_item_digest';
function ASN1_item_verify(it: PASN1_ITEM; alg: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'ASN1_item_verify';
function ASN1_item_verify_ctx(it: PASN1_ITEM; alg: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; ctx: PEVP_MD_CTX): TIdC_INT; cdecl external CLibCrypto name 'ASN1_item_verify_ctx';
function ASN1_item_sign(it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY; md: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'ASN1_item_sign';
function ASN1_item_sign_ctx(it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; ctx: PEVP_MD_CTX): TIdC_INT; cdecl external CLibCrypto name 'ASN1_item_sign_ctx';
function X509_get_version(x: PX509): TIdC_LONG; cdecl external CLibCrypto name 'X509_get_version';
function X509_set_version(x: PX509; version: TIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'X509_set_version';
function X509_set_serialNumber(x: PX509; serial: PASN1_INTEGER): TIdC_INT; cdecl external CLibCrypto name 'X509_set_serialNumber';
function X509_get_serialNumber(x: PX509): PASN1_INTEGER; cdecl external CLibCrypto name 'X509_get_serialNumber';
function X509_get0_serialNumber(x: PX509): PASN1_INTEGER; cdecl external CLibCrypto name 'X509_get0_serialNumber';
function X509_set_issuer_name(x: PX509; name: PX509_NAME): TIdC_INT; cdecl external CLibCrypto name 'X509_set_issuer_name';
function X509_get_issuer_name(a: PX509): PX509_NAME; cdecl external CLibCrypto name 'X509_get_issuer_name';
function X509_set_subject_name(x: PX509; name: PX509_NAME): TIdC_INT; cdecl external CLibCrypto name 'X509_set_subject_name';
function X509_get_subject_name(a: PX509): PX509_NAME; cdecl external CLibCrypto name 'X509_get_subject_name';
function X509_get0_notBefore(x: PX509): PASN1_TIME; cdecl external CLibCrypto name 'X509_get0_notBefore';
function X509_getm_notBefore(x: PX509): PASN1_TIME; cdecl external CLibCrypto name 'X509_getm_notBefore';
function X509_set1_notBefore(x: PX509; tm: PASN1_TIME): TIdC_INT; cdecl external CLibCrypto name 'X509_set1_notBefore';
function X509_get0_notAfter(x: PX509): PASN1_TIME; cdecl external CLibCrypto name 'X509_get0_notAfter';
function X509_getm_notAfter(x: PX509): PASN1_TIME; cdecl external CLibCrypto name 'X509_getm_notAfter';
function X509_set1_notAfter(x: PX509; tm: PASN1_TIME): TIdC_INT; cdecl external CLibCrypto name 'X509_set1_notAfter';
function X509_set_pubkey(x: PX509; pkey: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'X509_set_pubkey';
function X509_up_ref(x: PX509): TIdC_INT; cdecl external CLibCrypto name 'X509_up_ref';
function X509_get_signature_type(x: PX509): TIdC_INT; cdecl external CLibCrypto name 'X509_get_signature_type';
function X509_get_X509_PUBKEY(x: PX509): PX509_PUBKEY; cdecl external CLibCrypto name 'X509_get_X509_PUBKEY';
function X509_get0_extensions(x: PX509): Pstack_st_X509_EXTENSION; cdecl external CLibCrypto name 'X509_get0_extensions';
procedure X509_get0_uids(x: PX509; piuid: PPASN1_BIT_STRING; psuid: PPASN1_BIT_STRING); cdecl external CLibCrypto name 'X509_get0_uids';
function X509_get0_tbs_sigalg(x: PX509): PX509_ALGOR; cdecl external CLibCrypto name 'X509_get0_tbs_sigalg';
function X509_get0_pubkey(x: PX509): PEVP_PKEY; cdecl external CLibCrypto name 'X509_get0_pubkey';
function X509_get_pubkey(x: PX509): PEVP_PKEY; cdecl external CLibCrypto name 'X509_get_pubkey';
function X509_get0_pubkey_bitstr(x: PX509): PASN1_BIT_STRING; cdecl external CLibCrypto name 'X509_get0_pubkey_bitstr';
function X509_REQ_get_version(req: PX509_REQ): TIdC_LONG; cdecl external CLibCrypto name 'X509_REQ_get_version';
function X509_REQ_set_version(x: PX509_REQ; version: TIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'X509_REQ_set_version';
function X509_REQ_get_subject_name(req: PX509_REQ): PX509_NAME; cdecl external CLibCrypto name 'X509_REQ_get_subject_name';
function X509_REQ_set_subject_name(req: PX509_REQ; name: PX509_NAME): TIdC_INT; cdecl external CLibCrypto name 'X509_REQ_set_subject_name';
procedure X509_REQ_get0_signature(req: PX509_REQ; psig: PPASN1_BIT_STRING; palg: PPX509_ALGOR); cdecl external CLibCrypto name 'X509_REQ_get0_signature';
procedure X509_REQ_set0_signature(req: PX509_REQ; psig: PASN1_BIT_STRING); cdecl external CLibCrypto name 'X509_REQ_set0_signature';
function X509_REQ_set1_signature_algo(req: PX509_REQ; palg: PX509_ALGOR): TIdC_INT; cdecl external CLibCrypto name 'X509_REQ_set1_signature_algo';
function X509_REQ_get_signature_nid(req: PX509_REQ): TIdC_INT; cdecl external CLibCrypto name 'X509_REQ_get_signature_nid';
function i2d_re_X509_REQ_tbs(req: PX509_REQ; pp: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_re_X509_REQ_tbs';
function X509_REQ_set_pubkey(x: PX509_REQ; pkey: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'X509_REQ_set_pubkey';
function X509_REQ_get_pubkey(req: PX509_REQ): PEVP_PKEY; cdecl external CLibCrypto name 'X509_REQ_get_pubkey';
function X509_REQ_get0_pubkey(req: PX509_REQ): PEVP_PKEY; cdecl external CLibCrypto name 'X509_REQ_get0_pubkey';
function X509_REQ_get_X509_PUBKEY(req: PX509_REQ): PX509_PUBKEY; cdecl external CLibCrypto name 'X509_REQ_get_X509_PUBKEY';
function X509_REQ_extension_nid(nid: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_REQ_extension_nid';
function X509_REQ_get_extension_nids: PIdC_INT; cdecl external CLibCrypto name 'X509_REQ_get_extension_nids';
procedure X509_REQ_set_extension_nids(nids: PIdC_INT); cdecl external CLibCrypto name 'X509_REQ_set_extension_nids';
function X509_REQ_get_extensions(req: PX509_REQ): Pstack_st_X509_EXTENSION; cdecl external CLibCrypto name 'X509_REQ_get_extensions';
function X509_REQ_add_extensions_nid(req: PX509_REQ; exts: Pstack_st_X509_EXTENSION; nid: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_REQ_add_extensions_nid';
function X509_REQ_add_extensions(req: PX509_REQ; ext: Pstack_st_X509_EXTENSION): TIdC_INT; cdecl external CLibCrypto name 'X509_REQ_add_extensions';
function X509_REQ_get_attr_count(req: PX509_REQ): TIdC_INT; cdecl external CLibCrypto name 'X509_REQ_get_attr_count';
function X509_REQ_get_attr_by_NID(req: PX509_REQ; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_REQ_get_attr_by_NID';
function X509_REQ_get_attr_by_OBJ(req: PX509_REQ; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_REQ_get_attr_by_OBJ';
function X509_REQ_get_attr(req: PX509_REQ; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl external CLibCrypto name 'X509_REQ_get_attr';
function X509_REQ_delete_attr(req: PX509_REQ; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl external CLibCrypto name 'X509_REQ_delete_attr';
function X509_REQ_add1_attr(req: PX509_REQ; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl external CLibCrypto name 'X509_REQ_add1_attr';
function X509_REQ_add1_attr_by_OBJ(req: PX509_REQ; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_REQ_add1_attr_by_OBJ';
function X509_REQ_add1_attr_by_NID(req: PX509_REQ; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_REQ_add1_attr_by_NID';
function X509_REQ_add1_attr_by_txt(req: PX509_REQ; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_REQ_add1_attr_by_txt';
function X509_CRL_set_version(x: PX509_CRL; version: TIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_set_version';
function X509_CRL_set_issuer_name(x: PX509_CRL; name: PX509_NAME): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_set_issuer_name';
function X509_CRL_set1_lastUpdate(x: PX509_CRL; tm: PASN1_TIME): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_set1_lastUpdate';
function X509_CRL_set1_nextUpdate(x: PX509_CRL; tm: PASN1_TIME): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_set1_nextUpdate';
function X509_CRL_sort(crl: PX509_CRL): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_sort';
function X509_CRL_up_ref(crl: PX509_CRL): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_up_ref';
function X509_CRL_get_version(crl: PX509_CRL): TIdC_LONG; cdecl external CLibCrypto name 'X509_CRL_get_version';
function X509_CRL_get0_lastUpdate(crl: PX509_CRL): PASN1_TIME; cdecl external CLibCrypto name 'X509_CRL_get0_lastUpdate';
function X509_CRL_get0_nextUpdate(crl: PX509_CRL): PASN1_TIME; cdecl external CLibCrypto name 'X509_CRL_get0_nextUpdate';
function X509_CRL_get_issuer(crl: PX509_CRL): PX509_NAME; cdecl external CLibCrypto name 'X509_CRL_get_issuer';
function X509_CRL_get0_extensions(crl: PX509_CRL): Pstack_st_X509_EXTENSION; cdecl external CLibCrypto name 'X509_CRL_get0_extensions';
function X509_CRL_get_REVOKED(crl: PX509_CRL): Pstack_st_X509_REVOKED; cdecl external CLibCrypto name 'X509_CRL_get_REVOKED';
function X509_CRL_get0_tbs_sigalg(crl: PX509_CRL): PX509_ALGOR; cdecl external CLibCrypto name 'X509_CRL_get0_tbs_sigalg';
procedure X509_CRL_get0_signature(crl: PX509_CRL; psig: PPASN1_BIT_STRING; palg: PPX509_ALGOR); cdecl external CLibCrypto name 'X509_CRL_get0_signature';
function X509_CRL_get_signature_nid(crl: PX509_CRL): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_get_signature_nid';
function i2d_re_X509_CRL_tbs(req: PX509_CRL; pp: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_re_X509_CRL_tbs';
function X509_REVOKED_get0_serialNumber(x: PX509_REVOKED): PASN1_INTEGER; cdecl external CLibCrypto name 'X509_REVOKED_get0_serialNumber';
function X509_REVOKED_set_serialNumber(x: PX509_REVOKED; serial: PASN1_INTEGER): TIdC_INT; cdecl external CLibCrypto name 'X509_REVOKED_set_serialNumber';
function X509_REVOKED_get0_revocationDate(x: PX509_REVOKED): PASN1_TIME; cdecl external CLibCrypto name 'X509_REVOKED_get0_revocationDate';
function X509_REVOKED_set_revocationDate(r: PX509_REVOKED; tm: PASN1_TIME): TIdC_INT; cdecl external CLibCrypto name 'X509_REVOKED_set_revocationDate';
function X509_REVOKED_get0_extensions(r: PX509_REVOKED): Pstack_st_X509_EXTENSION; cdecl external CLibCrypto name 'X509_REVOKED_get0_extensions';
function X509_CRL_diff(base: PX509_CRL; newer: PX509_CRL; skey: PEVP_PKEY; md: PEVP_MD; flags: TIdC_UINT): PX509_CRL; cdecl external CLibCrypto name 'X509_CRL_diff';
function X509_REQ_check_private_key(req: PX509_REQ; pkey: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'X509_REQ_check_private_key';
function X509_check_private_key(cert: PX509; pkey: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'X509_check_private_key';
function X509_chain_check_suiteb(perror_depth: PIdC_INT; x: PX509; chain: Pstack_st_X509; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'X509_chain_check_suiteb';
function X509_CRL_check_suiteb(crl: PX509_CRL; pk: PEVP_PKEY; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_check_suiteb';
procedure OSSL_STACK_OF_X509_free(certs: Pstack_st_X509); cdecl external CLibCrypto name 'OSSL_STACK_OF_X509_free';
function X509_chain_up_ref(chain: Pstack_st_X509): Pstack_st_X509; cdecl external CLibCrypto name 'X509_chain_up_ref';
function X509_issuer_and_serial_cmp(a: PX509; b: PX509): TIdC_INT; cdecl external CLibCrypto name 'X509_issuer_and_serial_cmp';
function X509_issuer_and_serial_hash(a: PX509): TIdC_ULONG; cdecl external CLibCrypto name 'X509_issuer_and_serial_hash';
function X509_issuer_name_cmp(a: PX509; b: PX509): TIdC_INT; cdecl external CLibCrypto name 'X509_issuer_name_cmp';
function X509_issuer_name_hash(a: PX509): TIdC_ULONG; cdecl external CLibCrypto name 'X509_issuer_name_hash';
function X509_subject_name_cmp(a: PX509; b: PX509): TIdC_INT; cdecl external CLibCrypto name 'X509_subject_name_cmp';
function X509_subject_name_hash(x: PX509): TIdC_ULONG; cdecl external CLibCrypto name 'X509_subject_name_hash';
function X509_issuer_name_hash_old(a: PX509): TIdC_ULONG; cdecl external CLibCrypto name 'X509_issuer_name_hash_old';
function X509_subject_name_hash_old(x: PX509): TIdC_ULONG; cdecl external CLibCrypto name 'X509_subject_name_hash_old';
function X509_add_cert(sk: Pstack_st_X509; cert: PX509; flags: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_add_cert';
function X509_add_certs(sk: Pstack_st_X509; certs: Pstack_st_X509; flags: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_add_certs';
function X509_cmp(a: PX509; b: PX509): TIdC_INT; cdecl external CLibCrypto name 'X509_cmp';
function X509_NAME_cmp(a: PX509_NAME; b: PX509_NAME): TIdC_INT; cdecl external CLibCrypto name 'X509_NAME_cmp';
function X509_certificate_type(x: PX509; pubkey: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'X509_certificate_type';
function X509_NAME_hash_ex(x: PX509_NAME; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; ok: PIdC_INT): TIdC_ULONG; cdecl external CLibCrypto name 'X509_NAME_hash_ex';
function X509_NAME_hash_old(x: PX509_NAME): TIdC_ULONG; cdecl external CLibCrypto name 'X509_NAME_hash_old';
function X509_CRL_cmp(a: PX509_CRL; b: PX509_CRL): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_cmp';
function X509_CRL_match(a: PX509_CRL; b: PX509_CRL): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_match';
function X509_aux_print(_out: PBIO; x: PX509; indent: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_aux_print';
function X509_print_ex_fp(bp: PFILE; x: PX509; nmflag: TIdC_ULONG; cflag: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'X509_print_ex_fp';
function X509_print_fp(bp: PFILE; x: PX509): TIdC_INT; cdecl external CLibCrypto name 'X509_print_fp';
function X509_CRL_print_fp(bp: PFILE; x: PX509_CRL): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_print_fp';
function X509_REQ_print_fp(bp: PFILE; req: PX509_REQ): TIdC_INT; cdecl external CLibCrypto name 'X509_REQ_print_fp';
function X509_NAME_print_ex_fp(fp: PFILE; nm: PX509_NAME; indent: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'X509_NAME_print_ex_fp';
function X509_NAME_print(bp: PBIO; name: PX509_NAME; obase: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_NAME_print';
function X509_NAME_print_ex(_out: PBIO; nm: PX509_NAME; indent: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'X509_NAME_print_ex';
function X509_print_ex(bp: PBIO; x: PX509; nmflag: TIdC_ULONG; cflag: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'X509_print_ex';
function X509_print(bp: PBIO; x: PX509): TIdC_INT; cdecl external CLibCrypto name 'X509_print';
function X509_ocspid_print(bp: PBIO; x: PX509): TIdC_INT; cdecl external CLibCrypto name 'X509_ocspid_print';
function X509_CRL_print_ex(_out: PBIO; x: PX509_CRL; nmflag: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_print_ex';
function X509_CRL_print(bp: PBIO; x: PX509_CRL): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_print';
function X509_REQ_print_ex(bp: PBIO; x: PX509_REQ; nmflag: TIdC_ULONG; cflag: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'X509_REQ_print_ex';
function X509_REQ_print(bp: PBIO; req: PX509_REQ): TIdC_INT; cdecl external CLibCrypto name 'X509_REQ_print';
function X509_NAME_entry_count(name: PX509_NAME): TIdC_INT; cdecl external CLibCrypto name 'X509_NAME_entry_count';
function X509_NAME_get_text_by_NID(name: PX509_NAME; nid: TIdC_INT; buf: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_NAME_get_text_by_NID';
function X509_NAME_get_text_by_OBJ(name: PX509_NAME; obj: PASN1_OBJECT; buf: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_NAME_get_text_by_OBJ';
function X509_NAME_get_index_by_NID(name: PX509_NAME; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_NAME_get_index_by_NID';
function X509_NAME_get_index_by_OBJ(name: PX509_NAME; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_NAME_get_index_by_OBJ';
function X509_NAME_get_entry(name: PX509_NAME; loc: TIdC_INT): PX509_NAME_ENTRY; cdecl external CLibCrypto name 'X509_NAME_get_entry';
function X509_NAME_delete_entry(name: PX509_NAME; loc: TIdC_INT): PX509_NAME_ENTRY; cdecl external CLibCrypto name 'X509_NAME_delete_entry';
function X509_NAME_add_entry(name: PX509_NAME; ne: PX509_NAME_ENTRY; loc: TIdC_INT; _set: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_NAME_add_entry';
function X509_NAME_add_entry_by_OBJ(name: PX509_NAME; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT; loc: TIdC_INT; _set: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_NAME_add_entry_by_OBJ';
function X509_NAME_add_entry_by_NID(name: PX509_NAME; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT; loc: TIdC_INT; _set: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_NAME_add_entry_by_NID';
function X509_NAME_ENTRY_create_by_txt(ne: PPX509_NAME_ENTRY; field: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): PX509_NAME_ENTRY; cdecl external CLibCrypto name 'X509_NAME_ENTRY_create_by_txt';
function X509_NAME_ENTRY_create_by_NID(ne: PPX509_NAME_ENTRY; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): PX509_NAME_ENTRY; cdecl external CLibCrypto name 'X509_NAME_ENTRY_create_by_NID';
function X509_NAME_add_entry_by_txt(name: PX509_NAME; field: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT; loc: TIdC_INT; _set: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_NAME_add_entry_by_txt';
function X509_NAME_ENTRY_create_by_OBJ(ne: PPX509_NAME_ENTRY; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): PX509_NAME_ENTRY; cdecl external CLibCrypto name 'X509_NAME_ENTRY_create_by_OBJ';
function X509_NAME_ENTRY_set_object(ne: PX509_NAME_ENTRY; obj: PASN1_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'X509_NAME_ENTRY_set_object';
function X509_NAME_ENTRY_set_data(ne: PX509_NAME_ENTRY; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_NAME_ENTRY_set_data';
function X509_NAME_ENTRY_get_object(ne: PX509_NAME_ENTRY): PASN1_OBJECT; cdecl external CLibCrypto name 'X509_NAME_ENTRY_get_object';
function X509_NAME_ENTRY_get_data(ne: PX509_NAME_ENTRY): PASN1_STRING; cdecl external CLibCrypto name 'X509_NAME_ENTRY_get_data';
function X509_NAME_ENTRY_set(ne: PX509_NAME_ENTRY): TIdC_INT; cdecl external CLibCrypto name 'X509_NAME_ENTRY_set';
function X509_NAME_get0_der(nm: PX509_NAME; pder: PPIdAnsiChar; pderlen: PIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'X509_NAME_get0_der';
function X509v3_get_ext_count(x: Pstack_st_X509_EXTENSION): TIdC_INT; cdecl external CLibCrypto name 'X509v3_get_ext_count';
function X509v3_get_ext_by_NID(x: Pstack_st_X509_EXTENSION; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509v3_get_ext_by_NID';
function X509v3_get_ext_by_OBJ(x: Pstack_st_X509_EXTENSION; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509v3_get_ext_by_OBJ';
function X509v3_get_ext_by_critical(x: Pstack_st_X509_EXTENSION; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509v3_get_ext_by_critical';
function X509v3_get_ext(x: Pstack_st_X509_EXTENSION; loc: TIdC_INT): PX509_EXTENSION; cdecl external CLibCrypto name 'X509v3_get_ext';
function X509v3_delete_ext(x: Pstack_st_X509_EXTENSION; loc: TIdC_INT): PX509_EXTENSION; cdecl external CLibCrypto name 'X509v3_delete_ext';
function X509v3_add_ext(x: PPstack_st_X509_EXTENSION; ex: PX509_EXTENSION; loc: TIdC_INT): Pstack_st_X509_EXTENSION; cdecl external CLibCrypto name 'X509v3_add_ext';
function X509v3_add_extensions(target: PPstack_st_X509_EXTENSION; exts: Pstack_st_X509_EXTENSION): Pstack_st_X509_EXTENSION; cdecl external CLibCrypto name 'X509v3_add_extensions';
function X509_get_ext_count(x: PX509): TIdC_INT; cdecl external CLibCrypto name 'X509_get_ext_count';
function X509_get_ext_by_NID(x: PX509; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_get_ext_by_NID';
function X509_get_ext_by_OBJ(x: PX509; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_get_ext_by_OBJ';
function X509_get_ext_by_critical(x: PX509; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_get_ext_by_critical';
function X509_get_ext(x: PX509; loc: TIdC_INT): PX509_EXTENSION; cdecl external CLibCrypto name 'X509_get_ext';
function X509_delete_ext(x: PX509; loc: TIdC_INT): PX509_EXTENSION; cdecl external CLibCrypto name 'X509_delete_ext';
function X509_add_ext(x: PX509; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_add_ext';
function X509_get_ext_d2i(x: PX509; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl external CLibCrypto name 'X509_get_ext_d2i';
function X509_add1_ext_i2d(x: PX509; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'X509_add1_ext_i2d';
function X509_CRL_get_ext_count(x: PX509_CRL): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_get_ext_count';
function X509_CRL_get_ext_by_NID(x: PX509_CRL; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_get_ext_by_NID';
function X509_CRL_get_ext_by_OBJ(x: PX509_CRL; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_get_ext_by_OBJ';
function X509_CRL_get_ext_by_critical(x: PX509_CRL; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_get_ext_by_critical';
function X509_CRL_get_ext(x: PX509_CRL; loc: TIdC_INT): PX509_EXTENSION; cdecl external CLibCrypto name 'X509_CRL_get_ext';
function X509_CRL_delete_ext(x: PX509_CRL; loc: TIdC_INT): PX509_EXTENSION; cdecl external CLibCrypto name 'X509_CRL_delete_ext';
function X509_CRL_add_ext(x: PX509_CRL; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_add_ext';
function X509_CRL_get_ext_d2i(x: PX509_CRL; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl external CLibCrypto name 'X509_CRL_get_ext_d2i';
function X509_CRL_add1_ext_i2d(x: PX509_CRL; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'X509_CRL_add1_ext_i2d';
function X509_REVOKED_get_ext_count(x: PX509_REVOKED): TIdC_INT; cdecl external CLibCrypto name 'X509_REVOKED_get_ext_count';
function X509_REVOKED_get_ext_by_NID(x: PX509_REVOKED; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_REVOKED_get_ext_by_NID';
function X509_REVOKED_get_ext_by_OBJ(x: PX509_REVOKED; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_REVOKED_get_ext_by_OBJ';
function X509_REVOKED_get_ext_by_critical(x: PX509_REVOKED; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_REVOKED_get_ext_by_critical';
function X509_REVOKED_get_ext(x: PX509_REVOKED; loc: TIdC_INT): PX509_EXTENSION; cdecl external CLibCrypto name 'X509_REVOKED_get_ext';
function X509_REVOKED_delete_ext(x: PX509_REVOKED; loc: TIdC_INT): PX509_EXTENSION; cdecl external CLibCrypto name 'X509_REVOKED_delete_ext';
function X509_REVOKED_add_ext(x: PX509_REVOKED; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_REVOKED_add_ext';
function X509_REVOKED_get_ext_d2i(x: PX509_REVOKED; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl external CLibCrypto name 'X509_REVOKED_get_ext_d2i';
function X509_REVOKED_add1_ext_i2d(x: PX509_REVOKED; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'X509_REVOKED_add1_ext_i2d';
function X509_EXTENSION_create_by_NID(ex: PPX509_EXTENSION; nid: TIdC_INT; crit: TIdC_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION; cdecl external CLibCrypto name 'X509_EXTENSION_create_by_NID';
function X509_EXTENSION_create_by_OBJ(ex: PPX509_EXTENSION; obj: PASN1_OBJECT; crit: TIdC_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION; cdecl external CLibCrypto name 'X509_EXTENSION_create_by_OBJ';
function X509_EXTENSION_set_object(ex: PX509_EXTENSION; obj: PASN1_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'X509_EXTENSION_set_object';
function X509_EXTENSION_set_critical(ex: PX509_EXTENSION; crit: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_EXTENSION_set_critical';
function X509_EXTENSION_set_data(ex: PX509_EXTENSION; data: PASN1_OCTET_STRING): TIdC_INT; cdecl external CLibCrypto name 'X509_EXTENSION_set_data';
function X509_EXTENSION_get_object(ex: PX509_EXTENSION): PASN1_OBJECT; cdecl external CLibCrypto name 'X509_EXTENSION_get_object';
function X509_EXTENSION_get_data(ne: PX509_EXTENSION): PASN1_OCTET_STRING; cdecl external CLibCrypto name 'X509_EXTENSION_get_data';
function X509_EXTENSION_get_critical(ex: PX509_EXTENSION): TIdC_INT; cdecl external CLibCrypto name 'X509_EXTENSION_get_critical';
function X509at_get_attr_count(x: Pstack_st_X509_ATTRIBUTE): TIdC_INT; cdecl external CLibCrypto name 'X509at_get_attr_count';
function X509at_get_attr_by_NID(x: Pstack_st_X509_ATTRIBUTE; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509at_get_attr_by_NID';
function X509at_get_attr_by_OBJ(sk: Pstack_st_X509_ATTRIBUTE; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509at_get_attr_by_OBJ';
function X509at_get_attr(x: Pstack_st_X509_ATTRIBUTE; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl external CLibCrypto name 'X509at_get_attr';
function X509at_delete_attr(x: Pstack_st_X509_ATTRIBUTE; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl external CLibCrypto name 'X509at_delete_attr';
function X509at_add1_attr(x: PPstack_st_X509_ATTRIBUTE; attr: PX509_ATTRIBUTE): Pstack_st_X509_ATTRIBUTE; cdecl external CLibCrypto name 'X509at_add1_attr';
function X509at_add1_attr_by_OBJ(x: PPstack_st_X509_ATTRIBUTE; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): Pstack_st_X509_ATTRIBUTE; cdecl external CLibCrypto name 'X509at_add1_attr_by_OBJ';
function X509at_add1_attr_by_NID(x: PPstack_st_X509_ATTRIBUTE; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): Pstack_st_X509_ATTRIBUTE; cdecl external CLibCrypto name 'X509at_add1_attr_by_NID';
function X509at_add1_attr_by_txt(x: PPstack_st_X509_ATTRIBUTE; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): Pstack_st_X509_ATTRIBUTE; cdecl external CLibCrypto name 'X509at_add1_attr_by_txt';
function X509at_get0_data_by_OBJ(x: Pstack_st_X509_ATTRIBUTE; obj: PASN1_OBJECT; lastpos: TIdC_INT; _type: TIdC_INT): Pointer; cdecl external CLibCrypto name 'X509at_get0_data_by_OBJ';
function X509_ATTRIBUTE_create_by_NID(attr: PPX509_ATTRIBUTE; nid: TIdC_INT; atrtype: TIdC_INT; data: Pointer; len: TIdC_INT): PX509_ATTRIBUTE; cdecl external CLibCrypto name 'X509_ATTRIBUTE_create_by_NID';
function X509_ATTRIBUTE_create_by_OBJ(attr: PPX509_ATTRIBUTE; obj: PASN1_OBJECT; atrtype: TIdC_INT; data: Pointer; len: TIdC_INT): PX509_ATTRIBUTE; cdecl external CLibCrypto name 'X509_ATTRIBUTE_create_by_OBJ';
function X509_ATTRIBUTE_create_by_txt(attr: PPX509_ATTRIBUTE; atrname: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): PX509_ATTRIBUTE; cdecl external CLibCrypto name 'X509_ATTRIBUTE_create_by_txt';
function X509_ATTRIBUTE_set1_object(attr: PX509_ATTRIBUTE; obj: PASN1_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'X509_ATTRIBUTE_set1_object';
function X509_ATTRIBUTE_set1_data(attr: PX509_ATTRIBUTE; attrtype: TIdC_INT; data: Pointer; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_ATTRIBUTE_set1_data';
function X509_ATTRIBUTE_get0_data(attr: PX509_ATTRIBUTE; idx: TIdC_INT; atrtype: TIdC_INT; data: Pointer): Pointer; cdecl external CLibCrypto name 'X509_ATTRIBUTE_get0_data';
function X509_ATTRIBUTE_count(attr: PX509_ATTRIBUTE): TIdC_INT; cdecl external CLibCrypto name 'X509_ATTRIBUTE_count';
function X509_ATTRIBUTE_get0_object(attr: PX509_ATTRIBUTE): PASN1_OBJECT; cdecl external CLibCrypto name 'X509_ATTRIBUTE_get0_object';
function X509_ATTRIBUTE_get0_type(attr: PX509_ATTRIBUTE; idx: TIdC_INT): PASN1_TYPE; cdecl external CLibCrypto name 'X509_ATTRIBUTE_get0_type';
function EVP_PKEY_get_attr_count(key: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_get_attr_count';
function EVP_PKEY_get_attr_by_NID(key: PEVP_PKEY; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_get_attr_by_NID';
function EVP_PKEY_get_attr_by_OBJ(key: PEVP_PKEY; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_get_attr_by_OBJ';
function EVP_PKEY_get_attr(key: PEVP_PKEY; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl external CLibCrypto name 'EVP_PKEY_get_attr';
function EVP_PKEY_delete_attr(key: PEVP_PKEY; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl external CLibCrypto name 'EVP_PKEY_delete_attr';
function EVP_PKEY_add1_attr(key: PEVP_PKEY; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_add1_attr';
function EVP_PKEY_add1_attr_by_OBJ(key: PEVP_PKEY; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_add1_attr_by_OBJ';
function EVP_PKEY_add1_attr_by_NID(key: PEVP_PKEY; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_add1_attr_by_NID';
function EVP_PKEY_add1_attr_by_txt(key: PEVP_PKEY; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'EVP_PKEY_add1_attr_by_txt';
function X509_find_by_issuer_and_serial(sk: Pstack_st_X509; name: PX509_NAME; serial: PASN1_INTEGER): PX509; cdecl external CLibCrypto name 'X509_find_by_issuer_and_serial';
function X509_find_by_subject(sk: Pstack_st_X509; name: PX509_NAME): PX509; cdecl external CLibCrypto name 'X509_find_by_subject';
function PBEPARAM_new: PPBEPARAM; cdecl external CLibCrypto name 'PBEPARAM_new';
procedure PBEPARAM_free(a: PPBEPARAM); cdecl external CLibCrypto name 'PBEPARAM_free';
function d2i_PBEPARAM(a: PPPBEPARAM; _in: PPIdAnsiChar; len: TIdC_LONG): PPBEPARAM; cdecl external CLibCrypto name 'd2i_PBEPARAM';
function i2d_PBEPARAM(a: PPBEPARAM; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_PBEPARAM';
function PBEPARAM_it: PASN1_ITEM; cdecl external CLibCrypto name 'PBEPARAM_it';
function PBE2PARAM_new: PPBE2PARAM; cdecl external CLibCrypto name 'PBE2PARAM_new';
procedure PBE2PARAM_free(a: PPBE2PARAM); cdecl external CLibCrypto name 'PBE2PARAM_free';
function d2i_PBE2PARAM(a: PPPBE2PARAM; _in: PPIdAnsiChar; len: TIdC_LONG): PPBE2PARAM; cdecl external CLibCrypto name 'd2i_PBE2PARAM';
function i2d_PBE2PARAM(a: PPBE2PARAM; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_PBE2PARAM';
function PBE2PARAM_it: PASN1_ITEM; cdecl external CLibCrypto name 'PBE2PARAM_it';
function PBKDF2PARAM_new: PPBKDF2PARAM; cdecl external CLibCrypto name 'PBKDF2PARAM_new';
procedure PBKDF2PARAM_free(a: PPBKDF2PARAM); cdecl external CLibCrypto name 'PBKDF2PARAM_free';
function d2i_PBKDF2PARAM(a: PPPBKDF2PARAM; _in: PPIdAnsiChar; len: TIdC_LONG): PPBKDF2PARAM; cdecl external CLibCrypto name 'd2i_PBKDF2PARAM';
function i2d_PBKDF2PARAM(a: PPBKDF2PARAM; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_PBKDF2PARAM';
function PBKDF2PARAM_it: PASN1_ITEM; cdecl external CLibCrypto name 'PBKDF2PARAM_it';
function PBMAC1PARAM_new: PPBMAC1PARAM; cdecl external CLibCrypto name 'PBMAC1PARAM_new';
procedure PBMAC1PARAM_free(a: PPBMAC1PARAM); cdecl external CLibCrypto name 'PBMAC1PARAM_free';
function d2i_PBMAC1PARAM(a: PPPBMAC1PARAM; _in: PPIdAnsiChar; len: TIdC_LONG): PPBMAC1PARAM; cdecl external CLibCrypto name 'd2i_PBMAC1PARAM';
function i2d_PBMAC1PARAM(a: PPBMAC1PARAM; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_PBMAC1PARAM';
function PBMAC1PARAM_it: PASN1_ITEM; cdecl external CLibCrypto name 'PBMAC1PARAM_it';
function SCRYPT_PARAMS_new: PSCRYPT_PARAMS; cdecl external CLibCrypto name 'SCRYPT_PARAMS_new';
procedure SCRYPT_PARAMS_free(a: PSCRYPT_PARAMS); cdecl external CLibCrypto name 'SCRYPT_PARAMS_free';
function d2i_SCRYPT_PARAMS(a: PPSCRYPT_PARAMS; _in: PPIdAnsiChar; len: TIdC_LONG): PSCRYPT_PARAMS; cdecl external CLibCrypto name 'd2i_SCRYPT_PARAMS';
function i2d_SCRYPT_PARAMS(a: PSCRYPT_PARAMS; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_SCRYPT_PARAMS';
function SCRYPT_PARAMS_it: PASN1_ITEM; cdecl external CLibCrypto name 'SCRYPT_PARAMS_it';
function PKCS5_pbe_set0_algor(algor: PX509_ALGOR; alg: TIdC_INT; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'PKCS5_pbe_set0_algor';
function PKCS5_pbe_set0_algor_ex(algor: PX509_ALGOR; alg: TIdC_INT; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; libctx: POSSL_LIB_CTX): TIdC_INT; cdecl external CLibCrypto name 'PKCS5_pbe_set0_algor_ex';
function PKCS5_pbe_set(alg: TIdC_INT; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT): PX509_ALGOR; cdecl external CLibCrypto name 'PKCS5_pbe_set';
function PKCS5_pbe_set_ex(alg: TIdC_INT; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; libctx: POSSL_LIB_CTX): PX509_ALGOR; cdecl external CLibCrypto name 'PKCS5_pbe_set_ex';
function PKCS5_pbe2_set(cipher: PEVP_CIPHER; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT): PX509_ALGOR; cdecl external CLibCrypto name 'PKCS5_pbe2_set';
function PKCS5_pbe2_set_iv(cipher: PEVP_CIPHER; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; aiv: PIdAnsiChar; prf_nid: TIdC_INT): PX509_ALGOR; cdecl external CLibCrypto name 'PKCS5_pbe2_set_iv';
function PKCS5_pbe2_set_iv_ex(cipher: PEVP_CIPHER; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; aiv: PIdAnsiChar; prf_nid: TIdC_INT; libctx: POSSL_LIB_CTX): PX509_ALGOR; cdecl external CLibCrypto name 'PKCS5_pbe2_set_iv_ex';
function PKCS5_pbe2_set_scrypt(cipher: PEVP_CIPHER; salt: PIdAnsiChar; saltlen: TIdC_INT; aiv: PIdAnsiChar; N: TIdC_UINT64; r: TIdC_UINT64; p: TIdC_UINT64): PX509_ALGOR; cdecl external CLibCrypto name 'PKCS5_pbe2_set_scrypt';
function PKCS5_pbkdf2_set(iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; prf_nid: TIdC_INT; keylen: TIdC_INT): PX509_ALGOR; cdecl external CLibCrypto name 'PKCS5_pbkdf2_set';
function PKCS5_pbkdf2_set_ex(iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; prf_nid: TIdC_INT; keylen: TIdC_INT; libctx: POSSL_LIB_CTX): PX509_ALGOR; cdecl external CLibCrypto name 'PKCS5_pbkdf2_set_ex';
function PBMAC1_get1_pbkdf2_param(macalg: PX509_ALGOR): PPBKDF2PARAM; cdecl external CLibCrypto name 'PBMAC1_get1_pbkdf2_param';
function PKCS8_PRIV_KEY_INFO_new: PPKCS8_PRIV_KEY_INFO; cdecl external CLibCrypto name 'PKCS8_PRIV_KEY_INFO_new';
procedure PKCS8_PRIV_KEY_INFO_free(a: PPKCS8_PRIV_KEY_INFO); cdecl external CLibCrypto name 'PKCS8_PRIV_KEY_INFO_free';
function d2i_PKCS8_PRIV_KEY_INFO(a: PPPKCS8_PRIV_KEY_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS8_PRIV_KEY_INFO; cdecl external CLibCrypto name 'd2i_PKCS8_PRIV_KEY_INFO';
function i2d_PKCS8_PRIV_KEY_INFO(a: PPKCS8_PRIV_KEY_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS8_PRIV_KEY_INFO';
function PKCS8_PRIV_KEY_INFO_it: PASN1_ITEM; cdecl external CLibCrypto name 'PKCS8_PRIV_KEY_INFO_it';
function EVP_PKCS82PKEY(p8: PPKCS8_PRIV_KEY_INFO): PEVP_PKEY; cdecl external CLibCrypto name 'EVP_PKCS82PKEY';
function EVP_PKCS82PKEY_ex(p8: PPKCS8_PRIV_KEY_INFO; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl external CLibCrypto name 'EVP_PKCS82PKEY_ex';
function EVP_PKEY2PKCS8(pkey: PEVP_PKEY): PPKCS8_PRIV_KEY_INFO; cdecl external CLibCrypto name 'EVP_PKEY2PKCS8';
function PKCS8_pkey_set0(priv: PPKCS8_PRIV_KEY_INFO; aobj: PASN1_OBJECT; version: TIdC_INT; ptype: TIdC_INT; pval: Pointer; penc: PIdAnsiChar; penclen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'PKCS8_pkey_set0';
function PKCS8_pkey_get0(ppkalg: PPASN1_OBJECT; pk: PPIdAnsiChar; ppklen: PIdC_INT; pa: PPX509_ALGOR; p8: PPKCS8_PRIV_KEY_INFO): TIdC_INT; cdecl external CLibCrypto name 'PKCS8_pkey_get0';
function PKCS8_pkey_get0_attrs(p8: PPKCS8_PRIV_KEY_INFO): Pstack_st_X509_ATTRIBUTE; cdecl external CLibCrypto name 'PKCS8_pkey_get0_attrs';
function PKCS8_pkey_add1_attr(p8: PPKCS8_PRIV_KEY_INFO; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl external CLibCrypto name 'PKCS8_pkey_add1_attr';
function PKCS8_pkey_add1_attr_by_NID(p8: PPKCS8_PRIV_KEY_INFO; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'PKCS8_pkey_add1_attr_by_NID';
function PKCS8_pkey_add1_attr_by_OBJ(p8: PPKCS8_PRIV_KEY_INFO; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'PKCS8_pkey_add1_attr_by_OBJ';
procedure X509_PUBKEY_set0_public_key(pub: PX509_PUBKEY; penc: PIdAnsiChar; penclen: TIdC_INT); cdecl external CLibCrypto name 'X509_PUBKEY_set0_public_key';
function X509_PUBKEY_set0_param(pub: PX509_PUBKEY; aobj: PASN1_OBJECT; ptype: TIdC_INT; pval: Pointer; penc: PIdAnsiChar; penclen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_PUBKEY_set0_param';
function X509_PUBKEY_get0_param(ppkalg: PPASN1_OBJECT; pk: PPIdAnsiChar; ppklen: PIdC_INT; pa: PPX509_ALGOR; pub: PX509_PUBKEY): TIdC_INT; cdecl external CLibCrypto name 'X509_PUBKEY_get0_param';
function X509_PUBKEY_eq(a: PX509_PUBKEY; b: PX509_PUBKEY): TIdC_INT; cdecl external CLibCrypto name 'X509_PUBKEY_eq';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  X509_CRL_set_default_method_procname = 'X509_CRL_set_default_method';
  X509_CRL_set_default_method_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_METHOD_new_procname = 'X509_CRL_METHOD_new';
  X509_CRL_METHOD_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_METHOD_free_procname = 'X509_CRL_METHOD_free';
  X509_CRL_METHOD_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_set_meth_data_procname = 'X509_CRL_set_meth_data';
  X509_CRL_set_meth_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_get_meth_data_procname = 'X509_CRL_get_meth_data';
  X509_CRL_get_meth_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_verify_cert_error_string_procname = 'X509_verify_cert_error_string';
  X509_verify_cert_error_string_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_verify_procname = 'X509_verify';
  X509_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_self_signed_procname = 'X509_self_signed';
  X509_self_signed_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_REQ_verify_ex_procname = 'X509_REQ_verify_ex';
  X509_REQ_verify_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_REQ_verify_procname = 'X509_REQ_verify';
  X509_REQ_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_verify_procname = 'X509_CRL_verify';
  X509_CRL_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NETSCAPE_SPKI_verify_procname = 'NETSCAPE_SPKI_verify';
  NETSCAPE_SPKI_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NETSCAPE_SPKI_b64_decode_procname = 'NETSCAPE_SPKI_b64_decode';
  NETSCAPE_SPKI_b64_decode_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NETSCAPE_SPKI_b64_encode_procname = 'NETSCAPE_SPKI_b64_encode';
  NETSCAPE_SPKI_b64_encode_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NETSCAPE_SPKI_get_pubkey_procname = 'NETSCAPE_SPKI_get_pubkey';
  NETSCAPE_SPKI_get_pubkey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NETSCAPE_SPKI_set_pubkey_procname = 'NETSCAPE_SPKI_set_pubkey';
  NETSCAPE_SPKI_set_pubkey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NETSCAPE_SPKI_print_procname = 'NETSCAPE_SPKI_print';
  NETSCAPE_SPKI_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_signature_dump_procname = 'X509_signature_dump';
  X509_signature_dump_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_signature_print_procname = 'X509_signature_print';
  X509_signature_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_sign_procname = 'X509_sign';
  X509_sign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_sign_ctx_procname = 'X509_sign_ctx';
  X509_sign_ctx_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_sign_procname = 'X509_REQ_sign';
  X509_REQ_sign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_sign_ctx_procname = 'X509_REQ_sign_ctx';
  X509_REQ_sign_ctx_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_sign_procname = 'X509_CRL_sign';
  X509_CRL_sign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_sign_ctx_procname = 'X509_CRL_sign_ctx';
  X509_CRL_sign_ctx_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NETSCAPE_SPKI_sign_procname = 'NETSCAPE_SPKI_sign';
  NETSCAPE_SPKI_sign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_pubkey_digest_procname = 'X509_pubkey_digest';
  X509_pubkey_digest_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_digest_procname = 'X509_digest';
  X509_digest_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_digest_sig_procname = 'X509_digest_sig';
  X509_digest_sig_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_CRL_digest_procname = 'X509_CRL_digest';
  X509_CRL_digest_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_digest_procname = 'X509_REQ_digest';
  X509_REQ_digest_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_digest_procname = 'X509_NAME_digest';
  X509_NAME_digest_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_load_http_procname = 'X509_load_http';
  X509_load_http_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_CRL_load_http_procname = 'X509_CRL_load_http';
  X509_CRL_load_http_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_X509_fp_procname = 'd2i_X509_fp';
  d2i_X509_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_X509_fp_procname = 'i2d_X509_fp';
  i2d_X509_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_CRL_fp_procname = 'd2i_X509_CRL_fp';
  d2i_X509_CRL_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_X509_CRL_fp_procname = 'i2d_X509_CRL_fp';
  i2d_X509_CRL_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_REQ_fp_procname = 'd2i_X509_REQ_fp';
  d2i_X509_REQ_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_X509_REQ_fp_procname = 'i2d_X509_REQ_fp';
  i2d_X509_REQ_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_RSAPrivateKey_fp_procname = 'd2i_RSAPrivateKey_fp';
  d2i_RSAPrivateKey_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  d2i_RSAPrivateKey_fp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_RSAPrivateKey_fp_procname = 'i2d_RSAPrivateKey_fp';
  i2d_RSAPrivateKey_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2d_RSAPrivateKey_fp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_RSAPublicKey_fp_procname = 'd2i_RSAPublicKey_fp';
  d2i_RSAPublicKey_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  d2i_RSAPublicKey_fp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_RSAPublicKey_fp_procname = 'i2d_RSAPublicKey_fp';
  i2d_RSAPublicKey_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2d_RSAPublicKey_fp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_RSA_PUBKEY_fp_procname = 'd2i_RSA_PUBKEY_fp';
  d2i_RSA_PUBKEY_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  d2i_RSA_PUBKEY_fp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_RSA_PUBKEY_fp_procname = 'i2d_RSA_PUBKEY_fp';
  i2d_RSA_PUBKEY_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2d_RSA_PUBKEY_fp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_DSA_PUBKEY_fp_procname = 'd2i_DSA_PUBKEY_fp';
  d2i_DSA_PUBKEY_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  d2i_DSA_PUBKEY_fp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_DSA_PUBKEY_fp_procname = 'i2d_DSA_PUBKEY_fp';
  i2d_DSA_PUBKEY_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2d_DSA_PUBKEY_fp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_DSAPrivateKey_fp_procname = 'd2i_DSAPrivateKey_fp';
  d2i_DSAPrivateKey_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  d2i_DSAPrivateKey_fp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_DSAPrivateKey_fp_procname = 'i2d_DSAPrivateKey_fp';
  i2d_DSAPrivateKey_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2d_DSAPrivateKey_fp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_EC_PUBKEY_fp_procname = 'd2i_EC_PUBKEY_fp';
  d2i_EC_PUBKEY_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  d2i_EC_PUBKEY_fp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_EC_PUBKEY_fp_procname = 'i2d_EC_PUBKEY_fp';
  i2d_EC_PUBKEY_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2d_EC_PUBKEY_fp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_ECPrivateKey_fp_procname = 'd2i_ECPrivateKey_fp';
  d2i_ECPrivateKey_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  d2i_ECPrivateKey_fp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_ECPrivateKey_fp_procname = 'i2d_ECPrivateKey_fp';
  i2d_ECPrivateKey_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2d_ECPrivateKey_fp_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_PKCS8_fp_procname = 'd2i_PKCS8_fp';
  d2i_PKCS8_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS8_fp_procname = 'i2d_PKCS8_fp';
  i2d_PKCS8_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_PUBKEY_fp_procname = 'd2i_X509_PUBKEY_fp';
  d2i_X509_PUBKEY_fp_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_X509_PUBKEY_fp_procname = 'i2d_X509_PUBKEY_fp';
  i2d_X509_PUBKEY_fp_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_PKCS8_PRIV_KEY_INFO_fp_procname = 'd2i_PKCS8_PRIV_KEY_INFO_fp';
  d2i_PKCS8_PRIV_KEY_INFO_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS8_PRIV_KEY_INFO_fp_procname = 'i2d_PKCS8_PRIV_KEY_INFO_fp';
  i2d_PKCS8_PRIV_KEY_INFO_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS8PrivateKeyInfo_fp_procname = 'i2d_PKCS8PrivateKeyInfo_fp';
  i2d_PKCS8PrivateKeyInfo_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PrivateKey_fp_procname = 'i2d_PrivateKey_fp';
  i2d_PrivateKey_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PrivateKey_ex_fp_procname = 'd2i_PrivateKey_ex_fp';
  d2i_PrivateKey_ex_fp_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_PrivateKey_fp_procname = 'd2i_PrivateKey_fp';
  d2i_PrivateKey_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PUBKEY_fp_procname = 'i2d_PUBKEY_fp';
  i2d_PUBKEY_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PUBKEY_ex_fp_procname = 'd2i_PUBKEY_ex_fp';
  d2i_PUBKEY_ex_fp_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  d2i_PUBKEY_fp_procname = 'd2i_PUBKEY_fp';
  d2i_PUBKEY_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_bio_procname = 'd2i_X509_bio';
  d2i_X509_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_X509_bio_procname = 'i2d_X509_bio';
  i2d_X509_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_CRL_bio_procname = 'd2i_X509_CRL_bio';
  d2i_X509_CRL_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_X509_CRL_bio_procname = 'i2d_X509_CRL_bio';
  i2d_X509_CRL_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_REQ_bio_procname = 'd2i_X509_REQ_bio';
  d2i_X509_REQ_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_X509_REQ_bio_procname = 'i2d_X509_REQ_bio';
  i2d_X509_REQ_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_RSAPrivateKey_bio_procname = 'd2i_RSAPrivateKey_bio';
  d2i_RSAPrivateKey_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  d2i_RSAPrivateKey_bio_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_RSAPrivateKey_bio_procname = 'i2d_RSAPrivateKey_bio';
  i2d_RSAPrivateKey_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2d_RSAPrivateKey_bio_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_RSAPublicKey_bio_procname = 'd2i_RSAPublicKey_bio';
  d2i_RSAPublicKey_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  d2i_RSAPublicKey_bio_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_RSAPublicKey_bio_procname = 'i2d_RSAPublicKey_bio';
  i2d_RSAPublicKey_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2d_RSAPublicKey_bio_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_RSA_PUBKEY_bio_procname = 'd2i_RSA_PUBKEY_bio';
  d2i_RSA_PUBKEY_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  d2i_RSA_PUBKEY_bio_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_RSA_PUBKEY_bio_procname = 'i2d_RSA_PUBKEY_bio';
  i2d_RSA_PUBKEY_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2d_RSA_PUBKEY_bio_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_DSA_PUBKEY_bio_procname = 'd2i_DSA_PUBKEY_bio';
  d2i_DSA_PUBKEY_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  d2i_DSA_PUBKEY_bio_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_DSA_PUBKEY_bio_procname = 'i2d_DSA_PUBKEY_bio';
  i2d_DSA_PUBKEY_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2d_DSA_PUBKEY_bio_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_DSAPrivateKey_bio_procname = 'd2i_DSAPrivateKey_bio';
  d2i_DSAPrivateKey_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  d2i_DSAPrivateKey_bio_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_DSAPrivateKey_bio_procname = 'i2d_DSAPrivateKey_bio';
  i2d_DSAPrivateKey_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2d_DSAPrivateKey_bio_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_EC_PUBKEY_bio_procname = 'd2i_EC_PUBKEY_bio';
  d2i_EC_PUBKEY_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  d2i_EC_PUBKEY_bio_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_EC_PUBKEY_bio_procname = 'i2d_EC_PUBKEY_bio';
  i2d_EC_PUBKEY_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2d_EC_PUBKEY_bio_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_ECPrivateKey_bio_procname = 'd2i_ECPrivateKey_bio';
  d2i_ECPrivateKey_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  d2i_ECPrivateKey_bio_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_ECPrivateKey_bio_procname = 'i2d_ECPrivateKey_bio';
  i2d_ECPrivateKey_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2d_ECPrivateKey_bio_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_PKCS8_bio_procname = 'd2i_PKCS8_bio';
  d2i_PKCS8_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS8_bio_procname = 'i2d_PKCS8_bio';
  i2d_PKCS8_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_PUBKEY_bio_procname = 'd2i_X509_PUBKEY_bio';
  d2i_X509_PUBKEY_bio_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_X509_PUBKEY_bio_procname = 'i2d_X509_PUBKEY_bio';
  i2d_X509_PUBKEY_bio_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_PKCS8_PRIV_KEY_INFO_bio_procname = 'd2i_PKCS8_PRIV_KEY_INFO_bio';
  d2i_PKCS8_PRIV_KEY_INFO_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS8_PRIV_KEY_INFO_bio_procname = 'i2d_PKCS8_PRIV_KEY_INFO_bio';
  i2d_PKCS8_PRIV_KEY_INFO_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS8PrivateKeyInfo_bio_procname = 'i2d_PKCS8PrivateKeyInfo_bio';
  i2d_PKCS8PrivateKeyInfo_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PrivateKey_bio_procname = 'i2d_PrivateKey_bio';
  i2d_PrivateKey_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PrivateKey_ex_bio_procname = 'd2i_PrivateKey_ex_bio';
  d2i_PrivateKey_ex_bio_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_PrivateKey_bio_procname = 'd2i_PrivateKey_bio';
  d2i_PrivateKey_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PUBKEY_bio_procname = 'i2d_PUBKEY_bio';
  i2d_PUBKEY_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PUBKEY_ex_bio_procname = 'd2i_PUBKEY_ex_bio';
  d2i_PUBKEY_ex_bio_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  d2i_PUBKEY_bio_procname = 'd2i_PUBKEY_bio';
  d2i_PUBKEY_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_dup_procname = 'X509_dup';
  X509_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_ALGOR_dup_procname = 'X509_ALGOR_dup';
  X509_ALGOR_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_ATTRIBUTE_dup_procname = 'X509_ATTRIBUTE_dup';
  X509_ATTRIBUTE_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_dup_procname = 'X509_CRL_dup';
  X509_CRL_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_EXTENSION_dup_procname = 'X509_EXTENSION_dup';
  X509_EXTENSION_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_PUBKEY_dup_procname = 'X509_PUBKEY_dup';
  X509_PUBKEY_dup_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_REQ_dup_procname = 'X509_REQ_dup';
  X509_REQ_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REVOKED_dup_procname = 'X509_REVOKED_dup';
  X509_REVOKED_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_ALGOR_set0_procname = 'X509_ALGOR_set0';
  X509_ALGOR_set0_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_ALGOR_get0_procname = 'X509_ALGOR_get0';
  X509_ALGOR_get0_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_ALGOR_set_md_procname = 'X509_ALGOR_set_md';
  X509_ALGOR_set_md_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_ALGOR_cmp_procname = 'X509_ALGOR_cmp';
  X509_ALGOR_cmp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_ALGOR_copy_procname = 'X509_ALGOR_copy';
  X509_ALGOR_copy_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1h);

  X509_NAME_dup_procname = 'X509_NAME_dup';
  X509_NAME_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_ENTRY_dup_procname = 'X509_NAME_ENTRY_dup';
  X509_NAME_ENTRY_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_cmp_time_procname = 'X509_cmp_time';
  X509_cmp_time_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_cmp_current_time_procname = 'X509_cmp_current_time';
  X509_cmp_current_time_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_cmp_timeframe_procname = 'X509_cmp_timeframe';
  X509_cmp_timeframe_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_time_adj_procname = 'X509_time_adj';
  X509_time_adj_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_time_adj_ex_procname = 'X509_time_adj_ex';
  X509_time_adj_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_gmtime_adj_procname = 'X509_gmtime_adj';
  X509_gmtime_adj_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_default_cert_area_procname = 'X509_get_default_cert_area';
  X509_get_default_cert_area_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_default_cert_dir_procname = 'X509_get_default_cert_dir';
  X509_get_default_cert_dir_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_default_cert_file_procname = 'X509_get_default_cert_file';
  X509_get_default_cert_file_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_default_cert_dir_env_procname = 'X509_get_default_cert_dir_env';
  X509_get_default_cert_dir_env_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_default_cert_file_env_procname = 'X509_get_default_cert_file_env';
  X509_get_default_cert_file_env_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_default_private_dir_procname = 'X509_get_default_private_dir';
  X509_get_default_private_dir_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_to_X509_REQ_procname = 'X509_to_X509_REQ';
  X509_to_X509_REQ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_to_X509_procname = 'X509_REQ_to_X509';
  X509_REQ_to_X509_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_ALGOR_new_procname = 'X509_ALGOR_new';
  X509_ALGOR_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_ALGOR_free_procname = 'X509_ALGOR_free';
  X509_ALGOR_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_ALGOR_procname = 'd2i_X509_ALGOR';
  d2i_X509_ALGOR_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_X509_ALGOR_procname = 'i2d_X509_ALGOR';
  i2d_X509_ALGOR_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_ALGOR_it_procname = 'X509_ALGOR_it';
  X509_ALGOR_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_ALGORS_procname = 'd2i_X509_ALGORS';
  d2i_X509_ALGORS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_X509_ALGORS_procname = 'i2d_X509_ALGORS';
  i2d_X509_ALGORS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_ALGORS_it_procname = 'X509_ALGORS_it';
  X509_ALGORS_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VAL_new_procname = 'X509_VAL_new';
  X509_VAL_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VAL_free_procname = 'X509_VAL_free';
  X509_VAL_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_VAL_procname = 'd2i_X509_VAL';
  d2i_X509_VAL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_X509_VAL_procname = 'i2d_X509_VAL';
  i2d_X509_VAL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_VAL_it_procname = 'X509_VAL_it';
  X509_VAL_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_PUBKEY_new_procname = 'X509_PUBKEY_new';
  X509_PUBKEY_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_PUBKEY_free_procname = 'X509_PUBKEY_free';
  X509_PUBKEY_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_PUBKEY_procname = 'd2i_X509_PUBKEY';
  d2i_X509_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_X509_PUBKEY_procname = 'i2d_X509_PUBKEY';
  i2d_X509_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_PUBKEY_it_procname = 'X509_PUBKEY_it';
  X509_PUBKEY_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_PUBKEY_new_ex_procname = 'X509_PUBKEY_new_ex';
  X509_PUBKEY_new_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_PUBKEY_set_procname = 'X509_PUBKEY_set';
  X509_PUBKEY_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_PUBKEY_get0_procname = 'X509_PUBKEY_get0';
  X509_PUBKEY_get0_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_PUBKEY_get_procname = 'X509_PUBKEY_get';
  X509_PUBKEY_get_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_pubkey_parameters_procname = 'X509_get_pubkey_parameters';
  X509_get_pubkey_parameters_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_pathlen_procname = 'X509_get_pathlen';
  X509_get_pathlen_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PUBKEY_procname = 'd2i_PUBKEY';
  d2i_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PUBKEY_procname = 'i2d_PUBKEY';
  i2d_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PUBKEY_ex_procname = 'd2i_PUBKEY_ex';
  d2i_PUBKEY_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_RSA_PUBKEY_procname = 'd2i_RSA_PUBKEY';
  d2i_RSA_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  d2i_RSA_PUBKEY_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_RSA_PUBKEY_procname = 'i2d_RSA_PUBKEY';
  i2d_RSA_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2d_RSA_PUBKEY_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_DSA_PUBKEY_procname = 'd2i_DSA_PUBKEY';
  d2i_DSA_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  d2i_DSA_PUBKEY_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_DSA_PUBKEY_procname = 'i2d_DSA_PUBKEY';
  i2d_DSA_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2d_DSA_PUBKEY_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  d2i_EC_PUBKEY_procname = 'd2i_EC_PUBKEY';
  d2i_EC_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  d2i_EC_PUBKEY_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_EC_PUBKEY_procname = 'i2d_EC_PUBKEY';
  i2d_EC_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  i2d_EC_PUBKEY_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_SIG_new_procname = 'X509_SIG_new';
  X509_SIG_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_SIG_free_procname = 'X509_SIG_free';
  X509_SIG_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_SIG_procname = 'd2i_X509_SIG';
  d2i_X509_SIG_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_X509_SIG_procname = 'i2d_X509_SIG';
  i2d_X509_SIG_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_SIG_it_procname = 'X509_SIG_it';
  X509_SIG_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_SIG_get0_procname = 'X509_SIG_get0';
  X509_SIG_get0_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_SIG_getm_procname = 'X509_SIG_getm';
  X509_SIG_getm_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_INFO_new_procname = 'X509_REQ_INFO_new';
  X509_REQ_INFO_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_INFO_free_procname = 'X509_REQ_INFO_free';
  X509_REQ_INFO_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_REQ_INFO_procname = 'd2i_X509_REQ_INFO';
  d2i_X509_REQ_INFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_X509_REQ_INFO_procname = 'i2d_X509_REQ_INFO';
  i2d_X509_REQ_INFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_INFO_it_procname = 'X509_REQ_INFO_it';
  X509_REQ_INFO_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_new_procname = 'X509_REQ_new';
  X509_REQ_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_free_procname = 'X509_REQ_free';
  X509_REQ_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_REQ_procname = 'd2i_X509_REQ';
  d2i_X509_REQ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_X509_REQ_procname = 'i2d_X509_REQ';
  i2d_X509_REQ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_it_procname = 'X509_REQ_it';
  X509_REQ_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_new_ex_procname = 'X509_REQ_new_ex';
  X509_REQ_new_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_ATTRIBUTE_new_procname = 'X509_ATTRIBUTE_new';
  X509_ATTRIBUTE_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_ATTRIBUTE_free_procname = 'X509_ATTRIBUTE_free';
  X509_ATTRIBUTE_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_ATTRIBUTE_procname = 'd2i_X509_ATTRIBUTE';
  d2i_X509_ATTRIBUTE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_X509_ATTRIBUTE_procname = 'i2d_X509_ATTRIBUTE';
  i2d_X509_ATTRIBUTE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_ATTRIBUTE_it_procname = 'X509_ATTRIBUTE_it';
  X509_ATTRIBUTE_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_ATTRIBUTE_create_procname = 'X509_ATTRIBUTE_create';
  X509_ATTRIBUTE_create_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_EXTENSION_new_procname = 'X509_EXTENSION_new';
  X509_EXTENSION_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_EXTENSION_free_procname = 'X509_EXTENSION_free';
  X509_EXTENSION_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_EXTENSION_procname = 'd2i_X509_EXTENSION';
  d2i_X509_EXTENSION_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_X509_EXTENSION_procname = 'i2d_X509_EXTENSION';
  i2d_X509_EXTENSION_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_EXTENSION_it_procname = 'X509_EXTENSION_it';
  X509_EXTENSION_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_EXTENSIONS_procname = 'd2i_X509_EXTENSIONS';
  d2i_X509_EXTENSIONS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_X509_EXTENSIONS_procname = 'i2d_X509_EXTENSIONS';
  i2d_X509_EXTENSIONS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_EXTENSIONS_it_procname = 'X509_EXTENSIONS_it';
  X509_EXTENSIONS_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_ENTRY_new_procname = 'X509_NAME_ENTRY_new';
  X509_NAME_ENTRY_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_ENTRY_free_procname = 'X509_NAME_ENTRY_free';
  X509_NAME_ENTRY_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_NAME_ENTRY_procname = 'd2i_X509_NAME_ENTRY';
  d2i_X509_NAME_ENTRY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_X509_NAME_ENTRY_procname = 'i2d_X509_NAME_ENTRY';
  i2d_X509_NAME_ENTRY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_ENTRY_it_procname = 'X509_NAME_ENTRY_it';
  X509_NAME_ENTRY_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_new_procname = 'X509_NAME_new';
  X509_NAME_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_free_procname = 'X509_NAME_free';
  X509_NAME_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_NAME_procname = 'd2i_X509_NAME';
  d2i_X509_NAME_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_X509_NAME_procname = 'i2d_X509_NAME';
  i2d_X509_NAME_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_it_procname = 'X509_NAME_it';
  X509_NAME_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_set_procname = 'X509_NAME_set';
  X509_NAME_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CINF_new_procname = 'X509_CINF_new';
  X509_CINF_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CINF_free_procname = 'X509_CINF_free';
  X509_CINF_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_CINF_procname = 'd2i_X509_CINF';
  d2i_X509_CINF_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_X509_CINF_procname = 'i2d_X509_CINF';
  i2d_X509_CINF_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CINF_it_procname = 'X509_CINF_it';
  X509_CINF_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_new_procname = 'X509_new';
  X509_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_free_procname = 'X509_free';
  X509_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_procname = 'd2i_X509';
  d2i_X509_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_X509_procname = 'i2d_X509';
  i2d_X509_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_it_procname = 'X509_it';
  X509_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_new_ex_procname = 'X509_new_ex';
  X509_new_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_CERT_AUX_new_procname = 'X509_CERT_AUX_new';
  X509_CERT_AUX_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CERT_AUX_free_procname = 'X509_CERT_AUX_free';
  X509_CERT_AUX_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_CERT_AUX_procname = 'd2i_X509_CERT_AUX';
  d2i_X509_CERT_AUX_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_X509_CERT_AUX_procname = 'i2d_X509_CERT_AUX';
  i2d_X509_CERT_AUX_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CERT_AUX_it_procname = 'X509_CERT_AUX_it';
  X509_CERT_AUX_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_set_ex_data_procname = 'X509_set_ex_data';
  X509_set_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_ex_data_procname = 'X509_get_ex_data';
  X509_get_ex_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_AUX_procname = 'd2i_X509_AUX';
  d2i_X509_AUX_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_X509_AUX_procname = 'i2d_X509_AUX';
  i2d_X509_AUX_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_re_X509_tbs_procname = 'i2d_re_X509_tbs';
  i2d_re_X509_tbs_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_SIG_INFO_get_procname = 'X509_SIG_INFO_get';
  X509_SIG_INFO_get_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  X509_SIG_INFO_set_procname = 'X509_SIG_INFO_set';
  X509_SIG_INFO_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  X509_get_signature_info_procname = 'X509_get_signature_info';
  X509_get_signature_info_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  X509_get0_signature_procname = 'X509_get0_signature';
  X509_get0_signature_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_signature_nid_procname = 'X509_get_signature_nid';
  X509_get_signature_nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_set0_distinguishing_id_procname = 'X509_set0_distinguishing_id';
  X509_set0_distinguishing_id_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_get0_distinguishing_id_procname = 'X509_get0_distinguishing_id';
  X509_get0_distinguishing_id_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_REQ_set0_distinguishing_id_procname = 'X509_REQ_set0_distinguishing_id';
  X509_REQ_set0_distinguishing_id_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_REQ_get0_distinguishing_id_procname = 'X509_REQ_get0_distinguishing_id';
  X509_REQ_get0_distinguishing_id_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_alias_set1_procname = 'X509_alias_set1';
  X509_alias_set1_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_keyid_set1_procname = 'X509_keyid_set1';
  X509_keyid_set1_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_alias_get0_procname = 'X509_alias_get0';
  X509_alias_get0_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_keyid_get0_procname = 'X509_keyid_get0';
  X509_keyid_get0_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REVOKED_new_procname = 'X509_REVOKED_new';
  X509_REVOKED_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REVOKED_free_procname = 'X509_REVOKED_free';
  X509_REVOKED_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_REVOKED_procname = 'd2i_X509_REVOKED';
  d2i_X509_REVOKED_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_X509_REVOKED_procname = 'i2d_X509_REVOKED';
  i2d_X509_REVOKED_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REVOKED_it_procname = 'X509_REVOKED_it';
  X509_REVOKED_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_INFO_new_procname = 'X509_CRL_INFO_new';
  X509_CRL_INFO_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_INFO_free_procname = 'X509_CRL_INFO_free';
  X509_CRL_INFO_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_CRL_INFO_procname = 'd2i_X509_CRL_INFO';
  d2i_X509_CRL_INFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_X509_CRL_INFO_procname = 'i2d_X509_CRL_INFO';
  i2d_X509_CRL_INFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_INFO_it_procname = 'X509_CRL_INFO_it';
  X509_CRL_INFO_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_new_procname = 'X509_CRL_new';
  X509_CRL_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_free_procname = 'X509_CRL_free';
  X509_CRL_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_X509_CRL_procname = 'd2i_X509_CRL';
  d2i_X509_CRL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_X509_CRL_procname = 'i2d_X509_CRL';
  i2d_X509_CRL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_it_procname = 'X509_CRL_it';
  X509_CRL_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_new_ex_procname = 'X509_CRL_new_ex';
  X509_CRL_new_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_CRL_add0_revoked_procname = 'X509_CRL_add0_revoked';
  X509_CRL_add0_revoked_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_get0_by_serial_procname = 'X509_CRL_get0_by_serial';
  X509_CRL_get0_by_serial_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_get0_by_cert_procname = 'X509_CRL_get0_by_cert';
  X509_CRL_get0_by_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_PKEY_new_procname = 'X509_PKEY_new';
  X509_PKEY_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_PKEY_free_procname = 'X509_PKEY_free';
  X509_PKEY_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NETSCAPE_SPKI_new_procname = 'NETSCAPE_SPKI_new';
  NETSCAPE_SPKI_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NETSCAPE_SPKI_free_procname = 'NETSCAPE_SPKI_free';
  NETSCAPE_SPKI_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_NETSCAPE_SPKI_procname = 'd2i_NETSCAPE_SPKI';
  d2i_NETSCAPE_SPKI_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_NETSCAPE_SPKI_procname = 'i2d_NETSCAPE_SPKI';
  i2d_NETSCAPE_SPKI_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NETSCAPE_SPKI_it_procname = 'NETSCAPE_SPKI_it';
  NETSCAPE_SPKI_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NETSCAPE_SPKAC_new_procname = 'NETSCAPE_SPKAC_new';
  NETSCAPE_SPKAC_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NETSCAPE_SPKAC_free_procname = 'NETSCAPE_SPKAC_free';
  NETSCAPE_SPKAC_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_NETSCAPE_SPKAC_procname = 'd2i_NETSCAPE_SPKAC';
  d2i_NETSCAPE_SPKAC_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_NETSCAPE_SPKAC_procname = 'i2d_NETSCAPE_SPKAC';
  i2d_NETSCAPE_SPKAC_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NETSCAPE_SPKAC_it_procname = 'NETSCAPE_SPKAC_it';
  NETSCAPE_SPKAC_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NETSCAPE_CERT_SEQUENCE_new_procname = 'NETSCAPE_CERT_SEQUENCE_new';
  NETSCAPE_CERT_SEQUENCE_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NETSCAPE_CERT_SEQUENCE_free_procname = 'NETSCAPE_CERT_SEQUENCE_free';
  NETSCAPE_CERT_SEQUENCE_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_NETSCAPE_CERT_SEQUENCE_procname = 'd2i_NETSCAPE_CERT_SEQUENCE';
  d2i_NETSCAPE_CERT_SEQUENCE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_NETSCAPE_CERT_SEQUENCE_procname = 'i2d_NETSCAPE_CERT_SEQUENCE';
  i2d_NETSCAPE_CERT_SEQUENCE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  NETSCAPE_CERT_SEQUENCE_it_procname = 'NETSCAPE_CERT_SEQUENCE_it';
  NETSCAPE_CERT_SEQUENCE_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_INFO_new_procname = 'X509_INFO_new';
  X509_INFO_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_INFO_free_procname = 'X509_INFO_free';
  X509_INFO_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_oneline_procname = 'X509_NAME_oneline';
  X509_NAME_oneline_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_verify_procname = 'ASN1_verify';
  ASN1_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_verify_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ASN1_digest_procname = 'ASN1_digest';
  ASN1_digest_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_digest_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ASN1_sign_procname = 'ASN1_sign';
  ASN1_sign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  ASN1_sign_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ASN1_item_digest_procname = 'ASN1_item_digest';
  ASN1_item_digest_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_item_verify_procname = 'ASN1_item_verify';
  ASN1_item_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_item_verify_ctx_procname = 'ASN1_item_verify_ctx';
  ASN1_item_verify_ctx_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  ASN1_item_sign_procname = 'ASN1_item_sign';
  ASN1_item_sign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  ASN1_item_sign_ctx_procname = 'ASN1_item_sign_ctx';
  ASN1_item_sign_ctx_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_version_procname = 'X509_get_version';
  X509_get_version_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_set_version_procname = 'X509_set_version';
  X509_set_version_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_set_serialNumber_procname = 'X509_set_serialNumber';
  X509_set_serialNumber_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_serialNumber_procname = 'X509_get_serialNumber';
  X509_get_serialNumber_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get0_serialNumber_procname = 'X509_get0_serialNumber';
  X509_get0_serialNumber_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_set_issuer_name_procname = 'X509_set_issuer_name';
  X509_set_issuer_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_issuer_name_procname = 'X509_get_issuer_name';
  X509_get_issuer_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_set_subject_name_procname = 'X509_set_subject_name';
  X509_set_subject_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_subject_name_procname = 'X509_get_subject_name';
  X509_get_subject_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get0_notBefore_procname = 'X509_get0_notBefore';
  X509_get0_notBefore_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_getm_notBefore_procname = 'X509_getm_notBefore';
  X509_getm_notBefore_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_set1_notBefore_procname = 'X509_set1_notBefore';
  X509_set1_notBefore_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get0_notAfter_procname = 'X509_get0_notAfter';
  X509_get0_notAfter_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_getm_notAfter_procname = 'X509_getm_notAfter';
  X509_getm_notAfter_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_set1_notAfter_procname = 'X509_set1_notAfter';
  X509_set1_notAfter_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_set_pubkey_procname = 'X509_set_pubkey';
  X509_set_pubkey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_up_ref_procname = 'X509_up_ref';
  X509_up_ref_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_signature_type_procname = 'X509_get_signature_type';
  X509_get_signature_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_X509_PUBKEY_procname = 'X509_get_X509_PUBKEY';
  X509_get_X509_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get0_extensions_procname = 'X509_get0_extensions';
  X509_get0_extensions_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get0_uids_procname = 'X509_get0_uids';
  X509_get0_uids_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get0_tbs_sigalg_procname = 'X509_get0_tbs_sigalg';
  X509_get0_tbs_sigalg_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get0_pubkey_procname = 'X509_get0_pubkey';
  X509_get0_pubkey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_pubkey_procname = 'X509_get_pubkey';
  X509_get_pubkey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get0_pubkey_bitstr_procname = 'X509_get0_pubkey_bitstr';
  X509_get0_pubkey_bitstr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_get_version_procname = 'X509_REQ_get_version';
  X509_REQ_get_version_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_set_version_procname = 'X509_REQ_set_version';
  X509_REQ_set_version_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_get_subject_name_procname = 'X509_REQ_get_subject_name';
  X509_REQ_get_subject_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_set_subject_name_procname = 'X509_REQ_set_subject_name';
  X509_REQ_set_subject_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_get0_signature_procname = 'X509_REQ_get0_signature';
  X509_REQ_get0_signature_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_set0_signature_procname = 'X509_REQ_set0_signature';
  X509_REQ_set0_signature_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1h);

  X509_REQ_set1_signature_algo_procname = 'X509_REQ_set1_signature_algo';
  X509_REQ_set1_signature_algo_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1h);

  X509_REQ_get_signature_nid_procname = 'X509_REQ_get_signature_nid';
  X509_REQ_get_signature_nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_re_X509_REQ_tbs_procname = 'i2d_re_X509_REQ_tbs';
  i2d_re_X509_REQ_tbs_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_set_pubkey_procname = 'X509_REQ_set_pubkey';
  X509_REQ_set_pubkey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_get_pubkey_procname = 'X509_REQ_get_pubkey';
  X509_REQ_get_pubkey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_get0_pubkey_procname = 'X509_REQ_get0_pubkey';
  X509_REQ_get0_pubkey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_get_X509_PUBKEY_procname = 'X509_REQ_get_X509_PUBKEY';
  X509_REQ_get_X509_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_extension_nid_procname = 'X509_REQ_extension_nid';
  X509_REQ_extension_nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_get_extension_nids_procname = 'X509_REQ_get_extension_nids';
  X509_REQ_get_extension_nids_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_set_extension_nids_procname = 'X509_REQ_set_extension_nids';
  X509_REQ_set_extension_nids_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_get_extensions_procname = 'X509_REQ_get_extensions';
  X509_REQ_get_extensions_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_add_extensions_nid_procname = 'X509_REQ_add_extensions_nid';
  X509_REQ_add_extensions_nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_add_extensions_procname = 'X509_REQ_add_extensions';
  X509_REQ_add_extensions_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_get_attr_count_procname = 'X509_REQ_get_attr_count';
  X509_REQ_get_attr_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_get_attr_by_NID_procname = 'X509_REQ_get_attr_by_NID';
  X509_REQ_get_attr_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_get_attr_by_OBJ_procname = 'X509_REQ_get_attr_by_OBJ';
  X509_REQ_get_attr_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_get_attr_procname = 'X509_REQ_get_attr';
  X509_REQ_get_attr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_delete_attr_procname = 'X509_REQ_delete_attr';
  X509_REQ_delete_attr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_add1_attr_procname = 'X509_REQ_add1_attr';
  X509_REQ_add1_attr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_add1_attr_by_OBJ_procname = 'X509_REQ_add1_attr_by_OBJ';
  X509_REQ_add1_attr_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_add1_attr_by_NID_procname = 'X509_REQ_add1_attr_by_NID';
  X509_REQ_add1_attr_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_add1_attr_by_txt_procname = 'X509_REQ_add1_attr_by_txt';
  X509_REQ_add1_attr_by_txt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_set_version_procname = 'X509_CRL_set_version';
  X509_CRL_set_version_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_set_issuer_name_procname = 'X509_CRL_set_issuer_name';
  X509_CRL_set_issuer_name_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_set1_lastUpdate_procname = 'X509_CRL_set1_lastUpdate';
  X509_CRL_set1_lastUpdate_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_set1_nextUpdate_procname = 'X509_CRL_set1_nextUpdate';
  X509_CRL_set1_nextUpdate_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_sort_procname = 'X509_CRL_sort';
  X509_CRL_sort_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_up_ref_procname = 'X509_CRL_up_ref';
  X509_CRL_up_ref_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_get_version_procname = 'X509_CRL_get_version';
  X509_CRL_get_version_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_get0_lastUpdate_procname = 'X509_CRL_get0_lastUpdate';
  X509_CRL_get0_lastUpdate_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_get0_nextUpdate_procname = 'X509_CRL_get0_nextUpdate';
  X509_CRL_get0_nextUpdate_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_get_issuer_procname = 'X509_CRL_get_issuer';
  X509_CRL_get_issuer_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_get0_extensions_procname = 'X509_CRL_get0_extensions';
  X509_CRL_get0_extensions_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_get_REVOKED_procname = 'X509_CRL_get_REVOKED';
  X509_CRL_get_REVOKED_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_get0_tbs_sigalg_procname = 'X509_CRL_get0_tbs_sigalg';
  X509_CRL_get0_tbs_sigalg_introduced = (byte(3) shl 8 or byte(6)) shl 8 or byte(0);

  X509_CRL_get0_signature_procname = 'X509_CRL_get0_signature';
  X509_CRL_get0_signature_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_get_signature_nid_procname = 'X509_CRL_get_signature_nid';
  X509_CRL_get_signature_nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_re_X509_CRL_tbs_procname = 'i2d_re_X509_CRL_tbs';
  i2d_re_X509_CRL_tbs_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REVOKED_get0_serialNumber_procname = 'X509_REVOKED_get0_serialNumber';
  X509_REVOKED_get0_serialNumber_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REVOKED_set_serialNumber_procname = 'X509_REVOKED_set_serialNumber';
  X509_REVOKED_set_serialNumber_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REVOKED_get0_revocationDate_procname = 'X509_REVOKED_get0_revocationDate';
  X509_REVOKED_get0_revocationDate_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REVOKED_set_revocationDate_procname = 'X509_REVOKED_set_revocationDate';
  X509_REVOKED_set_revocationDate_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REVOKED_get0_extensions_procname = 'X509_REVOKED_get0_extensions';
  X509_REVOKED_get0_extensions_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_diff_procname = 'X509_CRL_diff';
  X509_CRL_diff_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_check_private_key_procname = 'X509_REQ_check_private_key';
  X509_REQ_check_private_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_check_private_key_procname = 'X509_check_private_key';
  X509_check_private_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_chain_check_suiteb_procname = 'X509_chain_check_suiteb';
  X509_chain_check_suiteb_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_check_suiteb_procname = 'X509_CRL_check_suiteb';
  X509_CRL_check_suiteb_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OSSL_STACK_OF_X509_free_procname = 'OSSL_STACK_OF_X509_free';
  OSSL_STACK_OF_X509_free_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  X509_chain_up_ref_procname = 'X509_chain_up_ref';
  X509_chain_up_ref_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_issuer_and_serial_cmp_procname = 'X509_issuer_and_serial_cmp';
  X509_issuer_and_serial_cmp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_issuer_and_serial_hash_procname = 'X509_issuer_and_serial_hash';
  X509_issuer_and_serial_hash_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_issuer_name_cmp_procname = 'X509_issuer_name_cmp';
  X509_issuer_name_cmp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_issuer_name_hash_procname = 'X509_issuer_name_hash';
  X509_issuer_name_hash_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_subject_name_cmp_procname = 'X509_subject_name_cmp';
  X509_subject_name_cmp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_subject_name_hash_procname = 'X509_subject_name_hash';
  X509_subject_name_hash_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_issuer_name_hash_old_procname = 'X509_issuer_name_hash_old';
  X509_issuer_name_hash_old_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_subject_name_hash_old_procname = 'X509_subject_name_hash_old';
  X509_subject_name_hash_old_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_add_cert_procname = 'X509_add_cert';
  X509_add_cert_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_add_certs_procname = 'X509_add_certs';
  X509_add_certs_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_cmp_procname = 'X509_cmp';
  X509_cmp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_cmp_procname = 'X509_NAME_cmp';
  X509_NAME_cmp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_certificate_type_procname = 'X509_certificate_type';
  X509_certificate_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  X509_certificate_type_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_NAME_hash_ex_procname = 'X509_NAME_hash_ex';
  X509_NAME_hash_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_NAME_hash_old_procname = 'X509_NAME_hash_old';
  X509_NAME_hash_old_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_cmp_procname = 'X509_CRL_cmp';
  X509_CRL_cmp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_match_procname = 'X509_CRL_match';
  X509_CRL_match_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_aux_print_procname = 'X509_aux_print';
  X509_aux_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_print_ex_fp_procname = 'X509_print_ex_fp';
  X509_print_ex_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_print_fp_procname = 'X509_print_fp';
  X509_print_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_print_fp_procname = 'X509_CRL_print_fp';
  X509_CRL_print_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_print_fp_procname = 'X509_REQ_print_fp';
  X509_REQ_print_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_print_ex_fp_procname = 'X509_NAME_print_ex_fp';
  X509_NAME_print_ex_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_print_procname = 'X509_NAME_print';
  X509_NAME_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_print_ex_procname = 'X509_NAME_print_ex';
  X509_NAME_print_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_print_ex_procname = 'X509_print_ex';
  X509_print_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_print_procname = 'X509_print';
  X509_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_ocspid_print_procname = 'X509_ocspid_print';
  X509_ocspid_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_print_ex_procname = 'X509_CRL_print_ex';
  X509_CRL_print_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  X509_CRL_print_procname = 'X509_CRL_print';
  X509_CRL_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_print_ex_procname = 'X509_REQ_print_ex';
  X509_REQ_print_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REQ_print_procname = 'X509_REQ_print';
  X509_REQ_print_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_entry_count_procname = 'X509_NAME_entry_count';
  X509_NAME_entry_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_get_text_by_NID_procname = 'X509_NAME_get_text_by_NID';
  X509_NAME_get_text_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_get_text_by_OBJ_procname = 'X509_NAME_get_text_by_OBJ';
  X509_NAME_get_text_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_get_index_by_NID_procname = 'X509_NAME_get_index_by_NID';
  X509_NAME_get_index_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_get_index_by_OBJ_procname = 'X509_NAME_get_index_by_OBJ';
  X509_NAME_get_index_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_get_entry_procname = 'X509_NAME_get_entry';
  X509_NAME_get_entry_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_delete_entry_procname = 'X509_NAME_delete_entry';
  X509_NAME_delete_entry_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_add_entry_procname = 'X509_NAME_add_entry';
  X509_NAME_add_entry_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_add_entry_by_OBJ_procname = 'X509_NAME_add_entry_by_OBJ';
  X509_NAME_add_entry_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_add_entry_by_NID_procname = 'X509_NAME_add_entry_by_NID';
  X509_NAME_add_entry_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_ENTRY_create_by_txt_procname = 'X509_NAME_ENTRY_create_by_txt';
  X509_NAME_ENTRY_create_by_txt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_ENTRY_create_by_NID_procname = 'X509_NAME_ENTRY_create_by_NID';
  X509_NAME_ENTRY_create_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_add_entry_by_txt_procname = 'X509_NAME_add_entry_by_txt';
  X509_NAME_add_entry_by_txt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_ENTRY_create_by_OBJ_procname = 'X509_NAME_ENTRY_create_by_OBJ';
  X509_NAME_ENTRY_create_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_ENTRY_set_object_procname = 'X509_NAME_ENTRY_set_object';
  X509_NAME_ENTRY_set_object_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_ENTRY_set_data_procname = 'X509_NAME_ENTRY_set_data';
  X509_NAME_ENTRY_set_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_ENTRY_get_object_procname = 'X509_NAME_ENTRY_get_object';
  X509_NAME_ENTRY_get_object_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_ENTRY_get_data_procname = 'X509_NAME_ENTRY_get_data';
  X509_NAME_ENTRY_get_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_ENTRY_set_procname = 'X509_NAME_ENTRY_set';
  X509_NAME_ENTRY_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_NAME_get0_der_procname = 'X509_NAME_get0_der';
  X509_NAME_get0_der_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_get_ext_count_procname = 'X509v3_get_ext_count';
  X509v3_get_ext_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_get_ext_by_NID_procname = 'X509v3_get_ext_by_NID';
  X509v3_get_ext_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_get_ext_by_OBJ_procname = 'X509v3_get_ext_by_OBJ';
  X509v3_get_ext_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_get_ext_by_critical_procname = 'X509v3_get_ext_by_critical';
  X509v3_get_ext_by_critical_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_get_ext_procname = 'X509v3_get_ext';
  X509v3_get_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_delete_ext_procname = 'X509v3_delete_ext';
  X509v3_delete_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_add_ext_procname = 'X509v3_add_ext';
  X509v3_add_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509v3_add_extensions_procname = 'X509v3_add_extensions';
  X509v3_add_extensions_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_get_ext_count_procname = 'X509_get_ext_count';
  X509_get_ext_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_ext_by_NID_procname = 'X509_get_ext_by_NID';
  X509_get_ext_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_ext_by_OBJ_procname = 'X509_get_ext_by_OBJ';
  X509_get_ext_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_ext_by_critical_procname = 'X509_get_ext_by_critical';
  X509_get_ext_by_critical_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_ext_procname = 'X509_get_ext';
  X509_get_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_delete_ext_procname = 'X509_delete_ext';
  X509_delete_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_add_ext_procname = 'X509_add_ext';
  X509_add_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_get_ext_d2i_procname = 'X509_get_ext_d2i';
  X509_get_ext_d2i_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_add1_ext_i2d_procname = 'X509_add1_ext_i2d';
  X509_add1_ext_i2d_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_get_ext_count_procname = 'X509_CRL_get_ext_count';
  X509_CRL_get_ext_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_get_ext_by_NID_procname = 'X509_CRL_get_ext_by_NID';
  X509_CRL_get_ext_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_get_ext_by_OBJ_procname = 'X509_CRL_get_ext_by_OBJ';
  X509_CRL_get_ext_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_get_ext_by_critical_procname = 'X509_CRL_get_ext_by_critical';
  X509_CRL_get_ext_by_critical_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_get_ext_procname = 'X509_CRL_get_ext';
  X509_CRL_get_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_delete_ext_procname = 'X509_CRL_delete_ext';
  X509_CRL_delete_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_add_ext_procname = 'X509_CRL_add_ext';
  X509_CRL_add_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_get_ext_d2i_procname = 'X509_CRL_get_ext_d2i';
  X509_CRL_get_ext_d2i_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_CRL_add1_ext_i2d_procname = 'X509_CRL_add1_ext_i2d';
  X509_CRL_add1_ext_i2d_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REVOKED_get_ext_count_procname = 'X509_REVOKED_get_ext_count';
  X509_REVOKED_get_ext_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REVOKED_get_ext_by_NID_procname = 'X509_REVOKED_get_ext_by_NID';
  X509_REVOKED_get_ext_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REVOKED_get_ext_by_OBJ_procname = 'X509_REVOKED_get_ext_by_OBJ';
  X509_REVOKED_get_ext_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REVOKED_get_ext_by_critical_procname = 'X509_REVOKED_get_ext_by_critical';
  X509_REVOKED_get_ext_by_critical_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REVOKED_get_ext_procname = 'X509_REVOKED_get_ext';
  X509_REVOKED_get_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REVOKED_delete_ext_procname = 'X509_REVOKED_delete_ext';
  X509_REVOKED_delete_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REVOKED_add_ext_procname = 'X509_REVOKED_add_ext';
  X509_REVOKED_add_ext_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REVOKED_get_ext_d2i_procname = 'X509_REVOKED_get_ext_d2i';
  X509_REVOKED_get_ext_d2i_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_REVOKED_add1_ext_i2d_procname = 'X509_REVOKED_add1_ext_i2d';
  X509_REVOKED_add1_ext_i2d_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_EXTENSION_create_by_NID_procname = 'X509_EXTENSION_create_by_NID';
  X509_EXTENSION_create_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_EXTENSION_create_by_OBJ_procname = 'X509_EXTENSION_create_by_OBJ';
  X509_EXTENSION_create_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_EXTENSION_set_object_procname = 'X509_EXTENSION_set_object';
  X509_EXTENSION_set_object_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_EXTENSION_set_critical_procname = 'X509_EXTENSION_set_critical';
  X509_EXTENSION_set_critical_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_EXTENSION_set_data_procname = 'X509_EXTENSION_set_data';
  X509_EXTENSION_set_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_EXTENSION_get_object_procname = 'X509_EXTENSION_get_object';
  X509_EXTENSION_get_object_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_EXTENSION_get_data_procname = 'X509_EXTENSION_get_data';
  X509_EXTENSION_get_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_EXTENSION_get_critical_procname = 'X509_EXTENSION_get_critical';
  X509_EXTENSION_get_critical_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509at_get_attr_count_procname = 'X509at_get_attr_count';
  X509at_get_attr_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509at_get_attr_by_NID_procname = 'X509at_get_attr_by_NID';
  X509at_get_attr_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509at_get_attr_by_OBJ_procname = 'X509at_get_attr_by_OBJ';
  X509at_get_attr_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509at_get_attr_procname = 'X509at_get_attr';
  X509at_get_attr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509at_delete_attr_procname = 'X509at_delete_attr';
  X509at_delete_attr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509at_add1_attr_procname = 'X509at_add1_attr';
  X509at_add1_attr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509at_add1_attr_by_OBJ_procname = 'X509at_add1_attr_by_OBJ';
  X509at_add1_attr_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509at_add1_attr_by_NID_procname = 'X509at_add1_attr_by_NID';
  X509at_add1_attr_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509at_add1_attr_by_txt_procname = 'X509at_add1_attr_by_txt';
  X509at_add1_attr_by_txt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509at_get0_data_by_OBJ_procname = 'X509at_get0_data_by_OBJ';
  X509at_get0_data_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_ATTRIBUTE_create_by_NID_procname = 'X509_ATTRIBUTE_create_by_NID';
  X509_ATTRIBUTE_create_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_ATTRIBUTE_create_by_OBJ_procname = 'X509_ATTRIBUTE_create_by_OBJ';
  X509_ATTRIBUTE_create_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_ATTRIBUTE_create_by_txt_procname = 'X509_ATTRIBUTE_create_by_txt';
  X509_ATTRIBUTE_create_by_txt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_ATTRIBUTE_set1_object_procname = 'X509_ATTRIBUTE_set1_object';
  X509_ATTRIBUTE_set1_object_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_ATTRIBUTE_set1_data_procname = 'X509_ATTRIBUTE_set1_data';
  X509_ATTRIBUTE_set1_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_ATTRIBUTE_get0_data_procname = 'X509_ATTRIBUTE_get0_data';
  X509_ATTRIBUTE_get0_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_ATTRIBUTE_count_procname = 'X509_ATTRIBUTE_count';
  X509_ATTRIBUTE_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_ATTRIBUTE_get0_object_procname = 'X509_ATTRIBUTE_get0_object';
  X509_ATTRIBUTE_get0_object_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_ATTRIBUTE_get0_type_procname = 'X509_ATTRIBUTE_get0_type';
  X509_ATTRIBUTE_get0_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EVP_PKEY_get_attr_count_procname = 'EVP_PKEY_get_attr_count';
  EVP_PKEY_get_attr_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EVP_PKEY_get_attr_by_NID_procname = 'EVP_PKEY_get_attr_by_NID';
  EVP_PKEY_get_attr_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EVP_PKEY_get_attr_by_OBJ_procname = 'EVP_PKEY_get_attr_by_OBJ';
  EVP_PKEY_get_attr_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EVP_PKEY_get_attr_procname = 'EVP_PKEY_get_attr';
  EVP_PKEY_get_attr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EVP_PKEY_delete_attr_procname = 'EVP_PKEY_delete_attr';
  EVP_PKEY_delete_attr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EVP_PKEY_add1_attr_procname = 'EVP_PKEY_add1_attr';
  EVP_PKEY_add1_attr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EVP_PKEY_add1_attr_by_OBJ_procname = 'EVP_PKEY_add1_attr_by_OBJ';
  EVP_PKEY_add1_attr_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EVP_PKEY_add1_attr_by_NID_procname = 'EVP_PKEY_add1_attr_by_NID';
  EVP_PKEY_add1_attr_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EVP_PKEY_add1_attr_by_txt_procname = 'EVP_PKEY_add1_attr_by_txt';
  EVP_PKEY_add1_attr_by_txt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_find_by_issuer_and_serial_procname = 'X509_find_by_issuer_and_serial';
  X509_find_by_issuer_and_serial_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_find_by_subject_procname = 'X509_find_by_subject';
  X509_find_by_subject_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PBEPARAM_new_procname = 'PBEPARAM_new';
  PBEPARAM_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PBEPARAM_free_procname = 'PBEPARAM_free';
  PBEPARAM_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PBEPARAM_procname = 'd2i_PBEPARAM';
  d2i_PBEPARAM_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PBEPARAM_procname = 'i2d_PBEPARAM';
  i2d_PBEPARAM_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PBEPARAM_it_procname = 'PBEPARAM_it';
  PBEPARAM_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PBE2PARAM_new_procname = 'PBE2PARAM_new';
  PBE2PARAM_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PBE2PARAM_free_procname = 'PBE2PARAM_free';
  PBE2PARAM_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PBE2PARAM_procname = 'd2i_PBE2PARAM';
  d2i_PBE2PARAM_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PBE2PARAM_procname = 'i2d_PBE2PARAM';
  i2d_PBE2PARAM_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PBE2PARAM_it_procname = 'PBE2PARAM_it';
  PBE2PARAM_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PBKDF2PARAM_new_procname = 'PBKDF2PARAM_new';
  PBKDF2PARAM_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PBKDF2PARAM_free_procname = 'PBKDF2PARAM_free';
  PBKDF2PARAM_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PBKDF2PARAM_procname = 'd2i_PBKDF2PARAM';
  d2i_PBKDF2PARAM_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PBKDF2PARAM_procname = 'i2d_PBKDF2PARAM';
  i2d_PBKDF2PARAM_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PBKDF2PARAM_it_procname = 'PBKDF2PARAM_it';
  PBKDF2PARAM_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PBMAC1PARAM_new_procname = 'PBMAC1PARAM_new';
  PBMAC1PARAM_new_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  PBMAC1PARAM_free_procname = 'PBMAC1PARAM_free';
  PBMAC1PARAM_free_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  d2i_PBMAC1PARAM_procname = 'd2i_PBMAC1PARAM';
  d2i_PBMAC1PARAM_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  i2d_PBMAC1PARAM_procname = 'i2d_PBMAC1PARAM';
  i2d_PBMAC1PARAM_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  PBMAC1PARAM_it_procname = 'PBMAC1PARAM_it';
  PBMAC1PARAM_it_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  SCRYPT_PARAMS_new_procname = 'SCRYPT_PARAMS_new';
  SCRYPT_PARAMS_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  SCRYPT_PARAMS_free_procname = 'SCRYPT_PARAMS_free';
  SCRYPT_PARAMS_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  d2i_SCRYPT_PARAMS_procname = 'd2i_SCRYPT_PARAMS';
  d2i_SCRYPT_PARAMS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  i2d_SCRYPT_PARAMS_procname = 'i2d_SCRYPT_PARAMS';
  i2d_SCRYPT_PARAMS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  SCRYPT_PARAMS_it_procname = 'SCRYPT_PARAMS_it';
  SCRYPT_PARAMS_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  PKCS5_pbe_set0_algor_procname = 'PKCS5_pbe_set0_algor';
  PKCS5_pbe_set0_algor_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS5_pbe_set0_algor_ex_procname = 'PKCS5_pbe_set0_algor_ex';
  PKCS5_pbe_set0_algor_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS5_pbe_set_procname = 'PKCS5_pbe_set';
  PKCS5_pbe_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS5_pbe_set_ex_procname = 'PKCS5_pbe_set_ex';
  PKCS5_pbe_set_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS5_pbe2_set_procname = 'PKCS5_pbe2_set';
  PKCS5_pbe2_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS5_pbe2_set_iv_procname = 'PKCS5_pbe2_set_iv';
  PKCS5_pbe2_set_iv_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS5_pbe2_set_iv_ex_procname = 'PKCS5_pbe2_set_iv_ex';
  PKCS5_pbe2_set_iv_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS5_pbe2_set_scrypt_procname = 'PKCS5_pbe2_set_scrypt';
  PKCS5_pbe2_set_scrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS5_pbkdf2_set_procname = 'PKCS5_pbkdf2_set';
  PKCS5_pbkdf2_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS5_pbkdf2_set_ex_procname = 'PKCS5_pbkdf2_set_ex';
  PKCS5_pbkdf2_set_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PBMAC1_get1_pbkdf2_param_procname = 'PBMAC1_get1_pbkdf2_param';
  PBMAC1_get1_pbkdf2_param_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  PKCS8_PRIV_KEY_INFO_new_procname = 'PKCS8_PRIV_KEY_INFO_new';
  PKCS8_PRIV_KEY_INFO_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS8_PRIV_KEY_INFO_free_procname = 'PKCS8_PRIV_KEY_INFO_free';
  PKCS8_PRIV_KEY_INFO_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PKCS8_PRIV_KEY_INFO_procname = 'd2i_PKCS8_PRIV_KEY_INFO';
  d2i_PKCS8_PRIV_KEY_INFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS8_PRIV_KEY_INFO_procname = 'i2d_PKCS8_PRIV_KEY_INFO';
  i2d_PKCS8_PRIV_KEY_INFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS8_PRIV_KEY_INFO_it_procname = 'PKCS8_PRIV_KEY_INFO_it';
  PKCS8_PRIV_KEY_INFO_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EVP_PKCS82PKEY_procname = 'EVP_PKCS82PKEY';
  EVP_PKCS82PKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  EVP_PKCS82PKEY_ex_procname = 'EVP_PKCS82PKEY_ex';
  EVP_PKCS82PKEY_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  EVP_PKEY2PKCS8_procname = 'EVP_PKEY2PKCS8';
  EVP_PKEY2PKCS8_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS8_pkey_set0_procname = 'PKCS8_pkey_set0';
  PKCS8_pkey_set0_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS8_pkey_get0_procname = 'PKCS8_pkey_get0';
  PKCS8_pkey_get0_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS8_pkey_get0_attrs_procname = 'PKCS8_pkey_get0_attrs';
  PKCS8_pkey_get0_attrs_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS8_pkey_add1_attr_procname = 'PKCS8_pkey_add1_attr';
  PKCS8_pkey_add1_attr_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS8_pkey_add1_attr_by_NID_procname = 'PKCS8_pkey_add1_attr_by_NID';
  PKCS8_pkey_add1_attr_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS8_pkey_add1_attr_by_OBJ_procname = 'PKCS8_pkey_add1_attr_by_OBJ';
  PKCS8_pkey_add1_attr_by_OBJ_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  X509_PUBKEY_set0_public_key_procname = 'X509_PUBKEY_set0_public_key';
  X509_PUBKEY_set0_public_key_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  X509_PUBKEY_set0_param_procname = 'X509_PUBKEY_set0_param';
  X509_PUBKEY_set0_param_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_PUBKEY_get0_param_procname = 'X509_PUBKEY_get0_param';
  X509_PUBKEY_get0_param_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  X509_PUBKEY_eq_procname = 'X509_PUBKEY_eq';
  X509_PUBKEY_eq_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function X509_http_nbio(rctx: Pointer; pcert: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_http_nbio(rctx, pcert) \
    OSSL_HTTP_REQ_CTX_nbio_d2i(rctx, pcert, ASN1_ITEM_rptr(X509))
  }
end;

function X509_CRL_http_nbio(rctx: Pointer; pcrl: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_CRL_http_nbio(rctx, pcrl) \
    OSSL_HTTP_REQ_CTX_nbio_d2i(rctx, pcrl, ASN1_ITEM_rptr(X509_CRL))
  }
end;

function X509_NAME_hash(x: Pointer): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_NAME_hash(x) X509_NAME_hash_ex(x, NULL, NULL, NULL)
  }
end;

function X509_get_notBefore(x: PX509): PASN1_TIME; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_get_notBefore X509_getm_notBefore
  }
end;

function X509_get_notAfter(x: PX509): PASN1_TIME; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_get_notAfter X509_getm_notAfter
  }
end;

function X509_set_notBefore(x: PX509; tm: PASN1_TIME): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_set_notBefore X509_set1_notBefore
  }
end;

function X509_set_notAfter(x: PX509; tm: PASN1_TIME): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_set_notAfter X509_set1_notAfter
  }
end;

function X509_CRL_set_lastUpdate(x: PX509_CRL; tm: PASN1_TIME): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_CRL_set_lastUpdate X509_CRL_set1_lastUpdate
  }
end;

function X509_CRL_set_nextUpdate(x: PX509_CRL; tm: PASN1_TIME): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    X509_CRL_set_nextUpdate X509_CRL_set1_nextUpdate
  }
end;

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

procedure ERR_X509_CRL_set_default_method(meth: PX509_CRL_METHOD); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_set_default_method_procname);
end;

function ERR_X509_CRL_METHOD_new(crl_init: TX509_CRL_METHOD_new_crl_init_cb; crl_free: TX509_CRL_METHOD_new_crl_init_cb; crl_lookup: TX509_CRL_METHOD_new_crl_lookup_cb; crl_verify: TX509_CRL_METHOD_new_crl_verify_cb): PX509_CRL_METHOD; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_METHOD_new_procname);
end;

procedure ERR_X509_CRL_METHOD_free(m: PX509_CRL_METHOD); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_METHOD_free_procname);
end;

procedure ERR_X509_CRL_set_meth_data(crl: PX509_CRL; dat: Pointer); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_set_meth_data_procname);
end;

function ERR_X509_CRL_get_meth_data(crl: PX509_CRL): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get_meth_data_procname);
end;

function ERR_X509_verify_cert_error_string(n: TIdC_LONG): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_verify_cert_error_string_procname);
end;

function ERR_X509_verify(a: PX509; r: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_verify_procname);
end;

function ERR_X509_self_signed(cert: PX509; verify_signature: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_self_signed_procname);
end;

function ERR_X509_REQ_verify_ex(a: PX509_REQ; r: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_verify_ex_procname);
end;

function ERR_X509_REQ_verify(a: PX509_REQ; r: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_verify_procname);
end;

function ERR_X509_CRL_verify(a: PX509_CRL; r: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_verify_procname);
end;

function ERR_NETSCAPE_SPKI_verify(a: PNETSCAPE_SPKI; r: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NETSCAPE_SPKI_verify_procname);
end;

function ERR_NETSCAPE_SPKI_b64_decode(str: PIdAnsiChar; len: TIdC_INT): PNETSCAPE_SPKI; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NETSCAPE_SPKI_b64_decode_procname);
end;

function ERR_NETSCAPE_SPKI_b64_encode(x: PNETSCAPE_SPKI): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NETSCAPE_SPKI_b64_encode_procname);
end;

function ERR_NETSCAPE_SPKI_get_pubkey(x: PNETSCAPE_SPKI): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NETSCAPE_SPKI_get_pubkey_procname);
end;

function ERR_NETSCAPE_SPKI_set_pubkey(x: PNETSCAPE_SPKI; pkey: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NETSCAPE_SPKI_set_pubkey_procname);
end;

function ERR_NETSCAPE_SPKI_print(_out: PBIO; spki: PNETSCAPE_SPKI): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NETSCAPE_SPKI_print_procname);
end;

function ERR_X509_signature_dump(bp: PBIO; sig: PASN1_STRING; indent: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_signature_dump_procname);
end;

function ERR_X509_signature_print(bp: PBIO; alg: PX509_ALGOR; sig: PASN1_STRING): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_signature_print_procname);
end;

function ERR_X509_sign(x: PX509; pkey: PEVP_PKEY; md: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_sign_procname);
end;

function ERR_X509_sign_ctx(x: PX509; ctx: PEVP_MD_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_sign_ctx_procname);
end;

function ERR_X509_REQ_sign(x: PX509_REQ; pkey: PEVP_PKEY; md: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_sign_procname);
end;

function ERR_X509_REQ_sign_ctx(x: PX509_REQ; ctx: PEVP_MD_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_sign_ctx_procname);
end;

function ERR_X509_CRL_sign(x: PX509_CRL; pkey: PEVP_PKEY; md: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_sign_procname);
end;

function ERR_X509_CRL_sign_ctx(x: PX509_CRL; ctx: PEVP_MD_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_sign_ctx_procname);
end;

function ERR_NETSCAPE_SPKI_sign(x: PNETSCAPE_SPKI; pkey: PEVP_PKEY; md: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NETSCAPE_SPKI_sign_procname);
end;

function ERR_X509_pubkey_digest(data: PX509; _type: PEVP_MD; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_pubkey_digest_procname);
end;

function ERR_X509_digest(data: PX509; _type: PEVP_MD; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_digest_procname);
end;

function ERR_X509_digest_sig(cert: PX509; md_used: PPEVP_MD; md_is_fallback: PIdC_INT): PASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_digest_sig_procname);
end;

function ERR_X509_CRL_digest(data: PX509_CRL; _type: PEVP_MD; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_digest_procname);
end;

function ERR_X509_REQ_digest(data: PX509_REQ; _type: PEVP_MD; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_digest_procname);
end;

function ERR_X509_NAME_digest(data: PX509_NAME; _type: PEVP_MD; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_digest_procname);
end;

function ERR_X509_load_http(url: PIdAnsiChar; bio: PBIO; rbio: PBIO; timeout: TIdC_INT): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_load_http_procname);
end;

function ERR_X509_CRL_load_http(url: PIdAnsiChar; bio: PBIO; rbio: PBIO; timeout: TIdC_INT): PX509_CRL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_load_http_procname);
end;

function ERR_d2i_X509_fp(fp: PFILE; x509: PPX509): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_fp_procname);
end;

function ERR_i2d_X509_fp(fp: PFILE; x509: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_fp_procname);
end;

function ERR_d2i_X509_CRL_fp(fp: PFILE; crl: PPX509_CRL): PX509_CRL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_CRL_fp_procname);
end;

function ERR_i2d_X509_CRL_fp(fp: PFILE; crl: PX509_CRL): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_CRL_fp_procname);
end;

function ERR_d2i_X509_REQ_fp(fp: PFILE; req: PPX509_REQ): PX509_REQ; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_REQ_fp_procname);
end;

function ERR_i2d_X509_REQ_fp(fp: PFILE; req: PX509_REQ): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_REQ_fp_procname);
end;

function ERR_d2i_RSAPrivateKey_fp(fp: PFILE; rsa: PPRSA): PRSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_RSAPrivateKey_fp_procname);
end;

function ERR_i2d_RSAPrivateKey_fp(fp: PFILE; rsa: PRSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_RSAPrivateKey_fp_procname);
end;

function ERR_d2i_RSAPublicKey_fp(fp: PFILE; rsa: PPRSA): PRSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_RSAPublicKey_fp_procname);
end;

function ERR_i2d_RSAPublicKey_fp(fp: PFILE; rsa: PRSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_RSAPublicKey_fp_procname);
end;

function ERR_d2i_RSA_PUBKEY_fp(fp: PFILE; rsa: PPRSA): PRSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_RSA_PUBKEY_fp_procname);
end;

function ERR_i2d_RSA_PUBKEY_fp(fp: PFILE; rsa: PRSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_RSA_PUBKEY_fp_procname);
end;

function ERR_d2i_DSA_PUBKEY_fp(fp: PFILE; dsa: PPDSA): PDSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_DSA_PUBKEY_fp_procname);
end;

function ERR_i2d_DSA_PUBKEY_fp(fp: PFILE; dsa: PDSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_DSA_PUBKEY_fp_procname);
end;

function ERR_d2i_DSAPrivateKey_fp(fp: PFILE; dsa: PPDSA): PDSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_DSAPrivateKey_fp_procname);
end;

function ERR_i2d_DSAPrivateKey_fp(fp: PFILE; dsa: PDSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_DSAPrivateKey_fp_procname);
end;

function ERR_d2i_EC_PUBKEY_fp(fp: PFILE; eckey: PPEC_KEY): PEC_KEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_EC_PUBKEY_fp_procname);
end;

function ERR_i2d_EC_PUBKEY_fp(fp: PFILE; eckey: PEC_KEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_EC_PUBKEY_fp_procname);
end;

function ERR_d2i_ECPrivateKey_fp(fp: PFILE; eckey: PPEC_KEY): PEC_KEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ECPrivateKey_fp_procname);
end;

function ERR_i2d_ECPrivateKey_fp(fp: PFILE; eckey: PEC_KEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ECPrivateKey_fp_procname);
end;

function ERR_d2i_PKCS8_fp(fp: PFILE; p8: PPX509_SIG): PX509_SIG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS8_fp_procname);
end;

function ERR_i2d_PKCS8_fp(fp: PFILE; p8: PX509_SIG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS8_fp_procname);
end;

function ERR_d2i_X509_PUBKEY_fp(fp: PFILE; xpk: PPX509_PUBKEY): PX509_PUBKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_PUBKEY_fp_procname);
end;

function ERR_i2d_X509_PUBKEY_fp(fp: PFILE; xpk: PX509_PUBKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_PUBKEY_fp_procname);
end;

function ERR_d2i_PKCS8_PRIV_KEY_INFO_fp(fp: PFILE; p8inf: PPPKCS8_PRIV_KEY_INFO): PPKCS8_PRIV_KEY_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS8_PRIV_KEY_INFO_fp_procname);
end;

function ERR_i2d_PKCS8_PRIV_KEY_INFO_fp(fp: PFILE; p8inf: PPKCS8_PRIV_KEY_INFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS8_PRIV_KEY_INFO_fp_procname);
end;

function ERR_i2d_PKCS8PrivateKeyInfo_fp(fp: PFILE; key: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS8PrivateKeyInfo_fp_procname);
end;

function ERR_i2d_PrivateKey_fp(fp: PFILE; pkey: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PrivateKey_fp_procname);
end;

function ERR_d2i_PrivateKey_ex_fp(fp: PFILE; a: PPEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PrivateKey_ex_fp_procname);
end;

function ERR_d2i_PrivateKey_fp(fp: PFILE; a: PPEVP_PKEY): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PrivateKey_fp_procname);
end;

function ERR_i2d_PUBKEY_fp(fp: PFILE; pkey: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PUBKEY_fp_procname);
end;

function ERR_d2i_PUBKEY_ex_fp(fp: PFILE; a: PPEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PUBKEY_ex_fp_procname);
end;

function ERR_d2i_PUBKEY_fp(fp: PFILE; a: PPEVP_PKEY): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PUBKEY_fp_procname);
end;

function ERR_d2i_X509_bio(bp: PBIO; x509: PPX509): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_bio_procname);
end;

function ERR_i2d_X509_bio(bp: PBIO; x509: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_bio_procname);
end;

function ERR_d2i_X509_CRL_bio(bp: PBIO; crl: PPX509_CRL): PX509_CRL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_CRL_bio_procname);
end;

function ERR_i2d_X509_CRL_bio(bp: PBIO; crl: PX509_CRL): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_CRL_bio_procname);
end;

function ERR_d2i_X509_REQ_bio(bp: PBIO; req: PPX509_REQ): PX509_REQ; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_REQ_bio_procname);
end;

function ERR_i2d_X509_REQ_bio(bp: PBIO; req: PX509_REQ): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_REQ_bio_procname);
end;

function ERR_d2i_RSAPrivateKey_bio(bp: PBIO; rsa: PPRSA): PRSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_RSAPrivateKey_bio_procname);
end;

function ERR_i2d_RSAPrivateKey_bio(bp: PBIO; rsa: PRSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_RSAPrivateKey_bio_procname);
end;

function ERR_d2i_RSAPublicKey_bio(bp: PBIO; rsa: PPRSA): PRSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_RSAPublicKey_bio_procname);
end;

function ERR_i2d_RSAPublicKey_bio(bp: PBIO; rsa: PRSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_RSAPublicKey_bio_procname);
end;

function ERR_d2i_RSA_PUBKEY_bio(bp: PBIO; rsa: PPRSA): PRSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_RSA_PUBKEY_bio_procname);
end;

function ERR_i2d_RSA_PUBKEY_bio(bp: PBIO; rsa: PRSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_RSA_PUBKEY_bio_procname);
end;

function ERR_d2i_DSA_PUBKEY_bio(bp: PBIO; dsa: PPDSA): PDSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_DSA_PUBKEY_bio_procname);
end;

function ERR_i2d_DSA_PUBKEY_bio(bp: PBIO; dsa: PDSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_DSA_PUBKEY_bio_procname);
end;

function ERR_d2i_DSAPrivateKey_bio(bp: PBIO; dsa: PPDSA): PDSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_DSAPrivateKey_bio_procname);
end;

function ERR_i2d_DSAPrivateKey_bio(bp: PBIO; dsa: PDSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_DSAPrivateKey_bio_procname);
end;

function ERR_d2i_EC_PUBKEY_bio(bp: PBIO; eckey: PPEC_KEY): PEC_KEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_EC_PUBKEY_bio_procname);
end;

function ERR_i2d_EC_PUBKEY_bio(bp: PBIO; eckey: PEC_KEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_EC_PUBKEY_bio_procname);
end;

function ERR_d2i_ECPrivateKey_bio(bp: PBIO; eckey: PPEC_KEY): PEC_KEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_ECPrivateKey_bio_procname);
end;

function ERR_i2d_ECPrivateKey_bio(bp: PBIO; eckey: PEC_KEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_ECPrivateKey_bio_procname);
end;

function ERR_d2i_PKCS8_bio(bp: PBIO; p8: PPX509_SIG): PX509_SIG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS8_bio_procname);
end;

function ERR_i2d_PKCS8_bio(bp: PBIO; p8: PX509_SIG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS8_bio_procname);
end;

function ERR_d2i_X509_PUBKEY_bio(bp: PBIO; xpk: PPX509_PUBKEY): PX509_PUBKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_PUBKEY_bio_procname);
end;

function ERR_i2d_X509_PUBKEY_bio(bp: PBIO; xpk: PX509_PUBKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_PUBKEY_bio_procname);
end;

function ERR_d2i_PKCS8_PRIV_KEY_INFO_bio(bp: PBIO; p8inf: PPPKCS8_PRIV_KEY_INFO): PPKCS8_PRIV_KEY_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS8_PRIV_KEY_INFO_bio_procname);
end;

function ERR_i2d_PKCS8_PRIV_KEY_INFO_bio(bp: PBIO; p8inf: PPKCS8_PRIV_KEY_INFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS8_PRIV_KEY_INFO_bio_procname);
end;

function ERR_i2d_PKCS8PrivateKeyInfo_bio(bp: PBIO; key: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS8PrivateKeyInfo_bio_procname);
end;

function ERR_i2d_PrivateKey_bio(bp: PBIO; pkey: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PrivateKey_bio_procname);
end;

function ERR_d2i_PrivateKey_ex_bio(bp: PBIO; a: PPEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PrivateKey_ex_bio_procname);
end;

function ERR_d2i_PrivateKey_bio(bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PrivateKey_bio_procname);
end;

function ERR_i2d_PUBKEY_bio(bp: PBIO; pkey: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PUBKEY_bio_procname);
end;

function ERR_d2i_PUBKEY_ex_bio(bp: PBIO; a: PPEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PUBKEY_ex_bio_procname);
end;

function ERR_d2i_PUBKEY_bio(bp: PBIO; a: PPEVP_PKEY): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PUBKEY_bio_procname);
end;

function ERR_X509_dup(a: PX509): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_dup_procname);
end;

function ERR_X509_ALGOR_dup(a: PX509_ALGOR): PX509_ALGOR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ALGOR_dup_procname);
end;

function ERR_X509_ATTRIBUTE_dup(a: PX509_ATTRIBUTE): PX509_ATTRIBUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_dup_procname);
end;

function ERR_X509_CRL_dup(a: PX509_CRL): PX509_CRL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_dup_procname);
end;

function ERR_X509_EXTENSION_dup(a: PX509_EXTENSION): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_EXTENSION_dup_procname);
end;

function ERR_X509_PUBKEY_dup(a: PX509_PUBKEY): PX509_PUBKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PUBKEY_dup_procname);
end;

function ERR_X509_REQ_dup(a: PX509_REQ): PX509_REQ; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_dup_procname);
end;

function ERR_X509_REVOKED_dup(a: PX509_REVOKED): PX509_REVOKED; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_dup_procname);
end;

function ERR_X509_ALGOR_set0(alg: PX509_ALGOR; aobj: PASN1_OBJECT; ptype: TIdC_INT; pval: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ALGOR_set0_procname);
end;

procedure ERR_X509_ALGOR_get0(paobj: PPASN1_OBJECT; pptype: PIdC_INT; ppval: PPointer; algor: PX509_ALGOR); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ALGOR_get0_procname);
end;

procedure ERR_X509_ALGOR_set_md(alg: PX509_ALGOR; md: PEVP_MD); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ALGOR_set_md_procname);
end;

function ERR_X509_ALGOR_cmp(a: PX509_ALGOR; b: PX509_ALGOR): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ALGOR_cmp_procname);
end;

function ERR_X509_ALGOR_copy(dest: PX509_ALGOR; src: PX509_ALGOR): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ALGOR_copy_procname);
end;

function ERR_X509_NAME_dup(a: PX509_NAME): PX509_NAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_dup_procname);
end;

function ERR_X509_NAME_ENTRY_dup(a: PX509_NAME_ENTRY): PX509_NAME_ENTRY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_ENTRY_dup_procname);
end;

function ERR_X509_cmp_time(s: PASN1_TIME; t: PIdC_TIMET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_cmp_time_procname);
end;

function ERR_X509_cmp_current_time(s: PASN1_TIME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_cmp_current_time_procname);
end;

function ERR_X509_cmp_timeframe(vpm: PX509_VERIFY_PARAM; start: PASN1_TIME; _end: PASN1_TIME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_cmp_timeframe_procname);
end;

function ERR_X509_time_adj(s: PASN1_TIME; adj: TIdC_LONG; t: PIdC_TIMET): PASN1_TIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_time_adj_procname);
end;

function ERR_X509_time_adj_ex(s: PASN1_TIME; offset_day: TIdC_INT; offset_sec: TIdC_LONG; t: PIdC_TIMET): PASN1_TIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_time_adj_ex_procname);
end;

function ERR_X509_gmtime_adj(s: PASN1_TIME; adj: TIdC_LONG): PASN1_TIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_gmtime_adj_procname);
end;

function ERR_X509_get_default_cert_area: PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_default_cert_area_procname);
end;

function ERR_X509_get_default_cert_dir: PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_default_cert_dir_procname);
end;

function ERR_X509_get_default_cert_file: PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_default_cert_file_procname);
end;

function ERR_X509_get_default_cert_dir_env: PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_default_cert_dir_env_procname);
end;

function ERR_X509_get_default_cert_file_env: PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_default_cert_file_env_procname);
end;

function ERR_X509_get_default_private_dir: PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_default_private_dir_procname);
end;

function ERR_X509_to_X509_REQ(x: PX509; pkey: PEVP_PKEY; md: PEVP_MD): PX509_REQ; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_to_X509_REQ_procname);
end;

function ERR_X509_REQ_to_X509(r: PX509_REQ; days: TIdC_INT; pkey: PEVP_PKEY): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_to_X509_procname);
end;

function ERR_X509_ALGOR_new: PX509_ALGOR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ALGOR_new_procname);
end;

procedure ERR_X509_ALGOR_free(a: PX509_ALGOR); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ALGOR_free_procname);
end;

function ERR_d2i_X509_ALGOR(a: PPX509_ALGOR; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_ALGOR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_ALGOR_procname);
end;

function ERR_i2d_X509_ALGOR(a: PX509_ALGOR; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_ALGOR_procname);
end;

function ERR_X509_ALGOR_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ALGOR_it_procname);
end;

function ERR_d2i_X509_ALGORS(a: PPX509_ALGORS; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_ALGORS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_ALGORS_procname);
end;

function ERR_i2d_X509_ALGORS(a: PX509_ALGORS; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_ALGORS_procname);
end;

function ERR_X509_ALGORS_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ALGORS_it_procname);
end;

function ERR_X509_VAL_new: PX509_VAL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VAL_new_procname);
end;

procedure ERR_X509_VAL_free(a: PX509_VAL); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VAL_free_procname);
end;

function ERR_d2i_X509_VAL(a: PPX509_VAL; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_VAL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_VAL_procname);
end;

function ERR_i2d_X509_VAL(a: PX509_VAL; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_VAL_procname);
end;

function ERR_X509_VAL_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_VAL_it_procname);
end;

function ERR_X509_PUBKEY_new: PX509_PUBKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PUBKEY_new_procname);
end;

procedure ERR_X509_PUBKEY_free(a: PX509_PUBKEY); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PUBKEY_free_procname);
end;

function ERR_d2i_X509_PUBKEY(a: PPX509_PUBKEY; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_PUBKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_PUBKEY_procname);
end;

function ERR_i2d_X509_PUBKEY(a: PX509_PUBKEY; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_PUBKEY_procname);
end;

function ERR_X509_PUBKEY_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PUBKEY_it_procname);
end;

function ERR_X509_PUBKEY_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_PUBKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PUBKEY_new_ex_procname);
end;

function ERR_X509_PUBKEY_set(x: PPX509_PUBKEY; pkey: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PUBKEY_set_procname);
end;

function ERR_X509_PUBKEY_get0(key: PX509_PUBKEY): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PUBKEY_get0_procname);
end;

function ERR_X509_PUBKEY_get(key: PX509_PUBKEY): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PUBKEY_get_procname);
end;

function ERR_X509_get_pubkey_parameters(pkey: PEVP_PKEY; chain: Pstack_st_X509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_pubkey_parameters_procname);
end;

function ERR_X509_get_pathlen(x: PX509): TIdC_LONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_pathlen_procname);
end;

function ERR_d2i_PUBKEY(a: PPEVP_PKEY; _in: PPIdAnsiChar; len: TIdC_LONG): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PUBKEY_procname);
end;

function ERR_i2d_PUBKEY(a: PEVP_PKEY; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PUBKEY_procname);
end;

function ERR_d2i_PUBKEY_ex(a: PPEVP_PKEY; pp: PPIdAnsiChar; length: TIdC_LONG; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PUBKEY_ex_procname);
end;

function ERR_d2i_RSA_PUBKEY(a: PPRSA; _in: PPIdAnsiChar; len: TIdC_LONG): PRSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_RSA_PUBKEY_procname);
end;

function ERR_i2d_RSA_PUBKEY(a: PRSA; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_RSA_PUBKEY_procname);
end;

function ERR_d2i_DSA_PUBKEY(a: PPDSA; _in: PPIdAnsiChar; len: TIdC_LONG): PDSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_DSA_PUBKEY_procname);
end;

function ERR_i2d_DSA_PUBKEY(a: PDSA; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_DSA_PUBKEY_procname);
end;

function ERR_d2i_EC_PUBKEY(a: PPEC_KEY; _in: PPIdAnsiChar; len: TIdC_LONG): PEC_KEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_EC_PUBKEY_procname);
end;

function ERR_i2d_EC_PUBKEY(a: PEC_KEY; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_EC_PUBKEY_procname);
end;

function ERR_X509_SIG_new: PX509_SIG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_SIG_new_procname);
end;

procedure ERR_X509_SIG_free(a: PX509_SIG); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_SIG_free_procname);
end;

function ERR_d2i_X509_SIG(a: PPX509_SIG; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_SIG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_SIG_procname);
end;

function ERR_i2d_X509_SIG(a: PX509_SIG; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_SIG_procname);
end;

function ERR_X509_SIG_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_SIG_it_procname);
end;

procedure ERR_X509_SIG_get0(sig: PX509_SIG; palg: PPX509_ALGOR; pdigest: PPASN1_OCTET_STRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_SIG_get0_procname);
end;

procedure ERR_X509_SIG_getm(sig: PX509_SIG; palg: PPX509_ALGOR; pdigest: PPASN1_OCTET_STRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_SIG_getm_procname);
end;

function ERR_X509_REQ_INFO_new: PX509_REQ_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_INFO_new_procname);
end;

procedure ERR_X509_REQ_INFO_free(a: PX509_REQ_INFO); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_INFO_free_procname);
end;

function ERR_d2i_X509_REQ_INFO(a: PPX509_REQ_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_REQ_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_REQ_INFO_procname);
end;

function ERR_i2d_X509_REQ_INFO(a: PX509_REQ_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_REQ_INFO_procname);
end;

function ERR_X509_REQ_INFO_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_INFO_it_procname);
end;

function ERR_X509_REQ_new: PX509_REQ; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_new_procname);
end;

procedure ERR_X509_REQ_free(a: PX509_REQ); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_free_procname);
end;

function ERR_d2i_X509_REQ(a: PPX509_REQ; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_REQ; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_REQ_procname);
end;

function ERR_i2d_X509_REQ(a: PX509_REQ; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_REQ_procname);
end;

function ERR_X509_REQ_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_it_procname);
end;

function ERR_X509_REQ_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_REQ; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_new_ex_procname);
end;

function ERR_X509_ATTRIBUTE_new: PX509_ATTRIBUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_new_procname);
end;

procedure ERR_X509_ATTRIBUTE_free(a: PX509_ATTRIBUTE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_free_procname);
end;

function ERR_d2i_X509_ATTRIBUTE(a: PPX509_ATTRIBUTE; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_ATTRIBUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_ATTRIBUTE_procname);
end;

function ERR_i2d_X509_ATTRIBUTE(a: PX509_ATTRIBUTE; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_ATTRIBUTE_procname);
end;

function ERR_X509_ATTRIBUTE_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_it_procname);
end;

function ERR_X509_ATTRIBUTE_create(nid: TIdC_INT; atrtype: TIdC_INT; value: Pointer): PX509_ATTRIBUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_create_procname);
end;

function ERR_X509_EXTENSION_new: PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_EXTENSION_new_procname);
end;

procedure ERR_X509_EXTENSION_free(a: PX509_EXTENSION); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_EXTENSION_free_procname);
end;

function ERR_d2i_X509_EXTENSION(a: PPX509_EXTENSION; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_EXTENSION_procname);
end;

function ERR_i2d_X509_EXTENSION(a: PX509_EXTENSION; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_EXTENSION_procname);
end;

function ERR_X509_EXTENSION_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_EXTENSION_it_procname);
end;

function ERR_d2i_X509_EXTENSIONS(a: PPX509_EXTENSIONS; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_EXTENSIONS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_EXTENSIONS_procname);
end;

function ERR_i2d_X509_EXTENSIONS(a: PX509_EXTENSIONS; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_EXTENSIONS_procname);
end;

function ERR_X509_EXTENSIONS_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_EXTENSIONS_it_procname);
end;

function ERR_X509_NAME_ENTRY_new: PX509_NAME_ENTRY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_ENTRY_new_procname);
end;

procedure ERR_X509_NAME_ENTRY_free(a: PX509_NAME_ENTRY); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_ENTRY_free_procname);
end;

function ERR_d2i_X509_NAME_ENTRY(a: PPX509_NAME_ENTRY; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_NAME_ENTRY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_NAME_ENTRY_procname);
end;

function ERR_i2d_X509_NAME_ENTRY(a: PX509_NAME_ENTRY; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_NAME_ENTRY_procname);
end;

function ERR_X509_NAME_ENTRY_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_ENTRY_it_procname);
end;

function ERR_X509_NAME_new: PX509_NAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_new_procname);
end;

procedure ERR_X509_NAME_free(a: PX509_NAME); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_free_procname);
end;

function ERR_d2i_X509_NAME(a: PPX509_NAME; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_NAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_NAME_procname);
end;

function ERR_i2d_X509_NAME(a: PX509_NAME; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_NAME_procname);
end;

function ERR_X509_NAME_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_it_procname);
end;

function ERR_X509_NAME_set(xn: PPX509_NAME; name: PX509_NAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_set_procname);
end;

function ERR_X509_CINF_new: PX509_CINF; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CINF_new_procname);
end;

procedure ERR_X509_CINF_free(a: PX509_CINF); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CINF_free_procname);
end;

function ERR_d2i_X509_CINF(a: PPX509_CINF; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_CINF; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_CINF_procname);
end;

function ERR_i2d_X509_CINF(a: PX509_CINF; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_CINF_procname);
end;

function ERR_X509_CINF_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CINF_it_procname);
end;

function ERR_X509_new: PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_new_procname);
end;

procedure ERR_X509_free(a: PX509); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_free_procname);
end;

function ERR_d2i_X509(a: PPX509; _in: PPIdAnsiChar; len: TIdC_LONG): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_procname);
end;

function ERR_i2d_X509(a: PX509; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_procname);
end;

function ERR_X509_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_it_procname);
end;

function ERR_X509_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_new_ex_procname);
end;

function ERR_X509_CERT_AUX_new: PX509_CERT_AUX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CERT_AUX_new_procname);
end;

procedure ERR_X509_CERT_AUX_free(a: PX509_CERT_AUX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CERT_AUX_free_procname);
end;

function ERR_d2i_X509_CERT_AUX(a: PPX509_CERT_AUX; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_CERT_AUX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_CERT_AUX_procname);
end;

function ERR_i2d_X509_CERT_AUX(a: PX509_CERT_AUX; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_CERT_AUX_procname);
end;

function ERR_X509_CERT_AUX_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CERT_AUX_it_procname);
end;

function ERR_X509_set_ex_data(r: PX509; idx: TIdC_INT; arg: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_set_ex_data_procname);
end;

function ERR_X509_get_ex_data(r: PX509; idx: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_ex_data_procname);
end;

function ERR_d2i_X509_AUX(a: PPX509; _in: PPIdAnsiChar; len: TIdC_LONG): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_AUX_procname);
end;

function ERR_i2d_X509_AUX(a: PX509; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_AUX_procname);
end;

function ERR_i2d_re_X509_tbs(x: PX509; pp: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_re_X509_tbs_procname);
end;

function ERR_X509_SIG_INFO_get(siginf: PX509_SIG_INFO; mdnid: PIdC_INT; pknid: PIdC_INT; secbits: PIdC_INT; flags: PIdC_UINT32): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_SIG_INFO_get_procname);
end;

procedure ERR_X509_SIG_INFO_set(siginf: PX509_SIG_INFO; mdnid: TIdC_INT; pknid: TIdC_INT; secbits: TIdC_INT; flags: TIdC_UINT32); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_SIG_INFO_set_procname);
end;

function ERR_X509_get_signature_info(x: PX509; mdnid: PIdC_INT; pknid: PIdC_INT; secbits: PIdC_INT; flags: PIdC_UINT32): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_signature_info_procname);
end;

procedure ERR_X509_get0_signature(psig: PPASN1_BIT_STRING; palg: PPX509_ALGOR; x: PX509); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_signature_procname);
end;

function ERR_X509_get_signature_nid(x: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_signature_nid_procname);
end;

procedure ERR_X509_set0_distinguishing_id(x: PX509; d_id: PASN1_OCTET_STRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_set0_distinguishing_id_procname);
end;

function ERR_X509_get0_distinguishing_id(x: PX509): PASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_distinguishing_id_procname);
end;

procedure ERR_X509_REQ_set0_distinguishing_id(x: PX509_REQ; d_id: PASN1_OCTET_STRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_set0_distinguishing_id_procname);
end;

function ERR_X509_REQ_get0_distinguishing_id(x: PX509_REQ): PASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get0_distinguishing_id_procname);
end;

function ERR_X509_alias_set1(x: PX509; name: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_alias_set1_procname);
end;

function ERR_X509_keyid_set1(x: PX509; id: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_keyid_set1_procname);
end;

function ERR_X509_alias_get0(x: PX509; len: PIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_alias_get0_procname);
end;

function ERR_X509_keyid_get0(x: PX509; len: PIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_keyid_get0_procname);
end;

function ERR_X509_REVOKED_new: PX509_REVOKED; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_new_procname);
end;

procedure ERR_X509_REVOKED_free(a: PX509_REVOKED); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_free_procname);
end;

function ERR_d2i_X509_REVOKED(a: PPX509_REVOKED; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_REVOKED; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_REVOKED_procname);
end;

function ERR_i2d_X509_REVOKED(a: PX509_REVOKED; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_REVOKED_procname);
end;

function ERR_X509_REVOKED_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_it_procname);
end;

function ERR_X509_CRL_INFO_new: PX509_CRL_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_INFO_new_procname);
end;

procedure ERR_X509_CRL_INFO_free(a: PX509_CRL_INFO); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_INFO_free_procname);
end;

function ERR_d2i_X509_CRL_INFO(a: PPX509_CRL_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_CRL_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_CRL_INFO_procname);
end;

function ERR_i2d_X509_CRL_INFO(a: PX509_CRL_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_CRL_INFO_procname);
end;

function ERR_X509_CRL_INFO_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_INFO_it_procname);
end;

function ERR_X509_CRL_new: PX509_CRL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_new_procname);
end;

procedure ERR_X509_CRL_free(a: PX509_CRL); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_free_procname);
end;

function ERR_d2i_X509_CRL(a: PPX509_CRL; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_CRL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_CRL_procname);
end;

function ERR_i2d_X509_CRL(a: PX509_CRL; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_CRL_procname);
end;

function ERR_X509_CRL_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_it_procname);
end;

function ERR_X509_CRL_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_CRL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_new_ex_procname);
end;

function ERR_X509_CRL_add0_revoked(crl: PX509_CRL; rev: PX509_REVOKED): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_add0_revoked_procname);
end;

function ERR_X509_CRL_get0_by_serial(crl: PX509_CRL; ret: PPX509_REVOKED; serial: PASN1_INTEGER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get0_by_serial_procname);
end;

function ERR_X509_CRL_get0_by_cert(crl: PX509_CRL; ret: PPX509_REVOKED; x: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get0_by_cert_procname);
end;

function ERR_X509_PKEY_new: PX509_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PKEY_new_procname);
end;

procedure ERR_X509_PKEY_free(a: PX509_PKEY); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PKEY_free_procname);
end;

function ERR_NETSCAPE_SPKI_new: PNETSCAPE_SPKI; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NETSCAPE_SPKI_new_procname);
end;

procedure ERR_NETSCAPE_SPKI_free(a: PNETSCAPE_SPKI); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NETSCAPE_SPKI_free_procname);
end;

function ERR_d2i_NETSCAPE_SPKI(a: PPNETSCAPE_SPKI; _in: PPIdAnsiChar; len: TIdC_LONG): PNETSCAPE_SPKI; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_NETSCAPE_SPKI_procname);
end;

function ERR_i2d_NETSCAPE_SPKI(a: PNETSCAPE_SPKI; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_NETSCAPE_SPKI_procname);
end;

function ERR_NETSCAPE_SPKI_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NETSCAPE_SPKI_it_procname);
end;

function ERR_NETSCAPE_SPKAC_new: PNETSCAPE_SPKAC; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NETSCAPE_SPKAC_new_procname);
end;

procedure ERR_NETSCAPE_SPKAC_free(a: PNETSCAPE_SPKAC); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NETSCAPE_SPKAC_free_procname);
end;

function ERR_d2i_NETSCAPE_SPKAC(a: PPNETSCAPE_SPKAC; _in: PPIdAnsiChar; len: TIdC_LONG): PNETSCAPE_SPKAC; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_NETSCAPE_SPKAC_procname);
end;

function ERR_i2d_NETSCAPE_SPKAC(a: PNETSCAPE_SPKAC; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_NETSCAPE_SPKAC_procname);
end;

function ERR_NETSCAPE_SPKAC_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NETSCAPE_SPKAC_it_procname);
end;

function ERR_NETSCAPE_CERT_SEQUENCE_new: PNETSCAPE_CERT_SEQUENCE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NETSCAPE_CERT_SEQUENCE_new_procname);
end;

procedure ERR_NETSCAPE_CERT_SEQUENCE_free(a: PNETSCAPE_CERT_SEQUENCE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NETSCAPE_CERT_SEQUENCE_free_procname);
end;

function ERR_d2i_NETSCAPE_CERT_SEQUENCE(a: PPNETSCAPE_CERT_SEQUENCE; _in: PPIdAnsiChar; len: TIdC_LONG): PNETSCAPE_CERT_SEQUENCE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_NETSCAPE_CERT_SEQUENCE_procname);
end;

function ERR_i2d_NETSCAPE_CERT_SEQUENCE(a: PNETSCAPE_CERT_SEQUENCE; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_NETSCAPE_CERT_SEQUENCE_procname);
end;

function ERR_NETSCAPE_CERT_SEQUENCE_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NETSCAPE_CERT_SEQUENCE_it_procname);
end;

function ERR_X509_INFO_new: PX509_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_INFO_new_procname);
end;

procedure ERR_X509_INFO_free(a: PX509_INFO); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_INFO_free_procname);
end;

function ERR_X509_NAME_oneline(a: PX509_NAME; buf: PIdAnsiChar; size: TIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_oneline_procname);
end;

function ERR_ASN1_verify(i2d: TASN1_verify_i2d_cb; algor1: PX509_ALGOR; signature: PASN1_BIT_STRING; data: PIdAnsiChar; pkey: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_verify_procname);
end;

function ERR_ASN1_digest(i2d: TASN1_verify_i2d_cb; _type: PEVP_MD; data: PIdAnsiChar; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_digest_procname);
end;

function ERR_ASN1_sign(i2d: TASN1_verify_i2d_cb; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: PIdAnsiChar; pkey: PEVP_PKEY; _type: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_sign_procname);
end;

function ERR_ASN1_item_digest(it: PASN1_ITEM; _type: PEVP_MD; data: Pointer; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_digest_procname);
end;

function ERR_ASN1_item_verify(it: PASN1_ITEM; alg: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_verify_procname);
end;

function ERR_ASN1_item_verify_ctx(it: PASN1_ITEM; alg: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; ctx: PEVP_MD_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_verify_ctx_procname);
end;

function ERR_ASN1_item_sign(it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; pkey: PEVP_PKEY; md: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_sign_procname);
end;

function ERR_ASN1_item_sign_ctx(it: PASN1_ITEM; algor1: PX509_ALGOR; algor2: PX509_ALGOR; signature: PASN1_BIT_STRING; data: Pointer; ctx: PEVP_MD_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ASN1_item_sign_ctx_procname);
end;

function ERR_X509_get_version(x: PX509): TIdC_LONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_version_procname);
end;

function ERR_X509_set_version(x: PX509; version: TIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_set_version_procname);
end;

function ERR_X509_set_serialNumber(x: PX509; serial: PASN1_INTEGER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_set_serialNumber_procname);
end;

function ERR_X509_get_serialNumber(x: PX509): PASN1_INTEGER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_serialNumber_procname);
end;

function ERR_X509_get0_serialNumber(x: PX509): PASN1_INTEGER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_serialNumber_procname);
end;

function ERR_X509_set_issuer_name(x: PX509; name: PX509_NAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_set_issuer_name_procname);
end;

function ERR_X509_get_issuer_name(a: PX509): PX509_NAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_issuer_name_procname);
end;

function ERR_X509_set_subject_name(x: PX509; name: PX509_NAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_set_subject_name_procname);
end;

function ERR_X509_get_subject_name(a: PX509): PX509_NAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_subject_name_procname);
end;

function ERR_X509_get0_notBefore(x: PX509): PASN1_TIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_notBefore_procname);
end;

function ERR_X509_getm_notBefore(x: PX509): PASN1_TIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_getm_notBefore_procname);
end;

function ERR_X509_set1_notBefore(x: PX509; tm: PASN1_TIME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_set1_notBefore_procname);
end;

function ERR_X509_get0_notAfter(x: PX509): PASN1_TIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_notAfter_procname);
end;

function ERR_X509_getm_notAfter(x: PX509): PASN1_TIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_getm_notAfter_procname);
end;

function ERR_X509_set1_notAfter(x: PX509; tm: PASN1_TIME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_set1_notAfter_procname);
end;

function ERR_X509_set_pubkey(x: PX509; pkey: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_set_pubkey_procname);
end;

function ERR_X509_up_ref(x: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_up_ref_procname);
end;

function ERR_X509_get_signature_type(x: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_signature_type_procname);
end;

function ERR_X509_get_X509_PUBKEY(x: PX509): PX509_PUBKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_X509_PUBKEY_procname);
end;

function ERR_X509_get0_extensions(x: PX509): Pstack_st_X509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_extensions_procname);
end;

procedure ERR_X509_get0_uids(x: PX509; piuid: PPASN1_BIT_STRING; psuid: PPASN1_BIT_STRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_uids_procname);
end;

function ERR_X509_get0_tbs_sigalg(x: PX509): PX509_ALGOR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_tbs_sigalg_procname);
end;

function ERR_X509_get0_pubkey(x: PX509): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_pubkey_procname);
end;

function ERR_X509_get_pubkey(x: PX509): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_pubkey_procname);
end;

function ERR_X509_get0_pubkey_bitstr(x: PX509): PASN1_BIT_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_pubkey_bitstr_procname);
end;

function ERR_X509_REQ_get_version(req: PX509_REQ): TIdC_LONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get_version_procname);
end;

function ERR_X509_REQ_set_version(x: PX509_REQ; version: TIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_set_version_procname);
end;

function ERR_X509_REQ_get_subject_name(req: PX509_REQ): PX509_NAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get_subject_name_procname);
end;

function ERR_X509_REQ_set_subject_name(req: PX509_REQ; name: PX509_NAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_set_subject_name_procname);
end;

procedure ERR_X509_REQ_get0_signature(req: PX509_REQ; psig: PPASN1_BIT_STRING; palg: PPX509_ALGOR); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get0_signature_procname);
end;

procedure ERR_X509_REQ_set0_signature(req: PX509_REQ; psig: PASN1_BIT_STRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_set0_signature_procname);
end;

function ERR_X509_REQ_set1_signature_algo(req: PX509_REQ; palg: PX509_ALGOR): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_set1_signature_algo_procname);
end;

function ERR_X509_REQ_get_signature_nid(req: PX509_REQ): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get_signature_nid_procname);
end;

function ERR_i2d_re_X509_REQ_tbs(req: PX509_REQ; pp: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_re_X509_REQ_tbs_procname);
end;

function ERR_X509_REQ_set_pubkey(x: PX509_REQ; pkey: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_set_pubkey_procname);
end;

function ERR_X509_REQ_get_pubkey(req: PX509_REQ): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get_pubkey_procname);
end;

function ERR_X509_REQ_get0_pubkey(req: PX509_REQ): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get0_pubkey_procname);
end;

function ERR_X509_REQ_get_X509_PUBKEY(req: PX509_REQ): PX509_PUBKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get_X509_PUBKEY_procname);
end;

function ERR_X509_REQ_extension_nid(nid: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_extension_nid_procname);
end;

function ERR_X509_REQ_get_extension_nids: PIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get_extension_nids_procname);
end;

procedure ERR_X509_REQ_set_extension_nids(nids: PIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_set_extension_nids_procname);
end;

function ERR_X509_REQ_get_extensions(req: PX509_REQ): Pstack_st_X509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get_extensions_procname);
end;

function ERR_X509_REQ_add_extensions_nid(req: PX509_REQ; exts: Pstack_st_X509_EXTENSION; nid: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_add_extensions_nid_procname);
end;

function ERR_X509_REQ_add_extensions(req: PX509_REQ; ext: Pstack_st_X509_EXTENSION): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_add_extensions_procname);
end;

function ERR_X509_REQ_get_attr_count(req: PX509_REQ): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get_attr_count_procname);
end;

function ERR_X509_REQ_get_attr_by_NID(req: PX509_REQ; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get_attr_by_NID_procname);
end;

function ERR_X509_REQ_get_attr_by_OBJ(req: PX509_REQ; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get_attr_by_OBJ_procname);
end;

function ERR_X509_REQ_get_attr(req: PX509_REQ; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get_attr_procname);
end;

function ERR_X509_REQ_delete_attr(req: PX509_REQ; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_delete_attr_procname);
end;

function ERR_X509_REQ_add1_attr(req: PX509_REQ; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_add1_attr_procname);
end;

function ERR_X509_REQ_add1_attr_by_OBJ(req: PX509_REQ; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_add1_attr_by_OBJ_procname);
end;

function ERR_X509_REQ_add1_attr_by_NID(req: PX509_REQ; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_add1_attr_by_NID_procname);
end;

function ERR_X509_REQ_add1_attr_by_txt(req: PX509_REQ; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_add1_attr_by_txt_procname);
end;

function ERR_X509_CRL_set_version(x: PX509_CRL; version: TIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_set_version_procname);
end;

function ERR_X509_CRL_set_issuer_name(x: PX509_CRL; name: PX509_NAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_set_issuer_name_procname);
end;

function ERR_X509_CRL_set1_lastUpdate(x: PX509_CRL; tm: PASN1_TIME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_set1_lastUpdate_procname);
end;

function ERR_X509_CRL_set1_nextUpdate(x: PX509_CRL; tm: PASN1_TIME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_set1_nextUpdate_procname);
end;

function ERR_X509_CRL_sort(crl: PX509_CRL): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_sort_procname);
end;

function ERR_X509_CRL_up_ref(crl: PX509_CRL): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_up_ref_procname);
end;

function ERR_X509_CRL_get_version(crl: PX509_CRL): TIdC_LONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get_version_procname);
end;

function ERR_X509_CRL_get0_lastUpdate(crl: PX509_CRL): PASN1_TIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get0_lastUpdate_procname);
end;

function ERR_X509_CRL_get0_nextUpdate(crl: PX509_CRL): PASN1_TIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get0_nextUpdate_procname);
end;

function ERR_X509_CRL_get_issuer(crl: PX509_CRL): PX509_NAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get_issuer_procname);
end;

function ERR_X509_CRL_get0_extensions(crl: PX509_CRL): Pstack_st_X509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get0_extensions_procname);
end;

function ERR_X509_CRL_get_REVOKED(crl: PX509_CRL): Pstack_st_X509_REVOKED; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get_REVOKED_procname);
end;

function ERR_X509_CRL_get0_tbs_sigalg(crl: PX509_CRL): PX509_ALGOR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get0_tbs_sigalg_procname);
end;

procedure ERR_X509_CRL_get0_signature(crl: PX509_CRL; psig: PPASN1_BIT_STRING; palg: PPX509_ALGOR); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get0_signature_procname);
end;

function ERR_X509_CRL_get_signature_nid(crl: PX509_CRL): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get_signature_nid_procname);
end;

function ERR_i2d_re_X509_CRL_tbs(req: PX509_CRL; pp: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_re_X509_CRL_tbs_procname);
end;

function ERR_X509_REVOKED_get0_serialNumber(x: PX509_REVOKED): PASN1_INTEGER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_get0_serialNumber_procname);
end;

function ERR_X509_REVOKED_set_serialNumber(x: PX509_REVOKED; serial: PASN1_INTEGER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_set_serialNumber_procname);
end;

function ERR_X509_REVOKED_get0_revocationDate(x: PX509_REVOKED): PASN1_TIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_get0_revocationDate_procname);
end;

function ERR_X509_REVOKED_set_revocationDate(r: PX509_REVOKED; tm: PASN1_TIME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_set_revocationDate_procname);
end;

function ERR_X509_REVOKED_get0_extensions(r: PX509_REVOKED): Pstack_st_X509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_get0_extensions_procname);
end;

function ERR_X509_CRL_diff(base: PX509_CRL; newer: PX509_CRL; skey: PEVP_PKEY; md: PEVP_MD; flags: TIdC_UINT): PX509_CRL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_diff_procname);
end;

function ERR_X509_REQ_check_private_key(req: PX509_REQ; pkey: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_check_private_key_procname);
end;

function ERR_X509_check_private_key(cert: PX509; pkey: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_check_private_key_procname);
end;

function ERR_X509_chain_check_suiteb(perror_depth: PIdC_INT; x: PX509; chain: Pstack_st_X509; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_chain_check_suiteb_procname);
end;

function ERR_X509_CRL_check_suiteb(crl: PX509_CRL; pk: PEVP_PKEY; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_check_suiteb_procname);
end;

procedure ERR_OSSL_STACK_OF_X509_free(certs: Pstack_st_X509); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_STACK_OF_X509_free_procname);
end;

function ERR_X509_chain_up_ref(chain: Pstack_st_X509): Pstack_st_X509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_chain_up_ref_procname);
end;

function ERR_X509_issuer_and_serial_cmp(a: PX509; b: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_issuer_and_serial_cmp_procname);
end;

function ERR_X509_issuer_and_serial_hash(a: PX509): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_issuer_and_serial_hash_procname);
end;

function ERR_X509_issuer_name_cmp(a: PX509; b: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_issuer_name_cmp_procname);
end;

function ERR_X509_issuer_name_hash(a: PX509): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_issuer_name_hash_procname);
end;

function ERR_X509_subject_name_cmp(a: PX509; b: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_subject_name_cmp_procname);
end;

function ERR_X509_subject_name_hash(x: PX509): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_subject_name_hash_procname);
end;

function ERR_X509_issuer_name_hash_old(a: PX509): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_issuer_name_hash_old_procname);
end;

function ERR_X509_subject_name_hash_old(x: PX509): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_subject_name_hash_old_procname);
end;

function ERR_X509_add_cert(sk: Pstack_st_X509; cert: PX509; flags: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_add_cert_procname);
end;

function ERR_X509_add_certs(sk: Pstack_st_X509; certs: Pstack_st_X509; flags: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_add_certs_procname);
end;

function ERR_X509_cmp(a: PX509; b: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_cmp_procname);
end;

function ERR_X509_NAME_cmp(a: PX509_NAME; b: PX509_NAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_cmp_procname);
end;

function ERR_X509_certificate_type(x: PX509; pubkey: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_certificate_type_procname);
end;

function ERR_X509_NAME_hash_ex(x: PX509_NAME; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar; ok: PIdC_INT): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_hash_ex_procname);
end;

function ERR_X509_NAME_hash_old(x: PX509_NAME): TIdC_ULONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_hash_old_procname);
end;

function ERR_X509_CRL_cmp(a: PX509_CRL; b: PX509_CRL): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_cmp_procname);
end;

function ERR_X509_CRL_match(a: PX509_CRL; b: PX509_CRL): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_match_procname);
end;

function ERR_X509_aux_print(_out: PBIO; x: PX509; indent: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_aux_print_procname);
end;

function ERR_X509_print_ex_fp(bp: PFILE; x: PX509; nmflag: TIdC_ULONG; cflag: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_print_ex_fp_procname);
end;

function ERR_X509_print_fp(bp: PFILE; x: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_print_fp_procname);
end;

function ERR_X509_CRL_print_fp(bp: PFILE; x: PX509_CRL): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_print_fp_procname);
end;

function ERR_X509_REQ_print_fp(bp: PFILE; req: PX509_REQ): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_print_fp_procname);
end;

function ERR_X509_NAME_print_ex_fp(fp: PFILE; nm: PX509_NAME; indent: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_print_ex_fp_procname);
end;

function ERR_X509_NAME_print(bp: PBIO; name: PX509_NAME; obase: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_print_procname);
end;

function ERR_X509_NAME_print_ex(_out: PBIO; nm: PX509_NAME; indent: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_print_ex_procname);
end;

function ERR_X509_print_ex(bp: PBIO; x: PX509; nmflag: TIdC_ULONG; cflag: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_print_ex_procname);
end;

function ERR_X509_print(bp: PBIO; x: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_print_procname);
end;

function ERR_X509_ocspid_print(bp: PBIO; x: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ocspid_print_procname);
end;

function ERR_X509_CRL_print_ex(_out: PBIO; x: PX509_CRL; nmflag: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_print_ex_procname);
end;

function ERR_X509_CRL_print(bp: PBIO; x: PX509_CRL): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_print_procname);
end;

function ERR_X509_REQ_print_ex(bp: PBIO; x: PX509_REQ; nmflag: TIdC_ULONG; cflag: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_print_ex_procname);
end;

function ERR_X509_REQ_print(bp: PBIO; req: PX509_REQ): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_print_procname);
end;

function ERR_X509_NAME_entry_count(name: PX509_NAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_entry_count_procname);
end;

function ERR_X509_NAME_get_text_by_NID(name: PX509_NAME; nid: TIdC_INT; buf: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_get_text_by_NID_procname);
end;

function ERR_X509_NAME_get_text_by_OBJ(name: PX509_NAME; obj: PASN1_OBJECT; buf: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_get_text_by_OBJ_procname);
end;

function ERR_X509_NAME_get_index_by_NID(name: PX509_NAME; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_get_index_by_NID_procname);
end;

function ERR_X509_NAME_get_index_by_OBJ(name: PX509_NAME; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_get_index_by_OBJ_procname);
end;

function ERR_X509_NAME_get_entry(name: PX509_NAME; loc: TIdC_INT): PX509_NAME_ENTRY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_get_entry_procname);
end;

function ERR_X509_NAME_delete_entry(name: PX509_NAME; loc: TIdC_INT): PX509_NAME_ENTRY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_delete_entry_procname);
end;

function ERR_X509_NAME_add_entry(name: PX509_NAME; ne: PX509_NAME_ENTRY; loc: TIdC_INT; _set: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_add_entry_procname);
end;

function ERR_X509_NAME_add_entry_by_OBJ(name: PX509_NAME; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT; loc: TIdC_INT; _set: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_add_entry_by_OBJ_procname);
end;

function ERR_X509_NAME_add_entry_by_NID(name: PX509_NAME; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT; loc: TIdC_INT; _set: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_add_entry_by_NID_procname);
end;

function ERR_X509_NAME_ENTRY_create_by_txt(ne: PPX509_NAME_ENTRY; field: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): PX509_NAME_ENTRY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_ENTRY_create_by_txt_procname);
end;

function ERR_X509_NAME_ENTRY_create_by_NID(ne: PPX509_NAME_ENTRY; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): PX509_NAME_ENTRY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_ENTRY_create_by_NID_procname);
end;

function ERR_X509_NAME_add_entry_by_txt(name: PX509_NAME; field: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT; loc: TIdC_INT; _set: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_add_entry_by_txt_procname);
end;

function ERR_X509_NAME_ENTRY_create_by_OBJ(ne: PPX509_NAME_ENTRY; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): PX509_NAME_ENTRY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_ENTRY_create_by_OBJ_procname);
end;

function ERR_X509_NAME_ENTRY_set_object(ne: PX509_NAME_ENTRY; obj: PASN1_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_ENTRY_set_object_procname);
end;

function ERR_X509_NAME_ENTRY_set_data(ne: PX509_NAME_ENTRY; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_ENTRY_set_data_procname);
end;

function ERR_X509_NAME_ENTRY_get_object(ne: PX509_NAME_ENTRY): PASN1_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_ENTRY_get_object_procname);
end;

function ERR_X509_NAME_ENTRY_get_data(ne: PX509_NAME_ENTRY): PASN1_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_ENTRY_get_data_procname);
end;

function ERR_X509_NAME_ENTRY_set(ne: PX509_NAME_ENTRY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_ENTRY_set_procname);
end;

function ERR_X509_NAME_get0_der(nm: PX509_NAME; pder: PPIdAnsiChar; pderlen: PIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_NAME_get0_der_procname);
end;

function ERR_X509v3_get_ext_count(x: Pstack_st_X509_EXTENSION): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_get_ext_count_procname);
end;

function ERR_X509v3_get_ext_by_NID(x: Pstack_st_X509_EXTENSION; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_get_ext_by_NID_procname);
end;

function ERR_X509v3_get_ext_by_OBJ(x: Pstack_st_X509_EXTENSION; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_get_ext_by_OBJ_procname);
end;

function ERR_X509v3_get_ext_by_critical(x: Pstack_st_X509_EXTENSION; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_get_ext_by_critical_procname);
end;

function ERR_X509v3_get_ext(x: Pstack_st_X509_EXTENSION; loc: TIdC_INT): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_get_ext_procname);
end;

function ERR_X509v3_delete_ext(x: Pstack_st_X509_EXTENSION; loc: TIdC_INT): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_delete_ext_procname);
end;

function ERR_X509v3_add_ext(x: PPstack_st_X509_EXTENSION; ex: PX509_EXTENSION; loc: TIdC_INT): Pstack_st_X509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_add_ext_procname);
end;

function ERR_X509v3_add_extensions(target: PPstack_st_X509_EXTENSION; exts: Pstack_st_X509_EXTENSION): Pstack_st_X509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_add_extensions_procname);
end;

function ERR_X509_get_ext_count(x: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_ext_count_procname);
end;

function ERR_X509_get_ext_by_NID(x: PX509; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_ext_by_NID_procname);
end;

function ERR_X509_get_ext_by_OBJ(x: PX509; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_ext_by_OBJ_procname);
end;

function ERR_X509_get_ext_by_critical(x: PX509; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_ext_by_critical_procname);
end;

function ERR_X509_get_ext(x: PX509; loc: TIdC_INT): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_ext_procname);
end;

function ERR_X509_delete_ext(x: PX509; loc: TIdC_INT): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_delete_ext_procname);
end;

function ERR_X509_add_ext(x: PX509; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_add_ext_procname);
end;

function ERR_X509_get_ext_d2i(x: PX509; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_ext_d2i_procname);
end;

function ERR_X509_add1_ext_i2d(x: PX509; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_add1_ext_i2d_procname);
end;

function ERR_X509_CRL_get_ext_count(x: PX509_CRL): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get_ext_count_procname);
end;

function ERR_X509_CRL_get_ext_by_NID(x: PX509_CRL; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get_ext_by_NID_procname);
end;

function ERR_X509_CRL_get_ext_by_OBJ(x: PX509_CRL; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get_ext_by_OBJ_procname);
end;

function ERR_X509_CRL_get_ext_by_critical(x: PX509_CRL; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get_ext_by_critical_procname);
end;

function ERR_X509_CRL_get_ext(x: PX509_CRL; loc: TIdC_INT): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get_ext_procname);
end;

function ERR_X509_CRL_delete_ext(x: PX509_CRL; loc: TIdC_INT): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_delete_ext_procname);
end;

function ERR_X509_CRL_add_ext(x: PX509_CRL; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_add_ext_procname);
end;

function ERR_X509_CRL_get_ext_d2i(x: PX509_CRL; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_get_ext_d2i_procname);
end;

function ERR_X509_CRL_add1_ext_i2d(x: PX509_CRL; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_CRL_add1_ext_i2d_procname);
end;

function ERR_X509_REVOKED_get_ext_count(x: PX509_REVOKED): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_get_ext_count_procname);
end;

function ERR_X509_REVOKED_get_ext_by_NID(x: PX509_REVOKED; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_get_ext_by_NID_procname);
end;

function ERR_X509_REVOKED_get_ext_by_OBJ(x: PX509_REVOKED; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_get_ext_by_OBJ_procname);
end;

function ERR_X509_REVOKED_get_ext_by_critical(x: PX509_REVOKED; crit: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_get_ext_by_critical_procname);
end;

function ERR_X509_REVOKED_get_ext(x: PX509_REVOKED; loc: TIdC_INT): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_get_ext_procname);
end;

function ERR_X509_REVOKED_delete_ext(x: PX509_REVOKED; loc: TIdC_INT): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_delete_ext_procname);
end;

function ERR_X509_REVOKED_add_ext(x: PX509_REVOKED; ex: PX509_EXTENSION; loc: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_add_ext_procname);
end;

function ERR_X509_REVOKED_get_ext_d2i(x: PX509_REVOKED; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_get_ext_d2i_procname);
end;

function ERR_X509_REVOKED_add1_ext_i2d(x: PX509_REVOKED; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REVOKED_add1_ext_i2d_procname);
end;

function ERR_X509_EXTENSION_create_by_NID(ex: PPX509_EXTENSION; nid: TIdC_INT; crit: TIdC_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_EXTENSION_create_by_NID_procname);
end;

function ERR_X509_EXTENSION_create_by_OBJ(ex: PPX509_EXTENSION; obj: PASN1_OBJECT; crit: TIdC_INT; data: PASN1_OCTET_STRING): PX509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_EXTENSION_create_by_OBJ_procname);
end;

function ERR_X509_EXTENSION_set_object(ex: PX509_EXTENSION; obj: PASN1_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_EXTENSION_set_object_procname);
end;

function ERR_X509_EXTENSION_set_critical(ex: PX509_EXTENSION; crit: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_EXTENSION_set_critical_procname);
end;

function ERR_X509_EXTENSION_set_data(ex: PX509_EXTENSION; data: PASN1_OCTET_STRING): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_EXTENSION_set_data_procname);
end;

function ERR_X509_EXTENSION_get_object(ex: PX509_EXTENSION): PASN1_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_EXTENSION_get_object_procname);
end;

function ERR_X509_EXTENSION_get_data(ne: PX509_EXTENSION): PASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_EXTENSION_get_data_procname);
end;

function ERR_X509_EXTENSION_get_critical(ex: PX509_EXTENSION): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_EXTENSION_get_critical_procname);
end;

function ERR_X509at_get_attr_count(x: Pstack_st_X509_ATTRIBUTE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509at_get_attr_count_procname);
end;

function ERR_X509at_get_attr_by_NID(x: Pstack_st_X509_ATTRIBUTE; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509at_get_attr_by_NID_procname);
end;

function ERR_X509at_get_attr_by_OBJ(sk: Pstack_st_X509_ATTRIBUTE; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509at_get_attr_by_OBJ_procname);
end;

function ERR_X509at_get_attr(x: Pstack_st_X509_ATTRIBUTE; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509at_get_attr_procname);
end;

function ERR_X509at_delete_attr(x: Pstack_st_X509_ATTRIBUTE; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509at_delete_attr_procname);
end;

function ERR_X509at_add1_attr(x: PPstack_st_X509_ATTRIBUTE; attr: PX509_ATTRIBUTE): Pstack_st_X509_ATTRIBUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509at_add1_attr_procname);
end;

function ERR_X509at_add1_attr_by_OBJ(x: PPstack_st_X509_ATTRIBUTE; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): Pstack_st_X509_ATTRIBUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509at_add1_attr_by_OBJ_procname);
end;

function ERR_X509at_add1_attr_by_NID(x: PPstack_st_X509_ATTRIBUTE; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): Pstack_st_X509_ATTRIBUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509at_add1_attr_by_NID_procname);
end;

function ERR_X509at_add1_attr_by_txt(x: PPstack_st_X509_ATTRIBUTE; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): Pstack_st_X509_ATTRIBUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509at_add1_attr_by_txt_procname);
end;

function ERR_X509at_get0_data_by_OBJ(x: Pstack_st_X509_ATTRIBUTE; obj: PASN1_OBJECT; lastpos: TIdC_INT; _type: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509at_get0_data_by_OBJ_procname);
end;

function ERR_X509_ATTRIBUTE_create_by_NID(attr: PPX509_ATTRIBUTE; nid: TIdC_INT; atrtype: TIdC_INT; data: Pointer; len: TIdC_INT): PX509_ATTRIBUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_create_by_NID_procname);
end;

function ERR_X509_ATTRIBUTE_create_by_OBJ(attr: PPX509_ATTRIBUTE; obj: PASN1_OBJECT; atrtype: TIdC_INT; data: Pointer; len: TIdC_INT): PX509_ATTRIBUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_create_by_OBJ_procname);
end;

function ERR_X509_ATTRIBUTE_create_by_txt(attr: PPX509_ATTRIBUTE; atrname: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): PX509_ATTRIBUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_create_by_txt_procname);
end;

function ERR_X509_ATTRIBUTE_set1_object(attr: PX509_ATTRIBUTE; obj: PASN1_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_set1_object_procname);
end;

function ERR_X509_ATTRIBUTE_set1_data(attr: PX509_ATTRIBUTE; attrtype: TIdC_INT; data: Pointer; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_set1_data_procname);
end;

function ERR_X509_ATTRIBUTE_get0_data(attr: PX509_ATTRIBUTE; idx: TIdC_INT; atrtype: TIdC_INT; data: Pointer): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_get0_data_procname);
end;

function ERR_X509_ATTRIBUTE_count(attr: PX509_ATTRIBUTE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_count_procname);
end;

function ERR_X509_ATTRIBUTE_get0_object(attr: PX509_ATTRIBUTE): PASN1_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_get0_object_procname);
end;

function ERR_X509_ATTRIBUTE_get0_type(attr: PX509_ATTRIBUTE; idx: TIdC_INT): PASN1_TYPE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ATTRIBUTE_get0_type_procname);
end;

function ERR_EVP_PKEY_get_attr_count(key: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get_attr_count_procname);
end;

function ERR_EVP_PKEY_get_attr_by_NID(key: PEVP_PKEY; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get_attr_by_NID_procname);
end;

function ERR_EVP_PKEY_get_attr_by_OBJ(key: PEVP_PKEY; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get_attr_by_OBJ_procname);
end;

function ERR_EVP_PKEY_get_attr(key: PEVP_PKEY; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_get_attr_procname);
end;

function ERR_EVP_PKEY_delete_attr(key: PEVP_PKEY; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_delete_attr_procname);
end;

function ERR_EVP_PKEY_add1_attr(key: PEVP_PKEY; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_add1_attr_procname);
end;

function ERR_EVP_PKEY_add1_attr_by_OBJ(key: PEVP_PKEY; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_add1_attr_by_OBJ_procname);
end;

function ERR_EVP_PKEY_add1_attr_by_NID(key: PEVP_PKEY; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_add1_attr_by_NID_procname);
end;

function ERR_EVP_PKEY_add1_attr_by_txt(key: PEVP_PKEY; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY_add1_attr_by_txt_procname);
end;

function ERR_X509_find_by_issuer_and_serial(sk: Pstack_st_X509; name: PX509_NAME; serial: PASN1_INTEGER): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_find_by_issuer_and_serial_procname);
end;

function ERR_X509_find_by_subject(sk: Pstack_st_X509; name: PX509_NAME): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_find_by_subject_procname);
end;

function ERR_PBEPARAM_new: PPBEPARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PBEPARAM_new_procname);
end;

procedure ERR_PBEPARAM_free(a: PPBEPARAM); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PBEPARAM_free_procname);
end;

function ERR_d2i_PBEPARAM(a: PPPBEPARAM; _in: PPIdAnsiChar; len: TIdC_LONG): PPBEPARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PBEPARAM_procname);
end;

function ERR_i2d_PBEPARAM(a: PPBEPARAM; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PBEPARAM_procname);
end;

function ERR_PBEPARAM_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PBEPARAM_it_procname);
end;

function ERR_PBE2PARAM_new: PPBE2PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PBE2PARAM_new_procname);
end;

procedure ERR_PBE2PARAM_free(a: PPBE2PARAM); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PBE2PARAM_free_procname);
end;

function ERR_d2i_PBE2PARAM(a: PPPBE2PARAM; _in: PPIdAnsiChar; len: TIdC_LONG): PPBE2PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PBE2PARAM_procname);
end;

function ERR_i2d_PBE2PARAM(a: PPBE2PARAM; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PBE2PARAM_procname);
end;

function ERR_PBE2PARAM_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PBE2PARAM_it_procname);
end;

function ERR_PBKDF2PARAM_new: PPBKDF2PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PBKDF2PARAM_new_procname);
end;

procedure ERR_PBKDF2PARAM_free(a: PPBKDF2PARAM); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PBKDF2PARAM_free_procname);
end;

function ERR_d2i_PBKDF2PARAM(a: PPPBKDF2PARAM; _in: PPIdAnsiChar; len: TIdC_LONG): PPBKDF2PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PBKDF2PARAM_procname);
end;

function ERR_i2d_PBKDF2PARAM(a: PPBKDF2PARAM; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PBKDF2PARAM_procname);
end;

function ERR_PBKDF2PARAM_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PBKDF2PARAM_it_procname);
end;

function ERR_PBMAC1PARAM_new: PPBMAC1PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PBMAC1PARAM_new_procname);
end;

procedure ERR_PBMAC1PARAM_free(a: PPBMAC1PARAM); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PBMAC1PARAM_free_procname);
end;

function ERR_d2i_PBMAC1PARAM(a: PPPBMAC1PARAM; _in: PPIdAnsiChar; len: TIdC_LONG): PPBMAC1PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PBMAC1PARAM_procname);
end;

function ERR_i2d_PBMAC1PARAM(a: PPBMAC1PARAM; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PBMAC1PARAM_procname);
end;

function ERR_PBMAC1PARAM_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PBMAC1PARAM_it_procname);
end;

function ERR_SCRYPT_PARAMS_new: PSCRYPT_PARAMS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCRYPT_PARAMS_new_procname);
end;

procedure ERR_SCRYPT_PARAMS_free(a: PSCRYPT_PARAMS); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCRYPT_PARAMS_free_procname);
end;

function ERR_d2i_SCRYPT_PARAMS(a: PPSCRYPT_PARAMS; _in: PPIdAnsiChar; len: TIdC_LONG): PSCRYPT_PARAMS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_SCRYPT_PARAMS_procname);
end;

function ERR_i2d_SCRYPT_PARAMS(a: PSCRYPT_PARAMS; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_SCRYPT_PARAMS_procname);
end;

function ERR_SCRYPT_PARAMS_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SCRYPT_PARAMS_it_procname);
end;

function ERR_PKCS5_pbe_set0_algor(algor: PX509_ALGOR; alg: TIdC_INT; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS5_pbe_set0_algor_procname);
end;

function ERR_PKCS5_pbe_set0_algor_ex(algor: PX509_ALGOR; alg: TIdC_INT; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; libctx: POSSL_LIB_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS5_pbe_set0_algor_ex_procname);
end;

function ERR_PKCS5_pbe_set(alg: TIdC_INT; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT): PX509_ALGOR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS5_pbe_set_procname);
end;

function ERR_PKCS5_pbe_set_ex(alg: TIdC_INT; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; libctx: POSSL_LIB_CTX): PX509_ALGOR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS5_pbe_set_ex_procname);
end;

function ERR_PKCS5_pbe2_set(cipher: PEVP_CIPHER; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT): PX509_ALGOR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS5_pbe2_set_procname);
end;

function ERR_PKCS5_pbe2_set_iv(cipher: PEVP_CIPHER; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; aiv: PIdAnsiChar; prf_nid: TIdC_INT): PX509_ALGOR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS5_pbe2_set_iv_procname);
end;

function ERR_PKCS5_pbe2_set_iv_ex(cipher: PEVP_CIPHER; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; aiv: PIdAnsiChar; prf_nid: TIdC_INT; libctx: POSSL_LIB_CTX): PX509_ALGOR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS5_pbe2_set_iv_ex_procname);
end;

function ERR_PKCS5_pbe2_set_scrypt(cipher: PEVP_CIPHER; salt: PIdAnsiChar; saltlen: TIdC_INT; aiv: PIdAnsiChar; N: TIdC_UINT64; r: TIdC_UINT64; p: TIdC_UINT64): PX509_ALGOR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS5_pbe2_set_scrypt_procname);
end;

function ERR_PKCS5_pbkdf2_set(iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; prf_nid: TIdC_INT; keylen: TIdC_INT): PX509_ALGOR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS5_pbkdf2_set_procname);
end;

function ERR_PKCS5_pbkdf2_set_ex(iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; prf_nid: TIdC_INT; keylen: TIdC_INT; libctx: POSSL_LIB_CTX): PX509_ALGOR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS5_pbkdf2_set_ex_procname);
end;

function ERR_PBMAC1_get1_pbkdf2_param(macalg: PX509_ALGOR): PPBKDF2PARAM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PBMAC1_get1_pbkdf2_param_procname);
end;

function ERR_PKCS8_PRIV_KEY_INFO_new: PPKCS8_PRIV_KEY_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS8_PRIV_KEY_INFO_new_procname);
end;

procedure ERR_PKCS8_PRIV_KEY_INFO_free(a: PPKCS8_PRIV_KEY_INFO); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS8_PRIV_KEY_INFO_free_procname);
end;

function ERR_d2i_PKCS8_PRIV_KEY_INFO(a: PPPKCS8_PRIV_KEY_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS8_PRIV_KEY_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS8_PRIV_KEY_INFO_procname);
end;

function ERR_i2d_PKCS8_PRIV_KEY_INFO(a: PPKCS8_PRIV_KEY_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS8_PRIV_KEY_INFO_procname);
end;

function ERR_PKCS8_PRIV_KEY_INFO_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS8_PRIV_KEY_INFO_it_procname);
end;

function ERR_EVP_PKCS82PKEY(p8: PPKCS8_PRIV_KEY_INFO): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKCS82PKEY_procname);
end;

function ERR_EVP_PKCS82PKEY_ex(p8: PPKCS8_PRIV_KEY_INFO; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKCS82PKEY_ex_procname);
end;

function ERR_EVP_PKEY2PKCS8(pkey: PEVP_PKEY): PPKCS8_PRIV_KEY_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(EVP_PKEY2PKCS8_procname);
end;

function ERR_PKCS8_pkey_set0(priv: PPKCS8_PRIV_KEY_INFO; aobj: PASN1_OBJECT; version: TIdC_INT; ptype: TIdC_INT; pval: Pointer; penc: PIdAnsiChar; penclen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS8_pkey_set0_procname);
end;

function ERR_PKCS8_pkey_get0(ppkalg: PPASN1_OBJECT; pk: PPIdAnsiChar; ppklen: PIdC_INT; pa: PPX509_ALGOR; p8: PPKCS8_PRIV_KEY_INFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS8_pkey_get0_procname);
end;

function ERR_PKCS8_pkey_get0_attrs(p8: PPKCS8_PRIV_KEY_INFO): Pstack_st_X509_ATTRIBUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS8_pkey_get0_attrs_procname);
end;

function ERR_PKCS8_pkey_add1_attr(p8: PPKCS8_PRIV_KEY_INFO; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS8_pkey_add1_attr_procname);
end;

function ERR_PKCS8_pkey_add1_attr_by_NID(p8: PPKCS8_PRIV_KEY_INFO; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS8_pkey_add1_attr_by_NID_procname);
end;

function ERR_PKCS8_pkey_add1_attr_by_OBJ(p8: PPKCS8_PRIV_KEY_INFO; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS8_pkey_add1_attr_by_OBJ_procname);
end;

procedure ERR_X509_PUBKEY_set0_public_key(pub: PX509_PUBKEY; penc: PIdAnsiChar; penclen: TIdC_INT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PUBKEY_set0_public_key_procname);
end;

function ERR_X509_PUBKEY_set0_param(pub: PX509_PUBKEY; aobj: PASN1_OBJECT; ptype: TIdC_INT; pval: Pointer; penc: PIdAnsiChar; penclen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PUBKEY_set0_param_procname);
end;

function ERR_X509_PUBKEY_get0_param(ppkalg: PPASN1_OBJECT; pk: PPIdAnsiChar; ppklen: PIdC_INT; pa: PPX509_ALGOR; pub: PX509_PUBKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PUBKEY_get0_param_procname);
end;

function ERR_X509_PUBKEY_eq(a: PX509_PUBKEY; b: PX509_PUBKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PUBKEY_eq_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  X509_CRL_set_default_method := LoadLibFunction(ADllHandle, X509_CRL_set_default_method_procname);
  FuncLoadError := not assigned(X509_CRL_set_default_method);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_set_default_method_allownil)}
    X509_CRL_set_default_method := ERR_X509_CRL_set_default_method;
    {$ifend}
    {$if declared(X509_CRL_set_default_method_introduced)}
    if LibVersion < X509_CRL_set_default_method_introduced then
    begin
      {$if declared(FC_X509_CRL_set_default_method)}
      X509_CRL_set_default_method := FC_X509_CRL_set_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_set_default_method_removed)}
    if X509_CRL_set_default_method_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_set_default_method)}
      X509_CRL_set_default_method := _X509_CRL_set_default_method;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_set_default_method_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_set_default_method');
    {$ifend}
  end;
  
  X509_CRL_METHOD_new := LoadLibFunction(ADllHandle, X509_CRL_METHOD_new_procname);
  FuncLoadError := not assigned(X509_CRL_METHOD_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_METHOD_new_allownil)}
    X509_CRL_METHOD_new := ERR_X509_CRL_METHOD_new;
    {$ifend}
    {$if declared(X509_CRL_METHOD_new_introduced)}
    if LibVersion < X509_CRL_METHOD_new_introduced then
    begin
      {$if declared(FC_X509_CRL_METHOD_new)}
      X509_CRL_METHOD_new := FC_X509_CRL_METHOD_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_METHOD_new_removed)}
    if X509_CRL_METHOD_new_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_METHOD_new)}
      X509_CRL_METHOD_new := _X509_CRL_METHOD_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_METHOD_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_METHOD_new');
    {$ifend}
  end;
  
  X509_CRL_METHOD_free := LoadLibFunction(ADllHandle, X509_CRL_METHOD_free_procname);
  FuncLoadError := not assigned(X509_CRL_METHOD_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_METHOD_free_allownil)}
    X509_CRL_METHOD_free := ERR_X509_CRL_METHOD_free;
    {$ifend}
    {$if declared(X509_CRL_METHOD_free_introduced)}
    if LibVersion < X509_CRL_METHOD_free_introduced then
    begin
      {$if declared(FC_X509_CRL_METHOD_free)}
      X509_CRL_METHOD_free := FC_X509_CRL_METHOD_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_METHOD_free_removed)}
    if X509_CRL_METHOD_free_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_METHOD_free)}
      X509_CRL_METHOD_free := _X509_CRL_METHOD_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_METHOD_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_METHOD_free');
    {$ifend}
  end;
  
  X509_CRL_set_meth_data := LoadLibFunction(ADllHandle, X509_CRL_set_meth_data_procname);
  FuncLoadError := not assigned(X509_CRL_set_meth_data);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_set_meth_data_allownil)}
    X509_CRL_set_meth_data := ERR_X509_CRL_set_meth_data;
    {$ifend}
    {$if declared(X509_CRL_set_meth_data_introduced)}
    if LibVersion < X509_CRL_set_meth_data_introduced then
    begin
      {$if declared(FC_X509_CRL_set_meth_data)}
      X509_CRL_set_meth_data := FC_X509_CRL_set_meth_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_set_meth_data_removed)}
    if X509_CRL_set_meth_data_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_set_meth_data)}
      X509_CRL_set_meth_data := _X509_CRL_set_meth_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_set_meth_data_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_set_meth_data');
    {$ifend}
  end;
  
  X509_CRL_get_meth_data := LoadLibFunction(ADllHandle, X509_CRL_get_meth_data_procname);
  FuncLoadError := not assigned(X509_CRL_get_meth_data);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_get_meth_data_allownil)}
    X509_CRL_get_meth_data := ERR_X509_CRL_get_meth_data;
    {$ifend}
    {$if declared(X509_CRL_get_meth_data_introduced)}
    if LibVersion < X509_CRL_get_meth_data_introduced then
    begin
      {$if declared(FC_X509_CRL_get_meth_data)}
      X509_CRL_get_meth_data := FC_X509_CRL_get_meth_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_get_meth_data_removed)}
    if X509_CRL_get_meth_data_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_get_meth_data)}
      X509_CRL_get_meth_data := _X509_CRL_get_meth_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_get_meth_data_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_get_meth_data');
    {$ifend}
  end;
  
  X509_verify_cert_error_string := LoadLibFunction(ADllHandle, X509_verify_cert_error_string_procname);
  FuncLoadError := not assigned(X509_verify_cert_error_string);
  if FuncLoadError then
  begin
    {$if not defined(X509_verify_cert_error_string_allownil)}
    X509_verify_cert_error_string := ERR_X509_verify_cert_error_string;
    {$ifend}
    {$if declared(X509_verify_cert_error_string_introduced)}
    if LibVersion < X509_verify_cert_error_string_introduced then
    begin
      {$if declared(FC_X509_verify_cert_error_string)}
      X509_verify_cert_error_string := FC_X509_verify_cert_error_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_verify_cert_error_string_removed)}
    if X509_verify_cert_error_string_removed <= LibVersion then
    begin
      {$if declared(_X509_verify_cert_error_string)}
      X509_verify_cert_error_string := _X509_verify_cert_error_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_verify_cert_error_string_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_verify_cert_error_string');
    {$ifend}
  end;
  
  X509_verify := LoadLibFunction(ADllHandle, X509_verify_procname);
  FuncLoadError := not assigned(X509_verify);
  if FuncLoadError then
  begin
    {$if not defined(X509_verify_allownil)}
    X509_verify := ERR_X509_verify;
    {$ifend}
    {$if declared(X509_verify_introduced)}
    if LibVersion < X509_verify_introduced then
    begin
      {$if declared(FC_X509_verify)}
      X509_verify := FC_X509_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_verify_removed)}
    if X509_verify_removed <= LibVersion then
    begin
      {$if declared(_X509_verify)}
      X509_verify := _X509_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_verify');
    {$ifend}
  end;
  
  X509_self_signed := LoadLibFunction(ADllHandle, X509_self_signed_procname);
  FuncLoadError := not assigned(X509_self_signed);
  if FuncLoadError then
  begin
    {$if not defined(X509_self_signed_allownil)}
    X509_self_signed := ERR_X509_self_signed;
    {$ifend}
    {$if declared(X509_self_signed_introduced)}
    if LibVersion < X509_self_signed_introduced then
    begin
      {$if declared(FC_X509_self_signed)}
      X509_self_signed := FC_X509_self_signed;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_self_signed_removed)}
    if X509_self_signed_removed <= LibVersion then
    begin
      {$if declared(_X509_self_signed)}
      X509_self_signed := _X509_self_signed;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_self_signed_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_self_signed');
    {$ifend}
  end;
  
  X509_REQ_verify_ex := LoadLibFunction(ADllHandle, X509_REQ_verify_ex_procname);
  FuncLoadError := not assigned(X509_REQ_verify_ex);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_verify_ex_allownil)}
    X509_REQ_verify_ex := ERR_X509_REQ_verify_ex;
    {$ifend}
    {$if declared(X509_REQ_verify_ex_introduced)}
    if LibVersion < X509_REQ_verify_ex_introduced then
    begin
      {$if declared(FC_X509_REQ_verify_ex)}
      X509_REQ_verify_ex := FC_X509_REQ_verify_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_verify_ex_removed)}
    if X509_REQ_verify_ex_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_verify_ex)}
      X509_REQ_verify_ex := _X509_REQ_verify_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_verify_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_verify_ex');
    {$ifend}
  end;
  
  X509_REQ_verify := LoadLibFunction(ADllHandle, X509_REQ_verify_procname);
  FuncLoadError := not assigned(X509_REQ_verify);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_verify_allownil)}
    X509_REQ_verify := ERR_X509_REQ_verify;
    {$ifend}
    {$if declared(X509_REQ_verify_introduced)}
    if LibVersion < X509_REQ_verify_introduced then
    begin
      {$if declared(FC_X509_REQ_verify)}
      X509_REQ_verify := FC_X509_REQ_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_verify_removed)}
    if X509_REQ_verify_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_verify)}
      X509_REQ_verify := _X509_REQ_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_verify');
    {$ifend}
  end;
  
  X509_CRL_verify := LoadLibFunction(ADllHandle, X509_CRL_verify_procname);
  FuncLoadError := not assigned(X509_CRL_verify);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_verify_allownil)}
    X509_CRL_verify := ERR_X509_CRL_verify;
    {$ifend}
    {$if declared(X509_CRL_verify_introduced)}
    if LibVersion < X509_CRL_verify_introduced then
    begin
      {$if declared(FC_X509_CRL_verify)}
      X509_CRL_verify := FC_X509_CRL_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_verify_removed)}
    if X509_CRL_verify_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_verify)}
      X509_CRL_verify := _X509_CRL_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_verify');
    {$ifend}
  end;
  
  NETSCAPE_SPKI_verify := LoadLibFunction(ADllHandle, NETSCAPE_SPKI_verify_procname);
  FuncLoadError := not assigned(NETSCAPE_SPKI_verify);
  if FuncLoadError then
  begin
    {$if not defined(NETSCAPE_SPKI_verify_allownil)}
    NETSCAPE_SPKI_verify := ERR_NETSCAPE_SPKI_verify;
    {$ifend}
    {$if declared(NETSCAPE_SPKI_verify_introduced)}
    if LibVersion < NETSCAPE_SPKI_verify_introduced then
    begin
      {$if declared(FC_NETSCAPE_SPKI_verify)}
      NETSCAPE_SPKI_verify := FC_NETSCAPE_SPKI_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NETSCAPE_SPKI_verify_removed)}
    if NETSCAPE_SPKI_verify_removed <= LibVersion then
    begin
      {$if declared(_NETSCAPE_SPKI_verify)}
      NETSCAPE_SPKI_verify := _NETSCAPE_SPKI_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NETSCAPE_SPKI_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('NETSCAPE_SPKI_verify');
    {$ifend}
  end;
  
  NETSCAPE_SPKI_b64_decode := LoadLibFunction(ADllHandle, NETSCAPE_SPKI_b64_decode_procname);
  FuncLoadError := not assigned(NETSCAPE_SPKI_b64_decode);
  if FuncLoadError then
  begin
    {$if not defined(NETSCAPE_SPKI_b64_decode_allownil)}
    NETSCAPE_SPKI_b64_decode := ERR_NETSCAPE_SPKI_b64_decode;
    {$ifend}
    {$if declared(NETSCAPE_SPKI_b64_decode_introduced)}
    if LibVersion < NETSCAPE_SPKI_b64_decode_introduced then
    begin
      {$if declared(FC_NETSCAPE_SPKI_b64_decode)}
      NETSCAPE_SPKI_b64_decode := FC_NETSCAPE_SPKI_b64_decode;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NETSCAPE_SPKI_b64_decode_removed)}
    if NETSCAPE_SPKI_b64_decode_removed <= LibVersion then
    begin
      {$if declared(_NETSCAPE_SPKI_b64_decode)}
      NETSCAPE_SPKI_b64_decode := _NETSCAPE_SPKI_b64_decode;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NETSCAPE_SPKI_b64_decode_allownil)}
    if FuncLoadError then
      AFailed.Add('NETSCAPE_SPKI_b64_decode');
    {$ifend}
  end;
  
  NETSCAPE_SPKI_b64_encode := LoadLibFunction(ADllHandle, NETSCAPE_SPKI_b64_encode_procname);
  FuncLoadError := not assigned(NETSCAPE_SPKI_b64_encode);
  if FuncLoadError then
  begin
    {$if not defined(NETSCAPE_SPKI_b64_encode_allownil)}
    NETSCAPE_SPKI_b64_encode := ERR_NETSCAPE_SPKI_b64_encode;
    {$ifend}
    {$if declared(NETSCAPE_SPKI_b64_encode_introduced)}
    if LibVersion < NETSCAPE_SPKI_b64_encode_introduced then
    begin
      {$if declared(FC_NETSCAPE_SPKI_b64_encode)}
      NETSCAPE_SPKI_b64_encode := FC_NETSCAPE_SPKI_b64_encode;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NETSCAPE_SPKI_b64_encode_removed)}
    if NETSCAPE_SPKI_b64_encode_removed <= LibVersion then
    begin
      {$if declared(_NETSCAPE_SPKI_b64_encode)}
      NETSCAPE_SPKI_b64_encode := _NETSCAPE_SPKI_b64_encode;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NETSCAPE_SPKI_b64_encode_allownil)}
    if FuncLoadError then
      AFailed.Add('NETSCAPE_SPKI_b64_encode');
    {$ifend}
  end;
  
  NETSCAPE_SPKI_get_pubkey := LoadLibFunction(ADllHandle, NETSCAPE_SPKI_get_pubkey_procname);
  FuncLoadError := not assigned(NETSCAPE_SPKI_get_pubkey);
  if FuncLoadError then
  begin
    {$if not defined(NETSCAPE_SPKI_get_pubkey_allownil)}
    NETSCAPE_SPKI_get_pubkey := ERR_NETSCAPE_SPKI_get_pubkey;
    {$ifend}
    {$if declared(NETSCAPE_SPKI_get_pubkey_introduced)}
    if LibVersion < NETSCAPE_SPKI_get_pubkey_introduced then
    begin
      {$if declared(FC_NETSCAPE_SPKI_get_pubkey)}
      NETSCAPE_SPKI_get_pubkey := FC_NETSCAPE_SPKI_get_pubkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NETSCAPE_SPKI_get_pubkey_removed)}
    if NETSCAPE_SPKI_get_pubkey_removed <= LibVersion then
    begin
      {$if declared(_NETSCAPE_SPKI_get_pubkey)}
      NETSCAPE_SPKI_get_pubkey := _NETSCAPE_SPKI_get_pubkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NETSCAPE_SPKI_get_pubkey_allownil)}
    if FuncLoadError then
      AFailed.Add('NETSCAPE_SPKI_get_pubkey');
    {$ifend}
  end;
  
  NETSCAPE_SPKI_set_pubkey := LoadLibFunction(ADllHandle, NETSCAPE_SPKI_set_pubkey_procname);
  FuncLoadError := not assigned(NETSCAPE_SPKI_set_pubkey);
  if FuncLoadError then
  begin
    {$if not defined(NETSCAPE_SPKI_set_pubkey_allownil)}
    NETSCAPE_SPKI_set_pubkey := ERR_NETSCAPE_SPKI_set_pubkey;
    {$ifend}
    {$if declared(NETSCAPE_SPKI_set_pubkey_introduced)}
    if LibVersion < NETSCAPE_SPKI_set_pubkey_introduced then
    begin
      {$if declared(FC_NETSCAPE_SPKI_set_pubkey)}
      NETSCAPE_SPKI_set_pubkey := FC_NETSCAPE_SPKI_set_pubkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NETSCAPE_SPKI_set_pubkey_removed)}
    if NETSCAPE_SPKI_set_pubkey_removed <= LibVersion then
    begin
      {$if declared(_NETSCAPE_SPKI_set_pubkey)}
      NETSCAPE_SPKI_set_pubkey := _NETSCAPE_SPKI_set_pubkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NETSCAPE_SPKI_set_pubkey_allownil)}
    if FuncLoadError then
      AFailed.Add('NETSCAPE_SPKI_set_pubkey');
    {$ifend}
  end;
  
  NETSCAPE_SPKI_print := LoadLibFunction(ADllHandle, NETSCAPE_SPKI_print_procname);
  FuncLoadError := not assigned(NETSCAPE_SPKI_print);
  if FuncLoadError then
  begin
    {$if not defined(NETSCAPE_SPKI_print_allownil)}
    NETSCAPE_SPKI_print := ERR_NETSCAPE_SPKI_print;
    {$ifend}
    {$if declared(NETSCAPE_SPKI_print_introduced)}
    if LibVersion < NETSCAPE_SPKI_print_introduced then
    begin
      {$if declared(FC_NETSCAPE_SPKI_print)}
      NETSCAPE_SPKI_print := FC_NETSCAPE_SPKI_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NETSCAPE_SPKI_print_removed)}
    if NETSCAPE_SPKI_print_removed <= LibVersion then
    begin
      {$if declared(_NETSCAPE_SPKI_print)}
      NETSCAPE_SPKI_print := _NETSCAPE_SPKI_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NETSCAPE_SPKI_print_allownil)}
    if FuncLoadError then
      AFailed.Add('NETSCAPE_SPKI_print');
    {$ifend}
  end;
  
  X509_signature_dump := LoadLibFunction(ADllHandle, X509_signature_dump_procname);
  FuncLoadError := not assigned(X509_signature_dump);
  if FuncLoadError then
  begin
    {$if not defined(X509_signature_dump_allownil)}
    X509_signature_dump := ERR_X509_signature_dump;
    {$ifend}
    {$if declared(X509_signature_dump_introduced)}
    if LibVersion < X509_signature_dump_introduced then
    begin
      {$if declared(FC_X509_signature_dump)}
      X509_signature_dump := FC_X509_signature_dump;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_signature_dump_removed)}
    if X509_signature_dump_removed <= LibVersion then
    begin
      {$if declared(_X509_signature_dump)}
      X509_signature_dump := _X509_signature_dump;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_signature_dump_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_signature_dump');
    {$ifend}
  end;
  
  X509_signature_print := LoadLibFunction(ADllHandle, X509_signature_print_procname);
  FuncLoadError := not assigned(X509_signature_print);
  if FuncLoadError then
  begin
    {$if not defined(X509_signature_print_allownil)}
    X509_signature_print := ERR_X509_signature_print;
    {$ifend}
    {$if declared(X509_signature_print_introduced)}
    if LibVersion < X509_signature_print_introduced then
    begin
      {$if declared(FC_X509_signature_print)}
      X509_signature_print := FC_X509_signature_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_signature_print_removed)}
    if X509_signature_print_removed <= LibVersion then
    begin
      {$if declared(_X509_signature_print)}
      X509_signature_print := _X509_signature_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_signature_print_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_signature_print');
    {$ifend}
  end;
  
  X509_sign := LoadLibFunction(ADllHandle, X509_sign_procname);
  FuncLoadError := not assigned(X509_sign);
  if FuncLoadError then
  begin
    {$if not defined(X509_sign_allownil)}
    X509_sign := ERR_X509_sign;
    {$ifend}
    {$if declared(X509_sign_introduced)}
    if LibVersion < X509_sign_introduced then
    begin
      {$if declared(FC_X509_sign)}
      X509_sign := FC_X509_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_sign_removed)}
    if X509_sign_removed <= LibVersion then
    begin
      {$if declared(_X509_sign)}
      X509_sign := _X509_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_sign');
    {$ifend}
  end;
  
  X509_sign_ctx := LoadLibFunction(ADllHandle, X509_sign_ctx_procname);
  FuncLoadError := not assigned(X509_sign_ctx);
  if FuncLoadError then
  begin
    {$if not defined(X509_sign_ctx_allownil)}
    X509_sign_ctx := ERR_X509_sign_ctx;
    {$ifend}
    {$if declared(X509_sign_ctx_introduced)}
    if LibVersion < X509_sign_ctx_introduced then
    begin
      {$if declared(FC_X509_sign_ctx)}
      X509_sign_ctx := FC_X509_sign_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_sign_ctx_removed)}
    if X509_sign_ctx_removed <= LibVersion then
    begin
      {$if declared(_X509_sign_ctx)}
      X509_sign_ctx := _X509_sign_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_sign_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_sign_ctx');
    {$ifend}
  end;
  
  X509_REQ_sign := LoadLibFunction(ADllHandle, X509_REQ_sign_procname);
  FuncLoadError := not assigned(X509_REQ_sign);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_sign_allownil)}
    X509_REQ_sign := ERR_X509_REQ_sign;
    {$ifend}
    {$if declared(X509_REQ_sign_introduced)}
    if LibVersion < X509_REQ_sign_introduced then
    begin
      {$if declared(FC_X509_REQ_sign)}
      X509_REQ_sign := FC_X509_REQ_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_sign_removed)}
    if X509_REQ_sign_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_sign)}
      X509_REQ_sign := _X509_REQ_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_sign');
    {$ifend}
  end;
  
  X509_REQ_sign_ctx := LoadLibFunction(ADllHandle, X509_REQ_sign_ctx_procname);
  FuncLoadError := not assigned(X509_REQ_sign_ctx);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_sign_ctx_allownil)}
    X509_REQ_sign_ctx := ERR_X509_REQ_sign_ctx;
    {$ifend}
    {$if declared(X509_REQ_sign_ctx_introduced)}
    if LibVersion < X509_REQ_sign_ctx_introduced then
    begin
      {$if declared(FC_X509_REQ_sign_ctx)}
      X509_REQ_sign_ctx := FC_X509_REQ_sign_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_sign_ctx_removed)}
    if X509_REQ_sign_ctx_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_sign_ctx)}
      X509_REQ_sign_ctx := _X509_REQ_sign_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_sign_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_sign_ctx');
    {$ifend}
  end;
  
  X509_CRL_sign := LoadLibFunction(ADllHandle, X509_CRL_sign_procname);
  FuncLoadError := not assigned(X509_CRL_sign);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_sign_allownil)}
    X509_CRL_sign := ERR_X509_CRL_sign;
    {$ifend}
    {$if declared(X509_CRL_sign_introduced)}
    if LibVersion < X509_CRL_sign_introduced then
    begin
      {$if declared(FC_X509_CRL_sign)}
      X509_CRL_sign := FC_X509_CRL_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_sign_removed)}
    if X509_CRL_sign_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_sign)}
      X509_CRL_sign := _X509_CRL_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_sign');
    {$ifend}
  end;
  
  X509_CRL_sign_ctx := LoadLibFunction(ADllHandle, X509_CRL_sign_ctx_procname);
  FuncLoadError := not assigned(X509_CRL_sign_ctx);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_sign_ctx_allownil)}
    X509_CRL_sign_ctx := ERR_X509_CRL_sign_ctx;
    {$ifend}
    {$if declared(X509_CRL_sign_ctx_introduced)}
    if LibVersion < X509_CRL_sign_ctx_introduced then
    begin
      {$if declared(FC_X509_CRL_sign_ctx)}
      X509_CRL_sign_ctx := FC_X509_CRL_sign_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_sign_ctx_removed)}
    if X509_CRL_sign_ctx_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_sign_ctx)}
      X509_CRL_sign_ctx := _X509_CRL_sign_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_sign_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_sign_ctx');
    {$ifend}
  end;
  
  NETSCAPE_SPKI_sign := LoadLibFunction(ADllHandle, NETSCAPE_SPKI_sign_procname);
  FuncLoadError := not assigned(NETSCAPE_SPKI_sign);
  if FuncLoadError then
  begin
    {$if not defined(NETSCAPE_SPKI_sign_allownil)}
    NETSCAPE_SPKI_sign := ERR_NETSCAPE_SPKI_sign;
    {$ifend}
    {$if declared(NETSCAPE_SPKI_sign_introduced)}
    if LibVersion < NETSCAPE_SPKI_sign_introduced then
    begin
      {$if declared(FC_NETSCAPE_SPKI_sign)}
      NETSCAPE_SPKI_sign := FC_NETSCAPE_SPKI_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NETSCAPE_SPKI_sign_removed)}
    if NETSCAPE_SPKI_sign_removed <= LibVersion then
    begin
      {$if declared(_NETSCAPE_SPKI_sign)}
      NETSCAPE_SPKI_sign := _NETSCAPE_SPKI_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NETSCAPE_SPKI_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('NETSCAPE_SPKI_sign');
    {$ifend}
  end;
  
  X509_pubkey_digest := LoadLibFunction(ADllHandle, X509_pubkey_digest_procname);
  FuncLoadError := not assigned(X509_pubkey_digest);
  if FuncLoadError then
  begin
    {$if not defined(X509_pubkey_digest_allownil)}
    X509_pubkey_digest := ERR_X509_pubkey_digest;
    {$ifend}
    {$if declared(X509_pubkey_digest_introduced)}
    if LibVersion < X509_pubkey_digest_introduced then
    begin
      {$if declared(FC_X509_pubkey_digest)}
      X509_pubkey_digest := FC_X509_pubkey_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_pubkey_digest_removed)}
    if X509_pubkey_digest_removed <= LibVersion then
    begin
      {$if declared(_X509_pubkey_digest)}
      X509_pubkey_digest := _X509_pubkey_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_pubkey_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_pubkey_digest');
    {$ifend}
  end;
  
  X509_digest := LoadLibFunction(ADllHandle, X509_digest_procname);
  FuncLoadError := not assigned(X509_digest);
  if FuncLoadError then
  begin
    {$if not defined(X509_digest_allownil)}
    X509_digest := ERR_X509_digest;
    {$ifend}
    {$if declared(X509_digest_introduced)}
    if LibVersion < X509_digest_introduced then
    begin
      {$if declared(FC_X509_digest)}
      X509_digest := FC_X509_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_digest_removed)}
    if X509_digest_removed <= LibVersion then
    begin
      {$if declared(_X509_digest)}
      X509_digest := _X509_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_digest');
    {$ifend}
  end;
  
  X509_digest_sig := LoadLibFunction(ADllHandle, X509_digest_sig_procname);
  FuncLoadError := not assigned(X509_digest_sig);
  if FuncLoadError then
  begin
    {$if not defined(X509_digest_sig_allownil)}
    X509_digest_sig := ERR_X509_digest_sig;
    {$ifend}
    {$if declared(X509_digest_sig_introduced)}
    if LibVersion < X509_digest_sig_introduced then
    begin
      {$if declared(FC_X509_digest_sig)}
      X509_digest_sig := FC_X509_digest_sig;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_digest_sig_removed)}
    if X509_digest_sig_removed <= LibVersion then
    begin
      {$if declared(_X509_digest_sig)}
      X509_digest_sig := _X509_digest_sig;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_digest_sig_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_digest_sig');
    {$ifend}
  end;
  
  X509_CRL_digest := LoadLibFunction(ADllHandle, X509_CRL_digest_procname);
  FuncLoadError := not assigned(X509_CRL_digest);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_digest_allownil)}
    X509_CRL_digest := ERR_X509_CRL_digest;
    {$ifend}
    {$if declared(X509_CRL_digest_introduced)}
    if LibVersion < X509_CRL_digest_introduced then
    begin
      {$if declared(FC_X509_CRL_digest)}
      X509_CRL_digest := FC_X509_CRL_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_digest_removed)}
    if X509_CRL_digest_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_digest)}
      X509_CRL_digest := _X509_CRL_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_digest');
    {$ifend}
  end;
  
  X509_REQ_digest := LoadLibFunction(ADllHandle, X509_REQ_digest_procname);
  FuncLoadError := not assigned(X509_REQ_digest);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_digest_allownil)}
    X509_REQ_digest := ERR_X509_REQ_digest;
    {$ifend}
    {$if declared(X509_REQ_digest_introduced)}
    if LibVersion < X509_REQ_digest_introduced then
    begin
      {$if declared(FC_X509_REQ_digest)}
      X509_REQ_digest := FC_X509_REQ_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_digest_removed)}
    if X509_REQ_digest_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_digest)}
      X509_REQ_digest := _X509_REQ_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_digest');
    {$ifend}
  end;
  
  X509_NAME_digest := LoadLibFunction(ADllHandle, X509_NAME_digest_procname);
  FuncLoadError := not assigned(X509_NAME_digest);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_digest_allownil)}
    X509_NAME_digest := ERR_X509_NAME_digest;
    {$ifend}
    {$if declared(X509_NAME_digest_introduced)}
    if LibVersion < X509_NAME_digest_introduced then
    begin
      {$if declared(FC_X509_NAME_digest)}
      X509_NAME_digest := FC_X509_NAME_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_digest_removed)}
    if X509_NAME_digest_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_digest)}
      X509_NAME_digest := _X509_NAME_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_digest');
    {$ifend}
  end;
  
  X509_load_http := LoadLibFunction(ADllHandle, X509_load_http_procname);
  FuncLoadError := not assigned(X509_load_http);
  if FuncLoadError then
  begin
    {$if not defined(X509_load_http_allownil)}
    X509_load_http := ERR_X509_load_http;
    {$ifend}
    {$if declared(X509_load_http_introduced)}
    if LibVersion < X509_load_http_introduced then
    begin
      {$if declared(FC_X509_load_http)}
      X509_load_http := FC_X509_load_http;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_load_http_removed)}
    if X509_load_http_removed <= LibVersion then
    begin
      {$if declared(_X509_load_http)}
      X509_load_http := _X509_load_http;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_load_http_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_load_http');
    {$ifend}
  end;
  
  X509_CRL_load_http := LoadLibFunction(ADllHandle, X509_CRL_load_http_procname);
  FuncLoadError := not assigned(X509_CRL_load_http);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_load_http_allownil)}
    X509_CRL_load_http := ERR_X509_CRL_load_http;
    {$ifend}
    {$if declared(X509_CRL_load_http_introduced)}
    if LibVersion < X509_CRL_load_http_introduced then
    begin
      {$if declared(FC_X509_CRL_load_http)}
      X509_CRL_load_http := FC_X509_CRL_load_http;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_load_http_removed)}
    if X509_CRL_load_http_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_load_http)}
      X509_CRL_load_http := _X509_CRL_load_http;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_load_http_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_load_http');
    {$ifend}
  end;
  
  d2i_X509_fp := LoadLibFunction(ADllHandle, d2i_X509_fp_procname);
  FuncLoadError := not assigned(d2i_X509_fp);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_fp_allownil)}
    d2i_X509_fp := ERR_d2i_X509_fp;
    {$ifend}
    {$if declared(d2i_X509_fp_introduced)}
    if LibVersion < d2i_X509_fp_introduced then
    begin
      {$if declared(FC_d2i_X509_fp)}
      d2i_X509_fp := FC_d2i_X509_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_fp_removed)}
    if d2i_X509_fp_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_fp)}
      d2i_X509_fp := _d2i_X509_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_fp');
    {$ifend}
  end;
  
  i2d_X509_fp := LoadLibFunction(ADllHandle, i2d_X509_fp_procname);
  FuncLoadError := not assigned(i2d_X509_fp);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_fp_allownil)}
    i2d_X509_fp := ERR_i2d_X509_fp;
    {$ifend}
    {$if declared(i2d_X509_fp_introduced)}
    if LibVersion < i2d_X509_fp_introduced then
    begin
      {$if declared(FC_i2d_X509_fp)}
      i2d_X509_fp := FC_i2d_X509_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_fp_removed)}
    if i2d_X509_fp_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_fp)}
      i2d_X509_fp := _i2d_X509_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_fp');
    {$ifend}
  end;
  
  d2i_X509_CRL_fp := LoadLibFunction(ADllHandle, d2i_X509_CRL_fp_procname);
  FuncLoadError := not assigned(d2i_X509_CRL_fp);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_CRL_fp_allownil)}
    d2i_X509_CRL_fp := ERR_d2i_X509_CRL_fp;
    {$ifend}
    {$if declared(d2i_X509_CRL_fp_introduced)}
    if LibVersion < d2i_X509_CRL_fp_introduced then
    begin
      {$if declared(FC_d2i_X509_CRL_fp)}
      d2i_X509_CRL_fp := FC_d2i_X509_CRL_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_CRL_fp_removed)}
    if d2i_X509_CRL_fp_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_CRL_fp)}
      d2i_X509_CRL_fp := _d2i_X509_CRL_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_CRL_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_CRL_fp');
    {$ifend}
  end;
  
  i2d_X509_CRL_fp := LoadLibFunction(ADllHandle, i2d_X509_CRL_fp_procname);
  FuncLoadError := not assigned(i2d_X509_CRL_fp);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_CRL_fp_allownil)}
    i2d_X509_CRL_fp := ERR_i2d_X509_CRL_fp;
    {$ifend}
    {$if declared(i2d_X509_CRL_fp_introduced)}
    if LibVersion < i2d_X509_CRL_fp_introduced then
    begin
      {$if declared(FC_i2d_X509_CRL_fp)}
      i2d_X509_CRL_fp := FC_i2d_X509_CRL_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_CRL_fp_removed)}
    if i2d_X509_CRL_fp_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_CRL_fp)}
      i2d_X509_CRL_fp := _i2d_X509_CRL_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_CRL_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_CRL_fp');
    {$ifend}
  end;
  
  d2i_X509_REQ_fp := LoadLibFunction(ADllHandle, d2i_X509_REQ_fp_procname);
  FuncLoadError := not assigned(d2i_X509_REQ_fp);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_REQ_fp_allownil)}
    d2i_X509_REQ_fp := ERR_d2i_X509_REQ_fp;
    {$ifend}
    {$if declared(d2i_X509_REQ_fp_introduced)}
    if LibVersion < d2i_X509_REQ_fp_introduced then
    begin
      {$if declared(FC_d2i_X509_REQ_fp)}
      d2i_X509_REQ_fp := FC_d2i_X509_REQ_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_REQ_fp_removed)}
    if d2i_X509_REQ_fp_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_REQ_fp)}
      d2i_X509_REQ_fp := _d2i_X509_REQ_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_REQ_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_REQ_fp');
    {$ifend}
  end;
  
  i2d_X509_REQ_fp := LoadLibFunction(ADllHandle, i2d_X509_REQ_fp_procname);
  FuncLoadError := not assigned(i2d_X509_REQ_fp);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_REQ_fp_allownil)}
    i2d_X509_REQ_fp := ERR_i2d_X509_REQ_fp;
    {$ifend}
    {$if declared(i2d_X509_REQ_fp_introduced)}
    if LibVersion < i2d_X509_REQ_fp_introduced then
    begin
      {$if declared(FC_i2d_X509_REQ_fp)}
      i2d_X509_REQ_fp := FC_i2d_X509_REQ_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_REQ_fp_removed)}
    if i2d_X509_REQ_fp_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_REQ_fp)}
      i2d_X509_REQ_fp := _i2d_X509_REQ_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_REQ_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_REQ_fp');
    {$ifend}
  end;
  
  d2i_RSAPrivateKey_fp := LoadLibFunction(ADllHandle, d2i_RSAPrivateKey_fp_procname);
  FuncLoadError := not assigned(d2i_RSAPrivateKey_fp);
  if FuncLoadError then
  begin
    {$if not defined(d2i_RSAPrivateKey_fp_allownil)}
    d2i_RSAPrivateKey_fp := ERR_d2i_RSAPrivateKey_fp;
    {$ifend}
    {$if declared(d2i_RSAPrivateKey_fp_introduced)}
    if LibVersion < d2i_RSAPrivateKey_fp_introduced then
    begin
      {$if declared(FC_d2i_RSAPrivateKey_fp)}
      d2i_RSAPrivateKey_fp := FC_d2i_RSAPrivateKey_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_RSAPrivateKey_fp_removed)}
    if d2i_RSAPrivateKey_fp_removed <= LibVersion then
    begin
      {$if declared(_d2i_RSAPrivateKey_fp)}
      d2i_RSAPrivateKey_fp := _d2i_RSAPrivateKey_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_RSAPrivateKey_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_RSAPrivateKey_fp');
    {$ifend}
  end;
  
  i2d_RSAPrivateKey_fp := LoadLibFunction(ADllHandle, i2d_RSAPrivateKey_fp_procname);
  FuncLoadError := not assigned(i2d_RSAPrivateKey_fp);
  if FuncLoadError then
  begin
    {$if not defined(i2d_RSAPrivateKey_fp_allownil)}
    i2d_RSAPrivateKey_fp := ERR_i2d_RSAPrivateKey_fp;
    {$ifend}
    {$if declared(i2d_RSAPrivateKey_fp_introduced)}
    if LibVersion < i2d_RSAPrivateKey_fp_introduced then
    begin
      {$if declared(FC_i2d_RSAPrivateKey_fp)}
      i2d_RSAPrivateKey_fp := FC_i2d_RSAPrivateKey_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_RSAPrivateKey_fp_removed)}
    if i2d_RSAPrivateKey_fp_removed <= LibVersion then
    begin
      {$if declared(_i2d_RSAPrivateKey_fp)}
      i2d_RSAPrivateKey_fp := _i2d_RSAPrivateKey_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_RSAPrivateKey_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_RSAPrivateKey_fp');
    {$ifend}
  end;
  
  d2i_RSAPublicKey_fp := LoadLibFunction(ADllHandle, d2i_RSAPublicKey_fp_procname);
  FuncLoadError := not assigned(d2i_RSAPublicKey_fp);
  if FuncLoadError then
  begin
    {$if not defined(d2i_RSAPublicKey_fp_allownil)}
    d2i_RSAPublicKey_fp := ERR_d2i_RSAPublicKey_fp;
    {$ifend}
    {$if declared(d2i_RSAPublicKey_fp_introduced)}
    if LibVersion < d2i_RSAPublicKey_fp_introduced then
    begin
      {$if declared(FC_d2i_RSAPublicKey_fp)}
      d2i_RSAPublicKey_fp := FC_d2i_RSAPublicKey_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_RSAPublicKey_fp_removed)}
    if d2i_RSAPublicKey_fp_removed <= LibVersion then
    begin
      {$if declared(_d2i_RSAPublicKey_fp)}
      d2i_RSAPublicKey_fp := _d2i_RSAPublicKey_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_RSAPublicKey_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_RSAPublicKey_fp');
    {$ifend}
  end;
  
  i2d_RSAPublicKey_fp := LoadLibFunction(ADllHandle, i2d_RSAPublicKey_fp_procname);
  FuncLoadError := not assigned(i2d_RSAPublicKey_fp);
  if FuncLoadError then
  begin
    {$if not defined(i2d_RSAPublicKey_fp_allownil)}
    i2d_RSAPublicKey_fp := ERR_i2d_RSAPublicKey_fp;
    {$ifend}
    {$if declared(i2d_RSAPublicKey_fp_introduced)}
    if LibVersion < i2d_RSAPublicKey_fp_introduced then
    begin
      {$if declared(FC_i2d_RSAPublicKey_fp)}
      i2d_RSAPublicKey_fp := FC_i2d_RSAPublicKey_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_RSAPublicKey_fp_removed)}
    if i2d_RSAPublicKey_fp_removed <= LibVersion then
    begin
      {$if declared(_i2d_RSAPublicKey_fp)}
      i2d_RSAPublicKey_fp := _i2d_RSAPublicKey_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_RSAPublicKey_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_RSAPublicKey_fp');
    {$ifend}
  end;
  
  d2i_RSA_PUBKEY_fp := LoadLibFunction(ADllHandle, d2i_RSA_PUBKEY_fp_procname);
  FuncLoadError := not assigned(d2i_RSA_PUBKEY_fp);
  if FuncLoadError then
  begin
    {$if not defined(d2i_RSA_PUBKEY_fp_allownil)}
    d2i_RSA_PUBKEY_fp := ERR_d2i_RSA_PUBKEY_fp;
    {$ifend}
    {$if declared(d2i_RSA_PUBKEY_fp_introduced)}
    if LibVersion < d2i_RSA_PUBKEY_fp_introduced then
    begin
      {$if declared(FC_d2i_RSA_PUBKEY_fp)}
      d2i_RSA_PUBKEY_fp := FC_d2i_RSA_PUBKEY_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_RSA_PUBKEY_fp_removed)}
    if d2i_RSA_PUBKEY_fp_removed <= LibVersion then
    begin
      {$if declared(_d2i_RSA_PUBKEY_fp)}
      d2i_RSA_PUBKEY_fp := _d2i_RSA_PUBKEY_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_RSA_PUBKEY_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_RSA_PUBKEY_fp');
    {$ifend}
  end;
  
  i2d_RSA_PUBKEY_fp := LoadLibFunction(ADllHandle, i2d_RSA_PUBKEY_fp_procname);
  FuncLoadError := not assigned(i2d_RSA_PUBKEY_fp);
  if FuncLoadError then
  begin
    {$if not defined(i2d_RSA_PUBKEY_fp_allownil)}
    i2d_RSA_PUBKEY_fp := ERR_i2d_RSA_PUBKEY_fp;
    {$ifend}
    {$if declared(i2d_RSA_PUBKEY_fp_introduced)}
    if LibVersion < i2d_RSA_PUBKEY_fp_introduced then
    begin
      {$if declared(FC_i2d_RSA_PUBKEY_fp)}
      i2d_RSA_PUBKEY_fp := FC_i2d_RSA_PUBKEY_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_RSA_PUBKEY_fp_removed)}
    if i2d_RSA_PUBKEY_fp_removed <= LibVersion then
    begin
      {$if declared(_i2d_RSA_PUBKEY_fp)}
      i2d_RSA_PUBKEY_fp := _i2d_RSA_PUBKEY_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_RSA_PUBKEY_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_RSA_PUBKEY_fp');
    {$ifend}
  end;
  
  d2i_DSA_PUBKEY_fp := LoadLibFunction(ADllHandle, d2i_DSA_PUBKEY_fp_procname);
  FuncLoadError := not assigned(d2i_DSA_PUBKEY_fp);
  if FuncLoadError then
  begin
    {$if not defined(d2i_DSA_PUBKEY_fp_allownil)}
    d2i_DSA_PUBKEY_fp := ERR_d2i_DSA_PUBKEY_fp;
    {$ifend}
    {$if declared(d2i_DSA_PUBKEY_fp_introduced)}
    if LibVersion < d2i_DSA_PUBKEY_fp_introduced then
    begin
      {$if declared(FC_d2i_DSA_PUBKEY_fp)}
      d2i_DSA_PUBKEY_fp := FC_d2i_DSA_PUBKEY_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_DSA_PUBKEY_fp_removed)}
    if d2i_DSA_PUBKEY_fp_removed <= LibVersion then
    begin
      {$if declared(_d2i_DSA_PUBKEY_fp)}
      d2i_DSA_PUBKEY_fp := _d2i_DSA_PUBKEY_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_DSA_PUBKEY_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_DSA_PUBKEY_fp');
    {$ifend}
  end;
  
  i2d_DSA_PUBKEY_fp := LoadLibFunction(ADllHandle, i2d_DSA_PUBKEY_fp_procname);
  FuncLoadError := not assigned(i2d_DSA_PUBKEY_fp);
  if FuncLoadError then
  begin
    {$if not defined(i2d_DSA_PUBKEY_fp_allownil)}
    i2d_DSA_PUBKEY_fp := ERR_i2d_DSA_PUBKEY_fp;
    {$ifend}
    {$if declared(i2d_DSA_PUBKEY_fp_introduced)}
    if LibVersion < i2d_DSA_PUBKEY_fp_introduced then
    begin
      {$if declared(FC_i2d_DSA_PUBKEY_fp)}
      i2d_DSA_PUBKEY_fp := FC_i2d_DSA_PUBKEY_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_DSA_PUBKEY_fp_removed)}
    if i2d_DSA_PUBKEY_fp_removed <= LibVersion then
    begin
      {$if declared(_i2d_DSA_PUBKEY_fp)}
      i2d_DSA_PUBKEY_fp := _i2d_DSA_PUBKEY_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_DSA_PUBKEY_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_DSA_PUBKEY_fp');
    {$ifend}
  end;
  
  d2i_DSAPrivateKey_fp := LoadLibFunction(ADllHandle, d2i_DSAPrivateKey_fp_procname);
  FuncLoadError := not assigned(d2i_DSAPrivateKey_fp);
  if FuncLoadError then
  begin
    {$if not defined(d2i_DSAPrivateKey_fp_allownil)}
    d2i_DSAPrivateKey_fp := ERR_d2i_DSAPrivateKey_fp;
    {$ifend}
    {$if declared(d2i_DSAPrivateKey_fp_introduced)}
    if LibVersion < d2i_DSAPrivateKey_fp_introduced then
    begin
      {$if declared(FC_d2i_DSAPrivateKey_fp)}
      d2i_DSAPrivateKey_fp := FC_d2i_DSAPrivateKey_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_DSAPrivateKey_fp_removed)}
    if d2i_DSAPrivateKey_fp_removed <= LibVersion then
    begin
      {$if declared(_d2i_DSAPrivateKey_fp)}
      d2i_DSAPrivateKey_fp := _d2i_DSAPrivateKey_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_DSAPrivateKey_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_DSAPrivateKey_fp');
    {$ifend}
  end;
  
  i2d_DSAPrivateKey_fp := LoadLibFunction(ADllHandle, i2d_DSAPrivateKey_fp_procname);
  FuncLoadError := not assigned(i2d_DSAPrivateKey_fp);
  if FuncLoadError then
  begin
    {$if not defined(i2d_DSAPrivateKey_fp_allownil)}
    i2d_DSAPrivateKey_fp := ERR_i2d_DSAPrivateKey_fp;
    {$ifend}
    {$if declared(i2d_DSAPrivateKey_fp_introduced)}
    if LibVersion < i2d_DSAPrivateKey_fp_introduced then
    begin
      {$if declared(FC_i2d_DSAPrivateKey_fp)}
      i2d_DSAPrivateKey_fp := FC_i2d_DSAPrivateKey_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_DSAPrivateKey_fp_removed)}
    if i2d_DSAPrivateKey_fp_removed <= LibVersion then
    begin
      {$if declared(_i2d_DSAPrivateKey_fp)}
      i2d_DSAPrivateKey_fp := _i2d_DSAPrivateKey_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_DSAPrivateKey_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_DSAPrivateKey_fp');
    {$ifend}
  end;
  
  d2i_EC_PUBKEY_fp := LoadLibFunction(ADllHandle, d2i_EC_PUBKEY_fp_procname);
  FuncLoadError := not assigned(d2i_EC_PUBKEY_fp);
  if FuncLoadError then
  begin
    {$if not defined(d2i_EC_PUBKEY_fp_allownil)}
    d2i_EC_PUBKEY_fp := ERR_d2i_EC_PUBKEY_fp;
    {$ifend}
    {$if declared(d2i_EC_PUBKEY_fp_introduced)}
    if LibVersion < d2i_EC_PUBKEY_fp_introduced then
    begin
      {$if declared(FC_d2i_EC_PUBKEY_fp)}
      d2i_EC_PUBKEY_fp := FC_d2i_EC_PUBKEY_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_EC_PUBKEY_fp_removed)}
    if d2i_EC_PUBKEY_fp_removed <= LibVersion then
    begin
      {$if declared(_d2i_EC_PUBKEY_fp)}
      d2i_EC_PUBKEY_fp := _d2i_EC_PUBKEY_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_EC_PUBKEY_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_EC_PUBKEY_fp');
    {$ifend}
  end;
  
  i2d_EC_PUBKEY_fp := LoadLibFunction(ADllHandle, i2d_EC_PUBKEY_fp_procname);
  FuncLoadError := not assigned(i2d_EC_PUBKEY_fp);
  if FuncLoadError then
  begin
    {$if not defined(i2d_EC_PUBKEY_fp_allownil)}
    i2d_EC_PUBKEY_fp := ERR_i2d_EC_PUBKEY_fp;
    {$ifend}
    {$if declared(i2d_EC_PUBKEY_fp_introduced)}
    if LibVersion < i2d_EC_PUBKEY_fp_introduced then
    begin
      {$if declared(FC_i2d_EC_PUBKEY_fp)}
      i2d_EC_PUBKEY_fp := FC_i2d_EC_PUBKEY_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_EC_PUBKEY_fp_removed)}
    if i2d_EC_PUBKEY_fp_removed <= LibVersion then
    begin
      {$if declared(_i2d_EC_PUBKEY_fp)}
      i2d_EC_PUBKEY_fp := _i2d_EC_PUBKEY_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_EC_PUBKEY_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_EC_PUBKEY_fp');
    {$ifend}
  end;
  
  d2i_ECPrivateKey_fp := LoadLibFunction(ADllHandle, d2i_ECPrivateKey_fp_procname);
  FuncLoadError := not assigned(d2i_ECPrivateKey_fp);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ECPrivateKey_fp_allownil)}
    d2i_ECPrivateKey_fp := ERR_d2i_ECPrivateKey_fp;
    {$ifend}
    {$if declared(d2i_ECPrivateKey_fp_introduced)}
    if LibVersion < d2i_ECPrivateKey_fp_introduced then
    begin
      {$if declared(FC_d2i_ECPrivateKey_fp)}
      d2i_ECPrivateKey_fp := FC_d2i_ECPrivateKey_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ECPrivateKey_fp_removed)}
    if d2i_ECPrivateKey_fp_removed <= LibVersion then
    begin
      {$if declared(_d2i_ECPrivateKey_fp)}
      d2i_ECPrivateKey_fp := _d2i_ECPrivateKey_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ECPrivateKey_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ECPrivateKey_fp');
    {$ifend}
  end;
  
  i2d_ECPrivateKey_fp := LoadLibFunction(ADllHandle, i2d_ECPrivateKey_fp_procname);
  FuncLoadError := not assigned(i2d_ECPrivateKey_fp);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ECPrivateKey_fp_allownil)}
    i2d_ECPrivateKey_fp := ERR_i2d_ECPrivateKey_fp;
    {$ifend}
    {$if declared(i2d_ECPrivateKey_fp_introduced)}
    if LibVersion < i2d_ECPrivateKey_fp_introduced then
    begin
      {$if declared(FC_i2d_ECPrivateKey_fp)}
      i2d_ECPrivateKey_fp := FC_i2d_ECPrivateKey_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ECPrivateKey_fp_removed)}
    if i2d_ECPrivateKey_fp_removed <= LibVersion then
    begin
      {$if declared(_i2d_ECPrivateKey_fp)}
      i2d_ECPrivateKey_fp := _i2d_ECPrivateKey_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ECPrivateKey_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ECPrivateKey_fp');
    {$ifend}
  end;
  
  d2i_PKCS8_fp := LoadLibFunction(ADllHandle, d2i_PKCS8_fp_procname);
  FuncLoadError := not assigned(d2i_PKCS8_fp);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS8_fp_allownil)}
    d2i_PKCS8_fp := ERR_d2i_PKCS8_fp;
    {$ifend}
    {$if declared(d2i_PKCS8_fp_introduced)}
    if LibVersion < d2i_PKCS8_fp_introduced then
    begin
      {$if declared(FC_d2i_PKCS8_fp)}
      d2i_PKCS8_fp := FC_d2i_PKCS8_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS8_fp_removed)}
    if d2i_PKCS8_fp_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS8_fp)}
      d2i_PKCS8_fp := _d2i_PKCS8_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS8_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS8_fp');
    {$ifend}
  end;
  
  i2d_PKCS8_fp := LoadLibFunction(ADllHandle, i2d_PKCS8_fp_procname);
  FuncLoadError := not assigned(i2d_PKCS8_fp);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS8_fp_allownil)}
    i2d_PKCS8_fp := ERR_i2d_PKCS8_fp;
    {$ifend}
    {$if declared(i2d_PKCS8_fp_introduced)}
    if LibVersion < i2d_PKCS8_fp_introduced then
    begin
      {$if declared(FC_i2d_PKCS8_fp)}
      i2d_PKCS8_fp := FC_i2d_PKCS8_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS8_fp_removed)}
    if i2d_PKCS8_fp_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS8_fp)}
      i2d_PKCS8_fp := _i2d_PKCS8_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS8_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS8_fp');
    {$ifend}
  end;
  
  d2i_X509_PUBKEY_fp := LoadLibFunction(ADllHandle, d2i_X509_PUBKEY_fp_procname);
  FuncLoadError := not assigned(d2i_X509_PUBKEY_fp);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_PUBKEY_fp_allownil)}
    d2i_X509_PUBKEY_fp := ERR_d2i_X509_PUBKEY_fp;
    {$ifend}
    {$if declared(d2i_X509_PUBKEY_fp_introduced)}
    if LibVersion < d2i_X509_PUBKEY_fp_introduced then
    begin
      {$if declared(FC_d2i_X509_PUBKEY_fp)}
      d2i_X509_PUBKEY_fp := FC_d2i_X509_PUBKEY_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_PUBKEY_fp_removed)}
    if d2i_X509_PUBKEY_fp_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_PUBKEY_fp)}
      d2i_X509_PUBKEY_fp := _d2i_X509_PUBKEY_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_PUBKEY_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_PUBKEY_fp');
    {$ifend}
  end;
  
  i2d_X509_PUBKEY_fp := LoadLibFunction(ADllHandle, i2d_X509_PUBKEY_fp_procname);
  FuncLoadError := not assigned(i2d_X509_PUBKEY_fp);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_PUBKEY_fp_allownil)}
    i2d_X509_PUBKEY_fp := ERR_i2d_X509_PUBKEY_fp;
    {$ifend}
    {$if declared(i2d_X509_PUBKEY_fp_introduced)}
    if LibVersion < i2d_X509_PUBKEY_fp_introduced then
    begin
      {$if declared(FC_i2d_X509_PUBKEY_fp)}
      i2d_X509_PUBKEY_fp := FC_i2d_X509_PUBKEY_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_PUBKEY_fp_removed)}
    if i2d_X509_PUBKEY_fp_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_PUBKEY_fp)}
      i2d_X509_PUBKEY_fp := _i2d_X509_PUBKEY_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_PUBKEY_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_PUBKEY_fp');
    {$ifend}
  end;
  
  d2i_PKCS8_PRIV_KEY_INFO_fp := LoadLibFunction(ADllHandle, d2i_PKCS8_PRIV_KEY_INFO_fp_procname);
  FuncLoadError := not assigned(d2i_PKCS8_PRIV_KEY_INFO_fp);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS8_PRIV_KEY_INFO_fp_allownil)}
    d2i_PKCS8_PRIV_KEY_INFO_fp := ERR_d2i_PKCS8_PRIV_KEY_INFO_fp;
    {$ifend}
    {$if declared(d2i_PKCS8_PRIV_KEY_INFO_fp_introduced)}
    if LibVersion < d2i_PKCS8_PRIV_KEY_INFO_fp_introduced then
    begin
      {$if declared(FC_d2i_PKCS8_PRIV_KEY_INFO_fp)}
      d2i_PKCS8_PRIV_KEY_INFO_fp := FC_d2i_PKCS8_PRIV_KEY_INFO_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS8_PRIV_KEY_INFO_fp_removed)}
    if d2i_PKCS8_PRIV_KEY_INFO_fp_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS8_PRIV_KEY_INFO_fp)}
      d2i_PKCS8_PRIV_KEY_INFO_fp := _d2i_PKCS8_PRIV_KEY_INFO_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS8_PRIV_KEY_INFO_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS8_PRIV_KEY_INFO_fp');
    {$ifend}
  end;
  
  i2d_PKCS8_PRIV_KEY_INFO_fp := LoadLibFunction(ADllHandle, i2d_PKCS8_PRIV_KEY_INFO_fp_procname);
  FuncLoadError := not assigned(i2d_PKCS8_PRIV_KEY_INFO_fp);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS8_PRIV_KEY_INFO_fp_allownil)}
    i2d_PKCS8_PRIV_KEY_INFO_fp := ERR_i2d_PKCS8_PRIV_KEY_INFO_fp;
    {$ifend}
    {$if declared(i2d_PKCS8_PRIV_KEY_INFO_fp_introduced)}
    if LibVersion < i2d_PKCS8_PRIV_KEY_INFO_fp_introduced then
    begin
      {$if declared(FC_i2d_PKCS8_PRIV_KEY_INFO_fp)}
      i2d_PKCS8_PRIV_KEY_INFO_fp := FC_i2d_PKCS8_PRIV_KEY_INFO_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS8_PRIV_KEY_INFO_fp_removed)}
    if i2d_PKCS8_PRIV_KEY_INFO_fp_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS8_PRIV_KEY_INFO_fp)}
      i2d_PKCS8_PRIV_KEY_INFO_fp := _i2d_PKCS8_PRIV_KEY_INFO_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS8_PRIV_KEY_INFO_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS8_PRIV_KEY_INFO_fp');
    {$ifend}
  end;
  
  i2d_PKCS8PrivateKeyInfo_fp := LoadLibFunction(ADllHandle, i2d_PKCS8PrivateKeyInfo_fp_procname);
  FuncLoadError := not assigned(i2d_PKCS8PrivateKeyInfo_fp);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS8PrivateKeyInfo_fp_allownil)}
    i2d_PKCS8PrivateKeyInfo_fp := ERR_i2d_PKCS8PrivateKeyInfo_fp;
    {$ifend}
    {$if declared(i2d_PKCS8PrivateKeyInfo_fp_introduced)}
    if LibVersion < i2d_PKCS8PrivateKeyInfo_fp_introduced then
    begin
      {$if declared(FC_i2d_PKCS8PrivateKeyInfo_fp)}
      i2d_PKCS8PrivateKeyInfo_fp := FC_i2d_PKCS8PrivateKeyInfo_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS8PrivateKeyInfo_fp_removed)}
    if i2d_PKCS8PrivateKeyInfo_fp_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS8PrivateKeyInfo_fp)}
      i2d_PKCS8PrivateKeyInfo_fp := _i2d_PKCS8PrivateKeyInfo_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS8PrivateKeyInfo_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS8PrivateKeyInfo_fp');
    {$ifend}
  end;
  
  i2d_PrivateKey_fp := LoadLibFunction(ADllHandle, i2d_PrivateKey_fp_procname);
  FuncLoadError := not assigned(i2d_PrivateKey_fp);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PrivateKey_fp_allownil)}
    i2d_PrivateKey_fp := ERR_i2d_PrivateKey_fp;
    {$ifend}
    {$if declared(i2d_PrivateKey_fp_introduced)}
    if LibVersion < i2d_PrivateKey_fp_introduced then
    begin
      {$if declared(FC_i2d_PrivateKey_fp)}
      i2d_PrivateKey_fp := FC_i2d_PrivateKey_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PrivateKey_fp_removed)}
    if i2d_PrivateKey_fp_removed <= LibVersion then
    begin
      {$if declared(_i2d_PrivateKey_fp)}
      i2d_PrivateKey_fp := _i2d_PrivateKey_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PrivateKey_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PrivateKey_fp');
    {$ifend}
  end;
  
  d2i_PrivateKey_ex_fp := LoadLibFunction(ADllHandle, d2i_PrivateKey_ex_fp_procname);
  FuncLoadError := not assigned(d2i_PrivateKey_ex_fp);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PrivateKey_ex_fp_allownil)}
    d2i_PrivateKey_ex_fp := ERR_d2i_PrivateKey_ex_fp;
    {$ifend}
    {$if declared(d2i_PrivateKey_ex_fp_introduced)}
    if LibVersion < d2i_PrivateKey_ex_fp_introduced then
    begin
      {$if declared(FC_d2i_PrivateKey_ex_fp)}
      d2i_PrivateKey_ex_fp := FC_d2i_PrivateKey_ex_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PrivateKey_ex_fp_removed)}
    if d2i_PrivateKey_ex_fp_removed <= LibVersion then
    begin
      {$if declared(_d2i_PrivateKey_ex_fp)}
      d2i_PrivateKey_ex_fp := _d2i_PrivateKey_ex_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PrivateKey_ex_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PrivateKey_ex_fp');
    {$ifend}
  end;
  
  d2i_PrivateKey_fp := LoadLibFunction(ADllHandle, d2i_PrivateKey_fp_procname);
  FuncLoadError := not assigned(d2i_PrivateKey_fp);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PrivateKey_fp_allownil)}
    d2i_PrivateKey_fp := ERR_d2i_PrivateKey_fp;
    {$ifend}
    {$if declared(d2i_PrivateKey_fp_introduced)}
    if LibVersion < d2i_PrivateKey_fp_introduced then
    begin
      {$if declared(FC_d2i_PrivateKey_fp)}
      d2i_PrivateKey_fp := FC_d2i_PrivateKey_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PrivateKey_fp_removed)}
    if d2i_PrivateKey_fp_removed <= LibVersion then
    begin
      {$if declared(_d2i_PrivateKey_fp)}
      d2i_PrivateKey_fp := _d2i_PrivateKey_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PrivateKey_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PrivateKey_fp');
    {$ifend}
  end;
  
  i2d_PUBKEY_fp := LoadLibFunction(ADllHandle, i2d_PUBKEY_fp_procname);
  FuncLoadError := not assigned(i2d_PUBKEY_fp);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PUBKEY_fp_allownil)}
    i2d_PUBKEY_fp := ERR_i2d_PUBKEY_fp;
    {$ifend}
    {$if declared(i2d_PUBKEY_fp_introduced)}
    if LibVersion < i2d_PUBKEY_fp_introduced then
    begin
      {$if declared(FC_i2d_PUBKEY_fp)}
      i2d_PUBKEY_fp := FC_i2d_PUBKEY_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PUBKEY_fp_removed)}
    if i2d_PUBKEY_fp_removed <= LibVersion then
    begin
      {$if declared(_i2d_PUBKEY_fp)}
      i2d_PUBKEY_fp := _i2d_PUBKEY_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PUBKEY_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PUBKEY_fp');
    {$ifend}
  end;
  
  d2i_PUBKEY_ex_fp := LoadLibFunction(ADllHandle, d2i_PUBKEY_ex_fp_procname);
  FuncLoadError := not assigned(d2i_PUBKEY_ex_fp);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PUBKEY_ex_fp_allownil)}
    d2i_PUBKEY_ex_fp := ERR_d2i_PUBKEY_ex_fp;
    {$ifend}
    {$if declared(d2i_PUBKEY_ex_fp_introduced)}
    if LibVersion < d2i_PUBKEY_ex_fp_introduced then
    begin
      {$if declared(FC_d2i_PUBKEY_ex_fp)}
      d2i_PUBKEY_ex_fp := FC_d2i_PUBKEY_ex_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PUBKEY_ex_fp_removed)}
    if d2i_PUBKEY_ex_fp_removed <= LibVersion then
    begin
      {$if declared(_d2i_PUBKEY_ex_fp)}
      d2i_PUBKEY_ex_fp := _d2i_PUBKEY_ex_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PUBKEY_ex_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PUBKEY_ex_fp');
    {$ifend}
  end;
  
  d2i_PUBKEY_fp := LoadLibFunction(ADllHandle, d2i_PUBKEY_fp_procname);
  FuncLoadError := not assigned(d2i_PUBKEY_fp);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PUBKEY_fp_allownil)}
    d2i_PUBKEY_fp := ERR_d2i_PUBKEY_fp;
    {$ifend}
    {$if declared(d2i_PUBKEY_fp_introduced)}
    if LibVersion < d2i_PUBKEY_fp_introduced then
    begin
      {$if declared(FC_d2i_PUBKEY_fp)}
      d2i_PUBKEY_fp := FC_d2i_PUBKEY_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PUBKEY_fp_removed)}
    if d2i_PUBKEY_fp_removed <= LibVersion then
    begin
      {$if declared(_d2i_PUBKEY_fp)}
      d2i_PUBKEY_fp := _d2i_PUBKEY_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PUBKEY_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PUBKEY_fp');
    {$ifend}
  end;
  
  d2i_X509_bio := LoadLibFunction(ADllHandle, d2i_X509_bio_procname);
  FuncLoadError := not assigned(d2i_X509_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_bio_allownil)}
    d2i_X509_bio := ERR_d2i_X509_bio;
    {$ifend}
    {$if declared(d2i_X509_bio_introduced)}
    if LibVersion < d2i_X509_bio_introduced then
    begin
      {$if declared(FC_d2i_X509_bio)}
      d2i_X509_bio := FC_d2i_X509_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_bio_removed)}
    if d2i_X509_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_bio)}
      d2i_X509_bio := _d2i_X509_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_bio');
    {$ifend}
  end;
  
  i2d_X509_bio := LoadLibFunction(ADllHandle, i2d_X509_bio_procname);
  FuncLoadError := not assigned(i2d_X509_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_bio_allownil)}
    i2d_X509_bio := ERR_i2d_X509_bio;
    {$ifend}
    {$if declared(i2d_X509_bio_introduced)}
    if LibVersion < i2d_X509_bio_introduced then
    begin
      {$if declared(FC_i2d_X509_bio)}
      i2d_X509_bio := FC_i2d_X509_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_bio_removed)}
    if i2d_X509_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_bio)}
      i2d_X509_bio := _i2d_X509_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_bio');
    {$ifend}
  end;
  
  d2i_X509_CRL_bio := LoadLibFunction(ADllHandle, d2i_X509_CRL_bio_procname);
  FuncLoadError := not assigned(d2i_X509_CRL_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_CRL_bio_allownil)}
    d2i_X509_CRL_bio := ERR_d2i_X509_CRL_bio;
    {$ifend}
    {$if declared(d2i_X509_CRL_bio_introduced)}
    if LibVersion < d2i_X509_CRL_bio_introduced then
    begin
      {$if declared(FC_d2i_X509_CRL_bio)}
      d2i_X509_CRL_bio := FC_d2i_X509_CRL_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_CRL_bio_removed)}
    if d2i_X509_CRL_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_CRL_bio)}
      d2i_X509_CRL_bio := _d2i_X509_CRL_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_CRL_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_CRL_bio');
    {$ifend}
  end;
  
  i2d_X509_CRL_bio := LoadLibFunction(ADllHandle, i2d_X509_CRL_bio_procname);
  FuncLoadError := not assigned(i2d_X509_CRL_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_CRL_bio_allownil)}
    i2d_X509_CRL_bio := ERR_i2d_X509_CRL_bio;
    {$ifend}
    {$if declared(i2d_X509_CRL_bio_introduced)}
    if LibVersion < i2d_X509_CRL_bio_introduced then
    begin
      {$if declared(FC_i2d_X509_CRL_bio)}
      i2d_X509_CRL_bio := FC_i2d_X509_CRL_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_CRL_bio_removed)}
    if i2d_X509_CRL_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_CRL_bio)}
      i2d_X509_CRL_bio := _i2d_X509_CRL_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_CRL_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_CRL_bio');
    {$ifend}
  end;
  
  d2i_X509_REQ_bio := LoadLibFunction(ADllHandle, d2i_X509_REQ_bio_procname);
  FuncLoadError := not assigned(d2i_X509_REQ_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_REQ_bio_allownil)}
    d2i_X509_REQ_bio := ERR_d2i_X509_REQ_bio;
    {$ifend}
    {$if declared(d2i_X509_REQ_bio_introduced)}
    if LibVersion < d2i_X509_REQ_bio_introduced then
    begin
      {$if declared(FC_d2i_X509_REQ_bio)}
      d2i_X509_REQ_bio := FC_d2i_X509_REQ_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_REQ_bio_removed)}
    if d2i_X509_REQ_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_REQ_bio)}
      d2i_X509_REQ_bio := _d2i_X509_REQ_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_REQ_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_REQ_bio');
    {$ifend}
  end;
  
  i2d_X509_REQ_bio := LoadLibFunction(ADllHandle, i2d_X509_REQ_bio_procname);
  FuncLoadError := not assigned(i2d_X509_REQ_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_REQ_bio_allownil)}
    i2d_X509_REQ_bio := ERR_i2d_X509_REQ_bio;
    {$ifend}
    {$if declared(i2d_X509_REQ_bio_introduced)}
    if LibVersion < i2d_X509_REQ_bio_introduced then
    begin
      {$if declared(FC_i2d_X509_REQ_bio)}
      i2d_X509_REQ_bio := FC_i2d_X509_REQ_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_REQ_bio_removed)}
    if i2d_X509_REQ_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_REQ_bio)}
      i2d_X509_REQ_bio := _i2d_X509_REQ_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_REQ_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_REQ_bio');
    {$ifend}
  end;
  
  d2i_RSAPrivateKey_bio := LoadLibFunction(ADllHandle, d2i_RSAPrivateKey_bio_procname);
  FuncLoadError := not assigned(d2i_RSAPrivateKey_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_RSAPrivateKey_bio_allownil)}
    d2i_RSAPrivateKey_bio := ERR_d2i_RSAPrivateKey_bio;
    {$ifend}
    {$if declared(d2i_RSAPrivateKey_bio_introduced)}
    if LibVersion < d2i_RSAPrivateKey_bio_introduced then
    begin
      {$if declared(FC_d2i_RSAPrivateKey_bio)}
      d2i_RSAPrivateKey_bio := FC_d2i_RSAPrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_RSAPrivateKey_bio_removed)}
    if d2i_RSAPrivateKey_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_RSAPrivateKey_bio)}
      d2i_RSAPrivateKey_bio := _d2i_RSAPrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_RSAPrivateKey_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_RSAPrivateKey_bio');
    {$ifend}
  end;
  
  i2d_RSAPrivateKey_bio := LoadLibFunction(ADllHandle, i2d_RSAPrivateKey_bio_procname);
  FuncLoadError := not assigned(i2d_RSAPrivateKey_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_RSAPrivateKey_bio_allownil)}
    i2d_RSAPrivateKey_bio := ERR_i2d_RSAPrivateKey_bio;
    {$ifend}
    {$if declared(i2d_RSAPrivateKey_bio_introduced)}
    if LibVersion < i2d_RSAPrivateKey_bio_introduced then
    begin
      {$if declared(FC_i2d_RSAPrivateKey_bio)}
      i2d_RSAPrivateKey_bio := FC_i2d_RSAPrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_RSAPrivateKey_bio_removed)}
    if i2d_RSAPrivateKey_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_RSAPrivateKey_bio)}
      i2d_RSAPrivateKey_bio := _i2d_RSAPrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_RSAPrivateKey_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_RSAPrivateKey_bio');
    {$ifend}
  end;
  
  d2i_RSAPublicKey_bio := LoadLibFunction(ADllHandle, d2i_RSAPublicKey_bio_procname);
  FuncLoadError := not assigned(d2i_RSAPublicKey_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_RSAPublicKey_bio_allownil)}
    d2i_RSAPublicKey_bio := ERR_d2i_RSAPublicKey_bio;
    {$ifend}
    {$if declared(d2i_RSAPublicKey_bio_introduced)}
    if LibVersion < d2i_RSAPublicKey_bio_introduced then
    begin
      {$if declared(FC_d2i_RSAPublicKey_bio)}
      d2i_RSAPublicKey_bio := FC_d2i_RSAPublicKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_RSAPublicKey_bio_removed)}
    if d2i_RSAPublicKey_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_RSAPublicKey_bio)}
      d2i_RSAPublicKey_bio := _d2i_RSAPublicKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_RSAPublicKey_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_RSAPublicKey_bio');
    {$ifend}
  end;
  
  i2d_RSAPublicKey_bio := LoadLibFunction(ADllHandle, i2d_RSAPublicKey_bio_procname);
  FuncLoadError := not assigned(i2d_RSAPublicKey_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_RSAPublicKey_bio_allownil)}
    i2d_RSAPublicKey_bio := ERR_i2d_RSAPublicKey_bio;
    {$ifend}
    {$if declared(i2d_RSAPublicKey_bio_introduced)}
    if LibVersion < i2d_RSAPublicKey_bio_introduced then
    begin
      {$if declared(FC_i2d_RSAPublicKey_bio)}
      i2d_RSAPublicKey_bio := FC_i2d_RSAPublicKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_RSAPublicKey_bio_removed)}
    if i2d_RSAPublicKey_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_RSAPublicKey_bio)}
      i2d_RSAPublicKey_bio := _i2d_RSAPublicKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_RSAPublicKey_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_RSAPublicKey_bio');
    {$ifend}
  end;
  
  d2i_RSA_PUBKEY_bio := LoadLibFunction(ADllHandle, d2i_RSA_PUBKEY_bio_procname);
  FuncLoadError := not assigned(d2i_RSA_PUBKEY_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_RSA_PUBKEY_bio_allownil)}
    d2i_RSA_PUBKEY_bio := ERR_d2i_RSA_PUBKEY_bio;
    {$ifend}
    {$if declared(d2i_RSA_PUBKEY_bio_introduced)}
    if LibVersion < d2i_RSA_PUBKEY_bio_introduced then
    begin
      {$if declared(FC_d2i_RSA_PUBKEY_bio)}
      d2i_RSA_PUBKEY_bio := FC_d2i_RSA_PUBKEY_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_RSA_PUBKEY_bio_removed)}
    if d2i_RSA_PUBKEY_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_RSA_PUBKEY_bio)}
      d2i_RSA_PUBKEY_bio := _d2i_RSA_PUBKEY_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_RSA_PUBKEY_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_RSA_PUBKEY_bio');
    {$ifend}
  end;
  
  i2d_RSA_PUBKEY_bio := LoadLibFunction(ADllHandle, i2d_RSA_PUBKEY_bio_procname);
  FuncLoadError := not assigned(i2d_RSA_PUBKEY_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_RSA_PUBKEY_bio_allownil)}
    i2d_RSA_PUBKEY_bio := ERR_i2d_RSA_PUBKEY_bio;
    {$ifend}
    {$if declared(i2d_RSA_PUBKEY_bio_introduced)}
    if LibVersion < i2d_RSA_PUBKEY_bio_introduced then
    begin
      {$if declared(FC_i2d_RSA_PUBKEY_bio)}
      i2d_RSA_PUBKEY_bio := FC_i2d_RSA_PUBKEY_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_RSA_PUBKEY_bio_removed)}
    if i2d_RSA_PUBKEY_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_RSA_PUBKEY_bio)}
      i2d_RSA_PUBKEY_bio := _i2d_RSA_PUBKEY_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_RSA_PUBKEY_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_RSA_PUBKEY_bio');
    {$ifend}
  end;
  
  d2i_DSA_PUBKEY_bio := LoadLibFunction(ADllHandle, d2i_DSA_PUBKEY_bio_procname);
  FuncLoadError := not assigned(d2i_DSA_PUBKEY_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_DSA_PUBKEY_bio_allownil)}
    d2i_DSA_PUBKEY_bio := ERR_d2i_DSA_PUBKEY_bio;
    {$ifend}
    {$if declared(d2i_DSA_PUBKEY_bio_introduced)}
    if LibVersion < d2i_DSA_PUBKEY_bio_introduced then
    begin
      {$if declared(FC_d2i_DSA_PUBKEY_bio)}
      d2i_DSA_PUBKEY_bio := FC_d2i_DSA_PUBKEY_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_DSA_PUBKEY_bio_removed)}
    if d2i_DSA_PUBKEY_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_DSA_PUBKEY_bio)}
      d2i_DSA_PUBKEY_bio := _d2i_DSA_PUBKEY_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_DSA_PUBKEY_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_DSA_PUBKEY_bio');
    {$ifend}
  end;
  
  i2d_DSA_PUBKEY_bio := LoadLibFunction(ADllHandle, i2d_DSA_PUBKEY_bio_procname);
  FuncLoadError := not assigned(i2d_DSA_PUBKEY_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_DSA_PUBKEY_bio_allownil)}
    i2d_DSA_PUBKEY_bio := ERR_i2d_DSA_PUBKEY_bio;
    {$ifend}
    {$if declared(i2d_DSA_PUBKEY_bio_introduced)}
    if LibVersion < i2d_DSA_PUBKEY_bio_introduced then
    begin
      {$if declared(FC_i2d_DSA_PUBKEY_bio)}
      i2d_DSA_PUBKEY_bio := FC_i2d_DSA_PUBKEY_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_DSA_PUBKEY_bio_removed)}
    if i2d_DSA_PUBKEY_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_DSA_PUBKEY_bio)}
      i2d_DSA_PUBKEY_bio := _i2d_DSA_PUBKEY_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_DSA_PUBKEY_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_DSA_PUBKEY_bio');
    {$ifend}
  end;
  
  d2i_DSAPrivateKey_bio := LoadLibFunction(ADllHandle, d2i_DSAPrivateKey_bio_procname);
  FuncLoadError := not assigned(d2i_DSAPrivateKey_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_DSAPrivateKey_bio_allownil)}
    d2i_DSAPrivateKey_bio := ERR_d2i_DSAPrivateKey_bio;
    {$ifend}
    {$if declared(d2i_DSAPrivateKey_bio_introduced)}
    if LibVersion < d2i_DSAPrivateKey_bio_introduced then
    begin
      {$if declared(FC_d2i_DSAPrivateKey_bio)}
      d2i_DSAPrivateKey_bio := FC_d2i_DSAPrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_DSAPrivateKey_bio_removed)}
    if d2i_DSAPrivateKey_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_DSAPrivateKey_bio)}
      d2i_DSAPrivateKey_bio := _d2i_DSAPrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_DSAPrivateKey_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_DSAPrivateKey_bio');
    {$ifend}
  end;
  
  i2d_DSAPrivateKey_bio := LoadLibFunction(ADllHandle, i2d_DSAPrivateKey_bio_procname);
  FuncLoadError := not assigned(i2d_DSAPrivateKey_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_DSAPrivateKey_bio_allownil)}
    i2d_DSAPrivateKey_bio := ERR_i2d_DSAPrivateKey_bio;
    {$ifend}
    {$if declared(i2d_DSAPrivateKey_bio_introduced)}
    if LibVersion < i2d_DSAPrivateKey_bio_introduced then
    begin
      {$if declared(FC_i2d_DSAPrivateKey_bio)}
      i2d_DSAPrivateKey_bio := FC_i2d_DSAPrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_DSAPrivateKey_bio_removed)}
    if i2d_DSAPrivateKey_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_DSAPrivateKey_bio)}
      i2d_DSAPrivateKey_bio := _i2d_DSAPrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_DSAPrivateKey_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_DSAPrivateKey_bio');
    {$ifend}
  end;
  
  d2i_EC_PUBKEY_bio := LoadLibFunction(ADllHandle, d2i_EC_PUBKEY_bio_procname);
  FuncLoadError := not assigned(d2i_EC_PUBKEY_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_EC_PUBKEY_bio_allownil)}
    d2i_EC_PUBKEY_bio := ERR_d2i_EC_PUBKEY_bio;
    {$ifend}
    {$if declared(d2i_EC_PUBKEY_bio_introduced)}
    if LibVersion < d2i_EC_PUBKEY_bio_introduced then
    begin
      {$if declared(FC_d2i_EC_PUBKEY_bio)}
      d2i_EC_PUBKEY_bio := FC_d2i_EC_PUBKEY_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_EC_PUBKEY_bio_removed)}
    if d2i_EC_PUBKEY_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_EC_PUBKEY_bio)}
      d2i_EC_PUBKEY_bio := _d2i_EC_PUBKEY_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_EC_PUBKEY_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_EC_PUBKEY_bio');
    {$ifend}
  end;
  
  i2d_EC_PUBKEY_bio := LoadLibFunction(ADllHandle, i2d_EC_PUBKEY_bio_procname);
  FuncLoadError := not assigned(i2d_EC_PUBKEY_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_EC_PUBKEY_bio_allownil)}
    i2d_EC_PUBKEY_bio := ERR_i2d_EC_PUBKEY_bio;
    {$ifend}
    {$if declared(i2d_EC_PUBKEY_bio_introduced)}
    if LibVersion < i2d_EC_PUBKEY_bio_introduced then
    begin
      {$if declared(FC_i2d_EC_PUBKEY_bio)}
      i2d_EC_PUBKEY_bio := FC_i2d_EC_PUBKEY_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_EC_PUBKEY_bio_removed)}
    if i2d_EC_PUBKEY_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_EC_PUBKEY_bio)}
      i2d_EC_PUBKEY_bio := _i2d_EC_PUBKEY_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_EC_PUBKEY_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_EC_PUBKEY_bio');
    {$ifend}
  end;
  
  d2i_ECPrivateKey_bio := LoadLibFunction(ADllHandle, d2i_ECPrivateKey_bio_procname);
  FuncLoadError := not assigned(d2i_ECPrivateKey_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_ECPrivateKey_bio_allownil)}
    d2i_ECPrivateKey_bio := ERR_d2i_ECPrivateKey_bio;
    {$ifend}
    {$if declared(d2i_ECPrivateKey_bio_introduced)}
    if LibVersion < d2i_ECPrivateKey_bio_introduced then
    begin
      {$if declared(FC_d2i_ECPrivateKey_bio)}
      d2i_ECPrivateKey_bio := FC_d2i_ECPrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_ECPrivateKey_bio_removed)}
    if d2i_ECPrivateKey_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_ECPrivateKey_bio)}
      d2i_ECPrivateKey_bio := _d2i_ECPrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_ECPrivateKey_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_ECPrivateKey_bio');
    {$ifend}
  end;
  
  i2d_ECPrivateKey_bio := LoadLibFunction(ADllHandle, i2d_ECPrivateKey_bio_procname);
  FuncLoadError := not assigned(i2d_ECPrivateKey_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_ECPrivateKey_bio_allownil)}
    i2d_ECPrivateKey_bio := ERR_i2d_ECPrivateKey_bio;
    {$ifend}
    {$if declared(i2d_ECPrivateKey_bio_introduced)}
    if LibVersion < i2d_ECPrivateKey_bio_introduced then
    begin
      {$if declared(FC_i2d_ECPrivateKey_bio)}
      i2d_ECPrivateKey_bio := FC_i2d_ECPrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_ECPrivateKey_bio_removed)}
    if i2d_ECPrivateKey_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_ECPrivateKey_bio)}
      i2d_ECPrivateKey_bio := _i2d_ECPrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_ECPrivateKey_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_ECPrivateKey_bio');
    {$ifend}
  end;
  
  d2i_PKCS8_bio := LoadLibFunction(ADllHandle, d2i_PKCS8_bio_procname);
  FuncLoadError := not assigned(d2i_PKCS8_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS8_bio_allownil)}
    d2i_PKCS8_bio := ERR_d2i_PKCS8_bio;
    {$ifend}
    {$if declared(d2i_PKCS8_bio_introduced)}
    if LibVersion < d2i_PKCS8_bio_introduced then
    begin
      {$if declared(FC_d2i_PKCS8_bio)}
      d2i_PKCS8_bio := FC_d2i_PKCS8_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS8_bio_removed)}
    if d2i_PKCS8_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS8_bio)}
      d2i_PKCS8_bio := _d2i_PKCS8_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS8_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS8_bio');
    {$ifend}
  end;
  
  i2d_PKCS8_bio := LoadLibFunction(ADllHandle, i2d_PKCS8_bio_procname);
  FuncLoadError := not assigned(i2d_PKCS8_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS8_bio_allownil)}
    i2d_PKCS8_bio := ERR_i2d_PKCS8_bio;
    {$ifend}
    {$if declared(i2d_PKCS8_bio_introduced)}
    if LibVersion < i2d_PKCS8_bio_introduced then
    begin
      {$if declared(FC_i2d_PKCS8_bio)}
      i2d_PKCS8_bio := FC_i2d_PKCS8_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS8_bio_removed)}
    if i2d_PKCS8_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS8_bio)}
      i2d_PKCS8_bio := _i2d_PKCS8_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS8_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS8_bio');
    {$ifend}
  end;
  
  d2i_X509_PUBKEY_bio := LoadLibFunction(ADllHandle, d2i_X509_PUBKEY_bio_procname);
  FuncLoadError := not assigned(d2i_X509_PUBKEY_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_PUBKEY_bio_allownil)}
    d2i_X509_PUBKEY_bio := ERR_d2i_X509_PUBKEY_bio;
    {$ifend}
    {$if declared(d2i_X509_PUBKEY_bio_introduced)}
    if LibVersion < d2i_X509_PUBKEY_bio_introduced then
    begin
      {$if declared(FC_d2i_X509_PUBKEY_bio)}
      d2i_X509_PUBKEY_bio := FC_d2i_X509_PUBKEY_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_PUBKEY_bio_removed)}
    if d2i_X509_PUBKEY_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_PUBKEY_bio)}
      d2i_X509_PUBKEY_bio := _d2i_X509_PUBKEY_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_PUBKEY_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_PUBKEY_bio');
    {$ifend}
  end;
  
  i2d_X509_PUBKEY_bio := LoadLibFunction(ADllHandle, i2d_X509_PUBKEY_bio_procname);
  FuncLoadError := not assigned(i2d_X509_PUBKEY_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_PUBKEY_bio_allownil)}
    i2d_X509_PUBKEY_bio := ERR_i2d_X509_PUBKEY_bio;
    {$ifend}
    {$if declared(i2d_X509_PUBKEY_bio_introduced)}
    if LibVersion < i2d_X509_PUBKEY_bio_introduced then
    begin
      {$if declared(FC_i2d_X509_PUBKEY_bio)}
      i2d_X509_PUBKEY_bio := FC_i2d_X509_PUBKEY_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_PUBKEY_bio_removed)}
    if i2d_X509_PUBKEY_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_PUBKEY_bio)}
      i2d_X509_PUBKEY_bio := _i2d_X509_PUBKEY_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_PUBKEY_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_PUBKEY_bio');
    {$ifend}
  end;
  
  d2i_PKCS8_PRIV_KEY_INFO_bio := LoadLibFunction(ADllHandle, d2i_PKCS8_PRIV_KEY_INFO_bio_procname);
  FuncLoadError := not assigned(d2i_PKCS8_PRIV_KEY_INFO_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS8_PRIV_KEY_INFO_bio_allownil)}
    d2i_PKCS8_PRIV_KEY_INFO_bio := ERR_d2i_PKCS8_PRIV_KEY_INFO_bio;
    {$ifend}
    {$if declared(d2i_PKCS8_PRIV_KEY_INFO_bio_introduced)}
    if LibVersion < d2i_PKCS8_PRIV_KEY_INFO_bio_introduced then
    begin
      {$if declared(FC_d2i_PKCS8_PRIV_KEY_INFO_bio)}
      d2i_PKCS8_PRIV_KEY_INFO_bio := FC_d2i_PKCS8_PRIV_KEY_INFO_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS8_PRIV_KEY_INFO_bio_removed)}
    if d2i_PKCS8_PRIV_KEY_INFO_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS8_PRIV_KEY_INFO_bio)}
      d2i_PKCS8_PRIV_KEY_INFO_bio := _d2i_PKCS8_PRIV_KEY_INFO_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS8_PRIV_KEY_INFO_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS8_PRIV_KEY_INFO_bio');
    {$ifend}
  end;
  
  i2d_PKCS8_PRIV_KEY_INFO_bio := LoadLibFunction(ADllHandle, i2d_PKCS8_PRIV_KEY_INFO_bio_procname);
  FuncLoadError := not assigned(i2d_PKCS8_PRIV_KEY_INFO_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS8_PRIV_KEY_INFO_bio_allownil)}
    i2d_PKCS8_PRIV_KEY_INFO_bio := ERR_i2d_PKCS8_PRIV_KEY_INFO_bio;
    {$ifend}
    {$if declared(i2d_PKCS8_PRIV_KEY_INFO_bio_introduced)}
    if LibVersion < i2d_PKCS8_PRIV_KEY_INFO_bio_introduced then
    begin
      {$if declared(FC_i2d_PKCS8_PRIV_KEY_INFO_bio)}
      i2d_PKCS8_PRIV_KEY_INFO_bio := FC_i2d_PKCS8_PRIV_KEY_INFO_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS8_PRIV_KEY_INFO_bio_removed)}
    if i2d_PKCS8_PRIV_KEY_INFO_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS8_PRIV_KEY_INFO_bio)}
      i2d_PKCS8_PRIV_KEY_INFO_bio := _i2d_PKCS8_PRIV_KEY_INFO_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS8_PRIV_KEY_INFO_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS8_PRIV_KEY_INFO_bio');
    {$ifend}
  end;
  
  i2d_PKCS8PrivateKeyInfo_bio := LoadLibFunction(ADllHandle, i2d_PKCS8PrivateKeyInfo_bio_procname);
  FuncLoadError := not assigned(i2d_PKCS8PrivateKeyInfo_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS8PrivateKeyInfo_bio_allownil)}
    i2d_PKCS8PrivateKeyInfo_bio := ERR_i2d_PKCS8PrivateKeyInfo_bio;
    {$ifend}
    {$if declared(i2d_PKCS8PrivateKeyInfo_bio_introduced)}
    if LibVersion < i2d_PKCS8PrivateKeyInfo_bio_introduced then
    begin
      {$if declared(FC_i2d_PKCS8PrivateKeyInfo_bio)}
      i2d_PKCS8PrivateKeyInfo_bio := FC_i2d_PKCS8PrivateKeyInfo_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS8PrivateKeyInfo_bio_removed)}
    if i2d_PKCS8PrivateKeyInfo_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS8PrivateKeyInfo_bio)}
      i2d_PKCS8PrivateKeyInfo_bio := _i2d_PKCS8PrivateKeyInfo_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS8PrivateKeyInfo_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS8PrivateKeyInfo_bio');
    {$ifend}
  end;
  
  i2d_PrivateKey_bio := LoadLibFunction(ADllHandle, i2d_PrivateKey_bio_procname);
  FuncLoadError := not assigned(i2d_PrivateKey_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PrivateKey_bio_allownil)}
    i2d_PrivateKey_bio := ERR_i2d_PrivateKey_bio;
    {$ifend}
    {$if declared(i2d_PrivateKey_bio_introduced)}
    if LibVersion < i2d_PrivateKey_bio_introduced then
    begin
      {$if declared(FC_i2d_PrivateKey_bio)}
      i2d_PrivateKey_bio := FC_i2d_PrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PrivateKey_bio_removed)}
    if i2d_PrivateKey_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_PrivateKey_bio)}
      i2d_PrivateKey_bio := _i2d_PrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PrivateKey_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PrivateKey_bio');
    {$ifend}
  end;
  
  d2i_PrivateKey_ex_bio := LoadLibFunction(ADllHandle, d2i_PrivateKey_ex_bio_procname);
  FuncLoadError := not assigned(d2i_PrivateKey_ex_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PrivateKey_ex_bio_allownil)}
    d2i_PrivateKey_ex_bio := ERR_d2i_PrivateKey_ex_bio;
    {$ifend}
    {$if declared(d2i_PrivateKey_ex_bio_introduced)}
    if LibVersion < d2i_PrivateKey_ex_bio_introduced then
    begin
      {$if declared(FC_d2i_PrivateKey_ex_bio)}
      d2i_PrivateKey_ex_bio := FC_d2i_PrivateKey_ex_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PrivateKey_ex_bio_removed)}
    if d2i_PrivateKey_ex_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_PrivateKey_ex_bio)}
      d2i_PrivateKey_ex_bio := _d2i_PrivateKey_ex_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PrivateKey_ex_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PrivateKey_ex_bio');
    {$ifend}
  end;
  
  d2i_PrivateKey_bio := LoadLibFunction(ADllHandle, d2i_PrivateKey_bio_procname);
  FuncLoadError := not assigned(d2i_PrivateKey_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PrivateKey_bio_allownil)}
    d2i_PrivateKey_bio := ERR_d2i_PrivateKey_bio;
    {$ifend}
    {$if declared(d2i_PrivateKey_bio_introduced)}
    if LibVersion < d2i_PrivateKey_bio_introduced then
    begin
      {$if declared(FC_d2i_PrivateKey_bio)}
      d2i_PrivateKey_bio := FC_d2i_PrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PrivateKey_bio_removed)}
    if d2i_PrivateKey_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_PrivateKey_bio)}
      d2i_PrivateKey_bio := _d2i_PrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PrivateKey_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PrivateKey_bio');
    {$ifend}
  end;
  
  i2d_PUBKEY_bio := LoadLibFunction(ADllHandle, i2d_PUBKEY_bio_procname);
  FuncLoadError := not assigned(i2d_PUBKEY_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PUBKEY_bio_allownil)}
    i2d_PUBKEY_bio := ERR_i2d_PUBKEY_bio;
    {$ifend}
    {$if declared(i2d_PUBKEY_bio_introduced)}
    if LibVersion < i2d_PUBKEY_bio_introduced then
    begin
      {$if declared(FC_i2d_PUBKEY_bio)}
      i2d_PUBKEY_bio := FC_i2d_PUBKEY_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PUBKEY_bio_removed)}
    if i2d_PUBKEY_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_PUBKEY_bio)}
      i2d_PUBKEY_bio := _i2d_PUBKEY_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PUBKEY_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PUBKEY_bio');
    {$ifend}
  end;
  
  d2i_PUBKEY_ex_bio := LoadLibFunction(ADllHandle, d2i_PUBKEY_ex_bio_procname);
  FuncLoadError := not assigned(d2i_PUBKEY_ex_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PUBKEY_ex_bio_allownil)}
    d2i_PUBKEY_ex_bio := ERR_d2i_PUBKEY_ex_bio;
    {$ifend}
    {$if declared(d2i_PUBKEY_ex_bio_introduced)}
    if LibVersion < d2i_PUBKEY_ex_bio_introduced then
    begin
      {$if declared(FC_d2i_PUBKEY_ex_bio)}
      d2i_PUBKEY_ex_bio := FC_d2i_PUBKEY_ex_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PUBKEY_ex_bio_removed)}
    if d2i_PUBKEY_ex_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_PUBKEY_ex_bio)}
      d2i_PUBKEY_ex_bio := _d2i_PUBKEY_ex_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PUBKEY_ex_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PUBKEY_ex_bio');
    {$ifend}
  end;
  
  d2i_PUBKEY_bio := LoadLibFunction(ADllHandle, d2i_PUBKEY_bio_procname);
  FuncLoadError := not assigned(d2i_PUBKEY_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PUBKEY_bio_allownil)}
    d2i_PUBKEY_bio := ERR_d2i_PUBKEY_bio;
    {$ifend}
    {$if declared(d2i_PUBKEY_bio_introduced)}
    if LibVersion < d2i_PUBKEY_bio_introduced then
    begin
      {$if declared(FC_d2i_PUBKEY_bio)}
      d2i_PUBKEY_bio := FC_d2i_PUBKEY_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PUBKEY_bio_removed)}
    if d2i_PUBKEY_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_PUBKEY_bio)}
      d2i_PUBKEY_bio := _d2i_PUBKEY_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PUBKEY_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PUBKEY_bio');
    {$ifend}
  end;
  
  X509_dup := LoadLibFunction(ADllHandle, X509_dup_procname);
  FuncLoadError := not assigned(X509_dup);
  if FuncLoadError then
  begin
    {$if not defined(X509_dup_allownil)}
    X509_dup := ERR_X509_dup;
    {$ifend}
    {$if declared(X509_dup_introduced)}
    if LibVersion < X509_dup_introduced then
    begin
      {$if declared(FC_X509_dup)}
      X509_dup := FC_X509_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_dup_removed)}
    if X509_dup_removed <= LibVersion then
    begin
      {$if declared(_X509_dup)}
      X509_dup := _X509_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_dup');
    {$ifend}
  end;
  
  X509_ALGOR_dup := LoadLibFunction(ADllHandle, X509_ALGOR_dup_procname);
  FuncLoadError := not assigned(X509_ALGOR_dup);
  if FuncLoadError then
  begin
    {$if not defined(X509_ALGOR_dup_allownil)}
    X509_ALGOR_dup := ERR_X509_ALGOR_dup;
    {$ifend}
    {$if declared(X509_ALGOR_dup_introduced)}
    if LibVersion < X509_ALGOR_dup_introduced then
    begin
      {$if declared(FC_X509_ALGOR_dup)}
      X509_ALGOR_dup := FC_X509_ALGOR_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ALGOR_dup_removed)}
    if X509_ALGOR_dup_removed <= LibVersion then
    begin
      {$if declared(_X509_ALGOR_dup)}
      X509_ALGOR_dup := _X509_ALGOR_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ALGOR_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ALGOR_dup');
    {$ifend}
  end;
  
  X509_ATTRIBUTE_dup := LoadLibFunction(ADllHandle, X509_ATTRIBUTE_dup_procname);
  FuncLoadError := not assigned(X509_ATTRIBUTE_dup);
  if FuncLoadError then
  begin
    {$if not defined(X509_ATTRIBUTE_dup_allownil)}
    X509_ATTRIBUTE_dup := ERR_X509_ATTRIBUTE_dup;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_dup_introduced)}
    if LibVersion < X509_ATTRIBUTE_dup_introduced then
    begin
      {$if declared(FC_X509_ATTRIBUTE_dup)}
      X509_ATTRIBUTE_dup := FC_X509_ATTRIBUTE_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_dup_removed)}
    if X509_ATTRIBUTE_dup_removed <= LibVersion then
    begin
      {$if declared(_X509_ATTRIBUTE_dup)}
      X509_ATTRIBUTE_dup := _X509_ATTRIBUTE_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ATTRIBUTE_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ATTRIBUTE_dup');
    {$ifend}
  end;
  
  X509_CRL_dup := LoadLibFunction(ADllHandle, X509_CRL_dup_procname);
  FuncLoadError := not assigned(X509_CRL_dup);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_dup_allownil)}
    X509_CRL_dup := ERR_X509_CRL_dup;
    {$ifend}
    {$if declared(X509_CRL_dup_introduced)}
    if LibVersion < X509_CRL_dup_introduced then
    begin
      {$if declared(FC_X509_CRL_dup)}
      X509_CRL_dup := FC_X509_CRL_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_dup_removed)}
    if X509_CRL_dup_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_dup)}
      X509_CRL_dup := _X509_CRL_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_dup');
    {$ifend}
  end;
  
  X509_EXTENSION_dup := LoadLibFunction(ADllHandle, X509_EXTENSION_dup_procname);
  FuncLoadError := not assigned(X509_EXTENSION_dup);
  if FuncLoadError then
  begin
    {$if not defined(X509_EXTENSION_dup_allownil)}
    X509_EXTENSION_dup := ERR_X509_EXTENSION_dup;
    {$ifend}
    {$if declared(X509_EXTENSION_dup_introduced)}
    if LibVersion < X509_EXTENSION_dup_introduced then
    begin
      {$if declared(FC_X509_EXTENSION_dup)}
      X509_EXTENSION_dup := FC_X509_EXTENSION_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_EXTENSION_dup_removed)}
    if X509_EXTENSION_dup_removed <= LibVersion then
    begin
      {$if declared(_X509_EXTENSION_dup)}
      X509_EXTENSION_dup := _X509_EXTENSION_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_EXTENSION_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_EXTENSION_dup');
    {$ifend}
  end;
  
  X509_PUBKEY_dup := LoadLibFunction(ADllHandle, X509_PUBKEY_dup_procname);
  FuncLoadError := not assigned(X509_PUBKEY_dup);
  if FuncLoadError then
  begin
    {$if not defined(X509_PUBKEY_dup_allownil)}
    X509_PUBKEY_dup := ERR_X509_PUBKEY_dup;
    {$ifend}
    {$if declared(X509_PUBKEY_dup_introduced)}
    if LibVersion < X509_PUBKEY_dup_introduced then
    begin
      {$if declared(FC_X509_PUBKEY_dup)}
      X509_PUBKEY_dup := FC_X509_PUBKEY_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PUBKEY_dup_removed)}
    if X509_PUBKEY_dup_removed <= LibVersion then
    begin
      {$if declared(_X509_PUBKEY_dup)}
      X509_PUBKEY_dup := _X509_PUBKEY_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PUBKEY_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PUBKEY_dup');
    {$ifend}
  end;
  
  X509_REQ_dup := LoadLibFunction(ADllHandle, X509_REQ_dup_procname);
  FuncLoadError := not assigned(X509_REQ_dup);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_dup_allownil)}
    X509_REQ_dup := ERR_X509_REQ_dup;
    {$ifend}
    {$if declared(X509_REQ_dup_introduced)}
    if LibVersion < X509_REQ_dup_introduced then
    begin
      {$if declared(FC_X509_REQ_dup)}
      X509_REQ_dup := FC_X509_REQ_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_dup_removed)}
    if X509_REQ_dup_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_dup)}
      X509_REQ_dup := _X509_REQ_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_dup');
    {$ifend}
  end;
  
  X509_REVOKED_dup := LoadLibFunction(ADllHandle, X509_REVOKED_dup_procname);
  FuncLoadError := not assigned(X509_REVOKED_dup);
  if FuncLoadError then
  begin
    {$if not defined(X509_REVOKED_dup_allownil)}
    X509_REVOKED_dup := ERR_X509_REVOKED_dup;
    {$ifend}
    {$if declared(X509_REVOKED_dup_introduced)}
    if LibVersion < X509_REVOKED_dup_introduced then
    begin
      {$if declared(FC_X509_REVOKED_dup)}
      X509_REVOKED_dup := FC_X509_REVOKED_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REVOKED_dup_removed)}
    if X509_REVOKED_dup_removed <= LibVersion then
    begin
      {$if declared(_X509_REVOKED_dup)}
      X509_REVOKED_dup := _X509_REVOKED_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REVOKED_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REVOKED_dup');
    {$ifend}
  end;
  
  X509_ALGOR_set0 := LoadLibFunction(ADllHandle, X509_ALGOR_set0_procname);
  FuncLoadError := not assigned(X509_ALGOR_set0);
  if FuncLoadError then
  begin
    {$if not defined(X509_ALGOR_set0_allownil)}
    X509_ALGOR_set0 := ERR_X509_ALGOR_set0;
    {$ifend}
    {$if declared(X509_ALGOR_set0_introduced)}
    if LibVersion < X509_ALGOR_set0_introduced then
    begin
      {$if declared(FC_X509_ALGOR_set0)}
      X509_ALGOR_set0 := FC_X509_ALGOR_set0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ALGOR_set0_removed)}
    if X509_ALGOR_set0_removed <= LibVersion then
    begin
      {$if declared(_X509_ALGOR_set0)}
      X509_ALGOR_set0 := _X509_ALGOR_set0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ALGOR_set0_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ALGOR_set0');
    {$ifend}
  end;
  
  X509_ALGOR_get0 := LoadLibFunction(ADllHandle, X509_ALGOR_get0_procname);
  FuncLoadError := not assigned(X509_ALGOR_get0);
  if FuncLoadError then
  begin
    {$if not defined(X509_ALGOR_get0_allownil)}
    X509_ALGOR_get0 := ERR_X509_ALGOR_get0;
    {$ifend}
    {$if declared(X509_ALGOR_get0_introduced)}
    if LibVersion < X509_ALGOR_get0_introduced then
    begin
      {$if declared(FC_X509_ALGOR_get0)}
      X509_ALGOR_get0 := FC_X509_ALGOR_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ALGOR_get0_removed)}
    if X509_ALGOR_get0_removed <= LibVersion then
    begin
      {$if declared(_X509_ALGOR_get0)}
      X509_ALGOR_get0 := _X509_ALGOR_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ALGOR_get0_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ALGOR_get0');
    {$ifend}
  end;
  
  X509_ALGOR_set_md := LoadLibFunction(ADllHandle, X509_ALGOR_set_md_procname);
  FuncLoadError := not assigned(X509_ALGOR_set_md);
  if FuncLoadError then
  begin
    {$if not defined(X509_ALGOR_set_md_allownil)}
    X509_ALGOR_set_md := ERR_X509_ALGOR_set_md;
    {$ifend}
    {$if declared(X509_ALGOR_set_md_introduced)}
    if LibVersion < X509_ALGOR_set_md_introduced then
    begin
      {$if declared(FC_X509_ALGOR_set_md)}
      X509_ALGOR_set_md := FC_X509_ALGOR_set_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ALGOR_set_md_removed)}
    if X509_ALGOR_set_md_removed <= LibVersion then
    begin
      {$if declared(_X509_ALGOR_set_md)}
      X509_ALGOR_set_md := _X509_ALGOR_set_md;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ALGOR_set_md_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ALGOR_set_md');
    {$ifend}
  end;
  
  X509_ALGOR_cmp := LoadLibFunction(ADllHandle, X509_ALGOR_cmp_procname);
  FuncLoadError := not assigned(X509_ALGOR_cmp);
  if FuncLoadError then
  begin
    {$if not defined(X509_ALGOR_cmp_allownil)}
    X509_ALGOR_cmp := ERR_X509_ALGOR_cmp;
    {$ifend}
    {$if declared(X509_ALGOR_cmp_introduced)}
    if LibVersion < X509_ALGOR_cmp_introduced then
    begin
      {$if declared(FC_X509_ALGOR_cmp)}
      X509_ALGOR_cmp := FC_X509_ALGOR_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ALGOR_cmp_removed)}
    if X509_ALGOR_cmp_removed <= LibVersion then
    begin
      {$if declared(_X509_ALGOR_cmp)}
      X509_ALGOR_cmp := _X509_ALGOR_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ALGOR_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ALGOR_cmp');
    {$ifend}
  end;
  
  X509_ALGOR_copy := LoadLibFunction(ADllHandle, X509_ALGOR_copy_procname);
  FuncLoadError := not assigned(X509_ALGOR_copy);
  if FuncLoadError then
  begin
    {$if not defined(X509_ALGOR_copy_allownil)}
    X509_ALGOR_copy := ERR_X509_ALGOR_copy;
    {$ifend}
    {$if declared(X509_ALGOR_copy_introduced)}
    if LibVersion < X509_ALGOR_copy_introduced then
    begin
      {$if declared(FC_X509_ALGOR_copy)}
      X509_ALGOR_copy := FC_X509_ALGOR_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ALGOR_copy_removed)}
    if X509_ALGOR_copy_removed <= LibVersion then
    begin
      {$if declared(_X509_ALGOR_copy)}
      X509_ALGOR_copy := _X509_ALGOR_copy;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ALGOR_copy_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ALGOR_copy');
    {$ifend}
  end;
  
  X509_NAME_dup := LoadLibFunction(ADllHandle, X509_NAME_dup_procname);
  FuncLoadError := not assigned(X509_NAME_dup);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_dup_allownil)}
    X509_NAME_dup := ERR_X509_NAME_dup;
    {$ifend}
    {$if declared(X509_NAME_dup_introduced)}
    if LibVersion < X509_NAME_dup_introduced then
    begin
      {$if declared(FC_X509_NAME_dup)}
      X509_NAME_dup := FC_X509_NAME_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_dup_removed)}
    if X509_NAME_dup_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_dup)}
      X509_NAME_dup := _X509_NAME_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_dup');
    {$ifend}
  end;
  
  X509_NAME_ENTRY_dup := LoadLibFunction(ADllHandle, X509_NAME_ENTRY_dup_procname);
  FuncLoadError := not assigned(X509_NAME_ENTRY_dup);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_ENTRY_dup_allownil)}
    X509_NAME_ENTRY_dup := ERR_X509_NAME_ENTRY_dup;
    {$ifend}
    {$if declared(X509_NAME_ENTRY_dup_introduced)}
    if LibVersion < X509_NAME_ENTRY_dup_introduced then
    begin
      {$if declared(FC_X509_NAME_ENTRY_dup)}
      X509_NAME_ENTRY_dup := FC_X509_NAME_ENTRY_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_ENTRY_dup_removed)}
    if X509_NAME_ENTRY_dup_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_ENTRY_dup)}
      X509_NAME_ENTRY_dup := _X509_NAME_ENTRY_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_ENTRY_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_ENTRY_dup');
    {$ifend}
  end;
  
  X509_cmp_time := LoadLibFunction(ADllHandle, X509_cmp_time_procname);
  FuncLoadError := not assigned(X509_cmp_time);
  if FuncLoadError then
  begin
    {$if not defined(X509_cmp_time_allownil)}
    X509_cmp_time := ERR_X509_cmp_time;
    {$ifend}
    {$if declared(X509_cmp_time_introduced)}
    if LibVersion < X509_cmp_time_introduced then
    begin
      {$if declared(FC_X509_cmp_time)}
      X509_cmp_time := FC_X509_cmp_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_cmp_time_removed)}
    if X509_cmp_time_removed <= LibVersion then
    begin
      {$if declared(_X509_cmp_time)}
      X509_cmp_time := _X509_cmp_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_cmp_time_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_cmp_time');
    {$ifend}
  end;
  
  X509_cmp_current_time := LoadLibFunction(ADllHandle, X509_cmp_current_time_procname);
  FuncLoadError := not assigned(X509_cmp_current_time);
  if FuncLoadError then
  begin
    {$if not defined(X509_cmp_current_time_allownil)}
    X509_cmp_current_time := ERR_X509_cmp_current_time;
    {$ifend}
    {$if declared(X509_cmp_current_time_introduced)}
    if LibVersion < X509_cmp_current_time_introduced then
    begin
      {$if declared(FC_X509_cmp_current_time)}
      X509_cmp_current_time := FC_X509_cmp_current_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_cmp_current_time_removed)}
    if X509_cmp_current_time_removed <= LibVersion then
    begin
      {$if declared(_X509_cmp_current_time)}
      X509_cmp_current_time := _X509_cmp_current_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_cmp_current_time_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_cmp_current_time');
    {$ifend}
  end;
  
  X509_cmp_timeframe := LoadLibFunction(ADllHandle, X509_cmp_timeframe_procname);
  FuncLoadError := not assigned(X509_cmp_timeframe);
  if FuncLoadError then
  begin
    {$if not defined(X509_cmp_timeframe_allownil)}
    X509_cmp_timeframe := ERR_X509_cmp_timeframe;
    {$ifend}
    {$if declared(X509_cmp_timeframe_introduced)}
    if LibVersion < X509_cmp_timeframe_introduced then
    begin
      {$if declared(FC_X509_cmp_timeframe)}
      X509_cmp_timeframe := FC_X509_cmp_timeframe;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_cmp_timeframe_removed)}
    if X509_cmp_timeframe_removed <= LibVersion then
    begin
      {$if declared(_X509_cmp_timeframe)}
      X509_cmp_timeframe := _X509_cmp_timeframe;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_cmp_timeframe_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_cmp_timeframe');
    {$ifend}
  end;
  
  X509_time_adj := LoadLibFunction(ADllHandle, X509_time_adj_procname);
  FuncLoadError := not assigned(X509_time_adj);
  if FuncLoadError then
  begin
    {$if not defined(X509_time_adj_allownil)}
    X509_time_adj := ERR_X509_time_adj;
    {$ifend}
    {$if declared(X509_time_adj_introduced)}
    if LibVersion < X509_time_adj_introduced then
    begin
      {$if declared(FC_X509_time_adj)}
      X509_time_adj := FC_X509_time_adj;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_time_adj_removed)}
    if X509_time_adj_removed <= LibVersion then
    begin
      {$if declared(_X509_time_adj)}
      X509_time_adj := _X509_time_adj;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_time_adj_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_time_adj');
    {$ifend}
  end;
  
  X509_time_adj_ex := LoadLibFunction(ADllHandle, X509_time_adj_ex_procname);
  FuncLoadError := not assigned(X509_time_adj_ex);
  if FuncLoadError then
  begin
    {$if not defined(X509_time_adj_ex_allownil)}
    X509_time_adj_ex := ERR_X509_time_adj_ex;
    {$ifend}
    {$if declared(X509_time_adj_ex_introduced)}
    if LibVersion < X509_time_adj_ex_introduced then
    begin
      {$if declared(FC_X509_time_adj_ex)}
      X509_time_adj_ex := FC_X509_time_adj_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_time_adj_ex_removed)}
    if X509_time_adj_ex_removed <= LibVersion then
    begin
      {$if declared(_X509_time_adj_ex)}
      X509_time_adj_ex := _X509_time_adj_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_time_adj_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_time_adj_ex');
    {$ifend}
  end;
  
  X509_gmtime_adj := LoadLibFunction(ADllHandle, X509_gmtime_adj_procname);
  FuncLoadError := not assigned(X509_gmtime_adj);
  if FuncLoadError then
  begin
    {$if not defined(X509_gmtime_adj_allownil)}
    X509_gmtime_adj := ERR_X509_gmtime_adj;
    {$ifend}
    {$if declared(X509_gmtime_adj_introduced)}
    if LibVersion < X509_gmtime_adj_introduced then
    begin
      {$if declared(FC_X509_gmtime_adj)}
      X509_gmtime_adj := FC_X509_gmtime_adj;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_gmtime_adj_removed)}
    if X509_gmtime_adj_removed <= LibVersion then
    begin
      {$if declared(_X509_gmtime_adj)}
      X509_gmtime_adj := _X509_gmtime_adj;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_gmtime_adj_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_gmtime_adj');
    {$ifend}
  end;
  
  X509_get_default_cert_area := LoadLibFunction(ADllHandle, X509_get_default_cert_area_procname);
  FuncLoadError := not assigned(X509_get_default_cert_area);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_default_cert_area_allownil)}
    X509_get_default_cert_area := ERR_X509_get_default_cert_area;
    {$ifend}
    {$if declared(X509_get_default_cert_area_introduced)}
    if LibVersion < X509_get_default_cert_area_introduced then
    begin
      {$if declared(FC_X509_get_default_cert_area)}
      X509_get_default_cert_area := FC_X509_get_default_cert_area;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_default_cert_area_removed)}
    if X509_get_default_cert_area_removed <= LibVersion then
    begin
      {$if declared(_X509_get_default_cert_area)}
      X509_get_default_cert_area := _X509_get_default_cert_area;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_default_cert_area_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_default_cert_area');
    {$ifend}
  end;
  
  X509_get_default_cert_dir := LoadLibFunction(ADllHandle, X509_get_default_cert_dir_procname);
  FuncLoadError := not assigned(X509_get_default_cert_dir);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_default_cert_dir_allownil)}
    X509_get_default_cert_dir := ERR_X509_get_default_cert_dir;
    {$ifend}
    {$if declared(X509_get_default_cert_dir_introduced)}
    if LibVersion < X509_get_default_cert_dir_introduced then
    begin
      {$if declared(FC_X509_get_default_cert_dir)}
      X509_get_default_cert_dir := FC_X509_get_default_cert_dir;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_default_cert_dir_removed)}
    if X509_get_default_cert_dir_removed <= LibVersion then
    begin
      {$if declared(_X509_get_default_cert_dir)}
      X509_get_default_cert_dir := _X509_get_default_cert_dir;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_default_cert_dir_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_default_cert_dir');
    {$ifend}
  end;
  
  X509_get_default_cert_file := LoadLibFunction(ADllHandle, X509_get_default_cert_file_procname);
  FuncLoadError := not assigned(X509_get_default_cert_file);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_default_cert_file_allownil)}
    X509_get_default_cert_file := ERR_X509_get_default_cert_file;
    {$ifend}
    {$if declared(X509_get_default_cert_file_introduced)}
    if LibVersion < X509_get_default_cert_file_introduced then
    begin
      {$if declared(FC_X509_get_default_cert_file)}
      X509_get_default_cert_file := FC_X509_get_default_cert_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_default_cert_file_removed)}
    if X509_get_default_cert_file_removed <= LibVersion then
    begin
      {$if declared(_X509_get_default_cert_file)}
      X509_get_default_cert_file := _X509_get_default_cert_file;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_default_cert_file_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_default_cert_file');
    {$ifend}
  end;
  
  X509_get_default_cert_dir_env := LoadLibFunction(ADllHandle, X509_get_default_cert_dir_env_procname);
  FuncLoadError := not assigned(X509_get_default_cert_dir_env);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_default_cert_dir_env_allownil)}
    X509_get_default_cert_dir_env := ERR_X509_get_default_cert_dir_env;
    {$ifend}
    {$if declared(X509_get_default_cert_dir_env_introduced)}
    if LibVersion < X509_get_default_cert_dir_env_introduced then
    begin
      {$if declared(FC_X509_get_default_cert_dir_env)}
      X509_get_default_cert_dir_env := FC_X509_get_default_cert_dir_env;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_default_cert_dir_env_removed)}
    if X509_get_default_cert_dir_env_removed <= LibVersion then
    begin
      {$if declared(_X509_get_default_cert_dir_env)}
      X509_get_default_cert_dir_env := _X509_get_default_cert_dir_env;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_default_cert_dir_env_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_default_cert_dir_env');
    {$ifend}
  end;
  
  X509_get_default_cert_file_env := LoadLibFunction(ADllHandle, X509_get_default_cert_file_env_procname);
  FuncLoadError := not assigned(X509_get_default_cert_file_env);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_default_cert_file_env_allownil)}
    X509_get_default_cert_file_env := ERR_X509_get_default_cert_file_env;
    {$ifend}
    {$if declared(X509_get_default_cert_file_env_introduced)}
    if LibVersion < X509_get_default_cert_file_env_introduced then
    begin
      {$if declared(FC_X509_get_default_cert_file_env)}
      X509_get_default_cert_file_env := FC_X509_get_default_cert_file_env;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_default_cert_file_env_removed)}
    if X509_get_default_cert_file_env_removed <= LibVersion then
    begin
      {$if declared(_X509_get_default_cert_file_env)}
      X509_get_default_cert_file_env := _X509_get_default_cert_file_env;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_default_cert_file_env_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_default_cert_file_env');
    {$ifend}
  end;
  
  X509_get_default_private_dir := LoadLibFunction(ADllHandle, X509_get_default_private_dir_procname);
  FuncLoadError := not assigned(X509_get_default_private_dir);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_default_private_dir_allownil)}
    X509_get_default_private_dir := ERR_X509_get_default_private_dir;
    {$ifend}
    {$if declared(X509_get_default_private_dir_introduced)}
    if LibVersion < X509_get_default_private_dir_introduced then
    begin
      {$if declared(FC_X509_get_default_private_dir)}
      X509_get_default_private_dir := FC_X509_get_default_private_dir;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_default_private_dir_removed)}
    if X509_get_default_private_dir_removed <= LibVersion then
    begin
      {$if declared(_X509_get_default_private_dir)}
      X509_get_default_private_dir := _X509_get_default_private_dir;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_default_private_dir_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_default_private_dir');
    {$ifend}
  end;
  
  X509_to_X509_REQ := LoadLibFunction(ADllHandle, X509_to_X509_REQ_procname);
  FuncLoadError := not assigned(X509_to_X509_REQ);
  if FuncLoadError then
  begin
    {$if not defined(X509_to_X509_REQ_allownil)}
    X509_to_X509_REQ := ERR_X509_to_X509_REQ;
    {$ifend}
    {$if declared(X509_to_X509_REQ_introduced)}
    if LibVersion < X509_to_X509_REQ_introduced then
    begin
      {$if declared(FC_X509_to_X509_REQ)}
      X509_to_X509_REQ := FC_X509_to_X509_REQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_to_X509_REQ_removed)}
    if X509_to_X509_REQ_removed <= LibVersion then
    begin
      {$if declared(_X509_to_X509_REQ)}
      X509_to_X509_REQ := _X509_to_X509_REQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_to_X509_REQ_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_to_X509_REQ');
    {$ifend}
  end;
  
  X509_REQ_to_X509 := LoadLibFunction(ADllHandle, X509_REQ_to_X509_procname);
  FuncLoadError := not assigned(X509_REQ_to_X509);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_to_X509_allownil)}
    X509_REQ_to_X509 := ERR_X509_REQ_to_X509;
    {$ifend}
    {$if declared(X509_REQ_to_X509_introduced)}
    if LibVersion < X509_REQ_to_X509_introduced then
    begin
      {$if declared(FC_X509_REQ_to_X509)}
      X509_REQ_to_X509 := FC_X509_REQ_to_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_to_X509_removed)}
    if X509_REQ_to_X509_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_to_X509)}
      X509_REQ_to_X509 := _X509_REQ_to_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_to_X509_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_to_X509');
    {$ifend}
  end;
  
  X509_ALGOR_new := LoadLibFunction(ADllHandle, X509_ALGOR_new_procname);
  FuncLoadError := not assigned(X509_ALGOR_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_ALGOR_new_allownil)}
    X509_ALGOR_new := ERR_X509_ALGOR_new;
    {$ifend}
    {$if declared(X509_ALGOR_new_introduced)}
    if LibVersion < X509_ALGOR_new_introduced then
    begin
      {$if declared(FC_X509_ALGOR_new)}
      X509_ALGOR_new := FC_X509_ALGOR_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ALGOR_new_removed)}
    if X509_ALGOR_new_removed <= LibVersion then
    begin
      {$if declared(_X509_ALGOR_new)}
      X509_ALGOR_new := _X509_ALGOR_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ALGOR_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ALGOR_new');
    {$ifend}
  end;
  
  X509_ALGOR_free := LoadLibFunction(ADllHandle, X509_ALGOR_free_procname);
  FuncLoadError := not assigned(X509_ALGOR_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_ALGOR_free_allownil)}
    X509_ALGOR_free := ERR_X509_ALGOR_free;
    {$ifend}
    {$if declared(X509_ALGOR_free_introduced)}
    if LibVersion < X509_ALGOR_free_introduced then
    begin
      {$if declared(FC_X509_ALGOR_free)}
      X509_ALGOR_free := FC_X509_ALGOR_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ALGOR_free_removed)}
    if X509_ALGOR_free_removed <= LibVersion then
    begin
      {$if declared(_X509_ALGOR_free)}
      X509_ALGOR_free := _X509_ALGOR_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ALGOR_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ALGOR_free');
    {$ifend}
  end;
  
  d2i_X509_ALGOR := LoadLibFunction(ADllHandle, d2i_X509_ALGOR_procname);
  FuncLoadError := not assigned(d2i_X509_ALGOR);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_ALGOR_allownil)}
    d2i_X509_ALGOR := ERR_d2i_X509_ALGOR;
    {$ifend}
    {$if declared(d2i_X509_ALGOR_introduced)}
    if LibVersion < d2i_X509_ALGOR_introduced then
    begin
      {$if declared(FC_d2i_X509_ALGOR)}
      d2i_X509_ALGOR := FC_d2i_X509_ALGOR;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_ALGOR_removed)}
    if d2i_X509_ALGOR_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_ALGOR)}
      d2i_X509_ALGOR := _d2i_X509_ALGOR;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_ALGOR_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_ALGOR');
    {$ifend}
  end;
  
  i2d_X509_ALGOR := LoadLibFunction(ADllHandle, i2d_X509_ALGOR_procname);
  FuncLoadError := not assigned(i2d_X509_ALGOR);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_ALGOR_allownil)}
    i2d_X509_ALGOR := ERR_i2d_X509_ALGOR;
    {$ifend}
    {$if declared(i2d_X509_ALGOR_introduced)}
    if LibVersion < i2d_X509_ALGOR_introduced then
    begin
      {$if declared(FC_i2d_X509_ALGOR)}
      i2d_X509_ALGOR := FC_i2d_X509_ALGOR;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_ALGOR_removed)}
    if i2d_X509_ALGOR_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_ALGOR)}
      i2d_X509_ALGOR := _i2d_X509_ALGOR;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_ALGOR_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_ALGOR');
    {$ifend}
  end;
  
  X509_ALGOR_it := LoadLibFunction(ADllHandle, X509_ALGOR_it_procname);
  FuncLoadError := not assigned(X509_ALGOR_it);
  if FuncLoadError then
  begin
    {$if not defined(X509_ALGOR_it_allownil)}
    X509_ALGOR_it := ERR_X509_ALGOR_it;
    {$ifend}
    {$if declared(X509_ALGOR_it_introduced)}
    if LibVersion < X509_ALGOR_it_introduced then
    begin
      {$if declared(FC_X509_ALGOR_it)}
      X509_ALGOR_it := FC_X509_ALGOR_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ALGOR_it_removed)}
    if X509_ALGOR_it_removed <= LibVersion then
    begin
      {$if declared(_X509_ALGOR_it)}
      X509_ALGOR_it := _X509_ALGOR_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ALGOR_it_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ALGOR_it');
    {$ifend}
  end;
  
  d2i_X509_ALGORS := LoadLibFunction(ADllHandle, d2i_X509_ALGORS_procname);
  FuncLoadError := not assigned(d2i_X509_ALGORS);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_ALGORS_allownil)}
    d2i_X509_ALGORS := ERR_d2i_X509_ALGORS;
    {$ifend}
    {$if declared(d2i_X509_ALGORS_introduced)}
    if LibVersion < d2i_X509_ALGORS_introduced then
    begin
      {$if declared(FC_d2i_X509_ALGORS)}
      d2i_X509_ALGORS := FC_d2i_X509_ALGORS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_ALGORS_removed)}
    if d2i_X509_ALGORS_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_ALGORS)}
      d2i_X509_ALGORS := _d2i_X509_ALGORS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_ALGORS_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_ALGORS');
    {$ifend}
  end;
  
  i2d_X509_ALGORS := LoadLibFunction(ADllHandle, i2d_X509_ALGORS_procname);
  FuncLoadError := not assigned(i2d_X509_ALGORS);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_ALGORS_allownil)}
    i2d_X509_ALGORS := ERR_i2d_X509_ALGORS;
    {$ifend}
    {$if declared(i2d_X509_ALGORS_introduced)}
    if LibVersion < i2d_X509_ALGORS_introduced then
    begin
      {$if declared(FC_i2d_X509_ALGORS)}
      i2d_X509_ALGORS := FC_i2d_X509_ALGORS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_ALGORS_removed)}
    if i2d_X509_ALGORS_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_ALGORS)}
      i2d_X509_ALGORS := _i2d_X509_ALGORS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_ALGORS_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_ALGORS');
    {$ifend}
  end;
  
  X509_ALGORS_it := LoadLibFunction(ADllHandle, X509_ALGORS_it_procname);
  FuncLoadError := not assigned(X509_ALGORS_it);
  if FuncLoadError then
  begin
    {$if not defined(X509_ALGORS_it_allownil)}
    X509_ALGORS_it := ERR_X509_ALGORS_it;
    {$ifend}
    {$if declared(X509_ALGORS_it_introduced)}
    if LibVersion < X509_ALGORS_it_introduced then
    begin
      {$if declared(FC_X509_ALGORS_it)}
      X509_ALGORS_it := FC_X509_ALGORS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ALGORS_it_removed)}
    if X509_ALGORS_it_removed <= LibVersion then
    begin
      {$if declared(_X509_ALGORS_it)}
      X509_ALGORS_it := _X509_ALGORS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ALGORS_it_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ALGORS_it');
    {$ifend}
  end;
  
  X509_VAL_new := LoadLibFunction(ADllHandle, X509_VAL_new_procname);
  FuncLoadError := not assigned(X509_VAL_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_VAL_new_allownil)}
    X509_VAL_new := ERR_X509_VAL_new;
    {$ifend}
    {$if declared(X509_VAL_new_introduced)}
    if LibVersion < X509_VAL_new_introduced then
    begin
      {$if declared(FC_X509_VAL_new)}
      X509_VAL_new := FC_X509_VAL_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VAL_new_removed)}
    if X509_VAL_new_removed <= LibVersion then
    begin
      {$if declared(_X509_VAL_new)}
      X509_VAL_new := _X509_VAL_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VAL_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VAL_new');
    {$ifend}
  end;
  
  X509_VAL_free := LoadLibFunction(ADllHandle, X509_VAL_free_procname);
  FuncLoadError := not assigned(X509_VAL_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_VAL_free_allownil)}
    X509_VAL_free := ERR_X509_VAL_free;
    {$ifend}
    {$if declared(X509_VAL_free_introduced)}
    if LibVersion < X509_VAL_free_introduced then
    begin
      {$if declared(FC_X509_VAL_free)}
      X509_VAL_free := FC_X509_VAL_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VAL_free_removed)}
    if X509_VAL_free_removed <= LibVersion then
    begin
      {$if declared(_X509_VAL_free)}
      X509_VAL_free := _X509_VAL_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VAL_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VAL_free');
    {$ifend}
  end;
  
  d2i_X509_VAL := LoadLibFunction(ADllHandle, d2i_X509_VAL_procname);
  FuncLoadError := not assigned(d2i_X509_VAL);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_VAL_allownil)}
    d2i_X509_VAL := ERR_d2i_X509_VAL;
    {$ifend}
    {$if declared(d2i_X509_VAL_introduced)}
    if LibVersion < d2i_X509_VAL_introduced then
    begin
      {$if declared(FC_d2i_X509_VAL)}
      d2i_X509_VAL := FC_d2i_X509_VAL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_VAL_removed)}
    if d2i_X509_VAL_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_VAL)}
      d2i_X509_VAL := _d2i_X509_VAL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_VAL_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_VAL');
    {$ifend}
  end;
  
  i2d_X509_VAL := LoadLibFunction(ADllHandle, i2d_X509_VAL_procname);
  FuncLoadError := not assigned(i2d_X509_VAL);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_VAL_allownil)}
    i2d_X509_VAL := ERR_i2d_X509_VAL;
    {$ifend}
    {$if declared(i2d_X509_VAL_introduced)}
    if LibVersion < i2d_X509_VAL_introduced then
    begin
      {$if declared(FC_i2d_X509_VAL)}
      i2d_X509_VAL := FC_i2d_X509_VAL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_VAL_removed)}
    if i2d_X509_VAL_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_VAL)}
      i2d_X509_VAL := _i2d_X509_VAL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_VAL_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_VAL');
    {$ifend}
  end;
  
  X509_VAL_it := LoadLibFunction(ADllHandle, X509_VAL_it_procname);
  FuncLoadError := not assigned(X509_VAL_it);
  if FuncLoadError then
  begin
    {$if not defined(X509_VAL_it_allownil)}
    X509_VAL_it := ERR_X509_VAL_it;
    {$ifend}
    {$if declared(X509_VAL_it_introduced)}
    if LibVersion < X509_VAL_it_introduced then
    begin
      {$if declared(FC_X509_VAL_it)}
      X509_VAL_it := FC_X509_VAL_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_VAL_it_removed)}
    if X509_VAL_it_removed <= LibVersion then
    begin
      {$if declared(_X509_VAL_it)}
      X509_VAL_it := _X509_VAL_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_VAL_it_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_VAL_it');
    {$ifend}
  end;
  
  X509_PUBKEY_new := LoadLibFunction(ADllHandle, X509_PUBKEY_new_procname);
  FuncLoadError := not assigned(X509_PUBKEY_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_PUBKEY_new_allownil)}
    X509_PUBKEY_new := ERR_X509_PUBKEY_new;
    {$ifend}
    {$if declared(X509_PUBKEY_new_introduced)}
    if LibVersion < X509_PUBKEY_new_introduced then
    begin
      {$if declared(FC_X509_PUBKEY_new)}
      X509_PUBKEY_new := FC_X509_PUBKEY_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PUBKEY_new_removed)}
    if X509_PUBKEY_new_removed <= LibVersion then
    begin
      {$if declared(_X509_PUBKEY_new)}
      X509_PUBKEY_new := _X509_PUBKEY_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PUBKEY_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PUBKEY_new');
    {$ifend}
  end;
  
  X509_PUBKEY_free := LoadLibFunction(ADllHandle, X509_PUBKEY_free_procname);
  FuncLoadError := not assigned(X509_PUBKEY_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_PUBKEY_free_allownil)}
    X509_PUBKEY_free := ERR_X509_PUBKEY_free;
    {$ifend}
    {$if declared(X509_PUBKEY_free_introduced)}
    if LibVersion < X509_PUBKEY_free_introduced then
    begin
      {$if declared(FC_X509_PUBKEY_free)}
      X509_PUBKEY_free := FC_X509_PUBKEY_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PUBKEY_free_removed)}
    if X509_PUBKEY_free_removed <= LibVersion then
    begin
      {$if declared(_X509_PUBKEY_free)}
      X509_PUBKEY_free := _X509_PUBKEY_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PUBKEY_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PUBKEY_free');
    {$ifend}
  end;
  
  d2i_X509_PUBKEY := LoadLibFunction(ADllHandle, d2i_X509_PUBKEY_procname);
  FuncLoadError := not assigned(d2i_X509_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_PUBKEY_allownil)}
    d2i_X509_PUBKEY := ERR_d2i_X509_PUBKEY;
    {$ifend}
    {$if declared(d2i_X509_PUBKEY_introduced)}
    if LibVersion < d2i_X509_PUBKEY_introduced then
    begin
      {$if declared(FC_d2i_X509_PUBKEY)}
      d2i_X509_PUBKEY := FC_d2i_X509_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_PUBKEY_removed)}
    if d2i_X509_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_PUBKEY)}
      d2i_X509_PUBKEY := _d2i_X509_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_PUBKEY');
    {$ifend}
  end;
  
  i2d_X509_PUBKEY := LoadLibFunction(ADllHandle, i2d_X509_PUBKEY_procname);
  FuncLoadError := not assigned(i2d_X509_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_PUBKEY_allownil)}
    i2d_X509_PUBKEY := ERR_i2d_X509_PUBKEY;
    {$ifend}
    {$if declared(i2d_X509_PUBKEY_introduced)}
    if LibVersion < i2d_X509_PUBKEY_introduced then
    begin
      {$if declared(FC_i2d_X509_PUBKEY)}
      i2d_X509_PUBKEY := FC_i2d_X509_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_PUBKEY_removed)}
    if i2d_X509_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_PUBKEY)}
      i2d_X509_PUBKEY := _i2d_X509_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_PUBKEY');
    {$ifend}
  end;
  
  X509_PUBKEY_it := LoadLibFunction(ADllHandle, X509_PUBKEY_it_procname);
  FuncLoadError := not assigned(X509_PUBKEY_it);
  if FuncLoadError then
  begin
    {$if not defined(X509_PUBKEY_it_allownil)}
    X509_PUBKEY_it := ERR_X509_PUBKEY_it;
    {$ifend}
    {$if declared(X509_PUBKEY_it_introduced)}
    if LibVersion < X509_PUBKEY_it_introduced then
    begin
      {$if declared(FC_X509_PUBKEY_it)}
      X509_PUBKEY_it := FC_X509_PUBKEY_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PUBKEY_it_removed)}
    if X509_PUBKEY_it_removed <= LibVersion then
    begin
      {$if declared(_X509_PUBKEY_it)}
      X509_PUBKEY_it := _X509_PUBKEY_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PUBKEY_it_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PUBKEY_it');
    {$ifend}
  end;
  
  X509_PUBKEY_new_ex := LoadLibFunction(ADllHandle, X509_PUBKEY_new_ex_procname);
  FuncLoadError := not assigned(X509_PUBKEY_new_ex);
  if FuncLoadError then
  begin
    {$if not defined(X509_PUBKEY_new_ex_allownil)}
    X509_PUBKEY_new_ex := ERR_X509_PUBKEY_new_ex;
    {$ifend}
    {$if declared(X509_PUBKEY_new_ex_introduced)}
    if LibVersion < X509_PUBKEY_new_ex_introduced then
    begin
      {$if declared(FC_X509_PUBKEY_new_ex)}
      X509_PUBKEY_new_ex := FC_X509_PUBKEY_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PUBKEY_new_ex_removed)}
    if X509_PUBKEY_new_ex_removed <= LibVersion then
    begin
      {$if declared(_X509_PUBKEY_new_ex)}
      X509_PUBKEY_new_ex := _X509_PUBKEY_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PUBKEY_new_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PUBKEY_new_ex');
    {$ifend}
  end;
  
  X509_PUBKEY_set := LoadLibFunction(ADllHandle, X509_PUBKEY_set_procname);
  FuncLoadError := not assigned(X509_PUBKEY_set);
  if FuncLoadError then
  begin
    {$if not defined(X509_PUBKEY_set_allownil)}
    X509_PUBKEY_set := ERR_X509_PUBKEY_set;
    {$ifend}
    {$if declared(X509_PUBKEY_set_introduced)}
    if LibVersion < X509_PUBKEY_set_introduced then
    begin
      {$if declared(FC_X509_PUBKEY_set)}
      X509_PUBKEY_set := FC_X509_PUBKEY_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PUBKEY_set_removed)}
    if X509_PUBKEY_set_removed <= LibVersion then
    begin
      {$if declared(_X509_PUBKEY_set)}
      X509_PUBKEY_set := _X509_PUBKEY_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PUBKEY_set_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PUBKEY_set');
    {$ifend}
  end;
  
  X509_PUBKEY_get0 := LoadLibFunction(ADllHandle, X509_PUBKEY_get0_procname);
  FuncLoadError := not assigned(X509_PUBKEY_get0);
  if FuncLoadError then
  begin
    {$if not defined(X509_PUBKEY_get0_allownil)}
    X509_PUBKEY_get0 := ERR_X509_PUBKEY_get0;
    {$ifend}
    {$if declared(X509_PUBKEY_get0_introduced)}
    if LibVersion < X509_PUBKEY_get0_introduced then
    begin
      {$if declared(FC_X509_PUBKEY_get0)}
      X509_PUBKEY_get0 := FC_X509_PUBKEY_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PUBKEY_get0_removed)}
    if X509_PUBKEY_get0_removed <= LibVersion then
    begin
      {$if declared(_X509_PUBKEY_get0)}
      X509_PUBKEY_get0 := _X509_PUBKEY_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PUBKEY_get0_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PUBKEY_get0');
    {$ifend}
  end;
  
  X509_PUBKEY_get := LoadLibFunction(ADllHandle, X509_PUBKEY_get_procname);
  FuncLoadError := not assigned(X509_PUBKEY_get);
  if FuncLoadError then
  begin
    {$if not defined(X509_PUBKEY_get_allownil)}
    X509_PUBKEY_get := ERR_X509_PUBKEY_get;
    {$ifend}
    {$if declared(X509_PUBKEY_get_introduced)}
    if LibVersion < X509_PUBKEY_get_introduced then
    begin
      {$if declared(FC_X509_PUBKEY_get)}
      X509_PUBKEY_get := FC_X509_PUBKEY_get;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PUBKEY_get_removed)}
    if X509_PUBKEY_get_removed <= LibVersion then
    begin
      {$if declared(_X509_PUBKEY_get)}
      X509_PUBKEY_get := _X509_PUBKEY_get;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PUBKEY_get_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PUBKEY_get');
    {$ifend}
  end;
  
  X509_get_pubkey_parameters := LoadLibFunction(ADllHandle, X509_get_pubkey_parameters_procname);
  FuncLoadError := not assigned(X509_get_pubkey_parameters);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_pubkey_parameters_allownil)}
    X509_get_pubkey_parameters := ERR_X509_get_pubkey_parameters;
    {$ifend}
    {$if declared(X509_get_pubkey_parameters_introduced)}
    if LibVersion < X509_get_pubkey_parameters_introduced then
    begin
      {$if declared(FC_X509_get_pubkey_parameters)}
      X509_get_pubkey_parameters := FC_X509_get_pubkey_parameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_pubkey_parameters_removed)}
    if X509_get_pubkey_parameters_removed <= LibVersion then
    begin
      {$if declared(_X509_get_pubkey_parameters)}
      X509_get_pubkey_parameters := _X509_get_pubkey_parameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_pubkey_parameters_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_pubkey_parameters');
    {$ifend}
  end;
  
  X509_get_pathlen := LoadLibFunction(ADllHandle, X509_get_pathlen_procname);
  FuncLoadError := not assigned(X509_get_pathlen);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_pathlen_allownil)}
    X509_get_pathlen := ERR_X509_get_pathlen;
    {$ifend}
    {$if declared(X509_get_pathlen_introduced)}
    if LibVersion < X509_get_pathlen_introduced then
    begin
      {$if declared(FC_X509_get_pathlen)}
      X509_get_pathlen := FC_X509_get_pathlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_pathlen_removed)}
    if X509_get_pathlen_removed <= LibVersion then
    begin
      {$if declared(_X509_get_pathlen)}
      X509_get_pathlen := _X509_get_pathlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_pathlen_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_pathlen');
    {$ifend}
  end;
  
  d2i_PUBKEY := LoadLibFunction(ADllHandle, d2i_PUBKEY_procname);
  FuncLoadError := not assigned(d2i_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PUBKEY_allownil)}
    d2i_PUBKEY := ERR_d2i_PUBKEY;
    {$ifend}
    {$if declared(d2i_PUBKEY_introduced)}
    if LibVersion < d2i_PUBKEY_introduced then
    begin
      {$if declared(FC_d2i_PUBKEY)}
      d2i_PUBKEY := FC_d2i_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PUBKEY_removed)}
    if d2i_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_d2i_PUBKEY)}
      d2i_PUBKEY := _d2i_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PUBKEY');
    {$ifend}
  end;
  
  i2d_PUBKEY := LoadLibFunction(ADllHandle, i2d_PUBKEY_procname);
  FuncLoadError := not assigned(i2d_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PUBKEY_allownil)}
    i2d_PUBKEY := ERR_i2d_PUBKEY;
    {$ifend}
    {$if declared(i2d_PUBKEY_introduced)}
    if LibVersion < i2d_PUBKEY_introduced then
    begin
      {$if declared(FC_i2d_PUBKEY)}
      i2d_PUBKEY := FC_i2d_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PUBKEY_removed)}
    if i2d_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_i2d_PUBKEY)}
      i2d_PUBKEY := _i2d_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PUBKEY');
    {$ifend}
  end;
  
  d2i_PUBKEY_ex := LoadLibFunction(ADllHandle, d2i_PUBKEY_ex_procname);
  FuncLoadError := not assigned(d2i_PUBKEY_ex);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PUBKEY_ex_allownil)}
    d2i_PUBKEY_ex := ERR_d2i_PUBKEY_ex;
    {$ifend}
    {$if declared(d2i_PUBKEY_ex_introduced)}
    if LibVersion < d2i_PUBKEY_ex_introduced then
    begin
      {$if declared(FC_d2i_PUBKEY_ex)}
      d2i_PUBKEY_ex := FC_d2i_PUBKEY_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PUBKEY_ex_removed)}
    if d2i_PUBKEY_ex_removed <= LibVersion then
    begin
      {$if declared(_d2i_PUBKEY_ex)}
      d2i_PUBKEY_ex := _d2i_PUBKEY_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PUBKEY_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PUBKEY_ex');
    {$ifend}
  end;
  
  d2i_RSA_PUBKEY := LoadLibFunction(ADllHandle, d2i_RSA_PUBKEY_procname);
  FuncLoadError := not assigned(d2i_RSA_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(d2i_RSA_PUBKEY_allownil)}
    d2i_RSA_PUBKEY := ERR_d2i_RSA_PUBKEY;
    {$ifend}
    {$if declared(d2i_RSA_PUBKEY_introduced)}
    if LibVersion < d2i_RSA_PUBKEY_introduced then
    begin
      {$if declared(FC_d2i_RSA_PUBKEY)}
      d2i_RSA_PUBKEY := FC_d2i_RSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_RSA_PUBKEY_removed)}
    if d2i_RSA_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_d2i_RSA_PUBKEY)}
      d2i_RSA_PUBKEY := _d2i_RSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_RSA_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_RSA_PUBKEY');
    {$ifend}
  end;
  
  i2d_RSA_PUBKEY := LoadLibFunction(ADllHandle, i2d_RSA_PUBKEY_procname);
  FuncLoadError := not assigned(i2d_RSA_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(i2d_RSA_PUBKEY_allownil)}
    i2d_RSA_PUBKEY := ERR_i2d_RSA_PUBKEY;
    {$ifend}
    {$if declared(i2d_RSA_PUBKEY_introduced)}
    if LibVersion < i2d_RSA_PUBKEY_introduced then
    begin
      {$if declared(FC_i2d_RSA_PUBKEY)}
      i2d_RSA_PUBKEY := FC_i2d_RSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_RSA_PUBKEY_removed)}
    if i2d_RSA_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_i2d_RSA_PUBKEY)}
      i2d_RSA_PUBKEY := _i2d_RSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_RSA_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_RSA_PUBKEY');
    {$ifend}
  end;
  
  d2i_DSA_PUBKEY := LoadLibFunction(ADllHandle, d2i_DSA_PUBKEY_procname);
  FuncLoadError := not assigned(d2i_DSA_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(d2i_DSA_PUBKEY_allownil)}
    d2i_DSA_PUBKEY := ERR_d2i_DSA_PUBKEY;
    {$ifend}
    {$if declared(d2i_DSA_PUBKEY_introduced)}
    if LibVersion < d2i_DSA_PUBKEY_introduced then
    begin
      {$if declared(FC_d2i_DSA_PUBKEY)}
      d2i_DSA_PUBKEY := FC_d2i_DSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_DSA_PUBKEY_removed)}
    if d2i_DSA_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_d2i_DSA_PUBKEY)}
      d2i_DSA_PUBKEY := _d2i_DSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_DSA_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_DSA_PUBKEY');
    {$ifend}
  end;
  
  i2d_DSA_PUBKEY := LoadLibFunction(ADllHandle, i2d_DSA_PUBKEY_procname);
  FuncLoadError := not assigned(i2d_DSA_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(i2d_DSA_PUBKEY_allownil)}
    i2d_DSA_PUBKEY := ERR_i2d_DSA_PUBKEY;
    {$ifend}
    {$if declared(i2d_DSA_PUBKEY_introduced)}
    if LibVersion < i2d_DSA_PUBKEY_introduced then
    begin
      {$if declared(FC_i2d_DSA_PUBKEY)}
      i2d_DSA_PUBKEY := FC_i2d_DSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_DSA_PUBKEY_removed)}
    if i2d_DSA_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_i2d_DSA_PUBKEY)}
      i2d_DSA_PUBKEY := _i2d_DSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_DSA_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_DSA_PUBKEY');
    {$ifend}
  end;
  
  d2i_EC_PUBKEY := LoadLibFunction(ADllHandle, d2i_EC_PUBKEY_procname);
  FuncLoadError := not assigned(d2i_EC_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(d2i_EC_PUBKEY_allownil)}
    d2i_EC_PUBKEY := ERR_d2i_EC_PUBKEY;
    {$ifend}
    {$if declared(d2i_EC_PUBKEY_introduced)}
    if LibVersion < d2i_EC_PUBKEY_introduced then
    begin
      {$if declared(FC_d2i_EC_PUBKEY)}
      d2i_EC_PUBKEY := FC_d2i_EC_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_EC_PUBKEY_removed)}
    if d2i_EC_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_d2i_EC_PUBKEY)}
      d2i_EC_PUBKEY := _d2i_EC_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_EC_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_EC_PUBKEY');
    {$ifend}
  end;
  
  i2d_EC_PUBKEY := LoadLibFunction(ADllHandle, i2d_EC_PUBKEY_procname);
  FuncLoadError := not assigned(i2d_EC_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(i2d_EC_PUBKEY_allownil)}
    i2d_EC_PUBKEY := ERR_i2d_EC_PUBKEY;
    {$ifend}
    {$if declared(i2d_EC_PUBKEY_introduced)}
    if LibVersion < i2d_EC_PUBKEY_introduced then
    begin
      {$if declared(FC_i2d_EC_PUBKEY)}
      i2d_EC_PUBKEY := FC_i2d_EC_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_EC_PUBKEY_removed)}
    if i2d_EC_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_i2d_EC_PUBKEY)}
      i2d_EC_PUBKEY := _i2d_EC_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_EC_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_EC_PUBKEY');
    {$ifend}
  end;
  
  X509_SIG_new := LoadLibFunction(ADllHandle, X509_SIG_new_procname);
  FuncLoadError := not assigned(X509_SIG_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_SIG_new_allownil)}
    X509_SIG_new := ERR_X509_SIG_new;
    {$ifend}
    {$if declared(X509_SIG_new_introduced)}
    if LibVersion < X509_SIG_new_introduced then
    begin
      {$if declared(FC_X509_SIG_new)}
      X509_SIG_new := FC_X509_SIG_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_SIG_new_removed)}
    if X509_SIG_new_removed <= LibVersion then
    begin
      {$if declared(_X509_SIG_new)}
      X509_SIG_new := _X509_SIG_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_SIG_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_SIG_new');
    {$ifend}
  end;
  
  X509_SIG_free := LoadLibFunction(ADllHandle, X509_SIG_free_procname);
  FuncLoadError := not assigned(X509_SIG_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_SIG_free_allownil)}
    X509_SIG_free := ERR_X509_SIG_free;
    {$ifend}
    {$if declared(X509_SIG_free_introduced)}
    if LibVersion < X509_SIG_free_introduced then
    begin
      {$if declared(FC_X509_SIG_free)}
      X509_SIG_free := FC_X509_SIG_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_SIG_free_removed)}
    if X509_SIG_free_removed <= LibVersion then
    begin
      {$if declared(_X509_SIG_free)}
      X509_SIG_free := _X509_SIG_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_SIG_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_SIG_free');
    {$ifend}
  end;
  
  d2i_X509_SIG := LoadLibFunction(ADllHandle, d2i_X509_SIG_procname);
  FuncLoadError := not assigned(d2i_X509_SIG);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_SIG_allownil)}
    d2i_X509_SIG := ERR_d2i_X509_SIG;
    {$ifend}
    {$if declared(d2i_X509_SIG_introduced)}
    if LibVersion < d2i_X509_SIG_introduced then
    begin
      {$if declared(FC_d2i_X509_SIG)}
      d2i_X509_SIG := FC_d2i_X509_SIG;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_SIG_removed)}
    if d2i_X509_SIG_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_SIG)}
      d2i_X509_SIG := _d2i_X509_SIG;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_SIG_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_SIG');
    {$ifend}
  end;
  
  i2d_X509_SIG := LoadLibFunction(ADllHandle, i2d_X509_SIG_procname);
  FuncLoadError := not assigned(i2d_X509_SIG);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_SIG_allownil)}
    i2d_X509_SIG := ERR_i2d_X509_SIG;
    {$ifend}
    {$if declared(i2d_X509_SIG_introduced)}
    if LibVersion < i2d_X509_SIG_introduced then
    begin
      {$if declared(FC_i2d_X509_SIG)}
      i2d_X509_SIG := FC_i2d_X509_SIG;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_SIG_removed)}
    if i2d_X509_SIG_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_SIG)}
      i2d_X509_SIG := _i2d_X509_SIG;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_SIG_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_SIG');
    {$ifend}
  end;
  
  X509_SIG_it := LoadLibFunction(ADllHandle, X509_SIG_it_procname);
  FuncLoadError := not assigned(X509_SIG_it);
  if FuncLoadError then
  begin
    {$if not defined(X509_SIG_it_allownil)}
    X509_SIG_it := ERR_X509_SIG_it;
    {$ifend}
    {$if declared(X509_SIG_it_introduced)}
    if LibVersion < X509_SIG_it_introduced then
    begin
      {$if declared(FC_X509_SIG_it)}
      X509_SIG_it := FC_X509_SIG_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_SIG_it_removed)}
    if X509_SIG_it_removed <= LibVersion then
    begin
      {$if declared(_X509_SIG_it)}
      X509_SIG_it := _X509_SIG_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_SIG_it_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_SIG_it');
    {$ifend}
  end;
  
  X509_SIG_get0 := LoadLibFunction(ADllHandle, X509_SIG_get0_procname);
  FuncLoadError := not assigned(X509_SIG_get0);
  if FuncLoadError then
  begin
    {$if not defined(X509_SIG_get0_allownil)}
    X509_SIG_get0 := ERR_X509_SIG_get0;
    {$ifend}
    {$if declared(X509_SIG_get0_introduced)}
    if LibVersion < X509_SIG_get0_introduced then
    begin
      {$if declared(FC_X509_SIG_get0)}
      X509_SIG_get0 := FC_X509_SIG_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_SIG_get0_removed)}
    if X509_SIG_get0_removed <= LibVersion then
    begin
      {$if declared(_X509_SIG_get0)}
      X509_SIG_get0 := _X509_SIG_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_SIG_get0_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_SIG_get0');
    {$ifend}
  end;
  
  X509_SIG_getm := LoadLibFunction(ADllHandle, X509_SIG_getm_procname);
  FuncLoadError := not assigned(X509_SIG_getm);
  if FuncLoadError then
  begin
    {$if not defined(X509_SIG_getm_allownil)}
    X509_SIG_getm := ERR_X509_SIG_getm;
    {$ifend}
    {$if declared(X509_SIG_getm_introduced)}
    if LibVersion < X509_SIG_getm_introduced then
    begin
      {$if declared(FC_X509_SIG_getm)}
      X509_SIG_getm := FC_X509_SIG_getm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_SIG_getm_removed)}
    if X509_SIG_getm_removed <= LibVersion then
    begin
      {$if declared(_X509_SIG_getm)}
      X509_SIG_getm := _X509_SIG_getm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_SIG_getm_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_SIG_getm');
    {$ifend}
  end;
  
  X509_REQ_INFO_new := LoadLibFunction(ADllHandle, X509_REQ_INFO_new_procname);
  FuncLoadError := not assigned(X509_REQ_INFO_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_INFO_new_allownil)}
    X509_REQ_INFO_new := ERR_X509_REQ_INFO_new;
    {$ifend}
    {$if declared(X509_REQ_INFO_new_introduced)}
    if LibVersion < X509_REQ_INFO_new_introduced then
    begin
      {$if declared(FC_X509_REQ_INFO_new)}
      X509_REQ_INFO_new := FC_X509_REQ_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_INFO_new_removed)}
    if X509_REQ_INFO_new_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_INFO_new)}
      X509_REQ_INFO_new := _X509_REQ_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_INFO_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_INFO_new');
    {$ifend}
  end;
  
  X509_REQ_INFO_free := LoadLibFunction(ADllHandle, X509_REQ_INFO_free_procname);
  FuncLoadError := not assigned(X509_REQ_INFO_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_INFO_free_allownil)}
    X509_REQ_INFO_free := ERR_X509_REQ_INFO_free;
    {$ifend}
    {$if declared(X509_REQ_INFO_free_introduced)}
    if LibVersion < X509_REQ_INFO_free_introduced then
    begin
      {$if declared(FC_X509_REQ_INFO_free)}
      X509_REQ_INFO_free := FC_X509_REQ_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_INFO_free_removed)}
    if X509_REQ_INFO_free_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_INFO_free)}
      X509_REQ_INFO_free := _X509_REQ_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_INFO_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_INFO_free');
    {$ifend}
  end;
  
  d2i_X509_REQ_INFO := LoadLibFunction(ADllHandle, d2i_X509_REQ_INFO_procname);
  FuncLoadError := not assigned(d2i_X509_REQ_INFO);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_REQ_INFO_allownil)}
    d2i_X509_REQ_INFO := ERR_d2i_X509_REQ_INFO;
    {$ifend}
    {$if declared(d2i_X509_REQ_INFO_introduced)}
    if LibVersion < d2i_X509_REQ_INFO_introduced then
    begin
      {$if declared(FC_d2i_X509_REQ_INFO)}
      d2i_X509_REQ_INFO := FC_d2i_X509_REQ_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_REQ_INFO_removed)}
    if d2i_X509_REQ_INFO_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_REQ_INFO)}
      d2i_X509_REQ_INFO := _d2i_X509_REQ_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_REQ_INFO_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_REQ_INFO');
    {$ifend}
  end;
  
  i2d_X509_REQ_INFO := LoadLibFunction(ADllHandle, i2d_X509_REQ_INFO_procname);
  FuncLoadError := not assigned(i2d_X509_REQ_INFO);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_REQ_INFO_allownil)}
    i2d_X509_REQ_INFO := ERR_i2d_X509_REQ_INFO;
    {$ifend}
    {$if declared(i2d_X509_REQ_INFO_introduced)}
    if LibVersion < i2d_X509_REQ_INFO_introduced then
    begin
      {$if declared(FC_i2d_X509_REQ_INFO)}
      i2d_X509_REQ_INFO := FC_i2d_X509_REQ_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_REQ_INFO_removed)}
    if i2d_X509_REQ_INFO_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_REQ_INFO)}
      i2d_X509_REQ_INFO := _i2d_X509_REQ_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_REQ_INFO_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_REQ_INFO');
    {$ifend}
  end;
  
  X509_REQ_INFO_it := LoadLibFunction(ADllHandle, X509_REQ_INFO_it_procname);
  FuncLoadError := not assigned(X509_REQ_INFO_it);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_INFO_it_allownil)}
    X509_REQ_INFO_it := ERR_X509_REQ_INFO_it;
    {$ifend}
    {$if declared(X509_REQ_INFO_it_introduced)}
    if LibVersion < X509_REQ_INFO_it_introduced then
    begin
      {$if declared(FC_X509_REQ_INFO_it)}
      X509_REQ_INFO_it := FC_X509_REQ_INFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_INFO_it_removed)}
    if X509_REQ_INFO_it_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_INFO_it)}
      X509_REQ_INFO_it := _X509_REQ_INFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_INFO_it_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_INFO_it');
    {$ifend}
  end;
  
  X509_REQ_new := LoadLibFunction(ADllHandle, X509_REQ_new_procname);
  FuncLoadError := not assigned(X509_REQ_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_new_allownil)}
    X509_REQ_new := ERR_X509_REQ_new;
    {$ifend}
    {$if declared(X509_REQ_new_introduced)}
    if LibVersion < X509_REQ_new_introduced then
    begin
      {$if declared(FC_X509_REQ_new)}
      X509_REQ_new := FC_X509_REQ_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_new_removed)}
    if X509_REQ_new_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_new)}
      X509_REQ_new := _X509_REQ_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_new');
    {$ifend}
  end;
  
  X509_REQ_free := LoadLibFunction(ADllHandle, X509_REQ_free_procname);
  FuncLoadError := not assigned(X509_REQ_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_free_allownil)}
    X509_REQ_free := ERR_X509_REQ_free;
    {$ifend}
    {$if declared(X509_REQ_free_introduced)}
    if LibVersion < X509_REQ_free_introduced then
    begin
      {$if declared(FC_X509_REQ_free)}
      X509_REQ_free := FC_X509_REQ_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_free_removed)}
    if X509_REQ_free_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_free)}
      X509_REQ_free := _X509_REQ_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_free');
    {$ifend}
  end;
  
  d2i_X509_REQ := LoadLibFunction(ADllHandle, d2i_X509_REQ_procname);
  FuncLoadError := not assigned(d2i_X509_REQ);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_REQ_allownil)}
    d2i_X509_REQ := ERR_d2i_X509_REQ;
    {$ifend}
    {$if declared(d2i_X509_REQ_introduced)}
    if LibVersion < d2i_X509_REQ_introduced then
    begin
      {$if declared(FC_d2i_X509_REQ)}
      d2i_X509_REQ := FC_d2i_X509_REQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_REQ_removed)}
    if d2i_X509_REQ_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_REQ)}
      d2i_X509_REQ := _d2i_X509_REQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_REQ_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_REQ');
    {$ifend}
  end;
  
  i2d_X509_REQ := LoadLibFunction(ADllHandle, i2d_X509_REQ_procname);
  FuncLoadError := not assigned(i2d_X509_REQ);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_REQ_allownil)}
    i2d_X509_REQ := ERR_i2d_X509_REQ;
    {$ifend}
    {$if declared(i2d_X509_REQ_introduced)}
    if LibVersion < i2d_X509_REQ_introduced then
    begin
      {$if declared(FC_i2d_X509_REQ)}
      i2d_X509_REQ := FC_i2d_X509_REQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_REQ_removed)}
    if i2d_X509_REQ_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_REQ)}
      i2d_X509_REQ := _i2d_X509_REQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_REQ_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_REQ');
    {$ifend}
  end;
  
  X509_REQ_it := LoadLibFunction(ADllHandle, X509_REQ_it_procname);
  FuncLoadError := not assigned(X509_REQ_it);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_it_allownil)}
    X509_REQ_it := ERR_X509_REQ_it;
    {$ifend}
    {$if declared(X509_REQ_it_introduced)}
    if LibVersion < X509_REQ_it_introduced then
    begin
      {$if declared(FC_X509_REQ_it)}
      X509_REQ_it := FC_X509_REQ_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_it_removed)}
    if X509_REQ_it_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_it)}
      X509_REQ_it := _X509_REQ_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_it_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_it');
    {$ifend}
  end;
  
  X509_REQ_new_ex := LoadLibFunction(ADllHandle, X509_REQ_new_ex_procname);
  FuncLoadError := not assigned(X509_REQ_new_ex);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_new_ex_allownil)}
    X509_REQ_new_ex := ERR_X509_REQ_new_ex;
    {$ifend}
    {$if declared(X509_REQ_new_ex_introduced)}
    if LibVersion < X509_REQ_new_ex_introduced then
    begin
      {$if declared(FC_X509_REQ_new_ex)}
      X509_REQ_new_ex := FC_X509_REQ_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_new_ex_removed)}
    if X509_REQ_new_ex_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_new_ex)}
      X509_REQ_new_ex := _X509_REQ_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_new_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_new_ex');
    {$ifend}
  end;
  
  X509_ATTRIBUTE_new := LoadLibFunction(ADllHandle, X509_ATTRIBUTE_new_procname);
  FuncLoadError := not assigned(X509_ATTRIBUTE_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_ATTRIBUTE_new_allownil)}
    X509_ATTRIBUTE_new := ERR_X509_ATTRIBUTE_new;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_new_introduced)}
    if LibVersion < X509_ATTRIBUTE_new_introduced then
    begin
      {$if declared(FC_X509_ATTRIBUTE_new)}
      X509_ATTRIBUTE_new := FC_X509_ATTRIBUTE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_new_removed)}
    if X509_ATTRIBUTE_new_removed <= LibVersion then
    begin
      {$if declared(_X509_ATTRIBUTE_new)}
      X509_ATTRIBUTE_new := _X509_ATTRIBUTE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ATTRIBUTE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ATTRIBUTE_new');
    {$ifend}
  end;
  
  X509_ATTRIBUTE_free := LoadLibFunction(ADllHandle, X509_ATTRIBUTE_free_procname);
  FuncLoadError := not assigned(X509_ATTRIBUTE_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_ATTRIBUTE_free_allownil)}
    X509_ATTRIBUTE_free := ERR_X509_ATTRIBUTE_free;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_free_introduced)}
    if LibVersion < X509_ATTRIBUTE_free_introduced then
    begin
      {$if declared(FC_X509_ATTRIBUTE_free)}
      X509_ATTRIBUTE_free := FC_X509_ATTRIBUTE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_free_removed)}
    if X509_ATTRIBUTE_free_removed <= LibVersion then
    begin
      {$if declared(_X509_ATTRIBUTE_free)}
      X509_ATTRIBUTE_free := _X509_ATTRIBUTE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ATTRIBUTE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ATTRIBUTE_free');
    {$ifend}
  end;
  
  d2i_X509_ATTRIBUTE := LoadLibFunction(ADllHandle, d2i_X509_ATTRIBUTE_procname);
  FuncLoadError := not assigned(d2i_X509_ATTRIBUTE);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_ATTRIBUTE_allownil)}
    d2i_X509_ATTRIBUTE := ERR_d2i_X509_ATTRIBUTE;
    {$ifend}
    {$if declared(d2i_X509_ATTRIBUTE_introduced)}
    if LibVersion < d2i_X509_ATTRIBUTE_introduced then
    begin
      {$if declared(FC_d2i_X509_ATTRIBUTE)}
      d2i_X509_ATTRIBUTE := FC_d2i_X509_ATTRIBUTE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_ATTRIBUTE_removed)}
    if d2i_X509_ATTRIBUTE_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_ATTRIBUTE)}
      d2i_X509_ATTRIBUTE := _d2i_X509_ATTRIBUTE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_ATTRIBUTE_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_ATTRIBUTE');
    {$ifend}
  end;
  
  i2d_X509_ATTRIBUTE := LoadLibFunction(ADllHandle, i2d_X509_ATTRIBUTE_procname);
  FuncLoadError := not assigned(i2d_X509_ATTRIBUTE);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_ATTRIBUTE_allownil)}
    i2d_X509_ATTRIBUTE := ERR_i2d_X509_ATTRIBUTE;
    {$ifend}
    {$if declared(i2d_X509_ATTRIBUTE_introduced)}
    if LibVersion < i2d_X509_ATTRIBUTE_introduced then
    begin
      {$if declared(FC_i2d_X509_ATTRIBUTE)}
      i2d_X509_ATTRIBUTE := FC_i2d_X509_ATTRIBUTE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_ATTRIBUTE_removed)}
    if i2d_X509_ATTRIBUTE_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_ATTRIBUTE)}
      i2d_X509_ATTRIBUTE := _i2d_X509_ATTRIBUTE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_ATTRIBUTE_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_ATTRIBUTE');
    {$ifend}
  end;
  
  X509_ATTRIBUTE_it := LoadLibFunction(ADllHandle, X509_ATTRIBUTE_it_procname);
  FuncLoadError := not assigned(X509_ATTRIBUTE_it);
  if FuncLoadError then
  begin
    {$if not defined(X509_ATTRIBUTE_it_allownil)}
    X509_ATTRIBUTE_it := ERR_X509_ATTRIBUTE_it;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_it_introduced)}
    if LibVersion < X509_ATTRIBUTE_it_introduced then
    begin
      {$if declared(FC_X509_ATTRIBUTE_it)}
      X509_ATTRIBUTE_it := FC_X509_ATTRIBUTE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_it_removed)}
    if X509_ATTRIBUTE_it_removed <= LibVersion then
    begin
      {$if declared(_X509_ATTRIBUTE_it)}
      X509_ATTRIBUTE_it := _X509_ATTRIBUTE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ATTRIBUTE_it_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ATTRIBUTE_it');
    {$ifend}
  end;
  
  X509_ATTRIBUTE_create := LoadLibFunction(ADllHandle, X509_ATTRIBUTE_create_procname);
  FuncLoadError := not assigned(X509_ATTRIBUTE_create);
  if FuncLoadError then
  begin
    {$if not defined(X509_ATTRIBUTE_create_allownil)}
    X509_ATTRIBUTE_create := ERR_X509_ATTRIBUTE_create;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_create_introduced)}
    if LibVersion < X509_ATTRIBUTE_create_introduced then
    begin
      {$if declared(FC_X509_ATTRIBUTE_create)}
      X509_ATTRIBUTE_create := FC_X509_ATTRIBUTE_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_create_removed)}
    if X509_ATTRIBUTE_create_removed <= LibVersion then
    begin
      {$if declared(_X509_ATTRIBUTE_create)}
      X509_ATTRIBUTE_create := _X509_ATTRIBUTE_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ATTRIBUTE_create_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ATTRIBUTE_create');
    {$ifend}
  end;
  
  X509_EXTENSION_new := LoadLibFunction(ADllHandle, X509_EXTENSION_new_procname);
  FuncLoadError := not assigned(X509_EXTENSION_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_EXTENSION_new_allownil)}
    X509_EXTENSION_new := ERR_X509_EXTENSION_new;
    {$ifend}
    {$if declared(X509_EXTENSION_new_introduced)}
    if LibVersion < X509_EXTENSION_new_introduced then
    begin
      {$if declared(FC_X509_EXTENSION_new)}
      X509_EXTENSION_new := FC_X509_EXTENSION_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_EXTENSION_new_removed)}
    if X509_EXTENSION_new_removed <= LibVersion then
    begin
      {$if declared(_X509_EXTENSION_new)}
      X509_EXTENSION_new := _X509_EXTENSION_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_EXTENSION_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_EXTENSION_new');
    {$ifend}
  end;
  
  X509_EXTENSION_free := LoadLibFunction(ADllHandle, X509_EXTENSION_free_procname);
  FuncLoadError := not assigned(X509_EXTENSION_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_EXTENSION_free_allownil)}
    X509_EXTENSION_free := ERR_X509_EXTENSION_free;
    {$ifend}
    {$if declared(X509_EXTENSION_free_introduced)}
    if LibVersion < X509_EXTENSION_free_introduced then
    begin
      {$if declared(FC_X509_EXTENSION_free)}
      X509_EXTENSION_free := FC_X509_EXTENSION_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_EXTENSION_free_removed)}
    if X509_EXTENSION_free_removed <= LibVersion then
    begin
      {$if declared(_X509_EXTENSION_free)}
      X509_EXTENSION_free := _X509_EXTENSION_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_EXTENSION_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_EXTENSION_free');
    {$ifend}
  end;
  
  d2i_X509_EXTENSION := LoadLibFunction(ADllHandle, d2i_X509_EXTENSION_procname);
  FuncLoadError := not assigned(d2i_X509_EXTENSION);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_EXTENSION_allownil)}
    d2i_X509_EXTENSION := ERR_d2i_X509_EXTENSION;
    {$ifend}
    {$if declared(d2i_X509_EXTENSION_introduced)}
    if LibVersion < d2i_X509_EXTENSION_introduced then
    begin
      {$if declared(FC_d2i_X509_EXTENSION)}
      d2i_X509_EXTENSION := FC_d2i_X509_EXTENSION;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_EXTENSION_removed)}
    if d2i_X509_EXTENSION_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_EXTENSION)}
      d2i_X509_EXTENSION := _d2i_X509_EXTENSION;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_EXTENSION_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_EXTENSION');
    {$ifend}
  end;
  
  i2d_X509_EXTENSION := LoadLibFunction(ADllHandle, i2d_X509_EXTENSION_procname);
  FuncLoadError := not assigned(i2d_X509_EXTENSION);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_EXTENSION_allownil)}
    i2d_X509_EXTENSION := ERR_i2d_X509_EXTENSION;
    {$ifend}
    {$if declared(i2d_X509_EXTENSION_introduced)}
    if LibVersion < i2d_X509_EXTENSION_introduced then
    begin
      {$if declared(FC_i2d_X509_EXTENSION)}
      i2d_X509_EXTENSION := FC_i2d_X509_EXTENSION;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_EXTENSION_removed)}
    if i2d_X509_EXTENSION_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_EXTENSION)}
      i2d_X509_EXTENSION := _i2d_X509_EXTENSION;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_EXTENSION_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_EXTENSION');
    {$ifend}
  end;
  
  X509_EXTENSION_it := LoadLibFunction(ADllHandle, X509_EXTENSION_it_procname);
  FuncLoadError := not assigned(X509_EXTENSION_it);
  if FuncLoadError then
  begin
    {$if not defined(X509_EXTENSION_it_allownil)}
    X509_EXTENSION_it := ERR_X509_EXTENSION_it;
    {$ifend}
    {$if declared(X509_EXTENSION_it_introduced)}
    if LibVersion < X509_EXTENSION_it_introduced then
    begin
      {$if declared(FC_X509_EXTENSION_it)}
      X509_EXTENSION_it := FC_X509_EXTENSION_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_EXTENSION_it_removed)}
    if X509_EXTENSION_it_removed <= LibVersion then
    begin
      {$if declared(_X509_EXTENSION_it)}
      X509_EXTENSION_it := _X509_EXTENSION_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_EXTENSION_it_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_EXTENSION_it');
    {$ifend}
  end;
  
  d2i_X509_EXTENSIONS := LoadLibFunction(ADllHandle, d2i_X509_EXTENSIONS_procname);
  FuncLoadError := not assigned(d2i_X509_EXTENSIONS);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_EXTENSIONS_allownil)}
    d2i_X509_EXTENSIONS := ERR_d2i_X509_EXTENSIONS;
    {$ifend}
    {$if declared(d2i_X509_EXTENSIONS_introduced)}
    if LibVersion < d2i_X509_EXTENSIONS_introduced then
    begin
      {$if declared(FC_d2i_X509_EXTENSIONS)}
      d2i_X509_EXTENSIONS := FC_d2i_X509_EXTENSIONS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_EXTENSIONS_removed)}
    if d2i_X509_EXTENSIONS_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_EXTENSIONS)}
      d2i_X509_EXTENSIONS := _d2i_X509_EXTENSIONS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_EXTENSIONS_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_EXTENSIONS');
    {$ifend}
  end;
  
  i2d_X509_EXTENSIONS := LoadLibFunction(ADllHandle, i2d_X509_EXTENSIONS_procname);
  FuncLoadError := not assigned(i2d_X509_EXTENSIONS);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_EXTENSIONS_allownil)}
    i2d_X509_EXTENSIONS := ERR_i2d_X509_EXTENSIONS;
    {$ifend}
    {$if declared(i2d_X509_EXTENSIONS_introduced)}
    if LibVersion < i2d_X509_EXTENSIONS_introduced then
    begin
      {$if declared(FC_i2d_X509_EXTENSIONS)}
      i2d_X509_EXTENSIONS := FC_i2d_X509_EXTENSIONS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_EXTENSIONS_removed)}
    if i2d_X509_EXTENSIONS_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_EXTENSIONS)}
      i2d_X509_EXTENSIONS := _i2d_X509_EXTENSIONS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_EXTENSIONS_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_EXTENSIONS');
    {$ifend}
  end;
  
  X509_EXTENSIONS_it := LoadLibFunction(ADllHandle, X509_EXTENSIONS_it_procname);
  FuncLoadError := not assigned(X509_EXTENSIONS_it);
  if FuncLoadError then
  begin
    {$if not defined(X509_EXTENSIONS_it_allownil)}
    X509_EXTENSIONS_it := ERR_X509_EXTENSIONS_it;
    {$ifend}
    {$if declared(X509_EXTENSIONS_it_introduced)}
    if LibVersion < X509_EXTENSIONS_it_introduced then
    begin
      {$if declared(FC_X509_EXTENSIONS_it)}
      X509_EXTENSIONS_it := FC_X509_EXTENSIONS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_EXTENSIONS_it_removed)}
    if X509_EXTENSIONS_it_removed <= LibVersion then
    begin
      {$if declared(_X509_EXTENSIONS_it)}
      X509_EXTENSIONS_it := _X509_EXTENSIONS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_EXTENSIONS_it_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_EXTENSIONS_it');
    {$ifend}
  end;
  
  X509_NAME_ENTRY_new := LoadLibFunction(ADllHandle, X509_NAME_ENTRY_new_procname);
  FuncLoadError := not assigned(X509_NAME_ENTRY_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_ENTRY_new_allownil)}
    X509_NAME_ENTRY_new := ERR_X509_NAME_ENTRY_new;
    {$ifend}
    {$if declared(X509_NAME_ENTRY_new_introduced)}
    if LibVersion < X509_NAME_ENTRY_new_introduced then
    begin
      {$if declared(FC_X509_NAME_ENTRY_new)}
      X509_NAME_ENTRY_new := FC_X509_NAME_ENTRY_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_ENTRY_new_removed)}
    if X509_NAME_ENTRY_new_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_ENTRY_new)}
      X509_NAME_ENTRY_new := _X509_NAME_ENTRY_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_ENTRY_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_ENTRY_new');
    {$ifend}
  end;
  
  X509_NAME_ENTRY_free := LoadLibFunction(ADllHandle, X509_NAME_ENTRY_free_procname);
  FuncLoadError := not assigned(X509_NAME_ENTRY_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_ENTRY_free_allownil)}
    X509_NAME_ENTRY_free := ERR_X509_NAME_ENTRY_free;
    {$ifend}
    {$if declared(X509_NAME_ENTRY_free_introduced)}
    if LibVersion < X509_NAME_ENTRY_free_introduced then
    begin
      {$if declared(FC_X509_NAME_ENTRY_free)}
      X509_NAME_ENTRY_free := FC_X509_NAME_ENTRY_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_ENTRY_free_removed)}
    if X509_NAME_ENTRY_free_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_ENTRY_free)}
      X509_NAME_ENTRY_free := _X509_NAME_ENTRY_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_ENTRY_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_ENTRY_free');
    {$ifend}
  end;
  
  d2i_X509_NAME_ENTRY := LoadLibFunction(ADllHandle, d2i_X509_NAME_ENTRY_procname);
  FuncLoadError := not assigned(d2i_X509_NAME_ENTRY);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_NAME_ENTRY_allownil)}
    d2i_X509_NAME_ENTRY := ERR_d2i_X509_NAME_ENTRY;
    {$ifend}
    {$if declared(d2i_X509_NAME_ENTRY_introduced)}
    if LibVersion < d2i_X509_NAME_ENTRY_introduced then
    begin
      {$if declared(FC_d2i_X509_NAME_ENTRY)}
      d2i_X509_NAME_ENTRY := FC_d2i_X509_NAME_ENTRY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_NAME_ENTRY_removed)}
    if d2i_X509_NAME_ENTRY_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_NAME_ENTRY)}
      d2i_X509_NAME_ENTRY := _d2i_X509_NAME_ENTRY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_NAME_ENTRY_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_NAME_ENTRY');
    {$ifend}
  end;
  
  i2d_X509_NAME_ENTRY := LoadLibFunction(ADllHandle, i2d_X509_NAME_ENTRY_procname);
  FuncLoadError := not assigned(i2d_X509_NAME_ENTRY);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_NAME_ENTRY_allownil)}
    i2d_X509_NAME_ENTRY := ERR_i2d_X509_NAME_ENTRY;
    {$ifend}
    {$if declared(i2d_X509_NAME_ENTRY_introduced)}
    if LibVersion < i2d_X509_NAME_ENTRY_introduced then
    begin
      {$if declared(FC_i2d_X509_NAME_ENTRY)}
      i2d_X509_NAME_ENTRY := FC_i2d_X509_NAME_ENTRY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_NAME_ENTRY_removed)}
    if i2d_X509_NAME_ENTRY_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_NAME_ENTRY)}
      i2d_X509_NAME_ENTRY := _i2d_X509_NAME_ENTRY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_NAME_ENTRY_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_NAME_ENTRY');
    {$ifend}
  end;
  
  X509_NAME_ENTRY_it := LoadLibFunction(ADllHandle, X509_NAME_ENTRY_it_procname);
  FuncLoadError := not assigned(X509_NAME_ENTRY_it);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_ENTRY_it_allownil)}
    X509_NAME_ENTRY_it := ERR_X509_NAME_ENTRY_it;
    {$ifend}
    {$if declared(X509_NAME_ENTRY_it_introduced)}
    if LibVersion < X509_NAME_ENTRY_it_introduced then
    begin
      {$if declared(FC_X509_NAME_ENTRY_it)}
      X509_NAME_ENTRY_it := FC_X509_NAME_ENTRY_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_ENTRY_it_removed)}
    if X509_NAME_ENTRY_it_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_ENTRY_it)}
      X509_NAME_ENTRY_it := _X509_NAME_ENTRY_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_ENTRY_it_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_ENTRY_it');
    {$ifend}
  end;
  
  X509_NAME_new := LoadLibFunction(ADllHandle, X509_NAME_new_procname);
  FuncLoadError := not assigned(X509_NAME_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_new_allownil)}
    X509_NAME_new := ERR_X509_NAME_new;
    {$ifend}
    {$if declared(X509_NAME_new_introduced)}
    if LibVersion < X509_NAME_new_introduced then
    begin
      {$if declared(FC_X509_NAME_new)}
      X509_NAME_new := FC_X509_NAME_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_new_removed)}
    if X509_NAME_new_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_new)}
      X509_NAME_new := _X509_NAME_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_new');
    {$ifend}
  end;
  
  X509_NAME_free := LoadLibFunction(ADllHandle, X509_NAME_free_procname);
  FuncLoadError := not assigned(X509_NAME_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_free_allownil)}
    X509_NAME_free := ERR_X509_NAME_free;
    {$ifend}
    {$if declared(X509_NAME_free_introduced)}
    if LibVersion < X509_NAME_free_introduced then
    begin
      {$if declared(FC_X509_NAME_free)}
      X509_NAME_free := FC_X509_NAME_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_free_removed)}
    if X509_NAME_free_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_free)}
      X509_NAME_free := _X509_NAME_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_free');
    {$ifend}
  end;
  
  d2i_X509_NAME := LoadLibFunction(ADllHandle, d2i_X509_NAME_procname);
  FuncLoadError := not assigned(d2i_X509_NAME);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_NAME_allownil)}
    d2i_X509_NAME := ERR_d2i_X509_NAME;
    {$ifend}
    {$if declared(d2i_X509_NAME_introduced)}
    if LibVersion < d2i_X509_NAME_introduced then
    begin
      {$if declared(FC_d2i_X509_NAME)}
      d2i_X509_NAME := FC_d2i_X509_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_NAME_removed)}
    if d2i_X509_NAME_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_NAME)}
      d2i_X509_NAME := _d2i_X509_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_NAME_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_NAME');
    {$ifend}
  end;
  
  i2d_X509_NAME := LoadLibFunction(ADllHandle, i2d_X509_NAME_procname);
  FuncLoadError := not assigned(i2d_X509_NAME);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_NAME_allownil)}
    i2d_X509_NAME := ERR_i2d_X509_NAME;
    {$ifend}
    {$if declared(i2d_X509_NAME_introduced)}
    if LibVersion < i2d_X509_NAME_introduced then
    begin
      {$if declared(FC_i2d_X509_NAME)}
      i2d_X509_NAME := FC_i2d_X509_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_NAME_removed)}
    if i2d_X509_NAME_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_NAME)}
      i2d_X509_NAME := _i2d_X509_NAME;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_NAME_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_NAME');
    {$ifend}
  end;
  
  X509_NAME_it := LoadLibFunction(ADllHandle, X509_NAME_it_procname);
  FuncLoadError := not assigned(X509_NAME_it);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_it_allownil)}
    X509_NAME_it := ERR_X509_NAME_it;
    {$ifend}
    {$if declared(X509_NAME_it_introduced)}
    if LibVersion < X509_NAME_it_introduced then
    begin
      {$if declared(FC_X509_NAME_it)}
      X509_NAME_it := FC_X509_NAME_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_it_removed)}
    if X509_NAME_it_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_it)}
      X509_NAME_it := _X509_NAME_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_it_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_it');
    {$ifend}
  end;
  
  X509_NAME_set := LoadLibFunction(ADllHandle, X509_NAME_set_procname);
  FuncLoadError := not assigned(X509_NAME_set);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_set_allownil)}
    X509_NAME_set := ERR_X509_NAME_set;
    {$ifend}
    {$if declared(X509_NAME_set_introduced)}
    if LibVersion < X509_NAME_set_introduced then
    begin
      {$if declared(FC_X509_NAME_set)}
      X509_NAME_set := FC_X509_NAME_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_set_removed)}
    if X509_NAME_set_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_set)}
      X509_NAME_set := _X509_NAME_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_set_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_set');
    {$ifend}
  end;
  
  X509_CINF_new := LoadLibFunction(ADllHandle, X509_CINF_new_procname);
  FuncLoadError := not assigned(X509_CINF_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_CINF_new_allownil)}
    X509_CINF_new := ERR_X509_CINF_new;
    {$ifend}
    {$if declared(X509_CINF_new_introduced)}
    if LibVersion < X509_CINF_new_introduced then
    begin
      {$if declared(FC_X509_CINF_new)}
      X509_CINF_new := FC_X509_CINF_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CINF_new_removed)}
    if X509_CINF_new_removed <= LibVersion then
    begin
      {$if declared(_X509_CINF_new)}
      X509_CINF_new := _X509_CINF_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CINF_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CINF_new');
    {$ifend}
  end;
  
  X509_CINF_free := LoadLibFunction(ADllHandle, X509_CINF_free_procname);
  FuncLoadError := not assigned(X509_CINF_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_CINF_free_allownil)}
    X509_CINF_free := ERR_X509_CINF_free;
    {$ifend}
    {$if declared(X509_CINF_free_introduced)}
    if LibVersion < X509_CINF_free_introduced then
    begin
      {$if declared(FC_X509_CINF_free)}
      X509_CINF_free := FC_X509_CINF_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CINF_free_removed)}
    if X509_CINF_free_removed <= LibVersion then
    begin
      {$if declared(_X509_CINF_free)}
      X509_CINF_free := _X509_CINF_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CINF_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CINF_free');
    {$ifend}
  end;
  
  d2i_X509_CINF := LoadLibFunction(ADllHandle, d2i_X509_CINF_procname);
  FuncLoadError := not assigned(d2i_X509_CINF);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_CINF_allownil)}
    d2i_X509_CINF := ERR_d2i_X509_CINF;
    {$ifend}
    {$if declared(d2i_X509_CINF_introduced)}
    if LibVersion < d2i_X509_CINF_introduced then
    begin
      {$if declared(FC_d2i_X509_CINF)}
      d2i_X509_CINF := FC_d2i_X509_CINF;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_CINF_removed)}
    if d2i_X509_CINF_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_CINF)}
      d2i_X509_CINF := _d2i_X509_CINF;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_CINF_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_CINF');
    {$ifend}
  end;
  
  i2d_X509_CINF := LoadLibFunction(ADllHandle, i2d_X509_CINF_procname);
  FuncLoadError := not assigned(i2d_X509_CINF);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_CINF_allownil)}
    i2d_X509_CINF := ERR_i2d_X509_CINF;
    {$ifend}
    {$if declared(i2d_X509_CINF_introduced)}
    if LibVersion < i2d_X509_CINF_introduced then
    begin
      {$if declared(FC_i2d_X509_CINF)}
      i2d_X509_CINF := FC_i2d_X509_CINF;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_CINF_removed)}
    if i2d_X509_CINF_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_CINF)}
      i2d_X509_CINF := _i2d_X509_CINF;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_CINF_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_CINF');
    {$ifend}
  end;
  
  X509_CINF_it := LoadLibFunction(ADllHandle, X509_CINF_it_procname);
  FuncLoadError := not assigned(X509_CINF_it);
  if FuncLoadError then
  begin
    {$if not defined(X509_CINF_it_allownil)}
    X509_CINF_it := ERR_X509_CINF_it;
    {$ifend}
    {$if declared(X509_CINF_it_introduced)}
    if LibVersion < X509_CINF_it_introduced then
    begin
      {$if declared(FC_X509_CINF_it)}
      X509_CINF_it := FC_X509_CINF_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CINF_it_removed)}
    if X509_CINF_it_removed <= LibVersion then
    begin
      {$if declared(_X509_CINF_it)}
      X509_CINF_it := _X509_CINF_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CINF_it_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CINF_it');
    {$ifend}
  end;
  
  X509_new := LoadLibFunction(ADllHandle, X509_new_procname);
  FuncLoadError := not assigned(X509_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_new_allownil)}
    X509_new := ERR_X509_new;
    {$ifend}
    {$if declared(X509_new_introduced)}
    if LibVersion < X509_new_introduced then
    begin
      {$if declared(FC_X509_new)}
      X509_new := FC_X509_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_new_removed)}
    if X509_new_removed <= LibVersion then
    begin
      {$if declared(_X509_new)}
      X509_new := _X509_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_new');
    {$ifend}
  end;
  
  X509_free := LoadLibFunction(ADllHandle, X509_free_procname);
  FuncLoadError := not assigned(X509_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_free_allownil)}
    X509_free := ERR_X509_free;
    {$ifend}
    {$if declared(X509_free_introduced)}
    if LibVersion < X509_free_introduced then
    begin
      {$if declared(FC_X509_free)}
      X509_free := FC_X509_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_free_removed)}
    if X509_free_removed <= LibVersion then
    begin
      {$if declared(_X509_free)}
      X509_free := _X509_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_free');
    {$ifend}
  end;
  
  d2i_X509 := LoadLibFunction(ADllHandle, d2i_X509_procname);
  FuncLoadError := not assigned(d2i_X509);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_allownil)}
    d2i_X509 := ERR_d2i_X509;
    {$ifend}
    {$if declared(d2i_X509_introduced)}
    if LibVersion < d2i_X509_introduced then
    begin
      {$if declared(FC_d2i_X509)}
      d2i_X509 := FC_d2i_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_removed)}
    if d2i_X509_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509)}
      d2i_X509 := _d2i_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509');
    {$ifend}
  end;
  
  i2d_X509 := LoadLibFunction(ADllHandle, i2d_X509_procname);
  FuncLoadError := not assigned(i2d_X509);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_allownil)}
    i2d_X509 := ERR_i2d_X509;
    {$ifend}
    {$if declared(i2d_X509_introduced)}
    if LibVersion < i2d_X509_introduced then
    begin
      {$if declared(FC_i2d_X509)}
      i2d_X509 := FC_i2d_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_removed)}
    if i2d_X509_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509)}
      i2d_X509 := _i2d_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509');
    {$ifend}
  end;
  
  X509_it := LoadLibFunction(ADllHandle, X509_it_procname);
  FuncLoadError := not assigned(X509_it);
  if FuncLoadError then
  begin
    {$if not defined(X509_it_allownil)}
    X509_it := ERR_X509_it;
    {$ifend}
    {$if declared(X509_it_introduced)}
    if LibVersion < X509_it_introduced then
    begin
      {$if declared(FC_X509_it)}
      X509_it := FC_X509_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_it_removed)}
    if X509_it_removed <= LibVersion then
    begin
      {$if declared(_X509_it)}
      X509_it := _X509_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_it_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_it');
    {$ifend}
  end;
  
  X509_new_ex := LoadLibFunction(ADllHandle, X509_new_ex_procname);
  FuncLoadError := not assigned(X509_new_ex);
  if FuncLoadError then
  begin
    {$if not defined(X509_new_ex_allownil)}
    X509_new_ex := ERR_X509_new_ex;
    {$ifend}
    {$if declared(X509_new_ex_introduced)}
    if LibVersion < X509_new_ex_introduced then
    begin
      {$if declared(FC_X509_new_ex)}
      X509_new_ex := FC_X509_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_new_ex_removed)}
    if X509_new_ex_removed <= LibVersion then
    begin
      {$if declared(_X509_new_ex)}
      X509_new_ex := _X509_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_new_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_new_ex');
    {$ifend}
  end;
  
  X509_CERT_AUX_new := LoadLibFunction(ADllHandle, X509_CERT_AUX_new_procname);
  FuncLoadError := not assigned(X509_CERT_AUX_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_CERT_AUX_new_allownil)}
    X509_CERT_AUX_new := ERR_X509_CERT_AUX_new;
    {$ifend}
    {$if declared(X509_CERT_AUX_new_introduced)}
    if LibVersion < X509_CERT_AUX_new_introduced then
    begin
      {$if declared(FC_X509_CERT_AUX_new)}
      X509_CERT_AUX_new := FC_X509_CERT_AUX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CERT_AUX_new_removed)}
    if X509_CERT_AUX_new_removed <= LibVersion then
    begin
      {$if declared(_X509_CERT_AUX_new)}
      X509_CERT_AUX_new := _X509_CERT_AUX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CERT_AUX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CERT_AUX_new');
    {$ifend}
  end;
  
  X509_CERT_AUX_free := LoadLibFunction(ADllHandle, X509_CERT_AUX_free_procname);
  FuncLoadError := not assigned(X509_CERT_AUX_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_CERT_AUX_free_allownil)}
    X509_CERT_AUX_free := ERR_X509_CERT_AUX_free;
    {$ifend}
    {$if declared(X509_CERT_AUX_free_introduced)}
    if LibVersion < X509_CERT_AUX_free_introduced then
    begin
      {$if declared(FC_X509_CERT_AUX_free)}
      X509_CERT_AUX_free := FC_X509_CERT_AUX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CERT_AUX_free_removed)}
    if X509_CERT_AUX_free_removed <= LibVersion then
    begin
      {$if declared(_X509_CERT_AUX_free)}
      X509_CERT_AUX_free := _X509_CERT_AUX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CERT_AUX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CERT_AUX_free');
    {$ifend}
  end;
  
  d2i_X509_CERT_AUX := LoadLibFunction(ADllHandle, d2i_X509_CERT_AUX_procname);
  FuncLoadError := not assigned(d2i_X509_CERT_AUX);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_CERT_AUX_allownil)}
    d2i_X509_CERT_AUX := ERR_d2i_X509_CERT_AUX;
    {$ifend}
    {$if declared(d2i_X509_CERT_AUX_introduced)}
    if LibVersion < d2i_X509_CERT_AUX_introduced then
    begin
      {$if declared(FC_d2i_X509_CERT_AUX)}
      d2i_X509_CERT_AUX := FC_d2i_X509_CERT_AUX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_CERT_AUX_removed)}
    if d2i_X509_CERT_AUX_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_CERT_AUX)}
      d2i_X509_CERT_AUX := _d2i_X509_CERT_AUX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_CERT_AUX_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_CERT_AUX');
    {$ifend}
  end;
  
  i2d_X509_CERT_AUX := LoadLibFunction(ADllHandle, i2d_X509_CERT_AUX_procname);
  FuncLoadError := not assigned(i2d_X509_CERT_AUX);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_CERT_AUX_allownil)}
    i2d_X509_CERT_AUX := ERR_i2d_X509_CERT_AUX;
    {$ifend}
    {$if declared(i2d_X509_CERT_AUX_introduced)}
    if LibVersion < i2d_X509_CERT_AUX_introduced then
    begin
      {$if declared(FC_i2d_X509_CERT_AUX)}
      i2d_X509_CERT_AUX := FC_i2d_X509_CERT_AUX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_CERT_AUX_removed)}
    if i2d_X509_CERT_AUX_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_CERT_AUX)}
      i2d_X509_CERT_AUX := _i2d_X509_CERT_AUX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_CERT_AUX_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_CERT_AUX');
    {$ifend}
  end;
  
  X509_CERT_AUX_it := LoadLibFunction(ADllHandle, X509_CERT_AUX_it_procname);
  FuncLoadError := not assigned(X509_CERT_AUX_it);
  if FuncLoadError then
  begin
    {$if not defined(X509_CERT_AUX_it_allownil)}
    X509_CERT_AUX_it := ERR_X509_CERT_AUX_it;
    {$ifend}
    {$if declared(X509_CERT_AUX_it_introduced)}
    if LibVersion < X509_CERT_AUX_it_introduced then
    begin
      {$if declared(FC_X509_CERT_AUX_it)}
      X509_CERT_AUX_it := FC_X509_CERT_AUX_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CERT_AUX_it_removed)}
    if X509_CERT_AUX_it_removed <= LibVersion then
    begin
      {$if declared(_X509_CERT_AUX_it)}
      X509_CERT_AUX_it := _X509_CERT_AUX_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CERT_AUX_it_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CERT_AUX_it');
    {$ifend}
  end;
  
  X509_set_ex_data := LoadLibFunction(ADllHandle, X509_set_ex_data_procname);
  FuncLoadError := not assigned(X509_set_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(X509_set_ex_data_allownil)}
    X509_set_ex_data := ERR_X509_set_ex_data;
    {$ifend}
    {$if declared(X509_set_ex_data_introduced)}
    if LibVersion < X509_set_ex_data_introduced then
    begin
      {$if declared(FC_X509_set_ex_data)}
      X509_set_ex_data := FC_X509_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_set_ex_data_removed)}
    if X509_set_ex_data_removed <= LibVersion then
    begin
      {$if declared(_X509_set_ex_data)}
      X509_set_ex_data := _X509_set_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_set_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_set_ex_data');
    {$ifend}
  end;
  
  X509_get_ex_data := LoadLibFunction(ADllHandle, X509_get_ex_data_procname);
  FuncLoadError := not assigned(X509_get_ex_data);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_ex_data_allownil)}
    X509_get_ex_data := ERR_X509_get_ex_data;
    {$ifend}
    {$if declared(X509_get_ex_data_introduced)}
    if LibVersion < X509_get_ex_data_introduced then
    begin
      {$if declared(FC_X509_get_ex_data)}
      X509_get_ex_data := FC_X509_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_ex_data_removed)}
    if X509_get_ex_data_removed <= LibVersion then
    begin
      {$if declared(_X509_get_ex_data)}
      X509_get_ex_data := _X509_get_ex_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_ex_data_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_ex_data');
    {$ifend}
  end;
  
  d2i_X509_AUX := LoadLibFunction(ADllHandle, d2i_X509_AUX_procname);
  FuncLoadError := not assigned(d2i_X509_AUX);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_AUX_allownil)}
    d2i_X509_AUX := ERR_d2i_X509_AUX;
    {$ifend}
    {$if declared(d2i_X509_AUX_introduced)}
    if LibVersion < d2i_X509_AUX_introduced then
    begin
      {$if declared(FC_d2i_X509_AUX)}
      d2i_X509_AUX := FC_d2i_X509_AUX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_AUX_removed)}
    if d2i_X509_AUX_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_AUX)}
      d2i_X509_AUX := _d2i_X509_AUX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_AUX_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_AUX');
    {$ifend}
  end;
  
  i2d_X509_AUX := LoadLibFunction(ADllHandle, i2d_X509_AUX_procname);
  FuncLoadError := not assigned(i2d_X509_AUX);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_AUX_allownil)}
    i2d_X509_AUX := ERR_i2d_X509_AUX;
    {$ifend}
    {$if declared(i2d_X509_AUX_introduced)}
    if LibVersion < i2d_X509_AUX_introduced then
    begin
      {$if declared(FC_i2d_X509_AUX)}
      i2d_X509_AUX := FC_i2d_X509_AUX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_AUX_removed)}
    if i2d_X509_AUX_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_AUX)}
      i2d_X509_AUX := _i2d_X509_AUX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_AUX_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_AUX');
    {$ifend}
  end;
  
  i2d_re_X509_tbs := LoadLibFunction(ADllHandle, i2d_re_X509_tbs_procname);
  FuncLoadError := not assigned(i2d_re_X509_tbs);
  if FuncLoadError then
  begin
    {$if not defined(i2d_re_X509_tbs_allownil)}
    i2d_re_X509_tbs := ERR_i2d_re_X509_tbs;
    {$ifend}
    {$if declared(i2d_re_X509_tbs_introduced)}
    if LibVersion < i2d_re_X509_tbs_introduced then
    begin
      {$if declared(FC_i2d_re_X509_tbs)}
      i2d_re_X509_tbs := FC_i2d_re_X509_tbs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_re_X509_tbs_removed)}
    if i2d_re_X509_tbs_removed <= LibVersion then
    begin
      {$if declared(_i2d_re_X509_tbs)}
      i2d_re_X509_tbs := _i2d_re_X509_tbs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_re_X509_tbs_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_re_X509_tbs');
    {$ifend}
  end;
  
  X509_SIG_INFO_get := LoadLibFunction(ADllHandle, X509_SIG_INFO_get_procname);
  FuncLoadError := not assigned(X509_SIG_INFO_get);
  if FuncLoadError then
  begin
    {$if not defined(X509_SIG_INFO_get_allownil)}
    X509_SIG_INFO_get := ERR_X509_SIG_INFO_get;
    {$ifend}
    {$if declared(X509_SIG_INFO_get_introduced)}
    if LibVersion < X509_SIG_INFO_get_introduced then
    begin
      {$if declared(FC_X509_SIG_INFO_get)}
      X509_SIG_INFO_get := FC_X509_SIG_INFO_get;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_SIG_INFO_get_removed)}
    if X509_SIG_INFO_get_removed <= LibVersion then
    begin
      {$if declared(_X509_SIG_INFO_get)}
      X509_SIG_INFO_get := _X509_SIG_INFO_get;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_SIG_INFO_get_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_SIG_INFO_get');
    {$ifend}
  end;
  
  X509_SIG_INFO_set := LoadLibFunction(ADllHandle, X509_SIG_INFO_set_procname);
  FuncLoadError := not assigned(X509_SIG_INFO_set);
  if FuncLoadError then
  begin
    {$if not defined(X509_SIG_INFO_set_allownil)}
    X509_SIG_INFO_set := ERR_X509_SIG_INFO_set;
    {$ifend}
    {$if declared(X509_SIG_INFO_set_introduced)}
    if LibVersion < X509_SIG_INFO_set_introduced then
    begin
      {$if declared(FC_X509_SIG_INFO_set)}
      X509_SIG_INFO_set := FC_X509_SIG_INFO_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_SIG_INFO_set_removed)}
    if X509_SIG_INFO_set_removed <= LibVersion then
    begin
      {$if declared(_X509_SIG_INFO_set)}
      X509_SIG_INFO_set := _X509_SIG_INFO_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_SIG_INFO_set_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_SIG_INFO_set');
    {$ifend}
  end;
  
  X509_get_signature_info := LoadLibFunction(ADllHandle, X509_get_signature_info_procname);
  FuncLoadError := not assigned(X509_get_signature_info);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_signature_info_allownil)}
    X509_get_signature_info := ERR_X509_get_signature_info;
    {$ifend}
    {$if declared(X509_get_signature_info_introduced)}
    if LibVersion < X509_get_signature_info_introduced then
    begin
      {$if declared(FC_X509_get_signature_info)}
      X509_get_signature_info := FC_X509_get_signature_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_signature_info_removed)}
    if X509_get_signature_info_removed <= LibVersion then
    begin
      {$if declared(_X509_get_signature_info)}
      X509_get_signature_info := _X509_get_signature_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_signature_info_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_signature_info');
    {$ifend}
  end;
  
  X509_get0_signature := LoadLibFunction(ADllHandle, X509_get0_signature_procname);
  FuncLoadError := not assigned(X509_get0_signature);
  if FuncLoadError then
  begin
    {$if not defined(X509_get0_signature_allownil)}
    X509_get0_signature := ERR_X509_get0_signature;
    {$ifend}
    {$if declared(X509_get0_signature_introduced)}
    if LibVersion < X509_get0_signature_introduced then
    begin
      {$if declared(FC_X509_get0_signature)}
      X509_get0_signature := FC_X509_get0_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get0_signature_removed)}
    if X509_get0_signature_removed <= LibVersion then
    begin
      {$if declared(_X509_get0_signature)}
      X509_get0_signature := _X509_get0_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get0_signature_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get0_signature');
    {$ifend}
  end;
  
  X509_get_signature_nid := LoadLibFunction(ADllHandle, X509_get_signature_nid_procname);
  FuncLoadError := not assigned(X509_get_signature_nid);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_signature_nid_allownil)}
    X509_get_signature_nid := ERR_X509_get_signature_nid;
    {$ifend}
    {$if declared(X509_get_signature_nid_introduced)}
    if LibVersion < X509_get_signature_nid_introduced then
    begin
      {$if declared(FC_X509_get_signature_nid)}
      X509_get_signature_nid := FC_X509_get_signature_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_signature_nid_removed)}
    if X509_get_signature_nid_removed <= LibVersion then
    begin
      {$if declared(_X509_get_signature_nid)}
      X509_get_signature_nid := _X509_get_signature_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_signature_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_signature_nid');
    {$ifend}
  end;
  
  X509_set0_distinguishing_id := LoadLibFunction(ADllHandle, X509_set0_distinguishing_id_procname);
  FuncLoadError := not assigned(X509_set0_distinguishing_id);
  if FuncLoadError then
  begin
    {$if not defined(X509_set0_distinguishing_id_allownil)}
    X509_set0_distinguishing_id := ERR_X509_set0_distinguishing_id;
    {$ifend}
    {$if declared(X509_set0_distinguishing_id_introduced)}
    if LibVersion < X509_set0_distinguishing_id_introduced then
    begin
      {$if declared(FC_X509_set0_distinguishing_id)}
      X509_set0_distinguishing_id := FC_X509_set0_distinguishing_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_set0_distinguishing_id_removed)}
    if X509_set0_distinguishing_id_removed <= LibVersion then
    begin
      {$if declared(_X509_set0_distinguishing_id)}
      X509_set0_distinguishing_id := _X509_set0_distinguishing_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_set0_distinguishing_id_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_set0_distinguishing_id');
    {$ifend}
  end;
  
  X509_get0_distinguishing_id := LoadLibFunction(ADllHandle, X509_get0_distinguishing_id_procname);
  FuncLoadError := not assigned(X509_get0_distinguishing_id);
  if FuncLoadError then
  begin
    {$if not defined(X509_get0_distinguishing_id_allownil)}
    X509_get0_distinguishing_id := ERR_X509_get0_distinguishing_id;
    {$ifend}
    {$if declared(X509_get0_distinguishing_id_introduced)}
    if LibVersion < X509_get0_distinguishing_id_introduced then
    begin
      {$if declared(FC_X509_get0_distinguishing_id)}
      X509_get0_distinguishing_id := FC_X509_get0_distinguishing_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get0_distinguishing_id_removed)}
    if X509_get0_distinguishing_id_removed <= LibVersion then
    begin
      {$if declared(_X509_get0_distinguishing_id)}
      X509_get0_distinguishing_id := _X509_get0_distinguishing_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get0_distinguishing_id_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get0_distinguishing_id');
    {$ifend}
  end;
  
  X509_REQ_set0_distinguishing_id := LoadLibFunction(ADllHandle, X509_REQ_set0_distinguishing_id_procname);
  FuncLoadError := not assigned(X509_REQ_set0_distinguishing_id);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_set0_distinguishing_id_allownil)}
    X509_REQ_set0_distinguishing_id := ERR_X509_REQ_set0_distinguishing_id;
    {$ifend}
    {$if declared(X509_REQ_set0_distinguishing_id_introduced)}
    if LibVersion < X509_REQ_set0_distinguishing_id_introduced then
    begin
      {$if declared(FC_X509_REQ_set0_distinguishing_id)}
      X509_REQ_set0_distinguishing_id := FC_X509_REQ_set0_distinguishing_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_set0_distinguishing_id_removed)}
    if X509_REQ_set0_distinguishing_id_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_set0_distinguishing_id)}
      X509_REQ_set0_distinguishing_id := _X509_REQ_set0_distinguishing_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_set0_distinguishing_id_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_set0_distinguishing_id');
    {$ifend}
  end;
  
  X509_REQ_get0_distinguishing_id := LoadLibFunction(ADllHandle, X509_REQ_get0_distinguishing_id_procname);
  FuncLoadError := not assigned(X509_REQ_get0_distinguishing_id);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_get0_distinguishing_id_allownil)}
    X509_REQ_get0_distinguishing_id := ERR_X509_REQ_get0_distinguishing_id;
    {$ifend}
    {$if declared(X509_REQ_get0_distinguishing_id_introduced)}
    if LibVersion < X509_REQ_get0_distinguishing_id_introduced then
    begin
      {$if declared(FC_X509_REQ_get0_distinguishing_id)}
      X509_REQ_get0_distinguishing_id := FC_X509_REQ_get0_distinguishing_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_get0_distinguishing_id_removed)}
    if X509_REQ_get0_distinguishing_id_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_get0_distinguishing_id)}
      X509_REQ_get0_distinguishing_id := _X509_REQ_get0_distinguishing_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_get0_distinguishing_id_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_get0_distinguishing_id');
    {$ifend}
  end;
  
  X509_alias_set1 := LoadLibFunction(ADllHandle, X509_alias_set1_procname);
  FuncLoadError := not assigned(X509_alias_set1);
  if FuncLoadError then
  begin
    {$if not defined(X509_alias_set1_allownil)}
    X509_alias_set1 := ERR_X509_alias_set1;
    {$ifend}
    {$if declared(X509_alias_set1_introduced)}
    if LibVersion < X509_alias_set1_introduced then
    begin
      {$if declared(FC_X509_alias_set1)}
      X509_alias_set1 := FC_X509_alias_set1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_alias_set1_removed)}
    if X509_alias_set1_removed <= LibVersion then
    begin
      {$if declared(_X509_alias_set1)}
      X509_alias_set1 := _X509_alias_set1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_alias_set1_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_alias_set1');
    {$ifend}
  end;
  
  X509_keyid_set1 := LoadLibFunction(ADllHandle, X509_keyid_set1_procname);
  FuncLoadError := not assigned(X509_keyid_set1);
  if FuncLoadError then
  begin
    {$if not defined(X509_keyid_set1_allownil)}
    X509_keyid_set1 := ERR_X509_keyid_set1;
    {$ifend}
    {$if declared(X509_keyid_set1_introduced)}
    if LibVersion < X509_keyid_set1_introduced then
    begin
      {$if declared(FC_X509_keyid_set1)}
      X509_keyid_set1 := FC_X509_keyid_set1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_keyid_set1_removed)}
    if X509_keyid_set1_removed <= LibVersion then
    begin
      {$if declared(_X509_keyid_set1)}
      X509_keyid_set1 := _X509_keyid_set1;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_keyid_set1_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_keyid_set1');
    {$ifend}
  end;
  
  X509_alias_get0 := LoadLibFunction(ADllHandle, X509_alias_get0_procname);
  FuncLoadError := not assigned(X509_alias_get0);
  if FuncLoadError then
  begin
    {$if not defined(X509_alias_get0_allownil)}
    X509_alias_get0 := ERR_X509_alias_get0;
    {$ifend}
    {$if declared(X509_alias_get0_introduced)}
    if LibVersion < X509_alias_get0_introduced then
    begin
      {$if declared(FC_X509_alias_get0)}
      X509_alias_get0 := FC_X509_alias_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_alias_get0_removed)}
    if X509_alias_get0_removed <= LibVersion then
    begin
      {$if declared(_X509_alias_get0)}
      X509_alias_get0 := _X509_alias_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_alias_get0_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_alias_get0');
    {$ifend}
  end;
  
  X509_keyid_get0 := LoadLibFunction(ADllHandle, X509_keyid_get0_procname);
  FuncLoadError := not assigned(X509_keyid_get0);
  if FuncLoadError then
  begin
    {$if not defined(X509_keyid_get0_allownil)}
    X509_keyid_get0 := ERR_X509_keyid_get0;
    {$ifend}
    {$if declared(X509_keyid_get0_introduced)}
    if LibVersion < X509_keyid_get0_introduced then
    begin
      {$if declared(FC_X509_keyid_get0)}
      X509_keyid_get0 := FC_X509_keyid_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_keyid_get0_removed)}
    if X509_keyid_get0_removed <= LibVersion then
    begin
      {$if declared(_X509_keyid_get0)}
      X509_keyid_get0 := _X509_keyid_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_keyid_get0_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_keyid_get0');
    {$ifend}
  end;
  
  X509_REVOKED_new := LoadLibFunction(ADllHandle, X509_REVOKED_new_procname);
  FuncLoadError := not assigned(X509_REVOKED_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_REVOKED_new_allownil)}
    X509_REVOKED_new := ERR_X509_REVOKED_new;
    {$ifend}
    {$if declared(X509_REVOKED_new_introduced)}
    if LibVersion < X509_REVOKED_new_introduced then
    begin
      {$if declared(FC_X509_REVOKED_new)}
      X509_REVOKED_new := FC_X509_REVOKED_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REVOKED_new_removed)}
    if X509_REVOKED_new_removed <= LibVersion then
    begin
      {$if declared(_X509_REVOKED_new)}
      X509_REVOKED_new := _X509_REVOKED_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REVOKED_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REVOKED_new');
    {$ifend}
  end;
  
  X509_REVOKED_free := LoadLibFunction(ADllHandle, X509_REVOKED_free_procname);
  FuncLoadError := not assigned(X509_REVOKED_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_REVOKED_free_allownil)}
    X509_REVOKED_free := ERR_X509_REVOKED_free;
    {$ifend}
    {$if declared(X509_REVOKED_free_introduced)}
    if LibVersion < X509_REVOKED_free_introduced then
    begin
      {$if declared(FC_X509_REVOKED_free)}
      X509_REVOKED_free := FC_X509_REVOKED_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REVOKED_free_removed)}
    if X509_REVOKED_free_removed <= LibVersion then
    begin
      {$if declared(_X509_REVOKED_free)}
      X509_REVOKED_free := _X509_REVOKED_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REVOKED_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REVOKED_free');
    {$ifend}
  end;
  
  d2i_X509_REVOKED := LoadLibFunction(ADllHandle, d2i_X509_REVOKED_procname);
  FuncLoadError := not assigned(d2i_X509_REVOKED);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_REVOKED_allownil)}
    d2i_X509_REVOKED := ERR_d2i_X509_REVOKED;
    {$ifend}
    {$if declared(d2i_X509_REVOKED_introduced)}
    if LibVersion < d2i_X509_REVOKED_introduced then
    begin
      {$if declared(FC_d2i_X509_REVOKED)}
      d2i_X509_REVOKED := FC_d2i_X509_REVOKED;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_REVOKED_removed)}
    if d2i_X509_REVOKED_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_REVOKED)}
      d2i_X509_REVOKED := _d2i_X509_REVOKED;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_REVOKED_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_REVOKED');
    {$ifend}
  end;
  
  i2d_X509_REVOKED := LoadLibFunction(ADllHandle, i2d_X509_REVOKED_procname);
  FuncLoadError := not assigned(i2d_X509_REVOKED);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_REVOKED_allownil)}
    i2d_X509_REVOKED := ERR_i2d_X509_REVOKED;
    {$ifend}
    {$if declared(i2d_X509_REVOKED_introduced)}
    if LibVersion < i2d_X509_REVOKED_introduced then
    begin
      {$if declared(FC_i2d_X509_REVOKED)}
      i2d_X509_REVOKED := FC_i2d_X509_REVOKED;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_REVOKED_removed)}
    if i2d_X509_REVOKED_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_REVOKED)}
      i2d_X509_REVOKED := _i2d_X509_REVOKED;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_REVOKED_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_REVOKED');
    {$ifend}
  end;
  
  X509_REVOKED_it := LoadLibFunction(ADllHandle, X509_REVOKED_it_procname);
  FuncLoadError := not assigned(X509_REVOKED_it);
  if FuncLoadError then
  begin
    {$if not defined(X509_REVOKED_it_allownil)}
    X509_REVOKED_it := ERR_X509_REVOKED_it;
    {$ifend}
    {$if declared(X509_REVOKED_it_introduced)}
    if LibVersion < X509_REVOKED_it_introduced then
    begin
      {$if declared(FC_X509_REVOKED_it)}
      X509_REVOKED_it := FC_X509_REVOKED_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REVOKED_it_removed)}
    if X509_REVOKED_it_removed <= LibVersion then
    begin
      {$if declared(_X509_REVOKED_it)}
      X509_REVOKED_it := _X509_REVOKED_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REVOKED_it_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REVOKED_it');
    {$ifend}
  end;
  
  X509_CRL_INFO_new := LoadLibFunction(ADllHandle, X509_CRL_INFO_new_procname);
  FuncLoadError := not assigned(X509_CRL_INFO_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_INFO_new_allownil)}
    X509_CRL_INFO_new := ERR_X509_CRL_INFO_new;
    {$ifend}
    {$if declared(X509_CRL_INFO_new_introduced)}
    if LibVersion < X509_CRL_INFO_new_introduced then
    begin
      {$if declared(FC_X509_CRL_INFO_new)}
      X509_CRL_INFO_new := FC_X509_CRL_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_INFO_new_removed)}
    if X509_CRL_INFO_new_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_INFO_new)}
      X509_CRL_INFO_new := _X509_CRL_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_INFO_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_INFO_new');
    {$ifend}
  end;
  
  X509_CRL_INFO_free := LoadLibFunction(ADllHandle, X509_CRL_INFO_free_procname);
  FuncLoadError := not assigned(X509_CRL_INFO_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_INFO_free_allownil)}
    X509_CRL_INFO_free := ERR_X509_CRL_INFO_free;
    {$ifend}
    {$if declared(X509_CRL_INFO_free_introduced)}
    if LibVersion < X509_CRL_INFO_free_introduced then
    begin
      {$if declared(FC_X509_CRL_INFO_free)}
      X509_CRL_INFO_free := FC_X509_CRL_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_INFO_free_removed)}
    if X509_CRL_INFO_free_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_INFO_free)}
      X509_CRL_INFO_free := _X509_CRL_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_INFO_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_INFO_free');
    {$ifend}
  end;
  
  d2i_X509_CRL_INFO := LoadLibFunction(ADllHandle, d2i_X509_CRL_INFO_procname);
  FuncLoadError := not assigned(d2i_X509_CRL_INFO);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_CRL_INFO_allownil)}
    d2i_X509_CRL_INFO := ERR_d2i_X509_CRL_INFO;
    {$ifend}
    {$if declared(d2i_X509_CRL_INFO_introduced)}
    if LibVersion < d2i_X509_CRL_INFO_introduced then
    begin
      {$if declared(FC_d2i_X509_CRL_INFO)}
      d2i_X509_CRL_INFO := FC_d2i_X509_CRL_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_CRL_INFO_removed)}
    if d2i_X509_CRL_INFO_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_CRL_INFO)}
      d2i_X509_CRL_INFO := _d2i_X509_CRL_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_CRL_INFO_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_CRL_INFO');
    {$ifend}
  end;
  
  i2d_X509_CRL_INFO := LoadLibFunction(ADllHandle, i2d_X509_CRL_INFO_procname);
  FuncLoadError := not assigned(i2d_X509_CRL_INFO);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_CRL_INFO_allownil)}
    i2d_X509_CRL_INFO := ERR_i2d_X509_CRL_INFO;
    {$ifend}
    {$if declared(i2d_X509_CRL_INFO_introduced)}
    if LibVersion < i2d_X509_CRL_INFO_introduced then
    begin
      {$if declared(FC_i2d_X509_CRL_INFO)}
      i2d_X509_CRL_INFO := FC_i2d_X509_CRL_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_CRL_INFO_removed)}
    if i2d_X509_CRL_INFO_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_CRL_INFO)}
      i2d_X509_CRL_INFO := _i2d_X509_CRL_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_CRL_INFO_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_CRL_INFO');
    {$ifend}
  end;
  
  X509_CRL_INFO_it := LoadLibFunction(ADllHandle, X509_CRL_INFO_it_procname);
  FuncLoadError := not assigned(X509_CRL_INFO_it);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_INFO_it_allownil)}
    X509_CRL_INFO_it := ERR_X509_CRL_INFO_it;
    {$ifend}
    {$if declared(X509_CRL_INFO_it_introduced)}
    if LibVersion < X509_CRL_INFO_it_introduced then
    begin
      {$if declared(FC_X509_CRL_INFO_it)}
      X509_CRL_INFO_it := FC_X509_CRL_INFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_INFO_it_removed)}
    if X509_CRL_INFO_it_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_INFO_it)}
      X509_CRL_INFO_it := _X509_CRL_INFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_INFO_it_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_INFO_it');
    {$ifend}
  end;
  
  X509_CRL_new := LoadLibFunction(ADllHandle, X509_CRL_new_procname);
  FuncLoadError := not assigned(X509_CRL_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_new_allownil)}
    X509_CRL_new := ERR_X509_CRL_new;
    {$ifend}
    {$if declared(X509_CRL_new_introduced)}
    if LibVersion < X509_CRL_new_introduced then
    begin
      {$if declared(FC_X509_CRL_new)}
      X509_CRL_new := FC_X509_CRL_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_new_removed)}
    if X509_CRL_new_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_new)}
      X509_CRL_new := _X509_CRL_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_new');
    {$ifend}
  end;
  
  X509_CRL_free := LoadLibFunction(ADllHandle, X509_CRL_free_procname);
  FuncLoadError := not assigned(X509_CRL_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_free_allownil)}
    X509_CRL_free := ERR_X509_CRL_free;
    {$ifend}
    {$if declared(X509_CRL_free_introduced)}
    if LibVersion < X509_CRL_free_introduced then
    begin
      {$if declared(FC_X509_CRL_free)}
      X509_CRL_free := FC_X509_CRL_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_free_removed)}
    if X509_CRL_free_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_free)}
      X509_CRL_free := _X509_CRL_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_free');
    {$ifend}
  end;
  
  d2i_X509_CRL := LoadLibFunction(ADllHandle, d2i_X509_CRL_procname);
  FuncLoadError := not assigned(d2i_X509_CRL);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_CRL_allownil)}
    d2i_X509_CRL := ERR_d2i_X509_CRL;
    {$ifend}
    {$if declared(d2i_X509_CRL_introduced)}
    if LibVersion < d2i_X509_CRL_introduced then
    begin
      {$if declared(FC_d2i_X509_CRL)}
      d2i_X509_CRL := FC_d2i_X509_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_CRL_removed)}
    if d2i_X509_CRL_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_CRL)}
      d2i_X509_CRL := _d2i_X509_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_CRL_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_CRL');
    {$ifend}
  end;
  
  i2d_X509_CRL := LoadLibFunction(ADllHandle, i2d_X509_CRL_procname);
  FuncLoadError := not assigned(i2d_X509_CRL);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_CRL_allownil)}
    i2d_X509_CRL := ERR_i2d_X509_CRL;
    {$ifend}
    {$if declared(i2d_X509_CRL_introduced)}
    if LibVersion < i2d_X509_CRL_introduced then
    begin
      {$if declared(FC_i2d_X509_CRL)}
      i2d_X509_CRL := FC_i2d_X509_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_CRL_removed)}
    if i2d_X509_CRL_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_CRL)}
      i2d_X509_CRL := _i2d_X509_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_CRL_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_CRL');
    {$ifend}
  end;
  
  X509_CRL_it := LoadLibFunction(ADllHandle, X509_CRL_it_procname);
  FuncLoadError := not assigned(X509_CRL_it);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_it_allownil)}
    X509_CRL_it := ERR_X509_CRL_it;
    {$ifend}
    {$if declared(X509_CRL_it_introduced)}
    if LibVersion < X509_CRL_it_introduced then
    begin
      {$if declared(FC_X509_CRL_it)}
      X509_CRL_it := FC_X509_CRL_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_it_removed)}
    if X509_CRL_it_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_it)}
      X509_CRL_it := _X509_CRL_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_it_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_it');
    {$ifend}
  end;
  
  X509_CRL_new_ex := LoadLibFunction(ADllHandle, X509_CRL_new_ex_procname);
  FuncLoadError := not assigned(X509_CRL_new_ex);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_new_ex_allownil)}
    X509_CRL_new_ex := ERR_X509_CRL_new_ex;
    {$ifend}
    {$if declared(X509_CRL_new_ex_introduced)}
    if LibVersion < X509_CRL_new_ex_introduced then
    begin
      {$if declared(FC_X509_CRL_new_ex)}
      X509_CRL_new_ex := FC_X509_CRL_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_new_ex_removed)}
    if X509_CRL_new_ex_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_new_ex)}
      X509_CRL_new_ex := _X509_CRL_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_new_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_new_ex');
    {$ifend}
  end;
  
  X509_CRL_add0_revoked := LoadLibFunction(ADllHandle, X509_CRL_add0_revoked_procname);
  FuncLoadError := not assigned(X509_CRL_add0_revoked);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_add0_revoked_allownil)}
    X509_CRL_add0_revoked := ERR_X509_CRL_add0_revoked;
    {$ifend}
    {$if declared(X509_CRL_add0_revoked_introduced)}
    if LibVersion < X509_CRL_add0_revoked_introduced then
    begin
      {$if declared(FC_X509_CRL_add0_revoked)}
      X509_CRL_add0_revoked := FC_X509_CRL_add0_revoked;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_add0_revoked_removed)}
    if X509_CRL_add0_revoked_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_add0_revoked)}
      X509_CRL_add0_revoked := _X509_CRL_add0_revoked;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_add0_revoked_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_add0_revoked');
    {$ifend}
  end;
  
  X509_CRL_get0_by_serial := LoadLibFunction(ADllHandle, X509_CRL_get0_by_serial_procname);
  FuncLoadError := not assigned(X509_CRL_get0_by_serial);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_get0_by_serial_allownil)}
    X509_CRL_get0_by_serial := ERR_X509_CRL_get0_by_serial;
    {$ifend}
    {$if declared(X509_CRL_get0_by_serial_introduced)}
    if LibVersion < X509_CRL_get0_by_serial_introduced then
    begin
      {$if declared(FC_X509_CRL_get0_by_serial)}
      X509_CRL_get0_by_serial := FC_X509_CRL_get0_by_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_get0_by_serial_removed)}
    if X509_CRL_get0_by_serial_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_get0_by_serial)}
      X509_CRL_get0_by_serial := _X509_CRL_get0_by_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_get0_by_serial_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_get0_by_serial');
    {$ifend}
  end;
  
  X509_CRL_get0_by_cert := LoadLibFunction(ADllHandle, X509_CRL_get0_by_cert_procname);
  FuncLoadError := not assigned(X509_CRL_get0_by_cert);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_get0_by_cert_allownil)}
    X509_CRL_get0_by_cert := ERR_X509_CRL_get0_by_cert;
    {$ifend}
    {$if declared(X509_CRL_get0_by_cert_introduced)}
    if LibVersion < X509_CRL_get0_by_cert_introduced then
    begin
      {$if declared(FC_X509_CRL_get0_by_cert)}
      X509_CRL_get0_by_cert := FC_X509_CRL_get0_by_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_get0_by_cert_removed)}
    if X509_CRL_get0_by_cert_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_get0_by_cert)}
      X509_CRL_get0_by_cert := _X509_CRL_get0_by_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_get0_by_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_get0_by_cert');
    {$ifend}
  end;
  
  X509_PKEY_new := LoadLibFunction(ADllHandle, X509_PKEY_new_procname);
  FuncLoadError := not assigned(X509_PKEY_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_PKEY_new_allownil)}
    X509_PKEY_new := ERR_X509_PKEY_new;
    {$ifend}
    {$if declared(X509_PKEY_new_introduced)}
    if LibVersion < X509_PKEY_new_introduced then
    begin
      {$if declared(FC_X509_PKEY_new)}
      X509_PKEY_new := FC_X509_PKEY_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PKEY_new_removed)}
    if X509_PKEY_new_removed <= LibVersion then
    begin
      {$if declared(_X509_PKEY_new)}
      X509_PKEY_new := _X509_PKEY_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PKEY_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PKEY_new');
    {$ifend}
  end;
  
  X509_PKEY_free := LoadLibFunction(ADllHandle, X509_PKEY_free_procname);
  FuncLoadError := not assigned(X509_PKEY_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_PKEY_free_allownil)}
    X509_PKEY_free := ERR_X509_PKEY_free;
    {$ifend}
    {$if declared(X509_PKEY_free_introduced)}
    if LibVersion < X509_PKEY_free_introduced then
    begin
      {$if declared(FC_X509_PKEY_free)}
      X509_PKEY_free := FC_X509_PKEY_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PKEY_free_removed)}
    if X509_PKEY_free_removed <= LibVersion then
    begin
      {$if declared(_X509_PKEY_free)}
      X509_PKEY_free := _X509_PKEY_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PKEY_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PKEY_free');
    {$ifend}
  end;
  
  NETSCAPE_SPKI_new := LoadLibFunction(ADllHandle, NETSCAPE_SPKI_new_procname);
  FuncLoadError := not assigned(NETSCAPE_SPKI_new);
  if FuncLoadError then
  begin
    {$if not defined(NETSCAPE_SPKI_new_allownil)}
    NETSCAPE_SPKI_new := ERR_NETSCAPE_SPKI_new;
    {$ifend}
    {$if declared(NETSCAPE_SPKI_new_introduced)}
    if LibVersion < NETSCAPE_SPKI_new_introduced then
    begin
      {$if declared(FC_NETSCAPE_SPKI_new)}
      NETSCAPE_SPKI_new := FC_NETSCAPE_SPKI_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NETSCAPE_SPKI_new_removed)}
    if NETSCAPE_SPKI_new_removed <= LibVersion then
    begin
      {$if declared(_NETSCAPE_SPKI_new)}
      NETSCAPE_SPKI_new := _NETSCAPE_SPKI_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NETSCAPE_SPKI_new_allownil)}
    if FuncLoadError then
      AFailed.Add('NETSCAPE_SPKI_new');
    {$ifend}
  end;
  
  NETSCAPE_SPKI_free := LoadLibFunction(ADllHandle, NETSCAPE_SPKI_free_procname);
  FuncLoadError := not assigned(NETSCAPE_SPKI_free);
  if FuncLoadError then
  begin
    {$if not defined(NETSCAPE_SPKI_free_allownil)}
    NETSCAPE_SPKI_free := ERR_NETSCAPE_SPKI_free;
    {$ifend}
    {$if declared(NETSCAPE_SPKI_free_introduced)}
    if LibVersion < NETSCAPE_SPKI_free_introduced then
    begin
      {$if declared(FC_NETSCAPE_SPKI_free)}
      NETSCAPE_SPKI_free := FC_NETSCAPE_SPKI_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NETSCAPE_SPKI_free_removed)}
    if NETSCAPE_SPKI_free_removed <= LibVersion then
    begin
      {$if declared(_NETSCAPE_SPKI_free)}
      NETSCAPE_SPKI_free := _NETSCAPE_SPKI_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NETSCAPE_SPKI_free_allownil)}
    if FuncLoadError then
      AFailed.Add('NETSCAPE_SPKI_free');
    {$ifend}
  end;
  
  d2i_NETSCAPE_SPKI := LoadLibFunction(ADllHandle, d2i_NETSCAPE_SPKI_procname);
  FuncLoadError := not assigned(d2i_NETSCAPE_SPKI);
  if FuncLoadError then
  begin
    {$if not defined(d2i_NETSCAPE_SPKI_allownil)}
    d2i_NETSCAPE_SPKI := ERR_d2i_NETSCAPE_SPKI;
    {$ifend}
    {$if declared(d2i_NETSCAPE_SPKI_introduced)}
    if LibVersion < d2i_NETSCAPE_SPKI_introduced then
    begin
      {$if declared(FC_d2i_NETSCAPE_SPKI)}
      d2i_NETSCAPE_SPKI := FC_d2i_NETSCAPE_SPKI;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_NETSCAPE_SPKI_removed)}
    if d2i_NETSCAPE_SPKI_removed <= LibVersion then
    begin
      {$if declared(_d2i_NETSCAPE_SPKI)}
      d2i_NETSCAPE_SPKI := _d2i_NETSCAPE_SPKI;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_NETSCAPE_SPKI_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_NETSCAPE_SPKI');
    {$ifend}
  end;
  
  i2d_NETSCAPE_SPKI := LoadLibFunction(ADllHandle, i2d_NETSCAPE_SPKI_procname);
  FuncLoadError := not assigned(i2d_NETSCAPE_SPKI);
  if FuncLoadError then
  begin
    {$if not defined(i2d_NETSCAPE_SPKI_allownil)}
    i2d_NETSCAPE_SPKI := ERR_i2d_NETSCAPE_SPKI;
    {$ifend}
    {$if declared(i2d_NETSCAPE_SPKI_introduced)}
    if LibVersion < i2d_NETSCAPE_SPKI_introduced then
    begin
      {$if declared(FC_i2d_NETSCAPE_SPKI)}
      i2d_NETSCAPE_SPKI := FC_i2d_NETSCAPE_SPKI;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_NETSCAPE_SPKI_removed)}
    if i2d_NETSCAPE_SPKI_removed <= LibVersion then
    begin
      {$if declared(_i2d_NETSCAPE_SPKI)}
      i2d_NETSCAPE_SPKI := _i2d_NETSCAPE_SPKI;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_NETSCAPE_SPKI_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_NETSCAPE_SPKI');
    {$ifend}
  end;
  
  NETSCAPE_SPKI_it := LoadLibFunction(ADllHandle, NETSCAPE_SPKI_it_procname);
  FuncLoadError := not assigned(NETSCAPE_SPKI_it);
  if FuncLoadError then
  begin
    {$if not defined(NETSCAPE_SPKI_it_allownil)}
    NETSCAPE_SPKI_it := ERR_NETSCAPE_SPKI_it;
    {$ifend}
    {$if declared(NETSCAPE_SPKI_it_introduced)}
    if LibVersion < NETSCAPE_SPKI_it_introduced then
    begin
      {$if declared(FC_NETSCAPE_SPKI_it)}
      NETSCAPE_SPKI_it := FC_NETSCAPE_SPKI_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NETSCAPE_SPKI_it_removed)}
    if NETSCAPE_SPKI_it_removed <= LibVersion then
    begin
      {$if declared(_NETSCAPE_SPKI_it)}
      NETSCAPE_SPKI_it := _NETSCAPE_SPKI_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NETSCAPE_SPKI_it_allownil)}
    if FuncLoadError then
      AFailed.Add('NETSCAPE_SPKI_it');
    {$ifend}
  end;
  
  NETSCAPE_SPKAC_new := LoadLibFunction(ADllHandle, NETSCAPE_SPKAC_new_procname);
  FuncLoadError := not assigned(NETSCAPE_SPKAC_new);
  if FuncLoadError then
  begin
    {$if not defined(NETSCAPE_SPKAC_new_allownil)}
    NETSCAPE_SPKAC_new := ERR_NETSCAPE_SPKAC_new;
    {$ifend}
    {$if declared(NETSCAPE_SPKAC_new_introduced)}
    if LibVersion < NETSCAPE_SPKAC_new_introduced then
    begin
      {$if declared(FC_NETSCAPE_SPKAC_new)}
      NETSCAPE_SPKAC_new := FC_NETSCAPE_SPKAC_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NETSCAPE_SPKAC_new_removed)}
    if NETSCAPE_SPKAC_new_removed <= LibVersion then
    begin
      {$if declared(_NETSCAPE_SPKAC_new)}
      NETSCAPE_SPKAC_new := _NETSCAPE_SPKAC_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NETSCAPE_SPKAC_new_allownil)}
    if FuncLoadError then
      AFailed.Add('NETSCAPE_SPKAC_new');
    {$ifend}
  end;
  
  NETSCAPE_SPKAC_free := LoadLibFunction(ADllHandle, NETSCAPE_SPKAC_free_procname);
  FuncLoadError := not assigned(NETSCAPE_SPKAC_free);
  if FuncLoadError then
  begin
    {$if not defined(NETSCAPE_SPKAC_free_allownil)}
    NETSCAPE_SPKAC_free := ERR_NETSCAPE_SPKAC_free;
    {$ifend}
    {$if declared(NETSCAPE_SPKAC_free_introduced)}
    if LibVersion < NETSCAPE_SPKAC_free_introduced then
    begin
      {$if declared(FC_NETSCAPE_SPKAC_free)}
      NETSCAPE_SPKAC_free := FC_NETSCAPE_SPKAC_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NETSCAPE_SPKAC_free_removed)}
    if NETSCAPE_SPKAC_free_removed <= LibVersion then
    begin
      {$if declared(_NETSCAPE_SPKAC_free)}
      NETSCAPE_SPKAC_free := _NETSCAPE_SPKAC_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NETSCAPE_SPKAC_free_allownil)}
    if FuncLoadError then
      AFailed.Add('NETSCAPE_SPKAC_free');
    {$ifend}
  end;
  
  d2i_NETSCAPE_SPKAC := LoadLibFunction(ADllHandle, d2i_NETSCAPE_SPKAC_procname);
  FuncLoadError := not assigned(d2i_NETSCAPE_SPKAC);
  if FuncLoadError then
  begin
    {$if not defined(d2i_NETSCAPE_SPKAC_allownil)}
    d2i_NETSCAPE_SPKAC := ERR_d2i_NETSCAPE_SPKAC;
    {$ifend}
    {$if declared(d2i_NETSCAPE_SPKAC_introduced)}
    if LibVersion < d2i_NETSCAPE_SPKAC_introduced then
    begin
      {$if declared(FC_d2i_NETSCAPE_SPKAC)}
      d2i_NETSCAPE_SPKAC := FC_d2i_NETSCAPE_SPKAC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_NETSCAPE_SPKAC_removed)}
    if d2i_NETSCAPE_SPKAC_removed <= LibVersion then
    begin
      {$if declared(_d2i_NETSCAPE_SPKAC)}
      d2i_NETSCAPE_SPKAC := _d2i_NETSCAPE_SPKAC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_NETSCAPE_SPKAC_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_NETSCAPE_SPKAC');
    {$ifend}
  end;
  
  i2d_NETSCAPE_SPKAC := LoadLibFunction(ADllHandle, i2d_NETSCAPE_SPKAC_procname);
  FuncLoadError := not assigned(i2d_NETSCAPE_SPKAC);
  if FuncLoadError then
  begin
    {$if not defined(i2d_NETSCAPE_SPKAC_allownil)}
    i2d_NETSCAPE_SPKAC := ERR_i2d_NETSCAPE_SPKAC;
    {$ifend}
    {$if declared(i2d_NETSCAPE_SPKAC_introduced)}
    if LibVersion < i2d_NETSCAPE_SPKAC_introduced then
    begin
      {$if declared(FC_i2d_NETSCAPE_SPKAC)}
      i2d_NETSCAPE_SPKAC := FC_i2d_NETSCAPE_SPKAC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_NETSCAPE_SPKAC_removed)}
    if i2d_NETSCAPE_SPKAC_removed <= LibVersion then
    begin
      {$if declared(_i2d_NETSCAPE_SPKAC)}
      i2d_NETSCAPE_SPKAC := _i2d_NETSCAPE_SPKAC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_NETSCAPE_SPKAC_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_NETSCAPE_SPKAC');
    {$ifend}
  end;
  
  NETSCAPE_SPKAC_it := LoadLibFunction(ADllHandle, NETSCAPE_SPKAC_it_procname);
  FuncLoadError := not assigned(NETSCAPE_SPKAC_it);
  if FuncLoadError then
  begin
    {$if not defined(NETSCAPE_SPKAC_it_allownil)}
    NETSCAPE_SPKAC_it := ERR_NETSCAPE_SPKAC_it;
    {$ifend}
    {$if declared(NETSCAPE_SPKAC_it_introduced)}
    if LibVersion < NETSCAPE_SPKAC_it_introduced then
    begin
      {$if declared(FC_NETSCAPE_SPKAC_it)}
      NETSCAPE_SPKAC_it := FC_NETSCAPE_SPKAC_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NETSCAPE_SPKAC_it_removed)}
    if NETSCAPE_SPKAC_it_removed <= LibVersion then
    begin
      {$if declared(_NETSCAPE_SPKAC_it)}
      NETSCAPE_SPKAC_it := _NETSCAPE_SPKAC_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NETSCAPE_SPKAC_it_allownil)}
    if FuncLoadError then
      AFailed.Add('NETSCAPE_SPKAC_it');
    {$ifend}
  end;
  
  NETSCAPE_CERT_SEQUENCE_new := LoadLibFunction(ADllHandle, NETSCAPE_CERT_SEQUENCE_new_procname);
  FuncLoadError := not assigned(NETSCAPE_CERT_SEQUENCE_new);
  if FuncLoadError then
  begin
    {$if not defined(NETSCAPE_CERT_SEQUENCE_new_allownil)}
    NETSCAPE_CERT_SEQUENCE_new := ERR_NETSCAPE_CERT_SEQUENCE_new;
    {$ifend}
    {$if declared(NETSCAPE_CERT_SEQUENCE_new_introduced)}
    if LibVersion < NETSCAPE_CERT_SEQUENCE_new_introduced then
    begin
      {$if declared(FC_NETSCAPE_CERT_SEQUENCE_new)}
      NETSCAPE_CERT_SEQUENCE_new := FC_NETSCAPE_CERT_SEQUENCE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NETSCAPE_CERT_SEQUENCE_new_removed)}
    if NETSCAPE_CERT_SEQUENCE_new_removed <= LibVersion then
    begin
      {$if declared(_NETSCAPE_CERT_SEQUENCE_new)}
      NETSCAPE_CERT_SEQUENCE_new := _NETSCAPE_CERT_SEQUENCE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NETSCAPE_CERT_SEQUENCE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('NETSCAPE_CERT_SEQUENCE_new');
    {$ifend}
  end;
  
  NETSCAPE_CERT_SEQUENCE_free := LoadLibFunction(ADllHandle, NETSCAPE_CERT_SEQUENCE_free_procname);
  FuncLoadError := not assigned(NETSCAPE_CERT_SEQUENCE_free);
  if FuncLoadError then
  begin
    {$if not defined(NETSCAPE_CERT_SEQUENCE_free_allownil)}
    NETSCAPE_CERT_SEQUENCE_free := ERR_NETSCAPE_CERT_SEQUENCE_free;
    {$ifend}
    {$if declared(NETSCAPE_CERT_SEQUENCE_free_introduced)}
    if LibVersion < NETSCAPE_CERT_SEQUENCE_free_introduced then
    begin
      {$if declared(FC_NETSCAPE_CERT_SEQUENCE_free)}
      NETSCAPE_CERT_SEQUENCE_free := FC_NETSCAPE_CERT_SEQUENCE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NETSCAPE_CERT_SEQUENCE_free_removed)}
    if NETSCAPE_CERT_SEQUENCE_free_removed <= LibVersion then
    begin
      {$if declared(_NETSCAPE_CERT_SEQUENCE_free)}
      NETSCAPE_CERT_SEQUENCE_free := _NETSCAPE_CERT_SEQUENCE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NETSCAPE_CERT_SEQUENCE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('NETSCAPE_CERT_SEQUENCE_free');
    {$ifend}
  end;
  
  d2i_NETSCAPE_CERT_SEQUENCE := LoadLibFunction(ADllHandle, d2i_NETSCAPE_CERT_SEQUENCE_procname);
  FuncLoadError := not assigned(d2i_NETSCAPE_CERT_SEQUENCE);
  if FuncLoadError then
  begin
    {$if not defined(d2i_NETSCAPE_CERT_SEQUENCE_allownil)}
    d2i_NETSCAPE_CERT_SEQUENCE := ERR_d2i_NETSCAPE_CERT_SEQUENCE;
    {$ifend}
    {$if declared(d2i_NETSCAPE_CERT_SEQUENCE_introduced)}
    if LibVersion < d2i_NETSCAPE_CERT_SEQUENCE_introduced then
    begin
      {$if declared(FC_d2i_NETSCAPE_CERT_SEQUENCE)}
      d2i_NETSCAPE_CERT_SEQUENCE := FC_d2i_NETSCAPE_CERT_SEQUENCE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_NETSCAPE_CERT_SEQUENCE_removed)}
    if d2i_NETSCAPE_CERT_SEQUENCE_removed <= LibVersion then
    begin
      {$if declared(_d2i_NETSCAPE_CERT_SEQUENCE)}
      d2i_NETSCAPE_CERT_SEQUENCE := _d2i_NETSCAPE_CERT_SEQUENCE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_NETSCAPE_CERT_SEQUENCE_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_NETSCAPE_CERT_SEQUENCE');
    {$ifend}
  end;
  
  i2d_NETSCAPE_CERT_SEQUENCE := LoadLibFunction(ADllHandle, i2d_NETSCAPE_CERT_SEQUENCE_procname);
  FuncLoadError := not assigned(i2d_NETSCAPE_CERT_SEQUENCE);
  if FuncLoadError then
  begin
    {$if not defined(i2d_NETSCAPE_CERT_SEQUENCE_allownil)}
    i2d_NETSCAPE_CERT_SEQUENCE := ERR_i2d_NETSCAPE_CERT_SEQUENCE;
    {$ifend}
    {$if declared(i2d_NETSCAPE_CERT_SEQUENCE_introduced)}
    if LibVersion < i2d_NETSCAPE_CERT_SEQUENCE_introduced then
    begin
      {$if declared(FC_i2d_NETSCAPE_CERT_SEQUENCE)}
      i2d_NETSCAPE_CERT_SEQUENCE := FC_i2d_NETSCAPE_CERT_SEQUENCE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_NETSCAPE_CERT_SEQUENCE_removed)}
    if i2d_NETSCAPE_CERT_SEQUENCE_removed <= LibVersion then
    begin
      {$if declared(_i2d_NETSCAPE_CERT_SEQUENCE)}
      i2d_NETSCAPE_CERT_SEQUENCE := _i2d_NETSCAPE_CERT_SEQUENCE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_NETSCAPE_CERT_SEQUENCE_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_NETSCAPE_CERT_SEQUENCE');
    {$ifend}
  end;
  
  NETSCAPE_CERT_SEQUENCE_it := LoadLibFunction(ADllHandle, NETSCAPE_CERT_SEQUENCE_it_procname);
  FuncLoadError := not assigned(NETSCAPE_CERT_SEQUENCE_it);
  if FuncLoadError then
  begin
    {$if not defined(NETSCAPE_CERT_SEQUENCE_it_allownil)}
    NETSCAPE_CERT_SEQUENCE_it := ERR_NETSCAPE_CERT_SEQUENCE_it;
    {$ifend}
    {$if declared(NETSCAPE_CERT_SEQUENCE_it_introduced)}
    if LibVersion < NETSCAPE_CERT_SEQUENCE_it_introduced then
    begin
      {$if declared(FC_NETSCAPE_CERT_SEQUENCE_it)}
      NETSCAPE_CERT_SEQUENCE_it := FC_NETSCAPE_CERT_SEQUENCE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NETSCAPE_CERT_SEQUENCE_it_removed)}
    if NETSCAPE_CERT_SEQUENCE_it_removed <= LibVersion then
    begin
      {$if declared(_NETSCAPE_CERT_SEQUENCE_it)}
      NETSCAPE_CERT_SEQUENCE_it := _NETSCAPE_CERT_SEQUENCE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NETSCAPE_CERT_SEQUENCE_it_allownil)}
    if FuncLoadError then
      AFailed.Add('NETSCAPE_CERT_SEQUENCE_it');
    {$ifend}
  end;
  
  X509_INFO_new := LoadLibFunction(ADllHandle, X509_INFO_new_procname);
  FuncLoadError := not assigned(X509_INFO_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_INFO_new_allownil)}
    X509_INFO_new := ERR_X509_INFO_new;
    {$ifend}
    {$if declared(X509_INFO_new_introduced)}
    if LibVersion < X509_INFO_new_introduced then
    begin
      {$if declared(FC_X509_INFO_new)}
      X509_INFO_new := FC_X509_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_INFO_new_removed)}
    if X509_INFO_new_removed <= LibVersion then
    begin
      {$if declared(_X509_INFO_new)}
      X509_INFO_new := _X509_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_INFO_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_INFO_new');
    {$ifend}
  end;
  
  X509_INFO_free := LoadLibFunction(ADllHandle, X509_INFO_free_procname);
  FuncLoadError := not assigned(X509_INFO_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_INFO_free_allownil)}
    X509_INFO_free := ERR_X509_INFO_free;
    {$ifend}
    {$if declared(X509_INFO_free_introduced)}
    if LibVersion < X509_INFO_free_introduced then
    begin
      {$if declared(FC_X509_INFO_free)}
      X509_INFO_free := FC_X509_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_INFO_free_removed)}
    if X509_INFO_free_removed <= LibVersion then
    begin
      {$if declared(_X509_INFO_free)}
      X509_INFO_free := _X509_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_INFO_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_INFO_free');
    {$ifend}
  end;
  
  X509_NAME_oneline := LoadLibFunction(ADllHandle, X509_NAME_oneline_procname);
  FuncLoadError := not assigned(X509_NAME_oneline);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_oneline_allownil)}
    X509_NAME_oneline := ERR_X509_NAME_oneline;
    {$ifend}
    {$if declared(X509_NAME_oneline_introduced)}
    if LibVersion < X509_NAME_oneline_introduced then
    begin
      {$if declared(FC_X509_NAME_oneline)}
      X509_NAME_oneline := FC_X509_NAME_oneline;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_oneline_removed)}
    if X509_NAME_oneline_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_oneline)}
      X509_NAME_oneline := _X509_NAME_oneline;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_oneline_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_oneline');
    {$ifend}
  end;
  
  ASN1_verify := LoadLibFunction(ADllHandle, ASN1_verify_procname);
  FuncLoadError := not assigned(ASN1_verify);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_verify_allownil)}
    ASN1_verify := ERR_ASN1_verify;
    {$ifend}
    {$if declared(ASN1_verify_introduced)}
    if LibVersion < ASN1_verify_introduced then
    begin
      {$if declared(FC_ASN1_verify)}
      ASN1_verify := FC_ASN1_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_verify_removed)}
    if ASN1_verify_removed <= LibVersion then
    begin
      {$if declared(_ASN1_verify)}
      ASN1_verify := _ASN1_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_verify');
    {$ifend}
  end;
  
  ASN1_digest := LoadLibFunction(ADllHandle, ASN1_digest_procname);
  FuncLoadError := not assigned(ASN1_digest);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_digest_allownil)}
    ASN1_digest := ERR_ASN1_digest;
    {$ifend}
    {$if declared(ASN1_digest_introduced)}
    if LibVersion < ASN1_digest_introduced then
    begin
      {$if declared(FC_ASN1_digest)}
      ASN1_digest := FC_ASN1_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_digest_removed)}
    if ASN1_digest_removed <= LibVersion then
    begin
      {$if declared(_ASN1_digest)}
      ASN1_digest := _ASN1_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_digest');
    {$ifend}
  end;
  
  ASN1_sign := LoadLibFunction(ADllHandle, ASN1_sign_procname);
  FuncLoadError := not assigned(ASN1_sign);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_sign_allownil)}
    ASN1_sign := ERR_ASN1_sign;
    {$ifend}
    {$if declared(ASN1_sign_introduced)}
    if LibVersion < ASN1_sign_introduced then
    begin
      {$if declared(FC_ASN1_sign)}
      ASN1_sign := FC_ASN1_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_sign_removed)}
    if ASN1_sign_removed <= LibVersion then
    begin
      {$if declared(_ASN1_sign)}
      ASN1_sign := _ASN1_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_sign');
    {$ifend}
  end;
  
  ASN1_item_digest := LoadLibFunction(ADllHandle, ASN1_item_digest_procname);
  FuncLoadError := not assigned(ASN1_item_digest);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_digest_allownil)}
    ASN1_item_digest := ERR_ASN1_item_digest;
    {$ifend}
    {$if declared(ASN1_item_digest_introduced)}
    if LibVersion < ASN1_item_digest_introduced then
    begin
      {$if declared(FC_ASN1_item_digest)}
      ASN1_item_digest := FC_ASN1_item_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_digest_removed)}
    if ASN1_item_digest_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_digest)}
      ASN1_item_digest := _ASN1_item_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_digest');
    {$ifend}
  end;
  
  ASN1_item_verify := LoadLibFunction(ADllHandle, ASN1_item_verify_procname);
  FuncLoadError := not assigned(ASN1_item_verify);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_verify_allownil)}
    ASN1_item_verify := ERR_ASN1_item_verify;
    {$ifend}
    {$if declared(ASN1_item_verify_introduced)}
    if LibVersion < ASN1_item_verify_introduced then
    begin
      {$if declared(FC_ASN1_item_verify)}
      ASN1_item_verify := FC_ASN1_item_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_verify_removed)}
    if ASN1_item_verify_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_verify)}
      ASN1_item_verify := _ASN1_item_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_verify');
    {$ifend}
  end;
  
  ASN1_item_verify_ctx := LoadLibFunction(ADllHandle, ASN1_item_verify_ctx_procname);
  FuncLoadError := not assigned(ASN1_item_verify_ctx);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_verify_ctx_allownil)}
    ASN1_item_verify_ctx := ERR_ASN1_item_verify_ctx;
    {$ifend}
    {$if declared(ASN1_item_verify_ctx_introduced)}
    if LibVersion < ASN1_item_verify_ctx_introduced then
    begin
      {$if declared(FC_ASN1_item_verify_ctx)}
      ASN1_item_verify_ctx := FC_ASN1_item_verify_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_verify_ctx_removed)}
    if ASN1_item_verify_ctx_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_verify_ctx)}
      ASN1_item_verify_ctx := _ASN1_item_verify_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_verify_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_verify_ctx');
    {$ifend}
  end;
  
  ASN1_item_sign := LoadLibFunction(ADllHandle, ASN1_item_sign_procname);
  FuncLoadError := not assigned(ASN1_item_sign);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_sign_allownil)}
    ASN1_item_sign := ERR_ASN1_item_sign;
    {$ifend}
    {$if declared(ASN1_item_sign_introduced)}
    if LibVersion < ASN1_item_sign_introduced then
    begin
      {$if declared(FC_ASN1_item_sign)}
      ASN1_item_sign := FC_ASN1_item_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_sign_removed)}
    if ASN1_item_sign_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_sign)}
      ASN1_item_sign := _ASN1_item_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_sign');
    {$ifend}
  end;
  
  ASN1_item_sign_ctx := LoadLibFunction(ADllHandle, ASN1_item_sign_ctx_procname);
  FuncLoadError := not assigned(ASN1_item_sign_ctx);
  if FuncLoadError then
  begin
    {$if not defined(ASN1_item_sign_ctx_allownil)}
    ASN1_item_sign_ctx := ERR_ASN1_item_sign_ctx;
    {$ifend}
    {$if declared(ASN1_item_sign_ctx_introduced)}
    if LibVersion < ASN1_item_sign_ctx_introduced then
    begin
      {$if declared(FC_ASN1_item_sign_ctx)}
      ASN1_item_sign_ctx := FC_ASN1_item_sign_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ASN1_item_sign_ctx_removed)}
    if ASN1_item_sign_ctx_removed <= LibVersion then
    begin
      {$if declared(_ASN1_item_sign_ctx)}
      ASN1_item_sign_ctx := _ASN1_item_sign_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ASN1_item_sign_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('ASN1_item_sign_ctx');
    {$ifend}
  end;
  
  X509_get_version := LoadLibFunction(ADllHandle, X509_get_version_procname);
  FuncLoadError := not assigned(X509_get_version);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_version_allownil)}
    X509_get_version := ERR_X509_get_version;
    {$ifend}
    {$if declared(X509_get_version_introduced)}
    if LibVersion < X509_get_version_introduced then
    begin
      {$if declared(FC_X509_get_version)}
      X509_get_version := FC_X509_get_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_version_removed)}
    if X509_get_version_removed <= LibVersion then
    begin
      {$if declared(_X509_get_version)}
      X509_get_version := _X509_get_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_version_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_version');
    {$ifend}
  end;
  
  X509_set_version := LoadLibFunction(ADllHandle, X509_set_version_procname);
  FuncLoadError := not assigned(X509_set_version);
  if FuncLoadError then
  begin
    {$if not defined(X509_set_version_allownil)}
    X509_set_version := ERR_X509_set_version;
    {$ifend}
    {$if declared(X509_set_version_introduced)}
    if LibVersion < X509_set_version_introduced then
    begin
      {$if declared(FC_X509_set_version)}
      X509_set_version := FC_X509_set_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_set_version_removed)}
    if X509_set_version_removed <= LibVersion then
    begin
      {$if declared(_X509_set_version)}
      X509_set_version := _X509_set_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_set_version_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_set_version');
    {$ifend}
  end;
  
  X509_set_serialNumber := LoadLibFunction(ADllHandle, X509_set_serialNumber_procname);
  FuncLoadError := not assigned(X509_set_serialNumber);
  if FuncLoadError then
  begin
    {$if not defined(X509_set_serialNumber_allownil)}
    X509_set_serialNumber := ERR_X509_set_serialNumber;
    {$ifend}
    {$if declared(X509_set_serialNumber_introduced)}
    if LibVersion < X509_set_serialNumber_introduced then
    begin
      {$if declared(FC_X509_set_serialNumber)}
      X509_set_serialNumber := FC_X509_set_serialNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_set_serialNumber_removed)}
    if X509_set_serialNumber_removed <= LibVersion then
    begin
      {$if declared(_X509_set_serialNumber)}
      X509_set_serialNumber := _X509_set_serialNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_set_serialNumber_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_set_serialNumber');
    {$ifend}
  end;
  
  X509_get_serialNumber := LoadLibFunction(ADllHandle, X509_get_serialNumber_procname);
  FuncLoadError := not assigned(X509_get_serialNumber);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_serialNumber_allownil)}
    X509_get_serialNumber := ERR_X509_get_serialNumber;
    {$ifend}
    {$if declared(X509_get_serialNumber_introduced)}
    if LibVersion < X509_get_serialNumber_introduced then
    begin
      {$if declared(FC_X509_get_serialNumber)}
      X509_get_serialNumber := FC_X509_get_serialNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_serialNumber_removed)}
    if X509_get_serialNumber_removed <= LibVersion then
    begin
      {$if declared(_X509_get_serialNumber)}
      X509_get_serialNumber := _X509_get_serialNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_serialNumber_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_serialNumber');
    {$ifend}
  end;
  
  X509_get0_serialNumber := LoadLibFunction(ADllHandle, X509_get0_serialNumber_procname);
  FuncLoadError := not assigned(X509_get0_serialNumber);
  if FuncLoadError then
  begin
    {$if not defined(X509_get0_serialNumber_allownil)}
    X509_get0_serialNumber := ERR_X509_get0_serialNumber;
    {$ifend}
    {$if declared(X509_get0_serialNumber_introduced)}
    if LibVersion < X509_get0_serialNumber_introduced then
    begin
      {$if declared(FC_X509_get0_serialNumber)}
      X509_get0_serialNumber := FC_X509_get0_serialNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get0_serialNumber_removed)}
    if X509_get0_serialNumber_removed <= LibVersion then
    begin
      {$if declared(_X509_get0_serialNumber)}
      X509_get0_serialNumber := _X509_get0_serialNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get0_serialNumber_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get0_serialNumber');
    {$ifend}
  end;
  
  X509_set_issuer_name := LoadLibFunction(ADllHandle, X509_set_issuer_name_procname);
  FuncLoadError := not assigned(X509_set_issuer_name);
  if FuncLoadError then
  begin
    {$if not defined(X509_set_issuer_name_allownil)}
    X509_set_issuer_name := ERR_X509_set_issuer_name;
    {$ifend}
    {$if declared(X509_set_issuer_name_introduced)}
    if LibVersion < X509_set_issuer_name_introduced then
    begin
      {$if declared(FC_X509_set_issuer_name)}
      X509_set_issuer_name := FC_X509_set_issuer_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_set_issuer_name_removed)}
    if X509_set_issuer_name_removed <= LibVersion then
    begin
      {$if declared(_X509_set_issuer_name)}
      X509_set_issuer_name := _X509_set_issuer_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_set_issuer_name_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_set_issuer_name');
    {$ifend}
  end;
  
  X509_get_issuer_name := LoadLibFunction(ADllHandle, X509_get_issuer_name_procname);
  FuncLoadError := not assigned(X509_get_issuer_name);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_issuer_name_allownil)}
    X509_get_issuer_name := ERR_X509_get_issuer_name;
    {$ifend}
    {$if declared(X509_get_issuer_name_introduced)}
    if LibVersion < X509_get_issuer_name_introduced then
    begin
      {$if declared(FC_X509_get_issuer_name)}
      X509_get_issuer_name := FC_X509_get_issuer_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_issuer_name_removed)}
    if X509_get_issuer_name_removed <= LibVersion then
    begin
      {$if declared(_X509_get_issuer_name)}
      X509_get_issuer_name := _X509_get_issuer_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_issuer_name_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_issuer_name');
    {$ifend}
  end;
  
  X509_set_subject_name := LoadLibFunction(ADllHandle, X509_set_subject_name_procname);
  FuncLoadError := not assigned(X509_set_subject_name);
  if FuncLoadError then
  begin
    {$if not defined(X509_set_subject_name_allownil)}
    X509_set_subject_name := ERR_X509_set_subject_name;
    {$ifend}
    {$if declared(X509_set_subject_name_introduced)}
    if LibVersion < X509_set_subject_name_introduced then
    begin
      {$if declared(FC_X509_set_subject_name)}
      X509_set_subject_name := FC_X509_set_subject_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_set_subject_name_removed)}
    if X509_set_subject_name_removed <= LibVersion then
    begin
      {$if declared(_X509_set_subject_name)}
      X509_set_subject_name := _X509_set_subject_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_set_subject_name_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_set_subject_name');
    {$ifend}
  end;
  
  X509_get_subject_name := LoadLibFunction(ADllHandle, X509_get_subject_name_procname);
  FuncLoadError := not assigned(X509_get_subject_name);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_subject_name_allownil)}
    X509_get_subject_name := ERR_X509_get_subject_name;
    {$ifend}
    {$if declared(X509_get_subject_name_introduced)}
    if LibVersion < X509_get_subject_name_introduced then
    begin
      {$if declared(FC_X509_get_subject_name)}
      X509_get_subject_name := FC_X509_get_subject_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_subject_name_removed)}
    if X509_get_subject_name_removed <= LibVersion then
    begin
      {$if declared(_X509_get_subject_name)}
      X509_get_subject_name := _X509_get_subject_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_subject_name_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_subject_name');
    {$ifend}
  end;
  
  X509_get0_notBefore := LoadLibFunction(ADllHandle, X509_get0_notBefore_procname);
  FuncLoadError := not assigned(X509_get0_notBefore);
  if FuncLoadError then
  begin
    {$if not defined(X509_get0_notBefore_allownil)}
    X509_get0_notBefore := ERR_X509_get0_notBefore;
    {$ifend}
    {$if declared(X509_get0_notBefore_introduced)}
    if LibVersion < X509_get0_notBefore_introduced then
    begin
      {$if declared(FC_X509_get0_notBefore)}
      X509_get0_notBefore := FC_X509_get0_notBefore;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get0_notBefore_removed)}
    if X509_get0_notBefore_removed <= LibVersion then
    begin
      {$if declared(_X509_get0_notBefore)}
      X509_get0_notBefore := _X509_get0_notBefore;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get0_notBefore_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get0_notBefore');
    {$ifend}
  end;
  
  X509_getm_notBefore := LoadLibFunction(ADllHandle, X509_getm_notBefore_procname);
  FuncLoadError := not assigned(X509_getm_notBefore);
  if FuncLoadError then
  begin
    {$if not defined(X509_getm_notBefore_allownil)}
    X509_getm_notBefore := ERR_X509_getm_notBefore;
    {$ifend}
    {$if declared(X509_getm_notBefore_introduced)}
    if LibVersion < X509_getm_notBefore_introduced then
    begin
      {$if declared(FC_X509_getm_notBefore)}
      X509_getm_notBefore := FC_X509_getm_notBefore;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_getm_notBefore_removed)}
    if X509_getm_notBefore_removed <= LibVersion then
    begin
      {$if declared(_X509_getm_notBefore)}
      X509_getm_notBefore := _X509_getm_notBefore;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_getm_notBefore_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_getm_notBefore');
    {$ifend}
  end;
  
  X509_set1_notBefore := LoadLibFunction(ADllHandle, X509_set1_notBefore_procname);
  FuncLoadError := not assigned(X509_set1_notBefore);
  if FuncLoadError then
  begin
    {$if not defined(X509_set1_notBefore_allownil)}
    X509_set1_notBefore := ERR_X509_set1_notBefore;
    {$ifend}
    {$if declared(X509_set1_notBefore_introduced)}
    if LibVersion < X509_set1_notBefore_introduced then
    begin
      {$if declared(FC_X509_set1_notBefore)}
      X509_set1_notBefore := FC_X509_set1_notBefore;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_set1_notBefore_removed)}
    if X509_set1_notBefore_removed <= LibVersion then
    begin
      {$if declared(_X509_set1_notBefore)}
      X509_set1_notBefore := _X509_set1_notBefore;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_set1_notBefore_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_set1_notBefore');
    {$ifend}
  end;
  
  X509_get0_notAfter := LoadLibFunction(ADllHandle, X509_get0_notAfter_procname);
  FuncLoadError := not assigned(X509_get0_notAfter);
  if FuncLoadError then
  begin
    {$if not defined(X509_get0_notAfter_allownil)}
    X509_get0_notAfter := ERR_X509_get0_notAfter;
    {$ifend}
    {$if declared(X509_get0_notAfter_introduced)}
    if LibVersion < X509_get0_notAfter_introduced then
    begin
      {$if declared(FC_X509_get0_notAfter)}
      X509_get0_notAfter := FC_X509_get0_notAfter;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get0_notAfter_removed)}
    if X509_get0_notAfter_removed <= LibVersion then
    begin
      {$if declared(_X509_get0_notAfter)}
      X509_get0_notAfter := _X509_get0_notAfter;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get0_notAfter_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get0_notAfter');
    {$ifend}
  end;
  
  X509_getm_notAfter := LoadLibFunction(ADllHandle, X509_getm_notAfter_procname);
  FuncLoadError := not assigned(X509_getm_notAfter);
  if FuncLoadError then
  begin
    {$if not defined(X509_getm_notAfter_allownil)}
    X509_getm_notAfter := ERR_X509_getm_notAfter;
    {$ifend}
    {$if declared(X509_getm_notAfter_introduced)}
    if LibVersion < X509_getm_notAfter_introduced then
    begin
      {$if declared(FC_X509_getm_notAfter)}
      X509_getm_notAfter := FC_X509_getm_notAfter;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_getm_notAfter_removed)}
    if X509_getm_notAfter_removed <= LibVersion then
    begin
      {$if declared(_X509_getm_notAfter)}
      X509_getm_notAfter := _X509_getm_notAfter;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_getm_notAfter_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_getm_notAfter');
    {$ifend}
  end;
  
  X509_set1_notAfter := LoadLibFunction(ADllHandle, X509_set1_notAfter_procname);
  FuncLoadError := not assigned(X509_set1_notAfter);
  if FuncLoadError then
  begin
    {$if not defined(X509_set1_notAfter_allownil)}
    X509_set1_notAfter := ERR_X509_set1_notAfter;
    {$ifend}
    {$if declared(X509_set1_notAfter_introduced)}
    if LibVersion < X509_set1_notAfter_introduced then
    begin
      {$if declared(FC_X509_set1_notAfter)}
      X509_set1_notAfter := FC_X509_set1_notAfter;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_set1_notAfter_removed)}
    if X509_set1_notAfter_removed <= LibVersion then
    begin
      {$if declared(_X509_set1_notAfter)}
      X509_set1_notAfter := _X509_set1_notAfter;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_set1_notAfter_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_set1_notAfter');
    {$ifend}
  end;
  
  X509_set_pubkey := LoadLibFunction(ADllHandle, X509_set_pubkey_procname);
  FuncLoadError := not assigned(X509_set_pubkey);
  if FuncLoadError then
  begin
    {$if not defined(X509_set_pubkey_allownil)}
    X509_set_pubkey := ERR_X509_set_pubkey;
    {$ifend}
    {$if declared(X509_set_pubkey_introduced)}
    if LibVersion < X509_set_pubkey_introduced then
    begin
      {$if declared(FC_X509_set_pubkey)}
      X509_set_pubkey := FC_X509_set_pubkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_set_pubkey_removed)}
    if X509_set_pubkey_removed <= LibVersion then
    begin
      {$if declared(_X509_set_pubkey)}
      X509_set_pubkey := _X509_set_pubkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_set_pubkey_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_set_pubkey');
    {$ifend}
  end;
  
  X509_up_ref := LoadLibFunction(ADllHandle, X509_up_ref_procname);
  FuncLoadError := not assigned(X509_up_ref);
  if FuncLoadError then
  begin
    {$if not defined(X509_up_ref_allownil)}
    X509_up_ref := ERR_X509_up_ref;
    {$ifend}
    {$if declared(X509_up_ref_introduced)}
    if LibVersion < X509_up_ref_introduced then
    begin
      {$if declared(FC_X509_up_ref)}
      X509_up_ref := FC_X509_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_up_ref_removed)}
    if X509_up_ref_removed <= LibVersion then
    begin
      {$if declared(_X509_up_ref)}
      X509_up_ref := _X509_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_up_ref_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_up_ref');
    {$ifend}
  end;
  
  X509_get_signature_type := LoadLibFunction(ADllHandle, X509_get_signature_type_procname);
  FuncLoadError := not assigned(X509_get_signature_type);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_signature_type_allownil)}
    X509_get_signature_type := ERR_X509_get_signature_type;
    {$ifend}
    {$if declared(X509_get_signature_type_introduced)}
    if LibVersion < X509_get_signature_type_introduced then
    begin
      {$if declared(FC_X509_get_signature_type)}
      X509_get_signature_type := FC_X509_get_signature_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_signature_type_removed)}
    if X509_get_signature_type_removed <= LibVersion then
    begin
      {$if declared(_X509_get_signature_type)}
      X509_get_signature_type := _X509_get_signature_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_signature_type_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_signature_type');
    {$ifend}
  end;
  
  X509_get_X509_PUBKEY := LoadLibFunction(ADllHandle, X509_get_X509_PUBKEY_procname);
  FuncLoadError := not assigned(X509_get_X509_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_X509_PUBKEY_allownil)}
    X509_get_X509_PUBKEY := ERR_X509_get_X509_PUBKEY;
    {$ifend}
    {$if declared(X509_get_X509_PUBKEY_introduced)}
    if LibVersion < X509_get_X509_PUBKEY_introduced then
    begin
      {$if declared(FC_X509_get_X509_PUBKEY)}
      X509_get_X509_PUBKEY := FC_X509_get_X509_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_X509_PUBKEY_removed)}
    if X509_get_X509_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_X509_get_X509_PUBKEY)}
      X509_get_X509_PUBKEY := _X509_get_X509_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_X509_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_X509_PUBKEY');
    {$ifend}
  end;
  
  X509_get0_extensions := LoadLibFunction(ADllHandle, X509_get0_extensions_procname);
  FuncLoadError := not assigned(X509_get0_extensions);
  if FuncLoadError then
  begin
    {$if not defined(X509_get0_extensions_allownil)}
    X509_get0_extensions := ERR_X509_get0_extensions;
    {$ifend}
    {$if declared(X509_get0_extensions_introduced)}
    if LibVersion < X509_get0_extensions_introduced then
    begin
      {$if declared(FC_X509_get0_extensions)}
      X509_get0_extensions := FC_X509_get0_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get0_extensions_removed)}
    if X509_get0_extensions_removed <= LibVersion then
    begin
      {$if declared(_X509_get0_extensions)}
      X509_get0_extensions := _X509_get0_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get0_extensions_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get0_extensions');
    {$ifend}
  end;
  
  X509_get0_uids := LoadLibFunction(ADllHandle, X509_get0_uids_procname);
  FuncLoadError := not assigned(X509_get0_uids);
  if FuncLoadError then
  begin
    {$if not defined(X509_get0_uids_allownil)}
    X509_get0_uids := ERR_X509_get0_uids;
    {$ifend}
    {$if declared(X509_get0_uids_introduced)}
    if LibVersion < X509_get0_uids_introduced then
    begin
      {$if declared(FC_X509_get0_uids)}
      X509_get0_uids := FC_X509_get0_uids;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get0_uids_removed)}
    if X509_get0_uids_removed <= LibVersion then
    begin
      {$if declared(_X509_get0_uids)}
      X509_get0_uids := _X509_get0_uids;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get0_uids_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get0_uids');
    {$ifend}
  end;
  
  X509_get0_tbs_sigalg := LoadLibFunction(ADllHandle, X509_get0_tbs_sigalg_procname);
  FuncLoadError := not assigned(X509_get0_tbs_sigalg);
  if FuncLoadError then
  begin
    {$if not defined(X509_get0_tbs_sigalg_allownil)}
    X509_get0_tbs_sigalg := ERR_X509_get0_tbs_sigalg;
    {$ifend}
    {$if declared(X509_get0_tbs_sigalg_introduced)}
    if LibVersion < X509_get0_tbs_sigalg_introduced then
    begin
      {$if declared(FC_X509_get0_tbs_sigalg)}
      X509_get0_tbs_sigalg := FC_X509_get0_tbs_sigalg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get0_tbs_sigalg_removed)}
    if X509_get0_tbs_sigalg_removed <= LibVersion then
    begin
      {$if declared(_X509_get0_tbs_sigalg)}
      X509_get0_tbs_sigalg := _X509_get0_tbs_sigalg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get0_tbs_sigalg_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get0_tbs_sigalg');
    {$ifend}
  end;
  
  X509_get0_pubkey := LoadLibFunction(ADllHandle, X509_get0_pubkey_procname);
  FuncLoadError := not assigned(X509_get0_pubkey);
  if FuncLoadError then
  begin
    {$if not defined(X509_get0_pubkey_allownil)}
    X509_get0_pubkey := ERR_X509_get0_pubkey;
    {$ifend}
    {$if declared(X509_get0_pubkey_introduced)}
    if LibVersion < X509_get0_pubkey_introduced then
    begin
      {$if declared(FC_X509_get0_pubkey)}
      X509_get0_pubkey := FC_X509_get0_pubkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get0_pubkey_removed)}
    if X509_get0_pubkey_removed <= LibVersion then
    begin
      {$if declared(_X509_get0_pubkey)}
      X509_get0_pubkey := _X509_get0_pubkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get0_pubkey_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get0_pubkey');
    {$ifend}
  end;
  
  X509_get_pubkey := LoadLibFunction(ADllHandle, X509_get_pubkey_procname);
  FuncLoadError := not assigned(X509_get_pubkey);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_pubkey_allownil)}
    X509_get_pubkey := ERR_X509_get_pubkey;
    {$ifend}
    {$if declared(X509_get_pubkey_introduced)}
    if LibVersion < X509_get_pubkey_introduced then
    begin
      {$if declared(FC_X509_get_pubkey)}
      X509_get_pubkey := FC_X509_get_pubkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_pubkey_removed)}
    if X509_get_pubkey_removed <= LibVersion then
    begin
      {$if declared(_X509_get_pubkey)}
      X509_get_pubkey := _X509_get_pubkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_pubkey_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_pubkey');
    {$ifend}
  end;
  
  X509_get0_pubkey_bitstr := LoadLibFunction(ADllHandle, X509_get0_pubkey_bitstr_procname);
  FuncLoadError := not assigned(X509_get0_pubkey_bitstr);
  if FuncLoadError then
  begin
    {$if not defined(X509_get0_pubkey_bitstr_allownil)}
    X509_get0_pubkey_bitstr := ERR_X509_get0_pubkey_bitstr;
    {$ifend}
    {$if declared(X509_get0_pubkey_bitstr_introduced)}
    if LibVersion < X509_get0_pubkey_bitstr_introduced then
    begin
      {$if declared(FC_X509_get0_pubkey_bitstr)}
      X509_get0_pubkey_bitstr := FC_X509_get0_pubkey_bitstr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get0_pubkey_bitstr_removed)}
    if X509_get0_pubkey_bitstr_removed <= LibVersion then
    begin
      {$if declared(_X509_get0_pubkey_bitstr)}
      X509_get0_pubkey_bitstr := _X509_get0_pubkey_bitstr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get0_pubkey_bitstr_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get0_pubkey_bitstr');
    {$ifend}
  end;
  
  X509_REQ_get_version := LoadLibFunction(ADllHandle, X509_REQ_get_version_procname);
  FuncLoadError := not assigned(X509_REQ_get_version);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_get_version_allownil)}
    X509_REQ_get_version := ERR_X509_REQ_get_version;
    {$ifend}
    {$if declared(X509_REQ_get_version_introduced)}
    if LibVersion < X509_REQ_get_version_introduced then
    begin
      {$if declared(FC_X509_REQ_get_version)}
      X509_REQ_get_version := FC_X509_REQ_get_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_get_version_removed)}
    if X509_REQ_get_version_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_get_version)}
      X509_REQ_get_version := _X509_REQ_get_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_get_version_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_get_version');
    {$ifend}
  end;
  
  X509_REQ_set_version := LoadLibFunction(ADllHandle, X509_REQ_set_version_procname);
  FuncLoadError := not assigned(X509_REQ_set_version);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_set_version_allownil)}
    X509_REQ_set_version := ERR_X509_REQ_set_version;
    {$ifend}
    {$if declared(X509_REQ_set_version_introduced)}
    if LibVersion < X509_REQ_set_version_introduced then
    begin
      {$if declared(FC_X509_REQ_set_version)}
      X509_REQ_set_version := FC_X509_REQ_set_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_set_version_removed)}
    if X509_REQ_set_version_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_set_version)}
      X509_REQ_set_version := _X509_REQ_set_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_set_version_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_set_version');
    {$ifend}
  end;
  
  X509_REQ_get_subject_name := LoadLibFunction(ADllHandle, X509_REQ_get_subject_name_procname);
  FuncLoadError := not assigned(X509_REQ_get_subject_name);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_get_subject_name_allownil)}
    X509_REQ_get_subject_name := ERR_X509_REQ_get_subject_name;
    {$ifend}
    {$if declared(X509_REQ_get_subject_name_introduced)}
    if LibVersion < X509_REQ_get_subject_name_introduced then
    begin
      {$if declared(FC_X509_REQ_get_subject_name)}
      X509_REQ_get_subject_name := FC_X509_REQ_get_subject_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_get_subject_name_removed)}
    if X509_REQ_get_subject_name_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_get_subject_name)}
      X509_REQ_get_subject_name := _X509_REQ_get_subject_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_get_subject_name_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_get_subject_name');
    {$ifend}
  end;
  
  X509_REQ_set_subject_name := LoadLibFunction(ADllHandle, X509_REQ_set_subject_name_procname);
  FuncLoadError := not assigned(X509_REQ_set_subject_name);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_set_subject_name_allownil)}
    X509_REQ_set_subject_name := ERR_X509_REQ_set_subject_name;
    {$ifend}
    {$if declared(X509_REQ_set_subject_name_introduced)}
    if LibVersion < X509_REQ_set_subject_name_introduced then
    begin
      {$if declared(FC_X509_REQ_set_subject_name)}
      X509_REQ_set_subject_name := FC_X509_REQ_set_subject_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_set_subject_name_removed)}
    if X509_REQ_set_subject_name_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_set_subject_name)}
      X509_REQ_set_subject_name := _X509_REQ_set_subject_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_set_subject_name_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_set_subject_name');
    {$ifend}
  end;
  
  X509_REQ_get0_signature := LoadLibFunction(ADllHandle, X509_REQ_get0_signature_procname);
  FuncLoadError := not assigned(X509_REQ_get0_signature);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_get0_signature_allownil)}
    X509_REQ_get0_signature := ERR_X509_REQ_get0_signature;
    {$ifend}
    {$if declared(X509_REQ_get0_signature_introduced)}
    if LibVersion < X509_REQ_get0_signature_introduced then
    begin
      {$if declared(FC_X509_REQ_get0_signature)}
      X509_REQ_get0_signature := FC_X509_REQ_get0_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_get0_signature_removed)}
    if X509_REQ_get0_signature_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_get0_signature)}
      X509_REQ_get0_signature := _X509_REQ_get0_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_get0_signature_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_get0_signature');
    {$ifend}
  end;
  
  X509_REQ_set0_signature := LoadLibFunction(ADllHandle, X509_REQ_set0_signature_procname);
  FuncLoadError := not assigned(X509_REQ_set0_signature);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_set0_signature_allownil)}
    X509_REQ_set0_signature := ERR_X509_REQ_set0_signature;
    {$ifend}
    {$if declared(X509_REQ_set0_signature_introduced)}
    if LibVersion < X509_REQ_set0_signature_introduced then
    begin
      {$if declared(FC_X509_REQ_set0_signature)}
      X509_REQ_set0_signature := FC_X509_REQ_set0_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_set0_signature_removed)}
    if X509_REQ_set0_signature_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_set0_signature)}
      X509_REQ_set0_signature := _X509_REQ_set0_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_set0_signature_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_set0_signature');
    {$ifend}
  end;
  
  X509_REQ_set1_signature_algo := LoadLibFunction(ADllHandle, X509_REQ_set1_signature_algo_procname);
  FuncLoadError := not assigned(X509_REQ_set1_signature_algo);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_set1_signature_algo_allownil)}
    X509_REQ_set1_signature_algo := ERR_X509_REQ_set1_signature_algo;
    {$ifend}
    {$if declared(X509_REQ_set1_signature_algo_introduced)}
    if LibVersion < X509_REQ_set1_signature_algo_introduced then
    begin
      {$if declared(FC_X509_REQ_set1_signature_algo)}
      X509_REQ_set1_signature_algo := FC_X509_REQ_set1_signature_algo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_set1_signature_algo_removed)}
    if X509_REQ_set1_signature_algo_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_set1_signature_algo)}
      X509_REQ_set1_signature_algo := _X509_REQ_set1_signature_algo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_set1_signature_algo_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_set1_signature_algo');
    {$ifend}
  end;
  
  X509_REQ_get_signature_nid := LoadLibFunction(ADllHandle, X509_REQ_get_signature_nid_procname);
  FuncLoadError := not assigned(X509_REQ_get_signature_nid);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_get_signature_nid_allownil)}
    X509_REQ_get_signature_nid := ERR_X509_REQ_get_signature_nid;
    {$ifend}
    {$if declared(X509_REQ_get_signature_nid_introduced)}
    if LibVersion < X509_REQ_get_signature_nid_introduced then
    begin
      {$if declared(FC_X509_REQ_get_signature_nid)}
      X509_REQ_get_signature_nid := FC_X509_REQ_get_signature_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_get_signature_nid_removed)}
    if X509_REQ_get_signature_nid_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_get_signature_nid)}
      X509_REQ_get_signature_nid := _X509_REQ_get_signature_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_get_signature_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_get_signature_nid');
    {$ifend}
  end;
  
  i2d_re_X509_REQ_tbs := LoadLibFunction(ADllHandle, i2d_re_X509_REQ_tbs_procname);
  FuncLoadError := not assigned(i2d_re_X509_REQ_tbs);
  if FuncLoadError then
  begin
    {$if not defined(i2d_re_X509_REQ_tbs_allownil)}
    i2d_re_X509_REQ_tbs := ERR_i2d_re_X509_REQ_tbs;
    {$ifend}
    {$if declared(i2d_re_X509_REQ_tbs_introduced)}
    if LibVersion < i2d_re_X509_REQ_tbs_introduced then
    begin
      {$if declared(FC_i2d_re_X509_REQ_tbs)}
      i2d_re_X509_REQ_tbs := FC_i2d_re_X509_REQ_tbs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_re_X509_REQ_tbs_removed)}
    if i2d_re_X509_REQ_tbs_removed <= LibVersion then
    begin
      {$if declared(_i2d_re_X509_REQ_tbs)}
      i2d_re_X509_REQ_tbs := _i2d_re_X509_REQ_tbs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_re_X509_REQ_tbs_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_re_X509_REQ_tbs');
    {$ifend}
  end;
  
  X509_REQ_set_pubkey := LoadLibFunction(ADllHandle, X509_REQ_set_pubkey_procname);
  FuncLoadError := not assigned(X509_REQ_set_pubkey);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_set_pubkey_allownil)}
    X509_REQ_set_pubkey := ERR_X509_REQ_set_pubkey;
    {$ifend}
    {$if declared(X509_REQ_set_pubkey_introduced)}
    if LibVersion < X509_REQ_set_pubkey_introduced then
    begin
      {$if declared(FC_X509_REQ_set_pubkey)}
      X509_REQ_set_pubkey := FC_X509_REQ_set_pubkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_set_pubkey_removed)}
    if X509_REQ_set_pubkey_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_set_pubkey)}
      X509_REQ_set_pubkey := _X509_REQ_set_pubkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_set_pubkey_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_set_pubkey');
    {$ifend}
  end;
  
  X509_REQ_get_pubkey := LoadLibFunction(ADllHandle, X509_REQ_get_pubkey_procname);
  FuncLoadError := not assigned(X509_REQ_get_pubkey);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_get_pubkey_allownil)}
    X509_REQ_get_pubkey := ERR_X509_REQ_get_pubkey;
    {$ifend}
    {$if declared(X509_REQ_get_pubkey_introduced)}
    if LibVersion < X509_REQ_get_pubkey_introduced then
    begin
      {$if declared(FC_X509_REQ_get_pubkey)}
      X509_REQ_get_pubkey := FC_X509_REQ_get_pubkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_get_pubkey_removed)}
    if X509_REQ_get_pubkey_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_get_pubkey)}
      X509_REQ_get_pubkey := _X509_REQ_get_pubkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_get_pubkey_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_get_pubkey');
    {$ifend}
  end;
  
  X509_REQ_get0_pubkey := LoadLibFunction(ADllHandle, X509_REQ_get0_pubkey_procname);
  FuncLoadError := not assigned(X509_REQ_get0_pubkey);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_get0_pubkey_allownil)}
    X509_REQ_get0_pubkey := ERR_X509_REQ_get0_pubkey;
    {$ifend}
    {$if declared(X509_REQ_get0_pubkey_introduced)}
    if LibVersion < X509_REQ_get0_pubkey_introduced then
    begin
      {$if declared(FC_X509_REQ_get0_pubkey)}
      X509_REQ_get0_pubkey := FC_X509_REQ_get0_pubkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_get0_pubkey_removed)}
    if X509_REQ_get0_pubkey_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_get0_pubkey)}
      X509_REQ_get0_pubkey := _X509_REQ_get0_pubkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_get0_pubkey_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_get0_pubkey');
    {$ifend}
  end;
  
  X509_REQ_get_X509_PUBKEY := LoadLibFunction(ADllHandle, X509_REQ_get_X509_PUBKEY_procname);
  FuncLoadError := not assigned(X509_REQ_get_X509_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_get_X509_PUBKEY_allownil)}
    X509_REQ_get_X509_PUBKEY := ERR_X509_REQ_get_X509_PUBKEY;
    {$ifend}
    {$if declared(X509_REQ_get_X509_PUBKEY_introduced)}
    if LibVersion < X509_REQ_get_X509_PUBKEY_introduced then
    begin
      {$if declared(FC_X509_REQ_get_X509_PUBKEY)}
      X509_REQ_get_X509_PUBKEY := FC_X509_REQ_get_X509_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_get_X509_PUBKEY_removed)}
    if X509_REQ_get_X509_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_get_X509_PUBKEY)}
      X509_REQ_get_X509_PUBKEY := _X509_REQ_get_X509_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_get_X509_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_get_X509_PUBKEY');
    {$ifend}
  end;
  
  X509_REQ_extension_nid := LoadLibFunction(ADllHandle, X509_REQ_extension_nid_procname);
  FuncLoadError := not assigned(X509_REQ_extension_nid);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_extension_nid_allownil)}
    X509_REQ_extension_nid := ERR_X509_REQ_extension_nid;
    {$ifend}
    {$if declared(X509_REQ_extension_nid_introduced)}
    if LibVersion < X509_REQ_extension_nid_introduced then
    begin
      {$if declared(FC_X509_REQ_extension_nid)}
      X509_REQ_extension_nid := FC_X509_REQ_extension_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_extension_nid_removed)}
    if X509_REQ_extension_nid_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_extension_nid)}
      X509_REQ_extension_nid := _X509_REQ_extension_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_extension_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_extension_nid');
    {$ifend}
  end;
  
  X509_REQ_get_extension_nids := LoadLibFunction(ADllHandle, X509_REQ_get_extension_nids_procname);
  FuncLoadError := not assigned(X509_REQ_get_extension_nids);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_get_extension_nids_allownil)}
    X509_REQ_get_extension_nids := ERR_X509_REQ_get_extension_nids;
    {$ifend}
    {$if declared(X509_REQ_get_extension_nids_introduced)}
    if LibVersion < X509_REQ_get_extension_nids_introduced then
    begin
      {$if declared(FC_X509_REQ_get_extension_nids)}
      X509_REQ_get_extension_nids := FC_X509_REQ_get_extension_nids;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_get_extension_nids_removed)}
    if X509_REQ_get_extension_nids_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_get_extension_nids)}
      X509_REQ_get_extension_nids := _X509_REQ_get_extension_nids;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_get_extension_nids_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_get_extension_nids');
    {$ifend}
  end;
  
  X509_REQ_set_extension_nids := LoadLibFunction(ADllHandle, X509_REQ_set_extension_nids_procname);
  FuncLoadError := not assigned(X509_REQ_set_extension_nids);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_set_extension_nids_allownil)}
    X509_REQ_set_extension_nids := ERR_X509_REQ_set_extension_nids;
    {$ifend}
    {$if declared(X509_REQ_set_extension_nids_introduced)}
    if LibVersion < X509_REQ_set_extension_nids_introduced then
    begin
      {$if declared(FC_X509_REQ_set_extension_nids)}
      X509_REQ_set_extension_nids := FC_X509_REQ_set_extension_nids;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_set_extension_nids_removed)}
    if X509_REQ_set_extension_nids_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_set_extension_nids)}
      X509_REQ_set_extension_nids := _X509_REQ_set_extension_nids;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_set_extension_nids_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_set_extension_nids');
    {$ifend}
  end;
  
  X509_REQ_get_extensions := LoadLibFunction(ADllHandle, X509_REQ_get_extensions_procname);
  FuncLoadError := not assigned(X509_REQ_get_extensions);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_get_extensions_allownil)}
    X509_REQ_get_extensions := ERR_X509_REQ_get_extensions;
    {$ifend}
    {$if declared(X509_REQ_get_extensions_introduced)}
    if LibVersion < X509_REQ_get_extensions_introduced then
    begin
      {$if declared(FC_X509_REQ_get_extensions)}
      X509_REQ_get_extensions := FC_X509_REQ_get_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_get_extensions_removed)}
    if X509_REQ_get_extensions_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_get_extensions)}
      X509_REQ_get_extensions := _X509_REQ_get_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_get_extensions_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_get_extensions');
    {$ifend}
  end;
  
  X509_REQ_add_extensions_nid := LoadLibFunction(ADllHandle, X509_REQ_add_extensions_nid_procname);
  FuncLoadError := not assigned(X509_REQ_add_extensions_nid);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_add_extensions_nid_allownil)}
    X509_REQ_add_extensions_nid := ERR_X509_REQ_add_extensions_nid;
    {$ifend}
    {$if declared(X509_REQ_add_extensions_nid_introduced)}
    if LibVersion < X509_REQ_add_extensions_nid_introduced then
    begin
      {$if declared(FC_X509_REQ_add_extensions_nid)}
      X509_REQ_add_extensions_nid := FC_X509_REQ_add_extensions_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_add_extensions_nid_removed)}
    if X509_REQ_add_extensions_nid_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_add_extensions_nid)}
      X509_REQ_add_extensions_nid := _X509_REQ_add_extensions_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_add_extensions_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_add_extensions_nid');
    {$ifend}
  end;
  
  X509_REQ_add_extensions := LoadLibFunction(ADllHandle, X509_REQ_add_extensions_procname);
  FuncLoadError := not assigned(X509_REQ_add_extensions);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_add_extensions_allownil)}
    X509_REQ_add_extensions := ERR_X509_REQ_add_extensions;
    {$ifend}
    {$if declared(X509_REQ_add_extensions_introduced)}
    if LibVersion < X509_REQ_add_extensions_introduced then
    begin
      {$if declared(FC_X509_REQ_add_extensions)}
      X509_REQ_add_extensions := FC_X509_REQ_add_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_add_extensions_removed)}
    if X509_REQ_add_extensions_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_add_extensions)}
      X509_REQ_add_extensions := _X509_REQ_add_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_add_extensions_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_add_extensions');
    {$ifend}
  end;
  
  X509_REQ_get_attr_count := LoadLibFunction(ADllHandle, X509_REQ_get_attr_count_procname);
  FuncLoadError := not assigned(X509_REQ_get_attr_count);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_get_attr_count_allownil)}
    X509_REQ_get_attr_count := ERR_X509_REQ_get_attr_count;
    {$ifend}
    {$if declared(X509_REQ_get_attr_count_introduced)}
    if LibVersion < X509_REQ_get_attr_count_introduced then
    begin
      {$if declared(FC_X509_REQ_get_attr_count)}
      X509_REQ_get_attr_count := FC_X509_REQ_get_attr_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_get_attr_count_removed)}
    if X509_REQ_get_attr_count_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_get_attr_count)}
      X509_REQ_get_attr_count := _X509_REQ_get_attr_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_get_attr_count_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_get_attr_count');
    {$ifend}
  end;
  
  X509_REQ_get_attr_by_NID := LoadLibFunction(ADllHandle, X509_REQ_get_attr_by_NID_procname);
  FuncLoadError := not assigned(X509_REQ_get_attr_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_get_attr_by_NID_allownil)}
    X509_REQ_get_attr_by_NID := ERR_X509_REQ_get_attr_by_NID;
    {$ifend}
    {$if declared(X509_REQ_get_attr_by_NID_introduced)}
    if LibVersion < X509_REQ_get_attr_by_NID_introduced then
    begin
      {$if declared(FC_X509_REQ_get_attr_by_NID)}
      X509_REQ_get_attr_by_NID := FC_X509_REQ_get_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_get_attr_by_NID_removed)}
    if X509_REQ_get_attr_by_NID_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_get_attr_by_NID)}
      X509_REQ_get_attr_by_NID := _X509_REQ_get_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_get_attr_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_get_attr_by_NID');
    {$ifend}
  end;
  
  X509_REQ_get_attr_by_OBJ := LoadLibFunction(ADllHandle, X509_REQ_get_attr_by_OBJ_procname);
  FuncLoadError := not assigned(X509_REQ_get_attr_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_get_attr_by_OBJ_allownil)}
    X509_REQ_get_attr_by_OBJ := ERR_X509_REQ_get_attr_by_OBJ;
    {$ifend}
    {$if declared(X509_REQ_get_attr_by_OBJ_introduced)}
    if LibVersion < X509_REQ_get_attr_by_OBJ_introduced then
    begin
      {$if declared(FC_X509_REQ_get_attr_by_OBJ)}
      X509_REQ_get_attr_by_OBJ := FC_X509_REQ_get_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_get_attr_by_OBJ_removed)}
    if X509_REQ_get_attr_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_get_attr_by_OBJ)}
      X509_REQ_get_attr_by_OBJ := _X509_REQ_get_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_get_attr_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_get_attr_by_OBJ');
    {$ifend}
  end;
  
  X509_REQ_get_attr := LoadLibFunction(ADllHandle, X509_REQ_get_attr_procname);
  FuncLoadError := not assigned(X509_REQ_get_attr);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_get_attr_allownil)}
    X509_REQ_get_attr := ERR_X509_REQ_get_attr;
    {$ifend}
    {$if declared(X509_REQ_get_attr_introduced)}
    if LibVersion < X509_REQ_get_attr_introduced then
    begin
      {$if declared(FC_X509_REQ_get_attr)}
      X509_REQ_get_attr := FC_X509_REQ_get_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_get_attr_removed)}
    if X509_REQ_get_attr_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_get_attr)}
      X509_REQ_get_attr := _X509_REQ_get_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_get_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_get_attr');
    {$ifend}
  end;
  
  X509_REQ_delete_attr := LoadLibFunction(ADllHandle, X509_REQ_delete_attr_procname);
  FuncLoadError := not assigned(X509_REQ_delete_attr);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_delete_attr_allownil)}
    X509_REQ_delete_attr := ERR_X509_REQ_delete_attr;
    {$ifend}
    {$if declared(X509_REQ_delete_attr_introduced)}
    if LibVersion < X509_REQ_delete_attr_introduced then
    begin
      {$if declared(FC_X509_REQ_delete_attr)}
      X509_REQ_delete_attr := FC_X509_REQ_delete_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_delete_attr_removed)}
    if X509_REQ_delete_attr_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_delete_attr)}
      X509_REQ_delete_attr := _X509_REQ_delete_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_delete_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_delete_attr');
    {$ifend}
  end;
  
  X509_REQ_add1_attr := LoadLibFunction(ADllHandle, X509_REQ_add1_attr_procname);
  FuncLoadError := not assigned(X509_REQ_add1_attr);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_add1_attr_allownil)}
    X509_REQ_add1_attr := ERR_X509_REQ_add1_attr;
    {$ifend}
    {$if declared(X509_REQ_add1_attr_introduced)}
    if LibVersion < X509_REQ_add1_attr_introduced then
    begin
      {$if declared(FC_X509_REQ_add1_attr)}
      X509_REQ_add1_attr := FC_X509_REQ_add1_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_add1_attr_removed)}
    if X509_REQ_add1_attr_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_add1_attr)}
      X509_REQ_add1_attr := _X509_REQ_add1_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_add1_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_add1_attr');
    {$ifend}
  end;
  
  X509_REQ_add1_attr_by_OBJ := LoadLibFunction(ADllHandle, X509_REQ_add1_attr_by_OBJ_procname);
  FuncLoadError := not assigned(X509_REQ_add1_attr_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_add1_attr_by_OBJ_allownil)}
    X509_REQ_add1_attr_by_OBJ := ERR_X509_REQ_add1_attr_by_OBJ;
    {$ifend}
    {$if declared(X509_REQ_add1_attr_by_OBJ_introduced)}
    if LibVersion < X509_REQ_add1_attr_by_OBJ_introduced then
    begin
      {$if declared(FC_X509_REQ_add1_attr_by_OBJ)}
      X509_REQ_add1_attr_by_OBJ := FC_X509_REQ_add1_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_add1_attr_by_OBJ_removed)}
    if X509_REQ_add1_attr_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_add1_attr_by_OBJ)}
      X509_REQ_add1_attr_by_OBJ := _X509_REQ_add1_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_add1_attr_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_add1_attr_by_OBJ');
    {$ifend}
  end;
  
  X509_REQ_add1_attr_by_NID := LoadLibFunction(ADllHandle, X509_REQ_add1_attr_by_NID_procname);
  FuncLoadError := not assigned(X509_REQ_add1_attr_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_add1_attr_by_NID_allownil)}
    X509_REQ_add1_attr_by_NID := ERR_X509_REQ_add1_attr_by_NID;
    {$ifend}
    {$if declared(X509_REQ_add1_attr_by_NID_introduced)}
    if LibVersion < X509_REQ_add1_attr_by_NID_introduced then
    begin
      {$if declared(FC_X509_REQ_add1_attr_by_NID)}
      X509_REQ_add1_attr_by_NID := FC_X509_REQ_add1_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_add1_attr_by_NID_removed)}
    if X509_REQ_add1_attr_by_NID_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_add1_attr_by_NID)}
      X509_REQ_add1_attr_by_NID := _X509_REQ_add1_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_add1_attr_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_add1_attr_by_NID');
    {$ifend}
  end;
  
  X509_REQ_add1_attr_by_txt := LoadLibFunction(ADllHandle, X509_REQ_add1_attr_by_txt_procname);
  FuncLoadError := not assigned(X509_REQ_add1_attr_by_txt);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_add1_attr_by_txt_allownil)}
    X509_REQ_add1_attr_by_txt := ERR_X509_REQ_add1_attr_by_txt;
    {$ifend}
    {$if declared(X509_REQ_add1_attr_by_txt_introduced)}
    if LibVersion < X509_REQ_add1_attr_by_txt_introduced then
    begin
      {$if declared(FC_X509_REQ_add1_attr_by_txt)}
      X509_REQ_add1_attr_by_txt := FC_X509_REQ_add1_attr_by_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_add1_attr_by_txt_removed)}
    if X509_REQ_add1_attr_by_txt_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_add1_attr_by_txt)}
      X509_REQ_add1_attr_by_txt := _X509_REQ_add1_attr_by_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_add1_attr_by_txt_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_add1_attr_by_txt');
    {$ifend}
  end;
  
  X509_CRL_set_version := LoadLibFunction(ADllHandle, X509_CRL_set_version_procname);
  FuncLoadError := not assigned(X509_CRL_set_version);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_set_version_allownil)}
    X509_CRL_set_version := ERR_X509_CRL_set_version;
    {$ifend}
    {$if declared(X509_CRL_set_version_introduced)}
    if LibVersion < X509_CRL_set_version_introduced then
    begin
      {$if declared(FC_X509_CRL_set_version)}
      X509_CRL_set_version := FC_X509_CRL_set_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_set_version_removed)}
    if X509_CRL_set_version_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_set_version)}
      X509_CRL_set_version := _X509_CRL_set_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_set_version_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_set_version');
    {$ifend}
  end;
  
  X509_CRL_set_issuer_name := LoadLibFunction(ADllHandle, X509_CRL_set_issuer_name_procname);
  FuncLoadError := not assigned(X509_CRL_set_issuer_name);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_set_issuer_name_allownil)}
    X509_CRL_set_issuer_name := ERR_X509_CRL_set_issuer_name;
    {$ifend}
    {$if declared(X509_CRL_set_issuer_name_introduced)}
    if LibVersion < X509_CRL_set_issuer_name_introduced then
    begin
      {$if declared(FC_X509_CRL_set_issuer_name)}
      X509_CRL_set_issuer_name := FC_X509_CRL_set_issuer_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_set_issuer_name_removed)}
    if X509_CRL_set_issuer_name_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_set_issuer_name)}
      X509_CRL_set_issuer_name := _X509_CRL_set_issuer_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_set_issuer_name_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_set_issuer_name');
    {$ifend}
  end;
  
  X509_CRL_set1_lastUpdate := LoadLibFunction(ADllHandle, X509_CRL_set1_lastUpdate_procname);
  FuncLoadError := not assigned(X509_CRL_set1_lastUpdate);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_set1_lastUpdate_allownil)}
    X509_CRL_set1_lastUpdate := ERR_X509_CRL_set1_lastUpdate;
    {$ifend}
    {$if declared(X509_CRL_set1_lastUpdate_introduced)}
    if LibVersion < X509_CRL_set1_lastUpdate_introduced then
    begin
      {$if declared(FC_X509_CRL_set1_lastUpdate)}
      X509_CRL_set1_lastUpdate := FC_X509_CRL_set1_lastUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_set1_lastUpdate_removed)}
    if X509_CRL_set1_lastUpdate_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_set1_lastUpdate)}
      X509_CRL_set1_lastUpdate := _X509_CRL_set1_lastUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_set1_lastUpdate_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_set1_lastUpdate');
    {$ifend}
  end;
  
  X509_CRL_set1_nextUpdate := LoadLibFunction(ADllHandle, X509_CRL_set1_nextUpdate_procname);
  FuncLoadError := not assigned(X509_CRL_set1_nextUpdate);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_set1_nextUpdate_allownil)}
    X509_CRL_set1_nextUpdate := ERR_X509_CRL_set1_nextUpdate;
    {$ifend}
    {$if declared(X509_CRL_set1_nextUpdate_introduced)}
    if LibVersion < X509_CRL_set1_nextUpdate_introduced then
    begin
      {$if declared(FC_X509_CRL_set1_nextUpdate)}
      X509_CRL_set1_nextUpdate := FC_X509_CRL_set1_nextUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_set1_nextUpdate_removed)}
    if X509_CRL_set1_nextUpdate_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_set1_nextUpdate)}
      X509_CRL_set1_nextUpdate := _X509_CRL_set1_nextUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_set1_nextUpdate_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_set1_nextUpdate');
    {$ifend}
  end;
  
  X509_CRL_sort := LoadLibFunction(ADllHandle, X509_CRL_sort_procname);
  FuncLoadError := not assigned(X509_CRL_sort);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_sort_allownil)}
    X509_CRL_sort := ERR_X509_CRL_sort;
    {$ifend}
    {$if declared(X509_CRL_sort_introduced)}
    if LibVersion < X509_CRL_sort_introduced then
    begin
      {$if declared(FC_X509_CRL_sort)}
      X509_CRL_sort := FC_X509_CRL_sort;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_sort_removed)}
    if X509_CRL_sort_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_sort)}
      X509_CRL_sort := _X509_CRL_sort;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_sort_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_sort');
    {$ifend}
  end;
  
  X509_CRL_up_ref := LoadLibFunction(ADllHandle, X509_CRL_up_ref_procname);
  FuncLoadError := not assigned(X509_CRL_up_ref);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_up_ref_allownil)}
    X509_CRL_up_ref := ERR_X509_CRL_up_ref;
    {$ifend}
    {$if declared(X509_CRL_up_ref_introduced)}
    if LibVersion < X509_CRL_up_ref_introduced then
    begin
      {$if declared(FC_X509_CRL_up_ref)}
      X509_CRL_up_ref := FC_X509_CRL_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_up_ref_removed)}
    if X509_CRL_up_ref_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_up_ref)}
      X509_CRL_up_ref := _X509_CRL_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_up_ref_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_up_ref');
    {$ifend}
  end;
  
  X509_CRL_get_version := LoadLibFunction(ADllHandle, X509_CRL_get_version_procname);
  FuncLoadError := not assigned(X509_CRL_get_version);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_get_version_allownil)}
    X509_CRL_get_version := ERR_X509_CRL_get_version;
    {$ifend}
    {$if declared(X509_CRL_get_version_introduced)}
    if LibVersion < X509_CRL_get_version_introduced then
    begin
      {$if declared(FC_X509_CRL_get_version)}
      X509_CRL_get_version := FC_X509_CRL_get_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_get_version_removed)}
    if X509_CRL_get_version_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_get_version)}
      X509_CRL_get_version := _X509_CRL_get_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_get_version_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_get_version');
    {$ifend}
  end;
  
  X509_CRL_get0_lastUpdate := LoadLibFunction(ADllHandle, X509_CRL_get0_lastUpdate_procname);
  FuncLoadError := not assigned(X509_CRL_get0_lastUpdate);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_get0_lastUpdate_allownil)}
    X509_CRL_get0_lastUpdate := ERR_X509_CRL_get0_lastUpdate;
    {$ifend}
    {$if declared(X509_CRL_get0_lastUpdate_introduced)}
    if LibVersion < X509_CRL_get0_lastUpdate_introduced then
    begin
      {$if declared(FC_X509_CRL_get0_lastUpdate)}
      X509_CRL_get0_lastUpdate := FC_X509_CRL_get0_lastUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_get0_lastUpdate_removed)}
    if X509_CRL_get0_lastUpdate_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_get0_lastUpdate)}
      X509_CRL_get0_lastUpdate := _X509_CRL_get0_lastUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_get0_lastUpdate_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_get0_lastUpdate');
    {$ifend}
  end;
  
  X509_CRL_get0_nextUpdate := LoadLibFunction(ADllHandle, X509_CRL_get0_nextUpdate_procname);
  FuncLoadError := not assigned(X509_CRL_get0_nextUpdate);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_get0_nextUpdate_allownil)}
    X509_CRL_get0_nextUpdate := ERR_X509_CRL_get0_nextUpdate;
    {$ifend}
    {$if declared(X509_CRL_get0_nextUpdate_introduced)}
    if LibVersion < X509_CRL_get0_nextUpdate_introduced then
    begin
      {$if declared(FC_X509_CRL_get0_nextUpdate)}
      X509_CRL_get0_nextUpdate := FC_X509_CRL_get0_nextUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_get0_nextUpdate_removed)}
    if X509_CRL_get0_nextUpdate_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_get0_nextUpdate)}
      X509_CRL_get0_nextUpdate := _X509_CRL_get0_nextUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_get0_nextUpdate_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_get0_nextUpdate');
    {$ifend}
  end;
  
  
  
  X509_CRL_get_issuer := LoadLibFunction(ADllHandle, X509_CRL_get_issuer_procname);
  FuncLoadError := not assigned(X509_CRL_get_issuer);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_get_issuer_allownil)}
    X509_CRL_get_issuer := ERR_X509_CRL_get_issuer;
    {$ifend}
    {$if declared(X509_CRL_get_issuer_introduced)}
    if LibVersion < X509_CRL_get_issuer_introduced then
    begin
      {$if declared(FC_X509_CRL_get_issuer)}
      X509_CRL_get_issuer := FC_X509_CRL_get_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_get_issuer_removed)}
    if X509_CRL_get_issuer_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_get_issuer)}
      X509_CRL_get_issuer := _X509_CRL_get_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_get_issuer_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_get_issuer');
    {$ifend}
  end;
  
  X509_CRL_get0_extensions := LoadLibFunction(ADllHandle, X509_CRL_get0_extensions_procname);
  FuncLoadError := not assigned(X509_CRL_get0_extensions);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_get0_extensions_allownil)}
    X509_CRL_get0_extensions := ERR_X509_CRL_get0_extensions;
    {$ifend}
    {$if declared(X509_CRL_get0_extensions_introduced)}
    if LibVersion < X509_CRL_get0_extensions_introduced then
    begin
      {$if declared(FC_X509_CRL_get0_extensions)}
      X509_CRL_get0_extensions := FC_X509_CRL_get0_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_get0_extensions_removed)}
    if X509_CRL_get0_extensions_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_get0_extensions)}
      X509_CRL_get0_extensions := _X509_CRL_get0_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_get0_extensions_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_get0_extensions');
    {$ifend}
  end;
  
  X509_CRL_get_REVOKED := LoadLibFunction(ADllHandle, X509_CRL_get_REVOKED_procname);
  FuncLoadError := not assigned(X509_CRL_get_REVOKED);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_get_REVOKED_allownil)}
    X509_CRL_get_REVOKED := ERR_X509_CRL_get_REVOKED;
    {$ifend}
    {$if declared(X509_CRL_get_REVOKED_introduced)}
    if LibVersion < X509_CRL_get_REVOKED_introduced then
    begin
      {$if declared(FC_X509_CRL_get_REVOKED)}
      X509_CRL_get_REVOKED := FC_X509_CRL_get_REVOKED;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_get_REVOKED_removed)}
    if X509_CRL_get_REVOKED_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_get_REVOKED)}
      X509_CRL_get_REVOKED := _X509_CRL_get_REVOKED;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_get_REVOKED_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_get_REVOKED');
    {$ifend}
  end;
  
  X509_CRL_get0_tbs_sigalg := LoadLibFunction(ADllHandle, X509_CRL_get0_tbs_sigalg_procname);
  FuncLoadError := not assigned(X509_CRL_get0_tbs_sigalg);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_get0_tbs_sigalg_allownil)}
    X509_CRL_get0_tbs_sigalg := ERR_X509_CRL_get0_tbs_sigalg;
    {$ifend}
    {$if declared(X509_CRL_get0_tbs_sigalg_introduced)}
    if LibVersion < X509_CRL_get0_tbs_sigalg_introduced then
    begin
      {$if declared(FC_X509_CRL_get0_tbs_sigalg)}
      X509_CRL_get0_tbs_sigalg := FC_X509_CRL_get0_tbs_sigalg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_get0_tbs_sigalg_removed)}
    if X509_CRL_get0_tbs_sigalg_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_get0_tbs_sigalg)}
      X509_CRL_get0_tbs_sigalg := _X509_CRL_get0_tbs_sigalg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_get0_tbs_sigalg_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_get0_tbs_sigalg');
    {$ifend}
  end;
  
  X509_CRL_get0_signature := LoadLibFunction(ADllHandle, X509_CRL_get0_signature_procname);
  FuncLoadError := not assigned(X509_CRL_get0_signature);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_get0_signature_allownil)}
    X509_CRL_get0_signature := ERR_X509_CRL_get0_signature;
    {$ifend}
    {$if declared(X509_CRL_get0_signature_introduced)}
    if LibVersion < X509_CRL_get0_signature_introduced then
    begin
      {$if declared(FC_X509_CRL_get0_signature)}
      X509_CRL_get0_signature := FC_X509_CRL_get0_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_get0_signature_removed)}
    if X509_CRL_get0_signature_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_get0_signature)}
      X509_CRL_get0_signature := _X509_CRL_get0_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_get0_signature_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_get0_signature');
    {$ifend}
  end;
  
  X509_CRL_get_signature_nid := LoadLibFunction(ADllHandle, X509_CRL_get_signature_nid_procname);
  FuncLoadError := not assigned(X509_CRL_get_signature_nid);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_get_signature_nid_allownil)}
    X509_CRL_get_signature_nid := ERR_X509_CRL_get_signature_nid;
    {$ifend}
    {$if declared(X509_CRL_get_signature_nid_introduced)}
    if LibVersion < X509_CRL_get_signature_nid_introduced then
    begin
      {$if declared(FC_X509_CRL_get_signature_nid)}
      X509_CRL_get_signature_nid := FC_X509_CRL_get_signature_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_get_signature_nid_removed)}
    if X509_CRL_get_signature_nid_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_get_signature_nid)}
      X509_CRL_get_signature_nid := _X509_CRL_get_signature_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_get_signature_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_get_signature_nid');
    {$ifend}
  end;
  
  i2d_re_X509_CRL_tbs := LoadLibFunction(ADllHandle, i2d_re_X509_CRL_tbs_procname);
  FuncLoadError := not assigned(i2d_re_X509_CRL_tbs);
  if FuncLoadError then
  begin
    {$if not defined(i2d_re_X509_CRL_tbs_allownil)}
    i2d_re_X509_CRL_tbs := ERR_i2d_re_X509_CRL_tbs;
    {$ifend}
    {$if declared(i2d_re_X509_CRL_tbs_introduced)}
    if LibVersion < i2d_re_X509_CRL_tbs_introduced then
    begin
      {$if declared(FC_i2d_re_X509_CRL_tbs)}
      i2d_re_X509_CRL_tbs := FC_i2d_re_X509_CRL_tbs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_re_X509_CRL_tbs_removed)}
    if i2d_re_X509_CRL_tbs_removed <= LibVersion then
    begin
      {$if declared(_i2d_re_X509_CRL_tbs)}
      i2d_re_X509_CRL_tbs := _i2d_re_X509_CRL_tbs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_re_X509_CRL_tbs_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_re_X509_CRL_tbs');
    {$ifend}
  end;
  
  X509_REVOKED_get0_serialNumber := LoadLibFunction(ADllHandle, X509_REVOKED_get0_serialNumber_procname);
  FuncLoadError := not assigned(X509_REVOKED_get0_serialNumber);
  if FuncLoadError then
  begin
    {$if not defined(X509_REVOKED_get0_serialNumber_allownil)}
    X509_REVOKED_get0_serialNumber := ERR_X509_REVOKED_get0_serialNumber;
    {$ifend}
    {$if declared(X509_REVOKED_get0_serialNumber_introduced)}
    if LibVersion < X509_REVOKED_get0_serialNumber_introduced then
    begin
      {$if declared(FC_X509_REVOKED_get0_serialNumber)}
      X509_REVOKED_get0_serialNumber := FC_X509_REVOKED_get0_serialNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REVOKED_get0_serialNumber_removed)}
    if X509_REVOKED_get0_serialNumber_removed <= LibVersion then
    begin
      {$if declared(_X509_REVOKED_get0_serialNumber)}
      X509_REVOKED_get0_serialNumber := _X509_REVOKED_get0_serialNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REVOKED_get0_serialNumber_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REVOKED_get0_serialNumber');
    {$ifend}
  end;
  
  X509_REVOKED_set_serialNumber := LoadLibFunction(ADllHandle, X509_REVOKED_set_serialNumber_procname);
  FuncLoadError := not assigned(X509_REVOKED_set_serialNumber);
  if FuncLoadError then
  begin
    {$if not defined(X509_REVOKED_set_serialNumber_allownil)}
    X509_REVOKED_set_serialNumber := ERR_X509_REVOKED_set_serialNumber;
    {$ifend}
    {$if declared(X509_REVOKED_set_serialNumber_introduced)}
    if LibVersion < X509_REVOKED_set_serialNumber_introduced then
    begin
      {$if declared(FC_X509_REVOKED_set_serialNumber)}
      X509_REVOKED_set_serialNumber := FC_X509_REVOKED_set_serialNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REVOKED_set_serialNumber_removed)}
    if X509_REVOKED_set_serialNumber_removed <= LibVersion then
    begin
      {$if declared(_X509_REVOKED_set_serialNumber)}
      X509_REVOKED_set_serialNumber := _X509_REVOKED_set_serialNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REVOKED_set_serialNumber_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REVOKED_set_serialNumber');
    {$ifend}
  end;
  
  X509_REVOKED_get0_revocationDate := LoadLibFunction(ADllHandle, X509_REVOKED_get0_revocationDate_procname);
  FuncLoadError := not assigned(X509_REVOKED_get0_revocationDate);
  if FuncLoadError then
  begin
    {$if not defined(X509_REVOKED_get0_revocationDate_allownil)}
    X509_REVOKED_get0_revocationDate := ERR_X509_REVOKED_get0_revocationDate;
    {$ifend}
    {$if declared(X509_REVOKED_get0_revocationDate_introduced)}
    if LibVersion < X509_REVOKED_get0_revocationDate_introduced then
    begin
      {$if declared(FC_X509_REVOKED_get0_revocationDate)}
      X509_REVOKED_get0_revocationDate := FC_X509_REVOKED_get0_revocationDate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REVOKED_get0_revocationDate_removed)}
    if X509_REVOKED_get0_revocationDate_removed <= LibVersion then
    begin
      {$if declared(_X509_REVOKED_get0_revocationDate)}
      X509_REVOKED_get0_revocationDate := _X509_REVOKED_get0_revocationDate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REVOKED_get0_revocationDate_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REVOKED_get0_revocationDate');
    {$ifend}
  end;
  
  X509_REVOKED_set_revocationDate := LoadLibFunction(ADllHandle, X509_REVOKED_set_revocationDate_procname);
  FuncLoadError := not assigned(X509_REVOKED_set_revocationDate);
  if FuncLoadError then
  begin
    {$if not defined(X509_REVOKED_set_revocationDate_allownil)}
    X509_REVOKED_set_revocationDate := ERR_X509_REVOKED_set_revocationDate;
    {$ifend}
    {$if declared(X509_REVOKED_set_revocationDate_introduced)}
    if LibVersion < X509_REVOKED_set_revocationDate_introduced then
    begin
      {$if declared(FC_X509_REVOKED_set_revocationDate)}
      X509_REVOKED_set_revocationDate := FC_X509_REVOKED_set_revocationDate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REVOKED_set_revocationDate_removed)}
    if X509_REVOKED_set_revocationDate_removed <= LibVersion then
    begin
      {$if declared(_X509_REVOKED_set_revocationDate)}
      X509_REVOKED_set_revocationDate := _X509_REVOKED_set_revocationDate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REVOKED_set_revocationDate_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REVOKED_set_revocationDate');
    {$ifend}
  end;
  
  X509_REVOKED_get0_extensions := LoadLibFunction(ADllHandle, X509_REVOKED_get0_extensions_procname);
  FuncLoadError := not assigned(X509_REVOKED_get0_extensions);
  if FuncLoadError then
  begin
    {$if not defined(X509_REVOKED_get0_extensions_allownil)}
    X509_REVOKED_get0_extensions := ERR_X509_REVOKED_get0_extensions;
    {$ifend}
    {$if declared(X509_REVOKED_get0_extensions_introduced)}
    if LibVersion < X509_REVOKED_get0_extensions_introduced then
    begin
      {$if declared(FC_X509_REVOKED_get0_extensions)}
      X509_REVOKED_get0_extensions := FC_X509_REVOKED_get0_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REVOKED_get0_extensions_removed)}
    if X509_REVOKED_get0_extensions_removed <= LibVersion then
    begin
      {$if declared(_X509_REVOKED_get0_extensions)}
      X509_REVOKED_get0_extensions := _X509_REVOKED_get0_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REVOKED_get0_extensions_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REVOKED_get0_extensions');
    {$ifend}
  end;
  
  X509_CRL_diff := LoadLibFunction(ADllHandle, X509_CRL_diff_procname);
  FuncLoadError := not assigned(X509_CRL_diff);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_diff_allownil)}
    X509_CRL_diff := ERR_X509_CRL_diff;
    {$ifend}
    {$if declared(X509_CRL_diff_introduced)}
    if LibVersion < X509_CRL_diff_introduced then
    begin
      {$if declared(FC_X509_CRL_diff)}
      X509_CRL_diff := FC_X509_CRL_diff;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_diff_removed)}
    if X509_CRL_diff_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_diff)}
      X509_CRL_diff := _X509_CRL_diff;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_diff_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_diff');
    {$ifend}
  end;
  
  X509_REQ_check_private_key := LoadLibFunction(ADllHandle, X509_REQ_check_private_key_procname);
  FuncLoadError := not assigned(X509_REQ_check_private_key);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_check_private_key_allownil)}
    X509_REQ_check_private_key := ERR_X509_REQ_check_private_key;
    {$ifend}
    {$if declared(X509_REQ_check_private_key_introduced)}
    if LibVersion < X509_REQ_check_private_key_introduced then
    begin
      {$if declared(FC_X509_REQ_check_private_key)}
      X509_REQ_check_private_key := FC_X509_REQ_check_private_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_check_private_key_removed)}
    if X509_REQ_check_private_key_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_check_private_key)}
      X509_REQ_check_private_key := _X509_REQ_check_private_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_check_private_key_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_check_private_key');
    {$ifend}
  end;
  
  X509_check_private_key := LoadLibFunction(ADllHandle, X509_check_private_key_procname);
  FuncLoadError := not assigned(X509_check_private_key);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_private_key_allownil)}
    X509_check_private_key := ERR_X509_check_private_key;
    {$ifend}
    {$if declared(X509_check_private_key_introduced)}
    if LibVersion < X509_check_private_key_introduced then
    begin
      {$if declared(FC_X509_check_private_key)}
      X509_check_private_key := FC_X509_check_private_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_private_key_removed)}
    if X509_check_private_key_removed <= LibVersion then
    begin
      {$if declared(_X509_check_private_key)}
      X509_check_private_key := _X509_check_private_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_private_key_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_private_key');
    {$ifend}
  end;
  
  X509_chain_check_suiteb := LoadLibFunction(ADllHandle, X509_chain_check_suiteb_procname);
  FuncLoadError := not assigned(X509_chain_check_suiteb);
  if FuncLoadError then
  begin
    {$if not defined(X509_chain_check_suiteb_allownil)}
    X509_chain_check_suiteb := ERR_X509_chain_check_suiteb;
    {$ifend}
    {$if declared(X509_chain_check_suiteb_introduced)}
    if LibVersion < X509_chain_check_suiteb_introduced then
    begin
      {$if declared(FC_X509_chain_check_suiteb)}
      X509_chain_check_suiteb := FC_X509_chain_check_suiteb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_chain_check_suiteb_removed)}
    if X509_chain_check_suiteb_removed <= LibVersion then
    begin
      {$if declared(_X509_chain_check_suiteb)}
      X509_chain_check_suiteb := _X509_chain_check_suiteb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_chain_check_suiteb_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_chain_check_suiteb');
    {$ifend}
  end;
  
  X509_CRL_check_suiteb := LoadLibFunction(ADllHandle, X509_CRL_check_suiteb_procname);
  FuncLoadError := not assigned(X509_CRL_check_suiteb);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_check_suiteb_allownil)}
    X509_CRL_check_suiteb := ERR_X509_CRL_check_suiteb;
    {$ifend}
    {$if declared(X509_CRL_check_suiteb_introduced)}
    if LibVersion < X509_CRL_check_suiteb_introduced then
    begin
      {$if declared(FC_X509_CRL_check_suiteb)}
      X509_CRL_check_suiteb := FC_X509_CRL_check_suiteb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_check_suiteb_removed)}
    if X509_CRL_check_suiteb_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_check_suiteb)}
      X509_CRL_check_suiteb := _X509_CRL_check_suiteb;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_check_suiteb_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_check_suiteb');
    {$ifend}
  end;
  
  OSSL_STACK_OF_X509_free := LoadLibFunction(ADllHandle, OSSL_STACK_OF_X509_free_procname);
  FuncLoadError := not assigned(OSSL_STACK_OF_X509_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_STACK_OF_X509_free_allownil)}
    OSSL_STACK_OF_X509_free := ERR_OSSL_STACK_OF_X509_free;
    {$ifend}
    {$if declared(OSSL_STACK_OF_X509_free_introduced)}
    if LibVersion < OSSL_STACK_OF_X509_free_introduced then
    begin
      {$if declared(FC_OSSL_STACK_OF_X509_free)}
      OSSL_STACK_OF_X509_free := FC_OSSL_STACK_OF_X509_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_STACK_OF_X509_free_removed)}
    if OSSL_STACK_OF_X509_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_STACK_OF_X509_free)}
      OSSL_STACK_OF_X509_free := _OSSL_STACK_OF_X509_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_STACK_OF_X509_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_STACK_OF_X509_free');
    {$ifend}
  end;
  
  X509_chain_up_ref := LoadLibFunction(ADllHandle, X509_chain_up_ref_procname);
  FuncLoadError := not assigned(X509_chain_up_ref);
  if FuncLoadError then
  begin
    {$if not defined(X509_chain_up_ref_allownil)}
    X509_chain_up_ref := ERR_X509_chain_up_ref;
    {$ifend}
    {$if declared(X509_chain_up_ref_introduced)}
    if LibVersion < X509_chain_up_ref_introduced then
    begin
      {$if declared(FC_X509_chain_up_ref)}
      X509_chain_up_ref := FC_X509_chain_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_chain_up_ref_removed)}
    if X509_chain_up_ref_removed <= LibVersion then
    begin
      {$if declared(_X509_chain_up_ref)}
      X509_chain_up_ref := _X509_chain_up_ref;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_chain_up_ref_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_chain_up_ref');
    {$ifend}
  end;
  
  X509_issuer_and_serial_cmp := LoadLibFunction(ADllHandle, X509_issuer_and_serial_cmp_procname);
  FuncLoadError := not assigned(X509_issuer_and_serial_cmp);
  if FuncLoadError then
  begin
    {$if not defined(X509_issuer_and_serial_cmp_allownil)}
    X509_issuer_and_serial_cmp := ERR_X509_issuer_and_serial_cmp;
    {$ifend}
    {$if declared(X509_issuer_and_serial_cmp_introduced)}
    if LibVersion < X509_issuer_and_serial_cmp_introduced then
    begin
      {$if declared(FC_X509_issuer_and_serial_cmp)}
      X509_issuer_and_serial_cmp := FC_X509_issuer_and_serial_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_issuer_and_serial_cmp_removed)}
    if X509_issuer_and_serial_cmp_removed <= LibVersion then
    begin
      {$if declared(_X509_issuer_and_serial_cmp)}
      X509_issuer_and_serial_cmp := _X509_issuer_and_serial_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_issuer_and_serial_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_issuer_and_serial_cmp');
    {$ifend}
  end;
  
  X509_issuer_and_serial_hash := LoadLibFunction(ADllHandle, X509_issuer_and_serial_hash_procname);
  FuncLoadError := not assigned(X509_issuer_and_serial_hash);
  if FuncLoadError then
  begin
    {$if not defined(X509_issuer_and_serial_hash_allownil)}
    X509_issuer_and_serial_hash := ERR_X509_issuer_and_serial_hash;
    {$ifend}
    {$if declared(X509_issuer_and_serial_hash_introduced)}
    if LibVersion < X509_issuer_and_serial_hash_introduced then
    begin
      {$if declared(FC_X509_issuer_and_serial_hash)}
      X509_issuer_and_serial_hash := FC_X509_issuer_and_serial_hash;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_issuer_and_serial_hash_removed)}
    if X509_issuer_and_serial_hash_removed <= LibVersion then
    begin
      {$if declared(_X509_issuer_and_serial_hash)}
      X509_issuer_and_serial_hash := _X509_issuer_and_serial_hash;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_issuer_and_serial_hash_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_issuer_and_serial_hash');
    {$ifend}
  end;
  
  X509_issuer_name_cmp := LoadLibFunction(ADllHandle, X509_issuer_name_cmp_procname);
  FuncLoadError := not assigned(X509_issuer_name_cmp);
  if FuncLoadError then
  begin
    {$if not defined(X509_issuer_name_cmp_allownil)}
    X509_issuer_name_cmp := ERR_X509_issuer_name_cmp;
    {$ifend}
    {$if declared(X509_issuer_name_cmp_introduced)}
    if LibVersion < X509_issuer_name_cmp_introduced then
    begin
      {$if declared(FC_X509_issuer_name_cmp)}
      X509_issuer_name_cmp := FC_X509_issuer_name_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_issuer_name_cmp_removed)}
    if X509_issuer_name_cmp_removed <= LibVersion then
    begin
      {$if declared(_X509_issuer_name_cmp)}
      X509_issuer_name_cmp := _X509_issuer_name_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_issuer_name_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_issuer_name_cmp');
    {$ifend}
  end;
  
  X509_issuer_name_hash := LoadLibFunction(ADllHandle, X509_issuer_name_hash_procname);
  FuncLoadError := not assigned(X509_issuer_name_hash);
  if FuncLoadError then
  begin
    {$if not defined(X509_issuer_name_hash_allownil)}
    X509_issuer_name_hash := ERR_X509_issuer_name_hash;
    {$ifend}
    {$if declared(X509_issuer_name_hash_introduced)}
    if LibVersion < X509_issuer_name_hash_introduced then
    begin
      {$if declared(FC_X509_issuer_name_hash)}
      X509_issuer_name_hash := FC_X509_issuer_name_hash;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_issuer_name_hash_removed)}
    if X509_issuer_name_hash_removed <= LibVersion then
    begin
      {$if declared(_X509_issuer_name_hash)}
      X509_issuer_name_hash := _X509_issuer_name_hash;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_issuer_name_hash_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_issuer_name_hash');
    {$ifend}
  end;
  
  X509_subject_name_cmp := LoadLibFunction(ADllHandle, X509_subject_name_cmp_procname);
  FuncLoadError := not assigned(X509_subject_name_cmp);
  if FuncLoadError then
  begin
    {$if not defined(X509_subject_name_cmp_allownil)}
    X509_subject_name_cmp := ERR_X509_subject_name_cmp;
    {$ifend}
    {$if declared(X509_subject_name_cmp_introduced)}
    if LibVersion < X509_subject_name_cmp_introduced then
    begin
      {$if declared(FC_X509_subject_name_cmp)}
      X509_subject_name_cmp := FC_X509_subject_name_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_subject_name_cmp_removed)}
    if X509_subject_name_cmp_removed <= LibVersion then
    begin
      {$if declared(_X509_subject_name_cmp)}
      X509_subject_name_cmp := _X509_subject_name_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_subject_name_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_subject_name_cmp');
    {$ifend}
  end;
  
  X509_subject_name_hash := LoadLibFunction(ADllHandle, X509_subject_name_hash_procname);
  FuncLoadError := not assigned(X509_subject_name_hash);
  if FuncLoadError then
  begin
    {$if not defined(X509_subject_name_hash_allownil)}
    X509_subject_name_hash := ERR_X509_subject_name_hash;
    {$ifend}
    {$if declared(X509_subject_name_hash_introduced)}
    if LibVersion < X509_subject_name_hash_introduced then
    begin
      {$if declared(FC_X509_subject_name_hash)}
      X509_subject_name_hash := FC_X509_subject_name_hash;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_subject_name_hash_removed)}
    if X509_subject_name_hash_removed <= LibVersion then
    begin
      {$if declared(_X509_subject_name_hash)}
      X509_subject_name_hash := _X509_subject_name_hash;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_subject_name_hash_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_subject_name_hash');
    {$ifend}
  end;
  
  X509_issuer_name_hash_old := LoadLibFunction(ADllHandle, X509_issuer_name_hash_old_procname);
  FuncLoadError := not assigned(X509_issuer_name_hash_old);
  if FuncLoadError then
  begin
    {$if not defined(X509_issuer_name_hash_old_allownil)}
    X509_issuer_name_hash_old := ERR_X509_issuer_name_hash_old;
    {$ifend}
    {$if declared(X509_issuer_name_hash_old_introduced)}
    if LibVersion < X509_issuer_name_hash_old_introduced then
    begin
      {$if declared(FC_X509_issuer_name_hash_old)}
      X509_issuer_name_hash_old := FC_X509_issuer_name_hash_old;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_issuer_name_hash_old_removed)}
    if X509_issuer_name_hash_old_removed <= LibVersion then
    begin
      {$if declared(_X509_issuer_name_hash_old)}
      X509_issuer_name_hash_old := _X509_issuer_name_hash_old;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_issuer_name_hash_old_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_issuer_name_hash_old');
    {$ifend}
  end;
  
  X509_subject_name_hash_old := LoadLibFunction(ADllHandle, X509_subject_name_hash_old_procname);
  FuncLoadError := not assigned(X509_subject_name_hash_old);
  if FuncLoadError then
  begin
    {$if not defined(X509_subject_name_hash_old_allownil)}
    X509_subject_name_hash_old := ERR_X509_subject_name_hash_old;
    {$ifend}
    {$if declared(X509_subject_name_hash_old_introduced)}
    if LibVersion < X509_subject_name_hash_old_introduced then
    begin
      {$if declared(FC_X509_subject_name_hash_old)}
      X509_subject_name_hash_old := FC_X509_subject_name_hash_old;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_subject_name_hash_old_removed)}
    if X509_subject_name_hash_old_removed <= LibVersion then
    begin
      {$if declared(_X509_subject_name_hash_old)}
      X509_subject_name_hash_old := _X509_subject_name_hash_old;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_subject_name_hash_old_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_subject_name_hash_old');
    {$ifend}
  end;
  
  X509_add_cert := LoadLibFunction(ADllHandle, X509_add_cert_procname);
  FuncLoadError := not assigned(X509_add_cert);
  if FuncLoadError then
  begin
    {$if not defined(X509_add_cert_allownil)}
    X509_add_cert := ERR_X509_add_cert;
    {$ifend}
    {$if declared(X509_add_cert_introduced)}
    if LibVersion < X509_add_cert_introduced then
    begin
      {$if declared(FC_X509_add_cert)}
      X509_add_cert := FC_X509_add_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_add_cert_removed)}
    if X509_add_cert_removed <= LibVersion then
    begin
      {$if declared(_X509_add_cert)}
      X509_add_cert := _X509_add_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_add_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_add_cert');
    {$ifend}
  end;
  
  X509_add_certs := LoadLibFunction(ADllHandle, X509_add_certs_procname);
  FuncLoadError := not assigned(X509_add_certs);
  if FuncLoadError then
  begin
    {$if not defined(X509_add_certs_allownil)}
    X509_add_certs := ERR_X509_add_certs;
    {$ifend}
    {$if declared(X509_add_certs_introduced)}
    if LibVersion < X509_add_certs_introduced then
    begin
      {$if declared(FC_X509_add_certs)}
      X509_add_certs := FC_X509_add_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_add_certs_removed)}
    if X509_add_certs_removed <= LibVersion then
    begin
      {$if declared(_X509_add_certs)}
      X509_add_certs := _X509_add_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_add_certs_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_add_certs');
    {$ifend}
  end;
  
  X509_cmp := LoadLibFunction(ADllHandle, X509_cmp_procname);
  FuncLoadError := not assigned(X509_cmp);
  if FuncLoadError then
  begin
    {$if not defined(X509_cmp_allownil)}
    X509_cmp := ERR_X509_cmp;
    {$ifend}
    {$if declared(X509_cmp_introduced)}
    if LibVersion < X509_cmp_introduced then
    begin
      {$if declared(FC_X509_cmp)}
      X509_cmp := FC_X509_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_cmp_removed)}
    if X509_cmp_removed <= LibVersion then
    begin
      {$if declared(_X509_cmp)}
      X509_cmp := _X509_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_cmp');
    {$ifend}
  end;
  
  X509_NAME_cmp := LoadLibFunction(ADllHandle, X509_NAME_cmp_procname);
  FuncLoadError := not assigned(X509_NAME_cmp);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_cmp_allownil)}
    X509_NAME_cmp := ERR_X509_NAME_cmp;
    {$ifend}
    {$if declared(X509_NAME_cmp_introduced)}
    if LibVersion < X509_NAME_cmp_introduced then
    begin
      {$if declared(FC_X509_NAME_cmp)}
      X509_NAME_cmp := FC_X509_NAME_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_cmp_removed)}
    if X509_NAME_cmp_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_cmp)}
      X509_NAME_cmp := _X509_NAME_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_cmp');
    {$ifend}
  end;
  
  X509_certificate_type := LoadLibFunction(ADllHandle, X509_certificate_type_procname);
  FuncLoadError := not assigned(X509_certificate_type);
  if FuncLoadError then
  begin
    {$if not defined(X509_certificate_type_allownil)}
    X509_certificate_type := ERR_X509_certificate_type;
    {$ifend}
    {$if declared(X509_certificate_type_introduced)}
    if LibVersion < X509_certificate_type_introduced then
    begin
      {$if declared(FC_X509_certificate_type)}
      X509_certificate_type := FC_X509_certificate_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_certificate_type_removed)}
    if X509_certificate_type_removed <= LibVersion then
    begin
      {$if declared(_X509_certificate_type)}
      X509_certificate_type := _X509_certificate_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_certificate_type_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_certificate_type');
    {$ifend}
  end;
  
  X509_NAME_hash_ex := LoadLibFunction(ADllHandle, X509_NAME_hash_ex_procname);
  FuncLoadError := not assigned(X509_NAME_hash_ex);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_hash_ex_allownil)}
    X509_NAME_hash_ex := ERR_X509_NAME_hash_ex;
    {$ifend}
    {$if declared(X509_NAME_hash_ex_introduced)}
    if LibVersion < X509_NAME_hash_ex_introduced then
    begin
      {$if declared(FC_X509_NAME_hash_ex)}
      X509_NAME_hash_ex := FC_X509_NAME_hash_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_hash_ex_removed)}
    if X509_NAME_hash_ex_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_hash_ex)}
      X509_NAME_hash_ex := _X509_NAME_hash_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_hash_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_hash_ex');
    {$ifend}
  end;
  
  X509_NAME_hash_old := LoadLibFunction(ADllHandle, X509_NAME_hash_old_procname);
  FuncLoadError := not assigned(X509_NAME_hash_old);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_hash_old_allownil)}
    X509_NAME_hash_old := ERR_X509_NAME_hash_old;
    {$ifend}
    {$if declared(X509_NAME_hash_old_introduced)}
    if LibVersion < X509_NAME_hash_old_introduced then
    begin
      {$if declared(FC_X509_NAME_hash_old)}
      X509_NAME_hash_old := FC_X509_NAME_hash_old;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_hash_old_removed)}
    if X509_NAME_hash_old_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_hash_old)}
      X509_NAME_hash_old := _X509_NAME_hash_old;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_hash_old_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_hash_old');
    {$ifend}
  end;
  
  X509_CRL_cmp := LoadLibFunction(ADllHandle, X509_CRL_cmp_procname);
  FuncLoadError := not assigned(X509_CRL_cmp);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_cmp_allownil)}
    X509_CRL_cmp := ERR_X509_CRL_cmp;
    {$ifend}
    {$if declared(X509_CRL_cmp_introduced)}
    if LibVersion < X509_CRL_cmp_introduced then
    begin
      {$if declared(FC_X509_CRL_cmp)}
      X509_CRL_cmp := FC_X509_CRL_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_cmp_removed)}
    if X509_CRL_cmp_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_cmp)}
      X509_CRL_cmp := _X509_CRL_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_cmp');
    {$ifend}
  end;
  
  X509_CRL_match := LoadLibFunction(ADllHandle, X509_CRL_match_procname);
  FuncLoadError := not assigned(X509_CRL_match);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_match_allownil)}
    X509_CRL_match := ERR_X509_CRL_match;
    {$ifend}
    {$if declared(X509_CRL_match_introduced)}
    if LibVersion < X509_CRL_match_introduced then
    begin
      {$if declared(FC_X509_CRL_match)}
      X509_CRL_match := FC_X509_CRL_match;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_match_removed)}
    if X509_CRL_match_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_match)}
      X509_CRL_match := _X509_CRL_match;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_match_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_match');
    {$ifend}
  end;
  
  X509_aux_print := LoadLibFunction(ADllHandle, X509_aux_print_procname);
  FuncLoadError := not assigned(X509_aux_print);
  if FuncLoadError then
  begin
    {$if not defined(X509_aux_print_allownil)}
    X509_aux_print := ERR_X509_aux_print;
    {$ifend}
    {$if declared(X509_aux_print_introduced)}
    if LibVersion < X509_aux_print_introduced then
    begin
      {$if declared(FC_X509_aux_print)}
      X509_aux_print := FC_X509_aux_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_aux_print_removed)}
    if X509_aux_print_removed <= LibVersion then
    begin
      {$if declared(_X509_aux_print)}
      X509_aux_print := _X509_aux_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_aux_print_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_aux_print');
    {$ifend}
  end;
  
  X509_print_ex_fp := LoadLibFunction(ADllHandle, X509_print_ex_fp_procname);
  FuncLoadError := not assigned(X509_print_ex_fp);
  if FuncLoadError then
  begin
    {$if not defined(X509_print_ex_fp_allownil)}
    X509_print_ex_fp := ERR_X509_print_ex_fp;
    {$ifend}
    {$if declared(X509_print_ex_fp_introduced)}
    if LibVersion < X509_print_ex_fp_introduced then
    begin
      {$if declared(FC_X509_print_ex_fp)}
      X509_print_ex_fp := FC_X509_print_ex_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_print_ex_fp_removed)}
    if X509_print_ex_fp_removed <= LibVersion then
    begin
      {$if declared(_X509_print_ex_fp)}
      X509_print_ex_fp := _X509_print_ex_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_print_ex_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_print_ex_fp');
    {$ifend}
  end;
  
  X509_print_fp := LoadLibFunction(ADllHandle, X509_print_fp_procname);
  FuncLoadError := not assigned(X509_print_fp);
  if FuncLoadError then
  begin
    {$if not defined(X509_print_fp_allownil)}
    X509_print_fp := ERR_X509_print_fp;
    {$ifend}
    {$if declared(X509_print_fp_introduced)}
    if LibVersion < X509_print_fp_introduced then
    begin
      {$if declared(FC_X509_print_fp)}
      X509_print_fp := FC_X509_print_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_print_fp_removed)}
    if X509_print_fp_removed <= LibVersion then
    begin
      {$if declared(_X509_print_fp)}
      X509_print_fp := _X509_print_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_print_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_print_fp');
    {$ifend}
  end;
  
  X509_CRL_print_fp := LoadLibFunction(ADllHandle, X509_CRL_print_fp_procname);
  FuncLoadError := not assigned(X509_CRL_print_fp);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_print_fp_allownil)}
    X509_CRL_print_fp := ERR_X509_CRL_print_fp;
    {$ifend}
    {$if declared(X509_CRL_print_fp_introduced)}
    if LibVersion < X509_CRL_print_fp_introduced then
    begin
      {$if declared(FC_X509_CRL_print_fp)}
      X509_CRL_print_fp := FC_X509_CRL_print_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_print_fp_removed)}
    if X509_CRL_print_fp_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_print_fp)}
      X509_CRL_print_fp := _X509_CRL_print_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_print_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_print_fp');
    {$ifend}
  end;
  
  X509_REQ_print_fp := LoadLibFunction(ADllHandle, X509_REQ_print_fp_procname);
  FuncLoadError := not assigned(X509_REQ_print_fp);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_print_fp_allownil)}
    X509_REQ_print_fp := ERR_X509_REQ_print_fp;
    {$ifend}
    {$if declared(X509_REQ_print_fp_introduced)}
    if LibVersion < X509_REQ_print_fp_introduced then
    begin
      {$if declared(FC_X509_REQ_print_fp)}
      X509_REQ_print_fp := FC_X509_REQ_print_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_print_fp_removed)}
    if X509_REQ_print_fp_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_print_fp)}
      X509_REQ_print_fp := _X509_REQ_print_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_print_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_print_fp');
    {$ifend}
  end;
  
  X509_NAME_print_ex_fp := LoadLibFunction(ADllHandle, X509_NAME_print_ex_fp_procname);
  FuncLoadError := not assigned(X509_NAME_print_ex_fp);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_print_ex_fp_allownil)}
    X509_NAME_print_ex_fp := ERR_X509_NAME_print_ex_fp;
    {$ifend}
    {$if declared(X509_NAME_print_ex_fp_introduced)}
    if LibVersion < X509_NAME_print_ex_fp_introduced then
    begin
      {$if declared(FC_X509_NAME_print_ex_fp)}
      X509_NAME_print_ex_fp := FC_X509_NAME_print_ex_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_print_ex_fp_removed)}
    if X509_NAME_print_ex_fp_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_print_ex_fp)}
      X509_NAME_print_ex_fp := _X509_NAME_print_ex_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_print_ex_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_print_ex_fp');
    {$ifend}
  end;
  
  X509_NAME_print := LoadLibFunction(ADllHandle, X509_NAME_print_procname);
  FuncLoadError := not assigned(X509_NAME_print);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_print_allownil)}
    X509_NAME_print := ERR_X509_NAME_print;
    {$ifend}
    {$if declared(X509_NAME_print_introduced)}
    if LibVersion < X509_NAME_print_introduced then
    begin
      {$if declared(FC_X509_NAME_print)}
      X509_NAME_print := FC_X509_NAME_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_print_removed)}
    if X509_NAME_print_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_print)}
      X509_NAME_print := _X509_NAME_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_print_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_print');
    {$ifend}
  end;
  
  X509_NAME_print_ex := LoadLibFunction(ADllHandle, X509_NAME_print_ex_procname);
  FuncLoadError := not assigned(X509_NAME_print_ex);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_print_ex_allownil)}
    X509_NAME_print_ex := ERR_X509_NAME_print_ex;
    {$ifend}
    {$if declared(X509_NAME_print_ex_introduced)}
    if LibVersion < X509_NAME_print_ex_introduced then
    begin
      {$if declared(FC_X509_NAME_print_ex)}
      X509_NAME_print_ex := FC_X509_NAME_print_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_print_ex_removed)}
    if X509_NAME_print_ex_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_print_ex)}
      X509_NAME_print_ex := _X509_NAME_print_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_print_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_print_ex');
    {$ifend}
  end;
  
  X509_print_ex := LoadLibFunction(ADllHandle, X509_print_ex_procname);
  FuncLoadError := not assigned(X509_print_ex);
  if FuncLoadError then
  begin
    {$if not defined(X509_print_ex_allownil)}
    X509_print_ex := ERR_X509_print_ex;
    {$ifend}
    {$if declared(X509_print_ex_introduced)}
    if LibVersion < X509_print_ex_introduced then
    begin
      {$if declared(FC_X509_print_ex)}
      X509_print_ex := FC_X509_print_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_print_ex_removed)}
    if X509_print_ex_removed <= LibVersion then
    begin
      {$if declared(_X509_print_ex)}
      X509_print_ex := _X509_print_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_print_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_print_ex');
    {$ifend}
  end;
  
  X509_print := LoadLibFunction(ADllHandle, X509_print_procname);
  FuncLoadError := not assigned(X509_print);
  if FuncLoadError then
  begin
    {$if not defined(X509_print_allownil)}
    X509_print := ERR_X509_print;
    {$ifend}
    {$if declared(X509_print_introduced)}
    if LibVersion < X509_print_introduced then
    begin
      {$if declared(FC_X509_print)}
      X509_print := FC_X509_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_print_removed)}
    if X509_print_removed <= LibVersion then
    begin
      {$if declared(_X509_print)}
      X509_print := _X509_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_print_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_print');
    {$ifend}
  end;
  
  X509_ocspid_print := LoadLibFunction(ADllHandle, X509_ocspid_print_procname);
  FuncLoadError := not assigned(X509_ocspid_print);
  if FuncLoadError then
  begin
    {$if not defined(X509_ocspid_print_allownil)}
    X509_ocspid_print := ERR_X509_ocspid_print;
    {$ifend}
    {$if declared(X509_ocspid_print_introduced)}
    if LibVersion < X509_ocspid_print_introduced then
    begin
      {$if declared(FC_X509_ocspid_print)}
      X509_ocspid_print := FC_X509_ocspid_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ocspid_print_removed)}
    if X509_ocspid_print_removed <= LibVersion then
    begin
      {$if declared(_X509_ocspid_print)}
      X509_ocspid_print := _X509_ocspid_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ocspid_print_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ocspid_print');
    {$ifend}
  end;
  
  X509_CRL_print_ex := LoadLibFunction(ADllHandle, X509_CRL_print_ex_procname);
  FuncLoadError := not assigned(X509_CRL_print_ex);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_print_ex_allownil)}
    X509_CRL_print_ex := ERR_X509_CRL_print_ex;
    {$ifend}
    {$if declared(X509_CRL_print_ex_introduced)}
    if LibVersion < X509_CRL_print_ex_introduced then
    begin
      {$if declared(FC_X509_CRL_print_ex)}
      X509_CRL_print_ex := FC_X509_CRL_print_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_print_ex_removed)}
    if X509_CRL_print_ex_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_print_ex)}
      X509_CRL_print_ex := _X509_CRL_print_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_print_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_print_ex');
    {$ifend}
  end;
  
  X509_CRL_print := LoadLibFunction(ADllHandle, X509_CRL_print_procname);
  FuncLoadError := not assigned(X509_CRL_print);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_print_allownil)}
    X509_CRL_print := ERR_X509_CRL_print;
    {$ifend}
    {$if declared(X509_CRL_print_introduced)}
    if LibVersion < X509_CRL_print_introduced then
    begin
      {$if declared(FC_X509_CRL_print)}
      X509_CRL_print := FC_X509_CRL_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_print_removed)}
    if X509_CRL_print_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_print)}
      X509_CRL_print := _X509_CRL_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_print_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_print');
    {$ifend}
  end;
  
  X509_REQ_print_ex := LoadLibFunction(ADllHandle, X509_REQ_print_ex_procname);
  FuncLoadError := not assigned(X509_REQ_print_ex);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_print_ex_allownil)}
    X509_REQ_print_ex := ERR_X509_REQ_print_ex;
    {$ifend}
    {$if declared(X509_REQ_print_ex_introduced)}
    if LibVersion < X509_REQ_print_ex_introduced then
    begin
      {$if declared(FC_X509_REQ_print_ex)}
      X509_REQ_print_ex := FC_X509_REQ_print_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_print_ex_removed)}
    if X509_REQ_print_ex_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_print_ex)}
      X509_REQ_print_ex := _X509_REQ_print_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_print_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_print_ex');
    {$ifend}
  end;
  
  X509_REQ_print := LoadLibFunction(ADllHandle, X509_REQ_print_procname);
  FuncLoadError := not assigned(X509_REQ_print);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_print_allownil)}
    X509_REQ_print := ERR_X509_REQ_print;
    {$ifend}
    {$if declared(X509_REQ_print_introduced)}
    if LibVersion < X509_REQ_print_introduced then
    begin
      {$if declared(FC_X509_REQ_print)}
      X509_REQ_print := FC_X509_REQ_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_print_removed)}
    if X509_REQ_print_removed <= LibVersion then
    begin
      {$if declared(_X509_REQ_print)}
      X509_REQ_print := _X509_REQ_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_print_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_print');
    {$ifend}
  end;
  
  X509_NAME_entry_count := LoadLibFunction(ADllHandle, X509_NAME_entry_count_procname);
  FuncLoadError := not assigned(X509_NAME_entry_count);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_entry_count_allownil)}
    X509_NAME_entry_count := ERR_X509_NAME_entry_count;
    {$ifend}
    {$if declared(X509_NAME_entry_count_introduced)}
    if LibVersion < X509_NAME_entry_count_introduced then
    begin
      {$if declared(FC_X509_NAME_entry_count)}
      X509_NAME_entry_count := FC_X509_NAME_entry_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_entry_count_removed)}
    if X509_NAME_entry_count_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_entry_count)}
      X509_NAME_entry_count := _X509_NAME_entry_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_entry_count_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_entry_count');
    {$ifend}
  end;
  
  X509_NAME_get_text_by_NID := LoadLibFunction(ADllHandle, X509_NAME_get_text_by_NID_procname);
  FuncLoadError := not assigned(X509_NAME_get_text_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_get_text_by_NID_allownil)}
    X509_NAME_get_text_by_NID := ERR_X509_NAME_get_text_by_NID;
    {$ifend}
    {$if declared(X509_NAME_get_text_by_NID_introduced)}
    if LibVersion < X509_NAME_get_text_by_NID_introduced then
    begin
      {$if declared(FC_X509_NAME_get_text_by_NID)}
      X509_NAME_get_text_by_NID := FC_X509_NAME_get_text_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_get_text_by_NID_removed)}
    if X509_NAME_get_text_by_NID_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_get_text_by_NID)}
      X509_NAME_get_text_by_NID := _X509_NAME_get_text_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_get_text_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_get_text_by_NID');
    {$ifend}
  end;
  
  X509_NAME_get_text_by_OBJ := LoadLibFunction(ADllHandle, X509_NAME_get_text_by_OBJ_procname);
  FuncLoadError := not assigned(X509_NAME_get_text_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_get_text_by_OBJ_allownil)}
    X509_NAME_get_text_by_OBJ := ERR_X509_NAME_get_text_by_OBJ;
    {$ifend}
    {$if declared(X509_NAME_get_text_by_OBJ_introduced)}
    if LibVersion < X509_NAME_get_text_by_OBJ_introduced then
    begin
      {$if declared(FC_X509_NAME_get_text_by_OBJ)}
      X509_NAME_get_text_by_OBJ := FC_X509_NAME_get_text_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_get_text_by_OBJ_removed)}
    if X509_NAME_get_text_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_get_text_by_OBJ)}
      X509_NAME_get_text_by_OBJ := _X509_NAME_get_text_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_get_text_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_get_text_by_OBJ');
    {$ifend}
  end;
  
  X509_NAME_get_index_by_NID := LoadLibFunction(ADllHandle, X509_NAME_get_index_by_NID_procname);
  FuncLoadError := not assigned(X509_NAME_get_index_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_get_index_by_NID_allownil)}
    X509_NAME_get_index_by_NID := ERR_X509_NAME_get_index_by_NID;
    {$ifend}
    {$if declared(X509_NAME_get_index_by_NID_introduced)}
    if LibVersion < X509_NAME_get_index_by_NID_introduced then
    begin
      {$if declared(FC_X509_NAME_get_index_by_NID)}
      X509_NAME_get_index_by_NID := FC_X509_NAME_get_index_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_get_index_by_NID_removed)}
    if X509_NAME_get_index_by_NID_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_get_index_by_NID)}
      X509_NAME_get_index_by_NID := _X509_NAME_get_index_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_get_index_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_get_index_by_NID');
    {$ifend}
  end;
  
  X509_NAME_get_index_by_OBJ := LoadLibFunction(ADllHandle, X509_NAME_get_index_by_OBJ_procname);
  FuncLoadError := not assigned(X509_NAME_get_index_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_get_index_by_OBJ_allownil)}
    X509_NAME_get_index_by_OBJ := ERR_X509_NAME_get_index_by_OBJ;
    {$ifend}
    {$if declared(X509_NAME_get_index_by_OBJ_introduced)}
    if LibVersion < X509_NAME_get_index_by_OBJ_introduced then
    begin
      {$if declared(FC_X509_NAME_get_index_by_OBJ)}
      X509_NAME_get_index_by_OBJ := FC_X509_NAME_get_index_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_get_index_by_OBJ_removed)}
    if X509_NAME_get_index_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_get_index_by_OBJ)}
      X509_NAME_get_index_by_OBJ := _X509_NAME_get_index_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_get_index_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_get_index_by_OBJ');
    {$ifend}
  end;
  
  X509_NAME_get_entry := LoadLibFunction(ADllHandle, X509_NAME_get_entry_procname);
  FuncLoadError := not assigned(X509_NAME_get_entry);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_get_entry_allownil)}
    X509_NAME_get_entry := ERR_X509_NAME_get_entry;
    {$ifend}
    {$if declared(X509_NAME_get_entry_introduced)}
    if LibVersion < X509_NAME_get_entry_introduced then
    begin
      {$if declared(FC_X509_NAME_get_entry)}
      X509_NAME_get_entry := FC_X509_NAME_get_entry;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_get_entry_removed)}
    if X509_NAME_get_entry_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_get_entry)}
      X509_NAME_get_entry := _X509_NAME_get_entry;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_get_entry_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_get_entry');
    {$ifend}
  end;
  
  X509_NAME_delete_entry := LoadLibFunction(ADllHandle, X509_NAME_delete_entry_procname);
  FuncLoadError := not assigned(X509_NAME_delete_entry);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_delete_entry_allownil)}
    X509_NAME_delete_entry := ERR_X509_NAME_delete_entry;
    {$ifend}
    {$if declared(X509_NAME_delete_entry_introduced)}
    if LibVersion < X509_NAME_delete_entry_introduced then
    begin
      {$if declared(FC_X509_NAME_delete_entry)}
      X509_NAME_delete_entry := FC_X509_NAME_delete_entry;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_delete_entry_removed)}
    if X509_NAME_delete_entry_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_delete_entry)}
      X509_NAME_delete_entry := _X509_NAME_delete_entry;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_delete_entry_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_delete_entry');
    {$ifend}
  end;
  
  X509_NAME_add_entry := LoadLibFunction(ADllHandle, X509_NAME_add_entry_procname);
  FuncLoadError := not assigned(X509_NAME_add_entry);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_add_entry_allownil)}
    X509_NAME_add_entry := ERR_X509_NAME_add_entry;
    {$ifend}
    {$if declared(X509_NAME_add_entry_introduced)}
    if LibVersion < X509_NAME_add_entry_introduced then
    begin
      {$if declared(FC_X509_NAME_add_entry)}
      X509_NAME_add_entry := FC_X509_NAME_add_entry;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_add_entry_removed)}
    if X509_NAME_add_entry_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_add_entry)}
      X509_NAME_add_entry := _X509_NAME_add_entry;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_add_entry_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_add_entry');
    {$ifend}
  end;
  
  X509_NAME_add_entry_by_OBJ := LoadLibFunction(ADllHandle, X509_NAME_add_entry_by_OBJ_procname);
  FuncLoadError := not assigned(X509_NAME_add_entry_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_add_entry_by_OBJ_allownil)}
    X509_NAME_add_entry_by_OBJ := ERR_X509_NAME_add_entry_by_OBJ;
    {$ifend}
    {$if declared(X509_NAME_add_entry_by_OBJ_introduced)}
    if LibVersion < X509_NAME_add_entry_by_OBJ_introduced then
    begin
      {$if declared(FC_X509_NAME_add_entry_by_OBJ)}
      X509_NAME_add_entry_by_OBJ := FC_X509_NAME_add_entry_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_add_entry_by_OBJ_removed)}
    if X509_NAME_add_entry_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_add_entry_by_OBJ)}
      X509_NAME_add_entry_by_OBJ := _X509_NAME_add_entry_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_add_entry_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_add_entry_by_OBJ');
    {$ifend}
  end;
  
  X509_NAME_add_entry_by_NID := LoadLibFunction(ADllHandle, X509_NAME_add_entry_by_NID_procname);
  FuncLoadError := not assigned(X509_NAME_add_entry_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_add_entry_by_NID_allownil)}
    X509_NAME_add_entry_by_NID := ERR_X509_NAME_add_entry_by_NID;
    {$ifend}
    {$if declared(X509_NAME_add_entry_by_NID_introduced)}
    if LibVersion < X509_NAME_add_entry_by_NID_introduced then
    begin
      {$if declared(FC_X509_NAME_add_entry_by_NID)}
      X509_NAME_add_entry_by_NID := FC_X509_NAME_add_entry_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_add_entry_by_NID_removed)}
    if X509_NAME_add_entry_by_NID_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_add_entry_by_NID)}
      X509_NAME_add_entry_by_NID := _X509_NAME_add_entry_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_add_entry_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_add_entry_by_NID');
    {$ifend}
  end;
  
  X509_NAME_ENTRY_create_by_txt := LoadLibFunction(ADllHandle, X509_NAME_ENTRY_create_by_txt_procname);
  FuncLoadError := not assigned(X509_NAME_ENTRY_create_by_txt);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_ENTRY_create_by_txt_allownil)}
    X509_NAME_ENTRY_create_by_txt := ERR_X509_NAME_ENTRY_create_by_txt;
    {$ifend}
    {$if declared(X509_NAME_ENTRY_create_by_txt_introduced)}
    if LibVersion < X509_NAME_ENTRY_create_by_txt_introduced then
    begin
      {$if declared(FC_X509_NAME_ENTRY_create_by_txt)}
      X509_NAME_ENTRY_create_by_txt := FC_X509_NAME_ENTRY_create_by_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_ENTRY_create_by_txt_removed)}
    if X509_NAME_ENTRY_create_by_txt_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_ENTRY_create_by_txt)}
      X509_NAME_ENTRY_create_by_txt := _X509_NAME_ENTRY_create_by_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_ENTRY_create_by_txt_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_ENTRY_create_by_txt');
    {$ifend}
  end;
  
  X509_NAME_ENTRY_create_by_NID := LoadLibFunction(ADllHandle, X509_NAME_ENTRY_create_by_NID_procname);
  FuncLoadError := not assigned(X509_NAME_ENTRY_create_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_ENTRY_create_by_NID_allownil)}
    X509_NAME_ENTRY_create_by_NID := ERR_X509_NAME_ENTRY_create_by_NID;
    {$ifend}
    {$if declared(X509_NAME_ENTRY_create_by_NID_introduced)}
    if LibVersion < X509_NAME_ENTRY_create_by_NID_introduced then
    begin
      {$if declared(FC_X509_NAME_ENTRY_create_by_NID)}
      X509_NAME_ENTRY_create_by_NID := FC_X509_NAME_ENTRY_create_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_ENTRY_create_by_NID_removed)}
    if X509_NAME_ENTRY_create_by_NID_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_ENTRY_create_by_NID)}
      X509_NAME_ENTRY_create_by_NID := _X509_NAME_ENTRY_create_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_ENTRY_create_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_ENTRY_create_by_NID');
    {$ifend}
  end;
  
  X509_NAME_add_entry_by_txt := LoadLibFunction(ADllHandle, X509_NAME_add_entry_by_txt_procname);
  FuncLoadError := not assigned(X509_NAME_add_entry_by_txt);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_add_entry_by_txt_allownil)}
    X509_NAME_add_entry_by_txt := ERR_X509_NAME_add_entry_by_txt;
    {$ifend}
    {$if declared(X509_NAME_add_entry_by_txt_introduced)}
    if LibVersion < X509_NAME_add_entry_by_txt_introduced then
    begin
      {$if declared(FC_X509_NAME_add_entry_by_txt)}
      X509_NAME_add_entry_by_txt := FC_X509_NAME_add_entry_by_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_add_entry_by_txt_removed)}
    if X509_NAME_add_entry_by_txt_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_add_entry_by_txt)}
      X509_NAME_add_entry_by_txt := _X509_NAME_add_entry_by_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_add_entry_by_txt_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_add_entry_by_txt');
    {$ifend}
  end;
  
  X509_NAME_ENTRY_create_by_OBJ := LoadLibFunction(ADllHandle, X509_NAME_ENTRY_create_by_OBJ_procname);
  FuncLoadError := not assigned(X509_NAME_ENTRY_create_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_ENTRY_create_by_OBJ_allownil)}
    X509_NAME_ENTRY_create_by_OBJ := ERR_X509_NAME_ENTRY_create_by_OBJ;
    {$ifend}
    {$if declared(X509_NAME_ENTRY_create_by_OBJ_introduced)}
    if LibVersion < X509_NAME_ENTRY_create_by_OBJ_introduced then
    begin
      {$if declared(FC_X509_NAME_ENTRY_create_by_OBJ)}
      X509_NAME_ENTRY_create_by_OBJ := FC_X509_NAME_ENTRY_create_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_ENTRY_create_by_OBJ_removed)}
    if X509_NAME_ENTRY_create_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_ENTRY_create_by_OBJ)}
      X509_NAME_ENTRY_create_by_OBJ := _X509_NAME_ENTRY_create_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_ENTRY_create_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_ENTRY_create_by_OBJ');
    {$ifend}
  end;
  
  X509_NAME_ENTRY_set_object := LoadLibFunction(ADllHandle, X509_NAME_ENTRY_set_object_procname);
  FuncLoadError := not assigned(X509_NAME_ENTRY_set_object);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_ENTRY_set_object_allownil)}
    X509_NAME_ENTRY_set_object := ERR_X509_NAME_ENTRY_set_object;
    {$ifend}
    {$if declared(X509_NAME_ENTRY_set_object_introduced)}
    if LibVersion < X509_NAME_ENTRY_set_object_introduced then
    begin
      {$if declared(FC_X509_NAME_ENTRY_set_object)}
      X509_NAME_ENTRY_set_object := FC_X509_NAME_ENTRY_set_object;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_ENTRY_set_object_removed)}
    if X509_NAME_ENTRY_set_object_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_ENTRY_set_object)}
      X509_NAME_ENTRY_set_object := _X509_NAME_ENTRY_set_object;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_ENTRY_set_object_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_ENTRY_set_object');
    {$ifend}
  end;
  
  X509_NAME_ENTRY_set_data := LoadLibFunction(ADllHandle, X509_NAME_ENTRY_set_data_procname);
  FuncLoadError := not assigned(X509_NAME_ENTRY_set_data);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_ENTRY_set_data_allownil)}
    X509_NAME_ENTRY_set_data := ERR_X509_NAME_ENTRY_set_data;
    {$ifend}
    {$if declared(X509_NAME_ENTRY_set_data_introduced)}
    if LibVersion < X509_NAME_ENTRY_set_data_introduced then
    begin
      {$if declared(FC_X509_NAME_ENTRY_set_data)}
      X509_NAME_ENTRY_set_data := FC_X509_NAME_ENTRY_set_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_ENTRY_set_data_removed)}
    if X509_NAME_ENTRY_set_data_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_ENTRY_set_data)}
      X509_NAME_ENTRY_set_data := _X509_NAME_ENTRY_set_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_ENTRY_set_data_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_ENTRY_set_data');
    {$ifend}
  end;
  
  X509_NAME_ENTRY_get_object := LoadLibFunction(ADllHandle, X509_NAME_ENTRY_get_object_procname);
  FuncLoadError := not assigned(X509_NAME_ENTRY_get_object);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_ENTRY_get_object_allownil)}
    X509_NAME_ENTRY_get_object := ERR_X509_NAME_ENTRY_get_object;
    {$ifend}
    {$if declared(X509_NAME_ENTRY_get_object_introduced)}
    if LibVersion < X509_NAME_ENTRY_get_object_introduced then
    begin
      {$if declared(FC_X509_NAME_ENTRY_get_object)}
      X509_NAME_ENTRY_get_object := FC_X509_NAME_ENTRY_get_object;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_ENTRY_get_object_removed)}
    if X509_NAME_ENTRY_get_object_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_ENTRY_get_object)}
      X509_NAME_ENTRY_get_object := _X509_NAME_ENTRY_get_object;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_ENTRY_get_object_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_ENTRY_get_object');
    {$ifend}
  end;
  
  X509_NAME_ENTRY_get_data := LoadLibFunction(ADllHandle, X509_NAME_ENTRY_get_data_procname);
  FuncLoadError := not assigned(X509_NAME_ENTRY_get_data);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_ENTRY_get_data_allownil)}
    X509_NAME_ENTRY_get_data := ERR_X509_NAME_ENTRY_get_data;
    {$ifend}
    {$if declared(X509_NAME_ENTRY_get_data_introduced)}
    if LibVersion < X509_NAME_ENTRY_get_data_introduced then
    begin
      {$if declared(FC_X509_NAME_ENTRY_get_data)}
      X509_NAME_ENTRY_get_data := FC_X509_NAME_ENTRY_get_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_ENTRY_get_data_removed)}
    if X509_NAME_ENTRY_get_data_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_ENTRY_get_data)}
      X509_NAME_ENTRY_get_data := _X509_NAME_ENTRY_get_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_ENTRY_get_data_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_ENTRY_get_data');
    {$ifend}
  end;
  
  X509_NAME_ENTRY_set := LoadLibFunction(ADllHandle, X509_NAME_ENTRY_set_procname);
  FuncLoadError := not assigned(X509_NAME_ENTRY_set);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_ENTRY_set_allownil)}
    X509_NAME_ENTRY_set := ERR_X509_NAME_ENTRY_set;
    {$ifend}
    {$if declared(X509_NAME_ENTRY_set_introduced)}
    if LibVersion < X509_NAME_ENTRY_set_introduced then
    begin
      {$if declared(FC_X509_NAME_ENTRY_set)}
      X509_NAME_ENTRY_set := FC_X509_NAME_ENTRY_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_ENTRY_set_removed)}
    if X509_NAME_ENTRY_set_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_ENTRY_set)}
      X509_NAME_ENTRY_set := _X509_NAME_ENTRY_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_ENTRY_set_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_ENTRY_set');
    {$ifend}
  end;
  
  X509_NAME_get0_der := LoadLibFunction(ADllHandle, X509_NAME_get0_der_procname);
  FuncLoadError := not assigned(X509_NAME_get0_der);
  if FuncLoadError then
  begin
    {$if not defined(X509_NAME_get0_der_allownil)}
    X509_NAME_get0_der := ERR_X509_NAME_get0_der;
    {$ifend}
    {$if declared(X509_NAME_get0_der_introduced)}
    if LibVersion < X509_NAME_get0_der_introduced then
    begin
      {$if declared(FC_X509_NAME_get0_der)}
      X509_NAME_get0_der := FC_X509_NAME_get0_der;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_NAME_get0_der_removed)}
    if X509_NAME_get0_der_removed <= LibVersion then
    begin
      {$if declared(_X509_NAME_get0_der)}
      X509_NAME_get0_der := _X509_NAME_get0_der;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_NAME_get0_der_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_NAME_get0_der');
    {$ifend}
  end;
  
  X509v3_get_ext_count := LoadLibFunction(ADllHandle, X509v3_get_ext_count_procname);
  FuncLoadError := not assigned(X509v3_get_ext_count);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_get_ext_count_allownil)}
    X509v3_get_ext_count := ERR_X509v3_get_ext_count;
    {$ifend}
    {$if declared(X509v3_get_ext_count_introduced)}
    if LibVersion < X509v3_get_ext_count_introduced then
    begin
      {$if declared(FC_X509v3_get_ext_count)}
      X509v3_get_ext_count := FC_X509v3_get_ext_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_get_ext_count_removed)}
    if X509v3_get_ext_count_removed <= LibVersion then
    begin
      {$if declared(_X509v3_get_ext_count)}
      X509v3_get_ext_count := _X509v3_get_ext_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_get_ext_count_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_get_ext_count');
    {$ifend}
  end;
  
  X509v3_get_ext_by_NID := LoadLibFunction(ADllHandle, X509v3_get_ext_by_NID_procname);
  FuncLoadError := not assigned(X509v3_get_ext_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_get_ext_by_NID_allownil)}
    X509v3_get_ext_by_NID := ERR_X509v3_get_ext_by_NID;
    {$ifend}
    {$if declared(X509v3_get_ext_by_NID_introduced)}
    if LibVersion < X509v3_get_ext_by_NID_introduced then
    begin
      {$if declared(FC_X509v3_get_ext_by_NID)}
      X509v3_get_ext_by_NID := FC_X509v3_get_ext_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_get_ext_by_NID_removed)}
    if X509v3_get_ext_by_NID_removed <= LibVersion then
    begin
      {$if declared(_X509v3_get_ext_by_NID)}
      X509v3_get_ext_by_NID := _X509v3_get_ext_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_get_ext_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_get_ext_by_NID');
    {$ifend}
  end;
  
  X509v3_get_ext_by_OBJ := LoadLibFunction(ADllHandle, X509v3_get_ext_by_OBJ_procname);
  FuncLoadError := not assigned(X509v3_get_ext_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_get_ext_by_OBJ_allownil)}
    X509v3_get_ext_by_OBJ := ERR_X509v3_get_ext_by_OBJ;
    {$ifend}
    {$if declared(X509v3_get_ext_by_OBJ_introduced)}
    if LibVersion < X509v3_get_ext_by_OBJ_introduced then
    begin
      {$if declared(FC_X509v3_get_ext_by_OBJ)}
      X509v3_get_ext_by_OBJ := FC_X509v3_get_ext_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_get_ext_by_OBJ_removed)}
    if X509v3_get_ext_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_X509v3_get_ext_by_OBJ)}
      X509v3_get_ext_by_OBJ := _X509v3_get_ext_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_get_ext_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_get_ext_by_OBJ');
    {$ifend}
  end;
  
  X509v3_get_ext_by_critical := LoadLibFunction(ADllHandle, X509v3_get_ext_by_critical_procname);
  FuncLoadError := not assigned(X509v3_get_ext_by_critical);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_get_ext_by_critical_allownil)}
    X509v3_get_ext_by_critical := ERR_X509v3_get_ext_by_critical;
    {$ifend}
    {$if declared(X509v3_get_ext_by_critical_introduced)}
    if LibVersion < X509v3_get_ext_by_critical_introduced then
    begin
      {$if declared(FC_X509v3_get_ext_by_critical)}
      X509v3_get_ext_by_critical := FC_X509v3_get_ext_by_critical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_get_ext_by_critical_removed)}
    if X509v3_get_ext_by_critical_removed <= LibVersion then
    begin
      {$if declared(_X509v3_get_ext_by_critical)}
      X509v3_get_ext_by_critical := _X509v3_get_ext_by_critical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_get_ext_by_critical_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_get_ext_by_critical');
    {$ifend}
  end;
  
  X509v3_get_ext := LoadLibFunction(ADllHandle, X509v3_get_ext_procname);
  FuncLoadError := not assigned(X509v3_get_ext);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_get_ext_allownil)}
    X509v3_get_ext := ERR_X509v3_get_ext;
    {$ifend}
    {$if declared(X509v3_get_ext_introduced)}
    if LibVersion < X509v3_get_ext_introduced then
    begin
      {$if declared(FC_X509v3_get_ext)}
      X509v3_get_ext := FC_X509v3_get_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_get_ext_removed)}
    if X509v3_get_ext_removed <= LibVersion then
    begin
      {$if declared(_X509v3_get_ext)}
      X509v3_get_ext := _X509v3_get_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_get_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_get_ext');
    {$ifend}
  end;
  
  X509v3_delete_ext := LoadLibFunction(ADllHandle, X509v3_delete_ext_procname);
  FuncLoadError := not assigned(X509v3_delete_ext);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_delete_ext_allownil)}
    X509v3_delete_ext := ERR_X509v3_delete_ext;
    {$ifend}
    {$if declared(X509v3_delete_ext_introduced)}
    if LibVersion < X509v3_delete_ext_introduced then
    begin
      {$if declared(FC_X509v3_delete_ext)}
      X509v3_delete_ext := FC_X509v3_delete_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_delete_ext_removed)}
    if X509v3_delete_ext_removed <= LibVersion then
    begin
      {$if declared(_X509v3_delete_ext)}
      X509v3_delete_ext := _X509v3_delete_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_delete_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_delete_ext');
    {$ifend}
  end;
  
  X509v3_add_ext := LoadLibFunction(ADllHandle, X509v3_add_ext_procname);
  FuncLoadError := not assigned(X509v3_add_ext);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_add_ext_allownil)}
    X509v3_add_ext := ERR_X509v3_add_ext;
    {$ifend}
    {$if declared(X509v3_add_ext_introduced)}
    if LibVersion < X509v3_add_ext_introduced then
    begin
      {$if declared(FC_X509v3_add_ext)}
      X509v3_add_ext := FC_X509v3_add_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_add_ext_removed)}
    if X509v3_add_ext_removed <= LibVersion then
    begin
      {$if declared(_X509v3_add_ext)}
      X509v3_add_ext := _X509v3_add_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_add_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_add_ext');
    {$ifend}
  end;
  
  X509v3_add_extensions := LoadLibFunction(ADllHandle, X509v3_add_extensions_procname);
  FuncLoadError := not assigned(X509v3_add_extensions);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_add_extensions_allownil)}
    X509v3_add_extensions := ERR_X509v3_add_extensions;
    {$ifend}
    {$if declared(X509v3_add_extensions_introduced)}
    if LibVersion < X509v3_add_extensions_introduced then
    begin
      {$if declared(FC_X509v3_add_extensions)}
      X509v3_add_extensions := FC_X509v3_add_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_add_extensions_removed)}
    if X509v3_add_extensions_removed <= LibVersion then
    begin
      {$if declared(_X509v3_add_extensions)}
      X509v3_add_extensions := _X509v3_add_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_add_extensions_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_add_extensions');
    {$ifend}
  end;
  
  X509_get_ext_count := LoadLibFunction(ADllHandle, X509_get_ext_count_procname);
  FuncLoadError := not assigned(X509_get_ext_count);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_ext_count_allownil)}
    X509_get_ext_count := ERR_X509_get_ext_count;
    {$ifend}
    {$if declared(X509_get_ext_count_introduced)}
    if LibVersion < X509_get_ext_count_introduced then
    begin
      {$if declared(FC_X509_get_ext_count)}
      X509_get_ext_count := FC_X509_get_ext_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_ext_count_removed)}
    if X509_get_ext_count_removed <= LibVersion then
    begin
      {$if declared(_X509_get_ext_count)}
      X509_get_ext_count := _X509_get_ext_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_ext_count_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_ext_count');
    {$ifend}
  end;
  
  X509_get_ext_by_NID := LoadLibFunction(ADllHandle, X509_get_ext_by_NID_procname);
  FuncLoadError := not assigned(X509_get_ext_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_ext_by_NID_allownil)}
    X509_get_ext_by_NID := ERR_X509_get_ext_by_NID;
    {$ifend}
    {$if declared(X509_get_ext_by_NID_introduced)}
    if LibVersion < X509_get_ext_by_NID_introduced then
    begin
      {$if declared(FC_X509_get_ext_by_NID)}
      X509_get_ext_by_NID := FC_X509_get_ext_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_ext_by_NID_removed)}
    if X509_get_ext_by_NID_removed <= LibVersion then
    begin
      {$if declared(_X509_get_ext_by_NID)}
      X509_get_ext_by_NID := _X509_get_ext_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_ext_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_ext_by_NID');
    {$ifend}
  end;
  
  X509_get_ext_by_OBJ := LoadLibFunction(ADllHandle, X509_get_ext_by_OBJ_procname);
  FuncLoadError := not assigned(X509_get_ext_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_ext_by_OBJ_allownil)}
    X509_get_ext_by_OBJ := ERR_X509_get_ext_by_OBJ;
    {$ifend}
    {$if declared(X509_get_ext_by_OBJ_introduced)}
    if LibVersion < X509_get_ext_by_OBJ_introduced then
    begin
      {$if declared(FC_X509_get_ext_by_OBJ)}
      X509_get_ext_by_OBJ := FC_X509_get_ext_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_ext_by_OBJ_removed)}
    if X509_get_ext_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_X509_get_ext_by_OBJ)}
      X509_get_ext_by_OBJ := _X509_get_ext_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_ext_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_ext_by_OBJ');
    {$ifend}
  end;
  
  X509_get_ext_by_critical := LoadLibFunction(ADllHandle, X509_get_ext_by_critical_procname);
  FuncLoadError := not assigned(X509_get_ext_by_critical);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_ext_by_critical_allownil)}
    X509_get_ext_by_critical := ERR_X509_get_ext_by_critical;
    {$ifend}
    {$if declared(X509_get_ext_by_critical_introduced)}
    if LibVersion < X509_get_ext_by_critical_introduced then
    begin
      {$if declared(FC_X509_get_ext_by_critical)}
      X509_get_ext_by_critical := FC_X509_get_ext_by_critical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_ext_by_critical_removed)}
    if X509_get_ext_by_critical_removed <= LibVersion then
    begin
      {$if declared(_X509_get_ext_by_critical)}
      X509_get_ext_by_critical := _X509_get_ext_by_critical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_ext_by_critical_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_ext_by_critical');
    {$ifend}
  end;
  
  X509_get_ext := LoadLibFunction(ADllHandle, X509_get_ext_procname);
  FuncLoadError := not assigned(X509_get_ext);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_ext_allownil)}
    X509_get_ext := ERR_X509_get_ext;
    {$ifend}
    {$if declared(X509_get_ext_introduced)}
    if LibVersion < X509_get_ext_introduced then
    begin
      {$if declared(FC_X509_get_ext)}
      X509_get_ext := FC_X509_get_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_ext_removed)}
    if X509_get_ext_removed <= LibVersion then
    begin
      {$if declared(_X509_get_ext)}
      X509_get_ext := _X509_get_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_ext');
    {$ifend}
  end;
  
  X509_delete_ext := LoadLibFunction(ADllHandle, X509_delete_ext_procname);
  FuncLoadError := not assigned(X509_delete_ext);
  if FuncLoadError then
  begin
    {$if not defined(X509_delete_ext_allownil)}
    X509_delete_ext := ERR_X509_delete_ext;
    {$ifend}
    {$if declared(X509_delete_ext_introduced)}
    if LibVersion < X509_delete_ext_introduced then
    begin
      {$if declared(FC_X509_delete_ext)}
      X509_delete_ext := FC_X509_delete_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_delete_ext_removed)}
    if X509_delete_ext_removed <= LibVersion then
    begin
      {$if declared(_X509_delete_ext)}
      X509_delete_ext := _X509_delete_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_delete_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_delete_ext');
    {$ifend}
  end;
  
  X509_add_ext := LoadLibFunction(ADllHandle, X509_add_ext_procname);
  FuncLoadError := not assigned(X509_add_ext);
  if FuncLoadError then
  begin
    {$if not defined(X509_add_ext_allownil)}
    X509_add_ext := ERR_X509_add_ext;
    {$ifend}
    {$if declared(X509_add_ext_introduced)}
    if LibVersion < X509_add_ext_introduced then
    begin
      {$if declared(FC_X509_add_ext)}
      X509_add_ext := FC_X509_add_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_add_ext_removed)}
    if X509_add_ext_removed <= LibVersion then
    begin
      {$if declared(_X509_add_ext)}
      X509_add_ext := _X509_add_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_add_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_add_ext');
    {$ifend}
  end;
  
  X509_get_ext_d2i := LoadLibFunction(ADllHandle, X509_get_ext_d2i_procname);
  FuncLoadError := not assigned(X509_get_ext_d2i);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_ext_d2i_allownil)}
    X509_get_ext_d2i := ERR_X509_get_ext_d2i;
    {$ifend}
    {$if declared(X509_get_ext_d2i_introduced)}
    if LibVersion < X509_get_ext_d2i_introduced then
    begin
      {$if declared(FC_X509_get_ext_d2i)}
      X509_get_ext_d2i := FC_X509_get_ext_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_ext_d2i_removed)}
    if X509_get_ext_d2i_removed <= LibVersion then
    begin
      {$if declared(_X509_get_ext_d2i)}
      X509_get_ext_d2i := _X509_get_ext_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_ext_d2i_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_ext_d2i');
    {$ifend}
  end;
  
  X509_add1_ext_i2d := LoadLibFunction(ADllHandle, X509_add1_ext_i2d_procname);
  FuncLoadError := not assigned(X509_add1_ext_i2d);
  if FuncLoadError then
  begin
    {$if not defined(X509_add1_ext_i2d_allownil)}
    X509_add1_ext_i2d := ERR_X509_add1_ext_i2d;
    {$ifend}
    {$if declared(X509_add1_ext_i2d_introduced)}
    if LibVersion < X509_add1_ext_i2d_introduced then
    begin
      {$if declared(FC_X509_add1_ext_i2d)}
      X509_add1_ext_i2d := FC_X509_add1_ext_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_add1_ext_i2d_removed)}
    if X509_add1_ext_i2d_removed <= LibVersion then
    begin
      {$if declared(_X509_add1_ext_i2d)}
      X509_add1_ext_i2d := _X509_add1_ext_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_add1_ext_i2d_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_add1_ext_i2d');
    {$ifend}
  end;
  
  X509_CRL_get_ext_count := LoadLibFunction(ADllHandle, X509_CRL_get_ext_count_procname);
  FuncLoadError := not assigned(X509_CRL_get_ext_count);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_get_ext_count_allownil)}
    X509_CRL_get_ext_count := ERR_X509_CRL_get_ext_count;
    {$ifend}
    {$if declared(X509_CRL_get_ext_count_introduced)}
    if LibVersion < X509_CRL_get_ext_count_introduced then
    begin
      {$if declared(FC_X509_CRL_get_ext_count)}
      X509_CRL_get_ext_count := FC_X509_CRL_get_ext_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_get_ext_count_removed)}
    if X509_CRL_get_ext_count_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_get_ext_count)}
      X509_CRL_get_ext_count := _X509_CRL_get_ext_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_get_ext_count_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_get_ext_count');
    {$ifend}
  end;
  
  X509_CRL_get_ext_by_NID := LoadLibFunction(ADllHandle, X509_CRL_get_ext_by_NID_procname);
  FuncLoadError := not assigned(X509_CRL_get_ext_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_get_ext_by_NID_allownil)}
    X509_CRL_get_ext_by_NID := ERR_X509_CRL_get_ext_by_NID;
    {$ifend}
    {$if declared(X509_CRL_get_ext_by_NID_introduced)}
    if LibVersion < X509_CRL_get_ext_by_NID_introduced then
    begin
      {$if declared(FC_X509_CRL_get_ext_by_NID)}
      X509_CRL_get_ext_by_NID := FC_X509_CRL_get_ext_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_get_ext_by_NID_removed)}
    if X509_CRL_get_ext_by_NID_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_get_ext_by_NID)}
      X509_CRL_get_ext_by_NID := _X509_CRL_get_ext_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_get_ext_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_get_ext_by_NID');
    {$ifend}
  end;
  
  X509_CRL_get_ext_by_OBJ := LoadLibFunction(ADllHandle, X509_CRL_get_ext_by_OBJ_procname);
  FuncLoadError := not assigned(X509_CRL_get_ext_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_get_ext_by_OBJ_allownil)}
    X509_CRL_get_ext_by_OBJ := ERR_X509_CRL_get_ext_by_OBJ;
    {$ifend}
    {$if declared(X509_CRL_get_ext_by_OBJ_introduced)}
    if LibVersion < X509_CRL_get_ext_by_OBJ_introduced then
    begin
      {$if declared(FC_X509_CRL_get_ext_by_OBJ)}
      X509_CRL_get_ext_by_OBJ := FC_X509_CRL_get_ext_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_get_ext_by_OBJ_removed)}
    if X509_CRL_get_ext_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_get_ext_by_OBJ)}
      X509_CRL_get_ext_by_OBJ := _X509_CRL_get_ext_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_get_ext_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_get_ext_by_OBJ');
    {$ifend}
  end;
  
  X509_CRL_get_ext_by_critical := LoadLibFunction(ADllHandle, X509_CRL_get_ext_by_critical_procname);
  FuncLoadError := not assigned(X509_CRL_get_ext_by_critical);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_get_ext_by_critical_allownil)}
    X509_CRL_get_ext_by_critical := ERR_X509_CRL_get_ext_by_critical;
    {$ifend}
    {$if declared(X509_CRL_get_ext_by_critical_introduced)}
    if LibVersion < X509_CRL_get_ext_by_critical_introduced then
    begin
      {$if declared(FC_X509_CRL_get_ext_by_critical)}
      X509_CRL_get_ext_by_critical := FC_X509_CRL_get_ext_by_critical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_get_ext_by_critical_removed)}
    if X509_CRL_get_ext_by_critical_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_get_ext_by_critical)}
      X509_CRL_get_ext_by_critical := _X509_CRL_get_ext_by_critical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_get_ext_by_critical_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_get_ext_by_critical');
    {$ifend}
  end;
  
  X509_CRL_get_ext := LoadLibFunction(ADllHandle, X509_CRL_get_ext_procname);
  FuncLoadError := not assigned(X509_CRL_get_ext);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_get_ext_allownil)}
    X509_CRL_get_ext := ERR_X509_CRL_get_ext;
    {$ifend}
    {$if declared(X509_CRL_get_ext_introduced)}
    if LibVersion < X509_CRL_get_ext_introduced then
    begin
      {$if declared(FC_X509_CRL_get_ext)}
      X509_CRL_get_ext := FC_X509_CRL_get_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_get_ext_removed)}
    if X509_CRL_get_ext_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_get_ext)}
      X509_CRL_get_ext := _X509_CRL_get_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_get_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_get_ext');
    {$ifend}
  end;
  
  X509_CRL_delete_ext := LoadLibFunction(ADllHandle, X509_CRL_delete_ext_procname);
  FuncLoadError := not assigned(X509_CRL_delete_ext);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_delete_ext_allownil)}
    X509_CRL_delete_ext := ERR_X509_CRL_delete_ext;
    {$ifend}
    {$if declared(X509_CRL_delete_ext_introduced)}
    if LibVersion < X509_CRL_delete_ext_introduced then
    begin
      {$if declared(FC_X509_CRL_delete_ext)}
      X509_CRL_delete_ext := FC_X509_CRL_delete_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_delete_ext_removed)}
    if X509_CRL_delete_ext_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_delete_ext)}
      X509_CRL_delete_ext := _X509_CRL_delete_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_delete_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_delete_ext');
    {$ifend}
  end;
  
  X509_CRL_add_ext := LoadLibFunction(ADllHandle, X509_CRL_add_ext_procname);
  FuncLoadError := not assigned(X509_CRL_add_ext);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_add_ext_allownil)}
    X509_CRL_add_ext := ERR_X509_CRL_add_ext;
    {$ifend}
    {$if declared(X509_CRL_add_ext_introduced)}
    if LibVersion < X509_CRL_add_ext_introduced then
    begin
      {$if declared(FC_X509_CRL_add_ext)}
      X509_CRL_add_ext := FC_X509_CRL_add_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_add_ext_removed)}
    if X509_CRL_add_ext_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_add_ext)}
      X509_CRL_add_ext := _X509_CRL_add_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_add_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_add_ext');
    {$ifend}
  end;
  
  X509_CRL_get_ext_d2i := LoadLibFunction(ADllHandle, X509_CRL_get_ext_d2i_procname);
  FuncLoadError := not assigned(X509_CRL_get_ext_d2i);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_get_ext_d2i_allownil)}
    X509_CRL_get_ext_d2i := ERR_X509_CRL_get_ext_d2i;
    {$ifend}
    {$if declared(X509_CRL_get_ext_d2i_introduced)}
    if LibVersion < X509_CRL_get_ext_d2i_introduced then
    begin
      {$if declared(FC_X509_CRL_get_ext_d2i)}
      X509_CRL_get_ext_d2i := FC_X509_CRL_get_ext_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_get_ext_d2i_removed)}
    if X509_CRL_get_ext_d2i_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_get_ext_d2i)}
      X509_CRL_get_ext_d2i := _X509_CRL_get_ext_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_get_ext_d2i_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_get_ext_d2i');
    {$ifend}
  end;
  
  X509_CRL_add1_ext_i2d := LoadLibFunction(ADllHandle, X509_CRL_add1_ext_i2d_procname);
  FuncLoadError := not assigned(X509_CRL_add1_ext_i2d);
  if FuncLoadError then
  begin
    {$if not defined(X509_CRL_add1_ext_i2d_allownil)}
    X509_CRL_add1_ext_i2d := ERR_X509_CRL_add1_ext_i2d;
    {$ifend}
    {$if declared(X509_CRL_add1_ext_i2d_introduced)}
    if LibVersion < X509_CRL_add1_ext_i2d_introduced then
    begin
      {$if declared(FC_X509_CRL_add1_ext_i2d)}
      X509_CRL_add1_ext_i2d := FC_X509_CRL_add1_ext_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_CRL_add1_ext_i2d_removed)}
    if X509_CRL_add1_ext_i2d_removed <= LibVersion then
    begin
      {$if declared(_X509_CRL_add1_ext_i2d)}
      X509_CRL_add1_ext_i2d := _X509_CRL_add1_ext_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_CRL_add1_ext_i2d_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_CRL_add1_ext_i2d');
    {$ifend}
  end;
  
  X509_REVOKED_get_ext_count := LoadLibFunction(ADllHandle, X509_REVOKED_get_ext_count_procname);
  FuncLoadError := not assigned(X509_REVOKED_get_ext_count);
  if FuncLoadError then
  begin
    {$if not defined(X509_REVOKED_get_ext_count_allownil)}
    X509_REVOKED_get_ext_count := ERR_X509_REVOKED_get_ext_count;
    {$ifend}
    {$if declared(X509_REVOKED_get_ext_count_introduced)}
    if LibVersion < X509_REVOKED_get_ext_count_introduced then
    begin
      {$if declared(FC_X509_REVOKED_get_ext_count)}
      X509_REVOKED_get_ext_count := FC_X509_REVOKED_get_ext_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REVOKED_get_ext_count_removed)}
    if X509_REVOKED_get_ext_count_removed <= LibVersion then
    begin
      {$if declared(_X509_REVOKED_get_ext_count)}
      X509_REVOKED_get_ext_count := _X509_REVOKED_get_ext_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REVOKED_get_ext_count_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REVOKED_get_ext_count');
    {$ifend}
  end;
  
  X509_REVOKED_get_ext_by_NID := LoadLibFunction(ADllHandle, X509_REVOKED_get_ext_by_NID_procname);
  FuncLoadError := not assigned(X509_REVOKED_get_ext_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(X509_REVOKED_get_ext_by_NID_allownil)}
    X509_REVOKED_get_ext_by_NID := ERR_X509_REVOKED_get_ext_by_NID;
    {$ifend}
    {$if declared(X509_REVOKED_get_ext_by_NID_introduced)}
    if LibVersion < X509_REVOKED_get_ext_by_NID_introduced then
    begin
      {$if declared(FC_X509_REVOKED_get_ext_by_NID)}
      X509_REVOKED_get_ext_by_NID := FC_X509_REVOKED_get_ext_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REVOKED_get_ext_by_NID_removed)}
    if X509_REVOKED_get_ext_by_NID_removed <= LibVersion then
    begin
      {$if declared(_X509_REVOKED_get_ext_by_NID)}
      X509_REVOKED_get_ext_by_NID := _X509_REVOKED_get_ext_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REVOKED_get_ext_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REVOKED_get_ext_by_NID');
    {$ifend}
  end;
  
  X509_REVOKED_get_ext_by_OBJ := LoadLibFunction(ADllHandle, X509_REVOKED_get_ext_by_OBJ_procname);
  FuncLoadError := not assigned(X509_REVOKED_get_ext_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(X509_REVOKED_get_ext_by_OBJ_allownil)}
    X509_REVOKED_get_ext_by_OBJ := ERR_X509_REVOKED_get_ext_by_OBJ;
    {$ifend}
    {$if declared(X509_REVOKED_get_ext_by_OBJ_introduced)}
    if LibVersion < X509_REVOKED_get_ext_by_OBJ_introduced then
    begin
      {$if declared(FC_X509_REVOKED_get_ext_by_OBJ)}
      X509_REVOKED_get_ext_by_OBJ := FC_X509_REVOKED_get_ext_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REVOKED_get_ext_by_OBJ_removed)}
    if X509_REVOKED_get_ext_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_X509_REVOKED_get_ext_by_OBJ)}
      X509_REVOKED_get_ext_by_OBJ := _X509_REVOKED_get_ext_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REVOKED_get_ext_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REVOKED_get_ext_by_OBJ');
    {$ifend}
  end;
  
  X509_REVOKED_get_ext_by_critical := LoadLibFunction(ADllHandle, X509_REVOKED_get_ext_by_critical_procname);
  FuncLoadError := not assigned(X509_REVOKED_get_ext_by_critical);
  if FuncLoadError then
  begin
    {$if not defined(X509_REVOKED_get_ext_by_critical_allownil)}
    X509_REVOKED_get_ext_by_critical := ERR_X509_REVOKED_get_ext_by_critical;
    {$ifend}
    {$if declared(X509_REVOKED_get_ext_by_critical_introduced)}
    if LibVersion < X509_REVOKED_get_ext_by_critical_introduced then
    begin
      {$if declared(FC_X509_REVOKED_get_ext_by_critical)}
      X509_REVOKED_get_ext_by_critical := FC_X509_REVOKED_get_ext_by_critical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REVOKED_get_ext_by_critical_removed)}
    if X509_REVOKED_get_ext_by_critical_removed <= LibVersion then
    begin
      {$if declared(_X509_REVOKED_get_ext_by_critical)}
      X509_REVOKED_get_ext_by_critical := _X509_REVOKED_get_ext_by_critical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REVOKED_get_ext_by_critical_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REVOKED_get_ext_by_critical');
    {$ifend}
  end;
  
  X509_REVOKED_get_ext := LoadLibFunction(ADllHandle, X509_REVOKED_get_ext_procname);
  FuncLoadError := not assigned(X509_REVOKED_get_ext);
  if FuncLoadError then
  begin
    {$if not defined(X509_REVOKED_get_ext_allownil)}
    X509_REVOKED_get_ext := ERR_X509_REVOKED_get_ext;
    {$ifend}
    {$if declared(X509_REVOKED_get_ext_introduced)}
    if LibVersion < X509_REVOKED_get_ext_introduced then
    begin
      {$if declared(FC_X509_REVOKED_get_ext)}
      X509_REVOKED_get_ext := FC_X509_REVOKED_get_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REVOKED_get_ext_removed)}
    if X509_REVOKED_get_ext_removed <= LibVersion then
    begin
      {$if declared(_X509_REVOKED_get_ext)}
      X509_REVOKED_get_ext := _X509_REVOKED_get_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REVOKED_get_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REVOKED_get_ext');
    {$ifend}
  end;
  
  X509_REVOKED_delete_ext := LoadLibFunction(ADllHandle, X509_REVOKED_delete_ext_procname);
  FuncLoadError := not assigned(X509_REVOKED_delete_ext);
  if FuncLoadError then
  begin
    {$if not defined(X509_REVOKED_delete_ext_allownil)}
    X509_REVOKED_delete_ext := ERR_X509_REVOKED_delete_ext;
    {$ifend}
    {$if declared(X509_REVOKED_delete_ext_introduced)}
    if LibVersion < X509_REVOKED_delete_ext_introduced then
    begin
      {$if declared(FC_X509_REVOKED_delete_ext)}
      X509_REVOKED_delete_ext := FC_X509_REVOKED_delete_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REVOKED_delete_ext_removed)}
    if X509_REVOKED_delete_ext_removed <= LibVersion then
    begin
      {$if declared(_X509_REVOKED_delete_ext)}
      X509_REVOKED_delete_ext := _X509_REVOKED_delete_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REVOKED_delete_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REVOKED_delete_ext');
    {$ifend}
  end;
  
  X509_REVOKED_add_ext := LoadLibFunction(ADllHandle, X509_REVOKED_add_ext_procname);
  FuncLoadError := not assigned(X509_REVOKED_add_ext);
  if FuncLoadError then
  begin
    {$if not defined(X509_REVOKED_add_ext_allownil)}
    X509_REVOKED_add_ext := ERR_X509_REVOKED_add_ext;
    {$ifend}
    {$if declared(X509_REVOKED_add_ext_introduced)}
    if LibVersion < X509_REVOKED_add_ext_introduced then
    begin
      {$if declared(FC_X509_REVOKED_add_ext)}
      X509_REVOKED_add_ext := FC_X509_REVOKED_add_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REVOKED_add_ext_removed)}
    if X509_REVOKED_add_ext_removed <= LibVersion then
    begin
      {$if declared(_X509_REVOKED_add_ext)}
      X509_REVOKED_add_ext := _X509_REVOKED_add_ext;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REVOKED_add_ext_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REVOKED_add_ext');
    {$ifend}
  end;
  
  X509_REVOKED_get_ext_d2i := LoadLibFunction(ADllHandle, X509_REVOKED_get_ext_d2i_procname);
  FuncLoadError := not assigned(X509_REVOKED_get_ext_d2i);
  if FuncLoadError then
  begin
    {$if not defined(X509_REVOKED_get_ext_d2i_allownil)}
    X509_REVOKED_get_ext_d2i := ERR_X509_REVOKED_get_ext_d2i;
    {$ifend}
    {$if declared(X509_REVOKED_get_ext_d2i_introduced)}
    if LibVersion < X509_REVOKED_get_ext_d2i_introduced then
    begin
      {$if declared(FC_X509_REVOKED_get_ext_d2i)}
      X509_REVOKED_get_ext_d2i := FC_X509_REVOKED_get_ext_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REVOKED_get_ext_d2i_removed)}
    if X509_REVOKED_get_ext_d2i_removed <= LibVersion then
    begin
      {$if declared(_X509_REVOKED_get_ext_d2i)}
      X509_REVOKED_get_ext_d2i := _X509_REVOKED_get_ext_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REVOKED_get_ext_d2i_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REVOKED_get_ext_d2i');
    {$ifend}
  end;
  
  X509_REVOKED_add1_ext_i2d := LoadLibFunction(ADllHandle, X509_REVOKED_add1_ext_i2d_procname);
  FuncLoadError := not assigned(X509_REVOKED_add1_ext_i2d);
  if FuncLoadError then
  begin
    {$if not defined(X509_REVOKED_add1_ext_i2d_allownil)}
    X509_REVOKED_add1_ext_i2d := ERR_X509_REVOKED_add1_ext_i2d;
    {$ifend}
    {$if declared(X509_REVOKED_add1_ext_i2d_introduced)}
    if LibVersion < X509_REVOKED_add1_ext_i2d_introduced then
    begin
      {$if declared(FC_X509_REVOKED_add1_ext_i2d)}
      X509_REVOKED_add1_ext_i2d := FC_X509_REVOKED_add1_ext_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REVOKED_add1_ext_i2d_removed)}
    if X509_REVOKED_add1_ext_i2d_removed <= LibVersion then
    begin
      {$if declared(_X509_REVOKED_add1_ext_i2d)}
      X509_REVOKED_add1_ext_i2d := _X509_REVOKED_add1_ext_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REVOKED_add1_ext_i2d_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REVOKED_add1_ext_i2d');
    {$ifend}
  end;
  
  X509_EXTENSION_create_by_NID := LoadLibFunction(ADllHandle, X509_EXTENSION_create_by_NID_procname);
  FuncLoadError := not assigned(X509_EXTENSION_create_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(X509_EXTENSION_create_by_NID_allownil)}
    X509_EXTENSION_create_by_NID := ERR_X509_EXTENSION_create_by_NID;
    {$ifend}
    {$if declared(X509_EXTENSION_create_by_NID_introduced)}
    if LibVersion < X509_EXTENSION_create_by_NID_introduced then
    begin
      {$if declared(FC_X509_EXTENSION_create_by_NID)}
      X509_EXTENSION_create_by_NID := FC_X509_EXTENSION_create_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_EXTENSION_create_by_NID_removed)}
    if X509_EXTENSION_create_by_NID_removed <= LibVersion then
    begin
      {$if declared(_X509_EXTENSION_create_by_NID)}
      X509_EXTENSION_create_by_NID := _X509_EXTENSION_create_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_EXTENSION_create_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_EXTENSION_create_by_NID');
    {$ifend}
  end;
  
  X509_EXTENSION_create_by_OBJ := LoadLibFunction(ADllHandle, X509_EXTENSION_create_by_OBJ_procname);
  FuncLoadError := not assigned(X509_EXTENSION_create_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(X509_EXTENSION_create_by_OBJ_allownil)}
    X509_EXTENSION_create_by_OBJ := ERR_X509_EXTENSION_create_by_OBJ;
    {$ifend}
    {$if declared(X509_EXTENSION_create_by_OBJ_introduced)}
    if LibVersion < X509_EXTENSION_create_by_OBJ_introduced then
    begin
      {$if declared(FC_X509_EXTENSION_create_by_OBJ)}
      X509_EXTENSION_create_by_OBJ := FC_X509_EXTENSION_create_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_EXTENSION_create_by_OBJ_removed)}
    if X509_EXTENSION_create_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_X509_EXTENSION_create_by_OBJ)}
      X509_EXTENSION_create_by_OBJ := _X509_EXTENSION_create_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_EXTENSION_create_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_EXTENSION_create_by_OBJ');
    {$ifend}
  end;
  
  X509_EXTENSION_set_object := LoadLibFunction(ADllHandle, X509_EXTENSION_set_object_procname);
  FuncLoadError := not assigned(X509_EXTENSION_set_object);
  if FuncLoadError then
  begin
    {$if not defined(X509_EXTENSION_set_object_allownil)}
    X509_EXTENSION_set_object := ERR_X509_EXTENSION_set_object;
    {$ifend}
    {$if declared(X509_EXTENSION_set_object_introduced)}
    if LibVersion < X509_EXTENSION_set_object_introduced then
    begin
      {$if declared(FC_X509_EXTENSION_set_object)}
      X509_EXTENSION_set_object := FC_X509_EXTENSION_set_object;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_EXTENSION_set_object_removed)}
    if X509_EXTENSION_set_object_removed <= LibVersion then
    begin
      {$if declared(_X509_EXTENSION_set_object)}
      X509_EXTENSION_set_object := _X509_EXTENSION_set_object;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_EXTENSION_set_object_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_EXTENSION_set_object');
    {$ifend}
  end;
  
  X509_EXTENSION_set_critical := LoadLibFunction(ADllHandle, X509_EXTENSION_set_critical_procname);
  FuncLoadError := not assigned(X509_EXTENSION_set_critical);
  if FuncLoadError then
  begin
    {$if not defined(X509_EXTENSION_set_critical_allownil)}
    X509_EXTENSION_set_critical := ERR_X509_EXTENSION_set_critical;
    {$ifend}
    {$if declared(X509_EXTENSION_set_critical_introduced)}
    if LibVersion < X509_EXTENSION_set_critical_introduced then
    begin
      {$if declared(FC_X509_EXTENSION_set_critical)}
      X509_EXTENSION_set_critical := FC_X509_EXTENSION_set_critical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_EXTENSION_set_critical_removed)}
    if X509_EXTENSION_set_critical_removed <= LibVersion then
    begin
      {$if declared(_X509_EXTENSION_set_critical)}
      X509_EXTENSION_set_critical := _X509_EXTENSION_set_critical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_EXTENSION_set_critical_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_EXTENSION_set_critical');
    {$ifend}
  end;
  
  X509_EXTENSION_set_data := LoadLibFunction(ADllHandle, X509_EXTENSION_set_data_procname);
  FuncLoadError := not assigned(X509_EXTENSION_set_data);
  if FuncLoadError then
  begin
    {$if not defined(X509_EXTENSION_set_data_allownil)}
    X509_EXTENSION_set_data := ERR_X509_EXTENSION_set_data;
    {$ifend}
    {$if declared(X509_EXTENSION_set_data_introduced)}
    if LibVersion < X509_EXTENSION_set_data_introduced then
    begin
      {$if declared(FC_X509_EXTENSION_set_data)}
      X509_EXTENSION_set_data := FC_X509_EXTENSION_set_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_EXTENSION_set_data_removed)}
    if X509_EXTENSION_set_data_removed <= LibVersion then
    begin
      {$if declared(_X509_EXTENSION_set_data)}
      X509_EXTENSION_set_data := _X509_EXTENSION_set_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_EXTENSION_set_data_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_EXTENSION_set_data');
    {$ifend}
  end;
  
  X509_EXTENSION_get_object := LoadLibFunction(ADllHandle, X509_EXTENSION_get_object_procname);
  FuncLoadError := not assigned(X509_EXTENSION_get_object);
  if FuncLoadError then
  begin
    {$if not defined(X509_EXTENSION_get_object_allownil)}
    X509_EXTENSION_get_object := ERR_X509_EXTENSION_get_object;
    {$ifend}
    {$if declared(X509_EXTENSION_get_object_introduced)}
    if LibVersion < X509_EXTENSION_get_object_introduced then
    begin
      {$if declared(FC_X509_EXTENSION_get_object)}
      X509_EXTENSION_get_object := FC_X509_EXTENSION_get_object;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_EXTENSION_get_object_removed)}
    if X509_EXTENSION_get_object_removed <= LibVersion then
    begin
      {$if declared(_X509_EXTENSION_get_object)}
      X509_EXTENSION_get_object := _X509_EXTENSION_get_object;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_EXTENSION_get_object_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_EXTENSION_get_object');
    {$ifend}
  end;
  
  X509_EXTENSION_get_data := LoadLibFunction(ADllHandle, X509_EXTENSION_get_data_procname);
  FuncLoadError := not assigned(X509_EXTENSION_get_data);
  if FuncLoadError then
  begin
    {$if not defined(X509_EXTENSION_get_data_allownil)}
    X509_EXTENSION_get_data := ERR_X509_EXTENSION_get_data;
    {$ifend}
    {$if declared(X509_EXTENSION_get_data_introduced)}
    if LibVersion < X509_EXTENSION_get_data_introduced then
    begin
      {$if declared(FC_X509_EXTENSION_get_data)}
      X509_EXTENSION_get_data := FC_X509_EXTENSION_get_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_EXTENSION_get_data_removed)}
    if X509_EXTENSION_get_data_removed <= LibVersion then
    begin
      {$if declared(_X509_EXTENSION_get_data)}
      X509_EXTENSION_get_data := _X509_EXTENSION_get_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_EXTENSION_get_data_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_EXTENSION_get_data');
    {$ifend}
  end;
  
  X509_EXTENSION_get_critical := LoadLibFunction(ADllHandle, X509_EXTENSION_get_critical_procname);
  FuncLoadError := not assigned(X509_EXTENSION_get_critical);
  if FuncLoadError then
  begin
    {$if not defined(X509_EXTENSION_get_critical_allownil)}
    X509_EXTENSION_get_critical := ERR_X509_EXTENSION_get_critical;
    {$ifend}
    {$if declared(X509_EXTENSION_get_critical_introduced)}
    if LibVersion < X509_EXTENSION_get_critical_introduced then
    begin
      {$if declared(FC_X509_EXTENSION_get_critical)}
      X509_EXTENSION_get_critical := FC_X509_EXTENSION_get_critical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_EXTENSION_get_critical_removed)}
    if X509_EXTENSION_get_critical_removed <= LibVersion then
    begin
      {$if declared(_X509_EXTENSION_get_critical)}
      X509_EXTENSION_get_critical := _X509_EXTENSION_get_critical;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_EXTENSION_get_critical_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_EXTENSION_get_critical');
    {$ifend}
  end;
  
  X509at_get_attr_count := LoadLibFunction(ADllHandle, X509at_get_attr_count_procname);
  FuncLoadError := not assigned(X509at_get_attr_count);
  if FuncLoadError then
  begin
    {$if not defined(X509at_get_attr_count_allownil)}
    X509at_get_attr_count := ERR_X509at_get_attr_count;
    {$ifend}
    {$if declared(X509at_get_attr_count_introduced)}
    if LibVersion < X509at_get_attr_count_introduced then
    begin
      {$if declared(FC_X509at_get_attr_count)}
      X509at_get_attr_count := FC_X509at_get_attr_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509at_get_attr_count_removed)}
    if X509at_get_attr_count_removed <= LibVersion then
    begin
      {$if declared(_X509at_get_attr_count)}
      X509at_get_attr_count := _X509at_get_attr_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509at_get_attr_count_allownil)}
    if FuncLoadError then
      AFailed.Add('X509at_get_attr_count');
    {$ifend}
  end;
  
  X509at_get_attr_by_NID := LoadLibFunction(ADllHandle, X509at_get_attr_by_NID_procname);
  FuncLoadError := not assigned(X509at_get_attr_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(X509at_get_attr_by_NID_allownil)}
    X509at_get_attr_by_NID := ERR_X509at_get_attr_by_NID;
    {$ifend}
    {$if declared(X509at_get_attr_by_NID_introduced)}
    if LibVersion < X509at_get_attr_by_NID_introduced then
    begin
      {$if declared(FC_X509at_get_attr_by_NID)}
      X509at_get_attr_by_NID := FC_X509at_get_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509at_get_attr_by_NID_removed)}
    if X509at_get_attr_by_NID_removed <= LibVersion then
    begin
      {$if declared(_X509at_get_attr_by_NID)}
      X509at_get_attr_by_NID := _X509at_get_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509at_get_attr_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('X509at_get_attr_by_NID');
    {$ifend}
  end;
  
  X509at_get_attr_by_OBJ := LoadLibFunction(ADllHandle, X509at_get_attr_by_OBJ_procname);
  FuncLoadError := not assigned(X509at_get_attr_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(X509at_get_attr_by_OBJ_allownil)}
    X509at_get_attr_by_OBJ := ERR_X509at_get_attr_by_OBJ;
    {$ifend}
    {$if declared(X509at_get_attr_by_OBJ_introduced)}
    if LibVersion < X509at_get_attr_by_OBJ_introduced then
    begin
      {$if declared(FC_X509at_get_attr_by_OBJ)}
      X509at_get_attr_by_OBJ := FC_X509at_get_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509at_get_attr_by_OBJ_removed)}
    if X509at_get_attr_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_X509at_get_attr_by_OBJ)}
      X509at_get_attr_by_OBJ := _X509at_get_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509at_get_attr_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('X509at_get_attr_by_OBJ');
    {$ifend}
  end;
  
  X509at_get_attr := LoadLibFunction(ADllHandle, X509at_get_attr_procname);
  FuncLoadError := not assigned(X509at_get_attr);
  if FuncLoadError then
  begin
    {$if not defined(X509at_get_attr_allownil)}
    X509at_get_attr := ERR_X509at_get_attr;
    {$ifend}
    {$if declared(X509at_get_attr_introduced)}
    if LibVersion < X509at_get_attr_introduced then
    begin
      {$if declared(FC_X509at_get_attr)}
      X509at_get_attr := FC_X509at_get_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509at_get_attr_removed)}
    if X509at_get_attr_removed <= LibVersion then
    begin
      {$if declared(_X509at_get_attr)}
      X509at_get_attr := _X509at_get_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509at_get_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('X509at_get_attr');
    {$ifend}
  end;
  
  X509at_delete_attr := LoadLibFunction(ADllHandle, X509at_delete_attr_procname);
  FuncLoadError := not assigned(X509at_delete_attr);
  if FuncLoadError then
  begin
    {$if not defined(X509at_delete_attr_allownil)}
    X509at_delete_attr := ERR_X509at_delete_attr;
    {$ifend}
    {$if declared(X509at_delete_attr_introduced)}
    if LibVersion < X509at_delete_attr_introduced then
    begin
      {$if declared(FC_X509at_delete_attr)}
      X509at_delete_attr := FC_X509at_delete_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509at_delete_attr_removed)}
    if X509at_delete_attr_removed <= LibVersion then
    begin
      {$if declared(_X509at_delete_attr)}
      X509at_delete_attr := _X509at_delete_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509at_delete_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('X509at_delete_attr');
    {$ifend}
  end;
  
  X509at_add1_attr := LoadLibFunction(ADllHandle, X509at_add1_attr_procname);
  FuncLoadError := not assigned(X509at_add1_attr);
  if FuncLoadError then
  begin
    {$if not defined(X509at_add1_attr_allownil)}
    X509at_add1_attr := ERR_X509at_add1_attr;
    {$ifend}
    {$if declared(X509at_add1_attr_introduced)}
    if LibVersion < X509at_add1_attr_introduced then
    begin
      {$if declared(FC_X509at_add1_attr)}
      X509at_add1_attr := FC_X509at_add1_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509at_add1_attr_removed)}
    if X509at_add1_attr_removed <= LibVersion then
    begin
      {$if declared(_X509at_add1_attr)}
      X509at_add1_attr := _X509at_add1_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509at_add1_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('X509at_add1_attr');
    {$ifend}
  end;
  
  X509at_add1_attr_by_OBJ := LoadLibFunction(ADllHandle, X509at_add1_attr_by_OBJ_procname);
  FuncLoadError := not assigned(X509at_add1_attr_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(X509at_add1_attr_by_OBJ_allownil)}
    X509at_add1_attr_by_OBJ := ERR_X509at_add1_attr_by_OBJ;
    {$ifend}
    {$if declared(X509at_add1_attr_by_OBJ_introduced)}
    if LibVersion < X509at_add1_attr_by_OBJ_introduced then
    begin
      {$if declared(FC_X509at_add1_attr_by_OBJ)}
      X509at_add1_attr_by_OBJ := FC_X509at_add1_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509at_add1_attr_by_OBJ_removed)}
    if X509at_add1_attr_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_X509at_add1_attr_by_OBJ)}
      X509at_add1_attr_by_OBJ := _X509at_add1_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509at_add1_attr_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('X509at_add1_attr_by_OBJ');
    {$ifend}
  end;
  
  X509at_add1_attr_by_NID := LoadLibFunction(ADllHandle, X509at_add1_attr_by_NID_procname);
  FuncLoadError := not assigned(X509at_add1_attr_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(X509at_add1_attr_by_NID_allownil)}
    X509at_add1_attr_by_NID := ERR_X509at_add1_attr_by_NID;
    {$ifend}
    {$if declared(X509at_add1_attr_by_NID_introduced)}
    if LibVersion < X509at_add1_attr_by_NID_introduced then
    begin
      {$if declared(FC_X509at_add1_attr_by_NID)}
      X509at_add1_attr_by_NID := FC_X509at_add1_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509at_add1_attr_by_NID_removed)}
    if X509at_add1_attr_by_NID_removed <= LibVersion then
    begin
      {$if declared(_X509at_add1_attr_by_NID)}
      X509at_add1_attr_by_NID := _X509at_add1_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509at_add1_attr_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('X509at_add1_attr_by_NID');
    {$ifend}
  end;
  
  X509at_add1_attr_by_txt := LoadLibFunction(ADllHandle, X509at_add1_attr_by_txt_procname);
  FuncLoadError := not assigned(X509at_add1_attr_by_txt);
  if FuncLoadError then
  begin
    {$if not defined(X509at_add1_attr_by_txt_allownil)}
    X509at_add1_attr_by_txt := ERR_X509at_add1_attr_by_txt;
    {$ifend}
    {$if declared(X509at_add1_attr_by_txt_introduced)}
    if LibVersion < X509at_add1_attr_by_txt_introduced then
    begin
      {$if declared(FC_X509at_add1_attr_by_txt)}
      X509at_add1_attr_by_txt := FC_X509at_add1_attr_by_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509at_add1_attr_by_txt_removed)}
    if X509at_add1_attr_by_txt_removed <= LibVersion then
    begin
      {$if declared(_X509at_add1_attr_by_txt)}
      X509at_add1_attr_by_txt := _X509at_add1_attr_by_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509at_add1_attr_by_txt_allownil)}
    if FuncLoadError then
      AFailed.Add('X509at_add1_attr_by_txt');
    {$ifend}
  end;
  
  X509at_get0_data_by_OBJ := LoadLibFunction(ADllHandle, X509at_get0_data_by_OBJ_procname);
  FuncLoadError := not assigned(X509at_get0_data_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(X509at_get0_data_by_OBJ_allownil)}
    X509at_get0_data_by_OBJ := ERR_X509at_get0_data_by_OBJ;
    {$ifend}
    {$if declared(X509at_get0_data_by_OBJ_introduced)}
    if LibVersion < X509at_get0_data_by_OBJ_introduced then
    begin
      {$if declared(FC_X509at_get0_data_by_OBJ)}
      X509at_get0_data_by_OBJ := FC_X509at_get0_data_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509at_get0_data_by_OBJ_removed)}
    if X509at_get0_data_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_X509at_get0_data_by_OBJ)}
      X509at_get0_data_by_OBJ := _X509at_get0_data_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509at_get0_data_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('X509at_get0_data_by_OBJ');
    {$ifend}
  end;
  
  X509_ATTRIBUTE_create_by_NID := LoadLibFunction(ADllHandle, X509_ATTRIBUTE_create_by_NID_procname);
  FuncLoadError := not assigned(X509_ATTRIBUTE_create_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(X509_ATTRIBUTE_create_by_NID_allownil)}
    X509_ATTRIBUTE_create_by_NID := ERR_X509_ATTRIBUTE_create_by_NID;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_create_by_NID_introduced)}
    if LibVersion < X509_ATTRIBUTE_create_by_NID_introduced then
    begin
      {$if declared(FC_X509_ATTRIBUTE_create_by_NID)}
      X509_ATTRIBUTE_create_by_NID := FC_X509_ATTRIBUTE_create_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_create_by_NID_removed)}
    if X509_ATTRIBUTE_create_by_NID_removed <= LibVersion then
    begin
      {$if declared(_X509_ATTRIBUTE_create_by_NID)}
      X509_ATTRIBUTE_create_by_NID := _X509_ATTRIBUTE_create_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ATTRIBUTE_create_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ATTRIBUTE_create_by_NID');
    {$ifend}
  end;
  
  X509_ATTRIBUTE_create_by_OBJ := LoadLibFunction(ADllHandle, X509_ATTRIBUTE_create_by_OBJ_procname);
  FuncLoadError := not assigned(X509_ATTRIBUTE_create_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(X509_ATTRIBUTE_create_by_OBJ_allownil)}
    X509_ATTRIBUTE_create_by_OBJ := ERR_X509_ATTRIBUTE_create_by_OBJ;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_create_by_OBJ_introduced)}
    if LibVersion < X509_ATTRIBUTE_create_by_OBJ_introduced then
    begin
      {$if declared(FC_X509_ATTRIBUTE_create_by_OBJ)}
      X509_ATTRIBUTE_create_by_OBJ := FC_X509_ATTRIBUTE_create_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_create_by_OBJ_removed)}
    if X509_ATTRIBUTE_create_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_X509_ATTRIBUTE_create_by_OBJ)}
      X509_ATTRIBUTE_create_by_OBJ := _X509_ATTRIBUTE_create_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ATTRIBUTE_create_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ATTRIBUTE_create_by_OBJ');
    {$ifend}
  end;
  
  X509_ATTRIBUTE_create_by_txt := LoadLibFunction(ADllHandle, X509_ATTRIBUTE_create_by_txt_procname);
  FuncLoadError := not assigned(X509_ATTRIBUTE_create_by_txt);
  if FuncLoadError then
  begin
    {$if not defined(X509_ATTRIBUTE_create_by_txt_allownil)}
    X509_ATTRIBUTE_create_by_txt := ERR_X509_ATTRIBUTE_create_by_txt;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_create_by_txt_introduced)}
    if LibVersion < X509_ATTRIBUTE_create_by_txt_introduced then
    begin
      {$if declared(FC_X509_ATTRIBUTE_create_by_txt)}
      X509_ATTRIBUTE_create_by_txt := FC_X509_ATTRIBUTE_create_by_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_create_by_txt_removed)}
    if X509_ATTRIBUTE_create_by_txt_removed <= LibVersion then
    begin
      {$if declared(_X509_ATTRIBUTE_create_by_txt)}
      X509_ATTRIBUTE_create_by_txt := _X509_ATTRIBUTE_create_by_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ATTRIBUTE_create_by_txt_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ATTRIBUTE_create_by_txt');
    {$ifend}
  end;
  
  X509_ATTRIBUTE_set1_object := LoadLibFunction(ADllHandle, X509_ATTRIBUTE_set1_object_procname);
  FuncLoadError := not assigned(X509_ATTRIBUTE_set1_object);
  if FuncLoadError then
  begin
    {$if not defined(X509_ATTRIBUTE_set1_object_allownil)}
    X509_ATTRIBUTE_set1_object := ERR_X509_ATTRIBUTE_set1_object;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_set1_object_introduced)}
    if LibVersion < X509_ATTRIBUTE_set1_object_introduced then
    begin
      {$if declared(FC_X509_ATTRIBUTE_set1_object)}
      X509_ATTRIBUTE_set1_object := FC_X509_ATTRIBUTE_set1_object;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_set1_object_removed)}
    if X509_ATTRIBUTE_set1_object_removed <= LibVersion then
    begin
      {$if declared(_X509_ATTRIBUTE_set1_object)}
      X509_ATTRIBUTE_set1_object := _X509_ATTRIBUTE_set1_object;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ATTRIBUTE_set1_object_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ATTRIBUTE_set1_object');
    {$ifend}
  end;
  
  X509_ATTRIBUTE_set1_data := LoadLibFunction(ADllHandle, X509_ATTRIBUTE_set1_data_procname);
  FuncLoadError := not assigned(X509_ATTRIBUTE_set1_data);
  if FuncLoadError then
  begin
    {$if not defined(X509_ATTRIBUTE_set1_data_allownil)}
    X509_ATTRIBUTE_set1_data := ERR_X509_ATTRIBUTE_set1_data;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_set1_data_introduced)}
    if LibVersion < X509_ATTRIBUTE_set1_data_introduced then
    begin
      {$if declared(FC_X509_ATTRIBUTE_set1_data)}
      X509_ATTRIBUTE_set1_data := FC_X509_ATTRIBUTE_set1_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_set1_data_removed)}
    if X509_ATTRIBUTE_set1_data_removed <= LibVersion then
    begin
      {$if declared(_X509_ATTRIBUTE_set1_data)}
      X509_ATTRIBUTE_set1_data := _X509_ATTRIBUTE_set1_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ATTRIBUTE_set1_data_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ATTRIBUTE_set1_data');
    {$ifend}
  end;
  
  X509_ATTRIBUTE_get0_data := LoadLibFunction(ADllHandle, X509_ATTRIBUTE_get0_data_procname);
  FuncLoadError := not assigned(X509_ATTRIBUTE_get0_data);
  if FuncLoadError then
  begin
    {$if not defined(X509_ATTRIBUTE_get0_data_allownil)}
    X509_ATTRIBUTE_get0_data := ERR_X509_ATTRIBUTE_get0_data;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_get0_data_introduced)}
    if LibVersion < X509_ATTRIBUTE_get0_data_introduced then
    begin
      {$if declared(FC_X509_ATTRIBUTE_get0_data)}
      X509_ATTRIBUTE_get0_data := FC_X509_ATTRIBUTE_get0_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_get0_data_removed)}
    if X509_ATTRIBUTE_get0_data_removed <= LibVersion then
    begin
      {$if declared(_X509_ATTRIBUTE_get0_data)}
      X509_ATTRIBUTE_get0_data := _X509_ATTRIBUTE_get0_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ATTRIBUTE_get0_data_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ATTRIBUTE_get0_data');
    {$ifend}
  end;
  
  X509_ATTRIBUTE_count := LoadLibFunction(ADllHandle, X509_ATTRIBUTE_count_procname);
  FuncLoadError := not assigned(X509_ATTRIBUTE_count);
  if FuncLoadError then
  begin
    {$if not defined(X509_ATTRIBUTE_count_allownil)}
    X509_ATTRIBUTE_count := ERR_X509_ATTRIBUTE_count;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_count_introduced)}
    if LibVersion < X509_ATTRIBUTE_count_introduced then
    begin
      {$if declared(FC_X509_ATTRIBUTE_count)}
      X509_ATTRIBUTE_count := FC_X509_ATTRIBUTE_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_count_removed)}
    if X509_ATTRIBUTE_count_removed <= LibVersion then
    begin
      {$if declared(_X509_ATTRIBUTE_count)}
      X509_ATTRIBUTE_count := _X509_ATTRIBUTE_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ATTRIBUTE_count_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ATTRIBUTE_count');
    {$ifend}
  end;
  
  X509_ATTRIBUTE_get0_object := LoadLibFunction(ADllHandle, X509_ATTRIBUTE_get0_object_procname);
  FuncLoadError := not assigned(X509_ATTRIBUTE_get0_object);
  if FuncLoadError then
  begin
    {$if not defined(X509_ATTRIBUTE_get0_object_allownil)}
    X509_ATTRIBUTE_get0_object := ERR_X509_ATTRIBUTE_get0_object;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_get0_object_introduced)}
    if LibVersion < X509_ATTRIBUTE_get0_object_introduced then
    begin
      {$if declared(FC_X509_ATTRIBUTE_get0_object)}
      X509_ATTRIBUTE_get0_object := FC_X509_ATTRIBUTE_get0_object;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_get0_object_removed)}
    if X509_ATTRIBUTE_get0_object_removed <= LibVersion then
    begin
      {$if declared(_X509_ATTRIBUTE_get0_object)}
      X509_ATTRIBUTE_get0_object := _X509_ATTRIBUTE_get0_object;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ATTRIBUTE_get0_object_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ATTRIBUTE_get0_object');
    {$ifend}
  end;
  
  X509_ATTRIBUTE_get0_type := LoadLibFunction(ADllHandle, X509_ATTRIBUTE_get0_type_procname);
  FuncLoadError := not assigned(X509_ATTRIBUTE_get0_type);
  if FuncLoadError then
  begin
    {$if not defined(X509_ATTRIBUTE_get0_type_allownil)}
    X509_ATTRIBUTE_get0_type := ERR_X509_ATTRIBUTE_get0_type;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_get0_type_introduced)}
    if LibVersion < X509_ATTRIBUTE_get0_type_introduced then
    begin
      {$if declared(FC_X509_ATTRIBUTE_get0_type)}
      X509_ATTRIBUTE_get0_type := FC_X509_ATTRIBUTE_get0_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ATTRIBUTE_get0_type_removed)}
    if X509_ATTRIBUTE_get0_type_removed <= LibVersion then
    begin
      {$if declared(_X509_ATTRIBUTE_get0_type)}
      X509_ATTRIBUTE_get0_type := _X509_ATTRIBUTE_get0_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ATTRIBUTE_get0_type_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ATTRIBUTE_get0_type');
    {$ifend}
  end;
  
  EVP_PKEY_get_attr_count := LoadLibFunction(ADllHandle, EVP_PKEY_get_attr_count_procname);
  FuncLoadError := not assigned(EVP_PKEY_get_attr_count);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_get_attr_count_allownil)}
    EVP_PKEY_get_attr_count := ERR_EVP_PKEY_get_attr_count;
    {$ifend}
    {$if declared(EVP_PKEY_get_attr_count_introduced)}
    if LibVersion < EVP_PKEY_get_attr_count_introduced then
    begin
      {$if declared(FC_EVP_PKEY_get_attr_count)}
      EVP_PKEY_get_attr_count := FC_EVP_PKEY_get_attr_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_get_attr_count_removed)}
    if EVP_PKEY_get_attr_count_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_get_attr_count)}
      EVP_PKEY_get_attr_count := _EVP_PKEY_get_attr_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_get_attr_count_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_get_attr_count');
    {$ifend}
  end;
  
  EVP_PKEY_get_attr_by_NID := LoadLibFunction(ADllHandle, EVP_PKEY_get_attr_by_NID_procname);
  FuncLoadError := not assigned(EVP_PKEY_get_attr_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_get_attr_by_NID_allownil)}
    EVP_PKEY_get_attr_by_NID := ERR_EVP_PKEY_get_attr_by_NID;
    {$ifend}
    {$if declared(EVP_PKEY_get_attr_by_NID_introduced)}
    if LibVersion < EVP_PKEY_get_attr_by_NID_introduced then
    begin
      {$if declared(FC_EVP_PKEY_get_attr_by_NID)}
      EVP_PKEY_get_attr_by_NID := FC_EVP_PKEY_get_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_get_attr_by_NID_removed)}
    if EVP_PKEY_get_attr_by_NID_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_get_attr_by_NID)}
      EVP_PKEY_get_attr_by_NID := _EVP_PKEY_get_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_get_attr_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_get_attr_by_NID');
    {$ifend}
  end;
  
  EVP_PKEY_get_attr_by_OBJ := LoadLibFunction(ADllHandle, EVP_PKEY_get_attr_by_OBJ_procname);
  FuncLoadError := not assigned(EVP_PKEY_get_attr_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_get_attr_by_OBJ_allownil)}
    EVP_PKEY_get_attr_by_OBJ := ERR_EVP_PKEY_get_attr_by_OBJ;
    {$ifend}
    {$if declared(EVP_PKEY_get_attr_by_OBJ_introduced)}
    if LibVersion < EVP_PKEY_get_attr_by_OBJ_introduced then
    begin
      {$if declared(FC_EVP_PKEY_get_attr_by_OBJ)}
      EVP_PKEY_get_attr_by_OBJ := FC_EVP_PKEY_get_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_get_attr_by_OBJ_removed)}
    if EVP_PKEY_get_attr_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_get_attr_by_OBJ)}
      EVP_PKEY_get_attr_by_OBJ := _EVP_PKEY_get_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_get_attr_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_get_attr_by_OBJ');
    {$ifend}
  end;
  
  EVP_PKEY_get_attr := LoadLibFunction(ADllHandle, EVP_PKEY_get_attr_procname);
  FuncLoadError := not assigned(EVP_PKEY_get_attr);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_get_attr_allownil)}
    EVP_PKEY_get_attr := ERR_EVP_PKEY_get_attr;
    {$ifend}
    {$if declared(EVP_PKEY_get_attr_introduced)}
    if LibVersion < EVP_PKEY_get_attr_introduced then
    begin
      {$if declared(FC_EVP_PKEY_get_attr)}
      EVP_PKEY_get_attr := FC_EVP_PKEY_get_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_get_attr_removed)}
    if EVP_PKEY_get_attr_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_get_attr)}
      EVP_PKEY_get_attr := _EVP_PKEY_get_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_get_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_get_attr');
    {$ifend}
  end;
  
  EVP_PKEY_delete_attr := LoadLibFunction(ADllHandle, EVP_PKEY_delete_attr_procname);
  FuncLoadError := not assigned(EVP_PKEY_delete_attr);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_delete_attr_allownil)}
    EVP_PKEY_delete_attr := ERR_EVP_PKEY_delete_attr;
    {$ifend}
    {$if declared(EVP_PKEY_delete_attr_introduced)}
    if LibVersion < EVP_PKEY_delete_attr_introduced then
    begin
      {$if declared(FC_EVP_PKEY_delete_attr)}
      EVP_PKEY_delete_attr := FC_EVP_PKEY_delete_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_delete_attr_removed)}
    if EVP_PKEY_delete_attr_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_delete_attr)}
      EVP_PKEY_delete_attr := _EVP_PKEY_delete_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_delete_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_delete_attr');
    {$ifend}
  end;
  
  EVP_PKEY_add1_attr := LoadLibFunction(ADllHandle, EVP_PKEY_add1_attr_procname);
  FuncLoadError := not assigned(EVP_PKEY_add1_attr);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_add1_attr_allownil)}
    EVP_PKEY_add1_attr := ERR_EVP_PKEY_add1_attr;
    {$ifend}
    {$if declared(EVP_PKEY_add1_attr_introduced)}
    if LibVersion < EVP_PKEY_add1_attr_introduced then
    begin
      {$if declared(FC_EVP_PKEY_add1_attr)}
      EVP_PKEY_add1_attr := FC_EVP_PKEY_add1_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_add1_attr_removed)}
    if EVP_PKEY_add1_attr_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_add1_attr)}
      EVP_PKEY_add1_attr := _EVP_PKEY_add1_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_add1_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_add1_attr');
    {$ifend}
  end;
  
  EVP_PKEY_add1_attr_by_OBJ := LoadLibFunction(ADllHandle, EVP_PKEY_add1_attr_by_OBJ_procname);
  FuncLoadError := not assigned(EVP_PKEY_add1_attr_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_add1_attr_by_OBJ_allownil)}
    EVP_PKEY_add1_attr_by_OBJ := ERR_EVP_PKEY_add1_attr_by_OBJ;
    {$ifend}
    {$if declared(EVP_PKEY_add1_attr_by_OBJ_introduced)}
    if LibVersion < EVP_PKEY_add1_attr_by_OBJ_introduced then
    begin
      {$if declared(FC_EVP_PKEY_add1_attr_by_OBJ)}
      EVP_PKEY_add1_attr_by_OBJ := FC_EVP_PKEY_add1_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_add1_attr_by_OBJ_removed)}
    if EVP_PKEY_add1_attr_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_add1_attr_by_OBJ)}
      EVP_PKEY_add1_attr_by_OBJ := _EVP_PKEY_add1_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_add1_attr_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_add1_attr_by_OBJ');
    {$ifend}
  end;
  
  EVP_PKEY_add1_attr_by_NID := LoadLibFunction(ADllHandle, EVP_PKEY_add1_attr_by_NID_procname);
  FuncLoadError := not assigned(EVP_PKEY_add1_attr_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_add1_attr_by_NID_allownil)}
    EVP_PKEY_add1_attr_by_NID := ERR_EVP_PKEY_add1_attr_by_NID;
    {$ifend}
    {$if declared(EVP_PKEY_add1_attr_by_NID_introduced)}
    if LibVersion < EVP_PKEY_add1_attr_by_NID_introduced then
    begin
      {$if declared(FC_EVP_PKEY_add1_attr_by_NID)}
      EVP_PKEY_add1_attr_by_NID := FC_EVP_PKEY_add1_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_add1_attr_by_NID_removed)}
    if EVP_PKEY_add1_attr_by_NID_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_add1_attr_by_NID)}
      EVP_PKEY_add1_attr_by_NID := _EVP_PKEY_add1_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_add1_attr_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_add1_attr_by_NID');
    {$ifend}
  end;
  
  EVP_PKEY_add1_attr_by_txt := LoadLibFunction(ADllHandle, EVP_PKEY_add1_attr_by_txt_procname);
  FuncLoadError := not assigned(EVP_PKEY_add1_attr_by_txt);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY_add1_attr_by_txt_allownil)}
    EVP_PKEY_add1_attr_by_txt := ERR_EVP_PKEY_add1_attr_by_txt;
    {$ifend}
    {$if declared(EVP_PKEY_add1_attr_by_txt_introduced)}
    if LibVersion < EVP_PKEY_add1_attr_by_txt_introduced then
    begin
      {$if declared(FC_EVP_PKEY_add1_attr_by_txt)}
      EVP_PKEY_add1_attr_by_txt := FC_EVP_PKEY_add1_attr_by_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY_add1_attr_by_txt_removed)}
    if EVP_PKEY_add1_attr_by_txt_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY_add1_attr_by_txt)}
      EVP_PKEY_add1_attr_by_txt := _EVP_PKEY_add1_attr_by_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY_add1_attr_by_txt_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_add1_attr_by_txt');
    {$ifend}
  end;
  
  X509_find_by_issuer_and_serial := LoadLibFunction(ADllHandle, X509_find_by_issuer_and_serial_procname);
  FuncLoadError := not assigned(X509_find_by_issuer_and_serial);
  if FuncLoadError then
  begin
    {$if not defined(X509_find_by_issuer_and_serial_allownil)}
    X509_find_by_issuer_and_serial := ERR_X509_find_by_issuer_and_serial;
    {$ifend}
    {$if declared(X509_find_by_issuer_and_serial_introduced)}
    if LibVersion < X509_find_by_issuer_and_serial_introduced then
    begin
      {$if declared(FC_X509_find_by_issuer_and_serial)}
      X509_find_by_issuer_and_serial := FC_X509_find_by_issuer_and_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_find_by_issuer_and_serial_removed)}
    if X509_find_by_issuer_and_serial_removed <= LibVersion then
    begin
      {$if declared(_X509_find_by_issuer_and_serial)}
      X509_find_by_issuer_and_serial := _X509_find_by_issuer_and_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_find_by_issuer_and_serial_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_find_by_issuer_and_serial');
    {$ifend}
  end;
  
  X509_find_by_subject := LoadLibFunction(ADllHandle, X509_find_by_subject_procname);
  FuncLoadError := not assigned(X509_find_by_subject);
  if FuncLoadError then
  begin
    {$if not defined(X509_find_by_subject_allownil)}
    X509_find_by_subject := ERR_X509_find_by_subject;
    {$ifend}
    {$if declared(X509_find_by_subject_introduced)}
    if LibVersion < X509_find_by_subject_introduced then
    begin
      {$if declared(FC_X509_find_by_subject)}
      X509_find_by_subject := FC_X509_find_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_find_by_subject_removed)}
    if X509_find_by_subject_removed <= LibVersion then
    begin
      {$if declared(_X509_find_by_subject)}
      X509_find_by_subject := _X509_find_by_subject;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_find_by_subject_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_find_by_subject');
    {$ifend}
  end;
  
  PBEPARAM_new := LoadLibFunction(ADllHandle, PBEPARAM_new_procname);
  FuncLoadError := not assigned(PBEPARAM_new);
  if FuncLoadError then
  begin
    {$if not defined(PBEPARAM_new_allownil)}
    PBEPARAM_new := ERR_PBEPARAM_new;
    {$ifend}
    {$if declared(PBEPARAM_new_introduced)}
    if LibVersion < PBEPARAM_new_introduced then
    begin
      {$if declared(FC_PBEPARAM_new)}
      PBEPARAM_new := FC_PBEPARAM_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PBEPARAM_new_removed)}
    if PBEPARAM_new_removed <= LibVersion then
    begin
      {$if declared(_PBEPARAM_new)}
      PBEPARAM_new := _PBEPARAM_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PBEPARAM_new_allownil)}
    if FuncLoadError then
      AFailed.Add('PBEPARAM_new');
    {$ifend}
  end;
  
  PBEPARAM_free := LoadLibFunction(ADllHandle, PBEPARAM_free_procname);
  FuncLoadError := not assigned(PBEPARAM_free);
  if FuncLoadError then
  begin
    {$if not defined(PBEPARAM_free_allownil)}
    PBEPARAM_free := ERR_PBEPARAM_free;
    {$ifend}
    {$if declared(PBEPARAM_free_introduced)}
    if LibVersion < PBEPARAM_free_introduced then
    begin
      {$if declared(FC_PBEPARAM_free)}
      PBEPARAM_free := FC_PBEPARAM_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PBEPARAM_free_removed)}
    if PBEPARAM_free_removed <= LibVersion then
    begin
      {$if declared(_PBEPARAM_free)}
      PBEPARAM_free := _PBEPARAM_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PBEPARAM_free_allownil)}
    if FuncLoadError then
      AFailed.Add('PBEPARAM_free');
    {$ifend}
  end;
  
  d2i_PBEPARAM := LoadLibFunction(ADllHandle, d2i_PBEPARAM_procname);
  FuncLoadError := not assigned(d2i_PBEPARAM);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PBEPARAM_allownil)}
    d2i_PBEPARAM := ERR_d2i_PBEPARAM;
    {$ifend}
    {$if declared(d2i_PBEPARAM_introduced)}
    if LibVersion < d2i_PBEPARAM_introduced then
    begin
      {$if declared(FC_d2i_PBEPARAM)}
      d2i_PBEPARAM := FC_d2i_PBEPARAM;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PBEPARAM_removed)}
    if d2i_PBEPARAM_removed <= LibVersion then
    begin
      {$if declared(_d2i_PBEPARAM)}
      d2i_PBEPARAM := _d2i_PBEPARAM;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PBEPARAM_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PBEPARAM');
    {$ifend}
  end;
  
  i2d_PBEPARAM := LoadLibFunction(ADllHandle, i2d_PBEPARAM_procname);
  FuncLoadError := not assigned(i2d_PBEPARAM);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PBEPARAM_allownil)}
    i2d_PBEPARAM := ERR_i2d_PBEPARAM;
    {$ifend}
    {$if declared(i2d_PBEPARAM_introduced)}
    if LibVersion < i2d_PBEPARAM_introduced then
    begin
      {$if declared(FC_i2d_PBEPARAM)}
      i2d_PBEPARAM := FC_i2d_PBEPARAM;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PBEPARAM_removed)}
    if i2d_PBEPARAM_removed <= LibVersion then
    begin
      {$if declared(_i2d_PBEPARAM)}
      i2d_PBEPARAM := _i2d_PBEPARAM;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PBEPARAM_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PBEPARAM');
    {$ifend}
  end;
  
  PBEPARAM_it := LoadLibFunction(ADllHandle, PBEPARAM_it_procname);
  FuncLoadError := not assigned(PBEPARAM_it);
  if FuncLoadError then
  begin
    {$if not defined(PBEPARAM_it_allownil)}
    PBEPARAM_it := ERR_PBEPARAM_it;
    {$ifend}
    {$if declared(PBEPARAM_it_introduced)}
    if LibVersion < PBEPARAM_it_introduced then
    begin
      {$if declared(FC_PBEPARAM_it)}
      PBEPARAM_it := FC_PBEPARAM_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PBEPARAM_it_removed)}
    if PBEPARAM_it_removed <= LibVersion then
    begin
      {$if declared(_PBEPARAM_it)}
      PBEPARAM_it := _PBEPARAM_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PBEPARAM_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PBEPARAM_it');
    {$ifend}
  end;
  
  PBE2PARAM_new := LoadLibFunction(ADllHandle, PBE2PARAM_new_procname);
  FuncLoadError := not assigned(PBE2PARAM_new);
  if FuncLoadError then
  begin
    {$if not defined(PBE2PARAM_new_allownil)}
    PBE2PARAM_new := ERR_PBE2PARAM_new;
    {$ifend}
    {$if declared(PBE2PARAM_new_introduced)}
    if LibVersion < PBE2PARAM_new_introduced then
    begin
      {$if declared(FC_PBE2PARAM_new)}
      PBE2PARAM_new := FC_PBE2PARAM_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PBE2PARAM_new_removed)}
    if PBE2PARAM_new_removed <= LibVersion then
    begin
      {$if declared(_PBE2PARAM_new)}
      PBE2PARAM_new := _PBE2PARAM_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PBE2PARAM_new_allownil)}
    if FuncLoadError then
      AFailed.Add('PBE2PARAM_new');
    {$ifend}
  end;
  
  PBE2PARAM_free := LoadLibFunction(ADllHandle, PBE2PARAM_free_procname);
  FuncLoadError := not assigned(PBE2PARAM_free);
  if FuncLoadError then
  begin
    {$if not defined(PBE2PARAM_free_allownil)}
    PBE2PARAM_free := ERR_PBE2PARAM_free;
    {$ifend}
    {$if declared(PBE2PARAM_free_introduced)}
    if LibVersion < PBE2PARAM_free_introduced then
    begin
      {$if declared(FC_PBE2PARAM_free)}
      PBE2PARAM_free := FC_PBE2PARAM_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PBE2PARAM_free_removed)}
    if PBE2PARAM_free_removed <= LibVersion then
    begin
      {$if declared(_PBE2PARAM_free)}
      PBE2PARAM_free := _PBE2PARAM_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PBE2PARAM_free_allownil)}
    if FuncLoadError then
      AFailed.Add('PBE2PARAM_free');
    {$ifend}
  end;
  
  d2i_PBE2PARAM := LoadLibFunction(ADllHandle, d2i_PBE2PARAM_procname);
  FuncLoadError := not assigned(d2i_PBE2PARAM);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PBE2PARAM_allownil)}
    d2i_PBE2PARAM := ERR_d2i_PBE2PARAM;
    {$ifend}
    {$if declared(d2i_PBE2PARAM_introduced)}
    if LibVersion < d2i_PBE2PARAM_introduced then
    begin
      {$if declared(FC_d2i_PBE2PARAM)}
      d2i_PBE2PARAM := FC_d2i_PBE2PARAM;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PBE2PARAM_removed)}
    if d2i_PBE2PARAM_removed <= LibVersion then
    begin
      {$if declared(_d2i_PBE2PARAM)}
      d2i_PBE2PARAM := _d2i_PBE2PARAM;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PBE2PARAM_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PBE2PARAM');
    {$ifend}
  end;
  
  i2d_PBE2PARAM := LoadLibFunction(ADllHandle, i2d_PBE2PARAM_procname);
  FuncLoadError := not assigned(i2d_PBE2PARAM);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PBE2PARAM_allownil)}
    i2d_PBE2PARAM := ERR_i2d_PBE2PARAM;
    {$ifend}
    {$if declared(i2d_PBE2PARAM_introduced)}
    if LibVersion < i2d_PBE2PARAM_introduced then
    begin
      {$if declared(FC_i2d_PBE2PARAM)}
      i2d_PBE2PARAM := FC_i2d_PBE2PARAM;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PBE2PARAM_removed)}
    if i2d_PBE2PARAM_removed <= LibVersion then
    begin
      {$if declared(_i2d_PBE2PARAM)}
      i2d_PBE2PARAM := _i2d_PBE2PARAM;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PBE2PARAM_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PBE2PARAM');
    {$ifend}
  end;
  
  PBE2PARAM_it := LoadLibFunction(ADllHandle, PBE2PARAM_it_procname);
  FuncLoadError := not assigned(PBE2PARAM_it);
  if FuncLoadError then
  begin
    {$if not defined(PBE2PARAM_it_allownil)}
    PBE2PARAM_it := ERR_PBE2PARAM_it;
    {$ifend}
    {$if declared(PBE2PARAM_it_introduced)}
    if LibVersion < PBE2PARAM_it_introduced then
    begin
      {$if declared(FC_PBE2PARAM_it)}
      PBE2PARAM_it := FC_PBE2PARAM_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PBE2PARAM_it_removed)}
    if PBE2PARAM_it_removed <= LibVersion then
    begin
      {$if declared(_PBE2PARAM_it)}
      PBE2PARAM_it := _PBE2PARAM_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PBE2PARAM_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PBE2PARAM_it');
    {$ifend}
  end;
  
  PBKDF2PARAM_new := LoadLibFunction(ADllHandle, PBKDF2PARAM_new_procname);
  FuncLoadError := not assigned(PBKDF2PARAM_new);
  if FuncLoadError then
  begin
    {$if not defined(PBKDF2PARAM_new_allownil)}
    PBKDF2PARAM_new := ERR_PBKDF2PARAM_new;
    {$ifend}
    {$if declared(PBKDF2PARAM_new_introduced)}
    if LibVersion < PBKDF2PARAM_new_introduced then
    begin
      {$if declared(FC_PBKDF2PARAM_new)}
      PBKDF2PARAM_new := FC_PBKDF2PARAM_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PBKDF2PARAM_new_removed)}
    if PBKDF2PARAM_new_removed <= LibVersion then
    begin
      {$if declared(_PBKDF2PARAM_new)}
      PBKDF2PARAM_new := _PBKDF2PARAM_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PBKDF2PARAM_new_allownil)}
    if FuncLoadError then
      AFailed.Add('PBKDF2PARAM_new');
    {$ifend}
  end;
  
  PBKDF2PARAM_free := LoadLibFunction(ADllHandle, PBKDF2PARAM_free_procname);
  FuncLoadError := not assigned(PBKDF2PARAM_free);
  if FuncLoadError then
  begin
    {$if not defined(PBKDF2PARAM_free_allownil)}
    PBKDF2PARAM_free := ERR_PBKDF2PARAM_free;
    {$ifend}
    {$if declared(PBKDF2PARAM_free_introduced)}
    if LibVersion < PBKDF2PARAM_free_introduced then
    begin
      {$if declared(FC_PBKDF2PARAM_free)}
      PBKDF2PARAM_free := FC_PBKDF2PARAM_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PBKDF2PARAM_free_removed)}
    if PBKDF2PARAM_free_removed <= LibVersion then
    begin
      {$if declared(_PBKDF2PARAM_free)}
      PBKDF2PARAM_free := _PBKDF2PARAM_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PBKDF2PARAM_free_allownil)}
    if FuncLoadError then
      AFailed.Add('PBKDF2PARAM_free');
    {$ifend}
  end;
  
  d2i_PBKDF2PARAM := LoadLibFunction(ADllHandle, d2i_PBKDF2PARAM_procname);
  FuncLoadError := not assigned(d2i_PBKDF2PARAM);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PBKDF2PARAM_allownil)}
    d2i_PBKDF2PARAM := ERR_d2i_PBKDF2PARAM;
    {$ifend}
    {$if declared(d2i_PBKDF2PARAM_introduced)}
    if LibVersion < d2i_PBKDF2PARAM_introduced then
    begin
      {$if declared(FC_d2i_PBKDF2PARAM)}
      d2i_PBKDF2PARAM := FC_d2i_PBKDF2PARAM;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PBKDF2PARAM_removed)}
    if d2i_PBKDF2PARAM_removed <= LibVersion then
    begin
      {$if declared(_d2i_PBKDF2PARAM)}
      d2i_PBKDF2PARAM := _d2i_PBKDF2PARAM;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PBKDF2PARAM_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PBKDF2PARAM');
    {$ifend}
  end;
  
  i2d_PBKDF2PARAM := LoadLibFunction(ADllHandle, i2d_PBKDF2PARAM_procname);
  FuncLoadError := not assigned(i2d_PBKDF2PARAM);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PBKDF2PARAM_allownil)}
    i2d_PBKDF2PARAM := ERR_i2d_PBKDF2PARAM;
    {$ifend}
    {$if declared(i2d_PBKDF2PARAM_introduced)}
    if LibVersion < i2d_PBKDF2PARAM_introduced then
    begin
      {$if declared(FC_i2d_PBKDF2PARAM)}
      i2d_PBKDF2PARAM := FC_i2d_PBKDF2PARAM;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PBKDF2PARAM_removed)}
    if i2d_PBKDF2PARAM_removed <= LibVersion then
    begin
      {$if declared(_i2d_PBKDF2PARAM)}
      i2d_PBKDF2PARAM := _i2d_PBKDF2PARAM;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PBKDF2PARAM_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PBKDF2PARAM');
    {$ifend}
  end;
  
  PBKDF2PARAM_it := LoadLibFunction(ADllHandle, PBKDF2PARAM_it_procname);
  FuncLoadError := not assigned(PBKDF2PARAM_it);
  if FuncLoadError then
  begin
    {$if not defined(PBKDF2PARAM_it_allownil)}
    PBKDF2PARAM_it := ERR_PBKDF2PARAM_it;
    {$ifend}
    {$if declared(PBKDF2PARAM_it_introduced)}
    if LibVersion < PBKDF2PARAM_it_introduced then
    begin
      {$if declared(FC_PBKDF2PARAM_it)}
      PBKDF2PARAM_it := FC_PBKDF2PARAM_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PBKDF2PARAM_it_removed)}
    if PBKDF2PARAM_it_removed <= LibVersion then
    begin
      {$if declared(_PBKDF2PARAM_it)}
      PBKDF2PARAM_it := _PBKDF2PARAM_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PBKDF2PARAM_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PBKDF2PARAM_it');
    {$ifend}
  end;
  
  PBMAC1PARAM_new := LoadLibFunction(ADllHandle, PBMAC1PARAM_new_procname);
  FuncLoadError := not assigned(PBMAC1PARAM_new);
  if FuncLoadError then
  begin
    {$if not defined(PBMAC1PARAM_new_allownil)}
    PBMAC1PARAM_new := ERR_PBMAC1PARAM_new;
    {$ifend}
    {$if declared(PBMAC1PARAM_new_introduced)}
    if LibVersion < PBMAC1PARAM_new_introduced then
    begin
      {$if declared(FC_PBMAC1PARAM_new)}
      PBMAC1PARAM_new := FC_PBMAC1PARAM_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PBMAC1PARAM_new_removed)}
    if PBMAC1PARAM_new_removed <= LibVersion then
    begin
      {$if declared(_PBMAC1PARAM_new)}
      PBMAC1PARAM_new := _PBMAC1PARAM_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PBMAC1PARAM_new_allownil)}
    if FuncLoadError then
      AFailed.Add('PBMAC1PARAM_new');
    {$ifend}
  end;
  
  PBMAC1PARAM_free := LoadLibFunction(ADllHandle, PBMAC1PARAM_free_procname);
  FuncLoadError := not assigned(PBMAC1PARAM_free);
  if FuncLoadError then
  begin
    {$if not defined(PBMAC1PARAM_free_allownil)}
    PBMAC1PARAM_free := ERR_PBMAC1PARAM_free;
    {$ifend}
    {$if declared(PBMAC1PARAM_free_introduced)}
    if LibVersion < PBMAC1PARAM_free_introduced then
    begin
      {$if declared(FC_PBMAC1PARAM_free)}
      PBMAC1PARAM_free := FC_PBMAC1PARAM_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PBMAC1PARAM_free_removed)}
    if PBMAC1PARAM_free_removed <= LibVersion then
    begin
      {$if declared(_PBMAC1PARAM_free)}
      PBMAC1PARAM_free := _PBMAC1PARAM_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PBMAC1PARAM_free_allownil)}
    if FuncLoadError then
      AFailed.Add('PBMAC1PARAM_free');
    {$ifend}
  end;
  
  d2i_PBMAC1PARAM := LoadLibFunction(ADllHandle, d2i_PBMAC1PARAM_procname);
  FuncLoadError := not assigned(d2i_PBMAC1PARAM);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PBMAC1PARAM_allownil)}
    d2i_PBMAC1PARAM := ERR_d2i_PBMAC1PARAM;
    {$ifend}
    {$if declared(d2i_PBMAC1PARAM_introduced)}
    if LibVersion < d2i_PBMAC1PARAM_introduced then
    begin
      {$if declared(FC_d2i_PBMAC1PARAM)}
      d2i_PBMAC1PARAM := FC_d2i_PBMAC1PARAM;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PBMAC1PARAM_removed)}
    if d2i_PBMAC1PARAM_removed <= LibVersion then
    begin
      {$if declared(_d2i_PBMAC1PARAM)}
      d2i_PBMAC1PARAM := _d2i_PBMAC1PARAM;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PBMAC1PARAM_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PBMAC1PARAM');
    {$ifend}
  end;
  
  i2d_PBMAC1PARAM := LoadLibFunction(ADllHandle, i2d_PBMAC1PARAM_procname);
  FuncLoadError := not assigned(i2d_PBMAC1PARAM);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PBMAC1PARAM_allownil)}
    i2d_PBMAC1PARAM := ERR_i2d_PBMAC1PARAM;
    {$ifend}
    {$if declared(i2d_PBMAC1PARAM_introduced)}
    if LibVersion < i2d_PBMAC1PARAM_introduced then
    begin
      {$if declared(FC_i2d_PBMAC1PARAM)}
      i2d_PBMAC1PARAM := FC_i2d_PBMAC1PARAM;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PBMAC1PARAM_removed)}
    if i2d_PBMAC1PARAM_removed <= LibVersion then
    begin
      {$if declared(_i2d_PBMAC1PARAM)}
      i2d_PBMAC1PARAM := _i2d_PBMAC1PARAM;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PBMAC1PARAM_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PBMAC1PARAM');
    {$ifend}
  end;
  
  PBMAC1PARAM_it := LoadLibFunction(ADllHandle, PBMAC1PARAM_it_procname);
  FuncLoadError := not assigned(PBMAC1PARAM_it);
  if FuncLoadError then
  begin
    {$if not defined(PBMAC1PARAM_it_allownil)}
    PBMAC1PARAM_it := ERR_PBMAC1PARAM_it;
    {$ifend}
    {$if declared(PBMAC1PARAM_it_introduced)}
    if LibVersion < PBMAC1PARAM_it_introduced then
    begin
      {$if declared(FC_PBMAC1PARAM_it)}
      PBMAC1PARAM_it := FC_PBMAC1PARAM_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PBMAC1PARAM_it_removed)}
    if PBMAC1PARAM_it_removed <= LibVersion then
    begin
      {$if declared(_PBMAC1PARAM_it)}
      PBMAC1PARAM_it := _PBMAC1PARAM_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PBMAC1PARAM_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PBMAC1PARAM_it');
    {$ifend}
  end;
  
  SCRYPT_PARAMS_new := LoadLibFunction(ADllHandle, SCRYPT_PARAMS_new_procname);
  FuncLoadError := not assigned(SCRYPT_PARAMS_new);
  if FuncLoadError then
  begin
    {$if not defined(SCRYPT_PARAMS_new_allownil)}
    SCRYPT_PARAMS_new := ERR_SCRYPT_PARAMS_new;
    {$ifend}
    {$if declared(SCRYPT_PARAMS_new_introduced)}
    if LibVersion < SCRYPT_PARAMS_new_introduced then
    begin
      {$if declared(FC_SCRYPT_PARAMS_new)}
      SCRYPT_PARAMS_new := FC_SCRYPT_PARAMS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCRYPT_PARAMS_new_removed)}
    if SCRYPT_PARAMS_new_removed <= LibVersion then
    begin
      {$if declared(_SCRYPT_PARAMS_new)}
      SCRYPT_PARAMS_new := _SCRYPT_PARAMS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCRYPT_PARAMS_new_allownil)}
    if FuncLoadError then
      AFailed.Add('SCRYPT_PARAMS_new');
    {$ifend}
  end;
  
  SCRYPT_PARAMS_free := LoadLibFunction(ADllHandle, SCRYPT_PARAMS_free_procname);
  FuncLoadError := not assigned(SCRYPT_PARAMS_free);
  if FuncLoadError then
  begin
    {$if not defined(SCRYPT_PARAMS_free_allownil)}
    SCRYPT_PARAMS_free := ERR_SCRYPT_PARAMS_free;
    {$ifend}
    {$if declared(SCRYPT_PARAMS_free_introduced)}
    if LibVersion < SCRYPT_PARAMS_free_introduced then
    begin
      {$if declared(FC_SCRYPT_PARAMS_free)}
      SCRYPT_PARAMS_free := FC_SCRYPT_PARAMS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCRYPT_PARAMS_free_removed)}
    if SCRYPT_PARAMS_free_removed <= LibVersion then
    begin
      {$if declared(_SCRYPT_PARAMS_free)}
      SCRYPT_PARAMS_free := _SCRYPT_PARAMS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCRYPT_PARAMS_free_allownil)}
    if FuncLoadError then
      AFailed.Add('SCRYPT_PARAMS_free');
    {$ifend}
  end;
  
  d2i_SCRYPT_PARAMS := LoadLibFunction(ADllHandle, d2i_SCRYPT_PARAMS_procname);
  FuncLoadError := not assigned(d2i_SCRYPT_PARAMS);
  if FuncLoadError then
  begin
    {$if not defined(d2i_SCRYPT_PARAMS_allownil)}
    d2i_SCRYPT_PARAMS := ERR_d2i_SCRYPT_PARAMS;
    {$ifend}
    {$if declared(d2i_SCRYPT_PARAMS_introduced)}
    if LibVersion < d2i_SCRYPT_PARAMS_introduced then
    begin
      {$if declared(FC_d2i_SCRYPT_PARAMS)}
      d2i_SCRYPT_PARAMS := FC_d2i_SCRYPT_PARAMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_SCRYPT_PARAMS_removed)}
    if d2i_SCRYPT_PARAMS_removed <= LibVersion then
    begin
      {$if declared(_d2i_SCRYPT_PARAMS)}
      d2i_SCRYPT_PARAMS := _d2i_SCRYPT_PARAMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_SCRYPT_PARAMS_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_SCRYPT_PARAMS');
    {$ifend}
  end;
  
  i2d_SCRYPT_PARAMS := LoadLibFunction(ADllHandle, i2d_SCRYPT_PARAMS_procname);
  FuncLoadError := not assigned(i2d_SCRYPT_PARAMS);
  if FuncLoadError then
  begin
    {$if not defined(i2d_SCRYPT_PARAMS_allownil)}
    i2d_SCRYPT_PARAMS := ERR_i2d_SCRYPT_PARAMS;
    {$ifend}
    {$if declared(i2d_SCRYPT_PARAMS_introduced)}
    if LibVersion < i2d_SCRYPT_PARAMS_introduced then
    begin
      {$if declared(FC_i2d_SCRYPT_PARAMS)}
      i2d_SCRYPT_PARAMS := FC_i2d_SCRYPT_PARAMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_SCRYPT_PARAMS_removed)}
    if i2d_SCRYPT_PARAMS_removed <= LibVersion then
    begin
      {$if declared(_i2d_SCRYPT_PARAMS)}
      i2d_SCRYPT_PARAMS := _i2d_SCRYPT_PARAMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_SCRYPT_PARAMS_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_SCRYPT_PARAMS');
    {$ifend}
  end;
  
  SCRYPT_PARAMS_it := LoadLibFunction(ADllHandle, SCRYPT_PARAMS_it_procname);
  FuncLoadError := not assigned(SCRYPT_PARAMS_it);
  if FuncLoadError then
  begin
    {$if not defined(SCRYPT_PARAMS_it_allownil)}
    SCRYPT_PARAMS_it := ERR_SCRYPT_PARAMS_it;
    {$ifend}
    {$if declared(SCRYPT_PARAMS_it_introduced)}
    if LibVersion < SCRYPT_PARAMS_it_introduced then
    begin
      {$if declared(FC_SCRYPT_PARAMS_it)}
      SCRYPT_PARAMS_it := FC_SCRYPT_PARAMS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SCRYPT_PARAMS_it_removed)}
    if SCRYPT_PARAMS_it_removed <= LibVersion then
    begin
      {$if declared(_SCRYPT_PARAMS_it)}
      SCRYPT_PARAMS_it := _SCRYPT_PARAMS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SCRYPT_PARAMS_it_allownil)}
    if FuncLoadError then
      AFailed.Add('SCRYPT_PARAMS_it');
    {$ifend}
  end;
  
  PKCS5_pbe_set0_algor := LoadLibFunction(ADllHandle, PKCS5_pbe_set0_algor_procname);
  FuncLoadError := not assigned(PKCS5_pbe_set0_algor);
  if FuncLoadError then
  begin
    {$if not defined(PKCS5_pbe_set0_algor_allownil)}
    PKCS5_pbe_set0_algor := ERR_PKCS5_pbe_set0_algor;
    {$ifend}
    {$if declared(PKCS5_pbe_set0_algor_introduced)}
    if LibVersion < PKCS5_pbe_set0_algor_introduced then
    begin
      {$if declared(FC_PKCS5_pbe_set0_algor)}
      PKCS5_pbe_set0_algor := FC_PKCS5_pbe_set0_algor;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS5_pbe_set0_algor_removed)}
    if PKCS5_pbe_set0_algor_removed <= LibVersion then
    begin
      {$if declared(_PKCS5_pbe_set0_algor)}
      PKCS5_pbe_set0_algor := _PKCS5_pbe_set0_algor;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS5_pbe_set0_algor_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS5_pbe_set0_algor');
    {$ifend}
  end;
  
  PKCS5_pbe_set0_algor_ex := LoadLibFunction(ADllHandle, PKCS5_pbe_set0_algor_ex_procname);
  FuncLoadError := not assigned(PKCS5_pbe_set0_algor_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS5_pbe_set0_algor_ex_allownil)}
    PKCS5_pbe_set0_algor_ex := ERR_PKCS5_pbe_set0_algor_ex;
    {$ifend}
    {$if declared(PKCS5_pbe_set0_algor_ex_introduced)}
    if LibVersion < PKCS5_pbe_set0_algor_ex_introduced then
    begin
      {$if declared(FC_PKCS5_pbe_set0_algor_ex)}
      PKCS5_pbe_set0_algor_ex := FC_PKCS5_pbe_set0_algor_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS5_pbe_set0_algor_ex_removed)}
    if PKCS5_pbe_set0_algor_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS5_pbe_set0_algor_ex)}
      PKCS5_pbe_set0_algor_ex := _PKCS5_pbe_set0_algor_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS5_pbe_set0_algor_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS5_pbe_set0_algor_ex');
    {$ifend}
  end;
  
  PKCS5_pbe_set := LoadLibFunction(ADllHandle, PKCS5_pbe_set_procname);
  FuncLoadError := not assigned(PKCS5_pbe_set);
  if FuncLoadError then
  begin
    {$if not defined(PKCS5_pbe_set_allownil)}
    PKCS5_pbe_set := ERR_PKCS5_pbe_set;
    {$ifend}
    {$if declared(PKCS5_pbe_set_introduced)}
    if LibVersion < PKCS5_pbe_set_introduced then
    begin
      {$if declared(FC_PKCS5_pbe_set)}
      PKCS5_pbe_set := FC_PKCS5_pbe_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS5_pbe_set_removed)}
    if PKCS5_pbe_set_removed <= LibVersion then
    begin
      {$if declared(_PKCS5_pbe_set)}
      PKCS5_pbe_set := _PKCS5_pbe_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS5_pbe_set_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS5_pbe_set');
    {$ifend}
  end;
  
  PKCS5_pbe_set_ex := LoadLibFunction(ADllHandle, PKCS5_pbe_set_ex_procname);
  FuncLoadError := not assigned(PKCS5_pbe_set_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS5_pbe_set_ex_allownil)}
    PKCS5_pbe_set_ex := ERR_PKCS5_pbe_set_ex;
    {$ifend}
    {$if declared(PKCS5_pbe_set_ex_introduced)}
    if LibVersion < PKCS5_pbe_set_ex_introduced then
    begin
      {$if declared(FC_PKCS5_pbe_set_ex)}
      PKCS5_pbe_set_ex := FC_PKCS5_pbe_set_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS5_pbe_set_ex_removed)}
    if PKCS5_pbe_set_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS5_pbe_set_ex)}
      PKCS5_pbe_set_ex := _PKCS5_pbe_set_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS5_pbe_set_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS5_pbe_set_ex');
    {$ifend}
  end;
  
  PKCS5_pbe2_set := LoadLibFunction(ADllHandle, PKCS5_pbe2_set_procname);
  FuncLoadError := not assigned(PKCS5_pbe2_set);
  if FuncLoadError then
  begin
    {$if not defined(PKCS5_pbe2_set_allownil)}
    PKCS5_pbe2_set := ERR_PKCS5_pbe2_set;
    {$ifend}
    {$if declared(PKCS5_pbe2_set_introduced)}
    if LibVersion < PKCS5_pbe2_set_introduced then
    begin
      {$if declared(FC_PKCS5_pbe2_set)}
      PKCS5_pbe2_set := FC_PKCS5_pbe2_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS5_pbe2_set_removed)}
    if PKCS5_pbe2_set_removed <= LibVersion then
    begin
      {$if declared(_PKCS5_pbe2_set)}
      PKCS5_pbe2_set := _PKCS5_pbe2_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS5_pbe2_set_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS5_pbe2_set');
    {$ifend}
  end;
  
  PKCS5_pbe2_set_iv := LoadLibFunction(ADllHandle, PKCS5_pbe2_set_iv_procname);
  FuncLoadError := not assigned(PKCS5_pbe2_set_iv);
  if FuncLoadError then
  begin
    {$if not defined(PKCS5_pbe2_set_iv_allownil)}
    PKCS5_pbe2_set_iv := ERR_PKCS5_pbe2_set_iv;
    {$ifend}
    {$if declared(PKCS5_pbe2_set_iv_introduced)}
    if LibVersion < PKCS5_pbe2_set_iv_introduced then
    begin
      {$if declared(FC_PKCS5_pbe2_set_iv)}
      PKCS5_pbe2_set_iv := FC_PKCS5_pbe2_set_iv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS5_pbe2_set_iv_removed)}
    if PKCS5_pbe2_set_iv_removed <= LibVersion then
    begin
      {$if declared(_PKCS5_pbe2_set_iv)}
      PKCS5_pbe2_set_iv := _PKCS5_pbe2_set_iv;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS5_pbe2_set_iv_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS5_pbe2_set_iv');
    {$ifend}
  end;
  
  PKCS5_pbe2_set_iv_ex := LoadLibFunction(ADllHandle, PKCS5_pbe2_set_iv_ex_procname);
  FuncLoadError := not assigned(PKCS5_pbe2_set_iv_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS5_pbe2_set_iv_ex_allownil)}
    PKCS5_pbe2_set_iv_ex := ERR_PKCS5_pbe2_set_iv_ex;
    {$ifend}
    {$if declared(PKCS5_pbe2_set_iv_ex_introduced)}
    if LibVersion < PKCS5_pbe2_set_iv_ex_introduced then
    begin
      {$if declared(FC_PKCS5_pbe2_set_iv_ex)}
      PKCS5_pbe2_set_iv_ex := FC_PKCS5_pbe2_set_iv_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS5_pbe2_set_iv_ex_removed)}
    if PKCS5_pbe2_set_iv_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS5_pbe2_set_iv_ex)}
      PKCS5_pbe2_set_iv_ex := _PKCS5_pbe2_set_iv_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS5_pbe2_set_iv_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS5_pbe2_set_iv_ex');
    {$ifend}
  end;
  
  PKCS5_pbe2_set_scrypt := LoadLibFunction(ADllHandle, PKCS5_pbe2_set_scrypt_procname);
  FuncLoadError := not assigned(PKCS5_pbe2_set_scrypt);
  if FuncLoadError then
  begin
    {$if not defined(PKCS5_pbe2_set_scrypt_allownil)}
    PKCS5_pbe2_set_scrypt := ERR_PKCS5_pbe2_set_scrypt;
    {$ifend}
    {$if declared(PKCS5_pbe2_set_scrypt_introduced)}
    if LibVersion < PKCS5_pbe2_set_scrypt_introduced then
    begin
      {$if declared(FC_PKCS5_pbe2_set_scrypt)}
      PKCS5_pbe2_set_scrypt := FC_PKCS5_pbe2_set_scrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS5_pbe2_set_scrypt_removed)}
    if PKCS5_pbe2_set_scrypt_removed <= LibVersion then
    begin
      {$if declared(_PKCS5_pbe2_set_scrypt)}
      PKCS5_pbe2_set_scrypt := _PKCS5_pbe2_set_scrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS5_pbe2_set_scrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS5_pbe2_set_scrypt');
    {$ifend}
  end;
  
  PKCS5_pbkdf2_set := LoadLibFunction(ADllHandle, PKCS5_pbkdf2_set_procname);
  FuncLoadError := not assigned(PKCS5_pbkdf2_set);
  if FuncLoadError then
  begin
    {$if not defined(PKCS5_pbkdf2_set_allownil)}
    PKCS5_pbkdf2_set := ERR_PKCS5_pbkdf2_set;
    {$ifend}
    {$if declared(PKCS5_pbkdf2_set_introduced)}
    if LibVersion < PKCS5_pbkdf2_set_introduced then
    begin
      {$if declared(FC_PKCS5_pbkdf2_set)}
      PKCS5_pbkdf2_set := FC_PKCS5_pbkdf2_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS5_pbkdf2_set_removed)}
    if PKCS5_pbkdf2_set_removed <= LibVersion then
    begin
      {$if declared(_PKCS5_pbkdf2_set)}
      PKCS5_pbkdf2_set := _PKCS5_pbkdf2_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS5_pbkdf2_set_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS5_pbkdf2_set');
    {$ifend}
  end;
  
  PKCS5_pbkdf2_set_ex := LoadLibFunction(ADllHandle, PKCS5_pbkdf2_set_ex_procname);
  FuncLoadError := not assigned(PKCS5_pbkdf2_set_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS5_pbkdf2_set_ex_allownil)}
    PKCS5_pbkdf2_set_ex := ERR_PKCS5_pbkdf2_set_ex;
    {$ifend}
    {$if declared(PKCS5_pbkdf2_set_ex_introduced)}
    if LibVersion < PKCS5_pbkdf2_set_ex_introduced then
    begin
      {$if declared(FC_PKCS5_pbkdf2_set_ex)}
      PKCS5_pbkdf2_set_ex := FC_PKCS5_pbkdf2_set_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS5_pbkdf2_set_ex_removed)}
    if PKCS5_pbkdf2_set_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS5_pbkdf2_set_ex)}
      PKCS5_pbkdf2_set_ex := _PKCS5_pbkdf2_set_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS5_pbkdf2_set_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS5_pbkdf2_set_ex');
    {$ifend}
  end;
  
  PBMAC1_get1_pbkdf2_param := LoadLibFunction(ADllHandle, PBMAC1_get1_pbkdf2_param_procname);
  FuncLoadError := not assigned(PBMAC1_get1_pbkdf2_param);
  if FuncLoadError then
  begin
    {$if not defined(PBMAC1_get1_pbkdf2_param_allownil)}
    PBMAC1_get1_pbkdf2_param := ERR_PBMAC1_get1_pbkdf2_param;
    {$ifend}
    {$if declared(PBMAC1_get1_pbkdf2_param_introduced)}
    if LibVersion < PBMAC1_get1_pbkdf2_param_introduced then
    begin
      {$if declared(FC_PBMAC1_get1_pbkdf2_param)}
      PBMAC1_get1_pbkdf2_param := FC_PBMAC1_get1_pbkdf2_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PBMAC1_get1_pbkdf2_param_removed)}
    if PBMAC1_get1_pbkdf2_param_removed <= LibVersion then
    begin
      {$if declared(_PBMAC1_get1_pbkdf2_param)}
      PBMAC1_get1_pbkdf2_param := _PBMAC1_get1_pbkdf2_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PBMAC1_get1_pbkdf2_param_allownil)}
    if FuncLoadError then
      AFailed.Add('PBMAC1_get1_pbkdf2_param');
    {$ifend}
  end;
  
  PKCS8_PRIV_KEY_INFO_new := LoadLibFunction(ADllHandle, PKCS8_PRIV_KEY_INFO_new_procname);
  FuncLoadError := not assigned(PKCS8_PRIV_KEY_INFO_new);
  if FuncLoadError then
  begin
    {$if not defined(PKCS8_PRIV_KEY_INFO_new_allownil)}
    PKCS8_PRIV_KEY_INFO_new := ERR_PKCS8_PRIV_KEY_INFO_new;
    {$ifend}
    {$if declared(PKCS8_PRIV_KEY_INFO_new_introduced)}
    if LibVersion < PKCS8_PRIV_KEY_INFO_new_introduced then
    begin
      {$if declared(FC_PKCS8_PRIV_KEY_INFO_new)}
      PKCS8_PRIV_KEY_INFO_new := FC_PKCS8_PRIV_KEY_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS8_PRIV_KEY_INFO_new_removed)}
    if PKCS8_PRIV_KEY_INFO_new_removed <= LibVersion then
    begin
      {$if declared(_PKCS8_PRIV_KEY_INFO_new)}
      PKCS8_PRIV_KEY_INFO_new := _PKCS8_PRIV_KEY_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS8_PRIV_KEY_INFO_new_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS8_PRIV_KEY_INFO_new');
    {$ifend}
  end;
  
  PKCS8_PRIV_KEY_INFO_free := LoadLibFunction(ADllHandle, PKCS8_PRIV_KEY_INFO_free_procname);
  FuncLoadError := not assigned(PKCS8_PRIV_KEY_INFO_free);
  if FuncLoadError then
  begin
    {$if not defined(PKCS8_PRIV_KEY_INFO_free_allownil)}
    PKCS8_PRIV_KEY_INFO_free := ERR_PKCS8_PRIV_KEY_INFO_free;
    {$ifend}
    {$if declared(PKCS8_PRIV_KEY_INFO_free_introduced)}
    if LibVersion < PKCS8_PRIV_KEY_INFO_free_introduced then
    begin
      {$if declared(FC_PKCS8_PRIV_KEY_INFO_free)}
      PKCS8_PRIV_KEY_INFO_free := FC_PKCS8_PRIV_KEY_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS8_PRIV_KEY_INFO_free_removed)}
    if PKCS8_PRIV_KEY_INFO_free_removed <= LibVersion then
    begin
      {$if declared(_PKCS8_PRIV_KEY_INFO_free)}
      PKCS8_PRIV_KEY_INFO_free := _PKCS8_PRIV_KEY_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS8_PRIV_KEY_INFO_free_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS8_PRIV_KEY_INFO_free');
    {$ifend}
  end;
  
  d2i_PKCS8_PRIV_KEY_INFO := LoadLibFunction(ADllHandle, d2i_PKCS8_PRIV_KEY_INFO_procname);
  FuncLoadError := not assigned(d2i_PKCS8_PRIV_KEY_INFO);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS8_PRIV_KEY_INFO_allownil)}
    d2i_PKCS8_PRIV_KEY_INFO := ERR_d2i_PKCS8_PRIV_KEY_INFO;
    {$ifend}
    {$if declared(d2i_PKCS8_PRIV_KEY_INFO_introduced)}
    if LibVersion < d2i_PKCS8_PRIV_KEY_INFO_introduced then
    begin
      {$if declared(FC_d2i_PKCS8_PRIV_KEY_INFO)}
      d2i_PKCS8_PRIV_KEY_INFO := FC_d2i_PKCS8_PRIV_KEY_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS8_PRIV_KEY_INFO_removed)}
    if d2i_PKCS8_PRIV_KEY_INFO_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS8_PRIV_KEY_INFO)}
      d2i_PKCS8_PRIV_KEY_INFO := _d2i_PKCS8_PRIV_KEY_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS8_PRIV_KEY_INFO_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS8_PRIV_KEY_INFO');
    {$ifend}
  end;
  
  i2d_PKCS8_PRIV_KEY_INFO := LoadLibFunction(ADllHandle, i2d_PKCS8_PRIV_KEY_INFO_procname);
  FuncLoadError := not assigned(i2d_PKCS8_PRIV_KEY_INFO);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS8_PRIV_KEY_INFO_allownil)}
    i2d_PKCS8_PRIV_KEY_INFO := ERR_i2d_PKCS8_PRIV_KEY_INFO;
    {$ifend}
    {$if declared(i2d_PKCS8_PRIV_KEY_INFO_introduced)}
    if LibVersion < i2d_PKCS8_PRIV_KEY_INFO_introduced then
    begin
      {$if declared(FC_i2d_PKCS8_PRIV_KEY_INFO)}
      i2d_PKCS8_PRIV_KEY_INFO := FC_i2d_PKCS8_PRIV_KEY_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS8_PRIV_KEY_INFO_removed)}
    if i2d_PKCS8_PRIV_KEY_INFO_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS8_PRIV_KEY_INFO)}
      i2d_PKCS8_PRIV_KEY_INFO := _i2d_PKCS8_PRIV_KEY_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS8_PRIV_KEY_INFO_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS8_PRIV_KEY_INFO');
    {$ifend}
  end;
  
  PKCS8_PRIV_KEY_INFO_it := LoadLibFunction(ADllHandle, PKCS8_PRIV_KEY_INFO_it_procname);
  FuncLoadError := not assigned(PKCS8_PRIV_KEY_INFO_it);
  if FuncLoadError then
  begin
    {$if not defined(PKCS8_PRIV_KEY_INFO_it_allownil)}
    PKCS8_PRIV_KEY_INFO_it := ERR_PKCS8_PRIV_KEY_INFO_it;
    {$ifend}
    {$if declared(PKCS8_PRIV_KEY_INFO_it_introduced)}
    if LibVersion < PKCS8_PRIV_KEY_INFO_it_introduced then
    begin
      {$if declared(FC_PKCS8_PRIV_KEY_INFO_it)}
      PKCS8_PRIV_KEY_INFO_it := FC_PKCS8_PRIV_KEY_INFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS8_PRIV_KEY_INFO_it_removed)}
    if PKCS8_PRIV_KEY_INFO_it_removed <= LibVersion then
    begin
      {$if declared(_PKCS8_PRIV_KEY_INFO_it)}
      PKCS8_PRIV_KEY_INFO_it := _PKCS8_PRIV_KEY_INFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS8_PRIV_KEY_INFO_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS8_PRIV_KEY_INFO_it');
    {$ifend}
  end;
  
  EVP_PKCS82PKEY := LoadLibFunction(ADllHandle, EVP_PKCS82PKEY_procname);
  FuncLoadError := not assigned(EVP_PKCS82PKEY);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKCS82PKEY_allownil)}
    EVP_PKCS82PKEY := ERR_EVP_PKCS82PKEY;
    {$ifend}
    {$if declared(EVP_PKCS82PKEY_introduced)}
    if LibVersion < EVP_PKCS82PKEY_introduced then
    begin
      {$if declared(FC_EVP_PKCS82PKEY)}
      EVP_PKCS82PKEY := FC_EVP_PKCS82PKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKCS82PKEY_removed)}
    if EVP_PKCS82PKEY_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKCS82PKEY)}
      EVP_PKCS82PKEY := _EVP_PKCS82PKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKCS82PKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKCS82PKEY');
    {$ifend}
  end;
  
  EVP_PKCS82PKEY_ex := LoadLibFunction(ADllHandle, EVP_PKCS82PKEY_ex_procname);
  FuncLoadError := not assigned(EVP_PKCS82PKEY_ex);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKCS82PKEY_ex_allownil)}
    EVP_PKCS82PKEY_ex := ERR_EVP_PKCS82PKEY_ex;
    {$ifend}
    {$if declared(EVP_PKCS82PKEY_ex_introduced)}
    if LibVersion < EVP_PKCS82PKEY_ex_introduced then
    begin
      {$if declared(FC_EVP_PKCS82PKEY_ex)}
      EVP_PKCS82PKEY_ex := FC_EVP_PKCS82PKEY_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKCS82PKEY_ex_removed)}
    if EVP_PKCS82PKEY_ex_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKCS82PKEY_ex)}
      EVP_PKCS82PKEY_ex := _EVP_PKCS82PKEY_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKCS82PKEY_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKCS82PKEY_ex');
    {$ifend}
  end;
  
  EVP_PKEY2PKCS8 := LoadLibFunction(ADllHandle, EVP_PKEY2PKCS8_procname);
  FuncLoadError := not assigned(EVP_PKEY2PKCS8);
  if FuncLoadError then
  begin
    {$if not defined(EVP_PKEY2PKCS8_allownil)}
    EVP_PKEY2PKCS8 := ERR_EVP_PKEY2PKCS8;
    {$ifend}
    {$if declared(EVP_PKEY2PKCS8_introduced)}
    if LibVersion < EVP_PKEY2PKCS8_introduced then
    begin
      {$if declared(FC_EVP_PKEY2PKCS8)}
      EVP_PKEY2PKCS8 := FC_EVP_PKEY2PKCS8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(EVP_PKEY2PKCS8_removed)}
    if EVP_PKEY2PKCS8_removed <= LibVersion then
    begin
      {$if declared(_EVP_PKEY2PKCS8)}
      EVP_PKEY2PKCS8 := _EVP_PKEY2PKCS8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(EVP_PKEY2PKCS8_allownil)}
    if FuncLoadError then
      AFailed.Add('EVP_PKEY2PKCS8');
    {$ifend}
  end;
  
  PKCS8_pkey_set0 := LoadLibFunction(ADllHandle, PKCS8_pkey_set0_procname);
  FuncLoadError := not assigned(PKCS8_pkey_set0);
  if FuncLoadError then
  begin
    {$if not defined(PKCS8_pkey_set0_allownil)}
    PKCS8_pkey_set0 := ERR_PKCS8_pkey_set0;
    {$ifend}
    {$if declared(PKCS8_pkey_set0_introduced)}
    if LibVersion < PKCS8_pkey_set0_introduced then
    begin
      {$if declared(FC_PKCS8_pkey_set0)}
      PKCS8_pkey_set0 := FC_PKCS8_pkey_set0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS8_pkey_set0_removed)}
    if PKCS8_pkey_set0_removed <= LibVersion then
    begin
      {$if declared(_PKCS8_pkey_set0)}
      PKCS8_pkey_set0 := _PKCS8_pkey_set0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS8_pkey_set0_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS8_pkey_set0');
    {$ifend}
  end;
  
  PKCS8_pkey_get0 := LoadLibFunction(ADllHandle, PKCS8_pkey_get0_procname);
  FuncLoadError := not assigned(PKCS8_pkey_get0);
  if FuncLoadError then
  begin
    {$if not defined(PKCS8_pkey_get0_allownil)}
    PKCS8_pkey_get0 := ERR_PKCS8_pkey_get0;
    {$ifend}
    {$if declared(PKCS8_pkey_get0_introduced)}
    if LibVersion < PKCS8_pkey_get0_introduced then
    begin
      {$if declared(FC_PKCS8_pkey_get0)}
      PKCS8_pkey_get0 := FC_PKCS8_pkey_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS8_pkey_get0_removed)}
    if PKCS8_pkey_get0_removed <= LibVersion then
    begin
      {$if declared(_PKCS8_pkey_get0)}
      PKCS8_pkey_get0 := _PKCS8_pkey_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS8_pkey_get0_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS8_pkey_get0');
    {$ifend}
  end;
  
  PKCS8_pkey_get0_attrs := LoadLibFunction(ADllHandle, PKCS8_pkey_get0_attrs_procname);
  FuncLoadError := not assigned(PKCS8_pkey_get0_attrs);
  if FuncLoadError then
  begin
    {$if not defined(PKCS8_pkey_get0_attrs_allownil)}
    PKCS8_pkey_get0_attrs := ERR_PKCS8_pkey_get0_attrs;
    {$ifend}
    {$if declared(PKCS8_pkey_get0_attrs_introduced)}
    if LibVersion < PKCS8_pkey_get0_attrs_introduced then
    begin
      {$if declared(FC_PKCS8_pkey_get0_attrs)}
      PKCS8_pkey_get0_attrs := FC_PKCS8_pkey_get0_attrs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS8_pkey_get0_attrs_removed)}
    if PKCS8_pkey_get0_attrs_removed <= LibVersion then
    begin
      {$if declared(_PKCS8_pkey_get0_attrs)}
      PKCS8_pkey_get0_attrs := _PKCS8_pkey_get0_attrs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS8_pkey_get0_attrs_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS8_pkey_get0_attrs');
    {$ifend}
  end;
  
  PKCS8_pkey_add1_attr := LoadLibFunction(ADllHandle, PKCS8_pkey_add1_attr_procname);
  FuncLoadError := not assigned(PKCS8_pkey_add1_attr);
  if FuncLoadError then
  begin
    {$if not defined(PKCS8_pkey_add1_attr_allownil)}
    PKCS8_pkey_add1_attr := ERR_PKCS8_pkey_add1_attr;
    {$ifend}
    {$if declared(PKCS8_pkey_add1_attr_introduced)}
    if LibVersion < PKCS8_pkey_add1_attr_introduced then
    begin
      {$if declared(FC_PKCS8_pkey_add1_attr)}
      PKCS8_pkey_add1_attr := FC_PKCS8_pkey_add1_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS8_pkey_add1_attr_removed)}
    if PKCS8_pkey_add1_attr_removed <= LibVersion then
    begin
      {$if declared(_PKCS8_pkey_add1_attr)}
      PKCS8_pkey_add1_attr := _PKCS8_pkey_add1_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS8_pkey_add1_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS8_pkey_add1_attr');
    {$ifend}
  end;
  
  PKCS8_pkey_add1_attr_by_NID := LoadLibFunction(ADllHandle, PKCS8_pkey_add1_attr_by_NID_procname);
  FuncLoadError := not assigned(PKCS8_pkey_add1_attr_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(PKCS8_pkey_add1_attr_by_NID_allownil)}
    PKCS8_pkey_add1_attr_by_NID := ERR_PKCS8_pkey_add1_attr_by_NID;
    {$ifend}
    {$if declared(PKCS8_pkey_add1_attr_by_NID_introduced)}
    if LibVersion < PKCS8_pkey_add1_attr_by_NID_introduced then
    begin
      {$if declared(FC_PKCS8_pkey_add1_attr_by_NID)}
      PKCS8_pkey_add1_attr_by_NID := FC_PKCS8_pkey_add1_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS8_pkey_add1_attr_by_NID_removed)}
    if PKCS8_pkey_add1_attr_by_NID_removed <= LibVersion then
    begin
      {$if declared(_PKCS8_pkey_add1_attr_by_NID)}
      PKCS8_pkey_add1_attr_by_NID := _PKCS8_pkey_add1_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS8_pkey_add1_attr_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS8_pkey_add1_attr_by_NID');
    {$ifend}
  end;
  
  PKCS8_pkey_add1_attr_by_OBJ := LoadLibFunction(ADllHandle, PKCS8_pkey_add1_attr_by_OBJ_procname);
  FuncLoadError := not assigned(PKCS8_pkey_add1_attr_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(PKCS8_pkey_add1_attr_by_OBJ_allownil)}
    PKCS8_pkey_add1_attr_by_OBJ := ERR_PKCS8_pkey_add1_attr_by_OBJ;
    {$ifend}
    {$if declared(PKCS8_pkey_add1_attr_by_OBJ_introduced)}
    if LibVersion < PKCS8_pkey_add1_attr_by_OBJ_introduced then
    begin
      {$if declared(FC_PKCS8_pkey_add1_attr_by_OBJ)}
      PKCS8_pkey_add1_attr_by_OBJ := FC_PKCS8_pkey_add1_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS8_pkey_add1_attr_by_OBJ_removed)}
    if PKCS8_pkey_add1_attr_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_PKCS8_pkey_add1_attr_by_OBJ)}
      PKCS8_pkey_add1_attr_by_OBJ := _PKCS8_pkey_add1_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS8_pkey_add1_attr_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS8_pkey_add1_attr_by_OBJ');
    {$ifend}
  end;
  
  X509_PUBKEY_set0_public_key := LoadLibFunction(ADllHandle, X509_PUBKEY_set0_public_key_procname);
  FuncLoadError := not assigned(X509_PUBKEY_set0_public_key);
  if FuncLoadError then
  begin
    {$if not defined(X509_PUBKEY_set0_public_key_allownil)}
    X509_PUBKEY_set0_public_key := ERR_X509_PUBKEY_set0_public_key;
    {$ifend}
    {$if declared(X509_PUBKEY_set0_public_key_introduced)}
    if LibVersion < X509_PUBKEY_set0_public_key_introduced then
    begin
      {$if declared(FC_X509_PUBKEY_set0_public_key)}
      X509_PUBKEY_set0_public_key := FC_X509_PUBKEY_set0_public_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PUBKEY_set0_public_key_removed)}
    if X509_PUBKEY_set0_public_key_removed <= LibVersion then
    begin
      {$if declared(_X509_PUBKEY_set0_public_key)}
      X509_PUBKEY_set0_public_key := _X509_PUBKEY_set0_public_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PUBKEY_set0_public_key_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PUBKEY_set0_public_key');
    {$ifend}
  end;
  
  X509_PUBKEY_set0_param := LoadLibFunction(ADllHandle, X509_PUBKEY_set0_param_procname);
  FuncLoadError := not assigned(X509_PUBKEY_set0_param);
  if FuncLoadError then
  begin
    {$if not defined(X509_PUBKEY_set0_param_allownil)}
    X509_PUBKEY_set0_param := ERR_X509_PUBKEY_set0_param;
    {$ifend}
    {$if declared(X509_PUBKEY_set0_param_introduced)}
    if LibVersion < X509_PUBKEY_set0_param_introduced then
    begin
      {$if declared(FC_X509_PUBKEY_set0_param)}
      X509_PUBKEY_set0_param := FC_X509_PUBKEY_set0_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PUBKEY_set0_param_removed)}
    if X509_PUBKEY_set0_param_removed <= LibVersion then
    begin
      {$if declared(_X509_PUBKEY_set0_param)}
      X509_PUBKEY_set0_param := _X509_PUBKEY_set0_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PUBKEY_set0_param_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PUBKEY_set0_param');
    {$ifend}
  end;
  
  X509_PUBKEY_get0_param := LoadLibFunction(ADllHandle, X509_PUBKEY_get0_param_procname);
  FuncLoadError := not assigned(X509_PUBKEY_get0_param);
  if FuncLoadError then
  begin
    {$if not defined(X509_PUBKEY_get0_param_allownil)}
    X509_PUBKEY_get0_param := ERR_X509_PUBKEY_get0_param;
    {$ifend}
    {$if declared(X509_PUBKEY_get0_param_introduced)}
    if LibVersion < X509_PUBKEY_get0_param_introduced then
    begin
      {$if declared(FC_X509_PUBKEY_get0_param)}
      X509_PUBKEY_get0_param := FC_X509_PUBKEY_get0_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PUBKEY_get0_param_removed)}
    if X509_PUBKEY_get0_param_removed <= LibVersion then
    begin
      {$if declared(_X509_PUBKEY_get0_param)}
      X509_PUBKEY_get0_param := _X509_PUBKEY_get0_param;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PUBKEY_get0_param_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PUBKEY_get0_param');
    {$ifend}
  end;
  
  X509_PUBKEY_eq := LoadLibFunction(ADllHandle, X509_PUBKEY_eq_procname);
  FuncLoadError := not assigned(X509_PUBKEY_eq);
  if FuncLoadError then
  begin
    {$if not defined(X509_PUBKEY_eq_allownil)}
    X509_PUBKEY_eq := ERR_X509_PUBKEY_eq;
    {$ifend}
    {$if declared(X509_PUBKEY_eq_introduced)}
    if LibVersion < X509_PUBKEY_eq_introduced then
    begin
      {$if declared(FC_X509_PUBKEY_eq)}
      X509_PUBKEY_eq := FC_X509_PUBKEY_eq;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PUBKEY_eq_removed)}
    if X509_PUBKEY_eq_removed <= LibVersion then
    begin
      {$if declared(_X509_PUBKEY_eq)}
      X509_PUBKEY_eq := _X509_PUBKEY_eq;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PUBKEY_eq_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PUBKEY_eq');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  X509_CRL_set_default_method := nil;
  X509_CRL_METHOD_new := nil;
  X509_CRL_METHOD_free := nil;
  X509_CRL_set_meth_data := nil;
  X509_CRL_get_meth_data := nil;
  X509_verify_cert_error_string := nil;
  X509_verify := nil;
  X509_self_signed := nil;
  X509_REQ_verify_ex := nil;
  X509_REQ_verify := nil;
  X509_CRL_verify := nil;
  NETSCAPE_SPKI_verify := nil;
  NETSCAPE_SPKI_b64_decode := nil;
  NETSCAPE_SPKI_b64_encode := nil;
  NETSCAPE_SPKI_get_pubkey := nil;
  NETSCAPE_SPKI_set_pubkey := nil;
  NETSCAPE_SPKI_print := nil;
  X509_signature_dump := nil;
  X509_signature_print := nil;
  X509_sign := nil;
  X509_sign_ctx := nil;
  X509_REQ_sign := nil;
  X509_REQ_sign_ctx := nil;
  X509_CRL_sign := nil;
  X509_CRL_sign_ctx := nil;
  NETSCAPE_SPKI_sign := nil;
  X509_pubkey_digest := nil;
  X509_digest := nil;
  X509_digest_sig := nil;
  X509_CRL_digest := nil;
  X509_REQ_digest := nil;
  X509_NAME_digest := nil;
  X509_load_http := nil;
  X509_CRL_load_http := nil;
  d2i_X509_fp := nil;
  i2d_X509_fp := nil;
  d2i_X509_CRL_fp := nil;
  i2d_X509_CRL_fp := nil;
  d2i_X509_REQ_fp := nil;
  i2d_X509_REQ_fp := nil;
  d2i_RSAPrivateKey_fp := nil;
  i2d_RSAPrivateKey_fp := nil;
  d2i_RSAPublicKey_fp := nil;
  i2d_RSAPublicKey_fp := nil;
  d2i_RSA_PUBKEY_fp := nil;
  i2d_RSA_PUBKEY_fp := nil;
  d2i_DSA_PUBKEY_fp := nil;
  i2d_DSA_PUBKEY_fp := nil;
  d2i_DSAPrivateKey_fp := nil;
  i2d_DSAPrivateKey_fp := nil;
  d2i_EC_PUBKEY_fp := nil;
  i2d_EC_PUBKEY_fp := nil;
  d2i_ECPrivateKey_fp := nil;
  i2d_ECPrivateKey_fp := nil;
  d2i_PKCS8_fp := nil;
  i2d_PKCS8_fp := nil;
  d2i_X509_PUBKEY_fp := nil;
  i2d_X509_PUBKEY_fp := nil;
  d2i_PKCS8_PRIV_KEY_INFO_fp := nil;
  i2d_PKCS8_PRIV_KEY_INFO_fp := nil;
  i2d_PKCS8PrivateKeyInfo_fp := nil;
  i2d_PrivateKey_fp := nil;
  d2i_PrivateKey_ex_fp := nil;
  d2i_PrivateKey_fp := nil;
  i2d_PUBKEY_fp := nil;
  d2i_PUBKEY_ex_fp := nil;
  d2i_PUBKEY_fp := nil;
  d2i_X509_bio := nil;
  i2d_X509_bio := nil;
  d2i_X509_CRL_bio := nil;
  i2d_X509_CRL_bio := nil;
  d2i_X509_REQ_bio := nil;
  i2d_X509_REQ_bio := nil;
  d2i_RSAPrivateKey_bio := nil;
  i2d_RSAPrivateKey_bio := nil;
  d2i_RSAPublicKey_bio := nil;
  i2d_RSAPublicKey_bio := nil;
  d2i_RSA_PUBKEY_bio := nil;
  i2d_RSA_PUBKEY_bio := nil;
  d2i_DSA_PUBKEY_bio := nil;
  i2d_DSA_PUBKEY_bio := nil;
  d2i_DSAPrivateKey_bio := nil;
  i2d_DSAPrivateKey_bio := nil;
  d2i_EC_PUBKEY_bio := nil;
  i2d_EC_PUBKEY_bio := nil;
  d2i_ECPrivateKey_bio := nil;
  i2d_ECPrivateKey_bio := nil;
  d2i_PKCS8_bio := nil;
  i2d_PKCS8_bio := nil;
  d2i_X509_PUBKEY_bio := nil;
  i2d_X509_PUBKEY_bio := nil;
  d2i_PKCS8_PRIV_KEY_INFO_bio := nil;
  i2d_PKCS8_PRIV_KEY_INFO_bio := nil;
  i2d_PKCS8PrivateKeyInfo_bio := nil;
  i2d_PrivateKey_bio := nil;
  d2i_PrivateKey_ex_bio := nil;
  d2i_PrivateKey_bio := nil;
  i2d_PUBKEY_bio := nil;
  d2i_PUBKEY_ex_bio := nil;
  d2i_PUBKEY_bio := nil;
  X509_dup := nil;
  X509_ALGOR_dup := nil;
  X509_ATTRIBUTE_dup := nil;
  X509_CRL_dup := nil;
  X509_EXTENSION_dup := nil;
  X509_PUBKEY_dup := nil;
  X509_REQ_dup := nil;
  X509_REVOKED_dup := nil;
  X509_ALGOR_set0 := nil;
  X509_ALGOR_get0 := nil;
  X509_ALGOR_set_md := nil;
  X509_ALGOR_cmp := nil;
  X509_ALGOR_copy := nil;
  X509_NAME_dup := nil;
  X509_NAME_ENTRY_dup := nil;
  X509_cmp_time := nil;
  X509_cmp_current_time := nil;
  X509_cmp_timeframe := nil;
  X509_time_adj := nil;
  X509_time_adj_ex := nil;
  X509_gmtime_adj := nil;
  X509_get_default_cert_area := nil;
  X509_get_default_cert_dir := nil;
  X509_get_default_cert_file := nil;
  X509_get_default_cert_dir_env := nil;
  X509_get_default_cert_file_env := nil;
  X509_get_default_private_dir := nil;
  X509_to_X509_REQ := nil;
  X509_REQ_to_X509 := nil;
  X509_ALGOR_new := nil;
  X509_ALGOR_free := nil;
  d2i_X509_ALGOR := nil;
  i2d_X509_ALGOR := nil;
  X509_ALGOR_it := nil;
  d2i_X509_ALGORS := nil;
  i2d_X509_ALGORS := nil;
  X509_ALGORS_it := nil;
  X509_VAL_new := nil;
  X509_VAL_free := nil;
  d2i_X509_VAL := nil;
  i2d_X509_VAL := nil;
  X509_VAL_it := nil;
  X509_PUBKEY_new := nil;
  X509_PUBKEY_free := nil;
  d2i_X509_PUBKEY := nil;
  i2d_X509_PUBKEY := nil;
  X509_PUBKEY_it := nil;
  X509_PUBKEY_new_ex := nil;
  X509_PUBKEY_set := nil;
  X509_PUBKEY_get0 := nil;
  X509_PUBKEY_get := nil;
  X509_get_pubkey_parameters := nil;
  X509_get_pathlen := nil;
  d2i_PUBKEY := nil;
  i2d_PUBKEY := nil;
  d2i_PUBKEY_ex := nil;
  d2i_RSA_PUBKEY := nil;
  i2d_RSA_PUBKEY := nil;
  d2i_DSA_PUBKEY := nil;
  i2d_DSA_PUBKEY := nil;
  d2i_EC_PUBKEY := nil;
  i2d_EC_PUBKEY := nil;
  X509_SIG_new := nil;
  X509_SIG_free := nil;
  d2i_X509_SIG := nil;
  i2d_X509_SIG := nil;
  X509_SIG_it := nil;
  X509_SIG_get0 := nil;
  X509_SIG_getm := nil;
  X509_REQ_INFO_new := nil;
  X509_REQ_INFO_free := nil;
  d2i_X509_REQ_INFO := nil;
  i2d_X509_REQ_INFO := nil;
  X509_REQ_INFO_it := nil;
  X509_REQ_new := nil;
  X509_REQ_free := nil;
  d2i_X509_REQ := nil;
  i2d_X509_REQ := nil;
  X509_REQ_it := nil;
  X509_REQ_new_ex := nil;
  X509_ATTRIBUTE_new := nil;
  X509_ATTRIBUTE_free := nil;
  d2i_X509_ATTRIBUTE := nil;
  i2d_X509_ATTRIBUTE := nil;
  X509_ATTRIBUTE_it := nil;
  X509_ATTRIBUTE_create := nil;
  X509_EXTENSION_new := nil;
  X509_EXTENSION_free := nil;
  d2i_X509_EXTENSION := nil;
  i2d_X509_EXTENSION := nil;
  X509_EXTENSION_it := nil;
  d2i_X509_EXTENSIONS := nil;
  i2d_X509_EXTENSIONS := nil;
  X509_EXTENSIONS_it := nil;
  X509_NAME_ENTRY_new := nil;
  X509_NAME_ENTRY_free := nil;
  d2i_X509_NAME_ENTRY := nil;
  i2d_X509_NAME_ENTRY := nil;
  X509_NAME_ENTRY_it := nil;
  X509_NAME_new := nil;
  X509_NAME_free := nil;
  d2i_X509_NAME := nil;
  i2d_X509_NAME := nil;
  X509_NAME_it := nil;
  X509_NAME_set := nil;
  X509_CINF_new := nil;
  X509_CINF_free := nil;
  d2i_X509_CINF := nil;
  i2d_X509_CINF := nil;
  X509_CINF_it := nil;
  X509_new := nil;
  X509_free := nil;
  d2i_X509 := nil;
  i2d_X509 := nil;
  X509_it := nil;
  X509_new_ex := nil;
  X509_CERT_AUX_new := nil;
  X509_CERT_AUX_free := nil;
  d2i_X509_CERT_AUX := nil;
  i2d_X509_CERT_AUX := nil;
  X509_CERT_AUX_it := nil;
  X509_set_ex_data := nil;
  X509_get_ex_data := nil;
  d2i_X509_AUX := nil;
  i2d_X509_AUX := nil;
  i2d_re_X509_tbs := nil;
  X509_SIG_INFO_get := nil;
  X509_SIG_INFO_set := nil;
  X509_get_signature_info := nil;
  X509_get0_signature := nil;
  X509_get_signature_nid := nil;
  X509_set0_distinguishing_id := nil;
  X509_get0_distinguishing_id := nil;
  X509_REQ_set0_distinguishing_id := nil;
  X509_REQ_get0_distinguishing_id := nil;
  X509_alias_set1 := nil;
  X509_keyid_set1 := nil;
  X509_alias_get0 := nil;
  X509_keyid_get0 := nil;
  X509_REVOKED_new := nil;
  X509_REVOKED_free := nil;
  d2i_X509_REVOKED := nil;
  i2d_X509_REVOKED := nil;
  X509_REVOKED_it := nil;
  X509_CRL_INFO_new := nil;
  X509_CRL_INFO_free := nil;
  d2i_X509_CRL_INFO := nil;
  i2d_X509_CRL_INFO := nil;
  X509_CRL_INFO_it := nil;
  X509_CRL_new := nil;
  X509_CRL_free := nil;
  d2i_X509_CRL := nil;
  i2d_X509_CRL := nil;
  X509_CRL_it := nil;
  X509_CRL_new_ex := nil;
  X509_CRL_add0_revoked := nil;
  X509_CRL_get0_by_serial := nil;
  X509_CRL_get0_by_cert := nil;
  X509_PKEY_new := nil;
  X509_PKEY_free := nil;
  NETSCAPE_SPKI_new := nil;
  NETSCAPE_SPKI_free := nil;
  d2i_NETSCAPE_SPKI := nil;
  i2d_NETSCAPE_SPKI := nil;
  NETSCAPE_SPKI_it := nil;
  NETSCAPE_SPKAC_new := nil;
  NETSCAPE_SPKAC_free := nil;
  d2i_NETSCAPE_SPKAC := nil;
  i2d_NETSCAPE_SPKAC := nil;
  NETSCAPE_SPKAC_it := nil;
  NETSCAPE_CERT_SEQUENCE_new := nil;
  NETSCAPE_CERT_SEQUENCE_free := nil;
  d2i_NETSCAPE_CERT_SEQUENCE := nil;
  i2d_NETSCAPE_CERT_SEQUENCE := nil;
  NETSCAPE_CERT_SEQUENCE_it := nil;
  X509_INFO_new := nil;
  X509_INFO_free := nil;
  X509_NAME_oneline := nil;
  ASN1_verify := nil;
  ASN1_digest := nil;
  ASN1_sign := nil;
  ASN1_item_digest := nil;
  ASN1_item_verify := nil;
  ASN1_item_verify_ctx := nil;
  ASN1_item_sign := nil;
  ASN1_item_sign_ctx := nil;
  X509_get_version := nil;
  X509_set_version := nil;
  X509_set_serialNumber := nil;
  X509_get_serialNumber := nil;
  X509_get0_serialNumber := nil;
  X509_set_issuer_name := nil;
  X509_get_issuer_name := nil;
  X509_set_subject_name := nil;
  X509_get_subject_name := nil;
  X509_get0_notBefore := nil;
  X509_getm_notBefore := nil;
  X509_set1_notBefore := nil;
  X509_get0_notAfter := nil;
  X509_getm_notAfter := nil;
  X509_set1_notAfter := nil;
  X509_set_pubkey := nil;
  X509_up_ref := nil;
  X509_get_signature_type := nil;
  X509_get_X509_PUBKEY := nil;
  X509_get0_extensions := nil;
  X509_get0_uids := nil;
  X509_get0_tbs_sigalg := nil;
  X509_get0_pubkey := nil;
  X509_get_pubkey := nil;
  X509_get0_pubkey_bitstr := nil;
  X509_REQ_get_version := nil;
  X509_REQ_set_version := nil;
  X509_REQ_get_subject_name := nil;
  X509_REQ_set_subject_name := nil;
  X509_REQ_get0_signature := nil;
  X509_REQ_set0_signature := nil;
  X509_REQ_set1_signature_algo := nil;
  X509_REQ_get_signature_nid := nil;
  i2d_re_X509_REQ_tbs := nil;
  X509_REQ_set_pubkey := nil;
  X509_REQ_get_pubkey := nil;
  X509_REQ_get0_pubkey := nil;
  X509_REQ_get_X509_PUBKEY := nil;
  X509_REQ_extension_nid := nil;
  X509_REQ_get_extension_nids := nil;
  X509_REQ_set_extension_nids := nil;
  X509_REQ_get_extensions := nil;
  X509_REQ_add_extensions_nid := nil;
  X509_REQ_add_extensions := nil;
  X509_REQ_get_attr_count := nil;
  X509_REQ_get_attr_by_NID := nil;
  X509_REQ_get_attr_by_OBJ := nil;
  X509_REQ_get_attr := nil;
  X509_REQ_delete_attr := nil;
  X509_REQ_add1_attr := nil;
  X509_REQ_add1_attr_by_OBJ := nil;
  X509_REQ_add1_attr_by_NID := nil;
  X509_REQ_add1_attr_by_txt := nil;
  X509_CRL_set_version := nil;
  X509_CRL_set_issuer_name := nil;
  X509_CRL_set1_lastUpdate := nil;
  X509_CRL_set1_nextUpdate := nil;
  X509_CRL_sort := nil;
  X509_CRL_up_ref := nil;
  X509_CRL_get_version := nil;
  X509_CRL_get0_lastUpdate := nil;
  X509_CRL_get0_nextUpdate := nil;
  X509_CRL_get_issuer := nil;
  X509_CRL_get0_extensions := nil;
  X509_CRL_get_REVOKED := nil;
  X509_CRL_get0_tbs_sigalg := nil;
  X509_CRL_get0_signature := nil;
  X509_CRL_get_signature_nid := nil;
  i2d_re_X509_CRL_tbs := nil;
  X509_REVOKED_get0_serialNumber := nil;
  X509_REVOKED_set_serialNumber := nil;
  X509_REVOKED_get0_revocationDate := nil;
  X509_REVOKED_set_revocationDate := nil;
  X509_REVOKED_get0_extensions := nil;
  X509_CRL_diff := nil;
  X509_REQ_check_private_key := nil;
  X509_check_private_key := nil;
  X509_chain_check_suiteb := nil;
  X509_CRL_check_suiteb := nil;
  OSSL_STACK_OF_X509_free := nil;
  X509_chain_up_ref := nil;
  X509_issuer_and_serial_cmp := nil;
  X509_issuer_and_serial_hash := nil;
  X509_issuer_name_cmp := nil;
  X509_issuer_name_hash := nil;
  X509_subject_name_cmp := nil;
  X509_subject_name_hash := nil;
  X509_issuer_name_hash_old := nil;
  X509_subject_name_hash_old := nil;
  X509_add_cert := nil;
  X509_add_certs := nil;
  X509_cmp := nil;
  X509_NAME_cmp := nil;
  X509_certificate_type := nil;
  X509_NAME_hash_ex := nil;
  X509_NAME_hash_old := nil;
  X509_CRL_cmp := nil;
  X509_CRL_match := nil;
  X509_aux_print := nil;
  X509_print_ex_fp := nil;
  X509_print_fp := nil;
  X509_CRL_print_fp := nil;
  X509_REQ_print_fp := nil;
  X509_NAME_print_ex_fp := nil;
  X509_NAME_print := nil;
  X509_NAME_print_ex := nil;
  X509_print_ex := nil;
  X509_print := nil;
  X509_ocspid_print := nil;
  X509_CRL_print_ex := nil;
  X509_CRL_print := nil;
  X509_REQ_print_ex := nil;
  X509_REQ_print := nil;
  X509_NAME_entry_count := nil;
  X509_NAME_get_text_by_NID := nil;
  X509_NAME_get_text_by_OBJ := nil;
  X509_NAME_get_index_by_NID := nil;
  X509_NAME_get_index_by_OBJ := nil;
  X509_NAME_get_entry := nil;
  X509_NAME_delete_entry := nil;
  X509_NAME_add_entry := nil;
  X509_NAME_add_entry_by_OBJ := nil;
  X509_NAME_add_entry_by_NID := nil;
  X509_NAME_ENTRY_create_by_txt := nil;
  X509_NAME_ENTRY_create_by_NID := nil;
  X509_NAME_add_entry_by_txt := nil;
  X509_NAME_ENTRY_create_by_OBJ := nil;
  X509_NAME_ENTRY_set_object := nil;
  X509_NAME_ENTRY_set_data := nil;
  X509_NAME_ENTRY_get_object := nil;
  X509_NAME_ENTRY_get_data := nil;
  X509_NAME_ENTRY_set := nil;
  X509_NAME_get0_der := nil;
  X509v3_get_ext_count := nil;
  X509v3_get_ext_by_NID := nil;
  X509v3_get_ext_by_OBJ := nil;
  X509v3_get_ext_by_critical := nil;
  X509v3_get_ext := nil;
  X509v3_delete_ext := nil;
  X509v3_add_ext := nil;
  X509v3_add_extensions := nil;
  X509_get_ext_count := nil;
  X509_get_ext_by_NID := nil;
  X509_get_ext_by_OBJ := nil;
  X509_get_ext_by_critical := nil;
  X509_get_ext := nil;
  X509_delete_ext := nil;
  X509_add_ext := nil;
  X509_get_ext_d2i := nil;
  X509_add1_ext_i2d := nil;
  X509_CRL_get_ext_count := nil;
  X509_CRL_get_ext_by_NID := nil;
  X509_CRL_get_ext_by_OBJ := nil;
  X509_CRL_get_ext_by_critical := nil;
  X509_CRL_get_ext := nil;
  X509_CRL_delete_ext := nil;
  X509_CRL_add_ext := nil;
  X509_CRL_get_ext_d2i := nil;
  X509_CRL_add1_ext_i2d := nil;
  X509_REVOKED_get_ext_count := nil;
  X509_REVOKED_get_ext_by_NID := nil;
  X509_REVOKED_get_ext_by_OBJ := nil;
  X509_REVOKED_get_ext_by_critical := nil;
  X509_REVOKED_get_ext := nil;
  X509_REVOKED_delete_ext := nil;
  X509_REVOKED_add_ext := nil;
  X509_REVOKED_get_ext_d2i := nil;
  X509_REVOKED_add1_ext_i2d := nil;
  X509_EXTENSION_create_by_NID := nil;
  X509_EXTENSION_create_by_OBJ := nil;
  X509_EXTENSION_set_object := nil;
  X509_EXTENSION_set_critical := nil;
  X509_EXTENSION_set_data := nil;
  X509_EXTENSION_get_object := nil;
  X509_EXTENSION_get_data := nil;
  X509_EXTENSION_get_critical := nil;
  X509at_get_attr_count := nil;
  X509at_get_attr_by_NID := nil;
  X509at_get_attr_by_OBJ := nil;
  X509at_get_attr := nil;
  X509at_delete_attr := nil;
  X509at_add1_attr := nil;
  X509at_add1_attr_by_OBJ := nil;
  X509at_add1_attr_by_NID := nil;
  X509at_add1_attr_by_txt := nil;
  X509at_get0_data_by_OBJ := nil;
  X509_ATTRIBUTE_create_by_NID := nil;
  X509_ATTRIBUTE_create_by_OBJ := nil;
  X509_ATTRIBUTE_create_by_txt := nil;
  X509_ATTRIBUTE_set1_object := nil;
  X509_ATTRIBUTE_set1_data := nil;
  X509_ATTRIBUTE_get0_data := nil;
  X509_ATTRIBUTE_count := nil;
  X509_ATTRIBUTE_get0_object := nil;
  X509_ATTRIBUTE_get0_type := nil;
  EVP_PKEY_get_attr_count := nil;
  EVP_PKEY_get_attr_by_NID := nil;
  EVP_PKEY_get_attr_by_OBJ := nil;
  EVP_PKEY_get_attr := nil;
  EVP_PKEY_delete_attr := nil;
  EVP_PKEY_add1_attr := nil;
  EVP_PKEY_add1_attr_by_OBJ := nil;
  EVP_PKEY_add1_attr_by_NID := nil;
  EVP_PKEY_add1_attr_by_txt := nil;
  X509_find_by_issuer_and_serial := nil;
  X509_find_by_subject := nil;
  PBEPARAM_new := nil;
  PBEPARAM_free := nil;
  d2i_PBEPARAM := nil;
  i2d_PBEPARAM := nil;
  PBEPARAM_it := nil;
  PBE2PARAM_new := nil;
  PBE2PARAM_free := nil;
  d2i_PBE2PARAM := nil;
  i2d_PBE2PARAM := nil;
  PBE2PARAM_it := nil;
  PBKDF2PARAM_new := nil;
  PBKDF2PARAM_free := nil;
  d2i_PBKDF2PARAM := nil;
  i2d_PBKDF2PARAM := nil;
  PBKDF2PARAM_it := nil;
  PBMAC1PARAM_new := nil;
  PBMAC1PARAM_free := nil;
  d2i_PBMAC1PARAM := nil;
  i2d_PBMAC1PARAM := nil;
  PBMAC1PARAM_it := nil;
  SCRYPT_PARAMS_new := nil;
  SCRYPT_PARAMS_free := nil;
  d2i_SCRYPT_PARAMS := nil;
  i2d_SCRYPT_PARAMS := nil;
  SCRYPT_PARAMS_it := nil;
  PKCS5_pbe_set0_algor := nil;
  PKCS5_pbe_set0_algor_ex := nil;
  PKCS5_pbe_set := nil;
  PKCS5_pbe_set_ex := nil;
  PKCS5_pbe2_set := nil;
  PKCS5_pbe2_set_iv := nil;
  PKCS5_pbe2_set_iv_ex := nil;
  PKCS5_pbe2_set_scrypt := nil;
  PKCS5_pbkdf2_set := nil;
  PKCS5_pbkdf2_set_ex := nil;
  PBMAC1_get1_pbkdf2_param := nil;
  PKCS8_PRIV_KEY_INFO_new := nil;
  PKCS8_PRIV_KEY_INFO_free := nil;
  d2i_PKCS8_PRIV_KEY_INFO := nil;
  i2d_PKCS8_PRIV_KEY_INFO := nil;
  PKCS8_PRIV_KEY_INFO_it := nil;
  EVP_PKCS82PKEY := nil;
  EVP_PKCS82PKEY_ex := nil;
  EVP_PKEY2PKCS8 := nil;
  PKCS8_pkey_set0 := nil;
  PKCS8_pkey_get0 := nil;
  PKCS8_pkey_get0_attrs := nil;
  PKCS8_pkey_add1_attr := nil;
  PKCS8_pkey_add1_attr_by_NID := nil;
  PKCS8_pkey_add1_attr_by_OBJ := nil;
  X509_PUBKEY_set0_public_key := nil;
  X509_PUBKEY_set0_param := nil;
  X509_PUBKEY_get0_param := nil;
  X509_PUBKEY_eq := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.