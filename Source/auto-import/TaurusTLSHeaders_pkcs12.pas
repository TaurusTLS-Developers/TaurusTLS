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

unit TaurusTLSHeaders_pkcs12;

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
  PPKCS12_MAC_DATA_st = ^TPKCS12_MAC_DATA_st;
  TPKCS12_MAC_DATA_st = record end;
  {$EXTERNALSYM PPKCS12_MAC_DATA_st}

  PPKCS12_MAC_DATA = ^TPKCS12_MAC_DATA;
  TPKCS12_MAC_DATA = TPKCS12_MAC_DATA_st;
  {$EXTERNALSYM PPKCS12_MAC_DATA}

  PPKCS12_st = ^TPKCS12_st;
  TPKCS12_st = record end;
  {$EXTERNALSYM PPKCS12_st}

  PPKCS12 = ^TPKCS12;
  TPKCS12 = TPKCS12_st;
  {$EXTERNALSYM PPKCS12}

  PPKCS12_SAFEBAG_st = ^TPKCS12_SAFEBAG_st;
  TPKCS12_SAFEBAG_st = record end;
  {$EXTERNALSYM PPKCS12_SAFEBAG_st}

  PPKCS12_SAFEBAG = ^TPKCS12_SAFEBAG;
  TPKCS12_SAFEBAG = TPKCS12_SAFEBAG_st;
  {$EXTERNALSYM PPKCS12_SAFEBAG}

  Pstack_st_PKCS12_SAFEBAG = ^Tstack_st_PKCS12_SAFEBAG;
  Tstack_st_PKCS12_SAFEBAG = record end;
  {$EXTERNALSYM Pstack_st_PKCS12_SAFEBAG}

  Ppkcs12_bag_st = ^Tpkcs12_bag_st;
  Tpkcs12_bag_st = record end;
  {$EXTERNALSYM Ppkcs12_bag_st}

  PPKCS12_BAGS = ^TPKCS12_BAGS;
  TPKCS12_BAGS = Tpkcs12_bag_st;
  {$EXTERNALSYM PPKCS12_BAGS}


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  Tsk_PKCS12_SAFEBAG_compfunc_func_cb = function(arg1: PPPKCS12_SAFEBAG; arg2: PPPKCS12_SAFEBAG): TIdC_INT; cdecl;
  Tsk_PKCS12_SAFEBAG_freefunc_func_cb = procedure(arg1: PPKCS12_SAFEBAG); cdecl;
  Tsk_PKCS12_SAFEBAG_copyfunc_func_cb = function(arg1: PPKCS12_SAFEBAG): PPKCS12_SAFEBAG; cdecl;
  TPKCS12_create_cb_func_cb = function(arg1: PPKCS12_SAFEBAG; arg2: Pointer): TIdC_INT; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  PKCS12_KEY_ID = 1;
  PKCS12_IV_ID = 2;
  PKCS12_MAC_ID = 3;
  PKCS12_DEFAULT_ITER = PKCS5_DEFAULT_ITER;
  PKCS12_MAC_KEY_LENGTH = 20;
  PKCS12_SALT_LEN = 16;
  KEY_EX = $10;
  KEY_SIG = $80;
  PKCS12_ERROR = 0;
  PKCS12_OK = 1;
  M_PKCS12_bag_type = PKCS12_bag_type;
  M_PKCS12_cert_bag_type = PKCS12_cert_bag_type;
  M_PKCS12_crl_bag_type = PKCS12_cert_bag_type;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  PKCS8_get_attr: function(p8: PPKCS8_PRIV_KEY_INFO; attr_nid: TIdC_INT): PASN1_TYPE; cdecl = nil;
  {$EXTERNALSYM PKCS8_get_attr}

  PKCS12_mac_present: function(p12: PPKCS12): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_mac_present}

  PKCS12_get0_mac: procedure(pmac: PPASN1_OCTET_STRING; pmacalg: PPX509_ALGOR; psalt: PPASN1_OCTET_STRING; piter: PPASN1_INTEGER; p12: PPKCS12); cdecl = nil;
  {$EXTERNALSYM PKCS12_get0_mac}

  PKCS12_SAFEBAG_get0_attr: function(bag: PPKCS12_SAFEBAG; attr_nid: TIdC_INT): PASN1_TYPE; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_get0_attr}

  PKCS12_SAFEBAG_get0_type: function(bag: PPKCS12_SAFEBAG): PASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_get0_type}

  PKCS12_SAFEBAG_get_nid: function(bag: PPKCS12_SAFEBAG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_get_nid}

  PKCS12_SAFEBAG_get_bag_nid: function(bag: PPKCS12_SAFEBAG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_get_bag_nid}

  PKCS12_SAFEBAG_get0_bag_obj: function(bag: PPKCS12_SAFEBAG): PASN1_TYPE; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_get0_bag_obj}

  PKCS12_SAFEBAG_get0_bag_type: function(bag: PPKCS12_SAFEBAG): PASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_get0_bag_type}

  PKCS12_SAFEBAG_get1_cert_ex: function(bag: PPKCS12_SAFEBAG; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_get1_cert_ex}

  PKCS12_SAFEBAG_get1_cert: function(bag: PPKCS12_SAFEBAG): PX509; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_get1_cert}

  PKCS12_SAFEBAG_get1_crl_ex: function(bag: PPKCS12_SAFEBAG; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_CRL; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_get1_crl_ex}

  PKCS12_SAFEBAG_get1_crl: function(bag: PPKCS12_SAFEBAG): PX509_CRL; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_get1_crl}

  PKCS12_SAFEBAG_get0_safes: function(bag: PPKCS12_SAFEBAG): Pstack_st_PKCS12_SAFEBAG; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_get0_safes}

  PKCS12_SAFEBAG_get0_p8inf: function(bag: PPKCS12_SAFEBAG): PPKCS8_PRIV_KEY_INFO; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_get0_p8inf}

  PKCS12_SAFEBAG_get0_pkcs8: function(bag: PPKCS12_SAFEBAG): PX509_SIG; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_get0_pkcs8}

  PKCS12_SAFEBAG_create_cert: function(x509: PX509): PPKCS12_SAFEBAG; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_create_cert}

  PKCS12_SAFEBAG_create_crl: function(crl: PX509_CRL): PPKCS12_SAFEBAG; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_create_crl}

  PKCS12_SAFEBAG_create_secret: function(_type: TIdC_INT; vtype: TIdC_INT; value: PIdAnsiChar; len: TIdC_INT): PPKCS12_SAFEBAG; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_create_secret}

  PKCS12_SAFEBAG_create0_p8inf: function(p8: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_create0_p8inf}

  PKCS12_SAFEBAG_create0_pkcs8: function(p8: PX509_SIG): PPKCS12_SAFEBAG; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_create0_pkcs8}

  PKCS12_SAFEBAG_create_pkcs8_encrypt: function(pbe_nid: TIdC_INT; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; p8inf: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_create_pkcs8_encrypt}

  PKCS12_SAFEBAG_create_pkcs8_encrypt_ex: function(pbe_nid: TIdC_INT; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; p8inf: PPKCS8_PRIV_KEY_INFO; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS12_SAFEBAG; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_create_pkcs8_encrypt_ex}

  PKCS12_item_pack_safebag: function(obj: Pointer; it: PASN1_ITEM; nid1: TIdC_INT; nid2: TIdC_INT): PPKCS12_SAFEBAG; cdecl = nil;
  {$EXTERNALSYM PKCS12_item_pack_safebag}

  PKCS8_decrypt: function(p8: PX509_SIG; pass: PIdAnsiChar; passlen: TIdC_INT): PPKCS8_PRIV_KEY_INFO; cdecl = nil;
  {$EXTERNALSYM PKCS8_decrypt}

  PKCS8_decrypt_ex: function(p8: PX509_SIG; pass: PIdAnsiChar; passlen: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS8_PRIV_KEY_INFO; cdecl = nil;
  {$EXTERNALSYM PKCS8_decrypt_ex}

  PKCS12_decrypt_skey: function(bag: PPKCS12_SAFEBAG; pass: PIdAnsiChar; passlen: TIdC_INT): PPKCS8_PRIV_KEY_INFO; cdecl = nil;
  {$EXTERNALSYM PKCS12_decrypt_skey}

  PKCS12_decrypt_skey_ex: function(bag: PPKCS12_SAFEBAG; pass: PIdAnsiChar; passlen: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS8_PRIV_KEY_INFO; cdecl = nil;
  {$EXTERNALSYM PKCS12_decrypt_skey_ex}

  PKCS8_encrypt: function(pbe_nid: TIdC_INT; cipher: PEVP_CIPHER; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; p8: PPKCS8_PRIV_KEY_INFO): PX509_SIG; cdecl = nil;
  {$EXTERNALSYM PKCS8_encrypt}

  PKCS8_encrypt_ex: function(pbe_nid: TIdC_INT; cipher: PEVP_CIPHER; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; p8: PPKCS8_PRIV_KEY_INFO; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_SIG; cdecl = nil;
  {$EXTERNALSYM PKCS8_encrypt_ex}

  PKCS8_set0_pbe: function(pass: PIdAnsiChar; passlen: TIdC_INT; p8inf: PPKCS8_PRIV_KEY_INFO; pbe: PX509_ALGOR): PX509_SIG; cdecl = nil;
  {$EXTERNALSYM PKCS8_set0_pbe}

  PKCS8_set0_pbe_ex: function(pass: PIdAnsiChar; passlen: TIdC_INT; p8inf: PPKCS8_PRIV_KEY_INFO; pbe: PX509_ALGOR; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_SIG; cdecl = nil;
  {$EXTERNALSYM PKCS8_set0_pbe_ex}

  PKCS12_pack_p7data: function(sk: Pstack_st_PKCS12_SAFEBAG): PPKCS7; cdecl = nil;
  {$EXTERNALSYM PKCS12_pack_p7data}

  PKCS12_unpack_p7data: function(p7: PPKCS7): Pstack_st_PKCS12_SAFEBAG; cdecl = nil;
  {$EXTERNALSYM PKCS12_unpack_p7data}

  PKCS12_pack_p7encdata: function(pbe_nid: TIdC_INT; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; bags: Pstack_st_PKCS12_SAFEBAG): PPKCS7; cdecl = nil;
  {$EXTERNALSYM PKCS12_pack_p7encdata}

  PKCS12_pack_p7encdata_ex: function(pbe_nid: TIdC_INT; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; bags: Pstack_st_PKCS12_SAFEBAG; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS7; cdecl = nil;
  {$EXTERNALSYM PKCS12_pack_p7encdata_ex}

  PKCS12_unpack_p7encdata: function(p7: PPKCS7; pass: PIdAnsiChar; passlen: TIdC_INT): Pstack_st_PKCS12_SAFEBAG; cdecl = nil;
  {$EXTERNALSYM PKCS12_unpack_p7encdata}

  PKCS12_pack_authsafes: function(p12: PPKCS12; safes: Pstack_st_PKCS7): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_pack_authsafes}

  PKCS12_unpack_authsafes: function(p12: PPKCS12): Pstack_st_PKCS7; cdecl = nil;
  {$EXTERNALSYM PKCS12_unpack_authsafes}

  PKCS12_add_localkeyid: function(bag: PPKCS12_SAFEBAG; name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_add_localkeyid}

  PKCS12_add_friendlyname_asc: function(bag: PPKCS12_SAFEBAG; name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_add_friendlyname_asc}

  PKCS12_add_friendlyname_utf8: function(bag: PPKCS12_SAFEBAG; name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_add_friendlyname_utf8}

  PKCS12_add_CSPName_asc: function(bag: PPKCS12_SAFEBAG; name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_add_CSPName_asc}

  PKCS12_add_friendlyname_uni: function(bag: PPKCS12_SAFEBAG; name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_add_friendlyname_uni}

  PKCS12_add1_attr_by_NID: function(bag: PPKCS12_SAFEBAG; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_add1_attr_by_NID}

  PKCS12_add1_attr_by_txt: function(bag: PPKCS12_SAFEBAG; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_add1_attr_by_txt}

  PKCS8_add_keyusage: function(p8: PPKCS8_PRIV_KEY_INFO; usage: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS8_add_keyusage}

  PKCS12_get_attr_gen: function(attrs: Pstack_st_X509_ATTRIBUTE; attr_nid: TIdC_INT): PASN1_TYPE; cdecl = nil;
  {$EXTERNALSYM PKCS12_get_attr_gen}

  PKCS12_get_friendlyname: function(bag: PPKCS12_SAFEBAG): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM PKCS12_get_friendlyname}

  PKCS12_SAFEBAG_get0_attrs: function(bag: PPKCS12_SAFEBAG): Pstack_st_X509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_get0_attrs}

  PKCS12_SAFEBAG_set0_attrs: procedure(bag: PPKCS12_SAFEBAG; attrs: Pstack_st_X509_ATTRIBUTE); cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_set0_attrs}

  PKCS12_pbe_crypt: function(algor: PX509_ALGOR; pass: PIdAnsiChar; passlen: TIdC_INT; _in: PIdAnsiChar; inlen: TIdC_INT; data: PPIdAnsiChar; datalen: PIdC_INT; en_de: TIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM PKCS12_pbe_crypt}

  PKCS12_pbe_crypt_ex: function(algor: PX509_ALGOR; pass: PIdAnsiChar; passlen: TIdC_INT; _in: PIdAnsiChar; inlen: TIdC_INT; data: PPIdAnsiChar; datalen: PIdC_INT; en_de: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM PKCS12_pbe_crypt_ex}

  PKCS12_item_decrypt_d2i: function(algor: PX509_ALGOR; it: PASN1_ITEM; pass: PIdAnsiChar; passlen: TIdC_INT; oct: PASN1_OCTET_STRING; zbuf: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM PKCS12_item_decrypt_d2i}

  PKCS12_item_decrypt_d2i_ex: function(algor: PX509_ALGOR; it: PASN1_ITEM; pass: PIdAnsiChar; passlen: TIdC_INT; oct: PASN1_OCTET_STRING; zbuf: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pointer; cdecl = nil;
  {$EXTERNALSYM PKCS12_item_decrypt_d2i_ex}

  PKCS12_item_i2d_encrypt: function(algor: PX509_ALGOR; it: PASN1_ITEM; pass: PIdAnsiChar; passlen: TIdC_INT; obj: Pointer; zbuf: TIdC_INT): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM PKCS12_item_i2d_encrypt}

  PKCS12_item_i2d_encrypt_ex: function(algor: PX509_ALGOR; it: PASN1_ITEM; pass: PIdAnsiChar; passlen: TIdC_INT; obj: Pointer; zbuf: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM PKCS12_item_i2d_encrypt_ex}

  PKCS12_init: function(mode: TIdC_INT): PPKCS12; cdecl = nil;
  {$EXTERNALSYM PKCS12_init}

  PKCS12_init_ex: function(mode: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS12; cdecl = nil;
  {$EXTERNALSYM PKCS12_init_ex}

  PKCS12_key_gen_asc: function(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_key_gen_asc}

  PKCS12_key_gen_asc_ex: function(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_key_gen_asc_ex}

  PKCS12_key_gen_uni: function(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_key_gen_uni}

  PKCS12_key_gen_uni_ex: function(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_key_gen_uni_ex}

  PKCS12_key_gen_utf8: function(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_key_gen_utf8}

  PKCS12_key_gen_utf8_ex: function(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_key_gen_utf8_ex}

  PKCS12_PBE_keyivgen: function(ctx: PEVP_CIPHER_CTX; pass: PIdAnsiChar; passlen: TIdC_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md_type: PEVP_MD; en_de: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_PBE_keyivgen}

  PKCS12_PBE_keyivgen_ex: function(ctx: PEVP_CIPHER_CTX; pass: PIdAnsiChar; passlen: TIdC_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md_type: PEVP_MD; en_de: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_PBE_keyivgen_ex}

  PKCS12_gen_mac: function(p12: PPKCS12; pass: PIdAnsiChar; passlen: TIdC_INT; mac: PIdAnsiChar; maclen: PIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_gen_mac}

  PKCS12_verify_mac: function(p12: PPKCS12; pass: PIdAnsiChar; passlen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_verify_mac}

  PKCS12_set_mac: function(p12: PPKCS12; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; md_type: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_set_mac}

  PKCS12_set_pbmac1_pbkdf2: function(p12: PPKCS12; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; md_type: PEVP_MD; prf_md_name: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_set_pbmac1_pbkdf2}

  PKCS12_setup_mac: function(p12: PPKCS12; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; md_type: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_setup_mac}

  OPENSSL_asc2uni: function(asc: PIdAnsiChar; asclen: TIdC_INT; uni: PPIdAnsiChar; unilen: PIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OPENSSL_asc2uni}

  OPENSSL_uni2asc: function(uni: PIdAnsiChar; unilen: TIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OPENSSL_uni2asc}

  OPENSSL_utf82uni: function(asc: PIdAnsiChar; asclen: TIdC_INT; uni: PPIdAnsiChar; unilen: PIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OPENSSL_utf82uni}

  OPENSSL_uni2utf8: function(uni: PIdAnsiChar; unilen: TIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OPENSSL_uni2utf8}

  PKCS12_new: function: PPKCS12; cdecl = nil;
  {$EXTERNALSYM PKCS12_new}

  PKCS12_free: procedure(a: PPKCS12); cdecl = nil;
  {$EXTERNALSYM PKCS12_free}

  d2i_PKCS12: function(a: PPPKCS12; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS12; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS12}

  i2d_PKCS12: function(a: PPKCS12; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS12}

  PKCS12_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PKCS12_it}

  PKCS12_MAC_DATA_new: function: PPKCS12_MAC_DATA; cdecl = nil;
  {$EXTERNALSYM PKCS12_MAC_DATA_new}

  PKCS12_MAC_DATA_free: procedure(a: PPKCS12_MAC_DATA); cdecl = nil;
  {$EXTERNALSYM PKCS12_MAC_DATA_free}

  d2i_PKCS12_MAC_DATA: function(a: PPPKCS12_MAC_DATA; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS12_MAC_DATA; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS12_MAC_DATA}

  i2d_PKCS12_MAC_DATA: function(a: PPKCS12_MAC_DATA; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS12_MAC_DATA}

  PKCS12_MAC_DATA_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PKCS12_MAC_DATA_it}

  PKCS12_SAFEBAG_new: function: PPKCS12_SAFEBAG; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_new}

  PKCS12_SAFEBAG_free: procedure(a: PPKCS12_SAFEBAG); cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_free}

  d2i_PKCS12_SAFEBAG: function(a: PPPKCS12_SAFEBAG; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS12_SAFEBAG; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS12_SAFEBAG}

  i2d_PKCS12_SAFEBAG: function(a: PPKCS12_SAFEBAG; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS12_SAFEBAG}

  PKCS12_SAFEBAG_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_it}

  PKCS12_BAGS_new: function: PPKCS12_BAGS; cdecl = nil;
  {$EXTERNALSYM PKCS12_BAGS_new}

  PKCS12_BAGS_free: procedure(a: PPKCS12_BAGS); cdecl = nil;
  {$EXTERNALSYM PKCS12_BAGS_free}

  d2i_PKCS12_BAGS: function(a: PPPKCS12_BAGS; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS12_BAGS; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS12_BAGS}

  i2d_PKCS12_BAGS: function(a: PPKCS12_BAGS; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS12_BAGS}

  PKCS12_BAGS_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PKCS12_BAGS_it}

  PKCS12_SAFEBAGS_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAGS_it}

  PKCS12_AUTHSAFES_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PKCS12_AUTHSAFES_it}

  PKCS12_PBE_add: procedure; cdecl = nil;
  {$EXTERNALSYM PKCS12_PBE_add}

  PKCS12_parse: function(p12: PPKCS12; pass: PIdAnsiChar; pkey: PPEVP_PKEY; cert: PPX509; ca: PPstack_st_X509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_parse}

  PKCS12_create: function(pass: PIdAnsiChar; name: PIdAnsiChar; pkey: PEVP_PKEY; cert: PX509; ca: Pstack_st_X509; nid_key: TIdC_INT; nid_cert: TIdC_INT; iter: TIdC_INT; mac_iter: TIdC_INT; keytype: TIdC_INT): PPKCS12; cdecl = nil;
  {$EXTERNALSYM PKCS12_create}

  PKCS12_create_ex: function(pass: PIdAnsiChar; name: PIdAnsiChar; pkey: PEVP_PKEY; cert: PX509; ca: Pstack_st_X509; nid_key: TIdC_INT; nid_cert: TIdC_INT; iter: TIdC_INT; mac_iter: TIdC_INT; keytype: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS12; cdecl = nil;
  {$EXTERNALSYM PKCS12_create_ex}

  PKCS12_create_ex2: function(pass: PIdAnsiChar; name: PIdAnsiChar; pkey: PEVP_PKEY; cert: PX509; ca: Pstack_st_X509; nid_key: TIdC_INT; nid_cert: TIdC_INT; iter: TIdC_INT; mac_iter: TIdC_INT; keytype: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar; cb: TPKCS12_create_cb_func_cb; cbarg: Pointer): PPKCS12; cdecl = nil;
  {$EXTERNALSYM PKCS12_create_ex2}

  PKCS12_add_cert: function(pbags: PPstack_st_PKCS12_SAFEBAG; cert: PX509): PPKCS12_SAFEBAG; cdecl = nil;
  {$EXTERNALSYM PKCS12_add_cert}

  PKCS12_add_key: function(pbags: PPstack_st_PKCS12_SAFEBAG; key: PEVP_PKEY; key_usage: TIdC_INT; iter: TIdC_INT; key_nid: TIdC_INT; pass: PIdAnsiChar): PPKCS12_SAFEBAG; cdecl = nil;
  {$EXTERNALSYM PKCS12_add_key}

  PKCS12_add_key_ex: function(pbags: PPstack_st_PKCS12_SAFEBAG; key: PEVP_PKEY; key_usage: TIdC_INT; iter: TIdC_INT; key_nid: TIdC_INT; pass: PIdAnsiChar; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS12_SAFEBAG; cdecl = nil;
  {$EXTERNALSYM PKCS12_add_key_ex}

  PKCS12_add_secret: function(pbags: PPstack_st_PKCS12_SAFEBAG; nid_type: TIdC_INT; value: PIdAnsiChar; len: TIdC_INT): PPKCS12_SAFEBAG; cdecl = nil;
  {$EXTERNALSYM PKCS12_add_secret}

  PKCS12_add_safe: function(psafes: PPstack_st_PKCS7; bags: Pstack_st_PKCS12_SAFEBAG; safe_nid: TIdC_INT; iter: TIdC_INT; pass: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_add_safe}

  PKCS12_add_safe_ex: function(psafes: PPstack_st_PKCS7; bags: Pstack_st_PKCS12_SAFEBAG; safe_nid: TIdC_INT; iter: TIdC_INT; pass: PIdAnsiChar; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_add_safe_ex}

  PKCS12_add_safes: function(safes: Pstack_st_PKCS7; p7_nid: TIdC_INT): PPKCS12; cdecl = nil;
  {$EXTERNALSYM PKCS12_add_safes}

  PKCS12_add_safes_ex: function(safes: Pstack_st_PKCS7; p7_nid: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS12; cdecl = nil;
  {$EXTERNALSYM PKCS12_add_safes_ex}

  i2d_PKCS12_bio: function(bp: PBIO; p12: PPKCS12): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS12_bio}

  i2d_PKCS12_fp: function(fp: PFILE; p12: PPKCS12): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS12_fp}

  d2i_PKCS12_bio: function(bp: PBIO; p12: PPPKCS12): PPKCS12; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS12_bio}

  d2i_PKCS12_fp: function(fp: PFILE; p12: PPPKCS12): PPKCS12; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS12_fp}

  PKCS12_newpass: function(p12: PPKCS12; oldpass: PIdAnsiChar; newpass: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_newpass}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function PKCS8_get_attr(p8: PPKCS8_PRIV_KEY_INFO; attr_nid: TIdC_INT): PASN1_TYPE; cdecl;
function PKCS12_mac_present(p12: PPKCS12): TIdC_INT; cdecl;
procedure PKCS12_get0_mac(pmac: PPASN1_OCTET_STRING; pmacalg: PPX509_ALGOR; psalt: PPASN1_OCTET_STRING; piter: PPASN1_INTEGER; p12: PPKCS12); cdecl;
function PKCS12_SAFEBAG_get0_attr(bag: PPKCS12_SAFEBAG; attr_nid: TIdC_INT): PASN1_TYPE; cdecl;
function PKCS12_SAFEBAG_get0_type(bag: PPKCS12_SAFEBAG): PASN1_OBJECT; cdecl;
function PKCS12_SAFEBAG_get_nid(bag: PPKCS12_SAFEBAG): TIdC_INT; cdecl;
function PKCS12_SAFEBAG_get_bag_nid(bag: PPKCS12_SAFEBAG): TIdC_INT; cdecl;
function PKCS12_SAFEBAG_get0_bag_obj(bag: PPKCS12_SAFEBAG): PASN1_TYPE; cdecl;
function PKCS12_SAFEBAG_get0_bag_type(bag: PPKCS12_SAFEBAG): PASN1_OBJECT; cdecl;
function PKCS12_SAFEBAG_get1_cert_ex(bag: PPKCS12_SAFEBAG; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509; cdecl;
function PKCS12_SAFEBAG_get1_cert(bag: PPKCS12_SAFEBAG): PX509; cdecl;
function PKCS12_SAFEBAG_get1_crl_ex(bag: PPKCS12_SAFEBAG; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_CRL; cdecl;
function PKCS12_SAFEBAG_get1_crl(bag: PPKCS12_SAFEBAG): PX509_CRL; cdecl;
function PKCS12_SAFEBAG_get0_safes(bag: PPKCS12_SAFEBAG): Pstack_st_PKCS12_SAFEBAG; cdecl;
function PKCS12_SAFEBAG_get0_p8inf(bag: PPKCS12_SAFEBAG): PPKCS8_PRIV_KEY_INFO; cdecl;
function PKCS12_SAFEBAG_get0_pkcs8(bag: PPKCS12_SAFEBAG): PX509_SIG; cdecl;
function PKCS12_SAFEBAG_create_cert(x509: PX509): PPKCS12_SAFEBAG; cdecl;
function PKCS12_SAFEBAG_create_crl(crl: PX509_CRL): PPKCS12_SAFEBAG; cdecl;
function PKCS12_SAFEBAG_create_secret(_type: TIdC_INT; vtype: TIdC_INT; value: PIdAnsiChar; len: TIdC_INT): PPKCS12_SAFEBAG; cdecl;
function PKCS12_SAFEBAG_create0_p8inf(p8: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl;
function PKCS12_SAFEBAG_create0_pkcs8(p8: PX509_SIG): PPKCS12_SAFEBAG; cdecl;
function PKCS12_SAFEBAG_create_pkcs8_encrypt(pbe_nid: TIdC_INT; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; p8inf: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl;
function PKCS12_SAFEBAG_create_pkcs8_encrypt_ex(pbe_nid: TIdC_INT; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; p8inf: PPKCS8_PRIV_KEY_INFO; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS12_SAFEBAG; cdecl;
function PKCS12_item_pack_safebag(obj: Pointer; it: PASN1_ITEM; nid1: TIdC_INT; nid2: TIdC_INT): PPKCS12_SAFEBAG; cdecl;
function PKCS8_decrypt(p8: PX509_SIG; pass: PIdAnsiChar; passlen: TIdC_INT): PPKCS8_PRIV_KEY_INFO; cdecl;
function PKCS8_decrypt_ex(p8: PX509_SIG; pass: PIdAnsiChar; passlen: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS8_PRIV_KEY_INFO; cdecl;
function PKCS12_decrypt_skey(bag: PPKCS12_SAFEBAG; pass: PIdAnsiChar; passlen: TIdC_INT): PPKCS8_PRIV_KEY_INFO; cdecl;
function PKCS12_decrypt_skey_ex(bag: PPKCS12_SAFEBAG; pass: PIdAnsiChar; passlen: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS8_PRIV_KEY_INFO; cdecl;
function PKCS8_encrypt(pbe_nid: TIdC_INT; cipher: PEVP_CIPHER; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; p8: PPKCS8_PRIV_KEY_INFO): PX509_SIG; cdecl;
function PKCS8_encrypt_ex(pbe_nid: TIdC_INT; cipher: PEVP_CIPHER; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; p8: PPKCS8_PRIV_KEY_INFO; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_SIG; cdecl;
function PKCS8_set0_pbe(pass: PIdAnsiChar; passlen: TIdC_INT; p8inf: PPKCS8_PRIV_KEY_INFO; pbe: PX509_ALGOR): PX509_SIG; cdecl;
function PKCS8_set0_pbe_ex(pass: PIdAnsiChar; passlen: TIdC_INT; p8inf: PPKCS8_PRIV_KEY_INFO; pbe: PX509_ALGOR; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_SIG; cdecl;
function PKCS12_pack_p7data(sk: Pstack_st_PKCS12_SAFEBAG): PPKCS7; cdecl;
function PKCS12_unpack_p7data(p7: PPKCS7): Pstack_st_PKCS12_SAFEBAG; cdecl;
function PKCS12_pack_p7encdata(pbe_nid: TIdC_INT; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; bags: Pstack_st_PKCS12_SAFEBAG): PPKCS7; cdecl;
function PKCS12_pack_p7encdata_ex(pbe_nid: TIdC_INT; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; bags: Pstack_st_PKCS12_SAFEBAG; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS7; cdecl;
function PKCS12_unpack_p7encdata(p7: PPKCS7; pass: PIdAnsiChar; passlen: TIdC_INT): Pstack_st_PKCS12_SAFEBAG; cdecl;
function PKCS12_pack_authsafes(p12: PPKCS12; safes: Pstack_st_PKCS7): TIdC_INT; cdecl;
function PKCS12_unpack_authsafes(p12: PPKCS12): Pstack_st_PKCS7; cdecl;
function PKCS12_add_localkeyid(bag: PPKCS12_SAFEBAG; name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT; cdecl;
function PKCS12_add_friendlyname_asc(bag: PPKCS12_SAFEBAG; name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT; cdecl;
function PKCS12_add_friendlyname_utf8(bag: PPKCS12_SAFEBAG; name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT; cdecl;
function PKCS12_add_CSPName_asc(bag: PPKCS12_SAFEBAG; name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT; cdecl;
function PKCS12_add_friendlyname_uni(bag: PPKCS12_SAFEBAG; name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT; cdecl;
function PKCS12_add1_attr_by_NID(bag: PPKCS12_SAFEBAG; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function PKCS12_add1_attr_by_txt(bag: PPKCS12_SAFEBAG; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function PKCS8_add_keyusage(p8: PPKCS8_PRIV_KEY_INFO; usage: TIdC_INT): TIdC_INT; cdecl;
function PKCS12_get_attr_gen(attrs: Pstack_st_X509_ATTRIBUTE; attr_nid: TIdC_INT): PASN1_TYPE; cdecl;
function PKCS12_get_friendlyname(bag: PPKCS12_SAFEBAG): PIdAnsiChar; cdecl;
function PKCS12_SAFEBAG_get0_attrs(bag: PPKCS12_SAFEBAG): Pstack_st_X509_ATTRIBUTE; cdecl;
procedure PKCS12_SAFEBAG_set0_attrs(bag: PPKCS12_SAFEBAG; attrs: Pstack_st_X509_ATTRIBUTE); cdecl;
function PKCS12_pbe_crypt(algor: PX509_ALGOR; pass: PIdAnsiChar; passlen: TIdC_INT; _in: PIdAnsiChar; inlen: TIdC_INT; data: PPIdAnsiChar; datalen: PIdC_INT; en_de: TIdC_INT): PIdAnsiChar; cdecl;
function PKCS12_pbe_crypt_ex(algor: PX509_ALGOR; pass: PIdAnsiChar; passlen: TIdC_INT; _in: PIdAnsiChar; inlen: TIdC_INT; data: PPIdAnsiChar; datalen: PIdC_INT; en_de: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PIdAnsiChar; cdecl;
function PKCS12_item_decrypt_d2i(algor: PX509_ALGOR; it: PASN1_ITEM; pass: PIdAnsiChar; passlen: TIdC_INT; oct: PASN1_OCTET_STRING; zbuf: TIdC_INT): Pointer; cdecl;
function PKCS12_item_decrypt_d2i_ex(algor: PX509_ALGOR; it: PASN1_ITEM; pass: PIdAnsiChar; passlen: TIdC_INT; oct: PASN1_OCTET_STRING; zbuf: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pointer; cdecl;
function PKCS12_item_i2d_encrypt(algor: PX509_ALGOR; it: PASN1_ITEM; pass: PIdAnsiChar; passlen: TIdC_INT; obj: Pointer; zbuf: TIdC_INT): PASN1_OCTET_STRING; cdecl;
function PKCS12_item_i2d_encrypt_ex(algor: PX509_ALGOR; it: PASN1_ITEM; pass: PIdAnsiChar; passlen: TIdC_INT; obj: Pointer; zbuf: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PASN1_OCTET_STRING; cdecl;
function PKCS12_init(mode: TIdC_INT): PPKCS12; cdecl;
function PKCS12_init_ex(mode: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS12; cdecl;
function PKCS12_key_gen_asc(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD): TIdC_INT; cdecl;
function PKCS12_key_gen_asc_ex(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function PKCS12_key_gen_uni(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD): TIdC_INT; cdecl;
function PKCS12_key_gen_uni_ex(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function PKCS12_key_gen_utf8(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD): TIdC_INT; cdecl;
function PKCS12_key_gen_utf8_ex(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function PKCS12_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; pass: PIdAnsiChar; passlen: TIdC_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md_type: PEVP_MD; en_de: TIdC_INT): TIdC_INT; cdecl;
function PKCS12_PBE_keyivgen_ex(ctx: PEVP_CIPHER_CTX; pass: PIdAnsiChar; passlen: TIdC_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md_type: PEVP_MD; en_de: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function PKCS12_gen_mac(p12: PPKCS12; pass: PIdAnsiChar; passlen: TIdC_INT; mac: PIdAnsiChar; maclen: PIdC_UINT): TIdC_INT; cdecl;
function PKCS12_verify_mac(p12: PPKCS12; pass: PIdAnsiChar; passlen: TIdC_INT): TIdC_INT; cdecl;
function PKCS12_set_mac(p12: PPKCS12; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; md_type: PEVP_MD): TIdC_INT; cdecl;
function PKCS12_set_pbmac1_pbkdf2(p12: PPKCS12; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; md_type: PEVP_MD; prf_md_name: PIdAnsiChar): TIdC_INT; cdecl;
function PKCS12_setup_mac(p12: PPKCS12; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; md_type: PEVP_MD): TIdC_INT; cdecl;
function OPENSSL_asc2uni(asc: PIdAnsiChar; asclen: TIdC_INT; uni: PPIdAnsiChar; unilen: PIdC_INT): PIdAnsiChar; cdecl;
function OPENSSL_uni2asc(uni: PIdAnsiChar; unilen: TIdC_INT): PIdAnsiChar; cdecl;
function OPENSSL_utf82uni(asc: PIdAnsiChar; asclen: TIdC_INT; uni: PPIdAnsiChar; unilen: PIdC_INT): PIdAnsiChar; cdecl;
function OPENSSL_uni2utf8(uni: PIdAnsiChar; unilen: TIdC_INT): PIdAnsiChar; cdecl;
function PKCS12_new: PPKCS12; cdecl;
procedure PKCS12_free(a: PPKCS12); cdecl;
function d2i_PKCS12(a: PPPKCS12; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS12; cdecl;
function i2d_PKCS12(a: PPKCS12; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function PKCS12_it: PASN1_ITEM; cdecl;
function PKCS12_MAC_DATA_new: PPKCS12_MAC_DATA; cdecl;
procedure PKCS12_MAC_DATA_free(a: PPKCS12_MAC_DATA); cdecl;
function d2i_PKCS12_MAC_DATA(a: PPPKCS12_MAC_DATA; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS12_MAC_DATA; cdecl;
function i2d_PKCS12_MAC_DATA(a: PPKCS12_MAC_DATA; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function PKCS12_MAC_DATA_it: PASN1_ITEM; cdecl;
function PKCS12_SAFEBAG_new: PPKCS12_SAFEBAG; cdecl;
procedure PKCS12_SAFEBAG_free(a: PPKCS12_SAFEBAG); cdecl;
function d2i_PKCS12_SAFEBAG(a: PPPKCS12_SAFEBAG; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS12_SAFEBAG; cdecl;
function i2d_PKCS12_SAFEBAG(a: PPKCS12_SAFEBAG; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function PKCS12_SAFEBAG_it: PASN1_ITEM; cdecl;
function PKCS12_BAGS_new: PPKCS12_BAGS; cdecl;
procedure PKCS12_BAGS_free(a: PPKCS12_BAGS); cdecl;
function d2i_PKCS12_BAGS(a: PPPKCS12_BAGS; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS12_BAGS; cdecl;
function i2d_PKCS12_BAGS(a: PPKCS12_BAGS; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function PKCS12_BAGS_it: PASN1_ITEM; cdecl;
function PKCS12_SAFEBAGS_it: PASN1_ITEM; cdecl;
function PKCS12_AUTHSAFES_it: PASN1_ITEM; cdecl;
procedure PKCS12_PBE_add; cdecl;
function PKCS12_parse(p12: PPKCS12; pass: PIdAnsiChar; pkey: PPEVP_PKEY; cert: PPX509; ca: PPstack_st_X509): TIdC_INT; cdecl;
function PKCS12_create(pass: PIdAnsiChar; name: PIdAnsiChar; pkey: PEVP_PKEY; cert: PX509; ca: Pstack_st_X509; nid_key: TIdC_INT; nid_cert: TIdC_INT; iter: TIdC_INT; mac_iter: TIdC_INT; keytype: TIdC_INT): PPKCS12; cdecl;
function PKCS12_create_ex(pass: PIdAnsiChar; name: PIdAnsiChar; pkey: PEVP_PKEY; cert: PX509; ca: Pstack_st_X509; nid_key: TIdC_INT; nid_cert: TIdC_INT; iter: TIdC_INT; mac_iter: TIdC_INT; keytype: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS12; cdecl;
function PKCS12_create_ex2(pass: PIdAnsiChar; name: PIdAnsiChar; pkey: PEVP_PKEY; cert: PX509; ca: Pstack_st_X509; nid_key: TIdC_INT; nid_cert: TIdC_INT; iter: TIdC_INT; mac_iter: TIdC_INT; keytype: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar; cb: TPKCS12_create_cb_func_cb; cbarg: Pointer): PPKCS12; cdecl;
function PKCS12_add_cert(pbags: PPstack_st_PKCS12_SAFEBAG; cert: PX509): PPKCS12_SAFEBAG; cdecl;
function PKCS12_add_key(pbags: PPstack_st_PKCS12_SAFEBAG; key: PEVP_PKEY; key_usage: TIdC_INT; iter: TIdC_INT; key_nid: TIdC_INT; pass: PIdAnsiChar): PPKCS12_SAFEBAG; cdecl;
function PKCS12_add_key_ex(pbags: PPstack_st_PKCS12_SAFEBAG; key: PEVP_PKEY; key_usage: TIdC_INT; iter: TIdC_INT; key_nid: TIdC_INT; pass: PIdAnsiChar; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS12_SAFEBAG; cdecl;
function PKCS12_add_secret(pbags: PPstack_st_PKCS12_SAFEBAG; nid_type: TIdC_INT; value: PIdAnsiChar; len: TIdC_INT): PPKCS12_SAFEBAG; cdecl;
function PKCS12_add_safe(psafes: PPstack_st_PKCS7; bags: Pstack_st_PKCS12_SAFEBAG; safe_nid: TIdC_INT; iter: TIdC_INT; pass: PIdAnsiChar): TIdC_INT; cdecl;
function PKCS12_add_safe_ex(psafes: PPstack_st_PKCS7; bags: Pstack_st_PKCS12_SAFEBAG; safe_nid: TIdC_INT; iter: TIdC_INT; pass: PIdAnsiChar; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function PKCS12_add_safes(safes: Pstack_st_PKCS7; p7_nid: TIdC_INT): PPKCS12; cdecl;
function PKCS12_add_safes_ex(safes: Pstack_st_PKCS7; p7_nid: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS12; cdecl;
function i2d_PKCS12_bio(bp: PBIO; p12: PPKCS12): TIdC_INT; cdecl;
function i2d_PKCS12_fp(fp: PFILE; p12: PPKCS12): TIdC_INT; cdecl;
function d2i_PKCS12_bio(bp: PBIO; p12: PPPKCS12): PPKCS12; cdecl;
function d2i_PKCS12_fp(fp: PFILE; p12: PPPKCS12): PPKCS12; cdecl;
function PKCS12_newpass(p12: PPKCS12; oldpass: PIdAnsiChar; newpass: PIdAnsiChar): TIdC_INT; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// INLINE OR MACRO ROUTINES
// =============================================================================

function PKCS12_key_gen(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function PKCS12_add_friendlyname(bag: PPKCS12_SAFEBAG; name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function PKCS12_certbag2x509(bag: PPKCS12_SAFEBAG): PX509; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function PKCS12_certbag2scrl(bag: PPKCS12_SAFEBAG): PX509_CRL; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function PKCS12_bag_type(bag: PPKCS12_SAFEBAG): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function PKCS12_cert_bag_type(bag: PPKCS12_SAFEBAG): TIdC_INT; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function PKCS12_x5092certbag(x509: PX509): PPKCS12_SAFEBAG; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function PKCS12_x509crl2certbag(crl: PX509_CRL): PPKCS12_SAFEBAG; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function PKCS12_MAKE_KEYBAG(p8: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}

function PKCS12_MAKE_SHKEYBAG(pbe_nid: TIdC_INT; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; p8inf: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl;
  {$IFDEF USE_INLINE}inline; {$ENDIF}


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

function PKCS8_get_attr(p8: PPKCS8_PRIV_KEY_INFO; attr_nid: TIdC_INT): PASN1_TYPE; cdecl external CLibCrypto name 'PKCS8_get_attr';
function PKCS12_mac_present(p12: PPKCS12): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_mac_present';
procedure PKCS12_get0_mac(pmac: PPASN1_OCTET_STRING; pmacalg: PPX509_ALGOR; psalt: PPASN1_OCTET_STRING; piter: PPASN1_INTEGER; p12: PPKCS12); cdecl external CLibCrypto name 'PKCS12_get0_mac';
function PKCS12_SAFEBAG_get0_attr(bag: PPKCS12_SAFEBAG; attr_nid: TIdC_INT): PASN1_TYPE; cdecl external CLibCrypto name 'PKCS12_SAFEBAG_get0_attr';
function PKCS12_SAFEBAG_get0_type(bag: PPKCS12_SAFEBAG): PASN1_OBJECT; cdecl external CLibCrypto name 'PKCS12_SAFEBAG_get0_type';
function PKCS12_SAFEBAG_get_nid(bag: PPKCS12_SAFEBAG): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_SAFEBAG_get_nid';
function PKCS12_SAFEBAG_get_bag_nid(bag: PPKCS12_SAFEBAG): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_SAFEBAG_get_bag_nid';
function PKCS12_SAFEBAG_get0_bag_obj(bag: PPKCS12_SAFEBAG): PASN1_TYPE; cdecl external CLibCrypto name 'PKCS12_SAFEBAG_get0_bag_obj';
function PKCS12_SAFEBAG_get0_bag_type(bag: PPKCS12_SAFEBAG): PASN1_OBJECT; cdecl external CLibCrypto name 'PKCS12_SAFEBAG_get0_bag_type';
function PKCS12_SAFEBAG_get1_cert_ex(bag: PPKCS12_SAFEBAG; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509; cdecl external CLibCrypto name 'PKCS12_SAFEBAG_get1_cert_ex';
function PKCS12_SAFEBAG_get1_cert(bag: PPKCS12_SAFEBAG): PX509; cdecl external CLibCrypto name 'PKCS12_SAFEBAG_get1_cert';
function PKCS12_SAFEBAG_get1_crl_ex(bag: PPKCS12_SAFEBAG; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_CRL; cdecl external CLibCrypto name 'PKCS12_SAFEBAG_get1_crl_ex';
function PKCS12_SAFEBAG_get1_crl(bag: PPKCS12_SAFEBAG): PX509_CRL; cdecl external CLibCrypto name 'PKCS12_SAFEBAG_get1_crl';
function PKCS12_SAFEBAG_get0_safes(bag: PPKCS12_SAFEBAG): Pstack_st_PKCS12_SAFEBAG; cdecl external CLibCrypto name 'PKCS12_SAFEBAG_get0_safes';
function PKCS12_SAFEBAG_get0_p8inf(bag: PPKCS12_SAFEBAG): PPKCS8_PRIV_KEY_INFO; cdecl external CLibCrypto name 'PKCS12_SAFEBAG_get0_p8inf';
function PKCS12_SAFEBAG_get0_pkcs8(bag: PPKCS12_SAFEBAG): PX509_SIG; cdecl external CLibCrypto name 'PKCS12_SAFEBAG_get0_pkcs8';
function PKCS12_SAFEBAG_create_cert(x509: PX509): PPKCS12_SAFEBAG; cdecl external CLibCrypto name 'PKCS12_SAFEBAG_create_cert';
function PKCS12_SAFEBAG_create_crl(crl: PX509_CRL): PPKCS12_SAFEBAG; cdecl external CLibCrypto name 'PKCS12_SAFEBAG_create_crl';
function PKCS12_SAFEBAG_create_secret(_type: TIdC_INT; vtype: TIdC_INT; value: PIdAnsiChar; len: TIdC_INT): PPKCS12_SAFEBAG; cdecl external CLibCrypto name 'PKCS12_SAFEBAG_create_secret';
function PKCS12_SAFEBAG_create0_p8inf(p8: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl external CLibCrypto name 'PKCS12_SAFEBAG_create0_p8inf';
function PKCS12_SAFEBAG_create0_pkcs8(p8: PX509_SIG): PPKCS12_SAFEBAG; cdecl external CLibCrypto name 'PKCS12_SAFEBAG_create0_pkcs8';
function PKCS12_SAFEBAG_create_pkcs8_encrypt(pbe_nid: TIdC_INT; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; p8inf: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl external CLibCrypto name 'PKCS12_SAFEBAG_create_pkcs8_encrypt';
function PKCS12_SAFEBAG_create_pkcs8_encrypt_ex(pbe_nid: TIdC_INT; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; p8inf: PPKCS8_PRIV_KEY_INFO; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS12_SAFEBAG; cdecl external CLibCrypto name 'PKCS12_SAFEBAG_create_pkcs8_encrypt_ex';
function PKCS12_item_pack_safebag(obj: Pointer; it: PASN1_ITEM; nid1: TIdC_INT; nid2: TIdC_INT): PPKCS12_SAFEBAG; cdecl external CLibCrypto name 'PKCS12_item_pack_safebag';
function PKCS8_decrypt(p8: PX509_SIG; pass: PIdAnsiChar; passlen: TIdC_INT): PPKCS8_PRIV_KEY_INFO; cdecl external CLibCrypto name 'PKCS8_decrypt';
function PKCS8_decrypt_ex(p8: PX509_SIG; pass: PIdAnsiChar; passlen: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS8_PRIV_KEY_INFO; cdecl external CLibCrypto name 'PKCS8_decrypt_ex';
function PKCS12_decrypt_skey(bag: PPKCS12_SAFEBAG; pass: PIdAnsiChar; passlen: TIdC_INT): PPKCS8_PRIV_KEY_INFO; cdecl external CLibCrypto name 'PKCS12_decrypt_skey';
function PKCS12_decrypt_skey_ex(bag: PPKCS12_SAFEBAG; pass: PIdAnsiChar; passlen: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS8_PRIV_KEY_INFO; cdecl external CLibCrypto name 'PKCS12_decrypt_skey_ex';
function PKCS8_encrypt(pbe_nid: TIdC_INT; cipher: PEVP_CIPHER; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; p8: PPKCS8_PRIV_KEY_INFO): PX509_SIG; cdecl external CLibCrypto name 'PKCS8_encrypt';
function PKCS8_encrypt_ex(pbe_nid: TIdC_INT; cipher: PEVP_CIPHER; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; p8: PPKCS8_PRIV_KEY_INFO; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_SIG; cdecl external CLibCrypto name 'PKCS8_encrypt_ex';
function PKCS8_set0_pbe(pass: PIdAnsiChar; passlen: TIdC_INT; p8inf: PPKCS8_PRIV_KEY_INFO; pbe: PX509_ALGOR): PX509_SIG; cdecl external CLibCrypto name 'PKCS8_set0_pbe';
function PKCS8_set0_pbe_ex(pass: PIdAnsiChar; passlen: TIdC_INT; p8inf: PPKCS8_PRIV_KEY_INFO; pbe: PX509_ALGOR; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_SIG; cdecl external CLibCrypto name 'PKCS8_set0_pbe_ex';
function PKCS12_pack_p7data(sk: Pstack_st_PKCS12_SAFEBAG): PPKCS7; cdecl external CLibCrypto name 'PKCS12_pack_p7data';
function PKCS12_unpack_p7data(p7: PPKCS7): Pstack_st_PKCS12_SAFEBAG; cdecl external CLibCrypto name 'PKCS12_unpack_p7data';
function PKCS12_pack_p7encdata(pbe_nid: TIdC_INT; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; bags: Pstack_st_PKCS12_SAFEBAG): PPKCS7; cdecl external CLibCrypto name 'PKCS12_pack_p7encdata';
function PKCS12_pack_p7encdata_ex(pbe_nid: TIdC_INT; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; bags: Pstack_st_PKCS12_SAFEBAG; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS7; cdecl external CLibCrypto name 'PKCS12_pack_p7encdata_ex';
function PKCS12_unpack_p7encdata(p7: PPKCS7; pass: PIdAnsiChar; passlen: TIdC_INT): Pstack_st_PKCS12_SAFEBAG; cdecl external CLibCrypto name 'PKCS12_unpack_p7encdata';
function PKCS12_pack_authsafes(p12: PPKCS12; safes: Pstack_st_PKCS7): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_pack_authsafes';
function PKCS12_unpack_authsafes(p12: PPKCS12): Pstack_st_PKCS7; cdecl external CLibCrypto name 'PKCS12_unpack_authsafes';
function PKCS12_add_localkeyid(bag: PPKCS12_SAFEBAG; name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_add_localkeyid';
function PKCS12_add_friendlyname_asc(bag: PPKCS12_SAFEBAG; name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_add_friendlyname_asc';
function PKCS12_add_friendlyname_utf8(bag: PPKCS12_SAFEBAG; name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_add_friendlyname_utf8';
function PKCS12_add_CSPName_asc(bag: PPKCS12_SAFEBAG; name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_add_CSPName_asc';
function PKCS12_add_friendlyname_uni(bag: PPKCS12_SAFEBAG; name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_add_friendlyname_uni';
function PKCS12_add1_attr_by_NID(bag: PPKCS12_SAFEBAG; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_add1_attr_by_NID';
function PKCS12_add1_attr_by_txt(bag: PPKCS12_SAFEBAG; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_add1_attr_by_txt';
function PKCS8_add_keyusage(p8: PPKCS8_PRIV_KEY_INFO; usage: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'PKCS8_add_keyusage';
function PKCS12_get_attr_gen(attrs: Pstack_st_X509_ATTRIBUTE; attr_nid: TIdC_INT): PASN1_TYPE; cdecl external CLibCrypto name 'PKCS12_get_attr_gen';
function PKCS12_get_friendlyname(bag: PPKCS12_SAFEBAG): PIdAnsiChar; cdecl external CLibCrypto name 'PKCS12_get_friendlyname';
function PKCS12_SAFEBAG_get0_attrs(bag: PPKCS12_SAFEBAG): Pstack_st_X509_ATTRIBUTE; cdecl external CLibCrypto name 'PKCS12_SAFEBAG_get0_attrs';
procedure PKCS12_SAFEBAG_set0_attrs(bag: PPKCS12_SAFEBAG; attrs: Pstack_st_X509_ATTRIBUTE); cdecl external CLibCrypto name 'PKCS12_SAFEBAG_set0_attrs';
function PKCS12_pbe_crypt(algor: PX509_ALGOR; pass: PIdAnsiChar; passlen: TIdC_INT; _in: PIdAnsiChar; inlen: TIdC_INT; data: PPIdAnsiChar; datalen: PIdC_INT; en_de: TIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'PKCS12_pbe_crypt';
function PKCS12_pbe_crypt_ex(algor: PX509_ALGOR; pass: PIdAnsiChar; passlen: TIdC_INT; _in: PIdAnsiChar; inlen: TIdC_INT; data: PPIdAnsiChar; datalen: PIdC_INT; en_de: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PIdAnsiChar; cdecl external CLibCrypto name 'PKCS12_pbe_crypt_ex';
function PKCS12_item_decrypt_d2i(algor: PX509_ALGOR; it: PASN1_ITEM; pass: PIdAnsiChar; passlen: TIdC_INT; oct: PASN1_OCTET_STRING; zbuf: TIdC_INT): Pointer; cdecl external CLibCrypto name 'PKCS12_item_decrypt_d2i';
function PKCS12_item_decrypt_d2i_ex(algor: PX509_ALGOR; it: PASN1_ITEM; pass: PIdAnsiChar; passlen: TIdC_INT; oct: PASN1_OCTET_STRING; zbuf: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pointer; cdecl external CLibCrypto name 'PKCS12_item_decrypt_d2i_ex';
function PKCS12_item_i2d_encrypt(algor: PX509_ALGOR; it: PASN1_ITEM; pass: PIdAnsiChar; passlen: TIdC_INT; obj: Pointer; zbuf: TIdC_INT): PASN1_OCTET_STRING; cdecl external CLibCrypto name 'PKCS12_item_i2d_encrypt';
function PKCS12_item_i2d_encrypt_ex(algor: PX509_ALGOR; it: PASN1_ITEM; pass: PIdAnsiChar; passlen: TIdC_INT; obj: Pointer; zbuf: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PASN1_OCTET_STRING; cdecl external CLibCrypto name 'PKCS12_item_i2d_encrypt_ex';
function PKCS12_init(mode: TIdC_INT): PPKCS12; cdecl external CLibCrypto name 'PKCS12_init';
function PKCS12_init_ex(mode: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS12; cdecl external CLibCrypto name 'PKCS12_init_ex';
function PKCS12_key_gen_asc(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_key_gen_asc';
function PKCS12_key_gen_asc_ex(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_key_gen_asc_ex';
function PKCS12_key_gen_uni(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_key_gen_uni';
function PKCS12_key_gen_uni_ex(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_key_gen_uni_ex';
function PKCS12_key_gen_utf8(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_key_gen_utf8';
function PKCS12_key_gen_utf8_ex(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_key_gen_utf8_ex';
function PKCS12_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; pass: PIdAnsiChar; passlen: TIdC_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md_type: PEVP_MD; en_de: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_PBE_keyivgen';
function PKCS12_PBE_keyivgen_ex(ctx: PEVP_CIPHER_CTX; pass: PIdAnsiChar; passlen: TIdC_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md_type: PEVP_MD; en_de: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_PBE_keyivgen_ex';
function PKCS12_gen_mac(p12: PPKCS12; pass: PIdAnsiChar; passlen: TIdC_INT; mac: PIdAnsiChar; maclen: PIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_gen_mac';
function PKCS12_verify_mac(p12: PPKCS12; pass: PIdAnsiChar; passlen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_verify_mac';
function PKCS12_set_mac(p12: PPKCS12; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; md_type: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_set_mac';
function PKCS12_set_pbmac1_pbkdf2(p12: PPKCS12; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; md_type: PEVP_MD; prf_md_name: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_set_pbmac1_pbkdf2';
function PKCS12_setup_mac(p12: PPKCS12; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; md_type: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_setup_mac';
function OPENSSL_asc2uni(asc: PIdAnsiChar; asclen: TIdC_INT; uni: PPIdAnsiChar; unilen: PIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'OPENSSL_asc2uni';
function OPENSSL_uni2asc(uni: PIdAnsiChar; unilen: TIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'OPENSSL_uni2asc';
function OPENSSL_utf82uni(asc: PIdAnsiChar; asclen: TIdC_INT; uni: PPIdAnsiChar; unilen: PIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'OPENSSL_utf82uni';
function OPENSSL_uni2utf8(uni: PIdAnsiChar; unilen: TIdC_INT): PIdAnsiChar; cdecl external CLibCrypto name 'OPENSSL_uni2utf8';
function PKCS12_new: PPKCS12; cdecl external CLibCrypto name 'PKCS12_new';
procedure PKCS12_free(a: PPKCS12); cdecl external CLibCrypto name 'PKCS12_free';
function d2i_PKCS12(a: PPPKCS12; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS12; cdecl external CLibCrypto name 'd2i_PKCS12';
function i2d_PKCS12(a: PPKCS12; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS12';
function PKCS12_it: PASN1_ITEM; cdecl external CLibCrypto name 'PKCS12_it';
function PKCS12_MAC_DATA_new: PPKCS12_MAC_DATA; cdecl external CLibCrypto name 'PKCS12_MAC_DATA_new';
procedure PKCS12_MAC_DATA_free(a: PPKCS12_MAC_DATA); cdecl external CLibCrypto name 'PKCS12_MAC_DATA_free';
function d2i_PKCS12_MAC_DATA(a: PPPKCS12_MAC_DATA; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS12_MAC_DATA; cdecl external CLibCrypto name 'd2i_PKCS12_MAC_DATA';
function i2d_PKCS12_MAC_DATA(a: PPKCS12_MAC_DATA; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS12_MAC_DATA';
function PKCS12_MAC_DATA_it: PASN1_ITEM; cdecl external CLibCrypto name 'PKCS12_MAC_DATA_it';
function PKCS12_SAFEBAG_new: PPKCS12_SAFEBAG; cdecl external CLibCrypto name 'PKCS12_SAFEBAG_new';
procedure PKCS12_SAFEBAG_free(a: PPKCS12_SAFEBAG); cdecl external CLibCrypto name 'PKCS12_SAFEBAG_free';
function d2i_PKCS12_SAFEBAG(a: PPPKCS12_SAFEBAG; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS12_SAFEBAG; cdecl external CLibCrypto name 'd2i_PKCS12_SAFEBAG';
function i2d_PKCS12_SAFEBAG(a: PPKCS12_SAFEBAG; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS12_SAFEBAG';
function PKCS12_SAFEBAG_it: PASN1_ITEM; cdecl external CLibCrypto name 'PKCS12_SAFEBAG_it';
function PKCS12_BAGS_new: PPKCS12_BAGS; cdecl external CLibCrypto name 'PKCS12_BAGS_new';
procedure PKCS12_BAGS_free(a: PPKCS12_BAGS); cdecl external CLibCrypto name 'PKCS12_BAGS_free';
function d2i_PKCS12_BAGS(a: PPPKCS12_BAGS; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS12_BAGS; cdecl external CLibCrypto name 'd2i_PKCS12_BAGS';
function i2d_PKCS12_BAGS(a: PPKCS12_BAGS; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS12_BAGS';
function PKCS12_BAGS_it: PASN1_ITEM; cdecl external CLibCrypto name 'PKCS12_BAGS_it';
function PKCS12_SAFEBAGS_it: PASN1_ITEM; cdecl external CLibCrypto name 'PKCS12_SAFEBAGS_it';
function PKCS12_AUTHSAFES_it: PASN1_ITEM; cdecl external CLibCrypto name 'PKCS12_AUTHSAFES_it';
procedure PKCS12_PBE_add; cdecl external CLibCrypto name 'PKCS12_PBE_add';
function PKCS12_parse(p12: PPKCS12; pass: PIdAnsiChar; pkey: PPEVP_PKEY; cert: PPX509; ca: PPstack_st_X509): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_parse';
function PKCS12_create(pass: PIdAnsiChar; name: PIdAnsiChar; pkey: PEVP_PKEY; cert: PX509; ca: Pstack_st_X509; nid_key: TIdC_INT; nid_cert: TIdC_INT; iter: TIdC_INT; mac_iter: TIdC_INT; keytype: TIdC_INT): PPKCS12; cdecl external CLibCrypto name 'PKCS12_create';
function PKCS12_create_ex(pass: PIdAnsiChar; name: PIdAnsiChar; pkey: PEVP_PKEY; cert: PX509; ca: Pstack_st_X509; nid_key: TIdC_INT; nid_cert: TIdC_INT; iter: TIdC_INT; mac_iter: TIdC_INT; keytype: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS12; cdecl external CLibCrypto name 'PKCS12_create_ex';
function PKCS12_create_ex2(pass: PIdAnsiChar; name: PIdAnsiChar; pkey: PEVP_PKEY; cert: PX509; ca: Pstack_st_X509; nid_key: TIdC_INT; nid_cert: TIdC_INT; iter: TIdC_INT; mac_iter: TIdC_INT; keytype: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar; cb: TPKCS12_create_cb_func_cb; cbarg: Pointer): PPKCS12; cdecl external CLibCrypto name 'PKCS12_create_ex2';
function PKCS12_add_cert(pbags: PPstack_st_PKCS12_SAFEBAG; cert: PX509): PPKCS12_SAFEBAG; cdecl external CLibCrypto name 'PKCS12_add_cert';
function PKCS12_add_key(pbags: PPstack_st_PKCS12_SAFEBAG; key: PEVP_PKEY; key_usage: TIdC_INT; iter: TIdC_INT; key_nid: TIdC_INT; pass: PIdAnsiChar): PPKCS12_SAFEBAG; cdecl external CLibCrypto name 'PKCS12_add_key';
function PKCS12_add_key_ex(pbags: PPstack_st_PKCS12_SAFEBAG; key: PEVP_PKEY; key_usage: TIdC_INT; iter: TIdC_INT; key_nid: TIdC_INT; pass: PIdAnsiChar; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS12_SAFEBAG; cdecl external CLibCrypto name 'PKCS12_add_key_ex';
function PKCS12_add_secret(pbags: PPstack_st_PKCS12_SAFEBAG; nid_type: TIdC_INT; value: PIdAnsiChar; len: TIdC_INT): PPKCS12_SAFEBAG; cdecl external CLibCrypto name 'PKCS12_add_secret';
function PKCS12_add_safe(psafes: PPstack_st_PKCS7; bags: Pstack_st_PKCS12_SAFEBAG; safe_nid: TIdC_INT; iter: TIdC_INT; pass: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_add_safe';
function PKCS12_add_safe_ex(psafes: PPstack_st_PKCS7; bags: Pstack_st_PKCS12_SAFEBAG; safe_nid: TIdC_INT; iter: TIdC_INT; pass: PIdAnsiChar; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_add_safe_ex';
function PKCS12_add_safes(safes: Pstack_st_PKCS7; p7_nid: TIdC_INT): PPKCS12; cdecl external CLibCrypto name 'PKCS12_add_safes';
function PKCS12_add_safes_ex(safes: Pstack_st_PKCS7; p7_nid: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS12; cdecl external CLibCrypto name 'PKCS12_add_safes_ex';
function i2d_PKCS12_bio(bp: PBIO; p12: PPKCS12): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS12_bio';
function i2d_PKCS12_fp(fp: PFILE; p12: PPKCS12): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS12_fp';
function d2i_PKCS12_bio(bp: PBIO; p12: PPPKCS12): PPKCS12; cdecl external CLibCrypto name 'd2i_PKCS12_bio';
function d2i_PKCS12_fp(fp: PFILE; p12: PPPKCS12): PPKCS12; cdecl external CLibCrypto name 'd2i_PKCS12_fp';
function PKCS12_newpass(p12: PPKCS12; oldpass: PIdAnsiChar; newpass: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'PKCS12_newpass';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  PKCS8_get_attr_procname = 'PKCS8_get_attr';
  PKCS8_get_attr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_mac_present_procname = 'PKCS12_mac_present';
  PKCS12_mac_present_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_get0_mac_procname = 'PKCS12_get0_mac';
  PKCS12_get0_mac_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_SAFEBAG_get0_attr_procname = 'PKCS12_SAFEBAG_get0_attr';
  PKCS12_SAFEBAG_get0_attr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_SAFEBAG_get0_type_procname = 'PKCS12_SAFEBAG_get0_type';
  PKCS12_SAFEBAG_get0_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_SAFEBAG_get_nid_procname = 'PKCS12_SAFEBAG_get_nid';
  PKCS12_SAFEBAG_get_nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_SAFEBAG_get_bag_nid_procname = 'PKCS12_SAFEBAG_get_bag_nid';
  PKCS12_SAFEBAG_get_bag_nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_SAFEBAG_get0_bag_obj_procname = 'PKCS12_SAFEBAG_get0_bag_obj';
  PKCS12_SAFEBAG_get0_bag_obj_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS12_SAFEBAG_get0_bag_type_procname = 'PKCS12_SAFEBAG_get0_bag_type';
  PKCS12_SAFEBAG_get0_bag_type_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS12_SAFEBAG_get1_cert_ex_procname = 'PKCS12_SAFEBAG_get1_cert_ex';
  PKCS12_SAFEBAG_get1_cert_ex_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  PKCS12_SAFEBAG_get1_cert_procname = 'PKCS12_SAFEBAG_get1_cert';
  PKCS12_SAFEBAG_get1_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_SAFEBAG_get1_crl_ex_procname = 'PKCS12_SAFEBAG_get1_crl_ex';
  PKCS12_SAFEBAG_get1_crl_ex_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  PKCS12_SAFEBAG_get1_crl_procname = 'PKCS12_SAFEBAG_get1_crl';
  PKCS12_SAFEBAG_get1_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_SAFEBAG_get0_safes_procname = 'PKCS12_SAFEBAG_get0_safes';
  PKCS12_SAFEBAG_get0_safes_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_SAFEBAG_get0_p8inf_procname = 'PKCS12_SAFEBAG_get0_p8inf';
  PKCS12_SAFEBAG_get0_p8inf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_SAFEBAG_get0_pkcs8_procname = 'PKCS12_SAFEBAG_get0_pkcs8';
  PKCS12_SAFEBAG_get0_pkcs8_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_SAFEBAG_create_cert_procname = 'PKCS12_SAFEBAG_create_cert';
  PKCS12_SAFEBAG_create_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_SAFEBAG_create_crl_procname = 'PKCS12_SAFEBAG_create_crl';
  PKCS12_SAFEBAG_create_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_SAFEBAG_create_secret_procname = 'PKCS12_SAFEBAG_create_secret';
  PKCS12_SAFEBAG_create_secret_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS12_SAFEBAG_create0_p8inf_procname = 'PKCS12_SAFEBAG_create0_p8inf';
  PKCS12_SAFEBAG_create0_p8inf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_SAFEBAG_create0_pkcs8_procname = 'PKCS12_SAFEBAG_create0_pkcs8';
  PKCS12_SAFEBAG_create0_pkcs8_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_SAFEBAG_create_pkcs8_encrypt_procname = 'PKCS12_SAFEBAG_create_pkcs8_encrypt';
  PKCS12_SAFEBAG_create_pkcs8_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_SAFEBAG_create_pkcs8_encrypt_ex_procname = 'PKCS12_SAFEBAG_create_pkcs8_encrypt_ex';
  PKCS12_SAFEBAG_create_pkcs8_encrypt_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS12_item_pack_safebag_procname = 'PKCS12_item_pack_safebag';
  PKCS12_item_pack_safebag_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS8_decrypt_procname = 'PKCS8_decrypt';
  PKCS8_decrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS8_decrypt_ex_procname = 'PKCS8_decrypt_ex';
  PKCS8_decrypt_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS12_decrypt_skey_procname = 'PKCS12_decrypt_skey';
  PKCS12_decrypt_skey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_decrypt_skey_ex_procname = 'PKCS12_decrypt_skey_ex';
  PKCS12_decrypt_skey_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS8_encrypt_procname = 'PKCS8_encrypt';
  PKCS8_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS8_encrypt_ex_procname = 'PKCS8_encrypt_ex';
  PKCS8_encrypt_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS8_set0_pbe_procname = 'PKCS8_set0_pbe';
  PKCS8_set0_pbe_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS8_set0_pbe_ex_procname = 'PKCS8_set0_pbe_ex';
  PKCS8_set0_pbe_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS12_pack_p7data_procname = 'PKCS12_pack_p7data';
  PKCS12_pack_p7data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_unpack_p7data_procname = 'PKCS12_unpack_p7data';
  PKCS12_unpack_p7data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_pack_p7encdata_procname = 'PKCS12_pack_p7encdata';
  PKCS12_pack_p7encdata_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_pack_p7encdata_ex_procname = 'PKCS12_pack_p7encdata_ex';
  PKCS12_pack_p7encdata_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS12_unpack_p7encdata_procname = 'PKCS12_unpack_p7encdata';
  PKCS12_unpack_p7encdata_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_pack_authsafes_procname = 'PKCS12_pack_authsafes';
  PKCS12_pack_authsafes_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_unpack_authsafes_procname = 'PKCS12_unpack_authsafes';
  PKCS12_unpack_authsafes_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_add_localkeyid_procname = 'PKCS12_add_localkeyid';
  PKCS12_add_localkeyid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_add_friendlyname_asc_procname = 'PKCS12_add_friendlyname_asc';
  PKCS12_add_friendlyname_asc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_add_friendlyname_utf8_procname = 'PKCS12_add_friendlyname_utf8';
  PKCS12_add_friendlyname_utf8_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_add_CSPName_asc_procname = 'PKCS12_add_CSPName_asc';
  PKCS12_add_CSPName_asc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_add_friendlyname_uni_procname = 'PKCS12_add_friendlyname_uni';
  PKCS12_add_friendlyname_uni_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_add1_attr_by_NID_procname = 'PKCS12_add1_attr_by_NID';
  PKCS12_add1_attr_by_NID_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS12_add1_attr_by_txt_procname = 'PKCS12_add1_attr_by_txt';
  PKCS12_add1_attr_by_txt_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS8_add_keyusage_procname = 'PKCS8_add_keyusage';
  PKCS8_add_keyusage_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_get_attr_gen_procname = 'PKCS12_get_attr_gen';
  PKCS12_get_attr_gen_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_get_friendlyname_procname = 'PKCS12_get_friendlyname';
  PKCS12_get_friendlyname_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_SAFEBAG_get0_attrs_procname = 'PKCS12_SAFEBAG_get0_attrs';
  PKCS12_SAFEBAG_get0_attrs_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_SAFEBAG_set0_attrs_procname = 'PKCS12_SAFEBAG_set0_attrs';
  PKCS12_SAFEBAG_set0_attrs_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  PKCS12_pbe_crypt_procname = 'PKCS12_pbe_crypt';
  PKCS12_pbe_crypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_pbe_crypt_ex_procname = 'PKCS12_pbe_crypt_ex';
  PKCS12_pbe_crypt_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS12_item_decrypt_d2i_procname = 'PKCS12_item_decrypt_d2i';
  PKCS12_item_decrypt_d2i_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_item_decrypt_d2i_ex_procname = 'PKCS12_item_decrypt_d2i_ex';
  PKCS12_item_decrypt_d2i_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS12_item_i2d_encrypt_procname = 'PKCS12_item_i2d_encrypt';
  PKCS12_item_i2d_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_item_i2d_encrypt_ex_procname = 'PKCS12_item_i2d_encrypt_ex';
  PKCS12_item_i2d_encrypt_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS12_init_procname = 'PKCS12_init';
  PKCS12_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_init_ex_procname = 'PKCS12_init_ex';
  PKCS12_init_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS12_key_gen_asc_procname = 'PKCS12_key_gen_asc';
  PKCS12_key_gen_asc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_key_gen_asc_ex_procname = 'PKCS12_key_gen_asc_ex';
  PKCS12_key_gen_asc_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS12_key_gen_uni_procname = 'PKCS12_key_gen_uni';
  PKCS12_key_gen_uni_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_key_gen_uni_ex_procname = 'PKCS12_key_gen_uni_ex';
  PKCS12_key_gen_uni_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS12_key_gen_utf8_procname = 'PKCS12_key_gen_utf8';
  PKCS12_key_gen_utf8_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_key_gen_utf8_ex_procname = 'PKCS12_key_gen_utf8_ex';
  PKCS12_key_gen_utf8_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS12_PBE_keyivgen_procname = 'PKCS12_PBE_keyivgen';
  PKCS12_PBE_keyivgen_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_PBE_keyivgen_ex_procname = 'PKCS12_PBE_keyivgen_ex';
  PKCS12_PBE_keyivgen_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS12_gen_mac_procname = 'PKCS12_gen_mac';
  PKCS12_gen_mac_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_verify_mac_procname = 'PKCS12_verify_mac';
  PKCS12_verify_mac_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_set_mac_procname = 'PKCS12_set_mac';
  PKCS12_set_mac_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_set_pbmac1_pbkdf2_procname = 'PKCS12_set_pbmac1_pbkdf2';
  PKCS12_set_pbmac1_pbkdf2_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  PKCS12_setup_mac_procname = 'PKCS12_setup_mac';
  PKCS12_setup_mac_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_asc2uni_procname = 'OPENSSL_asc2uni';
  OPENSSL_asc2uni_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_uni2asc_procname = 'OPENSSL_uni2asc';
  OPENSSL_uni2asc_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_utf82uni_procname = 'OPENSSL_utf82uni';
  OPENSSL_utf82uni_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  OPENSSL_uni2utf8_procname = 'OPENSSL_uni2utf8';
  OPENSSL_uni2utf8_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_new_procname = 'PKCS12_new';
  PKCS12_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_free_procname = 'PKCS12_free';
  PKCS12_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PKCS12_procname = 'd2i_PKCS12';
  d2i_PKCS12_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS12_procname = 'i2d_PKCS12';
  i2d_PKCS12_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_it_procname = 'PKCS12_it';
  PKCS12_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_MAC_DATA_new_procname = 'PKCS12_MAC_DATA_new';
  PKCS12_MAC_DATA_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_MAC_DATA_free_procname = 'PKCS12_MAC_DATA_free';
  PKCS12_MAC_DATA_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PKCS12_MAC_DATA_procname = 'd2i_PKCS12_MAC_DATA';
  d2i_PKCS12_MAC_DATA_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS12_MAC_DATA_procname = 'i2d_PKCS12_MAC_DATA';
  i2d_PKCS12_MAC_DATA_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_MAC_DATA_it_procname = 'PKCS12_MAC_DATA_it';
  PKCS12_MAC_DATA_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_SAFEBAG_new_procname = 'PKCS12_SAFEBAG_new';
  PKCS12_SAFEBAG_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_SAFEBAG_free_procname = 'PKCS12_SAFEBAG_free';
  PKCS12_SAFEBAG_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PKCS12_SAFEBAG_procname = 'd2i_PKCS12_SAFEBAG';
  d2i_PKCS12_SAFEBAG_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS12_SAFEBAG_procname = 'i2d_PKCS12_SAFEBAG';
  i2d_PKCS12_SAFEBAG_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_SAFEBAG_it_procname = 'PKCS12_SAFEBAG_it';
  PKCS12_SAFEBAG_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_BAGS_new_procname = 'PKCS12_BAGS_new';
  PKCS12_BAGS_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_BAGS_free_procname = 'PKCS12_BAGS_free';
  PKCS12_BAGS_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PKCS12_BAGS_procname = 'd2i_PKCS12_BAGS';
  d2i_PKCS12_BAGS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS12_BAGS_procname = 'i2d_PKCS12_BAGS';
  i2d_PKCS12_BAGS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_BAGS_it_procname = 'PKCS12_BAGS_it';
  PKCS12_BAGS_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_SAFEBAGS_it_procname = 'PKCS12_SAFEBAGS_it';
  PKCS12_SAFEBAGS_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_AUTHSAFES_it_procname = 'PKCS12_AUTHSAFES_it';
  PKCS12_AUTHSAFES_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_PBE_add_procname = 'PKCS12_PBE_add';
  PKCS12_PBE_add_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_parse_procname = 'PKCS12_parse';
  PKCS12_parse_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_create_procname = 'PKCS12_create';
  PKCS12_create_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_create_ex_procname = 'PKCS12_create_ex';
  PKCS12_create_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS12_create_ex2_procname = 'PKCS12_create_ex2';
  PKCS12_create_ex2_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  PKCS12_add_cert_procname = 'PKCS12_add_cert';
  PKCS12_add_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_add_key_procname = 'PKCS12_add_key';
  PKCS12_add_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_add_key_ex_procname = 'PKCS12_add_key_ex';
  PKCS12_add_key_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS12_add_secret_procname = 'PKCS12_add_secret';
  PKCS12_add_secret_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS12_add_safe_procname = 'PKCS12_add_safe';
  PKCS12_add_safe_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_add_safe_ex_procname = 'PKCS12_add_safe_ex';
  PKCS12_add_safe_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS12_add_safes_procname = 'PKCS12_add_safes';
  PKCS12_add_safes_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_add_safes_ex_procname = 'PKCS12_add_safes_ex';
  PKCS12_add_safes_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2d_PKCS12_bio_procname = 'i2d_PKCS12_bio';
  i2d_PKCS12_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS12_fp_procname = 'i2d_PKCS12_fp';
  i2d_PKCS12_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PKCS12_bio_procname = 'd2i_PKCS12_bio';
  d2i_PKCS12_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PKCS12_fp_procname = 'd2i_PKCS12_fp';
  d2i_PKCS12_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS12_newpass_procname = 'PKCS12_newpass';
  PKCS12_newpass_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

// =============================================================================
// INLINE/MACRO IMPLEMENTATIONS
// =============================================================================

function PKCS12_key_gen(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    PKCS12_key_gen PKCS12_key_gen_utf8
  }
end;

function PKCS12_add_friendlyname(bag: PPKCS12_SAFEBAG; name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    PKCS12_add_friendlyname PKCS12_add_friendlyname_utf8
  }
end;

function PKCS12_certbag2x509(bag: PPKCS12_SAFEBAG): PX509; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    PKCS12_certbag2x509 PKCS12_SAFEBAG_get1_cert
  }
end;

function PKCS12_certbag2scrl(bag: PPKCS12_SAFEBAG): PX509_CRL; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    PKCS12_certbag2scrl PKCS12_SAFEBAG_get1_crl
  }
end;

function PKCS12_bag_type(bag: PPKCS12_SAFEBAG): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    PKCS12_bag_type PKCS12_SAFEBAG_get_nid
  }
end;

function PKCS12_cert_bag_type(bag: PPKCS12_SAFEBAG): TIdC_INT; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    PKCS12_cert_bag_type PKCS12_SAFEBAG_get_bag_nid
  }
end;

function PKCS12_x5092certbag(x509: PX509): PPKCS12_SAFEBAG; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    PKCS12_x5092certbag PKCS12_SAFEBAG_create_cert
  }
end;

function PKCS12_x509crl2certbag(crl: PX509_CRL): PPKCS12_SAFEBAG; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    PKCS12_x509crl2certbag PKCS12_SAFEBAG_create_crl
  }
end;

function PKCS12_MAKE_KEYBAG(p8: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    PKCS12_MAKE_KEYBAG PKCS12_SAFEBAG_create0_p8inf
  }
end;

function PKCS12_MAKE_SHKEYBAG(pbe_nid: TIdC_INT; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; p8inf: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl
begin
 { TODO 1 -copenssl inline routines : To replace placeholder body with the actual code. }
  // This is an inline routine or macro. Manual implementation required if needed.
  { Original C Declaration:
    PKCS12_MAKE_SHKEYBAG PKCS12_SAFEBAG_create_pkcs8_encrypt
  }
end;

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_PKCS8_get_attr(p8: PPKCS8_PRIV_KEY_INFO; attr_nid: TIdC_INT): PASN1_TYPE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS8_get_attr_procname);
end;

function ERR_PKCS12_mac_present(p12: PPKCS12): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_mac_present_procname);
end;

procedure ERR_PKCS12_get0_mac(pmac: PPASN1_OCTET_STRING; pmacalg: PPX509_ALGOR; psalt: PPASN1_OCTET_STRING; piter: PPASN1_INTEGER; p12: PPKCS12); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_get0_mac_procname);
end;

function ERR_PKCS12_SAFEBAG_get0_attr(bag: PPKCS12_SAFEBAG; attr_nid: TIdC_INT): PASN1_TYPE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_get0_attr_procname);
end;

function ERR_PKCS12_SAFEBAG_get0_type(bag: PPKCS12_SAFEBAG): PASN1_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_get0_type_procname);
end;

function ERR_PKCS12_SAFEBAG_get_nid(bag: PPKCS12_SAFEBAG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_get_nid_procname);
end;

function ERR_PKCS12_SAFEBAG_get_bag_nid(bag: PPKCS12_SAFEBAG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_get_bag_nid_procname);
end;

function ERR_PKCS12_SAFEBAG_get0_bag_obj(bag: PPKCS12_SAFEBAG): PASN1_TYPE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_get0_bag_obj_procname);
end;

function ERR_PKCS12_SAFEBAG_get0_bag_type(bag: PPKCS12_SAFEBAG): PASN1_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_get0_bag_type_procname);
end;

function ERR_PKCS12_SAFEBAG_get1_cert_ex(bag: PPKCS12_SAFEBAG; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_get1_cert_ex_procname);
end;

function ERR_PKCS12_SAFEBAG_get1_cert(bag: PPKCS12_SAFEBAG): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_get1_cert_procname);
end;

function ERR_PKCS12_SAFEBAG_get1_crl_ex(bag: PPKCS12_SAFEBAG; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_CRL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_get1_crl_ex_procname);
end;

function ERR_PKCS12_SAFEBAG_get1_crl(bag: PPKCS12_SAFEBAG): PX509_CRL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_get1_crl_procname);
end;

function ERR_PKCS12_SAFEBAG_get0_safes(bag: PPKCS12_SAFEBAG): Pstack_st_PKCS12_SAFEBAG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_get0_safes_procname);
end;

function ERR_PKCS12_SAFEBAG_get0_p8inf(bag: PPKCS12_SAFEBAG): PPKCS8_PRIV_KEY_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_get0_p8inf_procname);
end;

function ERR_PKCS12_SAFEBAG_get0_pkcs8(bag: PPKCS12_SAFEBAG): PX509_SIG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_get0_pkcs8_procname);
end;

function ERR_PKCS12_SAFEBAG_create_cert(x509: PX509): PPKCS12_SAFEBAG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_create_cert_procname);
end;

function ERR_PKCS12_SAFEBAG_create_crl(crl: PX509_CRL): PPKCS12_SAFEBAG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_create_crl_procname);
end;

function ERR_PKCS12_SAFEBAG_create_secret(_type: TIdC_INT; vtype: TIdC_INT; value: PIdAnsiChar; len: TIdC_INT): PPKCS12_SAFEBAG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_create_secret_procname);
end;

function ERR_PKCS12_SAFEBAG_create0_p8inf(p8: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_create0_p8inf_procname);
end;

function ERR_PKCS12_SAFEBAG_create0_pkcs8(p8: PX509_SIG): PPKCS12_SAFEBAG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_create0_pkcs8_procname);
end;

function ERR_PKCS12_SAFEBAG_create_pkcs8_encrypt(pbe_nid: TIdC_INT; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; p8inf: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_create_pkcs8_encrypt_procname);
end;

function ERR_PKCS12_SAFEBAG_create_pkcs8_encrypt_ex(pbe_nid: TIdC_INT; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; p8inf: PPKCS8_PRIV_KEY_INFO; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS12_SAFEBAG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_create_pkcs8_encrypt_ex_procname);
end;

function ERR_PKCS12_item_pack_safebag(obj: Pointer; it: PASN1_ITEM; nid1: TIdC_INT; nid2: TIdC_INT): PPKCS12_SAFEBAG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_item_pack_safebag_procname);
end;

function ERR_PKCS8_decrypt(p8: PX509_SIG; pass: PIdAnsiChar; passlen: TIdC_INT): PPKCS8_PRIV_KEY_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS8_decrypt_procname);
end;

function ERR_PKCS8_decrypt_ex(p8: PX509_SIG; pass: PIdAnsiChar; passlen: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS8_PRIV_KEY_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS8_decrypt_ex_procname);
end;

function ERR_PKCS12_decrypt_skey(bag: PPKCS12_SAFEBAG; pass: PIdAnsiChar; passlen: TIdC_INT): PPKCS8_PRIV_KEY_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_decrypt_skey_procname);
end;

function ERR_PKCS12_decrypt_skey_ex(bag: PPKCS12_SAFEBAG; pass: PIdAnsiChar; passlen: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS8_PRIV_KEY_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_decrypt_skey_ex_procname);
end;

function ERR_PKCS8_encrypt(pbe_nid: TIdC_INT; cipher: PEVP_CIPHER; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; p8: PPKCS8_PRIV_KEY_INFO): PX509_SIG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS8_encrypt_procname);
end;

function ERR_PKCS8_encrypt_ex(pbe_nid: TIdC_INT; cipher: PEVP_CIPHER; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; p8: PPKCS8_PRIV_KEY_INFO; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_SIG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS8_encrypt_ex_procname);
end;

function ERR_PKCS8_set0_pbe(pass: PIdAnsiChar; passlen: TIdC_INT; p8inf: PPKCS8_PRIV_KEY_INFO; pbe: PX509_ALGOR): PX509_SIG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS8_set0_pbe_procname);
end;

function ERR_PKCS8_set0_pbe_ex(pass: PIdAnsiChar; passlen: TIdC_INT; p8inf: PPKCS8_PRIV_KEY_INFO; pbe: PX509_ALGOR; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PX509_SIG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS8_set0_pbe_ex_procname);
end;

function ERR_PKCS12_pack_p7data(sk: Pstack_st_PKCS12_SAFEBAG): PPKCS7; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_pack_p7data_procname);
end;

function ERR_PKCS12_unpack_p7data(p7: PPKCS7): Pstack_st_PKCS12_SAFEBAG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_unpack_p7data_procname);
end;

function ERR_PKCS12_pack_p7encdata(pbe_nid: TIdC_INT; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; bags: Pstack_st_PKCS12_SAFEBAG): PPKCS7; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_pack_p7encdata_procname);
end;

function ERR_PKCS12_pack_p7encdata_ex(pbe_nid: TIdC_INT; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; bags: Pstack_st_PKCS12_SAFEBAG; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS7; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_pack_p7encdata_ex_procname);
end;

function ERR_PKCS12_unpack_p7encdata(p7: PPKCS7; pass: PIdAnsiChar; passlen: TIdC_INT): Pstack_st_PKCS12_SAFEBAG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_unpack_p7encdata_procname);
end;

function ERR_PKCS12_pack_authsafes(p12: PPKCS12; safes: Pstack_st_PKCS7): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_pack_authsafes_procname);
end;

function ERR_PKCS12_unpack_authsafes(p12: PPKCS12): Pstack_st_PKCS7; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_unpack_authsafes_procname);
end;

function ERR_PKCS12_add_localkeyid(bag: PPKCS12_SAFEBAG; name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_add_localkeyid_procname);
end;

function ERR_PKCS12_add_friendlyname_asc(bag: PPKCS12_SAFEBAG; name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_add_friendlyname_asc_procname);
end;

function ERR_PKCS12_add_friendlyname_utf8(bag: PPKCS12_SAFEBAG; name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_add_friendlyname_utf8_procname);
end;

function ERR_PKCS12_add_CSPName_asc(bag: PPKCS12_SAFEBAG; name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_add_CSPName_asc_procname);
end;

function ERR_PKCS12_add_friendlyname_uni(bag: PPKCS12_SAFEBAG; name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_add_friendlyname_uni_procname);
end;

function ERR_PKCS12_add1_attr_by_NID(bag: PPKCS12_SAFEBAG; nid: TIdC_INT; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_add1_attr_by_NID_procname);
end;

function ERR_PKCS12_add1_attr_by_txt(bag: PPKCS12_SAFEBAG; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_add1_attr_by_txt_procname);
end;

function ERR_PKCS8_add_keyusage(p8: PPKCS8_PRIV_KEY_INFO; usage: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS8_add_keyusage_procname);
end;

function ERR_PKCS12_get_attr_gen(attrs: Pstack_st_X509_ATTRIBUTE; attr_nid: TIdC_INT): PASN1_TYPE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_get_attr_gen_procname);
end;

function ERR_PKCS12_get_friendlyname(bag: PPKCS12_SAFEBAG): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_get_friendlyname_procname);
end;

function ERR_PKCS12_SAFEBAG_get0_attrs(bag: PPKCS12_SAFEBAG): Pstack_st_X509_ATTRIBUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_get0_attrs_procname);
end;

procedure ERR_PKCS12_SAFEBAG_set0_attrs(bag: PPKCS12_SAFEBAG; attrs: Pstack_st_X509_ATTRIBUTE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_set0_attrs_procname);
end;

function ERR_PKCS12_pbe_crypt(algor: PX509_ALGOR; pass: PIdAnsiChar; passlen: TIdC_INT; _in: PIdAnsiChar; inlen: TIdC_INT; data: PPIdAnsiChar; datalen: PIdC_INT; en_de: TIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_pbe_crypt_procname);
end;

function ERR_PKCS12_pbe_crypt_ex(algor: PX509_ALGOR; pass: PIdAnsiChar; passlen: TIdC_INT; _in: PIdAnsiChar; inlen: TIdC_INT; data: PPIdAnsiChar; datalen: PIdC_INT; en_de: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_pbe_crypt_ex_procname);
end;

function ERR_PKCS12_item_decrypt_d2i(algor: PX509_ALGOR; it: PASN1_ITEM; pass: PIdAnsiChar; passlen: TIdC_INT; oct: PASN1_OCTET_STRING; zbuf: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_item_decrypt_d2i_procname);
end;

function ERR_PKCS12_item_decrypt_d2i_ex(algor: PX509_ALGOR; it: PASN1_ITEM; pass: PIdAnsiChar; passlen: TIdC_INT; oct: PASN1_OCTET_STRING; zbuf: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_item_decrypt_d2i_ex_procname);
end;

function ERR_PKCS12_item_i2d_encrypt(algor: PX509_ALGOR; it: PASN1_ITEM; pass: PIdAnsiChar; passlen: TIdC_INT; obj: Pointer; zbuf: TIdC_INT): PASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_item_i2d_encrypt_procname);
end;

function ERR_PKCS12_item_i2d_encrypt_ex(algor: PX509_ALGOR; it: PASN1_ITEM; pass: PIdAnsiChar; passlen: TIdC_INT; obj: Pointer; zbuf: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_item_i2d_encrypt_ex_procname);
end;

function ERR_PKCS12_init(mode: TIdC_INT): PPKCS12; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_init_procname);
end;

function ERR_PKCS12_init_ex(mode: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS12; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_init_ex_procname);
end;

function ERR_PKCS12_key_gen_asc(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_key_gen_asc_procname);
end;

function ERR_PKCS12_key_gen_asc_ex(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_key_gen_asc_ex_procname);
end;

function ERR_PKCS12_key_gen_uni(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_key_gen_uni_procname);
end;

function ERR_PKCS12_key_gen_uni_ex(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_key_gen_uni_ex_procname);
end;

function ERR_PKCS12_key_gen_utf8(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_key_gen_utf8_procname);
end;

function ERR_PKCS12_key_gen_utf8_ex(pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; _out: PIdAnsiChar; md_type: PEVP_MD; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_key_gen_utf8_ex_procname);
end;

function ERR_PKCS12_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; pass: PIdAnsiChar; passlen: TIdC_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md_type: PEVP_MD; en_de: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_PBE_keyivgen_procname);
end;

function ERR_PKCS12_PBE_keyivgen_ex(ctx: PEVP_CIPHER_CTX; pass: PIdAnsiChar; passlen: TIdC_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md_type: PEVP_MD; en_de: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_PBE_keyivgen_ex_procname);
end;

function ERR_PKCS12_gen_mac(p12: PPKCS12; pass: PIdAnsiChar; passlen: TIdC_INT; mac: PIdAnsiChar; maclen: PIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_gen_mac_procname);
end;

function ERR_PKCS12_verify_mac(p12: PPKCS12; pass: PIdAnsiChar; passlen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_verify_mac_procname);
end;

function ERR_PKCS12_set_mac(p12: PPKCS12; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; md_type: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_set_mac_procname);
end;

function ERR_PKCS12_set_pbmac1_pbkdf2(p12: PPKCS12; pass: PIdAnsiChar; passlen: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; iter: TIdC_INT; md_type: PEVP_MD; prf_md_name: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_set_pbmac1_pbkdf2_procname);
end;

function ERR_PKCS12_setup_mac(p12: PPKCS12; iter: TIdC_INT; salt: PIdAnsiChar; saltlen: TIdC_INT; md_type: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_setup_mac_procname);
end;

function ERR_OPENSSL_asc2uni(asc: PIdAnsiChar; asclen: TIdC_INT; uni: PPIdAnsiChar; unilen: PIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_asc2uni_procname);
end;

function ERR_OPENSSL_uni2asc(uni: PIdAnsiChar; unilen: TIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_uni2asc_procname);
end;

function ERR_OPENSSL_utf82uni(asc: PIdAnsiChar; asclen: TIdC_INT; uni: PPIdAnsiChar; unilen: PIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_utf82uni_procname);
end;

function ERR_OPENSSL_uni2utf8(uni: PIdAnsiChar; unilen: TIdC_INT): PIdAnsiChar; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_uni2utf8_procname);
end;

function ERR_PKCS12_new: PPKCS12; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_new_procname);
end;

procedure ERR_PKCS12_free(a: PPKCS12); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_free_procname);
end;

function ERR_d2i_PKCS12(a: PPPKCS12; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS12; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS12_procname);
end;

function ERR_i2d_PKCS12(a: PPKCS12; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS12_procname);
end;

function ERR_PKCS12_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_it_procname);
end;

function ERR_PKCS12_MAC_DATA_new: PPKCS12_MAC_DATA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_MAC_DATA_new_procname);
end;

procedure ERR_PKCS12_MAC_DATA_free(a: PPKCS12_MAC_DATA); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_MAC_DATA_free_procname);
end;

function ERR_d2i_PKCS12_MAC_DATA(a: PPPKCS12_MAC_DATA; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS12_MAC_DATA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS12_MAC_DATA_procname);
end;

function ERR_i2d_PKCS12_MAC_DATA(a: PPKCS12_MAC_DATA; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS12_MAC_DATA_procname);
end;

function ERR_PKCS12_MAC_DATA_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_MAC_DATA_it_procname);
end;

function ERR_PKCS12_SAFEBAG_new: PPKCS12_SAFEBAG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_new_procname);
end;

procedure ERR_PKCS12_SAFEBAG_free(a: PPKCS12_SAFEBAG); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_free_procname);
end;

function ERR_d2i_PKCS12_SAFEBAG(a: PPPKCS12_SAFEBAG; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS12_SAFEBAG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS12_SAFEBAG_procname);
end;

function ERR_i2d_PKCS12_SAFEBAG(a: PPKCS12_SAFEBAG; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS12_SAFEBAG_procname);
end;

function ERR_PKCS12_SAFEBAG_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_it_procname);
end;

function ERR_PKCS12_BAGS_new: PPKCS12_BAGS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_BAGS_new_procname);
end;

procedure ERR_PKCS12_BAGS_free(a: PPKCS12_BAGS); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_BAGS_free_procname);
end;

function ERR_d2i_PKCS12_BAGS(a: PPPKCS12_BAGS; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS12_BAGS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS12_BAGS_procname);
end;

function ERR_i2d_PKCS12_BAGS(a: PPKCS12_BAGS; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS12_BAGS_procname);
end;

function ERR_PKCS12_BAGS_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_BAGS_it_procname);
end;

function ERR_PKCS12_SAFEBAGS_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAGS_it_procname);
end;

function ERR_PKCS12_AUTHSAFES_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_AUTHSAFES_it_procname);
end;

procedure ERR_PKCS12_PBE_add; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_PBE_add_procname);
end;

function ERR_PKCS12_parse(p12: PPKCS12; pass: PIdAnsiChar; pkey: PPEVP_PKEY; cert: PPX509; ca: PPstack_st_X509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_parse_procname);
end;

function ERR_PKCS12_create(pass: PIdAnsiChar; name: PIdAnsiChar; pkey: PEVP_PKEY; cert: PX509; ca: Pstack_st_X509; nid_key: TIdC_INT; nid_cert: TIdC_INT; iter: TIdC_INT; mac_iter: TIdC_INT; keytype: TIdC_INT): PPKCS12; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_create_procname);
end;

function ERR_PKCS12_create_ex(pass: PIdAnsiChar; name: PIdAnsiChar; pkey: PEVP_PKEY; cert: PX509; ca: Pstack_st_X509; nid_key: TIdC_INT; nid_cert: TIdC_INT; iter: TIdC_INT; mac_iter: TIdC_INT; keytype: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS12; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_create_ex_procname);
end;

function ERR_PKCS12_create_ex2(pass: PIdAnsiChar; name: PIdAnsiChar; pkey: PEVP_PKEY; cert: PX509; ca: Pstack_st_X509; nid_key: TIdC_INT; nid_cert: TIdC_INT; iter: TIdC_INT; mac_iter: TIdC_INT; keytype: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar; cb: TPKCS12_create_cb_func_cb; cbarg: Pointer): PPKCS12; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_create_ex2_procname);
end;

function ERR_PKCS12_add_cert(pbags: PPstack_st_PKCS12_SAFEBAG; cert: PX509): PPKCS12_SAFEBAG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_add_cert_procname);
end;

function ERR_PKCS12_add_key(pbags: PPstack_st_PKCS12_SAFEBAG; key: PEVP_PKEY; key_usage: TIdC_INT; iter: TIdC_INT; key_nid: TIdC_INT; pass: PIdAnsiChar): PPKCS12_SAFEBAG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_add_key_procname);
end;

function ERR_PKCS12_add_key_ex(pbags: PPstack_st_PKCS12_SAFEBAG; key: PEVP_PKEY; key_usage: TIdC_INT; iter: TIdC_INT; key_nid: TIdC_INT; pass: PIdAnsiChar; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS12_SAFEBAG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_add_key_ex_procname);
end;

function ERR_PKCS12_add_secret(pbags: PPstack_st_PKCS12_SAFEBAG; nid_type: TIdC_INT; value: PIdAnsiChar; len: TIdC_INT): PPKCS12_SAFEBAG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_add_secret_procname);
end;

function ERR_PKCS12_add_safe(psafes: PPstack_st_PKCS7; bags: Pstack_st_PKCS12_SAFEBAG; safe_nid: TIdC_INT; iter: TIdC_INT; pass: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_add_safe_procname);
end;

function ERR_PKCS12_add_safe_ex(psafes: PPstack_st_PKCS7; bags: Pstack_st_PKCS12_SAFEBAG; safe_nid: TIdC_INT; iter: TIdC_INT; pass: PIdAnsiChar; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_add_safe_ex_procname);
end;

function ERR_PKCS12_add_safes(safes: Pstack_st_PKCS7; p7_nid: TIdC_INT): PPKCS12; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_add_safes_procname);
end;

function ERR_PKCS12_add_safes_ex(safes: Pstack_st_PKCS7; p7_nid: TIdC_INT; ctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS12; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_add_safes_ex_procname);
end;

function ERR_i2d_PKCS12_bio(bp: PBIO; p12: PPKCS12): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS12_bio_procname);
end;

function ERR_i2d_PKCS12_fp(fp: PFILE; p12: PPKCS12): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS12_fp_procname);
end;

function ERR_d2i_PKCS12_bio(bp: PBIO; p12: PPPKCS12): PPKCS12; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS12_bio_procname);
end;

function ERR_d2i_PKCS12_fp(fp: PFILE; p12: PPPKCS12): PPKCS12; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS12_fp_procname);
end;

function ERR_PKCS12_newpass(p12: PPKCS12; oldpass: PIdAnsiChar; newpass: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_newpass_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  
  PKCS8_get_attr := LoadLibFunction(ADllHandle, PKCS8_get_attr_procname);
  FuncLoadError := not assigned(PKCS8_get_attr);
  if FuncLoadError then
  begin
    {$if not defined(PKCS8_get_attr_allownil)}
    PKCS8_get_attr := ERR_PKCS8_get_attr;
    {$ifend}
    {$if declared(PKCS8_get_attr_introduced)}
    if LibVersion < PKCS8_get_attr_introduced then
    begin
      {$if declared(FC_PKCS8_get_attr)}
      PKCS8_get_attr := FC_PKCS8_get_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS8_get_attr_removed)}
    if PKCS8_get_attr_removed <= LibVersion then
    begin
      {$if declared(_PKCS8_get_attr)}
      PKCS8_get_attr := _PKCS8_get_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS8_get_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS8_get_attr');
    {$ifend}
  end;
  
  PKCS12_mac_present := LoadLibFunction(ADllHandle, PKCS12_mac_present_procname);
  FuncLoadError := not assigned(PKCS12_mac_present);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_mac_present_allownil)}
    PKCS12_mac_present := ERR_PKCS12_mac_present;
    {$ifend}
    {$if declared(PKCS12_mac_present_introduced)}
    if LibVersion < PKCS12_mac_present_introduced then
    begin
      {$if declared(FC_PKCS12_mac_present)}
      PKCS12_mac_present := FC_PKCS12_mac_present;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_mac_present_removed)}
    if PKCS12_mac_present_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_mac_present)}
      PKCS12_mac_present := _PKCS12_mac_present;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_mac_present_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_mac_present');
    {$ifend}
  end;
  
  PKCS12_get0_mac := LoadLibFunction(ADllHandle, PKCS12_get0_mac_procname);
  FuncLoadError := not assigned(PKCS12_get0_mac);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_get0_mac_allownil)}
    PKCS12_get0_mac := ERR_PKCS12_get0_mac;
    {$ifend}
    {$if declared(PKCS12_get0_mac_introduced)}
    if LibVersion < PKCS12_get0_mac_introduced then
    begin
      {$if declared(FC_PKCS12_get0_mac)}
      PKCS12_get0_mac := FC_PKCS12_get0_mac;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_get0_mac_removed)}
    if PKCS12_get0_mac_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_get0_mac)}
      PKCS12_get0_mac := _PKCS12_get0_mac;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_get0_mac_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_get0_mac');
    {$ifend}
  end;
  
  PKCS12_SAFEBAG_get0_attr := LoadLibFunction(ADllHandle, PKCS12_SAFEBAG_get0_attr_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAG_get0_attr);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAG_get0_attr_allownil)}
    PKCS12_SAFEBAG_get0_attr := ERR_PKCS12_SAFEBAG_get0_attr;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get0_attr_introduced)}
    if LibVersion < PKCS12_SAFEBAG_get0_attr_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAG_get0_attr)}
      PKCS12_SAFEBAG_get0_attr := FC_PKCS12_SAFEBAG_get0_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get0_attr_removed)}
    if PKCS12_SAFEBAG_get0_attr_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAG_get0_attr)}
      PKCS12_SAFEBAG_get0_attr := _PKCS12_SAFEBAG_get0_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAG_get0_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAG_get0_attr');
    {$ifend}
  end;
  
  PKCS12_SAFEBAG_get0_type := LoadLibFunction(ADllHandle, PKCS12_SAFEBAG_get0_type_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAG_get0_type);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAG_get0_type_allownil)}
    PKCS12_SAFEBAG_get0_type := ERR_PKCS12_SAFEBAG_get0_type;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get0_type_introduced)}
    if LibVersion < PKCS12_SAFEBAG_get0_type_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAG_get0_type)}
      PKCS12_SAFEBAG_get0_type := FC_PKCS12_SAFEBAG_get0_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get0_type_removed)}
    if PKCS12_SAFEBAG_get0_type_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAG_get0_type)}
      PKCS12_SAFEBAG_get0_type := _PKCS12_SAFEBAG_get0_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAG_get0_type_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAG_get0_type');
    {$ifend}
  end;
  
  PKCS12_SAFEBAG_get_nid := LoadLibFunction(ADllHandle, PKCS12_SAFEBAG_get_nid_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAG_get_nid);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAG_get_nid_allownil)}
    PKCS12_SAFEBAG_get_nid := ERR_PKCS12_SAFEBAG_get_nid;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get_nid_introduced)}
    if LibVersion < PKCS12_SAFEBAG_get_nid_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAG_get_nid)}
      PKCS12_SAFEBAG_get_nid := FC_PKCS12_SAFEBAG_get_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get_nid_removed)}
    if PKCS12_SAFEBAG_get_nid_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAG_get_nid)}
      PKCS12_SAFEBAG_get_nid := _PKCS12_SAFEBAG_get_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAG_get_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAG_get_nid');
    {$ifend}
  end;
  
  PKCS12_SAFEBAG_get_bag_nid := LoadLibFunction(ADllHandle, PKCS12_SAFEBAG_get_bag_nid_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAG_get_bag_nid);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAG_get_bag_nid_allownil)}
    PKCS12_SAFEBAG_get_bag_nid := ERR_PKCS12_SAFEBAG_get_bag_nid;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get_bag_nid_introduced)}
    if LibVersion < PKCS12_SAFEBAG_get_bag_nid_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAG_get_bag_nid)}
      PKCS12_SAFEBAG_get_bag_nid := FC_PKCS12_SAFEBAG_get_bag_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get_bag_nid_removed)}
    if PKCS12_SAFEBAG_get_bag_nid_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAG_get_bag_nid)}
      PKCS12_SAFEBAG_get_bag_nid := _PKCS12_SAFEBAG_get_bag_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAG_get_bag_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAG_get_bag_nid');
    {$ifend}
  end;
  
  PKCS12_SAFEBAG_get0_bag_obj := LoadLibFunction(ADllHandle, PKCS12_SAFEBAG_get0_bag_obj_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAG_get0_bag_obj);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAG_get0_bag_obj_allownil)}
    PKCS12_SAFEBAG_get0_bag_obj := ERR_PKCS12_SAFEBAG_get0_bag_obj;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get0_bag_obj_introduced)}
    if LibVersion < PKCS12_SAFEBAG_get0_bag_obj_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAG_get0_bag_obj)}
      PKCS12_SAFEBAG_get0_bag_obj := FC_PKCS12_SAFEBAG_get0_bag_obj;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get0_bag_obj_removed)}
    if PKCS12_SAFEBAG_get0_bag_obj_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAG_get0_bag_obj)}
      PKCS12_SAFEBAG_get0_bag_obj := _PKCS12_SAFEBAG_get0_bag_obj;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAG_get0_bag_obj_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAG_get0_bag_obj');
    {$ifend}
  end;
  
  PKCS12_SAFEBAG_get0_bag_type := LoadLibFunction(ADllHandle, PKCS12_SAFEBAG_get0_bag_type_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAG_get0_bag_type);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAG_get0_bag_type_allownil)}
    PKCS12_SAFEBAG_get0_bag_type := ERR_PKCS12_SAFEBAG_get0_bag_type;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get0_bag_type_introduced)}
    if LibVersion < PKCS12_SAFEBAG_get0_bag_type_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAG_get0_bag_type)}
      PKCS12_SAFEBAG_get0_bag_type := FC_PKCS12_SAFEBAG_get0_bag_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get0_bag_type_removed)}
    if PKCS12_SAFEBAG_get0_bag_type_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAG_get0_bag_type)}
      PKCS12_SAFEBAG_get0_bag_type := _PKCS12_SAFEBAG_get0_bag_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAG_get0_bag_type_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAG_get0_bag_type');
    {$ifend}
  end;
  
  PKCS12_SAFEBAG_get1_cert_ex := LoadLibFunction(ADllHandle, PKCS12_SAFEBAG_get1_cert_ex_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAG_get1_cert_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAG_get1_cert_ex_allownil)}
    PKCS12_SAFEBAG_get1_cert_ex := ERR_PKCS12_SAFEBAG_get1_cert_ex;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get1_cert_ex_introduced)}
    if LibVersion < PKCS12_SAFEBAG_get1_cert_ex_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAG_get1_cert_ex)}
      PKCS12_SAFEBAG_get1_cert_ex := FC_PKCS12_SAFEBAG_get1_cert_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get1_cert_ex_removed)}
    if PKCS12_SAFEBAG_get1_cert_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAG_get1_cert_ex)}
      PKCS12_SAFEBAG_get1_cert_ex := _PKCS12_SAFEBAG_get1_cert_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAG_get1_cert_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAG_get1_cert_ex');
    {$ifend}
  end;
  
  PKCS12_SAFEBAG_get1_cert := LoadLibFunction(ADllHandle, PKCS12_SAFEBAG_get1_cert_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAG_get1_cert);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAG_get1_cert_allownil)}
    PKCS12_SAFEBAG_get1_cert := ERR_PKCS12_SAFEBAG_get1_cert;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get1_cert_introduced)}
    if LibVersion < PKCS12_SAFEBAG_get1_cert_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAG_get1_cert)}
      PKCS12_SAFEBAG_get1_cert := FC_PKCS12_SAFEBAG_get1_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get1_cert_removed)}
    if PKCS12_SAFEBAG_get1_cert_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAG_get1_cert)}
      PKCS12_SAFEBAG_get1_cert := _PKCS12_SAFEBAG_get1_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAG_get1_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAG_get1_cert');
    {$ifend}
  end;
  
  PKCS12_SAFEBAG_get1_crl_ex := LoadLibFunction(ADllHandle, PKCS12_SAFEBAG_get1_crl_ex_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAG_get1_crl_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAG_get1_crl_ex_allownil)}
    PKCS12_SAFEBAG_get1_crl_ex := ERR_PKCS12_SAFEBAG_get1_crl_ex;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get1_crl_ex_introduced)}
    if LibVersion < PKCS12_SAFEBAG_get1_crl_ex_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAG_get1_crl_ex)}
      PKCS12_SAFEBAG_get1_crl_ex := FC_PKCS12_SAFEBAG_get1_crl_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get1_crl_ex_removed)}
    if PKCS12_SAFEBAG_get1_crl_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAG_get1_crl_ex)}
      PKCS12_SAFEBAG_get1_crl_ex := _PKCS12_SAFEBAG_get1_crl_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAG_get1_crl_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAG_get1_crl_ex');
    {$ifend}
  end;
  
  PKCS12_SAFEBAG_get1_crl := LoadLibFunction(ADllHandle, PKCS12_SAFEBAG_get1_crl_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAG_get1_crl);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAG_get1_crl_allownil)}
    PKCS12_SAFEBAG_get1_crl := ERR_PKCS12_SAFEBAG_get1_crl;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get1_crl_introduced)}
    if LibVersion < PKCS12_SAFEBAG_get1_crl_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAG_get1_crl)}
      PKCS12_SAFEBAG_get1_crl := FC_PKCS12_SAFEBAG_get1_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get1_crl_removed)}
    if PKCS12_SAFEBAG_get1_crl_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAG_get1_crl)}
      PKCS12_SAFEBAG_get1_crl := _PKCS12_SAFEBAG_get1_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAG_get1_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAG_get1_crl');
    {$ifend}
  end;
  
  PKCS12_SAFEBAG_get0_safes := LoadLibFunction(ADllHandle, PKCS12_SAFEBAG_get0_safes_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAG_get0_safes);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAG_get0_safes_allownil)}
    PKCS12_SAFEBAG_get0_safes := ERR_PKCS12_SAFEBAG_get0_safes;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get0_safes_introduced)}
    if LibVersion < PKCS12_SAFEBAG_get0_safes_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAG_get0_safes)}
      PKCS12_SAFEBAG_get0_safes := FC_PKCS12_SAFEBAG_get0_safes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get0_safes_removed)}
    if PKCS12_SAFEBAG_get0_safes_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAG_get0_safes)}
      PKCS12_SAFEBAG_get0_safes := _PKCS12_SAFEBAG_get0_safes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAG_get0_safes_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAG_get0_safes');
    {$ifend}
  end;
  
  PKCS12_SAFEBAG_get0_p8inf := LoadLibFunction(ADllHandle, PKCS12_SAFEBAG_get0_p8inf_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAG_get0_p8inf);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAG_get0_p8inf_allownil)}
    PKCS12_SAFEBAG_get0_p8inf := ERR_PKCS12_SAFEBAG_get0_p8inf;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get0_p8inf_introduced)}
    if LibVersion < PKCS12_SAFEBAG_get0_p8inf_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAG_get0_p8inf)}
      PKCS12_SAFEBAG_get0_p8inf := FC_PKCS12_SAFEBAG_get0_p8inf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get0_p8inf_removed)}
    if PKCS12_SAFEBAG_get0_p8inf_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAG_get0_p8inf)}
      PKCS12_SAFEBAG_get0_p8inf := _PKCS12_SAFEBAG_get0_p8inf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAG_get0_p8inf_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAG_get0_p8inf');
    {$ifend}
  end;
  
  PKCS12_SAFEBAG_get0_pkcs8 := LoadLibFunction(ADllHandle, PKCS12_SAFEBAG_get0_pkcs8_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAG_get0_pkcs8);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAG_get0_pkcs8_allownil)}
    PKCS12_SAFEBAG_get0_pkcs8 := ERR_PKCS12_SAFEBAG_get0_pkcs8;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get0_pkcs8_introduced)}
    if LibVersion < PKCS12_SAFEBAG_get0_pkcs8_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAG_get0_pkcs8)}
      PKCS12_SAFEBAG_get0_pkcs8 := FC_PKCS12_SAFEBAG_get0_pkcs8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get0_pkcs8_removed)}
    if PKCS12_SAFEBAG_get0_pkcs8_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAG_get0_pkcs8)}
      PKCS12_SAFEBAG_get0_pkcs8 := _PKCS12_SAFEBAG_get0_pkcs8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAG_get0_pkcs8_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAG_get0_pkcs8');
    {$ifend}
  end;
  
  PKCS12_SAFEBAG_create_cert := LoadLibFunction(ADllHandle, PKCS12_SAFEBAG_create_cert_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAG_create_cert);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAG_create_cert_allownil)}
    PKCS12_SAFEBAG_create_cert := ERR_PKCS12_SAFEBAG_create_cert;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_create_cert_introduced)}
    if LibVersion < PKCS12_SAFEBAG_create_cert_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAG_create_cert)}
      PKCS12_SAFEBAG_create_cert := FC_PKCS12_SAFEBAG_create_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_create_cert_removed)}
    if PKCS12_SAFEBAG_create_cert_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAG_create_cert)}
      PKCS12_SAFEBAG_create_cert := _PKCS12_SAFEBAG_create_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAG_create_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAG_create_cert');
    {$ifend}
  end;
  
  PKCS12_SAFEBAG_create_crl := LoadLibFunction(ADllHandle, PKCS12_SAFEBAG_create_crl_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAG_create_crl);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAG_create_crl_allownil)}
    PKCS12_SAFEBAG_create_crl := ERR_PKCS12_SAFEBAG_create_crl;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_create_crl_introduced)}
    if LibVersion < PKCS12_SAFEBAG_create_crl_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAG_create_crl)}
      PKCS12_SAFEBAG_create_crl := FC_PKCS12_SAFEBAG_create_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_create_crl_removed)}
    if PKCS12_SAFEBAG_create_crl_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAG_create_crl)}
      PKCS12_SAFEBAG_create_crl := _PKCS12_SAFEBAG_create_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAG_create_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAG_create_crl');
    {$ifend}
  end;
  
  PKCS12_SAFEBAG_create_secret := LoadLibFunction(ADllHandle, PKCS12_SAFEBAG_create_secret_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAG_create_secret);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAG_create_secret_allownil)}
    PKCS12_SAFEBAG_create_secret := ERR_PKCS12_SAFEBAG_create_secret;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_create_secret_introduced)}
    if LibVersion < PKCS12_SAFEBAG_create_secret_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAG_create_secret)}
      PKCS12_SAFEBAG_create_secret := FC_PKCS12_SAFEBAG_create_secret;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_create_secret_removed)}
    if PKCS12_SAFEBAG_create_secret_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAG_create_secret)}
      PKCS12_SAFEBAG_create_secret := _PKCS12_SAFEBAG_create_secret;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAG_create_secret_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAG_create_secret');
    {$ifend}
  end;
  
  PKCS12_SAFEBAG_create0_p8inf := LoadLibFunction(ADllHandle, PKCS12_SAFEBAG_create0_p8inf_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAG_create0_p8inf);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAG_create0_p8inf_allownil)}
    PKCS12_SAFEBAG_create0_p8inf := ERR_PKCS12_SAFEBAG_create0_p8inf;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_create0_p8inf_introduced)}
    if LibVersion < PKCS12_SAFEBAG_create0_p8inf_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAG_create0_p8inf)}
      PKCS12_SAFEBAG_create0_p8inf := FC_PKCS12_SAFEBAG_create0_p8inf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_create0_p8inf_removed)}
    if PKCS12_SAFEBAG_create0_p8inf_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAG_create0_p8inf)}
      PKCS12_SAFEBAG_create0_p8inf := _PKCS12_SAFEBAG_create0_p8inf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAG_create0_p8inf_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAG_create0_p8inf');
    {$ifend}
  end;
  
  PKCS12_SAFEBAG_create0_pkcs8 := LoadLibFunction(ADllHandle, PKCS12_SAFEBAG_create0_pkcs8_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAG_create0_pkcs8);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAG_create0_pkcs8_allownil)}
    PKCS12_SAFEBAG_create0_pkcs8 := ERR_PKCS12_SAFEBAG_create0_pkcs8;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_create0_pkcs8_introduced)}
    if LibVersion < PKCS12_SAFEBAG_create0_pkcs8_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAG_create0_pkcs8)}
      PKCS12_SAFEBAG_create0_pkcs8 := FC_PKCS12_SAFEBAG_create0_pkcs8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_create0_pkcs8_removed)}
    if PKCS12_SAFEBAG_create0_pkcs8_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAG_create0_pkcs8)}
      PKCS12_SAFEBAG_create0_pkcs8 := _PKCS12_SAFEBAG_create0_pkcs8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAG_create0_pkcs8_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAG_create0_pkcs8');
    {$ifend}
  end;
  
  PKCS12_SAFEBAG_create_pkcs8_encrypt := LoadLibFunction(ADllHandle, PKCS12_SAFEBAG_create_pkcs8_encrypt_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAG_create_pkcs8_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAG_create_pkcs8_encrypt_allownil)}
    PKCS12_SAFEBAG_create_pkcs8_encrypt := ERR_PKCS12_SAFEBAG_create_pkcs8_encrypt;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_create_pkcs8_encrypt_introduced)}
    if LibVersion < PKCS12_SAFEBAG_create_pkcs8_encrypt_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAG_create_pkcs8_encrypt)}
      PKCS12_SAFEBAG_create_pkcs8_encrypt := FC_PKCS12_SAFEBAG_create_pkcs8_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_create_pkcs8_encrypt_removed)}
    if PKCS12_SAFEBAG_create_pkcs8_encrypt_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAG_create_pkcs8_encrypt)}
      PKCS12_SAFEBAG_create_pkcs8_encrypt := _PKCS12_SAFEBAG_create_pkcs8_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAG_create_pkcs8_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAG_create_pkcs8_encrypt');
    {$ifend}
  end;
  
  PKCS12_SAFEBAG_create_pkcs8_encrypt_ex := LoadLibFunction(ADllHandle, PKCS12_SAFEBAG_create_pkcs8_encrypt_ex_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAG_create_pkcs8_encrypt_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAG_create_pkcs8_encrypt_ex_allownil)}
    PKCS12_SAFEBAG_create_pkcs8_encrypt_ex := ERR_PKCS12_SAFEBAG_create_pkcs8_encrypt_ex;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_create_pkcs8_encrypt_ex_introduced)}
    if LibVersion < PKCS12_SAFEBAG_create_pkcs8_encrypt_ex_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAG_create_pkcs8_encrypt_ex)}
      PKCS12_SAFEBAG_create_pkcs8_encrypt_ex := FC_PKCS12_SAFEBAG_create_pkcs8_encrypt_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_create_pkcs8_encrypt_ex_removed)}
    if PKCS12_SAFEBAG_create_pkcs8_encrypt_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAG_create_pkcs8_encrypt_ex)}
      PKCS12_SAFEBAG_create_pkcs8_encrypt_ex := _PKCS12_SAFEBAG_create_pkcs8_encrypt_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAG_create_pkcs8_encrypt_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAG_create_pkcs8_encrypt_ex');
    {$ifend}
  end;
  
  PKCS12_item_pack_safebag := LoadLibFunction(ADllHandle, PKCS12_item_pack_safebag_procname);
  FuncLoadError := not assigned(PKCS12_item_pack_safebag);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_item_pack_safebag_allownil)}
    PKCS12_item_pack_safebag := ERR_PKCS12_item_pack_safebag;
    {$ifend}
    {$if declared(PKCS12_item_pack_safebag_introduced)}
    if LibVersion < PKCS12_item_pack_safebag_introduced then
    begin
      {$if declared(FC_PKCS12_item_pack_safebag)}
      PKCS12_item_pack_safebag := FC_PKCS12_item_pack_safebag;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_item_pack_safebag_removed)}
    if PKCS12_item_pack_safebag_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_item_pack_safebag)}
      PKCS12_item_pack_safebag := _PKCS12_item_pack_safebag;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_item_pack_safebag_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_item_pack_safebag');
    {$ifend}
  end;
  
  PKCS8_decrypt := LoadLibFunction(ADllHandle, PKCS8_decrypt_procname);
  FuncLoadError := not assigned(PKCS8_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(PKCS8_decrypt_allownil)}
    PKCS8_decrypt := ERR_PKCS8_decrypt;
    {$ifend}
    {$if declared(PKCS8_decrypt_introduced)}
    if LibVersion < PKCS8_decrypt_introduced then
    begin
      {$if declared(FC_PKCS8_decrypt)}
      PKCS8_decrypt := FC_PKCS8_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS8_decrypt_removed)}
    if PKCS8_decrypt_removed <= LibVersion then
    begin
      {$if declared(_PKCS8_decrypt)}
      PKCS8_decrypt := _PKCS8_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS8_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS8_decrypt');
    {$ifend}
  end;
  
  PKCS8_decrypt_ex := LoadLibFunction(ADllHandle, PKCS8_decrypt_ex_procname);
  FuncLoadError := not assigned(PKCS8_decrypt_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS8_decrypt_ex_allownil)}
    PKCS8_decrypt_ex := ERR_PKCS8_decrypt_ex;
    {$ifend}
    {$if declared(PKCS8_decrypt_ex_introduced)}
    if LibVersion < PKCS8_decrypt_ex_introduced then
    begin
      {$if declared(FC_PKCS8_decrypt_ex)}
      PKCS8_decrypt_ex := FC_PKCS8_decrypt_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS8_decrypt_ex_removed)}
    if PKCS8_decrypt_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS8_decrypt_ex)}
      PKCS8_decrypt_ex := _PKCS8_decrypt_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS8_decrypt_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS8_decrypt_ex');
    {$ifend}
  end;
  
  PKCS12_decrypt_skey := LoadLibFunction(ADllHandle, PKCS12_decrypt_skey_procname);
  FuncLoadError := not assigned(PKCS12_decrypt_skey);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_decrypt_skey_allownil)}
    PKCS12_decrypt_skey := ERR_PKCS12_decrypt_skey;
    {$ifend}
    {$if declared(PKCS12_decrypt_skey_introduced)}
    if LibVersion < PKCS12_decrypt_skey_introduced then
    begin
      {$if declared(FC_PKCS12_decrypt_skey)}
      PKCS12_decrypt_skey := FC_PKCS12_decrypt_skey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_decrypt_skey_removed)}
    if PKCS12_decrypt_skey_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_decrypt_skey)}
      PKCS12_decrypt_skey := _PKCS12_decrypt_skey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_decrypt_skey_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_decrypt_skey');
    {$ifend}
  end;
  
  PKCS12_decrypt_skey_ex := LoadLibFunction(ADllHandle, PKCS12_decrypt_skey_ex_procname);
  FuncLoadError := not assigned(PKCS12_decrypt_skey_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_decrypt_skey_ex_allownil)}
    PKCS12_decrypt_skey_ex := ERR_PKCS12_decrypt_skey_ex;
    {$ifend}
    {$if declared(PKCS12_decrypt_skey_ex_introduced)}
    if LibVersion < PKCS12_decrypt_skey_ex_introduced then
    begin
      {$if declared(FC_PKCS12_decrypt_skey_ex)}
      PKCS12_decrypt_skey_ex := FC_PKCS12_decrypt_skey_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_decrypt_skey_ex_removed)}
    if PKCS12_decrypt_skey_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_decrypt_skey_ex)}
      PKCS12_decrypt_skey_ex := _PKCS12_decrypt_skey_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_decrypt_skey_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_decrypt_skey_ex');
    {$ifend}
  end;
  
  PKCS8_encrypt := LoadLibFunction(ADllHandle, PKCS8_encrypt_procname);
  FuncLoadError := not assigned(PKCS8_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(PKCS8_encrypt_allownil)}
    PKCS8_encrypt := ERR_PKCS8_encrypt;
    {$ifend}
    {$if declared(PKCS8_encrypt_introduced)}
    if LibVersion < PKCS8_encrypt_introduced then
    begin
      {$if declared(FC_PKCS8_encrypt)}
      PKCS8_encrypt := FC_PKCS8_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS8_encrypt_removed)}
    if PKCS8_encrypt_removed <= LibVersion then
    begin
      {$if declared(_PKCS8_encrypt)}
      PKCS8_encrypt := _PKCS8_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS8_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS8_encrypt');
    {$ifend}
  end;
  
  PKCS8_encrypt_ex := LoadLibFunction(ADllHandle, PKCS8_encrypt_ex_procname);
  FuncLoadError := not assigned(PKCS8_encrypt_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS8_encrypt_ex_allownil)}
    PKCS8_encrypt_ex := ERR_PKCS8_encrypt_ex;
    {$ifend}
    {$if declared(PKCS8_encrypt_ex_introduced)}
    if LibVersion < PKCS8_encrypt_ex_introduced then
    begin
      {$if declared(FC_PKCS8_encrypt_ex)}
      PKCS8_encrypt_ex := FC_PKCS8_encrypt_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS8_encrypt_ex_removed)}
    if PKCS8_encrypt_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS8_encrypt_ex)}
      PKCS8_encrypt_ex := _PKCS8_encrypt_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS8_encrypt_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS8_encrypt_ex');
    {$ifend}
  end;
  
  PKCS8_set0_pbe := LoadLibFunction(ADllHandle, PKCS8_set0_pbe_procname);
  FuncLoadError := not assigned(PKCS8_set0_pbe);
  if FuncLoadError then
  begin
    {$if not defined(PKCS8_set0_pbe_allownil)}
    PKCS8_set0_pbe := ERR_PKCS8_set0_pbe;
    {$ifend}
    {$if declared(PKCS8_set0_pbe_introduced)}
    if LibVersion < PKCS8_set0_pbe_introduced then
    begin
      {$if declared(FC_PKCS8_set0_pbe)}
      PKCS8_set0_pbe := FC_PKCS8_set0_pbe;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS8_set0_pbe_removed)}
    if PKCS8_set0_pbe_removed <= LibVersion then
    begin
      {$if declared(_PKCS8_set0_pbe)}
      PKCS8_set0_pbe := _PKCS8_set0_pbe;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS8_set0_pbe_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS8_set0_pbe');
    {$ifend}
  end;
  
  PKCS8_set0_pbe_ex := LoadLibFunction(ADllHandle, PKCS8_set0_pbe_ex_procname);
  FuncLoadError := not assigned(PKCS8_set0_pbe_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS8_set0_pbe_ex_allownil)}
    PKCS8_set0_pbe_ex := ERR_PKCS8_set0_pbe_ex;
    {$ifend}
    {$if declared(PKCS8_set0_pbe_ex_introduced)}
    if LibVersion < PKCS8_set0_pbe_ex_introduced then
    begin
      {$if declared(FC_PKCS8_set0_pbe_ex)}
      PKCS8_set0_pbe_ex := FC_PKCS8_set0_pbe_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS8_set0_pbe_ex_removed)}
    if PKCS8_set0_pbe_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS8_set0_pbe_ex)}
      PKCS8_set0_pbe_ex := _PKCS8_set0_pbe_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS8_set0_pbe_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS8_set0_pbe_ex');
    {$ifend}
  end;
  
  PKCS12_pack_p7data := LoadLibFunction(ADllHandle, PKCS12_pack_p7data_procname);
  FuncLoadError := not assigned(PKCS12_pack_p7data);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_pack_p7data_allownil)}
    PKCS12_pack_p7data := ERR_PKCS12_pack_p7data;
    {$ifend}
    {$if declared(PKCS12_pack_p7data_introduced)}
    if LibVersion < PKCS12_pack_p7data_introduced then
    begin
      {$if declared(FC_PKCS12_pack_p7data)}
      PKCS12_pack_p7data := FC_PKCS12_pack_p7data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_pack_p7data_removed)}
    if PKCS12_pack_p7data_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_pack_p7data)}
      PKCS12_pack_p7data := _PKCS12_pack_p7data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_pack_p7data_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_pack_p7data');
    {$ifend}
  end;
  
  PKCS12_unpack_p7data := LoadLibFunction(ADllHandle, PKCS12_unpack_p7data_procname);
  FuncLoadError := not assigned(PKCS12_unpack_p7data);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_unpack_p7data_allownil)}
    PKCS12_unpack_p7data := ERR_PKCS12_unpack_p7data;
    {$ifend}
    {$if declared(PKCS12_unpack_p7data_introduced)}
    if LibVersion < PKCS12_unpack_p7data_introduced then
    begin
      {$if declared(FC_PKCS12_unpack_p7data)}
      PKCS12_unpack_p7data := FC_PKCS12_unpack_p7data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_unpack_p7data_removed)}
    if PKCS12_unpack_p7data_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_unpack_p7data)}
      PKCS12_unpack_p7data := _PKCS12_unpack_p7data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_unpack_p7data_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_unpack_p7data');
    {$ifend}
  end;
  
  PKCS12_pack_p7encdata := LoadLibFunction(ADllHandle, PKCS12_pack_p7encdata_procname);
  FuncLoadError := not assigned(PKCS12_pack_p7encdata);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_pack_p7encdata_allownil)}
    PKCS12_pack_p7encdata := ERR_PKCS12_pack_p7encdata;
    {$ifend}
    {$if declared(PKCS12_pack_p7encdata_introduced)}
    if LibVersion < PKCS12_pack_p7encdata_introduced then
    begin
      {$if declared(FC_PKCS12_pack_p7encdata)}
      PKCS12_pack_p7encdata := FC_PKCS12_pack_p7encdata;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_pack_p7encdata_removed)}
    if PKCS12_pack_p7encdata_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_pack_p7encdata)}
      PKCS12_pack_p7encdata := _PKCS12_pack_p7encdata;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_pack_p7encdata_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_pack_p7encdata');
    {$ifend}
  end;
  
  PKCS12_pack_p7encdata_ex := LoadLibFunction(ADllHandle, PKCS12_pack_p7encdata_ex_procname);
  FuncLoadError := not assigned(PKCS12_pack_p7encdata_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_pack_p7encdata_ex_allownil)}
    PKCS12_pack_p7encdata_ex := ERR_PKCS12_pack_p7encdata_ex;
    {$ifend}
    {$if declared(PKCS12_pack_p7encdata_ex_introduced)}
    if LibVersion < PKCS12_pack_p7encdata_ex_introduced then
    begin
      {$if declared(FC_PKCS12_pack_p7encdata_ex)}
      PKCS12_pack_p7encdata_ex := FC_PKCS12_pack_p7encdata_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_pack_p7encdata_ex_removed)}
    if PKCS12_pack_p7encdata_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_pack_p7encdata_ex)}
      PKCS12_pack_p7encdata_ex := _PKCS12_pack_p7encdata_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_pack_p7encdata_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_pack_p7encdata_ex');
    {$ifend}
  end;
  
  PKCS12_unpack_p7encdata := LoadLibFunction(ADllHandle, PKCS12_unpack_p7encdata_procname);
  FuncLoadError := not assigned(PKCS12_unpack_p7encdata);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_unpack_p7encdata_allownil)}
    PKCS12_unpack_p7encdata := ERR_PKCS12_unpack_p7encdata;
    {$ifend}
    {$if declared(PKCS12_unpack_p7encdata_introduced)}
    if LibVersion < PKCS12_unpack_p7encdata_introduced then
    begin
      {$if declared(FC_PKCS12_unpack_p7encdata)}
      PKCS12_unpack_p7encdata := FC_PKCS12_unpack_p7encdata;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_unpack_p7encdata_removed)}
    if PKCS12_unpack_p7encdata_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_unpack_p7encdata)}
      PKCS12_unpack_p7encdata := _PKCS12_unpack_p7encdata;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_unpack_p7encdata_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_unpack_p7encdata');
    {$ifend}
  end;
  
  PKCS12_pack_authsafes := LoadLibFunction(ADllHandle, PKCS12_pack_authsafes_procname);
  FuncLoadError := not assigned(PKCS12_pack_authsafes);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_pack_authsafes_allownil)}
    PKCS12_pack_authsafes := ERR_PKCS12_pack_authsafes;
    {$ifend}
    {$if declared(PKCS12_pack_authsafes_introduced)}
    if LibVersion < PKCS12_pack_authsafes_introduced then
    begin
      {$if declared(FC_PKCS12_pack_authsafes)}
      PKCS12_pack_authsafes := FC_PKCS12_pack_authsafes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_pack_authsafes_removed)}
    if PKCS12_pack_authsafes_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_pack_authsafes)}
      PKCS12_pack_authsafes := _PKCS12_pack_authsafes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_pack_authsafes_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_pack_authsafes');
    {$ifend}
  end;
  
  PKCS12_unpack_authsafes := LoadLibFunction(ADllHandle, PKCS12_unpack_authsafes_procname);
  FuncLoadError := not assigned(PKCS12_unpack_authsafes);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_unpack_authsafes_allownil)}
    PKCS12_unpack_authsafes := ERR_PKCS12_unpack_authsafes;
    {$ifend}
    {$if declared(PKCS12_unpack_authsafes_introduced)}
    if LibVersion < PKCS12_unpack_authsafes_introduced then
    begin
      {$if declared(FC_PKCS12_unpack_authsafes)}
      PKCS12_unpack_authsafes := FC_PKCS12_unpack_authsafes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_unpack_authsafes_removed)}
    if PKCS12_unpack_authsafes_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_unpack_authsafes)}
      PKCS12_unpack_authsafes := _PKCS12_unpack_authsafes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_unpack_authsafes_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_unpack_authsafes');
    {$ifend}
  end;
  
  PKCS12_add_localkeyid := LoadLibFunction(ADllHandle, PKCS12_add_localkeyid_procname);
  FuncLoadError := not assigned(PKCS12_add_localkeyid);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_add_localkeyid_allownil)}
    PKCS12_add_localkeyid := ERR_PKCS12_add_localkeyid;
    {$ifend}
    {$if declared(PKCS12_add_localkeyid_introduced)}
    if LibVersion < PKCS12_add_localkeyid_introduced then
    begin
      {$if declared(FC_PKCS12_add_localkeyid)}
      PKCS12_add_localkeyid := FC_PKCS12_add_localkeyid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_add_localkeyid_removed)}
    if PKCS12_add_localkeyid_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_add_localkeyid)}
      PKCS12_add_localkeyid := _PKCS12_add_localkeyid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_add_localkeyid_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_add_localkeyid');
    {$ifend}
  end;
  
  PKCS12_add_friendlyname_asc := LoadLibFunction(ADllHandle, PKCS12_add_friendlyname_asc_procname);
  FuncLoadError := not assigned(PKCS12_add_friendlyname_asc);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_add_friendlyname_asc_allownil)}
    PKCS12_add_friendlyname_asc := ERR_PKCS12_add_friendlyname_asc;
    {$ifend}
    {$if declared(PKCS12_add_friendlyname_asc_introduced)}
    if LibVersion < PKCS12_add_friendlyname_asc_introduced then
    begin
      {$if declared(FC_PKCS12_add_friendlyname_asc)}
      PKCS12_add_friendlyname_asc := FC_PKCS12_add_friendlyname_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_add_friendlyname_asc_removed)}
    if PKCS12_add_friendlyname_asc_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_add_friendlyname_asc)}
      PKCS12_add_friendlyname_asc := _PKCS12_add_friendlyname_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_add_friendlyname_asc_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_add_friendlyname_asc');
    {$ifend}
  end;
  
  PKCS12_add_friendlyname_utf8 := LoadLibFunction(ADllHandle, PKCS12_add_friendlyname_utf8_procname);
  FuncLoadError := not assigned(PKCS12_add_friendlyname_utf8);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_add_friendlyname_utf8_allownil)}
    PKCS12_add_friendlyname_utf8 := ERR_PKCS12_add_friendlyname_utf8;
    {$ifend}
    {$if declared(PKCS12_add_friendlyname_utf8_introduced)}
    if LibVersion < PKCS12_add_friendlyname_utf8_introduced then
    begin
      {$if declared(FC_PKCS12_add_friendlyname_utf8)}
      PKCS12_add_friendlyname_utf8 := FC_PKCS12_add_friendlyname_utf8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_add_friendlyname_utf8_removed)}
    if PKCS12_add_friendlyname_utf8_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_add_friendlyname_utf8)}
      PKCS12_add_friendlyname_utf8 := _PKCS12_add_friendlyname_utf8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_add_friendlyname_utf8_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_add_friendlyname_utf8');
    {$ifend}
  end;
  
  PKCS12_add_CSPName_asc := LoadLibFunction(ADllHandle, PKCS12_add_CSPName_asc_procname);
  FuncLoadError := not assigned(PKCS12_add_CSPName_asc);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_add_CSPName_asc_allownil)}
    PKCS12_add_CSPName_asc := ERR_PKCS12_add_CSPName_asc;
    {$ifend}
    {$if declared(PKCS12_add_CSPName_asc_introduced)}
    if LibVersion < PKCS12_add_CSPName_asc_introduced then
    begin
      {$if declared(FC_PKCS12_add_CSPName_asc)}
      PKCS12_add_CSPName_asc := FC_PKCS12_add_CSPName_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_add_CSPName_asc_removed)}
    if PKCS12_add_CSPName_asc_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_add_CSPName_asc)}
      PKCS12_add_CSPName_asc := _PKCS12_add_CSPName_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_add_CSPName_asc_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_add_CSPName_asc');
    {$ifend}
  end;
  
  PKCS12_add_friendlyname_uni := LoadLibFunction(ADllHandle, PKCS12_add_friendlyname_uni_procname);
  FuncLoadError := not assigned(PKCS12_add_friendlyname_uni);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_add_friendlyname_uni_allownil)}
    PKCS12_add_friendlyname_uni := ERR_PKCS12_add_friendlyname_uni;
    {$ifend}
    {$if declared(PKCS12_add_friendlyname_uni_introduced)}
    if LibVersion < PKCS12_add_friendlyname_uni_introduced then
    begin
      {$if declared(FC_PKCS12_add_friendlyname_uni)}
      PKCS12_add_friendlyname_uni := FC_PKCS12_add_friendlyname_uni;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_add_friendlyname_uni_removed)}
    if PKCS12_add_friendlyname_uni_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_add_friendlyname_uni)}
      PKCS12_add_friendlyname_uni := _PKCS12_add_friendlyname_uni;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_add_friendlyname_uni_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_add_friendlyname_uni');
    {$ifend}
  end;
  
  PKCS12_add1_attr_by_NID := LoadLibFunction(ADllHandle, PKCS12_add1_attr_by_NID_procname);
  FuncLoadError := not assigned(PKCS12_add1_attr_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_add1_attr_by_NID_allownil)}
    PKCS12_add1_attr_by_NID := ERR_PKCS12_add1_attr_by_NID;
    {$ifend}
    {$if declared(PKCS12_add1_attr_by_NID_introduced)}
    if LibVersion < PKCS12_add1_attr_by_NID_introduced then
    begin
      {$if declared(FC_PKCS12_add1_attr_by_NID)}
      PKCS12_add1_attr_by_NID := FC_PKCS12_add1_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_add1_attr_by_NID_removed)}
    if PKCS12_add1_attr_by_NID_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_add1_attr_by_NID)}
      PKCS12_add1_attr_by_NID := _PKCS12_add1_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_add1_attr_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_add1_attr_by_NID');
    {$ifend}
  end;
  
  PKCS12_add1_attr_by_txt := LoadLibFunction(ADllHandle, PKCS12_add1_attr_by_txt_procname);
  FuncLoadError := not assigned(PKCS12_add1_attr_by_txt);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_add1_attr_by_txt_allownil)}
    PKCS12_add1_attr_by_txt := ERR_PKCS12_add1_attr_by_txt;
    {$ifend}
    {$if declared(PKCS12_add1_attr_by_txt_introduced)}
    if LibVersion < PKCS12_add1_attr_by_txt_introduced then
    begin
      {$if declared(FC_PKCS12_add1_attr_by_txt)}
      PKCS12_add1_attr_by_txt := FC_PKCS12_add1_attr_by_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_add1_attr_by_txt_removed)}
    if PKCS12_add1_attr_by_txt_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_add1_attr_by_txt)}
      PKCS12_add1_attr_by_txt := _PKCS12_add1_attr_by_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_add1_attr_by_txt_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_add1_attr_by_txt');
    {$ifend}
  end;
  
  PKCS8_add_keyusage := LoadLibFunction(ADllHandle, PKCS8_add_keyusage_procname);
  FuncLoadError := not assigned(PKCS8_add_keyusage);
  if FuncLoadError then
  begin
    {$if not defined(PKCS8_add_keyusage_allownil)}
    PKCS8_add_keyusage := ERR_PKCS8_add_keyusage;
    {$ifend}
    {$if declared(PKCS8_add_keyusage_introduced)}
    if LibVersion < PKCS8_add_keyusage_introduced then
    begin
      {$if declared(FC_PKCS8_add_keyusage)}
      PKCS8_add_keyusage := FC_PKCS8_add_keyusage;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS8_add_keyusage_removed)}
    if PKCS8_add_keyusage_removed <= LibVersion then
    begin
      {$if declared(_PKCS8_add_keyusage)}
      PKCS8_add_keyusage := _PKCS8_add_keyusage;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS8_add_keyusage_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS8_add_keyusage');
    {$ifend}
  end;
  
  PKCS12_get_attr_gen := LoadLibFunction(ADllHandle, PKCS12_get_attr_gen_procname);
  FuncLoadError := not assigned(PKCS12_get_attr_gen);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_get_attr_gen_allownil)}
    PKCS12_get_attr_gen := ERR_PKCS12_get_attr_gen;
    {$ifend}
    {$if declared(PKCS12_get_attr_gen_introduced)}
    if LibVersion < PKCS12_get_attr_gen_introduced then
    begin
      {$if declared(FC_PKCS12_get_attr_gen)}
      PKCS12_get_attr_gen := FC_PKCS12_get_attr_gen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_get_attr_gen_removed)}
    if PKCS12_get_attr_gen_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_get_attr_gen)}
      PKCS12_get_attr_gen := _PKCS12_get_attr_gen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_get_attr_gen_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_get_attr_gen');
    {$ifend}
  end;
  
  PKCS12_get_friendlyname := LoadLibFunction(ADllHandle, PKCS12_get_friendlyname_procname);
  FuncLoadError := not assigned(PKCS12_get_friendlyname);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_get_friendlyname_allownil)}
    PKCS12_get_friendlyname := ERR_PKCS12_get_friendlyname;
    {$ifend}
    {$if declared(PKCS12_get_friendlyname_introduced)}
    if LibVersion < PKCS12_get_friendlyname_introduced then
    begin
      {$if declared(FC_PKCS12_get_friendlyname)}
      PKCS12_get_friendlyname := FC_PKCS12_get_friendlyname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_get_friendlyname_removed)}
    if PKCS12_get_friendlyname_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_get_friendlyname)}
      PKCS12_get_friendlyname := _PKCS12_get_friendlyname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_get_friendlyname_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_get_friendlyname');
    {$ifend}
  end;
  
  PKCS12_SAFEBAG_get0_attrs := LoadLibFunction(ADllHandle, PKCS12_SAFEBAG_get0_attrs_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAG_get0_attrs);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAG_get0_attrs_allownil)}
    PKCS12_SAFEBAG_get0_attrs := ERR_PKCS12_SAFEBAG_get0_attrs;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get0_attrs_introduced)}
    if LibVersion < PKCS12_SAFEBAG_get0_attrs_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAG_get0_attrs)}
      PKCS12_SAFEBAG_get0_attrs := FC_PKCS12_SAFEBAG_get0_attrs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_get0_attrs_removed)}
    if PKCS12_SAFEBAG_get0_attrs_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAG_get0_attrs)}
      PKCS12_SAFEBAG_get0_attrs := _PKCS12_SAFEBAG_get0_attrs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAG_get0_attrs_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAG_get0_attrs');
    {$ifend}
  end;
  
  PKCS12_SAFEBAG_set0_attrs := LoadLibFunction(ADllHandle, PKCS12_SAFEBAG_set0_attrs_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAG_set0_attrs);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAG_set0_attrs_allownil)}
    PKCS12_SAFEBAG_set0_attrs := ERR_PKCS12_SAFEBAG_set0_attrs;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_set0_attrs_introduced)}
    if LibVersion < PKCS12_SAFEBAG_set0_attrs_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAG_set0_attrs)}
      PKCS12_SAFEBAG_set0_attrs := FC_PKCS12_SAFEBAG_set0_attrs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_set0_attrs_removed)}
    if PKCS12_SAFEBAG_set0_attrs_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAG_set0_attrs)}
      PKCS12_SAFEBAG_set0_attrs := _PKCS12_SAFEBAG_set0_attrs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAG_set0_attrs_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAG_set0_attrs');
    {$ifend}
  end;
  
  PKCS12_pbe_crypt := LoadLibFunction(ADllHandle, PKCS12_pbe_crypt_procname);
  FuncLoadError := not assigned(PKCS12_pbe_crypt);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_pbe_crypt_allownil)}
    PKCS12_pbe_crypt := ERR_PKCS12_pbe_crypt;
    {$ifend}
    {$if declared(PKCS12_pbe_crypt_introduced)}
    if LibVersion < PKCS12_pbe_crypt_introduced then
    begin
      {$if declared(FC_PKCS12_pbe_crypt)}
      PKCS12_pbe_crypt := FC_PKCS12_pbe_crypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_pbe_crypt_removed)}
    if PKCS12_pbe_crypt_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_pbe_crypt)}
      PKCS12_pbe_crypt := _PKCS12_pbe_crypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_pbe_crypt_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_pbe_crypt');
    {$ifend}
  end;
  
  PKCS12_pbe_crypt_ex := LoadLibFunction(ADllHandle, PKCS12_pbe_crypt_ex_procname);
  FuncLoadError := not assigned(PKCS12_pbe_crypt_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_pbe_crypt_ex_allownil)}
    PKCS12_pbe_crypt_ex := ERR_PKCS12_pbe_crypt_ex;
    {$ifend}
    {$if declared(PKCS12_pbe_crypt_ex_introduced)}
    if LibVersion < PKCS12_pbe_crypt_ex_introduced then
    begin
      {$if declared(FC_PKCS12_pbe_crypt_ex)}
      PKCS12_pbe_crypt_ex := FC_PKCS12_pbe_crypt_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_pbe_crypt_ex_removed)}
    if PKCS12_pbe_crypt_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_pbe_crypt_ex)}
      PKCS12_pbe_crypt_ex := _PKCS12_pbe_crypt_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_pbe_crypt_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_pbe_crypt_ex');
    {$ifend}
  end;
  
  PKCS12_item_decrypt_d2i := LoadLibFunction(ADllHandle, PKCS12_item_decrypt_d2i_procname);
  FuncLoadError := not assigned(PKCS12_item_decrypt_d2i);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_item_decrypt_d2i_allownil)}
    PKCS12_item_decrypt_d2i := ERR_PKCS12_item_decrypt_d2i;
    {$ifend}
    {$if declared(PKCS12_item_decrypt_d2i_introduced)}
    if LibVersion < PKCS12_item_decrypt_d2i_introduced then
    begin
      {$if declared(FC_PKCS12_item_decrypt_d2i)}
      PKCS12_item_decrypt_d2i := FC_PKCS12_item_decrypt_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_item_decrypt_d2i_removed)}
    if PKCS12_item_decrypt_d2i_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_item_decrypt_d2i)}
      PKCS12_item_decrypt_d2i := _PKCS12_item_decrypt_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_item_decrypt_d2i_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_item_decrypt_d2i');
    {$ifend}
  end;
  
  PKCS12_item_decrypt_d2i_ex := LoadLibFunction(ADllHandle, PKCS12_item_decrypt_d2i_ex_procname);
  FuncLoadError := not assigned(PKCS12_item_decrypt_d2i_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_item_decrypt_d2i_ex_allownil)}
    PKCS12_item_decrypt_d2i_ex := ERR_PKCS12_item_decrypt_d2i_ex;
    {$ifend}
    {$if declared(PKCS12_item_decrypt_d2i_ex_introduced)}
    if LibVersion < PKCS12_item_decrypt_d2i_ex_introduced then
    begin
      {$if declared(FC_PKCS12_item_decrypt_d2i_ex)}
      PKCS12_item_decrypt_d2i_ex := FC_PKCS12_item_decrypt_d2i_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_item_decrypt_d2i_ex_removed)}
    if PKCS12_item_decrypt_d2i_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_item_decrypt_d2i_ex)}
      PKCS12_item_decrypt_d2i_ex := _PKCS12_item_decrypt_d2i_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_item_decrypt_d2i_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_item_decrypt_d2i_ex');
    {$ifend}
  end;
  
  PKCS12_item_i2d_encrypt := LoadLibFunction(ADllHandle, PKCS12_item_i2d_encrypt_procname);
  FuncLoadError := not assigned(PKCS12_item_i2d_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_item_i2d_encrypt_allownil)}
    PKCS12_item_i2d_encrypt := ERR_PKCS12_item_i2d_encrypt;
    {$ifend}
    {$if declared(PKCS12_item_i2d_encrypt_introduced)}
    if LibVersion < PKCS12_item_i2d_encrypt_introduced then
    begin
      {$if declared(FC_PKCS12_item_i2d_encrypt)}
      PKCS12_item_i2d_encrypt := FC_PKCS12_item_i2d_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_item_i2d_encrypt_removed)}
    if PKCS12_item_i2d_encrypt_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_item_i2d_encrypt)}
      PKCS12_item_i2d_encrypt := _PKCS12_item_i2d_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_item_i2d_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_item_i2d_encrypt');
    {$ifend}
  end;
  
  PKCS12_item_i2d_encrypt_ex := LoadLibFunction(ADllHandle, PKCS12_item_i2d_encrypt_ex_procname);
  FuncLoadError := not assigned(PKCS12_item_i2d_encrypt_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_item_i2d_encrypt_ex_allownil)}
    PKCS12_item_i2d_encrypt_ex := ERR_PKCS12_item_i2d_encrypt_ex;
    {$ifend}
    {$if declared(PKCS12_item_i2d_encrypt_ex_introduced)}
    if LibVersion < PKCS12_item_i2d_encrypt_ex_introduced then
    begin
      {$if declared(FC_PKCS12_item_i2d_encrypt_ex)}
      PKCS12_item_i2d_encrypt_ex := FC_PKCS12_item_i2d_encrypt_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_item_i2d_encrypt_ex_removed)}
    if PKCS12_item_i2d_encrypt_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_item_i2d_encrypt_ex)}
      PKCS12_item_i2d_encrypt_ex := _PKCS12_item_i2d_encrypt_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_item_i2d_encrypt_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_item_i2d_encrypt_ex');
    {$ifend}
  end;
  
  PKCS12_init := LoadLibFunction(ADllHandle, PKCS12_init_procname);
  FuncLoadError := not assigned(PKCS12_init);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_init_allownil)}
    PKCS12_init := ERR_PKCS12_init;
    {$ifend}
    {$if declared(PKCS12_init_introduced)}
    if LibVersion < PKCS12_init_introduced then
    begin
      {$if declared(FC_PKCS12_init)}
      PKCS12_init := FC_PKCS12_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_init_removed)}
    if PKCS12_init_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_init)}
      PKCS12_init := _PKCS12_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_init_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_init');
    {$ifend}
  end;
  
  PKCS12_init_ex := LoadLibFunction(ADllHandle, PKCS12_init_ex_procname);
  FuncLoadError := not assigned(PKCS12_init_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_init_ex_allownil)}
    PKCS12_init_ex := ERR_PKCS12_init_ex;
    {$ifend}
    {$if declared(PKCS12_init_ex_introduced)}
    if LibVersion < PKCS12_init_ex_introduced then
    begin
      {$if declared(FC_PKCS12_init_ex)}
      PKCS12_init_ex := FC_PKCS12_init_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_init_ex_removed)}
    if PKCS12_init_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_init_ex)}
      PKCS12_init_ex := _PKCS12_init_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_init_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_init_ex');
    {$ifend}
  end;
  
  PKCS12_key_gen_asc := LoadLibFunction(ADllHandle, PKCS12_key_gen_asc_procname);
  FuncLoadError := not assigned(PKCS12_key_gen_asc);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_key_gen_asc_allownil)}
    PKCS12_key_gen_asc := ERR_PKCS12_key_gen_asc;
    {$ifend}
    {$if declared(PKCS12_key_gen_asc_introduced)}
    if LibVersion < PKCS12_key_gen_asc_introduced then
    begin
      {$if declared(FC_PKCS12_key_gen_asc)}
      PKCS12_key_gen_asc := FC_PKCS12_key_gen_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_key_gen_asc_removed)}
    if PKCS12_key_gen_asc_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_key_gen_asc)}
      PKCS12_key_gen_asc := _PKCS12_key_gen_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_key_gen_asc_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_key_gen_asc');
    {$ifend}
  end;
  
  PKCS12_key_gen_asc_ex := LoadLibFunction(ADllHandle, PKCS12_key_gen_asc_ex_procname);
  FuncLoadError := not assigned(PKCS12_key_gen_asc_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_key_gen_asc_ex_allownil)}
    PKCS12_key_gen_asc_ex := ERR_PKCS12_key_gen_asc_ex;
    {$ifend}
    {$if declared(PKCS12_key_gen_asc_ex_introduced)}
    if LibVersion < PKCS12_key_gen_asc_ex_introduced then
    begin
      {$if declared(FC_PKCS12_key_gen_asc_ex)}
      PKCS12_key_gen_asc_ex := FC_PKCS12_key_gen_asc_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_key_gen_asc_ex_removed)}
    if PKCS12_key_gen_asc_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_key_gen_asc_ex)}
      PKCS12_key_gen_asc_ex := _PKCS12_key_gen_asc_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_key_gen_asc_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_key_gen_asc_ex');
    {$ifend}
  end;
  
  PKCS12_key_gen_uni := LoadLibFunction(ADllHandle, PKCS12_key_gen_uni_procname);
  FuncLoadError := not assigned(PKCS12_key_gen_uni);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_key_gen_uni_allownil)}
    PKCS12_key_gen_uni := ERR_PKCS12_key_gen_uni;
    {$ifend}
    {$if declared(PKCS12_key_gen_uni_introduced)}
    if LibVersion < PKCS12_key_gen_uni_introduced then
    begin
      {$if declared(FC_PKCS12_key_gen_uni)}
      PKCS12_key_gen_uni := FC_PKCS12_key_gen_uni;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_key_gen_uni_removed)}
    if PKCS12_key_gen_uni_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_key_gen_uni)}
      PKCS12_key_gen_uni := _PKCS12_key_gen_uni;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_key_gen_uni_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_key_gen_uni');
    {$ifend}
  end;
  
  PKCS12_key_gen_uni_ex := LoadLibFunction(ADllHandle, PKCS12_key_gen_uni_ex_procname);
  FuncLoadError := not assigned(PKCS12_key_gen_uni_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_key_gen_uni_ex_allownil)}
    PKCS12_key_gen_uni_ex := ERR_PKCS12_key_gen_uni_ex;
    {$ifend}
    {$if declared(PKCS12_key_gen_uni_ex_introduced)}
    if LibVersion < PKCS12_key_gen_uni_ex_introduced then
    begin
      {$if declared(FC_PKCS12_key_gen_uni_ex)}
      PKCS12_key_gen_uni_ex := FC_PKCS12_key_gen_uni_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_key_gen_uni_ex_removed)}
    if PKCS12_key_gen_uni_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_key_gen_uni_ex)}
      PKCS12_key_gen_uni_ex := _PKCS12_key_gen_uni_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_key_gen_uni_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_key_gen_uni_ex');
    {$ifend}
  end;
  
  PKCS12_key_gen_utf8 := LoadLibFunction(ADllHandle, PKCS12_key_gen_utf8_procname);
  FuncLoadError := not assigned(PKCS12_key_gen_utf8);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_key_gen_utf8_allownil)}
    PKCS12_key_gen_utf8 := ERR_PKCS12_key_gen_utf8;
    {$ifend}
    {$if declared(PKCS12_key_gen_utf8_introduced)}
    if LibVersion < PKCS12_key_gen_utf8_introduced then
    begin
      {$if declared(FC_PKCS12_key_gen_utf8)}
      PKCS12_key_gen_utf8 := FC_PKCS12_key_gen_utf8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_key_gen_utf8_removed)}
    if PKCS12_key_gen_utf8_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_key_gen_utf8)}
      PKCS12_key_gen_utf8 := _PKCS12_key_gen_utf8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_key_gen_utf8_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_key_gen_utf8');
    {$ifend}
  end;
  
  PKCS12_key_gen_utf8_ex := LoadLibFunction(ADllHandle, PKCS12_key_gen_utf8_ex_procname);
  FuncLoadError := not assigned(PKCS12_key_gen_utf8_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_key_gen_utf8_ex_allownil)}
    PKCS12_key_gen_utf8_ex := ERR_PKCS12_key_gen_utf8_ex;
    {$ifend}
    {$if declared(PKCS12_key_gen_utf8_ex_introduced)}
    if LibVersion < PKCS12_key_gen_utf8_ex_introduced then
    begin
      {$if declared(FC_PKCS12_key_gen_utf8_ex)}
      PKCS12_key_gen_utf8_ex := FC_PKCS12_key_gen_utf8_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_key_gen_utf8_ex_removed)}
    if PKCS12_key_gen_utf8_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_key_gen_utf8_ex)}
      PKCS12_key_gen_utf8_ex := _PKCS12_key_gen_utf8_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_key_gen_utf8_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_key_gen_utf8_ex');
    {$ifend}
  end;
  
  PKCS12_PBE_keyivgen := LoadLibFunction(ADllHandle, PKCS12_PBE_keyivgen_procname);
  FuncLoadError := not assigned(PKCS12_PBE_keyivgen);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_PBE_keyivgen_allownil)}
    PKCS12_PBE_keyivgen := ERR_PKCS12_PBE_keyivgen;
    {$ifend}
    {$if declared(PKCS12_PBE_keyivgen_introduced)}
    if LibVersion < PKCS12_PBE_keyivgen_introduced then
    begin
      {$if declared(FC_PKCS12_PBE_keyivgen)}
      PKCS12_PBE_keyivgen := FC_PKCS12_PBE_keyivgen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_PBE_keyivgen_removed)}
    if PKCS12_PBE_keyivgen_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_PBE_keyivgen)}
      PKCS12_PBE_keyivgen := _PKCS12_PBE_keyivgen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_PBE_keyivgen_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_PBE_keyivgen');
    {$ifend}
  end;
  
  PKCS12_PBE_keyivgen_ex := LoadLibFunction(ADllHandle, PKCS12_PBE_keyivgen_ex_procname);
  FuncLoadError := not assigned(PKCS12_PBE_keyivgen_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_PBE_keyivgen_ex_allownil)}
    PKCS12_PBE_keyivgen_ex := ERR_PKCS12_PBE_keyivgen_ex;
    {$ifend}
    {$if declared(PKCS12_PBE_keyivgen_ex_introduced)}
    if LibVersion < PKCS12_PBE_keyivgen_ex_introduced then
    begin
      {$if declared(FC_PKCS12_PBE_keyivgen_ex)}
      PKCS12_PBE_keyivgen_ex := FC_PKCS12_PBE_keyivgen_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_PBE_keyivgen_ex_removed)}
    if PKCS12_PBE_keyivgen_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_PBE_keyivgen_ex)}
      PKCS12_PBE_keyivgen_ex := _PKCS12_PBE_keyivgen_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_PBE_keyivgen_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_PBE_keyivgen_ex');
    {$ifend}
  end;
  
  PKCS12_gen_mac := LoadLibFunction(ADllHandle, PKCS12_gen_mac_procname);
  FuncLoadError := not assigned(PKCS12_gen_mac);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_gen_mac_allownil)}
    PKCS12_gen_mac := ERR_PKCS12_gen_mac;
    {$ifend}
    {$if declared(PKCS12_gen_mac_introduced)}
    if LibVersion < PKCS12_gen_mac_introduced then
    begin
      {$if declared(FC_PKCS12_gen_mac)}
      PKCS12_gen_mac := FC_PKCS12_gen_mac;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_gen_mac_removed)}
    if PKCS12_gen_mac_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_gen_mac)}
      PKCS12_gen_mac := _PKCS12_gen_mac;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_gen_mac_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_gen_mac');
    {$ifend}
  end;
  
  PKCS12_verify_mac := LoadLibFunction(ADllHandle, PKCS12_verify_mac_procname);
  FuncLoadError := not assigned(PKCS12_verify_mac);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_verify_mac_allownil)}
    PKCS12_verify_mac := ERR_PKCS12_verify_mac;
    {$ifend}
    {$if declared(PKCS12_verify_mac_introduced)}
    if LibVersion < PKCS12_verify_mac_introduced then
    begin
      {$if declared(FC_PKCS12_verify_mac)}
      PKCS12_verify_mac := FC_PKCS12_verify_mac;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_verify_mac_removed)}
    if PKCS12_verify_mac_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_verify_mac)}
      PKCS12_verify_mac := _PKCS12_verify_mac;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_verify_mac_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_verify_mac');
    {$ifend}
  end;
  
  PKCS12_set_mac := LoadLibFunction(ADllHandle, PKCS12_set_mac_procname);
  FuncLoadError := not assigned(PKCS12_set_mac);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_set_mac_allownil)}
    PKCS12_set_mac := ERR_PKCS12_set_mac;
    {$ifend}
    {$if declared(PKCS12_set_mac_introduced)}
    if LibVersion < PKCS12_set_mac_introduced then
    begin
      {$if declared(FC_PKCS12_set_mac)}
      PKCS12_set_mac := FC_PKCS12_set_mac;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_set_mac_removed)}
    if PKCS12_set_mac_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_set_mac)}
      PKCS12_set_mac := _PKCS12_set_mac;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_set_mac_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_set_mac');
    {$ifend}
  end;
  
  PKCS12_set_pbmac1_pbkdf2 := LoadLibFunction(ADllHandle, PKCS12_set_pbmac1_pbkdf2_procname);
  FuncLoadError := not assigned(PKCS12_set_pbmac1_pbkdf2);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_set_pbmac1_pbkdf2_allownil)}
    PKCS12_set_pbmac1_pbkdf2 := ERR_PKCS12_set_pbmac1_pbkdf2;
    {$ifend}
    {$if declared(PKCS12_set_pbmac1_pbkdf2_introduced)}
    if LibVersion < PKCS12_set_pbmac1_pbkdf2_introduced then
    begin
      {$if declared(FC_PKCS12_set_pbmac1_pbkdf2)}
      PKCS12_set_pbmac1_pbkdf2 := FC_PKCS12_set_pbmac1_pbkdf2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_set_pbmac1_pbkdf2_removed)}
    if PKCS12_set_pbmac1_pbkdf2_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_set_pbmac1_pbkdf2)}
      PKCS12_set_pbmac1_pbkdf2 := _PKCS12_set_pbmac1_pbkdf2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_set_pbmac1_pbkdf2_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_set_pbmac1_pbkdf2');
    {$ifend}
  end;
  
  PKCS12_setup_mac := LoadLibFunction(ADllHandle, PKCS12_setup_mac_procname);
  FuncLoadError := not assigned(PKCS12_setup_mac);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_setup_mac_allownil)}
    PKCS12_setup_mac := ERR_PKCS12_setup_mac;
    {$ifend}
    {$if declared(PKCS12_setup_mac_introduced)}
    if LibVersion < PKCS12_setup_mac_introduced then
    begin
      {$if declared(FC_PKCS12_setup_mac)}
      PKCS12_setup_mac := FC_PKCS12_setup_mac;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_setup_mac_removed)}
    if PKCS12_setup_mac_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_setup_mac)}
      PKCS12_setup_mac := _PKCS12_setup_mac;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_setup_mac_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_setup_mac');
    {$ifend}
  end;
  
  OPENSSL_asc2uni := LoadLibFunction(ADllHandle, OPENSSL_asc2uni_procname);
  FuncLoadError := not assigned(OPENSSL_asc2uni);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_asc2uni_allownil)}
    OPENSSL_asc2uni := ERR_OPENSSL_asc2uni;
    {$ifend}
    {$if declared(OPENSSL_asc2uni_introduced)}
    if LibVersion < OPENSSL_asc2uni_introduced then
    begin
      {$if declared(FC_OPENSSL_asc2uni)}
      OPENSSL_asc2uni := FC_OPENSSL_asc2uni;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_asc2uni_removed)}
    if OPENSSL_asc2uni_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_asc2uni)}
      OPENSSL_asc2uni := _OPENSSL_asc2uni;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_asc2uni_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_asc2uni');
    {$ifend}
  end;
  
  OPENSSL_uni2asc := LoadLibFunction(ADllHandle, OPENSSL_uni2asc_procname);
  FuncLoadError := not assigned(OPENSSL_uni2asc);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_uni2asc_allownil)}
    OPENSSL_uni2asc := ERR_OPENSSL_uni2asc;
    {$ifend}
    {$if declared(OPENSSL_uni2asc_introduced)}
    if LibVersion < OPENSSL_uni2asc_introduced then
    begin
      {$if declared(FC_OPENSSL_uni2asc)}
      OPENSSL_uni2asc := FC_OPENSSL_uni2asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_uni2asc_removed)}
    if OPENSSL_uni2asc_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_uni2asc)}
      OPENSSL_uni2asc := _OPENSSL_uni2asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_uni2asc_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_uni2asc');
    {$ifend}
  end;
  
  OPENSSL_utf82uni := LoadLibFunction(ADllHandle, OPENSSL_utf82uni_procname);
  FuncLoadError := not assigned(OPENSSL_utf82uni);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_utf82uni_allownil)}
    OPENSSL_utf82uni := ERR_OPENSSL_utf82uni;
    {$ifend}
    {$if declared(OPENSSL_utf82uni_introduced)}
    if LibVersion < OPENSSL_utf82uni_introduced then
    begin
      {$if declared(FC_OPENSSL_utf82uni)}
      OPENSSL_utf82uni := FC_OPENSSL_utf82uni;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_utf82uni_removed)}
    if OPENSSL_utf82uni_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_utf82uni)}
      OPENSSL_utf82uni := _OPENSSL_utf82uni;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_utf82uni_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_utf82uni');
    {$ifend}
  end;
  
  OPENSSL_uni2utf8 := LoadLibFunction(ADllHandle, OPENSSL_uni2utf8_procname);
  FuncLoadError := not assigned(OPENSSL_uni2utf8);
  if FuncLoadError then
  begin
    {$if not defined(OPENSSL_uni2utf8_allownil)}
    OPENSSL_uni2utf8 := ERR_OPENSSL_uni2utf8;
    {$ifend}
    {$if declared(OPENSSL_uni2utf8_introduced)}
    if LibVersion < OPENSSL_uni2utf8_introduced then
    begin
      {$if declared(FC_OPENSSL_uni2utf8)}
      OPENSSL_uni2utf8 := FC_OPENSSL_uni2utf8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OPENSSL_uni2utf8_removed)}
    if OPENSSL_uni2utf8_removed <= LibVersion then
    begin
      {$if declared(_OPENSSL_uni2utf8)}
      OPENSSL_uni2utf8 := _OPENSSL_uni2utf8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OPENSSL_uni2utf8_allownil)}
    if FuncLoadError then
      AFailed.Add('OPENSSL_uni2utf8');
    {$ifend}
  end;
  
  PKCS12_new := LoadLibFunction(ADllHandle, PKCS12_new_procname);
  FuncLoadError := not assigned(PKCS12_new);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_new_allownil)}
    PKCS12_new := ERR_PKCS12_new;
    {$ifend}
    {$if declared(PKCS12_new_introduced)}
    if LibVersion < PKCS12_new_introduced then
    begin
      {$if declared(FC_PKCS12_new)}
      PKCS12_new := FC_PKCS12_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_new_removed)}
    if PKCS12_new_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_new)}
      PKCS12_new := _PKCS12_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_new_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_new');
    {$ifend}
  end;
  
  PKCS12_free := LoadLibFunction(ADllHandle, PKCS12_free_procname);
  FuncLoadError := not assigned(PKCS12_free);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_free_allownil)}
    PKCS12_free := ERR_PKCS12_free;
    {$ifend}
    {$if declared(PKCS12_free_introduced)}
    if LibVersion < PKCS12_free_introduced then
    begin
      {$if declared(FC_PKCS12_free)}
      PKCS12_free := FC_PKCS12_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_free_removed)}
    if PKCS12_free_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_free)}
      PKCS12_free := _PKCS12_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_free_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_free');
    {$ifend}
  end;
  
  d2i_PKCS12 := LoadLibFunction(ADllHandle, d2i_PKCS12_procname);
  FuncLoadError := not assigned(d2i_PKCS12);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS12_allownil)}
    d2i_PKCS12 := ERR_d2i_PKCS12;
    {$ifend}
    {$if declared(d2i_PKCS12_introduced)}
    if LibVersion < d2i_PKCS12_introduced then
    begin
      {$if declared(FC_d2i_PKCS12)}
      d2i_PKCS12 := FC_d2i_PKCS12;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS12_removed)}
    if d2i_PKCS12_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS12)}
      d2i_PKCS12 := _d2i_PKCS12;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS12_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS12');
    {$ifend}
  end;
  
  i2d_PKCS12 := LoadLibFunction(ADllHandle, i2d_PKCS12_procname);
  FuncLoadError := not assigned(i2d_PKCS12);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS12_allownil)}
    i2d_PKCS12 := ERR_i2d_PKCS12;
    {$ifend}
    {$if declared(i2d_PKCS12_introduced)}
    if LibVersion < i2d_PKCS12_introduced then
    begin
      {$if declared(FC_i2d_PKCS12)}
      i2d_PKCS12 := FC_i2d_PKCS12;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS12_removed)}
    if i2d_PKCS12_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS12)}
      i2d_PKCS12 := _i2d_PKCS12;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS12_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS12');
    {$ifend}
  end;
  
  PKCS12_it := LoadLibFunction(ADllHandle, PKCS12_it_procname);
  FuncLoadError := not assigned(PKCS12_it);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_it_allownil)}
    PKCS12_it := ERR_PKCS12_it;
    {$ifend}
    {$if declared(PKCS12_it_introduced)}
    if LibVersion < PKCS12_it_introduced then
    begin
      {$if declared(FC_PKCS12_it)}
      PKCS12_it := FC_PKCS12_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_it_removed)}
    if PKCS12_it_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_it)}
      PKCS12_it := _PKCS12_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_it');
    {$ifend}
  end;
  
  PKCS12_MAC_DATA_new := LoadLibFunction(ADllHandle, PKCS12_MAC_DATA_new_procname);
  FuncLoadError := not assigned(PKCS12_MAC_DATA_new);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_MAC_DATA_new_allownil)}
    PKCS12_MAC_DATA_new := ERR_PKCS12_MAC_DATA_new;
    {$ifend}
    {$if declared(PKCS12_MAC_DATA_new_introduced)}
    if LibVersion < PKCS12_MAC_DATA_new_introduced then
    begin
      {$if declared(FC_PKCS12_MAC_DATA_new)}
      PKCS12_MAC_DATA_new := FC_PKCS12_MAC_DATA_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_MAC_DATA_new_removed)}
    if PKCS12_MAC_DATA_new_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_MAC_DATA_new)}
      PKCS12_MAC_DATA_new := _PKCS12_MAC_DATA_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_MAC_DATA_new_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_MAC_DATA_new');
    {$ifend}
  end;
  
  PKCS12_MAC_DATA_free := LoadLibFunction(ADllHandle, PKCS12_MAC_DATA_free_procname);
  FuncLoadError := not assigned(PKCS12_MAC_DATA_free);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_MAC_DATA_free_allownil)}
    PKCS12_MAC_DATA_free := ERR_PKCS12_MAC_DATA_free;
    {$ifend}
    {$if declared(PKCS12_MAC_DATA_free_introduced)}
    if LibVersion < PKCS12_MAC_DATA_free_introduced then
    begin
      {$if declared(FC_PKCS12_MAC_DATA_free)}
      PKCS12_MAC_DATA_free := FC_PKCS12_MAC_DATA_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_MAC_DATA_free_removed)}
    if PKCS12_MAC_DATA_free_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_MAC_DATA_free)}
      PKCS12_MAC_DATA_free := _PKCS12_MAC_DATA_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_MAC_DATA_free_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_MAC_DATA_free');
    {$ifend}
  end;
  
  d2i_PKCS12_MAC_DATA := LoadLibFunction(ADllHandle, d2i_PKCS12_MAC_DATA_procname);
  FuncLoadError := not assigned(d2i_PKCS12_MAC_DATA);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS12_MAC_DATA_allownil)}
    d2i_PKCS12_MAC_DATA := ERR_d2i_PKCS12_MAC_DATA;
    {$ifend}
    {$if declared(d2i_PKCS12_MAC_DATA_introduced)}
    if LibVersion < d2i_PKCS12_MAC_DATA_introduced then
    begin
      {$if declared(FC_d2i_PKCS12_MAC_DATA)}
      d2i_PKCS12_MAC_DATA := FC_d2i_PKCS12_MAC_DATA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS12_MAC_DATA_removed)}
    if d2i_PKCS12_MAC_DATA_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS12_MAC_DATA)}
      d2i_PKCS12_MAC_DATA := _d2i_PKCS12_MAC_DATA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS12_MAC_DATA_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS12_MAC_DATA');
    {$ifend}
  end;
  
  i2d_PKCS12_MAC_DATA := LoadLibFunction(ADllHandle, i2d_PKCS12_MAC_DATA_procname);
  FuncLoadError := not assigned(i2d_PKCS12_MAC_DATA);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS12_MAC_DATA_allownil)}
    i2d_PKCS12_MAC_DATA := ERR_i2d_PKCS12_MAC_DATA;
    {$ifend}
    {$if declared(i2d_PKCS12_MAC_DATA_introduced)}
    if LibVersion < i2d_PKCS12_MAC_DATA_introduced then
    begin
      {$if declared(FC_i2d_PKCS12_MAC_DATA)}
      i2d_PKCS12_MAC_DATA := FC_i2d_PKCS12_MAC_DATA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS12_MAC_DATA_removed)}
    if i2d_PKCS12_MAC_DATA_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS12_MAC_DATA)}
      i2d_PKCS12_MAC_DATA := _i2d_PKCS12_MAC_DATA;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS12_MAC_DATA_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS12_MAC_DATA');
    {$ifend}
  end;
  
  PKCS12_MAC_DATA_it := LoadLibFunction(ADllHandle, PKCS12_MAC_DATA_it_procname);
  FuncLoadError := not assigned(PKCS12_MAC_DATA_it);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_MAC_DATA_it_allownil)}
    PKCS12_MAC_DATA_it := ERR_PKCS12_MAC_DATA_it;
    {$ifend}
    {$if declared(PKCS12_MAC_DATA_it_introduced)}
    if LibVersion < PKCS12_MAC_DATA_it_introduced then
    begin
      {$if declared(FC_PKCS12_MAC_DATA_it)}
      PKCS12_MAC_DATA_it := FC_PKCS12_MAC_DATA_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_MAC_DATA_it_removed)}
    if PKCS12_MAC_DATA_it_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_MAC_DATA_it)}
      PKCS12_MAC_DATA_it := _PKCS12_MAC_DATA_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_MAC_DATA_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_MAC_DATA_it');
    {$ifend}
  end;
  
  PKCS12_SAFEBAG_new := LoadLibFunction(ADllHandle, PKCS12_SAFEBAG_new_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAG_new);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAG_new_allownil)}
    PKCS12_SAFEBAG_new := ERR_PKCS12_SAFEBAG_new;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_new_introduced)}
    if LibVersion < PKCS12_SAFEBAG_new_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAG_new)}
      PKCS12_SAFEBAG_new := FC_PKCS12_SAFEBAG_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_new_removed)}
    if PKCS12_SAFEBAG_new_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAG_new)}
      PKCS12_SAFEBAG_new := _PKCS12_SAFEBAG_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAG_new_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAG_new');
    {$ifend}
  end;
  
  PKCS12_SAFEBAG_free := LoadLibFunction(ADllHandle, PKCS12_SAFEBAG_free_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAG_free);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAG_free_allownil)}
    PKCS12_SAFEBAG_free := ERR_PKCS12_SAFEBAG_free;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_free_introduced)}
    if LibVersion < PKCS12_SAFEBAG_free_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAG_free)}
      PKCS12_SAFEBAG_free := FC_PKCS12_SAFEBAG_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_free_removed)}
    if PKCS12_SAFEBAG_free_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAG_free)}
      PKCS12_SAFEBAG_free := _PKCS12_SAFEBAG_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAG_free_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAG_free');
    {$ifend}
  end;
  
  d2i_PKCS12_SAFEBAG := LoadLibFunction(ADllHandle, d2i_PKCS12_SAFEBAG_procname);
  FuncLoadError := not assigned(d2i_PKCS12_SAFEBAG);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS12_SAFEBAG_allownil)}
    d2i_PKCS12_SAFEBAG := ERR_d2i_PKCS12_SAFEBAG;
    {$ifend}
    {$if declared(d2i_PKCS12_SAFEBAG_introduced)}
    if LibVersion < d2i_PKCS12_SAFEBAG_introduced then
    begin
      {$if declared(FC_d2i_PKCS12_SAFEBAG)}
      d2i_PKCS12_SAFEBAG := FC_d2i_PKCS12_SAFEBAG;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS12_SAFEBAG_removed)}
    if d2i_PKCS12_SAFEBAG_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS12_SAFEBAG)}
      d2i_PKCS12_SAFEBAG := _d2i_PKCS12_SAFEBAG;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS12_SAFEBAG_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS12_SAFEBAG');
    {$ifend}
  end;
  
  i2d_PKCS12_SAFEBAG := LoadLibFunction(ADllHandle, i2d_PKCS12_SAFEBAG_procname);
  FuncLoadError := not assigned(i2d_PKCS12_SAFEBAG);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS12_SAFEBAG_allownil)}
    i2d_PKCS12_SAFEBAG := ERR_i2d_PKCS12_SAFEBAG;
    {$ifend}
    {$if declared(i2d_PKCS12_SAFEBAG_introduced)}
    if LibVersion < i2d_PKCS12_SAFEBAG_introduced then
    begin
      {$if declared(FC_i2d_PKCS12_SAFEBAG)}
      i2d_PKCS12_SAFEBAG := FC_i2d_PKCS12_SAFEBAG;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS12_SAFEBAG_removed)}
    if i2d_PKCS12_SAFEBAG_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS12_SAFEBAG)}
      i2d_PKCS12_SAFEBAG := _i2d_PKCS12_SAFEBAG;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS12_SAFEBAG_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS12_SAFEBAG');
    {$ifend}
  end;
  
  PKCS12_SAFEBAG_it := LoadLibFunction(ADllHandle, PKCS12_SAFEBAG_it_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAG_it);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAG_it_allownil)}
    PKCS12_SAFEBAG_it := ERR_PKCS12_SAFEBAG_it;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_it_introduced)}
    if LibVersion < PKCS12_SAFEBAG_it_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAG_it)}
      PKCS12_SAFEBAG_it := FC_PKCS12_SAFEBAG_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAG_it_removed)}
    if PKCS12_SAFEBAG_it_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAG_it)}
      PKCS12_SAFEBAG_it := _PKCS12_SAFEBAG_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAG_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAG_it');
    {$ifend}
  end;
  
  PKCS12_BAGS_new := LoadLibFunction(ADllHandle, PKCS12_BAGS_new_procname);
  FuncLoadError := not assigned(PKCS12_BAGS_new);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_BAGS_new_allownil)}
    PKCS12_BAGS_new := ERR_PKCS12_BAGS_new;
    {$ifend}
    {$if declared(PKCS12_BAGS_new_introduced)}
    if LibVersion < PKCS12_BAGS_new_introduced then
    begin
      {$if declared(FC_PKCS12_BAGS_new)}
      PKCS12_BAGS_new := FC_PKCS12_BAGS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_BAGS_new_removed)}
    if PKCS12_BAGS_new_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_BAGS_new)}
      PKCS12_BAGS_new := _PKCS12_BAGS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_BAGS_new_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_BAGS_new');
    {$ifend}
  end;
  
  PKCS12_BAGS_free := LoadLibFunction(ADllHandle, PKCS12_BAGS_free_procname);
  FuncLoadError := not assigned(PKCS12_BAGS_free);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_BAGS_free_allownil)}
    PKCS12_BAGS_free := ERR_PKCS12_BAGS_free;
    {$ifend}
    {$if declared(PKCS12_BAGS_free_introduced)}
    if LibVersion < PKCS12_BAGS_free_introduced then
    begin
      {$if declared(FC_PKCS12_BAGS_free)}
      PKCS12_BAGS_free := FC_PKCS12_BAGS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_BAGS_free_removed)}
    if PKCS12_BAGS_free_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_BAGS_free)}
      PKCS12_BAGS_free := _PKCS12_BAGS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_BAGS_free_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_BAGS_free');
    {$ifend}
  end;
  
  d2i_PKCS12_BAGS := LoadLibFunction(ADllHandle, d2i_PKCS12_BAGS_procname);
  FuncLoadError := not assigned(d2i_PKCS12_BAGS);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS12_BAGS_allownil)}
    d2i_PKCS12_BAGS := ERR_d2i_PKCS12_BAGS;
    {$ifend}
    {$if declared(d2i_PKCS12_BAGS_introduced)}
    if LibVersion < d2i_PKCS12_BAGS_introduced then
    begin
      {$if declared(FC_d2i_PKCS12_BAGS)}
      d2i_PKCS12_BAGS := FC_d2i_PKCS12_BAGS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS12_BAGS_removed)}
    if d2i_PKCS12_BAGS_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS12_BAGS)}
      d2i_PKCS12_BAGS := _d2i_PKCS12_BAGS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS12_BAGS_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS12_BAGS');
    {$ifend}
  end;
  
  i2d_PKCS12_BAGS := LoadLibFunction(ADllHandle, i2d_PKCS12_BAGS_procname);
  FuncLoadError := not assigned(i2d_PKCS12_BAGS);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS12_BAGS_allownil)}
    i2d_PKCS12_BAGS := ERR_i2d_PKCS12_BAGS;
    {$ifend}
    {$if declared(i2d_PKCS12_BAGS_introduced)}
    if LibVersion < i2d_PKCS12_BAGS_introduced then
    begin
      {$if declared(FC_i2d_PKCS12_BAGS)}
      i2d_PKCS12_BAGS := FC_i2d_PKCS12_BAGS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS12_BAGS_removed)}
    if i2d_PKCS12_BAGS_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS12_BAGS)}
      i2d_PKCS12_BAGS := _i2d_PKCS12_BAGS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS12_BAGS_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS12_BAGS');
    {$ifend}
  end;
  
  PKCS12_BAGS_it := LoadLibFunction(ADllHandle, PKCS12_BAGS_it_procname);
  FuncLoadError := not assigned(PKCS12_BAGS_it);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_BAGS_it_allownil)}
    PKCS12_BAGS_it := ERR_PKCS12_BAGS_it;
    {$ifend}
    {$if declared(PKCS12_BAGS_it_introduced)}
    if LibVersion < PKCS12_BAGS_it_introduced then
    begin
      {$if declared(FC_PKCS12_BAGS_it)}
      PKCS12_BAGS_it := FC_PKCS12_BAGS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_BAGS_it_removed)}
    if PKCS12_BAGS_it_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_BAGS_it)}
      PKCS12_BAGS_it := _PKCS12_BAGS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_BAGS_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_BAGS_it');
    {$ifend}
  end;
  
  PKCS12_SAFEBAGS_it := LoadLibFunction(ADllHandle, PKCS12_SAFEBAGS_it_procname);
  FuncLoadError := not assigned(PKCS12_SAFEBAGS_it);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_SAFEBAGS_it_allownil)}
    PKCS12_SAFEBAGS_it := ERR_PKCS12_SAFEBAGS_it;
    {$ifend}
    {$if declared(PKCS12_SAFEBAGS_it_introduced)}
    if LibVersion < PKCS12_SAFEBAGS_it_introduced then
    begin
      {$if declared(FC_PKCS12_SAFEBAGS_it)}
      PKCS12_SAFEBAGS_it := FC_PKCS12_SAFEBAGS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_SAFEBAGS_it_removed)}
    if PKCS12_SAFEBAGS_it_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_SAFEBAGS_it)}
      PKCS12_SAFEBAGS_it := _PKCS12_SAFEBAGS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_SAFEBAGS_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_SAFEBAGS_it');
    {$ifend}
  end;
  
  PKCS12_AUTHSAFES_it := LoadLibFunction(ADllHandle, PKCS12_AUTHSAFES_it_procname);
  FuncLoadError := not assigned(PKCS12_AUTHSAFES_it);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_AUTHSAFES_it_allownil)}
    PKCS12_AUTHSAFES_it := ERR_PKCS12_AUTHSAFES_it;
    {$ifend}
    {$if declared(PKCS12_AUTHSAFES_it_introduced)}
    if LibVersion < PKCS12_AUTHSAFES_it_introduced then
    begin
      {$if declared(FC_PKCS12_AUTHSAFES_it)}
      PKCS12_AUTHSAFES_it := FC_PKCS12_AUTHSAFES_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_AUTHSAFES_it_removed)}
    if PKCS12_AUTHSAFES_it_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_AUTHSAFES_it)}
      PKCS12_AUTHSAFES_it := _PKCS12_AUTHSAFES_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_AUTHSAFES_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_AUTHSAFES_it');
    {$ifend}
  end;
  
  PKCS12_PBE_add := LoadLibFunction(ADllHandle, PKCS12_PBE_add_procname);
  FuncLoadError := not assigned(PKCS12_PBE_add);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_PBE_add_allownil)}
    PKCS12_PBE_add := ERR_PKCS12_PBE_add;
    {$ifend}
    {$if declared(PKCS12_PBE_add_introduced)}
    if LibVersion < PKCS12_PBE_add_introduced then
    begin
      {$if declared(FC_PKCS12_PBE_add)}
      PKCS12_PBE_add := FC_PKCS12_PBE_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_PBE_add_removed)}
    if PKCS12_PBE_add_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_PBE_add)}
      PKCS12_PBE_add := _PKCS12_PBE_add;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_PBE_add_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_PBE_add');
    {$ifend}
  end;
  
  PKCS12_parse := LoadLibFunction(ADllHandle, PKCS12_parse_procname);
  FuncLoadError := not assigned(PKCS12_parse);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_parse_allownil)}
    PKCS12_parse := ERR_PKCS12_parse;
    {$ifend}
    {$if declared(PKCS12_parse_introduced)}
    if LibVersion < PKCS12_parse_introduced then
    begin
      {$if declared(FC_PKCS12_parse)}
      PKCS12_parse := FC_PKCS12_parse;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_parse_removed)}
    if PKCS12_parse_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_parse)}
      PKCS12_parse := _PKCS12_parse;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_parse_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_parse');
    {$ifend}
  end;
  
  PKCS12_create := LoadLibFunction(ADllHandle, PKCS12_create_procname);
  FuncLoadError := not assigned(PKCS12_create);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_create_allownil)}
    PKCS12_create := ERR_PKCS12_create;
    {$ifend}
    {$if declared(PKCS12_create_introduced)}
    if LibVersion < PKCS12_create_introduced then
    begin
      {$if declared(FC_PKCS12_create)}
      PKCS12_create := FC_PKCS12_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_create_removed)}
    if PKCS12_create_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_create)}
      PKCS12_create := _PKCS12_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_create_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_create');
    {$ifend}
  end;
  
  PKCS12_create_ex := LoadLibFunction(ADllHandle, PKCS12_create_ex_procname);
  FuncLoadError := not assigned(PKCS12_create_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_create_ex_allownil)}
    PKCS12_create_ex := ERR_PKCS12_create_ex;
    {$ifend}
    {$if declared(PKCS12_create_ex_introduced)}
    if LibVersion < PKCS12_create_ex_introduced then
    begin
      {$if declared(FC_PKCS12_create_ex)}
      PKCS12_create_ex := FC_PKCS12_create_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_create_ex_removed)}
    if PKCS12_create_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_create_ex)}
      PKCS12_create_ex := _PKCS12_create_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_create_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_create_ex');
    {$ifend}
  end;
  
  PKCS12_create_ex2 := LoadLibFunction(ADllHandle, PKCS12_create_ex2_procname);
  FuncLoadError := not assigned(PKCS12_create_ex2);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_create_ex2_allownil)}
    PKCS12_create_ex2 := ERR_PKCS12_create_ex2;
    {$ifend}
    {$if declared(PKCS12_create_ex2_introduced)}
    if LibVersion < PKCS12_create_ex2_introduced then
    begin
      {$if declared(FC_PKCS12_create_ex2)}
      PKCS12_create_ex2 := FC_PKCS12_create_ex2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_create_ex2_removed)}
    if PKCS12_create_ex2_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_create_ex2)}
      PKCS12_create_ex2 := _PKCS12_create_ex2;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_create_ex2_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_create_ex2');
    {$ifend}
  end;
  
  PKCS12_add_cert := LoadLibFunction(ADllHandle, PKCS12_add_cert_procname);
  FuncLoadError := not assigned(PKCS12_add_cert);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_add_cert_allownil)}
    PKCS12_add_cert := ERR_PKCS12_add_cert;
    {$ifend}
    {$if declared(PKCS12_add_cert_introduced)}
    if LibVersion < PKCS12_add_cert_introduced then
    begin
      {$if declared(FC_PKCS12_add_cert)}
      PKCS12_add_cert := FC_PKCS12_add_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_add_cert_removed)}
    if PKCS12_add_cert_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_add_cert)}
      PKCS12_add_cert := _PKCS12_add_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_add_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_add_cert');
    {$ifend}
  end;
  
  PKCS12_add_key := LoadLibFunction(ADllHandle, PKCS12_add_key_procname);
  FuncLoadError := not assigned(PKCS12_add_key);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_add_key_allownil)}
    PKCS12_add_key := ERR_PKCS12_add_key;
    {$ifend}
    {$if declared(PKCS12_add_key_introduced)}
    if LibVersion < PKCS12_add_key_introduced then
    begin
      {$if declared(FC_PKCS12_add_key)}
      PKCS12_add_key := FC_PKCS12_add_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_add_key_removed)}
    if PKCS12_add_key_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_add_key)}
      PKCS12_add_key := _PKCS12_add_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_add_key_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_add_key');
    {$ifend}
  end;
  
  PKCS12_add_key_ex := LoadLibFunction(ADllHandle, PKCS12_add_key_ex_procname);
  FuncLoadError := not assigned(PKCS12_add_key_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_add_key_ex_allownil)}
    PKCS12_add_key_ex := ERR_PKCS12_add_key_ex;
    {$ifend}
    {$if declared(PKCS12_add_key_ex_introduced)}
    if LibVersion < PKCS12_add_key_ex_introduced then
    begin
      {$if declared(FC_PKCS12_add_key_ex)}
      PKCS12_add_key_ex := FC_PKCS12_add_key_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_add_key_ex_removed)}
    if PKCS12_add_key_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_add_key_ex)}
      PKCS12_add_key_ex := _PKCS12_add_key_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_add_key_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_add_key_ex');
    {$ifend}
  end;
  
  PKCS12_add_secret := LoadLibFunction(ADllHandle, PKCS12_add_secret_procname);
  FuncLoadError := not assigned(PKCS12_add_secret);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_add_secret_allownil)}
    PKCS12_add_secret := ERR_PKCS12_add_secret;
    {$ifend}
    {$if declared(PKCS12_add_secret_introduced)}
    if LibVersion < PKCS12_add_secret_introduced then
    begin
      {$if declared(FC_PKCS12_add_secret)}
      PKCS12_add_secret := FC_PKCS12_add_secret;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_add_secret_removed)}
    if PKCS12_add_secret_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_add_secret)}
      PKCS12_add_secret := _PKCS12_add_secret;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_add_secret_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_add_secret');
    {$ifend}
  end;
  
  PKCS12_add_safe := LoadLibFunction(ADllHandle, PKCS12_add_safe_procname);
  FuncLoadError := not assigned(PKCS12_add_safe);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_add_safe_allownil)}
    PKCS12_add_safe := ERR_PKCS12_add_safe;
    {$ifend}
    {$if declared(PKCS12_add_safe_introduced)}
    if LibVersion < PKCS12_add_safe_introduced then
    begin
      {$if declared(FC_PKCS12_add_safe)}
      PKCS12_add_safe := FC_PKCS12_add_safe;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_add_safe_removed)}
    if PKCS12_add_safe_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_add_safe)}
      PKCS12_add_safe := _PKCS12_add_safe;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_add_safe_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_add_safe');
    {$ifend}
  end;
  
  PKCS12_add_safe_ex := LoadLibFunction(ADllHandle, PKCS12_add_safe_ex_procname);
  FuncLoadError := not assigned(PKCS12_add_safe_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_add_safe_ex_allownil)}
    PKCS12_add_safe_ex := ERR_PKCS12_add_safe_ex;
    {$ifend}
    {$if declared(PKCS12_add_safe_ex_introduced)}
    if LibVersion < PKCS12_add_safe_ex_introduced then
    begin
      {$if declared(FC_PKCS12_add_safe_ex)}
      PKCS12_add_safe_ex := FC_PKCS12_add_safe_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_add_safe_ex_removed)}
    if PKCS12_add_safe_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_add_safe_ex)}
      PKCS12_add_safe_ex := _PKCS12_add_safe_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_add_safe_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_add_safe_ex');
    {$ifend}
  end;
  
  PKCS12_add_safes := LoadLibFunction(ADllHandle, PKCS12_add_safes_procname);
  FuncLoadError := not assigned(PKCS12_add_safes);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_add_safes_allownil)}
    PKCS12_add_safes := ERR_PKCS12_add_safes;
    {$ifend}
    {$if declared(PKCS12_add_safes_introduced)}
    if LibVersion < PKCS12_add_safes_introduced then
    begin
      {$if declared(FC_PKCS12_add_safes)}
      PKCS12_add_safes := FC_PKCS12_add_safes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_add_safes_removed)}
    if PKCS12_add_safes_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_add_safes)}
      PKCS12_add_safes := _PKCS12_add_safes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_add_safes_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_add_safes');
    {$ifend}
  end;
  
  PKCS12_add_safes_ex := LoadLibFunction(ADllHandle, PKCS12_add_safes_ex_procname);
  FuncLoadError := not assigned(PKCS12_add_safes_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_add_safes_ex_allownil)}
    PKCS12_add_safes_ex := ERR_PKCS12_add_safes_ex;
    {$ifend}
    {$if declared(PKCS12_add_safes_ex_introduced)}
    if LibVersion < PKCS12_add_safes_ex_introduced then
    begin
      {$if declared(FC_PKCS12_add_safes_ex)}
      PKCS12_add_safes_ex := FC_PKCS12_add_safes_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_add_safes_ex_removed)}
    if PKCS12_add_safes_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_add_safes_ex)}
      PKCS12_add_safes_ex := _PKCS12_add_safes_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_add_safes_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_add_safes_ex');
    {$ifend}
  end;
  
  i2d_PKCS12_bio := LoadLibFunction(ADllHandle, i2d_PKCS12_bio_procname);
  FuncLoadError := not assigned(i2d_PKCS12_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS12_bio_allownil)}
    i2d_PKCS12_bio := ERR_i2d_PKCS12_bio;
    {$ifend}
    {$if declared(i2d_PKCS12_bio_introduced)}
    if LibVersion < i2d_PKCS12_bio_introduced then
    begin
      {$if declared(FC_i2d_PKCS12_bio)}
      i2d_PKCS12_bio := FC_i2d_PKCS12_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS12_bio_removed)}
    if i2d_PKCS12_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS12_bio)}
      i2d_PKCS12_bio := _i2d_PKCS12_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS12_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS12_bio');
    {$ifend}
  end;
  
  i2d_PKCS12_fp := LoadLibFunction(ADllHandle, i2d_PKCS12_fp_procname);
  FuncLoadError := not assigned(i2d_PKCS12_fp);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS12_fp_allownil)}
    i2d_PKCS12_fp := ERR_i2d_PKCS12_fp;
    {$ifend}
    {$if declared(i2d_PKCS12_fp_introduced)}
    if LibVersion < i2d_PKCS12_fp_introduced then
    begin
      {$if declared(FC_i2d_PKCS12_fp)}
      i2d_PKCS12_fp := FC_i2d_PKCS12_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS12_fp_removed)}
    if i2d_PKCS12_fp_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS12_fp)}
      i2d_PKCS12_fp := _i2d_PKCS12_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS12_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS12_fp');
    {$ifend}
  end;
  
  d2i_PKCS12_bio := LoadLibFunction(ADllHandle, d2i_PKCS12_bio_procname);
  FuncLoadError := not assigned(d2i_PKCS12_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS12_bio_allownil)}
    d2i_PKCS12_bio := ERR_d2i_PKCS12_bio;
    {$ifend}
    {$if declared(d2i_PKCS12_bio_introduced)}
    if LibVersion < d2i_PKCS12_bio_introduced then
    begin
      {$if declared(FC_d2i_PKCS12_bio)}
      d2i_PKCS12_bio := FC_d2i_PKCS12_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS12_bio_removed)}
    if d2i_PKCS12_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS12_bio)}
      d2i_PKCS12_bio := _d2i_PKCS12_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS12_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS12_bio');
    {$ifend}
  end;
  
  d2i_PKCS12_fp := LoadLibFunction(ADllHandle, d2i_PKCS12_fp_procname);
  FuncLoadError := not assigned(d2i_PKCS12_fp);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS12_fp_allownil)}
    d2i_PKCS12_fp := ERR_d2i_PKCS12_fp;
    {$ifend}
    {$if declared(d2i_PKCS12_fp_introduced)}
    if LibVersion < d2i_PKCS12_fp_introduced then
    begin
      {$if declared(FC_d2i_PKCS12_fp)}
      d2i_PKCS12_fp := FC_d2i_PKCS12_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS12_fp_removed)}
    if d2i_PKCS12_fp_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS12_fp)}
      d2i_PKCS12_fp := _d2i_PKCS12_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS12_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS12_fp');
    {$ifend}
  end;
  
  PKCS12_newpass := LoadLibFunction(ADllHandle, PKCS12_newpass_procname);
  FuncLoadError := not assigned(PKCS12_newpass);
  if FuncLoadError then
  begin
    {$if not defined(PKCS12_newpass_allownil)}
    PKCS12_newpass := ERR_PKCS12_newpass;
    {$ifend}
    {$if declared(PKCS12_newpass_introduced)}
    if LibVersion < PKCS12_newpass_introduced then
    begin
      {$if declared(FC_PKCS12_newpass)}
      PKCS12_newpass := FC_PKCS12_newpass;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS12_newpass_removed)}
    if PKCS12_newpass_removed <= LibVersion then
    begin
      {$if declared(_PKCS12_newpass)}
      PKCS12_newpass := _PKCS12_newpass;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS12_newpass_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS12_newpass');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  PKCS8_get_attr := nil;
  PKCS12_mac_present := nil;
  PKCS12_get0_mac := nil;
  PKCS12_SAFEBAG_get0_attr := nil;
  PKCS12_SAFEBAG_get0_type := nil;
  PKCS12_SAFEBAG_get_nid := nil;
  PKCS12_SAFEBAG_get_bag_nid := nil;
  PKCS12_SAFEBAG_get0_bag_obj := nil;
  PKCS12_SAFEBAG_get0_bag_type := nil;
  PKCS12_SAFEBAG_get1_cert_ex := nil;
  PKCS12_SAFEBAG_get1_cert := nil;
  PKCS12_SAFEBAG_get1_crl_ex := nil;
  PKCS12_SAFEBAG_get1_crl := nil;
  PKCS12_SAFEBAG_get0_safes := nil;
  PKCS12_SAFEBAG_get0_p8inf := nil;
  PKCS12_SAFEBAG_get0_pkcs8 := nil;
  PKCS12_SAFEBAG_create_cert := nil;
  PKCS12_SAFEBAG_create_crl := nil;
  PKCS12_SAFEBAG_create_secret := nil;
  PKCS12_SAFEBAG_create0_p8inf := nil;
  PKCS12_SAFEBAG_create0_pkcs8 := nil;
  PKCS12_SAFEBAG_create_pkcs8_encrypt := nil;
  PKCS12_SAFEBAG_create_pkcs8_encrypt_ex := nil;
  PKCS12_item_pack_safebag := nil;
  PKCS8_decrypt := nil;
  PKCS8_decrypt_ex := nil;
  PKCS12_decrypt_skey := nil;
  PKCS12_decrypt_skey_ex := nil;
  PKCS8_encrypt := nil;
  PKCS8_encrypt_ex := nil;
  PKCS8_set0_pbe := nil;
  PKCS8_set0_pbe_ex := nil;
  PKCS12_pack_p7data := nil;
  PKCS12_unpack_p7data := nil;
  PKCS12_pack_p7encdata := nil;
  PKCS12_pack_p7encdata_ex := nil;
  PKCS12_unpack_p7encdata := nil;
  PKCS12_pack_authsafes := nil;
  PKCS12_unpack_authsafes := nil;
  PKCS12_add_localkeyid := nil;
  PKCS12_add_friendlyname_asc := nil;
  PKCS12_add_friendlyname_utf8 := nil;
  PKCS12_add_CSPName_asc := nil;
  PKCS12_add_friendlyname_uni := nil;
  PKCS12_add1_attr_by_NID := nil;
  PKCS12_add1_attr_by_txt := nil;
  PKCS8_add_keyusage := nil;
  PKCS12_get_attr_gen := nil;
  PKCS12_get_friendlyname := nil;
  PKCS12_SAFEBAG_get0_attrs := nil;
  PKCS12_SAFEBAG_set0_attrs := nil;
  PKCS12_pbe_crypt := nil;
  PKCS12_pbe_crypt_ex := nil;
  PKCS12_item_decrypt_d2i := nil;
  PKCS12_item_decrypt_d2i_ex := nil;
  PKCS12_item_i2d_encrypt := nil;
  PKCS12_item_i2d_encrypt_ex := nil;
  PKCS12_init := nil;
  PKCS12_init_ex := nil;
  PKCS12_key_gen_asc := nil;
  PKCS12_key_gen_asc_ex := nil;
  PKCS12_key_gen_uni := nil;
  PKCS12_key_gen_uni_ex := nil;
  PKCS12_key_gen_utf8 := nil;
  PKCS12_key_gen_utf8_ex := nil;
  PKCS12_PBE_keyivgen := nil;
  PKCS12_PBE_keyivgen_ex := nil;
  PKCS12_gen_mac := nil;
  PKCS12_verify_mac := nil;
  PKCS12_set_mac := nil;
  PKCS12_set_pbmac1_pbkdf2 := nil;
  PKCS12_setup_mac := nil;
  OPENSSL_asc2uni := nil;
  OPENSSL_uni2asc := nil;
  OPENSSL_utf82uni := nil;
  OPENSSL_uni2utf8 := nil;
  PKCS12_new := nil;
  PKCS12_free := nil;
  d2i_PKCS12 := nil;
  i2d_PKCS12 := nil;
  PKCS12_it := nil;
  PKCS12_MAC_DATA_new := nil;
  PKCS12_MAC_DATA_free := nil;
  d2i_PKCS12_MAC_DATA := nil;
  i2d_PKCS12_MAC_DATA := nil;
  PKCS12_MAC_DATA_it := nil;
  PKCS12_SAFEBAG_new := nil;
  PKCS12_SAFEBAG_free := nil;
  d2i_PKCS12_SAFEBAG := nil;
  i2d_PKCS12_SAFEBAG := nil;
  PKCS12_SAFEBAG_it := nil;
  PKCS12_BAGS_new := nil;
  PKCS12_BAGS_free := nil;
  d2i_PKCS12_BAGS := nil;
  i2d_PKCS12_BAGS := nil;
  PKCS12_BAGS_it := nil;
  PKCS12_SAFEBAGS_it := nil;
  PKCS12_AUTHSAFES_it := nil;
  PKCS12_PBE_add := nil;
  PKCS12_parse := nil;
  PKCS12_create := nil;
  PKCS12_create_ex := nil;
  PKCS12_create_ex2 := nil;
  PKCS12_add_cert := nil;
  PKCS12_add_key := nil;
  PKCS12_add_key_ex := nil;
  PKCS12_add_secret := nil;
  PKCS12_add_safe := nil;
  PKCS12_add_safe_ex := nil;
  PKCS12_add_safes := nil;
  PKCS12_add_safes_ex := nil;
  i2d_PKCS12_bio := nil;
  i2d_PKCS12_fp := nil;
  d2i_PKCS12_bio := nil;
  d2i_PKCS12_fp := nil;
  PKCS12_newpass := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.