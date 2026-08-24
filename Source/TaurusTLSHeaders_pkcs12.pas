/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_pkcs12.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_pkcs12.h2pas
     and this file regenerated. TaurusTLSHeaders_pkcs12.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_pkcs12;

interface

// Headers for OpenSSL 1.1.1
// pkcs12.h


uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_pkcs7,
  TaurusTLSHeaders_x509;

const
  {$EXTERNALSYM PKCS12_KEY_ID}
  PKCS12_KEY_ID = 1;
  {$EXTERNALSYM PKCS12_IV_ID}
  PKCS12_IV_ID = 2;
  {$EXTERNALSYM PKCS12_MAC_ID}
  PKCS12_MAC_ID = 3;

  ///* Default iteration count */
  //# ifndef PKCS12_DEFAULT_ITER
  //#  define PKCS12_DEFAULT_ITER     PKCS5_DEFAULT_ITER
  //# endif

  {$EXTERNALSYM PKCS12_MAC_KEY_LENGTH}
  PKCS12_MAC_KEY_LENGTH = 20;

  {$EXTERNALSYM PKCS12_SALT_LEN}
  PKCS12_SALT_LEN = 8;

  ///* It's not clear if these are actually needed... */
  //# define PKCS12_key_gen PKCS12_key_gen_utf8
  //# define PKCS12_add_friendlyname PKCS12_add_friendlyname_utf8

  (* MS key usage constants *)
  {$EXTERNALSYM KEY_EX}
  KEY_EX  = $10;
  {$EXTERNALSYM KEY_SIG}
  KEY_SIG = $80;

  {$EXTERNALSYM PKCS12_ERROR}
  PKCS12_ERROR    = 0;
  {$EXTERNALSYM PKCS12_OK}
  PKCS12_OK       = 1;

type
  {$EXTERNALSYM PKCS12_MAC_DATA_st}
  PKCS12_MAC_DATA_st = record end;
  {$EXTERNALSYM PKCS12_MAC_DATA}
  PKCS12_MAC_DATA = PKCS12_MAC_DATA_st;
  {$EXTERNALSYM PPKCS12_MAC_DATA}
  PPKCS12_MAC_DATA = ^PKCS12_MAC_DATA;
  {$EXTERNALSYM PPPKCS12_MAC_DATA}
  PPPKCS12_MAC_DATA = ^PPKCS12_MAC_DATA;

  {$EXTERNALSYM PKCS12_st}
  PKCS12_st = record end;
  {$EXTERNALSYM PKCS12}
  PKCS12 = PKCS12_st;
  {$EXTERNALSYM PPKCS12}
  PPKCS12 = ^PKCS12;
  {$EXTERNALSYM PPPKCS12}
  PPPKCS12 = ^PPKCS12;

  {$EXTERNALSYM PKCS12_SAFEBAG_st}
  PKCS12_SAFEBAG_st = record end;
  {$EXTERNALSYM PKCS12_SAFEBAG}
  PKCS12_SAFEBAG = PKCS12_SAFEBAG_st;
  {$EXTERNALSYM PPKCS12_SAFEBAG}
  PPKCS12_SAFEBAG = ^PKCS12_SAFEBAG;
  {$EXTERNALSYM PPPKCS12_SAFEBAG}
  PPPKCS12_SAFEBAG = ^PPKCS12_SAFEBAG;

//  DEFINE_STACK_OF(PKCS12_SAFEBAG)

  {$EXTERNALSYM pkcs12_bag_st}
  pkcs12_bag_st = record end;
  {$EXTERNALSYM PKCS12_BAGS}
  PKCS12_BAGS = pkcs12_bag_st;
  {$EXTERNALSYM PPKCS12_BAGS}
  PPKCS12_BAGS = ^PKCS12_BAGS;
  {$EXTERNALSYM PPPKCS12_BAGS}
  PPPKCS12_BAGS = ^PPKCS12_BAGS;

  //ASN1_TYPE *PKCS8_get_attr(PKCS8_PRIV_KEY_INFO *p8, TIdC_INT attr_nid);
    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM PKCS12_mac_present}
  PKCS12_mac_present: function (const p12: PPKCS12): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM PKCS12_get0_mac}
  PKCS12_get0_mac: procedure (const pmac: PPASN1_OCTET_STRING; const pmacalg: PPX509_ALGOR; const psalt: PPASN1_OCTET_STRING; const piter: PPASN1_INTEGER; const p12: PPKCS12); cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM PKCS12_SAFEBAG_get0_attr}
  PKCS12_SAFEBAG_get0_attr: function (const bag: PPKCS12_SAFEBAG; attr_nid: TIdC_INT): PASN1_TYPE; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM PKCS12_SAFEBAG_get0_type}
  PKCS12_SAFEBAG_get0_type: function (const bag: PPKCS12_SAFEBAG): PASN1_OBJECT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM PKCS12_SAFEBAG_get_nid}
  PKCS12_SAFEBAG_get_nid: function (const bag: PPKCS12_SAFEBAG): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM PKCS12_SAFEBAG_get_bag_nid}
  PKCS12_SAFEBAG_get_bag_nid: function (const bag: PPKCS12_SAFEBAG): TIdC_INT; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM PKCS12_SAFEBAG_get1_cert}
  PKCS12_SAFEBAG_get1_cert: function (const bag: PPKCS12_SAFEBAG): PX509; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM PKCS12_SAFEBAG_get1_crl}
  PKCS12_SAFEBAG_get1_crl: function (const bag: PPKCS12_SAFEBAG): PX509_CRL; cdecl = nil; {introduced 1.1.0}
//  const STACK_OF(PKCS12_SAFEBAG) *PKCS12_SAFEBAG_get0_safes(const PKCS12_SAFEBAG *bag);
  {$EXTERNALSYM PKCS12_SAFEBAG_get0_p8inf}
  PKCS12_SAFEBAG_get0_p8inf: function (const bag: PPKCS12_SAFEBAG): PPKCS8_PRIV_KEY_INFO; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM PKCS12_SAFEBAG_get0_pkcs8}
  PKCS12_SAFEBAG_get0_pkcs8: function (const bag: PPKCS12_SAFEBAG): PX509_SIG; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM PKCS12_SAFEBAG_create_cert}
  PKCS12_SAFEBAG_create_cert: function (x509: PX509): PPKCS12_SAFEBAG; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM PKCS12_SAFEBAG_create_crl}
  PKCS12_SAFEBAG_create_crl: function (crl: PX509_CRL): PPKCS12_SAFEBAG; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM PKCS12_SAFEBAG_create0_p8inf}
  PKCS12_SAFEBAG_create0_p8inf: function (p8: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM PKCS12_SAFEBAG_create0_pkcs8}
  PKCS12_SAFEBAG_create0_pkcs8: function (p8: PX509_SIG): PPKCS12_SAFEBAG; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM PKCS12_SAFEBAG_create_pkcs8_encrypt}
  PKCS12_SAFEBAG_create_pkcs8_encrypt: function (pbe_nid: TIdC_INT; const pass: PIdAnsiChar; passlen: TIdC_INT; salt: PByte; saltlen: TIdC_INT; iter: TIdC_INT; p8inf: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM PKCS12_item_pack_safebag}
  PKCS12_item_pack_safebag: function (obj: Pointer; const it: PASN1_ITEM; nid1: TIdC_INT; nid2: TIdC_INT): PPKCS12_SAFEBAG; cdecl = nil;
  {$EXTERNALSYM PKCS8_decrypt}
  PKCS8_decrypt: function (const p8: PX509_SIG; const pass: PIdAnsiChar; passlen: TIdC_INT): PPKCS8_PRIV_KEY_INFO; cdecl = nil;
  {$EXTERNALSYM PKCS12_decrypt_skey}
  PKCS12_decrypt_skey: function (const bag: PPKCS12_SAFEBAG; const pass: PIdAnsiChar; passlen: TIdC_INT): PPKCS8_PRIV_KEY_INFO; cdecl = nil;
  {$EXTERNALSYM PKCS8_encrypt}
  PKCS8_encrypt: function (pbe_nid: TIdC_INT; const cipher: PEVP_CIPHER; const pass: PIdAnsiChar; passlen: TIdC_INT; salt: PByte; saltlen: TIdC_INT; iter: TIdC_INT; p8: PPKCS8_PRIV_KEY_INFO): PX509_SIG; cdecl = nil;
  {$EXTERNALSYM PKCS8_set0_pbe}
  PKCS8_set0_pbe: function (const pass: PIdAnsiChar; passlen: TIdC_INT; p8inf: PPKCS8_PRIV_KEY_INFO; pbe: PX509_ALGOR): PX509_SIG; cdecl = nil; {introduced 1.1.0}
//  PKCS7 *PKCS12_pack_p7data(STACK_OF(PKCS12_SAFEBAG) *sk);
//  STACK_OF(PKCS12_SAFEBAG) *PKCS12_unpack_p7data(PKCS7 *p7);
//  function PKCS12_pack_p7encdata(TIdC_INT pbe_nid, const PIdAnsiChar pass, TIdC_INT passlen,
//                               Byte *salt, TIdC_INT saltlen, TIdC_INT iter,
//                               STACK_OF(PKCS12_SAFEBAG) *bags): PPKCS7;
//  STACK_OF(PKCS12_SAFEBAG) *PKCS12_unpack_p7encdata(PKCS7 *p7, const PIdAnsiChar *pass,
//                                                    TIdC_INT passlen);

//  TIdC_INT PKCS12_pack_authsafes(PKCS12 *p12, STACK_OF(PKCS7) *safes);
//  STACK_OF(PKCS7) *PKCS12_unpack_authsafes(const PKCS12 *p12);

  {$EXTERNALSYM PKCS12_add_localkeyid}
  PKCS12_add_localkeyid: function (bag: PPKCS12_SAFEBAG; name: PByte; namelen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_add_friendlyname_asc}
  PKCS12_add_friendlyname_asc: function (bag: PPKCS12_SAFEBAG; const name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_add_friendlyname_utf8}
  PKCS12_add_friendlyname_utf8: function (bag: PPKCS12_SAFEBAG; const name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM PKCS12_add_CSPName_asc}
  PKCS12_add_CSPName_asc: function (bag: PPKCS12_SAFEBAG; const name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_add_friendlyname_uni}
  PKCS12_add_friendlyname_uni: function (bag: PPKCS12_SAFEBAG; const name: PByte; namelen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS8_add_keyusage}
  PKCS8_add_keyusage: function (p8: PPKCS8_PRIV_KEY_INFO; usage: TIdC_INT): TIdC_INT; cdecl = nil;
//  function PKCS12_get_attr_gen(const STACK_OF(X509_ATTRIBUTE) *attrs; TIdC_INT attr_nid): PASN1_TYPE;
  {$EXTERNALSYM PKCS12_get_friendlyname}
  PKCS12_get_friendlyname: function (bag: PPKCS12_SAFEBAG): PIdAnsiChar; cdecl = nil;
//  const STACK_OF(X509_ATTRIBUTE) *PKCS12_SAFEBAG_get0_attrs(const PKCS12_SAFEBAG *bag);
  {$EXTERNALSYM PKCS12_pbe_crypt}
  PKCS12_pbe_crypt: function (const algor: PX509_ALGOR; const pass: PIdAnsiChar; passlen: TIdC_INT; const in_: PByte; inlen: TIdC_INT; data: PPByte; datalen: PIdC_INT; en_de: TIdC_INT): PByte; cdecl = nil;
  {$EXTERNALSYM PKCS12_item_decrypt_d2i}
  PKCS12_item_decrypt_d2i: function (const algor: PX509_ALGOR; const it: PASN1_ITEM; const pass: PIdAnsiChar; passlen: TIdC_INT; const oct: PASN1_OCTET_STRING; zbuf: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM PKCS12_item_i2d_encrypt}
  PKCS12_item_i2d_encrypt: function (algor: PX509_ALGOR; const it: PASN1_ITEM; const pass: PIdAnsiChar; passlen: TIdC_INT; obj: Pointer; zbuf: TIdC_INT): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM PKCS12_init}
  PKCS12_init: function (mode: TIdC_INT): PPKCS12; cdecl = nil;
  {$EXTERNALSYM PKCS12_key_gen_asc}
  PKCS12_key_gen_asc: function (const pass: PIdAnsiChar; passlen: TIdC_INT; salt: PByte; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; out_: PByte; const md_type: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_key_gen_uni}
  PKCS12_key_gen_uni: function (pass: PByte; passlen: TIdC_INT; salt: PByte; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; out_: PByte; const md_type: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_key_gen_utf8}
  PKCS12_key_gen_utf8: function (const pass: PIdAnsiChar; passlen: TIdC_INT; salt: PByte; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; out_: PByte; const md_type: PEVP_MD): TIdC_INT; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM PKCS12_PBE_keyivgen}
  PKCS12_PBE_keyivgen: function (ctx: PEVP_CIPHER_CTX; const pass: PIdAnsiChar; passlen: TIdC_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md_type: PEVP_MD; en_de: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_gen_mac}
  PKCS12_gen_mac: function (p12: PPKCS12; const pass: PIdAnsiChar; passlen: TIdC_INT; mac: PByte; maclen: PIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_verify_mac}
  PKCS12_verify_mac: function (p12: PPKCS12; const pass: PIdAnsiChar; passlen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_set_mac}
  PKCS12_set_mac: function (p12: PPKCS12; const pass: PIdAnsiChar; passlen: TIdC_INT; salt: PByte; saltlen: TIdC_INT; iter: TIdC_INT; const md_type: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_setup_mac}
  PKCS12_setup_mac: function (p12: PPKCS12; iter: TIdC_INT; salt: PByte; saltlen: TIdC_INT; const md_type: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OPENSSL_asc2uni}
  OPENSSL_asc2uni: function (const asc: PIdAnsiChar; asclen: TIdC_INT; uni: PPByte; unilen: PIdC_INT): PByte; cdecl = nil;
  {$EXTERNALSYM OPENSSL_uni2asc}
  OPENSSL_uni2asc: function (const uni: PByte; unilen: TIdC_INT): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM OPENSSL_utf82uni}
  OPENSSL_utf82uni: function (const asc: PIdAnsiChar; asclen: TIdC_INT; uni: PPByte; unilen: PIdC_INT): PByte; cdecl = nil; {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_uni2utf8}
  OPENSSL_uni2utf8: function (const uni: PByte; unilen: TIdC_INT): PIdAnsiChar; cdecl = nil; {introduced 1.1.0}

  {$EXTERNALSYM PKCS12_new}
  PKCS12_new: function : PPKCS12; cdecl = nil;
  {$EXTERNALSYM PKCS12_free}
  PKCS12_free: procedure (a: PPKCS12); cdecl = nil;
  {$EXTERNALSYM d2i_PKCS12}
  d2i_PKCS12: function (a: PPPKCS12; const in_: PPByte; len: TIdC_LONG): PPKCS12; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS12}
  i2d_PKCS12: function (a: PPKCS12; out_: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_it}
  PKCS12_it: function : PASN1_ITEM; cdecl = nil;

  {$EXTERNALSYM PKCS12_MAC_DATA_new}
  PKCS12_MAC_DATA_new: function : PPKCS12_MAC_DATA; cdecl = nil;
  {$EXTERNALSYM PKCS12_MAC_DATA_free}
  PKCS12_MAC_DATA_free: procedure (a: PPKCS12_MAC_DATA); cdecl = nil;
  {$EXTERNALSYM d2i_PKCS12_MAC_DATA}
  d2i_PKCS12_MAC_DATA: function (a: PPPKCS12_MAC_DATA; const in_: PPByte; len: TIdC_LONG): PPKCS12_MAC_DATA; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS12_MAC_DATA}
  i2d_PKCS12_MAC_DATA: function (a: PPKCS12_MAC_DATA; out_: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_MAC_DATA_it}
  PKCS12_MAC_DATA_it: function : PASN1_ITEM; cdecl = nil;

  {$EXTERNALSYM PKCS12_SAFEBAG_new}
  PKCS12_SAFEBAG_new: function : PPKCS12_SAFEBAG; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_free}
  PKCS12_SAFEBAG_free: procedure (a: PPKCS12_SAFEBAG); cdecl = nil;
  {$EXTERNALSYM d2i_PKCS12_SAFEBAG}
  d2i_PKCS12_SAFEBAG: function (a: PPPKCS12_SAFEBAG; const in_: PPByte; len: TIdC_LONG): PPKCS12_SAFEBAG; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS12_SAFEBAG}
  i2d_PKCS12_SAFEBAG: function (a: PPKCS12_SAFEBAG; out_: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_SAFEBAG_it}
  PKCS12_SAFEBAG_it: function : PASN1_ITEM; cdecl = nil;

  {$EXTERNALSYM PKCS12_BAGS_new}
  PKCS12_BAGS_new: function : PPKCS12_BAGS; cdecl = nil;
  {$EXTERNALSYM PKCS12_BAGS_free}
  PKCS12_BAGS_free: procedure (a: PPKCS12_BAGS); cdecl = nil;
  {$EXTERNALSYM d2i_PKCS12_BAGS}
  d2i_PKCS12_BAGS: function (a: PPPKCS12_BAGS; const in_: PPByte; len: TIdC_LONG): PPKCS12_BAGS; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS12_BAGS}
  i2d_PKCS12_BAGS: function (a: PPKCS12_BAGS; out_: PPByte): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_BAGS_it}
  PKCS12_BAGS_it: function : PASN1_ITEM; cdecl = nil;

  {$EXTERNALSYM PKCS12_PBE_add}
  PKCS12_PBE_add: procedure (v: Pointer); cdecl = nil;
  {$EXTERNALSYM PKCS12_parse}
  PKCS12_parse: function (p12: PPKCS12; const pass: PIdAnsiChar; var pkey: PEVP_PKEY; var cert: PX509; ca: PPStack_Of_X509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS12_create}
  PKCS12_create: function (const pass: PIdAnsiChar; const name: PIdAnsiChar; pkey: PEVP_PKEY; cert: PX509; ca: PStack_Of_X509; nid_key: TIdC_INT; nid_cert: TIdC_INT; iter: TIdC_INT; mac_iter: TIdC_INT; keytype: TIdC_INT): PPKCS12; cdecl = nil;

//  function PKCS12_add_cert(STACK_OF(PKCS12_SAFEBAG) **pbags; X509 *cert): PKCS12_SAFEBAG;
//  PKCS12_SAFEBAG *PKCS12_add_key(STACK_OF(PKCS12_SAFEBAG) **pbags;
//                                 EVP_PKEY *key; TIdC_INT key_usage; iter: TIdC_INT;
//                                 TIdC_INT key_nid; const pass: PIdAnsiChar);
//  TIdC_INT PKCS12_add_safe(STACK_OF(PKCS7) **psafes; STACK_OF(PKCS12_SAFEBAG) *bags;
//                      TIdC_INT safe_nid; iter: TIdC_INT; const pass: PIdAnsiChar);
//  PKCS12 *PKCS12_add_safes(STACK_OF(PKCS7) *safes; TIdC_INT p7_nid);

  {$EXTERNALSYM i2d_PKCS12_bio}
  i2d_PKCS12_bio: function (bp: PBIO; p12: PPKCS12): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS12_bio}
  d2i_PKCS12_bio: function (bp: PBIO; p12: PPPKCS12): PPKCS12; cdecl = nil;
  {$EXTERNALSYM PKCS12_newpass}
  PKCS12_newpass: function (p12: PPKCS12; const oldpass: PIdAnsiChar; const newpass: PIdAnsiChar): TIdC_INT; cdecl = nil;

{$ELSE}
  {$EXTERNALSYM PKCS12_mac_present}
  function PKCS12_mac_present(const p12: PPKCS12): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM PKCS12_get0_mac}
  procedure PKCS12_get0_mac(const pmac: PPASN1_OCTET_STRING; const pmacalg: PPX509_ALGOR; const psalt: PPASN1_OCTET_STRING; const piter: PPASN1_INTEGER; const p12: PPKCS12) cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM PKCS12_SAFEBAG_get0_attr}
  function PKCS12_SAFEBAG_get0_attr(const bag: PPKCS12_SAFEBAG; attr_nid: TIdC_INT): PASN1_TYPE cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM PKCS12_SAFEBAG_get0_type}
  function PKCS12_SAFEBAG_get0_type(const bag: PPKCS12_SAFEBAG): PASN1_OBJECT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM PKCS12_SAFEBAG_get_nid}
  function PKCS12_SAFEBAG_get_nid(const bag: PPKCS12_SAFEBAG): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM PKCS12_SAFEBAG_get_bag_nid}
  function PKCS12_SAFEBAG_get_bag_nid(const bag: PPKCS12_SAFEBAG): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM PKCS12_SAFEBAG_get1_cert}
  function PKCS12_SAFEBAG_get1_cert(const bag: PPKCS12_SAFEBAG): PX509 cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM PKCS12_SAFEBAG_get1_crl}
  function PKCS12_SAFEBAG_get1_crl(const bag: PPKCS12_SAFEBAG): PX509_CRL cdecl; external CLibCrypto; {introduced 1.1.0}
//  const STACK_OF(PKCS12_SAFEBAG) *PKCS12_SAFEBAG_get0_safes(const PKCS12_SAFEBAG *bag);
  {$EXTERNALSYM PKCS12_SAFEBAG_get0_p8inf}
  function PKCS12_SAFEBAG_get0_p8inf(const bag: PPKCS12_SAFEBAG): PPKCS8_PRIV_KEY_INFO cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM PKCS12_SAFEBAG_get0_pkcs8}
  function PKCS12_SAFEBAG_get0_pkcs8(const bag: PPKCS12_SAFEBAG): PX509_SIG cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM PKCS12_SAFEBAG_create_cert}
  function PKCS12_SAFEBAG_create_cert(x509: PX509): PPKCS12_SAFEBAG cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM PKCS12_SAFEBAG_create_crl}
  function PKCS12_SAFEBAG_create_crl(crl: PX509_CRL): PPKCS12_SAFEBAG cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM PKCS12_SAFEBAG_create0_p8inf}
  function PKCS12_SAFEBAG_create0_p8inf(p8: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM PKCS12_SAFEBAG_create0_pkcs8}
  function PKCS12_SAFEBAG_create0_pkcs8(p8: PX509_SIG): PPKCS12_SAFEBAG cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM PKCS12_SAFEBAG_create_pkcs8_encrypt}
  function PKCS12_SAFEBAG_create_pkcs8_encrypt(pbe_nid: TIdC_INT; const pass: PIdAnsiChar; passlen: TIdC_INT; salt: PByte; saltlen: TIdC_INT; iter: TIdC_INT; p8inf: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM PKCS12_item_pack_safebag}
  function PKCS12_item_pack_safebag(obj: Pointer; const it: PASN1_ITEM; nid1: TIdC_INT; nid2: TIdC_INT): PPKCS12_SAFEBAG cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS8_decrypt}
  function PKCS8_decrypt(const p8: PX509_SIG; const pass: PIdAnsiChar; passlen: TIdC_INT): PPKCS8_PRIV_KEY_INFO cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS12_decrypt_skey}
  function PKCS12_decrypt_skey(const bag: PPKCS12_SAFEBAG; const pass: PIdAnsiChar; passlen: TIdC_INT): PPKCS8_PRIV_KEY_INFO cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS8_encrypt}
  function PKCS8_encrypt(pbe_nid: TIdC_INT; const cipher: PEVP_CIPHER; const pass: PIdAnsiChar; passlen: TIdC_INT; salt: PByte; saltlen: TIdC_INT; iter: TIdC_INT; p8: PPKCS8_PRIV_KEY_INFO): PX509_SIG cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS8_set0_pbe}
  function PKCS8_set0_pbe(const pass: PIdAnsiChar; passlen: TIdC_INT; p8inf: PPKCS8_PRIV_KEY_INFO; pbe: PX509_ALGOR): PX509_SIG cdecl; external CLibCrypto; {introduced 1.1.0}
//  PKCS7 *PKCS12_pack_p7data(STACK_OF(PKCS12_SAFEBAG) *sk);
//  STACK_OF(PKCS12_SAFEBAG) *PKCS12_unpack_p7data(PKCS7 *p7);
//  function PKCS12_pack_p7encdata(TIdC_INT pbe_nid, const PIdAnsiChar pass, TIdC_INT passlen,
//                               Byte *salt, TIdC_INT saltlen, TIdC_INT iter,
//                               STACK_OF(PKCS12_SAFEBAG) *bags): PPKCS7;
//  STACK_OF(PKCS12_SAFEBAG) *PKCS12_unpack_p7encdata(PKCS7 *p7, const PIdAnsiChar *pass,
//                                                    TIdC_INT passlen);

//  TIdC_INT PKCS12_pack_authsafes(PKCS12 *p12, STACK_OF(PKCS7) *safes);
//  STACK_OF(PKCS7) *PKCS12_unpack_authsafes(const PKCS12 *p12);

  {$EXTERNALSYM PKCS12_add_localkeyid}
  function PKCS12_add_localkeyid(bag: PPKCS12_SAFEBAG; name: PByte; namelen: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS12_add_friendlyname_asc}
  function PKCS12_add_friendlyname_asc(bag: PPKCS12_SAFEBAG; const name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS12_add_friendlyname_utf8}
  function PKCS12_add_friendlyname_utf8(bag: PPKCS12_SAFEBAG; const name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM PKCS12_add_CSPName_asc}
  function PKCS12_add_CSPName_asc(bag: PPKCS12_SAFEBAG; const name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS12_add_friendlyname_uni}
  function PKCS12_add_friendlyname_uni(bag: PPKCS12_SAFEBAG; const name: PByte; namelen: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS8_add_keyusage}
  function PKCS8_add_keyusage(p8: PPKCS8_PRIV_KEY_INFO; usage: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
//  function PKCS12_get_attr_gen(const STACK_OF(X509_ATTRIBUTE) *attrs; TIdC_INT attr_nid): PASN1_TYPE;
  {$EXTERNALSYM PKCS12_get_friendlyname}
  function PKCS12_get_friendlyname(bag: PPKCS12_SAFEBAG): PIdAnsiChar cdecl; external CLibCrypto;
//  const STACK_OF(X509_ATTRIBUTE) *PKCS12_SAFEBAG_get0_attrs(const PKCS12_SAFEBAG *bag);
  {$EXTERNALSYM PKCS12_pbe_crypt}
  function PKCS12_pbe_crypt(const algor: PX509_ALGOR; const pass: PIdAnsiChar; passlen: TIdC_INT; const in_: PByte; inlen: TIdC_INT; data: PPByte; datalen: PIdC_INT; en_de: TIdC_INT): PByte cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS12_item_decrypt_d2i}
  function PKCS12_item_decrypt_d2i(const algor: PX509_ALGOR; const it: PASN1_ITEM; const pass: PIdAnsiChar; passlen: TIdC_INT; const oct: PASN1_OCTET_STRING; zbuf: TIdC_INT): Pointer cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS12_item_i2d_encrypt}
  function PKCS12_item_i2d_encrypt(algor: PX509_ALGOR; const it: PASN1_ITEM; const pass: PIdAnsiChar; passlen: TIdC_INT; obj: Pointer; zbuf: TIdC_INT): PASN1_OCTET_STRING cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS12_init}
  function PKCS12_init(mode: TIdC_INT): PPKCS12 cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS12_key_gen_asc}
  function PKCS12_key_gen_asc(const pass: PIdAnsiChar; passlen: TIdC_INT; salt: PByte; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; out_: PByte; const md_type: PEVP_MD): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS12_key_gen_uni}
  function PKCS12_key_gen_uni(pass: PByte; passlen: TIdC_INT; salt: PByte; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; out_: PByte; const md_type: PEVP_MD): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS12_key_gen_utf8}
  function PKCS12_key_gen_utf8(const pass: PIdAnsiChar; passlen: TIdC_INT; salt: PByte; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; out_: PByte; const md_type: PEVP_MD): TIdC_INT cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM PKCS12_PBE_keyivgen}
  function PKCS12_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PIdAnsiChar; passlen: TIdC_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md_type: PEVP_MD; en_de: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS12_gen_mac}
  function PKCS12_gen_mac(p12: PPKCS12; const pass: PIdAnsiChar; passlen: TIdC_INT; mac: PByte; maclen: PIdC_UINT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS12_verify_mac}
  function PKCS12_verify_mac(p12: PPKCS12; const pass: PIdAnsiChar; passlen: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS12_set_mac}
  function PKCS12_set_mac(p12: PPKCS12; const pass: PIdAnsiChar; passlen: TIdC_INT; salt: PByte; saltlen: TIdC_INT; iter: TIdC_INT; const md_type: PEVP_MD): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS12_setup_mac}
  function PKCS12_setup_mac(p12: PPKCS12; iter: TIdC_INT; salt: PByte; saltlen: TIdC_INT; const md_type: PEVP_MD): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM OPENSSL_asc2uni}
  function OPENSSL_asc2uni(const asc: PIdAnsiChar; asclen: TIdC_INT; uni: PPByte; unilen: PIdC_INT): PByte cdecl; external CLibCrypto;
  {$EXTERNALSYM OPENSSL_uni2asc}
  function OPENSSL_uni2asc(const uni: PByte; unilen: TIdC_INT): PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM OPENSSL_utf82uni}
  function OPENSSL_utf82uni(const asc: PIdAnsiChar; asclen: TIdC_INT; uni: PPByte; unilen: PIdC_INT): PByte cdecl; external CLibCrypto; {introduced 1.1.0}
  {$EXTERNALSYM OPENSSL_uni2utf8}
  function OPENSSL_uni2utf8(const uni: PByte; unilen: TIdC_INT): PIdAnsiChar cdecl; external CLibCrypto; {introduced 1.1.0}

  {$EXTERNALSYM PKCS12_new}
  function PKCS12_new: PPKCS12 cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS12_free}
  procedure PKCS12_free(a: PPKCS12) cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_PKCS12}
  function d2i_PKCS12(a: PPPKCS12; const in_: PPByte; len: TIdC_LONG): PPKCS12 cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_PKCS12}
  function i2d_PKCS12(a: PPKCS12; out_: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS12_it}
  function PKCS12_it: PASN1_ITEM cdecl; external CLibCrypto;

  {$EXTERNALSYM PKCS12_MAC_DATA_new}
  function PKCS12_MAC_DATA_new: PPKCS12_MAC_DATA cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS12_MAC_DATA_free}
  procedure PKCS12_MAC_DATA_free(a: PPKCS12_MAC_DATA) cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_PKCS12_MAC_DATA}
  function d2i_PKCS12_MAC_DATA(a: PPPKCS12_MAC_DATA; const in_: PPByte; len: TIdC_LONG): PPKCS12_MAC_DATA cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_PKCS12_MAC_DATA}
  function i2d_PKCS12_MAC_DATA(a: PPKCS12_MAC_DATA; out_: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS12_MAC_DATA_it}
  function PKCS12_MAC_DATA_it: PASN1_ITEM cdecl; external CLibCrypto;

  {$EXTERNALSYM PKCS12_SAFEBAG_new}
  function PKCS12_SAFEBAG_new: PPKCS12_SAFEBAG cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS12_SAFEBAG_free}
  procedure PKCS12_SAFEBAG_free(a: PPKCS12_SAFEBAG) cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_PKCS12_SAFEBAG}
  function d2i_PKCS12_SAFEBAG(a: PPPKCS12_SAFEBAG; const in_: PPByte; len: TIdC_LONG): PPKCS12_SAFEBAG cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_PKCS12_SAFEBAG}
  function i2d_PKCS12_SAFEBAG(a: PPKCS12_SAFEBAG; out_: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS12_SAFEBAG_it}
  function PKCS12_SAFEBAG_it: PASN1_ITEM cdecl; external CLibCrypto;

  {$EXTERNALSYM PKCS12_BAGS_new}
  function PKCS12_BAGS_new: PPKCS12_BAGS cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS12_BAGS_free}
  procedure PKCS12_BAGS_free(a: PPKCS12_BAGS) cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_PKCS12_BAGS}
  function d2i_PKCS12_BAGS(a: PPPKCS12_BAGS; const in_: PPByte; len: TIdC_LONG): PPKCS12_BAGS cdecl; external CLibCrypto;
  {$EXTERNALSYM i2d_PKCS12_BAGS}
  function i2d_PKCS12_BAGS(a: PPKCS12_BAGS; out_: PPByte): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS12_BAGS_it}
  function PKCS12_BAGS_it: PASN1_ITEM cdecl; external CLibCrypto;

  {$EXTERNALSYM PKCS12_PBE_add}
  procedure PKCS12_PBE_add(v: Pointer) cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS12_parse}
  function PKCS12_parse(p12: PPKCS12; const pass: PIdAnsiChar; var pkey: PEVP_PKEY; var cert: PX509; ca: PPStack_Of_X509): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS12_create}
  function PKCS12_create(const pass: PIdAnsiChar; const name: PIdAnsiChar; pkey: PEVP_PKEY; cert: PX509; ca: PStack_Of_X509; nid_key: TIdC_INT; nid_cert: TIdC_INT; iter: TIdC_INT; mac_iter: TIdC_INT; keytype: TIdC_INT): PPKCS12 cdecl; external CLibCrypto;

//  function PKCS12_add_cert(STACK_OF(PKCS12_SAFEBAG) **pbags; X509 *cert): PKCS12_SAFEBAG;
//  PKCS12_SAFEBAG *PKCS12_add_key(STACK_OF(PKCS12_SAFEBAG) **pbags;
//                                 EVP_PKEY *key; TIdC_INT key_usage; iter: TIdC_INT;
//                                 TIdC_INT key_nid; const pass: PIdAnsiChar);
//  TIdC_INT PKCS12_add_safe(STACK_OF(PKCS7) **psafes; STACK_OF(PKCS12_SAFEBAG) *bags;
//                      TIdC_INT safe_nid; iter: TIdC_INT; const pass: PIdAnsiChar);
//  PKCS12 *PKCS12_add_safes(STACK_OF(PKCS7) *safes; TIdC_INT p7_nid);

  {$EXTERNALSYM i2d_PKCS12_bio}
  function i2d_PKCS12_bio(bp: PBIO; p12: PPKCS12): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM d2i_PKCS12_bio}
  function d2i_PKCS12_bio(bp: PBIO; p12: PPPKCS12): PPKCS12 cdecl; external CLibCrypto;
  {$EXTERNALSYM PKCS12_newpass}
  function PKCS12_newpass(p12: PPKCS12; const oldpass: PIdAnsiChar; const newpass: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;

{$ENDIF}

implementation

  uses
    classes, 
    TaurusTLSExceptionHandlers
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    ,TaurusTLSLoader
  {$ENDIF};
  
const
  PKCS12_mac_present_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PKCS12_get0_mac_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PKCS12_SAFEBAG_get0_attr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PKCS12_SAFEBAG_get0_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PKCS12_SAFEBAG_get_nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PKCS12_SAFEBAG_get_bag_nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PKCS12_SAFEBAG_get1_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PKCS12_SAFEBAG_get1_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PKCS12_SAFEBAG_get0_p8inf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PKCS12_SAFEBAG_get0_pkcs8_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PKCS12_SAFEBAG_create_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PKCS12_SAFEBAG_create_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PKCS12_SAFEBAG_create0_p8inf_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PKCS12_SAFEBAG_create0_pkcs8_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PKCS12_SAFEBAG_create_pkcs8_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PKCS8_set0_pbe_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PKCS12_add_friendlyname_utf8_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PKCS12_key_gen_utf8_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_utf82uni_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  OPENSSL_uni2utf8_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
const
  PKCS12_mac_present_procname = 'PKCS12_mac_present'; {introduced 1.1.0}
  PKCS12_get0_mac_procname = 'PKCS12_get0_mac'; {introduced 1.1.0}

  PKCS12_SAFEBAG_get0_attr_procname = 'PKCS12_SAFEBAG_get0_attr'; {introduced 1.1.0}
  PKCS12_SAFEBAG_get0_type_procname = 'PKCS12_SAFEBAG_get0_type'; {introduced 1.1.0}
  PKCS12_SAFEBAG_get_nid_procname = 'PKCS12_SAFEBAG_get_nid'; {introduced 1.1.0}
  PKCS12_SAFEBAG_get_bag_nid_procname = 'PKCS12_SAFEBAG_get_bag_nid'; {introduced 1.1.0}

  PKCS12_SAFEBAG_get1_cert_procname = 'PKCS12_SAFEBAG_get1_cert'; {introduced 1.1.0}
  PKCS12_SAFEBAG_get1_crl_procname = 'PKCS12_SAFEBAG_get1_crl'; {introduced 1.1.0}
//  const STACK_OF(PKCS12_SAFEBAG) *PKCS12_SAFEBAG_get0_safes(const PKCS12_SAFEBAG *bag);
  PKCS12_SAFEBAG_get0_p8inf_procname = 'PKCS12_SAFEBAG_get0_p8inf'; {introduced 1.1.0}
  PKCS12_SAFEBAG_get0_pkcs8_procname = 'PKCS12_SAFEBAG_get0_pkcs8'; {introduced 1.1.0}

  PKCS12_SAFEBAG_create_cert_procname = 'PKCS12_SAFEBAG_create_cert'; {introduced 1.1.0}
  PKCS12_SAFEBAG_create_crl_procname = 'PKCS12_SAFEBAG_create_crl'; {introduced 1.1.0}
  PKCS12_SAFEBAG_create0_p8inf_procname = 'PKCS12_SAFEBAG_create0_p8inf'; {introduced 1.1.0}
  PKCS12_SAFEBAG_create0_pkcs8_procname = 'PKCS12_SAFEBAG_create0_pkcs8'; {introduced 1.1.0}
  PKCS12_SAFEBAG_create_pkcs8_encrypt_procname = 'PKCS12_SAFEBAG_create_pkcs8_encrypt'; {introduced 1.1.0}

  PKCS12_item_pack_safebag_procname = 'PKCS12_item_pack_safebag';
  PKCS8_decrypt_procname = 'PKCS8_decrypt';
  PKCS12_decrypt_skey_procname = 'PKCS12_decrypt_skey';
  PKCS8_encrypt_procname = 'PKCS8_encrypt';
  PKCS8_set0_pbe_procname = 'PKCS8_set0_pbe'; {introduced 1.1.0}
//  PKCS7 *PKCS12_pack_p7data(STACK_OF(PKCS12_SAFEBAG) *sk);
//  STACK_OF(PKCS12_SAFEBAG) *PKCS12_unpack_p7data(PKCS7 *p7);
//  function PKCS12_pack_p7encdata(TIdC_INT pbe_nid, const PIdAnsiChar pass, TIdC_INT passlen,
//                               Byte *salt, TIdC_INT saltlen, TIdC_INT iter,
//                               STACK_OF(PKCS12_SAFEBAG) *bags): PPKCS7;
//  STACK_OF(PKCS12_SAFEBAG) *PKCS12_unpack_p7encdata(PKCS7 *p7, const PIdAnsiChar *pass,
//                                                    TIdC_INT passlen);

//  TIdC_INT PKCS12_pack_authsafes(PKCS12 *p12, STACK_OF(PKCS7) *safes);
//  STACK_OF(PKCS7) *PKCS12_unpack_authsafes(const PKCS12 *p12);

  PKCS12_add_localkeyid_procname = 'PKCS12_add_localkeyid';
  PKCS12_add_friendlyname_asc_procname = 'PKCS12_add_friendlyname_asc';
  PKCS12_add_friendlyname_utf8_procname = 'PKCS12_add_friendlyname_utf8'; {introduced 1.1.0}
  PKCS12_add_CSPName_asc_procname = 'PKCS12_add_CSPName_asc';
  PKCS12_add_friendlyname_uni_procname = 'PKCS12_add_friendlyname_uni';
  PKCS8_add_keyusage_procname = 'PKCS8_add_keyusage';
//  function PKCS12_get_attr_gen(const STACK_OF(X509_ATTRIBUTE) *attrs; TIdC_INT attr_nid): PASN1_TYPE;
  PKCS12_get_friendlyname_procname = 'PKCS12_get_friendlyname';
//  const STACK_OF(X509_ATTRIBUTE) *PKCS12_SAFEBAG_get0_attrs(const PKCS12_SAFEBAG *bag);
  PKCS12_pbe_crypt_procname = 'PKCS12_pbe_crypt';
  PKCS12_item_decrypt_d2i_procname = 'PKCS12_item_decrypt_d2i';
  PKCS12_item_i2d_encrypt_procname = 'PKCS12_item_i2d_encrypt';
  PKCS12_init_procname = 'PKCS12_init';
  PKCS12_key_gen_asc_procname = 'PKCS12_key_gen_asc';
  PKCS12_key_gen_uni_procname = 'PKCS12_key_gen_uni';
  PKCS12_key_gen_utf8_procname = 'PKCS12_key_gen_utf8'; {introduced 1.1.0}
  PKCS12_PBE_keyivgen_procname = 'PKCS12_PBE_keyivgen';
  PKCS12_gen_mac_procname = 'PKCS12_gen_mac';
  PKCS12_verify_mac_procname = 'PKCS12_verify_mac';
  PKCS12_set_mac_procname = 'PKCS12_set_mac';
  PKCS12_setup_mac_procname = 'PKCS12_setup_mac';
  OPENSSL_asc2uni_procname = 'OPENSSL_asc2uni';
  OPENSSL_uni2asc_procname = 'OPENSSL_uni2asc';
  OPENSSL_utf82uni_procname = 'OPENSSL_utf82uni'; {introduced 1.1.0}
  OPENSSL_uni2utf8_procname = 'OPENSSL_uni2utf8'; {introduced 1.1.0}

  PKCS12_new_procname = 'PKCS12_new';
  PKCS12_free_procname = 'PKCS12_free';
  d2i_PKCS12_procname = 'd2i_PKCS12';
  i2d_PKCS12_procname = 'i2d_PKCS12';
  PKCS12_it_procname = 'PKCS12_it';

  PKCS12_MAC_DATA_new_procname = 'PKCS12_MAC_DATA_new';
  PKCS12_MAC_DATA_free_procname = 'PKCS12_MAC_DATA_free';
  d2i_PKCS12_MAC_DATA_procname = 'd2i_PKCS12_MAC_DATA';
  i2d_PKCS12_MAC_DATA_procname = 'i2d_PKCS12_MAC_DATA';
  PKCS12_MAC_DATA_it_procname = 'PKCS12_MAC_DATA_it';

  PKCS12_SAFEBAG_new_procname = 'PKCS12_SAFEBAG_new';
  PKCS12_SAFEBAG_free_procname = 'PKCS12_SAFEBAG_free';
  d2i_PKCS12_SAFEBAG_procname = 'd2i_PKCS12_SAFEBAG';
  i2d_PKCS12_SAFEBAG_procname = 'i2d_PKCS12_SAFEBAG';
  PKCS12_SAFEBAG_it_procname = 'PKCS12_SAFEBAG_it';

  PKCS12_BAGS_new_procname = 'PKCS12_BAGS_new';
  PKCS12_BAGS_free_procname = 'PKCS12_BAGS_free';
  d2i_PKCS12_BAGS_procname = 'd2i_PKCS12_BAGS';
  i2d_PKCS12_BAGS_procname = 'i2d_PKCS12_BAGS';
  PKCS12_BAGS_it_procname = 'PKCS12_BAGS_it';

  PKCS12_PBE_add_procname = 'PKCS12_PBE_add';
  PKCS12_parse_procname = 'PKCS12_parse';
  PKCS12_create_procname = 'PKCS12_create';

//  function PKCS12_add_cert(STACK_OF(PKCS12_SAFEBAG) **pbags; X509 *cert): PKCS12_SAFEBAG;
//  PKCS12_SAFEBAG *PKCS12_add_key(STACK_OF(PKCS12_SAFEBAG) **pbags;
//                                 EVP_PKEY *key; TIdC_INT key_usage; iter: TIdC_INT;
//                                 TIdC_INT key_nid; const pass: PIdAnsiChar);
//  TIdC_INT PKCS12_add_safe(STACK_OF(PKCS7) **psafes; STACK_OF(PKCS12_SAFEBAG) *bags;
//                      TIdC_INT safe_nid; iter: TIdC_INT; const pass: PIdAnsiChar);
//  PKCS12 *PKCS12_add_safes(STACK_OF(PKCS7) *safes; TIdC_INT p7_nid);

  i2d_PKCS12_bio_procname = 'i2d_PKCS12_bio';
  d2i_PKCS12_bio_procname = 'd2i_PKCS12_bio';
  PKCS12_newpass_procname = 'PKCS12_newpass';

  {$IFNDEF _FIXINSIGHT_}
  {$I TaurusTLSNoRetValOff.inc}
function  ERR_PKCS12_mac_present(const p12: PPKCS12): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_mac_present_procname);
end;

 {introduced 1.1.0}
procedure  ERR_PKCS12_get0_mac(const pmac: PPASN1_OCTET_STRING; const pmacalg: PPX509_ALGOR; const psalt: PPASN1_OCTET_STRING; const piter: PPASN1_INTEGER; const p12: PPKCS12);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_get0_mac_procname);
end;

 {introduced 1.1.0}

function  ERR_PKCS12_SAFEBAG_get0_attr(const bag: PPKCS12_SAFEBAG; attr_nid: TIdC_INT): PASN1_TYPE;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_get0_attr_procname);
end;

 {introduced 1.1.0}
function  ERR_PKCS12_SAFEBAG_get0_type(const bag: PPKCS12_SAFEBAG): PASN1_OBJECT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_get0_type_procname);
end;

 {introduced 1.1.0}
function  ERR_PKCS12_SAFEBAG_get_nid(const bag: PPKCS12_SAFEBAG): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_get_nid_procname);
end;

 {introduced 1.1.0}
function  ERR_PKCS12_SAFEBAG_get_bag_nid(const bag: PPKCS12_SAFEBAG): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_get_bag_nid_procname);
end;

 {introduced 1.1.0}

function  ERR_PKCS12_SAFEBAG_get1_cert(const bag: PPKCS12_SAFEBAG): PX509;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_get1_cert_procname);
end;

 {introduced 1.1.0}
function  ERR_PKCS12_SAFEBAG_get1_crl(const bag: PPKCS12_SAFEBAG): PX509_CRL;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_get1_crl_procname);
end;

 {introduced 1.1.0}
//  const STACK_OF(PKCS12_SAFEBAG) *PKCS12_SAFEBAG_get0_safes(const PKCS12_SAFEBAG *bag);
function  ERR_PKCS12_SAFEBAG_get0_p8inf(const bag: PPKCS12_SAFEBAG): PPKCS8_PRIV_KEY_INFO;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_get0_p8inf_procname);
end;

 {introduced 1.1.0}
function  ERR_PKCS12_SAFEBAG_get0_pkcs8(const bag: PPKCS12_SAFEBAG): PX509_SIG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_get0_pkcs8_procname);
end;

 {introduced 1.1.0}

function  ERR_PKCS12_SAFEBAG_create_cert(x509: PX509): PPKCS12_SAFEBAG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_create_cert_procname);
end;

 {introduced 1.1.0}
function  ERR_PKCS12_SAFEBAG_create_crl(crl: PX509_CRL): PPKCS12_SAFEBAG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_create_crl_procname);
end;

 {introduced 1.1.0}
function  ERR_PKCS12_SAFEBAG_create0_p8inf(p8: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_create0_p8inf_procname);
end;

 {introduced 1.1.0}
function  ERR_PKCS12_SAFEBAG_create0_pkcs8(p8: PX509_SIG): PPKCS12_SAFEBAG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_create0_pkcs8_procname);
end;

 {introduced 1.1.0}
function  ERR_PKCS12_SAFEBAG_create_pkcs8_encrypt(pbe_nid: TIdC_INT; const pass: PIdAnsiChar; passlen: TIdC_INT; salt: PByte; saltlen: TIdC_INT; iter: TIdC_INT; p8inf: PPKCS8_PRIV_KEY_INFO): PPKCS12_SAFEBAG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_create_pkcs8_encrypt_procname);
end;

 {introduced 1.1.0}

function  ERR_PKCS12_item_pack_safebag(obj: Pointer; const it: PASN1_ITEM; nid1: TIdC_INT; nid2: TIdC_INT): PPKCS12_SAFEBAG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_item_pack_safebag_procname);
end;


function  ERR_PKCS8_decrypt(const p8: PX509_SIG; const pass: PIdAnsiChar; passlen: TIdC_INT): PPKCS8_PRIV_KEY_INFO;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS8_decrypt_procname);
end;


function  ERR_PKCS12_decrypt_skey(const bag: PPKCS12_SAFEBAG; const pass: PIdAnsiChar; passlen: TIdC_INT): PPKCS8_PRIV_KEY_INFO;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_decrypt_skey_procname);
end;


function  ERR_PKCS8_encrypt(pbe_nid: TIdC_INT; const cipher: PEVP_CIPHER; const pass: PIdAnsiChar; passlen: TIdC_INT; salt: PByte; saltlen: TIdC_INT; iter: TIdC_INT; p8: PPKCS8_PRIV_KEY_INFO): PX509_SIG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS8_encrypt_procname);
end;


function  ERR_PKCS8_set0_pbe(const pass: PIdAnsiChar; passlen: TIdC_INT; p8inf: PPKCS8_PRIV_KEY_INFO; pbe: PX509_ALGOR): PX509_SIG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS8_set0_pbe_procname);
end;

 {introduced 1.1.0}
//  PKCS7 *PKCS12_pack_p7data(STACK_OF(PKCS12_SAFEBAG) *sk);
//  STACK_OF(PKCS12_SAFEBAG) *PKCS12_unpack_p7data(PKCS7 *p7);
//  function PKCS12_pack_p7encdata(TIdC_INT pbe_nid, const PIdAnsiChar pass, TIdC_INT passlen,
//                               Byte *salt, TIdC_INT saltlen, TIdC_INT iter,
//                               STACK_OF(PKCS12_SAFEBAG) *bags): PPKCS7;
//  STACK_OF(PKCS12_SAFEBAG) *PKCS12_unpack_p7encdata(PKCS7 *p7, const PIdAnsiChar *pass,
//                                                    TIdC_INT passlen);

//  TIdC_INT PKCS12_pack_authsafes(PKCS12 *p12, STACK_OF(PKCS7) *safes);
//  STACK_OF(PKCS7) *PKCS12_unpack_authsafes(const PKCS12 *p12);

function  ERR_PKCS12_add_localkeyid(bag: PPKCS12_SAFEBAG; name: PByte; namelen: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_add_localkeyid_procname);
end;


function  ERR_PKCS12_add_friendlyname_asc(bag: PPKCS12_SAFEBAG; const name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_add_friendlyname_asc_procname);
end;


function  ERR_PKCS12_add_friendlyname_utf8(bag: PPKCS12_SAFEBAG; const name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_add_friendlyname_utf8_procname);
end;

 {introduced 1.1.0}
function  ERR_PKCS12_add_CSPName_asc(bag: PPKCS12_SAFEBAG; const name: PIdAnsiChar; namelen: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_add_CSPName_asc_procname);
end;


function  ERR_PKCS12_add_friendlyname_uni(bag: PPKCS12_SAFEBAG; const name: PByte; namelen: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_add_friendlyname_uni_procname);
end;


function  ERR_PKCS8_add_keyusage(p8: PPKCS8_PRIV_KEY_INFO; usage: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS8_add_keyusage_procname);
end;


//  function PKCS12_get_attr_gen(const STACK_OF(X509_ATTRIBUTE) *attrs; TIdC_INT attr_nid): PASN1_TYPE;
function  ERR_PKCS12_get_friendlyname(bag: PPKCS12_SAFEBAG): PIdAnsiChar;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_get_friendlyname_procname);
end;


//  const STACK_OF(X509_ATTRIBUTE) *PKCS12_SAFEBAG_get0_attrs(const PKCS12_SAFEBAG *bag);
function  ERR_PKCS12_pbe_crypt(const algor: PX509_ALGOR; const pass: PIdAnsiChar; passlen: TIdC_INT; const in_: PByte; inlen: TIdC_INT; data: PPByte; datalen: PIdC_INT; en_de: TIdC_INT): PByte; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_pbe_crypt_procname);
end;


function  ERR_PKCS12_item_decrypt_d2i(const algor: PX509_ALGOR; const it: PASN1_ITEM; const pass: PIdAnsiChar; passlen: TIdC_INT; const oct: PASN1_OCTET_STRING; zbuf: TIdC_INT): Pointer;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_item_decrypt_d2i_procname);
end;


function  ERR_PKCS12_item_i2d_encrypt(algor: PX509_ALGOR; const it: PASN1_ITEM; const pass: PIdAnsiChar; passlen: TIdC_INT; obj: Pointer; zbuf: TIdC_INT): PASN1_OCTET_STRING;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_item_i2d_encrypt_procname);
end;


function  ERR_PKCS12_init(mode: TIdC_INT): PPKCS12;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_init_procname);
end;


function  ERR_PKCS12_key_gen_asc(const pass: PIdAnsiChar; passlen: TIdC_INT; salt: PByte; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; out_: PByte; const md_type: PEVP_MD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_key_gen_asc_procname);
end;


function  ERR_PKCS12_key_gen_uni(pass: PByte; passlen: TIdC_INT; salt: PByte; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; out_: PByte; const md_type: PEVP_MD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_key_gen_uni_procname);
end;


function  ERR_PKCS12_key_gen_utf8(const pass: PIdAnsiChar; passlen: TIdC_INT; salt: PByte; saltlen: TIdC_INT; id: TIdC_INT; iter: TIdC_INT; n: TIdC_INT; out_: PByte; const md_type: PEVP_MD): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_key_gen_utf8_procname);
end;

 {introduced 1.1.0}
function  ERR_PKCS12_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PIdAnsiChar; passlen: TIdC_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md_type: PEVP_MD; en_de: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_PBE_keyivgen_procname);
end;


function  ERR_PKCS12_gen_mac(p12: PPKCS12; const pass: PIdAnsiChar; passlen: TIdC_INT; mac: PByte; maclen: PIdC_UINT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_gen_mac_procname);
end;


function  ERR_PKCS12_verify_mac(p12: PPKCS12; const pass: PIdAnsiChar; passlen: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_verify_mac_procname);
end;


function  ERR_PKCS12_set_mac(p12: PPKCS12; const pass: PIdAnsiChar; passlen: TIdC_INT; salt: PByte; saltlen: TIdC_INT; iter: TIdC_INT; const md_type: PEVP_MD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_set_mac_procname);
end;


function  ERR_PKCS12_setup_mac(p12: PPKCS12; iter: TIdC_INT; salt: PByte; saltlen: TIdC_INT; const md_type: PEVP_MD): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_setup_mac_procname);
end;


function  ERR_OPENSSL_asc2uni(const asc: PIdAnsiChar; asclen: TIdC_INT; uni: PPByte; unilen: PIdC_INT): PByte; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_asc2uni_procname);
end;


function  ERR_OPENSSL_uni2asc(const uni: PByte; unilen: TIdC_INT): PIdAnsiChar;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_uni2asc_procname);
end;


function  ERR_OPENSSL_utf82uni(const asc: PIdAnsiChar; asclen: TIdC_INT; uni: PPByte; unilen: PIdC_INT): PByte;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_utf82uni_procname);
end;

 {introduced 1.1.0}
function  ERR_OPENSSL_uni2utf8(const uni: PByte; unilen: TIdC_INT): PIdAnsiChar;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OPENSSL_uni2utf8_procname);
end;

 {introduced 1.1.0}

function  ERR_PKCS12_new: PPKCS12;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_new_procname);
end;


procedure  ERR_PKCS12_free(a: PPKCS12);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_free_procname);
end;


function  ERR_d2i_PKCS12(a: PPPKCS12; const in_: PPByte; len: TIdC_LONG): PPKCS12;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS12_procname);
end;


function  ERR_i2d_PKCS12(a: PPKCS12; out_: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS12_procname);
end;


function  ERR_PKCS12_it: PASN1_ITEM;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_it_procname);
end;



function  ERR_PKCS12_MAC_DATA_new: PPKCS12_MAC_DATA;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_MAC_DATA_new_procname);
end;


procedure  ERR_PKCS12_MAC_DATA_free(a: PPKCS12_MAC_DATA);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_MAC_DATA_free_procname);
end;


function  ERR_d2i_PKCS12_MAC_DATA(a: PPPKCS12_MAC_DATA; const in_: PPByte; len: TIdC_LONG): PPKCS12_MAC_DATA;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS12_MAC_DATA_procname);
end;


function  ERR_i2d_PKCS12_MAC_DATA(a: PPKCS12_MAC_DATA; out_: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS12_MAC_DATA_procname);
end;


function  ERR_PKCS12_MAC_DATA_it: PASN1_ITEM;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_MAC_DATA_it_procname);
end;



function  ERR_PKCS12_SAFEBAG_new: PPKCS12_SAFEBAG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_new_procname);
end;


procedure  ERR_PKCS12_SAFEBAG_free(a: PPKCS12_SAFEBAG);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_free_procname);
end;


function  ERR_d2i_PKCS12_SAFEBAG(a: PPPKCS12_SAFEBAG; const in_: PPByte; len: TIdC_LONG): PPKCS12_SAFEBAG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS12_SAFEBAG_procname);
end;


function  ERR_i2d_PKCS12_SAFEBAG(a: PPKCS12_SAFEBAG; out_: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS12_SAFEBAG_procname);
end;


function  ERR_PKCS12_SAFEBAG_it: PASN1_ITEM;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_SAFEBAG_it_procname);
end;



function  ERR_PKCS12_BAGS_new: PPKCS12_BAGS;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_BAGS_new_procname);
end;


procedure  ERR_PKCS12_BAGS_free(a: PPKCS12_BAGS);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_BAGS_free_procname);
end;


function  ERR_d2i_PKCS12_BAGS(a: PPPKCS12_BAGS; const in_: PPByte; len: TIdC_LONG): PPKCS12_BAGS;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS12_BAGS_procname);
end;


function  ERR_i2d_PKCS12_BAGS(a: PPKCS12_BAGS; out_: PPByte): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS12_BAGS_procname);
end;


function  ERR_PKCS12_BAGS_it: PASN1_ITEM;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_BAGS_it_procname);
end;



procedure  ERR_PKCS12_PBE_add(v: Pointer); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_PBE_add_procname);
end;


function  ERR_PKCS12_parse(p12: PPKCS12; const pass: PIdAnsiChar; var pkey: PEVP_PKEY; var cert: PX509; ca: PPStack_Of_X509): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_parse_procname);
end;


function  ERR_PKCS12_create(const pass: PIdAnsiChar; const name: PIdAnsiChar; pkey: PEVP_PKEY; cert: PX509; ca: PStack_Of_X509; nid_key: TIdC_INT; nid_cert: TIdC_INT; iter: TIdC_INT; mac_iter: TIdC_INT; keytype: TIdC_INT): PPKCS12; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_create_procname);
end;



//  function PKCS12_add_cert(STACK_OF(PKCS12_SAFEBAG) **pbags; X509 *cert): PKCS12_SAFEBAG;
//  PKCS12_SAFEBAG *PKCS12_add_key(STACK_OF(PKCS12_SAFEBAG) **pbags;
//                                 EVP_PKEY *key; TIdC_INT key_usage; iter: TIdC_INT;
//                                 TIdC_INT key_nid; const pass: PIdAnsiChar);
//  TIdC_INT PKCS12_add_safe(STACK_OF(PKCS7) **psafes; STACK_OF(PKCS12_SAFEBAG) *bags;
//                      TIdC_INT safe_nid; iter: TIdC_INT; const pass: PIdAnsiChar);
//  PKCS12 *PKCS12_add_safes(STACK_OF(PKCS7) *safes; TIdC_INT p7_nid);

function  ERR_i2d_PKCS12_bio(bp: PBIO; p12: PPKCS12): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS12_bio_procname);
end;


function  ERR_d2i_PKCS12_bio(bp: PBIO; p12: PPPKCS12): PPKCS12; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS12_bio_procname);
end;


function  ERR_PKCS12_newpass(p12: PPKCS12; const oldpass: PIdAnsiChar; const newpass: PIdAnsiChar): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS12_newpass_procname);
end;

{$I TaurusTLSNoRetValOn.inc}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);

var FuncLoadError: boolean;

begin
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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

 {introduced 1.1.0}
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
  PKCS12_mac_present := nil; {introduced 1.1.0}
  PKCS12_get0_mac := nil; {introduced 1.1.0}
  PKCS12_SAFEBAG_get0_attr := nil; {introduced 1.1.0}
  PKCS12_SAFEBAG_get0_type := nil; {introduced 1.1.0}
  PKCS12_SAFEBAG_get_nid := nil; {introduced 1.1.0}
  PKCS12_SAFEBAG_get_bag_nid := nil; {introduced 1.1.0}
  PKCS12_SAFEBAG_get1_cert := nil; {introduced 1.1.0}
  PKCS12_SAFEBAG_get1_crl := nil; {introduced 1.1.0}
  PKCS12_SAFEBAG_get0_p8inf := nil; {introduced 1.1.0}
  PKCS12_SAFEBAG_get0_pkcs8 := nil; {introduced 1.1.0}
  PKCS12_SAFEBAG_create_cert := nil; {introduced 1.1.0}
  PKCS12_SAFEBAG_create_crl := nil; {introduced 1.1.0}
  PKCS12_SAFEBAG_create0_p8inf := nil; {introduced 1.1.0}
  PKCS12_SAFEBAG_create0_pkcs8 := nil; {introduced 1.1.0}
  PKCS12_SAFEBAG_create_pkcs8_encrypt := nil; {introduced 1.1.0}
  PKCS12_item_pack_safebag := nil;
  PKCS8_decrypt := nil;
  PKCS12_decrypt_skey := nil;
  PKCS8_encrypt := nil;
  PKCS8_set0_pbe := nil; {introduced 1.1.0}
  PKCS12_add_localkeyid := nil;
  PKCS12_add_friendlyname_asc := nil;
  PKCS12_add_friendlyname_utf8 := nil; {introduced 1.1.0}
  PKCS12_add_CSPName_asc := nil;
  PKCS12_add_friendlyname_uni := nil;
  PKCS8_add_keyusage := nil;
  PKCS12_get_friendlyname := nil;
  PKCS12_pbe_crypt := nil;
  PKCS12_item_decrypt_d2i := nil;
  PKCS12_item_i2d_encrypt := nil;
  PKCS12_init := nil;
  PKCS12_key_gen_asc := nil;
  PKCS12_key_gen_uni := nil;
  PKCS12_key_gen_utf8 := nil; {introduced 1.1.0}
  PKCS12_PBE_keyivgen := nil;
  PKCS12_gen_mac := nil;
  PKCS12_verify_mac := nil;
  PKCS12_set_mac := nil;
  PKCS12_setup_mac := nil;
  OPENSSL_asc2uni := nil;
  OPENSSL_uni2asc := nil;
  OPENSSL_utf82uni := nil; {introduced 1.1.0}
  OPENSSL_uni2utf8 := nil; {introduced 1.1.0}
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
  PKCS12_PBE_add := nil;
  PKCS12_parse := nil;
  PKCS12_create := nil;
  i2d_PKCS12_bio := nil;
  d2i_PKCS12_bio := nil;
  PKCS12_newpass := nil;
end;
  {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
