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

unit TaurusTLSHeaders_pem;

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
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // PEM_do_header_callback_cb = function(arg1: PIdAnsiChar; arg2: TIdC_INT; arg3: TIdC_INT; arg4: Pointer): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // PEM_ASN1_read_bio_d2i_cb = function(arg1: PPointer; arg2: PPIdAnsiChar; arg3: TIdC_LONG): Pointer; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // PEM_ASN1_write_bio_i2d_cb = function(arg1: Pointer; arg2: PPIdAnsiChar): TIdC_INT; cdecl;
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // PEM_ASN1_write_bio_ctx_i2d_cb = function(arg1: Pointer; arg2: PPIdAnsiChar; arg3: Pointer): TIdC_INT; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  PEM_BUFSIZE = 1024;
  PEM_STRING_X509_OLD = 'X509 CERTIFICATE';
  PEM_STRING_X509 = 'CERTIFICATE';
  PEM_STRING_X509_TRUSTED = 'TRUSTED CERTIFICATE';
  PEM_STRING_X509_REQ_OLD = 'NEW CERTIFICATE REQUEST';
  PEM_STRING_X509_REQ = 'CERTIFICATE REQUEST';
  PEM_STRING_X509_CRL = 'X509 CRL';
  PEM_STRING_EVP_PKEY = 'ANY PRIVATE KEY';
  PEM_STRING_PUBLIC = 'PUBLIC KEY';
  PEM_STRING_RSA = 'RSA PRIVATE KEY';
  PEM_STRING_RSA_PUBLIC = 'RSA PUBLIC KEY';
  PEM_STRING_DSA = 'DSA PRIVATE KEY';
  PEM_STRING_DSA_PUBLIC = 'DSA PUBLIC KEY';
  PEM_STRING_PKCS7 = 'PKCS7';
  PEM_STRING_PKCS7_SIGNED = 'PKCS #7 SIGNED DATA';
  PEM_STRING_PKCS8 = 'ENCRYPTED PRIVATE KEY';
  PEM_STRING_PKCS8INF = 'PRIVATE KEY';
  PEM_STRING_DHPARAMS = 'DH PARAMETERS';
  PEM_STRING_DHXPARAMS = 'X9.42 DH PARAMETERS';
  PEM_STRING_SSL_SESSION = 'SSL SESSION PARAMETERS';
  PEM_STRING_DSAPARAMS = 'DSA PARAMETERS';
  PEM_STRING_ECDSA_PUBLIC = 'ECDSA PUBLIC KEY';
  PEM_STRING_ECPARAMETERS = 'EC PARAMETERS';
  PEM_STRING_ECPRIVATEKEY = 'EC PRIVATE KEY';
  PEM_STRING_PARAMETERS = 'PARAMETERS';
  PEM_STRING_CMS = 'CMS';
  PEM_STRING_SM2PRIVATEKEY = 'SM2 PRIVATE KEY';
  PEM_STRING_SM2PARAMETERS = 'SM2 PARAMETERS';
  PEM_STRING_ACERT = 'ATTRIBUTE CERTIFICATE';
  PEM_TYPE_ENCRYPTED = 10;
  PEM_TYPE_MIC_ONLY = 20;
  PEM_TYPE_MIC_CLEAR = 30;
  PEM_TYPE_CLEAR = 40;
  PEM_FLAG_SECURE = $1;
  PEM_FLAG_EAY_COMPATIBLE = $2;
  PEM_FLAG_ONLY_B64 = $4;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  PEM_get_EVP_CIPHER_INFO: function(header: PIdAnsiChar; cipher: PEVP_CIPHER_INFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_get_EVP_CIPHER_INFO}

  PEM_do_header: function(cipher: PEVP_CIPHER_INFO; data: PIdAnsiChar; len: PIdC_LONG; callback: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_do_header}

  PEM_read_bio: function(bp: PBIO; name: PPIdAnsiChar; header: PPIdAnsiChar; data: PPIdAnsiChar; len: PIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_read_bio}

  PEM_read_bio_ex: function(bp: PBIO; name: PPIdAnsiChar; header: PPIdAnsiChar; data: PPIdAnsiChar; len: PIdC_LONG; flags: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_read_bio_ex}

  PEM_bytes_read_bio_secmem: function(pdata: PPIdAnsiChar; plen: PIdC_LONG; pnm: PPIdAnsiChar; name: PIdAnsiChar; bp: PBIO; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_bytes_read_bio_secmem}

  PEM_write_bio: function(bp: PBIO; name: PIdAnsiChar; hdr: PIdAnsiChar; data: PIdAnsiChar; len: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_bio}

  PEM_bytes_read_bio: function(pdata: PPIdAnsiChar; plen: PIdC_LONG; pnm: PPIdAnsiChar; name: PIdAnsiChar; bp: PBIO; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_bytes_read_bio}

  PEM_ASN1_read_bio: function(d2i: TPEM_ASN1_read_bio_d2i_cb; name: PIdAnsiChar; bp: PBIO; x: PPointer; cb: TPEM_do_header_callback_cb; u: Pointer): Pointer; cdecl = nil;
  {$EXTERNALSYM PEM_ASN1_read_bio}

  PEM_ASN1_write_bio: function(i2d: TPEM_ASN1_write_bio_i2d_cb; name: PIdAnsiChar; bp: PBIO; x: Pointer; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_ASN1_write_bio}

  PEM_ASN1_write_bio_ctx: function(i2d: TPEM_ASN1_write_bio_ctx_i2d_cb; vctx: Pointer; name: PIdAnsiChar; bp: PBIO; x: Pointer; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_ASN1_write_bio_ctx}

  PEM_X509_INFO_read_bio: function(bp: PBIO; sk: Pstack_st_X509_INFO; cb: TPEM_do_header_callback_cb; u: Pointer): Pstack_st_X509_INFO; cdecl = nil;
  {$EXTERNALSYM PEM_X509_INFO_read_bio}

  PEM_X509_INFO_read_bio_ex: function(bp: PBIO; sk: Pstack_st_X509_INFO; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pstack_st_X509_INFO; cdecl = nil;
  {$EXTERNALSYM PEM_X509_INFO_read_bio_ex}

  PEM_X509_INFO_write_bio: function(bp: PBIO; xi: PX509_INFO; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cd: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_X509_INFO_write_bio}

  PEM_read: function(fp: PFILE; name: PPIdAnsiChar; header: PPIdAnsiChar; data: PPIdAnsiChar; len: PIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_read}

  PEM_write: function(fp: PFILE; name: PIdAnsiChar; hdr: PIdAnsiChar; data: PIdAnsiChar; len: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write}

  PEM_ASN1_read: function(d2i: TPEM_ASN1_read_bio_d2i_cb; name: PIdAnsiChar; fp: PFILE; x: PPointer; cb: TPEM_do_header_callback_cb; u: Pointer): Pointer; cdecl = nil;
  {$EXTERNALSYM PEM_ASN1_read}

  PEM_ASN1_write: function(i2d: TPEM_ASN1_write_bio_i2d_cb; name: PIdAnsiChar; fp: PFILE; x: Pointer; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; callback: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_ASN1_write}

  PEM_X509_INFO_read: function(fp: PFILE; sk: Pstack_st_X509_INFO; cb: TPEM_do_header_callback_cb; u: Pointer): Pstack_st_X509_INFO; cdecl = nil;
  {$EXTERNALSYM PEM_X509_INFO_read}

  PEM_X509_INFO_read_ex: function(fp: PFILE; sk: Pstack_st_X509_INFO; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pstack_st_X509_INFO; cdecl = nil;
  {$EXTERNALSYM PEM_X509_INFO_read_ex}

  PEM_SignInit: function(ctx: PEVP_MD_CTX; _type: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_SignInit}

  PEM_SignUpdate: function(ctx: PEVP_MD_CTX; d: PIdAnsiChar; cnt: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_SignUpdate}

  PEM_SignFinal: function(ctx: PEVP_MD_CTX; sigret: PIdAnsiChar; siglen: PIdC_UINT; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_SignFinal}

  PEM_def_callback: function(buf: PIdAnsiChar; num: TIdC_INT; rwflag: TIdC_INT; userdata: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_def_callback}

  PEM_proc_type: function(buf: PIdAnsiChar; _type: TIdC_INT): void; cdecl = nil;
  {$EXTERNALSYM PEM_proc_type}

  PEM_dek_info: function(buf: PIdAnsiChar; _type: PIdAnsiChar; len: TIdC_INT; str: PIdAnsiChar): void; cdecl = nil;
  {$EXTERNALSYM PEM_dek_info}

  PEM_read_bio_X509: function(_out: PBIO; x: PPX509; cb: TPEM_do_header_callback_cb; u: Pointer): PX509; cdecl = nil;
  {$EXTERNALSYM PEM_read_bio_X509}

  PEM_read_X509: function(_out: PFILE; x: PPX509; cb: TPEM_do_header_callback_cb; u: Pointer): PX509; cdecl = nil;
  {$EXTERNALSYM PEM_read_X509}

  PEM_write_bio_X509: function(_out: PBIO; x: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_bio_X509}

  PEM_write_X509: function(_out: PFILE; x: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_X509}

  PEM_read_bio_X509_AUX: function(_out: PBIO; x: PPX509; cb: TPEM_do_header_callback_cb; u: Pointer): PX509; cdecl = nil;
  {$EXTERNALSYM PEM_read_bio_X509_AUX}

  PEM_read_X509_AUX: function(_out: PFILE; x: PPX509; cb: TPEM_do_header_callback_cb; u: Pointer): PX509; cdecl = nil;
  {$EXTERNALSYM PEM_read_X509_AUX}

  PEM_write_bio_X509_AUX: function(_out: PBIO; x: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_bio_X509_AUX}

  PEM_write_X509_AUX: function(_out: PFILE; x: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_X509_AUX}

  PEM_read_bio_X509_REQ: function(_out: PBIO; x: PPX509_REQ; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_REQ; cdecl = nil;
  {$EXTERNALSYM PEM_read_bio_X509_REQ}

  PEM_read_X509_REQ: function(_out: PFILE; x: PPX509_REQ; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_REQ; cdecl = nil;
  {$EXTERNALSYM PEM_read_X509_REQ}

  PEM_write_bio_X509_REQ: function(_out: PBIO; x: PX509_REQ): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_bio_X509_REQ}

  PEM_write_X509_REQ: function(_out: PFILE; x: PX509_REQ): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_X509_REQ}

  PEM_write_bio_X509_REQ_NEW: function(_out: PBIO; x: PX509_REQ): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_bio_X509_REQ_NEW}

  PEM_write_X509_REQ_NEW: function(_out: PFILE; x: PX509_REQ): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_X509_REQ_NEW}

  PEM_read_bio_X509_CRL: function(_out: PBIO; x: PPX509_CRL; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_CRL; cdecl = nil;
  {$EXTERNALSYM PEM_read_bio_X509_CRL}

  PEM_read_X509_CRL: function(_out: PFILE; x: PPX509_CRL; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_CRL; cdecl = nil;
  {$EXTERNALSYM PEM_read_X509_CRL}

  PEM_write_bio_X509_CRL: function(_out: PBIO; x: PX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_bio_X509_CRL}

  PEM_write_X509_CRL: function(_out: PFILE; x: PX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_X509_CRL}

  PEM_read_bio_X509_PUBKEY: function(_out: PBIO; x: PPX509_PUBKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_PUBKEY; cdecl = nil;
  {$EXTERNALSYM PEM_read_bio_X509_PUBKEY}

  PEM_read_X509_PUBKEY: function(_out: PFILE; x: PPX509_PUBKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_PUBKEY; cdecl = nil;
  {$EXTERNALSYM PEM_read_X509_PUBKEY}

  PEM_write_bio_X509_PUBKEY: function(_out: PBIO; x: PX509_PUBKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_bio_X509_PUBKEY}

  PEM_write_X509_PUBKEY: function(_out: PFILE; x: PX509_PUBKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_X509_PUBKEY}

  PEM_read_bio_PKCS7: function(_out: PBIO; x: PPPKCS7; cb: TPEM_do_header_callback_cb; u: Pointer): PPKCS7; cdecl = nil;
  {$EXTERNALSYM PEM_read_bio_PKCS7}

  PEM_read_PKCS7: function(_out: PFILE; x: PPPKCS7; cb: TPEM_do_header_callback_cb; u: Pointer): PPKCS7; cdecl = nil;
  {$EXTERNALSYM PEM_read_PKCS7}

  PEM_write_bio_PKCS7: function(_out: PBIO; x: PPKCS7): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_bio_PKCS7}

  PEM_write_PKCS7: function(_out: PFILE; x: PPKCS7): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_PKCS7}

  PEM_read_bio_NETSCAPE_CERT_SEQUENCE: function(_out: PBIO; x: PPNETSCAPE_CERT_SEQUENCE; cb: TPEM_do_header_callback_cb; u: Pointer): PNETSCAPE_CERT_SEQUENCE; cdecl = nil;
  {$EXTERNALSYM PEM_read_bio_NETSCAPE_CERT_SEQUENCE}

  PEM_read_NETSCAPE_CERT_SEQUENCE: function(_out: PFILE; x: PPNETSCAPE_CERT_SEQUENCE; cb: TPEM_do_header_callback_cb; u: Pointer): PNETSCAPE_CERT_SEQUENCE; cdecl = nil;
  {$EXTERNALSYM PEM_read_NETSCAPE_CERT_SEQUENCE}

  PEM_write_bio_NETSCAPE_CERT_SEQUENCE: function(_out: PBIO; x: PNETSCAPE_CERT_SEQUENCE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_bio_NETSCAPE_CERT_SEQUENCE}

  PEM_write_NETSCAPE_CERT_SEQUENCE: function(_out: PFILE; x: PNETSCAPE_CERT_SEQUENCE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_NETSCAPE_CERT_SEQUENCE}

  PEM_read_bio_PKCS8: function(_out: PBIO; x: PPX509_SIG; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_SIG; cdecl = nil;
  {$EXTERNALSYM PEM_read_bio_PKCS8}

  PEM_read_PKCS8: function(_out: PFILE; x: PPX509_SIG; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_SIG; cdecl = nil;
  {$EXTERNALSYM PEM_read_PKCS8}

  PEM_write_bio_PKCS8: function(_out: PBIO; x: PX509_SIG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_bio_PKCS8}

  PEM_write_PKCS8: function(_out: PFILE; x: PX509_SIG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_PKCS8}

  PEM_read_bio_PKCS8_PRIV_KEY_INFO: function(_out: PBIO; x: PPPKCS8_PRIV_KEY_INFO; cb: TPEM_do_header_callback_cb; u: Pointer): PPKCS8_PRIV_KEY_INFO; cdecl = nil;
  {$EXTERNALSYM PEM_read_bio_PKCS8_PRIV_KEY_INFO}

  PEM_read_PKCS8_PRIV_KEY_INFO: function(_out: PFILE; x: PPPKCS8_PRIV_KEY_INFO; cb: TPEM_do_header_callback_cb; u: Pointer): PPKCS8_PRIV_KEY_INFO; cdecl = nil;
  {$EXTERNALSYM PEM_read_PKCS8_PRIV_KEY_INFO}

  PEM_write_bio_PKCS8_PRIV_KEY_INFO: function(_out: PBIO; x: PPKCS8_PRIV_KEY_INFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_bio_PKCS8_PRIV_KEY_INFO}

  PEM_write_PKCS8_PRIV_KEY_INFO: function(_out: PFILE; x: PPKCS8_PRIV_KEY_INFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_PKCS8_PRIV_KEY_INFO}

  PEM_read_bio_RSAPrivateKey: function(_out: PBIO; x: PPRSA; cb: TPEM_do_header_callback_cb; u: Pointer): PRSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_read_bio_RSAPrivateKey}

  PEM_read_RSAPrivateKey: function(_out: PFILE; x: PPRSA; cb: TPEM_do_header_callback_cb; u: Pointer): PRSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_read_RSAPrivateKey}

  PEM_write_bio_RSAPrivateKey: function(_out: PBIO; x: PRSA; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_write_bio_RSAPrivateKey}

  PEM_write_RSAPrivateKey: function(_out: PFILE; x: PRSA; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_write_RSAPrivateKey}

  PEM_read_bio_RSAPublicKey: function(_out: PBIO; x: PPRSA; cb: TPEM_do_header_callback_cb; u: Pointer): PRSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_read_bio_RSAPublicKey}

  PEM_read_RSAPublicKey: function(_out: PFILE; x: PPRSA; cb: TPEM_do_header_callback_cb; u: Pointer): PRSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_read_RSAPublicKey}

  PEM_write_bio_RSAPublicKey: function(_out: PBIO; x: PRSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_write_bio_RSAPublicKey}

  PEM_write_RSAPublicKey: function(_out: PFILE; x: PRSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_write_RSAPublicKey}

  PEM_read_bio_RSA_PUBKEY: function(_out: PBIO; x: PPRSA; cb: TPEM_do_header_callback_cb; u: Pointer): PRSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_read_bio_RSA_PUBKEY}

  PEM_read_RSA_PUBKEY: function(_out: PFILE; x: PPRSA; cb: TPEM_do_header_callback_cb; u: Pointer): PRSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_read_RSA_PUBKEY}

  PEM_write_bio_RSA_PUBKEY: function(_out: PBIO; x: PRSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_write_bio_RSA_PUBKEY}

  PEM_write_RSA_PUBKEY: function(_out: PFILE; x: PRSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_write_RSA_PUBKEY}

  PEM_read_bio_DSAPrivateKey: function(_out: PBIO; x: PPDSA; cb: TPEM_do_header_callback_cb; u: Pointer): PDSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_read_bio_DSAPrivateKey}

  PEM_read_DSAPrivateKey: function(_out: PFILE; x: PPDSA; cb: TPEM_do_header_callback_cb; u: Pointer): PDSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_read_DSAPrivateKey}

  PEM_write_bio_DSAPrivateKey: function(_out: PBIO; x: PDSA; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_write_bio_DSAPrivateKey}

  PEM_write_DSAPrivateKey: function(_out: PFILE; x: PDSA; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_write_DSAPrivateKey}

  PEM_read_bio_DSA_PUBKEY: function(_out: PBIO; x: PPDSA; cb: TPEM_do_header_callback_cb; u: Pointer): PDSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_read_bio_DSA_PUBKEY}

  PEM_read_DSA_PUBKEY: function(_out: PFILE; x: PPDSA; cb: TPEM_do_header_callback_cb; u: Pointer): PDSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_read_DSA_PUBKEY}

  PEM_write_bio_DSA_PUBKEY: function(_out: PBIO; x: PDSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_write_bio_DSA_PUBKEY}

  PEM_write_DSA_PUBKEY: function(_out: PFILE; x: PDSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_write_DSA_PUBKEY}

  PEM_read_bio_DSAparams: function(_out: PBIO; x: PPDSA; cb: TPEM_do_header_callback_cb; u: Pointer): PDSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_read_bio_DSAparams}

  PEM_read_DSAparams: function(_out: PFILE; x: PPDSA; cb: TPEM_do_header_callback_cb; u: Pointer): PDSA; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_read_DSAparams}

  PEM_write_bio_DSAparams: function(_out: PBIO; x: PDSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_write_bio_DSAparams}

  PEM_write_DSAparams: function(_out: PFILE; x: PDSA): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_write_DSAparams}

  PEM_read_bio_ECPKParameters: function(_out: PBIO; x: PPEC_GROUP; cb: TPEM_do_header_callback_cb; u: Pointer): PEC_GROUP; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_read_bio_ECPKParameters}

  PEM_read_ECPKParameters: function(_out: PFILE; x: PPEC_GROUP; cb: TPEM_do_header_callback_cb; u: Pointer): PEC_GROUP; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_read_ECPKParameters}

  PEM_write_bio_ECPKParameters: function(_out: PBIO; x: PEC_GROUP): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_write_bio_ECPKParameters}

  PEM_write_ECPKParameters: function(_out: PFILE; x: PEC_GROUP): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_write_ECPKParameters}

  PEM_read_bio_ECPrivateKey: function(_out: PBIO; x: PPEC_KEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEC_KEY; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_read_bio_ECPrivateKey}

  PEM_read_ECPrivateKey: function(_out: PFILE; x: PPEC_KEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEC_KEY; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_read_ECPrivateKey}

  PEM_write_bio_ECPrivateKey: function(_out: PBIO; x: PEC_KEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_write_bio_ECPrivateKey}

  PEM_write_ECPrivateKey: function(_out: PFILE; x: PEC_KEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_write_ECPrivateKey}

  PEM_read_bio_EC_PUBKEY: function(_out: PBIO; x: PPEC_KEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEC_KEY; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_read_bio_EC_PUBKEY}

  PEM_read_EC_PUBKEY: function(_out: PFILE; x: PPEC_KEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEC_KEY; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_read_EC_PUBKEY}

  PEM_write_bio_EC_PUBKEY: function(_out: PBIO; x: PEC_KEY): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_write_bio_EC_PUBKEY}

  PEM_write_EC_PUBKEY: function(_out: PFILE; x: PEC_KEY): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_write_EC_PUBKEY}

  PEM_read_bio_DHparams: function(_out: PBIO; x: PPDH; cb: TPEM_do_header_callback_cb; u: Pointer): PDH; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_read_bio_DHparams}

  PEM_read_DHparams: function(_out: PFILE; x: PPDH; cb: TPEM_do_header_callback_cb; u: Pointer): PDH; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_read_DHparams}

  PEM_write_bio_DHparams: function(_out: PBIO; x: PDH): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_write_bio_DHparams}

  PEM_write_DHparams: function(_out: PFILE; x: PDH): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_write_DHparams}

  PEM_write_bio_DHxparams: function(_out: PBIO; x: PDH): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_write_bio_DHxparams}

  PEM_write_DHxparams: function(_out: PFILE; x: PDH): TIdC_INT; cdecl = nil; // Deprecated in 3_0_0
  {$EXTERNALSYM PEM_write_DHxparams}

  PEM_read_bio_PrivateKey: function(_out: PBIO; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM PEM_read_bio_PrivateKey}

  PEM_read_bio_PrivateKey_ex: function(_out: PBIO; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM PEM_read_bio_PrivateKey_ex}

  PEM_read_PrivateKey: function(_out: PFILE; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM PEM_read_PrivateKey}

  PEM_read_PrivateKey_ex: function(_out: PFILE; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM PEM_read_PrivateKey_ex}

  PEM_write_bio_PrivateKey: function(_out: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_bio_PrivateKey}

  PEM_write_bio_PrivateKey_ex: function(_out: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_bio_PrivateKey_ex}

  PEM_write_PrivateKey: function(_out: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_PrivateKey}

  PEM_write_PrivateKey_ex: function(_out: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_PrivateKey_ex}

  PEM_read_bio_PUBKEY: function(_out: PBIO; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM PEM_read_bio_PUBKEY}

  PEM_read_bio_PUBKEY_ex: function(_out: PBIO; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM PEM_read_bio_PUBKEY_ex}

  PEM_read_PUBKEY: function(_out: PFILE; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM PEM_read_PUBKEY}

  PEM_read_PUBKEY_ex: function(_out: PFILE; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM PEM_read_PUBKEY_ex}

  PEM_write_bio_PUBKEY: function(_out: PBIO; x: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_bio_PUBKEY}

  PEM_write_bio_PUBKEY_ex: function(_out: PBIO; x: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_bio_PUBKEY_ex}

  PEM_write_PUBKEY: function(_out: PFILE; x: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_PUBKEY}

  PEM_write_PUBKEY_ex: function(_out: PFILE; x: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_PUBKEY_ex}

  PEM_write_bio_PrivateKey_traditional: function(bp: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_bio_PrivateKey_traditional}

  PEM_write_bio_PKCS8PrivateKey_nid: function(bp: PBIO; x: PEVP_PKEY; nid: TIdC_INT; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_bio_PKCS8PrivateKey_nid}

  PEM_write_bio_PKCS8PrivateKey: function(arg1: PBIO; arg2: PEVP_PKEY; arg3: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_bio_PKCS8PrivateKey}

  i2d_PKCS8PrivateKey_bio: function(bp: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS8PrivateKey_bio}

  i2d_PKCS8PrivateKey_nid_bio: function(bp: PBIO; x: PEVP_PKEY; nid: TIdC_INT; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS8PrivateKey_nid_bio}

  d2i_PKCS8PrivateKey_bio: function(bp: PBIO; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS8PrivateKey_bio}

  i2d_PKCS8PrivateKey_fp: function(fp: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS8PrivateKey_fp}

  i2d_PKCS8PrivateKey_nid_fp: function(fp: PFILE; x: PEVP_PKEY; nid: TIdC_INT; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS8PrivateKey_nid_fp}

  PEM_write_PKCS8PrivateKey_nid: function(fp: PFILE; x: PEVP_PKEY; nid: TIdC_INT; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_PKCS8PrivateKey_nid}

  d2i_PKCS8PrivateKey_fp: function(fp: PFILE; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS8PrivateKey_fp}

  PEM_write_PKCS8PrivateKey: function(fp: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cd: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_PKCS8PrivateKey}

  PEM_read_bio_Parameters_ex: function(bp: PBIO; x: PPEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM PEM_read_bio_Parameters_ex}

  PEM_read_bio_Parameters: function(bp: PBIO; x: PPEVP_PKEY): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM PEM_read_bio_Parameters}

  PEM_write_bio_Parameters: function(bp: PBIO; x: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_bio_Parameters}

  b2i_PrivateKey: function(_in: PPIdAnsiChar; length: TIdC_LONG): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM b2i_PrivateKey}

  b2i_PublicKey: function(_in: PPIdAnsiChar; length: TIdC_LONG): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM b2i_PublicKey}

  b2i_PrivateKey_bio: function(_in: PBIO): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM b2i_PrivateKey_bio}

  b2i_PublicKey_bio: function(_in: PBIO): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM b2i_PublicKey_bio}

  i2b_PrivateKey_bio: function(_out: PBIO; pk: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2b_PrivateKey_bio}

  i2b_PublicKey_bio: function(_out: PBIO; pk: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2b_PublicKey_bio}

  b2i_PVK_bio: function(_in: PBIO; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM b2i_PVK_bio}

  b2i_PVK_bio_ex: function(_in: PBIO; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl = nil;
  {$EXTERNALSYM b2i_PVK_bio_ex}

  i2b_PVK_bio: function(_out: PBIO; pk: PEVP_PKEY; enclevel: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2b_PVK_bio}

  i2b_PVK_bio_ex: function(_out: PBIO; pk: PEVP_PKEY; enclevel: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2b_PVK_bio_ex}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function PEM_get_EVP_CIPHER_INFO(header: PIdAnsiChar; cipher: PEVP_CIPHER_INFO): TIdC_INT; cdecl;
function PEM_do_header(cipher: PEVP_CIPHER_INFO; data: PIdAnsiChar; len: PIdC_LONG; callback: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl;
function PEM_read_bio(bp: PBIO; name: PPIdAnsiChar; header: PPIdAnsiChar; data: PPIdAnsiChar; len: PIdC_LONG): TIdC_INT; cdecl;
function PEM_read_bio_ex(bp: PBIO; name: PPIdAnsiChar; header: PPIdAnsiChar; data: PPIdAnsiChar; len: PIdC_LONG; flags: TIdC_UINT): TIdC_INT; cdecl;
function PEM_bytes_read_bio_secmem(pdata: PPIdAnsiChar; plen: PIdC_LONG; pnm: PPIdAnsiChar; name: PIdAnsiChar; bp: PBIO; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl;
function PEM_write_bio(bp: PBIO; name: PIdAnsiChar; hdr: PIdAnsiChar; data: PIdAnsiChar; len: TIdC_LONG): TIdC_INT; cdecl;
function PEM_bytes_read_bio(pdata: PPIdAnsiChar; plen: PIdC_LONG; pnm: PPIdAnsiChar; name: PIdAnsiChar; bp: PBIO; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl;
function PEM_ASN1_read_bio(d2i: TPEM_ASN1_read_bio_d2i_cb; name: PIdAnsiChar; bp: PBIO; x: PPointer; cb: TPEM_do_header_callback_cb; u: Pointer): Pointer; cdecl;
function PEM_ASN1_write_bio(i2d: TPEM_ASN1_write_bio_i2d_cb; name: PIdAnsiChar; bp: PBIO; x: Pointer; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl;
function PEM_ASN1_write_bio_ctx(i2d: TPEM_ASN1_write_bio_ctx_i2d_cb; vctx: Pointer; name: PIdAnsiChar; bp: PBIO; x: Pointer; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl;
function PEM_X509_INFO_read_bio(bp: PBIO; sk: Pstack_st_X509_INFO; cb: TPEM_do_header_callback_cb; u: Pointer): Pstack_st_X509_INFO; cdecl;
function PEM_X509_INFO_read_bio_ex(bp: PBIO; sk: Pstack_st_X509_INFO; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pstack_st_X509_INFO; cdecl;
function PEM_X509_INFO_write_bio(bp: PBIO; xi: PX509_INFO; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cd: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl;
function PEM_read(fp: PFILE; name: PPIdAnsiChar; header: PPIdAnsiChar; data: PPIdAnsiChar; len: PIdC_LONG): TIdC_INT; cdecl;
function PEM_write(fp: PFILE; name: PIdAnsiChar; hdr: PIdAnsiChar; data: PIdAnsiChar; len: TIdC_LONG): TIdC_INT; cdecl;
function PEM_ASN1_read(d2i: TPEM_ASN1_read_bio_d2i_cb; name: PIdAnsiChar; fp: PFILE; x: PPointer; cb: TPEM_do_header_callback_cb; u: Pointer): Pointer; cdecl;
function PEM_ASN1_write(i2d: TPEM_ASN1_write_bio_i2d_cb; name: PIdAnsiChar; fp: PFILE; x: Pointer; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; callback: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl;
function PEM_X509_INFO_read(fp: PFILE; sk: Pstack_st_X509_INFO; cb: TPEM_do_header_callback_cb; u: Pointer): Pstack_st_X509_INFO; cdecl;
function PEM_X509_INFO_read_ex(fp: PFILE; sk: Pstack_st_X509_INFO; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pstack_st_X509_INFO; cdecl;
function PEM_SignInit(ctx: PEVP_MD_CTX; _type: PEVP_MD): TIdC_INT; cdecl;
function PEM_SignUpdate(ctx: PEVP_MD_CTX; d: PIdAnsiChar; cnt: TIdC_UINT): TIdC_INT; cdecl;
function PEM_SignFinal(ctx: PEVP_MD_CTX; sigret: PIdAnsiChar; siglen: PIdC_UINT; pkey: PEVP_PKEY): TIdC_INT; cdecl;
function PEM_def_callback(buf: PIdAnsiChar; num: TIdC_INT; rwflag: TIdC_INT; userdata: Pointer): TIdC_INT; cdecl;
function PEM_proc_type(buf: PIdAnsiChar; _type: TIdC_INT): void; cdecl;
function PEM_dek_info(buf: PIdAnsiChar; _type: PIdAnsiChar; len: TIdC_INT; str: PIdAnsiChar): void; cdecl;
function PEM_read_bio_X509(_out: PBIO; x: PPX509; cb: TPEM_do_header_callback_cb; u: Pointer): PX509; cdecl;
function PEM_read_X509(_out: PFILE; x: PPX509; cb: TPEM_do_header_callback_cb; u: Pointer): PX509; cdecl;
function PEM_write_bio_X509(_out: PBIO; x: PX509): TIdC_INT; cdecl;
function PEM_write_X509(_out: PFILE; x: PX509): TIdC_INT; cdecl;
function PEM_read_bio_X509_AUX(_out: PBIO; x: PPX509; cb: TPEM_do_header_callback_cb; u: Pointer): PX509; cdecl;
function PEM_read_X509_AUX(_out: PFILE; x: PPX509; cb: TPEM_do_header_callback_cb; u: Pointer): PX509; cdecl;
function PEM_write_bio_X509_AUX(_out: PBIO; x: PX509): TIdC_INT; cdecl;
function PEM_write_X509_AUX(_out: PFILE; x: PX509): TIdC_INT; cdecl;
function PEM_read_bio_X509_REQ(_out: PBIO; x: PPX509_REQ; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_REQ; cdecl;
function PEM_read_X509_REQ(_out: PFILE; x: PPX509_REQ; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_REQ; cdecl;
function PEM_write_bio_X509_REQ(_out: PBIO; x: PX509_REQ): TIdC_INT; cdecl;
function PEM_write_X509_REQ(_out: PFILE; x: PX509_REQ): TIdC_INT; cdecl;
function PEM_write_bio_X509_REQ_NEW(_out: PBIO; x: PX509_REQ): TIdC_INT; cdecl;
function PEM_write_X509_REQ_NEW(_out: PFILE; x: PX509_REQ): TIdC_INT; cdecl;
function PEM_read_bio_X509_CRL(_out: PBIO; x: PPX509_CRL; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_CRL; cdecl;
function PEM_read_X509_CRL(_out: PFILE; x: PPX509_CRL; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_CRL; cdecl;
function PEM_write_bio_X509_CRL(_out: PBIO; x: PX509_CRL): TIdC_INT; cdecl;
function PEM_write_X509_CRL(_out: PFILE; x: PX509_CRL): TIdC_INT; cdecl;
function PEM_read_bio_X509_PUBKEY(_out: PBIO; x: PPX509_PUBKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_PUBKEY; cdecl;
function PEM_read_X509_PUBKEY(_out: PFILE; x: PPX509_PUBKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_PUBKEY; cdecl;
function PEM_write_bio_X509_PUBKEY(_out: PBIO; x: PX509_PUBKEY): TIdC_INT; cdecl;
function PEM_write_X509_PUBKEY(_out: PFILE; x: PX509_PUBKEY): TIdC_INT; cdecl;
function PEM_read_bio_PKCS7(_out: PBIO; x: PPPKCS7; cb: TPEM_do_header_callback_cb; u: Pointer): PPKCS7; cdecl;
function PEM_read_PKCS7(_out: PFILE; x: PPPKCS7; cb: TPEM_do_header_callback_cb; u: Pointer): PPKCS7; cdecl;
function PEM_write_bio_PKCS7(_out: PBIO; x: PPKCS7): TIdC_INT; cdecl;
function PEM_write_PKCS7(_out: PFILE; x: PPKCS7): TIdC_INT; cdecl;
function PEM_read_bio_NETSCAPE_CERT_SEQUENCE(_out: PBIO; x: PPNETSCAPE_CERT_SEQUENCE; cb: TPEM_do_header_callback_cb; u: Pointer): PNETSCAPE_CERT_SEQUENCE; cdecl;
function PEM_read_NETSCAPE_CERT_SEQUENCE(_out: PFILE; x: PPNETSCAPE_CERT_SEQUENCE; cb: TPEM_do_header_callback_cb; u: Pointer): PNETSCAPE_CERT_SEQUENCE; cdecl;
function PEM_write_bio_NETSCAPE_CERT_SEQUENCE(_out: PBIO; x: PNETSCAPE_CERT_SEQUENCE): TIdC_INT; cdecl;
function PEM_write_NETSCAPE_CERT_SEQUENCE(_out: PFILE; x: PNETSCAPE_CERT_SEQUENCE): TIdC_INT; cdecl;
function PEM_read_bio_PKCS8(_out: PBIO; x: PPX509_SIG; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_SIG; cdecl;
function PEM_read_PKCS8(_out: PFILE; x: PPX509_SIG; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_SIG; cdecl;
function PEM_write_bio_PKCS8(_out: PBIO; x: PX509_SIG): TIdC_INT; cdecl;
function PEM_write_PKCS8(_out: PFILE; x: PX509_SIG): TIdC_INT; cdecl;
function PEM_read_bio_PKCS8_PRIV_KEY_INFO(_out: PBIO; x: PPPKCS8_PRIV_KEY_INFO; cb: TPEM_do_header_callback_cb; u: Pointer): PPKCS8_PRIV_KEY_INFO; cdecl;
function PEM_read_PKCS8_PRIV_KEY_INFO(_out: PFILE; x: PPPKCS8_PRIV_KEY_INFO; cb: TPEM_do_header_callback_cb; u: Pointer): PPKCS8_PRIV_KEY_INFO; cdecl;
function PEM_write_bio_PKCS8_PRIV_KEY_INFO(_out: PBIO; x: PPKCS8_PRIV_KEY_INFO): TIdC_INT; cdecl;
function PEM_write_PKCS8_PRIV_KEY_INFO(_out: PFILE; x: PPKCS8_PRIV_KEY_INFO): TIdC_INT; cdecl;
function PEM_read_bio_RSAPrivateKey(_out: PBIO; x: PPRSA; cb: TPEM_do_header_callback_cb; u: Pointer): PRSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_read_RSAPrivateKey(_out: PFILE; x: PPRSA; cb: TPEM_do_header_callback_cb; u: Pointer): PRSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_write_bio_RSAPrivateKey(_out: PBIO; x: PRSA; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_write_RSAPrivateKey(_out: PFILE; x: PRSA; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_read_bio_RSAPublicKey(_out: PBIO; x: PPRSA; cb: TPEM_do_header_callback_cb; u: Pointer): PRSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_read_RSAPublicKey(_out: PFILE; x: PPRSA; cb: TPEM_do_header_callback_cb; u: Pointer): PRSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_write_bio_RSAPublicKey(_out: PBIO; x: PRSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_write_RSAPublicKey(_out: PFILE; x: PRSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_read_bio_RSA_PUBKEY(_out: PBIO; x: PPRSA; cb: TPEM_do_header_callback_cb; u: Pointer): PRSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_read_RSA_PUBKEY(_out: PFILE; x: PPRSA; cb: TPEM_do_header_callback_cb; u: Pointer): PRSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_write_bio_RSA_PUBKEY(_out: PBIO; x: PRSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_write_RSA_PUBKEY(_out: PFILE; x: PRSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_read_bio_DSAPrivateKey(_out: PBIO; x: PPDSA; cb: TPEM_do_header_callback_cb; u: Pointer): PDSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_read_DSAPrivateKey(_out: PFILE; x: PPDSA; cb: TPEM_do_header_callback_cb; u: Pointer): PDSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_write_bio_DSAPrivateKey(_out: PBIO; x: PDSA; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_write_DSAPrivateKey(_out: PFILE; x: PDSA; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_read_bio_DSA_PUBKEY(_out: PBIO; x: PPDSA; cb: TPEM_do_header_callback_cb; u: Pointer): PDSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_read_DSA_PUBKEY(_out: PFILE; x: PPDSA; cb: TPEM_do_header_callback_cb; u: Pointer): PDSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_write_bio_DSA_PUBKEY(_out: PBIO; x: PDSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_write_DSA_PUBKEY(_out: PFILE; x: PDSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_read_bio_DSAparams(_out: PBIO; x: PPDSA; cb: TPEM_do_header_callback_cb; u: Pointer): PDSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_read_DSAparams(_out: PFILE; x: PPDSA; cb: TPEM_do_header_callback_cb; u: Pointer): PDSA; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_write_bio_DSAparams(_out: PBIO; x: PDSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_write_DSAparams(_out: PFILE; x: PDSA): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_read_bio_ECPKParameters(_out: PBIO; x: PPEC_GROUP; cb: TPEM_do_header_callback_cb; u: Pointer): PEC_GROUP; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_read_ECPKParameters(_out: PFILE; x: PPEC_GROUP; cb: TPEM_do_header_callback_cb; u: Pointer): PEC_GROUP; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_write_bio_ECPKParameters(_out: PBIO; x: PEC_GROUP): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_write_ECPKParameters(_out: PFILE; x: PEC_GROUP): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_read_bio_ECPrivateKey(_out: PBIO; x: PPEC_KEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEC_KEY; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_read_ECPrivateKey(_out: PFILE; x: PPEC_KEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEC_KEY; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_write_bio_ECPrivateKey(_out: PBIO; x: PEC_KEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_write_ECPrivateKey(_out: PFILE; x: PEC_KEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_read_bio_EC_PUBKEY(_out: PBIO; x: PPEC_KEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEC_KEY; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_read_EC_PUBKEY(_out: PFILE; x: PPEC_KEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEC_KEY; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_write_bio_EC_PUBKEY(_out: PBIO; x: PEC_KEY): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_write_EC_PUBKEY(_out: PFILE; x: PEC_KEY): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_read_bio_DHparams(_out: PBIO; x: PPDH; cb: TPEM_do_header_callback_cb; u: Pointer): PDH; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_read_DHparams(_out: PFILE; x: PPDH; cb: TPEM_do_header_callback_cb; u: Pointer): PDH; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_write_bio_DHparams(_out: PBIO; x: PDH): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_write_DHparams(_out: PFILE; x: PDH): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_write_bio_DHxparams(_out: PBIO; x: PDH): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_write_DHxparams(_out: PFILE; x: PDH): TIdC_INT; cdecl; deprecated 'In OpenSSL 3_0_0';
function PEM_read_bio_PrivateKey(_out: PBIO; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl;
function PEM_read_bio_PrivateKey_ex(_out: PBIO; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl;
function PEM_read_PrivateKey(_out: PFILE; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl;
function PEM_read_PrivateKey_ex(_out: PFILE; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl;
function PEM_write_bio_PrivateKey(_out: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl;
function PEM_write_bio_PrivateKey_ex(_out: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function PEM_write_PrivateKey(_out: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl;
function PEM_write_PrivateKey_ex(_out: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function PEM_read_bio_PUBKEY(_out: PBIO; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl;
function PEM_read_bio_PUBKEY_ex(_out: PBIO; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl;
function PEM_read_PUBKEY(_out: PFILE; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl;
function PEM_read_PUBKEY_ex(_out: PFILE; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl;
function PEM_write_bio_PUBKEY(_out: PBIO; x: PEVP_PKEY): TIdC_INT; cdecl;
function PEM_write_bio_PUBKEY_ex(_out: PBIO; x: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function PEM_write_PUBKEY(_out: PFILE; x: PEVP_PKEY): TIdC_INT; cdecl;
function PEM_write_PUBKEY_ex(_out: PFILE; x: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
function PEM_write_bio_PrivateKey_traditional(bp: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl;
function PEM_write_bio_PKCS8PrivateKey_nid(bp: PBIO; x: PEVP_PKEY; nid: TIdC_INT; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl;
function PEM_write_bio_PKCS8PrivateKey(arg1: PBIO; arg2: PEVP_PKEY; arg3: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl;
function i2d_PKCS8PrivateKey_bio(bp: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl;
function i2d_PKCS8PrivateKey_nid_bio(bp: PBIO; x: PEVP_PKEY; nid: TIdC_INT; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl;
function d2i_PKCS8PrivateKey_bio(bp: PBIO; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl;
function i2d_PKCS8PrivateKey_fp(fp: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl;
function i2d_PKCS8PrivateKey_nid_fp(fp: PFILE; x: PEVP_PKEY; nid: TIdC_INT; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl;
function PEM_write_PKCS8PrivateKey_nid(fp: PFILE; x: PEVP_PKEY; nid: TIdC_INT; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl;
function d2i_PKCS8PrivateKey_fp(fp: PFILE; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl;
function PEM_write_PKCS8PrivateKey(fp: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cd: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl;
function PEM_read_bio_Parameters_ex(bp: PBIO; x: PPEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl;
function PEM_read_bio_Parameters(bp: PBIO; x: PPEVP_PKEY): PEVP_PKEY; cdecl;
function PEM_write_bio_Parameters(bp: PBIO; x: PEVP_PKEY): TIdC_INT; cdecl;
function b2i_PrivateKey(_in: PPIdAnsiChar; length: TIdC_LONG): PEVP_PKEY; cdecl;
function b2i_PublicKey(_in: PPIdAnsiChar; length: TIdC_LONG): PEVP_PKEY; cdecl;
function b2i_PrivateKey_bio(_in: PBIO): PEVP_PKEY; cdecl;
function b2i_PublicKey_bio(_in: PBIO): PEVP_PKEY; cdecl;
function i2b_PrivateKey_bio(_out: PBIO; pk: PEVP_PKEY): TIdC_INT; cdecl;
function i2b_PublicKey_bio(_out: PBIO; pk: PEVP_PKEY): TIdC_INT; cdecl;
function b2i_PVK_bio(_in: PBIO; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl;
function b2i_PVK_bio_ex(_in: PBIO; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl;
function i2b_PVK_bio(_out: PBIO; pk: PEVP_PKEY; enclevel: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl;
function i2b_PVK_bio_ex(_out: PBIO; pk: PEVP_PKEY; enclevel: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl;
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

function PEM_get_EVP_CIPHER_INFO(header: PIdAnsiChar; cipher: PEVP_CIPHER_INFO): TIdC_INT; cdecl external CLibCrypto name 'PEM_get_EVP_CIPHER_INFO';
function PEM_do_header(cipher: PEVP_CIPHER_INFO; data: PIdAnsiChar; len: PIdC_LONG; callback: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl external CLibCrypto name 'PEM_do_header';
function PEM_read_bio(bp: PBIO; name: PPIdAnsiChar; header: PPIdAnsiChar; data: PPIdAnsiChar; len: PIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'PEM_read_bio';
function PEM_read_bio_ex(bp: PBIO; name: PPIdAnsiChar; header: PPIdAnsiChar; data: PPIdAnsiChar; len: PIdC_LONG; flags: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'PEM_read_bio_ex';
function PEM_bytes_read_bio_secmem(pdata: PPIdAnsiChar; plen: PIdC_LONG; pnm: PPIdAnsiChar; name: PIdAnsiChar; bp: PBIO; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl external CLibCrypto name 'PEM_bytes_read_bio_secmem';
function PEM_write_bio(bp: PBIO; name: PIdAnsiChar; hdr: PIdAnsiChar; data: PIdAnsiChar; len: TIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio';
function PEM_bytes_read_bio(pdata: PPIdAnsiChar; plen: PIdC_LONG; pnm: PPIdAnsiChar; name: PIdAnsiChar; bp: PBIO; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl external CLibCrypto name 'PEM_bytes_read_bio';
function PEM_ASN1_read_bio(d2i: TPEM_ASN1_read_bio_d2i_cb; name: PIdAnsiChar; bp: PBIO; x: PPointer; cb: TPEM_do_header_callback_cb; u: Pointer): Pointer; cdecl external CLibCrypto name 'PEM_ASN1_read_bio';
function PEM_ASN1_write_bio(i2d: TPEM_ASN1_write_bio_i2d_cb; name: PIdAnsiChar; bp: PBIO; x: Pointer; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl external CLibCrypto name 'PEM_ASN1_write_bio';
function PEM_ASN1_write_bio_ctx(i2d: TPEM_ASN1_write_bio_ctx_i2d_cb; vctx: Pointer; name: PIdAnsiChar; bp: PBIO; x: Pointer; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl external CLibCrypto name 'PEM_ASN1_write_bio_ctx';
function PEM_X509_INFO_read_bio(bp: PBIO; sk: Pstack_st_X509_INFO; cb: TPEM_do_header_callback_cb; u: Pointer): Pstack_st_X509_INFO; cdecl external CLibCrypto name 'PEM_X509_INFO_read_bio';
function PEM_X509_INFO_read_bio_ex(bp: PBIO; sk: Pstack_st_X509_INFO; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pstack_st_X509_INFO; cdecl external CLibCrypto name 'PEM_X509_INFO_read_bio_ex';
function PEM_X509_INFO_write_bio(bp: PBIO; xi: PX509_INFO; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cd: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl external CLibCrypto name 'PEM_X509_INFO_write_bio';
function PEM_read(fp: PFILE; name: PPIdAnsiChar; header: PPIdAnsiChar; data: PPIdAnsiChar; len: PIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'PEM_read';
function PEM_write(fp: PFILE; name: PIdAnsiChar; hdr: PIdAnsiChar; data: PIdAnsiChar; len: TIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'PEM_write';
function PEM_ASN1_read(d2i: TPEM_ASN1_read_bio_d2i_cb; name: PIdAnsiChar; fp: PFILE; x: PPointer; cb: TPEM_do_header_callback_cb; u: Pointer): Pointer; cdecl external CLibCrypto name 'PEM_ASN1_read';
function PEM_ASN1_write(i2d: TPEM_ASN1_write_bio_i2d_cb; name: PIdAnsiChar; fp: PFILE; x: Pointer; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; callback: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl external CLibCrypto name 'PEM_ASN1_write';
function PEM_X509_INFO_read(fp: PFILE; sk: Pstack_st_X509_INFO; cb: TPEM_do_header_callback_cb; u: Pointer): Pstack_st_X509_INFO; cdecl external CLibCrypto name 'PEM_X509_INFO_read';
function PEM_X509_INFO_read_ex(fp: PFILE; sk: Pstack_st_X509_INFO; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pstack_st_X509_INFO; cdecl external CLibCrypto name 'PEM_X509_INFO_read_ex';
function PEM_SignInit(ctx: PEVP_MD_CTX; _type: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'PEM_SignInit';
function PEM_SignUpdate(ctx: PEVP_MD_CTX; d: PIdAnsiChar; cnt: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'PEM_SignUpdate';
function PEM_SignFinal(ctx: PEVP_MD_CTX; sigret: PIdAnsiChar; siglen: PIdC_UINT; pkey: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'PEM_SignFinal';
function PEM_def_callback(buf: PIdAnsiChar; num: TIdC_INT; rwflag: TIdC_INT; userdata: Pointer): TIdC_INT; cdecl external CLibCrypto name 'PEM_def_callback';
function PEM_proc_type(buf: PIdAnsiChar; _type: TIdC_INT): void; cdecl external CLibCrypto name 'PEM_proc_type';
function PEM_dek_info(buf: PIdAnsiChar; _type: PIdAnsiChar; len: TIdC_INT; str: PIdAnsiChar): void; cdecl external CLibCrypto name 'PEM_dek_info';
function PEM_read_bio_X509(_out: PBIO; x: PPX509; cb: TPEM_do_header_callback_cb; u: Pointer): PX509; cdecl external CLibCrypto name 'PEM_read_bio_X509';
function PEM_read_X509(_out: PFILE; x: PPX509; cb: TPEM_do_header_callback_cb; u: Pointer): PX509; cdecl external CLibCrypto name 'PEM_read_X509';
function PEM_write_bio_X509(_out: PBIO; x: PX509): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_X509';
function PEM_write_X509(_out: PFILE; x: PX509): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_X509';
function PEM_read_bio_X509_AUX(_out: PBIO; x: PPX509; cb: TPEM_do_header_callback_cb; u: Pointer): PX509; cdecl external CLibCrypto name 'PEM_read_bio_X509_AUX';
function PEM_read_X509_AUX(_out: PFILE; x: PPX509; cb: TPEM_do_header_callback_cb; u: Pointer): PX509; cdecl external CLibCrypto name 'PEM_read_X509_AUX';
function PEM_write_bio_X509_AUX(_out: PBIO; x: PX509): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_X509_AUX';
function PEM_write_X509_AUX(_out: PFILE; x: PX509): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_X509_AUX';
function PEM_read_bio_X509_REQ(_out: PBIO; x: PPX509_REQ; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_REQ; cdecl external CLibCrypto name 'PEM_read_bio_X509_REQ';
function PEM_read_X509_REQ(_out: PFILE; x: PPX509_REQ; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_REQ; cdecl external CLibCrypto name 'PEM_read_X509_REQ';
function PEM_write_bio_X509_REQ(_out: PBIO; x: PX509_REQ): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_X509_REQ';
function PEM_write_X509_REQ(_out: PFILE; x: PX509_REQ): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_X509_REQ';
function PEM_write_bio_X509_REQ_NEW(_out: PBIO; x: PX509_REQ): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_X509_REQ_NEW';
function PEM_write_X509_REQ_NEW(_out: PFILE; x: PX509_REQ): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_X509_REQ_NEW';
function PEM_read_bio_X509_CRL(_out: PBIO; x: PPX509_CRL; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_CRL; cdecl external CLibCrypto name 'PEM_read_bio_X509_CRL';
function PEM_read_X509_CRL(_out: PFILE; x: PPX509_CRL; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_CRL; cdecl external CLibCrypto name 'PEM_read_X509_CRL';
function PEM_write_bio_X509_CRL(_out: PBIO; x: PX509_CRL): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_X509_CRL';
function PEM_write_X509_CRL(_out: PFILE; x: PX509_CRL): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_X509_CRL';
function PEM_read_bio_X509_PUBKEY(_out: PBIO; x: PPX509_PUBKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_PUBKEY; cdecl external CLibCrypto name 'PEM_read_bio_X509_PUBKEY';
function PEM_read_X509_PUBKEY(_out: PFILE; x: PPX509_PUBKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_PUBKEY; cdecl external CLibCrypto name 'PEM_read_X509_PUBKEY';
function PEM_write_bio_X509_PUBKEY(_out: PBIO; x: PX509_PUBKEY): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_X509_PUBKEY';
function PEM_write_X509_PUBKEY(_out: PFILE; x: PX509_PUBKEY): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_X509_PUBKEY';
function PEM_read_bio_PKCS7(_out: PBIO; x: PPPKCS7; cb: TPEM_do_header_callback_cb; u: Pointer): PPKCS7; cdecl external CLibCrypto name 'PEM_read_bio_PKCS7';
function PEM_read_PKCS7(_out: PFILE; x: PPPKCS7; cb: TPEM_do_header_callback_cb; u: Pointer): PPKCS7; cdecl external CLibCrypto name 'PEM_read_PKCS7';
function PEM_write_bio_PKCS7(_out: PBIO; x: PPKCS7): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_PKCS7';
function PEM_write_PKCS7(_out: PFILE; x: PPKCS7): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_PKCS7';
function PEM_read_bio_NETSCAPE_CERT_SEQUENCE(_out: PBIO; x: PPNETSCAPE_CERT_SEQUENCE; cb: TPEM_do_header_callback_cb; u: Pointer): PNETSCAPE_CERT_SEQUENCE; cdecl external CLibCrypto name 'PEM_read_bio_NETSCAPE_CERT_SEQUENCE';
function PEM_read_NETSCAPE_CERT_SEQUENCE(_out: PFILE; x: PPNETSCAPE_CERT_SEQUENCE; cb: TPEM_do_header_callback_cb; u: Pointer): PNETSCAPE_CERT_SEQUENCE; cdecl external CLibCrypto name 'PEM_read_NETSCAPE_CERT_SEQUENCE';
function PEM_write_bio_NETSCAPE_CERT_SEQUENCE(_out: PBIO; x: PNETSCAPE_CERT_SEQUENCE): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_NETSCAPE_CERT_SEQUENCE';
function PEM_write_NETSCAPE_CERT_SEQUENCE(_out: PFILE; x: PNETSCAPE_CERT_SEQUENCE): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_NETSCAPE_CERT_SEQUENCE';
function PEM_read_bio_PKCS8(_out: PBIO; x: PPX509_SIG; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_SIG; cdecl external CLibCrypto name 'PEM_read_bio_PKCS8';
function PEM_read_PKCS8(_out: PFILE; x: PPX509_SIG; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_SIG; cdecl external CLibCrypto name 'PEM_read_PKCS8';
function PEM_write_bio_PKCS8(_out: PBIO; x: PX509_SIG): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_PKCS8';
function PEM_write_PKCS8(_out: PFILE; x: PX509_SIG): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_PKCS8';
function PEM_read_bio_PKCS8_PRIV_KEY_INFO(_out: PBIO; x: PPPKCS8_PRIV_KEY_INFO; cb: TPEM_do_header_callback_cb; u: Pointer): PPKCS8_PRIV_KEY_INFO; cdecl external CLibCrypto name 'PEM_read_bio_PKCS8_PRIV_KEY_INFO';
function PEM_read_PKCS8_PRIV_KEY_INFO(_out: PFILE; x: PPPKCS8_PRIV_KEY_INFO; cb: TPEM_do_header_callback_cb; u: Pointer): PPKCS8_PRIV_KEY_INFO; cdecl external CLibCrypto name 'PEM_read_PKCS8_PRIV_KEY_INFO';
function PEM_write_bio_PKCS8_PRIV_KEY_INFO(_out: PBIO; x: PPKCS8_PRIV_KEY_INFO): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_PKCS8_PRIV_KEY_INFO';
function PEM_write_PKCS8_PRIV_KEY_INFO(_out: PFILE; x: PPKCS8_PRIV_KEY_INFO): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_PKCS8_PRIV_KEY_INFO';
function PEM_read_bio_RSAPrivateKey(_out: PBIO; x: PPRSA; cb: TPEM_do_header_callback_cb; u: Pointer): PRSA; cdecl external CLibCrypto name 'PEM_read_bio_RSAPrivateKey';
function PEM_read_RSAPrivateKey(_out: PFILE; x: PPRSA; cb: TPEM_do_header_callback_cb; u: Pointer): PRSA; cdecl external CLibCrypto name 'PEM_read_RSAPrivateKey';
function PEM_write_bio_RSAPrivateKey(_out: PBIO; x: PRSA; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_RSAPrivateKey';
function PEM_write_RSAPrivateKey(_out: PFILE; x: PRSA; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_RSAPrivateKey';
function PEM_read_bio_RSAPublicKey(_out: PBIO; x: PPRSA; cb: TPEM_do_header_callback_cb; u: Pointer): PRSA; cdecl external CLibCrypto name 'PEM_read_bio_RSAPublicKey';
function PEM_read_RSAPublicKey(_out: PFILE; x: PPRSA; cb: TPEM_do_header_callback_cb; u: Pointer): PRSA; cdecl external CLibCrypto name 'PEM_read_RSAPublicKey';
function PEM_write_bio_RSAPublicKey(_out: PBIO; x: PRSA): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_RSAPublicKey';
function PEM_write_RSAPublicKey(_out: PFILE; x: PRSA): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_RSAPublicKey';
function PEM_read_bio_RSA_PUBKEY(_out: PBIO; x: PPRSA; cb: TPEM_do_header_callback_cb; u: Pointer): PRSA; cdecl external CLibCrypto name 'PEM_read_bio_RSA_PUBKEY';
function PEM_read_RSA_PUBKEY(_out: PFILE; x: PPRSA; cb: TPEM_do_header_callback_cb; u: Pointer): PRSA; cdecl external CLibCrypto name 'PEM_read_RSA_PUBKEY';
function PEM_write_bio_RSA_PUBKEY(_out: PBIO; x: PRSA): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_RSA_PUBKEY';
function PEM_write_RSA_PUBKEY(_out: PFILE; x: PRSA): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_RSA_PUBKEY';
function PEM_read_bio_DSAPrivateKey(_out: PBIO; x: PPDSA; cb: TPEM_do_header_callback_cb; u: Pointer): PDSA; cdecl external CLibCrypto name 'PEM_read_bio_DSAPrivateKey';
function PEM_read_DSAPrivateKey(_out: PFILE; x: PPDSA; cb: TPEM_do_header_callback_cb; u: Pointer): PDSA; cdecl external CLibCrypto name 'PEM_read_DSAPrivateKey';
function PEM_write_bio_DSAPrivateKey(_out: PBIO; x: PDSA; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_DSAPrivateKey';
function PEM_write_DSAPrivateKey(_out: PFILE; x: PDSA; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_DSAPrivateKey';
function PEM_read_bio_DSA_PUBKEY(_out: PBIO; x: PPDSA; cb: TPEM_do_header_callback_cb; u: Pointer): PDSA; cdecl external CLibCrypto name 'PEM_read_bio_DSA_PUBKEY';
function PEM_read_DSA_PUBKEY(_out: PFILE; x: PPDSA; cb: TPEM_do_header_callback_cb; u: Pointer): PDSA; cdecl external CLibCrypto name 'PEM_read_DSA_PUBKEY';
function PEM_write_bio_DSA_PUBKEY(_out: PBIO; x: PDSA): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_DSA_PUBKEY';
function PEM_write_DSA_PUBKEY(_out: PFILE; x: PDSA): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_DSA_PUBKEY';
function PEM_read_bio_DSAparams(_out: PBIO; x: PPDSA; cb: TPEM_do_header_callback_cb; u: Pointer): PDSA; cdecl external CLibCrypto name 'PEM_read_bio_DSAparams';
function PEM_read_DSAparams(_out: PFILE; x: PPDSA; cb: TPEM_do_header_callback_cb; u: Pointer): PDSA; cdecl external CLibCrypto name 'PEM_read_DSAparams';
function PEM_write_bio_DSAparams(_out: PBIO; x: PDSA): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_DSAparams';
function PEM_write_DSAparams(_out: PFILE; x: PDSA): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_DSAparams';
function PEM_read_bio_ECPKParameters(_out: PBIO; x: PPEC_GROUP; cb: TPEM_do_header_callback_cb; u: Pointer): PEC_GROUP; cdecl external CLibCrypto name 'PEM_read_bio_ECPKParameters';
function PEM_read_ECPKParameters(_out: PFILE; x: PPEC_GROUP; cb: TPEM_do_header_callback_cb; u: Pointer): PEC_GROUP; cdecl external CLibCrypto name 'PEM_read_ECPKParameters';
function PEM_write_bio_ECPKParameters(_out: PBIO; x: PEC_GROUP): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_ECPKParameters';
function PEM_write_ECPKParameters(_out: PFILE; x: PEC_GROUP): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_ECPKParameters';
function PEM_read_bio_ECPrivateKey(_out: PBIO; x: PPEC_KEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEC_KEY; cdecl external CLibCrypto name 'PEM_read_bio_ECPrivateKey';
function PEM_read_ECPrivateKey(_out: PFILE; x: PPEC_KEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEC_KEY; cdecl external CLibCrypto name 'PEM_read_ECPrivateKey';
function PEM_write_bio_ECPrivateKey(_out: PBIO; x: PEC_KEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_ECPrivateKey';
function PEM_write_ECPrivateKey(_out: PFILE; x: PEC_KEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_ECPrivateKey';
function PEM_read_bio_EC_PUBKEY(_out: PBIO; x: PPEC_KEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEC_KEY; cdecl external CLibCrypto name 'PEM_read_bio_EC_PUBKEY';
function PEM_read_EC_PUBKEY(_out: PFILE; x: PPEC_KEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEC_KEY; cdecl external CLibCrypto name 'PEM_read_EC_PUBKEY';
function PEM_write_bio_EC_PUBKEY(_out: PBIO; x: PEC_KEY): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_EC_PUBKEY';
function PEM_write_EC_PUBKEY(_out: PFILE; x: PEC_KEY): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_EC_PUBKEY';
function PEM_read_bio_DHparams(_out: PBIO; x: PPDH; cb: TPEM_do_header_callback_cb; u: Pointer): PDH; cdecl external CLibCrypto name 'PEM_read_bio_DHparams';
function PEM_read_DHparams(_out: PFILE; x: PPDH; cb: TPEM_do_header_callback_cb; u: Pointer): PDH; cdecl external CLibCrypto name 'PEM_read_DHparams';
function PEM_write_bio_DHparams(_out: PBIO; x: PDH): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_DHparams';
function PEM_write_DHparams(_out: PFILE; x: PDH): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_DHparams';
function PEM_write_bio_DHxparams(_out: PBIO; x: PDH): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_DHxparams';
function PEM_write_DHxparams(_out: PFILE; x: PDH): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_DHxparams';
function PEM_read_bio_PrivateKey(_out: PBIO; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl external CLibCrypto name 'PEM_read_bio_PrivateKey';
function PEM_read_bio_PrivateKey_ex(_out: PBIO; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl external CLibCrypto name 'PEM_read_bio_PrivateKey_ex';
function PEM_read_PrivateKey(_out: PFILE; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl external CLibCrypto name 'PEM_read_PrivateKey';
function PEM_read_PrivateKey_ex(_out: PFILE; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl external CLibCrypto name 'PEM_read_PrivateKey_ex';
function PEM_write_bio_PrivateKey(_out: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_PrivateKey';
function PEM_write_bio_PrivateKey_ex(_out: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_PrivateKey_ex';
function PEM_write_PrivateKey(_out: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_PrivateKey';
function PEM_write_PrivateKey_ex(_out: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_PrivateKey_ex';
function PEM_read_bio_PUBKEY(_out: PBIO; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl external CLibCrypto name 'PEM_read_bio_PUBKEY';
function PEM_read_bio_PUBKEY_ex(_out: PBIO; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl external CLibCrypto name 'PEM_read_bio_PUBKEY_ex';
function PEM_read_PUBKEY(_out: PFILE; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl external CLibCrypto name 'PEM_read_PUBKEY';
function PEM_read_PUBKEY_ex(_out: PFILE; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl external CLibCrypto name 'PEM_read_PUBKEY_ex';
function PEM_write_bio_PUBKEY(_out: PBIO; x: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_PUBKEY';
function PEM_write_bio_PUBKEY_ex(_out: PBIO; x: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_PUBKEY_ex';
function PEM_write_PUBKEY(_out: PFILE; x: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_PUBKEY';
function PEM_write_PUBKEY_ex(_out: PFILE; x: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_PUBKEY_ex';
function PEM_write_bio_PrivateKey_traditional(bp: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_PrivateKey_traditional';
function PEM_write_bio_PKCS8PrivateKey_nid(bp: PBIO; x: PEVP_PKEY; nid: TIdC_INT; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_PKCS8PrivateKey_nid';
function PEM_write_bio_PKCS8PrivateKey(arg1: PBIO; arg2: PEVP_PKEY; arg3: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_PKCS8PrivateKey';
function i2d_PKCS8PrivateKey_bio(bp: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS8PrivateKey_bio';
function i2d_PKCS8PrivateKey_nid_bio(bp: PBIO; x: PEVP_PKEY; nid: TIdC_INT; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS8PrivateKey_nid_bio';
function d2i_PKCS8PrivateKey_bio(bp: PBIO; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl external CLibCrypto name 'd2i_PKCS8PrivateKey_bio';
function i2d_PKCS8PrivateKey_fp(fp: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS8PrivateKey_fp';
function i2d_PKCS8PrivateKey_nid_fp(fp: PFILE; x: PEVP_PKEY; nid: TIdC_INT; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS8PrivateKey_nid_fp';
function PEM_write_PKCS8PrivateKey_nid(fp: PFILE; x: PEVP_PKEY; nid: TIdC_INT; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_PKCS8PrivateKey_nid';
function d2i_PKCS8PrivateKey_fp(fp: PFILE; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl external CLibCrypto name 'd2i_PKCS8PrivateKey_fp';
function PEM_write_PKCS8PrivateKey(fp: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cd: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_PKCS8PrivateKey';
function PEM_read_bio_Parameters_ex(bp: PBIO; x: PPEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl external CLibCrypto name 'PEM_read_bio_Parameters_ex';
function PEM_read_bio_Parameters(bp: PBIO; x: PPEVP_PKEY): PEVP_PKEY; cdecl external CLibCrypto name 'PEM_read_bio_Parameters';
function PEM_write_bio_Parameters(bp: PBIO; x: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_Parameters';
function b2i_PrivateKey(_in: PPIdAnsiChar; length: TIdC_LONG): PEVP_PKEY; cdecl external CLibCrypto name 'b2i_PrivateKey';
function b2i_PublicKey(_in: PPIdAnsiChar; length: TIdC_LONG): PEVP_PKEY; cdecl external CLibCrypto name 'b2i_PublicKey';
function b2i_PrivateKey_bio(_in: PBIO): PEVP_PKEY; cdecl external CLibCrypto name 'b2i_PrivateKey_bio';
function b2i_PublicKey_bio(_in: PBIO): PEVP_PKEY; cdecl external CLibCrypto name 'b2i_PublicKey_bio';
function i2b_PrivateKey_bio(_out: PBIO; pk: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'i2b_PrivateKey_bio';
function i2b_PublicKey_bio(_out: PBIO; pk: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'i2b_PublicKey_bio';
function b2i_PVK_bio(_in: PBIO; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl external CLibCrypto name 'b2i_PVK_bio';
function b2i_PVK_bio_ex(_in: PBIO; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl external CLibCrypto name 'b2i_PVK_bio_ex';
function i2b_PVK_bio(_out: PBIO; pk: PEVP_PKEY; enclevel: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl external CLibCrypto name 'i2b_PVK_bio';
function i2b_PVK_bio_ex(_out: PBIO; pk: PEVP_PKEY; enclevel: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2b_PVK_bio_ex';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  PEM_get_EVP_CIPHER_INFO_procname = 'PEM_get_EVP_CIPHER_INFO';
  PEM_get_EVP_CIPHER_INFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_do_header_procname = 'PEM_do_header';
  PEM_do_header_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_read_bio_procname = 'PEM_read_bio';
  PEM_read_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_read_bio_ex_procname = 'PEM_read_bio_ex';
  PEM_read_bio_ex_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  PEM_bytes_read_bio_secmem_procname = 'PEM_bytes_read_bio_secmem';
  PEM_bytes_read_bio_secmem_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(1);

  PEM_write_bio_procname = 'PEM_write_bio';
  PEM_write_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_bytes_read_bio_procname = 'PEM_bytes_read_bio';
  PEM_bytes_read_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_ASN1_read_bio_procname = 'PEM_ASN1_read_bio';
  PEM_ASN1_read_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_ASN1_write_bio_procname = 'PEM_ASN1_write_bio';
  PEM_ASN1_write_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_ASN1_write_bio_ctx_procname = 'PEM_ASN1_write_bio_ctx';
  PEM_ASN1_write_bio_ctx_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  PEM_X509_INFO_read_bio_procname = 'PEM_X509_INFO_read_bio';
  PEM_X509_INFO_read_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_X509_INFO_read_bio_ex_procname = 'PEM_X509_INFO_read_bio_ex';
  PEM_X509_INFO_read_bio_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_X509_INFO_write_bio_procname = 'PEM_X509_INFO_write_bio';
  PEM_X509_INFO_write_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_read_procname = 'PEM_read';
  PEM_read_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_procname = 'PEM_write';
  PEM_write_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_ASN1_read_procname = 'PEM_ASN1_read';
  PEM_ASN1_read_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_ASN1_write_procname = 'PEM_ASN1_write';
  PEM_ASN1_write_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_X509_INFO_read_procname = 'PEM_X509_INFO_read';
  PEM_X509_INFO_read_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_X509_INFO_read_ex_procname = 'PEM_X509_INFO_read_ex';
  PEM_X509_INFO_read_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_SignInit_procname = 'PEM_SignInit';
  PEM_SignInit_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_SignUpdate_procname = 'PEM_SignUpdate';
  PEM_SignUpdate_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_SignFinal_procname = 'PEM_SignFinal';
  PEM_SignFinal_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_def_callback_procname = 'PEM_def_callback';
  PEM_def_callback_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_proc_type_procname = 'PEM_proc_type';
  PEM_proc_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_dek_info_procname = 'PEM_dek_info';
  PEM_dek_info_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_read_bio_X509_procname = 'PEM_read_bio_X509';
  PEM_read_bio_X509_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_read_X509_procname = 'PEM_read_X509';
  PEM_read_X509_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_bio_X509_procname = 'PEM_write_bio_X509';
  PEM_write_bio_X509_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_X509_procname = 'PEM_write_X509';
  PEM_write_X509_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_read_bio_X509_AUX_procname = 'PEM_read_bio_X509_AUX';
  PEM_read_bio_X509_AUX_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_read_X509_AUX_procname = 'PEM_read_X509_AUX';
  PEM_read_X509_AUX_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_bio_X509_AUX_procname = 'PEM_write_bio_X509_AUX';
  PEM_write_bio_X509_AUX_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_X509_AUX_procname = 'PEM_write_X509_AUX';
  PEM_write_X509_AUX_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_read_bio_X509_REQ_procname = 'PEM_read_bio_X509_REQ';
  PEM_read_bio_X509_REQ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_read_X509_REQ_procname = 'PEM_read_X509_REQ';
  PEM_read_X509_REQ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_bio_X509_REQ_procname = 'PEM_write_bio_X509_REQ';
  PEM_write_bio_X509_REQ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_X509_REQ_procname = 'PEM_write_X509_REQ';
  PEM_write_X509_REQ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_bio_X509_REQ_NEW_procname = 'PEM_write_bio_X509_REQ_NEW';
  PEM_write_bio_X509_REQ_NEW_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_X509_REQ_NEW_procname = 'PEM_write_X509_REQ_NEW';
  PEM_write_X509_REQ_NEW_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_read_bio_X509_CRL_procname = 'PEM_read_bio_X509_CRL';
  PEM_read_bio_X509_CRL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_read_X509_CRL_procname = 'PEM_read_X509_CRL';
  PEM_read_X509_CRL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_bio_X509_CRL_procname = 'PEM_write_bio_X509_CRL';
  PEM_write_bio_X509_CRL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_X509_CRL_procname = 'PEM_write_X509_CRL';
  PEM_write_X509_CRL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_read_bio_X509_PUBKEY_procname = 'PEM_read_bio_X509_PUBKEY';
  PEM_read_bio_X509_PUBKEY_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_X509_PUBKEY_procname = 'PEM_read_X509_PUBKEY';
  PEM_read_X509_PUBKEY_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_bio_X509_PUBKEY_procname = 'PEM_write_bio_X509_PUBKEY';
  PEM_write_bio_X509_PUBKEY_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_X509_PUBKEY_procname = 'PEM_write_X509_PUBKEY';
  PEM_write_X509_PUBKEY_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_bio_PKCS7_procname = 'PEM_read_bio_PKCS7';
  PEM_read_bio_PKCS7_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_read_PKCS7_procname = 'PEM_read_PKCS7';
  PEM_read_PKCS7_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_bio_PKCS7_procname = 'PEM_write_bio_PKCS7';
  PEM_write_bio_PKCS7_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_PKCS7_procname = 'PEM_write_PKCS7';
  PEM_write_PKCS7_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_read_bio_NETSCAPE_CERT_SEQUENCE_procname = 'PEM_read_bio_NETSCAPE_CERT_SEQUENCE';
  PEM_read_bio_NETSCAPE_CERT_SEQUENCE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_read_NETSCAPE_CERT_SEQUENCE_procname = 'PEM_read_NETSCAPE_CERT_SEQUENCE';
  PEM_read_NETSCAPE_CERT_SEQUENCE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_bio_NETSCAPE_CERT_SEQUENCE_procname = 'PEM_write_bio_NETSCAPE_CERT_SEQUENCE';
  PEM_write_bio_NETSCAPE_CERT_SEQUENCE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_NETSCAPE_CERT_SEQUENCE_procname = 'PEM_write_NETSCAPE_CERT_SEQUENCE';
  PEM_write_NETSCAPE_CERT_SEQUENCE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_read_bio_PKCS8_procname = 'PEM_read_bio_PKCS8';
  PEM_read_bio_PKCS8_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_read_PKCS8_procname = 'PEM_read_PKCS8';
  PEM_read_PKCS8_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_bio_PKCS8_procname = 'PEM_write_bio_PKCS8';
  PEM_write_bio_PKCS8_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_PKCS8_procname = 'PEM_write_PKCS8';
  PEM_write_PKCS8_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_read_bio_PKCS8_PRIV_KEY_INFO_procname = 'PEM_read_bio_PKCS8_PRIV_KEY_INFO';
  PEM_read_bio_PKCS8_PRIV_KEY_INFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_read_PKCS8_PRIV_KEY_INFO_procname = 'PEM_read_PKCS8_PRIV_KEY_INFO';
  PEM_read_PKCS8_PRIV_KEY_INFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_bio_PKCS8_PRIV_KEY_INFO_procname = 'PEM_write_bio_PKCS8_PRIV_KEY_INFO';
  PEM_write_bio_PKCS8_PRIV_KEY_INFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_PKCS8_PRIV_KEY_INFO_procname = 'PEM_write_PKCS8_PRIV_KEY_INFO';
  PEM_write_PKCS8_PRIV_KEY_INFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_read_bio_RSAPrivateKey_procname = 'PEM_read_bio_RSAPrivateKey';
  PEM_read_bio_RSAPrivateKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_read_bio_RSAPrivateKey_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_RSAPrivateKey_procname = 'PEM_read_RSAPrivateKey';
  PEM_read_RSAPrivateKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_read_RSAPrivateKey_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_bio_RSAPrivateKey_procname = 'PEM_write_bio_RSAPrivateKey';
  PEM_write_bio_RSAPrivateKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_write_bio_RSAPrivateKey_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_RSAPrivateKey_procname = 'PEM_write_RSAPrivateKey';
  PEM_write_RSAPrivateKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_write_RSAPrivateKey_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_bio_RSAPublicKey_procname = 'PEM_read_bio_RSAPublicKey';
  PEM_read_bio_RSAPublicKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_read_bio_RSAPublicKey_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_RSAPublicKey_procname = 'PEM_read_RSAPublicKey';
  PEM_read_RSAPublicKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_read_RSAPublicKey_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_bio_RSAPublicKey_procname = 'PEM_write_bio_RSAPublicKey';
  PEM_write_bio_RSAPublicKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_write_bio_RSAPublicKey_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_RSAPublicKey_procname = 'PEM_write_RSAPublicKey';
  PEM_write_RSAPublicKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_write_RSAPublicKey_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_bio_RSA_PUBKEY_procname = 'PEM_read_bio_RSA_PUBKEY';
  PEM_read_bio_RSA_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_read_bio_RSA_PUBKEY_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_RSA_PUBKEY_procname = 'PEM_read_RSA_PUBKEY';
  PEM_read_RSA_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_read_RSA_PUBKEY_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_bio_RSA_PUBKEY_procname = 'PEM_write_bio_RSA_PUBKEY';
  PEM_write_bio_RSA_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_write_bio_RSA_PUBKEY_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_RSA_PUBKEY_procname = 'PEM_write_RSA_PUBKEY';
  PEM_write_RSA_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_write_RSA_PUBKEY_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_bio_DSAPrivateKey_procname = 'PEM_read_bio_DSAPrivateKey';
  PEM_read_bio_DSAPrivateKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_read_bio_DSAPrivateKey_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_DSAPrivateKey_procname = 'PEM_read_DSAPrivateKey';
  PEM_read_DSAPrivateKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_read_DSAPrivateKey_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_bio_DSAPrivateKey_procname = 'PEM_write_bio_DSAPrivateKey';
  PEM_write_bio_DSAPrivateKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_write_bio_DSAPrivateKey_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_DSAPrivateKey_procname = 'PEM_write_DSAPrivateKey';
  PEM_write_DSAPrivateKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_write_DSAPrivateKey_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_bio_DSA_PUBKEY_procname = 'PEM_read_bio_DSA_PUBKEY';
  PEM_read_bio_DSA_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_read_bio_DSA_PUBKEY_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_DSA_PUBKEY_procname = 'PEM_read_DSA_PUBKEY';
  PEM_read_DSA_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_read_DSA_PUBKEY_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_bio_DSA_PUBKEY_procname = 'PEM_write_bio_DSA_PUBKEY';
  PEM_write_bio_DSA_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_write_bio_DSA_PUBKEY_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_DSA_PUBKEY_procname = 'PEM_write_DSA_PUBKEY';
  PEM_write_DSA_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_write_DSA_PUBKEY_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_bio_DSAparams_procname = 'PEM_read_bio_DSAparams';
  PEM_read_bio_DSAparams_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_read_bio_DSAparams_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_DSAparams_procname = 'PEM_read_DSAparams';
  PEM_read_DSAparams_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_read_DSAparams_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_bio_DSAparams_procname = 'PEM_write_bio_DSAparams';
  PEM_write_bio_DSAparams_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_write_bio_DSAparams_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_DSAparams_procname = 'PEM_write_DSAparams';
  PEM_write_DSAparams_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_write_DSAparams_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_bio_ECPKParameters_procname = 'PEM_read_bio_ECPKParameters';
  PEM_read_bio_ECPKParameters_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_read_bio_ECPKParameters_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_ECPKParameters_procname = 'PEM_read_ECPKParameters';
  PEM_read_ECPKParameters_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_read_ECPKParameters_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_bio_ECPKParameters_procname = 'PEM_write_bio_ECPKParameters';
  PEM_write_bio_ECPKParameters_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_write_bio_ECPKParameters_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_ECPKParameters_procname = 'PEM_write_ECPKParameters';
  PEM_write_ECPKParameters_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_write_ECPKParameters_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_bio_ECPrivateKey_procname = 'PEM_read_bio_ECPrivateKey';
  PEM_read_bio_ECPrivateKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_read_bio_ECPrivateKey_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_ECPrivateKey_procname = 'PEM_read_ECPrivateKey';
  PEM_read_ECPrivateKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_read_ECPrivateKey_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_bio_ECPrivateKey_procname = 'PEM_write_bio_ECPrivateKey';
  PEM_write_bio_ECPrivateKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_write_bio_ECPrivateKey_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_ECPrivateKey_procname = 'PEM_write_ECPrivateKey';
  PEM_write_ECPrivateKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_write_ECPrivateKey_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_bio_EC_PUBKEY_procname = 'PEM_read_bio_EC_PUBKEY';
  PEM_read_bio_EC_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_read_bio_EC_PUBKEY_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_EC_PUBKEY_procname = 'PEM_read_EC_PUBKEY';
  PEM_read_EC_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_read_EC_PUBKEY_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_bio_EC_PUBKEY_procname = 'PEM_write_bio_EC_PUBKEY';
  PEM_write_bio_EC_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_write_bio_EC_PUBKEY_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_EC_PUBKEY_procname = 'PEM_write_EC_PUBKEY';
  PEM_write_EC_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_write_EC_PUBKEY_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_bio_DHparams_procname = 'PEM_read_bio_DHparams';
  PEM_read_bio_DHparams_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_read_bio_DHparams_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_DHparams_procname = 'PEM_read_DHparams';
  PEM_read_DHparams_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_read_DHparams_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_bio_DHparams_procname = 'PEM_write_bio_DHparams';
  PEM_write_bio_DHparams_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_write_bio_DHparams_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_DHparams_procname = 'PEM_write_DHparams';
  PEM_write_DHparams_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_write_DHparams_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_bio_DHxparams_procname = 'PEM_write_bio_DHxparams';
  PEM_write_bio_DHxparams_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_write_bio_DHxparams_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_DHxparams_procname = 'PEM_write_DHxparams';
  PEM_write_DHxparams_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);
  PEM_write_DHxparams_removed = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_bio_PrivateKey_procname = 'PEM_read_bio_PrivateKey';
  PEM_read_bio_PrivateKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_read_bio_PrivateKey_ex_procname = 'PEM_read_bio_PrivateKey_ex';
  PEM_read_bio_PrivateKey_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_PrivateKey_procname = 'PEM_read_PrivateKey';
  PEM_read_PrivateKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_read_PrivateKey_ex_procname = 'PEM_read_PrivateKey_ex';
  PEM_read_PrivateKey_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_bio_PrivateKey_procname = 'PEM_write_bio_PrivateKey';
  PEM_write_bio_PrivateKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_bio_PrivateKey_ex_procname = 'PEM_write_bio_PrivateKey_ex';
  PEM_write_bio_PrivateKey_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_PrivateKey_procname = 'PEM_write_PrivateKey';
  PEM_write_PrivateKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_PrivateKey_ex_procname = 'PEM_write_PrivateKey_ex';
  PEM_write_PrivateKey_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_bio_PUBKEY_procname = 'PEM_read_bio_PUBKEY';
  PEM_read_bio_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_read_bio_PUBKEY_ex_procname = 'PEM_read_bio_PUBKEY_ex';
  PEM_read_bio_PUBKEY_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_PUBKEY_procname = 'PEM_read_PUBKEY';
  PEM_read_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_read_PUBKEY_ex_procname = 'PEM_read_PUBKEY_ex';
  PEM_read_PUBKEY_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_bio_PUBKEY_procname = 'PEM_write_bio_PUBKEY';
  PEM_write_bio_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_bio_PUBKEY_ex_procname = 'PEM_write_bio_PUBKEY_ex';
  PEM_write_bio_PUBKEY_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_PUBKEY_procname = 'PEM_write_PUBKEY';
  PEM_write_PUBKEY_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_PUBKEY_ex_procname = 'PEM_write_PUBKEY_ex';
  PEM_write_PUBKEY_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_write_bio_PrivateKey_traditional_procname = 'PEM_write_bio_PrivateKey_traditional';
  PEM_write_bio_PrivateKey_traditional_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_bio_PKCS8PrivateKey_nid_procname = 'PEM_write_bio_PKCS8PrivateKey_nid';
  PEM_write_bio_PKCS8PrivateKey_nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_bio_PKCS8PrivateKey_procname = 'PEM_write_bio_PKCS8PrivateKey';
  PEM_write_bio_PKCS8PrivateKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS8PrivateKey_bio_procname = 'i2d_PKCS8PrivateKey_bio';
  i2d_PKCS8PrivateKey_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS8PrivateKey_nid_bio_procname = 'i2d_PKCS8PrivateKey_nid_bio';
  i2d_PKCS8PrivateKey_nid_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PKCS8PrivateKey_bio_procname = 'd2i_PKCS8PrivateKey_bio';
  d2i_PKCS8PrivateKey_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS8PrivateKey_fp_procname = 'i2d_PKCS8PrivateKey_fp';
  i2d_PKCS8PrivateKey_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS8PrivateKey_nid_fp_procname = 'i2d_PKCS8PrivateKey_nid_fp';
  i2d_PKCS8PrivateKey_nid_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_PKCS8PrivateKey_nid_procname = 'PEM_write_PKCS8PrivateKey_nid';
  PEM_write_PKCS8PrivateKey_nid_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PKCS8PrivateKey_fp_procname = 'd2i_PKCS8PrivateKey_fp';
  d2i_PKCS8PrivateKey_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_PKCS8PrivateKey_procname = 'PEM_write_PKCS8PrivateKey';
  PEM_write_PKCS8PrivateKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_read_bio_Parameters_ex_procname = 'PEM_read_bio_Parameters_ex';
  PEM_read_bio_Parameters_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PEM_read_bio_Parameters_procname = 'PEM_read_bio_Parameters';
  PEM_read_bio_Parameters_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_bio_Parameters_procname = 'PEM_write_bio_Parameters';
  PEM_write_bio_Parameters_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  b2i_PrivateKey_procname = 'b2i_PrivateKey';
  b2i_PrivateKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  b2i_PublicKey_procname = 'b2i_PublicKey';
  b2i_PublicKey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  b2i_PrivateKey_bio_procname = 'b2i_PrivateKey_bio';
  b2i_PrivateKey_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  b2i_PublicKey_bio_procname = 'b2i_PublicKey_bio';
  b2i_PublicKey_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2b_PrivateKey_bio_procname = 'i2b_PrivateKey_bio';
  i2b_PrivateKey_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2b_PublicKey_bio_procname = 'i2b_PublicKey_bio';
  i2b_PublicKey_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  b2i_PVK_bio_procname = 'b2i_PVK_bio';
  b2i_PVK_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  b2i_PVK_bio_ex_procname = 'b2i_PVK_bio_ex';
  b2i_PVK_bio_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  i2b_PVK_bio_procname = 'i2b_PVK_bio';
  i2b_PVK_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2b_PVK_bio_ex_procname = 'i2b_PVK_bio_ex';
  i2b_PVK_bio_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_PEM_get_EVP_CIPHER_INFO(header: PIdAnsiChar; cipher: PEVP_CIPHER_INFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_get_EVP_CIPHER_INFO_procname);
end;

function ERR_PEM_do_header(cipher: PEVP_CIPHER_INFO; data: PIdAnsiChar; len: PIdC_LONG; callback: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_do_header_procname);
end;

function ERR_PEM_read_bio(bp: PBIO; name: PPIdAnsiChar; header: PPIdAnsiChar; data: PPIdAnsiChar; len: PIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_procname);
end;

function ERR_PEM_read_bio_ex(bp: PBIO; name: PPIdAnsiChar; header: PPIdAnsiChar; data: PPIdAnsiChar; len: PIdC_LONG; flags: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_ex_procname);
end;

function ERR_PEM_bytes_read_bio_secmem(pdata: PPIdAnsiChar; plen: PIdC_LONG; pnm: PPIdAnsiChar; name: PIdAnsiChar; bp: PBIO; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_bytes_read_bio_secmem_procname);
end;

function ERR_PEM_write_bio(bp: PBIO; name: PIdAnsiChar; hdr: PIdAnsiChar; data: PIdAnsiChar; len: TIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_procname);
end;

function ERR_PEM_bytes_read_bio(pdata: PPIdAnsiChar; plen: PIdC_LONG; pnm: PPIdAnsiChar; name: PIdAnsiChar; bp: PBIO; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_bytes_read_bio_procname);
end;

function ERR_PEM_ASN1_read_bio(d2i: TPEM_ASN1_read_bio_d2i_cb; name: PIdAnsiChar; bp: PBIO; x: PPointer; cb: TPEM_do_header_callback_cb; u: Pointer): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_ASN1_read_bio_procname);
end;

function ERR_PEM_ASN1_write_bio(i2d: TPEM_ASN1_write_bio_i2d_cb; name: PIdAnsiChar; bp: PBIO; x: Pointer; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_ASN1_write_bio_procname);
end;

function ERR_PEM_ASN1_write_bio_ctx(i2d: TPEM_ASN1_write_bio_ctx_i2d_cb; vctx: Pointer; name: PIdAnsiChar; bp: PBIO; x: Pointer; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_ASN1_write_bio_ctx_procname);
end;

function ERR_PEM_X509_INFO_read_bio(bp: PBIO; sk: Pstack_st_X509_INFO; cb: TPEM_do_header_callback_cb; u: Pointer): Pstack_st_X509_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_X509_INFO_read_bio_procname);
end;

function ERR_PEM_X509_INFO_read_bio_ex(bp: PBIO; sk: Pstack_st_X509_INFO; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pstack_st_X509_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_X509_INFO_read_bio_ex_procname);
end;

function ERR_PEM_X509_INFO_write_bio(bp: PBIO; xi: PX509_INFO; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cd: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_X509_INFO_write_bio_procname);
end;

function ERR_PEM_read(fp: PFILE; name: PPIdAnsiChar; header: PPIdAnsiChar; data: PPIdAnsiChar; len: PIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_procname);
end;

function ERR_PEM_write(fp: PFILE; name: PIdAnsiChar; hdr: PIdAnsiChar; data: PIdAnsiChar; len: TIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_procname);
end;

function ERR_PEM_ASN1_read(d2i: TPEM_ASN1_read_bio_d2i_cb; name: PIdAnsiChar; fp: PFILE; x: PPointer; cb: TPEM_do_header_callback_cb; u: Pointer): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_ASN1_read_procname);
end;

function ERR_PEM_ASN1_write(i2d: TPEM_ASN1_write_bio_i2d_cb; name: PIdAnsiChar; fp: PFILE; x: Pointer; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; callback: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_ASN1_write_procname);
end;

function ERR_PEM_X509_INFO_read(fp: PFILE; sk: Pstack_st_X509_INFO; cb: TPEM_do_header_callback_cb; u: Pointer): Pstack_st_X509_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_X509_INFO_read_procname);
end;

function ERR_PEM_X509_INFO_read_ex(fp: PFILE; sk: Pstack_st_X509_INFO; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): Pstack_st_X509_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_X509_INFO_read_ex_procname);
end;

function ERR_PEM_SignInit(ctx: PEVP_MD_CTX; _type: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_SignInit_procname);
end;

function ERR_PEM_SignUpdate(ctx: PEVP_MD_CTX; d: PIdAnsiChar; cnt: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_SignUpdate_procname);
end;

function ERR_PEM_SignFinal(ctx: PEVP_MD_CTX; sigret: PIdAnsiChar; siglen: PIdC_UINT; pkey: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_SignFinal_procname);
end;

function ERR_PEM_def_callback(buf: PIdAnsiChar; num: TIdC_INT; rwflag: TIdC_INT; userdata: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_def_callback_procname);
end;

function ERR_PEM_proc_type(buf: PIdAnsiChar; _type: TIdC_INT): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_proc_type_procname);
end;

function ERR_PEM_dek_info(buf: PIdAnsiChar; _type: PIdAnsiChar; len: TIdC_INT; str: PIdAnsiChar): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_dek_info_procname);
end;

function ERR_PEM_read_bio_X509(_out: PBIO; x: PPX509; cb: TPEM_do_header_callback_cb; u: Pointer): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_X509_procname);
end;

function ERR_PEM_read_X509(_out: PFILE; x: PPX509; cb: TPEM_do_header_callback_cb; u: Pointer): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_X509_procname);
end;

function ERR_PEM_write_bio_X509(_out: PBIO; x: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_X509_procname);
end;

function ERR_PEM_write_X509(_out: PFILE; x: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_X509_procname);
end;

function ERR_PEM_read_bio_X509_AUX(_out: PBIO; x: PPX509; cb: TPEM_do_header_callback_cb; u: Pointer): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_X509_AUX_procname);
end;

function ERR_PEM_read_X509_AUX(_out: PFILE; x: PPX509; cb: TPEM_do_header_callback_cb; u: Pointer): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_X509_AUX_procname);
end;

function ERR_PEM_write_bio_X509_AUX(_out: PBIO; x: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_X509_AUX_procname);
end;

function ERR_PEM_write_X509_AUX(_out: PFILE; x: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_X509_AUX_procname);
end;

function ERR_PEM_read_bio_X509_REQ(_out: PBIO; x: PPX509_REQ; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_REQ; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_X509_REQ_procname);
end;

function ERR_PEM_read_X509_REQ(_out: PFILE; x: PPX509_REQ; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_REQ; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_X509_REQ_procname);
end;

function ERR_PEM_write_bio_X509_REQ(_out: PBIO; x: PX509_REQ): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_X509_REQ_procname);
end;

function ERR_PEM_write_X509_REQ(_out: PFILE; x: PX509_REQ): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_X509_REQ_procname);
end;

function ERR_PEM_write_bio_X509_REQ_NEW(_out: PBIO; x: PX509_REQ): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_X509_REQ_NEW_procname);
end;

function ERR_PEM_write_X509_REQ_NEW(_out: PFILE; x: PX509_REQ): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_X509_REQ_NEW_procname);
end;

function ERR_PEM_read_bio_X509_CRL(_out: PBIO; x: PPX509_CRL; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_CRL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_X509_CRL_procname);
end;

function ERR_PEM_read_X509_CRL(_out: PFILE; x: PPX509_CRL; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_CRL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_X509_CRL_procname);
end;

function ERR_PEM_write_bio_X509_CRL(_out: PBIO; x: PX509_CRL): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_X509_CRL_procname);
end;

function ERR_PEM_write_X509_CRL(_out: PFILE; x: PX509_CRL): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_X509_CRL_procname);
end;

function ERR_PEM_read_bio_X509_PUBKEY(_out: PBIO; x: PPX509_PUBKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_PUBKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_X509_PUBKEY_procname);
end;

function ERR_PEM_read_X509_PUBKEY(_out: PFILE; x: PPX509_PUBKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_PUBKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_X509_PUBKEY_procname);
end;

function ERR_PEM_write_bio_X509_PUBKEY(_out: PBIO; x: PX509_PUBKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_X509_PUBKEY_procname);
end;

function ERR_PEM_write_X509_PUBKEY(_out: PFILE; x: PX509_PUBKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_X509_PUBKEY_procname);
end;

function ERR_PEM_read_bio_PKCS7(_out: PBIO; x: PPPKCS7; cb: TPEM_do_header_callback_cb; u: Pointer): PPKCS7; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_PKCS7_procname);
end;

function ERR_PEM_read_PKCS7(_out: PFILE; x: PPPKCS7; cb: TPEM_do_header_callback_cb; u: Pointer): PPKCS7; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_PKCS7_procname);
end;

function ERR_PEM_write_bio_PKCS7(_out: PBIO; x: PPKCS7): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_PKCS7_procname);
end;

function ERR_PEM_write_PKCS7(_out: PFILE; x: PPKCS7): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_PKCS7_procname);
end;

function ERR_PEM_read_bio_NETSCAPE_CERT_SEQUENCE(_out: PBIO; x: PPNETSCAPE_CERT_SEQUENCE; cb: TPEM_do_header_callback_cb; u: Pointer): PNETSCAPE_CERT_SEQUENCE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_NETSCAPE_CERT_SEQUENCE_procname);
end;

function ERR_PEM_read_NETSCAPE_CERT_SEQUENCE(_out: PFILE; x: PPNETSCAPE_CERT_SEQUENCE; cb: TPEM_do_header_callback_cb; u: Pointer): PNETSCAPE_CERT_SEQUENCE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_NETSCAPE_CERT_SEQUENCE_procname);
end;

function ERR_PEM_write_bio_NETSCAPE_CERT_SEQUENCE(_out: PBIO; x: PNETSCAPE_CERT_SEQUENCE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_NETSCAPE_CERT_SEQUENCE_procname);
end;

function ERR_PEM_write_NETSCAPE_CERT_SEQUENCE(_out: PFILE; x: PNETSCAPE_CERT_SEQUENCE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_NETSCAPE_CERT_SEQUENCE_procname);
end;

function ERR_PEM_read_bio_PKCS8(_out: PBIO; x: PPX509_SIG; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_SIG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_PKCS8_procname);
end;

function ERR_PEM_read_PKCS8(_out: PFILE; x: PPX509_SIG; cb: TPEM_do_header_callback_cb; u: Pointer): PX509_SIG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_PKCS8_procname);
end;

function ERR_PEM_write_bio_PKCS8(_out: PBIO; x: PX509_SIG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_PKCS8_procname);
end;

function ERR_PEM_write_PKCS8(_out: PFILE; x: PX509_SIG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_PKCS8_procname);
end;

function ERR_PEM_read_bio_PKCS8_PRIV_KEY_INFO(_out: PBIO; x: PPPKCS8_PRIV_KEY_INFO; cb: TPEM_do_header_callback_cb; u: Pointer): PPKCS8_PRIV_KEY_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_PKCS8_PRIV_KEY_INFO_procname);
end;

function ERR_PEM_read_PKCS8_PRIV_KEY_INFO(_out: PFILE; x: PPPKCS8_PRIV_KEY_INFO; cb: TPEM_do_header_callback_cb; u: Pointer): PPKCS8_PRIV_KEY_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_PKCS8_PRIV_KEY_INFO_procname);
end;

function ERR_PEM_write_bio_PKCS8_PRIV_KEY_INFO(_out: PBIO; x: PPKCS8_PRIV_KEY_INFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_PKCS8_PRIV_KEY_INFO_procname);
end;

function ERR_PEM_write_PKCS8_PRIV_KEY_INFO(_out: PFILE; x: PPKCS8_PRIV_KEY_INFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_PKCS8_PRIV_KEY_INFO_procname);
end;

function ERR_PEM_read_bio_RSAPrivateKey(_out: PBIO; x: PPRSA; cb: TPEM_do_header_callback_cb; u: Pointer): PRSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_RSAPrivateKey_procname);
end;

function ERR_PEM_read_RSAPrivateKey(_out: PFILE; x: PPRSA; cb: TPEM_do_header_callback_cb; u: Pointer): PRSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_RSAPrivateKey_procname);
end;

function ERR_PEM_write_bio_RSAPrivateKey(_out: PBIO; x: PRSA; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_RSAPrivateKey_procname);
end;

function ERR_PEM_write_RSAPrivateKey(_out: PFILE; x: PRSA; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_RSAPrivateKey_procname);
end;

function ERR_PEM_read_bio_RSAPublicKey(_out: PBIO; x: PPRSA; cb: TPEM_do_header_callback_cb; u: Pointer): PRSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_RSAPublicKey_procname);
end;

function ERR_PEM_read_RSAPublicKey(_out: PFILE; x: PPRSA; cb: TPEM_do_header_callback_cb; u: Pointer): PRSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_RSAPublicKey_procname);
end;

function ERR_PEM_write_bio_RSAPublicKey(_out: PBIO; x: PRSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_RSAPublicKey_procname);
end;

function ERR_PEM_write_RSAPublicKey(_out: PFILE; x: PRSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_RSAPublicKey_procname);
end;

function ERR_PEM_read_bio_RSA_PUBKEY(_out: PBIO; x: PPRSA; cb: TPEM_do_header_callback_cb; u: Pointer): PRSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_RSA_PUBKEY_procname);
end;

function ERR_PEM_read_RSA_PUBKEY(_out: PFILE; x: PPRSA; cb: TPEM_do_header_callback_cb; u: Pointer): PRSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_RSA_PUBKEY_procname);
end;

function ERR_PEM_write_bio_RSA_PUBKEY(_out: PBIO; x: PRSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_RSA_PUBKEY_procname);
end;

function ERR_PEM_write_RSA_PUBKEY(_out: PFILE; x: PRSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_RSA_PUBKEY_procname);
end;

function ERR_PEM_read_bio_DSAPrivateKey(_out: PBIO; x: PPDSA; cb: TPEM_do_header_callback_cb; u: Pointer): PDSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_DSAPrivateKey_procname);
end;

function ERR_PEM_read_DSAPrivateKey(_out: PFILE; x: PPDSA; cb: TPEM_do_header_callback_cb; u: Pointer): PDSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_DSAPrivateKey_procname);
end;

function ERR_PEM_write_bio_DSAPrivateKey(_out: PBIO; x: PDSA; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_DSAPrivateKey_procname);
end;

function ERR_PEM_write_DSAPrivateKey(_out: PFILE; x: PDSA; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_DSAPrivateKey_procname);
end;

function ERR_PEM_read_bio_DSA_PUBKEY(_out: PBIO; x: PPDSA; cb: TPEM_do_header_callback_cb; u: Pointer): PDSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_DSA_PUBKEY_procname);
end;

function ERR_PEM_read_DSA_PUBKEY(_out: PFILE; x: PPDSA; cb: TPEM_do_header_callback_cb; u: Pointer): PDSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_DSA_PUBKEY_procname);
end;

function ERR_PEM_write_bio_DSA_PUBKEY(_out: PBIO; x: PDSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_DSA_PUBKEY_procname);
end;

function ERR_PEM_write_DSA_PUBKEY(_out: PFILE; x: PDSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_DSA_PUBKEY_procname);
end;

function ERR_PEM_read_bio_DSAparams(_out: PBIO; x: PPDSA; cb: TPEM_do_header_callback_cb; u: Pointer): PDSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_DSAparams_procname);
end;

function ERR_PEM_read_DSAparams(_out: PFILE; x: PPDSA; cb: TPEM_do_header_callback_cb; u: Pointer): PDSA; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_DSAparams_procname);
end;

function ERR_PEM_write_bio_DSAparams(_out: PBIO; x: PDSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_DSAparams_procname);
end;

function ERR_PEM_write_DSAparams(_out: PFILE; x: PDSA): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_DSAparams_procname);
end;

function ERR_PEM_read_bio_ECPKParameters(_out: PBIO; x: PPEC_GROUP; cb: TPEM_do_header_callback_cb; u: Pointer): PEC_GROUP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_ECPKParameters_procname);
end;

function ERR_PEM_read_ECPKParameters(_out: PFILE; x: PPEC_GROUP; cb: TPEM_do_header_callback_cb; u: Pointer): PEC_GROUP; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_ECPKParameters_procname);
end;

function ERR_PEM_write_bio_ECPKParameters(_out: PBIO; x: PEC_GROUP): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_ECPKParameters_procname);
end;

function ERR_PEM_write_ECPKParameters(_out: PFILE; x: PEC_GROUP): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_ECPKParameters_procname);
end;

function ERR_PEM_read_bio_ECPrivateKey(_out: PBIO; x: PPEC_KEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEC_KEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_ECPrivateKey_procname);
end;

function ERR_PEM_read_ECPrivateKey(_out: PFILE; x: PPEC_KEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEC_KEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_ECPrivateKey_procname);
end;

function ERR_PEM_write_bio_ECPrivateKey(_out: PBIO; x: PEC_KEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_ECPrivateKey_procname);
end;

function ERR_PEM_write_ECPrivateKey(_out: PFILE; x: PEC_KEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_ECPrivateKey_procname);
end;

function ERR_PEM_read_bio_EC_PUBKEY(_out: PBIO; x: PPEC_KEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEC_KEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_EC_PUBKEY_procname);
end;

function ERR_PEM_read_EC_PUBKEY(_out: PFILE; x: PPEC_KEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEC_KEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_EC_PUBKEY_procname);
end;

function ERR_PEM_write_bio_EC_PUBKEY(_out: PBIO; x: PEC_KEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_EC_PUBKEY_procname);
end;

function ERR_PEM_write_EC_PUBKEY(_out: PFILE; x: PEC_KEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_EC_PUBKEY_procname);
end;

function ERR_PEM_read_bio_DHparams(_out: PBIO; x: PPDH; cb: TPEM_do_header_callback_cb; u: Pointer): PDH; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_DHparams_procname);
end;

function ERR_PEM_read_DHparams(_out: PFILE; x: PPDH; cb: TPEM_do_header_callback_cb; u: Pointer): PDH; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_DHparams_procname);
end;

function ERR_PEM_write_bio_DHparams(_out: PBIO; x: PDH): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_DHparams_procname);
end;

function ERR_PEM_write_DHparams(_out: PFILE; x: PDH): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_DHparams_procname);
end;

function ERR_PEM_write_bio_DHxparams(_out: PBIO; x: PDH): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_DHxparams_procname);
end;

function ERR_PEM_write_DHxparams(_out: PFILE; x: PDH): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_DHxparams_procname);
end;

function ERR_PEM_read_bio_PrivateKey(_out: PBIO; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_PrivateKey_procname);
end;

function ERR_PEM_read_bio_PrivateKey_ex(_out: PBIO; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_PrivateKey_ex_procname);
end;

function ERR_PEM_read_PrivateKey(_out: PFILE; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_PrivateKey_procname);
end;

function ERR_PEM_read_PrivateKey_ex(_out: PFILE; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_PrivateKey_ex_procname);
end;

function ERR_PEM_write_bio_PrivateKey(_out: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_PrivateKey_procname);
end;

function ERR_PEM_write_bio_PrivateKey_ex(_out: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_PrivateKey_ex_procname);
end;

function ERR_PEM_write_PrivateKey(_out: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_PrivateKey_procname);
end;

function ERR_PEM_write_PrivateKey_ex(_out: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_PrivateKey_ex_procname);
end;

function ERR_PEM_read_bio_PUBKEY(_out: PBIO; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_PUBKEY_procname);
end;

function ERR_PEM_read_bio_PUBKEY_ex(_out: PBIO; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_PUBKEY_ex_procname);
end;

function ERR_PEM_read_PUBKEY(_out: PFILE; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_PUBKEY_procname);
end;

function ERR_PEM_read_PUBKEY_ex(_out: PFILE; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_PUBKEY_ex_procname);
end;

function ERR_PEM_write_bio_PUBKEY(_out: PBIO; x: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_PUBKEY_procname);
end;

function ERR_PEM_write_bio_PUBKEY_ex(_out: PBIO; x: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_PUBKEY_ex_procname);
end;

function ERR_PEM_write_PUBKEY(_out: PFILE; x: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_PUBKEY_procname);
end;

function ERR_PEM_write_PUBKEY_ex(_out: PFILE; x: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_PUBKEY_ex_procname);
end;

function ERR_PEM_write_bio_PrivateKey_traditional(bp: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_PrivateKey_traditional_procname);
end;

function ERR_PEM_write_bio_PKCS8PrivateKey_nid(bp: PBIO; x: PEVP_PKEY; nid: TIdC_INT; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_PKCS8PrivateKey_nid_procname);
end;

function ERR_PEM_write_bio_PKCS8PrivateKey(arg1: PBIO; arg2: PEVP_PKEY; arg3: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_PKCS8PrivateKey_procname);
end;

function ERR_i2d_PKCS8PrivateKey_bio(bp: PBIO; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS8PrivateKey_bio_procname);
end;

function ERR_i2d_PKCS8PrivateKey_nid_bio(bp: PBIO; x: PEVP_PKEY; nid: TIdC_INT; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS8PrivateKey_nid_bio_procname);
end;

function ERR_d2i_PKCS8PrivateKey_bio(bp: PBIO; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS8PrivateKey_bio_procname);
end;

function ERR_i2d_PKCS8PrivateKey_fp(fp: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS8PrivateKey_fp_procname);
end;

function ERR_i2d_PKCS8PrivateKey_nid_fp(fp: PFILE; x: PEVP_PKEY; nid: TIdC_INT; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS8PrivateKey_nid_fp_procname);
end;

function ERR_PEM_write_PKCS8PrivateKey_nid(fp: PFILE; x: PEVP_PKEY; nid: TIdC_INT; kstr: PIdAnsiChar; klen: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_PKCS8PrivateKey_nid_procname);
end;

function ERR_d2i_PKCS8PrivateKey_fp(fp: PFILE; x: PPEVP_PKEY; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS8PrivateKey_fp_procname);
end;

function ERR_PEM_write_PKCS8PrivateKey(fp: PFILE; x: PEVP_PKEY; enc: PEVP_CIPHER; kstr: PIdAnsiChar; klen: TIdC_INT; cd: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_PKCS8PrivateKey_procname);
end;

function ERR_PEM_read_bio_Parameters_ex(bp: PBIO; x: PPEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_Parameters_ex_procname);
end;

function ERR_PEM_read_bio_Parameters(bp: PBIO; x: PPEVP_PKEY): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_Parameters_procname);
end;

function ERR_PEM_write_bio_Parameters(bp: PBIO; x: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_Parameters_procname);
end;

function ERR_b2i_PrivateKey(_in: PPIdAnsiChar; length: TIdC_LONG): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(b2i_PrivateKey_procname);
end;

function ERR_b2i_PublicKey(_in: PPIdAnsiChar; length: TIdC_LONG): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(b2i_PublicKey_procname);
end;

function ERR_b2i_PrivateKey_bio(_in: PBIO): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(b2i_PrivateKey_bio_procname);
end;

function ERR_b2i_PublicKey_bio(_in: PBIO): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(b2i_PublicKey_bio_procname);
end;

function ERR_i2b_PrivateKey_bio(_out: PBIO; pk: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2b_PrivateKey_bio_procname);
end;

function ERR_i2b_PublicKey_bio(_out: PBIO; pk: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2b_PublicKey_bio_procname);
end;

function ERR_b2i_PVK_bio(_in: PBIO; cb: TPEM_do_header_callback_cb; u: Pointer): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(b2i_PVK_bio_procname);
end;

function ERR_b2i_PVK_bio_ex(_in: PBIO; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PEVP_PKEY; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(b2i_PVK_bio_ex_procname);
end;

function ERR_i2b_PVK_bio(_out: PBIO; pk: PEVP_PKEY; enclevel: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2b_PVK_bio_procname);
end;

function ERR_i2b_PVK_bio_ex(_out: PBIO; pk: PEVP_PKEY; enclevel: TIdC_INT; cb: TPEM_do_header_callback_cb; u: Pointer; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2b_PVK_bio_ex_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  PEM_get_EVP_CIPHER_INFO := LoadLibFunction(ADllHandle, PEM_get_EVP_CIPHER_INFO_procname);
  FuncLoadError := not assigned(PEM_get_EVP_CIPHER_INFO);
  if FuncLoadError then
  begin
    {$if not defined(PEM_get_EVP_CIPHER_INFO_allownil)}
    PEM_get_EVP_CIPHER_INFO := ERR_PEM_get_EVP_CIPHER_INFO;
    {$ifend}
    {$if declared(PEM_get_EVP_CIPHER_INFO_introduced)}
    if LibVersion < PEM_get_EVP_CIPHER_INFO_introduced then
    begin
      {$if declared(FC_PEM_get_EVP_CIPHER_INFO)}
      PEM_get_EVP_CIPHER_INFO := FC_PEM_get_EVP_CIPHER_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_get_EVP_CIPHER_INFO_removed)}
    if PEM_get_EVP_CIPHER_INFO_removed <= LibVersion then
    begin
      {$if declared(_PEM_get_EVP_CIPHER_INFO)}
      PEM_get_EVP_CIPHER_INFO := _PEM_get_EVP_CIPHER_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_get_EVP_CIPHER_INFO_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_get_EVP_CIPHER_INFO');
    {$ifend}
  end;
  
  PEM_do_header := LoadLibFunction(ADllHandle, PEM_do_header_procname);
  FuncLoadError := not assigned(PEM_do_header);
  if FuncLoadError then
  begin
    {$if not defined(PEM_do_header_allownil)}
    PEM_do_header := ERR_PEM_do_header;
    {$ifend}
    {$if declared(PEM_do_header_introduced)}
    if LibVersion < PEM_do_header_introduced then
    begin
      {$if declared(FC_PEM_do_header)}
      PEM_do_header := FC_PEM_do_header;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_do_header_removed)}
    if PEM_do_header_removed <= LibVersion then
    begin
      {$if declared(_PEM_do_header)}
      PEM_do_header := _PEM_do_header;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_do_header_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_do_header');
    {$ifend}
  end;
  
  PEM_read_bio := LoadLibFunction(ADllHandle, PEM_read_bio_procname);
  FuncLoadError := not assigned(PEM_read_bio);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_allownil)}
    PEM_read_bio := ERR_PEM_read_bio;
    {$ifend}
    {$if declared(PEM_read_bio_introduced)}
    if LibVersion < PEM_read_bio_introduced then
    begin
      {$if declared(FC_PEM_read_bio)}
      PEM_read_bio := FC_PEM_read_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_removed)}
    if PEM_read_bio_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio)}
      PEM_read_bio := _PEM_read_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio');
    {$ifend}
  end;
  
  PEM_read_bio_ex := LoadLibFunction(ADllHandle, PEM_read_bio_ex_procname);
  FuncLoadError := not assigned(PEM_read_bio_ex);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_ex_allownil)}
    PEM_read_bio_ex := ERR_PEM_read_bio_ex;
    {$ifend}
    {$if declared(PEM_read_bio_ex_introduced)}
    if LibVersion < PEM_read_bio_ex_introduced then
    begin
      {$if declared(FC_PEM_read_bio_ex)}
      PEM_read_bio_ex := FC_PEM_read_bio_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_ex_removed)}
    if PEM_read_bio_ex_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_ex)}
      PEM_read_bio_ex := _PEM_read_bio_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_ex');
    {$ifend}
  end;
  
  PEM_bytes_read_bio_secmem := LoadLibFunction(ADllHandle, PEM_bytes_read_bio_secmem_procname);
  FuncLoadError := not assigned(PEM_bytes_read_bio_secmem);
  if FuncLoadError then
  begin
    {$if not defined(PEM_bytes_read_bio_secmem_allownil)}
    PEM_bytes_read_bio_secmem := ERR_PEM_bytes_read_bio_secmem;
    {$ifend}
    {$if declared(PEM_bytes_read_bio_secmem_introduced)}
    if LibVersion < PEM_bytes_read_bio_secmem_introduced then
    begin
      {$if declared(FC_PEM_bytes_read_bio_secmem)}
      PEM_bytes_read_bio_secmem := FC_PEM_bytes_read_bio_secmem;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_bytes_read_bio_secmem_removed)}
    if PEM_bytes_read_bio_secmem_removed <= LibVersion then
    begin
      {$if declared(_PEM_bytes_read_bio_secmem)}
      PEM_bytes_read_bio_secmem := _PEM_bytes_read_bio_secmem;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_bytes_read_bio_secmem_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_bytes_read_bio_secmem');
    {$ifend}
  end;
  
  PEM_write_bio := LoadLibFunction(ADllHandle, PEM_write_bio_procname);
  FuncLoadError := not assigned(PEM_write_bio);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_allownil)}
    PEM_write_bio := ERR_PEM_write_bio;
    {$ifend}
    {$if declared(PEM_write_bio_introduced)}
    if LibVersion < PEM_write_bio_introduced then
    begin
      {$if declared(FC_PEM_write_bio)}
      PEM_write_bio := FC_PEM_write_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_removed)}
    if PEM_write_bio_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio)}
      PEM_write_bio := _PEM_write_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio');
    {$ifend}
  end;
  
  PEM_bytes_read_bio := LoadLibFunction(ADllHandle, PEM_bytes_read_bio_procname);
  FuncLoadError := not assigned(PEM_bytes_read_bio);
  if FuncLoadError then
  begin
    {$if not defined(PEM_bytes_read_bio_allownil)}
    PEM_bytes_read_bio := ERR_PEM_bytes_read_bio;
    {$ifend}
    {$if declared(PEM_bytes_read_bio_introduced)}
    if LibVersion < PEM_bytes_read_bio_introduced then
    begin
      {$if declared(FC_PEM_bytes_read_bio)}
      PEM_bytes_read_bio := FC_PEM_bytes_read_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_bytes_read_bio_removed)}
    if PEM_bytes_read_bio_removed <= LibVersion then
    begin
      {$if declared(_PEM_bytes_read_bio)}
      PEM_bytes_read_bio := _PEM_bytes_read_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_bytes_read_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_bytes_read_bio');
    {$ifend}
  end;
  
  PEM_ASN1_read_bio := LoadLibFunction(ADllHandle, PEM_ASN1_read_bio_procname);
  FuncLoadError := not assigned(PEM_ASN1_read_bio);
  if FuncLoadError then
  begin
    {$if not defined(PEM_ASN1_read_bio_allownil)}
    PEM_ASN1_read_bio := ERR_PEM_ASN1_read_bio;
    {$ifend}
    {$if declared(PEM_ASN1_read_bio_introduced)}
    if LibVersion < PEM_ASN1_read_bio_introduced then
    begin
      {$if declared(FC_PEM_ASN1_read_bio)}
      PEM_ASN1_read_bio := FC_PEM_ASN1_read_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_ASN1_read_bio_removed)}
    if PEM_ASN1_read_bio_removed <= LibVersion then
    begin
      {$if declared(_PEM_ASN1_read_bio)}
      PEM_ASN1_read_bio := _PEM_ASN1_read_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_ASN1_read_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_ASN1_read_bio');
    {$ifend}
  end;
  
  PEM_ASN1_write_bio := LoadLibFunction(ADllHandle, PEM_ASN1_write_bio_procname);
  FuncLoadError := not assigned(PEM_ASN1_write_bio);
  if FuncLoadError then
  begin
    {$if not defined(PEM_ASN1_write_bio_allownil)}
    PEM_ASN1_write_bio := ERR_PEM_ASN1_write_bio;
    {$ifend}
    {$if declared(PEM_ASN1_write_bio_introduced)}
    if LibVersion < PEM_ASN1_write_bio_introduced then
    begin
      {$if declared(FC_PEM_ASN1_write_bio)}
      PEM_ASN1_write_bio := FC_PEM_ASN1_write_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_ASN1_write_bio_removed)}
    if PEM_ASN1_write_bio_removed <= LibVersion then
    begin
      {$if declared(_PEM_ASN1_write_bio)}
      PEM_ASN1_write_bio := _PEM_ASN1_write_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_ASN1_write_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_ASN1_write_bio');
    {$ifend}
  end;
  
  PEM_ASN1_write_bio_ctx := LoadLibFunction(ADllHandle, PEM_ASN1_write_bio_ctx_procname);
  FuncLoadError := not assigned(PEM_ASN1_write_bio_ctx);
  if FuncLoadError then
  begin
    {$if not defined(PEM_ASN1_write_bio_ctx_allownil)}
    PEM_ASN1_write_bio_ctx := ERR_PEM_ASN1_write_bio_ctx;
    {$ifend}
    {$if declared(PEM_ASN1_write_bio_ctx_introduced)}
    if LibVersion < PEM_ASN1_write_bio_ctx_introduced then
    begin
      {$if declared(FC_PEM_ASN1_write_bio_ctx)}
      PEM_ASN1_write_bio_ctx := FC_PEM_ASN1_write_bio_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_ASN1_write_bio_ctx_removed)}
    if PEM_ASN1_write_bio_ctx_removed <= LibVersion then
    begin
      {$if declared(_PEM_ASN1_write_bio_ctx)}
      PEM_ASN1_write_bio_ctx := _PEM_ASN1_write_bio_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_ASN1_write_bio_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_ASN1_write_bio_ctx');
    {$ifend}
  end;
  
  PEM_X509_INFO_read_bio := LoadLibFunction(ADllHandle, PEM_X509_INFO_read_bio_procname);
  FuncLoadError := not assigned(PEM_X509_INFO_read_bio);
  if FuncLoadError then
  begin
    {$if not defined(PEM_X509_INFO_read_bio_allownil)}
    PEM_X509_INFO_read_bio := ERR_PEM_X509_INFO_read_bio;
    {$ifend}
    {$if declared(PEM_X509_INFO_read_bio_introduced)}
    if LibVersion < PEM_X509_INFO_read_bio_introduced then
    begin
      {$if declared(FC_PEM_X509_INFO_read_bio)}
      PEM_X509_INFO_read_bio := FC_PEM_X509_INFO_read_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_X509_INFO_read_bio_removed)}
    if PEM_X509_INFO_read_bio_removed <= LibVersion then
    begin
      {$if declared(_PEM_X509_INFO_read_bio)}
      PEM_X509_INFO_read_bio := _PEM_X509_INFO_read_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_X509_INFO_read_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_X509_INFO_read_bio');
    {$ifend}
  end;
  
  PEM_X509_INFO_read_bio_ex := LoadLibFunction(ADllHandle, PEM_X509_INFO_read_bio_ex_procname);
  FuncLoadError := not assigned(PEM_X509_INFO_read_bio_ex);
  if FuncLoadError then
  begin
    {$if not defined(PEM_X509_INFO_read_bio_ex_allownil)}
    PEM_X509_INFO_read_bio_ex := ERR_PEM_X509_INFO_read_bio_ex;
    {$ifend}
    {$if declared(PEM_X509_INFO_read_bio_ex_introduced)}
    if LibVersion < PEM_X509_INFO_read_bio_ex_introduced then
    begin
      {$if declared(FC_PEM_X509_INFO_read_bio_ex)}
      PEM_X509_INFO_read_bio_ex := FC_PEM_X509_INFO_read_bio_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_X509_INFO_read_bio_ex_removed)}
    if PEM_X509_INFO_read_bio_ex_removed <= LibVersion then
    begin
      {$if declared(_PEM_X509_INFO_read_bio_ex)}
      PEM_X509_INFO_read_bio_ex := _PEM_X509_INFO_read_bio_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_X509_INFO_read_bio_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_X509_INFO_read_bio_ex');
    {$ifend}
  end;
  
  PEM_X509_INFO_write_bio := LoadLibFunction(ADllHandle, PEM_X509_INFO_write_bio_procname);
  FuncLoadError := not assigned(PEM_X509_INFO_write_bio);
  if FuncLoadError then
  begin
    {$if not defined(PEM_X509_INFO_write_bio_allownil)}
    PEM_X509_INFO_write_bio := ERR_PEM_X509_INFO_write_bio;
    {$ifend}
    {$if declared(PEM_X509_INFO_write_bio_introduced)}
    if LibVersion < PEM_X509_INFO_write_bio_introduced then
    begin
      {$if declared(FC_PEM_X509_INFO_write_bio)}
      PEM_X509_INFO_write_bio := FC_PEM_X509_INFO_write_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_X509_INFO_write_bio_removed)}
    if PEM_X509_INFO_write_bio_removed <= LibVersion then
    begin
      {$if declared(_PEM_X509_INFO_write_bio)}
      PEM_X509_INFO_write_bio := _PEM_X509_INFO_write_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_X509_INFO_write_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_X509_INFO_write_bio');
    {$ifend}
  end;
  
  PEM_read := LoadLibFunction(ADllHandle, PEM_read_procname);
  FuncLoadError := not assigned(PEM_read);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_allownil)}
    PEM_read := ERR_PEM_read;
    {$ifend}
    {$if declared(PEM_read_introduced)}
    if LibVersion < PEM_read_introduced then
    begin
      {$if declared(FC_PEM_read)}
      PEM_read := FC_PEM_read;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_removed)}
    if PEM_read_removed <= LibVersion then
    begin
      {$if declared(_PEM_read)}
      PEM_read := _PEM_read;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read');
    {$ifend}
  end;
  
  PEM_write := LoadLibFunction(ADllHandle, PEM_write_procname);
  FuncLoadError := not assigned(PEM_write);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_allownil)}
    PEM_write := ERR_PEM_write;
    {$ifend}
    {$if declared(PEM_write_introduced)}
    if LibVersion < PEM_write_introduced then
    begin
      {$if declared(FC_PEM_write)}
      PEM_write := FC_PEM_write;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_removed)}
    if PEM_write_removed <= LibVersion then
    begin
      {$if declared(_PEM_write)}
      PEM_write := _PEM_write;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write');
    {$ifend}
  end;
  
  PEM_ASN1_read := LoadLibFunction(ADllHandle, PEM_ASN1_read_procname);
  FuncLoadError := not assigned(PEM_ASN1_read);
  if FuncLoadError then
  begin
    {$if not defined(PEM_ASN1_read_allownil)}
    PEM_ASN1_read := ERR_PEM_ASN1_read;
    {$ifend}
    {$if declared(PEM_ASN1_read_introduced)}
    if LibVersion < PEM_ASN1_read_introduced then
    begin
      {$if declared(FC_PEM_ASN1_read)}
      PEM_ASN1_read := FC_PEM_ASN1_read;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_ASN1_read_removed)}
    if PEM_ASN1_read_removed <= LibVersion then
    begin
      {$if declared(_PEM_ASN1_read)}
      PEM_ASN1_read := _PEM_ASN1_read;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_ASN1_read_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_ASN1_read');
    {$ifend}
  end;
  
  PEM_ASN1_write := LoadLibFunction(ADllHandle, PEM_ASN1_write_procname);
  FuncLoadError := not assigned(PEM_ASN1_write);
  if FuncLoadError then
  begin
    {$if not defined(PEM_ASN1_write_allownil)}
    PEM_ASN1_write := ERR_PEM_ASN1_write;
    {$ifend}
    {$if declared(PEM_ASN1_write_introduced)}
    if LibVersion < PEM_ASN1_write_introduced then
    begin
      {$if declared(FC_PEM_ASN1_write)}
      PEM_ASN1_write := FC_PEM_ASN1_write;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_ASN1_write_removed)}
    if PEM_ASN1_write_removed <= LibVersion then
    begin
      {$if declared(_PEM_ASN1_write)}
      PEM_ASN1_write := _PEM_ASN1_write;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_ASN1_write_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_ASN1_write');
    {$ifend}
  end;
  
  PEM_X509_INFO_read := LoadLibFunction(ADllHandle, PEM_X509_INFO_read_procname);
  FuncLoadError := not assigned(PEM_X509_INFO_read);
  if FuncLoadError then
  begin
    {$if not defined(PEM_X509_INFO_read_allownil)}
    PEM_X509_INFO_read := ERR_PEM_X509_INFO_read;
    {$ifend}
    {$if declared(PEM_X509_INFO_read_introduced)}
    if LibVersion < PEM_X509_INFO_read_introduced then
    begin
      {$if declared(FC_PEM_X509_INFO_read)}
      PEM_X509_INFO_read := FC_PEM_X509_INFO_read;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_X509_INFO_read_removed)}
    if PEM_X509_INFO_read_removed <= LibVersion then
    begin
      {$if declared(_PEM_X509_INFO_read)}
      PEM_X509_INFO_read := _PEM_X509_INFO_read;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_X509_INFO_read_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_X509_INFO_read');
    {$ifend}
  end;
  
  PEM_X509_INFO_read_ex := LoadLibFunction(ADllHandle, PEM_X509_INFO_read_ex_procname);
  FuncLoadError := not assigned(PEM_X509_INFO_read_ex);
  if FuncLoadError then
  begin
    {$if not defined(PEM_X509_INFO_read_ex_allownil)}
    PEM_X509_INFO_read_ex := ERR_PEM_X509_INFO_read_ex;
    {$ifend}
    {$if declared(PEM_X509_INFO_read_ex_introduced)}
    if LibVersion < PEM_X509_INFO_read_ex_introduced then
    begin
      {$if declared(FC_PEM_X509_INFO_read_ex)}
      PEM_X509_INFO_read_ex := FC_PEM_X509_INFO_read_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_X509_INFO_read_ex_removed)}
    if PEM_X509_INFO_read_ex_removed <= LibVersion then
    begin
      {$if declared(_PEM_X509_INFO_read_ex)}
      PEM_X509_INFO_read_ex := _PEM_X509_INFO_read_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_X509_INFO_read_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_X509_INFO_read_ex');
    {$ifend}
  end;
  
  PEM_SignInit := LoadLibFunction(ADllHandle, PEM_SignInit_procname);
  FuncLoadError := not assigned(PEM_SignInit);
  if FuncLoadError then
  begin
    {$if not defined(PEM_SignInit_allownil)}
    PEM_SignInit := ERR_PEM_SignInit;
    {$ifend}
    {$if declared(PEM_SignInit_introduced)}
    if LibVersion < PEM_SignInit_introduced then
    begin
      {$if declared(FC_PEM_SignInit)}
      PEM_SignInit := FC_PEM_SignInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_SignInit_removed)}
    if PEM_SignInit_removed <= LibVersion then
    begin
      {$if declared(_PEM_SignInit)}
      PEM_SignInit := _PEM_SignInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_SignInit_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_SignInit');
    {$ifend}
  end;
  
  PEM_SignUpdate := LoadLibFunction(ADllHandle, PEM_SignUpdate_procname);
  FuncLoadError := not assigned(PEM_SignUpdate);
  if FuncLoadError then
  begin
    {$if not defined(PEM_SignUpdate_allownil)}
    PEM_SignUpdate := ERR_PEM_SignUpdate;
    {$ifend}
    {$if declared(PEM_SignUpdate_introduced)}
    if LibVersion < PEM_SignUpdate_introduced then
    begin
      {$if declared(FC_PEM_SignUpdate)}
      PEM_SignUpdate := FC_PEM_SignUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_SignUpdate_removed)}
    if PEM_SignUpdate_removed <= LibVersion then
    begin
      {$if declared(_PEM_SignUpdate)}
      PEM_SignUpdate := _PEM_SignUpdate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_SignUpdate_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_SignUpdate');
    {$ifend}
  end;
  
  PEM_SignFinal := LoadLibFunction(ADllHandle, PEM_SignFinal_procname);
  FuncLoadError := not assigned(PEM_SignFinal);
  if FuncLoadError then
  begin
    {$if not defined(PEM_SignFinal_allownil)}
    PEM_SignFinal := ERR_PEM_SignFinal;
    {$ifend}
    {$if declared(PEM_SignFinal_introduced)}
    if LibVersion < PEM_SignFinal_introduced then
    begin
      {$if declared(FC_PEM_SignFinal)}
      PEM_SignFinal := FC_PEM_SignFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_SignFinal_removed)}
    if PEM_SignFinal_removed <= LibVersion then
    begin
      {$if declared(_PEM_SignFinal)}
      PEM_SignFinal := _PEM_SignFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_SignFinal_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_SignFinal');
    {$ifend}
  end;
  
  PEM_def_callback := LoadLibFunction(ADllHandle, PEM_def_callback_procname);
  FuncLoadError := not assigned(PEM_def_callback);
  if FuncLoadError then
  begin
    {$if not defined(PEM_def_callback_allownil)}
    PEM_def_callback := ERR_PEM_def_callback;
    {$ifend}
    {$if declared(PEM_def_callback_introduced)}
    if LibVersion < PEM_def_callback_introduced then
    begin
      {$if declared(FC_PEM_def_callback)}
      PEM_def_callback := FC_PEM_def_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_def_callback_removed)}
    if PEM_def_callback_removed <= LibVersion then
    begin
      {$if declared(_PEM_def_callback)}
      PEM_def_callback := _PEM_def_callback;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_def_callback_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_def_callback');
    {$ifend}
  end;
  
  PEM_proc_type := LoadLibFunction(ADllHandle, PEM_proc_type_procname);
  FuncLoadError := not assigned(PEM_proc_type);
  if FuncLoadError then
  begin
    {$if not defined(PEM_proc_type_allownil)}
    PEM_proc_type := ERR_PEM_proc_type;
    {$ifend}
    {$if declared(PEM_proc_type_introduced)}
    if LibVersion < PEM_proc_type_introduced then
    begin
      {$if declared(FC_PEM_proc_type)}
      PEM_proc_type := FC_PEM_proc_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_proc_type_removed)}
    if PEM_proc_type_removed <= LibVersion then
    begin
      {$if declared(_PEM_proc_type)}
      PEM_proc_type := _PEM_proc_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_proc_type_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_proc_type');
    {$ifend}
  end;
  
  PEM_dek_info := LoadLibFunction(ADllHandle, PEM_dek_info_procname);
  FuncLoadError := not assigned(PEM_dek_info);
  if FuncLoadError then
  begin
    {$if not defined(PEM_dek_info_allownil)}
    PEM_dek_info := ERR_PEM_dek_info;
    {$ifend}
    {$if declared(PEM_dek_info_introduced)}
    if LibVersion < PEM_dek_info_introduced then
    begin
      {$if declared(FC_PEM_dek_info)}
      PEM_dek_info := FC_PEM_dek_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_dek_info_removed)}
    if PEM_dek_info_removed <= LibVersion then
    begin
      {$if declared(_PEM_dek_info)}
      PEM_dek_info := _PEM_dek_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_dek_info_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_dek_info');
    {$ifend}
  end;
  
  PEM_read_bio_X509 := LoadLibFunction(ADllHandle, PEM_read_bio_X509_procname);
  FuncLoadError := not assigned(PEM_read_bio_X509);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_X509_allownil)}
    PEM_read_bio_X509 := ERR_PEM_read_bio_X509;
    {$ifend}
    {$if declared(PEM_read_bio_X509_introduced)}
    if LibVersion < PEM_read_bio_X509_introduced then
    begin
      {$if declared(FC_PEM_read_bio_X509)}
      PEM_read_bio_X509 := FC_PEM_read_bio_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_X509_removed)}
    if PEM_read_bio_X509_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_X509)}
      PEM_read_bio_X509 := _PEM_read_bio_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_X509_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_X509');
    {$ifend}
  end;
  
  PEM_read_X509 := LoadLibFunction(ADllHandle, PEM_read_X509_procname);
  FuncLoadError := not assigned(PEM_read_X509);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_X509_allownil)}
    PEM_read_X509 := ERR_PEM_read_X509;
    {$ifend}
    {$if declared(PEM_read_X509_introduced)}
    if LibVersion < PEM_read_X509_introduced then
    begin
      {$if declared(FC_PEM_read_X509)}
      PEM_read_X509 := FC_PEM_read_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_X509_removed)}
    if PEM_read_X509_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_X509)}
      PEM_read_X509 := _PEM_read_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_X509_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_X509');
    {$ifend}
  end;
  
  PEM_write_bio_X509 := LoadLibFunction(ADllHandle, PEM_write_bio_X509_procname);
  FuncLoadError := not assigned(PEM_write_bio_X509);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_X509_allownil)}
    PEM_write_bio_X509 := ERR_PEM_write_bio_X509;
    {$ifend}
    {$if declared(PEM_write_bio_X509_introduced)}
    if LibVersion < PEM_write_bio_X509_introduced then
    begin
      {$if declared(FC_PEM_write_bio_X509)}
      PEM_write_bio_X509 := FC_PEM_write_bio_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_X509_removed)}
    if PEM_write_bio_X509_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_X509)}
      PEM_write_bio_X509 := _PEM_write_bio_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_X509_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_X509');
    {$ifend}
  end;
  
  PEM_write_X509 := LoadLibFunction(ADllHandle, PEM_write_X509_procname);
  FuncLoadError := not assigned(PEM_write_X509);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_X509_allownil)}
    PEM_write_X509 := ERR_PEM_write_X509;
    {$ifend}
    {$if declared(PEM_write_X509_introduced)}
    if LibVersion < PEM_write_X509_introduced then
    begin
      {$if declared(FC_PEM_write_X509)}
      PEM_write_X509 := FC_PEM_write_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_X509_removed)}
    if PEM_write_X509_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_X509)}
      PEM_write_X509 := _PEM_write_X509;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_X509_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_X509');
    {$ifend}
  end;
  
  PEM_read_bio_X509_AUX := LoadLibFunction(ADllHandle, PEM_read_bio_X509_AUX_procname);
  FuncLoadError := not assigned(PEM_read_bio_X509_AUX);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_X509_AUX_allownil)}
    PEM_read_bio_X509_AUX := ERR_PEM_read_bio_X509_AUX;
    {$ifend}
    {$if declared(PEM_read_bio_X509_AUX_introduced)}
    if LibVersion < PEM_read_bio_X509_AUX_introduced then
    begin
      {$if declared(FC_PEM_read_bio_X509_AUX)}
      PEM_read_bio_X509_AUX := FC_PEM_read_bio_X509_AUX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_X509_AUX_removed)}
    if PEM_read_bio_X509_AUX_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_X509_AUX)}
      PEM_read_bio_X509_AUX := _PEM_read_bio_X509_AUX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_X509_AUX_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_X509_AUX');
    {$ifend}
  end;
  
  PEM_read_X509_AUX := LoadLibFunction(ADllHandle, PEM_read_X509_AUX_procname);
  FuncLoadError := not assigned(PEM_read_X509_AUX);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_X509_AUX_allownil)}
    PEM_read_X509_AUX := ERR_PEM_read_X509_AUX;
    {$ifend}
    {$if declared(PEM_read_X509_AUX_introduced)}
    if LibVersion < PEM_read_X509_AUX_introduced then
    begin
      {$if declared(FC_PEM_read_X509_AUX)}
      PEM_read_X509_AUX := FC_PEM_read_X509_AUX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_X509_AUX_removed)}
    if PEM_read_X509_AUX_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_X509_AUX)}
      PEM_read_X509_AUX := _PEM_read_X509_AUX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_X509_AUX_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_X509_AUX');
    {$ifend}
  end;
  
  PEM_write_bio_X509_AUX := LoadLibFunction(ADllHandle, PEM_write_bio_X509_AUX_procname);
  FuncLoadError := not assigned(PEM_write_bio_X509_AUX);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_X509_AUX_allownil)}
    PEM_write_bio_X509_AUX := ERR_PEM_write_bio_X509_AUX;
    {$ifend}
    {$if declared(PEM_write_bio_X509_AUX_introduced)}
    if LibVersion < PEM_write_bio_X509_AUX_introduced then
    begin
      {$if declared(FC_PEM_write_bio_X509_AUX)}
      PEM_write_bio_X509_AUX := FC_PEM_write_bio_X509_AUX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_X509_AUX_removed)}
    if PEM_write_bio_X509_AUX_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_X509_AUX)}
      PEM_write_bio_X509_AUX := _PEM_write_bio_X509_AUX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_X509_AUX_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_X509_AUX');
    {$ifend}
  end;
  
  PEM_write_X509_AUX := LoadLibFunction(ADllHandle, PEM_write_X509_AUX_procname);
  FuncLoadError := not assigned(PEM_write_X509_AUX);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_X509_AUX_allownil)}
    PEM_write_X509_AUX := ERR_PEM_write_X509_AUX;
    {$ifend}
    {$if declared(PEM_write_X509_AUX_introduced)}
    if LibVersion < PEM_write_X509_AUX_introduced then
    begin
      {$if declared(FC_PEM_write_X509_AUX)}
      PEM_write_X509_AUX := FC_PEM_write_X509_AUX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_X509_AUX_removed)}
    if PEM_write_X509_AUX_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_X509_AUX)}
      PEM_write_X509_AUX := _PEM_write_X509_AUX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_X509_AUX_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_X509_AUX');
    {$ifend}
  end;
  
  PEM_read_bio_X509_REQ := LoadLibFunction(ADllHandle, PEM_read_bio_X509_REQ_procname);
  FuncLoadError := not assigned(PEM_read_bio_X509_REQ);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_X509_REQ_allownil)}
    PEM_read_bio_X509_REQ := ERR_PEM_read_bio_X509_REQ;
    {$ifend}
    {$if declared(PEM_read_bio_X509_REQ_introduced)}
    if LibVersion < PEM_read_bio_X509_REQ_introduced then
    begin
      {$if declared(FC_PEM_read_bio_X509_REQ)}
      PEM_read_bio_X509_REQ := FC_PEM_read_bio_X509_REQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_X509_REQ_removed)}
    if PEM_read_bio_X509_REQ_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_X509_REQ)}
      PEM_read_bio_X509_REQ := _PEM_read_bio_X509_REQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_X509_REQ_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_X509_REQ');
    {$ifend}
  end;
  
  PEM_read_X509_REQ := LoadLibFunction(ADllHandle, PEM_read_X509_REQ_procname);
  FuncLoadError := not assigned(PEM_read_X509_REQ);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_X509_REQ_allownil)}
    PEM_read_X509_REQ := ERR_PEM_read_X509_REQ;
    {$ifend}
    {$if declared(PEM_read_X509_REQ_introduced)}
    if LibVersion < PEM_read_X509_REQ_introduced then
    begin
      {$if declared(FC_PEM_read_X509_REQ)}
      PEM_read_X509_REQ := FC_PEM_read_X509_REQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_X509_REQ_removed)}
    if PEM_read_X509_REQ_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_X509_REQ)}
      PEM_read_X509_REQ := _PEM_read_X509_REQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_X509_REQ_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_X509_REQ');
    {$ifend}
  end;
  
  PEM_write_bio_X509_REQ := LoadLibFunction(ADllHandle, PEM_write_bio_X509_REQ_procname);
  FuncLoadError := not assigned(PEM_write_bio_X509_REQ);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_X509_REQ_allownil)}
    PEM_write_bio_X509_REQ := ERR_PEM_write_bio_X509_REQ;
    {$ifend}
    {$if declared(PEM_write_bio_X509_REQ_introduced)}
    if LibVersion < PEM_write_bio_X509_REQ_introduced then
    begin
      {$if declared(FC_PEM_write_bio_X509_REQ)}
      PEM_write_bio_X509_REQ := FC_PEM_write_bio_X509_REQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_X509_REQ_removed)}
    if PEM_write_bio_X509_REQ_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_X509_REQ)}
      PEM_write_bio_X509_REQ := _PEM_write_bio_X509_REQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_X509_REQ_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_X509_REQ');
    {$ifend}
  end;
  
  PEM_write_X509_REQ := LoadLibFunction(ADllHandle, PEM_write_X509_REQ_procname);
  FuncLoadError := not assigned(PEM_write_X509_REQ);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_X509_REQ_allownil)}
    PEM_write_X509_REQ := ERR_PEM_write_X509_REQ;
    {$ifend}
    {$if declared(PEM_write_X509_REQ_introduced)}
    if LibVersion < PEM_write_X509_REQ_introduced then
    begin
      {$if declared(FC_PEM_write_X509_REQ)}
      PEM_write_X509_REQ := FC_PEM_write_X509_REQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_X509_REQ_removed)}
    if PEM_write_X509_REQ_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_X509_REQ)}
      PEM_write_X509_REQ := _PEM_write_X509_REQ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_X509_REQ_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_X509_REQ');
    {$ifend}
  end;
  
  PEM_write_bio_X509_REQ_NEW := LoadLibFunction(ADllHandle, PEM_write_bio_X509_REQ_NEW_procname);
  FuncLoadError := not assigned(PEM_write_bio_X509_REQ_NEW);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_X509_REQ_NEW_allownil)}
    PEM_write_bio_X509_REQ_NEW := ERR_PEM_write_bio_X509_REQ_NEW;
    {$ifend}
    {$if declared(PEM_write_bio_X509_REQ_NEW_introduced)}
    if LibVersion < PEM_write_bio_X509_REQ_NEW_introduced then
    begin
      {$if declared(FC_PEM_write_bio_X509_REQ_NEW)}
      PEM_write_bio_X509_REQ_NEW := FC_PEM_write_bio_X509_REQ_NEW;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_X509_REQ_NEW_removed)}
    if PEM_write_bio_X509_REQ_NEW_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_X509_REQ_NEW)}
      PEM_write_bio_X509_REQ_NEW := _PEM_write_bio_X509_REQ_NEW;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_X509_REQ_NEW_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_X509_REQ_NEW');
    {$ifend}
  end;
  
  PEM_write_X509_REQ_NEW := LoadLibFunction(ADllHandle, PEM_write_X509_REQ_NEW_procname);
  FuncLoadError := not assigned(PEM_write_X509_REQ_NEW);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_X509_REQ_NEW_allownil)}
    PEM_write_X509_REQ_NEW := ERR_PEM_write_X509_REQ_NEW;
    {$ifend}
    {$if declared(PEM_write_X509_REQ_NEW_introduced)}
    if LibVersion < PEM_write_X509_REQ_NEW_introduced then
    begin
      {$if declared(FC_PEM_write_X509_REQ_NEW)}
      PEM_write_X509_REQ_NEW := FC_PEM_write_X509_REQ_NEW;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_X509_REQ_NEW_removed)}
    if PEM_write_X509_REQ_NEW_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_X509_REQ_NEW)}
      PEM_write_X509_REQ_NEW := _PEM_write_X509_REQ_NEW;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_X509_REQ_NEW_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_X509_REQ_NEW');
    {$ifend}
  end;
  
  PEM_read_bio_X509_CRL := LoadLibFunction(ADllHandle, PEM_read_bio_X509_CRL_procname);
  FuncLoadError := not assigned(PEM_read_bio_X509_CRL);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_X509_CRL_allownil)}
    PEM_read_bio_X509_CRL := ERR_PEM_read_bio_X509_CRL;
    {$ifend}
    {$if declared(PEM_read_bio_X509_CRL_introduced)}
    if LibVersion < PEM_read_bio_X509_CRL_introduced then
    begin
      {$if declared(FC_PEM_read_bio_X509_CRL)}
      PEM_read_bio_X509_CRL := FC_PEM_read_bio_X509_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_X509_CRL_removed)}
    if PEM_read_bio_X509_CRL_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_X509_CRL)}
      PEM_read_bio_X509_CRL := _PEM_read_bio_X509_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_X509_CRL_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_X509_CRL');
    {$ifend}
  end;
  
  PEM_read_X509_CRL := LoadLibFunction(ADllHandle, PEM_read_X509_CRL_procname);
  FuncLoadError := not assigned(PEM_read_X509_CRL);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_X509_CRL_allownil)}
    PEM_read_X509_CRL := ERR_PEM_read_X509_CRL;
    {$ifend}
    {$if declared(PEM_read_X509_CRL_introduced)}
    if LibVersion < PEM_read_X509_CRL_introduced then
    begin
      {$if declared(FC_PEM_read_X509_CRL)}
      PEM_read_X509_CRL := FC_PEM_read_X509_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_X509_CRL_removed)}
    if PEM_read_X509_CRL_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_X509_CRL)}
      PEM_read_X509_CRL := _PEM_read_X509_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_X509_CRL_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_X509_CRL');
    {$ifend}
  end;
  
  PEM_write_bio_X509_CRL := LoadLibFunction(ADllHandle, PEM_write_bio_X509_CRL_procname);
  FuncLoadError := not assigned(PEM_write_bio_X509_CRL);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_X509_CRL_allownil)}
    PEM_write_bio_X509_CRL := ERR_PEM_write_bio_X509_CRL;
    {$ifend}
    {$if declared(PEM_write_bio_X509_CRL_introduced)}
    if LibVersion < PEM_write_bio_X509_CRL_introduced then
    begin
      {$if declared(FC_PEM_write_bio_X509_CRL)}
      PEM_write_bio_X509_CRL := FC_PEM_write_bio_X509_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_X509_CRL_removed)}
    if PEM_write_bio_X509_CRL_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_X509_CRL)}
      PEM_write_bio_X509_CRL := _PEM_write_bio_X509_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_X509_CRL_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_X509_CRL');
    {$ifend}
  end;
  
  PEM_write_X509_CRL := LoadLibFunction(ADllHandle, PEM_write_X509_CRL_procname);
  FuncLoadError := not assigned(PEM_write_X509_CRL);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_X509_CRL_allownil)}
    PEM_write_X509_CRL := ERR_PEM_write_X509_CRL;
    {$ifend}
    {$if declared(PEM_write_X509_CRL_introduced)}
    if LibVersion < PEM_write_X509_CRL_introduced then
    begin
      {$if declared(FC_PEM_write_X509_CRL)}
      PEM_write_X509_CRL := FC_PEM_write_X509_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_X509_CRL_removed)}
    if PEM_write_X509_CRL_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_X509_CRL)}
      PEM_write_X509_CRL := _PEM_write_X509_CRL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_X509_CRL_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_X509_CRL');
    {$ifend}
  end;
  
  PEM_read_bio_X509_PUBKEY := LoadLibFunction(ADllHandle, PEM_read_bio_X509_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_read_bio_X509_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_X509_PUBKEY_allownil)}
    PEM_read_bio_X509_PUBKEY := ERR_PEM_read_bio_X509_PUBKEY;
    {$ifend}
    {$if declared(PEM_read_bio_X509_PUBKEY_introduced)}
    if LibVersion < PEM_read_bio_X509_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_read_bio_X509_PUBKEY)}
      PEM_read_bio_X509_PUBKEY := FC_PEM_read_bio_X509_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_X509_PUBKEY_removed)}
    if PEM_read_bio_X509_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_X509_PUBKEY)}
      PEM_read_bio_X509_PUBKEY := _PEM_read_bio_X509_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_X509_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_X509_PUBKEY');
    {$ifend}
  end;
  
  PEM_read_X509_PUBKEY := LoadLibFunction(ADllHandle, PEM_read_X509_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_read_X509_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_X509_PUBKEY_allownil)}
    PEM_read_X509_PUBKEY := ERR_PEM_read_X509_PUBKEY;
    {$ifend}
    {$if declared(PEM_read_X509_PUBKEY_introduced)}
    if LibVersion < PEM_read_X509_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_read_X509_PUBKEY)}
      PEM_read_X509_PUBKEY := FC_PEM_read_X509_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_X509_PUBKEY_removed)}
    if PEM_read_X509_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_X509_PUBKEY)}
      PEM_read_X509_PUBKEY := _PEM_read_X509_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_X509_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_X509_PUBKEY');
    {$ifend}
  end;
  
  PEM_write_bio_X509_PUBKEY := LoadLibFunction(ADllHandle, PEM_write_bio_X509_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_write_bio_X509_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_X509_PUBKEY_allownil)}
    PEM_write_bio_X509_PUBKEY := ERR_PEM_write_bio_X509_PUBKEY;
    {$ifend}
    {$if declared(PEM_write_bio_X509_PUBKEY_introduced)}
    if LibVersion < PEM_write_bio_X509_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_write_bio_X509_PUBKEY)}
      PEM_write_bio_X509_PUBKEY := FC_PEM_write_bio_X509_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_X509_PUBKEY_removed)}
    if PEM_write_bio_X509_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_X509_PUBKEY)}
      PEM_write_bio_X509_PUBKEY := _PEM_write_bio_X509_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_X509_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_X509_PUBKEY');
    {$ifend}
  end;
  
  PEM_write_X509_PUBKEY := LoadLibFunction(ADllHandle, PEM_write_X509_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_write_X509_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_X509_PUBKEY_allownil)}
    PEM_write_X509_PUBKEY := ERR_PEM_write_X509_PUBKEY;
    {$ifend}
    {$if declared(PEM_write_X509_PUBKEY_introduced)}
    if LibVersion < PEM_write_X509_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_write_X509_PUBKEY)}
      PEM_write_X509_PUBKEY := FC_PEM_write_X509_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_X509_PUBKEY_removed)}
    if PEM_write_X509_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_X509_PUBKEY)}
      PEM_write_X509_PUBKEY := _PEM_write_X509_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_X509_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_X509_PUBKEY');
    {$ifend}
  end;
  
  PEM_read_bio_PKCS7 := LoadLibFunction(ADllHandle, PEM_read_bio_PKCS7_procname);
  FuncLoadError := not assigned(PEM_read_bio_PKCS7);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_PKCS7_allownil)}
    PEM_read_bio_PKCS7 := ERR_PEM_read_bio_PKCS7;
    {$ifend}
    {$if declared(PEM_read_bio_PKCS7_introduced)}
    if LibVersion < PEM_read_bio_PKCS7_introduced then
    begin
      {$if declared(FC_PEM_read_bio_PKCS7)}
      PEM_read_bio_PKCS7 := FC_PEM_read_bio_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_PKCS7_removed)}
    if PEM_read_bio_PKCS7_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_PKCS7)}
      PEM_read_bio_PKCS7 := _PEM_read_bio_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_PKCS7_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_PKCS7');
    {$ifend}
  end;
  
  PEM_read_PKCS7 := LoadLibFunction(ADllHandle, PEM_read_PKCS7_procname);
  FuncLoadError := not assigned(PEM_read_PKCS7);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_PKCS7_allownil)}
    PEM_read_PKCS7 := ERR_PEM_read_PKCS7;
    {$ifend}
    {$if declared(PEM_read_PKCS7_introduced)}
    if LibVersion < PEM_read_PKCS7_introduced then
    begin
      {$if declared(FC_PEM_read_PKCS7)}
      PEM_read_PKCS7 := FC_PEM_read_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_PKCS7_removed)}
    if PEM_read_PKCS7_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_PKCS7)}
      PEM_read_PKCS7 := _PEM_read_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_PKCS7_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_PKCS7');
    {$ifend}
  end;
  
  PEM_write_bio_PKCS7 := LoadLibFunction(ADllHandle, PEM_write_bio_PKCS7_procname);
  FuncLoadError := not assigned(PEM_write_bio_PKCS7);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_PKCS7_allownil)}
    PEM_write_bio_PKCS7 := ERR_PEM_write_bio_PKCS7;
    {$ifend}
    {$if declared(PEM_write_bio_PKCS7_introduced)}
    if LibVersion < PEM_write_bio_PKCS7_introduced then
    begin
      {$if declared(FC_PEM_write_bio_PKCS7)}
      PEM_write_bio_PKCS7 := FC_PEM_write_bio_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_PKCS7_removed)}
    if PEM_write_bio_PKCS7_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_PKCS7)}
      PEM_write_bio_PKCS7 := _PEM_write_bio_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_PKCS7_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_PKCS7');
    {$ifend}
  end;
  
  PEM_write_PKCS7 := LoadLibFunction(ADllHandle, PEM_write_PKCS7_procname);
  FuncLoadError := not assigned(PEM_write_PKCS7);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_PKCS7_allownil)}
    PEM_write_PKCS7 := ERR_PEM_write_PKCS7;
    {$ifend}
    {$if declared(PEM_write_PKCS7_introduced)}
    if LibVersion < PEM_write_PKCS7_introduced then
    begin
      {$if declared(FC_PEM_write_PKCS7)}
      PEM_write_PKCS7 := FC_PEM_write_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_PKCS7_removed)}
    if PEM_write_PKCS7_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_PKCS7)}
      PEM_write_PKCS7 := _PEM_write_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_PKCS7_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_PKCS7');
    {$ifend}
  end;
  
  PEM_read_bio_NETSCAPE_CERT_SEQUENCE := LoadLibFunction(ADllHandle, PEM_read_bio_NETSCAPE_CERT_SEQUENCE_procname);
  FuncLoadError := not assigned(PEM_read_bio_NETSCAPE_CERT_SEQUENCE);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_NETSCAPE_CERT_SEQUENCE_allownil)}
    PEM_read_bio_NETSCAPE_CERT_SEQUENCE := ERR_PEM_read_bio_NETSCAPE_CERT_SEQUENCE;
    {$ifend}
    {$if declared(PEM_read_bio_NETSCAPE_CERT_SEQUENCE_introduced)}
    if LibVersion < PEM_read_bio_NETSCAPE_CERT_SEQUENCE_introduced then
    begin
      {$if declared(FC_PEM_read_bio_NETSCAPE_CERT_SEQUENCE)}
      PEM_read_bio_NETSCAPE_CERT_SEQUENCE := FC_PEM_read_bio_NETSCAPE_CERT_SEQUENCE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_NETSCAPE_CERT_SEQUENCE_removed)}
    if PEM_read_bio_NETSCAPE_CERT_SEQUENCE_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_NETSCAPE_CERT_SEQUENCE)}
      PEM_read_bio_NETSCAPE_CERT_SEQUENCE := _PEM_read_bio_NETSCAPE_CERT_SEQUENCE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_NETSCAPE_CERT_SEQUENCE_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_NETSCAPE_CERT_SEQUENCE');
    {$ifend}
  end;
  
  PEM_read_NETSCAPE_CERT_SEQUENCE := LoadLibFunction(ADllHandle, PEM_read_NETSCAPE_CERT_SEQUENCE_procname);
  FuncLoadError := not assigned(PEM_read_NETSCAPE_CERT_SEQUENCE);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_NETSCAPE_CERT_SEQUENCE_allownil)}
    PEM_read_NETSCAPE_CERT_SEQUENCE := ERR_PEM_read_NETSCAPE_CERT_SEQUENCE;
    {$ifend}
    {$if declared(PEM_read_NETSCAPE_CERT_SEQUENCE_introduced)}
    if LibVersion < PEM_read_NETSCAPE_CERT_SEQUENCE_introduced then
    begin
      {$if declared(FC_PEM_read_NETSCAPE_CERT_SEQUENCE)}
      PEM_read_NETSCAPE_CERT_SEQUENCE := FC_PEM_read_NETSCAPE_CERT_SEQUENCE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_NETSCAPE_CERT_SEQUENCE_removed)}
    if PEM_read_NETSCAPE_CERT_SEQUENCE_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_NETSCAPE_CERT_SEQUENCE)}
      PEM_read_NETSCAPE_CERT_SEQUENCE := _PEM_read_NETSCAPE_CERT_SEQUENCE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_NETSCAPE_CERT_SEQUENCE_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_NETSCAPE_CERT_SEQUENCE');
    {$ifend}
  end;
  
  PEM_write_bio_NETSCAPE_CERT_SEQUENCE := LoadLibFunction(ADllHandle, PEM_write_bio_NETSCAPE_CERT_SEQUENCE_procname);
  FuncLoadError := not assigned(PEM_write_bio_NETSCAPE_CERT_SEQUENCE);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_NETSCAPE_CERT_SEQUENCE_allownil)}
    PEM_write_bio_NETSCAPE_CERT_SEQUENCE := ERR_PEM_write_bio_NETSCAPE_CERT_SEQUENCE;
    {$ifend}
    {$if declared(PEM_write_bio_NETSCAPE_CERT_SEQUENCE_introduced)}
    if LibVersion < PEM_write_bio_NETSCAPE_CERT_SEQUENCE_introduced then
    begin
      {$if declared(FC_PEM_write_bio_NETSCAPE_CERT_SEQUENCE)}
      PEM_write_bio_NETSCAPE_CERT_SEQUENCE := FC_PEM_write_bio_NETSCAPE_CERT_SEQUENCE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_NETSCAPE_CERT_SEQUENCE_removed)}
    if PEM_write_bio_NETSCAPE_CERT_SEQUENCE_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_NETSCAPE_CERT_SEQUENCE)}
      PEM_write_bio_NETSCAPE_CERT_SEQUENCE := _PEM_write_bio_NETSCAPE_CERT_SEQUENCE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_NETSCAPE_CERT_SEQUENCE_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_NETSCAPE_CERT_SEQUENCE');
    {$ifend}
  end;
  
  PEM_write_NETSCAPE_CERT_SEQUENCE := LoadLibFunction(ADllHandle, PEM_write_NETSCAPE_CERT_SEQUENCE_procname);
  FuncLoadError := not assigned(PEM_write_NETSCAPE_CERT_SEQUENCE);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_NETSCAPE_CERT_SEQUENCE_allownil)}
    PEM_write_NETSCAPE_CERT_SEQUENCE := ERR_PEM_write_NETSCAPE_CERT_SEQUENCE;
    {$ifend}
    {$if declared(PEM_write_NETSCAPE_CERT_SEQUENCE_introduced)}
    if LibVersion < PEM_write_NETSCAPE_CERT_SEQUENCE_introduced then
    begin
      {$if declared(FC_PEM_write_NETSCAPE_CERT_SEQUENCE)}
      PEM_write_NETSCAPE_CERT_SEQUENCE := FC_PEM_write_NETSCAPE_CERT_SEQUENCE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_NETSCAPE_CERT_SEQUENCE_removed)}
    if PEM_write_NETSCAPE_CERT_SEQUENCE_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_NETSCAPE_CERT_SEQUENCE)}
      PEM_write_NETSCAPE_CERT_SEQUENCE := _PEM_write_NETSCAPE_CERT_SEQUENCE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_NETSCAPE_CERT_SEQUENCE_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_NETSCAPE_CERT_SEQUENCE');
    {$ifend}
  end;
  
  PEM_read_bio_PKCS8 := LoadLibFunction(ADllHandle, PEM_read_bio_PKCS8_procname);
  FuncLoadError := not assigned(PEM_read_bio_PKCS8);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_PKCS8_allownil)}
    PEM_read_bio_PKCS8 := ERR_PEM_read_bio_PKCS8;
    {$ifend}
    {$if declared(PEM_read_bio_PKCS8_introduced)}
    if LibVersion < PEM_read_bio_PKCS8_introduced then
    begin
      {$if declared(FC_PEM_read_bio_PKCS8)}
      PEM_read_bio_PKCS8 := FC_PEM_read_bio_PKCS8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_PKCS8_removed)}
    if PEM_read_bio_PKCS8_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_PKCS8)}
      PEM_read_bio_PKCS8 := _PEM_read_bio_PKCS8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_PKCS8_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_PKCS8');
    {$ifend}
  end;
  
  PEM_read_PKCS8 := LoadLibFunction(ADllHandle, PEM_read_PKCS8_procname);
  FuncLoadError := not assigned(PEM_read_PKCS8);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_PKCS8_allownil)}
    PEM_read_PKCS8 := ERR_PEM_read_PKCS8;
    {$ifend}
    {$if declared(PEM_read_PKCS8_introduced)}
    if LibVersion < PEM_read_PKCS8_introduced then
    begin
      {$if declared(FC_PEM_read_PKCS8)}
      PEM_read_PKCS8 := FC_PEM_read_PKCS8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_PKCS8_removed)}
    if PEM_read_PKCS8_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_PKCS8)}
      PEM_read_PKCS8 := _PEM_read_PKCS8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_PKCS8_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_PKCS8');
    {$ifend}
  end;
  
  PEM_write_bio_PKCS8 := LoadLibFunction(ADllHandle, PEM_write_bio_PKCS8_procname);
  FuncLoadError := not assigned(PEM_write_bio_PKCS8);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_PKCS8_allownil)}
    PEM_write_bio_PKCS8 := ERR_PEM_write_bio_PKCS8;
    {$ifend}
    {$if declared(PEM_write_bio_PKCS8_introduced)}
    if LibVersion < PEM_write_bio_PKCS8_introduced then
    begin
      {$if declared(FC_PEM_write_bio_PKCS8)}
      PEM_write_bio_PKCS8 := FC_PEM_write_bio_PKCS8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_PKCS8_removed)}
    if PEM_write_bio_PKCS8_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_PKCS8)}
      PEM_write_bio_PKCS8 := _PEM_write_bio_PKCS8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_PKCS8_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_PKCS8');
    {$ifend}
  end;
  
  PEM_write_PKCS8 := LoadLibFunction(ADllHandle, PEM_write_PKCS8_procname);
  FuncLoadError := not assigned(PEM_write_PKCS8);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_PKCS8_allownil)}
    PEM_write_PKCS8 := ERR_PEM_write_PKCS8;
    {$ifend}
    {$if declared(PEM_write_PKCS8_introduced)}
    if LibVersion < PEM_write_PKCS8_introduced then
    begin
      {$if declared(FC_PEM_write_PKCS8)}
      PEM_write_PKCS8 := FC_PEM_write_PKCS8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_PKCS8_removed)}
    if PEM_write_PKCS8_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_PKCS8)}
      PEM_write_PKCS8 := _PEM_write_PKCS8;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_PKCS8_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_PKCS8');
    {$ifend}
  end;
  
  PEM_read_bio_PKCS8_PRIV_KEY_INFO := LoadLibFunction(ADllHandle, PEM_read_bio_PKCS8_PRIV_KEY_INFO_procname);
  FuncLoadError := not assigned(PEM_read_bio_PKCS8_PRIV_KEY_INFO);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_PKCS8_PRIV_KEY_INFO_allownil)}
    PEM_read_bio_PKCS8_PRIV_KEY_INFO := ERR_PEM_read_bio_PKCS8_PRIV_KEY_INFO;
    {$ifend}
    {$if declared(PEM_read_bio_PKCS8_PRIV_KEY_INFO_introduced)}
    if LibVersion < PEM_read_bio_PKCS8_PRIV_KEY_INFO_introduced then
    begin
      {$if declared(FC_PEM_read_bio_PKCS8_PRIV_KEY_INFO)}
      PEM_read_bio_PKCS8_PRIV_KEY_INFO := FC_PEM_read_bio_PKCS8_PRIV_KEY_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_PKCS8_PRIV_KEY_INFO_removed)}
    if PEM_read_bio_PKCS8_PRIV_KEY_INFO_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_PKCS8_PRIV_KEY_INFO)}
      PEM_read_bio_PKCS8_PRIV_KEY_INFO := _PEM_read_bio_PKCS8_PRIV_KEY_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_PKCS8_PRIV_KEY_INFO_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_PKCS8_PRIV_KEY_INFO');
    {$ifend}
  end;
  
  PEM_read_PKCS8_PRIV_KEY_INFO := LoadLibFunction(ADllHandle, PEM_read_PKCS8_PRIV_KEY_INFO_procname);
  FuncLoadError := not assigned(PEM_read_PKCS8_PRIV_KEY_INFO);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_PKCS8_PRIV_KEY_INFO_allownil)}
    PEM_read_PKCS8_PRIV_KEY_INFO := ERR_PEM_read_PKCS8_PRIV_KEY_INFO;
    {$ifend}
    {$if declared(PEM_read_PKCS8_PRIV_KEY_INFO_introduced)}
    if LibVersion < PEM_read_PKCS8_PRIV_KEY_INFO_introduced then
    begin
      {$if declared(FC_PEM_read_PKCS8_PRIV_KEY_INFO)}
      PEM_read_PKCS8_PRIV_KEY_INFO := FC_PEM_read_PKCS8_PRIV_KEY_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_PKCS8_PRIV_KEY_INFO_removed)}
    if PEM_read_PKCS8_PRIV_KEY_INFO_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_PKCS8_PRIV_KEY_INFO)}
      PEM_read_PKCS8_PRIV_KEY_INFO := _PEM_read_PKCS8_PRIV_KEY_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_PKCS8_PRIV_KEY_INFO_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_PKCS8_PRIV_KEY_INFO');
    {$ifend}
  end;
  
  PEM_write_bio_PKCS8_PRIV_KEY_INFO := LoadLibFunction(ADllHandle, PEM_write_bio_PKCS8_PRIV_KEY_INFO_procname);
  FuncLoadError := not assigned(PEM_write_bio_PKCS8_PRIV_KEY_INFO);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_PKCS8_PRIV_KEY_INFO_allownil)}
    PEM_write_bio_PKCS8_PRIV_KEY_INFO := ERR_PEM_write_bio_PKCS8_PRIV_KEY_INFO;
    {$ifend}
    {$if declared(PEM_write_bio_PKCS8_PRIV_KEY_INFO_introduced)}
    if LibVersion < PEM_write_bio_PKCS8_PRIV_KEY_INFO_introduced then
    begin
      {$if declared(FC_PEM_write_bio_PKCS8_PRIV_KEY_INFO)}
      PEM_write_bio_PKCS8_PRIV_KEY_INFO := FC_PEM_write_bio_PKCS8_PRIV_KEY_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_PKCS8_PRIV_KEY_INFO_removed)}
    if PEM_write_bio_PKCS8_PRIV_KEY_INFO_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_PKCS8_PRIV_KEY_INFO)}
      PEM_write_bio_PKCS8_PRIV_KEY_INFO := _PEM_write_bio_PKCS8_PRIV_KEY_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_PKCS8_PRIV_KEY_INFO_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_PKCS8_PRIV_KEY_INFO');
    {$ifend}
  end;
  
  PEM_write_PKCS8_PRIV_KEY_INFO := LoadLibFunction(ADllHandle, PEM_write_PKCS8_PRIV_KEY_INFO_procname);
  FuncLoadError := not assigned(PEM_write_PKCS8_PRIV_KEY_INFO);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_PKCS8_PRIV_KEY_INFO_allownil)}
    PEM_write_PKCS8_PRIV_KEY_INFO := ERR_PEM_write_PKCS8_PRIV_KEY_INFO;
    {$ifend}
    {$if declared(PEM_write_PKCS8_PRIV_KEY_INFO_introduced)}
    if LibVersion < PEM_write_PKCS8_PRIV_KEY_INFO_introduced then
    begin
      {$if declared(FC_PEM_write_PKCS8_PRIV_KEY_INFO)}
      PEM_write_PKCS8_PRIV_KEY_INFO := FC_PEM_write_PKCS8_PRIV_KEY_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_PKCS8_PRIV_KEY_INFO_removed)}
    if PEM_write_PKCS8_PRIV_KEY_INFO_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_PKCS8_PRIV_KEY_INFO)}
      PEM_write_PKCS8_PRIV_KEY_INFO := _PEM_write_PKCS8_PRIV_KEY_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_PKCS8_PRIV_KEY_INFO_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_PKCS8_PRIV_KEY_INFO');
    {$ifend}
  end;
  
  PEM_read_bio_RSAPrivateKey := LoadLibFunction(ADllHandle, PEM_read_bio_RSAPrivateKey_procname);
  FuncLoadError := not assigned(PEM_read_bio_RSAPrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_RSAPrivateKey_allownil)}
    PEM_read_bio_RSAPrivateKey := ERR_PEM_read_bio_RSAPrivateKey;
    {$ifend}
    {$if declared(PEM_read_bio_RSAPrivateKey_introduced)}
    if LibVersion < PEM_read_bio_RSAPrivateKey_introduced then
    begin
      {$if declared(FC_PEM_read_bio_RSAPrivateKey)}
      PEM_read_bio_RSAPrivateKey := FC_PEM_read_bio_RSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_RSAPrivateKey_removed)}
    if PEM_read_bio_RSAPrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_RSAPrivateKey)}
      PEM_read_bio_RSAPrivateKey := _PEM_read_bio_RSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_RSAPrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_RSAPrivateKey');
    {$ifend}
  end;
  
  PEM_read_RSAPrivateKey := LoadLibFunction(ADllHandle, PEM_read_RSAPrivateKey_procname);
  FuncLoadError := not assigned(PEM_read_RSAPrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_RSAPrivateKey_allownil)}
    PEM_read_RSAPrivateKey := ERR_PEM_read_RSAPrivateKey;
    {$ifend}
    {$if declared(PEM_read_RSAPrivateKey_introduced)}
    if LibVersion < PEM_read_RSAPrivateKey_introduced then
    begin
      {$if declared(FC_PEM_read_RSAPrivateKey)}
      PEM_read_RSAPrivateKey := FC_PEM_read_RSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_RSAPrivateKey_removed)}
    if PEM_read_RSAPrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_RSAPrivateKey)}
      PEM_read_RSAPrivateKey := _PEM_read_RSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_RSAPrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_RSAPrivateKey');
    {$ifend}
  end;
  
  PEM_write_bio_RSAPrivateKey := LoadLibFunction(ADllHandle, PEM_write_bio_RSAPrivateKey_procname);
  FuncLoadError := not assigned(PEM_write_bio_RSAPrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_RSAPrivateKey_allownil)}
    PEM_write_bio_RSAPrivateKey := ERR_PEM_write_bio_RSAPrivateKey;
    {$ifend}
    {$if declared(PEM_write_bio_RSAPrivateKey_introduced)}
    if LibVersion < PEM_write_bio_RSAPrivateKey_introduced then
    begin
      {$if declared(FC_PEM_write_bio_RSAPrivateKey)}
      PEM_write_bio_RSAPrivateKey := FC_PEM_write_bio_RSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_RSAPrivateKey_removed)}
    if PEM_write_bio_RSAPrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_RSAPrivateKey)}
      PEM_write_bio_RSAPrivateKey := _PEM_write_bio_RSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_RSAPrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_RSAPrivateKey');
    {$ifend}
  end;
  
  PEM_write_RSAPrivateKey := LoadLibFunction(ADllHandle, PEM_write_RSAPrivateKey_procname);
  FuncLoadError := not assigned(PEM_write_RSAPrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_RSAPrivateKey_allownil)}
    PEM_write_RSAPrivateKey := ERR_PEM_write_RSAPrivateKey;
    {$ifend}
    {$if declared(PEM_write_RSAPrivateKey_introduced)}
    if LibVersion < PEM_write_RSAPrivateKey_introduced then
    begin
      {$if declared(FC_PEM_write_RSAPrivateKey)}
      PEM_write_RSAPrivateKey := FC_PEM_write_RSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_RSAPrivateKey_removed)}
    if PEM_write_RSAPrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_RSAPrivateKey)}
      PEM_write_RSAPrivateKey := _PEM_write_RSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_RSAPrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_RSAPrivateKey');
    {$ifend}
  end;
  
  PEM_read_bio_RSAPublicKey := LoadLibFunction(ADllHandle, PEM_read_bio_RSAPublicKey_procname);
  FuncLoadError := not assigned(PEM_read_bio_RSAPublicKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_RSAPublicKey_allownil)}
    PEM_read_bio_RSAPublicKey := ERR_PEM_read_bio_RSAPublicKey;
    {$ifend}
    {$if declared(PEM_read_bio_RSAPublicKey_introduced)}
    if LibVersion < PEM_read_bio_RSAPublicKey_introduced then
    begin
      {$if declared(FC_PEM_read_bio_RSAPublicKey)}
      PEM_read_bio_RSAPublicKey := FC_PEM_read_bio_RSAPublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_RSAPublicKey_removed)}
    if PEM_read_bio_RSAPublicKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_RSAPublicKey)}
      PEM_read_bio_RSAPublicKey := _PEM_read_bio_RSAPublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_RSAPublicKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_RSAPublicKey');
    {$ifend}
  end;
  
  PEM_read_RSAPublicKey := LoadLibFunction(ADllHandle, PEM_read_RSAPublicKey_procname);
  FuncLoadError := not assigned(PEM_read_RSAPublicKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_RSAPublicKey_allownil)}
    PEM_read_RSAPublicKey := ERR_PEM_read_RSAPublicKey;
    {$ifend}
    {$if declared(PEM_read_RSAPublicKey_introduced)}
    if LibVersion < PEM_read_RSAPublicKey_introduced then
    begin
      {$if declared(FC_PEM_read_RSAPublicKey)}
      PEM_read_RSAPublicKey := FC_PEM_read_RSAPublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_RSAPublicKey_removed)}
    if PEM_read_RSAPublicKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_RSAPublicKey)}
      PEM_read_RSAPublicKey := _PEM_read_RSAPublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_RSAPublicKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_RSAPublicKey');
    {$ifend}
  end;
  
  PEM_write_bio_RSAPublicKey := LoadLibFunction(ADllHandle, PEM_write_bio_RSAPublicKey_procname);
  FuncLoadError := not assigned(PEM_write_bio_RSAPublicKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_RSAPublicKey_allownil)}
    PEM_write_bio_RSAPublicKey := ERR_PEM_write_bio_RSAPublicKey;
    {$ifend}
    {$if declared(PEM_write_bio_RSAPublicKey_introduced)}
    if LibVersion < PEM_write_bio_RSAPublicKey_introduced then
    begin
      {$if declared(FC_PEM_write_bio_RSAPublicKey)}
      PEM_write_bio_RSAPublicKey := FC_PEM_write_bio_RSAPublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_RSAPublicKey_removed)}
    if PEM_write_bio_RSAPublicKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_RSAPublicKey)}
      PEM_write_bio_RSAPublicKey := _PEM_write_bio_RSAPublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_RSAPublicKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_RSAPublicKey');
    {$ifend}
  end;
  
  PEM_write_RSAPublicKey := LoadLibFunction(ADllHandle, PEM_write_RSAPublicKey_procname);
  FuncLoadError := not assigned(PEM_write_RSAPublicKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_RSAPublicKey_allownil)}
    PEM_write_RSAPublicKey := ERR_PEM_write_RSAPublicKey;
    {$ifend}
    {$if declared(PEM_write_RSAPublicKey_introduced)}
    if LibVersion < PEM_write_RSAPublicKey_introduced then
    begin
      {$if declared(FC_PEM_write_RSAPublicKey)}
      PEM_write_RSAPublicKey := FC_PEM_write_RSAPublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_RSAPublicKey_removed)}
    if PEM_write_RSAPublicKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_RSAPublicKey)}
      PEM_write_RSAPublicKey := _PEM_write_RSAPublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_RSAPublicKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_RSAPublicKey');
    {$ifend}
  end;
  
  PEM_read_bio_RSA_PUBKEY := LoadLibFunction(ADllHandle, PEM_read_bio_RSA_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_read_bio_RSA_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_RSA_PUBKEY_allownil)}
    PEM_read_bio_RSA_PUBKEY := ERR_PEM_read_bio_RSA_PUBKEY;
    {$ifend}
    {$if declared(PEM_read_bio_RSA_PUBKEY_introduced)}
    if LibVersion < PEM_read_bio_RSA_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_read_bio_RSA_PUBKEY)}
      PEM_read_bio_RSA_PUBKEY := FC_PEM_read_bio_RSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_RSA_PUBKEY_removed)}
    if PEM_read_bio_RSA_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_RSA_PUBKEY)}
      PEM_read_bio_RSA_PUBKEY := _PEM_read_bio_RSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_RSA_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_RSA_PUBKEY');
    {$ifend}
  end;
  
  PEM_read_RSA_PUBKEY := LoadLibFunction(ADllHandle, PEM_read_RSA_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_read_RSA_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_RSA_PUBKEY_allownil)}
    PEM_read_RSA_PUBKEY := ERR_PEM_read_RSA_PUBKEY;
    {$ifend}
    {$if declared(PEM_read_RSA_PUBKEY_introduced)}
    if LibVersion < PEM_read_RSA_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_read_RSA_PUBKEY)}
      PEM_read_RSA_PUBKEY := FC_PEM_read_RSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_RSA_PUBKEY_removed)}
    if PEM_read_RSA_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_RSA_PUBKEY)}
      PEM_read_RSA_PUBKEY := _PEM_read_RSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_RSA_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_RSA_PUBKEY');
    {$ifend}
  end;
  
  PEM_write_bio_RSA_PUBKEY := LoadLibFunction(ADllHandle, PEM_write_bio_RSA_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_write_bio_RSA_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_RSA_PUBKEY_allownil)}
    PEM_write_bio_RSA_PUBKEY := ERR_PEM_write_bio_RSA_PUBKEY;
    {$ifend}
    {$if declared(PEM_write_bio_RSA_PUBKEY_introduced)}
    if LibVersion < PEM_write_bio_RSA_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_write_bio_RSA_PUBKEY)}
      PEM_write_bio_RSA_PUBKEY := FC_PEM_write_bio_RSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_RSA_PUBKEY_removed)}
    if PEM_write_bio_RSA_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_RSA_PUBKEY)}
      PEM_write_bio_RSA_PUBKEY := _PEM_write_bio_RSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_RSA_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_RSA_PUBKEY');
    {$ifend}
  end;
  
  PEM_write_RSA_PUBKEY := LoadLibFunction(ADllHandle, PEM_write_RSA_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_write_RSA_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_RSA_PUBKEY_allownil)}
    PEM_write_RSA_PUBKEY := ERR_PEM_write_RSA_PUBKEY;
    {$ifend}
    {$if declared(PEM_write_RSA_PUBKEY_introduced)}
    if LibVersion < PEM_write_RSA_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_write_RSA_PUBKEY)}
      PEM_write_RSA_PUBKEY := FC_PEM_write_RSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_RSA_PUBKEY_removed)}
    if PEM_write_RSA_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_RSA_PUBKEY)}
      PEM_write_RSA_PUBKEY := _PEM_write_RSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_RSA_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_RSA_PUBKEY');
    {$ifend}
  end;
  
  PEM_read_bio_DSAPrivateKey := LoadLibFunction(ADllHandle, PEM_read_bio_DSAPrivateKey_procname);
  FuncLoadError := not assigned(PEM_read_bio_DSAPrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_DSAPrivateKey_allownil)}
    PEM_read_bio_DSAPrivateKey := ERR_PEM_read_bio_DSAPrivateKey;
    {$ifend}
    {$if declared(PEM_read_bio_DSAPrivateKey_introduced)}
    if LibVersion < PEM_read_bio_DSAPrivateKey_introduced then
    begin
      {$if declared(FC_PEM_read_bio_DSAPrivateKey)}
      PEM_read_bio_DSAPrivateKey := FC_PEM_read_bio_DSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_DSAPrivateKey_removed)}
    if PEM_read_bio_DSAPrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_DSAPrivateKey)}
      PEM_read_bio_DSAPrivateKey := _PEM_read_bio_DSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_DSAPrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_DSAPrivateKey');
    {$ifend}
  end;
  
  PEM_read_DSAPrivateKey := LoadLibFunction(ADllHandle, PEM_read_DSAPrivateKey_procname);
  FuncLoadError := not assigned(PEM_read_DSAPrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_DSAPrivateKey_allownil)}
    PEM_read_DSAPrivateKey := ERR_PEM_read_DSAPrivateKey;
    {$ifend}
    {$if declared(PEM_read_DSAPrivateKey_introduced)}
    if LibVersion < PEM_read_DSAPrivateKey_introduced then
    begin
      {$if declared(FC_PEM_read_DSAPrivateKey)}
      PEM_read_DSAPrivateKey := FC_PEM_read_DSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_DSAPrivateKey_removed)}
    if PEM_read_DSAPrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_DSAPrivateKey)}
      PEM_read_DSAPrivateKey := _PEM_read_DSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_DSAPrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_DSAPrivateKey');
    {$ifend}
  end;
  
  PEM_write_bio_DSAPrivateKey := LoadLibFunction(ADllHandle, PEM_write_bio_DSAPrivateKey_procname);
  FuncLoadError := not assigned(PEM_write_bio_DSAPrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_DSAPrivateKey_allownil)}
    PEM_write_bio_DSAPrivateKey := ERR_PEM_write_bio_DSAPrivateKey;
    {$ifend}
    {$if declared(PEM_write_bio_DSAPrivateKey_introduced)}
    if LibVersion < PEM_write_bio_DSAPrivateKey_introduced then
    begin
      {$if declared(FC_PEM_write_bio_DSAPrivateKey)}
      PEM_write_bio_DSAPrivateKey := FC_PEM_write_bio_DSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_DSAPrivateKey_removed)}
    if PEM_write_bio_DSAPrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_DSAPrivateKey)}
      PEM_write_bio_DSAPrivateKey := _PEM_write_bio_DSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_DSAPrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_DSAPrivateKey');
    {$ifend}
  end;
  
  PEM_write_DSAPrivateKey := LoadLibFunction(ADllHandle, PEM_write_DSAPrivateKey_procname);
  FuncLoadError := not assigned(PEM_write_DSAPrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_DSAPrivateKey_allownil)}
    PEM_write_DSAPrivateKey := ERR_PEM_write_DSAPrivateKey;
    {$ifend}
    {$if declared(PEM_write_DSAPrivateKey_introduced)}
    if LibVersion < PEM_write_DSAPrivateKey_introduced then
    begin
      {$if declared(FC_PEM_write_DSAPrivateKey)}
      PEM_write_DSAPrivateKey := FC_PEM_write_DSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_DSAPrivateKey_removed)}
    if PEM_write_DSAPrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_DSAPrivateKey)}
      PEM_write_DSAPrivateKey := _PEM_write_DSAPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_DSAPrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_DSAPrivateKey');
    {$ifend}
  end;
  
  PEM_read_bio_DSA_PUBKEY := LoadLibFunction(ADllHandle, PEM_read_bio_DSA_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_read_bio_DSA_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_DSA_PUBKEY_allownil)}
    PEM_read_bio_DSA_PUBKEY := ERR_PEM_read_bio_DSA_PUBKEY;
    {$ifend}
    {$if declared(PEM_read_bio_DSA_PUBKEY_introduced)}
    if LibVersion < PEM_read_bio_DSA_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_read_bio_DSA_PUBKEY)}
      PEM_read_bio_DSA_PUBKEY := FC_PEM_read_bio_DSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_DSA_PUBKEY_removed)}
    if PEM_read_bio_DSA_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_DSA_PUBKEY)}
      PEM_read_bio_DSA_PUBKEY := _PEM_read_bio_DSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_DSA_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_DSA_PUBKEY');
    {$ifend}
  end;
  
  PEM_read_DSA_PUBKEY := LoadLibFunction(ADllHandle, PEM_read_DSA_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_read_DSA_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_DSA_PUBKEY_allownil)}
    PEM_read_DSA_PUBKEY := ERR_PEM_read_DSA_PUBKEY;
    {$ifend}
    {$if declared(PEM_read_DSA_PUBKEY_introduced)}
    if LibVersion < PEM_read_DSA_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_read_DSA_PUBKEY)}
      PEM_read_DSA_PUBKEY := FC_PEM_read_DSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_DSA_PUBKEY_removed)}
    if PEM_read_DSA_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_DSA_PUBKEY)}
      PEM_read_DSA_PUBKEY := _PEM_read_DSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_DSA_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_DSA_PUBKEY');
    {$ifend}
  end;
  
  PEM_write_bio_DSA_PUBKEY := LoadLibFunction(ADllHandle, PEM_write_bio_DSA_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_write_bio_DSA_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_DSA_PUBKEY_allownil)}
    PEM_write_bio_DSA_PUBKEY := ERR_PEM_write_bio_DSA_PUBKEY;
    {$ifend}
    {$if declared(PEM_write_bio_DSA_PUBKEY_introduced)}
    if LibVersion < PEM_write_bio_DSA_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_write_bio_DSA_PUBKEY)}
      PEM_write_bio_DSA_PUBKEY := FC_PEM_write_bio_DSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_DSA_PUBKEY_removed)}
    if PEM_write_bio_DSA_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_DSA_PUBKEY)}
      PEM_write_bio_DSA_PUBKEY := _PEM_write_bio_DSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_DSA_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_DSA_PUBKEY');
    {$ifend}
  end;
  
  PEM_write_DSA_PUBKEY := LoadLibFunction(ADllHandle, PEM_write_DSA_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_write_DSA_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_DSA_PUBKEY_allownil)}
    PEM_write_DSA_PUBKEY := ERR_PEM_write_DSA_PUBKEY;
    {$ifend}
    {$if declared(PEM_write_DSA_PUBKEY_introduced)}
    if LibVersion < PEM_write_DSA_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_write_DSA_PUBKEY)}
      PEM_write_DSA_PUBKEY := FC_PEM_write_DSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_DSA_PUBKEY_removed)}
    if PEM_write_DSA_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_DSA_PUBKEY)}
      PEM_write_DSA_PUBKEY := _PEM_write_DSA_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_DSA_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_DSA_PUBKEY');
    {$ifend}
  end;
  
  PEM_read_bio_DSAparams := LoadLibFunction(ADllHandle, PEM_read_bio_DSAparams_procname);
  FuncLoadError := not assigned(PEM_read_bio_DSAparams);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_DSAparams_allownil)}
    PEM_read_bio_DSAparams := ERR_PEM_read_bio_DSAparams;
    {$ifend}
    {$if declared(PEM_read_bio_DSAparams_introduced)}
    if LibVersion < PEM_read_bio_DSAparams_introduced then
    begin
      {$if declared(FC_PEM_read_bio_DSAparams)}
      PEM_read_bio_DSAparams := FC_PEM_read_bio_DSAparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_DSAparams_removed)}
    if PEM_read_bio_DSAparams_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_DSAparams)}
      PEM_read_bio_DSAparams := _PEM_read_bio_DSAparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_DSAparams_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_DSAparams');
    {$ifend}
  end;
  
  PEM_read_DSAparams := LoadLibFunction(ADllHandle, PEM_read_DSAparams_procname);
  FuncLoadError := not assigned(PEM_read_DSAparams);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_DSAparams_allownil)}
    PEM_read_DSAparams := ERR_PEM_read_DSAparams;
    {$ifend}
    {$if declared(PEM_read_DSAparams_introduced)}
    if LibVersion < PEM_read_DSAparams_introduced then
    begin
      {$if declared(FC_PEM_read_DSAparams)}
      PEM_read_DSAparams := FC_PEM_read_DSAparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_DSAparams_removed)}
    if PEM_read_DSAparams_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_DSAparams)}
      PEM_read_DSAparams := _PEM_read_DSAparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_DSAparams_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_DSAparams');
    {$ifend}
  end;
  
  PEM_write_bio_DSAparams := LoadLibFunction(ADllHandle, PEM_write_bio_DSAparams_procname);
  FuncLoadError := not assigned(PEM_write_bio_DSAparams);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_DSAparams_allownil)}
    PEM_write_bio_DSAparams := ERR_PEM_write_bio_DSAparams;
    {$ifend}
    {$if declared(PEM_write_bio_DSAparams_introduced)}
    if LibVersion < PEM_write_bio_DSAparams_introduced then
    begin
      {$if declared(FC_PEM_write_bio_DSAparams)}
      PEM_write_bio_DSAparams := FC_PEM_write_bio_DSAparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_DSAparams_removed)}
    if PEM_write_bio_DSAparams_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_DSAparams)}
      PEM_write_bio_DSAparams := _PEM_write_bio_DSAparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_DSAparams_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_DSAparams');
    {$ifend}
  end;
  
  PEM_write_DSAparams := LoadLibFunction(ADllHandle, PEM_write_DSAparams_procname);
  FuncLoadError := not assigned(PEM_write_DSAparams);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_DSAparams_allownil)}
    PEM_write_DSAparams := ERR_PEM_write_DSAparams;
    {$ifend}
    {$if declared(PEM_write_DSAparams_introduced)}
    if LibVersion < PEM_write_DSAparams_introduced then
    begin
      {$if declared(FC_PEM_write_DSAparams)}
      PEM_write_DSAparams := FC_PEM_write_DSAparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_DSAparams_removed)}
    if PEM_write_DSAparams_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_DSAparams)}
      PEM_write_DSAparams := _PEM_write_DSAparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_DSAparams_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_DSAparams');
    {$ifend}
  end;
  
  PEM_read_bio_ECPKParameters := LoadLibFunction(ADllHandle, PEM_read_bio_ECPKParameters_procname);
  FuncLoadError := not assigned(PEM_read_bio_ECPKParameters);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_ECPKParameters_allownil)}
    PEM_read_bio_ECPKParameters := ERR_PEM_read_bio_ECPKParameters;
    {$ifend}
    {$if declared(PEM_read_bio_ECPKParameters_introduced)}
    if LibVersion < PEM_read_bio_ECPKParameters_introduced then
    begin
      {$if declared(FC_PEM_read_bio_ECPKParameters)}
      PEM_read_bio_ECPKParameters := FC_PEM_read_bio_ECPKParameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_ECPKParameters_removed)}
    if PEM_read_bio_ECPKParameters_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_ECPKParameters)}
      PEM_read_bio_ECPKParameters := _PEM_read_bio_ECPKParameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_ECPKParameters_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_ECPKParameters');
    {$ifend}
  end;
  
  PEM_read_ECPKParameters := LoadLibFunction(ADllHandle, PEM_read_ECPKParameters_procname);
  FuncLoadError := not assigned(PEM_read_ECPKParameters);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_ECPKParameters_allownil)}
    PEM_read_ECPKParameters := ERR_PEM_read_ECPKParameters;
    {$ifend}
    {$if declared(PEM_read_ECPKParameters_introduced)}
    if LibVersion < PEM_read_ECPKParameters_introduced then
    begin
      {$if declared(FC_PEM_read_ECPKParameters)}
      PEM_read_ECPKParameters := FC_PEM_read_ECPKParameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_ECPKParameters_removed)}
    if PEM_read_ECPKParameters_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_ECPKParameters)}
      PEM_read_ECPKParameters := _PEM_read_ECPKParameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_ECPKParameters_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_ECPKParameters');
    {$ifend}
  end;
  
  PEM_write_bio_ECPKParameters := LoadLibFunction(ADllHandle, PEM_write_bio_ECPKParameters_procname);
  FuncLoadError := not assigned(PEM_write_bio_ECPKParameters);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_ECPKParameters_allownil)}
    PEM_write_bio_ECPKParameters := ERR_PEM_write_bio_ECPKParameters;
    {$ifend}
    {$if declared(PEM_write_bio_ECPKParameters_introduced)}
    if LibVersion < PEM_write_bio_ECPKParameters_introduced then
    begin
      {$if declared(FC_PEM_write_bio_ECPKParameters)}
      PEM_write_bio_ECPKParameters := FC_PEM_write_bio_ECPKParameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_ECPKParameters_removed)}
    if PEM_write_bio_ECPKParameters_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_ECPKParameters)}
      PEM_write_bio_ECPKParameters := _PEM_write_bio_ECPKParameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_ECPKParameters_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_ECPKParameters');
    {$ifend}
  end;
  
  PEM_write_ECPKParameters := LoadLibFunction(ADllHandle, PEM_write_ECPKParameters_procname);
  FuncLoadError := not assigned(PEM_write_ECPKParameters);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_ECPKParameters_allownil)}
    PEM_write_ECPKParameters := ERR_PEM_write_ECPKParameters;
    {$ifend}
    {$if declared(PEM_write_ECPKParameters_introduced)}
    if LibVersion < PEM_write_ECPKParameters_introduced then
    begin
      {$if declared(FC_PEM_write_ECPKParameters)}
      PEM_write_ECPKParameters := FC_PEM_write_ECPKParameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_ECPKParameters_removed)}
    if PEM_write_ECPKParameters_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_ECPKParameters)}
      PEM_write_ECPKParameters := _PEM_write_ECPKParameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_ECPKParameters_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_ECPKParameters');
    {$ifend}
  end;
  
  PEM_read_bio_ECPrivateKey := LoadLibFunction(ADllHandle, PEM_read_bio_ECPrivateKey_procname);
  FuncLoadError := not assigned(PEM_read_bio_ECPrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_ECPrivateKey_allownil)}
    PEM_read_bio_ECPrivateKey := ERR_PEM_read_bio_ECPrivateKey;
    {$ifend}
    {$if declared(PEM_read_bio_ECPrivateKey_introduced)}
    if LibVersion < PEM_read_bio_ECPrivateKey_introduced then
    begin
      {$if declared(FC_PEM_read_bio_ECPrivateKey)}
      PEM_read_bio_ECPrivateKey := FC_PEM_read_bio_ECPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_ECPrivateKey_removed)}
    if PEM_read_bio_ECPrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_ECPrivateKey)}
      PEM_read_bio_ECPrivateKey := _PEM_read_bio_ECPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_ECPrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_ECPrivateKey');
    {$ifend}
  end;
  
  PEM_read_ECPrivateKey := LoadLibFunction(ADllHandle, PEM_read_ECPrivateKey_procname);
  FuncLoadError := not assigned(PEM_read_ECPrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_ECPrivateKey_allownil)}
    PEM_read_ECPrivateKey := ERR_PEM_read_ECPrivateKey;
    {$ifend}
    {$if declared(PEM_read_ECPrivateKey_introduced)}
    if LibVersion < PEM_read_ECPrivateKey_introduced then
    begin
      {$if declared(FC_PEM_read_ECPrivateKey)}
      PEM_read_ECPrivateKey := FC_PEM_read_ECPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_ECPrivateKey_removed)}
    if PEM_read_ECPrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_ECPrivateKey)}
      PEM_read_ECPrivateKey := _PEM_read_ECPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_ECPrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_ECPrivateKey');
    {$ifend}
  end;
  
  PEM_write_bio_ECPrivateKey := LoadLibFunction(ADllHandle, PEM_write_bio_ECPrivateKey_procname);
  FuncLoadError := not assigned(PEM_write_bio_ECPrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_ECPrivateKey_allownil)}
    PEM_write_bio_ECPrivateKey := ERR_PEM_write_bio_ECPrivateKey;
    {$ifend}
    {$if declared(PEM_write_bio_ECPrivateKey_introduced)}
    if LibVersion < PEM_write_bio_ECPrivateKey_introduced then
    begin
      {$if declared(FC_PEM_write_bio_ECPrivateKey)}
      PEM_write_bio_ECPrivateKey := FC_PEM_write_bio_ECPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_ECPrivateKey_removed)}
    if PEM_write_bio_ECPrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_ECPrivateKey)}
      PEM_write_bio_ECPrivateKey := _PEM_write_bio_ECPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_ECPrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_ECPrivateKey');
    {$ifend}
  end;
  
  PEM_write_ECPrivateKey := LoadLibFunction(ADllHandle, PEM_write_ECPrivateKey_procname);
  FuncLoadError := not assigned(PEM_write_ECPrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_ECPrivateKey_allownil)}
    PEM_write_ECPrivateKey := ERR_PEM_write_ECPrivateKey;
    {$ifend}
    {$if declared(PEM_write_ECPrivateKey_introduced)}
    if LibVersion < PEM_write_ECPrivateKey_introduced then
    begin
      {$if declared(FC_PEM_write_ECPrivateKey)}
      PEM_write_ECPrivateKey := FC_PEM_write_ECPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_ECPrivateKey_removed)}
    if PEM_write_ECPrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_ECPrivateKey)}
      PEM_write_ECPrivateKey := _PEM_write_ECPrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_ECPrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_ECPrivateKey');
    {$ifend}
  end;
  
  PEM_read_bio_EC_PUBKEY := LoadLibFunction(ADllHandle, PEM_read_bio_EC_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_read_bio_EC_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_EC_PUBKEY_allownil)}
    PEM_read_bio_EC_PUBKEY := ERR_PEM_read_bio_EC_PUBKEY;
    {$ifend}
    {$if declared(PEM_read_bio_EC_PUBKEY_introduced)}
    if LibVersion < PEM_read_bio_EC_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_read_bio_EC_PUBKEY)}
      PEM_read_bio_EC_PUBKEY := FC_PEM_read_bio_EC_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_EC_PUBKEY_removed)}
    if PEM_read_bio_EC_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_EC_PUBKEY)}
      PEM_read_bio_EC_PUBKEY := _PEM_read_bio_EC_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_EC_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_EC_PUBKEY');
    {$ifend}
  end;
  
  PEM_read_EC_PUBKEY := LoadLibFunction(ADllHandle, PEM_read_EC_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_read_EC_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_EC_PUBKEY_allownil)}
    PEM_read_EC_PUBKEY := ERR_PEM_read_EC_PUBKEY;
    {$ifend}
    {$if declared(PEM_read_EC_PUBKEY_introduced)}
    if LibVersion < PEM_read_EC_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_read_EC_PUBKEY)}
      PEM_read_EC_PUBKEY := FC_PEM_read_EC_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_EC_PUBKEY_removed)}
    if PEM_read_EC_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_EC_PUBKEY)}
      PEM_read_EC_PUBKEY := _PEM_read_EC_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_EC_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_EC_PUBKEY');
    {$ifend}
  end;
  
  PEM_write_bio_EC_PUBKEY := LoadLibFunction(ADllHandle, PEM_write_bio_EC_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_write_bio_EC_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_EC_PUBKEY_allownil)}
    PEM_write_bio_EC_PUBKEY := ERR_PEM_write_bio_EC_PUBKEY;
    {$ifend}
    {$if declared(PEM_write_bio_EC_PUBKEY_introduced)}
    if LibVersion < PEM_write_bio_EC_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_write_bio_EC_PUBKEY)}
      PEM_write_bio_EC_PUBKEY := FC_PEM_write_bio_EC_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_EC_PUBKEY_removed)}
    if PEM_write_bio_EC_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_EC_PUBKEY)}
      PEM_write_bio_EC_PUBKEY := _PEM_write_bio_EC_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_EC_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_EC_PUBKEY');
    {$ifend}
  end;
  
  PEM_write_EC_PUBKEY := LoadLibFunction(ADllHandle, PEM_write_EC_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_write_EC_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_EC_PUBKEY_allownil)}
    PEM_write_EC_PUBKEY := ERR_PEM_write_EC_PUBKEY;
    {$ifend}
    {$if declared(PEM_write_EC_PUBKEY_introduced)}
    if LibVersion < PEM_write_EC_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_write_EC_PUBKEY)}
      PEM_write_EC_PUBKEY := FC_PEM_write_EC_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_EC_PUBKEY_removed)}
    if PEM_write_EC_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_EC_PUBKEY)}
      PEM_write_EC_PUBKEY := _PEM_write_EC_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_EC_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_EC_PUBKEY');
    {$ifend}
  end;
  
  PEM_read_bio_DHparams := LoadLibFunction(ADllHandle, PEM_read_bio_DHparams_procname);
  FuncLoadError := not assigned(PEM_read_bio_DHparams);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_DHparams_allownil)}
    PEM_read_bio_DHparams := ERR_PEM_read_bio_DHparams;
    {$ifend}
    {$if declared(PEM_read_bio_DHparams_introduced)}
    if LibVersion < PEM_read_bio_DHparams_introduced then
    begin
      {$if declared(FC_PEM_read_bio_DHparams)}
      PEM_read_bio_DHparams := FC_PEM_read_bio_DHparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_DHparams_removed)}
    if PEM_read_bio_DHparams_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_DHparams)}
      PEM_read_bio_DHparams := _PEM_read_bio_DHparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_DHparams_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_DHparams');
    {$ifend}
  end;
  
  PEM_read_DHparams := LoadLibFunction(ADllHandle, PEM_read_DHparams_procname);
  FuncLoadError := not assigned(PEM_read_DHparams);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_DHparams_allownil)}
    PEM_read_DHparams := ERR_PEM_read_DHparams;
    {$ifend}
    {$if declared(PEM_read_DHparams_introduced)}
    if LibVersion < PEM_read_DHparams_introduced then
    begin
      {$if declared(FC_PEM_read_DHparams)}
      PEM_read_DHparams := FC_PEM_read_DHparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_DHparams_removed)}
    if PEM_read_DHparams_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_DHparams)}
      PEM_read_DHparams := _PEM_read_DHparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_DHparams_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_DHparams');
    {$ifend}
  end;
  
  PEM_write_bio_DHparams := LoadLibFunction(ADllHandle, PEM_write_bio_DHparams_procname);
  FuncLoadError := not assigned(PEM_write_bio_DHparams);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_DHparams_allownil)}
    PEM_write_bio_DHparams := ERR_PEM_write_bio_DHparams;
    {$ifend}
    {$if declared(PEM_write_bio_DHparams_introduced)}
    if LibVersion < PEM_write_bio_DHparams_introduced then
    begin
      {$if declared(FC_PEM_write_bio_DHparams)}
      PEM_write_bio_DHparams := FC_PEM_write_bio_DHparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_DHparams_removed)}
    if PEM_write_bio_DHparams_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_DHparams)}
      PEM_write_bio_DHparams := _PEM_write_bio_DHparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_DHparams_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_DHparams');
    {$ifend}
  end;
  
  PEM_write_DHparams := LoadLibFunction(ADllHandle, PEM_write_DHparams_procname);
  FuncLoadError := not assigned(PEM_write_DHparams);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_DHparams_allownil)}
    PEM_write_DHparams := ERR_PEM_write_DHparams;
    {$ifend}
    {$if declared(PEM_write_DHparams_introduced)}
    if LibVersion < PEM_write_DHparams_introduced then
    begin
      {$if declared(FC_PEM_write_DHparams)}
      PEM_write_DHparams := FC_PEM_write_DHparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_DHparams_removed)}
    if PEM_write_DHparams_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_DHparams)}
      PEM_write_DHparams := _PEM_write_DHparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_DHparams_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_DHparams');
    {$ifend}
  end;
  
  PEM_write_bio_DHxparams := LoadLibFunction(ADllHandle, PEM_write_bio_DHxparams_procname);
  FuncLoadError := not assigned(PEM_write_bio_DHxparams);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_DHxparams_allownil)}
    PEM_write_bio_DHxparams := ERR_PEM_write_bio_DHxparams;
    {$ifend}
    {$if declared(PEM_write_bio_DHxparams_introduced)}
    if LibVersion < PEM_write_bio_DHxparams_introduced then
    begin
      {$if declared(FC_PEM_write_bio_DHxparams)}
      PEM_write_bio_DHxparams := FC_PEM_write_bio_DHxparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_DHxparams_removed)}
    if PEM_write_bio_DHxparams_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_DHxparams)}
      PEM_write_bio_DHxparams := _PEM_write_bio_DHxparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_DHxparams_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_DHxparams');
    {$ifend}
  end;
  
  PEM_write_DHxparams := LoadLibFunction(ADllHandle, PEM_write_DHxparams_procname);
  FuncLoadError := not assigned(PEM_write_DHxparams);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_DHxparams_allownil)}
    PEM_write_DHxparams := ERR_PEM_write_DHxparams;
    {$ifend}
    {$if declared(PEM_write_DHxparams_introduced)}
    if LibVersion < PEM_write_DHxparams_introduced then
    begin
      {$if declared(FC_PEM_write_DHxparams)}
      PEM_write_DHxparams := FC_PEM_write_DHxparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_DHxparams_removed)}
    if PEM_write_DHxparams_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_DHxparams)}
      PEM_write_DHxparams := _PEM_write_DHxparams;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_DHxparams_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_DHxparams');
    {$ifend}
  end;
  
  PEM_read_bio_PrivateKey := LoadLibFunction(ADllHandle, PEM_read_bio_PrivateKey_procname);
  FuncLoadError := not assigned(PEM_read_bio_PrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_PrivateKey_allownil)}
    PEM_read_bio_PrivateKey := ERR_PEM_read_bio_PrivateKey;
    {$ifend}
    {$if declared(PEM_read_bio_PrivateKey_introduced)}
    if LibVersion < PEM_read_bio_PrivateKey_introduced then
    begin
      {$if declared(FC_PEM_read_bio_PrivateKey)}
      PEM_read_bio_PrivateKey := FC_PEM_read_bio_PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_PrivateKey_removed)}
    if PEM_read_bio_PrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_PrivateKey)}
      PEM_read_bio_PrivateKey := _PEM_read_bio_PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_PrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_PrivateKey');
    {$ifend}
  end;
  
  PEM_read_bio_PrivateKey_ex := LoadLibFunction(ADllHandle, PEM_read_bio_PrivateKey_ex_procname);
  FuncLoadError := not assigned(PEM_read_bio_PrivateKey_ex);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_PrivateKey_ex_allownil)}
    PEM_read_bio_PrivateKey_ex := ERR_PEM_read_bio_PrivateKey_ex;
    {$ifend}
    {$if declared(PEM_read_bio_PrivateKey_ex_introduced)}
    if LibVersion < PEM_read_bio_PrivateKey_ex_introduced then
    begin
      {$if declared(FC_PEM_read_bio_PrivateKey_ex)}
      PEM_read_bio_PrivateKey_ex := FC_PEM_read_bio_PrivateKey_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_PrivateKey_ex_removed)}
    if PEM_read_bio_PrivateKey_ex_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_PrivateKey_ex)}
      PEM_read_bio_PrivateKey_ex := _PEM_read_bio_PrivateKey_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_PrivateKey_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_PrivateKey_ex');
    {$ifend}
  end;
  
  PEM_read_PrivateKey := LoadLibFunction(ADllHandle, PEM_read_PrivateKey_procname);
  FuncLoadError := not assigned(PEM_read_PrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_PrivateKey_allownil)}
    PEM_read_PrivateKey := ERR_PEM_read_PrivateKey;
    {$ifend}
    {$if declared(PEM_read_PrivateKey_introduced)}
    if LibVersion < PEM_read_PrivateKey_introduced then
    begin
      {$if declared(FC_PEM_read_PrivateKey)}
      PEM_read_PrivateKey := FC_PEM_read_PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_PrivateKey_removed)}
    if PEM_read_PrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_PrivateKey)}
      PEM_read_PrivateKey := _PEM_read_PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_PrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_PrivateKey');
    {$ifend}
  end;
  
  PEM_read_PrivateKey_ex := LoadLibFunction(ADllHandle, PEM_read_PrivateKey_ex_procname);
  FuncLoadError := not assigned(PEM_read_PrivateKey_ex);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_PrivateKey_ex_allownil)}
    PEM_read_PrivateKey_ex := ERR_PEM_read_PrivateKey_ex;
    {$ifend}
    {$if declared(PEM_read_PrivateKey_ex_introduced)}
    if LibVersion < PEM_read_PrivateKey_ex_introduced then
    begin
      {$if declared(FC_PEM_read_PrivateKey_ex)}
      PEM_read_PrivateKey_ex := FC_PEM_read_PrivateKey_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_PrivateKey_ex_removed)}
    if PEM_read_PrivateKey_ex_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_PrivateKey_ex)}
      PEM_read_PrivateKey_ex := _PEM_read_PrivateKey_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_PrivateKey_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_PrivateKey_ex');
    {$ifend}
  end;
  
  PEM_write_bio_PrivateKey := LoadLibFunction(ADllHandle, PEM_write_bio_PrivateKey_procname);
  FuncLoadError := not assigned(PEM_write_bio_PrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_PrivateKey_allownil)}
    PEM_write_bio_PrivateKey := ERR_PEM_write_bio_PrivateKey;
    {$ifend}
    {$if declared(PEM_write_bio_PrivateKey_introduced)}
    if LibVersion < PEM_write_bio_PrivateKey_introduced then
    begin
      {$if declared(FC_PEM_write_bio_PrivateKey)}
      PEM_write_bio_PrivateKey := FC_PEM_write_bio_PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_PrivateKey_removed)}
    if PEM_write_bio_PrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_PrivateKey)}
      PEM_write_bio_PrivateKey := _PEM_write_bio_PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_PrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_PrivateKey');
    {$ifend}
  end;
  
  PEM_write_bio_PrivateKey_ex := LoadLibFunction(ADllHandle, PEM_write_bio_PrivateKey_ex_procname);
  FuncLoadError := not assigned(PEM_write_bio_PrivateKey_ex);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_PrivateKey_ex_allownil)}
    PEM_write_bio_PrivateKey_ex := ERR_PEM_write_bio_PrivateKey_ex;
    {$ifend}
    {$if declared(PEM_write_bio_PrivateKey_ex_introduced)}
    if LibVersion < PEM_write_bio_PrivateKey_ex_introduced then
    begin
      {$if declared(FC_PEM_write_bio_PrivateKey_ex)}
      PEM_write_bio_PrivateKey_ex := FC_PEM_write_bio_PrivateKey_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_PrivateKey_ex_removed)}
    if PEM_write_bio_PrivateKey_ex_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_PrivateKey_ex)}
      PEM_write_bio_PrivateKey_ex := _PEM_write_bio_PrivateKey_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_PrivateKey_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_PrivateKey_ex');
    {$ifend}
  end;
  
  PEM_write_PrivateKey := LoadLibFunction(ADllHandle, PEM_write_PrivateKey_procname);
  FuncLoadError := not assigned(PEM_write_PrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_PrivateKey_allownil)}
    PEM_write_PrivateKey := ERR_PEM_write_PrivateKey;
    {$ifend}
    {$if declared(PEM_write_PrivateKey_introduced)}
    if LibVersion < PEM_write_PrivateKey_introduced then
    begin
      {$if declared(FC_PEM_write_PrivateKey)}
      PEM_write_PrivateKey := FC_PEM_write_PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_PrivateKey_removed)}
    if PEM_write_PrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_PrivateKey)}
      PEM_write_PrivateKey := _PEM_write_PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_PrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_PrivateKey');
    {$ifend}
  end;
  
  PEM_write_PrivateKey_ex := LoadLibFunction(ADllHandle, PEM_write_PrivateKey_ex_procname);
  FuncLoadError := not assigned(PEM_write_PrivateKey_ex);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_PrivateKey_ex_allownil)}
    PEM_write_PrivateKey_ex := ERR_PEM_write_PrivateKey_ex;
    {$ifend}
    {$if declared(PEM_write_PrivateKey_ex_introduced)}
    if LibVersion < PEM_write_PrivateKey_ex_introduced then
    begin
      {$if declared(FC_PEM_write_PrivateKey_ex)}
      PEM_write_PrivateKey_ex := FC_PEM_write_PrivateKey_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_PrivateKey_ex_removed)}
    if PEM_write_PrivateKey_ex_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_PrivateKey_ex)}
      PEM_write_PrivateKey_ex := _PEM_write_PrivateKey_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_PrivateKey_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_PrivateKey_ex');
    {$ifend}
  end;
  
  PEM_read_bio_PUBKEY := LoadLibFunction(ADllHandle, PEM_read_bio_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_read_bio_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_PUBKEY_allownil)}
    PEM_read_bio_PUBKEY := ERR_PEM_read_bio_PUBKEY;
    {$ifend}
    {$if declared(PEM_read_bio_PUBKEY_introduced)}
    if LibVersion < PEM_read_bio_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_read_bio_PUBKEY)}
      PEM_read_bio_PUBKEY := FC_PEM_read_bio_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_PUBKEY_removed)}
    if PEM_read_bio_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_PUBKEY)}
      PEM_read_bio_PUBKEY := _PEM_read_bio_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_PUBKEY');
    {$ifend}
  end;
  
  PEM_read_bio_PUBKEY_ex := LoadLibFunction(ADllHandle, PEM_read_bio_PUBKEY_ex_procname);
  FuncLoadError := not assigned(PEM_read_bio_PUBKEY_ex);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_PUBKEY_ex_allownil)}
    PEM_read_bio_PUBKEY_ex := ERR_PEM_read_bio_PUBKEY_ex;
    {$ifend}
    {$if declared(PEM_read_bio_PUBKEY_ex_introduced)}
    if LibVersion < PEM_read_bio_PUBKEY_ex_introduced then
    begin
      {$if declared(FC_PEM_read_bio_PUBKEY_ex)}
      PEM_read_bio_PUBKEY_ex := FC_PEM_read_bio_PUBKEY_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_PUBKEY_ex_removed)}
    if PEM_read_bio_PUBKEY_ex_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_PUBKEY_ex)}
      PEM_read_bio_PUBKEY_ex := _PEM_read_bio_PUBKEY_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_PUBKEY_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_PUBKEY_ex');
    {$ifend}
  end;
  
  PEM_read_PUBKEY := LoadLibFunction(ADllHandle, PEM_read_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_read_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_PUBKEY_allownil)}
    PEM_read_PUBKEY := ERR_PEM_read_PUBKEY;
    {$ifend}
    {$if declared(PEM_read_PUBKEY_introduced)}
    if LibVersion < PEM_read_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_read_PUBKEY)}
      PEM_read_PUBKEY := FC_PEM_read_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_PUBKEY_removed)}
    if PEM_read_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_PUBKEY)}
      PEM_read_PUBKEY := _PEM_read_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_PUBKEY');
    {$ifend}
  end;
  
  PEM_read_PUBKEY_ex := LoadLibFunction(ADllHandle, PEM_read_PUBKEY_ex_procname);
  FuncLoadError := not assigned(PEM_read_PUBKEY_ex);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_PUBKEY_ex_allownil)}
    PEM_read_PUBKEY_ex := ERR_PEM_read_PUBKEY_ex;
    {$ifend}
    {$if declared(PEM_read_PUBKEY_ex_introduced)}
    if LibVersion < PEM_read_PUBKEY_ex_introduced then
    begin
      {$if declared(FC_PEM_read_PUBKEY_ex)}
      PEM_read_PUBKEY_ex := FC_PEM_read_PUBKEY_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_PUBKEY_ex_removed)}
    if PEM_read_PUBKEY_ex_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_PUBKEY_ex)}
      PEM_read_PUBKEY_ex := _PEM_read_PUBKEY_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_PUBKEY_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_PUBKEY_ex');
    {$ifend}
  end;
  
  PEM_write_bio_PUBKEY := LoadLibFunction(ADllHandle, PEM_write_bio_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_write_bio_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_PUBKEY_allownil)}
    PEM_write_bio_PUBKEY := ERR_PEM_write_bio_PUBKEY;
    {$ifend}
    {$if declared(PEM_write_bio_PUBKEY_introduced)}
    if LibVersion < PEM_write_bio_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_write_bio_PUBKEY)}
      PEM_write_bio_PUBKEY := FC_PEM_write_bio_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_PUBKEY_removed)}
    if PEM_write_bio_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_PUBKEY)}
      PEM_write_bio_PUBKEY := _PEM_write_bio_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_PUBKEY');
    {$ifend}
  end;
  
  PEM_write_bio_PUBKEY_ex := LoadLibFunction(ADllHandle, PEM_write_bio_PUBKEY_ex_procname);
  FuncLoadError := not assigned(PEM_write_bio_PUBKEY_ex);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_PUBKEY_ex_allownil)}
    PEM_write_bio_PUBKEY_ex := ERR_PEM_write_bio_PUBKEY_ex;
    {$ifend}
    {$if declared(PEM_write_bio_PUBKEY_ex_introduced)}
    if LibVersion < PEM_write_bio_PUBKEY_ex_introduced then
    begin
      {$if declared(FC_PEM_write_bio_PUBKEY_ex)}
      PEM_write_bio_PUBKEY_ex := FC_PEM_write_bio_PUBKEY_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_PUBKEY_ex_removed)}
    if PEM_write_bio_PUBKEY_ex_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_PUBKEY_ex)}
      PEM_write_bio_PUBKEY_ex := _PEM_write_bio_PUBKEY_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_PUBKEY_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_PUBKEY_ex');
    {$ifend}
  end;
  
  PEM_write_PUBKEY := LoadLibFunction(ADllHandle, PEM_write_PUBKEY_procname);
  FuncLoadError := not assigned(PEM_write_PUBKEY);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_PUBKEY_allownil)}
    PEM_write_PUBKEY := ERR_PEM_write_PUBKEY;
    {$ifend}
    {$if declared(PEM_write_PUBKEY_introduced)}
    if LibVersion < PEM_write_PUBKEY_introduced then
    begin
      {$if declared(FC_PEM_write_PUBKEY)}
      PEM_write_PUBKEY := FC_PEM_write_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_PUBKEY_removed)}
    if PEM_write_PUBKEY_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_PUBKEY)}
      PEM_write_PUBKEY := _PEM_write_PUBKEY;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_PUBKEY_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_PUBKEY');
    {$ifend}
  end;
  
  PEM_write_PUBKEY_ex := LoadLibFunction(ADllHandle, PEM_write_PUBKEY_ex_procname);
  FuncLoadError := not assigned(PEM_write_PUBKEY_ex);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_PUBKEY_ex_allownil)}
    PEM_write_PUBKEY_ex := ERR_PEM_write_PUBKEY_ex;
    {$ifend}
    {$if declared(PEM_write_PUBKEY_ex_introduced)}
    if LibVersion < PEM_write_PUBKEY_ex_introduced then
    begin
      {$if declared(FC_PEM_write_PUBKEY_ex)}
      PEM_write_PUBKEY_ex := FC_PEM_write_PUBKEY_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_PUBKEY_ex_removed)}
    if PEM_write_PUBKEY_ex_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_PUBKEY_ex)}
      PEM_write_PUBKEY_ex := _PEM_write_PUBKEY_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_PUBKEY_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_PUBKEY_ex');
    {$ifend}
  end;
  
  PEM_write_bio_PrivateKey_traditional := LoadLibFunction(ADllHandle, PEM_write_bio_PrivateKey_traditional_procname);
  FuncLoadError := not assigned(PEM_write_bio_PrivateKey_traditional);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_PrivateKey_traditional_allownil)}
    PEM_write_bio_PrivateKey_traditional := ERR_PEM_write_bio_PrivateKey_traditional;
    {$ifend}
    {$if declared(PEM_write_bio_PrivateKey_traditional_introduced)}
    if LibVersion < PEM_write_bio_PrivateKey_traditional_introduced then
    begin
      {$if declared(FC_PEM_write_bio_PrivateKey_traditional)}
      PEM_write_bio_PrivateKey_traditional := FC_PEM_write_bio_PrivateKey_traditional;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_PrivateKey_traditional_removed)}
    if PEM_write_bio_PrivateKey_traditional_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_PrivateKey_traditional)}
      PEM_write_bio_PrivateKey_traditional := _PEM_write_bio_PrivateKey_traditional;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_PrivateKey_traditional_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_PrivateKey_traditional');
    {$ifend}
  end;
  
  PEM_write_bio_PKCS8PrivateKey_nid := LoadLibFunction(ADllHandle, PEM_write_bio_PKCS8PrivateKey_nid_procname);
  FuncLoadError := not assigned(PEM_write_bio_PKCS8PrivateKey_nid);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_PKCS8PrivateKey_nid_allownil)}
    PEM_write_bio_PKCS8PrivateKey_nid := ERR_PEM_write_bio_PKCS8PrivateKey_nid;
    {$ifend}
    {$if declared(PEM_write_bio_PKCS8PrivateKey_nid_introduced)}
    if LibVersion < PEM_write_bio_PKCS8PrivateKey_nid_introduced then
    begin
      {$if declared(FC_PEM_write_bio_PKCS8PrivateKey_nid)}
      PEM_write_bio_PKCS8PrivateKey_nid := FC_PEM_write_bio_PKCS8PrivateKey_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_PKCS8PrivateKey_nid_removed)}
    if PEM_write_bio_PKCS8PrivateKey_nid_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_PKCS8PrivateKey_nid)}
      PEM_write_bio_PKCS8PrivateKey_nid := _PEM_write_bio_PKCS8PrivateKey_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_PKCS8PrivateKey_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_PKCS8PrivateKey_nid');
    {$ifend}
  end;
  
  PEM_write_bio_PKCS8PrivateKey := LoadLibFunction(ADllHandle, PEM_write_bio_PKCS8PrivateKey_procname);
  FuncLoadError := not assigned(PEM_write_bio_PKCS8PrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_PKCS8PrivateKey_allownil)}
    PEM_write_bio_PKCS8PrivateKey := ERR_PEM_write_bio_PKCS8PrivateKey;
    {$ifend}
    {$if declared(PEM_write_bio_PKCS8PrivateKey_introduced)}
    if LibVersion < PEM_write_bio_PKCS8PrivateKey_introduced then
    begin
      {$if declared(FC_PEM_write_bio_PKCS8PrivateKey)}
      PEM_write_bio_PKCS8PrivateKey := FC_PEM_write_bio_PKCS8PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_PKCS8PrivateKey_removed)}
    if PEM_write_bio_PKCS8PrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_PKCS8PrivateKey)}
      PEM_write_bio_PKCS8PrivateKey := _PEM_write_bio_PKCS8PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_PKCS8PrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_PKCS8PrivateKey');
    {$ifend}
  end;
  
  i2d_PKCS8PrivateKey_bio := LoadLibFunction(ADllHandle, i2d_PKCS8PrivateKey_bio_procname);
  FuncLoadError := not assigned(i2d_PKCS8PrivateKey_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS8PrivateKey_bio_allownil)}
    i2d_PKCS8PrivateKey_bio := ERR_i2d_PKCS8PrivateKey_bio;
    {$ifend}
    {$if declared(i2d_PKCS8PrivateKey_bio_introduced)}
    if LibVersion < i2d_PKCS8PrivateKey_bio_introduced then
    begin
      {$if declared(FC_i2d_PKCS8PrivateKey_bio)}
      i2d_PKCS8PrivateKey_bio := FC_i2d_PKCS8PrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS8PrivateKey_bio_removed)}
    if i2d_PKCS8PrivateKey_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS8PrivateKey_bio)}
      i2d_PKCS8PrivateKey_bio := _i2d_PKCS8PrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS8PrivateKey_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS8PrivateKey_bio');
    {$ifend}
  end;
  
  i2d_PKCS8PrivateKey_nid_bio := LoadLibFunction(ADllHandle, i2d_PKCS8PrivateKey_nid_bio_procname);
  FuncLoadError := not assigned(i2d_PKCS8PrivateKey_nid_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS8PrivateKey_nid_bio_allownil)}
    i2d_PKCS8PrivateKey_nid_bio := ERR_i2d_PKCS8PrivateKey_nid_bio;
    {$ifend}
    {$if declared(i2d_PKCS8PrivateKey_nid_bio_introduced)}
    if LibVersion < i2d_PKCS8PrivateKey_nid_bio_introduced then
    begin
      {$if declared(FC_i2d_PKCS8PrivateKey_nid_bio)}
      i2d_PKCS8PrivateKey_nid_bio := FC_i2d_PKCS8PrivateKey_nid_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS8PrivateKey_nid_bio_removed)}
    if i2d_PKCS8PrivateKey_nid_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS8PrivateKey_nid_bio)}
      i2d_PKCS8PrivateKey_nid_bio := _i2d_PKCS8PrivateKey_nid_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS8PrivateKey_nid_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS8PrivateKey_nid_bio');
    {$ifend}
  end;
  
  d2i_PKCS8PrivateKey_bio := LoadLibFunction(ADllHandle, d2i_PKCS8PrivateKey_bio_procname);
  FuncLoadError := not assigned(d2i_PKCS8PrivateKey_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS8PrivateKey_bio_allownil)}
    d2i_PKCS8PrivateKey_bio := ERR_d2i_PKCS8PrivateKey_bio;
    {$ifend}
    {$if declared(d2i_PKCS8PrivateKey_bio_introduced)}
    if LibVersion < d2i_PKCS8PrivateKey_bio_introduced then
    begin
      {$if declared(FC_d2i_PKCS8PrivateKey_bio)}
      d2i_PKCS8PrivateKey_bio := FC_d2i_PKCS8PrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS8PrivateKey_bio_removed)}
    if d2i_PKCS8PrivateKey_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS8PrivateKey_bio)}
      d2i_PKCS8PrivateKey_bio := _d2i_PKCS8PrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS8PrivateKey_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS8PrivateKey_bio');
    {$ifend}
  end;
  
  i2d_PKCS8PrivateKey_fp := LoadLibFunction(ADllHandle, i2d_PKCS8PrivateKey_fp_procname);
  FuncLoadError := not assigned(i2d_PKCS8PrivateKey_fp);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS8PrivateKey_fp_allownil)}
    i2d_PKCS8PrivateKey_fp := ERR_i2d_PKCS8PrivateKey_fp;
    {$ifend}
    {$if declared(i2d_PKCS8PrivateKey_fp_introduced)}
    if LibVersion < i2d_PKCS8PrivateKey_fp_introduced then
    begin
      {$if declared(FC_i2d_PKCS8PrivateKey_fp)}
      i2d_PKCS8PrivateKey_fp := FC_i2d_PKCS8PrivateKey_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS8PrivateKey_fp_removed)}
    if i2d_PKCS8PrivateKey_fp_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS8PrivateKey_fp)}
      i2d_PKCS8PrivateKey_fp := _i2d_PKCS8PrivateKey_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS8PrivateKey_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS8PrivateKey_fp');
    {$ifend}
  end;
  
  i2d_PKCS8PrivateKey_nid_fp := LoadLibFunction(ADllHandle, i2d_PKCS8PrivateKey_nid_fp_procname);
  FuncLoadError := not assigned(i2d_PKCS8PrivateKey_nid_fp);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS8PrivateKey_nid_fp_allownil)}
    i2d_PKCS8PrivateKey_nid_fp := ERR_i2d_PKCS8PrivateKey_nid_fp;
    {$ifend}
    {$if declared(i2d_PKCS8PrivateKey_nid_fp_introduced)}
    if LibVersion < i2d_PKCS8PrivateKey_nid_fp_introduced then
    begin
      {$if declared(FC_i2d_PKCS8PrivateKey_nid_fp)}
      i2d_PKCS8PrivateKey_nid_fp := FC_i2d_PKCS8PrivateKey_nid_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS8PrivateKey_nid_fp_removed)}
    if i2d_PKCS8PrivateKey_nid_fp_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS8PrivateKey_nid_fp)}
      i2d_PKCS8PrivateKey_nid_fp := _i2d_PKCS8PrivateKey_nid_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS8PrivateKey_nid_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS8PrivateKey_nid_fp');
    {$ifend}
  end;
  
  PEM_write_PKCS8PrivateKey_nid := LoadLibFunction(ADllHandle, PEM_write_PKCS8PrivateKey_nid_procname);
  FuncLoadError := not assigned(PEM_write_PKCS8PrivateKey_nid);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_PKCS8PrivateKey_nid_allownil)}
    PEM_write_PKCS8PrivateKey_nid := ERR_PEM_write_PKCS8PrivateKey_nid;
    {$ifend}
    {$if declared(PEM_write_PKCS8PrivateKey_nid_introduced)}
    if LibVersion < PEM_write_PKCS8PrivateKey_nid_introduced then
    begin
      {$if declared(FC_PEM_write_PKCS8PrivateKey_nid)}
      PEM_write_PKCS8PrivateKey_nid := FC_PEM_write_PKCS8PrivateKey_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_PKCS8PrivateKey_nid_removed)}
    if PEM_write_PKCS8PrivateKey_nid_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_PKCS8PrivateKey_nid)}
      PEM_write_PKCS8PrivateKey_nid := _PEM_write_PKCS8PrivateKey_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_PKCS8PrivateKey_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_PKCS8PrivateKey_nid');
    {$ifend}
  end;
  
  d2i_PKCS8PrivateKey_fp := LoadLibFunction(ADllHandle, d2i_PKCS8PrivateKey_fp_procname);
  FuncLoadError := not assigned(d2i_PKCS8PrivateKey_fp);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS8PrivateKey_fp_allownil)}
    d2i_PKCS8PrivateKey_fp := ERR_d2i_PKCS8PrivateKey_fp;
    {$ifend}
    {$if declared(d2i_PKCS8PrivateKey_fp_introduced)}
    if LibVersion < d2i_PKCS8PrivateKey_fp_introduced then
    begin
      {$if declared(FC_d2i_PKCS8PrivateKey_fp)}
      d2i_PKCS8PrivateKey_fp := FC_d2i_PKCS8PrivateKey_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS8PrivateKey_fp_removed)}
    if d2i_PKCS8PrivateKey_fp_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS8PrivateKey_fp)}
      d2i_PKCS8PrivateKey_fp := _d2i_PKCS8PrivateKey_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS8PrivateKey_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS8PrivateKey_fp');
    {$ifend}
  end;
  
  PEM_write_PKCS8PrivateKey := LoadLibFunction(ADllHandle, PEM_write_PKCS8PrivateKey_procname);
  FuncLoadError := not assigned(PEM_write_PKCS8PrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_PKCS8PrivateKey_allownil)}
    PEM_write_PKCS8PrivateKey := ERR_PEM_write_PKCS8PrivateKey;
    {$ifend}
    {$if declared(PEM_write_PKCS8PrivateKey_introduced)}
    if LibVersion < PEM_write_PKCS8PrivateKey_introduced then
    begin
      {$if declared(FC_PEM_write_PKCS8PrivateKey)}
      PEM_write_PKCS8PrivateKey := FC_PEM_write_PKCS8PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_PKCS8PrivateKey_removed)}
    if PEM_write_PKCS8PrivateKey_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_PKCS8PrivateKey)}
      PEM_write_PKCS8PrivateKey := _PEM_write_PKCS8PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_PKCS8PrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_PKCS8PrivateKey');
    {$ifend}
  end;
  
  PEM_read_bio_Parameters_ex := LoadLibFunction(ADllHandle, PEM_read_bio_Parameters_ex_procname);
  FuncLoadError := not assigned(PEM_read_bio_Parameters_ex);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_Parameters_ex_allownil)}
    PEM_read_bio_Parameters_ex := ERR_PEM_read_bio_Parameters_ex;
    {$ifend}
    {$if declared(PEM_read_bio_Parameters_ex_introduced)}
    if LibVersion < PEM_read_bio_Parameters_ex_introduced then
    begin
      {$if declared(FC_PEM_read_bio_Parameters_ex)}
      PEM_read_bio_Parameters_ex := FC_PEM_read_bio_Parameters_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_Parameters_ex_removed)}
    if PEM_read_bio_Parameters_ex_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_Parameters_ex)}
      PEM_read_bio_Parameters_ex := _PEM_read_bio_Parameters_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_Parameters_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_Parameters_ex');
    {$ifend}
  end;
  
  PEM_read_bio_Parameters := LoadLibFunction(ADllHandle, PEM_read_bio_Parameters_procname);
  FuncLoadError := not assigned(PEM_read_bio_Parameters);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_Parameters_allownil)}
    PEM_read_bio_Parameters := ERR_PEM_read_bio_Parameters;
    {$ifend}
    {$if declared(PEM_read_bio_Parameters_introduced)}
    if LibVersion < PEM_read_bio_Parameters_introduced then
    begin
      {$if declared(FC_PEM_read_bio_Parameters)}
      PEM_read_bio_Parameters := FC_PEM_read_bio_Parameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_Parameters_removed)}
    if PEM_read_bio_Parameters_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_Parameters)}
      PEM_read_bio_Parameters := _PEM_read_bio_Parameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_Parameters_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_Parameters');
    {$ifend}
  end;
  
  PEM_write_bio_Parameters := LoadLibFunction(ADllHandle, PEM_write_bio_Parameters_procname);
  FuncLoadError := not assigned(PEM_write_bio_Parameters);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_Parameters_allownil)}
    PEM_write_bio_Parameters := ERR_PEM_write_bio_Parameters;
    {$ifend}
    {$if declared(PEM_write_bio_Parameters_introduced)}
    if LibVersion < PEM_write_bio_Parameters_introduced then
    begin
      {$if declared(FC_PEM_write_bio_Parameters)}
      PEM_write_bio_Parameters := FC_PEM_write_bio_Parameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_Parameters_removed)}
    if PEM_write_bio_Parameters_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_Parameters)}
      PEM_write_bio_Parameters := _PEM_write_bio_Parameters;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_Parameters_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_Parameters');
    {$ifend}
  end;
  
  b2i_PrivateKey := LoadLibFunction(ADllHandle, b2i_PrivateKey_procname);
  FuncLoadError := not assigned(b2i_PrivateKey);
  if FuncLoadError then
  begin
    {$if not defined(b2i_PrivateKey_allownil)}
    b2i_PrivateKey := ERR_b2i_PrivateKey;
    {$ifend}
    {$if declared(b2i_PrivateKey_introduced)}
    if LibVersion < b2i_PrivateKey_introduced then
    begin
      {$if declared(FC_b2i_PrivateKey)}
      b2i_PrivateKey := FC_b2i_PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(b2i_PrivateKey_removed)}
    if b2i_PrivateKey_removed <= LibVersion then
    begin
      {$if declared(_b2i_PrivateKey)}
      b2i_PrivateKey := _b2i_PrivateKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(b2i_PrivateKey_allownil)}
    if FuncLoadError then
      AFailed.Add('b2i_PrivateKey');
    {$ifend}
  end;
  
  b2i_PublicKey := LoadLibFunction(ADllHandle, b2i_PublicKey_procname);
  FuncLoadError := not assigned(b2i_PublicKey);
  if FuncLoadError then
  begin
    {$if not defined(b2i_PublicKey_allownil)}
    b2i_PublicKey := ERR_b2i_PublicKey;
    {$ifend}
    {$if declared(b2i_PublicKey_introduced)}
    if LibVersion < b2i_PublicKey_introduced then
    begin
      {$if declared(FC_b2i_PublicKey)}
      b2i_PublicKey := FC_b2i_PublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(b2i_PublicKey_removed)}
    if b2i_PublicKey_removed <= LibVersion then
    begin
      {$if declared(_b2i_PublicKey)}
      b2i_PublicKey := _b2i_PublicKey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(b2i_PublicKey_allownil)}
    if FuncLoadError then
      AFailed.Add('b2i_PublicKey');
    {$ifend}
  end;
  
  b2i_PrivateKey_bio := LoadLibFunction(ADllHandle, b2i_PrivateKey_bio_procname);
  FuncLoadError := not assigned(b2i_PrivateKey_bio);
  if FuncLoadError then
  begin
    {$if not defined(b2i_PrivateKey_bio_allownil)}
    b2i_PrivateKey_bio := ERR_b2i_PrivateKey_bio;
    {$ifend}
    {$if declared(b2i_PrivateKey_bio_introduced)}
    if LibVersion < b2i_PrivateKey_bio_introduced then
    begin
      {$if declared(FC_b2i_PrivateKey_bio)}
      b2i_PrivateKey_bio := FC_b2i_PrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(b2i_PrivateKey_bio_removed)}
    if b2i_PrivateKey_bio_removed <= LibVersion then
    begin
      {$if declared(_b2i_PrivateKey_bio)}
      b2i_PrivateKey_bio := _b2i_PrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(b2i_PrivateKey_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('b2i_PrivateKey_bio');
    {$ifend}
  end;
  
  b2i_PublicKey_bio := LoadLibFunction(ADllHandle, b2i_PublicKey_bio_procname);
  FuncLoadError := not assigned(b2i_PublicKey_bio);
  if FuncLoadError then
  begin
    {$if not defined(b2i_PublicKey_bio_allownil)}
    b2i_PublicKey_bio := ERR_b2i_PublicKey_bio;
    {$ifend}
    {$if declared(b2i_PublicKey_bio_introduced)}
    if LibVersion < b2i_PublicKey_bio_introduced then
    begin
      {$if declared(FC_b2i_PublicKey_bio)}
      b2i_PublicKey_bio := FC_b2i_PublicKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(b2i_PublicKey_bio_removed)}
    if b2i_PublicKey_bio_removed <= LibVersion then
    begin
      {$if declared(_b2i_PublicKey_bio)}
      b2i_PublicKey_bio := _b2i_PublicKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(b2i_PublicKey_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('b2i_PublicKey_bio');
    {$ifend}
  end;
  
  i2b_PrivateKey_bio := LoadLibFunction(ADllHandle, i2b_PrivateKey_bio_procname);
  FuncLoadError := not assigned(i2b_PrivateKey_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2b_PrivateKey_bio_allownil)}
    i2b_PrivateKey_bio := ERR_i2b_PrivateKey_bio;
    {$ifend}
    {$if declared(i2b_PrivateKey_bio_introduced)}
    if LibVersion < i2b_PrivateKey_bio_introduced then
    begin
      {$if declared(FC_i2b_PrivateKey_bio)}
      i2b_PrivateKey_bio := FC_i2b_PrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2b_PrivateKey_bio_removed)}
    if i2b_PrivateKey_bio_removed <= LibVersion then
    begin
      {$if declared(_i2b_PrivateKey_bio)}
      i2b_PrivateKey_bio := _i2b_PrivateKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2b_PrivateKey_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2b_PrivateKey_bio');
    {$ifend}
  end;
  
  i2b_PublicKey_bio := LoadLibFunction(ADllHandle, i2b_PublicKey_bio_procname);
  FuncLoadError := not assigned(i2b_PublicKey_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2b_PublicKey_bio_allownil)}
    i2b_PublicKey_bio := ERR_i2b_PublicKey_bio;
    {$ifend}
    {$if declared(i2b_PublicKey_bio_introduced)}
    if LibVersion < i2b_PublicKey_bio_introduced then
    begin
      {$if declared(FC_i2b_PublicKey_bio)}
      i2b_PublicKey_bio := FC_i2b_PublicKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2b_PublicKey_bio_removed)}
    if i2b_PublicKey_bio_removed <= LibVersion then
    begin
      {$if declared(_i2b_PublicKey_bio)}
      i2b_PublicKey_bio := _i2b_PublicKey_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2b_PublicKey_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2b_PublicKey_bio');
    {$ifend}
  end;
  
  b2i_PVK_bio := LoadLibFunction(ADllHandle, b2i_PVK_bio_procname);
  FuncLoadError := not assigned(b2i_PVK_bio);
  if FuncLoadError then
  begin
    {$if not defined(b2i_PVK_bio_allownil)}
    b2i_PVK_bio := ERR_b2i_PVK_bio;
    {$ifend}
    {$if declared(b2i_PVK_bio_introduced)}
    if LibVersion < b2i_PVK_bio_introduced then
    begin
      {$if declared(FC_b2i_PVK_bio)}
      b2i_PVK_bio := FC_b2i_PVK_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(b2i_PVK_bio_removed)}
    if b2i_PVK_bio_removed <= LibVersion then
    begin
      {$if declared(_b2i_PVK_bio)}
      b2i_PVK_bio := _b2i_PVK_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(b2i_PVK_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('b2i_PVK_bio');
    {$ifend}
  end;
  
  b2i_PVK_bio_ex := LoadLibFunction(ADllHandle, b2i_PVK_bio_ex_procname);
  FuncLoadError := not assigned(b2i_PVK_bio_ex);
  if FuncLoadError then
  begin
    {$if not defined(b2i_PVK_bio_ex_allownil)}
    b2i_PVK_bio_ex := ERR_b2i_PVK_bio_ex;
    {$ifend}
    {$if declared(b2i_PVK_bio_ex_introduced)}
    if LibVersion < b2i_PVK_bio_ex_introduced then
    begin
      {$if declared(FC_b2i_PVK_bio_ex)}
      b2i_PVK_bio_ex := FC_b2i_PVK_bio_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(b2i_PVK_bio_ex_removed)}
    if b2i_PVK_bio_ex_removed <= LibVersion then
    begin
      {$if declared(_b2i_PVK_bio_ex)}
      b2i_PVK_bio_ex := _b2i_PVK_bio_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(b2i_PVK_bio_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('b2i_PVK_bio_ex');
    {$ifend}
  end;
  
  i2b_PVK_bio := LoadLibFunction(ADllHandle, i2b_PVK_bio_procname);
  FuncLoadError := not assigned(i2b_PVK_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2b_PVK_bio_allownil)}
    i2b_PVK_bio := ERR_i2b_PVK_bio;
    {$ifend}
    {$if declared(i2b_PVK_bio_introduced)}
    if LibVersion < i2b_PVK_bio_introduced then
    begin
      {$if declared(FC_i2b_PVK_bio)}
      i2b_PVK_bio := FC_i2b_PVK_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2b_PVK_bio_removed)}
    if i2b_PVK_bio_removed <= LibVersion then
    begin
      {$if declared(_i2b_PVK_bio)}
      i2b_PVK_bio := _i2b_PVK_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2b_PVK_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2b_PVK_bio');
    {$ifend}
  end;
  
  i2b_PVK_bio_ex := LoadLibFunction(ADllHandle, i2b_PVK_bio_ex_procname);
  FuncLoadError := not assigned(i2b_PVK_bio_ex);
  if FuncLoadError then
  begin
    {$if not defined(i2b_PVK_bio_ex_allownil)}
    i2b_PVK_bio_ex := ERR_i2b_PVK_bio_ex;
    {$ifend}
    {$if declared(i2b_PVK_bio_ex_introduced)}
    if LibVersion < i2b_PVK_bio_ex_introduced then
    begin
      {$if declared(FC_i2b_PVK_bio_ex)}
      i2b_PVK_bio_ex := FC_i2b_PVK_bio_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2b_PVK_bio_ex_removed)}
    if i2b_PVK_bio_ex_removed <= LibVersion then
    begin
      {$if declared(_i2b_PVK_bio_ex)}
      i2b_PVK_bio_ex := _i2b_PVK_bio_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2b_PVK_bio_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('i2b_PVK_bio_ex');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  PEM_get_EVP_CIPHER_INFO := nil;
  PEM_do_header := nil;
  PEM_read_bio := nil;
  PEM_read_bio_ex := nil;
  PEM_bytes_read_bio_secmem := nil;
  PEM_write_bio := nil;
  PEM_bytes_read_bio := nil;
  PEM_ASN1_read_bio := nil;
  PEM_ASN1_write_bio := nil;
  PEM_ASN1_write_bio_ctx := nil;
  PEM_X509_INFO_read_bio := nil;
  PEM_X509_INFO_read_bio_ex := nil;
  PEM_X509_INFO_write_bio := nil;
  PEM_read := nil;
  PEM_write := nil;
  PEM_ASN1_read := nil;
  PEM_ASN1_write := nil;
  PEM_X509_INFO_read := nil;
  PEM_X509_INFO_read_ex := nil;
  PEM_SignInit := nil;
  PEM_SignUpdate := nil;
  PEM_SignFinal := nil;
  PEM_def_callback := nil;
  PEM_proc_type := nil;
  PEM_dek_info := nil;
  PEM_read_bio_X509 := nil;
  PEM_read_X509 := nil;
  PEM_write_bio_X509 := nil;
  PEM_write_X509 := nil;
  PEM_read_bio_X509_AUX := nil;
  PEM_read_X509_AUX := nil;
  PEM_write_bio_X509_AUX := nil;
  PEM_write_X509_AUX := nil;
  PEM_read_bio_X509_REQ := nil;
  PEM_read_X509_REQ := nil;
  PEM_write_bio_X509_REQ := nil;
  PEM_write_X509_REQ := nil;
  PEM_write_bio_X509_REQ_NEW := nil;
  PEM_write_X509_REQ_NEW := nil;
  PEM_read_bio_X509_CRL := nil;
  PEM_read_X509_CRL := nil;
  PEM_write_bio_X509_CRL := nil;
  PEM_write_X509_CRL := nil;
  PEM_read_bio_X509_PUBKEY := nil;
  PEM_read_X509_PUBKEY := nil;
  PEM_write_bio_X509_PUBKEY := nil;
  PEM_write_X509_PUBKEY := nil;
  PEM_read_bio_PKCS7 := nil;
  PEM_read_PKCS7 := nil;
  PEM_write_bio_PKCS7 := nil;
  PEM_write_PKCS7 := nil;
  PEM_read_bio_NETSCAPE_CERT_SEQUENCE := nil;
  PEM_read_NETSCAPE_CERT_SEQUENCE := nil;
  PEM_write_bio_NETSCAPE_CERT_SEQUENCE := nil;
  PEM_write_NETSCAPE_CERT_SEQUENCE := nil;
  PEM_read_bio_PKCS8 := nil;
  PEM_read_PKCS8 := nil;
  PEM_write_bio_PKCS8 := nil;
  PEM_write_PKCS8 := nil;
  PEM_read_bio_PKCS8_PRIV_KEY_INFO := nil;
  PEM_read_PKCS8_PRIV_KEY_INFO := nil;
  PEM_write_bio_PKCS8_PRIV_KEY_INFO := nil;
  PEM_write_PKCS8_PRIV_KEY_INFO := nil;
  PEM_read_bio_RSAPrivateKey := nil;
  PEM_read_RSAPrivateKey := nil;
  PEM_write_bio_RSAPrivateKey := nil;
  PEM_write_RSAPrivateKey := nil;
  PEM_read_bio_RSAPublicKey := nil;
  PEM_read_RSAPublicKey := nil;
  PEM_write_bio_RSAPublicKey := nil;
  PEM_write_RSAPublicKey := nil;
  PEM_read_bio_RSA_PUBKEY := nil;
  PEM_read_RSA_PUBKEY := nil;
  PEM_write_bio_RSA_PUBKEY := nil;
  PEM_write_RSA_PUBKEY := nil;
  PEM_read_bio_DSAPrivateKey := nil;
  PEM_read_DSAPrivateKey := nil;
  PEM_write_bio_DSAPrivateKey := nil;
  PEM_write_DSAPrivateKey := nil;
  PEM_read_bio_DSA_PUBKEY := nil;
  PEM_read_DSA_PUBKEY := nil;
  PEM_write_bio_DSA_PUBKEY := nil;
  PEM_write_DSA_PUBKEY := nil;
  PEM_read_bio_DSAparams := nil;
  PEM_read_DSAparams := nil;
  PEM_write_bio_DSAparams := nil;
  PEM_write_DSAparams := nil;
  PEM_read_bio_ECPKParameters := nil;
  PEM_read_ECPKParameters := nil;
  PEM_write_bio_ECPKParameters := nil;
  PEM_write_ECPKParameters := nil;
  PEM_read_bio_ECPrivateKey := nil;
  PEM_read_ECPrivateKey := nil;
  PEM_write_bio_ECPrivateKey := nil;
  PEM_write_ECPrivateKey := nil;
  PEM_read_bio_EC_PUBKEY := nil;
  PEM_read_EC_PUBKEY := nil;
  PEM_write_bio_EC_PUBKEY := nil;
  PEM_write_EC_PUBKEY := nil;
  PEM_read_bio_DHparams := nil;
  PEM_read_DHparams := nil;
  PEM_write_bio_DHparams := nil;
  PEM_write_DHparams := nil;
  PEM_write_bio_DHxparams := nil;
  PEM_write_DHxparams := nil;
  PEM_read_bio_PrivateKey := nil;
  PEM_read_bio_PrivateKey_ex := nil;
  PEM_read_PrivateKey := nil;
  PEM_read_PrivateKey_ex := nil;
  PEM_write_bio_PrivateKey := nil;
  PEM_write_bio_PrivateKey_ex := nil;
  PEM_write_PrivateKey := nil;
  PEM_write_PrivateKey_ex := nil;
  PEM_read_bio_PUBKEY := nil;
  PEM_read_bio_PUBKEY_ex := nil;
  PEM_read_PUBKEY := nil;
  PEM_read_PUBKEY_ex := nil;
  PEM_write_bio_PUBKEY := nil;
  PEM_write_bio_PUBKEY_ex := nil;
  PEM_write_PUBKEY := nil;
  PEM_write_PUBKEY_ex := nil;
  PEM_write_bio_PrivateKey_traditional := nil;
  PEM_write_bio_PKCS8PrivateKey_nid := nil;
  PEM_write_bio_PKCS8PrivateKey := nil;
  i2d_PKCS8PrivateKey_bio := nil;
  i2d_PKCS8PrivateKey_nid_bio := nil;
  d2i_PKCS8PrivateKey_bio := nil;
  i2d_PKCS8PrivateKey_fp := nil;
  i2d_PKCS8PrivateKey_nid_fp := nil;
  PEM_write_PKCS8PrivateKey_nid := nil;
  d2i_PKCS8PrivateKey_fp := nil;
  PEM_write_PKCS8PrivateKey := nil;
  PEM_read_bio_Parameters_ex := nil;
  PEM_read_bio_Parameters := nil;
  PEM_write_bio_Parameters := nil;
  b2i_PrivateKey := nil;
  b2i_PublicKey := nil;
  b2i_PrivateKey_bio := nil;
  b2i_PublicKey_bio := nil;
  i2b_PrivateKey_bio := nil;
  i2b_PublicKey_bio := nil;
  b2i_PVK_bio := nil;
  b2i_PVK_bio_ex := nil;
  i2b_PVK_bio := nil;
  i2b_PVK_bio_ex := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.