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

unit TaurusTLSHeaders_pkcs7;

interface

uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_ossl_types,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_core,
  ossl_types;



// =============================================================================
// TYPE DECLARATIONS
// =============================================================================
type
  PPKCS7_CTX_st = ^TPKCS7_CTX_st;
  TPKCS7_CTX_st =   record
    libctx: POSSL_LIB_CTX;
    propq: PIdAnsiChar;
  end;
  {$EXTERNALSYM PPKCS7_CTX_st}

  Ppkcs7_issuer_and_serial_st = ^Tpkcs7_issuer_and_serial_st;
  Tpkcs7_issuer_and_serial_st =   record
    issuer: PX509_NAME;
    serial: PASN1_INTEGER;
  end;
  {$EXTERNALSYM Ppkcs7_issuer_and_serial_st}

  Ppkcs7_signer_info_st = ^Tpkcs7_signer_info_st;
  Tpkcs7_signer_info_st =   record
    version: PASN1_INTEGER;
    issuer_and_serial: PPKCS7_ISSUER_AND_SERIAL;
    digest_alg: PX509_ALGOR;
    auth_attr: Pstack_st_X509_ATTRIBUTE;
    digest_enc_alg: PX509_ALGOR;
    enc_digest: PASN1_OCTET_STRING;
    unauth_attr: Pstack_st_X509_ATTRIBUTE;
    pkey: PEVP_PKEY;
    ctx: PPKCS7_CTX;
  end;
  {$EXTERNALSYM Ppkcs7_signer_info_st}

  Ppkcs7_recip_info_st = ^Tpkcs7_recip_info_st;
  Tpkcs7_recip_info_st =   record
    version: PASN1_INTEGER;
    issuer_and_serial: PPKCS7_ISSUER_AND_SERIAL;
    key_enc_algor: PX509_ALGOR;
    enc_key: PASN1_OCTET_STRING;
    cert: PX509;
    ctx: PPKCS7_CTX;
  end;
  {$EXTERNALSYM Ppkcs7_recip_info_st}

  Ppkcs7_signed_st = ^Tpkcs7_signed_st;
  Tpkcs7_signed_st =   record
    version: PASN1_INTEGER;
    md_algs: Pstack_st_X509_ALGOR;
    cert: Pstack_st_X509;
    crl: Pstack_st_X509_CRL;
    signer_info: Pstack_st_PKCS7_SIGNER_INFO;
    contents: Ppkcs7_st;
  end;
  {$EXTERNALSYM Ppkcs7_signed_st}

  Ppkcs7_st = ^Tpkcs7_st;
  Tpkcs7_st =   record end;
  {$EXTERNALSYM Ppkcs7_st}

  Ppkcs7_enc_content_st = ^Tpkcs7_enc_content_st;
  Tpkcs7_enc_content_st =   record
    content_type: PASN1_OBJECT;
    algorithm: PX509_ALGOR;
    enc_data: PASN1_OCTET_STRING;
    cipher: PEVP_CIPHER;
    ctx: PPKCS7_CTX;
  end;
  {$EXTERNALSYM Ppkcs7_enc_content_st}

  Ppkcs7_enveloped_st = ^Tpkcs7_enveloped_st;
  Tpkcs7_enveloped_st =   record
    version: PASN1_INTEGER;
    recipientinfo: Pstack_st_PKCS7_RECIP_INFO;
    enc_data: PPKCS7_ENC_CONTENT;
  end;
  {$EXTERNALSYM Ppkcs7_enveloped_st}

  Ppkcs7_signedandenveloped_st = ^Tpkcs7_signedandenveloped_st;
  Tpkcs7_signedandenveloped_st =   record
    version: PASN1_INTEGER;
    md_algs: Pstack_st_X509_ALGOR;
    cert: Pstack_st_X509;
    crl: Pstack_st_X509_CRL;
    signer_info: Pstack_st_PKCS7_SIGNER_INFO;
    enc_data: PPKCS7_ENC_CONTENT;
    recipientinfo: Pstack_st_PKCS7_RECIP_INFO;
  end;
  {$EXTERNALSYM Ppkcs7_signedandenveloped_st}

  Ppkcs7_digest_st = ^Tpkcs7_digest_st;
  Tpkcs7_digest_st =   record
    version: PASN1_INTEGER;
    md: PX509_ALGOR;
    contents: Ppkcs7_st;
    digest: PASN1_OCTET_STRING;
  end;
  {$EXTERNALSYM Ppkcs7_digest_st}

  Ppkcs7_encrypted_st = ^Tpkcs7_encrypted_st;
  Tpkcs7_encrypted_st =   record
    version: PASN1_INTEGER;
    enc_data: PPKCS7_ENC_CONTENT;
  end;
  {$EXTERNALSYM Ppkcs7_encrypted_st}


// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  PKCS7_S_HEADER = 0;
  PKCS7_S_BODY = 1;
  PKCS7_S_TAIL = 2;
  PKCS7_OP_SET_DETACHED_SIGNATURE = 1;
  PKCS7_OP_GET_DETACHED_SIGNATURE = 2;
  PKCS7_TEXT = $1;
  PKCS7_NOCERTS = $2;
  PKCS7_NOSIGS = $4;
  PKCS7_NOCHAIN = $8;
  PKCS7_NOINTERN = $10;
  PKCS7_NOVERIFY = $20;
  PKCS7_DETACHED = $40;
  PKCS7_BINARY = $80;
  PKCS7_NOATTR = $100;
  PKCS7_NOSMIMECAP = $200;
  PKCS7_NOOLDMIMETYPE = $400;
  PKCS7_CRLFEOL = $800;
  PKCS7_STREAM = $1000;
  PKCS7_NOCRL = $2000;
  PKCS7_PARTIAL = $4000;
  PKCS7_REUSE_DIGEST = $8000;
  PKCS7_NO_DUAL_CONTENT = $10000;
  SMIME_TEXT = PKCS7_TEXT;
  SMIME_NOCERTS = PKCS7_NOCERTS;
  SMIME_NOSIGS = PKCS7_NOSIGS;
  SMIME_NOCHAIN = PKCS7_NOCHAIN;
  SMIME_NOINTERN = PKCS7_NOINTERN;
  SMIME_NOVERIFY = PKCS7_NOVERIFY;
  SMIME_DETACHED = PKCS7_DETACHED;
  SMIME_BINARY = PKCS7_BINARY;
  SMIME_NOATTR = PKCS7_NOATTR;
  SMIME_ASCIICRLF = $80000;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  PKCS7_ISSUER_AND_SERIAL_new: function: PPKCS7_ISSUER_AND_SERIAL; cdecl = nil;
  {$EXTERNALSYM PKCS7_ISSUER_AND_SERIAL_new}

  PKCS7_ISSUER_AND_SERIAL_free: procedure(a: PPKCS7_ISSUER_AND_SERIAL); cdecl = nil;
  {$EXTERNALSYM PKCS7_ISSUER_AND_SERIAL_free}

  d2i_PKCS7_ISSUER_AND_SERIAL: function(a: PPPKCS7_ISSUER_AND_SERIAL; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_ISSUER_AND_SERIAL; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS7_ISSUER_AND_SERIAL}

  i2d_PKCS7_ISSUER_AND_SERIAL: function(a: PPKCS7_ISSUER_AND_SERIAL; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS7_ISSUER_AND_SERIAL}

  PKCS7_ISSUER_AND_SERIAL_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PKCS7_ISSUER_AND_SERIAL_it}

  PKCS7_ISSUER_AND_SERIAL_digest: function(data: PPKCS7_ISSUER_AND_SERIAL; _type: PEVP_MD; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_ISSUER_AND_SERIAL_digest}

  d2i_PKCS7_fp: function(fp: PFILE; p7: PPPKCS7): PPKCS7; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS7_fp}

  i2d_PKCS7_fp: function(fp: PFILE; p7: PPKCS7): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS7_fp}

  PKCS7_dup: function(a: PPKCS7): PPKCS7; cdecl = nil;
  {$EXTERNALSYM PKCS7_dup}

  d2i_PKCS7_bio: function(bp: PBIO; p7: PPPKCS7): PPKCS7; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS7_bio}

  i2d_PKCS7_bio: function(bp: PBIO; p7: PPKCS7): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS7_bio}

  i2d_PKCS7_bio_stream: function(_out: PBIO; p7: PPKCS7; _in: PBIO; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS7_bio_stream}

  PEM_write_bio_PKCS7_stream: function(_out: PBIO; p7: PPKCS7; _in: PBIO; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_bio_PKCS7_stream}

  PKCS7_SIGNER_INFO_new: function: PPKCS7_SIGNER_INFO; cdecl = nil;
  {$EXTERNALSYM PKCS7_SIGNER_INFO_new}

  PKCS7_SIGNER_INFO_free: procedure(a: PPKCS7_SIGNER_INFO); cdecl = nil;
  {$EXTERNALSYM PKCS7_SIGNER_INFO_free}

  d2i_PKCS7_SIGNER_INFO: function(a: PPPKCS7_SIGNER_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_SIGNER_INFO; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS7_SIGNER_INFO}

  i2d_PKCS7_SIGNER_INFO: function(a: PPKCS7_SIGNER_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS7_SIGNER_INFO}

  PKCS7_SIGNER_INFO_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PKCS7_SIGNER_INFO_it}

  PKCS7_RECIP_INFO_new: function: PPKCS7_RECIP_INFO; cdecl = nil;
  {$EXTERNALSYM PKCS7_RECIP_INFO_new}

  PKCS7_RECIP_INFO_free: procedure(a: PPKCS7_RECIP_INFO); cdecl = nil;
  {$EXTERNALSYM PKCS7_RECIP_INFO_free}

  d2i_PKCS7_RECIP_INFO: function(a: PPPKCS7_RECIP_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_RECIP_INFO; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS7_RECIP_INFO}

  i2d_PKCS7_RECIP_INFO: function(a: PPKCS7_RECIP_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS7_RECIP_INFO}

  PKCS7_RECIP_INFO_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PKCS7_RECIP_INFO_it}

  PKCS7_SIGNED_new: function: PPKCS7_SIGNED; cdecl = nil;
  {$EXTERNALSYM PKCS7_SIGNED_new}

  PKCS7_SIGNED_free: procedure(a: PPKCS7_SIGNED); cdecl = nil;
  {$EXTERNALSYM PKCS7_SIGNED_free}

  d2i_PKCS7_SIGNED: function(a: PPPKCS7_SIGNED; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_SIGNED; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS7_SIGNED}

  i2d_PKCS7_SIGNED: function(a: PPKCS7_SIGNED; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS7_SIGNED}

  PKCS7_SIGNED_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PKCS7_SIGNED_it}

  PKCS7_ENC_CONTENT_new: function: PPKCS7_ENC_CONTENT; cdecl = nil;
  {$EXTERNALSYM PKCS7_ENC_CONTENT_new}

  PKCS7_ENC_CONTENT_free: procedure(a: PPKCS7_ENC_CONTENT); cdecl = nil;
  {$EXTERNALSYM PKCS7_ENC_CONTENT_free}

  d2i_PKCS7_ENC_CONTENT: function(a: PPPKCS7_ENC_CONTENT; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_ENC_CONTENT; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS7_ENC_CONTENT}

  i2d_PKCS7_ENC_CONTENT: function(a: PPKCS7_ENC_CONTENT; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS7_ENC_CONTENT}

  PKCS7_ENC_CONTENT_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PKCS7_ENC_CONTENT_it}

  PKCS7_ENVELOPE_new: function: PPKCS7_ENVELOPE; cdecl = nil;
  {$EXTERNALSYM PKCS7_ENVELOPE_new}

  PKCS7_ENVELOPE_free: procedure(a: PPKCS7_ENVELOPE); cdecl = nil;
  {$EXTERNALSYM PKCS7_ENVELOPE_free}

  d2i_PKCS7_ENVELOPE: function(a: PPPKCS7_ENVELOPE; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_ENVELOPE; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS7_ENVELOPE}

  i2d_PKCS7_ENVELOPE: function(a: PPKCS7_ENVELOPE; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS7_ENVELOPE}

  PKCS7_ENVELOPE_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PKCS7_ENVELOPE_it}

  PKCS7_SIGN_ENVELOPE_new: function: PPKCS7_SIGN_ENVELOPE; cdecl = nil;
  {$EXTERNALSYM PKCS7_SIGN_ENVELOPE_new}

  PKCS7_SIGN_ENVELOPE_free: procedure(a: PPKCS7_SIGN_ENVELOPE); cdecl = nil;
  {$EXTERNALSYM PKCS7_SIGN_ENVELOPE_free}

  d2i_PKCS7_SIGN_ENVELOPE: function(a: PPPKCS7_SIGN_ENVELOPE; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_SIGN_ENVELOPE; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS7_SIGN_ENVELOPE}

  i2d_PKCS7_SIGN_ENVELOPE: function(a: PPKCS7_SIGN_ENVELOPE; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS7_SIGN_ENVELOPE}

  PKCS7_SIGN_ENVELOPE_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PKCS7_SIGN_ENVELOPE_it}

  PKCS7_DIGEST_new: function: PPKCS7_DIGEST; cdecl = nil;
  {$EXTERNALSYM PKCS7_DIGEST_new}

  PKCS7_DIGEST_free: procedure(a: PPKCS7_DIGEST); cdecl = nil;
  {$EXTERNALSYM PKCS7_DIGEST_free}

  d2i_PKCS7_DIGEST: function(a: PPPKCS7_DIGEST; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_DIGEST; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS7_DIGEST}

  i2d_PKCS7_DIGEST: function(a: PPKCS7_DIGEST; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS7_DIGEST}

  PKCS7_DIGEST_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PKCS7_DIGEST_it}

  PKCS7_ENCRYPT_new: function: PPKCS7_ENCRYPT; cdecl = nil;
  {$EXTERNALSYM PKCS7_ENCRYPT_new}

  PKCS7_ENCRYPT_free: procedure(a: PPKCS7_ENCRYPT); cdecl = nil;
  {$EXTERNALSYM PKCS7_ENCRYPT_free}

  d2i_PKCS7_ENCRYPT: function(a: PPPKCS7_ENCRYPT; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_ENCRYPT; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS7_ENCRYPT}

  i2d_PKCS7_ENCRYPT: function(a: PPKCS7_ENCRYPT; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS7_ENCRYPT}

  PKCS7_ENCRYPT_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PKCS7_ENCRYPT_it}

  PKCS7_new: function: PPKCS7; cdecl = nil;
  {$EXTERNALSYM PKCS7_new}

  PKCS7_free: procedure(a: PPKCS7); cdecl = nil;
  {$EXTERNALSYM PKCS7_free}

  d2i_PKCS7: function(a: PPPKCS7; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7; cdecl = nil;
  {$EXTERNALSYM d2i_PKCS7}

  i2d_PKCS7: function(a: PPKCS7; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS7}

  PKCS7_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PKCS7_it}

  PKCS7_new_ex: function(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS7; cdecl = nil;
  {$EXTERNALSYM PKCS7_new_ex}

  PKCS7_ATTR_SIGN_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PKCS7_ATTR_SIGN_it}

  PKCS7_ATTR_VERIFY_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM PKCS7_ATTR_VERIFY_it}

  i2d_PKCS7_NDEF: function(a: PPKCS7; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_PKCS7_NDEF}

  PKCS7_print_ctx: function(_out: PBIO; x: PPKCS7; indent: TIdC_INT; pctx: PASN1_PCTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_print_ctx}

  PKCS7_ctrl: function(p7: PPKCS7; cmd: TIdC_INT; larg: TIdC_LONG; parg: PIdAnsiChar): TIdC_LONG; cdecl = nil;
  {$EXTERNALSYM PKCS7_ctrl}

  PKCS7_type_is_other: function(p7: PPKCS7): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_type_is_other}

  PKCS7_set_type: function(p7: PPKCS7; _type: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_set_type}

  PKCS7_set0_type_other: function(p7: PPKCS7; _type: TIdC_INT; other: PASN1_TYPE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_set0_type_other}

  PKCS7_set_content: function(p7: PPKCS7; p7_data: PPKCS7): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_set_content}

  PKCS7_SIGNER_INFO_set: function(p7i: PPKCS7_SIGNER_INFO; x509: PX509; pkey: PEVP_PKEY; dgst: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_SIGNER_INFO_set}

  PKCS7_SIGNER_INFO_sign: function(si: PPKCS7_SIGNER_INFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_SIGNER_INFO_sign}

  PKCS7_add_signer: function(p7: PPKCS7; p7i: PPKCS7_SIGNER_INFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_add_signer}

  PKCS7_add_certificate: function(p7: PPKCS7; cert: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_add_certificate}

  PKCS7_add_crl: function(p7: PPKCS7; crl: PX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_add_crl}

  PKCS7_content_new: function(p7: PPKCS7; nid: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_content_new}

  PKCS7_dataVerify: function(cert_store: PX509_STORE; ctx: PX509_STORE_CTX; bio: PBIO; p7: PPKCS7; si: PPKCS7_SIGNER_INFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_dataVerify}

  PKCS7_signatureVerify: function(bio: PBIO; p7: PPKCS7; si: PPKCS7_SIGNER_INFO; signer: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_signatureVerify}

  PKCS7_dataInit: function(p7: PPKCS7; bio: PBIO): PBIO; cdecl = nil;
  {$EXTERNALSYM PKCS7_dataInit}

  PKCS7_dataFinal: function(p7: PPKCS7; bio: PBIO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_dataFinal}

  PKCS7_dataDecode: function(p7: PPKCS7; pkey: PEVP_PKEY; in_bio: PBIO; pcert: PX509): PBIO; cdecl = nil;
  {$EXTERNALSYM PKCS7_dataDecode}

  PKCS7_add_signature: function(p7: PPKCS7; x509: PX509; pkey: PEVP_PKEY; dgst: PEVP_MD): PPKCS7_SIGNER_INFO; cdecl = nil;
  {$EXTERNALSYM PKCS7_add_signature}

  PKCS7_cert_from_signer_info: function(p7: PPKCS7; si: PPKCS7_SIGNER_INFO): PX509; cdecl = nil;
  {$EXTERNALSYM PKCS7_cert_from_signer_info}

  PKCS7_set_digest: function(p7: PPKCS7; md: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_set_digest}

  PKCS7_get_signer_info: function(p7: PPKCS7): Pstack_st_PKCS7_SIGNER_INFO; cdecl = nil;
  {$EXTERNALSYM PKCS7_get_signer_info}

  PKCS7_add_recipient: function(p7: PPKCS7; x509: PX509): PPKCS7_RECIP_INFO; cdecl = nil;
  {$EXTERNALSYM PKCS7_add_recipient}

  PKCS7_SIGNER_INFO_get0_algs: procedure(si: PPKCS7_SIGNER_INFO; pk: PPEVP_PKEY; pdig: PPX509_ALGOR; psig: PPX509_ALGOR); cdecl = nil;
  {$EXTERNALSYM PKCS7_SIGNER_INFO_get0_algs}

  PKCS7_RECIP_INFO_get0_alg: procedure(ri: PPKCS7_RECIP_INFO; penc: PPX509_ALGOR); cdecl = nil;
  {$EXTERNALSYM PKCS7_RECIP_INFO_get0_alg}

  PKCS7_add_recipient_info: function(p7: PPKCS7; ri: PPKCS7_RECIP_INFO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_add_recipient_info}

  PKCS7_RECIP_INFO_set: function(p7i: PPKCS7_RECIP_INFO; x509: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_RECIP_INFO_set}

  PKCS7_set_cipher: function(p7: PPKCS7; cipher: PEVP_CIPHER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_set_cipher}

  PKCS7_stream: function(boundary: PPPIdAnsiChar; p7: PPKCS7): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_stream}

  PKCS7_get_issuer_and_serial: function(p7: PPKCS7; idx: TIdC_INT): PPKCS7_ISSUER_AND_SERIAL; cdecl = nil;
  {$EXTERNALSYM PKCS7_get_issuer_and_serial}

  PKCS7_get_octet_string: function(p7: PPKCS7): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM PKCS7_get_octet_string}

  PKCS7_digest_from_attributes: function(sk: Pstack_st_X509_ATTRIBUTE): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM PKCS7_digest_from_attributes}

  PKCS7_add_signed_attribute: function(p7si: PPKCS7_SIGNER_INFO; nid: TIdC_INT; _type: TIdC_INT; data: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_add_signed_attribute}

  PKCS7_add_attribute: function(p7si: PPKCS7_SIGNER_INFO; nid: TIdC_INT; atrtype: TIdC_INT; value: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_add_attribute}

  PKCS7_get_attribute: function(si: PPKCS7_SIGNER_INFO; nid: TIdC_INT): PASN1_TYPE; cdecl = nil;
  {$EXTERNALSYM PKCS7_get_attribute}

  PKCS7_get_signed_attribute: function(si: PPKCS7_SIGNER_INFO; nid: TIdC_INT): PASN1_TYPE; cdecl = nil;
  {$EXTERNALSYM PKCS7_get_signed_attribute}

  PKCS7_set_signed_attributes: function(p7si: PPKCS7_SIGNER_INFO; sk: Pstack_st_X509_ATTRIBUTE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_set_signed_attributes}

  PKCS7_set_attributes: function(p7si: PPKCS7_SIGNER_INFO; sk: Pstack_st_X509_ATTRIBUTE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_set_attributes}

  PKCS7_sign: function(signcert: PX509; pkey: PEVP_PKEY; certs: Pstack_st_X509; data: PBIO; flags: TIdC_INT): PPKCS7; cdecl = nil;
  {$EXTERNALSYM PKCS7_sign}

  PKCS7_sign_ex: function(signcert: PX509; pkey: PEVP_PKEY; certs: Pstack_st_X509; data: PBIO; flags: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS7; cdecl = nil;
  {$EXTERNALSYM PKCS7_sign_ex}

  PKCS7_sign_add_signer: function(p7: PPKCS7; signcert: PX509; pkey: PEVP_PKEY; md: PEVP_MD; flags: TIdC_INT): PPKCS7_SIGNER_INFO; cdecl = nil;
  {$EXTERNALSYM PKCS7_sign_add_signer}

  PKCS7_final: function(p7: PPKCS7; data: PBIO; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_final}

  PKCS7_verify: function(p7: PPKCS7; certs: Pstack_st_X509; store: PX509_STORE; indata: PBIO; _out: PBIO; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_verify}

  PKCS7_get0_signers: function(p7: PPKCS7; certs: Pstack_st_X509; flags: TIdC_INT): Pstack_st_X509; cdecl = nil;
  {$EXTERNALSYM PKCS7_get0_signers}

  PKCS7_encrypt: function(certs: Pstack_st_X509; _in: PBIO; cipher: PEVP_CIPHER; flags: TIdC_INT): PPKCS7; cdecl = nil;
  {$EXTERNALSYM PKCS7_encrypt}

  PKCS7_encrypt_ex: function(certs: Pstack_st_X509; _in: PBIO; cipher: PEVP_CIPHER; flags: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS7; cdecl = nil;
  {$EXTERNALSYM PKCS7_encrypt_ex}

  PKCS7_decrypt: function(p7: PPKCS7; pkey: PEVP_PKEY; cert: PX509; data: PBIO; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_decrypt}

  PKCS7_add_attrib_smimecap: function(si: PPKCS7_SIGNER_INFO; cap: Pstack_st_X509_ALGOR): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_add_attrib_smimecap}

  PKCS7_get_smimecap: function(si: PPKCS7_SIGNER_INFO): Pstack_st_X509_ALGOR; cdecl = nil;
  {$EXTERNALSYM PKCS7_get_smimecap}

  PKCS7_simple_smimecap: function(sk: Pstack_st_X509_ALGOR; nid: TIdC_INT; arg: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_simple_smimecap}

  PKCS7_add_attrib_content_type: function(si: PPKCS7_SIGNER_INFO; coid: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_add_attrib_content_type}

  PKCS7_add0_attrib_signing_time: function(si: PPKCS7_SIGNER_INFO; t: PASN1_TIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_add0_attrib_signing_time}

  PKCS7_add1_attrib_digest: function(si: PPKCS7_SIGNER_INFO; md: PIdAnsiChar; mdlen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PKCS7_add1_attrib_digest}

  SMIME_write_PKCS7: function(bio: PBIO; p7: PPKCS7; data: PBIO; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SMIME_write_PKCS7}

  SMIME_read_PKCS7_ex: function(bio: PBIO; bcont: PPBIO; p7: PPPKCS7): PPKCS7; cdecl = nil;
  {$EXTERNALSYM SMIME_read_PKCS7_ex}

  SMIME_read_PKCS7: function(bio: PBIO; bcont: PPBIO): PPKCS7; cdecl = nil;
  {$EXTERNALSYM SMIME_read_PKCS7}

  BIO_new_PKCS7: function(_out: PBIO; p7: PPKCS7): PBIO; cdecl = nil;
  {$EXTERNALSYM BIO_new_PKCS7}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function PKCS7_ISSUER_AND_SERIAL_new: PPKCS7_ISSUER_AND_SERIAL; cdecl;
procedure PKCS7_ISSUER_AND_SERIAL_free(a: PPKCS7_ISSUER_AND_SERIAL); cdecl;
function d2i_PKCS7_ISSUER_AND_SERIAL(a: PPPKCS7_ISSUER_AND_SERIAL; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_ISSUER_AND_SERIAL; cdecl;
function i2d_PKCS7_ISSUER_AND_SERIAL(a: PPKCS7_ISSUER_AND_SERIAL; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function PKCS7_ISSUER_AND_SERIAL_it: PASN1_ITEM; cdecl;
function PKCS7_ISSUER_AND_SERIAL_digest(data: PPKCS7_ISSUER_AND_SERIAL; _type: PEVP_MD; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl;
function d2i_PKCS7_fp(fp: PFILE; p7: PPPKCS7): PPKCS7; cdecl;
function i2d_PKCS7_fp(fp: PFILE; p7: PPKCS7): TIdC_INT; cdecl;
function PKCS7_dup(a: PPKCS7): PPKCS7; cdecl;
function d2i_PKCS7_bio(bp: PBIO; p7: PPPKCS7): PPKCS7; cdecl;
function i2d_PKCS7_bio(bp: PBIO; p7: PPKCS7): TIdC_INT; cdecl;
function i2d_PKCS7_bio_stream(_out: PBIO; p7: PPKCS7; _in: PBIO; flags: TIdC_INT): TIdC_INT; cdecl;
function PEM_write_bio_PKCS7_stream(_out: PBIO; p7: PPKCS7; _in: PBIO; flags: TIdC_INT): TIdC_INT; cdecl;
function PKCS7_SIGNER_INFO_new: PPKCS7_SIGNER_INFO; cdecl;
procedure PKCS7_SIGNER_INFO_free(a: PPKCS7_SIGNER_INFO); cdecl;
function d2i_PKCS7_SIGNER_INFO(a: PPPKCS7_SIGNER_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_SIGNER_INFO; cdecl;
function i2d_PKCS7_SIGNER_INFO(a: PPKCS7_SIGNER_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function PKCS7_SIGNER_INFO_it: PASN1_ITEM; cdecl;
function PKCS7_RECIP_INFO_new: PPKCS7_RECIP_INFO; cdecl;
procedure PKCS7_RECIP_INFO_free(a: PPKCS7_RECIP_INFO); cdecl;
function d2i_PKCS7_RECIP_INFO(a: PPPKCS7_RECIP_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_RECIP_INFO; cdecl;
function i2d_PKCS7_RECIP_INFO(a: PPKCS7_RECIP_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function PKCS7_RECIP_INFO_it: PASN1_ITEM; cdecl;
function PKCS7_SIGNED_new: PPKCS7_SIGNED; cdecl;
procedure PKCS7_SIGNED_free(a: PPKCS7_SIGNED); cdecl;
function d2i_PKCS7_SIGNED(a: PPPKCS7_SIGNED; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_SIGNED; cdecl;
function i2d_PKCS7_SIGNED(a: PPKCS7_SIGNED; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function PKCS7_SIGNED_it: PASN1_ITEM; cdecl;
function PKCS7_ENC_CONTENT_new: PPKCS7_ENC_CONTENT; cdecl;
procedure PKCS7_ENC_CONTENT_free(a: PPKCS7_ENC_CONTENT); cdecl;
function d2i_PKCS7_ENC_CONTENT(a: PPPKCS7_ENC_CONTENT; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_ENC_CONTENT; cdecl;
function i2d_PKCS7_ENC_CONTENT(a: PPKCS7_ENC_CONTENT; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function PKCS7_ENC_CONTENT_it: PASN1_ITEM; cdecl;
function PKCS7_ENVELOPE_new: PPKCS7_ENVELOPE; cdecl;
procedure PKCS7_ENVELOPE_free(a: PPKCS7_ENVELOPE); cdecl;
function d2i_PKCS7_ENVELOPE(a: PPPKCS7_ENVELOPE; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_ENVELOPE; cdecl;
function i2d_PKCS7_ENVELOPE(a: PPKCS7_ENVELOPE; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function PKCS7_ENVELOPE_it: PASN1_ITEM; cdecl;
function PKCS7_SIGN_ENVELOPE_new: PPKCS7_SIGN_ENVELOPE; cdecl;
procedure PKCS7_SIGN_ENVELOPE_free(a: PPKCS7_SIGN_ENVELOPE); cdecl;
function d2i_PKCS7_SIGN_ENVELOPE(a: PPPKCS7_SIGN_ENVELOPE; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_SIGN_ENVELOPE; cdecl;
function i2d_PKCS7_SIGN_ENVELOPE(a: PPKCS7_SIGN_ENVELOPE; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function PKCS7_SIGN_ENVELOPE_it: PASN1_ITEM; cdecl;
function PKCS7_DIGEST_new: PPKCS7_DIGEST; cdecl;
procedure PKCS7_DIGEST_free(a: PPKCS7_DIGEST); cdecl;
function d2i_PKCS7_DIGEST(a: PPPKCS7_DIGEST; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_DIGEST; cdecl;
function i2d_PKCS7_DIGEST(a: PPKCS7_DIGEST; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function PKCS7_DIGEST_it: PASN1_ITEM; cdecl;
function PKCS7_ENCRYPT_new: PPKCS7_ENCRYPT; cdecl;
procedure PKCS7_ENCRYPT_free(a: PPKCS7_ENCRYPT); cdecl;
function d2i_PKCS7_ENCRYPT(a: PPPKCS7_ENCRYPT; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_ENCRYPT; cdecl;
function i2d_PKCS7_ENCRYPT(a: PPKCS7_ENCRYPT; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function PKCS7_ENCRYPT_it: PASN1_ITEM; cdecl;
function PKCS7_new: PPKCS7; cdecl;
procedure PKCS7_free(a: PPKCS7); cdecl;
function d2i_PKCS7(a: PPPKCS7; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7; cdecl;
function i2d_PKCS7(a: PPKCS7; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function PKCS7_it: PASN1_ITEM; cdecl;
function PKCS7_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS7; cdecl;
function PKCS7_ATTR_SIGN_it: PASN1_ITEM; cdecl;
function PKCS7_ATTR_VERIFY_it: PASN1_ITEM; cdecl;
function i2d_PKCS7_NDEF(a: PPKCS7; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function PKCS7_print_ctx(_out: PBIO; x: PPKCS7; indent: TIdC_INT; pctx: PASN1_PCTX): TIdC_INT; cdecl;
function PKCS7_ctrl(p7: PPKCS7; cmd: TIdC_INT; larg: TIdC_LONG; parg: PIdAnsiChar): TIdC_LONG; cdecl;
function PKCS7_type_is_other(p7: PPKCS7): TIdC_INT; cdecl;
function PKCS7_set_type(p7: PPKCS7; _type: TIdC_INT): TIdC_INT; cdecl;
function PKCS7_set0_type_other(p7: PPKCS7; _type: TIdC_INT; other: PASN1_TYPE): TIdC_INT; cdecl;
function PKCS7_set_content(p7: PPKCS7; p7_data: PPKCS7): TIdC_INT; cdecl;
function PKCS7_SIGNER_INFO_set(p7i: PPKCS7_SIGNER_INFO; x509: PX509; pkey: PEVP_PKEY; dgst: PEVP_MD): TIdC_INT; cdecl;
function PKCS7_SIGNER_INFO_sign(si: PPKCS7_SIGNER_INFO): TIdC_INT; cdecl;
function PKCS7_add_signer(p7: PPKCS7; p7i: PPKCS7_SIGNER_INFO): TIdC_INT; cdecl;
function PKCS7_add_certificate(p7: PPKCS7; cert: PX509): TIdC_INT; cdecl;
function PKCS7_add_crl(p7: PPKCS7; crl: PX509_CRL): TIdC_INT; cdecl;
function PKCS7_content_new(p7: PPKCS7; nid: TIdC_INT): TIdC_INT; cdecl;
function PKCS7_dataVerify(cert_store: PX509_STORE; ctx: PX509_STORE_CTX; bio: PBIO; p7: PPKCS7; si: PPKCS7_SIGNER_INFO): TIdC_INT; cdecl;
function PKCS7_signatureVerify(bio: PBIO; p7: PPKCS7; si: PPKCS7_SIGNER_INFO; signer: PX509): TIdC_INT; cdecl;
function PKCS7_dataInit(p7: PPKCS7; bio: PBIO): PBIO; cdecl;
function PKCS7_dataFinal(p7: PPKCS7; bio: PBIO): TIdC_INT; cdecl;
function PKCS7_dataDecode(p7: PPKCS7; pkey: PEVP_PKEY; in_bio: PBIO; pcert: PX509): PBIO; cdecl;
function PKCS7_add_signature(p7: PPKCS7; x509: PX509; pkey: PEVP_PKEY; dgst: PEVP_MD): PPKCS7_SIGNER_INFO; cdecl;
function PKCS7_cert_from_signer_info(p7: PPKCS7; si: PPKCS7_SIGNER_INFO): PX509; cdecl;
function PKCS7_set_digest(p7: PPKCS7; md: PEVP_MD): TIdC_INT; cdecl;
function PKCS7_get_signer_info(p7: PPKCS7): Pstack_st_PKCS7_SIGNER_INFO; cdecl;
function PKCS7_add_recipient(p7: PPKCS7; x509: PX509): PPKCS7_RECIP_INFO; cdecl;
procedure PKCS7_SIGNER_INFO_get0_algs(si: PPKCS7_SIGNER_INFO; pk: PPEVP_PKEY; pdig: PPX509_ALGOR; psig: PPX509_ALGOR); cdecl;
procedure PKCS7_RECIP_INFO_get0_alg(ri: PPKCS7_RECIP_INFO; penc: PPX509_ALGOR); cdecl;
function PKCS7_add_recipient_info(p7: PPKCS7; ri: PPKCS7_RECIP_INFO): TIdC_INT; cdecl;
function PKCS7_RECIP_INFO_set(p7i: PPKCS7_RECIP_INFO; x509: PX509): TIdC_INT; cdecl;
function PKCS7_set_cipher(p7: PPKCS7; cipher: PEVP_CIPHER): TIdC_INT; cdecl;
function PKCS7_stream(boundary: PPPIdAnsiChar; p7: PPKCS7): TIdC_INT; cdecl;
function PKCS7_get_issuer_and_serial(p7: PPKCS7; idx: TIdC_INT): PPKCS7_ISSUER_AND_SERIAL; cdecl;
function PKCS7_get_octet_string(p7: PPKCS7): PASN1_OCTET_STRING; cdecl;
function PKCS7_digest_from_attributes(sk: Pstack_st_X509_ATTRIBUTE): PASN1_OCTET_STRING; cdecl;
function PKCS7_add_signed_attribute(p7si: PPKCS7_SIGNER_INFO; nid: TIdC_INT; _type: TIdC_INT; data: Pointer): TIdC_INT; cdecl;
function PKCS7_add_attribute(p7si: PPKCS7_SIGNER_INFO; nid: TIdC_INT; atrtype: TIdC_INT; value: Pointer): TIdC_INT; cdecl;
function PKCS7_get_attribute(si: PPKCS7_SIGNER_INFO; nid: TIdC_INT): PASN1_TYPE; cdecl;
function PKCS7_get_signed_attribute(si: PPKCS7_SIGNER_INFO; nid: TIdC_INT): PASN1_TYPE; cdecl;
function PKCS7_set_signed_attributes(p7si: PPKCS7_SIGNER_INFO; sk: Pstack_st_X509_ATTRIBUTE): TIdC_INT; cdecl;
function PKCS7_set_attributes(p7si: PPKCS7_SIGNER_INFO; sk: Pstack_st_X509_ATTRIBUTE): TIdC_INT; cdecl;
function PKCS7_sign(signcert: PX509; pkey: PEVP_PKEY; certs: Pstack_st_X509; data: PBIO; flags: TIdC_INT): PPKCS7; cdecl;
function PKCS7_sign_ex(signcert: PX509; pkey: PEVP_PKEY; certs: Pstack_st_X509; data: PBIO; flags: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS7; cdecl;
function PKCS7_sign_add_signer(p7: PPKCS7; signcert: PX509; pkey: PEVP_PKEY; md: PEVP_MD; flags: TIdC_INT): PPKCS7_SIGNER_INFO; cdecl;
function PKCS7_final(p7: PPKCS7; data: PBIO; flags: TIdC_INT): TIdC_INT; cdecl;
function PKCS7_verify(p7: PPKCS7; certs: Pstack_st_X509; store: PX509_STORE; indata: PBIO; _out: PBIO; flags: TIdC_INT): TIdC_INT; cdecl;
function PKCS7_get0_signers(p7: PPKCS7; certs: Pstack_st_X509; flags: TIdC_INT): Pstack_st_X509; cdecl;
function PKCS7_encrypt(certs: Pstack_st_X509; _in: PBIO; cipher: PEVP_CIPHER; flags: TIdC_INT): PPKCS7; cdecl;
function PKCS7_encrypt_ex(certs: Pstack_st_X509; _in: PBIO; cipher: PEVP_CIPHER; flags: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS7; cdecl;
function PKCS7_decrypt(p7: PPKCS7; pkey: PEVP_PKEY; cert: PX509; data: PBIO; flags: TIdC_INT): TIdC_INT; cdecl;
function PKCS7_add_attrib_smimecap(si: PPKCS7_SIGNER_INFO; cap: Pstack_st_X509_ALGOR): TIdC_INT; cdecl;
function PKCS7_get_smimecap(si: PPKCS7_SIGNER_INFO): Pstack_st_X509_ALGOR; cdecl;
function PKCS7_simple_smimecap(sk: Pstack_st_X509_ALGOR; nid: TIdC_INT; arg: TIdC_INT): TIdC_INT; cdecl;
function PKCS7_add_attrib_content_type(si: PPKCS7_SIGNER_INFO; coid: PASN1_OBJECT): TIdC_INT; cdecl;
function PKCS7_add0_attrib_signing_time(si: PPKCS7_SIGNER_INFO; t: PASN1_TIME): TIdC_INT; cdecl;
function PKCS7_add1_attrib_digest(si: PPKCS7_SIGNER_INFO; md: PIdAnsiChar; mdlen: TIdC_INT): TIdC_INT; cdecl;
function SMIME_write_PKCS7(bio: PBIO; p7: PPKCS7; data: PBIO; flags: TIdC_INT): TIdC_INT; cdecl;
function SMIME_read_PKCS7_ex(bio: PBIO; bcont: PPBIO; p7: PPPKCS7): PPKCS7; cdecl;
function SMIME_read_PKCS7(bio: PBIO; bcont: PPBIO): PPKCS7; cdecl;
function BIO_new_PKCS7(_out: PBIO; p7: PPKCS7): PBIO; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// OPENSSL STACK DEFINITIONS
// =============================================================================
type
  { TODO 1 -copenssl stack PKCS7_SIGNER_INFO definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_PKCS7_SIGNER_INFO = Pointer;
  {$EXTERNALSYM PSTACK_OF_PKCS7_SIGNER_INFO}

  { Original Stack Macros for PKCS7_SIGNER_INFO:
    SKM_DEFINE_STACK_OF_INTERNAL(PKCS7_SIGNER_INFO, PKCS7_SIGNER_INFO, PKCS7_SIGNER_INFO)
    sk_PKCS7_SIGNER_INFO_num(sk) OPENSSL_sk_num(ossl_check_const_PKCS7_SIGNER_INFO_sk_type(sk))
    sk_PKCS7_SIGNER_INFO_value(sk, idx) ((PKCS7_SIGNER_INFO *)OPENSSL_sk_value(ossl_check_const_PKCS7_SIGNER_INFO_sk_type(sk), (idx)))
    sk_PKCS7_SIGNER_INFO_new(cmp) ((STACK_OF(PKCS7_SIGNER_INFO) *)OPENSSL_sk_new(ossl_check_PKCS7_SIGNER_INFO_compfunc_type(cmp)))
    sk_PKCS7_SIGNER_INFO_new_null() ((STACK_OF(PKCS7_SIGNER_INFO) *)OPENSSL_sk_new_null())
    sk_PKCS7_SIGNER_INFO_new_reserve(cmp, n) ((STACK_OF(PKCS7_SIGNER_INFO) *)OPENSSL_sk_new_reserve(ossl_check_PKCS7_SIGNER_INFO_compfunc_type(cmp), (n)))
    sk_PKCS7_SIGNER_INFO_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_PKCS7_SIGNER_INFO_sk_type(sk), (n))
    sk_PKCS7_SIGNER_INFO_free(sk) OPENSSL_sk_free(ossl_check_PKCS7_SIGNER_INFO_sk_type(sk))
    sk_PKCS7_SIGNER_INFO_zero(sk) OPENSSL_sk_zero(ossl_check_PKCS7_SIGNER_INFO_sk_type(sk))
    sk_PKCS7_SIGNER_INFO_delete(sk, i) ((PKCS7_SIGNER_INFO *)OPENSSL_sk_delete(ossl_check_PKCS7_SIGNER_INFO_sk_type(sk), (i)))
    sk_PKCS7_SIGNER_INFO_delete_ptr(sk, ptr) ((PKCS7_SIGNER_INFO *)OPENSSL_sk_delete_ptr(ossl_check_PKCS7_SIGNER_INFO_sk_type(sk), ossl_check_PKCS7_SIGNER_INFO_type(ptr)))
    sk_PKCS7_SIGNER_INFO_push(sk, ptr) OPENSSL_sk_push(ossl_check_PKCS7_SIGNER_INFO_sk_type(sk), ossl_check_PKCS7_SIGNER_INFO_type(ptr))
    sk_PKCS7_SIGNER_INFO_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_PKCS7_SIGNER_INFO_sk_type(sk), ossl_check_PKCS7_SIGNER_INFO_type(ptr))
    sk_PKCS7_SIGNER_INFO_pop(sk) ((PKCS7_SIGNER_INFO *)OPENSSL_sk_pop(ossl_check_PKCS7_SIGNER_INFO_sk_type(sk)))
    sk_PKCS7_SIGNER_INFO_shift(sk) ((PKCS7_SIGNER_INFO *)OPENSSL_sk_shift(ossl_check_PKCS7_SIGNER_INFO_sk_type(sk)))
    sk_PKCS7_SIGNER_INFO_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_PKCS7_SIGNER_INFO_sk_type(sk), ossl_check_PKCS7_SIGNER_INFO_freefunc_type(freefunc))
    sk_PKCS7_SIGNER_INFO_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_PKCS7_SIGNER_INFO_sk_type(sk), ossl_check_PKCS7_SIGNER_INFO_type(ptr), (idx))
    sk_PKCS7_SIGNER_INFO_set(sk, idx, ptr) ((PKCS7_SIGNER_INFO *)OPENSSL_sk_set(ossl_check_PKCS7_SIGNER_INFO_sk_type(sk), (idx), ossl_check_PKCS7_SIGNER_INFO_type(ptr)))
    sk_PKCS7_SIGNER_INFO_find(sk, ptr) OPENSSL_sk_find(ossl_check_PKCS7_SIGNER_INFO_sk_type(sk), ossl_check_PKCS7_SIGNER_INFO_type(ptr))
    sk_PKCS7_SIGNER_INFO_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_PKCS7_SIGNER_INFO_sk_type(sk), ossl_check_PKCS7_SIGNER_INFO_type(ptr))
    sk_PKCS7_SIGNER_INFO_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_PKCS7_SIGNER_INFO_sk_type(sk), ossl_check_PKCS7_SIGNER_INFO_type(ptr), pnum)
    sk_PKCS7_SIGNER_INFO_sort(sk) OPENSSL_sk_sort(ossl_check_PKCS7_SIGNER_INFO_sk_type(sk))
    sk_PKCS7_SIGNER_INFO_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_PKCS7_SIGNER_INFO_sk_type(sk))
    sk_PKCS7_SIGNER_INFO_dup(sk) ((STACK_OF(PKCS7_SIGNER_INFO) *)OPENSSL_sk_dup(ossl_check_const_PKCS7_SIGNER_INFO_sk_type(sk)))
    sk_PKCS7_SIGNER_INFO_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(PKCS7_SIGNER_INFO) *)OPENSSL_sk_deep_copy(ossl_check_const_PKCS7_SIGNER_INFO_sk_type(sk), ossl_check_PKCS7_SIGNER_INFO_copyfunc_type(copyfunc), ossl_check_PKCS7_SIGNER_INFO_freefunc_type(freefunc)))
    sk_PKCS7_SIGNER_INFO_set_cmp_func(sk, cmp) ((sk_PKCS7_SIGNER_INFO_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_PKCS7_SIGNER_INFO_sk_type(sk), ossl_check_PKCS7_SIGNER_INFO_compfunc_type(cmp)))
  }

  { TODO 1 -copenssl stack PKCS7_RECIP_INFO definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_PKCS7_RECIP_INFO = Pointer;
  {$EXTERNALSYM PSTACK_OF_PKCS7_RECIP_INFO}

  { Original Stack Macros for PKCS7_RECIP_INFO:
    SKM_DEFINE_STACK_OF_INTERNAL(PKCS7_RECIP_INFO, PKCS7_RECIP_INFO, PKCS7_RECIP_INFO)
    sk_PKCS7_RECIP_INFO_num(sk) OPENSSL_sk_num(ossl_check_const_PKCS7_RECIP_INFO_sk_type(sk))
    sk_PKCS7_RECIP_INFO_value(sk, idx) ((PKCS7_RECIP_INFO *)OPENSSL_sk_value(ossl_check_const_PKCS7_RECIP_INFO_sk_type(sk), (idx)))
    sk_PKCS7_RECIP_INFO_new(cmp) ((STACK_OF(PKCS7_RECIP_INFO) *)OPENSSL_sk_new(ossl_check_PKCS7_RECIP_INFO_compfunc_type(cmp)))
    sk_PKCS7_RECIP_INFO_new_null() ((STACK_OF(PKCS7_RECIP_INFO) *)OPENSSL_sk_new_null())
    sk_PKCS7_RECIP_INFO_new_reserve(cmp, n) ((STACK_OF(PKCS7_RECIP_INFO) *)OPENSSL_sk_new_reserve(ossl_check_PKCS7_RECIP_INFO_compfunc_type(cmp), (n)))
    sk_PKCS7_RECIP_INFO_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_PKCS7_RECIP_INFO_sk_type(sk), (n))
    sk_PKCS7_RECIP_INFO_free(sk) OPENSSL_sk_free(ossl_check_PKCS7_RECIP_INFO_sk_type(sk))
    sk_PKCS7_RECIP_INFO_zero(sk) OPENSSL_sk_zero(ossl_check_PKCS7_RECIP_INFO_sk_type(sk))
    sk_PKCS7_RECIP_INFO_delete(sk, i) ((PKCS7_RECIP_INFO *)OPENSSL_sk_delete(ossl_check_PKCS7_RECIP_INFO_sk_type(sk), (i)))
    sk_PKCS7_RECIP_INFO_delete_ptr(sk, ptr) ((PKCS7_RECIP_INFO *)OPENSSL_sk_delete_ptr(ossl_check_PKCS7_RECIP_INFO_sk_type(sk), ossl_check_PKCS7_RECIP_INFO_type(ptr)))
    sk_PKCS7_RECIP_INFO_push(sk, ptr) OPENSSL_sk_push(ossl_check_PKCS7_RECIP_INFO_sk_type(sk), ossl_check_PKCS7_RECIP_INFO_type(ptr))
    sk_PKCS7_RECIP_INFO_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_PKCS7_RECIP_INFO_sk_type(sk), ossl_check_PKCS7_RECIP_INFO_type(ptr))
    sk_PKCS7_RECIP_INFO_pop(sk) ((PKCS7_RECIP_INFO *)OPENSSL_sk_pop(ossl_check_PKCS7_RECIP_INFO_sk_type(sk)))
    sk_PKCS7_RECIP_INFO_shift(sk) ((PKCS7_RECIP_INFO *)OPENSSL_sk_shift(ossl_check_PKCS7_RECIP_INFO_sk_type(sk)))
    sk_PKCS7_RECIP_INFO_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_PKCS7_RECIP_INFO_sk_type(sk), ossl_check_PKCS7_RECIP_INFO_freefunc_type(freefunc))
    sk_PKCS7_RECIP_INFO_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_PKCS7_RECIP_INFO_sk_type(sk), ossl_check_PKCS7_RECIP_INFO_type(ptr), (idx))
    sk_PKCS7_RECIP_INFO_set(sk, idx, ptr) ((PKCS7_RECIP_INFO *)OPENSSL_sk_set(ossl_check_PKCS7_RECIP_INFO_sk_type(sk), (idx), ossl_check_PKCS7_RECIP_INFO_type(ptr)))
    sk_PKCS7_RECIP_INFO_find(sk, ptr) OPENSSL_sk_find(ossl_check_PKCS7_RECIP_INFO_sk_type(sk), ossl_check_PKCS7_RECIP_INFO_type(ptr))
    sk_PKCS7_RECIP_INFO_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_PKCS7_RECIP_INFO_sk_type(sk), ossl_check_PKCS7_RECIP_INFO_type(ptr))
    sk_PKCS7_RECIP_INFO_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_PKCS7_RECIP_INFO_sk_type(sk), ossl_check_PKCS7_RECIP_INFO_type(ptr), pnum)
    sk_PKCS7_RECIP_INFO_sort(sk) OPENSSL_sk_sort(ossl_check_PKCS7_RECIP_INFO_sk_type(sk))
    sk_PKCS7_RECIP_INFO_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_PKCS7_RECIP_INFO_sk_type(sk))
    sk_PKCS7_RECIP_INFO_dup(sk) ((STACK_OF(PKCS7_RECIP_INFO) *)OPENSSL_sk_dup(ossl_check_const_PKCS7_RECIP_INFO_sk_type(sk)))
    sk_PKCS7_RECIP_INFO_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(PKCS7_RECIP_INFO) *)OPENSSL_sk_deep_copy(ossl_check_const_PKCS7_RECIP_INFO_sk_type(sk), ossl_check_PKCS7_RECIP_INFO_copyfunc_type(copyfunc), ossl_check_PKCS7_RECIP_INFO_freefunc_type(freefunc)))
    sk_PKCS7_RECIP_INFO_set_cmp_func(sk, cmp) ((sk_PKCS7_RECIP_INFO_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_PKCS7_RECIP_INFO_sk_type(sk), ossl_check_PKCS7_RECIP_INFO_compfunc_type(cmp)))
  }

  { TODO 1 -copenssl stack PKCS7 definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_PKCS7 = Pointer;
  {$EXTERNALSYM PSTACK_OF_PKCS7}

  { Original Stack Macros for PKCS7:
    SKM_DEFINE_STACK_OF_INTERNAL(PKCS7, PKCS7, PKCS7)
    sk_PKCS7_num(sk) OPENSSL_sk_num(ossl_check_const_PKCS7_sk_type(sk))
    sk_PKCS7_value(sk, idx) ((PKCS7 *)OPENSSL_sk_value(ossl_check_const_PKCS7_sk_type(sk), (idx)))
    sk_PKCS7_new(cmp) ((STACK_OF(PKCS7) *)OPENSSL_sk_new(ossl_check_PKCS7_compfunc_type(cmp)))
    sk_PKCS7_new_null() ((STACK_OF(PKCS7) *)OPENSSL_sk_new_null())
    sk_PKCS7_new_reserve(cmp, n) ((STACK_OF(PKCS7) *)OPENSSL_sk_new_reserve(ossl_check_PKCS7_compfunc_type(cmp), (n)))
    sk_PKCS7_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_PKCS7_sk_type(sk), (n))
    sk_PKCS7_free(sk) OPENSSL_sk_free(ossl_check_PKCS7_sk_type(sk))
    sk_PKCS7_zero(sk) OPENSSL_sk_zero(ossl_check_PKCS7_sk_type(sk))
    sk_PKCS7_delete(sk, i) ((PKCS7 *)OPENSSL_sk_delete(ossl_check_PKCS7_sk_type(sk), (i)))
    sk_PKCS7_delete_ptr(sk, ptr) ((PKCS7 *)OPENSSL_sk_delete_ptr(ossl_check_PKCS7_sk_type(sk), ossl_check_PKCS7_type(ptr)))
    sk_PKCS7_push(sk, ptr) OPENSSL_sk_push(ossl_check_PKCS7_sk_type(sk), ossl_check_PKCS7_type(ptr))
    sk_PKCS7_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_PKCS7_sk_type(sk), ossl_check_PKCS7_type(ptr))
    sk_PKCS7_pop(sk) ((PKCS7 *)OPENSSL_sk_pop(ossl_check_PKCS7_sk_type(sk)))
    sk_PKCS7_shift(sk) ((PKCS7 *)OPENSSL_sk_shift(ossl_check_PKCS7_sk_type(sk)))
    sk_PKCS7_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_PKCS7_sk_type(sk), ossl_check_PKCS7_freefunc_type(freefunc))
    sk_PKCS7_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_PKCS7_sk_type(sk), ossl_check_PKCS7_type(ptr), (idx))
    sk_PKCS7_set(sk, idx, ptr) ((PKCS7 *)OPENSSL_sk_set(ossl_check_PKCS7_sk_type(sk), (idx), ossl_check_PKCS7_type(ptr)))
    sk_PKCS7_find(sk, ptr) OPENSSL_sk_find(ossl_check_PKCS7_sk_type(sk), ossl_check_PKCS7_type(ptr))
    sk_PKCS7_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_PKCS7_sk_type(sk), ossl_check_PKCS7_type(ptr))
    sk_PKCS7_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_PKCS7_sk_type(sk), ossl_check_PKCS7_type(ptr), pnum)
    sk_PKCS7_sort(sk) OPENSSL_sk_sort(ossl_check_PKCS7_sk_type(sk))
    sk_PKCS7_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_PKCS7_sk_type(sk))
    sk_PKCS7_dup(sk) ((STACK_OF(PKCS7) *)OPENSSL_sk_dup(ossl_check_const_PKCS7_sk_type(sk)))
    sk_PKCS7_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(PKCS7) *)OPENSSL_sk_deep_copy(ossl_check_const_PKCS7_sk_type(sk), ossl_check_PKCS7_copyfunc_type(copyfunc), ossl_check_PKCS7_freefunc_type(freefunc)))
    sk_PKCS7_set_cmp_func(sk, cmp) ((sk_PKCS7_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_PKCS7_sk_type(sk), ossl_check_PKCS7_compfunc_type(cmp)))
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

function PKCS7_ISSUER_AND_SERIAL_new: PPKCS7_ISSUER_AND_SERIAL; cdecl external CLibCrypto name 'PKCS7_ISSUER_AND_SERIAL_new';
procedure PKCS7_ISSUER_AND_SERIAL_free(a: PPKCS7_ISSUER_AND_SERIAL); cdecl external CLibCrypto name 'PKCS7_ISSUER_AND_SERIAL_free';
function d2i_PKCS7_ISSUER_AND_SERIAL(a: PPPKCS7_ISSUER_AND_SERIAL; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_ISSUER_AND_SERIAL; cdecl external CLibCrypto name 'd2i_PKCS7_ISSUER_AND_SERIAL';
function i2d_PKCS7_ISSUER_AND_SERIAL(a: PPKCS7_ISSUER_AND_SERIAL; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS7_ISSUER_AND_SERIAL';
function PKCS7_ISSUER_AND_SERIAL_it: PASN1_ITEM; cdecl external CLibCrypto name 'PKCS7_ISSUER_AND_SERIAL_it';
function PKCS7_ISSUER_AND_SERIAL_digest(data: PPKCS7_ISSUER_AND_SERIAL; _type: PEVP_MD; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_ISSUER_AND_SERIAL_digest';
function d2i_PKCS7_fp(fp: PFILE; p7: PPPKCS7): PPKCS7; cdecl external CLibCrypto name 'd2i_PKCS7_fp';
function i2d_PKCS7_fp(fp: PFILE; p7: PPKCS7): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS7_fp';
function PKCS7_dup(a: PPKCS7): PPKCS7; cdecl external CLibCrypto name 'PKCS7_dup';
function d2i_PKCS7_bio(bp: PBIO; p7: PPPKCS7): PPKCS7; cdecl external CLibCrypto name 'd2i_PKCS7_bio';
function i2d_PKCS7_bio(bp: PBIO; p7: PPKCS7): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS7_bio';
function i2d_PKCS7_bio_stream(_out: PBIO; p7: PPKCS7; _in: PBIO; flags: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS7_bio_stream';
function PEM_write_bio_PKCS7_stream(_out: PBIO; p7: PPKCS7; _in: PBIO; flags: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_PKCS7_stream';
function PKCS7_SIGNER_INFO_new: PPKCS7_SIGNER_INFO; cdecl external CLibCrypto name 'PKCS7_SIGNER_INFO_new';
procedure PKCS7_SIGNER_INFO_free(a: PPKCS7_SIGNER_INFO); cdecl external CLibCrypto name 'PKCS7_SIGNER_INFO_free';
function d2i_PKCS7_SIGNER_INFO(a: PPPKCS7_SIGNER_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_SIGNER_INFO; cdecl external CLibCrypto name 'd2i_PKCS7_SIGNER_INFO';
function i2d_PKCS7_SIGNER_INFO(a: PPKCS7_SIGNER_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS7_SIGNER_INFO';
function PKCS7_SIGNER_INFO_it: PASN1_ITEM; cdecl external CLibCrypto name 'PKCS7_SIGNER_INFO_it';
function PKCS7_RECIP_INFO_new: PPKCS7_RECIP_INFO; cdecl external CLibCrypto name 'PKCS7_RECIP_INFO_new';
procedure PKCS7_RECIP_INFO_free(a: PPKCS7_RECIP_INFO); cdecl external CLibCrypto name 'PKCS7_RECIP_INFO_free';
function d2i_PKCS7_RECIP_INFO(a: PPPKCS7_RECIP_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_RECIP_INFO; cdecl external CLibCrypto name 'd2i_PKCS7_RECIP_INFO';
function i2d_PKCS7_RECIP_INFO(a: PPKCS7_RECIP_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS7_RECIP_INFO';
function PKCS7_RECIP_INFO_it: PASN1_ITEM; cdecl external CLibCrypto name 'PKCS7_RECIP_INFO_it';
function PKCS7_SIGNED_new: PPKCS7_SIGNED; cdecl external CLibCrypto name 'PKCS7_SIGNED_new';
procedure PKCS7_SIGNED_free(a: PPKCS7_SIGNED); cdecl external CLibCrypto name 'PKCS7_SIGNED_free';
function d2i_PKCS7_SIGNED(a: PPPKCS7_SIGNED; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_SIGNED; cdecl external CLibCrypto name 'd2i_PKCS7_SIGNED';
function i2d_PKCS7_SIGNED(a: PPKCS7_SIGNED; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS7_SIGNED';
function PKCS7_SIGNED_it: PASN1_ITEM; cdecl external CLibCrypto name 'PKCS7_SIGNED_it';
function PKCS7_ENC_CONTENT_new: PPKCS7_ENC_CONTENT; cdecl external CLibCrypto name 'PKCS7_ENC_CONTENT_new';
procedure PKCS7_ENC_CONTENT_free(a: PPKCS7_ENC_CONTENT); cdecl external CLibCrypto name 'PKCS7_ENC_CONTENT_free';
function d2i_PKCS7_ENC_CONTENT(a: PPPKCS7_ENC_CONTENT; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_ENC_CONTENT; cdecl external CLibCrypto name 'd2i_PKCS7_ENC_CONTENT';
function i2d_PKCS7_ENC_CONTENT(a: PPKCS7_ENC_CONTENT; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS7_ENC_CONTENT';
function PKCS7_ENC_CONTENT_it: PASN1_ITEM; cdecl external CLibCrypto name 'PKCS7_ENC_CONTENT_it';
function PKCS7_ENVELOPE_new: PPKCS7_ENVELOPE; cdecl external CLibCrypto name 'PKCS7_ENVELOPE_new';
procedure PKCS7_ENVELOPE_free(a: PPKCS7_ENVELOPE); cdecl external CLibCrypto name 'PKCS7_ENVELOPE_free';
function d2i_PKCS7_ENVELOPE(a: PPPKCS7_ENVELOPE; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_ENVELOPE; cdecl external CLibCrypto name 'd2i_PKCS7_ENVELOPE';
function i2d_PKCS7_ENVELOPE(a: PPKCS7_ENVELOPE; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS7_ENVELOPE';
function PKCS7_ENVELOPE_it: PASN1_ITEM; cdecl external CLibCrypto name 'PKCS7_ENVELOPE_it';
function PKCS7_SIGN_ENVELOPE_new: PPKCS7_SIGN_ENVELOPE; cdecl external CLibCrypto name 'PKCS7_SIGN_ENVELOPE_new';
procedure PKCS7_SIGN_ENVELOPE_free(a: PPKCS7_SIGN_ENVELOPE); cdecl external CLibCrypto name 'PKCS7_SIGN_ENVELOPE_free';
function d2i_PKCS7_SIGN_ENVELOPE(a: PPPKCS7_SIGN_ENVELOPE; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_SIGN_ENVELOPE; cdecl external CLibCrypto name 'd2i_PKCS7_SIGN_ENVELOPE';
function i2d_PKCS7_SIGN_ENVELOPE(a: PPKCS7_SIGN_ENVELOPE; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS7_SIGN_ENVELOPE';
function PKCS7_SIGN_ENVELOPE_it: PASN1_ITEM; cdecl external CLibCrypto name 'PKCS7_SIGN_ENVELOPE_it';
function PKCS7_DIGEST_new: PPKCS7_DIGEST; cdecl external CLibCrypto name 'PKCS7_DIGEST_new';
procedure PKCS7_DIGEST_free(a: PPKCS7_DIGEST); cdecl external CLibCrypto name 'PKCS7_DIGEST_free';
function d2i_PKCS7_DIGEST(a: PPPKCS7_DIGEST; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_DIGEST; cdecl external CLibCrypto name 'd2i_PKCS7_DIGEST';
function i2d_PKCS7_DIGEST(a: PPKCS7_DIGEST; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS7_DIGEST';
function PKCS7_DIGEST_it: PASN1_ITEM; cdecl external CLibCrypto name 'PKCS7_DIGEST_it';
function PKCS7_ENCRYPT_new: PPKCS7_ENCRYPT; cdecl external CLibCrypto name 'PKCS7_ENCRYPT_new';
procedure PKCS7_ENCRYPT_free(a: PPKCS7_ENCRYPT); cdecl external CLibCrypto name 'PKCS7_ENCRYPT_free';
function d2i_PKCS7_ENCRYPT(a: PPPKCS7_ENCRYPT; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_ENCRYPT; cdecl external CLibCrypto name 'd2i_PKCS7_ENCRYPT';
function i2d_PKCS7_ENCRYPT(a: PPKCS7_ENCRYPT; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS7_ENCRYPT';
function PKCS7_ENCRYPT_it: PASN1_ITEM; cdecl external CLibCrypto name 'PKCS7_ENCRYPT_it';
function PKCS7_new: PPKCS7; cdecl external CLibCrypto name 'PKCS7_new';
procedure PKCS7_free(a: PPKCS7); cdecl external CLibCrypto name 'PKCS7_free';
function d2i_PKCS7(a: PPPKCS7; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7; cdecl external CLibCrypto name 'd2i_PKCS7';
function i2d_PKCS7(a: PPKCS7; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS7';
function PKCS7_it: PASN1_ITEM; cdecl external CLibCrypto name 'PKCS7_it';
function PKCS7_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS7; cdecl external CLibCrypto name 'PKCS7_new_ex';
function PKCS7_ATTR_SIGN_it: PASN1_ITEM; cdecl external CLibCrypto name 'PKCS7_ATTR_SIGN_it';
function PKCS7_ATTR_VERIFY_it: PASN1_ITEM; cdecl external CLibCrypto name 'PKCS7_ATTR_VERIFY_it';
function i2d_PKCS7_NDEF(a: PPKCS7; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_PKCS7_NDEF';
function PKCS7_print_ctx(_out: PBIO; x: PPKCS7; indent: TIdC_INT; pctx: PASN1_PCTX): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_print_ctx';
function PKCS7_ctrl(p7: PPKCS7; cmd: TIdC_INT; larg: TIdC_LONG; parg: PIdAnsiChar): TIdC_LONG; cdecl external CLibCrypto name 'PKCS7_ctrl';
function PKCS7_type_is_other(p7: PPKCS7): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_type_is_other';
function PKCS7_set_type(p7: PPKCS7; _type: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_set_type';
function PKCS7_set0_type_other(p7: PPKCS7; _type: TIdC_INT; other: PASN1_TYPE): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_set0_type_other';
function PKCS7_set_content(p7: PPKCS7; p7_data: PPKCS7): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_set_content';
function PKCS7_SIGNER_INFO_set(p7i: PPKCS7_SIGNER_INFO; x509: PX509; pkey: PEVP_PKEY; dgst: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_SIGNER_INFO_set';
function PKCS7_SIGNER_INFO_sign(si: PPKCS7_SIGNER_INFO): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_SIGNER_INFO_sign';
function PKCS7_add_signer(p7: PPKCS7; p7i: PPKCS7_SIGNER_INFO): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_add_signer';
function PKCS7_add_certificate(p7: PPKCS7; cert: PX509): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_add_certificate';
function PKCS7_add_crl(p7: PPKCS7; crl: PX509_CRL): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_add_crl';
function PKCS7_content_new(p7: PPKCS7; nid: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_content_new';
function PKCS7_dataVerify(cert_store: PX509_STORE; ctx: PX509_STORE_CTX; bio: PBIO; p7: PPKCS7; si: PPKCS7_SIGNER_INFO): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_dataVerify';
function PKCS7_signatureVerify(bio: PBIO; p7: PPKCS7; si: PPKCS7_SIGNER_INFO; signer: PX509): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_signatureVerify';
function PKCS7_dataInit(p7: PPKCS7; bio: PBIO): PBIO; cdecl external CLibCrypto name 'PKCS7_dataInit';
function PKCS7_dataFinal(p7: PPKCS7; bio: PBIO): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_dataFinal';
function PKCS7_dataDecode(p7: PPKCS7; pkey: PEVP_PKEY; in_bio: PBIO; pcert: PX509): PBIO; cdecl external CLibCrypto name 'PKCS7_dataDecode';
function PKCS7_add_signature(p7: PPKCS7; x509: PX509; pkey: PEVP_PKEY; dgst: PEVP_MD): PPKCS7_SIGNER_INFO; cdecl external CLibCrypto name 'PKCS7_add_signature';
function PKCS7_cert_from_signer_info(p7: PPKCS7; si: PPKCS7_SIGNER_INFO): PX509; cdecl external CLibCrypto name 'PKCS7_cert_from_signer_info';
function PKCS7_set_digest(p7: PPKCS7; md: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_set_digest';
function PKCS7_get_signer_info(p7: PPKCS7): Pstack_st_PKCS7_SIGNER_INFO; cdecl external CLibCrypto name 'PKCS7_get_signer_info';
function PKCS7_add_recipient(p7: PPKCS7; x509: PX509): PPKCS7_RECIP_INFO; cdecl external CLibCrypto name 'PKCS7_add_recipient';
procedure PKCS7_SIGNER_INFO_get0_algs(si: PPKCS7_SIGNER_INFO; pk: PPEVP_PKEY; pdig: PPX509_ALGOR; psig: PPX509_ALGOR); cdecl external CLibCrypto name 'PKCS7_SIGNER_INFO_get0_algs';
procedure PKCS7_RECIP_INFO_get0_alg(ri: PPKCS7_RECIP_INFO; penc: PPX509_ALGOR); cdecl external CLibCrypto name 'PKCS7_RECIP_INFO_get0_alg';
function PKCS7_add_recipient_info(p7: PPKCS7; ri: PPKCS7_RECIP_INFO): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_add_recipient_info';
function PKCS7_RECIP_INFO_set(p7i: PPKCS7_RECIP_INFO; x509: PX509): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_RECIP_INFO_set';
function PKCS7_set_cipher(p7: PPKCS7; cipher: PEVP_CIPHER): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_set_cipher';
function PKCS7_stream(boundary: PPPIdAnsiChar; p7: PPKCS7): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_stream';
function PKCS7_get_issuer_and_serial(p7: PPKCS7; idx: TIdC_INT): PPKCS7_ISSUER_AND_SERIAL; cdecl external CLibCrypto name 'PKCS7_get_issuer_and_serial';
function PKCS7_get_octet_string(p7: PPKCS7): PASN1_OCTET_STRING; cdecl external CLibCrypto name 'PKCS7_get_octet_string';
function PKCS7_digest_from_attributes(sk: Pstack_st_X509_ATTRIBUTE): PASN1_OCTET_STRING; cdecl external CLibCrypto name 'PKCS7_digest_from_attributes';
function PKCS7_add_signed_attribute(p7si: PPKCS7_SIGNER_INFO; nid: TIdC_INT; _type: TIdC_INT; data: Pointer): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_add_signed_attribute';
function PKCS7_add_attribute(p7si: PPKCS7_SIGNER_INFO; nid: TIdC_INT; atrtype: TIdC_INT; value: Pointer): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_add_attribute';
function PKCS7_get_attribute(si: PPKCS7_SIGNER_INFO; nid: TIdC_INT): PASN1_TYPE; cdecl external CLibCrypto name 'PKCS7_get_attribute';
function PKCS7_get_signed_attribute(si: PPKCS7_SIGNER_INFO; nid: TIdC_INT): PASN1_TYPE; cdecl external CLibCrypto name 'PKCS7_get_signed_attribute';
function PKCS7_set_signed_attributes(p7si: PPKCS7_SIGNER_INFO; sk: Pstack_st_X509_ATTRIBUTE): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_set_signed_attributes';
function PKCS7_set_attributes(p7si: PPKCS7_SIGNER_INFO; sk: Pstack_st_X509_ATTRIBUTE): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_set_attributes';
function PKCS7_sign(signcert: PX509; pkey: PEVP_PKEY; certs: Pstack_st_X509; data: PBIO; flags: TIdC_INT): PPKCS7; cdecl external CLibCrypto name 'PKCS7_sign';
function PKCS7_sign_ex(signcert: PX509; pkey: PEVP_PKEY; certs: Pstack_st_X509; data: PBIO; flags: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS7; cdecl external CLibCrypto name 'PKCS7_sign_ex';
function PKCS7_sign_add_signer(p7: PPKCS7; signcert: PX509; pkey: PEVP_PKEY; md: PEVP_MD; flags: TIdC_INT): PPKCS7_SIGNER_INFO; cdecl external CLibCrypto name 'PKCS7_sign_add_signer';
function PKCS7_final(p7: PPKCS7; data: PBIO; flags: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_final';
function PKCS7_verify(p7: PPKCS7; certs: Pstack_st_X509; store: PX509_STORE; indata: PBIO; _out: PBIO; flags: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_verify';
function PKCS7_get0_signers(p7: PPKCS7; certs: Pstack_st_X509; flags: TIdC_INT): Pstack_st_X509; cdecl external CLibCrypto name 'PKCS7_get0_signers';
function PKCS7_encrypt(certs: Pstack_st_X509; _in: PBIO; cipher: PEVP_CIPHER; flags: TIdC_INT): PPKCS7; cdecl external CLibCrypto name 'PKCS7_encrypt';
function PKCS7_encrypt_ex(certs: Pstack_st_X509; _in: PBIO; cipher: PEVP_CIPHER; flags: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS7; cdecl external CLibCrypto name 'PKCS7_encrypt_ex';
function PKCS7_decrypt(p7: PPKCS7; pkey: PEVP_PKEY; cert: PX509; data: PBIO; flags: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_decrypt';
function PKCS7_add_attrib_smimecap(si: PPKCS7_SIGNER_INFO; cap: Pstack_st_X509_ALGOR): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_add_attrib_smimecap';
function PKCS7_get_smimecap(si: PPKCS7_SIGNER_INFO): Pstack_st_X509_ALGOR; cdecl external CLibCrypto name 'PKCS7_get_smimecap';
function PKCS7_simple_smimecap(sk: Pstack_st_X509_ALGOR; nid: TIdC_INT; arg: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_simple_smimecap';
function PKCS7_add_attrib_content_type(si: PPKCS7_SIGNER_INFO; coid: PASN1_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_add_attrib_content_type';
function PKCS7_add0_attrib_signing_time(si: PPKCS7_SIGNER_INFO; t: PASN1_TIME): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_add0_attrib_signing_time';
function PKCS7_add1_attrib_digest(si: PPKCS7_SIGNER_INFO; md: PIdAnsiChar; mdlen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'PKCS7_add1_attrib_digest';
function SMIME_write_PKCS7(bio: PBIO; p7: PPKCS7; data: PBIO; flags: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'SMIME_write_PKCS7';
function SMIME_read_PKCS7_ex(bio: PBIO; bcont: PPBIO; p7: PPPKCS7): PPKCS7; cdecl external CLibCrypto name 'SMIME_read_PKCS7_ex';
function SMIME_read_PKCS7(bio: PBIO; bcont: PPBIO): PPKCS7; cdecl external CLibCrypto name 'SMIME_read_PKCS7';
function BIO_new_PKCS7(_out: PBIO; p7: PPKCS7): PBIO; cdecl external CLibCrypto name 'BIO_new_PKCS7';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  PKCS7_ISSUER_AND_SERIAL_new_procname = 'PKCS7_ISSUER_AND_SERIAL_new';
  PKCS7_ISSUER_AND_SERIAL_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_ISSUER_AND_SERIAL_free_procname = 'PKCS7_ISSUER_AND_SERIAL_free';
  PKCS7_ISSUER_AND_SERIAL_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PKCS7_ISSUER_AND_SERIAL_procname = 'd2i_PKCS7_ISSUER_AND_SERIAL';
  d2i_PKCS7_ISSUER_AND_SERIAL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS7_ISSUER_AND_SERIAL_procname = 'i2d_PKCS7_ISSUER_AND_SERIAL';
  i2d_PKCS7_ISSUER_AND_SERIAL_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_ISSUER_AND_SERIAL_it_procname = 'PKCS7_ISSUER_AND_SERIAL_it';
  PKCS7_ISSUER_AND_SERIAL_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_ISSUER_AND_SERIAL_digest_procname = 'PKCS7_ISSUER_AND_SERIAL_digest';
  PKCS7_ISSUER_AND_SERIAL_digest_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PKCS7_fp_procname = 'd2i_PKCS7_fp';
  d2i_PKCS7_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS7_fp_procname = 'i2d_PKCS7_fp';
  i2d_PKCS7_fp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_dup_procname = 'PKCS7_dup';
  PKCS7_dup_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PKCS7_bio_procname = 'd2i_PKCS7_bio';
  d2i_PKCS7_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS7_bio_procname = 'i2d_PKCS7_bio';
  i2d_PKCS7_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS7_bio_stream_procname = 'i2d_PKCS7_bio_stream';
  i2d_PKCS7_bio_stream_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_bio_PKCS7_stream_procname = 'PEM_write_bio_PKCS7_stream';
  PEM_write_bio_PKCS7_stream_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_SIGNER_INFO_new_procname = 'PKCS7_SIGNER_INFO_new';
  PKCS7_SIGNER_INFO_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_SIGNER_INFO_free_procname = 'PKCS7_SIGNER_INFO_free';
  PKCS7_SIGNER_INFO_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PKCS7_SIGNER_INFO_procname = 'd2i_PKCS7_SIGNER_INFO';
  d2i_PKCS7_SIGNER_INFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS7_SIGNER_INFO_procname = 'i2d_PKCS7_SIGNER_INFO';
  i2d_PKCS7_SIGNER_INFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_SIGNER_INFO_it_procname = 'PKCS7_SIGNER_INFO_it';
  PKCS7_SIGNER_INFO_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_RECIP_INFO_new_procname = 'PKCS7_RECIP_INFO_new';
  PKCS7_RECIP_INFO_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_RECIP_INFO_free_procname = 'PKCS7_RECIP_INFO_free';
  PKCS7_RECIP_INFO_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PKCS7_RECIP_INFO_procname = 'd2i_PKCS7_RECIP_INFO';
  d2i_PKCS7_RECIP_INFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS7_RECIP_INFO_procname = 'i2d_PKCS7_RECIP_INFO';
  i2d_PKCS7_RECIP_INFO_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_RECIP_INFO_it_procname = 'PKCS7_RECIP_INFO_it';
  PKCS7_RECIP_INFO_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_SIGNED_new_procname = 'PKCS7_SIGNED_new';
  PKCS7_SIGNED_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_SIGNED_free_procname = 'PKCS7_SIGNED_free';
  PKCS7_SIGNED_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PKCS7_SIGNED_procname = 'd2i_PKCS7_SIGNED';
  d2i_PKCS7_SIGNED_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS7_SIGNED_procname = 'i2d_PKCS7_SIGNED';
  i2d_PKCS7_SIGNED_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_SIGNED_it_procname = 'PKCS7_SIGNED_it';
  PKCS7_SIGNED_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_ENC_CONTENT_new_procname = 'PKCS7_ENC_CONTENT_new';
  PKCS7_ENC_CONTENT_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_ENC_CONTENT_free_procname = 'PKCS7_ENC_CONTENT_free';
  PKCS7_ENC_CONTENT_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PKCS7_ENC_CONTENT_procname = 'd2i_PKCS7_ENC_CONTENT';
  d2i_PKCS7_ENC_CONTENT_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS7_ENC_CONTENT_procname = 'i2d_PKCS7_ENC_CONTENT';
  i2d_PKCS7_ENC_CONTENT_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_ENC_CONTENT_it_procname = 'PKCS7_ENC_CONTENT_it';
  PKCS7_ENC_CONTENT_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_ENVELOPE_new_procname = 'PKCS7_ENVELOPE_new';
  PKCS7_ENVELOPE_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_ENVELOPE_free_procname = 'PKCS7_ENVELOPE_free';
  PKCS7_ENVELOPE_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PKCS7_ENVELOPE_procname = 'd2i_PKCS7_ENVELOPE';
  d2i_PKCS7_ENVELOPE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS7_ENVELOPE_procname = 'i2d_PKCS7_ENVELOPE';
  i2d_PKCS7_ENVELOPE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_ENVELOPE_it_procname = 'PKCS7_ENVELOPE_it';
  PKCS7_ENVELOPE_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_SIGN_ENVELOPE_new_procname = 'PKCS7_SIGN_ENVELOPE_new';
  PKCS7_SIGN_ENVELOPE_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_SIGN_ENVELOPE_free_procname = 'PKCS7_SIGN_ENVELOPE_free';
  PKCS7_SIGN_ENVELOPE_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PKCS7_SIGN_ENVELOPE_procname = 'd2i_PKCS7_SIGN_ENVELOPE';
  d2i_PKCS7_SIGN_ENVELOPE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS7_SIGN_ENVELOPE_procname = 'i2d_PKCS7_SIGN_ENVELOPE';
  i2d_PKCS7_SIGN_ENVELOPE_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_SIGN_ENVELOPE_it_procname = 'PKCS7_SIGN_ENVELOPE_it';
  PKCS7_SIGN_ENVELOPE_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_DIGEST_new_procname = 'PKCS7_DIGEST_new';
  PKCS7_DIGEST_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_DIGEST_free_procname = 'PKCS7_DIGEST_free';
  PKCS7_DIGEST_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PKCS7_DIGEST_procname = 'd2i_PKCS7_DIGEST';
  d2i_PKCS7_DIGEST_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS7_DIGEST_procname = 'i2d_PKCS7_DIGEST';
  i2d_PKCS7_DIGEST_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_DIGEST_it_procname = 'PKCS7_DIGEST_it';
  PKCS7_DIGEST_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_ENCRYPT_new_procname = 'PKCS7_ENCRYPT_new';
  PKCS7_ENCRYPT_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_ENCRYPT_free_procname = 'PKCS7_ENCRYPT_free';
  PKCS7_ENCRYPT_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PKCS7_ENCRYPT_procname = 'd2i_PKCS7_ENCRYPT';
  d2i_PKCS7_ENCRYPT_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS7_ENCRYPT_procname = 'i2d_PKCS7_ENCRYPT';
  i2d_PKCS7_ENCRYPT_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_ENCRYPT_it_procname = 'PKCS7_ENCRYPT_it';
  PKCS7_ENCRYPT_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_new_procname = 'PKCS7_new';
  PKCS7_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_free_procname = 'PKCS7_free';
  PKCS7_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_PKCS7_procname = 'd2i_PKCS7';
  d2i_PKCS7_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS7_procname = 'i2d_PKCS7';
  i2d_PKCS7_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_it_procname = 'PKCS7_it';
  PKCS7_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_new_ex_procname = 'PKCS7_new_ex';
  PKCS7_new_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS7_ATTR_SIGN_it_procname = 'PKCS7_ATTR_SIGN_it';
  PKCS7_ATTR_SIGN_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_ATTR_VERIFY_it_procname = 'PKCS7_ATTR_VERIFY_it';
  PKCS7_ATTR_VERIFY_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_PKCS7_NDEF_procname = 'i2d_PKCS7_NDEF';
  i2d_PKCS7_NDEF_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_print_ctx_procname = 'PKCS7_print_ctx';
  PKCS7_print_ctx_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_ctrl_procname = 'PKCS7_ctrl';
  PKCS7_ctrl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_type_is_other_procname = 'PKCS7_type_is_other';
  PKCS7_type_is_other_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS7_set_type_procname = 'PKCS7_set_type';
  PKCS7_set_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_set0_type_other_procname = 'PKCS7_set0_type_other';
  PKCS7_set0_type_other_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_set_content_procname = 'PKCS7_set_content';
  PKCS7_set_content_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_SIGNER_INFO_set_procname = 'PKCS7_SIGNER_INFO_set';
  PKCS7_SIGNER_INFO_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_SIGNER_INFO_sign_procname = 'PKCS7_SIGNER_INFO_sign';
  PKCS7_SIGNER_INFO_sign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_add_signer_procname = 'PKCS7_add_signer';
  PKCS7_add_signer_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_add_certificate_procname = 'PKCS7_add_certificate';
  PKCS7_add_certificate_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_add_crl_procname = 'PKCS7_add_crl';
  PKCS7_add_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_content_new_procname = 'PKCS7_content_new';
  PKCS7_content_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_dataVerify_procname = 'PKCS7_dataVerify';
  PKCS7_dataVerify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_signatureVerify_procname = 'PKCS7_signatureVerify';
  PKCS7_signatureVerify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_dataInit_procname = 'PKCS7_dataInit';
  PKCS7_dataInit_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_dataFinal_procname = 'PKCS7_dataFinal';
  PKCS7_dataFinal_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_dataDecode_procname = 'PKCS7_dataDecode';
  PKCS7_dataDecode_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_add_signature_procname = 'PKCS7_add_signature';
  PKCS7_add_signature_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_cert_from_signer_info_procname = 'PKCS7_cert_from_signer_info';
  PKCS7_cert_from_signer_info_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_set_digest_procname = 'PKCS7_set_digest';
  PKCS7_set_digest_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_get_signer_info_procname = 'PKCS7_get_signer_info';
  PKCS7_get_signer_info_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_add_recipient_procname = 'PKCS7_add_recipient';
  PKCS7_add_recipient_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_SIGNER_INFO_get0_algs_procname = 'PKCS7_SIGNER_INFO_get0_algs';
  PKCS7_SIGNER_INFO_get0_algs_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_RECIP_INFO_get0_alg_procname = 'PKCS7_RECIP_INFO_get0_alg';
  PKCS7_RECIP_INFO_get0_alg_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_add_recipient_info_procname = 'PKCS7_add_recipient_info';
  PKCS7_add_recipient_info_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_RECIP_INFO_set_procname = 'PKCS7_RECIP_INFO_set';
  PKCS7_RECIP_INFO_set_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_set_cipher_procname = 'PKCS7_set_cipher';
  PKCS7_set_cipher_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_stream_procname = 'PKCS7_stream';
  PKCS7_stream_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_get_issuer_and_serial_procname = 'PKCS7_get_issuer_and_serial';
  PKCS7_get_issuer_and_serial_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_get_octet_string_procname = 'PKCS7_get_octet_string';
  PKCS7_get_octet_string_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS7_digest_from_attributes_procname = 'PKCS7_digest_from_attributes';
  PKCS7_digest_from_attributes_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_add_signed_attribute_procname = 'PKCS7_add_signed_attribute';
  PKCS7_add_signed_attribute_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_add_attribute_procname = 'PKCS7_add_attribute';
  PKCS7_add_attribute_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_get_attribute_procname = 'PKCS7_get_attribute';
  PKCS7_get_attribute_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_get_signed_attribute_procname = 'PKCS7_get_signed_attribute';
  PKCS7_get_signed_attribute_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_set_signed_attributes_procname = 'PKCS7_set_signed_attributes';
  PKCS7_set_signed_attributes_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_set_attributes_procname = 'PKCS7_set_attributes';
  PKCS7_set_attributes_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_sign_procname = 'PKCS7_sign';
  PKCS7_sign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_sign_ex_procname = 'PKCS7_sign_ex';
  PKCS7_sign_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS7_sign_add_signer_procname = 'PKCS7_sign_add_signer';
  PKCS7_sign_add_signer_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_final_procname = 'PKCS7_final';
  PKCS7_final_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_verify_procname = 'PKCS7_verify';
  PKCS7_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_get0_signers_procname = 'PKCS7_get0_signers';
  PKCS7_get0_signers_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_encrypt_procname = 'PKCS7_encrypt';
  PKCS7_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_encrypt_ex_procname = 'PKCS7_encrypt_ex';
  PKCS7_encrypt_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  PKCS7_decrypt_procname = 'PKCS7_decrypt';
  PKCS7_decrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_add_attrib_smimecap_procname = 'PKCS7_add_attrib_smimecap';
  PKCS7_add_attrib_smimecap_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_get_smimecap_procname = 'PKCS7_get_smimecap';
  PKCS7_get_smimecap_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_simple_smimecap_procname = 'PKCS7_simple_smimecap';
  PKCS7_simple_smimecap_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_add_attrib_content_type_procname = 'PKCS7_add_attrib_content_type';
  PKCS7_add_attrib_content_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_add0_attrib_signing_time_procname = 'PKCS7_add0_attrib_signing_time';
  PKCS7_add0_attrib_signing_time_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PKCS7_add1_attrib_digest_procname = 'PKCS7_add1_attrib_digest';
  PKCS7_add1_attrib_digest_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SMIME_write_PKCS7_procname = 'SMIME_write_PKCS7';
  SMIME_write_PKCS7_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SMIME_read_PKCS7_ex_procname = 'SMIME_read_PKCS7_ex';
  SMIME_read_PKCS7_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SMIME_read_PKCS7_procname = 'SMIME_read_PKCS7';
  SMIME_read_PKCS7_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_new_PKCS7_procname = 'BIO_new_PKCS7';
  BIO_new_PKCS7_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_PKCS7_ISSUER_AND_SERIAL_new: PPKCS7_ISSUER_AND_SERIAL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_ISSUER_AND_SERIAL_new_procname);
end;

procedure ERR_PKCS7_ISSUER_AND_SERIAL_free(a: PPKCS7_ISSUER_AND_SERIAL); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_ISSUER_AND_SERIAL_free_procname);
end;

function ERR_d2i_PKCS7_ISSUER_AND_SERIAL(a: PPPKCS7_ISSUER_AND_SERIAL; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_ISSUER_AND_SERIAL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS7_ISSUER_AND_SERIAL_procname);
end;

function ERR_i2d_PKCS7_ISSUER_AND_SERIAL(a: PPKCS7_ISSUER_AND_SERIAL; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS7_ISSUER_AND_SERIAL_procname);
end;

function ERR_PKCS7_ISSUER_AND_SERIAL_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_ISSUER_AND_SERIAL_it_procname);
end;

function ERR_PKCS7_ISSUER_AND_SERIAL_digest(data: PPKCS7_ISSUER_AND_SERIAL; _type: PEVP_MD; md: PIdAnsiChar; len: PIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_ISSUER_AND_SERIAL_digest_procname);
end;

function ERR_d2i_PKCS7_fp(fp: PFILE; p7: PPPKCS7): PPKCS7; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS7_fp_procname);
end;

function ERR_i2d_PKCS7_fp(fp: PFILE; p7: PPKCS7): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS7_fp_procname);
end;

function ERR_PKCS7_dup(a: PPKCS7): PPKCS7; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_dup_procname);
end;

function ERR_d2i_PKCS7_bio(bp: PBIO; p7: PPPKCS7): PPKCS7; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS7_bio_procname);
end;

function ERR_i2d_PKCS7_bio(bp: PBIO; p7: PPKCS7): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS7_bio_procname);
end;

function ERR_i2d_PKCS7_bio_stream(_out: PBIO; p7: PPKCS7; _in: PBIO; flags: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS7_bio_stream_procname);
end;

function ERR_PEM_write_bio_PKCS7_stream(_out: PBIO; p7: PPKCS7; _in: PBIO; flags: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_PKCS7_stream_procname);
end;

function ERR_PKCS7_SIGNER_INFO_new: PPKCS7_SIGNER_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_SIGNER_INFO_new_procname);
end;

procedure ERR_PKCS7_SIGNER_INFO_free(a: PPKCS7_SIGNER_INFO); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_SIGNER_INFO_free_procname);
end;

function ERR_d2i_PKCS7_SIGNER_INFO(a: PPPKCS7_SIGNER_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_SIGNER_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS7_SIGNER_INFO_procname);
end;

function ERR_i2d_PKCS7_SIGNER_INFO(a: PPKCS7_SIGNER_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS7_SIGNER_INFO_procname);
end;

function ERR_PKCS7_SIGNER_INFO_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_SIGNER_INFO_it_procname);
end;

function ERR_PKCS7_RECIP_INFO_new: PPKCS7_RECIP_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_RECIP_INFO_new_procname);
end;

procedure ERR_PKCS7_RECIP_INFO_free(a: PPKCS7_RECIP_INFO); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_RECIP_INFO_free_procname);
end;

function ERR_d2i_PKCS7_RECIP_INFO(a: PPPKCS7_RECIP_INFO; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_RECIP_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS7_RECIP_INFO_procname);
end;

function ERR_i2d_PKCS7_RECIP_INFO(a: PPKCS7_RECIP_INFO; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS7_RECIP_INFO_procname);
end;

function ERR_PKCS7_RECIP_INFO_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_RECIP_INFO_it_procname);
end;

function ERR_PKCS7_SIGNED_new: PPKCS7_SIGNED; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_SIGNED_new_procname);
end;

procedure ERR_PKCS7_SIGNED_free(a: PPKCS7_SIGNED); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_SIGNED_free_procname);
end;

function ERR_d2i_PKCS7_SIGNED(a: PPPKCS7_SIGNED; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_SIGNED; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS7_SIGNED_procname);
end;

function ERR_i2d_PKCS7_SIGNED(a: PPKCS7_SIGNED; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS7_SIGNED_procname);
end;

function ERR_PKCS7_SIGNED_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_SIGNED_it_procname);
end;

function ERR_PKCS7_ENC_CONTENT_new: PPKCS7_ENC_CONTENT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_ENC_CONTENT_new_procname);
end;

procedure ERR_PKCS7_ENC_CONTENT_free(a: PPKCS7_ENC_CONTENT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_ENC_CONTENT_free_procname);
end;

function ERR_d2i_PKCS7_ENC_CONTENT(a: PPPKCS7_ENC_CONTENT; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_ENC_CONTENT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS7_ENC_CONTENT_procname);
end;

function ERR_i2d_PKCS7_ENC_CONTENT(a: PPKCS7_ENC_CONTENT; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS7_ENC_CONTENT_procname);
end;

function ERR_PKCS7_ENC_CONTENT_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_ENC_CONTENT_it_procname);
end;

function ERR_PKCS7_ENVELOPE_new: PPKCS7_ENVELOPE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_ENVELOPE_new_procname);
end;

procedure ERR_PKCS7_ENVELOPE_free(a: PPKCS7_ENVELOPE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_ENVELOPE_free_procname);
end;

function ERR_d2i_PKCS7_ENVELOPE(a: PPPKCS7_ENVELOPE; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_ENVELOPE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS7_ENVELOPE_procname);
end;

function ERR_i2d_PKCS7_ENVELOPE(a: PPKCS7_ENVELOPE; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS7_ENVELOPE_procname);
end;

function ERR_PKCS7_ENVELOPE_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_ENVELOPE_it_procname);
end;

function ERR_PKCS7_SIGN_ENVELOPE_new: PPKCS7_SIGN_ENVELOPE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_SIGN_ENVELOPE_new_procname);
end;

procedure ERR_PKCS7_SIGN_ENVELOPE_free(a: PPKCS7_SIGN_ENVELOPE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_SIGN_ENVELOPE_free_procname);
end;

function ERR_d2i_PKCS7_SIGN_ENVELOPE(a: PPPKCS7_SIGN_ENVELOPE; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_SIGN_ENVELOPE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS7_SIGN_ENVELOPE_procname);
end;

function ERR_i2d_PKCS7_SIGN_ENVELOPE(a: PPKCS7_SIGN_ENVELOPE; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS7_SIGN_ENVELOPE_procname);
end;

function ERR_PKCS7_SIGN_ENVELOPE_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_SIGN_ENVELOPE_it_procname);
end;

function ERR_PKCS7_DIGEST_new: PPKCS7_DIGEST; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_DIGEST_new_procname);
end;

procedure ERR_PKCS7_DIGEST_free(a: PPKCS7_DIGEST); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_DIGEST_free_procname);
end;

function ERR_d2i_PKCS7_DIGEST(a: PPPKCS7_DIGEST; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_DIGEST; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS7_DIGEST_procname);
end;

function ERR_i2d_PKCS7_DIGEST(a: PPKCS7_DIGEST; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS7_DIGEST_procname);
end;

function ERR_PKCS7_DIGEST_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_DIGEST_it_procname);
end;

function ERR_PKCS7_ENCRYPT_new: PPKCS7_ENCRYPT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_ENCRYPT_new_procname);
end;

procedure ERR_PKCS7_ENCRYPT_free(a: PPKCS7_ENCRYPT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_ENCRYPT_free_procname);
end;

function ERR_d2i_PKCS7_ENCRYPT(a: PPPKCS7_ENCRYPT; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7_ENCRYPT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS7_ENCRYPT_procname);
end;

function ERR_i2d_PKCS7_ENCRYPT(a: PPKCS7_ENCRYPT; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS7_ENCRYPT_procname);
end;

function ERR_PKCS7_ENCRYPT_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_ENCRYPT_it_procname);
end;

function ERR_PKCS7_new: PPKCS7; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_new_procname);
end;

procedure ERR_PKCS7_free(a: PPKCS7); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_free_procname);
end;

function ERR_d2i_PKCS7(a: PPPKCS7; _in: PPIdAnsiChar; len: TIdC_LONG): PPKCS7; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_PKCS7_procname);
end;

function ERR_i2d_PKCS7(a: PPKCS7; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS7_procname);
end;

function ERR_PKCS7_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_it_procname);
end;

function ERR_PKCS7_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS7; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_new_ex_procname);
end;

function ERR_PKCS7_ATTR_SIGN_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_ATTR_SIGN_it_procname);
end;

function ERR_PKCS7_ATTR_VERIFY_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_ATTR_VERIFY_it_procname);
end;

function ERR_i2d_PKCS7_NDEF(a: PPKCS7; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_PKCS7_NDEF_procname);
end;

function ERR_PKCS7_print_ctx(_out: PBIO; x: PPKCS7; indent: TIdC_INT; pctx: PASN1_PCTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_print_ctx_procname);
end;

function ERR_PKCS7_ctrl(p7: PPKCS7; cmd: TIdC_INT; larg: TIdC_LONG; parg: PIdAnsiChar): TIdC_LONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_ctrl_procname);
end;

function ERR_PKCS7_type_is_other(p7: PPKCS7): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_type_is_other_procname);
end;

function ERR_PKCS7_set_type(p7: PPKCS7; _type: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_set_type_procname);
end;

function ERR_PKCS7_set0_type_other(p7: PPKCS7; _type: TIdC_INT; other: PASN1_TYPE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_set0_type_other_procname);
end;

function ERR_PKCS7_set_content(p7: PPKCS7; p7_data: PPKCS7): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_set_content_procname);
end;

function ERR_PKCS7_SIGNER_INFO_set(p7i: PPKCS7_SIGNER_INFO; x509: PX509; pkey: PEVP_PKEY; dgst: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_SIGNER_INFO_set_procname);
end;

function ERR_PKCS7_SIGNER_INFO_sign(si: PPKCS7_SIGNER_INFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_SIGNER_INFO_sign_procname);
end;

function ERR_PKCS7_add_signer(p7: PPKCS7; p7i: PPKCS7_SIGNER_INFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_add_signer_procname);
end;

function ERR_PKCS7_add_certificate(p7: PPKCS7; cert: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_add_certificate_procname);
end;

function ERR_PKCS7_add_crl(p7: PPKCS7; crl: PX509_CRL): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_add_crl_procname);
end;

function ERR_PKCS7_content_new(p7: PPKCS7; nid: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_content_new_procname);
end;

function ERR_PKCS7_dataVerify(cert_store: PX509_STORE; ctx: PX509_STORE_CTX; bio: PBIO; p7: PPKCS7; si: PPKCS7_SIGNER_INFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_dataVerify_procname);
end;

function ERR_PKCS7_signatureVerify(bio: PBIO; p7: PPKCS7; si: PPKCS7_SIGNER_INFO; signer: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_signatureVerify_procname);
end;

function ERR_PKCS7_dataInit(p7: PPKCS7; bio: PBIO): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_dataInit_procname);
end;

function ERR_PKCS7_dataFinal(p7: PPKCS7; bio: PBIO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_dataFinal_procname);
end;

function ERR_PKCS7_dataDecode(p7: PPKCS7; pkey: PEVP_PKEY; in_bio: PBIO; pcert: PX509): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_dataDecode_procname);
end;

function ERR_PKCS7_add_signature(p7: PPKCS7; x509: PX509; pkey: PEVP_PKEY; dgst: PEVP_MD): PPKCS7_SIGNER_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_add_signature_procname);
end;

function ERR_PKCS7_cert_from_signer_info(p7: PPKCS7; si: PPKCS7_SIGNER_INFO): PX509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_cert_from_signer_info_procname);
end;

function ERR_PKCS7_set_digest(p7: PPKCS7; md: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_set_digest_procname);
end;

function ERR_PKCS7_get_signer_info(p7: PPKCS7): Pstack_st_PKCS7_SIGNER_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_get_signer_info_procname);
end;

function ERR_PKCS7_add_recipient(p7: PPKCS7; x509: PX509): PPKCS7_RECIP_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_add_recipient_procname);
end;

procedure ERR_PKCS7_SIGNER_INFO_get0_algs(si: PPKCS7_SIGNER_INFO; pk: PPEVP_PKEY; pdig: PPX509_ALGOR; psig: PPX509_ALGOR); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_SIGNER_INFO_get0_algs_procname);
end;

procedure ERR_PKCS7_RECIP_INFO_get0_alg(ri: PPKCS7_RECIP_INFO; penc: PPX509_ALGOR); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_RECIP_INFO_get0_alg_procname);
end;

function ERR_PKCS7_add_recipient_info(p7: PPKCS7; ri: PPKCS7_RECIP_INFO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_add_recipient_info_procname);
end;

function ERR_PKCS7_RECIP_INFO_set(p7i: PPKCS7_RECIP_INFO; x509: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_RECIP_INFO_set_procname);
end;

function ERR_PKCS7_set_cipher(p7: PPKCS7; cipher: PEVP_CIPHER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_set_cipher_procname);
end;

function ERR_PKCS7_stream(boundary: PPPIdAnsiChar; p7: PPKCS7): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_stream_procname);
end;

function ERR_PKCS7_get_issuer_and_serial(p7: PPKCS7; idx: TIdC_INT): PPKCS7_ISSUER_AND_SERIAL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_get_issuer_and_serial_procname);
end;

function ERR_PKCS7_get_octet_string(p7: PPKCS7): PASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_get_octet_string_procname);
end;

function ERR_PKCS7_digest_from_attributes(sk: Pstack_st_X509_ATTRIBUTE): PASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_digest_from_attributes_procname);
end;

function ERR_PKCS7_add_signed_attribute(p7si: PPKCS7_SIGNER_INFO; nid: TIdC_INT; _type: TIdC_INT; data: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_add_signed_attribute_procname);
end;

function ERR_PKCS7_add_attribute(p7si: PPKCS7_SIGNER_INFO; nid: TIdC_INT; atrtype: TIdC_INT; value: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_add_attribute_procname);
end;

function ERR_PKCS7_get_attribute(si: PPKCS7_SIGNER_INFO; nid: TIdC_INT): PASN1_TYPE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_get_attribute_procname);
end;

function ERR_PKCS7_get_signed_attribute(si: PPKCS7_SIGNER_INFO; nid: TIdC_INT): PASN1_TYPE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_get_signed_attribute_procname);
end;

function ERR_PKCS7_set_signed_attributes(p7si: PPKCS7_SIGNER_INFO; sk: Pstack_st_X509_ATTRIBUTE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_set_signed_attributes_procname);
end;

function ERR_PKCS7_set_attributes(p7si: PPKCS7_SIGNER_INFO; sk: Pstack_st_X509_ATTRIBUTE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_set_attributes_procname);
end;

function ERR_PKCS7_sign(signcert: PX509; pkey: PEVP_PKEY; certs: Pstack_st_X509; data: PBIO; flags: TIdC_INT): PPKCS7; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_sign_procname);
end;

function ERR_PKCS7_sign_ex(signcert: PX509; pkey: PEVP_PKEY; certs: Pstack_st_X509; data: PBIO; flags: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS7; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_sign_ex_procname);
end;

function ERR_PKCS7_sign_add_signer(p7: PPKCS7; signcert: PX509; pkey: PEVP_PKEY; md: PEVP_MD; flags: TIdC_INT): PPKCS7_SIGNER_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_sign_add_signer_procname);
end;

function ERR_PKCS7_final(p7: PPKCS7; data: PBIO; flags: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_final_procname);
end;

function ERR_PKCS7_verify(p7: PPKCS7; certs: Pstack_st_X509; store: PX509_STORE; indata: PBIO; _out: PBIO; flags: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_verify_procname);
end;

function ERR_PKCS7_get0_signers(p7: PPKCS7; certs: Pstack_st_X509; flags: TIdC_INT): Pstack_st_X509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_get0_signers_procname);
end;

function ERR_PKCS7_encrypt(certs: Pstack_st_X509; _in: PBIO; cipher: PEVP_CIPHER; flags: TIdC_INT): PPKCS7; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_encrypt_procname);
end;

function ERR_PKCS7_encrypt_ex(certs: Pstack_st_X509; _in: PBIO; cipher: PEVP_CIPHER; flags: TIdC_INT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PPKCS7; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_encrypt_ex_procname);
end;

function ERR_PKCS7_decrypt(p7: PPKCS7; pkey: PEVP_PKEY; cert: PX509; data: PBIO; flags: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_decrypt_procname);
end;

function ERR_PKCS7_add_attrib_smimecap(si: PPKCS7_SIGNER_INFO; cap: Pstack_st_X509_ALGOR): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_add_attrib_smimecap_procname);
end;

function ERR_PKCS7_get_smimecap(si: PPKCS7_SIGNER_INFO): Pstack_st_X509_ALGOR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_get_smimecap_procname);
end;

function ERR_PKCS7_simple_smimecap(sk: Pstack_st_X509_ALGOR; nid: TIdC_INT; arg: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_simple_smimecap_procname);
end;

function ERR_PKCS7_add_attrib_content_type(si: PPKCS7_SIGNER_INFO; coid: PASN1_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_add_attrib_content_type_procname);
end;

function ERR_PKCS7_add0_attrib_signing_time(si: PPKCS7_SIGNER_INFO; t: PASN1_TIME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_add0_attrib_signing_time_procname);
end;

function ERR_PKCS7_add1_attrib_digest(si: PPKCS7_SIGNER_INFO; md: PIdAnsiChar; mdlen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PKCS7_add1_attrib_digest_procname);
end;

function ERR_SMIME_write_PKCS7(bio: PBIO; p7: PPKCS7; data: PBIO; flags: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SMIME_write_PKCS7_procname);
end;

function ERR_SMIME_read_PKCS7_ex(bio: PBIO; bcont: PPBIO; p7: PPPKCS7): PPKCS7; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SMIME_read_PKCS7_ex_procname);
end;

function ERR_SMIME_read_PKCS7(bio: PBIO; bcont: PPBIO): PPKCS7; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SMIME_read_PKCS7_procname);
end;

function ERR_BIO_new_PKCS7(_out: PBIO; p7: PPKCS7): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_PKCS7_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  PKCS7_ISSUER_AND_SERIAL_new := LoadLibFunction(ADllHandle, PKCS7_ISSUER_AND_SERIAL_new_procname);
  FuncLoadError := not assigned(PKCS7_ISSUER_AND_SERIAL_new);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_ISSUER_AND_SERIAL_new_allownil)}
    PKCS7_ISSUER_AND_SERIAL_new := ERR_PKCS7_ISSUER_AND_SERIAL_new;
    {$ifend}
    {$if declared(PKCS7_ISSUER_AND_SERIAL_new_introduced)}
    if LibVersion < PKCS7_ISSUER_AND_SERIAL_new_introduced then
    begin
      {$if declared(FC_PKCS7_ISSUER_AND_SERIAL_new)}
      PKCS7_ISSUER_AND_SERIAL_new := FC_PKCS7_ISSUER_AND_SERIAL_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_ISSUER_AND_SERIAL_new_removed)}
    if PKCS7_ISSUER_AND_SERIAL_new_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_ISSUER_AND_SERIAL_new)}
      PKCS7_ISSUER_AND_SERIAL_new := _PKCS7_ISSUER_AND_SERIAL_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_ISSUER_AND_SERIAL_new_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_ISSUER_AND_SERIAL_new');
    {$ifend}
  end;
  
  PKCS7_ISSUER_AND_SERIAL_free := LoadLibFunction(ADllHandle, PKCS7_ISSUER_AND_SERIAL_free_procname);
  FuncLoadError := not assigned(PKCS7_ISSUER_AND_SERIAL_free);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_ISSUER_AND_SERIAL_free_allownil)}
    PKCS7_ISSUER_AND_SERIAL_free := ERR_PKCS7_ISSUER_AND_SERIAL_free;
    {$ifend}
    {$if declared(PKCS7_ISSUER_AND_SERIAL_free_introduced)}
    if LibVersion < PKCS7_ISSUER_AND_SERIAL_free_introduced then
    begin
      {$if declared(FC_PKCS7_ISSUER_AND_SERIAL_free)}
      PKCS7_ISSUER_AND_SERIAL_free := FC_PKCS7_ISSUER_AND_SERIAL_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_ISSUER_AND_SERIAL_free_removed)}
    if PKCS7_ISSUER_AND_SERIAL_free_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_ISSUER_AND_SERIAL_free)}
      PKCS7_ISSUER_AND_SERIAL_free := _PKCS7_ISSUER_AND_SERIAL_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_ISSUER_AND_SERIAL_free_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_ISSUER_AND_SERIAL_free');
    {$ifend}
  end;
  
  d2i_PKCS7_ISSUER_AND_SERIAL := LoadLibFunction(ADllHandle, d2i_PKCS7_ISSUER_AND_SERIAL_procname);
  FuncLoadError := not assigned(d2i_PKCS7_ISSUER_AND_SERIAL);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS7_ISSUER_AND_SERIAL_allownil)}
    d2i_PKCS7_ISSUER_AND_SERIAL := ERR_d2i_PKCS7_ISSUER_AND_SERIAL;
    {$ifend}
    {$if declared(d2i_PKCS7_ISSUER_AND_SERIAL_introduced)}
    if LibVersion < d2i_PKCS7_ISSUER_AND_SERIAL_introduced then
    begin
      {$if declared(FC_d2i_PKCS7_ISSUER_AND_SERIAL)}
      d2i_PKCS7_ISSUER_AND_SERIAL := FC_d2i_PKCS7_ISSUER_AND_SERIAL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS7_ISSUER_AND_SERIAL_removed)}
    if d2i_PKCS7_ISSUER_AND_SERIAL_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS7_ISSUER_AND_SERIAL)}
      d2i_PKCS7_ISSUER_AND_SERIAL := _d2i_PKCS7_ISSUER_AND_SERIAL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS7_ISSUER_AND_SERIAL_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS7_ISSUER_AND_SERIAL');
    {$ifend}
  end;
  
  i2d_PKCS7_ISSUER_AND_SERIAL := LoadLibFunction(ADllHandle, i2d_PKCS7_ISSUER_AND_SERIAL_procname);
  FuncLoadError := not assigned(i2d_PKCS7_ISSUER_AND_SERIAL);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS7_ISSUER_AND_SERIAL_allownil)}
    i2d_PKCS7_ISSUER_AND_SERIAL := ERR_i2d_PKCS7_ISSUER_AND_SERIAL;
    {$ifend}
    {$if declared(i2d_PKCS7_ISSUER_AND_SERIAL_introduced)}
    if LibVersion < i2d_PKCS7_ISSUER_AND_SERIAL_introduced then
    begin
      {$if declared(FC_i2d_PKCS7_ISSUER_AND_SERIAL)}
      i2d_PKCS7_ISSUER_AND_SERIAL := FC_i2d_PKCS7_ISSUER_AND_SERIAL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS7_ISSUER_AND_SERIAL_removed)}
    if i2d_PKCS7_ISSUER_AND_SERIAL_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS7_ISSUER_AND_SERIAL)}
      i2d_PKCS7_ISSUER_AND_SERIAL := _i2d_PKCS7_ISSUER_AND_SERIAL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS7_ISSUER_AND_SERIAL_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS7_ISSUER_AND_SERIAL');
    {$ifend}
  end;
  
  PKCS7_ISSUER_AND_SERIAL_it := LoadLibFunction(ADllHandle, PKCS7_ISSUER_AND_SERIAL_it_procname);
  FuncLoadError := not assigned(PKCS7_ISSUER_AND_SERIAL_it);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_ISSUER_AND_SERIAL_it_allownil)}
    PKCS7_ISSUER_AND_SERIAL_it := ERR_PKCS7_ISSUER_AND_SERIAL_it;
    {$ifend}
    {$if declared(PKCS7_ISSUER_AND_SERIAL_it_introduced)}
    if LibVersion < PKCS7_ISSUER_AND_SERIAL_it_introduced then
    begin
      {$if declared(FC_PKCS7_ISSUER_AND_SERIAL_it)}
      PKCS7_ISSUER_AND_SERIAL_it := FC_PKCS7_ISSUER_AND_SERIAL_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_ISSUER_AND_SERIAL_it_removed)}
    if PKCS7_ISSUER_AND_SERIAL_it_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_ISSUER_AND_SERIAL_it)}
      PKCS7_ISSUER_AND_SERIAL_it := _PKCS7_ISSUER_AND_SERIAL_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_ISSUER_AND_SERIAL_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_ISSUER_AND_SERIAL_it');
    {$ifend}
  end;
  
  PKCS7_ISSUER_AND_SERIAL_digest := LoadLibFunction(ADllHandle, PKCS7_ISSUER_AND_SERIAL_digest_procname);
  FuncLoadError := not assigned(PKCS7_ISSUER_AND_SERIAL_digest);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_ISSUER_AND_SERIAL_digest_allownil)}
    PKCS7_ISSUER_AND_SERIAL_digest := ERR_PKCS7_ISSUER_AND_SERIAL_digest;
    {$ifend}
    {$if declared(PKCS7_ISSUER_AND_SERIAL_digest_introduced)}
    if LibVersion < PKCS7_ISSUER_AND_SERIAL_digest_introduced then
    begin
      {$if declared(FC_PKCS7_ISSUER_AND_SERIAL_digest)}
      PKCS7_ISSUER_AND_SERIAL_digest := FC_PKCS7_ISSUER_AND_SERIAL_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_ISSUER_AND_SERIAL_digest_removed)}
    if PKCS7_ISSUER_AND_SERIAL_digest_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_ISSUER_AND_SERIAL_digest)}
      PKCS7_ISSUER_AND_SERIAL_digest := _PKCS7_ISSUER_AND_SERIAL_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_ISSUER_AND_SERIAL_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_ISSUER_AND_SERIAL_digest');
    {$ifend}
  end;
  
  d2i_PKCS7_fp := LoadLibFunction(ADllHandle, d2i_PKCS7_fp_procname);
  FuncLoadError := not assigned(d2i_PKCS7_fp);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS7_fp_allownil)}
    d2i_PKCS7_fp := ERR_d2i_PKCS7_fp;
    {$ifend}
    {$if declared(d2i_PKCS7_fp_introduced)}
    if LibVersion < d2i_PKCS7_fp_introduced then
    begin
      {$if declared(FC_d2i_PKCS7_fp)}
      d2i_PKCS7_fp := FC_d2i_PKCS7_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS7_fp_removed)}
    if d2i_PKCS7_fp_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS7_fp)}
      d2i_PKCS7_fp := _d2i_PKCS7_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS7_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS7_fp');
    {$ifend}
  end;
  
  i2d_PKCS7_fp := LoadLibFunction(ADllHandle, i2d_PKCS7_fp_procname);
  FuncLoadError := not assigned(i2d_PKCS7_fp);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS7_fp_allownil)}
    i2d_PKCS7_fp := ERR_i2d_PKCS7_fp;
    {$ifend}
    {$if declared(i2d_PKCS7_fp_introduced)}
    if LibVersion < i2d_PKCS7_fp_introduced then
    begin
      {$if declared(FC_i2d_PKCS7_fp)}
      i2d_PKCS7_fp := FC_i2d_PKCS7_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS7_fp_removed)}
    if i2d_PKCS7_fp_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS7_fp)}
      i2d_PKCS7_fp := _i2d_PKCS7_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS7_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS7_fp');
    {$ifend}
  end;
  
  PKCS7_dup := LoadLibFunction(ADllHandle, PKCS7_dup_procname);
  FuncLoadError := not assigned(PKCS7_dup);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_dup_allownil)}
    PKCS7_dup := ERR_PKCS7_dup;
    {$ifend}
    {$if declared(PKCS7_dup_introduced)}
    if LibVersion < PKCS7_dup_introduced then
    begin
      {$if declared(FC_PKCS7_dup)}
      PKCS7_dup := FC_PKCS7_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_dup_removed)}
    if PKCS7_dup_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_dup)}
      PKCS7_dup := _PKCS7_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_dup');
    {$ifend}
  end;
  
  d2i_PKCS7_bio := LoadLibFunction(ADllHandle, d2i_PKCS7_bio_procname);
  FuncLoadError := not assigned(d2i_PKCS7_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS7_bio_allownil)}
    d2i_PKCS7_bio := ERR_d2i_PKCS7_bio;
    {$ifend}
    {$if declared(d2i_PKCS7_bio_introduced)}
    if LibVersion < d2i_PKCS7_bio_introduced then
    begin
      {$if declared(FC_d2i_PKCS7_bio)}
      d2i_PKCS7_bio := FC_d2i_PKCS7_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS7_bio_removed)}
    if d2i_PKCS7_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS7_bio)}
      d2i_PKCS7_bio := _d2i_PKCS7_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS7_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS7_bio');
    {$ifend}
  end;
  
  i2d_PKCS7_bio := LoadLibFunction(ADllHandle, i2d_PKCS7_bio_procname);
  FuncLoadError := not assigned(i2d_PKCS7_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS7_bio_allownil)}
    i2d_PKCS7_bio := ERR_i2d_PKCS7_bio;
    {$ifend}
    {$if declared(i2d_PKCS7_bio_introduced)}
    if LibVersion < i2d_PKCS7_bio_introduced then
    begin
      {$if declared(FC_i2d_PKCS7_bio)}
      i2d_PKCS7_bio := FC_i2d_PKCS7_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS7_bio_removed)}
    if i2d_PKCS7_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS7_bio)}
      i2d_PKCS7_bio := _i2d_PKCS7_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS7_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS7_bio');
    {$ifend}
  end;
  
  i2d_PKCS7_bio_stream := LoadLibFunction(ADllHandle, i2d_PKCS7_bio_stream_procname);
  FuncLoadError := not assigned(i2d_PKCS7_bio_stream);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS7_bio_stream_allownil)}
    i2d_PKCS7_bio_stream := ERR_i2d_PKCS7_bio_stream;
    {$ifend}
    {$if declared(i2d_PKCS7_bio_stream_introduced)}
    if LibVersion < i2d_PKCS7_bio_stream_introduced then
    begin
      {$if declared(FC_i2d_PKCS7_bio_stream)}
      i2d_PKCS7_bio_stream := FC_i2d_PKCS7_bio_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS7_bio_stream_removed)}
    if i2d_PKCS7_bio_stream_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS7_bio_stream)}
      i2d_PKCS7_bio_stream := _i2d_PKCS7_bio_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS7_bio_stream_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS7_bio_stream');
    {$ifend}
  end;
  
  PEM_write_bio_PKCS7_stream := LoadLibFunction(ADllHandle, PEM_write_bio_PKCS7_stream_procname);
  FuncLoadError := not assigned(PEM_write_bio_PKCS7_stream);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_PKCS7_stream_allownil)}
    PEM_write_bio_PKCS7_stream := ERR_PEM_write_bio_PKCS7_stream;
    {$ifend}
    {$if declared(PEM_write_bio_PKCS7_stream_introduced)}
    if LibVersion < PEM_write_bio_PKCS7_stream_introduced then
    begin
      {$if declared(FC_PEM_write_bio_PKCS7_stream)}
      PEM_write_bio_PKCS7_stream := FC_PEM_write_bio_PKCS7_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_PKCS7_stream_removed)}
    if PEM_write_bio_PKCS7_stream_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_PKCS7_stream)}
      PEM_write_bio_PKCS7_stream := _PEM_write_bio_PKCS7_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_PKCS7_stream_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_PKCS7_stream');
    {$ifend}
  end;
  
  PKCS7_SIGNER_INFO_new := LoadLibFunction(ADllHandle, PKCS7_SIGNER_INFO_new_procname);
  FuncLoadError := not assigned(PKCS7_SIGNER_INFO_new);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_SIGNER_INFO_new_allownil)}
    PKCS7_SIGNER_INFO_new := ERR_PKCS7_SIGNER_INFO_new;
    {$ifend}
    {$if declared(PKCS7_SIGNER_INFO_new_introduced)}
    if LibVersion < PKCS7_SIGNER_INFO_new_introduced then
    begin
      {$if declared(FC_PKCS7_SIGNER_INFO_new)}
      PKCS7_SIGNER_INFO_new := FC_PKCS7_SIGNER_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_SIGNER_INFO_new_removed)}
    if PKCS7_SIGNER_INFO_new_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_SIGNER_INFO_new)}
      PKCS7_SIGNER_INFO_new := _PKCS7_SIGNER_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_SIGNER_INFO_new_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_SIGNER_INFO_new');
    {$ifend}
  end;
  
  PKCS7_SIGNER_INFO_free := LoadLibFunction(ADllHandle, PKCS7_SIGNER_INFO_free_procname);
  FuncLoadError := not assigned(PKCS7_SIGNER_INFO_free);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_SIGNER_INFO_free_allownil)}
    PKCS7_SIGNER_INFO_free := ERR_PKCS7_SIGNER_INFO_free;
    {$ifend}
    {$if declared(PKCS7_SIGNER_INFO_free_introduced)}
    if LibVersion < PKCS7_SIGNER_INFO_free_introduced then
    begin
      {$if declared(FC_PKCS7_SIGNER_INFO_free)}
      PKCS7_SIGNER_INFO_free := FC_PKCS7_SIGNER_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_SIGNER_INFO_free_removed)}
    if PKCS7_SIGNER_INFO_free_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_SIGNER_INFO_free)}
      PKCS7_SIGNER_INFO_free := _PKCS7_SIGNER_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_SIGNER_INFO_free_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_SIGNER_INFO_free');
    {$ifend}
  end;
  
  d2i_PKCS7_SIGNER_INFO := LoadLibFunction(ADllHandle, d2i_PKCS7_SIGNER_INFO_procname);
  FuncLoadError := not assigned(d2i_PKCS7_SIGNER_INFO);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS7_SIGNER_INFO_allownil)}
    d2i_PKCS7_SIGNER_INFO := ERR_d2i_PKCS7_SIGNER_INFO;
    {$ifend}
    {$if declared(d2i_PKCS7_SIGNER_INFO_introduced)}
    if LibVersion < d2i_PKCS7_SIGNER_INFO_introduced then
    begin
      {$if declared(FC_d2i_PKCS7_SIGNER_INFO)}
      d2i_PKCS7_SIGNER_INFO := FC_d2i_PKCS7_SIGNER_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS7_SIGNER_INFO_removed)}
    if d2i_PKCS7_SIGNER_INFO_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS7_SIGNER_INFO)}
      d2i_PKCS7_SIGNER_INFO := _d2i_PKCS7_SIGNER_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS7_SIGNER_INFO_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS7_SIGNER_INFO');
    {$ifend}
  end;
  
  i2d_PKCS7_SIGNER_INFO := LoadLibFunction(ADllHandle, i2d_PKCS7_SIGNER_INFO_procname);
  FuncLoadError := not assigned(i2d_PKCS7_SIGNER_INFO);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS7_SIGNER_INFO_allownil)}
    i2d_PKCS7_SIGNER_INFO := ERR_i2d_PKCS7_SIGNER_INFO;
    {$ifend}
    {$if declared(i2d_PKCS7_SIGNER_INFO_introduced)}
    if LibVersion < i2d_PKCS7_SIGNER_INFO_introduced then
    begin
      {$if declared(FC_i2d_PKCS7_SIGNER_INFO)}
      i2d_PKCS7_SIGNER_INFO := FC_i2d_PKCS7_SIGNER_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS7_SIGNER_INFO_removed)}
    if i2d_PKCS7_SIGNER_INFO_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS7_SIGNER_INFO)}
      i2d_PKCS7_SIGNER_INFO := _i2d_PKCS7_SIGNER_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS7_SIGNER_INFO_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS7_SIGNER_INFO');
    {$ifend}
  end;
  
  PKCS7_SIGNER_INFO_it := LoadLibFunction(ADllHandle, PKCS7_SIGNER_INFO_it_procname);
  FuncLoadError := not assigned(PKCS7_SIGNER_INFO_it);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_SIGNER_INFO_it_allownil)}
    PKCS7_SIGNER_INFO_it := ERR_PKCS7_SIGNER_INFO_it;
    {$ifend}
    {$if declared(PKCS7_SIGNER_INFO_it_introduced)}
    if LibVersion < PKCS7_SIGNER_INFO_it_introduced then
    begin
      {$if declared(FC_PKCS7_SIGNER_INFO_it)}
      PKCS7_SIGNER_INFO_it := FC_PKCS7_SIGNER_INFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_SIGNER_INFO_it_removed)}
    if PKCS7_SIGNER_INFO_it_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_SIGNER_INFO_it)}
      PKCS7_SIGNER_INFO_it := _PKCS7_SIGNER_INFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_SIGNER_INFO_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_SIGNER_INFO_it');
    {$ifend}
  end;
  
  PKCS7_RECIP_INFO_new := LoadLibFunction(ADllHandle, PKCS7_RECIP_INFO_new_procname);
  FuncLoadError := not assigned(PKCS7_RECIP_INFO_new);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_RECIP_INFO_new_allownil)}
    PKCS7_RECIP_INFO_new := ERR_PKCS7_RECIP_INFO_new;
    {$ifend}
    {$if declared(PKCS7_RECIP_INFO_new_introduced)}
    if LibVersion < PKCS7_RECIP_INFO_new_introduced then
    begin
      {$if declared(FC_PKCS7_RECIP_INFO_new)}
      PKCS7_RECIP_INFO_new := FC_PKCS7_RECIP_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_RECIP_INFO_new_removed)}
    if PKCS7_RECIP_INFO_new_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_RECIP_INFO_new)}
      PKCS7_RECIP_INFO_new := _PKCS7_RECIP_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_RECIP_INFO_new_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_RECIP_INFO_new');
    {$ifend}
  end;
  
  PKCS7_RECIP_INFO_free := LoadLibFunction(ADllHandle, PKCS7_RECIP_INFO_free_procname);
  FuncLoadError := not assigned(PKCS7_RECIP_INFO_free);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_RECIP_INFO_free_allownil)}
    PKCS7_RECIP_INFO_free := ERR_PKCS7_RECIP_INFO_free;
    {$ifend}
    {$if declared(PKCS7_RECIP_INFO_free_introduced)}
    if LibVersion < PKCS7_RECIP_INFO_free_introduced then
    begin
      {$if declared(FC_PKCS7_RECIP_INFO_free)}
      PKCS7_RECIP_INFO_free := FC_PKCS7_RECIP_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_RECIP_INFO_free_removed)}
    if PKCS7_RECIP_INFO_free_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_RECIP_INFO_free)}
      PKCS7_RECIP_INFO_free := _PKCS7_RECIP_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_RECIP_INFO_free_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_RECIP_INFO_free');
    {$ifend}
  end;
  
  d2i_PKCS7_RECIP_INFO := LoadLibFunction(ADllHandle, d2i_PKCS7_RECIP_INFO_procname);
  FuncLoadError := not assigned(d2i_PKCS7_RECIP_INFO);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS7_RECIP_INFO_allownil)}
    d2i_PKCS7_RECIP_INFO := ERR_d2i_PKCS7_RECIP_INFO;
    {$ifend}
    {$if declared(d2i_PKCS7_RECIP_INFO_introduced)}
    if LibVersion < d2i_PKCS7_RECIP_INFO_introduced then
    begin
      {$if declared(FC_d2i_PKCS7_RECIP_INFO)}
      d2i_PKCS7_RECIP_INFO := FC_d2i_PKCS7_RECIP_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS7_RECIP_INFO_removed)}
    if d2i_PKCS7_RECIP_INFO_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS7_RECIP_INFO)}
      d2i_PKCS7_RECIP_INFO := _d2i_PKCS7_RECIP_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS7_RECIP_INFO_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS7_RECIP_INFO');
    {$ifend}
  end;
  
  i2d_PKCS7_RECIP_INFO := LoadLibFunction(ADllHandle, i2d_PKCS7_RECIP_INFO_procname);
  FuncLoadError := not assigned(i2d_PKCS7_RECIP_INFO);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS7_RECIP_INFO_allownil)}
    i2d_PKCS7_RECIP_INFO := ERR_i2d_PKCS7_RECIP_INFO;
    {$ifend}
    {$if declared(i2d_PKCS7_RECIP_INFO_introduced)}
    if LibVersion < i2d_PKCS7_RECIP_INFO_introduced then
    begin
      {$if declared(FC_i2d_PKCS7_RECIP_INFO)}
      i2d_PKCS7_RECIP_INFO := FC_i2d_PKCS7_RECIP_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS7_RECIP_INFO_removed)}
    if i2d_PKCS7_RECIP_INFO_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS7_RECIP_INFO)}
      i2d_PKCS7_RECIP_INFO := _i2d_PKCS7_RECIP_INFO;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS7_RECIP_INFO_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS7_RECIP_INFO');
    {$ifend}
  end;
  
  PKCS7_RECIP_INFO_it := LoadLibFunction(ADllHandle, PKCS7_RECIP_INFO_it_procname);
  FuncLoadError := not assigned(PKCS7_RECIP_INFO_it);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_RECIP_INFO_it_allownil)}
    PKCS7_RECIP_INFO_it := ERR_PKCS7_RECIP_INFO_it;
    {$ifend}
    {$if declared(PKCS7_RECIP_INFO_it_introduced)}
    if LibVersion < PKCS7_RECIP_INFO_it_introduced then
    begin
      {$if declared(FC_PKCS7_RECIP_INFO_it)}
      PKCS7_RECIP_INFO_it := FC_PKCS7_RECIP_INFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_RECIP_INFO_it_removed)}
    if PKCS7_RECIP_INFO_it_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_RECIP_INFO_it)}
      PKCS7_RECIP_INFO_it := _PKCS7_RECIP_INFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_RECIP_INFO_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_RECIP_INFO_it');
    {$ifend}
  end;
  
  PKCS7_SIGNED_new := LoadLibFunction(ADllHandle, PKCS7_SIGNED_new_procname);
  FuncLoadError := not assigned(PKCS7_SIGNED_new);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_SIGNED_new_allownil)}
    PKCS7_SIGNED_new := ERR_PKCS7_SIGNED_new;
    {$ifend}
    {$if declared(PKCS7_SIGNED_new_introduced)}
    if LibVersion < PKCS7_SIGNED_new_introduced then
    begin
      {$if declared(FC_PKCS7_SIGNED_new)}
      PKCS7_SIGNED_new := FC_PKCS7_SIGNED_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_SIGNED_new_removed)}
    if PKCS7_SIGNED_new_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_SIGNED_new)}
      PKCS7_SIGNED_new := _PKCS7_SIGNED_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_SIGNED_new_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_SIGNED_new');
    {$ifend}
  end;
  
  PKCS7_SIGNED_free := LoadLibFunction(ADllHandle, PKCS7_SIGNED_free_procname);
  FuncLoadError := not assigned(PKCS7_SIGNED_free);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_SIGNED_free_allownil)}
    PKCS7_SIGNED_free := ERR_PKCS7_SIGNED_free;
    {$ifend}
    {$if declared(PKCS7_SIGNED_free_introduced)}
    if LibVersion < PKCS7_SIGNED_free_introduced then
    begin
      {$if declared(FC_PKCS7_SIGNED_free)}
      PKCS7_SIGNED_free := FC_PKCS7_SIGNED_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_SIGNED_free_removed)}
    if PKCS7_SIGNED_free_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_SIGNED_free)}
      PKCS7_SIGNED_free := _PKCS7_SIGNED_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_SIGNED_free_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_SIGNED_free');
    {$ifend}
  end;
  
  d2i_PKCS7_SIGNED := LoadLibFunction(ADllHandle, d2i_PKCS7_SIGNED_procname);
  FuncLoadError := not assigned(d2i_PKCS7_SIGNED);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS7_SIGNED_allownil)}
    d2i_PKCS7_SIGNED := ERR_d2i_PKCS7_SIGNED;
    {$ifend}
    {$if declared(d2i_PKCS7_SIGNED_introduced)}
    if LibVersion < d2i_PKCS7_SIGNED_introduced then
    begin
      {$if declared(FC_d2i_PKCS7_SIGNED)}
      d2i_PKCS7_SIGNED := FC_d2i_PKCS7_SIGNED;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS7_SIGNED_removed)}
    if d2i_PKCS7_SIGNED_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS7_SIGNED)}
      d2i_PKCS7_SIGNED := _d2i_PKCS7_SIGNED;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS7_SIGNED_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS7_SIGNED');
    {$ifend}
  end;
  
  i2d_PKCS7_SIGNED := LoadLibFunction(ADllHandle, i2d_PKCS7_SIGNED_procname);
  FuncLoadError := not assigned(i2d_PKCS7_SIGNED);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS7_SIGNED_allownil)}
    i2d_PKCS7_SIGNED := ERR_i2d_PKCS7_SIGNED;
    {$ifend}
    {$if declared(i2d_PKCS7_SIGNED_introduced)}
    if LibVersion < i2d_PKCS7_SIGNED_introduced then
    begin
      {$if declared(FC_i2d_PKCS7_SIGNED)}
      i2d_PKCS7_SIGNED := FC_i2d_PKCS7_SIGNED;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS7_SIGNED_removed)}
    if i2d_PKCS7_SIGNED_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS7_SIGNED)}
      i2d_PKCS7_SIGNED := _i2d_PKCS7_SIGNED;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS7_SIGNED_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS7_SIGNED');
    {$ifend}
  end;
  
  PKCS7_SIGNED_it := LoadLibFunction(ADllHandle, PKCS7_SIGNED_it_procname);
  FuncLoadError := not assigned(PKCS7_SIGNED_it);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_SIGNED_it_allownil)}
    PKCS7_SIGNED_it := ERR_PKCS7_SIGNED_it;
    {$ifend}
    {$if declared(PKCS7_SIGNED_it_introduced)}
    if LibVersion < PKCS7_SIGNED_it_introduced then
    begin
      {$if declared(FC_PKCS7_SIGNED_it)}
      PKCS7_SIGNED_it := FC_PKCS7_SIGNED_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_SIGNED_it_removed)}
    if PKCS7_SIGNED_it_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_SIGNED_it)}
      PKCS7_SIGNED_it := _PKCS7_SIGNED_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_SIGNED_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_SIGNED_it');
    {$ifend}
  end;
  
  PKCS7_ENC_CONTENT_new := LoadLibFunction(ADllHandle, PKCS7_ENC_CONTENT_new_procname);
  FuncLoadError := not assigned(PKCS7_ENC_CONTENT_new);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_ENC_CONTENT_new_allownil)}
    PKCS7_ENC_CONTENT_new := ERR_PKCS7_ENC_CONTENT_new;
    {$ifend}
    {$if declared(PKCS7_ENC_CONTENT_new_introduced)}
    if LibVersion < PKCS7_ENC_CONTENT_new_introduced then
    begin
      {$if declared(FC_PKCS7_ENC_CONTENT_new)}
      PKCS7_ENC_CONTENT_new := FC_PKCS7_ENC_CONTENT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_ENC_CONTENT_new_removed)}
    if PKCS7_ENC_CONTENT_new_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_ENC_CONTENT_new)}
      PKCS7_ENC_CONTENT_new := _PKCS7_ENC_CONTENT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_ENC_CONTENT_new_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_ENC_CONTENT_new');
    {$ifend}
  end;
  
  PKCS7_ENC_CONTENT_free := LoadLibFunction(ADllHandle, PKCS7_ENC_CONTENT_free_procname);
  FuncLoadError := not assigned(PKCS7_ENC_CONTENT_free);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_ENC_CONTENT_free_allownil)}
    PKCS7_ENC_CONTENT_free := ERR_PKCS7_ENC_CONTENT_free;
    {$ifend}
    {$if declared(PKCS7_ENC_CONTENT_free_introduced)}
    if LibVersion < PKCS7_ENC_CONTENT_free_introduced then
    begin
      {$if declared(FC_PKCS7_ENC_CONTENT_free)}
      PKCS7_ENC_CONTENT_free := FC_PKCS7_ENC_CONTENT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_ENC_CONTENT_free_removed)}
    if PKCS7_ENC_CONTENT_free_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_ENC_CONTENT_free)}
      PKCS7_ENC_CONTENT_free := _PKCS7_ENC_CONTENT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_ENC_CONTENT_free_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_ENC_CONTENT_free');
    {$ifend}
  end;
  
  d2i_PKCS7_ENC_CONTENT := LoadLibFunction(ADllHandle, d2i_PKCS7_ENC_CONTENT_procname);
  FuncLoadError := not assigned(d2i_PKCS7_ENC_CONTENT);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS7_ENC_CONTENT_allownil)}
    d2i_PKCS7_ENC_CONTENT := ERR_d2i_PKCS7_ENC_CONTENT;
    {$ifend}
    {$if declared(d2i_PKCS7_ENC_CONTENT_introduced)}
    if LibVersion < d2i_PKCS7_ENC_CONTENT_introduced then
    begin
      {$if declared(FC_d2i_PKCS7_ENC_CONTENT)}
      d2i_PKCS7_ENC_CONTENT := FC_d2i_PKCS7_ENC_CONTENT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS7_ENC_CONTENT_removed)}
    if d2i_PKCS7_ENC_CONTENT_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS7_ENC_CONTENT)}
      d2i_PKCS7_ENC_CONTENT := _d2i_PKCS7_ENC_CONTENT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS7_ENC_CONTENT_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS7_ENC_CONTENT');
    {$ifend}
  end;
  
  i2d_PKCS7_ENC_CONTENT := LoadLibFunction(ADllHandle, i2d_PKCS7_ENC_CONTENT_procname);
  FuncLoadError := not assigned(i2d_PKCS7_ENC_CONTENT);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS7_ENC_CONTENT_allownil)}
    i2d_PKCS7_ENC_CONTENT := ERR_i2d_PKCS7_ENC_CONTENT;
    {$ifend}
    {$if declared(i2d_PKCS7_ENC_CONTENT_introduced)}
    if LibVersion < i2d_PKCS7_ENC_CONTENT_introduced then
    begin
      {$if declared(FC_i2d_PKCS7_ENC_CONTENT)}
      i2d_PKCS7_ENC_CONTENT := FC_i2d_PKCS7_ENC_CONTENT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS7_ENC_CONTENT_removed)}
    if i2d_PKCS7_ENC_CONTENT_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS7_ENC_CONTENT)}
      i2d_PKCS7_ENC_CONTENT := _i2d_PKCS7_ENC_CONTENT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS7_ENC_CONTENT_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS7_ENC_CONTENT');
    {$ifend}
  end;
  
  PKCS7_ENC_CONTENT_it := LoadLibFunction(ADllHandle, PKCS7_ENC_CONTENT_it_procname);
  FuncLoadError := not assigned(PKCS7_ENC_CONTENT_it);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_ENC_CONTENT_it_allownil)}
    PKCS7_ENC_CONTENT_it := ERR_PKCS7_ENC_CONTENT_it;
    {$ifend}
    {$if declared(PKCS7_ENC_CONTENT_it_introduced)}
    if LibVersion < PKCS7_ENC_CONTENT_it_introduced then
    begin
      {$if declared(FC_PKCS7_ENC_CONTENT_it)}
      PKCS7_ENC_CONTENT_it := FC_PKCS7_ENC_CONTENT_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_ENC_CONTENT_it_removed)}
    if PKCS7_ENC_CONTENT_it_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_ENC_CONTENT_it)}
      PKCS7_ENC_CONTENT_it := _PKCS7_ENC_CONTENT_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_ENC_CONTENT_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_ENC_CONTENT_it');
    {$ifend}
  end;
  
  PKCS7_ENVELOPE_new := LoadLibFunction(ADllHandle, PKCS7_ENVELOPE_new_procname);
  FuncLoadError := not assigned(PKCS7_ENVELOPE_new);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_ENVELOPE_new_allownil)}
    PKCS7_ENVELOPE_new := ERR_PKCS7_ENVELOPE_new;
    {$ifend}
    {$if declared(PKCS7_ENVELOPE_new_introduced)}
    if LibVersion < PKCS7_ENVELOPE_new_introduced then
    begin
      {$if declared(FC_PKCS7_ENVELOPE_new)}
      PKCS7_ENVELOPE_new := FC_PKCS7_ENVELOPE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_ENVELOPE_new_removed)}
    if PKCS7_ENVELOPE_new_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_ENVELOPE_new)}
      PKCS7_ENVELOPE_new := _PKCS7_ENVELOPE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_ENVELOPE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_ENVELOPE_new');
    {$ifend}
  end;
  
  PKCS7_ENVELOPE_free := LoadLibFunction(ADllHandle, PKCS7_ENVELOPE_free_procname);
  FuncLoadError := not assigned(PKCS7_ENVELOPE_free);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_ENVELOPE_free_allownil)}
    PKCS7_ENVELOPE_free := ERR_PKCS7_ENVELOPE_free;
    {$ifend}
    {$if declared(PKCS7_ENVELOPE_free_introduced)}
    if LibVersion < PKCS7_ENVELOPE_free_introduced then
    begin
      {$if declared(FC_PKCS7_ENVELOPE_free)}
      PKCS7_ENVELOPE_free := FC_PKCS7_ENVELOPE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_ENVELOPE_free_removed)}
    if PKCS7_ENVELOPE_free_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_ENVELOPE_free)}
      PKCS7_ENVELOPE_free := _PKCS7_ENVELOPE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_ENVELOPE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_ENVELOPE_free');
    {$ifend}
  end;
  
  d2i_PKCS7_ENVELOPE := LoadLibFunction(ADllHandle, d2i_PKCS7_ENVELOPE_procname);
  FuncLoadError := not assigned(d2i_PKCS7_ENVELOPE);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS7_ENVELOPE_allownil)}
    d2i_PKCS7_ENVELOPE := ERR_d2i_PKCS7_ENVELOPE;
    {$ifend}
    {$if declared(d2i_PKCS7_ENVELOPE_introduced)}
    if LibVersion < d2i_PKCS7_ENVELOPE_introduced then
    begin
      {$if declared(FC_d2i_PKCS7_ENVELOPE)}
      d2i_PKCS7_ENVELOPE := FC_d2i_PKCS7_ENVELOPE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS7_ENVELOPE_removed)}
    if d2i_PKCS7_ENVELOPE_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS7_ENVELOPE)}
      d2i_PKCS7_ENVELOPE := _d2i_PKCS7_ENVELOPE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS7_ENVELOPE_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS7_ENVELOPE');
    {$ifend}
  end;
  
  i2d_PKCS7_ENVELOPE := LoadLibFunction(ADllHandle, i2d_PKCS7_ENVELOPE_procname);
  FuncLoadError := not assigned(i2d_PKCS7_ENVELOPE);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS7_ENVELOPE_allownil)}
    i2d_PKCS7_ENVELOPE := ERR_i2d_PKCS7_ENVELOPE;
    {$ifend}
    {$if declared(i2d_PKCS7_ENVELOPE_introduced)}
    if LibVersion < i2d_PKCS7_ENVELOPE_introduced then
    begin
      {$if declared(FC_i2d_PKCS7_ENVELOPE)}
      i2d_PKCS7_ENVELOPE := FC_i2d_PKCS7_ENVELOPE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS7_ENVELOPE_removed)}
    if i2d_PKCS7_ENVELOPE_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS7_ENVELOPE)}
      i2d_PKCS7_ENVELOPE := _i2d_PKCS7_ENVELOPE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS7_ENVELOPE_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS7_ENVELOPE');
    {$ifend}
  end;
  
  PKCS7_ENVELOPE_it := LoadLibFunction(ADllHandle, PKCS7_ENVELOPE_it_procname);
  FuncLoadError := not assigned(PKCS7_ENVELOPE_it);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_ENVELOPE_it_allownil)}
    PKCS7_ENVELOPE_it := ERR_PKCS7_ENVELOPE_it;
    {$ifend}
    {$if declared(PKCS7_ENVELOPE_it_introduced)}
    if LibVersion < PKCS7_ENVELOPE_it_introduced then
    begin
      {$if declared(FC_PKCS7_ENVELOPE_it)}
      PKCS7_ENVELOPE_it := FC_PKCS7_ENVELOPE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_ENVELOPE_it_removed)}
    if PKCS7_ENVELOPE_it_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_ENVELOPE_it)}
      PKCS7_ENVELOPE_it := _PKCS7_ENVELOPE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_ENVELOPE_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_ENVELOPE_it');
    {$ifend}
  end;
  
  PKCS7_SIGN_ENVELOPE_new := LoadLibFunction(ADllHandle, PKCS7_SIGN_ENVELOPE_new_procname);
  FuncLoadError := not assigned(PKCS7_SIGN_ENVELOPE_new);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_SIGN_ENVELOPE_new_allownil)}
    PKCS7_SIGN_ENVELOPE_new := ERR_PKCS7_SIGN_ENVELOPE_new;
    {$ifend}
    {$if declared(PKCS7_SIGN_ENVELOPE_new_introduced)}
    if LibVersion < PKCS7_SIGN_ENVELOPE_new_introduced then
    begin
      {$if declared(FC_PKCS7_SIGN_ENVELOPE_new)}
      PKCS7_SIGN_ENVELOPE_new := FC_PKCS7_SIGN_ENVELOPE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_SIGN_ENVELOPE_new_removed)}
    if PKCS7_SIGN_ENVELOPE_new_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_SIGN_ENVELOPE_new)}
      PKCS7_SIGN_ENVELOPE_new := _PKCS7_SIGN_ENVELOPE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_SIGN_ENVELOPE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_SIGN_ENVELOPE_new');
    {$ifend}
  end;
  
  PKCS7_SIGN_ENVELOPE_free := LoadLibFunction(ADllHandle, PKCS7_SIGN_ENVELOPE_free_procname);
  FuncLoadError := not assigned(PKCS7_SIGN_ENVELOPE_free);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_SIGN_ENVELOPE_free_allownil)}
    PKCS7_SIGN_ENVELOPE_free := ERR_PKCS7_SIGN_ENVELOPE_free;
    {$ifend}
    {$if declared(PKCS7_SIGN_ENVELOPE_free_introduced)}
    if LibVersion < PKCS7_SIGN_ENVELOPE_free_introduced then
    begin
      {$if declared(FC_PKCS7_SIGN_ENVELOPE_free)}
      PKCS7_SIGN_ENVELOPE_free := FC_PKCS7_SIGN_ENVELOPE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_SIGN_ENVELOPE_free_removed)}
    if PKCS7_SIGN_ENVELOPE_free_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_SIGN_ENVELOPE_free)}
      PKCS7_SIGN_ENVELOPE_free := _PKCS7_SIGN_ENVELOPE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_SIGN_ENVELOPE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_SIGN_ENVELOPE_free');
    {$ifend}
  end;
  
  d2i_PKCS7_SIGN_ENVELOPE := LoadLibFunction(ADllHandle, d2i_PKCS7_SIGN_ENVELOPE_procname);
  FuncLoadError := not assigned(d2i_PKCS7_SIGN_ENVELOPE);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS7_SIGN_ENVELOPE_allownil)}
    d2i_PKCS7_SIGN_ENVELOPE := ERR_d2i_PKCS7_SIGN_ENVELOPE;
    {$ifend}
    {$if declared(d2i_PKCS7_SIGN_ENVELOPE_introduced)}
    if LibVersion < d2i_PKCS7_SIGN_ENVELOPE_introduced then
    begin
      {$if declared(FC_d2i_PKCS7_SIGN_ENVELOPE)}
      d2i_PKCS7_SIGN_ENVELOPE := FC_d2i_PKCS7_SIGN_ENVELOPE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS7_SIGN_ENVELOPE_removed)}
    if d2i_PKCS7_SIGN_ENVELOPE_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS7_SIGN_ENVELOPE)}
      d2i_PKCS7_SIGN_ENVELOPE := _d2i_PKCS7_SIGN_ENVELOPE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS7_SIGN_ENVELOPE_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS7_SIGN_ENVELOPE');
    {$ifend}
  end;
  
  i2d_PKCS7_SIGN_ENVELOPE := LoadLibFunction(ADllHandle, i2d_PKCS7_SIGN_ENVELOPE_procname);
  FuncLoadError := not assigned(i2d_PKCS7_SIGN_ENVELOPE);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS7_SIGN_ENVELOPE_allownil)}
    i2d_PKCS7_SIGN_ENVELOPE := ERR_i2d_PKCS7_SIGN_ENVELOPE;
    {$ifend}
    {$if declared(i2d_PKCS7_SIGN_ENVELOPE_introduced)}
    if LibVersion < i2d_PKCS7_SIGN_ENVELOPE_introduced then
    begin
      {$if declared(FC_i2d_PKCS7_SIGN_ENVELOPE)}
      i2d_PKCS7_SIGN_ENVELOPE := FC_i2d_PKCS7_SIGN_ENVELOPE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS7_SIGN_ENVELOPE_removed)}
    if i2d_PKCS7_SIGN_ENVELOPE_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS7_SIGN_ENVELOPE)}
      i2d_PKCS7_SIGN_ENVELOPE := _i2d_PKCS7_SIGN_ENVELOPE;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS7_SIGN_ENVELOPE_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS7_SIGN_ENVELOPE');
    {$ifend}
  end;
  
  PKCS7_SIGN_ENVELOPE_it := LoadLibFunction(ADllHandle, PKCS7_SIGN_ENVELOPE_it_procname);
  FuncLoadError := not assigned(PKCS7_SIGN_ENVELOPE_it);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_SIGN_ENVELOPE_it_allownil)}
    PKCS7_SIGN_ENVELOPE_it := ERR_PKCS7_SIGN_ENVELOPE_it;
    {$ifend}
    {$if declared(PKCS7_SIGN_ENVELOPE_it_introduced)}
    if LibVersion < PKCS7_SIGN_ENVELOPE_it_introduced then
    begin
      {$if declared(FC_PKCS7_SIGN_ENVELOPE_it)}
      PKCS7_SIGN_ENVELOPE_it := FC_PKCS7_SIGN_ENVELOPE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_SIGN_ENVELOPE_it_removed)}
    if PKCS7_SIGN_ENVELOPE_it_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_SIGN_ENVELOPE_it)}
      PKCS7_SIGN_ENVELOPE_it := _PKCS7_SIGN_ENVELOPE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_SIGN_ENVELOPE_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_SIGN_ENVELOPE_it');
    {$ifend}
  end;
  
  PKCS7_DIGEST_new := LoadLibFunction(ADllHandle, PKCS7_DIGEST_new_procname);
  FuncLoadError := not assigned(PKCS7_DIGEST_new);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_DIGEST_new_allownil)}
    PKCS7_DIGEST_new := ERR_PKCS7_DIGEST_new;
    {$ifend}
    {$if declared(PKCS7_DIGEST_new_introduced)}
    if LibVersion < PKCS7_DIGEST_new_introduced then
    begin
      {$if declared(FC_PKCS7_DIGEST_new)}
      PKCS7_DIGEST_new := FC_PKCS7_DIGEST_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_DIGEST_new_removed)}
    if PKCS7_DIGEST_new_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_DIGEST_new)}
      PKCS7_DIGEST_new := _PKCS7_DIGEST_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_DIGEST_new_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_DIGEST_new');
    {$ifend}
  end;
  
  PKCS7_DIGEST_free := LoadLibFunction(ADllHandle, PKCS7_DIGEST_free_procname);
  FuncLoadError := not assigned(PKCS7_DIGEST_free);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_DIGEST_free_allownil)}
    PKCS7_DIGEST_free := ERR_PKCS7_DIGEST_free;
    {$ifend}
    {$if declared(PKCS7_DIGEST_free_introduced)}
    if LibVersion < PKCS7_DIGEST_free_introduced then
    begin
      {$if declared(FC_PKCS7_DIGEST_free)}
      PKCS7_DIGEST_free := FC_PKCS7_DIGEST_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_DIGEST_free_removed)}
    if PKCS7_DIGEST_free_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_DIGEST_free)}
      PKCS7_DIGEST_free := _PKCS7_DIGEST_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_DIGEST_free_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_DIGEST_free');
    {$ifend}
  end;
  
  d2i_PKCS7_DIGEST := LoadLibFunction(ADllHandle, d2i_PKCS7_DIGEST_procname);
  FuncLoadError := not assigned(d2i_PKCS7_DIGEST);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS7_DIGEST_allownil)}
    d2i_PKCS7_DIGEST := ERR_d2i_PKCS7_DIGEST;
    {$ifend}
    {$if declared(d2i_PKCS7_DIGEST_introduced)}
    if LibVersion < d2i_PKCS7_DIGEST_introduced then
    begin
      {$if declared(FC_d2i_PKCS7_DIGEST)}
      d2i_PKCS7_DIGEST := FC_d2i_PKCS7_DIGEST;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS7_DIGEST_removed)}
    if d2i_PKCS7_DIGEST_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS7_DIGEST)}
      d2i_PKCS7_DIGEST := _d2i_PKCS7_DIGEST;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS7_DIGEST_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS7_DIGEST');
    {$ifend}
  end;
  
  i2d_PKCS7_DIGEST := LoadLibFunction(ADllHandle, i2d_PKCS7_DIGEST_procname);
  FuncLoadError := not assigned(i2d_PKCS7_DIGEST);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS7_DIGEST_allownil)}
    i2d_PKCS7_DIGEST := ERR_i2d_PKCS7_DIGEST;
    {$ifend}
    {$if declared(i2d_PKCS7_DIGEST_introduced)}
    if LibVersion < i2d_PKCS7_DIGEST_introduced then
    begin
      {$if declared(FC_i2d_PKCS7_DIGEST)}
      i2d_PKCS7_DIGEST := FC_i2d_PKCS7_DIGEST;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS7_DIGEST_removed)}
    if i2d_PKCS7_DIGEST_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS7_DIGEST)}
      i2d_PKCS7_DIGEST := _i2d_PKCS7_DIGEST;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS7_DIGEST_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS7_DIGEST');
    {$ifend}
  end;
  
  PKCS7_DIGEST_it := LoadLibFunction(ADllHandle, PKCS7_DIGEST_it_procname);
  FuncLoadError := not assigned(PKCS7_DIGEST_it);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_DIGEST_it_allownil)}
    PKCS7_DIGEST_it := ERR_PKCS7_DIGEST_it;
    {$ifend}
    {$if declared(PKCS7_DIGEST_it_introduced)}
    if LibVersion < PKCS7_DIGEST_it_introduced then
    begin
      {$if declared(FC_PKCS7_DIGEST_it)}
      PKCS7_DIGEST_it := FC_PKCS7_DIGEST_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_DIGEST_it_removed)}
    if PKCS7_DIGEST_it_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_DIGEST_it)}
      PKCS7_DIGEST_it := _PKCS7_DIGEST_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_DIGEST_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_DIGEST_it');
    {$ifend}
  end;
  
  PKCS7_ENCRYPT_new := LoadLibFunction(ADllHandle, PKCS7_ENCRYPT_new_procname);
  FuncLoadError := not assigned(PKCS7_ENCRYPT_new);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_ENCRYPT_new_allownil)}
    PKCS7_ENCRYPT_new := ERR_PKCS7_ENCRYPT_new;
    {$ifend}
    {$if declared(PKCS7_ENCRYPT_new_introduced)}
    if LibVersion < PKCS7_ENCRYPT_new_introduced then
    begin
      {$if declared(FC_PKCS7_ENCRYPT_new)}
      PKCS7_ENCRYPT_new := FC_PKCS7_ENCRYPT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_ENCRYPT_new_removed)}
    if PKCS7_ENCRYPT_new_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_ENCRYPT_new)}
      PKCS7_ENCRYPT_new := _PKCS7_ENCRYPT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_ENCRYPT_new_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_ENCRYPT_new');
    {$ifend}
  end;
  
  PKCS7_ENCRYPT_free := LoadLibFunction(ADllHandle, PKCS7_ENCRYPT_free_procname);
  FuncLoadError := not assigned(PKCS7_ENCRYPT_free);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_ENCRYPT_free_allownil)}
    PKCS7_ENCRYPT_free := ERR_PKCS7_ENCRYPT_free;
    {$ifend}
    {$if declared(PKCS7_ENCRYPT_free_introduced)}
    if LibVersion < PKCS7_ENCRYPT_free_introduced then
    begin
      {$if declared(FC_PKCS7_ENCRYPT_free)}
      PKCS7_ENCRYPT_free := FC_PKCS7_ENCRYPT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_ENCRYPT_free_removed)}
    if PKCS7_ENCRYPT_free_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_ENCRYPT_free)}
      PKCS7_ENCRYPT_free := _PKCS7_ENCRYPT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_ENCRYPT_free_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_ENCRYPT_free');
    {$ifend}
  end;
  
  d2i_PKCS7_ENCRYPT := LoadLibFunction(ADllHandle, d2i_PKCS7_ENCRYPT_procname);
  FuncLoadError := not assigned(d2i_PKCS7_ENCRYPT);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS7_ENCRYPT_allownil)}
    d2i_PKCS7_ENCRYPT := ERR_d2i_PKCS7_ENCRYPT;
    {$ifend}
    {$if declared(d2i_PKCS7_ENCRYPT_introduced)}
    if LibVersion < d2i_PKCS7_ENCRYPT_introduced then
    begin
      {$if declared(FC_d2i_PKCS7_ENCRYPT)}
      d2i_PKCS7_ENCRYPT := FC_d2i_PKCS7_ENCRYPT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS7_ENCRYPT_removed)}
    if d2i_PKCS7_ENCRYPT_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS7_ENCRYPT)}
      d2i_PKCS7_ENCRYPT := _d2i_PKCS7_ENCRYPT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS7_ENCRYPT_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS7_ENCRYPT');
    {$ifend}
  end;
  
  i2d_PKCS7_ENCRYPT := LoadLibFunction(ADllHandle, i2d_PKCS7_ENCRYPT_procname);
  FuncLoadError := not assigned(i2d_PKCS7_ENCRYPT);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS7_ENCRYPT_allownil)}
    i2d_PKCS7_ENCRYPT := ERR_i2d_PKCS7_ENCRYPT;
    {$ifend}
    {$if declared(i2d_PKCS7_ENCRYPT_introduced)}
    if LibVersion < i2d_PKCS7_ENCRYPT_introduced then
    begin
      {$if declared(FC_i2d_PKCS7_ENCRYPT)}
      i2d_PKCS7_ENCRYPT := FC_i2d_PKCS7_ENCRYPT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS7_ENCRYPT_removed)}
    if i2d_PKCS7_ENCRYPT_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS7_ENCRYPT)}
      i2d_PKCS7_ENCRYPT := _i2d_PKCS7_ENCRYPT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS7_ENCRYPT_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS7_ENCRYPT');
    {$ifend}
  end;
  
  PKCS7_ENCRYPT_it := LoadLibFunction(ADllHandle, PKCS7_ENCRYPT_it_procname);
  FuncLoadError := not assigned(PKCS7_ENCRYPT_it);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_ENCRYPT_it_allownil)}
    PKCS7_ENCRYPT_it := ERR_PKCS7_ENCRYPT_it;
    {$ifend}
    {$if declared(PKCS7_ENCRYPT_it_introduced)}
    if LibVersion < PKCS7_ENCRYPT_it_introduced then
    begin
      {$if declared(FC_PKCS7_ENCRYPT_it)}
      PKCS7_ENCRYPT_it := FC_PKCS7_ENCRYPT_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_ENCRYPT_it_removed)}
    if PKCS7_ENCRYPT_it_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_ENCRYPT_it)}
      PKCS7_ENCRYPT_it := _PKCS7_ENCRYPT_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_ENCRYPT_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_ENCRYPT_it');
    {$ifend}
  end;
  
  PKCS7_new := LoadLibFunction(ADllHandle, PKCS7_new_procname);
  FuncLoadError := not assigned(PKCS7_new);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_new_allownil)}
    PKCS7_new := ERR_PKCS7_new;
    {$ifend}
    {$if declared(PKCS7_new_introduced)}
    if LibVersion < PKCS7_new_introduced then
    begin
      {$if declared(FC_PKCS7_new)}
      PKCS7_new := FC_PKCS7_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_new_removed)}
    if PKCS7_new_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_new)}
      PKCS7_new := _PKCS7_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_new_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_new');
    {$ifend}
  end;
  
  PKCS7_free := LoadLibFunction(ADllHandle, PKCS7_free_procname);
  FuncLoadError := not assigned(PKCS7_free);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_free_allownil)}
    PKCS7_free := ERR_PKCS7_free;
    {$ifend}
    {$if declared(PKCS7_free_introduced)}
    if LibVersion < PKCS7_free_introduced then
    begin
      {$if declared(FC_PKCS7_free)}
      PKCS7_free := FC_PKCS7_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_free_removed)}
    if PKCS7_free_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_free)}
      PKCS7_free := _PKCS7_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_free_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_free');
    {$ifend}
  end;
  
  d2i_PKCS7 := LoadLibFunction(ADllHandle, d2i_PKCS7_procname);
  FuncLoadError := not assigned(d2i_PKCS7);
  if FuncLoadError then
  begin
    {$if not defined(d2i_PKCS7_allownil)}
    d2i_PKCS7 := ERR_d2i_PKCS7;
    {$ifend}
    {$if declared(d2i_PKCS7_introduced)}
    if LibVersion < d2i_PKCS7_introduced then
    begin
      {$if declared(FC_d2i_PKCS7)}
      d2i_PKCS7 := FC_d2i_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_PKCS7_removed)}
    if d2i_PKCS7_removed <= LibVersion then
    begin
      {$if declared(_d2i_PKCS7)}
      d2i_PKCS7 := _d2i_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_PKCS7_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_PKCS7');
    {$ifend}
  end;
  
  i2d_PKCS7 := LoadLibFunction(ADllHandle, i2d_PKCS7_procname);
  FuncLoadError := not assigned(i2d_PKCS7);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS7_allownil)}
    i2d_PKCS7 := ERR_i2d_PKCS7;
    {$ifend}
    {$if declared(i2d_PKCS7_introduced)}
    if LibVersion < i2d_PKCS7_introduced then
    begin
      {$if declared(FC_i2d_PKCS7)}
      i2d_PKCS7 := FC_i2d_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS7_removed)}
    if i2d_PKCS7_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS7)}
      i2d_PKCS7 := _i2d_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS7_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS7');
    {$ifend}
  end;
  
  PKCS7_it := LoadLibFunction(ADllHandle, PKCS7_it_procname);
  FuncLoadError := not assigned(PKCS7_it);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_it_allownil)}
    PKCS7_it := ERR_PKCS7_it;
    {$ifend}
    {$if declared(PKCS7_it_introduced)}
    if LibVersion < PKCS7_it_introduced then
    begin
      {$if declared(FC_PKCS7_it)}
      PKCS7_it := FC_PKCS7_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_it_removed)}
    if PKCS7_it_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_it)}
      PKCS7_it := _PKCS7_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_it');
    {$ifend}
  end;
  
  PKCS7_new_ex := LoadLibFunction(ADllHandle, PKCS7_new_ex_procname);
  FuncLoadError := not assigned(PKCS7_new_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_new_ex_allownil)}
    PKCS7_new_ex := ERR_PKCS7_new_ex;
    {$ifend}
    {$if declared(PKCS7_new_ex_introduced)}
    if LibVersion < PKCS7_new_ex_introduced then
    begin
      {$if declared(FC_PKCS7_new_ex)}
      PKCS7_new_ex := FC_PKCS7_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_new_ex_removed)}
    if PKCS7_new_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_new_ex)}
      PKCS7_new_ex := _PKCS7_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_new_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_new_ex');
    {$ifend}
  end;
  
  PKCS7_ATTR_SIGN_it := LoadLibFunction(ADllHandle, PKCS7_ATTR_SIGN_it_procname);
  FuncLoadError := not assigned(PKCS7_ATTR_SIGN_it);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_ATTR_SIGN_it_allownil)}
    PKCS7_ATTR_SIGN_it := ERR_PKCS7_ATTR_SIGN_it;
    {$ifend}
    {$if declared(PKCS7_ATTR_SIGN_it_introduced)}
    if LibVersion < PKCS7_ATTR_SIGN_it_introduced then
    begin
      {$if declared(FC_PKCS7_ATTR_SIGN_it)}
      PKCS7_ATTR_SIGN_it := FC_PKCS7_ATTR_SIGN_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_ATTR_SIGN_it_removed)}
    if PKCS7_ATTR_SIGN_it_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_ATTR_SIGN_it)}
      PKCS7_ATTR_SIGN_it := _PKCS7_ATTR_SIGN_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_ATTR_SIGN_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_ATTR_SIGN_it');
    {$ifend}
  end;
  
  PKCS7_ATTR_VERIFY_it := LoadLibFunction(ADllHandle, PKCS7_ATTR_VERIFY_it_procname);
  FuncLoadError := not assigned(PKCS7_ATTR_VERIFY_it);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_ATTR_VERIFY_it_allownil)}
    PKCS7_ATTR_VERIFY_it := ERR_PKCS7_ATTR_VERIFY_it;
    {$ifend}
    {$if declared(PKCS7_ATTR_VERIFY_it_introduced)}
    if LibVersion < PKCS7_ATTR_VERIFY_it_introduced then
    begin
      {$if declared(FC_PKCS7_ATTR_VERIFY_it)}
      PKCS7_ATTR_VERIFY_it := FC_PKCS7_ATTR_VERIFY_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_ATTR_VERIFY_it_removed)}
    if PKCS7_ATTR_VERIFY_it_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_ATTR_VERIFY_it)}
      PKCS7_ATTR_VERIFY_it := _PKCS7_ATTR_VERIFY_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_ATTR_VERIFY_it_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_ATTR_VERIFY_it');
    {$ifend}
  end;
  
  i2d_PKCS7_NDEF := LoadLibFunction(ADllHandle, i2d_PKCS7_NDEF_procname);
  FuncLoadError := not assigned(i2d_PKCS7_NDEF);
  if FuncLoadError then
  begin
    {$if not defined(i2d_PKCS7_NDEF_allownil)}
    i2d_PKCS7_NDEF := ERR_i2d_PKCS7_NDEF;
    {$ifend}
    {$if declared(i2d_PKCS7_NDEF_introduced)}
    if LibVersion < i2d_PKCS7_NDEF_introduced then
    begin
      {$if declared(FC_i2d_PKCS7_NDEF)}
      i2d_PKCS7_NDEF := FC_i2d_PKCS7_NDEF;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_PKCS7_NDEF_removed)}
    if i2d_PKCS7_NDEF_removed <= LibVersion then
    begin
      {$if declared(_i2d_PKCS7_NDEF)}
      i2d_PKCS7_NDEF := _i2d_PKCS7_NDEF;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_PKCS7_NDEF_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_PKCS7_NDEF');
    {$ifend}
  end;
  
  PKCS7_print_ctx := LoadLibFunction(ADllHandle, PKCS7_print_ctx_procname);
  FuncLoadError := not assigned(PKCS7_print_ctx);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_print_ctx_allownil)}
    PKCS7_print_ctx := ERR_PKCS7_print_ctx;
    {$ifend}
    {$if declared(PKCS7_print_ctx_introduced)}
    if LibVersion < PKCS7_print_ctx_introduced then
    begin
      {$if declared(FC_PKCS7_print_ctx)}
      PKCS7_print_ctx := FC_PKCS7_print_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_print_ctx_removed)}
    if PKCS7_print_ctx_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_print_ctx)}
      PKCS7_print_ctx := _PKCS7_print_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_print_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_print_ctx');
    {$ifend}
  end;
  
  PKCS7_ctrl := LoadLibFunction(ADllHandle, PKCS7_ctrl_procname);
  FuncLoadError := not assigned(PKCS7_ctrl);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_ctrl_allownil)}
    PKCS7_ctrl := ERR_PKCS7_ctrl;
    {$ifend}
    {$if declared(PKCS7_ctrl_introduced)}
    if LibVersion < PKCS7_ctrl_introduced then
    begin
      {$if declared(FC_PKCS7_ctrl)}
      PKCS7_ctrl := FC_PKCS7_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_ctrl_removed)}
    if PKCS7_ctrl_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_ctrl)}
      PKCS7_ctrl := _PKCS7_ctrl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_ctrl_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_ctrl');
    {$ifend}
  end;
  
  PKCS7_type_is_other := LoadLibFunction(ADllHandle, PKCS7_type_is_other_procname);
  FuncLoadError := not assigned(PKCS7_type_is_other);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_type_is_other_allownil)}
    PKCS7_type_is_other := ERR_PKCS7_type_is_other;
    {$ifend}
    {$if declared(PKCS7_type_is_other_introduced)}
    if LibVersion < PKCS7_type_is_other_introduced then
    begin
      {$if declared(FC_PKCS7_type_is_other)}
      PKCS7_type_is_other := FC_PKCS7_type_is_other;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_type_is_other_removed)}
    if PKCS7_type_is_other_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_type_is_other)}
      PKCS7_type_is_other := _PKCS7_type_is_other;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_type_is_other_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_type_is_other');
    {$ifend}
  end;
  
  PKCS7_set_type := LoadLibFunction(ADllHandle, PKCS7_set_type_procname);
  FuncLoadError := not assigned(PKCS7_set_type);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_set_type_allownil)}
    PKCS7_set_type := ERR_PKCS7_set_type;
    {$ifend}
    {$if declared(PKCS7_set_type_introduced)}
    if LibVersion < PKCS7_set_type_introduced then
    begin
      {$if declared(FC_PKCS7_set_type)}
      PKCS7_set_type := FC_PKCS7_set_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_set_type_removed)}
    if PKCS7_set_type_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_set_type)}
      PKCS7_set_type := _PKCS7_set_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_set_type_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_set_type');
    {$ifend}
  end;
  
  PKCS7_set0_type_other := LoadLibFunction(ADllHandle, PKCS7_set0_type_other_procname);
  FuncLoadError := not assigned(PKCS7_set0_type_other);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_set0_type_other_allownil)}
    PKCS7_set0_type_other := ERR_PKCS7_set0_type_other;
    {$ifend}
    {$if declared(PKCS7_set0_type_other_introduced)}
    if LibVersion < PKCS7_set0_type_other_introduced then
    begin
      {$if declared(FC_PKCS7_set0_type_other)}
      PKCS7_set0_type_other := FC_PKCS7_set0_type_other;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_set0_type_other_removed)}
    if PKCS7_set0_type_other_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_set0_type_other)}
      PKCS7_set0_type_other := _PKCS7_set0_type_other;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_set0_type_other_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_set0_type_other');
    {$ifend}
  end;
  
  PKCS7_set_content := LoadLibFunction(ADllHandle, PKCS7_set_content_procname);
  FuncLoadError := not assigned(PKCS7_set_content);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_set_content_allownil)}
    PKCS7_set_content := ERR_PKCS7_set_content;
    {$ifend}
    {$if declared(PKCS7_set_content_introduced)}
    if LibVersion < PKCS7_set_content_introduced then
    begin
      {$if declared(FC_PKCS7_set_content)}
      PKCS7_set_content := FC_PKCS7_set_content;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_set_content_removed)}
    if PKCS7_set_content_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_set_content)}
      PKCS7_set_content := _PKCS7_set_content;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_set_content_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_set_content');
    {$ifend}
  end;
  
  PKCS7_SIGNER_INFO_set := LoadLibFunction(ADllHandle, PKCS7_SIGNER_INFO_set_procname);
  FuncLoadError := not assigned(PKCS7_SIGNER_INFO_set);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_SIGNER_INFO_set_allownil)}
    PKCS7_SIGNER_INFO_set := ERR_PKCS7_SIGNER_INFO_set;
    {$ifend}
    {$if declared(PKCS7_SIGNER_INFO_set_introduced)}
    if LibVersion < PKCS7_SIGNER_INFO_set_introduced then
    begin
      {$if declared(FC_PKCS7_SIGNER_INFO_set)}
      PKCS7_SIGNER_INFO_set := FC_PKCS7_SIGNER_INFO_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_SIGNER_INFO_set_removed)}
    if PKCS7_SIGNER_INFO_set_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_SIGNER_INFO_set)}
      PKCS7_SIGNER_INFO_set := _PKCS7_SIGNER_INFO_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_SIGNER_INFO_set_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_SIGNER_INFO_set');
    {$ifend}
  end;
  
  PKCS7_SIGNER_INFO_sign := LoadLibFunction(ADllHandle, PKCS7_SIGNER_INFO_sign_procname);
  FuncLoadError := not assigned(PKCS7_SIGNER_INFO_sign);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_SIGNER_INFO_sign_allownil)}
    PKCS7_SIGNER_INFO_sign := ERR_PKCS7_SIGNER_INFO_sign;
    {$ifend}
    {$if declared(PKCS7_SIGNER_INFO_sign_introduced)}
    if LibVersion < PKCS7_SIGNER_INFO_sign_introduced then
    begin
      {$if declared(FC_PKCS7_SIGNER_INFO_sign)}
      PKCS7_SIGNER_INFO_sign := FC_PKCS7_SIGNER_INFO_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_SIGNER_INFO_sign_removed)}
    if PKCS7_SIGNER_INFO_sign_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_SIGNER_INFO_sign)}
      PKCS7_SIGNER_INFO_sign := _PKCS7_SIGNER_INFO_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_SIGNER_INFO_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_SIGNER_INFO_sign');
    {$ifend}
  end;
  
  PKCS7_add_signer := LoadLibFunction(ADllHandle, PKCS7_add_signer_procname);
  FuncLoadError := not assigned(PKCS7_add_signer);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_add_signer_allownil)}
    PKCS7_add_signer := ERR_PKCS7_add_signer;
    {$ifend}
    {$if declared(PKCS7_add_signer_introduced)}
    if LibVersion < PKCS7_add_signer_introduced then
    begin
      {$if declared(FC_PKCS7_add_signer)}
      PKCS7_add_signer := FC_PKCS7_add_signer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_add_signer_removed)}
    if PKCS7_add_signer_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_add_signer)}
      PKCS7_add_signer := _PKCS7_add_signer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_add_signer_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_add_signer');
    {$ifend}
  end;
  
  PKCS7_add_certificate := LoadLibFunction(ADllHandle, PKCS7_add_certificate_procname);
  FuncLoadError := not assigned(PKCS7_add_certificate);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_add_certificate_allownil)}
    PKCS7_add_certificate := ERR_PKCS7_add_certificate;
    {$ifend}
    {$if declared(PKCS7_add_certificate_introduced)}
    if LibVersion < PKCS7_add_certificate_introduced then
    begin
      {$if declared(FC_PKCS7_add_certificate)}
      PKCS7_add_certificate := FC_PKCS7_add_certificate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_add_certificate_removed)}
    if PKCS7_add_certificate_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_add_certificate)}
      PKCS7_add_certificate := _PKCS7_add_certificate;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_add_certificate_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_add_certificate');
    {$ifend}
  end;
  
  PKCS7_add_crl := LoadLibFunction(ADllHandle, PKCS7_add_crl_procname);
  FuncLoadError := not assigned(PKCS7_add_crl);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_add_crl_allownil)}
    PKCS7_add_crl := ERR_PKCS7_add_crl;
    {$ifend}
    {$if declared(PKCS7_add_crl_introduced)}
    if LibVersion < PKCS7_add_crl_introduced then
    begin
      {$if declared(FC_PKCS7_add_crl)}
      PKCS7_add_crl := FC_PKCS7_add_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_add_crl_removed)}
    if PKCS7_add_crl_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_add_crl)}
      PKCS7_add_crl := _PKCS7_add_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_add_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_add_crl');
    {$ifend}
  end;
  
  PKCS7_content_new := LoadLibFunction(ADllHandle, PKCS7_content_new_procname);
  FuncLoadError := not assigned(PKCS7_content_new);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_content_new_allownil)}
    PKCS7_content_new := ERR_PKCS7_content_new;
    {$ifend}
    {$if declared(PKCS7_content_new_introduced)}
    if LibVersion < PKCS7_content_new_introduced then
    begin
      {$if declared(FC_PKCS7_content_new)}
      PKCS7_content_new := FC_PKCS7_content_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_content_new_removed)}
    if PKCS7_content_new_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_content_new)}
      PKCS7_content_new := _PKCS7_content_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_content_new_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_content_new');
    {$ifend}
  end;
  
  PKCS7_dataVerify := LoadLibFunction(ADllHandle, PKCS7_dataVerify_procname);
  FuncLoadError := not assigned(PKCS7_dataVerify);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_dataVerify_allownil)}
    PKCS7_dataVerify := ERR_PKCS7_dataVerify;
    {$ifend}
    {$if declared(PKCS7_dataVerify_introduced)}
    if LibVersion < PKCS7_dataVerify_introduced then
    begin
      {$if declared(FC_PKCS7_dataVerify)}
      PKCS7_dataVerify := FC_PKCS7_dataVerify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_dataVerify_removed)}
    if PKCS7_dataVerify_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_dataVerify)}
      PKCS7_dataVerify := _PKCS7_dataVerify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_dataVerify_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_dataVerify');
    {$ifend}
  end;
  
  PKCS7_signatureVerify := LoadLibFunction(ADllHandle, PKCS7_signatureVerify_procname);
  FuncLoadError := not assigned(PKCS7_signatureVerify);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_signatureVerify_allownil)}
    PKCS7_signatureVerify := ERR_PKCS7_signatureVerify;
    {$ifend}
    {$if declared(PKCS7_signatureVerify_introduced)}
    if LibVersion < PKCS7_signatureVerify_introduced then
    begin
      {$if declared(FC_PKCS7_signatureVerify)}
      PKCS7_signatureVerify := FC_PKCS7_signatureVerify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_signatureVerify_removed)}
    if PKCS7_signatureVerify_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_signatureVerify)}
      PKCS7_signatureVerify := _PKCS7_signatureVerify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_signatureVerify_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_signatureVerify');
    {$ifend}
  end;
  
  PKCS7_dataInit := LoadLibFunction(ADllHandle, PKCS7_dataInit_procname);
  FuncLoadError := not assigned(PKCS7_dataInit);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_dataInit_allownil)}
    PKCS7_dataInit := ERR_PKCS7_dataInit;
    {$ifend}
    {$if declared(PKCS7_dataInit_introduced)}
    if LibVersion < PKCS7_dataInit_introduced then
    begin
      {$if declared(FC_PKCS7_dataInit)}
      PKCS7_dataInit := FC_PKCS7_dataInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_dataInit_removed)}
    if PKCS7_dataInit_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_dataInit)}
      PKCS7_dataInit := _PKCS7_dataInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_dataInit_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_dataInit');
    {$ifend}
  end;
  
  PKCS7_dataFinal := LoadLibFunction(ADllHandle, PKCS7_dataFinal_procname);
  FuncLoadError := not assigned(PKCS7_dataFinal);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_dataFinal_allownil)}
    PKCS7_dataFinal := ERR_PKCS7_dataFinal;
    {$ifend}
    {$if declared(PKCS7_dataFinal_introduced)}
    if LibVersion < PKCS7_dataFinal_introduced then
    begin
      {$if declared(FC_PKCS7_dataFinal)}
      PKCS7_dataFinal := FC_PKCS7_dataFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_dataFinal_removed)}
    if PKCS7_dataFinal_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_dataFinal)}
      PKCS7_dataFinal := _PKCS7_dataFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_dataFinal_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_dataFinal');
    {$ifend}
  end;
  
  PKCS7_dataDecode := LoadLibFunction(ADllHandle, PKCS7_dataDecode_procname);
  FuncLoadError := not assigned(PKCS7_dataDecode);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_dataDecode_allownil)}
    PKCS7_dataDecode := ERR_PKCS7_dataDecode;
    {$ifend}
    {$if declared(PKCS7_dataDecode_introduced)}
    if LibVersion < PKCS7_dataDecode_introduced then
    begin
      {$if declared(FC_PKCS7_dataDecode)}
      PKCS7_dataDecode := FC_PKCS7_dataDecode;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_dataDecode_removed)}
    if PKCS7_dataDecode_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_dataDecode)}
      PKCS7_dataDecode := _PKCS7_dataDecode;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_dataDecode_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_dataDecode');
    {$ifend}
  end;
  
  PKCS7_add_signature := LoadLibFunction(ADllHandle, PKCS7_add_signature_procname);
  FuncLoadError := not assigned(PKCS7_add_signature);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_add_signature_allownil)}
    PKCS7_add_signature := ERR_PKCS7_add_signature;
    {$ifend}
    {$if declared(PKCS7_add_signature_introduced)}
    if LibVersion < PKCS7_add_signature_introduced then
    begin
      {$if declared(FC_PKCS7_add_signature)}
      PKCS7_add_signature := FC_PKCS7_add_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_add_signature_removed)}
    if PKCS7_add_signature_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_add_signature)}
      PKCS7_add_signature := _PKCS7_add_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_add_signature_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_add_signature');
    {$ifend}
  end;
  
  PKCS7_cert_from_signer_info := LoadLibFunction(ADllHandle, PKCS7_cert_from_signer_info_procname);
  FuncLoadError := not assigned(PKCS7_cert_from_signer_info);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_cert_from_signer_info_allownil)}
    PKCS7_cert_from_signer_info := ERR_PKCS7_cert_from_signer_info;
    {$ifend}
    {$if declared(PKCS7_cert_from_signer_info_introduced)}
    if LibVersion < PKCS7_cert_from_signer_info_introduced then
    begin
      {$if declared(FC_PKCS7_cert_from_signer_info)}
      PKCS7_cert_from_signer_info := FC_PKCS7_cert_from_signer_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_cert_from_signer_info_removed)}
    if PKCS7_cert_from_signer_info_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_cert_from_signer_info)}
      PKCS7_cert_from_signer_info := _PKCS7_cert_from_signer_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_cert_from_signer_info_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_cert_from_signer_info');
    {$ifend}
  end;
  
  PKCS7_set_digest := LoadLibFunction(ADllHandle, PKCS7_set_digest_procname);
  FuncLoadError := not assigned(PKCS7_set_digest);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_set_digest_allownil)}
    PKCS7_set_digest := ERR_PKCS7_set_digest;
    {$ifend}
    {$if declared(PKCS7_set_digest_introduced)}
    if LibVersion < PKCS7_set_digest_introduced then
    begin
      {$if declared(FC_PKCS7_set_digest)}
      PKCS7_set_digest := FC_PKCS7_set_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_set_digest_removed)}
    if PKCS7_set_digest_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_set_digest)}
      PKCS7_set_digest := _PKCS7_set_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_set_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_set_digest');
    {$ifend}
  end;
  
  PKCS7_get_signer_info := LoadLibFunction(ADllHandle, PKCS7_get_signer_info_procname);
  FuncLoadError := not assigned(PKCS7_get_signer_info);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_get_signer_info_allownil)}
    PKCS7_get_signer_info := ERR_PKCS7_get_signer_info;
    {$ifend}
    {$if declared(PKCS7_get_signer_info_introduced)}
    if LibVersion < PKCS7_get_signer_info_introduced then
    begin
      {$if declared(FC_PKCS7_get_signer_info)}
      PKCS7_get_signer_info := FC_PKCS7_get_signer_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_get_signer_info_removed)}
    if PKCS7_get_signer_info_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_get_signer_info)}
      PKCS7_get_signer_info := _PKCS7_get_signer_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_get_signer_info_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_get_signer_info');
    {$ifend}
  end;
  
  PKCS7_add_recipient := LoadLibFunction(ADllHandle, PKCS7_add_recipient_procname);
  FuncLoadError := not assigned(PKCS7_add_recipient);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_add_recipient_allownil)}
    PKCS7_add_recipient := ERR_PKCS7_add_recipient;
    {$ifend}
    {$if declared(PKCS7_add_recipient_introduced)}
    if LibVersion < PKCS7_add_recipient_introduced then
    begin
      {$if declared(FC_PKCS7_add_recipient)}
      PKCS7_add_recipient := FC_PKCS7_add_recipient;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_add_recipient_removed)}
    if PKCS7_add_recipient_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_add_recipient)}
      PKCS7_add_recipient := _PKCS7_add_recipient;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_add_recipient_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_add_recipient');
    {$ifend}
  end;
  
  PKCS7_SIGNER_INFO_get0_algs := LoadLibFunction(ADllHandle, PKCS7_SIGNER_INFO_get0_algs_procname);
  FuncLoadError := not assigned(PKCS7_SIGNER_INFO_get0_algs);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_SIGNER_INFO_get0_algs_allownil)}
    PKCS7_SIGNER_INFO_get0_algs := ERR_PKCS7_SIGNER_INFO_get0_algs;
    {$ifend}
    {$if declared(PKCS7_SIGNER_INFO_get0_algs_introduced)}
    if LibVersion < PKCS7_SIGNER_INFO_get0_algs_introduced then
    begin
      {$if declared(FC_PKCS7_SIGNER_INFO_get0_algs)}
      PKCS7_SIGNER_INFO_get0_algs := FC_PKCS7_SIGNER_INFO_get0_algs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_SIGNER_INFO_get0_algs_removed)}
    if PKCS7_SIGNER_INFO_get0_algs_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_SIGNER_INFO_get0_algs)}
      PKCS7_SIGNER_INFO_get0_algs := _PKCS7_SIGNER_INFO_get0_algs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_SIGNER_INFO_get0_algs_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_SIGNER_INFO_get0_algs');
    {$ifend}
  end;
  
  PKCS7_RECIP_INFO_get0_alg := LoadLibFunction(ADllHandle, PKCS7_RECIP_INFO_get0_alg_procname);
  FuncLoadError := not assigned(PKCS7_RECIP_INFO_get0_alg);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_RECIP_INFO_get0_alg_allownil)}
    PKCS7_RECIP_INFO_get0_alg := ERR_PKCS7_RECIP_INFO_get0_alg;
    {$ifend}
    {$if declared(PKCS7_RECIP_INFO_get0_alg_introduced)}
    if LibVersion < PKCS7_RECIP_INFO_get0_alg_introduced then
    begin
      {$if declared(FC_PKCS7_RECIP_INFO_get0_alg)}
      PKCS7_RECIP_INFO_get0_alg := FC_PKCS7_RECIP_INFO_get0_alg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_RECIP_INFO_get0_alg_removed)}
    if PKCS7_RECIP_INFO_get0_alg_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_RECIP_INFO_get0_alg)}
      PKCS7_RECIP_INFO_get0_alg := _PKCS7_RECIP_INFO_get0_alg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_RECIP_INFO_get0_alg_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_RECIP_INFO_get0_alg');
    {$ifend}
  end;
  
  PKCS7_add_recipient_info := LoadLibFunction(ADllHandle, PKCS7_add_recipient_info_procname);
  FuncLoadError := not assigned(PKCS7_add_recipient_info);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_add_recipient_info_allownil)}
    PKCS7_add_recipient_info := ERR_PKCS7_add_recipient_info;
    {$ifend}
    {$if declared(PKCS7_add_recipient_info_introduced)}
    if LibVersion < PKCS7_add_recipient_info_introduced then
    begin
      {$if declared(FC_PKCS7_add_recipient_info)}
      PKCS7_add_recipient_info := FC_PKCS7_add_recipient_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_add_recipient_info_removed)}
    if PKCS7_add_recipient_info_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_add_recipient_info)}
      PKCS7_add_recipient_info := _PKCS7_add_recipient_info;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_add_recipient_info_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_add_recipient_info');
    {$ifend}
  end;
  
  PKCS7_RECIP_INFO_set := LoadLibFunction(ADllHandle, PKCS7_RECIP_INFO_set_procname);
  FuncLoadError := not assigned(PKCS7_RECIP_INFO_set);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_RECIP_INFO_set_allownil)}
    PKCS7_RECIP_INFO_set := ERR_PKCS7_RECIP_INFO_set;
    {$ifend}
    {$if declared(PKCS7_RECIP_INFO_set_introduced)}
    if LibVersion < PKCS7_RECIP_INFO_set_introduced then
    begin
      {$if declared(FC_PKCS7_RECIP_INFO_set)}
      PKCS7_RECIP_INFO_set := FC_PKCS7_RECIP_INFO_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_RECIP_INFO_set_removed)}
    if PKCS7_RECIP_INFO_set_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_RECIP_INFO_set)}
      PKCS7_RECIP_INFO_set := _PKCS7_RECIP_INFO_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_RECIP_INFO_set_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_RECIP_INFO_set');
    {$ifend}
  end;
  
  PKCS7_set_cipher := LoadLibFunction(ADllHandle, PKCS7_set_cipher_procname);
  FuncLoadError := not assigned(PKCS7_set_cipher);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_set_cipher_allownil)}
    PKCS7_set_cipher := ERR_PKCS7_set_cipher;
    {$ifend}
    {$if declared(PKCS7_set_cipher_introduced)}
    if LibVersion < PKCS7_set_cipher_introduced then
    begin
      {$if declared(FC_PKCS7_set_cipher)}
      PKCS7_set_cipher := FC_PKCS7_set_cipher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_set_cipher_removed)}
    if PKCS7_set_cipher_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_set_cipher)}
      PKCS7_set_cipher := _PKCS7_set_cipher;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_set_cipher_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_set_cipher');
    {$ifend}
  end;
  
  PKCS7_stream := LoadLibFunction(ADllHandle, PKCS7_stream_procname);
  FuncLoadError := not assigned(PKCS7_stream);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_stream_allownil)}
    PKCS7_stream := ERR_PKCS7_stream;
    {$ifend}
    {$if declared(PKCS7_stream_introduced)}
    if LibVersion < PKCS7_stream_introduced then
    begin
      {$if declared(FC_PKCS7_stream)}
      PKCS7_stream := FC_PKCS7_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_stream_removed)}
    if PKCS7_stream_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_stream)}
      PKCS7_stream := _PKCS7_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_stream_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_stream');
    {$ifend}
  end;
  
  PKCS7_get_issuer_and_serial := LoadLibFunction(ADllHandle, PKCS7_get_issuer_and_serial_procname);
  FuncLoadError := not assigned(PKCS7_get_issuer_and_serial);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_get_issuer_and_serial_allownil)}
    PKCS7_get_issuer_and_serial := ERR_PKCS7_get_issuer_and_serial;
    {$ifend}
    {$if declared(PKCS7_get_issuer_and_serial_introduced)}
    if LibVersion < PKCS7_get_issuer_and_serial_introduced then
    begin
      {$if declared(FC_PKCS7_get_issuer_and_serial)}
      PKCS7_get_issuer_and_serial := FC_PKCS7_get_issuer_and_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_get_issuer_and_serial_removed)}
    if PKCS7_get_issuer_and_serial_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_get_issuer_and_serial)}
      PKCS7_get_issuer_and_serial := _PKCS7_get_issuer_and_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_get_issuer_and_serial_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_get_issuer_and_serial');
    {$ifend}
  end;
  
  PKCS7_get_octet_string := LoadLibFunction(ADllHandle, PKCS7_get_octet_string_procname);
  FuncLoadError := not assigned(PKCS7_get_octet_string);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_get_octet_string_allownil)}
    PKCS7_get_octet_string := ERR_PKCS7_get_octet_string;
    {$ifend}
    {$if declared(PKCS7_get_octet_string_introduced)}
    if LibVersion < PKCS7_get_octet_string_introduced then
    begin
      {$if declared(FC_PKCS7_get_octet_string)}
      PKCS7_get_octet_string := FC_PKCS7_get_octet_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_get_octet_string_removed)}
    if PKCS7_get_octet_string_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_get_octet_string)}
      PKCS7_get_octet_string := _PKCS7_get_octet_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_get_octet_string_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_get_octet_string');
    {$ifend}
  end;
  
  PKCS7_digest_from_attributes := LoadLibFunction(ADllHandle, PKCS7_digest_from_attributes_procname);
  FuncLoadError := not assigned(PKCS7_digest_from_attributes);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_digest_from_attributes_allownil)}
    PKCS7_digest_from_attributes := ERR_PKCS7_digest_from_attributes;
    {$ifend}
    {$if declared(PKCS7_digest_from_attributes_introduced)}
    if LibVersion < PKCS7_digest_from_attributes_introduced then
    begin
      {$if declared(FC_PKCS7_digest_from_attributes)}
      PKCS7_digest_from_attributes := FC_PKCS7_digest_from_attributes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_digest_from_attributes_removed)}
    if PKCS7_digest_from_attributes_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_digest_from_attributes)}
      PKCS7_digest_from_attributes := _PKCS7_digest_from_attributes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_digest_from_attributes_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_digest_from_attributes');
    {$ifend}
  end;
  
  PKCS7_add_signed_attribute := LoadLibFunction(ADllHandle, PKCS7_add_signed_attribute_procname);
  FuncLoadError := not assigned(PKCS7_add_signed_attribute);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_add_signed_attribute_allownil)}
    PKCS7_add_signed_attribute := ERR_PKCS7_add_signed_attribute;
    {$ifend}
    {$if declared(PKCS7_add_signed_attribute_introduced)}
    if LibVersion < PKCS7_add_signed_attribute_introduced then
    begin
      {$if declared(FC_PKCS7_add_signed_attribute)}
      PKCS7_add_signed_attribute := FC_PKCS7_add_signed_attribute;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_add_signed_attribute_removed)}
    if PKCS7_add_signed_attribute_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_add_signed_attribute)}
      PKCS7_add_signed_attribute := _PKCS7_add_signed_attribute;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_add_signed_attribute_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_add_signed_attribute');
    {$ifend}
  end;
  
  PKCS7_add_attribute := LoadLibFunction(ADllHandle, PKCS7_add_attribute_procname);
  FuncLoadError := not assigned(PKCS7_add_attribute);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_add_attribute_allownil)}
    PKCS7_add_attribute := ERR_PKCS7_add_attribute;
    {$ifend}
    {$if declared(PKCS7_add_attribute_introduced)}
    if LibVersion < PKCS7_add_attribute_introduced then
    begin
      {$if declared(FC_PKCS7_add_attribute)}
      PKCS7_add_attribute := FC_PKCS7_add_attribute;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_add_attribute_removed)}
    if PKCS7_add_attribute_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_add_attribute)}
      PKCS7_add_attribute := _PKCS7_add_attribute;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_add_attribute_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_add_attribute');
    {$ifend}
  end;
  
  PKCS7_get_attribute := LoadLibFunction(ADllHandle, PKCS7_get_attribute_procname);
  FuncLoadError := not assigned(PKCS7_get_attribute);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_get_attribute_allownil)}
    PKCS7_get_attribute := ERR_PKCS7_get_attribute;
    {$ifend}
    {$if declared(PKCS7_get_attribute_introduced)}
    if LibVersion < PKCS7_get_attribute_introduced then
    begin
      {$if declared(FC_PKCS7_get_attribute)}
      PKCS7_get_attribute := FC_PKCS7_get_attribute;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_get_attribute_removed)}
    if PKCS7_get_attribute_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_get_attribute)}
      PKCS7_get_attribute := _PKCS7_get_attribute;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_get_attribute_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_get_attribute');
    {$ifend}
  end;
  
  PKCS7_get_signed_attribute := LoadLibFunction(ADllHandle, PKCS7_get_signed_attribute_procname);
  FuncLoadError := not assigned(PKCS7_get_signed_attribute);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_get_signed_attribute_allownil)}
    PKCS7_get_signed_attribute := ERR_PKCS7_get_signed_attribute;
    {$ifend}
    {$if declared(PKCS7_get_signed_attribute_introduced)}
    if LibVersion < PKCS7_get_signed_attribute_introduced then
    begin
      {$if declared(FC_PKCS7_get_signed_attribute)}
      PKCS7_get_signed_attribute := FC_PKCS7_get_signed_attribute;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_get_signed_attribute_removed)}
    if PKCS7_get_signed_attribute_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_get_signed_attribute)}
      PKCS7_get_signed_attribute := _PKCS7_get_signed_attribute;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_get_signed_attribute_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_get_signed_attribute');
    {$ifend}
  end;
  
  PKCS7_set_signed_attributes := LoadLibFunction(ADllHandle, PKCS7_set_signed_attributes_procname);
  FuncLoadError := not assigned(PKCS7_set_signed_attributes);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_set_signed_attributes_allownil)}
    PKCS7_set_signed_attributes := ERR_PKCS7_set_signed_attributes;
    {$ifend}
    {$if declared(PKCS7_set_signed_attributes_introduced)}
    if LibVersion < PKCS7_set_signed_attributes_introduced then
    begin
      {$if declared(FC_PKCS7_set_signed_attributes)}
      PKCS7_set_signed_attributes := FC_PKCS7_set_signed_attributes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_set_signed_attributes_removed)}
    if PKCS7_set_signed_attributes_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_set_signed_attributes)}
      PKCS7_set_signed_attributes := _PKCS7_set_signed_attributes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_set_signed_attributes_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_set_signed_attributes');
    {$ifend}
  end;
  
  PKCS7_set_attributes := LoadLibFunction(ADllHandle, PKCS7_set_attributes_procname);
  FuncLoadError := not assigned(PKCS7_set_attributes);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_set_attributes_allownil)}
    PKCS7_set_attributes := ERR_PKCS7_set_attributes;
    {$ifend}
    {$if declared(PKCS7_set_attributes_introduced)}
    if LibVersion < PKCS7_set_attributes_introduced then
    begin
      {$if declared(FC_PKCS7_set_attributes)}
      PKCS7_set_attributes := FC_PKCS7_set_attributes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_set_attributes_removed)}
    if PKCS7_set_attributes_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_set_attributes)}
      PKCS7_set_attributes := _PKCS7_set_attributes;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_set_attributes_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_set_attributes');
    {$ifend}
  end;
  
  PKCS7_sign := LoadLibFunction(ADllHandle, PKCS7_sign_procname);
  FuncLoadError := not assigned(PKCS7_sign);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_sign_allownil)}
    PKCS7_sign := ERR_PKCS7_sign;
    {$ifend}
    {$if declared(PKCS7_sign_introduced)}
    if LibVersion < PKCS7_sign_introduced then
    begin
      {$if declared(FC_PKCS7_sign)}
      PKCS7_sign := FC_PKCS7_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_sign_removed)}
    if PKCS7_sign_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_sign)}
      PKCS7_sign := _PKCS7_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_sign');
    {$ifend}
  end;
  
  PKCS7_sign_ex := LoadLibFunction(ADllHandle, PKCS7_sign_ex_procname);
  FuncLoadError := not assigned(PKCS7_sign_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_sign_ex_allownil)}
    PKCS7_sign_ex := ERR_PKCS7_sign_ex;
    {$ifend}
    {$if declared(PKCS7_sign_ex_introduced)}
    if LibVersion < PKCS7_sign_ex_introduced then
    begin
      {$if declared(FC_PKCS7_sign_ex)}
      PKCS7_sign_ex := FC_PKCS7_sign_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_sign_ex_removed)}
    if PKCS7_sign_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_sign_ex)}
      PKCS7_sign_ex := _PKCS7_sign_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_sign_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_sign_ex');
    {$ifend}
  end;
  
  PKCS7_sign_add_signer := LoadLibFunction(ADllHandle, PKCS7_sign_add_signer_procname);
  FuncLoadError := not assigned(PKCS7_sign_add_signer);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_sign_add_signer_allownil)}
    PKCS7_sign_add_signer := ERR_PKCS7_sign_add_signer;
    {$ifend}
    {$if declared(PKCS7_sign_add_signer_introduced)}
    if LibVersion < PKCS7_sign_add_signer_introduced then
    begin
      {$if declared(FC_PKCS7_sign_add_signer)}
      PKCS7_sign_add_signer := FC_PKCS7_sign_add_signer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_sign_add_signer_removed)}
    if PKCS7_sign_add_signer_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_sign_add_signer)}
      PKCS7_sign_add_signer := _PKCS7_sign_add_signer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_sign_add_signer_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_sign_add_signer');
    {$ifend}
  end;
  
  PKCS7_final := LoadLibFunction(ADllHandle, PKCS7_final_procname);
  FuncLoadError := not assigned(PKCS7_final);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_final_allownil)}
    PKCS7_final := ERR_PKCS7_final;
    {$ifend}
    {$if declared(PKCS7_final_introduced)}
    if LibVersion < PKCS7_final_introduced then
    begin
      {$if declared(FC_PKCS7_final)}
      PKCS7_final := FC_PKCS7_final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_final_removed)}
    if PKCS7_final_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_final)}
      PKCS7_final := _PKCS7_final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_final_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_final');
    {$ifend}
  end;
  
  PKCS7_verify := LoadLibFunction(ADllHandle, PKCS7_verify_procname);
  FuncLoadError := not assigned(PKCS7_verify);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_verify_allownil)}
    PKCS7_verify := ERR_PKCS7_verify;
    {$ifend}
    {$if declared(PKCS7_verify_introduced)}
    if LibVersion < PKCS7_verify_introduced then
    begin
      {$if declared(FC_PKCS7_verify)}
      PKCS7_verify := FC_PKCS7_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_verify_removed)}
    if PKCS7_verify_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_verify)}
      PKCS7_verify := _PKCS7_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_verify');
    {$ifend}
  end;
  
  PKCS7_get0_signers := LoadLibFunction(ADllHandle, PKCS7_get0_signers_procname);
  FuncLoadError := not assigned(PKCS7_get0_signers);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_get0_signers_allownil)}
    PKCS7_get0_signers := ERR_PKCS7_get0_signers;
    {$ifend}
    {$if declared(PKCS7_get0_signers_introduced)}
    if LibVersion < PKCS7_get0_signers_introduced then
    begin
      {$if declared(FC_PKCS7_get0_signers)}
      PKCS7_get0_signers := FC_PKCS7_get0_signers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_get0_signers_removed)}
    if PKCS7_get0_signers_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_get0_signers)}
      PKCS7_get0_signers := _PKCS7_get0_signers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_get0_signers_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_get0_signers');
    {$ifend}
  end;
  
  PKCS7_encrypt := LoadLibFunction(ADllHandle, PKCS7_encrypt_procname);
  FuncLoadError := not assigned(PKCS7_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_encrypt_allownil)}
    PKCS7_encrypt := ERR_PKCS7_encrypt;
    {$ifend}
    {$if declared(PKCS7_encrypt_introduced)}
    if LibVersion < PKCS7_encrypt_introduced then
    begin
      {$if declared(FC_PKCS7_encrypt)}
      PKCS7_encrypt := FC_PKCS7_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_encrypt_removed)}
    if PKCS7_encrypt_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_encrypt)}
      PKCS7_encrypt := _PKCS7_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_encrypt');
    {$ifend}
  end;
  
  PKCS7_encrypt_ex := LoadLibFunction(ADllHandle, PKCS7_encrypt_ex_procname);
  FuncLoadError := not assigned(PKCS7_encrypt_ex);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_encrypt_ex_allownil)}
    PKCS7_encrypt_ex := ERR_PKCS7_encrypt_ex;
    {$ifend}
    {$if declared(PKCS7_encrypt_ex_introduced)}
    if LibVersion < PKCS7_encrypt_ex_introduced then
    begin
      {$if declared(FC_PKCS7_encrypt_ex)}
      PKCS7_encrypt_ex := FC_PKCS7_encrypt_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_encrypt_ex_removed)}
    if PKCS7_encrypt_ex_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_encrypt_ex)}
      PKCS7_encrypt_ex := _PKCS7_encrypt_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_encrypt_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_encrypt_ex');
    {$ifend}
  end;
  
  PKCS7_decrypt := LoadLibFunction(ADllHandle, PKCS7_decrypt_procname);
  FuncLoadError := not assigned(PKCS7_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_decrypt_allownil)}
    PKCS7_decrypt := ERR_PKCS7_decrypt;
    {$ifend}
    {$if declared(PKCS7_decrypt_introduced)}
    if LibVersion < PKCS7_decrypt_introduced then
    begin
      {$if declared(FC_PKCS7_decrypt)}
      PKCS7_decrypt := FC_PKCS7_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_decrypt_removed)}
    if PKCS7_decrypt_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_decrypt)}
      PKCS7_decrypt := _PKCS7_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_decrypt');
    {$ifend}
  end;
  
  PKCS7_add_attrib_smimecap := LoadLibFunction(ADllHandle, PKCS7_add_attrib_smimecap_procname);
  FuncLoadError := not assigned(PKCS7_add_attrib_smimecap);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_add_attrib_smimecap_allownil)}
    PKCS7_add_attrib_smimecap := ERR_PKCS7_add_attrib_smimecap;
    {$ifend}
    {$if declared(PKCS7_add_attrib_smimecap_introduced)}
    if LibVersion < PKCS7_add_attrib_smimecap_introduced then
    begin
      {$if declared(FC_PKCS7_add_attrib_smimecap)}
      PKCS7_add_attrib_smimecap := FC_PKCS7_add_attrib_smimecap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_add_attrib_smimecap_removed)}
    if PKCS7_add_attrib_smimecap_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_add_attrib_smimecap)}
      PKCS7_add_attrib_smimecap := _PKCS7_add_attrib_smimecap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_add_attrib_smimecap_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_add_attrib_smimecap');
    {$ifend}
  end;
  
  PKCS7_get_smimecap := LoadLibFunction(ADllHandle, PKCS7_get_smimecap_procname);
  FuncLoadError := not assigned(PKCS7_get_smimecap);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_get_smimecap_allownil)}
    PKCS7_get_smimecap := ERR_PKCS7_get_smimecap;
    {$ifend}
    {$if declared(PKCS7_get_smimecap_introduced)}
    if LibVersion < PKCS7_get_smimecap_introduced then
    begin
      {$if declared(FC_PKCS7_get_smimecap)}
      PKCS7_get_smimecap := FC_PKCS7_get_smimecap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_get_smimecap_removed)}
    if PKCS7_get_smimecap_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_get_smimecap)}
      PKCS7_get_smimecap := _PKCS7_get_smimecap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_get_smimecap_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_get_smimecap');
    {$ifend}
  end;
  
  PKCS7_simple_smimecap := LoadLibFunction(ADllHandle, PKCS7_simple_smimecap_procname);
  FuncLoadError := not assigned(PKCS7_simple_smimecap);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_simple_smimecap_allownil)}
    PKCS7_simple_smimecap := ERR_PKCS7_simple_smimecap;
    {$ifend}
    {$if declared(PKCS7_simple_smimecap_introduced)}
    if LibVersion < PKCS7_simple_smimecap_introduced then
    begin
      {$if declared(FC_PKCS7_simple_smimecap)}
      PKCS7_simple_smimecap := FC_PKCS7_simple_smimecap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_simple_smimecap_removed)}
    if PKCS7_simple_smimecap_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_simple_smimecap)}
      PKCS7_simple_smimecap := _PKCS7_simple_smimecap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_simple_smimecap_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_simple_smimecap');
    {$ifend}
  end;
  
  PKCS7_add_attrib_content_type := LoadLibFunction(ADllHandle, PKCS7_add_attrib_content_type_procname);
  FuncLoadError := not assigned(PKCS7_add_attrib_content_type);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_add_attrib_content_type_allownil)}
    PKCS7_add_attrib_content_type := ERR_PKCS7_add_attrib_content_type;
    {$ifend}
    {$if declared(PKCS7_add_attrib_content_type_introduced)}
    if LibVersion < PKCS7_add_attrib_content_type_introduced then
    begin
      {$if declared(FC_PKCS7_add_attrib_content_type)}
      PKCS7_add_attrib_content_type := FC_PKCS7_add_attrib_content_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_add_attrib_content_type_removed)}
    if PKCS7_add_attrib_content_type_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_add_attrib_content_type)}
      PKCS7_add_attrib_content_type := _PKCS7_add_attrib_content_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_add_attrib_content_type_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_add_attrib_content_type');
    {$ifend}
  end;
  
  PKCS7_add0_attrib_signing_time := LoadLibFunction(ADllHandle, PKCS7_add0_attrib_signing_time_procname);
  FuncLoadError := not assigned(PKCS7_add0_attrib_signing_time);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_add0_attrib_signing_time_allownil)}
    PKCS7_add0_attrib_signing_time := ERR_PKCS7_add0_attrib_signing_time;
    {$ifend}
    {$if declared(PKCS7_add0_attrib_signing_time_introduced)}
    if LibVersion < PKCS7_add0_attrib_signing_time_introduced then
    begin
      {$if declared(FC_PKCS7_add0_attrib_signing_time)}
      PKCS7_add0_attrib_signing_time := FC_PKCS7_add0_attrib_signing_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_add0_attrib_signing_time_removed)}
    if PKCS7_add0_attrib_signing_time_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_add0_attrib_signing_time)}
      PKCS7_add0_attrib_signing_time := _PKCS7_add0_attrib_signing_time;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_add0_attrib_signing_time_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_add0_attrib_signing_time');
    {$ifend}
  end;
  
  PKCS7_add1_attrib_digest := LoadLibFunction(ADllHandle, PKCS7_add1_attrib_digest_procname);
  FuncLoadError := not assigned(PKCS7_add1_attrib_digest);
  if FuncLoadError then
  begin
    {$if not defined(PKCS7_add1_attrib_digest_allownil)}
    PKCS7_add1_attrib_digest := ERR_PKCS7_add1_attrib_digest;
    {$ifend}
    {$if declared(PKCS7_add1_attrib_digest_introduced)}
    if LibVersion < PKCS7_add1_attrib_digest_introduced then
    begin
      {$if declared(FC_PKCS7_add1_attrib_digest)}
      PKCS7_add1_attrib_digest := FC_PKCS7_add1_attrib_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PKCS7_add1_attrib_digest_removed)}
    if PKCS7_add1_attrib_digest_removed <= LibVersion then
    begin
      {$if declared(_PKCS7_add1_attrib_digest)}
      PKCS7_add1_attrib_digest := _PKCS7_add1_attrib_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PKCS7_add1_attrib_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('PKCS7_add1_attrib_digest');
    {$ifend}
  end;
  
  SMIME_write_PKCS7 := LoadLibFunction(ADllHandle, SMIME_write_PKCS7_procname);
  FuncLoadError := not assigned(SMIME_write_PKCS7);
  if FuncLoadError then
  begin
    {$if not defined(SMIME_write_PKCS7_allownil)}
    SMIME_write_PKCS7 := ERR_SMIME_write_PKCS7;
    {$ifend}
    {$if declared(SMIME_write_PKCS7_introduced)}
    if LibVersion < SMIME_write_PKCS7_introduced then
    begin
      {$if declared(FC_SMIME_write_PKCS7)}
      SMIME_write_PKCS7 := FC_SMIME_write_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SMIME_write_PKCS7_removed)}
    if SMIME_write_PKCS7_removed <= LibVersion then
    begin
      {$if declared(_SMIME_write_PKCS7)}
      SMIME_write_PKCS7 := _SMIME_write_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SMIME_write_PKCS7_allownil)}
    if FuncLoadError then
      AFailed.Add('SMIME_write_PKCS7');
    {$ifend}
  end;
  
  SMIME_read_PKCS7_ex := LoadLibFunction(ADllHandle, SMIME_read_PKCS7_ex_procname);
  FuncLoadError := not assigned(SMIME_read_PKCS7_ex);
  if FuncLoadError then
  begin
    {$if not defined(SMIME_read_PKCS7_ex_allownil)}
    SMIME_read_PKCS7_ex := ERR_SMIME_read_PKCS7_ex;
    {$ifend}
    {$if declared(SMIME_read_PKCS7_ex_introduced)}
    if LibVersion < SMIME_read_PKCS7_ex_introduced then
    begin
      {$if declared(FC_SMIME_read_PKCS7_ex)}
      SMIME_read_PKCS7_ex := FC_SMIME_read_PKCS7_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SMIME_read_PKCS7_ex_removed)}
    if SMIME_read_PKCS7_ex_removed <= LibVersion then
    begin
      {$if declared(_SMIME_read_PKCS7_ex)}
      SMIME_read_PKCS7_ex := _SMIME_read_PKCS7_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SMIME_read_PKCS7_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('SMIME_read_PKCS7_ex');
    {$ifend}
  end;
  
  SMIME_read_PKCS7 := LoadLibFunction(ADllHandle, SMIME_read_PKCS7_procname);
  FuncLoadError := not assigned(SMIME_read_PKCS7);
  if FuncLoadError then
  begin
    {$if not defined(SMIME_read_PKCS7_allownil)}
    SMIME_read_PKCS7 := ERR_SMIME_read_PKCS7;
    {$ifend}
    {$if declared(SMIME_read_PKCS7_introduced)}
    if LibVersion < SMIME_read_PKCS7_introduced then
    begin
      {$if declared(FC_SMIME_read_PKCS7)}
      SMIME_read_PKCS7 := FC_SMIME_read_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SMIME_read_PKCS7_removed)}
    if SMIME_read_PKCS7_removed <= LibVersion then
    begin
      {$if declared(_SMIME_read_PKCS7)}
      SMIME_read_PKCS7 := _SMIME_read_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SMIME_read_PKCS7_allownil)}
    if FuncLoadError then
      AFailed.Add('SMIME_read_PKCS7');
    {$ifend}
  end;
  
  BIO_new_PKCS7 := LoadLibFunction(ADllHandle, BIO_new_PKCS7_procname);
  FuncLoadError := not assigned(BIO_new_PKCS7);
  if FuncLoadError then
  begin
    {$if not defined(BIO_new_PKCS7_allownil)}
    BIO_new_PKCS7 := ERR_BIO_new_PKCS7;
    {$ifend}
    {$if declared(BIO_new_PKCS7_introduced)}
    if LibVersion < BIO_new_PKCS7_introduced then
    begin
      {$if declared(FC_BIO_new_PKCS7)}
      BIO_new_PKCS7 := FC_BIO_new_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_new_PKCS7_removed)}
    if BIO_new_PKCS7_removed <= LibVersion then
    begin
      {$if declared(_BIO_new_PKCS7)}
      BIO_new_PKCS7 := _BIO_new_PKCS7;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_new_PKCS7_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_new_PKCS7');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  PKCS7_ISSUER_AND_SERIAL_new := nil;
  PKCS7_ISSUER_AND_SERIAL_free := nil;
  d2i_PKCS7_ISSUER_AND_SERIAL := nil;
  i2d_PKCS7_ISSUER_AND_SERIAL := nil;
  PKCS7_ISSUER_AND_SERIAL_it := nil;
  PKCS7_ISSUER_AND_SERIAL_digest := nil;
  d2i_PKCS7_fp := nil;
  i2d_PKCS7_fp := nil;
  PKCS7_dup := nil;
  d2i_PKCS7_bio := nil;
  i2d_PKCS7_bio := nil;
  i2d_PKCS7_bio_stream := nil;
  PEM_write_bio_PKCS7_stream := nil;
  PKCS7_SIGNER_INFO_new := nil;
  PKCS7_SIGNER_INFO_free := nil;
  d2i_PKCS7_SIGNER_INFO := nil;
  i2d_PKCS7_SIGNER_INFO := nil;
  PKCS7_SIGNER_INFO_it := nil;
  PKCS7_RECIP_INFO_new := nil;
  PKCS7_RECIP_INFO_free := nil;
  d2i_PKCS7_RECIP_INFO := nil;
  i2d_PKCS7_RECIP_INFO := nil;
  PKCS7_RECIP_INFO_it := nil;
  PKCS7_SIGNED_new := nil;
  PKCS7_SIGNED_free := nil;
  d2i_PKCS7_SIGNED := nil;
  i2d_PKCS7_SIGNED := nil;
  PKCS7_SIGNED_it := nil;
  PKCS7_ENC_CONTENT_new := nil;
  PKCS7_ENC_CONTENT_free := nil;
  d2i_PKCS7_ENC_CONTENT := nil;
  i2d_PKCS7_ENC_CONTENT := nil;
  PKCS7_ENC_CONTENT_it := nil;
  PKCS7_ENVELOPE_new := nil;
  PKCS7_ENVELOPE_free := nil;
  d2i_PKCS7_ENVELOPE := nil;
  i2d_PKCS7_ENVELOPE := nil;
  PKCS7_ENVELOPE_it := nil;
  PKCS7_SIGN_ENVELOPE_new := nil;
  PKCS7_SIGN_ENVELOPE_free := nil;
  d2i_PKCS7_SIGN_ENVELOPE := nil;
  i2d_PKCS7_SIGN_ENVELOPE := nil;
  PKCS7_SIGN_ENVELOPE_it := nil;
  PKCS7_DIGEST_new := nil;
  PKCS7_DIGEST_free := nil;
  d2i_PKCS7_DIGEST := nil;
  i2d_PKCS7_DIGEST := nil;
  PKCS7_DIGEST_it := nil;
  PKCS7_ENCRYPT_new := nil;
  PKCS7_ENCRYPT_free := nil;
  d2i_PKCS7_ENCRYPT := nil;
  i2d_PKCS7_ENCRYPT := nil;
  PKCS7_ENCRYPT_it := nil;
  PKCS7_new := nil;
  PKCS7_free := nil;
  d2i_PKCS7 := nil;
  i2d_PKCS7 := nil;
  PKCS7_it := nil;
  PKCS7_new_ex := nil;
  PKCS7_ATTR_SIGN_it := nil;
  PKCS7_ATTR_VERIFY_it := nil;
  i2d_PKCS7_NDEF := nil;
  PKCS7_print_ctx := nil;
  PKCS7_ctrl := nil;
  PKCS7_type_is_other := nil;
  PKCS7_set_type := nil;
  PKCS7_set0_type_other := nil;
  PKCS7_set_content := nil;
  PKCS7_SIGNER_INFO_set := nil;
  PKCS7_SIGNER_INFO_sign := nil;
  PKCS7_add_signer := nil;
  PKCS7_add_certificate := nil;
  PKCS7_add_crl := nil;
  PKCS7_content_new := nil;
  PKCS7_dataVerify := nil;
  PKCS7_signatureVerify := nil;
  PKCS7_dataInit := nil;
  PKCS7_dataFinal := nil;
  PKCS7_dataDecode := nil;
  PKCS7_add_signature := nil;
  PKCS7_cert_from_signer_info := nil;
  PKCS7_set_digest := nil;
  PKCS7_get_signer_info := nil;
  PKCS7_add_recipient := nil;
  PKCS7_SIGNER_INFO_get0_algs := nil;
  PKCS7_RECIP_INFO_get0_alg := nil;
  PKCS7_add_recipient_info := nil;
  PKCS7_RECIP_INFO_set := nil;
  PKCS7_set_cipher := nil;
  PKCS7_stream := nil;
  PKCS7_get_issuer_and_serial := nil;
  PKCS7_get_octet_string := nil;
  PKCS7_digest_from_attributes := nil;
  PKCS7_add_signed_attribute := nil;
  PKCS7_add_attribute := nil;
  PKCS7_get_attribute := nil;
  PKCS7_get_signed_attribute := nil;
  PKCS7_set_signed_attributes := nil;
  PKCS7_set_attributes := nil;
  PKCS7_sign := nil;
  PKCS7_sign_ex := nil;
  PKCS7_sign_add_signer := nil;
  PKCS7_final := nil;
  PKCS7_verify := nil;
  PKCS7_get0_signers := nil;
  PKCS7_encrypt := nil;
  PKCS7_encrypt_ex := nil;
  PKCS7_decrypt := nil;
  PKCS7_add_attrib_smimecap := nil;
  PKCS7_get_smimecap := nil;
  PKCS7_simple_smimecap := nil;
  PKCS7_add_attrib_content_type := nil;
  PKCS7_add0_attrib_signing_time := nil;
  PKCS7_add1_attrib_digest := nil;
  SMIME_write_PKCS7 := nil;
  SMIME_read_PKCS7_ex := nil;
  SMIME_read_PKCS7 := nil;
  BIO_new_PKCS7 := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.