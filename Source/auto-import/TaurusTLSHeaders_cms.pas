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

unit TaurusTLSHeaders_cms;

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
  PCMS_EnvelopedData_st = ^TCMS_EnvelopedData_st;
  TCMS_EnvelopedData_st =   record end;
  {$EXTERNALSYM PCMS_EnvelopedData_st}

  PCMS_ContentInfo_st = ^TCMS_ContentInfo_st;
  TCMS_ContentInfo_st =   record end;
  {$EXTERNALSYM PCMS_ContentInfo_st}

  PCMS_SignerInfo_st = ^TCMS_SignerInfo_st;
  TCMS_SignerInfo_st =   record end;
  {$EXTERNALSYM PCMS_SignerInfo_st}

  PCMS_SignedData_st = ^TCMS_SignedData_st;
  TCMS_SignedData_st =   record end;
  {$EXTERNALSYM PCMS_SignedData_st}

  PCMS_CertificateChoices = ^TCMS_CertificateChoices;
  TCMS_CertificateChoices =   record end;
  {$EXTERNALSYM PCMS_CertificateChoices}

  PCMS_RevocationInfoChoice_st = ^TCMS_RevocationInfoChoice_st;
  TCMS_RevocationInfoChoice_st =   record end;
  {$EXTERNALSYM PCMS_RevocationInfoChoice_st}

  PCMS_RecipientInfo_st = ^TCMS_RecipientInfo_st;
  TCMS_RecipientInfo_st =   record end;
  {$EXTERNALSYM PCMS_RecipientInfo_st}

  PCMS_ReceiptRequest_st = ^TCMS_ReceiptRequest_st;
  TCMS_ReceiptRequest_st =   record end;
  {$EXTERNALSYM PCMS_ReceiptRequest_st}

  PCMS_Receipt_st = ^TCMS_Receipt_st;
  TCMS_Receipt_st =   record end;
  {$EXTERNALSYM PCMS_Receipt_st}

  PCMS_RecipientEncryptedKey_st = ^TCMS_RecipientEncryptedKey_st;
  TCMS_RecipientEncryptedKey_st =   record end;
  {$EXTERNALSYM PCMS_RecipientEncryptedKey_st}

  PCMS_OtherKeyAttribute_st = ^TCMS_OtherKeyAttribute_st;
  TCMS_OtherKeyAttribute_st =   record end;
  {$EXTERNALSYM PCMS_OtherKeyAttribute_st}


// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  CMS_SIGNERINFO_ISSUER_SERIAL = 0;
  CMS_SIGNERINFO_KEYIDENTIFIER = 1;
  CMS_RECIPINFO_NONE = -1;
  CMS_RECIPINFO_TRANS = 0;
  CMS_RECIPINFO_AGREE = 1;
  CMS_RECIPINFO_KEK = 2;
  CMS_RECIPINFO_PASS = 3;
  CMS_RECIPINFO_OTHER = 4;
  CMS_RECIPINFO_KEM = 5;
  CMS_TEXT = $1;
  CMS_NOCERTS = $2;
  CMS_NO_CONTENT_VERIFY = $4;
  CMS_NO_ATTR_VERIFY = $8;
  CMS_NOSIGS = (CMS_NO_CONTENT_VERIFY or CMS_NO_ATTR_VERIFY);
  CMS_NOINTERN = $10;
  CMS_NO_SIGNER_CERT_VERIFY = $20;
  CMS_NOVERIFY = $20;
  CMS_DETACHED = $40;
  CMS_BINARY = $80;
  CMS_NOATTR = $100;
  CMS_NOSMIMECAP = $200;
  CMS_NOOLDMIMETYPE = $400;
  CMS_CRLFEOL = $800;
  CMS_STREAM = $1000;
  CMS_NOCRL = $2000;
  CMS_PARTIAL = $4000;
  CMS_REUSE_DIGEST = $8000;
  CMS_USE_KEYID = $10000;
  CMS_DEBUG_DECRYPT = $20000;
  CMS_KEY_PARAM = $40000;
  CMS_ASCIICRLF = $80000;
  CMS_CADES = $100000;
  CMS_USE_ORIGINATOR_KEYID = $200000;
  CMS_NO_SIGNING_TIME = $400000;
  CMS_R_UNKNOWN_DIGEST_ALGORITM = CMS_R_UNKNOWN_DIGEST_ALGORITHM;
  CMS_R_UNSUPPORTED_RECPIENTINFO_TYPE = CMS_R_UNSUPPORTED_RECIPIENTINFO_TYPE;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  CMS_EnvelopedData_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM CMS_EnvelopedData_it}

  CMS_SignedData_new: function: PCMS_SignedData; cdecl = nil;
  {$EXTERNALSYM CMS_SignedData_new}

  CMS_SignedData_free: function(a: PCMS_SignedData): void; cdecl = nil;
  {$EXTERNALSYM CMS_SignedData_free}

  CMS_ContentInfo_new: function: PCMS_ContentInfo; cdecl = nil;
  {$EXTERNALSYM CMS_ContentInfo_new}

  CMS_ContentInfo_free: function(a: PCMS_ContentInfo): void; cdecl = nil;
  {$EXTERNALSYM CMS_ContentInfo_free}

  d2i_CMS_ContentInfo: function(a: PPCMS_ContentInfo; _in: PPIdAnsiChar; len: TIdC_LONG): PCMS_ContentInfo; cdecl = nil;
  {$EXTERNALSYM d2i_CMS_ContentInfo}

  i2d_CMS_ContentInfo: function(a: PCMS_ContentInfo; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_CMS_ContentInfo}

  CMS_ContentInfo_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM CMS_ContentInfo_it}

  CMS_ReceiptRequest_new: function: PCMS_ReceiptRequest; cdecl = nil;
  {$EXTERNALSYM CMS_ReceiptRequest_new}

  CMS_ReceiptRequest_free: function(a: PCMS_ReceiptRequest): void; cdecl = nil;
  {$EXTERNALSYM CMS_ReceiptRequest_free}

  d2i_CMS_ReceiptRequest: function(a: PPCMS_ReceiptRequest; _in: PPIdAnsiChar; len: TIdC_LONG): PCMS_ReceiptRequest; cdecl = nil;
  {$EXTERNALSYM d2i_CMS_ReceiptRequest}

  i2d_CMS_ReceiptRequest: function(a: PCMS_ReceiptRequest; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_CMS_ReceiptRequest}

  CMS_ReceiptRequest_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM CMS_ReceiptRequest_it}

  CMS_ContentInfo_print_ctx: function(_out: PBIO; x: PCMS_ContentInfo; indent: TIdC_INT; pctx: PASN1_PCTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_ContentInfo_print_ctx}

  CMS_EnvelopedData_dup: function(a: PCMS_EnvelopedData): PCMS_EnvelopedData; cdecl = nil;
  {$EXTERNALSYM CMS_EnvelopedData_dup}

  CMS_ContentInfo_new_ex: function(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl = nil;
  {$EXTERNALSYM CMS_ContentInfo_new_ex}

  CMS_get0_type: function(cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM CMS_get0_type}

  CMS_dataInit: function(cms: PCMS_ContentInfo; icont: PBIO): PBIO; cdecl = nil;
  {$EXTERNALSYM CMS_dataInit}

  CMS_dataFinal: function(cms: PCMS_ContentInfo; bio: PBIO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_dataFinal}

  CMS_get0_content: function(cms: PCMS_ContentInfo): PPASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM CMS_get0_content}

  CMS_is_detached: function(cms: PCMS_ContentInfo): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_is_detached}

  CMS_set_detached: function(cms: PCMS_ContentInfo; detached: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_set_detached}

  CMS_stream: function(boundary: PPPIdAnsiChar; cms: PCMS_ContentInfo): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_stream}

  d2i_CMS_bio: function(bp: PBIO; cms: PPCMS_ContentInfo): PCMS_ContentInfo; cdecl = nil;
  {$EXTERNALSYM d2i_CMS_bio}

  i2d_CMS_bio: function(bp: PBIO; cms: PCMS_ContentInfo): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_CMS_bio}

  BIO_new_CMS: function(_out: PBIO; cms: PCMS_ContentInfo): PBIO; cdecl = nil;
  {$EXTERNALSYM BIO_new_CMS}

  i2d_CMS_bio_stream: function(_out: PBIO; cms: PCMS_ContentInfo; _in: PBIO; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_CMS_bio_stream}

  PEM_write_bio_CMS_stream: function(_out: PBIO; cms: PCMS_ContentInfo; _in: PBIO; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_bio_CMS_stream}

  SMIME_read_CMS: function(bio: PBIO; bcont: PPBIO): PCMS_ContentInfo; cdecl = nil;
  {$EXTERNALSYM SMIME_read_CMS}

  SMIME_read_CMS_ex: function(bio: PBIO; flags: TIdC_INT; bcont: PPBIO; ci: PPCMS_ContentInfo): PCMS_ContentInfo; cdecl = nil;
  {$EXTERNALSYM SMIME_read_CMS_ex}

  SMIME_write_CMS: function(bio: PBIO; cms: PCMS_ContentInfo; data: PBIO; flags: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM SMIME_write_CMS}

  CMS_final: function(cms: PCMS_ContentInfo; data: PBIO; dcont: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_final}

  CMS_final_digest: function(cms: PCMS_ContentInfo; md: PIdAnsiChar; mdlen: TIdC_UINT; dcont: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_final_digest}

  CMS_sign: function(signcert: PX509; pkey: PEVP_PKEY; certs: Pstack_st_X509; data: PBIO; flags: TIdC_UINT): PCMS_ContentInfo; cdecl = nil;
  {$EXTERNALSYM CMS_sign}

  CMS_sign_ex: function(signcert: PX509; pkey: PEVP_PKEY; certs: Pstack_st_X509; data: PBIO; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl = nil;
  {$EXTERNALSYM CMS_sign_ex}

  CMS_sign_receipt: function(si: PCMS_SignerInfo; signcert: PX509; pkey: PEVP_PKEY; certs: Pstack_st_X509; flags: TIdC_UINT): PCMS_ContentInfo; cdecl = nil;
  {$EXTERNALSYM CMS_sign_receipt}

  CMS_data: function(cms: PCMS_ContentInfo; _out: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_data}

  CMS_data_create: function(_in: PBIO; flags: TIdC_UINT): PCMS_ContentInfo; cdecl = nil;
  {$EXTERNALSYM CMS_data_create}

  CMS_data_create_ex: function(_in: PBIO; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl = nil;
  {$EXTERNALSYM CMS_data_create_ex}

  CMS_digest_verify: function(cms: PCMS_ContentInfo; dcont: PBIO; _out: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_digest_verify}

  CMS_digest_create: function(_in: PBIO; md: PEVP_MD; flags: TIdC_UINT): PCMS_ContentInfo; cdecl = nil;
  {$EXTERNALSYM CMS_digest_create}

  CMS_digest_create_ex: function(_in: PBIO; md: PEVP_MD; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl = nil;
  {$EXTERNALSYM CMS_digest_create_ex}

  CMS_EncryptedData_decrypt: function(cms: PCMS_ContentInfo; key: PIdAnsiChar; keylen: TIdC_SIZET; dcont: PBIO; _out: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_EncryptedData_decrypt}

  CMS_EncryptedData_encrypt: function(_in: PBIO; cipher: PEVP_CIPHER; key: PIdAnsiChar; keylen: TIdC_SIZET; flags: TIdC_UINT): PCMS_ContentInfo; cdecl = nil;
  {$EXTERNALSYM CMS_EncryptedData_encrypt}

  CMS_EncryptedData_encrypt_ex: function(_in: PBIO; cipher: PEVP_CIPHER; key: PIdAnsiChar; keylen: TIdC_SIZET; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl = nil;
  {$EXTERNALSYM CMS_EncryptedData_encrypt_ex}

  CMS_EncryptedData_set1_key: function(cms: PCMS_ContentInfo; ciph: PEVP_CIPHER; key: PIdAnsiChar; keylen: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_EncryptedData_set1_key}

  CMS_verify: function(cms: PCMS_ContentInfo; certs: Pstack_st_X509; store: PX509_STORE; dcont: PBIO; _out: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_verify}

  CMS_verify_receipt: function(rcms: PCMS_ContentInfo; ocms: PCMS_ContentInfo; certs: Pstack_st_X509; store: PX509_STORE; flags: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_verify_receipt}

  CMS_get0_signers: function(cms: PCMS_ContentInfo): Pstack_st_X509; cdecl = nil;
  {$EXTERNALSYM CMS_get0_signers}

  CMS_encrypt: function(certs: Pstack_st_X509; _in: PBIO; cipher: PEVP_CIPHER; flags: TIdC_UINT): PCMS_ContentInfo; cdecl = nil;
  {$EXTERNALSYM CMS_encrypt}

  CMS_encrypt_ex: function(certs: Pstack_st_X509; _in: PBIO; cipher: PEVP_CIPHER; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl = nil;
  {$EXTERNALSYM CMS_encrypt_ex}

  CMS_decrypt: function(cms: PCMS_ContentInfo; pkey: PEVP_PKEY; cert: PX509; dcont: PBIO; _out: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_decrypt}

  CMS_decrypt_set1_pkey: function(cms: PCMS_ContentInfo; pk: PEVP_PKEY; cert: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_decrypt_set1_pkey}

  CMS_decrypt_set1_pkey_and_peer: function(cms: PCMS_ContentInfo; pk: PEVP_PKEY; cert: PX509; peer: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_decrypt_set1_pkey_and_peer}

  CMS_decrypt_set1_key: function(cms: PCMS_ContentInfo; key: PIdAnsiChar; keylen: TIdC_SIZET; id: PIdAnsiChar; idlen: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_decrypt_set1_key}

  CMS_decrypt_set1_password: function(cms: PCMS_ContentInfo; pass: PIdAnsiChar; passlen: TIdC_SSIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_decrypt_set1_password}

  CMS_get0_RecipientInfos: function(cms: PCMS_ContentInfo): Pstack_st_CMS_RecipientInfo; cdecl = nil;
  {$EXTERNALSYM CMS_get0_RecipientInfos}

  CMS_RecipientInfo_type: function(ri: PCMS_RecipientInfo): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientInfo_type}

  CMS_RecipientInfo_get0_pkey_ctx: function(ri: PCMS_RecipientInfo): PEVP_PKEY_CTX; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientInfo_get0_pkey_ctx}

  CMS_AuthEnvelopedData_create: function(cipher: PEVP_CIPHER): PCMS_ContentInfo; cdecl = nil;
  {$EXTERNALSYM CMS_AuthEnvelopedData_create}

  CMS_AuthEnvelopedData_create_ex: function(cipher: PEVP_CIPHER; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl = nil;
  {$EXTERNALSYM CMS_AuthEnvelopedData_create_ex}

  CMS_EnvelopedData_create: function(cipher: PEVP_CIPHER): PCMS_ContentInfo; cdecl = nil;
  {$EXTERNALSYM CMS_EnvelopedData_create}

  CMS_EnvelopedData_create_ex: function(cipher: PEVP_CIPHER; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl = nil;
  {$EXTERNALSYM CMS_EnvelopedData_create_ex}

  CMS_EnvelopedData_decrypt: function(env: PCMS_EnvelopedData; detached_data: PBIO; pkey: PEVP_PKEY; cert: PX509; secret: PASN1_OCTET_STRING; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PBIO; cdecl = nil;
  {$EXTERNALSYM CMS_EnvelopedData_decrypt}

  CMS_add1_recipient_cert: function(cms: PCMS_ContentInfo; recip: PX509; flags: TIdC_UINT): PCMS_RecipientInfo; cdecl = nil;
  {$EXTERNALSYM CMS_add1_recipient_cert}

  CMS_add1_recipient: function(cms: PCMS_ContentInfo; recip: PX509; originatorPrivKey: PEVP_PKEY; originator: PX509; flags: TIdC_UINT): PCMS_RecipientInfo; cdecl = nil;
  {$EXTERNALSYM CMS_add1_recipient}

  CMS_RecipientInfo_set0_pkey: function(ri: PCMS_RecipientInfo; pkey: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientInfo_set0_pkey}

  CMS_RecipientInfo_ktri_cert_cmp: function(ri: PCMS_RecipientInfo; cert: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientInfo_ktri_cert_cmp}

  CMS_RecipientInfo_ktri_get0_algs: function(ri: PCMS_RecipientInfo; pk: PPEVP_PKEY; recip: PPX509; palg: PPX509_ALGOR): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientInfo_ktri_get0_algs}

  CMS_RecipientInfo_ktri_get0_signer_id: function(ri: PCMS_RecipientInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientInfo_ktri_get0_signer_id}

  CMS_add0_recipient_key: function(cms: PCMS_ContentInfo; nid: TIdC_INT; key: PIdAnsiChar; keylen: TIdC_SIZET; id: PIdAnsiChar; idlen: TIdC_SIZET; date: PASN1_GENERALIZEDTIME; otherTypeId: PASN1_OBJECT; otherType: PASN1_TYPE): PCMS_RecipientInfo; cdecl = nil;
  {$EXTERNALSYM CMS_add0_recipient_key}

  CMS_RecipientInfo_kekri_get0_id: function(ri: PCMS_RecipientInfo; palg: PPX509_ALGOR; pid: PPASN1_OCTET_STRING; pdate: PPASN1_GENERALIZEDTIME; potherid: PPASN1_OBJECT; pothertype: PPASN1_TYPE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientInfo_kekri_get0_id}

  CMS_RecipientInfo_set0_key: function(ri: PCMS_RecipientInfo; key: PIdAnsiChar; keylen: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientInfo_set0_key}

  CMS_RecipientInfo_kekri_id_cmp: function(ri: PCMS_RecipientInfo; id: PIdAnsiChar; idlen: TIdC_SIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientInfo_kekri_id_cmp}

  CMS_RecipientInfo_set0_password: function(ri: PCMS_RecipientInfo; pass: PIdAnsiChar; passlen: TIdC_SSIZET): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientInfo_set0_password}

  CMS_add0_recipient_password: function(cms: PCMS_ContentInfo; iter: TIdC_INT; wrap_nid: TIdC_INT; pbe_nid: TIdC_INT; pass: PIdAnsiChar; passlen: TIdC_SSIZET; kekciph: PEVP_CIPHER): PCMS_RecipientInfo; cdecl = nil;
  {$EXTERNALSYM CMS_add0_recipient_password}

  CMS_RecipientInfo_decrypt: function(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientInfo_decrypt}

  CMS_RecipientInfo_encrypt: function(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientInfo_encrypt}

  CMS_uncompress: function(cms: PCMS_ContentInfo; dcont: PBIO; _out: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_uncompress}

  CMS_compress: function(_in: PBIO; comp_nid: TIdC_INT; flags: TIdC_UINT): PCMS_ContentInfo; cdecl = nil;
  {$EXTERNALSYM CMS_compress}

  CMS_set1_eContentType: function(cms: PCMS_ContentInfo; oid: PASN1_OBJECT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_set1_eContentType}

  CMS_get0_eContentType: function(cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM CMS_get0_eContentType}

  CMS_add0_CertificateChoices: function(cms: PCMS_ContentInfo): PCMS_CertificateChoices; cdecl = nil;
  {$EXTERNALSYM CMS_add0_CertificateChoices}

  CMS_add0_cert: function(cms: PCMS_ContentInfo; cert: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_add0_cert}

  CMS_add1_cert: function(cms: PCMS_ContentInfo; cert: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_add1_cert}

  CMS_get1_certs: function(cms: PCMS_ContentInfo): Pstack_st_X509; cdecl = nil;
  {$EXTERNALSYM CMS_get1_certs}

  CMS_add0_RevocationInfoChoice: function(cms: PCMS_ContentInfo): PCMS_RevocationInfoChoice; cdecl = nil;
  {$EXTERNALSYM CMS_add0_RevocationInfoChoice}

  CMS_add0_crl: function(cms: PCMS_ContentInfo; crl: PX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_add0_crl}

  CMS_add1_crl: function(cms: PCMS_ContentInfo; crl: PX509_CRL): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_add1_crl}

  CMS_get1_crls: function(cms: PCMS_ContentInfo): Pstack_st_X509_CRL; cdecl = nil;
  {$EXTERNALSYM CMS_get1_crls}

  CMS_SignedData_init: function(cms: PCMS_ContentInfo): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_SignedData_init}

  CMS_add1_signer: function(cms: PCMS_ContentInfo; signer: PX509; pk: PEVP_PKEY; md: PEVP_MD; flags: TIdC_UINT): PCMS_SignerInfo; cdecl = nil;
  {$EXTERNALSYM CMS_add1_signer}

  CMS_SignerInfo_get0_pkey_ctx: function(si: PCMS_SignerInfo): PEVP_PKEY_CTX; cdecl = nil;
  {$EXTERNALSYM CMS_SignerInfo_get0_pkey_ctx}

  CMS_SignerInfo_get0_md_ctx: function(si: PCMS_SignerInfo): PEVP_MD_CTX; cdecl = nil;
  {$EXTERNALSYM CMS_SignerInfo_get0_md_ctx}

  CMS_get0_SignerInfos: function(cms: PCMS_ContentInfo): Pstack_st_CMS_SignerInfo; cdecl = nil;
  {$EXTERNALSYM CMS_get0_SignerInfos}

  CMS_SignerInfo_set1_signer_cert: function(si: PCMS_SignerInfo; signer: PX509): void; cdecl = nil;
  {$EXTERNALSYM CMS_SignerInfo_set1_signer_cert}

  CMS_SignerInfo_get0_signer_id: function(si: PCMS_SignerInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_SignerInfo_get0_signer_id}

  CMS_SignerInfo_cert_cmp: function(si: PCMS_SignerInfo; cert: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_SignerInfo_cert_cmp}

  CMS_set1_signers_certs: function(cms: PCMS_ContentInfo; certs: Pstack_st_X509; flags: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_set1_signers_certs}

  CMS_SignerInfo_get0_algs: function(si: PCMS_SignerInfo; pk: PPEVP_PKEY; signer: PPX509; pdig: PPX509_ALGOR; psig: PPX509_ALGOR): void; cdecl = nil;
  {$EXTERNALSYM CMS_SignerInfo_get0_algs}

  CMS_SignerInfo_get0_signature: function(si: PCMS_SignerInfo): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM CMS_SignerInfo_get0_signature}

  CMS_SignerInfo_sign: function(si: PCMS_SignerInfo): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_SignerInfo_sign}

  CMS_SignerInfo_verify: function(si: PCMS_SignerInfo): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_SignerInfo_verify}

  CMS_SignerInfo_verify_content: function(si: PCMS_SignerInfo; chain: PBIO): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_SignerInfo_verify_content}

  CMS_SignedData_verify: function(sd: PCMS_SignedData; detached_data: PBIO; scerts: Pstack_st_X509; store: PX509_STORE; extra: Pstack_st_X509; crls: Pstack_st_X509_CRL; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PBIO; cdecl = nil;
  {$EXTERNALSYM CMS_SignedData_verify}

  CMS_add_smimecap: function(si: PCMS_SignerInfo; algs: Pstack_st_X509_ALGOR): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_add_smimecap}

  CMS_add_simple_smimecap: function(algs: PPstack_st_X509_ALGOR; algnid: TIdC_INT; keysize: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_add_simple_smimecap}

  CMS_add_standard_smimecap: function(smcap: PPstack_st_X509_ALGOR): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_add_standard_smimecap}

  CMS_signed_get_attr_count: function(si: PCMS_SignerInfo): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_signed_get_attr_count}

  CMS_signed_get_attr_by_NID: function(si: PCMS_SignerInfo; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_signed_get_attr_by_NID}

  CMS_signed_get_attr_by_OBJ: function(si: PCMS_SignerInfo; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_signed_get_attr_by_OBJ}

  CMS_signed_get_attr: function(si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM CMS_signed_get_attr}

  CMS_signed_delete_attr: function(si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM CMS_signed_delete_attr}

  CMS_signed_add1_attr: function(si: PCMS_SignerInfo; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_signed_add1_attr}

  CMS_signed_add1_attr_by_OBJ: function(si: PCMS_SignerInfo; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_signed_add1_attr_by_OBJ}

  CMS_signed_add1_attr_by_NID: function(si: PCMS_SignerInfo; nid: TIdC_INT; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_signed_add1_attr_by_NID}

  CMS_signed_add1_attr_by_txt: function(si: PCMS_SignerInfo; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_signed_add1_attr_by_txt}

  CMS_signed_get0_data_by_OBJ: function(si: PCMS_SignerInfo; oid: PASN1_OBJECT; lastpos: TIdC_INT; _type: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM CMS_signed_get0_data_by_OBJ}

  CMS_unsigned_get_attr_count: function(si: PCMS_SignerInfo): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_unsigned_get_attr_count}

  CMS_unsigned_get_attr_by_NID: function(si: PCMS_SignerInfo; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_unsigned_get_attr_by_NID}

  CMS_unsigned_get_attr_by_OBJ: function(si: PCMS_SignerInfo; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_unsigned_get_attr_by_OBJ}

  CMS_unsigned_get_attr: function(si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM CMS_unsigned_get_attr}

  CMS_unsigned_delete_attr: function(si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM CMS_unsigned_delete_attr}

  CMS_unsigned_add1_attr: function(si: PCMS_SignerInfo; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_unsigned_add1_attr}

  CMS_unsigned_add1_attr_by_OBJ: function(si: PCMS_SignerInfo; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_unsigned_add1_attr_by_OBJ}

  CMS_unsigned_add1_attr_by_NID: function(si: PCMS_SignerInfo; nid: TIdC_INT; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_unsigned_add1_attr_by_NID}

  CMS_unsigned_add1_attr_by_txt: function(si: PCMS_SignerInfo; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_unsigned_add1_attr_by_txt}

  CMS_unsigned_get0_data_by_OBJ: function(si: PCMS_SignerInfo; oid: PASN1_OBJECT; lastpos: TIdC_INT; _type: TIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM CMS_unsigned_get0_data_by_OBJ}

  CMS_get1_ReceiptRequest: function(si: PCMS_SignerInfo; prr: PPCMS_ReceiptRequest): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_get1_ReceiptRequest}

  CMS_ReceiptRequest_create0: function(id: PIdAnsiChar; idlen: TIdC_INT; allorfirst: TIdC_INT; receiptList: Pstack_st_GENERAL_NAMES; receiptsTo: Pstack_st_GENERAL_NAMES): PCMS_ReceiptRequest; cdecl = nil;
  {$EXTERNALSYM CMS_ReceiptRequest_create0}

  CMS_ReceiptRequest_create0_ex: function(id: PIdAnsiChar; idlen: TIdC_INT; allorfirst: TIdC_INT; receiptList: Pstack_st_GENERAL_NAMES; receiptsTo: Pstack_st_GENERAL_NAMES; libctx: POSSL_LIB_CTX): PCMS_ReceiptRequest; cdecl = nil;
  {$EXTERNALSYM CMS_ReceiptRequest_create0_ex}

  CMS_add1_ReceiptRequest: function(si: PCMS_SignerInfo; rr: PCMS_ReceiptRequest): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_add1_ReceiptRequest}

  CMS_ReceiptRequest_get0_values: function(rr: PCMS_ReceiptRequest; pcid: PPASN1_STRING; pallorfirst: PIdC_INT; plist: PPstack_st_GENERAL_NAMES; prto: PPstack_st_GENERAL_NAMES): void; cdecl = nil;
  {$EXTERNALSYM CMS_ReceiptRequest_get0_values}

  CMS_RecipientInfo_kari_get0_alg: function(ri: PCMS_RecipientInfo; palg: PPX509_ALGOR; pukm: PPASN1_OCTET_STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientInfo_kari_get0_alg}

  CMS_RecipientInfo_kari_get0_reks: function(ri: PCMS_RecipientInfo): Pstack_st_CMS_RecipientEncryptedKey; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientInfo_kari_get0_reks}

  CMS_RecipientInfo_kari_get0_orig_id: function(ri: PCMS_RecipientInfo; pubalg: PPX509_ALGOR; pubkey: PPASN1_BIT_STRING; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientInfo_kari_get0_orig_id}

  CMS_RecipientInfo_kari_orig_id_cmp: function(ri: PCMS_RecipientInfo; cert: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientInfo_kari_orig_id_cmp}

  CMS_RecipientEncryptedKey_get0_id: function(rek: PCMS_RecipientEncryptedKey; keyid: PPASN1_OCTET_STRING; tm: PPASN1_GENERALIZEDTIME; other: PPCMS_OtherKeyAttribute; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientEncryptedKey_get0_id}

  CMS_RecipientEncryptedKey_cert_cmp: function(rek: PCMS_RecipientEncryptedKey; cert: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientEncryptedKey_cert_cmp}

  CMS_RecipientInfo_kari_set0_pkey: function(ri: PCMS_RecipientInfo; pk: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientInfo_kari_set0_pkey}

  CMS_RecipientInfo_kari_set0_pkey_and_peer: function(ri: PCMS_RecipientInfo; pk: PEVP_PKEY; peer: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientInfo_kari_set0_pkey_and_peer}

  CMS_RecipientInfo_kari_get0_ctx: function(ri: PCMS_RecipientInfo): PEVP_CIPHER_CTX; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientInfo_kari_get0_ctx}

  CMS_RecipientInfo_kari_decrypt: function(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo; rek: PCMS_RecipientEncryptedKey): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientInfo_kari_decrypt}

  CMS_SharedInfo_encode: function(pder: PPIdAnsiChar; kekalg: PX509_ALGOR; ukm: PASN1_OCTET_STRING; keylen: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_SharedInfo_encode}

  CMS_RecipientInfo_kemri_cert_cmp: function(ri: PCMS_RecipientInfo; cert: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientInfo_kemri_cert_cmp}

  CMS_RecipientInfo_kemri_set0_pkey: function(ri: PCMS_RecipientInfo; pk: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientInfo_kemri_set0_pkey}

  CMS_RecipientInfo_kemri_get0_ctx: function(ri: PCMS_RecipientInfo): PEVP_CIPHER_CTX; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientInfo_kemri_get0_ctx}

  CMS_RecipientInfo_kemri_get0_kdf_alg: function(ri: PCMS_RecipientInfo): PX509_ALGOR; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientInfo_kemri_get0_kdf_alg}

  CMS_RecipientInfo_kemri_set_ukm: function(ri: PCMS_RecipientInfo; ukm: PIdAnsiChar; ukmLength: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM CMS_RecipientInfo_kemri_set_ukm}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function CMS_EnvelopedData_it: PASN1_ITEM; cdecl;
function CMS_SignedData_new: PCMS_SignedData; cdecl;
function CMS_SignedData_free(a: PCMS_SignedData): void; cdecl;
function CMS_ContentInfo_new: PCMS_ContentInfo; cdecl;
function CMS_ContentInfo_free(a: PCMS_ContentInfo): void; cdecl;
function d2i_CMS_ContentInfo(a: PPCMS_ContentInfo; _in: PPIdAnsiChar; len: TIdC_LONG): PCMS_ContentInfo; cdecl;
function i2d_CMS_ContentInfo(a: PCMS_ContentInfo; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function CMS_ContentInfo_it: PASN1_ITEM; cdecl;
function CMS_ReceiptRequest_new: PCMS_ReceiptRequest; cdecl;
function CMS_ReceiptRequest_free(a: PCMS_ReceiptRequest): void; cdecl;
function d2i_CMS_ReceiptRequest(a: PPCMS_ReceiptRequest; _in: PPIdAnsiChar; len: TIdC_LONG): PCMS_ReceiptRequest; cdecl;
function i2d_CMS_ReceiptRequest(a: PCMS_ReceiptRequest; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function CMS_ReceiptRequest_it: PASN1_ITEM; cdecl;
function CMS_ContentInfo_print_ctx(_out: PBIO; x: PCMS_ContentInfo; indent: TIdC_INT; pctx: PASN1_PCTX): TIdC_INT; cdecl;
function CMS_EnvelopedData_dup(a: PCMS_EnvelopedData): PCMS_EnvelopedData; cdecl;
function CMS_ContentInfo_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl;
function CMS_get0_type(cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl;
function CMS_dataInit(cms: PCMS_ContentInfo; icont: PBIO): PBIO; cdecl;
function CMS_dataFinal(cms: PCMS_ContentInfo; bio: PBIO): TIdC_INT; cdecl;
function CMS_get0_content(cms: PCMS_ContentInfo): PPASN1_OCTET_STRING; cdecl;
function CMS_is_detached(cms: PCMS_ContentInfo): TIdC_INT; cdecl;
function CMS_set_detached(cms: PCMS_ContentInfo; detached: TIdC_INT): TIdC_INT; cdecl;
function CMS_stream(boundary: PPPIdAnsiChar; cms: PCMS_ContentInfo): TIdC_INT; cdecl;
function d2i_CMS_bio(bp: PBIO; cms: PPCMS_ContentInfo): PCMS_ContentInfo; cdecl;
function i2d_CMS_bio(bp: PBIO; cms: PCMS_ContentInfo): TIdC_INT; cdecl;
function BIO_new_CMS(_out: PBIO; cms: PCMS_ContentInfo): PBIO; cdecl;
function i2d_CMS_bio_stream(_out: PBIO; cms: PCMS_ContentInfo; _in: PBIO; flags: TIdC_INT): TIdC_INT; cdecl;
function PEM_write_bio_CMS_stream(_out: PBIO; cms: PCMS_ContentInfo; _in: PBIO; flags: TIdC_INT): TIdC_INT; cdecl;
function SMIME_read_CMS(bio: PBIO; bcont: PPBIO): PCMS_ContentInfo; cdecl;
function SMIME_read_CMS_ex(bio: PBIO; flags: TIdC_INT; bcont: PPBIO; ci: PPCMS_ContentInfo): PCMS_ContentInfo; cdecl;
function SMIME_write_CMS(bio: PBIO; cms: PCMS_ContentInfo; data: PBIO; flags: TIdC_INT): TIdC_INT; cdecl;
function CMS_final(cms: PCMS_ContentInfo; data: PBIO; dcont: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl;
function CMS_final_digest(cms: PCMS_ContentInfo; md: PIdAnsiChar; mdlen: TIdC_UINT; dcont: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl;
function CMS_sign(signcert: PX509; pkey: PEVP_PKEY; certs: Pstack_st_X509; data: PBIO; flags: TIdC_UINT): PCMS_ContentInfo; cdecl;
function CMS_sign_ex(signcert: PX509; pkey: PEVP_PKEY; certs: Pstack_st_X509; data: PBIO; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl;
function CMS_sign_receipt(si: PCMS_SignerInfo; signcert: PX509; pkey: PEVP_PKEY; certs: Pstack_st_X509; flags: TIdC_UINT): PCMS_ContentInfo; cdecl;
function CMS_data(cms: PCMS_ContentInfo; _out: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl;
function CMS_data_create(_in: PBIO; flags: TIdC_UINT): PCMS_ContentInfo; cdecl;
function CMS_data_create_ex(_in: PBIO; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl;
function CMS_digest_verify(cms: PCMS_ContentInfo; dcont: PBIO; _out: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl;
function CMS_digest_create(_in: PBIO; md: PEVP_MD; flags: TIdC_UINT): PCMS_ContentInfo; cdecl;
function CMS_digest_create_ex(_in: PBIO; md: PEVP_MD; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl;
function CMS_EncryptedData_decrypt(cms: PCMS_ContentInfo; key: PIdAnsiChar; keylen: TIdC_SIZET; dcont: PBIO; _out: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl;
function CMS_EncryptedData_encrypt(_in: PBIO; cipher: PEVP_CIPHER; key: PIdAnsiChar; keylen: TIdC_SIZET; flags: TIdC_UINT): PCMS_ContentInfo; cdecl;
function CMS_EncryptedData_encrypt_ex(_in: PBIO; cipher: PEVP_CIPHER; key: PIdAnsiChar; keylen: TIdC_SIZET; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl;
function CMS_EncryptedData_set1_key(cms: PCMS_ContentInfo; ciph: PEVP_CIPHER; key: PIdAnsiChar; keylen: TIdC_SIZET): TIdC_INT; cdecl;
function CMS_verify(cms: PCMS_ContentInfo; certs: Pstack_st_X509; store: PX509_STORE; dcont: PBIO; _out: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl;
function CMS_verify_receipt(rcms: PCMS_ContentInfo; ocms: PCMS_ContentInfo; certs: Pstack_st_X509; store: PX509_STORE; flags: TIdC_UINT): TIdC_INT; cdecl;
function CMS_get0_signers(cms: PCMS_ContentInfo): Pstack_st_X509; cdecl;
function CMS_encrypt(certs: Pstack_st_X509; _in: PBIO; cipher: PEVP_CIPHER; flags: TIdC_UINT): PCMS_ContentInfo; cdecl;
function CMS_encrypt_ex(certs: Pstack_st_X509; _in: PBIO; cipher: PEVP_CIPHER; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl;
function CMS_decrypt(cms: PCMS_ContentInfo; pkey: PEVP_PKEY; cert: PX509; dcont: PBIO; _out: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl;
function CMS_decrypt_set1_pkey(cms: PCMS_ContentInfo; pk: PEVP_PKEY; cert: PX509): TIdC_INT; cdecl;
function CMS_decrypt_set1_pkey_and_peer(cms: PCMS_ContentInfo; pk: PEVP_PKEY; cert: PX509; peer: PX509): TIdC_INT; cdecl;
function CMS_decrypt_set1_key(cms: PCMS_ContentInfo; key: PIdAnsiChar; keylen: TIdC_SIZET; id: PIdAnsiChar; idlen: TIdC_SIZET): TIdC_INT; cdecl;
function CMS_decrypt_set1_password(cms: PCMS_ContentInfo; pass: PIdAnsiChar; passlen: TIdC_SSIZET): TIdC_INT; cdecl;
function CMS_get0_RecipientInfos(cms: PCMS_ContentInfo): Pstack_st_CMS_RecipientInfo; cdecl;
function CMS_RecipientInfo_type(ri: PCMS_RecipientInfo): TIdC_INT; cdecl;
function CMS_RecipientInfo_get0_pkey_ctx(ri: PCMS_RecipientInfo): PEVP_PKEY_CTX; cdecl;
function CMS_AuthEnvelopedData_create(cipher: PEVP_CIPHER): PCMS_ContentInfo; cdecl;
function CMS_AuthEnvelopedData_create_ex(cipher: PEVP_CIPHER; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl;
function CMS_EnvelopedData_create(cipher: PEVP_CIPHER): PCMS_ContentInfo; cdecl;
function CMS_EnvelopedData_create_ex(cipher: PEVP_CIPHER; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl;
function CMS_EnvelopedData_decrypt(env: PCMS_EnvelopedData; detached_data: PBIO; pkey: PEVP_PKEY; cert: PX509; secret: PASN1_OCTET_STRING; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PBIO; cdecl;
function CMS_add1_recipient_cert(cms: PCMS_ContentInfo; recip: PX509; flags: TIdC_UINT): PCMS_RecipientInfo; cdecl;
function CMS_add1_recipient(cms: PCMS_ContentInfo; recip: PX509; originatorPrivKey: PEVP_PKEY; originator: PX509; flags: TIdC_UINT): PCMS_RecipientInfo; cdecl;
function CMS_RecipientInfo_set0_pkey(ri: PCMS_RecipientInfo; pkey: PEVP_PKEY): TIdC_INT; cdecl;
function CMS_RecipientInfo_ktri_cert_cmp(ri: PCMS_RecipientInfo; cert: PX509): TIdC_INT; cdecl;
function CMS_RecipientInfo_ktri_get0_algs(ri: PCMS_RecipientInfo; pk: PPEVP_PKEY; recip: PPX509; palg: PPX509_ALGOR): TIdC_INT; cdecl;
function CMS_RecipientInfo_ktri_get0_signer_id(ri: PCMS_RecipientInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT; cdecl;
function CMS_add0_recipient_key(cms: PCMS_ContentInfo; nid: TIdC_INT; key: PIdAnsiChar; keylen: TIdC_SIZET; id: PIdAnsiChar; idlen: TIdC_SIZET; date: PASN1_GENERALIZEDTIME; otherTypeId: PASN1_OBJECT; otherType: PASN1_TYPE): PCMS_RecipientInfo; cdecl;
function CMS_RecipientInfo_kekri_get0_id(ri: PCMS_RecipientInfo; palg: PPX509_ALGOR; pid: PPASN1_OCTET_STRING; pdate: PPASN1_GENERALIZEDTIME; potherid: PPASN1_OBJECT; pothertype: PPASN1_TYPE): TIdC_INT; cdecl;
function CMS_RecipientInfo_set0_key(ri: PCMS_RecipientInfo; key: PIdAnsiChar; keylen: TIdC_SIZET): TIdC_INT; cdecl;
function CMS_RecipientInfo_kekri_id_cmp(ri: PCMS_RecipientInfo; id: PIdAnsiChar; idlen: TIdC_SIZET): TIdC_INT; cdecl;
function CMS_RecipientInfo_set0_password(ri: PCMS_RecipientInfo; pass: PIdAnsiChar; passlen: TIdC_SSIZET): TIdC_INT; cdecl;
function CMS_add0_recipient_password(cms: PCMS_ContentInfo; iter: TIdC_INT; wrap_nid: TIdC_INT; pbe_nid: TIdC_INT; pass: PIdAnsiChar; passlen: TIdC_SSIZET; kekciph: PEVP_CIPHER): PCMS_RecipientInfo; cdecl;
function CMS_RecipientInfo_decrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TIdC_INT; cdecl;
function CMS_RecipientInfo_encrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TIdC_INT; cdecl;
function CMS_uncompress(cms: PCMS_ContentInfo; dcont: PBIO; _out: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl;
function CMS_compress(_in: PBIO; comp_nid: TIdC_INT; flags: TIdC_UINT): PCMS_ContentInfo; cdecl;
function CMS_set1_eContentType(cms: PCMS_ContentInfo; oid: PASN1_OBJECT): TIdC_INT; cdecl;
function CMS_get0_eContentType(cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl;
function CMS_add0_CertificateChoices(cms: PCMS_ContentInfo): PCMS_CertificateChoices; cdecl;
function CMS_add0_cert(cms: PCMS_ContentInfo; cert: PX509): TIdC_INT; cdecl;
function CMS_add1_cert(cms: PCMS_ContentInfo; cert: PX509): TIdC_INT; cdecl;
function CMS_get1_certs(cms: PCMS_ContentInfo): Pstack_st_X509; cdecl;
function CMS_add0_RevocationInfoChoice(cms: PCMS_ContentInfo): PCMS_RevocationInfoChoice; cdecl;
function CMS_add0_crl(cms: PCMS_ContentInfo; crl: PX509_CRL): TIdC_INT; cdecl;
function CMS_add1_crl(cms: PCMS_ContentInfo; crl: PX509_CRL): TIdC_INT; cdecl;
function CMS_get1_crls(cms: PCMS_ContentInfo): Pstack_st_X509_CRL; cdecl;
function CMS_SignedData_init(cms: PCMS_ContentInfo): TIdC_INT; cdecl;
function CMS_add1_signer(cms: PCMS_ContentInfo; signer: PX509; pk: PEVP_PKEY; md: PEVP_MD; flags: TIdC_UINT): PCMS_SignerInfo; cdecl;
function CMS_SignerInfo_get0_pkey_ctx(si: PCMS_SignerInfo): PEVP_PKEY_CTX; cdecl;
function CMS_SignerInfo_get0_md_ctx(si: PCMS_SignerInfo): PEVP_MD_CTX; cdecl;
function CMS_get0_SignerInfos(cms: PCMS_ContentInfo): Pstack_st_CMS_SignerInfo; cdecl;
function CMS_SignerInfo_set1_signer_cert(si: PCMS_SignerInfo; signer: PX509): void; cdecl;
function CMS_SignerInfo_get0_signer_id(si: PCMS_SignerInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT; cdecl;
function CMS_SignerInfo_cert_cmp(si: PCMS_SignerInfo; cert: PX509): TIdC_INT; cdecl;
function CMS_set1_signers_certs(cms: PCMS_ContentInfo; certs: Pstack_st_X509; flags: TIdC_UINT): TIdC_INT; cdecl;
function CMS_SignerInfo_get0_algs(si: PCMS_SignerInfo; pk: PPEVP_PKEY; signer: PPX509; pdig: PPX509_ALGOR; psig: PPX509_ALGOR): void; cdecl;
function CMS_SignerInfo_get0_signature(si: PCMS_SignerInfo): PASN1_OCTET_STRING; cdecl;
function CMS_SignerInfo_sign(si: PCMS_SignerInfo): TIdC_INT; cdecl;
function CMS_SignerInfo_verify(si: PCMS_SignerInfo): TIdC_INT; cdecl;
function CMS_SignerInfo_verify_content(si: PCMS_SignerInfo; chain: PBIO): TIdC_INT; cdecl;
function CMS_SignedData_verify(sd: PCMS_SignedData; detached_data: PBIO; scerts: Pstack_st_X509; store: PX509_STORE; extra: Pstack_st_X509; crls: Pstack_st_X509_CRL; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PBIO; cdecl;
function CMS_add_smimecap(si: PCMS_SignerInfo; algs: Pstack_st_X509_ALGOR): TIdC_INT; cdecl;
function CMS_add_simple_smimecap(algs: PPstack_st_X509_ALGOR; algnid: TIdC_INT; keysize: TIdC_INT): TIdC_INT; cdecl;
function CMS_add_standard_smimecap(smcap: PPstack_st_X509_ALGOR): TIdC_INT; cdecl;
function CMS_signed_get_attr_count(si: PCMS_SignerInfo): TIdC_INT; cdecl;
function CMS_signed_get_attr_by_NID(si: PCMS_SignerInfo; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function CMS_signed_get_attr_by_OBJ(si: PCMS_SignerInfo; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function CMS_signed_get_attr(si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl;
function CMS_signed_delete_attr(si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl;
function CMS_signed_add1_attr(si: PCMS_SignerInfo; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl;
function CMS_signed_add1_attr_by_OBJ(si: PCMS_SignerInfo; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl;
function CMS_signed_add1_attr_by_NID(si: PCMS_SignerInfo; nid: TIdC_INT; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl;
function CMS_signed_add1_attr_by_txt(si: PCMS_SignerInfo; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl;
function CMS_signed_get0_data_by_OBJ(si: PCMS_SignerInfo; oid: PASN1_OBJECT; lastpos: TIdC_INT; _type: TIdC_INT): Pointer; cdecl;
function CMS_unsigned_get_attr_count(si: PCMS_SignerInfo): TIdC_INT; cdecl;
function CMS_unsigned_get_attr_by_NID(si: PCMS_SignerInfo; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function CMS_unsigned_get_attr_by_OBJ(si: PCMS_SignerInfo; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function CMS_unsigned_get_attr(si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl;
function CMS_unsigned_delete_attr(si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl;
function CMS_unsigned_add1_attr(si: PCMS_SignerInfo; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl;
function CMS_unsigned_add1_attr_by_OBJ(si: PCMS_SignerInfo; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl;
function CMS_unsigned_add1_attr_by_NID(si: PCMS_SignerInfo; nid: TIdC_INT; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl;
function CMS_unsigned_add1_attr_by_txt(si: PCMS_SignerInfo; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl;
function CMS_unsigned_get0_data_by_OBJ(si: PCMS_SignerInfo; oid: PASN1_OBJECT; lastpos: TIdC_INT; _type: TIdC_INT): Pointer; cdecl;
function CMS_get1_ReceiptRequest(si: PCMS_SignerInfo; prr: PPCMS_ReceiptRequest): TIdC_INT; cdecl;
function CMS_ReceiptRequest_create0(id: PIdAnsiChar; idlen: TIdC_INT; allorfirst: TIdC_INT; receiptList: Pstack_st_GENERAL_NAMES; receiptsTo: Pstack_st_GENERAL_NAMES): PCMS_ReceiptRequest; cdecl;
function CMS_ReceiptRequest_create0_ex(id: PIdAnsiChar; idlen: TIdC_INT; allorfirst: TIdC_INT; receiptList: Pstack_st_GENERAL_NAMES; receiptsTo: Pstack_st_GENERAL_NAMES; libctx: POSSL_LIB_CTX): PCMS_ReceiptRequest; cdecl;
function CMS_add1_ReceiptRequest(si: PCMS_SignerInfo; rr: PCMS_ReceiptRequest): TIdC_INT; cdecl;
function CMS_ReceiptRequest_get0_values(rr: PCMS_ReceiptRequest; pcid: PPASN1_STRING; pallorfirst: PIdC_INT; plist: PPstack_st_GENERAL_NAMES; prto: PPstack_st_GENERAL_NAMES): void; cdecl;
function CMS_RecipientInfo_kari_get0_alg(ri: PCMS_RecipientInfo; palg: PPX509_ALGOR; pukm: PPASN1_OCTET_STRING): TIdC_INT; cdecl;
function CMS_RecipientInfo_kari_get0_reks(ri: PCMS_RecipientInfo): Pstack_st_CMS_RecipientEncryptedKey; cdecl;
function CMS_RecipientInfo_kari_get0_orig_id(ri: PCMS_RecipientInfo; pubalg: PPX509_ALGOR; pubkey: PPASN1_BIT_STRING; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT; cdecl;
function CMS_RecipientInfo_kari_orig_id_cmp(ri: PCMS_RecipientInfo; cert: PX509): TIdC_INT; cdecl;
function CMS_RecipientEncryptedKey_get0_id(rek: PCMS_RecipientEncryptedKey; keyid: PPASN1_OCTET_STRING; tm: PPASN1_GENERALIZEDTIME; other: PPCMS_OtherKeyAttribute; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT; cdecl;
function CMS_RecipientEncryptedKey_cert_cmp(rek: PCMS_RecipientEncryptedKey; cert: PX509): TIdC_INT; cdecl;
function CMS_RecipientInfo_kari_set0_pkey(ri: PCMS_RecipientInfo; pk: PEVP_PKEY): TIdC_INT; cdecl;
function CMS_RecipientInfo_kari_set0_pkey_and_peer(ri: PCMS_RecipientInfo; pk: PEVP_PKEY; peer: PX509): TIdC_INT; cdecl;
function CMS_RecipientInfo_kari_get0_ctx(ri: PCMS_RecipientInfo): PEVP_CIPHER_CTX; cdecl;
function CMS_RecipientInfo_kari_decrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo; rek: PCMS_RecipientEncryptedKey): TIdC_INT; cdecl;
function CMS_SharedInfo_encode(pder: PPIdAnsiChar; kekalg: PX509_ALGOR; ukm: PASN1_OCTET_STRING; keylen: TIdC_INT): TIdC_INT; cdecl;
function CMS_RecipientInfo_kemri_cert_cmp(ri: PCMS_RecipientInfo; cert: PX509): TIdC_INT; cdecl;
function CMS_RecipientInfo_kemri_set0_pkey(ri: PCMS_RecipientInfo; pk: PEVP_PKEY): TIdC_INT; cdecl;
function CMS_RecipientInfo_kemri_get0_ctx(ri: PCMS_RecipientInfo): PEVP_CIPHER_CTX; cdecl;
function CMS_RecipientInfo_kemri_get0_kdf_alg(ri: PCMS_RecipientInfo): PX509_ALGOR; cdecl;
function CMS_RecipientInfo_kemri_set_ukm(ri: PCMS_RecipientInfo; ukm: PIdAnsiChar; ukmLength: TIdC_INT): TIdC_INT; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// OPENSSL STACK DEFINITIONS
// =============================================================================
type
  { TODO 1 -copenssl stack CMS_SignerInfo definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_CMS_SignerInfo = Pointer;
  {$EXTERNALSYM PSTACK_OF_CMS_SignerInfo}

  { Original Stack Macros for CMS_SignerInfo:
    SKM_DEFINE_STACK_OF_INTERNAL(CMS_SignerInfo, CMS_SignerInfo, CMS_SignerInfo)
    sk_CMS_SignerInfo_num(sk) OPENSSL_sk_num(ossl_check_const_CMS_SignerInfo_sk_type(sk))
    sk_CMS_SignerInfo_value(sk, idx) ((CMS_SignerInfo *)OPENSSL_sk_value(ossl_check_const_CMS_SignerInfo_sk_type(sk), (idx)))
    sk_CMS_SignerInfo_new(cmp) ((STACK_OF(CMS_SignerInfo) *)OPENSSL_sk_new(ossl_check_CMS_SignerInfo_compfunc_type(cmp)))
    sk_CMS_SignerInfo_new_null() ((STACK_OF(CMS_SignerInfo) *)OPENSSL_sk_new_null())
    sk_CMS_SignerInfo_new_reserve(cmp, n) ((STACK_OF(CMS_SignerInfo) *)OPENSSL_sk_new_reserve(ossl_check_CMS_SignerInfo_compfunc_type(cmp), (n)))
    sk_CMS_SignerInfo_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_CMS_SignerInfo_sk_type(sk), (n))
    sk_CMS_SignerInfo_free(sk) OPENSSL_sk_free(ossl_check_CMS_SignerInfo_sk_type(sk))
    sk_CMS_SignerInfo_zero(sk) OPENSSL_sk_zero(ossl_check_CMS_SignerInfo_sk_type(sk))
    sk_CMS_SignerInfo_delete(sk, i) ((CMS_SignerInfo *)OPENSSL_sk_delete(ossl_check_CMS_SignerInfo_sk_type(sk), (i)))
    sk_CMS_SignerInfo_delete_ptr(sk, ptr) ((CMS_SignerInfo *)OPENSSL_sk_delete_ptr(ossl_check_CMS_SignerInfo_sk_type(sk), ossl_check_CMS_SignerInfo_type(ptr)))
    sk_CMS_SignerInfo_push(sk, ptr) OPENSSL_sk_push(ossl_check_CMS_SignerInfo_sk_type(sk), ossl_check_CMS_SignerInfo_type(ptr))
    sk_CMS_SignerInfo_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_CMS_SignerInfo_sk_type(sk), ossl_check_CMS_SignerInfo_type(ptr))
    sk_CMS_SignerInfo_pop(sk) ((CMS_SignerInfo *)OPENSSL_sk_pop(ossl_check_CMS_SignerInfo_sk_type(sk)))
    sk_CMS_SignerInfo_shift(sk) ((CMS_SignerInfo *)OPENSSL_sk_shift(ossl_check_CMS_SignerInfo_sk_type(sk)))
    sk_CMS_SignerInfo_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_CMS_SignerInfo_sk_type(sk), ossl_check_CMS_SignerInfo_freefunc_type(freefunc))
    sk_CMS_SignerInfo_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_CMS_SignerInfo_sk_type(sk), ossl_check_CMS_SignerInfo_type(ptr), (idx))
    sk_CMS_SignerInfo_set(sk, idx, ptr) ((CMS_SignerInfo *)OPENSSL_sk_set(ossl_check_CMS_SignerInfo_sk_type(sk), (idx), ossl_check_CMS_SignerInfo_type(ptr)))
    sk_CMS_SignerInfo_find(sk, ptr) OPENSSL_sk_find(ossl_check_CMS_SignerInfo_sk_type(sk), ossl_check_CMS_SignerInfo_type(ptr))
    sk_CMS_SignerInfo_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_CMS_SignerInfo_sk_type(sk), ossl_check_CMS_SignerInfo_type(ptr))
    sk_CMS_SignerInfo_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_CMS_SignerInfo_sk_type(sk), ossl_check_CMS_SignerInfo_type(ptr), pnum)
    sk_CMS_SignerInfo_sort(sk) OPENSSL_sk_sort(ossl_check_CMS_SignerInfo_sk_type(sk))
    sk_CMS_SignerInfo_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_CMS_SignerInfo_sk_type(sk))
    sk_CMS_SignerInfo_dup(sk) ((STACK_OF(CMS_SignerInfo) *)OPENSSL_sk_dup(ossl_check_const_CMS_SignerInfo_sk_type(sk)))
    sk_CMS_SignerInfo_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(CMS_SignerInfo) *)OPENSSL_sk_deep_copy(ossl_check_const_CMS_SignerInfo_sk_type(sk), ossl_check_CMS_SignerInfo_copyfunc_type(copyfunc), ossl_check_CMS_SignerInfo_freefunc_type(freefunc)))
    sk_CMS_SignerInfo_set_cmp_func(sk, cmp) ((sk_CMS_SignerInfo_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_CMS_SignerInfo_sk_type(sk), ossl_check_CMS_SignerInfo_compfunc_type(cmp)))
  }

  { TODO 1 -copenssl stack CMS_RecipientEncryptedKey definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_CMS_RecipientEncryptedKey = Pointer;
  {$EXTERNALSYM PSTACK_OF_CMS_RecipientEncryptedKey}

  { Original Stack Macros for CMS_RecipientEncryptedKey:
    SKM_DEFINE_STACK_OF_INTERNAL(CMS_RecipientEncryptedKey, CMS_RecipientEncryptedKey, CMS_RecipientEncryptedKey)
    sk_CMS_RecipientEncryptedKey_num(sk) OPENSSL_sk_num(ossl_check_const_CMS_RecipientEncryptedKey_sk_type(sk))
    sk_CMS_RecipientEncryptedKey_value(sk, idx) ((CMS_RecipientEncryptedKey *)OPENSSL_sk_value(ossl_check_const_CMS_RecipientEncryptedKey_sk_type(sk), (idx)))
    sk_CMS_RecipientEncryptedKey_new(cmp) ((STACK_OF(CMS_RecipientEncryptedKey) *)OPENSSL_sk_new(ossl_check_CMS_RecipientEncryptedKey_compfunc_type(cmp)))
    sk_CMS_RecipientEncryptedKey_new_null() ((STACK_OF(CMS_RecipientEncryptedKey) *)OPENSSL_sk_new_null())
    sk_CMS_RecipientEncryptedKey_new_reserve(cmp, n) ((STACK_OF(CMS_RecipientEncryptedKey) *)OPENSSL_sk_new_reserve(ossl_check_CMS_RecipientEncryptedKey_compfunc_type(cmp), (n)))
    sk_CMS_RecipientEncryptedKey_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_CMS_RecipientEncryptedKey_sk_type(sk), (n))
    sk_CMS_RecipientEncryptedKey_free(sk) OPENSSL_sk_free(ossl_check_CMS_RecipientEncryptedKey_sk_type(sk))
    sk_CMS_RecipientEncryptedKey_zero(sk) OPENSSL_sk_zero(ossl_check_CMS_RecipientEncryptedKey_sk_type(sk))
    sk_CMS_RecipientEncryptedKey_delete(sk, i) ((CMS_RecipientEncryptedKey *)OPENSSL_sk_delete(ossl_check_CMS_RecipientEncryptedKey_sk_type(sk), (i)))
    sk_CMS_RecipientEncryptedKey_delete_ptr(sk, ptr) ((CMS_RecipientEncryptedKey *)OPENSSL_sk_delete_ptr(ossl_check_CMS_RecipientEncryptedKey_sk_type(sk), ossl_check_CMS_RecipientEncryptedKey_type(ptr)))
    sk_CMS_RecipientEncryptedKey_push(sk, ptr) OPENSSL_sk_push(ossl_check_CMS_RecipientEncryptedKey_sk_type(sk), ossl_check_CMS_RecipientEncryptedKey_type(ptr))
    sk_CMS_RecipientEncryptedKey_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_CMS_RecipientEncryptedKey_sk_type(sk), ossl_check_CMS_RecipientEncryptedKey_type(ptr))
    sk_CMS_RecipientEncryptedKey_pop(sk) ((CMS_RecipientEncryptedKey *)OPENSSL_sk_pop(ossl_check_CMS_RecipientEncryptedKey_sk_type(sk)))
    sk_CMS_RecipientEncryptedKey_shift(sk) ((CMS_RecipientEncryptedKey *)OPENSSL_sk_shift(ossl_check_CMS_RecipientEncryptedKey_sk_type(sk)))
    sk_CMS_RecipientEncryptedKey_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_CMS_RecipientEncryptedKey_sk_type(sk), ossl_check_CMS_RecipientEncryptedKey_freefunc_type(freefunc))
    sk_CMS_RecipientEncryptedKey_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_CMS_RecipientEncryptedKey_sk_type(sk), ossl_check_CMS_RecipientEncryptedKey_type(ptr), (idx))
    sk_CMS_RecipientEncryptedKey_set(sk, idx, ptr) ((CMS_RecipientEncryptedKey *)OPENSSL_sk_set(ossl_check_CMS_RecipientEncryptedKey_sk_type(sk), (idx), ossl_check_CMS_RecipientEncryptedKey_type(ptr)))
    sk_CMS_RecipientEncryptedKey_find(sk, ptr) OPENSSL_sk_find(ossl_check_CMS_RecipientEncryptedKey_sk_type(sk), ossl_check_CMS_RecipientEncryptedKey_type(ptr))
    sk_CMS_RecipientEncryptedKey_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_CMS_RecipientEncryptedKey_sk_type(sk), ossl_check_CMS_RecipientEncryptedKey_type(ptr))
    sk_CMS_RecipientEncryptedKey_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_CMS_RecipientEncryptedKey_sk_type(sk), ossl_check_CMS_RecipientEncryptedKey_type(ptr), pnum)
    sk_CMS_RecipientEncryptedKey_sort(sk) OPENSSL_sk_sort(ossl_check_CMS_RecipientEncryptedKey_sk_type(sk))
    sk_CMS_RecipientEncryptedKey_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_CMS_RecipientEncryptedKey_sk_type(sk))
    sk_CMS_RecipientEncryptedKey_dup(sk) ((STACK_OF(CMS_RecipientEncryptedKey) *)OPENSSL_sk_dup(ossl_check_const_CMS_RecipientEncryptedKey_sk_type(sk)))
    sk_CMS_RecipientEncryptedKey_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(CMS_RecipientEncryptedKey) *)OPENSSL_sk_deep_copy(ossl_check_const_CMS_RecipientEncryptedKey_sk_type(sk), ossl_check_CMS_RecipientEncryptedKey_copyfunc_type(copyfunc), ossl_check_CMS_RecipientEncryptedKey_freefunc_type(freefunc)))
    sk_CMS_RecipientEncryptedKey_set_cmp_func(sk, cmp) ((sk_CMS_RecipientEncryptedKey_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_CMS_RecipientEncryptedKey_sk_type(sk), ossl_check_CMS_RecipientEncryptedKey_compfunc_type(cmp)))
  }

  { TODO 1 -copenssl stack CMS_RecipientInfo definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_CMS_RecipientInfo = Pointer;
  {$EXTERNALSYM PSTACK_OF_CMS_RecipientInfo}

  { Original Stack Macros for CMS_RecipientInfo:
    SKM_DEFINE_STACK_OF_INTERNAL(CMS_RecipientInfo, CMS_RecipientInfo, CMS_RecipientInfo)
    sk_CMS_RecipientInfo_num(sk) OPENSSL_sk_num(ossl_check_const_CMS_RecipientInfo_sk_type(sk))
    sk_CMS_RecipientInfo_value(sk, idx) ((CMS_RecipientInfo *)OPENSSL_sk_value(ossl_check_const_CMS_RecipientInfo_sk_type(sk), (idx)))
    sk_CMS_RecipientInfo_new(cmp) ((STACK_OF(CMS_RecipientInfo) *)OPENSSL_sk_new(ossl_check_CMS_RecipientInfo_compfunc_type(cmp)))
    sk_CMS_RecipientInfo_new_null() ((STACK_OF(CMS_RecipientInfo) *)OPENSSL_sk_new_null())
    sk_CMS_RecipientInfo_new_reserve(cmp, n) ((STACK_OF(CMS_RecipientInfo) *)OPENSSL_sk_new_reserve(ossl_check_CMS_RecipientInfo_compfunc_type(cmp), (n)))
    sk_CMS_RecipientInfo_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_CMS_RecipientInfo_sk_type(sk), (n))
    sk_CMS_RecipientInfo_free(sk) OPENSSL_sk_free(ossl_check_CMS_RecipientInfo_sk_type(sk))
    sk_CMS_RecipientInfo_zero(sk) OPENSSL_sk_zero(ossl_check_CMS_RecipientInfo_sk_type(sk))
    sk_CMS_RecipientInfo_delete(sk, i) ((CMS_RecipientInfo *)OPENSSL_sk_delete(ossl_check_CMS_RecipientInfo_sk_type(sk), (i)))
    sk_CMS_RecipientInfo_delete_ptr(sk, ptr) ((CMS_RecipientInfo *)OPENSSL_sk_delete_ptr(ossl_check_CMS_RecipientInfo_sk_type(sk), ossl_check_CMS_RecipientInfo_type(ptr)))
    sk_CMS_RecipientInfo_push(sk, ptr) OPENSSL_sk_push(ossl_check_CMS_RecipientInfo_sk_type(sk), ossl_check_CMS_RecipientInfo_type(ptr))
    sk_CMS_RecipientInfo_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_CMS_RecipientInfo_sk_type(sk), ossl_check_CMS_RecipientInfo_type(ptr))
    sk_CMS_RecipientInfo_pop(sk) ((CMS_RecipientInfo *)OPENSSL_sk_pop(ossl_check_CMS_RecipientInfo_sk_type(sk)))
    sk_CMS_RecipientInfo_shift(sk) ((CMS_RecipientInfo *)OPENSSL_sk_shift(ossl_check_CMS_RecipientInfo_sk_type(sk)))
    sk_CMS_RecipientInfo_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_CMS_RecipientInfo_sk_type(sk), ossl_check_CMS_RecipientInfo_freefunc_type(freefunc))
    sk_CMS_RecipientInfo_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_CMS_RecipientInfo_sk_type(sk), ossl_check_CMS_RecipientInfo_type(ptr), (idx))
    sk_CMS_RecipientInfo_set(sk, idx, ptr) ((CMS_RecipientInfo *)OPENSSL_sk_set(ossl_check_CMS_RecipientInfo_sk_type(sk), (idx), ossl_check_CMS_RecipientInfo_type(ptr)))
    sk_CMS_RecipientInfo_find(sk, ptr) OPENSSL_sk_find(ossl_check_CMS_RecipientInfo_sk_type(sk), ossl_check_CMS_RecipientInfo_type(ptr))
    sk_CMS_RecipientInfo_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_CMS_RecipientInfo_sk_type(sk), ossl_check_CMS_RecipientInfo_type(ptr))
    sk_CMS_RecipientInfo_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_CMS_RecipientInfo_sk_type(sk), ossl_check_CMS_RecipientInfo_type(ptr), pnum)
    sk_CMS_RecipientInfo_sort(sk) OPENSSL_sk_sort(ossl_check_CMS_RecipientInfo_sk_type(sk))
    sk_CMS_RecipientInfo_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_CMS_RecipientInfo_sk_type(sk))
    sk_CMS_RecipientInfo_dup(sk) ((STACK_OF(CMS_RecipientInfo) *)OPENSSL_sk_dup(ossl_check_const_CMS_RecipientInfo_sk_type(sk)))
    sk_CMS_RecipientInfo_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(CMS_RecipientInfo) *)OPENSSL_sk_deep_copy(ossl_check_const_CMS_RecipientInfo_sk_type(sk), ossl_check_CMS_RecipientInfo_copyfunc_type(copyfunc), ossl_check_CMS_RecipientInfo_freefunc_type(freefunc)))
    sk_CMS_RecipientInfo_set_cmp_func(sk, cmp) ((sk_CMS_RecipientInfo_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_CMS_RecipientInfo_sk_type(sk), ossl_check_CMS_RecipientInfo_compfunc_type(cmp)))
  }

  { TODO 1 -copenssl stack CMS_RevocationInfoChoice definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_CMS_RevocationInfoChoice = Pointer;
  {$EXTERNALSYM PSTACK_OF_CMS_RevocationInfoChoice}

  { Original Stack Macros for CMS_RevocationInfoChoice:
    SKM_DEFINE_STACK_OF_INTERNAL(CMS_RevocationInfoChoice, CMS_RevocationInfoChoice, CMS_RevocationInfoChoice)
    sk_CMS_RevocationInfoChoice_num(sk) OPENSSL_sk_num(ossl_check_const_CMS_RevocationInfoChoice_sk_type(sk))
    sk_CMS_RevocationInfoChoice_value(sk, idx) ((CMS_RevocationInfoChoice *)OPENSSL_sk_value(ossl_check_const_CMS_RevocationInfoChoice_sk_type(sk), (idx)))
    sk_CMS_RevocationInfoChoice_new(cmp) ((STACK_OF(CMS_RevocationInfoChoice) *)OPENSSL_sk_new(ossl_check_CMS_RevocationInfoChoice_compfunc_type(cmp)))
    sk_CMS_RevocationInfoChoice_new_null() ((STACK_OF(CMS_RevocationInfoChoice) *)OPENSSL_sk_new_null())
    sk_CMS_RevocationInfoChoice_new_reserve(cmp, n) ((STACK_OF(CMS_RevocationInfoChoice) *)OPENSSL_sk_new_reserve(ossl_check_CMS_RevocationInfoChoice_compfunc_type(cmp), (n)))
    sk_CMS_RevocationInfoChoice_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_CMS_RevocationInfoChoice_sk_type(sk), (n))
    sk_CMS_RevocationInfoChoice_free(sk) OPENSSL_sk_free(ossl_check_CMS_RevocationInfoChoice_sk_type(sk))
    sk_CMS_RevocationInfoChoice_zero(sk) OPENSSL_sk_zero(ossl_check_CMS_RevocationInfoChoice_sk_type(sk))
    sk_CMS_RevocationInfoChoice_delete(sk, i) ((CMS_RevocationInfoChoice *)OPENSSL_sk_delete(ossl_check_CMS_RevocationInfoChoice_sk_type(sk), (i)))
    sk_CMS_RevocationInfoChoice_delete_ptr(sk, ptr) ((CMS_RevocationInfoChoice *)OPENSSL_sk_delete_ptr(ossl_check_CMS_RevocationInfoChoice_sk_type(sk), ossl_check_CMS_RevocationInfoChoice_type(ptr)))
    sk_CMS_RevocationInfoChoice_push(sk, ptr) OPENSSL_sk_push(ossl_check_CMS_RevocationInfoChoice_sk_type(sk), ossl_check_CMS_RevocationInfoChoice_type(ptr))
    sk_CMS_RevocationInfoChoice_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_CMS_RevocationInfoChoice_sk_type(sk), ossl_check_CMS_RevocationInfoChoice_type(ptr))
    sk_CMS_RevocationInfoChoice_pop(sk) ((CMS_RevocationInfoChoice *)OPENSSL_sk_pop(ossl_check_CMS_RevocationInfoChoice_sk_type(sk)))
    sk_CMS_RevocationInfoChoice_shift(sk) ((CMS_RevocationInfoChoice *)OPENSSL_sk_shift(ossl_check_CMS_RevocationInfoChoice_sk_type(sk)))
    sk_CMS_RevocationInfoChoice_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_CMS_RevocationInfoChoice_sk_type(sk), ossl_check_CMS_RevocationInfoChoice_freefunc_type(freefunc))
    sk_CMS_RevocationInfoChoice_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_CMS_RevocationInfoChoice_sk_type(sk), ossl_check_CMS_RevocationInfoChoice_type(ptr), (idx))
    sk_CMS_RevocationInfoChoice_set(sk, idx, ptr) ((CMS_RevocationInfoChoice *)OPENSSL_sk_set(ossl_check_CMS_RevocationInfoChoice_sk_type(sk), (idx), ossl_check_CMS_RevocationInfoChoice_type(ptr)))
    sk_CMS_RevocationInfoChoice_find(sk, ptr) OPENSSL_sk_find(ossl_check_CMS_RevocationInfoChoice_sk_type(sk), ossl_check_CMS_RevocationInfoChoice_type(ptr))
    sk_CMS_RevocationInfoChoice_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_CMS_RevocationInfoChoice_sk_type(sk), ossl_check_CMS_RevocationInfoChoice_type(ptr))
    sk_CMS_RevocationInfoChoice_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_CMS_RevocationInfoChoice_sk_type(sk), ossl_check_CMS_RevocationInfoChoice_type(ptr), pnum)
    sk_CMS_RevocationInfoChoice_sort(sk) OPENSSL_sk_sort(ossl_check_CMS_RevocationInfoChoice_sk_type(sk))
    sk_CMS_RevocationInfoChoice_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_CMS_RevocationInfoChoice_sk_type(sk))
    sk_CMS_RevocationInfoChoice_dup(sk) ((STACK_OF(CMS_RevocationInfoChoice) *)OPENSSL_sk_dup(ossl_check_const_CMS_RevocationInfoChoice_sk_type(sk)))
    sk_CMS_RevocationInfoChoice_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(CMS_RevocationInfoChoice) *)OPENSSL_sk_deep_copy(ossl_check_const_CMS_RevocationInfoChoice_sk_type(sk), ossl_check_CMS_RevocationInfoChoice_copyfunc_type(copyfunc), ossl_check_CMS_RevocationInfoChoice_freefunc_type(freefunc)))
    sk_CMS_RevocationInfoChoice_set_cmp_func(sk, cmp) ((sk_CMS_RevocationInfoChoice_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_CMS_RevocationInfoChoice_sk_type(sk), ossl_check_CMS_RevocationInfoChoice_compfunc_type(cmp)))
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

function CMS_EnvelopedData_it: PASN1_ITEM; cdecl external CLibCrypto name 'CMS_EnvelopedData_it';
function CMS_SignedData_new: PCMS_SignedData; cdecl external CLibCrypto name 'CMS_SignedData_new';
function CMS_SignedData_free(a: PCMS_SignedData): void; cdecl external CLibCrypto name 'CMS_SignedData_free';
function CMS_ContentInfo_new: PCMS_ContentInfo; cdecl external CLibCrypto name 'CMS_ContentInfo_new';
function CMS_ContentInfo_free(a: PCMS_ContentInfo): void; cdecl external CLibCrypto name 'CMS_ContentInfo_free';
function d2i_CMS_ContentInfo(a: PPCMS_ContentInfo; _in: PPIdAnsiChar; len: TIdC_LONG): PCMS_ContentInfo; cdecl external CLibCrypto name 'd2i_CMS_ContentInfo';
function i2d_CMS_ContentInfo(a: PCMS_ContentInfo; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_CMS_ContentInfo';
function CMS_ContentInfo_it: PASN1_ITEM; cdecl external CLibCrypto name 'CMS_ContentInfo_it';
function CMS_ReceiptRequest_new: PCMS_ReceiptRequest; cdecl external CLibCrypto name 'CMS_ReceiptRequest_new';
function CMS_ReceiptRequest_free(a: PCMS_ReceiptRequest): void; cdecl external CLibCrypto name 'CMS_ReceiptRequest_free';
function d2i_CMS_ReceiptRequest(a: PPCMS_ReceiptRequest; _in: PPIdAnsiChar; len: TIdC_LONG): PCMS_ReceiptRequest; cdecl external CLibCrypto name 'd2i_CMS_ReceiptRequest';
function i2d_CMS_ReceiptRequest(a: PCMS_ReceiptRequest; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_CMS_ReceiptRequest';
function CMS_ReceiptRequest_it: PASN1_ITEM; cdecl external CLibCrypto name 'CMS_ReceiptRequest_it';
function CMS_ContentInfo_print_ctx(_out: PBIO; x: PCMS_ContentInfo; indent: TIdC_INT; pctx: PASN1_PCTX): TIdC_INT; cdecl external CLibCrypto name 'CMS_ContentInfo_print_ctx';
function CMS_EnvelopedData_dup(a: PCMS_EnvelopedData): PCMS_EnvelopedData; cdecl external CLibCrypto name 'CMS_EnvelopedData_dup';
function CMS_ContentInfo_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl external CLibCrypto name 'CMS_ContentInfo_new_ex';
function CMS_get0_type(cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl external CLibCrypto name 'CMS_get0_type';
function CMS_dataInit(cms: PCMS_ContentInfo; icont: PBIO): PBIO; cdecl external CLibCrypto name 'CMS_dataInit';
function CMS_dataFinal(cms: PCMS_ContentInfo; bio: PBIO): TIdC_INT; cdecl external CLibCrypto name 'CMS_dataFinal';
function CMS_get0_content(cms: PCMS_ContentInfo): PPASN1_OCTET_STRING; cdecl external CLibCrypto name 'CMS_get0_content';
function CMS_is_detached(cms: PCMS_ContentInfo): TIdC_INT; cdecl external CLibCrypto name 'CMS_is_detached';
function CMS_set_detached(cms: PCMS_ContentInfo; detached: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'CMS_set_detached';
function CMS_stream(boundary: PPPIdAnsiChar; cms: PCMS_ContentInfo): TIdC_INT; cdecl external CLibCrypto name 'CMS_stream';
function d2i_CMS_bio(bp: PBIO; cms: PPCMS_ContentInfo): PCMS_ContentInfo; cdecl external CLibCrypto name 'd2i_CMS_bio';
function i2d_CMS_bio(bp: PBIO; cms: PCMS_ContentInfo): TIdC_INT; cdecl external CLibCrypto name 'i2d_CMS_bio';
function BIO_new_CMS(_out: PBIO; cms: PCMS_ContentInfo): PBIO; cdecl external CLibCrypto name 'BIO_new_CMS';
function i2d_CMS_bio_stream(_out: PBIO; cms: PCMS_ContentInfo; _in: PBIO; flags: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'i2d_CMS_bio_stream';
function PEM_write_bio_CMS_stream(_out: PBIO; cms: PCMS_ContentInfo; _in: PBIO; flags: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_CMS_stream';
function SMIME_read_CMS(bio: PBIO; bcont: PPBIO): PCMS_ContentInfo; cdecl external CLibCrypto name 'SMIME_read_CMS';
function SMIME_read_CMS_ex(bio: PBIO; flags: TIdC_INT; bcont: PPBIO; ci: PPCMS_ContentInfo): PCMS_ContentInfo; cdecl external CLibCrypto name 'SMIME_read_CMS_ex';
function SMIME_write_CMS(bio: PBIO; cms: PCMS_ContentInfo; data: PBIO; flags: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'SMIME_write_CMS';
function CMS_final(cms: PCMS_ContentInfo; data: PBIO; dcont: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'CMS_final';
function CMS_final_digest(cms: PCMS_ContentInfo; md: PIdAnsiChar; mdlen: TIdC_UINT; dcont: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'CMS_final_digest';
function CMS_sign(signcert: PX509; pkey: PEVP_PKEY; certs: Pstack_st_X509; data: PBIO; flags: TIdC_UINT): PCMS_ContentInfo; cdecl external CLibCrypto name 'CMS_sign';
function CMS_sign_ex(signcert: PX509; pkey: PEVP_PKEY; certs: Pstack_st_X509; data: PBIO; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl external CLibCrypto name 'CMS_sign_ex';
function CMS_sign_receipt(si: PCMS_SignerInfo; signcert: PX509; pkey: PEVP_PKEY; certs: Pstack_st_X509; flags: TIdC_UINT): PCMS_ContentInfo; cdecl external CLibCrypto name 'CMS_sign_receipt';
function CMS_data(cms: PCMS_ContentInfo; _out: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'CMS_data';
function CMS_data_create(_in: PBIO; flags: TIdC_UINT): PCMS_ContentInfo; cdecl external CLibCrypto name 'CMS_data_create';
function CMS_data_create_ex(_in: PBIO; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl external CLibCrypto name 'CMS_data_create_ex';
function CMS_digest_verify(cms: PCMS_ContentInfo; dcont: PBIO; _out: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'CMS_digest_verify';
function CMS_digest_create(_in: PBIO; md: PEVP_MD; flags: TIdC_UINT): PCMS_ContentInfo; cdecl external CLibCrypto name 'CMS_digest_create';
function CMS_digest_create_ex(_in: PBIO; md: PEVP_MD; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl external CLibCrypto name 'CMS_digest_create_ex';
function CMS_EncryptedData_decrypt(cms: PCMS_ContentInfo; key: PIdAnsiChar; keylen: TIdC_SIZET; dcont: PBIO; _out: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'CMS_EncryptedData_decrypt';
function CMS_EncryptedData_encrypt(_in: PBIO; cipher: PEVP_CIPHER; key: PIdAnsiChar; keylen: TIdC_SIZET; flags: TIdC_UINT): PCMS_ContentInfo; cdecl external CLibCrypto name 'CMS_EncryptedData_encrypt';
function CMS_EncryptedData_encrypt_ex(_in: PBIO; cipher: PEVP_CIPHER; key: PIdAnsiChar; keylen: TIdC_SIZET; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl external CLibCrypto name 'CMS_EncryptedData_encrypt_ex';
function CMS_EncryptedData_set1_key(cms: PCMS_ContentInfo; ciph: PEVP_CIPHER; key: PIdAnsiChar; keylen: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'CMS_EncryptedData_set1_key';
function CMS_verify(cms: PCMS_ContentInfo; certs: Pstack_st_X509; store: PX509_STORE; dcont: PBIO; _out: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'CMS_verify';
function CMS_verify_receipt(rcms: PCMS_ContentInfo; ocms: PCMS_ContentInfo; certs: Pstack_st_X509; store: PX509_STORE; flags: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'CMS_verify_receipt';
function CMS_get0_signers(cms: PCMS_ContentInfo): Pstack_st_X509; cdecl external CLibCrypto name 'CMS_get0_signers';
function CMS_encrypt(certs: Pstack_st_X509; _in: PBIO; cipher: PEVP_CIPHER; flags: TIdC_UINT): PCMS_ContentInfo; cdecl external CLibCrypto name 'CMS_encrypt';
function CMS_encrypt_ex(certs: Pstack_st_X509; _in: PBIO; cipher: PEVP_CIPHER; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl external CLibCrypto name 'CMS_encrypt_ex';
function CMS_decrypt(cms: PCMS_ContentInfo; pkey: PEVP_PKEY; cert: PX509; dcont: PBIO; _out: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'CMS_decrypt';
function CMS_decrypt_set1_pkey(cms: PCMS_ContentInfo; pk: PEVP_PKEY; cert: PX509): TIdC_INT; cdecl external CLibCrypto name 'CMS_decrypt_set1_pkey';
function CMS_decrypt_set1_pkey_and_peer(cms: PCMS_ContentInfo; pk: PEVP_PKEY; cert: PX509; peer: PX509): TIdC_INT; cdecl external CLibCrypto name 'CMS_decrypt_set1_pkey_and_peer';
function CMS_decrypt_set1_key(cms: PCMS_ContentInfo; key: PIdAnsiChar; keylen: TIdC_SIZET; id: PIdAnsiChar; idlen: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'CMS_decrypt_set1_key';
function CMS_decrypt_set1_password(cms: PCMS_ContentInfo; pass: PIdAnsiChar; passlen: TIdC_SSIZET): TIdC_INT; cdecl external CLibCrypto name 'CMS_decrypt_set1_password';
function CMS_get0_RecipientInfos(cms: PCMS_ContentInfo): Pstack_st_CMS_RecipientInfo; cdecl external CLibCrypto name 'CMS_get0_RecipientInfos';
function CMS_RecipientInfo_type(ri: PCMS_RecipientInfo): TIdC_INT; cdecl external CLibCrypto name 'CMS_RecipientInfo_type';
function CMS_RecipientInfo_get0_pkey_ctx(ri: PCMS_RecipientInfo): PEVP_PKEY_CTX; cdecl external CLibCrypto name 'CMS_RecipientInfo_get0_pkey_ctx';
function CMS_AuthEnvelopedData_create(cipher: PEVP_CIPHER): PCMS_ContentInfo; cdecl external CLibCrypto name 'CMS_AuthEnvelopedData_create';
function CMS_AuthEnvelopedData_create_ex(cipher: PEVP_CIPHER; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl external CLibCrypto name 'CMS_AuthEnvelopedData_create_ex';
function CMS_EnvelopedData_create(cipher: PEVP_CIPHER): PCMS_ContentInfo; cdecl external CLibCrypto name 'CMS_EnvelopedData_create';
function CMS_EnvelopedData_create_ex(cipher: PEVP_CIPHER; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl external CLibCrypto name 'CMS_EnvelopedData_create_ex';
function CMS_EnvelopedData_decrypt(env: PCMS_EnvelopedData; detached_data: PBIO; pkey: PEVP_PKEY; cert: PX509; secret: PASN1_OCTET_STRING; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PBIO; cdecl external CLibCrypto name 'CMS_EnvelopedData_decrypt';
function CMS_add1_recipient_cert(cms: PCMS_ContentInfo; recip: PX509; flags: TIdC_UINT): PCMS_RecipientInfo; cdecl external CLibCrypto name 'CMS_add1_recipient_cert';
function CMS_add1_recipient(cms: PCMS_ContentInfo; recip: PX509; originatorPrivKey: PEVP_PKEY; originator: PX509; flags: TIdC_UINT): PCMS_RecipientInfo; cdecl external CLibCrypto name 'CMS_add1_recipient';
function CMS_RecipientInfo_set0_pkey(ri: PCMS_RecipientInfo; pkey: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'CMS_RecipientInfo_set0_pkey';
function CMS_RecipientInfo_ktri_cert_cmp(ri: PCMS_RecipientInfo; cert: PX509): TIdC_INT; cdecl external CLibCrypto name 'CMS_RecipientInfo_ktri_cert_cmp';
function CMS_RecipientInfo_ktri_get0_algs(ri: PCMS_RecipientInfo; pk: PPEVP_PKEY; recip: PPX509; palg: PPX509_ALGOR): TIdC_INT; cdecl external CLibCrypto name 'CMS_RecipientInfo_ktri_get0_algs';
function CMS_RecipientInfo_ktri_get0_signer_id(ri: PCMS_RecipientInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT; cdecl external CLibCrypto name 'CMS_RecipientInfo_ktri_get0_signer_id';
function CMS_add0_recipient_key(cms: PCMS_ContentInfo; nid: TIdC_INT; key: PIdAnsiChar; keylen: TIdC_SIZET; id: PIdAnsiChar; idlen: TIdC_SIZET; date: PASN1_GENERALIZEDTIME; otherTypeId: PASN1_OBJECT; otherType: PASN1_TYPE): PCMS_RecipientInfo; cdecl external CLibCrypto name 'CMS_add0_recipient_key';
function CMS_RecipientInfo_kekri_get0_id(ri: PCMS_RecipientInfo; palg: PPX509_ALGOR; pid: PPASN1_OCTET_STRING; pdate: PPASN1_GENERALIZEDTIME; potherid: PPASN1_OBJECT; pothertype: PPASN1_TYPE): TIdC_INT; cdecl external CLibCrypto name 'CMS_RecipientInfo_kekri_get0_id';
function CMS_RecipientInfo_set0_key(ri: PCMS_RecipientInfo; key: PIdAnsiChar; keylen: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'CMS_RecipientInfo_set0_key';
function CMS_RecipientInfo_kekri_id_cmp(ri: PCMS_RecipientInfo; id: PIdAnsiChar; idlen: TIdC_SIZET): TIdC_INT; cdecl external CLibCrypto name 'CMS_RecipientInfo_kekri_id_cmp';
function CMS_RecipientInfo_set0_password(ri: PCMS_RecipientInfo; pass: PIdAnsiChar; passlen: TIdC_SSIZET): TIdC_INT; cdecl external CLibCrypto name 'CMS_RecipientInfo_set0_password';
function CMS_add0_recipient_password(cms: PCMS_ContentInfo; iter: TIdC_INT; wrap_nid: TIdC_INT; pbe_nid: TIdC_INT; pass: PIdAnsiChar; passlen: TIdC_SSIZET; kekciph: PEVP_CIPHER): PCMS_RecipientInfo; cdecl external CLibCrypto name 'CMS_add0_recipient_password';
function CMS_RecipientInfo_decrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TIdC_INT; cdecl external CLibCrypto name 'CMS_RecipientInfo_decrypt';
function CMS_RecipientInfo_encrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TIdC_INT; cdecl external CLibCrypto name 'CMS_RecipientInfo_encrypt';
function CMS_uncompress(cms: PCMS_ContentInfo; dcont: PBIO; _out: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'CMS_uncompress';
function CMS_compress(_in: PBIO; comp_nid: TIdC_INT; flags: TIdC_UINT): PCMS_ContentInfo; cdecl external CLibCrypto name 'CMS_compress';
function CMS_set1_eContentType(cms: PCMS_ContentInfo; oid: PASN1_OBJECT): TIdC_INT; cdecl external CLibCrypto name 'CMS_set1_eContentType';
function CMS_get0_eContentType(cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl external CLibCrypto name 'CMS_get0_eContentType';
function CMS_add0_CertificateChoices(cms: PCMS_ContentInfo): PCMS_CertificateChoices; cdecl external CLibCrypto name 'CMS_add0_CertificateChoices';
function CMS_add0_cert(cms: PCMS_ContentInfo; cert: PX509): TIdC_INT; cdecl external CLibCrypto name 'CMS_add0_cert';
function CMS_add1_cert(cms: PCMS_ContentInfo; cert: PX509): TIdC_INT; cdecl external CLibCrypto name 'CMS_add1_cert';
function CMS_get1_certs(cms: PCMS_ContentInfo): Pstack_st_X509; cdecl external CLibCrypto name 'CMS_get1_certs';
function CMS_add0_RevocationInfoChoice(cms: PCMS_ContentInfo): PCMS_RevocationInfoChoice; cdecl external CLibCrypto name 'CMS_add0_RevocationInfoChoice';
function CMS_add0_crl(cms: PCMS_ContentInfo; crl: PX509_CRL): TIdC_INT; cdecl external CLibCrypto name 'CMS_add0_crl';
function CMS_add1_crl(cms: PCMS_ContentInfo; crl: PX509_CRL): TIdC_INT; cdecl external CLibCrypto name 'CMS_add1_crl';
function CMS_get1_crls(cms: PCMS_ContentInfo): Pstack_st_X509_CRL; cdecl external CLibCrypto name 'CMS_get1_crls';
function CMS_SignedData_init(cms: PCMS_ContentInfo): TIdC_INT; cdecl external CLibCrypto name 'CMS_SignedData_init';
function CMS_add1_signer(cms: PCMS_ContentInfo; signer: PX509; pk: PEVP_PKEY; md: PEVP_MD; flags: TIdC_UINT): PCMS_SignerInfo; cdecl external CLibCrypto name 'CMS_add1_signer';
function CMS_SignerInfo_get0_pkey_ctx(si: PCMS_SignerInfo): PEVP_PKEY_CTX; cdecl external CLibCrypto name 'CMS_SignerInfo_get0_pkey_ctx';
function CMS_SignerInfo_get0_md_ctx(si: PCMS_SignerInfo): PEVP_MD_CTX; cdecl external CLibCrypto name 'CMS_SignerInfo_get0_md_ctx';
function CMS_get0_SignerInfos(cms: PCMS_ContentInfo): Pstack_st_CMS_SignerInfo; cdecl external CLibCrypto name 'CMS_get0_SignerInfos';
function CMS_SignerInfo_set1_signer_cert(si: PCMS_SignerInfo; signer: PX509): void; cdecl external CLibCrypto name 'CMS_SignerInfo_set1_signer_cert';
function CMS_SignerInfo_get0_signer_id(si: PCMS_SignerInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT; cdecl external CLibCrypto name 'CMS_SignerInfo_get0_signer_id';
function CMS_SignerInfo_cert_cmp(si: PCMS_SignerInfo; cert: PX509): TIdC_INT; cdecl external CLibCrypto name 'CMS_SignerInfo_cert_cmp';
function CMS_set1_signers_certs(cms: PCMS_ContentInfo; certs: Pstack_st_X509; flags: TIdC_UINT): TIdC_INT; cdecl external CLibCrypto name 'CMS_set1_signers_certs';
function CMS_SignerInfo_get0_algs(si: PCMS_SignerInfo; pk: PPEVP_PKEY; signer: PPX509; pdig: PPX509_ALGOR; psig: PPX509_ALGOR): void; cdecl external CLibCrypto name 'CMS_SignerInfo_get0_algs';
function CMS_SignerInfo_get0_signature(si: PCMS_SignerInfo): PASN1_OCTET_STRING; cdecl external CLibCrypto name 'CMS_SignerInfo_get0_signature';
function CMS_SignerInfo_sign(si: PCMS_SignerInfo): TIdC_INT; cdecl external CLibCrypto name 'CMS_SignerInfo_sign';
function CMS_SignerInfo_verify(si: PCMS_SignerInfo): TIdC_INT; cdecl external CLibCrypto name 'CMS_SignerInfo_verify';
function CMS_SignerInfo_verify_content(si: PCMS_SignerInfo; chain: PBIO): TIdC_INT; cdecl external CLibCrypto name 'CMS_SignerInfo_verify_content';
function CMS_SignedData_verify(sd: PCMS_SignedData; detached_data: PBIO; scerts: Pstack_st_X509; store: PX509_STORE; extra: Pstack_st_X509; crls: Pstack_st_X509_CRL; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PBIO; cdecl external CLibCrypto name 'CMS_SignedData_verify';
function CMS_add_smimecap(si: PCMS_SignerInfo; algs: Pstack_st_X509_ALGOR): TIdC_INT; cdecl external CLibCrypto name 'CMS_add_smimecap';
function CMS_add_simple_smimecap(algs: PPstack_st_X509_ALGOR; algnid: TIdC_INT; keysize: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'CMS_add_simple_smimecap';
function CMS_add_standard_smimecap(smcap: PPstack_st_X509_ALGOR): TIdC_INT; cdecl external CLibCrypto name 'CMS_add_standard_smimecap';
function CMS_signed_get_attr_count(si: PCMS_SignerInfo): TIdC_INT; cdecl external CLibCrypto name 'CMS_signed_get_attr_count';
function CMS_signed_get_attr_by_NID(si: PCMS_SignerInfo; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'CMS_signed_get_attr_by_NID';
function CMS_signed_get_attr_by_OBJ(si: PCMS_SignerInfo; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'CMS_signed_get_attr_by_OBJ';
function CMS_signed_get_attr(si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl external CLibCrypto name 'CMS_signed_get_attr';
function CMS_signed_delete_attr(si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl external CLibCrypto name 'CMS_signed_delete_attr';
function CMS_signed_add1_attr(si: PCMS_SignerInfo; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl external CLibCrypto name 'CMS_signed_add1_attr';
function CMS_signed_add1_attr_by_OBJ(si: PCMS_SignerInfo; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'CMS_signed_add1_attr_by_OBJ';
function CMS_signed_add1_attr_by_NID(si: PCMS_SignerInfo; nid: TIdC_INT; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'CMS_signed_add1_attr_by_NID';
function CMS_signed_add1_attr_by_txt(si: PCMS_SignerInfo; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'CMS_signed_add1_attr_by_txt';
function CMS_signed_get0_data_by_OBJ(si: PCMS_SignerInfo; oid: PASN1_OBJECT; lastpos: TIdC_INT; _type: TIdC_INT): Pointer; cdecl external CLibCrypto name 'CMS_signed_get0_data_by_OBJ';
function CMS_unsigned_get_attr_count(si: PCMS_SignerInfo): TIdC_INT; cdecl external CLibCrypto name 'CMS_unsigned_get_attr_count';
function CMS_unsigned_get_attr_by_NID(si: PCMS_SignerInfo; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'CMS_unsigned_get_attr_by_NID';
function CMS_unsigned_get_attr_by_OBJ(si: PCMS_SignerInfo; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'CMS_unsigned_get_attr_by_OBJ';
function CMS_unsigned_get_attr(si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl external CLibCrypto name 'CMS_unsigned_get_attr';
function CMS_unsigned_delete_attr(si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl external CLibCrypto name 'CMS_unsigned_delete_attr';
function CMS_unsigned_add1_attr(si: PCMS_SignerInfo; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl external CLibCrypto name 'CMS_unsigned_add1_attr';
function CMS_unsigned_add1_attr_by_OBJ(si: PCMS_SignerInfo; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'CMS_unsigned_add1_attr_by_OBJ';
function CMS_unsigned_add1_attr_by_NID(si: PCMS_SignerInfo; nid: TIdC_INT; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'CMS_unsigned_add1_attr_by_NID';
function CMS_unsigned_add1_attr_by_txt(si: PCMS_SignerInfo; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'CMS_unsigned_add1_attr_by_txt';
function CMS_unsigned_get0_data_by_OBJ(si: PCMS_SignerInfo; oid: PASN1_OBJECT; lastpos: TIdC_INT; _type: TIdC_INT): Pointer; cdecl external CLibCrypto name 'CMS_unsigned_get0_data_by_OBJ';
function CMS_get1_ReceiptRequest(si: PCMS_SignerInfo; prr: PPCMS_ReceiptRequest): TIdC_INT; cdecl external CLibCrypto name 'CMS_get1_ReceiptRequest';
function CMS_ReceiptRequest_create0(id: PIdAnsiChar; idlen: TIdC_INT; allorfirst: TIdC_INT; receiptList: Pstack_st_GENERAL_NAMES; receiptsTo: Pstack_st_GENERAL_NAMES): PCMS_ReceiptRequest; cdecl external CLibCrypto name 'CMS_ReceiptRequest_create0';
function CMS_ReceiptRequest_create0_ex(id: PIdAnsiChar; idlen: TIdC_INT; allorfirst: TIdC_INT; receiptList: Pstack_st_GENERAL_NAMES; receiptsTo: Pstack_st_GENERAL_NAMES; libctx: POSSL_LIB_CTX): PCMS_ReceiptRequest; cdecl external CLibCrypto name 'CMS_ReceiptRequest_create0_ex';
function CMS_add1_ReceiptRequest(si: PCMS_SignerInfo; rr: PCMS_ReceiptRequest): TIdC_INT; cdecl external CLibCrypto name 'CMS_add1_ReceiptRequest';
function CMS_ReceiptRequest_get0_values(rr: PCMS_ReceiptRequest; pcid: PPASN1_STRING; pallorfirst: PIdC_INT; plist: PPstack_st_GENERAL_NAMES; prto: PPstack_st_GENERAL_NAMES): void; cdecl external CLibCrypto name 'CMS_ReceiptRequest_get0_values';
function CMS_RecipientInfo_kari_get0_alg(ri: PCMS_RecipientInfo; palg: PPX509_ALGOR; pukm: PPASN1_OCTET_STRING): TIdC_INT; cdecl external CLibCrypto name 'CMS_RecipientInfo_kari_get0_alg';
function CMS_RecipientInfo_kari_get0_reks(ri: PCMS_RecipientInfo): Pstack_st_CMS_RecipientEncryptedKey; cdecl external CLibCrypto name 'CMS_RecipientInfo_kari_get0_reks';
function CMS_RecipientInfo_kari_get0_orig_id(ri: PCMS_RecipientInfo; pubalg: PPX509_ALGOR; pubkey: PPASN1_BIT_STRING; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT; cdecl external CLibCrypto name 'CMS_RecipientInfo_kari_get0_orig_id';
function CMS_RecipientInfo_kari_orig_id_cmp(ri: PCMS_RecipientInfo; cert: PX509): TIdC_INT; cdecl external CLibCrypto name 'CMS_RecipientInfo_kari_orig_id_cmp';
function CMS_RecipientEncryptedKey_get0_id(rek: PCMS_RecipientEncryptedKey; keyid: PPASN1_OCTET_STRING; tm: PPASN1_GENERALIZEDTIME; other: PPCMS_OtherKeyAttribute; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT; cdecl external CLibCrypto name 'CMS_RecipientEncryptedKey_get0_id';
function CMS_RecipientEncryptedKey_cert_cmp(rek: PCMS_RecipientEncryptedKey; cert: PX509): TIdC_INT; cdecl external CLibCrypto name 'CMS_RecipientEncryptedKey_cert_cmp';
function CMS_RecipientInfo_kari_set0_pkey(ri: PCMS_RecipientInfo; pk: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'CMS_RecipientInfo_kari_set0_pkey';
function CMS_RecipientInfo_kari_set0_pkey_and_peer(ri: PCMS_RecipientInfo; pk: PEVP_PKEY; peer: PX509): TIdC_INT; cdecl external CLibCrypto name 'CMS_RecipientInfo_kari_set0_pkey_and_peer';
function CMS_RecipientInfo_kari_get0_ctx(ri: PCMS_RecipientInfo): PEVP_CIPHER_CTX; cdecl external CLibCrypto name 'CMS_RecipientInfo_kari_get0_ctx';
function CMS_RecipientInfo_kari_decrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo; rek: PCMS_RecipientEncryptedKey): TIdC_INT; cdecl external CLibCrypto name 'CMS_RecipientInfo_kari_decrypt';
function CMS_SharedInfo_encode(pder: PPIdAnsiChar; kekalg: PX509_ALGOR; ukm: PASN1_OCTET_STRING; keylen: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'CMS_SharedInfo_encode';
function CMS_RecipientInfo_kemri_cert_cmp(ri: PCMS_RecipientInfo; cert: PX509): TIdC_INT; cdecl external CLibCrypto name 'CMS_RecipientInfo_kemri_cert_cmp';
function CMS_RecipientInfo_kemri_set0_pkey(ri: PCMS_RecipientInfo; pk: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'CMS_RecipientInfo_kemri_set0_pkey';
function CMS_RecipientInfo_kemri_get0_ctx(ri: PCMS_RecipientInfo): PEVP_CIPHER_CTX; cdecl external CLibCrypto name 'CMS_RecipientInfo_kemri_get0_ctx';
function CMS_RecipientInfo_kemri_get0_kdf_alg(ri: PCMS_RecipientInfo): PX509_ALGOR; cdecl external CLibCrypto name 'CMS_RecipientInfo_kemri_get0_kdf_alg';
function CMS_RecipientInfo_kemri_set_ukm(ri: PCMS_RecipientInfo; ukm: PIdAnsiChar; ukmLength: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'CMS_RecipientInfo_kemri_set_ukm';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  CMS_EnvelopedData_it_procname = 'CMS_EnvelopedData_it';
  CMS_EnvelopedData_it_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  CMS_SignedData_new_procname = 'CMS_SignedData_new';
  CMS_SignedData_new_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  CMS_SignedData_free_procname = 'CMS_SignedData_free';
  CMS_SignedData_free_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  CMS_ContentInfo_new_procname = 'CMS_ContentInfo_new';
  CMS_ContentInfo_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_ContentInfo_free_procname = 'CMS_ContentInfo_free';
  CMS_ContentInfo_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_CMS_ContentInfo_procname = 'd2i_CMS_ContentInfo';
  d2i_CMS_ContentInfo_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_CMS_ContentInfo_procname = 'i2d_CMS_ContentInfo';
  i2d_CMS_ContentInfo_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_ContentInfo_it_procname = 'CMS_ContentInfo_it';
  CMS_ContentInfo_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_ReceiptRequest_new_procname = 'CMS_ReceiptRequest_new';
  CMS_ReceiptRequest_new_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_ReceiptRequest_free_procname = 'CMS_ReceiptRequest_free';
  CMS_ReceiptRequest_free_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_CMS_ReceiptRequest_procname = 'd2i_CMS_ReceiptRequest';
  d2i_CMS_ReceiptRequest_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_CMS_ReceiptRequest_procname = 'i2d_CMS_ReceiptRequest';
  i2d_CMS_ReceiptRequest_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_ReceiptRequest_it_procname = 'CMS_ReceiptRequest_it';
  CMS_ReceiptRequest_it_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_ContentInfo_print_ctx_procname = 'CMS_ContentInfo_print_ctx';
  CMS_ContentInfo_print_ctx_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_EnvelopedData_dup_procname = 'CMS_EnvelopedData_dup';
  CMS_EnvelopedData_dup_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  CMS_ContentInfo_new_ex_procname = 'CMS_ContentInfo_new_ex';
  CMS_ContentInfo_new_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CMS_get0_type_procname = 'CMS_get0_type';
  CMS_get0_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_dataInit_procname = 'CMS_dataInit';
  CMS_dataInit_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_dataFinal_procname = 'CMS_dataFinal';
  CMS_dataFinal_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_get0_content_procname = 'CMS_get0_content';
  CMS_get0_content_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_is_detached_procname = 'CMS_is_detached';
  CMS_is_detached_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_set_detached_procname = 'CMS_set_detached';
  CMS_set_detached_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_stream_procname = 'CMS_stream';
  CMS_stream_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  d2i_CMS_bio_procname = 'd2i_CMS_bio';
  d2i_CMS_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_CMS_bio_procname = 'i2d_CMS_bio';
  i2d_CMS_bio_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  BIO_new_CMS_procname = 'BIO_new_CMS';
  BIO_new_CMS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  i2d_CMS_bio_stream_procname = 'i2d_CMS_bio_stream';
  i2d_CMS_bio_stream_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  PEM_write_bio_CMS_stream_procname = 'PEM_write_bio_CMS_stream';
  PEM_write_bio_CMS_stream_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SMIME_read_CMS_procname = 'SMIME_read_CMS';
  SMIME_read_CMS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  SMIME_read_CMS_ex_procname = 'SMIME_read_CMS_ex';
  SMIME_read_CMS_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  SMIME_write_CMS_procname = 'SMIME_write_CMS';
  SMIME_write_CMS_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_final_procname = 'CMS_final';
  CMS_final_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_final_digest_procname = 'CMS_final_digest';
  CMS_final_digest_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  CMS_sign_procname = 'CMS_sign';
  CMS_sign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_sign_ex_procname = 'CMS_sign_ex';
  CMS_sign_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CMS_sign_receipt_procname = 'CMS_sign_receipt';
  CMS_sign_receipt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_data_procname = 'CMS_data';
  CMS_data_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_data_create_procname = 'CMS_data_create';
  CMS_data_create_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_data_create_ex_procname = 'CMS_data_create_ex';
  CMS_data_create_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CMS_digest_verify_procname = 'CMS_digest_verify';
  CMS_digest_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_digest_create_procname = 'CMS_digest_create';
  CMS_digest_create_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_digest_create_ex_procname = 'CMS_digest_create_ex';
  CMS_digest_create_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CMS_EncryptedData_decrypt_procname = 'CMS_EncryptedData_decrypt';
  CMS_EncryptedData_decrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_EncryptedData_encrypt_procname = 'CMS_EncryptedData_encrypt';
  CMS_EncryptedData_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_EncryptedData_encrypt_ex_procname = 'CMS_EncryptedData_encrypt_ex';
  CMS_EncryptedData_encrypt_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CMS_EncryptedData_set1_key_procname = 'CMS_EncryptedData_set1_key';
  CMS_EncryptedData_set1_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_verify_procname = 'CMS_verify';
  CMS_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_verify_receipt_procname = 'CMS_verify_receipt';
  CMS_verify_receipt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_get0_signers_procname = 'CMS_get0_signers';
  CMS_get0_signers_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_encrypt_procname = 'CMS_encrypt';
  CMS_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_encrypt_ex_procname = 'CMS_encrypt_ex';
  CMS_encrypt_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CMS_decrypt_procname = 'CMS_decrypt';
  CMS_decrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_decrypt_set1_pkey_procname = 'CMS_decrypt_set1_pkey';
  CMS_decrypt_set1_pkey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_decrypt_set1_pkey_and_peer_procname = 'CMS_decrypt_set1_pkey_and_peer';
  CMS_decrypt_set1_pkey_and_peer_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CMS_decrypt_set1_key_procname = 'CMS_decrypt_set1_key';
  CMS_decrypt_set1_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_decrypt_set1_password_procname = 'CMS_decrypt_set1_password';
  CMS_decrypt_set1_password_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_get0_RecipientInfos_procname = 'CMS_get0_RecipientInfos';
  CMS_get0_RecipientInfos_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_RecipientInfo_type_procname = 'CMS_RecipientInfo_type';
  CMS_RecipientInfo_type_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_RecipientInfo_get0_pkey_ctx_procname = 'CMS_RecipientInfo_get0_pkey_ctx';
  CMS_RecipientInfo_get0_pkey_ctx_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_AuthEnvelopedData_create_procname = 'CMS_AuthEnvelopedData_create';
  CMS_AuthEnvelopedData_create_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CMS_AuthEnvelopedData_create_ex_procname = 'CMS_AuthEnvelopedData_create_ex';
  CMS_AuthEnvelopedData_create_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CMS_EnvelopedData_create_procname = 'CMS_EnvelopedData_create';
  CMS_EnvelopedData_create_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_EnvelopedData_create_ex_procname = 'CMS_EnvelopedData_create_ex';
  CMS_EnvelopedData_create_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CMS_EnvelopedData_decrypt_procname = 'CMS_EnvelopedData_decrypt';
  CMS_EnvelopedData_decrypt_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  CMS_add1_recipient_cert_procname = 'CMS_add1_recipient_cert';
  CMS_add1_recipient_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_add1_recipient_procname = 'CMS_add1_recipient';
  CMS_add1_recipient_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CMS_RecipientInfo_set0_pkey_procname = 'CMS_RecipientInfo_set0_pkey';
  CMS_RecipientInfo_set0_pkey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_RecipientInfo_ktri_cert_cmp_procname = 'CMS_RecipientInfo_ktri_cert_cmp';
  CMS_RecipientInfo_ktri_cert_cmp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_RecipientInfo_ktri_get0_algs_procname = 'CMS_RecipientInfo_ktri_get0_algs';
  CMS_RecipientInfo_ktri_get0_algs_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_RecipientInfo_ktri_get0_signer_id_procname = 'CMS_RecipientInfo_ktri_get0_signer_id';
  CMS_RecipientInfo_ktri_get0_signer_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_add0_recipient_key_procname = 'CMS_add0_recipient_key';
  CMS_add0_recipient_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_RecipientInfo_kekri_get0_id_procname = 'CMS_RecipientInfo_kekri_get0_id';
  CMS_RecipientInfo_kekri_get0_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_RecipientInfo_set0_key_procname = 'CMS_RecipientInfo_set0_key';
  CMS_RecipientInfo_set0_key_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_RecipientInfo_kekri_id_cmp_procname = 'CMS_RecipientInfo_kekri_id_cmp';
  CMS_RecipientInfo_kekri_id_cmp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_RecipientInfo_set0_password_procname = 'CMS_RecipientInfo_set0_password';
  CMS_RecipientInfo_set0_password_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_add0_recipient_password_procname = 'CMS_add0_recipient_password';
  CMS_add0_recipient_password_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_RecipientInfo_decrypt_procname = 'CMS_RecipientInfo_decrypt';
  CMS_RecipientInfo_decrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_RecipientInfo_encrypt_procname = 'CMS_RecipientInfo_encrypt';
  CMS_RecipientInfo_encrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_uncompress_procname = 'CMS_uncompress';
  CMS_uncompress_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_compress_procname = 'CMS_compress';
  CMS_compress_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_set1_eContentType_procname = 'CMS_set1_eContentType';
  CMS_set1_eContentType_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_get0_eContentType_procname = 'CMS_get0_eContentType';
  CMS_get0_eContentType_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_add0_CertificateChoices_procname = 'CMS_add0_CertificateChoices';
  CMS_add0_CertificateChoices_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_add0_cert_procname = 'CMS_add0_cert';
  CMS_add0_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_add1_cert_procname = 'CMS_add1_cert';
  CMS_add1_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_get1_certs_procname = 'CMS_get1_certs';
  CMS_get1_certs_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_add0_RevocationInfoChoice_procname = 'CMS_add0_RevocationInfoChoice';
  CMS_add0_RevocationInfoChoice_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_add0_crl_procname = 'CMS_add0_crl';
  CMS_add0_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_add1_crl_procname = 'CMS_add1_crl';
  CMS_add1_crl_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_get1_crls_procname = 'CMS_get1_crls';
  CMS_get1_crls_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_SignedData_init_procname = 'CMS_SignedData_init';
  CMS_SignedData_init_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_add1_signer_procname = 'CMS_add1_signer';
  CMS_add1_signer_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_SignerInfo_get0_pkey_ctx_procname = 'CMS_SignerInfo_get0_pkey_ctx';
  CMS_SignerInfo_get0_pkey_ctx_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_SignerInfo_get0_md_ctx_procname = 'CMS_SignerInfo_get0_md_ctx';
  CMS_SignerInfo_get0_md_ctx_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_get0_SignerInfos_procname = 'CMS_get0_SignerInfos';
  CMS_get0_SignerInfos_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_SignerInfo_set1_signer_cert_procname = 'CMS_SignerInfo_set1_signer_cert';
  CMS_SignerInfo_set1_signer_cert_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_SignerInfo_get0_signer_id_procname = 'CMS_SignerInfo_get0_signer_id';
  CMS_SignerInfo_get0_signer_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_SignerInfo_cert_cmp_procname = 'CMS_SignerInfo_cert_cmp';
  CMS_SignerInfo_cert_cmp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_set1_signers_certs_procname = 'CMS_set1_signers_certs';
  CMS_set1_signers_certs_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_SignerInfo_get0_algs_procname = 'CMS_SignerInfo_get0_algs';
  CMS_SignerInfo_get0_algs_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_SignerInfo_get0_signature_procname = 'CMS_SignerInfo_get0_signature';
  CMS_SignerInfo_get0_signature_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_SignerInfo_sign_procname = 'CMS_SignerInfo_sign';
  CMS_SignerInfo_sign_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_SignerInfo_verify_procname = 'CMS_SignerInfo_verify';
  CMS_SignerInfo_verify_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_SignerInfo_verify_content_procname = 'CMS_SignerInfo_verify_content';
  CMS_SignerInfo_verify_content_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_SignedData_verify_procname = 'CMS_SignedData_verify';
  CMS_SignedData_verify_introduced = (byte(3) shl 8 or byte(2)) shl 8 or byte(0);

  CMS_add_smimecap_procname = 'CMS_add_smimecap';
  CMS_add_smimecap_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_add_simple_smimecap_procname = 'CMS_add_simple_smimecap';
  CMS_add_simple_smimecap_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_add_standard_smimecap_procname = 'CMS_add_standard_smimecap';
  CMS_add_standard_smimecap_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_signed_get_attr_count_procname = 'CMS_signed_get_attr_count';
  CMS_signed_get_attr_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_signed_get_attr_by_NID_procname = 'CMS_signed_get_attr_by_NID';
  CMS_signed_get_attr_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_signed_get_attr_by_OBJ_procname = 'CMS_signed_get_attr_by_OBJ';
  CMS_signed_get_attr_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_signed_get_attr_procname = 'CMS_signed_get_attr';
  CMS_signed_get_attr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_signed_delete_attr_procname = 'CMS_signed_delete_attr';
  CMS_signed_delete_attr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_signed_add1_attr_procname = 'CMS_signed_add1_attr';
  CMS_signed_add1_attr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_signed_add1_attr_by_OBJ_procname = 'CMS_signed_add1_attr_by_OBJ';
  CMS_signed_add1_attr_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_signed_add1_attr_by_NID_procname = 'CMS_signed_add1_attr_by_NID';
  CMS_signed_add1_attr_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_signed_add1_attr_by_txt_procname = 'CMS_signed_add1_attr_by_txt';
  CMS_signed_add1_attr_by_txt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_signed_get0_data_by_OBJ_procname = 'CMS_signed_get0_data_by_OBJ';
  CMS_signed_get0_data_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_unsigned_get_attr_count_procname = 'CMS_unsigned_get_attr_count';
  CMS_unsigned_get_attr_count_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_unsigned_get_attr_by_NID_procname = 'CMS_unsigned_get_attr_by_NID';
  CMS_unsigned_get_attr_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_unsigned_get_attr_by_OBJ_procname = 'CMS_unsigned_get_attr_by_OBJ';
  CMS_unsigned_get_attr_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_unsigned_get_attr_procname = 'CMS_unsigned_get_attr';
  CMS_unsigned_get_attr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_unsigned_delete_attr_procname = 'CMS_unsigned_delete_attr';
  CMS_unsigned_delete_attr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_unsigned_add1_attr_procname = 'CMS_unsigned_add1_attr';
  CMS_unsigned_add1_attr_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_unsigned_add1_attr_by_OBJ_procname = 'CMS_unsigned_add1_attr_by_OBJ';
  CMS_unsigned_add1_attr_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_unsigned_add1_attr_by_NID_procname = 'CMS_unsigned_add1_attr_by_NID';
  CMS_unsigned_add1_attr_by_NID_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_unsigned_add1_attr_by_txt_procname = 'CMS_unsigned_add1_attr_by_txt';
  CMS_unsigned_add1_attr_by_txt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_unsigned_get0_data_by_OBJ_procname = 'CMS_unsigned_get0_data_by_OBJ';
  CMS_unsigned_get0_data_by_OBJ_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_get1_ReceiptRequest_procname = 'CMS_get1_ReceiptRequest';
  CMS_get1_ReceiptRequest_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_ReceiptRequest_create0_procname = 'CMS_ReceiptRequest_create0';
  CMS_ReceiptRequest_create0_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_ReceiptRequest_create0_ex_procname = 'CMS_ReceiptRequest_create0_ex';
  CMS_ReceiptRequest_create0_ex_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CMS_add1_ReceiptRequest_procname = 'CMS_add1_ReceiptRequest';
  CMS_add1_ReceiptRequest_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_ReceiptRequest_get0_values_procname = 'CMS_ReceiptRequest_get0_values';
  CMS_ReceiptRequest_get0_values_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_RecipientInfo_kari_get0_alg_procname = 'CMS_RecipientInfo_kari_get0_alg';
  CMS_RecipientInfo_kari_get0_alg_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_RecipientInfo_kari_get0_reks_procname = 'CMS_RecipientInfo_kari_get0_reks';
  CMS_RecipientInfo_kari_get0_reks_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_RecipientInfo_kari_get0_orig_id_procname = 'CMS_RecipientInfo_kari_get0_orig_id';
  CMS_RecipientInfo_kari_get0_orig_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_RecipientInfo_kari_orig_id_cmp_procname = 'CMS_RecipientInfo_kari_orig_id_cmp';
  CMS_RecipientInfo_kari_orig_id_cmp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_RecipientEncryptedKey_get0_id_procname = 'CMS_RecipientEncryptedKey_get0_id';
  CMS_RecipientEncryptedKey_get0_id_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_RecipientEncryptedKey_cert_cmp_procname = 'CMS_RecipientEncryptedKey_cert_cmp';
  CMS_RecipientEncryptedKey_cert_cmp_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_RecipientInfo_kari_set0_pkey_procname = 'CMS_RecipientInfo_kari_set0_pkey';
  CMS_RecipientInfo_kari_set0_pkey_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_RecipientInfo_kari_set0_pkey_and_peer_procname = 'CMS_RecipientInfo_kari_set0_pkey_and_peer';
  CMS_RecipientInfo_kari_set0_pkey_and_peer_introduced = (byte(3) shl 8 or byte(0)) shl 8 or byte(0);

  CMS_RecipientInfo_kari_get0_ctx_procname = 'CMS_RecipientInfo_kari_get0_ctx';
  CMS_RecipientInfo_kari_get0_ctx_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_RecipientInfo_kari_decrypt_procname = 'CMS_RecipientInfo_kari_decrypt';
  CMS_RecipientInfo_kari_decrypt_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_SharedInfo_encode_procname = 'CMS_SharedInfo_encode';
  CMS_SharedInfo_encode_introduced = (byte(1) shl 8 or byte(1)) shl 8 or byte(0);

  CMS_RecipientInfo_kemri_cert_cmp_procname = 'CMS_RecipientInfo_kemri_cert_cmp';
  CMS_RecipientInfo_kemri_cert_cmp_introduced = (byte(3) shl 8 or byte(6)) shl 8 or byte(0);

  CMS_RecipientInfo_kemri_set0_pkey_procname = 'CMS_RecipientInfo_kemri_set0_pkey';
  CMS_RecipientInfo_kemri_set0_pkey_introduced = (byte(3) shl 8 or byte(6)) shl 8 or byte(0);

  CMS_RecipientInfo_kemri_get0_ctx_procname = 'CMS_RecipientInfo_kemri_get0_ctx';
  CMS_RecipientInfo_kemri_get0_ctx_introduced = (byte(3) shl 8 or byte(6)) shl 8 or byte(0);

  CMS_RecipientInfo_kemri_get0_kdf_alg_procname = 'CMS_RecipientInfo_kemri_get0_kdf_alg';
  CMS_RecipientInfo_kemri_get0_kdf_alg_introduced = (byte(3) shl 8 or byte(6)) shl 8 or byte(0);

  CMS_RecipientInfo_kemri_set_ukm_procname = 'CMS_RecipientInfo_kemri_set_ukm';
  CMS_RecipientInfo_kemri_set_ukm_introduced = (byte(3) shl 8 or byte(6)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_CMS_EnvelopedData_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_EnvelopedData_it_procname);
end;

function ERR_CMS_SignedData_new: PCMS_SignedData; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_SignedData_new_procname);
end;

function ERR_CMS_SignedData_free(a: PCMS_SignedData): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_SignedData_free_procname);
end;

function ERR_CMS_ContentInfo_new: PCMS_ContentInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_ContentInfo_new_procname);
end;

function ERR_CMS_ContentInfo_free(a: PCMS_ContentInfo): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_ContentInfo_free_procname);
end;

function ERR_d2i_CMS_ContentInfo(a: PPCMS_ContentInfo; _in: PPIdAnsiChar; len: TIdC_LONG): PCMS_ContentInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_CMS_ContentInfo_procname);
end;

function ERR_i2d_CMS_ContentInfo(a: PCMS_ContentInfo; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_CMS_ContentInfo_procname);
end;

function ERR_CMS_ContentInfo_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_ContentInfo_it_procname);
end;

function ERR_CMS_ReceiptRequest_new: PCMS_ReceiptRequest; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_ReceiptRequest_new_procname);
end;

function ERR_CMS_ReceiptRequest_free(a: PCMS_ReceiptRequest): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_ReceiptRequest_free_procname);
end;

function ERR_d2i_CMS_ReceiptRequest(a: PPCMS_ReceiptRequest; _in: PPIdAnsiChar; len: TIdC_LONG): PCMS_ReceiptRequest; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_CMS_ReceiptRequest_procname);
end;

function ERR_i2d_CMS_ReceiptRequest(a: PCMS_ReceiptRequest; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_CMS_ReceiptRequest_procname);
end;

function ERR_CMS_ReceiptRequest_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_ReceiptRequest_it_procname);
end;

function ERR_CMS_ContentInfo_print_ctx(_out: PBIO; x: PCMS_ContentInfo; indent: TIdC_INT; pctx: PASN1_PCTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_ContentInfo_print_ctx_procname);
end;

function ERR_CMS_EnvelopedData_dup(a: PCMS_EnvelopedData): PCMS_EnvelopedData; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_EnvelopedData_dup_procname);
end;

function ERR_CMS_ContentInfo_new_ex(libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_ContentInfo_new_ex_procname);
end;

function ERR_CMS_get0_type(cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_get0_type_procname);
end;

function ERR_CMS_dataInit(cms: PCMS_ContentInfo; icont: PBIO): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_dataInit_procname);
end;

function ERR_CMS_dataFinal(cms: PCMS_ContentInfo; bio: PBIO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_dataFinal_procname);
end;

function ERR_CMS_get0_content(cms: PCMS_ContentInfo): PPASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_get0_content_procname);
end;

function ERR_CMS_is_detached(cms: PCMS_ContentInfo): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_is_detached_procname);
end;

function ERR_CMS_set_detached(cms: PCMS_ContentInfo; detached: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_set_detached_procname);
end;

function ERR_CMS_stream(boundary: PPPIdAnsiChar; cms: PCMS_ContentInfo): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_stream_procname);
end;

function ERR_d2i_CMS_bio(bp: PBIO; cms: PPCMS_ContentInfo): PCMS_ContentInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_CMS_bio_procname);
end;

function ERR_i2d_CMS_bio(bp: PBIO; cms: PCMS_ContentInfo): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_CMS_bio_procname);
end;

function ERR_BIO_new_CMS(_out: PBIO; cms: PCMS_ContentInfo): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BIO_new_CMS_procname);
end;

function ERR_i2d_CMS_bio_stream(_out: PBIO; cms: PCMS_ContentInfo; _in: PBIO; flags: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_CMS_bio_stream_procname);
end;

function ERR_PEM_write_bio_CMS_stream(_out: PBIO; cms: PCMS_ContentInfo; _in: PBIO; flags: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_CMS_stream_procname);
end;

function ERR_SMIME_read_CMS(bio: PBIO; bcont: PPBIO): PCMS_ContentInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SMIME_read_CMS_procname);
end;

function ERR_SMIME_read_CMS_ex(bio: PBIO; flags: TIdC_INT; bcont: PPBIO; ci: PPCMS_ContentInfo): PCMS_ContentInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SMIME_read_CMS_ex_procname);
end;

function ERR_SMIME_write_CMS(bio: PBIO; cms: PCMS_ContentInfo; data: PBIO; flags: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(SMIME_write_CMS_procname);
end;

function ERR_CMS_final(cms: PCMS_ContentInfo; data: PBIO; dcont: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_final_procname);
end;

function ERR_CMS_final_digest(cms: PCMS_ContentInfo; md: PIdAnsiChar; mdlen: TIdC_UINT; dcont: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_final_digest_procname);
end;

function ERR_CMS_sign(signcert: PX509; pkey: PEVP_PKEY; certs: Pstack_st_X509; data: PBIO; flags: TIdC_UINT): PCMS_ContentInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_sign_procname);
end;

function ERR_CMS_sign_ex(signcert: PX509; pkey: PEVP_PKEY; certs: Pstack_st_X509; data: PBIO; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_sign_ex_procname);
end;

function ERR_CMS_sign_receipt(si: PCMS_SignerInfo; signcert: PX509; pkey: PEVP_PKEY; certs: Pstack_st_X509; flags: TIdC_UINT): PCMS_ContentInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_sign_receipt_procname);
end;

function ERR_CMS_data(cms: PCMS_ContentInfo; _out: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_data_procname);
end;

function ERR_CMS_data_create(_in: PBIO; flags: TIdC_UINT): PCMS_ContentInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_data_create_procname);
end;

function ERR_CMS_data_create_ex(_in: PBIO; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_data_create_ex_procname);
end;

function ERR_CMS_digest_verify(cms: PCMS_ContentInfo; dcont: PBIO; _out: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_digest_verify_procname);
end;

function ERR_CMS_digest_create(_in: PBIO; md: PEVP_MD; flags: TIdC_UINT): PCMS_ContentInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_digest_create_procname);
end;

function ERR_CMS_digest_create_ex(_in: PBIO; md: PEVP_MD; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_digest_create_ex_procname);
end;

function ERR_CMS_EncryptedData_decrypt(cms: PCMS_ContentInfo; key: PIdAnsiChar; keylen: TIdC_SIZET; dcont: PBIO; _out: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_EncryptedData_decrypt_procname);
end;

function ERR_CMS_EncryptedData_encrypt(_in: PBIO; cipher: PEVP_CIPHER; key: PIdAnsiChar; keylen: TIdC_SIZET; flags: TIdC_UINT): PCMS_ContentInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_EncryptedData_encrypt_procname);
end;

function ERR_CMS_EncryptedData_encrypt_ex(_in: PBIO; cipher: PEVP_CIPHER; key: PIdAnsiChar; keylen: TIdC_SIZET; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_EncryptedData_encrypt_ex_procname);
end;

function ERR_CMS_EncryptedData_set1_key(cms: PCMS_ContentInfo; ciph: PEVP_CIPHER; key: PIdAnsiChar; keylen: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_EncryptedData_set1_key_procname);
end;

function ERR_CMS_verify(cms: PCMS_ContentInfo; certs: Pstack_st_X509; store: PX509_STORE; dcont: PBIO; _out: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_verify_procname);
end;

function ERR_CMS_verify_receipt(rcms: PCMS_ContentInfo; ocms: PCMS_ContentInfo; certs: Pstack_st_X509; store: PX509_STORE; flags: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_verify_receipt_procname);
end;

function ERR_CMS_get0_signers(cms: PCMS_ContentInfo): Pstack_st_X509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_get0_signers_procname);
end;

function ERR_CMS_encrypt(certs: Pstack_st_X509; _in: PBIO; cipher: PEVP_CIPHER; flags: TIdC_UINT): PCMS_ContentInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_encrypt_procname);
end;

function ERR_CMS_encrypt_ex(certs: Pstack_st_X509; _in: PBIO; cipher: PEVP_CIPHER; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_encrypt_ex_procname);
end;

function ERR_CMS_decrypt(cms: PCMS_ContentInfo; pkey: PEVP_PKEY; cert: PX509; dcont: PBIO; _out: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_decrypt_procname);
end;

function ERR_CMS_decrypt_set1_pkey(cms: PCMS_ContentInfo; pk: PEVP_PKEY; cert: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_decrypt_set1_pkey_procname);
end;

function ERR_CMS_decrypt_set1_pkey_and_peer(cms: PCMS_ContentInfo; pk: PEVP_PKEY; cert: PX509; peer: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_decrypt_set1_pkey_and_peer_procname);
end;

function ERR_CMS_decrypt_set1_key(cms: PCMS_ContentInfo; key: PIdAnsiChar; keylen: TIdC_SIZET; id: PIdAnsiChar; idlen: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_decrypt_set1_key_procname);
end;

function ERR_CMS_decrypt_set1_password(cms: PCMS_ContentInfo; pass: PIdAnsiChar; passlen: TIdC_SSIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_decrypt_set1_password_procname);
end;

function ERR_CMS_get0_RecipientInfos(cms: PCMS_ContentInfo): Pstack_st_CMS_RecipientInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_get0_RecipientInfos_procname);
end;

function ERR_CMS_RecipientInfo_type(ri: PCMS_RecipientInfo): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_type_procname);
end;

function ERR_CMS_RecipientInfo_get0_pkey_ctx(ri: PCMS_RecipientInfo): PEVP_PKEY_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_get0_pkey_ctx_procname);
end;

function ERR_CMS_AuthEnvelopedData_create(cipher: PEVP_CIPHER): PCMS_ContentInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_AuthEnvelopedData_create_procname);
end;

function ERR_CMS_AuthEnvelopedData_create_ex(cipher: PEVP_CIPHER; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_AuthEnvelopedData_create_ex_procname);
end;

function ERR_CMS_EnvelopedData_create(cipher: PEVP_CIPHER): PCMS_ContentInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_EnvelopedData_create_procname);
end;

function ERR_CMS_EnvelopedData_create_ex(cipher: PEVP_CIPHER; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PCMS_ContentInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_EnvelopedData_create_ex_procname);
end;

function ERR_CMS_EnvelopedData_decrypt(env: PCMS_EnvelopedData; detached_data: PBIO; pkey: PEVP_PKEY; cert: PX509; secret: PASN1_OCTET_STRING; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_EnvelopedData_decrypt_procname);
end;

function ERR_CMS_add1_recipient_cert(cms: PCMS_ContentInfo; recip: PX509; flags: TIdC_UINT): PCMS_RecipientInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_add1_recipient_cert_procname);
end;

function ERR_CMS_add1_recipient(cms: PCMS_ContentInfo; recip: PX509; originatorPrivKey: PEVP_PKEY; originator: PX509; flags: TIdC_UINT): PCMS_RecipientInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_add1_recipient_procname);
end;

function ERR_CMS_RecipientInfo_set0_pkey(ri: PCMS_RecipientInfo; pkey: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_set0_pkey_procname);
end;

function ERR_CMS_RecipientInfo_ktri_cert_cmp(ri: PCMS_RecipientInfo; cert: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_ktri_cert_cmp_procname);
end;

function ERR_CMS_RecipientInfo_ktri_get0_algs(ri: PCMS_RecipientInfo; pk: PPEVP_PKEY; recip: PPX509; palg: PPX509_ALGOR): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_ktri_get0_algs_procname);
end;

function ERR_CMS_RecipientInfo_ktri_get0_signer_id(ri: PCMS_RecipientInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_ktri_get0_signer_id_procname);
end;

function ERR_CMS_add0_recipient_key(cms: PCMS_ContentInfo; nid: TIdC_INT; key: PIdAnsiChar; keylen: TIdC_SIZET; id: PIdAnsiChar; idlen: TIdC_SIZET; date: PASN1_GENERALIZEDTIME; otherTypeId: PASN1_OBJECT; otherType: PASN1_TYPE): PCMS_RecipientInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_add0_recipient_key_procname);
end;

function ERR_CMS_RecipientInfo_kekri_get0_id(ri: PCMS_RecipientInfo; palg: PPX509_ALGOR; pid: PPASN1_OCTET_STRING; pdate: PPASN1_GENERALIZEDTIME; potherid: PPASN1_OBJECT; pothertype: PPASN1_TYPE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_kekri_get0_id_procname);
end;

function ERR_CMS_RecipientInfo_set0_key(ri: PCMS_RecipientInfo; key: PIdAnsiChar; keylen: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_set0_key_procname);
end;

function ERR_CMS_RecipientInfo_kekri_id_cmp(ri: PCMS_RecipientInfo; id: PIdAnsiChar; idlen: TIdC_SIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_kekri_id_cmp_procname);
end;

function ERR_CMS_RecipientInfo_set0_password(ri: PCMS_RecipientInfo; pass: PIdAnsiChar; passlen: TIdC_SSIZET): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_set0_password_procname);
end;

function ERR_CMS_add0_recipient_password(cms: PCMS_ContentInfo; iter: TIdC_INT; wrap_nid: TIdC_INT; pbe_nid: TIdC_INT; pass: PIdAnsiChar; passlen: TIdC_SSIZET; kekciph: PEVP_CIPHER): PCMS_RecipientInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_add0_recipient_password_procname);
end;

function ERR_CMS_RecipientInfo_decrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_decrypt_procname);
end;

function ERR_CMS_RecipientInfo_encrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_encrypt_procname);
end;

function ERR_CMS_uncompress(cms: PCMS_ContentInfo; dcont: PBIO; _out: PBIO; flags: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_uncompress_procname);
end;

function ERR_CMS_compress(_in: PBIO; comp_nid: TIdC_INT; flags: TIdC_UINT): PCMS_ContentInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_compress_procname);
end;

function ERR_CMS_set1_eContentType(cms: PCMS_ContentInfo; oid: PASN1_OBJECT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_set1_eContentType_procname);
end;

function ERR_CMS_get0_eContentType(cms: PCMS_ContentInfo): PASN1_OBJECT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_get0_eContentType_procname);
end;

function ERR_CMS_add0_CertificateChoices(cms: PCMS_ContentInfo): PCMS_CertificateChoices; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_add0_CertificateChoices_procname);
end;

function ERR_CMS_add0_cert(cms: PCMS_ContentInfo; cert: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_add0_cert_procname);
end;

function ERR_CMS_add1_cert(cms: PCMS_ContentInfo; cert: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_add1_cert_procname);
end;

function ERR_CMS_get1_certs(cms: PCMS_ContentInfo): Pstack_st_X509; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_get1_certs_procname);
end;

function ERR_CMS_add0_RevocationInfoChoice(cms: PCMS_ContentInfo): PCMS_RevocationInfoChoice; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_add0_RevocationInfoChoice_procname);
end;

function ERR_CMS_add0_crl(cms: PCMS_ContentInfo; crl: PX509_CRL): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_add0_crl_procname);
end;

function ERR_CMS_add1_crl(cms: PCMS_ContentInfo; crl: PX509_CRL): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_add1_crl_procname);
end;

function ERR_CMS_get1_crls(cms: PCMS_ContentInfo): Pstack_st_X509_CRL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_get1_crls_procname);
end;

function ERR_CMS_SignedData_init(cms: PCMS_ContentInfo): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_SignedData_init_procname);
end;

function ERR_CMS_add1_signer(cms: PCMS_ContentInfo; signer: PX509; pk: PEVP_PKEY; md: PEVP_MD; flags: TIdC_UINT): PCMS_SignerInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_add1_signer_procname);
end;

function ERR_CMS_SignerInfo_get0_pkey_ctx(si: PCMS_SignerInfo): PEVP_PKEY_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_SignerInfo_get0_pkey_ctx_procname);
end;

function ERR_CMS_SignerInfo_get0_md_ctx(si: PCMS_SignerInfo): PEVP_MD_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_SignerInfo_get0_md_ctx_procname);
end;

function ERR_CMS_get0_SignerInfos(cms: PCMS_ContentInfo): Pstack_st_CMS_SignerInfo; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_get0_SignerInfos_procname);
end;

function ERR_CMS_SignerInfo_set1_signer_cert(si: PCMS_SignerInfo; signer: PX509): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_SignerInfo_set1_signer_cert_procname);
end;

function ERR_CMS_SignerInfo_get0_signer_id(si: PCMS_SignerInfo; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_SignerInfo_get0_signer_id_procname);
end;

function ERR_CMS_SignerInfo_cert_cmp(si: PCMS_SignerInfo; cert: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_SignerInfo_cert_cmp_procname);
end;

function ERR_CMS_set1_signers_certs(cms: PCMS_ContentInfo; certs: Pstack_st_X509; flags: TIdC_UINT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_set1_signers_certs_procname);
end;

function ERR_CMS_SignerInfo_get0_algs(si: PCMS_SignerInfo; pk: PPEVP_PKEY; signer: PPX509; pdig: PPX509_ALGOR; psig: PPX509_ALGOR): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_SignerInfo_get0_algs_procname);
end;

function ERR_CMS_SignerInfo_get0_signature(si: PCMS_SignerInfo): PASN1_OCTET_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_SignerInfo_get0_signature_procname);
end;

function ERR_CMS_SignerInfo_sign(si: PCMS_SignerInfo): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_SignerInfo_sign_procname);
end;

function ERR_CMS_SignerInfo_verify(si: PCMS_SignerInfo): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_SignerInfo_verify_procname);
end;

function ERR_CMS_SignerInfo_verify_content(si: PCMS_SignerInfo; chain: PBIO): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_SignerInfo_verify_content_procname);
end;

function ERR_CMS_SignedData_verify(sd: PCMS_SignedData; detached_data: PBIO; scerts: Pstack_st_X509; store: PX509_STORE; extra: Pstack_st_X509; crls: Pstack_st_X509_CRL; flags: TIdC_UINT; libctx: POSSL_LIB_CTX; propq: PIdAnsiChar): PBIO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_SignedData_verify_procname);
end;

function ERR_CMS_add_smimecap(si: PCMS_SignerInfo; algs: Pstack_st_X509_ALGOR): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_add_smimecap_procname);
end;

function ERR_CMS_add_simple_smimecap(algs: PPstack_st_X509_ALGOR; algnid: TIdC_INT; keysize: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_add_simple_smimecap_procname);
end;

function ERR_CMS_add_standard_smimecap(smcap: PPstack_st_X509_ALGOR): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_add_standard_smimecap_procname);
end;

function ERR_CMS_signed_get_attr_count(si: PCMS_SignerInfo): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_signed_get_attr_count_procname);
end;

function ERR_CMS_signed_get_attr_by_NID(si: PCMS_SignerInfo; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_signed_get_attr_by_NID_procname);
end;

function ERR_CMS_signed_get_attr_by_OBJ(si: PCMS_SignerInfo; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_signed_get_attr_by_OBJ_procname);
end;

function ERR_CMS_signed_get_attr(si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_signed_get_attr_procname);
end;

function ERR_CMS_signed_delete_attr(si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_signed_delete_attr_procname);
end;

function ERR_CMS_signed_add1_attr(si: PCMS_SignerInfo; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_signed_add1_attr_procname);
end;

function ERR_CMS_signed_add1_attr_by_OBJ(si: PCMS_SignerInfo; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_signed_add1_attr_by_OBJ_procname);
end;

function ERR_CMS_signed_add1_attr_by_NID(si: PCMS_SignerInfo; nid: TIdC_INT; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_signed_add1_attr_by_NID_procname);
end;

function ERR_CMS_signed_add1_attr_by_txt(si: PCMS_SignerInfo; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_signed_add1_attr_by_txt_procname);
end;

function ERR_CMS_signed_get0_data_by_OBJ(si: PCMS_SignerInfo; oid: PASN1_OBJECT; lastpos: TIdC_INT; _type: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_signed_get0_data_by_OBJ_procname);
end;

function ERR_CMS_unsigned_get_attr_count(si: PCMS_SignerInfo): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_unsigned_get_attr_count_procname);
end;

function ERR_CMS_unsigned_get_attr_by_NID(si: PCMS_SignerInfo; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_unsigned_get_attr_by_NID_procname);
end;

function ERR_CMS_unsigned_get_attr_by_OBJ(si: PCMS_SignerInfo; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_unsigned_get_attr_by_OBJ_procname);
end;

function ERR_CMS_unsigned_get_attr(si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_unsigned_get_attr_procname);
end;

function ERR_CMS_unsigned_delete_attr(si: PCMS_SignerInfo; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_unsigned_delete_attr_procname);
end;

function ERR_CMS_unsigned_add1_attr(si: PCMS_SignerInfo; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_unsigned_add1_attr_procname);
end;

function ERR_CMS_unsigned_add1_attr_by_OBJ(si: PCMS_SignerInfo; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_unsigned_add1_attr_by_OBJ_procname);
end;

function ERR_CMS_unsigned_add1_attr_by_NID(si: PCMS_SignerInfo; nid: TIdC_INT; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_unsigned_add1_attr_by_NID_procname);
end;

function ERR_CMS_unsigned_add1_attr_by_txt(si: PCMS_SignerInfo; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_unsigned_add1_attr_by_txt_procname);
end;

function ERR_CMS_unsigned_get0_data_by_OBJ(si: PCMS_SignerInfo; oid: PASN1_OBJECT; lastpos: TIdC_INT; _type: TIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_unsigned_get0_data_by_OBJ_procname);
end;

function ERR_CMS_get1_ReceiptRequest(si: PCMS_SignerInfo; prr: PPCMS_ReceiptRequest): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_get1_ReceiptRequest_procname);
end;

function ERR_CMS_ReceiptRequest_create0(id: PIdAnsiChar; idlen: TIdC_INT; allorfirst: TIdC_INT; receiptList: Pstack_st_GENERAL_NAMES; receiptsTo: Pstack_st_GENERAL_NAMES): PCMS_ReceiptRequest; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_ReceiptRequest_create0_procname);
end;

function ERR_CMS_ReceiptRequest_create0_ex(id: PIdAnsiChar; idlen: TIdC_INT; allorfirst: TIdC_INT; receiptList: Pstack_st_GENERAL_NAMES; receiptsTo: Pstack_st_GENERAL_NAMES; libctx: POSSL_LIB_CTX): PCMS_ReceiptRequest; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_ReceiptRequest_create0_ex_procname);
end;

function ERR_CMS_add1_ReceiptRequest(si: PCMS_SignerInfo; rr: PCMS_ReceiptRequest): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_add1_ReceiptRequest_procname);
end;

function ERR_CMS_ReceiptRequest_get0_values(rr: PCMS_ReceiptRequest; pcid: PPASN1_STRING; pallorfirst: PIdC_INT; plist: PPstack_st_GENERAL_NAMES; prto: PPstack_st_GENERAL_NAMES): void; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_ReceiptRequest_get0_values_procname);
end;

function ERR_CMS_RecipientInfo_kari_get0_alg(ri: PCMS_RecipientInfo; palg: PPX509_ALGOR; pukm: PPASN1_OCTET_STRING): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_kari_get0_alg_procname);
end;

function ERR_CMS_RecipientInfo_kari_get0_reks(ri: PCMS_RecipientInfo): Pstack_st_CMS_RecipientEncryptedKey; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_kari_get0_reks_procname);
end;

function ERR_CMS_RecipientInfo_kari_get0_orig_id(ri: PCMS_RecipientInfo; pubalg: PPX509_ALGOR; pubkey: PPASN1_BIT_STRING; keyid: PPASN1_OCTET_STRING; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_kari_get0_orig_id_procname);
end;

function ERR_CMS_RecipientInfo_kari_orig_id_cmp(ri: PCMS_RecipientInfo; cert: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_kari_orig_id_cmp_procname);
end;

function ERR_CMS_RecipientEncryptedKey_get0_id(rek: PCMS_RecipientEncryptedKey; keyid: PPASN1_OCTET_STRING; tm: PPASN1_GENERALIZEDTIME; other: PPCMS_OtherKeyAttribute; issuer: PPX509_NAME; sno: PPASN1_INTEGER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientEncryptedKey_get0_id_procname);
end;

function ERR_CMS_RecipientEncryptedKey_cert_cmp(rek: PCMS_RecipientEncryptedKey; cert: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientEncryptedKey_cert_cmp_procname);
end;

function ERR_CMS_RecipientInfo_kari_set0_pkey(ri: PCMS_RecipientInfo; pk: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_kari_set0_pkey_procname);
end;

function ERR_CMS_RecipientInfo_kari_set0_pkey_and_peer(ri: PCMS_RecipientInfo; pk: PEVP_PKEY; peer: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_kari_set0_pkey_and_peer_procname);
end;

function ERR_CMS_RecipientInfo_kari_get0_ctx(ri: PCMS_RecipientInfo): PEVP_CIPHER_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_kari_get0_ctx_procname);
end;

function ERR_CMS_RecipientInfo_kari_decrypt(cms: PCMS_ContentInfo; ri: PCMS_RecipientInfo; rek: PCMS_RecipientEncryptedKey): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_kari_decrypt_procname);
end;

function ERR_CMS_SharedInfo_encode(pder: PPIdAnsiChar; kekalg: PX509_ALGOR; ukm: PASN1_OCTET_STRING; keylen: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_SharedInfo_encode_procname);
end;

function ERR_CMS_RecipientInfo_kemri_cert_cmp(ri: PCMS_RecipientInfo; cert: PX509): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_kemri_cert_cmp_procname);
end;

function ERR_CMS_RecipientInfo_kemri_set0_pkey(ri: PCMS_RecipientInfo; pk: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_kemri_set0_pkey_procname);
end;

function ERR_CMS_RecipientInfo_kemri_get0_ctx(ri: PCMS_RecipientInfo): PEVP_CIPHER_CTX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_kemri_get0_ctx_procname);
end;

function ERR_CMS_RecipientInfo_kemri_get0_kdf_alg(ri: PCMS_RecipientInfo): PX509_ALGOR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_kemri_get0_kdf_alg_procname);
end;

function ERR_CMS_RecipientInfo_kemri_set_ukm(ri: PCMS_RecipientInfo; ukm: PIdAnsiChar; ukmLength: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(CMS_RecipientInfo_kemri_set_ukm_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  CMS_EnvelopedData_it := LoadLibFunction(ADllHandle, CMS_EnvelopedData_it_procname);
  FuncLoadError := not assigned(CMS_EnvelopedData_it);
  if FuncLoadError then
  begin
    {$if not defined(CMS_EnvelopedData_it_allownil)}
    CMS_EnvelopedData_it := ERR_CMS_EnvelopedData_it;
    {$ifend}
    {$if declared(CMS_EnvelopedData_it_introduced)}
    if LibVersion < CMS_EnvelopedData_it_introduced then
    begin
      {$if declared(FC_CMS_EnvelopedData_it)}
      CMS_EnvelopedData_it := FC_CMS_EnvelopedData_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_EnvelopedData_it_removed)}
    if CMS_EnvelopedData_it_removed <= LibVersion then
    begin
      {$if declared(_CMS_EnvelopedData_it)}
      CMS_EnvelopedData_it := _CMS_EnvelopedData_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_EnvelopedData_it_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_EnvelopedData_it');
    {$ifend}
  end;
  
  CMS_SignedData_new := LoadLibFunction(ADllHandle, CMS_SignedData_new_procname);
  FuncLoadError := not assigned(CMS_SignedData_new);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SignedData_new_allownil)}
    CMS_SignedData_new := ERR_CMS_SignedData_new;
    {$ifend}
    {$if declared(CMS_SignedData_new_introduced)}
    if LibVersion < CMS_SignedData_new_introduced then
    begin
      {$if declared(FC_CMS_SignedData_new)}
      CMS_SignedData_new := FC_CMS_SignedData_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SignedData_new_removed)}
    if CMS_SignedData_new_removed <= LibVersion then
    begin
      {$if declared(_CMS_SignedData_new)}
      CMS_SignedData_new := _CMS_SignedData_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SignedData_new_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SignedData_new');
    {$ifend}
  end;
  
  CMS_SignedData_free := LoadLibFunction(ADllHandle, CMS_SignedData_free_procname);
  FuncLoadError := not assigned(CMS_SignedData_free);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SignedData_free_allownil)}
    CMS_SignedData_free := ERR_CMS_SignedData_free;
    {$ifend}
    {$if declared(CMS_SignedData_free_introduced)}
    if LibVersion < CMS_SignedData_free_introduced then
    begin
      {$if declared(FC_CMS_SignedData_free)}
      CMS_SignedData_free := FC_CMS_SignedData_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SignedData_free_removed)}
    if CMS_SignedData_free_removed <= LibVersion then
    begin
      {$if declared(_CMS_SignedData_free)}
      CMS_SignedData_free := _CMS_SignedData_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SignedData_free_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SignedData_free');
    {$ifend}
  end;
  
  CMS_ContentInfo_new := LoadLibFunction(ADllHandle, CMS_ContentInfo_new_procname);
  FuncLoadError := not assigned(CMS_ContentInfo_new);
  if FuncLoadError then
  begin
    {$if not defined(CMS_ContentInfo_new_allownil)}
    CMS_ContentInfo_new := ERR_CMS_ContentInfo_new;
    {$ifend}
    {$if declared(CMS_ContentInfo_new_introduced)}
    if LibVersion < CMS_ContentInfo_new_introduced then
    begin
      {$if declared(FC_CMS_ContentInfo_new)}
      CMS_ContentInfo_new := FC_CMS_ContentInfo_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_ContentInfo_new_removed)}
    if CMS_ContentInfo_new_removed <= LibVersion then
    begin
      {$if declared(_CMS_ContentInfo_new)}
      CMS_ContentInfo_new := _CMS_ContentInfo_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_ContentInfo_new_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_ContentInfo_new');
    {$ifend}
  end;
  
  CMS_ContentInfo_free := LoadLibFunction(ADllHandle, CMS_ContentInfo_free_procname);
  FuncLoadError := not assigned(CMS_ContentInfo_free);
  if FuncLoadError then
  begin
    {$if not defined(CMS_ContentInfo_free_allownil)}
    CMS_ContentInfo_free := ERR_CMS_ContentInfo_free;
    {$ifend}
    {$if declared(CMS_ContentInfo_free_introduced)}
    if LibVersion < CMS_ContentInfo_free_introduced then
    begin
      {$if declared(FC_CMS_ContentInfo_free)}
      CMS_ContentInfo_free := FC_CMS_ContentInfo_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_ContentInfo_free_removed)}
    if CMS_ContentInfo_free_removed <= LibVersion then
    begin
      {$if declared(_CMS_ContentInfo_free)}
      CMS_ContentInfo_free := _CMS_ContentInfo_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_ContentInfo_free_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_ContentInfo_free');
    {$ifend}
  end;
  
  d2i_CMS_ContentInfo := LoadLibFunction(ADllHandle, d2i_CMS_ContentInfo_procname);
  FuncLoadError := not assigned(d2i_CMS_ContentInfo);
  if FuncLoadError then
  begin
    {$if not defined(d2i_CMS_ContentInfo_allownil)}
    d2i_CMS_ContentInfo := ERR_d2i_CMS_ContentInfo;
    {$ifend}
    {$if declared(d2i_CMS_ContentInfo_introduced)}
    if LibVersion < d2i_CMS_ContentInfo_introduced then
    begin
      {$if declared(FC_d2i_CMS_ContentInfo)}
      d2i_CMS_ContentInfo := FC_d2i_CMS_ContentInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_CMS_ContentInfo_removed)}
    if d2i_CMS_ContentInfo_removed <= LibVersion then
    begin
      {$if declared(_d2i_CMS_ContentInfo)}
      d2i_CMS_ContentInfo := _d2i_CMS_ContentInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_CMS_ContentInfo_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_CMS_ContentInfo');
    {$ifend}
  end;
  
  i2d_CMS_ContentInfo := LoadLibFunction(ADllHandle, i2d_CMS_ContentInfo_procname);
  FuncLoadError := not assigned(i2d_CMS_ContentInfo);
  if FuncLoadError then
  begin
    {$if not defined(i2d_CMS_ContentInfo_allownil)}
    i2d_CMS_ContentInfo := ERR_i2d_CMS_ContentInfo;
    {$ifend}
    {$if declared(i2d_CMS_ContentInfo_introduced)}
    if LibVersion < i2d_CMS_ContentInfo_introduced then
    begin
      {$if declared(FC_i2d_CMS_ContentInfo)}
      i2d_CMS_ContentInfo := FC_i2d_CMS_ContentInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_CMS_ContentInfo_removed)}
    if i2d_CMS_ContentInfo_removed <= LibVersion then
    begin
      {$if declared(_i2d_CMS_ContentInfo)}
      i2d_CMS_ContentInfo := _i2d_CMS_ContentInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_CMS_ContentInfo_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_CMS_ContentInfo');
    {$ifend}
  end;
  
  CMS_ContentInfo_it := LoadLibFunction(ADllHandle, CMS_ContentInfo_it_procname);
  FuncLoadError := not assigned(CMS_ContentInfo_it);
  if FuncLoadError then
  begin
    {$if not defined(CMS_ContentInfo_it_allownil)}
    CMS_ContentInfo_it := ERR_CMS_ContentInfo_it;
    {$ifend}
    {$if declared(CMS_ContentInfo_it_introduced)}
    if LibVersion < CMS_ContentInfo_it_introduced then
    begin
      {$if declared(FC_CMS_ContentInfo_it)}
      CMS_ContentInfo_it := FC_CMS_ContentInfo_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_ContentInfo_it_removed)}
    if CMS_ContentInfo_it_removed <= LibVersion then
    begin
      {$if declared(_CMS_ContentInfo_it)}
      CMS_ContentInfo_it := _CMS_ContentInfo_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_ContentInfo_it_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_ContentInfo_it');
    {$ifend}
  end;
  
  CMS_ReceiptRequest_new := LoadLibFunction(ADllHandle, CMS_ReceiptRequest_new_procname);
  FuncLoadError := not assigned(CMS_ReceiptRequest_new);
  if FuncLoadError then
  begin
    {$if not defined(CMS_ReceiptRequest_new_allownil)}
    CMS_ReceiptRequest_new := ERR_CMS_ReceiptRequest_new;
    {$ifend}
    {$if declared(CMS_ReceiptRequest_new_introduced)}
    if LibVersion < CMS_ReceiptRequest_new_introduced then
    begin
      {$if declared(FC_CMS_ReceiptRequest_new)}
      CMS_ReceiptRequest_new := FC_CMS_ReceiptRequest_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_ReceiptRequest_new_removed)}
    if CMS_ReceiptRequest_new_removed <= LibVersion then
    begin
      {$if declared(_CMS_ReceiptRequest_new)}
      CMS_ReceiptRequest_new := _CMS_ReceiptRequest_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_ReceiptRequest_new_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_ReceiptRequest_new');
    {$ifend}
  end;
  
  CMS_ReceiptRequest_free := LoadLibFunction(ADllHandle, CMS_ReceiptRequest_free_procname);
  FuncLoadError := not assigned(CMS_ReceiptRequest_free);
  if FuncLoadError then
  begin
    {$if not defined(CMS_ReceiptRequest_free_allownil)}
    CMS_ReceiptRequest_free := ERR_CMS_ReceiptRequest_free;
    {$ifend}
    {$if declared(CMS_ReceiptRequest_free_introduced)}
    if LibVersion < CMS_ReceiptRequest_free_introduced then
    begin
      {$if declared(FC_CMS_ReceiptRequest_free)}
      CMS_ReceiptRequest_free := FC_CMS_ReceiptRequest_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_ReceiptRequest_free_removed)}
    if CMS_ReceiptRequest_free_removed <= LibVersion then
    begin
      {$if declared(_CMS_ReceiptRequest_free)}
      CMS_ReceiptRequest_free := _CMS_ReceiptRequest_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_ReceiptRequest_free_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_ReceiptRequest_free');
    {$ifend}
  end;
  
  d2i_CMS_ReceiptRequest := LoadLibFunction(ADllHandle, d2i_CMS_ReceiptRequest_procname);
  FuncLoadError := not assigned(d2i_CMS_ReceiptRequest);
  if FuncLoadError then
  begin
    {$if not defined(d2i_CMS_ReceiptRequest_allownil)}
    d2i_CMS_ReceiptRequest := ERR_d2i_CMS_ReceiptRequest;
    {$ifend}
    {$if declared(d2i_CMS_ReceiptRequest_introduced)}
    if LibVersion < d2i_CMS_ReceiptRequest_introduced then
    begin
      {$if declared(FC_d2i_CMS_ReceiptRequest)}
      d2i_CMS_ReceiptRequest := FC_d2i_CMS_ReceiptRequest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_CMS_ReceiptRequest_removed)}
    if d2i_CMS_ReceiptRequest_removed <= LibVersion then
    begin
      {$if declared(_d2i_CMS_ReceiptRequest)}
      d2i_CMS_ReceiptRequest := _d2i_CMS_ReceiptRequest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_CMS_ReceiptRequest_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_CMS_ReceiptRequest');
    {$ifend}
  end;
  
  i2d_CMS_ReceiptRequest := LoadLibFunction(ADllHandle, i2d_CMS_ReceiptRequest_procname);
  FuncLoadError := not assigned(i2d_CMS_ReceiptRequest);
  if FuncLoadError then
  begin
    {$if not defined(i2d_CMS_ReceiptRequest_allownil)}
    i2d_CMS_ReceiptRequest := ERR_i2d_CMS_ReceiptRequest;
    {$ifend}
    {$if declared(i2d_CMS_ReceiptRequest_introduced)}
    if LibVersion < i2d_CMS_ReceiptRequest_introduced then
    begin
      {$if declared(FC_i2d_CMS_ReceiptRequest)}
      i2d_CMS_ReceiptRequest := FC_i2d_CMS_ReceiptRequest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_CMS_ReceiptRequest_removed)}
    if i2d_CMS_ReceiptRequest_removed <= LibVersion then
    begin
      {$if declared(_i2d_CMS_ReceiptRequest)}
      i2d_CMS_ReceiptRequest := _i2d_CMS_ReceiptRequest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_CMS_ReceiptRequest_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_CMS_ReceiptRequest');
    {$ifend}
  end;
  
  CMS_ReceiptRequest_it := LoadLibFunction(ADllHandle, CMS_ReceiptRequest_it_procname);
  FuncLoadError := not assigned(CMS_ReceiptRequest_it);
  if FuncLoadError then
  begin
    {$if not defined(CMS_ReceiptRequest_it_allownil)}
    CMS_ReceiptRequest_it := ERR_CMS_ReceiptRequest_it;
    {$ifend}
    {$if declared(CMS_ReceiptRequest_it_introduced)}
    if LibVersion < CMS_ReceiptRequest_it_introduced then
    begin
      {$if declared(FC_CMS_ReceiptRequest_it)}
      CMS_ReceiptRequest_it := FC_CMS_ReceiptRequest_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_ReceiptRequest_it_removed)}
    if CMS_ReceiptRequest_it_removed <= LibVersion then
    begin
      {$if declared(_CMS_ReceiptRequest_it)}
      CMS_ReceiptRequest_it := _CMS_ReceiptRequest_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_ReceiptRequest_it_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_ReceiptRequest_it');
    {$ifend}
  end;
  
  CMS_ContentInfo_print_ctx := LoadLibFunction(ADllHandle, CMS_ContentInfo_print_ctx_procname);
  FuncLoadError := not assigned(CMS_ContentInfo_print_ctx);
  if FuncLoadError then
  begin
    {$if not defined(CMS_ContentInfo_print_ctx_allownil)}
    CMS_ContentInfo_print_ctx := ERR_CMS_ContentInfo_print_ctx;
    {$ifend}
    {$if declared(CMS_ContentInfo_print_ctx_introduced)}
    if LibVersion < CMS_ContentInfo_print_ctx_introduced then
    begin
      {$if declared(FC_CMS_ContentInfo_print_ctx)}
      CMS_ContentInfo_print_ctx := FC_CMS_ContentInfo_print_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_ContentInfo_print_ctx_removed)}
    if CMS_ContentInfo_print_ctx_removed <= LibVersion then
    begin
      {$if declared(_CMS_ContentInfo_print_ctx)}
      CMS_ContentInfo_print_ctx := _CMS_ContentInfo_print_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_ContentInfo_print_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_ContentInfo_print_ctx');
    {$ifend}
  end;
  
  CMS_EnvelopedData_dup := LoadLibFunction(ADllHandle, CMS_EnvelopedData_dup_procname);
  FuncLoadError := not assigned(CMS_EnvelopedData_dup);
  if FuncLoadError then
  begin
    {$if not defined(CMS_EnvelopedData_dup_allownil)}
    CMS_EnvelopedData_dup := ERR_CMS_EnvelopedData_dup;
    {$ifend}
    {$if declared(CMS_EnvelopedData_dup_introduced)}
    if LibVersion < CMS_EnvelopedData_dup_introduced then
    begin
      {$if declared(FC_CMS_EnvelopedData_dup)}
      CMS_EnvelopedData_dup := FC_CMS_EnvelopedData_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_EnvelopedData_dup_removed)}
    if CMS_EnvelopedData_dup_removed <= LibVersion then
    begin
      {$if declared(_CMS_EnvelopedData_dup)}
      CMS_EnvelopedData_dup := _CMS_EnvelopedData_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_EnvelopedData_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_EnvelopedData_dup');
    {$ifend}
  end;
  
  CMS_ContentInfo_new_ex := LoadLibFunction(ADllHandle, CMS_ContentInfo_new_ex_procname);
  FuncLoadError := not assigned(CMS_ContentInfo_new_ex);
  if FuncLoadError then
  begin
    {$if not defined(CMS_ContentInfo_new_ex_allownil)}
    CMS_ContentInfo_new_ex := ERR_CMS_ContentInfo_new_ex;
    {$ifend}
    {$if declared(CMS_ContentInfo_new_ex_introduced)}
    if LibVersion < CMS_ContentInfo_new_ex_introduced then
    begin
      {$if declared(FC_CMS_ContentInfo_new_ex)}
      CMS_ContentInfo_new_ex := FC_CMS_ContentInfo_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_ContentInfo_new_ex_removed)}
    if CMS_ContentInfo_new_ex_removed <= LibVersion then
    begin
      {$if declared(_CMS_ContentInfo_new_ex)}
      CMS_ContentInfo_new_ex := _CMS_ContentInfo_new_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_ContentInfo_new_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_ContentInfo_new_ex');
    {$ifend}
  end;
  
  CMS_get0_type := LoadLibFunction(ADllHandle, CMS_get0_type_procname);
  FuncLoadError := not assigned(CMS_get0_type);
  if FuncLoadError then
  begin
    {$if not defined(CMS_get0_type_allownil)}
    CMS_get0_type := ERR_CMS_get0_type;
    {$ifend}
    {$if declared(CMS_get0_type_introduced)}
    if LibVersion < CMS_get0_type_introduced then
    begin
      {$if declared(FC_CMS_get0_type)}
      CMS_get0_type := FC_CMS_get0_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_get0_type_removed)}
    if CMS_get0_type_removed <= LibVersion then
    begin
      {$if declared(_CMS_get0_type)}
      CMS_get0_type := _CMS_get0_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_get0_type_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_get0_type');
    {$ifend}
  end;
  
  CMS_dataInit := LoadLibFunction(ADllHandle, CMS_dataInit_procname);
  FuncLoadError := not assigned(CMS_dataInit);
  if FuncLoadError then
  begin
    {$if not defined(CMS_dataInit_allownil)}
    CMS_dataInit := ERR_CMS_dataInit;
    {$ifend}
    {$if declared(CMS_dataInit_introduced)}
    if LibVersion < CMS_dataInit_introduced then
    begin
      {$if declared(FC_CMS_dataInit)}
      CMS_dataInit := FC_CMS_dataInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_dataInit_removed)}
    if CMS_dataInit_removed <= LibVersion then
    begin
      {$if declared(_CMS_dataInit)}
      CMS_dataInit := _CMS_dataInit;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_dataInit_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_dataInit');
    {$ifend}
  end;
  
  CMS_dataFinal := LoadLibFunction(ADllHandle, CMS_dataFinal_procname);
  FuncLoadError := not assigned(CMS_dataFinal);
  if FuncLoadError then
  begin
    {$if not defined(CMS_dataFinal_allownil)}
    CMS_dataFinal := ERR_CMS_dataFinal;
    {$ifend}
    {$if declared(CMS_dataFinal_introduced)}
    if LibVersion < CMS_dataFinal_introduced then
    begin
      {$if declared(FC_CMS_dataFinal)}
      CMS_dataFinal := FC_CMS_dataFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_dataFinal_removed)}
    if CMS_dataFinal_removed <= LibVersion then
    begin
      {$if declared(_CMS_dataFinal)}
      CMS_dataFinal := _CMS_dataFinal;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_dataFinal_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_dataFinal');
    {$ifend}
  end;
  
  CMS_get0_content := LoadLibFunction(ADllHandle, CMS_get0_content_procname);
  FuncLoadError := not assigned(CMS_get0_content);
  if FuncLoadError then
  begin
    {$if not defined(CMS_get0_content_allownil)}
    CMS_get0_content := ERR_CMS_get0_content;
    {$ifend}
    {$if declared(CMS_get0_content_introduced)}
    if LibVersion < CMS_get0_content_introduced then
    begin
      {$if declared(FC_CMS_get0_content)}
      CMS_get0_content := FC_CMS_get0_content;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_get0_content_removed)}
    if CMS_get0_content_removed <= LibVersion then
    begin
      {$if declared(_CMS_get0_content)}
      CMS_get0_content := _CMS_get0_content;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_get0_content_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_get0_content');
    {$ifend}
  end;
  
  CMS_is_detached := LoadLibFunction(ADllHandle, CMS_is_detached_procname);
  FuncLoadError := not assigned(CMS_is_detached);
  if FuncLoadError then
  begin
    {$if not defined(CMS_is_detached_allownil)}
    CMS_is_detached := ERR_CMS_is_detached;
    {$ifend}
    {$if declared(CMS_is_detached_introduced)}
    if LibVersion < CMS_is_detached_introduced then
    begin
      {$if declared(FC_CMS_is_detached)}
      CMS_is_detached := FC_CMS_is_detached;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_is_detached_removed)}
    if CMS_is_detached_removed <= LibVersion then
    begin
      {$if declared(_CMS_is_detached)}
      CMS_is_detached := _CMS_is_detached;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_is_detached_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_is_detached');
    {$ifend}
  end;
  
  CMS_set_detached := LoadLibFunction(ADllHandle, CMS_set_detached_procname);
  FuncLoadError := not assigned(CMS_set_detached);
  if FuncLoadError then
  begin
    {$if not defined(CMS_set_detached_allownil)}
    CMS_set_detached := ERR_CMS_set_detached;
    {$ifend}
    {$if declared(CMS_set_detached_introduced)}
    if LibVersion < CMS_set_detached_introduced then
    begin
      {$if declared(FC_CMS_set_detached)}
      CMS_set_detached := FC_CMS_set_detached;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_set_detached_removed)}
    if CMS_set_detached_removed <= LibVersion then
    begin
      {$if declared(_CMS_set_detached)}
      CMS_set_detached := _CMS_set_detached;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_set_detached_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_set_detached');
    {$ifend}
  end;
  
  CMS_stream := LoadLibFunction(ADllHandle, CMS_stream_procname);
  FuncLoadError := not assigned(CMS_stream);
  if FuncLoadError then
  begin
    {$if not defined(CMS_stream_allownil)}
    CMS_stream := ERR_CMS_stream;
    {$ifend}
    {$if declared(CMS_stream_introduced)}
    if LibVersion < CMS_stream_introduced then
    begin
      {$if declared(FC_CMS_stream)}
      CMS_stream := FC_CMS_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_stream_removed)}
    if CMS_stream_removed <= LibVersion then
    begin
      {$if declared(_CMS_stream)}
      CMS_stream := _CMS_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_stream_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_stream');
    {$ifend}
  end;
  
  d2i_CMS_bio := LoadLibFunction(ADllHandle, d2i_CMS_bio_procname);
  FuncLoadError := not assigned(d2i_CMS_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_CMS_bio_allownil)}
    d2i_CMS_bio := ERR_d2i_CMS_bio;
    {$ifend}
    {$if declared(d2i_CMS_bio_introduced)}
    if LibVersion < d2i_CMS_bio_introduced then
    begin
      {$if declared(FC_d2i_CMS_bio)}
      d2i_CMS_bio := FC_d2i_CMS_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_CMS_bio_removed)}
    if d2i_CMS_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_CMS_bio)}
      d2i_CMS_bio := _d2i_CMS_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_CMS_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_CMS_bio');
    {$ifend}
  end;
  
  i2d_CMS_bio := LoadLibFunction(ADllHandle, i2d_CMS_bio_procname);
  FuncLoadError := not assigned(i2d_CMS_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_CMS_bio_allownil)}
    i2d_CMS_bio := ERR_i2d_CMS_bio;
    {$ifend}
    {$if declared(i2d_CMS_bio_introduced)}
    if LibVersion < i2d_CMS_bio_introduced then
    begin
      {$if declared(FC_i2d_CMS_bio)}
      i2d_CMS_bio := FC_i2d_CMS_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_CMS_bio_removed)}
    if i2d_CMS_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_CMS_bio)}
      i2d_CMS_bio := _i2d_CMS_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_CMS_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_CMS_bio');
    {$ifend}
  end;
  
  BIO_new_CMS := LoadLibFunction(ADllHandle, BIO_new_CMS_procname);
  FuncLoadError := not assigned(BIO_new_CMS);
  if FuncLoadError then
  begin
    {$if not defined(BIO_new_CMS_allownil)}
    BIO_new_CMS := ERR_BIO_new_CMS;
    {$ifend}
    {$if declared(BIO_new_CMS_introduced)}
    if LibVersion < BIO_new_CMS_introduced then
    begin
      {$if declared(FC_BIO_new_CMS)}
      BIO_new_CMS := FC_BIO_new_CMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BIO_new_CMS_removed)}
    if BIO_new_CMS_removed <= LibVersion then
    begin
      {$if declared(_BIO_new_CMS)}
      BIO_new_CMS := _BIO_new_CMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BIO_new_CMS_allownil)}
    if FuncLoadError then
      AFailed.Add('BIO_new_CMS');
    {$ifend}
  end;
  
  i2d_CMS_bio_stream := LoadLibFunction(ADllHandle, i2d_CMS_bio_stream_procname);
  FuncLoadError := not assigned(i2d_CMS_bio_stream);
  if FuncLoadError then
  begin
    {$if not defined(i2d_CMS_bio_stream_allownil)}
    i2d_CMS_bio_stream := ERR_i2d_CMS_bio_stream;
    {$ifend}
    {$if declared(i2d_CMS_bio_stream_introduced)}
    if LibVersion < i2d_CMS_bio_stream_introduced then
    begin
      {$if declared(FC_i2d_CMS_bio_stream)}
      i2d_CMS_bio_stream := FC_i2d_CMS_bio_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_CMS_bio_stream_removed)}
    if i2d_CMS_bio_stream_removed <= LibVersion then
    begin
      {$if declared(_i2d_CMS_bio_stream)}
      i2d_CMS_bio_stream := _i2d_CMS_bio_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_CMS_bio_stream_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_CMS_bio_stream');
    {$ifend}
  end;
  
  PEM_write_bio_CMS_stream := LoadLibFunction(ADllHandle, PEM_write_bio_CMS_stream_procname);
  FuncLoadError := not assigned(PEM_write_bio_CMS_stream);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_CMS_stream_allownil)}
    PEM_write_bio_CMS_stream := ERR_PEM_write_bio_CMS_stream;
    {$ifend}
    {$if declared(PEM_write_bio_CMS_stream_introduced)}
    if LibVersion < PEM_write_bio_CMS_stream_introduced then
    begin
      {$if declared(FC_PEM_write_bio_CMS_stream)}
      PEM_write_bio_CMS_stream := FC_PEM_write_bio_CMS_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_CMS_stream_removed)}
    if PEM_write_bio_CMS_stream_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_CMS_stream)}
      PEM_write_bio_CMS_stream := _PEM_write_bio_CMS_stream;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_CMS_stream_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_CMS_stream');
    {$ifend}
  end;
  
  SMIME_read_CMS := LoadLibFunction(ADllHandle, SMIME_read_CMS_procname);
  FuncLoadError := not assigned(SMIME_read_CMS);
  if FuncLoadError then
  begin
    {$if not defined(SMIME_read_CMS_allownil)}
    SMIME_read_CMS := ERR_SMIME_read_CMS;
    {$ifend}
    {$if declared(SMIME_read_CMS_introduced)}
    if LibVersion < SMIME_read_CMS_introduced then
    begin
      {$if declared(FC_SMIME_read_CMS)}
      SMIME_read_CMS := FC_SMIME_read_CMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SMIME_read_CMS_removed)}
    if SMIME_read_CMS_removed <= LibVersion then
    begin
      {$if declared(_SMIME_read_CMS)}
      SMIME_read_CMS := _SMIME_read_CMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SMIME_read_CMS_allownil)}
    if FuncLoadError then
      AFailed.Add('SMIME_read_CMS');
    {$ifend}
  end;
  
  SMIME_read_CMS_ex := LoadLibFunction(ADllHandle, SMIME_read_CMS_ex_procname);
  FuncLoadError := not assigned(SMIME_read_CMS_ex);
  if FuncLoadError then
  begin
    {$if not defined(SMIME_read_CMS_ex_allownil)}
    SMIME_read_CMS_ex := ERR_SMIME_read_CMS_ex;
    {$ifend}
    {$if declared(SMIME_read_CMS_ex_introduced)}
    if LibVersion < SMIME_read_CMS_ex_introduced then
    begin
      {$if declared(FC_SMIME_read_CMS_ex)}
      SMIME_read_CMS_ex := FC_SMIME_read_CMS_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SMIME_read_CMS_ex_removed)}
    if SMIME_read_CMS_ex_removed <= LibVersion then
    begin
      {$if declared(_SMIME_read_CMS_ex)}
      SMIME_read_CMS_ex := _SMIME_read_CMS_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SMIME_read_CMS_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('SMIME_read_CMS_ex');
    {$ifend}
  end;
  
  SMIME_write_CMS := LoadLibFunction(ADllHandle, SMIME_write_CMS_procname);
  FuncLoadError := not assigned(SMIME_write_CMS);
  if FuncLoadError then
  begin
    {$if not defined(SMIME_write_CMS_allownil)}
    SMIME_write_CMS := ERR_SMIME_write_CMS;
    {$ifend}
    {$if declared(SMIME_write_CMS_introduced)}
    if LibVersion < SMIME_write_CMS_introduced then
    begin
      {$if declared(FC_SMIME_write_CMS)}
      SMIME_write_CMS := FC_SMIME_write_CMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(SMIME_write_CMS_removed)}
    if SMIME_write_CMS_removed <= LibVersion then
    begin
      {$if declared(_SMIME_write_CMS)}
      SMIME_write_CMS := _SMIME_write_CMS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(SMIME_write_CMS_allownil)}
    if FuncLoadError then
      AFailed.Add('SMIME_write_CMS');
    {$ifend}
  end;
  
  CMS_final := LoadLibFunction(ADllHandle, CMS_final_procname);
  FuncLoadError := not assigned(CMS_final);
  if FuncLoadError then
  begin
    {$if not defined(CMS_final_allownil)}
    CMS_final := ERR_CMS_final;
    {$ifend}
    {$if declared(CMS_final_introduced)}
    if LibVersion < CMS_final_introduced then
    begin
      {$if declared(FC_CMS_final)}
      CMS_final := FC_CMS_final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_final_removed)}
    if CMS_final_removed <= LibVersion then
    begin
      {$if declared(_CMS_final)}
      CMS_final := _CMS_final;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_final_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_final');
    {$ifend}
  end;
  
  CMS_final_digest := LoadLibFunction(ADllHandle, CMS_final_digest_procname);
  FuncLoadError := not assigned(CMS_final_digest);
  if FuncLoadError then
  begin
    {$if not defined(CMS_final_digest_allownil)}
    CMS_final_digest := ERR_CMS_final_digest;
    {$ifend}
    {$if declared(CMS_final_digest_introduced)}
    if LibVersion < CMS_final_digest_introduced then
    begin
      {$if declared(FC_CMS_final_digest)}
      CMS_final_digest := FC_CMS_final_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_final_digest_removed)}
    if CMS_final_digest_removed <= LibVersion then
    begin
      {$if declared(_CMS_final_digest)}
      CMS_final_digest := _CMS_final_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_final_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_final_digest');
    {$ifend}
  end;
  
  CMS_sign := LoadLibFunction(ADllHandle, CMS_sign_procname);
  FuncLoadError := not assigned(CMS_sign);
  if FuncLoadError then
  begin
    {$if not defined(CMS_sign_allownil)}
    CMS_sign := ERR_CMS_sign;
    {$ifend}
    {$if declared(CMS_sign_introduced)}
    if LibVersion < CMS_sign_introduced then
    begin
      {$if declared(FC_CMS_sign)}
      CMS_sign := FC_CMS_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_sign_removed)}
    if CMS_sign_removed <= LibVersion then
    begin
      {$if declared(_CMS_sign)}
      CMS_sign := _CMS_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_sign');
    {$ifend}
  end;
  
  CMS_sign_ex := LoadLibFunction(ADllHandle, CMS_sign_ex_procname);
  FuncLoadError := not assigned(CMS_sign_ex);
  if FuncLoadError then
  begin
    {$if not defined(CMS_sign_ex_allownil)}
    CMS_sign_ex := ERR_CMS_sign_ex;
    {$ifend}
    {$if declared(CMS_sign_ex_introduced)}
    if LibVersion < CMS_sign_ex_introduced then
    begin
      {$if declared(FC_CMS_sign_ex)}
      CMS_sign_ex := FC_CMS_sign_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_sign_ex_removed)}
    if CMS_sign_ex_removed <= LibVersion then
    begin
      {$if declared(_CMS_sign_ex)}
      CMS_sign_ex := _CMS_sign_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_sign_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_sign_ex');
    {$ifend}
  end;
  
  CMS_sign_receipt := LoadLibFunction(ADllHandle, CMS_sign_receipt_procname);
  FuncLoadError := not assigned(CMS_sign_receipt);
  if FuncLoadError then
  begin
    {$if not defined(CMS_sign_receipt_allownil)}
    CMS_sign_receipt := ERR_CMS_sign_receipt;
    {$ifend}
    {$if declared(CMS_sign_receipt_introduced)}
    if LibVersion < CMS_sign_receipt_introduced then
    begin
      {$if declared(FC_CMS_sign_receipt)}
      CMS_sign_receipt := FC_CMS_sign_receipt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_sign_receipt_removed)}
    if CMS_sign_receipt_removed <= LibVersion then
    begin
      {$if declared(_CMS_sign_receipt)}
      CMS_sign_receipt := _CMS_sign_receipt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_sign_receipt_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_sign_receipt');
    {$ifend}
  end;
  
  CMS_data := LoadLibFunction(ADllHandle, CMS_data_procname);
  FuncLoadError := not assigned(CMS_data);
  if FuncLoadError then
  begin
    {$if not defined(CMS_data_allownil)}
    CMS_data := ERR_CMS_data;
    {$ifend}
    {$if declared(CMS_data_introduced)}
    if LibVersion < CMS_data_introduced then
    begin
      {$if declared(FC_CMS_data)}
      CMS_data := FC_CMS_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_data_removed)}
    if CMS_data_removed <= LibVersion then
    begin
      {$if declared(_CMS_data)}
      CMS_data := _CMS_data;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_data_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_data');
    {$ifend}
  end;
  
  CMS_data_create := LoadLibFunction(ADllHandle, CMS_data_create_procname);
  FuncLoadError := not assigned(CMS_data_create);
  if FuncLoadError then
  begin
    {$if not defined(CMS_data_create_allownil)}
    CMS_data_create := ERR_CMS_data_create;
    {$ifend}
    {$if declared(CMS_data_create_introduced)}
    if LibVersion < CMS_data_create_introduced then
    begin
      {$if declared(FC_CMS_data_create)}
      CMS_data_create := FC_CMS_data_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_data_create_removed)}
    if CMS_data_create_removed <= LibVersion then
    begin
      {$if declared(_CMS_data_create)}
      CMS_data_create := _CMS_data_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_data_create_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_data_create');
    {$ifend}
  end;
  
  CMS_data_create_ex := LoadLibFunction(ADllHandle, CMS_data_create_ex_procname);
  FuncLoadError := not assigned(CMS_data_create_ex);
  if FuncLoadError then
  begin
    {$if not defined(CMS_data_create_ex_allownil)}
    CMS_data_create_ex := ERR_CMS_data_create_ex;
    {$ifend}
    {$if declared(CMS_data_create_ex_introduced)}
    if LibVersion < CMS_data_create_ex_introduced then
    begin
      {$if declared(FC_CMS_data_create_ex)}
      CMS_data_create_ex := FC_CMS_data_create_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_data_create_ex_removed)}
    if CMS_data_create_ex_removed <= LibVersion then
    begin
      {$if declared(_CMS_data_create_ex)}
      CMS_data_create_ex := _CMS_data_create_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_data_create_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_data_create_ex');
    {$ifend}
  end;
  
  CMS_digest_verify := LoadLibFunction(ADllHandle, CMS_digest_verify_procname);
  FuncLoadError := not assigned(CMS_digest_verify);
  if FuncLoadError then
  begin
    {$if not defined(CMS_digest_verify_allownil)}
    CMS_digest_verify := ERR_CMS_digest_verify;
    {$ifend}
    {$if declared(CMS_digest_verify_introduced)}
    if LibVersion < CMS_digest_verify_introduced then
    begin
      {$if declared(FC_CMS_digest_verify)}
      CMS_digest_verify := FC_CMS_digest_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_digest_verify_removed)}
    if CMS_digest_verify_removed <= LibVersion then
    begin
      {$if declared(_CMS_digest_verify)}
      CMS_digest_verify := _CMS_digest_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_digest_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_digest_verify');
    {$ifend}
  end;
  
  CMS_digest_create := LoadLibFunction(ADllHandle, CMS_digest_create_procname);
  FuncLoadError := not assigned(CMS_digest_create);
  if FuncLoadError then
  begin
    {$if not defined(CMS_digest_create_allownil)}
    CMS_digest_create := ERR_CMS_digest_create;
    {$ifend}
    {$if declared(CMS_digest_create_introduced)}
    if LibVersion < CMS_digest_create_introduced then
    begin
      {$if declared(FC_CMS_digest_create)}
      CMS_digest_create := FC_CMS_digest_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_digest_create_removed)}
    if CMS_digest_create_removed <= LibVersion then
    begin
      {$if declared(_CMS_digest_create)}
      CMS_digest_create := _CMS_digest_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_digest_create_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_digest_create');
    {$ifend}
  end;
  
  CMS_digest_create_ex := LoadLibFunction(ADllHandle, CMS_digest_create_ex_procname);
  FuncLoadError := not assigned(CMS_digest_create_ex);
  if FuncLoadError then
  begin
    {$if not defined(CMS_digest_create_ex_allownil)}
    CMS_digest_create_ex := ERR_CMS_digest_create_ex;
    {$ifend}
    {$if declared(CMS_digest_create_ex_introduced)}
    if LibVersion < CMS_digest_create_ex_introduced then
    begin
      {$if declared(FC_CMS_digest_create_ex)}
      CMS_digest_create_ex := FC_CMS_digest_create_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_digest_create_ex_removed)}
    if CMS_digest_create_ex_removed <= LibVersion then
    begin
      {$if declared(_CMS_digest_create_ex)}
      CMS_digest_create_ex := _CMS_digest_create_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_digest_create_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_digest_create_ex');
    {$ifend}
  end;
  
  CMS_EncryptedData_decrypt := LoadLibFunction(ADllHandle, CMS_EncryptedData_decrypt_procname);
  FuncLoadError := not assigned(CMS_EncryptedData_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(CMS_EncryptedData_decrypt_allownil)}
    CMS_EncryptedData_decrypt := ERR_CMS_EncryptedData_decrypt;
    {$ifend}
    {$if declared(CMS_EncryptedData_decrypt_introduced)}
    if LibVersion < CMS_EncryptedData_decrypt_introduced then
    begin
      {$if declared(FC_CMS_EncryptedData_decrypt)}
      CMS_EncryptedData_decrypt := FC_CMS_EncryptedData_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_EncryptedData_decrypt_removed)}
    if CMS_EncryptedData_decrypt_removed <= LibVersion then
    begin
      {$if declared(_CMS_EncryptedData_decrypt)}
      CMS_EncryptedData_decrypt := _CMS_EncryptedData_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_EncryptedData_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_EncryptedData_decrypt');
    {$ifend}
  end;
  
  CMS_EncryptedData_encrypt := LoadLibFunction(ADllHandle, CMS_EncryptedData_encrypt_procname);
  FuncLoadError := not assigned(CMS_EncryptedData_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(CMS_EncryptedData_encrypt_allownil)}
    CMS_EncryptedData_encrypt := ERR_CMS_EncryptedData_encrypt;
    {$ifend}
    {$if declared(CMS_EncryptedData_encrypt_introduced)}
    if LibVersion < CMS_EncryptedData_encrypt_introduced then
    begin
      {$if declared(FC_CMS_EncryptedData_encrypt)}
      CMS_EncryptedData_encrypt := FC_CMS_EncryptedData_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_EncryptedData_encrypt_removed)}
    if CMS_EncryptedData_encrypt_removed <= LibVersion then
    begin
      {$if declared(_CMS_EncryptedData_encrypt)}
      CMS_EncryptedData_encrypt := _CMS_EncryptedData_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_EncryptedData_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_EncryptedData_encrypt');
    {$ifend}
  end;
  
  CMS_EncryptedData_encrypt_ex := LoadLibFunction(ADllHandle, CMS_EncryptedData_encrypt_ex_procname);
  FuncLoadError := not assigned(CMS_EncryptedData_encrypt_ex);
  if FuncLoadError then
  begin
    {$if not defined(CMS_EncryptedData_encrypt_ex_allownil)}
    CMS_EncryptedData_encrypt_ex := ERR_CMS_EncryptedData_encrypt_ex;
    {$ifend}
    {$if declared(CMS_EncryptedData_encrypt_ex_introduced)}
    if LibVersion < CMS_EncryptedData_encrypt_ex_introduced then
    begin
      {$if declared(FC_CMS_EncryptedData_encrypt_ex)}
      CMS_EncryptedData_encrypt_ex := FC_CMS_EncryptedData_encrypt_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_EncryptedData_encrypt_ex_removed)}
    if CMS_EncryptedData_encrypt_ex_removed <= LibVersion then
    begin
      {$if declared(_CMS_EncryptedData_encrypt_ex)}
      CMS_EncryptedData_encrypt_ex := _CMS_EncryptedData_encrypt_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_EncryptedData_encrypt_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_EncryptedData_encrypt_ex');
    {$ifend}
  end;
  
  CMS_EncryptedData_set1_key := LoadLibFunction(ADllHandle, CMS_EncryptedData_set1_key_procname);
  FuncLoadError := not assigned(CMS_EncryptedData_set1_key);
  if FuncLoadError then
  begin
    {$if not defined(CMS_EncryptedData_set1_key_allownil)}
    CMS_EncryptedData_set1_key := ERR_CMS_EncryptedData_set1_key;
    {$ifend}
    {$if declared(CMS_EncryptedData_set1_key_introduced)}
    if LibVersion < CMS_EncryptedData_set1_key_introduced then
    begin
      {$if declared(FC_CMS_EncryptedData_set1_key)}
      CMS_EncryptedData_set1_key := FC_CMS_EncryptedData_set1_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_EncryptedData_set1_key_removed)}
    if CMS_EncryptedData_set1_key_removed <= LibVersion then
    begin
      {$if declared(_CMS_EncryptedData_set1_key)}
      CMS_EncryptedData_set1_key := _CMS_EncryptedData_set1_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_EncryptedData_set1_key_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_EncryptedData_set1_key');
    {$ifend}
  end;
  
  CMS_verify := LoadLibFunction(ADllHandle, CMS_verify_procname);
  FuncLoadError := not assigned(CMS_verify);
  if FuncLoadError then
  begin
    {$if not defined(CMS_verify_allownil)}
    CMS_verify := ERR_CMS_verify;
    {$ifend}
    {$if declared(CMS_verify_introduced)}
    if LibVersion < CMS_verify_introduced then
    begin
      {$if declared(FC_CMS_verify)}
      CMS_verify := FC_CMS_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_verify_removed)}
    if CMS_verify_removed <= LibVersion then
    begin
      {$if declared(_CMS_verify)}
      CMS_verify := _CMS_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_verify');
    {$ifend}
  end;
  
  CMS_verify_receipt := LoadLibFunction(ADllHandle, CMS_verify_receipt_procname);
  FuncLoadError := not assigned(CMS_verify_receipt);
  if FuncLoadError then
  begin
    {$if not defined(CMS_verify_receipt_allownil)}
    CMS_verify_receipt := ERR_CMS_verify_receipt;
    {$ifend}
    {$if declared(CMS_verify_receipt_introduced)}
    if LibVersion < CMS_verify_receipt_introduced then
    begin
      {$if declared(FC_CMS_verify_receipt)}
      CMS_verify_receipt := FC_CMS_verify_receipt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_verify_receipt_removed)}
    if CMS_verify_receipt_removed <= LibVersion then
    begin
      {$if declared(_CMS_verify_receipt)}
      CMS_verify_receipt := _CMS_verify_receipt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_verify_receipt_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_verify_receipt');
    {$ifend}
  end;
  
  CMS_get0_signers := LoadLibFunction(ADllHandle, CMS_get0_signers_procname);
  FuncLoadError := not assigned(CMS_get0_signers);
  if FuncLoadError then
  begin
    {$if not defined(CMS_get0_signers_allownil)}
    CMS_get0_signers := ERR_CMS_get0_signers;
    {$ifend}
    {$if declared(CMS_get0_signers_introduced)}
    if LibVersion < CMS_get0_signers_introduced then
    begin
      {$if declared(FC_CMS_get0_signers)}
      CMS_get0_signers := FC_CMS_get0_signers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_get0_signers_removed)}
    if CMS_get0_signers_removed <= LibVersion then
    begin
      {$if declared(_CMS_get0_signers)}
      CMS_get0_signers := _CMS_get0_signers;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_get0_signers_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_get0_signers');
    {$ifend}
  end;
  
  CMS_encrypt := LoadLibFunction(ADllHandle, CMS_encrypt_procname);
  FuncLoadError := not assigned(CMS_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(CMS_encrypt_allownil)}
    CMS_encrypt := ERR_CMS_encrypt;
    {$ifend}
    {$if declared(CMS_encrypt_introduced)}
    if LibVersion < CMS_encrypt_introduced then
    begin
      {$if declared(FC_CMS_encrypt)}
      CMS_encrypt := FC_CMS_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_encrypt_removed)}
    if CMS_encrypt_removed <= LibVersion then
    begin
      {$if declared(_CMS_encrypt)}
      CMS_encrypt := _CMS_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_encrypt');
    {$ifend}
  end;
  
  CMS_encrypt_ex := LoadLibFunction(ADllHandle, CMS_encrypt_ex_procname);
  FuncLoadError := not assigned(CMS_encrypt_ex);
  if FuncLoadError then
  begin
    {$if not defined(CMS_encrypt_ex_allownil)}
    CMS_encrypt_ex := ERR_CMS_encrypt_ex;
    {$ifend}
    {$if declared(CMS_encrypt_ex_introduced)}
    if LibVersion < CMS_encrypt_ex_introduced then
    begin
      {$if declared(FC_CMS_encrypt_ex)}
      CMS_encrypt_ex := FC_CMS_encrypt_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_encrypt_ex_removed)}
    if CMS_encrypt_ex_removed <= LibVersion then
    begin
      {$if declared(_CMS_encrypt_ex)}
      CMS_encrypt_ex := _CMS_encrypt_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_encrypt_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_encrypt_ex');
    {$ifend}
  end;
  
  CMS_decrypt := LoadLibFunction(ADllHandle, CMS_decrypt_procname);
  FuncLoadError := not assigned(CMS_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(CMS_decrypt_allownil)}
    CMS_decrypt := ERR_CMS_decrypt;
    {$ifend}
    {$if declared(CMS_decrypt_introduced)}
    if LibVersion < CMS_decrypt_introduced then
    begin
      {$if declared(FC_CMS_decrypt)}
      CMS_decrypt := FC_CMS_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_decrypt_removed)}
    if CMS_decrypt_removed <= LibVersion then
    begin
      {$if declared(_CMS_decrypt)}
      CMS_decrypt := _CMS_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_decrypt');
    {$ifend}
  end;
  
  CMS_decrypt_set1_pkey := LoadLibFunction(ADllHandle, CMS_decrypt_set1_pkey_procname);
  FuncLoadError := not assigned(CMS_decrypt_set1_pkey);
  if FuncLoadError then
  begin
    {$if not defined(CMS_decrypt_set1_pkey_allownil)}
    CMS_decrypt_set1_pkey := ERR_CMS_decrypt_set1_pkey;
    {$ifend}
    {$if declared(CMS_decrypt_set1_pkey_introduced)}
    if LibVersion < CMS_decrypt_set1_pkey_introduced then
    begin
      {$if declared(FC_CMS_decrypt_set1_pkey)}
      CMS_decrypt_set1_pkey := FC_CMS_decrypt_set1_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_decrypt_set1_pkey_removed)}
    if CMS_decrypt_set1_pkey_removed <= LibVersion then
    begin
      {$if declared(_CMS_decrypt_set1_pkey)}
      CMS_decrypt_set1_pkey := _CMS_decrypt_set1_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_decrypt_set1_pkey_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_decrypt_set1_pkey');
    {$ifend}
  end;
  
  CMS_decrypt_set1_pkey_and_peer := LoadLibFunction(ADllHandle, CMS_decrypt_set1_pkey_and_peer_procname);
  FuncLoadError := not assigned(CMS_decrypt_set1_pkey_and_peer);
  if FuncLoadError then
  begin
    {$if not defined(CMS_decrypt_set1_pkey_and_peer_allownil)}
    CMS_decrypt_set1_pkey_and_peer := ERR_CMS_decrypt_set1_pkey_and_peer;
    {$ifend}
    {$if declared(CMS_decrypt_set1_pkey_and_peer_introduced)}
    if LibVersion < CMS_decrypt_set1_pkey_and_peer_introduced then
    begin
      {$if declared(FC_CMS_decrypt_set1_pkey_and_peer)}
      CMS_decrypt_set1_pkey_and_peer := FC_CMS_decrypt_set1_pkey_and_peer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_decrypt_set1_pkey_and_peer_removed)}
    if CMS_decrypt_set1_pkey_and_peer_removed <= LibVersion then
    begin
      {$if declared(_CMS_decrypt_set1_pkey_and_peer)}
      CMS_decrypt_set1_pkey_and_peer := _CMS_decrypt_set1_pkey_and_peer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_decrypt_set1_pkey_and_peer_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_decrypt_set1_pkey_and_peer');
    {$ifend}
  end;
  
  CMS_decrypt_set1_key := LoadLibFunction(ADllHandle, CMS_decrypt_set1_key_procname);
  FuncLoadError := not assigned(CMS_decrypt_set1_key);
  if FuncLoadError then
  begin
    {$if not defined(CMS_decrypt_set1_key_allownil)}
    CMS_decrypt_set1_key := ERR_CMS_decrypt_set1_key;
    {$ifend}
    {$if declared(CMS_decrypt_set1_key_introduced)}
    if LibVersion < CMS_decrypt_set1_key_introduced then
    begin
      {$if declared(FC_CMS_decrypt_set1_key)}
      CMS_decrypt_set1_key := FC_CMS_decrypt_set1_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_decrypt_set1_key_removed)}
    if CMS_decrypt_set1_key_removed <= LibVersion then
    begin
      {$if declared(_CMS_decrypt_set1_key)}
      CMS_decrypt_set1_key := _CMS_decrypt_set1_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_decrypt_set1_key_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_decrypt_set1_key');
    {$ifend}
  end;
  
  CMS_decrypt_set1_password := LoadLibFunction(ADllHandle, CMS_decrypt_set1_password_procname);
  FuncLoadError := not assigned(CMS_decrypt_set1_password);
  if FuncLoadError then
  begin
    {$if not defined(CMS_decrypt_set1_password_allownil)}
    CMS_decrypt_set1_password := ERR_CMS_decrypt_set1_password;
    {$ifend}
    {$if declared(CMS_decrypt_set1_password_introduced)}
    if LibVersion < CMS_decrypt_set1_password_introduced then
    begin
      {$if declared(FC_CMS_decrypt_set1_password)}
      CMS_decrypt_set1_password := FC_CMS_decrypt_set1_password;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_decrypt_set1_password_removed)}
    if CMS_decrypt_set1_password_removed <= LibVersion then
    begin
      {$if declared(_CMS_decrypt_set1_password)}
      CMS_decrypt_set1_password := _CMS_decrypt_set1_password;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_decrypt_set1_password_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_decrypt_set1_password');
    {$ifend}
  end;
  
  CMS_get0_RecipientInfos := LoadLibFunction(ADllHandle, CMS_get0_RecipientInfos_procname);
  FuncLoadError := not assigned(CMS_get0_RecipientInfos);
  if FuncLoadError then
  begin
    {$if not defined(CMS_get0_RecipientInfos_allownil)}
    CMS_get0_RecipientInfos := ERR_CMS_get0_RecipientInfos;
    {$ifend}
    {$if declared(CMS_get0_RecipientInfos_introduced)}
    if LibVersion < CMS_get0_RecipientInfos_introduced then
    begin
      {$if declared(FC_CMS_get0_RecipientInfos)}
      CMS_get0_RecipientInfos := FC_CMS_get0_RecipientInfos;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_get0_RecipientInfos_removed)}
    if CMS_get0_RecipientInfos_removed <= LibVersion then
    begin
      {$if declared(_CMS_get0_RecipientInfos)}
      CMS_get0_RecipientInfos := _CMS_get0_RecipientInfos;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_get0_RecipientInfos_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_get0_RecipientInfos');
    {$ifend}
  end;
  
  CMS_RecipientInfo_type := LoadLibFunction(ADllHandle, CMS_RecipientInfo_type_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_type);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_type_allownil)}
    CMS_RecipientInfo_type := ERR_CMS_RecipientInfo_type;
    {$ifend}
    {$if declared(CMS_RecipientInfo_type_introduced)}
    if LibVersion < CMS_RecipientInfo_type_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_type)}
      CMS_RecipientInfo_type := FC_CMS_RecipientInfo_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_type_removed)}
    if CMS_RecipientInfo_type_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_type)}
      CMS_RecipientInfo_type := _CMS_RecipientInfo_type;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_type_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_type');
    {$ifend}
  end;
  
  CMS_RecipientInfo_get0_pkey_ctx := LoadLibFunction(ADllHandle, CMS_RecipientInfo_get0_pkey_ctx_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_get0_pkey_ctx);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_get0_pkey_ctx_allownil)}
    CMS_RecipientInfo_get0_pkey_ctx := ERR_CMS_RecipientInfo_get0_pkey_ctx;
    {$ifend}
    {$if declared(CMS_RecipientInfo_get0_pkey_ctx_introduced)}
    if LibVersion < CMS_RecipientInfo_get0_pkey_ctx_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_get0_pkey_ctx)}
      CMS_RecipientInfo_get0_pkey_ctx := FC_CMS_RecipientInfo_get0_pkey_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_get0_pkey_ctx_removed)}
    if CMS_RecipientInfo_get0_pkey_ctx_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_get0_pkey_ctx)}
      CMS_RecipientInfo_get0_pkey_ctx := _CMS_RecipientInfo_get0_pkey_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_get0_pkey_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_get0_pkey_ctx');
    {$ifend}
  end;
  
  CMS_AuthEnvelopedData_create := LoadLibFunction(ADllHandle, CMS_AuthEnvelopedData_create_procname);
  FuncLoadError := not assigned(CMS_AuthEnvelopedData_create);
  if FuncLoadError then
  begin
    {$if not defined(CMS_AuthEnvelopedData_create_allownil)}
    CMS_AuthEnvelopedData_create := ERR_CMS_AuthEnvelopedData_create;
    {$ifend}
    {$if declared(CMS_AuthEnvelopedData_create_introduced)}
    if LibVersion < CMS_AuthEnvelopedData_create_introduced then
    begin
      {$if declared(FC_CMS_AuthEnvelopedData_create)}
      CMS_AuthEnvelopedData_create := FC_CMS_AuthEnvelopedData_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_AuthEnvelopedData_create_removed)}
    if CMS_AuthEnvelopedData_create_removed <= LibVersion then
    begin
      {$if declared(_CMS_AuthEnvelopedData_create)}
      CMS_AuthEnvelopedData_create := _CMS_AuthEnvelopedData_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_AuthEnvelopedData_create_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_AuthEnvelopedData_create');
    {$ifend}
  end;
  
  CMS_AuthEnvelopedData_create_ex := LoadLibFunction(ADllHandle, CMS_AuthEnvelopedData_create_ex_procname);
  FuncLoadError := not assigned(CMS_AuthEnvelopedData_create_ex);
  if FuncLoadError then
  begin
    {$if not defined(CMS_AuthEnvelopedData_create_ex_allownil)}
    CMS_AuthEnvelopedData_create_ex := ERR_CMS_AuthEnvelopedData_create_ex;
    {$ifend}
    {$if declared(CMS_AuthEnvelopedData_create_ex_introduced)}
    if LibVersion < CMS_AuthEnvelopedData_create_ex_introduced then
    begin
      {$if declared(FC_CMS_AuthEnvelopedData_create_ex)}
      CMS_AuthEnvelopedData_create_ex := FC_CMS_AuthEnvelopedData_create_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_AuthEnvelopedData_create_ex_removed)}
    if CMS_AuthEnvelopedData_create_ex_removed <= LibVersion then
    begin
      {$if declared(_CMS_AuthEnvelopedData_create_ex)}
      CMS_AuthEnvelopedData_create_ex := _CMS_AuthEnvelopedData_create_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_AuthEnvelopedData_create_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_AuthEnvelopedData_create_ex');
    {$ifend}
  end;
  
  CMS_EnvelopedData_create := LoadLibFunction(ADllHandle, CMS_EnvelopedData_create_procname);
  FuncLoadError := not assigned(CMS_EnvelopedData_create);
  if FuncLoadError then
  begin
    {$if not defined(CMS_EnvelopedData_create_allownil)}
    CMS_EnvelopedData_create := ERR_CMS_EnvelopedData_create;
    {$ifend}
    {$if declared(CMS_EnvelopedData_create_introduced)}
    if LibVersion < CMS_EnvelopedData_create_introduced then
    begin
      {$if declared(FC_CMS_EnvelopedData_create)}
      CMS_EnvelopedData_create := FC_CMS_EnvelopedData_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_EnvelopedData_create_removed)}
    if CMS_EnvelopedData_create_removed <= LibVersion then
    begin
      {$if declared(_CMS_EnvelopedData_create)}
      CMS_EnvelopedData_create := _CMS_EnvelopedData_create;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_EnvelopedData_create_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_EnvelopedData_create');
    {$ifend}
  end;
  
  CMS_EnvelopedData_create_ex := LoadLibFunction(ADllHandle, CMS_EnvelopedData_create_ex_procname);
  FuncLoadError := not assigned(CMS_EnvelopedData_create_ex);
  if FuncLoadError then
  begin
    {$if not defined(CMS_EnvelopedData_create_ex_allownil)}
    CMS_EnvelopedData_create_ex := ERR_CMS_EnvelopedData_create_ex;
    {$ifend}
    {$if declared(CMS_EnvelopedData_create_ex_introduced)}
    if LibVersion < CMS_EnvelopedData_create_ex_introduced then
    begin
      {$if declared(FC_CMS_EnvelopedData_create_ex)}
      CMS_EnvelopedData_create_ex := FC_CMS_EnvelopedData_create_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_EnvelopedData_create_ex_removed)}
    if CMS_EnvelopedData_create_ex_removed <= LibVersion then
    begin
      {$if declared(_CMS_EnvelopedData_create_ex)}
      CMS_EnvelopedData_create_ex := _CMS_EnvelopedData_create_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_EnvelopedData_create_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_EnvelopedData_create_ex');
    {$ifend}
  end;
  
  CMS_EnvelopedData_decrypt := LoadLibFunction(ADllHandle, CMS_EnvelopedData_decrypt_procname);
  FuncLoadError := not assigned(CMS_EnvelopedData_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(CMS_EnvelopedData_decrypt_allownil)}
    CMS_EnvelopedData_decrypt := ERR_CMS_EnvelopedData_decrypt;
    {$ifend}
    {$if declared(CMS_EnvelopedData_decrypt_introduced)}
    if LibVersion < CMS_EnvelopedData_decrypt_introduced then
    begin
      {$if declared(FC_CMS_EnvelopedData_decrypt)}
      CMS_EnvelopedData_decrypt := FC_CMS_EnvelopedData_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_EnvelopedData_decrypt_removed)}
    if CMS_EnvelopedData_decrypt_removed <= LibVersion then
    begin
      {$if declared(_CMS_EnvelopedData_decrypt)}
      CMS_EnvelopedData_decrypt := _CMS_EnvelopedData_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_EnvelopedData_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_EnvelopedData_decrypt');
    {$ifend}
  end;
  
  CMS_add1_recipient_cert := LoadLibFunction(ADllHandle, CMS_add1_recipient_cert_procname);
  FuncLoadError := not assigned(CMS_add1_recipient_cert);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add1_recipient_cert_allownil)}
    CMS_add1_recipient_cert := ERR_CMS_add1_recipient_cert;
    {$ifend}
    {$if declared(CMS_add1_recipient_cert_introduced)}
    if LibVersion < CMS_add1_recipient_cert_introduced then
    begin
      {$if declared(FC_CMS_add1_recipient_cert)}
      CMS_add1_recipient_cert := FC_CMS_add1_recipient_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add1_recipient_cert_removed)}
    if CMS_add1_recipient_cert_removed <= LibVersion then
    begin
      {$if declared(_CMS_add1_recipient_cert)}
      CMS_add1_recipient_cert := _CMS_add1_recipient_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add1_recipient_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add1_recipient_cert');
    {$ifend}
  end;
  
  CMS_add1_recipient := LoadLibFunction(ADllHandle, CMS_add1_recipient_procname);
  FuncLoadError := not assigned(CMS_add1_recipient);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add1_recipient_allownil)}
    CMS_add1_recipient := ERR_CMS_add1_recipient;
    {$ifend}
    {$if declared(CMS_add1_recipient_introduced)}
    if LibVersion < CMS_add1_recipient_introduced then
    begin
      {$if declared(FC_CMS_add1_recipient)}
      CMS_add1_recipient := FC_CMS_add1_recipient;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add1_recipient_removed)}
    if CMS_add1_recipient_removed <= LibVersion then
    begin
      {$if declared(_CMS_add1_recipient)}
      CMS_add1_recipient := _CMS_add1_recipient;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add1_recipient_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add1_recipient');
    {$ifend}
  end;
  
  CMS_RecipientInfo_set0_pkey := LoadLibFunction(ADllHandle, CMS_RecipientInfo_set0_pkey_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_set0_pkey);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_set0_pkey_allownil)}
    CMS_RecipientInfo_set0_pkey := ERR_CMS_RecipientInfo_set0_pkey;
    {$ifend}
    {$if declared(CMS_RecipientInfo_set0_pkey_introduced)}
    if LibVersion < CMS_RecipientInfo_set0_pkey_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_set0_pkey)}
      CMS_RecipientInfo_set0_pkey := FC_CMS_RecipientInfo_set0_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_set0_pkey_removed)}
    if CMS_RecipientInfo_set0_pkey_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_set0_pkey)}
      CMS_RecipientInfo_set0_pkey := _CMS_RecipientInfo_set0_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_set0_pkey_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_set0_pkey');
    {$ifend}
  end;
  
  CMS_RecipientInfo_ktri_cert_cmp := LoadLibFunction(ADllHandle, CMS_RecipientInfo_ktri_cert_cmp_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_ktri_cert_cmp);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_ktri_cert_cmp_allownil)}
    CMS_RecipientInfo_ktri_cert_cmp := ERR_CMS_RecipientInfo_ktri_cert_cmp;
    {$ifend}
    {$if declared(CMS_RecipientInfo_ktri_cert_cmp_introduced)}
    if LibVersion < CMS_RecipientInfo_ktri_cert_cmp_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_ktri_cert_cmp)}
      CMS_RecipientInfo_ktri_cert_cmp := FC_CMS_RecipientInfo_ktri_cert_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_ktri_cert_cmp_removed)}
    if CMS_RecipientInfo_ktri_cert_cmp_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_ktri_cert_cmp)}
      CMS_RecipientInfo_ktri_cert_cmp := _CMS_RecipientInfo_ktri_cert_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_ktri_cert_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_ktri_cert_cmp');
    {$ifend}
  end;
  
  CMS_RecipientInfo_ktri_get0_algs := LoadLibFunction(ADllHandle, CMS_RecipientInfo_ktri_get0_algs_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_ktri_get0_algs);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_ktri_get0_algs_allownil)}
    CMS_RecipientInfo_ktri_get0_algs := ERR_CMS_RecipientInfo_ktri_get0_algs;
    {$ifend}
    {$if declared(CMS_RecipientInfo_ktri_get0_algs_introduced)}
    if LibVersion < CMS_RecipientInfo_ktri_get0_algs_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_ktri_get0_algs)}
      CMS_RecipientInfo_ktri_get0_algs := FC_CMS_RecipientInfo_ktri_get0_algs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_ktri_get0_algs_removed)}
    if CMS_RecipientInfo_ktri_get0_algs_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_ktri_get0_algs)}
      CMS_RecipientInfo_ktri_get0_algs := _CMS_RecipientInfo_ktri_get0_algs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_ktri_get0_algs_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_ktri_get0_algs');
    {$ifend}
  end;
  
  CMS_RecipientInfo_ktri_get0_signer_id := LoadLibFunction(ADllHandle, CMS_RecipientInfo_ktri_get0_signer_id_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_ktri_get0_signer_id);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_ktri_get0_signer_id_allownil)}
    CMS_RecipientInfo_ktri_get0_signer_id := ERR_CMS_RecipientInfo_ktri_get0_signer_id;
    {$ifend}
    {$if declared(CMS_RecipientInfo_ktri_get0_signer_id_introduced)}
    if LibVersion < CMS_RecipientInfo_ktri_get0_signer_id_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_ktri_get0_signer_id)}
      CMS_RecipientInfo_ktri_get0_signer_id := FC_CMS_RecipientInfo_ktri_get0_signer_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_ktri_get0_signer_id_removed)}
    if CMS_RecipientInfo_ktri_get0_signer_id_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_ktri_get0_signer_id)}
      CMS_RecipientInfo_ktri_get0_signer_id := _CMS_RecipientInfo_ktri_get0_signer_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_ktri_get0_signer_id_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_ktri_get0_signer_id');
    {$ifend}
  end;
  
  CMS_add0_recipient_key := LoadLibFunction(ADllHandle, CMS_add0_recipient_key_procname);
  FuncLoadError := not assigned(CMS_add0_recipient_key);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add0_recipient_key_allownil)}
    CMS_add0_recipient_key := ERR_CMS_add0_recipient_key;
    {$ifend}
    {$if declared(CMS_add0_recipient_key_introduced)}
    if LibVersion < CMS_add0_recipient_key_introduced then
    begin
      {$if declared(FC_CMS_add0_recipient_key)}
      CMS_add0_recipient_key := FC_CMS_add0_recipient_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add0_recipient_key_removed)}
    if CMS_add0_recipient_key_removed <= LibVersion then
    begin
      {$if declared(_CMS_add0_recipient_key)}
      CMS_add0_recipient_key := _CMS_add0_recipient_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add0_recipient_key_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add0_recipient_key');
    {$ifend}
  end;
  
  CMS_RecipientInfo_kekri_get0_id := LoadLibFunction(ADllHandle, CMS_RecipientInfo_kekri_get0_id_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_kekri_get0_id);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_kekri_get0_id_allownil)}
    CMS_RecipientInfo_kekri_get0_id := ERR_CMS_RecipientInfo_kekri_get0_id;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kekri_get0_id_introduced)}
    if LibVersion < CMS_RecipientInfo_kekri_get0_id_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_kekri_get0_id)}
      CMS_RecipientInfo_kekri_get0_id := FC_CMS_RecipientInfo_kekri_get0_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kekri_get0_id_removed)}
    if CMS_RecipientInfo_kekri_get0_id_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_kekri_get0_id)}
      CMS_RecipientInfo_kekri_get0_id := _CMS_RecipientInfo_kekri_get0_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_kekri_get0_id_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_kekri_get0_id');
    {$ifend}
  end;
  
  CMS_RecipientInfo_set0_key := LoadLibFunction(ADllHandle, CMS_RecipientInfo_set0_key_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_set0_key);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_set0_key_allownil)}
    CMS_RecipientInfo_set0_key := ERR_CMS_RecipientInfo_set0_key;
    {$ifend}
    {$if declared(CMS_RecipientInfo_set0_key_introduced)}
    if LibVersion < CMS_RecipientInfo_set0_key_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_set0_key)}
      CMS_RecipientInfo_set0_key := FC_CMS_RecipientInfo_set0_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_set0_key_removed)}
    if CMS_RecipientInfo_set0_key_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_set0_key)}
      CMS_RecipientInfo_set0_key := _CMS_RecipientInfo_set0_key;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_set0_key_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_set0_key');
    {$ifend}
  end;
  
  CMS_RecipientInfo_kekri_id_cmp := LoadLibFunction(ADllHandle, CMS_RecipientInfo_kekri_id_cmp_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_kekri_id_cmp);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_kekri_id_cmp_allownil)}
    CMS_RecipientInfo_kekri_id_cmp := ERR_CMS_RecipientInfo_kekri_id_cmp;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kekri_id_cmp_introduced)}
    if LibVersion < CMS_RecipientInfo_kekri_id_cmp_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_kekri_id_cmp)}
      CMS_RecipientInfo_kekri_id_cmp := FC_CMS_RecipientInfo_kekri_id_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kekri_id_cmp_removed)}
    if CMS_RecipientInfo_kekri_id_cmp_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_kekri_id_cmp)}
      CMS_RecipientInfo_kekri_id_cmp := _CMS_RecipientInfo_kekri_id_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_kekri_id_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_kekri_id_cmp');
    {$ifend}
  end;
  
  CMS_RecipientInfo_set0_password := LoadLibFunction(ADllHandle, CMS_RecipientInfo_set0_password_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_set0_password);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_set0_password_allownil)}
    CMS_RecipientInfo_set0_password := ERR_CMS_RecipientInfo_set0_password;
    {$ifend}
    {$if declared(CMS_RecipientInfo_set0_password_introduced)}
    if LibVersion < CMS_RecipientInfo_set0_password_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_set0_password)}
      CMS_RecipientInfo_set0_password := FC_CMS_RecipientInfo_set0_password;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_set0_password_removed)}
    if CMS_RecipientInfo_set0_password_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_set0_password)}
      CMS_RecipientInfo_set0_password := _CMS_RecipientInfo_set0_password;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_set0_password_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_set0_password');
    {$ifend}
  end;
  
  CMS_add0_recipient_password := LoadLibFunction(ADllHandle, CMS_add0_recipient_password_procname);
  FuncLoadError := not assigned(CMS_add0_recipient_password);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add0_recipient_password_allownil)}
    CMS_add0_recipient_password := ERR_CMS_add0_recipient_password;
    {$ifend}
    {$if declared(CMS_add0_recipient_password_introduced)}
    if LibVersion < CMS_add0_recipient_password_introduced then
    begin
      {$if declared(FC_CMS_add0_recipient_password)}
      CMS_add0_recipient_password := FC_CMS_add0_recipient_password;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add0_recipient_password_removed)}
    if CMS_add0_recipient_password_removed <= LibVersion then
    begin
      {$if declared(_CMS_add0_recipient_password)}
      CMS_add0_recipient_password := _CMS_add0_recipient_password;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add0_recipient_password_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add0_recipient_password');
    {$ifend}
  end;
  
  CMS_RecipientInfo_decrypt := LoadLibFunction(ADllHandle, CMS_RecipientInfo_decrypt_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_decrypt_allownil)}
    CMS_RecipientInfo_decrypt := ERR_CMS_RecipientInfo_decrypt;
    {$ifend}
    {$if declared(CMS_RecipientInfo_decrypt_introduced)}
    if LibVersion < CMS_RecipientInfo_decrypt_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_decrypt)}
      CMS_RecipientInfo_decrypt := FC_CMS_RecipientInfo_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_decrypt_removed)}
    if CMS_RecipientInfo_decrypt_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_decrypt)}
      CMS_RecipientInfo_decrypt := _CMS_RecipientInfo_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_decrypt');
    {$ifend}
  end;
  
  CMS_RecipientInfo_encrypt := LoadLibFunction(ADllHandle, CMS_RecipientInfo_encrypt_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_encrypt);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_encrypt_allownil)}
    CMS_RecipientInfo_encrypt := ERR_CMS_RecipientInfo_encrypt;
    {$ifend}
    {$if declared(CMS_RecipientInfo_encrypt_introduced)}
    if LibVersion < CMS_RecipientInfo_encrypt_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_encrypt)}
      CMS_RecipientInfo_encrypt := FC_CMS_RecipientInfo_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_encrypt_removed)}
    if CMS_RecipientInfo_encrypt_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_encrypt)}
      CMS_RecipientInfo_encrypt := _CMS_RecipientInfo_encrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_encrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_encrypt');
    {$ifend}
  end;
  
  CMS_uncompress := LoadLibFunction(ADllHandle, CMS_uncompress_procname);
  FuncLoadError := not assigned(CMS_uncompress);
  if FuncLoadError then
  begin
    {$if not defined(CMS_uncompress_allownil)}
    CMS_uncompress := ERR_CMS_uncompress;
    {$ifend}
    {$if declared(CMS_uncompress_introduced)}
    if LibVersion < CMS_uncompress_introduced then
    begin
      {$if declared(FC_CMS_uncompress)}
      CMS_uncompress := FC_CMS_uncompress;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_uncompress_removed)}
    if CMS_uncompress_removed <= LibVersion then
    begin
      {$if declared(_CMS_uncompress)}
      CMS_uncompress := _CMS_uncompress;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_uncompress_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_uncompress');
    {$ifend}
  end;
  
  CMS_compress := LoadLibFunction(ADllHandle, CMS_compress_procname);
  FuncLoadError := not assigned(CMS_compress);
  if FuncLoadError then
  begin
    {$if not defined(CMS_compress_allownil)}
    CMS_compress := ERR_CMS_compress;
    {$ifend}
    {$if declared(CMS_compress_introduced)}
    if LibVersion < CMS_compress_introduced then
    begin
      {$if declared(FC_CMS_compress)}
      CMS_compress := FC_CMS_compress;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_compress_removed)}
    if CMS_compress_removed <= LibVersion then
    begin
      {$if declared(_CMS_compress)}
      CMS_compress := _CMS_compress;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_compress_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_compress');
    {$ifend}
  end;
  
  CMS_set1_eContentType := LoadLibFunction(ADllHandle, CMS_set1_eContentType_procname);
  FuncLoadError := not assigned(CMS_set1_eContentType);
  if FuncLoadError then
  begin
    {$if not defined(CMS_set1_eContentType_allownil)}
    CMS_set1_eContentType := ERR_CMS_set1_eContentType;
    {$ifend}
    {$if declared(CMS_set1_eContentType_introduced)}
    if LibVersion < CMS_set1_eContentType_introduced then
    begin
      {$if declared(FC_CMS_set1_eContentType)}
      CMS_set1_eContentType := FC_CMS_set1_eContentType;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_set1_eContentType_removed)}
    if CMS_set1_eContentType_removed <= LibVersion then
    begin
      {$if declared(_CMS_set1_eContentType)}
      CMS_set1_eContentType := _CMS_set1_eContentType;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_set1_eContentType_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_set1_eContentType');
    {$ifend}
  end;
  
  CMS_get0_eContentType := LoadLibFunction(ADllHandle, CMS_get0_eContentType_procname);
  FuncLoadError := not assigned(CMS_get0_eContentType);
  if FuncLoadError then
  begin
    {$if not defined(CMS_get0_eContentType_allownil)}
    CMS_get0_eContentType := ERR_CMS_get0_eContentType;
    {$ifend}
    {$if declared(CMS_get0_eContentType_introduced)}
    if LibVersion < CMS_get0_eContentType_introduced then
    begin
      {$if declared(FC_CMS_get0_eContentType)}
      CMS_get0_eContentType := FC_CMS_get0_eContentType;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_get0_eContentType_removed)}
    if CMS_get0_eContentType_removed <= LibVersion then
    begin
      {$if declared(_CMS_get0_eContentType)}
      CMS_get0_eContentType := _CMS_get0_eContentType;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_get0_eContentType_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_get0_eContentType');
    {$ifend}
  end;
  
  CMS_add0_CertificateChoices := LoadLibFunction(ADllHandle, CMS_add0_CertificateChoices_procname);
  FuncLoadError := not assigned(CMS_add0_CertificateChoices);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add0_CertificateChoices_allownil)}
    CMS_add0_CertificateChoices := ERR_CMS_add0_CertificateChoices;
    {$ifend}
    {$if declared(CMS_add0_CertificateChoices_introduced)}
    if LibVersion < CMS_add0_CertificateChoices_introduced then
    begin
      {$if declared(FC_CMS_add0_CertificateChoices)}
      CMS_add0_CertificateChoices := FC_CMS_add0_CertificateChoices;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add0_CertificateChoices_removed)}
    if CMS_add0_CertificateChoices_removed <= LibVersion then
    begin
      {$if declared(_CMS_add0_CertificateChoices)}
      CMS_add0_CertificateChoices := _CMS_add0_CertificateChoices;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add0_CertificateChoices_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add0_CertificateChoices');
    {$ifend}
  end;
  
  CMS_add0_cert := LoadLibFunction(ADllHandle, CMS_add0_cert_procname);
  FuncLoadError := not assigned(CMS_add0_cert);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add0_cert_allownil)}
    CMS_add0_cert := ERR_CMS_add0_cert;
    {$ifend}
    {$if declared(CMS_add0_cert_introduced)}
    if LibVersion < CMS_add0_cert_introduced then
    begin
      {$if declared(FC_CMS_add0_cert)}
      CMS_add0_cert := FC_CMS_add0_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add0_cert_removed)}
    if CMS_add0_cert_removed <= LibVersion then
    begin
      {$if declared(_CMS_add0_cert)}
      CMS_add0_cert := _CMS_add0_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add0_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add0_cert');
    {$ifend}
  end;
  
  CMS_add1_cert := LoadLibFunction(ADllHandle, CMS_add1_cert_procname);
  FuncLoadError := not assigned(CMS_add1_cert);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add1_cert_allownil)}
    CMS_add1_cert := ERR_CMS_add1_cert;
    {$ifend}
    {$if declared(CMS_add1_cert_introduced)}
    if LibVersion < CMS_add1_cert_introduced then
    begin
      {$if declared(FC_CMS_add1_cert)}
      CMS_add1_cert := FC_CMS_add1_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add1_cert_removed)}
    if CMS_add1_cert_removed <= LibVersion then
    begin
      {$if declared(_CMS_add1_cert)}
      CMS_add1_cert := _CMS_add1_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add1_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add1_cert');
    {$ifend}
  end;
  
  CMS_get1_certs := LoadLibFunction(ADllHandle, CMS_get1_certs_procname);
  FuncLoadError := not assigned(CMS_get1_certs);
  if FuncLoadError then
  begin
    {$if not defined(CMS_get1_certs_allownil)}
    CMS_get1_certs := ERR_CMS_get1_certs;
    {$ifend}
    {$if declared(CMS_get1_certs_introduced)}
    if LibVersion < CMS_get1_certs_introduced then
    begin
      {$if declared(FC_CMS_get1_certs)}
      CMS_get1_certs := FC_CMS_get1_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_get1_certs_removed)}
    if CMS_get1_certs_removed <= LibVersion then
    begin
      {$if declared(_CMS_get1_certs)}
      CMS_get1_certs := _CMS_get1_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_get1_certs_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_get1_certs');
    {$ifend}
  end;
  
  CMS_add0_RevocationInfoChoice := LoadLibFunction(ADllHandle, CMS_add0_RevocationInfoChoice_procname);
  FuncLoadError := not assigned(CMS_add0_RevocationInfoChoice);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add0_RevocationInfoChoice_allownil)}
    CMS_add0_RevocationInfoChoice := ERR_CMS_add0_RevocationInfoChoice;
    {$ifend}
    {$if declared(CMS_add0_RevocationInfoChoice_introduced)}
    if LibVersion < CMS_add0_RevocationInfoChoice_introduced then
    begin
      {$if declared(FC_CMS_add0_RevocationInfoChoice)}
      CMS_add0_RevocationInfoChoice := FC_CMS_add0_RevocationInfoChoice;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add0_RevocationInfoChoice_removed)}
    if CMS_add0_RevocationInfoChoice_removed <= LibVersion then
    begin
      {$if declared(_CMS_add0_RevocationInfoChoice)}
      CMS_add0_RevocationInfoChoice := _CMS_add0_RevocationInfoChoice;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add0_RevocationInfoChoice_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add0_RevocationInfoChoice');
    {$ifend}
  end;
  
  CMS_add0_crl := LoadLibFunction(ADllHandle, CMS_add0_crl_procname);
  FuncLoadError := not assigned(CMS_add0_crl);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add0_crl_allownil)}
    CMS_add0_crl := ERR_CMS_add0_crl;
    {$ifend}
    {$if declared(CMS_add0_crl_introduced)}
    if LibVersion < CMS_add0_crl_introduced then
    begin
      {$if declared(FC_CMS_add0_crl)}
      CMS_add0_crl := FC_CMS_add0_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add0_crl_removed)}
    if CMS_add0_crl_removed <= LibVersion then
    begin
      {$if declared(_CMS_add0_crl)}
      CMS_add0_crl := _CMS_add0_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add0_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add0_crl');
    {$ifend}
  end;
  
  CMS_add1_crl := LoadLibFunction(ADllHandle, CMS_add1_crl_procname);
  FuncLoadError := not assigned(CMS_add1_crl);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add1_crl_allownil)}
    CMS_add1_crl := ERR_CMS_add1_crl;
    {$ifend}
    {$if declared(CMS_add1_crl_introduced)}
    if LibVersion < CMS_add1_crl_introduced then
    begin
      {$if declared(FC_CMS_add1_crl)}
      CMS_add1_crl := FC_CMS_add1_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add1_crl_removed)}
    if CMS_add1_crl_removed <= LibVersion then
    begin
      {$if declared(_CMS_add1_crl)}
      CMS_add1_crl := _CMS_add1_crl;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add1_crl_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add1_crl');
    {$ifend}
  end;
  
  CMS_get1_crls := LoadLibFunction(ADllHandle, CMS_get1_crls_procname);
  FuncLoadError := not assigned(CMS_get1_crls);
  if FuncLoadError then
  begin
    {$if not defined(CMS_get1_crls_allownil)}
    CMS_get1_crls := ERR_CMS_get1_crls;
    {$ifend}
    {$if declared(CMS_get1_crls_introduced)}
    if LibVersion < CMS_get1_crls_introduced then
    begin
      {$if declared(FC_CMS_get1_crls)}
      CMS_get1_crls := FC_CMS_get1_crls;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_get1_crls_removed)}
    if CMS_get1_crls_removed <= LibVersion then
    begin
      {$if declared(_CMS_get1_crls)}
      CMS_get1_crls := _CMS_get1_crls;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_get1_crls_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_get1_crls');
    {$ifend}
  end;
  
  CMS_SignedData_init := LoadLibFunction(ADllHandle, CMS_SignedData_init_procname);
  FuncLoadError := not assigned(CMS_SignedData_init);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SignedData_init_allownil)}
    CMS_SignedData_init := ERR_CMS_SignedData_init;
    {$ifend}
    {$if declared(CMS_SignedData_init_introduced)}
    if LibVersion < CMS_SignedData_init_introduced then
    begin
      {$if declared(FC_CMS_SignedData_init)}
      CMS_SignedData_init := FC_CMS_SignedData_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SignedData_init_removed)}
    if CMS_SignedData_init_removed <= LibVersion then
    begin
      {$if declared(_CMS_SignedData_init)}
      CMS_SignedData_init := _CMS_SignedData_init;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SignedData_init_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SignedData_init');
    {$ifend}
  end;
  
  CMS_add1_signer := LoadLibFunction(ADllHandle, CMS_add1_signer_procname);
  FuncLoadError := not assigned(CMS_add1_signer);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add1_signer_allownil)}
    CMS_add1_signer := ERR_CMS_add1_signer;
    {$ifend}
    {$if declared(CMS_add1_signer_introduced)}
    if LibVersion < CMS_add1_signer_introduced then
    begin
      {$if declared(FC_CMS_add1_signer)}
      CMS_add1_signer := FC_CMS_add1_signer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add1_signer_removed)}
    if CMS_add1_signer_removed <= LibVersion then
    begin
      {$if declared(_CMS_add1_signer)}
      CMS_add1_signer := _CMS_add1_signer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add1_signer_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add1_signer');
    {$ifend}
  end;
  
  CMS_SignerInfo_get0_pkey_ctx := LoadLibFunction(ADllHandle, CMS_SignerInfo_get0_pkey_ctx_procname);
  FuncLoadError := not assigned(CMS_SignerInfo_get0_pkey_ctx);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SignerInfo_get0_pkey_ctx_allownil)}
    CMS_SignerInfo_get0_pkey_ctx := ERR_CMS_SignerInfo_get0_pkey_ctx;
    {$ifend}
    {$if declared(CMS_SignerInfo_get0_pkey_ctx_introduced)}
    if LibVersion < CMS_SignerInfo_get0_pkey_ctx_introduced then
    begin
      {$if declared(FC_CMS_SignerInfo_get0_pkey_ctx)}
      CMS_SignerInfo_get0_pkey_ctx := FC_CMS_SignerInfo_get0_pkey_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SignerInfo_get0_pkey_ctx_removed)}
    if CMS_SignerInfo_get0_pkey_ctx_removed <= LibVersion then
    begin
      {$if declared(_CMS_SignerInfo_get0_pkey_ctx)}
      CMS_SignerInfo_get0_pkey_ctx := _CMS_SignerInfo_get0_pkey_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SignerInfo_get0_pkey_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SignerInfo_get0_pkey_ctx');
    {$ifend}
  end;
  
  CMS_SignerInfo_get0_md_ctx := LoadLibFunction(ADllHandle, CMS_SignerInfo_get0_md_ctx_procname);
  FuncLoadError := not assigned(CMS_SignerInfo_get0_md_ctx);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SignerInfo_get0_md_ctx_allownil)}
    CMS_SignerInfo_get0_md_ctx := ERR_CMS_SignerInfo_get0_md_ctx;
    {$ifend}
    {$if declared(CMS_SignerInfo_get0_md_ctx_introduced)}
    if LibVersion < CMS_SignerInfo_get0_md_ctx_introduced then
    begin
      {$if declared(FC_CMS_SignerInfo_get0_md_ctx)}
      CMS_SignerInfo_get0_md_ctx := FC_CMS_SignerInfo_get0_md_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SignerInfo_get0_md_ctx_removed)}
    if CMS_SignerInfo_get0_md_ctx_removed <= LibVersion then
    begin
      {$if declared(_CMS_SignerInfo_get0_md_ctx)}
      CMS_SignerInfo_get0_md_ctx := _CMS_SignerInfo_get0_md_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SignerInfo_get0_md_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SignerInfo_get0_md_ctx');
    {$ifend}
  end;
  
  CMS_get0_SignerInfos := LoadLibFunction(ADllHandle, CMS_get0_SignerInfos_procname);
  FuncLoadError := not assigned(CMS_get0_SignerInfos);
  if FuncLoadError then
  begin
    {$if not defined(CMS_get0_SignerInfos_allownil)}
    CMS_get0_SignerInfos := ERR_CMS_get0_SignerInfos;
    {$ifend}
    {$if declared(CMS_get0_SignerInfos_introduced)}
    if LibVersion < CMS_get0_SignerInfos_introduced then
    begin
      {$if declared(FC_CMS_get0_SignerInfos)}
      CMS_get0_SignerInfos := FC_CMS_get0_SignerInfos;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_get0_SignerInfos_removed)}
    if CMS_get0_SignerInfos_removed <= LibVersion then
    begin
      {$if declared(_CMS_get0_SignerInfos)}
      CMS_get0_SignerInfos := _CMS_get0_SignerInfos;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_get0_SignerInfos_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_get0_SignerInfos');
    {$ifend}
  end;
  
  CMS_SignerInfo_set1_signer_cert := LoadLibFunction(ADllHandle, CMS_SignerInfo_set1_signer_cert_procname);
  FuncLoadError := not assigned(CMS_SignerInfo_set1_signer_cert);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SignerInfo_set1_signer_cert_allownil)}
    CMS_SignerInfo_set1_signer_cert := ERR_CMS_SignerInfo_set1_signer_cert;
    {$ifend}
    {$if declared(CMS_SignerInfo_set1_signer_cert_introduced)}
    if LibVersion < CMS_SignerInfo_set1_signer_cert_introduced then
    begin
      {$if declared(FC_CMS_SignerInfo_set1_signer_cert)}
      CMS_SignerInfo_set1_signer_cert := FC_CMS_SignerInfo_set1_signer_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SignerInfo_set1_signer_cert_removed)}
    if CMS_SignerInfo_set1_signer_cert_removed <= LibVersion then
    begin
      {$if declared(_CMS_SignerInfo_set1_signer_cert)}
      CMS_SignerInfo_set1_signer_cert := _CMS_SignerInfo_set1_signer_cert;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SignerInfo_set1_signer_cert_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SignerInfo_set1_signer_cert');
    {$ifend}
  end;
  
  CMS_SignerInfo_get0_signer_id := LoadLibFunction(ADllHandle, CMS_SignerInfo_get0_signer_id_procname);
  FuncLoadError := not assigned(CMS_SignerInfo_get0_signer_id);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SignerInfo_get0_signer_id_allownil)}
    CMS_SignerInfo_get0_signer_id := ERR_CMS_SignerInfo_get0_signer_id;
    {$ifend}
    {$if declared(CMS_SignerInfo_get0_signer_id_introduced)}
    if LibVersion < CMS_SignerInfo_get0_signer_id_introduced then
    begin
      {$if declared(FC_CMS_SignerInfo_get0_signer_id)}
      CMS_SignerInfo_get0_signer_id := FC_CMS_SignerInfo_get0_signer_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SignerInfo_get0_signer_id_removed)}
    if CMS_SignerInfo_get0_signer_id_removed <= LibVersion then
    begin
      {$if declared(_CMS_SignerInfo_get0_signer_id)}
      CMS_SignerInfo_get0_signer_id := _CMS_SignerInfo_get0_signer_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SignerInfo_get0_signer_id_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SignerInfo_get0_signer_id');
    {$ifend}
  end;
  
  CMS_SignerInfo_cert_cmp := LoadLibFunction(ADllHandle, CMS_SignerInfo_cert_cmp_procname);
  FuncLoadError := not assigned(CMS_SignerInfo_cert_cmp);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SignerInfo_cert_cmp_allownil)}
    CMS_SignerInfo_cert_cmp := ERR_CMS_SignerInfo_cert_cmp;
    {$ifend}
    {$if declared(CMS_SignerInfo_cert_cmp_introduced)}
    if LibVersion < CMS_SignerInfo_cert_cmp_introduced then
    begin
      {$if declared(FC_CMS_SignerInfo_cert_cmp)}
      CMS_SignerInfo_cert_cmp := FC_CMS_SignerInfo_cert_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SignerInfo_cert_cmp_removed)}
    if CMS_SignerInfo_cert_cmp_removed <= LibVersion then
    begin
      {$if declared(_CMS_SignerInfo_cert_cmp)}
      CMS_SignerInfo_cert_cmp := _CMS_SignerInfo_cert_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SignerInfo_cert_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SignerInfo_cert_cmp');
    {$ifend}
  end;
  
  CMS_set1_signers_certs := LoadLibFunction(ADllHandle, CMS_set1_signers_certs_procname);
  FuncLoadError := not assigned(CMS_set1_signers_certs);
  if FuncLoadError then
  begin
    {$if not defined(CMS_set1_signers_certs_allownil)}
    CMS_set1_signers_certs := ERR_CMS_set1_signers_certs;
    {$ifend}
    {$if declared(CMS_set1_signers_certs_introduced)}
    if LibVersion < CMS_set1_signers_certs_introduced then
    begin
      {$if declared(FC_CMS_set1_signers_certs)}
      CMS_set1_signers_certs := FC_CMS_set1_signers_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_set1_signers_certs_removed)}
    if CMS_set1_signers_certs_removed <= LibVersion then
    begin
      {$if declared(_CMS_set1_signers_certs)}
      CMS_set1_signers_certs := _CMS_set1_signers_certs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_set1_signers_certs_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_set1_signers_certs');
    {$ifend}
  end;
  
  CMS_SignerInfo_get0_algs := LoadLibFunction(ADllHandle, CMS_SignerInfo_get0_algs_procname);
  FuncLoadError := not assigned(CMS_SignerInfo_get0_algs);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SignerInfo_get0_algs_allownil)}
    CMS_SignerInfo_get0_algs := ERR_CMS_SignerInfo_get0_algs;
    {$ifend}
    {$if declared(CMS_SignerInfo_get0_algs_introduced)}
    if LibVersion < CMS_SignerInfo_get0_algs_introduced then
    begin
      {$if declared(FC_CMS_SignerInfo_get0_algs)}
      CMS_SignerInfo_get0_algs := FC_CMS_SignerInfo_get0_algs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SignerInfo_get0_algs_removed)}
    if CMS_SignerInfo_get0_algs_removed <= LibVersion then
    begin
      {$if declared(_CMS_SignerInfo_get0_algs)}
      CMS_SignerInfo_get0_algs := _CMS_SignerInfo_get0_algs;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SignerInfo_get0_algs_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SignerInfo_get0_algs');
    {$ifend}
  end;
  
  CMS_SignerInfo_get0_signature := LoadLibFunction(ADllHandle, CMS_SignerInfo_get0_signature_procname);
  FuncLoadError := not assigned(CMS_SignerInfo_get0_signature);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SignerInfo_get0_signature_allownil)}
    CMS_SignerInfo_get0_signature := ERR_CMS_SignerInfo_get0_signature;
    {$ifend}
    {$if declared(CMS_SignerInfo_get0_signature_introduced)}
    if LibVersion < CMS_SignerInfo_get0_signature_introduced then
    begin
      {$if declared(FC_CMS_SignerInfo_get0_signature)}
      CMS_SignerInfo_get0_signature := FC_CMS_SignerInfo_get0_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SignerInfo_get0_signature_removed)}
    if CMS_SignerInfo_get0_signature_removed <= LibVersion then
    begin
      {$if declared(_CMS_SignerInfo_get0_signature)}
      CMS_SignerInfo_get0_signature := _CMS_SignerInfo_get0_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SignerInfo_get0_signature_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SignerInfo_get0_signature');
    {$ifend}
  end;
  
  CMS_SignerInfo_sign := LoadLibFunction(ADllHandle, CMS_SignerInfo_sign_procname);
  FuncLoadError := not assigned(CMS_SignerInfo_sign);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SignerInfo_sign_allownil)}
    CMS_SignerInfo_sign := ERR_CMS_SignerInfo_sign;
    {$ifend}
    {$if declared(CMS_SignerInfo_sign_introduced)}
    if LibVersion < CMS_SignerInfo_sign_introduced then
    begin
      {$if declared(FC_CMS_SignerInfo_sign)}
      CMS_SignerInfo_sign := FC_CMS_SignerInfo_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SignerInfo_sign_removed)}
    if CMS_SignerInfo_sign_removed <= LibVersion then
    begin
      {$if declared(_CMS_SignerInfo_sign)}
      CMS_SignerInfo_sign := _CMS_SignerInfo_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SignerInfo_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SignerInfo_sign');
    {$ifend}
  end;
  
  CMS_SignerInfo_verify := LoadLibFunction(ADllHandle, CMS_SignerInfo_verify_procname);
  FuncLoadError := not assigned(CMS_SignerInfo_verify);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SignerInfo_verify_allownil)}
    CMS_SignerInfo_verify := ERR_CMS_SignerInfo_verify;
    {$ifend}
    {$if declared(CMS_SignerInfo_verify_introduced)}
    if LibVersion < CMS_SignerInfo_verify_introduced then
    begin
      {$if declared(FC_CMS_SignerInfo_verify)}
      CMS_SignerInfo_verify := FC_CMS_SignerInfo_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SignerInfo_verify_removed)}
    if CMS_SignerInfo_verify_removed <= LibVersion then
    begin
      {$if declared(_CMS_SignerInfo_verify)}
      CMS_SignerInfo_verify := _CMS_SignerInfo_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SignerInfo_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SignerInfo_verify');
    {$ifend}
  end;
  
  CMS_SignerInfo_verify_content := LoadLibFunction(ADllHandle, CMS_SignerInfo_verify_content_procname);
  FuncLoadError := not assigned(CMS_SignerInfo_verify_content);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SignerInfo_verify_content_allownil)}
    CMS_SignerInfo_verify_content := ERR_CMS_SignerInfo_verify_content;
    {$ifend}
    {$if declared(CMS_SignerInfo_verify_content_introduced)}
    if LibVersion < CMS_SignerInfo_verify_content_introduced then
    begin
      {$if declared(FC_CMS_SignerInfo_verify_content)}
      CMS_SignerInfo_verify_content := FC_CMS_SignerInfo_verify_content;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SignerInfo_verify_content_removed)}
    if CMS_SignerInfo_verify_content_removed <= LibVersion then
    begin
      {$if declared(_CMS_SignerInfo_verify_content)}
      CMS_SignerInfo_verify_content := _CMS_SignerInfo_verify_content;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SignerInfo_verify_content_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SignerInfo_verify_content');
    {$ifend}
  end;
  
  CMS_SignedData_verify := LoadLibFunction(ADllHandle, CMS_SignedData_verify_procname);
  FuncLoadError := not assigned(CMS_SignedData_verify);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SignedData_verify_allownil)}
    CMS_SignedData_verify := ERR_CMS_SignedData_verify;
    {$ifend}
    {$if declared(CMS_SignedData_verify_introduced)}
    if LibVersion < CMS_SignedData_verify_introduced then
    begin
      {$if declared(FC_CMS_SignedData_verify)}
      CMS_SignedData_verify := FC_CMS_SignedData_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SignedData_verify_removed)}
    if CMS_SignedData_verify_removed <= LibVersion then
    begin
      {$if declared(_CMS_SignedData_verify)}
      CMS_SignedData_verify := _CMS_SignedData_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SignedData_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SignedData_verify');
    {$ifend}
  end;
  
  CMS_add_smimecap := LoadLibFunction(ADllHandle, CMS_add_smimecap_procname);
  FuncLoadError := not assigned(CMS_add_smimecap);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add_smimecap_allownil)}
    CMS_add_smimecap := ERR_CMS_add_smimecap;
    {$ifend}
    {$if declared(CMS_add_smimecap_introduced)}
    if LibVersion < CMS_add_smimecap_introduced then
    begin
      {$if declared(FC_CMS_add_smimecap)}
      CMS_add_smimecap := FC_CMS_add_smimecap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add_smimecap_removed)}
    if CMS_add_smimecap_removed <= LibVersion then
    begin
      {$if declared(_CMS_add_smimecap)}
      CMS_add_smimecap := _CMS_add_smimecap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add_smimecap_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add_smimecap');
    {$ifend}
  end;
  
  CMS_add_simple_smimecap := LoadLibFunction(ADllHandle, CMS_add_simple_smimecap_procname);
  FuncLoadError := not assigned(CMS_add_simple_smimecap);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add_simple_smimecap_allownil)}
    CMS_add_simple_smimecap := ERR_CMS_add_simple_smimecap;
    {$ifend}
    {$if declared(CMS_add_simple_smimecap_introduced)}
    if LibVersion < CMS_add_simple_smimecap_introduced then
    begin
      {$if declared(FC_CMS_add_simple_smimecap)}
      CMS_add_simple_smimecap := FC_CMS_add_simple_smimecap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add_simple_smimecap_removed)}
    if CMS_add_simple_smimecap_removed <= LibVersion then
    begin
      {$if declared(_CMS_add_simple_smimecap)}
      CMS_add_simple_smimecap := _CMS_add_simple_smimecap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add_simple_smimecap_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add_simple_smimecap');
    {$ifend}
  end;
  
  CMS_add_standard_smimecap := LoadLibFunction(ADllHandle, CMS_add_standard_smimecap_procname);
  FuncLoadError := not assigned(CMS_add_standard_smimecap);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add_standard_smimecap_allownil)}
    CMS_add_standard_smimecap := ERR_CMS_add_standard_smimecap;
    {$ifend}
    {$if declared(CMS_add_standard_smimecap_introduced)}
    if LibVersion < CMS_add_standard_smimecap_introduced then
    begin
      {$if declared(FC_CMS_add_standard_smimecap)}
      CMS_add_standard_smimecap := FC_CMS_add_standard_smimecap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add_standard_smimecap_removed)}
    if CMS_add_standard_smimecap_removed <= LibVersion then
    begin
      {$if declared(_CMS_add_standard_smimecap)}
      CMS_add_standard_smimecap := _CMS_add_standard_smimecap;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add_standard_smimecap_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add_standard_smimecap');
    {$ifend}
  end;
  
  CMS_signed_get_attr_count := LoadLibFunction(ADllHandle, CMS_signed_get_attr_count_procname);
  FuncLoadError := not assigned(CMS_signed_get_attr_count);
  if FuncLoadError then
  begin
    {$if not defined(CMS_signed_get_attr_count_allownil)}
    CMS_signed_get_attr_count := ERR_CMS_signed_get_attr_count;
    {$ifend}
    {$if declared(CMS_signed_get_attr_count_introduced)}
    if LibVersion < CMS_signed_get_attr_count_introduced then
    begin
      {$if declared(FC_CMS_signed_get_attr_count)}
      CMS_signed_get_attr_count := FC_CMS_signed_get_attr_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_signed_get_attr_count_removed)}
    if CMS_signed_get_attr_count_removed <= LibVersion then
    begin
      {$if declared(_CMS_signed_get_attr_count)}
      CMS_signed_get_attr_count := _CMS_signed_get_attr_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_signed_get_attr_count_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_signed_get_attr_count');
    {$ifend}
  end;
  
  CMS_signed_get_attr_by_NID := LoadLibFunction(ADllHandle, CMS_signed_get_attr_by_NID_procname);
  FuncLoadError := not assigned(CMS_signed_get_attr_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(CMS_signed_get_attr_by_NID_allownil)}
    CMS_signed_get_attr_by_NID := ERR_CMS_signed_get_attr_by_NID;
    {$ifend}
    {$if declared(CMS_signed_get_attr_by_NID_introduced)}
    if LibVersion < CMS_signed_get_attr_by_NID_introduced then
    begin
      {$if declared(FC_CMS_signed_get_attr_by_NID)}
      CMS_signed_get_attr_by_NID := FC_CMS_signed_get_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_signed_get_attr_by_NID_removed)}
    if CMS_signed_get_attr_by_NID_removed <= LibVersion then
    begin
      {$if declared(_CMS_signed_get_attr_by_NID)}
      CMS_signed_get_attr_by_NID := _CMS_signed_get_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_signed_get_attr_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_signed_get_attr_by_NID');
    {$ifend}
  end;
  
  CMS_signed_get_attr_by_OBJ := LoadLibFunction(ADllHandle, CMS_signed_get_attr_by_OBJ_procname);
  FuncLoadError := not assigned(CMS_signed_get_attr_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(CMS_signed_get_attr_by_OBJ_allownil)}
    CMS_signed_get_attr_by_OBJ := ERR_CMS_signed_get_attr_by_OBJ;
    {$ifend}
    {$if declared(CMS_signed_get_attr_by_OBJ_introduced)}
    if LibVersion < CMS_signed_get_attr_by_OBJ_introduced then
    begin
      {$if declared(FC_CMS_signed_get_attr_by_OBJ)}
      CMS_signed_get_attr_by_OBJ := FC_CMS_signed_get_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_signed_get_attr_by_OBJ_removed)}
    if CMS_signed_get_attr_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_CMS_signed_get_attr_by_OBJ)}
      CMS_signed_get_attr_by_OBJ := _CMS_signed_get_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_signed_get_attr_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_signed_get_attr_by_OBJ');
    {$ifend}
  end;
  
  CMS_signed_get_attr := LoadLibFunction(ADllHandle, CMS_signed_get_attr_procname);
  FuncLoadError := not assigned(CMS_signed_get_attr);
  if FuncLoadError then
  begin
    {$if not defined(CMS_signed_get_attr_allownil)}
    CMS_signed_get_attr := ERR_CMS_signed_get_attr;
    {$ifend}
    {$if declared(CMS_signed_get_attr_introduced)}
    if LibVersion < CMS_signed_get_attr_introduced then
    begin
      {$if declared(FC_CMS_signed_get_attr)}
      CMS_signed_get_attr := FC_CMS_signed_get_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_signed_get_attr_removed)}
    if CMS_signed_get_attr_removed <= LibVersion then
    begin
      {$if declared(_CMS_signed_get_attr)}
      CMS_signed_get_attr := _CMS_signed_get_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_signed_get_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_signed_get_attr');
    {$ifend}
  end;
  
  CMS_signed_delete_attr := LoadLibFunction(ADllHandle, CMS_signed_delete_attr_procname);
  FuncLoadError := not assigned(CMS_signed_delete_attr);
  if FuncLoadError then
  begin
    {$if not defined(CMS_signed_delete_attr_allownil)}
    CMS_signed_delete_attr := ERR_CMS_signed_delete_attr;
    {$ifend}
    {$if declared(CMS_signed_delete_attr_introduced)}
    if LibVersion < CMS_signed_delete_attr_introduced then
    begin
      {$if declared(FC_CMS_signed_delete_attr)}
      CMS_signed_delete_attr := FC_CMS_signed_delete_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_signed_delete_attr_removed)}
    if CMS_signed_delete_attr_removed <= LibVersion then
    begin
      {$if declared(_CMS_signed_delete_attr)}
      CMS_signed_delete_attr := _CMS_signed_delete_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_signed_delete_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_signed_delete_attr');
    {$ifend}
  end;
  
  CMS_signed_add1_attr := LoadLibFunction(ADllHandle, CMS_signed_add1_attr_procname);
  FuncLoadError := not assigned(CMS_signed_add1_attr);
  if FuncLoadError then
  begin
    {$if not defined(CMS_signed_add1_attr_allownil)}
    CMS_signed_add1_attr := ERR_CMS_signed_add1_attr;
    {$ifend}
    {$if declared(CMS_signed_add1_attr_introduced)}
    if LibVersion < CMS_signed_add1_attr_introduced then
    begin
      {$if declared(FC_CMS_signed_add1_attr)}
      CMS_signed_add1_attr := FC_CMS_signed_add1_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_signed_add1_attr_removed)}
    if CMS_signed_add1_attr_removed <= LibVersion then
    begin
      {$if declared(_CMS_signed_add1_attr)}
      CMS_signed_add1_attr := _CMS_signed_add1_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_signed_add1_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_signed_add1_attr');
    {$ifend}
  end;
  
  CMS_signed_add1_attr_by_OBJ := LoadLibFunction(ADllHandle, CMS_signed_add1_attr_by_OBJ_procname);
  FuncLoadError := not assigned(CMS_signed_add1_attr_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(CMS_signed_add1_attr_by_OBJ_allownil)}
    CMS_signed_add1_attr_by_OBJ := ERR_CMS_signed_add1_attr_by_OBJ;
    {$ifend}
    {$if declared(CMS_signed_add1_attr_by_OBJ_introduced)}
    if LibVersion < CMS_signed_add1_attr_by_OBJ_introduced then
    begin
      {$if declared(FC_CMS_signed_add1_attr_by_OBJ)}
      CMS_signed_add1_attr_by_OBJ := FC_CMS_signed_add1_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_signed_add1_attr_by_OBJ_removed)}
    if CMS_signed_add1_attr_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_CMS_signed_add1_attr_by_OBJ)}
      CMS_signed_add1_attr_by_OBJ := _CMS_signed_add1_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_signed_add1_attr_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_signed_add1_attr_by_OBJ');
    {$ifend}
  end;
  
  CMS_signed_add1_attr_by_NID := LoadLibFunction(ADllHandle, CMS_signed_add1_attr_by_NID_procname);
  FuncLoadError := not assigned(CMS_signed_add1_attr_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(CMS_signed_add1_attr_by_NID_allownil)}
    CMS_signed_add1_attr_by_NID := ERR_CMS_signed_add1_attr_by_NID;
    {$ifend}
    {$if declared(CMS_signed_add1_attr_by_NID_introduced)}
    if LibVersion < CMS_signed_add1_attr_by_NID_introduced then
    begin
      {$if declared(FC_CMS_signed_add1_attr_by_NID)}
      CMS_signed_add1_attr_by_NID := FC_CMS_signed_add1_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_signed_add1_attr_by_NID_removed)}
    if CMS_signed_add1_attr_by_NID_removed <= LibVersion then
    begin
      {$if declared(_CMS_signed_add1_attr_by_NID)}
      CMS_signed_add1_attr_by_NID := _CMS_signed_add1_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_signed_add1_attr_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_signed_add1_attr_by_NID');
    {$ifend}
  end;
  
  CMS_signed_add1_attr_by_txt := LoadLibFunction(ADllHandle, CMS_signed_add1_attr_by_txt_procname);
  FuncLoadError := not assigned(CMS_signed_add1_attr_by_txt);
  if FuncLoadError then
  begin
    {$if not defined(CMS_signed_add1_attr_by_txt_allownil)}
    CMS_signed_add1_attr_by_txt := ERR_CMS_signed_add1_attr_by_txt;
    {$ifend}
    {$if declared(CMS_signed_add1_attr_by_txt_introduced)}
    if LibVersion < CMS_signed_add1_attr_by_txt_introduced then
    begin
      {$if declared(FC_CMS_signed_add1_attr_by_txt)}
      CMS_signed_add1_attr_by_txt := FC_CMS_signed_add1_attr_by_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_signed_add1_attr_by_txt_removed)}
    if CMS_signed_add1_attr_by_txt_removed <= LibVersion then
    begin
      {$if declared(_CMS_signed_add1_attr_by_txt)}
      CMS_signed_add1_attr_by_txt := _CMS_signed_add1_attr_by_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_signed_add1_attr_by_txt_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_signed_add1_attr_by_txt');
    {$ifend}
  end;
  
  CMS_signed_get0_data_by_OBJ := LoadLibFunction(ADllHandle, CMS_signed_get0_data_by_OBJ_procname);
  FuncLoadError := not assigned(CMS_signed_get0_data_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(CMS_signed_get0_data_by_OBJ_allownil)}
    CMS_signed_get0_data_by_OBJ := ERR_CMS_signed_get0_data_by_OBJ;
    {$ifend}
    {$if declared(CMS_signed_get0_data_by_OBJ_introduced)}
    if LibVersion < CMS_signed_get0_data_by_OBJ_introduced then
    begin
      {$if declared(FC_CMS_signed_get0_data_by_OBJ)}
      CMS_signed_get0_data_by_OBJ := FC_CMS_signed_get0_data_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_signed_get0_data_by_OBJ_removed)}
    if CMS_signed_get0_data_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_CMS_signed_get0_data_by_OBJ)}
      CMS_signed_get0_data_by_OBJ := _CMS_signed_get0_data_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_signed_get0_data_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_signed_get0_data_by_OBJ');
    {$ifend}
  end;
  
  CMS_unsigned_get_attr_count := LoadLibFunction(ADllHandle, CMS_unsigned_get_attr_count_procname);
  FuncLoadError := not assigned(CMS_unsigned_get_attr_count);
  if FuncLoadError then
  begin
    {$if not defined(CMS_unsigned_get_attr_count_allownil)}
    CMS_unsigned_get_attr_count := ERR_CMS_unsigned_get_attr_count;
    {$ifend}
    {$if declared(CMS_unsigned_get_attr_count_introduced)}
    if LibVersion < CMS_unsigned_get_attr_count_introduced then
    begin
      {$if declared(FC_CMS_unsigned_get_attr_count)}
      CMS_unsigned_get_attr_count := FC_CMS_unsigned_get_attr_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_unsigned_get_attr_count_removed)}
    if CMS_unsigned_get_attr_count_removed <= LibVersion then
    begin
      {$if declared(_CMS_unsigned_get_attr_count)}
      CMS_unsigned_get_attr_count := _CMS_unsigned_get_attr_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_unsigned_get_attr_count_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_unsigned_get_attr_count');
    {$ifend}
  end;
  
  CMS_unsigned_get_attr_by_NID := LoadLibFunction(ADllHandle, CMS_unsigned_get_attr_by_NID_procname);
  FuncLoadError := not assigned(CMS_unsigned_get_attr_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(CMS_unsigned_get_attr_by_NID_allownil)}
    CMS_unsigned_get_attr_by_NID := ERR_CMS_unsigned_get_attr_by_NID;
    {$ifend}
    {$if declared(CMS_unsigned_get_attr_by_NID_introduced)}
    if LibVersion < CMS_unsigned_get_attr_by_NID_introduced then
    begin
      {$if declared(FC_CMS_unsigned_get_attr_by_NID)}
      CMS_unsigned_get_attr_by_NID := FC_CMS_unsigned_get_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_unsigned_get_attr_by_NID_removed)}
    if CMS_unsigned_get_attr_by_NID_removed <= LibVersion then
    begin
      {$if declared(_CMS_unsigned_get_attr_by_NID)}
      CMS_unsigned_get_attr_by_NID := _CMS_unsigned_get_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_unsigned_get_attr_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_unsigned_get_attr_by_NID');
    {$ifend}
  end;
  
  CMS_unsigned_get_attr_by_OBJ := LoadLibFunction(ADllHandle, CMS_unsigned_get_attr_by_OBJ_procname);
  FuncLoadError := not assigned(CMS_unsigned_get_attr_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(CMS_unsigned_get_attr_by_OBJ_allownil)}
    CMS_unsigned_get_attr_by_OBJ := ERR_CMS_unsigned_get_attr_by_OBJ;
    {$ifend}
    {$if declared(CMS_unsigned_get_attr_by_OBJ_introduced)}
    if LibVersion < CMS_unsigned_get_attr_by_OBJ_introduced then
    begin
      {$if declared(FC_CMS_unsigned_get_attr_by_OBJ)}
      CMS_unsigned_get_attr_by_OBJ := FC_CMS_unsigned_get_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_unsigned_get_attr_by_OBJ_removed)}
    if CMS_unsigned_get_attr_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_CMS_unsigned_get_attr_by_OBJ)}
      CMS_unsigned_get_attr_by_OBJ := _CMS_unsigned_get_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_unsigned_get_attr_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_unsigned_get_attr_by_OBJ');
    {$ifend}
  end;
  
  CMS_unsigned_get_attr := LoadLibFunction(ADllHandle, CMS_unsigned_get_attr_procname);
  FuncLoadError := not assigned(CMS_unsigned_get_attr);
  if FuncLoadError then
  begin
    {$if not defined(CMS_unsigned_get_attr_allownil)}
    CMS_unsigned_get_attr := ERR_CMS_unsigned_get_attr;
    {$ifend}
    {$if declared(CMS_unsigned_get_attr_introduced)}
    if LibVersion < CMS_unsigned_get_attr_introduced then
    begin
      {$if declared(FC_CMS_unsigned_get_attr)}
      CMS_unsigned_get_attr := FC_CMS_unsigned_get_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_unsigned_get_attr_removed)}
    if CMS_unsigned_get_attr_removed <= LibVersion then
    begin
      {$if declared(_CMS_unsigned_get_attr)}
      CMS_unsigned_get_attr := _CMS_unsigned_get_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_unsigned_get_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_unsigned_get_attr');
    {$ifend}
  end;
  
  CMS_unsigned_delete_attr := LoadLibFunction(ADllHandle, CMS_unsigned_delete_attr_procname);
  FuncLoadError := not assigned(CMS_unsigned_delete_attr);
  if FuncLoadError then
  begin
    {$if not defined(CMS_unsigned_delete_attr_allownil)}
    CMS_unsigned_delete_attr := ERR_CMS_unsigned_delete_attr;
    {$ifend}
    {$if declared(CMS_unsigned_delete_attr_introduced)}
    if LibVersion < CMS_unsigned_delete_attr_introduced then
    begin
      {$if declared(FC_CMS_unsigned_delete_attr)}
      CMS_unsigned_delete_attr := FC_CMS_unsigned_delete_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_unsigned_delete_attr_removed)}
    if CMS_unsigned_delete_attr_removed <= LibVersion then
    begin
      {$if declared(_CMS_unsigned_delete_attr)}
      CMS_unsigned_delete_attr := _CMS_unsigned_delete_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_unsigned_delete_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_unsigned_delete_attr');
    {$ifend}
  end;
  
  CMS_unsigned_add1_attr := LoadLibFunction(ADllHandle, CMS_unsigned_add1_attr_procname);
  FuncLoadError := not assigned(CMS_unsigned_add1_attr);
  if FuncLoadError then
  begin
    {$if not defined(CMS_unsigned_add1_attr_allownil)}
    CMS_unsigned_add1_attr := ERR_CMS_unsigned_add1_attr;
    {$ifend}
    {$if declared(CMS_unsigned_add1_attr_introduced)}
    if LibVersion < CMS_unsigned_add1_attr_introduced then
    begin
      {$if declared(FC_CMS_unsigned_add1_attr)}
      CMS_unsigned_add1_attr := FC_CMS_unsigned_add1_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_unsigned_add1_attr_removed)}
    if CMS_unsigned_add1_attr_removed <= LibVersion then
    begin
      {$if declared(_CMS_unsigned_add1_attr)}
      CMS_unsigned_add1_attr := _CMS_unsigned_add1_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_unsigned_add1_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_unsigned_add1_attr');
    {$ifend}
  end;
  
  CMS_unsigned_add1_attr_by_OBJ := LoadLibFunction(ADllHandle, CMS_unsigned_add1_attr_by_OBJ_procname);
  FuncLoadError := not assigned(CMS_unsigned_add1_attr_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(CMS_unsigned_add1_attr_by_OBJ_allownil)}
    CMS_unsigned_add1_attr_by_OBJ := ERR_CMS_unsigned_add1_attr_by_OBJ;
    {$ifend}
    {$if declared(CMS_unsigned_add1_attr_by_OBJ_introduced)}
    if LibVersion < CMS_unsigned_add1_attr_by_OBJ_introduced then
    begin
      {$if declared(FC_CMS_unsigned_add1_attr_by_OBJ)}
      CMS_unsigned_add1_attr_by_OBJ := FC_CMS_unsigned_add1_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_unsigned_add1_attr_by_OBJ_removed)}
    if CMS_unsigned_add1_attr_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_CMS_unsigned_add1_attr_by_OBJ)}
      CMS_unsigned_add1_attr_by_OBJ := _CMS_unsigned_add1_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_unsigned_add1_attr_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_unsigned_add1_attr_by_OBJ');
    {$ifend}
  end;
  
  CMS_unsigned_add1_attr_by_NID := LoadLibFunction(ADllHandle, CMS_unsigned_add1_attr_by_NID_procname);
  FuncLoadError := not assigned(CMS_unsigned_add1_attr_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(CMS_unsigned_add1_attr_by_NID_allownil)}
    CMS_unsigned_add1_attr_by_NID := ERR_CMS_unsigned_add1_attr_by_NID;
    {$ifend}
    {$if declared(CMS_unsigned_add1_attr_by_NID_introduced)}
    if LibVersion < CMS_unsigned_add1_attr_by_NID_introduced then
    begin
      {$if declared(FC_CMS_unsigned_add1_attr_by_NID)}
      CMS_unsigned_add1_attr_by_NID := FC_CMS_unsigned_add1_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_unsigned_add1_attr_by_NID_removed)}
    if CMS_unsigned_add1_attr_by_NID_removed <= LibVersion then
    begin
      {$if declared(_CMS_unsigned_add1_attr_by_NID)}
      CMS_unsigned_add1_attr_by_NID := _CMS_unsigned_add1_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_unsigned_add1_attr_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_unsigned_add1_attr_by_NID');
    {$ifend}
  end;
  
  CMS_unsigned_add1_attr_by_txt := LoadLibFunction(ADllHandle, CMS_unsigned_add1_attr_by_txt_procname);
  FuncLoadError := not assigned(CMS_unsigned_add1_attr_by_txt);
  if FuncLoadError then
  begin
    {$if not defined(CMS_unsigned_add1_attr_by_txt_allownil)}
    CMS_unsigned_add1_attr_by_txt := ERR_CMS_unsigned_add1_attr_by_txt;
    {$ifend}
    {$if declared(CMS_unsigned_add1_attr_by_txt_introduced)}
    if LibVersion < CMS_unsigned_add1_attr_by_txt_introduced then
    begin
      {$if declared(FC_CMS_unsigned_add1_attr_by_txt)}
      CMS_unsigned_add1_attr_by_txt := FC_CMS_unsigned_add1_attr_by_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_unsigned_add1_attr_by_txt_removed)}
    if CMS_unsigned_add1_attr_by_txt_removed <= LibVersion then
    begin
      {$if declared(_CMS_unsigned_add1_attr_by_txt)}
      CMS_unsigned_add1_attr_by_txt := _CMS_unsigned_add1_attr_by_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_unsigned_add1_attr_by_txt_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_unsigned_add1_attr_by_txt');
    {$ifend}
  end;
  
  CMS_unsigned_get0_data_by_OBJ := LoadLibFunction(ADllHandle, CMS_unsigned_get0_data_by_OBJ_procname);
  FuncLoadError := not assigned(CMS_unsigned_get0_data_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(CMS_unsigned_get0_data_by_OBJ_allownil)}
    CMS_unsigned_get0_data_by_OBJ := ERR_CMS_unsigned_get0_data_by_OBJ;
    {$ifend}
    {$if declared(CMS_unsigned_get0_data_by_OBJ_introduced)}
    if LibVersion < CMS_unsigned_get0_data_by_OBJ_introduced then
    begin
      {$if declared(FC_CMS_unsigned_get0_data_by_OBJ)}
      CMS_unsigned_get0_data_by_OBJ := FC_CMS_unsigned_get0_data_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_unsigned_get0_data_by_OBJ_removed)}
    if CMS_unsigned_get0_data_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_CMS_unsigned_get0_data_by_OBJ)}
      CMS_unsigned_get0_data_by_OBJ := _CMS_unsigned_get0_data_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_unsigned_get0_data_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_unsigned_get0_data_by_OBJ');
    {$ifend}
  end;
  
  CMS_get1_ReceiptRequest := LoadLibFunction(ADllHandle, CMS_get1_ReceiptRequest_procname);
  FuncLoadError := not assigned(CMS_get1_ReceiptRequest);
  if FuncLoadError then
  begin
    {$if not defined(CMS_get1_ReceiptRequest_allownil)}
    CMS_get1_ReceiptRequest := ERR_CMS_get1_ReceiptRequest;
    {$ifend}
    {$if declared(CMS_get1_ReceiptRequest_introduced)}
    if LibVersion < CMS_get1_ReceiptRequest_introduced then
    begin
      {$if declared(FC_CMS_get1_ReceiptRequest)}
      CMS_get1_ReceiptRequest := FC_CMS_get1_ReceiptRequest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_get1_ReceiptRequest_removed)}
    if CMS_get1_ReceiptRequest_removed <= LibVersion then
    begin
      {$if declared(_CMS_get1_ReceiptRequest)}
      CMS_get1_ReceiptRequest := _CMS_get1_ReceiptRequest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_get1_ReceiptRequest_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_get1_ReceiptRequest');
    {$ifend}
  end;
  
  CMS_ReceiptRequest_create0 := LoadLibFunction(ADllHandle, CMS_ReceiptRequest_create0_procname);
  FuncLoadError := not assigned(CMS_ReceiptRequest_create0);
  if FuncLoadError then
  begin
    {$if not defined(CMS_ReceiptRequest_create0_allownil)}
    CMS_ReceiptRequest_create0 := ERR_CMS_ReceiptRequest_create0;
    {$ifend}
    {$if declared(CMS_ReceiptRequest_create0_introduced)}
    if LibVersion < CMS_ReceiptRequest_create0_introduced then
    begin
      {$if declared(FC_CMS_ReceiptRequest_create0)}
      CMS_ReceiptRequest_create0 := FC_CMS_ReceiptRequest_create0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_ReceiptRequest_create0_removed)}
    if CMS_ReceiptRequest_create0_removed <= LibVersion then
    begin
      {$if declared(_CMS_ReceiptRequest_create0)}
      CMS_ReceiptRequest_create0 := _CMS_ReceiptRequest_create0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_ReceiptRequest_create0_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_ReceiptRequest_create0');
    {$ifend}
  end;
  
  CMS_ReceiptRequest_create0_ex := LoadLibFunction(ADllHandle, CMS_ReceiptRequest_create0_ex_procname);
  FuncLoadError := not assigned(CMS_ReceiptRequest_create0_ex);
  if FuncLoadError then
  begin
    {$if not defined(CMS_ReceiptRequest_create0_ex_allownil)}
    CMS_ReceiptRequest_create0_ex := ERR_CMS_ReceiptRequest_create0_ex;
    {$ifend}
    {$if declared(CMS_ReceiptRequest_create0_ex_introduced)}
    if LibVersion < CMS_ReceiptRequest_create0_ex_introduced then
    begin
      {$if declared(FC_CMS_ReceiptRequest_create0_ex)}
      CMS_ReceiptRequest_create0_ex := FC_CMS_ReceiptRequest_create0_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_ReceiptRequest_create0_ex_removed)}
    if CMS_ReceiptRequest_create0_ex_removed <= LibVersion then
    begin
      {$if declared(_CMS_ReceiptRequest_create0_ex)}
      CMS_ReceiptRequest_create0_ex := _CMS_ReceiptRequest_create0_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_ReceiptRequest_create0_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_ReceiptRequest_create0_ex');
    {$ifend}
  end;
  
  CMS_add1_ReceiptRequest := LoadLibFunction(ADllHandle, CMS_add1_ReceiptRequest_procname);
  FuncLoadError := not assigned(CMS_add1_ReceiptRequest);
  if FuncLoadError then
  begin
    {$if not defined(CMS_add1_ReceiptRequest_allownil)}
    CMS_add1_ReceiptRequest := ERR_CMS_add1_ReceiptRequest;
    {$ifend}
    {$if declared(CMS_add1_ReceiptRequest_introduced)}
    if LibVersion < CMS_add1_ReceiptRequest_introduced then
    begin
      {$if declared(FC_CMS_add1_ReceiptRequest)}
      CMS_add1_ReceiptRequest := FC_CMS_add1_ReceiptRequest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_add1_ReceiptRequest_removed)}
    if CMS_add1_ReceiptRequest_removed <= LibVersion then
    begin
      {$if declared(_CMS_add1_ReceiptRequest)}
      CMS_add1_ReceiptRequest := _CMS_add1_ReceiptRequest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_add1_ReceiptRequest_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_add1_ReceiptRequest');
    {$ifend}
  end;
  
  CMS_ReceiptRequest_get0_values := LoadLibFunction(ADllHandle, CMS_ReceiptRequest_get0_values_procname);
  FuncLoadError := not assigned(CMS_ReceiptRequest_get0_values);
  if FuncLoadError then
  begin
    {$if not defined(CMS_ReceiptRequest_get0_values_allownil)}
    CMS_ReceiptRequest_get0_values := ERR_CMS_ReceiptRequest_get0_values;
    {$ifend}
    {$if declared(CMS_ReceiptRequest_get0_values_introduced)}
    if LibVersion < CMS_ReceiptRequest_get0_values_introduced then
    begin
      {$if declared(FC_CMS_ReceiptRequest_get0_values)}
      CMS_ReceiptRequest_get0_values := FC_CMS_ReceiptRequest_get0_values;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_ReceiptRequest_get0_values_removed)}
    if CMS_ReceiptRequest_get0_values_removed <= LibVersion then
    begin
      {$if declared(_CMS_ReceiptRequest_get0_values)}
      CMS_ReceiptRequest_get0_values := _CMS_ReceiptRequest_get0_values;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_ReceiptRequest_get0_values_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_ReceiptRequest_get0_values');
    {$ifend}
  end;
  
  CMS_RecipientInfo_kari_get0_alg := LoadLibFunction(ADllHandle, CMS_RecipientInfo_kari_get0_alg_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_kari_get0_alg);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_kari_get0_alg_allownil)}
    CMS_RecipientInfo_kari_get0_alg := ERR_CMS_RecipientInfo_kari_get0_alg;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_get0_alg_introduced)}
    if LibVersion < CMS_RecipientInfo_kari_get0_alg_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_kari_get0_alg)}
      CMS_RecipientInfo_kari_get0_alg := FC_CMS_RecipientInfo_kari_get0_alg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_get0_alg_removed)}
    if CMS_RecipientInfo_kari_get0_alg_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_kari_get0_alg)}
      CMS_RecipientInfo_kari_get0_alg := _CMS_RecipientInfo_kari_get0_alg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_kari_get0_alg_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_kari_get0_alg');
    {$ifend}
  end;
  
  CMS_RecipientInfo_kari_get0_reks := LoadLibFunction(ADllHandle, CMS_RecipientInfo_kari_get0_reks_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_kari_get0_reks);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_kari_get0_reks_allownil)}
    CMS_RecipientInfo_kari_get0_reks := ERR_CMS_RecipientInfo_kari_get0_reks;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_get0_reks_introduced)}
    if LibVersion < CMS_RecipientInfo_kari_get0_reks_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_kari_get0_reks)}
      CMS_RecipientInfo_kari_get0_reks := FC_CMS_RecipientInfo_kari_get0_reks;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_get0_reks_removed)}
    if CMS_RecipientInfo_kari_get0_reks_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_kari_get0_reks)}
      CMS_RecipientInfo_kari_get0_reks := _CMS_RecipientInfo_kari_get0_reks;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_kari_get0_reks_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_kari_get0_reks');
    {$ifend}
  end;
  
  CMS_RecipientInfo_kari_get0_orig_id := LoadLibFunction(ADllHandle, CMS_RecipientInfo_kari_get0_orig_id_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_kari_get0_orig_id);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_kari_get0_orig_id_allownil)}
    CMS_RecipientInfo_kari_get0_orig_id := ERR_CMS_RecipientInfo_kari_get0_orig_id;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_get0_orig_id_introduced)}
    if LibVersion < CMS_RecipientInfo_kari_get0_orig_id_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_kari_get0_orig_id)}
      CMS_RecipientInfo_kari_get0_orig_id := FC_CMS_RecipientInfo_kari_get0_orig_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_get0_orig_id_removed)}
    if CMS_RecipientInfo_kari_get0_orig_id_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_kari_get0_orig_id)}
      CMS_RecipientInfo_kari_get0_orig_id := _CMS_RecipientInfo_kari_get0_orig_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_kari_get0_orig_id_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_kari_get0_orig_id');
    {$ifend}
  end;
  
  CMS_RecipientInfo_kari_orig_id_cmp := LoadLibFunction(ADllHandle, CMS_RecipientInfo_kari_orig_id_cmp_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_kari_orig_id_cmp);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_kari_orig_id_cmp_allownil)}
    CMS_RecipientInfo_kari_orig_id_cmp := ERR_CMS_RecipientInfo_kari_orig_id_cmp;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_orig_id_cmp_introduced)}
    if LibVersion < CMS_RecipientInfo_kari_orig_id_cmp_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_kari_orig_id_cmp)}
      CMS_RecipientInfo_kari_orig_id_cmp := FC_CMS_RecipientInfo_kari_orig_id_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_orig_id_cmp_removed)}
    if CMS_RecipientInfo_kari_orig_id_cmp_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_kari_orig_id_cmp)}
      CMS_RecipientInfo_kari_orig_id_cmp := _CMS_RecipientInfo_kari_orig_id_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_kari_orig_id_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_kari_orig_id_cmp');
    {$ifend}
  end;
  
  CMS_RecipientEncryptedKey_get0_id := LoadLibFunction(ADllHandle, CMS_RecipientEncryptedKey_get0_id_procname);
  FuncLoadError := not assigned(CMS_RecipientEncryptedKey_get0_id);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientEncryptedKey_get0_id_allownil)}
    CMS_RecipientEncryptedKey_get0_id := ERR_CMS_RecipientEncryptedKey_get0_id;
    {$ifend}
    {$if declared(CMS_RecipientEncryptedKey_get0_id_introduced)}
    if LibVersion < CMS_RecipientEncryptedKey_get0_id_introduced then
    begin
      {$if declared(FC_CMS_RecipientEncryptedKey_get0_id)}
      CMS_RecipientEncryptedKey_get0_id := FC_CMS_RecipientEncryptedKey_get0_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientEncryptedKey_get0_id_removed)}
    if CMS_RecipientEncryptedKey_get0_id_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientEncryptedKey_get0_id)}
      CMS_RecipientEncryptedKey_get0_id := _CMS_RecipientEncryptedKey_get0_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientEncryptedKey_get0_id_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientEncryptedKey_get0_id');
    {$ifend}
  end;
  
  CMS_RecipientEncryptedKey_cert_cmp := LoadLibFunction(ADllHandle, CMS_RecipientEncryptedKey_cert_cmp_procname);
  FuncLoadError := not assigned(CMS_RecipientEncryptedKey_cert_cmp);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientEncryptedKey_cert_cmp_allownil)}
    CMS_RecipientEncryptedKey_cert_cmp := ERR_CMS_RecipientEncryptedKey_cert_cmp;
    {$ifend}
    {$if declared(CMS_RecipientEncryptedKey_cert_cmp_introduced)}
    if LibVersion < CMS_RecipientEncryptedKey_cert_cmp_introduced then
    begin
      {$if declared(FC_CMS_RecipientEncryptedKey_cert_cmp)}
      CMS_RecipientEncryptedKey_cert_cmp := FC_CMS_RecipientEncryptedKey_cert_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientEncryptedKey_cert_cmp_removed)}
    if CMS_RecipientEncryptedKey_cert_cmp_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientEncryptedKey_cert_cmp)}
      CMS_RecipientEncryptedKey_cert_cmp := _CMS_RecipientEncryptedKey_cert_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientEncryptedKey_cert_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientEncryptedKey_cert_cmp');
    {$ifend}
  end;
  
  CMS_RecipientInfo_kari_set0_pkey := LoadLibFunction(ADllHandle, CMS_RecipientInfo_kari_set0_pkey_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_kari_set0_pkey);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_kari_set0_pkey_allownil)}
    CMS_RecipientInfo_kari_set0_pkey := ERR_CMS_RecipientInfo_kari_set0_pkey;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_set0_pkey_introduced)}
    if LibVersion < CMS_RecipientInfo_kari_set0_pkey_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_kari_set0_pkey)}
      CMS_RecipientInfo_kari_set0_pkey := FC_CMS_RecipientInfo_kari_set0_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_set0_pkey_removed)}
    if CMS_RecipientInfo_kari_set0_pkey_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_kari_set0_pkey)}
      CMS_RecipientInfo_kari_set0_pkey := _CMS_RecipientInfo_kari_set0_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_kari_set0_pkey_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_kari_set0_pkey');
    {$ifend}
  end;
  
  CMS_RecipientInfo_kari_set0_pkey_and_peer := LoadLibFunction(ADllHandle, CMS_RecipientInfo_kari_set0_pkey_and_peer_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_kari_set0_pkey_and_peer);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_kari_set0_pkey_and_peer_allownil)}
    CMS_RecipientInfo_kari_set0_pkey_and_peer := ERR_CMS_RecipientInfo_kari_set0_pkey_and_peer;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_set0_pkey_and_peer_introduced)}
    if LibVersion < CMS_RecipientInfo_kari_set0_pkey_and_peer_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_kari_set0_pkey_and_peer)}
      CMS_RecipientInfo_kari_set0_pkey_and_peer := FC_CMS_RecipientInfo_kari_set0_pkey_and_peer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_set0_pkey_and_peer_removed)}
    if CMS_RecipientInfo_kari_set0_pkey_and_peer_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_kari_set0_pkey_and_peer)}
      CMS_RecipientInfo_kari_set0_pkey_and_peer := _CMS_RecipientInfo_kari_set0_pkey_and_peer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_kari_set0_pkey_and_peer_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_kari_set0_pkey_and_peer');
    {$ifend}
  end;
  
  CMS_RecipientInfo_kari_get0_ctx := LoadLibFunction(ADllHandle, CMS_RecipientInfo_kari_get0_ctx_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_kari_get0_ctx);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_kari_get0_ctx_allownil)}
    CMS_RecipientInfo_kari_get0_ctx := ERR_CMS_RecipientInfo_kari_get0_ctx;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_get0_ctx_introduced)}
    if LibVersion < CMS_RecipientInfo_kari_get0_ctx_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_kari_get0_ctx)}
      CMS_RecipientInfo_kari_get0_ctx := FC_CMS_RecipientInfo_kari_get0_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_get0_ctx_removed)}
    if CMS_RecipientInfo_kari_get0_ctx_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_kari_get0_ctx)}
      CMS_RecipientInfo_kari_get0_ctx := _CMS_RecipientInfo_kari_get0_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_kari_get0_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_kari_get0_ctx');
    {$ifend}
  end;
  
  CMS_RecipientInfo_kari_decrypt := LoadLibFunction(ADllHandle, CMS_RecipientInfo_kari_decrypt_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_kari_decrypt);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_kari_decrypt_allownil)}
    CMS_RecipientInfo_kari_decrypt := ERR_CMS_RecipientInfo_kari_decrypt;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_decrypt_introduced)}
    if LibVersion < CMS_RecipientInfo_kari_decrypt_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_kari_decrypt)}
      CMS_RecipientInfo_kari_decrypt := FC_CMS_RecipientInfo_kari_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kari_decrypt_removed)}
    if CMS_RecipientInfo_kari_decrypt_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_kari_decrypt)}
      CMS_RecipientInfo_kari_decrypt := _CMS_RecipientInfo_kari_decrypt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_kari_decrypt_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_kari_decrypt');
    {$ifend}
  end;
  
  CMS_SharedInfo_encode := LoadLibFunction(ADllHandle, CMS_SharedInfo_encode_procname);
  FuncLoadError := not assigned(CMS_SharedInfo_encode);
  if FuncLoadError then
  begin
    {$if not defined(CMS_SharedInfo_encode_allownil)}
    CMS_SharedInfo_encode := ERR_CMS_SharedInfo_encode;
    {$ifend}
    {$if declared(CMS_SharedInfo_encode_introduced)}
    if LibVersion < CMS_SharedInfo_encode_introduced then
    begin
      {$if declared(FC_CMS_SharedInfo_encode)}
      CMS_SharedInfo_encode := FC_CMS_SharedInfo_encode;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_SharedInfo_encode_removed)}
    if CMS_SharedInfo_encode_removed <= LibVersion then
    begin
      {$if declared(_CMS_SharedInfo_encode)}
      CMS_SharedInfo_encode := _CMS_SharedInfo_encode;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_SharedInfo_encode_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_SharedInfo_encode');
    {$ifend}
  end;
  
  CMS_RecipientInfo_kemri_cert_cmp := LoadLibFunction(ADllHandle, CMS_RecipientInfo_kemri_cert_cmp_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_kemri_cert_cmp);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_kemri_cert_cmp_allownil)}
    CMS_RecipientInfo_kemri_cert_cmp := ERR_CMS_RecipientInfo_kemri_cert_cmp;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kemri_cert_cmp_introduced)}
    if LibVersion < CMS_RecipientInfo_kemri_cert_cmp_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_kemri_cert_cmp)}
      CMS_RecipientInfo_kemri_cert_cmp := FC_CMS_RecipientInfo_kemri_cert_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kemri_cert_cmp_removed)}
    if CMS_RecipientInfo_kemri_cert_cmp_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_kemri_cert_cmp)}
      CMS_RecipientInfo_kemri_cert_cmp := _CMS_RecipientInfo_kemri_cert_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_kemri_cert_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_kemri_cert_cmp');
    {$ifend}
  end;
  
  CMS_RecipientInfo_kemri_set0_pkey := LoadLibFunction(ADllHandle, CMS_RecipientInfo_kemri_set0_pkey_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_kemri_set0_pkey);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_kemri_set0_pkey_allownil)}
    CMS_RecipientInfo_kemri_set0_pkey := ERR_CMS_RecipientInfo_kemri_set0_pkey;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kemri_set0_pkey_introduced)}
    if LibVersion < CMS_RecipientInfo_kemri_set0_pkey_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_kemri_set0_pkey)}
      CMS_RecipientInfo_kemri_set0_pkey := FC_CMS_RecipientInfo_kemri_set0_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kemri_set0_pkey_removed)}
    if CMS_RecipientInfo_kemri_set0_pkey_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_kemri_set0_pkey)}
      CMS_RecipientInfo_kemri_set0_pkey := _CMS_RecipientInfo_kemri_set0_pkey;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_kemri_set0_pkey_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_kemri_set0_pkey');
    {$ifend}
  end;
  
  CMS_RecipientInfo_kemri_get0_ctx := LoadLibFunction(ADllHandle, CMS_RecipientInfo_kemri_get0_ctx_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_kemri_get0_ctx);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_kemri_get0_ctx_allownil)}
    CMS_RecipientInfo_kemri_get0_ctx := ERR_CMS_RecipientInfo_kemri_get0_ctx;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kemri_get0_ctx_introduced)}
    if LibVersion < CMS_RecipientInfo_kemri_get0_ctx_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_kemri_get0_ctx)}
      CMS_RecipientInfo_kemri_get0_ctx := FC_CMS_RecipientInfo_kemri_get0_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kemri_get0_ctx_removed)}
    if CMS_RecipientInfo_kemri_get0_ctx_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_kemri_get0_ctx)}
      CMS_RecipientInfo_kemri_get0_ctx := _CMS_RecipientInfo_kemri_get0_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_kemri_get0_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_kemri_get0_ctx');
    {$ifend}
  end;
  
  CMS_RecipientInfo_kemri_get0_kdf_alg := LoadLibFunction(ADllHandle, CMS_RecipientInfo_kemri_get0_kdf_alg_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_kemri_get0_kdf_alg);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_kemri_get0_kdf_alg_allownil)}
    CMS_RecipientInfo_kemri_get0_kdf_alg := ERR_CMS_RecipientInfo_kemri_get0_kdf_alg;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kemri_get0_kdf_alg_introduced)}
    if LibVersion < CMS_RecipientInfo_kemri_get0_kdf_alg_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_kemri_get0_kdf_alg)}
      CMS_RecipientInfo_kemri_get0_kdf_alg := FC_CMS_RecipientInfo_kemri_get0_kdf_alg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kemri_get0_kdf_alg_removed)}
    if CMS_RecipientInfo_kemri_get0_kdf_alg_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_kemri_get0_kdf_alg)}
      CMS_RecipientInfo_kemri_get0_kdf_alg := _CMS_RecipientInfo_kemri_get0_kdf_alg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_kemri_get0_kdf_alg_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_kemri_get0_kdf_alg');
    {$ifend}
  end;
  
  CMS_RecipientInfo_kemri_set_ukm := LoadLibFunction(ADllHandle, CMS_RecipientInfo_kemri_set_ukm_procname);
  FuncLoadError := not assigned(CMS_RecipientInfo_kemri_set_ukm);
  if FuncLoadError then
  begin
    {$if not defined(CMS_RecipientInfo_kemri_set_ukm_allownil)}
    CMS_RecipientInfo_kemri_set_ukm := ERR_CMS_RecipientInfo_kemri_set_ukm;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kemri_set_ukm_introduced)}
    if LibVersion < CMS_RecipientInfo_kemri_set_ukm_introduced then
    begin
      {$if declared(FC_CMS_RecipientInfo_kemri_set_ukm)}
      CMS_RecipientInfo_kemri_set_ukm := FC_CMS_RecipientInfo_kemri_set_ukm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(CMS_RecipientInfo_kemri_set_ukm_removed)}
    if CMS_RecipientInfo_kemri_set_ukm_removed <= LibVersion then
    begin
      {$if declared(_CMS_RecipientInfo_kemri_set_ukm)}
      CMS_RecipientInfo_kemri_set_ukm := _CMS_RecipientInfo_kemri_set_ukm;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(CMS_RecipientInfo_kemri_set_ukm_allownil)}
    if FuncLoadError then
      AFailed.Add('CMS_RecipientInfo_kemri_set_ukm');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  CMS_EnvelopedData_it := nil;
  CMS_SignedData_new := nil;
  CMS_SignedData_free := nil;
  CMS_ContentInfo_new := nil;
  CMS_ContentInfo_free := nil;
  d2i_CMS_ContentInfo := nil;
  i2d_CMS_ContentInfo := nil;
  CMS_ContentInfo_it := nil;
  CMS_ReceiptRequest_new := nil;
  CMS_ReceiptRequest_free := nil;
  d2i_CMS_ReceiptRequest := nil;
  i2d_CMS_ReceiptRequest := nil;
  CMS_ReceiptRequest_it := nil;
  CMS_ContentInfo_print_ctx := nil;
  CMS_EnvelopedData_dup := nil;
  CMS_ContentInfo_new_ex := nil;
  CMS_get0_type := nil;
  CMS_dataInit := nil;
  CMS_dataFinal := nil;
  CMS_get0_content := nil;
  CMS_is_detached := nil;
  CMS_set_detached := nil;
  CMS_stream := nil;
  d2i_CMS_bio := nil;
  i2d_CMS_bio := nil;
  BIO_new_CMS := nil;
  i2d_CMS_bio_stream := nil;
  PEM_write_bio_CMS_stream := nil;
  SMIME_read_CMS := nil;
  SMIME_read_CMS_ex := nil;
  SMIME_write_CMS := nil;
  CMS_final := nil;
  CMS_final_digest := nil;
  CMS_sign := nil;
  CMS_sign_ex := nil;
  CMS_sign_receipt := nil;
  CMS_data := nil;
  CMS_data_create := nil;
  CMS_data_create_ex := nil;
  CMS_digest_verify := nil;
  CMS_digest_create := nil;
  CMS_digest_create_ex := nil;
  CMS_EncryptedData_decrypt := nil;
  CMS_EncryptedData_encrypt := nil;
  CMS_EncryptedData_encrypt_ex := nil;
  CMS_EncryptedData_set1_key := nil;
  CMS_verify := nil;
  CMS_verify_receipt := nil;
  CMS_get0_signers := nil;
  CMS_encrypt := nil;
  CMS_encrypt_ex := nil;
  CMS_decrypt := nil;
  CMS_decrypt_set1_pkey := nil;
  CMS_decrypt_set1_pkey_and_peer := nil;
  CMS_decrypt_set1_key := nil;
  CMS_decrypt_set1_password := nil;
  CMS_get0_RecipientInfos := nil;
  CMS_RecipientInfo_type := nil;
  CMS_RecipientInfo_get0_pkey_ctx := nil;
  CMS_AuthEnvelopedData_create := nil;
  CMS_AuthEnvelopedData_create_ex := nil;
  CMS_EnvelopedData_create := nil;
  CMS_EnvelopedData_create_ex := nil;
  CMS_EnvelopedData_decrypt := nil;
  CMS_add1_recipient_cert := nil;
  CMS_add1_recipient := nil;
  CMS_RecipientInfo_set0_pkey := nil;
  CMS_RecipientInfo_ktri_cert_cmp := nil;
  CMS_RecipientInfo_ktri_get0_algs := nil;
  CMS_RecipientInfo_ktri_get0_signer_id := nil;
  CMS_add0_recipient_key := nil;
  CMS_RecipientInfo_kekri_get0_id := nil;
  CMS_RecipientInfo_set0_key := nil;
  CMS_RecipientInfo_kekri_id_cmp := nil;
  CMS_RecipientInfo_set0_password := nil;
  CMS_add0_recipient_password := nil;
  CMS_RecipientInfo_decrypt := nil;
  CMS_RecipientInfo_encrypt := nil;
  CMS_uncompress := nil;
  CMS_compress := nil;
  CMS_set1_eContentType := nil;
  CMS_get0_eContentType := nil;
  CMS_add0_CertificateChoices := nil;
  CMS_add0_cert := nil;
  CMS_add1_cert := nil;
  CMS_get1_certs := nil;
  CMS_add0_RevocationInfoChoice := nil;
  CMS_add0_crl := nil;
  CMS_add1_crl := nil;
  CMS_get1_crls := nil;
  CMS_SignedData_init := nil;
  CMS_add1_signer := nil;
  CMS_SignerInfo_get0_pkey_ctx := nil;
  CMS_SignerInfo_get0_md_ctx := nil;
  CMS_get0_SignerInfos := nil;
  CMS_SignerInfo_set1_signer_cert := nil;
  CMS_SignerInfo_get0_signer_id := nil;
  CMS_SignerInfo_cert_cmp := nil;
  CMS_set1_signers_certs := nil;
  CMS_SignerInfo_get0_algs := nil;
  CMS_SignerInfo_get0_signature := nil;
  CMS_SignerInfo_sign := nil;
  CMS_SignerInfo_verify := nil;
  CMS_SignerInfo_verify_content := nil;
  CMS_SignedData_verify := nil;
  CMS_add_smimecap := nil;
  CMS_add_simple_smimecap := nil;
  CMS_add_standard_smimecap := nil;
  CMS_signed_get_attr_count := nil;
  CMS_signed_get_attr_by_NID := nil;
  CMS_signed_get_attr_by_OBJ := nil;
  CMS_signed_get_attr := nil;
  CMS_signed_delete_attr := nil;
  CMS_signed_add1_attr := nil;
  CMS_signed_add1_attr_by_OBJ := nil;
  CMS_signed_add1_attr_by_NID := nil;
  CMS_signed_add1_attr_by_txt := nil;
  CMS_signed_get0_data_by_OBJ := nil;
  CMS_unsigned_get_attr_count := nil;
  CMS_unsigned_get_attr_by_NID := nil;
  CMS_unsigned_get_attr_by_OBJ := nil;
  CMS_unsigned_get_attr := nil;
  CMS_unsigned_delete_attr := nil;
  CMS_unsigned_add1_attr := nil;
  CMS_unsigned_add1_attr_by_OBJ := nil;
  CMS_unsigned_add1_attr_by_NID := nil;
  CMS_unsigned_add1_attr_by_txt := nil;
  CMS_unsigned_get0_data_by_OBJ := nil;
  CMS_get1_ReceiptRequest := nil;
  CMS_ReceiptRequest_create0 := nil;
  CMS_ReceiptRequest_create0_ex := nil;
  CMS_add1_ReceiptRequest := nil;
  CMS_ReceiptRequest_get0_values := nil;
  CMS_RecipientInfo_kari_get0_alg := nil;
  CMS_RecipientInfo_kari_get0_reks := nil;
  CMS_RecipientInfo_kari_get0_orig_id := nil;
  CMS_RecipientInfo_kari_orig_id_cmp := nil;
  CMS_RecipientEncryptedKey_get0_id := nil;
  CMS_RecipientEncryptedKey_cert_cmp := nil;
  CMS_RecipientInfo_kari_set0_pkey := nil;
  CMS_RecipientInfo_kari_set0_pkey_and_peer := nil;
  CMS_RecipientInfo_kari_get0_ctx := nil;
  CMS_RecipientInfo_kari_decrypt := nil;
  CMS_SharedInfo_encode := nil;
  CMS_RecipientInfo_kemri_cert_cmp := nil;
  CMS_RecipientInfo_kemri_set0_pkey := nil;
  CMS_RecipientInfo_kemri_get0_ctx := nil;
  CMS_RecipientInfo_kemri_get0_kdf_alg := nil;
  CMS_RecipientInfo_kemri_set_ukm := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.