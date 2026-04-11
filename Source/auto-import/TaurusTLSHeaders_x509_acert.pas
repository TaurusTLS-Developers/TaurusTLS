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

unit TaurusTLSHeaders_x509_acert;

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
  PX509_acert_st = ^TX509_acert_st;
  TX509_acert_st =   record end;
  {$EXTERNALSYM PX509_acert_st}

  PX509_acert_info_st = ^TX509_acert_info_st;
  TX509_acert_info_st =   record end;
  {$EXTERNALSYM PX509_acert_info_st}

  Possl_object_digest_info_st = ^Tossl_object_digest_info_st;
  Tossl_object_digest_info_st =   record end;
  {$EXTERNALSYM Possl_object_digest_info_st}

  Possl_issuer_serial_st = ^Tossl_issuer_serial_st;
  Tossl_issuer_serial_st =   record end;
  {$EXTERNALSYM Possl_issuer_serial_st}

  PX509_acert_issuer_v2form_st = ^TX509_acert_issuer_v2form_st;
  TX509_acert_issuer_v2form_st =   record end;
  {$EXTERNALSYM PX509_acert_issuer_v2form_st}

  POSSL_IETF_ATTR_SYNTAX_VALUE_st = ^TOSSL_IETF_ATTR_SYNTAX_VALUE_st;
  TOSSL_IETF_ATTR_SYNTAX_VALUE_st =   record end;
  {$EXTERNALSYM POSSL_IETF_ATTR_SYNTAX_VALUE_st}

  POSSL_IETF_ATTR_SYNTAX_st = ^TOSSL_IETF_ATTR_SYNTAX_st;
  TOSSL_IETF_ATTR_SYNTAX_st =   record end;
  {$EXTERNALSYM POSSL_IETF_ATTR_SYNTAX_st}

  PARGET_CERT_st = ^TARGET_CERT_st;
  TARGET_CERT_st =   record
    targetCertificate: POSSL_ISSUER_SERIAL;
    targetName: PGENERAL_NAME;
    certDigestInfo: POSSL_OBJECT_DIGEST_INFO;
  end;
  {$EXTERNALSYM PARGET_CERT_st}

  { TODO 1 -cID Needs manual mapping (Union or complex type) : Review it and update. }
  // struct TARGET_st {
  //     int type;
  //     union {
  //         GENERAL_NAME *targetName;
  //         GENERAL_NAME *targetGroup;
  //         OSSL_TARGET_CERT *targetCert;
  //     } choice;
  // }


// =============================================================================
// CALLBACK TYPE DECLARATIONS
// =============================================================================
type
  { TODO 1 -cID Anonymous Callback : Promoted from pointer. Review name and placement. }
  // PEM_read_bio_X509_ACERT_cb_cb = function(arg1: PIdAnsiChar; arg2: TIdC_INT; arg3: TIdC_INT; arg4: Pointer): TIdC_INT; cdecl;

// =============================================================================
// CONSTANTS DECLARATIONS
// =============================================================================
const
  X509_ACERT_VERSION_2 = 1;
  OSSL_OBJECT_DIGEST_INFO_PUBLIC_KEY = 0;
  OSSL_OBJECT_DIGEST_INFO_PUBLIC_KEY_CERT = 1;
  OSSL_OBJECT_DIGEST_INFO_OTHER = 2;
  OSSL_IETFAS_OCTETS = 0;
  OSSL_IETFAS_OID = 1;
  OSSL_IETFAS_STRING = 2;
  OSSL_TGT_TARGET_NAME = 0;
  OSSL_TGT_TARGET_GROUP = 1;
  OSSL_TGT_TARGET_CERT = 2;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// DYNMAIC BINDING VARIABLES
// =============================================================================
var

  X509_ACERT_new: function: PX509_ACERT; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_new}

  X509_ACERT_free: procedure(a: PX509_ACERT); cdecl = nil;
  {$EXTERNALSYM X509_ACERT_free}

  d2i_X509_ACERT: function(a: PPX509_ACERT; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_ACERT; cdecl = nil;
  {$EXTERNALSYM d2i_X509_ACERT}

  i2d_X509_ACERT: function(a: PX509_ACERT; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_ACERT}

  X509_ACERT_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_it}

  X509_ACERT_dup: function(a: PX509_ACERT): PX509_ACERT; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_dup}

  X509_ACERT_INFO_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_INFO_it}

  X509_ACERT_INFO_new: function: PX509_ACERT_INFO; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_INFO_new}

  X509_ACERT_INFO_free: procedure(a: PX509_ACERT_INFO); cdecl = nil;
  {$EXTERNALSYM X509_ACERT_INFO_free}

  OSSL_OBJECT_DIGEST_INFO_new: function: POSSL_OBJECT_DIGEST_INFO; cdecl = nil;
  {$EXTERNALSYM OSSL_OBJECT_DIGEST_INFO_new}

  OSSL_OBJECT_DIGEST_INFO_free: procedure(a: POSSL_OBJECT_DIGEST_INFO); cdecl = nil;
  {$EXTERNALSYM OSSL_OBJECT_DIGEST_INFO_free}

  OSSL_ISSUER_SERIAL_new: function: POSSL_ISSUER_SERIAL; cdecl = nil;
  {$EXTERNALSYM OSSL_ISSUER_SERIAL_new}

  OSSL_ISSUER_SERIAL_free: procedure(a: POSSL_ISSUER_SERIAL); cdecl = nil;
  {$EXTERNALSYM OSSL_ISSUER_SERIAL_free}

  X509_ACERT_ISSUER_V2FORM_new: function: PX509_ACERT_ISSUER_V2FORM; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_ISSUER_V2FORM_new}

  X509_ACERT_ISSUER_V2FORM_free: procedure(a: PX509_ACERT_ISSUER_V2FORM); cdecl = nil;
  {$EXTERNALSYM X509_ACERT_ISSUER_V2FORM_free}

  d2i_X509_ACERT_fp: function(fp: PFILE; acert: PPX509_ACERT): PX509_ACERT; cdecl = nil;
  {$EXTERNALSYM d2i_X509_ACERT_fp}

  i2d_X509_ACERT_fp: function(fp: PFILE; acert: PX509_ACERT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_ACERT_fp}

  PEM_read_bio_X509_ACERT: function(_out: PBIO; x: PPX509_ACERT; cb: TPEM_read_bio_X509_ACERT_cb_cb; u: Pointer): PX509_ACERT; cdecl = nil;
  {$EXTERNALSYM PEM_read_bio_X509_ACERT}

  PEM_read_X509_ACERT: function(_out: PFILE; x: PPX509_ACERT; cb: TPEM_read_bio_X509_ACERT_cb_cb; u: Pointer): PX509_ACERT; cdecl = nil;
  {$EXTERNALSYM PEM_read_X509_ACERT}

  PEM_write_bio_X509_ACERT: function(_out: PBIO; x: PX509_ACERT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_bio_X509_ACERT}

  PEM_write_X509_ACERT: function(_out: PFILE; x: PX509_ACERT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM PEM_write_X509_ACERT}

  d2i_X509_ACERT_bio: function(bp: PBIO; acert: PPX509_ACERT): PX509_ACERT; cdecl = nil;
  {$EXTERNALSYM d2i_X509_ACERT_bio}

  i2d_X509_ACERT_bio: function(bp: PBIO; acert: PX509_ACERT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_X509_ACERT_bio}

  X509_ACERT_sign: function(x: PX509_ACERT; pkey: PEVP_PKEY; md: PEVP_MD): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_sign}

  X509_ACERT_sign_ctx: function(x: PX509_ACERT; ctx: PEVP_MD_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_sign_ctx}

  X509_ACERT_verify: function(a: PX509_ACERT; r: PEVP_PKEY): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_verify}

  X509_ACERT_get0_holder_entityName: function(x: PX509_ACERT): PGENERAL_NAMES; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_get0_holder_entityName}

  X509_ACERT_get0_holder_baseCertId: function(x: PX509_ACERT): POSSL_ISSUER_SERIAL; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_get0_holder_baseCertId}

  X509_ACERT_get0_holder_digest: function(x: PX509_ACERT): POSSL_OBJECT_DIGEST_INFO; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_get0_holder_digest}

  X509_ACERT_get0_issuerName: function(x: PX509_ACERT): PX509_NAME; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_get0_issuerName}

  X509_ACERT_get_version: function(x: PX509_ACERT): TIdC_LONG; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_get_version}

  X509_ACERT_get0_signature: procedure(x: PX509_ACERT; psig: PPASN1_BIT_STRING; palg: PPX509_ALGOR); cdecl = nil;
  {$EXTERNALSYM X509_ACERT_get0_signature}

  X509_ACERT_get_signature_nid: function(x: PX509_ACERT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_get_signature_nid}

  X509_ACERT_get0_info_sigalg: function(x: PX509_ACERT): PX509_ALGOR; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_get0_info_sigalg}

  X509_ACERT_get0_serialNumber: function(x: PX509_ACERT): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_get0_serialNumber}

  X509_ACERT_get0_notBefore: function(x: PX509_ACERT): PASN1_TIME; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_get0_notBefore}

  X509_ACERT_get0_notAfter: function(x: PX509_ACERT): PASN1_TIME; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_get0_notAfter}

  X509_ACERT_get0_issuerUID: function(x: PX509_ACERT): PASN1_BIT_STRING; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_get0_issuerUID}

  X509_ACERT_print: function(bp: PBIO; x: PX509_ACERT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_print}

  X509_ACERT_print_ex: function(bp: PBIO; x: PX509_ACERT; nmflags: TIdC_ULONG; cflag: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_print_ex}

  X509_ACERT_get_attr_count: function(x: PX509_ACERT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_get_attr_count}

  X509_ACERT_get_attr_by_NID: function(x: PX509_ACERT; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_get_attr_by_NID}

  X509_ACERT_get_attr_by_OBJ: function(x: PX509_ACERT; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_get_attr_by_OBJ}

  X509_ACERT_get_attr: function(x: PX509_ACERT; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_get_attr}

  X509_ACERT_delete_attr: function(x: PX509_ACERT; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_delete_attr}

  X509_ACERT_get_ext_d2i: function(x: PX509_ACERT; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_get_ext_d2i}

  X509_ACERT_add1_ext_i2d: function(x: PX509_ACERT; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_add1_ext_i2d}

  X509_ACERT_get0_extensions: function(x: PX509_ACERT): Pstack_st_X509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_get0_extensions}

  X509_ACERT_set_version: function(x: PX509_ACERT; version: TIdC_LONG): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_set_version}

  X509_ACERT_set0_holder_entityName: procedure(x: PX509_ACERT; name: PGENERAL_NAMES); cdecl = nil;
  {$EXTERNALSYM X509_ACERT_set0_holder_entityName}

  X509_ACERT_set0_holder_baseCertId: procedure(x: PX509_ACERT; isss: POSSL_ISSUER_SERIAL); cdecl = nil;
  {$EXTERNALSYM X509_ACERT_set0_holder_baseCertId}

  X509_ACERT_set0_holder_digest: procedure(x: PX509_ACERT; dinfo: POSSL_OBJECT_DIGEST_INFO); cdecl = nil;
  {$EXTERNALSYM X509_ACERT_set0_holder_digest}

  X509_ACERT_add1_attr: function(x: PX509_ACERT; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_add1_attr}

  X509_ACERT_add1_attr_by_OBJ: function(x: PX509_ACERT; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_add1_attr_by_OBJ}

  X509_ACERT_add1_attr_by_NID: function(x: PX509_ACERT; nid: TIdC_INT; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_add1_attr_by_NID}

  X509_ACERT_add1_attr_by_txt: function(x: PX509_ACERT; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_add1_attr_by_txt}

  X509_ACERT_add_attr_nconf: function(conf: PCONF; section: PIdAnsiChar; acert: PX509_ACERT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_add_attr_nconf}

  X509_ACERT_set1_issuerName: function(x: PX509_ACERT; name: PX509_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_set1_issuerName}

  X509_ACERT_set1_serialNumber: function(x: PX509_ACERT; serial: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_set1_serialNumber}

  X509_ACERT_set1_notBefore: function(x: PX509_ACERT; time: PASN1_GENERALIZEDTIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_set1_notBefore}

  X509_ACERT_set1_notAfter: function(x: PX509_ACERT; time: PASN1_GENERALIZEDTIME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_ACERT_set1_notAfter}

  OSSL_OBJECT_DIGEST_INFO_get0_digest: procedure(o: POSSL_OBJECT_DIGEST_INFO; digestedObjectType: PIdC_INT; digestAlgorithm: PPX509_ALGOR; digest: PPASN1_BIT_STRING); cdecl = nil;
  {$EXTERNALSYM OSSL_OBJECT_DIGEST_INFO_get0_digest}

  OSSL_OBJECT_DIGEST_INFO_set1_digest: function(o: POSSL_OBJECT_DIGEST_INFO; digestedObjectType: TIdC_INT; digestAlgorithm: PX509_ALGOR; digest: PASN1_BIT_STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_OBJECT_DIGEST_INFO_set1_digest}

  OSSL_ISSUER_SERIAL_get0_issuer: function(isss: POSSL_ISSUER_SERIAL): PX509_NAME; cdecl = nil;
  {$EXTERNALSYM OSSL_ISSUER_SERIAL_get0_issuer}

  OSSL_ISSUER_SERIAL_get0_serial: function(isss: POSSL_ISSUER_SERIAL): PASN1_INTEGER; cdecl = nil;
  {$EXTERNALSYM OSSL_ISSUER_SERIAL_get0_serial}

  OSSL_ISSUER_SERIAL_get0_issuerUID: function(isss: POSSL_ISSUER_SERIAL): PASN1_BIT_STRING; cdecl = nil;
  {$EXTERNALSYM OSSL_ISSUER_SERIAL_get0_issuerUID}

  OSSL_ISSUER_SERIAL_set1_issuer: function(isss: POSSL_ISSUER_SERIAL; issuer: PX509_NAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ISSUER_SERIAL_set1_issuer}

  OSSL_ISSUER_SERIAL_set1_serial: function(isss: POSSL_ISSUER_SERIAL; serial: PASN1_INTEGER): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ISSUER_SERIAL_set1_serial}

  OSSL_ISSUER_SERIAL_set1_issuerUID: function(isss: POSSL_ISSUER_SERIAL; uid: PASN1_BIT_STRING): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_ISSUER_SERIAL_set1_issuerUID}

  OSSL_IETF_ATTR_SYNTAX_VALUE_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_IETF_ATTR_SYNTAX_VALUE_it}

  OSSL_IETF_ATTR_SYNTAX_VALUE_new: function: POSSL_IETF_ATTR_SYNTAX_VALUE; cdecl = nil;
  {$EXTERNALSYM OSSL_IETF_ATTR_SYNTAX_VALUE_new}

  OSSL_IETF_ATTR_SYNTAX_VALUE_free: procedure(a: POSSL_IETF_ATTR_SYNTAX_VALUE); cdecl = nil;
  {$EXTERNALSYM OSSL_IETF_ATTR_SYNTAX_VALUE_free}

  OSSL_IETF_ATTR_SYNTAX_new: function: POSSL_IETF_ATTR_SYNTAX; cdecl = nil;
  {$EXTERNALSYM OSSL_IETF_ATTR_SYNTAX_new}

  OSSL_IETF_ATTR_SYNTAX_free: procedure(a: POSSL_IETF_ATTR_SYNTAX); cdecl = nil;
  {$EXTERNALSYM OSSL_IETF_ATTR_SYNTAX_free}

  d2i_OSSL_IETF_ATTR_SYNTAX: function(a: PPOSSL_IETF_ATTR_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_IETF_ATTR_SYNTAX; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_IETF_ATTR_SYNTAX}

  i2d_OSSL_IETF_ATTR_SYNTAX: function(a: POSSL_IETF_ATTR_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_IETF_ATTR_SYNTAX}

  OSSL_IETF_ATTR_SYNTAX_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_IETF_ATTR_SYNTAX_it}

  OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority: function(a: POSSL_IETF_ATTR_SYNTAX): PGENERAL_NAMES; cdecl = nil;
  {$EXTERNALSYM OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority}

  OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority: procedure(a: POSSL_IETF_ATTR_SYNTAX; names: PGENERAL_NAMES); cdecl = nil;
  {$EXTERNALSYM OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority}

  OSSL_IETF_ATTR_SYNTAX_get_value_num: function(a: POSSL_IETF_ATTR_SYNTAX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_IETF_ATTR_SYNTAX_get_value_num}

  OSSL_IETF_ATTR_SYNTAX_get0_value: function(a: POSSL_IETF_ATTR_SYNTAX; ind: TIdC_INT; _type: PIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM OSSL_IETF_ATTR_SYNTAX_get0_value}

  OSSL_IETF_ATTR_SYNTAX_add1_value: function(a: POSSL_IETF_ATTR_SYNTAX; _type: TIdC_INT; data: Pointer): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_IETF_ATTR_SYNTAX_add1_value}

  OSSL_IETF_ATTR_SYNTAX_print: function(bp: PBIO; a: POSSL_IETF_ATTR_SYNTAX; indent: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM OSSL_IETF_ATTR_SYNTAX_print}

  OSSL_TARGET_new: function: POSSL_TARGET; cdecl = nil;
  {$EXTERNALSYM OSSL_TARGET_new}

  OSSL_TARGET_free: procedure(a: POSSL_TARGET); cdecl = nil;
  {$EXTERNALSYM OSSL_TARGET_free}

  d2i_OSSL_TARGET: function(a: PPOSSL_TARGET; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TARGET; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_TARGET}

  i2d_OSSL_TARGET: function(a: POSSL_TARGET; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_TARGET}

  OSSL_TARGET_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_TARGET_it}

  OSSL_TARGETS_new: function: POSSL_TARGETS; cdecl = nil;
  {$EXTERNALSYM OSSL_TARGETS_new}

  OSSL_TARGETS_free: procedure(a: POSSL_TARGETS); cdecl = nil;
  {$EXTERNALSYM OSSL_TARGETS_free}

  d2i_OSSL_TARGETS: function(a: PPOSSL_TARGETS; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TARGETS; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_TARGETS}

  i2d_OSSL_TARGETS: function(a: POSSL_TARGETS; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_TARGETS}

  OSSL_TARGETS_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_TARGETS_it}

  OSSL_TARGETING_INFORMATION_new: function: POSSL_TARGETING_INFORMATION; cdecl = nil;
  {$EXTERNALSYM OSSL_TARGETING_INFORMATION_new}

  OSSL_TARGETING_INFORMATION_free: procedure(a: POSSL_TARGETING_INFORMATION); cdecl = nil;
  {$EXTERNALSYM OSSL_TARGETING_INFORMATION_free}

  d2i_OSSL_TARGETING_INFORMATION: function(a: PPOSSL_TARGETING_INFORMATION; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TARGETING_INFORMATION; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_TARGETING_INFORMATION}

  i2d_OSSL_TARGETING_INFORMATION: function(a: POSSL_TARGETING_INFORMATION; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_TARGETING_INFORMATION}

  OSSL_TARGETING_INFORMATION_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_TARGETING_INFORMATION_it}

  OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new: function: POSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX; cdecl = nil;
  {$EXTERNALSYM OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new}

  OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free: procedure(a: POSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX); cdecl = nil;
  {$EXTERNALSYM OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free}

  d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX: function(a: PPOSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX; cdecl = nil;
  {$EXTERNALSYM d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX}

  i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX: function(a: POSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX}

  OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it: function: PASN1_ITEM; cdecl = nil;
  {$EXTERNALSYM OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it}

{$ENDIF OPENSSL_STATIC_LINK_MODEL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// STATIC BINDING ROUTINES
// =============================================================================

function X509_ACERT_new: PX509_ACERT; cdecl;
procedure X509_ACERT_free(a: PX509_ACERT); cdecl;
function d2i_X509_ACERT(a: PPX509_ACERT; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_ACERT; cdecl;
function i2d_X509_ACERT(a: PX509_ACERT; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function X509_ACERT_it: PASN1_ITEM; cdecl;
function X509_ACERT_dup(a: PX509_ACERT): PX509_ACERT; cdecl;
function X509_ACERT_INFO_it: PASN1_ITEM; cdecl;
function X509_ACERT_INFO_new: PX509_ACERT_INFO; cdecl;
procedure X509_ACERT_INFO_free(a: PX509_ACERT_INFO); cdecl;
function OSSL_OBJECT_DIGEST_INFO_new: POSSL_OBJECT_DIGEST_INFO; cdecl;
procedure OSSL_OBJECT_DIGEST_INFO_free(a: POSSL_OBJECT_DIGEST_INFO); cdecl;
function OSSL_ISSUER_SERIAL_new: POSSL_ISSUER_SERIAL; cdecl;
procedure OSSL_ISSUER_SERIAL_free(a: POSSL_ISSUER_SERIAL); cdecl;
function X509_ACERT_ISSUER_V2FORM_new: PX509_ACERT_ISSUER_V2FORM; cdecl;
procedure X509_ACERT_ISSUER_V2FORM_free(a: PX509_ACERT_ISSUER_V2FORM); cdecl;
function d2i_X509_ACERT_fp(fp: PFILE; acert: PPX509_ACERT): PX509_ACERT; cdecl;
function i2d_X509_ACERT_fp(fp: PFILE; acert: PX509_ACERT): TIdC_INT; cdecl;
function PEM_read_bio_X509_ACERT(_out: PBIO; x: PPX509_ACERT; cb: TPEM_read_bio_X509_ACERT_cb_cb; u: Pointer): PX509_ACERT; cdecl;
function PEM_read_X509_ACERT(_out: PFILE; x: PPX509_ACERT; cb: TPEM_read_bio_X509_ACERT_cb_cb; u: Pointer): PX509_ACERT; cdecl;
function PEM_write_bio_X509_ACERT(_out: PBIO; x: PX509_ACERT): TIdC_INT; cdecl;
function PEM_write_X509_ACERT(_out: PFILE; x: PX509_ACERT): TIdC_INT; cdecl;
function d2i_X509_ACERT_bio(bp: PBIO; acert: PPX509_ACERT): PX509_ACERT; cdecl;
function i2d_X509_ACERT_bio(bp: PBIO; acert: PX509_ACERT): TIdC_INT; cdecl;
function X509_ACERT_sign(x: PX509_ACERT; pkey: PEVP_PKEY; md: PEVP_MD): TIdC_INT; cdecl;
function X509_ACERT_sign_ctx(x: PX509_ACERT; ctx: PEVP_MD_CTX): TIdC_INT; cdecl;
function X509_ACERT_verify(a: PX509_ACERT; r: PEVP_PKEY): TIdC_INT; cdecl;
function X509_ACERT_get0_holder_entityName(x: PX509_ACERT): PGENERAL_NAMES; cdecl;
function X509_ACERT_get0_holder_baseCertId(x: PX509_ACERT): POSSL_ISSUER_SERIAL; cdecl;
function X509_ACERT_get0_holder_digest(x: PX509_ACERT): POSSL_OBJECT_DIGEST_INFO; cdecl;
function X509_ACERT_get0_issuerName(x: PX509_ACERT): PX509_NAME; cdecl;
function X509_ACERT_get_version(x: PX509_ACERT): TIdC_LONG; cdecl;
procedure X509_ACERT_get0_signature(x: PX509_ACERT; psig: PPASN1_BIT_STRING; palg: PPX509_ALGOR); cdecl;
function X509_ACERT_get_signature_nid(x: PX509_ACERT): TIdC_INT; cdecl;
function X509_ACERT_get0_info_sigalg(x: PX509_ACERT): PX509_ALGOR; cdecl;
function X509_ACERT_get0_serialNumber(x: PX509_ACERT): PASN1_INTEGER; cdecl;
function X509_ACERT_get0_notBefore(x: PX509_ACERT): PASN1_TIME; cdecl;
function X509_ACERT_get0_notAfter(x: PX509_ACERT): PASN1_TIME; cdecl;
function X509_ACERT_get0_issuerUID(x: PX509_ACERT): PASN1_BIT_STRING; cdecl;
function X509_ACERT_print(bp: PBIO; x: PX509_ACERT): TIdC_INT; cdecl;
function X509_ACERT_print_ex(bp: PBIO; x: PX509_ACERT; nmflags: TIdC_ULONG; cflag: TIdC_ULONG): TIdC_INT; cdecl;
function X509_ACERT_get_attr_count(x: PX509_ACERT): TIdC_INT; cdecl;
function X509_ACERT_get_attr_by_NID(x: PX509_ACERT; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function X509_ACERT_get_attr_by_OBJ(x: PX509_ACERT; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl;
function X509_ACERT_get_attr(x: PX509_ACERT; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl;
function X509_ACERT_delete_attr(x: PX509_ACERT; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl;
function X509_ACERT_get_ext_d2i(x: PX509_ACERT; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl;
function X509_ACERT_add1_ext_i2d(x: PX509_ACERT; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl;
function X509_ACERT_get0_extensions(x: PX509_ACERT): Pstack_st_X509_EXTENSION; cdecl;
function X509_ACERT_set_version(x: PX509_ACERT; version: TIdC_LONG): TIdC_INT; cdecl;
procedure X509_ACERT_set0_holder_entityName(x: PX509_ACERT; name: PGENERAL_NAMES); cdecl;
procedure X509_ACERT_set0_holder_baseCertId(x: PX509_ACERT; isss: POSSL_ISSUER_SERIAL); cdecl;
procedure X509_ACERT_set0_holder_digest(x: PX509_ACERT; dinfo: POSSL_OBJECT_DIGEST_INFO); cdecl;
function X509_ACERT_add1_attr(x: PX509_ACERT; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl;
function X509_ACERT_add1_attr_by_OBJ(x: PX509_ACERT; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl;
function X509_ACERT_add1_attr_by_NID(x: PX509_ACERT; nid: TIdC_INT; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl;
function X509_ACERT_add1_attr_by_txt(x: PX509_ACERT; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl;
function X509_ACERT_add_attr_nconf(conf: PCONF; section: PIdAnsiChar; acert: PX509_ACERT): TIdC_INT; cdecl;
function X509_ACERT_set1_issuerName(x: PX509_ACERT; name: PX509_NAME): TIdC_INT; cdecl;
function X509_ACERT_set1_serialNumber(x: PX509_ACERT; serial: PASN1_INTEGER): TIdC_INT; cdecl;
function X509_ACERT_set1_notBefore(x: PX509_ACERT; time: PASN1_GENERALIZEDTIME): TIdC_INT; cdecl;
function X509_ACERT_set1_notAfter(x: PX509_ACERT; time: PASN1_GENERALIZEDTIME): TIdC_INT; cdecl;
procedure OSSL_OBJECT_DIGEST_INFO_get0_digest(o: POSSL_OBJECT_DIGEST_INFO; digestedObjectType: PIdC_INT; digestAlgorithm: PPX509_ALGOR; digest: PPASN1_BIT_STRING); cdecl;
function OSSL_OBJECT_DIGEST_INFO_set1_digest(o: POSSL_OBJECT_DIGEST_INFO; digestedObjectType: TIdC_INT; digestAlgorithm: PX509_ALGOR; digest: PASN1_BIT_STRING): TIdC_INT; cdecl;
function OSSL_ISSUER_SERIAL_get0_issuer(isss: POSSL_ISSUER_SERIAL): PX509_NAME; cdecl;
function OSSL_ISSUER_SERIAL_get0_serial(isss: POSSL_ISSUER_SERIAL): PASN1_INTEGER; cdecl;
function OSSL_ISSUER_SERIAL_get0_issuerUID(isss: POSSL_ISSUER_SERIAL): PASN1_BIT_STRING; cdecl;
function OSSL_ISSUER_SERIAL_set1_issuer(isss: POSSL_ISSUER_SERIAL; issuer: PX509_NAME): TIdC_INT; cdecl;
function OSSL_ISSUER_SERIAL_set1_serial(isss: POSSL_ISSUER_SERIAL; serial: PASN1_INTEGER): TIdC_INT; cdecl;
function OSSL_ISSUER_SERIAL_set1_issuerUID(isss: POSSL_ISSUER_SERIAL; uid: PASN1_BIT_STRING): TIdC_INT; cdecl;
function OSSL_IETF_ATTR_SYNTAX_VALUE_it: PASN1_ITEM; cdecl;
function OSSL_IETF_ATTR_SYNTAX_VALUE_new: POSSL_IETF_ATTR_SYNTAX_VALUE; cdecl;
procedure OSSL_IETF_ATTR_SYNTAX_VALUE_free(a: POSSL_IETF_ATTR_SYNTAX_VALUE); cdecl;
function OSSL_IETF_ATTR_SYNTAX_new: POSSL_IETF_ATTR_SYNTAX; cdecl;
procedure OSSL_IETF_ATTR_SYNTAX_free(a: POSSL_IETF_ATTR_SYNTAX); cdecl;
function d2i_OSSL_IETF_ATTR_SYNTAX(a: PPOSSL_IETF_ATTR_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_IETF_ATTR_SYNTAX; cdecl;
function i2d_OSSL_IETF_ATTR_SYNTAX(a: POSSL_IETF_ATTR_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_IETF_ATTR_SYNTAX_it: PASN1_ITEM; cdecl;
function OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority(a: POSSL_IETF_ATTR_SYNTAX): PGENERAL_NAMES; cdecl;
procedure OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority(a: POSSL_IETF_ATTR_SYNTAX; names: PGENERAL_NAMES); cdecl;
function OSSL_IETF_ATTR_SYNTAX_get_value_num(a: POSSL_IETF_ATTR_SYNTAX): TIdC_INT; cdecl;
function OSSL_IETF_ATTR_SYNTAX_get0_value(a: POSSL_IETF_ATTR_SYNTAX; ind: TIdC_INT; _type: PIdC_INT): Pointer; cdecl;
function OSSL_IETF_ATTR_SYNTAX_add1_value(a: POSSL_IETF_ATTR_SYNTAX; _type: TIdC_INT; data: Pointer): TIdC_INT; cdecl;
function OSSL_IETF_ATTR_SYNTAX_print(bp: PBIO; a: POSSL_IETF_ATTR_SYNTAX; indent: TIdC_INT): TIdC_INT; cdecl;
function OSSL_TARGET_new: POSSL_TARGET; cdecl;
procedure OSSL_TARGET_free(a: POSSL_TARGET); cdecl;
function d2i_OSSL_TARGET(a: PPOSSL_TARGET; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TARGET; cdecl;
function i2d_OSSL_TARGET(a: POSSL_TARGET; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_TARGET_it: PASN1_ITEM; cdecl;
function OSSL_TARGETS_new: POSSL_TARGETS; cdecl;
procedure OSSL_TARGETS_free(a: POSSL_TARGETS); cdecl;
function d2i_OSSL_TARGETS(a: PPOSSL_TARGETS; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TARGETS; cdecl;
function i2d_OSSL_TARGETS(a: POSSL_TARGETS; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_TARGETS_it: PASN1_ITEM; cdecl;
function OSSL_TARGETING_INFORMATION_new: POSSL_TARGETING_INFORMATION; cdecl;
procedure OSSL_TARGETING_INFORMATION_free(a: POSSL_TARGETING_INFORMATION); cdecl;
function d2i_OSSL_TARGETING_INFORMATION(a: PPOSSL_TARGETING_INFORMATION; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TARGETING_INFORMATION; cdecl;
function i2d_OSSL_TARGETING_INFORMATION(a: POSSL_TARGETING_INFORMATION; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_TARGETING_INFORMATION_it: PASN1_ITEM; cdecl;
function OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new: POSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX; cdecl;
procedure OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free(a: POSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX); cdecl;
function d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX(a: PPOSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX; cdecl;
function i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX(a: POSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl;
function OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it: PASN1_ITEM; cdecl;
{$ENDIF OPENSSL_STATIC_LINK_MODEL}

// =============================================================================
// OPENSSL STACK DEFINITIONS
// =============================================================================
type
  { TODO 1 -copenssl stack OSSL_IETF_ATTR_SYNTAX_VALUE definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_OSSL_IETF_ATTR_SYNTAX_VALUE = Pointer;
  {$EXTERNALSYM PSTACK_OF_OSSL_IETF_ATTR_SYNTAX_VALUE}

  { Original Stack Macros for OSSL_IETF_ATTR_SYNTAX_VALUE:
    SKM_DEFINE_STACK_OF_INTERNAL(OSSL_IETF_ATTR_SYNTAX_VALUE, OSSL_IETF_ATTR_SYNTAX_VALUE, OSSL_IETF_ATTR_SYNTAX_VALUE)
    sk_OSSL_IETF_ATTR_SYNTAX_VALUE_num(sk) OPENSSL_sk_num(ossl_check_const_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk))
    sk_OSSL_IETF_ATTR_SYNTAX_VALUE_value(sk, idx) ((OSSL_IETF_ATTR_SYNTAX_VALUE *)OPENSSL_sk_value(ossl_check_const_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), (idx)))
    sk_OSSL_IETF_ATTR_SYNTAX_VALUE_new(cmp) ((STACK_OF(OSSL_IETF_ATTR_SYNTAX_VALUE) *)OPENSSL_sk_new(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_compfunc_type(cmp)))
    sk_OSSL_IETF_ATTR_SYNTAX_VALUE_new_null() ((STACK_OF(OSSL_IETF_ATTR_SYNTAX_VALUE) *)OPENSSL_sk_new_null())
    sk_OSSL_IETF_ATTR_SYNTAX_VALUE_new_reserve(cmp, n) ((STACK_OF(OSSL_IETF_ATTR_SYNTAX_VALUE) *)OPENSSL_sk_new_reserve(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_compfunc_type(cmp), (n)))
    sk_OSSL_IETF_ATTR_SYNTAX_VALUE_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), (n))
    sk_OSSL_IETF_ATTR_SYNTAX_VALUE_free(sk) OPENSSL_sk_free(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk))
    sk_OSSL_IETF_ATTR_SYNTAX_VALUE_zero(sk) OPENSSL_sk_zero(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk))
    sk_OSSL_IETF_ATTR_SYNTAX_VALUE_delete(sk, i) ((OSSL_IETF_ATTR_SYNTAX_VALUE *)OPENSSL_sk_delete(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), (i)))
    sk_OSSL_IETF_ATTR_SYNTAX_VALUE_delete_ptr(sk, ptr) ((OSSL_IETF_ATTR_SYNTAX_VALUE *)OPENSSL_sk_delete_ptr(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_type(ptr)))
    sk_OSSL_IETF_ATTR_SYNTAX_VALUE_push(sk, ptr) OPENSSL_sk_push(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_type(ptr))
    sk_OSSL_IETF_ATTR_SYNTAX_VALUE_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_type(ptr))
    sk_OSSL_IETF_ATTR_SYNTAX_VALUE_pop(sk) ((OSSL_IETF_ATTR_SYNTAX_VALUE *)OPENSSL_sk_pop(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk)))
    sk_OSSL_IETF_ATTR_SYNTAX_VALUE_shift(sk) ((OSSL_IETF_ATTR_SYNTAX_VALUE *)OPENSSL_sk_shift(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk)))
    sk_OSSL_IETF_ATTR_SYNTAX_VALUE_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_freefunc_type(freefunc))
    sk_OSSL_IETF_ATTR_SYNTAX_VALUE_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_type(ptr), (idx))
    sk_OSSL_IETF_ATTR_SYNTAX_VALUE_set(sk, idx, ptr) ((OSSL_IETF_ATTR_SYNTAX_VALUE *)OPENSSL_sk_set(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), (idx), ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_type(ptr)))
    sk_OSSL_IETF_ATTR_SYNTAX_VALUE_find(sk, ptr) OPENSSL_sk_find(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_type(ptr))
    sk_OSSL_IETF_ATTR_SYNTAX_VALUE_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_type(ptr))
    sk_OSSL_IETF_ATTR_SYNTAX_VALUE_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_type(ptr), pnum)
    sk_OSSL_IETF_ATTR_SYNTAX_VALUE_sort(sk) OPENSSL_sk_sort(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk))
    sk_OSSL_IETF_ATTR_SYNTAX_VALUE_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk))
    sk_OSSL_IETF_ATTR_SYNTAX_VALUE_dup(sk) ((STACK_OF(OSSL_IETF_ATTR_SYNTAX_VALUE) *)OPENSSL_sk_dup(ossl_check_const_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk)))
    sk_OSSL_IETF_ATTR_SYNTAX_VALUE_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(OSSL_IETF_ATTR_SYNTAX_VALUE) *)OPENSSL_sk_deep_copy(ossl_check_const_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_copyfunc_type(copyfunc), ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_freefunc_type(freefunc)))
    sk_OSSL_IETF_ATTR_SYNTAX_VALUE_set_cmp_func(sk, cmp) ((sk_OSSL_IETF_ATTR_SYNTAX_VALUE_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_compfunc_type(cmp)))
  }

  { TODO 1 -copenssl stack OSSL_TARGET definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_OSSL_TARGET = Pointer;
  {$EXTERNALSYM PSTACK_OF_OSSL_TARGET}

  { Original Stack Macros for OSSL_TARGET:
    SKM_DEFINE_STACK_OF_INTERNAL(OSSL_TARGET, OSSL_TARGET, OSSL_TARGET)
    sk_OSSL_TARGET_num(sk) OPENSSL_sk_num(ossl_check_const_OSSL_TARGET_sk_type(sk))
    sk_OSSL_TARGET_value(sk, idx) ((OSSL_TARGET *)OPENSSL_sk_value(ossl_check_const_OSSL_TARGET_sk_type(sk), (idx)))
    sk_OSSL_TARGET_new(cmp) ((STACK_OF(OSSL_TARGET) *)OPENSSL_sk_new(ossl_check_OSSL_TARGET_compfunc_type(cmp)))
    sk_OSSL_TARGET_new_null() ((STACK_OF(OSSL_TARGET) *)OPENSSL_sk_new_null())
    sk_OSSL_TARGET_new_reserve(cmp, n) ((STACK_OF(OSSL_TARGET) *)OPENSSL_sk_new_reserve(ossl_check_OSSL_TARGET_compfunc_type(cmp), (n)))
    sk_OSSL_TARGET_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_OSSL_TARGET_sk_type(sk), (n))
    sk_OSSL_TARGET_free(sk) OPENSSL_sk_free(ossl_check_OSSL_TARGET_sk_type(sk))
    sk_OSSL_TARGET_zero(sk) OPENSSL_sk_zero(ossl_check_OSSL_TARGET_sk_type(sk))
    sk_OSSL_TARGET_delete(sk, i) ((OSSL_TARGET *)OPENSSL_sk_delete(ossl_check_OSSL_TARGET_sk_type(sk), (i)))
    sk_OSSL_TARGET_delete_ptr(sk, ptr) ((OSSL_TARGET *)OPENSSL_sk_delete_ptr(ossl_check_OSSL_TARGET_sk_type(sk), ossl_check_OSSL_TARGET_type(ptr)))
    sk_OSSL_TARGET_push(sk, ptr) OPENSSL_sk_push(ossl_check_OSSL_TARGET_sk_type(sk), ossl_check_OSSL_TARGET_type(ptr))
    sk_OSSL_TARGET_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_OSSL_TARGET_sk_type(sk), ossl_check_OSSL_TARGET_type(ptr))
    sk_OSSL_TARGET_pop(sk) ((OSSL_TARGET *)OPENSSL_sk_pop(ossl_check_OSSL_TARGET_sk_type(sk)))
    sk_OSSL_TARGET_shift(sk) ((OSSL_TARGET *)OPENSSL_sk_shift(ossl_check_OSSL_TARGET_sk_type(sk)))
    sk_OSSL_TARGET_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_OSSL_TARGET_sk_type(sk), ossl_check_OSSL_TARGET_freefunc_type(freefunc))
    sk_OSSL_TARGET_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_OSSL_TARGET_sk_type(sk), ossl_check_OSSL_TARGET_type(ptr), (idx))
    sk_OSSL_TARGET_set(sk, idx, ptr) ((OSSL_TARGET *)OPENSSL_sk_set(ossl_check_OSSL_TARGET_sk_type(sk), (idx), ossl_check_OSSL_TARGET_type(ptr)))
    sk_OSSL_TARGET_find(sk, ptr) OPENSSL_sk_find(ossl_check_OSSL_TARGET_sk_type(sk), ossl_check_OSSL_TARGET_type(ptr))
    sk_OSSL_TARGET_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_OSSL_TARGET_sk_type(sk), ossl_check_OSSL_TARGET_type(ptr))
    sk_OSSL_TARGET_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_OSSL_TARGET_sk_type(sk), ossl_check_OSSL_TARGET_type(ptr), pnum)
    sk_OSSL_TARGET_sort(sk) OPENSSL_sk_sort(ossl_check_OSSL_TARGET_sk_type(sk))
    sk_OSSL_TARGET_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_OSSL_TARGET_sk_type(sk))
    sk_OSSL_TARGET_dup(sk) ((STACK_OF(OSSL_TARGET) *)OPENSSL_sk_dup(ossl_check_const_OSSL_TARGET_sk_type(sk)))
    sk_OSSL_TARGET_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(OSSL_TARGET) *)OPENSSL_sk_deep_copy(ossl_check_const_OSSL_TARGET_sk_type(sk), ossl_check_OSSL_TARGET_copyfunc_type(copyfunc), ossl_check_OSSL_TARGET_freefunc_type(freefunc)))
    sk_OSSL_TARGET_set_cmp_func(sk, cmp) ((sk_OSSL_TARGET_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_OSSL_TARGET_sk_type(sk), ossl_check_OSSL_TARGET_compfunc_type(cmp)))
  }

  { TODO 1 -copenssl stack OSSL_TARGETS definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_OSSL_TARGETS = Pointer;
  {$EXTERNALSYM PSTACK_OF_OSSL_TARGETS}

  { Original Stack Macros for OSSL_TARGETS:
    SKM_DEFINE_STACK_OF_INTERNAL(OSSL_TARGETS, OSSL_TARGETS, OSSL_TARGETS)
    sk_OSSL_TARGETS_num(sk) OPENSSL_sk_num(ossl_check_const_OSSL_TARGETS_sk_type(sk))
    sk_OSSL_TARGETS_value(sk, idx) ((OSSL_TARGETS *)OPENSSL_sk_value(ossl_check_const_OSSL_TARGETS_sk_type(sk), (idx)))
    sk_OSSL_TARGETS_new(cmp) ((STACK_OF(OSSL_TARGETS) *)OPENSSL_sk_new(ossl_check_OSSL_TARGETS_compfunc_type(cmp)))
    sk_OSSL_TARGETS_new_null() ((STACK_OF(OSSL_TARGETS) *)OPENSSL_sk_new_null())
    sk_OSSL_TARGETS_new_reserve(cmp, n) ((STACK_OF(OSSL_TARGETS) *)OPENSSL_sk_new_reserve(ossl_check_OSSL_TARGETS_compfunc_type(cmp), (n)))
    sk_OSSL_TARGETS_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_OSSL_TARGETS_sk_type(sk), (n))
    sk_OSSL_TARGETS_free(sk) OPENSSL_sk_free(ossl_check_OSSL_TARGETS_sk_type(sk))
    sk_OSSL_TARGETS_zero(sk) OPENSSL_sk_zero(ossl_check_OSSL_TARGETS_sk_type(sk))
    sk_OSSL_TARGETS_delete(sk, i) ((OSSL_TARGETS *)OPENSSL_sk_delete(ossl_check_OSSL_TARGETS_sk_type(sk), (i)))
    sk_OSSL_TARGETS_delete_ptr(sk, ptr) ((OSSL_TARGETS *)OPENSSL_sk_delete_ptr(ossl_check_OSSL_TARGETS_sk_type(sk), ossl_check_OSSL_TARGETS_type(ptr)))
    sk_OSSL_TARGETS_push(sk, ptr) OPENSSL_sk_push(ossl_check_OSSL_TARGETS_sk_type(sk), ossl_check_OSSL_TARGETS_type(ptr))
    sk_OSSL_TARGETS_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_OSSL_TARGETS_sk_type(sk), ossl_check_OSSL_TARGETS_type(ptr))
    sk_OSSL_TARGETS_pop(sk) ((OSSL_TARGETS *)OPENSSL_sk_pop(ossl_check_OSSL_TARGETS_sk_type(sk)))
    sk_OSSL_TARGETS_shift(sk) ((OSSL_TARGETS *)OPENSSL_sk_shift(ossl_check_OSSL_TARGETS_sk_type(sk)))
    sk_OSSL_TARGETS_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_OSSL_TARGETS_sk_type(sk), ossl_check_OSSL_TARGETS_freefunc_type(freefunc))
    sk_OSSL_TARGETS_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_OSSL_TARGETS_sk_type(sk), ossl_check_OSSL_TARGETS_type(ptr), (idx))
    sk_OSSL_TARGETS_set(sk, idx, ptr) ((OSSL_TARGETS *)OPENSSL_sk_set(ossl_check_OSSL_TARGETS_sk_type(sk), (idx), ossl_check_OSSL_TARGETS_type(ptr)))
    sk_OSSL_TARGETS_find(sk, ptr) OPENSSL_sk_find(ossl_check_OSSL_TARGETS_sk_type(sk), ossl_check_OSSL_TARGETS_type(ptr))
    sk_OSSL_TARGETS_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_OSSL_TARGETS_sk_type(sk), ossl_check_OSSL_TARGETS_type(ptr))
    sk_OSSL_TARGETS_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_OSSL_TARGETS_sk_type(sk), ossl_check_OSSL_TARGETS_type(ptr), pnum)
    sk_OSSL_TARGETS_sort(sk) OPENSSL_sk_sort(ossl_check_OSSL_TARGETS_sk_type(sk))
    sk_OSSL_TARGETS_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_OSSL_TARGETS_sk_type(sk))
    sk_OSSL_TARGETS_dup(sk) ((STACK_OF(OSSL_TARGETS) *)OPENSSL_sk_dup(ossl_check_const_OSSL_TARGETS_sk_type(sk)))
    sk_OSSL_TARGETS_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(OSSL_TARGETS) *)OPENSSL_sk_deep_copy(ossl_check_const_OSSL_TARGETS_sk_type(sk), ossl_check_OSSL_TARGETS_copyfunc_type(copyfunc), ossl_check_OSSL_TARGETS_freefunc_type(freefunc)))
    sk_OSSL_TARGETS_set_cmp_func(sk, cmp) ((sk_OSSL_TARGETS_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_OSSL_TARGETS_sk_type(sk), ossl_check_OSSL_TARGETS_compfunc_type(cmp)))
  }

  { TODO 1 -copenssl stack OSSL_ISSUER_SERIAL definitions : To replace placeholder body with the actual type and callbacks. }
  PSTACK_OF_OSSL_ISSUER_SERIAL = Pointer;
  {$EXTERNALSYM PSTACK_OF_OSSL_ISSUER_SERIAL}

  { Original Stack Macros for OSSL_ISSUER_SERIAL:
    SKM_DEFINE_STACK_OF_INTERNAL(OSSL_ISSUER_SERIAL, OSSL_ISSUER_SERIAL, OSSL_ISSUER_SERIAL)
    sk_OSSL_ISSUER_SERIAL_num(sk) OPENSSL_sk_num(ossl_check_const_OSSL_ISSUER_SERIAL_sk_type(sk))
    sk_OSSL_ISSUER_SERIAL_value(sk, idx) ((OSSL_ISSUER_SERIAL *)OPENSSL_sk_value(ossl_check_const_OSSL_ISSUER_SERIAL_sk_type(sk), (idx)))
    sk_OSSL_ISSUER_SERIAL_new(cmp) ((STACK_OF(OSSL_ISSUER_SERIAL) *)OPENSSL_sk_new(ossl_check_OSSL_ISSUER_SERIAL_compfunc_type(cmp)))
    sk_OSSL_ISSUER_SERIAL_new_null() ((STACK_OF(OSSL_ISSUER_SERIAL) *)OPENSSL_sk_new_null())
    sk_OSSL_ISSUER_SERIAL_new_reserve(cmp, n) ((STACK_OF(OSSL_ISSUER_SERIAL) *)OPENSSL_sk_new_reserve(ossl_check_OSSL_ISSUER_SERIAL_compfunc_type(cmp), (n)))
    sk_OSSL_ISSUER_SERIAL_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk), (n))
    sk_OSSL_ISSUER_SERIAL_free(sk) OPENSSL_sk_free(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk))
    sk_OSSL_ISSUER_SERIAL_zero(sk) OPENSSL_sk_zero(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk))
    sk_OSSL_ISSUER_SERIAL_delete(sk, i) ((OSSL_ISSUER_SERIAL *)OPENSSL_sk_delete(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk), (i)))
    sk_OSSL_ISSUER_SERIAL_delete_ptr(sk, ptr) ((OSSL_ISSUER_SERIAL *)OPENSSL_sk_delete_ptr(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk), ossl_check_OSSL_ISSUER_SERIAL_type(ptr)))
    sk_OSSL_ISSUER_SERIAL_push(sk, ptr) OPENSSL_sk_push(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk), ossl_check_OSSL_ISSUER_SERIAL_type(ptr))
    sk_OSSL_ISSUER_SERIAL_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk), ossl_check_OSSL_ISSUER_SERIAL_type(ptr))
    sk_OSSL_ISSUER_SERIAL_pop(sk) ((OSSL_ISSUER_SERIAL *)OPENSSL_sk_pop(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk)))
    sk_OSSL_ISSUER_SERIAL_shift(sk) ((OSSL_ISSUER_SERIAL *)OPENSSL_sk_shift(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk)))
    sk_OSSL_ISSUER_SERIAL_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk), ossl_check_OSSL_ISSUER_SERIAL_freefunc_type(freefunc))
    sk_OSSL_ISSUER_SERIAL_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk), ossl_check_OSSL_ISSUER_SERIAL_type(ptr), (idx))
    sk_OSSL_ISSUER_SERIAL_set(sk, idx, ptr) ((OSSL_ISSUER_SERIAL *)OPENSSL_sk_set(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk), (idx), ossl_check_OSSL_ISSUER_SERIAL_type(ptr)))
    sk_OSSL_ISSUER_SERIAL_find(sk, ptr) OPENSSL_sk_find(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk), ossl_check_OSSL_ISSUER_SERIAL_type(ptr))
    sk_OSSL_ISSUER_SERIAL_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk), ossl_check_OSSL_ISSUER_SERIAL_type(ptr))
    sk_OSSL_ISSUER_SERIAL_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk), ossl_check_OSSL_ISSUER_SERIAL_type(ptr), pnum)
    sk_OSSL_ISSUER_SERIAL_sort(sk) OPENSSL_sk_sort(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk))
    sk_OSSL_ISSUER_SERIAL_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_OSSL_ISSUER_SERIAL_sk_type(sk))
    sk_OSSL_ISSUER_SERIAL_dup(sk) ((STACK_OF(OSSL_ISSUER_SERIAL) *)OPENSSL_sk_dup(ossl_check_const_OSSL_ISSUER_SERIAL_sk_type(sk)))
    sk_OSSL_ISSUER_SERIAL_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(OSSL_ISSUER_SERIAL) *)OPENSSL_sk_deep_copy(ossl_check_const_OSSL_ISSUER_SERIAL_sk_type(sk), ossl_check_OSSL_ISSUER_SERIAL_copyfunc_type(copyfunc), ossl_check_OSSL_ISSUER_SERIAL_freefunc_type(freefunc)))
    sk_OSSL_ISSUER_SERIAL_set_cmp_func(sk, cmp) ((sk_OSSL_ISSUER_SERIAL_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk), ossl_check_OSSL_ISSUER_SERIAL_compfunc_type(cmp)))
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

function X509_ACERT_new: PX509_ACERT; cdecl external CLibCrypto name 'X509_ACERT_new';
procedure X509_ACERT_free(a: PX509_ACERT); cdecl external CLibCrypto name 'X509_ACERT_free';
function d2i_X509_ACERT(a: PPX509_ACERT; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_ACERT; cdecl external CLibCrypto name 'd2i_X509_ACERT';
function i2d_X509_ACERT(a: PX509_ACERT; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_ACERT';
function X509_ACERT_it: PASN1_ITEM; cdecl external CLibCrypto name 'X509_ACERT_it';
function X509_ACERT_dup(a: PX509_ACERT): PX509_ACERT; cdecl external CLibCrypto name 'X509_ACERT_dup';
function X509_ACERT_INFO_it: PASN1_ITEM; cdecl external CLibCrypto name 'X509_ACERT_INFO_it';
function X509_ACERT_INFO_new: PX509_ACERT_INFO; cdecl external CLibCrypto name 'X509_ACERT_INFO_new';
procedure X509_ACERT_INFO_free(a: PX509_ACERT_INFO); cdecl external CLibCrypto name 'X509_ACERT_INFO_free';
function OSSL_OBJECT_DIGEST_INFO_new: POSSL_OBJECT_DIGEST_INFO; cdecl external CLibCrypto name 'OSSL_OBJECT_DIGEST_INFO_new';
procedure OSSL_OBJECT_DIGEST_INFO_free(a: POSSL_OBJECT_DIGEST_INFO); cdecl external CLibCrypto name 'OSSL_OBJECT_DIGEST_INFO_free';
function OSSL_ISSUER_SERIAL_new: POSSL_ISSUER_SERIAL; cdecl external CLibCrypto name 'OSSL_ISSUER_SERIAL_new';
procedure OSSL_ISSUER_SERIAL_free(a: POSSL_ISSUER_SERIAL); cdecl external CLibCrypto name 'OSSL_ISSUER_SERIAL_free';
function X509_ACERT_ISSUER_V2FORM_new: PX509_ACERT_ISSUER_V2FORM; cdecl external CLibCrypto name 'X509_ACERT_ISSUER_V2FORM_new';
procedure X509_ACERT_ISSUER_V2FORM_free(a: PX509_ACERT_ISSUER_V2FORM); cdecl external CLibCrypto name 'X509_ACERT_ISSUER_V2FORM_free';
function d2i_X509_ACERT_fp(fp: PFILE; acert: PPX509_ACERT): PX509_ACERT; cdecl external CLibCrypto name 'd2i_X509_ACERT_fp';
function i2d_X509_ACERT_fp(fp: PFILE; acert: PX509_ACERT): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_ACERT_fp';
function PEM_read_bio_X509_ACERT(_out: PBIO; x: PPX509_ACERT; cb: TPEM_read_bio_X509_ACERT_cb_cb; u: Pointer): PX509_ACERT; cdecl external CLibCrypto name 'PEM_read_bio_X509_ACERT';
function PEM_read_X509_ACERT(_out: PFILE; x: PPX509_ACERT; cb: TPEM_read_bio_X509_ACERT_cb_cb; u: Pointer): PX509_ACERT; cdecl external CLibCrypto name 'PEM_read_X509_ACERT';
function PEM_write_bio_X509_ACERT(_out: PBIO; x: PX509_ACERT): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_bio_X509_ACERT';
function PEM_write_X509_ACERT(_out: PFILE; x: PX509_ACERT): TIdC_INT; cdecl external CLibCrypto name 'PEM_write_X509_ACERT';
function d2i_X509_ACERT_bio(bp: PBIO; acert: PPX509_ACERT): PX509_ACERT; cdecl external CLibCrypto name 'd2i_X509_ACERT_bio';
function i2d_X509_ACERT_bio(bp: PBIO; acert: PX509_ACERT): TIdC_INT; cdecl external CLibCrypto name 'i2d_X509_ACERT_bio';
function X509_ACERT_sign(x: PX509_ACERT; pkey: PEVP_PKEY; md: PEVP_MD): TIdC_INT; cdecl external CLibCrypto name 'X509_ACERT_sign';
function X509_ACERT_sign_ctx(x: PX509_ACERT; ctx: PEVP_MD_CTX): TIdC_INT; cdecl external CLibCrypto name 'X509_ACERT_sign_ctx';
function X509_ACERT_verify(a: PX509_ACERT; r: PEVP_PKEY): TIdC_INT; cdecl external CLibCrypto name 'X509_ACERT_verify';
function X509_ACERT_get0_holder_entityName(x: PX509_ACERT): PGENERAL_NAMES; cdecl external CLibCrypto name 'X509_ACERT_get0_holder_entityName';
function X509_ACERT_get0_holder_baseCertId(x: PX509_ACERT): POSSL_ISSUER_SERIAL; cdecl external CLibCrypto name 'X509_ACERT_get0_holder_baseCertId';
function X509_ACERT_get0_holder_digest(x: PX509_ACERT): POSSL_OBJECT_DIGEST_INFO; cdecl external CLibCrypto name 'X509_ACERT_get0_holder_digest';
function X509_ACERT_get0_issuerName(x: PX509_ACERT): PX509_NAME; cdecl external CLibCrypto name 'X509_ACERT_get0_issuerName';
function X509_ACERT_get_version(x: PX509_ACERT): TIdC_LONG; cdecl external CLibCrypto name 'X509_ACERT_get_version';
procedure X509_ACERT_get0_signature(x: PX509_ACERT; psig: PPASN1_BIT_STRING; palg: PPX509_ALGOR); cdecl external CLibCrypto name 'X509_ACERT_get0_signature';
function X509_ACERT_get_signature_nid(x: PX509_ACERT): TIdC_INT; cdecl external CLibCrypto name 'X509_ACERT_get_signature_nid';
function X509_ACERT_get0_info_sigalg(x: PX509_ACERT): PX509_ALGOR; cdecl external CLibCrypto name 'X509_ACERT_get0_info_sigalg';
function X509_ACERT_get0_serialNumber(x: PX509_ACERT): PASN1_INTEGER; cdecl external CLibCrypto name 'X509_ACERT_get0_serialNumber';
function X509_ACERT_get0_notBefore(x: PX509_ACERT): PASN1_TIME; cdecl external CLibCrypto name 'X509_ACERT_get0_notBefore';
function X509_ACERT_get0_notAfter(x: PX509_ACERT): PASN1_TIME; cdecl external CLibCrypto name 'X509_ACERT_get0_notAfter';
function X509_ACERT_get0_issuerUID(x: PX509_ACERT): PASN1_BIT_STRING; cdecl external CLibCrypto name 'X509_ACERT_get0_issuerUID';
function X509_ACERT_print(bp: PBIO; x: PX509_ACERT): TIdC_INT; cdecl external CLibCrypto name 'X509_ACERT_print';
function X509_ACERT_print_ex(bp: PBIO; x: PX509_ACERT; nmflags: TIdC_ULONG; cflag: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'X509_ACERT_print_ex';
function X509_ACERT_get_attr_count(x: PX509_ACERT): TIdC_INT; cdecl external CLibCrypto name 'X509_ACERT_get_attr_count';
function X509_ACERT_get_attr_by_NID(x: PX509_ACERT; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_ACERT_get_attr_by_NID';
function X509_ACERT_get_attr_by_OBJ(x: PX509_ACERT; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_ACERT_get_attr_by_OBJ';
function X509_ACERT_get_attr(x: PX509_ACERT; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl external CLibCrypto name 'X509_ACERT_get_attr';
function X509_ACERT_delete_attr(x: PX509_ACERT; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl external CLibCrypto name 'X509_ACERT_delete_attr';
function X509_ACERT_get_ext_d2i(x: PX509_ACERT; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl external CLibCrypto name 'X509_ACERT_get_ext_d2i';
function X509_ACERT_add1_ext_i2d(x: PX509_ACERT; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl external CLibCrypto name 'X509_ACERT_add1_ext_i2d';
function X509_ACERT_get0_extensions(x: PX509_ACERT): Pstack_st_X509_EXTENSION; cdecl external CLibCrypto name 'X509_ACERT_get0_extensions';
function X509_ACERT_set_version(x: PX509_ACERT; version: TIdC_LONG): TIdC_INT; cdecl external CLibCrypto name 'X509_ACERT_set_version';
procedure X509_ACERT_set0_holder_entityName(x: PX509_ACERT; name: PGENERAL_NAMES); cdecl external CLibCrypto name 'X509_ACERT_set0_holder_entityName';
procedure X509_ACERT_set0_holder_baseCertId(x: PX509_ACERT; isss: POSSL_ISSUER_SERIAL); cdecl external CLibCrypto name 'X509_ACERT_set0_holder_baseCertId';
procedure X509_ACERT_set0_holder_digest(x: PX509_ACERT; dinfo: POSSL_OBJECT_DIGEST_INFO); cdecl external CLibCrypto name 'X509_ACERT_set0_holder_digest';
function X509_ACERT_add1_attr(x: PX509_ACERT; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl external CLibCrypto name 'X509_ACERT_add1_attr';
function X509_ACERT_add1_attr_by_OBJ(x: PX509_ACERT; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_ACERT_add1_attr_by_OBJ';
function X509_ACERT_add1_attr_by_NID(x: PX509_ACERT; nid: TIdC_INT; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_ACERT_add1_attr_by_NID';
function X509_ACERT_add1_attr_by_txt(x: PX509_ACERT; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'X509_ACERT_add1_attr_by_txt';
function X509_ACERT_add_attr_nconf(conf: PCONF; section: PIdAnsiChar; acert: PX509_ACERT): TIdC_INT; cdecl external CLibCrypto name 'X509_ACERT_add_attr_nconf';
function X509_ACERT_set1_issuerName(x: PX509_ACERT; name: PX509_NAME): TIdC_INT; cdecl external CLibCrypto name 'X509_ACERT_set1_issuerName';
function X509_ACERT_set1_serialNumber(x: PX509_ACERT; serial: PASN1_INTEGER): TIdC_INT; cdecl external CLibCrypto name 'X509_ACERT_set1_serialNumber';
function X509_ACERT_set1_notBefore(x: PX509_ACERT; time: PASN1_GENERALIZEDTIME): TIdC_INT; cdecl external CLibCrypto name 'X509_ACERT_set1_notBefore';
function X509_ACERT_set1_notAfter(x: PX509_ACERT; time: PASN1_GENERALIZEDTIME): TIdC_INT; cdecl external CLibCrypto name 'X509_ACERT_set1_notAfter';
procedure OSSL_OBJECT_DIGEST_INFO_get0_digest(o: POSSL_OBJECT_DIGEST_INFO; digestedObjectType: PIdC_INT; digestAlgorithm: PPX509_ALGOR; digest: PPASN1_BIT_STRING); cdecl external CLibCrypto name 'OSSL_OBJECT_DIGEST_INFO_get0_digest';
function OSSL_OBJECT_DIGEST_INFO_set1_digest(o: POSSL_OBJECT_DIGEST_INFO; digestedObjectType: TIdC_INT; digestAlgorithm: PX509_ALGOR; digest: PASN1_BIT_STRING): TIdC_INT; cdecl external CLibCrypto name 'OSSL_OBJECT_DIGEST_INFO_set1_digest';
function OSSL_ISSUER_SERIAL_get0_issuer(isss: POSSL_ISSUER_SERIAL): PX509_NAME; cdecl external CLibCrypto name 'OSSL_ISSUER_SERIAL_get0_issuer';
function OSSL_ISSUER_SERIAL_get0_serial(isss: POSSL_ISSUER_SERIAL): PASN1_INTEGER; cdecl external CLibCrypto name 'OSSL_ISSUER_SERIAL_get0_serial';
function OSSL_ISSUER_SERIAL_get0_issuerUID(isss: POSSL_ISSUER_SERIAL): PASN1_BIT_STRING; cdecl external CLibCrypto name 'OSSL_ISSUER_SERIAL_get0_issuerUID';
function OSSL_ISSUER_SERIAL_set1_issuer(isss: POSSL_ISSUER_SERIAL; issuer: PX509_NAME): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ISSUER_SERIAL_set1_issuer';
function OSSL_ISSUER_SERIAL_set1_serial(isss: POSSL_ISSUER_SERIAL; serial: PASN1_INTEGER): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ISSUER_SERIAL_set1_serial';
function OSSL_ISSUER_SERIAL_set1_issuerUID(isss: POSSL_ISSUER_SERIAL; uid: PASN1_BIT_STRING): TIdC_INT; cdecl external CLibCrypto name 'OSSL_ISSUER_SERIAL_set1_issuerUID';
function OSSL_IETF_ATTR_SYNTAX_VALUE_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_IETF_ATTR_SYNTAX_VALUE_it';
function OSSL_IETF_ATTR_SYNTAX_VALUE_new: POSSL_IETF_ATTR_SYNTAX_VALUE; cdecl external CLibCrypto name 'OSSL_IETF_ATTR_SYNTAX_VALUE_new';
procedure OSSL_IETF_ATTR_SYNTAX_VALUE_free(a: POSSL_IETF_ATTR_SYNTAX_VALUE); cdecl external CLibCrypto name 'OSSL_IETF_ATTR_SYNTAX_VALUE_free';
function OSSL_IETF_ATTR_SYNTAX_new: POSSL_IETF_ATTR_SYNTAX; cdecl external CLibCrypto name 'OSSL_IETF_ATTR_SYNTAX_new';
procedure OSSL_IETF_ATTR_SYNTAX_free(a: POSSL_IETF_ATTR_SYNTAX); cdecl external CLibCrypto name 'OSSL_IETF_ATTR_SYNTAX_free';
function d2i_OSSL_IETF_ATTR_SYNTAX(a: PPOSSL_IETF_ATTR_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_IETF_ATTR_SYNTAX; cdecl external CLibCrypto name 'd2i_OSSL_IETF_ATTR_SYNTAX';
function i2d_OSSL_IETF_ATTR_SYNTAX(a: POSSL_IETF_ATTR_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_IETF_ATTR_SYNTAX';
function OSSL_IETF_ATTR_SYNTAX_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_IETF_ATTR_SYNTAX_it';
function OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority(a: POSSL_IETF_ATTR_SYNTAX): PGENERAL_NAMES; cdecl external CLibCrypto name 'OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority';
procedure OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority(a: POSSL_IETF_ATTR_SYNTAX; names: PGENERAL_NAMES); cdecl external CLibCrypto name 'OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority';
function OSSL_IETF_ATTR_SYNTAX_get_value_num(a: POSSL_IETF_ATTR_SYNTAX): TIdC_INT; cdecl external CLibCrypto name 'OSSL_IETF_ATTR_SYNTAX_get_value_num';
function OSSL_IETF_ATTR_SYNTAX_get0_value(a: POSSL_IETF_ATTR_SYNTAX; ind: TIdC_INT; _type: PIdC_INT): Pointer; cdecl external CLibCrypto name 'OSSL_IETF_ATTR_SYNTAX_get0_value';
function OSSL_IETF_ATTR_SYNTAX_add1_value(a: POSSL_IETF_ATTR_SYNTAX; _type: TIdC_INT; data: Pointer): TIdC_INT; cdecl external CLibCrypto name 'OSSL_IETF_ATTR_SYNTAX_add1_value';
function OSSL_IETF_ATTR_SYNTAX_print(bp: PBIO; a: POSSL_IETF_ATTR_SYNTAX; indent: TIdC_INT): TIdC_INT; cdecl external CLibCrypto name 'OSSL_IETF_ATTR_SYNTAX_print';
function OSSL_TARGET_new: POSSL_TARGET; cdecl external CLibCrypto name 'OSSL_TARGET_new';
procedure OSSL_TARGET_free(a: POSSL_TARGET); cdecl external CLibCrypto name 'OSSL_TARGET_free';
function d2i_OSSL_TARGET(a: PPOSSL_TARGET; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TARGET; cdecl external CLibCrypto name 'd2i_OSSL_TARGET';
function i2d_OSSL_TARGET(a: POSSL_TARGET; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_TARGET';
function OSSL_TARGET_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_TARGET_it';
function OSSL_TARGETS_new: POSSL_TARGETS; cdecl external CLibCrypto name 'OSSL_TARGETS_new';
procedure OSSL_TARGETS_free(a: POSSL_TARGETS); cdecl external CLibCrypto name 'OSSL_TARGETS_free';
function d2i_OSSL_TARGETS(a: PPOSSL_TARGETS; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TARGETS; cdecl external CLibCrypto name 'd2i_OSSL_TARGETS';
function i2d_OSSL_TARGETS(a: POSSL_TARGETS; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_TARGETS';
function OSSL_TARGETS_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_TARGETS_it';
function OSSL_TARGETING_INFORMATION_new: POSSL_TARGETING_INFORMATION; cdecl external CLibCrypto name 'OSSL_TARGETING_INFORMATION_new';
procedure OSSL_TARGETING_INFORMATION_free(a: POSSL_TARGETING_INFORMATION); cdecl external CLibCrypto name 'OSSL_TARGETING_INFORMATION_free';
function d2i_OSSL_TARGETING_INFORMATION(a: PPOSSL_TARGETING_INFORMATION; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TARGETING_INFORMATION; cdecl external CLibCrypto name 'd2i_OSSL_TARGETING_INFORMATION';
function i2d_OSSL_TARGETING_INFORMATION(a: POSSL_TARGETING_INFORMATION; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_TARGETING_INFORMATION';
function OSSL_TARGETING_INFORMATION_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_TARGETING_INFORMATION_it';
function OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new: POSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX; cdecl external CLibCrypto name 'OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new';
procedure OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free(a: POSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX); cdecl external CLibCrypto name 'OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free';
function d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX(a: PPOSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX; cdecl external CLibCrypto name 'd2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX';
function i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX(a: POSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl external CLibCrypto name 'i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX';
function OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it: PASN1_ITEM; cdecl external CLibCrypto name 'OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it';
{$ENDIF}

// =============================================================================
// DYNAMIC BINDING ROUTINES CONSTANTS
// =============================================================================

const

  X509_ACERT_new_procname = 'X509_ACERT_new';
  X509_ACERT_new_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_free_procname = 'X509_ACERT_free';
  X509_ACERT_free_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  d2i_X509_ACERT_procname = 'd2i_X509_ACERT';
  d2i_X509_ACERT_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  i2d_X509_ACERT_procname = 'i2d_X509_ACERT';
  i2d_X509_ACERT_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_it_procname = 'X509_ACERT_it';
  X509_ACERT_it_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_dup_procname = 'X509_ACERT_dup';
  X509_ACERT_dup_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_INFO_it_procname = 'X509_ACERT_INFO_it';
  X509_ACERT_INFO_it_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_INFO_new_procname = 'X509_ACERT_INFO_new';
  X509_ACERT_INFO_new_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_INFO_free_procname = 'X509_ACERT_INFO_free';
  X509_ACERT_INFO_free_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_OBJECT_DIGEST_INFO_new_procname = 'OSSL_OBJECT_DIGEST_INFO_new';
  OSSL_OBJECT_DIGEST_INFO_new_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_OBJECT_DIGEST_INFO_free_procname = 'OSSL_OBJECT_DIGEST_INFO_free';
  OSSL_OBJECT_DIGEST_INFO_free_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_ISSUER_SERIAL_new_procname = 'OSSL_ISSUER_SERIAL_new';
  OSSL_ISSUER_SERIAL_new_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_ISSUER_SERIAL_free_procname = 'OSSL_ISSUER_SERIAL_free';
  OSSL_ISSUER_SERIAL_free_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_ISSUER_V2FORM_new_procname = 'X509_ACERT_ISSUER_V2FORM_new';
  X509_ACERT_ISSUER_V2FORM_new_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_ISSUER_V2FORM_free_procname = 'X509_ACERT_ISSUER_V2FORM_free';
  X509_ACERT_ISSUER_V2FORM_free_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  d2i_X509_ACERT_fp_procname = 'd2i_X509_ACERT_fp';
  d2i_X509_ACERT_fp_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  i2d_X509_ACERT_fp_procname = 'i2d_X509_ACERT_fp';
  i2d_X509_ACERT_fp_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  PEM_read_bio_X509_ACERT_procname = 'PEM_read_bio_X509_ACERT';
  PEM_read_bio_X509_ACERT_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  PEM_read_X509_ACERT_procname = 'PEM_read_X509_ACERT';
  PEM_read_X509_ACERT_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  PEM_write_bio_X509_ACERT_procname = 'PEM_write_bio_X509_ACERT';
  PEM_write_bio_X509_ACERT_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  PEM_write_X509_ACERT_procname = 'PEM_write_X509_ACERT';
  PEM_write_X509_ACERT_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  d2i_X509_ACERT_bio_procname = 'd2i_X509_ACERT_bio';
  d2i_X509_ACERT_bio_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  i2d_X509_ACERT_bio_procname = 'i2d_X509_ACERT_bio';
  i2d_X509_ACERT_bio_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_sign_procname = 'X509_ACERT_sign';
  X509_ACERT_sign_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_sign_ctx_procname = 'X509_ACERT_sign_ctx';
  X509_ACERT_sign_ctx_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_verify_procname = 'X509_ACERT_verify';
  X509_ACERT_verify_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_get0_holder_entityName_procname = 'X509_ACERT_get0_holder_entityName';
  X509_ACERT_get0_holder_entityName_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_get0_holder_baseCertId_procname = 'X509_ACERT_get0_holder_baseCertId';
  X509_ACERT_get0_holder_baseCertId_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_get0_holder_digest_procname = 'X509_ACERT_get0_holder_digest';
  X509_ACERT_get0_holder_digest_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_get0_issuerName_procname = 'X509_ACERT_get0_issuerName';
  X509_ACERT_get0_issuerName_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_get_version_procname = 'X509_ACERT_get_version';
  X509_ACERT_get_version_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_get0_signature_procname = 'X509_ACERT_get0_signature';
  X509_ACERT_get0_signature_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_get_signature_nid_procname = 'X509_ACERT_get_signature_nid';
  X509_ACERT_get_signature_nid_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_get0_info_sigalg_procname = 'X509_ACERT_get0_info_sigalg';
  X509_ACERT_get0_info_sigalg_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_get0_serialNumber_procname = 'X509_ACERT_get0_serialNumber';
  X509_ACERT_get0_serialNumber_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_get0_notBefore_procname = 'X509_ACERT_get0_notBefore';
  X509_ACERT_get0_notBefore_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_get0_notAfter_procname = 'X509_ACERT_get0_notAfter';
  X509_ACERT_get0_notAfter_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_get0_issuerUID_procname = 'X509_ACERT_get0_issuerUID';
  X509_ACERT_get0_issuerUID_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_print_procname = 'X509_ACERT_print';
  X509_ACERT_print_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_print_ex_procname = 'X509_ACERT_print_ex';
  X509_ACERT_print_ex_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_get_attr_count_procname = 'X509_ACERT_get_attr_count';
  X509_ACERT_get_attr_count_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_get_attr_by_NID_procname = 'X509_ACERT_get_attr_by_NID';
  X509_ACERT_get_attr_by_NID_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_get_attr_by_OBJ_procname = 'X509_ACERT_get_attr_by_OBJ';
  X509_ACERT_get_attr_by_OBJ_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_get_attr_procname = 'X509_ACERT_get_attr';
  X509_ACERT_get_attr_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_delete_attr_procname = 'X509_ACERT_delete_attr';
  X509_ACERT_delete_attr_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_get_ext_d2i_procname = 'X509_ACERT_get_ext_d2i';
  X509_ACERT_get_ext_d2i_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_add1_ext_i2d_procname = 'X509_ACERT_add1_ext_i2d';
  X509_ACERT_add1_ext_i2d_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_get0_extensions_procname = 'X509_ACERT_get0_extensions';
  X509_ACERT_get0_extensions_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_set_version_procname = 'X509_ACERT_set_version';
  X509_ACERT_set_version_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_set0_holder_entityName_procname = 'X509_ACERT_set0_holder_entityName';
  X509_ACERT_set0_holder_entityName_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_set0_holder_baseCertId_procname = 'X509_ACERT_set0_holder_baseCertId';
  X509_ACERT_set0_holder_baseCertId_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_set0_holder_digest_procname = 'X509_ACERT_set0_holder_digest';
  X509_ACERT_set0_holder_digest_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_add1_attr_procname = 'X509_ACERT_add1_attr';
  X509_ACERT_add1_attr_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_add1_attr_by_OBJ_procname = 'X509_ACERT_add1_attr_by_OBJ';
  X509_ACERT_add1_attr_by_OBJ_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_add1_attr_by_NID_procname = 'X509_ACERT_add1_attr_by_NID';
  X509_ACERT_add1_attr_by_NID_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_add1_attr_by_txt_procname = 'X509_ACERT_add1_attr_by_txt';
  X509_ACERT_add1_attr_by_txt_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_add_attr_nconf_procname = 'X509_ACERT_add_attr_nconf';
  X509_ACERT_add_attr_nconf_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_set1_issuerName_procname = 'X509_ACERT_set1_issuerName';
  X509_ACERT_set1_issuerName_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_set1_serialNumber_procname = 'X509_ACERT_set1_serialNumber';
  X509_ACERT_set1_serialNumber_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_set1_notBefore_procname = 'X509_ACERT_set1_notBefore';
  X509_ACERT_set1_notBefore_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  X509_ACERT_set1_notAfter_procname = 'X509_ACERT_set1_notAfter';
  X509_ACERT_set1_notAfter_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_OBJECT_DIGEST_INFO_get0_digest_procname = 'OSSL_OBJECT_DIGEST_INFO_get0_digest';
  OSSL_OBJECT_DIGEST_INFO_get0_digest_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_OBJECT_DIGEST_INFO_set1_digest_procname = 'OSSL_OBJECT_DIGEST_INFO_set1_digest';
  OSSL_OBJECT_DIGEST_INFO_set1_digest_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_ISSUER_SERIAL_get0_issuer_procname = 'OSSL_ISSUER_SERIAL_get0_issuer';
  OSSL_ISSUER_SERIAL_get0_issuer_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_ISSUER_SERIAL_get0_serial_procname = 'OSSL_ISSUER_SERIAL_get0_serial';
  OSSL_ISSUER_SERIAL_get0_serial_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_ISSUER_SERIAL_get0_issuerUID_procname = 'OSSL_ISSUER_SERIAL_get0_issuerUID';
  OSSL_ISSUER_SERIAL_get0_issuerUID_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_ISSUER_SERIAL_set1_issuer_procname = 'OSSL_ISSUER_SERIAL_set1_issuer';
  OSSL_ISSUER_SERIAL_set1_issuer_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_ISSUER_SERIAL_set1_serial_procname = 'OSSL_ISSUER_SERIAL_set1_serial';
  OSSL_ISSUER_SERIAL_set1_serial_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_ISSUER_SERIAL_set1_issuerUID_procname = 'OSSL_ISSUER_SERIAL_set1_issuerUID';
  OSSL_ISSUER_SERIAL_set1_issuerUID_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_IETF_ATTR_SYNTAX_VALUE_it_procname = 'OSSL_IETF_ATTR_SYNTAX_VALUE_it';
  OSSL_IETF_ATTR_SYNTAX_VALUE_it_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_IETF_ATTR_SYNTAX_VALUE_new_procname = 'OSSL_IETF_ATTR_SYNTAX_VALUE_new';
  OSSL_IETF_ATTR_SYNTAX_VALUE_new_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_IETF_ATTR_SYNTAX_VALUE_free_procname = 'OSSL_IETF_ATTR_SYNTAX_VALUE_free';
  OSSL_IETF_ATTR_SYNTAX_VALUE_free_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_IETF_ATTR_SYNTAX_new_procname = 'OSSL_IETF_ATTR_SYNTAX_new';
  OSSL_IETF_ATTR_SYNTAX_new_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_IETF_ATTR_SYNTAX_free_procname = 'OSSL_IETF_ATTR_SYNTAX_free';
  OSSL_IETF_ATTR_SYNTAX_free_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  d2i_OSSL_IETF_ATTR_SYNTAX_procname = 'd2i_OSSL_IETF_ATTR_SYNTAX';
  d2i_OSSL_IETF_ATTR_SYNTAX_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  i2d_OSSL_IETF_ATTR_SYNTAX_procname = 'i2d_OSSL_IETF_ATTR_SYNTAX';
  i2d_OSSL_IETF_ATTR_SYNTAX_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_IETF_ATTR_SYNTAX_it_procname = 'OSSL_IETF_ATTR_SYNTAX_it';
  OSSL_IETF_ATTR_SYNTAX_it_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority_procname = 'OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority';
  OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority_procname = 'OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority';
  OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_IETF_ATTR_SYNTAX_get_value_num_procname = 'OSSL_IETF_ATTR_SYNTAX_get_value_num';
  OSSL_IETF_ATTR_SYNTAX_get_value_num_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_IETF_ATTR_SYNTAX_get0_value_procname = 'OSSL_IETF_ATTR_SYNTAX_get0_value';
  OSSL_IETF_ATTR_SYNTAX_get0_value_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_IETF_ATTR_SYNTAX_add1_value_procname = 'OSSL_IETF_ATTR_SYNTAX_add1_value';
  OSSL_IETF_ATTR_SYNTAX_add1_value_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_IETF_ATTR_SYNTAX_print_procname = 'OSSL_IETF_ATTR_SYNTAX_print';
  OSSL_IETF_ATTR_SYNTAX_print_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_TARGET_new_procname = 'OSSL_TARGET_new';
  OSSL_TARGET_new_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_TARGET_free_procname = 'OSSL_TARGET_free';
  OSSL_TARGET_free_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  d2i_OSSL_TARGET_procname = 'd2i_OSSL_TARGET';
  d2i_OSSL_TARGET_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  i2d_OSSL_TARGET_procname = 'i2d_OSSL_TARGET';
  i2d_OSSL_TARGET_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_TARGET_it_procname = 'OSSL_TARGET_it';
  OSSL_TARGET_it_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_TARGETS_new_procname = 'OSSL_TARGETS_new';
  OSSL_TARGETS_new_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_TARGETS_free_procname = 'OSSL_TARGETS_free';
  OSSL_TARGETS_free_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  d2i_OSSL_TARGETS_procname = 'd2i_OSSL_TARGETS';
  d2i_OSSL_TARGETS_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  i2d_OSSL_TARGETS_procname = 'i2d_OSSL_TARGETS';
  i2d_OSSL_TARGETS_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_TARGETS_it_procname = 'OSSL_TARGETS_it';
  OSSL_TARGETS_it_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_TARGETING_INFORMATION_new_procname = 'OSSL_TARGETING_INFORMATION_new';
  OSSL_TARGETING_INFORMATION_new_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_TARGETING_INFORMATION_free_procname = 'OSSL_TARGETING_INFORMATION_free';
  OSSL_TARGETING_INFORMATION_free_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  d2i_OSSL_TARGETING_INFORMATION_procname = 'd2i_OSSL_TARGETING_INFORMATION';
  d2i_OSSL_TARGETING_INFORMATION_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  i2d_OSSL_TARGETING_INFORMATION_procname = 'i2d_OSSL_TARGETING_INFORMATION';
  i2d_OSSL_TARGETING_INFORMATION_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_TARGETING_INFORMATION_it_procname = 'OSSL_TARGETING_INFORMATION_it';
  OSSL_TARGETING_INFORMATION_it_introduced = (byte(3) shl 8 or byte(4)) shl 8 or byte(0);

  OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new_procname = 'OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new';
  OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free_procname = 'OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free';
  OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_procname = 'd2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX';
  d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_procname = 'i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX';
  i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

  OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it_procname = 'OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it';
  OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it_introduced = (byte(3) shl 8 or byte(5)) shl 8 or byte(0);

 

// =============================================================================
// FORWARD and REMOVE COMPATIBILITY IMPLEMENTATIONS
// =============================================================================

{ TODO 1 -cinline forrward and remove compatibility routines : To add required procedures/functions. }

// =============================================================================
// ERRORS STUBS
// =============================================================================

function ERR_X509_ACERT_new: PX509_ACERT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_new_procname);
end;

procedure ERR_X509_ACERT_free(a: PX509_ACERT); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_free_procname);
end;

function ERR_d2i_X509_ACERT(a: PPX509_ACERT; _in: PPIdAnsiChar; len: TIdC_LONG): PX509_ACERT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_ACERT_procname);
end;

function ERR_i2d_X509_ACERT(a: PX509_ACERT; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_ACERT_procname);
end;

function ERR_X509_ACERT_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_it_procname);
end;

function ERR_X509_ACERT_dup(a: PX509_ACERT): PX509_ACERT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_dup_procname);
end;

function ERR_X509_ACERT_INFO_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_INFO_it_procname);
end;

function ERR_X509_ACERT_INFO_new: PX509_ACERT_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_INFO_new_procname);
end;

procedure ERR_X509_ACERT_INFO_free(a: PX509_ACERT_INFO); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_INFO_free_procname);
end;

function ERR_OSSL_OBJECT_DIGEST_INFO_new: POSSL_OBJECT_DIGEST_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_OBJECT_DIGEST_INFO_new_procname);
end;

procedure ERR_OSSL_OBJECT_DIGEST_INFO_free(a: POSSL_OBJECT_DIGEST_INFO); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_OBJECT_DIGEST_INFO_free_procname);
end;

function ERR_OSSL_ISSUER_SERIAL_new: POSSL_ISSUER_SERIAL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ISSUER_SERIAL_new_procname);
end;

procedure ERR_OSSL_ISSUER_SERIAL_free(a: POSSL_ISSUER_SERIAL); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ISSUER_SERIAL_free_procname);
end;

function ERR_X509_ACERT_ISSUER_V2FORM_new: PX509_ACERT_ISSUER_V2FORM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_ISSUER_V2FORM_new_procname);
end;

procedure ERR_X509_ACERT_ISSUER_V2FORM_free(a: PX509_ACERT_ISSUER_V2FORM); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_ISSUER_V2FORM_free_procname);
end;

function ERR_d2i_X509_ACERT_fp(fp: PFILE; acert: PPX509_ACERT): PX509_ACERT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_ACERT_fp_procname);
end;

function ERR_i2d_X509_ACERT_fp(fp: PFILE; acert: PX509_ACERT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_ACERT_fp_procname);
end;

function ERR_PEM_read_bio_X509_ACERT(_out: PBIO; x: PPX509_ACERT; cb: TPEM_read_bio_X509_ACERT_cb_cb; u: Pointer): PX509_ACERT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_bio_X509_ACERT_procname);
end;

function ERR_PEM_read_X509_ACERT(_out: PFILE; x: PPX509_ACERT; cb: TPEM_read_bio_X509_ACERT_cb_cb; u: Pointer): PX509_ACERT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_read_X509_ACERT_procname);
end;

function ERR_PEM_write_bio_X509_ACERT(_out: PBIO; x: PX509_ACERT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_bio_X509_ACERT_procname);
end;

function ERR_PEM_write_X509_ACERT(_out: PFILE; x: PX509_ACERT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PEM_write_X509_ACERT_procname);
end;

function ERR_d2i_X509_ACERT_bio(bp: PBIO; acert: PPX509_ACERT): PX509_ACERT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_X509_ACERT_bio_procname);
end;

function ERR_i2d_X509_ACERT_bio(bp: PBIO; acert: PX509_ACERT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_X509_ACERT_bio_procname);
end;

function ERR_X509_ACERT_sign(x: PX509_ACERT; pkey: PEVP_PKEY; md: PEVP_MD): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_sign_procname);
end;

function ERR_X509_ACERT_sign_ctx(x: PX509_ACERT; ctx: PEVP_MD_CTX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_sign_ctx_procname);
end;

function ERR_X509_ACERT_verify(a: PX509_ACERT; r: PEVP_PKEY): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_verify_procname);
end;

function ERR_X509_ACERT_get0_holder_entityName(x: PX509_ACERT): PGENERAL_NAMES; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_get0_holder_entityName_procname);
end;

function ERR_X509_ACERT_get0_holder_baseCertId(x: PX509_ACERT): POSSL_ISSUER_SERIAL; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_get0_holder_baseCertId_procname);
end;

function ERR_X509_ACERT_get0_holder_digest(x: PX509_ACERT): POSSL_OBJECT_DIGEST_INFO; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_get0_holder_digest_procname);
end;

function ERR_X509_ACERT_get0_issuerName(x: PX509_ACERT): PX509_NAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_get0_issuerName_procname);
end;

function ERR_X509_ACERT_get_version(x: PX509_ACERT): TIdC_LONG; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_get_version_procname);
end;

procedure ERR_X509_ACERT_get0_signature(x: PX509_ACERT; psig: PPASN1_BIT_STRING; palg: PPX509_ALGOR); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_get0_signature_procname);
end;

function ERR_X509_ACERT_get_signature_nid(x: PX509_ACERT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_get_signature_nid_procname);
end;

function ERR_X509_ACERT_get0_info_sigalg(x: PX509_ACERT): PX509_ALGOR; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_get0_info_sigalg_procname);
end;

function ERR_X509_ACERT_get0_serialNumber(x: PX509_ACERT): PASN1_INTEGER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_get0_serialNumber_procname);
end;

function ERR_X509_ACERT_get0_notBefore(x: PX509_ACERT): PASN1_TIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_get0_notBefore_procname);
end;

function ERR_X509_ACERT_get0_notAfter(x: PX509_ACERT): PASN1_TIME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_get0_notAfter_procname);
end;

function ERR_X509_ACERT_get0_issuerUID(x: PX509_ACERT): PASN1_BIT_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_get0_issuerUID_procname);
end;

function ERR_X509_ACERT_print(bp: PBIO; x: PX509_ACERT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_print_procname);
end;

function ERR_X509_ACERT_print_ex(bp: PBIO; x: PX509_ACERT; nmflags: TIdC_ULONG; cflag: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_print_ex_procname);
end;

function ERR_X509_ACERT_get_attr_count(x: PX509_ACERT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_get_attr_count_procname);
end;

function ERR_X509_ACERT_get_attr_by_NID(x: PX509_ACERT; nid: TIdC_INT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_get_attr_by_NID_procname);
end;

function ERR_X509_ACERT_get_attr_by_OBJ(x: PX509_ACERT; obj: PASN1_OBJECT; lastpos: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_get_attr_by_OBJ_procname);
end;

function ERR_X509_ACERT_get_attr(x: PX509_ACERT; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_get_attr_procname);
end;

function ERR_X509_ACERT_delete_attr(x: PX509_ACERT; loc: TIdC_INT): PX509_ATTRIBUTE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_delete_attr_procname);
end;

function ERR_X509_ACERT_get_ext_d2i(x: PX509_ACERT; nid: TIdC_INT; crit: PIdC_INT; idx: PIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_get_ext_d2i_procname);
end;

function ERR_X509_ACERT_add1_ext_i2d(x: PX509_ACERT; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; flags: TIdC_ULONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_add1_ext_i2d_procname);
end;

function ERR_X509_ACERT_get0_extensions(x: PX509_ACERT): Pstack_st_X509_EXTENSION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_get0_extensions_procname);
end;

function ERR_X509_ACERT_set_version(x: PX509_ACERT; version: TIdC_LONG): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_set_version_procname);
end;

procedure ERR_X509_ACERT_set0_holder_entityName(x: PX509_ACERT; name: PGENERAL_NAMES); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_set0_holder_entityName_procname);
end;

procedure ERR_X509_ACERT_set0_holder_baseCertId(x: PX509_ACERT; isss: POSSL_ISSUER_SERIAL); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_set0_holder_baseCertId_procname);
end;

procedure ERR_X509_ACERT_set0_holder_digest(x: PX509_ACERT; dinfo: POSSL_OBJECT_DIGEST_INFO); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_set0_holder_digest_procname);
end;

function ERR_X509_ACERT_add1_attr(x: PX509_ACERT; attr: PX509_ATTRIBUTE): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_add1_attr_procname);
end;

function ERR_X509_ACERT_add1_attr_by_OBJ(x: PX509_ACERT; obj: PASN1_OBJECT; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_add1_attr_by_OBJ_procname);
end;

function ERR_X509_ACERT_add1_attr_by_NID(x: PX509_ACERT; nid: TIdC_INT; _type: TIdC_INT; bytes: Pointer; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_add1_attr_by_NID_procname);
end;

function ERR_X509_ACERT_add1_attr_by_txt(x: PX509_ACERT; attrname: PIdAnsiChar; _type: TIdC_INT; bytes: PIdAnsiChar; len: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_add1_attr_by_txt_procname);
end;

function ERR_X509_ACERT_add_attr_nconf(conf: PCONF; section: PIdAnsiChar; acert: PX509_ACERT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_add_attr_nconf_procname);
end;

function ERR_X509_ACERT_set1_issuerName(x: PX509_ACERT; name: PX509_NAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_set1_issuerName_procname);
end;

function ERR_X509_ACERT_set1_serialNumber(x: PX509_ACERT; serial: PASN1_INTEGER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_set1_serialNumber_procname);
end;

function ERR_X509_ACERT_set1_notBefore(x: PX509_ACERT; time: PASN1_GENERALIZEDTIME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_set1_notBefore_procname);
end;

function ERR_X509_ACERT_set1_notAfter(x: PX509_ACERT; time: PASN1_GENERALIZEDTIME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_ACERT_set1_notAfter_procname);
end;

procedure ERR_OSSL_OBJECT_DIGEST_INFO_get0_digest(o: POSSL_OBJECT_DIGEST_INFO; digestedObjectType: PIdC_INT; digestAlgorithm: PPX509_ALGOR; digest: PPASN1_BIT_STRING); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_OBJECT_DIGEST_INFO_get0_digest_procname);
end;

function ERR_OSSL_OBJECT_DIGEST_INFO_set1_digest(o: POSSL_OBJECT_DIGEST_INFO; digestedObjectType: TIdC_INT; digestAlgorithm: PX509_ALGOR; digest: PASN1_BIT_STRING): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_OBJECT_DIGEST_INFO_set1_digest_procname);
end;

function ERR_OSSL_ISSUER_SERIAL_get0_issuer(isss: POSSL_ISSUER_SERIAL): PX509_NAME; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ISSUER_SERIAL_get0_issuer_procname);
end;

function ERR_OSSL_ISSUER_SERIAL_get0_serial(isss: POSSL_ISSUER_SERIAL): PASN1_INTEGER; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ISSUER_SERIAL_get0_serial_procname);
end;

function ERR_OSSL_ISSUER_SERIAL_get0_issuerUID(isss: POSSL_ISSUER_SERIAL): PASN1_BIT_STRING; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ISSUER_SERIAL_get0_issuerUID_procname);
end;

function ERR_OSSL_ISSUER_SERIAL_set1_issuer(isss: POSSL_ISSUER_SERIAL; issuer: PX509_NAME): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ISSUER_SERIAL_set1_issuer_procname);
end;

function ERR_OSSL_ISSUER_SERIAL_set1_serial(isss: POSSL_ISSUER_SERIAL; serial: PASN1_INTEGER): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ISSUER_SERIAL_set1_serial_procname);
end;

function ERR_OSSL_ISSUER_SERIAL_set1_issuerUID(isss: POSSL_ISSUER_SERIAL; uid: PASN1_BIT_STRING): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_ISSUER_SERIAL_set1_issuerUID_procname);
end;

function ERR_OSSL_IETF_ATTR_SYNTAX_VALUE_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_IETF_ATTR_SYNTAX_VALUE_it_procname);
end;

function ERR_OSSL_IETF_ATTR_SYNTAX_VALUE_new: POSSL_IETF_ATTR_SYNTAX_VALUE; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_IETF_ATTR_SYNTAX_VALUE_new_procname);
end;

procedure ERR_OSSL_IETF_ATTR_SYNTAX_VALUE_free(a: POSSL_IETF_ATTR_SYNTAX_VALUE); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_IETF_ATTR_SYNTAX_VALUE_free_procname);
end;

function ERR_OSSL_IETF_ATTR_SYNTAX_new: POSSL_IETF_ATTR_SYNTAX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_IETF_ATTR_SYNTAX_new_procname);
end;

procedure ERR_OSSL_IETF_ATTR_SYNTAX_free(a: POSSL_IETF_ATTR_SYNTAX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_IETF_ATTR_SYNTAX_free_procname);
end;

function ERR_d2i_OSSL_IETF_ATTR_SYNTAX(a: PPOSSL_IETF_ATTR_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_IETF_ATTR_SYNTAX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_IETF_ATTR_SYNTAX_procname);
end;

function ERR_i2d_OSSL_IETF_ATTR_SYNTAX(a: POSSL_IETF_ATTR_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_IETF_ATTR_SYNTAX_procname);
end;

function ERR_OSSL_IETF_ATTR_SYNTAX_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_IETF_ATTR_SYNTAX_it_procname);
end;

function ERR_OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority(a: POSSL_IETF_ATTR_SYNTAX): PGENERAL_NAMES; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority_procname);
end;

procedure ERR_OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority(a: POSSL_IETF_ATTR_SYNTAX; names: PGENERAL_NAMES); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority_procname);
end;

function ERR_OSSL_IETF_ATTR_SYNTAX_get_value_num(a: POSSL_IETF_ATTR_SYNTAX): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_IETF_ATTR_SYNTAX_get_value_num_procname);
end;

function ERR_OSSL_IETF_ATTR_SYNTAX_get0_value(a: POSSL_IETF_ATTR_SYNTAX; ind: TIdC_INT; _type: PIdC_INT): Pointer; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_IETF_ATTR_SYNTAX_get0_value_procname);
end;

function ERR_OSSL_IETF_ATTR_SYNTAX_add1_value(a: POSSL_IETF_ATTR_SYNTAX; _type: TIdC_INT; data: Pointer): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_IETF_ATTR_SYNTAX_add1_value_procname);
end;

function ERR_OSSL_IETF_ATTR_SYNTAX_print(bp: PBIO; a: POSSL_IETF_ATTR_SYNTAX; indent: TIdC_INT): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_IETF_ATTR_SYNTAX_print_procname);
end;

function ERR_OSSL_TARGET_new: POSSL_TARGET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TARGET_new_procname);
end;

procedure ERR_OSSL_TARGET_free(a: POSSL_TARGET); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TARGET_free_procname);
end;

function ERR_d2i_OSSL_TARGET(a: PPOSSL_TARGET; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TARGET; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_TARGET_procname);
end;

function ERR_i2d_OSSL_TARGET(a: POSSL_TARGET; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_TARGET_procname);
end;

function ERR_OSSL_TARGET_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TARGET_it_procname);
end;

function ERR_OSSL_TARGETS_new: POSSL_TARGETS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TARGETS_new_procname);
end;

procedure ERR_OSSL_TARGETS_free(a: POSSL_TARGETS); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TARGETS_free_procname);
end;

function ERR_d2i_OSSL_TARGETS(a: PPOSSL_TARGETS; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TARGETS; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_TARGETS_procname);
end;

function ERR_i2d_OSSL_TARGETS(a: POSSL_TARGETS; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_TARGETS_procname);
end;

function ERR_OSSL_TARGETS_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TARGETS_it_procname);
end;

function ERR_OSSL_TARGETING_INFORMATION_new: POSSL_TARGETING_INFORMATION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TARGETING_INFORMATION_new_procname);
end;

procedure ERR_OSSL_TARGETING_INFORMATION_free(a: POSSL_TARGETING_INFORMATION); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TARGETING_INFORMATION_free_procname);
end;

function ERR_d2i_OSSL_TARGETING_INFORMATION(a: PPOSSL_TARGETING_INFORMATION; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_TARGETING_INFORMATION; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_TARGETING_INFORMATION_procname);
end;

function ERR_i2d_OSSL_TARGETING_INFORMATION(a: POSSL_TARGETING_INFORMATION; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_TARGETING_INFORMATION_procname);
end;

function ERR_OSSL_TARGETING_INFORMATION_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_TARGETING_INFORMATION_it_procname);
end;

function ERR_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new: POSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new_procname);
end;

procedure ERR_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free(a: POSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX); cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free_procname);
end;

function ERR_d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX(a: PPOSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX; _in: PPIdAnsiChar; len: TIdC_LONG): POSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_procname);
end;

function ERR_i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX(a: POSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX; _out: PPIdAnsiChar): TIdC_INT; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_procname);
end;

function ERR_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it: PASN1_ITEM; cdecl
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it_procname);
end;

 

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT;
  const AFailed: TStringList);
var
  FuncLoadError: Boolean;
begin
  X509_ACERT_new := LoadLibFunction(ADllHandle, X509_ACERT_new_procname);
  FuncLoadError := not assigned(X509_ACERT_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_new_allownil)}
    X509_ACERT_new := ERR_X509_ACERT_new;
    {$ifend}
    {$if declared(X509_ACERT_new_introduced)}
    if LibVersion < X509_ACERT_new_introduced then
    begin
      {$if declared(FC_X509_ACERT_new)}
      X509_ACERT_new := FC_X509_ACERT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_new_removed)}
    if X509_ACERT_new_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_new)}
      X509_ACERT_new := _X509_ACERT_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_new');
    {$ifend}
  end;
  
  X509_ACERT_free := LoadLibFunction(ADllHandle, X509_ACERT_free_procname);
  FuncLoadError := not assigned(X509_ACERT_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_free_allownil)}
    X509_ACERT_free := ERR_X509_ACERT_free;
    {$ifend}
    {$if declared(X509_ACERT_free_introduced)}
    if LibVersion < X509_ACERT_free_introduced then
    begin
      {$if declared(FC_X509_ACERT_free)}
      X509_ACERT_free := FC_X509_ACERT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_free_removed)}
    if X509_ACERT_free_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_free)}
      X509_ACERT_free := _X509_ACERT_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_free');
    {$ifend}
  end;
  
  d2i_X509_ACERT := LoadLibFunction(ADllHandle, d2i_X509_ACERT_procname);
  FuncLoadError := not assigned(d2i_X509_ACERT);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_ACERT_allownil)}
    d2i_X509_ACERT := ERR_d2i_X509_ACERT;
    {$ifend}
    {$if declared(d2i_X509_ACERT_introduced)}
    if LibVersion < d2i_X509_ACERT_introduced then
    begin
      {$if declared(FC_d2i_X509_ACERT)}
      d2i_X509_ACERT := FC_d2i_X509_ACERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_ACERT_removed)}
    if d2i_X509_ACERT_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_ACERT)}
      d2i_X509_ACERT := _d2i_X509_ACERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_ACERT_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_ACERT');
    {$ifend}
  end;
  
  i2d_X509_ACERT := LoadLibFunction(ADllHandle, i2d_X509_ACERT_procname);
  FuncLoadError := not assigned(i2d_X509_ACERT);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_ACERT_allownil)}
    i2d_X509_ACERT := ERR_i2d_X509_ACERT;
    {$ifend}
    {$if declared(i2d_X509_ACERT_introduced)}
    if LibVersion < i2d_X509_ACERT_introduced then
    begin
      {$if declared(FC_i2d_X509_ACERT)}
      i2d_X509_ACERT := FC_i2d_X509_ACERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_ACERT_removed)}
    if i2d_X509_ACERT_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_ACERT)}
      i2d_X509_ACERT := _i2d_X509_ACERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_ACERT_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_ACERT');
    {$ifend}
  end;
  
  X509_ACERT_it := LoadLibFunction(ADllHandle, X509_ACERT_it_procname);
  FuncLoadError := not assigned(X509_ACERT_it);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_it_allownil)}
    X509_ACERT_it := ERR_X509_ACERT_it;
    {$ifend}
    {$if declared(X509_ACERT_it_introduced)}
    if LibVersion < X509_ACERT_it_introduced then
    begin
      {$if declared(FC_X509_ACERT_it)}
      X509_ACERT_it := FC_X509_ACERT_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_it_removed)}
    if X509_ACERT_it_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_it)}
      X509_ACERT_it := _X509_ACERT_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_it_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_it');
    {$ifend}
  end;
  
  X509_ACERT_dup := LoadLibFunction(ADllHandle, X509_ACERT_dup_procname);
  FuncLoadError := not assigned(X509_ACERT_dup);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_dup_allownil)}
    X509_ACERT_dup := ERR_X509_ACERT_dup;
    {$ifend}
    {$if declared(X509_ACERT_dup_introduced)}
    if LibVersion < X509_ACERT_dup_introduced then
    begin
      {$if declared(FC_X509_ACERT_dup)}
      X509_ACERT_dup := FC_X509_ACERT_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_dup_removed)}
    if X509_ACERT_dup_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_dup)}
      X509_ACERT_dup := _X509_ACERT_dup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_dup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_dup');
    {$ifend}
  end;
  
  X509_ACERT_INFO_it := LoadLibFunction(ADllHandle, X509_ACERT_INFO_it_procname);
  FuncLoadError := not assigned(X509_ACERT_INFO_it);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_INFO_it_allownil)}
    X509_ACERT_INFO_it := ERR_X509_ACERT_INFO_it;
    {$ifend}
    {$if declared(X509_ACERT_INFO_it_introduced)}
    if LibVersion < X509_ACERT_INFO_it_introduced then
    begin
      {$if declared(FC_X509_ACERT_INFO_it)}
      X509_ACERT_INFO_it := FC_X509_ACERT_INFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_INFO_it_removed)}
    if X509_ACERT_INFO_it_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_INFO_it)}
      X509_ACERT_INFO_it := _X509_ACERT_INFO_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_INFO_it_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_INFO_it');
    {$ifend}
  end;
  
  X509_ACERT_INFO_new := LoadLibFunction(ADllHandle, X509_ACERT_INFO_new_procname);
  FuncLoadError := not assigned(X509_ACERT_INFO_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_INFO_new_allownil)}
    X509_ACERT_INFO_new := ERR_X509_ACERT_INFO_new;
    {$ifend}
    {$if declared(X509_ACERT_INFO_new_introduced)}
    if LibVersion < X509_ACERT_INFO_new_introduced then
    begin
      {$if declared(FC_X509_ACERT_INFO_new)}
      X509_ACERT_INFO_new := FC_X509_ACERT_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_INFO_new_removed)}
    if X509_ACERT_INFO_new_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_INFO_new)}
      X509_ACERT_INFO_new := _X509_ACERT_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_INFO_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_INFO_new');
    {$ifend}
  end;
  
  X509_ACERT_INFO_free := LoadLibFunction(ADllHandle, X509_ACERT_INFO_free_procname);
  FuncLoadError := not assigned(X509_ACERT_INFO_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_INFO_free_allownil)}
    X509_ACERT_INFO_free := ERR_X509_ACERT_INFO_free;
    {$ifend}
    {$if declared(X509_ACERT_INFO_free_introduced)}
    if LibVersion < X509_ACERT_INFO_free_introduced then
    begin
      {$if declared(FC_X509_ACERT_INFO_free)}
      X509_ACERT_INFO_free := FC_X509_ACERT_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_INFO_free_removed)}
    if X509_ACERT_INFO_free_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_INFO_free)}
      X509_ACERT_INFO_free := _X509_ACERT_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_INFO_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_INFO_free');
    {$ifend}
  end;
  
  OSSL_OBJECT_DIGEST_INFO_new := LoadLibFunction(ADllHandle, OSSL_OBJECT_DIGEST_INFO_new_procname);
  FuncLoadError := not assigned(OSSL_OBJECT_DIGEST_INFO_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_OBJECT_DIGEST_INFO_new_allownil)}
    OSSL_OBJECT_DIGEST_INFO_new := ERR_OSSL_OBJECT_DIGEST_INFO_new;
    {$ifend}
    {$if declared(OSSL_OBJECT_DIGEST_INFO_new_introduced)}
    if LibVersion < OSSL_OBJECT_DIGEST_INFO_new_introduced then
    begin
      {$if declared(FC_OSSL_OBJECT_DIGEST_INFO_new)}
      OSSL_OBJECT_DIGEST_INFO_new := FC_OSSL_OBJECT_DIGEST_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_OBJECT_DIGEST_INFO_new_removed)}
    if OSSL_OBJECT_DIGEST_INFO_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_OBJECT_DIGEST_INFO_new)}
      OSSL_OBJECT_DIGEST_INFO_new := _OSSL_OBJECT_DIGEST_INFO_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_OBJECT_DIGEST_INFO_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_OBJECT_DIGEST_INFO_new');
    {$ifend}
  end;
  
  OSSL_OBJECT_DIGEST_INFO_free := LoadLibFunction(ADllHandle, OSSL_OBJECT_DIGEST_INFO_free_procname);
  FuncLoadError := not assigned(OSSL_OBJECT_DIGEST_INFO_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_OBJECT_DIGEST_INFO_free_allownil)}
    OSSL_OBJECT_DIGEST_INFO_free := ERR_OSSL_OBJECT_DIGEST_INFO_free;
    {$ifend}
    {$if declared(OSSL_OBJECT_DIGEST_INFO_free_introduced)}
    if LibVersion < OSSL_OBJECT_DIGEST_INFO_free_introduced then
    begin
      {$if declared(FC_OSSL_OBJECT_DIGEST_INFO_free)}
      OSSL_OBJECT_DIGEST_INFO_free := FC_OSSL_OBJECT_DIGEST_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_OBJECT_DIGEST_INFO_free_removed)}
    if OSSL_OBJECT_DIGEST_INFO_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_OBJECT_DIGEST_INFO_free)}
      OSSL_OBJECT_DIGEST_INFO_free := _OSSL_OBJECT_DIGEST_INFO_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_OBJECT_DIGEST_INFO_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_OBJECT_DIGEST_INFO_free');
    {$ifend}
  end;
  
  OSSL_ISSUER_SERIAL_new := LoadLibFunction(ADllHandle, OSSL_ISSUER_SERIAL_new_procname);
  FuncLoadError := not assigned(OSSL_ISSUER_SERIAL_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ISSUER_SERIAL_new_allownil)}
    OSSL_ISSUER_SERIAL_new := ERR_OSSL_ISSUER_SERIAL_new;
    {$ifend}
    {$if declared(OSSL_ISSUER_SERIAL_new_introduced)}
    if LibVersion < OSSL_ISSUER_SERIAL_new_introduced then
    begin
      {$if declared(FC_OSSL_ISSUER_SERIAL_new)}
      OSSL_ISSUER_SERIAL_new := FC_OSSL_ISSUER_SERIAL_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ISSUER_SERIAL_new_removed)}
    if OSSL_ISSUER_SERIAL_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ISSUER_SERIAL_new)}
      OSSL_ISSUER_SERIAL_new := _OSSL_ISSUER_SERIAL_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ISSUER_SERIAL_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ISSUER_SERIAL_new');
    {$ifend}
  end;
  
  OSSL_ISSUER_SERIAL_free := LoadLibFunction(ADllHandle, OSSL_ISSUER_SERIAL_free_procname);
  FuncLoadError := not assigned(OSSL_ISSUER_SERIAL_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ISSUER_SERIAL_free_allownil)}
    OSSL_ISSUER_SERIAL_free := ERR_OSSL_ISSUER_SERIAL_free;
    {$ifend}
    {$if declared(OSSL_ISSUER_SERIAL_free_introduced)}
    if LibVersion < OSSL_ISSUER_SERIAL_free_introduced then
    begin
      {$if declared(FC_OSSL_ISSUER_SERIAL_free)}
      OSSL_ISSUER_SERIAL_free := FC_OSSL_ISSUER_SERIAL_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ISSUER_SERIAL_free_removed)}
    if OSSL_ISSUER_SERIAL_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ISSUER_SERIAL_free)}
      OSSL_ISSUER_SERIAL_free := _OSSL_ISSUER_SERIAL_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ISSUER_SERIAL_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ISSUER_SERIAL_free');
    {$ifend}
  end;
  
  X509_ACERT_ISSUER_V2FORM_new := LoadLibFunction(ADllHandle, X509_ACERT_ISSUER_V2FORM_new_procname);
  FuncLoadError := not assigned(X509_ACERT_ISSUER_V2FORM_new);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_ISSUER_V2FORM_new_allownil)}
    X509_ACERT_ISSUER_V2FORM_new := ERR_X509_ACERT_ISSUER_V2FORM_new;
    {$ifend}
    {$if declared(X509_ACERT_ISSUER_V2FORM_new_introduced)}
    if LibVersion < X509_ACERT_ISSUER_V2FORM_new_introduced then
    begin
      {$if declared(FC_X509_ACERT_ISSUER_V2FORM_new)}
      X509_ACERT_ISSUER_V2FORM_new := FC_X509_ACERT_ISSUER_V2FORM_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_ISSUER_V2FORM_new_removed)}
    if X509_ACERT_ISSUER_V2FORM_new_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_ISSUER_V2FORM_new)}
      X509_ACERT_ISSUER_V2FORM_new := _X509_ACERT_ISSUER_V2FORM_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_ISSUER_V2FORM_new_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_ISSUER_V2FORM_new');
    {$ifend}
  end;
  
  X509_ACERT_ISSUER_V2FORM_free := LoadLibFunction(ADllHandle, X509_ACERT_ISSUER_V2FORM_free_procname);
  FuncLoadError := not assigned(X509_ACERT_ISSUER_V2FORM_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_ISSUER_V2FORM_free_allownil)}
    X509_ACERT_ISSUER_V2FORM_free := ERR_X509_ACERT_ISSUER_V2FORM_free;
    {$ifend}
    {$if declared(X509_ACERT_ISSUER_V2FORM_free_introduced)}
    if LibVersion < X509_ACERT_ISSUER_V2FORM_free_introduced then
    begin
      {$if declared(FC_X509_ACERT_ISSUER_V2FORM_free)}
      X509_ACERT_ISSUER_V2FORM_free := FC_X509_ACERT_ISSUER_V2FORM_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_ISSUER_V2FORM_free_removed)}
    if X509_ACERT_ISSUER_V2FORM_free_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_ISSUER_V2FORM_free)}
      X509_ACERT_ISSUER_V2FORM_free := _X509_ACERT_ISSUER_V2FORM_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_ISSUER_V2FORM_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_ISSUER_V2FORM_free');
    {$ifend}
  end;
  
  d2i_X509_ACERT_fp := LoadLibFunction(ADllHandle, d2i_X509_ACERT_fp_procname);
  FuncLoadError := not assigned(d2i_X509_ACERT_fp);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_ACERT_fp_allownil)}
    d2i_X509_ACERT_fp := ERR_d2i_X509_ACERT_fp;
    {$ifend}
    {$if declared(d2i_X509_ACERT_fp_introduced)}
    if LibVersion < d2i_X509_ACERT_fp_introduced then
    begin
      {$if declared(FC_d2i_X509_ACERT_fp)}
      d2i_X509_ACERT_fp := FC_d2i_X509_ACERT_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_ACERT_fp_removed)}
    if d2i_X509_ACERT_fp_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_ACERT_fp)}
      d2i_X509_ACERT_fp := _d2i_X509_ACERT_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_ACERT_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_ACERT_fp');
    {$ifend}
  end;
  
  i2d_X509_ACERT_fp := LoadLibFunction(ADllHandle, i2d_X509_ACERT_fp_procname);
  FuncLoadError := not assigned(i2d_X509_ACERT_fp);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_ACERT_fp_allownil)}
    i2d_X509_ACERT_fp := ERR_i2d_X509_ACERT_fp;
    {$ifend}
    {$if declared(i2d_X509_ACERT_fp_introduced)}
    if LibVersion < i2d_X509_ACERT_fp_introduced then
    begin
      {$if declared(FC_i2d_X509_ACERT_fp)}
      i2d_X509_ACERT_fp := FC_i2d_X509_ACERT_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_ACERT_fp_removed)}
    if i2d_X509_ACERT_fp_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_ACERT_fp)}
      i2d_X509_ACERT_fp := _i2d_X509_ACERT_fp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_ACERT_fp_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_ACERT_fp');
    {$ifend}
  end;
  
  PEM_read_bio_X509_ACERT := LoadLibFunction(ADllHandle, PEM_read_bio_X509_ACERT_procname);
  FuncLoadError := not assigned(PEM_read_bio_X509_ACERT);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_bio_X509_ACERT_allownil)}
    PEM_read_bio_X509_ACERT := ERR_PEM_read_bio_X509_ACERT;
    {$ifend}
    {$if declared(PEM_read_bio_X509_ACERT_introduced)}
    if LibVersion < PEM_read_bio_X509_ACERT_introduced then
    begin
      {$if declared(FC_PEM_read_bio_X509_ACERT)}
      PEM_read_bio_X509_ACERT := FC_PEM_read_bio_X509_ACERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_bio_X509_ACERT_removed)}
    if PEM_read_bio_X509_ACERT_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_bio_X509_ACERT)}
      PEM_read_bio_X509_ACERT := _PEM_read_bio_X509_ACERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_bio_X509_ACERT_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_bio_X509_ACERT');
    {$ifend}
  end;
  
  PEM_read_X509_ACERT := LoadLibFunction(ADllHandle, PEM_read_X509_ACERT_procname);
  FuncLoadError := not assigned(PEM_read_X509_ACERT);
  if FuncLoadError then
  begin
    {$if not defined(PEM_read_X509_ACERT_allownil)}
    PEM_read_X509_ACERT := ERR_PEM_read_X509_ACERT;
    {$ifend}
    {$if declared(PEM_read_X509_ACERT_introduced)}
    if LibVersion < PEM_read_X509_ACERT_introduced then
    begin
      {$if declared(FC_PEM_read_X509_ACERT)}
      PEM_read_X509_ACERT := FC_PEM_read_X509_ACERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_read_X509_ACERT_removed)}
    if PEM_read_X509_ACERT_removed <= LibVersion then
    begin
      {$if declared(_PEM_read_X509_ACERT)}
      PEM_read_X509_ACERT := _PEM_read_X509_ACERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_read_X509_ACERT_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_read_X509_ACERT');
    {$ifend}
  end;
  
  PEM_write_bio_X509_ACERT := LoadLibFunction(ADllHandle, PEM_write_bio_X509_ACERT_procname);
  FuncLoadError := not assigned(PEM_write_bio_X509_ACERT);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_bio_X509_ACERT_allownil)}
    PEM_write_bio_X509_ACERT := ERR_PEM_write_bio_X509_ACERT;
    {$ifend}
    {$if declared(PEM_write_bio_X509_ACERT_introduced)}
    if LibVersion < PEM_write_bio_X509_ACERT_introduced then
    begin
      {$if declared(FC_PEM_write_bio_X509_ACERT)}
      PEM_write_bio_X509_ACERT := FC_PEM_write_bio_X509_ACERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_bio_X509_ACERT_removed)}
    if PEM_write_bio_X509_ACERT_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_bio_X509_ACERT)}
      PEM_write_bio_X509_ACERT := _PEM_write_bio_X509_ACERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_bio_X509_ACERT_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_bio_X509_ACERT');
    {$ifend}
  end;
  
  PEM_write_X509_ACERT := LoadLibFunction(ADllHandle, PEM_write_X509_ACERT_procname);
  FuncLoadError := not assigned(PEM_write_X509_ACERT);
  if FuncLoadError then
  begin
    {$if not defined(PEM_write_X509_ACERT_allownil)}
    PEM_write_X509_ACERT := ERR_PEM_write_X509_ACERT;
    {$ifend}
    {$if declared(PEM_write_X509_ACERT_introduced)}
    if LibVersion < PEM_write_X509_ACERT_introduced then
    begin
      {$if declared(FC_PEM_write_X509_ACERT)}
      PEM_write_X509_ACERT := FC_PEM_write_X509_ACERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PEM_write_X509_ACERT_removed)}
    if PEM_write_X509_ACERT_removed <= LibVersion then
    begin
      {$if declared(_PEM_write_X509_ACERT)}
      PEM_write_X509_ACERT := _PEM_write_X509_ACERT;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PEM_write_X509_ACERT_allownil)}
    if FuncLoadError then
      AFailed.Add('PEM_write_X509_ACERT');
    {$ifend}
  end;
  
  d2i_X509_ACERT_bio := LoadLibFunction(ADllHandle, d2i_X509_ACERT_bio_procname);
  FuncLoadError := not assigned(d2i_X509_ACERT_bio);
  if FuncLoadError then
  begin
    {$if not defined(d2i_X509_ACERT_bio_allownil)}
    d2i_X509_ACERT_bio := ERR_d2i_X509_ACERT_bio;
    {$ifend}
    {$if declared(d2i_X509_ACERT_bio_introduced)}
    if LibVersion < d2i_X509_ACERT_bio_introduced then
    begin
      {$if declared(FC_d2i_X509_ACERT_bio)}
      d2i_X509_ACERT_bio := FC_d2i_X509_ACERT_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_X509_ACERT_bio_removed)}
    if d2i_X509_ACERT_bio_removed <= LibVersion then
    begin
      {$if declared(_d2i_X509_ACERT_bio)}
      d2i_X509_ACERT_bio := _d2i_X509_ACERT_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_X509_ACERT_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_X509_ACERT_bio');
    {$ifend}
  end;
  
  i2d_X509_ACERT_bio := LoadLibFunction(ADllHandle, i2d_X509_ACERT_bio_procname);
  FuncLoadError := not assigned(i2d_X509_ACERT_bio);
  if FuncLoadError then
  begin
    {$if not defined(i2d_X509_ACERT_bio_allownil)}
    i2d_X509_ACERT_bio := ERR_i2d_X509_ACERT_bio;
    {$ifend}
    {$if declared(i2d_X509_ACERT_bio_introduced)}
    if LibVersion < i2d_X509_ACERT_bio_introduced then
    begin
      {$if declared(FC_i2d_X509_ACERT_bio)}
      i2d_X509_ACERT_bio := FC_i2d_X509_ACERT_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_X509_ACERT_bio_removed)}
    if i2d_X509_ACERT_bio_removed <= LibVersion then
    begin
      {$if declared(_i2d_X509_ACERT_bio)}
      i2d_X509_ACERT_bio := _i2d_X509_ACERT_bio;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_X509_ACERT_bio_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_X509_ACERT_bio');
    {$ifend}
  end;
  
  X509_ACERT_sign := LoadLibFunction(ADllHandle, X509_ACERT_sign_procname);
  FuncLoadError := not assigned(X509_ACERT_sign);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_sign_allownil)}
    X509_ACERT_sign := ERR_X509_ACERT_sign;
    {$ifend}
    {$if declared(X509_ACERT_sign_introduced)}
    if LibVersion < X509_ACERT_sign_introduced then
    begin
      {$if declared(FC_X509_ACERT_sign)}
      X509_ACERT_sign := FC_X509_ACERT_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_sign_removed)}
    if X509_ACERT_sign_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_sign)}
      X509_ACERT_sign := _X509_ACERT_sign;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_sign_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_sign');
    {$ifend}
  end;
  
  X509_ACERT_sign_ctx := LoadLibFunction(ADllHandle, X509_ACERT_sign_ctx_procname);
  FuncLoadError := not assigned(X509_ACERT_sign_ctx);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_sign_ctx_allownil)}
    X509_ACERT_sign_ctx := ERR_X509_ACERT_sign_ctx;
    {$ifend}
    {$if declared(X509_ACERT_sign_ctx_introduced)}
    if LibVersion < X509_ACERT_sign_ctx_introduced then
    begin
      {$if declared(FC_X509_ACERT_sign_ctx)}
      X509_ACERT_sign_ctx := FC_X509_ACERT_sign_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_sign_ctx_removed)}
    if X509_ACERT_sign_ctx_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_sign_ctx)}
      X509_ACERT_sign_ctx := _X509_ACERT_sign_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_sign_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_sign_ctx');
    {$ifend}
  end;
  
  X509_ACERT_verify := LoadLibFunction(ADllHandle, X509_ACERT_verify_procname);
  FuncLoadError := not assigned(X509_ACERT_verify);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_verify_allownil)}
    X509_ACERT_verify := ERR_X509_ACERT_verify;
    {$ifend}
    {$if declared(X509_ACERT_verify_introduced)}
    if LibVersion < X509_ACERT_verify_introduced then
    begin
      {$if declared(FC_X509_ACERT_verify)}
      X509_ACERT_verify := FC_X509_ACERT_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_verify_removed)}
    if X509_ACERT_verify_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_verify)}
      X509_ACERT_verify := _X509_ACERT_verify;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_verify_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_verify');
    {$ifend}
  end;
  
  X509_ACERT_get0_holder_entityName := LoadLibFunction(ADllHandle, X509_ACERT_get0_holder_entityName_procname);
  FuncLoadError := not assigned(X509_ACERT_get0_holder_entityName);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_get0_holder_entityName_allownil)}
    X509_ACERT_get0_holder_entityName := ERR_X509_ACERT_get0_holder_entityName;
    {$ifend}
    {$if declared(X509_ACERT_get0_holder_entityName_introduced)}
    if LibVersion < X509_ACERT_get0_holder_entityName_introduced then
    begin
      {$if declared(FC_X509_ACERT_get0_holder_entityName)}
      X509_ACERT_get0_holder_entityName := FC_X509_ACERT_get0_holder_entityName;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_get0_holder_entityName_removed)}
    if X509_ACERT_get0_holder_entityName_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_get0_holder_entityName)}
      X509_ACERT_get0_holder_entityName := _X509_ACERT_get0_holder_entityName;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_get0_holder_entityName_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_get0_holder_entityName');
    {$ifend}
  end;
  
  X509_ACERT_get0_holder_baseCertId := LoadLibFunction(ADllHandle, X509_ACERT_get0_holder_baseCertId_procname);
  FuncLoadError := not assigned(X509_ACERT_get0_holder_baseCertId);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_get0_holder_baseCertId_allownil)}
    X509_ACERT_get0_holder_baseCertId := ERR_X509_ACERT_get0_holder_baseCertId;
    {$ifend}
    {$if declared(X509_ACERT_get0_holder_baseCertId_introduced)}
    if LibVersion < X509_ACERT_get0_holder_baseCertId_introduced then
    begin
      {$if declared(FC_X509_ACERT_get0_holder_baseCertId)}
      X509_ACERT_get0_holder_baseCertId := FC_X509_ACERT_get0_holder_baseCertId;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_get0_holder_baseCertId_removed)}
    if X509_ACERT_get0_holder_baseCertId_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_get0_holder_baseCertId)}
      X509_ACERT_get0_holder_baseCertId := _X509_ACERT_get0_holder_baseCertId;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_get0_holder_baseCertId_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_get0_holder_baseCertId');
    {$ifend}
  end;
  
  X509_ACERT_get0_holder_digest := LoadLibFunction(ADllHandle, X509_ACERT_get0_holder_digest_procname);
  FuncLoadError := not assigned(X509_ACERT_get0_holder_digest);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_get0_holder_digest_allownil)}
    X509_ACERT_get0_holder_digest := ERR_X509_ACERT_get0_holder_digest;
    {$ifend}
    {$if declared(X509_ACERT_get0_holder_digest_introduced)}
    if LibVersion < X509_ACERT_get0_holder_digest_introduced then
    begin
      {$if declared(FC_X509_ACERT_get0_holder_digest)}
      X509_ACERT_get0_holder_digest := FC_X509_ACERT_get0_holder_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_get0_holder_digest_removed)}
    if X509_ACERT_get0_holder_digest_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_get0_holder_digest)}
      X509_ACERT_get0_holder_digest := _X509_ACERT_get0_holder_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_get0_holder_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_get0_holder_digest');
    {$ifend}
  end;
  
  X509_ACERT_get0_issuerName := LoadLibFunction(ADllHandle, X509_ACERT_get0_issuerName_procname);
  FuncLoadError := not assigned(X509_ACERT_get0_issuerName);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_get0_issuerName_allownil)}
    X509_ACERT_get0_issuerName := ERR_X509_ACERT_get0_issuerName;
    {$ifend}
    {$if declared(X509_ACERT_get0_issuerName_introduced)}
    if LibVersion < X509_ACERT_get0_issuerName_introduced then
    begin
      {$if declared(FC_X509_ACERT_get0_issuerName)}
      X509_ACERT_get0_issuerName := FC_X509_ACERT_get0_issuerName;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_get0_issuerName_removed)}
    if X509_ACERT_get0_issuerName_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_get0_issuerName)}
      X509_ACERT_get0_issuerName := _X509_ACERT_get0_issuerName;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_get0_issuerName_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_get0_issuerName');
    {$ifend}
  end;
  
  X509_ACERT_get_version := LoadLibFunction(ADllHandle, X509_ACERT_get_version_procname);
  FuncLoadError := not assigned(X509_ACERT_get_version);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_get_version_allownil)}
    X509_ACERT_get_version := ERR_X509_ACERT_get_version;
    {$ifend}
    {$if declared(X509_ACERT_get_version_introduced)}
    if LibVersion < X509_ACERT_get_version_introduced then
    begin
      {$if declared(FC_X509_ACERT_get_version)}
      X509_ACERT_get_version := FC_X509_ACERT_get_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_get_version_removed)}
    if X509_ACERT_get_version_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_get_version)}
      X509_ACERT_get_version := _X509_ACERT_get_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_get_version_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_get_version');
    {$ifend}
  end;
  
  X509_ACERT_get0_signature := LoadLibFunction(ADllHandle, X509_ACERT_get0_signature_procname);
  FuncLoadError := not assigned(X509_ACERT_get0_signature);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_get0_signature_allownil)}
    X509_ACERT_get0_signature := ERR_X509_ACERT_get0_signature;
    {$ifend}
    {$if declared(X509_ACERT_get0_signature_introduced)}
    if LibVersion < X509_ACERT_get0_signature_introduced then
    begin
      {$if declared(FC_X509_ACERT_get0_signature)}
      X509_ACERT_get0_signature := FC_X509_ACERT_get0_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_get0_signature_removed)}
    if X509_ACERT_get0_signature_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_get0_signature)}
      X509_ACERT_get0_signature := _X509_ACERT_get0_signature;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_get0_signature_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_get0_signature');
    {$ifend}
  end;
  
  X509_ACERT_get_signature_nid := LoadLibFunction(ADllHandle, X509_ACERT_get_signature_nid_procname);
  FuncLoadError := not assigned(X509_ACERT_get_signature_nid);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_get_signature_nid_allownil)}
    X509_ACERT_get_signature_nid := ERR_X509_ACERT_get_signature_nid;
    {$ifend}
    {$if declared(X509_ACERT_get_signature_nid_introduced)}
    if LibVersion < X509_ACERT_get_signature_nid_introduced then
    begin
      {$if declared(FC_X509_ACERT_get_signature_nid)}
      X509_ACERT_get_signature_nid := FC_X509_ACERT_get_signature_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_get_signature_nid_removed)}
    if X509_ACERT_get_signature_nid_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_get_signature_nid)}
      X509_ACERT_get_signature_nid := _X509_ACERT_get_signature_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_get_signature_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_get_signature_nid');
    {$ifend}
  end;
  
  X509_ACERT_get0_info_sigalg := LoadLibFunction(ADllHandle, X509_ACERT_get0_info_sigalg_procname);
  FuncLoadError := not assigned(X509_ACERT_get0_info_sigalg);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_get0_info_sigalg_allownil)}
    X509_ACERT_get0_info_sigalg := ERR_X509_ACERT_get0_info_sigalg;
    {$ifend}
    {$if declared(X509_ACERT_get0_info_sigalg_introduced)}
    if LibVersion < X509_ACERT_get0_info_sigalg_introduced then
    begin
      {$if declared(FC_X509_ACERT_get0_info_sigalg)}
      X509_ACERT_get0_info_sigalg := FC_X509_ACERT_get0_info_sigalg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_get0_info_sigalg_removed)}
    if X509_ACERT_get0_info_sigalg_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_get0_info_sigalg)}
      X509_ACERT_get0_info_sigalg := _X509_ACERT_get0_info_sigalg;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_get0_info_sigalg_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_get0_info_sigalg');
    {$ifend}
  end;
  
  X509_ACERT_get0_serialNumber := LoadLibFunction(ADllHandle, X509_ACERT_get0_serialNumber_procname);
  FuncLoadError := not assigned(X509_ACERT_get0_serialNumber);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_get0_serialNumber_allownil)}
    X509_ACERT_get0_serialNumber := ERR_X509_ACERT_get0_serialNumber;
    {$ifend}
    {$if declared(X509_ACERT_get0_serialNumber_introduced)}
    if LibVersion < X509_ACERT_get0_serialNumber_introduced then
    begin
      {$if declared(FC_X509_ACERT_get0_serialNumber)}
      X509_ACERT_get0_serialNumber := FC_X509_ACERT_get0_serialNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_get0_serialNumber_removed)}
    if X509_ACERT_get0_serialNumber_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_get0_serialNumber)}
      X509_ACERT_get0_serialNumber := _X509_ACERT_get0_serialNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_get0_serialNumber_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_get0_serialNumber');
    {$ifend}
  end;
  
  X509_ACERT_get0_notBefore := LoadLibFunction(ADllHandle, X509_ACERT_get0_notBefore_procname);
  FuncLoadError := not assigned(X509_ACERT_get0_notBefore);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_get0_notBefore_allownil)}
    X509_ACERT_get0_notBefore := ERR_X509_ACERT_get0_notBefore;
    {$ifend}
    {$if declared(X509_ACERT_get0_notBefore_introduced)}
    if LibVersion < X509_ACERT_get0_notBefore_introduced then
    begin
      {$if declared(FC_X509_ACERT_get0_notBefore)}
      X509_ACERT_get0_notBefore := FC_X509_ACERT_get0_notBefore;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_get0_notBefore_removed)}
    if X509_ACERT_get0_notBefore_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_get0_notBefore)}
      X509_ACERT_get0_notBefore := _X509_ACERT_get0_notBefore;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_get0_notBefore_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_get0_notBefore');
    {$ifend}
  end;
  
  X509_ACERT_get0_notAfter := LoadLibFunction(ADllHandle, X509_ACERT_get0_notAfter_procname);
  FuncLoadError := not assigned(X509_ACERT_get0_notAfter);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_get0_notAfter_allownil)}
    X509_ACERT_get0_notAfter := ERR_X509_ACERT_get0_notAfter;
    {$ifend}
    {$if declared(X509_ACERT_get0_notAfter_introduced)}
    if LibVersion < X509_ACERT_get0_notAfter_introduced then
    begin
      {$if declared(FC_X509_ACERT_get0_notAfter)}
      X509_ACERT_get0_notAfter := FC_X509_ACERT_get0_notAfter;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_get0_notAfter_removed)}
    if X509_ACERT_get0_notAfter_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_get0_notAfter)}
      X509_ACERT_get0_notAfter := _X509_ACERT_get0_notAfter;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_get0_notAfter_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_get0_notAfter');
    {$ifend}
  end;
  
  X509_ACERT_get0_issuerUID := LoadLibFunction(ADllHandle, X509_ACERT_get0_issuerUID_procname);
  FuncLoadError := not assigned(X509_ACERT_get0_issuerUID);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_get0_issuerUID_allownil)}
    X509_ACERT_get0_issuerUID := ERR_X509_ACERT_get0_issuerUID;
    {$ifend}
    {$if declared(X509_ACERT_get0_issuerUID_introduced)}
    if LibVersion < X509_ACERT_get0_issuerUID_introduced then
    begin
      {$if declared(FC_X509_ACERT_get0_issuerUID)}
      X509_ACERT_get0_issuerUID := FC_X509_ACERT_get0_issuerUID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_get0_issuerUID_removed)}
    if X509_ACERT_get0_issuerUID_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_get0_issuerUID)}
      X509_ACERT_get0_issuerUID := _X509_ACERT_get0_issuerUID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_get0_issuerUID_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_get0_issuerUID');
    {$ifend}
  end;
  
  X509_ACERT_print := LoadLibFunction(ADllHandle, X509_ACERT_print_procname);
  FuncLoadError := not assigned(X509_ACERT_print);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_print_allownil)}
    X509_ACERT_print := ERR_X509_ACERT_print;
    {$ifend}
    {$if declared(X509_ACERT_print_introduced)}
    if LibVersion < X509_ACERT_print_introduced then
    begin
      {$if declared(FC_X509_ACERT_print)}
      X509_ACERT_print := FC_X509_ACERT_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_print_removed)}
    if X509_ACERT_print_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_print)}
      X509_ACERT_print := _X509_ACERT_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_print_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_print');
    {$ifend}
  end;
  
  X509_ACERT_print_ex := LoadLibFunction(ADllHandle, X509_ACERT_print_ex_procname);
  FuncLoadError := not assigned(X509_ACERT_print_ex);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_print_ex_allownil)}
    X509_ACERT_print_ex := ERR_X509_ACERT_print_ex;
    {$ifend}
    {$if declared(X509_ACERT_print_ex_introduced)}
    if LibVersion < X509_ACERT_print_ex_introduced then
    begin
      {$if declared(FC_X509_ACERT_print_ex)}
      X509_ACERT_print_ex := FC_X509_ACERT_print_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_print_ex_removed)}
    if X509_ACERT_print_ex_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_print_ex)}
      X509_ACERT_print_ex := _X509_ACERT_print_ex;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_print_ex_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_print_ex');
    {$ifend}
  end;
  
  X509_ACERT_get_attr_count := LoadLibFunction(ADllHandle, X509_ACERT_get_attr_count_procname);
  FuncLoadError := not assigned(X509_ACERT_get_attr_count);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_get_attr_count_allownil)}
    X509_ACERT_get_attr_count := ERR_X509_ACERT_get_attr_count;
    {$ifend}
    {$if declared(X509_ACERT_get_attr_count_introduced)}
    if LibVersion < X509_ACERT_get_attr_count_introduced then
    begin
      {$if declared(FC_X509_ACERT_get_attr_count)}
      X509_ACERT_get_attr_count := FC_X509_ACERT_get_attr_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_get_attr_count_removed)}
    if X509_ACERT_get_attr_count_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_get_attr_count)}
      X509_ACERT_get_attr_count := _X509_ACERT_get_attr_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_get_attr_count_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_get_attr_count');
    {$ifend}
  end;
  
  X509_ACERT_get_attr_by_NID := LoadLibFunction(ADllHandle, X509_ACERT_get_attr_by_NID_procname);
  FuncLoadError := not assigned(X509_ACERT_get_attr_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_get_attr_by_NID_allownil)}
    X509_ACERT_get_attr_by_NID := ERR_X509_ACERT_get_attr_by_NID;
    {$ifend}
    {$if declared(X509_ACERT_get_attr_by_NID_introduced)}
    if LibVersion < X509_ACERT_get_attr_by_NID_introduced then
    begin
      {$if declared(FC_X509_ACERT_get_attr_by_NID)}
      X509_ACERT_get_attr_by_NID := FC_X509_ACERT_get_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_get_attr_by_NID_removed)}
    if X509_ACERT_get_attr_by_NID_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_get_attr_by_NID)}
      X509_ACERT_get_attr_by_NID := _X509_ACERT_get_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_get_attr_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_get_attr_by_NID');
    {$ifend}
  end;
  
  X509_ACERT_get_attr_by_OBJ := LoadLibFunction(ADllHandle, X509_ACERT_get_attr_by_OBJ_procname);
  FuncLoadError := not assigned(X509_ACERT_get_attr_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_get_attr_by_OBJ_allownil)}
    X509_ACERT_get_attr_by_OBJ := ERR_X509_ACERT_get_attr_by_OBJ;
    {$ifend}
    {$if declared(X509_ACERT_get_attr_by_OBJ_introduced)}
    if LibVersion < X509_ACERT_get_attr_by_OBJ_introduced then
    begin
      {$if declared(FC_X509_ACERT_get_attr_by_OBJ)}
      X509_ACERT_get_attr_by_OBJ := FC_X509_ACERT_get_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_get_attr_by_OBJ_removed)}
    if X509_ACERT_get_attr_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_get_attr_by_OBJ)}
      X509_ACERT_get_attr_by_OBJ := _X509_ACERT_get_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_get_attr_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_get_attr_by_OBJ');
    {$ifend}
  end;
  
  X509_ACERT_get_attr := LoadLibFunction(ADllHandle, X509_ACERT_get_attr_procname);
  FuncLoadError := not assigned(X509_ACERT_get_attr);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_get_attr_allownil)}
    X509_ACERT_get_attr := ERR_X509_ACERT_get_attr;
    {$ifend}
    {$if declared(X509_ACERT_get_attr_introduced)}
    if LibVersion < X509_ACERT_get_attr_introduced then
    begin
      {$if declared(FC_X509_ACERT_get_attr)}
      X509_ACERT_get_attr := FC_X509_ACERT_get_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_get_attr_removed)}
    if X509_ACERT_get_attr_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_get_attr)}
      X509_ACERT_get_attr := _X509_ACERT_get_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_get_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_get_attr');
    {$ifend}
  end;
  
  X509_ACERT_delete_attr := LoadLibFunction(ADllHandle, X509_ACERT_delete_attr_procname);
  FuncLoadError := not assigned(X509_ACERT_delete_attr);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_delete_attr_allownil)}
    X509_ACERT_delete_attr := ERR_X509_ACERT_delete_attr;
    {$ifend}
    {$if declared(X509_ACERT_delete_attr_introduced)}
    if LibVersion < X509_ACERT_delete_attr_introduced then
    begin
      {$if declared(FC_X509_ACERT_delete_attr)}
      X509_ACERT_delete_attr := FC_X509_ACERT_delete_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_delete_attr_removed)}
    if X509_ACERT_delete_attr_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_delete_attr)}
      X509_ACERT_delete_attr := _X509_ACERT_delete_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_delete_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_delete_attr');
    {$ifend}
  end;
  
  X509_ACERT_get_ext_d2i := LoadLibFunction(ADllHandle, X509_ACERT_get_ext_d2i_procname);
  FuncLoadError := not assigned(X509_ACERT_get_ext_d2i);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_get_ext_d2i_allownil)}
    X509_ACERT_get_ext_d2i := ERR_X509_ACERT_get_ext_d2i;
    {$ifend}
    {$if declared(X509_ACERT_get_ext_d2i_introduced)}
    if LibVersion < X509_ACERT_get_ext_d2i_introduced then
    begin
      {$if declared(FC_X509_ACERT_get_ext_d2i)}
      X509_ACERT_get_ext_d2i := FC_X509_ACERT_get_ext_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_get_ext_d2i_removed)}
    if X509_ACERT_get_ext_d2i_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_get_ext_d2i)}
      X509_ACERT_get_ext_d2i := _X509_ACERT_get_ext_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_get_ext_d2i_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_get_ext_d2i');
    {$ifend}
  end;
  
  X509_ACERT_add1_ext_i2d := LoadLibFunction(ADllHandle, X509_ACERT_add1_ext_i2d_procname);
  FuncLoadError := not assigned(X509_ACERT_add1_ext_i2d);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_add1_ext_i2d_allownil)}
    X509_ACERT_add1_ext_i2d := ERR_X509_ACERT_add1_ext_i2d;
    {$ifend}
    {$if declared(X509_ACERT_add1_ext_i2d_introduced)}
    if LibVersion < X509_ACERT_add1_ext_i2d_introduced then
    begin
      {$if declared(FC_X509_ACERT_add1_ext_i2d)}
      X509_ACERT_add1_ext_i2d := FC_X509_ACERT_add1_ext_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_add1_ext_i2d_removed)}
    if X509_ACERT_add1_ext_i2d_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_add1_ext_i2d)}
      X509_ACERT_add1_ext_i2d := _X509_ACERT_add1_ext_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_add1_ext_i2d_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_add1_ext_i2d');
    {$ifend}
  end;
  
  X509_ACERT_get0_extensions := LoadLibFunction(ADllHandle, X509_ACERT_get0_extensions_procname);
  FuncLoadError := not assigned(X509_ACERT_get0_extensions);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_get0_extensions_allownil)}
    X509_ACERT_get0_extensions := ERR_X509_ACERT_get0_extensions;
    {$ifend}
    {$if declared(X509_ACERT_get0_extensions_introduced)}
    if LibVersion < X509_ACERT_get0_extensions_introduced then
    begin
      {$if declared(FC_X509_ACERT_get0_extensions)}
      X509_ACERT_get0_extensions := FC_X509_ACERT_get0_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_get0_extensions_removed)}
    if X509_ACERT_get0_extensions_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_get0_extensions)}
      X509_ACERT_get0_extensions := _X509_ACERT_get0_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_get0_extensions_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_get0_extensions');
    {$ifend}
  end;
  
  X509_ACERT_set_version := LoadLibFunction(ADllHandle, X509_ACERT_set_version_procname);
  FuncLoadError := not assigned(X509_ACERT_set_version);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_set_version_allownil)}
    X509_ACERT_set_version := ERR_X509_ACERT_set_version;
    {$ifend}
    {$if declared(X509_ACERT_set_version_introduced)}
    if LibVersion < X509_ACERT_set_version_introduced then
    begin
      {$if declared(FC_X509_ACERT_set_version)}
      X509_ACERT_set_version := FC_X509_ACERT_set_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_set_version_removed)}
    if X509_ACERT_set_version_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_set_version)}
      X509_ACERT_set_version := _X509_ACERT_set_version;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_set_version_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_set_version');
    {$ifend}
  end;
  
  X509_ACERT_set0_holder_entityName := LoadLibFunction(ADllHandle, X509_ACERT_set0_holder_entityName_procname);
  FuncLoadError := not assigned(X509_ACERT_set0_holder_entityName);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_set0_holder_entityName_allownil)}
    X509_ACERT_set0_holder_entityName := ERR_X509_ACERT_set0_holder_entityName;
    {$ifend}
    {$if declared(X509_ACERT_set0_holder_entityName_introduced)}
    if LibVersion < X509_ACERT_set0_holder_entityName_introduced then
    begin
      {$if declared(FC_X509_ACERT_set0_holder_entityName)}
      X509_ACERT_set0_holder_entityName := FC_X509_ACERT_set0_holder_entityName;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_set0_holder_entityName_removed)}
    if X509_ACERT_set0_holder_entityName_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_set0_holder_entityName)}
      X509_ACERT_set0_holder_entityName := _X509_ACERT_set0_holder_entityName;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_set0_holder_entityName_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_set0_holder_entityName');
    {$ifend}
  end;
  
  X509_ACERT_set0_holder_baseCertId := LoadLibFunction(ADllHandle, X509_ACERT_set0_holder_baseCertId_procname);
  FuncLoadError := not assigned(X509_ACERT_set0_holder_baseCertId);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_set0_holder_baseCertId_allownil)}
    X509_ACERT_set0_holder_baseCertId := ERR_X509_ACERT_set0_holder_baseCertId;
    {$ifend}
    {$if declared(X509_ACERT_set0_holder_baseCertId_introduced)}
    if LibVersion < X509_ACERT_set0_holder_baseCertId_introduced then
    begin
      {$if declared(FC_X509_ACERT_set0_holder_baseCertId)}
      X509_ACERT_set0_holder_baseCertId := FC_X509_ACERT_set0_holder_baseCertId;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_set0_holder_baseCertId_removed)}
    if X509_ACERT_set0_holder_baseCertId_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_set0_holder_baseCertId)}
      X509_ACERT_set0_holder_baseCertId := _X509_ACERT_set0_holder_baseCertId;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_set0_holder_baseCertId_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_set0_holder_baseCertId');
    {$ifend}
  end;
  
  X509_ACERT_set0_holder_digest := LoadLibFunction(ADllHandle, X509_ACERT_set0_holder_digest_procname);
  FuncLoadError := not assigned(X509_ACERT_set0_holder_digest);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_set0_holder_digest_allownil)}
    X509_ACERT_set0_holder_digest := ERR_X509_ACERT_set0_holder_digest;
    {$ifend}
    {$if declared(X509_ACERT_set0_holder_digest_introduced)}
    if LibVersion < X509_ACERT_set0_holder_digest_introduced then
    begin
      {$if declared(FC_X509_ACERT_set0_holder_digest)}
      X509_ACERT_set0_holder_digest := FC_X509_ACERT_set0_holder_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_set0_holder_digest_removed)}
    if X509_ACERT_set0_holder_digest_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_set0_holder_digest)}
      X509_ACERT_set0_holder_digest := _X509_ACERT_set0_holder_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_set0_holder_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_set0_holder_digest');
    {$ifend}
  end;
  
  X509_ACERT_add1_attr := LoadLibFunction(ADllHandle, X509_ACERT_add1_attr_procname);
  FuncLoadError := not assigned(X509_ACERT_add1_attr);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_add1_attr_allownil)}
    X509_ACERT_add1_attr := ERR_X509_ACERT_add1_attr;
    {$ifend}
    {$if declared(X509_ACERT_add1_attr_introduced)}
    if LibVersion < X509_ACERT_add1_attr_introduced then
    begin
      {$if declared(FC_X509_ACERT_add1_attr)}
      X509_ACERT_add1_attr := FC_X509_ACERT_add1_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_add1_attr_removed)}
    if X509_ACERT_add1_attr_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_add1_attr)}
      X509_ACERT_add1_attr := _X509_ACERT_add1_attr;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_add1_attr_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_add1_attr');
    {$ifend}
  end;
  
  X509_ACERT_add1_attr_by_OBJ := LoadLibFunction(ADllHandle, X509_ACERT_add1_attr_by_OBJ_procname);
  FuncLoadError := not assigned(X509_ACERT_add1_attr_by_OBJ);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_add1_attr_by_OBJ_allownil)}
    X509_ACERT_add1_attr_by_OBJ := ERR_X509_ACERT_add1_attr_by_OBJ;
    {$ifend}
    {$if declared(X509_ACERT_add1_attr_by_OBJ_introduced)}
    if LibVersion < X509_ACERT_add1_attr_by_OBJ_introduced then
    begin
      {$if declared(FC_X509_ACERT_add1_attr_by_OBJ)}
      X509_ACERT_add1_attr_by_OBJ := FC_X509_ACERT_add1_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_add1_attr_by_OBJ_removed)}
    if X509_ACERT_add1_attr_by_OBJ_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_add1_attr_by_OBJ)}
      X509_ACERT_add1_attr_by_OBJ := _X509_ACERT_add1_attr_by_OBJ;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_add1_attr_by_OBJ_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_add1_attr_by_OBJ');
    {$ifend}
  end;
  
  X509_ACERT_add1_attr_by_NID := LoadLibFunction(ADllHandle, X509_ACERT_add1_attr_by_NID_procname);
  FuncLoadError := not assigned(X509_ACERT_add1_attr_by_NID);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_add1_attr_by_NID_allownil)}
    X509_ACERT_add1_attr_by_NID := ERR_X509_ACERT_add1_attr_by_NID;
    {$ifend}
    {$if declared(X509_ACERT_add1_attr_by_NID_introduced)}
    if LibVersion < X509_ACERT_add1_attr_by_NID_introduced then
    begin
      {$if declared(FC_X509_ACERT_add1_attr_by_NID)}
      X509_ACERT_add1_attr_by_NID := FC_X509_ACERT_add1_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_add1_attr_by_NID_removed)}
    if X509_ACERT_add1_attr_by_NID_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_add1_attr_by_NID)}
      X509_ACERT_add1_attr_by_NID := _X509_ACERT_add1_attr_by_NID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_add1_attr_by_NID_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_add1_attr_by_NID');
    {$ifend}
  end;
  
  X509_ACERT_add1_attr_by_txt := LoadLibFunction(ADllHandle, X509_ACERT_add1_attr_by_txt_procname);
  FuncLoadError := not assigned(X509_ACERT_add1_attr_by_txt);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_add1_attr_by_txt_allownil)}
    X509_ACERT_add1_attr_by_txt := ERR_X509_ACERT_add1_attr_by_txt;
    {$ifend}
    {$if declared(X509_ACERT_add1_attr_by_txt_introduced)}
    if LibVersion < X509_ACERT_add1_attr_by_txt_introduced then
    begin
      {$if declared(FC_X509_ACERT_add1_attr_by_txt)}
      X509_ACERT_add1_attr_by_txt := FC_X509_ACERT_add1_attr_by_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_add1_attr_by_txt_removed)}
    if X509_ACERT_add1_attr_by_txt_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_add1_attr_by_txt)}
      X509_ACERT_add1_attr_by_txt := _X509_ACERT_add1_attr_by_txt;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_add1_attr_by_txt_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_add1_attr_by_txt');
    {$ifend}
  end;
  
  X509_ACERT_add_attr_nconf := LoadLibFunction(ADllHandle, X509_ACERT_add_attr_nconf_procname);
  FuncLoadError := not assigned(X509_ACERT_add_attr_nconf);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_add_attr_nconf_allownil)}
    X509_ACERT_add_attr_nconf := ERR_X509_ACERT_add_attr_nconf;
    {$ifend}
    {$if declared(X509_ACERT_add_attr_nconf_introduced)}
    if LibVersion < X509_ACERT_add_attr_nconf_introduced then
    begin
      {$if declared(FC_X509_ACERT_add_attr_nconf)}
      X509_ACERT_add_attr_nconf := FC_X509_ACERT_add_attr_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_add_attr_nconf_removed)}
    if X509_ACERT_add_attr_nconf_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_add_attr_nconf)}
      X509_ACERT_add_attr_nconf := _X509_ACERT_add_attr_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_add_attr_nconf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_add_attr_nconf');
    {$ifend}
  end;
  
  X509_ACERT_set1_issuerName := LoadLibFunction(ADllHandle, X509_ACERT_set1_issuerName_procname);
  FuncLoadError := not assigned(X509_ACERT_set1_issuerName);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_set1_issuerName_allownil)}
    X509_ACERT_set1_issuerName := ERR_X509_ACERT_set1_issuerName;
    {$ifend}
    {$if declared(X509_ACERT_set1_issuerName_introduced)}
    if LibVersion < X509_ACERT_set1_issuerName_introduced then
    begin
      {$if declared(FC_X509_ACERT_set1_issuerName)}
      X509_ACERT_set1_issuerName := FC_X509_ACERT_set1_issuerName;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_set1_issuerName_removed)}
    if X509_ACERT_set1_issuerName_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_set1_issuerName)}
      X509_ACERT_set1_issuerName := _X509_ACERT_set1_issuerName;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_set1_issuerName_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_set1_issuerName');
    {$ifend}
  end;
  
  X509_ACERT_set1_serialNumber := LoadLibFunction(ADllHandle, X509_ACERT_set1_serialNumber_procname);
  FuncLoadError := not assigned(X509_ACERT_set1_serialNumber);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_set1_serialNumber_allownil)}
    X509_ACERT_set1_serialNumber := ERR_X509_ACERT_set1_serialNumber;
    {$ifend}
    {$if declared(X509_ACERT_set1_serialNumber_introduced)}
    if LibVersion < X509_ACERT_set1_serialNumber_introduced then
    begin
      {$if declared(FC_X509_ACERT_set1_serialNumber)}
      X509_ACERT_set1_serialNumber := FC_X509_ACERT_set1_serialNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_set1_serialNumber_removed)}
    if X509_ACERT_set1_serialNumber_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_set1_serialNumber)}
      X509_ACERT_set1_serialNumber := _X509_ACERT_set1_serialNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_set1_serialNumber_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_set1_serialNumber');
    {$ifend}
  end;
  
  X509_ACERT_set1_notBefore := LoadLibFunction(ADllHandle, X509_ACERT_set1_notBefore_procname);
  FuncLoadError := not assigned(X509_ACERT_set1_notBefore);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_set1_notBefore_allownil)}
    X509_ACERT_set1_notBefore := ERR_X509_ACERT_set1_notBefore;
    {$ifend}
    {$if declared(X509_ACERT_set1_notBefore_introduced)}
    if LibVersion < X509_ACERT_set1_notBefore_introduced then
    begin
      {$if declared(FC_X509_ACERT_set1_notBefore)}
      X509_ACERT_set1_notBefore := FC_X509_ACERT_set1_notBefore;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_set1_notBefore_removed)}
    if X509_ACERT_set1_notBefore_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_set1_notBefore)}
      X509_ACERT_set1_notBefore := _X509_ACERT_set1_notBefore;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_set1_notBefore_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_set1_notBefore');
    {$ifend}
  end;
  
  X509_ACERT_set1_notAfter := LoadLibFunction(ADllHandle, X509_ACERT_set1_notAfter_procname);
  FuncLoadError := not assigned(X509_ACERT_set1_notAfter);
  if FuncLoadError then
  begin
    {$if not defined(X509_ACERT_set1_notAfter_allownil)}
    X509_ACERT_set1_notAfter := ERR_X509_ACERT_set1_notAfter;
    {$ifend}
    {$if declared(X509_ACERT_set1_notAfter_introduced)}
    if LibVersion < X509_ACERT_set1_notAfter_introduced then
    begin
      {$if declared(FC_X509_ACERT_set1_notAfter)}
      X509_ACERT_set1_notAfter := FC_X509_ACERT_set1_notAfter;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_ACERT_set1_notAfter_removed)}
    if X509_ACERT_set1_notAfter_removed <= LibVersion then
    begin
      {$if declared(_X509_ACERT_set1_notAfter)}
      X509_ACERT_set1_notAfter := _X509_ACERT_set1_notAfter;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_ACERT_set1_notAfter_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_ACERT_set1_notAfter');
    {$ifend}
  end;
  
  OSSL_OBJECT_DIGEST_INFO_get0_digest := LoadLibFunction(ADllHandle, OSSL_OBJECT_DIGEST_INFO_get0_digest_procname);
  FuncLoadError := not assigned(OSSL_OBJECT_DIGEST_INFO_get0_digest);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_OBJECT_DIGEST_INFO_get0_digest_allownil)}
    OSSL_OBJECT_DIGEST_INFO_get0_digest := ERR_OSSL_OBJECT_DIGEST_INFO_get0_digest;
    {$ifend}
    {$if declared(OSSL_OBJECT_DIGEST_INFO_get0_digest_introduced)}
    if LibVersion < OSSL_OBJECT_DIGEST_INFO_get0_digest_introduced then
    begin
      {$if declared(FC_OSSL_OBJECT_DIGEST_INFO_get0_digest)}
      OSSL_OBJECT_DIGEST_INFO_get0_digest := FC_OSSL_OBJECT_DIGEST_INFO_get0_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_OBJECT_DIGEST_INFO_get0_digest_removed)}
    if OSSL_OBJECT_DIGEST_INFO_get0_digest_removed <= LibVersion then
    begin
      {$if declared(_OSSL_OBJECT_DIGEST_INFO_get0_digest)}
      OSSL_OBJECT_DIGEST_INFO_get0_digest := _OSSL_OBJECT_DIGEST_INFO_get0_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_OBJECT_DIGEST_INFO_get0_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_OBJECT_DIGEST_INFO_get0_digest');
    {$ifend}
  end;
  
  OSSL_OBJECT_DIGEST_INFO_set1_digest := LoadLibFunction(ADllHandle, OSSL_OBJECT_DIGEST_INFO_set1_digest_procname);
  FuncLoadError := not assigned(OSSL_OBJECT_DIGEST_INFO_set1_digest);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_OBJECT_DIGEST_INFO_set1_digest_allownil)}
    OSSL_OBJECT_DIGEST_INFO_set1_digest := ERR_OSSL_OBJECT_DIGEST_INFO_set1_digest;
    {$ifend}
    {$if declared(OSSL_OBJECT_DIGEST_INFO_set1_digest_introduced)}
    if LibVersion < OSSL_OBJECT_DIGEST_INFO_set1_digest_introduced then
    begin
      {$if declared(FC_OSSL_OBJECT_DIGEST_INFO_set1_digest)}
      OSSL_OBJECT_DIGEST_INFO_set1_digest := FC_OSSL_OBJECT_DIGEST_INFO_set1_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_OBJECT_DIGEST_INFO_set1_digest_removed)}
    if OSSL_OBJECT_DIGEST_INFO_set1_digest_removed <= LibVersion then
    begin
      {$if declared(_OSSL_OBJECT_DIGEST_INFO_set1_digest)}
      OSSL_OBJECT_DIGEST_INFO_set1_digest := _OSSL_OBJECT_DIGEST_INFO_set1_digest;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_OBJECT_DIGEST_INFO_set1_digest_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_OBJECT_DIGEST_INFO_set1_digest');
    {$ifend}
  end;
  
  OSSL_ISSUER_SERIAL_get0_issuer := LoadLibFunction(ADllHandle, OSSL_ISSUER_SERIAL_get0_issuer_procname);
  FuncLoadError := not assigned(OSSL_ISSUER_SERIAL_get0_issuer);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ISSUER_SERIAL_get0_issuer_allownil)}
    OSSL_ISSUER_SERIAL_get0_issuer := ERR_OSSL_ISSUER_SERIAL_get0_issuer;
    {$ifend}
    {$if declared(OSSL_ISSUER_SERIAL_get0_issuer_introduced)}
    if LibVersion < OSSL_ISSUER_SERIAL_get0_issuer_introduced then
    begin
      {$if declared(FC_OSSL_ISSUER_SERIAL_get0_issuer)}
      OSSL_ISSUER_SERIAL_get0_issuer := FC_OSSL_ISSUER_SERIAL_get0_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ISSUER_SERIAL_get0_issuer_removed)}
    if OSSL_ISSUER_SERIAL_get0_issuer_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ISSUER_SERIAL_get0_issuer)}
      OSSL_ISSUER_SERIAL_get0_issuer := _OSSL_ISSUER_SERIAL_get0_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ISSUER_SERIAL_get0_issuer_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ISSUER_SERIAL_get0_issuer');
    {$ifend}
  end;
  
  OSSL_ISSUER_SERIAL_get0_serial := LoadLibFunction(ADllHandle, OSSL_ISSUER_SERIAL_get0_serial_procname);
  FuncLoadError := not assigned(OSSL_ISSUER_SERIAL_get0_serial);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ISSUER_SERIAL_get0_serial_allownil)}
    OSSL_ISSUER_SERIAL_get0_serial := ERR_OSSL_ISSUER_SERIAL_get0_serial;
    {$ifend}
    {$if declared(OSSL_ISSUER_SERIAL_get0_serial_introduced)}
    if LibVersion < OSSL_ISSUER_SERIAL_get0_serial_introduced then
    begin
      {$if declared(FC_OSSL_ISSUER_SERIAL_get0_serial)}
      OSSL_ISSUER_SERIAL_get0_serial := FC_OSSL_ISSUER_SERIAL_get0_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ISSUER_SERIAL_get0_serial_removed)}
    if OSSL_ISSUER_SERIAL_get0_serial_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ISSUER_SERIAL_get0_serial)}
      OSSL_ISSUER_SERIAL_get0_serial := _OSSL_ISSUER_SERIAL_get0_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ISSUER_SERIAL_get0_serial_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ISSUER_SERIAL_get0_serial');
    {$ifend}
  end;
  
  OSSL_ISSUER_SERIAL_get0_issuerUID := LoadLibFunction(ADllHandle, OSSL_ISSUER_SERIAL_get0_issuerUID_procname);
  FuncLoadError := not assigned(OSSL_ISSUER_SERIAL_get0_issuerUID);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ISSUER_SERIAL_get0_issuerUID_allownil)}
    OSSL_ISSUER_SERIAL_get0_issuerUID := ERR_OSSL_ISSUER_SERIAL_get0_issuerUID;
    {$ifend}
    {$if declared(OSSL_ISSUER_SERIAL_get0_issuerUID_introduced)}
    if LibVersion < OSSL_ISSUER_SERIAL_get0_issuerUID_introduced then
    begin
      {$if declared(FC_OSSL_ISSUER_SERIAL_get0_issuerUID)}
      OSSL_ISSUER_SERIAL_get0_issuerUID := FC_OSSL_ISSUER_SERIAL_get0_issuerUID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ISSUER_SERIAL_get0_issuerUID_removed)}
    if OSSL_ISSUER_SERIAL_get0_issuerUID_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ISSUER_SERIAL_get0_issuerUID)}
      OSSL_ISSUER_SERIAL_get0_issuerUID := _OSSL_ISSUER_SERIAL_get0_issuerUID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ISSUER_SERIAL_get0_issuerUID_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ISSUER_SERIAL_get0_issuerUID');
    {$ifend}
  end;
  
  OSSL_ISSUER_SERIAL_set1_issuer := LoadLibFunction(ADllHandle, OSSL_ISSUER_SERIAL_set1_issuer_procname);
  FuncLoadError := not assigned(OSSL_ISSUER_SERIAL_set1_issuer);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ISSUER_SERIAL_set1_issuer_allownil)}
    OSSL_ISSUER_SERIAL_set1_issuer := ERR_OSSL_ISSUER_SERIAL_set1_issuer;
    {$ifend}
    {$if declared(OSSL_ISSUER_SERIAL_set1_issuer_introduced)}
    if LibVersion < OSSL_ISSUER_SERIAL_set1_issuer_introduced then
    begin
      {$if declared(FC_OSSL_ISSUER_SERIAL_set1_issuer)}
      OSSL_ISSUER_SERIAL_set1_issuer := FC_OSSL_ISSUER_SERIAL_set1_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ISSUER_SERIAL_set1_issuer_removed)}
    if OSSL_ISSUER_SERIAL_set1_issuer_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ISSUER_SERIAL_set1_issuer)}
      OSSL_ISSUER_SERIAL_set1_issuer := _OSSL_ISSUER_SERIAL_set1_issuer;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ISSUER_SERIAL_set1_issuer_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ISSUER_SERIAL_set1_issuer');
    {$ifend}
  end;
  
  OSSL_ISSUER_SERIAL_set1_serial := LoadLibFunction(ADllHandle, OSSL_ISSUER_SERIAL_set1_serial_procname);
  FuncLoadError := not assigned(OSSL_ISSUER_SERIAL_set1_serial);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ISSUER_SERIAL_set1_serial_allownil)}
    OSSL_ISSUER_SERIAL_set1_serial := ERR_OSSL_ISSUER_SERIAL_set1_serial;
    {$ifend}
    {$if declared(OSSL_ISSUER_SERIAL_set1_serial_introduced)}
    if LibVersion < OSSL_ISSUER_SERIAL_set1_serial_introduced then
    begin
      {$if declared(FC_OSSL_ISSUER_SERIAL_set1_serial)}
      OSSL_ISSUER_SERIAL_set1_serial := FC_OSSL_ISSUER_SERIAL_set1_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ISSUER_SERIAL_set1_serial_removed)}
    if OSSL_ISSUER_SERIAL_set1_serial_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ISSUER_SERIAL_set1_serial)}
      OSSL_ISSUER_SERIAL_set1_serial := _OSSL_ISSUER_SERIAL_set1_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ISSUER_SERIAL_set1_serial_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ISSUER_SERIAL_set1_serial');
    {$ifend}
  end;
  
  OSSL_ISSUER_SERIAL_set1_issuerUID := LoadLibFunction(ADllHandle, OSSL_ISSUER_SERIAL_set1_issuerUID_procname);
  FuncLoadError := not assigned(OSSL_ISSUER_SERIAL_set1_issuerUID);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_ISSUER_SERIAL_set1_issuerUID_allownil)}
    OSSL_ISSUER_SERIAL_set1_issuerUID := ERR_OSSL_ISSUER_SERIAL_set1_issuerUID;
    {$ifend}
    {$if declared(OSSL_ISSUER_SERIAL_set1_issuerUID_introduced)}
    if LibVersion < OSSL_ISSUER_SERIAL_set1_issuerUID_introduced then
    begin
      {$if declared(FC_OSSL_ISSUER_SERIAL_set1_issuerUID)}
      OSSL_ISSUER_SERIAL_set1_issuerUID := FC_OSSL_ISSUER_SERIAL_set1_issuerUID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_ISSUER_SERIAL_set1_issuerUID_removed)}
    if OSSL_ISSUER_SERIAL_set1_issuerUID_removed <= LibVersion then
    begin
      {$if declared(_OSSL_ISSUER_SERIAL_set1_issuerUID)}
      OSSL_ISSUER_SERIAL_set1_issuerUID := _OSSL_ISSUER_SERIAL_set1_issuerUID;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_ISSUER_SERIAL_set1_issuerUID_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_ISSUER_SERIAL_set1_issuerUID');
    {$ifend}
  end;
  
  OSSL_IETF_ATTR_SYNTAX_VALUE_it := LoadLibFunction(ADllHandle, OSSL_IETF_ATTR_SYNTAX_VALUE_it_procname);
  FuncLoadError := not assigned(OSSL_IETF_ATTR_SYNTAX_VALUE_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_IETF_ATTR_SYNTAX_VALUE_it_allownil)}
    OSSL_IETF_ATTR_SYNTAX_VALUE_it := ERR_OSSL_IETF_ATTR_SYNTAX_VALUE_it;
    {$ifend}
    {$if declared(OSSL_IETF_ATTR_SYNTAX_VALUE_it_introduced)}
    if LibVersion < OSSL_IETF_ATTR_SYNTAX_VALUE_it_introduced then
    begin
      {$if declared(FC_OSSL_IETF_ATTR_SYNTAX_VALUE_it)}
      OSSL_IETF_ATTR_SYNTAX_VALUE_it := FC_OSSL_IETF_ATTR_SYNTAX_VALUE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_IETF_ATTR_SYNTAX_VALUE_it_removed)}
    if OSSL_IETF_ATTR_SYNTAX_VALUE_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_IETF_ATTR_SYNTAX_VALUE_it)}
      OSSL_IETF_ATTR_SYNTAX_VALUE_it := _OSSL_IETF_ATTR_SYNTAX_VALUE_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_IETF_ATTR_SYNTAX_VALUE_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_IETF_ATTR_SYNTAX_VALUE_it');
    {$ifend}
  end;
  
  OSSL_IETF_ATTR_SYNTAX_VALUE_new := LoadLibFunction(ADllHandle, OSSL_IETF_ATTR_SYNTAX_VALUE_new_procname);
  FuncLoadError := not assigned(OSSL_IETF_ATTR_SYNTAX_VALUE_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_IETF_ATTR_SYNTAX_VALUE_new_allownil)}
    OSSL_IETF_ATTR_SYNTAX_VALUE_new := ERR_OSSL_IETF_ATTR_SYNTAX_VALUE_new;
    {$ifend}
    {$if declared(OSSL_IETF_ATTR_SYNTAX_VALUE_new_introduced)}
    if LibVersion < OSSL_IETF_ATTR_SYNTAX_VALUE_new_introduced then
    begin
      {$if declared(FC_OSSL_IETF_ATTR_SYNTAX_VALUE_new)}
      OSSL_IETF_ATTR_SYNTAX_VALUE_new := FC_OSSL_IETF_ATTR_SYNTAX_VALUE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_IETF_ATTR_SYNTAX_VALUE_new_removed)}
    if OSSL_IETF_ATTR_SYNTAX_VALUE_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_IETF_ATTR_SYNTAX_VALUE_new)}
      OSSL_IETF_ATTR_SYNTAX_VALUE_new := _OSSL_IETF_ATTR_SYNTAX_VALUE_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_IETF_ATTR_SYNTAX_VALUE_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_IETF_ATTR_SYNTAX_VALUE_new');
    {$ifend}
  end;
  
  OSSL_IETF_ATTR_SYNTAX_VALUE_free := LoadLibFunction(ADllHandle, OSSL_IETF_ATTR_SYNTAX_VALUE_free_procname);
  FuncLoadError := not assigned(OSSL_IETF_ATTR_SYNTAX_VALUE_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_IETF_ATTR_SYNTAX_VALUE_free_allownil)}
    OSSL_IETF_ATTR_SYNTAX_VALUE_free := ERR_OSSL_IETF_ATTR_SYNTAX_VALUE_free;
    {$ifend}
    {$if declared(OSSL_IETF_ATTR_SYNTAX_VALUE_free_introduced)}
    if LibVersion < OSSL_IETF_ATTR_SYNTAX_VALUE_free_introduced then
    begin
      {$if declared(FC_OSSL_IETF_ATTR_SYNTAX_VALUE_free)}
      OSSL_IETF_ATTR_SYNTAX_VALUE_free := FC_OSSL_IETF_ATTR_SYNTAX_VALUE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_IETF_ATTR_SYNTAX_VALUE_free_removed)}
    if OSSL_IETF_ATTR_SYNTAX_VALUE_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_IETF_ATTR_SYNTAX_VALUE_free)}
      OSSL_IETF_ATTR_SYNTAX_VALUE_free := _OSSL_IETF_ATTR_SYNTAX_VALUE_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_IETF_ATTR_SYNTAX_VALUE_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_IETF_ATTR_SYNTAX_VALUE_free');
    {$ifend}
  end;
  
  OSSL_IETF_ATTR_SYNTAX_new := LoadLibFunction(ADllHandle, OSSL_IETF_ATTR_SYNTAX_new_procname);
  FuncLoadError := not assigned(OSSL_IETF_ATTR_SYNTAX_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_IETF_ATTR_SYNTAX_new_allownil)}
    OSSL_IETF_ATTR_SYNTAX_new := ERR_OSSL_IETF_ATTR_SYNTAX_new;
    {$ifend}
    {$if declared(OSSL_IETF_ATTR_SYNTAX_new_introduced)}
    if LibVersion < OSSL_IETF_ATTR_SYNTAX_new_introduced then
    begin
      {$if declared(FC_OSSL_IETF_ATTR_SYNTAX_new)}
      OSSL_IETF_ATTR_SYNTAX_new := FC_OSSL_IETF_ATTR_SYNTAX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_IETF_ATTR_SYNTAX_new_removed)}
    if OSSL_IETF_ATTR_SYNTAX_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_IETF_ATTR_SYNTAX_new)}
      OSSL_IETF_ATTR_SYNTAX_new := _OSSL_IETF_ATTR_SYNTAX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_IETF_ATTR_SYNTAX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_IETF_ATTR_SYNTAX_new');
    {$ifend}
  end;
  
  OSSL_IETF_ATTR_SYNTAX_free := LoadLibFunction(ADllHandle, OSSL_IETF_ATTR_SYNTAX_free_procname);
  FuncLoadError := not assigned(OSSL_IETF_ATTR_SYNTAX_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_IETF_ATTR_SYNTAX_free_allownil)}
    OSSL_IETF_ATTR_SYNTAX_free := ERR_OSSL_IETF_ATTR_SYNTAX_free;
    {$ifend}
    {$if declared(OSSL_IETF_ATTR_SYNTAX_free_introduced)}
    if LibVersion < OSSL_IETF_ATTR_SYNTAX_free_introduced then
    begin
      {$if declared(FC_OSSL_IETF_ATTR_SYNTAX_free)}
      OSSL_IETF_ATTR_SYNTAX_free := FC_OSSL_IETF_ATTR_SYNTAX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_IETF_ATTR_SYNTAX_free_removed)}
    if OSSL_IETF_ATTR_SYNTAX_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_IETF_ATTR_SYNTAX_free)}
      OSSL_IETF_ATTR_SYNTAX_free := _OSSL_IETF_ATTR_SYNTAX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_IETF_ATTR_SYNTAX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_IETF_ATTR_SYNTAX_free');
    {$ifend}
  end;
  
  d2i_OSSL_IETF_ATTR_SYNTAX := LoadLibFunction(ADllHandle, d2i_OSSL_IETF_ATTR_SYNTAX_procname);
  FuncLoadError := not assigned(d2i_OSSL_IETF_ATTR_SYNTAX);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_IETF_ATTR_SYNTAX_allownil)}
    d2i_OSSL_IETF_ATTR_SYNTAX := ERR_d2i_OSSL_IETF_ATTR_SYNTAX;
    {$ifend}
    {$if declared(d2i_OSSL_IETF_ATTR_SYNTAX_introduced)}
    if LibVersion < d2i_OSSL_IETF_ATTR_SYNTAX_introduced then
    begin
      {$if declared(FC_d2i_OSSL_IETF_ATTR_SYNTAX)}
      d2i_OSSL_IETF_ATTR_SYNTAX := FC_d2i_OSSL_IETF_ATTR_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_IETF_ATTR_SYNTAX_removed)}
    if d2i_OSSL_IETF_ATTR_SYNTAX_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_IETF_ATTR_SYNTAX)}
      d2i_OSSL_IETF_ATTR_SYNTAX := _d2i_OSSL_IETF_ATTR_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_IETF_ATTR_SYNTAX_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_IETF_ATTR_SYNTAX');
    {$ifend}
  end;
  
  i2d_OSSL_IETF_ATTR_SYNTAX := LoadLibFunction(ADllHandle, i2d_OSSL_IETF_ATTR_SYNTAX_procname);
  FuncLoadError := not assigned(i2d_OSSL_IETF_ATTR_SYNTAX);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_IETF_ATTR_SYNTAX_allownil)}
    i2d_OSSL_IETF_ATTR_SYNTAX := ERR_i2d_OSSL_IETF_ATTR_SYNTAX;
    {$ifend}
    {$if declared(i2d_OSSL_IETF_ATTR_SYNTAX_introduced)}
    if LibVersion < i2d_OSSL_IETF_ATTR_SYNTAX_introduced then
    begin
      {$if declared(FC_i2d_OSSL_IETF_ATTR_SYNTAX)}
      i2d_OSSL_IETF_ATTR_SYNTAX := FC_i2d_OSSL_IETF_ATTR_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_IETF_ATTR_SYNTAX_removed)}
    if i2d_OSSL_IETF_ATTR_SYNTAX_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_IETF_ATTR_SYNTAX)}
      i2d_OSSL_IETF_ATTR_SYNTAX := _i2d_OSSL_IETF_ATTR_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_IETF_ATTR_SYNTAX_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_IETF_ATTR_SYNTAX');
    {$ifend}
  end;
  
  OSSL_IETF_ATTR_SYNTAX_it := LoadLibFunction(ADllHandle, OSSL_IETF_ATTR_SYNTAX_it_procname);
  FuncLoadError := not assigned(OSSL_IETF_ATTR_SYNTAX_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_IETF_ATTR_SYNTAX_it_allownil)}
    OSSL_IETF_ATTR_SYNTAX_it := ERR_OSSL_IETF_ATTR_SYNTAX_it;
    {$ifend}
    {$if declared(OSSL_IETF_ATTR_SYNTAX_it_introduced)}
    if LibVersion < OSSL_IETF_ATTR_SYNTAX_it_introduced then
    begin
      {$if declared(FC_OSSL_IETF_ATTR_SYNTAX_it)}
      OSSL_IETF_ATTR_SYNTAX_it := FC_OSSL_IETF_ATTR_SYNTAX_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_IETF_ATTR_SYNTAX_it_removed)}
    if OSSL_IETF_ATTR_SYNTAX_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_IETF_ATTR_SYNTAX_it)}
      OSSL_IETF_ATTR_SYNTAX_it := _OSSL_IETF_ATTR_SYNTAX_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_IETF_ATTR_SYNTAX_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_IETF_ATTR_SYNTAX_it');
    {$ifend}
  end;
  
  OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority := LoadLibFunction(ADllHandle, OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority_procname);
  FuncLoadError := not assigned(OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority_allownil)}
    OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority := ERR_OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority;
    {$ifend}
    {$if declared(OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority_introduced)}
    if LibVersion < OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority_introduced then
    begin
      {$if declared(FC_OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority)}
      OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority := FC_OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority_removed)}
    if OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority_removed <= LibVersion then
    begin
      {$if declared(_OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority)}
      OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority := _OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority');
    {$ifend}
  end;
  
  OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority := LoadLibFunction(ADllHandle, OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority_procname);
  FuncLoadError := not assigned(OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority_allownil)}
    OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority := ERR_OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority;
    {$ifend}
    {$if declared(OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority_introduced)}
    if LibVersion < OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority_introduced then
    begin
      {$if declared(FC_OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority)}
      OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority := FC_OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority_removed)}
    if OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority_removed <= LibVersion then
    begin
      {$if declared(_OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority)}
      OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority := _OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority');
    {$ifend}
  end;
  
  OSSL_IETF_ATTR_SYNTAX_get_value_num := LoadLibFunction(ADllHandle, OSSL_IETF_ATTR_SYNTAX_get_value_num_procname);
  FuncLoadError := not assigned(OSSL_IETF_ATTR_SYNTAX_get_value_num);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_IETF_ATTR_SYNTAX_get_value_num_allownil)}
    OSSL_IETF_ATTR_SYNTAX_get_value_num := ERR_OSSL_IETF_ATTR_SYNTAX_get_value_num;
    {$ifend}
    {$if declared(OSSL_IETF_ATTR_SYNTAX_get_value_num_introduced)}
    if LibVersion < OSSL_IETF_ATTR_SYNTAX_get_value_num_introduced then
    begin
      {$if declared(FC_OSSL_IETF_ATTR_SYNTAX_get_value_num)}
      OSSL_IETF_ATTR_SYNTAX_get_value_num := FC_OSSL_IETF_ATTR_SYNTAX_get_value_num;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_IETF_ATTR_SYNTAX_get_value_num_removed)}
    if OSSL_IETF_ATTR_SYNTAX_get_value_num_removed <= LibVersion then
    begin
      {$if declared(_OSSL_IETF_ATTR_SYNTAX_get_value_num)}
      OSSL_IETF_ATTR_SYNTAX_get_value_num := _OSSL_IETF_ATTR_SYNTAX_get_value_num;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_IETF_ATTR_SYNTAX_get_value_num_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_IETF_ATTR_SYNTAX_get_value_num');
    {$ifend}
  end;
  
  OSSL_IETF_ATTR_SYNTAX_get0_value := LoadLibFunction(ADllHandle, OSSL_IETF_ATTR_SYNTAX_get0_value_procname);
  FuncLoadError := not assigned(OSSL_IETF_ATTR_SYNTAX_get0_value);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_IETF_ATTR_SYNTAX_get0_value_allownil)}
    OSSL_IETF_ATTR_SYNTAX_get0_value := ERR_OSSL_IETF_ATTR_SYNTAX_get0_value;
    {$ifend}
    {$if declared(OSSL_IETF_ATTR_SYNTAX_get0_value_introduced)}
    if LibVersion < OSSL_IETF_ATTR_SYNTAX_get0_value_introduced then
    begin
      {$if declared(FC_OSSL_IETF_ATTR_SYNTAX_get0_value)}
      OSSL_IETF_ATTR_SYNTAX_get0_value := FC_OSSL_IETF_ATTR_SYNTAX_get0_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_IETF_ATTR_SYNTAX_get0_value_removed)}
    if OSSL_IETF_ATTR_SYNTAX_get0_value_removed <= LibVersion then
    begin
      {$if declared(_OSSL_IETF_ATTR_SYNTAX_get0_value)}
      OSSL_IETF_ATTR_SYNTAX_get0_value := _OSSL_IETF_ATTR_SYNTAX_get0_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_IETF_ATTR_SYNTAX_get0_value_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_IETF_ATTR_SYNTAX_get0_value');
    {$ifend}
  end;
  
  OSSL_IETF_ATTR_SYNTAX_add1_value := LoadLibFunction(ADllHandle, OSSL_IETF_ATTR_SYNTAX_add1_value_procname);
  FuncLoadError := not assigned(OSSL_IETF_ATTR_SYNTAX_add1_value);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_IETF_ATTR_SYNTAX_add1_value_allownil)}
    OSSL_IETF_ATTR_SYNTAX_add1_value := ERR_OSSL_IETF_ATTR_SYNTAX_add1_value;
    {$ifend}
    {$if declared(OSSL_IETF_ATTR_SYNTAX_add1_value_introduced)}
    if LibVersion < OSSL_IETF_ATTR_SYNTAX_add1_value_introduced then
    begin
      {$if declared(FC_OSSL_IETF_ATTR_SYNTAX_add1_value)}
      OSSL_IETF_ATTR_SYNTAX_add1_value := FC_OSSL_IETF_ATTR_SYNTAX_add1_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_IETF_ATTR_SYNTAX_add1_value_removed)}
    if OSSL_IETF_ATTR_SYNTAX_add1_value_removed <= LibVersion then
    begin
      {$if declared(_OSSL_IETF_ATTR_SYNTAX_add1_value)}
      OSSL_IETF_ATTR_SYNTAX_add1_value := _OSSL_IETF_ATTR_SYNTAX_add1_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_IETF_ATTR_SYNTAX_add1_value_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_IETF_ATTR_SYNTAX_add1_value');
    {$ifend}
  end;
  
  OSSL_IETF_ATTR_SYNTAX_print := LoadLibFunction(ADllHandle, OSSL_IETF_ATTR_SYNTAX_print_procname);
  FuncLoadError := not assigned(OSSL_IETF_ATTR_SYNTAX_print);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_IETF_ATTR_SYNTAX_print_allownil)}
    OSSL_IETF_ATTR_SYNTAX_print := ERR_OSSL_IETF_ATTR_SYNTAX_print;
    {$ifend}
    {$if declared(OSSL_IETF_ATTR_SYNTAX_print_introduced)}
    if LibVersion < OSSL_IETF_ATTR_SYNTAX_print_introduced then
    begin
      {$if declared(FC_OSSL_IETF_ATTR_SYNTAX_print)}
      OSSL_IETF_ATTR_SYNTAX_print := FC_OSSL_IETF_ATTR_SYNTAX_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_IETF_ATTR_SYNTAX_print_removed)}
    if OSSL_IETF_ATTR_SYNTAX_print_removed <= LibVersion then
    begin
      {$if declared(_OSSL_IETF_ATTR_SYNTAX_print)}
      OSSL_IETF_ATTR_SYNTAX_print := _OSSL_IETF_ATTR_SYNTAX_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_IETF_ATTR_SYNTAX_print_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_IETF_ATTR_SYNTAX_print');
    {$ifend}
  end;
  
  OSSL_TARGET_new := LoadLibFunction(ADllHandle, OSSL_TARGET_new_procname);
  FuncLoadError := not assigned(OSSL_TARGET_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TARGET_new_allownil)}
    OSSL_TARGET_new := ERR_OSSL_TARGET_new;
    {$ifend}
    {$if declared(OSSL_TARGET_new_introduced)}
    if LibVersion < OSSL_TARGET_new_introduced then
    begin
      {$if declared(FC_OSSL_TARGET_new)}
      OSSL_TARGET_new := FC_OSSL_TARGET_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TARGET_new_removed)}
    if OSSL_TARGET_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TARGET_new)}
      OSSL_TARGET_new := _OSSL_TARGET_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TARGET_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TARGET_new');
    {$ifend}
  end;
  
  OSSL_TARGET_free := LoadLibFunction(ADllHandle, OSSL_TARGET_free_procname);
  FuncLoadError := not assigned(OSSL_TARGET_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TARGET_free_allownil)}
    OSSL_TARGET_free := ERR_OSSL_TARGET_free;
    {$ifend}
    {$if declared(OSSL_TARGET_free_introduced)}
    if LibVersion < OSSL_TARGET_free_introduced then
    begin
      {$if declared(FC_OSSL_TARGET_free)}
      OSSL_TARGET_free := FC_OSSL_TARGET_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TARGET_free_removed)}
    if OSSL_TARGET_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TARGET_free)}
      OSSL_TARGET_free := _OSSL_TARGET_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TARGET_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TARGET_free');
    {$ifend}
  end;
  
  d2i_OSSL_TARGET := LoadLibFunction(ADllHandle, d2i_OSSL_TARGET_procname);
  FuncLoadError := not assigned(d2i_OSSL_TARGET);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_TARGET_allownil)}
    d2i_OSSL_TARGET := ERR_d2i_OSSL_TARGET;
    {$ifend}
    {$if declared(d2i_OSSL_TARGET_introduced)}
    if LibVersion < d2i_OSSL_TARGET_introduced then
    begin
      {$if declared(FC_d2i_OSSL_TARGET)}
      d2i_OSSL_TARGET := FC_d2i_OSSL_TARGET;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_TARGET_removed)}
    if d2i_OSSL_TARGET_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_TARGET)}
      d2i_OSSL_TARGET := _d2i_OSSL_TARGET;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_TARGET_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_TARGET');
    {$ifend}
  end;
  
  i2d_OSSL_TARGET := LoadLibFunction(ADllHandle, i2d_OSSL_TARGET_procname);
  FuncLoadError := not assigned(i2d_OSSL_TARGET);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_TARGET_allownil)}
    i2d_OSSL_TARGET := ERR_i2d_OSSL_TARGET;
    {$ifend}
    {$if declared(i2d_OSSL_TARGET_introduced)}
    if LibVersion < i2d_OSSL_TARGET_introduced then
    begin
      {$if declared(FC_i2d_OSSL_TARGET)}
      i2d_OSSL_TARGET := FC_i2d_OSSL_TARGET;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_TARGET_removed)}
    if i2d_OSSL_TARGET_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_TARGET)}
      i2d_OSSL_TARGET := _i2d_OSSL_TARGET;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_TARGET_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_TARGET');
    {$ifend}
  end;
  
  OSSL_TARGET_it := LoadLibFunction(ADllHandle, OSSL_TARGET_it_procname);
  FuncLoadError := not assigned(OSSL_TARGET_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TARGET_it_allownil)}
    OSSL_TARGET_it := ERR_OSSL_TARGET_it;
    {$ifend}
    {$if declared(OSSL_TARGET_it_introduced)}
    if LibVersion < OSSL_TARGET_it_introduced then
    begin
      {$if declared(FC_OSSL_TARGET_it)}
      OSSL_TARGET_it := FC_OSSL_TARGET_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TARGET_it_removed)}
    if OSSL_TARGET_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TARGET_it)}
      OSSL_TARGET_it := _OSSL_TARGET_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TARGET_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TARGET_it');
    {$ifend}
  end;
  
  OSSL_TARGETS_new := LoadLibFunction(ADllHandle, OSSL_TARGETS_new_procname);
  FuncLoadError := not assigned(OSSL_TARGETS_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TARGETS_new_allownil)}
    OSSL_TARGETS_new := ERR_OSSL_TARGETS_new;
    {$ifend}
    {$if declared(OSSL_TARGETS_new_introduced)}
    if LibVersion < OSSL_TARGETS_new_introduced then
    begin
      {$if declared(FC_OSSL_TARGETS_new)}
      OSSL_TARGETS_new := FC_OSSL_TARGETS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TARGETS_new_removed)}
    if OSSL_TARGETS_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TARGETS_new)}
      OSSL_TARGETS_new := _OSSL_TARGETS_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TARGETS_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TARGETS_new');
    {$ifend}
  end;
  
  OSSL_TARGETS_free := LoadLibFunction(ADllHandle, OSSL_TARGETS_free_procname);
  FuncLoadError := not assigned(OSSL_TARGETS_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TARGETS_free_allownil)}
    OSSL_TARGETS_free := ERR_OSSL_TARGETS_free;
    {$ifend}
    {$if declared(OSSL_TARGETS_free_introduced)}
    if LibVersion < OSSL_TARGETS_free_introduced then
    begin
      {$if declared(FC_OSSL_TARGETS_free)}
      OSSL_TARGETS_free := FC_OSSL_TARGETS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TARGETS_free_removed)}
    if OSSL_TARGETS_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TARGETS_free)}
      OSSL_TARGETS_free := _OSSL_TARGETS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TARGETS_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TARGETS_free');
    {$ifend}
  end;
  
  d2i_OSSL_TARGETS := LoadLibFunction(ADllHandle, d2i_OSSL_TARGETS_procname);
  FuncLoadError := not assigned(d2i_OSSL_TARGETS);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_TARGETS_allownil)}
    d2i_OSSL_TARGETS := ERR_d2i_OSSL_TARGETS;
    {$ifend}
    {$if declared(d2i_OSSL_TARGETS_introduced)}
    if LibVersion < d2i_OSSL_TARGETS_introduced then
    begin
      {$if declared(FC_d2i_OSSL_TARGETS)}
      d2i_OSSL_TARGETS := FC_d2i_OSSL_TARGETS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_TARGETS_removed)}
    if d2i_OSSL_TARGETS_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_TARGETS)}
      d2i_OSSL_TARGETS := _d2i_OSSL_TARGETS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_TARGETS_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_TARGETS');
    {$ifend}
  end;
  
  i2d_OSSL_TARGETS := LoadLibFunction(ADllHandle, i2d_OSSL_TARGETS_procname);
  FuncLoadError := not assigned(i2d_OSSL_TARGETS);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_TARGETS_allownil)}
    i2d_OSSL_TARGETS := ERR_i2d_OSSL_TARGETS;
    {$ifend}
    {$if declared(i2d_OSSL_TARGETS_introduced)}
    if LibVersion < i2d_OSSL_TARGETS_introduced then
    begin
      {$if declared(FC_i2d_OSSL_TARGETS)}
      i2d_OSSL_TARGETS := FC_i2d_OSSL_TARGETS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_TARGETS_removed)}
    if i2d_OSSL_TARGETS_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_TARGETS)}
      i2d_OSSL_TARGETS := _i2d_OSSL_TARGETS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_TARGETS_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_TARGETS');
    {$ifend}
  end;
  
  OSSL_TARGETS_it := LoadLibFunction(ADllHandle, OSSL_TARGETS_it_procname);
  FuncLoadError := not assigned(OSSL_TARGETS_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TARGETS_it_allownil)}
    OSSL_TARGETS_it := ERR_OSSL_TARGETS_it;
    {$ifend}
    {$if declared(OSSL_TARGETS_it_introduced)}
    if LibVersion < OSSL_TARGETS_it_introduced then
    begin
      {$if declared(FC_OSSL_TARGETS_it)}
      OSSL_TARGETS_it := FC_OSSL_TARGETS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TARGETS_it_removed)}
    if OSSL_TARGETS_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TARGETS_it)}
      OSSL_TARGETS_it := _OSSL_TARGETS_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TARGETS_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TARGETS_it');
    {$ifend}
  end;
  
  OSSL_TARGETING_INFORMATION_new := LoadLibFunction(ADllHandle, OSSL_TARGETING_INFORMATION_new_procname);
  FuncLoadError := not assigned(OSSL_TARGETING_INFORMATION_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TARGETING_INFORMATION_new_allownil)}
    OSSL_TARGETING_INFORMATION_new := ERR_OSSL_TARGETING_INFORMATION_new;
    {$ifend}
    {$if declared(OSSL_TARGETING_INFORMATION_new_introduced)}
    if LibVersion < OSSL_TARGETING_INFORMATION_new_introduced then
    begin
      {$if declared(FC_OSSL_TARGETING_INFORMATION_new)}
      OSSL_TARGETING_INFORMATION_new := FC_OSSL_TARGETING_INFORMATION_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TARGETING_INFORMATION_new_removed)}
    if OSSL_TARGETING_INFORMATION_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TARGETING_INFORMATION_new)}
      OSSL_TARGETING_INFORMATION_new := _OSSL_TARGETING_INFORMATION_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TARGETING_INFORMATION_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TARGETING_INFORMATION_new');
    {$ifend}
  end;
  
  OSSL_TARGETING_INFORMATION_free := LoadLibFunction(ADllHandle, OSSL_TARGETING_INFORMATION_free_procname);
  FuncLoadError := not assigned(OSSL_TARGETING_INFORMATION_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TARGETING_INFORMATION_free_allownil)}
    OSSL_TARGETING_INFORMATION_free := ERR_OSSL_TARGETING_INFORMATION_free;
    {$ifend}
    {$if declared(OSSL_TARGETING_INFORMATION_free_introduced)}
    if LibVersion < OSSL_TARGETING_INFORMATION_free_introduced then
    begin
      {$if declared(FC_OSSL_TARGETING_INFORMATION_free)}
      OSSL_TARGETING_INFORMATION_free := FC_OSSL_TARGETING_INFORMATION_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TARGETING_INFORMATION_free_removed)}
    if OSSL_TARGETING_INFORMATION_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TARGETING_INFORMATION_free)}
      OSSL_TARGETING_INFORMATION_free := _OSSL_TARGETING_INFORMATION_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TARGETING_INFORMATION_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TARGETING_INFORMATION_free');
    {$ifend}
  end;
  
  d2i_OSSL_TARGETING_INFORMATION := LoadLibFunction(ADllHandle, d2i_OSSL_TARGETING_INFORMATION_procname);
  FuncLoadError := not assigned(d2i_OSSL_TARGETING_INFORMATION);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_TARGETING_INFORMATION_allownil)}
    d2i_OSSL_TARGETING_INFORMATION := ERR_d2i_OSSL_TARGETING_INFORMATION;
    {$ifend}
    {$if declared(d2i_OSSL_TARGETING_INFORMATION_introduced)}
    if LibVersion < d2i_OSSL_TARGETING_INFORMATION_introduced then
    begin
      {$if declared(FC_d2i_OSSL_TARGETING_INFORMATION)}
      d2i_OSSL_TARGETING_INFORMATION := FC_d2i_OSSL_TARGETING_INFORMATION;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_TARGETING_INFORMATION_removed)}
    if d2i_OSSL_TARGETING_INFORMATION_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_TARGETING_INFORMATION)}
      d2i_OSSL_TARGETING_INFORMATION := _d2i_OSSL_TARGETING_INFORMATION;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_TARGETING_INFORMATION_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_TARGETING_INFORMATION');
    {$ifend}
  end;
  
  i2d_OSSL_TARGETING_INFORMATION := LoadLibFunction(ADllHandle, i2d_OSSL_TARGETING_INFORMATION_procname);
  FuncLoadError := not assigned(i2d_OSSL_TARGETING_INFORMATION);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_TARGETING_INFORMATION_allownil)}
    i2d_OSSL_TARGETING_INFORMATION := ERR_i2d_OSSL_TARGETING_INFORMATION;
    {$ifend}
    {$if declared(i2d_OSSL_TARGETING_INFORMATION_introduced)}
    if LibVersion < i2d_OSSL_TARGETING_INFORMATION_introduced then
    begin
      {$if declared(FC_i2d_OSSL_TARGETING_INFORMATION)}
      i2d_OSSL_TARGETING_INFORMATION := FC_i2d_OSSL_TARGETING_INFORMATION;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_TARGETING_INFORMATION_removed)}
    if i2d_OSSL_TARGETING_INFORMATION_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_TARGETING_INFORMATION)}
      i2d_OSSL_TARGETING_INFORMATION := _i2d_OSSL_TARGETING_INFORMATION;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_TARGETING_INFORMATION_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_TARGETING_INFORMATION');
    {$ifend}
  end;
  
  OSSL_TARGETING_INFORMATION_it := LoadLibFunction(ADllHandle, OSSL_TARGETING_INFORMATION_it_procname);
  FuncLoadError := not assigned(OSSL_TARGETING_INFORMATION_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_TARGETING_INFORMATION_it_allownil)}
    OSSL_TARGETING_INFORMATION_it := ERR_OSSL_TARGETING_INFORMATION_it;
    {$ifend}
    {$if declared(OSSL_TARGETING_INFORMATION_it_introduced)}
    if LibVersion < OSSL_TARGETING_INFORMATION_it_introduced then
    begin
      {$if declared(FC_OSSL_TARGETING_INFORMATION_it)}
      OSSL_TARGETING_INFORMATION_it := FC_OSSL_TARGETING_INFORMATION_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_TARGETING_INFORMATION_it_removed)}
    if OSSL_TARGETING_INFORMATION_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_TARGETING_INFORMATION_it)}
      OSSL_TARGETING_INFORMATION_it := _OSSL_TARGETING_INFORMATION_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_TARGETING_INFORMATION_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_TARGETING_INFORMATION_it');
    {$ifend}
  end;
  
  OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new := LoadLibFunction(ADllHandle, OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new_procname);
  FuncLoadError := not assigned(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new_allownil)}
    OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new := ERR_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new;
    {$ifend}
    {$if declared(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new_introduced)}
    if LibVersion < OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new_introduced then
    begin
      {$if declared(FC_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new)}
      OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new := FC_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new_removed)}
    if OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new_removed <= LibVersion then
    begin
      {$if declared(_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new)}
      OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new := _OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new');
    {$ifend}
  end;
  
  OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free := LoadLibFunction(ADllHandle, OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free_procname);
  FuncLoadError := not assigned(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free_allownil)}
    OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free := ERR_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free;
    {$ifend}
    {$if declared(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free_introduced)}
    if LibVersion < OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free_introduced then
    begin
      {$if declared(FC_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free)}
      OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free := FC_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free_removed)}
    if OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free_removed <= LibVersion then
    begin
      {$if declared(_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free)}
      OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free := _OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free');
    {$ifend}
  end;
  
  d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX := LoadLibFunction(ADllHandle, d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_procname);
  FuncLoadError := not assigned(d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX);
  if FuncLoadError then
  begin
    {$if not defined(d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_allownil)}
    d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX := ERR_d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX;
    {$ifend}
    {$if declared(d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_introduced)}
    if LibVersion < d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_introduced then
    begin
      {$if declared(FC_d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX)}
      d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX := FC_d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_removed)}
    if d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_removed <= LibVersion then
    begin
      {$if declared(_d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX)}
      d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX := _d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_allownil)}
    if FuncLoadError then
      AFailed.Add('d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX');
    {$ifend}
  end;
  
  i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX := LoadLibFunction(ADllHandle, i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_procname);
  FuncLoadError := not assigned(i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX);
  if FuncLoadError then
  begin
    {$if not defined(i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_allownil)}
    i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX := ERR_i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX;
    {$ifend}
    {$if declared(i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_introduced)}
    if LibVersion < i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_introduced then
    begin
      {$if declared(FC_i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX)}
      i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX := FC_i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_removed)}
    if i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_removed <= LibVersion then
    begin
      {$if declared(_i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX)}
      i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX := _i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_allownil)}
    if FuncLoadError then
      AFailed.Add('i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX');
    {$ifend}
  end;
  
  OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it := LoadLibFunction(ADllHandle, OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it_procname);
  FuncLoadError := not assigned(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it);
  if FuncLoadError then
  begin
    {$if not defined(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it_allownil)}
    OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it := ERR_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it;
    {$ifend}
    {$if declared(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it_introduced)}
    if LibVersion < OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it_introduced then
    begin
      {$if declared(FC_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it)}
      OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it := FC_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it_removed)}
    if OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it_removed <= LibVersion then
    begin
      {$if declared(_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it)}
      OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it := _OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it_allownil)}
    if FuncLoadError then
      AFailed.Add('OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it');
    {$ifend}
  end;
  
end;

procedure Unload;
begin
  X509_ACERT_new := nil;
  X509_ACERT_free := nil;
  d2i_X509_ACERT := nil;
  i2d_X509_ACERT := nil;
  X509_ACERT_it := nil;
  X509_ACERT_dup := nil;
  X509_ACERT_INFO_it := nil;
  X509_ACERT_INFO_new := nil;
  X509_ACERT_INFO_free := nil;
  OSSL_OBJECT_DIGEST_INFO_new := nil;
  OSSL_OBJECT_DIGEST_INFO_free := nil;
  OSSL_ISSUER_SERIAL_new := nil;
  OSSL_ISSUER_SERIAL_free := nil;
  X509_ACERT_ISSUER_V2FORM_new := nil;
  X509_ACERT_ISSUER_V2FORM_free := nil;
  d2i_X509_ACERT_fp := nil;
  i2d_X509_ACERT_fp := nil;
  PEM_read_bio_X509_ACERT := nil;
  PEM_read_X509_ACERT := nil;
  PEM_write_bio_X509_ACERT := nil;
  PEM_write_X509_ACERT := nil;
  d2i_X509_ACERT_bio := nil;
  i2d_X509_ACERT_bio := nil;
  X509_ACERT_sign := nil;
  X509_ACERT_sign_ctx := nil;
  X509_ACERT_verify := nil;
  X509_ACERT_get0_holder_entityName := nil;
  X509_ACERT_get0_holder_baseCertId := nil;
  X509_ACERT_get0_holder_digest := nil;
  X509_ACERT_get0_issuerName := nil;
  X509_ACERT_get_version := nil;
  X509_ACERT_get0_signature := nil;
  X509_ACERT_get_signature_nid := nil;
  X509_ACERT_get0_info_sigalg := nil;
  X509_ACERT_get0_serialNumber := nil;
  X509_ACERT_get0_notBefore := nil;
  X509_ACERT_get0_notAfter := nil;
  X509_ACERT_get0_issuerUID := nil;
  X509_ACERT_print := nil;
  X509_ACERT_print_ex := nil;
  X509_ACERT_get_attr_count := nil;
  X509_ACERT_get_attr_by_NID := nil;
  X509_ACERT_get_attr_by_OBJ := nil;
  X509_ACERT_get_attr := nil;
  X509_ACERT_delete_attr := nil;
  X509_ACERT_get_ext_d2i := nil;
  X509_ACERT_add1_ext_i2d := nil;
  X509_ACERT_get0_extensions := nil;
  X509_ACERT_set_version := nil;
  X509_ACERT_set0_holder_entityName := nil;
  X509_ACERT_set0_holder_baseCertId := nil;
  X509_ACERT_set0_holder_digest := nil;
  X509_ACERT_add1_attr := nil;
  X509_ACERT_add1_attr_by_OBJ := nil;
  X509_ACERT_add1_attr_by_NID := nil;
  X509_ACERT_add1_attr_by_txt := nil;
  X509_ACERT_add_attr_nconf := nil;
  X509_ACERT_set1_issuerName := nil;
  X509_ACERT_set1_serialNumber := nil;
  X509_ACERT_set1_notBefore := nil;
  X509_ACERT_set1_notAfter := nil;
  OSSL_OBJECT_DIGEST_INFO_get0_digest := nil;
  OSSL_OBJECT_DIGEST_INFO_set1_digest := nil;
  OSSL_ISSUER_SERIAL_get0_issuer := nil;
  OSSL_ISSUER_SERIAL_get0_serial := nil;
  OSSL_ISSUER_SERIAL_get0_issuerUID := nil;
  OSSL_ISSUER_SERIAL_set1_issuer := nil;
  OSSL_ISSUER_SERIAL_set1_serial := nil;
  OSSL_ISSUER_SERIAL_set1_issuerUID := nil;
  OSSL_IETF_ATTR_SYNTAX_VALUE_it := nil;
  OSSL_IETF_ATTR_SYNTAX_VALUE_new := nil;
  OSSL_IETF_ATTR_SYNTAX_VALUE_free := nil;
  OSSL_IETF_ATTR_SYNTAX_new := nil;
  OSSL_IETF_ATTR_SYNTAX_free := nil;
  d2i_OSSL_IETF_ATTR_SYNTAX := nil;
  i2d_OSSL_IETF_ATTR_SYNTAX := nil;
  OSSL_IETF_ATTR_SYNTAX_it := nil;
  OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority := nil;
  OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority := nil;
  OSSL_IETF_ATTR_SYNTAX_get_value_num := nil;
  OSSL_IETF_ATTR_SYNTAX_get0_value := nil;
  OSSL_IETF_ATTR_SYNTAX_add1_value := nil;
  OSSL_IETF_ATTR_SYNTAX_print := nil;
  OSSL_TARGET_new := nil;
  OSSL_TARGET_free := nil;
  d2i_OSSL_TARGET := nil;
  i2d_OSSL_TARGET := nil;
  OSSL_TARGET_it := nil;
  OSSL_TARGETS_new := nil;
  OSSL_TARGETS_free := nil;
  d2i_OSSL_TARGETS := nil;
  i2d_OSSL_TARGETS := nil;
  OSSL_TARGETS_it := nil;
  OSSL_TARGETING_INFORMATION_new := nil;
  OSSL_TARGETING_INFORMATION_free := nil;
  d2i_OSSL_TARGETING_INFORMATION := nil;
  i2d_OSSL_TARGETING_INFORMATION := nil;
  OSSL_TARGETING_INFORMATION_it := nil;
  OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new := nil;
  OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free := nil;
  d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX := nil;
  i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX := nil;
  OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it := nil;
end;
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.