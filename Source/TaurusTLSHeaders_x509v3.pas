/// <exclude />
  (* This unit was generated using the script genTaurusTLSHdrs.sh from the source file TaurusTLSHeaders_x509v3.h2pas
     It should not be modified directly. All changes should be made to TaurusTLSHeaders_x509v3.h2pas
     and this file regenerated. TaurusTLSHeaders_x509v3.h2pas is distributed with the full Indy
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
unit TaurusTLSHeaders_x509v3;

interface

// Headers for OpenSSL 1.1.1
// x509v3.h

{$IFDEF HAS_DIRECTIVE_HPPEMIT_NAMESPACE}
{$HPPEMIT OPENNAMESPACE}
{$ELSE}
(*$HPPEMIT 'namespace Taurustlsheaders_x509v3'*)
(*$HPPEMIT '{'*)
{$ENDIF}
(*$HPPEMIT ' struct GENERAL_NAME;'*)
(*$HPPEMIT ' typedef GENERAL_NAME* PGENERAL_NAME;'*)
{$IFDEF HAS_DIRECTIVE_HPPEMIT_NAMESPACE}
{$HPPEMIT CLOSENAMESPACE}
{$ELSE}
(*$HPPEMIT '}'*)
{$ENDIF}

uses
  IdCTypes,
  IdGlobal,
  {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  TaurusTLSConsts,
  {$ENDIF}
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_asn1,
  TaurusTLSHeaders_asn1t,
  TaurusTLSHeaders_safestack,
  TaurusTLSHeaders_stack,
  TaurusTLSHeaders_x509;

const
  (* ext_flags values *)
  {$EXTERNALSYM X509V3_EXT_DYNAMIC}
  X509V3_EXT_DYNAMIC      = $1;
  {$EXTERNALSYM X509V3_EXT_CTX_DEP}
  X509V3_EXT_CTX_DEP      = $2;
  {$EXTERNALSYM X509V3_EXT_MULTILINE}
  X509V3_EXT_MULTILINE    = $4;

  // v3_ext_ctx
  {$EXTERNALSYM CTX_TEST}
  CTX_TEST = $1;
  {$EXTERNALSYM X509V3_CTX_REPLACE}
  X509V3_CTX_REPLACE = $2;

  // GENERAL_NAME_st
  {$EXTERNALSYM GEN_OTHERNAME}
  GEN_OTHERNAME   = 0;
  {$EXTERNALSYM GEN_EMAIL}
  GEN_EMAIL       = 1;
  {$EXTERNALSYM GEN_DNS}
  GEN_DNS         = 2;
  {$EXTERNALSYM GEN_X400}
  GEN_X400        = 3;
  {$EXTERNALSYM GEN_DIRNAME}
  GEN_DIRNAME     = 4;
  {$EXTERNALSYM GEN_EDIPARTY}
  GEN_EDIPARTY    = 5;
  {$EXTERNALSYM GEN_URI}
  GEN_URI         = 6;
  {$EXTERNALSYM GEN_IPADD}
  GEN_IPADD       = 7;
  {$EXTERNALSYM GEN_RID}
  GEN_RID         = 8;

  (* All existing reasons *)
  {$EXTERNALSYM CRLDP_ALL_REASONS}
  CRLDP_ALL_REASONS       = $807f;

  {$EXTERNALSYM CRL_REASON_NONE}
  CRL_REASON_NONE                         = -1;
  {$EXTERNALSYM CRL_REASON_UNSPECIFIED}
  CRL_REASON_UNSPECIFIED                  = 0;
  {$EXTERNALSYM CRL_REASON_KEY_COMPROMISE}
  CRL_REASON_KEY_COMPROMISE               = 1;
  {$EXTERNALSYM CRL_REASON_CA_COMPROMISE}
  CRL_REASON_CA_COMPROMISE                = 2;
  {$EXTERNALSYM CRL_REASON_AFFILIATION_CHANGED}
  CRL_REASON_AFFILIATION_CHANGED          = 3;
  {$EXTERNALSYM CRL_REASON_SUPERSEDED}
  CRL_REASON_SUPERSEDED                   = 4;
  {$EXTERNALSYM CRL_REASON_CESSATION_OF_OPERATION}
  CRL_REASON_CESSATION_OF_OPERATION       = 5;
  {$EXTERNALSYM CRL_REASON_CERTIFICATE_HOLD}
  CRL_REASON_CERTIFICATE_HOLD             = 6;
  {$EXTERNALSYM CRL_REASON_REMOVE_FROM_CRL}
  CRL_REASON_REMOVE_FROM_CRL              = 8;
  {$EXTERNALSYM CRL_REASON_PRIVILEGE_WITHDRAWN}
  CRL_REASON_PRIVILEGE_WITHDRAWN          = 9;
  {$EXTERNALSYM CRL_REASON_AA_COMPROMISE}
  CRL_REASON_AA_COMPROMISE                = 10;

  (* Values in idp_flags field *)
  (* IDP present *)
  {$EXTERNALSYM IDP_PRESENT}
  IDP_PRESENT     = $1;
  (* IDP values inconsistent *)
  {$EXTERNALSYM IDP_INVALID}
  IDP_INVALID     = $2;
  (* onlyuser true *)
  {$EXTERNALSYM IDP_ONLYUSER}
  IDP_ONLYUSER    = $4;
  (* onlyCA true *)
  {$EXTERNALSYM IDP_ONLYCA}
  IDP_ONLYCA      = $8;
  (* onlyattr true *)
  {$EXTERNALSYM IDP_ONLYATTR}
  IDP_ONLYATTR    = $10;
  (* indirectCRL true *)
  {$EXTERNALSYM IDP_INDIRECT}
  IDP_INDIRECT    = $20;
  (* onlysomereasons present *)
  {$EXTERNALSYM IDP_REASONS}
  IDP_REASONS     = $40;

  {$EXTERNALSYM EXT_END}
  EXT_END: array[0..13] of TIdC_INT = (-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

  (* X509_PURPOSE stuff *)

  {$EXTERNALSYM EXFLAG_BCONS}
  EXFLAG_BCONS            = $1;
  {$EXTERNALSYM EXFLAG_KUSAGE}
  EXFLAG_KUSAGE           = $2;
  {$EXTERNALSYM EXFLAG_XKUSAGE}
  EXFLAG_XKUSAGE          = $4;
  {$EXTERNALSYM EXFLAG_NSCERT}
  EXFLAG_NSCERT           = $8;

  {$EXTERNALSYM EXFLAG_CA}
  EXFLAG_CA               = $10;
  (* Really self issued not necessarily self signed *)
  {$EXTERNALSYM EXFLAG_SI}
  EXFLAG_SI               = $20;
  {$EXTERNALSYM EXFLAG_V1}
  EXFLAG_V1               = $40;
  {$EXTERNALSYM EXFLAG_INVALID}
  EXFLAG_INVALID          = $80;
  (* EXFLAG_SET is set to indicate that some values have been precomputed *)
  {$EXTERNALSYM EXFLAG_SET}
  EXFLAG_SET              = $100;
  {$EXTERNALSYM EXFLAG_CRITICAL}
  EXFLAG_CRITICAL         = $200;
  {$EXTERNALSYM EXFLAG_PROXY}
  EXFLAG_PROXY            = $400;

  {$EXTERNALSYM EXFLAG_INVALID_POLICY}
  EXFLAG_INVALID_POLICY   = $800;
  {$EXTERNALSYM EXFLAG_FRESHEST}
  EXFLAG_FRESHEST         = $1000;
  (* Self signed *)
  {$EXTERNALSYM EXFLAG_SS}
  EXFLAG_SS               = $2000;

  {$EXTERNALSYM EXFLAG_BCONS_CRITICAL}
  EXFLAG_BCONS_CRITICAL   = $10000; //introudced 3.0.0
  {$EXTERNALSYM EXFLAG_AKID_CRITICAL}
  EXFLAG_AKID_CRITICAL    = $20000; //introduced 3.0.0
  {$EXTERNALSYM EXFLAG_SKID_CRITICAL}
  EXFLAG_SKID_CRITICAL    = $40000; //introduced 3.0.0
  {$EXTERNALSYM EXFLAG_SAN_CRITICAL}
  EXFLAG_SAN_CRITICAL     = $80000; //introudced 3.0.0
  {$EXTERNALSYM EXFLAG_NO_FINGERPRINT}
  EXFLAG_NO_FINGERPRINT   = $100000; //introduced 3.0.0

  {$EXTERNALSYM KU_DIGITAL_SIGNATURE}
  KU_DIGITAL_SIGNATURE    = $0080;
  {$EXTERNALSYM KU_NON_REPUDIATION}
  KU_NON_REPUDIATION      = $0040;
  {$EXTERNALSYM KU_KEY_ENCIPHERMENT}
  KU_KEY_ENCIPHERMENT     = $0020;
  {$EXTERNALSYM KU_DATA_ENCIPHERMENT}
  KU_DATA_ENCIPHERMENT    = $0010;
  {$EXTERNALSYM KU_KEY_AGREEMENT}
  KU_KEY_AGREEMENT        = $0008;
  {$EXTERNALSYM KU_KEY_CERT_SIGN}
  KU_KEY_CERT_SIGN        = $0004;
  {$EXTERNALSYM KU_CRL_SIGN}
  KU_CRL_SIGN             = $0002;
  {$EXTERNALSYM KU_ENCIPHER_ONLY}
  KU_ENCIPHER_ONLY        = $0001;
  {$EXTERNALSYM KU_DECIPHER_ONLY}
  KU_DECIPHER_ONLY        = $8000;

  {$EXTERNALSYM NS_SSL_CLIENT}
  NS_SSL_CLIENT           = $80;
  {$EXTERNALSYM NS_SSL_SERVER}
  NS_SSL_SERVER           = $40;
  {$EXTERNALSYM NS_SMIME}
  NS_SMIME                = $20;
  {$EXTERNALSYM NS_OBJSIGN}
  NS_OBJSIGN              = $10;
  {$EXTERNALSYM NS_SSL_CA}
  NS_SSL_CA               = $04;
  {$EXTERNALSYM NS_SMIME_CA}
  NS_SMIME_CA             = $02;
  {$EXTERNALSYM NS_OBJSIGN_CA}
  NS_OBJSIGN_CA           = $01;
  {$EXTERNALSYM NS_ANY_CA}
  NS_ANY_CA               = NS_SSL_CA or NS_SMIME_CA or NS_OBJSIGN_CA;

  {$EXTERNALSYM XKU_SSL_SERVER}
  XKU_SSL_SERVER          = $1;
  {$EXTERNALSYM XKU_SSL_CLIENT}
  XKU_SSL_CLIENT          = $2;
  {$EXTERNALSYM XKU_SMIME}
  XKU_SMIME               = $4;
  {$EXTERNALSYM XKU_CODE_SIGN}
  XKU_CODE_SIGN           = $8;
  {$EXTERNALSYM XKU_SGC}
  XKU_SGC                 = $10;
  {$EXTERNALSYM XKU_OCSP_SIGN}
  XKU_OCSP_SIGN           = $20;
  {$EXTERNALSYM XKU_TIMESTAMP}
  XKU_TIMESTAMP           = $40;
  {$EXTERNALSYM XKU_DVCS}
  XKU_DVCS                = $80;
  {$EXTERNALSYM XKU_ANYEKU}
  XKU_ANYEKU              = $100;

  {$EXTERNALSYM X509_PURPOSE_DYNAMIC}
  X509_PURPOSE_DYNAMIC            = $1;
  {$EXTERNALSYM X509_PURPOSE_DYNAMIC_NAME}
  X509_PURPOSE_DYNAMIC_NAME       = $2;

  {$EXTERNALSYM X509_PURPOSE_DEFAULT_ANY}
  X509_PURPOSE_DEFAULT_ANY        = 0;
  {$EXTERNALSYM X509_PURPOSE_SSL_CLIENT}
  X509_PURPOSE_SSL_CLIENT         = 1;
  {$EXTERNALSYM X509_PURPOSE_SSL_SERVER}
  X509_PURPOSE_SSL_SERVER         = 2;
  {$EXTERNALSYM X509_PURPOSE_NS_SSL_SERVER}
  X509_PURPOSE_NS_SSL_SERVER      = 3;
  {$EXTERNALSYM X509_PURPOSE_SMIME_SIGN}
  X509_PURPOSE_SMIME_SIGN         = 4;
  {$EXTERNALSYM X509_PURPOSE_SMIME_ENCRYPT}
  X509_PURPOSE_SMIME_ENCRYPT      = 5;
  {$EXTERNALSYM X509_PURPOSE_CRL_SIGN}
  X509_PURPOSE_CRL_SIGN           = 6;
  {$EXTERNALSYM X509_PURPOSE_ANY}
  X509_PURPOSE_ANY                = 7;
  {$EXTERNALSYM X509_PURPOSE_OCSP_HELPER}
  X509_PURPOSE_OCSP_HELPER        = 8;
  {$EXTERNALSYM X509_PURPOSE_TIMESTAMP_SIGN}
  X509_PURPOSE_TIMESTAMP_SIGN     = 9;
  {$EXTERNALSYM X509_PURPOSE_CODE_SIGN}
  X509_PURPOSE_CODE_SIGN          = 10;  // Added in OpenSSL 3.2

  {$EXTERNALSYM X509_PURPOSE_MIN}
  X509_PURPOSE_MIN                = 1;
  {$EXTERNALSYM X509_PURPOSE_MAX}
  X509_PURPOSE_MAX                = 10;

  (* Flags for X509V3_EXT_print() *)

  {$EXTERNALSYM X509V3_EXT_UNKNOWN_MASK}
  X509V3_EXT_UNKNOWN_MASK         = TIdC_LONG($f) shl 16;
  (* Return error for unknown extensions *)
  {$EXTERNALSYM X509V3_EXT_DEFAULT}
  X509V3_EXT_DEFAULT              = 0;
  (* Print error for unknown extensions *)
  {$EXTERNALSYM X509V3_EXT_ERROR_UNKNOWN}
  X509V3_EXT_ERROR_UNKNOWN        = TIdC_LONG(1) shl 16;
  (* ASN1 parse unknown extensions *)
  {$EXTERNALSYM X509V3_EXT_PARSE_UNKNOWN}
  X509V3_EXT_PARSE_UNKNOWN        = TIdC_LONG(2) shl 16;
  (* BIO_dump unknown extensions *)
  {$EXTERNALSYM X509V3_EXT_DUMP_UNKNOWN}
  X509V3_EXT_DUMP_UNKNOWN         = TIdC_LONG(3) shl 16;

  (* Flags for X509V3_add1_i2d *)

  {$EXTERNALSYM X509V3_ADD_OP_MASK}
  X509V3_ADD_OP_MASK              = TIdC_LONG($f);
  {$EXTERNALSYM X509V3_ADD_DEFAULT}
  X509V3_ADD_DEFAULT              = TIdC_LONG(0);
  {$EXTERNALSYM X509V3_ADD_APPEND}
  X509V3_ADD_APPEND               = TIdC_LONG(1);
  {$EXTERNALSYM X509V3_ADD_REPLACE}
  X509V3_ADD_REPLACE              = TIdC_LONG(2);
  {$EXTERNALSYM X509V3_ADD_REPLACE_EXISTING}
  X509V3_ADD_REPLACE_EXISTING     = TIdC_LONG(3);
  {$EXTERNALSYM X509V3_ADD_KEEP_EXISTING}
  X509V3_ADD_KEEP_EXISTING        = TIdC_LONG(4);
  {$EXTERNALSYM X509V3_ADD_DELETE}
  X509V3_ADD_DELETE               = TIdC_LONG(5);
  {$EXTERNALSYM X509V3_ADD_SILENT}
  X509V3_ADD_SILENT               = $10;

  (* Flags for X509_check_* functions *)

  (*
   * Always check subject name for host match even if subject alt names present
   *)
  {$EXTERNALSYM X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT}
  X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT    = $1;
  (* Disable wildcard matching for dnsName fields and common name. *)
  {$EXTERNALSYM X509_CHECK_FLAG_NO_WILDCARDS}
  X509_CHECK_FLAG_NO_WILDCARDS    = $2;
  (* Wildcards must not match a partial label. *)
  {$EXTERNALSYM X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS}
  X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS = $4;
  (* Allow (non-partial) wildcards to match multiple labels. *)
  {$EXTERNALSYM X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS}
  X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS = $8;
  (* Constraint verifier subdomain patterns to match a single labels. *)
  {$EXTERNALSYM X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS}
  X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS = $10;
  (* Never check the subject CN *)
  {$EXTERNALSYM X509_CHECK_FLAG_NEVER_CHECK_SUBJECT}
  X509_CHECK_FLAG_NEVER_CHECK_SUBJECT    = $20;
  (*
   * Match reference identifiers starting with "." to any sub-domain.
   * This is a non-public flag, turned on implicitly when the subject
   * reference identity is a DNS name.
   *)
  {$EXTERNALSYM _X509_CHECK_FLAG_DOT_SUBDOMAINS}
  _X509_CHECK_FLAG_DOT_SUBDOMAINS = $8000;

  {$EXTERNALSYM ASIdOrRange_id}
  ASIdOrRange_id          = 0;
  {$EXTERNALSYM ASIdOrRange_range}
  ASIdOrRange_range       = 1;

  {$EXTERNALSYM ASIdentifierChoice_inherit}
  ASIdentifierChoice_inherit              = 0;
  {$EXTERNALSYM ASIdentifierChoice_asIdsOrRanges}
  ASIdentifierChoice_asIdsOrRanges        = 1;

  {$EXTERNALSYM IPAddressOrRange_addressPrefix}
  IPAddressOrRange_addressPrefix  = 0;
  {$EXTERNALSYM IPAddressOrRange_addressRange}
  IPAddressOrRange_addressRange   = 1;

  {$EXTERNALSYM IPAddressChoice_inherit}
  IPAddressChoice_inherit                 = 0;
  {$EXTERNALSYM IPAddressChoice_addressesOrRanges}
  IPAddressChoice_addressesOrRanges       = 1;

  (*
   * API tag for elements of the ASIdentifer SEQUENCE.
   *)
  {$EXTERNALSYM V3_ASID_ASNUM}
  V3_ASID_ASNUM   = 0;
  {$EXTERNALSYM V3_ASID_RDI}
  V3_ASID_RDI     = 1;

  (*
   * AFI values, assigned by IANA.  It'd be nice to make the AFI
   * handling code totally generic, but there are too many little things
   * that would need to be defined for other address families for it to
   * be worth the trouble.
   *)
  {$EXTERNALSYM IANA_AFI_IPV4}
  IANA_AFI_IPV4   = 1;
  {$EXTERNALSYM IANA_AFI_IPV6}
  IANA_AFI_IPV6   = 2;

type
  (* Forward reference *)
  //Pv3_ext_method = ^v3_ext_method;
  //Pv3_ext_ctx = ^v3_ext_ctx;

  (* Useful typedefs *)

  //X509V3_EXT_NEW = function: Pointer; cdecl;
  //X509V3_EXT_FREE = procedure(v1: Pointer); cdecl;
  //X509V3_EXT_D2I = function(v1: Pointer; v2: PPByte; v3: TIdC_Long): Pointer; cdecl;
  //X509V3_EXT_I2D = function(v1: Pointer; v2: PPByte): TIdC_INT; cdecl;
//  typedef STACK_OF(CONF_VALUE) *
//      (*X509V3_EXT_I2V) (const struct v3_ext_method *method, void *ext,
//                         STACK_OF(CONF_VALUE) *extlist);
//  typedef void *(*X509V3_EXT_V2I)(const struct v3_ext_method *method,
//                                  struct v3_ext_ctx *ctx,
//                                  STACK_OF(CONF_VALUE) *values);
  //X509V3_EXT_I2S = function(method: Pv3_ext_method; ext: Pointer): PIdAnsiChar; cdecl;
  //X509V3_EXT_S2I = function(method: Pv3_ext_method; ctx: Pv3_ext_ctx; const _str: PIdAnsiChar): Pointer; cdecl;
  //X509V3_EXT_I2R = function(const method: Pv3_ext_method; ext: Pointer; out_: PBIO; indent: TIdC_INT): TIdC_INT; cdecl;
  //X509V3_EXT_R2I = function(const method: Pv3_ext_method; ctx: Pv3_ext_ctx; const _str: PIdAnsiChar): Pointer; cdecl;

//  (* V3 extension structure *)
//  v3_ext_method = record
//    ext_nid: TIdC_INT;
//    ext_flags: TIdC_INT;
//(* If this is set the following four fields are ignored *)
//    it: PASN1_ITEM_EXP;
//(* Old style ASN1 calls *)
//    ext_new: X509V3_EXT_NEW;
//    ext_free: X509V3_EXT_FREE;
//    d2i: X509V3_EXT_D2I;
//    i2d: X509V3_EXT_I2D;
//(* The following pair is used for string extensions *)
//    i2s: X509V3_EXT_I2S;
//    s2i: X509V3_EXT_S2I;
//(* The following pair is used for multi-valued extensions *)
//    i2v: X509V3_EXT_I2V;
//    v2i: X509V3_EXT_V2I;
//(* The following are used for raw extensions *)
//    i2r: X509V3_EXT_I2R;
//    r2i: X509V3_EXT_R2I;
//    usr_data: Pointer;             (* Any extension specific data *)
//  end;
//  X509V3_EXT_METHOD = v3_ext_method;
//  PX509V3_EXT_METHOD = ^X509V3_EXT_METHOD;
//  DEFINE_STACK_OF(X509V3_EXT_METHOD)

//  typedef struct X509V3_CONF_METHOD_st {
//      PIdAnsiChar *(*get_string) (void *db, const section: PIdAnsiChar, const value: PIdAnsiChar);
//      STACK_OF(CONF_VALUE) *(*get_section) (void *db, const section: PIdAnsiChar);
//      void (*free_string) (void *db, PIdAnsiChar *string);
//      void (*free_section) (void *db, STACK_OF(CONF_VALUE) *section);
//  } X509V3_CONF_METHOD;

// Moved to ossl_typ
//  (* Context specific info *)
//  v3_ext_ctx = record
//    flags: TIdC_INT;
//    issuer_cert: PX509;
//    subject_cert: PX509;
//    subject_req: PX509_REQ;
//    crl: PX509_CRL;
//    db_meth: PX509V3_CONF_METHOD;
//    db: Pointer;
//  (* Maybe more here *)
//  end;

  {$EXTERNALSYM ENUMERATED_NAMES}
  ENUMERATED_NAMES = BIT_STRING_BITNAME;

  {$EXTERNALSYM BASIC_CONSTRAINTS_st}
  BASIC_CONSTRAINTS_st = record
    ca: TIdC_INT;
    pathlen: PASN1_INTEGER;
  end;
  {$EXTERNALSYM BASIC_CONSTRAINTS}
  BASIC_CONSTRAINTS = BASIC_CONSTRAINTS_st;
  {$EXTERNALSYM PBASIC_CONSTRAINTS}
  PBASIC_CONSTRAINTS = ^BASIC_CONSTRAINTS;

  {$EXTERNALSYM PKEY_USAGE_PERIOD_st}
  PKEY_USAGE_PERIOD_st = record
    notBefore: PASN1_GENERALIZEDTIME;
    notAfter: PASN1_GENERALIZEDTIME;
  end;
  {$EXTERNALSYM PKEY_USAGE_PERIOD}
  PKEY_USAGE_PERIOD = PKEY_USAGE_PERIOD_st;
  {$EXTERNALSYM PPKEY_USAGE_PERIOD}
  PPKEY_USAGE_PERIOD = ^PKEY_USAGE_PERIOD;

  {$EXTERNALSYM otherName_st}
  otherName_st = record
    type_id: PASN1_OBJECT;
    value: PASN1_TYPE;
  end;
  {$EXTERNALSYM OTHERNAME}
  OTHERNAME = otherName_st;
  {$EXTERNALSYM POTHERNAME}
  POTHERNAME = ^OTHERNAME;

  {$EXTERNALSYM EDIPartyName_st}
  EDIPartyName_st  = record
    nameAssigner: PASN1_STRING;
    partyName: PASN1_STRING;
  end;
  {$EXTERNALSYM EDIPARTYNAME}
  EDIPARTYNAME = EDIPartyName_st;
  {$EXTERNALSYM PEDIPARTYNAME}
  PEDIPARTYNAME = ^EDIPARTYNAME;

  {$EXTERNALSYM GENERAL_NAME_st_union}
  GENERAL_NAME_st_union = record
    case TIdC_INT of
      0: (_ptr: PIdAnsiChar);
      1: (otherName: POTHERNAME);   (* otherName *)
      2: (rfc822Name: PASN1_IA5STRING);
      3: (dNSName: PASN1_IA5STRING);
      4: (x400Address: PASN1_TYPE);
      5: (directoryName: PX509_NAME);
      6: (ediPartyName: PEDIPARTYNAME);
      7: (uniformResourceIdentifier: PASN1_IA5STRING);
      8: (iPAddress: PASN1_OCTET_STRING);
      9: (registeredID: PASN1_OBJECT);
      (* Old names *)
      10: (ip: PASN1_OCTET_STRING);  (* iPAddress *)
      11: (dirn: PX509_NAME);        (* dirn *)
      12: (ia5: PASN1_IA5STRING);    (* rfc822Name, dNSName,
                                      * uniformResourceIdentifier *)
      13: (rid: PASN1_OBJECT);       (* registeredID *)
      14: (other: PASN1_TYPE);       (* x400Address *)
  end;
  {$EXTERNALSYM GENERAL_NAME_st}
  GENERAL_NAME_st = record
    type_: TIdC_INT;
    d: GENERAL_NAME_st_union;
  end;
  {$EXTERNALSYM GENERAL_NAME}
  GENERAL_NAME = GENERAL_NAME_st;
  {$EXTERNALSYM PGENERAL_NAME}
  PGENERAL_NAME = ^GENERAL_NAME;

  {$EXTERNALSYM PSTACK_OF_GENERAL_NAME}
  PSTACK_OF_GENERAL_NAME = Pointer;
  {$EXTERNALSYM PGENERAL_NAMES}
  PGENERAL_NAMES = PSTACK_OF_GENERAL_NAME;

  {$EXTERNALSYM ACCESS_DESCRIPTION_st}
  ACCESS_DESCRIPTION_st = record
    method: PASN1_OBJECT;
    location: PGENERAL_NAME;
  end;
  {$EXTERNALSYM ACCESS_DESCRIPTION}
  ACCESS_DESCRIPTION = ACCESS_DESCRIPTION_st;
  {$EXTERNALSYM PACCESS_DESCRIPTION}
  PACCESS_DESCRIPTION = ^ACCESS_DESCRIPTION;
  {$EXTERNALSYM STACK_OF_ACCESS_DESCRIPTION}
  STACK_OF_ACCESS_DESCRIPTION = record end;
  {$EXTERNALSYM PSTACK_OF_ACCESS_DESCRIPTION}
  PSTACK_OF_ACCESS_DESCRIPTION = ^STACK_OF_ACCESS_DESCRIPTION;

  {$EXTERNALSYM AUTHORITY_INFO_ACCESS}
  AUTHORITY_INFO_ACCESS = PSTACK_OF_ACCESS_DESCRIPTION;


  {$EXTERNALSYM EXTENDED_KEY_USAGE}
  EXTENDED_KEY_USAGE = PSTACK_OF_ASN1_OBJECT;

  {$EXTERNALSYM TLS_FEATURE}
  TLS_FEATURE = PSTACK_OF_ASN1_INTEGER;

  {$EXTERNALSYM DIST_POINT_NAME_st_union}
  DIST_POINT_NAME_st_union = record
    case TIdC_INT of
      0: (fullname : PGENERAL_NAMES);
      1: (relativename : PSTACK_OF_X509_NAME_ENTRY);
  end;
  {$EXTERNALSYM DIST_POINT_NAME_st}
  DIST_POINT_NAME_st = record
    type_: TIdC_INT;
    (* If relativename then this contains the full distribution point name *)
    dpname: PX509_NAME;
  end;
  {$EXTERNALSYM DIST_POINT_NAME}
  DIST_POINT_NAME = DIST_POINT_NAME_st;
  {$EXTERNALSYM PDIST_POINT_NAME}
  PDIST_POINT_NAME = ^DIST_POINT_NAME;


  {$EXTERNALSYM DIST_POINT_ST}
  DIST_POINT_ST = record
      distpoint : PDIST_POINT_NAME;
      reasons : PASN1_BIT_STRING;
      CRLissuer : PGENERAL_NAMES;
      dp_reasons : TIdC_INT;
   end;

  {$EXTERNALSYM CRL_DIST_POINTS}
  CRL_DIST_POINTS = PSTACK_OF_DIST_POINT;

//  DEFINE_STACK_OF(DIST_POINT)

  {$EXTERNALSYM AUTHORITY_KEYID_st}
  AUTHORITY_KEYID_st = record
    keyid: PASN1_OCTET_STRING;
    issuer: PGENERAL_NAMES;
    serial: PASN1_INTEGER;
  end;
  {$EXTERNALSYM PAUTHORITY_KEYID_st}
  PAUTHORITY_KEYID_st = ^AUTHORITY_KEYID_st;

  (* Strong extranet structures *)

  {$EXTERNALSYM SXNET_ID_st}
  SXNET_ID_st = record
    zone: PASN1_INTEGER;
    user: PASN1_OCTET_STRING;
  end;
  {$EXTERNALSYM SXNETID}
  SXNETID = SXNET_ID_st;
  {$EXTERNALSYM PSXNETID}
  PSXNETID = ^SXNETID;
  {$EXTERNALSYM STACK_OF_SXNETID}
  STACK_OF_SXNETID = record end;
  {$EXTERNALSYM PSTACK_OF_SXNETID}
  PSTACK_OF_SXNETID = ^STACK_OF_SXNETID;

  {$EXTERNALSYM SXNET_st}
  SXNET_st = record
    version : PASN1_INTEGER;
    ids : PSTACK_OF_SXNETID;
  end;
  {$EXTERNALSYM SXNET}
  SXNET = SXNET_st;
  {$EXTERNALSYM PSXNET}
  PSXNET = ^SXNET;

  {$EXTERNALSYM NOTICEREF_st}
  NOTICEREF_st = record
    organization : PASN1_STRING;
    noticenos : PSTACK_OF_ASN1_INTEGER;
  end;
  {$EXTERNALSYM NOTICEREF}
  NOTICEREF = NOTICEREF_st;
  {$EXTERNALSYM PNOTICEREF}
  PNOTICEREF = ^NOTICEREF;

  {$EXTERNALSYM USERNOTICE_st}
  USERNOTICE_st = record
    noticeref: PNOTICEREF;
    exptext: PASN1_STRING;
  end;
  {$EXTERNALSYM USERNOTICE}
  USERNOTICE = USERNOTICE_st;
  {$EXTERNALSYM PUSERNOTICE}
  PUSERNOTICE = ^USERNOTICE;

  {$EXTERNALSYM POLICYQUALINFO_st_union}
  POLICYQUALINFO_st_union = record
    case TIdC_INT of
      0: (cpsuri: PASN1_IA5STRING);
      1: (usernotice: PUSERNOTICE);
      2: (other: PASN1_TYPE);
  end;
  {$EXTERNALSYM POLICYQUALINFO_st}
  POLICYQUALINFO_st = record
    pqualid: PASN1_OBJECT;
    d: POLICYQUALINFO_st_union;
  end;
  {$EXTERNALSYM POLICYQUALINFO}
  POLICYQUALINFO = POLICYQUALINFO_st;
  {$EXTERNALSYM PPOLICYQUALINFO}
  PPOLICYQUALINFO = ^POLICYQUALINFO;
  {$EXTERNALSYM STACK_OF_POLICYQUALINFO}
  STACK_OF_POLICYQUALINFO = record end;
  {$EXTERNALSYM PSTACK_OF_POLICYQUALINFO}
  PSTACK_OF_POLICYQUALINFO = ^STACK_OF_POLICYQUALINFO;

  {$EXTERNALSYM POLICYINFO_st}
  POLICYINFO_st = record
    policyid : PASN1_OBJECT;
    qualifiers : PSTACK_OF_POLICYQUALINFO;
  end;
  {$EXTERNALSYM POLICYINFO}
  POLICYINFO = POLICYINFO_st;
  {$EXTERNALSYM PPOLICYINFO}
  PPOLICYINFO = ^POLICYINFO;

  {$EXTERNALSYM STACK_OF_POLICYINFO}
  STACK_OF_POLICYINFO = record end;
  {$EXTERNALSYM PSTACK_OF_POLICYINFO}
  PSTACK_OF_POLICYINFO = ^STACK_OF_POLICYINFO;
  {$EXTERNALSYM CERTIFICATEPOLICIES}
  CERTIFICATEPOLICIES = PSTACK_OF_POLICYINFO;

  {$EXTERNALSYM POLICY_MAPPING_st}
  POLICY_MAPPING_st = record
    issuerDomainPolicy: PASN1_OBJECT;
    subjectDomainPolicy: PASN1_OBJECT;
  end;
  {$EXTERNALSYM POLICY_MAPPING}
  POLICY_MAPPING = POLICY_MAPPING_st;
  {$EXTERNALSYM PPOLICY_MAPPING}
  PPOLICY_MAPPING = ^POLICY_MAPPING;
  {$EXTERNALSYM STACK_OF_POLICY_MAPPING}
  STACK_OF_POLICY_MAPPING = record end;
  {$EXTERNALSYM PSTACK_OF_POLICY_MAPPING}
  PSTACK_OF_POLICY_MAPPING = ^STACK_OF_POLICY_MAPPING;
  {$EXTERNALSYM POLICY_MAPPINGS}
  POLICY_MAPPINGS = PSTACK_OF_POLICY_MAPPING;

  {$EXTERNALSYM GENERAL_SUBTREE_st}
  GENERAL_SUBTREE_st = record
    base: PGENERAL_NAME;
    minimum: PASN1_INTEGER;
    maximum: PASN1_INTEGER;
  end;
  {$EXTERNALSYM GENERAL_SUBTREE}
  GENERAL_SUBTREE = GENERAL_SUBTREE_st;
  {$EXTERNALSYM PGENERAL_SUBTREE}
  PGENERAL_SUBTREE = ^GENERAL_SUBTREE;
  {$EXTERNALSYM STACK_OF_GENERAL_SUBTREE}
  STACK_OF_GENERAL_SUBTREE = record end;
  {$EXTERNALSYM PSTACK_OF_GENERAL_SUBTREE}
  PSTACK_OF_GENERAL_SUBTREE = ^STACK_OF_GENERAL_SUBTREE;

  {$EXTERNALSYM NAME_CONSTRAINTS_st}
  NAME_CONSTRAINTS_st = record
    permittedSubtrees : PSTACK_OF_GENERAL_SUBTREE;
    excludedSubtrees : PSTACK_OF_GENERAL_SUBTREE;
  end;

  {$EXTERNALSYM POLICY_CONSTRAINTS_st}
  POLICY_CONSTRAINTS_st = record
    requireExplicitPolicy: PASN1_INTEGER;
    inhibitPolicyMapping: PASN1_INTEGER;
  end;
  {$EXTERNALSYM POLICY_CONSTRAINTS}
  POLICY_CONSTRAINTS = POLICY_CONSTRAINTS_st;
  {$EXTERNALSYM PPOLICY_CONSTRAINTS}
  PPOLICY_CONSTRAINTS = ^POLICY_CONSTRAINTS;

  (* Proxy certificate structures, see RFC 3820 *)
  {$EXTERNALSYM PROXY_POLICY_st}
  PROXY_POLICY_st = record
    policyLanguage: PASN1_OBJECT;
    policy: PASN1_OCTET_STRING;
  end;
  {$EXTERNALSYM PROXY_POLICY}
  PROXY_POLICY = PROXY_POLICY_st;
  {$EXTERNALSYM PPROXY_POLICY}
  PPROXY_POLICY = ^PROXY_POLICY;
//  DECLARE_ASN1_FUNCTIONS(PROXY_POLICY)

  {$EXTERNALSYM PROXY_CERT_INFO_EXTENSION_st}
  PROXY_CERT_INFO_EXTENSION_st = record
    pcPathLengthConstraint: PASN1_INTEGER;
    proxyPolicy: PPROXY_POLICY;
  end;
  {$EXTERNALSYM PROXY_CERT_INFO_EXTENSION}
  PROXY_CERT_INFO_EXTENSION = PROXY_CERT_INFO_EXTENSION_st;
  {$EXTERNALSYM PPROXY_CERT_INFO_EXTENSION}
  PPROXY_CERT_INFO_EXTENSION = ^PROXY_CERT_INFO_EXTENSION;
//  DECLARE_ASN1_FUNCTIONS(PROXY_CERT_INFO_EXTENSION)

  {$EXTERNALSYM ISSUING_DIST_POint_st}
  ISSUING_DIST_POint_st = record
    distpoint: PDIST_POINT_NAME;
    onlyuser : TIdC_INT;
    onlyCA : TIdC_INT;
    onlysomereasons: PASN1_BIT_STRING;
    indirectCRL : TIdC_INT;
    onlyattr : TIdC_INT;
  end;
  {$EXTERNALSYM STACK_OF_ASN1_STRING}
  STACK_OF_ASN1_STRING = record end;
  {$EXTERNALSYM PSTACK_OF_ASN1_STRING}
  PSTACK_OF_ASN1_STRING = ^STACK_OF_ASN1_STRING;

//  # define X509V3_conf_err(val) ERR_add_error_data(6, \
//                          "section:", (val)->section, \
//                          ",name:", (val)->name, ",value:", (val)->value)
//
//  # define X509V3_set_ctx_test(ctx) \
//                          X509V3_set_ctx(ctx, NULL, NULL, NULL, NULL, CTX_TEST)
//  # define X509V3_set_ctx_nodb(ctx) (ctx)->db = NULL;
//
//  # define EXT_BITSTRING(nid, table) { nid, 0, ASN1_ITEM_ref(ASN1_BIT_STRING), \
//                          0,0,0,0, \
//                          0,0, \
//                          (X509V3_EXT_I2V)i2v_ASN1_BIT_STRING, \
//                          (X509V3_EXT_V2I)v2i_ASN1_BIT_STRING, \
//                          NULL, NULL, \
//                          table}
//
//  # define EXT_IA5STRING(nid) { nid, 0, ASN1_ITEM_ref(ASN1_IA5STRING), \
//                          0,0,0,0, \
//                          (X509V3_EXT_I2S)i2s_ASN1_IA5STRING, \
//                          (X509V3_EXT_S2I)s2i_ASN1_IA5STRING, \
//                          0,0,0,0, \
//                          NULL}

  {$EXTERNALSYM PX509_PURPOSE}
  PX509_PURPOSE = ^X509_PURPOSE;
  {$EXTERNALSYM x509_purpose_st}
  x509_purpose_st = record
    purpose: TIdC_INT;
    trust: TIdC_INT;                  (* Default trust ID *)
    flags: TIdC_INT;
    check_purpose: function(const v1: PX509_PURPOSE; const v2: PX509; v3: TIdC_INT): TIdC_INT; cdecl;
    name: PIdAnsiChar;
    sname: PIdAnsiChar;
    usr_data: Pointer;
  end;
  {$EXTERNALSYM X509_PURPOSE}
  X509_PURPOSE = x509_purpose_st;
  {$EXTERNALSYM STACK_OF_X509_PURPOSE}
  STACK_OF_X509_PURPOSE = record end;
  {$EXTERNALSYM PSTACK_OF_X509_PURPOSE}
  PSTACK_OF_X509_PURPOSE = ^STACK_OF_X509_PURPOSE;
  {$EXTERNALSYM STACK_OF_X509_POLICY_NODE}
  STACK_OF_X509_POLICY_NODE = record end;
  {$EXTERNALSYM PSTACK_OF_X509_POLICY_NODE}
  PSTACK_OF_X509_POLICY_NODE = ^STACK_OF_X509_POLICY_NODE;

//  DECLARE_ASN1_FUNCTIONS(BASIC_CONSTRAINTS_st)

//  DECLARE_ASN1_FUNCTIONS(SXNET)
//  DECLARE_ASN1_FUNCTIONS(SXNETID)

  {$EXTERNALSYM ASRange_st}
  ASRange_st = record
    min, max: PASN1_INTEGER;
  end;
  {$EXTERNALSYM ASRange}
  ASRange = ASRange_st;
  {$EXTERNALSYM PASRange}
  PASRange = ^ASRange;

  {$EXTERNALSYM ASIdOrRange_st}
  ASIdOrRange_st = record
    type_: TIdC_INT;
    case u: TIdC_INT of
      0: (id: PASN1_INTEGER);
      1: (range: PASRange);
  end;
  {$EXTERNALSYM ASIdOrRange}
  ASIdOrRange = ASIdOrRange_st;
  {$EXTERNALSYM PASIdOrRange}
  PASIdOrRange = ^ASIdOrRange;
  {$EXTERNALSYM ASIdOrRanges}
  ASIdOrRanges = PSTACK_OF_ASIdOrRange;

  {$EXTERNALSYM ASIdentifierChoice_st}
  ASIdentifierChoice_st = record
    type_: TIdC_INT;
    case u: TIdC_INT of
      0: (inherit: PASN1_NULL);
      1: (asIdsOrRanges: PASIdOrRanges);
  end;
  {$EXTERNALSYM ASIdentifierChoice}
  ASIdentifierChoice = ASIdentifierChoice_st;
  {$EXTERNALSYM PASIdentifierChoice}
  PASIdentifierChoice = ^ASIdentifierChoice;

  {$EXTERNALSYM ASIdentifiers_st}
  ASIdentifiers_st = record
    asnum, rdi: PASIdentifierChoice;
  end;
  {$EXTERNALSYM ASIdentifiers}
  ASIdentifiers = ASIdentifiers_st;
  {$EXTERNALSYM PASIdentifiers}
  PASIdentifiers = ^ASIdentifiers;

//  DECLARE_ASN1_FUNCTIONS(ASRange)
//  DECLARE_ASN1_FUNCTIONS(ASIdOrRange)
//  DECLARE_ASN1_FUNCTIONS(ASIdentifierChoice)
//  DECLARE_ASN1_FUNCTIONS(ASIdentifiers)

  {$EXTERNALSYM IPAddressRange_st}
  IPAddressRange_st = record
    min, max: PASN1_BIT_STRING;
  end;
  {$EXTERNALSYM IPAddressRange}
  IPAddressRange = IPAddressRange_st;
  {$EXTERNALSYM PIPAddressRange}
  PIPAddressRange = ^IPAddressRange;

  {$EXTERNALSYM IPAddressOrRange_st}
  IPAddressOrRange_st = record
    type_: TIdC_INT;
    case u: TIdC_INT of
      0: (addressPrefix: PASN1_BIT_STRING);
      1: (addressRange: PIPAddressRange);
  end;
  {$EXTERNALSYM IPAddressOrRange}
  IPAddressOrRange = IPAddressOrRange_st;
  {$EXTERNALSYM PIPAddressOrRange}
  PIPAddressOrRange = ^IPAddressOrRange;

  {$EXTERNALSYM STACK_OF_IPAddressOrRange}
  STACK_OF_IPAddressOrRange = record end;
  {$EXTERNALSYM PSTACK_OF_IPAddressOrRange}
  PSTACK_OF_IPAddressOrRange = ^STACK_OF_IPAddressOrRange;
  {$EXTERNALSYM PIPAddressOrRanges}
  PIPAddressOrRanges = PSTACK_OF_IPAddressOrRange;

  {$EXTERNALSYM IPAddressChoice_st}
  IPAddressChoice_st = record
    type_: TIdC_INT;
    case u: TIdC_INT of
      0: (inherit: PASN1_NULL);
      1: (addressesOrRanges: PIPAddressOrRanges);
  end;
  {$EXTERNALSYM IPAddressChoice}
  IPAddressChoice = IPAddressChoice_st;
  {$EXTERNALSYM PIPAddressChoice}
  PIPAddressChoice = ^IPAddressChoice;

  {$EXTERNALSYM IPAddressFamily_st}
  IPAddressFamily_st = record
    addressFamily: PASN1_OCTET_STRING;
    ipAddressChoice: PIPAddressChoice;
  end;
  {$EXTERNALSYM IPAddressFamily}
  IPAddressFamily = IPAddressFamily_st;
  {$EXTERNALSYM PIPAddressFamily}
  PIPAddressFamily = ^IPAddressFamily;
  {$EXTERNALSYM IPAddrBlocks}
  IPAddrBlocks = PSTACK_OF_IPAddressFamily;

//  DECLARE_ASN1_FUNCTIONS(IPAddressRange)
//  DECLARE_ASN1_FUNCTIONS(IPAddressOrRange)
//  DECLARE_ASN1_FUNCTIONS(IPAddressChoice)
//  DECLARE_ASN1_FUNCTIONS(IPAddressFamily)

  {$EXTERNALSYM NamingAuthority_st}
  NamingAuthority_st = record end;
  {$EXTERNALSYM NAMING_AUTHORITY}
  NAMING_AUTHORITY = NamingAuthority_st;
  {$EXTERNALSYM PNAMING_AUTHORITY}
  PNAMING_AUTHORITY = ^NAMING_AUTHORITY;

  {$EXTERNALSYM ProfessionInfo_st}
  ProfessionInfo_st = record end;
  {$EXTERNALSYM PROFESSION_INFO}
  PROFESSION_INFO = ProfessionInfo_st;
  {$EXTERNALSYM PPROFESSION_INFO}
  PPROFESSION_INFO = ^PROFESSION_INFO;

  {$EXTERNALSYM Admissions_st}
  Admissions_st = record end;
  {$EXTERNALSYM ADMISSIONS}
  ADMISSIONS = Admissions_st;
  {$EXTERNALSYM PADMISSIONS}
  PADMISSIONS = ^ADMISSIONS;

  {$EXTERNALSYM AdmissionSyntax_st}
  AdmissionSyntax_st = record end;
  {$EXTERNALSYM ADMISSION_SYNTAX}
  ADMISSION_SYNTAX = AdmissionSyntax_st;
  {$EXTERNALSYM PADMISSION_SYNTAX}
  PADMISSION_SYNTAX = ^ADMISSION_SYNTAX;
//  DECLARE_ASN1_FUNCTIONS(NAMING_AUTHORITY)
//  DECLARE_ASN1_FUNCTIONS(PROFESSION_INFO)
//  DECLARE_ASN1_FUNCTIONS(ADMISSIONS)
//  DECLARE_ASN1_FUNCTIONS(ADMISSION_SYNTAX)
//  DEFINE_STACK_OF(ADMISSIONS)
//  DEFINE_STACK_OF(PROFESSION_INFO)
//  typedef STACK_OF(PROFESSION_INFO) PROFESSION_INFOS;

//  function SXNET_add_id_asc(psx: PPSXNET; const zone: PIdAnsiChar; const user: PIdAnsiChar; userlen: TIdC_INT): TIdC_INT;
//  function SXNET_add_id_ulong(psx: PPSXNET; lzone: TIdC_ULONG; const user: PIdAnsiChar; userlen: TIdC_INT): TIdC_INT;
//  function SXNET_add_id_INTEGER(psx: PPSXNET; izone: PASN1_INTEGER; const user: PIdAnsiChar; userlen: TIdC_INT): TIdC_INT;

//  function SXNET_get_id_asc(sx: PSXNET; const zone: PIdAnsiChar): PASN1_OCTET_STRING;
//  function SXNET_get_id_ulong(sx: PSXNET; lzone: TIdC_ULONG): PASN1_OCTET_STRING;
//  function SXNET_get_id_INTEGER(sx: PSXNET; zone: PASN1_INTEGER): PASN1_OCTET_STRING;

//  DECLARE_ASN1_FUNCTIONS(AUTHORITY_KEYID)

//  DECLARE_ASN1_FUNCTIONS(PKEY_USAGE_PERIOD)

//  DECLARE_ASN1_FUNCTIONS(GENERAL_NAME)
//  GENERAL_NAME *GENERAL_NAME_dup(a: PGENERAL_NAME);
    { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:
		
  	  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
	  files generated for C++. }
	  

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
var
  {$EXTERNALSYM GENERAL_NAME_cmp}
  GENERAL_NAME_cmp: function (a: PGENERAL_NAME; b: PGENERAL_NAME): TIdC_INT; cdecl = nil;

//  ASN1_BIT_STRING *v2i_ASN1_BIT_STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; STACK_OF(CONF_VALUE) *nval);
//  STACK_OF(CONF_VALUE) *i2v_ASN1_BIT_STRING(method: PX509V3_EXT_METHOD; ASN1_BIT_STRING *bits; STACK_OF(CONF_VALUE) *extlist);
  //function i2s_ASN1_IA5STRING(method: PX509V3_EXT_METHOD; ia5: PASN1_IA5STRING): PIdAnsiChar;
  //function s2i_ASN1_IA5STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; const _str: PIdAnsiChar): PASN1_IA5STRING;

//  STACK_OF(CONF_VALUE) *i2v_GENERAL_NAME(method: PX509V3_EXT_METHOD; gen: PGENERAL_NAME; STACK_OF(CONF_VALUE) *ret);
  {$EXTERNALSYM GENERAL_NAME_print}
  GENERAL_NAME_print: function (out_: PBIO; gen: PGENERAL_NAME): TIdC_INT; cdecl = nil;

//  DECLARE_ASN1_FUNCTIONS(GENERAL_NAMES)

//  STACK_OF(CONF_VALUE) *i2v_GENERAL_NAMES(method: PX509V3_EXT_METHOD, GENERAL_NAMES *gen, STACK_OF(CONF_VALUE) *extlist);
//  GENERAL_NAMES *v2i_GENERAL_NAMES(const method: PX509V3_EXT_METHOD, ctx: PX509V3_CTX, STACK_OF(CONF_VALUE) *nval);

//  DECLARE_ASN1_FUNCTIONS(OTHERNAME)
//  DECLARE_ASN1_FUNCTIONS(EDIPARTYNAME)
  {$EXTERNALSYM OTHERNAME_cmp}
  OTHERNAME_cmp: function (a: POTHERNAME; b: POTHERNAME): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM GENERAL_NAME_set0_value}
  GENERAL_NAME_set0_value: procedure (a: PGENERAL_NAME; type_: TIdC_INT; value: Pointer); cdecl = nil;
  {$EXTERNALSYM GENERAL_NAME_get0_value}
  GENERAL_NAME_get0_value: function (const a: PGENERAL_NAME; ptype: PIdC_INT): Pointer; cdecl = nil;
  {$EXTERNALSYM GENERAL_NAME_set0_othername}
  GENERAL_NAME_set0_othername: function (gen: PGENERAL_NAME; oid: PASN1_OBJECT; value: PASN1_TYPE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM GENERAL_NAME_get0_otherName}
  GENERAL_NAME_get0_otherName: function (const gen: PGENERAL_NAME; poid: PPASN1_OBJECT; pvalue: PPASN1_TYPE): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM GENERAL_NAMES_free}
  GENERAL_NAMES_free : procedure(a : PGENERAL_NAMES); cdecl =nil;
  //function i2s_ASN1_OCTET_STRING(method: PX509V3_EXT_METHOD; const ia5: PASN1_OCTET_STRING): PIdAnsiChar;
  //function s2i_ASN1_OCTET_STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; const _str: PIdAnsiChar): PASN1_OCTET_STRING;

//  DECLARE_ASN1_FUNCTIONS(EXTENDED_KEY_USAGE)
  {$EXTERNALSYM i2a_ACCESS_DESCRIPTION}
  i2a_ACCESS_DESCRIPTION: function (bp: PBIO; const a: PACCESS_DESCRIPTION): TIdC_INT; cdecl = nil;

//  DECLARE_ASN1_ALLOC_FUNCTIONS(TLS_FEATURE)

//  DECLARE_ASN1_FUNCTIONS(CERTIFICATEPOLICIES)
//  DECLARE_ASN1_FUNCTIONS(POLICYINFO)
//  DECLARE_ASN1_FUNCTIONS(POLICYQUALINFO)
//  DECLARE_ASN1_FUNCTIONS(USERNOTICE)
//  DECLARE_ASN1_FUNCTIONS(NOTICEREF)

//  DECLARE_ASN1_FUNCTIONS(CRL_DIST_POINTS)
//  DECLARE_ASN1_FUNCTIONS(DIST_POINT)
//  DECLARE_ASN1_FUNCTIONS(DIST_POINT_NAME)
//  DECLARE_ASN1_FUNCTIONS(ISSUING_DIST_POINT)

  {$EXTERNALSYM DIST_POINT_set_dpname}
  DIST_POINT_set_dpname: function (dpn: PDIST_POINT_NAME; iname: PX509_NAME): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM NAME_CONSTRAINTS_check}
  NAME_CONSTRAINTS_check: function (x: PX509; nc: PNAME_CONSTRAINTS): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM NAME_CONSTRAINTS_check_CN}
  NAME_CONSTRAINTS_check_CN: function (x: PX509; nc: PNAME_CONSTRAINTS): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM BASIC_CONSTRAINTS_free}
  BASIC_CONSTRAINTS_free : procedure(bc : PBASIC_CONSTRAINTS); cdecl = nil;
  {$EXTERNALSYM AUTHORITY_KEYID_free}
  AUTHORITY_KEYID_free : procedure(id : PAUTHORITY_KEYID); cdecl = nil;
//  DECLARE_ASN1_FUNCTIONS(ACCESS_DESCRIPTION)
//  DECLARE_ASN1_FUNCTIONS(AUTHORITY_INFO_ACCESS)

//  DECLARE_ASN1_ITEM(POLICY_MAPPING)
//  DECLARE_ASN1_ALLOC_FUNCTIONS(POLICY_MAPPING)
//  DECLARE_ASN1_ITEM(POLICY_MAPPINGS)

//  DECLARE_ASN1_ITEM(GENERAL_SUBTREE)
//  DECLARE_ASN1_ALLOC_FUNCTIONS(GENERAL_SUBTREE)

//  DECLARE_ASN1_ITEM(NAME_CONSTRAINTS)
//  DECLARE_ASN1_ALLOC_FUNCTIONS(NAME_CONSTRAINTS)

//  DECLARE_ASN1_ALLOC_FUNCTIONS(POLICY_CONSTRAINTS)
//  DECLARE_ASN1_ITEM(POLICY_CONSTRAINTS)

  //function a2i_GENERAL_NAME(out_: PGENERAL_NAME; const method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; TIdC_INT gen_type; const value: PIdAnsiChar; is_nc: TIdC_INT): GENERAL_NAME;

  //function v2i_GENERAL_NAME(const method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; cnf: PCONF_VALUE): PGENERAL_NAME;
  //function v2i_GENERAL_NAME_ex(out_: PGENERAL_NAME; const method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; cnf: PCONF_VALUE; is_nc: TIdC_INT): PGENERAL_NAME;
  //procedure X509V3_conf_free(_val: PCONF_VALUE);

  {$EXTERNALSYM X509V3_EXT_nconf_nid}
  X509V3_EXT_nconf_nid: function (conf: PCONF; ctx: PX509V3_CTX; ext_nid: TIdC_INT; const value: PIdAnsiChar): PX509_EXTENSION; cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_nconf}
  X509V3_EXT_nconf: function (conf: PCONF; ctx: PX509V3_CTX; const name: PIdAnsiChar; const value: PIdAnsiChar): PX509_EXTENSION; cdecl = nil;
//  TIdC_INT X509V3_EXT_add_nconf_sk(conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; STACK_OF(X509_EXTENSION) **sk);
  {$EXTERNALSYM X509V3_EXT_add_nconf}
  X509V3_EXT_add_nconf: function (conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; cert: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_REQ_add_nconf}
  X509V3_EXT_REQ_add_nconf: function (conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; req: PX509_REQ): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_CRL_add_nconf}
  X509V3_EXT_CRL_add_nconf: function (conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; crl: PX509_CRL): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509V3_EXT_conf_nid}
  X509V3_EXT_conf_nid: function (conf: Pointer; ctx: PX509V3_CTX; ext_nid: TIdC_INT; const value: PIdAnsiChar): PX509_EXTENSION; cdecl = nil;
//  X509_EXTENSION *X509V3_EXT_conf_nid(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; ext_nid: TIdC_INT; const value: PIdAnsiChar);
  {$EXTERNALSYM X509V3_EXT_conf}
  X509V3_EXT_conf: function (conf: Pointer; ctx: PX509V3_CTX; const name: PIdAnsiChar; const value: PIdAnsiChar): PX509_EXTENSION; cdecl = nil;
//  X509_EXTENSION *X509V3_EXT_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const name: PIdAnsiChar; const value: PIdAnsiChar);
  {$EXTERNALSYM X509V3_EXT_add_conf}
  X509V3_EXT_add_conf: function (conf: Pointer; ctx: PX509V3_CTX; const section: PIdAnsiChar; cert: PX509): TIdC_INT; cdecl = nil;
//  TIdC_INT X509V3_EXT_add_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const section: PIdAnsiChar; cert: PX509);
  {$EXTERNALSYM X509V3_EXT_REQ_add_conf}
  X509V3_EXT_REQ_add_conf: function (conf: Pointer; ctx: PX509V3_CTX; const section: PIdAnsiChar; req: PX509_REQ): TIdC_INT; cdecl = nil;
//  TIdC_INT X509V3_EXT_REQ_add_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const section: PIdAnsiChar; req: PX509_REQ);
  {$EXTERNALSYM X509V3_EXT_CRL_add_conf}
  X509V3_EXT_CRL_add_conf: function (conf: Pointer; ctx: PX509V3_CTX; const section: PIdAnsiChar; crl: PX509_CRL): TIdC_INT; cdecl = nil;
//  TIdC_INT X509V3_EXT_CRL_add_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const section: PIdAnsiChar; crl: PX509_CRL);

//  TIdC_INT X509V3_add_value_bool_nf(const name: PIdAnsiChar; TIdC_INT asn1_bool; STACK_OF(CONF_VALUE) **extlist);
  //function X509V3_get_value_bool(const value: PCONF_VALUE; asn1_bool: PIdC_INT): TIdC_INT;
  //function X509V3_get_value_int(const value: PCONF_VALUE; aint: PPASN1_INTEGER): TIdC_INT;
  {$EXTERNALSYM X509V3_set_nconf}
  X509V3_set_nconf: procedure (ctx: PX509V3_CTX; conf: PCONF); cdecl = nil;
//  void X509V3_set_conf_lhash(ctx: PX509V3_CTX; LHASH_OF(CONF_VALUE) *lhash);

  {$EXTERNALSYM X509V3_get_string}
  X509V3_get_string: function (ctx: PX509V3_CTX; const name: PIdAnsiChar; const section: PIdAnsiChar): PIdAnsiChar; cdecl = nil;
//  STACK_OF(CONF_VALUE) *X509V3_get_section(ctx: PX509V3_CTX; const section: PIdAnsiChar);
  {$EXTERNALSYM X509V3_string_free}
  X509V3_string_free: procedure (ctx: PX509V3_CTX; _str: PIdAnsiChar); cdecl = nil;
//  void X509V3_section_free(ctx: PX509V3_CTX; STACK_OF(CONF_VALUE) *section);
  {$EXTERNALSYM X509V3_set_ctx}
  X509V3_set_ctx: procedure (ctx: PX509V3_CTX; issuer: PX509; subject: PX509; req: PX509_REQ; crl: PX509_CRL; flags: TIdC_INT); cdecl = nil;

//  TIdC_INT X509V3_add_value(const name: PIdAnsiChar; const value: PIdAnsiChar; STACK_OF(CONF_VALUE) **extlist);
//  TIdC_INT X509V3_add_value_uPIdAnsiChar(const name: PIdAnsiChar; const Byte *value; STACK_OF(CONF_VALUE) **extlist);
//  TIdC_INT X509V3_add_value_bool(const name: PIdAnsiChar; TIdC_INT asn1_bool; STACK_OF(CONF_VALUE) **extlist);
//  TIdC_INT X509V3_add_value_int(const name: PIdAnsiChar; const aint: PASN1_INTEGER; STACK_OF(CONF_VALUE) **extlist);
  //function i2s_ASN1_INTEGER(meth: PX509V3_EXT_METHOD; const aint: PASN1_INTEGER): PIdAnsiChar;
  //function s2i_ASN1_INTEGER(meth: PX509V3_EXT_METHOD; const value: PIdAnsiChar): PASN1_INTEGER;
  //function i2s_ASN1_ENUMERATED(meth: PX509V3_EXT_METHOD; const aint: PASN1_ENUMERATED): PIdAnsiChar;
  //function i2s_ASN1_ENUMERATED_TABLE(meth: PX509V3_EXT_METHOD; const aint: PASN1_ENUMERATED): PIdAnsiChar;
  //function X509V3_EXT_add(ext: PX509V3_EXT_METHOD): TIdC_INT;
  //function X509V3_EXT_add_list(extlist: PX509V3_EXT_METHOD): TIdC_INT;
  {$EXTERNALSYM X509V3_EXT_add_alias}
  X509V3_EXT_add_alias: function (nid_to: TIdC_INT; nid_from: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509V3_EXT_cleanup}
  X509V3_EXT_cleanup: procedure ; cdecl = nil;

  //function X509V3_EXT_get(ext: PX509_EXTENSION): PX509V3_EXT_METHOD;
  //function X509V3_EXT_get_nid(nid: TIdC_INT): PX509V3_EXT_METHOD;
  {$EXTERNALSYM X509V3_add_standard_extensions}
  X509V3_add_standard_extensions: function : TIdC_INT; cdecl = nil;
//  STACK_OF(CONF_VALUE) *X509V3_parse_list(const line: PIdAnsiChar);
  {$EXTERNALSYM X509V3_EXT_d2i}
  X509V3_EXT_d2i: function (ext: PX509_EXTENSION): Pointer; cdecl = nil;
//  void *X509V3_get_d2i(const STACK_OF(X509_EXTENSION) *x; nid: TIdC_INT; TIdC_INT *crit; TIdC_INT *idx);

  {$EXTERNALSYM X509V3_EXT_i2d}
  X509V3_EXT_i2d: function (ext_nid: TIdC_INT; crit: TIdC_INT; ext_struc: Pointer): PX509_EXTENSION; cdecl = nil;
//  TIdC_INT X509V3_add1_i2d(STACK_OF(X509_EXTENSION) **x; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; TIdC_ULONG flags);

//  void X509V3_EXT_val_prn(out_: PBIO; STACK_OF(CONF_VALUE) *val; indent: TIdC_INT; TIdC_INT ml);
  {$EXTERNALSYM X509V3_EXT_print}
  X509V3_EXT_print: function (out_: PBIO; ext: PX509_EXTENSION; flag: TIdC_ULONG; indent: TIdC_INT): TIdC_INT; cdecl = nil;
//  TIdC_INT X509V3_extensions_print(out_: PBIO; const PIdAnsiChar *title; const STACK_OF(X509_EXTENSION) *exts; flag: TIdC_ULONG; indent: TIdC_INT);

  {$EXTERNALSYM X509_check_ca}
  X509_check_ca: function (x: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_check_purpose}
  X509_check_purpose: function (x: PX509; id: TIdC_INT; ca: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_supported_extension}
  X509_supported_extension: function (ex: PX509_EXTENSION): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_PURPOSE_set}
  X509_PURPOSE_set: function (p: PIdC_INT; purpose: TIdC_INT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_check_issued}
  X509_check_issued: function (issuer: PX509; subject: PX509): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_check_akid}
  X509_check_akid: function (issuer: PX509; akid: PAUTHORITY_KEYID): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_set_proxy_flag}
  X509_set_proxy_flag: procedure (x: PX509); cdecl = nil;
  {$EXTERNALSYM X509_set_proxy_pathlen}
  X509_set_proxy_pathlen: procedure (x: PX509; l: TIdC_LONG); cdecl = nil;
  {$EXTERNALSYM X509_get_proxy_pathlen}
  X509_get_proxy_pathlen: function (x: PX509): TIdC_LONG; cdecl = nil;

  {$EXTERNALSYM X509_get_extension_flags}
  X509_get_extension_flags: function (x: PX509): TIdC_UINT32; cdecl = nil;
  {$EXTERNALSYM X509_get_key_usage}
  X509_get_key_usage: function (x: PX509): TIdC_UINT32; cdecl = nil;
  {$EXTERNALSYM X509_get_extended_key_usage}
  X509_get_extended_key_usage: function (x: PX509): TIdC_UINT32; cdecl = nil;
  {$EXTERNALSYM X509_get0_subject_key_id}
  X509_get0_subject_key_id: function (x: PX509): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM X509_get0_authority_key_id}
  X509_get0_authority_key_id: function (x: PX509): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM X509_get0_authority_issuer}
  X509_get0_authority_issuer: function(x : PX509) : PGENERAL_NAMES;  cdecl = nil;
  {$EXTERNALSYM X509_get0_authority_serial}
  X509_get0_authority_serial: function (x: PX509): PASN1_INTEGER; cdecl = nil;

  {$EXTERNALSYM X509_PURPOSE_get_count}
  X509_PURPOSE_get_count: function : TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_PURPOSE_get0}
  X509_PURPOSE_get0: function (idx: TIdC_INT): PX509_PURPOSE; cdecl = nil;
  {$EXTERNALSYM X509_PURPOSE_get_by_sname}
  X509_PURPOSE_get_by_sname: function (const sname: PIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_PURPOSE_get_by_id}
  X509_PURPOSE_get_by_id: function (id: TIdC_INT): TIdC_INT; cdecl = nil;
//  TIdC_INT X509_PURPOSE_add(id: TIdC_INT, TIdC_INT trust, flags: TIdC_INT, TIdC_INT (*ck) (const X509_PURPOSE *, const X509 *, TIdC_INT), const name: PIdAnsiChar, const sname: PIdAnsiChar, void *arg);
  {$EXTERNALSYM X509_PURPOSE_get0_name}
  X509_PURPOSE_get0_name: function (const xp: PX509_PURPOSE): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_PURPOSE_get0_sname}
  X509_PURPOSE_get0_sname: function (const xp: PX509_PURPOSE): PIdAnsiChar; cdecl = nil;
  {$EXTERNALSYM X509_PURPOSE_get_trust}
  X509_PURPOSE_get_trust: function (const xp: PX509_PURPOSE): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_PURPOSE_cleanup}
  X509_PURPOSE_cleanup: procedure ; cdecl = nil;
  {$EXTERNALSYM X509_PURPOSE_get_id}
  X509_PURPOSE_get_id: function (const v1: PX509_PURPOSE): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM X509_get1_email}
  X509_get1_email : function (x: PX509) : PSTACK_OF_OPENSSL_STRING;  cdecl = nil;
  {$EXTERNALSYM X509_REQ_get1_email}
  X509_REQ_get1_email : function( x : PX509_REQ) : PSTACK_OF_OPENSSL_STRING;  cdecl = nil;
  {$EXTERNALSYM X509_email_free}
  X509_email_free : procedure(sk : PSTACK_OF_OPENSSL_STRING); cdecl = nil;
  {$EXTERNALSYM X509_get1_ocsp}
  X509_get1_ocsp : function(x: PX509) : PSTACK_OF_OPENSSL_STRING; cdecl = nil;

  {$EXTERNALSYM X509_check_host}
  X509_check_host: function (x: PX509; const chk: PIdAnsiChar; chklen: TIdC_SIZET; flags: TIdC_UINT; peername: PPIdAnsiChar): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_check_email}
  X509_check_email: function (x: PX509; const chk: PIdAnsiChar; chklen: TIdC_SIZET; flags: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_check_ip}
  X509_check_ip: function (x: PX509; const chk: PByte; chklen: TIdC_SIZET; flags: TIdC_UINT): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509_check_ip_asc}
  X509_check_ip_asc: function (x: PX509; const ipasc: PIdAnsiChar; flags: TIdC_UINT): TIdC_INT; cdecl = nil;

  {$EXTERNALSYM a2i_IPADDRESS}
  a2i_IPADDRESS: function (const ipasc: PIdAnsiChar): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM a2i_IPADDRESS_NC}
  a2i_IPADDRESS_NC: function (const ipasc: PIdAnsiChar): PASN1_OCTET_STRING; cdecl = nil;
//  TIdC_INT X509V3_NAME_from_section(X509_NAME *nm; STACK_OF(CONF_VALUE) *dn_sk; TIdC_ULONG chtype);

  {$EXTERNALSYM X509_POLICY_NODE_print}
  X509_POLICY_NODE_print: procedure (out_: PBIO; node: PX509_POLICY_NODE; indent: TIdC_INT); cdecl = nil;
//  DEFINE_STACK_OF(X509_POLICY_NODE)

  (*
   * Utilities to construct and extract values from RFC3779 extensions,
   * since some of the encodings (particularly for IP address prefixes
   * and ranges) are a bit tedious to work with directly.
   *)
  //function X509v3_asid_add_inherit(asid: PASIdentifiers; which: TIdC_INT): TIdC_INT;
  //function X509v3_asid_add_id_or_range(asid: PASIdentifiers; which: TIdC_INT; min: PASN1_INTEGER; max: PASN1_INTEGER): TIdC_INT;
  //function X509v3_addr_add_inherit(address: PIPAddrBlocks; const afi: TIdC_UINT; const safi: PIdC_UINT): TIdC_INT;
  //function X509v3_addr_add_prefix(address: PIPAddrBlocks; const afi: TIdC_UINT; const safi: PIdC_UINT; a: PByte; const prefixlen: TIdC_INT): TIdC_INT;
  //function X509v3_addr_add_range(address: PIPAddrBlocks; const afi: TIdC_UINT; const safi: PIdC_UINT; min: PByte; max: PByte): TIdC_INT;
  //function X509v3_addr_get_afi(const f: PIPAddressFamily): TIdC_UINT;
  {$EXTERNALSYM X509v3_addr_get_range}
  X509v3_addr_get_range: function (aor: PIPAddressOrRange; const afi: TIdC_UINT; min: PByte; max: Byte; const _length: TIdC_INT): TIdC_INT; cdecl = nil;

  (*
   * Canonical forms.
   *)
  //function X509v3_asid_is_canonical(asid: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_is_canonical(address: PIPAddrBlocks): TIdC_INT;
  //function X509v3_asid_canonize(asid: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_canonize(address: PIPAddrBlocks): TIdC_INT;

  (*
   * Tests for inheritance and containment.
   *)
  //function X509v3_asid_inherits(asid: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_inherits(address: PIPAddrBlocks): TIdC_INT;
  //function X509v3_asid_subset(a: PASIdentifiers; b: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_subset(a: PIPAddrBlocks; b: PIPAddrBlocks): TIdC_INT;

  (*
   * Check whether RFC 3779 extensions nest properly in chains.
   *)
  {$EXTERNALSYM X509v3_asid_validate_path}
  X509v3_asid_validate_path: function (v1: PX509_STORE_CTX): TIdC_INT; cdecl = nil;
  {$EXTERNALSYM X509v3_addr_validate_path}
  X509v3_addr_validate_path: function (v1: PX509_STORE_CTX): TIdC_INT; cdecl = nil;
//  TIdC_INT X509v3_asid_validate_resource_set(STACK_OF(X509) *chain; ASIdentifiers *ext; TIdC_INT allow_inheritance);
//  TIdC_INT X509v3_addr_validate_resource_set(STACK_OF(X509) *chain; IPAddrBlocks *ext; TIdC_INT allow_inheritance);


//  DEFINE_STACK_OF(ASN1_STRING)

  (*
   * Admission Syntax
   *)
  {$EXTERNALSYM NAMING_AUTHORITY_get0_authorityId}
  NAMING_AUTHORITY_get0_authorityId: function (const n: PNAMING_AUTHORITY): PASN1_OBJECT; cdecl = nil;
  {$EXTERNALSYM NAMING_AUTHORITY_get0_authorityURL}
  NAMING_AUTHORITY_get0_authorityURL: function (const n: PNAMING_AUTHORITY): PASN1_IA5STRING; cdecl = nil;
  {$EXTERNALSYM NAMING_AUTHORITY_get0_authorityText}
  NAMING_AUTHORITY_get0_authorityText: function (const n: PNAMING_AUTHORITY): PASN1_STRING; cdecl = nil;
  {$EXTERNALSYM NAMING_AUTHORITY_set0_authorityId}
  NAMING_AUTHORITY_set0_authorityId: procedure (n: PNAMING_AUTHORITY; namingAuthorityId: PASN1_OBJECT); cdecl = nil;
  {$EXTERNALSYM NAMING_AUTHORITY_set0_authorityURL}
  NAMING_AUTHORITY_set0_authorityURL: procedure (n: PNAMING_AUTHORITY; namingAuthorityUrl: PASN1_IA5STRING); cdecl = nil;
  {$EXTERNALSYM NAMING_AUTHORITY_set0_authorityText}
  NAMING_AUTHORITY_set0_authorityText: procedure (n: PNAMING_AUTHORITY; namingAuthorityText: PASN1_STRING); cdecl = nil;

  {$EXTERNALSYM ADMISSION_SYNTAX_get0_admissionAuthority}
  ADMISSION_SYNTAX_get0_admissionAuthority: function (const as_: ADMISSION_SYNTAX): PGENERAL_NAME; cdecl = nil;
  {$EXTERNALSYM ADMISSION_SYNTAX_set0_admissionAuthority}
  ADMISSION_SYNTAX_set0_admissionAuthority: procedure (as_: ADMISSION_SYNTAX; aa: PGENERAL_NAME); cdecl = nil;
//  const STACK_OF(ADMISSIONS) *ADMISSION_SYNTAX_get0_contentsOfAdmissions(const as_: ADMISSION_SYNTAX);
//  void ADMISSION_SYNTAX_set0_contentsOfAdmissions(as_: ADMISSION_SYNTAX; STACK_OF(ADMISSIONS) *a);
  {$EXTERNALSYM ADMISSIONS_get0_admissionAuthority}
  ADMISSIONS_get0_admissionAuthority: function (const a: PADMISSIONS): PGENERAL_NAME; cdecl = nil;
  {$EXTERNALSYM ADMISSIONS_set0_admissionAuthority}
  ADMISSIONS_set0_admissionAuthority: procedure (a: PADMISSIONS; aa: PGENERAL_NAME); cdecl = nil;
  {$EXTERNALSYM ADMISSIONS_get0_namingAuthority}
  ADMISSIONS_get0_namingAuthority: function (const a: PADMISSIONS): PNAMING_AUTHORITY; cdecl = nil;
  {$EXTERNALSYM ADMISSIONS_set0_namingAuthority}
  ADMISSIONS_set0_namingAuthority: procedure (a: PADMISSIONS; na: PNAMING_AUTHORITY); cdecl = nil;
  //function ADMISSIONS_get0_professionInfos(const a: PADMISSIONS): PPROFESSION_INFOS;
  //procedure ADMISSIONS_set0_professionInfos(a: PADMISSIONS; _pi: PPROFESSION_INFOS);
  {$EXTERNALSYM PROFESSION_INFO_get0_addProfessionInfo}
  PROFESSION_INFO_get0_addProfessionInfo: function (const _pi: PPROFESSION_INFO): PASN1_OCTET_STRING; cdecl = nil;
  {$EXTERNALSYM PROFESSION_INFO_set0_addProfessionInfo}
  PROFESSION_INFO_set0_addProfessionInfo: procedure (_pi: PPROFESSION_INFO; aos: PASN1_OCTET_STRING); cdecl = nil;
  {$EXTERNALSYM PROFESSION_INFO_get0_namingAuthority}
  PROFESSION_INFO_get0_namingAuthority: function (const _pi: PPROFESSION_INFO): PNAMING_AUTHORITY; cdecl = nil;
  {$EXTERNALSYM PROFESSION_INFO_set0_namingAuthority}
  PROFESSION_INFO_set0_namingAuthority: procedure (_pi: PPROFESSION_INFO; na: PNAMING_AUTHORITY); cdecl = nil;
//  const STACK_OF(ASN1_STRING) *PROFESSION_INFO_get0_professionItems(const _pi: PPROFESSION_INFO);
//  void PROFESSION_INFO_set0_professionItems(_pi: PPROFESSION_INFO; STACK_OF(ASN1_STRING) *as);
//  const STACK_OF(ASN1_OBJECT) *PROFESSION_INFO_get0_professionOIDs(const _pi: PPROFESSION_INFO);
//  void PROFESSION_INFO_set0_professionOIDs(_pi: PPROFESSION_INFO; STACK_OF(ASN1_OBJECT) *po);
  {$EXTERNALSYM PROFESSION_INFO_get0_registrationNumber}
  PROFESSION_INFO_get0_registrationNumber: function (const _pi: PPROFESSION_INFO): PASN1_PRINTABLESTRING; cdecl = nil;
  {$EXTERNALSYM PROFESSION_INFO_set0_registrationNumber}
  PROFESSION_INFO_set0_registrationNumber: procedure (_pi: PPROFESSION_INFO; rn: PASN1_PRINTABLESTRING); cdecl = nil;


{$ELSE}
  {$EXTERNALSYM GENERAL_NAME_cmp}
  function GENERAL_NAME_cmp(a: PGENERAL_NAME; b: PGENERAL_NAME): TIdC_INT cdecl; external CLibCrypto;

//  ASN1_BIT_STRING *v2i_ASN1_BIT_STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; STACK_OF(CONF_VALUE) *nval);
//  STACK_OF(CONF_VALUE) *i2v_ASN1_BIT_STRING(method: PX509V3_EXT_METHOD; ASN1_BIT_STRING *bits; STACK_OF(CONF_VALUE) *extlist);
  //function i2s_ASN1_IA5STRING(method: PX509V3_EXT_METHOD; ia5: PASN1_IA5STRING): PIdAnsiChar;
  //function s2i_ASN1_IA5STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; const _str: PIdAnsiChar): PASN1_IA5STRING;

//  STACK_OF(CONF_VALUE) *i2v_GENERAL_NAME(method: PX509V3_EXT_METHOD; gen: PGENERAL_NAME; STACK_OF(CONF_VALUE) *ret);
  {$EXTERNALSYM GENERAL_NAME_print}
  function GENERAL_NAME_print(out_: PBIO; gen: PGENERAL_NAME): TIdC_INT cdecl; external CLibCrypto;

//  DECLARE_ASN1_FUNCTIONS(GENERAL_NAMES)

//  STACK_OF(CONF_VALUE) *i2v_GENERAL_NAMES(method: PX509V3_EXT_METHOD, GENERAL_NAMES *gen, STACK_OF(CONF_VALUE) *extlist);
//  GENERAL_NAMES *v2i_GENERAL_NAMES(const method: PX509V3_EXT_METHOD, ctx: PX509V3_CTX, STACK_OF(CONF_VALUE) *nval);

//  DECLARE_ASN1_FUNCTIONS(OTHERNAME)
//  DECLARE_ASN1_FUNCTIONS(EDIPARTYNAME)
  {$EXTERNALSYM OTHERNAME_cmp}
  function OTHERNAME_cmp(a: POTHERNAME; b: POTHERNAME): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM GENERAL_NAME_set0_value}
  procedure GENERAL_NAME_set0_value(a: PGENERAL_NAME; type_: TIdC_INT; value: Pointer) cdecl; external CLibCrypto;
  {$EXTERNALSYM GENERAL_NAME_get0_value}
  function GENERAL_NAME_get0_value(const a: PGENERAL_NAME; ptype: PIdC_INT): Pointer cdecl; external CLibCrypto;
  {$EXTERNALSYM GENERAL_NAME_set0_othername}
  function GENERAL_NAME_set0_othername(gen: PGENERAL_NAME; oid: PASN1_OBJECT; value: PASN1_TYPE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM GENERAL_NAME_get0_otherName}
  function GENERAL_NAME_get0_otherName(const gen: PGENERAL_NAME; poid: PPASN1_OBJECT; pvalue: PPASN1_TYPE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM GENERAL_NAMES_free}
  procedure GENERAL_NAMES_free(a : PGENERAL_NAMES); cdecl;  external CLibCrypto;

  //function i2s_ASN1_OCTET_STRING(method: PX509V3_EXT_METHOD; const ia5: PASN1_OCTET_STRING): PIdAnsiChar;
  //function s2i_ASN1_OCTET_STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; const _str: PIdAnsiChar): PASN1_OCTET_STRING;

//  DECLARE_ASN1_FUNCTIONS(EXTENDED_KEY_USAGE)
  {$EXTERNALSYM i2a_ACCESS_DESCRIPTION}
  function i2a_ACCESS_DESCRIPTION(bp: PBIO; const a: PACCESS_DESCRIPTION): TIdC_INT cdecl; external CLibCrypto;

//  DECLARE_ASN1_ALLOC_FUNCTIONS(TLS_FEATURE)

//  DECLARE_ASN1_FUNCTIONS(CERTIFICATEPOLICIES)
//  DECLARE_ASN1_FUNCTIONS(POLICYINFO)
//  DECLARE_ASN1_FUNCTIONS(POLICYQUALINFO)
//  DECLARE_ASN1_FUNCTIONS(USERNOTICE)
//  DECLARE_ASN1_FUNCTIONS(NOTICEREF)

//  DECLARE_ASN1_FUNCTIONS(CRL_DIST_POINTS)
//  DECLARE_ASN1_FUNCTIONS(DIST_POINT)
//  DECLARE_ASN1_FUNCTIONS(DIST_POINT_NAME)
//  DECLARE_ASN1_FUNCTIONS(ISSUING_DIST_POINT)

  {$EXTERNALSYM DIST_POINT_set_dpname}
  function DIST_POINT_set_dpname(dpn: PDIST_POINT_NAME; iname: PX509_NAME): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM NAME_CONSTRAINTS_check}
  function NAME_CONSTRAINTS_check(x: PX509; nc: PNAME_CONSTRAINTS): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM NAME_CONSTRAINTS_check_CN}
  function NAME_CONSTRAINTS_check_CN(x: PX509; nc: PNAME_CONSTRAINTS): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM BASIC_CONSTRAINTS_free}
  procedure  BASIC_CONSTRAINTS_free(bc : PBASIC_CONSTRAINTS); cdecl;  external CLibCrypto;
  {$EXTERNALSYM AUTHORITY_KEYID_free}
  procedure AUTHORITY_KEYID_free(id : AUTHORITY_KEYID); cdecl; external CLibCrypto;
//  DECLARE_ASN1_FUNCTIONS(ACCESS_DESCRIPTION)
//  DECLARE_ASN1_FUNCTIONS(AUTHORITY_INFO_ACCESS)

//  DECLARE_ASN1_ITEM(POLICY_MAPPING)
//  DECLARE_ASN1_ALLOC_FUNCTIONS(POLICY_MAPPING)
//  DECLARE_ASN1_ITEM(POLICY_MAPPINGS)

//  DECLARE_ASN1_ITEM(GENERAL_SUBTREE)
//  DECLARE_ASN1_ALLOC_FUNCTIONS(GENERAL_SUBTREE)

//  DECLARE_ASN1_ITEM(NAME_CONSTRAINTS)
//  DECLARE_ASN1_ALLOC_FUNCTIONS(NAME_CONSTRAINTS)

//  DECLARE_ASN1_ALLOC_FUNCTIONS(POLICY_CONSTRAINTS)
//  DECLARE_ASN1_ITEM(POLICY_CONSTRAINTS)

  //function a2i_GENERAL_NAME(out_: PGENERAL_NAME; const method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; TIdC_INT gen_type; const value: PIdAnsiChar; is_nc: TIdC_INT): GENERAL_NAME;

  //function v2i_GENERAL_NAME(const method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; cnf: PCONF_VALUE): PGENERAL_NAME;
  //function v2i_GENERAL_NAME_ex(out_: PGENERAL_NAME; const method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; cnf: PCONF_VALUE; is_nc: TIdC_INT): PGENERAL_NAME;
  //procedure X509V3_conf_free(_val: PCONF_VALUE);

  {$EXTERNALSYM X509V3_EXT_nconf_nid}
  function X509V3_EXT_nconf_nid(conf: PCONF; ctx: PX509V3_CTX; ext_nid: TIdC_INT; const value: PIdAnsiChar): PX509_EXTENSION cdecl; external CLibCrypto;
  {$EXTERNALSYM X509V3_EXT_nconf}
  function X509V3_EXT_nconf(conf: PCONF; ctx: PX509V3_CTX; const name: PIdAnsiChar; const value: PIdAnsiChar): PX509_EXTENSION cdecl; external CLibCrypto;
//  TIdC_INT X509V3_EXT_add_nconf_sk(conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; STACK_OF(X509_EXTENSION) **sk);
  {$EXTERNALSYM X509V3_EXT_add_nconf}
  function X509V3_EXT_add_nconf(conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; cert: PX509): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509V3_EXT_REQ_add_nconf}
  function X509V3_EXT_REQ_add_nconf(conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; req: PX509_REQ): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509V3_EXT_CRL_add_nconf}
  function X509V3_EXT_CRL_add_nconf(conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; crl: PX509_CRL): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509V3_EXT_conf_nid}
  function X509V3_EXT_conf_nid(conf: Pointer; ctx: PX509V3_CTX; ext_nid: TIdC_INT; const value: PIdAnsiChar): PX509_EXTENSION cdecl; external CLibCrypto;
//  X509_EXTENSION *X509V3_EXT_conf_nid(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; ext_nid: TIdC_INT; const value: PIdAnsiChar);
  {$EXTERNALSYM X509V3_EXT_conf}
  function X509V3_EXT_conf(conf: Pointer; ctx: PX509V3_CTX; const name: PIdAnsiChar; const value: PIdAnsiChar): PX509_EXTENSION cdecl; external CLibCrypto;
//  X509_EXTENSION *X509V3_EXT_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const name: PIdAnsiChar; const value: PIdAnsiChar);
  {$EXTERNALSYM X509V3_EXT_add_conf}
  function X509V3_EXT_add_conf(conf: Pointer; ctx: PX509V3_CTX; const section: PIdAnsiChar; cert: PX509): TIdC_INT cdecl; external CLibCrypto;
//  TIdC_INT X509V3_EXT_add_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const section: PIdAnsiChar; cert: PX509);
  {$EXTERNALSYM X509V3_EXT_REQ_add_conf}
  function X509V3_EXT_REQ_add_conf(conf: Pointer; ctx: PX509V3_CTX; const section: PIdAnsiChar; req: PX509_REQ): TIdC_INT cdecl; external CLibCrypto;
//  TIdC_INT X509V3_EXT_REQ_add_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const section: PIdAnsiChar; req: PX509_REQ);
  {$EXTERNALSYM X509V3_EXT_CRL_add_conf}
  function X509V3_EXT_CRL_add_conf(conf: Pointer; ctx: PX509V3_CTX; const section: PIdAnsiChar; crl: PX509_CRL): TIdC_INT cdecl; external CLibCrypto;
//  TIdC_INT X509V3_EXT_CRL_add_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const section: PIdAnsiChar; crl: PX509_CRL);

//  TIdC_INT X509V3_add_value_bool_nf(const name: PIdAnsiChar; TIdC_INT asn1_bool; STACK_OF(CONF_VALUE) **extlist);
  //function X509V3_get_value_bool(const value: PCONF_VALUE; asn1_bool: PIdC_INT): TIdC_INT;
  //function X509V3_get_value_int(const value: PCONF_VALUE; aint: PPASN1_INTEGER): TIdC_INT;
  {$EXTERNALSYM X509V3_set_nconf}
  procedure X509V3_set_nconf(ctx: PX509V3_CTX; conf: PCONF) cdecl; external CLibCrypto;
//  void X509V3_set_conf_lhash(ctx: PX509V3_CTX; LHASH_OF(CONF_VALUE) *lhash);

  {$EXTERNALSYM X509V3_get_string}
  function X509V3_get_string(ctx: PX509V3_CTX; const name: PIdAnsiChar; const section: PIdAnsiChar): PIdAnsiChar cdecl; external CLibCrypto;
//  STACK_OF(CONF_VALUE) *X509V3_get_section(ctx: PX509V3_CTX; const section: PIdAnsiChar);
  {$EXTERNALSYM X509V3_string_free}
  procedure X509V3_string_free(ctx: PX509V3_CTX; _str: PIdAnsiChar) cdecl; external CLibCrypto;
//  void X509V3_section_free(ctx: PX509V3_CTX; STACK_OF(CONF_VALUE) *section);
  {$EXTERNALSYM X509V3_set_ctx}
  procedure X509V3_set_ctx(ctx: PX509V3_CTX; issuer: PX509; subject: PX509; req: PX509_REQ; crl: PX509_CRL; flags: TIdC_INT) cdecl; external CLibCrypto;

//  TIdC_INT X509V3_add_value(const name: PIdAnsiChar; const value: PIdAnsiChar; STACK_OF(CONF_VALUE) **extlist);
//  TIdC_INT X509V3_add_value_uPIdAnsiChar(const name: PIdAnsiChar; const Byte *value; STACK_OF(CONF_VALUE) **extlist);
//  TIdC_INT X509V3_add_value_bool(const name: PIdAnsiChar; TIdC_INT asn1_bool; STACK_OF(CONF_VALUE) **extlist);
//  TIdC_INT X509V3_add_value_int(const name: PIdAnsiChar; const aint: PASN1_INTEGER; STACK_OF(CONF_VALUE) **extlist);
  //function i2s_ASN1_INTEGER(meth: PX509V3_EXT_METHOD; const aint: PASN1_INTEGER): PIdAnsiChar;
  //function s2i_ASN1_INTEGER(meth: PX509V3_EXT_METHOD; const value: PIdAnsiChar): PASN1_INTEGER;
  //function i2s_ASN1_ENUMERATED(meth: PX509V3_EXT_METHOD; const aint: PASN1_ENUMERATED): PIdAnsiChar;
  //function i2s_ASN1_ENUMERATED_TABLE(meth: PX509V3_EXT_METHOD; const aint: PASN1_ENUMERATED): PIdAnsiChar;
  //function X509V3_EXT_add(ext: PX509V3_EXT_METHOD): TIdC_INT;
  //function X509V3_EXT_add_list(extlist: PX509V3_EXT_METHOD): TIdC_INT;
  {$EXTERNALSYM X509V3_EXT_add_alias}
  function X509V3_EXT_add_alias(nid_to: TIdC_INT; nid_from: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509V3_EXT_cleanup}
  procedure X509V3_EXT_cleanup cdecl; external CLibCrypto;

  //function X509V3_EXT_get(ext: PX509_EXTENSION): PX509V3_EXT_METHOD;
  //function X509V3_EXT_get_nid(nid: TIdC_INT): PX509V3_EXT_METHOD;
  {$EXTERNALSYM X509V3_add_standard_extensions}
  function X509V3_add_standard_extensions: TIdC_INT cdecl; external CLibCrypto;
//  STACK_OF(CONF_VALUE) *X509V3_parse_list(const line: PIdAnsiChar);
  {$EXTERNALSYM X509V3_EXT_d2i}
  function X509V3_EXT_d2i(ext: PX509_EXTENSION): Pointer cdecl; external CLibCrypto;
//  void *X509V3_get_d2i(const STACK_OF(X509_EXTENSION) *x; nid: TIdC_INT; TIdC_INT *crit; TIdC_INT *idx);

  {$EXTERNALSYM X509V3_EXT_i2d}
  function X509V3_EXT_i2d(ext_nid: TIdC_INT; crit: TIdC_INT; ext_struc: Pointer): PX509_EXTENSION cdecl; external CLibCrypto;
//  TIdC_INT X509V3_add1_i2d(STACK_OF(X509_EXTENSION) **x; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; TIdC_ULONG flags);

//  void X509V3_EXT_val_prn(out_: PBIO; STACK_OF(CONF_VALUE) *val; indent: TIdC_INT; TIdC_INT ml);
  {$EXTERNALSYM X509V3_EXT_print}
  function X509V3_EXT_print(out_: PBIO; ext: PX509_EXTENSION; flag: TIdC_ULONG; indent: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
//  TIdC_INT X509V3_extensions_print(out_: PBIO; const PIdAnsiChar *title; const STACK_OF(X509_EXTENSION) *exts; flag: TIdC_ULONG; indent: TIdC_INT);

  {$EXTERNALSYM X509_check_ca}
  function X509_check_ca(x: PX509): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_check_purpose}
  function X509_check_purpose(x: PX509; id: TIdC_INT; ca: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_supported_extension}
  function X509_supported_extension(ex: PX509_EXTENSION): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_PURPOSE_set}
  function X509_PURPOSE_set(p: PIdC_INT; purpose: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_check_issued}
  function X509_check_issued(issuer: PX509; subject: PX509): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_check_akid}
  function X509_check_akid(issuer: PX509; akid: PAUTHORITY_KEYID): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_set_proxy_flag}
  procedure X509_set_proxy_flag(x: PX509) cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_set_proxy_pathlen}
  procedure X509_set_proxy_pathlen(x: PX509; l: TIdC_LONG) cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_get_proxy_pathlen}
  function X509_get_proxy_pathlen(x: PX509): TIdC_LONG cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_get_extension_flags}
  function X509_get_extension_flags(x: PX509): TIdC_UINT32 cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_get_key_usage}
  function X509_get_key_usage(x: PX509): TIdC_UINT32 cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_get_extended_key_usage}
  function X509_get_extended_key_usage(x: PX509): TIdC_UINT32 cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_get0_subject_key_id}
  function X509_get0_subject_key_id(x: PX509): PASN1_OCTET_STRING cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_get0_authority_key_id}
  function X509_get0_authority_key_id(x: PX509): PASN1_OCTET_STRING cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_get0_authority_issuer}
  function X509_get0_authority_issuer(x: PX509): PGENERAL_NAMES;  cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_get0_authority_serial}
  function X509_get0_authority_serial(x: PX509): PASN1_INTEGER cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_PURPOSE_get_count}
  function X509_PURPOSE_get_count: TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_PURPOSE_get0}
  function X509_PURPOSE_get0(idx: TIdC_INT): PX509_PURPOSE cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_PURPOSE_get_by_sname}
  function X509_PURPOSE_get_by_sname(const sname: PIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_PURPOSE_get_by_id}
  function X509_PURPOSE_get_by_id(id: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;
//  TIdC_INT X509_PURPOSE_add(id: TIdC_INT, TIdC_INT trust, flags: TIdC_INT, TIdC_INT (*ck) (const X509_PURPOSE *, const X509 *, TIdC_INT), const name: PIdAnsiChar, const sname: PIdAnsiChar, void *arg);
  {$EXTERNALSYM X509_PURPOSE_get0_name}
  function X509_PURPOSE_get0_name(const xp: PX509_PURPOSE): PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_PURPOSE_get0_sname}
  function X509_PURPOSE_get0_sname(const xp: PX509_PURPOSE): PIdAnsiChar cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_PURPOSE_get_trust}
  function X509_PURPOSE_get_trust(const xp: PX509_PURPOSE): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_PURPOSE_cleanup}
  procedure X509_PURPOSE_cleanup cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_PURPOSE_get_id}
  function X509_PURPOSE_get_id(const v1: PX509_PURPOSE): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_get1_email}
  function X509_get1_email(x: PX509) : PSTACK_OF_OPENSSL_STRING; cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_REQ_get1_email}
  function X509_REQ_get1_email( x : PX509_REQ) : PSTACK_OF_OPENSSL_STRING;  cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_email_free}
  procedure X509_email_free(sk : PSTACK_OF_OPENSSL_STRING);  cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_get1_ocsp}
  function X509_get1_ocsp(x: PX509) : PSTACK_OF_OPENSSL_STRING;  cdecl; external CLibCrypto;

  {$EXTERNALSYM X509_check_host}
  function X509_check_host(x: PX509; const chk: PIdAnsiChar; chklen: TIdC_SIZET; flags: TIdC_UINT; peername: PPIdAnsiChar): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_check_email}
  function X509_check_email(x: PX509; const chk: PIdAnsiChar; chklen: TIdC_SIZET; flags: TIdC_UINT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_check_ip}
  function X509_check_ip(x: PX509; const chk: PByte; chklen: TIdC_SIZET; flags: TIdC_UINT): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509_check_ip_asc}
  function X509_check_ip_asc(x: PX509; const ipasc: PIdAnsiChar; flags: TIdC_UINT): TIdC_INT cdecl; external CLibCrypto;

  {$EXTERNALSYM a2i_IPADDRESS}
  function a2i_IPADDRESS(const ipasc: PIdAnsiChar): PASN1_OCTET_STRING cdecl; external CLibCrypto;
  {$EXTERNALSYM a2i_IPADDRESS_NC}
  function a2i_IPADDRESS_NC(const ipasc: PIdAnsiChar): PASN1_OCTET_STRING cdecl; external CLibCrypto;
//  TIdC_INT X509V3_NAME_from_section(X509_NAME *nm; STACK_OF(CONF_VALUE) *dn_sk; TIdC_ULONG chtype);

  {$EXTERNALSYM X509_POLICY_NODE_print}
  procedure X509_POLICY_NODE_print(out_: PBIO; node: PX509_POLICY_NODE; indent: TIdC_INT) cdecl; external CLibCrypto;
//  DEFINE_STACK_OF(X509_POLICY_NODE)

  (*
   * Utilities to construct and extract values from RFC3779 extensions,
   * since some of the encodings (particularly for IP address prefixes
   * and ranges) are a bit tedious to work with directly.
   *)
  //function X509v3_asid_add_inherit(asid: PASIdentifiers; which: TIdC_INT): TIdC_INT;
  //function X509v3_asid_add_id_or_range(asid: PASIdentifiers; which: TIdC_INT; min: PASN1_INTEGER; max: PASN1_INTEGER): TIdC_INT;
  //function X509v3_addr_add_inherit(address: PIPAddrBlocks; const afi: TIdC_UINT; const safi: PIdC_UINT): TIdC_INT;
  //function X509v3_addr_add_prefix(address: PIPAddrBlocks; const afi: TIdC_UINT; const safi: PIdC_UINT; a: PByte; const prefixlen: TIdC_INT): TIdC_INT;
  //function X509v3_addr_add_range(address: PIPAddrBlocks; const afi: TIdC_UINT; const safi: PIdC_UINT; min: PByte; max: PByte): TIdC_INT;
  //function X509v3_addr_get_afi(const f: PIPAddressFamily): TIdC_UINT;
  {$EXTERNALSYM X509v3_addr_get_range}
  function X509v3_addr_get_range(aor: PIPAddressOrRange; const afi: TIdC_UINT; min: PByte; max: Byte; const _length: TIdC_INT): TIdC_INT cdecl; external CLibCrypto;

  (*
   * Canonical forms.
   *)
  //function X509v3_asid_is_canonical(asid: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_is_canonical(address: PIPAddrBlocks): TIdC_INT;
  //function X509v3_asid_canonize(asid: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_canonize(address: PIPAddrBlocks): TIdC_INT;

  (*
   * Tests for inheritance and containment.
   *)
  //function X509v3_asid_inherits(asid: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_inherits(address: PIPAddrBlocks): TIdC_INT;
  //function X509v3_asid_subset(a: PASIdentifiers; b: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_subset(a: PIPAddrBlocks; b: PIPAddrBlocks): TIdC_INT;

  (*
   * Check whether RFC 3779 extensions nest properly in chains.
   *)
  {$EXTERNALSYM X509v3_asid_validate_path}
  function X509v3_asid_validate_path(v1: PX509_STORE_CTX): TIdC_INT cdecl; external CLibCrypto;
  {$EXTERNALSYM X509v3_addr_validate_path}
  function X509v3_addr_validate_path(v1: PX509_STORE_CTX): TIdC_INT cdecl; external CLibCrypto;
//  TIdC_INT X509v3_asid_validate_resource_set(STACK_OF(X509) *chain; ASIdentifiers *ext; TIdC_INT allow_inheritance);
//  TIdC_INT X509v3_addr_validate_resource_set(STACK_OF(X509) *chain; IPAddrBlocks *ext; TIdC_INT allow_inheritance);


//  DEFINE_STACK_OF(ASN1_STRING)

  (*
   * Admission Syntax
   *)
  {$EXTERNALSYM NAMING_AUTHORITY_get0_authorityId}
  function NAMING_AUTHORITY_get0_authorityId(const n: PNAMING_AUTHORITY): PASN1_OBJECT cdecl; external CLibCrypto;
  {$EXTERNALSYM NAMING_AUTHORITY_get0_authorityURL}
  function NAMING_AUTHORITY_get0_authorityURL(const n: PNAMING_AUTHORITY): PASN1_IA5STRING cdecl; external CLibCrypto;
  {$EXTERNALSYM NAMING_AUTHORITY_get0_authorityText}
  function NAMING_AUTHORITY_get0_authorityText(const n: PNAMING_AUTHORITY): PASN1_STRING cdecl; external CLibCrypto;
  {$EXTERNALSYM NAMING_AUTHORITY_set0_authorityId}
  procedure NAMING_AUTHORITY_set0_authorityId(n: PNAMING_AUTHORITY; namingAuthorityId: PASN1_OBJECT) cdecl; external CLibCrypto;
  {$EXTERNALSYM NAMING_AUTHORITY_set0_authorityURL}
  procedure NAMING_AUTHORITY_set0_authorityURL(n: PNAMING_AUTHORITY; namingAuthorityUrl: PASN1_IA5STRING) cdecl; external CLibCrypto;
  {$EXTERNALSYM NAMING_AUTHORITY_set0_authorityText}
  procedure NAMING_AUTHORITY_set0_authorityText(n: PNAMING_AUTHORITY; namingAuthorityText: PASN1_STRING) cdecl; external CLibCrypto;

  {$EXTERNALSYM ADMISSION_SYNTAX_get0_admissionAuthority}
  function ADMISSION_SYNTAX_get0_admissionAuthority(const as_: ADMISSION_SYNTAX): PGENERAL_NAME cdecl; external CLibCrypto;
  {$EXTERNALSYM ADMISSION_SYNTAX_set0_admissionAuthority}
  procedure ADMISSION_SYNTAX_set0_admissionAuthority(as_: ADMISSION_SYNTAX; aa: PGENERAL_NAME) cdecl; external CLibCrypto;
//  const STACK_OF(ADMISSIONS) *ADMISSION_SYNTAX_get0_contentsOfAdmissions(const as_: ADMISSION_SYNTAX);
//  void ADMISSION_SYNTAX_set0_contentsOfAdmissions(as_: ADMISSION_SYNTAX; STACK_OF(ADMISSIONS) *a);
  {$EXTERNALSYM ADMISSIONS_get0_admissionAuthority}
  function ADMISSIONS_get0_admissionAuthority(const a: PADMISSIONS): PGENERAL_NAME cdecl; external CLibCrypto;
  {$EXTERNALSYM ADMISSIONS_set0_admissionAuthority}
  procedure ADMISSIONS_set0_admissionAuthority(a: PADMISSIONS; aa: PGENERAL_NAME) cdecl; external CLibCrypto;
  {$EXTERNALSYM ADMISSIONS_get0_namingAuthority}
  function ADMISSIONS_get0_namingAuthority(const a: PADMISSIONS): PNAMING_AUTHORITY cdecl; external CLibCrypto;
  {$EXTERNALSYM ADMISSIONS_set0_namingAuthority}
  procedure ADMISSIONS_set0_namingAuthority(a: PADMISSIONS; na: PNAMING_AUTHORITY) cdecl; external CLibCrypto;
  //function ADMISSIONS_get0_professionInfos(const a: PADMISSIONS): PPROFESSION_INFOS;
  //procedure ADMISSIONS_set0_professionInfos(a: PADMISSIONS; _pi: PPROFESSION_INFOS);
  {$EXTERNALSYM PROFESSION_INFO_get0_addProfessionInfo}
  function PROFESSION_INFO_get0_addProfessionInfo(const _pi: PPROFESSION_INFO): PASN1_OCTET_STRING cdecl; external CLibCrypto;
  {$EXTERNALSYM PROFESSION_INFO_set0_addProfessionInfo}
  procedure PROFESSION_INFO_set0_addProfessionInfo(_pi: PPROFESSION_INFO; aos: PASN1_OCTET_STRING) cdecl; external CLibCrypto;
  {$EXTERNALSYM PROFESSION_INFO_get0_namingAuthority}
  function PROFESSION_INFO_get0_namingAuthority(const _pi: PPROFESSION_INFO): PNAMING_AUTHORITY cdecl; external CLibCrypto;
  {$EXTERNALSYM PROFESSION_INFO_set0_namingAuthority}
  procedure PROFESSION_INFO_set0_namingAuthority(_pi: PPROFESSION_INFO; na: PNAMING_AUTHORITY) cdecl; external CLibCrypto;
//  const STACK_OF(ASN1_STRING) *PROFESSION_INFO_get0_professionItems(const _pi: PPROFESSION_INFO);
//  void PROFESSION_INFO_set0_professionItems(_pi: PPROFESSION_INFO; STACK_OF(ASN1_STRING) *as);
//  const STACK_OF(ASN1_OBJECT) *PROFESSION_INFO_get0_professionOIDs(const _pi: PPROFESSION_INFO);
//  void PROFESSION_INFO_set0_professionOIDs(_pi: PPROFESSION_INFO; STACK_OF(ASN1_OBJECT) *po);
  {$EXTERNALSYM PROFESSION_INFO_get0_registrationNumber}
  function PROFESSION_INFO_get0_registrationNumber(const _pi: PPROFESSION_INFO): PASN1_PRINTABLESTRING cdecl; external CLibCrypto;
  {$EXTERNALSYM PROFESSION_INFO_set0_registrationNumber}
  procedure PROFESSION_INFO_set0_registrationNumber(_pi: PPROFESSION_INFO; rn: PASN1_PRINTABLESTRING) cdecl; external CLibCrypto;


{$ENDIF}
 {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
type
  {$EXTERNALSYM Tsk_ASIdOrRange_new}
  Tsk_ASIdOrRange_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_ASIdOrRange cdecl;
  {$EXTERNALSYM Tsk_ASIdOrRange_new_null}
  Tsk_ASIdOrRange_new_null = function : PSTACK_OF_ASIdOrRange cdecl;
  {$EXTERNALSYM Tsk_ASIdOrRange_free}
  Tsk_ASIdOrRange_free = procedure(st : PSTACK_OF_ASIdOrRange) cdecl;
  {$EXTERNALSYM Tsk_ASIdOrRange_num}
  Tsk_ASIdOrRange_num = function (const sk : PSTACK_OF_ASIdOrRange) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ASIdOrRange_value}
  Tsk_ASIdOrRange_value = function (const sk : PSTACK_OF_ASIdOrRange; i : TIdC_INT) : PASIdOrRange cdecl;
  {$EXTERNALSYM Tsk_ASIdOrRange_push}
  Tsk_ASIdOrRange_push = function (sk : PSTACK_OF_ASIdOrRange; st : PASIdOrRange) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ASIdOrRange_dup}
  Tsk_ASIdOrRange_dup = function (sk : PSTACK_OF_ASIdOrRange) : PSTACK_OF_ASIdOrRange cdecl;
  {$EXTERNALSYM Tsk_ASIdOrRange_find}
  Tsk_ASIdOrRange_find = function (sk : PSTACK_OF_ASIdOrRange; _val : PASIdOrRange) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ASIdOrRange_pop_free}
  Tsk_ASIdOrRange_pop_free = procedure (sk : PSTACK_OF_ASIdOrRange; func: TOPENSSL_sk_freefunc) cdecl;
  {$EXTERNALSYM Tsk_IPAddressOrRange_new}
  Tsk_IPAddressOrRange_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_IPAddressOrRange cdecl;
  {$EXTERNALSYM Tsk_IPAddressOrRange_new_null}
  Tsk_IPAddressOrRange_new_null = function : PSTACK_OF_IPAddressOrRange cdecl;
  {$EXTERNALSYM Tsk_IPAddressOrRange_free}
  Tsk_IPAddressOrRange_free = procedure(st : PSTACK_OF_IPAddressOrRange) cdecl;
  {$EXTERNALSYM Tsk_IPAddressOrRange_num}
  Tsk_IPAddressOrRange_num = function (const sk : PSTACK_OF_IPAddressOrRange) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_IPAddressOrRange_value}
  Tsk_IPAddressOrRange_value = function (const sk : PSTACK_OF_IPAddressOrRange; i : TIdC_INT) : PIPAddressOrRange cdecl;
  {$EXTERNALSYM Tsk_IPAddressOrRange_push}
  Tsk_IPAddressOrRange_push = function (sk : PSTACK_OF_IPAddressOrRange; st : PIPAddressOrRange) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_IPAddressOrRange_dup}
  Tsk_IPAddressOrRange_dup = function (sk : PSTACK_OF_IPAddressOrRange) : PSTACK_OF_IPAddressOrRange cdecl;
  {$EXTERNALSYM Tsk_IPAddressOrRange_find}
  Tsk_IPAddressOrRange_find = function (sk : PSTACK_OF_IPAddressOrRange; _val : PIPAddressOrRange) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_IPAddressOrRange_pop_free}
  Tsk_IPAddressOrRange_pop_free = procedure (sk : PSTACK_OF_IPAddressOrRange; func: TOPENSSL_sk_freefunc) cdecl;
  {$EXTERNALSYM Tsk_IPAddressFamily_new}
  Tsk_IPAddressFamily_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_IPAddressFamily cdecl;
  {$EXTERNALSYM Tsk_IPAddressFamily_new_null}
  Tsk_IPAddressFamily_new_null = function : PSTACK_OF_IPAddressFamily cdecl;
  {$EXTERNALSYM Tsk_IPAddressFamily_free}
  Tsk_IPAddressFamily_free = procedure(st : PSTACK_OF_IPAddressFamily) cdecl;
  {$EXTERNALSYM Tsk_IPAddressFamily_num}
  Tsk_IPAddressFamily_num = function (const sk : PSTACK_OF_IPAddressFamily) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_IPAddressFamily_value}
  Tsk_IPAddressFamily_value = function (const sk : PSTACK_OF_IPAddressFamily; i : TIdC_INT) : PIPAddressFamily cdecl;
  {$EXTERNALSYM Tsk_IPAddressFamily_push}
  Tsk_IPAddressFamily_push = function (sk : PSTACK_OF_IPAddressFamily; st : PIPAddressFamily) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_IPAddressFamily_dup}
  Tsk_IPAddressFamily_dup = function (sk : PSTACK_OF_IPAddressFamily) : PSTACK_OF_IPAddressFamily cdecl;
  {$EXTERNALSYM Tsk_IPAddressFamily_find}
  Tsk_IPAddressFamily_find = function (sk : PSTACK_OF_IPAddressFamily; _val : PIPAddressFamily) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_IPAddressFamily_pop_free}
  Tsk_IPAddressFamily_pop_free = procedure (sk : PSTACK_OF_IPAddressFamily; func: TOPENSSL_sk_freefunc) cdecl;
  {$EXTERNALSYM Tsk_GENERAL_NAME_new}
  Tsk_GENERAL_NAME_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_GENERAL_NAME cdecl;
  {$EXTERNALSYM Tsk_GENERAL_NAME_new_null}
  Tsk_GENERAL_NAME_new_null = function : PSTACK_OF_GENERAL_NAME cdecl;
  {$EXTERNALSYM Tsk_GENERAL_NAME_free}
  Tsk_GENERAL_NAME_free = procedure(st : PSTACK_OF_GENERAL_NAME) cdecl;
  {$EXTERNALSYM Tsk_GENERAL_NAME_num}
  Tsk_GENERAL_NAME_num = function (const sk : PSTACK_OF_GENERAL_NAME) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_GENERAL_NAME_value}
  Tsk_GENERAL_NAME_value = function (const sk : PSTACK_OF_GENERAL_NAME; i : TIdC_INT) : PGENERAL_NAME cdecl;
  {$EXTERNALSYM Tsk_GENERAL_NAME_push}
  Tsk_GENERAL_NAME_push = function (sk : PSTACK_OF_GENERAL_NAME; st : PGENERAL_NAME) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_GENERAL_NAME_dup}
  Tsk_GENERAL_NAME_dup = function (sk : PSTACK_OF_GENERAL_NAME) : PSTACK_OF_GENERAL_NAME cdecl;
  {$EXTERNALSYM Tsk_GENERAL_NAME_find}
  Tsk_GENERAL_NAME_find = function (sk : PSTACK_OF_GENERAL_NAME; _val : PGENERAL_NAME) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_GENERAL_NAME_pop_free}
  Tsk_GENERAL_NAME_pop_free = procedure (sk : PSTACK_OF_GENERAL_NAME; func: TOPENSSL_sk_freefunc) cdecl;
  {$EXTERNALSYM Tsk_ACCESS_DESCRIPTION_new}
  Tsk_ACCESS_DESCRIPTION_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_ACCESS_DESCRIPTION cdecl;
  {$EXTERNALSYM Tsk_ACCESS_DESCRIPTION_new_null}
  Tsk_ACCESS_DESCRIPTION_new_null = function : PSTACK_OF_ACCESS_DESCRIPTION cdecl;
  {$EXTERNALSYM Tsk_ACCESS_DESCRIPTION_free}
  Tsk_ACCESS_DESCRIPTION_free = procedure(st : PSTACK_OF_ACCESS_DESCRIPTION) cdecl;
  {$EXTERNALSYM Tsk_ACCESS_DESCRIPTION_num}
  Tsk_ACCESS_DESCRIPTION_num = function (const sk : PSTACK_OF_ACCESS_DESCRIPTION) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ACCESS_DESCRIPTION_value}
  Tsk_ACCESS_DESCRIPTION_value = function (const sk : PSTACK_OF_ACCESS_DESCRIPTION; i : TIdC_INT) : PACCESS_DESCRIPTION cdecl;
  {$EXTERNALSYM Tsk_ACCESS_DESCRIPTION_push}
  Tsk_ACCESS_DESCRIPTION_push = function (sk : PSTACK_OF_ACCESS_DESCRIPTION; st : PACCESS_DESCRIPTION) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ACCESS_DESCRIPTION_dup}
  Tsk_ACCESS_DESCRIPTION_dup = function (sk : PSTACK_OF_ACCESS_DESCRIPTION) : PSTACK_OF_ACCESS_DESCRIPTION cdecl;
  {$EXTERNALSYM Tsk_ACCESS_DESCRIPTION_find}
  Tsk_ACCESS_DESCRIPTION_find = function (sk : PSTACK_OF_ACCESS_DESCRIPTION; _val : PACCESS_DESCRIPTION) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ACCESS_DESCRIPTION_pop_free}
  Tsk_ACCESS_DESCRIPTION_pop_free = procedure (sk : PSTACK_OF_ACCESS_DESCRIPTION; func: TOPENSSL_sk_freefunc) cdecl;
  {$EXTERNALSYM Tsk_DIST_POINT_new}
  Tsk_DIST_POINT_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_DIST_POINT cdecl;
  {$EXTERNALSYM Tsk_DIST_POINT_new_null}
  Tsk_DIST_POINT_new_null = function : PSTACK_OF_DIST_POINT cdecl;
  {$EXTERNALSYM Tsk_DIST_POINT_free}
  Tsk_DIST_POINT_free = procedure(st : PSTACK_OF_DIST_POINT) cdecl;
  {$EXTERNALSYM Tsk_DIST_POINT_num}
  Tsk_DIST_POINT_num = function (const sk : PSTACK_OF_DIST_POINT) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_DIST_POINT_value}
  Tsk_DIST_POINT_value = function (const sk : PSTACK_OF_DIST_POINT; i : TIdC_INT) : PDIST_POINT cdecl;
  {$EXTERNALSYM Tsk_DIST_POINT_push}
  Tsk_DIST_POINT_push = function (sk : PSTACK_OF_DIST_POINT; st : PDIST_POINT) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_DIST_POINT_dup}
  Tsk_DIST_POINT_dup = function (sk : PSTACK_OF_DIST_POINT) : PSTACK_OF_DIST_POINT cdecl;
  {$EXTERNALSYM Tsk_DIST_POINT_find}
  Tsk_DIST_POINT_find = function (sk : PSTACK_OF_DIST_POINT; _val : PDIST_POINT) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_DIST_POINT_pop_free}
  Tsk_DIST_POINT_pop_free = procedure (sk : PSTACK_OF_DIST_POINT; func: TOPENSSL_sk_freefunc) cdecl;
  {$EXTERNALSYM Tsk_SXNETID_new}
  Tsk_SXNETID_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_SXNETID cdecl;
  {$EXTERNALSYM Tsk_SXNETID_new_null}
  Tsk_SXNETID_new_null = function : PSTACK_OF_SXNETID cdecl;
  {$EXTERNALSYM Tsk_SXNETID_free}
  Tsk_SXNETID_free = procedure(st : PSTACK_OF_SXNETID) cdecl;
  {$EXTERNALSYM Tsk_SXNETID_num}
  Tsk_SXNETID_num = function (const sk : PSTACK_OF_SXNETID) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_SXNETID_value}
  Tsk_SXNETID_value = function (const sk : PSTACK_OF_SXNETID; i : TIdC_INT) : PSXNETID cdecl;
  {$EXTERNALSYM Tsk_SXNETID_push}
  Tsk_SXNETID_push = function (sk : PSTACK_OF_SXNETID; st : PSXNETID) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_SXNETID_dup}
  Tsk_SXNETID_dup = function (sk : PSTACK_OF_SXNETID) : PSTACK_OF_SXNETID cdecl;
  {$EXTERNALSYM Tsk_SXNETID_find}
  Tsk_SXNETID_find = function (sk : PSTACK_OF_SXNETID; _val : PSXNETID) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_SXNETID_pop_free}
  Tsk_SXNETID_pop_free = procedure (sk : PSTACK_OF_SXNETID; func: TOPENSSL_sk_freefunc) cdecl;
  {$EXTERNALSYM Tsk_POLICYQUALINFO_new}
  Tsk_POLICYQUALINFO_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_POLICYQUALINFO cdecl;
  {$EXTERNALSYM Tsk_POLICYQUALINFO_new_null}
  Tsk_POLICYQUALINFO_new_null = function : PSTACK_OF_POLICYQUALINFO cdecl;
  {$EXTERNALSYM Tsk_POLICYQUALINFO_free}
  Tsk_POLICYQUALINFO_free = procedure(st : PSTACK_OF_POLICYQUALINFO) cdecl;
  {$EXTERNALSYM Tsk_POLICYQUALINFO_num}
  Tsk_POLICYQUALINFO_num = function (const sk : PSTACK_OF_POLICYQUALINFO) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_POLICYQUALINFO_value}
  Tsk_POLICYQUALINFO_value = function (const sk : PSTACK_OF_POLICYQUALINFO; i : TIdC_INT) : PPOLICYQUALINFO cdecl;
  {$EXTERNALSYM Tsk_POLICYQUALINFO_push}
  Tsk_POLICYQUALINFO_push = function (sk : PSTACK_OF_POLICYQUALINFO; st : PPOLICYQUALINFO) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_POLICYQUALINFO_dup}
  Tsk_POLICYQUALINFO_dup = function (sk : PSTACK_OF_POLICYQUALINFO) : PSTACK_OF_POLICYQUALINFO cdecl;
  {$EXTERNALSYM Tsk_POLICYQUALINFO_find}
  Tsk_POLICYQUALINFO_find = function (sk : PSTACK_OF_POLICYQUALINFO; _val : PPOLICYQUALINFO) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_POLICYQUALINFO_pop_free}
  Tsk_POLICYQUALINFO_pop_free = procedure (sk : PSTACK_OF_POLICYQUALINFO; func: TOPENSSL_sk_freefunc) cdecl;
  {$EXTERNALSYM Tsk_POLICYINFO_new}
  Tsk_POLICYINFO_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_POLICYINFO cdecl;
  {$EXTERNALSYM Tsk_POLICYINFO_new_null}
  Tsk_POLICYINFO_new_null = function : PSTACK_OF_POLICYINFO cdecl;
  {$EXTERNALSYM Tsk_POLICYINFO_free}
  Tsk_POLICYINFO_free = procedure(st : PSTACK_OF_POLICYINFO) cdecl;
  {$EXTERNALSYM Tsk_POLICYINFO_num}
  Tsk_POLICYINFO_num = function (const sk : PSTACK_OF_POLICYINFO) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_POLICYINFO_value}
  Tsk_POLICYINFO_value = function (const sk : PSTACK_OF_POLICYINFO; i : TIdC_INT) : PPOLICYINFO cdecl;
  {$EXTERNALSYM Tsk_POLICYINFO_push}
  Tsk_POLICYINFO_push = function (sk : PSTACK_OF_POLICYINFO; st : PPOLICYINFO) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_POLICYINFO_dup}
  Tsk_POLICYINFO_dup = function (sk : PSTACK_OF_POLICYINFO) : PSTACK_OF_POLICYINFO cdecl;
  {$EXTERNALSYM Tsk_POLICYINFO_find}
  Tsk_POLICYINFO_find = function (sk : PSTACK_OF_POLICYINFO; _val : PPOLICYINFO) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_POLICYINFO_pop_free}
  Tsk_POLICYINFO_pop_free = procedure (sk : PSTACK_OF_POLICYINFO; func: TOPENSSL_sk_freefunc) cdecl;
  {$EXTERNALSYM Tsk_POLICY_MAPPING_new}
  Tsk_POLICY_MAPPING_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_POLICY_MAPPING cdecl;
  {$EXTERNALSYM Tsk_POLICY_MAPPING_new_null}
  Tsk_POLICY_MAPPING_new_null = function : PSTACK_OF_POLICY_MAPPING cdecl;
  {$EXTERNALSYM Tsk_POLICY_MAPPING_free}
  Tsk_POLICY_MAPPING_free = procedure(st : PSTACK_OF_POLICY_MAPPING) cdecl;
  {$EXTERNALSYM Tsk_POLICY_MAPPING_num}
  Tsk_POLICY_MAPPING_num = function (const sk : PSTACK_OF_POLICY_MAPPING) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_POLICY_MAPPING_value}
  Tsk_POLICY_MAPPING_value = function (const sk : PSTACK_OF_POLICY_MAPPING; i : TIdC_INT) : PPOLICY_MAPPING cdecl;
  {$EXTERNALSYM Tsk_POLICY_MAPPING_push}
  Tsk_POLICY_MAPPING_push = function (sk : PSTACK_OF_POLICY_MAPPING; st : PPOLICY_MAPPING) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_POLICY_MAPPING_dup}
  Tsk_POLICY_MAPPING_dup = function (sk : PSTACK_OF_POLICY_MAPPING) : PSTACK_OF_POLICY_MAPPING cdecl;
  {$EXTERNALSYM Tsk_POLICY_MAPPING_find}
  Tsk_POLICY_MAPPING_find = function (sk : PSTACK_OF_POLICY_MAPPING; _val : PPOLICY_MAPPING) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_POLICY_MAPPING_pop_free}
  Tsk_POLICY_MAPPING_pop_free = procedure (sk : PSTACK_OF_POLICY_MAPPING; func: TOPENSSL_sk_freefunc) cdecl;
  {$EXTERNALSYM Tsk_GENERAL_SUBTREE_new}
  Tsk_GENERAL_SUBTREE_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_GENERAL_SUBTREE cdecl;
  {$EXTERNALSYM Tsk_GENERAL_SUBTREE_new_null}
  Tsk_GENERAL_SUBTREE_new_null = function : PSTACK_OF_GENERAL_SUBTREE cdecl;
  {$EXTERNALSYM Tsk_GENERAL_SUBTREE_free}
  Tsk_GENERAL_SUBTREE_free = procedure(st : PSTACK_OF_GENERAL_SUBTREE) cdecl;
  {$EXTERNALSYM Tsk_GENERAL_SUBTREE_num}
  Tsk_GENERAL_SUBTREE_num = function (const sk : PSTACK_OF_GENERAL_SUBTREE) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_GENERAL_SUBTREE_value}
  Tsk_GENERAL_SUBTREE_value = function (const sk : PSTACK_OF_GENERAL_SUBTREE; i : TIdC_INT) : PGENERAL_SUBTREE cdecl;
  {$EXTERNALSYM Tsk_GENERAL_SUBTREE_push}
  Tsk_GENERAL_SUBTREE_push = function (sk : PSTACK_OF_GENERAL_SUBTREE; st : PGENERAL_SUBTREE) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_GENERAL_SUBTREE_dup}
  Tsk_GENERAL_SUBTREE_dup = function (sk : PSTACK_OF_GENERAL_SUBTREE) : PSTACK_OF_GENERAL_SUBTREE cdecl;
  {$EXTERNALSYM Tsk_GENERAL_SUBTREE_find}
  Tsk_GENERAL_SUBTREE_find = function (sk : PSTACK_OF_GENERAL_SUBTREE; _val : PGENERAL_SUBTREE) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_GENERAL_SUBTREE_pop_free}
  Tsk_GENERAL_SUBTREE_pop_free = procedure (sk : PSTACK_OF_GENERAL_SUBTREE; func: TOPENSSL_sk_freefunc) cdecl;

  {$EXTERNALSYM Tsk_ASN1_STRING_new}
  Tsk_ASN1_STRING_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_ASN1_STRING cdecl;
  {$EXTERNALSYM Tsk_ASN1_STRING_new_null}
  Tsk_ASN1_STRING_new_null = function : PSTACK_OF_ASN1_STRING cdecl;
  {$EXTERNALSYM Tsk_ASN1_STRING_free}
  Tsk_ASN1_STRING_free = procedure(st : PSTACK_OF_ASN1_STRING) cdecl;
  {$EXTERNALSYM Tsk_ASN1_STRING_num}
  Tsk_ASN1_STRING_num = function (const sk : PSTACK_OF_ASN1_STRING) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ASN1_STRING_value}
  Tsk_ASN1_STRING_value = function (const sk : PSTACK_OF_ASN1_STRING; i : TIdC_INT) : PASN1_STRING cdecl;
  {$EXTERNALSYM Tsk_ASN1_STRING_push}
  Tsk_ASN1_STRING_push = function (sk : PSTACK_OF_ASN1_STRING; st : PASN1_STRING) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ASN1_STRING_dup}
  Tsk_ASN1_STRING_dup = function (sk : PSTACK_OF_ASN1_STRING) : PSTACK_OF_ASN1_STRING cdecl;
  {$EXTERNALSYM Tsk_ASN1_STRING_find}
  Tsk_ASN1_STRING_find = function (sk : PSTACK_OF_ASN1_STRING; _val : PASN1_STRING) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_ASN1_STRING_pop_free}
  Tsk_ASN1_STRING_pop_free = procedure (sk : PSTACK_OF_ASN1_STRING; func: TOPENSSL_sk_freefunc) cdecl;

  {$EXTERNALSYM Tsk_X509_PURPOSE_new}
  Tsk_X509_PURPOSE_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_X509_PURPOSE cdecl;
  {$EXTERNALSYM Tsk_X509_PURPOSE_new_null}
  Tsk_X509_PURPOSE_new_null = function : PSTACK_OF_X509_PURPOSE cdecl;
  {$EXTERNALSYM Tsk_X509_PURPOSE_free}
  Tsk_X509_PURPOSE_free = procedure(st : PSTACK_OF_X509_PURPOSE) cdecl;
  {$EXTERNALSYM Tsk_X509_PURPOSE_num}
  Tsk_X509_PURPOSE_num = function (const sk : PSTACK_OF_X509_PURPOSE) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_PURPOSE_value}
  Tsk_X509_PURPOSE_value = function (const sk : PSTACK_OF_X509_PURPOSE; i : TIdC_INT) : PX509_PURPOSE cdecl;
  {$EXTERNALSYM Tsk_X509_PURPOSE_push}
  Tsk_X509_PURPOSE_push = function (sk : PSTACK_OF_X509_PURPOSE; st : PX509_PURPOSE) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_PURPOSE_dup}
  Tsk_X509_PURPOSE_dup = function (sk : PSTACK_OF_X509_PURPOSE) : PSTACK_OF_X509_PURPOSE cdecl;
  {$EXTERNALSYM Tsk_X509_PURPOSE_find}
  Tsk_X509_PURPOSE_find = function (sk : PSTACK_OF_X509_PURPOSE; _val : PX509_PURPOSE) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_PURPOSE_pop_free}
  Tsk_X509_PURPOSE_pop_free = procedure (sk : PSTACK_OF_X509_PURPOSE; func: TOPENSSL_sk_freefunc) cdecl;

  {$EXTERNALSYM Tsk_X509_POLICY_NODE_new}
  Tsk_X509_POLICY_NODE_new = function(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_X509_POLICY_NODE cdecl;
  {$EXTERNALSYM Tsk_X509_POLICY_NODE_new_null}
  Tsk_X509_POLICY_NODE_new_null = function : PSTACK_OF_X509_POLICY_NODE cdecl;
  {$EXTERNALSYM Tsk_X509_POLICY_NODE_free}
  Tsk_X509_POLICY_NODE_free = procedure(st : PSTACK_OF_X509_POLICY_NODE) cdecl;
  {$EXTERNALSYM Tsk_X509_POLICY_NODE_num}
  Tsk_X509_POLICY_NODE_num = function (const sk : PSTACK_OF_X509_POLICY_NODE) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_POLICY_NODE_value}
  Tsk_X509_POLICY_NODE_value = function (const sk : PSTACK_OF_X509_POLICY_NODE; i : TIdC_INT) : PX509_POLICY_NODE cdecl;
  {$EXTERNALSYM Tsk_X509_POLICY_NODE_push}
  Tsk_X509_POLICY_NODE_push = function (sk : PSTACK_OF_X509_POLICY_NODE; st : PX509_POLICY_NODE) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_POLICY_NODE_dup}
  Tsk_X509_POLICY_NODE_dup = function (sk : PSTACK_OF_X509_POLICY_NODE) : PSTACK_OF_X509_POLICY_NODE cdecl;
  {$EXTERNALSYM Tsk_X509_POLICY_NODE_find}
  Tsk_X509_POLICY_NODE_find = function (sk : PSTACK_OF_X509_POLICY_NODE; _val : PX509_POLICY_NODE) : TIdC_INT cdecl;
  {$EXTERNALSYM Tsk_X509_POLICY_NODE_pop_free}
  Tsk_X509_POLICY_NODE_pop_free = procedure (sk : PSTACK_OF_X509_POLICY_NODE; func: TOPENSSL_sk_freefunc) cdecl;


var
  {$EXTERNALSYM sk_ASIdOrRange_new}
  sk_ASIdOrRange_new: Tsk_ASIdOrRange_new = nil;
  {$EXTERNALSYM sk_ASIdOrRange_new_null}
  sk_ASIdOrRange_new_null : Tsk_ASIdOrRange_new_null = nil;
  {$EXTERNALSYM sk_ASIdOrRange_free}
  sk_ASIdOrRange_free : Tsk_ASIdOrRange_free = nil;
  {$EXTERNALSYM sk_ASIdOrRange_num}
  sk_ASIdOrRange_num : Tsk_ASIdOrRange_num = nil;
  {$EXTERNALSYM sk_ASIdOrRange_value}
  sk_ASIdOrRange_value : Tsk_ASIdOrRange_value = nil;
  {$EXTERNALSYM sk_ASIdOrRange_push}
  sk_ASIdOrRange_push : Tsk_ASIdOrRange_push = nil;
  {$EXTERNALSYM sk_ASIdOrRange_dup}
  sk_ASIdOrRange_dup : Tsk_ASIdOrRange_dup = nil;
  {$EXTERNALSYM sk_ASIdOrRange_find}
  sk_ASIdOrRange_find : Tsk_ASIdOrRange_find = nil;
  {$EXTERNALSYM sk_ASIdOrRange_pop_free}
  sk_ASIdOrRange_pop_free :  Tsk_ASIdOrRange_pop_free = nil;
  {$EXTERNALSYM sk_IPAddressFamily_new}
  sk_IPAddressFamily_new: Tsk_IPAddressFamily_new = nil;
  {$EXTERNALSYM sk_IPAddressFamily_new_null}
  sk_IPAddressFamily_new_null : Tsk_IPAddressFamily_new_null = nil;
  {$EXTERNALSYM sk_IPAddressFamily_free}
  sk_IPAddressFamily_free : Tsk_IPAddressFamily_free = nil;
  {$EXTERNALSYM sk_IPAddressFamily_num}
  sk_IPAddressFamily_num : Tsk_IPAddressFamily_num = nil;
  {$EXTERNALSYM sk_IPAddressFamily_value}
  sk_IPAddressFamily_value : Tsk_IPAddressFamily_value = nil;
  {$EXTERNALSYM sk_IPAddressFamily_push}
  sk_IPAddressFamily_push : Tsk_IPAddressFamily_push = nil;
  {$EXTERNALSYM sk_IPAddressFamily_dup}
  sk_IPAddressFamily_dup : Tsk_IPAddressFamily_dup = nil;
  {$EXTERNALSYM sk_IPAddressFamily_find}
  sk_IPAddressFamily_find : Tsk_IPAddressFamily_find = nil;
  {$EXTERNALSYM sk_IPAddressFamily_pop_free}
  sk_IPAddressFamily_pop_free :  Tsk_IPAddressFamily_pop_free = nil;
  {$EXTERNALSYM sk_GENERAL_NAME_new}
  sk_GENERAL_NAME_new :  Tsk_GENERAL_NAME_new = nil;
  {$EXTERNALSYM sk_GENERAL_NAME_new_null}
  sk_GENERAL_NAME_new_null : Tsk_GENERAL_NAME_new_null = nil;
  {$EXTERNALSYM sk_GENERAL_NAME_free}
  sk_GENERAL_NAME_free : Tsk_GENERAL_NAME_free = nil;
  {$EXTERNALSYM sk_GENERAL_NAME_num}
  sk_GENERAL_NAME_num :  Tsk_GENERAL_NAME_num = nil;
  {$EXTERNALSYM sk_GENERAL_NAME_value}
  sk_GENERAL_NAME_value : Tsk_GENERAL_NAME_value = nil;
  {$EXTERNALSYM sk_GENERAL_NAME_push}
  sk_GENERAL_NAME_push : Tsk_GENERAL_NAME_push = nil;
  {$EXTERNALSYM sk_GENERAL_NAME_dup}
  sk_GENERAL_NAME_dup : Tsk_GENERAL_NAME_dup = nil;
  {$EXTERNALSYM sk_GENERAL_NAME_find}
  sk_GENERAL_NAME_find : Tsk_GENERAL_NAME_find = nil;
  {$EXTERNALSYM sk_GENERAL_NAME_pop_free}
  sk_GENERAL_NAME_pop_free : Tsk_GENERAL_NAME_pop_free = nil;
  {$EXTERNALSYM sk_ACCESS_DESCRIPTION_new}
  sk_ACCESS_DESCRIPTION_new :  Tsk_ACCESS_DESCRIPTION_new = nil;
  {$EXTERNALSYM sk_ACCESS_DESCRIPTION_new_null}
  sk_ACCESS_DESCRIPTION_new_null : Tsk_ACCESS_DESCRIPTION_new_null = nil;
  {$EXTERNALSYM sk_ACCESS_DESCRIPTION_free}
  sk_ACCESS_DESCRIPTION_free : Tsk_ACCESS_DESCRIPTION_free = nil;
  {$EXTERNALSYM sk_ACCESS_DESCRIPTION_num}
  sk_ACCESS_DESCRIPTION_num :  Tsk_ACCESS_DESCRIPTION_num = nil;
  {$EXTERNALSYM sk_ACCESS_DESCRIPTION_value}
  sk_ACCESS_DESCRIPTION_value : Tsk_ACCESS_DESCRIPTION_value = nil;
  {$EXTERNALSYM sk_ACCESS_DESCRIPTION_push}
  sk_ACCESS_DESCRIPTION_push : Tsk_ACCESS_DESCRIPTION_push = nil;
  {$EXTERNALSYM sk_ACCESS_DESCRIPTION_dup}
  sk_ACCESS_DESCRIPTION_dup : Tsk_ACCESS_DESCRIPTION_dup = nil;
  {$EXTERNALSYM sk_ACCESS_DESCRIPTION_find}
  sk_ACCESS_DESCRIPTION_find : Tsk_ACCESS_DESCRIPTION_find = nil;
  {$EXTERNALSYM sk_ACCESS_DESCRIPTION_pop_free}
  sk_ACCESS_DESCRIPTION_pop_free : Tsk_ACCESS_DESCRIPTION_pop_free = nil;
  {$EXTERNALSYM sk_DIST_POINT_new}
  sk_DIST_POINT_new: Tsk_DIST_POINT_new = nil;
  {$EXTERNALSYM sk_DIST_POINT_new_null}
  sk_DIST_POINT_new_null : Tsk_DIST_POINT_new_null = nil;
  {$EXTERNALSYM sk_DIST_POINT_free}
  sk_DIST_POINT_free : Tsk_DIST_POINT_free = nil;
  {$EXTERNALSYM sk_DIST_POINT_num}
  sk_DIST_POINT_num : Tsk_DIST_POINT_num = nil;
  {$EXTERNALSYM sk_DIST_POINT_value}
  sk_DIST_POINT_value : Tsk_DIST_POINT_value = nil;
  {$EXTERNALSYM sk_DIST_POINT_push}
  sk_DIST_POINT_push : Tsk_DIST_POINT_push = nil;
  {$EXTERNALSYM sk_DIST_POINT_dup}
  sk_DIST_POINT_dup : Tsk_DIST_POINT_dup = nil;
  {$EXTERNALSYM sk_DIST_POINT_find}
  sk_DIST_POINT_find : Tsk_DIST_POINT_find = nil;
  {$EXTERNALSYM sk_DIST_POINT_pop_free}
  sk_DIST_POINT_pop_free :  Tsk_DIST_POINT_pop_free = nil;
  {$EXTERNALSYM sk_SXNETID_new}
  sk_SXNETID_new :  Tsk_SXNETID_new = nil;
  {$EXTERNALSYM sk_SXNETID_new_null}
  sk_SXNETID_new_null : Tsk_SXNETID_new_null = nil;
  {$EXTERNALSYM sk_SXNETID_free}
  sk_SXNETID_free : Tsk_SXNETID_free = nil;
  {$EXTERNALSYM sk_SXNETID_num}
  sk_SXNETID_num :  Tsk_SXNETID_num = nil;
  {$EXTERNALSYM sk_SXNETID_value}
  sk_SXNETID_value : Tsk_SXNETID_value = nil;
  {$EXTERNALSYM sk_SXNETID_push}
  sk_SXNETID_push : Tsk_SXNETID_push = nil;
  {$EXTERNALSYM sk_SXNETID_dup}
  sk_SXNETID_dup : Tsk_SXNETID_dup = nil;
  {$EXTERNALSYM sk_SXNETID_find}
  sk_SXNETID_find : Tsk_SXNETID_find = nil;
  {$EXTERNALSYM sk_SXNETID_pop_free}
  sk_SXNETID_pop_free : Tsk_SXNETID_pop_free = nil;
  {$EXTERNALSYM sk_POLICYQUALINFO_new}
  sk_POLICYQUALINFO_new :  Tsk_POLICYQUALINFO_new = nil;
  {$EXTERNALSYM sk_POLICYQUALINFO_new_null}
  sk_POLICYQUALINFO_new_null : Tsk_POLICYQUALINFO_new_null = nil;
  {$EXTERNALSYM sk_POLICYQUALINFO_free}
  sk_POLICYQUALINFO_free : Tsk_POLICYQUALINFO_free = nil;
  {$EXTERNALSYM sk_POLICYQUALINFO_num}
  sk_POLICYQUALINFO_num :  Tsk_POLICYQUALINFO_num = nil;
  {$EXTERNALSYM sk_POLICYQUALINFO_value}
  sk_POLICYQUALINFO_value : Tsk_POLICYQUALINFO_value = nil;
  {$EXTERNALSYM sk_POLICYQUALINFO_push}
  sk_POLICYQUALINFO_push : Tsk_POLICYQUALINFO_push = nil;
  {$EXTERNALSYM sk_POLICYQUALINFO_dup}
  sk_POLICYQUALINFO_dup : Tsk_POLICYQUALINFO_dup = nil;
  {$EXTERNALSYM sk_POLICYQUALINFO_find}
  sk_POLICYQUALINFO_find : Tsk_POLICYQUALINFO_find = nil;
  {$EXTERNALSYM sk_POLICYQUALINFO_pop_free}
  sk_POLICYQUALINFO_pop_free : Tsk_POLICYQUALINFO_pop_free = nil;
  {$EXTERNALSYM sk_POLICYINFO_new}
  sk_POLICYINFO_new :  Tsk_POLICYINFO_new = nil;
  {$EXTERNALSYM sk_POLICYINFO_new_null}
  sk_POLICYINFO_new_null : Tsk_POLICYINFO_new_null = nil;
  {$EXTERNALSYM sk_POLICYINFO_free}
  sk_POLICYINFO_free : Tsk_POLICYINFO_free = nil;
  {$EXTERNALSYM sk_POLICYINFO_num}
  sk_POLICYINFO_num :  Tsk_POLICYINFO_num = nil;
  {$EXTERNALSYM sk_POLICYINFO_value}
  sk_POLICYINFO_value : Tsk_POLICYINFO_value = nil;
  {$EXTERNALSYM sk_POLICYINFO_push}
  sk_POLICYINFO_push : Tsk_POLICYINFO_push = nil;
  {$EXTERNALSYM sk_POLICYINFO_dup}
  sk_POLICYINFO_dup : Tsk_POLICYINFO_dup = nil;
  {$EXTERNALSYM sk_POLICYINFO_find}
  sk_POLICYINFO_find : Tsk_POLICYINFO_find = nil;
  {$EXTERNALSYM sk_POLICYINFO_pop_free}
  sk_POLICYINFO_pop_free : Tsk_POLICYINFO_pop_free = nil;
  {$EXTERNALSYM sk_POLICY_MAPPING_new}
  sk_POLICY_MAPPING_new :  Tsk_POLICY_MAPPING_new = nil;
  {$EXTERNALSYM sk_POLICY_MAPPING_new_null}
  sk_POLICY_MAPPING_new_null : Tsk_POLICY_MAPPING_new_null = nil;
  {$EXTERNALSYM sk_POLICY_MAPPING_free}
  sk_POLICY_MAPPING_free : Tsk_POLICY_MAPPING_free = nil;
  {$EXTERNALSYM sk_POLICY_MAPPING_num}
  sk_POLICY_MAPPING_num :  Tsk_POLICY_MAPPING_num = nil;
  {$EXTERNALSYM sk_POLICY_MAPPING_value}
  sk_POLICY_MAPPING_value : Tsk_POLICY_MAPPING_value = nil;
  {$EXTERNALSYM sk_POLICY_MAPPING_push}
  sk_POLICY_MAPPING_push : Tsk_POLICY_MAPPING_push = nil;
  {$EXTERNALSYM sk_POLICY_MAPPING_dup}
  sk_POLICY_MAPPING_dup : Tsk_POLICY_MAPPING_dup = nil;
  {$EXTERNALSYM sk_POLICY_MAPPING_find}
  sk_POLICY_MAPPING_find : Tsk_POLICY_MAPPING_find = nil;
  {$EXTERNALSYM sk_POLICY_MAPPING_pop_free}
  sk_POLICY_MAPPING_pop_free : Tsk_POLICY_MAPPING_pop_free = nil;
  {$EXTERNALSYM sk_GENERAL_SUBTREE_new}
  sk_GENERAL_SUBTREE_new :  Tsk_GENERAL_SUBTREE_new = nil;
  {$EXTERNALSYM sk_GENERAL_SUBTREE_new_null}
  sk_GENERAL_SUBTREE_new_null : Tsk_GENERAL_SUBTREE_new_null = nil;
  {$EXTERNALSYM sk_GENERAL_SUBTREE_free}
  sk_GENERAL_SUBTREE_free : Tsk_GENERAL_SUBTREE_free = nil;
  {$EXTERNALSYM sk_GENERAL_SUBTREE_num}
  sk_GENERAL_SUBTREE_num :  Tsk_GENERAL_SUBTREE_num = nil;
  {$EXTERNALSYM sk_GENERAL_SUBTREE_value}
  sk_GENERAL_SUBTREE_value : Tsk_GENERAL_SUBTREE_value = nil;
  {$EXTERNALSYM sk_GENERAL_SUBTREE_push}
  sk_GENERAL_SUBTREE_push : Tsk_GENERAL_SUBTREE_push = nil;
  {$EXTERNALSYM sk_GENERAL_SUBTREE_dup}
  sk_GENERAL_SUBTREE_dup : Tsk_GENERAL_SUBTREE_dup = nil;
  {$EXTERNALSYM sk_GENERAL_SUBTREE_find}
  sk_GENERAL_SUBTREE_find : Tsk_GENERAL_SUBTREE_find = nil;
  {$EXTERNALSYM sk_GENERAL_SUBTREE_pop_free}
  sk_GENERAL_SUBTREE_pop_free : Tsk_GENERAL_SUBTREE_pop_free = nil;

  {$EXTERNALSYM sk_ASN1_STRING_new}
  sk_ASN1_STRING_new :  Tsk_ASN1_STRING_new = nil;
  {$EXTERNALSYM sk_ASN1_STRING_new_null}
  sk_ASN1_STRING_new_null : Tsk_ASN1_STRING_new_null = nil;
  {$EXTERNALSYM sk_ASN1_STRING_free}
  sk_ASN1_STRING_free : Tsk_ASN1_STRING_free = nil;
  {$EXTERNALSYM sk_ASN1_STRING_num}
  sk_ASN1_STRING_num :  Tsk_ASN1_STRING_num = nil;
  {$EXTERNALSYM sk_ASN1_STRING_value}
  sk_ASN1_STRING_value : Tsk_ASN1_STRING_value = nil;
  {$EXTERNALSYM sk_ASN1_STRING_push}
  sk_ASN1_STRING_push : Tsk_ASN1_STRING_push = nil;
  {$EXTERNALSYM sk_ASN1_STRING_dup}
  sk_ASN1_STRING_dup : Tsk_ASN1_STRING_dup = nil;
  {$EXTERNALSYM sk_ASN1_STRING_find}
  sk_ASN1_STRING_find : Tsk_ASN1_STRING_find = nil;
  {$EXTERNALSYM sk_ASN1_STRING_pop_free}
  sk_ASN1_STRING_pop_free : Tsk_ASN1_STRING_pop_free = nil;

  {$EXTERNALSYM sk_X509_PURPOSE_new}
  sk_X509_PURPOSE_new :  Tsk_X509_PURPOSE_new = nil;
  {$EXTERNALSYM sk_X509_PURPOSE_new_null}
  sk_X509_PURPOSE_new_null : Tsk_X509_PURPOSE_new_null = nil;
  {$EXTERNALSYM sk_X509_PURPOSE_free}
  sk_X509_PURPOSE_free : Tsk_X509_PURPOSE_free = nil;
  {$EXTERNALSYM sk_X509_PURPOSE_num}
  sk_X509_PURPOSE_num :  Tsk_X509_PURPOSE_num = nil;
  {$EXTERNALSYM sk_X509_PURPOSE_value}
  sk_X509_PURPOSE_value : Tsk_X509_PURPOSE_value = nil;
  {$EXTERNALSYM sk_X509_PURPOSE_push}
  sk_X509_PURPOSE_push : Tsk_X509_PURPOSE_push = nil;
  {$EXTERNALSYM sk_X509_PURPOSE_dup}
  sk_X509_PURPOSE_dup : Tsk_X509_PURPOSE_dup = nil;
  {$EXTERNALSYM sk_X509_PURPOSE_find}
  sk_X509_PURPOSE_find : Tsk_X509_PURPOSE_find = nil;
  {$EXTERNALSYM sk_X509_PURPOSE_pop_free}
  sk_X509_PURPOSE_pop_free : Tsk_X509_PURPOSE_pop_free = nil;

  {$EXTERNALSYM sk_X509_POLICY_NODE_new}
  sk_X509_POLICY_NODE_new :  Tsk_X509_POLICY_NODE_new = nil;
  {$EXTERNALSYM sk_X509_POLICY_NODE_new_null}
  sk_X509_POLICY_NODE_new_null : Tsk_X509_POLICY_NODE_new_null = nil;
  {$EXTERNALSYM sk_X509_POLICY_NODE_free}
  sk_X509_POLICY_NODE_free : Tsk_X509_POLICY_NODE_free = nil;
  {$EXTERNALSYM sk_X509_POLICY_NODE_num}
  sk_X509_POLICY_NODE_num :  Tsk_X509_POLICY_NODE_num = nil;
  {$EXTERNALSYM sk_X509_POLICY_NODE_value}
  sk_X509_POLICY_NODE_value : Tsk_X509_POLICY_NODE_value = nil;
  {$EXTERNALSYM sk_X509_POLICY_NODE_push}
  sk_X509_POLICY_NODE_push : Tsk_X509_POLICY_NODE_push = nil;
  {$EXTERNALSYM sk_X509_POLICY_NODE_dup}
  sk_X509_POLICY_NODE_dup : Tsk_X509_POLICY_NODE_dup = nil;
  {$EXTERNALSYM sk_X509_POLICY_NODE_find}
  sk_X509_POLICY_NODE_find : Tsk_X509_POLICY_NODE_find = nil;
  {$EXTERNALSYM sk_X509_POLICY_NODE_pop_free}
  sk_X509_POLICY_NODE_pop_free : Tsk_X509_POLICY_NODE_pop_free = nil;

{$ELSE}
  {$EXTERNALSYM sk_ASIdOrRange_new}
  function sk_ASIdOrRange_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_ASIdOrRange cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_ASIdOrRange_new_null}
  function sk_ASIdOrRange_new_null : PSTACK_OF_ASIdOrRange cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_ASIdOrRange_free}
  procedure sk_ASIdOrRange_free(st : PSTACK_OF_ASIdOrRange) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_ASIdOrRange_num}
  function sk_ASIdOrRange_num (const sk : PSTACK_OF_ASIdOrRange) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_ASIdOrRange_value}
  function sk_ASIdOrRange_value (const sk : PSTACK_OF_ASIdOrRange; i : TIdC_INT): PASIdOrRange cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_ASIdOrRange_push}
  function sk_ASIdOrRange_push (sk : PSTACK_OF_ASIdOrRange; st : PASIdOrRange): TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_ASIdOrRange_dup}
  function sk_ASIdOrRange_dup (sk : PSTACK_OF_ASIdOrRange) : PSTACK_OF_ASIdOrRange cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_ASIdOrRange_find}
  function sk_ASIdOrRange_find (sk : PSTACK_OF_ASIdOrRange; _val : PASIdOrRange) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_ASIdOrRange_pop_free}
  procedure sk_ASIdOrRange_pop_free (sk : PSTACK_OF_ASIdOrRange; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';
  {$EXTERNALSYM sk_IPAddressOrRange_new}
  function sk_IPAddressOrRange_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_IPAddressOrRange cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_IPAddressOrRange_new_null}
  function sk_IPAddressOrRange_new_null : PSTACK_OF_IPAddressOrRange cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_IPAddressOrRange_free}
  procedure sk_IPAddressOrRange_free(st : PSTACK_OF_IPAddressOrRange) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_IPAddressOrRange_num}
  function sk_IPAddressOrRange_num (const sk : PSTACK_OF_IPAddressOrRange) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_IPAddressOrRange_value}
  function sk_IPAddressOrRange_value (const sk : PSTACK_OF_IPAddressOrRange; i : TIdC_INT): PIPAddressOrRange cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_IPAddressOrRange_push}
  function sk_IPAddressOrRange_push (sk : PSTACK_OF_IPAddressOrRange; st : PIPAddressOrRange): TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_IPAddressOrRange_dup}
  function sk_IPAddressOrRange_dup (sk : PSTACK_OF_IPAddressOrRange) : PSTACK_OF_IPAddressOrRange cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_IPAddressOrRange_find}
  function sk_IPAddressOrRange_find (sk : PSTACK_OF_IPAddressOrRange; _val : PIPAddressOrRange) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_IPAddressOrRange_pop_free}
  procedure sk_IPAddressOrRange_pop_free (sk : PSTACK_OF_IPAddressOrRange; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';
  {$EXTERNALSYM sk_IPAddressFamily_new}
  function sk_IPAddressFamily_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_IPAddressFamily cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_IPAddressFamily_new_null}
  function sk_IPAddressFamily_new_null : PSTACK_OF_IPAddressFamily cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_IPAddressFamily_free}
  procedure sk_IPAddressFamily_free(st : PSTACK_OF_IPAddressFamily) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_IPAddressFamily_num}
  function sk_IPAddressFamily_num (const sk : PSTACK_OF_IPAddressFamily) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_IPAddressFamily_value}
  function sk_IPAddressFamily_value (const sk : PSTACK_OF_IPAddressFamily; i : TIdC_INT): PX509_NAME cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_IPAddressFamily_push}
  function sk_IPAddressFamily_push (sk : PSTACK_OF_IPAddressFamily; st : PX509_NAME): TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_IPAddressFamily_dup}
  function sk_IPAddressFamily_dup (sk : PSTACK_OF_IPAddressFamily) : PSTACK_OF_IPAddressFamily cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_IPAddressFamily_find}
  function sk_IPAddressFamily_find (sk : PSTACK_OF_IPAddressFamily; _val : PX509_NAME) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_IPAddressFamily_pop_free}
  procedure sk_IPAddressFamily_pop_free (sk : PSTACK_OF_IPAddressFamily; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';
  {$EXTERNALSYM sk_GENERAL_NAME_new}
  function sk_GENERAL_NAME_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_GENERAL_NAME cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_GENERAL_NAME_new_null}
  function sk_GENERAL_NAME_new_null : PSTACK_OF_GENERAL_NAME cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_GENERAL_NAME_free}
  procedure sk_GENERAL_NAME_free(st : PSTACK_OF_GENERAL_NAME) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_GENERAL_NAME_num}
  function sk_GENERAL_NAME_num (const sk : PSTACK_OF_GENERAL_NAME) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_GENERAL_NAME_value}
  function sk_GENERAL_NAME_value (const sk : PSTACK_OF_GENERAL_NAME; i : TIdC_INT): PGENERAL_NAME cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_GENERAL_NAME_push}
  function sk_GENERAL_NAME_push (sk : PSTACK_OF_GENERAL_NAME; st : PGENERAL_NAME): TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_GENERAL_NAME_dup}
  function sk_GENERAL_NAME_dup (sk : PSTACK_OF_GENERAL_NAME) : PSTACK_OF_GENERAL_NAME cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_GENERAL_NAME_find}
  function sk_GENERAL_NAME_find (sk : PSTACK_OF_GENERAL_NAME; _val : PGENERAL_NAME) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_GENERAL_NAME_pop_free}
  procedure sk_GENERAL_NAME_pop_free (sk : PSTACK_OF_GENERAL_NAME; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';
  {$EXTERNALSYM sk_ACCESS_DESCRIPTION_new}
  function sk_ACCESS_DESCRIPTION_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_ACCESS_DESCRIPTION cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_ACCESS_DESCRIPTION_new_null}
  function sk_ACCESS_DESCRIPTION_new_null : PSTACK_OF_ACCESS_DESCRIPTION cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_ACCESS_DESCRIPTION_free}
  procedure sk_ACCESS_DESCRIPTION_free(st : PSTACK_OF_ACCESS_DESCRIPTION) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_ACCESS_DESCRIPTION_num}
  function sk_ACCESS_DESCRIPTION_num (const sk : PSTACK_OF_ACCESS_DESCRIPTION) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_ACCESS_DESCRIPTION_value}
  function sk_ACCESS_DESCRIPTION_value (const sk : PSTACK_OF_ACCESS_DESCRIPTION; i : TIdC_INT): PACCESS_DESCRIPTION cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_ACCESS_DESCRIPTION_push}
  function sk_ACCESS_DESCRIPTION_push (sk : PSTACK_OF_ACCESS_DESCRIPTION; st : PACCESS_DESCRIPTION): TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_ACCESS_DESCRIPTION_dup}
  function sk_ACCESS_DESCRIPTION_dup (sk : PSTACK_OF_ACCESS_DESCRIPTION) : PSTACK_OF_ACCESS_DESCRIPTION cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_ACCESS_DESCRIPTION_find}
  function sk_ACCESS_DESCRIPTION_find (sk : PSTACK_OF_ACCESS_DESCRIPTION; _val : PACCESS_DESCRIPTION) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_ACCESS_DESCRIPTION_pop_free}
  procedure sk_ACCESS_DESCRIPTION_pop_free (sk : PSTACK_OF_ACCESS_DESCRIPTION; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';
  {$EXTERNALSYM sk_DIST_POINT_new}
  function sk_DIST_POINT_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_DIST_POINT cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_DIST_POINT_new_null}
  function sk_DIST_POINT_new_null : PSTACK_OF_DIST_POINT cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_DIST_POINT_free}
  procedure sk_DIST_POINT_free(st : PSTACK_OF_DIST_POINT) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_DIST_POINT_num}
  function sk_DIST_POINT_num (const sk : PSTACK_OF_DIST_POINT) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_DIST_POINT_value}
  function sk_DIST_POINT_value (const sk : PSTACK_OF_DIST_POINT; i : TIdC_INT): PDIST_POINT cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_DIST_POINT_push}
  function sk_DIST_POINT_push (sk : PSTACK_OF_DIST_POINT; st : PDIST_POINT): TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_DIST_POINT_dup}
  function sk_DIST_POINT_dup (sk : PSTACK_OF_DIST_POINT) : PSTACK_OF_DIST_POINT cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_DIST_POINT_find}
  function sk_DIST_POINT_find (sk : PSTACK_OF_DIST_POINT; _val : PDIST_POINT) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_DIST_POINT_pop_free}
  procedure sk_DIST_POINT_pop_free (sk : PSTACK_OF_DIST_POINT; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';

  {$EXTERNALSYM sk_SXNETID_new}
  function sk_SXNETID_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_SXNETID cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_SXNETID_new_null}
  function sk_SXNETID_new_null : PSTACK_OF_SXNETID cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_SXNETID_free}
  procedure sk_SXNETID_free(st : PSTACK_OF_SXNETID) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_SXNETID_num}
  function sk_SXNETID_num (const sk : PSTACK_OF_SXNETID) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_SXNETID_value}
  function sk_SXNETID_value (const sk : PSTACK_OF_SXNETID; i : TIdC_INT): PSXNETID cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_SXNETID_push}
  function sk_SXNETID_push (sk : PSTACK_OF_SXNETID; st : PSXNETID): TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_SXNETID_dup}
  function sk_SXNETID_dup (sk : PSTACK_OF_SXNETID) : PSTACK_OF_SXNETID cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_SXNETID_find}
  function sk_SXNETID_find (sk : PSTACK_OF_SXNETID; _val : PSXNETID) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_SXNETID_pop_free}
  procedure sk_SXNETID_pop_free (sk : PSTACK_OF_SXNETID; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';

  {$EXTERNALSYM sk_POLICYQUALINFO_new}
  function sk_POLICYQUALINFO_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_POLICYQUALINFO cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_POLICYQUALINFO_new_null}
  function sk_POLICYQUALINFO_new_null : PSTACK_OF_POLICYQUALINFO cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_POLICYQUALINFO_free}
  procedure sk_POLICYQUALINFO_free(st : PSTACK_OF_POLICYQUALINFO) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_POLICYQUALINFO_num}
  function sk_POLICYQUALINFO_num (const sk : PSTACK_OF_POLICYQUALINFO) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_POLICYQUALINFO_value}
  function sk_POLICYQUALINFO_value (const sk : PSTACK_OF_POLICYQUALINFO; i : TIdC_INT): PPOLICYQUALINFO cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_POLICYQUALINFO_push}
  function sk_POLICYQUALINFO_push (sk : PSTACK_OF_POLICYQUALINFO; st : PPOLICYQUALINFO): TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_POLICYQUALINFO_dup}
  function sk_POLICYQUALINFO_dup (sk : PSTACK_OF_POLICYQUALINFO) : PSTACK_OF_POLICYQUALINFO cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_POLICYQUALINFO_find}
  function sk_POLICYQUALINFO_find (sk : PSTACK_OF_POLICYQUALINFO; _val : PPOLICYQUALINFO) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_POLICYQUALINFO_pop_free}
  procedure sk_POLICYQUALINFO_pop_free (sk : PSTACK_OF_POLICYQUALINFO; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';

  {$EXTERNALSYM sk_POLICYINFO_new}
  function sk_POLICYINFO_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_POLICYINFO cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_POLICYINFO_new_null}
  function sk_POLICYINFO_new_null : PSTACK_OF_POLICYINFO cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_POLICYINFO_free}
  procedure sk_POLICYINFO_free(st : PSTACK_OF_POLICYINFO) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_POLICYINFO_num}
  function sk_POLICYINFO_num (const sk : PSTACK_OF_POLICYINFO) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_POLICYINFO_value}
  function sk_POLICYINFO_value (const sk : PSTACK_OF_POLICYINFO; i : TIdC_INT): PPOLICYINFO cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_POLICYINFO_push}
  function sk_POLICYINFO_push (sk : PSTACK_OF_POLICYINFO; st : PPOLICYINFO): TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_POLICYINFO_dup}
  function sk_POLICYINFO_dup (sk : PSTACK_OF_POLICYINFO) : PSTACK_OF_POLICYINFO cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_POLICYINFO_find}
  function sk_POLICYINFO_find (sk : PSTACK_OF_POLICYINFO; _val : PPOLICYINFO) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_POLICYINFO_pop_free}
  procedure sk_POLICYINFO_pop_free (sk : PSTACK_OF_POLICYINFO; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';
  {$EXTERNALSYM sk_POLICY_MAPPING_new}
  function sk_POLICY_MAPPING_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_POLICY_MAPPING cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_POLICY_MAPPING_new_null}
  function sk_POLICY_MAPPING_new_null : PSTACK_OF_POLICY_MAPPING cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_POLICY_MAPPING_free}
  procedure sk_POLICY_MAPPING_free(st : PSTACK_OF_POLICY_MAPPING) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_POLICY_MAPPING_num}
  function sk_POLICY_MAPPING_num (const sk : PSTACK_OF_POLICY_MAPPING) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_POLICY_MAPPING_value}
  function sk_POLICY_MAPPING_value (const sk : PSTACK_OF_POLICY_MAPPING; i : TIdC_INT): PPOLICY_MAPPING cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_POLICY_MAPPING_push}
  function sk_POLICY_MAPPING_push (sk : PSTACK_OF_POLICY_MAPPING; st : PPOLICY_MAPPING): TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_POLICY_MAPPING_dup}
  function sk_POLICY_MAPPING_dup (sk : PSTACK_OF_POLICY_MAPPING) : PSTACK_OF_POLICY_MAPPING cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_POLICY_MAPPING_find}
  function sk_POLICY_MAPPING_find (sk : PSTACK_OF_POLICY_MAPPING; _val : PPOLICY_MAPPING) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_POLICY_MAPPING_pop_free}
  procedure sk_POLICY_MAPPING_pop_free (sk : PSTACK_OF_POLICY_MAPPING; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';
  {$EXTERNALSYM sk_GENERAL_SUBTREE_new}
  function sk_GENERAL_SUBTREE_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_GENERAL_SUBTREE cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_GENERAL_SUBTREE_new_null}
  function sk_GENERAL_SUBTREE_new_null : PSTACK_OF_GENERAL_SUBTREE cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_GENERAL_SUBTREE_free}
  procedure sk_GENERAL_SUBTREE_free(st : PSTACK_OF_GENERAL_SUBTREE) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_GENERAL_SUBTREE_num}
  function sk_GENERAL_SUBTREE_num (const sk : PSTACK_OF_GENERAL_SUBTREE) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_GENERAL_SUBTREE_value}
  function sk_GENERAL_SUBTREE_value (const sk : PSTACK_OF_GENERAL_SUBTREE; i : TIdC_INT): PGENERAL_SUBTREE cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_GENERAL_SUBTREE_push}
  function sk_GENERAL_SUBTREE_push (sk : PSTACK_OF_GENERAL_SUBTREE; st : PGENERAL_SUBTREE): TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_GENERAL_SUBTREE_dup}
  function sk_GENERAL_SUBTREE_dup (sk : PSTACK_OF_GENERAL_SUBTREE) : PSTACK_OF_GENERAL_SUBTREE cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_GENERAL_SUBTREE_find}
  function sk_GENERAL_SUBTREE_find (sk : PSTACK_OF_GENERAL_SUBTREE; _val : PGENERAL_SUBTREE) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_GENERAL_SUBTREE_pop_free}
  procedure sk_GENERAL_SUBTREE_pop_free (sk : PSTACK_OF_GENERAL_SUBTREE; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';

  {$EXTERNALSYM sk_ASN1_STRING_new}
  function sk_ASN1_STRING_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_ASN1_STRING cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_ASN1_STRING_new_null}
  function sk_ASN1_STRING_new_null : PSTACK_OF_ASN1_STRING cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_ASN1_STRING_free}
  procedure sk_ASN1_STRING_free(st : PSTACK_OF_ASN1_STRING) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_ASN1_STRING_num}
  function sk_ASN1_STRING_num (const sk : PSTACK_OF_ASN1_STRING) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_ASN1_STRING_value}
  function sk_ASN1_STRING_value (const sk : PSTACK_OF_ASN1_STRING; i : TIdC_INT): PASN1_STRING cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_ASN1_STRING_push}
  function sk_ASN1_STRING_push (sk : PSTACK_OF_ASN1_STRING; st : PASN1_STRING): TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_ASN1_STRING_dup}
  function sk_ASN1_STRING_dup (sk : PSTACK_OF_ASN1_STRING) : PSTACK_OF_ASN1_STRING cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_ASN1_STRING_find}
  function sk_ASN1_STRING_find (sk : PSTACK_OF_ASN1_STRING; _val : PASN1_STRING) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_ASN1_STRING_pop_free}
  procedure sk_ASN1_STRING_pop_free (sk : PSTACK_OF_ASN1_STRING; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';

  {$EXTERNALSYM sk_X509_PURPOSE_new}
  function sk_X509_PURPOSE_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_X509_PURPOSE cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_X509_PURPOSE_new_null}
  function sk_X509_PURPOSE_new_null : PSTACK_OF_X509_PURPOSE cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_X509_PURPOSE_free}
  procedure sk_X509_PURPOSE_free(st : PSTACK_OF_X509_PURPOSE) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_X509_PURPOSE_num}
  function sk_X509_PURPOSE_num (const sk : PSTACK_OF_X509_PURPOSE) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_X509_PURPOSE_value}
  function sk_X509_PURPOSE_value (const sk : PSTACK_OF_X509_PURPOSE; i : TIdC_INT): PX509_PURPOSE cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_X509_PURPOSE_push}
  function sk_X509_PURPOSE_push (sk : PSTACK_OF_X509_PURPOSE; st : PX509_PURPOSE): TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_X509_PURPOSE_dup}
  function sk_X509_PURPOSE_dup (sk : PSTACK_OF_X509_PURPOSE) : PSTACK_OF_X509_PURPOSE cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_X509_PURPOSE_find}
  function sk_X509_PURPOSE_find (sk : PSTACK_OF_X509_PURPOSE; _val : PX509_PURPOSE) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_X509_PURPOSE_pop_free}
  procedure sk_X509_PURPOSE_pop_free (sk : PSTACK_OF_X509_PURPOSE; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';

  {$EXTERNALSYM sk_X509_POLICY_NODE_new}
  function sk_X509_POLICY_NODE_new(cmp : TOPENSSL_sk_compfunc) : PSTACK_OF_X509_POLICY_NODE cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  {$EXTERNALSYM sk_X509_POLICY_NODE_new_null}
  function sk_X509_POLICY_NODE_new_null : PSTACK_OF_X509_POLICY_NODE cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  {$EXTERNALSYM sk_X509_POLICY_NODE_free}
  procedure sk_X509_POLICY_NODE_free(st : PSTACK_OF_X509_POLICY_NODE) cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$EXTERNALSYM sk_X509_POLICY_NODE_num}
  function sk_X509_POLICY_NODE_num (const sk : PSTACK_OF_X509_POLICY_NODE) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_num';
  {$EXTERNALSYM sk_X509_POLICY_NODE_value}
  function sk_X509_POLICY_NODE_value (const sk : PSTACK_OF_X509_POLICY_NODE; i : TIdC_INT): PX509_POLICY_NODE cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  {$EXTERNALSYM sk_X509_POLICY_NODE_push}
  function sk_X509_POLICY_NODE_push (sk : PSTACK_OF_X509_POLICY_NODE; st : PX509_POLICY_NODE): TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_push';
  {$EXTERNALSYM sk_X509_POLICY_NODE_dup}
  function sk_X509_POLICY_NODE_dup (sk : PSTACK_OF_X509_POLICY_NODE) : PSTACK_OF_X509_POLICY_NODE cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  {$EXTERNALSYM sk_X509_POLICY_NODE_find}
  function sk_X509_POLICY_NODE_find (sk : PSTACK_OF_X509_POLICY_NODE; _val : PX509_POLICY_NODE) : TIdC_INT cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  {$EXTERNALSYM sk_X509_POLICY_NODE_pop_free}
  procedure sk_X509_POLICY_NODE_pop_free (sk : PSTACK_OF_X509_POLICY_NODE; func: TOPENSSL_sk_freefunc) cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';

{$ENDIF}

implementation

  uses
    classes,
    TaurusTLSExceptionHandlers
  {$IFNDEF OPENSSL_STATIC_LINK_MODEL}
    ,TaurusTLSLoader
  {$ENDIF};


{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
const
  GENERAL_NAME_cmp_procname = 'GENERAL_NAME_cmp';

//  ASN1_BIT_STRING *v2i_ASN1_BIT_STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; STACK_OF(CONF_VALUE) *nval);
//  STACK_OF(CONF_VALUE) *i2v_ASN1_BIT_STRING(method: PX509V3_EXT_METHOD; ASN1_BIT_STRING *bits; STACK_OF(CONF_VALUE) *extlist);
  //function i2s_ASN1_IA5STRING(method: PX509V3_EXT_METHOD; ia5: PASN1_IA5STRING): PIdAnsiChar;
  //function s2i_ASN1_IA5STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; const _str: PIdAnsiChar): PASN1_IA5STRING;

//  STACK_OF(CONF_VALUE) *i2v_GENERAL_NAME(method: PX509V3_EXT_METHOD; gen: PGENERAL_NAME; STACK_OF(CONF_VALUE) *ret);
  GENERAL_NAME_print_procname = 'GENERAL_NAME_print';

//  DECLARE_ASN1_FUNCTIONS(GENERAL_NAMES)

//  STACK_OF(CONF_VALUE) *i2v_GENERAL_NAMES(method: PX509V3_EXT_METHOD, GENERAL_NAMES *gen, STACK_OF(CONF_VALUE) *extlist);
//  GENERAL_NAMES *v2i_GENERAL_NAMES(const method: PX509V3_EXT_METHOD, ctx: PX509V3_CTX, STACK_OF(CONF_VALUE) *nval);

//  DECLARE_ASN1_FUNCTIONS(OTHERNAME)
//  DECLARE_ASN1_FUNCTIONS(EDIPARTYNAME)
  OTHERNAME_cmp_procname = 'OTHERNAME_cmp';
  GENERAL_NAME_set0_value_procname = 'GENERAL_NAME_set0_value';
  GENERAL_NAME_get0_value_procname = 'GENERAL_NAME_get0_value';
  GENERAL_NAME_set0_othername_procname = 'GENERAL_NAME_set0_othername';
  GENERAL_NAME_get0_otherName_procname = 'GENERAL_NAME_get0_otherName';
  GENERAL_NAMES_free_procname = 'GENERAL_NAMES_free';

  //function i2s_ASN1_OCTET_STRING(method: PX509V3_EXT_METHOD; const ia5: PASN1_OCTET_STRING): PIdAnsiChar;
  //function s2i_ASN1_OCTET_STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; const _str: PIdAnsiChar): PASN1_OCTET_STRING;

//  DECLARE_ASN1_FUNCTIONS(EXTENDED_KEY_USAGE)
  i2a_ACCESS_DESCRIPTION_procname = 'i2a_ACCESS_DESCRIPTION';

//  DECLARE_ASN1_ALLOC_FUNCTIONS(TLS_FEATURE)

//  DECLARE_ASN1_FUNCTIONS(CERTIFICATEPOLICIES)
//  DECLARE_ASN1_FUNCTIONS(POLICYINFO)
//  DECLARE_ASN1_FUNCTIONS(POLICYQUALINFO)
//  DECLARE_ASN1_FUNCTIONS(USERNOTICE)
//  DECLARE_ASN1_FUNCTIONS(NOTICEREF)

//  DECLARE_ASN1_FUNCTIONS(CRL_DIST_POINTS)
//  DECLARE_ASN1_FUNCTIONS(DIST_POINT)
//  DECLARE_ASN1_FUNCTIONS(DIST_POINT_NAME)
//  DECLARE_ASN1_FUNCTIONS(ISSUING_DIST_POINT)

  DIST_POINT_set_dpname_procname = 'DIST_POINT_set_dpname';

  NAME_CONSTRAINTS_check_procname = 'NAME_CONSTRAINTS_check';
  NAME_CONSTRAINTS_check_CN_procname = 'NAME_CONSTRAINTS_check_CN';

  BASIC_CONSTRAINTS_free_procname = 'BASIC_CONSTRAINTS_free';
  AUTHORITY_KEYID_free_procname = 'AUTHORITY_KEYID_free';

//  DECLARE_ASN1_FUNCTIONS(ACCESS_DESCRIPTION)
//  DECLARE_ASN1_FUNCTIONS(AUTHORITY_INFO_ACCESS)

//  DECLARE_ASN1_ITEM(POLICY_MAPPING)
//  DECLARE_ASN1_ALLOC_FUNCTIONS(POLICY_MAPPING)
//  DECLARE_ASN1_ITEM(POLICY_MAPPINGS)

//  DECLARE_ASN1_ITEM(GENERAL_SUBTREE)
//  DECLARE_ASN1_ALLOC_FUNCTIONS(GENERAL_SUBTREE)

//  DECLARE_ASN1_ITEM(NAME_CONSTRAINTS)
//  DECLARE_ASN1_ALLOC_FUNCTIONS(NAME_CONSTRAINTS)

//  DECLARE_ASN1_ALLOC_FUNCTIONS(POLICY_CONSTRAINTS)
//  DECLARE_ASN1_ITEM(POLICY_CONSTRAINTS)

  //function a2i_GENERAL_NAME(out_: PGENERAL_NAME; const method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; TIdC_INT gen_type; const value: PIdAnsiChar; is_nc: TIdC_INT): GENERAL_NAME;

  //function v2i_GENERAL_NAME(const method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; cnf: PCONF_VALUE): PGENERAL_NAME;
  //function v2i_GENERAL_NAME_ex(out_: PGENERAL_NAME; const method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; cnf: PCONF_VALUE; is_nc: TIdC_INT): PGENERAL_NAME;
  //procedure X509V3_conf_free(_val: PCONF_VALUE);

  X509V3_EXT_nconf_nid_procname = 'X509V3_EXT_nconf_nid';
  X509V3_EXT_nconf_procname = 'X509V3_EXT_nconf';
//  TIdC_INT X509V3_EXT_add_nconf_sk(conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; STACK_OF(X509_EXTENSION) **sk);
  X509V3_EXT_add_nconf_procname = 'X509V3_EXT_add_nconf';
  X509V3_EXT_REQ_add_nconf_procname = 'X509V3_EXT_REQ_add_nconf';
  X509V3_EXT_CRL_add_nconf_procname = 'X509V3_EXT_CRL_add_nconf';

  X509V3_EXT_conf_nid_procname = 'X509V3_EXT_conf_nid';
//  X509_EXTENSION *X509V3_EXT_conf_nid(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; ext_nid: TIdC_INT; const value: PIdAnsiChar);
  X509V3_EXT_conf_procname = 'X509V3_EXT_conf';
//  X509_EXTENSION *X509V3_EXT_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const name: PIdAnsiChar; const value: PIdAnsiChar);
  X509V3_EXT_add_conf_procname = 'X509V3_EXT_add_conf';
//  TIdC_INT X509V3_EXT_add_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const section: PIdAnsiChar; cert: PX509);
  X509V3_EXT_REQ_add_conf_procname = 'X509V3_EXT_REQ_add_conf';
//  TIdC_INT X509V3_EXT_REQ_add_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const section: PIdAnsiChar; req: PX509_REQ);
  X509V3_EXT_CRL_add_conf_procname = 'X509V3_EXT_CRL_add_conf';
//  TIdC_INT X509V3_EXT_CRL_add_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const section: PIdAnsiChar; crl: PX509_CRL);

//  TIdC_INT X509V3_add_value_bool_nf(const name: PIdAnsiChar; TIdC_INT asn1_bool; STACK_OF(CONF_VALUE) **extlist);
  //function X509V3_get_value_bool(const value: PCONF_VALUE; asn1_bool: PIdC_INT): TIdC_INT;
  //function X509V3_get_value_int(const value: PCONF_VALUE; aint: PPASN1_INTEGER): TIdC_INT;
  X509V3_set_nconf_procname = 'X509V3_set_nconf';
//  void X509V3_set_conf_lhash(ctx: PX509V3_CTX; LHASH_OF(CONF_VALUE) *lhash);

  X509V3_get_string_procname = 'X509V3_get_string';
//  STACK_OF(CONF_VALUE) *X509V3_get_section(ctx: PX509V3_CTX; const section: PIdAnsiChar);
  X509V3_string_free_procname = 'X509V3_string_free';
//  void X509V3_section_free(ctx: PX509V3_CTX; STACK_OF(CONF_VALUE) *section);
  X509V3_set_ctx_procname = 'X509V3_set_ctx';

//  TIdC_INT X509V3_add_value(const name: PIdAnsiChar; const value: PIdAnsiChar; STACK_OF(CONF_VALUE) **extlist);
//  TIdC_INT X509V3_add_value_uPIdAnsiChar(const name: PIdAnsiChar; const Byte *value; STACK_OF(CONF_VALUE) **extlist);
//  TIdC_INT X509V3_add_value_bool(const name: PIdAnsiChar; TIdC_INT asn1_bool; STACK_OF(CONF_VALUE) **extlist);
//  TIdC_INT X509V3_add_value_int(const name: PIdAnsiChar; const aint: PASN1_INTEGER; STACK_OF(CONF_VALUE) **extlist);
  //function i2s_ASN1_INTEGER(meth: PX509V3_EXT_METHOD; const aint: PASN1_INTEGER): PIdAnsiChar;
  //function s2i_ASN1_INTEGER(meth: PX509V3_EXT_METHOD; const value: PIdAnsiChar): PASN1_INTEGER;
  //function i2s_ASN1_ENUMERATED(meth: PX509V3_EXT_METHOD; const aint: PASN1_ENUMERATED): PIdAnsiChar;
  //function i2s_ASN1_ENUMERATED_TABLE(meth: PX509V3_EXT_METHOD; const aint: PASN1_ENUMERATED): PIdAnsiChar;
  //function X509V3_EXT_add(ext: PX509V3_EXT_METHOD): TIdC_INT;
  //function X509V3_EXT_add_list(extlist: PX509V3_EXT_METHOD): TIdC_INT;
  X509V3_EXT_add_alias_procname = 'X509V3_EXT_add_alias';
  X509V3_EXT_cleanup_procname = 'X509V3_EXT_cleanup';

  //function X509V3_EXT_get(ext: PX509_EXTENSION): PX509V3_EXT_METHOD;
  //function X509V3_EXT_get_nid(nid: TIdC_INT): PX509V3_EXT_METHOD;
  X509V3_add_standard_extensions_procname = 'X509V3_add_standard_extensions';
//  STACK_OF(CONF_VALUE) *X509V3_parse_list(const line: PIdAnsiChar);
  X509V3_EXT_d2i_procname = 'X509V3_EXT_d2i';
//  void *X509V3_get_d2i(const STACK_OF(X509_EXTENSION) *x; nid: TIdC_INT; TIdC_INT *crit; TIdC_INT *idx);

  X509V3_EXT_i2d_procname = 'X509V3_EXT_i2d';
//  TIdC_INT X509V3_add1_i2d(STACK_OF(X509_EXTENSION) **x; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; TIdC_ULONG flags);

//  void X509V3_EXT_val_prn(out_: PBIO; STACK_OF(CONF_VALUE) *val; indent: TIdC_INT; TIdC_INT ml);
  X509V3_EXT_print_procname = 'X509V3_EXT_print';
//  TIdC_INT X509V3_extensions_print(out_: PBIO; const PIdAnsiChar *title; const STACK_OF(X509_EXTENSION) *exts; flag: TIdC_ULONG; indent: TIdC_INT);

  X509_check_ca_procname = 'X509_check_ca';
  X509_check_purpose_procname = 'X509_check_purpose';
  X509_supported_extension_procname = 'X509_supported_extension';
  X509_PURPOSE_set_procname = 'X509_PURPOSE_set';
  X509_check_issued_procname = 'X509_check_issued';
  X509_check_akid_procname = 'X509_check_akid';
  X509_set_proxy_flag_procname = 'X509_set_proxy_flag';
  X509_set_proxy_pathlen_procname = 'X509_set_proxy_pathlen';
  X509_get_proxy_pathlen_procname = 'X509_get_proxy_pathlen';

  X509_get_extension_flags_procname = 'X509_get_extension_flags';
  X509_get_key_usage_procname = 'X509_get_key_usage';
  X509_get_extended_key_usage_procname = 'X509_get_extended_key_usage';
  X509_get0_subject_key_id_procname = 'X509_get0_subject_key_id';
  X509_get0_authority_key_id_procname = 'X509_get0_authority_key_id';
  X509_get0_authority_issuer_procname =  'X509_get0_authority_issuer';
  X509_get0_authority_serial_procname = 'X509_get0_authority_serial';

  X509_PURPOSE_get_count_procname = 'X509_PURPOSE_get_count';
  X509_PURPOSE_get0_procname = 'X509_PURPOSE_get0';
  X509_PURPOSE_get_by_sname_procname = 'X509_PURPOSE_get_by_sname';
  X509_PURPOSE_get_by_id_procname = 'X509_PURPOSE_get_by_id';
//  TIdC_INT X509_PURPOSE_add(id: TIdC_INT, TIdC_INT trust, flags: TIdC_INT, TIdC_INT (*ck) (const X509_PURPOSE *, const X509 *, TIdC_INT), const name: PIdAnsiChar, const sname: PIdAnsiChar, void *arg);
  X509_PURPOSE_get0_name_procname = 'X509_PURPOSE_get0_name';
  X509_PURPOSE_get0_sname_procname = 'X509_PURPOSE_get0_sname';
  X509_PURPOSE_get_trust_procname = 'X509_PURPOSE_get_trust';
  X509_PURPOSE_cleanup_procname = 'X509_PURPOSE_cleanup';
  X509_PURPOSE_get_id_procname = 'X509_PURPOSE_get_id';

  X509_get1_email_procname = 'X509_get1_email';
  X509_REQ_get1_email_procname = 'X509_REQ_get1_email';
  X509_email_free_procname = 'X509_email_free';
  X509_get1_ocsp_procname = 'X509_get1_ocsp';

  X509_check_host_procname = 'X509_check_host';
  X509_check_email_procname = 'X509_check_email';
  X509_check_ip_procname = 'X509_check_ip';
  X509_check_ip_asc_procname = 'X509_check_ip_asc';

  a2i_IPADDRESS_procname = 'a2i_IPADDRESS';
  a2i_IPADDRESS_NC_procname = 'a2i_IPADDRESS_NC';
//  TIdC_INT X509V3_NAME_from_section(X509_NAME *nm; STACK_OF(CONF_VALUE) *dn_sk; TIdC_ULONG chtype);

  X509_POLICY_NODE_print_procname = 'X509_POLICY_NODE_print';
//  DEFINE_STACK_OF(X509_POLICY_NODE)

  (*
   * Utilities to construct and extract values from RFC3779 extensions,
   * since some of the encodings (particularly for IP address prefixes
   * and ranges) are a bit tedious to work with directly.
   *)
  //function X509v3_asid_add_inherit(asid: PASIdentifiers; which: TIdC_INT): TIdC_INT;
  //function X509v3_asid_add_id_or_range(asid: PASIdentifiers; which: TIdC_INT; min: PASN1_INTEGER; max: PASN1_INTEGER): TIdC_INT;
  //function X509v3_addr_add_inherit(address: PIPAddrBlocks; const afi: TIdC_UINT; const safi: PIdC_UINT): TIdC_INT;
  //function X509v3_addr_add_prefix(address: PIPAddrBlocks; const afi: TIdC_UINT; const safi: PIdC_UINT; a: PByte; const prefixlen: TIdC_INT): TIdC_INT;
  //function X509v3_addr_add_range(address: PIPAddrBlocks; const afi: TIdC_UINT; const safi: PIdC_UINT; min: PByte; max: PByte): TIdC_INT;
  //function X509v3_addr_get_afi(const f: PIPAddressFamily): TIdC_UINT;
  X509v3_addr_get_range_procname = 'X509v3_addr_get_range';

  (*
   * Canonical forms.
   *)
  //function X509v3_asid_is_canonical(asid: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_is_canonical(address: PIPAddrBlocks): TIdC_INT;
  //function X509v3_asid_canonize(asid: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_canonize(address: PIPAddrBlocks): TIdC_INT;

  (*
   * Tests for inheritance and containment.
   *)
  //function X509v3_asid_inherits(asid: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_inherits(address: PIPAddrBlocks): TIdC_INT;
  //function X509v3_asid_subset(a: PASIdentifiers; b: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_subset(a: PIPAddrBlocks; b: PIPAddrBlocks): TIdC_INT;

  (*
   * Check whether RFC 3779 extensions nest properly in chains.
   *)
  X509v3_asid_validate_path_procname = 'X509v3_asid_validate_path';
  X509v3_addr_validate_path_procname = 'X509v3_addr_validate_path';
//  TIdC_INT X509v3_asid_validate_resource_set(STACK_OF(X509) *chain; ASIdentifiers *ext; TIdC_INT allow_inheritance);
//  TIdC_INT X509v3_addr_validate_resource_set(STACK_OF(X509) *chain; IPAddrBlocks *ext; TIdC_INT allow_inheritance);


//  DEFINE_STACK_OF(ASN1_STRING)

  (*
   * Admission Syntax
   *)
  NAMING_AUTHORITY_get0_authorityId_procname = 'NAMING_AUTHORITY_get0_authorityId';
  NAMING_AUTHORITY_get0_authorityURL_procname = 'NAMING_AUTHORITY_get0_authorityURL';
  NAMING_AUTHORITY_get0_authorityText_procname = 'NAMING_AUTHORITY_get0_authorityText';
  NAMING_AUTHORITY_set0_authorityId_procname = 'NAMING_AUTHORITY_set0_authorityId';
  NAMING_AUTHORITY_set0_authorityURL_procname = 'NAMING_AUTHORITY_set0_authorityURL';
  NAMING_AUTHORITY_set0_authorityText_procname = 'NAMING_AUTHORITY_set0_authorityText';

  ADMISSION_SYNTAX_get0_admissionAuthority_procname = 'ADMISSION_SYNTAX_get0_admissionAuthority';
  ADMISSION_SYNTAX_set0_admissionAuthority_procname = 'ADMISSION_SYNTAX_set0_admissionAuthority';
//  const STACK_OF(ADMISSIONS) *ADMISSION_SYNTAX_get0_contentsOfAdmissions(const as_: ADMISSION_SYNTAX);
//  void ADMISSION_SYNTAX_set0_contentsOfAdmissions(as_: ADMISSION_SYNTAX; STACK_OF(ADMISSIONS) *a);
  ADMISSIONS_get0_admissionAuthority_procname = 'ADMISSIONS_get0_admissionAuthority';
  ADMISSIONS_set0_admissionAuthority_procname = 'ADMISSIONS_set0_admissionAuthority';
  ADMISSIONS_get0_namingAuthority_procname = 'ADMISSIONS_get0_namingAuthority';
  ADMISSIONS_set0_namingAuthority_procname = 'ADMISSIONS_set0_namingAuthority';
  //function ADMISSIONS_get0_professionInfos(const a: PADMISSIONS): PPROFESSION_INFOS;
  //procedure ADMISSIONS_set0_professionInfos(a: PADMISSIONS; _pi: PPROFESSION_INFOS);
  PROFESSION_INFO_get0_addProfessionInfo_procname = 'PROFESSION_INFO_get0_addProfessionInfo';
  PROFESSION_INFO_set0_addProfessionInfo_procname = 'PROFESSION_INFO_set0_addProfessionInfo';
  PROFESSION_INFO_get0_namingAuthority_procname = 'PROFESSION_INFO_get0_namingAuthority';
  PROFESSION_INFO_set0_namingAuthority_procname = 'PROFESSION_INFO_set0_namingAuthority';
//  const STACK_OF(ASN1_STRING) *PROFESSION_INFO_get0_professionItems(const _pi: PPROFESSION_INFO);
//  void PROFESSION_INFO_set0_professionItems(_pi: PPROFESSION_INFO; STACK_OF(ASN1_STRING) *as);
//  const STACK_OF(ASN1_OBJECT) *PROFESSION_INFO_get0_professionOIDs(const _pi: PPROFESSION_INFO);
//  void PROFESSION_INFO_set0_professionOIDs(_pi: PPROFESSION_INFO; STACK_OF(ASN1_OBJECT) *po);
  PROFESSION_INFO_get0_registrationNumber_procname = 'PROFESSION_INFO_get0_registrationNumber';
  PROFESSION_INFO_set0_registrationNumber_procname = 'PROFESSION_INFO_set0_registrationNumber';

  {$I TaurusTLSNoRetValOff.inc}
  {$IFNDEF _FIXINSIGHT_}
function  ERR_GENERAL_NAME_cmp(a: PGENERAL_NAME; b: PGENERAL_NAME): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(GENERAL_NAME_cmp_procname);
end;



//  ASN1_BIT_STRING *v2i_ASN1_BIT_STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; STACK_OF(CONF_VALUE) *nval);
//  STACK_OF(CONF_VALUE) *i2v_ASN1_BIT_STRING(method: PX509V3_EXT_METHOD; ASN1_BIT_STRING *bits; STACK_OF(CONF_VALUE) *extlist);
  //function i2s_ASN1_IA5STRING(method: PX509V3_EXT_METHOD; ia5: PASN1_IA5STRING): PIdAnsiChar;
  //function s2i_ASN1_IA5STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; const _str: PIdAnsiChar): PASN1_IA5STRING;

//  STACK_OF(CONF_VALUE) *i2v_GENERAL_NAME(method: PX509V3_EXT_METHOD; gen: PGENERAL_NAME; STACK_OF(CONF_VALUE) *ret);
function  ERR_GENERAL_NAME_print(out_: PBIO; gen: PGENERAL_NAME): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(GENERAL_NAME_print_procname);
end;



//  DECLARE_ASN1_FUNCTIONS(GENERAL_NAMES)

//  STACK_OF(CONF_VALUE) *i2v_GENERAL_NAMES(method: PX509V3_EXT_METHOD, GENERAL_NAMES *gen, STACK_OF(CONF_VALUE) *extlist);
//  GENERAL_NAMES *v2i_GENERAL_NAMES(const method: PX509V3_EXT_METHOD, ctx: PX509V3_CTX, STACK_OF(CONF_VALUE) *nval);

//  DECLARE_ASN1_FUNCTIONS(OTHERNAME)
//  DECLARE_ASN1_FUNCTIONS(EDIPARTYNAME)
function  ERR_OTHERNAME_cmp(a: POTHERNAME; b: POTHERNAME): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(OTHERNAME_cmp_procname);
end;


procedure  ERR_GENERAL_NAME_set0_value(a: PGENERAL_NAME; type_: TIdC_INT; value: Pointer);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(GENERAL_NAME_set0_value_procname);
end;


function  ERR_GENERAL_NAME_get0_value(const a: PGENERAL_NAME; ptype: PIdC_INT): Pointer;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(GENERAL_NAME_get0_value_procname);
end;


function  ERR_GENERAL_NAME_set0_othername(gen: PGENERAL_NAME; oid: PASN1_OBJECT; value: PASN1_TYPE): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(GENERAL_NAME_set0_othername_procname);
end;


function  ERR_GENERAL_NAME_get0_otherName(const gen: PGENERAL_NAME; poid: PPASN1_OBJECT; pvalue: PPASN1_TYPE): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(GENERAL_NAME_get0_otherName_procname);
end;

procedure ERR_GENERAL_NAMES_free(a : PGENERAL_NAMES); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(GENERAL_NAMES_free_procname);
end;

  //function i2s_ASN1_OCTET_STRING(method: PX509V3_EXT_METHOD; const ia5: PASN1_OCTET_STRING): PIdAnsiChar;
  //function s2i_ASN1_OCTET_STRING(method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; const _str: PIdAnsiChar): PASN1_OCTET_STRING;

//  DECLARE_ASN1_FUNCTIONS(EXTENDED_KEY_USAGE)
function  ERR_i2a_ACCESS_DESCRIPTION(bp: PBIO; const a: PACCESS_DESCRIPTION): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(i2a_ACCESS_DESCRIPTION_procname);
end;



//  DECLARE_ASN1_ALLOC_FUNCTIONS(TLS_FEATURE)

//  DECLARE_ASN1_FUNCTIONS(CERTIFICATEPOLICIES)
//  DECLARE_ASN1_FUNCTIONS(POLICYINFO)
//  DECLARE_ASN1_FUNCTIONS(POLICYQUALINFO)
//  DECLARE_ASN1_FUNCTIONS(USERNOTICE)
//  DECLARE_ASN1_FUNCTIONS(NOTICEREF)

//  DECLARE_ASN1_FUNCTIONS(CRL_DIST_POINTS)
//  DECLARE_ASN1_FUNCTIONS(DIST_POINT)
//  DECLARE_ASN1_FUNCTIONS(DIST_POINT_NAME)
//  DECLARE_ASN1_FUNCTIONS(ISSUING_DIST_POINT)

function  ERR_DIST_POINT_set_dpname(dpn: PDIST_POINT_NAME; iname: PX509_NAME): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(DIST_POINT_set_dpname_procname);
end;



function  ERR_NAME_CONSTRAINTS_check(x: PX509; nc: PNAME_CONSTRAINTS): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NAME_CONSTRAINTS_check_procname);
end;


function  ERR_NAME_CONSTRAINTS_check_CN(x: PX509; nc: PNAME_CONSTRAINTS): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NAME_CONSTRAINTS_check_CN_procname);
end;


procedure ERR_BASIC_CONSTRAINTS_free(bc : PBASIC_CONSTRAINTS); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(BASIC_CONSTRAINTS_free_procname);
end;

procedure ERR_AUTHORITY_KEYID_free(id : PAUTHORITY_KEYID); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(AUTHORITY_KEYID_free_procname);
end;

//  DECLARE_ASN1_FUNCTIONS(ACCESS_DESCRIPTION)
//  DECLARE_ASN1_FUNCTIONS(AUTHORITY_INFO_ACCESS)

//  DECLARE_ASN1_ITEM(POLICY_MAPPING)
//  DECLARE_ASN1_ALLOC_FUNCTIONS(POLICY_MAPPING)
//  DECLARE_ASN1_ITEM(POLICY_MAPPINGS)

//  DECLARE_ASN1_ITEM(GENERAL_SUBTREE)
//  DECLARE_ASN1_ALLOC_FUNCTIONS(GENERAL_SUBTREE)

//  DECLARE_ASN1_ITEM(NAME_CONSTRAINTS)
//  DECLARE_ASN1_ALLOC_FUNCTIONS(NAME_CONSTRAINTS)

//  DECLARE_ASN1_ALLOC_FUNCTIONS(POLICY_CONSTRAINTS)
//  DECLARE_ASN1_ITEM(POLICY_CONSTRAINTS)

  //function a2i_GENERAL_NAME(out_: PGENERAL_NAME; const method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; TIdC_INT gen_type; const value: PIdAnsiChar; is_nc: TIdC_INT): GENERAL_NAME;

  //function v2i_GENERAL_NAME(const method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; cnf: PCONF_VALUE): PGENERAL_NAME;
  //function v2i_GENERAL_NAME_ex(out_: PGENERAL_NAME; const method: PX509V3_EXT_METHOD; ctx: PX509V3_CTX; cnf: PCONF_VALUE; is_nc: TIdC_INT): PGENERAL_NAME;
  //procedure X509V3_conf_free(_val: PCONF_VALUE);

function  ERR_X509V3_EXT_nconf_nid(conf: PCONF; ctx: PX509V3_CTX; ext_nid: TIdC_INT; const value: PIdAnsiChar): PX509_EXTENSION;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_nconf_nid_procname);
end;


function  ERR_X509V3_EXT_nconf(conf: PCONF; ctx: PX509V3_CTX; const name: PIdAnsiChar; const value: PIdAnsiChar): PX509_EXTENSION;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_nconf_procname);
end;


//  TIdC_INT X509V3_EXT_add_nconf_sk(conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; STACK_OF(X509_EXTENSION) **sk);
function  ERR_X509V3_EXT_add_nconf(conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; cert: PX509): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_add_nconf_procname);
end;


function  ERR_X509V3_EXT_REQ_add_nconf(conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; req: PX509_REQ): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_REQ_add_nconf_procname);
end;


function  ERR_X509V3_EXT_CRL_add_nconf(conf: PCONF; ctx: PX509V3_CTX; const section: PIdAnsiChar; crl: PX509_CRL): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_CRL_add_nconf_procname);
end;



function  ERR_X509V3_EXT_conf_nid(conf: Pointer; ctx: PX509V3_CTX; ext_nid: TIdC_INT; const value: PIdAnsiChar): PX509_EXTENSION;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_conf_nid_procname);
end;


//  X509_EXTENSION *X509V3_EXT_conf_nid(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; ext_nid: TIdC_INT; const value: PIdAnsiChar);
function  ERR_X509V3_EXT_conf(conf: Pointer; ctx: PX509V3_CTX; const name: PIdAnsiChar; const value: PIdAnsiChar): PX509_EXTENSION;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_conf_procname);
end;


//  X509_EXTENSION *X509V3_EXT_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const name: PIdAnsiChar; const value: PIdAnsiChar);
function  ERR_X509V3_EXT_add_conf(conf: Pointer; ctx: PX509V3_CTX; const section: PIdAnsiChar; cert: PX509): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_add_conf_procname);
end;


//  TIdC_INT X509V3_EXT_add_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const section: PIdAnsiChar; cert: PX509);
function  ERR_X509V3_EXT_REQ_add_conf(conf: Pointer; ctx: PX509V3_CTX; const section: PIdAnsiChar; req: PX509_REQ): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_REQ_add_conf_procname);
end;


//  TIdC_INT X509V3_EXT_REQ_add_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const section: PIdAnsiChar; req: PX509_REQ);
function  ERR_X509V3_EXT_CRL_add_conf(conf: Pointer; ctx: PX509V3_CTX; const section: PIdAnsiChar; crl: PX509_CRL): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_CRL_add_conf_procname);
end;


//  TIdC_INT X509V3_EXT_CRL_add_conf(LHASH_OF(CONF_VALUE) *conf; ctx: PX509V3_CTX; const section: PIdAnsiChar; crl: PX509_CRL);

//  TIdC_INT X509V3_add_value_bool_nf(const name: PIdAnsiChar; TIdC_INT asn1_bool; STACK_OF(CONF_VALUE) **extlist);
  //function X509V3_get_value_bool(const value: PCONF_VALUE; asn1_bool: PIdC_INT): TIdC_INT;
  //function X509V3_get_value_int(const value: PCONF_VALUE; aint: PPASN1_INTEGER): TIdC_INT;
procedure  ERR_X509V3_set_nconf(ctx: PX509V3_CTX; conf: PCONF);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_set_nconf_procname);
end;


//  void X509V3_set_conf_lhash(ctx: PX509V3_CTX; LHASH_OF(CONF_VALUE) *lhash);

function  ERR_X509V3_get_string(ctx: PX509V3_CTX; const name: PIdAnsiChar; const section: PIdAnsiChar): PIdAnsiChar;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_get_string_procname);
end;


//  STACK_OF(CONF_VALUE) *X509V3_get_section(ctx: PX509V3_CTX; const section: PIdAnsiChar);
procedure  ERR_X509V3_string_free(ctx: PX509V3_CTX; _str: PIdAnsiChar);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_string_free_procname);
end;


//  void X509V3_section_free(ctx: PX509V3_CTX; STACK_OF(CONF_VALUE) *section);
procedure  ERR_X509V3_set_ctx(ctx: PX509V3_CTX; issuer: PX509; subject: PX509; req: PX509_REQ; crl: PX509_CRL; flags: TIdC_INT);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_set_ctx_procname);
end;



//  TIdC_INT X509V3_add_value(const name: PIdAnsiChar; const value: PIdAnsiChar; STACK_OF(CONF_VALUE) **extlist);
//  TIdC_INT X509V3_add_value_uPIdAnsiChar(const name: PIdAnsiChar; const Byte *value; STACK_OF(CONF_VALUE) **extlist);
//  TIdC_INT X509V3_add_value_bool(const name: PIdAnsiChar; TIdC_INT asn1_bool; STACK_OF(CONF_VALUE) **extlist);
//  TIdC_INT X509V3_add_value_int(const name: PIdAnsiChar; const aint: PASN1_INTEGER; STACK_OF(CONF_VALUE) **extlist);
  //function i2s_ASN1_INTEGER(meth: PX509V3_EXT_METHOD; const aint: PASN1_INTEGER): PIdAnsiChar;
  //function s2i_ASN1_INTEGER(meth: PX509V3_EXT_METHOD; const value: PIdAnsiChar): PASN1_INTEGER;
  //function i2s_ASN1_ENUMERATED(meth: PX509V3_EXT_METHOD; const aint: PASN1_ENUMERATED): PIdAnsiChar;
  //function i2s_ASN1_ENUMERATED_TABLE(meth: PX509V3_EXT_METHOD; const aint: PASN1_ENUMERATED): PIdAnsiChar;
  //function X509V3_EXT_add(ext: PX509V3_EXT_METHOD): TIdC_INT;
  //function X509V3_EXT_add_list(extlist: PX509V3_EXT_METHOD): TIdC_INT;
function  ERR_X509V3_EXT_add_alias(nid_to: TIdC_INT; nid_from: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_add_alias_procname);
end;


procedure  ERR_X509V3_EXT_cleanup;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_cleanup_procname);
end;



  //function X509V3_EXT_get(ext: PX509_EXTENSION): PX509V3_EXT_METHOD;
  //function X509V3_EXT_get_nid(nid: TIdC_INT): PX509V3_EXT_METHOD;
function  ERR_X509V3_add_standard_extensions: TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_add_standard_extensions_procname);
end;


//  STACK_OF(CONF_VALUE) *X509V3_parse_list(const line: PIdAnsiChar);
function  ERR_X509V3_EXT_d2i(ext: PX509_EXTENSION): Pointer;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_d2i_procname);
end;


//  void *X509V3_get_d2i(const STACK_OF(X509_EXTENSION) *x; nid: TIdC_INT; TIdC_INT *crit; TIdC_INT *idx);

function  ERR_X509V3_EXT_i2d(ext_nid: TIdC_INT; crit: TIdC_INT; ext_struc: Pointer): PX509_EXTENSION;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_i2d_procname);
end;


//  TIdC_INT X509V3_add1_i2d(STACK_OF(X509_EXTENSION) **x; nid: TIdC_INT; value: Pointer; crit: TIdC_INT; TIdC_ULONG flags);

//  void X509V3_EXT_val_prn(out_: PBIO; STACK_OF(CONF_VALUE) *val; indent: TIdC_INT; TIdC_INT ml);
function  ERR_X509V3_EXT_print(out_: PBIO; ext: PX509_EXTENSION; flag: TIdC_ULONG; indent: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509V3_EXT_print_procname);
end;


//  TIdC_INT X509V3_extensions_print(out_: PBIO; const PIdAnsiChar *title; const STACK_OF(X509_EXTENSION) *exts; flag: TIdC_ULONG; indent: TIdC_INT);

function  ERR_X509_check_ca(x: PX509): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_check_ca_procname);
end;


function  ERR_X509_check_purpose(x: PX509; id: TIdC_INT; ca: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_check_purpose_procname);
end;


function  ERR_X509_supported_extension(ex: PX509_EXTENSION): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_supported_extension_procname);
end;


function  ERR_X509_PURPOSE_set(p: PIdC_INT; purpose: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PURPOSE_set_procname);
end;


function  ERR_X509_check_issued(issuer: PX509; subject: PX509): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_check_issued_procname);
end;


function  ERR_X509_check_akid(issuer: PX509; akid: PAUTHORITY_KEYID): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_check_akid_procname);
end;


procedure  ERR_X509_set_proxy_flag(x: PX509);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_set_proxy_flag_procname);
end;


procedure  ERR_X509_set_proxy_pathlen(x: PX509; l: TIdC_LONG);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_set_proxy_pathlen_procname);
end;


function  ERR_X509_get_proxy_pathlen(x: PX509): TIdC_LONG;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_proxy_pathlen_procname);
end;



function  ERR_X509_get_extension_flags(x: PX509): TIdC_UINT32;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_extension_flags_procname);
end;


function  ERR_X509_get_key_usage(x: PX509): TIdC_UINT32;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_key_usage_procname);
end;


function  ERR_X509_get_extended_key_usage(x: PX509): TIdC_UINT32;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get_extended_key_usage_procname);
end;


function  ERR_X509_get0_subject_key_id(x: PX509): PASN1_OCTET_STRING;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_subject_key_id_procname);
end;


function  ERR_X509_get0_authority_key_id(x: PX509): PASN1_OCTET_STRING;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_authority_key_id_procname);
end;


function ERR_X509_get0_authority_issuer(x: PX509): PGENERAL_NAMES; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_authority_issuer_procname);
end;

function  ERR_X509_get0_authority_serial(x: PX509): PASN1_INTEGER; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get0_authority_serial_procname);
end;



function  ERR_X509_PURPOSE_get_count: TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PURPOSE_get_count_procname);
end;


function  ERR_X509_PURPOSE_get0(idx: TIdC_INT): PX509_PURPOSE;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PURPOSE_get0_procname);
end;


function  ERR_X509_PURPOSE_get_by_sname(const sname: PIdAnsiChar): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PURPOSE_get_by_sname_procname);
end;


function  ERR_X509_PURPOSE_get_by_id(id: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PURPOSE_get_by_id_procname);
end;


//  TIdC_INT X509_PURPOSE_add(id: TIdC_INT, TIdC_INT trust, flags: TIdC_INT, TIdC_INT (*ck) (const X509_PURPOSE *, const X509 *, TIdC_INT), const name: PIdAnsiChar, const sname: PIdAnsiChar, void *arg);
function  ERR_X509_PURPOSE_get0_name(const xp: PX509_PURPOSE): PIdAnsiChar;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PURPOSE_get0_name_procname);
end;


function  ERR_X509_PURPOSE_get0_sname(const xp: PX509_PURPOSE): PIdAnsiChar;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PURPOSE_get0_sname_procname);
end;


function  ERR_X509_PURPOSE_get_trust(const xp: PX509_PURPOSE): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PURPOSE_get_trust_procname);
end;


procedure  ERR_X509_PURPOSE_cleanup;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PURPOSE_cleanup_procname);
end;


function  ERR_X509_PURPOSE_get_id(const v1: PX509_PURPOSE): TIdC_INT; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_PURPOSE_get_id_procname);
end;

function ERR_X509_get1_email(x: PX509) : PSTACK_OF_OPENSSL_STRING; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get1_email_procname);
end;

function ERR_X509_REQ_get1_email( x : PX509_REQ) : PSTACK_OF_OPENSSL_STRING; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_REQ_get1_email_procname);
end;

procedure ERR_X509_email_free(sk : PSTACK_OF_OPENSSL_STRING); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_email_free_procname);
end;

function ERR_X509_get1_ocsp(x: PX509) : PSTACK_OF_OPENSSL_STRING; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_get1_ocsp_procname);
end;

function  ERR_X509_check_host(x: PX509; const chk: PIdAnsiChar; chklen: TIdC_SIZET; flags: TIdC_UINT; peername: PPIdAnsiChar): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_check_host_procname);
end;


function  ERR_X509_check_email(x: PX509; const chk: PIdAnsiChar; chklen: TIdC_SIZET; flags: TIdC_UINT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_check_email_procname);
end;


function  ERR_X509_check_ip(x: PX509; const chk: PByte; chklen: TIdC_SIZET; flags: TIdC_UINT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_check_ip_procname);
end;


function  ERR_X509_check_ip_asc(x: PX509; const ipasc: PIdAnsiChar; flags: TIdC_UINT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_check_ip_asc_procname);
end;



function  ERR_a2i_IPADDRESS(const ipasc: PIdAnsiChar): PASN1_OCTET_STRING;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(a2i_IPADDRESS_procname);
end;


function  ERR_a2i_IPADDRESS_NC(const ipasc: PIdAnsiChar): PASN1_OCTET_STRING;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(a2i_IPADDRESS_NC_procname);
end;


//  TIdC_INT X509V3_NAME_from_section(X509_NAME *nm; STACK_OF(CONF_VALUE) *dn_sk; TIdC_ULONG chtype);

procedure  ERR_X509_POLICY_NODE_print(out_: PBIO; node: PX509_POLICY_NODE; indent: TIdC_INT);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509_POLICY_NODE_print_procname);
end;


//  DEFINE_STACK_OF(X509_POLICY_NODE)

  (*
   * Utilities to construct and extract values from RFC3779 extensions,
   * since some of the encodings (particularly for IP address prefixes
   * and ranges) are a bit tedious to work with directly.
   *)
  //function X509v3_asid_add_inherit(asid: PASIdentifiers; which: TIdC_INT): TIdC_INT;
  //function X509v3_asid_add_id_or_range(asid: PASIdentifiers; which: TIdC_INT; min: PASN1_INTEGER; max: PASN1_INTEGER): TIdC_INT;
  //function X509v3_addr_add_inherit(address: PIPAddrBlocks; const afi: TIdC_UINT; const safi: PIdC_UINT): TIdC_INT;
  //function X509v3_addr_add_prefix(address: PIPAddrBlocks; const afi: TIdC_UINT; const safi: PIdC_UINT; a: PByte; const prefixlen: TIdC_INT): TIdC_INT;
  //function X509v3_addr_add_range(address: PIPAddrBlocks; const afi: TIdC_UINT; const safi: PIdC_UINT; min: PByte; max: PByte): TIdC_INT;
  //function X509v3_addr_get_afi(const f: PIPAddressFamily): TIdC_UINT;
function  ERR_X509v3_addr_get_range(aor: PIPAddressOrRange; const afi: TIdC_UINT; min: PByte; max: Byte; const _length: TIdC_INT): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_addr_get_range_procname);
end;



  (*
   * Canonical forms.
   *)
  //function X509v3_asid_is_canonical(asid: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_is_canonical(address: PIPAddrBlocks): TIdC_INT;
  //function X509v3_asid_canonize(asid: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_canonize(address: PIPAddrBlocks): TIdC_INT;

  (*
   * Tests for inheritance and containment.
   *)
  //function X509v3_asid_inherits(asid: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_inherits(address: PIPAddrBlocks): TIdC_INT;
  //function X509v3_asid_subset(a: PASIdentifiers; b: PASIdentifiers): TIdC_INT;
  //function X509v3_addr_subset(a: PIPAddrBlocks; b: PIPAddrBlocks): TIdC_INT;

  (*
   * Check whether RFC 3779 extensions nest properly in chains.
   *)
function  ERR_X509v3_asid_validate_path(v1: PX509_STORE_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_asid_validate_path_procname);
end;


function  ERR_X509v3_addr_validate_path(v1: PX509_STORE_CTX): TIdC_INT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(X509v3_addr_validate_path_procname);
end;


//  TIdC_INT X509v3_asid_validate_resource_set(STACK_OF(X509) *chain; ASIdentifiers *ext; TIdC_INT allow_inheritance);
//  TIdC_INT X509v3_addr_validate_resource_set(STACK_OF(X509) *chain; IPAddrBlocks *ext; TIdC_INT allow_inheritance);


//  DEFINE_STACK_OF(ASN1_STRING)

  (*
   * Admission Syntax
   *)
function  ERR_NAMING_AUTHORITY_get0_authorityId(const n: PNAMING_AUTHORITY): PASN1_OBJECT;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NAMING_AUTHORITY_get0_authorityId_procname);
end;


function  ERR_NAMING_AUTHORITY_get0_authorityURL(const n: PNAMING_AUTHORITY): PASN1_IA5STRING;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NAMING_AUTHORITY_get0_authorityURL_procname);
end;


function  ERR_NAMING_AUTHORITY_get0_authorityText(const n: PNAMING_AUTHORITY): PASN1_STRING;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NAMING_AUTHORITY_get0_authorityText_procname);
end;


procedure  ERR_NAMING_AUTHORITY_set0_authorityId(n: PNAMING_AUTHORITY; namingAuthorityId: PASN1_OBJECT);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NAMING_AUTHORITY_set0_authorityId_procname);
end;


procedure  ERR_NAMING_AUTHORITY_set0_authorityURL(n: PNAMING_AUTHORITY; namingAuthorityUrl: PASN1_IA5STRING);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NAMING_AUTHORITY_set0_authorityURL_procname);
end;


procedure  ERR_NAMING_AUTHORITY_set0_authorityText(n: PNAMING_AUTHORITY; namingAuthorityText: PASN1_STRING);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(NAMING_AUTHORITY_set0_authorityText_procname);
end;



function  ERR_ADMISSION_SYNTAX_get0_admissionAuthority(const as_: ADMISSION_SYNTAX): PGENERAL_NAME;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ADMISSION_SYNTAX_get0_admissionAuthority_procname);
end;


procedure  ERR_ADMISSION_SYNTAX_set0_admissionAuthority(as_: ADMISSION_SYNTAX; aa: PGENERAL_NAME);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ADMISSION_SYNTAX_set0_admissionAuthority_procname);
end;


//  const STACK_OF(ADMISSIONS) *ADMISSION_SYNTAX_get0_contentsOfAdmissions(const as_: ADMISSION_SYNTAX);
//  void ADMISSION_SYNTAX_set0_contentsOfAdmissions(as_: ADMISSION_SYNTAX; STACK_OF(ADMISSIONS) *a);
function  ERR_ADMISSIONS_get0_admissionAuthority(const a: PADMISSIONS): PGENERAL_NAME;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ADMISSIONS_get0_admissionAuthority_procname);
end;


procedure  ERR_ADMISSIONS_set0_admissionAuthority(a: PADMISSIONS; aa: PGENERAL_NAME);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ADMISSIONS_set0_admissionAuthority_procname);
end;


function  ERR_ADMISSIONS_get0_namingAuthority(const a: PADMISSIONS): PNAMING_AUTHORITY;  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ADMISSIONS_get0_namingAuthority_procname);
end;


procedure  ERR_ADMISSIONS_set0_namingAuthority(a: PADMISSIONS; na: PNAMING_AUTHORITY);  cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(ADMISSIONS_set0_namingAuthority_procname);
end;


  //function ADMISSIONS_get0_professionInfos(const a: PADMISSIONS): PPROFESSION_INFOS;
  //procedure ADMISSIONS_set0_professionInfos(a: PADMISSIONS; _pi: PPROFESSION_INFOS);
function  ERR_PROFESSION_INFO_get0_addProfessionInfo(const _pi: PPROFESSION_INFO): PASN1_OCTET_STRING; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PROFESSION_INFO_get0_addProfessionInfo_procname);
end;


procedure  ERR_PROFESSION_INFO_set0_addProfessionInfo(_pi: PPROFESSION_INFO; aos: PASN1_OCTET_STRING); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PROFESSION_INFO_set0_addProfessionInfo_procname);
end;


function  ERR_PROFESSION_INFO_get0_namingAuthority(const _pi: PPROFESSION_INFO): PNAMING_AUTHORITY; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PROFESSION_INFO_get0_namingAuthority_procname);
end;


procedure  ERR_PROFESSION_INFO_set0_namingAuthority(_pi: PPROFESSION_INFO; na: PNAMING_AUTHORITY); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PROFESSION_INFO_set0_namingAuthority_procname);
end;


//  const STACK_OF(ASN1_STRING) *PROFESSION_INFO_get0_professionItems(const _pi: PPROFESSION_INFO);
//  void PROFESSION_INFO_set0_professionItems(_pi: PPROFESSION_INFO; STACK_OF(ASN1_STRING) *as);
//  const STACK_OF(ASN1_OBJECT) *PROFESSION_INFO_get0_professionOIDs(const _pi: PPROFESSION_INFO);
//  void PROFESSION_INFO_set0_professionOIDs(_pi: PPROFESSION_INFO; STACK_OF(ASN1_OBJECT) *po);
function  ERR_PROFESSION_INFO_get0_registrationNumber(const _pi: PPROFESSION_INFO): PASN1_PRINTABLESTRING; cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PROFESSION_INFO_get0_registrationNumber_procname);
end;


procedure  ERR_PROFESSION_INFO_set0_registrationNumber(_pi: PPROFESSION_INFO; rn: PASN1_PRINTABLESTRING); cdecl;
begin
  ETaurusTLSAPIFunctionNotPresent.RaiseException(PROFESSION_INFO_set0_registrationNumber_procname);
end;


  {$I TaurusTLSNoRetValOn.inc}

  {$I TaurusTLSUnusedParamOff.inc}

procedure Load(const ADllHandle: TIdLibHandle; LibVersion: TIdC_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;

begin
  GENERAL_NAME_cmp := LoadLibFunction(ADllHandle, GENERAL_NAME_cmp_procname);
  FuncLoadError := not assigned(GENERAL_NAME_cmp);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAME_cmp_allownil)}
    GENERAL_NAME_cmp := ERR_GENERAL_NAME_cmp;
    {$ifend}
    {$if declared(GENERAL_NAME_cmp_introduced)}
    if LibVersion < GENERAL_NAME_cmp_introduced then
    begin
      {$if declared(FC_GENERAL_NAME_cmp)}
      GENERAL_NAME_cmp := FC_GENERAL_NAME_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAME_cmp_removed)}
    if GENERAL_NAME_cmp_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAME_cmp)}
      GENERAL_NAME_cmp := _GENERAL_NAME_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAME_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAME_cmp');
    {$ifend}
  end;


  GENERAL_NAME_print := LoadLibFunction(ADllHandle, GENERAL_NAME_print_procname);
  FuncLoadError := not assigned(GENERAL_NAME_print);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAME_print_allownil)}
    GENERAL_NAME_print := ERR_GENERAL_NAME_print;
    {$ifend}
    {$if declared(GENERAL_NAME_print_introduced)}
    if LibVersion < GENERAL_NAME_print_introduced then
    begin
      {$if declared(FC_GENERAL_NAME_print)}
      GENERAL_NAME_print := FC_GENERAL_NAME_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAME_print_removed)}
    if GENERAL_NAME_print_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAME_print)}
      GENERAL_NAME_print := _GENERAL_NAME_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAME_print_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAME_print');
    {$ifend}
  end;


  OTHERNAME_cmp := LoadLibFunction(ADllHandle, OTHERNAME_cmp_procname);
  FuncLoadError := not assigned(OTHERNAME_cmp);
  if FuncLoadError then
  begin
    {$if not defined(OTHERNAME_cmp_allownil)}
    OTHERNAME_cmp := ERR_OTHERNAME_cmp;
    {$ifend}
    {$if declared(OTHERNAME_cmp_introduced)}
    if LibVersion < OTHERNAME_cmp_introduced then
    begin
      {$if declared(FC_OTHERNAME_cmp)}
      OTHERNAME_cmp := FC_OTHERNAME_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(OTHERNAME_cmp_removed)}
    if OTHERNAME_cmp_removed <= LibVersion then
    begin
      {$if declared(_OTHERNAME_cmp)}
      OTHERNAME_cmp := _OTHERNAME_cmp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(OTHERNAME_cmp_allownil)}
    if FuncLoadError then
      AFailed.Add('OTHERNAME_cmp');
    {$ifend}
  end;


  GENERAL_NAME_set0_value := LoadLibFunction(ADllHandle, GENERAL_NAME_set0_value_procname);
  FuncLoadError := not assigned(GENERAL_NAME_set0_value);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAME_set0_value_allownil)}
    GENERAL_NAME_set0_value := ERR_GENERAL_NAME_set0_value;
    {$ifend}
    {$if declared(GENERAL_NAME_set0_value_introduced)}
    if LibVersion < GENERAL_NAME_set0_value_introduced then
    begin
      {$if declared(FC_GENERAL_NAME_set0_value)}
      GENERAL_NAME_set0_value := FC_GENERAL_NAME_set0_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAME_set0_value_removed)}
    if GENERAL_NAME_set0_value_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAME_set0_value)}
      GENERAL_NAME_set0_value := _GENERAL_NAME_set0_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAME_set0_value_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAME_set0_value');
    {$ifend}
  end;


  GENERAL_NAME_get0_value := LoadLibFunction(ADllHandle, GENERAL_NAME_get0_value_procname);
  FuncLoadError := not assigned(GENERAL_NAME_get0_value);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAME_get0_value_allownil)}
    GENERAL_NAME_get0_value := ERR_GENERAL_NAME_get0_value;
    {$ifend}
    {$if declared(GENERAL_NAME_get0_value_introduced)}
    if LibVersion < GENERAL_NAME_get0_value_introduced then
    begin
      {$if declared(FC_GENERAL_NAME_get0_value)}
      GENERAL_NAME_get0_value := FC_GENERAL_NAME_get0_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAME_get0_value_removed)}
    if GENERAL_NAME_get0_value_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAME_get0_value)}
      GENERAL_NAME_get0_value := _GENERAL_NAME_get0_value;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAME_get0_value_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAME_get0_value');
    {$ifend}
  end;


  GENERAL_NAME_set0_othername := LoadLibFunction(ADllHandle, GENERAL_NAME_set0_othername_procname);
  FuncLoadError := not assigned(GENERAL_NAME_set0_othername);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAME_set0_othername_allownil)}
    GENERAL_NAME_set0_othername := ERR_GENERAL_NAME_set0_othername;
    {$ifend}
    {$if declared(GENERAL_NAME_set0_othername_introduced)}
    if LibVersion < GENERAL_NAME_set0_othername_introduced then
    begin
      {$if declared(FC_GENERAL_NAME_set0_othername)}
      GENERAL_NAME_set0_othername := FC_GENERAL_NAME_set0_othername;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAME_set0_othername_removed)}
    if GENERAL_NAME_set0_othername_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAME_set0_othername)}
      GENERAL_NAME_set0_othername := _GENERAL_NAME_set0_othername;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAME_set0_othername_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAME_set0_othername');
    {$ifend}
  end;


  GENERAL_NAME_get0_otherName := LoadLibFunction(ADllHandle, GENERAL_NAME_get0_otherName_procname);
  FuncLoadError := not assigned(GENERAL_NAME_get0_otherName);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAME_get0_otherName_allownil)}
    GENERAL_NAME_get0_otherName := ERR_GENERAL_NAME_get0_otherName;
    {$ifend}
    {$if declared(GENERAL_NAME_get0_otherName_introduced)}
    if LibVersion < GENERAL_NAME_get0_otherName_introduced then
    begin
      {$if declared(FC_GENERAL_NAME_get0_otherName)}
      GENERAL_NAME_get0_otherName := FC_GENERAL_NAME_get0_otherName;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAME_get0_otherName_removed)}
    if GENERAL_NAME_get0_otherName_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAME_get0_otherName)}
      GENERAL_NAME_get0_otherName := _GENERAL_NAME_get0_otherName;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAME_get0_otherName_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAME_get0_otherName');
    {$ifend}
  end;


  GENERAL_NAMES_free := LoadLibFunction(ADllHandle, GENERAL_NAMES_free_procname);
  FuncLoadError := not assigned(GENERAL_NAME_get0_otherName);
  if FuncLoadError then
  begin
    {$if not defined(GENERAL_NAMES_free_allownil)}
    GENERAL_NAMES_free := ERR_GENERAL_NAMES_free;
    {$ifend}
    {$if declared(GENERAL_NAMES_free_introduced)}
    if LibVersion < GENERAL_NAMES_free_introduced then
    begin
      {$if declared(FC_GENERAL_NAMES_free)}
      GENERAL_NAMES_free := FC_GENERAL_NAMES_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(GENERAL_NAMES_free_removed)}
    if GENERAL_NAMES_free_removed <= LibVersion then
    begin
      {$if declared(_GENERAL_NAMES_free)}
      GENERAL_NAMES_free := _GENERAL_NAMES_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(GENERAL_NAMES_free_allownil)}
    if FuncLoadError then
      AFailed.Add('GENERAL_NAMES_free');
    {$ifend}
  end;


  i2a_ACCESS_DESCRIPTION := LoadLibFunction(ADllHandle, i2a_ACCESS_DESCRIPTION_procname);
  FuncLoadError := not assigned(i2a_ACCESS_DESCRIPTION);
  if FuncLoadError then
  begin
    {$if not defined(i2a_ACCESS_DESCRIPTION_allownil)}
    i2a_ACCESS_DESCRIPTION := ERR_i2a_ACCESS_DESCRIPTION;
    {$ifend}
    {$if declared(i2a_ACCESS_DESCRIPTION_introduced)}
    if LibVersion < i2a_ACCESS_DESCRIPTION_introduced then
    begin
      {$if declared(FC_i2a_ACCESS_DESCRIPTION)}
      i2a_ACCESS_DESCRIPTION := FC_i2a_ACCESS_DESCRIPTION;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(i2a_ACCESS_DESCRIPTION_removed)}
    if i2a_ACCESS_DESCRIPTION_removed <= LibVersion then
    begin
      {$if declared(_i2a_ACCESS_DESCRIPTION)}
      i2a_ACCESS_DESCRIPTION := _i2a_ACCESS_DESCRIPTION;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(i2a_ACCESS_DESCRIPTION_allownil)}
    if FuncLoadError then
      AFailed.Add('i2a_ACCESS_DESCRIPTION');
    {$ifend}
  end;


  DIST_POINT_set_dpname := LoadLibFunction(ADllHandle, DIST_POINT_set_dpname_procname);
  FuncLoadError := not assigned(DIST_POINT_set_dpname);
  if FuncLoadError then
  begin
    {$if not defined(DIST_POINT_set_dpname_allownil)}
    DIST_POINT_set_dpname := ERR_DIST_POINT_set_dpname;
    {$ifend}
    {$if declared(DIST_POINT_set_dpname_introduced)}
    if LibVersion < DIST_POINT_set_dpname_introduced then
    begin
      {$if declared(FC_DIST_POINT_set_dpname)}
      DIST_POINT_set_dpname := FC_DIST_POINT_set_dpname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(DIST_POINT_set_dpname_removed)}
    if DIST_POINT_set_dpname_removed <= LibVersion then
    begin
      {$if declared(_DIST_POINT_set_dpname)}
      DIST_POINT_set_dpname := _DIST_POINT_set_dpname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(DIST_POINT_set_dpname_allownil)}
    if FuncLoadError then
      AFailed.Add('DIST_POINT_set_dpname');
    {$ifend}
  end;


  NAME_CONSTRAINTS_check := LoadLibFunction(ADllHandle, NAME_CONSTRAINTS_check_procname);
  FuncLoadError := not assigned(NAME_CONSTRAINTS_check);
  if FuncLoadError then
  begin
    {$if not defined(NAME_CONSTRAINTS_check_allownil)}
    NAME_CONSTRAINTS_check := ERR_NAME_CONSTRAINTS_check;
    {$ifend}
    {$if declared(NAME_CONSTRAINTS_check_introduced)}
    if LibVersion < NAME_CONSTRAINTS_check_introduced then
    begin
      {$if declared(FC_NAME_CONSTRAINTS_check)}
      NAME_CONSTRAINTS_check := FC_NAME_CONSTRAINTS_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAME_CONSTRAINTS_check_removed)}
    if NAME_CONSTRAINTS_check_removed <= LibVersion then
    begin
      {$if declared(_NAME_CONSTRAINTS_check)}
      NAME_CONSTRAINTS_check := _NAME_CONSTRAINTS_check;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAME_CONSTRAINTS_check_allownil)}
    if FuncLoadError then
      AFailed.Add('NAME_CONSTRAINTS_check');
    {$ifend}
  end;


  NAME_CONSTRAINTS_check_CN := LoadLibFunction(ADllHandle, NAME_CONSTRAINTS_check_CN_procname);
  FuncLoadError := not assigned(NAME_CONSTRAINTS_check_CN);
  if FuncLoadError then
  begin
    {$if not defined(NAME_CONSTRAINTS_check_CN_allownil)}
    NAME_CONSTRAINTS_check_CN := ERR_NAME_CONSTRAINTS_check_CN;
    {$ifend}
    {$if declared(NAME_CONSTRAINTS_check_CN_introduced)}
    if LibVersion < NAME_CONSTRAINTS_check_CN_introduced then
    begin
      {$if declared(FC_NAME_CONSTRAINTS_check_CN)}
      NAME_CONSTRAINTS_check_CN := FC_NAME_CONSTRAINTS_check_CN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAME_CONSTRAINTS_check_CN_removed)}
    if NAME_CONSTRAINTS_check_CN_removed <= LibVersion then
    begin
      {$if declared(_NAME_CONSTRAINTS_check_CN)}
      NAME_CONSTRAINTS_check_CN := _NAME_CONSTRAINTS_check_CN;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAME_CONSTRAINTS_check_CN_allownil)}
    if FuncLoadError then
      AFailed.Add('NAME_CONSTRAINTS_check_CN');
    {$ifend}
  end;


   BASIC_CONSTRAINTS_free := LoadLibFunction(ADllHandle, BASIC_CONSTRAINTS_free_procname);
  FuncLoadError := not assigned(BASIC_CONSTRAINTS_free);
  if FuncLoadError then
  begin
    {$if not defined(BASIC_CONSTRAINTS_free_allownil)}
    BASIC_CONSTRAINTS_free := ERR_BASIC_CONSTRAINTS_free;
    {$ifend}
    {$if declared(BASIC_CONSTRAINTS_free_introduced)}
    if LibVersion < BASIC_CONSTRAINTS_free_introduced then
    begin
      {$if declared(FC_BASIC_CONSTRAINTS_free)}
      BASIC_CONSTRAINTS_free := FC_BASIC_CONSTRAINTS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(BASIC_CONSTRAINTS_free_removed)}
    if BASIC_CONSTRAINTS_free_removed <= LibVersion then
    begin
      {$if declared(_BASIC_CONSTRAINTS_free)}
      BASIC_CONSTRAINTS_free := _BASIC_CONSTRAINTS_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(BASIC_CONSTRAINTS_free_allownil)}
    if FuncLoadError then
      AFailed.Add('BASIC_CONSTRAINTS_free');
    {$ifend}
  end;


  AUTHORITY_KEYID_free  := LoadLibFunction(ADllHandle, AUTHORITY_KEYID_free_procname);
  FuncLoadError := not assigned(AUTHORITY_KEYID_free);
  if FuncLoadError then
  begin
    {$if not defined(AUTHORITY_KEYID_free_allownil)}
    AUTHORITY_KEYID_free := ERR_AUTHORITY_KEYID_free;
    {$ifend}
    {$if declared(AUTHORITY_KEYID_free_introduced)}
    if LibVersion < AUTHORITY_KEYID_free_introduced then
    begin
      {$if declared(FC_AUTHORITY_KEYID_free)}
      AUTHORITY_KEYID_free := FC_AUTHORITY_KEYID_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(AUTHORITY_KEYID_free_removed)}
    if AUTHORITY_KEYID_free_removed <= LibVersion then
    begin
      {$if declared(_AUTHORITY_KEYID_free)}
      AUTHORITY_KEYID_free := _AUTHORITY_KEYID_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(AUTHORITY_KEYID_free_allownil)}
    if FuncLoadError then
      AFailed.Add('AUTHORITY_KEYID_free');
    {$ifend}
  end;


  X509V3_EXT_nconf_nid := LoadLibFunction(ADllHandle, X509V3_EXT_nconf_nid_procname);
  FuncLoadError := not assigned(X509V3_EXT_nconf_nid);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_nconf_nid_allownil)}
    X509V3_EXT_nconf_nid := ERR_X509V3_EXT_nconf_nid;
    {$ifend}
    {$if declared(X509V3_EXT_nconf_nid_introduced)}
    if LibVersion < X509V3_EXT_nconf_nid_introduced then
    begin
      {$if declared(FC_X509V3_EXT_nconf_nid)}
      X509V3_EXT_nconf_nid := FC_X509V3_EXT_nconf_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_nconf_nid_removed)}
    if X509V3_EXT_nconf_nid_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_nconf_nid)}
      X509V3_EXT_nconf_nid := _X509V3_EXT_nconf_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_nconf_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_nconf_nid');
    {$ifend}
  end;


  X509V3_EXT_nconf := LoadLibFunction(ADllHandle, X509V3_EXT_nconf_procname);
  FuncLoadError := not assigned(X509V3_EXT_nconf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_nconf_allownil)}
    X509V3_EXT_nconf := ERR_X509V3_EXT_nconf;
    {$ifend}
    {$if declared(X509V3_EXT_nconf_introduced)}
    if LibVersion < X509V3_EXT_nconf_introduced then
    begin
      {$if declared(FC_X509V3_EXT_nconf)}
      X509V3_EXT_nconf := FC_X509V3_EXT_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_nconf_removed)}
    if X509V3_EXT_nconf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_nconf)}
      X509V3_EXT_nconf := _X509V3_EXT_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_nconf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_nconf');
    {$ifend}
  end;


  X509V3_EXT_add_nconf := LoadLibFunction(ADllHandle, X509V3_EXT_add_nconf_procname);
  FuncLoadError := not assigned(X509V3_EXT_add_nconf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_add_nconf_allownil)}
    X509V3_EXT_add_nconf := ERR_X509V3_EXT_add_nconf;
    {$ifend}
    {$if declared(X509V3_EXT_add_nconf_introduced)}
    if LibVersion < X509V3_EXT_add_nconf_introduced then
    begin
      {$if declared(FC_X509V3_EXT_add_nconf)}
      X509V3_EXT_add_nconf := FC_X509V3_EXT_add_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_add_nconf_removed)}
    if X509V3_EXT_add_nconf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_add_nconf)}
      X509V3_EXT_add_nconf := _X509V3_EXT_add_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_add_nconf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_add_nconf');
    {$ifend}
  end;


  X509V3_EXT_REQ_add_nconf := LoadLibFunction(ADllHandle, X509V3_EXT_REQ_add_nconf_procname);
  FuncLoadError := not assigned(X509V3_EXT_REQ_add_nconf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_REQ_add_nconf_allownil)}
    X509V3_EXT_REQ_add_nconf := ERR_X509V3_EXT_REQ_add_nconf;
    {$ifend}
    {$if declared(X509V3_EXT_REQ_add_nconf_introduced)}
    if LibVersion < X509V3_EXT_REQ_add_nconf_introduced then
    begin
      {$if declared(FC_X509V3_EXT_REQ_add_nconf)}
      X509V3_EXT_REQ_add_nconf := FC_X509V3_EXT_REQ_add_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_REQ_add_nconf_removed)}
    if X509V3_EXT_REQ_add_nconf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_REQ_add_nconf)}
      X509V3_EXT_REQ_add_nconf := _X509V3_EXT_REQ_add_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_REQ_add_nconf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_REQ_add_nconf');
    {$ifend}
  end;


  X509V3_EXT_CRL_add_nconf := LoadLibFunction(ADllHandle, X509V3_EXT_CRL_add_nconf_procname);
  FuncLoadError := not assigned(X509V3_EXT_CRL_add_nconf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_CRL_add_nconf_allownil)}
    X509V3_EXT_CRL_add_nconf := ERR_X509V3_EXT_CRL_add_nconf;
    {$ifend}
    {$if declared(X509V3_EXT_CRL_add_nconf_introduced)}
    if LibVersion < X509V3_EXT_CRL_add_nconf_introduced then
    begin
      {$if declared(FC_X509V3_EXT_CRL_add_nconf)}
      X509V3_EXT_CRL_add_nconf := FC_X509V3_EXT_CRL_add_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_CRL_add_nconf_removed)}
    if X509V3_EXT_CRL_add_nconf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_CRL_add_nconf)}
      X509V3_EXT_CRL_add_nconf := _X509V3_EXT_CRL_add_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_CRL_add_nconf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_CRL_add_nconf');
    {$ifend}
  end;


  X509V3_EXT_conf_nid := LoadLibFunction(ADllHandle, X509V3_EXT_conf_nid_procname);
  FuncLoadError := not assigned(X509V3_EXT_conf_nid);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_conf_nid_allownil)}
    X509V3_EXT_conf_nid := ERR_X509V3_EXT_conf_nid;
    {$ifend}
    {$if declared(X509V3_EXT_conf_nid_introduced)}
    if LibVersion < X509V3_EXT_conf_nid_introduced then
    begin
      {$if declared(FC_X509V3_EXT_conf_nid)}
      X509V3_EXT_conf_nid := FC_X509V3_EXT_conf_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_conf_nid_removed)}
    if X509V3_EXT_conf_nid_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_conf_nid)}
      X509V3_EXT_conf_nid := _X509V3_EXT_conf_nid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_conf_nid_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_conf_nid');
    {$ifend}
  end;


  X509V3_EXT_conf := LoadLibFunction(ADllHandle, X509V3_EXT_conf_procname);
  FuncLoadError := not assigned(X509V3_EXT_conf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_conf_allownil)}
    X509V3_EXT_conf := ERR_X509V3_EXT_conf;
    {$ifend}
    {$if declared(X509V3_EXT_conf_introduced)}
    if LibVersion < X509V3_EXT_conf_introduced then
    begin
      {$if declared(FC_X509V3_EXT_conf)}
      X509V3_EXT_conf := FC_X509V3_EXT_conf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_conf_removed)}
    if X509V3_EXT_conf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_conf)}
      X509V3_EXT_conf := _X509V3_EXT_conf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_conf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_conf');
    {$ifend}
  end;


  X509V3_EXT_add_conf := LoadLibFunction(ADllHandle, X509V3_EXT_add_conf_procname);
  FuncLoadError := not assigned(X509V3_EXT_add_conf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_add_conf_allownil)}
    X509V3_EXT_add_conf := ERR_X509V3_EXT_add_conf;
    {$ifend}
    {$if declared(X509V3_EXT_add_conf_introduced)}
    if LibVersion < X509V3_EXT_add_conf_introduced then
    begin
      {$if declared(FC_X509V3_EXT_add_conf)}
      X509V3_EXT_add_conf := FC_X509V3_EXT_add_conf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_add_conf_removed)}
    if X509V3_EXT_add_conf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_add_conf)}
      X509V3_EXT_add_conf := _X509V3_EXT_add_conf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_add_conf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_add_conf');
    {$ifend}
  end;


  X509V3_EXT_REQ_add_conf := LoadLibFunction(ADllHandle, X509V3_EXT_REQ_add_conf_procname);
  FuncLoadError := not assigned(X509V3_EXT_REQ_add_conf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_REQ_add_conf_allownil)}
    X509V3_EXT_REQ_add_conf := ERR_X509V3_EXT_REQ_add_conf;
    {$ifend}
    {$if declared(X509V3_EXT_REQ_add_conf_introduced)}
    if LibVersion < X509V3_EXT_REQ_add_conf_introduced then
    begin
      {$if declared(FC_X509V3_EXT_REQ_add_conf)}
      X509V3_EXT_REQ_add_conf := FC_X509V3_EXT_REQ_add_conf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_REQ_add_conf_removed)}
    if X509V3_EXT_REQ_add_conf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_REQ_add_conf)}
      X509V3_EXT_REQ_add_conf := _X509V3_EXT_REQ_add_conf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_REQ_add_conf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_REQ_add_conf');
    {$ifend}
  end;


  X509V3_EXT_CRL_add_conf := LoadLibFunction(ADllHandle, X509V3_EXT_CRL_add_conf_procname);
  FuncLoadError := not assigned(X509V3_EXT_CRL_add_conf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_CRL_add_conf_allownil)}
    X509V3_EXT_CRL_add_conf := ERR_X509V3_EXT_CRL_add_conf;
    {$ifend}
    {$if declared(X509V3_EXT_CRL_add_conf_introduced)}
    if LibVersion < X509V3_EXT_CRL_add_conf_introduced then
    begin
      {$if declared(FC_X509V3_EXT_CRL_add_conf)}
      X509V3_EXT_CRL_add_conf := FC_X509V3_EXT_CRL_add_conf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_CRL_add_conf_removed)}
    if X509V3_EXT_CRL_add_conf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_CRL_add_conf)}
      X509V3_EXT_CRL_add_conf := _X509V3_EXT_CRL_add_conf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_CRL_add_conf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_CRL_add_conf');
    {$ifend}
  end;


  X509V3_set_nconf := LoadLibFunction(ADllHandle, X509V3_set_nconf_procname);
  FuncLoadError := not assigned(X509V3_set_nconf);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_set_nconf_allownil)}
    X509V3_set_nconf := ERR_X509V3_set_nconf;
    {$ifend}
    {$if declared(X509V3_set_nconf_introduced)}
    if LibVersion < X509V3_set_nconf_introduced then
    begin
      {$if declared(FC_X509V3_set_nconf)}
      X509V3_set_nconf := FC_X509V3_set_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_set_nconf_removed)}
    if X509V3_set_nconf_removed <= LibVersion then
    begin
      {$if declared(_X509V3_set_nconf)}
      X509V3_set_nconf := _X509V3_set_nconf;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_set_nconf_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_set_nconf');
    {$ifend}
  end;


  X509V3_get_string := LoadLibFunction(ADllHandle, X509V3_get_string_procname);
  FuncLoadError := not assigned(X509V3_get_string);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_get_string_allownil)}
    X509V3_get_string := ERR_X509V3_get_string;
    {$ifend}
    {$if declared(X509V3_get_string_introduced)}
    if LibVersion < X509V3_get_string_introduced then
    begin
      {$if declared(FC_X509V3_get_string)}
      X509V3_get_string := FC_X509V3_get_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_get_string_removed)}
    if X509V3_get_string_removed <= LibVersion then
    begin
      {$if declared(_X509V3_get_string)}
      X509V3_get_string := _X509V3_get_string;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_get_string_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_get_string');
    {$ifend}
  end;


  X509V3_string_free := LoadLibFunction(ADllHandle, X509V3_string_free_procname);
  FuncLoadError := not assigned(X509V3_string_free);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_string_free_allownil)}
    X509V3_string_free := ERR_X509V3_string_free;
    {$ifend}
    {$if declared(X509V3_string_free_introduced)}
    if LibVersion < X509V3_string_free_introduced then
    begin
      {$if declared(FC_X509V3_string_free)}
      X509V3_string_free := FC_X509V3_string_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_string_free_removed)}
    if X509V3_string_free_removed <= LibVersion then
    begin
      {$if declared(_X509V3_string_free)}
      X509V3_string_free := _X509V3_string_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_string_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_string_free');
    {$ifend}
  end;


  X509V3_set_ctx := LoadLibFunction(ADllHandle, X509V3_set_ctx_procname);
  FuncLoadError := not assigned(X509V3_set_ctx);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_set_ctx_allownil)}
    X509V3_set_ctx := ERR_X509V3_set_ctx;
    {$ifend}
    {$if declared(X509V3_set_ctx_introduced)}
    if LibVersion < X509V3_set_ctx_introduced then
    begin
      {$if declared(FC_X509V3_set_ctx)}
      X509V3_set_ctx := FC_X509V3_set_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_set_ctx_removed)}
    if X509V3_set_ctx_removed <= LibVersion then
    begin
      {$if declared(_X509V3_set_ctx)}
      X509V3_set_ctx := _X509V3_set_ctx;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_set_ctx_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_set_ctx');
    {$ifend}
  end;


  X509V3_EXT_add_alias := LoadLibFunction(ADllHandle, X509V3_EXT_add_alias_procname);
  FuncLoadError := not assigned(X509V3_EXT_add_alias);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_add_alias_allownil)}
    X509V3_EXT_add_alias := ERR_X509V3_EXT_add_alias;
    {$ifend}
    {$if declared(X509V3_EXT_add_alias_introduced)}
    if LibVersion < X509V3_EXT_add_alias_introduced then
    begin
      {$if declared(FC_X509V3_EXT_add_alias)}
      X509V3_EXT_add_alias := FC_X509V3_EXT_add_alias;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_add_alias_removed)}
    if X509V3_EXT_add_alias_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_add_alias)}
      X509V3_EXT_add_alias := _X509V3_EXT_add_alias;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_add_alias_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_add_alias');
    {$ifend}
  end;


  X509V3_EXT_cleanup := LoadLibFunction(ADllHandle, X509V3_EXT_cleanup_procname);
  FuncLoadError := not assigned(X509V3_EXT_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_cleanup_allownil)}
    X509V3_EXT_cleanup := ERR_X509V3_EXT_cleanup;
    {$ifend}
    {$if declared(X509V3_EXT_cleanup_introduced)}
    if LibVersion < X509V3_EXT_cleanup_introduced then
    begin
      {$if declared(FC_X509V3_EXT_cleanup)}
      X509V3_EXT_cleanup := FC_X509V3_EXT_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_cleanup_removed)}
    if X509V3_EXT_cleanup_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_cleanup)}
      X509V3_EXT_cleanup := _X509V3_EXT_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_cleanup');
    {$ifend}
  end;


  X509V3_add_standard_extensions := LoadLibFunction(ADllHandle, X509V3_add_standard_extensions_procname);
  FuncLoadError := not assigned(X509V3_add_standard_extensions);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_add_standard_extensions_allownil)}
    X509V3_add_standard_extensions := ERR_X509V3_add_standard_extensions;
    {$ifend}
    {$if declared(X509V3_add_standard_extensions_introduced)}
    if LibVersion < X509V3_add_standard_extensions_introduced then
    begin
      {$if declared(FC_X509V3_add_standard_extensions)}
      X509V3_add_standard_extensions := FC_X509V3_add_standard_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_add_standard_extensions_removed)}
    if X509V3_add_standard_extensions_removed <= LibVersion then
    begin
      {$if declared(_X509V3_add_standard_extensions)}
      X509V3_add_standard_extensions := _X509V3_add_standard_extensions;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_add_standard_extensions_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_add_standard_extensions');
    {$ifend}
  end;


  X509V3_EXT_d2i := LoadLibFunction(ADllHandle, X509V3_EXT_d2i_procname);
  FuncLoadError := not assigned(X509V3_EXT_d2i);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_d2i_allownil)}
    X509V3_EXT_d2i := ERR_X509V3_EXT_d2i;
    {$ifend}
    {$if declared(X509V3_EXT_d2i_introduced)}
    if LibVersion < X509V3_EXT_d2i_introduced then
    begin
      {$if declared(FC_X509V3_EXT_d2i)}
      X509V3_EXT_d2i := FC_X509V3_EXT_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_d2i_removed)}
    if X509V3_EXT_d2i_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_d2i)}
      X509V3_EXT_d2i := _X509V3_EXT_d2i;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_d2i_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_d2i');
    {$ifend}
  end;


  X509V3_EXT_i2d := LoadLibFunction(ADllHandle, X509V3_EXT_i2d_procname);
  FuncLoadError := not assigned(X509V3_EXT_i2d);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_i2d_allownil)}
    X509V3_EXT_i2d := ERR_X509V3_EXT_i2d;
    {$ifend}
    {$if declared(X509V3_EXT_i2d_introduced)}
    if LibVersion < X509V3_EXT_i2d_introduced then
    begin
      {$if declared(FC_X509V3_EXT_i2d)}
      X509V3_EXT_i2d := FC_X509V3_EXT_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_i2d_removed)}
    if X509V3_EXT_i2d_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_i2d)}
      X509V3_EXT_i2d := _X509V3_EXT_i2d;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_i2d_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_i2d');
    {$ifend}
  end;


  X509V3_EXT_print := LoadLibFunction(ADllHandle, X509V3_EXT_print_procname);
  FuncLoadError := not assigned(X509V3_EXT_print);
  if FuncLoadError then
  begin
    {$if not defined(X509V3_EXT_print_allownil)}
    X509V3_EXT_print := ERR_X509V3_EXT_print;
    {$ifend}
    {$if declared(X509V3_EXT_print_introduced)}
    if LibVersion < X509V3_EXT_print_introduced then
    begin
      {$if declared(FC_X509V3_EXT_print)}
      X509V3_EXT_print := FC_X509V3_EXT_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509V3_EXT_print_removed)}
    if X509V3_EXT_print_removed <= LibVersion then
    begin
      {$if declared(_X509V3_EXT_print)}
      X509V3_EXT_print := _X509V3_EXT_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509V3_EXT_print_allownil)}
    if FuncLoadError then
      AFailed.Add('X509V3_EXT_print');
    {$ifend}
  end;


  X509_check_ca := LoadLibFunction(ADllHandle, X509_check_ca_procname);
  FuncLoadError := not assigned(X509_check_ca);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_ca_allownil)}
    X509_check_ca := ERR_X509_check_ca;
    {$ifend}
    {$if declared(X509_check_ca_introduced)}
    if LibVersion < X509_check_ca_introduced then
    begin
      {$if declared(FC_X509_check_ca)}
      X509_check_ca := FC_X509_check_ca;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_ca_removed)}
    if X509_check_ca_removed <= LibVersion then
    begin
      {$if declared(_X509_check_ca)}
      X509_check_ca := _X509_check_ca;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_ca_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_ca');
    {$ifend}
  end;


  X509_check_purpose := LoadLibFunction(ADllHandle, X509_check_purpose_procname);
  FuncLoadError := not assigned(X509_check_purpose);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_purpose_allownil)}
    X509_check_purpose := ERR_X509_check_purpose;
    {$ifend}
    {$if declared(X509_check_purpose_introduced)}
    if LibVersion < X509_check_purpose_introduced then
    begin
      {$if declared(FC_X509_check_purpose)}
      X509_check_purpose := FC_X509_check_purpose;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_purpose_removed)}
    if X509_check_purpose_removed <= LibVersion then
    begin
      {$if declared(_X509_check_purpose)}
      X509_check_purpose := _X509_check_purpose;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_purpose_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_purpose');
    {$ifend}
  end;


  X509_supported_extension := LoadLibFunction(ADllHandle, X509_supported_extension_procname);
  FuncLoadError := not assigned(X509_supported_extension);
  if FuncLoadError then
  begin
    {$if not defined(X509_supported_extension_allownil)}
    X509_supported_extension := ERR_X509_supported_extension;
    {$ifend}
    {$if declared(X509_supported_extension_introduced)}
    if LibVersion < X509_supported_extension_introduced then
    begin
      {$if declared(FC_X509_supported_extension)}
      X509_supported_extension := FC_X509_supported_extension;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_supported_extension_removed)}
    if X509_supported_extension_removed <= LibVersion then
    begin
      {$if declared(_X509_supported_extension)}
      X509_supported_extension := _X509_supported_extension;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_supported_extension_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_supported_extension');
    {$ifend}
  end;


  X509_PURPOSE_set := LoadLibFunction(ADllHandle, X509_PURPOSE_set_procname);
  FuncLoadError := not assigned(X509_PURPOSE_set);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_set_allownil)}
    X509_PURPOSE_set := ERR_X509_PURPOSE_set;
    {$ifend}
    {$if declared(X509_PURPOSE_set_introduced)}
    if LibVersion < X509_PURPOSE_set_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_set)}
      X509_PURPOSE_set := FC_X509_PURPOSE_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_set_removed)}
    if X509_PURPOSE_set_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_set)}
      X509_PURPOSE_set := _X509_PURPOSE_set;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_set_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_set');
    {$ifend}
  end;


  X509_check_issued := LoadLibFunction(ADllHandle, X509_check_issued_procname);
  FuncLoadError := not assigned(X509_check_issued);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_issued_allownil)}
    X509_check_issued := ERR_X509_check_issued;
    {$ifend}
    {$if declared(X509_check_issued_introduced)}
    if LibVersion < X509_check_issued_introduced then
    begin
      {$if declared(FC_X509_check_issued)}
      X509_check_issued := FC_X509_check_issued;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_issued_removed)}
    if X509_check_issued_removed <= LibVersion then
    begin
      {$if declared(_X509_check_issued)}
      X509_check_issued := _X509_check_issued;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_issued_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_issued');
    {$ifend}
  end;


  X509_check_akid := LoadLibFunction(ADllHandle, X509_check_akid_procname);
  FuncLoadError := not assigned(X509_check_akid);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_akid_allownil)}
    X509_check_akid := ERR_X509_check_akid;
    {$ifend}
    {$if declared(X509_check_akid_introduced)}
    if LibVersion < X509_check_akid_introduced then
    begin
      {$if declared(FC_X509_check_akid)}
      X509_check_akid := FC_X509_check_akid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_akid_removed)}
    if X509_check_akid_removed <= LibVersion then
    begin
      {$if declared(_X509_check_akid)}
      X509_check_akid := _X509_check_akid;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_akid_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_akid');
    {$ifend}
  end;


  X509_set_proxy_flag := LoadLibFunction(ADllHandle, X509_set_proxy_flag_procname);
  FuncLoadError := not assigned(X509_set_proxy_flag);
  if FuncLoadError then
  begin
    {$if not defined(X509_set_proxy_flag_allownil)}
    X509_set_proxy_flag := ERR_X509_set_proxy_flag;
    {$ifend}
    {$if declared(X509_set_proxy_flag_introduced)}
    if LibVersion < X509_set_proxy_flag_introduced then
    begin
      {$if declared(FC_X509_set_proxy_flag)}
      X509_set_proxy_flag := FC_X509_set_proxy_flag;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_set_proxy_flag_removed)}
    if X509_set_proxy_flag_removed <= LibVersion then
    begin
      {$if declared(_X509_set_proxy_flag)}
      X509_set_proxy_flag := _X509_set_proxy_flag;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_set_proxy_flag_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_set_proxy_flag');
    {$ifend}
  end;


  X509_set_proxy_pathlen := LoadLibFunction(ADllHandle, X509_set_proxy_pathlen_procname);
  FuncLoadError := not assigned(X509_set_proxy_pathlen);
  if FuncLoadError then
  begin
    {$if not defined(X509_set_proxy_pathlen_allownil)}
    X509_set_proxy_pathlen := ERR_X509_set_proxy_pathlen;
    {$ifend}
    {$if declared(X509_set_proxy_pathlen_introduced)}
    if LibVersion < X509_set_proxy_pathlen_introduced then
    begin
      {$if declared(FC_X509_set_proxy_pathlen)}
      X509_set_proxy_pathlen := FC_X509_set_proxy_pathlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_set_proxy_pathlen_removed)}
    if X509_set_proxy_pathlen_removed <= LibVersion then
    begin
      {$if declared(_X509_set_proxy_pathlen)}
      X509_set_proxy_pathlen := _X509_set_proxy_pathlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_set_proxy_pathlen_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_set_proxy_pathlen');
    {$ifend}
  end;


  X509_get_proxy_pathlen := LoadLibFunction(ADllHandle, X509_get_proxy_pathlen_procname);
  FuncLoadError := not assigned(X509_get_proxy_pathlen);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_proxy_pathlen_allownil)}
    X509_get_proxy_pathlen := ERR_X509_get_proxy_pathlen;
    {$ifend}
    {$if declared(X509_get_proxy_pathlen_introduced)}
    if LibVersion < X509_get_proxy_pathlen_introduced then
    begin
      {$if declared(FC_X509_get_proxy_pathlen)}
      X509_get_proxy_pathlen := FC_X509_get_proxy_pathlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_proxy_pathlen_removed)}
    if X509_get_proxy_pathlen_removed <= LibVersion then
    begin
      {$if declared(_X509_get_proxy_pathlen)}
      X509_get_proxy_pathlen := _X509_get_proxy_pathlen;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_proxy_pathlen_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_proxy_pathlen');
    {$ifend}
  end;


  X509_get_extension_flags := LoadLibFunction(ADllHandle, X509_get_extension_flags_procname);
  FuncLoadError := not assigned(X509_get_extension_flags);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_extension_flags_allownil)}
    X509_get_extension_flags := ERR_X509_get_extension_flags;
    {$ifend}
    {$if declared(X509_get_extension_flags_introduced)}
    if LibVersion < X509_get_extension_flags_introduced then
    begin
      {$if declared(FC_X509_get_extension_flags)}
      X509_get_extension_flags := FC_X509_get_extension_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_extension_flags_removed)}
    if X509_get_extension_flags_removed <= LibVersion then
    begin
      {$if declared(_X509_get_extension_flags)}
      X509_get_extension_flags := _X509_get_extension_flags;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_extension_flags_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_extension_flags');
    {$ifend}
  end;


  X509_get_key_usage := LoadLibFunction(ADllHandle, X509_get_key_usage_procname);
  FuncLoadError := not assigned(X509_get_key_usage);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_key_usage_allownil)}
    X509_get_key_usage := ERR_X509_get_key_usage;
    {$ifend}
    {$if declared(X509_get_key_usage_introduced)}
    if LibVersion < X509_get_key_usage_introduced then
    begin
      {$if declared(FC_X509_get_key_usage)}
      X509_get_key_usage := FC_X509_get_key_usage;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_key_usage_removed)}
    if X509_get_key_usage_removed <= LibVersion then
    begin
      {$if declared(_X509_get_key_usage)}
      X509_get_key_usage := _X509_get_key_usage;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_key_usage_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_key_usage');
    {$ifend}
  end;


  X509_get_extended_key_usage := LoadLibFunction(ADllHandle, X509_get_extended_key_usage_procname);
  FuncLoadError := not assigned(X509_get_extended_key_usage);
  if FuncLoadError then
  begin
    {$if not defined(X509_get_extended_key_usage_allownil)}
    X509_get_extended_key_usage := ERR_X509_get_extended_key_usage;
    {$ifend}
    {$if declared(X509_get_extended_key_usage_introduced)}
    if LibVersion < X509_get_extended_key_usage_introduced then
    begin
      {$if declared(FC_X509_get_extended_key_usage)}
      X509_get_extended_key_usage := FC_X509_get_extended_key_usage;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get_extended_key_usage_removed)}
    if X509_get_extended_key_usage_removed <= LibVersion then
    begin
      {$if declared(_X509_get_extended_key_usage)}
      X509_get_extended_key_usage := _X509_get_extended_key_usage;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get_extended_key_usage_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get_extended_key_usage');
    {$ifend}
  end;


  X509_get0_subject_key_id := LoadLibFunction(ADllHandle, X509_get0_subject_key_id_procname);
  FuncLoadError := not assigned(X509_get0_subject_key_id);
  if FuncLoadError then
  begin
    {$if not defined(X509_get0_subject_key_id_allownil)}
    X509_get0_subject_key_id := ERR_X509_get0_subject_key_id;
    {$ifend}
    {$if declared(X509_get0_subject_key_id_introduced)}
    if LibVersion < X509_get0_subject_key_id_introduced then
    begin
      {$if declared(FC_X509_get0_subject_key_id)}
      X509_get0_subject_key_id := FC_X509_get0_subject_key_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get0_subject_key_id_removed)}
    if X509_get0_subject_key_id_removed <= LibVersion then
    begin
      {$if declared(_X509_get0_subject_key_id)}
      X509_get0_subject_key_id := _X509_get0_subject_key_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get0_subject_key_id_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get0_subject_key_id');
    {$ifend}
  end;

  X509_get0_authority_issuer := LoadLibFunction(ADllHandle, X509_get0_authority_issuer_procname);
  FuncLoadError := not assigned(X509_get0_subject_key_id);
  if FuncLoadError then
  begin
    {$if not defined(X509_get0_authority_issuer_allownil)}
    X509_get0_authority_issuer := ERR_X509_get0_authority_issuer;
    {$ifend}
    {$if declared(X509_get0_authority_issuer_introduced)}
    if LibVersion < X509_get0_subject_key_id_introduced then
    begin
      {$if declared(FC_X509_get0_authority_issuer)}
      X509_get0_subject_key_id := FC_X509_get0_subject_key_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get0_authority_issuer_removed)}
    if X509_get0_subject_key_id_removed <= LibVersion then
    begin
      {$if declared(_X509_get0_authority_issuer)}
      X509_get0_subject_key_id := _X509_get0_subject_key_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get0_authority_issuer_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get0_authority_issuer');
    {$ifend}
  end;

  X509_get0_authority_key_id := LoadLibFunction(ADllHandle, X509_get0_authority_key_id_procname);
  FuncLoadError := not assigned(X509_get0_authority_key_id);
  if FuncLoadError then
  begin
    {$if not defined(X509_get0_authority_key_id_allownil)}
    X509_get0_authority_key_id := ERR_X509_get0_authority_key_id;
    {$ifend}
    {$if declared(X509_get0_authority_key_id_introduced)}
    if LibVersion < X509_get0_authority_key_id_introduced then
    begin
      {$if declared(FC_X509_get0_authority_key_id)}
      X509_get0_authority_key_id := FC_X509_get0_authority_key_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get0_authority_key_id_removed)}
    if X509_get0_authority_key_id_removed <= LibVersion then
    begin
      {$if declared(_X509_get0_authority_key_id)}
      X509_get0_authority_key_id := _X509_get0_authority_key_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get0_authority_key_id_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get0_authority_key_id');
    {$ifend}
  end;


  X509_get0_authority_serial := LoadLibFunction(ADllHandle, X509_get0_authority_serial_procname);
  FuncLoadError := not assigned(X509_get0_authority_serial);
  if FuncLoadError then
  begin
    {$if not defined(X509_get0_authority_serial_allownil)}
    X509_get0_authority_serial := ERR_X509_get0_authority_serial;
    {$ifend}
    {$if declared(X509_get0_authority_serial_introduced)}
    if LibVersion < X509_get0_authority_serial_introduced then
    begin
      {$if declared(FC_X509_get0_authority_serial)}
      X509_get0_authority_serial := FC_X509_get0_authority_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get0_authority_serial_removed)}
    if X509_get0_authority_serial_removed <= LibVersion then
    begin
      {$if declared(_X509_get0_authority_serial)}
      X509_get0_authority_serial := _X509_get0_authority_serial;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get0_authority_serial_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get0_authority_serial');
    {$ifend}
  end;


  X509_PURPOSE_get_count := LoadLibFunction(ADllHandle, X509_PURPOSE_get_count_procname);
  FuncLoadError := not assigned(X509_PURPOSE_get_count);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get_count_allownil)}
    X509_PURPOSE_get_count := ERR_X509_PURPOSE_get_count;
    {$ifend}
    {$if declared(X509_PURPOSE_get_count_introduced)}
    if LibVersion < X509_PURPOSE_get_count_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_get_count)}
      X509_PURPOSE_get_count := FC_X509_PURPOSE_get_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_get_count_removed)}
    if X509_PURPOSE_get_count_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get_count)}
      X509_PURPOSE_get_count := _X509_PURPOSE_get_count;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_get_count_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_get_count');
    {$ifend}
  end;


  X509_PURPOSE_get0 := LoadLibFunction(ADllHandle, X509_PURPOSE_get0_procname);
  FuncLoadError := not assigned(X509_PURPOSE_get0);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get0_allownil)}
    X509_PURPOSE_get0 := ERR_X509_PURPOSE_get0;
    {$ifend}
    {$if declared(X509_PURPOSE_get0_introduced)}
    if LibVersion < X509_PURPOSE_get0_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_get0)}
      X509_PURPOSE_get0 := FC_X509_PURPOSE_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_get0_removed)}
    if X509_PURPOSE_get0_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get0)}
      X509_PURPOSE_get0 := _X509_PURPOSE_get0;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_get0_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_get0');
    {$ifend}
  end;


  X509_PURPOSE_get_by_sname := LoadLibFunction(ADllHandle, X509_PURPOSE_get_by_sname_procname);
  FuncLoadError := not assigned(X509_PURPOSE_get_by_sname);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get_by_sname_allownil)}
    X509_PURPOSE_get_by_sname := ERR_X509_PURPOSE_get_by_sname;
    {$ifend}
    {$if declared(X509_PURPOSE_get_by_sname_introduced)}
    if LibVersion < X509_PURPOSE_get_by_sname_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_get_by_sname)}
      X509_PURPOSE_get_by_sname := FC_X509_PURPOSE_get_by_sname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_get_by_sname_removed)}
    if X509_PURPOSE_get_by_sname_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get_by_sname)}
      X509_PURPOSE_get_by_sname := _X509_PURPOSE_get_by_sname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_get_by_sname_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_get_by_sname');
    {$ifend}
  end;


  X509_PURPOSE_get_by_id := LoadLibFunction(ADllHandle, X509_PURPOSE_get_by_id_procname);
  FuncLoadError := not assigned(X509_PURPOSE_get_by_id);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get_by_id_allownil)}
    X509_PURPOSE_get_by_id := ERR_X509_PURPOSE_get_by_id;
    {$ifend}
    {$if declared(X509_PURPOSE_get_by_id_introduced)}
    if LibVersion < X509_PURPOSE_get_by_id_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_get_by_id)}
      X509_PURPOSE_get_by_id := FC_X509_PURPOSE_get_by_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_get_by_id_removed)}
    if X509_PURPOSE_get_by_id_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get_by_id)}
      X509_PURPOSE_get_by_id := _X509_PURPOSE_get_by_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_get_by_id_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_get_by_id');
    {$ifend}
  end;


  X509_PURPOSE_get0_name := LoadLibFunction(ADllHandle, X509_PURPOSE_get0_name_procname);
  FuncLoadError := not assigned(X509_PURPOSE_get0_name);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get0_name_allownil)}
    X509_PURPOSE_get0_name := ERR_X509_PURPOSE_get0_name;
    {$ifend}
    {$if declared(X509_PURPOSE_get0_name_introduced)}
    if LibVersion < X509_PURPOSE_get0_name_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_get0_name)}
      X509_PURPOSE_get0_name := FC_X509_PURPOSE_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_get0_name_removed)}
    if X509_PURPOSE_get0_name_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get0_name)}
      X509_PURPOSE_get0_name := _X509_PURPOSE_get0_name;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_get0_name_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_get0_name');
    {$ifend}
  end;


  X509_PURPOSE_get0_sname := LoadLibFunction(ADllHandle, X509_PURPOSE_get0_sname_procname);
  FuncLoadError := not assigned(X509_PURPOSE_get0_sname);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get0_sname_allownil)}
    X509_PURPOSE_get0_sname := ERR_X509_PURPOSE_get0_sname;
    {$ifend}
    {$if declared(X509_PURPOSE_get0_sname_introduced)}
    if LibVersion < X509_PURPOSE_get0_sname_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_get0_sname)}
      X509_PURPOSE_get0_sname := FC_X509_PURPOSE_get0_sname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_get0_sname_removed)}
    if X509_PURPOSE_get0_sname_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get0_sname)}
      X509_PURPOSE_get0_sname := _X509_PURPOSE_get0_sname;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_get0_sname_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_get0_sname');
    {$ifend}
  end;


  X509_PURPOSE_get_trust := LoadLibFunction(ADllHandle, X509_PURPOSE_get_trust_procname);
  FuncLoadError := not assigned(X509_PURPOSE_get_trust);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get_trust_allownil)}
    X509_PURPOSE_get_trust := ERR_X509_PURPOSE_get_trust;
    {$ifend}
    {$if declared(X509_PURPOSE_get_trust_introduced)}
    if LibVersion < X509_PURPOSE_get_trust_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_get_trust)}
      X509_PURPOSE_get_trust := FC_X509_PURPOSE_get_trust;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_get_trust_removed)}
    if X509_PURPOSE_get_trust_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get_trust)}
      X509_PURPOSE_get_trust := _X509_PURPOSE_get_trust;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_get_trust_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_get_trust');
    {$ifend}
  end;


  X509_PURPOSE_cleanup := LoadLibFunction(ADllHandle, X509_PURPOSE_cleanup_procname);
  FuncLoadError := not assigned(X509_PURPOSE_cleanup);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_cleanup_allownil)}
    X509_PURPOSE_cleanup := ERR_X509_PURPOSE_cleanup;
    {$ifend}
    {$if declared(X509_PURPOSE_cleanup_introduced)}
    if LibVersion < X509_PURPOSE_cleanup_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_cleanup)}
      X509_PURPOSE_cleanup := FC_X509_PURPOSE_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_cleanup_removed)}
    if X509_PURPOSE_cleanup_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_cleanup)}
      X509_PURPOSE_cleanup := _X509_PURPOSE_cleanup;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_cleanup_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_cleanup');
    {$ifend}
  end;


  X509_PURPOSE_get_id := LoadLibFunction(ADllHandle, X509_PURPOSE_get_id_procname);
  FuncLoadError := not assigned(X509_PURPOSE_get_id);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get_id_allownil)}
    X509_PURPOSE_get_id := ERR_X509_PURPOSE_get_id;
    {$ifend}
    {$if declared(X509_PURPOSE_get_id_introduced)}
    if LibVersion < X509_PURPOSE_get_id_introduced then
    begin
      {$if declared(FC_X509_PURPOSE_get_id)}
      X509_PURPOSE_get_id := FC_X509_PURPOSE_get_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_PURPOSE_get_id_removed)}
    if X509_PURPOSE_get_id_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get_id)}
      X509_PURPOSE_get_id := _X509_PURPOSE_get_id;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_PURPOSE_get_id_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_PURPOSE_get_id');
    {$ifend}
  end;


  X509_get1_email := LoadLibFunction(ADllHandle, X509_get1_email_procname);
  FuncLoadError := not assigned(X509_get1_email);
  if FuncLoadError then
  begin
    {$if not defined(X509_PURPOSE_get_id_allownil)}
    X509_get1_email := ERR_X509_get1_email;
    {$ifend}
    {$if declared(X509_get1_email_introduced)}
    if LibVersion < X509_get1_email_introduced then
    begin
      {$if declared(FC_X509_get1_email)}
      X509_get1_email := FC_X509_get1_email;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get1_email_removed)}
    if X509_get1_email_removed <= LibVersion then
    begin
      {$if declared(_X509_PURPOSE_get_id)}
      X509_get1_email := _X509_get1_email;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get1_email_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get1_email');
    {$ifend}
  end;


  X509_REQ_get1_email := LoadLibFunction(ADllHandle,  X509_REQ_get1_email_procname);
  FuncLoadError := not assigned(X509_REQ_get1_email);
  if FuncLoadError then
  begin
    {$if not defined(X509_REQ_get1_email_allownil)}
    X509_REQ_get1_email := ERR_X509_REQ_get1_email;
    {$ifend}
    {$if declared(X509_REQ_get1_email_introduced)}
    if LibVersion < X509_REQ_get1_email_introduced then
    begin
      {$if declared(FC_X509_REQ_get1_email)}
      X509_REQ_get1_email := FC_X509_REQ_get1_email;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_REQ_get1_email_removed)}
    if X509_REQ_get1_email_removed <= LibVersion then
    begin
      {$if declared(_X509_get1_email)}
      X509_REQ_get1_email := _X509_REQ_get1_email;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_REQ_get1_email_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_REQ_get1_email');
    {$ifend}
  end;


  X509_email_free := LoadLibFunction(ADllHandle, X509_email_free_procname);
  FuncLoadError := not assigned(X509_email_free);
  if FuncLoadError then
  begin
    {$if not defined(X509_email_free_allownil)}
    X509_email_free := ERR_X509_email_free;
    {$ifend}
    {$if declared(X509_email_free_introduced)}
    if LibVersion < X509_email_free_introduced then
    begin
      {$if declared(FC_X509_email_free)}
      X509_email_free := FC_X509_email_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_email_free_removed)}
    if X509_email_free_removed <= LibVersion then
    begin
      {$if declared(_X509_get1_email)}
      X509_email_free := _X509_email_free;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_email_free_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_email_free');
    {$ifend}
  end;


  X509_get1_ocsp := LoadLibFunction(ADllHandle, X509_get1_ocsp_procname);
  FuncLoadError := not assigned(X509_get1_ocsp);
  if FuncLoadError then
  begin
    {$if not defined(X509_get1_ocsp_allownil)}
    X509_get1_ocsp := ERR_X509_get1_ocsp;
    {$ifend}
    {$if declared(X509_get1_ocsp_introduced)}
    if LibVersion < X509_get1_ocsp_introduced then
    begin
      {$if declared(FC_X509_get1_ocsp)}
      X509_get1_ocsp := FC_X509_get1_ocsp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_get1_ocsp_removed)}
    if X509_get1_ocsp_removed <= LibVersion then
    begin
      {$if declared(_X509_get1_email)}
      X509_get1_ocsp := _X509_get1_ocsp;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_get1_ocsp_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_get1_ocsp');
    {$ifend}
  end;


  X509_check_host := LoadLibFunction(ADllHandle, X509_check_host_procname);
  FuncLoadError := not assigned(X509_check_host);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_host_allownil)}
    X509_check_host := ERR_X509_check_host;
    {$ifend}
    {$if declared(X509_check_host_introduced)}
    if LibVersion < X509_check_host_introduced then
    begin
      {$if declared(FC_X509_check_host)}
      X509_check_host := FC_X509_check_host;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_host_removed)}
    if X509_check_host_removed <= LibVersion then
    begin
      {$if declared(_X509_check_host)}
      X509_check_host := _X509_check_host;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_host_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_host');
    {$ifend}
  end;


  X509_check_email := LoadLibFunction(ADllHandle, X509_check_email_procname);
  FuncLoadError := not assigned(X509_check_email);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_email_allownil)}
    X509_check_email := ERR_X509_check_email;
    {$ifend}
    {$if declared(X509_check_email_introduced)}
    if LibVersion < X509_check_email_introduced then
    begin
      {$if declared(FC_X509_check_email)}
      X509_check_email := FC_X509_check_email;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_email_removed)}
    if X509_check_email_removed <= LibVersion then
    begin
      {$if declared(_X509_check_email)}
      X509_check_email := _X509_check_email;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_email_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_email');
    {$ifend}
  end;


  X509_check_ip := LoadLibFunction(ADllHandle, X509_check_ip_procname);
  FuncLoadError := not assigned(X509_check_ip);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_ip_allownil)}
    X509_check_ip := ERR_X509_check_ip;
    {$ifend}
    {$if declared(X509_check_ip_introduced)}
    if LibVersion < X509_check_ip_introduced then
    begin
      {$if declared(FC_X509_check_ip)}
      X509_check_ip := FC_X509_check_ip;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_ip_removed)}
    if X509_check_ip_removed <= LibVersion then
    begin
      {$if declared(_X509_check_ip)}
      X509_check_ip := _X509_check_ip;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_ip_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_ip');
    {$ifend}
  end;


  X509_check_ip_asc := LoadLibFunction(ADllHandle, X509_check_ip_asc_procname);
  FuncLoadError := not assigned(X509_check_ip_asc);
  if FuncLoadError then
  begin
    {$if not defined(X509_check_ip_asc_allownil)}
    X509_check_ip_asc := ERR_X509_check_ip_asc;
    {$ifend}
    {$if declared(X509_check_ip_asc_introduced)}
    if LibVersion < X509_check_ip_asc_introduced then
    begin
      {$if declared(FC_X509_check_ip_asc)}
      X509_check_ip_asc := FC_X509_check_ip_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_check_ip_asc_removed)}
    if X509_check_ip_asc_removed <= LibVersion then
    begin
      {$if declared(_X509_check_ip_asc)}
      X509_check_ip_asc := _X509_check_ip_asc;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_check_ip_asc_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_check_ip_asc');
    {$ifend}
  end;


  a2i_IPADDRESS := LoadLibFunction(ADllHandle, a2i_IPADDRESS_procname);
  FuncLoadError := not assigned(a2i_IPADDRESS);
  if FuncLoadError then
  begin
    {$if not defined(a2i_IPADDRESS_allownil)}
    a2i_IPADDRESS := ERR_a2i_IPADDRESS;
    {$ifend}
    {$if declared(a2i_IPADDRESS_introduced)}
    if LibVersion < a2i_IPADDRESS_introduced then
    begin
      {$if declared(FC_a2i_IPADDRESS)}
      a2i_IPADDRESS := FC_a2i_IPADDRESS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(a2i_IPADDRESS_removed)}
    if a2i_IPADDRESS_removed <= LibVersion then
    begin
      {$if declared(_a2i_IPADDRESS)}
      a2i_IPADDRESS := _a2i_IPADDRESS;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(a2i_IPADDRESS_allownil)}
    if FuncLoadError then
      AFailed.Add('a2i_IPADDRESS');
    {$ifend}
  end;


  a2i_IPADDRESS_NC := LoadLibFunction(ADllHandle, a2i_IPADDRESS_NC_procname);
  FuncLoadError := not assigned(a2i_IPADDRESS_NC);
  if FuncLoadError then
  begin
    {$if not defined(a2i_IPADDRESS_NC_allownil)}
    a2i_IPADDRESS_NC := ERR_a2i_IPADDRESS_NC;
    {$ifend}
    {$if declared(a2i_IPADDRESS_NC_introduced)}
    if LibVersion < a2i_IPADDRESS_NC_introduced then
    begin
      {$if declared(FC_a2i_IPADDRESS_NC)}
      a2i_IPADDRESS_NC := FC_a2i_IPADDRESS_NC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(a2i_IPADDRESS_NC_removed)}
    if a2i_IPADDRESS_NC_removed <= LibVersion then
    begin
      {$if declared(_a2i_IPADDRESS_NC)}
      a2i_IPADDRESS_NC := _a2i_IPADDRESS_NC;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(a2i_IPADDRESS_NC_allownil)}
    if FuncLoadError then
      AFailed.Add('a2i_IPADDRESS_NC');
    {$ifend}
  end;


  X509_POLICY_NODE_print := LoadLibFunction(ADllHandle, X509_POLICY_NODE_print_procname);
  FuncLoadError := not assigned(X509_POLICY_NODE_print);
  if FuncLoadError then
  begin
    {$if not defined(X509_POLICY_NODE_print_allownil)}
    X509_POLICY_NODE_print := ERR_X509_POLICY_NODE_print;
    {$ifend}
    {$if declared(X509_POLICY_NODE_print_introduced)}
    if LibVersion < X509_POLICY_NODE_print_introduced then
    begin
      {$if declared(FC_X509_POLICY_NODE_print)}
      X509_POLICY_NODE_print := FC_X509_POLICY_NODE_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509_POLICY_NODE_print_removed)}
    if X509_POLICY_NODE_print_removed <= LibVersion then
    begin
      {$if declared(_X509_POLICY_NODE_print)}
      X509_POLICY_NODE_print := _X509_POLICY_NODE_print;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509_POLICY_NODE_print_allownil)}
    if FuncLoadError then
      AFailed.Add('X509_POLICY_NODE_print');
    {$ifend}
  end;


  X509v3_addr_get_range := LoadLibFunction(ADllHandle, X509v3_addr_get_range_procname);
  FuncLoadError := not assigned(X509v3_addr_get_range);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_addr_get_range_allownil)}
    X509v3_addr_get_range := ERR_X509v3_addr_get_range;
    {$ifend}
    {$if declared(X509v3_addr_get_range_introduced)}
    if LibVersion < X509v3_addr_get_range_introduced then
    begin
      {$if declared(FC_X509v3_addr_get_range)}
      X509v3_addr_get_range := FC_X509v3_addr_get_range;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_addr_get_range_removed)}
    if X509v3_addr_get_range_removed <= LibVersion then
    begin
      {$if declared(_X509v3_addr_get_range)}
      X509v3_addr_get_range := _X509v3_addr_get_range;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_addr_get_range_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_addr_get_range');
    {$ifend}
  end;


  X509v3_asid_validate_path := LoadLibFunction(ADllHandle, X509v3_asid_validate_path_procname);
  FuncLoadError := not assigned(X509v3_asid_validate_path);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_asid_validate_path_allownil)}
    X509v3_asid_validate_path := ERR_X509v3_asid_validate_path;
    {$ifend}
    {$if declared(X509v3_asid_validate_path_introduced)}
    if LibVersion < X509v3_asid_validate_path_introduced then
    begin
      {$if declared(FC_X509v3_asid_validate_path)}
      X509v3_asid_validate_path := FC_X509v3_asid_validate_path;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_asid_validate_path_removed)}
    if X509v3_asid_validate_path_removed <= LibVersion then
    begin
      {$if declared(_X509v3_asid_validate_path)}
      X509v3_asid_validate_path := _X509v3_asid_validate_path;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_asid_validate_path_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_asid_validate_path');
    {$ifend}
  end;


  X509v3_addr_validate_path := LoadLibFunction(ADllHandle, X509v3_addr_validate_path_procname);
  FuncLoadError := not assigned(X509v3_addr_validate_path);
  if FuncLoadError then
  begin
    {$if not defined(X509v3_addr_validate_path_allownil)}
    X509v3_addr_validate_path := ERR_X509v3_addr_validate_path;
    {$ifend}
    {$if declared(X509v3_addr_validate_path_introduced)}
    if LibVersion < X509v3_addr_validate_path_introduced then
    begin
      {$if declared(FC_X509v3_addr_validate_path)}
      X509v3_addr_validate_path := FC_X509v3_addr_validate_path;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(X509v3_addr_validate_path_removed)}
    if X509v3_addr_validate_path_removed <= LibVersion then
    begin
      {$if declared(_X509v3_addr_validate_path)}
      X509v3_addr_validate_path := _X509v3_addr_validate_path;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(X509v3_addr_validate_path_allownil)}
    if FuncLoadError then
      AFailed.Add('X509v3_addr_validate_path');
    {$ifend}
  end;


  NAMING_AUTHORITY_get0_authorityId := LoadLibFunction(ADllHandle, NAMING_AUTHORITY_get0_authorityId_procname);
  FuncLoadError := not assigned(NAMING_AUTHORITY_get0_authorityId);
  if FuncLoadError then
  begin
    {$if not defined(NAMING_AUTHORITY_get0_authorityId_allownil)}
    NAMING_AUTHORITY_get0_authorityId := ERR_NAMING_AUTHORITY_get0_authorityId;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_get0_authorityId_introduced)}
    if LibVersion < NAMING_AUTHORITY_get0_authorityId_introduced then
    begin
      {$if declared(FC_NAMING_AUTHORITY_get0_authorityId)}
      NAMING_AUTHORITY_get0_authorityId := FC_NAMING_AUTHORITY_get0_authorityId;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_get0_authorityId_removed)}
    if NAMING_AUTHORITY_get0_authorityId_removed <= LibVersion then
    begin
      {$if declared(_NAMING_AUTHORITY_get0_authorityId)}
      NAMING_AUTHORITY_get0_authorityId := _NAMING_AUTHORITY_get0_authorityId;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAMING_AUTHORITY_get0_authorityId_allownil)}
    if FuncLoadError then
      AFailed.Add('NAMING_AUTHORITY_get0_authorityId');
    {$ifend}
  end;


  NAMING_AUTHORITY_get0_authorityURL := LoadLibFunction(ADllHandle, NAMING_AUTHORITY_get0_authorityURL_procname);
  FuncLoadError := not assigned(NAMING_AUTHORITY_get0_authorityURL);
  if FuncLoadError then
  begin
    {$if not defined(NAMING_AUTHORITY_get0_authorityURL_allownil)}
    NAMING_AUTHORITY_get0_authorityURL := ERR_NAMING_AUTHORITY_get0_authorityURL;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_get0_authorityURL_introduced)}
    if LibVersion < NAMING_AUTHORITY_get0_authorityURL_introduced then
    begin
      {$if declared(FC_NAMING_AUTHORITY_get0_authorityURL)}
      NAMING_AUTHORITY_get0_authorityURL := FC_NAMING_AUTHORITY_get0_authorityURL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_get0_authorityURL_removed)}
    if NAMING_AUTHORITY_get0_authorityURL_removed <= LibVersion then
    begin
      {$if declared(_NAMING_AUTHORITY_get0_authorityURL)}
      NAMING_AUTHORITY_get0_authorityURL := _NAMING_AUTHORITY_get0_authorityURL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAMING_AUTHORITY_get0_authorityURL_allownil)}
    if FuncLoadError then
      AFailed.Add('NAMING_AUTHORITY_get0_authorityURL');
    {$ifend}
  end;


  NAMING_AUTHORITY_get0_authorityText := LoadLibFunction(ADllHandle, NAMING_AUTHORITY_get0_authorityText_procname);
  FuncLoadError := not assigned(NAMING_AUTHORITY_get0_authorityText);
  if FuncLoadError then
  begin
    {$if not defined(NAMING_AUTHORITY_get0_authorityText_allownil)}
    NAMING_AUTHORITY_get0_authorityText := ERR_NAMING_AUTHORITY_get0_authorityText;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_get0_authorityText_introduced)}
    if LibVersion < NAMING_AUTHORITY_get0_authorityText_introduced then
    begin
      {$if declared(FC_NAMING_AUTHORITY_get0_authorityText)}
      NAMING_AUTHORITY_get0_authorityText := FC_NAMING_AUTHORITY_get0_authorityText;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_get0_authorityText_removed)}
    if NAMING_AUTHORITY_get0_authorityText_removed <= LibVersion then
    begin
      {$if declared(_NAMING_AUTHORITY_get0_authorityText)}
      NAMING_AUTHORITY_get0_authorityText := _NAMING_AUTHORITY_get0_authorityText;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAMING_AUTHORITY_get0_authorityText_allownil)}
    if FuncLoadError then
      AFailed.Add('NAMING_AUTHORITY_get0_authorityText');
    {$ifend}
  end;


  NAMING_AUTHORITY_set0_authorityId := LoadLibFunction(ADllHandle, NAMING_AUTHORITY_set0_authorityId_procname);
  FuncLoadError := not assigned(NAMING_AUTHORITY_set0_authorityId);
  if FuncLoadError then
  begin
    {$if not defined(NAMING_AUTHORITY_set0_authorityId_allownil)}
    NAMING_AUTHORITY_set0_authorityId := ERR_NAMING_AUTHORITY_set0_authorityId;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_set0_authorityId_introduced)}
    if LibVersion < NAMING_AUTHORITY_set0_authorityId_introduced then
    begin
      {$if declared(FC_NAMING_AUTHORITY_set0_authorityId)}
      NAMING_AUTHORITY_set0_authorityId := FC_NAMING_AUTHORITY_set0_authorityId;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_set0_authorityId_removed)}
    if NAMING_AUTHORITY_set0_authorityId_removed <= LibVersion then
    begin
      {$if declared(_NAMING_AUTHORITY_set0_authorityId)}
      NAMING_AUTHORITY_set0_authorityId := _NAMING_AUTHORITY_set0_authorityId;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAMING_AUTHORITY_set0_authorityId_allownil)}
    if FuncLoadError then
      AFailed.Add('NAMING_AUTHORITY_set0_authorityId');
    {$ifend}
  end;


  NAMING_AUTHORITY_set0_authorityURL := LoadLibFunction(ADllHandle, NAMING_AUTHORITY_set0_authorityURL_procname);
  FuncLoadError := not assigned(NAMING_AUTHORITY_set0_authorityURL);
  if FuncLoadError then
  begin
    {$if not defined(NAMING_AUTHORITY_set0_authorityURL_allownil)}
    NAMING_AUTHORITY_set0_authorityURL := ERR_NAMING_AUTHORITY_set0_authorityURL;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_set0_authorityURL_introduced)}
    if LibVersion < NAMING_AUTHORITY_set0_authorityURL_introduced then
    begin
      {$if declared(FC_NAMING_AUTHORITY_set0_authorityURL)}
      NAMING_AUTHORITY_set0_authorityURL := FC_NAMING_AUTHORITY_set0_authorityURL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_set0_authorityURL_removed)}
    if NAMING_AUTHORITY_set0_authorityURL_removed <= LibVersion then
    begin
      {$if declared(_NAMING_AUTHORITY_set0_authorityURL)}
      NAMING_AUTHORITY_set0_authorityURL := _NAMING_AUTHORITY_set0_authorityURL;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAMING_AUTHORITY_set0_authorityURL_allownil)}
    if FuncLoadError then
      AFailed.Add('NAMING_AUTHORITY_set0_authorityURL');
    {$ifend}
  end;


  NAMING_AUTHORITY_set0_authorityText := LoadLibFunction(ADllHandle, NAMING_AUTHORITY_set0_authorityText_procname);
  FuncLoadError := not assigned(NAMING_AUTHORITY_set0_authorityText);
  if FuncLoadError then
  begin
    {$if not defined(NAMING_AUTHORITY_set0_authorityText_allownil)}
    NAMING_AUTHORITY_set0_authorityText := ERR_NAMING_AUTHORITY_set0_authorityText;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_set0_authorityText_introduced)}
    if LibVersion < NAMING_AUTHORITY_set0_authorityText_introduced then
    begin
      {$if declared(FC_NAMING_AUTHORITY_set0_authorityText)}
      NAMING_AUTHORITY_set0_authorityText := FC_NAMING_AUTHORITY_set0_authorityText;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(NAMING_AUTHORITY_set0_authorityText_removed)}
    if NAMING_AUTHORITY_set0_authorityText_removed <= LibVersion then
    begin
      {$if declared(_NAMING_AUTHORITY_set0_authorityText)}
      NAMING_AUTHORITY_set0_authorityText := _NAMING_AUTHORITY_set0_authorityText;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(NAMING_AUTHORITY_set0_authorityText_allownil)}
    if FuncLoadError then
      AFailed.Add('NAMING_AUTHORITY_set0_authorityText');
    {$ifend}
  end;


  ADMISSION_SYNTAX_get0_admissionAuthority := LoadLibFunction(ADllHandle, ADMISSION_SYNTAX_get0_admissionAuthority_procname);
  FuncLoadError := not assigned(ADMISSION_SYNTAX_get0_admissionAuthority);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSION_SYNTAX_get0_admissionAuthority_allownil)}
    ADMISSION_SYNTAX_get0_admissionAuthority := ERR_ADMISSION_SYNTAX_get0_admissionAuthority;
    {$ifend}
    {$if declared(ADMISSION_SYNTAX_get0_admissionAuthority_introduced)}
    if LibVersion < ADMISSION_SYNTAX_get0_admissionAuthority_introduced then
    begin
      {$if declared(FC_ADMISSION_SYNTAX_get0_admissionAuthority)}
      ADMISSION_SYNTAX_get0_admissionAuthority := FC_ADMISSION_SYNTAX_get0_admissionAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSION_SYNTAX_get0_admissionAuthority_removed)}
    if ADMISSION_SYNTAX_get0_admissionAuthority_removed <= LibVersion then
    begin
      {$if declared(_ADMISSION_SYNTAX_get0_admissionAuthority)}
      ADMISSION_SYNTAX_get0_admissionAuthority := _ADMISSION_SYNTAX_get0_admissionAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSION_SYNTAX_get0_admissionAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSION_SYNTAX_get0_admissionAuthority');
    {$ifend}
  end;


  ADMISSION_SYNTAX_set0_admissionAuthority := LoadLibFunction(ADllHandle, ADMISSION_SYNTAX_set0_admissionAuthority_procname);
  FuncLoadError := not assigned(ADMISSION_SYNTAX_set0_admissionAuthority);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSION_SYNTAX_set0_admissionAuthority_allownil)}
    ADMISSION_SYNTAX_set0_admissionAuthority := ERR_ADMISSION_SYNTAX_set0_admissionAuthority;
    {$ifend}
    {$if declared(ADMISSION_SYNTAX_set0_admissionAuthority_introduced)}
    if LibVersion < ADMISSION_SYNTAX_set0_admissionAuthority_introduced then
    begin
      {$if declared(FC_ADMISSION_SYNTAX_set0_admissionAuthority)}
      ADMISSION_SYNTAX_set0_admissionAuthority := FC_ADMISSION_SYNTAX_set0_admissionAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSION_SYNTAX_set0_admissionAuthority_removed)}
    if ADMISSION_SYNTAX_set0_admissionAuthority_removed <= LibVersion then
    begin
      {$if declared(_ADMISSION_SYNTAX_set0_admissionAuthority)}
      ADMISSION_SYNTAX_set0_admissionAuthority := _ADMISSION_SYNTAX_set0_admissionAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSION_SYNTAX_set0_admissionAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSION_SYNTAX_set0_admissionAuthority');
    {$ifend}
  end;


  ADMISSIONS_get0_admissionAuthority := LoadLibFunction(ADllHandle, ADMISSIONS_get0_admissionAuthority_procname);
  FuncLoadError := not assigned(ADMISSIONS_get0_admissionAuthority);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSIONS_get0_admissionAuthority_allownil)}
    ADMISSIONS_get0_admissionAuthority := ERR_ADMISSIONS_get0_admissionAuthority;
    {$ifend}
    {$if declared(ADMISSIONS_get0_admissionAuthority_introduced)}
    if LibVersion < ADMISSIONS_get0_admissionAuthority_introduced then
    begin
      {$if declared(FC_ADMISSIONS_get0_admissionAuthority)}
      ADMISSIONS_get0_admissionAuthority := FC_ADMISSIONS_get0_admissionAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSIONS_get0_admissionAuthority_removed)}
    if ADMISSIONS_get0_admissionAuthority_removed <= LibVersion then
    begin
      {$if declared(_ADMISSIONS_get0_admissionAuthority)}
      ADMISSIONS_get0_admissionAuthority := _ADMISSIONS_get0_admissionAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSIONS_get0_admissionAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSIONS_get0_admissionAuthority');
    {$ifend}
  end;


  ADMISSIONS_set0_admissionAuthority := LoadLibFunction(ADllHandle, ADMISSIONS_set0_admissionAuthority_procname);
  FuncLoadError := not assigned(ADMISSIONS_set0_admissionAuthority);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSIONS_set0_admissionAuthority_allownil)}
    ADMISSIONS_set0_admissionAuthority := ERR_ADMISSIONS_set0_admissionAuthority;
    {$ifend}
    {$if declared(ADMISSIONS_set0_admissionAuthority_introduced)}
    if LibVersion < ADMISSIONS_set0_admissionAuthority_introduced then
    begin
      {$if declared(FC_ADMISSIONS_set0_admissionAuthority)}
      ADMISSIONS_set0_admissionAuthority := FC_ADMISSIONS_set0_admissionAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSIONS_set0_admissionAuthority_removed)}
    if ADMISSIONS_set0_admissionAuthority_removed <= LibVersion then
    begin
      {$if declared(_ADMISSIONS_set0_admissionAuthority)}
      ADMISSIONS_set0_admissionAuthority := _ADMISSIONS_set0_admissionAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSIONS_set0_admissionAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSIONS_set0_admissionAuthority');
    {$ifend}
  end;


  ADMISSIONS_get0_namingAuthority := LoadLibFunction(ADllHandle, ADMISSIONS_get0_namingAuthority_procname);
  FuncLoadError := not assigned(ADMISSIONS_get0_namingAuthority);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSIONS_get0_namingAuthority_allownil)}
    ADMISSIONS_get0_namingAuthority := ERR_ADMISSIONS_get0_namingAuthority;
    {$ifend}
    {$if declared(ADMISSIONS_get0_namingAuthority_introduced)}
    if LibVersion < ADMISSIONS_get0_namingAuthority_introduced then
    begin
      {$if declared(FC_ADMISSIONS_get0_namingAuthority)}
      ADMISSIONS_get0_namingAuthority := FC_ADMISSIONS_get0_namingAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSIONS_get0_namingAuthority_removed)}
    if ADMISSIONS_get0_namingAuthority_removed <= LibVersion then
    begin
      {$if declared(_ADMISSIONS_get0_namingAuthority)}
      ADMISSIONS_get0_namingAuthority := _ADMISSIONS_get0_namingAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSIONS_get0_namingAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSIONS_get0_namingAuthority');
    {$ifend}
  end;


  ADMISSIONS_set0_namingAuthority := LoadLibFunction(ADllHandle, ADMISSIONS_set0_namingAuthority_procname);
  FuncLoadError := not assigned(ADMISSIONS_set0_namingAuthority);
  if FuncLoadError then
  begin
    {$if not defined(ADMISSIONS_set0_namingAuthority_allownil)}
    ADMISSIONS_set0_namingAuthority := ERR_ADMISSIONS_set0_namingAuthority;
    {$ifend}
    {$if declared(ADMISSIONS_set0_namingAuthority_introduced)}
    if LibVersion < ADMISSIONS_set0_namingAuthority_introduced then
    begin
      {$if declared(FC_ADMISSIONS_set0_namingAuthority)}
      ADMISSIONS_set0_namingAuthority := FC_ADMISSIONS_set0_namingAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(ADMISSIONS_set0_namingAuthority_removed)}
    if ADMISSIONS_set0_namingAuthority_removed <= LibVersion then
    begin
      {$if declared(_ADMISSIONS_set0_namingAuthority)}
      ADMISSIONS_set0_namingAuthority := _ADMISSIONS_set0_namingAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(ADMISSIONS_set0_namingAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('ADMISSIONS_set0_namingAuthority');
    {$ifend}
  end;


  PROFESSION_INFO_get0_addProfessionInfo := LoadLibFunction(ADllHandle, PROFESSION_INFO_get0_addProfessionInfo_procname);
  FuncLoadError := not assigned(PROFESSION_INFO_get0_addProfessionInfo);
  if FuncLoadError then
  begin
    {$if not defined(PROFESSION_INFO_get0_addProfessionInfo_allownil)}
    PROFESSION_INFO_get0_addProfessionInfo := ERR_PROFESSION_INFO_get0_addProfessionInfo;
    {$ifend}
    {$if declared(PROFESSION_INFO_get0_addProfessionInfo_introduced)}
    if LibVersion < PROFESSION_INFO_get0_addProfessionInfo_introduced then
    begin
      {$if declared(FC_PROFESSION_INFO_get0_addProfessionInfo)}
      PROFESSION_INFO_get0_addProfessionInfo := FC_PROFESSION_INFO_get0_addProfessionInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROFESSION_INFO_get0_addProfessionInfo_removed)}
    if PROFESSION_INFO_get0_addProfessionInfo_removed <= LibVersion then
    begin
      {$if declared(_PROFESSION_INFO_get0_addProfessionInfo)}
      PROFESSION_INFO_get0_addProfessionInfo := _PROFESSION_INFO_get0_addProfessionInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROFESSION_INFO_get0_addProfessionInfo_allownil)}
    if FuncLoadError then
      AFailed.Add('PROFESSION_INFO_get0_addProfessionInfo');
    {$ifend}
  end;


  PROFESSION_INFO_set0_addProfessionInfo := LoadLibFunction(ADllHandle, PROFESSION_INFO_set0_addProfessionInfo_procname);
  FuncLoadError := not assigned(PROFESSION_INFO_set0_addProfessionInfo);
  if FuncLoadError then
  begin
    {$if not defined(PROFESSION_INFO_set0_addProfessionInfo_allownil)}
    PROFESSION_INFO_set0_addProfessionInfo := ERR_PROFESSION_INFO_set0_addProfessionInfo;
    {$ifend}
    {$if declared(PROFESSION_INFO_set0_addProfessionInfo_introduced)}
    if LibVersion < PROFESSION_INFO_set0_addProfessionInfo_introduced then
    begin
      {$if declared(FC_PROFESSION_INFO_set0_addProfessionInfo)}
      PROFESSION_INFO_set0_addProfessionInfo := FC_PROFESSION_INFO_set0_addProfessionInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROFESSION_INFO_set0_addProfessionInfo_removed)}
    if PROFESSION_INFO_set0_addProfessionInfo_removed <= LibVersion then
    begin
      {$if declared(_PROFESSION_INFO_set0_addProfessionInfo)}
      PROFESSION_INFO_set0_addProfessionInfo := _PROFESSION_INFO_set0_addProfessionInfo;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROFESSION_INFO_set0_addProfessionInfo_allownil)}
    if FuncLoadError then
      AFailed.Add('PROFESSION_INFO_set0_addProfessionInfo');
    {$ifend}
  end;


  PROFESSION_INFO_get0_namingAuthority := LoadLibFunction(ADllHandle, PROFESSION_INFO_get0_namingAuthority_procname);
  FuncLoadError := not assigned(PROFESSION_INFO_get0_namingAuthority);
  if FuncLoadError then
  begin
    {$if not defined(PROFESSION_INFO_get0_namingAuthority_allownil)}
    PROFESSION_INFO_get0_namingAuthority := ERR_PROFESSION_INFO_get0_namingAuthority;
    {$ifend}
    {$if declared(PROFESSION_INFO_get0_namingAuthority_introduced)}
    if LibVersion < PROFESSION_INFO_get0_namingAuthority_introduced then
    begin
      {$if declared(FC_PROFESSION_INFO_get0_namingAuthority)}
      PROFESSION_INFO_get0_namingAuthority := FC_PROFESSION_INFO_get0_namingAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROFESSION_INFO_get0_namingAuthority_removed)}
    if PROFESSION_INFO_get0_namingAuthority_removed <= LibVersion then
    begin
      {$if declared(_PROFESSION_INFO_get0_namingAuthority)}
      PROFESSION_INFO_get0_namingAuthority := _PROFESSION_INFO_get0_namingAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROFESSION_INFO_get0_namingAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('PROFESSION_INFO_get0_namingAuthority');
    {$ifend}
  end;


  PROFESSION_INFO_set0_namingAuthority := LoadLibFunction(ADllHandle, PROFESSION_INFO_set0_namingAuthority_procname);
  FuncLoadError := not assigned(PROFESSION_INFO_set0_namingAuthority);
  if FuncLoadError then
  begin
    {$if not defined(PROFESSION_INFO_set0_namingAuthority_allownil)}
    PROFESSION_INFO_set0_namingAuthority := ERR_PROFESSION_INFO_set0_namingAuthority;
    {$ifend}
    {$if declared(PROFESSION_INFO_set0_namingAuthority_introduced)}
    if LibVersion < PROFESSION_INFO_set0_namingAuthority_introduced then
    begin
      {$if declared(FC_PROFESSION_INFO_set0_namingAuthority)}
      PROFESSION_INFO_set0_namingAuthority := FC_PROFESSION_INFO_set0_namingAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROFESSION_INFO_set0_namingAuthority_removed)}
    if PROFESSION_INFO_set0_namingAuthority_removed <= LibVersion then
    begin
      {$if declared(_PROFESSION_INFO_set0_namingAuthority)}
      PROFESSION_INFO_set0_namingAuthority := _PROFESSION_INFO_set0_namingAuthority;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROFESSION_INFO_set0_namingAuthority_allownil)}
    if FuncLoadError then
      AFailed.Add('PROFESSION_INFO_set0_namingAuthority');
    {$ifend}
  end;


  PROFESSION_INFO_get0_registrationNumber := LoadLibFunction(ADllHandle, PROFESSION_INFO_get0_registrationNumber_procname);
  FuncLoadError := not assigned(PROFESSION_INFO_get0_registrationNumber);
  if FuncLoadError then
  begin
    {$if not defined(PROFESSION_INFO_get0_registrationNumber_allownil)}
    PROFESSION_INFO_get0_registrationNumber := ERR_PROFESSION_INFO_get0_registrationNumber;
    {$ifend}
    {$if declared(PROFESSION_INFO_get0_registrationNumber_introduced)}
    if LibVersion < PROFESSION_INFO_get0_registrationNumber_introduced then
    begin
      {$if declared(FC_PROFESSION_INFO_get0_registrationNumber)}
      PROFESSION_INFO_get0_registrationNumber := FC_PROFESSION_INFO_get0_registrationNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROFESSION_INFO_get0_registrationNumber_removed)}
    if PROFESSION_INFO_get0_registrationNumber_removed <= LibVersion then
    begin
      {$if declared(_PROFESSION_INFO_get0_registrationNumber)}
      PROFESSION_INFO_get0_registrationNumber := _PROFESSION_INFO_get0_registrationNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROFESSION_INFO_get0_registrationNumber_allownil)}
    if FuncLoadError then
      AFailed.Add('PROFESSION_INFO_get0_registrationNumber');
    {$ifend}
  end;


  PROFESSION_INFO_set0_registrationNumber := LoadLibFunction(ADllHandle, PROFESSION_INFO_set0_registrationNumber_procname);
  FuncLoadError := not assigned(PROFESSION_INFO_set0_registrationNumber);
  if FuncLoadError then
  begin
    {$if not defined(PROFESSION_INFO_set0_registrationNumber_allownil)}
    PROFESSION_INFO_set0_registrationNumber := ERR_PROFESSION_INFO_set0_registrationNumber;
    {$ifend}
    {$if declared(PROFESSION_INFO_set0_registrationNumber_introduced)}
    if LibVersion < PROFESSION_INFO_set0_registrationNumber_introduced then
    begin
      {$if declared(FC_PROFESSION_INFO_set0_registrationNumber)}
      PROFESSION_INFO_set0_registrationNumber := FC_PROFESSION_INFO_set0_registrationNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if declared(PROFESSION_INFO_set0_registrationNumber_removed)}
    if PROFESSION_INFO_set0_registrationNumber_removed <= LibVersion then
    begin
      {$if declared(_PROFESSION_INFO_set0_registrationNumber)}
      PROFESSION_INFO_set0_registrationNumber := _PROFESSION_INFO_set0_registrationNumber;
      {$ifend}
      FuncLoadError := false;
    end;
    {$ifend}
    {$if not defined(PROFESSION_INFO_set0_registrationNumber_allownil)}
    if FuncLoadError then
      AFailed.Add('PROFESSION_INFO_set0_registrationNumber');
    {$ifend}
  end;

  //stack of macros
  LoadStackFunctions(ADllHandle,libVersion,AFailed);
  //Disable PAL warnings for Bad Typecast
  sk_ASIdOrRange_new:= Tsk_ASIdOrRange_new(sk_new);  //PALOFF
  sk_ASIdOrRange_new_null := Tsk_ASIdOrRange_new_null(sk_new_null);  //PALOFF
  sk_ASIdOrRange_free := Tsk_ASIdOrRange_free(sk_free);  //PALOFF
  sk_ASIdOrRange_num := Tsk_ASIdOrRange_num(sk_num);  //PALOFF
  sk_ASIdOrRange_value := Tsk_ASIdOrRange_value(sk_value);  //PALOFF
  sk_ASIdOrRange_push := Tsk_ASIdOrRange_push(sk_push);   //PALOFF
  sk_ASIdOrRange_dup := Tsk_ASIdOrRange_dup(sk_dup);  //PALOFF
  sk_ASIdOrRange_find := Tsk_ASIdOrRange_find(sk_find);  //PALOFF
  sk_ASIdOrRange_pop_free :=  Tsk_ASIdOrRange_pop_free(sk_pop_free);  //PALOFF
  sk_IPAddressFamily_new:= Tsk_IPAddressFamily_new(sk_new);   //PALOFF
  sk_IPAddressFamily_new_null := Tsk_IPAddressFamily_new_null(sk_new_null);   //PALOFF
  sk_IPAddressFamily_free := Tsk_IPAddressFamily_free(sk_free);   //PALOFF
  sk_IPAddressFamily_num := Tsk_IPAddressFamily_num(sk_num);   //PALOFF
  sk_IPAddressFamily_value := Tsk_IPAddressFamily_value(sk_value);  //PALOFF
  sk_IPAddressFamily_push := Tsk_IPAddressFamily_push(sk_push);  //PALOFF
  sk_IPAddressFamily_dup := Tsk_IPAddressFamily_dup(sk_dup);  //PALOFF
  sk_IPAddressFamily_find := Tsk_IPAddressFamily_find(sk_find);  //PALOFF
  sk_IPAddressFamily_pop_free :=  Tsk_IPAddressFamily_pop_free(sk_pop_free); //PALOFF
  sk_GENERAL_NAME_new :=  Tsk_GENERAL_NAME_new(sk_new);   //PALOFF
  sk_GENERAL_NAME_new_null := Tsk_GENERAL_NAME_new_null(sk_new_null);  //PALOFF
  sk_GENERAL_NAME_free := Tsk_GENERAL_NAME_free(sk_free);  //PALOFF
  sk_GENERAL_NAME_num :=  Tsk_GENERAL_NAME_num(sk_num);  //PALOFF
  sk_GENERAL_NAME_value := Tsk_GENERAL_NAME_value(sk_value);  //PALOFF
  sk_GENERAL_NAME_push := Tsk_GENERAL_NAME_push(sk_push);   //PALOFF
  sk_GENERAL_NAME_dup := Tsk_GENERAL_NAME_dup(sk_dup);   //PALOFF
  sk_GENERAL_NAME_find := Tsk_GENERAL_NAME_find(sk_find);  //PALOFF
  sk_GENERAL_NAME_pop_free := Tsk_GENERAL_NAME_pop_free(sk_pop_free);  //PALOFF
  sk_ACCESS_DESCRIPTION_new :=  Tsk_ACCESS_DESCRIPTION_new(sk_new);  //PALOFF
  sk_ACCESS_DESCRIPTION_new_null := Tsk_ACCESS_DESCRIPTION_new_null(sk_new_null); //PALOFF
  sk_ACCESS_DESCRIPTION_free := Tsk_ACCESS_DESCRIPTION_free(sk_free);  //PALOFF
  sk_ACCESS_DESCRIPTION_num :=  Tsk_ACCESS_DESCRIPTION_num(sk_num);   //PALOFF
  sk_ACCESS_DESCRIPTION_value := Tsk_ACCESS_DESCRIPTION_value(sk_value);  //PALOFF
  sk_ACCESS_DESCRIPTION_push := Tsk_ACCESS_DESCRIPTION_push(sk_push);  //PALOFF
  sk_ACCESS_DESCRIPTION_dup := Tsk_ACCESS_DESCRIPTION_dup(sk_dup);  //PALOFF
  sk_ACCESS_DESCRIPTION_find := Tsk_ACCESS_DESCRIPTION_find(sk_find);  //PALOFF
  sk_ACCESS_DESCRIPTION_pop_free := Tsk_ACCESS_DESCRIPTION_pop_free(sk_pop_free);  //PALOFF
  sk_DIST_POINT_new:= Tsk_DIST_POINT_new(sk_new);  //PALOFF
  sk_DIST_POINT_new_null := Tsk_DIST_POINT_new_null(sk_new_null);  //PALOFF
  sk_DIST_POINT_free := Tsk_DIST_POINT_free(sk_free);  //PALOFF
  sk_DIST_POINT_num := Tsk_DIST_POINT_num(sk_num);   //PALOFF
  sk_DIST_POINT_value := Tsk_DIST_POINT_value(sk_value);  //PALOFF
  sk_DIST_POINT_push := Tsk_DIST_POINT_push(sk_push);  //PALOFF
  sk_DIST_POINT_dup := Tsk_DIST_POINT_dup(sk_dup);  //PALOFF
  sk_DIST_POINT_find := Tsk_DIST_POINT_find(sk_find);  //PALOFF
  sk_DIST_POINT_pop_free :=  Tsk_DIST_POINT_pop_free(sk_pop_free);  //PALOFF
  sk_SXNETID_new :=  Tsk_SXNETID_new(sk_new);  //PALOFF
  sk_SXNETID_new_null := Tsk_SXNETID_new_null(sk_new_null); //PALOFF
  sk_SXNETID_free := Tsk_SXNETID_free(sk_free);  //PALOFF
  sk_SXNETID_num :=  Tsk_SXNETID_num(sk_num);  //PALOFF
  sk_SXNETID_value := Tsk_SXNETID_value(sk_value);  //PALOFF
  sk_SXNETID_push := Tsk_SXNETID_push(sk_push);  //PALOFF
  sk_SXNETID_dup := Tsk_SXNETID_dup(sk_dup);  //PALOFF
  sk_SXNETID_find := Tsk_SXNETID_find(sk_find);  //PALOFF
  sk_SXNETID_pop_free := Tsk_SXNETID_pop_free(sk_pop_free);  //PALOFF
  sk_POLICYQUALINFO_new :=  Tsk_POLICYQUALINFO_new(sk_new);  //PALOFF
  sk_POLICYQUALINFO_new_null := Tsk_POLICYQUALINFO_new_null(sk_new_null);  //PALOFF
  sk_POLICYQUALINFO_free := Tsk_POLICYQUALINFO_free(sk_free);  //PALOFF
  sk_POLICYQUALINFO_num :=  Tsk_POLICYQUALINFO_num(sk_num);  //PALOFF
  sk_POLICYQUALINFO_value := Tsk_POLICYQUALINFO_value(sk_value);  //PALOFF
  sk_POLICYQUALINFO_push := Tsk_POLICYQUALINFO_push(sk_push);  //PALOFF
  sk_POLICYQUALINFO_dup := Tsk_POLICYQUALINFO_dup(sk_dup);  //PALOFF
  sk_POLICYQUALINFO_find := Tsk_POLICYQUALINFO_find(sk_find);  //PALOFF
  sk_POLICYQUALINFO_pop_free := Tsk_POLICYQUALINFO_pop_free(sk_pop_free); //PALOFF
  sk_POLICYINFO_new :=  Tsk_POLICYINFO_new(sk_new);  //PALOFF
  sk_POLICYINFO_new_null := Tsk_POLICYINFO_new_null(sk_new_null);  //PALOFF
  sk_POLICYINFO_free := Tsk_POLICYINFO_free(sk_free);  //PALOFF
  sk_POLICYINFO_num :=  Tsk_POLICYINFO_num(sk_num);  //PALOFF
  sk_POLICYINFO_value := Tsk_POLICYINFO_value(sk_value);  //PALOFF
  sk_POLICYINFO_push := Tsk_POLICYINFO_push(sk_push);  //PALOFF
  sk_POLICYINFO_dup := Tsk_POLICYINFO_dup(sk_dup);  //PALOFF
  sk_POLICYINFO_find := Tsk_POLICYINFO_find(sk_find);  //PALOFF
  sk_POLICYINFO_pop_free := Tsk_POLICYINFO_pop_free(sk_pop_free);  //PALOFF
  sk_POLICY_MAPPING_new :=  Tsk_POLICY_MAPPING_new(sk_new);  //PALOFF
  sk_POLICY_MAPPING_new_null := Tsk_POLICY_MAPPING_new_null(sk_new_null);  //PALOFF
  sk_POLICY_MAPPING_free := Tsk_POLICY_MAPPING_free(sk_free);  //PALOFF
  sk_POLICY_MAPPING_num :=  Tsk_POLICY_MAPPING_num(sk_num);  //PALOFF
  sk_POLICY_MAPPING_value := Tsk_POLICY_MAPPING_value(sk_value);  //PALOFF
  sk_POLICY_MAPPING_push := Tsk_POLICY_MAPPING_push(sk_push);  //PALOFF
  sk_POLICY_MAPPING_dup := Tsk_POLICY_MAPPING_dup(sk_dup);  //PALOFF
  sk_POLICY_MAPPING_find := Tsk_POLICY_MAPPING_find(sk_find);  //PALOFF
  sk_POLICY_MAPPING_pop_free := Tsk_POLICY_MAPPING_pop_free(sk_pop_free);  //PALOFF
  sk_GENERAL_SUBTREE_new :=  Tsk_GENERAL_SUBTREE_new(sk_new);  //PALOFF
  sk_GENERAL_SUBTREE_new_null := Tsk_GENERAL_SUBTREE_new_null(sk_new_null);  //PALOFF
  sk_GENERAL_SUBTREE_free := Tsk_GENERAL_SUBTREE_free(sk_free);  //PALOFF
  sk_GENERAL_SUBTREE_num :=  Tsk_GENERAL_SUBTREE_num(sk_num);  //PALOFF
  sk_GENERAL_SUBTREE_value := Tsk_GENERAL_SUBTREE_value(sk_value);  //PALOFF
  sk_GENERAL_SUBTREE_push := Tsk_GENERAL_SUBTREE_push(sk_push);  //PALOFF
  sk_GENERAL_SUBTREE_dup := Tsk_GENERAL_SUBTREE_dup(sk_dup);  //PALOFF
  sk_GENERAL_SUBTREE_find := Tsk_GENERAL_SUBTREE_find(sk_find);  //PALOFF
  sk_GENERAL_SUBTREE_pop_free := Tsk_GENERAL_SUBTREE_pop_free(sk_pop_free); //PALOFF

  sk_ASN1_STRING_new :=  Tsk_ASN1_STRING_new(sk_new);  //PALOFF
  sk_ASN1_STRING_new_null := Tsk_ASN1_STRING_new_null(sk_new_null);  //PALOFF
  sk_ASN1_STRING_free := Tsk_ASN1_STRING_free(sk_free);   //PALOFF
  sk_ASN1_STRING_num :=  Tsk_ASN1_STRING_num(sk_num);  //PALOFF
  sk_ASN1_STRING_value := Tsk_ASN1_STRING_value(sk_value);   //PALOFF
  sk_ASN1_STRING_push := Tsk_ASN1_STRING_push(sk_push);   //PALOFF
  sk_ASN1_STRING_dup := Tsk_ASN1_STRING_dup(sk_dup);   //PALOFF
  sk_ASN1_STRING_find := Tsk_ASN1_STRING_find(sk_find);   //PALOFF
  sk_ASN1_STRING_pop_free := Tsk_ASN1_STRING_pop_free(sk_pop_free);  //PALOFF

  sk_X509_PURPOSE_new :=  Tsk_X509_PURPOSE_new(sk_new);   //PALOFF
  sk_X509_PURPOSE_new_null := Tsk_X509_PURPOSE_new_null(sk_new_null);  //PALOFF
  sk_X509_PURPOSE_free := Tsk_X509_PURPOSE_free(sk_free);  //PALOFF
  sk_X509_PURPOSE_num :=  Tsk_X509_PURPOSE_num(sk_num);   //PALOFF
  sk_X509_PURPOSE_value := Tsk_X509_PURPOSE_value(sk_value);   //PALOFF
  sk_X509_PURPOSE_push := Tsk_X509_PURPOSE_push(sk_push);  //PALOFF
  sk_X509_PURPOSE_dup := Tsk_X509_PURPOSE_dup(sk_dup);  //PALOFF
  sk_X509_PURPOSE_find := Tsk_X509_PURPOSE_find(sk_find);   //PALOFF
  sk_X509_PURPOSE_pop_free := Tsk_X509_PURPOSE_pop_free(sk_pop_free);  //PALOFF

  sk_X509_POLICY_NODE_new :=  Tsk_X509_POLICY_NODE_new(sk_new);  //PALOFF
  sk_X509_POLICY_NODE_new_null := Tsk_X509_POLICY_NODE_new_null(sk_new_null);  //PALOFF
  sk_X509_POLICY_NODE_free := Tsk_X509_POLICY_NODE_free(sk_free);  //PALOFF
  sk_X509_POLICY_NODE_num :=  Tsk_X509_POLICY_NODE_num(sk_num);  //PALOFF
  sk_X509_POLICY_NODE_value := Tsk_X509_POLICY_NODE_value(sk_value);  //PALOFF
  sk_X509_POLICY_NODE_push := Tsk_X509_POLICY_NODE_push(sk_push);  //PALOFF
  sk_X509_POLICY_NODE_dup := Tsk_X509_POLICY_NODE_dup(sk_dup);  //PALOFF
  sk_X509_POLICY_NODE_find := Tsk_X509_POLICY_NODE_find(sk_find);  //PALOFF
  sk_X509_POLICY_NODE_pop_free := Tsk_X509_POLICY_NODE_pop_free(sk_pop_free);   //PALOFF

end;

{$I TaurusTLSUnusedParamOn.inc}

procedure Unload;
begin
  GENERAL_NAME_cmp := nil;
  GENERAL_NAME_print := nil;
  OTHERNAME_cmp := nil;
  GENERAL_NAME_set0_value := nil;
  GENERAL_NAME_get0_value := nil;
  GENERAL_NAME_set0_othername := nil;
  GENERAL_NAME_get0_otherName := nil;
  GENERAL_NAMES_free := nil;
  i2a_ACCESS_DESCRIPTION := nil;
  DIST_POINT_set_dpname := nil;
  NAME_CONSTRAINTS_check := nil;
  NAME_CONSTRAINTS_check_CN := nil;
  BASIC_CONSTRAINTS_free := nil;
  AUTHORITY_KEYID_free := nil;
  X509V3_EXT_nconf_nid := nil;
  X509V3_EXT_nconf := nil;
  X509V3_EXT_add_nconf := nil;
  X509V3_EXT_REQ_add_nconf := nil;
  X509V3_EXT_CRL_add_nconf := nil;
  X509V3_EXT_conf_nid := nil;
  X509V3_EXT_conf := nil;
  X509V3_EXT_add_conf := nil;
  X509V3_EXT_REQ_add_conf := nil;
  X509V3_EXT_CRL_add_conf := nil;
  X509V3_set_nconf := nil;
  X509V3_get_string := nil;
  X509V3_string_free := nil;
  X509V3_set_ctx := nil;
  X509V3_EXT_add_alias := nil;
  X509V3_EXT_cleanup := nil;
  X509V3_add_standard_extensions := nil;
  X509V3_EXT_d2i := nil;
  X509V3_EXT_i2d := nil;
  X509V3_EXT_print := nil;
  X509_check_ca := nil;
  X509_check_purpose := nil;
  X509_supported_extension := nil;
  X509_PURPOSE_set := nil;
  X509_check_issued := nil;
  X509_check_akid := nil;
  X509_set_proxy_flag := nil;
  X509_set_proxy_pathlen := nil;
  X509_get_proxy_pathlen := nil;
  X509_get_extension_flags := nil;
  X509_get_key_usage := nil;
  X509_get_extended_key_usage := nil;
  X509_get0_subject_key_id := nil;
  X509_get0_authority_key_id := nil;
  X509_get0_authority_serial := nil;
  X509_PURPOSE_get_count := nil;
  X509_PURPOSE_get0 := nil;
  X509_PURPOSE_get_by_sname := nil;
  X509_PURPOSE_get_by_id := nil;
  X509_PURPOSE_get0_name := nil;
  X509_PURPOSE_get0_sname := nil;
  X509_PURPOSE_get_trust := nil;
  X509_PURPOSE_cleanup := nil;
  X509_PURPOSE_get_id := nil;
  X509_get1_email := nil;
  X509_REQ_get1_email := nil;
  X509_email_free := nil;
  X509_get1_ocsp := nil;
  X509_check_host := nil;
  X509_check_email := nil;
  X509_check_ip := nil;
  X509_check_ip_asc := nil;
  a2i_IPADDRESS := nil;
  a2i_IPADDRESS_NC := nil;
  X509_POLICY_NODE_print := nil;
  X509v3_addr_get_range := nil;
  X509v3_asid_validate_path := nil;
  X509v3_addr_validate_path := nil;
  NAMING_AUTHORITY_get0_authorityId := nil;
  NAMING_AUTHORITY_get0_authorityURL := nil;
  NAMING_AUTHORITY_get0_authorityText := nil;
  NAMING_AUTHORITY_set0_authorityId := nil;
  NAMING_AUTHORITY_set0_authorityURL := nil;
  NAMING_AUTHORITY_set0_authorityText := nil;
  ADMISSION_SYNTAX_get0_admissionAuthority := nil;
  ADMISSION_SYNTAX_set0_admissionAuthority := nil;
  ADMISSIONS_get0_admissionAuthority := nil;
  ADMISSIONS_set0_admissionAuthority := nil;
  ADMISSIONS_get0_namingAuthority := nil;
  ADMISSIONS_set0_namingAuthority := nil;
  PROFESSION_INFO_get0_addProfessionInfo := nil;
  PROFESSION_INFO_set0_addProfessionInfo := nil;
  PROFESSION_INFO_get0_namingAuthority := nil;
  PROFESSION_INFO_set0_namingAuthority := nil;
  PROFESSION_INFO_get0_registrationNumber := nil;
  PROFESSION_INFO_set0_registrationNumber := nil;

  //stack of macros
  sk_ASIdOrRange_new:= nil;
  sk_ASIdOrRange_new_null := nil;
  sk_ASIdOrRange_free := nil;
  sk_ASIdOrRange_num := nil;
  sk_ASIdOrRange_value := nil;
  sk_ASIdOrRange_push := nil;
  sk_ASIdOrRange_dup := nil;
  sk_ASIdOrRange_find := nil;
  sk_ASIdOrRange_pop_free := nil;
  sk_IPAddressFamily_new:= nil;
  sk_IPAddressFamily_new_null := nil;
  sk_IPAddressFamily_free := nil;
  sk_IPAddressFamily_num := nil;
  sk_IPAddressFamily_value := nil;
  sk_IPAddressFamily_push := nil;
  sk_IPAddressFamily_dup := nil;
  sk_IPAddressFamily_find := nil;
  sk_IPAddressFamily_pop_free := nil;
  sk_GENERAL_NAME_new := nil;
  sk_GENERAL_NAME_new_null := nil;
  sk_GENERAL_NAME_free := nil;
  sk_GENERAL_NAME_num := nil;
  sk_GENERAL_NAME_value := nil;
  sk_GENERAL_NAME_push := nil;
  sk_GENERAL_NAME_dup := nil;
  sk_GENERAL_NAME_find := nil;
  sk_GENERAL_NAME_pop_free := nil;
  sk_ACCESS_DESCRIPTION_new := nil;
  sk_ACCESS_DESCRIPTION_new_null := nil;
  sk_ACCESS_DESCRIPTION_free := nil;
  sk_ACCESS_DESCRIPTION_num := nil;
  sk_ACCESS_DESCRIPTION_value := nil;
  sk_ACCESS_DESCRIPTION_push := nil;
  sk_ACCESS_DESCRIPTION_dup := nil;
  sk_ACCESS_DESCRIPTION_find := nil;
  sk_ACCESS_DESCRIPTION_pop_free := nil;
  sk_DIST_POINT_new:= nil;
  sk_DIST_POINT_new_null := nil;
  sk_DIST_POINT_free := nil;
  sk_DIST_POINT_num := nil;
  sk_DIST_POINT_value := nil;
  sk_DIST_POINT_push := nil;
  sk_DIST_POINT_dup := nil;
  sk_DIST_POINT_find := nil;
  sk_DIST_POINT_pop_free := nil;
  sk_SXNETID_new := nil;
  sk_SXNETID_new_null := nil;
  sk_SXNETID_free := nil;
  sk_SXNETID_num := nil;
  sk_SXNETID_value := nil;
  sk_SXNETID_push := nil;
  sk_SXNETID_dup := nil;
  sk_SXNETID_find := nil;
  sk_SXNETID_pop_free := nil;
  sk_POLICYQUALINFO_new := nil;
  sk_POLICYQUALINFO_new_null := nil;
  sk_POLICYQUALINFO_free := nil;
  sk_POLICYQUALINFO_num := nil;
  sk_POLICYQUALINFO_value := nil;
  sk_POLICYQUALINFO_push := nil;
  sk_POLICYQUALINFO_dup := nil;
  sk_POLICYQUALINFO_find := nil;
  sk_POLICYQUALINFO_pop_free := nil;
  sk_POLICYINFO_new := nil;
  sk_POLICYINFO_new_null := nil;
  sk_POLICYINFO_free := nil;
  sk_POLICYINFO_num := nil;
  sk_POLICYINFO_value := nil;
  sk_POLICYINFO_push := nil;
  sk_POLICYINFO_dup := nil;
  sk_POLICYINFO_find := nil;
  sk_POLICYINFO_pop_free := nil;
  sk_POLICY_MAPPING_new := nil;
  sk_POLICY_MAPPING_new_null := nil;
  sk_POLICY_MAPPING_free := nil;
  sk_POLICY_MAPPING_num := nil;
  sk_POLICY_MAPPING_value := nil;
  sk_POLICY_MAPPING_push := nil;
  sk_POLICY_MAPPING_dup := nil;
  sk_POLICY_MAPPING_find := nil;
  sk_POLICY_MAPPING_pop_free := nil;
  sk_GENERAL_SUBTREE_new := nil;
  sk_GENERAL_SUBTREE_new_null := nil;
  sk_GENERAL_SUBTREE_free := nil;
  sk_GENERAL_SUBTREE_num := nil;
  sk_GENERAL_SUBTREE_value := nil;
  sk_GENERAL_SUBTREE_push := nil;
  sk_GENERAL_SUBTREE_dup := nil;
  sk_GENERAL_SUBTREE_find := nil;
  sk_GENERAL_SUBTREE_pop_free := nil;

  sk_ASN1_STRING_new := nil;
  sk_ASN1_STRING_new_null := nil;
  sk_ASN1_STRING_free := nil;
  sk_ASN1_STRING_num := nil;
  sk_ASN1_STRING_value := nil;
  sk_ASN1_STRING_push := nil;
  sk_ASN1_STRING_dup := nil;
  sk_ASN1_STRING_find := nil;
  sk_ASN1_STRING_pop_free := nil;

  sk_X509_PURPOSE_new := nil;
  sk_X509_PURPOSE_new_null := nil;
  sk_X509_PURPOSE_free := nil;
  sk_X509_PURPOSE_num := nil;
  sk_X509_PURPOSE_value := nil;
  sk_X509_PURPOSE_push := nil;
  sk_X509_PURPOSE_dup := nil;
  sk_X509_PURPOSE_find := nil;
  sk_X509_PURPOSE_pop_free := nil;
end;
  {$ENDIF}
{$ENDIF}

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
initialization
  Register_SSLLoader(Load,'LibCrypto');
  Register_SSLUnloader(Unload);
{$ENDIF}
end.
